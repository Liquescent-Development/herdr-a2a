#![allow(dead_code)]

#[path = "../src/doctor.rs"]
mod doctor;
#[path = "../src/managed.rs"]
mod managed;
#[path = "../src/status.rs"]
mod status;
#[path = "../src/status_tui.rs"]
mod status_tui;

use std::{
    env,
    ffi::{OsStr, OsString},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use doctor::{DoctorEvidence, DoctorIssue, DoctorState, evaluate_evidence};
use herdr_a2a_broker::{RuntimeDescriptor, SqliteTaskStore, test_support::TestBroker};
#[cfg(feature = "test-harness")]
use herdr_a2a_broker::{RuntimePaths, read_descriptor, write_descriptor};
use herdr_a2a_core::{
    AgentName, BrokerPersistence, BrokerState, DurableBrokerSnapshot, PersistenceBatch,
    PersistenceCommitOutcome, QueuedDelivery, SystemClock, ValidatedPayload, VerifiedAgent,
};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::{Digest, Sha256};
use status::{AgentStatus, OperationsError, WorkspaceStatus};
use status_tui::{TuiCommand, TuiState, TuiView, render};
#[cfg(feature = "test-harness")]
use std::process::Stdio;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, Lines},
    net::TcpListener,
    process::{Child, ChildStdin, ChildStdout},
};

#[derive(Clone)]
struct MemoryPersistence {
    snapshot: Arc<Mutex<DurableBrokerSnapshot>>,
}

impl MemoryPersistence {
    fn new() -> Self {
        Self {
            snapshot: Arc::new(Mutex::new(DurableBrokerSnapshot {
                last_registration_epoch: herdr_a2a_core::RegistrationEpoch::from_u64(0),
                tasks: Vec::new(),
            })),
        }
    }
}

#[async_trait]
impl BrokerPersistence for MemoryPersistence {
    async fn load(
        &self,
        _now_unix_ms: i64,
    ) -> Result<DurableBrokerSnapshot, herdr_a2a_core::DomainError> {
        Ok(self.snapshot.lock().unwrap().clone())
    }

    async fn commit(
        &self,
        batch: PersistenceBatch,
    ) -> Result<PersistenceCommitOutcome, herdr_a2a_core::DomainError> {
        let mut snapshot = self.snapshot.lock().unwrap();
        if let Some(epoch) = batch.registration_epoch_high_watermark {
            snapshot.last_registration_epoch = epoch;
        }
        for task in batch.upsert_tasks {
            if let Some(existing) = snapshot
                .tasks
                .iter_mut()
                .find(|item| item.task_id == task.task_id)
            {
                *existing = task;
            } else {
                snapshot.tasks.push(task);
            }
        }
        snapshot
            .tasks
            .retain(|task| !batch.delete_task_ids.contains(&task.task_id));
        Ok(PersistenceCommitOutcome::Complete)
    }
}

fn agent(name: &str, pane: &str) -> VerifiedAgent {
    VerifiedAgent {
        name: AgentName::parse(name).unwrap(),
        pane_id: pane.to_owned(),
        harness: "pi".to_owned(),
        workspace: PathBuf::from("/workspace"),
    }
}

struct EnvironmentGuard(Vec<(&'static str, Option<OsString>)>);

impl EnvironmentGuard {
    fn set(values: &[(&'static str, &OsStr)]) -> Self {
        let original = values
            .iter()
            .map(|(name, _)| (*name, env::var_os(name)))
            .collect();
        for (name, value) in values {
            // SAFETY: Task 7 operations tests are required to run with RUST_TEST_THREADS=1 and
            // this guard restores every value before the test returns.
            unsafe { env::set_var(name, value) };
        }
        Self(original)
    }
}

impl Drop for EnvironmentGuard {
    fn drop(&mut self) {
        for (name, value) in self.0.drain(..).rev() {
            // SAFETY: See `EnvironmentGuard::set`; the focused test process is single-threaded.
            unsafe {
                match value {
                    Some(value) => env::set_var(name, value),
                    None => env::remove_var(name),
                }
            }
        }
    }
}

fn file_digest(path: &Path) -> String {
    format!("{:x}", Sha256::digest(fs::read(path).unwrap()))
}

fn tree_digest(root: &Path) -> String {
    fn files(root: &Path, paths: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(root).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                files(&entry.path(), paths);
            } else {
                paths.push(entry.path());
            }
        }
    }
    let mut paths = Vec::new();
    files(root, &mut paths);
    paths.sort();
    let mut hasher = Sha256::new();
    for path in paths {
        let relative = path
            .strip_prefix(root)
            .unwrap()
            .as_os_str()
            .as_encoded_bytes();
        hasher.update((relative.len() as u64).to_be_bytes());
        hasher.update(relative);
        hasher.update(fs::read(path).unwrap());
    }
    format!("{:x}", hasher.finalize())
}

struct ManagedDoctorFixture {
    _root: tempfile::TempDir,
    home: PathBuf,
    data_home: PathBuf,
    pi_root: PathBuf,
    runtime: PathBuf,
    plugin_state: PathBuf,
    fake_bin: PathBuf,
    ownership: PathBuf,
    stable_binary: PathBuf,
    package: PathBuf,
    package_manifest: PathBuf,
    plugin_manifest: PathBuf,
    settings: PathBuf,
}

impl ManagedDoctorFixture {
    fn new(
        record_version: &str,
        plugin_version: &str,
        adapter_version: &str,
        pi_version: &str,
    ) -> Self {
        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let home = root_path.join("home");
        let data_home = root_path.join("data");
        #[cfg(target_os = "macos")]
        let stable_root = home.join("Library/Application Support/herdr-a2a");
        #[cfg(not(target_os = "macos"))]
        let stable_root = data_home.join("herdr-a2a");
        let generation = stable_root.join("generations/generation-one");
        let stable_binary = generation.join("bin/herdr-a2a");
        let package = generation.join("pi");
        let package_manifest = package.join("package.json");
        let package_extension = package.join("extensions/herdr-a2a.ts");
        let plugin_root = root_path.join("plugin");
        let helper = plugin_root.join("libexec/herdr-a2a-dispatch");
        let pointer = plugin_root.join("stable-bin-path");
        let plugin_manifest = plugin_root.join("herdr-plugin.toml");
        let rescue_directory = stable_root.join("rescue");
        let rescue = rescue_directory.join("uninstall.sh");
        let rescue_marker = rescue_directory.join("owner-v1");
        let pi_root = root_path.join("pi");
        let settings = pi_root.join("settings.json");
        let runtime = root_path.join("runtime");
        let plugin_state = root_path.join("plugin-state");
        let fake_bin = root_path.join("bin");
        for directory in [
            &home,
            &stable_root,
            &generation,
            stable_binary.parent().unwrap(),
            &package,
            package_extension.parent().unwrap(),
            &plugin_root,
            helper.parent().unwrap(),
            &rescue_directory,
            &pi_root,
            &runtime,
            &plugin_state,
            &fake_bin,
        ] {
            fs::create_dir_all(directory).unwrap();
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(&stable_binary, b"managed-binary-v1").unwrap();
        fs::write(&helper, b"managed-binary-v1").unwrap();
        fs::write(
            &package_manifest,
            format!(
                r#"{{"name":"@herdr/a2a-pi","version":"{adapter_version}","peerDependencies":{{"@earendil-works/pi-coding-agent":">=0.84.2","typebox":">=1.3.7 <1.4.0"}}}}"#
            ),
        )
        .unwrap();
        fs::write(&package_extension, b"export const managed = true;\n").unwrap();
        fs::write(&pointer, format!("{}\n", stable_binary.display())).unwrap();
        fs::write(&rescue, b"managed rescue notice\n").unwrap();
        fs::write(&rescue_marker, b"managed rescue marker\n").unwrap();
        fs::write(
            &plugin_manifest,
            format!("id = \"herdr.a2a\"\nversion = \"{plugin_version}\"\n"),
        )
        .unwrap();
        fs::write(
            &settings,
            serde_json::to_vec(&json!({"packages": [package.to_string_lossy()]})).unwrap(),
        )
        .unwrap();
        let pi = fake_bin.join("pi");
        fs::write(&pi, format!("#!/bin/sh\nprintf '%s\\n' '{pi_version}'\n")).unwrap();
        for (path, mode) in [
            (&stable_binary, 0o700),
            (&helper, 0o700),
            (&package_manifest, 0o600),
            (&package_extension, 0o600),
            (&pointer, 0o600),
            (&rescue, 0o600),
            (&rescue_marker, 0o600),
            (&plugin_manifest, 0o600),
            (&settings, 0o600),
            (&pi, 0o700),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }
        let mut owned_files = vec![
            json!({"path": stable_binary, "sha256": file_digest(&stable_binary), "mode": 0o700}),
            json!({"path": package_manifest, "sha256": file_digest(&package_manifest), "mode": 0o600}),
            json!({"path": package_extension, "sha256": file_digest(&package_extension), "mode": 0o600}),
            json!({"path": helper, "sha256": file_digest(&helper), "mode": 0o700}),
            json!({"path": pointer, "sha256": file_digest(&pointer), "mode": 0o600}),
            json!({"path": rescue, "sha256": file_digest(&rescue), "mode": 0o600}),
            json!({"path": rescue_marker, "sha256": file_digest(&rescue_marker), "mode": 0o600}),
        ];
        owned_files.sort_by_key(|entry| entry["path"].as_str().unwrap().to_owned());
        let ownership = stable_root.join("ownership.json");
        fs::write(
            &ownership,
            serde_json::to_vec(&json!({
                "schema_version": 3,
                "state": "Ready",
                "plugin_version": record_version,
                "broker_digest": file_digest(&stable_binary),
                "pi_package_digest": tree_digest(&package),
                "pi_package_source": package,
                "pi_config_path": settings,
                "pi_package_entry": package.to_string_lossy(),
                "purge_authority": false,
                "rescue_path": rescue,
                "rescue_marker_digest": file_digest(&rescue_marker),
                "install_kind": "managed",
                "plugin_root": plugin_root,
                "stable_binary": stable_binary,
                "ownership_path": ownership,
                "owned_files": owned_files
            }))
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(&ownership, fs::Permissions::from_mode(0o600)).unwrap();
        Self {
            _root: root,
            home,
            data_home,
            pi_root,
            runtime,
            plugin_state,
            fake_bin,
            ownership,
            stable_binary,
            package,
            package_manifest,
            plugin_manifest,
            settings,
        }
    }

    fn environment(&self) -> EnvironmentGuard {
        let socket = self.home.parent().unwrap().join("herdr.sock");
        EnvironmentGuard::set(&[
            ("HOME", self.home.as_os_str()),
            ("XDG_DATA_HOME", self.data_home.as_os_str()),
            ("PI_CODING_AGENT_DIR", self.pi_root.as_os_str()),
            ("PATH", self.fake_bin.as_os_str()),
            ("XDG_RUNTIME_DIR", self.runtime.as_os_str()),
            ("HERDR_SOCKET_PATH", socket.as_os_str()),
            ("HERDR_WORKSPACE_ID", OsStr::new("workspace-one")),
            ("HERDR_PLUGIN_STATE_DIR", self.plugin_state.as_os_str()),
        ])
    }

    fn replace_adapter_manifest_and_refresh_ownership(&self, manifest: serde_json::Value) {
        fs::write(
            &self.package_manifest,
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let mut ownership: serde_json::Value =
            serde_json::from_slice(&fs::read(&self.ownership).unwrap()).unwrap();
        ownership["pi_package_digest"] = json!(tree_digest(&self.package));
        for owned in ownership["owned_files"].as_array_mut().unwrap() {
            if owned["path"].as_str() == self.package_manifest.to_str() {
                owned["sha256"] = json!(file_digest(&self.package_manifest));
            }
        }
        fs::write(&self.ownership, serde_json::to_vec(&ownership).unwrap()).unwrap();
    }
}

#[cfg(feature = "test-harness")]
struct RestartFixture {
    root: tempfile::TempDir,
    socket: PathBuf,
    executable: PathBuf,
    herdr: PathBuf,
}

#[cfg(feature = "test-harness")]
impl RestartFixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let runtime = root.path().join("runtime");
        let state = root.path().join("state");
        fs::create_dir_all(&runtime).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
        let herdr = root.path().join("herdr");
        fs::write(
            &herdr,
            format!(
                "#!/bin/sh\nif [ \"$1 $2 $3 $4\" = 'plugin action invoke herdr.a2a.ensure-broker' ]; then\n  exec '{}' coordinator serve\nfi\nif [ \"$1 $2\" = 'agent get' ]; then\n  pane=$3\n  case \"$pane\" in\n    *:p1) role=implementer ;;\n    *:p2) role=reviewer ;;\n    *) exit 97 ;;\n  esac\n  printf '%s\\n' \"{{\\\"result\\\":{{\\\"agent\\\":{{\\\"pane_id\\\":\\\"$pane\\\",\\\"name\\\":\\\"$role\\\",\\\"agent\\\":\\\"pi\\\",\\\"workspace_id\\\":\\\"workspace-one\\\",\\\"cwd\\\":\\\"/repo\\\"}}}}}}\"\n  exit 0\nfi\nexit 97\n",
                executable.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&herdr, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            socket: root.path().join("herdr.sock"),
            executable,
            herdr,
            root,
        }
    }

    fn paths(&self) -> RuntimePaths {
        let session_key = format!(
            "{:x}",
            Sha256::digest(self.socket.as_os_str().as_encoded_bytes())
        );
        RuntimePaths::for_test(
            &self.root.path().join("runtime/herdr-a2a"),
            &session_key,
            "workspace-one",
        )
    }

    fn command(&self, arguments: &[&str]) -> tokio::process::Command {
        let mut command = tokio::process::Command::new(&self.executable);
        command
            .args(arguments)
            .env("HERDR_SOCKET_PATH", &self.socket)
            .env("HERDR_WORKSPACE_ID", "workspace-one")
            .env("HERDR_BIN_PATH", &self.herdr)
            .env("HERDR_PLUGIN_STATE_DIR", self.root.path().join("state"))
            .env(
                "HERDR_A2A_TEST_GENERATION_ID",
                "00000000000000000000000000000000",
            )
            .env("TMPDIR", self.root.path().join("runtime"))
            .env("XDG_RUNTIME_DIR", self.root.path().join("runtime"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        command
    }

    fn client(&self, pane: &str, session: &str) -> NdjsonClient {
        let mut command = self.command(&["client-session", "--harness-session-id", session]);
        command
            .env("HERDR_PANE_ID", pane)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        NdjsonClient::spawn(command)
    }

    async fn wait_for_descriptor(&self) -> RuntimeDescriptor {
        let paths = self.paths();
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if let Ok(descriptor) = read_descriptor(&paths) {
                    break descriptor;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("coordinator did not publish a descriptor")
    }

    async fn wait_for_coordinator_instance(&self, expected_instance: &str) -> serde_json::Value {
        let paths = self.paths();
        let coordinator_lock = paths
            .root
            .join(format!("{}.coordinator.lock", paths.scope.scope_key));
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(encoded) = fs::read(&coordinator_lock)
                    && let Ok(record) = serde_json::from_slice::<serde_json::Value>(&encoded)
                    && record["broker_instance_id"] == expected_instance
                {
                    break record;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("coordinator did not bind its exact broker instance")
    }
}

#[cfg(feature = "test-harness")]
async fn pause_restart_after_descriptor_absence(
    fixture: &RestartFixture,
    original_coordinator: &mut Child,
    marker: &Path,
) -> Child {
    let mut restart = fixture.command(&["restart"]);
    restart
        .env(
            "HERDR_A2A_TEST_STARTING_BOUNDARY",
            "after-restart-descriptor-absence-before-ensure",
        )
        .env("HERDR_A2A_TEST_STARTING_MARKER", marker);
    let mut restart = restart.spawn().unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !marker.exists() {
            if let Some(status) = restart.try_wait().unwrap() {
                let mut stderr = String::new();
                restart
                    .stderr
                    .take()
                    .unwrap()
                    .read_to_string(&mut stderr)
                    .await
                    .unwrap();
                panic!("restart exited before descriptor absence {status}: {stderr}");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("restart did not reach descriptor absence before ensure");
    tokio::time::timeout(Duration::from_secs(5), original_coordinator.wait())
        .await
        .expect("original coordinator remained alive at descriptor absence")
        .unwrap();
    assert!(
        !fixture.paths().descriptor.exists(),
        "restart boundary did not prove descriptor absence"
    );
    restart
}

#[cfg(feature = "test-harness")]
fn release_restart(marker: &Path) {
    fs::write(marker.with_extension("release"), b"continue\n").unwrap();
}

struct NdjsonClient {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Lines<BufReader<ChildStdout>>,
}

impl NdjsonClient {
    fn spawn(mut command: tokio::process::Command) -> Self {
        let mut child = command.spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        Self {
            child,
            stdin: Some(stdin),
            stdout: BufReader::new(stdout).lines(),
        }
    }

    async fn send(&mut self, value: serde_json::Value) {
        let stdin = self.stdin.as_mut().unwrap();
        stdin
            .write_all(format!("{}\n", serde_json::to_string(&value).unwrap()).as_bytes())
            .await
            .unwrap();
        stdin.flush().await.unwrap();
    }

    async fn recv(&mut self) -> serde_json::Value {
        let line = tokio::time::timeout(Duration::from_secs(15), self.stdout.next_line())
            .await
            .expect("client response timed out")
            .unwrap()
            .expect("client stdout closed");
        serde_json::from_str(&line).unwrap()
    }

    async fn close(mut self) {
        drop(self.stdin.take());
        tokio::time::timeout(Duration::from_secs(5), self.child.wait())
            .await
            .expect("client did not exit")
            .unwrap();
    }
}

#[tokio::test]
async fn status_json_never_contains_sensitive_values() {
    // Break caught: status serializes task payloads, complete task IDs, bearer credentials, or
    // descriptor paths instead of the deliberately small operations projection.
    let persistence = MemoryPersistence::new();
    let (broker, _) = BrokerState::recover(SystemClock, persistence)
        .await
        .unwrap();
    let sender = broker
        .register(agent("sender-k7m2", "w1:p1"), "pi-a")
        .await
        .unwrap();
    broker
        .register(agent("reviewer-r8c1", "w1:p2"), "pi-b")
        .await
        .unwrap();
    let full_task_id = "task-private-complete-identifier";
    let message_body = "private peer message body";
    broker
        .enqueue(
            &sender.credentials(),
            QueuedDelivery {
                task_id: full_task_id.to_owned(),
                context_id: "context-private".to_owned(),
                sender: AgentName::parse("sender-k7m2").unwrap(),
                recipient: AgentName::parse("reviewer-r8c1").unwrap(),
                payload: ValidatedPayload {
                    text: message_body.to_owned(),
                    metadata: json!({"secret": "metadata-secret"}),
                    file_refs: Vec::new(),
                },
                created_unix_ms: 0,
                attempt: 0,
            },
        )
        .await
        .unwrap();
    let broker_status = broker.operations_snapshot().await.unwrap();
    let status = WorkspaceStatus::from_broker(
        "workspace-one",
        vec![AgentStatus::new("reviewer", "reviewer-r8c1", "connected").unwrap()],
        broker_status,
    )
    .unwrap();
    let encoded = serde_json::to_string(&status).unwrap();

    assert_eq!(status.tasks.queued, 1);
    assert_eq!(status.registrations, 2);
    assert_eq!(status.last_event.as_ref().unwrap().kind, "task_queued");
    assert_eq!(
        status.last_event.as_ref().unwrap().canonical_name.as_str(),
        "sender-k7m2"
    );
    for forbidden in [
        "bearer-private-value",
        message_body,
        full_task_id,
        "/private/runtime/workspace.json",
        "metadata-secret",
    ] {
        assert!(
            !encoded.contains(forbidden),
            "leaked {forbidden:?}: {encoded}"
        );
    }
}

#[tokio::test]
async fn operations_snapshot_freezes_the_exact_live_registration_set() {
    // Break caught: status counts registrations under one broker lock, then fetches agents under
    // another lock and emits a response that strict consumers reject during registration churn.
    let broker = BrokerState::new();
    broker
        .register(agent("sender-k7m2", "w1:p1"), "pi-a")
        .await
        .unwrap();
    let before_interleaving = broker.operations_snapshot().await.unwrap();
    broker
        .register(agent("reviewer-r8c1", "w1:p2"), "pi-b")
        .await
        .unwrap();

    assert_eq!(before_interleaving.registrations, 1);
    assert_eq!(
        before_interleaving.agents[0].canonical_name.as_str(),
        "sender-k7m2"
    );
    assert_eq!(broker.operations_snapshot().await.unwrap().registrations, 2);
}

#[tokio::test]
async fn descriptor_status_transport_never_uses_environment_proxies() {
    // Break caught: reqwest's default system proxy observes and relays the otherwise bearer-free
    // status challenge, defeating the requirement that descriptor loopback transport be direct.
    let broker = TestBroker::start().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_url = format!("http://{}", listener.local_addr().unwrap());
    let proof_hits = Arc::new(AtomicUsize::new(0));
    let bearer_seen = Arc::new(AtomicBool::new(false));
    let proxy_proof_hits = Arc::clone(&proof_hits);
    let proxy_bearer_seen = Arc::clone(&bearer_seen);
    let origin = broker.base_url().to_owned();
    let proxy = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut request = Vec::new();
            let mut buffer = [0_u8; 2048];
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).unwrap();
            let target = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap();
            let path = reqwest::Url::parse(target).unwrap().path().to_owned();
            proxy_proof_hits.fetch_add(1, Ordering::SeqCst);
            proxy_bearer_seen.store(
                request.lines().any(|line| {
                    line.to_ascii_lowercase()
                        .starts_with("authorization: bearer ")
                }),
                Ordering::SeqCst,
            );
            let response = reqwest::Client::builder()
                .no_proxy()
                .build()
                .unwrap()
                .get(format!("{origin}{path}"))
                .send()
                .await
                .unwrap();
            let status = response.status().as_u16();
            let proof = response.headers()["x-herdr-a2a-status-proof"]
                .to_str()
                .unwrap()
                .to_owned();
            let instance = response.headers()["x-herdr-a2a-instance"]
                .to_str()
                .unwrap()
                .to_owned();
            let body = response.bytes().await.unwrap();
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\nx-herdr-a2a-status-proof: {proof}\r\nx-herdr-a2a-instance: {instance}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            stream.write_all(&body).await.unwrap();
        }
    });
    let descriptor = RuntimeDescriptor {
        session_key: "session-key".to_owned(),
        workspace_id: "test-workspace".to_owned(),
        base_url: broker.base_url().to_owned(),
        bearer_token: broker.bearer_token().to_owned(),
        broker_instance_id: broker.broker_instance_id().to_owned(),
        executable_path: PathBuf::from("/private/test/herdr-a2a"),
        broker_pid: 1,
        created_unix_ms: 1,
    };
    let _environment = EnvironmentGuard::set(&[
        ("HTTP_PROXY", OsStr::new(&proxy_url)),
        ("http_proxy", OsStr::new(&proxy_url)),
        ("ALL_PROXY", OsStr::new(&proxy_url)),
        ("all_proxy", OsStr::new(&proxy_url)),
        ("NO_PROXY", OsStr::new("")),
        ("no_proxy", OsStr::new("")),
    ]);

    let collected = status::collect_from_descriptor(&descriptor).await.unwrap();

    assert_eq!(collected.workspace_id, "test-workspace");
    assert_eq!(
        (
            proof_hits.load(Ordering::SeqCst),
            bearer_seen.load(Ordering::SeqCst)
        ),
        (0, false)
    );
    proxy.abort();
}

#[test]
fn doctor_maps_typed_status_failures_without_storage_collapse() {
    // Break caught: every failure after an initial proof is mislabeled as durable storage
    // divergence, hiding listener turnover, transport loss, and malformed status responses.
    for (error, expected) in [
        (
            OperationsError::BrokerProofFailed,
            DoctorIssue::BrokerProofFailed,
        ),
        (
            OperationsError::BrokerUnavailable,
            DoctorIssue::BrokerUnavailable,
        ),
        (
            OperationsError::InvalidResponse,
            DoctorIssue::BrokerStatusInvalid,
        ),
        (
            OperationsError::StorageReconciliationFailed,
            DoctorIssue::StorageReconciliationFailed,
        ),
    ] {
        assert_eq!(doctor::issue_for_operations_error(error), expected);
    }
}

#[tokio::test]
async fn doctor_maps_single_status_exchange_listener_turnover_to_unavailable() {
    // Break caught: an incomplete single status exchange is mislabeled as proof or storage
    // failure instead of listener availability.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let token = "turnover-private-token";
    let instance = URL_SAFE_NO_PAD.encode([0x41; 32]);
    let descriptor = RuntimeDescriptor {
        session_key: "session-key".to_owned(),
        workspace_id: "test-workspace".to_owned(),
        base_url,
        bearer_token: token.to_owned(),
        broker_instance_id: instance.clone(),
        executable_path: PathBuf::from("/private/test/herdr-a2a"),
        broker_pid: 1,
        created_unix_ms: 1,
    };
    let proof_hits = Arc::new(AtomicUsize::new(0));
    let server_hits = Arc::clone(&proof_hits);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 2048];
        loop {
            let read = stream.read(&mut buffer).await.unwrap();
            request.extend_from_slice(&buffer[..read]);
            if read == 0 || request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        server_hits.fetch_add(1, Ordering::SeqCst);
        assert!(
            String::from_utf8(request)
                .unwrap()
                .starts_with("GET /health/status/")
        );
    });

    let issue = doctor::inspect_descriptor(&descriptor).await;

    assert_eq!(issue, Some(DoctorIssue::BrokerUnavailable));
    assert_eq!(proof_hits.load(Ordering::SeqCst), 1);
    server.await.unwrap();
}

#[tokio::test]
async fn proved_listener_rebind_never_receives_a_bearer_or_second_request() {
    // Break caught: a valid proof response is followed by a separately authenticated request, so
    // a replacement listener on the same port receives the descriptor bearer without proving it.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let base_url = format!("http://{address}");
    let token = "rebind-private-bearer";
    let instance = URL_SAFE_NO_PAD.encode([0x63; 32]);
    let descriptor = RuntimeDescriptor {
        session_key: "session-key".to_owned(),
        workspace_id: "test-workspace".to_owned(),
        base_url,
        bearer_token: token.to_owned(),
        broker_instance_id: instance.clone(),
        executable_path: PathBuf::from("/private/test/herdr-a2a"),
        broker_pid: 1,
        created_unix_ms: 1,
    };
    let token = token.to_owned();
    let server = tokio::spawn(async move {
        let (mut proved_stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 2048];
        loop {
            let read = proved_stream.read(&mut buffer).await.unwrap();
            request.extend_from_slice(&buffer[..read]);
            if read == 0 || request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8(request).unwrap();
        let target = request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap();
        let initial_bearer = request.lines().any(|line| {
            line.to_ascii_lowercase()
                .starts_with("authorization: bearer ")
        });
        let nonce_text = target.rsplit('/').next().unwrap();
        let nonce = URL_SAFE_NO_PAD.decode(nonce_text).unwrap();
        drop(listener);
        let replacement = TcpListener::bind(address).await.unwrap();

        if target.starts_with("/health/proof/") {
            let key = Sha256::digest(token.as_bytes());
            let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
            mac.update(b"herdr-a2a-proof-v2\0");
            mac.update(instance.as_bytes());
            mac.update(&nonce);
            let proof = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
            proved_stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nx-herdr-a2a-health-proof: {proof}\r\nx-herdr-a2a-instance: {instance}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        } else {
            let body = br#"{"workspace_id":"test-workspace","broker":"healthy","storage":"reconciled","registrations":0,"agents":[],"tasks":{"queued":0,"leased":0,"waiting_reply":0,"terminal":0},"last_event":null}"#;
            let key = Sha256::digest(token.as_bytes());
            let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
            mac.update(b"herdr-a2a-status-v1\0");
            mac.update(instance.as_bytes());
            mac.update(&nonce);
            mac.update(body);
            let proof = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
            proved_stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nx-herdr-a2a-status-proof: {proof}\r\nx-herdr-a2a-instance: {instance}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        }
        proved_stream.shutdown().await.unwrap();

        match tokio::time::timeout(Duration::from_secs(1), replacement.accept()).await {
            Ok(Ok((mut stream, _))) => {
                let mut request = Vec::new();
                stream.read_to_end(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request);
                let bearer = request.lines().any(|line| {
                    line.to_ascii_lowercase()
                        .starts_with("authorization: bearer ")
                });
                (initial_bearer, true, bearer)
            }
            _ => (initial_bearer, false, false),
        }
    });

    let result = status::collect_from_descriptor(&descriptor).await;
    let replacement_observation = server.await.unwrap();

    assert!(result.is_err());
    assert_eq!(replacement_observation, (false, false, false));
}

#[tokio::test]
async fn status_challenge_response_has_one_deadline() {
    // Break caught: the one status challenge/response exchange can exceed its documented bound.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let token = "one-deadline-private-token";
    let instance = URL_SAFE_NO_PAD.encode([0x52; 32]);
    let descriptor = RuntimeDescriptor {
        session_key: "session-key".to_owned(),
        workspace_id: "test-workspace".to_owned(),
        base_url,
        bearer_token: token.to_owned(),
        broker_instance_id: instance.clone(),
        executable_path: PathBuf::from("/private/test/herdr-a2a"),
        broker_pid: 1,
        created_unix_ms: 1,
    };
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 2048];
        loop {
            let read = stream.read(&mut buffer).await.unwrap();
            request.extend_from_slice(&buffer[..read]);
            if read == 0 || request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        assert!(
            String::from_utf8(request)
                .unwrap()
                .starts_with("GET /health/status/")
        );
        tokio::time::sleep(Duration::from_secs(4)).await;
    });

    let result = status::collect_from_descriptor(&descriptor).await;

    assert_eq!(result, Err(OperationsError::BrokerUnavailable));
    server.abort();
}

#[tokio::test]
async fn doctor_reports_owned_pi_conflict_without_repairing_it() {
    // Break caught: observational Doctor silently treats or repairs a modified owned Pi entry.
    let original_settings = b"{\"packages\":[\"user-choice\"]}\n";
    let fixture = ManagedDoctorFixture::new(
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_VERSION"),
        "0.84.2",
    );
    fs::write(&fixture.settings, original_settings).unwrap();
    let _environment = fixture.environment();

    let report = doctor::collect().await;

    assert_eq!(report.overall, DoctorState::Failed);
    assert_eq!(report.primary_code(), Some("pi_owned_entry_modified"));
    assert_eq!(fs::read(&fixture.settings).unwrap(), original_settings);
}

#[tokio::test]
async fn doctor_independently_validates_owned_assets_and_component_versions() {
    // Break caught: a typed Ready ownership record masks missing/modified binary or adapter
    // assets and incompatible plugin, binary, adapter, or Pi versions.
    let cases = [
        ("missing_ownership", "managed_ownership_invalid"),
        ("ownership_schema", "incompatible_version"),
        ("modified_binary", "managed_binary_modified"),
        ("missing_adapter", "managed_adapter_modified"),
        ("plugin_version", "plugin_version_incompatible"),
        ("binary_version", "binary_version_incompatible"),
        ("adapter_metadata", "adapter_metadata_incompatible"),
        ("adapter_version", "adapter_version_incompatible"),
        ("pi_version", "pi_version_incompatible"),
    ];
    for (kind, expected) in cases {
        let (record, plugin, adapter, pi) = match kind {
            "plugin_version" => (
                env!("CARGO_PKG_VERSION"),
                "9.8.7",
                env!("CARGO_PKG_VERSION"),
                "0.84.2",
            ),
            "binary_version" => ("9.8.7", "9.8.7", "9.8.7", "0.84.2"),
            "adapter_version" => (
                env!("CARGO_PKG_VERSION"),
                env!("CARGO_PKG_VERSION"),
                "9.8.7",
                "0.84.2",
            ),
            "pi_version" => (
                env!("CARGO_PKG_VERSION"),
                env!("CARGO_PKG_VERSION"),
                env!("CARGO_PKG_VERSION"),
                "0.84.1",
            ),
            _ => (
                env!("CARGO_PKG_VERSION"),
                env!("CARGO_PKG_VERSION"),
                env!("CARGO_PKG_VERSION"),
                "0.84.2",
            ),
        };
        let fixture = ManagedDoctorFixture::new(record, plugin, adapter, pi);
        match kind {
            "missing_ownership" => fs::remove_file(&fixture.ownership).unwrap(),
            "ownership_schema" => {
                let mut record: serde_json::Value =
                    serde_json::from_slice(&fs::read(&fixture.ownership).unwrap()).unwrap();
                record["schema_version"] = json!(2);
                record.as_object_mut().unwrap().remove("purge_authority");
                record
                    .as_object_mut()
                    .unwrap()
                    .remove("rescue_marker_digest");
                fs::write(&fixture.ownership, serde_json::to_vec(&record).unwrap()).unwrap();
            }
            "modified_binary" => fs::write(&fixture.stable_binary, b"modified").unwrap(),
            "missing_adapter" => fs::remove_file(&fixture.package_manifest).unwrap(),
            "adapter_metadata" => fixture.replace_adapter_manifest_and_refresh_ownership(json!({
                "name": "@other/a2a-pi",
                "version": env!("CARGO_PKG_VERSION")
            })),
            _ => {}
        }
        let _environment = fixture.environment();
        let report = doctor::collect().await;
        assert_eq!(report.primary_code(), Some(expected), "{kind}: {report:?}");
        match kind {
            "missing_ownership" => assert!(!fixture.ownership.exists()),
            "modified_binary" => assert_eq!(fs::read(&fixture.stable_binary).unwrap(), b"modified"),
            "missing_adapter" => assert!(!fixture.package_manifest.exists()),
            _ => {}
        }
    }
}

#[test]
fn doctor_uses_stable_codes_for_every_fail_closed_case() {
    // Break caught: a diagnosis branch becomes free-form text or collapses distinct recovery
    // conditions into one unsafe generic repair result.
    for (issue, code) in [
        (DoctorIssue::PiOwnedEntryModified, "pi_owned_entry_modified"),
        (DoctorIssue::PiAdapterPending, "pi_adapter_pending"),
        (
            DoctorIssue::BrokerDescriptorStale,
            "broker_descriptor_stale",
        ),
        (DoctorIssue::BrokerProofFailed, "broker_proof_failed"),
        (
            DoctorIssue::StorageReconciliationFailed,
            "storage_reconciliation_failed",
        ),
        (
            DoctorIssue::LegacySessionDataPresent,
            "legacy_session_data_present",
        ),
        (
            DoctorIssue::UnsafeStatePermissions,
            "unsafe_state_permissions",
        ),
        (DoctorIssue::IncompatibleVersion, "incompatible_version"),
        (
            DoctorIssue::AdapterRegistrationMissing,
            "adapter_registration_missing",
        ),
        (DoctorIssue::BrokerNotRunning, "broker_not_running"),
        (DoctorIssue::BrokerUnavailable, "broker_unavailable"),
        (DoctorIssue::BrokerStatusInvalid, "broker_status_invalid"),
        (
            DoctorIssue::ManagedOwnershipInvalid,
            "managed_ownership_invalid",
        ),
        (
            DoctorIssue::ManagedBinaryModified,
            "managed_binary_modified",
        ),
        (
            DoctorIssue::ManagedAdapterModified,
            "managed_adapter_modified",
        ),
        (
            DoctorIssue::PluginVersionIncompatible,
            "plugin_version_incompatible",
        ),
        (
            DoctorIssue::BinaryVersionIncompatible,
            "binary_version_incompatible",
        ),
        (
            DoctorIssue::AdapterMetadataIncompatible,
            "adapter_metadata_incompatible",
        ),
        (
            DoctorIssue::AdapterVersionIncompatible,
            "adapter_version_incompatible",
        ),
        (
            DoctorIssue::PiVersionIncompatible,
            "pi_version_incompatible",
        ),
    ] {
        let report = evaluate_evidence(&DoctorEvidence::with_issue(issue));
        assert_eq!(report.primary_code(), Some(code), "{code}");
    }
}

#[tokio::test]
#[cfg(feature = "test-harness")]
async fn coordinated_restart_preserves_an_in_flight_task_identity() {
    // Break caught: public coordinated restart changes the workspace state root or descriptor
    // generation and the replacement broker cannot deliver the exact SQLite-retained task.
    let fixture = RestartFixture::new();
    let mut coordinator = fixture.command(&["coordinator", "serve"]).spawn().unwrap();
    let original = fixture.wait_for_descriptor().await;
    let mut sender = fixture.client("w1:p1", "sender-session");
    let mut recipient = fixture.client("w1:p2", "recipient-session");
    sender
        .send(json!({"id":"sender-ready","method":"list_agents","params":{}}))
        .await;
    recipient
        .send(json!({"id":"recipient-ready","method":"list_agents","params":{}}))
        .await;
    assert_eq!(sender.recv().await["id"], "sender-ready");
    assert_eq!(recipient.recv().await["id"], "recipient-ready");
    sender
        .send(json!({
            "id":"send-before-restart",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"survive immediate restart","wait":false}
        }))
        .await;
    let sent = sender.recv().await;
    let task_id = sent["result"]["task_id"]
        .as_str()
        .expect("send did not return a task identity")
        .to_owned();

    let restart = tokio::time::timeout(
        Duration::from_secs(15),
        fixture.command(&["restart"]).output(),
    )
    .await
    .expect("restart exceeded its one deadline")
    .unwrap();
    assert!(
        restart.status.success(),
        "restart failed: {}",
        String::from_utf8_lossy(&restart.stderr)
    );
    let replacement = fixture.wait_for_descriptor().await;
    assert_ne!(replacement.broker_instance_id, original.broker_instance_id);

    recipient
        .send(json!({
            "id":"receive-after-restart",
            "method":"wait_for_message",
            "params":{"timeout_ms":5_000}
        }))
        .await;
    let delivery = recipient.recv().await;
    assert_eq!(delivery["id"], "receive-after-restart", "{delivery}");
    assert_eq!(delivery["result"]["task_id"], task_id, "{delivery}");
    assert_eq!(
        delivery["result"]["payload"]["text"],
        "survive immediate restart"
    );

    sender.close().await;
    recipient.close().await;
    let stop = fixture
        .command(&["coordinator", "stop"])
        .output()
        .await
        .unwrap();
    assert!(stop.status.success());
    tokio::time::timeout(Duration::from_secs(5), coordinator.wait())
        .await
        .expect("original coordinator did not retire")
        .unwrap();
}

#[tokio::test]
#[cfg(feature = "test-harness")]
async fn coordinated_restart_gives_replacement_a_fresh_launch_deadline_after_slow_stop() {
    // Break caught: restart reuses its pre-stop deadline for replacement launch, so a bounded
    // broker retirement plus bounded restart bookkeeping exhausts the launch budget and reports
    // a false failure even though the replacement appears within its normal launch window.
    let fixture = RestartFixture::new();
    let marker = fixture.root.path().join("restart-stop.marker");
    let mut original_coordinator = fixture.command(&["coordinator", "serve"]).spawn().unwrap();
    let original = fixture.wait_for_descriptor().await;

    let mut restart = fixture.command(&["restart"]);
    restart
        .env(
            "HERDR_A2A_TEST_STARTING_BOUNDARY",
            "after-restart-stop-before-replacement-deadline",
        )
        .env("HERDR_A2A_TEST_STARTING_MARKER", &marker);
    let mut restart = restart.spawn().unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !marker.exists() {
            if let Some(status) = restart.try_wait().unwrap() {
                let mut stderr = String::new();
                restart
                    .stderr
                    .take()
                    .unwrap()
                    .read_to_string(&mut stderr)
                    .await
                    .unwrap();
                panic!("restart exited before the deadline boundary {status}: {stderr}");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("restart did not reach the controlled broker-stop boundary");
    tokio::time::sleep(Duration::from_secs(11)).await;
    fs::write(marker.with_extension("release"), b"continue\n").unwrap();
    let output = tokio::time::timeout(Duration::from_secs(20), restart.wait_with_output())
        .await
        .expect("restart exceeded the stop plus fresh launch deadlines")
        .unwrap();

    assert!(
        output.status.success(),
        "restart reused its pre-stop deadline: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let replacement = fixture.wait_for_descriptor().await;
    let stop = fixture
        .command(&["coordinator", "stop"])
        .output()
        .await
        .unwrap();
    assert!(stop.status.success());
    tokio::time::timeout(Duration::from_secs(5), original_coordinator.wait())
        .await
        .expect("original coordinator did not retire")
        .unwrap();

    assert_ne!(replacement.broker_instance_id, original.broker_instance_id);
}

#[tokio::test]
#[cfg(feature = "test-harness")]
async fn coordinated_restart_accepts_auto_recovery_after_original_processes_retire() {
    // Break caught: an idle Pi client's automatic recovery can win the coordinator lock after
    // the original generation retires but before restart observes the unlocked boundary. Restart
    // must accept only that healthy replacement after proving both original processes are gone.
    let fixture = RestartFixture::new();
    let mut original_coordinator = fixture.command(&["coordinator", "serve"]).spawn().unwrap();
    let original = tokio::select! {
        descriptor = fixture.wait_for_descriptor() => descriptor,
        status = original_coordinator.wait() => {
            let mut stderr = String::new();
            original_coordinator
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .await
                .unwrap();
            panic!("original coordinator exited {}: {stderr}", status.unwrap());
        }
    };
    fixture
        .wait_for_coordinator_instance(&original.broker_instance_id)
        .await;
    let marker = fixture.root.path().join("restart-stop-request.marker");
    let mut restart = fixture.command(&["restart"]);
    restart
        .env(
            "HERDR_A2A_TEST_STARTING_BOUNDARY",
            "after-stop-request-before-lock-check",
        )
        .env("HERDR_A2A_TEST_STARTING_MARKER", &marker);
    let mut restart = restart.spawn().unwrap();

    tokio::time::timeout(Duration::from_secs(10), async {
        while !marker.exists() {
            if let Some(status) = restart.try_wait().unwrap() {
                let mut stderr = String::new();
                restart
                    .stderr
                    .take()
                    .unwrap()
                    .read_to_string(&mut stderr)
                    .await
                    .unwrap();
                panic!("restart exited before the recovery race boundary {status}: {stderr}");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("restart did not reach the post-stop-request boundary");
    tokio::time::timeout(Duration::from_secs(5), original_coordinator.wait())
        .await
        .expect("original coordinator did not retire while restart was paused")
        .unwrap();
    let mut replacement_coordinator = fixture.command(&["coordinator", "serve"]).spawn().unwrap();
    let replacement = tokio::select! {
        descriptor = fixture.wait_for_descriptor() => descriptor,
        status = replacement_coordinator.wait() => {
            fs::write(marker.with_extension("release"), b"continue\n").unwrap();
            let mut stderr = String::new();
            replacement_coordinator
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .await
                .unwrap();
            panic!("replacement coordinator exited {}: {stderr}", status.unwrap());
        }
    };
    assert_ne!(replacement.broker_instance_id, original.broker_instance_id);
    fs::write(marker.with_extension("release"), b"continue\n").unwrap();

    let output = tokio::time::timeout(Duration::from_secs(15), restart.wait_with_output())
        .await
        .expect("restart did not settle after automatic recovery")
        .unwrap();
    let stop = fixture
        .command(&["coordinator", "stop"])
        .output()
        .await
        .unwrap();
    assert!(stop.status.success());
    tokio::time::timeout(Duration::from_secs(5), replacement_coordinator.wait())
        .await
        .expect("replacement coordinator did not retire")
        .unwrap();

    assert!(
        output.status.success(),
        "restart rejected a proved post-retirement replacement: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
#[cfg(feature = "test-harness")]
async fn coordinated_restart_accepts_a_fully_proved_descriptor_published_after_absence() {
    // Break caught: the descriptor-absent route rejects a replacement that is published only
    // after both original processes retire despite exact descriptor, lock, and process proofs.
    let fixture = RestartFixture::new();
    let mut original_coordinator = fixture.command(&["coordinator", "serve"]).spawn().unwrap();
    let original = fixture.wait_for_descriptor().await;
    let marker = fixture.root.path().join("descriptor-absence-valid.marker");
    let restart =
        pause_restart_after_descriptor_absence(&fixture, &mut original_coordinator, &marker).await;

    let mut replacement_coordinator = fixture.command(&["coordinator", "serve"]).spawn().unwrap();
    let replacement = fixture.wait_for_descriptor().await;
    assert_ne!(replacement.broker_instance_id, original.broker_instance_id);
    release_restart(&marker);
    let output = tokio::time::timeout(Duration::from_secs(15), restart.wait_with_output())
        .await
        .expect("restart did not validate the post-absence replacement")
        .unwrap();

    let stop = fixture
        .command(&["coordinator", "stop"])
        .output()
        .await
        .unwrap();
    assert!(stop.status.success());
    tokio::time::timeout(Duration::from_secs(5), replacement_coordinator.wait())
        .await
        .expect("replacement coordinator did not retire")
        .unwrap();
    assert!(
        output.status.success(),
        "restart rejected exact post-absence proof: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
#[cfg(feature = "test-harness")]
async fn coordinated_restart_rejects_a_post_absence_forged_executable() {
    // Break caught: generic ensure health-checks a descriptor but bypasses the retired
    // generation's exact executable proof.
    let fixture = RestartFixture::new();
    let mut original_coordinator = fixture.command(&["coordinator", "serve"]).spawn().unwrap();
    fixture.wait_for_descriptor().await;
    let marker = fixture
        .root
        .path()
        .join("descriptor-absence-forged-executable.marker");
    let restart =
        pause_restart_after_descriptor_absence(&fixture, &mut original_coordinator, &marker).await;

    let mut replacement_coordinator = fixture.command(&["coordinator", "serve"]).spawn().unwrap();
    let mut forged = fixture.wait_for_descriptor().await;
    fixture
        .wait_for_coordinator_instance(&forged.broker_instance_id)
        .await;
    forged.executable_path = Path::new("/bin/sh").canonicalize().unwrap();
    write_descriptor(&fixture.paths(), &forged).unwrap();
    release_restart(&marker);
    let output = tokio::time::timeout(Duration::from_secs(15), restart.wait_with_output())
        .await
        .expect("restart did not reject forged executable proof")
        .unwrap();

    let _ = replacement_coordinator.start_kill();
    let _ = replacement_coordinator.wait().await;
    assert!(
        !output.status.success(),
        "restart adopted a post-absence descriptor with a forged executable"
    );
}

#[tokio::test]
#[cfg(feature = "test-harness")]
async fn coordinated_restart_rejects_a_post_absence_descriptor_without_a_coordinator_lock() {
    // Break caught: generic ensure accepts a healthy broker descriptor with no authenticated
    // coordinator owner after the original descriptor has disappeared.
    let fixture = RestartFixture::new();
    let mut original_coordinator = fixture.command(&["coordinator", "serve"]).spawn().unwrap();
    let original = fixture.wait_for_descriptor().await;
    let marker = fixture
        .root
        .path()
        .join("descriptor-absence-missing-lock.marker");
    let restart =
        pause_restart_after_descriptor_absence(&fixture, &mut original_coordinator, &marker).await;

    let impostor = TestBroker::start().await;
    let forged = RuntimeDescriptor {
        session_key: original.session_key,
        workspace_id: original.workspace_id,
        base_url: impostor.base_url().to_owned(),
        bearer_token: impostor.bearer_token().to_owned(),
        broker_instance_id: impostor.broker_instance_id().to_owned(),
        executable_path: original.executable_path,
        broker_pid: original.broker_pid,
        created_unix_ms: original.created_unix_ms,
    };
    write_descriptor(&fixture.paths(), &forged).unwrap();
    release_restart(&marker);
    let output = tokio::time::timeout(Duration::from_secs(15), restart.wait_with_output())
        .await
        .expect("restart did not reject an ownerless replacement")
        .unwrap();
    assert!(
        !output.status.success(),
        "restart adopted a healthy replacement with no coordinator lock"
    );
}

#[tokio::test]
#[cfg(feature = "test-harness")]
async fn coordinated_restart_rejects_a_post_absence_descriptor_with_a_mismatched_lock() {
    // Break caught: generic ensure accepts a healthy descriptor even when the locked coordinator
    // record owns a different broker generation.
    let fixture = RestartFixture::new();
    let mut original_coordinator = fixture.command(&["coordinator", "serve"]).spawn().unwrap();
    fixture.wait_for_descriptor().await;
    let marker = fixture
        .root
        .path()
        .join("descriptor-absence-mismatched-lock.marker");
    let restart =
        pause_restart_after_descriptor_absence(&fixture, &mut original_coordinator, &marker).await;

    let mut replacement_coordinator = fixture.command(&["coordinator", "serve"]).spawn().unwrap();
    let replacement = fixture.wait_for_descriptor().await;
    let replacement_instance = replacement.broker_instance_id.clone();
    fixture
        .wait_for_coordinator_instance(&replacement_instance)
        .await;
    let impostor = TestBroker::start().await;
    let forged = RuntimeDescriptor {
        session_key: replacement.session_key,
        workspace_id: replacement.workspace_id,
        base_url: impostor.base_url().to_owned(),
        bearer_token: impostor.bearer_token().to_owned(),
        broker_instance_id: impostor.broker_instance_id().to_owned(),
        executable_path: replacement.executable_path,
        broker_pid: replacement.broker_pid,
        created_unix_ms: replacement.created_unix_ms,
    };
    write_descriptor(&fixture.paths(), &forged).unwrap();
    assert!(
        replacement_coordinator.try_wait().unwrap().is_none(),
        "replacement coordinator exited before the mismatched-lock check"
    );
    let locked_record = fixture
        .wait_for_coordinator_instance(&replacement_instance)
        .await;
    assert_eq!(
        locked_record["broker_instance_id"], replacement_instance,
        "coordinator lock did not retain the proved replacement instance"
    );
    assert_ne!(
        locked_record["broker_instance_id"], forged.broker_instance_id,
        "mismatched-lock fixture accidentally published a matching instance"
    );
    release_restart(&marker);
    let output = tokio::time::timeout(Duration::from_secs(15), restart.wait_with_output())
        .await
        .expect("restart did not reject mismatched coordinator ownership")
        .unwrap();

    let _ = replacement_coordinator.start_kill();
    let _ = replacement_coordinator.wait().await;
    assert!(
        !output.status.success(),
        "restart adopted a descriptor whose coordinator lock owned another instance"
    );
}

#[tokio::test]
#[cfg(feature = "test-harness")]
async fn coordinated_restart_preserves_an_in_flight_task_through_post_absence_recovery() {
    // Break caught: the strictly validated descriptor-absence recovery path loses the durable
    // task identity while replacing the retired broker.
    let fixture = RestartFixture::new();
    let mut original_coordinator = fixture.command(&["coordinator", "serve"]).spawn().unwrap();
    fixture.wait_for_descriptor().await;
    let mut sender = fixture.client("w1:p1", "post-absence-sender");
    let mut recipient = fixture.client("w1:p2", "post-absence-recipient");
    sender
        .send(json!({"id":"sender-ready","method":"list_agents","params":{}}))
        .await;
    recipient
        .send(json!({"id":"recipient-ready","method":"list_agents","params":{}}))
        .await;
    assert_eq!(sender.recv().await["id"], "sender-ready");
    assert_eq!(recipient.recv().await["id"], "recipient-ready");
    sender
        .send(json!({
            "id":"send-before-absence",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"survive validated post-absence recovery","wait":false}
        }))
        .await;
    let sent = sender.recv().await;
    let task_id = sent["result"]["task_id"].as_str().unwrap().to_owned();

    let marker = fixture
        .root
        .path()
        .join("descriptor-absence-in-flight.marker");
    let restart =
        pause_restart_after_descriptor_absence(&fixture, &mut original_coordinator, &marker).await;
    let mut replacement_coordinator = fixture.command(&["coordinator", "serve"]).spawn().unwrap();
    fixture.wait_for_descriptor().await;
    release_restart(&marker);
    let output = tokio::time::timeout(Duration::from_secs(15), restart.wait_with_output())
        .await
        .expect("restart did not settle after post-absence recovery")
        .unwrap();
    assert!(
        output.status.success(),
        "proved post-absence recovery failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    recipient
        .send(json!({
            "id":"receive-after-absence",
            "method":"wait_for_message",
            "params":{"timeout_ms":5_000}
        }))
        .await;
    let delivery = recipient.recv().await;
    assert_eq!(delivery["id"], "receive-after-absence", "{delivery}");
    assert_eq!(delivery["result"]["task_id"], task_id, "{delivery}");
    assert_eq!(
        delivery["result"]["payload"]["text"],
        "survive validated post-absence recovery"
    );

    sender.close().await;
    recipient.close().await;
    let stop = fixture
        .command(&["coordinator", "stop"])
        .output()
        .await
        .unwrap();
    assert!(stop.status.success());
    tokio::time::timeout(Duration::from_secs(5), replacement_coordinator.wait())
        .await
        .expect("replacement coordinator did not retire")
        .unwrap();
}

#[tokio::test]
#[cfg(feature = "test-harness")]
async fn coordinated_restart_replacement_launch_deadline_is_capped_at_ten_seconds() {
    // Break caught: DEFAULT_ENSURE_TIMEOUT is relaxed above ten seconds while broad restart
    // tests retain larger outer timeouts and therefore remain green.
    let fixture = RestartFixture::new();
    let mut original_coordinator = fixture.command(&["coordinator", "serve"]).spawn().unwrap();
    fixture.wait_for_descriptor().await;
    let marker = fixture.root.path().join("replacement-reservation.marker");
    let mut restart = fixture.command(&["restart"]);
    restart
        .env(
            "HERDR_A2A_TEST_STARTING_BOUNDARY",
            "after-coordinator-reservation",
        )
        .env("HERDR_A2A_TEST_STARTING_MARKER", &marker);
    let mut restart = restart.spawn().unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !marker.exists() {
            if restart.try_wait().unwrap().is_some() {
                panic!("restart exited before replacement reservation");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("replacement coordinator did not reach reservation boundary");
    tokio::time::timeout(Duration::from_secs(5), original_coordinator.wait())
        .await
        .expect("original coordinator did not retire")
        .unwrap();

    let bounded = tokio::time::timeout(Duration::from_secs(12), restart.wait()).await;
    release_restart(&marker);
    let mut stderr = String::new();
    if bounded.is_err() {
        let _ = restart.start_kill();
        let _ = restart.wait().await;
    }
    restart
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .await
        .unwrap();
    let replacement = fixture.wait_for_descriptor().await;
    let stop = fixture
        .command(&["coordinator", "stop"])
        .output()
        .await
        .unwrap();
    assert!(stop.status.success());
    assert_ne!(replacement.broker_instance_id, "");

    let status = bounded.expect("replacement launch exceeded the strict 12-second outer cap");
    assert!(!status.unwrap().success(), "restart unexpectedly succeeded");
    assert!(
        stderr.contains("broker launch deadline expired"),
        "restart did not report its bounded launch deadline: {stderr}"
    );
}

#[tokio::test]
async fn doctor_rejects_logically_divergent_sqlite_without_mutating_it() {
    // Break caught: PRAGMA quick_check accepts a structurally valid database whose public task
    // projection no longer matches the durable delivery ledger.
    let fixture = tempfile::tempdir().unwrap();
    let database = fixture.path().canonicalize().unwrap().join("tasks.sqlite3");
    let store = SqliteTaskStore::open(&database).unwrap();
    let (broker, _) = herdr_a2a_broker::server::recover_broker_state(SystemClock, &store)
        .await
        .unwrap();
    let sender = broker
        .register(agent("sender-k7m2", "w1:p1"), "pi-a")
        .await
        .unwrap();
    broker
        .register(agent("reviewer-r8c1", "w1:p2"), "pi-b")
        .await
        .unwrap();
    broker
        .enqueue(
            &sender.credentials(),
            QueuedDelivery {
                task_id: "task-logically-divergent".to_owned(),
                context_id: "context-original".to_owned(),
                sender: AgentName::parse("sender-k7m2").unwrap(),
                recipient: AgentName::parse("reviewer-r8c1").unwrap(),
                payload: ValidatedPayload {
                    text: "review this".to_owned(),
                    metadata: json!({}),
                    file_refs: Vec::new(),
                },
                created_unix_ms: 0,
                attempt: 0,
            },
        )
        .await
        .unwrap();
    drop(broker);
    drop(store);
    let connection = rusqlite::Connection::open(&database).unwrap();
    connection
        .execute(
            "UPDATE tasks SET context_id = 'context-divergent' WHERE task_id = 'task-logically-divergent'",
            [],
        )
        .unwrap();
    drop(connection);
    fs::set_permissions(&database, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        doctor::inspect_database(&database),
        Some(DoctorIssue::UnsafeStatePermissions)
    );
    fs::set_permissions(&database, fs::Permissions::from_mode(0o600)).unwrap();
    let before = fs::read(&database).unwrap();

    assert_eq!(
        doctor::inspect_database(&database),
        Some(DoctorIssue::StorageReconciliationFailed)
    );
    assert_eq!(fs::read(&database).unwrap(), before);
}

#[tokio::test]
#[cfg(feature = "test-harness")]
async fn coordinated_restart_fails_closed_when_the_proved_instance_turns_over() {
    // Break caught: a blind stop/ensure sequence accepts an unrelated but valid descriptor that
    // replaces the originally owned broker generation during restart.
    let fixture = RestartFixture::new();
    let mut coordinator = fixture.command(&["coordinator", "serve"]).spawn().unwrap();
    let original = fixture.wait_for_descriptor().await;
    fixture
        .wait_for_coordinator_instance(&original.broker_instance_id)
        .await;
    let impostor = TestBroker::start().await;
    let forged = RuntimeDescriptor {
        session_key: original.session_key.clone(),
        workspace_id: original.workspace_id.clone(),
        base_url: impostor.base_url().to_owned(),
        bearer_token: impostor.bearer_token().to_owned(),
        broker_instance_id: impostor.broker_instance_id().to_owned(),
        executable_path: original.executable_path.clone(),
        broker_pid: original.broker_pid,
        created_unix_ms: original.created_unix_ms,
    };
    write_descriptor(&fixture.paths(), &forged).unwrap();

    let output = tokio::time::timeout(
        Duration::from_secs(15),
        fixture.command(&["restart"]).output(),
    )
    .await
    .expect("restart exceeded its one bounded deadline")
    .unwrap();
    assert!(
        !output.status.success(),
        "restart adopted a changed broker instance"
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains(impostor.bearer_token()));
    assert_eq!(
        read_descriptor(&fixture.paths())
            .unwrap()
            .broker_instance_id,
        impostor.broker_instance_id()
    );
    assert!(
        coordinator.try_wait().unwrap().is_none(),
        "restart stopped a coordinator whose owned broker was not the proved instance"
    );

    let _ = coordinator.start_kill();
    let _ = coordinator.wait().await;
}

#[test]
fn tui_snapshot_is_redacted_and_only_documented_keys_mutate_state() {
    // Break caught: the operations pane gains task/message drill-down or undocumented keys that
    // can mutate state.
    let status = WorkspaceStatus::healthy_fixture("workspace-one");
    let snapshot = render(&TuiState::new(status.clone()));
    assert!(snapshot.contains("Herdr A2A · workspace: workspace-one"));
    assert!(snapshot.contains("[d] Doctor  [l] Logs  [r] Restart broker  [q] Close"));
    assert!(!snapshot.contains("task-"));
    assert!(!snapshot.contains("message"));

    let mut log_view = TuiState::new(status.clone());
    log_view.show_logs(vec![
        "connected with 9fd2a3c1-secret-value".to_owned(),
        "/private/workspace/operator-name".to_owned(),
    ]);
    let rendered_logs = render(&log_view);
    assert!(!rendered_logs.contains("9fd2a3c1-secret-value"));
    assert!(!rendered_logs.contains("/private/workspace/operator-name"));
    assert!(rendered_logs.contains("[redacted operational log line]"));

    for key in ['a', 'x', '1', '\n', '\u{1b}'] {
        let mut state = TuiState::new(status.clone());
        let before = state.clone();
        assert_eq!(state.handle_key(key), TuiCommand::None);
        assert_eq!(state, before, "undocumented key {key:?} mutated state");
    }

    let mut doctor = TuiState::new(status.clone());
    assert_eq!(doctor.handle_key('d'), TuiCommand::RunDoctor);
    assert_eq!(doctor.view, TuiView::Doctor);
    let mut logs = TuiState::new(status.clone());
    assert_eq!(logs.handle_key('l'), TuiCommand::ShowLogs);
    assert_eq!(logs.view, TuiView::Logs);
    let mut restart = TuiState::new(status.clone());
    assert_eq!(restart.handle_key('r'), TuiCommand::ConfirmRestart);
    assert_eq!(restart.view, TuiView::RestartConfirmation);
    let mut quit = TuiState::new(status);
    assert_eq!(quit.handle_key('q'), TuiCommand::Quit);
    assert!(quit.quit);
}

struct RecordingTuiBackend {
    restarts: AtomicUsize,
    doctors: AtomicUsize,
    logs: AtomicUsize,
}

#[async_trait]
impl status_tui::TuiBackend for RecordingTuiBackend {
    async fn status(&self) -> Result<WorkspaceStatus, String> {
        Ok(WorkspaceStatus::healthy_fixture("workspace-one"))
    }

    async fn doctor(&self) -> doctor::DoctorReport {
        self.doctors.fetch_add(1, Ordering::SeqCst);
        evaluate_evidence(&DoctorEvidence::default())
    }

    async fn restart(&self) -> Result<WorkspaceStatus, String> {
        self.restarts.fetch_add(1, Ordering::SeqCst);
        Ok(WorkspaceStatus::healthy_fixture("workspace-one"))
    }

    async fn logs(&self) -> Vec<String> {
        self.logs.fetch_add(1, Ordering::SeqCst);
        vec!["private raw line".to_owned()]
    }
}

#[tokio::test]
async fn tui_backend_accepts_only_unmodified_press_events() {
    // Break caught: key release/repeat or Ctrl/Alt-modified character events participate in
    // restart confirmation and invoke operational backends.
    let backend = RecordingTuiBackend {
        restarts: AtomicUsize::new(0),
        doctors: AtomicUsize::new(0),
        logs: AtomicUsize::new(0),
    };
    let mut state = TuiState::new(WorkspaceStatus::healthy_fixture("workspace-one"));
    for event in [
        KeyEvent::new_with_kind(
            KeyCode::Char('r'),
            KeyModifiers::NONE,
            KeyEventKind::Release,
        ),
        KeyEvent::new_with_kind(KeyCode::Char('r'), KeyModifiers::NONE, KeyEventKind::Repeat),
        KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL),
        KeyEvent::new(KeyCode::Char('d'), KeyModifiers::ALT),
        KeyEvent::new(KeyCode::Char('l'), KeyModifiers::SHIFT),
    ] {
        assert!(!status_tui::dispatch_key_event(&mut state, event, &backend).await);
    }
    assert_eq!(state.view, TuiView::Status);
    assert_eq!(backend.restarts.load(Ordering::SeqCst), 0);
    assert_eq!(backend.doctors.load(Ordering::SeqCst), 0);
    assert_eq!(backend.logs.load(Ordering::SeqCst), 0);

    assert!(
        !status_tui::dispatch_key_event(
            &mut state,
            KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE),
            &backend,
        )
        .await
    );
    assert_eq!(state.view, TuiView::RestartConfirmation);
    assert!(
        !status_tui::dispatch_key_event(
            &mut state,
            KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE),
            &backend,
        )
        .await
    );
    assert_eq!(backend.restarts.load(Ordering::SeqCst), 1);
}
