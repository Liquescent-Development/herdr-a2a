use std::{
    fs,
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    sync::{Arc, LazyLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use a2a::{Message, Part, Role, SendMessageConfiguration, SendMessageRequest};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use herdr_a2a_broker::{
    RuntimeDescriptor, RuntimePaths, SessionLock, read_descriptor,
    test_support::{EndpointStall, TestBroker, TestBrokerRuntime},
    write_descriptor,
};
use herdr_a2a_core::DeliveryId;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, Lines},
    net::TcpListener,
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::{OwnedSemaphorePermit, Semaphore, oneshot},
    task::JoinHandle,
};

const MAX_CLIENT_PROCESSES_PER_TEST: usize = 7;
#[cfg(unix)]
const TEST_MANAGED_GENERATION_ID: &str = "0123456789abcdef0123456789abcdef";

static CLIENT_PROCESS_LIMIT: LazyLock<Arc<Semaphore>> = LazyLock::new(|| {
    let parallel_tests = std::thread::available_parallelism()
        .map(|parallelism| parallelism.get())
        .unwrap_or(1);
    // Every default-parallel harness worker may hold one permit before requesting another.
    // Leave enough headroom for the largest live-process scenario to complete and release all
    // of its permits, while still bounding aggregate subprocess pressure.
    Arc::new(Semaphore::new(
        parallel_tests.saturating_add(MAX_CLIENT_PROCESSES_PER_TEST - 1),
    ))
});

const FORGED_TRANSPORT_PREFIXES: [&str; 6] = [
    "HTTP request failed:",
    "failed to fetch agent card:",
    "failed to parse JSON-RPC response:",
    "SSE stream error:",
    "SSE parse error:",
    "operation deadline expired",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginManifest {
    id: String,
    name: String,
    version: String,
    min_herdr_version: String,
    description: String,
    platforms: Vec<String>,
    panes: Vec<PluginPane>,
    build: Vec<PluginBuild>,
    startup: Vec<PluginStartup>,
    actions: Vec<PluginAction>,
    events: Vec<PluginEvent>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginPane {
    id: String,
    title: String,
    placement: String,
    width: String,
    height: String,
    command: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginBuild {
    platforms: Vec<String>,
    command: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginStartup {
    command: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginAction {
    id: String,
    title: String,
    contexts: Vec<String>,
    command: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginEvent {
    on: String,
    command: Vec<String>,
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("CLI crate must be two levels below the workspace root")
        .to_path_buf()
}

#[test]
fn manifest_contract_declares_hidden_workspace_broker_lifecycle() {
    // Break caught: Herdr parses a manifest whose argv or plugin-relative paths target the
    // wrong package, build profile, or executable.
    let root = workspace_root();
    let plugin_root = root.join("plugins/herdr");
    let encoded = fs::read_to_string(plugin_root.join("herdr-plugin.toml"))
        .expect("Herdr plugin manifest must exist");
    let manifest: PluginManifest = toml::from_str(&encoded).expect("manifest must parse as TOML");

    assert_eq!(manifest.id, "herdr.a2a");
    assert_eq!(manifest.name, "Herdr A2A Broker");
    assert_eq!(manifest.version, "0.1.9");
    assert_eq!(manifest.min_herdr_version, "0.8.0");
    assert!(!manifest.description.trim().is_empty());
    assert_eq!(manifest.platforms, ["macos", "linux"]);
    assert_eq!(manifest.panes.len(), 1);
    assert_eq!(manifest.panes[0].id, "status");
    assert_eq!(manifest.panes[0].title, "Herdr A2A status");
    assert_eq!(manifest.panes[0].placement, "popup");
    assert_eq!(manifest.panes[0].width, "80%");
    assert_eq!(manifest.panes[0].height, "70%");
    assert_eq!(
        manifest.panes[0].command,
        [
            "/bin/sh",
            "-c",
            "exec \"$HERDR_PLUGIN_ROOT/libexec/herdr-a2a-dispatch\" coordinator dispatch-exec -- status-tui",
        ]
    );
    assert_eq!(manifest.build.len(), 1);
    assert_eq!(manifest.build[0].platforms, ["macos", "linux"]);
    assert_eq!(manifest.build[0].command, ["bash", "scripts/install.sh"]);
    assert_eq!(manifest.startup.len(), 1);
    assert_eq!(
        manifest.startup[0].command,
        [
            "libexec/herdr-a2a-dispatch",
            "coordinator",
            "dispatch-exec",
            "--",
            "managed",
            "repair",
            "--startup",
        ]
    );
    assert_eq!(manifest.actions.len(), 2);
    assert_eq!(manifest.actions[0].id, "ensure-broker");
    assert_eq!(manifest.actions[0].title, "Ensure workspace A2A broker");
    assert_eq!(manifest.actions[0].contexts, ["workspace", "pane"]);
    assert_eq!(
        manifest.actions[0].command,
        [
            "libexec/herdr-a2a-dispatch",
            "coordinator",
            "dispatch-exec",
            "--",
            "coordinator",
            "serve",
        ]
    );
    assert_eq!(manifest.actions[1].id, "setup-dev");
    assert_eq!(
        manifest.actions[1].title,
        "Build and configure a linked Herdr A2A checkout"
    );
    assert_eq!(manifest.actions[1].contexts, ["global"]);
    assert_eq!(
        manifest.actions[1].command,
        ["bash", "scripts/install.sh", "--dev"]
    );
    assert_eq!(manifest.events.len(), 2);
    assert_eq!(manifest.events[0].on, "workspace.closed");
    assert_eq!(
        manifest.events[0].command,
        [
            "libexec/herdr-a2a-dispatch",
            "coordinator",
            "dispatch-exec",
            "--",
            "coordinator",
            "stop",
        ]
    );
    assert_eq!(manifest.events[1].on, "pane.agent_detected");
    assert_eq!(
        manifest.events[1].command,
        [
            "libexec/herdr-a2a-dispatch",
            "coordinator",
            "dispatch-exec",
            "--",
            "managed",
            "repair",
            "--event",
        ]
    );

    assert!(plugin_root.join(&manifest.build[0].command[1]).is_file());
    let lifecycle_target = Path::new(&manifest.actions[0].command[0]);
    assert!(!lifecycle_target.is_absolute());
    assert!(
        lifecycle_target
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
    );
    assert_eq!(
        manifest.events[0].command[0],
        manifest.actions[0].command[0]
    );
    assert_eq!(
        manifest.startup[0].command[0],
        lifecycle_target.to_str().unwrap()
    );
    assert_eq!(
        manifest.events[1].command[0],
        lifecycle_target.to_str().unwrap()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};

        let script = std::fs::symlink_metadata(plugin_root.join("scripts/dispatch.sh"))
            .expect("checked-in dispatch asset must exist");
        assert!(!script.file_type().is_symlink());
        assert!(!script.file_type().is_socket());
        assert_ne!(script.permissions().mode() & 0o111, 0);
    }
}

#[cfg(unix)]
#[tokio::test]
async fn smoke_diagnostics_read_health_and_agents_without_terminal_input() {
    // Break caught: smoke diagnostics call a mutating Herdr prompt/key API or fail to read the
    // protected descriptor and authenticated broker endpoints used by real Pi sessions.
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    let mut implementer = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    let mut reviewer = ClientSessionProcess::spawn(&broker, "w1:p2", "pi-session-2").await;
    implementer
        .send(json!({"id":"ready-1","method":"list_agents","params":{}}))
        .await;
    reviewer
        .send(json!({"id":"ready-2","method":"list_agents","params":{}}))
        .await;
    assert_eq!(implementer.recv().await["id"], "ready-1");
    assert_eq!(reviewer.recv().await["id"], "ready-2");

    let fixture = tempfile::tempdir().unwrap();
    let (fake_bin, calls) = fake_herdr(
        &fixture,
        r#"[{"pane_id":"w1:p1","agent":"pi","name":"implementer"},{"pane_id":"w1:p2","agent":"pi","name":"reviewer"}]"#,
    );
    let authoritative_herdr = fixture.path().join("authoritative herdr");
    fs::rename(fake_bin.join("herdr"), &authoritative_herdr).unwrap();
    fs::write(fake_bin.join("herdr"), "#!/bin/sh\nexit 97\n").unwrap();
    fs::set_permissions(fake_bin.join("herdr"), fs::Permissions::from_mode(0o700)).unwrap();

    let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
    let mut command = Command::new("bash");
    command
        .arg(root_smoke_script())
        .env("HERDR_ENV", "1")
        .env("HERDR_BIN_PATH", authoritative_herdr)
        .env(
            "PATH",
            format!(
                "{}:{}",
                fake_bin.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        );
    broker.configure_client(command.as_std_mut(), &executable);
    let output = command.output().await.expect("smoke helper must execute");

    assert!(
        output.status.success(),
        "smoke stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Broker health: ok"), "{stdout}");
    assert!(stdout.contains("implementer · implementer-"), "{stdout}");
    assert!(stdout.contains("reviewer · reviewer-"), "{stdout}");
    assert_eq!(
        fs::read_to_string(calls).unwrap(),
        "--version\nagent list\n"
    );

    implementer.close_stdin_and_wait().await;
    reviewer.close_stdin_and_wait().await;
}

#[cfg(unix)]
#[tokio::test]
async fn smoke_diagnostics_print_exact_rename_commands_without_executing_them() {
    // Break caught: an unnamed Pi pane is mutated by the diagnostic or receives ambiguous rename
    // guidance that cannot be pasted as a complete Herdr command.
    let broker = TestBroker::start().await;
    let fixture = tempfile::tempdir().unwrap();
    let (fake_bin, calls) = fake_herdr(
        &fixture,
        r#"[{"pane_id":"w1:p1","agent":"pi"},{"pane_id":"w1:p2","agent":"pi"}]"#,
    );
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
    let mut command = Command::new("bash");
    command
        .arg(root_smoke_script())
        .env("HERDR_ENV", "1")
        .env("HERDR_BIN_PATH", fake_bin.join("herdr"))
        .env(
            "PATH",
            format!(
                "{}:{}",
                fake_bin.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        );
    broker.configure_client(command.as_std_mut(), &executable);
    let output = command.output().await.expect("smoke helper must execute");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains(
            "Name the two Pi agents, then restart their Pi sessions so they register:\n\
             herdr agent rename w1:p1 implementer\n\
             herdr agent rename w1:p2 reviewer\n"
        ),
        "{stderr}"
    );
    assert_eq!(
        fs::read_to_string(calls).unwrap(),
        "--version\nagent list\n"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn smoke_diagnostics_reject_herdr_0_7_before_session_inspection() {
    // Break caught: a pre-0.8 binary reaches agent-list or descriptor inspection even though its
    // plugin/agent contracts are not compatible with this smoke workflow.
    let fixture = tempfile::tempdir().unwrap();
    let (fake_bin, calls) = fake_herdr_version(&fixture, "0.7.9", "[]");
    let output = Command::new("bash")
        .arg(root_smoke_script())
        .env("HERDR_ENV", "1")
        .env(
            "HERDR_SOCKET_PATH",
            "/descriptor/must/not/be/inspected.sock",
        )
        .env("HERDR_WORKSPACE_ID", "test-workspace")
        .env("HERDR_BIN_PATH", fake_bin.join("herdr"))
        .env(
            "PATH",
            format!(
                "{}:{}",
                fake_bin.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .output()
        .await
        .expect("smoke helper must execute");

    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("Herdr 0.8.0 or newer is required"),
        "old Herdr version was not rejected"
    );
    assert_eq!(fs::read_to_string(calls).unwrap(), "--version\n");
}

#[cfg(unix)]
#[tokio::test]
async fn smoke_diagnostics_reject_descriptors_the_pi_client_cannot_restart_from() {
    // Break caught: authenticated health makes smoke pass with a descriptor that the shared Pi
    // protected-discovery loader rejects after a session restart.
    type DescriptorMutation = (&'static str, fn(&mut Value));
    let cases: &[DescriptorMutation] = &[
        ("missing field", |value| {
            value.as_object_mut().unwrap().remove("broker_pid");
        }),
        ("unknown field", |value| {
            value["unexpected"] = json!(true);
        }),
        ("token", |value| {
            value["bearer_token"] = json!("not-base64url")
        }),
        ("missing instance", |value| {
            value.as_object_mut().unwrap().remove("broker_instance_id");
        }),
        ("empty instance", |value| {
            value["broker_instance_id"] = json!("")
        }),
        ("padded instance", |value| {
            value["broker_instance_id"] = json!("IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=")
        }),
        ("non-base64url instance", |value| {
            value["broker_instance_id"] = json!("IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi+")
        }),
        ("short instance", |value| {
            value["broker_instance_id"] = json!("IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi")
        }),
        ("long instance", |value| {
            value["broker_instance_id"] = json!("IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi")
        }),
        ("origin", |value| {
            value["base_url"] = json!("http://127.0.0.1:04312")
        }),
        ("executable", |value| {
            value["executable_path"] = json!("/tmp/../unsafe")
        }),
        ("PID", |value| value["broker_pid"] = json!(0)),
        ("timestamp", |value| {
            value["created_unix_ms"] = json!(i64::MAX)
        }),
    ];
    for (label, mutate) in cases {
        let broker = TestBroker::start().await;
        let fixture = tempfile::tempdir().unwrap();
        let (fake_bin, calls) = fake_herdr(&fixture, "[]");
        let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
        let mut command = smoke_command(&fake_bin);
        broker.configure_client(command.as_std_mut(), &executable);
        let descriptor_path = smoke_descriptor_path(&command);
        let mut descriptor: Value =
            serde_json::from_slice(&fs::read(&descriptor_path).unwrap()).unwrap();
        mutate(&mut descriptor);
        fs::write(&descriptor_path, serde_json::to_vec(&descriptor).unwrap()).unwrap();

        let output = command.output().await.expect("smoke helper must execute");

        assert_eq!(output.status.code(), Some(1), "{label} was accepted");
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("runtime descriptor"),
            "{label} failed for the wrong reason"
        );
        assert_eq!(fs::read_to_string(calls).unwrap(), "--version\n");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn smoke_diagnostics_reject_non_0600_symlinked_and_oversized_descriptors() {
    // Break caught: the smoke follows/re-reads an unsafe descriptor or accepts bytes beyond the
    // Pi client's fixed 64 KiB plus one bounded read.
    for case in [
        "parent-mode",
        "root-mode",
        "mode",
        "symlink",
        "oversized",
        "malformed",
    ] {
        let broker = TestBroker::start().await;
        let fixture = tempfile::tempdir().unwrap();
        let (fake_bin, calls) = fake_herdr(&fixture, "[]");
        let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
        let mut command = smoke_command(&fake_bin);
        broker.configure_client(command.as_std_mut(), &executable);
        let descriptor_path = smoke_descriptor_path(&command);
        match case {
            "parent-mode" => {
                fs::set_permissions(
                    descriptor_path.parent().unwrap().parent().unwrap(),
                    fs::Permissions::from_mode(0o777),
                )
                .unwrap();
            }
            "root-mode" => {
                fs::set_permissions(
                    descriptor_path.parent().unwrap(),
                    fs::Permissions::from_mode(0o755),
                )
                .unwrap();
            }
            "mode" => {
                fs::set_permissions(&descriptor_path, fs::Permissions::from_mode(0o700)).unwrap();
            }
            "symlink" => {
                let real = descriptor_path.with_extension("real");
                fs::rename(&descriptor_path, &real).unwrap();
                std::os::unix::fs::symlink(&real, &descriptor_path).unwrap();
            }
            "oversized" => {
                fs::write(&descriptor_path, vec![b'x'; 64 * 1024 + 1]).unwrap();
            }
            "malformed" => {
                fs::write(&descriptor_path, b"{not-json}").unwrap();
            }
            _ => unreachable!(),
        }

        let output = command.output().await.expect("smoke helper must execute");

        assert_eq!(
            output.status.code(),
            Some(1),
            "{case} descriptor was accepted"
        );
        assert_eq!(fs::read_to_string(calls).unwrap(), "--version\n");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn smoke_diagnostics_reject_a_symlinked_runtime_root() {
    // Break caught: the diagnostic follows a substituted runtime-root symlink even though the
    // broker and Pi client require the final private directory component to be no-follow.
    let broker = TestBroker::start().await;
    let fixture = tempfile::tempdir().unwrap();
    let (fake_bin, _calls) = fake_herdr(&fixture, "[]");
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
    let mut command = Command::new("bash");
    command
        .arg(root_smoke_script())
        .env("HERDR_ENV", "1")
        .env("HERDR_BIN_PATH", fake_bin.join("herdr"))
        .env(
            "PATH",
            format!(
                "{}:{}",
                fake_bin.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        );
    broker.configure_client(command.as_std_mut(), &executable);
    let runtime_base = command
        .as_std()
        .get_envs()
        .find_map(|(key, value)| (key == "TMPDIR").then_some(value.unwrap()))
        .map(PathBuf::from)
        .unwrap();
    let runtime_root = runtime_base.join("herdr-a2a");
    let moved_root = runtime_base.join("protected-runtime");
    fs::rename(&runtime_root, &moved_root).unwrap();
    std::os::unix::fs::symlink(&moved_root, &runtime_root).unwrap();

    let output = command.output().await.expect("smoke helper must execute");

    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("runtime directory is unsafe"),
        "symlinked runtime root was not rejected"
    );
}

#[cfg(unix)]
fn fake_herdr(fixture: &tempfile::TempDir, agents_json: &str) -> (PathBuf, PathBuf) {
    fake_herdr_version(fixture, "0.8.0", agents_json)
}

#[cfg(unix)]
fn fake_herdr_version(
    fixture: &tempfile::TempDir,
    version: &str,
    agents_json: &str,
) -> (PathBuf, PathBuf) {
    let fake_bin = fixture.path().join("bin");
    fs::create_dir(&fake_bin).unwrap();
    let calls = fixture.path().join("herdr-calls");
    let fake_herdr = fake_bin.join("herdr");
    fs::write(
        &fake_herdr,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nif [ \"$1\" = '--version' ]; then printf '%s\\n' 'herdr {version}'; exit 0; fi\n[ \"$1 $2\" = 'agent list' ] || exit 97\nprintf '%s\\n' '{{\"result\":{{\"agents\":{agents_json}}}}}'\n",
            calls.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_herdr, fs::Permissions::from_mode(0o700)).unwrap();
    (fake_bin, calls)
}

#[cfg(unix)]
fn lazy_broker_herdr(fixture: &tempfile::TempDir, executable: &Path) -> (PathBuf, PathBuf) {
    let fake_bin = fixture.path().join("lazy-bin");
    fs::create_dir(&fake_bin).unwrap();
    let calls = fixture.path().join("lazy-herdr-calls");
    let fake_herdr = fake_bin.join("herdr");
    fs::write(
        &fake_herdr,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n\
             if [ \"$1 $2 $3 $4\" = 'plugin action invoke herdr.a2a.ensure-broker' ]; then\n\
               exec '{}' coordinator serve\n\
             fi\n\
             if [ \"$1 $2\" = 'agent get' ]; then\n\
               pane=$3\n\
               suffix=${{pane##*:p}}\n\
               printf '%s\\n' \"{{\\\"result\\\":{{\\\"agent\\\":{{\\\"pane_id\\\":\\\"$pane\\\",\\\"name\\\":\\\"agent$suffix\\\",\\\"agent\\\":\\\"pi\\\",\\\"workspace_id\\\":\\\"test-workspace\\\",\\\"cwd\\\":\\\"/repo\\\"}}}}}}\"\n\
               exit 0\n\
             fi\n\
             exit 97\n",
            calls.display(),
            executable.display(),
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_herdr, fs::Permissions::from_mode(0o700)).unwrap();
    (fake_bin, calls)
}

#[cfg(unix)]
fn stage_managed_executable(fixture: &tempfile::TempDir, executable: &Path) -> PathBuf {
    let source = executable
        .canonicalize()
        .expect("test CLI executable must have a canonical path");
    let source_metadata = fs::metadata(&source).expect("test CLI executable metadata must exist");
    assert!(
        source_metadata.is_file(),
        "test CLI executable must be a file"
    );
    let source_mode = source_metadata.permissions().mode() & 0o7777;

    let bin = fixture
        .path()
        .join("generations")
        .join(TEST_MANAGED_GENERATION_ID)
        .join("bin");
    fs::create_dir_all(&bin).expect("managed test generation must be created");
    let staged = bin.join("herdr-a2a");
    let copied = fs::copy(&source, &staged).expect("test CLI executable must be staged");
    assert_eq!(copied, source_metadata.len());
    fs::set_permissions(&staged, fs::Permissions::from_mode(source_mode))
        .expect("staged test CLI permissions must match the built executable");
    assert_eq!(
        fs::metadata(&staged).unwrap().permissions().mode() & 0o7777,
        source_mode,
        "staged test CLI mode changed"
    );
    staged
        .canonicalize()
        .expect("staged test CLI executable must have a canonical path")
}

#[cfg(unix)]
fn lazy_client_command(
    executable: &Path,
    fake_herdr: &Path,
    fixture: &tempfile::TempDir,
    pane_id: &str,
    harness_session_id: &str,
) -> Command {
    let mut command = Command::new(executable);
    command
        .arg("client-session")
        .arg("--harness-session-id")
        .arg(harness_session_id)
        .env("HERDR_PANE_ID", pane_id)
        .env("HERDR_SOCKET_PATH", fixture.path().join("herdr.sock"))
        .env("HERDR_WORKSPACE_ID", "test-workspace")
        .env("HERDR_BIN_PATH", fake_herdr)
        .env("HERDR_PLUGIN_STATE_DIR", fixture.path().join("state"))
        .env("TMPDIR", fixture.path().join("runtime"))
        .env("XDG_RUNTIME_DIR", fixture.path().join("runtime"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    command
}

#[cfg(unix)]
async fn stop_lazy_coordinator(executable: &Path, fake_herdr: &Path, fixture: &tempfile::TempDir) {
    let output = Command::new(executable)
        .arg("coordinator")
        .arg("stop")
        .env("HERDR_SOCKET_PATH", fixture.path().join("herdr.sock"))
        .env("HERDR_WORKSPACE_ID", "test-workspace")
        .env("HERDR_BIN_PATH", fake_herdr)
        .env("HERDR_PLUGIN_STATE_DIR", fixture.path().join("state"))
        .env("TMPDIR", fixture.path().join("runtime"))
        .env("XDG_RUNTIME_DIR", fixture.path().join("runtime"))
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "coordinator stop failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
struct LazyClientProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Lines<BufReader<ChildStdout>>,
}

#[cfg(unix)]
impl LazyClientProcess {
    fn spawn(mut command: Command) -> Self {
        let mut child = command.spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        Self {
            child,
            stdin: Some(stdin),
            stdout: BufReader::new(stdout).lines(),
        }
    }

    async fn send(&mut self, request: Value) {
        let mut encoded = serde_json::to_vec(&request).unwrap();
        encoded.push(b'\n');
        let stdin = self.stdin.as_mut().unwrap();
        stdin.write_all(&encoded).await.unwrap();
        stdin.flush().await.unwrap();
    }

    async fn recv(&mut self) -> Value {
        let line = tokio::time::timeout(Duration::from_secs(15), self.stdout.next_line())
            .await
            .expect("lazy client response timed out")
            .unwrap()
            .expect("lazy client exited before responding");
        serde_json::from_str(&line).unwrap()
    }

    async fn close(&mut self) {
        self.stdin.take();
        let status = tokio::time::timeout(Duration::from_secs(5), self.child.wait())
            .await
            .expect("lazy client did not exit after stdin EOF")
            .unwrap();
        assert!(
            status.success(),
            "lazy client exited unsuccessfully: {status}"
        );
    }
}

#[cfg(unix)]
fn smoke_command(fake_bin: &Path) -> Command {
    let mut command = Command::new("bash");
    command
        .arg(root_smoke_script())
        .env("HERDR_ENV", "1")
        .env("HERDR_BIN_PATH", fake_bin.join("herdr"))
        .env(
            "PATH",
            format!(
                "{}:{}",
                fake_bin.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        );
    command
}

#[cfg(unix)]
fn smoke_descriptor_path(command: &Command) -> PathBuf {
    let command = command.as_std();
    let env_value = |name: &str| {
        command
            .get_envs()
            .find_map(|(key, value)| (key == name).then_some(value.unwrap()))
            .map(PathBuf::from)
            .unwrap()
    };
    let socket_path = env_value("HERDR_SOCKET_PATH");
    let session_key = format!(
        "{:x}",
        Sha256::digest(socket_path.as_os_str().as_encoded_bytes())
    );
    let workspace_id = env_value("HERDR_WORKSPACE_ID");
    let runtime_base = if cfg!(target_os = "macos") {
        env_value("TMPDIR")
    } else {
        env_value("XDG_RUNTIME_DIR")
    };
    RuntimePaths::for_test(
        &runtime_base.join("herdr-a2a"),
        &session_key,
        workspace_id.to_str().unwrap(),
    )
    .descriptor
}

fn root_smoke_script() -> PathBuf {
    workspace_root().join("scripts/pi-smoke.sh")
}

#[tokio::test]
async fn descriptor_is_not_published_until_reconciliation_finishes() {
    // Break caught: startup publishes credentials before durable recovery has committed and
    // rebuilt memory, allowing clients to authenticate against unreconciled broker state.
    let runtime = TestBrokerRuntime::new();
    let reconciliation = runtime.stall_reconciliation().await;
    let publication = runtime.stall_publication().await;
    let starting = tokio::spawn({
        let runtime = runtime.clone();
        async move { runtime.start_broker().await }
    });

    reconciliation.wait_until_entered().await;
    assert!(!runtime.descriptor_path().exists());
    reconciliation.release_one();
    publication.wait_until_entered().await;
    assert!(
        !runtime.descriptor_path().exists(),
        "descriptor was published before the final projection drain completed"
    );
    publication.release_one();
    let broker = starting.await.unwrap();
    assert!(runtime.descriptor_path().exists());
    broker.stop().await;
}

#[tokio::test]
async fn reconciliation_failure_preserves_database_and_publishes_no_descriptor() {
    // Break caught: startup publishes discovery or deletes the diagnostic database after core
    // recovery rejects durable state.
    let runtime = TestBrokerRuntime::new();
    runtime.poison_reconciliation().await;
    let before = fs::read(runtime.database_path()).unwrap();

    assert!(runtime.try_start_broker().await.is_err());
    assert!(!runtime.descriptor_path().exists());
    assert_eq!(fs::read(runtime.database_path()).unwrap(), before);
}

#[tokio::test]
async fn restart_uses_new_port_token_proof_and_instance_id() {
    // Break caught: a replacement process reuses any listener coordinate or credential from the
    // prior instance, allowing stale authenticated clients to reach it.
    let runtime = TestBrokerRuntime::new();
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
    let first = runtime.start_broker().await;
    first.add_agent("reviewer", "w1:p2").await;
    let mut first_command = Command::new(&executable);
    first.configure_client(first_command.as_std_mut(), &executable);
    let first_descriptor: RuntimeDescriptor =
        serde_json::from_slice(&fs::read(smoke_descriptor_path(&first_command)).unwrap()).unwrap();
    let no_redirect = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let registration: Value = no_redirect
        .post(format!("{}/v1/register", first_descriptor.base_url))
        .bearer_auth(&first_descriptor.bearer_token)
        .json(&json!({
            "pane_id": "w1:p2",
            "harness_session_id": "prior-instance-session"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let old_registration_id = registration["registration_id"].as_str().unwrap().to_owned();
    let old_registration_epoch = registration["registration_epoch"].as_u64().unwrap();
    let nonce = "ERERERERERERERERERERERERERERERERERERERERERE";
    let first_proof = no_redirect
        .get(format!(
            "{}/health/proof/{nonce}",
            first_descriptor.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(first_proof.status(), reqwest::StatusCode::OK);
    let first_proof_value = first_proof
        .headers()
        .get("x-herdr-a2a-health-proof")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    first.stop().await;

    let second = runtime.start_broker().await;
    let mut second_command = Command::new(&executable);
    second.configure_client(second_command.as_std_mut(), &executable);
    let second_descriptor: RuntimeDescriptor =
        serde_json::from_slice(&fs::read(smoke_descriptor_path(&second_command)).unwrap()).unwrap();

    assert_ne!(first_descriptor.base_url, second_descriptor.base_url);
    assert_ne!(
        first_descriptor.bearer_token,
        second_descriptor.bearer_token
    );
    assert_ne!(
        first_descriptor.broker_instance_id,
        second_descriptor.broker_instance_id
    );
    let second_proof = no_redirect
        .get(format!(
            "{}/health/proof/{nonce}",
            second_descriptor.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(second_proof.status(), reqwest::StatusCode::OK);
    assert_eq!(
        second_proof
            .headers()
            .get("x-herdr-a2a-instance")
            .unwrap()
            .to_str()
            .unwrap(),
        second_descriptor.broker_instance_id
    );
    assert_ne!(
        second_proof
            .headers()
            .get("x-herdr-a2a-health-proof")
            .unwrap()
            .to_str()
            .unwrap(),
        first_proof_value,
        "prior-instance proof material authenticated the replacement"
    );
    let response = no_redirect
        .get(format!("{}/health", second_descriptor.base_url))
        .bearer_auth(&first_descriptor.bearer_token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    let stale_registration = no_redirect
        .post(format!("{}/v1/renew", second_descriptor.base_url))
        .bearer_auth(&second_descriptor.bearer_token)
        .header("x-herdr-a2a-registration", old_registration_id)
        .header("x-herdr-a2a-registration-epoch", old_registration_epoch)
        .send()
        .await
        .unwrap();
    assert_eq!(
        stale_registration.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    second.stop().await;
}

const OBSERVATION_WINDOW: Duration = Duration::from_millis(100);
const MAX_OBSERVED_REQUEST_BYTES: usize = 64 * 1024;

struct ObservingListener {
    base_url: String,
    shutdown: Option<oneshot::Sender<()>>,
    requests: JoinHandle<Vec<Vec<u8>>>,
}

impl ObservingListener {
    async fn start<F>(respond: F) -> Self
    where
        F: Fn(&str) -> String + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let requests = tokio::spawn(async move {
            let mut requests = Vec::new();
            loop {
                let accepted = tokio::select! {
                    accepted = listener.accept() => accepted,
                    _ = &mut shutdown_rx => break,
                };
                let (mut connection, _) = accepted.unwrap();
                let request = read_observed_request(&mut connection).await;
                let encoded = String::from_utf8(request.clone()).unwrap();
                let response = respond(&encoded);
                connection.write_all(response.as_bytes()).await.unwrap();
                requests.push(request);
            }
            requests
        });
        Self {
            base_url,
            shutdown: Some(shutdown_tx),
            requests,
        }
    }

    async fn finish(mut self) -> Vec<Vec<u8>> {
        tokio::time::sleep(OBSERVATION_WINDOW).await;
        self.shutdown.take().unwrap().send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), self.requests)
            .await
            .expect("observation listener did not stop")
            .unwrap()
    }
}

async fn read_observed_request(connection: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut captured = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        let read = connection.read(&mut chunk).await.unwrap();
        assert!(read > 0, "connection closed before request headers");
        captured.extend_from_slice(&chunk[..read]);
        assert!(
            captured.len() <= MAX_OBSERVED_REQUEST_BYTES,
            "request exceeded observation bound"
        );
        if let Some(end) = captured.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }
    };
    let headers = std::str::from_utf8(&captured[..header_end]).unwrap();
    let content_length = headers
        .split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    let request_end = header_end.checked_add(content_length).unwrap();
    assert!(request_end <= MAX_OBSERVED_REQUEST_BYTES);
    while captured.len() < request_end {
        let read = connection.read(&mut chunk).await.unwrap();
        assert!(read > 0, "connection closed before request body");
        captured.extend_from_slice(&chunk[..read]);
        assert!(captured.len() <= MAX_OBSERVED_REQUEST_BYTES);
    }
    captured.truncate(request_end);
    captured
}

fn ok_json_response(extra_headers: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\n{extra_headers}Content-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
    )
}

fn proof_response(request: &str, bearer_token: &str, broker_instance_id: &str) -> String {
    let nonce = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|path| path.strip_prefix("/health/proof/"))
        .and_then(|encoded| URL_SAFE_NO_PAD.decode(encoded).ok())
        .expect("proof request must contain a canonical nonce");
    let key = Sha256::digest(bearer_token.as_bytes());
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
    mac.update(b"herdr-a2a-proof-v2\0");
    mac.update(broker_instance_id.as_bytes());
    mac.update(&nonce);
    let proof = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!(
        "HTTP/1.1 200 OK\r\nx-herdr-a2a-health-proof: {proof}\r\nx-herdr-a2a-instance: {broker_instance_id}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
}

fn write_test_descriptor(
    runtime: &tempfile::TempDir,
    socket_path: &Path,
    base_url: String,
    bearer_token: &str,
    executable: &Path,
    broker_pid: u32,
) -> RuntimePaths {
    let session_key = format!(
        "{:x}",
        Sha256::digest(socket_path.as_os_str().as_encoded_bytes())
    );
    let paths = RuntimePaths::for_test(
        &runtime.path().join("herdr-a2a"),
        &session_key,
        "test-workspace",
    );
    write_descriptor(
        &paths,
        &RuntimeDescriptor {
            session_key,
            workspace_id: paths.scope.workspace_id.clone(),
            base_url,
            bearer_token: bearer_token.to_owned(),
            broker_instance_id: "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI".to_owned(),
            executable_path: executable.canonicalize().unwrap(),
            broker_pid,
            created_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
                .try_into()
                .unwrap(),
        },
    )
    .unwrap();
    paths
}

#[test]
fn smoke_diagnostics_refuse_to_inspect_herdr_from_an_unmanaged_shell() {
    // Break caught: diagnostics fall through to session inspection when HERDR_ENV is absent.
    let output = std::process::Command::new("bash")
        .arg(root_smoke_script())
        .env_remove("HERDR_ENV")
        .output()
        .expect("smoke helper must execute");

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "pi-smoke: HERDR_ENV=1 is required; run this inside a Herdr pane.\n"
    );
}

struct ClientSessionProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<Lines<BufReader<ChildStdout>>>,
    _process_permit: OwnedSemaphorePermit,
}

impl ClientSessionProcess {
    async fn spawn(broker: &TestBroker, pane_id: &str, harness_session_id: &str) -> Self {
        let process_permit = CLIENT_PROCESS_LIMIT.clone().acquire_owned().await.unwrap();
        let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
        let mut command = Command::new(&executable);
        command
            .arg("client-session")
            .arg("--harness-session-id")
            .arg(harness_session_id)
            .env("HERDR_PANE_ID", pane_id)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        broker.configure_client(command.as_std_mut(), &executable);
        let mut child = command.spawn().expect("client-session must start");
        let stdin = child.stdin.take().expect("piped client stdin");
        let stdout = child.stdout.take().expect("piped client stdout");
        Self {
            child,
            stdin: Some(stdin),
            stdout: Some(BufReader::new(stdout).lines()),
            _process_permit: process_permit,
        }
    }

    #[cfg(unix)]
    async fn spawn_with_managed_environment(
        broker: &TestBroker,
        pane_id: &str,
        harness_session_id: &str,
        fixture: &tempfile::TempDir,
    ) -> Self {
        let process_permit = CLIENT_PROCESS_LIMIT.clone().acquire_owned().await.unwrap();
        let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
        let home = fixture.path().join("home with spaces");
        let data_home = fixture.path().join("data with spaces");
        let plugin_state = fixture.path().join("plugin state with spaces");
        for directory in [&home, &data_home, &plugin_state] {
            fs::create_dir(directory).unwrap();
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut command = Command::new(&executable);
        command
            .arg("client-session")
            .arg("--harness-session-id")
            .arg(harness_session_id)
            .env("HERDR_PANE_ID", pane_id)
            .env("HOME", home)
            .env("XDG_DATA_HOME", data_home)
            .env("HERDR_PLUGIN_STATE_DIR", plugin_state)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        broker.configure_client(command.as_std_mut(), &executable);
        let mut child = command.spawn().expect("client-session must start");
        let stdin = child.stdin.take().expect("piped client stdin");
        let stdout = child.stdout.take().expect("piped client stdout");
        Self {
            child,
            stdin: Some(stdin),
            stdout: Some(BufReader::new(stdout).lines()),
            _process_permit: process_permit,
        }
    }

    #[cfg(unix)]
    async fn spawn_with_herdr(
        broker: &TestBroker,
        pane_id: &str,
        harness_session_id: &str,
        herdr: &Path,
    ) -> Self {
        let process_permit = CLIENT_PROCESS_LIMIT.clone().acquire_owned().await.unwrap();
        let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
        let mut command = Command::new(&executable);
        command
            .arg("client-session")
            .arg("--harness-session-id")
            .arg(harness_session_id)
            .env("HERDR_PANE_ID", pane_id)
            .env("HERDR_BIN_PATH", herdr)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        broker.configure_client(command.as_std_mut(), &executable);
        let mut child = command.spawn().expect("client-session must start");
        let stdin = child.stdin.take().expect("piped client stdin");
        let stdout = child.stdout.take().expect("piped client stdout");
        Self {
            child,
            stdin: Some(stdin),
            stdout: Some(BufReader::new(stdout).lines()),
            _process_permit: process_permit,
        }
    }

    async fn send(&mut self, request: Value) {
        let mut encoded = serde_json::to_vec(&request).unwrap();
        encoded.push(b'\n');
        self.send_raw(&encoded).await;
    }

    async fn send_raw(&mut self, encoded: &[u8]) {
        let stdin = self.stdin.as_mut().expect("client stdin is open");
        stdin.write_all(encoded).await.unwrap();
        stdin.flush().await.unwrap();
    }

    async fn recv(&mut self) -> Value {
        let line = tokio::time::timeout(
            Duration::from_secs(10),
            self.stdout
                .as_mut()
                .expect("client stdout is open")
                .next_line(),
        )
        .await
        .expect("client-session did not respond within the test watchdog")
        .unwrap()
        .expect("client-session exited before responding");
        serde_json::from_str(&line)
            .expect("stdout must contain one complete JSON response per line")
    }

    async fn close_stdin_and_wait(&mut self) {
        self.close_stdin();
        self.wait_for_successful_exit("stdin EOF").await;
    }

    fn close_stdin(&mut self) {
        self.stdin.take();
    }

    async fn terminate_and_wait(&mut self) {
        self.send_sigterm().await;
        self.wait_for_successful_exit("SIGTERM").await;
    }

    async fn send_sigterm(&mut self) {
        let pid = self.child.id().expect("running client has a PID");
        let status = Command::new("/bin/kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .status()
            .await
            .unwrap();
        assert!(status.success());
    }

    async fn wait_for_successful_exit(&mut self, reason: &str) {
        let status = self.wait_for_exit(reason).await;
        assert!(status.success());
    }

    async fn wait_for_exit(&mut self, reason: &str) -> ExitStatus {
        tokio::time::timeout(Duration::from_secs(12), self.child.wait())
            .await
            .unwrap_or_else(|_| panic!("client-session did not exit after {reason}"))
            .unwrap()
    }

    fn break_stdout(&mut self) {
        self.stdout.take();
    }

    fn take_stdin(&mut self) -> ChildStdin {
        self.stdin.take().expect("client stdin is open")
    }
}

#[cfg(unix)]
#[tokio::test]
async fn managed_remove_session_method_is_bounded_and_uses_the_managed_backend() {
    // Break caught: Pi advertises uninstall but the persistent session rejects it as unknown or
    // accepts undeclared parameters before reaching the ownership-record gate.
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    let fixture = tempfile::tempdir().unwrap();
    let mut child = ClientSessionProcess::spawn_with_managed_environment(
        &broker,
        "w1:p1",
        "pi-session-1",
        &fixture,
    )
    .await;

    child
        .send(json!({
            "id": "remove",
            "method": "managed_remove",
            "params": {"purge": false}
        }))
        .await;
    let response = child.recv().await;
    assert_eq!(response["id"], "remove");
    assert!(
        response["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("ownership_record_missing")),
        "unexpected response: {response}"
    );

    child
        .send(json!({
            "id": "extra",
            "method": "managed_remove",
            "params": {"purge": false, "unexpected": true}
        }))
        .await;
    let response = child.recv().await;
    assert_eq!(response["id"], "extra");
    assert!(
        response.get("error").is_some(),
        "unexpected response: {response}"
    );
}

async fn await_client_pair_ready(
    first: &mut ClientSessionProcess,
    second: &mut ClientSessionProcess,
) {
    first
        .send(json!({"id":"first-ready","method":"list_agents","params":{}}))
        .await;
    second
        .send(json!({"id":"second-ready","method":"list_agents","params":{}}))
        .await;
    assert_eq!(first.recv().await["id"], "first-ready");
    assert_eq!(second.recv().await["id"], "second-ready");
}

async fn await_client_ready(client: &mut ClientSessionProcess) {
    client
        .send(json!({"id":"client-ready","method":"list_agents","params":{}}))
        .await;
    assert_eq!(client.recv().await["id"], "client-ready");
}

async fn canonical_agent(broker: &TestBroker, role: &str) -> String {
    broker
        .registration_for_agent(role)
        .await
        .agent
        .name
        .as_str()
        .to_owned()
}

fn agent_card_endpoint(canonical_agent: &str) -> String {
    format!("/agents/{canonical_agent}/.well-known/agent-card.json")
}

#[tokio::test]
async fn malformed_envelopes_are_correlated_and_unknown_fields_are_rejected() {
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    let mut child = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;

    for (request, expected_id) in [
        (
            json!({"id":"extra","method":"list_agents","params":{},"extra":true}),
            "extra",
        ),
        (json!({"id":"missing","params":{}}), "missing"),
        (json!({"id":"mistyped","method":7,"params":{}}), "mistyped"),
        (
            json!({"id":"method-long","method":"m".repeat(65),"params":{}}),
            "method-long",
        ),
        (
            json!({"id":"params-type","method":"list_agents","params":[]}),
            "params-type",
        ),
        (json!({"method":"list_agents","params":{}}), ""),
        (
            json!({"id":"x".repeat(300),"method":"list_agents","params":{}}),
            "",
        ),
    ] {
        child.send(request).await;
        let response = child.recv().await;
        assert_eq!(response["id"], expected_id);
        assert_eq!(response["error"]["code"], "protocol_error");
    }

    child.send_raw(b"{not-json}\n").await;
    let response = child.recv().await;
    assert_eq!(response["id"], "");
    assert_eq!(response["error"]["code"], "protocol_error");
}

#[tokio::test]
async fn oversized_line_is_discarded_incrementally_and_the_next_request_is_processed() {
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    let mut child = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    let mut oversized = vec![b'x'; 600 * 1024];
    oversized.push(b'\n');

    child.send_raw(&oversized).await;
    child
        .send(json!({"id":"after","method":"list_agents","params":{}}))
        .await;

    let rejected = child.recv().await;
    assert_eq!(rejected["id"], "");
    assert_eq!(rejected["error"]["code"], "protocol_error");
    assert_eq!(child.recv().await["id"], "after");
}

#[tokio::test]
async fn duplicate_in_flight_ids_are_rejected_then_reusable_after_output() {
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&broker, "w1:p2", "pi-session-2").await;
    recipient
        .send(json!({"id":"same","method":"wait_for_message","params":{"timeout_ms":5_000}}))
        .await;
    recipient
        .send(json!({"id":"same","method":"list_agents","params":{}}))
        .await;

    let duplicate = recipient.recv().await;
    assert_eq!(duplicate["id"], "same");
    assert_eq!(duplicate["error"]["code"], "duplicate_id");

    sender
        .send(json!({
            "id":"send",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"release wait","wait":false}
        }))
        .await;
    assert_eq!(sender.recv().await["id"], "send");
    assert_eq!(recipient.recv().await["id"], "same");

    recipient
        .send(json!({"id":"same","method":"list_agents","params":{}}))
        .await;
    let reused = recipient.recv().await;
    assert_eq!(reused["id"], "same");
    assert!(reused.get("result").is_some());
}

#[tokio::test]
async fn overall_in_flight_bound_rejects_request_sixty_five() {
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    let stall = broker.stall_endpoint("/v1/agents").await;
    let mut child = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    for index in 0..64 {
        child
            .send(json!({"id":format!("blocked-{index}"),"method":"list_agents","params":{}}))
            .await;
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        for _ in 0..64 {
            stall.wait_until_entered().await;
        }
    })
    .await
    .expect("the first 64 requests did not become active");

    child
        .send(json!({"id":"overflow","method":"list_agents","params":{}}))
        .await;
    let response = child.recv().await;

    assert_eq!(response["id"], "overflow");
    assert_eq!(response["error"]["code"], "too_many_requests");
    child.terminate_and_wait().await;
}

struct BrokerProcess(Child);

impl Drop for BrokerProcess {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

impl Drop for ClientSessionProcess {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

#[tokio::test]
async fn client_session_proves_descriptor_before_sending_bearer_or_registration() {
    // Break caught: client startup sends the descriptor bearer or registration body to a
    // different process that rebound the stale descriptor's loopback port.
    let _process_permit = CLIENT_PROCESS_LIMIT.clone().acquire_owned().await.unwrap();
    let fake = ObservingListener::start(|_| ok_json_response("")).await;
    let runtime = tempfile::tempdir().unwrap();
    let socket_path = runtime.path().join("herdr.sock");
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
    let bearer = "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM";
    write_test_descriptor(
        &runtime,
        &socket_path,
        fake.base_url.clone(),
        bearer,
        &executable,
        std::process::id(),
    );
    let mut command = Command::new(&executable);
    command
        .arg("client-session")
        .arg("--harness-session-id")
        .arg("pi-session-1")
        .env("HERDR_PANE_ID", "w1:p1")
        .env("HERDR_SOCKET_PATH", &socket_path)
        .env("HERDR_WORKSPACE_ID", "test-workspace")
        .env("TMPDIR", runtime.path())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let mut child = command.spawn().unwrap();
    let status = tokio::time::timeout(Duration::from_secs(3), child.wait())
        .await
        .expect("client startup was not bounded")
        .unwrap();
    assert!(!status.success(), "fake proof must prevent registration");
    let requests = fake.finish().await;
    assert_eq!(requests.len(), 1, "unexpected requests: {requests:?}");
    let request = String::from_utf8(requests.into_iter().next().unwrap()).unwrap();

    assert!(request.starts_with("GET /health/proof/"), "{request}");
    assert!(!request.to_ascii_lowercase().contains("authorization:"));
    assert!(!request.contains(bearer));
    assert!(!request.contains("/v1/register"));
    assert!(!request.contains("pi-session-1"));
}

#[cfg(unix)]
#[tokio::test]
async fn client_session_rejects_redirected_proof_without_disclosing_bearer_to_original_origin() {
    // Break caught: following the descriptor origin's redirect to a real proof-capable broker
    // authenticates the nonce, then sends the bearer and registration back to the fake origin.
    let _process_permit = CLIENT_PROCESS_LIMIT.clone().acquire_owned().await.unwrap();
    let real = TestBroker::start().await;
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
    let mut configured = Command::new(&executable);
    real.configure_client(configured.as_std_mut(), &executable);
    let real_descriptor: RuntimeDescriptor =
        serde_json::from_slice(&fs::read(smoke_descriptor_path(&configured)).unwrap()).unwrap();
    let real_base_url = real_descriptor.base_url.clone();
    let relay = ObservingListener::start(move |request| {
        let path = request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap();
        format!(
            "HTTP/1.1 302 Found\r\nLocation: {real_base_url}{path}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
    })
    .await;
    let relay_base_url = relay.base_url.clone();
    let fake = ObservingListener::start(move |request| {
        let path = request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap();
        if path.starts_with("/health/proof/") {
            format!(
                "HTTP/1.1 302 Found\r\nLocation: {relay_base_url}{path}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
        } else {
            ok_json_response("")
        }
    })
    .await;
    let runtime = tempfile::tempdir().unwrap();
    let socket_path = runtime.path().join("herdr.sock");
    write_test_descriptor(
        &runtime,
        &socket_path,
        fake.base_url.clone(),
        &real_descriptor.bearer_token,
        &executable,
        std::process::id(),
    );
    let mut command = Command::new(&executable);
    command
        .arg("client-session")
        .arg("--harness-session-id")
        .arg("redirect-session")
        .env("HERDR_PANE_ID", "w1:p1")
        .env("HERDR_SOCKET_PATH", &socket_path)
        .env("HERDR_WORKSPACE_ID", "test-workspace")
        .env("TMPDIR", runtime.path())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let mut child = command.spawn().unwrap();
    let status = tokio::time::timeout(Duration::from_secs(3), child.wait())
        .await
        .expect("redirected proof did not remain bounded")
        .unwrap();
    assert!(!status.success());
    let requests = fake.finish().await;
    let relay_requests = relay.finish().await;
    assert_eq!(requests.len(), 1, "unexpected requests: {requests:?}");
    assert!(
        relay_requests.is_empty(),
        "proof redirect was followed: {relay_requests:?}"
    );
    let request = String::from_utf8(requests.into_iter().next().unwrap()).unwrap();
    assert!(request.starts_with("GET /health/proof/"), "{request}");
    assert!(!request.to_ascii_lowercase().contains("authorization:"));
    assert!(!request.contains(&real_descriptor.bearer_token));
    assert!(!request.contains("/v1/register"));
    assert!(!request.contains("redirect-session"));
}

#[cfg(unix)]
#[tokio::test]
async fn client_session_does_not_follow_authenticated_redirect_or_disclose_bearer_to_target() {
    // Break caught: the proof client is no-redirect but the authenticated client follows a 3xx
    // and forwards the descriptor bearer to an origin that never proved the instance identity.
    let _process_permit = CLIENT_PROCESS_LIMIT.clone().acquire_owned().await.unwrap();
    let relay = ObservingListener::start(|_| ok_json_response("")).await;
    let relay_base_url = relay.base_url.clone();
    let bearer = "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM";
    let instance_id = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI";
    let fake = ObservingListener::start(move |request| {
        let path = request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap();
        if path.starts_with("/health/proof/") {
            proof_response(request, bearer, instance_id)
        } else {
            format!(
                "HTTP/1.1 302 Found\r\nLocation: {relay_base_url}{path}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
        }
    })
    .await;
    let runtime = tempfile::tempdir().unwrap();
    let socket_path = runtime.path().join("herdr.sock");
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
    write_test_descriptor(
        &runtime,
        &socket_path,
        fake.base_url.clone(),
        bearer,
        &executable,
        std::process::id(),
    );
    let mut child = Command::new(&executable)
        .arg("client-session")
        .arg("--harness-session-id")
        .arg("authenticated-redirect-session")
        .env("HERDR_PANE_ID", "w1:p1")
        .env("HERDR_SOCKET_PATH", &socket_path)
        .env("HERDR_WORKSPACE_ID", "test-workspace")
        .env("TMPDIR", runtime.path())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let status = tokio::time::timeout(Duration::from_secs(3), child.wait())
        .await
        .expect("authenticated redirect did not remain bounded")
        .unwrap();
    assert!(!status.success());
    let requests = fake.finish().await;
    let relay_requests = relay.finish().await;
    assert_eq!(
        requests.len(),
        3,
        "unexpected origin requests: {requests:?}"
    );
    assert!(
        relay_requests.is_empty(),
        "authenticated redirect was followed: {relay_requests:?}"
    );
    let proof = String::from_utf8(requests[0].clone()).unwrap();
    assert!(proof.starts_with("GET /health/proof/"), "{proof}");
    assert!(!proof.to_ascii_lowercase().contains("authorization:"));
    assert!(!proof.contains(bearer));
    let registration_proof = String::from_utf8(requests[1].clone()).unwrap();
    assert!(
        registration_proof.starts_with("GET /health/proof/"),
        "{registration_proof}"
    );
    assert!(
        !registration_proof
            .to_ascii_lowercase()
            .contains("authorization:")
    );
    assert!(!registration_proof.contains(bearer));
    let authenticated = String::from_utf8(requests[2].clone()).unwrap();
    assert!(authenticated.starts_with("GET /health "), "{authenticated}");
    assert!(authenticated.contains(&format!("Bearer {bearer}")));
}

#[tokio::test]
async fn client_session_registers_once_and_correlates_responses() {
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    let mut child = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;

    child
        .send(json!({"id":"a","method":"list_agents","params":{}}))
        .await;
    child
        .send(json!({"id":"b","method":"list_agents","params":{}}))
        .await;

    assert_eq!(child.recv().await["id"], "a");
    assert_eq!(child.recv().await["id"], "b");
    assert_eq!(broker.registration_count().await, 1);
}

#[tokio::test]
async fn automatic_bootstrap_directory_enriches_exact_workspace_identity() {
    // Break caught: the Pi child receives broker-scoped agents without an explicit workspace
    // identity, so the adapter cannot reject a cross-workspace or malformed directory response.
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    let mut child = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;

    child
        .send(json!({"id":"directory","method":"list_agents","params":{}}))
        .await;
    let response = child.recv().await;

    assert_eq!(response["id"], "directory");
    let agents = response["result"]["agents"]
        .as_array()
        .expect("directory must contain agents");
    assert!(!agents.is_empty());
    for agent in agents {
        let object = agent
            .as_object()
            .expect("directory agent must be an object");
        let mut fields = object.keys().map(String::as_str).collect::<Vec<_>>();
        fields.sort_unstable();
        assert_eq!(
            fields,
            [
                "canonical_name",
                "harness",
                "pane_id",
                "role",
                "status",
                "workspace_id",
            ]
        );
        assert_eq!(agent["workspace_id"], "test-workspace");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn create_team_uses_one_registration_wait_and_returns_canonical_directory() {
    // Break caught: NDJSON team creation predicts pane IDs, polls tasks, or omits canonical names.
    let broker = TestBroker::start().await;
    broker.add_agent("coordinator", "opaque-caller").await;
    broker.add_agent("worker", "opaque-worker").await;
    broker.add_agent("reviewer", "opaque-reviewer").await;

    let fixture = tempfile::tempdir().unwrap();
    let calls = fixture.path().join("team-calls");
    let split_count = fixture.path().join("split-count");
    let start_count = fixture.path().join("start-count");
    let focus = fixture.path().join("focused-pane");
    let herdr = fixture.path().join("herdr");
    fs::write(&focus, "opaque-caller").unwrap();
    fs::write(
        &herdr,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n\
             if [ \"$1 $2\" = 'pane layout' ]; then\n\
               focused=$(cat '{}')\n\
               printf '%s\\n' \"{{\\\"result\\\":{{\\\"layout\\\":{{\\\"workspace_id\\\":\\\"test-workspace\\\",\\\"focused_pane_id\\\":\\\"$focused\\\",\\\"panes\\\":[{{\\\"pane_id\\\":\\\"opaque-caller\\\",\\\"rect\\\":{{\\\"width\\\":120,\\\"height\\\":40}}}}]}}}}}}\"\n\
               exit 0\n\
             fi\n\
             if [ \"$1 $2\" = 'pane split' ]; then\n\
               count=0; [ -f '{}' ] && count=$(cat '{}')\n\
               count=$((count + 1)); printf '%s' \"$count\" > '{}'\n\
               if [ \"$count\" = 1 ]; then pane=opaque-worker; else pane=opaque-reviewer; fi\n\
               case \" $* \" in *' --no-focus '*) ;; *) printf '%s' \"$pane\" > '{}';; esac\n\
               printf '%s\\n' \"{{\\\"result\\\":{{\\\"pane\\\":{{\\\"pane_id\\\":\\\"$pane\\\"}}}}}}\"\n\
               exit 0\n\
             fi\n\
             if [ \"$1 $2 $3\" = 'pane process-info --pane' ]; then\n\
               case \"$4\" in opaque-worker) shell_pid=41001;; opaque-reviewer) shell_pid=41002;; *) exit 96;; esac\n\
               printf '%s\\n' \"{{\\\"result\\\":{{\\\"process_info\\\":{{\\\"pane_id\\\":\\\"$4\\\",\\\"shell_pid\\\":$shell_pid}}}}}}\"\n\
               exit 0\n\
             fi\n\
             if [ \"$1 $2\" = 'agent start' ]; then\n\
               [ \"$4 $5 $6 $8\" = '--kind pi --pane --timeout' ] || exit 95\n\
               case \"$3:$7\" in worker:opaque-worker|reviewer:opaque-reviewer) ;; *) exit 94;; esac\n\
               case \"$9\" in ''|*[!0-9]*) exit 93;; esac\n\
               [ \"$9\" -gt 3000 ] && [ \"$9\" -le 15000 ] || exit 92\n\
               count=0; [ -f '{}' ] && count=$(cat '{}')\n\
               count=$((count + 1)); printf '%s' \"$count\" > '{}'\n\
               if [ \"$3\" = worker ] && [ \"$count\" = 1 ]; then\n\
                 printf '%s\\n' '{{\"error\":{{\"code\":\"agent_pane_busy\",\"message\":\"agent target pane opaque-worker is not an available shell\"}},\"id\":\"cli:agent:start\"}}' >&2\n\
                 exit 1\n\
               fi\n\
               [ \"$3\" = worker ] && exit 98\n\
               printf '%s\\n' '{{\"result\":{{}}}}'; exit 0\n\
             fi\n\
             if [ \"$1 $2 $3\" = 'agent get opaque-worker' ]; then\n\
               printf '%s\\n' '{{\"result\":{{\"agent\":{{\"pane_id\":\"opaque-worker\",\"agent\":\"pi\"}}}}}}'; exit 0\n\
             fi\n\
             case \"$1 $2\" in 'agent rename'|'pane rename') printf '%s\\n' '{{\"result\":{{}}}}'; exit 0;; esac\n\
             exit 97\n",
            calls.display(),
            focus.display(),
            split_count.display(),
            split_count.display(),
            split_count.display(),
            focus.display(),
            start_count.display(),
            start_count.display(),
            start_count.display(),
        ),
    )
    .unwrap();
    fs::set_permissions(&herdr, fs::Permissions::from_mode(0o700)).unwrap();
    let mut child =
        ClientSessionProcess::spawn_with_herdr(&broker, "opaque-caller", "pi-session-team", &herdr)
            .await;
    await_client_ready(&mut child).await;
    assert_eq!(broker.active_registration_count().await, 1);

    let registration_calls = calls.clone();
    let registration_base_url = broker.base_url().to_owned();
    let registration_bearer = broker.bearer_token().to_owned();
    let registration_observer = tokio::spawn(async move {
        for (role, pane_id) in [("worker", "opaque-worker"), ("reviewer", "opaque-reviewer")] {
            let expected = format!("agent start {role} --kind pi --pane {pane_id} --timeout ");
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let observed = fs::read_to_string(&registration_calls).is_ok_and(|calls| {
                        calls.lines().any(|call| {
                            call.strip_prefix(&expected).is_some_and(|timeout| {
                                timeout.parse::<u64>().is_ok_and(|value| value == 15_000)
                            })
                        })
                    });
                    if observed {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            })
            .await
            .unwrap_or_else(|_| panic!("did not observe {expected}"));
            reqwest::Client::new()
                .post(format!("{registration_base_url}/v1/register"))
                .bearer_auth(&registration_bearer)
                .json(&json!({
                    "pane_id": pane_id,
                    "harness_session_id": format!("started-{role}")
                }))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap();
        }
    });
    let registration_wait = broker.stall_endpoint("/v1/agents/wait").await;

    child
        .send(json!({
            "id": "team",
            "method": "create_team",
            "params": {
                "self_role": "coordinator",
                "roles": ["worker", "reviewer"]
            }
        }))
        .await;
    tokio::time::timeout(
        Duration::from_secs(5),
        registration_wait.wait_until_entered(),
    )
    .await
    .expect("team registration wait was not observed");
    registration_wait.release_one();
    let response = child.recv().await;
    registration_observer.await.unwrap();
    let unexpected_second_wait = tokio::time::timeout(
        Duration::from_millis(50),
        registration_wait.wait_until_entered(),
    )
    .await
    .is_ok();
    if unexpected_second_wait {
        registration_wait.release_one();
    }
    assert!(
        !unexpected_second_wait,
        "team creation issued more than one wait"
    );
    assert_eq!(response["id"], "team");
    let members = response["result"]["members"].as_array().unwrap();
    assert_eq!(members.len(), 2);
    assert_eq!(members[0]["requested_role"], "worker");
    assert_eq!(members[0]["pane_id"], "opaque-worker");
    assert_eq!(members[0]["state"], "registered");
    assert!(
        members[0]["canonical_name"]
            .as_str()
            .unwrap()
            .starts_with("worker-")
    );
    assert_eq!(members[1]["requested_role"], "reviewer");
    assert_eq!(members[1]["pane_id"], "opaque-reviewer");
    assert_eq!(members[1]["state"], "registered");
    assert!(
        members[1]["canonical_name"]
            .as_str()
            .unwrap()
            .starts_with("reviewer-")
    );
    assert_ne!(members[0]["canonical_name"], members[1]["canonical_name"]);
    let worker_canonical = members[0]["canonical_name"].as_str().unwrap().to_owned();
    let reviewer_canonical = members[1]["canonical_name"].as_str().unwrap().to_owned();
    let cwd = std::env::current_dir().unwrap();
    let calls = fs::read_to_string(&calls).unwrap();
    let start_timeouts = |role: &str, pane_id: &str, expected_count: usize| {
        let prefix = format!("agent start {role} --kind pi --pane {pane_id} --timeout ");
        let matching = calls
            .lines()
            .filter_map(|call| call.strip_prefix(&prefix))
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), expected_count);
        matching
            .into_iter()
            .map(|value| value.parse::<u64>().unwrap())
            .inspect(|timeout| assert!((3_001..=15_000).contains(timeout)))
            .collect::<Vec<_>>()
    };
    let worker_timeouts = start_timeouts("worker", "opaque-worker", 2);
    let reviewer_timeouts = start_timeouts("reviewer", "opaque-reviewer", 1);
    assert_eq!(
        calls.lines().collect::<Vec<_>>(),
        [
            "agent rename opaque-caller coordinator".to_owned(),
            "pane layout --pane opaque-caller".to_owned(),
            format!(
                "pane split opaque-caller --direction right --cwd {} --no-focus",
                cwd.display()
            ),
            "pane rename opaque-worker worker".to_owned(),
            "pane process-info --pane opaque-worker".to_owned(),
            format!(
                "agent start worker --kind pi --pane opaque-worker --timeout {}",
                worker_timeouts[0]
            ),
            format!(
                "agent start worker --kind pi --pane opaque-worker --timeout {}",
                worker_timeouts[1]
            ),
            "agent get opaque-worker".to_owned(),
            "pane layout --pane opaque-caller".to_owned(),
            format!(
                "pane split opaque-caller --direction right --cwd {} --no-focus",
                cwd.display()
            ),
            "pane rename opaque-reviewer reviewer".to_owned(),
            "pane process-info --pane opaque-reviewer".to_owned(),
            format!(
                "agent start reviewer --kind pi --pane opaque-reviewer --timeout {}",
                reviewer_timeouts[0]
            ),
        ]
    );
    assert_eq!(fs::read_to_string(split_count).unwrap(), "2");
    assert_eq!(fs::read_to_string(focus).unwrap(), "opaque-caller");
    assert!(!calls.contains("send-text"));
    assert!(!calls.contains("send-keys"));
    assert!(!calls.contains("agent prompt"));

    let mut worker = ClientSessionProcess::spawn(&broker, "opaque-worker", "started-worker").await;
    let mut reviewer =
        ClientSessionProcess::spawn(&broker, "opaque-reviewer", "started-reviewer").await;
    await_client_pair_ready(&mut worker, &mut reviewer).await;
    assert_eq!(
        canonical_agent(&broker, &worker_canonical).await,
        worker_canonical
    );
    assert_eq!(
        canonical_agent(&broker, &reviewer_canonical).await,
        reviewer_canonical
    );
    worker
        .send(json!({
            "id": "team-send",
            "method": "send_message",
            "params": {
                "agent": reviewer_canonical,
                "text": "validate the created team",
                "metadata": {},
                "wait": true
            }
        }))
        .await;
    reviewer
        .send(json!({
            "id": "team-inbox",
            "method": "wait_for_message",
            "params": {"timeout_ms": 5_000}
        }))
        .await;
    let delivery = reviewer.recv().await;
    assert_eq!(
        delivery["result"]["payload"]["text"],
        "validate the created team"
    );
    let task_id = delivery["result"]["task_id"].as_str().unwrap();
    reviewer
        .send(json!({
            "id": "team-reply",
            "method": "reply",
            "params": {"task_id": task_id, "text": "team validated", "metadata": {}}
        }))
        .await;
    assert_eq!(reviewer.recv().await["id"], "team-reply");
    let reply = worker.recv().await;
    assert_eq!(reply["id"], "team-send");
    assert_eq!(reply["result"]["state"], "completed");
    assert_eq!(reply["result"]["text"], "team validated");

    worker.close_stdin_and_wait().await;
    reviewer.close_stdin_and_wait().await;
    child.close_stdin_and_wait().await;
}

#[cfg(unix)]
#[tokio::test]
async fn create_team_registration_wait_recovers_without_replaying_pane_mutations() {
    // Break caught: team readiness snapshots one broker connection, so turnover converts already
    // created panes to registration_wait_failed instead of reissuing only the bounded read wait.
    let runtime = TestBrokerRuntime::new();
    let first = runtime.start_broker().await;
    first.add_agent("coordinator", "opaque-caller").await;
    first.add_agent("worker", "opaque-worker").await;
    let fixture = tempfile::tempdir().unwrap();
    let calls = fixture.path().join("team-recovery-calls");
    let herdr = fixture.path().join("herdr");
    fs::write(
        &herdr,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n\
             if [ \"$1 $2\" = 'pane layout' ]; then\n\
               printf '%s\\n' '{{\"result\":{{\"layout\":{{\"workspace_id\":\"test-workspace\",\"focused_pane_id\":\"opaque-caller\",\"panes\":[{{\"pane_id\":\"opaque-caller\",\"rect\":{{\"width\":120,\"height\":40}}}}]}}}}}}'; exit 0\n\
             fi\n\
             if [ \"$1 $2\" = 'pane split' ]; then\n\
               printf '%s\\n' '{{\"result\":{{\"pane\":{{\"pane_id\":\"opaque-worker\"}}}}}}'; exit 0\n\
             fi\n\
             if [ \"$1 $2\" = 'pane rename' ]; then printf '%s\\n' '{{\"result\":{{}}}}'; exit 0; fi\n\
             if [ \"$1 $2 $3 $4\" = 'pane process-info --pane opaque-worker' ]; then\n\
               printf '%s\\n' '{{\"result\":{{\"process_info\":{{\"pane_id\":\"opaque-worker\",\"shell_pid\":42001}}}}}}'; exit 0\n\
             fi\n\
             if [ \"$1 $2 $3\" = 'agent start worker' ]; then printf '%s\\n' '{{\"result\":{{}}}}'; exit 0; fi\n\
             exit 97\n",
            calls.display(),
        ),
    )
    .unwrap();
    fs::set_permissions(&herdr, fs::Permissions::from_mode(0o700)).unwrap();
    let mut child =
        ClientSessionProcess::spawn_with_herdr(&first, "opaque-caller", "team-process", &herdr)
            .await;
    await_client_ready(&mut child).await;
    let first_wait = first.stall_endpoint("/v1/agents/wait").await;
    first
        .truncate_endpoint_response_once("/v1/agents/wait")
        .await;

    child
        .send(json!({
            "id":"team-recovery",
            "method":"create_team",
            "params":{"roles":["worker"]}
        }))
        .await;
    tokio::time::timeout(Duration::from_secs(5), first_wait.wait_until_entered())
        .await
        .expect("initial registration wait was not observed");

    let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
    let second = runtime.start_broker_for_executable(&executable).await;
    let replacement_wait = second.stall_endpoint("/v1/agents/wait").await;
    first_wait.release_one();
    if tokio::time::timeout(
        Duration::from_secs(5),
        replacement_wait.wait_until_entered(),
    )
    .await
    .is_err()
    {
        let early_response = tokio::time::timeout(Duration::from_millis(100), child.recv()).await;
        panic!(
            "registration wait was not reissued on the replacement broker; client response: {early_response:?}"
        );
    }
    drop(first);
    let registration = reqwest::Client::new()
        .post(format!("{}/v1/register", second.base_url()))
        .bearer_auth(second.bearer_token())
        .json(&json!({
            "pane_id":"opaque-worker",
            "harness_session_id":"worker-process-incarnation"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    assert!(registration.status().is_success());
    replacement_wait.release_one();
    let response = tokio::time::timeout(Duration::from_secs(5), child.recv())
        .await
        .expect("team response remained pending after replacement registration");

    assert_eq!(response["id"], "team-recovery", "{response}");
    assert_eq!(
        response["result"]["members"][0]["state"], "registered",
        "{response}"
    );
    assert!(
        response["result"]["members"][0]["canonical_name"]
            .as_str()
            .is_some_and(|name| name.starts_with("worker-"))
    );
    let calls = fs::read_to_string(calls).unwrap();
    assert_eq!(
        calls
            .lines()
            .filter(|call| call.starts_with("pane split "))
            .count(),
        1
    );
    assert_eq!(
        calls
            .lines()
            .filter(|call| call.starts_with("agent start worker "))
            .count(),
        1
    );
    assert!(!calls.contains("send-text"));
    assert!(!calls.contains("send-keys"));
    assert!(!calls.contains("agent prompt"));

    child.close_stdin_and_wait().await;
    second.stop().await;
}

#[cfg(unix)]
#[tokio::test]
async fn automatic_bootstrap_32_concurrent_sessions_share_one_descriptor_and_database() {
    // Break caught: simultaneous Pi bootstrap bypasses the workspace coordinator and leaves
    // multiple broker generations or durable databases authoritative for one workspace.
    let fixture = tempfile::tempdir().unwrap();
    fs::create_dir_all(fixture.path().join("runtime")).unwrap();
    let executable = stage_managed_executable(&fixture, Path::new(env!("CARGO_BIN_EXE_herdr-a2a")));
    let (fake_bin, _) = lazy_broker_herdr(&fixture, &executable);
    let fake_herdr = fake_bin.join("herdr");
    let socket_path = fixture.path().join("herdr.sock");
    let session_key = format!(
        "{:x}",
        Sha256::digest(socket_path.as_os_str().as_encoded_bytes())
    );
    let paths = RuntimePaths::for_test(
        &fixture.path().join("runtime/herdr-a2a"),
        &session_key,
        "test-workspace",
    );

    let mut clients = Vec::new();
    for index in 0..32 {
        clients.push(LazyClientProcess::spawn(lazy_client_command(
            &executable,
            &fake_herdr,
            &fixture,
            &format!("w1:p{index}"),
            &format!("pi-session-{index}"),
        )));
    }
    for (index, client) in clients.iter_mut().enumerate() {
        client
            .send(json!({"id":format!("ready-{index}"),"method":"list_agents","params":{}}))
            .await;
    }
    for (index, client) in clients.iter_mut().enumerate() {
        assert_eq!(client.recv().await["id"], format!("ready-{index}"));
    }

    let descriptor = read_descriptor(&paths).unwrap();
    let protected = reqwest::Client::new()
        .get(format!(
            "{}/health/proof/ERERERERERERERERERERERERERERERERERERERERERE",
            descriptor.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(protected.status(), reqwest::StatusCode::OK);
    assert_eq!(
        protected
            .headers()
            .get("x-herdr-a2a-instance")
            .unwrap()
            .to_str()
            .unwrap(),
        descriptor.broker_instance_id
    );
    let database_dir = fixture
        .path()
        .join("state/herdr-a2a")
        .join(&paths.scope.scope_key);
    assert!(database_dir.join("tasks.sqlite3").is_file());
    assert_eq!(
        fs::read_dir(fixture.path().join("state/herdr-a2a"))
            .unwrap()
            .count(),
        1,
        "one workspace must create one durable database directory"
    );

    for client in &mut clients {
        client.close().await;
    }
    stop_lazy_coordinator(&executable, &fake_herdr, &fixture).await;
}

#[cfg(unix)]
#[tokio::test]
async fn broker_replacement_next_a2a_recovery_lazy_starts_a_new_instance() {
    // Break caught: broker replacement reads a missing descriptor without invoking the launcher,
    // or the coordinator eagerly starts a replacement before the next A2A operation.
    let fixture = tempfile::tempdir().unwrap();
    fs::create_dir_all(fixture.path().join("runtime")).unwrap();
    let executable = stage_managed_executable(&fixture, Path::new(env!("CARGO_BIN_EXE_herdr-a2a")));
    let (fake_bin, calls) = lazy_broker_herdr(&fixture, &executable);
    let fake_herdr = fake_bin.join("herdr");
    let socket_path = fixture.path().join("herdr.sock");
    let session_key = format!(
        "{:x}",
        Sha256::digest(socket_path.as_os_str().as_encoded_bytes())
    );
    let paths = RuntimePaths::for_test(
        &fixture.path().join("runtime/herdr-a2a"),
        &session_key,
        "test-workspace",
    );
    let mut client = LazyClientProcess::spawn(lazy_client_command(
        &executable,
        &fake_herdr,
        &fixture,
        "w1:p1",
        "pi-session-1",
    ));
    client
        .send(json!({"id":"first","method":"list_agents","params":{}}))
        .await;
    assert_eq!(client.recv().await["id"], "first");
    let first = read_descriptor(&paths).unwrap();

    let killed = Command::new("/bin/kill")
        .arg("-KILL")
        .arg(first.broker_pid.to_string())
        .status()
        .await
        .unwrap();
    assert!(killed.success());
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if read_descriptor(&paths).is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("failed broker descriptor was not reaped");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(read_descriptor(&paths).is_err(), "broker restarted eagerly");

    client
        .send(json!({"id":"replacement","method":"list_agents","params":{}}))
        .await;
    assert_eq!(client.recv().await["id"], "replacement");
    let second = read_descriptor(&paths).unwrap();
    assert_ne!(first.broker_instance_id, second.broker_instance_id);
    assert_ne!(first.broker_pid, second.broker_pid);
    assert!(
        fs::read_to_string(calls)
            .unwrap()
            .lines()
            .filter(|line| *line == "plugin action invoke herdr.a2a.ensure-broker")
            .count()
            >= 2
    );

    client.close().await;
    stop_lazy_coordinator(&executable, &fake_herdr, &fixture).await;
}

#[tokio::test]
async fn client_process_limiter_does_not_hold_and_wait_across_live_sessions() {
    // Break caught: six parallel scenarios each hold one process permit while awaiting another,
    // so the default-parallel suite never reaches a client readiness watchdog.
    let broker = TestBroker::start().await;
    for index in 0..7 {
        broker
            .add_agent(&format!("agent{index}"), &format!("w1:p{index}"))
            .await;
    }

    let mut clients = tokio::time::timeout(Duration::from_secs(3), async {
        let mut clients = Vec::new();
        for index in 0..7 {
            clients.push(
                ClientSessionProcess::spawn(
                    &broker,
                    &format!("w1:p{index}"),
                    &format!("pi-session-{index}"),
                )
                .await,
            );
        }
        clients
    })
    .await
    .expect("live clients held the process limiter while waiting for another permit");

    for (index, client) in clients.iter_mut().enumerate() {
        client
            .send(json!({"id":format!("ready-{index}"),"method":"list_agents","params":{}}))
            .await;
    }
    for (index, client) in clients.iter_mut().enumerate() {
        assert_eq!(client.recv().await["id"], format!("ready-{index}"));
        client.close_stdin_and_wait().await;
    }
}

#[cfg(unix)]
#[tokio::test]
async fn stale_descriptor_probe_rejects_invalid_proof_without_disclosing_bearer() {
    // Break caught: stale-lock recovery trusts any 200 response on the descriptor port and sends
    // its bearer before deciding whether the listener is the broker that created the descriptor.
    let _process_permit = CLIENT_PROCESS_LIMIT.clone().acquire_owned().await.unwrap();
    let fake =
        ObservingListener::start(|_| ok_json_response("x-herdr-a2a-health-proof: malformed\r\n"))
            .await;
    let fake_base_url = fake.base_url.clone();
    let runtime = tempfile::tempdir().unwrap();
    let plugin_state = tempfile::tempdir().unwrap();
    let socket_path = runtime.path().join("herdr.sock");
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
    let bearer = "REREREREREREREREREREREREREREREREREREREREREQ";
    let mut departed = Command::new("/usr/bin/true").spawn().unwrap();
    let departed_pid = departed.id().unwrap();
    assert!(departed.wait().await.unwrap().success());
    let paths = write_test_descriptor(
        &runtime,
        &socket_path,
        fake_base_url.clone(),
        bearer,
        &executable,
        departed_pid,
    );
    fs::write(
        &paths.lock,
        serde_json::to_vec(&json!({"pid": departed_pid, "nonce": 1})).unwrap(),
    )
    .unwrap();
    fs::set_permissions(&paths.lock, fs::Permissions::from_mode(0o600)).unwrap();

    let mut command = Command::new(&executable);
    command
        .arg("broker")
        .env("HERDR_SOCKET_PATH", &socket_path)
        .env("HERDR_WORKSPACE_ID", "test-workspace")
        .env("HERDR_BIN_PATH", Path::new("/usr/bin/false"))
        .env("HERDR_PLUGIN_STATE_DIR", plugin_state.path())
        .env("TMPDIR", runtime.path())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut broker = BrokerProcess(command.spawn().unwrap());

    let replacement = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(status) = broker.0.try_wait().unwrap() {
                panic!("broker exited during stale recovery: {status}");
            }
            if let Ok(descriptor) = read_descriptor(&paths)
                && descriptor.base_url != fake_base_url
            {
                break descriptor;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("stale descriptor recovery did not remain bounded");
    assert_ne!(replacement.base_url, fake_base_url);

    let requests = fake.finish().await;
    assert_eq!(requests.len(), 1, "unexpected requests: {requests:?}");
    let request = String::from_utf8(requests.into_iter().next().unwrap()).unwrap();
    assert!(request.starts_with("GET /health/proof/"), "{request}");
    assert!(!request.to_ascii_lowercase().contains("authorization:"));
    assert!(!request.contains(bearer));
    assert!(!request.contains("/health HTTP"));

    broker.0.start_kill().unwrap();
    let _ = broker.0.wait().await;
}

#[tokio::test]
async fn wait_for_message_delivers_a_reply_without_task_polling() {
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&broker, "w1:p2", "pi-session-2").await;
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
            "id": "send-1",
            "method": "send_message",
            "params": {"agent": "reviewer", "text": "review this", "metadata": {}, "wait": true}
        }))
        .await;
    recipient
        .send(json!({
            "id": "inbox-1",
            "method": "wait_for_message",
            "params": {"timeout_ms": 5_000}
        }))
        .await;

    let delivery = recipient.recv().await;
    assert_eq!(delivery["id"], "inbox-1");
    assert_eq!(
        delivery["result"]["payload"]["text"], "review this",
        "unexpected delivery response: {delivery}"
    );
    let task_id = delivery["result"]["task_id"].as_str().unwrap();
    let conversation_id = delivery["result"]["context_id"].as_str().unwrap();
    recipient
        .send(json!({
            "id": "reply-1",
            "method": "reply",
            "params": {"task_id": task_id, "text": "approved", "metadata": {}}
        }))
        .await;
    assert_eq!(recipient.recv().await["id"], "reply-1");

    let response = sender.recv().await;
    assert_eq!(response["id"], "send-1");
    assert_eq!(response["result"]["task_id"], task_id);
    assert_eq!(response["result"]["conversation_id"], conversation_id);
    assert_eq!(response["result"]["state"], "completed");
    assert_eq!(response["result"]["text"], "approved");
    assert_eq!(broker.acknowledgement_count(), 1);
    assert_eq!(broker.task_poll_count(), 0);
}

#[tokio::test]
async fn canonical_identity_new_send_resolves_role_before_agent_card() {
    // Break caught: a mutable role is placed directly in the Agent Card URL and durable tenant.
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&broker, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;
    sender
        .send(json!({"id":"directory","method":"list_agents","params":{}}))
        .await;
    let directory = sender.recv().await;
    assert_eq!(directory["id"], "directory");
    let reviewer = directory["result"]["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|agent| agent["role"] == "reviewer")
        .unwrap();
    let canonical = reviewer["canonical_name"].as_str().unwrap().to_owned();
    assert_ne!(canonical, "reviewer");
    assert_eq!(reviewer["pane_id"], "w1:p2");
    assert_eq!(reviewer["harness"], "pi");
    assert_eq!(reviewer["status"], "live");
    assert_eq!(reviewer["workspace_id"], "test-workspace");
    assert_eq!(reviewer.as_object().unwrap().len(), 6);

    sender
        .send(json!({
            "id":"canonical-send",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"resolve first","wait":false}
        }))
        .await;
    let sent = sender.recv().await;
    assert_eq!(sent["id"], "canonical-send", "{sent}");
    assert_eq!(sent["result"]["agent"], canonical);
    assert_eq!(broker.send_message_count(), 1);

    recipient.close_stdin_and_wait().await;
    sender.close_stdin_and_wait().await;
}

#[tokio::test]
async fn canonical_identity_ambiguous_role_never_enqueues_or_subscribes() {
    // Break caught: client-side discovery guesses one of two live agents with the same role.
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    broker.add_agent("reviewer", "w1:p3").await;
    let mut sender = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    let mut first = ClientSessionProcess::spawn(&broker, "w1:p2", "pi-session-2").await;
    let mut second = ClientSessionProcess::spawn(&broker, "w1:p3", "pi-session-3").await;
    await_client_ready(&mut sender).await;
    await_client_ready(&mut first).await;
    await_client_ready(&mut second).await;
    let directory: Value = reqwest::Client::new()
        .get(format!("{}/v1/agents", broker.base_url()))
        .bearer_auth(broker.bearer_token())
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut expected_candidates = directory["agents"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|agent| agent["role"] == "reviewer")
        .map(|agent| agent["canonical_name"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    expected_candidates.sort();
    assert_eq!(expected_candidates.len(), 2);

    sender
        .send(json!({
            "id":"ambiguous-send",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"must not guess","wait":true}
        }))
        .await;
    let response = sender.recv().await;
    assert_eq!(response["id"], "ambiguous-send", "{response}");
    assert_eq!(response["error"]["code"], "ambiguous_agent", "{response}");
    assert_eq!(
        response["error"]["details"]["candidates"],
        json!(expected_candidates),
        "{response}"
    );
    assert_eq!(broker.send_message_count(), 0);
    assert_eq!(broker.streaming_send_count(), 0);
    assert_eq!(broker.task_subscription_count(), 0);

    second.close_stdin_and_wait().await;
    first.close_stdin_and_wait().await;
    sender.close_stdin_and_wait().await;
}

#[tokio::test]
async fn committed_ack_retries_after_same_instance_registration_refresh() {
    // Break caught: an ACK success is lost to an authentication response after commit, then the
    // refreshed same-principal registration cannot retry that exact delivery ID.
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&broker, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;
    let original_instance = broker.broker_instance_id().to_owned();
    let original_registration = broker.registration_for_agent("reviewer").await;
    broker
        .lose_success_to_registration_expiry_once("/v1/inbox/ack")
        .await;

    recipient
        .send(json!({
            "id":"refresh-delivery",
            "method":"wait_for_message",
            "params":{"timeout_ms":5_000}
        }))
        .await;
    sender
        .send(json!({
            "id":"refresh-send",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"ack before refresh","wait":false}
        }))
        .await;
    let sent = sender.recv().await;
    let delivered = recipient.recv().await;

    assert_eq!(sent["id"], "refresh-send");
    assert_eq!(delivered["id"], "refresh-delivery", "{delivered}");
    assert_eq!(delivered["result"]["task_id"], sent["result"]["task_id"]);
    assert_eq!(broker.broker_instance_id(), original_instance);
    let refreshed_registration = broker.registration_for_agent("reviewer").await;
    assert_ne!(
        refreshed_registration.credentials(),
        original_registration.credentials()
    );
    assert_eq!(broker.registration_count().await, 3);
    assert_eq!(broker.acknowledgement_count(), 1);

    recipient.close_stdin_and_wait().await;
    sender.close_stdin_and_wait().await;
}

#[tokio::test]
async fn recovery_role_rename_preserves_canonical_identity_without_replacing_a_peer() {
    // Break caught: a mutable role rename replaces either the renamed process's durable
    // canonical principal or the other live process that already has the new role.
    let broker = TestBroker::start().await;
    broker.add_agent("reviewer", "w1:p2").await;
    broker.add_agent("observer", "w1:p3").await;
    let mut reviewer = ClientSessionProcess::spawn(&broker, "w1:p2", "reviewer-session").await;
    let mut observer = ClientSessionProcess::spawn(&broker, "w1:p3", "observer-session").await;
    await_client_pair_ready(&mut reviewer, &mut observer).await;
    let reviewer_before = broker.registration_for_agent("reviewer").await;
    let observer_before = broker.registration_for_agent("observer").await;
    let reviewer_canonical = reviewer_before.agent.name.as_str().to_owned();
    let observer_canonical = observer_before.agent.name.as_str().to_owned();

    broker.add_agent("observer", "w1:p2").await;
    broker
        .expire_registration_before_request_once("/v1/agents")
        .await;
    reviewer
        .send(json!({"id":"renamed-pane","method":"list_agents","params":{}}))
        .await;
    let response = reviewer.recv().await;

    assert_eq!(response["id"], "renamed-pane");
    assert!(response.get("error").is_none(), "{response}");
    assert_eq!(
        response["result"]["agents"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|agent| agent["role"] == "observer")
            .count(),
        2,
        "{response}"
    );
    let reviewer_after = broker.registration_for_agent(&reviewer_canonical).await;
    let observer_after = broker.registration_for_agent(&observer_canonical).await;
    assert_eq!(reviewer_after.agent.name.as_str(), reviewer_canonical);
    assert_ne!(reviewer_after.credentials(), reviewer_before.credentials());
    assert_eq!(observer_after.credentials(), observer_before.credentials());
    assert_eq!(broker.active_registration_count().await, 2);
    observer
        .send(json!({"id":"observer-still-live","method":"list_agents","params":{}}))
        .await;
    assert_eq!(observer.recv().await["id"], "observer-still-live");

    reviewer.close_stdin_and_wait().await;
    observer.close_stdin_and_wait().await;
}

#[tokio::test]
async fn committed_ack_retries_after_broker_replacement() {
    // Break caught: an ACK commits before its connection disappears, then cold recovery restores
    // the exact delivery without an ephemeral owner and rejects the live client's retry.
    let runtime = TestBrokerRuntime::new();
    let first = runtime.start_broker().await;
    first.add_agent("implementer", "w1:p1").await;
    first.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&first, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&first, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;
    let ack_response = first.stall_endpoint_response_once("/v1/inbox/ack").await;

    recipient
        .send(json!({
            "id":"replacement-delivery",
            "method":"wait_for_message",
            "params":{"timeout_ms":5_000}
        }))
        .await;
    sender
        .send(json!({
            "id":"replacement-send",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"ack before replacement","wait":false}
        }))
        .await;
    let sent = sender.recv().await;
    tokio::time::timeout(Duration::from_secs(2), ack_response.wait_until_entered())
        .await
        .expect("ACK did not commit before the replacement boundary");

    let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
    let second = runtime.start_broker_for_executable(&executable).await;
    drop(first);
    let delivered = recipient.recv().await;
    sender
        .send(json!({"id":"replacement-sender-ready","method":"list_agents","params":{}}))
        .await;
    assert_eq!(sender.recv().await["id"], "replacement-sender-ready");

    assert_eq!(sent["id"], "replacement-send");
    assert_eq!(delivered["id"], "replacement-delivery", "{delivered}");
    assert_eq!(delivered["result"]["task_id"], sent["result"]["task_id"]);
    assert_eq!(second.registration_count().await, 2);
    assert_eq!(second.acknowledgement_count(), 1);

    recipient.close_stdin_and_wait().await;
    sender.close_stdin_and_wait().await;
    second.stop().await;
}

#[tokio::test]
async fn delivery_ack_replacement_keeps_the_original_finite_wait_deadline() {
    // Break caught: wait_for_message returns its delivery before mandatory ACK staging, then ACK
    // recovery uses no deadline and leaves a finite Pi tool pending indefinitely after turnover.
    let runtime = TestBrokerRuntime::new();
    let first = runtime.start_broker().await;
    first.add_agent("implementer", "w1:p1").await;
    first.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&first, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&first, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;
    let first_ack = first.stall_endpoint("/v1/inbox/ack").await;
    let started = tokio::time::Instant::now();

    recipient
        .send(json!({
            "id":"deadline-delivery",
            "method":"wait_for_message",
            "params":{"timeout_ms":2_500}
        }))
        .await;
    sender
        .send(json!({
            "id":"deadline-send",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"deadline-bound ack","wait":false}
        }))
        .await;
    assert_eq!(sender.recv().await["id"], "deadline-send");
    tokio::time::timeout(Duration::from_secs(1), first_ack.wait_until_entered())
        .await
        .expect("first ACK did not commit before replacement");
    tokio::time::sleep(Duration::from_millis(700)).await;

    let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
    let second = runtime.start_broker_for_executable(&executable).await;
    let replacement_health = second.stall_endpoint("/health").await;
    drop(first);
    tokio::time::timeout(
        Duration::from_secs(2),
        replacement_health.wait_until_entered(),
    )
    .await
    .expect("ACK recovery did not reach the replacement broker proof boundary");
    let bounded = tokio::time::timeout(Duration::from_secs(2), recipient.recv()).await;
    replacement_health.release_one();
    let response = bounded.expect("ACK recovery exceeded the original finite wait deadline");
    let elapsed = started.elapsed();

    assert_eq!(response["id"], "deadline-delivery", "{response}");
    assert_eq!(
        response["error"]["code"], "acknowledgement_failed",
        "{response}"
    );
    assert!(
        elapsed >= Duration::from_millis(2_300),
        "deadline ended early: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(2_900),
        "deadline was reset: {elapsed:?}"
    );

    recipient.close_stdin_and_wait().await;
    sender.close_stdin_and_wait().await;
    second.stop().await;
}

#[tokio::test]
async fn inbox_reconnect_survives_restart_without_redelivering_acknowledged_work() {
    // Break caught: a client-session keeps its startup URL/credentials after broker replacement,
    // loses durable inbox work, emits an ACKed delivery twice, or falls back to ListTasks.
    let runtime = TestBrokerRuntime::new();
    let first = runtime.start_broker().await;
    first.add_agent("implementer", "w1:p1").await;
    first.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&first, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&first, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;

    sender
        .send(json!({
            "id":"acked-send",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"already acknowledged","wait":false}
        }))
        .await;
    let acked_task = sender.recv().await["result"]["task_id"]
        .as_str()
        .unwrap()
        .to_owned();
    recipient
        .send(json!({
            "id":"acked-wait",
            "method":"wait_for_message",
            "params":{"timeout_ms":5_000}
        }))
        .await;
    let acknowledged = recipient.recv().await;
    assert_eq!(acknowledged["result"]["task_id"], acked_task);
    assert_eq!(first.acknowledgement_count(), 1);

    sender
        .send(json!({
            "id":"durable-send",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"survives restart","wait":false}
        }))
        .await;
    let durable_task = sender.recv().await["result"]["task_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(durable_task, acked_task);
    drop(first);

    let second = runtime.start_broker().await;
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
    let mut replacement_command = Command::new(&executable);
    second.configure_client(replacement_command.as_std_mut(), &executable);
    recipient
        .send(json!({
            "id":"inbox-reconnect",
            "method":"wait_for_message",
            "params":{"timeout_ms":5_000}
        }))
        .await;
    let recovered = tokio::time::timeout(Duration::from_secs(8), recipient.recv())
        .await
        .expect("the live NDJSON process did not reconnect");
    assert_eq!(recovered["id"], "inbox-reconnect");
    assert_eq!(recovered["result"]["task_id"], durable_task, "{recovered}");
    assert_eq!(recovered["result"]["payload"]["text"], "survives restart");
    assert_ne!(recovered["result"]["task_id"], acked_task);
    assert_eq!(second.registration_count().await, 1);
    assert_eq!(second.acknowledgement_count(), 1);
    assert_eq!(second.task_list_count(), 0);

    let timeout_started = tokio::time::Instant::now();
    recipient
        .send(json!({
            "id":"inbox-reconnect-timeout",
            "method":"wait_for_message",
            "params":{"timeout_ms":1_000}
        }))
        .await;
    let timeout = recipient.recv().await;
    let elapsed = timeout_started.elapsed();
    assert_eq!(timeout["id"], "inbox-reconnect-timeout");
    assert!(
        timeout.get("error").is_some(),
        "ACKed work was redelivered: {timeout}"
    );
    assert!(
        elapsed >= Duration::from_millis(900),
        "timeout reset too early: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(1_750),
        "timeout exceeded its original bound: {elapsed:?}"
    );
    assert_eq!(second.task_list_count(), 0);

    recipient.close_stdin_and_wait().await;
    sender.close_stdin_and_wait().await;
    second.stop().await;
}

#[tokio::test]
async fn inbox_reconnect_finite_timeout_keeps_its_cross_loss_deadline() {
    // Break caught: reconnecting after broker loss starts a fresh finite inbox timeout instead of
    // carrying the deadline created when the old broker received the request.
    let runtime = TestBrokerRuntime::new();
    let first = runtime.start_broker().await;
    first.add_agent("reviewer", "w1:p2").await;
    let wait = first.stall_endpoint("/v1/inbox/wait").await;
    first
        .truncate_endpoint_response_once("/v1/inbox/wait")
        .await;
    let mut recipient = ClientSessionProcess::spawn(&first, "w1:p2", "pi-session-2").await;
    recipient
        .send(json!({"id":"ready","method":"list_agents","params":{}}))
        .await;
    assert_eq!(recipient.recv().await["id"], "ready");

    let started = tokio::time::Instant::now();
    recipient
        .send(json!({
            "id":"cross-loss-timeout",
            "method":"wait_for_message",
            "params":{"timeout_ms":2_000}
        }))
        .await;
    wait.wait_until_entered().await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    wait.release_one();
    tokio::time::sleep(Duration::from_millis(400)).await;

    let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
    let second = runtime.start_broker_for_executable(&executable).await;
    let mut replacement_command = Command::new(&executable);
    second.configure_client(replacement_command.as_std_mut(), &executable);
    drop(first);
    let response = recipient.recv().await;
    let elapsed = started.elapsed();

    assert_eq!(response["id"], "cross-loss-timeout");
    assert!(
        response.get("error").is_some(),
        "unexpected delivery: {response}"
    );
    assert!(
        elapsed >= Duration::from_millis(1_900),
        "cross-loss wait ended early: {elapsed:?}: {response}"
    );
    assert!(
        elapsed < Duration::from_millis(2_300),
        "recovery reset the original wait deadline: {elapsed:?}"
    );
    assert_eq!(second.registration_count().await, 1);
    assert_eq!(second.task_list_count(), 0);
    recipient.close_stdin_and_wait().await;
    second.stop().await;
}

#[tokio::test]
async fn background_inbox_wait_multiplexes_and_recovers_once_after_broker_restart() {
    // Break caught: a pending inbox wait serializes unrelated NDJSON calls, remains pinned to the
    // dead broker, crosses workspace scope during recovery, or replays its delivery or ACK.
    let (workspace, other_workspace) = TestBrokerRuntime::workspace_pair();
    let first = workspace.start_broker().await;
    let other = other_workspace.start_broker().await;
    first.add_agent("implementer", "w1:p1").await;
    first.add_agent("reviewer", "w1:p2").await;
    other.add_agent("reviewer", "w2:p2").await;

    let http = reqwest::Client::new();
    let other_registration: Value = http
        .post(format!("{}/v1/register", other.base_url()))
        .bearer_auth(other.bearer_token())
        .json(&json!({
            "pane_id":"w2:p2",
            "harness_session_id":"other-workspace-reviewer"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(other_registration["registration_id"].is_string());
    assert_eq!(other.active_registration_count().await, 1);

    let mut recipient = ClientSessionProcess::spawn(&first, "w1:p2", "multiplexed-reviewer").await;
    recipient
        .send(json!({"id":"client-ready","method":"list_agents","params":{}}))
        .await;
    let ready = tokio::time::timeout(Duration::from_secs(2), recipient.recv())
        .await
        .expect("session client did not complete initial authentication");
    assert_eq!(ready["id"], "client-ready", "{ready}");
    let original_wait = first.stall_endpoint("/v1/inbox/wait").await;
    first
        .truncate_endpoint_response_once("/v1/inbox/wait")
        .await;
    let wait_started = tokio::time::Instant::now();
    recipient
        .send(json!({
            "id":"background-inbox",
            "method":"wait_for_message",
            "params":{"timeout_ms":5_000}
        }))
        .await;
    tokio::time::timeout(Duration::from_secs(2), original_wait.wait_until_entered())
        .await
        .expect("background wait did not reach the original broker");

    recipient
        .send(json!({"id":"multiplexed-directory","method":"list_agents","params":{}}))
        .await;
    let directory = tokio::time::timeout(Duration::from_secs(2), recipient.recv())
        .await
        .expect("list_agents serialized behind the pending inbox wait");
    assert_eq!(directory["id"], "multiplexed-directory", "{directory}");
    assert!(directory.get("error").is_none(), "{directory}");

    let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
    let second = workspace.start_broker_for_executable(&executable).await;
    let replacement_wait = second.stall_endpoint("/v1/inbox/wait").await;
    original_wait.release_one();
    tokio::time::timeout(
        Duration::from_secs(2),
        replacement_wait.wait_until_entered(),
    )
    .await
    .expect("pending inbox wait was not reissued on the replacement broker");
    drop(first);

    let sender_registration: Value = http
        .post(format!("{}/v1/register", second.base_url()))
        .bearer_auth(second.bearer_token())
        .json(&json!({
            "pane_id":"w1:p1",
            "harness_session_id":"replacement-sender"
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let recipient_name = canonical_agent(&second, "reviewer").await;
    let request = SendMessageRequest {
        message: Message::new(Role::User, vec![Part::text("one recovered delivery")]),
        configuration: Some(SendMessageConfiguration {
            accepted_output_modes: Some(vec!["text/plain".to_owned()]),
            task_push_notification_config: None,
            history_length: None,
            return_immediately: Some(true),
        }),
        metadata: None,
        tenant: Some(recipient_name),
    };
    let enqueued: Value = http
        .post(format!("{}/jsonrpc", second.base_url()))
        .bearer_auth(second.bearer_token())
        .header(
            "x-herdr-a2a-registration",
            sender_registration["registration_id"].as_str().unwrap(),
        )
        .header(
            "x-herdr-a2a-registration-epoch",
            sender_registration["registration_epoch"].as_u64().unwrap(),
        )
        .json(&json!({
            "jsonrpc":"2.0",
            "id":"replacement-enqueue",
            "method":"SendMessage",
            "params":request,
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(enqueued.get("error").is_none(), "{enqueued}");
    let task_id = enqueued["result"]["task"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    replacement_wait.release_one();

    let delivered = tokio::time::timeout(Duration::from_secs(2), recipient.recv())
        .await
        .expect("reissued inbox wait did not deliver replacement work");
    assert_eq!(delivered["id"], "background-inbox", "{delivered}");
    assert_eq!(delivered["result"]["task_id"], task_id, "{delivered}");
    assert_eq!(
        delivered["result"]["payload"]["text"], "one recovered delivery",
        "{delivered}"
    );
    assert!(
        wait_started.elapsed() < Duration::from_secs(5),
        "delivery exceeded the original absolute wait deadline"
    );
    assert_eq!(second.delivery_count(), 1);
    assert_eq!(second.acknowledgement_count(), 1);
    assert_eq!(other_workspace.task_count().await, 0);
    assert_eq!(other.delivery_count(), 0);
    assert_eq!(other.acknowledgement_count(), 0);

    recipient
        .send(json!({
            "id":"no-second-delivery",
            "method":"wait_for_message",
            "params":{"timeout_ms":1_000}
        }))
        .await;
    let no_second = tokio::time::timeout(Duration::from_millis(1_500), recipient.recv())
        .await
        .expect("bounded duplicate-delivery probe did not finish");
    assert_eq!(no_second["id"], "no-second-delivery", "{no_second}");
    assert_eq!(no_second["error"]["code"], "request_failed", "{no_second}");
    assert_eq!(second.delivery_count(), 1);
    assert_eq!(second.acknowledgement_count(), 1);
    assert_eq!(other_workspace.task_count().await, 0);

    recipient.close_stdin_and_wait().await;
    second.stop().await;
    other.stop().await;
}

#[tokio::test]
async fn stale_registration_is_fenced_from_every_private_mutation_after_restart() {
    // Break caught: a replacement broker accepts an old registration ID/epoch with its new bearer
    // for any lifecycle or inbox/task mutation.
    let runtime = TestBrokerRuntime::new();
    let first = runtime.start_broker().await;
    first.add_agent("reviewer", "w1:p2").await;
    let registration: Value = reqwest::Client::new()
        .post(format!("{}/v1/register", first.base_url()))
        .bearer_auth(first.bearer_token())
        .json(&json!({"pane_id":"w1:p2","harness_session_id":"stale-session"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let old_id = registration["registration_id"].as_str().unwrap().to_owned();
    let old_epoch = registration["registration_epoch"].as_u64().unwrap();
    first.stop().await;

    let second = runtime.start_broker().await;
    let http = reqwest::Client::new();
    let replacement: Value = http
        .post(format!("{}/v1/register", second.base_url()))
        .bearer_auth(second.bearer_token())
        .json(&json!({"pane_id":"w1:p2","harness_session_id":"replacement-session"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_ne!(replacement["registration_id"], old_id);
    let delivery_id = DeliveryId::new();
    for (path, body) in [
        ("/v1/renew", None),
        (
            "/v1/inbox/ack",
            Some(json!({"delivery_id":delivery_id.as_str()})),
        ),
        (
            "/v1/tasks/task-stale/reply",
            Some(json!({"text":"stale","metadata":{},"file_refs":[]})),
        ),
    ] {
        let mut request = http
            .post(format!("{}{path}", second.base_url()))
            .bearer_auth(second.bearer_token())
            .header("x-herdr-a2a-registration", &old_id)
            .header("x-herdr-a2a-registration-epoch", old_epoch);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.unwrap();
        assert_eq!(
            response.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "{path}"
        );
    }
    let stale_unregister = http
        .post(format!("{}/v1/unregister", second.base_url()))
        .bearer_auth(second.bearer_token())
        .header("x-herdr-a2a-registration", &old_id)
        .header("x-herdr-a2a-registration-epoch", old_epoch)
        .send()
        .await
        .unwrap();
    assert!(stale_unregister.status().is_success());
    assert_eq!(second.active_registration_count().await, 1);
    assert_eq!(second.acknowledgement_count(), 0);
    assert_eq!(second.unregistration_count(), 1);
    second.stop().await;
}

#[tokio::test]
async fn timed_out_send_can_resume_after_a_later_reply_with_one_owner_get() {
    // Break caught: timeout returns an orphaned working task that cannot recover its reply.
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&broker, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;
    let reviewer = canonical_agent(&broker, "reviewer").await;
    recipient
        .send(json!({
            "id":"delivery",
            "method":"wait_for_message",
            "params":{"timeout_ms":5_000}
        }))
        .await;
    sender
        .send(json!({
            "id":"initial",
            "method":"send_message",
            "params":{
                "agent":"reviewer",
                "text":"review after timeout",
                "timeout_ms":1_000
            }
        }))
        .await;

    let delivery = recipient.recv().await;
    let timed_out = sender.recv().await;
    let task_id = delivery["result"]["task_id"].as_str().unwrap();
    let conversation_id = delivery["result"]["context_id"].as_str().unwrap();
    assert_eq!(timed_out["result"]["agent"], reviewer);
    assert_eq!(timed_out["result"]["task_id"], task_id);
    assert_eq!(timed_out["result"]["conversation_id"], conversation_id);
    assert_eq!(timed_out["result"]["resume_task_id"], task_id);
    assert_eq!(timed_out["result"]["timed_out"], true);
    assert_eq!(broker.task_get_count(), 0);
    assert_eq!(broker.task_subscription_count(), 0);

    recipient
        .send(json!({
            "id":"reply",
            "method":"reply",
            "params":{"task_id":task_id,"text":"approved later"}
        }))
        .await;
    assert_eq!(recipient.recv().await["id"], "reply");
    sender
        .send(json!({
            "id":"resume",
            "method":"send_message",
            "params":{"agent":reviewer,"resume_task_id":task_id,"timeout_ms":5_000}
        }))
        .await;

    let resumed = sender.recv().await;
    assert_eq!(resumed["id"], "resume");
    assert_eq!(resumed["result"]["state"], "completed");
    assert_eq!(resumed["result"]["text"], "approved later");
    assert_eq!(broker.task_get_count(), 1);
    assert_eq!(broker.task_subscription_count(), 0);
    assert_eq!(broker.task_list_count(), 0);
}

#[tokio::test]
async fn send_recovers_after_restart_during_agent_card_resolution() {
    // Break caught: Agent Card resolution retains the dead SessionContext snapshot and returns
    // before the stable send operation can be continued through a replacement registration.
    let runtime = TestBrokerRuntime::new();
    let first = runtime.start_broker().await;
    first.add_agent("implementer", "w1:p1").await;
    first.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&first, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&first, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;
    let reviewer = canonical_agent(&first, "reviewer").await;
    let card_path = agent_card_endpoint(&reviewer);
    let card = first.stall_endpoint_response_once(&card_path).await;
    let recipient_reconnect = first.stall_endpoint("/v1/agents").await;
    first.truncate_endpoint_response_once("/v1/agents").await;
    recipient
        .send(json!({"id":"recipient-reconnect","method":"list_agents","params":{}}))
        .await;
    tokio::time::timeout(
        Duration::from_secs(2),
        recipient_reconnect.wait_until_entered(),
    )
    .await
    .expect("recipient reconnect request did not reach its response gate");

    sender
        .send(json!({
            "id":"send-restart-card",
            "method":"send_message",
            "params":{
                "agent":"reviewer",
                "text":"preserve this operation",
                "timeout_ms":5_000
            }
        }))
        .await;
    tokio::time::timeout(Duration::from_secs(2), card.wait_until_entered())
        .await
        .expect("send did not reach Agent Card resolution");

    let second = runtime.start_broker().await;
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
    let mut replacement_command = Command::new(&executable);
    second.configure_client(replacement_command.as_std_mut(), &executable);
    drop(first);
    recipient_reconnect.release_one();
    let recipient_ready = tokio::time::timeout(Duration::from_secs(3), recipient.recv())
        .await
        .expect("recipient session did not register with the replacement broker");
    assert_eq!(recipient_ready["id"], "recipient-reconnect");
    recipient
        .send(json!({
            "id":"delivery",
            "method":"wait_for_message",
            "params":{"timeout_ms":5_000}
        }))
        .await;
    card.release_one();

    let delivery = match tokio::time::timeout(Duration::from_secs(5), recipient.recv()).await {
        Ok(delivery) => delivery,
        Err(error) => {
            let sender_state =
                tokio::time::timeout(Duration::from_millis(100), sender.recv()).await;
            panic!(
                "replacement recipient did not receive the recovered send: {error:?}; sender={sender_state:?}"
            );
        }
    };
    if delivery.get("result").is_none() {
        let sender_state = tokio::time::timeout(Duration::from_millis(100), sender.recv()).await;
        panic!("delivery failed: {delivery}; sender={sender_state:?}");
    }
    let task_id = delivery["result"]["task_id"].as_str().unwrap();
    let context_id = delivery["result"]["context_id"].as_str().unwrap();
    assert_eq!(
        delivery["result"]["payload"]["text"],
        "preserve this operation"
    );
    recipient
        .send(json!({
            "id":"reply",
            "method":"reply",
            "params":{"task_id":task_id,"text":"exact recovered reply"}
        }))
        .await;
    assert_eq!(recipient.recv().await["id"], "reply");

    let recovered = tokio::time::timeout(Duration::from_secs(5), sender.recv())
        .await
        .expect("sender did not finish through the replacement broker");
    assert_eq!(recovered["id"], "send-restart-card");
    assert_eq!(recovered["result"]["task_id"], task_id);
    assert_eq!(recovered["result"]["conversation_id"], context_id);
    assert_eq!(recovered["result"]["state"], "completed");
    assert_eq!(recovered["result"]["text"], "exact recovered reply");
    assert_eq!(runtime.task_count().await, 1);
    assert_eq!(second.registration_count().await, 2);
    assert_eq!(second.delivery_count(), 1);
    assert_eq!(second.task_get_count(), 1);
    assert_eq!(second.streaming_send_count(), 1);
    assert_eq!(second.task_subscription_count(), 0);
    assert_eq!(second.task_list_count(), 0);
    assert_no_second_task7_delivery(&mut recipient, &second).await;
}

async fn restart_with_recipient_session(
    runtime: &TestBrokerRuntime,
    first: TestBroker,
    recipient: &mut ClientSessionProcess,
) -> TestBroker {
    let reconnect = first.stall_endpoint("/v1/agents").await;
    first.truncate_endpoint_response_once("/v1/agents").await;
    recipient
        .send(json!({"id":"recipient-reconnect","method":"list_agents","params":{}}))
        .await;
    tokio::time::timeout(Duration::from_secs(2), reconnect.wait_until_entered())
        .await
        .expect("recipient reconnect did not reach the old broker gate");
    let second = runtime.start_broker().await;
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
    let mut replacement_command = Command::new(&executable);
    second.configure_client(replacement_command.as_std_mut(), &executable);
    drop(first);
    reconnect.release_one();
    let response = tokio::time::timeout(Duration::from_secs(3), recipient.recv())
        .await
        .expect("recipient did not recover to the replacement broker");
    assert_eq!(response["id"], "recipient-reconnect", "{response}");
    second
}

async fn await_task7_gate(gate: &EndpointStall, description: &str) {
    tokio::time::timeout(Duration::from_secs(2), gate.wait_until_entered())
        .await
        .unwrap_or_else(|_| panic!("{description} did not reach its observable gate"));
}

async fn assert_no_second_task7_delivery(
    recipient: &mut ClientSessionProcess,
    broker: &TestBroker,
) {
    recipient
        .send(json!({
            "id":"task7-no-second-delivery",
            "method":"wait_for_message",
            "params":{"timeout_ms":1_000}
        }))
        .await;
    let response = tokio::time::timeout(Duration::from_millis(1_500), recipient.recv())
        .await
        .expect("bounded second recipient receive did not finish");
    assert_eq!(response["error"]["code"], "request_failed", "{response}");
    assert_eq!(broker.delivery_count(), 1);
}

async fn send_collision_task(broker: &TestBroker, owner: &str, task_id: &str, context_id: &str) {
    let registration = broker.registration_for_agent(owner).await;
    let recipient = canonical_agent(broker, "reviewer").await;
    let mut message = Message::new(Role::User, vec![Part::text("collision owner payload")]);
    message.task_id = Some(task_id.to_owned());
    message.context_id = Some(context_id.to_owned());
    let request = SendMessageRequest {
        message,
        configuration: Some(SendMessageConfiguration {
            accepted_output_modes: Some(vec!["text/plain".to_owned()]),
            task_push_notification_config: None,
            history_length: None,
            return_immediately: Some(true),
        }),
        metadata: None,
        tenant: Some(recipient),
    };
    let response = reqwest::Client::new()
        .post(format!("{}/jsonrpc", broker.base_url()))
        .bearer_auth(broker.bearer_token())
        .header("x-herdr-a2a-registration", registration.id.as_str())
        .header(
            "x-herdr-a2a-registration-epoch",
            registration.epoch.get().to_string(),
        )
        .json(&json!({
            "jsonrpc":"2.0",
            "id":"install-collision",
            "method":"SendMessage",
            "params":request,
        }))
        .send()
        .await
        .unwrap();
    let body: Value = response.json().await.unwrap();
    assert!(
        body.get("error").is_none(),
        "collision setup failed: {body}"
    );
    assert_eq!(body["result"]["task"]["id"], task_id);
}

async fn assert_streaming_send_restart(pre_working: bool) {
    let runtime = TestBrokerRuntime::new();
    let first = runtime.start_broker().await;
    first.add_agent("implementer", "w1:p1").await;
    first.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&first, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&first, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;
    recipient
        .send(json!({"id":"delivery","method":"wait_for_message","params":{"timeout_ms":5_000}}))
        .await;
    let send_response = first
        .stall_jsonrpc_response_once("SendStreamingMessage")
        .await;
    if pre_working {
        first
            .truncate_jsonrpc_response_once("SendStreamingMessage")
            .await;
    } else {
        first
            .truncate_jsonrpc_stream_once("SendStreamingMessage")
            .await;
    }
    sender
        .send(json!({
            "id":"streaming-restart",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"stream exactly once","timeout_ms":5_000}
        }))
        .await;
    await_task7_gate(&send_response, "streaming send").await;
    let delivery = recipient.recv().await;
    let task_id = delivery["result"]["task_id"].as_str().unwrap();
    let context_id = delivery["result"]["context_id"].as_str().unwrap();
    assert_eq!(first.delivery_count(), 1);
    assert_eq!(first.streaming_send_count(), 1);
    assert_eq!(first.task_list_count(), 0);
    assert_eq!(first.task_get_count(), 0);
    assert_eq!(first.task_subscription_count(), 0);
    let second = restart_with_recipient_session(&runtime, first, &mut recipient).await;
    send_response.release_one();
    tokio::time::timeout(Duration::from_secs(2), async {
        while second.task_subscription_count() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("stream recovery did not subscribe on the replacement broker");
    recipient
        .send(json!({
            "id":"reply",
            "method":"reply",
            "params":{"task_id":task_id,"text":"stream replacement reply"}
        }))
        .await;
    assert_eq!(recipient.recv().await["id"], "reply");
    let recovered = sender.recv().await;
    assert_eq!(recovered["result"]["task_id"], task_id);
    assert_eq!(recovered["result"]["conversation_id"], context_id);
    assert_eq!(recovered["result"]["state"], "completed");
    assert_eq!(recovered["result"]["text"], "stream replacement reply");
    assert_eq!(runtime.task_count().await, 1);
    assert_eq!(second.registration_count().await, 2);
    assert_eq!(second.delivery_count(), 1);
    assert_eq!(second.task_get_count(), 1);
    assert_eq!(second.streaming_send_count(), 0);
    assert_eq!(second.task_subscription_count(), 1);
    assert_eq!(second.task_list_count(), 0);
    assert_no_second_task7_delivery(&mut recipient, &second).await;
}

#[tokio::test]
async fn send_recovers_after_restart_during_streaming_pre_working() {
    assert_streaming_send_restart(true).await;
}

#[tokio::test]
async fn send_recovers_after_restart_during_streaming_post_working() {
    assert_streaming_send_restart(false).await;
}

#[tokio::test]
async fn reply_waiting_send_survives_replacement_card_registration_gap() {
    // Break caught: the sender reaches the replacement before the recipient re-registers, treats
    // the recipient Agent Card's transient HTTP 404 as a final protocol failure, and abandons the
    // durable reply-waiting operation instead of preserving its stable identity until registration.
    let runtime = TestBrokerRuntime::new();
    let first = runtime.start_broker().await;
    first.add_agent("implementer", "w1:p1").await;
    first.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&first, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&first, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;
    recipient
        .send(json!({"id":"delivery","method":"wait_for_message","params":{"timeout_ms":5_000}}))
        .await;
    let send_response = first
        .stall_jsonrpc_response_once("SendStreamingMessage")
        .await;
    first
        .truncate_jsonrpc_stream_once("SendStreamingMessage")
        .await;
    sender
        .send(json!({
            "id":"replacement-card-registration-gap",
            "method":"send_message",
            "params":{
                "agent":"reviewer",
                "text":"preserve send across registration gap",
                "timeout_ms":5_000
            }
        }))
        .await;
    await_task7_gate(&send_response, "registration-gap streaming send").await;
    let delivery = recipient.recv().await;
    let task_id = delivery["result"]["task_id"].as_str().unwrap().to_owned();
    let context_id = delivery["result"]["context_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let reviewer = canonical_agent(&first, "reviewer").await;
    assert_eq!(first.delivery_count(), 1);
    assert_eq!(first.send_message_count(), 0);
    assert_eq!(first.streaming_send_count(), 1);
    assert_eq!(first.task_list_count(), 0);

    let second = runtime.start_broker().await;
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
    let mut replacement_command = Command::new(&executable);
    second.configure_client(replacement_command.as_std_mut(), &executable);
    let card_path = agent_card_endpoint(&reviewer);
    let missing_card = second.stall_endpoint_response_once(&card_path).await;
    drop(first);
    send_response.release_one();
    await_task7_gate(&missing_card, "replacement reviewer Agent Card 404").await;

    recipient
        .send(json!({"id":"recipient-reconnect","method":"list_agents","params":{}}))
        .await;
    let reconnect = tokio::time::timeout(Duration::from_secs(3), recipient.recv())
        .await
        .expect("recipient did not re-register on the replacement broker");
    assert_eq!(reconnect["id"], "recipient-reconnect", "{reconnect}");
    missing_card.release_one();

    if let Ok(response) = tokio::time::timeout(Duration::from_millis(250), sender.recv()).await {
        panic!("transient replacement Agent Card gap ended the original send: {response}");
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while second.task_subscription_count() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("original send did not retry discovery and subscribe after recipient registration");
    assert_eq!(second.task_get_count(), 1);
    assert_eq!(second.task_subscription_count(), 1);
    recipient
        .send(json!({
            "id":"reply",
            "method":"reply",
            "params":{"task_id":task_id,"text":"review approved"}
        }))
        .await;
    assert_eq!(recipient.recv().await["id"], "reply");

    let recovered = tokio::time::timeout(Duration::from_secs(5), sender.recv())
        .await
        .expect("original blocking send did not resolve after the replacement reply");
    assert_eq!(recovered["id"], "replacement-card-registration-gap");
    assert!(recovered.get("error").is_none(), "{recovered}");
    assert_eq!(recovered["result"]["task_id"], task_id);
    assert_eq!(recovered["result"]["conversation_id"], context_id);
    assert_eq!(recovered["result"]["state"], "completed");
    assert_eq!(recovered["result"]["text"], "review approved");
    assert_eq!(runtime.task_count().await, 1);
    assert_eq!(second.registration_count().await, 2);
    assert_eq!(second.delivery_count(), 1);
    assert_eq!(second.send_message_count(), 0);
    assert_eq!(second.streaming_send_count(), 0);
    assert_eq!(second.task_list_count(), 0);
    assert_no_second_task7_delivery(&mut recipient, &second).await;
}

#[tokio::test]
async fn streaming_operation_survives_multiple_connection_losses() {
    // Break caught: the second connection loss drops the stable operation memory or routes into
    // a legacy loop, causing another send, a new identity, or loss of the terminal projection.
    let runtime = TestBrokerRuntime::new();
    let first = runtime.start_broker().await;
    first.add_agent("implementer", "w1:p1").await;
    first.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&first, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&first, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;
    recipient
        .send(json!({"id":"delivery","method":"wait_for_message","params":{"timeout_ms":5_000}}))
        .await;
    let first_stream = first
        .stall_jsonrpc_response_once("SendStreamingMessage")
        .await;
    first
        .truncate_jsonrpc_stream_once("SendStreamingMessage")
        .await;
    sender
        .send(json!({
            "id":"multiple-losses",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"one identity across two losses","timeout_ms":8_000}
        }))
        .await;
    await_task7_gate(&first_stream, "first streaming response").await;
    let delivery = recipient.recv().await;
    let task_id = delivery["result"]["task_id"].as_str().unwrap().to_owned();
    let context_id = delivery["result"]["context_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(first.delivery_count(), 1);
    assert_eq!(first.streaming_send_count(), 1);

    let second = restart_with_recipient_session(&runtime, first, &mut recipient).await;
    let second_subscribe = second.stall_jsonrpc_response_once("SubscribeToTask").await;
    second
        .truncate_jsonrpc_response_once("SubscribeToTask")
        .await;
    first_stream.release_one();
    await_task7_gate(&second_subscribe, "second-instance SubscribeToTask").await;
    assert_eq!(second.task_get_count(), 1);
    assert_eq!(second.task_subscription_count(), 1);
    assert_eq!(second.streaming_send_count(), 0);

    let third = restart_with_recipient_session(&runtime, second, &mut recipient).await;
    second_subscribe.release_one();
    tokio::time::timeout(Duration::from_secs(2), async {
        while third.task_subscription_count() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("second loss did not reach third-instance subscription");
    recipient
        .send(json!({
            "id":"reply",
            "method":"reply",
            "params":{"task_id":task_id,"text":"terminal after two losses"}
        }))
        .await;
    assert_eq!(recipient.recv().await["id"], "reply");
    let recovered = sender.recv().await;
    assert_eq!(recovered["result"]["task_id"], task_id);
    assert_eq!(recovered["result"]["conversation_id"], context_id);
    assert_eq!(recovered["result"]["state"], "completed");
    assert_eq!(recovered["result"]["text"], "terminal after two losses");
    assert_eq!(runtime.task_count().await, 1);
    assert_eq!(third.delivery_count(), 1);
    assert_eq!(third.task_get_count(), 1);
    assert_eq!(third.task_subscription_count(), 1);
    assert_eq!(third.streaming_send_count(), 0);
    assert_eq!(third.task_list_count(), 0);
    assert_no_second_task7_delivery(&mut recipient, &third).await;
}

#[tokio::test]
async fn resume_recovers_after_restart_during_subscribe() {
    // Break caught: explicit resume retains the dead A2A client after its owner GetTask and
    // returns stream_lost instead of replaying the replacement broker's retained terminal task.
    let runtime = TestBrokerRuntime::new();
    let first = runtime.start_broker().await;
    first.add_agent("implementer", "w1:p1").await;
    first.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&first, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&first, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;
    recipient
        .send(json!({"id":"delivery","method":"wait_for_message","params":{"timeout_ms":5_000}}))
        .await;
    sender
        .send(json!({
            "id":"start",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"resume across restart","wait":false}
        }))
        .await;
    let started = sender.recv().await;
    let reviewer = started["result"]["agent"].as_str().unwrap().to_owned();
    let delivery = recipient.recv().await;
    let task_id = started["result"]["task_id"].as_str().unwrap();
    let context_id = started["result"]["conversation_id"].as_str().unwrap();
    assert_eq!(delivery["result"]["task_id"], task_id);

    let subscribe = first.stall_jsonrpc_method("SubscribeToTask").await;
    first.truncate_jsonrpc_stream_once("SubscribeToTask").await;
    sender
        .send(json!({
            "id":"resume-restart-subscribe",
            "method":"send_message",
            "params":{"agent":reviewer,"resume_task_id":task_id,"timeout_ms":5_000}
        }))
        .await;
    tokio::time::timeout(Duration::from_secs(2), subscribe.wait_until_entered())
        .await
        .expect("resume did not reach SubscribeToTask");
    assert_eq!(first.delivery_count(), 1);
    assert_eq!(first.send_message_count(), 1);
    assert_eq!(first.task_get_count(), 1);
    assert_eq!(first.task_subscription_count(), 1);
    assert_eq!(first.task_list_count(), 0);

    let recipient_reconnect = first.stall_endpoint("/v1/agents").await;
    first.truncate_endpoint_response_once("/v1/agents").await;
    recipient
        .send(json!({"id":"recipient-reconnect","method":"list_agents","params":{}}))
        .await;
    await_task7_gate(&recipient_reconnect, "recipient reconnect").await;
    let second = runtime.start_broker().await;
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
    let mut replacement_command = Command::new(&executable);
    second.configure_client(replacement_command.as_std_mut(), &executable);
    drop(first);
    recipient_reconnect.release_one();
    assert_eq!(recipient.recv().await["id"], "recipient-reconnect");
    subscribe.release_one();

    tokio::time::timeout(Duration::from_secs(2), async {
        while second.task_subscription_count() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Subscribe recovery did not subscribe on the replacement broker");

    recipient
        .send(json!({
            "id":"reply",
            "method":"reply",
            "params":{"task_id":task_id,"text":"exact resumed reply"}
        }))
        .await;
    assert_eq!(recipient.recv().await["id"], "reply");
    let resumed = tokio::time::timeout(Duration::from_secs(5), sender.recv())
        .await
        .expect("resume did not finish through the replacement broker");
    assert_eq!(resumed["id"], "resume-restart-subscribe");
    assert_eq!(resumed["result"]["task_id"], task_id);
    assert_eq!(resumed["result"]["conversation_id"], context_id);
    assert_eq!(resumed["result"]["state"], "completed");
    assert_eq!(resumed["result"]["text"], "exact resumed reply");
    assert_eq!(runtime.task_count().await, 1);
    assert_eq!(second.registration_count().await, 2);
    assert_eq!(second.delivery_count(), 1);
    assert_eq!(second.task_get_count(), 1);
    assert_eq!(second.send_message_count(), 0);
    assert_eq!(second.streaming_send_count(), 0);
    assert_eq!(second.task_subscription_count(), 1);
    assert_eq!(second.task_list_count(), 0);
    assert_no_second_task7_delivery(&mut recipient, &second).await;
}

#[tokio::test]
async fn resume_recovers_after_restart_during_get_task() {
    // Break caught: explicit resume loses its stable ID when the owner GetTask committed a
    // response on the old instance but the response body was lost during restart.
    let runtime = TestBrokerRuntime::new();
    let first = runtime.start_broker().await;
    first.add_agent("implementer", "w1:p1").await;
    first.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&first, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&first, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;
    recipient
        .send(json!({"id":"delivery","method":"wait_for_message","params":{"timeout_ms":5_000}}))
        .await;
    sender
        .send(json!({
            "id":"start",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"resume get restart","wait":false}
        }))
        .await;
    let started = sender.recv().await;
    let reviewer = started["result"]["agent"].as_str().unwrap().to_owned();
    let delivery = recipient.recv().await;
    let task_id = started["result"]["task_id"].as_str().unwrap();
    let context_id = started["result"]["conversation_id"].as_str().unwrap();
    assert_eq!(delivery["result"]["task_id"], task_id);

    let get_response = first.stall_jsonrpc_response_once("GetTask").await;
    first.truncate_jsonrpc_response_once("GetTask").await;
    sender
        .send(json!({
            "id":"resume-restart-get",
            "method":"send_message",
            "params":{"agent":reviewer,"resume_task_id":task_id,"timeout_ms":5_000}
        }))
        .await;
    await_task7_gate(&get_response, "resume GetTask").await;
    assert_eq!(first.delivery_count(), 1);
    assert_eq!(first.send_message_count(), 1);
    assert_eq!(first.task_get_count(), 1);
    assert_eq!(first.task_subscription_count(), 0);
    assert_eq!(first.task_list_count(), 0);
    let second = restart_with_recipient_session(&runtime, first, &mut recipient).await;
    get_response.release_one();
    tokio::time::timeout(Duration::from_secs(2), async {
        while second.task_subscription_count() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("resume GetTask recovery did not subscribe on replacement");
    recipient
        .send(json!({
            "id":"reply",
            "method":"reply",
            "params":{"task_id":task_id,"text":"resume get exact reply"}
        }))
        .await;
    assert_eq!(recipient.recv().await["id"], "reply");
    let resumed = sender.recv().await;
    assert_eq!(resumed["result"]["task_id"], task_id);
    assert_eq!(resumed["result"]["conversation_id"], context_id);
    assert_eq!(resumed["result"]["state"], "completed");
    assert_eq!(resumed["result"]["text"], "resume get exact reply");
    assert_eq!(runtime.task_count().await, 1);
    assert_eq!(second.registration_count().await, 2);
    assert_eq!(second.delivery_count(), 1);
    assert_eq!(second.task_get_count(), 1);
    assert_eq!(second.send_message_count(), 0);
    assert_eq!(second.streaming_send_count(), 0);
    assert_eq!(second.task_subscription_count(), 1);
    assert_eq!(second.task_list_count(), 0);
    assert_no_second_task7_delivery(&mut recipient, &second).await;
}

#[tokio::test]
async fn recovered_subscribe_transport_error_runs_final_get_on_live_replacement() {
    // Break caught: after recovery GetTask confirms Working, a transport failure creating the
    // replacement subscription skips final GetTask and waits for a third broker instance.
    let runtime = TestBrokerRuntime::new();
    let first = runtime.start_broker().await;
    first.add_agent("implementer", "w1:p1").await;
    first.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&first, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&first, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;
    recipient
        .send(json!({"id":"delivery","method":"wait_for_message","params":{"timeout_ms":5_000}}))
        .await;
    sender
        .send(json!({
            "id":"start",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"working recovery task","wait":false}
        }))
        .await;
    let started = sender.recv().await;
    let reviewer = started["result"]["agent"].as_str().unwrap().to_owned();
    let delivery = recipient.recv().await;
    let task_id = started["result"]["task_id"].as_str().unwrap();
    let context_id = started["result"]["conversation_id"].as_str().unwrap();
    assert_eq!(delivery["result"]["task_id"], task_id);

    let old_get = first.stall_jsonrpc_response_once("GetTask").await;
    first.truncate_jsonrpc_response_once("GetTask").await;
    sender
        .send(json!({
            "id":"resume-subscribe-transport",
            "method":"send_message",
            "params":{"agent":reviewer,"resume_task_id":task_id,"timeout_ms":5_000}
        }))
        .await;
    await_task7_gate(&old_get, "old-instance resume GetTask").await;
    assert_eq!(first.delivery_count(), 1);
    assert_eq!(first.send_message_count(), 1);
    assert_eq!(first.task_get_count(), 1);
    assert_eq!(first.task_subscription_count(), 0);
    assert_eq!(first.task_list_count(), 0);
    let second = restart_with_recipient_session(&runtime, first, &mut recipient).await;
    second
        .truncate_jsonrpc_response_once("SubscribeToTask")
        .await;
    old_get.release_one();

    let resumed = tokio::time::timeout(Duration::from_secs(2), sender.recv())
        .await
        .expect("Subscribe transport loss waited for a third broker");
    assert_eq!(resumed["result"]["task_id"], task_id);
    assert_eq!(resumed["result"]["conversation_id"], context_id);
    assert_eq!(resumed["result"]["state"], "working");
    assert_eq!(resumed["result"]["stream_lost"], true);
    assert_eq!(resumed["result"]["task_confirmed"], true);
    assert_eq!(resumed["result"]["task_reachable"], true);
    assert_eq!(second.delivery_count(), 1);
    assert_eq!(second.task_get_count(), 2);
    assert_eq!(second.send_message_count(), 0);
    assert_eq!(second.streaming_send_count(), 0);
    assert_eq!(second.task_subscription_count(), 1);
    assert_eq!(second.task_list_count(), 0);
    assert_eq!(runtime.task_count().await, 1);
    assert_no_second_task7_delivery(&mut recipient, &second).await;
}

#[tokio::test]
async fn resume_recovers_after_restart_during_final_get_race() {
    // Break caught: completion racing the final Get after a closed subscription is lost when
    // that Get response is truncated by restart instead of reacquired by stable task ID.
    let runtime = TestBrokerRuntime::new();
    let first = runtime.start_broker().await;
    first.add_agent("implementer", "w1:p1").await;
    first.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&first, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&first, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;
    recipient
        .send(json!({"id":"delivery","method":"wait_for_message","params":{"timeout_ms":5_000}}))
        .await;
    sender
        .send(json!({
            "id":"start",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"final get race","wait":false}
        }))
        .await;
    let started = sender.recv().await;
    let reviewer = started["result"]["agent"].as_str().unwrap().to_owned();
    let delivery = recipient.recv().await;
    let task_id = started["result"]["task_id"].as_str().unwrap();
    let context_id = started["result"]["conversation_id"].as_str().unwrap();
    assert_eq!(delivery["result"]["task_id"], task_id);

    let subscribe = first.stall_jsonrpc_method("SubscribeToTask").await;
    first.truncate_jsonrpc_stream_once("SubscribeToTask").await;
    sender
        .send(json!({
            "id":"resume-final-get-race",
            "method":"send_message",
            "params":{"agent":reviewer,"resume_task_id":task_id,"timeout_ms":5_000}
        }))
        .await;
    await_task7_gate(&subscribe, "resume final-Get SubscribeToTask").await;
    let final_get = first.stall_jsonrpc_response_once("GetTask").await;
    first.truncate_jsonrpc_response_once("GetTask").await;
    subscribe.release_one();
    tokio::time::timeout(Duration::from_secs(2), final_get.wait_until_entered())
        .await
        .expect("closed subscription did not reach final GetTask");
    recipient
        .send(json!({
            "id":"reply",
            "method":"reply",
            "params":{"task_id":task_id,"text":"won final get restart race"}
        }))
        .await;
    assert_eq!(recipient.recv().await["id"], "reply");
    assert_eq!(first.delivery_count(), 1);
    assert_eq!(first.send_message_count(), 1);
    assert_eq!(first.task_get_count(), 2);
    assert_eq!(first.task_subscription_count(), 1);
    assert_eq!(first.task_list_count(), 0);
    let second = restart_with_recipient_session(&runtime, first, &mut recipient).await;
    final_get.release_one();

    let resumed = tokio::time::timeout(Duration::from_secs(5), sender.recv())
        .await
        .expect("final GetTask restart recovery did not finish");
    assert_eq!(resumed["result"]["task_id"], task_id);
    assert_eq!(resumed["result"]["conversation_id"], context_id);
    assert_eq!(resumed["result"]["state"], "completed");
    assert_eq!(resumed["result"]["text"], "won final get restart race");
    assert_eq!(runtime.task_count().await, 1);
    assert_eq!(second.registration_count().await, 2);
    assert_eq!(second.delivery_count(), 1);
    assert_eq!(second.task_get_count(), 1);
    assert_eq!(second.send_message_count(), 0);
    assert_eq!(second.streaming_send_count(), 0);
    assert_eq!(second.task_subscription_count(), 0);
    assert_eq!(second.task_list_count(), 0);
    assert_no_second_task7_delivery(&mut recipient, &second).await;
}

#[tokio::test]
async fn working_final_get_returns_reachable_stream_lost_without_waiting_for_replacement() {
    // Break caught: a same-instance subscription loss followed by a successful final GetTask
    // waits for a nonexistent replacement until the operation deadline and reports unavailable.
    let runtime = TestBrokerRuntime::new();
    let broker = runtime.start_broker().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&broker, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;
    recipient
        .send(json!({"id":"delivery","method":"wait_for_message","params":{"timeout_ms":5_000}}))
        .await;
    sender
        .send(json!({
            "id":"start",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"still working","wait":false}
        }))
        .await;
    let started = tokio::time::timeout(Duration::from_secs(2), sender.recv())
        .await
        .expect("nonblocking send did not return");
    let reviewer = started["result"]["agent"].as_str().unwrap().to_owned();
    let delivery = tokio::time::timeout(Duration::from_secs(2), recipient.recv())
        .await
        .expect("recipient did not receive task");
    let task_id = started["result"]["task_id"].as_str().unwrap();
    let context_id = started["result"]["conversation_id"].as_str().unwrap();
    assert_eq!(delivery["result"]["task_id"], task_id);

    broker.truncate_jsonrpc_stream_once("SubscribeToTask").await;
    sender
        .send(json!({
            "id":"resume-working-final-get",
            "method":"send_message",
            "params":{"agent":reviewer,"resume_task_id":task_id,"timeout_ms":5_000}
        }))
        .await;

    let resumed = tokio::time::timeout(Duration::from_secs(2), sender.recv())
        .await
        .expect("reachable working task waited for a replacement broker");
    assert_eq!(resumed["result"]["task_id"], task_id);
    assert_eq!(resumed["result"]["conversation_id"], context_id);
    assert_eq!(resumed["result"]["state"], "working");
    assert_eq!(resumed["result"]["stream_lost"], true);
    assert_eq!(resumed["result"]["task_confirmed"], true);
    assert_eq!(resumed["result"]["task_reachable"], true);
    assert_eq!(broker.task_get_count(), 2);
    assert_eq!(broker.delivery_count(), 1);
    assert_eq!(broker.send_message_count(), 1);
    assert_eq!(broker.streaming_send_count(), 0);
    assert_eq!(broker.task_subscription_count(), 1);
    assert_eq!(broker.task_list_count(), 0);
    assert_eq!(runtime.task_count().await, 1);
    assert_no_second_task7_delivery(&mut recipient, &broker).await;
}

#[tokio::test]
async fn application_internal_errors_with_transport_prefixes_are_final() {
    // Break caught: broker-controlled INTERNAL_ERROR text is mistaken for trusted transport
    // provenance and starts replacement recovery instead of returning the application error.
    let runtime = TestBrokerRuntime::new();
    let broker = runtime.start_broker().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&broker, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;

    for (index, prefix) in FORGED_TRANSPORT_PREFIXES.iter().enumerate() {
        let message = format!("{prefix} application-controlled detail");
        broker
            .fail_jsonrpc_method_once("SendMessage", &message)
            .await;
        sender
            .send(json!({
                "id":format!("application-error-{index}"),
                "method":"send_message",
                "params":{
                    "agent":"reviewer",
                    "text":"must stay final",
                    "wait":false,
                    "timeout_ms":1_000
                }
            }))
            .await;
        let response = tokio::time::timeout(Duration::from_millis(500), sender.recv())
            .await
            .unwrap_or_else(|_| panic!("{prefix} incorrectly entered broker recovery"));
        assert_eq!(response["error"]["code"], "request_failed", "{response}");
        assert_eq!(response["error"]["message"], message, "{response}");
    }
    assert_eq!(broker.send_message_count(), FORGED_TRANSPORT_PREFIXES.len());
    assert_eq!(broker.task_get_count(), 0);
    assert_eq!(broker.task_subscription_count(), 0);
    assert_eq!(broker.task_list_count(), 0);
    assert_eq!(runtime.task_count().await, 0);
}

#[tokio::test]
async fn streaming_send_application_errors_with_transport_prefixes_are_final() {
    // Break caught: an HTTP-success JSON-RPC error body without SSE delimiters is discarded at
    // EOF, then treated as recoverable stream loss instead of a final application response.
    let runtime = TestBrokerRuntime::new();
    let broker = runtime.start_broker().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&broker, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;

    for (index, prefix) in FORGED_TRANSPORT_PREFIXES.iter().enumerate() {
        let message = format!("{prefix} streaming application-controlled detail");
        broker
            .fail_jsonrpc_method_once("SendStreamingMessage", &message)
            .await;
        sender
            .send(json!({
                "id":format!("streaming-application-error-{index}"),
                "method":"send_message",
                "params":{
                    "agent":"reviewer",
                    "text":"streaming error must stay final",
                    "timeout_ms":1_000
                }
            }))
            .await;
        let response = tokio::time::timeout(Duration::from_millis(500), sender.recv())
            .await
            .unwrap_or_else(|_| panic!("{prefix} streaming error entered recovery"));
        assert_eq!(response["error"]["code"], "request_failed", "{response}");
        assert_eq!(response["error"]["message"], message, "{response}");
    }

    recipient
        .send(json!({
            "id":"streaming-application-no-delivery",
            "method":"wait_for_message",
            "params":{"timeout_ms":1_000}
        }))
        .await;
    let no_delivery = tokio::time::timeout(Duration::from_millis(1_500), recipient.recv())
        .await
        .expect("bounded recipient receive did not finish");
    assert_eq!(no_delivery["error"]["code"], "request_failed");
    assert_eq!(
        broker.streaming_send_count(),
        FORGED_TRANSPORT_PREFIXES.len()
    );
    assert_eq!(broker.send_message_count(), 0);
    assert_eq!(broker.task_get_count(), 0);
    assert_eq!(broker.task_subscription_count(), 0);
    assert_eq!(broker.task_list_count(), 0);
    assert_eq!(broker.delivery_count(), 0);
    assert_eq!(runtime.task_count().await, 0);
}

#[tokio::test]
async fn subscribe_application_errors_with_transport_prefixes_are_final() {
    // Break caught: SubscribeToTask's JSON-RPC error body is discarded by unconditional SSE
    // parsing, causing a final application error to enter replacement/final-Get recovery.
    let runtime = TestBrokerRuntime::new();
    let broker = runtime.start_broker().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&broker, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;
    recipient
        .send(json!({
            "id":"subscribe-error-delivery",
            "method":"wait_for_message",
            "params":{"timeout_ms":5_000}
        }))
        .await;
    sender
        .send(json!({
            "id":"subscribe-error-start",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"remain working","wait":false}
        }))
        .await;
    let started = tokio::time::timeout(Duration::from_secs(2), sender.recv())
        .await
        .expect("nonblocking send did not return");
    let reviewer = started["result"]["agent"].as_str().unwrap().to_owned();
    let delivery = tokio::time::timeout(Duration::from_secs(2), recipient.recv())
        .await
        .expect("recipient did not receive working task");
    let task_id = started["result"]["task_id"].as_str().unwrap();
    assert_eq!(delivery["result"]["task_id"], task_id);

    for (index, prefix) in FORGED_TRANSPORT_PREFIXES.iter().enumerate() {
        let message = format!("{prefix} subscribe application-controlled detail");
        broker
            .fail_jsonrpc_method_once("SubscribeToTask", &message)
            .await;
        sender
            .send(json!({
                "id":format!("subscribe-application-error-{index}"),
                "method":"send_message",
                "params":{
                    "agent":reviewer,
                    "resume_task_id":task_id,
                    "timeout_ms":1_000
                }
            }))
            .await;
        let response = tokio::time::timeout(Duration::from_millis(500), sender.recv())
            .await
            .unwrap_or_else(|_| panic!("{prefix} subscribe error entered recovery"));
        assert_eq!(response["error"]["code"], "request_failed", "{response}");
        assert_eq!(response["error"]["message"], message, "{response}");
    }

    assert_eq!(broker.send_message_count(), 1);
    assert_eq!(broker.streaming_send_count(), 0);
    assert_eq!(broker.task_get_count(), FORGED_TRANSPORT_PREFIXES.len());
    assert_eq!(
        broker.task_subscription_count(),
        FORGED_TRANSPORT_PREFIXES.len()
    );
    assert_eq!(broker.task_list_count(), 0);
    assert_eq!(runtime.task_count().await, 1);
    assert_no_second_task7_delivery(&mut recipient, &broker).await;
}

#[tokio::test]
async fn recovery_never_resends_when_stable_task_id_belongs_to_another_sender() {
    // Break caught: the authenticated owner-mismatch response is conflated with true absence,
    // causing recovery to replay the normalized send against another sender's stable task ID.
    let runtime = TestBrokerRuntime::new();
    let first = runtime.start_broker().await;
    first.add_agent("implementer", "w1:p1").await;
    first.add_agent("collider", "w1:p3").await;
    first.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&first, "w1:p1", "pi-session-1").await;
    let mut collider = ClientSessionProcess::spawn(&first, "w1:p3", "pi-session-3").await;
    let mut recipient = ClientSessionProcess::spawn(&first, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;
    collider
        .send(json!({"id":"collider-ready","method":"list_agents","params":{}}))
        .await;
    assert_eq!(collider.recv().await["id"], "collider-ready");

    recipient
        .send(json!({"id":"collision-delivery","method":"wait_for_message","params":{"timeout_ms":10_000}}))
        .await;
    let outbound = first.stall_jsonrpc_method("SendStreamingMessage").await;
    first
        .truncate_jsonrpc_response_once("SendStreamingMessage")
        .await;
    sender
        .send(json!({
            "id":"owner-collision",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"must never replay","timeout_ms":10_000}
        }))
        .await;
    await_task7_gate(&outbound, "colliding outbound send").await;
    let captured = first.take_jsonrpc_request("SendStreamingMessage").await;
    let task_id = captured["params"]["message"]["taskId"]
        .as_str()
        .expect("captured send has stable task ID")
        .to_owned();
    let context_id = captured["params"]["message"]["contextId"]
        .as_str()
        .expect("captured send has stable context ID")
        .to_owned();
    send_collision_task(&first, "collider", &task_id, &context_id).await;
    let collision = recipient.recv().await;
    assert_eq!(collision["result"]["task_id"], task_id, "{collision}");
    assert_eq!(
        collision["result"]["payload"]["text"],
        "collision owner payload"
    );
    assert_eq!(first.delivery_count(), 1);
    assert_eq!(first.send_message_count(), 1);
    assert_eq!(first.streaming_send_count(), 1);
    assert_eq!(runtime.task_count().await, 1);

    let second = restart_with_recipient_session(&runtime, first, &mut recipient).await;
    outbound.release_one();
    let rejected = tokio::time::timeout(Duration::from_secs(3), sender.recv())
        .await
        .expect("owner collision did not return a bounded final error");
    assert_eq!(rejected["error"]["code"], "request_failed", "{rejected}");
    assert!(
        rejected["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("owned by another agent")),
        "{rejected}"
    );
    assert_eq!(second.task_get_count(), 1);
    assert_eq!(second.streaming_send_count(), 0);
    assert_eq!(second.task_subscription_count(), 0);
    assert_eq!(second.task_list_count(), 0);
    assert_eq!(runtime.task_count().await, 1);

    recipient
        .send(json!({"id":"no-second-delivery","method":"wait_for_message","params":{"timeout_ms":1_000}}))
        .await;
    let no_delivery = tokio::time::timeout(Duration::from_millis(1_500), recipient.recv())
        .await
        .expect("bounded second recipient receive did not finish");
    assert_eq!(no_delivery["error"]["code"], "request_failed");
    assert_eq!(second.delivery_count(), 1);
}

#[tokio::test]
async fn restart_recovery_preserves_deadline_before_task_confirmation() {
    // Break caught: reconnect starts a fresh timeout or claims a task was reachable even though
    // the first broker disappeared before the operation reached its durable ledger.
    let runtime = TestBrokerRuntime::new();
    let first = runtime.start_broker().await;
    first.add_agent("implementer", "w1:p1").await;
    first.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&first, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&first, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;
    let reviewer = canonical_agent(&first, "reviewer").await;
    let card_path = agent_card_endpoint(&reviewer);
    let card = first.stall_endpoint(&card_path).await;
    first.truncate_endpoint_response_once(&card_path).await;
    let started = tokio::time::Instant::now();
    sender
        .send(json!({
            "id":"deadline-unconfirmed",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"never committed","timeout_ms":1_000}
        }))
        .await;
    await_task7_gate(&card, "deadline Agent Card request").await;
    drop(first);
    card.release_one();

    let response = tokio::time::timeout(Duration::from_millis(1_500), sender.recv())
        .await
        .expect("unconfirmed recovery exceeded its original deadline");
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(900),
        "deadline fired early: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(1_400),
        "deadline reset: {elapsed:?}"
    );
    assert_eq!(response["result"]["requested_agent"], "reviewer");
    assert_eq!(response["result"]["agent"], reviewer);
    assert_eq!(
        response["result"]["resume_task_id"],
        response["result"]["task_id"]
    );
    assert!(response["result"]["conversation_id"].as_str().is_some());
    assert_eq!(response["result"]["state"], "unknown");
    assert_eq!(response["result"]["timed_out"], true);
    assert_eq!(response["result"]["task_confirmed"], false);
    assert_eq!(response["result"]["task_reachable"], false);
    assert_eq!(response["result"]["recovery_reason"], "broker_unavailable");
    assert_eq!(runtime.task_count().await, 0);

    let second = runtime.start_broker().await;
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
    let mut replacement_command = Command::new(&executable);
    second.configure_client(replacement_command.as_std_mut(), &executable);
    recipient
        .send(json!({"id":"recipient-ready-again","method":"list_agents","params":{}}))
        .await;
    assert_eq!(recipient.recv().await["id"], "recipient-ready-again");
    let all_sends = second.stall_jsonrpc_method("SendStreamingMessage").await;
    for index in 0..32 {
        sender
            .send(json!({
                "id":format!("permit-{index}"),
                "method":"send_message",
                "params":{
                    "agent":"reviewer",
                    "text":format!("permit {index}"),
                    "timeout_ms":1_000
                }
            }))
            .await;
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        for _ in 0..32 {
            all_sends.wait_until_entered().await;
        }
    })
    .await
    .expect("not all 32 outbound permits reached the replacement broker gate");
    for _ in 0..32 {
        all_sends.release_one();
    }
    let permit_results = tokio::time::timeout(Duration::from_secs(2), async {
        let mut results = Vec::new();
        for _ in 0..32 {
            results.push(sender.recv().await);
        }
        results
    })
    .await
    .expect("the 32 post-timeout operations did not release their permits");
    assert!(
        permit_results
            .iter()
            .all(|result| result.get("error").is_none()),
        "a supposedly released permit was rejected: {permit_results:?}"
    );
    assert_eq!(second.registration_count().await, 2);
}

#[tokio::test]
async fn restart_recovery_preserves_deadline_after_task_confirmation() {
    // Break caught: a working task becomes unknown/unreachable when the broker disappears, or
    // recovery waits for a fresh timeout instead of retaining the operation's absolute deadline.
    let runtime = TestBrokerRuntime::new();
    let first = runtime.start_broker().await;
    first.add_agent("implementer", "w1:p1").await;
    first.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&first, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&first, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;
    let reviewer = canonical_agent(&first, "reviewer").await;
    recipient
        .send(json!({"id":"delivery","method":"wait_for_message","params":{"timeout_ms":5_000}}))
        .await;
    let response = first
        .stall_jsonrpc_response_once("SendStreamingMessage")
        .await;
    first
        .truncate_jsonrpc_stream_once("SendStreamingMessage")
        .await;
    let started = tokio::time::Instant::now();
    sender
        .send(json!({
            "id":"deadline-confirmed",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"committed before loss","timeout_ms":1_000}
        }))
        .await;
    await_task7_gate(&response, "confirmed streaming send").await;
    let delivery = recipient.recv().await;
    let task_id = delivery["result"]["task_id"].as_str().unwrap();
    let context_id = delivery["result"]["context_id"].as_str().unwrap();
    drop(first);
    response.release_one();

    let timed_out = tokio::time::timeout(Duration::from_millis(1_500), sender.recv())
        .await
        .expect("confirmed recovery exceeded its original deadline");
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(900),
        "deadline fired early: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(1_400),
        "deadline reset: {elapsed:?}"
    );
    assert_eq!(timed_out["result"]["agent"], reviewer);
    assert_eq!(timed_out["result"]["task_id"], task_id);
    assert_eq!(timed_out["result"]["resume_task_id"], task_id);
    assert_eq!(timed_out["result"]["conversation_id"], context_id);
    assert_eq!(timed_out["result"]["state"], "working");
    assert_eq!(timed_out["result"]["timed_out"], true);
    assert_eq!(timed_out["result"]["task_confirmed"], true);
    assert_eq!(timed_out["result"]["task_reachable"], true);
    assert_eq!(timed_out["result"]["recovery_reason"], "deadline_expired");
    assert_eq!(runtime.task_count().await, 1);
}

#[tokio::test]
async fn send_recovers_after_restart_during_unary_pre_response_ambiguous_send_completed() {
    // Break caught: a committed unary send whose response is lost is replayed with a new task ID
    // or delivered twice instead of resolving the retained Completed projection by stable ID.
    let runtime = TestBrokerRuntime::new();
    let first = runtime.start_broker().await;
    first.add_agent("implementer", "w1:p1").await;
    first.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&first, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&first, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;
    recipient
        .send(json!({"id":"delivery","method":"wait_for_message","params":{"timeout_ms":5_000}}))
        .await;
    let send_response = first.stall_jsonrpc_response_once("SendMessage").await;
    first.truncate_jsonrpc_response_once("SendMessage").await;
    sender
        .send(json!({
            "id":"ambiguous-send-completed",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"exactly once","wait":false,"timeout_ms":5_000}
        }))
        .await;
    await_task7_gate(&send_response, "ambiguous unary send").await;
    let delivery = recipient.recv().await;
    let task_id = delivery["result"]["task_id"].as_str().unwrap();
    let context_id = delivery["result"]["context_id"].as_str().unwrap();
    assert_eq!(delivery["result"]["payload"]["text"], "exactly once");
    recipient
        .send(json!({
            "id":"reply",
            "method":"reply",
            "params":{"task_id":task_id,"text":"retained terminal reply"}
        }))
        .await;
    assert_eq!(recipient.recv().await["id"], "reply");

    let recipient_reconnect = first.stall_endpoint("/v1/agents").await;
    first.truncate_endpoint_response_once("/v1/agents").await;
    recipient
        .send(json!({"id":"recipient-reconnect","method":"list_agents","params":{}}))
        .await;
    await_task7_gate(&recipient_reconnect, "recipient reconnect").await;
    assert_eq!(first.delivery_count(), 1);
    assert_eq!(first.send_message_count(), 1);
    assert_eq!(first.streaming_send_count(), 0);
    assert_eq!(first.task_get_count(), 0);
    assert_eq!(first.task_subscription_count(), 0);
    assert_eq!(first.task_list_count(), 0);
    let second = runtime.start_broker().await;
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
    let mut replacement_command = Command::new(&executable);
    second.configure_client(replacement_command.as_std_mut(), &executable);
    drop(first);
    recipient_reconnect.release_one();
    assert_eq!(recipient.recv().await["id"], "recipient-reconnect");
    send_response.release_one();

    let recovered = tokio::time::timeout(Duration::from_secs(5), sender.recv())
        .await
        .expect("ambiguous unary send did not recover");
    assert_eq!(recovered["id"], "ambiguous-send-completed");
    assert_eq!(recovered["result"]["task_id"], task_id);
    assert_eq!(recovered["result"]["conversation_id"], context_id);
    assert_eq!(recovered["result"]["state"], "completed");
    assert_eq!(recovered["result"]["text"], "retained terminal reply");
    assert_eq!(runtime.task_count().await, 1);
    assert_eq!(second.registration_count().await, 2);
    assert_eq!(second.delivery_count(), 1);
    assert_eq!(second.task_get_count(), 1);
    assert_eq!(second.send_message_count(), 0);
    assert_eq!(second.streaming_send_count(), 0);
    assert_eq!(second.task_subscription_count(), 0);
    assert_eq!(second.task_list_count(), 0);
    assert_no_second_task7_delivery(&mut recipient, &second).await;
}

#[derive(Clone, Copy)]
enum AmbiguousTerminal {
    Completed,
    Canceled,
    Failed,
    Rejected,
}

async fn assert_ambiguous_send_replays_terminal(terminal: AmbiguousTerminal, streaming: bool) {
    let runtime = TestBrokerRuntime::new();
    let first = runtime.start_broker().await;
    first.add_agent("implementer", "w1:p1").await;
    first.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&first, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&first, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;
    recipient
        .send(json!({"id":"delivery","method":"wait_for_message","params":{"timeout_ms":5_000}}))
        .await;
    let method = if streaming {
        "SendStreamingMessage"
    } else {
        "SendMessage"
    };
    let send_response = first.stall_jsonrpc_response_once(method).await;
    first.truncate_jsonrpc_response_once(method).await;
    sender
        .send(json!({
            "id":"ambiguous-send-terminal",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"terminal once","wait":streaming,"timeout_ms":5_000}
        }))
        .await;
    await_task7_gate(&send_response, "ambiguous terminal send").await;
    let delivery = recipient.recv().await;
    let task_id = delivery["result"]["task_id"].as_str().unwrap();
    let context_id = delivery["result"]["context_id"].as_str().unwrap();
    let (expected_state, expected_text) = match terminal {
        AmbiguousTerminal::Completed => {
            recipient
                .send(json!({
                    "id":"reply",
                    "method":"reply",
                    "params":{"task_id":task_id,"text":"retained completion"}
                }))
                .await;
            assert_eq!(recipient.recv().await["id"], "reply");
            ("completed", Some("retained completion"))
        }
        AmbiguousTerminal::Canceled => {
            sender
                .send(json!({
                    "id":"cancel",
                    "method":"cancel_task",
                    "params":{"task_id":task_id}
                }))
                .await;
            assert_eq!(sender.recv().await["id"], "cancel");
            ("canceled", None)
        }
        AmbiguousTerminal::Failed => {
            let reviewer = first.registration_for_agent("reviewer").await;
            first
                .fail_task(&reviewer, task_id, "retained failure")
                .await;
            ("failed", Some("retained failure"))
        }
        AmbiguousTerminal::Rejected => {
            let reviewer = first.registration_for_agent("reviewer").await;
            first
                .reject_task(&reviewer, task_id, "retained rejection")
                .await;
            ("rejected", Some("retained rejection"))
        }
    };

    let recipient_reconnect = first.stall_endpoint("/v1/agents").await;
    first.truncate_endpoint_response_once("/v1/agents").await;
    recipient
        .send(json!({"id":"recipient-reconnect","method":"list_agents","params":{}}))
        .await;
    await_task7_gate(&recipient_reconnect, "recipient reconnect").await;
    assert_eq!(first.delivery_count(), 1);
    assert_eq!(first.send_message_count(), usize::from(!streaming));
    assert_eq!(first.streaming_send_count(), usize::from(streaming));
    assert_eq!(first.task_get_count(), 0);
    assert_eq!(first.task_subscription_count(), 0);
    assert_eq!(first.task_list_count(), 0);
    let second = runtime.start_broker().await;
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
    let mut replacement_command = Command::new(&executable);
    second.configure_client(replacement_command.as_std_mut(), &executable);
    drop(first);
    recipient_reconnect.release_one();
    assert_eq!(recipient.recv().await["id"], "recipient-reconnect");
    send_response.release_one();

    let recovered = tokio::time::timeout(Duration::from_secs(5), sender.recv())
        .await
        .expect("ambiguous terminal send did not recover");
    assert_eq!(recovered["result"]["task_id"], task_id);
    assert_eq!(recovered["result"]["conversation_id"], context_id);
    assert_eq!(recovered["result"]["state"], expected_state);
    if let Some(expected_text) = expected_text {
        assert_eq!(recovered["result"]["text"], expected_text);
    }
    assert_eq!(runtime.task_count().await, 1);
    assert_eq!(second.registration_count().await, 2);
    assert_eq!(second.delivery_count(), 1);
    assert_eq!(second.task_get_count(), 1);
    assert_eq!(second.send_message_count(), 0);
    assert_eq!(second.streaming_send_count(), 0);
    assert_eq!(second.task_subscription_count(), 0);
    assert_eq!(second.task_list_count(), 0);
    assert_no_second_task7_delivery(&mut recipient, &second).await;
}

#[tokio::test]
async fn ambiguous_send_canceled_replays_exact_terminal_after_restart() {
    assert_ambiguous_send_replays_terminal(AmbiguousTerminal::Canceled, false).await;
}

#[tokio::test]
async fn ambiguous_send_failed_replays_exact_terminal_after_restart() {
    assert_ambiguous_send_replays_terminal(AmbiguousTerminal::Failed, false).await;
}

#[tokio::test]
async fn ambiguous_send_rejected_replays_exact_terminal_after_restart() {
    assert_ambiguous_send_replays_terminal(AmbiguousTerminal::Rejected, false).await;
}

#[tokio::test]
async fn ambiguous_send_streaming_completed_replays_exact_terminal_after_restart() {
    assert_ambiguous_send_replays_terminal(AmbiguousTerminal::Completed, true).await;
}

#[tokio::test]
async fn ambiguous_send_streaming_canceled_replays_exact_terminal_after_restart() {
    assert_ambiguous_send_replays_terminal(AmbiguousTerminal::Canceled, true).await;
}

#[tokio::test]
async fn ambiguous_send_streaming_failed_replays_exact_terminal_after_restart() {
    assert_ambiguous_send_replays_terminal(AmbiguousTerminal::Failed, true).await;
}

#[tokio::test]
async fn ambiguous_send_streaming_rejected_replays_exact_terminal_after_restart() {
    assert_ambiguous_send_replays_terminal(AmbiguousTerminal::Rejected, true).await;
}

#[tokio::test]
async fn lost_initial_stream_recovers_transparently_with_one_get_and_subscription() {
    // Break caught: a dropped SSE connection is returned as stream_lost instead of resubscribing.
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    broker
        .truncate_jsonrpc_stream_once("SendStreamingMessage")
        .await;
    let mut sender = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&broker, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;
    recipient
        .send(json!({
            "id":"delivery",
            "method":"wait_for_message",
            "params":{"timeout_ms":5_000}
        }))
        .await;
    sender
        .send(json!({
            "id":"send",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"survive stream loss","timeout_ms":5_000}
        }))
        .await;
    let delivery = recipient.recv().await;
    let task_id = delivery["result"]["task_id"].as_str().unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while broker.task_subscription_count() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("sender did not recover through SubscribeToTask");
    recipient
        .send(json!({
            "id":"reply",
            "method":"reply",
            "params":{"task_id":task_id,"text":"stream recovered"}
        }))
        .await;
    assert_eq!(recipient.recv().await["id"], "reply");

    let response = sender.recv().await;
    assert_eq!(response["id"], "send");
    assert_eq!(response["result"]["state"], "completed");
    assert_eq!(response["result"]["text"], "stream recovered");
    assert_eq!(broker.task_get_count(), 1);
    assert_eq!(broker.task_subscription_count(), 1);
    assert_eq!(broker.task_list_count(), 0);
}

#[tokio::test]
async fn preconfirmation_timeout_is_bounded_unknown_and_releases_outbound_permits() {
    // Break caught: initial SendStreamingMessage was outside the deadline and retained every
    // outbound permit indefinitely.
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    let initial_send = broker.stall_jsonrpc_method("SendStreamingMessage").await;
    let mut sender = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&broker, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;
    for index in 0..32 {
        sender
            .send(json!({
                "id":format!("blocked-{index}"),
                "method":"send_message",
                "params":{
                    "agent":"reviewer",
                    "text":format!("establish {index}"),
                    "timeout_ms":1_000
                }
            }))
            .await;
    }
    tokio::time::timeout(Duration::from_secs(2), initial_send.wait_until_entered())
        .await
        .expect("initial streaming send did not reach the broker");

    let responses = tokio::time::timeout(Duration::from_secs(3), async {
        let mut responses = Vec::new();
        for _ in 0..32 {
            responses.push(sender.recv().await);
        }
        responses
    })
    .await
    .expect("pre-confirmation sends exceeded their one-second deadlines");
    for response in responses {
        assert_eq!(response["result"]["state"], "unknown", "{response}");
        assert_eq!(response["result"]["timed_out"], true, "{response}");
        assert_eq!(response["result"]["task_reachable"], false, "{response}");
        assert!(response["result"]["conversation_id"].as_str().is_some());
        assert_eq!(
            response["result"]["resume_task_id"],
            response["result"]["task_id"]
        );
    }

    recipient
        .send(json!({
            "id":"delivery",
            "method":"wait_for_message",
            "params":{"timeout_ms":5_000}
        }))
        .await;
    sender
        .send(json!({
            "id":"after-timeouts",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"permit released","wait":false}
        }))
        .await;
    let started = tokio::time::timeout(Duration::from_secs(2), sender.recv())
        .await
        .expect("an outbound permit leaked after the bounded sends");
    assert_eq!(started["id"], "after-timeouts");
    let delivery = recipient.recv().await;
    let task_id = started["result"]["task_id"].as_str().unwrap();
    assert_eq!(delivery["result"]["task_id"], task_id);
    recipient
        .send(json!({
            "id":"reply",
            "method":"reply",
            "params":{"task_id":task_id,"text":"reachable"}
        }))
        .await;
    assert_eq!(recipient.recv().await["id"], "reply");
}

#[tokio::test]
async fn completion_between_resume_get_and_subscribe_is_recovered_by_one_final_get() {
    // Break caught: SubscribeToTask races task completion and loses an already-stored reply.
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    let subscribe = broker.stall_jsonrpc_method("SubscribeToTask").await;
    broker
        .truncate_jsonrpc_response_once("SubscribeToTask")
        .await;
    let mut sender = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&broker, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;
    recipient
        .send(json!({
            "id":"delivery",
            "method":"wait_for_message",
            "params":{"timeout_ms":5_000}
        }))
        .await;
    sender
        .send(json!({
            "id":"start",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"race completion","wait":false}
        }))
        .await;
    let started = sender.recv().await;
    let reviewer = started["result"]["agent"].as_str().unwrap().to_owned();
    let delivery = recipient.recv().await;
    let task_id = started["result"]["task_id"].as_str().unwrap();
    assert_eq!(delivery["result"]["task_id"], task_id);
    sender
        .send(json!({
            "id":"resume",
            "method":"send_message",
            "params":{"agent":reviewer,"resume_task_id":task_id,"timeout_ms":5_000}
        }))
        .await;
    tokio::time::timeout(Duration::from_secs(2), subscribe.wait_until_entered())
        .await
        .expect("resume did not reach SubscribeToTask after GetTask");
    recipient
        .send(json!({
            "id":"reply",
            "method":"reply",
            "params":{"task_id":task_id,"text":"won the race"}
        }))
        .await;
    assert_eq!(recipient.recv().await["id"], "reply");
    subscribe.release_one();

    let resumed = sender.recv().await;
    assert_eq!(resumed["result"]["state"], "completed");
    assert_eq!(resumed["result"]["text"], "won the race");
    assert_eq!(broker.task_get_count(), 2);
    assert_eq!(broker.task_subscription_count(), 1);
    assert_eq!(broker.task_list_count(), 0);
}

#[tokio::test]
async fn resume_bounds_its_owner_get_without_claiming_the_task_was_reached() {
    // Break caught: timeout_ms begins only after GetTask, so a stalled owner lookup hangs forever.
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&broker, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;
    recipient
        .send(json!({
            "id":"delivery",
            "method":"wait_for_message",
            "params":{"timeout_ms":5_000}
        }))
        .await;
    sender
        .send(json!({
            "id":"start",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"stall the lookup","wait":false}
        }))
        .await;
    let started = sender.recv().await;
    let reviewer = started["result"]["agent"].as_str().unwrap().to_owned();
    let task_id = started["result"]["task_id"].as_str().unwrap();
    assert_eq!(recipient.recv().await["result"]["task_id"], task_id);
    let get = broker.stall_jsonrpc_method("GetTask").await;
    sender
        .send(json!({
            "id":"resume",
            "method":"send_message",
            "params":{"agent":reviewer,"resume_task_id":task_id,"timeout_ms":1_000}
        }))
        .await;
    tokio::time::timeout(Duration::from_secs(1), get.wait_until_entered())
        .await
        .expect("resume did not reach its owner GetTask");
    let bounded = tokio::time::timeout(Duration::from_millis(1_500), sender.recv()).await;
    get.release_one();
    let response = bounded.expect("resume GetTask ignored its timeout bound");

    assert_eq!(response["result"]["agent"], reviewer);
    assert_eq!(response["result"]["task_id"], task_id);
    assert_eq!(response["result"]["resume_task_id"], task_id);
    assert_eq!(response["result"]["conversation_id"], Value::Null);
    assert_eq!(response["result"]["state"], "unknown");
    assert_eq!(response["result"]["timed_out"], true);
    assert_eq!(response["result"]["task_reachable"], false);
    assert_eq!(broker.task_get_count(), 1);
    assert_eq!(broker.task_subscription_count(), 0);
    assert_eq!(broker.task_list_count(), 0);
}

#[tokio::test]
async fn foreign_session_cannot_resume_another_senders_task() {
    // Break caught: resume uses an unauthenticated or recipient-owned task lookup.
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    let mut owner = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    let mut foreign = ClientSessionProcess::spawn(&broker, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut owner, &mut foreign).await;
    owner
        .send(json!({
            "id":"start",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"owner only","wait":false}
        }))
        .await;
    let started = owner.recv().await;
    let reviewer = started["result"]["agent"].as_str().unwrap().to_owned();
    let task_id = started["result"]["task_id"].as_str().unwrap();
    foreign
        .send(json!({
            "id":"steal",
            "method":"send_message",
            "params":{"agent":reviewer,"resume_task_id":task_id,"timeout_ms":1_000}
        }))
        .await;

    let rejected = foreign.recv().await;
    assert_eq!(rejected["id"], "steal");
    assert_eq!(rejected["error"]["code"], "request_failed");
    assert!(
        rejected["error"]["message"]
            .as_str()
            .is_some_and(|message| {
                message.contains("forbidden")
                    || message.contains("owner")
                    || message.contains("owned")
            }),
        "unexpected rejection: {rejected}"
    );
    assert_eq!(broker.task_get_count(), 1);
    assert_eq!(broker.task_subscription_count(), 0);
    assert_eq!(broker.task_list_count(), 0);
}

#[tokio::test]
async fn owner_cannot_resume_through_a_different_registered_agent() {
    // Break caught: ownership alone allowed a caller to select another agent's tenant and caused
    // Pi to label the original peer's content as though it came from that selected agent.
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    let mut owner = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    let mut reviewer = ClientSessionProcess::spawn(&broker, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut owner, &mut reviewer).await;
    reviewer
        .send(json!({
            "id":"delivery",
            "method":"wait_for_message",
            "params":{"timeout_ms":5_000}
        }))
        .await;
    owner
        .send(json!({
            "id":"start",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"recipient bound","wait":false}
        }))
        .await;
    let started = owner.recv().await;
    let reviewer_agent = started["result"]["agent"].as_str().unwrap().to_owned();
    let implementer_agent = canonical_agent(&broker, "implementer").await;
    let delivery = reviewer.recv().await;
    let task_id = started["result"]["task_id"].as_str().unwrap();
    assert_eq!(delivery["result"]["task_id"], task_id);

    owner
        .send(json!({
            "id":"wrong-agent",
            "method":"send_message",
            "params":{
                "agent":implementer_agent,
                "resume_task_id":task_id,
                "timeout_ms":1_000
            }
        }))
        .await;
    let rejected = owner.recv().await;
    assert_eq!(rejected["id"], "wrong-agent");
    assert_eq!(rejected["error"]["code"], "request_failed", "{rejected}");
    assert!(
        rejected["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("recipient")),
        "unexpected rejection: {rejected}"
    );

    reviewer
        .send(json!({
            "id":"reply",
            "method":"reply",
            "params":{"task_id":task_id,"text":"from the real peer"}
        }))
        .await;
    assert_eq!(reviewer.recv().await["id"], "reply");
    owner
        .send(json!({
            "id":"correct-agent",
            "method":"send_message",
            "params":{"agent":reviewer_agent,"resume_task_id":task_id,"timeout_ms":2_000}
        }))
        .await;
    let resumed = owner.recv().await;
    assert_eq!(resumed["id"], "correct-agent");
    assert_eq!(resumed["result"]["state"], "completed");
    assert_eq!(resumed["result"]["text"], "from the real peer");
}

#[tokio::test]
async fn send_rejects_out_of_range_timeouts_and_mixed_modes_before_a2a_io() {
    // Break caught: zero/oversized waits or ambiguous text+resume requests reach the peer.
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    let mut child = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    for (id, params) in [
        (
            "zero",
            json!({"agent":"reviewer","text":"x","timeout_ms":0}),
        ),
        (
            "over-max",
            json!({"agent":"reviewer","text":"x","timeout_ms":86_400_001_u64}),
        ),
        (
            "mixed",
            json!({
                "agent":"reviewer",
                "text":"x",
                "resume_task_id":"task-already-started"
            }),
        ),
        (
            "invalid-resume-id",
            json!({"agent":"reviewer","resume_task_id":"../task"}),
        ),
    ] {
        child
            .send(json!({"id":id,"method":"send_message","params":params}))
            .await;
        let response = child.recv().await;
        assert_eq!(response["id"], id);
        assert_eq!(response["error"]["code"], "request_failed", "{response}");
    }
    assert_eq!(broker.task_get_count(), 0);
    assert_eq!(broker.task_subscription_count(), 0);
    assert_eq!(broker.task_list_count(), 0);
}

#[tokio::test]
async fn simultaneous_blocking_sends_return_at_the_shared_explicit_bound() {
    // Break caught: two peers both block forever in send and neither can return to its inbox.
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    let mut implementer = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    let mut reviewer = ClientSessionProcess::spawn(&broker, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut implementer, &mut reviewer).await;
    implementer
        .send(json!({
            "id":"to-reviewer",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"mutual one","timeout_ms":1_000}
        }))
        .await;
    reviewer
        .send(json!({
            "id":"to-implementer",
            "method":"send_message",
            "params":{"agent":"implementer","text":"mutual two","timeout_ms":1_000}
        }))
        .await;

    let (one, two) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(implementer.recv(), reviewer.recv())
    })
    .await
    .expect("blocking sends exceeded their shared explicit deadline");
    assert_eq!(one["result"]["timed_out"], true, "{one}");
    assert_eq!(two["result"]["timed_out"], true, "{two}");
    assert_eq!(one["result"]["resume_task_id"], one["result"]["task_id"]);
    assert_eq!(two["result"]["resume_task_id"], two["result"]["task_id"]);
    assert_eq!(broker.task_get_count(), 0);
    assert_eq!(broker.task_subscription_count(), 0);
    assert_eq!(broker.task_list_count(), 0);
}

#[tokio::test]
async fn client_session_unregisters_on_stdin_eof() {
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    let mut child = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    child
        .send(json!({"id":"ready","method":"list_agents","params":{}}))
        .await;
    assert_eq!(child.recv().await["id"], "ready");
    assert_eq!(broker.active_registration_count().await, 1);

    child.close_stdin_and_wait().await;

    assert_eq!(broker.active_registration_count().await, 0);
}

#[tokio::test]
async fn stdin_eof_cancels_blocked_recovery_before_request_drain() {
    // Break caught: EOF starts the bounded request drain while a blocked recovery remains able to
    // discover and register with a replacement broker.
    let runtime = TestBrokerRuntime::new();
    let first = runtime.start_broker().await;
    first.add_agent("implementer", "w1:p1").await;
    let mut child = ClientSessionProcess::spawn(&first, "w1:p1", "pi-session-1").await;
    child
        .send(json!({"id":"ready","method":"list_agents","params":{}}))
        .await;
    assert_eq!(child.recv().await["id"], "ready");
    drop(first);

    let second = runtime.start_broker().await;
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
    let mut replacement_command = Command::new(&executable);
    second.configure_client(replacement_command.as_std_mut(), &executable);
    let health = second.stall_endpoint("/health").await;
    child
        .send(json!({"id":"recovering","method":"list_agents","params":{}}))
        .await;
    health.wait_until_entered().await;

    child.close_stdin();
    tokio::time::sleep(Duration::from_millis(50)).await;
    health.release_one();

    child.wait_for_successful_exit("EOF during recovery").await;
    assert_eq!(second.registration_count().await, 0);
    second.stop().await;
}

#[tokio::test]
async fn client_session_unregisters_on_sigterm() {
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    let mut child = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    child
        .send(json!({"id":"ready","method":"list_agents","params":{}}))
        .await;
    assert_eq!(child.recv().await["id"], "ready");
    assert_eq!(broker.active_registration_count().await, 1);

    child.terminate_and_wait().await;

    assert_eq!(broker.active_registration_count().await, 0);
}

#[tokio::test]
async fn stalled_registration_is_interrupted_by_sigterm() {
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    let stall = broker.stall_endpoint("/v1/register").await;
    let mut child = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    tokio::time::timeout(Duration::from_secs(2), stall.wait_until_entered())
        .await
        .expect("registration request did not reach broker");

    child.terminate_and_wait().await;

    assert_eq!(broker.active_registration_count().await, 0);
}

#[tokio::test]
async fn stalled_unregister_is_bounded_after_stdin_eof() {
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    let mut child = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    child
        .send(json!({"id":"ready","method":"list_agents","params":{}}))
        .await;
    assert_eq!(child.recv().await["id"], "ready");
    let stall = broker.stall_endpoint("/v1/unregister").await;

    child.close_stdin();
    tokio::time::timeout(Duration::from_secs(2), stall.wait_until_entered())
        .await
        .expect("unregister request did not reach broker");
    child.wait_for_successful_exit("stalled unregister").await;
}

#[tokio::test]
async fn expired_registration_reproves_and_registers_against_the_same_live_broker() {
    // Break caught: registration-auth loss is routed through replacement-only recovery, which
    // rejects the unchanged protected descriptor until this healthy broker is restarted.
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    let original_instance = broker.broker_instance_id().to_owned();
    let mut recipient = ClientSessionProcess::spawn(&broker, "w1:p2", "recipient-session").await;
    recipient
        .send(json!({"id":"ready","method":"list_agents","params":{}}))
        .await;
    assert_eq!(recipient.recv().await["id"], "ready");
    assert_eq!(broker.registration_count().await, 1);

    broker.advance_broker_time_without_renewal(Duration::from_secs(31));
    recipient
        .send(json!({
            "id":"wait-after-expiry",
            "method":"wait_for_message",
            "params":{"timeout_ms":5_000}
        }))
        .await;
    let reregistered = tokio::time::timeout(Duration::from_secs(2), async {
        while broker.registration_count().await < 2 || broker.active_registration_count().await != 1
        {
            tokio::task::yield_now().await;
        }
    })
    .await;
    if reregistered.is_err() {
        recipient.terminate_and_wait().await;
        panic!("expired client did not re-register against the live broker");
    }

    assert_eq!(broker.broker_instance_id(), original_instance);
    assert_eq!(broker.active_registration_count().await, 1);
    let mut sender = ClientSessionProcess::spawn(&broker, "w1:p1", "sender-session").await;
    sender
        .send(json!({"id":"sender-ready","method":"list_agents","params":{}}))
        .await;
    assert_eq!(sender.recv().await["id"], "sender-ready");
    sender
        .send(json!({
            "id":"send-after-reregistration",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"same broker","wait":false}
        }))
        .await;
    assert_eq!(sender.recv().await["id"], "send-after-reregistration");
    let delivery = recipient.recv().await;
    assert_eq!(delivery["id"], "wait-after-expiry");
    assert_eq!(delivery["result"]["payload"]["text"], "same broker");
    assert_eq!(broker.broker_instance_id(), original_instance);

    sender.close_stdin_and_wait().await;
    recipient.close_stdin_and_wait().await;
    assert_eq!(broker.active_registration_count().await, 0);
}

#[tokio::test]
async fn expired_registration_during_a2a_send_refreshes_the_same_live_broker() {
    // Break caught: A2A registration failures remain ordinary application errors instead of
    // carrying the registration-refresh recovery mode used by private endpoints.
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    let original_instance = broker.broker_instance_id().to_owned();
    let mut sender = ClientSessionProcess::spawn(&broker, "w1:p1", "sender-session").await;
    sender
        .send(json!({"id":"sender-ready","method":"list_agents","params":{}}))
        .await;
    assert_eq!(sender.recv().await["id"], "sender-ready");

    broker.advance_broker_time_without_renewal(Duration::from_secs(31));
    let mut recipient = ClientSessionProcess::spawn(&broker, "w1:p2", "recipient-session").await;
    recipient
        .send(json!({"id":"recipient-ready","method":"list_agents","params":{}}))
        .await;
    assert_eq!(recipient.recv().await["id"], "recipient-ready");
    sender
        .send(json!({
            "id":"send-after-expiry",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"refresh before send","wait":false}
        }))
        .await;
    let response = sender.recv().await;
    assert_eq!(response["id"], "send-after-expiry");
    assert!(response.get("error").is_none(), "{response}");
    recipient
        .send(json!({
            "id":"wait-for-refreshed-send",
            "method":"wait_for_message",
            "params":{"timeout_ms":5_000}
        }))
        .await;
    let delivery = recipient.recv().await;
    assert_eq!(delivery["id"], "wait-for-refreshed-send");
    assert_eq!(delivery["result"]["payload"]["text"], "refresh before send");
    assert_eq!(broker.broker_instance_id(), original_instance);
    assert_eq!(broker.registration_count().await, 3);

    sender.close_stdin_and_wait().await;
    recipient.close_stdin_and_wait().await;
    assert_eq!(broker.active_registration_count().await, 0);
}

#[tokio::test]
async fn stalled_renewal_does_not_block_requests_or_sigterm() {
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    let stall = broker.stall_endpoint("/v1/renew").await;
    let mut child = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    child
        .send(json!({"id":"ready","method":"list_agents","params":{}}))
        .await;
    assert_eq!(child.recv().await["id"], "ready");
    tokio::time::timeout(Duration::from_secs(13), stall.wait_until_entered())
        .await
        .expect("renewal did not run within its 10-12 second cadence");

    child
        .send(json!({"id":"during-renew","method":"list_agents","params":{}}))
        .await;
    let response = tokio::time::timeout(Duration::from_secs(2), child.recv())
        .await
        .expect("stalled renewal blocked the request loop");
    assert_eq!(response["id"], "during-renew");
    child.terminate_and_wait().await;
}

#[tokio::test]
async fn renewal_failure_keeps_the_session_running_until_normal_shutdown() {
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.fail_endpoint("/v1/renew").await;
    let mut child = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    child
        .send(json!({"id":"ready","method":"list_agents","params":{}}))
        .await;
    assert_eq!(child.recv().await["id"], "ready");

    tokio::time::timeout(Duration::from_secs(13), async {
        while broker.renewal_count() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("renewal did not run within its 10-12 second cadence");
    child
        .send(json!({"id":"after-renewal-failure","method":"list_agents","params":{}}))
        .await;
    let response = tokio::time::timeout(Duration::from_secs(2), child.recv())
        .await
        .expect("renewal failure ended the live session");
    assert_eq!(response["id"], "after-renewal-failure");
    child.close_stdin_and_wait().await;
    assert_eq!(broker.active_registration_count().await, 0);
    assert_eq!(broker.unregistration_count(), 1);
}

#[tokio::test]
async fn renewal_failure_preserves_an_acknowledged_record_and_live_session() {
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&broker, "w1:p2", "pi-session-2").await;
    sender
        .send(json!({"id":"sender-ready","method":"list_agents","params":{}}))
        .await;
    recipient
        .send(json!({"id":"recipient-ready","method":"list_agents","params":{}}))
        .await;
    assert_eq!(sender.recv().await["id"], "sender-ready");
    assert_eq!(recipient.recv().await["id"], "recipient-ready");

    recipient
        .send(json!({"id":"delivery","method":"wait_for_message","params":{"timeout_ms":5_000}}))
        .await;
    sender
        .send(json!({
            "id":"send",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"x".repeat(64 * 1024),"wait":false}
        }))
        .await;
    assert_eq!(sender.recv().await["id"], "send");
    tokio::time::timeout(Duration::from_secs(2), async {
        while broker.acknowledgement_count() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("broker did not commit the delivery acknowledgement");
    sender.close_stdin_and_wait().await;
    let unregistrations_before_recipient_exit = broker.unregistration_count();
    assert_eq!(unregistrations_before_recipient_exit, 1);

    let renewal = broker.stall_endpoint("/v1/renew").await;
    tokio::time::timeout(Duration::from_secs(13), renewal.wait_until_entered())
        .await
        .expect("renewal did not run within its 10-12 second cadence");
    broker.fail_endpoint("/v1/renew").await;
    renewal.release_one();

    let early_unregistration = tokio::time::timeout(Duration::from_secs(1), async {
        while broker.unregistration_count() == unregistrations_before_recipient_exit {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        early_unregistration.is_err(),
        "recipient unregistered before its acknowledged stdout record was drained"
    );

    let response = recipient.recv().await;
    assert_eq!(response["id"], "delivery");
    assert_eq!(response["result"]["payload"]["text"], "x".repeat(64 * 1024));
    recipient
        .send(json!({"id":"still-live","method":"list_agents","params":{}}))
        .await;
    assert_eq!(recipient.recv().await["id"], "still-live");
    recipient.close_stdin_and_wait().await;
    assert_eq!(broker.active_registration_count().await, 0);
    assert_eq!(
        broker.unregistration_count(),
        unregistrations_before_recipient_exit + 1
    );
}

#[tokio::test]
async fn broken_stdout_shuts_down_and_unregisters_the_session() {
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    let mut child = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    child
        .send(json!({"id":"ready","method":"list_agents","params":{}}))
        .await;
    assert_eq!(child.recv().await["id"], "ready");
    child.break_stdout();

    child
        .send(json!({"id":"break","method":"list_agents","params":{}}))
        .await;
    let status = child.wait_for_exit("broken stdout").await;

    assert!(!status.success());
    assert_eq!(broker.active_registration_count().await, 0);
}

#[tokio::test]
async fn broken_stdout_cancels_blocked_recovery_before_request_drain() {
    // Break caught: a writer failure enters producer drain without cancelling a request that is
    // waiting to discover and register with a replacement broker.
    let runtime = TestBrokerRuntime::new();
    let first = runtime.start_broker().await;
    first.add_agent("implementer", "w1:p1").await;
    let mut child = ClientSessionProcess::spawn(&first, "w1:p1", "pi-session-1").await;
    child
        .send(json!({"id":"ready","method":"list_agents","params":{}}))
        .await;
    assert_eq!(child.recv().await["id"], "ready");
    drop(first);

    let second = runtime.start_broker().await;
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
    let mut replacement_command = Command::new(&executable);
    second.configure_client(replacement_command.as_std_mut(), &executable);
    let health = second.stall_endpoint("/health").await;
    child
        .send(json!({"id":"recovering","method":"list_agents","params":{}}))
        .await;
    health.wait_until_entered().await;

    child.break_stdout();
    child.send_raw(b"{invalid-json}\n").await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    health.release_one();

    let status = child.wait_for_exit("broken stdout during recovery").await;
    assert!(!status.success());
    assert_eq!(second.registration_count().await, 0);
    second.stop().await;
}

async fn ack_write_survives_shutdown(signal: bool) {
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&broker, "w1:p2", "pi-session-2").await;
    recipient
        .send(json!({"id":"ready","method":"list_agents","params":{}}))
        .await;
    assert_eq!(recipient.recv().await["id"], "ready");
    let ack = broker.stall_endpoint("/v1/inbox/ack").await;
    recipient
        .send(json!({"id":"delivery","method":"wait_for_message","params":{"timeout_ms":5_000}}))
        .await;
    sender
        .send(json!({
            "id":"send",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"atomic output","wait":false}
        }))
        .await;
    assert_eq!(sender.recv().await["id"], "send");
    tokio::time::timeout(Duration::from_secs(2), ack.wait_until_entered())
        .await
        .expect("delivery acknowledgement did not start");

    if signal {
        recipient.send_sigterm().await;
    } else {
        recipient.close_stdin();
    }
    ack.release_one();

    let response = recipient.recv().await;
    assert_eq!(response["id"], "delivery");
    assert_eq!(response["result"]["payload"]["text"], "atomic output");
    recipient
        .wait_for_successful_exit(if signal {
            "SIGTERM during ACK"
        } else {
            "EOF during ACK"
        })
        .await;
}

#[tokio::test]
async fn signal_during_ack_emits_one_complete_line_before_shutdown() {
    ack_write_survives_shutdown(true).await;
}

#[tokio::test]
async fn eof_during_ack_emits_one_complete_line_before_shutdown() {
    ack_write_survives_shutdown(false).await;
}

#[tokio::test]
async fn open_undrained_stdout_is_process_bounded_on_shutdown() {
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&broker, "w1:p2", "pi-session-2").await;
    sender
        .send(json!({"id":"sender-ready","method":"list_agents","params":{}}))
        .await;
    recipient
        .send(json!({"id":"recipient-ready","method":"list_agents","params":{}}))
        .await;
    assert_eq!(sender.recv().await["id"], "sender-ready");
    assert_eq!(recipient.recv().await["id"], "recipient-ready");
    let ack = broker.stall_endpoint("/v1/inbox/ack").await;
    recipient
        .send(json!({"id":"large","method":"wait_for_message","params":{"timeout_ms":5_000}}))
        .await;
    sender
        .send(json!({
            "id":"send-large",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"x".repeat(64 * 1024),"wait":false}
        }))
        .await;
    assert_eq!(sender.recv().await["id"], "send-large");
    tokio::time::timeout(Duration::from_secs(2), ack.wait_until_entered())
        .await
        .expect("large delivery acknowledgement did not start");

    recipient.send_sigterm().await;
    ack.release_one();
    let status = recipient.wait_for_exit("open undrained stdout").await;

    assert!(!status.success());
}

#[tokio::test]
async fn flooded_protocol_error_output_still_observes_sigterm_and_exits_bounded() {
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    let mut child = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    child
        .send(json!({"id":"ready","method":"list_agents","params":{}}))
        .await;
    assert_eq!(child.recv().await["id"], "ready");

    let mut stdin = child.take_stdin();
    let (started, writing) = tokio::sync::oneshot::channel();
    let flood = b"{}\n".repeat(64 * 1024);
    let mut flood_task = tokio::spawn(async move {
        let _ = started.send(());
        stdin.write_all(&flood).await
    });
    writing.await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), &mut flood_task)
            .await
            .is_err(),
        "protocol-error flood did not backpressure the unread stdout pipe"
    );

    child.send_sigterm().await;
    let status = child
        .wait_for_exit("SIGTERM during protocol-error backpressure")
        .await;
    assert!(!status.success());
    let _ = flood_task.await;
    assert_eq!(broker.active_registration_count().await, 0);
}

#[tokio::test]
async fn blocked_inbox_wait_does_not_hold_back_an_unrelated_response() {
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    let mut child = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    child
        .send(json!({
            "id":"blocked",
            "method":"wait_for_message",
            "params":{"timeout_ms":5_000}
        }))
        .await;
    child
        .send(json!({"id":"ready","method":"list_agents","params":{}}))
        .await;

    let response = tokio::time::timeout(Duration::from_secs(2), child.recv())
        .await
        .expect("a completed response was held behind the inbox wait");
    assert_eq!(response["id"], "ready");
}

#[tokio::test]
async fn stalled_delivery_ack_allows_unrelated_output_but_precedes_delivery_bytes() {
    // Break caught: the single stdout writer awaits ACK and head-of-line blocks every response.
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&broker, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;
    let ack = broker.stall_endpoint("/v1/inbox/ack").await;
    recipient
        .send(json!({
            "id":"delivery",
            "method":"wait_for_message",
            "params":{"timeout_ms":5_000}
        }))
        .await;
    sender
        .send(json!({
            "id":"send",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"ack ordering","wait":false}
        }))
        .await;
    assert_eq!(sender.recv().await["id"], "send");
    tokio::time::timeout(Duration::from_secs(2), ack.wait_until_entered())
        .await
        .expect("delivery acknowledgement did not start");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), recipient.recv())
            .await
            .is_err(),
        "delivery response bytes were emitted before ACK committed"
    );

    recipient
        .send(json!({"id":"ready","method":"list_agents","params":{}}))
        .await;
    let unrelated = tokio::time::timeout(Duration::from_secs(2), recipient.recv())
        .await
        .expect("stalled delivery ACK held back unrelated stdout");
    assert_eq!(unrelated["id"], "ready");

    ack.release_one();
    let delivery = recipient.recv().await;
    assert_eq!(delivery["id"], "delivery");
    assert_eq!(delivery["result"]["payload"]["text"], "ack ordering");
    assert_eq!(broker.acknowledgement_count(), 1);
}

#[tokio::test]
async fn failed_ack_returns_a_correlated_error_and_the_expired_lease_redelivers() {
    // Break caught: ACK failure leaks the delivery response or loses the uncommitted message.
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    broker.fail_endpoint("/v1/inbox/ack").await;
    let mut sender = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&broker, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;
    recipient
        .send(json!({
            "id":"first-delivery",
            "method":"wait_for_message",
            "params":{"timeout_ms":5_000}
        }))
        .await;
    sender
        .send(json!({
            "id":"send",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"redeliver me","wait":false}
        }))
        .await;
    let sent = sender.recv().await;
    let task_id = sent["result"]["task_id"].as_str().unwrap().to_owned();
    let failed = recipient.recv().await;
    assert_eq!(failed["id"], "first-delivery");
    assert_eq!(failed["error"]["code"], "acknowledgement_failed");
    assert!(failed.get("result").is_none() || failed["result"].is_null());
    assert_eq!(broker.acknowledgement_count(), 0);

    broker.restore_endpoint("/v1/inbox/ack").await;
    broker.advance_broker_time(Duration::from_secs(60)).await;
    recipient
        .send(json!({
            "id":"redelivery",
            "method":"wait_for_message",
            "params":{"timeout_ms":5_000}
        }))
        .await;
    let redelivered = recipient.recv().await;
    assert_eq!(redelivered["result"]["task_id"], task_id);
    assert_eq!(redelivered["result"]["payload"]["text"], "redeliver me");
    assert_eq!(redelivered["result"]["attempt"], 1);
    assert_eq!(broker.acknowledgement_count(), 1);
}

#[tokio::test]
async fn nonblocking_send_times_out_during_card_resolution_and_releases_permit() {
    // Break caught: wait:false skips the shared deadline around agent-card discovery or leaks
    // its owned outbound permit when discovery times out.
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&broker, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;
    let reviewer = canonical_agent(&broker, "reviewer").await;
    let card_path = agent_card_endpoint(&reviewer);
    let card = broker.stall_endpoint(&card_path).await;

    sender
        .send(json!({
            "id":"card-timeout",
            "method":"send_message",
            "params":{
                "agent":"reviewer",
                "text":"bound discovery",
                "wait":false,
                "timeout_ms":1_500
            }
        }))
        .await;
    tokio::time::timeout(Duration::from_secs(1), card.wait_until_entered())
        .await
        .expect("nonblocking send did not reach agent-card discovery");
    let response = tokio::time::timeout(Duration::from_secs(2), sender.recv())
        .await
        .expect("nonblocking send ignored its discovery timeout");

    assert_eq!(response["result"]["state"], "unknown");
    assert_eq!(response["result"]["timed_out"], true);
    assert_eq!(response["result"]["task_reachable"], false);
    assert!(response["result"]["task_id"].as_str().is_some());
    assert!(response["result"]["conversation_id"].as_str().is_some());

    card.release_one();
    for _ in 0..32 {
        card.release_one();
    }
    let unary = broker.stall_jsonrpc_method("SendMessage").await;
    for index in 0..32 {
        sender
            .send(json!({
                "id":format!("card-permit-{index}"),
                "method":"send_message",
                "params":{
                    "agent":"reviewer",
                    "text":format!("hold permit {index}"),
                    "wait":false,
                    "timeout_ms":5_000
                }
            }))
            .await;
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        for _ in 0..32 {
            unary.wait_until_entered().await;
        }
    })
    .await
    .expect("the 32nd request did not reach the broker; a timed-out permit leaked");
    for _ in 0..32 {
        unary.release_one();
    }
    let mut response_ids = tokio::time::timeout(Duration::from_secs(3), async {
        let mut ids = Vec::new();
        for _ in 0..32 {
            let response = sender.recv().await;
            assert!(response.get("error").is_none(), "{response}");
            ids.push(response["id"].as_str().unwrap().to_owned());
        }
        ids
    })
    .await
    .expect("released nonblocking card-timeout requests did not drain");
    response_ids.sort();
    let mut expected_ids = (0..32)
        .map(|index| format!("card-permit-{index}"))
        .collect::<Vec<_>>();
    expected_ids.sort();
    assert_eq!(response_ids, expected_ids);
}

#[tokio::test]
async fn nonblocking_send_times_out_during_unary_request_and_returns_resume_identity() {
    // Break caught: wait:false bounds discovery but not SendMessage, omits the generated
    // conversation identity on timeout, or leaks its owned outbound permit.
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&broker, "w1:p2", "pi-session-2").await;
    await_client_pair_ready(&mut sender, &mut recipient).await;
    let unary = broker.stall_jsonrpc_response_once("SendMessage").await;

    sender
        .send(json!({
            "id":"unary-timeout",
            "method":"send_message",
            "params":{
                "agent":"reviewer",
                "text":"bound unary send",
                "conversation_id":"01890f47-2f45-7a6c-8e12-123456789abc",
                "wait":false,
                "timeout_ms":1_500
            }
        }))
        .await;
    tokio::time::timeout(Duration::from_secs(1), unary.wait_until_entered())
        .await
        .expect("nonblocking send did not reach SendMessage");
    let response = tokio::time::timeout(Duration::from_secs(2), sender.recv())
        .await
        .expect("nonblocking send ignored its unary timeout");
    let reviewer = response["result"]["agent"].as_str().unwrap().to_owned();

    assert_eq!(response["result"]["state"], "unknown");
    assert_eq!(response["result"]["timed_out"], true);
    assert_eq!(response["result"]["task_reachable"], false);
    assert!(response["result"]["task_id"].as_str().is_some());
    assert!(response["result"]["conversation_id"].as_str().is_some());
    let task_id = response["result"]["task_id"].as_str().unwrap().to_owned();
    let conversation_id = response["result"]["conversation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(response["result"]["resume_task_id"], task_id);
    assert_eq!(
        response["result"]["conversation_id"],
        "01890f47-2f45-7a6c-8e12-123456789abc"
    );

    unary.release_one();
    recipient
        .send(json!({
            "id":"timed-out-delivery",
            "method":"wait_for_message",
            "params":{"timeout_ms":5_000}
        }))
        .await;
    let delivery = recipient.recv().await;
    assert_eq!(delivery["id"], "timed-out-delivery");
    assert_eq!(delivery["result"]["task_id"], task_id, "{delivery}");
    assert_eq!(
        delivery["result"]["context_id"], conversation_id,
        "{delivery}"
    );
    recipient
        .send(json!({
            "id":"timed-out-reply",
            "method":"reply",
            "params":{"task_id":task_id,"text":"completed after ambiguous timeout"}
        }))
        .await;
    assert_eq!(recipient.recv().await["id"], "timed-out-reply");
    sender
        .send(json!({
            "id":"timed-out-resume",
            "method":"send_message",
            "params":{"agent":reviewer,"resume_task_id":task_id,"timeout_ms":5_000}
        }))
        .await;
    let resumed = sender.recv().await;
    assert_eq!(resumed["id"], "timed-out-resume");
    assert_eq!(resumed["result"]["state"], "completed");
    assert_eq!(
        resumed["result"]["text"],
        "completed after ambiguous timeout"
    );
    assert_eq!(resumed["result"]["task_id"], task_id);
    assert_eq!(resumed["result"]["conversation_id"], conversation_id);

    let held = broker.stall_jsonrpc_method("SendMessage").await;
    for index in 0..32 {
        sender
            .send(json!({
                "id":format!("unary-permit-{index}"),
                "method":"send_message",
                "params":{
                    "agent":"reviewer",
                    "text":format!("hold permit {index}"),
                    "wait":false,
                    "timeout_ms":5_000
                }
            }))
            .await;
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        for _ in 0..32 {
            held.wait_until_entered().await;
        }
    })
    .await
    .expect("the 32nd request did not reach the broker; a timed-out permit leaked");
    for _ in 0..32 {
        held.release_one();
    }
    let mut response_ids = tokio::time::timeout(Duration::from_secs(3), async {
        let mut ids = Vec::new();
        for _ in 0..32 {
            let response = sender.recv().await;
            assert!(response.get("error").is_none(), "{response}");
            ids.push(response["id"].as_str().unwrap().to_owned());
        }
        ids
    })
    .await
    .expect("released nonblocking unary-timeout requests did not drain");
    response_ids.sort();
    let mut expected_ids = (0..32)
        .map(|index| format!("unary-permit-{index}"))
        .collect::<Vec<_>>();
    expected_ids.sort();
    assert_eq!(response_ids, expected_ids);
}

#[tokio::test]
async fn nonblocking_send_returns_identifiers_and_can_be_canceled() {
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    let mut child = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&broker, "w1:p2", "pi-session-2").await;
    recipient
        .send(json!({"id":"ready","method":"list_agents","params":{}}))
        .await;
    assert_eq!(recipient.recv().await["id"], "ready");
    child
        .send(json!({
            "id":"send-now",
            "method":"send_message",
            "params":{"agent":"reviewer","text":"review later","wait":false,"timeout_ms":1_000}
        }))
        .await;

    let sent = child.recv().await;
    assert_eq!(sent["id"], "send-now");
    let task_id = sent["result"]["task_id"]
        .as_str()
        .unwrap_or_else(|| panic!("nonblocking send did not return a task: {sent}"));
    assert!(!task_id.is_empty());
    assert!(
        sent["result"]["conversation_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty())
    );
    child
        .send(json!({
            "id":"cancel-now",
            "method":"cancel_task",
            "params":{"task_id":task_id}
        }))
        .await;
    let canceled = child.recv().await;
    assert_eq!(canceled["id"], "cancel-now");
    assert_eq!(canceled["result"]["task_id"], task_id);
    assert_eq!(canceled["result"]["state"], "canceled");
}

#[tokio::test]
async fn task_id_url_injection_cannot_unregister_client_session() {
    // Break caught: string interpolation lets a task ID normalize reply/cancel into /v1/unregister.
    for method in ["reply", "cancel_task"] {
        let broker = TestBroker::start().await;
        broker.add_agent("implementer", "w1:p1").await;
        let mut child = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
        child
            .send(json!({"id":"ready","method":"list_agents","params":{}}))
            .await;
        assert_eq!(child.recv().await["id"], "ready");

        let params = if method == "reply" {
            json!({"task_id":"../unregister#","text":"pwned","metadata":{}})
        } else {
            json!({"task_id":"../unregister#"})
        };
        child
            .send(json!({"id":"malicious","method":method,"params":params}))
            .await;
        let response = child.recv().await;

        assert_eq!(response["id"], "malicious");
        assert_eq!(response["error"]["code"], "request_failed");
        assert!(
            response["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("invalid task ID")),
            "{method}: {response}"
        );
        assert_eq!(broker.active_registration_count().await, 1, "{method}");
        assert_eq!(broker.unregistration_count(), 0, "{method}");
        child.close_stdin_and_wait().await;
    }
}

#[tokio::test]
async fn timed_out_send_returns_reachable_task_identifiers_for_cancellation() {
    let broker = TestBroker::start().await;
    broker.add_agent("implementer", "w1:p1").await;
    broker.add_agent("reviewer", "w1:p2").await;
    let mut sender = ClientSessionProcess::spawn(&broker, "w1:p1", "pi-session-1").await;
    let mut recipient = ClientSessionProcess::spawn(&broker, "w1:p2", "pi-session-2").await;
    recipient
        .send(json!({"id":"ready","method":"list_agents","params":{}}))
        .await;
    assert_eq!(recipient.recv().await["id"], "ready");
    sender
        .send(json!({
            "id":"send-timeout",
            "method":"send_message",
            "params":{
                "agent":"reviewer",
                "text":"review eventually",
                "wait":true,
                "timeout_ms":1_000
            }
        }))
        .await;
    recipient
        .send(json!({
            "id":"delivery",
            "method":"wait_for_message",
            "params":{"timeout_ms":5_000}
        }))
        .await;
    let delivery = recipient.recv().await;
    let timed_out = sender.recv().await;

    assert_eq!(timed_out["id"], "send-timeout");
    assert_eq!(timed_out["result"]["timed_out"], true);
    assert_eq!(
        timed_out["result"]["task_id"],
        delivery["result"]["task_id"]
    );
    assert_eq!(
        timed_out["result"]["conversation_id"],
        delivery["result"]["context_id"]
    );
    let task_id = timed_out["result"]["task_id"].as_str().unwrap();
    sender
        .send(json!({
            "id":"cancel-timeout",
            "method":"cancel_task",
            "params":{"task_id":task_id}
        }))
        .await;
    let canceled = sender.recv().await;
    assert_eq!(canceled["id"], "cancel-timeout");
    assert_eq!(canceled["result"]["task_id"], task_id);
    assert_eq!(canceled["result"]["state"], "canceled");
}

#[tokio::test]
async fn broker_publishes_a_secure_descriptor_and_removes_it_on_sigterm() {
    let runtime = tempfile::tempdir().unwrap();
    let plugin_state = tempfile::tempdir().unwrap();
    let socket_path = runtime.path().join("herdr.sock");
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
    let mut command = Command::new(&executable);
    command
        .arg("broker")
        .env("HERDR_SOCKET_PATH", &socket_path)
        .env("HERDR_WORKSPACE_ID", "test-workspace")
        .env("HERDR_BIN_PATH", Path::new("/usr/bin/false"))
        .env("HERDR_PLUGIN_STATE_DIR", plugin_state.path())
        .env("TMPDIR", runtime.path())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    let child = command.spawn().unwrap();
    let mut broker = BrokerProcess(child);
    let session_key = format!(
        "{:x}",
        Sha256::digest(socket_path.as_os_str().as_encoded_bytes())
    );
    let paths = RuntimePaths::for_test(
        &runtime.path().join("herdr-a2a"),
        &session_key,
        "test-workspace",
    );

    let descriptor = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(descriptor) = read_descriptor(&paths) {
                break descriptor;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("broker did not publish a valid runtime descriptor");
    assert!(descriptor.base_url.starts_with("http://127.0.0.1:"));
    assert_eq!(
        base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &descriptor.bearer_token
        )
        .unwrap()
        .len(),
        32
    );
    assert_eq!(
        descriptor.executable_path,
        executable.canonicalize().unwrap()
    );
    let state_dir = plugin_state
        .path()
        .join("herdr-a2a")
        .join(&paths.scope.scope_key);
    assert!(state_dir.join("tasks.sqlite3").is_file());
    #[cfg(unix)]
    {
        assert_eq!(
            fs::metadata(plugin_state.path().join("herdr-a2a"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&state_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(state_dir.join("tasks.sqlite3"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    let pid = broker.0.id().unwrap();
    let signal_status = Command::new("/bin/kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .await
        .unwrap();
    assert!(signal_status.success());
    let status = tokio::time::timeout(Duration::from_secs(5), broker.0.wait())
        .await
        .expect("broker did not shut down after SIGTERM")
        .unwrap();
    assert!(status.success());
    assert!(!paths.descriptor.exists());
    assert!(!paths.lock.exists());
}

#[cfg(unix)]
#[tokio::test]
async fn workspace_brokers_partition_runtime_and_durable_state_for_one_socket() {
    // Break caught: deriving runtime or database ownership from only the Herdr session lets two
    // workspaces sharing one socket discover, lock, or persist into each other's broker state.
    let runtime = tempfile::tempdir().unwrap();
    let plugin_state = tempfile::tempdir().unwrap();
    let socket_path = runtime.path().join("herdr.sock");
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
    let runtime_root = runtime.path().join("herdr-a2a");
    let session_key = format!(
        "{:x}",
        Sha256::digest(socket_path.as_os_str().as_encoded_bytes())
    );
    fs::create_dir(&runtime_root).unwrap();
    fs::set_permissions(&runtime_root, fs::Permissions::from_mode(0o700)).unwrap();
    let legacy_descriptor = runtime_root.join(format!("{session_key}.json"));
    fs::write(&legacy_descriptor, b"legacy descriptor").unwrap();
    let legacy_database = plugin_state
        .path()
        .join("herdr-a2a")
        .join(&session_key)
        .join("tasks.sqlite3");
    fs::create_dir_all(legacy_database.parent().unwrap()).unwrap();
    fs::write(&legacy_database, b"legacy database").unwrap();
    let left_paths = RuntimePaths::for_test(&runtime_root, &session_key, "workspace-left");
    let right_paths = RuntimePaths::for_test(&runtime_root, &session_key, "workspace-right");

    let spawn = |workspace_id: &str| {
        let mut command = Command::new(&executable);
        command
            .arg("broker")
            .env("HERDR_SOCKET_PATH", &socket_path)
            .env("HERDR_WORKSPACE_ID", workspace_id)
            .env("HERDR_BIN_PATH", Path::new("/usr/bin/false"))
            .env("HERDR_PLUGIN_STATE_DIR", plugin_state.path())
            .env("TMPDIR", runtime.path())
            .env("XDG_RUNTIME_DIR", runtime.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        BrokerProcess(command.spawn().unwrap())
    };
    let mut left = spawn("workspace-left");
    let mut right = spawn("workspace-right");

    let (left_descriptor, right_descriptor) = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let (Ok(left), Ok(right)) =
                (read_descriptor(&left_paths), read_descriptor(&right_paths))
            {
                break (left, right);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("workspace brokers did not publish independent descriptors");

    let left_database = plugin_state
        .path()
        .join("herdr-a2a")
        .join(&left_paths.scope.scope_key)
        .join("tasks.sqlite3");
    let right_database = plugin_state
        .path()
        .join("herdr-a2a")
        .join(&right_paths.scope.scope_key)
        .join("tasks.sqlite3");
    assert_eq!(left_descriptor.workspace_id, "workspace-left");
    assert_eq!(right_descriptor.workspace_id, "workspace-right");
    assert_ne!(left_paths.descriptor, right_paths.descriptor);
    assert_ne!(left_database, right_database);
    assert!(left_database.is_file());
    assert!(right_database.is_file());
    assert_eq!(fs::read(&legacy_descriptor).unwrap(), b"legacy descriptor");
    assert_eq!(fs::read(&legacy_database).unwrap(), b"legacy database");
    assert!(!left_database.starts_with(right_database.parent().unwrap()));
    assert!(!right_database.starts_with(left_database.parent().unwrap()));

    for broker in [&mut left, &mut right] {
        let pid = broker.0.id().unwrap();
        assert!(
            Command::new("/bin/kill")
                .arg("-TERM")
                .arg(pid.to_string())
                .status()
                .await
                .unwrap()
                .success()
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(5), broker.0.wait())
                .await
                .expect("workspace broker did not stop")
                .unwrap()
                .success()
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn broker_rejects_nonexecutable_herdr_before_publishing_descriptor() {
    let runtime = tempfile::tempdir().unwrap();
    let plugin_state = tempfile::tempdir().unwrap();
    let socket_path = runtime.path().join("herdr.sock");
    let herdr = runtime.path().join("not-executable");
    fs::write(&herdr, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&herdr, fs::Permissions::from_mode(0o600)).unwrap();
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
    let mut command = Command::new(&executable);
    command
        .arg("broker")
        .env("HERDR_SOCKET_PATH", &socket_path)
        .env("HERDR_WORKSPACE_ID", "test-workspace")
        .env("HERDR_BIN_PATH", &herdr)
        .env("HERDR_PLUGIN_STATE_DIR", plugin_state.path())
        .env("TMPDIR", runtime.path())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command.spawn().unwrap();
    let status = tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await
        .expect("invalid broker startup did not terminate")
        .unwrap();
    assert!(!status.success());

    let session_key = format!(
        "{:x}",
        Sha256::digest(socket_path.as_os_str().as_encoded_bytes())
    );
    let paths = RuntimePaths::for_test(
        &runtime.path().join("herdr-a2a"),
        &session_key,
        "test-workspace",
    );
    assert!(!paths.descriptor.exists());
    assert!(!paths.lock.exists());
}

#[cfg(unix)]
#[tokio::test]
async fn broker_removes_descriptor_and_bounds_shutdown_with_a_stuck_verifier() {
    let runtime = tempfile::tempdir().unwrap();
    let plugin_state = tempfile::tempdir().unwrap();
    let script_dir = tempfile::tempdir().unwrap();
    let marker = script_dir.path().join("started");
    let herdr = script_dir.path().join("herdr");
    fs::write(
        &herdr,
        format!(
            "#!/bin/sh\nprintf started > '{}'\nexec sleep 600\n",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&herdr, fs::Permissions::from_mode(0o700)).unwrap();
    let socket_path = runtime.path().join("herdr.sock");
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
    let mut command = Command::new(&executable);
    command
        .arg("broker")
        .env("HERDR_SOCKET_PATH", &socket_path)
        .env("HERDR_WORKSPACE_ID", "test-workspace")
        .env("HERDR_BIN_PATH", &herdr)
        .env("HERDR_PLUGIN_STATE_DIR", plugin_state.path())
        .env("TMPDIR", runtime.path())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    let mut broker = BrokerProcess(command.spawn().unwrap());
    let session_key = format!(
        "{:x}",
        Sha256::digest(socket_path.as_os_str().as_encoded_bytes())
    );
    let paths = RuntimePaths::for_test(
        &runtime.path().join("herdr-a2a"),
        &session_key,
        "test-workspace",
    );
    let descriptor = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(descriptor) = read_descriptor(&paths) {
                break descriptor;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("broker did not become ready");
    let request = tokio::spawn({
        let descriptor = descriptor.clone();
        async move {
            reqwest::Client::new()
                .post(format!("{}/v1/register", descriptor.base_url))
                .bearer_auth(descriptor.bearer_token)
                .json(&json!({"pane_id":"w1:p1","harness_session_id":"pi-session"}))
                .send()
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while !marker.exists() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("verifier child did not start");

    let pid = broker.0.id().unwrap();
    assert!(
        Command::new("/bin/kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .status()
            .await
            .unwrap()
            .success()
    );
    tokio::time::timeout(Duration::from_millis(500), async {
        while paths.descriptor.exists() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("descriptor remained published during shutdown");
    let status = tokio::time::timeout(Duration::from_secs(3), broker.0.wait())
        .await
        .expect("broker did not bound graceful shutdown")
        .unwrap();
    assert!(status.success());
    assert!(!paths.lock.exists());
    request.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn broker_shutdown_does_not_block_on_a_contended_transition_lock() {
    let runtime = tempfile::tempdir().unwrap();
    let plugin_state = tempfile::tempdir().unwrap();
    let socket_path = runtime.path().join("herdr.sock");
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a"));
    let mut command = Command::new(&executable);
    command
        .arg("broker")
        .env("HERDR_SOCKET_PATH", &socket_path)
        .env("HERDR_WORKSPACE_ID", "test-workspace")
        .env("HERDR_BIN_PATH", Path::new("/usr/bin/false"))
        .env("HERDR_PLUGIN_STATE_DIR", plugin_state.path())
        .env("TMPDIR", runtime.path())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    let mut broker = BrokerProcess(command.spawn().unwrap());
    let session_key = format!(
        "{:x}",
        Sha256::digest(socket_path.as_os_str().as_encoded_bytes())
    );
    let paths = RuntimePaths::for_test(
        &runtime.path().join("herdr-a2a"),
        &session_key,
        "test-workspace",
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while read_descriptor(&paths).is_err() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("broker did not become ready");
    let transition_guard = fs::OpenOptions::new()
        .read(true)
        .open(
            paths
                .root
                .join(format!(".{}.acquire", paths.scope.scope_key)),
        )
        .unwrap();
    rustix::fs::flock(&transition_guard, rustix::fs::FlockOperation::LockExclusive).unwrap();

    let pid = broker.0.id().unwrap();
    assert!(
        Command::new("/bin/kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .status()
            .await
            .unwrap()
            .success()
    );
    let status = tokio::time::timeout(Duration::from_secs(3), broker.0.wait())
        .await
        .expect("broker shutdown blocked on transition lock")
        .unwrap();

    assert!(status.success());
    assert!(
        paths.descriptor.exists(),
        "contended safe cleanup should defer descriptor removal"
    );
    assert!(
        paths.lock.exists(),
        "contended release should leave a stale lock"
    );
    drop(transition_guard);
    let replacement = SessionLock::acquire(&paths, std::process::id(), |_| false).unwrap();
    assert!(
        !paths.descriptor.exists(),
        "stale-owner takeover should remove deferred discovery"
    );
    drop(replacement);
}
