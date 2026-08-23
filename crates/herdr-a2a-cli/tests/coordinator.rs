use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use herdr_a2a_broker::{RuntimeDescriptor, RuntimePaths, read_descriptor};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::process::{Child, Command};

const WORKSPACE_LEFT: &str = "workspace-left";
const WORKSPACE_RIGHT: &str = "workspace-right";
const TEST_GENERATION_ID: &str = "0123456789abcdef0123456789abcdef";

fn native_dispatch_command(helper: &Path) -> Command {
    let mut command = Command::new(helper);
    command.args(["coordinator", "dispatch-exec", "--"]);
    command
}

struct CoordinatorFixture {
    root: TempDir,
    socket_path: PathBuf,
    executable: PathBuf,
}

impl CoordinatorFixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        Self {
            socket_path: root.path().join("herdr.sock"),
            executable: PathBuf::from(env!("CARGO_BIN_EXE_herdr-a2a")),
            root,
        }
    }

    fn paths(&self, workspace_id: &str) -> RuntimePaths {
        let session_key = format!(
            "{:x}",
            Sha256::digest(self.socket_path.as_os_str().as_encoded_bytes())
        );
        RuntimePaths::for_test(
            &self.root.path().join("runtime/herdr-a2a"),
            &session_key,
            workspace_id,
        )
    }

    fn command(&self, workspace_id: &str, operation: &str) -> Command {
        let mut command = Command::new(&self.executable);
        command
            .arg("coordinator")
            .arg(operation)
            .env("HERDR_SOCKET_PATH", &self.socket_path)
            .env("HERDR_WORKSPACE_ID", workspace_id)
            .env("HERDR_BIN_PATH", Path::new("/usr/bin/false"))
            .env("HERDR_PLUGIN_STATE_DIR", self.root.path().join("state"))
            .env("HERDR_A2A_TEST_GENERATION_ID", TEST_GENERATION_ID)
            .env("TMPDIR", self.root.path().join("runtime"))
            .env("XDG_RUNTIME_DIR", self.root.path().join("runtime"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        command
    }

    fn broker_command(&self, workspace_id: &str) -> Command {
        let mut command = Command::new(&self.executable);
        command
            .arg("broker")
            .env("HERDR_SOCKET_PATH", &self.socket_path)
            .env("HERDR_WORKSPACE_ID", workspace_id)
            .env("HERDR_BIN_PATH", Path::new("/usr/bin/false"))
            .env("HERDR_PLUGIN_STATE_DIR", self.root.path().join("state"))
            .env("HERDR_A2A_TEST_GENERATION_ID", TEST_GENERATION_ID)
            .env("TMPDIR", self.root.path().join("runtime"))
            .env("XDG_RUNTIME_DIR", self.root.path().join("runtime"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        command
    }

    async fn wait_for_descriptor(&self, workspace_id: &str) -> RuntimeDescriptor {
        let paths = self.paths(workspace_id);
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Ok(descriptor) = read_descriptor(&paths) {
                    return descriptor;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("coordinator did not publish a descriptor")
    }

    async fn stop(&self, workspace_id: &str) {
        let output = self
            .command(workspace_id, "stop")
            .output()
            .await
            .expect("coordinator stop must execute");
        assert!(
            output.status.success(),
            "coordinator stop failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

async fn assert_protected_instance(descriptor: &RuntimeDescriptor) {
    let nonce = [0x5a; 32];
    let encoded_nonce = URL_SAFE_NO_PAD.encode(nonce);
    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .get(format!(
            "{}/health/proof/{encoded_nonce}",
            descriptor.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-herdr-a2a-instance")
            .unwrap()
            .to_str()
            .unwrap(),
        descriptor.broker_instance_id
    );
    let encoded_proof = response
        .headers()
        .get("x-herdr-a2a-health-proof")
        .unwrap()
        .to_str()
        .unwrap();
    let proof = URL_SAFE_NO_PAD.decode(encoded_proof).unwrap();
    let key = Sha256::digest(descriptor.bearer_token.as_bytes());
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
    mac.update(b"herdr-a2a-proof-v2\0");
    mac.update(descriptor.broker_instance_id.as_bytes());
    mac.update(&nonce);
    mac.verify_slice(&proof).unwrap();
}

async fn wait_for_exit(child: &mut Child) {
    tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .expect("coordinator did not exit")
        .unwrap();
}

async fn wait_for_process_exit(pid: u32) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let alive = Command::new("/bin/kill")
                .arg("-0")
                .arg(pid.to_string())
                .status()
                .await
                .unwrap()
                .success();
            if !alive {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("broker process remained alive");
}

#[cfg(unix)]
#[tokio::test]
async fn concurrent_ensures_spawn_exactly_one_broker() {
    // Break caught: omitting the descriptor/health recheck after the coordinator lock permits
    // simultaneous first bootstraps to publish multiple broker instances.
    let fixture = CoordinatorFixture::new();
    fs::create_dir_all(fixture.root.path().join("runtime")).unwrap();
    let mut coordinators = Vec::new();
    for _ in 0..32 {
        coordinators.push(fixture.command(WORKSPACE_LEFT, "serve").spawn().unwrap());
    }

    let descriptor = fixture.wait_for_descriptor(WORKSPACE_LEFT).await;
    assert_protected_instance(&descriptor).await;
    let mut instances = HashSet::new();
    for _ in 0..20 {
        instances.insert(
            read_descriptor(&fixture.paths(WORKSPACE_LEFT))
                .unwrap()
                .broker_instance_id,
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(instances.len(), 1);
    assert!(
        fixture
            .root
            .path()
            .join("state/herdr-a2a")
            .join(&fixture.paths(WORKSPACE_LEFT).scope.scope_key)
            .join("tasks.sqlite3")
            .is_file()
    );

    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut live = 0;
    for child in &mut coordinators {
        if child.try_wait().unwrap().is_none() {
            live += 1;
        }
    }
    assert_eq!(live, 1, "exactly one coordinator must own one broker child");

    fixture.stop(WORKSPACE_LEFT).await;
    for coordinator in &mut coordinators {
        wait_for_exit(coordinator).await;
    }
}

#[cfg(unix)]
#[tokio::test]
async fn post_lock_recheck_32_ensures_adopt_existing_protected_instance() {
    // Break caught: after winning the coordinator lock, an ensure skips the protected descriptor
    // recheck and attempts to spawn a second broker over an already-authoritative instance.
    let fixture = CoordinatorFixture::new();
    fs::create_dir_all(fixture.root.path().join("runtime")).unwrap();
    let mut broker = fixture.broker_command(WORKSPACE_LEFT).spawn().unwrap();
    let existing = fixture.wait_for_descriptor(WORKSPACE_LEFT).await;
    assert_protected_instance(&existing).await;

    let mut ensures = Vec::new();
    for _ in 0..32 {
        ensures.push(fixture.command(WORKSPACE_LEFT, "serve").spawn().unwrap());
    }
    for ensure in &mut ensures {
        let status = tokio::time::timeout(Duration::from_secs(5), ensure.wait())
            .await
            .expect("ensure did not adopt the protected descriptor")
            .unwrap();
        assert!(
            status.success(),
            "ensure attempted a duplicate broker: {status}"
        );
    }
    let adopted = read_descriptor(&fixture.paths(WORKSPACE_LEFT)).unwrap();
    assert_eq!(adopted.broker_instance_id, existing.broker_instance_id);
    assert_eq!(adopted.broker_pid, existing.broker_pid);

    let status = Command::new("/bin/kill")
        .arg("-TERM")
        .arg(existing.broker_pid.to_string())
        .status()
        .await
        .unwrap();
    assert!(status.success());
    wait_for_exit(&mut broker).await;
}

#[cfg(unix)]
#[tokio::test]
async fn failed_child_is_started_only_by_next_ensure() {
    // Break caught: the coordinator eagerly respawns a failed broker instead of allowing the
    // next bootstrap or recovery operation to initiate replacement.
    let fixture = CoordinatorFixture::new();
    fs::create_dir_all(fixture.root.path().join("runtime")).unwrap();
    let mut first_coordinator = fixture.command(WORKSPACE_LEFT, "serve").spawn().unwrap();
    let first = fixture.wait_for_descriptor(WORKSPACE_LEFT).await;

    let status = Command::new("/bin/kill")
        .arg("-KILL")
        .arg(first.broker_pid.to_string())
        .status()
        .await
        .unwrap();
    assert!(status.success());
    wait_for_exit(&mut first_coordinator).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(read_descriptor(&fixture.paths(WORKSPACE_LEFT)).is_err());

    let mut second_coordinator = fixture.command(WORKSPACE_LEFT, "serve").spawn().unwrap();
    let second = fixture.wait_for_descriptor(WORKSPACE_LEFT).await;
    assert_ne!(first.broker_instance_id, second.broker_instance_id);
    assert_protected_instance(&second).await;

    fixture.stop(WORKSPACE_LEFT).await;
    wait_for_exit(&mut second_coordinator).await;
}

#[cfg(unix)]
#[tokio::test]
async fn workspace_close_stops_only_its_matching_child() {
    // Break caught: workspace closure sends a broad process signal and terminates another
    // workspace's broker instead of the child protected by the matching coordinator lock.
    let fixture = CoordinatorFixture::new();
    fs::create_dir_all(fixture.root.path().join("runtime")).unwrap();
    let mut left = fixture.command(WORKSPACE_LEFT, "serve").spawn().unwrap();
    let mut right = fixture.command(WORKSPACE_RIGHT, "serve").spawn().unwrap();
    let left_descriptor = fixture.wait_for_descriptor(WORKSPACE_LEFT).await;
    let right_descriptor = fixture.wait_for_descriptor(WORKSPACE_RIGHT).await;

    fixture.stop(WORKSPACE_LEFT).await;
    wait_for_exit(&mut left).await;
    assert!(read_descriptor(&fixture.paths(WORKSPACE_LEFT)).is_err());
    assert_eq!(
        read_descriptor(&fixture.paths(WORKSPACE_RIGHT))
            .unwrap()
            .broker_instance_id,
        right_descriptor.broker_instance_id
    );
    assert_protected_instance(&right_descriptor).await;
    assert_ne!(left_descriptor.broker_pid, right_descriptor.broker_pid);

    fixture.stop(WORKSPACE_RIGHT).await;
    wait_for_exit(&mut right).await;
}

#[cfg(unix)]
#[tokio::test]
async fn coordinator_death_cannot_orphan_its_workspace_broker() {
    // Break caught: a SIGKILLed coordinator drops no supervision state, leaving its healthy
    // broker alive while `stop` observes an unlocked coordinator file and returns successfully.
    let fixture = CoordinatorFixture::new();
    fs::create_dir_all(fixture.root.path().join("runtime")).unwrap();
    let mut left = fixture.command(WORKSPACE_LEFT, "serve").spawn().unwrap();
    let mut right = fixture.command(WORKSPACE_RIGHT, "serve").spawn().unwrap();
    let left_descriptor = fixture.wait_for_descriptor(WORKSPACE_LEFT).await;
    let right_descriptor = fixture.wait_for_descriptor(WORKSPACE_RIGHT).await;

    let left_coordinator_pid = left.id().unwrap();
    assert!(
        Command::new("/bin/kill")
            .args(["-KILL", &left_coordinator_pid.to_string()])
            .status()
            .await
            .unwrap()
            .success()
    );
    wait_for_exit(&mut left).await;
    fixture.stop(WORKSPACE_LEFT).await;
    wait_for_process_exit(left_descriptor.broker_pid).await;
    assert!(read_descriptor(&fixture.paths(WORKSPACE_LEFT)).is_err());
    assert_eq!(
        read_descriptor(&fixture.paths(WORKSPACE_RIGHT))
            .unwrap()
            .broker_instance_id,
        right_descriptor.broker_instance_id
    );
    assert_protected_instance(&right_descriptor).await;

    fixture.stop(WORKSPACE_RIGHT).await;
    wait_for_exit(&mut right).await;
}

#[cfg(unix)]
#[tokio::test]
async fn stop_follows_a_coordinator_owner_turnover() {
    // Break caught: stop signals owner A once, then waits only for the lock; owner B can acquire
    // and rewrite the record before stop observes the unlocked generation, so B survives close.
    let fixture = CoordinatorFixture::new();
    fs::create_dir_all(fixture.root.path().join("runtime")).unwrap();
    let mut first = fixture.command(WORKSPACE_LEFT, "serve").spawn().unwrap();
    fixture.wait_for_descriptor(WORKSPACE_LEFT).await;

    let mut stop = fixture.command(WORKSPACE_LEFT, "stop").spawn().unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while read_descriptor(&fixture.paths(WORKSPACE_LEFT)).is_ok() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("stop never requested shutdown from the first owner");
    let stop_pid = stop.id().unwrap();
    assert!(
        Command::new("/bin/kill")
            .args(["-STOP", &stop_pid.to_string()])
            .status()
            .await
            .unwrap()
            .success()
    );
    wait_for_exit(&mut first).await;

    let mut second = fixture.command(WORKSPACE_LEFT, "serve").spawn().unwrap();
    let second_pid = second.id().unwrap();
    let paths = fixture.paths(WORKSPACE_LEFT);
    let coordinator_record = paths
        .root
        .join(format!("{}.coordinator.lock", paths.scope.scope_key));
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let owns_lock = fs::read(&coordinator_record)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                .and_then(|record| record.get("pid").and_then(|pid| pid.as_u64()))
                == Some(u64::from(second_pid));
            if owns_lock {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("replacement coordinator never published its owner generation");
    assert!(
        Command::new("/bin/kill")
            .args(["-CONT", &stop_pid.to_string()])
            .status()
            .await
            .unwrap()
            .success()
    );
    let stop_status = tokio::time::timeout(Duration::from_secs(6), stop.wait())
        .await
        .expect("stop lost the replacement coordinator generation")
        .unwrap();
    assert!(stop_status.success());
    wait_for_exit(&mut second).await;
    assert!(read_descriptor(&fixture.paths(WORKSPACE_LEFT)).is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn dispatch_uses_a_private_stable_pointer_and_preserves_exact_argv() {
    // Break caught: the lifecycle manifest goes through a shell check/use bootstrap, or the
    // native target evaluates argv, follows symlinks, or accepts an unsafe installation chain.
    let target_tmp = Path::new(env!("CARGO_TARGET_TMPDIR"));
    fs::create_dir_all(target_tmp).unwrap();
    fs::set_permissions(target_tmp, fs::Permissions::from_mode(0o700)).unwrap();
    let fixture = tempfile::tempdir_in(target_tmp).unwrap();
    fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let fixture_path = fixture.path().canonicalize().unwrap();
    let plugin = fixture_path.join("plugin");
    let libexec = plugin.join("libexec");
    fs::create_dir_all(&libexec).unwrap();
    fs::set_permissions(&plugin, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&libexec, fs::Permissions::from_mode(0o700)).unwrap();
    let helper = libexec.join("herdr-a2a-dispatch");
    fs::copy(Path::new(env!("CARGO_BIN_EXE_herdr-a2a")), &helper).unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();

    let stable_binary = fixture_path.join("stable binary");
    let calls = fixture_path.join("calls");
    let dispatched_plugin_root = fixture_path.join("dispatched-plugin-root");
    fs::write(
        &stable_binary,
        format!(
            "#!/bin/sh\nprintf '%s' \"${{HERDR_A2A_PLUGIN_ROOT:-}}\" > '{}'\n: > '{}'\nfor arg do printf '<%s>\\n' \"$arg\" >> '{}'; done\n",
            dispatched_plugin_root.display(),
            calls.display(),
            calls.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&stable_binary, fs::Permissions::from_mode(0o700)).unwrap();
    let pointer = plugin.join("stable-bin-path");
    fs::write(&pointer, format!("{}\n", stable_binary.display())).unwrap();
    fs::set_permissions(&pointer, fs::Permissions::from_mode(0o600)).unwrap();

    let status = native_dispatch_command(&helper)
        .env(
            "HERDR_A2A_PLUGIN_ROOT",
            fixture_path.join("ambient-attacker-root"),
        )
        .args(["coordinator", "serve", "two words", "*", "$(false)"])
        .status()
        .await
        .unwrap();
    assert!(status.success());
    assert_eq!(
        fs::read_to_string(&calls).unwrap(),
        "<coordinator>\n<serve>\n<two words>\n<*>\n<$(false)>\n"
    );
    assert_eq!(
        fs::read_to_string(&dispatched_plugin_root).unwrap(),
        plugin.to_string_lossy()
    );

    fs::set_permissions(&pointer, fs::Permissions::from_mode(0o666)).unwrap();
    let unsafe_status = native_dispatch_command(&helper)
        .arg("coordinator")
        .arg("serve")
        .status()
        .await
        .unwrap();
    assert!(!unsafe_status.success());

    fs::write(&pointer, format!("{}\n\n", stable_binary.display())).unwrap();
    fs::set_permissions(&pointer, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        !native_dispatch_command(&helper)
            .status()
            .await
            .unwrap()
            .success()
    );

    fs::write(&pointer, format!("{}\n", stable_binary.display())).unwrap();
    fs::set_permissions(&plugin, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(
        !native_dispatch_command(&helper)
            .status()
            .await
            .unwrap()
            .success()
    );
    fs::set_permissions(&plugin, fs::Permissions::from_mode(0o700)).unwrap();

    fs::remove_file(&pointer).unwrap();
    std::os::unix::fs::symlink(&stable_binary, &pointer).unwrap();
    assert!(
        !native_dispatch_command(&helper)
            .status()
            .await
            .unwrap()
            .success()
    );
    fs::remove_file(&pointer).unwrap();
    fs::write(&pointer, format!("{}\n", stable_binary.display())).unwrap();
    fs::set_permissions(&pointer, fs::Permissions::from_mode(0o600)).unwrap();

    let linked_plugin = fixture_path.join("linked-plugin");
    std::os::unix::fs::symlink(&plugin, &linked_plugin).unwrap();
    assert!(
        !native_dispatch_command(&linked_plugin.join("libexec/herdr-a2a-dispatch"))
            .status()
            .await
            .unwrap()
            .success()
    );

    let linked_binary = fixture_path.join("linked stable binary");
    std::os::unix::fs::symlink(&stable_binary, &linked_binary).unwrap();
    fs::write(&pointer, format!("{}\n", linked_binary.display())).unwrap();
    assert!(
        !native_dispatch_command(&helper)
            .status()
            .await
            .unwrap()
            .success()
    );

    let real_binary_parent = fixture_path.join("real-bin");
    fs::create_dir(&real_binary_parent).unwrap();
    let nested_binary = real_binary_parent.join("stable");
    fs::copy(&stable_binary, &nested_binary).unwrap();
    fs::set_permissions(&nested_binary, fs::Permissions::from_mode(0o700)).unwrap();
    let linked_binary_parent = fixture_path.join("linked-bin");
    std::os::unix::fs::symlink(&real_binary_parent, &linked_binary_parent).unwrap();
    fs::write(
        &pointer,
        format!("{}\n", linked_binary_parent.join("stable").display()),
    )
    .unwrap();
    assert!(
        !native_dispatch_command(&helper)
            .status()
            .await
            .unwrap()
            .success()
    );

    fs::remove_file(&pointer).unwrap();
    assert!(
        Command::new("/usr/bin/mkfifo")
            .arg(&pointer)
            .status()
            .await
            .unwrap()
            .success()
    );
    let fifo_status = tokio::time::timeout(
        Duration::from_secs(1),
        native_dispatch_command(&helper).status(),
    )
    .await
    .expect("dispatch blocked while opening a FIFO pointer")
    .unwrap();
    assert!(!fifo_status.success());

    fs::remove_file(&pointer).unwrap();
    fs::write(&pointer, vec![b'x'; 1024 * 1024]).unwrap();
    fs::set_permissions(&pointer, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        !native_dispatch_command(&helper)
            .status()
            .await
            .unwrap()
            .success()
    );

    let real_helper = fixture_path.join("real-helper");
    fs::rename(&helper, &real_helper).unwrap();
    std::os::unix::fs::symlink(&real_helper, &helper).unwrap();
    fs::remove_file(&pointer).unwrap();
    fs::write(&pointer, format!("{}\n", stable_binary.display())).unwrap();
    fs::set_permissions(&pointer, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        !native_dispatch_command(&helper)
            .status()
            .await
            .unwrap()
            .success()
    );
}
