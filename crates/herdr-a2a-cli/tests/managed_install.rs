#![cfg(unix)]

use std::io::{Read, Write};
use std::{
    collections::BTreeSet,
    env, fs,
    fs::File,
    os::unix::{
        ffi::OsStringExt,
        fs::{MetadataExt, PermissionsExt, symlink},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

use rustix::fs::{FlockOperation, flock};
#[cfg(not(target_os = "linux"))]
use rustix::process::test_kill_process_group;
use rustix::process::{Pid, Signal, kill_process, kill_process_group, setpgid};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::{Builder, TempDir};

const OWNERSHIP_SCHEMA: u64 = 3;
// Managed debug executables can spend about 46 seconds in macOS dyld/Gatekeeper before main,
// and that latency grows under a long serialized suite. Keep a generous test-only envelope so
// host load cannot masquerade as a lifecycle failure; production deadlines are unchanged.
const MANAGED_PROCESS_START_WATCHDOG: Duration = Duration::from_secs(120);
const STARTING_PROCESS_OPERATION_WATCHDOG: Duration = Duration::from_secs(120);
const STARTING_PROCESS_SETUP_WATCHDOG: Duration = Duration::from_secs(120);
const STARTING_PROCESS_CASE_WATCHDOG: Duration = Duration::from_secs(240);
const STARTING_PROCESS_AGGREGATE_WATCHDOG: Duration = Duration::from_secs(1_440);
const STARTING_PROCESS_CHILD_OUTPUT_LIMIT: usize = 64 * 1024;
const STARTING_PROCESS_AGGREGATE_LOG: &str = "HERDR_A2A_TEST_STARTING_AGGREGATE_LOG";
const STARTING_PROCESS_TIMEOUT_READY: &str = "HERDR_A2A_TEST_STARTING_TIMEOUT_READY";
const STARTING_PROCESS_GROUP_TERM_GRACE: Duration = Duration::from_secs(1);
const STARTING_PROCESS_GROUP_KILL_GRACE: Duration = Duration::from_secs(3);
const STARTING_PROCESS_FORCED_SETUP_WATCHDOG: Duration = Duration::from_secs(120);
const STARTING_PROCESS_FORCED_CASE_WATCHDOG: Duration = Duration::from_millis(20);
const STARTING_PROCESS_FORCED_OUTER_WATCHDOG: Duration = Duration::from_secs(135);

const HISTORICAL_SCHEMA_V2_BINARY: &[u8] = b"#!/bin/sh\ncase \"${1:-}\" in\n  --version) printf \"%s\\n\" \"herdr-a2a 0.1.0\" ;;\n  *) exit 64 ;;\nesac\n";
const HISTORICAL_SCHEMA_V2_EXTENSION: &[u8] = b"export const historicalAdapter = true;\n";
const HISTORICAL_SCHEMA_V2_MANIFEST: &[u8] = b"{\n  \"name\": \"@herdr/a2a-pi\",\n  \"version\": \"0.1.0\",\n  \"peerDependencies\": {\n    \"@earendil-works/pi-coding-agent\": \">=0.83.0\",\n    \"typebox\": \">=1.3.7 <1.4.0\"\n  }\n}\n";
const HISTORICAL_SCHEMA_V2_SKILL: &[u8] = b"historical skill\n";
const HISTORICAL_SCHEMA_V2_RESCUE: &[u8] = b"#!/bin/sh\nexit 0\n";

const AUTHORITATIVE_SCHEMA_V2_WIRE_SHAPE: &str = r#"{
  "schema_version": 2,
  "state": "Ready",
  "plugin_version": "0.1.0",
  "broker_digest": "acdb1626ece7bc39de8c52df3eb5b5d990dac72f24cdd0a41528aa2b9003297d",
  "pi_package_digest": "ad9f1748c3f0696f50a9feb0a9f39600092899531b815ff66eabb59bdf5a8f8f",
  "pi_package_source": "__STABLE_ROOT__/generations/0123456789abcdef0123456789abcdef/pi",
  "pi_config_path": "__PI_CONFIG_PATH__",
  "pi_package_entry": "__STABLE_ROOT__/generations/0123456789abcdef0123456789abcdef/pi",
  "purge_authority": true,
  "plugin_state_root": "__PLUGIN_STATE_ROOT__",
  "rescue_path": "__STABLE_ROOT__/rescue/uninstall.sh",
  "rescue_marker_digest": "0000000000000000000000000000000000000000000000000000000000000000",
  "install_kind": "managed",
  "plugin_root": "__PLUGIN_ROOT__",
  "stable_binary": "__STABLE_ROOT__/generations/0123456789abcdef0123456789abcdef/bin/herdr-a2a",
  "ownership_path": "__STABLE_ROOT__/ownership.json",
  "owned_files": [
    {"path": "__PLUGIN_ROOT__/libexec/herdr-a2a-dispatch", "sha256": "acdb1626ece7bc39de8c52df3eb5b5d990dac72f24cdd0a41528aa2b9003297d", "mode": 448},
    {"path": "__PLUGIN_ROOT__/stable-bin-path", "sha256": "0000000000000000000000000000000000000000000000000000000000000000", "mode": 384},
    {"path": "__STABLE_ROOT__/generations/0123456789abcdef0123456789abcdef/bin/herdr-a2a", "sha256": "acdb1626ece7bc39de8c52df3eb5b5d990dac72f24cdd0a41528aa2b9003297d", "mode": 448},
    {"path": "__STABLE_ROOT__/generations/0123456789abcdef0123456789abcdef/pi/extensions/herdr-a2a.ts", "sha256": "f814cbc09d6d0f0a03dc63412e8f86016d1b67933dde6fa2128ff31269fb69c8", "mode": 384},
    {"path": "__STABLE_ROOT__/generations/0123456789abcdef0123456789abcdef/pi/package.json", "sha256": "6719c2330ac7e61ff3450898a20f1cc17b5c0a99267e35a186c54633aec379e8", "mode": 384},
    {"path": "__STABLE_ROOT__/generations/0123456789abcdef0123456789abcdef/pi/skills/herdr-a2a/SKILL.md", "sha256": "94518720b0cf9f498f2dea43130693bd929355c68a7069c73c03bc315ee32202", "mode": 384},
    {"path": "__STABLE_ROOT__/rescue/owner-v1", "sha256": "0000000000000000000000000000000000000000000000000000000000000000", "mode": 384},
    {"path": "__STABLE_ROOT__/rescue/uninstall.sh", "sha256": "306c6ca7407560340797866e077e053627ad409277d1b9da58106fce4cf717cb", "mode": 384}
  ]
}"#;

#[test]
fn authoritative_schema_v2_literal_fixture_declares_every_authority_field() {
    // Break caught: a fixture field rename, omission, or partial authority form would silently
    // stop exercising the historical authority-bearing wire representation.
    let fixture: Value = serde_json::from_str(AUTHORITATIVE_SCHEMA_V2_WIRE_SHAPE).unwrap();
    assert_eq!(fixture["schema_version"], 2);
    assert_eq!(fixture["purge_authority"], true);
    for field in [
        "plugin_state_root",
        "rescue_marker_digest",
        "pi_package_source",
        "pi_config_path",
        "pi_package_entry",
        "plugin_root",
        "stable_binary",
        "ownership_path",
    ] {
        assert!(
            fixture.get(field).is_some(),
            "literal authority fixture omitted {field}"
        );
    }
    assert_eq!(fixture["owned_files"].as_array().unwrap().len(), 8);
}

#[test]
fn authoritative_schema_v2_literal_fixture_has_no_current_record_semantic_tokens() {
    // Break caught: the claimed historical fixture copied current record hashes/fields through
    // placeholders, so a current producer change silently changed the historical wire input.
    for token in [
        "__PLUGIN_VERSION__",
        "__BROKER_DIGEST__",
        "__PI_PACKAGE_DIGEST__",
        "__RESCUE_MARKER_DIGEST__",
        "__HELPER_DIGEST__",
        "__POINTER_DIGEST__",
        "__PI_EXTENSION_DIGEST__",
        "__PI_PACKAGE_MANIFEST_DIGEST__",
        "__PI_SKILL_DIGEST__",
        "__RESCUE_DIGEST__",
    ] {
        assert!(
            !AUTHORITATIVE_SCHEMA_V2_WIRE_SHAPE.contains(token),
            "historical fixture derives semantic field {token}"
        );
    }
    let fixture: Value = serde_json::from_str(AUTHORITATIVE_SCHEMA_V2_WIRE_SHAPE).unwrap();
    assert_ne!(fixture["pi_package_entry"], "__PI_PACKAGE_SOURCE__");
}

#[test]
fn authoritative_schema_v2_literal_fixture_materializes_fixed_historical_assets() {
    // Break caught: a fixture that only names fields, but does not create its historical bytes,
    // can inherit a changed current installer and still claim to exercise schema-2 authority.
    let fixture = ManagedFixture::new();
    fixture.materialize_authoritative_schema_v2_literal_for_matrix();
    let record = fixture.record();
    assert_eq!(record["pi_package_entry"], record["pi_package_source"]);
    for (path, bytes) in [
        (
            PathBuf::from(record["stable_binary"].as_str().unwrap()),
            HISTORICAL_SCHEMA_V2_BINARY,
        ),
        (
            fixture.plugin_root.join("libexec/herdr-a2a-dispatch"),
            HISTORICAL_SCHEMA_V2_BINARY,
        ),
        (
            PathBuf::from(record["pi_package_source"].as_str().unwrap())
                .join("extensions/herdr-a2a.ts"),
            HISTORICAL_SCHEMA_V2_EXTENSION,
        ),
        (
            PathBuf::from(record["pi_package_source"].as_str().unwrap()).join("package.json"),
            HISTORICAL_SCHEMA_V2_MANIFEST,
        ),
        (
            PathBuf::from(record["pi_package_source"].as_str().unwrap())
                .join("skills/herdr-a2a/SKILL.md"),
            HISTORICAL_SCHEMA_V2_SKILL,
        ),
        (
            PathBuf::from(record["rescue_path"].as_str().unwrap()),
            HISTORICAL_SCHEMA_V2_RESCUE,
        ),
    ] {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
    let mut package = Sha256::new();
    for relative in [
        "extensions/herdr-a2a.ts",
        "package.json",
        "skills/herdr-a2a/SKILL.md",
    ] {
        package.update((relative.len() as u64).to_be_bytes());
        package.update(relative.as_bytes());
        package.update(match relative {
            "extensions/herdr-a2a.ts" => HISTORICAL_SCHEMA_V2_EXTENSION,
            "package.json" => HISTORICAL_SCHEMA_V2_MANIFEST,
            "skills/herdr-a2a/SKILL.md" => HISTORICAL_SCHEMA_V2_SKILL,
            _ => unreachable!(),
        });
    }
    assert_eq!(
        format!("{:x}", package.finalize()),
        record["pi_package_digest"].as_str().unwrap()
    );
}

#[test]
fn authoritative_schema_v2_matrix_setup_materializes_without_an_installed_record() {
    // Break caught: command-level migration coverage used the runtime template only after
    // reading a current v3 ownership record, rather than starting each case from the literal.
    let fixture = ManagedFixture::new();
    fixture.materialize_authoritative_schema_v2_literal_for_matrix();
    let record: Value =
        serde_json::from_slice(&fs::read(fixture.ownership_path()).unwrap()).unwrap();
    assert_eq!(record["schema_version"], 2);
    assert_eq!(record["purge_authority"], true);
    assert_eq!(record["plugin_version"], "0.1.0");
    assert_eq!(
        record["pi_package_entry"], record["pi_package_source"],
        "matrix setup must retain the literal Pi entry"
    );
}

#[test]
fn authoritative_schema_v2_matrices_do_not_reintroduce_dynamic_fixture_authority() {
    // Break caught: a matrix could silently switch back to a current-record rewrite while its
    // literal-only smoke test still passed.
    let source = include_str!("managed_install.rs");
    let method = &source[source
        .find("\n    fn materialize_authoritative_schema_v2_literal_for_matrix")
        .unwrap()..];
    let method = &method[..method.find("\n    fn ").unwrap()];
    for forbidden in [
        "self.record(",
        "RUNTIME_AUTHORITATIVE_SCHEMA_V2_WIRE_TEMPLATE",
        "rewrite_record_as_authoritative_schema_v2",
    ] {
        assert!(
            !method.contains(forbidden),
            "literal matrix materializer must not derive {forbidden}"
        );
    }
    for matrix_name in [
        "authority_bearing_schema_v2_records_migrate_without_losing_purge_authority",
        "schema_v2_partial_authority_never_enables_purge",
    ] {
        let definition = format!("fn {matrix_name}()");
        let matrix = &source[source.find(&definition).unwrap()..];
        let matrix = &matrix[..matrix.find("\n#[test]").unwrap_or(matrix.len())];
        assert!(
            matrix.contains("materialize_authoritative_schema_v2_literal_for_matrix"),
            "{matrix_name} no longer starts from the literal materializer"
        );
        let setup = &matrix[..matrix
            .find("materialize_authoritative_schema_v2_literal_for_matrix")
            .unwrap()];
        assert!(
            !setup.contains("fixture.install("),
            "{matrix_name} obtains matrix authority from a current install"
        );
        assert!(
            !matrix.contains("rewrite_record_as_authoritative_schema_v2"),
            "{matrix_name} reintroduced dynamic matrix authority"
        );
    }
}

#[test]
fn authoritative_schema_v2_literal_remove_rejects_identity_override_without_destructive_mutation() {
    // Break caught: a debug product invocation could select a different executable than the
    // remover itself, bypassing the current-process identity proof for literal remove or purge.
    for purge in [false, true] {
        let fixture = ManagedFixture::new();
        fixture.materialize_authoritative_schema_v2_literal_for_matrix();
        let state_file = fixture.plugin_state.join("must-survive-identity-rejection");
        fs::write(&state_file, "owned state\n").unwrap();
        fs::set_permissions(&state_file, fs::Permissions::from_mode(0o600)).unwrap();
        fixture.herdr().set_unregister_success_and_plugin_absent();
        let record_before = fixture.record();
        let pi_before = fs::read(fixture.pi_agent_dir.join("settings.json")).unwrap();
        let owned_before = record_before["owned_files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|owned| {
                let path = PathBuf::from(owned["path"].as_str().unwrap());
                (path.clone(), fs::read(path).unwrap())
            })
            .collect::<Vec<_>>();

        let mut command = fixture.command();
        command
            .env(
                "HERDR_A2A_TEST_CURRENT_EXECUTABLE_IDENTITY",
                record_before["stable_binary"].as_str().unwrap(),
            )
            .args(["managed", "remove", "--skip-herdr-unregister"]);
        if purge {
            command.arg("--purge");
        }
        let output = command.output().unwrap();

        assert_failure_code(&output, "owned_process_mismatch");
        let record_after = fixture.record();
        assert_eq!(record_after["schema_version"], OWNERSHIP_SCHEMA);
        assert_eq!(record_after["purge_authority"], true);
        assert_eq!(
            record_after["plugin_state_root"],
            record_before["plugin_state_root"]
        );
        assert_eq!(
            fs::read(fixture.pi_agent_dir.join("settings.json")).unwrap(),
            pi_before
        );
        for (path, bytes) in owned_before {
            assert_eq!(
                fs::read(&path).unwrap(),
                bytes,
                "{} was mutated",
                path.display()
            );
        }
        assert_eq!(fs::read_to_string(&state_file).unwrap(), "owned state\n");
    }
}

struct ExactChildren(Vec<Child>);

impl Drop for ExactChildren {
    fn drop(&mut self) {
        for child in &mut self.0 {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

struct PausedExactProcesses {
    original_registry: String,
    pids: Vec<u32>,
    resumed: bool,
}

impl PausedExactProcesses {
    fn from_managed_install(stable_root: &Path) -> Self {
        let install_lock = File::options()
            .read(true)
            .write(true)
            .open(stable_root.join("install.lock"))
            .unwrap();
        flock(&install_lock, FlockOperation::LockExclusive).unwrap();
        let original_registry = fs::read_to_string(stable_root.join("process-registry")).unwrap();
        let mut pids = BTreeSet::new();
        for line in original_registry.lines().skip(1) {
            let fields = line.split('|').collect::<Vec<_>>();
            assert_eq!(
                fields.len(),
                13,
                "fixture process registry entry is invalid"
            );
            assert_eq!(
                fields[0], "entry",
                "fixture process registry tag is invalid"
            );
            for field in [5, 7] {
                pids.insert(fields[field].parse::<u32>().unwrap());
            }
        }
        assert_eq!(
            pids.len(),
            4,
            "fixture did not register two exact process pairs"
        );

        let mut paused = Self {
            original_registry,
            pids: Vec::new(),
            resumed: false,
        };
        for raw_pid in pids {
            let pid = Pid::from_raw(i32::try_from(raw_pid).unwrap()).unwrap();
            kill_process(pid, Signal::STOP).unwrap();
            paused.pids.push(raw_pid);
        }
        paused
    }

    fn resume(&mut self) {
        if self.resumed {
            return;
        }
        for pid in &self.pids {
            let pid = Pid::from_raw(i32::try_from(*pid).unwrap()).unwrap();
            kill_process(pid, Signal::CONT).unwrap();
        }
        self.resumed = true;
    }
}

impl Drop for PausedExactProcesses {
    fn drop(&mut self) {
        if self.resumed {
            return;
        }
        for pid in &self.pids {
            if let Ok(raw_pid) = i32::try_from(*pid)
                && let Some(pid) = Pid::from_raw(raw_pid)
            {
                let _ = kill_process(pid, Signal::CONT);
            }
        }
        self.resumed = true;
    }
}

struct PausedStartingChildren {
    coordinator: Child,
    broker_pid: Option<u32>,
}

impl PausedStartingChildren {
    fn assert_exact_coordinator_and_broker_live(&mut self) {
        assert!(
            self.coordinator.try_wait().unwrap().is_none(),
            "a stale-reservation mismatch unexpectedly retired the coordinator"
        );
        if let Some(broker_pid) = self.broker_pid {
            assert!(
                process_is_live(broker_pid),
                "a stale-reservation mismatch unexpectedly retired the broker"
            );
        }
    }

    fn assert_exact_coordinator_and_broker_retired(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.coordinator.try_wait().unwrap().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            self.coordinator.try_wait().unwrap().is_some(),
            "managed lifecycle command returned while its exact starting coordinator remained live"
        );
        if let Some(broker_pid) = self.broker_pid {
            assert!(
                !process_is_live(broker_pid),
                "managed lifecycle command returned while its exact starting broker remained live"
            );
        }
    }

    fn retire_for_fixture(&mut self) {
        if self.coordinator.try_wait().unwrap().is_none() {
            self.coordinator.kill().unwrap();
            self.coordinator.wait().unwrap();
        }
        if let Some(broker_pid) = self.broker_pid {
            let deadline = Instant::now() + Duration::from_secs(5);
            while process_is_live(broker_pid) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            assert!(
                !process_is_live(broker_pid),
                "fixture could not retire its exact broker"
            );
        }
    }
}

impl Drop for PausedStartingChildren {
    fn drop(&mut self) {
        if self.coordinator.try_wait().ok().flatten().is_none() {
            let _ = self.coordinator.kill();
            let _ = self.coordinator.wait();
        }
    }
}

struct ManagedFixture {
    _root: TempDir,
    base: PathBuf,
    home: PathBuf,
    data_home: PathBuf,
    plugin_root: PathBuf,
    pi_agent_dir: PathBuf,
    fake_bin: PathBuf,
    pi_log: PathBuf,
    herdr_log: PathBuf,
    herdr_control: PathBuf,
    plugin_state: PathBuf,
}

impl ManagedFixture {
    fn new() -> Self {
        let root = Builder::new()
            .prefix("herdr managed install ")
            .tempdir()
            .unwrap();
        let base = root.path().canonicalize().unwrap();
        let home = base.join("home with spaces");
        let data_home = base.join("data with spaces");
        let checkout = base.join("checkout with spaces");
        let plugin_root = checkout.join("plugins/herdr");
        let pi_agent_dir = base.join("pi agent");
        let fake_bin = base.join("fake bin");
        let pi_log = base.join("pi.log");
        let herdr_log = base.join("herdr.log");
        let herdr_control = base.join("herdr-control");
        let plugin_state = base.join("state base with spaces/herdr/plugins/herdr.a2a");
        for directory in [
            &home,
            &data_home,
            &plugin_root,
            &pi_agent_dir,
            &fake_bin,
            &plugin_state,
        ] {
            fs::create_dir_all(directory).unwrap();
        }
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        for directory in [
            &home,
            &data_home,
            &checkout,
            &checkout.join("plugins"),
            &fake_bin,
            &base.join("state base with spaces"),
        ] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::set_permissions(&plugin_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&plugin_state, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            plugin_root.join("herdr-plugin.toml"),
            format!("version = \"{}\"\n", env!("CARGO_PKG_VERSION")),
        )
        .unwrap();
        fs::set_permissions(
            plugin_root.join("herdr-plugin.toml"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::create_dir(plugin_root.join("scripts")).unwrap();
        fs::set_permissions(
            plugin_root.join("scripts"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::write(
            plugin_root.join("scripts/uninstall.sh"),
            include_bytes!("../../../plugins/herdr/scripts/uninstall.sh"),
        )
        .unwrap();
        fs::set_permissions(
            plugin_root.join("scripts/uninstall.sh"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::write(
            pi_agent_dir.join("settings.json"),
            serde_json::to_vec_pretty(&json!({ "packages": [] })).unwrap(),
        )
        .unwrap();
        fs::set_permissions(
            pi_agent_dir.join("settings.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        let fake_pi = fake_bin.join("pi");
        fs::write(
            &fake_pi,
            r##"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$HERDR_A2A_TEST_PI_LOG"
case "${HERDR_A2A_TEST_PI_MODE:-ok}" in
  fail)
    printf '%s\n' 'permission denied' >&2
    exit 23
    ;;
  noisy)
    python3 - <<'PY'
import sys
sys.stdout.write('x' * 70000)
PY
    exit 0
    ;;
  install_then_fail) ;;
  normalize_relative) ;;
  slow)
    sleep 0.2
    ;;
  block_remove)
    if [ "${1:-}" = remove ]; then
      : > "$HERDR_A2A_TEST_PI_BLOCKED"
      while [ ! -e "$HERDR_A2A_TEST_PI_RELEASE" ]; do sleep 0.01; done
    fi
    ;;
esac
command_name=${1:-}
source=${2:-}
settings=${PI_CODING_AGENT_DIR:-$HOME/.pi/agent}/settings.json
case "$command_name" in
  --version)
    printf '%s\n' "${HERDR_A2A_TEST_PI_VERSION:-0.84.2}"
    exit 0
    ;;
  install|remove)
    python3 - "$settings" "$command_name" "$source" <<'PY'
import json, os, sys, tempfile
path, command, source = sys.argv[1:]
mode = os.environ.get('HERDR_A2A_TEST_PI_MODE', 'ok')
with open(path, encoding='utf-8') as handle:
    value = json.load(handle)
packages = value.setdefault('packages', [])
def package_source(entry):
    return entry if isinstance(entry, str) else entry.get('source')
if command == 'install':
    stored = os.path.relpath(source, os.path.dirname(path)) if mode == 'normalize_relative' else source
    if not any(package_source(entry) == stored for entry in packages):
        packages.append(stored)
else:
    def canonical(candidate):
        return os.path.normpath(candidate if os.path.isabs(candidate) else os.path.join(os.path.dirname(path), candidate))
    matches = [index for index, entry in enumerate(packages) if canonical(package_source(entry)) == canonical(source)]
    if not matches:
        sys.exit(24)
    del packages[matches[0]]
fd, temporary = tempfile.mkstemp(prefix='.settings-', dir=os.path.dirname(path))
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        json.dump(value, handle, indent=2)
        handle.write('\n')
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY
    ;;
  list) ;;
  *) exit 64 ;;
esac
if [ "${HERDR_A2A_TEST_PI_MODE:-ok}" = install_then_fail ] && [ "$command_name" = install ]; then
  printf '%s\n' 'failed after settings mutation' >&2
  exit 23
fi
"##,
        )
        .unwrap();
        fs::set_permissions(&fake_pi, fs::Permissions::from_mode(0o700)).unwrap();

        let fake_herdr = fake_bin.join("herdr");
        fs::write(
            &fake_herdr,
            r##"#!/bin/sh
set -eu
control=$(cat "$HERDR_A2A_TEST_HERDR_CONTROL")
unregister_mode=${HERDR_A2A_TEST_HERDR_MODE:-${control%%|*}}
list_mode=${control#*|}
if [ "${1:-} ${2:-} ${3:-}" = "plugin uninstall herdr.a2a" ]; then
  printf '%s\n' uninstall >> "$HERDR_A2A_TEST_HERDR_LOG"
  [ "$unregister_mode" != fail ] || exit 23
  [ "$unregister_mode" != fail-if-uninstall-called ] || exit 97
  exit 0
fi
[ "${1:-} ${2:-} ${3:-} ${4:-} ${5:-}" = "plugin list --plugin herdr.a2a --json" ] || exit 64
case "$list_mode" in
  absent)
    printf '%s\n' '{"id":"cli:plugin","result":{"plugins":[],"type":"plugin_list"}}'
    ;;
  present)
    printf '{"id":"cli:plugin","result":{"plugins":[{"plugin_id":"herdr.a2a","enabled":true,"plugin_root":"%s"}],"type":"plugin_list"}}\n' "$HERDR_A2A_TEST_HERDR_PLUGIN_ROOT"
    ;;
  malformed)
    printf '%s\n' 'untrusted child output with /raw/path'
    ;;
  duplicate)
    printf '{"id":"cli:plugin","result":{"plugins":[{"plugin_id":"herdr.a2a","enabled":true,"plugin_root":"%s"},{"plugin_id":"herdr.a2a","enabled":true,"plugin_root":"%s"}],"type":"plugin_list"}}\n' "$HERDR_A2A_TEST_HERDR_PLUGIN_ROOT" "$HERDR_A2A_TEST_HERDR_PLUGIN_ROOT"
    ;;
  conflicting-root)
    printf '%s\n' '{"id":"cli:plugin","result":{"plugins":[{"plugin_id":"herdr.a2a","enabled":true,"plugin_root":"/conflicting/plugin/root"}],"type":"plugin_list"}}'
    ;;
  timeout)
    exec sleep 16
    ;;
  oversized)
    exec python3 -c 'import sys; sys.stdout.write("x" * 70000)'
    ;;
  redirected)
    printf '%s\n' '{"id":"cli:redirect","result":{"plugins":[],"type":"plugin_list"}}'
    ;;
  *) exit 64 ;;
esac
"##,
        )
        .unwrap();
        fs::set_permissions(&fake_herdr, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&herdr_control, "success|present\n").unwrap();

        Self {
            _root: root,
            base,
            home,
            data_home,
            plugin_root,
            pi_agent_dir,
            fake_bin,
            pi_log,
            herdr_log,
            herdr_control,
            plugin_state,
        }
    }

    fn stable_root(&self) -> PathBuf {
        if cfg!(target_os = "macos") {
            self.home.join("Library/Application Support/herdr-a2a")
        } else {
            self.data_home.join("herdr-a2a")
        }
    }

    fn ownership_path(&self) -> PathBuf {
        self.stable_root().join("ownership.json")
    }

    fn bundle(&self, name: &str, contents: &str) -> PathBuf {
        let bundle = self.base.join(format!("bundle {name}"));
        let binary = bundle.join("bin/herdr-a2a");
        let package = bundle.join("pi");
        fs::create_dir_all(binary.parent().unwrap()).unwrap();
        fs::create_dir_all(package.join("extensions")).unwrap();
        fs::create_dir_all(package.join("skills/herdr-a2a")).unwrap();
        fs::copy(env!("CARGO_BIN_EXE_herdr-a2a"), &binary).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            package.join("package.json"),
            format!(
                "{{\n  \"name\": \"@herdr/a2a-pi\",\n  \"version\": \"{}\",\n  \"peerDependencies\": {{\n    \"@earendil-works/pi-coding-agent\": \">=0.84.2\",\n    \"typebox\": \">=1.3.7 <1.4.0\"\n  }}\n}}\n",
                env!("CARGO_PKG_VERSION")
            ),
        )
        .unwrap();
        fs::write(package.join("extensions/herdr-a2a.ts"), contents).unwrap();
        fs::write(
            package.join("skills/herdr-a2a/SKILL.md"),
            format!("managed skill {name}\n"),
        )
        .unwrap();
        for directory in [
            &bundle,
            &bundle.join("bin"),
            &package,
            &package.join("extensions"),
            &package.join("skills"),
            &package.join("skills/herdr-a2a"),
        ] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        for file in [
            package.join("package.json"),
            package.join("extensions/herdr-a2a.ts"),
            package.join("skills/herdr-a2a/SKILL.md"),
        ] {
            fs::set_permissions(file, fs::Permissions::from_mode(0o600)).unwrap();
        }
        bundle
    }

    fn command(&self) -> Command {
        self.command_with_program(Path::new(env!("CARGO_BIN_EXE_herdr-a2a")))
    }

    fn command_with_program(&self, program: &Path) -> Command {
        let mut command = Command::new(program);
        let current_path = env::var_os("PATH").unwrap_or_default();
        command
            .env("HOME", &self.home)
            .env("XDG_DATA_HOME", &self.data_home)
            .env("PI_CODING_AGENT_DIR", &self.pi_agent_dir)
            .env("HERDR_A2A_PLUGIN_ROOT", &self.plugin_root)
            .env("HERDR_A2A_TEST_PI_LOG", &self.pi_log)
            .env("HERDR_A2A_TEST_HERDR_LOG", &self.herdr_log)
            .env("HERDR_A2A_TEST_HERDR_CONTROL", &self.herdr_control)
            .env("HERDR_A2A_TEST_HERDR_PLUGIN_ROOT", &self.plugin_root)
            .env("HERDR_PLUGIN_STATE_DIR", &self.plugin_state)
            .env(
                "PATH",
                env::join_paths(
                    std::iter::once(self.fake_bin.clone()).chain(env::split_paths(&current_path)),
                )
                .unwrap(),
            );
        command
    }

    fn remove(&self, purge: bool, skip_herdr_unregister: bool) -> Output {
        let mut command = self.command();
        command.args(["managed", "remove"]);
        if purge {
            command.arg("--purge");
        }
        if skip_herdr_unregister {
            command.arg("--skip-herdr-unregister");
        }
        command.output().unwrap()
    }

    fn remove_after_exact_plugin_absence(&self, purge: bool) -> Output {
        self.herdr().set_unregister_success_and_plugin_absent();
        self.remove(purge, true)
    }

    fn remove_with_mode(&self, mode: &str) -> Output {
        self.command()
            .env("HERDR_A2A_TEST_HERDR_MODE", mode)
            .args(["managed", "remove"])
            .output()
            .unwrap()
    }

    fn record_state(&self) -> String {
        self.record()["state"].as_str().unwrap().to_owned()
    }

    fn abort_after_external_unregister_before_phase_write(&self) -> Output {
        self.command()
            .env(
                "HERDR_A2A_TEST_ABORT_AFTER_EXTERNAL_UNREGISTER_BEFORE_PHASE_WRITE",
                "1",
            )
            .args(["managed", "remove"])
            .output()
            .unwrap()
    }

    fn herdr(&self) -> HerdrFixture<'_> {
        HerdrFixture { fixture: self }
    }

    fn install(&self, bundle: &Path) -> Output {
        self.command()
            .args(["managed", "install", "--bundle"])
            .arg(bundle)
            .output()
            .unwrap()
    }

    fn transactional_plugin_root(&self, token: &str) -> PathBuf {
        let root = self.base.join(format!(
            "config/herdr/plugins/.tmp-install-{token}/checkout/plugins/herdr"
        ));
        fs::create_dir_all(root.join("scripts")).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(root.join("scripts"), fs::Permissions::from_mode(0o700)).unwrap();
        for relative in ["herdr-plugin.toml", "scripts/uninstall.sh"] {
            fs::copy(self.plugin_root.join(relative), root.join(relative)).unwrap();
            fs::set_permissions(root.join(relative), fs::Permissions::from_mode(0o600)).unwrap();
        }
        root
    }

    fn install_from_plugin_root(&self, bundle: &Path, plugin_root: &Path) -> Output {
        self.command()
            .env("HERDR_A2A_PLUGIN_ROOT", plugin_root)
            .env("HERDR_A2A_TEST_HERDR_PLUGIN_ROOT", plugin_root)
            .args(["managed", "install", "--bundle"])
            .arg(bundle)
            .output()
            .unwrap()
    }

    fn run_lifecycle_operation_with_watchdog(
        &self,
        operation: &str,
        bundle: &Path,
        boundary: &str,
    ) -> Output {
        if operation == "remove" {
            self.herdr().set_unregister_success_and_plugin_absent();
        }
        let mut command = self.command();
        match operation {
            "update" => {
                command.args(["managed", "install", "--bundle"]).arg(bundle);
            }
            "remove" => {
                command.args(["managed", "remove", "--skip-herdr-unregister"]);
            }
            _ => panic!("unknown managed lifecycle operation {operation}"),
        }
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let started = Instant::now();
        eprintln!("starting-process case={operation}/{boundary} phase=operation-start");
        let mut child = command.spawn().unwrap();
        let deadline = started + STARTING_PROCESS_OPERATION_WATCHDOG;
        loop {
            if child.try_wait().unwrap().is_some() {
                let output = child.wait_with_output().unwrap();
                eprintln!(
                    "starting-process case={operation}/{boundary} phase=operation-finished elapsed_ms={}",
                    started.elapsed().as_millis()
                );
                return output;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "starting-process case={operation}/{boundary} watchdog expired after {} ms\nstdout: {}\nstderr: {}\nPi calls: {}",
                    started.elapsed().as_millis(),
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr),
                    self.pi_log(),
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn start_managed_coordinator_paused(&self, boundary: &str) -> PausedStartingChildren {
        let stable_binary = PathBuf::from(self.record()["stable_binary"].as_str().unwrap());
        let runtime = self.base.join(format!("starting runtime {boundary}"));
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let marker = self.base.join(format!("starting pause {boundary}"));
        let coordinator = self
            .command_with_program(&stable_binary)
            .args(["coordinator", "serve"])
            .env(
                "HERDR_SOCKET_PATH",
                self.base.join(format!("{boundary}.sock")),
            )
            .env("HERDR_WORKSPACE_ID", format!("workspace-{boundary}"))
            .env("HERDR_BIN_PATH", "/usr/bin/false")
            .env("TMPDIR", &runtime)
            .env("XDG_RUNTIME_DIR", &runtime)
            .env("HERDR_A2A_TEST_STARTING_BOUNDARY", boundary)
            .env("HERDR_A2A_TEST_STARTING_MARKER", &marker)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + MANAGED_PROCESS_START_WATCHDOG;
        while !marker.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            marker.exists(),
            "coordinator did not reach starting-process boundary {boundary}"
        );
        PausedStartingChildren {
            coordinator,
            broker_pid: None,
        }
    }

    fn wait_for_starting_registry(
        &self,
        boundary: &str,
        children: &mut PausedStartingChildren,
    ) -> Value {
        let registry = self.stable_root().join("starting-process-registry.json");
        let deadline = Instant::now() + Duration::from_secs(5);
        let starting = loop {
            let encoded = fs::read(&registry).unwrap_or_default();
            if let Ok(starting) = serde_json::from_slice::<Value>(&encoded)
                && starting["entries"]
                    .as_array()
                    .is_some_and(|entries| entries.len() == 1)
            {
                break starting;
            }
            assert!(
                Instant::now() < deadline,
                "{boundary} did not publish exactly one durable starting reservation: {:?}",
                String::from_utf8_lossy(&encoded)
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        let entry = &starting["entries"][0];
        assert_eq!(
            entry["coordinator_pid"].as_u64(),
            Some(u64::from(children.coordinator.id())),
            "{boundary} did not preserve the exact coordinator PID"
        );
        assert!(
            entry["coordinator_start"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "{boundary} has no exact coordinator start proof"
        );
        assert_eq!(
            entry["executable_path"].as_str(),
            self.record()["stable_binary"].as_str(),
            "{boundary} did not preserve the exact coordinator executable"
        );
        assert_eq!(
            entry["executable_digest"].as_str(),
            self.record()["broker_digest"].as_str(),
            "{boundary} did not preserve the exact coordinator digest"
        );

        if boundary == "after-coordinator-reservation" {
            assert!(
                entry.get("broker").is_none() || entry["broker"].is_null(),
                "{boundary} unexpectedly has a broker proof"
            );
        } else {
            let broker = &entry["broker"];
            let broker_pid = broker["broker_pid"]
                .as_u64()
                .unwrap_or_else(|| panic!("{boundary} has no durable broker PID"));
            children.broker_pid = Some(u32::try_from(broker_pid).unwrap());
            assert!(
                broker["broker_start"]
                    .as_str()
                    .is_some_and(|value| !value.is_empty()),
                "{boundary} has no exact broker start proof"
            );
            assert_eq!(
                broker["executable_path"].as_str(),
                self.record()["stable_binary"].as_str(),
                "{boundary} did not preserve the exact broker executable"
            );
            assert_eq!(
                broker["executable_digest"].as_str(),
                self.record()["broker_digest"].as_str(),
                "{boundary} did not preserve the exact broker digest"
            );
        }
        starting
    }

    fn assert_no_starting_or_registered_entry(&self) {
        let starting = self.stable_root().join("starting-process-registry.json");
        assert!(
            !starting.exists(),
            "managed lifecycle command retained a starting-process registry: {:?}",
            fs::read_to_string(&starting).unwrap_or_default()
        );
        let registered = self.stable_root().join("process-registry");
        assert!(
            !registered.exists()
                || fs::read_to_string(&registered)
                    .unwrap_or_default()
                    .lines()
                    .all(|line| !line.starts_with("entry|")),
            "managed lifecycle command retained a registered process entry: {:?}",
            fs::read_to_string(&registered).unwrap_or_default()
        );
    }

    fn repair(&self) -> Output {
        self.command()
            .args(["managed", "repair", "--startup"])
            .output()
            .unwrap()
    }

    fn status_json(&self) -> Output {
        self.command()
            .args(["managed", "status", "--json"])
            .output()
            .unwrap()
    }

    fn record(&self) -> Value {
        serde_json::from_slice(&fs::read(self.ownership_path()).unwrap()).unwrap()
    }

    fn set_record_state(&self, state: &str) {
        let mut record = self.record();
        record["state"] = json!(state);
        fs::write(
            self.ownership_path(),
            serde_json::to_vec_pretty(&record).unwrap(),
        )
        .unwrap();
        fs::set_permissions(self.ownership_path(), fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn downgrade_record_to_schema_v2(&self) {
        let mut record = self.record();
        let rescue = self.stable_root().join("rescue/uninstall.sh");
        let helper = self.stable_root().join("rescue/herdr-a2a-rescue");
        record["schema_version"] = json!(2);
        record.as_object_mut().unwrap().remove("purge_authority");
        record.as_object_mut().unwrap().remove("plugin_state_root");
        record
            .as_object_mut()
            .unwrap()
            .remove("rescue_marker_digest");
        record["owned_files"]
            .as_array_mut()
            .unwrap()
            .retain(|entry| entry["path"] != helper.to_str().unwrap());
        record["owned_files"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|entry| entry["path"] == rescue.to_str().unwrap())
            .unwrap()["mode"] = json!(0o700);
        fs::set_permissions(&rescue, fs::Permissions::from_mode(0o700)).unwrap();
        match fs::remove_file(&helper) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("remove v3-only rescue helper: {error}"),
        }
        fs::write(
            self.ownership_path(),
            serde_json::to_vec_pretty(&record).unwrap(),
        )
        .unwrap();
        fs::set_permissions(self.ownership_path(), fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn downgrade_current_record_to_authoritative_schema_v2(&self) {
        let mut record = self.record();
        record["schema_version"] = json!(2);
        fs::write(
            self.ownership_path(),
            serde_json::to_vec_pretty(&record).unwrap(),
        )
        .unwrap();
        fs::set_permissions(self.ownership_path(), fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn materialize_authoritative_schema_v2_literal_for_matrix(&self) {
        // Matrix authority is the checked-in pre-fix record and byte fixtures.  Root-derived
        // pointer/marker values are recomputed from those declared paths only; no installed
        // ownership record, runtime template, or current asset digest participates.
        let substitutions = [
            ("__STABLE_ROOT__", self.stable_root()),
            (
                "__PI_CONFIG_PATH__",
                self.pi_agent_dir.join("settings.json"),
            ),
            ("__PLUGIN_STATE_ROOT__", self.plugin_state.clone()),
            ("__PLUGIN_ROOT__", self.plugin_root.clone()),
        ];
        let mut encoded = AUTHORITATIVE_SCHEMA_V2_WIRE_SHAPE.to_owned();
        for (token, path) in substitutions {
            encoded = encoded.replace(token, &path.display().to_string());
        }
        assert!(
            !encoded.contains("__"),
            "literal has an undeclared substitution"
        );
        let mut record: Value = serde_json::from_str(&encoded).unwrap();
        let stable_root = PathBuf::from(record["ownership_path"].as_str().unwrap())
            .parent()
            .unwrap()
            .to_path_buf();
        let source = PathBuf::from(record["pi_package_source"].as_str().unwrap());
        let binary = PathBuf::from(record["stable_binary"].as_str().unwrap());
        let rescue = PathBuf::from(record["rescue_path"].as_str().unwrap());
        let plugin_root = PathBuf::from(record["plugin_root"].as_str().unwrap());
        let helper = plugin_root.join("libexec/herdr-a2a-dispatch");
        let pointer = plugin_root.join("stable-bin-path");
        let marker = stable_root.join("rescue/owner-v1");
        let generations = stable_root.join("generations");
        let extensions = source.join("extensions");
        let skills = source.join("skills");
        let skill_root = skills.join("herdr-a2a");
        let rescue_root = stable_root.join("rescue");
        let libexec = plugin_root.join("libexec");
        let extension = extensions.join("herdr-a2a.ts");
        let manifest = source.join("package.json");
        let skill = skill_root.join("SKILL.md");
        for anchor in [
            &stable_root,
            &source,
            &rescue_root,
            &plugin_root,
            &libexec,
            Path::new(record["pi_config_path"].as_str().unwrap())
                .parent()
                .unwrap(),
            Path::new(record["plugin_state_root"].as_str().unwrap()),
        ] {
            self.harden_literal_directory_chain(anchor);
        }
        for directory in [
            &stable_root,
            &generations,
            binary.parent().unwrap(),
            &source,
            &extensions,
            &skills,
            &skill_root,
            &rescue_root,
            &libexec,
        ] {
            self.harden_literal_directory_chain(directory);
        }
        for (path, bytes, mode) in [
            (&binary, HISTORICAL_SCHEMA_V2_BINARY, 0o700),
            (&helper, HISTORICAL_SCHEMA_V2_BINARY, 0o700),
            (&extension, HISTORICAL_SCHEMA_V2_EXTENSION, 0o600),
            (&manifest, HISTORICAL_SCHEMA_V2_MANIFEST, 0o600),
            (&skill, HISTORICAL_SCHEMA_V2_SKILL, 0o600),
            (&rescue, HISTORICAL_SCHEMA_V2_RESCUE, 0o600),
        ] {
            self.harden_literal_directory_chain(path.parent().unwrap());
            fs::write(path, bytes)
                .unwrap_or_else(|error| panic!("materialize {}: {error}", path.display()));
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }
        let pointer_bytes = format!("{}\n", binary.display()).into_bytes();
        fs::write(&pointer, &pointer_bytes).unwrap();
        fs::set_permissions(&pointer, fs::Permissions::from_mode(0o600)).unwrap();
        let pointer_digest = format!("{:x}", Sha256::digest(&pointer_bytes));
        let owned = record["owned_files"].as_array_mut().unwrap();
        owned
            .iter_mut()
            .find(|owned| owned["path"].as_str() == pointer.to_str())
            .unwrap()["sha256"] = json!(pointer_digest);

        let marker_contents = self.authoritative_schema_v2_rescue_marker(&record);
        let marker_digest = format!("{:x}", Sha256::digest(marker_contents.as_bytes()));
        fs::write(&marker, marker_contents).unwrap();
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
        record["rescue_marker_digest"] = json!(marker_digest.clone());
        record["owned_files"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|owned| owned["path"].as_str() == marker.to_str())
            .unwrap()["sha256"] = json!(marker_digest);

        fs::write(
            record["pi_config_path"].as_str().unwrap(),
            serde_json::to_vec_pretty(&json!({ "packages": [record["pi_package_entry"].clone()] }))
                .unwrap(),
        )
        .unwrap();
        fs::set_permissions(
            record["pi_config_path"].as_str().unwrap(),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::write(
            self.ownership_path(),
            serde_json::to_vec_pretty(&record).unwrap(),
        )
        .unwrap();
        fs::set_permissions(self.ownership_path(), fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn authoritative_schema_v2_rescue_marker(&self, record: &Value) -> String {
        let stable_root = PathBuf::from(record["ownership_path"].as_str().unwrap())
            .parent()
            .unwrap()
            .to_path_buf();
        let plugin_root = PathBuf::from(record["plugin_root"].as_str().unwrap());
        let generation = PathBuf::from(record["pi_package_source"].as_str().unwrap())
            .parent()
            .unwrap()
            .to_path_buf();
        let marker = stable_root.join("rescue/owner-v1");
        let mut contents = format!(
            "HERDR_A2A_RESCUE_V1\nstable_root={}\nstable_binary={}\npi_package_source={}\npi_config_path={}\nplugin_root={}\nbroker_digest={}\n",
            stable_root.display(),
            record["stable_binary"].as_str().unwrap(),
            record["pi_package_source"].as_str().unwrap(),
            record["pi_config_path"].as_str().unwrap(),
            record["plugin_root"].as_str().unwrap(),
            record["broker_digest"].as_str().unwrap(),
        );
        let owned = record["owned_files"].as_array().unwrap();
        for file in owned
            .iter()
            .filter(|file| file["path"].as_str() != marker.to_str())
        {
            contents.push_str(&format!(
                "owned={}|{}|{}\n",
                file["mode"].as_u64().unwrap(),
                file["sha256"].as_str().unwrap(),
                file["path"].as_str().unwrap(),
            ));
        }
        contents.push_str(&format!(
            "state_root={}\n",
            record["plugin_state_root"].as_str().unwrap()
        ));
        let mut directories = BTreeSet::from([
            generation.clone(),
            stable_root.join("rescue"),
            plugin_root.join("libexec"),
        ]);
        for file in owned {
            let mut parent = Path::new(file["path"].as_str().unwrap()).parent();
            while let Some(directory) = parent {
                if directory == generation.as_path() || directory.starts_with(&generation) {
                    directories.insert(directory.to_path_buf());
                    parent = directory.parent();
                } else {
                    break;
                }
            }
        }
        let mut directories = directories.into_iter().collect::<Vec<_>>();
        directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
        for directory in directories {
            contents.push_str(&format!("dir={}\n", directory.display()));
        }
        contents
    }

    fn harden_literal_directory_chain(&self, path: &Path) {
        let relative = path.strip_prefix(&self.base).unwrap_or_else(|_| {
            panic!(
                "literal directory {} escaped fixture base {}",
                path.display(),
                self.base.display()
            )
        });
        let mut current = self.base.clone();
        fs::set_permissions(&current, fs::Permissions::from_mode(0o700)).unwrap();
        for component in relative.components() {
            let std::path::Component::Normal(name) = component else {
                panic!(
                    "literal directory has a non-normal component: {}",
                    path.display()
                );
            };
            current.push(name);
            if !current.exists() {
                fs::create_dir(&current).unwrap();
            }
            let metadata = fs::symlink_metadata(&current).unwrap();
            assert!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "literal directory is not an owned directory: {}",
                current.display()
            );
            fs::set_permissions(&current, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    fn rewrite_record_as_round2_schema_v3_with_rescue_helper(&self) {
        let mut record = self.record();
        let rescue = self.stable_root().join("rescue/uninstall.sh");
        let marker = self.stable_root().join("rescue/owner-v1");
        let helper = self.stable_root().join("rescue/herdr-a2a-rescue");
        let stable_binary = PathBuf::from(record["stable_binary"].as_str().unwrap());
        fs::set_permissions(&rescue, fs::Permissions::from_mode(0o700)).unwrap();
        fs::copy(&stable_binary, &helper).unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
        let rescue_digest = format!("{:x}", Sha256::digest(fs::read(&rescue).unwrap()));
        let broker_digest = record["broker_digest"].clone();
        let stable_binary_text = record["stable_binary"].as_str().unwrap().to_owned();
        let pi_package_source_text = record["pi_package_source"].as_str().unwrap().to_owned();
        let pi_config_path_text = record["pi_config_path"].as_str().unwrap().to_owned();
        let plugin_root_text = record["plugin_root"].as_str().unwrap().to_owned();
        let broker_digest_text = record["broker_digest"].as_str().unwrap().to_owned();
        let plugin_state_root_text = record["plugin_state_root"].as_str().unwrap().to_owned();
        let generation = PathBuf::from(&pi_package_source_text)
            .parent()
            .unwrap()
            .to_path_buf();
        let files = record["owned_files"].as_array_mut().unwrap();
        files.retain(|entry| entry["path"] != marker.to_str().unwrap());
        let rescue_entry = files
            .iter_mut()
            .find(|entry| entry["path"] == rescue.to_str().unwrap())
            .unwrap();
        rescue_entry["mode"] = json!(0o700);
        rescue_entry["sha256"] = json!(rescue_digest);
        files.push(json!({
            "path": helper,
            "sha256": broker_digest,
            "mode": 0o700
        }));
        files.sort_by(|left, right| {
            left["path"]
                .as_str()
                .unwrap()
                .cmp(right["path"].as_str().unwrap())
        });
        let mut marker_contents = format!(
            "HERDR_A2A_RESCUE_V1\nstable_root={}\nstable_binary={}\npi_package_source={}\npi_config_path={}\nplugin_root={}\nbroker_digest={}\n",
            self.stable_root().display(),
            stable_binary_text,
            pi_package_source_text,
            pi_config_path_text,
            plugin_root_text,
            broker_digest_text,
        );
        for owned in files.iter() {
            marker_contents.push_str(&format!(
                "owned={}|{}|{}\n",
                owned["mode"].as_u64().unwrap(),
                owned["sha256"].as_str().unwrap(),
                owned["path"].as_str().unwrap(),
            ));
        }
        marker_contents.push_str(&format!("state_root={}\n", plugin_state_root_text));
        let mut directories = BTreeSet::from([
            generation.clone(),
            self.stable_root().join("rescue"),
            self.plugin_root.join("libexec"),
        ]);
        for owned in files.iter() {
            let owned = PathBuf::from(owned["path"].as_str().unwrap());
            let mut parent = owned.parent();
            while let Some(directory) = parent {
                if directory == generation || directory.starts_with(&generation) {
                    directories.insert(directory.to_path_buf());
                    parent = directory.parent();
                } else {
                    break;
                }
            }
        }
        let mut directories: Vec<_> = directories.into_iter().collect();
        directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
        for directory in directories {
            marker_contents.push_str(&format!("dir={}\n", directory.display()));
        }
        fs::write(&marker, marker_contents).unwrap();
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
        let marker_digest = format!("{:x}", Sha256::digest(fs::read(&marker).unwrap()));
        record["rescue_marker_digest"] = json!(marker_digest.clone());
        record["owned_files"].as_array_mut().unwrap().push(json!({
            "path": marker,
            "sha256": marker_digest,
            "mode": 0o600
        }));
        record["owned_files"]
            .as_array_mut()
            .unwrap()
            .sort_by(|left, right| {
                left["path"]
                    .as_str()
                    .unwrap()
                    .cmp(right["path"].as_str().unwrap())
            });
        record.as_object_mut().unwrap().remove("purge_authority");
        fs::write(
            self.ownership_path(),
            serde_json::to_vec_pretty(&record).unwrap(),
        )
        .unwrap();
        fs::set_permissions(self.ownership_path(), fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn package_source(&self) -> String {
        self.record()["pi_package_source"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn packages(&self) -> Vec<String> {
        let settings: Value =
            serde_json::from_slice(&fs::read(self.pi_agent_dir.join("settings.json")).unwrap())
                .unwrap();
        settings["packages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .or_else(|| entry["source"].as_str())
                    .unwrap()
                    .to_owned()
            })
            .collect()
    }

    fn set_packages(&self, packages: Vec<Value>) {
        fs::write(
            self.pi_agent_dir.join("settings.json"),
            serde_json::to_vec_pretty(&json!({ "packages": packages })).unwrap(),
        )
        .unwrap();
        fs::set_permissions(
            self.pi_agent_dir.join("settings.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }

    fn pi_log(&self) -> String {
        fs::read_to_string(&self.pi_log).unwrap_or_default()
    }
}

struct HerdrFixture<'a> {
    fixture: &'a ManagedFixture,
}

impl HerdrFixture<'_> {
    fn set_unregister_success_and_plugin_absent(&self) {
        fs::write(&self.fixture.herdr_control, "success|absent\n").unwrap();
    }

    fn set_unregister_success_and_plugin_list(&self, list: &str) {
        fs::write(&self.fixture.herdr_control, format!("success|{list}\n")).unwrap();
    }

    fn uninstall_call_count(&self) -> usize {
        fs::read_to_string(&self.fixture.herdr_log)
            .unwrap_or_default()
            .lines()
            .count()
    }
}

#[test]
fn cli_reports_the_manifest_version_for_release_validation() {
    let output = Command::new(env!("CARGO_BIN_EXE_herdr-a2a"))
        .arg("--version")
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("herdr-a2a {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn install_compatibility_preflight_rejects_every_mismatch_before_mutation() {
    // Break caught: install copied assets and mutated Pi before checking component/Pi interface
    // compatibility, then reported Ready even when `pi --version` was unusable.
    for (case, prepare) in [
        (
            "plugin",
            Box::new(|fixture: &ManagedFixture, _bundle: &Path| {
                fs::write(
                    fixture.plugin_root.join("herdr-plugin.toml"),
                    "version = \"9.8.7\"\n",
                )
                .unwrap();
            }) as Box<dyn Fn(&ManagedFixture, &Path)>,
        ),
        (
            "native",
            Box::new(|_fixture: &ManagedFixture, bundle: &Path| {
                let binary = bundle.join("bin/herdr-a2a");
                fs::write(
                    &binary,
                    "#!/bin/sh\n[ \"${1:-}\" = --version ] || exit 64\nprintf 'herdr-a2a 9.8.7\\n'\n",
                )
                .unwrap();
                fs::set_permissions(binary, fs::Permissions::from_mode(0o700)).unwrap();
            }),
        ),
        (
            "adapter",
            Box::new(|_fixture: &ManagedFixture, bundle: &Path| {
                let manifest = bundle.join("pi/package.json");
                let mut value: Value =
                    serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
                value["version"] = json!("9.8.7");
                fs::write(manifest, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
            }),
        ),
        (
            "typebox",
            Box::new(|_fixture: &ManagedFixture, bundle: &Path| {
                let manifest = bundle.join("pi/package.json");
                let mut value: Value =
                    serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
                value["peerDependencies"]["typebox"] = json!("*");
                fs::write(manifest, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
            }),
        ),
    ] {
        let fixture = ManagedFixture::new();
        let bundle = fixture.bundle(&format!("compat-{case}"), "adapter\n");
        prepare(&fixture, &bundle);
        let output = fixture.install(&bundle);

        assert_failure_code(&output, "incompatible_version");
        assert!(
            !fixture.stable_root().exists(),
            "{case} created managed state"
        );
        assert!(
            !fixture.plugin_root.join("libexec").exists(),
            "{case} published a helper"
        );
        assert!(fixture.packages().is_empty(), "{case} mutated Pi settings");
        assert!(
            !fixture
                .pi_log()
                .lines()
                .any(|line| line.starts_with("install ")),
            "{case} invoked Pi install"
        );
    }

    for version in ["0.84.1", "not-a-version"] {
        let fixture = ManagedFixture::new();
        let bundle = fixture.bundle(&format!("pi-{version}"), "adapter\n");
        let output = fixture
            .command()
            .env("HERDR_A2A_TEST_PI_VERSION", version)
            .args(["managed", "install", "--bundle"])
            .arg(&bundle)
            .output()
            .unwrap();

        assert_failure_code(&output, "incompatible_version");
        assert!(
            !fixture.stable_root().exists(),
            "Pi {version} created managed state"
        );
        assert!(!fixture.plugin_root.join("libexec").exists());
        assert!(fixture.packages().is_empty());
    }
}

#[test]
fn install_accepts_pi_newer_than_the_supported_minimum() {
    // Break caught: an artificial next-minor ceiling rejects a Pi release even when the adapter's
    // exercised extension contract remains compatible.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("pi-newer-than-minimum", "adapter\n");
    let output = fixture
        .command()
        .env("HERDR_A2A_TEST_PI_VERSION", "0.84.2")
        .args(["managed", "install", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(fixture.record()["state"], "Ready");
    assert_eq!(fixture.packages().len(), 1);
}

#[test]
fn repair_accepts_pi_newer_than_the_supported_minimum() {
    // Break caught: repair rejects an already Ready installation solely because Pi advanced to a
    // newer minor release, even though the exercised adapter contract remains compatible.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("repair-compat", "adapter\n");
    assert_success(&fixture.install(&bundle));
    let settings_before = fs::read(fixture.pi_agent_dir.join("settings.json")).unwrap();

    let output = fixture
        .command()
        .env("HERDR_A2A_TEST_PI_VERSION", "0.84.2")
        .args(["managed", "repair", "--startup"])
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(fixture.record()["state"], "Ready");
    assert_eq!(
        fs::read(fixture.pi_agent_dir.join("settings.json")).unwrap(),
        settings_before
    );
}

#[test]
fn fresh_install_hardens_the_owned_herdr_plugin_state_directory() {
    let fixture = ManagedFixture::new();
    fs::set_permissions(&fixture.plugin_state, fs::Permissions::from_mode(0o755)).unwrap();
    let unrelated = fixture.plugin_state.join("user-setting.json");
    fs::write(&unrelated, "preserve\n").unwrap();
    fs::set_permissions(&unrelated, fs::Permissions::from_mode(0o600)).unwrap();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");

    assert_success(&fixture.install(&bundle));

    assert_eq!(
        fs::symlink_metadata(&fixture.plugin_state)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(fs::read_to_string(unrelated).unwrap(), "preserve\n");
}

#[test]
fn fresh_install_hardens_the_owned_herdr_plugin_directory() {
    let fixture = ManagedFixture::new();
    fs::set_permissions(&fixture.plugin_root, fs::Permissions::from_mode(0o755)).unwrap();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");

    assert_success(&fixture.install(&bundle));

    assert_eq!(
        fs::symlink_metadata(&fixture.plugin_root)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}

#[test]
fn pi_relative_normalization_is_recorded_and_removed_exactly() {
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    let output = fixture
        .command()
        .env("HERDR_A2A_TEST_PI_MODE", "normalize_relative")
        .args(["managed", "install", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();

    assert_success(&output);
    let record = fixture.record();
    let entry = record["pi_package_entry"].as_str().unwrap();
    assert!(!Path::new(entry).is_absolute());
    assert_eq!(fixture.packages(), [entry]);

    fixture.herdr().set_unregister_success_and_plugin_absent();
    let output = fixture
        .command()
        .env("HERDR_A2A_TEST_PI_MODE", "normalize_relative")
        .args(["managed", "remove", "--skip-herdr-unregister"])
        .output()
        .unwrap();
    assert_success(&output);
    assert!(fixture.packages().is_empty());
}

#[test]
fn pre_task9_absolute_pi_ownership_repairs_updates_and_removes() {
    // Break caught: requiring only the newly derived settings-relative representation makes a
    // valid pre-Task-9 absolute ownership record unusable by repair, update, and removal.
    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    let installed = fixture
        .command()
        .env("HERDR_A2A_TEST_PI_MODE", "normalize_relative")
        .args(["managed", "install", "--bundle"])
        .arg(&first)
        .output()
        .unwrap();
    assert_success(&installed);

    let mut prior = fixture.record();
    let absolute_source = prior["pi_package_source"].as_str().unwrap().to_owned();
    prior["pi_package_entry"] = json!(absolute_source.clone());
    fs::write(
        fixture.ownership_path(),
        serde_json::to_vec_pretty(&prior).unwrap(),
    )
    .unwrap();
    fs::set_permissions(fixture.ownership_path(), fs::Permissions::from_mode(0o600)).unwrap();
    fixture.set_packages(vec![json!(absolute_source)]);

    assert_success(&fixture.repair());

    let second = fixture.bundle("2.0.0", "adapter two\n");
    assert_success(&fixture.install(&second));
    let updated = fixture.record();
    assert_eq!(
        updated["pi_package_entry"], updated["pi_package_source"],
        "ordinary Pi absolute persistence was not recorded exactly"
    );

    assert_success(&fixture.remove_after_exact_plugin_absence(false));
    assert!(fixture.packages().is_empty());
}

#[test]
fn pi_pending_repair_records_the_exact_absolute_entry_persisted_by_pi() {
    // Break caught: an install completed while Pi is absent precommits a relative entry, then
    // ordinary Pi appears and repair rejects its absolute persistence instead of owning it.
    let fixture = ManagedFixture::new();
    let pi = fixture.fake_bin.join("pi");
    let unavailable = fixture.fake_bin.join("pi-disabled");
    fs::rename(&pi, &unavailable).unwrap();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");

    let pending = fixture
        .command()
        .env("PATH", &fixture.fake_bin)
        .args(["managed", "install", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();
    assert_success(&pending);
    assert_eq!(fixture.record()["state"], "PiAdapterPending");
    fs::rename(&unavailable, &pi).unwrap();

    assert_success(&fixture.repair());
    let repaired = fixture.record();
    assert_eq!(repaired["state"], "Ready");
    assert_eq!(repaired["pi_package_entry"], repaired["pi_package_source"]);
    assert_eq!(fixture.packages(), [fixture.package_source()]);
}

#[test]
fn repair_adopts_the_exact_github_checkout_relocation_once() {
    // Break caught: Herdr builds a GitHub plugin in a private temporary checkout and atomically
    // moves that checkout into its managed store after the build succeeds. The first startup then
    // tried to inspect backup files under the vanished build path instead of authenticating and
    // recording the exact relocated helper and pointer.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));
    let prior_root = fixture.plugin_root.clone();
    let relocated_root = fixture
        .base
        .join("config/herdr/plugins/github/herdr.a2a-fixture/plugins/herdr");
    fs::create_dir_all(relocated_root.parent().unwrap()).unwrap();
    fs::rename(&prior_root, &relocated_root).unwrap();
    let config_parent = fixture.base.join("config");
    fs::set_permissions(&config_parent, fs::Permissions::from_mode(0o755)).unwrap();
    for directory in [
        fixture.base.join("config/herdr"),
        fixture.base.join("config/herdr/plugins"),
        fixture.base.join("config/herdr/plugins/github"),
        fixture
            .base
            .join("config/herdr/plugins/github/herdr.a2a-fixture"),
        fixture
            .base
            .join("config/herdr/plugins/github/herdr.a2a-fixture/plugins"),
    ] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o775)).unwrap();
    }

    let output = fixture
        .command()
        .env("HERDR_A2A_PLUGIN_ROOT", &relocated_root)
        .args(["managed", "repair", "--startup"])
        .output()
        .unwrap();

    assert_success(&output);
    let record = fixture.record();
    assert_eq!(record["plugin_root"], relocated_root.to_str().unwrap());
    let owned = record["owned_files"].as_array().unwrap();
    assert!(owned.iter().any(|entry| {
        entry["path"]
            == relocated_root
                .join("libexec/herdr-a2a-dispatch")
                .to_str()
                .unwrap()
    }));
    assert!(owned.iter().any(|entry| {
        entry["path"] == relocated_root.join("stable-bin-path").to_str().unwrap()
    }));
    assert!(owned.iter().all(|entry| {
        !entry["path"]
            .as_str()
            .unwrap()
            .starts_with(prior_root.to_str().unwrap())
    }));
    assert_eq!(
        fs::metadata(fixture.base.join("config/herdr/plugins/github"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert_eq!(
        fs::metadata(&relocated_root).unwrap().permissions().mode() & 0o777,
        0o700
    );

    let repeated = fixture
        .command()
        .env("HERDR_A2A_PLUGIN_ROOT", &relocated_root)
        .args(["managed", "repair", "--startup"])
        .output()
        .unwrap();
    assert_success(&repeated);
    assert_eq!(fixture.record(), record);
}

#[test]
fn real_herdr_pi_event_adopts_the_relocated_managed_root() {
    // Break caught: Herdr serializes pane.agent_detected with data.agent as a string. Treating
    // that value as an object made event repair report success without adopting the final root.
    let fixture = ManagedFixture::new();
    let transactional_root = fixture.transactional_plugin_root("event-123");
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install_from_plugin_root(&bundle, &transactional_root));
    let relocated_root = fixture
        .base
        .join("config/herdr/plugins/github/herdr.a2a-fixture/plugins/herdr");
    fs::create_dir_all(relocated_root.parent().unwrap()).unwrap();
    fs::rename(&transactional_root, &relocated_root).unwrap();

    let output = fixture
        .command()
        .env("HERDR_A2A_PLUGIN_ROOT", &relocated_root)
        .env("HERDR_A2A_TEST_HERDR_PLUGIN_ROOT", &relocated_root)
        .env(
            "HERDR_PLUGIN_EVENT_JSON",
            r#"{"event":"pane_agent_detected","data":{"pane_id":"w1:p1","workspace_id":"w1","agent":"pi","released":false}}"#,
        )
        .args(["managed", "repair", "--event"])
        .output()
        .unwrap();

    assert_success(&output);
    let record = fixture.record();
    assert_eq!(record["plugin_root"], relocated_root.to_str().unwrap());
    assert!(
        record["owned_files"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| {
                !entry["path"]
                    .as_str()
                    .unwrap()
                    .starts_with(transactional_root.to_str().unwrap())
            })
    );
}

#[test]
fn managed_remove_preserves_unowned_pi_configuration_and_durable_data() {
    // Break caught: broad Pi or stable-root cleanup removes a user package or retained workspace data.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));
    let owned_source = fixture.package_source();
    fixture.set_packages(vec![json!("user-package"), json!(owned_source.clone())]);
    let workspace = fixture.plugin_state.join("workspaces/scope with spaces");
    fs::create_dir_all(&workspace).unwrap();
    fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(workspace.join("tasks.sqlite3"), "durable\n").unwrap();
    fs::set_permissions(
        workspace.join("tasks.sqlite3"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    fixture.herdr().set_unregister_success_and_plugin_absent();
    let output = fixture.remove(false, false);
    assert_success(&output);

    assert_eq!(fixture.packages(), ["user-package"]);
    assert_eq!(
        fs::read_to_string(workspace.join("tasks.sqlite3")).unwrap(),
        "durable\n"
    );
    assert!(!Path::new(&owned_source).exists());
    assert_eq!(
        fs::read_to_string(&fixture.herdr_log).unwrap(),
        "uninstall\n"
    );
}

#[test]
fn reinstall_from_new_transaction_root_recovers_retained_durable_data() {
    // Break caught: Herdr runs every install from a new transactional checkout, but reinstall
    // rejected that new root before validating the prior Removed record and retained workspace.
    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&first));
    let retained = fixture
        .plugin_state
        .join("workspaces/retained/tasks.sqlite3");
    fs::create_dir_all(retained.parent().unwrap()).unwrap();
    fs::set_permissions(
        retained.parent().unwrap(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::write(&retained, "retained\n").unwrap();
    fs::set_permissions(&retained, fs::Permissions::from_mode(0o600)).unwrap();
    assert_success(&fixture.remove_after_exact_plugin_absence(false));
    assert_eq!(fixture.record()["state"], "Removed");

    let reinstall_root = fixture.transactional_plugin_root("123-456");
    let second = fixture.bundle("2.0.0", "adapter two\n");
    let output = fixture.install_from_plugin_root(&second, &reinstall_root);
    assert_success(&output);

    assert_eq!(fixture.record()["state"], "Ready");
    assert_eq!(
        fixture.record()["plugin_root"],
        reinstall_root.to_str().unwrap()
    );
    assert_eq!(fs::read_to_string(retained).unwrap(), "retained\n");
    assert_eq!(fixture.packages(), [fixture.package_source()]);
}

#[test]
fn reinstall_from_removed_rejects_unowned_rescue_residue() {
    // Break caught: Removed-record validation checked only formerly owned paths, so an unrelated
    // rescue entry survived reinstall and made the next managed removal permanently fail closed.
    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&first));
    assert_success(&fixture.remove_after_exact_plugin_absence(false));
    let rescue_directory = fixture.stable_root().join("rescue");
    fs::create_dir(&rescue_directory).unwrap();
    fs::set_permissions(&rescue_directory, fs::Permissions::from_mode(0o700)).unwrap();
    let residue = rescue_directory.join("unowned.txt");
    fs::write(&residue, "preserve\n").unwrap();
    fs::set_permissions(&residue, fs::Permissions::from_mode(0o600)).unwrap();

    let reinstall_root = fixture.transactional_plugin_root("residue-789");
    let second = fixture.bundle("2.0.0", "adapter two\n");
    let output = fixture.install_from_plugin_root(&second, &reinstall_root);

    assert_failure_code(&output, "ownership_conflict");
    assert_eq!(fixture.record()["state"], "Removed");
    assert_eq!(fs::read_to_string(&residue).unwrap(), "preserve\n");
}

#[test]
fn removed_managed_install_rejects_a_new_linked_development_root() {
    // Break caught: checking only the prior install kind let a new linked checkout claim a Removed
    // managed record merely by changing HERDR_A2A_PLUGIN_ROOT.
    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&first));
    assert_success(&fixture.remove_after_exact_plugin_absence(false));

    let linked_root = fixture.transactional_plugin_root("linked-123");
    let second = fixture.bundle("2.0.0", "adapter two\n");
    let output = fixture
        .command()
        .env("HERDR_A2A_PLUGIN_ROOT", &linked_root)
        .env("HERDR_A2A_TEST_HERDR_PLUGIN_ROOT", &linked_root)
        .env("HERDR_A2A_INSTALL_KIND", "linked-dev")
        .args(["managed", "install", "--bundle"])
        .arg(&second)
        .output()
        .unwrap();

    assert_failure_code(&output, "ownership_conflict");
    assert_eq!(fixture.record()["state"], "Removed");
}

#[test]
fn current_removed_reinstall_record_commit_interruption_rolls_back() {
    // Break caught: missing prior rescue snapshots identify both predecessor upgrades and current
    // reinstalls from Removed; treating both as predecessor forward commits changes current
    // transaction rollback semantics after a failed reinstall.
    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&first));
    assert_success(&fixture.remove_after_exact_plugin_absence(false));
    let removed_record = fs::read(fixture.ownership_path()).unwrap();

    let second = fixture.bundle("2.0.0", "adapter two\n");
    let interrupted = fixture
        .command()
        .env("HERDR_A2A_TEST_ABORT_AFTER_RECORD_RENAME", "1")
        .args(["managed", "install", "--bundle"])
        .arg(&second)
        .output()
        .unwrap();
    assert!(!interrupted.status.success());
    let journal_path = fixture.stable_root().join("install-transaction.json");
    let mut journal: Value = serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
    journal["phase"] = json!("RecordCommitting");
    fs::write(&journal_path, serde_json::to_vec_pretty(&journal).unwrap()).unwrap();
    fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(fixture.ownership_path(), &removed_record).unwrap();
    fs::set_permissions(fixture.ownership_path(), fs::Permissions::from_mode(0o600)).unwrap();

    assert_failure_code(&fixture.repair(), "already_removed");
    assert_eq!(fs::read(fixture.ownership_path()).unwrap(), removed_record);
    assert_eq!(fixture.record()["state"], "Removed");
    assert!(fixture.packages().is_empty());
    assert!(!journal_path.exists());
}

#[test]
fn managed_remove_without_purge_never_claims_the_recorded_state_root() {
    // Break caught: recording purge authority accidentally makes retained state a required asset.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));
    fs::remove_dir(&fixture.plugin_state).unwrap();

    let output = fixture.remove_after_exact_plugin_absence(false);

    assert_success(&output);
}

#[test]
fn managed_remove_accepts_a_fully_validated_schema_v2_record_without_purge() {
    // Break caught: adding v3-only fields strands the immediately preceding managed install.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));
    fixture.downgrade_record_to_schema_v2();

    let output = fixture.remove_after_exact_plugin_absence(false);

    assert_success(&output);
}

#[test]
fn current_binary_authoritative_schema_v2_remove_and_purge_succeed() {
    // Break caught: splitting fixed historical classification evidence from process identity
    // could accidentally strand the production current-binary remove or purge path.
    for purge in [false, true] {
        let fixture = ManagedFixture::new();
        let bundle = fixture.bundle("1.0.0", "adapter one\n");
        assert_success(&fixture.install(&bundle));
        fixture.downgrade_current_record_to_authoritative_schema_v2();
        let state_file = fixture.plugin_state.join("authoritative-v2-state");
        fs::write(&state_file, "owned state\n").unwrap();
        fs::set_permissions(&state_file, fs::Permissions::from_mode(0o600)).unwrap();

        let output = fixture.remove_after_exact_plugin_absence(purge);

        assert_success(&output);
        assert_eq!(fixture.record_state(), "Removed");
        if purge {
            assert!(!fixture.plugin_state.exists());
        } else {
            assert_eq!(fs::read_to_string(&state_file).unwrap(), "owned state\n");
        }
    }
}

#[test]
fn managed_remove_accepts_exact_round2_schema_v3_rescue_helper_inventory() {
    // Break caught: removing the legacy helper from the current expected multiset strands the
    // exact schema-v3 installation emitted by the immediately preceding release.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));
    fixture.rewrite_record_as_round2_schema_v3_with_rescue_helper();

    let output = fixture.remove_after_exact_plugin_absence(false);

    assert_success(&output);
    assert!(
        !fixture
            .stable_root()
            .join("rescue/herdr-a2a-rescue")
            .exists()
    );
}

#[test]
fn managed_update_migrates_schema_v2_to_v3_without_executable_backup_code() {
    // Break caught: update either rejects v2 or publishes an unauthenticated backup executable.
    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    let second = fixture.bundle("1.0.1", "adapter two\n");
    assert_success(&fixture.install(&first));
    fixture.downgrade_record_to_schema_v2();

    let output = fixture.install(&second);

    assert_success(&output);
    let record = fixture.record();
    assert_eq!(record["schema_version"], 3);
    assert_eq!(record["purge_authority"], false);
    assert!(
        !fixture
            .stable_root()
            .join("rescue/herdr-a2a-rescue")
            .exists()
    );
    let rescue = fs::read_to_string(fixture.stable_root().join("rescue/uninstall.sh")).unwrap();
    assert!(!rescue.contains("__HERDR_A2A_MANAGED_BINARY_LITERAL__"));
}

#[test]
fn managed_update_retires_exact_round2_rescue_helper_into_source_only_notice() {
    // Break caught: accepting the predecessor inventory without an authenticated migration leaves
    // its executable helper unrecorded and prevents later expected-empty rescue removal.
    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    let second = fixture.bundle("1.0.1", "adapter two\n");
    assert_success(&fixture.install(&first));
    fixture.rewrite_record_as_round2_schema_v3_with_rescue_helper();

    let output = fixture.install(&second);

    assert_success(&output);
    let record = fixture.record();
    let helper = fixture.stable_root().join("rescue/herdr-a2a-rescue");
    let rescue = fixture.stable_root().join("rescue/uninstall.sh");
    assert!(!helper.exists());
    assert_eq!(fs::symlink_metadata(&rescue).unwrap().mode() & 0o777, 0o600);
    assert!(
        record["owned_files"]
            .as_array()
            .unwrap()
            .iter()
            .all(|owned| owned["path"] != helper.to_str().unwrap())
    );
}

#[test]
fn round2_rescue_helper_drift_or_absence_fails_closed_before_migration() {
    // Break caught: recognizing the legacy helper path without proving its exact digest lets
    // attacker-controlled executable bytes cross the migration/removal ownership boundary.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));
    fixture.rewrite_record_as_round2_schema_v3_with_rescue_helper();
    let helper = fixture.stable_root().join("rescue/herdr-a2a-rescue");
    let source = fixture.package_source();
    let packages = fixture.packages();

    fs::write(&helper, "tampered helper\n").unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
    let modified = fixture.repair();
    assert_failure_code(&modified, "owned_asset_modified");
    assert_eq!(fs::read_to_string(&helper).unwrap(), "tampered helper\n");
    assert!(Path::new(&source).is_dir());
    assert_eq!(fixture.packages(), packages);

    fs::remove_file(&helper).unwrap();
    let missing = fixture.repair();
    assert!(!missing.status.success());
    assert!(Path::new(&source).is_dir());
    assert_eq!(fixture.packages(), packages);
    assert!(!fixture.stable_root().join("rescue-migration.json").exists());
}

#[test]
fn managed_repair_accepts_a_fully_validated_schema_v2_record() {
    // Break caught: repair deserialization required fields that did not exist in schema v2.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));
    fixture.downgrade_record_to_schema_v2();

    let output = fixture.repair();

    assert_success(&output);
    assert_eq!(fixture.record()["schema_version"], 2);
}

#[test]
fn managed_repair_retires_exact_round2_rescue_helper_into_source_only_notice() {
    // Break caught: repair accepts the legacy record but leaves its executable rescue helper as
    // persistent authenticated code instead of completing the bounded migration.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));
    fixture.rewrite_record_as_round2_schema_v3_with_rescue_helper();

    let output = fixture.repair();

    assert_success(&output);
    let helper = fixture.stable_root().join("rescue/herdr-a2a-rescue");
    let rescue = fixture.stable_root().join("rescue/uninstall.sh");
    assert!(!helper.exists());
    assert_eq!(fs::symlink_metadata(rescue).unwrap().mode() & 0o777, 0o600);
}

#[test]
fn interrupted_rescue_migration_recovers_exactly_before_repair_resumes() {
    // Break caught: a crash after moving the authenticated legacy rescue directory leaves neither
    // the old record nor the new notice usable unless the durable swap journal restores it.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));
    fixture.rewrite_record_as_round2_schema_v3_with_rescue_helper();

    let interrupted = fixture
        .command()
        .env("HERDR_A2A_TEST_ABORT_AFTER_RESCUE_BACKUP_RENAME", "1")
        .args(["managed", "repair", "--startup"])
        .output()
        .unwrap();
    assert!(
        !interrupted.status.success(),
        "migration fault did not abort"
    );
    assert!(
        fixture
            .stable_root()
            .join("rescue-migration.json")
            .is_file()
    );

    assert_success(&fixture.repair());
    assert!(
        !fixture
            .stable_root()
            .join("rescue/herdr-a2a-rescue")
            .exists()
    );
    assert_eq!(
        fs::symlink_metadata(fixture.stable_root().join("rescue/uninstall.sh"))
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
    assert!(!fixture.stable_root().join("rescue-migration.json").exists());
}

#[test]
fn rescue_migration_real_crashes_recover_across_intent_publication_and_cleanup() {
    // Break caught: rescue migration published unjournaled stage entries and required complete
    // stage snapshots after sequential cleanup, so a crash could leave permanent managed debris.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));

    let crash_at = |boundary: &str| {
        fixture
            .command()
            .env("HERDR_A2A_TEST_ABORT_RESCUE_MIGRATION", boundary)
            .args(["managed", "repair", "--startup"])
            .output()
            .unwrap()
    };
    let assert_recovered = || {
        let rescue = fixture.stable_root().join("rescue/uninstall.sh");
        assert_eq!(fs::symlink_metadata(&rescue).unwrap().mode() & 0o777, 0o600);
        assert!(
            !fixture
                .stable_root()
                .join("rescue/herdr-a2a-rescue")
                .exists()
        );
        assert!(!fixture.stable_root().join("rescue-migration.json").exists());
        let residual: Vec<_> = fs::read_dir(fixture.stable_root())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| {
                let name = name.to_string_lossy();
                name.starts_with(".rescue-migration-stage-")
                    || name.starts_with(".rescue-migration-backup-")
            })
            .collect();
        assert!(
            residual.is_empty(),
            "migration debris remained: {residual:?}"
        );
    };

    for boundary in ["intent-published", "notice-renamed", "backup-cleanup-2"] {
        eprintln!("real rescue migration crash boundary: {boundary}");
        fixture.rewrite_record_as_round2_schema_v3_with_rescue_helper();
        let interrupted = crash_at(boundary);
        assert!(
            !interrupted.status.success(),
            "migration boundary {boundary} did not abort"
        );
        assert!(
            fixture
                .stable_root()
                .join("rescue-migration.json")
                .is_file()
        );
        assert_success(&fixture.repair());
        assert_recovered();
    }
}

#[test]
fn rescue_migration_journal_temp_crashes_recover_only_the_authenticated_temp() {
    // Break caught: a crash after syncing a random journal temporary but before rename left an
    // unauthenticated sibling that every later managed operation refused without a safe recovery
    // path. Recovery must identify one exact deterministic temporary from durable migration
    // authority, preserve every other sibling, and remain idempotent.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));

    for (boundary, add_unowned_sibling) in [
        ("journal-temp-intent", true),
        ("journal-temp-prepared", false),
    ] {
        fixture.rewrite_record_as_round2_schema_v3_with_rescue_helper();
        let interrupted = fixture
            .command()
            .env("HERDR_A2A_TEST_ABORT_RESCUE_MIGRATION", boundary)
            .args(["managed", "repair", "--startup"])
            .output()
            .unwrap();
        assert!(
            !interrupted.status.success(),
            "journal publication boundary {boundary} did not abort"
        );

        let journal_temps: Vec<_> = fs::read_dir(fixture.stable_root())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".rescue-migration-journal-")
            })
            .collect();
        assert_eq!(journal_temps.len(), 1, "expected one exact journal temp");

        let unowned = fixture
            .stable_root()
            .join(format!(".rescue-migration-journal-{}", "f".repeat(32)));
        if add_unowned_sibling {
            assert_ne!(journal_temps[0], unowned);
            let authenticated_bytes = fs::read(&journal_temps[0]).unwrap();
            fs::write(&journal_temps[0], b"inexact\n").unwrap();
            let inexact = fixture.repair();
            assert_failure_code(&inexact, "recovery_needed");
            assert_eq!(fs::read(&journal_temps[0]).unwrap(), b"inexact\n");
            fs::write(&journal_temps[0], authenticated_bytes).unwrap();
            fs::set_permissions(&journal_temps[0], fs::Permissions::from_mode(0o600)).unwrap();

            fs::write(&unowned, b"unowned\n").unwrap();
            fs::set_permissions(&unowned, fs::Permissions::from_mode(0o600)).unwrap();

            let blocked = fixture.repair();
            assert_failure_code(&blocked, "recovery_needed");
            assert!(!journal_temps[0].exists(), "authenticated temp remained");
            assert_eq!(fs::read_to_string(&unowned).unwrap(), "unowned\n");

            fs::remove_file(&unowned).unwrap();
        }

        assert_success(&fixture.repair());
        assert_success(&fixture.repair());
        assert!(!fixture.stable_root().join("rescue-migration.json").exists());
        assert!(!journal_temps[0].exists());
    }
}

#[test]
fn managed_repair_rewrites_schema_v2_without_adding_v3_purge_fields() {
    // Break caught: a repair state transition serialized the internal false purge flag into v2,
    // making the next exact compatibility read reject the record it had just written.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));
    fixture.downgrade_record_to_schema_v2();
    let mut record = fixture.record();
    record["state"] = json!("PiAdapterPending");
    fs::write(
        fixture.ownership_path(),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();

    assert_success(&fixture.repair());

    let rewritten = fixture.record();
    assert_eq!(rewritten["schema_version"], 2);
    assert!(rewritten.get("purge_authority").is_none());
    assert!(rewritten.get("plugin_state_root").is_none());
    assert_success(&fixture.status_json());
}

#[test]
fn managed_remove_schema_v2_purge_never_derives_authority_from_the_environment() {
    // Break caught: a v2 record has no authenticated state root, so the ambient value is not proof.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));
    fixture.downgrade_record_to_schema_v2();
    fs::write(fixture.plugin_state.join("keep.txt"), "keep\n").unwrap();

    let output = fixture.remove(true, true);

    assert_failure_code(&output, "unsafe_owned_state");
    assert_eq!(
        fs::read_to_string(fixture.plugin_state.join("keep.txt")).unwrap(),
        "keep\n"
    );
}

#[test]
fn authority_bearing_schema_v2_records_migrate_without_losing_purge_authority() {
    // Break caught: release metadata drift made a fixed historical record impersonate the current
    // installation, or current schema-2 migration dropped its authenticated purge authority.
    let fixture = ManagedFixture::new();
    fixture.materialize_authoritative_schema_v2_literal_for_matrix();
    let historical_record = fixture.record();
    let mut migrated_historical_record = historical_record.clone();
    migrated_historical_record["schema_version"] = json!(OWNERSHIP_SCHEMA);
    let historical_pi = fs::read(fixture.pi_agent_dir.join("settings.json")).unwrap();
    let incompatible = fixture.repair();
    assert_failure_code(&incompatible, "incompatible_version");
    assert_eq!(fixture.record(), migrated_historical_record);
    assert_eq!(
        fixture.record()["plugin_state_root"],
        historical_record["plugin_state_root"]
    );
    assert_eq!(
        fixture.record()["rescue_marker_digest"],
        historical_record["rescue_marker_digest"]
    );
    assert_eq!(
        fs::read(fixture.pi_agent_dir.join("settings.json")).unwrap(),
        historical_pi
    );

    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&first));
    fixture.downgrade_current_record_to_authoritative_schema_v2();
    let original = fixture.record();
    let root = original["plugin_state_root"].clone();
    let marker_digest = original["rescue_marker_digest"].clone();
    assert_success(&fixture.repair());
    let repaired = fixture.record();
    assert_eq!(repaired["schema_version"], OWNERSHIP_SCHEMA);
    assert_eq!(repaired["purge_authority"], true);
    assert_eq!(repaired["plugin_state_root"], root);
    assert_eq!(repaired["rescue_marker_digest"], marker_digest);

    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    let second = fixture.bundle("1.0.1", "adapter two\n");
    assert_success(&fixture.install(&first));
    fixture.downgrade_current_record_to_authoritative_schema_v2();
    let original = fixture.record();
    assert_success(&fixture.install(&second));
    let updated = fixture.record();
    assert_eq!(updated["schema_version"], OWNERSHIP_SCHEMA);
    assert_eq!(updated["purge_authority"], true);
    assert_eq!(updated["plugin_state_root"], original["plugin_state_root"]);
    assert_ne!(
        updated["rescue_marker_digest"], original["rescue_marker_digest"],
        "the update must authenticate its newly materialized owned bytes, not preserve the historical marker"
    );
    assert_eq!(
        format!(
            "{:x}",
            Sha256::digest(fs::read(fixture.stable_root().join("rescue/owner-v1")).unwrap())
        ),
        updated["rescue_marker_digest"].as_str().unwrap(),
        "the updated marker must authenticate the update's materialized ownership"
    );

    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&first));
    fixture.downgrade_current_record_to_authoritative_schema_v2();
    let removed = fixture.remove_after_exact_plugin_absence(false);
    assert_success(&removed);
    assert_eq!(fixture.record()["state"], "Removed");
    assert!(fixture.plugin_state.is_dir());

    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&first));
    fixture.downgrade_current_record_to_authoritative_schema_v2();
    let owned_state = fixture.plugin_state.join("owned-state.txt");
    fs::write(&owned_state, "owned\n").unwrap();
    fs::set_permissions(&owned_state, fs::Permissions::from_mode(0o600)).unwrap();
    let purged = fixture.remove_after_exact_plugin_absence(true);
    assert_success(&purged);
    assert_eq!(fixture.record()["state"], "Removed");
    assert!(!fixture.plugin_state.exists());

    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&first));
    fixture.downgrade_current_record_to_authoritative_schema_v2();
    let record_before = fs::read(fixture.ownership_path()).unwrap();
    let pi_before = fs::read(fixture.pi_agent_dir.join("settings.json")).unwrap();
    let state_before = fs::read_dir(&fixture.plugin_state)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<BTreeSet<_>>();
    let interrupted = fixture
        .command()
        .env("HERDR_A2A_TEST_FAIL_BEFORE_RECORD_COMMIT", "1")
        .args(["managed", "repair", "--startup"])
        .output()
        .unwrap();
    assert_failure_code(&interrupted, "ownership_commit_failed");
    assert_eq!(fs::read(fixture.ownership_path()).unwrap(), record_before);
    assert_eq!(
        fs::read(fixture.pi_agent_dir.join("settings.json")).unwrap(),
        pi_before
    );
    assert_eq!(
        fs::read_dir(&fixture.plugin_state)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<BTreeSet<_>>(),
        state_before
    );
    assert_success(&fixture.repair());
    assert_eq!(fixture.record()["schema_version"], OWNERSHIP_SCHEMA);

    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&first));
    fixture.downgrade_current_record_to_authoritative_schema_v2();
    let interrupted = fixture
        .command()
        .env("HERDR_A2A_TEST_ABORT_AFTER_RECORD_RENAME", "1")
        .args(["managed", "repair", "--startup"])
        .output()
        .unwrap();
    assert!(!interrupted.status.success());
    assert_eq!(fixture.record()["schema_version"], OWNERSHIP_SCHEMA);
    assert_success(&fixture.repair());
}

#[test]
fn schema_v2_partial_authority_never_enables_purge() {
    // Break caught: a partial or contradictory schema-2 record could reach record migration or
    // purge setup before its complete historical authority proof was rejected.
    for mutation in [
        "false_with_root",
        "true_without_root",
        "true_without_marker",
        "wrong_marker_digest",
        "nonprivate_root",
        "root_path_relationship_mismatch",
        "incomplete_inventory",
        "changed_pi_entry",
        "changed_helper",
        "changed_pointer",
        "malformed_digest",
        "unknown_field",
    ] {
        let fixture = ManagedFixture::new();
        fixture.materialize_authoritative_schema_v2_literal_for_matrix();

        let mut record = fixture.record();
        match mutation {
            "false_with_root" => record["purge_authority"] = json!(false),
            "true_without_root" => {
                record.as_object_mut().unwrap().remove("plugin_state_root");
            }
            "true_without_marker" => {
                record
                    .as_object_mut()
                    .unwrap()
                    .remove("rescue_marker_digest");
            }
            "wrong_marker_digest" => record["rescue_marker_digest"] = json!("0".repeat(64)),
            "nonprivate_root" => {
                fs::set_permissions(&fixture.plugin_state, fs::Permissions::from_mode(0o755))
                    .unwrap();
            }
            "root_path_relationship_mismatch" => {
                record["plugin_state_root"] = json!(fixture.stable_root());
            }
            "incomplete_inventory" => {
                record["owned_files"].as_array_mut().unwrap().pop();
            }
            "changed_pi_entry" => {
                let mut settings: Value = serde_json::from_slice(
                    &fs::read(fixture.pi_agent_dir.join("settings.json")).unwrap(),
                )
                .unwrap();
                settings["packages"].as_array_mut().unwrap().push(json!({
                    "source": record["pi_package_source"].clone()
                }));
                fs::write(
                    fixture.pi_agent_dir.join("settings.json"),
                    serde_json::to_vec_pretty(&settings).unwrap(),
                )
                .unwrap();
            }
            "changed_helper" => {
                let helper = fixture.plugin_root.join("libexec/herdr-a2a-dispatch");
                record["owned_files"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|owned| owned["path"].as_str() == helper.to_str())
                    .unwrap()["path"] = json!(fixture.plugin_root.join("libexec/not-herdr-a2a"));
            }
            "changed_pointer" => {
                let pointer = fixture.plugin_root.join("stable-bin-path");
                record["owned_files"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|owned| owned["path"].as_str() == pointer.to_str())
                    .unwrap()["path"] = json!(fixture.plugin_root.join("not-stable-bin-path"));
            }
            "malformed_digest" => record["broker_digest"] = json!("not-a-digest"),
            "unknown_field" => record["unrecognized_authority_field"] = json!(true),
            _ => unreachable!(),
        }
        fs::write(
            fixture.ownership_path(),
            serde_json::to_vec_pretty(&record).unwrap(),
        )
        .unwrap();
        fs::set_permissions(fixture.ownership_path(), fs::Permissions::from_mode(0o600)).unwrap();
        let record_before = fs::read(fixture.ownership_path()).unwrap();
        let pi_before = fs::read(fixture.pi_agent_dir.join("settings.json")).unwrap();
        let state_before = fs::read_dir(&fixture.plugin_state)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<BTreeSet<_>>();

        let output = fixture.remove(true, true);

        assert_failure_code_one_of(&output, &["ownership_record_invalid", "ownership_conflict"]);
        assert_eq!(
            fs::read(fixture.ownership_path()).unwrap(),
            record_before,
            "{mutation} rewrote the rejected ownership record"
        );
        assert_eq!(
            fs::read(fixture.pi_agent_dir.join("settings.json")).unwrap(),
            pi_before,
            "{mutation} rewrote Pi settings"
        );
        assert_eq!(
            fs::read_dir(&fixture.plugin_state)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<BTreeSet<_>>(),
            state_before,
            "{mutation} changed the recorded state root"
        );
        assert!(
            fixture.plugin_state.is_dir(),
            "{mutation} purged a rejected root"
        );
    }
}

#[test]
fn authoritative_schema_v2_journal_requires_an_exact_v3_migration_adjacent_record() {
    // Break caught: recovery accepted an authoritative v2 prior record and a different v3 update
    // record, which would make a migration journal authorize more than a schema-only rewrite.
    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    let second = fixture.bundle("1.0.1", "adapter two\n");
    assert_success(
        &fixture
            .command()
            .env("HERDR_A2A_TEST_PI_MODE", "normalize_relative")
            .args(["managed", "install", "--bundle"])
            .arg(&first)
            .output()
            .unwrap(),
    );
    let interrupted = fixture
        .command()
        .env("HERDR_A2A_TEST_PI_MODE", "normalize_relative")
        .env("HERDR_A2A_TEST_ABORT_AFTER_RECORD_RENAME", "1")
        .args(["managed", "install", "--bundle"])
        .arg(&second)
        .output()
        .unwrap();
    assert!(!interrupted.status.success());

    let journal_path = fixture.stable_root().join("install-transaction.json");
    let mut journal: Value = serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
    let observed_pi_entry = fixture.record()["pi_package_entry"].clone();
    journal["prior_record"]["schema_version"] = json!(2);
    journal["new_pi_entry"] = observed_pi_entry.clone();
    journal["new_record"]["pi_package_entry"] = observed_pi_entry;
    fs::write(&journal_path, serde_json::to_vec_pretty(&journal).unwrap()).unwrap();
    fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();
    let journal_before = fs::read(&journal_path).unwrap();
    let record_before = fs::read(fixture.ownership_path()).unwrap();
    let pi_before = fs::read(fixture.pi_agent_dir.join("settings.json")).unwrap();

    let recovered = fixture.repair();

    assert_failure_code(&recovered, "recovery_needed");
    assert!(
        String::from_utf8_lossy(&recovered.stderr).contains(
            "authoritative schema v2 transaction records are not an exact schema v3 migration"
        ),
        "recovery did not reach the exact v2-to-v3 adjacency guard: {}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert_eq!(fs::read(&journal_path).unwrap(), journal_before);
    assert_eq!(fs::read(fixture.ownership_path()).unwrap(), record_before);
    assert_eq!(
        fs::read(fixture.pi_agent_dir.join("settings.json")).unwrap(),
        pi_before
    );
}

#[test]
fn authoritative_schema_v2_new_journal_endpoint_is_rejected_before_recovery_mutation() {
    // Break caught: transaction validation considered only the prior endpoint, allowing an
    // authority-bearing schema-2 new record to bypass ordered v2-to-v3 migration validation.
    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    let second = fixture.bundle("1.0.1", "adapter two\n");
    assert_success(
        &fixture
            .command()
            .env("HERDR_A2A_TEST_PI_MODE", "normalize_relative")
            .args(["managed", "install", "--bundle"])
            .arg(&first)
            .output()
            .unwrap(),
    );
    let interrupted = fixture
        .command()
        .env("HERDR_A2A_TEST_PI_MODE", "normalize_relative")
        .env("HERDR_A2A_TEST_ABORT_AFTER_RECORD_RENAME", "1")
        .args(["managed", "install", "--bundle"])
        .arg(&second)
        .output()
        .unwrap();
    assert!(!interrupted.status.success());

    let journal_path = fixture.stable_root().join("install-transaction.json");
    let mut journal: Value = serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
    let observed_pi_entry = fixture.record()["pi_package_entry"].clone();
    journal["new_pi_entry"] = observed_pi_entry.clone();
    journal["new_record"]["pi_package_entry"] = observed_pi_entry;
    journal["new_record"]["schema_version"] = json!(2);
    fs::write(&journal_path, serde_json::to_vec_pretty(&journal).unwrap()).unwrap();
    fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();
    let journal_before = fs::read(&journal_path).unwrap();
    let record_before = fs::read(fixture.ownership_path()).unwrap();
    let pi_before = fs::read(fixture.pi_agent_dir.join("settings.json")).unwrap();

    let recovered = fixture.repair();

    assert_failure_code(&recovered, "recovery_needed");
    assert!(
        String::from_utf8_lossy(&recovered.stderr).contains(
            "authoritative schema v2 transaction records are not an exact schema v3 migration"
        ),
        "recovery did not reach the ordered endpoint guard: {}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert_eq!(fs::read(&journal_path).unwrap(), journal_before);
    assert_eq!(fs::read(fixture.ownership_path()).unwrap(), record_before);
    assert_eq!(
        fs::read(fixture.pi_agent_dir.join("settings.json")).unwrap(),
        pi_before
    );
}

#[test]
fn schema_v2_update_cannot_launder_an_ambient_directory_into_purge_authority() {
    // Break caught: updating v2 copied the current environment path into authenticated v3 state.
    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    let second = fixture.bundle("1.0.1", "adapter two\n");
    let third = fixture.bundle("1.0.2", "adapter three\n");
    assert_success(&fixture.install(&first));
    fixture.downgrade_record_to_schema_v2();
    let unrelated = fixture.base.join("unrelated private purge target");
    fs::create_dir(&unrelated).unwrap();
    fs::set_permissions(&unrelated, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(unrelated.join("keep.txt"), "keep\n").unwrap();

    let migrated = fixture
        .command()
        .env("HERDR_PLUGIN_STATE_DIR", &unrelated)
        .args(["managed", "install", "--bundle"])
        .arg(&second)
        .output()
        .unwrap();
    assert_success(&migrated);
    assert_eq!(fixture.record()["schema_version"], 3);
    assert_eq!(fixture.record()["purge_authority"], false);
    assert!(fixture.record().get("plugin_state_root").is_none());

    let repeated = fixture
        .command()
        .env("HERDR_PLUGIN_STATE_DIR", &unrelated)
        .args(["managed", "install", "--bundle"])
        .arg(&third)
        .output()
        .unwrap();
    assert_success(&repeated);
    assert_eq!(fixture.record()["purge_authority"], false);
    assert!(fixture.record().get("plugin_state_root").is_none());

    let purge = fixture
        .command()
        .env("HERDR_PLUGIN_STATE_DIR", &unrelated)
        .args(["managed", "remove", "--purge", "--skip-herdr-unregister"])
        .output()
        .unwrap();
    assert_failure_code(&purge, "unsafe_owned_state");
    assert_eq!(
        fs::read_to_string(unrelated.join("keep.txt")).unwrap(),
        "keep\n"
    );
}

#[test]
fn source_only_rescue_fails_closed_without_starting_an_interpreter_or_disclosing_a_path() {
    // Break caught: an executable shebang loads hostile Linux LD_PRELOAD/LD_AUDIT code before
    // Bash can clear its environment, and its error disclosed the exact managed binary path.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));
    let record = fixture.record();
    let stable_binary = PathBuf::from(record["stable_binary"].as_str().unwrap());
    let rescue = fixture.stable_root().join("rescue/uninstall.sh");
    let owned_source = fixture.package_source();
    let hostile_env = fixture.fake_bin.join("hostile-bash-env");
    let hostile_log = fixture.base.join("hostile bootstrap.log");
    fs::write(
        &hostile_env,
        "printf '%s\\n' injected >> \"$HERDR_A2A_TEST_BOOTSTRAP_LOG\"\n",
    )
    .unwrap();
    fs::remove_file(&stable_binary).unwrap();

    assert_eq!(
        fs::symlink_metadata(&rescue).unwrap().mode() & 0o777,
        0o600,
        "the kernel must reject direct execution before loading an interpreter"
    );
    let direct = fixture
        .command_with_program(&rescue)
        .env("LD_PRELOAD", fixture.fake_bin.join("hostile-loader"))
        .output()
        .expect_err("a source-only notice must not be executable");
    assert_eq!(direct.kind(), std::io::ErrorKind::PermissionDenied);

    let output = fixture
        .command_with_program(Path::new("/bin/bash"))
        .args([
            "-p",
            "-c",
            "export BASH_ENV=$2 ENV=$2 LD_PRELOAD=$3 HERDR_A2A_TEST_BOOTSTRAP_LOG=$4; . \"$1\" --skip-herdr-unregister",
            "herdr-a2a-rescue-source",
        ])
        .arg(&rescue)
        .arg(&hostile_env)
        .arg(fixture.fake_bin.join("hostile-loader"))
        .arg(&hostile_log)
        .output()
        .unwrap();

    assert_failure_code(&output, "rescue_unavailable");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains(stable_binary.to_str().unwrap()));
    assert!(!stderr.contains(fixture.base.to_str().unwrap()));
    assert!(stderr.len() <= 512);
    assert!(fixture.ownership_path().is_file());
    assert!(Path::new(&owned_source).is_dir());
    assert_eq!(fixture.packages(), [owned_source]);
    assert!(
        !fixture
            .stable_root()
            .join("rescue/herdr-a2a-rescue")
            .exists()
    );
    assert!(!hostile_log.exists());
}

#[test]
fn managed_remove_has_stable_fail_closed_outcomes() {
    // Break caught: absent ownership or asset drift widens removal authority, and a second run mutates again.
    let second = ManagedFixture::new();
    let bundle = second.bundle("1.0.0", "adapter one\n");
    assert_success(&second.install(&bundle));
    assert_success(&second.remove_after_exact_plugin_absence(false));
    assert_failure_code(&second.remove(false, true), "already_removed");

    let modified = ManagedFixture::new();
    let bundle = modified.bundle("1.0.0", "adapter one\n");
    assert_success(&modified.install(&bundle));
    fs::write(
        PathBuf::from(modified.package_source()).join("extensions/herdr-a2a.ts"),
        "modified\n",
    )
    .unwrap();
    assert_failure_code(&modified.remove(false, true), "owned_asset_modified");

    let missing = ManagedFixture::new();
    assert_failure_code(&missing.remove(false, true), "ownership_record_missing");
}

#[test]
fn managed_remove_purge_rejects_a_symlinked_owned_state_root() {
    // Break caught: purge follows HERDR_PLUGIN_STATE_DIR to delete data outside the proved owned root.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));
    let unrelated = fixture.base.join("unrelated durable data");
    fs::create_dir(&unrelated).unwrap();
    fs::write(unrelated.join("keep.txt"), "keep\n").unwrap();
    let redirected = fixture.base.join("redirected plugin state");
    symlink(&unrelated, &redirected).unwrap();

    let output = fixture
        .command()
        .env("HERDR_PLUGIN_STATE_DIR", &redirected)
        .args(["managed", "remove", "--purge", "--skip-herdr-unregister"])
        .output()
        .unwrap();
    assert_failure_code(&output, "unsafe_owned_state");
    assert_eq!(
        fs::read_to_string(unrelated.join("keep.txt")).unwrap(),
        "keep\n"
    );
}

#[test]
fn managed_remove_purge_rejects_an_unrecorded_private_state_root_before_mutation() {
    // Break caught: the current environment supplies purge authority for an unrelated private tree.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));
    let owned_source = fixture.package_source();
    let unrelated = fixture.base.join("unrelated private state");
    fs::create_dir(&unrelated).unwrap();
    fs::set_permissions(&unrelated, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(unrelated.join("keep.txt"), "keep\n").unwrap();

    let output = fixture
        .command()
        .env("HERDR_PLUGIN_STATE_DIR", &unrelated)
        .args(["managed", "remove", "--purge", "--skip-herdr-unregister"])
        .output()
        .unwrap();

    assert_failure_code(&output, "unsafe_owned_state");
    assert_eq!(
        fs::read_to_string(unrelated.join("keep.txt")).unwrap(),
        "keep\n"
    );
    assert!(Path::new(&owned_source).exists());
    assert_eq!(fixture.packages(), [owned_source]);
}

#[test]
fn managed_remove_purge_preflights_depth_before_any_removal_mutation() {
    // Break caught: an unbounded purge tree is discovered only after Pi and exact assets are removed.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));
    let owned_source = fixture.package_source();
    let mut deep = fixture.plugin_state.clone();
    for index in 0..65 {
        deep.push(format!("level-{index}"));
        fs::create_dir(&deep).unwrap();
        fs::set_permissions(&deep, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(deep.join("keep.txt"), "keep\n").unwrap();

    let output = fixture.remove(true, true);

    assert_failure_code(&output, "unsafe_owned_state");
    assert_eq!(fs::read_to_string(deep.join("keep.txt")).unwrap(), "keep\n");
    assert!(Path::new(&owned_source).exists());
    assert_eq!(fixture.packages(), [owned_source]);
}

#[test]
fn purge_resumes_after_crash_immediately_after_authenticated_root_deletion() {
    // Break caught: purge authority existed only in memory, so a crash after exact root deletion
    // made the same authorized command fail forever because the root was now absent.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("purge-resume", "adapter\n");
    assert_success(&fixture.install(&bundle));
    let purge_root = PathBuf::from(fixture.record()["plugin_state_root"].as_str().unwrap());
    fs::create_dir_all(&purge_root).unwrap();
    fs::set_permissions(&purge_root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(purge_root.join("durable-task-data"), "owned\n").unwrap();
    fs::set_permissions(
        purge_root.join("durable-task-data"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    let interrupted = fixture
        .command()
        .env("HERDR_A2A_TEST_ABORT_AFTER_PURGE_ROOT_DELETION", "1")
        .args(["managed", "remove", "--purge", "--skip-herdr-unregister"])
        .output()
        .unwrap();
    assert!(!interrupted.status.success());
    assert!(!purge_root.exists(), "purge crash hook ran before deletion");
    assert!(
        fixture
            .stable_root()
            .join("removal-transaction.json")
            .exists(),
        "purge intent was not durable at deletion"
    );

    let resumed = fixture.remove_after_exact_plugin_absence(true);

    assert_success(&resumed);
    assert_eq!(fixture.record()["state"], "Removed");
    assert!(
        !fixture
            .stable_root()
            .join("removal-transaction.json")
            .exists()
    );
}

#[test]
fn managed_remove_errors_are_bounded_and_redacted() {
    // Break caught: exact owned paths and raw child stderr are forwarded through CLI/session errors.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));
    let output = fixture
        .command()
        .env("HERDR_A2A_TEST_PI_MODE", "fail")
        .args(["managed", "remove", "--skip-herdr-unregister"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_failure_code(&output, "pi_configuration_failed");
    assert!(
        !stderr.contains(fixture.base.to_str().unwrap()),
        "raw fixture path leaked: {stderr}"
    );
    assert!(
        !stderr.contains("permission denied"),
        "raw child stderr leaked: {stderr}"
    );
    assert!(stderr.len() <= 512, "removal error was not bounded");
}

#[test]
fn managed_remove_redacts_an_unexpected_entry_in_an_owned_directory() {
    // Break caught: the directory-not-empty error disclosed the absolute managed root.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));
    fs::write(
        fixture.stable_root().join("rescue/unexpected-private-name"),
        "unowned\n",
    )
    .unwrap();

    let output = fixture.remove(false, true);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_failure_code(&output, "ownership_conflict");
    assert!(
        !stderr.contains(fixture.base.to_str().unwrap()),
        "raw fixture path leaked: {stderr}"
    );
    assert!(stderr.len() <= 512, "removal error was not bounded");
}

#[test]
fn managed_remove_redacts_a_registry_type_substitution_at_unlink() {
    // Break caught: remove_if_exists formatted the full stable registry path into stderr.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));

    let output = fixture
        .command()
        .env("HERDR_A2A_TEST_REPLACE_REGISTRY_BEFORE_UNLINK", "directory")
        .args(["managed", "remove", "--skip-herdr-unregister"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_failure_code(&output, "removal_failed");
    assert!(
        !stderr.contains(fixture.base.to_str().unwrap()),
        "raw fixture path leaked: {stderr}"
    );
    assert!(stderr.len() <= 512, "removal error was not bounded");
}

#[test]
fn successful_unregister_crash_reconciles_from_exact_plugin_absence() {
    // Break caught: a crash after external unregister success retained UnregisterPending,
    // so recovery replayed a non-idempotent external mutation instead of observing absence.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("unregister-crash-reconcile", "adapter\n");
    assert_success(&fixture.install(&bundle));

    let failed = fixture.remove_with_mode("fail");
    assert_failure_code(&failed, "herdr_uninstall_failed");
    assert_eq!(fixture.record_state(), "UnregisterPending");
    fixture.herdr().set_unregister_success_and_plugin_absent();
    let interrupted = fixture.abort_after_external_unregister_before_phase_write();
    assert!(!interrupted.status.success());
    assert_eq!(fixture.record()["state"], "Unregistering");

    let resumed = fixture.remove_with_mode("fail-if-uninstall-called");
    assert_success(&resumed);
    assert_eq!(fixture.herdr().uninstall_call_count(), 2);
    assert_eq!(fixture.record()["state"], "Removed");
}

#[test]
fn skip_unregister_pending_requires_exact_plugin_absence() {
    // Break caught: --skip-herdr-unregister manufactured FinalizingRemoval from ordinary
    // UnregisterPending without observing whether the exact external registration remained.
    let present = ManagedFixture::new();
    let bundle = present.bundle("skip-pending-present", "adapter\n");
    assert_success(&present.install(&bundle));
    present
        .herdr()
        .set_unregister_success_and_plugin_list("present");
    let record = present.record();
    let stable_binary = PathBuf::from(record["stable_binary"].as_str().unwrap());
    let helper = present.plugin_root.join("libexec/herdr-a2a-dispatch");
    let pointer = present.plugin_root.join("stable-bin-path");

    let output = present.remove(false, true);
    assert_failure_code(&output, "herdr_uninstall_failed");
    assert_eq!(present.record()["state"], "UnregisterPending");
    for retained in [&stable_binary, &helper, &pointer] {
        assert!(
            retained.is_file(),
            "recovery asset was removed: {retained:?}"
        );
    }
    assert_eq!(present.herdr().uninstall_call_count(), 0);

    let absent = ManagedFixture::new();
    let bundle = absent.bundle("skip-pending-absent", "adapter\n");
    assert_success(&absent.install(&bundle));
    absent.herdr().set_unregister_success_and_plugin_absent();

    let output = absent.remove(false, true);
    assert_success(&output);
    assert_eq!(absent.record()["state"], "Removed");
    assert_eq!(absent.herdr().uninstall_call_count(), 0);

    for (list_mode, expected_code) in [
        ("malformed", "herdr_status_invalid"),
        ("timeout", "herdr_status_unavailable"),
    ] {
        let fixture = ManagedFixture::new();
        let bundle = fixture.bundle(&format!("skip-pending-{list_mode}"), "adapter\n");
        assert_success(&fixture.install(&bundle));
        fixture
            .herdr()
            .set_unregister_success_and_plugin_list(list_mode);
        let record = fixture.record();
        let stable_binary = PathBuf::from(record["stable_binary"].as_str().unwrap());
        let helper = fixture.plugin_root.join("libexec/herdr-a2a-dispatch");
        let pointer = fixture.plugin_root.join("stable-bin-path");

        let output = fixture.remove(false, true);
        assert_failure_code(&output, expected_code);
        assert_eq!(fixture.record()["state"], "Unregistering");
        for retained in [&stable_binary, &helper, &pointer] {
            assert!(
                retained.is_file(),
                "recovery asset was removed: {retained:?}"
            );
        }
        assert_eq!(fixture.herdr().uninstall_call_count(), 0);
    }
}

#[test]
fn skip_unregister_recovery_reconciles_durable_unregistering() {
    // Break caught: --skip-herdr-unregister bypassed the mandatory observation after a crash,
    // deleting the stable recovery assets while Herdr could still own the registration.
    let present = ManagedFixture::new();
    let bundle = present.bundle("skip-unregister-present", "adapter\n");
    assert_success(&present.install(&bundle));
    let failed = present.remove_with_mode("fail");
    assert_failure_code(&failed, "herdr_uninstall_failed");
    present
        .herdr()
        .set_unregister_success_and_plugin_list("present");
    let interrupted = present.abort_after_external_unregister_before_phase_write();
    assert!(!interrupted.status.success());
    assert_eq!(present.record()["state"], "Unregistering");
    let record = present.record();
    let stable_binary = PathBuf::from(record["stable_binary"].as_str().unwrap());
    let helper = present.plugin_root.join("libexec/herdr-a2a-dispatch");
    let pointer = present.plugin_root.join("stable-bin-path");

    let resumed = present.remove(false, true);
    assert_failure_code(&resumed, "herdr_uninstall_failed");
    assert_eq!(present.record()["state"], "UnregisterPending");
    for retained in [&stable_binary, &helper, &pointer] {
        assert!(
            retained.is_file(),
            "recovery asset was removed: {retained:?}"
        );
    }
    assert_eq!(present.herdr().uninstall_call_count(), 2);

    let unknown = ManagedFixture::new();
    let bundle = unknown.bundle("skip-unregister-unknown", "adapter\n");
    assert_success(&unknown.install(&bundle));
    let failed = unknown.remove_with_mode("fail");
    assert_failure_code(&failed, "herdr_uninstall_failed");
    unknown.set_record_state("Unregistering");
    unknown
        .herdr()
        .set_unregister_success_and_plugin_list("malformed");
    let before = fs::read(unknown.ownership_path()).unwrap();

    let resumed = unknown.remove(false, true);
    assert_failure_code(&resumed, "herdr_status_invalid");
    assert_eq!(unknown.record()["state"], "Unregistering");
    assert_eq!(fs::read(unknown.ownership_path()).unwrap(), before);
}

#[test]
fn unregister_recovery_accepts_only_exact_plugin_absence() {
    // Break caught: recovery trusted an ambiguous external response or replayed unregister
    // instead of making one bounded, read-only decision from the exact registration record.
    for (list_mode, expected_code) in [
        ("malformed", "herdr_status_invalid"),
        ("duplicate", "herdr_status_invalid"),
        ("redirected", "herdr_status_invalid"),
        ("conflicting-root", "ownership_conflict"),
        ("timeout", "herdr_status_unavailable"),
        ("oversized", "herdr_status_unavailable"),
    ] {
        let fixture = ManagedFixture::new();
        let bundle = fixture.bundle(&format!("unregister-{list_mode}"), "adapter\n");
        assert_success(&fixture.install(&bundle));
        let failed = fixture.remove_with_mode("fail");
        assert_failure_code(&failed, "herdr_uninstall_failed");
        fixture.set_record_state("Unregistering");
        fixture
            .herdr()
            .set_unregister_success_and_plugin_list(list_mode);
        let before = fs::read(fixture.ownership_path()).unwrap();

        let resumed = fixture.remove_with_mode("fail-if-uninstall-called");
        let stderr = String::from_utf8_lossy(&resumed.stderr);
        assert_failure_code(&resumed, expected_code);
        assert_eq!(fixture.record()["state"], "Unregistering");
        assert_eq!(fs::read(fixture.ownership_path()).unwrap(), before);
        assert!(!stderr.contains(fixture.base.to_str().unwrap()));
        assert!(!stderr.contains("/raw/path"));
        assert!(!stderr.contains("/conflicting/plugin/root"));
    }

    let present = ManagedFixture::new();
    let bundle = present.bundle("unregister-present", "adapter\n");
    assert_success(&present.install(&bundle));
    let failed = present.remove_with_mode("fail");
    assert_failure_code(&failed, "herdr_uninstall_failed");
    present.set_record_state("Unregistering");
    present
        .herdr()
        .set_unregister_success_and_plugin_list("present");
    let record = present.record();
    let stable_binary = PathBuf::from(record["stable_binary"].as_str().unwrap());
    let helper = present.plugin_root.join("libexec/herdr-a2a-dispatch");
    let pointer = present.plugin_root.join("stable-bin-path");

    let resumed = present.remove_with_mode("fail-if-uninstall-called");
    assert_failure_code(&resumed, "herdr_uninstall_failed");
    assert_eq!(present.record()["state"], "UnregisterPending");
    for retained in [&stable_binary, &helper, &pointer] {
        assert!(
            retained.is_file(),
            "recovery asset was removed: {retained:?}"
        );
    }
    assert_eq!(present.herdr().uninstall_call_count(), 1);

    let absent = ManagedFixture::new();
    let bundle = absent.bundle("unregister-absent", "adapter\n");
    assert_success(&absent.install(&bundle));
    let failed = absent.remove_with_mode("fail");
    assert_failure_code(&failed, "herdr_uninstall_failed");
    absent.set_record_state("Unregistering");
    absent
        .herdr()
        .set_unregister_success_and_plugin_list("absent");

    let resumed = absent.remove_with_mode("fail-if-uninstall-called");
    assert_success(&resumed);
    assert_eq!(absent.record()["state"], "Removed");
    assert_eq!(absent.herdr().uninstall_call_count(), 1);
}

#[test]
fn herdr_unregister_failure_and_finalization_are_retryable_without_losing_the_helper() {
    // Break caught: removal committed Removed and deleted its helper before Herdr unregister,
    // making a failed external unregister terminal and leaving an unusable registered plugin.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("unregister-retry", "adapter\n");
    assert_success(&fixture.install(&bundle));
    let record = fixture.record();
    let stable_binary = PathBuf::from(record["stable_binary"].as_str().unwrap());
    let helper = fixture.plugin_root.join("libexec/herdr-a2a-dispatch");
    let pointer = fixture.plugin_root.join("stable-bin-path");

    let failed = fixture
        .command()
        .env("HERDR_A2A_TEST_HERDR_MODE", "fail")
        .args(["managed", "remove"])
        .output()
        .unwrap();
    assert_failure_code(&failed, "herdr_uninstall_failed");
    assert_eq!(fixture.record()["state"], "UnregisterPending");
    for retained in [&stable_binary, &helper, &pointer] {
        assert!(retained.is_file(), "retry helper was removed: {retained:?}");
    }

    fixture.herdr().set_unregister_success_and_plugin_absent();
    let interrupted = fixture.abort_after_external_unregister_before_phase_write();
    assert!(!interrupted.status.success());
    assert_eq!(fixture.record()["state"], "Unregistering");
    assert!(stable_binary.is_file());

    let resumed = fixture
        .command()
        .env("HERDR_A2A_TEST_HERDR_MODE", "fail")
        .args(["managed", "remove"])
        .output()
        .unwrap();

    assert_success(&resumed);
    assert_eq!(fixture.record()["state"], "Removed");
    assert!(!stable_binary.exists());
    assert!(!helper.exists());
    assert!(!pointer.exists());
    assert_eq!(
        fs::read_to_string(&fixture.herdr_log)
            .unwrap()
            .lines()
            .count(),
        2,
        "finalization retried the already-completed Herdr unregister"
    );
}

#[test]
fn managed_install_rejects_a_package_tree_beyond_the_depth_bound() {
    // Break caught: recursive package enumeration had no depth or aggregate-work bound.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    let mut deep = bundle.join("pi");
    for index in 0..65 {
        deep.push(format!("level-{index}"));
        fs::create_dir(&deep).unwrap();
    }
    fs::write(deep.join("too-deep.txt"), "bounded\n").unwrap();

    let output = fixture.install(&bundle);

    assert_failure_code(&output, "bundle_invalid");
    assert!(!fixture.ownership_path().exists());
}

#[test]
fn managed_remove_stops_every_exact_registered_workspace() {
    // Break caught: removal only stops the caller's current workspace and leaves another managed
    // coordinator/broker pair alive after unlinking its recorded executable.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));
    let stable_binary = PathBuf::from(fixture.record()["stable_binary"].as_str().unwrap());
    let runtime = fixture.base.join("runtime with spaces");
    fs::create_dir(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();

    let mut children = ExactChildren(Vec::new());
    for workspace in ["workspace-left", "workspace-right"] {
        let child = fixture
            .command_with_program(&stable_binary)
            .args(["coordinator", "serve"])
            .env("HERDR_SOCKET_PATH", fixture.base.join("herdr.sock"))
            .env("HERDR_WORKSPACE_ID", workspace)
            .env("HERDR_BIN_PATH", "/usr/bin/false")
            .env("TMPDIR", &runtime)
            .env("XDG_RUNTIME_DIR", &runtime)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        children.0.push(child);
        let registry = fixture.stable_root().join("process-registry");
        let deadline = Instant::now() + MANAGED_PROCESS_START_WATCHDOG;
        while Instant::now() < deadline {
            if fs::read_to_string(&registry)
                .unwrap_or_default()
                .contains(workspace)
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    let registry = fixture.stable_root().join("process-registry");
    let registry_contents = fs::read_to_string(&registry).unwrap_or_default();
    let registry_ready = registry_contents.contains("workspace-left")
        && registry_contents.contains("workspace-right");
    let children_live = children
        .0
        .iter_mut()
        .all(|child| child.try_wait().unwrap().is_none());
    if !registry_ready || !children_live {
        for child in &mut children.0 {
            if child.try_wait().unwrap().is_none() {
                child.kill().unwrap();
                child.wait().unwrap();
            }
        }
        assert!(
            registry_ready,
            "coordinators did not register both workspaces; registry={registry_contents:?}; children_live={children_live}"
        );
        assert!(children_live, "a coordinator exited before managed removal");
    }

    let mut paused = PausedExactProcesses::from_managed_install(&fixture.stable_root());
    let original_registry = paused.original_registry.clone();

    fs::set_permissions(&registry, fs::Permissions::from_mode(0o644)).unwrap();
    let unsafe_mode = fixture.remove(false, true);
    fs::set_permissions(&registry, fs::Permissions::from_mode(0o600)).unwrap();
    assert_failure_code(&unsafe_mode, "owned_process_mismatch");

    for (field, mutation) in [
        (6, "stale-start-identity"),
        (9, "mismatched-broker-instance"),
        (10, "/private/tmp/unowned-herdr-a2a"),
    ] {
        fs::write(
            &registry,
            mutate_first_registry_entry(&original_registry, field, mutation),
        )
        .unwrap();
        fs::set_permissions(&registry, fs::Permissions::from_mode(0o600)).unwrap();
        assert_failure_code(&fixture.remove(false, true), "owned_process_mismatch");
        fs::write(&registry, &original_registry).unwrap();
        fs::set_permissions(&registry, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let displaced_registry = fixture.stable_root().join("process-registry-saved");
    fs::rename(&registry, &displaced_registry).unwrap();
    symlink(&displaced_registry, &registry).unwrap();
    assert_failure_code(&fixture.remove(false, true), "owned_process_mismatch");
    fs::remove_file(&registry).unwrap();
    fs::rename(&displaced_registry, &registry).unwrap();

    paused.resume();

    assert!(
        children
            .0
            .iter_mut()
            .all(|child| child.try_wait().unwrap().is_none()),
        "a rejected process-registry mutation stopped an owned child"
    );

    fixture.herdr().set_unregister_success_and_plugin_absent();
    let output = fixture.remove(false, true);
    let exit_deadline = Instant::now() + Duration::from_secs(5);
    let mut all_exited = false;
    while Instant::now() < exit_deadline {
        all_exited = children
            .0
            .iter_mut()
            .all(|child| child.try_wait().unwrap().is_some());
        if all_exited {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    for child in &mut children.0 {
        if child.try_wait().unwrap().is_none() {
            child.kill().unwrap();
            child.wait().unwrap();
        }
    }
    assert_success(&output);
    assert!(
        all_exited,
        "managed removal left a registered workspace alive"
    );
    assert!(
        !registry.exists(),
        "managed process registry was not cleaned up"
    );
}

#[test]
fn managed_remove_reconciles_an_authenticated_fully_retired_registration() {
    // Break caught: closing a Herdr workspace can retire both exact managed processes before the
    // coordinator unregisters them, leaving an authenticated stale entry that blocks uninstall.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));
    let stable_binary = PathBuf::from(fixture.record()["stable_binary"].as_str().unwrap());
    let runtime = fixture.base.join("retired runtime");
    fs::create_dir(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    let mut coordinator = fixture
        .command_with_program(&stable_binary)
        .args(["coordinator", "serve"])
        .env("HERDR_SOCKET_PATH", fixture.base.join("herdr.sock"))
        .env("HERDR_WORKSPACE_ID", "retired-workspace")
        .env("HERDR_BIN_PATH", "/usr/bin/false")
        .env("TMPDIR", &runtime)
        .env("XDG_RUNTIME_DIR", &runtime)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let registry = fixture.stable_root().join("process-registry");
    let deadline = Instant::now() + MANAGED_PROCESS_START_WATCHDOG;
    let broker_pid = loop {
        let encoded = fs::read_to_string(&registry).unwrap_or_default();
        if let Some(entry) = encoded.lines().find(|line| line.starts_with("entry|")) {
            break entry.split('|').nth(7).unwrap().to_owned();
        }
        assert!(Instant::now() < deadline, "coordinator did not register");
        std::thread::sleep(Duration::from_millis(20));
    };

    coordinator.kill().unwrap();
    coordinator.wait().unwrap();
    let exit_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < exit_deadline
        && Command::new("/bin/kill")
            .args(["-0", &broker_pid])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        registry.exists(),
        "abrupt retirement unexpectedly unregistered itself"
    );

    fixture.herdr().set_unregister_success_and_plugin_absent();
    let output = fixture.remove(false, true);

    assert_success(&output);
    assert!(!registry.exists());
}

#[test]
fn managed_update_stops_registered_workspace_before_replacing_generation() {
    // Break caught: update deleted the old generation while its registered broker remained live,
    // leaving a process registry that the new ownership record could never authenticate.
    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    let second = fixture.bundle("2.0.0", "adapter two\n");
    assert_success(&fixture.install(&first));
    let first_binary = PathBuf::from(fixture.record()["stable_binary"].as_str().unwrap());
    let runtime = fixture.base.join("runtime update");
    fs::create_dir(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    let mut child = fixture
        .command_with_program(&first_binary)
        .args(["coordinator", "serve"])
        .env("HERDR_SOCKET_PATH", fixture.base.join("herdr.sock"))
        .env("HERDR_WORKSPACE_ID", "workspace-update")
        .env("HERDR_BIN_PATH", "/usr/bin/false")
        .env("TMPDIR", &runtime)
        .env("XDG_RUNTIME_DIR", &runtime)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let registry = fixture.stable_root().join("process-registry");
    let registry_deadline = Instant::now() + MANAGED_PROCESS_START_WATCHDOG;
    while Instant::now() < registry_deadline
        && !fs::read_to_string(&registry)
            .unwrap_or_default()
            .contains("workspace-update")
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        fs::read_to_string(&registry)
            .unwrap_or_default()
            .contains("workspace-update"),
        "coordinator did not publish its managed registration"
    );

    let update = fixture.install(&second);
    let exit_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < exit_deadline && child.try_wait().unwrap().is_none() {
        std::thread::sleep(Duration::from_millis(20));
    }
    let exited = child.try_wait().unwrap().is_some();
    if !exited {
        child.kill().unwrap();
        child.wait().unwrap();
    }

    assert_success(&update);
    assert!(
        exited,
        "managed update left the old registered broker alive"
    );
    assert_eq!(
        fs::read_to_string(&registry).unwrap_or_default(),
        "HERDR_A2A_PROCESS_REGISTRY_V1\n",
        "managed update retained a stale process registration"
    );
    assert_ne!(
        PathBuf::from(fixture.record()["stable_binary"].as_str().unwrap()),
        first_binary,
        "managed update did not publish the replacement generation"
    );
}

#[test]
fn starting_process_operation_boundary_matrix_covers_all_release_cases() {
    let cases = starting_process_operation_boundary_matrix();
    assert_eq!(cases.len(), 6);
    for operation in ["update", "remove"] {
        for boundary in [
            "after-coordinator-reservation",
            "after-broker-proof-before-descriptor",
            "after-descriptor-before-registration",
        ] {
            assert!(
                cases
                    .iter()
                    .any(|case| case.operation == operation && case.boundary == boundary),
                "missing release case {operation}/{boundary}"
            );
        }
    }
    assert!(
        cases.iter().all(|case| {
            case.expect_broker == (case.boundary != "after-coordinator-reservation")
        })
    );
    let real_cases = cases
        .iter()
        .filter(|case| case.real_process)
        .collect::<Vec<_>>();
    assert_eq!(real_cases.len(), 6);
    assert!(real_cases.iter().all(|case| !case.real_test.is_empty()));
    let mapped_tests = real_cases
        .iter()
        .map(|case| case.real_test)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        mapped_tests.len(),
        6,
        "every matrix case needs its own real test"
    );
}

#[derive(Clone, Copy)]
struct StartingProcessLifecycleCase {
    operation: &'static str,
    boundary: &'static str,
    expect_broker: bool,
    real_process: bool,
    real_test: &'static str,
}

fn starting_process_operation_boundary_matrix() -> [StartingProcessLifecycleCase; 6] {
    [
        StartingProcessLifecycleCase {
            operation: "update",
            boundary: "after-coordinator-reservation",
            expect_broker: false,
            real_process: true,
            real_test: "starting_process_update_coordinator_reservation_is_retired_with_watchdog",
        },
        StartingProcessLifecycleCase {
            operation: "update",
            boundary: "after-broker-proof-before-descriptor",
            expect_broker: true,
            real_process: true,
            real_test: "starting_process_update_broker_proof_before_descriptor_is_retired_with_watchdog",
        },
        StartingProcessLifecycleCase {
            operation: "update",
            boundary: "after-descriptor-before-registration",
            expect_broker: true,
            real_process: true,
            real_test: "starting_process_update_descriptor_before_registration_is_retired_with_watchdog",
        },
        StartingProcessLifecycleCase {
            operation: "remove",
            boundary: "after-coordinator-reservation",
            expect_broker: false,
            real_process: true,
            real_test: "starting_process_remove_coordinator_reservation_is_retired_with_watchdog",
        },
        StartingProcessLifecycleCase {
            operation: "remove",
            boundary: "after-broker-proof-before-descriptor",
            expect_broker: true,
            real_process: true,
            real_test: "starting_process_remove_broker_proof_before_descriptor_is_retired_with_watchdog",
        },
        StartingProcessLifecycleCase {
            operation: "remove",
            boundary: "after-descriptor-before-registration",
            expect_broker: true,
            real_process: true,
            real_test: "starting_process_remove_descriptor_before_registration_is_retired_with_watchdog",
        },
    ]
}

#[test]
fn starting_process_update_coordinator_reservation_is_retired_with_watchdog() {
    let operation = "update";
    let boundary = "after-coordinator-reservation";
    eprintln!("starting-process case={operation}/{boundary} phase=setup");
    let fixture = ManagedFixture::new();
    let first = fixture.bundle("starting-watchdog-one", "adapter one\n");
    let second = fixture.bundle("starting-watchdog-two", "adapter two\n");
    assert_success(&fixture.install(&first));
    let mut children = fixture.start_managed_coordinator_paused(boundary);
    fixture.wait_for_starting_registry(boundary, &mut children);

    let output = fixture.run_lifecycle_operation_with_watchdog(operation, &second, boundary);

    assert_success(&output);
    children.assert_exact_coordinator_and_broker_retired();
    fixture.assert_no_starting_or_registered_entry();
    record_starting_process_case_execution(
        "starting_process_update_coordinator_reservation_is_retired_with_watchdog",
    );
}

#[test]
fn starting_process_is_retired_before_binding_during_update_and_remove() {
    // Break caught: removing any operation/boundary pair silently drops one of the release
    // obligations. The named aggregate must execute every distinct watchdog proof below.
    let cases = starting_process_operation_boundary_matrix();
    assert_eq!(cases.len(), 6);
    assert!(cases.iter().any(|case| case.operation == "update"));
    assert!(cases.iter().any(|case| case.operation == "remove"));
    let mapped_tests = cases
        .iter()
        .filter(|case| case.real_process)
        .map(|case| case.real_test)
        .collect::<BTreeSet<_>>();
    assert_eq!(mapped_tests.len(), 6);
    assert!(mapped_tests.iter().all(|test| !test.is_empty()));

    let execution_log_dir = tempfile::tempdir().unwrap();
    let execution_log = execution_log_dir
        .path()
        .join("starting-process-aggregate.log");
    fs::write(&execution_log, b"").unwrap();
    run_starting_process_case_aggregate(&cases, &execution_log);
    let executed = fs::read_to_string(&execution_log).unwrap_or_default();
    let executed = executed.lines().collect::<BTreeSet<_>>();
    assert_eq!(
        executed, mapped_tests,
        "the aggregate did not execute every mapped lifecycle watchdog"
    );
}

#[test]
fn starting_process_aggregate_forced_timeout_retires_its_exact_group() {
    let fixture = tempfile::tempdir().unwrap();
    let execution_log = fixture.path().join("starting-process-aggregate.log");
    let ready = fixture.path().join("starting-process-timeout-ready");
    fs::write(&execution_log, b"").unwrap();
    let case = starting_process_operation_boundary_matrix()
        .into_iter()
        .find(|case| {
            case.operation == "update" && case.boundary == "after-broker-proof-before-descriptor"
        })
        .unwrap();
    let started = Instant::now();
    let timeout = run_starting_process_case_aggregate_with_config(
        &[case],
        &execution_log,
        StartingProcessAggregateConfig::forced_timeout(&ready),
    )
    .expect_err("the forced aggregate deadline unexpectedly succeeded");

    assert!(
        started.elapsed() < STARTING_PROCESS_FORCED_OUTER_WATCHDOG,
        "forced aggregate timeout did not return within its bounded outer watchdog"
    );
    let ready = StartingProcessTimeoutReady::read(&ready).unwrap();
    assert!(!process_is_live(timeout.harness_pid));
    assert!(!process_group_is_live(timeout.group_pid));
    assert!(!process_is_live(ready.coordinator_pid));
    assert!(!process_is_live(ready.broker_pid));
}

struct BoundedChildOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

#[derive(Clone, Copy)]
struct StartingProcessAggregateConfig<'a> {
    case_watchdog: Duration,
    aggregate_watchdog: Duration,
    timeout_ready: Option<&'a Path>,
}

impl<'a> StartingProcessAggregateConfig<'a> {
    fn normal() -> Self {
        Self {
            case_watchdog: STARTING_PROCESS_CASE_WATCHDOG,
            aggregate_watchdog: STARTING_PROCESS_AGGREGATE_WATCHDOG,
            timeout_ready: None,
        }
    }

    fn forced_timeout(timeout_ready: &'a Path) -> Self {
        Self {
            case_watchdog: STARTING_PROCESS_FORCED_CASE_WATCHDOG,
            aggregate_watchdog: STARTING_PROCESS_FORCED_OUTER_WATCHDOG,
            timeout_ready: Some(timeout_ready),
        }
    }
}

struct StartingProcessAggregateFailure {
    harness_pid: u32,
    group_pid: u32,
    detail: String,
}

struct StartingProcessTimeoutReady {
    coordinator_pid: u32,
    broker_pid: u32,
}

impl StartingProcessTimeoutReady {
    fn read(path: &Path) -> Option<Self> {
        let contents = fs::read_to_string(path).ok()?;
        let mut values = contents
            .lines()
            .filter_map(|line| line.split_once('='))
            .filter_map(|(name, value)| value.parse::<u32>().ok().map(|value| (name, value)));
        let coordinator_pid =
            values.find_map(|(name, value)| (name == "coordinator_pid").then_some(value))?;
        let contents = fs::read_to_string(path).ok()?;
        let broker_pid = contents
            .lines()
            .filter_map(|line| line.split_once('='))
            .find_map(|(name, value)| (name == "broker_pid").then(|| value.parse().ok()))??;
        Some(Self {
            coordinator_pid,
            broker_pid,
        })
    }
}

fn run_starting_process_case_aggregate(
    cases: &[StartingProcessLifecycleCase],
    execution_log: &Path,
) {
    run_starting_process_case_aggregate_with_config(
        cases,
        execution_log,
        StartingProcessAggregateConfig::normal(),
    )
    .unwrap_or_else(|failure| {
        panic!(
            "starting-process aggregate harness={} group={}: {}",
            failure.harness_pid, failure.group_pid, failure.detail
        )
    });
}

fn run_starting_process_case_aggregate_with_config(
    cases: &[StartingProcessLifecycleCase],
    execution_log: &Path,
    config: StartingProcessAggregateConfig<'_>,
) -> Result<(), StartingProcessAggregateFailure> {
    let case_watchdog = STARTING_PROCESS_SETUP_WATCHDOG + STARTING_PROCESS_OPERATION_WATCHDOG;
    if config.timeout_ready.is_none() {
        assert_eq!(case_watchdog, config.case_watchdog);
    }
    let aggregate_started = Instant::now();
    let aggregate_deadline = aggregate_started + config.aggregate_watchdog;
    for case in cases.iter().filter(|case| case.real_process) {
        assert_ne!(
            case.real_test, "starting_process_is_retired_before_binding_during_update_and_remove",
            "the aggregate must never recursively invoke itself"
        );
        let started = Instant::now();
        eprintln!(
            "starting-process aggregate case={}/{} test={} phase=spawn",
            case.operation, case.boundary, case.real_test
        );
        let mut command = Command::new(env::current_exe().unwrap());
        command
            .args([case.real_test, "--exact", "--nocapture"])
            .env(STARTING_PROCESS_AGGREGATE_LOG, execution_log)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(timeout_ready) = config.timeout_ready {
            command.env(STARTING_PROCESS_TIMEOUT_READY, timeout_ready);
        }
        // SAFETY: the closure runs only in the newly forked test-harness child and changes that
        // child's process group to itself before exec, so group signalling cannot affect parent
        // tests or unrelated processes.
        unsafe {
            command.pre_exec(|| setpgid(None, None).map_err(|_| std::io::Error::last_os_error()));
        }
        let mut child = command.spawn().unwrap();
        let harness_pid = child.id();
        let group_pid = harness_pid;
        let stdout = std::thread::spawn({
            let stdout = child.stdout.take().unwrap();
            move || read_bounded_child_output(stdout)
        });
        let stderr = std::thread::spawn({
            let stderr = child.stderr.take().unwrap();
            move || read_bounded_child_output(stderr)
        });
        let case_deadline = if let Some(timeout_ready) = config.timeout_ready {
            wait_for_starting_process_timeout_ready(
                timeout_ready,
                &mut child,
                group_pid,
                aggregate_deadline,
            )?;
            Instant::now() + config.case_watchdog
        } else {
            started + case_watchdog
        };
        let mut observed_status = None;
        let timed_out = loop {
            if let Some(status) = child.try_wait().unwrap() {
                observed_status = Some(status);
                break false;
            }
            if Instant::now() >= case_deadline || Instant::now() >= aggregate_deadline {
                break true;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let status =
            retire_starting_process_aggregate_group(&mut child, group_pid, observed_status)
                .map_err(|detail| StartingProcessAggregateFailure {
                    harness_pid,
                    group_pid,
                    detail,
                })?;
        let stdout = stdout.join().unwrap().unwrap();
        let stderr = stderr.join().unwrap().unwrap();
        if timed_out {
            return Err(StartingProcessAggregateFailure {
                harness_pid,
                group_pid,
                detail: format!(
                    "case={}/{} test={} watchdog expired after {} ms; status={status}; stdout{}: {}; stderr{}: {}",
                    case.operation,
                    case.boundary,
                    case.real_test,
                    started.elapsed().as_millis(),
                    bounded_output_suffix(&stdout),
                    String::from_utf8_lossy(&stdout.bytes),
                    bounded_output_suffix(&stderr),
                    String::from_utf8_lossy(&stderr.bytes),
                ),
            });
        }
        assert!(
            status.success(),
            "starting-process aggregate case={}/{} test={} failed with {status}; stdout{}: {}; stderr{}: {}",
            case.operation,
            case.boundary,
            case.real_test,
            bounded_output_suffix(&stdout),
            String::from_utf8_lossy(&stdout.bytes),
            bounded_output_suffix(&stderr),
            String::from_utf8_lossy(&stderr.bytes),
        );
        eprintln!(
            "starting-process aggregate case={}/{} test={} phase=passed elapsed_ms={}",
            case.operation,
            case.boundary,
            case.real_test,
            started.elapsed().as_millis()
        );
    }
    Ok(())
}

fn wait_for_starting_process_timeout_ready(
    path: &Path,
    child: &mut Child,
    group_pid: u32,
    aggregate_deadline: Instant,
) -> Result<(), StartingProcessAggregateFailure> {
    let setup_deadline = Instant::now() + STARTING_PROCESS_FORCED_SETUP_WATCHDOG;
    loop {
        if StartingProcessTimeoutReady::read(path).is_some() {
            return Ok(());
        }
        if Instant::now() >= setup_deadline || Instant::now() >= aggregate_deadline {
            let harness_pid = child.id();
            let detail = retire_starting_process_aggregate_group(child, group_pid, None)
                .err()
                .unwrap_or_else(|| {
                    "forced-timeout fixture never reached its paused boundary".into()
                });
            return Err(StartingProcessAggregateFailure {
                harness_pid,
                group_pid,
                detail,
            });
        }
        if let Some(status) = child.try_wait().unwrap() {
            let harness_pid = child.id();
            let detail = retire_starting_process_aggregate_group(child, group_pid, Some(status))
                .err()
                .unwrap_or_else(|| {
                    format!("forced-timeout fixture exited before readiness: {status}")
                });
            return Err(StartingProcessAggregateFailure {
                harness_pid,
                group_pid,
                detail,
            });
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn retire_starting_process_aggregate_group(
    child: &mut Child,
    group_pid: u32,
    observed_status: Option<std::process::ExitStatus>,
) -> Result<std::process::ExitStatus, String> {
    if process_group_is_live(group_pid) {
        signal_starting_process_aggregate_group(group_pid, Signal::TERM)?;
        if !wait_for_process_group_retirement(
            group_pid,
            Instant::now() + STARTING_PROCESS_GROUP_TERM_GRACE,
        ) {
            signal_starting_process_aggregate_group(group_pid, Signal::KILL)?;
            if !wait_for_process_group_retirement(
                group_pid,
                Instant::now() + STARTING_PROCESS_GROUP_KILL_GRACE,
            ) {
                return Err("exact aggregate process group did not retire after TERM/KILL".into());
            }
        }
    }
    observed_status.map(Ok).unwrap_or_else(|| {
        child
            .wait()
            .map_err(|error| format!("reap aggregate harness: {error}"))
    })
}

fn signal_starting_process_aggregate_group(group_pid: u32, signal: Signal) -> Result<(), String> {
    let group = Pid::from_raw(i32::try_from(group_pid).map_err(|_| "invalid aggregate group PID")?)
        .ok_or("invalid aggregate group PID")?;
    kill_process_group(group, signal)
        .map_err(|error| format!("signal exact aggregate group: {error}"))
}

fn wait_for_process_group_retirement(group_pid: u32, deadline: Instant) -> bool {
    while process_group_is_live(group_pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    !process_group_is_live(group_pid)
}

#[cfg(target_os = "linux")]
fn process_group_is_live(group_pid: u32) -> bool {
    fs::read_dir("/proc")
        .unwrap()
        .filter_map(Result::ok)
        .any(|entry| {
            entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
                .and_then(linux_process_state_and_group)
                .is_some_and(|(state, process_group)| state != b'Z' && process_group == group_pid)
        })
}

#[cfg(not(target_os = "linux"))]
fn process_group_is_live(group_pid: u32) -> bool {
    i32::try_from(group_pid)
        .ok()
        .and_then(Pid::from_raw)
        .is_some_and(|group| test_kill_process_group(group).is_ok())
}

fn read_bounded_child_output(mut reader: impl Read) -> std::io::Result<BoundedChildOutput> {
    let mut output = BoundedChildOutput {
        bytes: Vec::new(),
        truncated: false,
    };
    let mut buffer = [0_u8; 4096];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok(output);
        }
        let remaining = STARTING_PROCESS_CHILD_OUTPUT_LIMIT.saturating_sub(output.bytes.len());
        let retained = remaining.min(count);
        output.bytes.extend_from_slice(&buffer[..retained]);
        output.truncated |= retained < count;
    }
}

fn bounded_output_suffix(output: &BoundedChildOutput) -> &'static str {
    if output.truncated { " (truncated)" } else { "" }
}

fn record_starting_process_case_execution(test_name: &str) {
    let Some(path) = env::var_os(STARTING_PROCESS_AGGREGATE_LOG) else {
        return;
    };
    let mut log = fs::OpenOptions::new().append(true).open(path).unwrap();
    writeln!(log, "{test_name}").unwrap();
}

fn record_starting_process_timeout_ready(children: &PausedStartingChildren) {
    let Some(path) = env::var_os(STARTING_PROCESS_TIMEOUT_READY) else {
        return;
    };
    let broker_pid = children
        .broker_pid
        .expect("forced-timeout fixture did not reach a broker-bearing boundary");
    fs::write(
        path,
        format!(
            "coordinator_pid={}\nbroker_pid={broker_pid}\n",
            children.coordinator.id()
        ),
    )
    .unwrap();
}

#[test]
fn starting_process_update_broker_proof_before_descriptor_is_retired_with_watchdog() {
    run_real_starting_process_case(
        starting_process_operation_boundary_matrix()
            .into_iter()
            .find(|case| {
                case.operation == "update"
                    && case.boundary == "after-broker-proof-before-descriptor"
            })
            .unwrap(),
    );
}

#[test]
fn starting_process_remove_coordinator_reservation_is_retired_with_watchdog() {
    run_real_starting_process_case(
        starting_process_operation_boundary_matrix()
            .into_iter()
            .find(|case| {
                case.operation == "remove" && case.boundary == "after-coordinator-reservation"
            })
            .unwrap(),
    );
}

#[test]
fn starting_process_remove_descriptor_before_registration_is_retired_with_watchdog() {
    run_real_starting_process_case(
        starting_process_operation_boundary_matrix()
            .into_iter()
            .find(|case| {
                case.operation == "remove"
                    && case.boundary == "after-descriptor-before-registration"
            })
            .unwrap(),
    );
}

#[test]
fn starting_process_remove_broker_proof_before_descriptor_is_retired_with_watchdog() {
    run_real_starting_process_case(
        starting_process_operation_boundary_matrix()
            .into_iter()
            .find(|case| {
                case.operation == "remove"
                    && case.boundary == "after-broker-proof-before-descriptor"
            })
            .unwrap(),
    );
}

#[test]
fn starting_process_update_descriptor_before_registration_is_retired_with_watchdog() {
    run_real_starting_process_case(
        starting_process_operation_boundary_matrix()
            .into_iter()
            .find(|case| {
                case.operation == "update"
                    && case.boundary == "after-descriptor-before-registration"
            })
            .unwrap(),
    );
}

fn run_real_starting_process_case(case: StartingProcessLifecycleCase) {
    eprintln!(
        "starting-process case={}/{} phase=setup",
        case.operation, case.boundary
    );
    let fixture = ManagedFixture::new();
    let first = fixture.bundle("starting-one", "adapter one\n");
    let second = fixture.bundle("starting-two", "adapter two\n");
    let installed = fixture.install(&first);
    if !installed.status.success() {
        panic!(
            "initial install failed for {} at {}\nstdout: {}\nstderr: {}\nPi calls: {}",
            case.operation,
            case.boundary,
            String::from_utf8_lossy(&installed.stdout),
            String::from_utf8_lossy(&installed.stderr),
            fixture.pi_log(),
        );
    }
    let mut children = fixture.start_managed_coordinator_paused(case.boundary);
    fixture.wait_for_starting_registry(case.boundary, &mut children);
    assert_eq!(
        children.broker_pid.is_some(),
        case.expect_broker,
        "{}/{} broker-proof expectation changed",
        case.operation,
        case.boundary
    );
    record_starting_process_timeout_ready(&children);
    let output =
        fixture.run_lifecycle_operation_with_watchdog(case.operation, &second, case.boundary);
    if !output.status.success() {
        panic!(
            "{} failed at {}\nstdout: {}\nstderr: {}\nPi calls: {}",
            case.operation,
            case.boundary,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
            fixture.pi_log(),
        );
    }
    children.assert_exact_coordinator_and_broker_retired();
    fixture.assert_no_starting_or_registered_entry();
    record_starting_process_case_execution(case.real_test);
}

#[test]
fn stale_starting_reservation_mismatch_matrix_is_complete() {
    assert_eq!(stale_starting_reservation_mismatch_matrix().len(), 6);
}

fn stale_starting_reservation_mismatch_matrix() -> [&'static str; 6] {
    [
        "CoordinatorPidReused",
        "BrokerPidReused",
        "ExecutableMismatch",
        "DigestMismatch",
        "GenerationMismatch",
        "WorkspaceMismatch",
    ]
}

#[test]
fn stale_starting_reservations_reconcile_only_with_exact_process_proof() {
    for (name, boundary, retire_before_remove) in [
        ("BothAbsent", "after-broker-proof-before-descriptor", true),
        (
            "ExactCoordinatorLive",
            "after-coordinator-reservation",
            false,
        ),
        (
            "ExactCoordinatorAndBrokerLive",
            "after-broker-proof-before-descriptor",
            false,
        ),
    ] {
        eprintln!("stale-starting case={name} phase=setup");
        let fixture = ManagedFixture::new();
        let bundle = fixture.bundle("stale-starting", "adapter one\n");
        assert_success(&fixture.install(&bundle));
        let mut children = fixture.start_managed_coordinator_paused(boundary);
        fixture.wait_for_starting_registry(boundary, &mut children);
        if retire_before_remove {
            children.retire_for_fixture();
        }
        fixture.herdr().set_unregister_success_and_plugin_absent();
        let output = fixture.remove(false, true);
        assert_success(&output);
        children.assert_exact_coordinator_and_broker_retired();
        fixture.assert_no_starting_or_registered_entry();
    }

    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("stale-starting-mismatches", "adapter one\n");
    assert_success(&fixture.install(&bundle));
    let boundary = "after-broker-proof-before-descriptor";
    let mut children = fixture.start_managed_coordinator_paused(boundary);
    let starting = fixture.wait_for_starting_registry(boundary, &mut children);
    let registry = fixture.stable_root().join("starting-process-registry.json");
    let original = serde_json::to_vec(&starting).unwrap();

    for mismatch in stale_starting_reservation_mismatch_matrix() {
        eprintln!("stale-starting case={mismatch} phase=reject");
        let mut mismatched = starting.clone();
        let entry = &mut mismatched["entries"][0];
        match mismatch {
            "CoordinatorPidReused" => {
                entry["coordinator_start"] = json!("reused-coordinator-start");
            }
            "BrokerPidReused" => {
                entry["broker"]["broker_start"] = json!("reused-broker-start");
            }
            "ExecutableMismatch" => {
                entry["executable_path"] = json!("/usr/bin/false");
                entry["broker"]["executable_path"] = json!("/usr/bin/false");
            }
            "DigestMismatch" => {
                entry["executable_digest"] = json!("0".repeat(64));
                entry["broker"]["executable_digest"] = json!("0".repeat(64));
            }
            "GenerationMismatch" => {
                entry["expected_generation"] = json!("0".repeat(32));
            }
            "WorkspaceMismatch" => {
                entry["workspace_id"] = json!("different-workspace");
            }
            _ => unreachable!(),
        }
        fs::write(&registry, serde_json::to_vec(&mismatched).unwrap()).unwrap();
        let expected_bytes = fs::read(&registry).unwrap();
        let output = fixture.remove(false, true);
        assert_failure_code(&output, "owned_process_mismatch");
        assert_eq!(
            fs::read(&registry).unwrap(),
            expected_bytes,
            "{mismatch} mutated its registry bytes"
        );
        children.assert_exact_coordinator_and_broker_live();
        fs::write(&registry, &original).unwrap();
    }

    fixture.herdr().set_unregister_success_and_plugin_absent();
    let output = fixture.remove(false, true);
    assert_success(&output);
    children.assert_exact_coordinator_and_broker_retired();
    fixture.assert_no_starting_or_registered_entry();
}

#[cfg(target_os = "linux")]
fn linux_process_state_and_group(pid: u32) -> Option<(u8, u32)> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields = stat
        .rsplit_once(") ")?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    let state = *fields.first()?.as_bytes().first()?;
    let process_group = fields.get(2)?.parse().ok()?;
    Some((state, process_group))
}

#[cfg(target_os = "linux")]
fn process_is_live(pid: u32) -> bool {
    linux_process_state_and_group(pid).is_some_and(|(state, _)| state != b'Z')
}

#[cfg(not(target_os = "linux"))]
fn process_is_live(pid: u32) -> bool {
    Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn mutate_first_registry_entry(contents: &str, field: usize, replacement: &str) -> String {
    let mut lines = contents.lines().map(str::to_owned).collect::<Vec<_>>();
    let mut fields = lines[1].split('|').map(str::to_owned).collect::<Vec<_>>();
    fields[field] = replacement.to_owned();
    lines[1] = fields.join("|");
    format!("{}\n", lines.join("\n"))
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_failure_code(output: &Output, code: &str) {
    assert!(!output.status.success(), "command unexpectedly succeeded");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(code),
        "missing {code:?} in stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_failure_code_one_of(output: &Output, codes: &[&str]) {
    assert!(!output.status.success(), "command unexpectedly succeeded");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        codes.iter().any(|code| stderr.contains(code)),
        "missing one of {codes:?} in stderr: {stderr}"
    );
}

#[test]
fn install_records_ready_state_and_private_native_dispatch_assets() {
    // Break caught: publishing the manifest before its native helper/pointer generation is
    // private and durable permits a shell/path swap at the lifecycle security boundary.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");

    let output = fixture.install(&bundle);
    assert_success(&output);

    let record = fixture.record();
    assert_eq!(record["schema_version"], OWNERSHIP_SCHEMA);
    assert_eq!(record["state"], "Ready");
    assert_eq!(record["plugin_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(record["install_kind"], "managed");
    for field in [
        "broker_digest",
        "pi_package_digest",
        "pi_package_source",
        "rescue_path",
    ] {
        assert!(
            record[field]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
    }
    assert!(
        record["owned_files"]
            .as_array()
            .is_some_and(|files| !files.is_empty())
    );

    let helper = fixture.plugin_root.join("libexec/herdr-a2a-dispatch");
    let pointer = fixture.plugin_root.join("stable-bin-path");
    let helper_metadata = fs::symlink_metadata(&helper).unwrap();
    let pointer_metadata = fs::symlink_metadata(&pointer).unwrap();
    assert!(helper_metadata.is_file());
    assert!(pointer_metadata.is_file());
    assert_eq!(helper_metadata.uid(), rustix::process::getuid().as_raw());
    assert_eq!(pointer_metadata.uid(), rustix::process::getuid().as_raw());
    assert_eq!(helper_metadata.nlink(), 1);
    assert_eq!(pointer_metadata.nlink(), 1);
    assert_eq!(helper_metadata.mode() & 0o777, 0o700);
    assert_eq!(pointer_metadata.mode() & 0o777, 0o600);
    let pointed_binary = fs::read_to_string(&pointer).unwrap();
    assert_eq!(pointed_binary.lines().count(), 1);
    assert!(pointed_binary.ends_with('\n'));
    assert!(!pointed_binary.ends_with("\n\n"));
    assert!(Path::new(pointed_binary.trim_end()).is_absolute());
    assert_eq!(fixture.packages(), [fixture.package_source()]);
}

#[test]
fn update_replaces_only_the_exact_owned_pi_entry_and_owned_files() {
    // Break caught: changing exact source equality to prefix matching removes the unrelated
    // user package whose source begins with the old managed path.
    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&first));
    let old_source = fixture.package_source();
    let unrelated_prefix = format!("{old_source}-user-package");
    fixture.set_packages(vec![
        json!("user-package"),
        json!({ "source": unrelated_prefix, "extensions": ["custom.ts"] }),
    ]);
    fs::write(fixture.stable_root().join("unrelated.txt"), "keep\n").unwrap();
    let second = fixture.bundle("2.0.0", "adapter two\n");

    let output = fixture.install(&second);
    assert_success(&output);

    let new_source = fixture.package_source();
    assert_ne!(new_source, old_source);
    assert_eq!(
        fixture.packages(),
        ["user-package".to_owned(), unrelated_prefix, new_source]
    );
    assert_eq!(
        fs::read_to_string(fixture.stable_root().join("unrelated.txt")).unwrap(),
        "keep\n"
    );
}

#[test]
fn detected_pi_failure_rolls_back_without_an_ownership_record() {
    // Break caught: committing ownership before Pi's supported installer succeeds can report
    // Ready after a detected-but-unconfigurable Pi installation.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    let output = fixture
        .command()
        .env("HERDR_A2A_TEST_PI_MODE", "install_then_fail")
        .args(["managed", "install", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();

    assert_failure_code(&output, "pi_configuration_failed");
    assert!(!fixture.ownership_path().exists());
    assert!(
        !fixture
            .plugin_root
            .join("libexec/herdr-a2a-dispatch")
            .exists()
    );
    assert!(!fixture.plugin_root.join("stable-bin-path").exists());
    assert!(fixture.packages().is_empty());
}

#[test]
fn failed_update_restores_the_prior_complete_generation() {
    // Break caught: discarding the prior record/generation before Pi succeeds leaves a partial
    // update and loses the last working helper pointer.
    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&first));
    let prior_record = fs::read(fixture.ownership_path()).unwrap();
    let prior_pointer = fs::read(fixture.plugin_root.join("stable-bin-path")).unwrap();
    let prior_source = fixture.package_source();
    let second = fixture.bundle("2.0.0", "adapter two\n");

    let output = fixture
        .command()
        .env("HERDR_A2A_TEST_PI_MODE", "install_then_fail")
        .args(["managed", "install", "--bundle"])
        .arg(&second)
        .output()
        .unwrap();

    assert_failure_code(&output, "pi_configuration_failed");
    assert_eq!(fs::read(fixture.ownership_path()).unwrap(), prior_record);
    assert_eq!(
        fs::read(fixture.plugin_root.join("stable-bin-path")).unwrap(),
        prior_pointer
    );
    assert_eq!(fixture.packages(), [prior_source]);
}

#[test]
fn ownership_commit_failure_restores_pi_and_the_prior_generation() {
    // Break caught: rolling back only filesystem assets after Pi succeeds leaves the new package
    // configured without the ownership record that authorizes it.
    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&first));
    let prior_record = fs::read(fixture.ownership_path()).unwrap();
    let prior_pointer = fs::read(fixture.plugin_root.join("stable-bin-path")).unwrap();
    let prior_source = fixture.package_source();
    let second = fixture.bundle("2.0.0", "adapter two\n");

    let output = fixture
        .command()
        .env("HERDR_A2A_TEST_FAIL_BEFORE_RECORD_COMMIT", "1")
        .args(["managed", "install", "--bundle"])
        .arg(&second)
        .output()
        .unwrap();

    assert_failure_code(&output, "ownership_commit_failed");
    assert_eq!(fs::read(fixture.ownership_path()).unwrap(), prior_record);
    assert_eq!(
        fs::read(fixture.plugin_root.join("stable-bin-path")).unwrap(),
        prior_pointer
    );
    assert_eq!(fixture.packages(), [prior_source]);
}

#[test]
fn interrupted_plugin_swap_is_restored_from_the_prior_record() {
    // Break caught: process death after helper/pointer publication but before ownership commit
    // leaves the prior record unable to validate unless repair reconciles the retained backups.
    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&first));
    let prior_record = fs::read(fixture.ownership_path()).unwrap();
    let prior_pointer = fs::read(fixture.plugin_root.join("stable-bin-path")).unwrap();
    let prior_source = fixture.package_source();
    let second = fixture.bundle("2.0.0", "adapter two\n");

    let interrupted = fixture
        .command()
        .env("HERDR_A2A_TEST_ABORT_AFTER_PLUGIN_SWAP", "1")
        .args(["managed", "install", "--bundle"])
        .arg(&second)
        .output()
        .unwrap();
    assert!(!interrupted.status.success());
    assert_eq!(fs::read(fixture.ownership_path()).unwrap(), prior_record);
    assert_ne!(
        fs::read(fixture.plugin_root.join("stable-bin-path")).unwrap(),
        prior_pointer
    );

    assert_success(&fixture.repair());
    assert_eq!(
        fs::read(fixture.plugin_root.join("stable-bin-path")).unwrap(),
        prior_pointer
    );
    assert_eq!(fixture.packages(), [prior_source]);
    assert!(
        fs::read_dir(fixture.plugin_root.join("libexec"))
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".herdr-a2a-backup-"))
    );
}

#[test]
fn pre_round3_install_journal_with_legacy_v3_record_recovers_exactly() {
    // Break caught: InstallTransaction embeds OwnershipRecord directly, so adding a mandatory
    // field prevents deserialization before an interrupted predecessor update can roll back.
    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    let second = fixture.bundle("2.0.0", "adapter two\n");
    assert_success(&fixture.install(&first));
    let prior_record = fs::read(fixture.ownership_path()).unwrap();
    let prior_source = fixture.package_source();

    let interrupted = fixture
        .command()
        .env("HERDR_A2A_TEST_ABORT_AFTER_PLUGIN_SWAP", "1")
        .args(["managed", "install", "--bundle"])
        .arg(&second)
        .output()
        .unwrap();
    assert!(!interrupted.status.success());
    let journal_path = fixture.stable_root().join("install-transaction.json");
    let mut journal: Value = serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
    journal["prior_record"]
        .as_object_mut()
        .unwrap()
        .remove("purge_authority");
    if let Some(record) = journal["new_record"].as_object_mut() {
        record.remove("purge_authority");
    }
    fs::write(&journal_path, serde_json::to_vec_pretty(&journal).unwrap()).unwrap();
    fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();

    assert_success(&fixture.repair());
    assert_eq!(fs::read(fixture.ownership_path()).unwrap(), prior_record);
    assert_eq!(fixture.packages(), [prior_source]);
    assert!(!journal_path.exists());
}

#[test]
fn predecessor_pi_mutated_journal_completes_authenticated_upgrade() {
    // Break caught: the predecessor published rescue assets before PiMutated but stored no
    // new_record, so current rollback skipped rescue restoration and could not prove the prior
    // ownership record after an interrupted upgrade. Because the predecessor retained no prior
    // notice bytes, recovery must authenticate and durably complete the already-published update.
    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    let second = fixture.bundle("2.0.0", "adapter two\n");
    assert_success(&fixture.install(&first));
    let prior_record = fs::read(fixture.ownership_path()).unwrap();
    let rescue = fixture.stable_root().join("rescue/uninstall.sh");
    let marker = fixture.stable_root().join("rescue/owner-v1");
    let prior_notice = fs::read(&rescue).unwrap();
    let prior_marker = fs::read(&marker).unwrap();
    let template = fixture.plugin_root.join("scripts/uninstall.sh");
    let mut changed_template = fs::read(&template).unwrap();
    changed_template.extend_from_slice(b"\n# predecessor update template\n");
    fs::write(&template, changed_template).unwrap();
    fs::set_permissions(&template, fs::Permissions::from_mode(0o600)).unwrap();

    let interrupted = fixture
        .command()
        .env("HERDR_A2A_TEST_ABORT_AFTER_RECORD_RENAME", "1")
        .args(["managed", "install", "--bundle"])
        .arg(&second)
        .output()
        .unwrap();
    assert!(!interrupted.status.success());
    let updated_notice = fs::read(&rescue).unwrap();
    let updated_marker = fs::read(&marker).unwrap();
    assert_ne!(updated_marker, prior_marker);

    let journal_path = fixture.stable_root().join("install-transaction.json");
    let mut journal: Value = serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
    journal["schema_version"] = json!(2);
    journal["phase"] = json!("PiMutated");
    journal["new_record"] = Value::Null;
    journal
        .as_object_mut()
        .unwrap()
        .remove("prior_rescue_notice");
    journal
        .as_object_mut()
        .unwrap()
        .remove("prior_rescue_marker");
    fs::write(&journal_path, serde_json::to_vec_pretty(&journal).unwrap()).unwrap();
    fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(fixture.ownership_path(), &prior_record).unwrap();
    fs::set_permissions(fixture.ownership_path(), fs::Permissions::from_mode(0o600)).unwrap();

    fs::write(&rescue, "tampered predecessor rescue\n").unwrap();
    fs::set_permissions(&rescue, fs::Permissions::from_mode(0o600)).unwrap();
    let rejected = fixture.repair();
    assert_failure_code(&rejected, "recovery_needed");
    assert_eq!(
        fs::read_to_string(&rescue).unwrap(),
        "tampered predecessor rescue\n"
    );
    assert!(journal_path.exists());
    fs::write(&rescue, &updated_notice).unwrap();
    fs::set_permissions(&rescue, fs::Permissions::from_mode(0o600)).unwrap();

    let recovery_interrupted = fixture
        .command()
        .env("HERDR_A2A_TEST_ABORT_AFTER_RECORD_RENAME", "1")
        .args(["managed", "repair", "--startup"])
        .output()
        .unwrap();
    assert!(!recovery_interrupted.status.success());
    assert!(journal_path.exists());
    assert_success(&fixture.repair());
    assert_ne!(fs::read(fixture.ownership_path()).unwrap(), prior_record);
    assert_eq!(fs::read(&rescue).unwrap(), updated_notice);
    assert_eq!(fs::read(&marker).unwrap(), updated_marker);
    assert_eq!(fixture.record()["state"], "Ready");
    assert_ne!(fs::read(&rescue).unwrap(), prior_notice);
    assert!(!journal_path.exists());
}

#[test]
fn predecessor_pi_mutating_journal_rolls_back_authenticated_rescue_assets() {
    // Break caught: the predecessor published rescue assets before entering PiMutating, but the
    // rollback path treated a missing new_record as proof that rescue publication never happened.
    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    let second = fixture.bundle("2.0.0", "adapter two\n");
    assert_success(&fixture.install(&first));
    let prior_record = fs::read(fixture.ownership_path()).unwrap();
    let prior_source = fixture.package_source();
    let rescue = fixture.stable_root().join("rescue/uninstall.sh");
    let marker = fixture.stable_root().join("rescue/owner-v1");
    let prior_notice = fs::read(&rescue).unwrap();
    let prior_marker = fs::read(&marker).unwrap();

    let interrupted = fixture
        .command()
        .env("HERDR_A2A_TEST_ABORT_AFTER_RECORD_RENAME", "1")
        .args(["managed", "install", "--bundle"])
        .arg(&second)
        .output()
        .unwrap();
    assert!(!interrupted.status.success());
    assert_ne!(fs::read(&marker).unwrap(), prior_marker);

    let journal_path = fixture.stable_root().join("install-transaction.json");
    let mut journal: Value = serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
    journal["schema_version"] = json!(2);
    journal["phase"] = json!("PiMutating");
    journal["new_record"] = Value::Null;
    journal
        .as_object_mut()
        .unwrap()
        .remove("prior_rescue_notice");
    journal
        .as_object_mut()
        .unwrap()
        .remove("prior_rescue_marker");
    fs::write(&journal_path, serde_json::to_vec_pretty(&journal).unwrap()).unwrap();
    fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(fixture.ownership_path(), &prior_record).unwrap();
    fs::set_permissions(fixture.ownership_path(), fs::Permissions::from_mode(0o600)).unwrap();

    assert_success(&fixture.repair());
    assert_eq!(fs::read(fixture.ownership_path()).unwrap(), prior_record);
    assert_eq!(fs::read(&rescue).unwrap(), prior_notice);
    assert_eq!(fs::read(&marker).unwrap(), prior_marker);
    assert_eq!(fixture.packages(), [prior_source]);
    assert!(!journal_path.exists());
}

#[test]
fn legacy_schema_v2_pi_mutated_current_order_rolls_back_exact_prior_rescue() {
    // Break caught: phase-only predecessor detection treats a real schema-2 journal written by
    // the post-Pi rescue order as if it had already published new rescue assets. Exact live prior
    // rescue authentication must select rollback without weakening predecessor forward recovery.
    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    let second = fixture.bundle("2.0.0", "adapter two\n");
    assert_success(&fixture.install(&first));
    let prior_record = fs::read(fixture.ownership_path()).unwrap();
    let prior_pointer = fs::read(fixture.plugin_root.join("stable-bin-path")).unwrap();
    let prior_packages = fixture.packages();
    let rescue = fixture.stable_root().join("rescue/uninstall.sh");
    let marker = fixture.stable_root().join("rescue/owner-v1");
    let prior_rescue = fs::read(&rescue).unwrap();
    let prior_marker = fs::read(&marker).unwrap();

    let interrupted = fixture
        .command()
        .env("HERDR_A2A_TEST_ABORT_AFTER_PI_MUTATION", "1")
        .args(["managed", "install", "--bundle"])
        .arg(&second)
        .output()
        .unwrap();
    assert!(!interrupted.status.success());
    assert_eq!(fs::read(&rescue).unwrap(), prior_rescue);
    assert_eq!(fs::read(&marker).unwrap(), prior_marker);

    let journal_path = fixture.stable_root().join("install-transaction.json");
    let mut journal: Value = serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
    journal["schema_version"] = json!(2);
    assert_eq!(journal["phase"], "PiMutated");
    assert!(journal["new_record"].is_null());
    let interrupted_generation = PathBuf::from(journal["generation"].as_str().unwrap());
    fs::write(&journal_path, serde_json::to_vec_pretty(&journal).unwrap()).unwrap();
    fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();

    assert_success(&fixture.repair());
    assert_eq!(fs::read(fixture.ownership_path()).unwrap(), prior_record);
    assert_eq!(
        fs::read(fixture.plugin_root.join("stable-bin-path")).unwrap(),
        prior_pointer
    );
    assert_eq!(fixture.packages(), prior_packages);
    assert_eq!(fs::read(&rescue).unwrap(), prior_rescue);
    assert_eq!(fs::read(&marker).unwrap(), prior_marker);
    assert!(!interrupted_generation.exists());
    assert!(!journal_path.exists());
}

fn assert_plugin_rename_crash_recovers(fault: &str) {
    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&first));
    let prior_record = fs::read(fixture.ownership_path()).unwrap();
    let prior_pointer = fs::read(fixture.plugin_root.join("stable-bin-path")).unwrap();
    let prior_packages = fixture.packages();
    let second = fixture.bundle("2.0.0", "adapter two\n");

    let interrupted = fixture
        .command()
        .env(fault, "1")
        .args(["managed", "install", "--bundle"])
        .arg(&second)
        .output()
        .unwrap();
    assert!(
        !interrupted.status.success(),
        "fault did not abort: {fault}"
    );
    assert!(
        fixture
            .stable_root()
            .join("install-transaction.json")
            .exists()
    );

    assert_success(&fixture.repair());
    assert_eq!(fs::read(fixture.ownership_path()).unwrap(), prior_record);
    assert_eq!(
        fs::read(fixture.plugin_root.join("stable-bin-path")).unwrap(),
        prior_pointer
    );
    assert_eq!(fixture.packages(), prior_packages);
    assert!(
        !fixture
            .stable_root()
            .join("install-transaction.json")
            .exists()
    );
    assert!(
        fs::read_dir(&fixture.plugin_root)
            .unwrap()
            .chain(fs::read_dir(fixture.plugin_root.join("libexec")).unwrap())
            .all(|entry| {
                let name = entry.unwrap().file_name();
                let name = name.to_string_lossy();
                !name.starts_with(".managed-stage-")
                    && !name.starts_with(".herdr-a2a-backup-")
                    && !name.starts_with(".stable-bin-backup-")
            })
    );
}

#[test]
fn crash_after_helper_backup_rename_recovers_exactly() {
    // Break caught: a single PluginPublishing state cannot authenticate the first of four
    // plugin-swap renames, permanently stranding a valid update journal.
    assert_plugin_rename_crash_recovers("HERDR_A2A_TEST_ABORT_AFTER_HELPER_BACKUP_RENAME");
}

#[test]
fn crash_after_pointer_backup_rename_recovers_exactly() {
    // Break caught: recovery rejects the exact state with both prior assets in recorded backups.
    assert_plugin_rename_crash_recovers("HERDR_A2A_TEST_ABORT_AFTER_POINTER_BACKUP_RENAME");
}

#[test]
fn crash_after_helper_publish_rename_recovers_exactly() {
    // Break caught: recovery cannot authenticate a moved staged helper while the staged pointer
    // remains in the exact journal inventory.
    assert_plugin_rename_crash_recovers("HERDR_A2A_TEST_ABORT_AFTER_HELPER_PUBLISH_RENAME");
}

#[test]
fn crash_after_pointer_publish_rename_recovers_exactly() {
    // Break caught: the final rename can occur before the journal stores published snapshots.
    assert_plugin_rename_crash_recovers("HERDR_A2A_TEST_ABORT_AFTER_POINTER_PUBLISH_RENAME");
}

#[test]
fn staged_pointer_publish_failure_rolls_back_exactly() {
    // Break caught: local best-effort rollback leaves only the staged pointer while the durable
    // journal still authenticates a full two-file stage, making centralized recovery impossible.
    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&first));
    let prior_record = fs::read(fixture.ownership_path()).unwrap();
    let prior_pointer = fs::read(fixture.plugin_root.join("stable-bin-path")).unwrap();
    let second = fixture.bundle("2.0.0", "adapter two\n");

    let output = fixture
        .command()
        .env("HERDR_A2A_TEST_FAIL_POINTER_PUBLISH", "1")
        .args(["managed", "install", "--bundle"])
        .arg(second)
        .output()
        .unwrap();
    assert_failure_code(&output, "generation_failed");
    assert_eq!(fs::read(fixture.ownership_path()).unwrap(), prior_record);
    assert_eq!(
        fs::read(fixture.plugin_root.join("stable-bin-path")).unwrap(),
        prior_pointer
    );
    assert!(
        !fixture
            .stable_root()
            .join("install-transaction.json")
            .exists()
    );
}

#[test]
fn absent_pi_commits_pending_and_repair_configures_it_once() {
    // Break caught: treating a missing Pi binary as failure, or re-running Pi after the exact
    // managed package is present, violates pending and idempotent repair semantics.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    let empty_path = fixture.base.join("empty path");
    fs::create_dir(&empty_path).unwrap();
    let output = fixture
        .command()
        .env("PATH", &empty_path)
        .args(["managed", "install", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();
    assert_success(&output);
    assert_eq!(fixture.record()["state"], "PiAdapterPending");

    assert_success(&fixture.repair());
    assert_eq!(fixture.record()["state"], "Ready");
    let after_first_repair = fixture.pi_log();
    let installs_after_first_repair = after_first_repair
        .lines()
        .filter(|line| line.starts_with("install "))
        .count();
    let version_checks_after_first_repair = after_first_repair
        .lines()
        .filter(|line| *line == "--version")
        .count();
    assert_success(&fixture.repair());
    let after_second_repair = fixture.pi_log();
    assert_eq!(
        after_second_repair
            .lines()
            .filter(|line| line.starts_with("install "))
            .count(),
        installs_after_first_repair,
        "idempotent repair must not configure Pi twice"
    );
    assert_eq!(
        after_second_repair
            .lines()
            .filter(|line| *line == "--version")
            .count(),
        version_checks_after_first_repair + 1,
        "each repair must revalidate Pi compatibility before returning Ready"
    );
}

#[test]
fn concurrent_repairs_are_lock_serialized_and_idempotent() {
    // Break caught: checking Pi state before the installer lock lets two discovery hooks both
    // invoke `pi install` for the same exact source.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));
    fixture.set_packages(vec![]);

    let mut first = fixture.command();
    first
        .env("HERDR_A2A_TEST_PI_MODE", "slow")
        .args(["managed", "repair", "--startup"]);
    let mut second = fixture.command();
    second
        .env("HERDR_A2A_TEST_PI_MODE", "slow")
        .args(["managed", "repair", "--startup"]);
    let first = first.spawn().unwrap();
    let second = second.spawn().unwrap();
    assert!(first.wait_with_output().unwrap().status.success());
    assert!(second.wait_with_output().unwrap().status.success());

    let installs = fixture
        .pi_log()
        .lines()
        .filter(|line| line.starts_with("install "))
        .count();
    assert_eq!(
        installs, 2,
        "one initial install plus one serialized repair"
    );
}

#[test]
fn modified_owned_asset_is_a_conflict_not_an_overwrite() {
    // Break caught: trusting paths in the record without re-hashing them overwrites a user's
    // modification during update.
    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&first));
    let source = PathBuf::from(fixture.package_source());
    fs::write(
        source.join("extensions/herdr-a2a.ts"),
        "user modification\n",
    )
    .unwrap();
    let second = fixture.bundle("2.0.0", "adapter two\n");

    let output = fixture.install(&second);
    assert_failure_code(&output, "owned_asset_modified");
    assert_eq!(
        fs::read_to_string(source.join("extensions/herdr-a2a.ts")).unwrap(),
        "user modification\n"
    );
}

#[test]
fn exact_legacy_checkout_package_is_adopted_but_modified_legacy_is_rejected() {
    // Break caught: adopting a legacy entry by basename/source prefix silently takes ownership
    // of an unrecognized or modified user package.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    let legacy = fixture
        .plugin_root
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("integrations/pi");
    copy_tree(&bundle.join("pi"), &legacy);
    fixture.set_packages(vec![json!(legacy.to_string_lossy())]);

    assert_success(&fixture.install(&bundle));
    assert_eq!(fixture.packages(), [fixture.package_source()]);

    let rejected = ManagedFixture::new();
    let rejected_bundle = rejected.bundle("1.0.0", "adapter one\n");
    let rejected_legacy = rejected
        .plugin_root
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("integrations/pi");
    copy_tree(&rejected_bundle.join("pi"), &rejected_legacy);
    fs::write(
        rejected_legacy.join("extensions/herdr-a2a.ts"),
        "modified legacy\n",
    )
    .unwrap();
    rejected.set_packages(vec![json!(rejected_legacy.to_string_lossy())]);
    let output = rejected.install(&rejected_bundle);
    assert_failure_code(&output, "legacy_package_conflict");
    assert_eq!(
        rejected.packages(),
        [rejected_legacy.to_string_lossy().into_owned()]
    );
}

#[test]
fn managed_plugin_root_hardens_group_writable_herdr_namespace() {
    // Break caught: Herdr 0.8.2 inherits umask 002 for its managed checkout, so rejecting every
    // group-writable component makes an ordinary clean Linux plugin installation impossible.
    let root = Builder::new()
        .prefix("herdr managed plugin root ")
        .tempdir()
        .unwrap();
    let base = root.path().canonicalize().unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    let config_parent = base.join("config");
    let herdr_config = config_parent.join("herdr");
    let plugin_root = herdr_config.join("plugins/.tmp-install-123-456/checkout/plugins/herdr");
    fs::create_dir_all(&plugin_root).unwrap();
    fs::write(
        plugin_root.join("herdr-plugin.toml"),
        b"version = \"0.1.8\"\n",
    )
    .unwrap();
    fs::set_permissions(
        plugin_root.join("herdr-plugin.toml"),
        fs::Permissions::from_mode(0o664),
    )
    .unwrap();
    fs::create_dir(plugin_root.join("scripts")).unwrap();
    fs::write(plugin_root.join("scripts/uninstall.sh"), b"#!/bin/sh\n").unwrap();
    fs::set_permissions(
        plugin_root.join("scripts"),
        fs::Permissions::from_mode(0o775),
    )
    .unwrap();
    fs::set_permissions(
        plugin_root.join("scripts/uninstall.sh"),
        fs::Permissions::from_mode(0o664),
    )
    .unwrap();
    fs::set_permissions(&config_parent, fs::Permissions::from_mode(0o755)).unwrap();
    for directory in [
        herdr_config.clone(),
        herdr_config.join("plugins"),
        herdr_config.join("plugins/.tmp-install-123-456"),
        herdr_config.join("plugins/.tmp-install-123-456/checkout"),
        herdr_config.join("plugins/.tmp-install-123-456/checkout/plugins"),
        plugin_root.clone(),
    ] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o775)).unwrap();
    }

    let output = Command::new(env!("CARGO_BIN_EXE_herdr-a2a"))
        .args([
            "managed",
            "validate-plugin-root",
            "--managed-install",
            "--path",
        ])
        .arg(&plugin_root)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "managed plugin-root preparation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::metadata(&config_parent).unwrap().permissions().mode() & 0o777,
        0o755,
        "the strict parent above the Herdr boundary changed"
    );
    for directory in [
        &herdr_config,
        &herdr_config.join("plugins"),
        &herdr_config.join("plugins/.tmp-install-123-456"),
        &herdr_config.join("plugins/.tmp-install-123-456/checkout"),
        &herdr_config.join("plugins/.tmp-install-123-456/checkout/plugins"),
    ] {
        assert_eq!(
            fs::metadata(directory).unwrap().permissions().mode() & 0o022,
            0,
            "{} remained writable outside its owner",
            directory.display()
        );
    }
    assert_eq!(
        fs::metadata(&plugin_root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(plugin_root.join("herdr-plugin.toml"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(plugin_root.join("scripts"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(plugin_root.join("scripts/uninstall.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn linked_plugin_root_does_not_harden_group_writable_checkout() {
    // Break caught: reusing managed preparation for linked development would silently chmod a
    // user's checkout instead of retaining the strict fail-closed contract.
    let root = Builder::new()
        .prefix("herdr linked plugin root ")
        .tempdir()
        .unwrap();
    let base = root.path().canonicalize().unwrap();
    let plugin_root = base.join("checkout/plugins/herdr");
    fs::create_dir_all(&plugin_root).unwrap();
    fs::set_permissions(&plugin_root, fs::Permissions::from_mode(0o775)).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_herdr-a2a"))
        .args(["managed", "validate-plugin-root", "--path"])
        .arg(&plugin_root)
        .output()
        .unwrap();

    assert_failure_code(&output, "unsafe_install_path");
    assert_eq!(
        fs::metadata(&plugin_root).unwrap().permissions().mode() & 0o777,
        0o775
    );
}

#[test]
fn managed_plugin_root_rejects_world_writable_namespace_without_mutation() {
    // Break caught: treating managed preparation as blanket chmod would accept a namespace that
    // any local account can replace while the installer is running.
    let root = Builder::new()
        .prefix("herdr shared plugin root ")
        .tempdir()
        .unwrap();
    let base = root.path().canonicalize().unwrap();
    let herdr_config = base.join("config/herdr");
    let plugin_root = herdr_config.join("plugins/.tmp-install-1/checkout/plugins/herdr");
    fs::create_dir_all(&plugin_root).unwrap();
    fs::set_permissions(&herdr_config, fs::Permissions::from_mode(0o777)).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_herdr-a2a"))
        .args([
            "managed",
            "validate-plugin-root",
            "--managed-install",
            "--path",
        ])
        .arg(&plugin_root)
        .output()
        .unwrap();

    assert_failure_code(&output, "unsafe_install_path");
    assert_eq!(
        fs::metadata(&herdr_config).unwrap().permissions().mode() & 0o777,
        0o777
    );
}

#[test]
fn managed_plugin_root_requires_exact_herdr_temporary_layout() {
    // Break caught: deriving a chmod boundary from an approximate path could modify an unrelated
    // user-owned tree supplied to the hidden validator.
    for suffix in [
        "plugins/.tmp-install-/checkout/plugins/herdr",
        "plugins/not-an-install/checkout/plugins/herdr",
        "plugins/.tmp-install-1/checkout/plugins/not-herdr",
    ] {
        let root = Builder::new()
            .prefix("herdr malformed plugin root ")
            .tempdir()
            .unwrap();
        let base = root.path().canonicalize().unwrap();
        let herdr_config = base.join("config/herdr");
        let plugin_root = herdr_config.join(suffix);
        fs::create_dir_all(&plugin_root).unwrap();
        fs::set_permissions(&herdr_config, fs::Permissions::from_mode(0o775)).unwrap();

        let output = Command::new(env!("CARGO_BIN_EXE_herdr-a2a"))
            .args([
                "managed",
                "validate-plugin-root",
                "--managed-install",
                "--path",
            ])
            .arg(&plugin_root)
            .output()
            .unwrap();

        assert_failure_code(&output, "unsafe_install_path");
        assert_eq!(
            fs::metadata(&herdr_config).unwrap().permissions().mode() & 0o777,
            0o775
        );
    }
}

#[test]
fn managed_plugin_root_rejects_symlinked_component_without_mutation() {
    // Break caught: lexical layout recognition must not permit openat traversal through a link
    // into another same-user directory.
    let root = Builder::new()
        .prefix("herdr linked managed root ")
        .tempdir()
        .unwrap();
    let base = root.path().canonicalize().unwrap();
    let herdr_config = base.join("config/herdr");
    let temporary = herdr_config.join("plugins/.tmp-install-1");
    let redirected = base.join("redirected/plugins/herdr");
    fs::create_dir_all(&temporary).unwrap();
    fs::create_dir_all(&redirected).unwrap();
    fs::set_permissions(&redirected, fs::Permissions::from_mode(0o775)).unwrap();
    symlink(base.join("redirected"), temporary.join("checkout")).unwrap();
    fs::set_permissions(&herdr_config, fs::Permissions::from_mode(0o775)).unwrap();
    let plugin_root = temporary.join("checkout/plugins/herdr");

    let output = Command::new(env!("CARGO_BIN_EXE_herdr-a2a"))
        .args([
            "managed",
            "validate-plugin-root",
            "--managed-install",
            "--path",
        ])
        .arg(&plugin_root)
        .output()
        .unwrap();

    assert_failure_code(&output, "unsafe_install_path");
    assert_eq!(
        fs::metadata(&redirected).unwrap().permissions().mode() & 0o777,
        0o775,
        "managed validation mutated a directory reached only through the symlink"
    );
    assert!(
        fs::symlink_metadata(temporary.join("checkout"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn linux_umask_002_clean_install_hardens_only_managed_namespaces() {
    // Break caught: an ordinary private-primary-group Linux account creates Pi configuration at
    // 0775/0664 and has no plugin-state directory before Herdr runs the plugin build.
    let fixture = ManagedFixture::new();
    let pi_root = fixture.home.join(".pi");
    let pi_agent = pi_root.join("agent");
    let pi_settings = pi_agent.join("settings.json");
    fs::create_dir_all(&pi_agent).unwrap();
    fs::write(
        &pi_settings,
        serde_json::to_vec_pretty(&json!({ "packages": [] })).unwrap(),
    )
    .unwrap();
    fs::set_permissions(&pi_root, fs::Permissions::from_mode(0o775)).unwrap();
    fs::set_permissions(&pi_agent, fs::Permissions::from_mode(0o775)).unwrap();
    fs::set_permissions(&pi_settings, fs::Permissions::from_mode(0o664)).unwrap();

    let state_base = fixture.base.join("managed state base");
    let plugin_state = state_base.join("herdr/plugins/herdr.a2a");
    fs::create_dir(&state_base).unwrap();
    fs::set_permissions(&state_base, fs::Permissions::from_mode(0o755)).unwrap();
    let home_mode = fs::metadata(&fixture.home).unwrap().permissions().mode() & 0o777;
    let state_base_mode = fs::metadata(&state_base).unwrap().permissions().mode() & 0o777;
    let bundle = fixture.bundle("linux umask 002", "adapter linux umask 002\n");
    let bundle_binary = fs::metadata(bundle.join("bin/herdr-a2a")).unwrap();
    assert_eq!(bundle_binary.uid(), rustix::process::getuid().as_raw());
    assert_eq!(bundle_binary.nlink(), 1);
    assert_eq!(bundle_binary.mode() & 0o777, 0o700);
    for file in [
        bundle.join("pi/package.json"),
        bundle.join("pi/extensions/herdr-a2a.ts"),
        bundle.join("pi/skills/herdr-a2a/SKILL.md"),
    ] {
        let metadata = fs::metadata(file).unwrap();
        assert_eq!(metadata.uid(), rustix::process::getuid().as_raw());
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.mode() & 0o777, 0o600);
    }

    let output = fixture
        .command()
        .env_remove("PI_CODING_AGENT_DIR")
        .env("HERDR_PLUGIN_STATE_DIR", &plugin_state)
        .env("HERDR_A2A_INSTALL_KIND", "managed")
        .args(["managed", "install", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();

    assert_success(&output);
    assert_eq!(fixture.record_state(), "Ready");
    for directory in [&pi_root, &pi_agent, &plugin_state] {
        assert_eq!(
            fs::metadata(directory).unwrap().permissions().mode() & 0o777,
            0o700,
            "{} was not made private",
            directory.display()
        );
    }
    assert_eq!(
        fs::metadata(&pi_settings).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&fixture.home).unwrap().permissions().mode() & 0o777,
        home_mode,
        "HOME permissions changed"
    );
    assert_eq!(
        fs::metadata(&state_base).unwrap().permissions().mode() & 0o777,
        state_base_mode,
        "state base permissions changed"
    );
}

#[test]
fn managed_pi_rejects_world_writable_namespace_without_mutation() {
    // Break caught: managed hardening may remove private-group write, but must never repair a
    // namespace writable by every local account.
    let fixture = ManagedFixture::new();
    let pi_root = fixture.home.join(".pi");
    let pi_agent = pi_root.join("agent");
    let pi_settings = pi_agent.join("settings.json");
    let settings_bytes = serde_json::to_vec_pretty(&json!({ "packages": [] })).unwrap();
    fs::create_dir_all(&pi_agent).unwrap();
    fs::write(&pi_settings, &settings_bytes).unwrap();
    fs::set_permissions(&pi_root, fs::Permissions::from_mode(0o777)).unwrap();
    fs::set_permissions(&pi_agent, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&pi_settings, fs::Permissions::from_mode(0o600)).unwrap();
    let bundle = fixture.bundle("unsafe Pi namespace", "unsafe Pi namespace\n");

    let output = fixture
        .command()
        .env_remove("PI_CODING_AGENT_DIR")
        .args(["managed", "install", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();

    assert_failure_code(&output, "unsafe_install_path");
    assert_eq!(
        fs::metadata(&pi_root).unwrap().permissions().mode() & 0o777,
        0o777
    );
    assert_eq!(fs::read(&pi_settings).unwrap(), settings_bytes);
}

#[test]
fn managed_pi_rejects_linked_settings_without_mutating_the_inode() {
    // Break caught: chmod-before-identity-validation would modify a multiply linked settings inode.
    let fixture = ManagedFixture::new();
    let pi_root = fixture.home.join(".pi");
    let pi_agent = pi_root.join("agent");
    let pi_settings = pi_agent.join("settings.json");
    let second_link = fixture.base.join("second settings link");
    fs::create_dir_all(&pi_agent).unwrap();
    fs::write(&pi_settings, b"{\"packages\": []}\n").unwrap();
    fs::set_permissions(&pi_root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&pi_agent, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&pi_settings, fs::Permissions::from_mode(0o664)).unwrap();
    fs::hard_link(&pi_settings, &second_link).unwrap();
    let bundle = fixture.bundle("linked Pi settings", "linked Pi settings\n");

    let output = fixture
        .command()
        .env_remove("PI_CODING_AGENT_DIR")
        .args(["managed", "install", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();

    assert_failure_code(&output, "pi_settings_unsafe");
    assert_eq!(
        fs::metadata(&pi_settings).unwrap().permissions().mode() & 0o777,
        0o664
    );
    assert_eq!(fs::metadata(&pi_settings).unwrap().nlink(), 2);
}

#[test]
fn managed_pi_rejects_symlinked_settings_without_mutating_the_target() {
    // Break caught: settings preparation must remain descriptor-relative and NOFOLLOW.
    let fixture = ManagedFixture::new();
    let pi_root = fixture.home.join(".pi");
    let pi_agent = pi_root.join("agent");
    let pi_settings = pi_agent.join("settings.json");
    let target = fixture.base.join("redirected settings.json");
    let target_bytes = b"{\"packages\": [\"unrelated\"]}\n";
    fs::create_dir_all(&pi_agent).unwrap();
    fs::write(&target, target_bytes).unwrap();
    fs::set_permissions(&pi_root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&pi_agent, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o664)).unwrap();
    symlink(&target, &pi_settings).unwrap();
    let bundle = fixture.bundle("symlinked Pi settings", "symlinked Pi settings\n");

    let output = fixture
        .command()
        .env_remove("PI_CODING_AGENT_DIR")
        .args(["managed", "install", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();

    assert_failure_code(&output, "pi_settings_unsafe");
    assert_eq!(fs::read(&target).unwrap(), target_bytes);
    assert_eq!(
        fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o664
    );
    assert!(
        fs::symlink_metadata(&pi_settings)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn managed_plugin_state_rejects_unbounded_or_linked_namespaces_without_mutation() {
    // Break caught: plugin-state creation is permitted only in the exact managed namespace, and
    // linked development must retain its pre-existing strict-directory contract.
    for case in ["malformed", "unsafe-parent", "linked-dev"] {
        let fixture = ManagedFixture::new();
        let bundle = fixture.bundle(case, &format!("plugin state {case}\n"));
        let state_base = fixture.base.join(format!("state discriminator {case}"));
        fs::create_dir(&state_base).unwrap();
        fs::set_permissions(&state_base, fs::Permissions::from_mode(0o755)).unwrap();
        let (plugin_state, install_kind) = match case {
            "malformed" => (state_base.join("not-herdr/plugins/herdr.a2a"), "managed"),
            "unsafe-parent" => {
                fs::set_permissions(&state_base, fs::Permissions::from_mode(0o777)).unwrap();
                (state_base.join("herdr/plugins/herdr.a2a"), "managed")
            }
            "linked-dev" => {
                let state = state_base.join("linked state");
                fs::create_dir(&state).unwrap();
                fs::set_permissions(&state, fs::Permissions::from_mode(0o775)).unwrap();
                (state, "linked-dev")
            }
            _ => unreachable!(),
        };
        let before_mode = fs::metadata(&state_base).unwrap().permissions().mode() & 0o777;

        let output = fixture
            .command()
            .env("HERDR_PLUGIN_STATE_DIR", &plugin_state)
            .env("HERDR_A2A_INSTALL_KIND", install_kind)
            .args(["managed", "install", "--bundle"])
            .arg(&bundle)
            .output()
            .unwrap();

        assert_failure_code(&output, "unsafe_install_path");
        assert_eq!(
            fs::metadata(&state_base).unwrap().permissions().mode() & 0o777,
            before_mode,
            "{case} changed the strict state parent"
        );
        if case == "linked-dev" {
            assert_eq!(
                fs::metadata(&plugin_state).unwrap().permissions().mode() & 0o777,
                0o775
            );
        } else {
            assert!(!plugin_state.exists(), "{case} created plugin-state data");
            assert_eq!(
                fs::read_dir(&state_base).unwrap().count(),
                0,
                "{case} created a sibling inside the strict state parent"
            );
        }
        assert!(
            !fixture
                .plugin_root
                .join("libexec/herdr-a2a-dispatch")
                .exists()
        );
        assert!(!fixture.plugin_root.join("stable-bin-path").exists());
    }
}

#[test]
fn symlinked_or_unsafe_install_paths_are_rejected() {
    // Break caught: following a stable-root symlink or accepting a writable plugin root lets an
    // attacker redirect helper, pointer, and ownership writes.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    let redirected = fixture.base.join("redirected");
    fs::create_dir(&redirected).unwrap();
    fs::create_dir_all(fixture.stable_root().parent().unwrap()).unwrap();
    symlink(&redirected, fixture.stable_root()).unwrap();
    let output = fixture.install(&bundle);
    assert_failure_code(&output, "unsafe_install_path");

    let unsafe_fixture = ManagedFixture::new();
    let unsafe_bundle = unsafe_fixture.bundle("1.0.0", "adapter one\n");
    fs::set_permissions(
        &unsafe_fixture.plugin_root,
        fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    let output = unsafe_fixture.install(&unsafe_bundle);
    assert_failure_code(&output, "unsafe_install_path");

    let state_fixture = ManagedFixture::new();
    let state_bundle = state_fixture.bundle("1.0.0", "adapter one\n");
    let unrelated_state = state_fixture.base.join("unrelated plugin state");
    fs::create_dir(&unrelated_state).unwrap();
    fs::write(unrelated_state.join("keep.txt"), "keep\n").unwrap();
    fs::remove_dir(&state_fixture.plugin_state).unwrap();
    symlink(&unrelated_state, &state_fixture.plugin_state).unwrap();
    let output = state_fixture.install(&state_bundle);
    assert_failure_code(&output, "unsafe_install_path");
    assert_eq!(
        fs::read_to_string(unrelated_state.join("keep.txt")).unwrap(),
        "keep\n"
    );
}

#[test]
fn helper_link_count_drift_is_rejected_by_repair() {
    // Break caught: path-only mode checks miss an extra hard link to the privileged native
    // dispatcher inode.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));
    let helper = fixture.plugin_root.join("libexec/herdr-a2a-dispatch");
    fs::hard_link(&helper, fixture.plugin_root.join("helper-extra-link")).unwrap();

    let output = fixture.repair();
    assert_failure_code(&output, "owned_asset_modified");
}

#[test]
fn pi_output_is_bounded_and_cannot_commit_install_state() {
    // Break caught: collecting unbounded child output permits a detected Pi executable to exhaust
    // installer memory before its failure can roll back.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    let output = fixture
        .command()
        .env("HERDR_A2A_TEST_PI_MODE", "noisy")
        .args(["managed", "install", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();

    assert_failure_code(&output, "pi_output_limit_exceeded");
    assert!(!fixture.ownership_path().exists());
}

#[test]
fn status_json_is_schema_versioned_and_reports_exact_state() {
    // Break caught: human-only or unversioned status output cannot be safely consumed by Doctor
    // and later removal workflows.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));

    let output = fixture
        .command()
        .args(["managed", "status", "--json"])
        .output()
        .unwrap();
    assert_success(&output);
    let status: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["schema_version"], OWNERSHIP_SCHEMA);
    assert_eq!(status["state"], "Ready");
    assert_eq!(status["pi_package_source"], fixture.package_source());
}

#[test]
fn event_repair_acts_only_for_pi_and_rejects_unbounded_json() {
    // Break caught: a generic pane discovery event repeatedly mutates Pi configuration or accepts
    // unbounded attacker-controlled event input.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));
    fixture.set_packages(vec![]);
    let initial_log = fixture.pi_log();

    let non_pi = fixture
        .command()
        .env(
            "HERDR_PLUGIN_EVENT_JSON",
            r#"{"event":"pane_agent_detected","data":{"pane_id":"w1:p2","workspace_id":"w1","agent":"claude","released":false}}"#,
        )
        .args(["managed", "repair", "--event"])
        .output()
        .unwrap();
    assert_success(&non_pi);
    assert_eq!(fixture.pi_log(), initial_log);

    let malformed = fixture
        .command()
        .env(
            "HERDR_PLUGIN_EVENT_JSON",
            r#"{"event":"pane_agent_detected","data":{"agent":["pi"]}}"#,
        )
        .args(["managed", "repair", "--event"])
        .output()
        .unwrap();
    assert_success(&malformed);
    assert_eq!(fixture.pi_log(), initial_log);

    let pi = fixture
        .command()
        .env(
            "HERDR_PLUGIN_EVENT_JSON",
            r#"{"event":"pane_agent_detected","data":{"pane_id":"w1:p2","workspace_id":"w1","agent":"pi","released":false}}"#,
        )
        .args(["managed", "repair", "--event"])
        .output()
        .unwrap();
    assert_success(&pi);
    assert!(String::from_utf8_lossy(&pi.stdout).contains("next Pi launch"));
    assert_eq!(fixture.packages(), [fixture.package_source()]);

    fixture.set_packages(vec![]);
    let legacy_pi = fixture
        .command()
        .env("HERDR_PLUGIN_EVENT_JSON", r#"{"pane":{"agent_kind":"pi"}}"#)
        .args(["managed", "repair", "--event"])
        .output()
        .unwrap();
    assert_success(&legacy_pi);
    assert_eq!(fixture.packages(), [fixture.package_source()]);

    let oversized = fixture
        .command()
        .env("HERDR_PLUGIN_EVENT_JSON", "x".repeat(70_000))
        .args(["managed", "repair", "--event"])
        .output()
        .unwrap();
    assert_failure_code(&oversized, "invalid_plugin_event");
}

#[test]
fn same_source_with_different_pi_entry_is_never_silently_adopted() {
    // Break caught: reducing Pi ownership to its source string adopts user filters/fields that
    // were never written or recorded by this installer.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));
    let source = fixture.package_source();
    fixture.set_packages(vec![json!({
        "source": source,
        "extensions": ["user-owned.ts"],
        "enabled": false
    })]);

    let output = fixture.repair();
    assert_failure_code(&output, "ownership_conflict");
    assert_eq!(fixture.record()["state"], "Failed");
    assert_eq!(
        serde_json::from_slice::<Value>(
            &fs::read(fixture.pi_agent_dir.join("settings.json")).unwrap()
        )
        .unwrap()["packages"][0]["extensions"][0],
        "user-owned.ts"
    );
}

#[test]
fn first_install_plugin_crash_is_reconciled_from_durable_intent() {
    // Break caught: publishing helper/pointer before a durable first-install intent leaves assets
    // that no ownership record can authorize or roll back after process death.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    let interrupted = fixture
        .command()
        .env("HERDR_A2A_TEST_ABORT_AFTER_PLUGIN_SWAP", "1")
        .args(["managed", "install", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(!interrupted.status.success());
    assert!(!fixture.ownership_path().exists());
    assert!(
        fixture
            .stable_root()
            .join("install-transaction.json")
            .exists()
    );

    assert_success(&fixture.install(&bundle));
    assert!(
        !fixture
            .stable_root()
            .join("install-transaction.json")
            .exists()
    );
    assert_eq!(fixture.record()["state"], "Ready");
}

#[test]
fn crash_after_pi_mutation_is_rolled_back_before_retry() {
    // Break caught: Pi mutation without a durable journal leaves an orphaned new package when the
    // process dies before ownership commit.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    let interrupted = fixture
        .command()
        .env("HERDR_A2A_TEST_ABORT_AFTER_PI_MUTATION", "1")
        .args(["managed", "install", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(!interrupted.status.success());
    assert!(!fixture.ownership_path().exists());
    assert_eq!(fixture.packages().len(), 1);

    assert_success(&fixture.install(&bundle));
    assert_eq!(fixture.packages(), [fixture.package_source()]);
    assert!(
        !fixture
            .stable_root()
            .join("install-transaction.json")
            .exists()
    );
}

#[test]
fn post_rename_record_failures_restore_record_before_assets() {
    // Break caught: treating every write_record error as pre-commit can leave the new record
    // naming assets and Pi state that the error path already rolled back.
    for fault in [
        "HERDR_A2A_TEST_FAIL_AFTER_RECORD_RENAME",
        "HERDR_A2A_TEST_FAIL_AFTER_RECORD_DIR_SYNC",
    ] {
        let fixture = ManagedFixture::new();
        let first = fixture.bundle("1.0.0", "adapter one\n");
        assert_success(&fixture.install(&first));
        let prior_record = fs::read(fixture.ownership_path()).unwrap();
        let prior_pointer = fs::read(fixture.plugin_root.join("stable-bin-path")).unwrap();
        let prior_packages = fixture.packages();
        let second = fixture.bundle("2.0.0", "adapter two\n");

        let output = fixture
            .command()
            .env(fault, "1")
            .args(["managed", "install", "--bundle"])
            .arg(second)
            .output()
            .unwrap();
        assert_failure_code(&output, "ownership_commit_failed");
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("rollback remains incomplete"),
            "{fault} did not complete rollback: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read(fixture.ownership_path()).unwrap(), prior_record);
        assert_eq!(
            fs::read(fixture.plugin_root.join("stable-bin-path")).unwrap(),
            prior_pointer
        );
        assert_eq!(fixture.packages(), prior_packages);
        let transaction_path = fixture.stable_root().join("install-transaction.json");
        assert!(
            !transaction_path.exists(),
            "{fault} retained a completed rollback transaction: {}",
            fs::read_to_string(&transaction_path).unwrap_or_default()
        );
        assert_success(&fixture.repair());
    }
}

#[test]
fn unrecorded_generation_entries_block_update_without_deletion() {
    // Break caught: remove_dir_all on a prior generation silently deletes files the ownership
    // record never authorized the installer to remove.
    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&first));
    let old_source = PathBuf::from(fixture.package_source());
    let extra = old_source.parent().unwrap().join("user-extra.txt");
    fs::write(&extra, "preserve me\n").unwrap();
    let second = fixture.bundle("2.0.0", "adapter two\n");

    let output = fixture.install(&second);
    assert_failure_code(&output, "ownership_conflict");
    assert_eq!(fs::read_to_string(&extra).unwrap(), "preserve me\n");
}

#[test]
fn lock_symlink_is_rejected_without_mutating_its_target() {
    // Break caught: opening/chmodding install.lock by path follows a symlink and changes an
    // unrelated inode before the separately reopened validation detects it.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    fs::create_dir_all(fixture.stable_root()).unwrap();
    fs::set_permissions(fixture.stable_root(), fs::Permissions::from_mode(0o700)).unwrap();
    let target = fixture.base.join("unrelated-lock-target");
    fs::write(&target, "keep\n").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
    symlink(&target, fixture.stable_root().join("install.lock")).unwrap();

    let output = fixture.install(&bundle);
    assert_failure_code(&output, "installer_lock_failed");
    assert_eq!(fs::metadata(&target).unwrap().mode() & 0o777, 0o640);
    assert_eq!(fs::read_to_string(target).unwrap(), "keep\n");
}

#[test]
fn lock_directory_entry_replacement_is_detected_after_flock() {
    // Break caught: validating a separately reopened pathname instead of the locked descriptor
    // lets contenders lock a replacement inode while this process believes it owns exclusion.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    let output = fixture
        .command()
        .env("HERDR_A2A_TEST_REPLACE_LOCK_BEFORE_RECHECK", "1")
        .args(["managed", "install", "--bundle"])
        .arg(bundle)
        .output()
        .unwrap();
    assert_failure_code(&output, "installer_lock_failed");
    assert!(!fixture.ownership_path().exists());
}

#[test]
fn status_locks_and_reports_semantic_record_drift_as_failed() {
    // Break caught: deserializing and echoing state without semantic validation reports Ready
    // after an owned asset or canonical relationship has drifted.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));
    fs::write(
        PathBuf::from(fixture.package_source()).join("extensions/herdr-a2a.ts"),
        "drift\n",
    )
    .unwrap();

    let output = fixture.status_json();
    assert_success(&output);
    let status: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["state"], "Failed");
    assert!(status["last_error"].as_str().unwrap().contains("modified"));
}

#[test]
fn pending_status_rejects_same_source_custom_and_duplicate_entries() {
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    let empty = fixture.base.join("no-pi");
    fs::create_dir(&empty).unwrap();
    let output = fixture
        .command()
        .env("PATH", &empty)
        .args(["managed", "install", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();
    assert_success(&output);
    let source = fixture.package_source();
    for entries in [
        vec![json!({"source": source, "extensions": ["custom.ts"]})],
        vec![json!(source), json!(source)],
    ] {
        fixture.set_packages(entries);
        let output = fixture.status_json();
        assert_success(&output);
        let status: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(status["state"], "Failed");
    }
}

#[test]
fn safe_read_only_pi_settings_mode_is_accepted() {
    // Break caught: requiring exact 0600 rejects a same-owner, regular, single-link settings file
    // even though group/other cannot write it.
    let fixture = ManagedFixture::new();
    fs::set_permissions(
        fixture.pi_agent_dir.join("settings.json"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&bundle));
}

#[test]
fn persisted_paths_reject_line_breaks_and_non_utf8() {
    // Break caught: lossy/line-oriented path serialization can create an empty or multi-line
    // stable pointer and a Pi source that cannot be compared exactly.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    let persisted_root_variable = if cfg!(target_os = "macos") {
        "HOME"
    } else {
        "XDG_DATA_HOME"
    };
    let newline_root = fixture.base.join("home\nline");
    fs::create_dir(&newline_root).unwrap();
    let output = fixture
        .command()
        .env(persisted_root_variable, &newline_root)
        .args(["managed", "install", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();
    assert_failure_code(&output, "unsafe_install_path");

    let non_utf8_root = fixture
        .base
        .join(std::ffi::OsString::from_vec(vec![b'h', b'o', 0xff]));
    let output = fixture
        .command()
        .env(persisted_root_variable, &non_utf8_root)
        .args(["managed", "install", "--bundle"])
        .arg(bundle)
        .output()
        .unwrap();
    assert_failure_code(&output, "unsafe_install_path");
}

#[test]
fn malformed_record_relationship_matrix_reports_failed_status() {
    // Break caught: schema-only deserialization accepts duplicate paths and unrelated canonical
    // fields, allowing Doctor/status to echo a forged Ready state.
    for mutation in 0..4 {
        let fixture = ManagedFixture::new();
        let bundle = fixture.bundle("1.0.0", "adapter one\n");
        assert_success(&fixture.install(&bundle));
        let mut record = fixture.record();
        match mutation {
            0 => {
                let duplicate = record["owned_files"][0].clone();
                record["owned_files"]
                    .as_array_mut()
                    .unwrap()
                    .push(duplicate);
            }
            1 => record["stable_binary"] = record["pi_package_source"].clone(),
            2 => {
                record["rescue_path"] = json!(fixture.base.join("foreign-rescue").to_string_lossy())
            }
            3 => {
                record["pi_package_entry"] = json!({
                    "source": fixture.package_source(),
                    "extensions": ["foreign.ts"]
                })
            }
            _ => unreachable!(),
        }
        fs::write(
            fixture.ownership_path(),
            serde_json::to_vec_pretty(&record).unwrap(),
        )
        .unwrap();
        fs::set_permissions(fixture.ownership_path(), fs::Permissions::from_mode(0o600)).unwrap();
        let output = fixture.status_json();
        assert_success(&output);
        let status: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(status["state"], "Failed", "mutation {mutation}");
    }
}

#[test]
fn every_durable_install_phase_recovers_after_process_death() {
    // Break caught: journaling only the plugin-swap phase misses generation, record-rename, and
    // committed-cleanup crashes on first install or update.
    for fault in [
        "HERDR_A2A_TEST_ABORT_AFTER_GENERATION",
        "HERDR_A2A_TEST_ABORT_AFTER_RESCUE_NOTICE",
        "HERDR_A2A_TEST_ABORT_AFTER_RECORD_RENAME",
        "HERDR_A2A_TEST_ABORT_AFTER_RECORD_COMMITTED",
    ] {
        let fixture = ManagedFixture::new();
        let bundle = fixture.bundle("1.0.0", "adapter one\n");
        let interrupted = fixture
            .command()
            .env(fault, "1")
            .args(["managed", "install", "--bundle"])
            .arg(&bundle)
            .output()
            .unwrap();
        assert!(!interrupted.status.success(), "fault {fault}");
        assert!(
            fixture
                .stable_root()
                .join("install-transaction.json")
                .exists()
        );
        assert_success(&fixture.install(&bundle));
        assert_eq!(fixture.record()["state"], "Ready");
        assert!(
            !fixture
                .stable_root()
                .join("install-transaction.json")
                .exists()
        );
    }
}

#[test]
fn rescue_publication_rollback_restores_prior_bytes_after_plugin_template_changes() {
    // Break caught: rollback reconstructed the prior rescue notice from the current plugin
    // template, which cannot recover an update when that template changed between versions.
    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&first));
    let rescue = fixture.stable_root().join("rescue/uninstall.sh");
    let marker = fixture.stable_root().join("rescue/owner-v1");
    let prior_notice = fs::read(&rescue).unwrap();
    let prior_marker = fs::read(&marker).unwrap();

    let template = fixture.plugin_root.join("scripts/uninstall.sh");
    let mut changed_template = fs::read(&template).unwrap();
    changed_template.extend_from_slice(b"\n# updated plugin template\n");
    fs::write(&template, &changed_template).unwrap();
    fs::set_permissions(&template, fs::Permissions::from_mode(0o600)).unwrap();

    let second = fixture.bundle("1.0.1", "adapter two\n");
    let interrupted = fixture
        .command()
        .env("HERDR_A2A_TEST_ABORT_AFTER_RESCUE_NOTICE", "1")
        .args(["managed", "install", "--bundle"])
        .arg(&second)
        .output()
        .unwrap();
    assert!(!interrupted.status.success());
    assert_ne!(fs::read(&rescue).unwrap(), prior_notice);

    assert_success(&fixture.repair());
    assert_eq!(fs::read(&rescue).unwrap(), prior_notice);
    assert_eq!(fs::read(&marker).unwrap(), prior_marker);
    assert!(
        !fixture
            .stable_root()
            .join("install-transaction.json")
            .exists()
    );
}

#[test]
fn malicious_journal_cannot_authorize_unrelated_path_mutation() {
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    let interrupted = fixture
        .command()
        .env("HERDR_A2A_TEST_ABORT_AFTER_PLUGIN_SWAP", "1")
        .args(["managed", "install", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(!interrupted.status.success());
    let unrelated = fixture.base.join("unrelated-helper");
    fs::write(&unrelated, "preserve\n").unwrap();
    fs::set_permissions(&unrelated, fs::Permissions::from_mode(0o700)).unwrap();
    let journal_path = fixture.stable_root().join("install-transaction.json");
    let mut journal: Value = serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
    journal["helper"] = json!(unrelated.to_string_lossy());
    fs::write(&journal_path, serde_json::to_vec_pretty(&journal).unwrap()).unwrap();
    fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();
    let output = fixture.repair();
    assert_failure_code(&output, "recovery_needed");
    assert_eq!(fs::read_to_string(&unrelated).unwrap(), "preserve\n");
    assert!(journal_path.exists());
}

#[test]
fn rollback_accepts_exact_prior_pi_multiset_with_duplicate_unrelated_sources() {
    // Break caught: restoring prior entries one source at a time rejects an unchanged pair of
    // unrelated entries that intentionally share a source.
    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&first));
    let prior_record = fs::read(fixture.ownership_path()).unwrap();
    let pointer = fixture.plugin_root.join("stable-bin-path");
    let prior_pointer = fs::read(&pointer).unwrap();
    let rescue = fixture.stable_root().join("rescue/uninstall.sh");
    let marker = fixture.stable_root().join("rescue/owner-v1");
    let prior_rescue = fs::read(&rescue).unwrap();
    let prior_marker = fs::read(&marker).unwrap();
    let prior_managed = json!(fixture.package_source());
    let unrelated = json!({ "source": "user-package", "extensions": ["custom.ts"] });
    let prior = vec![unrelated.clone(), unrelated, prior_managed];
    fixture.set_packages(prior.clone());
    let bundle = fixture.bundle("2.0.0", "adapter two\n");
    let interrupted = fixture
        .command()
        .env("HERDR_A2A_TEST_ABORT_AFTER_PI_MUTATION", "1")
        .args(["managed", "install", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(!interrupted.status.success());

    let journal_path = fixture.stable_root().join("install-transaction.json");
    let journal: Value = serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
    assert_eq!(
        journal["schema_version"], 3,
        "a current PiMutated journal must not be routed as a schema-2 predecessor"
    );
    assert_eq!(journal["phase"], "PiMutated");
    assert!(journal["new_record"].is_null());
    assert_eq!(fs::read(&rescue).unwrap(), prior_rescue);
    assert_eq!(fs::read(&marker).unwrap(), prior_marker);
    let interrupted_generation = PathBuf::from(journal["generation"].as_str().unwrap());
    assert!(interrupted_generation.is_dir());

    assert_success(&fixture.repair());
    assert_eq!(fs::read(fixture.ownership_path()).unwrap(), prior_record);
    assert_eq!(fs::read(pointer).unwrap(), prior_pointer);
    let settings: Value =
        serde_json::from_slice(&fs::read(fixture.pi_agent_dir.join("settings.json")).unwrap())
            .unwrap();
    assert_eq!(settings["packages"], json!(prior));
    assert!(!interrupted_generation.exists());
    assert!(!journal_path.exists());
}

#[test]
fn rollback_never_reinstalls_a_missing_unrelated_pi_entry() {
    // Break caught: treating the journal as authority for arbitrary prior sources invokes
    // `pi install` for user state that changed outside this transaction.
    let fixture = ManagedFixture::new();
    fixture.set_packages(vec![json!("user-package")]);
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    let interrupted = fixture
        .command()
        .env("HERDR_A2A_TEST_ABORT_AFTER_PI_MUTATION", "1")
        .args(["managed", "install", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(!interrupted.status.success());
    let journal_path = fixture.stable_root().join("install-transaction.json");
    let journal: Value = serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
    let new_entry = journal["new_pi_entry"].clone();
    fixture.set_packages(vec![new_entry.clone()]);
    let before_log = fixture.pi_log();

    let output = fixture.repair();
    assert_failure_code(&output, "recovery_needed");
    assert_eq!(fixture.pi_log(), before_log);
    let settings: Value =
        serde_json::from_slice(&fs::read(fixture.pi_agent_dir.join("settings.json")).unwrap())
            .unwrap();
    assert_eq!(settings["packages"], json!([new_entry]));
    assert!(journal_path.exists());
}

#[test]
fn interrupted_stage_with_unrecorded_entry_is_preserved() {
    // Break caught: a journal path alone authorizes recursive deletion of injected stage data.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    let interrupted = fixture
        .command()
        .env("HERDR_A2A_TEST_ABORT_AFTER_PLUGIN_SWAP", "1")
        .args(["managed", "install", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(!interrupted.status.success());
    let journal_path = fixture.stable_root().join("install-transaction.json");
    let journal: Value = serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
    let stage = PathBuf::from(journal["plugin_stage"].as_str().unwrap());
    let injected = stage.join("user-extra");
    fs::write(&injected, "preserve\n").unwrap();

    let output = fixture.repair();
    assert_failure_code(&output, "recovery_needed");
    assert_eq!(fs::read_to_string(&injected).unwrap(), "preserve\n");
    assert!(journal_path.exists());
}

#[test]
fn coherent_journal_plugin_redirect_is_rejected_without_mutation() {
    // Break caught: deriving the plugin root only from journal paths lets a coherently rewritten
    // journal authorize deletion in an unrelated same-owner private tree.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    let interrupted = fixture
        .command()
        .env("HERDR_A2A_TEST_ABORT_AFTER_PLUGIN_SWAP", "1")
        .args(["managed", "install", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(!interrupted.status.success());
    let journal_path = fixture.stable_root().join("install-transaction.json");
    let mut journal: Value = serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
    let token = Path::new(journal["plugin_stage"].as_str().unwrap())
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .strip_prefix(".managed-stage-")
        .unwrap()
        .to_owned();
    let unrelated = fixture.base.join("unrelated plugin");
    fs::create_dir_all(unrelated.join("libexec")).unwrap();
    fs::set_permissions(&unrelated, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(unrelated.join("libexec"), fs::Permissions::from_mode(0o700)).unwrap();
    let helper = unrelated.join("libexec/herdr-a2a-dispatch");
    let pointer = unrelated.join("stable-bin-path");
    fs::copy(Path::new(journal["helper"].as_str().unwrap()), &helper).unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
    fs::copy(Path::new(journal["pointer"].as_str().unwrap()), &pointer).unwrap();
    fs::set_permissions(&pointer, fs::Permissions::from_mode(0o600)).unwrap();
    let redirected_stage = unrelated.join(format!(".managed-stage-{token}"));
    let redirected_stage_libexec = redirected_stage.join("libexec");
    fs::create_dir(&redirected_stage).unwrap();
    fs::create_dir(&redirected_stage_libexec).unwrap();
    fs::set_permissions(&redirected_stage, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&redirected_stage_libexec, fs::Permissions::from_mode(0o700)).unwrap();
    let stage_metadata = fs::metadata(&redirected_stage).unwrap();
    let libexec_metadata = fs::metadata(&redirected_stage_libexec).unwrap();
    journal["plugin_stage"] = json!(redirected_stage.to_string_lossy());
    journal["plugin_stage_snapshot"] = json!({
        "directories": [
            {
                "path": redirected_stage.to_string_lossy(),
                "device": stage_metadata.dev(),
                "inode": stage_metadata.ino(),
                "mode": 0o700
            },
            {
                "path": redirected_stage_libexec.to_string_lossy(),
                "device": libexec_metadata.dev(),
                "inode": libexec_metadata.ino(),
                "mode": 0o700
            }
        ],
        "files": []
    });
    journal["helper"] = json!(helper.to_string_lossy());
    journal["pointer"] = json!(pointer.to_string_lossy());
    journal["helper_backup"] = json!(
        unrelated
            .join("libexec")
            .join(format!(".herdr-a2a-backup-{token}"))
            .to_string_lossy()
    );
    journal["pointer_backup"] = json!(
        unrelated
            .join(format!(".stable-bin-backup-{token}"))
            .to_string_lossy()
    );
    fs::write(&journal_path, serde_json::to_vec_pretty(&journal).unwrap()).unwrap();
    fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();

    let output = fixture.repair();
    assert_failure_code(&output, "recovery_needed");
    assert!(helper.exists());
    assert!(pointer.exists());
    assert!(redirected_stage.exists());
    assert!(journal_path.exists());
}

#[test]
fn modified_live_plugin_assets_block_recovery_without_deletion() {
    // Break caught: recovery removes the current helper or pointer without proving it is the
    // transaction-published inode and digest.
    for asset in ["helper", "pointer"] {
        let fixture = ManagedFixture::new();
        let bundle = fixture.bundle("1.0.0", "adapter one\n");
        let interrupted = fixture
            .command()
            .env("HERDR_A2A_TEST_ABORT_AFTER_PLUGIN_SWAP", "1")
            .args(["managed", "install", "--bundle"])
            .arg(&bundle)
            .output()
            .unwrap();
        assert!(!interrupted.status.success());
        let journal_path = fixture.stable_root().join("install-transaction.json");
        let journal: Value = serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
        let path = PathBuf::from(journal[asset].as_str().unwrap());
        let mode = if asset == "helper" { 0o700 } else { 0o600 };
        let original = fs::read(&path).unwrap();
        let original_inode = fs::metadata(&path).unwrap().ino();
        let replacement = path.with_extension("same-content-replacement");
        fs::write(&replacement, &original).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(mode)).unwrap();
        fs::rename(&replacement, &path).unwrap();
        assert_ne!(fs::metadata(&path).unwrap().ino(), original_inode);

        let output = fixture.repair();
        assert_failure_code(&output, "recovery_needed");
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(journal_path.exists());
    }
}

#[test]
fn same_content_generation_inode_replacement_blocks_recovery() {
    // Break caught: digest-only generation validation treats an externally replaced inode as the
    // exact transaction-published file and then authorizes its deletion.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    let interrupted = fixture
        .command()
        .env("HERDR_A2A_TEST_ABORT_AFTER_GENERATION", "1")
        .args(["managed", "install", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(!interrupted.status.success());
    let journal_path = fixture.stable_root().join("install-transaction.json");
    let journal: Value = serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
    let binary = PathBuf::from(journal["generation"].as_str().unwrap()).join("bin/herdr-a2a");
    let original = fs::read(&binary).unwrap();
    let original_inode = fs::metadata(&binary).unwrap().ino();
    let replacement = binary.with_extension("same-content-replacement");
    fs::write(&replacement, &original).unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700)).unwrap();
    fs::rename(&replacement, &binary).unwrap();
    assert_ne!(fs::metadata(&binary).unwrap().ino(), original_inode);

    let output = fixture.repair();
    assert_failure_code(&output, "recovery_needed");
    assert_eq!(fs::read(&binary).unwrap(), original);
    assert!(journal_path.exists());
}

#[test]
fn created_generation_replacement_during_pi_rollback_is_preserved() {
    // Break caught: validating the published generation only at recovery entry lets a same-owner
    // replacement race the later path/mode-only deletion while Pi rollback is blocked.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    let interrupted = fixture
        .command()
        .env("HERDR_A2A_TEST_ABORT_AFTER_PI_MUTATION", "1")
        .args(["managed", "install", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(!interrupted.status.success());
    assert_eq!(fixture.packages().len(), 1);
    let journal_path = fixture.stable_root().join("install-transaction.json");
    let journal: Value = serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
    let binary = PathBuf::from(journal["generation"].as_str().unwrap()).join("bin/herdr-a2a");
    let original = fs::read(&binary).unwrap();
    let original_inode = fs::metadata(&binary).unwrap().ino();
    let blocked = fixture.base.join("pi rollback blocked");
    let release = fixture.base.join("release pi rollback");
    let mut repair = fixture.command();
    repair
        .env("HERDR_A2A_TEST_PI_MODE", "block_remove")
        .env("HERDR_A2A_TEST_PI_BLOCKED", &blocked)
        .env("HERDR_A2A_TEST_PI_RELEASE", &release)
        .args(["managed", "repair", "--startup"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let repair = repair.spawn().unwrap();
    for _ in 0..3000 {
        if blocked.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if !blocked.exists() {
        let output = repair.wait_with_output().unwrap();
        panic!(
            "Pi rollback did not reach its deterministic barrier\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let replacement = binary.with_extension("same-content-replacement");
    fs::write(&replacement, &original).unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700)).unwrap();
    fs::rename(&replacement, &binary).unwrap();
    assert_ne!(fs::metadata(&binary).unwrap().ino(), original_inode);
    fs::write(&release, "continue\n").unwrap();

    let output = repair.wait_with_output().unwrap();
    assert_failure_code(&output, "recovery_needed");
    assert_eq!(fs::read(&binary).unwrap(), original);
    assert!(journal_path.exists());
}

#[test]
fn created_generation_requires_its_authenticated_snapshot_after_publication() {
    // Break caught: removing the optional stage snapshot from an otherwise coherent journal
    // bypasses the created generation's inode gate and authorizes deletion.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    let interrupted = fixture
        .command()
        .env("HERDR_A2A_TEST_ABORT_AFTER_GENERATION", "1")
        .args(["managed", "install", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(!interrupted.status.success());
    let journal_path = fixture.stable_root().join("install-transaction.json");
    let mut journal: Value = serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
    let generation = PathBuf::from(journal["generation"].as_str().unwrap());
    journal["generation_stage_snapshot"] = Value::Null;
    fs::write(&journal_path, serde_json::to_vec_pretty(&journal).unwrap()).unwrap();
    fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();

    let output = fixture.repair();
    assert_failure_code(&output, "recovery_needed");
    assert!(generation.exists());
    assert!(journal_path.exists());
}

#[test]
fn same_content_superseded_generation_inode_replacement_blocks_committed_cleanup() {
    // Break caught: the prior record's path/mode/digest metadata does not prove that the inode
    // being deleted during committed cleanup is the one present before transaction intent.
    let fixture = ManagedFixture::new();
    let first = fixture.bundle("1.0.0", "adapter one\n");
    assert_success(&fixture.install(&first));
    let prior_record = fixture.record();
    let prior_binary = PathBuf::from(prior_record["stable_binary"].as_str().unwrap());
    let original = fs::read(&prior_binary).unwrap();
    let original_inode = fs::metadata(&prior_binary).unwrap().ino();
    let second = fixture.bundle("2.0.0", "adapter two\n");
    let interrupted = fixture
        .command()
        .env("HERDR_A2A_TEST_ABORT_AFTER_RECORD_COMMITTED", "1")
        .args(["managed", "install", "--bundle"])
        .arg(second)
        .output()
        .unwrap();
    assert!(!interrupted.status.success());
    let replacement = prior_binary.with_extension("same-content-replacement");
    fs::write(&replacement, &original).unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700)).unwrap();
    fs::rename(&replacement, &prior_binary).unwrap();
    assert_ne!(fs::metadata(&prior_binary).unwrap().ino(), original_inode);
    let journal_path = fixture.stable_root().join("install-transaction.json");

    let output = fixture.repair();
    assert_failure_code(&output, "recovery_needed");
    assert_eq!(fs::read(&prior_binary).unwrap(), original);
    assert!(journal_path.exists());
}

#[test]
fn modified_live_record_blocks_recovery_without_overwrite() {
    // Break caught: a RecordRenaming recovery overwrites a live record without proving it is the
    // exact prior or new record permitted for that phase.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    let interrupted = fixture
        .command()
        .env("HERDR_A2A_TEST_ABORT_AFTER_RECORD_RENAME", "1")
        .args(["managed", "install", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(!interrupted.status.success());
    let journal_path = fixture.stable_root().join("install-transaction.json");
    let mut record = fixture.record();
    record["last_error"] = json!("external modification");
    let modified = serde_json::to_vec_pretty(&record).unwrap();
    fs::write(fixture.ownership_path(), &modified).unwrap();
    fs::set_permissions(fixture.ownership_path(), fs::Permissions::from_mode(0o600)).unwrap();

    let output = fixture.repair();
    assert_failure_code(&output, "recovery_needed");
    assert_eq!(fs::read(fixture.ownership_path()).unwrap(), modified);
    assert!(journal_path.exists());
}

#[test]
fn journal_new_pi_entry_must_name_the_planned_generation() {
    // Break caught: a syntactically valid but unrelated new Pi source is trusted while recovery
    // removes the genuine published generation.
    let fixture = ManagedFixture::new();
    let bundle = fixture.bundle("1.0.0", "adapter one\n");
    let interrupted = fixture
        .command()
        .env("HERDR_A2A_TEST_ABORT_AFTER_GENERATION", "1")
        .args(["managed", "install", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(!interrupted.status.success());
    let journal_path = fixture.stable_root().join("install-transaction.json");
    let mut journal: Value = serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
    let generation = PathBuf::from(journal["generation"].as_str().unwrap());
    journal["new_pi_entry"] = json!(fixture.base.join("unrelated pi").to_string_lossy());
    fs::write(&journal_path, serde_json::to_vec_pretty(&journal).unwrap()).unwrap();
    fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();

    let output = fixture.repair();
    assert_failure_code(&output, "recovery_needed");
    assert!(generation.exists());
    assert!(journal_path.exists());
}

#[test]
fn release_archive_accepts_only_the_exact_managed_bundle() {
    // Break caught: checksum verification followed by direct tar extraction permits traversal,
    // link/device entries, duplicates, missing or arbitrary package files, and unbounded expansion
    // before native validation.
    let fixture = ManagedFixture::new();
    let release_root = fixture.base.join("private release root");
    fs::create_dir(&release_root).unwrap();
    fs::set_permissions(&release_root, fs::Permissions::from_mode(0o700)).unwrap();
    let cases = [
        (
            "traversal",
            vec![("../escaped", b'0', 0o600, b"bad".to_vec())],
        ),
        ("symlink", vec![("bin/herdr-a2a", b'2', 0o700, Vec::new())]),
        ("device", vec![("pi/package.json", b'3', 0o600, Vec::new())]),
        (
            "duplicate",
            vec![("pi/package.json", b'0', 0o600, b"{}".to_vec())],
        ),
        (
            "extra-sibling",
            vec![("pi/src/unexpected.ts", b'0', 0o600, b"bad".to_vec())],
        ),
        (
            "bomb",
            vec![("pi/package.json", b'0', 0o600, vec![b'x'; 33 * 1024 * 1024])],
        ),
    ];
    for (name, extra) in cases {
        let archive = release_root.join(format!("{name}.tar.gz"));
        write_release_archive(&archive, true, extra);
        let destination = release_root.join(format!("extract-{name}"));
        let output = fixture
            .command()
            .args(["managed", "extract-release", "--archive"])
            .arg(&archive)
            .arg("--destination")
            .arg(&destination)
            .output()
            .unwrap();
        assert_failure_code(&output, "archive_invalid");
        assert!(!destination.exists());
        assert!(!fixture.base.join("escaped").exists());
    }

    let trailing = release_root.join("trailing.tar.gz");
    write_release_archive(&trailing, true, Vec::new());
    append_nonzero_after_tar_end(&trailing);
    let trailing_destination = release_root.join("extract-trailing");
    let output = fixture
        .command()
        .args(["managed", "extract-release", "--archive"])
        .arg(&trailing)
        .arg("--destination")
        .arg(&trailing_destination)
        .output()
        .unwrap();
    assert_failure_code(&output, "archive_invalid");
    assert!(!trailing_destination.exists());

    let missing = release_root.join("missing-inbox-pump.tar.gz");
    write_release_archive(&missing, false, Vec::new());
    let missing_destination = release_root.join("extract-missing-inbox-pump");
    let output = fixture
        .command()
        .args(["managed", "extract-release", "--archive"])
        .arg(&missing)
        .arg("--destination")
        .arg(&missing_destination)
        .output()
        .unwrap();
    assert_failure_code(&output, "archive_invalid");
    assert!(!missing_destination.exists());

    let archive = release_root.join("valid.tar.gz");
    write_release_archive(&archive, true, Vec::new());
    let destination = release_root.join("valid extract");
    let output = fixture
        .command()
        .args(["managed", "extract-release", "--archive"])
        .arg(&archive)
        .arg("--destination")
        .arg(&destination)
        .output()
        .unwrap();
    assert_success(&output);
    assert_eq!(
        fs::read_to_string(destination.join("pi/package.json")).unwrap(),
        "{}\n"
    );
    assert_eq!(
        fs::read_to_string(destination.join("metadata/ownership-template.json")).unwrap(),
        "{\"schema_version\":3}\n"
    );
    assert_eq!(
        fs::read_to_string(destination.join("pi/src/inbox-pump.ts")).unwrap(),
        "inbox pump\n"
    );
    assert_eq!(
        fs::read_to_string(destination.join("pi/src/session-client.ts")).unwrap(),
        "session client\n"
    );
    assert_eq!(
        fs::read_to_string(destination.join("pi/src/team-command.ts")).unwrap(),
        "team command\n"
    );
    assert_eq!(
        fs::read_to_string(destination.join("scripts/dispatch.sh")).unwrap(),
        "dispatch\n"
    );
    assert_eq!(
        fs::read_to_string(destination.join("scripts/uninstall.sh")).unwrap(),
        "rescue\n"
    );
}

fn write_release_archive(
    archive: &Path,
    include_inbox_pump: bool,
    extra: Vec<(&str, u8, u32, Vec<u8>)>,
) {
    let binary = b"verified release binary\n".to_vec();
    let mut entries = vec![
        ("bin/", b'5', 0o700, Vec::new()),
        ("bin/herdr-a2a", b'0', 0o700, binary),
        ("metadata/", b'5', 0o700, Vec::new()),
        (
            "metadata/ownership-template.json",
            b'0',
            0o600,
            b"{\"schema_version\":3}\n".to_vec(),
        ),
        ("pi/", b'5', 0o700, Vec::new()),
        ("pi/package.json", b'0', 0o600, b"{}\n".to_vec()),
        ("pi/extensions/", b'5', 0o700, Vec::new()),
        (
            "pi/extensions/herdr-a2a.ts",
            b'0',
            0o600,
            b"extension\n".to_vec(),
        ),
        ("pi/src/", b'5', 0o700, Vec::new()),
        (
            "pi/src/inbox-pump.ts",
            b'0',
            0o600,
            b"inbox pump\n".to_vec(),
        ),
        (
            "pi/src/session-client.ts",
            b'0',
            0o600,
            b"session client\n".to_vec(),
        ),
        (
            "pi/src/team-command.ts",
            b'0',
            0o600,
            b"team command\n".to_vec(),
        ),
        ("pi/skills/", b'5', 0o700, Vec::new()),
        ("pi/skills/herdr-a2a/", b'5', 0o700, Vec::new()),
        (
            "pi/skills/herdr-a2a/SKILL.md",
            b'0',
            0o600,
            b"skill\n".to_vec(),
        ),
        ("scripts/", b'5', 0o700, Vec::new()),
        ("scripts/dispatch.sh", b'0', 0o700, b"dispatch\n".to_vec()),
        ("scripts/uninstall.sh", b'0', 0o600, b"rescue\n".to_vec()),
    ];
    if !include_inbox_pump {
        entries.retain(|(name, _, _, _)| *name != "pi/src/inbox-pump.ts");
    }
    for (name, typeflag, _, _) in &extra {
        if *typeflag != b'0' {
            entries.retain(|(existing, _, _, _)| existing != name);
        }
    }
    entries.extend(extra);
    let mut tar = Vec::new();
    for (name, typeflag, mode, data) in entries {
        let mut header = [0_u8; 512];
        assert!(name.len() < 100);
        header[..name.len()].copy_from_slice(name.as_bytes());
        write_octal(&mut header[100..108], mode as u64);
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(&mut header[124..136], data.len() as u64);
        write_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = typeflag;
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum: u64 = header.iter().map(|byte| *byte as u64).sum();
        let checksum_text = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(checksum_text.as_bytes());
        tar.extend_from_slice(&header);
        tar.extend_from_slice(&data);
        tar.resize(tar.len().div_ceil(512) * 512, 0);
    }
    tar.resize(tar.len() + 1024, 0);
    let raw = archive.with_extension("tar");
    fs::write(&raw, tar).unwrap();
    let output = File::create(archive).unwrap();
    let status = Command::new("gzip")
        .arg("-c")
        .arg(&raw)
        .stdout(output)
        .status()
        .unwrap();
    assert!(status.success());
    fs::remove_file(raw).unwrap();
}

fn write_octal(field: &mut [u8], value: u64) {
    field.fill(b'0');
    let encoded = format!("{value:o}");
    let start = field.len() - encoded.len() - 1;
    field[start..start + encoded.len()].copy_from_slice(encoded.as_bytes());
    field[field.len() - 1] = 0;
}

fn append_nonzero_after_tar_end(archive: &Path) {
    let output = Command::new("gzip")
        .arg("-dc")
        .arg(archive)
        .output()
        .unwrap();
    assert!(output.status.success());
    let mut bytes = output.stdout;
    bytes.extend_from_slice(&[1_u8; 512]);
    let raw = archive.with_extension("trailing.tar");
    fs::write(&raw, bytes).unwrap();
    let compressed = File::create(archive).unwrap();
    let status = Command::new("gzip")
        .arg("-c")
        .arg(&raw)
        .stdout(compressed)
        .status()
        .unwrap();
    assert!(status.success());
    fs::remove_file(raw).unwrap();
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let destination = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).unwrap();
        }
    }
}
