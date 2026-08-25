use std::{
    collections::BTreeSet,
    env,
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use rustix::fs::{
    AtFlags, Dir, FlockOperation, Mode, OFlags, fchmod, flock, mkdirat, open, openat, statat,
    unlinkat,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::{io::AsyncReadExt, process::Command};

const OWNERSHIP_SCHEMA: u32 = 3;
const OWNERSHIP_FILE: &str = "ownership.json";
const INSTALL_LOCK: &str = "install.lock";
const TRANSACTION_FILE: &str = "install-transaction.json";
const LEGACY_TRANSACTION_SCHEMA: u32 = 2;
const TRANSACTION_SCHEMA: u32 = 3;
const RESCUE_MIGRATION_FILE: &str = "rescue-migration.json";
const RESCUE_MIGRATION_SCHEMA: u32 = 2;
const LEGACY_RESCUE_MIGRATION_SCHEMA: u32 = 1;
const REMOVAL_TRANSACTION_FILE: &str = "removal-transaction.json";
const REMOVAL_TRANSACTION_SCHEMA: u32 = 1;
const MAX_POINTER_BYTES: usize = 4 * 1024;
const MAX_RECORD_BYTES: u64 = 1024 * 1024;
const MAX_TRANSACTION_BYTES: u64 = 32 * 1024 * 1024;
const MAX_RESCUE_MIGRATION_BYTES: u64 = 8 * 1024 * 1024;
const MAX_SETTINGS_BYTES: u64 = 1024 * 1024;
const MAX_EVENT_BYTES: usize = 64 * 1024;
const MAX_PROCESS_OUTPUT: usize = 64 * 1024;
const MAX_HERDR_PLUGIN_REGISTRATIONS: usize = 8;
const PI_TIMEOUT: Duration = Duration::from_secs(15);
const PROCESS_DRAIN_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_ARCHIVE_EXPANDED_BYTES: usize = 32 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 25;
const RESCUE_DIRECTORY: &str = "rescue";
const RESCUE_MARKER: &str = "owner-v1";
const LEGACY_RESCUE_HELPER: &str = "herdr-a2a-rescue";
const PROCESS_REGISTRY: &str = "process-registry";
const PROCESS_REGISTRY_MAGIC: &str = "HERDR_A2A_PROCESS_REGISTRY_V1";
const STARTING_PROCESS_REGISTRY: &str = "starting-process-registry.json";
const STARTING_PROCESS_REGISTRY_SCHEMA: u32 = 1;
const MAX_PROCESS_REGISTRY_BYTES: u64 = 256 * 1024;
const MAX_PROCESS_REGISTRY_ENTRIES: usize = 64;
const MAX_OWNED_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PURGE_ENTRIES: usize = 4096;
const MAX_PURGE_DEPTH: usize = 64;
const MAX_PURGE_BYTES: u64 = 1024 * 1024 * 1024;
const SUPPORTED_PI_MIN: (u64, u64, u64) = (0, 84, 2);
pub(crate) const SUPPORTED_PI_PEER_RANGE: &str = ">=0.84.2";
pub(crate) const SUPPORTED_TYPEBOX_PEER_RANGE: &str = ">=1.3.7 <1.4.0";

type ManagedResult<T> = Result<T, ManagedError>;

#[derive(Debug)]
pub struct ManagedError {
    code: &'static str,
    message: String,
}

impl ManagedError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn io(code: &'static str, context: &str, error: io::Error) -> Self {
        Self::new(code, format!("{context}: {error}"))
    }
}

impl std::fmt::Display for ManagedError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ManagedError {}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum InstallState {
    Ready,
    PiAdapterPending,
    Failed,
    Removing,
    UnregisterPending,
    Unregistering,
    FinalizingRemoval,
    Removed,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnedFile {
    path: PathBuf,
    sha256: String,
    mode: u32,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnershipRecord {
    schema_version: u32,
    state: InstallState,
    plugin_version: String,
    broker_digest: String,
    pi_package_digest: String,
    pi_package_source: PathBuf,
    pi_config_path: PathBuf,
    pi_package_entry: Value,
    purge_authority: bool,
    #[serde(default, skip_serializing_if = "path_is_empty")]
    plugin_state_root: PathBuf,
    rescue_path: PathBuf,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    rescue_marker_digest: String,
    install_kind: String,
    plugin_root: PathBuf,
    stable_binary: PathBuf,
    ownership_path: PathBuf,
    owned_files: Vec<OwnedFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_error: Option<String>,
}

fn path_is_empty(path: &Path) -> bool {
    path.as_os_str().is_empty()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompatibleOwnershipRecord {
    schema_version: u32,
    state: InstallState,
    plugin_version: String,
    broker_digest: String,
    pi_package_digest: String,
    pi_package_source: PathBuf,
    pi_config_path: PathBuf,
    pi_package_entry: Value,
    purge_authority: Option<bool>,
    plugin_state_root: Option<PathBuf>,
    rescue_path: PathBuf,
    rescue_marker_digest: Option<String>,
    install_kind: String,
    plugin_root: PathBuf,
    stable_binary: PathBuf,
    ownership_path: PathBuf,
    owned_files: Vec<OwnedFile>,
    last_error: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DecodedOwnershipSchema {
    LegacyV2NoAuthority,
    AuthoritativeV2,
    LegacyV3Authority,
    CurrentV3,
}

fn classify_compatible_record(
    record: &CompatibleOwnershipRecord,
) -> ManagedResult<DecodedOwnershipSchema> {
    match (
        record.schema_version,
        record.purge_authority,
        record.plugin_state_root.as_ref(),
        record.rescue_marker_digest.as_deref(),
    ) {
        (2, None | Some(false), None, None) => Ok(DecodedOwnershipSchema::LegacyV2NoAuthority),
        (2, Some(true), Some(root), Some(marker_digest))
            if !root.as_os_str().is_empty() && valid_digest(marker_digest) =>
        {
            Ok(DecodedOwnershipSchema::AuthoritativeV2)
        }
        (OWNERSHIP_SCHEMA, None, Some(root), Some(marker_digest))
            if !root.as_os_str().is_empty() && valid_digest(marker_digest) =>
        {
            Ok(DecodedOwnershipSchema::LegacyV3Authority)
        }
        (OWNERSHIP_SCHEMA, Some(false), None, Some(marker_digest))
            if valid_digest(marker_digest) =>
        {
            Ok(DecodedOwnershipSchema::CurrentV3)
        }
        (OWNERSHIP_SCHEMA, Some(true), Some(root), Some(marker_digest))
            if !root.as_os_str().is_empty() && valid_digest(marker_digest) =>
        {
            Ok(DecodedOwnershipSchema::CurrentV3)
        }
        (2, ..) | (OWNERSHIP_SCHEMA, ..) => Err(ManagedError::new(
            "ownership_record_invalid",
            "ownership schema authority fields are incompatible",
        )),
        _ => Err(ManagedError::new(
            "ownership_record_invalid",
            "ownership schema fields are incompatible",
        )),
    }
}

impl TryFrom<CompatibleOwnershipRecord> for OwnershipRecord {
    type Error = ManagedError;

    fn try_from(record: CompatibleOwnershipRecord) -> ManagedResult<Self> {
        let (purge_authority, plugin_state_root, rescue_marker_digest) =
            match classify_compatible_record(&record)? {
                DecodedOwnershipSchema::LegacyV2NoAuthority => {
                    (false, PathBuf::new(), String::new())
                }
                DecodedOwnershipSchema::AuthoritativeV2 => (
                    true,
                    record
                        .plugin_state_root
                        .expect("classified authority root is present"),
                    record
                        .rescue_marker_digest
                        .expect("classified authority marker digest is present"),
                ),
                DecodedOwnershipSchema::LegacyV3Authority => (
                    true,
                    record
                        .plugin_state_root
                        .expect("classified legacy authority root is present"),
                    record
                        .rescue_marker_digest
                        .expect("classified legacy authority marker digest is present"),
                ),
                DecodedOwnershipSchema::CurrentV3 => (
                    record
                        .purge_authority
                        .expect("classified authority is present"),
                    record.plugin_state_root.unwrap_or_default(),
                    record
                        .rescue_marker_digest
                        .expect("classified marker digest is present"),
                ),
            };
        let plugin_state_root = if purge_authority {
            plugin_state_root
        } else {
            PathBuf::new()
        };
        Ok(Self {
            schema_version: record.schema_version,
            state: record.state,
            plugin_version: record.plugin_version,
            broker_digest: record.broker_digest,
            pi_package_digest: record.pi_package_digest,
            pi_package_source: record.pi_package_source,
            pi_config_path: record.pi_config_path,
            pi_package_entry: record.pi_package_entry,
            purge_authority,
            plugin_state_root,
            rescue_path: record.rescue_path,
            rescue_marker_digest,
            install_kind: record.install_kind,
            plugin_root: record.plugin_root,
            stable_binary: record.stable_binary,
            ownership_path: record.ownership_path,
            owned_files: record.owned_files,
            last_error: record.last_error,
        })
    }
}

impl<'de> Deserialize<'de> for OwnershipRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let record = CompatibleOwnershipRecord::deserialize(deserializer)?;
        record.try_into().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Serialize)]
pub struct RemovalResult {
    pub state: &'static str,
    pub retained_data: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedProcessEntry {
    pub runtime_root: PathBuf,
    pub session_key: String,
    pub workspace_id: String,
    pub scope_key: String,
    pub coordinator_pid: u32,
    pub coordinator_start: String,
    pub broker_pid: u32,
    pub broker_start: String,
    pub broker_instance_id: String,
    pub executable_path: PathBuf,
    pub executable_digest: String,
    pub control_port: u16,
    pub control_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedStartingBrokerProof {
    pub broker_pid: u32,
    pub broker_start: String,
    pub executable_path: PathBuf,
    pub executable_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedStartingProcessEntry {
    pub runtime_root: PathBuf,
    pub session_key: String,
    pub workspace_id: String,
    pub scope_key: String,
    pub coordinator_pid: u32,
    pub coordinator_start: String,
    pub executable_path: PathBuf,
    pub executable_digest: String,
    pub expected_generation: String,
    pub control_port: u16,
    pub control_nonce: String,
    pub broker: Option<ManagedStartingBrokerProof>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StartingProcessRegistry {
    schema_version: u32,
    entries: Vec<ManagedStartingProcessEntry>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
enum RemovalTransactionPhase {
    Intent,
    Deleting,
    Deleted,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RemovalTransaction {
    schema_version: u32,
    phase: RemovalTransactionPhase,
    purge_root: PathBuf,
    purge_snapshot: StageSnapshot,
    skip_herdr_unregister: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadOnlyManagedIssue {
    OwnershipInvalid,
    OwnershipVersionIncompatible,
    BinaryModified,
    AdapterModified,
    PiEntryModified,
    PiAdapterPending,
    PluginVersionIncompatible,
    BinaryVersionIncompatible,
    AdapterMetadataIncompatible,
    AdapterVersionIncompatible,
    PiVersionIncompatible,
}

pub async fn inspect_read_only() -> Vec<ReadOnlyManagedIssue> {
    let Ok(stable_root) = stable_root() else {
        return vec![ReadOnlyManagedIssue::OwnershipInvalid];
    };
    if validate_private_directory(&stable_root, 0o700).is_err() {
        return vec![ReadOnlyManagedIssue::OwnershipInvalid];
    }
    let record = match read_record(&stable_root) {
        Ok(record) => record,
        Err(_) => return vec![ReadOnlyManagedIssue::OwnershipInvalid],
    };
    if record.schema_version != OWNERSHIP_SCHEMA {
        return vec![ReadOnlyManagedIssue::OwnershipVersionIncompatible];
    }
    if validate_record(&record, &stable_root).is_err() {
        if !binary_assets_match(&record) {
            return vec![ReadOnlyManagedIssue::BinaryModified];
        }
        if !adapter_assets_match(&record) {
            return vec![ReadOnlyManagedIssue::AdapterModified];
        }
        return vec![ReadOnlyManagedIssue::OwnershipInvalid];
    }

    let mut issues = Vec::new();
    if read_plugin_version(&record.plugin_root).ok().as_deref()
        != Some(record.plugin_version.as_str())
    {
        issues.push(ReadOnlyManagedIssue::PluginVersionIncompatible);
    }
    if record.plugin_version != env!("CARGO_PKG_VERSION") {
        issues.push(ReadOnlyManagedIssue::BinaryVersionIncompatible);
    }
    match read_owned_adapter_contract(&record.pi_package_source) {
        Ok(contract) => {
            if contract.name != "@herdr/a2a-pi"
                || contract.pi_peer != SUPPORTED_PI_PEER_RANGE
                || contract.typebox_peer != SUPPORTED_TYPEBOX_PEER_RANGE
            {
                issues.push(ReadOnlyManagedIssue::AdapterMetadataIncompatible);
            }
            if contract.version != record.plugin_version {
                issues.push(ReadOnlyManagedIssue::AdapterVersionIncompatible);
            }
        }
        Err(_) => issues.push(ReadOnlyManagedIssue::AdapterMetadataIncompatible),
    }
    match record.state {
        InstallState::Ready => {
            if validate_ready_pi(&record).is_err() {
                issues.push(ReadOnlyManagedIssue::PiEntryModified);
            }
        }
        InstallState::PiAdapterPending => {
            issues.push(ReadOnlyManagedIssue::PiAdapterPending);
        }
        InstallState::Failed
        | InstallState::Removing
        | InstallState::UnregisterPending
        | InstallState::Unregistering
        | InstallState::FinalizingRemoval
        | InstallState::Removed => {
            issues.push(ReadOnlyManagedIssue::OwnershipInvalid);
        }
    }
    match detect_pi() {
        Ok(Some(snapshot)) => {
            let compatible = run_bounded_process(&snapshot.program, &[OsString::from("--version")])
                .await
                .ok()
                .filter(|output| output.success)
                .and_then(|output| parse_pi_version(&output.stdout))
                .is_some_and(pi_version_supported);
            if !compatible {
                issues.push(ReadOnlyManagedIssue::PiVersionIncompatible);
            }
        }
        Ok(None) => {
            if !issues.contains(&ReadOnlyManagedIssue::PiAdapterPending) {
                issues.push(ReadOnlyManagedIssue::PiAdapterPending);
            }
        }
        Err(_) => issues.push(ReadOnlyManagedIssue::PiVersionIncompatible),
    }
    issues
}

fn binary_assets_match(record: &OwnershipRecord) -> bool {
    let helper = record.plugin_root.join("libexec/herdr-a2a-dispatch");
    [(&record.stable_binary, 0o700), (&helper, 0o700)]
        .into_iter()
        .all(|(path, mode)| owned_asset_matches(record, path, mode))
        && digest_file(&record.stable_binary).ok().as_deref() == Some(&record.broker_digest)
        && digest_file(&helper).ok().as_deref() == Some(&record.broker_digest)
}

fn adapter_assets_match(record: &OwnershipRecord) -> bool {
    let Ok(files) = tree_files(&record.pi_package_source) else {
        return false;
    };
    digest_tree(&record.pi_package_source).ok().as_deref() == Some(&record.pi_package_digest)
        && files
            .iter()
            .all(|path| owned_asset_matches(record, path, 0o600))
}

fn owned_asset_matches(record: &OwnershipRecord, path: &Path, mode: u32) -> bool {
    let Some(owned) = record.owned_files.iter().find(|owned| owned.path == path) else {
        return false;
    };
    owned.mode == mode
        && validate_owned_regular_file(path, mode, "owned_asset_modified").is_ok()
        && digest_file(path).ok().as_deref() == Some(owned.sha256.as_str())
}

fn read_external_adapter_contract(package: &Path) -> ManagedResult<AdapterContract> {
    let manifest = package.join("package.json");
    let mut file = open_validated_absolute_file(&manifest)?;
    let metadata = validate_opened_external_file(&file, false)?;
    let value: Value = parse_bounded_opened_json(
        &mut file,
        metadata.len(),
        MAX_SETTINGS_BYTES,
        "bundle_invalid",
    )?;
    decode_adapter_contract(&value)
}

fn read_owned_adapter_contract(package: &Path) -> ManagedResult<AdapterContract> {
    let manifest = package.join("package.json");
    let mut file = open_validated_absolute_file(&manifest)?;
    let metadata = validate_opened_owned_regular_file(&file, 0o600, "owned_asset_modified")?;
    let value: Value = parse_bounded_opened_json(
        &mut file,
        metadata.len(),
        MAX_SETTINGS_BYTES,
        "ownership_record_invalid",
    )?;
    decode_adapter_contract(&value)
}

fn decode_adapter_contract(value: &Value) -> ManagedResult<AdapterContract> {
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty() && name.len() <= 128)
        .map(str::to_owned)
        .ok_or_else(|| {
            ManagedError::new(
                "ownership_record_invalid",
                "Pi adapter package name is invalid",
            )
        })?;
    let version = value
        .get("version")
        .and_then(Value::as_str)
        .filter(|version| !version.is_empty() && version.len() <= 128)
        .map(str::to_owned)
        .ok_or_else(|| {
            ManagedError::new(
                "ownership_record_invalid",
                "Pi adapter package version is invalid",
            )
        })?;
    let peer_dependencies = value
        .get("peerDependencies")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            ManagedError::new(
                "incompatible_version",
                "Pi adapter peer dependency contract is absent",
            )
        })?;
    let pi_peer = peer_dependencies
        .get("@earendil-works/pi-coding-agent")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .map(str::to_owned)
        .ok_or_else(|| {
            ManagedError::new(
                "incompatible_version",
                "Pi adapter supported Pi range is invalid",
            )
        })?;
    let typebox_peer = peer_dependencies
        .get("typebox")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .map(str::to_owned)
        .ok_or_else(|| {
            ManagedError::new(
                "incompatible_version",
                "Pi adapter supported Typebox range is invalid",
            )
        })?;
    Ok(AdapterContract {
        name,
        version,
        pi_peer,
        typebox_peer,
    })
}

fn parse_pi_version(stdout: &[u8]) -> Option<(u64, u64, u64)> {
    let output = std::str::from_utf8(stdout).ok()?;
    let mut tokens = output.split_whitespace();
    let version = parse_version_token(tokens.next()?)?;
    tokens.next().is_none().then_some(version)
}

fn parse_native_version(stdout: &[u8]) -> Option<(u64, u64, u64)> {
    let output = std::str::from_utf8(stdout).ok()?;
    let mut tokens = output.split_whitespace();
    if tokens.next()? != "herdr-a2a" {
        return None;
    }
    let version = parse_version_token(tokens.next()?)?;
    tokens.next().is_none().then_some(version)
}

fn parse_version_token(token: &str) -> Option<(u64, u64, u64)> {
    let token = token.strip_prefix('v').unwrap_or(token);
    let mut components = token.split('.');
    let parse_component = |component: &str| {
        if component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        component.parse::<u64>().ok()
    };
    let major = parse_component(components.next()?)?;
    let minor = parse_component(components.next()?)?;
    let patch = parse_component(components.next()?)?;
    components.next().is_none().then_some((major, minor, patch))
}

fn pi_version_supported(version: (u64, u64, u64)) -> bool {
    version >= SUPPORTED_PI_MIN
}

fn validate_adapter_contract(contract: &AdapterContract, version: &str) -> ManagedResult<()> {
    if contract.name != "@herdr/a2a-pi"
        || contract.version != version
        || contract.pi_peer != SUPPORTED_PI_PEER_RANGE
        || contract.typebox_peer != SUPPORTED_TYPEBOX_PEER_RANGE
    {
        return Err(ManagedError::new(
            "incompatible_version",
            format!(
                "managed A2A requires component version {version}, Pi {SUPPORTED_PI_PEER_RANGE}, and Typebox {SUPPORTED_TYPEBOX_PEER_RANGE}"
            ),
        ));
    }
    Ok(())
}

async fn validate_executable_version(program: &Path, expected: &str) -> ManagedResult<()> {
    let output = run_bounded_process(program, &[OsString::from("--version")])
        .await
        .map_err(|error| {
            ManagedError::new(
                "incompatible_version",
                format!("native version check failed: {error}"),
            )
        })?;
    let expected = parse_version_token(expected).ok_or_else(|| {
        ManagedError::new(
            "incompatible_version",
            "the compiled native version is not a supported semantic version",
        )
    })?;
    if !output.success || parse_native_version(&output.stdout) != Some(expected) {
        return Err(ManagedError::new(
            "incompatible_version",
            "the managed native binary version differs from the plugin version",
        ));
    }
    Ok(())
}

async fn validate_pi_compatibility(pi: Option<&PiSnapshot>) -> ManagedResult<()> {
    let Some(pi) = pi else {
        return Ok(());
    };
    let output = run_bounded_process(&pi.program, &[OsString::from("--version")])
        .await
        .map_err(|error| {
            ManagedError::new(
                "incompatible_version",
                format!("Pi version check failed: {error}"),
            )
        })?;
    let version = output
        .success
        .then(|| parse_pi_version(&output.stdout))
        .flatten();
    if !version.is_some_and(pi_version_supported) {
        return Err(ManagedError::new(
            "incompatible_version",
            format!("managed A2A requires Pi {SUPPORTED_PI_PEER_RANGE}"),
        ));
    }
    Ok(())
}

async fn validate_install_compatibility(
    plugin_root: &Path,
    bundle_binary: &Path,
    bundle_package: &Path,
    pi: Option<&PiSnapshot>,
) -> ManagedResult<()> {
    let plugin_version = read_plugin_version(plugin_root)?;
    if plugin_version != env!("CARGO_PKG_VERSION") {
        return Err(ManagedError::new(
            "incompatible_version",
            "the Herdr plugin and native installer versions differ",
        ));
    }
    validate_executable_version(bundle_binary, &plugin_version).await?;
    let adapter = read_external_adapter_contract(bundle_package)?;
    validate_adapter_contract(&adapter, &plugin_version)?;
    validate_pi_compatibility(pi).await
}

async fn validate_repair_compatibility(
    record: &OwnershipRecord,
    pi: Option<&PiSnapshot>,
) -> ManagedResult<()> {
    if record.plugin_version != env!("CARGO_PKG_VERSION")
        || read_plugin_version(&record.plugin_root)? != record.plugin_version
    {
        return Err(ManagedError::new(
            "incompatible_version",
            "the installed Herdr plugin and native helper versions differ",
        ));
    }
    validate_executable_version(&record.stable_binary, &record.plugin_version).await?;
    let adapter = read_owned_adapter_contract(&record.pi_package_source)?;
    validate_adapter_contract(&adapter, &record.plugin_version)?;
    validate_pi_compatibility(pi).await
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
enum TransactionPhase {
    Intent,
    GenerationPublishing,
    GenerationPublished,
    PluginPublishing,
    PluginBackingUpHelper,
    PluginBackingUpPointer,
    PluginPublishingHelper,
    PluginPublishingPointer,
    PluginPublished,
    PiMutating,
    PiMutated,
    RescuePublishing,
    RecordCommitting,
    RecordRenaming,
    RecordCommitted,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct InstallTransaction {
    schema_version: u32,
    phase: TransactionPhase,
    #[serde(deserialize_with = "deserialize_legacy_journal_ownership_record")]
    prior_record: Option<OwnershipRecord>,
    #[serde(deserialize_with = "deserialize_legacy_journal_ownership_record")]
    new_record: Option<OwnershipRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prior_rescue_notice: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prior_rescue_marker: Option<Vec<u8>>,
    broker_digest: String,
    pi_package_digest: String,
    generation: PathBuf,
    generation_stage: PathBuf,
    generation_stage_snapshot: Option<StageSnapshot>,
    generation_files: Vec<PathBuf>,
    generation_created: bool,
    prior_generation_snapshot: Option<StageSnapshot>,
    plugin_stage: PathBuf,
    plugin_stage_snapshot: Option<StageSnapshot>,
    helper: PathBuf,
    pointer: PathBuf,
    helper_backup: PathBuf,
    pointer_backup: PathBuf,
    prior_helper_present: bool,
    prior_pointer_present: bool,
    prior_helper_snapshot: Option<OwnedStageFile>,
    prior_pointer_snapshot: Option<OwnedStageFile>,
    new_helper_snapshot: Option<OwnedStageFile>,
    new_pointer_snapshot: Option<OwnedStageFile>,
    pi_config_path: PathBuf,
    prior_pi_entries: Vec<Value>,
    prior_owned_pi_entry: Option<Value>,
    new_pi_entry: Value,
}

fn deserialize_legacy_journal_ownership_record<'de, D>(
    deserializer: D,
) -> Result<Option<OwnershipRecord>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let record = Option::<CompatibleOwnershipRecord>::deserialize(deserializer)?;
    record
        .map(|mut record| {
            if record.schema_version == OWNERSHIP_SCHEMA
                && record.purge_authority.is_none()
                && record.plugin_state_root.is_some()
                && record.rescue_marker_digest.is_some()
            {
                record.purge_authority = Some(true);
            }
            record.try_into()
        })
        .transpose()
        .map_err(serde::de::Error::custom)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StageSnapshot {
    directories: Vec<OwnedDirectory>,
    files: Vec<OwnedStageFile>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
enum RescueMigrationPhase {
    Intent,
    Prepared,
    PriorBackingUp,
    PriorBackedUp,
    NoticePublishing,
    NoticePublished,
    RecordCommitting,
    RecordCommitted,
    BackupRetiring,
    NoticeCleaning,
    PriorRestoring,
    StageCleaning,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RescueRecordState {
    Prior,
    New,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RescueTreeState {
    Absent,
    Prior,
    New,
    PriorSubset,
    NewSubset,
    PlannedSubset,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RescueMigrationLiveState {
    record: RescueRecordState,
    rescue: RescueTreeState,
    stage: RescueTreeState,
    backup: RescueTreeState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RescueRecoveryRoute {
    Intent,
    BeforeNotice,
    NoticeRollback,
    Committed,
    NoticeCleanup,
    PriorRestore,
    StageCleanup,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RescueMigration {
    schema_version: u32,
    phase: RescueMigrationPhase,
    rescue: PathBuf,
    stage: PathBuf,
    backup: PathBuf,
    prior_record: OwnershipRecord,
    new_record: OwnershipRecord,
    prior_snapshot: StageSnapshot,
    new_snapshot: StageSnapshot,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OwnedDirectory {
    path: PathBuf,
    device: u64,
    inode: u64,
    mode: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OwnedStageFile {
    path: PathBuf,
    device: u64,
    inode: u64,
    mode: u32,
    sha256: String,
}

struct InstallLockGuard {
    _file: File,
}

struct PreparedGeneration {
    binary: PathBuf,
    package: PathBuf,
}

struct PluginSwap {
    helper: PathBuf,
    pointer: PathBuf,
    helper_backup: Option<PathBuf>,
    pointer_backup: Option<PathBuf>,
    stage_snapshot: StageSnapshot,
    helper_snapshot: OwnedStageFile,
    pointer_snapshot: OwnedStageFile,
}

#[derive(Clone)]
struct PiSnapshot {
    program: PathBuf,
    entries: Vec<Value>,
    config_path: PathBuf,
}

struct PiSettings {
    path: PathBuf,
    entries: Vec<Value>,
}

struct ProcessOutput {
    success: bool,
    stdout: Vec<u8>,
    _stderr: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HerdrPluginListResponse {
    id: String,
    result: HerdrPluginListResult,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HerdrPluginListResult {
    plugins: Vec<HerdrPluginRegistration>,
    #[serde(rename = "type")]
    result_type: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HerdrPluginRegistration {
    plugin_id: String,
    enabled: bool,
    plugin_root: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PluginRegistrationState {
    Absent,
    Present,
}

struct AdapterContract {
    name: String,
    version: String,
    pi_peer: String,
    typebox_peer: String,
}

pub async fn install(bundle: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    install_inner(bundle).await.map_err(Into::into)
}

pub async fn repair(
    startup: bool,
    event: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    repair_inner(startup, event).await.map_err(Into::into)
}

pub async fn status(json: bool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    status_inner(json).await.map_err(Into::into)
}

pub async fn remove(
    purge: bool,
    skip_herdr_unregister: bool,
) -> Result<RemovalResult, Box<dyn std::error::Error + Send + Sync>> {
    let result = remove_inner(purge, skip_herdr_unregister).await?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(result)
}

pub(crate) async fn remove_for_session(
    purge: bool,
) -> Result<RemovalResult, Box<dyn std::error::Error + Send + Sync>> {
    remove_inner(purge, false).await.map_err(Into::into)
}

pub async fn extract_release(
    archive: &Path,
    destination: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    extract_release_inner(archive, destination)
        .await
        .map_err(Into::into)
}

pub fn validate_plugin_root(
    path: &Path,
    managed_install: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = require_absolute_normal(path, "plugin root")?;
    if managed_install {
        let boundary = managed_plugin_config_boundary(&path)?;
        validate_or_harden_directory_chain(
            &path,
            DirectoryPolicy::ManagedOwned {
                boundary: &boundary,
                final_mode: Some(0o700),
            },
        )?;
    } else {
        harden_owned_private_directory(&path, "plugin root")?;
    }
    Ok(())
}

async fn install_inner(bundle: &Path) -> ManagedResult<()> {
    let bundle = require_absolute_normal(bundle, "bundle")?;
    validate_directory_chain(&bundle, false)?;
    let bundle_binary = bundle.join("bin/herdr-a2a");
    let bundle_package = bundle.join("pi");
    validate_external_file(&bundle_binary, true)?;
    validate_external_tree(&bundle_package)?;
    let broker_digest = digest_file(&bundle_binary)?;
    let package_digest = digest_tree(&bundle_package)?;
    let plugin_root = required_plugin_root()?;
    let mut pi = detect_pi()?;
    validate_install_compatibility(&plugin_root, &bundle_binary, &bundle_package, pi.as_ref())
        .await?;

    let stable_root = stable_root()?;
    create_private_directory(&stable_root)?;
    let mut install_lock = acquire_install_lock(&stable_root)?;
    reconcile_rescue_migration(&stable_root)?;
    reconcile_transaction(&stable_root).await?;
    if let Some(snapshot) = pi.as_mut() {
        let settings = read_pi_settings()?;
        if settings.path != snapshot.config_path {
            return Err(ManagedError::new(
                "ownership_conflict",
                "Pi settings path changed during transaction recovery",
            ));
        }
        snapshot.entries = settings.entries;
    }
    clean_stale_stages(&stable_root)?;

    harden_owned_private_directory(&plugin_root, "plugin root")?;
    let mut prior = read_record_optional(&stable_root)?;
    if let Some(record) = prior.as_mut() {
        if record.plugin_root != plugin_root {
            return Err(ManagedError::new(
                "ownership_conflict",
                "the existing ownership record belongs to a different plugin root",
            ));
        }
        if matches!(
            record.state,
            InstallState::Removing
                | InstallState::UnregisterPending
                | InstallState::Unregistering
                | InstallState::FinalizingRemoval
        ) {
            return Err(ManagedError::new(
                "removal_incomplete",
                "managed removal must be resumed before install",
            ));
        } else if record.state == InstallState::Removed {
            validate_removed_record_for_reinstall(record, &stable_root)?;
        } else {
            validate_record(record, &stable_root)?;
            validate_pi_entry_if_present(record)?;
            migrate_accepted_v2_record(&stable_root, record)?;
            reconcile_interrupted_plugin_swap(record)?;
            if rescue_layout(record, &stable_root)? != RescueLayout::SourceNotice {
                migrate_rescue_layout(&stable_root, &plugin_root, record)?;
                prior = Some(read_record(&stable_root)?);
            }
        }
    } else {
        reject_unowned_plugin_assets(&plugin_root)?;
    }
    let replacing_generation = prior.as_ref().is_some_and(|record| {
        record.state != InstallState::Removed
            && (record.broker_digest != broker_digest || record.pi_package_digest != package_digest)
    });
    if replacing_generation {
        let record = prior.as_ref().unwrap();
        let registered = read_process_registry(&stable_root, record)?;
        let starting = read_starting_process_registry(&stable_root, record)?;
        if !registered.is_empty() || !starting.is_empty() {
            drop(install_lock);
            drain_managed_processes(&stable_root, record).await?;
            install_lock = acquire_install_lock(&stable_root)?;
            if read_record_optional(&stable_root)? != prior
                || !read_process_registry(&stable_root, record)?.is_empty()
                || !read_starting_process_registry(&stable_root, record)?.is_empty()
            {
                return Err(ManagedError::new(
                    "owned_process_mismatch",
                    "managed installation changed during coordinated update stop",
                ));
            }
        }
    }
    let _install_lock = install_lock;
    let install_kind = match env::var("HERDR_A2A_INSTALL_KIND") {
        Ok(value) if value == "linked-dev" || value == "managed" => value,
        Ok(_) => {
            return Err(ManagedError::new(
                "invalid_install_kind",
                "HERDR_A2A_INSTALL_KIND must be managed or linked-dev",
            ));
        }
        Err(_) => "managed".to_owned(),
    };
    let (generation_directory, generation_files) = generation_plan(
        &stable_root,
        &bundle_package,
        &broker_digest,
        &package_digest,
    )?;
    let token = random_hex()?;
    let helper = plugin_root.join("libexec/herdr-a2a-dispatch");
    let pointer = plugin_root.join("stable-bin-path");
    let prior_helper_snapshot = prior
        .as_ref()
        .filter(|record| record.state != InstallState::Removed)
        .map(|_| snapshot_owned_file(&helper, 0o700))
        .transpose()?;
    let prior_pointer_snapshot = prior
        .as_ref()
        .filter(|record| record.state != InstallState::Removed)
        .map(|_| snapshot_owned_file(&pointer, 0o600))
        .transpose()?;
    let prior_generation_snapshot = prior
        .as_ref()
        .filter(|record| record.state != InstallState::Removed)
        .map(|record| snapshot_stage(record.pi_package_source.parent().unwrap()))
        .transpose()?;
    let pi_settings = read_pi_settings()?;
    let prior_owned_pi_entry = match &prior {
        Some(record) if record.state != InstallState::Removed => {
            Some(record.pi_package_entry.clone())
        }
        Some(_) => None,
        None => {
            let legacy = legacy_source(&plugin_root);
            let legacy_text = path_text(&legacy)?;
            let canonical = Value::String(legacy_text.to_owned());
            let matches: Vec<&Value> = pi_settings
                .entries
                .iter()
                .filter(|entry| pi_entry_source(entry) == Some(legacy_text))
                .collect();
            (matches.len() == 1
                && matches[0] == &canonical
                && digest_tree(&legacy).ok().as_deref() == Some(package_digest.as_str()))
            .then_some(canonical)
        }
    };
    let generation_will_be_created = !generation_directory.exists();
    let mut journal = InstallTransaction {
        schema_version: TRANSACTION_SCHEMA,
        phase: TransactionPhase::Intent,
        prior_record: prior.clone(),
        new_record: None,
        prior_rescue_notice: None,
        prior_rescue_marker: None,
        broker_digest: broker_digest.clone(),
        pi_package_digest: package_digest.clone(),
        generation: generation_directory,
        generation_stage: stable_root
            .join("generations")
            .join(format!(".stage-{token}")),
        generation_stage_snapshot: None,
        generation_files,
        generation_created: generation_will_be_created,
        prior_generation_snapshot,
        plugin_stage: plugin_root.join(format!(".managed-stage-{token}")),
        plugin_stage_snapshot: None,
        helper: helper.clone(),
        pointer: pointer.clone(),
        helper_backup: helper
            .parent()
            .unwrap()
            .join(format!(".herdr-a2a-backup-{token}")),
        pointer_backup: plugin_root.join(format!(".stable-bin-backup-{token}")),
        prior_helper_present: prior_helper_snapshot.is_some(),
        prior_pointer_present: prior_pointer_snapshot.is_some(),
        prior_helper_snapshot,
        prior_pointer_snapshot,
        new_helper_snapshot: None,
        new_pointer_snapshot: None,
        pi_config_path: pi_settings.path.clone(),
        prior_pi_entries: pi_settings.entries,
        prior_owned_pi_entry,
        new_pi_entry: managed_pi_entry(
            &pi_settings.path,
            &generation_plan_path(&stable_root, &broker_digest, &package_digest).join("pi"),
        )?,
    };
    write_transaction(&stable_root, &journal)?;
    journal.phase = TransactionPhase::GenerationPublishing;
    if let Err(error) = write_transaction(&stable_root, &journal) {
        return rollback_transaction_error(&stable_root, error).await;
    }

    let generation = match prepare_generation(
        &stable_root,
        &bundle_binary,
        &bundle_package,
        &broker_digest,
        &package_digest,
        &token,
        |snapshot| {
            journal.generation_stage_snapshot = Some(snapshot);
            write_transaction(&stable_root, &journal)
        },
    ) {
        Ok(value) => value,
        Err(error) => return rollback_transaction_error(&stable_root, error).await,
    };
    journal.phase = TransactionPhase::GenerationPublished;
    if let Err(error) = write_transaction(&stable_root, &journal) {
        return rollback_transaction_error(&stable_root, error).await;
    }
    #[cfg(debug_assertions)]
    if env::var_os("HERDR_A2A_TEST_ABORT_AFTER_GENERATION").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        std::process::abort();
    }
    let same_assets = prior.as_ref().is_some_and(|record| {
        record.state != InstallState::Removed
            && record.broker_digest == broker_digest
            && record.pi_package_digest == package_digest
            && record.stable_binary == generation.binary
            && record.pi_package_source == generation.package
    });

    journal.phase = TransactionPhase::PluginPublishing;
    if let Err(error) = write_transaction(&stable_root, &journal) {
        return rollback_transaction_error(&stable_root, error).await;
    }
    let swap = if same_assets {
        None
    } else {
        match install_plugin_assets(
            &plugin_root,
            &generation.binary,
            &token,
            |phase, snapshot| {
                journal.phase = phase;
                if let Some(snapshot) = snapshot {
                    journal.plugin_stage_snapshot = Some(snapshot);
                }
                write_transaction(&stable_root, &journal)
            },
        ) {
            Ok(value) => Some(value),
            Err(error) => return rollback_transaction_error(&stable_root, error).await,
        }
    };
    journal.plugin_stage_snapshot = swap.as_ref().map(|swap| swap.stage_snapshot.clone());
    journal.new_helper_snapshot = Some(match &swap {
        Some(swap) => swap.helper_snapshot.clone(),
        None => snapshot_owned_file(&helper, 0o700)?,
    });
    journal.new_pointer_snapshot = Some(match &swap {
        Some(swap) => swap.pointer_snapshot.clone(),
        None => snapshot_owned_file(&pointer, 0o600)?,
    });
    journal.phase = TransactionPhase::PluginPublished;
    if let Err(error) = write_transaction(&stable_root, &journal) {
        return rollback_transaction_error(&stable_root, error).await;
    }
    #[cfg(debug_assertions)]
    if env::var_os("HERDR_A2A_TEST_ABORT_AFTER_PLUGIN_SWAP").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        std::process::abort();
    }
    let mut record = match build_record(
        &stable_root,
        &plugin_root,
        &generation,
        prior.as_ref(),
        broker_digest,
        package_digest,
        InstallState::PiAdapterPending,
        install_kind,
    ) {
        Ok(record) => record,
        Err(error) => {
            return rollback_transaction_error(&stable_root, error).await;
        }
    };
    if let Some(snapshot) = pi {
        journal.phase = TransactionPhase::PiMutating;
        if let Err(error) = write_transaction(&stable_root, &journal) {
            return rollback_transaction_error(&stable_root, error).await;
        }
        match configure_install_pi(
            snapshot,
            &generation.package,
            prior
                .as_ref()
                .map(|record| record.pi_package_source.as_path()),
            &plugin_root,
            &bundle_package,
            &record.pi_package_digest,
        )
        .await
        {
            Ok(stored_entry) => {
                record.pi_package_entry = stored_entry.clone();
                journal.new_pi_entry = stored_entry;
                if let Err(error) = write_transaction(&stable_root, &journal) {
                    return rollback_transaction_error(&stable_root, error).await;
                }
                record.state = InstallState::Ready;
                journal.phase = TransactionPhase::PiMutated;
                if let Err(error) = write_transaction(&stable_root, &journal) {
                    return rollback_transaction_error(&stable_root, error).await;
                }
                #[cfg(debug_assertions)]
                if env::var_os("HERDR_A2A_TEST_ABORT_AFTER_PI_MUTATION").as_deref()
                    == Some(std::ffi::OsStr::new("1"))
                {
                    std::process::abort();
                }
            }
            Err(error) => {
                return rollback_transaction_error(&stable_root, error).await;
            }
        }
    }
    let rescue_assets = match prepare_rescue_assets(&stable_root, &plugin_root, &mut record) {
        Ok(assets) => assets,
        Err(error) => return rollback_transaction_error(&stable_root, error).await,
    };
    let (prior_rescue_notice, prior_rescue_marker) =
        match capture_prior_rescue_assets(&stable_root, prior.as_ref()) {
            Ok(snapshot) => snapshot,
            Err(error) => return rollback_transaction_error(&stable_root, error).await,
        };
    journal.new_record = Some(record.clone());
    journal.prior_rescue_notice = prior_rescue_notice;
    journal.prior_rescue_marker = prior_rescue_marker;
    journal.phase = TransactionPhase::RescuePublishing;
    if let Err(error) = write_transaction(&stable_root, &journal) {
        return rollback_transaction_error(&stable_root, error).await;
    }
    if let Err(error) = publish_rescue_assets(&stable_root, &rescue_assets) {
        return rollback_transaction_error(&stable_root, error).await;
    }
    journal.phase = TransactionPhase::RecordCommitting;
    if let Err(error) = write_transaction(&stable_root, &journal) {
        return rollback_transaction_error(&stable_root, error).await;
    }
    journal.phase = TransactionPhase::RecordRenaming;
    if let Err(error) = write_transaction(&stable_root, &journal) {
        return rollback_transaction_error(&stable_root, error).await;
    }
    if let Err(error) = write_record(&stable_root, &record) {
        return rollback_transaction_error(&stable_root, error).await;
    }
    journal.phase = TransactionPhase::RecordCommitted;
    if let Err(error) = write_transaction(&stable_root, &journal) {
        return rollback_transaction_error(&stable_root, error).await;
    }
    #[cfg(debug_assertions)]
    if env::var_os("HERDR_A2A_TEST_ABORT_AFTER_RECORD_COMMITTED").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        std::process::abort();
    }
    if let Some(swap) = &swap
        && let Err(error) = swap.commit()
    {
        eprintln!("herdr-a2a: installed assets committed; deferred backup cleanup: {error}");
    }
    if let Some(prior) = prior {
        remove_superseded_generation(
            &stable_root,
            &prior,
            &record,
            journal.prior_generation_snapshot.as_ref(),
        )?;
    }
    clear_transaction(&stable_root)?;
    print_state(&record.state);
    Ok(())
}

async fn repair_inner(_startup: bool, event: bool) -> ManagedResult<()> {
    if event && !event_is_pi()? {
        return Ok(());
    }
    let stable_root = stable_root()?;
    validate_private_directory(&stable_root, 0o700)?;
    let _lock = acquire_install_lock(&stable_root)?;
    reconcile_rescue_migration(&stable_root)?;
    reconcile_transaction(&stable_root).await?;
    let mut record = read_record(&stable_root)?;
    if record.state == InstallState::Removed {
        return Err(ManagedError::new(
            "already_removed",
            "managed installation is removed",
        ));
    }
    if matches!(
        record.state,
        InstallState::Removing
            | InstallState::UnregisterPending
            | InstallState::Unregistering
            | InstallState::FinalizingRemoval
    ) {
        return Err(ManagedError::new(
            "removal_incomplete",
            "managed removal must be resumed before repair",
        ));
    }
    migrate_accepted_v2_record(&stable_root, &mut record)?;
    record = reconcile_relocated_managed_plugin_root(&stable_root, &record)?;
    reconcile_interrupted_plugin_swap(&record)?;
    if let Err(error) = validate_record(&record, &stable_root) {
        record.state = InstallState::Failed;
        record.last_error = Some(error.to_string());
        let _ = write_record(&stable_root, &record);
        return Err(error);
    }
    let pi = detect_pi()?;
    validate_repair_compatibility(&record, pi.as_ref()).await?;
    if rescue_layout(&record, &stable_root)? != RescueLayout::SourceNotice {
        migrate_rescue_layout(&stable_root, &record.plugin_root, &record)?;
        record = read_record(&stable_root)?;
    }
    match pi {
        None => {
            if record.state != InstallState::PiAdapterPending || record.last_error.is_some() {
                record.state = InstallState::PiAdapterPending;
                record.last_error = None;
                write_record(&stable_root, &record)?;
            }
        }
        Some(snapshot) => {
            let mut pi_entry_changed = false;
            let matching: Vec<&Value> = snapshot
                .entries
                .iter()
                .filter(|entry| {
                    pi_entry_matches_path(entry, &snapshot.config_path, &record.pi_package_source)
                })
                .collect();
            if matching.len() > 1
                || matching
                    .first()
                    .is_some_and(|entry| **entry != record.pi_package_entry)
            {
                let error = ManagedError::new(
                    "ownership_conflict",
                    "Pi contains a same-source entry that differs from the exact recorded entry",
                );
                record.state = InstallState::Failed;
                record.last_error = Some(error.to_string());
                write_record(&stable_root, &record)?;
                return Err(error);
            }
            if matching.is_empty()
                && let Err(error) =
                    run_pi_checked(&snapshot.program, "install", &record.pi_package_source).await
            {
                record.state = InstallState::Failed;
                record.last_error = Some(error.to_string());
                write_record(&stable_root, &record)?;
                return Err(error);
            }
            if matching.is_empty() {
                let after = read_pi_settings()?;
                if after.path != snapshot.config_path {
                    return Err(ManagedError::new(
                        "ownership_conflict",
                        "Pi settings path changed during repair",
                    ));
                }
                let stored_entry = authenticated_managed_pi_entry(
                    &after.entries,
                    &after.path,
                    &record.pi_package_source,
                )?;
                if stored_entry != record.pi_package_entry {
                    record.pi_package_entry = stored_entry;
                    pi_entry_changed = true;
                }
            }
            if pi_entry_changed
                || record.state != InstallState::Ready
                || record.last_error.is_some()
            {
                record.state = InstallState::Ready;
                record.last_error = None;
                write_record(&stable_root, &record)?;
            }
        }
    }
    if event {
        println!("Herdr A2A is configured; activation occurs on the next Pi launch.");
    } else {
        print_state(&record.state);
    }
    Ok(())
}

async fn status_inner(json: bool) -> ManagedResult<()> {
    let stable_root = stable_root()?;
    if !stable_root.exists() {
        return print_missing_status(json);
    }
    validate_private_directory(&stable_root, 0o700)?;
    let _lock = acquire_install_lock(&stable_root)?;
    reconcile_rescue_migration(&stable_root)?;
    reconcile_transaction(&stable_root).await?;
    let record = read_record_optional(&stable_root)?;
    if record
        .as_ref()
        .is_some_and(|record| record.state == InstallState::Removed)
    {
        return Err(ManagedError::new(
            "already_removed",
            "managed installation is removed",
        ));
    }
    let validated = match record {
        Some(record) => {
            match validate_record(&record, &stable_root).and_then(|()| validate_ready_pi(&record)) {
                Ok(()) => Some(record),
                Err(error) => {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string(&serde_json::json!({
                                "schema_version": OWNERSHIP_SCHEMA,
                                "state": InstallState::Failed,
                                "last_error": error.to_string()
                            }))
                            .map_err(|encode| ManagedError::new(
                                "ownership_record_invalid",
                                encode.to_string()
                            ))?
                        );
                    } else {
                        println!("failed: {error}");
                    }
                    return Ok(());
                }
            }
        }
        None => None,
    };
    if json {
        match validated {
            Some(record) => println!(
                "{}",
                serde_json::to_string(&record).map_err(|error| {
                    ManagedError::new("ownership_record_invalid", error.to_string())
                })?
            ),
            None => println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "schema_version": OWNERSHIP_SCHEMA,
                    "state": InstallState::Failed,
                    "last_error": "not_installed"
                }))
                .map_err(|error| ManagedError::new(
                    "ownership_record_invalid",
                    error.to_string()
                ))?
            ),
        }
    } else if let Some(record) = validated {
        print_state(&record.state);
    } else {
        println!("failed: not installed");
    }
    Ok(())
}

async fn reconcile_unregistering(
    stable_root: &Path,
    record: &mut OwnershipRecord,
) -> ManagedResult<PluginRegistrationState> {
    let state = observe_exact_plugin_registration(record).await?;
    record.state = match state {
        PluginRegistrationState::Absent => InstallState::FinalizingRemoval,
        PluginRegistrationState::Present => InstallState::UnregisterPending,
    };
    record.last_error = None;
    write_record(stable_root, record)?;
    Ok(state)
}

async fn observe_exact_plugin_registration(
    record: &OwnershipRecord,
) -> ManagedResult<PluginRegistrationState> {
    let herdr = find_in_path("herdr").ok_or_else(|| {
        ManagedError::new(
            "herdr_status_unavailable",
            "Herdr executable is unavailable",
        )
    })?;
    let output = run_herdr_bounded(
        &herdr,
        &[
            OsString::from("plugin"),
            OsString::from("list"),
            OsString::from("--plugin"),
            OsString::from("herdr.a2a"),
            OsString::from("--json"),
        ],
        "herdr_status_unavailable",
    )
    .await?;
    if !output.success {
        return Err(ManagedError::new(
            "herdr_status_unavailable",
            "Herdr plugin status command failed",
        ));
    }
    decode_exact_plugin_registration(&output.stdout, record)
}

fn decode_exact_plugin_registration(
    encoded: &[u8],
    record: &OwnershipRecord,
) -> ManagedResult<PluginRegistrationState> {
    let response: HerdrPluginListResponse = serde_json::from_slice(encoded).map_err(|_| {
        ManagedError::new(
            "herdr_status_invalid",
            "Herdr plugin status was not an exact JSON response",
        )
    })?;
    if response.id != "cli:plugin"
        || response.result.result_type != "plugin_list"
        || response.result.plugins.len() > MAX_HERDR_PLUGIN_REGISTRATIONS
    {
        return Err(ManagedError::new(
            "herdr_status_invalid",
            "Herdr plugin status was not an exact registration listing",
        ));
    }
    match response.result.plugins.as_slice() {
        [] => Ok(PluginRegistrationState::Absent),
        [registration] if registration.plugin_id == "herdr.a2a" && registration.enabled => {
            if registration.plugin_root != record.plugin_root {
                return Err(ManagedError::new(
                    "ownership_conflict",
                    "Herdr plugin registration belongs to a different root",
                ));
            }
            Ok(PluginRegistrationState::Present)
        }
        _ => Err(ManagedError::new(
            "herdr_status_invalid",
            "Herdr plugin status did not contain one exact enabled registration",
        )),
    }
}

async fn run_exact_herdr_uninstall_bounded() -> ManagedResult<ProcessOutput> {
    let herdr = find_in_path("herdr").ok_or_else(|| {
        ManagedError::new("herdr_uninstall_failed", "Herdr executable was not found")
    })?;
    run_herdr_bounded(
        &herdr,
        &[
            OsString::from("plugin"),
            OsString::from("uninstall"),
            OsString::from("herdr.a2a"),
        ],
        "herdr_uninstall_failed",
    )
    .await
}

async fn remove_inner(purge: bool, skip_herdr_unregister: bool) -> ManagedResult<RemovalResult> {
    let stable_root = stable_root()?;
    if !stable_root.exists() {
        return Err(ManagedError::new(
            "ownership_record_missing",
            "managed ownership record is absent",
        ));
    }
    validate_private_directory(&stable_root, 0o700)?;
    let install_lock = acquire_install_lock(&stable_root)?;
    reconcile_rescue_migration(&stable_root)?;
    reconcile_transaction(&stable_root).await?;
    let mut record = read_record_optional(&stable_root)?.ok_or_else(|| {
        ManagedError::new(
            "ownership_record_missing",
            "managed ownership record is absent",
        )
    })?;
    if record.state == InstallState::Removed {
        return Err(ManagedError::new(
            "already_removed",
            "managed installation was already removed",
        ));
    }
    if matches!(
        record.state,
        InstallState::Removing
            | InstallState::UnregisterPending
            | InstallState::Unregistering
            | InstallState::FinalizingRemoval
    ) {
        validate_removal_inventory(&record, &stable_root)?;
        validate_pi_entry_if_present(&record)?;
    } else {
        validate_record_for_removal(&record, &stable_root, purge)?;
        validate_pi_entry_if_present(&record)?;
    }
    migrate_accepted_v2_record(&stable_root, &mut record)?;

    let existing_removal = read_removal_transaction(&stable_root)?;
    if !purge && existing_removal.is_some() {
        return Err(ManagedError::new(
            "recovery_needed",
            "an authenticated purge must be resumed with --purge",
        ));
    }
    let (mut removal_transaction, purge_snapshot) = if purge {
        match existing_removal {
            Some(transaction) => {
                validate_removal_transaction(&transaction, &record, skip_herdr_unregister)?;
                let snapshot = match fs::symlink_metadata(&transaction.purge_root) {
                    Ok(_) if transaction.phase == RemovalTransactionPhase::Deleted => {
                        return Err(ManagedError::new(
                            "unsafe_owned_state",
                            "a deleted authenticated purge root unexpectedly reappeared",
                        ));
                    }
                    Ok(_) => {
                        let current = snapshot_stage(&transaction.purge_root).map_err(|error| {
                            ManagedError::new("unsafe_owned_state", error.to_string())
                        })?;
                        if current != transaction.purge_snapshot {
                            return Err(ManagedError::new(
                                "unsafe_owned_state",
                                "the authenticated purge tree changed during recovery",
                            ));
                        }
                        Some(current)
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        if transaction.phase == RemovalTransactionPhase::Intent {
                            return Err(ManagedError::new(
                                "unsafe_owned_state",
                                "the purge root disappeared before deletion was authorized",
                            ));
                        }
                        None
                    }
                    Err(error) => {
                        return Err(ManagedError::io(
                            "unsafe_owned_state",
                            "cannot inspect authenticated purge recovery root",
                            error,
                        ));
                    }
                };
                (Some(transaction), snapshot)
            }
            None => {
                let root = validate_purge_root(&record, &stable_root)?;
                let snapshot = snapshot_stage(&root)
                    .map_err(|error| ManagedError::new("unsafe_owned_state", error.to_string()))?;
                let transaction = RemovalTransaction {
                    schema_version: REMOVAL_TRANSACTION_SCHEMA,
                    phase: RemovalTransactionPhase::Intent,
                    purge_root: root,
                    purge_snapshot: snapshot.clone(),
                    skip_herdr_unregister,
                };
                write_removal_transaction(&stable_root, &transaction)?;
                (Some(transaction), Some(snapshot))
            }
        }
    } else {
        (None, None)
    };
    validate_removal_executable(&record)?;

    if !matches!(
        record.state,
        InstallState::Removing
            | InstallState::UnregisterPending
            | InstallState::Unregistering
            | InstallState::FinalizingRemoval
    ) {
        record.state = InstallState::Removing;
        record.last_error = None;
        write_record(&stable_root, &record)?;
    }

    let registered = read_process_registry(&stable_root, &record)?;
    let starting = read_starting_process_registry(&stable_root, &record)?;
    drop(install_lock);
    if !registered.is_empty() || !starting.is_empty() {
        drain_managed_processes(&stable_root, &record).await?;
    }
    let _install_lock = acquire_install_lock(&stable_root)?;
    let resumed = read_record(&stable_root)?;
    if resumed != record
        || !read_process_registry(&stable_root, &record)?.is_empty()
        || !read_starting_process_registry(&stable_root, &record)?.is_empty()
    {
        return Err(ManagedError::new(
            "owned_process_mismatch",
            "managed process registry changed during coordinated stop",
        ));
    }
    remove_exact_pi_entry(&record).await?;
    let retained_unregister = unregister_retained_paths(&record)?;
    remove_recorded_assets_except(&record, &stable_root, &retained_unregister)?;
    #[cfg(debug_assertions)]
    if env::var_os("HERDR_A2A_TEST_REPLACE_REGISTRY_BEFORE_UNLINK").as_deref()
        == Some(OsStr::new("directory"))
    {
        fs::create_dir(stable_root.join(PROCESS_REGISTRY)).map_err(|error| {
            ManagedError::io(
                "removal_failed",
                "cannot substitute the process registry test fixture",
                error,
            )
        })?;
    }
    remove_if_exists(&stable_root.join(PROCESS_REGISTRY))?;
    remove_if_exists(&stable_root.join(STARTING_PROCESS_REGISTRY))?;
    sync_directory(&stable_root)?;
    if let Some(transaction) = removal_transaction.as_mut()
        && transaction.phase != RemovalTransactionPhase::Deleted
    {
        transaction.phase = RemovalTransactionPhase::Deleting;
        write_removal_transaction(&stable_root, transaction)?;
        if let Some(snapshot) = purge_snapshot {
            remove_exact_stage(&snapshot)
                .map_err(|error| ManagedError::new("unsafe_owned_state", error.to_string()))?;
            #[cfg(debug_assertions)]
            if env::var_os("HERDR_A2A_TEST_ABORT_AFTER_PURGE_ROOT_DELETION").as_deref()
                == Some(OsStr::new("1"))
            {
                std::process::abort();
            }
        }
        transaction.phase = RemovalTransactionPhase::Deleted;
        write_removal_transaction(&stable_root, transaction)?;
    }

    if record.state == InstallState::Removing {
        record.state = InstallState::UnregisterPending;
        record.last_error = None;
        write_record(&stable_root, &record)?;
    }

    match record.state {
        InstallState::UnregisterPending => {
            record.state = InstallState::Unregistering;
            record.last_error = None;
            write_record(&stable_root, &record)?;
            let external_result = if skip_herdr_unregister {
                None
            } else {
                Some(run_exact_herdr_uninstall_bounded().await)
            };
            #[cfg(debug_assertions)]
            if matches!(external_result.as_ref(), Some(Ok(output)) if output.success)
                && env::var_os("HERDR_A2A_TEST_ABORT_AFTER_EXTERNAL_UNREGISTER_BEFORE_PHASE_WRITE")
                    .as_deref()
                    == Some(OsStr::new("1"))
            {
                std::process::abort();
            }
            match reconcile_unregistering(&stable_root, &mut record).await? {
                PluginRegistrationState::Absent => {}
                PluginRegistrationState::Present => {
                    return Err(external_result.and_then(|result| result.err()).unwrap_or_else(|| {
                            ManagedError::new(
                                "herdr_uninstall_failed",
                                "Herdr plugin unregister command did not remove its exact registration",
                            )
                        }));
                }
            }
        }
        InstallState::Unregistering => {
            if reconcile_unregistering(&stable_root, &mut record).await?
                == PluginRegistrationState::Present
            {
                return Err(ManagedError::new(
                    "herdr_uninstall_failed",
                    "Herdr plugin unregister remains pending",
                ));
            }
        }
        InstallState::FinalizingRemoval => {}
        _ => {
            return Err(ManagedError::new(
                "ownership_record_invalid",
                "managed removal reached an invalid unregister state",
            ));
        }
    }

    remove_recorded_assets(&record, &stable_root)?;
    record.state = InstallState::Removed;
    record.last_error = None;
    write_record(&stable_root, &record)?;
    if removal_transaction.is_some() {
        clear_removal_transaction(&stable_root)?;
    }
    let result = RemovalResult {
        state: "removed",
        retained_data: !purge,
    };
    Ok(result)
}

fn validate_removal_executable(record: &OwnershipRecord) -> ManagedResult<()> {
    let current = env::current_exe()
        .map_err(|error| {
            ManagedError::io("owned_process_mismatch", "cannot locate executable", error)
        })?
        .canonicalize()
        .map_err(|error| {
            ManagedError::io("owned_process_mismatch", "cannot resolve executable", error)
        })?;
    if digest_file(&current)? != record.broker_digest {
        return Err(ManagedError::new(
            "owned_process_mismatch",
            "removal executable does not match the recorded managed binary digest",
        ));
    }
    Ok(())
}

#[cfg(not(test))]
async fn stop_registered_process(
    process: &ManagedProcessEntry,
    deadline: tokio::time::Instant,
) -> ManagedResult<()> {
    crate::coordinator::stop_registered_process(process, deadline)
        .await
        .map_err(|error| {
            ManagedError::new(
                "owned_process_mismatch",
                format!("registered coordinator/broker proof failed: {error}"),
            )
        })
}

async fn drain_managed_processes(
    stable_root: &Path,
    record: &OwnershipRecord,
) -> ManagedResult<()> {
    let deadline = tokio::time::Instant::now() + PROCESS_DRAIN_TIMEOUT;
    let mut work_began = false;
    loop {
        let starting = read_starting_process_registry(stable_root, record)?;
        let registered = read_process_registry(stable_root, record)?;
        if starting.is_empty() && registered.is_empty() {
            ensure_drain_deadline(deadline, work_began)?;
            return Ok(());
        }
        work_began = true;
        ensure_drain_deadline(deadline, work_began)?;
        for process in &starting {
            ensure_drain_deadline(deadline, work_began)?;
            let stop_deadline = bounded_stop_deadline(deadline, PROCESS_DRAIN_TIMEOUT)?;
            stop_starting_process(process, stop_deadline).await?;
        }
        for process in &registered {
            ensure_drain_deadline(deadline, work_began)?;
            let stop_deadline = bounded_stop_deadline(deadline, PROCESS_DRAIN_TIMEOUT)?;
            stop_registered_process(process, stop_deadline).await?;
        }
        ensure_drain_deadline(deadline, work_began)?;
    }
}

fn ensure_drain_deadline(deadline: tokio::time::Instant, work_began: bool) -> ManagedResult<()> {
    if work_began && tokio::time::Instant::now() >= deadline {
        return Err(ManagedError::new(
            "owned_process_mismatch",
            "managed process registries did not drain before the coordinated-stop deadline",
        ));
    }
    Ok(())
}

fn bounded_stop_deadline(
    shared_deadline: tokio::time::Instant,
    phase_limit: Duration,
) -> ManagedResult<tokio::time::Instant> {
    ensure_drain_deadline(shared_deadline, true)?;
    Ok(shared_deadline.min(tokio::time::Instant::now() + phase_limit))
}

#[cfg(not(test))]
async fn stop_starting_process(
    process: &ManagedStartingProcessEntry,
    deadline: tokio::time::Instant,
) -> ManagedResult<()> {
    crate::coordinator::stop_starting_process(process, deadline)
        .await
        .map_err(|error| {
            ManagedError::new(
                "owned_process_mismatch",
                format!("starting coordinator/broker proof failed: {error}"),
            )
        })?;
    unregister_managed_process_start(process)
}

#[cfg(test)]
async fn stop_registered_process(
    _process: &ManagedProcessEntry,
    _deadline: tokio::time::Instant,
) -> ManagedResult<()> {
    Err(ManagedError::new(
        "owned_process_mismatch",
        "registered process stop is unavailable in direct source-module tests",
    ))
}

#[cfg(test)]
async fn stop_starting_process(
    _process: &ManagedStartingProcessEntry,
    _deadline: tokio::time::Instant,
) -> ManagedResult<()> {
    Err(ManagedError::new(
        "owned_process_mismatch",
        "starting process stop is unavailable in direct source-module tests",
    ))
}

pub(crate) fn managed_executable_digest(path: &Path) -> Result<String, ManagedError> {
    digest_file(path)
}

pub(crate) fn reserve_managed_process_start(
    entry: ManagedStartingProcessEntry,
) -> Result<bool, ManagedError> {
    if env::var_os("HERDR_A2A_PLUGIN_ROOT").is_none() {
        return Ok(false);
    }
    let stable_root = stable_root()?;
    validate_private_directory(&stable_root, 0o700)?;
    let _lock = acquire_install_lock(&stable_root)?;
    let record = read_record(&stable_root)?;
    if !matches!(
        record.state,
        InstallState::Ready | InstallState::PiAdapterPending
    ) {
        return Err(ManagedError::new(
            "owned_process_mismatch",
            "managed installation is not accepting process reservations",
        ));
    }
    validate_record(&record, &stable_root)?;
    validate_starting_process_entry(&entry, &record)?;
    if read_process_registry(&stable_root, &record)?
        .iter()
        .any(|existing| existing.scope_key == entry.scope_key)
    {
        return Err(ManagedError::new(
            "owned_process_mismatch",
            "a registered process generation already owns this managed scope",
        ));
    }
    let mut entries = read_starting_process_registry(&stable_root, &record)?;
    if entries
        .iter()
        .any(|existing| existing.scope_key == entry.scope_key && existing != &entry)
    {
        return Err(ManagedError::new(
            "owned_process_mismatch",
            "a different starting process generation already owns this managed scope",
        ));
    }
    if !entries.contains(&entry) {
        entries.push(entry);
        entries.sort_by(|left, right| left.scope_key.cmp(&right.scope_key));
        write_starting_process_registry(&stable_root, &entries)?;
    }
    Ok(true)
}

pub(crate) fn bind_managed_process_start_broker(
    original: &ManagedStartingProcessEntry,
    broker: ManagedStartingBrokerProof,
) -> Result<(), ManagedError> {
    if env::var_os("HERDR_A2A_PLUGIN_ROOT").is_none() {
        return Ok(());
    }
    let stable_root = stable_root()?;
    validate_private_directory(&stable_root, 0o700)?;
    let _lock = acquire_install_lock(&stable_root)?;
    let record = read_record(&stable_root)?;
    if !matches!(
        record.state,
        InstallState::Ready | InstallState::PiAdapterPending
    ) {
        return Err(ManagedError::new(
            "owned_process_mismatch",
            "managed installation is not accepting process reservations",
        ));
    }
    validate_starting_process_entry(original, &record)?;
    validate_starting_broker_proof(&broker, &record)?;
    if original.broker.is_some() {
        return Err(ManagedError::new(
            "owned_process_mismatch",
            "managed starting reservation already has a broker proof",
        ));
    }
    let mut entries = read_starting_process_registry(&stable_root, &record)?;
    let reserved = entries
        .iter_mut()
        .find(|entry| *entry == original)
        .ok_or_else(|| {
            ManagedError::new(
                "owned_process_mismatch",
                "managed starting reservation disappeared before broker binding",
            )
        })?;
    if reserved.broker.is_some() {
        return Err(ManagedError::new(
            "owned_process_mismatch",
            "managed starting reservation changed before broker binding",
        ));
    }
    reserved.broker = Some(broker);
    write_starting_process_registry(&stable_root, &entries)
}

pub(crate) fn unregister_managed_process_start(
    entry: &ManagedStartingProcessEntry,
) -> Result<(), ManagedError> {
    if env::var_os("HERDR_A2A_PLUGIN_ROOT").is_none() {
        return Ok(());
    }
    let stable_root = stable_root()?;
    if !stable_root.exists() {
        return Ok(());
    }
    validate_private_directory(&stable_root, 0o700)?;
    let _lock = acquire_install_lock(&stable_root)?;
    let Some(record) = read_record_optional(&stable_root)? else {
        return Ok(());
    };
    let mut entries = read_starting_process_registry(&stable_root, &record)?;
    let prior_len = entries.len();
    entries.retain(|existing| existing != entry);
    if entries.len() != prior_len {
        write_starting_process_registry(&stable_root, &entries)?;
    }
    Ok(())
}

pub(crate) fn register_managed_process(entry: ManagedProcessEntry) -> Result<bool, ManagedError> {
    if env::var_os("HERDR_A2A_PLUGIN_ROOT").is_none() {
        return Ok(false);
    }
    let stable_root = stable_root()?;
    validate_private_directory(&stable_root, 0o700)?;
    let _lock = acquire_install_lock(&stable_root)?;
    let record = read_record(&stable_root)?;
    if !matches!(
        record.state,
        InstallState::Ready | InstallState::PiAdapterPending
    ) {
        return Err(ManagedError::new(
            "owned_process_mismatch",
            "managed installation is not accepting process registrations",
        ));
    }
    validate_record(&record, &stable_root)?;
    validate_process_entry(&entry, &record)?;
    let mut starting = read_starting_process_registry(&stable_root, &record)?;
    let reservation_index = starting
        .iter()
        .position(|reserved| starting_matches_process(reserved, &entry))
        .ok_or_else(|| {
            ManagedError::new(
                "owned_process_mismatch",
                "managed process has no exact bound starting reservation",
            )
        })?;
    let mut entries = read_process_registry(&stable_root, &record)?;
    if entries
        .iter()
        .any(|existing| existing.scope_key == entry.scope_key && existing != &entry)
    {
        return Err(ManagedError::new(
            "owned_process_mismatch",
            "a different process generation already owns this managed scope",
        ));
    }
    if !entries.contains(&entry) {
        entries.push(entry);
        entries.sort_by(|left, right| left.scope_key.cmp(&right.scope_key));
        write_process_registry(&stable_root, &entries)?;
    }
    starting.remove(reservation_index);
    write_starting_process_registry(&stable_root, &starting)?;
    Ok(true)
}

pub(crate) fn unregister_managed_process(entry: &ManagedProcessEntry) -> Result<(), ManagedError> {
    if env::var_os("HERDR_A2A_PLUGIN_ROOT").is_none() {
        return Ok(());
    }
    let stable_root = stable_root()?;
    if !stable_root.exists() {
        return Ok(());
    }
    validate_private_directory(&stable_root, 0o700)?;
    let _lock = acquire_install_lock(&stable_root)?;
    let Some(record) = read_record_optional(&stable_root)? else {
        return Ok(());
    };
    let mut entries = read_process_registry(&stable_root, &record)?;
    let prior_len = entries.len();
    entries.retain(|existing| existing != entry);
    if entries.len() != prior_len {
        write_process_registry(&stable_root, &entries)?;
    }
    let mut starting = read_starting_process_registry(&stable_root, &record)?;
    let prior_starting_len = starting.len();
    starting.retain(|reserved| !starting_matches_process(reserved, entry));
    if starting.len() != prior_starting_len {
        write_starting_process_registry(&stable_root, &starting)?;
    }
    Ok(())
}

fn validate_process_entry(
    entry: &ManagedProcessEntry,
    record: &OwnershipRecord,
) -> ManagedResult<()> {
    require_absolute_normal(&entry.runtime_root, "process runtime root")?;
    require_absolute_normal(&entry.executable_path, "process executable")?;
    for value in [
        path_text(&entry.runtime_root)?,
        path_text(&entry.executable_path)?,
        &entry.session_key,
        &entry.workspace_id,
        &entry.scope_key,
        &entry.coordinator_start,
        &entry.broker_start,
        &entry.broker_instance_id,
        &entry.executable_digest,
        &entry.control_nonce,
    ] {
        if value.is_empty() || value.len() > MAX_POINTER_BYTES || value.contains(['|', '\r', '\n'])
        {
            return Err(ManagedError::new(
                "owned_process_mismatch",
                "managed process registry field is invalid",
            ));
        }
    }
    if entry.coordinator_pid == 0
        || entry.broker_pid == 0
        || entry.control_port == 0
        || entry.executable_path != record.stable_binary
        || entry.executable_digest != record.broker_digest
        || entry.scope_key.len() != 64
        || entry.session_key.len() != 64
        || entry.executable_digest.len() != 64
        || ![
            &entry.scope_key,
            &entry.session_key,
            &entry.executable_digest,
        ]
        .iter()
        .all(|value| {
            value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
    {
        return Err(ManagedError::new(
            "owned_process_mismatch",
            "managed process registry identity is invalid",
        ));
    }
    Ok(())
}

fn validate_starting_process_entry(
    entry: &ManagedStartingProcessEntry,
    record: &OwnershipRecord,
) -> ManagedResult<()> {
    require_absolute_normal(&entry.runtime_root, "starting process runtime root")?;
    require_absolute_normal(&entry.executable_path, "starting process executable")?;
    for value in [
        path_text(&entry.runtime_root)?,
        path_text(&entry.executable_path)?,
        &entry.session_key,
        &entry.workspace_id,
        &entry.scope_key,
        &entry.coordinator_start,
        &entry.executable_digest,
        &entry.expected_generation,
        &entry.control_nonce,
    ] {
        if value.is_empty() || value.len() > MAX_POINTER_BYTES || value.contains(['|', '\r', '\n'])
        {
            return Err(ManagedError::new(
                "owned_process_mismatch",
                "managed starting reservation field is invalid",
            ));
        }
    }
    if entry.coordinator_pid == 0
        || entry.control_port == 0
        || entry.executable_path != record.stable_binary
        || entry.executable_digest != record.broker_digest
        || entry.expected_generation != expected_generation_for_record(record)?
        || entry.scope_key.len() != 64
        || entry.session_key.len() != 64
        || entry.executable_digest.len() != 64
        || ![
            &entry.scope_key,
            &entry.session_key,
            &entry.executable_digest,
        ]
        .iter()
        .all(|value| {
            value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
    {
        return Err(ManagedError::new(
            "owned_process_mismatch",
            "managed starting reservation identity is invalid",
        ));
    }
    if let Some(broker) = &entry.broker {
        validate_starting_broker_proof(broker, record)?;
    }
    Ok(())
}

fn validate_starting_broker_proof(
    broker: &ManagedStartingBrokerProof,
    record: &OwnershipRecord,
) -> ManagedResult<()> {
    require_absolute_normal(&broker.executable_path, "starting broker executable")?;
    for value in [
        path_text(&broker.executable_path)?,
        &broker.broker_start,
        &broker.executable_digest,
    ] {
        if value.is_empty() || value.len() > MAX_POINTER_BYTES || value.contains(['|', '\r', '\n'])
        {
            return Err(ManagedError::new(
                "owned_process_mismatch",
                "managed starting broker proof field is invalid",
            ));
        }
    }
    if broker.broker_pid == 0
        || broker.executable_path != record.stable_binary
        || broker.executable_digest != record.broker_digest
        || broker.executable_digest.len() != 64
        || !broker
            .executable_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ManagedError::new(
            "owned_process_mismatch",
            "managed starting broker proof identity is invalid",
        ));
    }
    Ok(())
}

fn expected_generation_for_record(record: &OwnershipRecord) -> ManagedResult<String> {
    let binary = &record.stable_binary;
    let Some(bin) = binary.parent() else {
        return Err(ManagedError::new(
            "owned_process_mismatch",
            "managed stable executable has no bin parent",
        ));
    };
    let Some(generation) = bin.parent() else {
        return Err(ManagedError::new(
            "owned_process_mismatch",
            "managed stable executable has no generation parent",
        ));
    };
    let Some(expected_generation) = generation.file_name().and_then(|name| name.to_str()) else {
        return Err(ManagedError::new(
            "owned_process_mismatch",
            "managed stable executable generation name is invalid",
        ));
    };
    if binary.file_name() != Some(OsStr::new("herdr-a2a"))
        || bin.file_name() != Some(OsStr::new("bin"))
        || generation.parent().and_then(Path::file_name) != Some(OsStr::new("generations"))
        || expected_generation.len() != 32
        || !expected_generation
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ManagedError::new(
            "owned_process_mismatch",
            "managed stable executable generation layout is invalid",
        ));
    }
    Ok(expected_generation.to_owned())
}

fn starting_matches_process(
    starting: &ManagedStartingProcessEntry,
    process: &ManagedProcessEntry,
) -> bool {
    starting.runtime_root == process.runtime_root
        && starting.session_key == process.session_key
        && starting.workspace_id == process.workspace_id
        && starting.scope_key == process.scope_key
        && starting.coordinator_pid == process.coordinator_pid
        && starting.coordinator_start == process.coordinator_start
        && starting.executable_path == process.executable_path
        && starting.executable_digest == process.executable_digest
        && starting.control_port == process.control_port
        && starting.control_nonce == process.control_nonce
        && starting.broker.as_ref()
            == Some(&ManagedStartingBrokerProof {
                broker_pid: process.broker_pid,
                broker_start: process.broker_start.clone(),
                executable_path: process.executable_path.clone(),
                executable_digest: process.executable_digest.clone(),
            })
}

fn read_starting_process_registry(
    stable_root: &Path,
    record: &OwnershipRecord,
) -> ManagedResult<Vec<ManagedStartingProcessEntry>> {
    let path = stable_root.join(STARTING_PROCESS_REGISTRY);
    match fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(ManagedError::io(
                "owned_process_mismatch",
                "cannot inspect managed starting process registry",
                error,
            ));
        }
    }
    validate_owned_regular_file(&path, 0o600, "owned_process_mismatch")
        .map_err(|error| ManagedError::new("owned_process_mismatch", error.to_string()))?;
    let mut file = open_validated_absolute_file(&path)
        .map_err(|error| ManagedError::new("owned_process_mismatch", error.to_string()))?;
    let metadata = file.metadata().map_err(|error| {
        ManagedError::io(
            "owned_process_mismatch",
            "cannot inspect managed starting process registry",
            error,
        )
    })?;
    let registry: StartingProcessRegistry = parse_bounded_opened_json(
        &mut file,
        metadata.len(),
        MAX_PROCESS_REGISTRY_BYTES,
        "owned_process_mismatch",
    )?;
    if registry.schema_version != STARTING_PROCESS_REGISTRY_SCHEMA
        || registry.entries.len() > MAX_PROCESS_REGISTRY_ENTRIES
    {
        return Err(ManagedError::new(
            "owned_process_mismatch",
            "managed starting process registry schema is invalid",
        ));
    }
    let mut scopes = BTreeSet::new();
    for entry in &registry.entries {
        validate_starting_process_entry(entry, record)?;
        if !scopes.insert(entry.scope_key.clone()) {
            return Err(ManagedError::new(
                "owned_process_mismatch",
                "managed starting process registry contains a duplicate scope",
            ));
        }
    }
    Ok(registry.entries)
}

fn write_starting_process_registry(
    stable_root: &Path,
    entries: &[ManagedStartingProcessEntry],
) -> ManagedResult<()> {
    if entries.is_empty() {
        remove_if_exists(&stable_root.join(STARTING_PROCESS_REGISTRY))?;
        sync_directory(stable_root)?;
        return Ok(());
    }
    if entries.len() > MAX_PROCESS_REGISTRY_ENTRIES {
        return Err(ManagedError::new(
            "owned_process_mismatch",
            "managed starting process registry is full",
        ));
    }
    let record = read_record(stable_root)?;
    for entry in entries {
        validate_starting_process_entry(entry, &record)?;
    }
    let encoded = serde_json::to_vec(&StartingProcessRegistry {
        schema_version: STARTING_PROCESS_REGISTRY_SCHEMA,
        entries: entries.to_vec(),
    })
    .map_err(|error| ManagedError::new("owned_process_mismatch", error.to_string()))?;
    if encoded.len() as u64 > MAX_PROCESS_REGISTRY_BYTES {
        return Err(ManagedError::new(
            "owned_process_mismatch",
            "managed starting process registry is oversized",
        ));
    }
    let path = stable_root.join(STARTING_PROCESS_REGISTRY);
    let temporary = stable_root.join(format!(".starting-process-registry-{}", random_hex()?));
    write_new_file(&temporary, &encoded, 0o600)?;
    fs::rename(&temporary, &path).map_err(|error| {
        ManagedError::io(
            "owned_process_mismatch",
            "cannot publish managed starting process registry",
            error,
        )
    })?;
    sync_directory(stable_root)?;
    validate_owned_regular_file(&path, 0o600, "owned_process_mismatch")
}

fn read_process_registry(
    stable_root: &Path,
    record: &OwnershipRecord,
) -> ManagedResult<Vec<ManagedProcessEntry>> {
    let path = stable_root.join(PROCESS_REGISTRY);
    match fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(ManagedError::io(
                "owned_process_mismatch",
                "cannot inspect managed process registry",
                error,
            ));
        }
    }
    validate_owned_regular_file(&path, 0o600, "owned_process_mismatch")
        .map_err(|error| ManagedError::new("owned_process_mismatch", error.to_string()))?;
    let mut file = open_validated_absolute_file(&path)
        .map_err(|error| ManagedError::new("owned_process_mismatch", error.to_string()))?;
    let metadata = file.metadata().map_err(|error| {
        ManagedError::io(
            "owned_process_mismatch",
            "cannot inspect managed process registry",
            error,
        )
    })?;
    if metadata.len() > MAX_PROCESS_REGISTRY_BYTES {
        return Err(ManagedError::new(
            "owned_process_mismatch",
            "managed process registry is oversized",
        ));
    }
    let encoded = read_bounded_opened_utf8(
        &mut file,
        metadata.len(),
        MAX_PROCESS_REGISTRY_BYTES,
        "owned_process_mismatch",
    )?;
    let mut lines = encoded.lines();
    if lines.next() != Some(PROCESS_REGISTRY_MAGIC) {
        return Err(ManagedError::new(
            "owned_process_mismatch",
            "managed process registry schema is invalid",
        ));
    }
    let mut entries = Vec::new();
    for line in lines {
        if line.is_empty() || entries.len() >= MAX_PROCESS_REGISTRY_ENTRIES {
            return Err(ManagedError::new(
                "owned_process_mismatch",
                "managed process registry shape is invalid",
            ));
        }
        let fields: Vec<&str> = line.split('|').collect();
        if fields.len() != 13 || fields[0] != "entry" {
            return Err(ManagedError::new(
                "owned_process_mismatch",
                "managed process registry entry is invalid",
            ));
        }
        let entry = ManagedProcessEntry {
            scope_key: fields[1].to_owned(),
            workspace_id: fields[2].to_owned(),
            session_key: fields[3].to_owned(),
            runtime_root: PathBuf::from(fields[4]),
            coordinator_pid: fields[5].parse().map_err(|_| {
                ManagedError::new("owned_process_mismatch", "coordinator PID is invalid")
            })?,
            coordinator_start: fields[6].to_owned(),
            broker_pid: fields[7].parse().map_err(|_| {
                ManagedError::new("owned_process_mismatch", "broker PID is invalid")
            })?,
            broker_start: fields[8].to_owned(),
            broker_instance_id: fields[9].to_owned(),
            executable_path: PathBuf::from(fields[10]),
            executable_digest: fields[11].to_owned(),
            control_port: fields[12]
                .split_once(':')
                .ok_or_else(|| {
                    ManagedError::new("owned_process_mismatch", "control identity is invalid")
                })?
                .0
                .parse()
                .map_err(|_| {
                    ManagedError::new("owned_process_mismatch", "control port is invalid")
                })?,
            control_nonce: fields[12].split_once(':').unwrap().1.to_owned(),
        };
        validate_process_entry(&entry, record)?;
        if entries
            .iter()
            .any(|existing: &ManagedProcessEntry| existing.scope_key == entry.scope_key)
        {
            return Err(ManagedError::new(
                "owned_process_mismatch",
                "managed process registry contains a duplicate scope",
            ));
        }
        entries.push(entry);
    }
    if !encoded.ends_with('\n') {
        return Err(ManagedError::new(
            "owned_process_mismatch",
            "managed process registry is not newline terminated",
        ));
    }
    Ok(entries)
}

fn write_process_registry(
    stable_root: &Path,
    entries: &[ManagedProcessEntry],
) -> ManagedResult<()> {
    if entries.len() > MAX_PROCESS_REGISTRY_ENTRIES {
        return Err(ManagedError::new(
            "owned_process_mismatch",
            "managed process registry is full",
        ));
    }
    let record = read_record(stable_root)?;
    let mut encoded = format!("{PROCESS_REGISTRY_MAGIC}\n");
    for entry in entries {
        validate_process_entry(entry, &record)?;
        encoded.push_str(&format!(
            "entry|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}:{}\n",
            entry.scope_key,
            entry.workspace_id,
            entry.session_key,
            path_text(&entry.runtime_root)?,
            entry.coordinator_pid,
            entry.coordinator_start,
            entry.broker_pid,
            entry.broker_start,
            entry.broker_instance_id,
            path_text(&entry.executable_path)?,
            entry.executable_digest,
            entry.control_port,
            entry.control_nonce,
        ));
    }
    if encoded.len() as u64 > MAX_PROCESS_REGISTRY_BYTES {
        return Err(ManagedError::new(
            "owned_process_mismatch",
            "managed process registry is oversized",
        ));
    }
    let path = stable_root.join(PROCESS_REGISTRY);
    let temporary = stable_root.join(format!(".process-registry-{}", random_hex()?));
    write_new_file(&temporary, encoded.as_bytes(), 0o600)?;
    fs::rename(&temporary, &path).map_err(|error| {
        ManagedError::io(
            "owned_process_mismatch",
            "cannot publish managed process registry",
            error,
        )
    })?;
    sync_directory(stable_root)?;
    validate_owned_regular_file(&path, 0o600, "owned_process_mismatch")
}

async fn remove_exact_pi_entry(record: &OwnershipRecord) -> ManagedResult<()> {
    let settings = read_pi_settings()?;
    let matching: Vec<&Value> = settings
        .entries
        .iter()
        .filter(|entry| pi_entry_matches_path(entry, &settings.path, &record.pi_package_source))
        .collect();
    if matching.is_empty() {
        return Ok(());
    }
    if matching.len() != 1 || matching[0] != &record.pi_package_entry {
        return Err(ManagedError::new(
            "ownership_conflict",
            "Pi entry no longer matches exact managed ownership",
        ));
    }
    let snapshot = detect_pi()?.ok_or_else(|| {
        ManagedError::new(
            "pi_configuration_failed",
            "Pi is required to remove its exact managed package entry",
        )
    })?;
    run_pi_checked(&snapshot.program, "remove", &record.pi_package_source).await?;
    let after = read_pi_settings()?;
    if after
        .entries
        .iter()
        .any(|entry| pi_entry_matches_path(entry, &after.path, &record.pi_package_source))
    {
        return Err(ManagedError::new(
            "pi_configuration_failed",
            "Pi retained the exact managed package after removal",
        ));
    }
    Ok(())
}

fn validate_removal_inventory(record: &OwnershipRecord, stable_root: &Path) -> ManagedResult<()> {
    validate_record_semantics(record, stable_root, &record.plugin_root)
        .map_err(|error| ManagedError::new("ownership_record_missing", error.to_string()))?;
    for owned in &record.owned_files {
        match fs::symlink_metadata(&owned.path) {
            Ok(_) => {
                validate_owned_file_digest(
                    &owned.path,
                    owned.mode,
                    &owned.sha256,
                    "owned_asset_modified",
                )?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(ManagedError::io(
                    "owned_asset_modified",
                    "cannot inspect removal inventory",
                    error,
                ));
            }
        }
    }
    Ok(())
}

fn remove_recorded_assets(record: &OwnershipRecord, stable_root: &Path) -> ManagedResult<()> {
    remove_recorded_assets_except(record, stable_root, &BTreeSet::new())
}

fn unregister_retained_paths(record: &OwnershipRecord) -> ManagedResult<BTreeSet<PathBuf>> {
    let retained = BTreeSet::from([
        record.stable_binary.clone(),
        record.plugin_root.join("libexec/herdr-a2a-dispatch"),
        record.plugin_root.join("stable-bin-path"),
    ]);
    if !retained
        .iter()
        .all(|path| record.owned_files.iter().any(|owned| &owned.path == path))
    {
        return Err(ManagedError::new(
            "ownership_record_missing",
            "the stable unregister helper inventory is incomplete",
        ));
    }
    Ok(retained)
}

fn remove_recorded_assets_except(
    record: &OwnershipRecord,
    stable_root: &Path,
    retained: &BTreeSet<PathBuf>,
) -> ManagedResult<()> {
    let mut owned = record.owned_files.clone();
    owned.sort_by_key(|file| std::cmp::Reverse(file.path.components().count()));
    for file in owned {
        if !retained.contains(&file.path) {
            unlink_recorded_owned_file(&file)?;
        }
    }
    let mut directories = removal_directories(record, stable_root)?;
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    directories.dedup();
    for directory in directories {
        if retained
            .iter()
            .any(|path| path == &directory || path.starts_with(&directory))
        {
            continue;
        }
        match fs::remove_dir(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) if error.kind() == io::ErrorKind::DirectoryNotEmpty => {
                return Err(ManagedError::new(
                    "ownership_conflict",
                    "an expected-empty owned directory contains an unrecorded entry",
                ));
            }
            Err(error) => {
                return Err(ManagedError::io(
                    "removal_failed",
                    "cannot remove expected-empty owned directory",
                    error,
                ));
            }
        }
    }
    Ok(())
}

fn unlink_recorded_owned_file(expected: &OwnedFile) -> ManagedResult<()> {
    match fs::symlink_metadata(&expected.path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(ManagedError::io(
                "removal_failed",
                "cannot inspect exact owned file",
                error,
            ));
        }
        Ok(_) => {}
    }
    let parent_path = expected
        .path
        .parent()
        .ok_or_else(|| ManagedError::new("ownership_record_missing", "owned file has no parent"))?;
    let name = expected.path.file_name().ok_or_else(|| {
        ManagedError::new(
            "ownership_record_missing",
            "owned file has no final component",
        )
    })?;
    let parent = open_validated_absolute_directory(parent_path, true)?;
    let mut opened = match openat(
        &parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(file) => File::from(file),
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(error) => {
            return Err(ManagedError::new(
                "removal_failed",
                format!("cannot open exact owned file: {error}"),
            ));
        }
    };
    let metadata =
        validate_opened_owned_regular_file(&opened, expected.mode, "owned_asset_modified")?;
    if digest_opened_owned_file(&mut opened, metadata.len(), "owned_asset_modified")?
        != expected.sha256
    {
        return Err(ManagedError::new(
            "owned_asset_modified",
            "a recorded owned file changed during removal",
        ));
    }
    let named = statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|error| {
        ManagedError::new(
            "removal_failed",
            format!("cannot revalidate exact owned file: {error}"),
        )
    })?;
    if u64::try_from(named.st_dev).ok() != Some(metadata.dev())
        || named.st_ino != metadata.ino()
        || named.st_nlink != 1
        || u32::from(named.st_mode & 0o777) != expected.mode
    {
        return Err(ManagedError::new(
            "owned_asset_modified",
            "a recorded owned file changed before unlink",
        ));
    }
    unlinkat(&parent, name, AtFlags::empty()).map_err(|error| {
        ManagedError::new(
            "removal_failed",
            format!("cannot unlink exact owned file: {error}"),
        )
    })
}

fn removal_directories(
    record: &OwnershipRecord,
    stable_root: &Path,
) -> ManagedResult<Vec<PathBuf>> {
    let generation = record.pi_package_source.parent().ok_or_else(|| {
        ManagedError::new(
            "ownership_record_missing",
            "managed generation root is absent",
        )
    })?;
    let mut directories = BTreeSet::new();
    directories.insert(generation.to_path_buf());
    directories.insert(stable_root.join(RESCUE_DIRECTORY));
    directories.insert(record.plugin_root.join("libexec"));
    for owned in &record.owned_files {
        let mut parent = owned.path.parent();
        while let Some(directory) = parent {
            if directory == generation || directory.starts_with(generation) {
                directories.insert(directory.to_path_buf());
                parent = directory.parent();
            } else {
                break;
            }
        }
    }
    Ok(directories.into_iter().collect())
}

fn read_removal_transaction(stable_root: &Path) -> ManagedResult<Option<RemovalTransaction>> {
    let path = stable_root.join(REMOVAL_TRANSACTION_FILE);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(ManagedError::io(
                "recovery_needed",
                "cannot inspect removal transaction",
                error,
            ));
        }
        Ok(_) => {}
    }
    let mut file = open_validated_absolute_file(&path)?;
    let metadata = validate_opened_owned_regular_file(&file, 0o600, "recovery_needed")?;
    let transaction = parse_bounded_opened_json(
        &mut file,
        metadata.len(),
        MAX_TRANSACTION_BYTES,
        "recovery_needed",
    )?;
    Ok(Some(transaction))
}

fn validate_removal_transaction(
    transaction: &RemovalTransaction,
    record: &OwnershipRecord,
    skip_herdr_unregister: bool,
) -> ManagedResult<()> {
    if transaction.schema_version != REMOVAL_TRANSACTION_SCHEMA
        || !record.purge_authority
        || transaction.purge_root != record.plugin_state_root
        || transaction.skip_herdr_unregister != skip_herdr_unregister
        || !transaction
            .purge_snapshot
            .directories
            .iter()
            .any(|directory| directory.path == transaction.purge_root)
        || transaction
            .purge_snapshot
            .directories
            .iter()
            .any(|directory| !directory.path.starts_with(&transaction.purge_root))
        || transaction
            .purge_snapshot
            .files
            .iter()
            .any(|file| !file.path.starts_with(&transaction.purge_root))
    {
        return Err(ManagedError::new(
            "recovery_needed",
            "the durable purge transaction does not match authenticated ownership",
        ));
    }
    Ok(())
}

fn write_removal_transaction(
    stable_root: &Path,
    transaction: &RemovalTransaction,
) -> ManagedResult<()> {
    let path = stable_root.join(REMOVAL_TRANSACTION_FILE);
    let temporary = stable_root.join(format!(".removal-transaction-{}", random_hex()?));
    let bytes = serde_json::to_vec_pretty(transaction)
        .map_err(|error| ManagedError::new("recovery_needed", error.to_string()))?;
    if bytes.len() as u64 > MAX_TRANSACTION_BYTES {
        return Err(ManagedError::new(
            "recovery_needed",
            "removal transaction exceeds its bound",
        ));
    }
    write_new_file(&temporary, &bytes, 0o600)?;
    fs::rename(&temporary, &path).map_err(|error| {
        ManagedError::io(
            "recovery_needed",
            "cannot publish removal transaction",
            error,
        )
    })?;
    sync_directory(stable_root)?;
    validate_owned_regular_file(&path, 0o600, "recovery_needed")
}

fn clear_removal_transaction(stable_root: &Path) -> ManagedResult<()> {
    remove_if_exists(&stable_root.join(REMOVAL_TRANSACTION_FILE))?;
    sync_directory(stable_root)
}

fn validate_purge_root(record: &OwnershipRecord, stable_root: &Path) -> ManagedResult<PathBuf> {
    if !record.purge_authority {
        return Err(ManagedError::new(
            "unsafe_owned_state",
            "purge authority is not established by authenticated ownership",
        ));
    }
    let value = env::var_os("HERDR_PLUGIN_STATE_DIR").ok_or_else(|| {
        ManagedError::new(
            "unsafe_owned_state",
            "HERDR_PLUGIN_STATE_DIR is required for purge",
        )
    })?;
    let root = require_absolute_normal(Path::new(&value), "HERDR_PLUGIN_STATE_DIR")
        .map_err(|error| ManagedError::new("unsafe_owned_state", error.to_string()))?;
    if root != record.plugin_state_root {
        return Err(ManagedError::new(
            "unsafe_owned_state",
            "purge root does not match authenticated ownership",
        ));
    }
    let home = required_home()?;
    if root == Path::new("/")
        || root == home
        || root == stable_root
        || root.starts_with(stable_root)
    {
        return Err(ManagedError::new(
            "unsafe_owned_state",
            "purge root overlaps a forbidden broad or installation path",
        ));
    }
    validate_private_directory(&root, 0o700)
        .map_err(|error| ManagedError::new("unsafe_owned_state", error.to_string()))?;
    Ok(root)
}

fn print_missing_status(json: bool) -> ManagedResult<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "schema_version": OWNERSHIP_SCHEMA,
                "state": InstallState::Failed,
                "last_error": "not_installed"
            }))
            .map_err(|error| ManagedError::new("ownership_record_invalid", error.to_string()))?
        );
    } else {
        println!("failed: not installed");
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "the ownership record builder keeps each authenticated input explicit"
)]
fn build_record(
    stable_root: &Path,
    plugin_root: &Path,
    generation: &PreparedGeneration,
    prior: Option<&OwnershipRecord>,
    broker_digest: String,
    pi_package_digest: String,
    state: InstallState,
    install_kind: String,
) -> ManagedResult<OwnershipRecord> {
    let helper = plugin_root.join("libexec/herdr-a2a-dispatch");
    let pointer = plugin_root.join("stable-bin-path");
    let mut owned_files = vec![owned_file(&generation.binary, 0o700)?];
    for file in tree_files(&generation.package)? {
        owned_files.push(owned_file(&file, 0o600)?);
    }
    owned_files.push(owned_file(&helper, 0o700)?);
    owned_files.push(owned_file(&pointer, 0o600)?);
    owned_files.sort_by(|left, right| left.path.cmp(&right.path));
    let (purge_authority, plugin_state_root) = match prior {
        None => (true, required_plugin_state_root(&install_kind)?),
        Some(record) if record.purge_authority => {
            validate_private_directory(&record.plugin_state_root, 0o700)?;
            (true, record.plugin_state_root.clone())
        }
        Some(_) => (false, PathBuf::new()),
    };
    Ok(OwnershipRecord {
        schema_version: OWNERSHIP_SCHEMA,
        state,
        plugin_version: read_plugin_version(plugin_root)?,
        broker_digest,
        pi_package_digest,
        pi_package_source: generation.package.clone(),
        pi_config_path: pi_settings_path()?,
        pi_package_entry: managed_pi_entry(&pi_settings_path()?, &generation.package)?,
        purge_authority,
        plugin_state_root,
        rescue_path: stable_root.join("rescue/uninstall.sh"),
        rescue_marker_digest: String::new(),
        install_kind,
        plugin_root: plugin_root.to_path_buf(),
        stable_binary: generation.binary.clone(),
        ownership_path: stable_root.join(OWNERSHIP_FILE),
        owned_files,
        last_error: None,
    })
}

struct PreparedRescueAssets {
    rescue: PathBuf,
    notice: Vec<u8>,
    marker: PathBuf,
    marker_bytes: Vec<u8>,
}

type PriorRescueSnapshot = (Option<Vec<u8>>, Option<Vec<u8>>);

fn prepare_rescue_assets(
    stable_root: &Path,
    plugin_root: &Path,
    record: &mut OwnershipRecord,
) -> ManagedResult<PreparedRescueAssets> {
    let rescue_directory = stable_root.join(RESCUE_DIRECTORY);
    let source = plugin_root.join("scripts/uninstall.sh");
    validate_external_file(&source, false)?;
    let rescue = rescue_directory.join("uninstall.sh");
    let notice = read_rescue_notice(&source)?;

    record.rescue_path = rescue.clone();
    record
        .owned_files
        .retain(|owned| owned.path != rescue && owned.path != rescue_directory.join(RESCUE_MARKER));
    record.owned_files.push(OwnedFile {
        path: rescue.clone(),
        sha256: sha256_bytes(&notice),
        mode: 0o600,
    });
    record
        .owned_files
        .sort_by(|left, right| left.path.cmp(&right.path));

    let marker_path = rescue_directory.join(RESCUE_MARKER);
    let marker_bytes = rescue_marker(record, stable_root)?.into_bytes();
    record.rescue_marker_digest = sha256_bytes(&marker_bytes);
    record.owned_files.push(OwnedFile {
        path: marker_path.clone(),
        sha256: record.rescue_marker_digest.clone(),
        mode: 0o600,
    });
    record
        .owned_files
        .sort_by(|left, right| left.path.cmp(&right.path));
    Ok(PreparedRescueAssets {
        rescue,
        notice,
        marker: marker_path,
        marker_bytes,
    })
}

fn capture_prior_rescue_assets(
    stable_root: &Path,
    prior: Option<&OwnershipRecord>,
) -> ManagedResult<PriorRescueSnapshot> {
    let Some(prior) = prior.filter(|record| record.state != InstallState::Removed) else {
        return Ok((None, None));
    };
    let rescue = stable_root.join(RESCUE_DIRECTORY).join("uninstall.sh");
    let marker = stable_root.join(RESCUE_DIRECTORY).join(RESCUE_MARKER);
    let prior_rescue = record_owned_file(prior, &rescue)
        .ok_or_else(|| ManagedError::new("recovery_needed", "prior record has no rescue notice"))?;
    let prior_marker = record_owned_file(prior, &marker)
        .ok_or_else(|| ManagedError::new("recovery_needed", "prior record has no rescue marker"))?;
    let notice = read_exact_owned_rescue_bytes(prior_rescue)?;
    let marker_bytes = read_exact_owned_rescue_bytes(prior_marker)?;
    if !prior_rescue_marker_is_authenticated(prior, prior_marker, &marker_bytes) {
        return Err(ManagedError::new(
            "recovery_needed",
            "prior rescue marker ownership is inconsistent",
        ));
    }
    Ok((Some(notice), Some(marker_bytes)))
}

fn prior_rescue_marker_is_authenticated(
    prior: &OwnershipRecord,
    marker: &OwnedFile,
    marker_bytes: &[u8],
) -> bool {
    let marker_path = prior
        .ownership_path
        .parent()
        .map(|stable_root| stable_root.join(RESCUE_DIRECTORY).join(RESCUE_MARKER));
    if marker_path.as_deref() != Some(marker.path.as_path())
        || marker.mode != 0o600
        || !valid_digest(&marker.sha256)
        || sha256_bytes(marker_bytes) != marker.sha256
    {
        return false;
    }
    if prior.schema_version == 2 && !prior.purge_authority {
        prior.rescue_marker_digest.is_empty()
    } else {
        valid_digest(&prior.rescue_marker_digest) && prior.rescue_marker_digest == marker.sha256
    }
}

fn read_exact_owned_rescue_bytes(owned: &OwnedFile) -> ManagedResult<Vec<u8>> {
    let mut file = open_validated_absolute_file(&owned.path)?;
    let metadata = validate_opened_owned_regular_file(&file, owned.mode, "recovery_needed")?;
    if metadata.len() > MAX_EVENT_BYTES as u64 {
        return Err(ManagedError::new(
            "recovery_needed",
            "owned rescue asset exceeds its size limit",
        ));
    }
    let bytes = read_bounded_opened_bytes(
        &mut file,
        metadata.len(),
        MAX_EVENT_BYTES as u64,
        "recovery_needed",
    )?;
    if sha256_bytes(&bytes) != owned.sha256 {
        return Err(ManagedError::new(
            "recovery_needed",
            "owned rescue asset digest changed while it was read",
        ));
    }
    Ok(bytes)
}

fn publish_rescue_assets(stable_root: &Path, assets: &PreparedRescueAssets) -> ManagedResult<()> {
    let rescue_directory = stable_root.join(RESCUE_DIRECTORY);
    if !rescue_directory.exists() {
        fs::create_dir(&rescue_directory).map_err(|error| {
            ManagedError::io("generation_failed", "cannot create rescue directory", error)
        })?;
        fs::set_permissions(&rescue_directory, fs::Permissions::from_mode(0o700)).map_err(
            |error| {
                ManagedError::io(
                    "generation_failed",
                    "cannot protect rescue directory",
                    error,
                )
            },
        )?;
        sync_directory(stable_root)?;
    }
    validate_private_directory(&rescue_directory, 0o700)?;
    replace_owned_bytes(&assets.rescue, &assets.notice, 0o600)?;
    #[cfg(debug_assertions)]
    if env::var_os("HERDR_A2A_TEST_ABORT_AFTER_RESCUE_NOTICE").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        std::process::abort();
    }
    replace_owned_bytes(&assets.marker, &assets.marker_bytes, 0o600)?;
    Ok(())
}

fn read_rescue_notice(source: &Path) -> ManagedResult<Vec<u8>> {
    let mut file = open_validated_absolute_file(source)?;
    let metadata = file.metadata().map_err(|error| {
        ManagedError::io(
            "generation_failed",
            "cannot inspect rescue bootstrap",
            error,
        )
    })?;
    if metadata.len() > MAX_EVENT_BYTES as u64 {
        return Err(ManagedError::new(
            "generation_failed",
            "rescue bootstrap template exceeds its size limit",
        ));
    }
    let notice = read_bounded_opened_bytes(
        &mut file,
        metadata.len(),
        MAX_EVENT_BYTES as u64,
        "generation_failed",
    )?;
    Ok(notice)
}

fn migrate_rescue_layout(
    stable_root: &Path,
    plugin_root: &Path,
    prior: &OwnershipRecord,
) -> ManagedResult<()> {
    if rescue_layout(prior, stable_root)? == RescueLayout::SourceNotice {
        return Ok(());
    }
    if stable_root.join(RESCUE_MIGRATION_FILE).exists() {
        return Err(ManagedError::new(
            "recovery_needed",
            "a rescue migration requires recovery before another migration",
        ));
    }
    reject_unowned_rescue_migration_artifacts(stable_root)?;
    let rescue = stable_root.join(RESCUE_DIRECTORY);
    let prior_snapshot = snapshot_stage(&rescue)?;
    validate_rescue_snapshot_for_record(prior, &rescue, &prior_snapshot)?;

    let token = random_hex()?;
    let stage = stable_root.join(format!(".rescue-migration-stage-{token}"));
    let backup = stable_root.join(format!(".rescue-migration-backup-{token}"));
    let source = plugin_root.join("scripts/uninstall.sh");
    validate_external_file(&source, false)?;
    let notice = read_rescue_notice(&source)?;

    let mut new_record = prior.clone();
    new_record
        .owned_files
        .retain(|owned| !owned.path.starts_with(&rescue));
    new_record.owned_files.push(OwnedFile {
        path: new_record.rescue_path.clone(),
        sha256: sha256_bytes(&notice),
        mode: 0o600,
    });
    new_record
        .owned_files
        .sort_by(|left, right| left.path.cmp(&right.path));
    let marker = rescue_marker(&new_record, stable_root)?;
    let marker_digest = sha256_bytes(marker.as_bytes());
    if new_record.schema_version == OWNERSHIP_SCHEMA {
        new_record.rescue_marker_digest = marker_digest.clone();
    }
    new_record.owned_files.push(OwnedFile {
        path: rescue.join(RESCUE_MARKER),
        sha256: marker_digest,
        mode: 0o600,
    });
    new_record
        .owned_files
        .sort_by(|left, right| left.path.cmp(&right.path));
    validate_record_semantics(&new_record, stable_root, plugin_root)?;

    let planned_snapshot = planned_rescue_stage_snapshot(&new_record, &rescue, &stage)?;
    let mut migration = RescueMigration {
        schema_version: RESCUE_MIGRATION_SCHEMA,
        phase: RescueMigrationPhase::Intent,
        rescue: rescue.clone(),
        stage: stage.clone(),
        backup: backup.clone(),
        prior_record: prior.clone(),
        new_record: new_record.clone(),
        prior_snapshot: prior_snapshot.clone(),
        new_snapshot: planned_snapshot,
    };
    write_rescue_migration(stable_root, &migration)?;
    test_abort_rescue_migration("intent-published");

    fs::create_dir(&stage).map_err(|error| {
        ManagedError::io(
            "recovery_needed",
            "cannot create rescue migration stage",
            error,
        )
    })?;
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o700)).map_err(|error| {
        ManagedError::io(
            "recovery_needed",
            "cannot protect rescue migration stage",
            error,
        )
    })?;
    sync_directory(stable_root)?;
    test_abort_rescue_migration("stage-directory-published");

    let staged_notice = stage.join("uninstall.sh");
    write_new_file(&staged_notice, &notice, 0o600)?;
    sync_directory(&stage)?;
    test_abort_rescue_migration("stage-notice-published");
    let staged_marker = stage.join(RESCUE_MARKER);
    write_new_file(&staged_marker, marker.as_bytes(), 0o600)?;
    sync_directory(&stage)?;
    test_abort_rescue_migration("stage-marker-published");

    let new_snapshot = snapshot_stage(&stage)?;
    let published_snapshot = relocate_stage_snapshot(&new_snapshot, &stage, &rescue)?;
    validate_rescue_snapshot_for_record(&new_record, &rescue, &published_snapshot)?;
    migration.new_snapshot = new_snapshot.clone();
    migration.phase = RescueMigrationPhase::Prepared;
    write_rescue_migration(stable_root, &migration)?;
    test_abort_rescue_migration("stage-prepared");

    migration.phase = RescueMigrationPhase::PriorBackingUp;
    write_rescue_migration(stable_root, &migration)?;
    test_abort_rescue_migration("backup-intent-published");
    validate_stage_snapshot_live(&rescue, &prior_snapshot)?;
    fs::rename(&rescue, &backup).map_err(|error| {
        ManagedError::io(
            "recovery_needed",
            "cannot back up authenticated rescue directory",
            error,
        )
    })?;
    sync_directory(stable_root)?;
    test_abort_rescue_migration("backup-renamed");
    #[cfg(debug_assertions)]
    if env::var_os("HERDR_A2A_TEST_ABORT_AFTER_RESCUE_BACKUP_RENAME").as_deref()
        == Some(OsStr::new("1"))
    {
        std::process::abort();
    }
    migration.phase = RescueMigrationPhase::PriorBackedUp;
    write_rescue_migration(stable_root, &migration)?;
    test_abort_rescue_migration("prior-backed-up");

    migration.phase = RescueMigrationPhase::NoticePublishing;
    write_rescue_migration(stable_root, &migration)?;
    test_abort_rescue_migration("notice-intent-published");
    validate_stage_snapshot_live(&stage, &new_snapshot)?;
    fs::rename(&stage, &rescue).map_err(|error| {
        ManagedError::io(
            "recovery_needed",
            "cannot publish authenticated rescue notice",
            error,
        )
    })?;
    sync_directory(stable_root)?;
    test_abort_rescue_migration("notice-renamed");
    migration.phase = RescueMigrationPhase::NoticePublished;
    write_rescue_migration(stable_root, &migration)?;
    test_abort_rescue_migration("notice-published");

    migration.phase = RescueMigrationPhase::RecordCommitting;
    write_rescue_migration(stable_root, &migration)?;
    test_abort_rescue_migration("record-intent-published");
    validate_stage_snapshot_live(&rescue, &published_snapshot)?;
    write_record(stable_root, &new_record)?;
    test_abort_rescue_migration("record-written");
    migration.phase = RescueMigrationPhase::RecordCommitted;
    write_rescue_migration(stable_root, &migration)?;
    test_abort_rescue_migration("record-committed");

    let backup_snapshot = relocate_stage_snapshot(&prior_snapshot, &rescue, &backup)?;
    migration.phase = RescueMigrationPhase::BackupRetiring;
    write_rescue_migration(stable_root, &migration)?;
    test_abort_rescue_migration("backup-retire-intent-published");
    remove_remaining_exact_stage(&backup_snapshot, "backup")?;
    test_abort_rescue_migration("backup-retired");
    clear_rescue_migration(stable_root)?;
    Ok(())
}

fn reject_unowned_rescue_migration_artifacts(stable_root: &Path) -> ManagedResult<()> {
    let entries = fs::read_dir(stable_root).map_err(|error| {
        ManagedError::io(
            "recovery_needed",
            "cannot inspect the managed root for rescue migration artifacts",
            error,
        )
    })?;
    for (index, entry) in entries.enumerate() {
        if index >= MAX_PURGE_ENTRIES {
            return Err(ManagedError::new(
                "recovery_needed",
                "the managed root exceeds its rescue migration inspection limit",
            ));
        }
        let entry = entry.map_err(|error| {
            ManagedError::io(
                "recovery_needed",
                "cannot inspect a managed root entry",
                error,
            )
        })?;
        if is_rescue_migration_artifact_name(&entry.file_name()) {
            return Err(ManagedError::new(
                "recovery_needed",
                "an unjournaled rescue migration artifact requires manual recovery",
            ));
        }
    }
    Ok(())
}

fn is_rescue_migration_artifact_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    [
        ".rescue-migration-stage-",
        ".rescue-migration-backup-",
        ".rescue-migration-journal-",
    ]
    .iter()
    .any(|prefix| {
        name.strip_prefix(prefix).is_some_and(|token| {
            token.len() == 32
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
    })
}

fn planned_rescue_stage_snapshot(
    record: &OwnershipRecord,
    rescue: &Path,
    stage: &Path,
) -> ManagedResult<StageSnapshot> {
    let files = record
        .owned_files
        .iter()
        .filter(|owned| owned.path.starts_with(rescue))
        .map(|owned| {
            let relative = owned.path.strip_prefix(rescue).map_err(|_| {
                ManagedError::new(
                    "recovery_needed",
                    "planned rescue file escaped its migration stage",
                )
            })?;
            Ok(OwnedStageFile {
                path: stage.join(relative),
                device: 0,
                inode: 0,
                mode: owned.mode,
                sha256: owned.sha256.clone(),
            })
        })
        .collect::<ManagedResult<Vec<_>>>()?;
    let mut snapshot = StageSnapshot {
        directories: vec![OwnedDirectory {
            path: stage.to_path_buf(),
            device: 0,
            inode: 0,
            mode: 0o700,
        }],
        files,
    };
    snapshot
        .files
        .sort_by(|left, right| left.path.cmp(&right.path));
    validate_stage_snapshot_semantics(stage, &snapshot)?;
    Ok(snapshot)
}

#[cfg(debug_assertions)]
fn test_abort_rescue_migration(boundary: &str) {
    if env::var_os("HERDR_A2A_TEST_ABORT_RESCUE_MIGRATION").as_deref() == Some(OsStr::new(boundary))
    {
        std::process::abort();
    }
}

#[cfg(not(debug_assertions))]
fn test_abort_rescue_migration(_boundary: &str) {}

fn test_abort_rescue_cleanup(cleanup: &str, step: usize) {
    test_abort_rescue_migration(&format!("{cleanup}-cleanup-{step}"));
}

fn validate_rescue_snapshot_for_record(
    record: &OwnershipRecord,
    rescue: &Path,
    snapshot: &StageSnapshot,
) -> ManagedResult<()> {
    validate_stage_snapshot_semantics(rescue, snapshot)?;
    if snapshot.directories.len() != 1 || snapshot.directories[0].path != rescue {
        return Err(ManagedError::new(
            "recovery_needed",
            "rescue snapshot directory inventory is not exact",
        ));
    }
    let expected: std::collections::BTreeMap<&Path, (u32, &str)> = record
        .owned_files
        .iter()
        .filter(|owned| owned.path.starts_with(rescue))
        .map(|owned| (owned.path.as_path(), (owned.mode, owned.sha256.as_str())))
        .collect();
    if snapshot.files.len() != expected.len()
        || snapshot.files.iter().any(|file| {
            expected.get(file.path.as_path()) != Some(&(file.mode, file.sha256.as_str()))
        })
    {
        return Err(ManagedError::new(
            "recovery_needed",
            "rescue snapshot file inventory is not exact",
        ));
    }
    Ok(())
}

fn write_rescue_migration(stable_root: &Path, migration: &RescueMigration) -> ManagedResult<()> {
    let bytes = serde_json::to_vec_pretty(migration)
        .map_err(|error| ManagedError::new("recovery_needed", error.to_string()))?;
    if bytes.len() as u64 > MAX_RESCUE_MIGRATION_BYTES {
        return Err(ManagedError::new(
            "recovery_needed",
            "rescue migration journal exceeds its size limit",
        ));
    }
    let path = stable_root.join(RESCUE_MIGRATION_FILE);
    let temporary = rescue_migration_temporary_path(stable_root, &migration.prior_record)?;
    write_new_file(&temporary, &bytes, 0o600)?;
    sync_directory(stable_root)?;
    test_abort_rescue_migration(&format!(
        "journal-temp-{}",
        rescue_migration_phase_name(migration.phase)
    ));
    fs::rename(&temporary, &path).map_err(|error| {
        ManagedError::io(
            "recovery_needed",
            "cannot publish rescue migration journal",
            error,
        )
    })?;
    sync_directory(stable_root)?;
    validate_owned_regular_file(&path, 0o600, "recovery_needed")
}

fn rescue_migration_temporary_path(
    stable_root: &Path,
    record: &OwnershipRecord,
) -> ManagedResult<PathBuf> {
    let rescue = stable_root.join(RESCUE_DIRECTORY);
    let normalized = normalized_non_rescue_record(record, &rescue);
    let bytes = serde_json::to_vec(&normalized)
        .map_err(|error| ManagedError::new("recovery_needed", error.to_string()))?;
    let digest = Sha256::digest(bytes);
    let token: String = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(stable_root.join(format!(".rescue-migration-journal-{token}")))
}

fn rescue_migration_phase_name(phase: RescueMigrationPhase) -> &'static str {
    use RescueMigrationPhase::*;
    match phase {
        Intent => "intent",
        Prepared => "prepared",
        PriorBackingUp => "prior-backing-up",
        PriorBackedUp => "prior-backed-up",
        NoticePublishing => "notice-publishing",
        NoticePublished => "notice-published",
        RecordCommitting => "record-committing",
        RecordCommitted => "record-committed",
        BackupRetiring => "backup-retiring",
        NoticeCleaning => "notice-cleaning",
        PriorRestoring => "prior-restoring",
        StageCleaning => "stage-cleaning",
    }
}

fn clear_rescue_migration(stable_root: &Path) -> ManagedResult<()> {
    remove_if_exists(&stable_root.join(RESCUE_MIGRATION_FILE))?;
    sync_directory(stable_root)
}

fn read_rescue_migration(stable_root: &Path) -> ManagedResult<Option<RescueMigration>> {
    let path = stable_root.join(RESCUE_MIGRATION_FILE);
    read_rescue_migration_path(stable_root, &path)
        .map(|value| value.map(|(migration, _)| migration))
}

fn read_rescue_migration_path(
    stable_root: &Path,
    path: &Path,
) -> ManagedResult<Option<(RescueMigration, OwnedFile)>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(ManagedError::io(
                "recovery_needed",
                "cannot inspect rescue migration journal",
                error,
            ));
        }
        Ok(_) => {}
    }
    let mut file = open_validated_absolute_file(path)?;
    let metadata = validate_opened_owned_regular_file(&file, 0o600, "recovery_needed")?;
    let bytes = read_bounded_opened_bytes(
        &mut file,
        metadata.len(),
        MAX_RESCUE_MIGRATION_BYTES,
        "recovery_needed",
    )?;
    let migration: RescueMigration = serde_json::from_slice(&bytes)
        .map_err(|error| ManagedError::new("recovery_needed", error.to_string()))?;
    validate_rescue_migration(stable_root, &migration)?;
    Ok(Some((
        migration,
        OwnedFile {
            path: path.to_path_buf(),
            sha256: sha256_bytes(&bytes),
            mode: 0o600,
        },
    )))
}

fn validate_rescue_migration(stable_root: &Path, migration: &RescueMigration) -> ManagedResult<()> {
    let rescue = stable_root.join(RESCUE_DIRECTORY);
    let stage_name = migration
        .stage
        .file_name()
        .and_then(OsStr::to_str)
        .and_then(|name| name.strip_prefix(".rescue-migration-stage-"))
        .ok_or_else(|| {
            ManagedError::new("recovery_needed", "rescue migration stage name is invalid")
        })?;
    if !rescue_migration_schema_phase_is_known(migration.schema_version, migration.phase)
        || migration.rescue != rescue
        || migration.stage.parent() != Some(stable_root)
        || migration.backup.parent() != Some(stable_root)
        || migration.backup.file_name()
            != Some(OsStr::new(&format!(
                ".rescue-migration-backup-{stage_name}"
            )))
        || stage_name.len() != 32
        || !stage_name
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ManagedError::new(
            "recovery_needed",
            "rescue migration journal relationships are invalid",
        ));
    }
    validate_record_semantics(
        &migration.prior_record,
        stable_root,
        &migration.prior_record.plugin_root,
    )?;
    validate_record_semantics(
        &migration.new_record,
        stable_root,
        &migration.new_record.plugin_root,
    )?;
    if rescue_layout(&migration.prior_record, stable_root)? == RescueLayout::SourceNotice
        || rescue_layout(&migration.new_record, stable_root)? != RescueLayout::SourceNotice
        || migration.prior_record.plugin_root != migration.new_record.plugin_root
        || normalized_non_rescue_record(&migration.prior_record, &rescue)
            != normalized_non_rescue_record(&migration.new_record, &rescue)
    {
        return Err(ManagedError::new(
            "recovery_needed",
            "rescue migration ownership transition is not exact",
        ));
    }
    validate_rescue_snapshot_for_record(
        &migration.prior_record,
        &rescue,
        &migration.prior_snapshot,
    )?;
    validate_stage_snapshot_semantics(&migration.stage, &migration.new_snapshot)?;
    let published = relocate_stage_snapshot(&migration.new_snapshot, &migration.stage, &rescue)?;
    validate_rescue_snapshot_for_record(&migration.new_record, &rescue, &published)?;
    let planned = rescue_stage_snapshot_is_planned(&migration.new_snapshot);
    if (migration.phase == RescueMigrationPhase::Intent && !planned)
        || (migration.phase != RescueMigrationPhase::Intent
            && migration.phase != RescueMigrationPhase::StageCleaning
            && planned)
    {
        return Err(ManagedError::new(
            "recovery_needed",
            "rescue migration stage identity does not match its phase",
        ));
    }
    Ok(())
}

fn rescue_migration_schema_phase_is_known(schema: u32, phase: RescueMigrationPhase) -> bool {
    schema == RESCUE_MIGRATION_SCHEMA
        || (schema == LEGACY_RESCUE_MIGRATION_SCHEMA
            && matches!(
                phase,
                RescueMigrationPhase::Prepared
                    | RescueMigrationPhase::PriorBackedUp
                    | RescueMigrationPhase::NoticePublished
                    | RescueMigrationPhase::RecordCommitted
            ))
}

fn normalized_non_rescue_record(record: &OwnershipRecord, rescue: &Path) -> OwnershipRecord {
    let mut normalized = record.clone();
    normalized
        .owned_files
        .retain(|owned| !owned.path.starts_with(rescue));
    normalized.rescue_marker_digest.clear();
    normalized
}

fn rescue_stage_snapshot_is_planned(snapshot: &StageSnapshot) -> bool {
    snapshot
        .directories
        .iter()
        .all(|directory| directory.device == 0 && directory.inode == 0)
        && snapshot
            .files
            .iter()
            .all(|file| file.device == 0 && file.inode == 0)
}

fn stage_snapshot_if_present(path: &Path) -> ManagedResult<Option<StageSnapshot>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(ManagedError::io(
            "recovery_needed",
            "cannot inspect rescue migration state",
            error,
        )),
        Ok(_) => snapshot_stage(path).map(Some),
    }
}

fn classify_rescue_tree(
    current: Option<&StageSnapshot>,
    prior: Option<&StageSnapshot>,
    new: Option<&StageSnapshot>,
    planned: Option<&StageSnapshot>,
) -> RescueTreeState {
    let Some(current) = current else {
        return RescueTreeState::Absent;
    };
    if prior == Some(current) {
        return RescueTreeState::Prior;
    }
    if new == Some(current) {
        return RescueTreeState::New;
    }
    if prior.is_some_and(|expected| stage_is_exact_subset(expected, current)) {
        return RescueTreeState::PriorSubset;
    }
    if new.is_some_and(|expected| stage_is_exact_subset(expected, current)) {
        return RescueTreeState::NewSubset;
    }
    if planned.is_some_and(|expected| planned_stage_is_exact_subset(expected, current)) {
        return RescueTreeState::PlannedSubset;
    }
    RescueTreeState::Other
}

fn observe_rescue_migration_state(
    migration: &RescueMigration,
    current_record: &OwnershipRecord,
) -> ManagedResult<RescueMigrationLiveState> {
    let prior_backup = relocate_stage_snapshot(
        &migration.prior_snapshot,
        &migration.rescue,
        &migration.backup,
    )?;
    let new_live =
        relocate_stage_snapshot(&migration.new_snapshot, &migration.stage, &migration.rescue)?;
    let planned = rescue_stage_snapshot_is_planned(&migration.new_snapshot);
    let rescue = stage_snapshot_if_present(&migration.rescue)?;
    let stage = stage_snapshot_if_present(&migration.stage)?;
    let backup = stage_snapshot_if_present(&migration.backup)?;
    Ok(RescueMigrationLiveState {
        record: if current_record == &migration.prior_record {
            RescueRecordState::Prior
        } else if current_record == &migration.new_record {
            RescueRecordState::New
        } else {
            RescueRecordState::Other
        },
        rescue: classify_rescue_tree(
            rescue.as_ref(),
            Some(&migration.prior_snapshot),
            (!planned).then_some(&new_live),
            None,
        ),
        stage: classify_rescue_tree(
            stage.as_ref(),
            None,
            (!planned).then_some(&migration.new_snapshot),
            planned.then_some(&migration.new_snapshot),
        ),
        backup: classify_rescue_tree(backup.as_ref(), Some(&prior_backup), None, None),
    })
}

fn rescue_recovery_route(
    phase: RescueMigrationPhase,
    live: RescueMigrationLiveState,
) -> ManagedResult<RescueRecoveryRoute> {
    use RescueMigrationPhase::*;
    use RescueRecordState::{New as NewRecord, Prior as PriorRecord};
    use RescueTreeState::*;
    let route = match (phase, live.record, live.rescue, live.stage, live.backup) {
        (Intent, PriorRecord, Prior, Absent | PlannedSubset, Absent) => RescueRecoveryRoute::Intent,
        (Prepared | PriorBackingUp, PriorRecord, Prior, New, Absent)
        | (
            Prepared | PriorBackingUp | PriorBackedUp | NoticePublishing,
            PriorRecord,
            Absent,
            New,
            Prior,
        ) => RescueRecoveryRoute::BeforeNotice,
        (
            PriorBackedUp | NoticePublishing | NoticePublished | RecordCommitting,
            PriorRecord,
            New,
            Absent,
            Prior,
        ) => RescueRecoveryRoute::NoticeRollback,
        (
            NoticePublished | RecordCommitting | RecordCommitted | BackupRetiring,
            NewRecord,
            New,
            Absent,
            Prior | PriorSubset | Absent,
        ) => RescueRecoveryRoute::Committed,
        (NoticeCleaning, PriorRecord, New | NewSubset | Absent, Absent, Prior) => {
            RescueRecoveryRoute::NoticeCleanup
        }
        (PriorRestoring, PriorRecord, Absent, New | NewSubset | Absent, Prior)
        | (PriorRestoring, PriorRecord, Prior, New | NewSubset | Absent, Absent) => {
            RescueRecoveryRoute::PriorRestore
        }
        (StageCleaning, PriorRecord, Prior, New | NewSubset | PlannedSubset | Absent, Absent) => {
            RescueRecoveryRoute::StageCleanup
        }
        _ => return Err(inexact_rescue_migration_state()),
    };
    Ok(route)
}

fn rescue_migration_temp_transition_is_allowed(
    published: RescueMigrationPhase,
    temporary: RescueMigrationPhase,
) -> bool {
    use RescueMigrationPhase::*;
    matches!(
        (published, temporary),
        (Intent, Prepared | StageCleaning)
            | (Prepared, PriorBackingUp | PriorRestoring)
            | (PriorBackingUp, PriorBackedUp | PriorRestoring)
            | (
                PriorBackedUp,
                NoticePublishing | NoticeCleaning | PriorRestoring
            )
            | (
                NoticePublishing,
                NoticePublished | NoticeCleaning | PriorRestoring
            )
            | (
                NoticePublished,
                RecordCommitting | NoticeCleaning | BackupRetiring
            )
            | (
                RecordCommitting,
                RecordCommitted | NoticeCleaning | BackupRetiring
            )
            | (RecordCommitted, BackupRetiring)
            | (BackupRetiring, BackupRetiring)
            | (NoticeCleaning, PriorRestoring)
            | (PriorRestoring, StageCleaning)
    )
}

fn rescue_snapshot_inventory_matches(left: &StageSnapshot, right: &StageSnapshot) -> bool {
    left.directories.len() == right.directories.len()
        && left.files.len() == right.files.len()
        && left.directories.iter().all(|directory| {
            right.directories.iter().any(|candidate| {
                candidate.path == directory.path && candidate.mode == directory.mode
            })
        })
        && left.files.iter().all(|file| {
            right.files.iter().any(|candidate| {
                candidate.path == file.path
                    && candidate.mode == file.mode
                    && candidate.sha256 == file.sha256
            })
        })
}

fn rescue_migration_temp_matches_published(
    published: &RescueMigration,
    temporary: &RescueMigration,
) -> bool {
    published.schema_version == temporary.schema_version
        && published.rescue == temporary.rescue
        && published.stage == temporary.stage
        && published.backup == temporary.backup
        && published.prior_record == temporary.prior_record
        && published.new_record == temporary.new_record
        && published.prior_snapshot == temporary.prior_snapshot
        && rescue_snapshot_inventory_matches(&published.new_snapshot, &temporary.new_snapshot)
        && rescue_migration_temp_transition_is_allowed(published.phase, temporary.phase)
}

fn remove_authenticated_rescue_migration_temp(
    stable_root: &Path,
    expected: &OwnedFile,
) -> ManagedResult<()> {
    unlink_recorded_owned_file(expected).map_err(|_| inexact_rescue_migration_state())?;
    sync_directory(stable_root)
}

fn reconcile_rescue_migration_temp(
    stable_root: &Path,
    published: Option<&RescueMigration>,
    current: Option<&OwnershipRecord>,
) -> ManagedResult<()> {
    let Some(authority) = published
        .map(|migration| &migration.prior_record)
        .or(current)
    else {
        return Ok(());
    };
    let path = rescue_migration_temporary_path(stable_root, authority)?;
    let Some((temporary, owned)) = read_rescue_migration_path(stable_root, &path)? else {
        return Ok(());
    };
    let current = current.ok_or_else(inexact_rescue_migration_state)?;
    let authenticated = if let Some(published) = published {
        rescue_migration_temp_matches_published(published, &temporary)
            && rescue_recovery_route(
                temporary.phase,
                observe_rescue_migration_state(&temporary, current)?,
            )
            .is_ok()
    } else {
        temporary.phase == RescueMigrationPhase::Intent
            && &temporary.prior_record == current
            && matches!(
                rescue_recovery_route(
                    temporary.phase,
                    observe_rescue_migration_state(&temporary, current)?,
                ),
                Ok(RescueRecoveryRoute::Intent)
            )
    };
    if !authenticated {
        return Err(inexact_rescue_migration_state());
    }
    remove_authenticated_rescue_migration_temp(stable_root, &owned)
}

fn reconcile_rescue_migration(stable_root: &Path) -> ManagedResult<()> {
    let published = read_rescue_migration(stable_root)?;
    let current = read_record_optional(stable_root)?;
    reconcile_rescue_migration_temp(stable_root, published.as_ref(), current.as_ref())?;
    let Some(mut migration) = published else {
        return reject_unowned_rescue_migration_artifacts(stable_root);
    };
    let current = current.ok_or_else(inexact_rescue_migration_state)?;
    let route = rescue_recovery_route(
        migration.phase,
        observe_rescue_migration_state(&migration, &current)?,
    )?;
    match route {
        RescueRecoveryRoute::Intent => {
            reconcile_rescue_intent(stable_root, &mut migration, &current)
        }
        RescueRecoveryRoute::BeforeNotice => {
            reconcile_rescue_before_notice(stable_root, &mut migration, &current)
        }
        RescueRecoveryRoute::NoticeRollback => {
            reconcile_rescue_notice_rollback(stable_root, &mut migration, &current)
        }
        RescueRecoveryRoute::Committed => {
            reconcile_committed_rescue_migration(stable_root, &mut migration, &current)
        }
        RescueRecoveryRoute::NoticeCleanup => {
            reconcile_rescue_notice_cleanup(stable_root, &mut migration, &current)
        }
        RescueRecoveryRoute::PriorRestore => {
            reconcile_rescue_prior_restore(stable_root, &mut migration, &current)
        }
        RescueRecoveryRoute::StageCleanup => {
            reconcile_rescue_stage_cleanup(stable_root, &migration, &current)
        }
    }
}

fn reconcile_rescue_intent(
    stable_root: &Path,
    migration: &mut RescueMigration,
    current: &OwnershipRecord,
) -> ManagedResult<()> {
    require_prior_rescue_endpoint(migration, current)?;
    if stage_snapshot_if_present(&migration.backup)?.is_some() {
        return Err(inexact_rescue_migration_state());
    }
    if let Some(stage) = stage_snapshot_if_present(&migration.stage)?
        && !planned_stage_is_exact_subset(&migration.new_snapshot, &stage)
    {
        return Err(inexact_rescue_migration_state());
    }
    migration.phase = RescueMigrationPhase::StageCleaning;
    write_rescue_migration(stable_root, migration)?;
    remove_remaining_planned_stage(&migration.new_snapshot, "stage")?;
    clear_rescue_migration(stable_root)
}

fn reconcile_rescue_before_notice(
    stable_root: &Path,
    migration: &mut RescueMigration,
    current: &OwnershipRecord,
) -> ManagedResult<()> {
    if current != &migration.prior_record
        || stage_snapshot_if_present(&migration.stage)?.as_ref() != Some(&migration.new_snapshot)
    {
        return Err(inexact_rescue_migration_state());
    }
    let rescue = stage_snapshot_if_present(&migration.rescue)?;
    let backup = stage_snapshot_if_present(&migration.backup)?;
    let prior_backup = relocate_stage_snapshot(
        &migration.prior_snapshot,
        &migration.rescue,
        &migration.backup,
    )?;
    let before_rename = rescue.as_ref() == Some(&migration.prior_snapshot) && backup.is_none();
    let after_rename = rescue.is_none() && backup.as_ref() == Some(&prior_backup);
    let allowed = match migration.phase {
        RescueMigrationPhase::PriorBackedUp => after_rename,
        RescueMigrationPhase::Prepared | RescueMigrationPhase::PriorBackingUp => {
            before_rename || after_rename
        }
        RescueMigrationPhase::NoticePublishing => after_rename,
        _ => false,
    };
    if !allowed {
        return Err(inexact_rescue_migration_state());
    }
    migration.phase = RescueMigrationPhase::PriorRestoring;
    write_rescue_migration(stable_root, migration)?;
    reconcile_rescue_prior_restore(stable_root, migration, current)
}

fn reconcile_rescue_notice_rollback(
    stable_root: &Path,
    migration: &mut RescueMigration,
    current: &OwnershipRecord,
) -> ManagedResult<()> {
    if current != &migration.prior_record {
        return Err(inexact_rescue_migration_state());
    }
    let rescue = stage_snapshot_if_present(&migration.rescue)?;
    let stage = stage_snapshot_if_present(&migration.stage)?;
    let backup = stage_snapshot_if_present(&migration.backup)?;
    let prior_backup = relocate_stage_snapshot(
        &migration.prior_snapshot,
        &migration.rescue,
        &migration.backup,
    )?;
    let new_live =
        relocate_stage_snapshot(&migration.new_snapshot, &migration.stage, &migration.rescue)?;
    let before_publish = rescue.is_none()
        && stage.as_ref() == Some(&migration.new_snapshot)
        && backup.as_ref() == Some(&prior_backup);
    let after_publish = rescue.as_ref() == Some(&new_live)
        && stage.is_none()
        && backup.as_ref() == Some(&prior_backup);
    let allowed = match migration.phase {
        RescueMigrationPhase::NoticePublishing => before_publish || after_publish,
        RescueMigrationPhase::PriorBackedUp
        | RescueMigrationPhase::NoticePublished
        | RescueMigrationPhase::RecordCommitting => after_publish,
        _ => false,
    };
    if !allowed {
        return Err(inexact_rescue_migration_state());
    }
    if before_publish {
        migration.phase = RescueMigrationPhase::PriorRestoring;
        write_rescue_migration(stable_root, migration)?;
        return reconcile_rescue_prior_restore(stable_root, migration, current);
    }
    migration.phase = RescueMigrationPhase::NoticeCleaning;
    write_rescue_migration(stable_root, migration)?;
    reconcile_rescue_notice_cleanup(stable_root, migration, current)
}

fn reconcile_rescue_notice_cleanup(
    stable_root: &Path,
    migration: &mut RescueMigration,
    current: &OwnershipRecord,
) -> ManagedResult<()> {
    if current != &migration.prior_record || stage_snapshot_if_present(&migration.stage)?.is_some()
    {
        return Err(inexact_rescue_migration_state());
    }
    let prior_backup = relocate_stage_snapshot(
        &migration.prior_snapshot,
        &migration.rescue,
        &migration.backup,
    )?;
    if stage_snapshot_if_present(&migration.backup)?.as_ref() != Some(&prior_backup) {
        return Err(inexact_rescue_migration_state());
    }
    let new_live =
        relocate_stage_snapshot(&migration.new_snapshot, &migration.stage, &migration.rescue)?;
    if let Some(live) = stage_snapshot_if_present(&migration.rescue)?
        && !stage_is_exact_subset(&new_live, &live)
    {
        return Err(inexact_rescue_migration_state());
    }
    remove_remaining_exact_stage(&new_live, "stage")?;
    migration.phase = RescueMigrationPhase::PriorRestoring;
    write_rescue_migration(stable_root, migration)?;
    reconcile_rescue_prior_restore(stable_root, migration, current)
}

fn reconcile_rescue_prior_restore(
    stable_root: &Path,
    migration: &mut RescueMigration,
    current: &OwnershipRecord,
) -> ManagedResult<()> {
    if current != &migration.prior_record {
        return Err(inexact_rescue_migration_state());
    }
    let rescue = stage_snapshot_if_present(&migration.rescue)?;
    let backup = stage_snapshot_if_present(&migration.backup)?;
    let prior_backup = relocate_stage_snapshot(
        &migration.prior_snapshot,
        &migration.rescue,
        &migration.backup,
    )?;
    if rescue.is_none() && backup.as_ref() == Some(&prior_backup) {
        fs::rename(&migration.backup, &migration.rescue).map_err(|error| {
            ManagedError::io(
                "recovery_needed",
                "cannot restore authenticated rescue backup",
                error,
            )
        })?;
        sync_directory(stable_root)?;
    } else if rescue.as_ref() != Some(&migration.prior_snapshot) || backup.is_some() {
        return Err(inexact_rescue_migration_state());
    }
    validate_stage_snapshot_live(&migration.rescue, &migration.prior_snapshot)?;
    if let Some(stage) = stage_snapshot_if_present(&migration.stage)?
        && !stage_is_exact_subset(&migration.new_snapshot, &stage)
    {
        return Err(inexact_rescue_migration_state());
    }
    migration.phase = RescueMigrationPhase::StageCleaning;
    write_rescue_migration(stable_root, migration)?;
    reconcile_rescue_stage_cleanup(stable_root, migration, current)
}

fn reconcile_rescue_stage_cleanup(
    stable_root: &Path,
    migration: &RescueMigration,
    current: &OwnershipRecord,
) -> ManagedResult<()> {
    require_prior_rescue_endpoint(migration, current)?;
    if stage_snapshot_if_present(&migration.backup)?.is_some() {
        return Err(inexact_rescue_migration_state());
    }
    if rescue_stage_snapshot_is_planned(&migration.new_snapshot) {
        if let Some(stage) = stage_snapshot_if_present(&migration.stage)?
            && !planned_stage_is_exact_subset(&migration.new_snapshot, &stage)
        {
            return Err(inexact_rescue_migration_state());
        }
        remove_remaining_planned_stage(&migration.new_snapshot, "stage")?;
    } else {
        if let Some(stage) = stage_snapshot_if_present(&migration.stage)?
            && !stage_is_exact_subset(&migration.new_snapshot, &stage)
        {
            return Err(inexact_rescue_migration_state());
        }
        remove_remaining_exact_stage(&migration.new_snapshot, "stage")?;
    }
    clear_rescue_migration(stable_root)
}

fn reconcile_committed_rescue_migration(
    stable_root: &Path,
    migration: &mut RescueMigration,
    current: &OwnershipRecord,
) -> ManagedResult<()> {
    let new_live =
        relocate_stage_snapshot(&migration.new_snapshot, &migration.stage, &migration.rescue)?;
    if current != &migration.new_record
        || stage_snapshot_if_present(&migration.rescue)?.as_ref() != Some(&new_live)
        || stage_snapshot_if_present(&migration.stage)?.is_some()
    {
        return Err(inexact_rescue_migration_state());
    }
    let prior_backup = relocate_stage_snapshot(
        &migration.prior_snapshot,
        &migration.rescue,
        &migration.backup,
    )?;
    if let Some(backup) = stage_snapshot_if_present(&migration.backup)?
        && !stage_is_exact_subset(&prior_backup, &backup)
    {
        return Err(inexact_rescue_migration_state());
    }
    migration.phase = RescueMigrationPhase::BackupRetiring;
    write_rescue_migration(stable_root, migration)?;
    remove_remaining_exact_stage(&prior_backup, "backup")?;
    clear_rescue_migration(stable_root)
}

fn require_prior_rescue_endpoint(
    migration: &RescueMigration,
    current: &OwnershipRecord,
) -> ManagedResult<()> {
    if current != &migration.prior_record
        || stage_snapshot_if_present(&migration.rescue)?.as_ref() != Some(&migration.prior_snapshot)
    {
        return Err(inexact_rescue_migration_state());
    }
    Ok(())
}

fn inexact_rescue_migration_state() -> ManagedError {
    ManagedError::new(
        "recovery_needed",
        "rescue migration live state is not an exact reachable state",
    )
}

fn rescue_marker(record: &OwnershipRecord, stable_root: &Path) -> ManagedResult<String> {
    let mut marker = format!(
        "HERDR_A2A_RESCUE_V1\nstable_root={}\nstable_binary={}\npi_package_source={}\npi_config_path={}\nplugin_root={}\nbroker_digest={}\n",
        path_text(stable_root)?,
        path_text(&record.stable_binary)?,
        path_text(&record.pi_package_source)?,
        path_text(&record.pi_config_path)?,
        path_text(&record.plugin_root)?,
        record.broker_digest,
    );
    for owned in &record.owned_files {
        marker.push_str(&format!("owned={}|{}|", owned.mode, owned.sha256));
        marker.push_str(path_text(&owned.path)?);
        marker.push('\n');
    }
    marker.push_str("state_root=");
    if record.purge_authority {
        marker.push_str(path_text(&record.plugin_state_root)?);
    } else {
        marker.push_str("disabled");
    }
    marker.push('\n');
    let mut directories = removal_directories(record, stable_root)?;
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    directories.dedup();
    for directory in directories {
        marker.push_str("dir=");
        marker.push_str(path_text(&directory)?);
        marker.push('\n');
    }
    Ok(marker)
}

fn replace_owned_bytes(path: &Path, bytes: &[u8], mode: u32) -> ManagedResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| ManagedError::new("generation_failed", "owned replacement has no parent"))?;
    validate_private_directory(parent, 0o700)?;
    let temporary = parent.join(format!(".rescue-stage-{}", random_hex()?));
    write_new_file(&temporary, bytes, mode)?;
    fs::rename(&temporary, path).map_err(|error| {
        ManagedError::io("generation_failed", "cannot publish rescue file", error)
    })?;
    sync_directory(parent)?;
    validate_owned_regular_file(path, mode, "generation_failed")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RescueLayout {
    SourceNotice,
    LegacyExecutable,
    LegacyHelper,
}

impl RescueLayout {
    fn notice_mode(self) -> u32 {
        match self {
            Self::SourceNotice => 0o600,
            Self::LegacyExecutable | Self::LegacyHelper => 0o700,
        }
    }
}

fn rescue_layout(record: &OwnershipRecord, stable_root: &Path) -> ManagedResult<RescueLayout> {
    let rescue = record
        .owned_files
        .iter()
        .find(|owned| owned.path == record.rescue_path)
        .ok_or_else(|| {
            ManagedError::new(
                "ownership_record_invalid",
                "ownership record has no rescue entry",
            )
        })?;
    let legacy_helper_path = stable_root
        .join(RESCUE_DIRECTORY)
        .join(LEGACY_RESCUE_HELPER);
    let legacy_helper = record
        .owned_files
        .iter()
        .find(|owned| owned.path == legacy_helper_path);
    match (rescue.mode, legacy_helper) {
        (0o600, None) => Ok(RescueLayout::SourceNotice),
        (0o700, None) => Ok(RescueLayout::LegacyExecutable),
        (0o700, Some(helper))
            if record.schema_version == OWNERSHIP_SCHEMA
                && helper.mode == 0o700
                && helper.sha256 == record.broker_digest =>
        {
            Ok(RescueLayout::LegacyHelper)
        }
        _ => Err(ManagedError::new(
            "ownership_record_invalid",
            "ownership rescue layout is not an exact supported version",
        )),
    }
}

fn validate_record(record: &OwnershipRecord, stable_root: &Path) -> ManagedResult<()> {
    validate_record_inner(record, stable_root, true).map_err(|error| {
        if record.schema_version == 2 && record.purge_authority {
            ManagedError::new("ownership_record_invalid", error.to_string())
        } else {
            error
        }
    })
}

fn validate_record_for_removal(
    record: &OwnershipRecord,
    stable_root: &Path,
    purge: bool,
) -> ManagedResult<()> {
    validate_record_inner(record, stable_root, purge).map_err(|error| {
        if record.schema_version == 2 && record.purge_authority {
            ManagedError::new("ownership_record_invalid", error.to_string())
        } else {
            error
        }
    })
}

fn validate_record_inner(
    record: &OwnershipRecord,
    stable_root: &Path,
    validate_purge_root: bool,
) -> ManagedResult<()> {
    validate_record_semantics(record, stable_root, &record.plugin_root)?;
    let rescue_layout = rescue_layout(record, stable_root)?;
    if !matches!(record.schema_version, 2 | OWNERSHIP_SCHEMA)
        || record.ownership_path != stable_root.join(OWNERSHIP_FILE)
        || record.rescue_path != stable_root.join("rescue/uninstall.sh")
        || !matches!(record.install_kind.as_str(), "managed" | "linked-dev")
    {
        return Err(ManagedError::new(
            "ownership_record_invalid",
            "ownership schema or absolute paths are invalid",
        ));
    }
    let mut paths = vec![
        stable_root,
        &record.stable_binary,
        &record.pi_package_source,
        &record.pi_config_path,
        &record.plugin_root,
        &record.ownership_path,
        &record.rescue_path,
    ];
    if record.purge_authority {
        paths.push(&record.plugin_state_root);
    }
    for path in paths {
        require_absolute_normal(path, "ownership path")?;
        path_text(path)?;
    }
    if record.pi_config_path != pi_settings_path()? {
        return Err(ManagedError::new(
            "ownership_record_invalid",
            "Pi configuration path changed",
        ));
    }
    let generation = record.pi_package_source.parent().ok_or_else(|| {
        ManagedError::new(
            "ownership_record_invalid",
            "Pi source has no generation parent",
        )
    })?;
    if generation.parent() != Some(stable_root.join("generations").as_path())
        || record.stable_binary != generation.join("bin/herdr-a2a")
        || !is_allowed_managed_pi_entry(
            &record.pi_package_entry,
            &record.pi_config_path,
            &record.pi_package_source,
        )?
    {
        return Err(ManagedError::new(
            "ownership_record_invalid",
            "record path relationships are not canonical",
        ));
    }
    validate_private_directory(&record.plugin_root, 0o700)?;
    validate_private_directory(&record.plugin_root.join("libexec"), 0o700)?;
    validate_private_directory(generation, 0o700)?;
    if record.purge_authority && validate_purge_root {
        validate_private_directory(&record.plugin_state_root, 0o700)?;
    }
    if digest_file(&record.stable_binary)? != record.broker_digest
        || digest_tree(&record.pi_package_source)? != record.pi_package_digest
    {
        return Err(ManagedError::new(
            "owned_asset_modified",
            "recorded aggregate digests do not match assets",
        ));
    }
    let helper = record.plugin_root.join("libexec/herdr-a2a-dispatch");
    let pointer_path = record.plugin_root.join("stable-bin-path");
    let mut expected_modes = std::collections::BTreeMap::new();
    expected_modes.insert(record.stable_binary.clone(), 0o700);
    for file in tree_files(&record.pi_package_source)? {
        expected_modes.insert(file, 0o600);
    }
    expected_modes.insert(helper.clone(), 0o700);
    expected_modes.insert(pointer_path.clone(), 0o600);
    expected_modes.insert(record.rescue_path.clone(), rescue_layout.notice_mode());
    if rescue_layout == RescueLayout::LegacyHelper {
        expected_modes.insert(
            stable_root
                .join(RESCUE_DIRECTORY)
                .join(LEGACY_RESCUE_HELPER),
            0o700,
        );
    }
    expected_modes.insert(
        stable_root.join(RESCUE_DIRECTORY).join(RESCUE_MARKER),
        0o600,
    );
    if record.owned_files.len() != expected_modes.len() {
        return Err(ManagedError::new(
            "ownership_record_invalid",
            "owned file set is not exact",
        ));
    }
    let mut seen = BTreeSet::new();
    for owned in &record.owned_files {
        path_text(&owned.path)?;
        if !seen.insert(owned.path.clone()) || expected_modes.get(&owned.path) != Some(&owned.mode)
        {
            return Err(ManagedError::new(
                "ownership_record_invalid",
                "owned paths or modes are not canonical and unique",
            ));
        }
        validate_owned_file_digest(
            &owned.path,
            owned.mode,
            &owned.sha256,
            "owned_asset_modified",
        )?;
    }
    if record.schema_version == 2 && record.purge_authority {
        let marker_path = stable_root.join(RESCUE_DIRECTORY).join(RESCUE_MARKER);
        let mut marker_record = record.clone();
        marker_record
            .owned_files
            .retain(|owned| owned.path != marker_path);
        if sha256_bytes(rescue_marker(&marker_record, stable_root)?.as_bytes())
            != record.rescue_marker_digest
        {
            return Err(ManagedError::new(
                "ownership_record_invalid",
                "authoritative schema v2 rescue marker does not match ownership",
            ));
        }
    }
    let generation_files: Vec<PathBuf> = expected_modes
        .keys()
        .filter(|path| path.starts_with(generation))
        .cloned()
        .collect();
    if tree_files(generation)? != generation_files {
        return Err(ManagedError::new(
            "ownership_conflict",
            "generation contains unrecorded files",
        ));
    }
    if digest_file(&helper)? != record.broker_digest {
        return Err(ManagedError::new(
            "owned_asset_modified",
            "native helper does not match broker digest",
        ));
    }
    let mut pointer_file = open_validated_absolute_file(&pointer_path)?;
    let pointer_metadata = pointer_file.metadata().map_err(|error| {
        ManagedError::io(
            "owned_asset_modified",
            "cannot inspect stable pointer",
            error,
        )
    })?;
    let pointer = read_bounded_opened_utf8(
        &mut pointer_file,
        pointer_metadata.len(),
        MAX_POINTER_BYTES as u64,
        "owned_asset_modified",
    )?;
    if pointer != format!("{}\n", path_text(&record.stable_binary)?) {
        return Err(ManagedError::new(
            "owned_asset_modified",
            "stable-bin-path no longer names the recorded binary exactly",
        ));
    }
    Ok(())
}

fn validate_record_semantics(
    record: &OwnershipRecord,
    stable_root: &Path,
    plugin_root: &Path,
) -> ManagedResult<()> {
    if !matches!(record.schema_version, 2 | OWNERSHIP_SCHEMA)
        || record.ownership_path != stable_root.join(OWNERSHIP_FILE)
        || record.rescue_path != stable_root.join("rescue/uninstall.sh")
        || record.plugin_root != plugin_root
        || record.pi_config_path != pi_settings_path()?
        || !matches!(record.install_kind.as_str(), "managed" | "linked-dev")
        || record.plugin_version.is_empty()
        || record.plugin_version.len() > 128
        || !valid_digest(&record.broker_digest)
        || !valid_digest(&record.pi_package_digest)
        || ((record.schema_version == OWNERSHIP_SCHEMA || record.purge_authority)
            && !valid_digest(&record.rescue_marker_digest))
        || (record.purge_authority && record.plugin_state_root.as_os_str().is_empty())
        || (!record.purge_authority && !record.plugin_state_root.as_os_str().is_empty())
    {
        return Err(ManagedError::new(
            "recovery_needed",
            "transaction record semantics are invalid",
        ));
    }
    let mut paths = vec![
        stable_root,
        plugin_root,
        &record.stable_binary,
        &record.pi_package_source,
        &record.pi_config_path,
        &record.ownership_path,
        &record.rescue_path,
    ];
    if record.purge_authority {
        paths.push(&record.plugin_state_root);
    }
    for path in paths {
        require_absolute_normal(path, "transaction record path")?;
        path_text(path)?;
    }
    let generation = record.pi_package_source.parent().ok_or_else(|| {
        ManagedError::new("recovery_needed", "transaction record has no generation")
    })?;
    let rescue_layout = rescue_layout(record, stable_root)
        .map_err(|error| ManagedError::new("recovery_needed", error.to_string()))?;
    let helper = plugin_root.join("libexec/herdr-a2a-dispatch");
    let pointer = plugin_root.join("stable-bin-path");
    if generation.parent() != Some(stable_root.join("generations").as_path())
        || record.stable_binary != generation.join("bin/herdr-a2a")
        || record.pi_package_source != generation.join("pi")
        || !is_allowed_managed_pi_entry(
            &record.pi_package_entry,
            &record.pi_config_path,
            &record.pi_package_source,
        )?
    {
        return Err(ManagedError::new(
            "recovery_needed",
            "transaction record path relationships are invalid",
        ));
    }
    let expected_pointer_digest =
        sha256_bytes(format!("{}\n", path_text(&record.stable_binary)?).as_bytes());
    let mut seen = BTreeSet::new();
    let mut has_binary = false;
    let mut has_helper = false;
    let mut has_pointer = false;
    let mut has_package_manifest = false;
    let mut has_rescue = false;
    let mut has_rescue_helper = false;
    let mut has_rescue_marker = false;
    for owned in &record.owned_files {
        require_absolute_normal(&owned.path, "transaction owned path")?;
        path_text(&owned.path)?;
        if !seen.insert(owned.path.clone()) || !valid_digest(&owned.sha256) {
            return Err(ManagedError::new(
                "recovery_needed",
                "transaction owned files are not exact and unique",
            ));
        }
        if owned.path == record.stable_binary {
            has_binary = owned.mode == 0o700 && owned.sha256 == record.broker_digest;
        } else if owned.path == helper {
            has_helper = owned.mode == 0o700 && owned.sha256 == record.broker_digest;
        } else if owned.path == pointer {
            has_pointer = owned.mode == 0o600 && owned.sha256 == expected_pointer_digest;
        } else if owned.path.starts_with(&record.pi_package_source) && owned.mode == 0o600 {
            has_package_manifest |= owned.path == record.pi_package_source.join("package.json");
        } else if owned.path == record.rescue_path && owned.mode == rescue_layout.notice_mode() {
            has_rescue = true;
        } else if owned.path
            == stable_root
                .join(RESCUE_DIRECTORY)
                .join(LEGACY_RESCUE_HELPER)
            && rescue_layout == RescueLayout::LegacyHelper
            && owned.mode == 0o700
            && owned.sha256 == record.broker_digest
        {
            has_rescue_helper = true;
        } else if owned.path == stable_root.join(RESCUE_DIRECTORY).join(RESCUE_MARKER)
            && owned.mode == 0o600
        {
            has_rescue_marker = record.schema_version == 2 && !record.purge_authority
                || owned.sha256 == record.rescue_marker_digest;
        } else {
            return Err(ManagedError::new(
                "recovery_needed",
                "transaction record owns an unrelated path",
            ));
        }
    }
    if !has_binary
        || !has_helper
        || !has_pointer
        || !has_package_manifest
        || !has_rescue
        || (rescue_layout == RescueLayout::LegacyHelper && !has_rescue_helper)
        || !has_rescue_marker
    {
        return Err(ManagedError::new(
            "recovery_needed",
            "transaction record owned inventory is incomplete",
        ));
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_ready_pi(record: &OwnershipRecord) -> ManagedResult<()> {
    let settings = read_pi_settings()?;
    if settings.path != record.pi_config_path {
        return Err(ManagedError::new(
            "ownership_conflict",
            "Pi settings path differs from the record",
        ));
    }
    let matching: Vec<&Value> = settings
        .entries
        .iter()
        .filter(|entry| pi_entry_matches_path(entry, &settings.path, &record.pi_package_source))
        .collect();
    if matching.len() > 1
        || matching
            .first()
            .is_some_and(|entry| **entry != record.pi_package_entry)
    {
        return Err(ManagedError::new(
            "ownership_conflict",
            "Pi contains a conflicting same-source entry",
        ));
    }
    if record.state == InstallState::Ready && matching.is_empty() {
        return Err(ManagedError::new(
            "ownership_conflict",
            "Ready state requires the exact Pi entry",
        ));
    }
    Ok(())
}

fn validate_pi_entry_if_present(record: &OwnershipRecord) -> ManagedResult<()> {
    let settings = read_pi_settings()?;
    let matching: Vec<&Value> = settings
        .entries
        .iter()
        .filter(|entry| pi_entry_matches_path(entry, &settings.path, &record.pi_package_source))
        .collect();
    if matching.len() > 1
        || matching
            .first()
            .is_some_and(|entry| **entry != record.pi_package_entry)
    {
        return Err(ManagedError::new(
            "ownership_conflict",
            "Pi contains a same-source entry that differs from the exact recorded entry",
        ));
    }
    Ok(())
}

fn validate_removed_record_for_reinstall(
    record: &OwnershipRecord,
    stable_root: &Path,
) -> ManagedResult<()> {
    if record.state != InstallState::Removed {
        return Err(ManagedError::new(
            "ownership_record_invalid",
            "reinstall recovery requires a removed ownership record",
        ));
    }
    validate_record_semantics(record, stable_root, &record.plugin_root)?;
    for owned in &record.owned_files {
        match fs::symlink_metadata(&owned.path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(ManagedError::new(
                    "ownership_conflict",
                    "a removed managed asset is present before reinstall",
                ));
            }
            Err(error) => {
                return Err(ManagedError::io(
                    "ownership_conflict",
                    "cannot inspect a removed managed asset",
                    error,
                ));
            }
        }
    }
    let rescue_directory = stable_root.join(RESCUE_DIRECTORY);
    match fs::symlink_metadata(&rescue_directory) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(_) => {
            validate_private_directory(&rescue_directory, 0o700)?;
            if !tree_files(&rescue_directory)?.is_empty() {
                return Err(ManagedError::new(
                    "ownership_conflict",
                    "a removed installation has unowned rescue residue",
                ));
            }
        }
        Err(error) => {
            return Err(ManagedError::io(
                "ownership_conflict",
                "cannot inspect the removed rescue directory",
                error,
            ));
        }
    }
    match fs::symlink_metadata(stable_root.join(PROCESS_REGISTRY)) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(_) => {
            return Err(ManagedError::new(
                "owned_process_mismatch",
                "a removed installation still has a process registry",
            ));
        }
        Err(error) => {
            return Err(ManagedError::io(
                "owned_process_mismatch",
                "cannot inspect the removed process registry",
                error,
            ));
        }
    }
    let settings = read_pi_settings()?;
    if settings.path != record.pi_config_path
        || settings
            .entries
            .iter()
            .any(|entry| pi_entry_matches_path(entry, &settings.path, &record.pi_package_source))
    {
        return Err(ManagedError::new(
            "ownership_conflict",
            "a removed installation still has its managed Pi entry",
        ));
    }
    Ok(())
}

fn reconcile_interrupted_plugin_swap(record: &OwnershipRecord) -> ManagedResult<()> {
    let helper = record.plugin_root.join("libexec/herdr-a2a-dispatch");
    let pointer = record.plugin_root.join("stable-bin-path");
    let helper_owned = record
        .owned_files
        .iter()
        .find(|owned| owned.path == helper)
        .ok_or_else(|| {
            ManagedError::new(
                "ownership_record_invalid",
                "ownership record has no native helper",
            )
        })?;
    let pointer_owned = record
        .owned_files
        .iter()
        .find(|owned| owned.path == pointer)
        .ok_or_else(|| {
            ManagedError::new(
                "ownership_record_invalid",
                "ownership record has no stable pointer",
            )
        })?;
    reconcile_interrupted_file(helper_owned, helper.parent().unwrap(), ".herdr-a2a-backup-")?;
    reconcile_interrupted_file(pointer_owned, &record.plugin_root, ".stable-bin-backup-")?;
    cleanup_plugin_stages(&record.plugin_root)?;
    sync_directory(helper.parent().unwrap())?;
    sync_directory(&record.plugin_root)
}

fn reconcile_relocated_managed_plugin_root(
    stable_root: &Path,
    record: &OwnershipRecord,
) -> ManagedResult<OwnershipRecord> {
    let current_root = required_plugin_root()?;
    if current_root == record.plugin_root {
        return Ok(record.clone());
    }
    if record.install_kind != "managed" {
        return Err(ManagedError::new(
            "ownership_conflict",
            "a linked development plugin root cannot be relocated",
        ));
    }
    match fs::symlink_metadata(&record.plugin_root) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(_) => {
            return Err(ManagedError::new(
                "ownership_conflict",
                "the recorded plugin root still exists during relocation",
            ));
        }
        Err(error) => {
            return Err(ManagedError::io(
                "ownership_conflict",
                "cannot inspect the recorded plugin root during relocation",
                error,
            ));
        }
    }
    harden_owned_private_directory(&current_root, "relocated plugin root")?;

    let prior_helper = record.plugin_root.join("libexec/herdr-a2a-dispatch");
    let prior_pointer = record.plugin_root.join("stable-bin-path");
    let current_helper = current_root.join("libexec/herdr-a2a-dispatch");
    let current_pointer = current_root.join("stable-bin-path");
    let mut relocated = record.clone();
    let mut relocated_count = 0usize;
    for owned in &mut relocated.owned_files {
        if owned.path == prior_helper {
            owned.path = current_helper.clone();
            relocated_count += 1;
        } else if owned.path == prior_pointer {
            owned.path = current_pointer.clone();
            relocated_count += 1;
        } else if owned.path.starts_with(&record.plugin_root) {
            return Err(ManagedError::new(
                "ownership_record_invalid",
                "the recorded plugin root contains an unexpected owned path",
            ));
        }
    }
    if relocated_count != 2 {
        return Err(ManagedError::new(
            "ownership_record_invalid",
            "the recorded plugin root does not own exactly one helper and pointer",
        ));
    }
    relocated.plugin_root = current_root;
    validate_record(&relocated, stable_root)?;
    validate_pi_entry_if_present(&relocated)?;
    write_record(stable_root, &relocated)?;
    Ok(relocated)
}

fn reconcile_interrupted_file(
    owned: &OwnedFile,
    backup_parent: &Path,
    backup_prefix: &str,
) -> ManagedResult<()> {
    let mut matching_backup = None;
    for entry in fs::read_dir(backup_parent).map_err(|error| {
        ManagedError::io(
            "rollback_failed",
            "cannot inspect the managed backup directory",
            error,
        )
    })? {
        let entry = entry.map_err(|error| {
            ManagedError::io("rollback_failed", "cannot inspect backup entry", error)
        })?;
        if !entry
            .file_name()
            .to_string_lossy()
            .starts_with(backup_prefix)
        {
            continue;
        }
        let candidate = entry.path();
        if !owned_file_matches(&candidate, owned) || matching_backup.is_some() {
            return Err(ManagedError::new(
                "ownership_conflict",
                "an interrupted managed backup is ambiguous",
            ));
        }
        matching_backup = Some(candidate);
    }

    if owned_file_matches(&owned.path, owned) {
        if let Some(backup) = matching_backup {
            fs::remove_file(&backup).map_err(|error| {
                ManagedError::io("rollback_failed", "cannot remove completed backup", error)
            })?;
        }
        return Ok(());
    }
    let backup = matching_backup.ok_or_else(|| {
        ManagedError::new(
            "owned_asset_modified",
            "an owned file changed without a recoverable backup",
        )
    })?;
    if owned.path.exists() {
        validate_owned_regular_file(&owned.path, owned.mode, "ownership_conflict")?;
        fs::remove_file(&owned.path).map_err(|error| {
            ManagedError::io("rollback_failed", "cannot remove interrupted asset", error)
        })?;
    }
    fs::rename(&backup, &owned.path).map_err(|error| {
        ManagedError::io(
            "rollback_failed",
            "cannot restore interrupted backup",
            error,
        )
    })?;
    if !owned_file_matches(&owned.path, owned) {
        return Err(ManagedError::new(
            "rollback_failed",
            "a restored managed asset does not match its ownership record",
        ));
    }
    Ok(())
}

fn owned_file_matches(path: &Path, owned: &OwnedFile) -> bool {
    validate_owned_regular_file(path, owned.mode, "owned_asset_modified").is_ok()
        && digest_file(path)
            .map(|digest| digest == owned.sha256)
            .unwrap_or(false)
}

fn cleanup_plugin_stages(plugin_root: &Path) -> ManagedResult<()> {
    for entry in fs::read_dir(plugin_root)
        .map_err(|error| ManagedError::io("rollback_failed", "cannot inspect plugin root", error))?
    {
        let entry = entry.map_err(|error| {
            ManagedError::io("rollback_failed", "cannot inspect plugin entry", error)
        })?;
        if !entry
            .file_name()
            .to_string_lossy()
            .starts_with(".managed-stage-")
        {
            continue;
        }
        return Err(ManagedError::new(
            "ownership_conflict",
            "an unauthenticated plugin stage was found",
        ));
    }
    Ok(())
}

fn read_plugin_version(plugin_root: &Path) -> ManagedResult<String> {
    let manifest = plugin_root.join("herdr-plugin.toml");
    let mut manifest_file = open_validated_absolute_file(&manifest)?;
    let metadata = validate_opened_external_file(&manifest_file, false)?;
    if metadata.len() > MAX_EVENT_BYTES as u64 {
        return Err(ManagedError::new(
            "bundle_invalid",
            "plugin manifest exceeds 65536 bytes",
        ));
    }
    let encoded = read_bounded_opened_utf8(
        &mut manifest_file,
        metadata.len(),
        MAX_EVENT_BYTES as u64,
        "bundle_invalid",
    )?;
    let manifest: toml::Value = toml::from_str(&encoded)
        .map_err(|error| ManagedError::new("bundle_invalid", error.to_string()))?;
    manifest
        .get("version")
        .and_then(toml::Value::as_str)
        .filter(|version| !version.is_empty() && version.len() <= 128)
        .map(str::to_owned)
        .ok_or_else(|| ManagedError::new("bundle_invalid", "plugin manifest version is missing"))
}

fn stable_root() -> ManagedResult<PathBuf> {
    #[cfg(target_os = "macos")]
    let root = required_home()?.join("Library/Application Support/herdr-a2a");
    #[cfg(not(target_os = "macos"))]
    let root = match env::var_os("XDG_DATA_HOME") {
        Some(value) if !value.is_empty() => {
            require_absolute_normal(Path::new(&value), "XDG_DATA_HOME")?.join("herdr-a2a")
        }
        _ => required_home()?.join(".local/share/herdr-a2a"),
    };
    require_absolute_normal(&root, "stable data root")
}

fn required_home() -> ManagedResult<PathBuf> {
    let home = env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ManagedError::new("unsafe_install_path", "HOME is required"))?;
    require_absolute_normal(Path::new(&home), "HOME")
}

fn required_plugin_root() -> ManagedResult<PathBuf> {
    let root = env::var_os("HERDR_A2A_PLUGIN_ROOT")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ManagedError::new(
                "unsafe_install_path",
                "HERDR_A2A_PLUGIN_ROOT is required during install",
            )
        })?;
    require_absolute_normal(Path::new(&root), "HERDR_A2A_PLUGIN_ROOT")
}

fn required_plugin_state_root(install_kind: &str) -> ManagedResult<PathBuf> {
    let root = env::var_os("HERDR_PLUGIN_STATE_DIR")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ManagedError::new(
                "unsafe_install_path",
                "HERDR_PLUGIN_STATE_DIR is required during install",
            )
        })?;
    let root = require_absolute_normal(Path::new(&root), "HERDR_PLUGIN_STATE_DIR")?;
    if install_kind == "managed" {
        prepare_managed_plugin_state_root(&root)?;
    } else {
        harden_owned_private_directory(&root, "plugin-state directory")?;
    }
    Ok(root)
}

fn prepare_managed_plugin_state_root(path: &Path) -> ManagedResult<()> {
    let plugin_name = path.file_name();
    let plugins = path.parent();
    let herdr = plugins.and_then(Path::parent);
    let strict_parent = herdr.and_then(Path::parent);
    if plugin_name != Some(OsStr::new("herdr.a2a"))
        || plugins.and_then(Path::file_name) != Some(OsStr::new("plugins"))
        || herdr.and_then(Path::file_name) != Some(OsStr::new("herdr"))
    {
        return Err(ManagedError::new(
            "unsafe_install_path",
            "managed plugin-state root does not match the Herdr plugin namespace",
        ));
    }
    let strict_parent = strict_parent.ok_or_else(|| {
        ManagedError::new(
            "unsafe_install_path",
            "managed plugin-state root has no strict parent",
        )
    })?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = open_strict_directory_chain(strict_parent)?;
    for name in [
        OsStr::new("herdr"),
        OsStr::new("plugins"),
        OsStr::new("herdr.a2a"),
    ] {
        let opened = match openat(&directory, name, flags, Mode::empty()) {
            Ok(opened) => opened,
            Err(error) if error == rustix::io::Errno::NOENT => {
                mkdirat(&directory, name, Mode::from_bits_retain(0o700)).map_err(|error| {
                    ManagedError::new(
                        "unsafe_install_path",
                        format!("cannot create managed plugin-state directory: {error}"),
                    )
                })?;
                directory.sync_all().map_err(|error| {
                    ManagedError::io(
                        "unsafe_install_path",
                        "cannot sync managed plugin-state parent",
                        error,
                    )
                })?;
                openat(&directory, name, flags, Mode::empty()).map_err(|error| {
                    ManagedError::new(
                        "unsafe_install_path",
                        format!("cannot open created plugin-state directory: {error}"),
                    )
                })?
            }
            Err(error) => {
                return Err(ManagedError::new(
                    "unsafe_install_path",
                    format!("cannot open managed plugin-state directory: {error}"),
                ));
            }
        };
        directory = File::from(opened);
        harden_opened_managed_directory(&directory, Some(0o700))?;
    }
    Ok(())
}

fn harden_owned_private_directory(path: &Path, label: &str) -> ManagedResult<()> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory =
        File::from(open(Path::new("/"), flags, Mode::empty()).map_err(|error| {
            ManagedError::new("unsafe_install_path", format!("cannot open root: {error}"))
        })?);
    validate_opened_directory(&directory, false)?;
    for name in normal_components(path)? {
        directory = File::from(openat(&directory, name, flags, Mode::empty()).map_err(
            |error| {
                ManagedError::new(
                    "unsafe_install_path",
                    format!("cannot open a {label} component: {error}"),
                )
            },
        )?);
        validate_opened_directory(&directory, false)?;
    }
    let metadata = directory.metadata().map_err(|error| {
        ManagedError::io(
            "unsafe_install_path",
            &format!("cannot inspect the {label}"),
            error,
        )
    })?;
    if metadata.uid() != rustix::process::getuid().as_raw() {
        return Err(ManagedError::new(
            "unsafe_install_path",
            format!("the {label} is not owned by the current user"),
        ));
    }
    fchmod(&directory, Mode::from_bits_retain(0o700)).map_err(|error| {
        ManagedError::new(
            "unsafe_install_path",
            format!("cannot protect the {label}: {error}"),
        )
    })?;
    validate_opened_directory(&directory, true)?;
    directory.sync_all().map_err(|error| {
        ManagedError::io(
            "unsafe_install_path",
            &format!("cannot sync the protected {label}"),
            error,
        )
    })
}

fn require_absolute_normal(path: &Path, label: &str) -> ManagedResult<PathBuf> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(ManagedError::new(
            "unsafe_install_path",
            format!("{label} must be an absolute normalized path"),
        ));
    }
    Ok(path.to_path_buf())
}

enum DirectoryPolicy<'a> {
    ManagedOwned {
        boundary: &'a Path,
        final_mode: Option<u32>,
    },
}

fn managed_plugin_config_boundary(path: &Path) -> ManagedResult<PathBuf> {
    let plugin_name = path.file_name();
    let repository_plugins = path.parent();
    let checkout = repository_plugins.and_then(Path::parent);
    let temporary = checkout.and_then(Path::parent);
    let managed_plugins = temporary.and_then(Path::parent);
    let config_root = managed_plugins.and_then(Path::parent);
    let temporary_name = temporary
        .and_then(Path::file_name)
        .and_then(std::ffi::OsStr::to_str);
    if plugin_name != Some(std::ffi::OsStr::new("herdr"))
        || repository_plugins.and_then(Path::file_name) != Some(std::ffi::OsStr::new("plugins"))
        || checkout.and_then(Path::file_name) != Some(std::ffi::OsStr::new("checkout"))
        || managed_plugins.and_then(Path::file_name) != Some(std::ffi::OsStr::new("plugins"))
        || config_root.and_then(Path::file_name) != Some(std::ffi::OsStr::new("herdr"))
        || !temporary_name.is_some_and(|name| {
            name.strip_prefix(".tmp-install-")
                .is_some_and(|suffix| !suffix.is_empty())
        })
    {
        return Err(ManagedError::new(
            "unsafe_install_path",
            "managed plugin root does not match the Herdr temporary checkout layout",
        ));
    }
    Ok(config_root.unwrap().to_path_buf())
}

fn validate_or_harden_directory_chain(
    path: &Path,
    policy: DirectoryPolicy<'_>,
) -> ManagedResult<()> {
    require_absolute_normal(path, "directory")?;
    let DirectoryPolicy::ManagedOwned {
        boundary,
        final_mode,
    } = policy;
    require_absolute_normal(boundary, "managed boundary")?;
    if !path.starts_with(boundary) {
        return Err(ManagedError::new(
            "unsafe_install_path",
            "managed boundary is outside the directory path",
        ));
    }
    let boundary_names = normal_components(boundary)?;
    let names = normal_components(path)?;
    if names.get(..boundary_names.len()) != Some(boundary_names.as_slice()) {
        return Err(ManagedError::new(
            "unsafe_install_path",
            "managed boundary is not an exact directory prefix",
        ));
    }

    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory =
        File::from(open(Path::new("/"), flags, Mode::empty()).map_err(|error| {
            ManagedError::new("unsafe_install_path", format!("cannot open root: {error}"))
        })?);
    validate_opened_directory(&directory, false)?;
    for (index, name) in names.iter().enumerate() {
        directory = File::from(openat(&directory, *name, flags, Mode::empty()).map_err(
            |error| {
                ManagedError::new(
                    "unsafe_install_path",
                    format!("cannot open a directory component: {error}"),
                )
            },
        )?);
        let component_count = index + 1;
        if component_count < boundary_names.len() {
            validate_opened_directory(&directory, false)?;
            continue;
        }
        let required_mode = (component_count == names.len())
            .then_some(final_mode)
            .flatten();
        harden_opened_managed_directory(&directory, required_mode)?;
    }
    Ok(())
}

fn open_strict_directory_chain(path: &Path) -> ManagedResult<File> {
    require_absolute_normal(path, "directory")?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory =
        File::from(open(Path::new("/"), flags, Mode::empty()).map_err(|error| {
            ManagedError::new("unsafe_install_path", format!("cannot open root: {error}"))
        })?);
    validate_opened_directory(&directory, false)?;
    for name in normal_components(path)? {
        directory = File::from(openat(&directory, name, flags, Mode::empty()).map_err(
            |error| {
                ManagedError::new(
                    "unsafe_install_path",
                    format!("cannot open a directory component: {error}"),
                )
            },
        )?);
        validate_opened_directory(&directory, false)?;
    }
    Ok(directory)
}

fn harden_opened_managed_directory(
    directory: &File,
    required_mode: Option<u32>,
) -> ManagedResult<()> {
    let metadata = directory.metadata().map_err(|error| {
        ManagedError::io(
            "unsafe_install_path",
            "cannot inspect managed directory",
            error,
        )
    })?;
    let uid = rustix::process::getuid().as_raw();
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o002 != 0 {
        return Err(ManagedError::new(
            "unsafe_install_path",
            "managed directory is not exclusively controlled by the current user",
        ));
    }
    let current_mode = metadata.mode() & 0o7777;
    let protected_mode = required_mode.unwrap_or(current_mode & !0o020);
    if current_mode != protected_mode {
        let protected_mode = u16::try_from(protected_mode).map_err(|_| {
            ManagedError::new("unsafe_install_path", "managed directory mode is invalid")
        })?;
        fchmod(directory, Mode::from_bits_retain(protected_mode)).map_err(|error| {
            ManagedError::new(
                "unsafe_install_path",
                format!("cannot protect managed directory: {error}"),
            )
        })?;
        directory.sync_all().map_err(|error| {
            ManagedError::io(
                "unsafe_install_path",
                "cannot sync protected managed directory",
                error,
            )
        })?;
    }
    validate_opened_directory(directory, required_mode == Some(0o700))
}

pub(crate) fn validate_directory_chain(path: &Path, private_final: bool) -> ManagedResult<()> {
    require_absolute_normal(path, "directory")?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory =
        File::from(open(Path::new("/"), flags, Mode::empty()).map_err(|error| {
            ManagedError::new("unsafe_install_path", format!("cannot open root: {error}"))
        })?);
    validate_opened_directory(&directory, false)?;
    let names = normal_components(path)?;
    for (index, name) in names.iter().enumerate() {
        directory = File::from(openat(&directory, *name, flags, Mode::empty()).map_err(
            |error| {
                ManagedError::new(
                    "unsafe_install_path",
                    format!("cannot open a directory component: {error}"),
                )
            },
        )?);
        validate_opened_directory(&directory, private_final && index + 1 == names.len())?;
    }
    Ok(())
}

fn normal_components(path: &Path) -> ManagedResult<Vec<&std::ffi::OsStr>> {
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err(ManagedError::new(
            "unsafe_install_path",
            "absolute path has no root",
        ));
    }
    components
        .map(|component| match component {
            Component::Normal(name) => Ok(name),
            _ => Err(ManagedError::new(
                "unsafe_install_path",
                "path contains an unsupported component",
            )),
        })
        .collect()
}

fn validate_opened_directory(directory: &File, private: bool) -> ManagedResult<()> {
    let metadata = directory.metadata().map_err(|error| {
        ManagedError::io(
            "unsafe_install_path",
            "cannot inspect opened directory",
            error,
        )
    })?;
    let uid = rustix::process::getuid().as_raw();
    let secure_sticky_root = !private && metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
    if !metadata.is_dir()
        || (metadata.uid() != 0 && metadata.uid() != uid)
        || (metadata.mode() & 0o022 != 0 && !secure_sticky_root)
        || (private && metadata.mode() & 0o777 != 0o700)
    {
        return Err(ManagedError::new(
            "unsafe_install_path",
            "directory chain contains an unsafe opened descriptor",
        ));
    }
    Ok(())
}

fn open_validated_absolute_file(path: &Path) -> ManagedResult<File> {
    require_absolute_normal(path, "file")?;
    let mut names = normal_components(path)?;
    let final_name = names.pop().ok_or_else(|| {
        ManagedError::new("unsafe_install_path", "file path has no final component")
    })?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory =
        File::from(open(Path::new("/"), flags, Mode::empty()).map_err(|error| {
            ManagedError::new("unsafe_install_path", format!("cannot open root: {error}"))
        })?);
    validate_opened_directory(&directory, false)?;
    for name in names {
        directory = File::from(openat(&directory, name, flags, Mode::empty()).map_err(
            |error| {
                ManagedError::new(
                    "unsafe_install_path",
                    format!("cannot open a file parent: {error}"),
                )
            },
        )?);
        validate_opened_directory(&directory, false)?;
    }
    let file = File::from(
        openat(
            &directory,
            final_name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|error| {
            ManagedError::new(
                "owned_asset_modified",
                format!("cannot open an owned file: {error}"),
            )
        })?,
    );
    Ok(file)
}

fn open_owned_regular_file_with_mode(
    path: &Path,
    boundary: &Path,
    mode: u32,
    code: &'static str,
) -> ManagedResult<File> {
    let path = require_absolute_normal(path, "owned file")?;
    let parent = path
        .parent()
        .ok_or_else(|| ManagedError::new(code, "owned file has no parent directory"))?;
    validate_or_harden_directory_chain(
        boundary,
        DirectoryPolicy::ManagedOwned {
            boundary,
            final_mode: Some(0o700),
        },
    )?;
    if parent != boundary {
        validate_or_harden_directory_chain(
            parent,
            DirectoryPolicy::ManagedOwned {
                boundary,
                final_mode: Some(0o700),
            },
        )?;
    }

    let directory = open_strict_directory_chain(parent)?;
    let final_name = path
        .file_name()
        .ok_or_else(|| ManagedError::new(code, "owned file path has no final component"))?;
    let file = File::from(
        openat(
            &directory,
            final_name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|error| ManagedError::new(code, format!("cannot open owned file: {error}")))?,
    );
    let metadata = file
        .metadata()
        .map_err(|error| ManagedError::io(code, "cannot inspect owned file", error))?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.nlink() != 1
        || metadata.mode() & 0o002 != 0
    {
        return Err(ManagedError::new(code, "owned file inode is unsafe"));
    }
    let mode =
        u16::try_from(mode).map_err(|_| ManagedError::new(code, "owned file mode is invalid"))?;
    fchmod(&file, Mode::from_bits_retain(mode))
        .map_err(|error| ManagedError::new(code, format!("cannot protect owned file: {error}")))?;
    file.sync_all()
        .map_err(|error| ManagedError::io(code, "cannot sync protected owned file", error))?;
    let metadata = file
        .metadata()
        .map_err(|error| ManagedError::io(code, "cannot re-inspect protected owned file", error))?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != u32::from(mode)
    {
        return Err(ManagedError::new(
            code,
            "protected owned file failed revalidation",
        ));
    }
    Ok(file)
}

fn validate_private_directory(path: &Path, mode: u32) -> ManagedResult<()> {
    validate_directory_chain(path, mode == 0o700)
}

fn create_private_directory(path: &Path) -> ManagedResult<()> {
    if fs::symlink_metadata(path).is_ok() {
        return validate_private_directory(path, 0o700);
    }
    let mut missing = Vec::new();
    let mut existing = path;
    while fs::symlink_metadata(existing).is_err() {
        missing.push(existing.to_path_buf());
        existing = existing.parent().ok_or_else(|| {
            ManagedError::new("unsafe_install_path", "private root has no existing parent")
        })?;
    }
    validate_directory_chain(existing, false)?;
    for directory in missing.into_iter().rev() {
        let parent = directory.parent().ok_or_else(|| {
            ManagedError::new("unsafe_install_path", "private directory has no parent")
        })?;
        fs::create_dir(&directory).map_err(|error| {
            ManagedError::io(
                "unsafe_install_path",
                "cannot create a managed directory",
                error,
            )
        })?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).map_err(|error| {
            ManagedError::io(
                "unsafe_install_path",
                "cannot protect private directory",
                error,
            )
        })?;
        sync_directory(parent)?;
    }
    validate_private_directory(path, 0o700)
}

fn validate_external_file(path: &Path, executable: bool) -> ManagedResult<()> {
    require_absolute_normal(path, "bundle file")?;
    let file = open_validated_absolute_file(path)?;
    validate_opened_external_file(&file, executable).map(|_| ())
}

fn validate_opened_external_file(file: &File, executable: bool) -> ManagedResult<fs::Metadata> {
    let metadata = file.metadata().map_err(|error| {
        ManagedError::io("bundle_invalid", "cannot inspect opened bundle file", error)
    })?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || (executable && metadata.mode() & 0o100 == 0)
    {
        return Err(ManagedError::new(
            "bundle_invalid",
            "the bundle contains an unsafe file",
        ));
    }
    Ok(metadata)
}

fn validate_external_tree(path: &Path) -> ManagedResult<()> {
    validate_directory_chain(path, false)?;
    let snapshot = snapshot_tree(path)?;
    if snapshot.files.is_empty()
        || !snapshot
            .files
            .iter()
            .any(|file| file.relative == Path::new("package.json"))
    {
        return Err(ManagedError::new(
            "bundle_invalid",
            "Pi bundle is empty or has no package.json",
        ));
    }
    Ok(())
}

fn acquire_install_lock(stable_root: &Path) -> ManagedResult<InstallLockGuard> {
    let lock_path = stable_root.join(INSTALL_LOCK);
    let directory = File::from(
        open(
            stable_root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| {
            ManagedError::new(
                "installer_lock_failed",
                format!("cannot open lock directory: {error}"),
            )
        })?,
    );
    let create_flags =
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let (file, created) = match openat(
        &directory,
        INSTALL_LOCK,
        create_flags,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(fd) => (File::from(fd), true),
        Err(rustix::io::Errno::EXIST) => (
            File::from(
                openat(
                    &directory,
                    INSTALL_LOCK,
                    OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|error| {
                    ManagedError::new(
                        "installer_lock_failed",
                        format!("cannot safely open lock: {error}"),
                    )
                })?,
            ),
            false,
        ),
        Err(error) => {
            return Err(ManagedError::new(
                "installer_lock_failed",
                format!("cannot create lock: {error}"),
            ));
        }
    };
    if created {
        fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(|error| {
            ManagedError::new(
                "installer_lock_failed",
                format!("cannot protect new lock: {error}"),
            )
        })?;
        file.sync_all().map_err(|error| {
            ManagedError::io("installer_lock_failed", "cannot sync new lock", error)
        })?;
        sync_directory(stable_root)?;
    }
    let opened = file.metadata().map_err(|error| {
        ManagedError::io("installer_lock_failed", "cannot inspect opened lock", error)
    })?;
    if !opened.is_file()
        || opened.uid() != rustix::process::getuid().as_raw()
        || opened.nlink() != 1
        || opened.mode() & 0o777 != 0o600
    {
        return Err(ManagedError::new(
            "installer_lock_failed",
            "opened lock inode is unsafe",
        ));
    }
    flock(&file, FlockOperation::LockExclusive)
        .map_err(|error| ManagedError::new("installer_lock_failed", error.to_string()))?;
    #[cfg(debug_assertions)]
    if env::var_os("HERDR_A2A_TEST_REPLACE_LOCK_BEFORE_RECHECK").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        let displaced = stable_root.join("install.lock.displaced");
        fs::rename(&lock_path, &displaced).map_err(|error| {
            ManagedError::io(
                "installer_lock_failed",
                "cannot inject lock replacement",
                error,
            )
        })?;
        write_new_file(&lock_path, b"replacement\n", 0o600)?;
    }
    let named = fs::symlink_metadata(&lock_path).map_err(|error| {
        ManagedError::io("installer_lock_failed", "cannot recheck named lock", error)
    })?;
    if !named.is_file()
        || named.file_type().is_symlink()
        || named.dev() != opened.dev()
        || named.ino() != opened.ino()
    {
        return Err(ManagedError::new(
            "installer_lock_failed",
            "lock directory entry was replaced",
        ));
    }
    Ok(InstallLockGuard { _file: file })
}

fn prepare_generation(
    stable_root: &Path,
    bundle_binary: &Path,
    bundle_package: &Path,
    broker_digest: &str,
    package_digest: &str,
    transaction_token: &str,
    record_stage: impl FnOnce(StageSnapshot) -> ManagedResult<()>,
) -> ManagedResult<PreparedGeneration> {
    let generations = stable_root.join("generations");
    if !generations.exists() {
        fs::create_dir(&generations).map_err(|error| {
            ManagedError::io("generation_failed", "cannot create generations", error)
        })?;
        fs::set_permissions(&generations, fs::Permissions::from_mode(0o700)).map_err(|error| {
            ManagedError::io("generation_failed", "cannot protect generations", error)
        })?;
        sync_directory(stable_root)?;
    }
    validate_private_directory(&generations, 0o700)?;
    let combined = sha256_bytes(format!("{broker_digest}\0{package_digest}").as_bytes());
    let directory = generations.join(&combined[..32]);
    let binary = directory.join("bin/herdr-a2a");
    let package = directory.join("pi");
    if directory.exists() {
        validate_private_directory(&directory, 0o700)?;
        if digest_file(&binary)? != broker_digest || digest_tree(&package)? != package_digest {
            return Err(ManagedError::new(
                "ownership_conflict",
                "an unrecognized generation occupies the managed digest path",
            ));
        }
        return Ok(PreparedGeneration { binary, package });
    }
    let stage = generations.join(format!(".stage-{transaction_token}"));
    fs::create_dir(&stage).map_err(|error| {
        ManagedError::io("generation_failed", "cannot create generation stage", error)
    })?;
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o700)).map_err(|error| {
        ManagedError::io(
            "generation_failed",
            "cannot protect generation stage",
            error,
        )
    })?;
    let result = (|| {
        let staged_binary = stage.join("bin/herdr-a2a");
        let staged_package = stage.join("pi");
        create_private_directory(stage.join("bin").as_path())?;
        copy_owned_file(bundle_binary, &staged_binary, 0o700)?;
        if copy_owned_tree(bundle_package, &staged_package)? != package_digest {
            return Err(ManagedError::new(
                "bundle_invalid",
                "bundle package changed between validation and copy",
            ));
        }
        sync_tree(&stage)?;
        record_stage(snapshot_stage(&stage)?)?;
        fs::rename(&stage, &directory).map_err(|error| {
            ManagedError::io("generation_failed", "cannot publish generation", error)
        })?;
        sync_directory(&generations)?;
        Ok(())
    })();
    if result.is_err()
        && stage.exists()
        && let Ok(snapshot) = snapshot_stage(&stage)
    {
        let _ = remove_exact_stage(&snapshot);
    }
    result?;
    Ok(PreparedGeneration { binary, package })
}

fn generation_plan_path(stable_root: &Path, broker_digest: &str, package_digest: &str) -> PathBuf {
    let combined = sha256_bytes(format!("{broker_digest}\0{package_digest}").as_bytes());
    stable_root.join("generations").join(&combined[..32])
}

fn generation_plan(
    stable_root: &Path,
    bundle_package: &Path,
    broker_digest: &str,
    package_digest: &str,
) -> ManagedResult<(PathBuf, Vec<PathBuf>)> {
    let directory = generation_plan_path(stable_root, broker_digest, package_digest);
    let mut files = vec![directory.join("bin/herdr-a2a")];
    for source in tree_files(bundle_package)? {
        let relative = source.strip_prefix(bundle_package).map_err(|_| {
            ManagedError::new("bundle_invalid", "bundle package file escaped its root")
        })?;
        files.push(directory.join("pi").join(relative));
    }
    files.sort();
    Ok((directory, files))
}

fn install_plugin_assets(
    plugin_root: &Path,
    stable_binary: &Path,
    token: &str,
    mut record_state: impl FnMut(TransactionPhase, Option<StageSnapshot>) -> ManagedResult<()>,
) -> ManagedResult<PluginSwap> {
    let stage = plugin_root.join(format!(".managed-stage-{token}"));
    fs::create_dir(&stage).map_err(|error| {
        ManagedError::io("generation_failed", "cannot create plugin stage", error)
    })?;
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o700)).map_err(|error| {
        ManagedError::io("generation_failed", "cannot protect plugin stage", error)
    })?;
    let staged_libexec = stage.join("libexec");
    fs::create_dir(&staged_libexec).map_err(|error| {
        ManagedError::io("generation_failed", "cannot create staged libexec", error)
    })?;
    fs::set_permissions(&staged_libexec, fs::Permissions::from_mode(0o700)).map_err(|error| {
        ManagedError::io("generation_failed", "cannot protect staged libexec", error)
    })?;
    let staged_helper = staged_libexec.join("herdr-a2a-dispatch");
    copy_owned_file(stable_binary, &staged_helper, 0o700)?;
    let staged_pointer = stage.join("stable-bin-path");
    write_new_file(
        &staged_pointer,
        format!("{}\n", path_text(stable_binary)?).as_bytes(),
        0o600,
    )?;
    sync_tree(&stage)?;
    let staged_snapshot = snapshot_stage(&stage)?;
    if let Err(error) = record_state(
        TransactionPhase::PluginPublishing,
        Some(staged_snapshot.clone()),
    ) {
        remove_exact_stage(&staged_snapshot)?;
        return Err(error);
    }

    let libexec = plugin_root.join("libexec");
    if !libexec.exists() {
        fs::create_dir(&libexec).map_err(|error| {
            ManagedError::io("generation_failed", "cannot create libexec", error)
        })?;
        fs::set_permissions(&libexec, fs::Permissions::from_mode(0o700)).map_err(|error| {
            ManagedError::io("generation_failed", "cannot protect libexec", error)
        })?;
        sync_directory(plugin_root)?;
    }
    validate_private_directory(&libexec, 0o700)?;
    let helper = libexec.join("herdr-a2a-dispatch");
    let pointer = plugin_root.join("stable-bin-path");
    let helper_backup = helper
        .exists()
        .then(|| libexec.join(format!(".herdr-a2a-backup-{token}")));
    let pointer_backup = pointer
        .exists()
        .then(|| plugin_root.join(format!(".stable-bin-backup-{token}")));
    record_state(TransactionPhase::PluginBackingUpHelper, None)?;
    if let Some(backup) = &helper_backup {
        fs::rename(&helper, backup).map_err(|error| {
            ManagedError::io("generation_failed", "cannot retain prior helper", error)
        })?;
        #[cfg(debug_assertions)]
        if env::var_os("HERDR_A2A_TEST_ABORT_AFTER_HELPER_BACKUP_RENAME").as_deref()
            == Some(std::ffi::OsStr::new("1"))
        {
            std::process::abort();
        }
    }
    record_state(TransactionPhase::PluginBackingUpPointer, None)?;
    if let Some(backup) = &pointer_backup {
        fs::rename(&pointer, backup).map_err(|error| {
            ManagedError::io("generation_failed", "cannot retain prior pointer", error)
        })?;
        #[cfg(debug_assertions)]
        if env::var_os("HERDR_A2A_TEST_ABORT_AFTER_POINTER_BACKUP_RENAME").as_deref()
            == Some(std::ffi::OsStr::new("1"))
        {
            std::process::abort();
        }
    }
    record_state(TransactionPhase::PluginPublishingHelper, None)?;
    fs::rename(&staged_helper, &helper)
        .map_err(|error| ManagedError::io("generation_failed", "cannot publish helper", error))?;
    #[cfg(debug_assertions)]
    if env::var_os("HERDR_A2A_TEST_ABORT_AFTER_HELPER_PUBLISH_RENAME").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        std::process::abort();
    }
    record_state(TransactionPhase::PluginPublishingPointer, None)?;
    #[cfg(debug_assertions)]
    if env::var_os("HERDR_A2A_TEST_FAIL_POINTER_PUBLISH").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        return Err(ManagedError::io(
            "generation_failed",
            "cannot publish pointer",
            io::Error::other("injected pointer publish failure"),
        ));
    }
    fs::rename(&staged_pointer, &pointer)
        .map_err(|error| ManagedError::io("generation_failed", "cannot publish pointer", error))?;
    #[cfg(debug_assertions)]
    if env::var_os("HERDR_A2A_TEST_ABORT_AFTER_POINTER_PUBLISH_RENAME").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        std::process::abort();
    }
    sync_directory(&libexec)?;
    sync_directory(plugin_root)?;
    validate_owned_regular_file(&helper, 0o700, "generation_failed")?;
    validate_owned_regular_file(&pointer, 0o600, "generation_failed")?;
    let helper_snapshot = snapshot_owned_file(&helper, 0o700)?;
    let pointer_snapshot = snapshot_owned_file(&pointer, 0o600)?;
    let stage_snapshot = snapshot_stage(&stage)?;
    Ok(PluginSwap {
        helper,
        pointer,
        helper_backup,
        pointer_backup,
        stage_snapshot,
        helper_snapshot,
        pointer_snapshot,
    })
}

impl PluginSwap {
    fn commit(&self) -> ManagedResult<()> {
        for backup in [self.helper_backup.as_ref(), self.pointer_backup.as_ref()]
            .into_iter()
            .flatten()
        {
            remove_if_exists(backup)?;
        }
        remove_exact_stage(&self.stage_snapshot)?;
        sync_directory(self.helper.parent().unwrap())?;
        sync_directory(self.pointer.parent().unwrap())?;
        Ok(())
    }
}

fn reject_unowned_plugin_assets(plugin_root: &Path) -> ManagedResult<()> {
    for path in [
        plugin_root.join("libexec/herdr-a2a-dispatch"),
        plugin_root.join("stable-bin-path"),
    ] {
        if fs::symlink_metadata(&path).is_ok() {
            return Err(ManagedError::new(
                "ownership_conflict",
                "an unowned managed path already exists",
            ));
        }
    }
    Ok(())
}

async fn configure_install_pi(
    snapshot: PiSnapshot,
    new_source: &Path,
    old_source: Option<&Path>,
    plugin_root: &Path,
    bundle_package: &Path,
    package_digest: &str,
) -> ManagedResult<Value> {
    let new_text = path_text(new_source)?;
    let mut replaced = old_source
        .filter(|source| path_text(source).ok() != Some(new_text))
        .map(Path::to_path_buf);
    let legacy = legacy_source(plugin_root);
    let legacy_text = path_text(&legacy)?;
    let legacy_matches: Vec<&Value> = snapshot
        .entries
        .iter()
        .filter(|entry| pi_entry_source(entry) == Some(legacy_text))
        .collect();
    if old_source.is_none() && !legacy_matches.is_empty() {
        if legacy_matches.len() != 1 || legacy_matches[0] != &Value::String(legacy_text.to_owned())
        {
            return Err(ManagedError::new(
                "legacy_package_conflict",
                "legacy Pi entry is not the exact canonical string entry",
            ));
        }
        if digest_tree(&legacy)? != package_digest || digest_tree(bundle_package)? != package_digest
        {
            return Err(ManagedError::new(
                "legacy_package_conflict",
                "the legacy Pi package is not the exact approved asset",
            ));
        }
        replaced = Some(legacy);
    }

    let new_matches: Vec<&Value> = snapshot
        .entries
        .iter()
        .filter(|entry| pi_entry_matches_path(entry, &snapshot.config_path, new_source))
        .collect();
    if old_source.is_none_or(|old| old != new_source) && !new_matches.is_empty() {
        return Err(ManagedError::new(
            "ownership_conflict",
            "the managed Pi source already exists without a durable ownership record",
        ));
    }
    if new_matches.len() > 1 {
        return Err(ManagedError::new(
            "ownership_conflict",
            "Pi has duplicate entries for the managed source",
        ));
    }
    let new_present = !new_matches.is_empty();
    if !new_present
        && let Err(error) = run_pi_checked(&snapshot.program, "install", new_source).await
    {
        return Err(error);
    }
    let stored_entry = if new_present {
        authenticated_managed_pi_entry(&snapshot.entries, &snapshot.config_path, new_source)?
    } else {
        let after = read_pi_settings()?;
        if after.path != snapshot.config_path {
            return Err(ManagedError::new(
                "ownership_conflict",
                "Pi settings path changed during install",
            ));
        }
        authenticated_managed_pi_entry(&after.entries, &after.path, new_source)?
    };
    if let Some(old) = replaced.as_deref()
        && snapshot
            .entries
            .iter()
            .any(|entry| pi_entry_matches_path(entry, &snapshot.config_path, old))
        && let Err(error) = run_pi_checked(&snapshot.program, "remove", old).await
    {
        return Err(error);
    }
    Ok(stored_entry)
}

fn detect_pi() -> ManagedResult<Option<PiSnapshot>> {
    let Some(program) = find_in_path("pi") else {
        return Ok(None);
    };
    let settings = read_pi_settings()?;
    Ok(Some(PiSnapshot {
        program,
        entries: settings.entries,
        config_path: settings.path,
    }))
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    env::var_os("PATH")
        .into_iter()
        .flat_map(|value| env::split_paths(&value).collect::<Vec<_>>())
        .filter(|directory| directory.is_absolute())
        .map(|directory| directory.join(name))
        .find(|candidate| {
            fs::metadata(candidate)
                .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        })
}

fn pi_settings_location() -> ManagedResult<(PathBuf, PathBuf)> {
    let (agent_dir, boundary) = match env::var_os("PI_CODING_AGENT_DIR") {
        Some(value) if !value.is_empty() => {
            let agent_dir = require_absolute_normal(Path::new(&value), "PI_CODING_AGENT_DIR")?;
            (agent_dir.clone(), agent_dir)
        }
        _ => {
            let pi_root = required_home()?.join(".pi");
            (pi_root.join("agent"), pi_root)
        }
    };
    Ok((agent_dir.join("settings.json"), boundary))
}

fn pi_settings_path() -> ManagedResult<PathBuf> {
    pi_settings_location().map(|(path, _)| path)
}

fn read_pi_settings() -> ManagedResult<PiSettings> {
    let (settings, boundary) = pi_settings_location()?;
    match fs::symlink_metadata(&settings) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(PiSettings {
                path: settings,
                entries: Vec::new(),
            });
        }
        Err(error) => {
            return Err(ManagedError::io(
                "pi_settings_unsafe",
                "cannot inspect Pi settings path",
                error,
            ));
        }
    }
    let mut file =
        open_owned_regular_file_with_mode(&settings, &boundary, 0o600, "pi_settings_unsafe")?;
    let metadata = file.metadata().map_err(|error| {
        ManagedError::io("pi_settings_unsafe", "cannot inspect settings", error)
    })?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(ManagedError::new(
            "pi_settings_unsafe",
            "Pi settings inode is unsafe",
        ));
    }
    let value: Value = parse_bounded_opened_json(
        &mut file,
        metadata.len(),
        MAX_SETTINGS_BYTES,
        "pi_settings_invalid",
    )?;
    let packages = value
        .get("packages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for entry in &packages {
        let source = pi_entry_source(entry).ok_or_else(|| {
            ManagedError::new(
                "pi_settings_invalid",
                "Pi package entry has no valid source",
            )
        })?;
        if source.contains(['\r', '\n']) {
            return Err(ManagedError::new(
                "pi_settings_invalid",
                "Pi package source contains a line break",
            ));
        }
    }
    Ok(PiSettings {
        path: settings,
        entries: packages,
    })
}

fn pi_entry_source(entry: &Value) -> Option<&str> {
    match entry {
        Value::String(source) if !source.is_empty() => Some(source),
        Value::Object(object) => object
            .get("source")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty()),
        _ => None,
    }
}

fn managed_pi_entry(settings_path: &Path, source: &Path) -> ManagedResult<Value> {
    let base = settings_path.parent().ok_or_else(|| {
        ManagedError::new("unsafe_install_path", "Pi settings path has no parent")
    })?;
    require_absolute_normal(base, "Pi settings parent")?;
    require_absolute_normal(source, "Pi package source")?;
    let base_components = normal_components(base)?;
    let source_components = normal_components(source)?;
    let common = base_components
        .iter()
        .zip(&source_components)
        .take_while(|(left, right)| left == right)
        .count();
    let mut relative = PathBuf::new();
    for _ in common..base_components.len() {
        relative.push("..");
    }
    for component in &source_components[common..] {
        relative.push(component);
    }
    if relative.as_os_str().is_empty() {
        relative.push(".");
    }
    Ok(Value::String(path_text(&relative)?.to_owned()))
}

fn absolute_managed_pi_entry(source: &Path) -> ManagedResult<Value> {
    require_absolute_normal(source, "Pi package source")?;
    Ok(Value::String(path_text(source)?.to_owned()))
}

fn allowed_managed_pi_entries(settings_path: &Path, source: &Path) -> ManagedResult<Vec<Value>> {
    let absolute = absolute_managed_pi_entry(source)?;
    let relative = managed_pi_entry(settings_path, source)?;
    if absolute == relative {
        Ok(vec![absolute])
    } else {
        Ok(vec![absolute, relative])
    }
}

fn is_allowed_managed_pi_entry(
    entry: &Value,
    settings_path: &Path,
    source: &Path,
) -> ManagedResult<bool> {
    Ok(allowed_managed_pi_entries(settings_path, source)?
        .iter()
        .any(|allowed| allowed == entry))
}

fn authenticated_managed_pi_entry(
    entries: &[Value],
    settings_path: &Path,
    source: &Path,
) -> ManagedResult<Value> {
    let matching: Vec<&Value> = entries
        .iter()
        .filter(|entry| pi_entry_matches_path(entry, settings_path, source))
        .collect();
    if matching.len() != 1 || !is_allowed_managed_pi_entry(matching[0], settings_path, source)? {
        return Err(ManagedError::new(
            "ownership_conflict",
            "Pi did not persist one exact allowed managed package entry",
        ));
    }
    Ok(matching[0].clone())
}

fn resolve_pi_entry_path(settings_path: &Path, entry: &Value) -> ManagedResult<PathBuf> {
    let source = pi_entry_source(entry)
        .ok_or_else(|| ManagedError::new("pi_settings_invalid", "Pi entry has no source"))?;
    let source = Path::new(source);
    if source.is_absolute() {
        return require_absolute_normal(source, "Pi package entry");
    }
    let mut resolved = settings_path
        .parent()
        .ok_or_else(|| ManagedError::new("pi_settings_invalid", "Pi settings path has no parent"))?
        .to_path_buf();
    for component in source.components() {
        match component {
            Component::Normal(name) => resolved.push(name),
            Component::ParentDir => {
                if !resolved.pop() {
                    return Err(ManagedError::new(
                        "pi_settings_invalid",
                        "relative Pi package entry escapes the filesystem root",
                    ));
                }
            }
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => {
                return Err(ManagedError::new(
                    "pi_settings_invalid",
                    "relative Pi package entry is malformed",
                ));
            }
        }
    }
    require_absolute_normal(&resolved, "resolved Pi package entry")
}

fn pi_entry_matches_path(entry: &Value, settings_path: &Path, source: &Path) -> bool {
    resolve_pi_entry_path(settings_path, entry).ok().as_deref() == Some(source)
}

async fn run_pi_checked(program: &Path, operation: &str, source: &Path) -> ManagedResult<()> {
    let output = run_bounded_process(
        program,
        &[OsString::from(operation), source.as_os_str().to_owned()],
    )
    .await?;
    if !output.success {
        return Err(ManagedError::new(
            "pi_configuration_failed",
            format!("Pi {operation} command failed"),
        ));
    }
    Ok(())
}

async fn run_bounded_process(program: &Path, args: &[OsString]) -> ManagedResult<ProcessOutput> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|error| ManagedError::io("pi_configuration_failed", "cannot start Pi", error))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ManagedError::new("pi_configuration_failed", "Pi stdout is unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ManagedError::new("pi_configuration_failed", "Pi stderr is unavailable"))?;
    let execution = async {
        let (status, stdout, stderr) =
            tokio::try_join!(child.wait(), read_limited(stdout), read_limited(stderr),).map_err(
                |error| {
                    if error.kind() == io::ErrorKind::InvalidData {
                        ManagedError::new("pi_output_limit_exceeded", error.to_string())
                    } else {
                        ManagedError::io("pi_configuration_failed", "Pi I/O failed", error)
                    }
                },
            )?;
        Ok::<_, ManagedError>(ProcessOutput {
            success: status.success(),
            stdout,
            _stderr: stderr,
        })
    };
    match tokio::time::timeout(PI_TIMEOUT, execution).await {
        Ok(result) => result,
        Err(_) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            Err(ManagedError::new(
                "pi_configuration_failed",
                "Pi configuration timed out",
            ))
        }
    }
}

async fn run_herdr_bounded(
    program: &Path,
    args: &[OsString],
    unavailable_code: &'static str,
) -> ManagedResult<ProcessOutput> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|_| ManagedError::new(unavailable_code, "Herdr command could not be started"))?;
    let stdout = child.stdout.take().ok_or_else(|| {
        ManagedError::new(unavailable_code, "Herdr command stdout is unavailable")
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        ManagedError::new(unavailable_code, "Herdr command stderr is unavailable")
    })?;
    let execution = async {
        let (status, stdout, stderr) =
            tokio::try_join!(child.wait(), read_limited(stdout), read_limited(stderr),).map_err(
                |_| ManagedError::new(unavailable_code, "Herdr command output is unavailable"),
            )?;
        Ok::<_, ManagedError>(ProcessOutput {
            success: status.success(),
            stdout,
            _stderr: stderr,
        })
    };
    match tokio::time::timeout(PI_TIMEOUT, execution).await {
        Ok(result) => result,
        Err(_) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            Err(ManagedError::new(
                unavailable_code,
                "Herdr command timed out",
            ))
        }
    }
}

async fn read_limited(mut reader: impl tokio::io::AsyncRead + Unpin) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            return Ok(output);
        }
        if output.len().saturating_add(read) > MAX_PROCESS_OUTPUT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Pi process output exceeded 65536 bytes",
            ));
        }
        output.extend_from_slice(&buffer[..read]);
    }
}

async fn extract_release_inner(archive: &Path, destination: &Path) -> ManagedResult<()> {
    let archive = require_absolute_normal(archive, "release archive")?;
    let destination = require_absolute_normal(destination, "release destination")?;
    validate_external_file(&archive, false)?;
    if destination.exists() {
        return Err(ManagedError::new(
            "archive_invalid",
            "release destination already exists",
        ));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| ManagedError::new("archive_invalid", "release destination has no parent"))?;
    validate_private_directory(parent, 0o700)?;

    let mut child = Command::new("gzip")
        .args([OsString::from("-dc"), archive.as_os_str().to_owned()])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| ManagedError::io("archive_invalid", "cannot start gzip", error))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ManagedError::new("archive_invalid", "gzip stdout unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ManagedError::new("archive_invalid", "gzip stderr unavailable"))?;
    let execution = async {
        let (status, expanded, _stderr) = tokio::try_join!(
            child.wait(),
            read_limited_to(stdout, MAX_ARCHIVE_EXPANDED_BYTES),
            read_limited_to(stderr, MAX_PROCESS_OUTPUT),
        )
        .map_err(|error| ManagedError::new("archive_invalid", error.to_string()))?;
        if !status.success() {
            return Err(ManagedError::new(
                "archive_invalid",
                "gzip rejected the release archive",
            ));
        }
        Ok(expanded)
    };
    let expanded = tokio::time::timeout(PI_TIMEOUT, execution)
        .await
        .map_err(|_| ManagedError::new("archive_invalid", "release decompression timed out"))??;
    extract_validated_tar(&expanded, &destination)
}

async fn read_limited_to(
    mut reader: impl tokio::io::AsyncRead + Unpin,
    limit: usize,
) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            return Ok(output);
        }
        if output.len().saturating_add(read) > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expanded archive exceeds limit",
            ));
        }
        output.extend_from_slice(&buffer[..read]);
    }
}

fn extract_validated_tar(bytes: &[u8], destination: &Path) -> ManagedResult<()> {
    let expected: [(&str, bool, u32); 18] = [
        ("bin/", true, 0o700),
        ("bin/herdr-a2a", false, 0o700),
        ("metadata/", true, 0o700),
        ("metadata/ownership-template.json", false, 0o600),
        ("pi/", true, 0o700),
        ("pi/extensions/", true, 0o700),
        ("pi/extensions/herdr-a2a.ts", false, 0o600),
        ("pi/package.json", false, 0o600),
        ("pi/src/", true, 0o700),
        ("pi/src/inbox-pump.ts", false, 0o600),
        ("pi/src/session-client.ts", false, 0o600),
        ("pi/src/team-command.ts", false, 0o600),
        ("pi/skills/", true, 0o700),
        ("pi/skills/herdr-a2a/", true, 0o700),
        ("pi/skills/herdr-a2a/SKILL.md", false, 0o600),
        ("scripts/", true, 0o700),
        ("scripts/dispatch.sh", false, 0o700),
        ("scripts/uninstall.sh", false, 0o600),
    ];
    let expected_map: std::collections::BTreeMap<_, _> = expected
        .iter()
        .map(|(name, directory, mode)| ((*name).to_owned(), (*directory, *mode)))
        .collect();
    let mut seen = BTreeSet::new();
    let mut entries: Vec<(String, bool, u32, &[u8])> = Vec::new();
    let mut offset = 0usize;
    let mut terminated = false;
    while offset + 512 <= bytes.len() {
        let header = &bytes[offset..offset + 512];
        if header.iter().all(|byte| *byte == 0) {
            let second_end = offset.checked_add(1024).ok_or_else(|| {
                ManagedError::new("archive_invalid", "archive end offset overflow")
            })?;
            if second_end > bytes.len()
                || bytes[offset + 512..second_end]
                    .iter()
                    .any(|byte| *byte != 0)
                || bytes[second_end..].iter().any(|byte| *byte != 0)
            {
                return Err(ManagedError::new(
                    "archive_invalid",
                    "release archive requires two zero end blocks and zero-only remainder",
                ));
            }
            terminated = true;
            break;
        }
        if entries.len() >= MAX_ARCHIVE_ENTRIES {
            return Err(ManagedError::new(
                "archive_invalid",
                "release archive has too many entries",
            ));
        }
        let stored_checksum = parse_tar_octal(&header[148..156])?;
        let actual_checksum: u64 = header
            .iter()
            .enumerate()
            .map(|(index, byte)| {
                if (148..156).contains(&index) {
                    b' ' as u64
                } else {
                    *byte as u64
                }
            })
            .sum();
        if stored_checksum != actual_checksum {
            return Err(ManagedError::new(
                "archive_invalid",
                "release archive header checksum is invalid",
            ));
        }
        let name = parse_tar_name(header)?;
        let Some((directory, expected_mode)) = expected_map.get(&name).copied() else {
            return Err(ManagedError::new(
                "archive_invalid",
                "release archive contains an unexpected entry",
            ));
        };
        if !seen.insert(name.clone()) {
            return Err(ManagedError::new(
                "archive_invalid",
                "release archive contains a duplicate entry",
            ));
        }
        let mode = parse_tar_octal(&header[100..108])? as u32 & 0o777;
        let size = usize::try_from(parse_tar_octal(&header[124..136])?).map_err(|_| {
            ManagedError::new("archive_invalid", "release entry size is unrepresentable")
        })?;
        let typeflag = header[156];
        if (directory && (typeflag != b'5' || size != 0))
            || (!directory && typeflag != b'0' && typeflag != 0)
            || mode != expected_mode
        {
            return Err(ManagedError::new(
                "archive_invalid",
                "release archive entry has an unsafe type, size, or mode",
            ));
        }
        let data_start = offset
            .checked_add(512)
            .ok_or_else(|| ManagedError::new("archive_invalid", "archive offset overflow"))?;
        let data_end = data_start
            .checked_add(size)
            .ok_or_else(|| ManagedError::new("archive_invalid", "archive size overflow"))?;
        if data_end > bytes.len() {
            return Err(ManagedError::new(
                "archive_invalid",
                "truncated release entry",
            ));
        }
        entries.push((name, directory, mode, &bytes[data_start..data_end]));
        let padded = size
            .checked_add(511)
            .ok_or_else(|| ManagedError::new("archive_invalid", "archive padding overflow"))?
            / 512
            * 512;
        offset = data_start
            .checked_add(padded)
            .ok_or_else(|| ManagedError::new("archive_invalid", "archive offset overflow"))?;
    }
    if !terminated {
        return Err(ManagedError::new(
            "archive_invalid",
            "release archive has no complete two-block end marker",
        ));
    }
    if seen.len() != expected_map.len() || seen.iter().ne(expected_map.keys()) {
        return Err(ManagedError::new(
            "archive_invalid",
            "release archive manifest is incomplete",
        ));
    }
    fs::create_dir(destination).map_err(|error| {
        ManagedError::io(
            "archive_invalid",
            "cannot create release destination",
            error,
        )
    })?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700)).map_err(|error| {
        ManagedError::io(
            "archive_invalid",
            "cannot protect release destination",
            error,
        )
    })?;
    for (name, directory, mode, data) in entries {
        let target = destination.join(name.trim_end_matches('/'));
        if directory {
            fs::create_dir(&target).map_err(|error| {
                ManagedError::io("archive_invalid", "cannot create release directory", error)
            })?;
            fs::set_permissions(&target, fs::Permissions::from_mode(mode)).map_err(|error| {
                ManagedError::io("archive_invalid", "cannot protect release directory", error)
            })?;
        } else {
            write_new_file(&target, data, mode)?;
        }
    }
    sync_tree(destination)?;
    validate_external_file(&destination.join("bin/herdr-a2a"), true)?;
    validate_external_tree(&destination.join("pi"))
}

fn parse_tar_octal(field: &[u8]) -> ManagedResult<u64> {
    let text = std::str::from_utf8(field)
        .map_err(|_| ManagedError::new("archive_invalid", "tar numeric field is not UTF-8"))?
        .trim_matches(['\0', ' ']);
    if text.is_empty() || !text.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
        return Err(ManagedError::new(
            "archive_invalid",
            "tar numeric field is not canonical octal",
        ));
    }
    u64::from_str_radix(text, 8)
        .map_err(|_| ManagedError::new("archive_invalid", "tar numeric field overflow"))
}

fn parse_tar_name(header: &[u8]) -> ManagedResult<String> {
    fn field(bytes: &[u8]) -> ManagedResult<&str> {
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        if bytes[end..].iter().any(|byte| *byte != 0) {
            return Err(ManagedError::new(
                "archive_invalid",
                "tar string has data after NUL",
            ));
        }
        std::str::from_utf8(&bytes[..end])
            .map_err(|_| ManagedError::new("archive_invalid", "tar path is not UTF-8"))
    }
    let name = field(&header[..100])?;
    let prefix = field(&header[345..500])?;
    let combined = if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}/{name}")
    };
    if combined.is_empty()
        || combined.starts_with('/')
        || combined.contains("//")
        || combined.contains(['\r', '\n'])
        || combined.split('/').any(|part| part == "." || part == "..")
    {
        return Err(ManagedError::new(
            "archive_invalid",
            "tar path is not normalized and relative",
        ));
    }
    Ok(combined)
}

fn event_is_pi() -> ManagedResult<bool> {
    let encoded = env::var("HERDR_PLUGIN_EVENT_JSON").map_err(|_| {
        ManagedError::new(
            "invalid_plugin_event",
            "HERDR_PLUGIN_EVENT_JSON is required for event repair",
        )
    })?;
    if encoded.len() > MAX_EVENT_BYTES {
        return Err(ManagedError::new(
            "invalid_plugin_event",
            "plugin event exceeds 65536 bytes",
        ));
    }
    let value: Value = serde_json::from_str(&encoded)
        .map_err(|error| ManagedError::new("invalid_plugin_event", error.to_string()))?;
    let pane = value.get("pane").unwrap_or(&value);
    let kind = ["agent_kind", "harness", "kind", "agent"]
        .into_iter()
        .find_map(|field| pane.get(field).and_then(Value::as_str));
    Ok(kind == Some("pi"))
}

fn read_record_optional(stable_root: &Path) -> ManagedResult<Option<OwnershipRecord>> {
    let path = stable_root.join(OWNERSHIP_FILE);
    if !path.exists() {
        return Ok(None);
    }
    read_record(stable_root).map(Some)
}

fn read_record(stable_root: &Path) -> ManagedResult<OwnershipRecord> {
    let path = stable_root.join(OWNERSHIP_FILE);
    let mut file = open_validated_absolute_file(&path)?;
    let metadata = validate_opened_owned_regular_file(&file, 0o600, "ownership_record_invalid")?;
    let record: CompatibleOwnershipRecord = parse_bounded_opened_json(
        &mut file,
        metadata.len(),
        MAX_RECORD_BYTES,
        "ownership_record_invalid",
    )?;
    record.try_into()
}

fn migrate_accepted_v2_record(
    stable_root: &Path,
    record: &mut OwnershipRecord,
) -> ManagedResult<()> {
    if record.schema_version != 2 || !record.purge_authority {
        return Ok(());
    }
    validate_record(record, stable_root)?;
    validate_pi_entry_if_present(record)?;
    record.schema_version = OWNERSHIP_SCHEMA;
    write_record(stable_root, record)
}

fn write_record(stable_root: &Path, record: &OwnershipRecord) -> ManagedResult<()> {
    write_record_with_validation(stable_root, record, false)
}

fn write_record_with_validation(
    stable_root: &Path,
    record: &OwnershipRecord,
    allow_missing_assets: bool,
) -> ManagedResult<()> {
    #[cfg(debug_assertions)]
    if env::var_os("HERDR_A2A_TEST_FAIL_BEFORE_RECORD_COMMIT").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        return Err(ManagedError::new(
            "ownership_commit_failed",
            "injected failure before ownership commit",
        ));
    }
    let path = stable_root.join(OWNERSHIP_FILE);
    let temporary = stable_root.join(format!(".ownership-{}", random_hex()?));
    let encoded = serialize_ownership_record(record, "ownership_record_invalid")?;
    write_new_file(&temporary, &encoded, 0o600)?;
    fs::rename(&temporary, &path).map_err(|error| {
        ManagedError::io(
            "ownership_commit_failed",
            "cannot commit ownership record",
            error,
        )
    })?;
    #[cfg(debug_assertions)]
    if env::var_os("HERDR_A2A_TEST_ABORT_AFTER_RECORD_RENAME").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        std::process::abort();
    }
    #[cfg(debug_assertions)]
    if env::var_os("HERDR_A2A_TEST_FAIL_AFTER_RECORD_RENAME").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        return Err(ManagedError::new(
            "ownership_commit_failed",
            "injected failure after ownership rename",
        ));
    }
    sync_directory(stable_root)?;
    #[cfg(debug_assertions)]
    if env::var_os("HERDR_A2A_TEST_FAIL_AFTER_RECORD_DIR_SYNC").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        return Err(ManagedError::new(
            "ownership_commit_failed",
            "injected failure after ownership directory sync",
        ));
    }
    validate_owned_regular_file(&path, 0o600, "ownership_commit_failed")?;
    if matches!(
        record.state,
        InstallState::Removing
            | InstallState::UnregisterPending
            | InstallState::Unregistering
            | InstallState::FinalizingRemoval
            | InstallState::Removed
    ) || allow_missing_assets
    {
        validate_record_semantics(record, stable_root, &record.plugin_root)
            .map_err(|error| ManagedError::new("ownership_commit_failed", error.to_string()))
    } else {
        validate_record(record, stable_root)
    }
}

fn read_transaction(stable_root: &Path) -> ManagedResult<Option<InstallTransaction>> {
    let path = stable_root.join(TRANSACTION_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let mut file = open_validated_absolute_file(&path)?;
    let metadata = validate_opened_owned_regular_file(&file, 0o600, "recovery_needed")?;
    let mut transaction: InstallTransaction = parse_bounded_opened_json(
        &mut file,
        metadata.len(),
        MAX_TRANSACTION_BYTES,
        "recovery_needed",
    )?;
    if !matches!(
        transaction.schema_version,
        LEGACY_TRANSACTION_SCHEMA | TRANSACTION_SCHEMA
    ) {
        return Err(ManagedError::new(
            "recovery_needed",
            "unsupported install transaction schema",
        ));
    }
    normalize_legacy_pi_transaction(&mut transaction)?;
    validate_transaction_semantics(stable_root, &transaction)?;
    Ok(Some(transaction))
}

fn normalize_legacy_pi_transaction(transaction: &mut InstallTransaction) -> ManagedResult<()> {
    let source = transaction.generation.join("pi");
    let expected = managed_pi_entry(&transaction.pi_config_path, &source)?;
    let legacy = Value::String(path_text(&source)?.to_owned());
    if transaction.new_pi_entry == legacy {
        match (&transaction.phase, &transaction.new_record) {
            (TransactionPhase::PiMutating, None) => {
                transaction.new_pi_entry = expected;
            }
            (TransactionPhase::PiMutated, None)
            | (
                TransactionPhase::RescuePublishing
                | TransactionPhase::RecordCommitting
                | TransactionPhase::RecordRenaming
                | TransactionPhase::RecordCommitted,
                Some(_),
            ) => {}
            _ => {
                return Err(ManagedError::new(
                    "recovery_needed",
                    "legacy absolute Pi entry is invalid for the transaction phase",
                ));
            }
        }
    }
    Ok(())
}

fn validate_transaction_semantics(
    stable_root: &Path,
    transaction: &InstallTransaction,
) -> ManagedResult<()> {
    let plugin_root = required_plugin_root()?;
    validate_private_directory(&plugin_root, 0o700)?;
    for path in [
        &transaction.generation,
        &transaction.generation_stage,
        &transaction.plugin_stage,
        &transaction.helper,
        &transaction.pointer,
        &transaction.helper_backup,
        &transaction.pointer_backup,
        &transaction.pi_config_path,
    ] {
        require_absolute_normal(path, "transaction path")?;
        path_text(path)?;
    }
    let generations = stable_root.join("generations");
    let expected_generation_name = &sha256_bytes(
        format!(
            "{}\0{}",
            transaction.broker_digest, transaction.pi_package_digest
        )
        .as_bytes(),
    )[..32];
    if transaction.generation.parent() != Some(generations.as_path())
        || transaction.generation.file_name()
            != Some(std::ffi::OsStr::new(expected_generation_name))
        || transaction.generation_stage.parent() != Some(generations.as_path())
        || !transaction
            .generation_stage
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with(".stage-"))
        || transaction.plugin_stage.parent() != Some(plugin_root.as_path())
        || transaction.helper != plugin_root.join("libexec/herdr-a2a-dispatch")
        || transaction.pointer != plugin_root.join("stable-bin-path")
        || transaction.helper_backup.parent() != transaction.helper.parent()
        || transaction.pointer_backup.parent() != Some(plugin_root.as_path())
        || transaction.pi_config_path != pi_settings_path()?
        || !valid_digest(&transaction.broker_digest)
        || !valid_digest(&transaction.pi_package_digest)
    {
        return Err(ManagedError::new(
            "recovery_needed",
            "transaction path relationships are invalid",
        ));
    }
    let token = transaction
        .plugin_stage
        .file_name()
        .unwrap()
        .to_string_lossy()
        .strip_prefix(".managed-stage-")
        .ok_or_else(|| {
            ManagedError::new(
                "recovery_needed",
                "transaction plugin stage name is invalid",
            )
        })?
        .to_owned();
    if token.len() != 32
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ManagedError::new(
            "recovery_needed",
            "transaction token is not authenticated",
        ));
    }
    if transaction.generation_stage.file_name().unwrap()
        != std::ffi::OsStr::new(&format!(".stage-{token}"))
        || transaction.helper_backup.file_name().unwrap()
            != std::ffi::OsStr::new(&format!(".herdr-a2a-backup-{token}"))
        || transaction.pointer_backup.file_name().unwrap()
            != std::ffi::OsStr::new(&format!(".stable-bin-backup-{token}"))
    {
        return Err(ManagedError::new(
            "recovery_needed",
            "transaction token relationships are invalid",
        ));
    }
    let mut generation_files = BTreeSet::new();
    for path in &transaction.generation_files {
        require_absolute_normal(path, "transaction generation file")?;
        path_text(path)?;
        if !path.starts_with(&transaction.generation) || !generation_files.insert(path.clone()) {
            return Err(ManagedError::new(
                "recovery_needed",
                "transaction generation enumeration escapes or is duplicated",
            ));
        }
    }
    if !generation_files.contains(&transaction.generation.join("bin/herdr-a2a"))
        || !generation_files.contains(&transaction.generation.join("pi/package.json"))
    {
        return Err(ManagedError::new(
            "recovery_needed",
            "transaction generation enumeration is incomplete",
        ));
    }
    if let Some(snapshot) = &transaction.generation_stage_snapshot {
        validate_stage_snapshot_semantics(&transaction.generation_stage, snapshot)?;
        let staged_files: BTreeSet<PathBuf> = snapshot
            .files
            .iter()
            .map(|file| {
                file.path
                    .strip_prefix(&transaction.generation_stage)
                    .map(|relative| transaction.generation.join(relative))
                    .map_err(|_| {
                        ManagedError::new(
                            "recovery_needed",
                            "transaction generation stage file escapes",
                        )
                    })
            })
            .collect::<ManagedResult<_>>()?;
        for file in &snapshot.files {
            let relative = file
                .path
                .strip_prefix(&transaction.generation_stage)
                .unwrap();
            let expected_mode = if relative == Path::new("bin/herdr-a2a") {
                0o700
            } else {
                0o600
            };
            if file.mode != expected_mode {
                return Err(ManagedError::new(
                    "recovery_needed",
                    "transaction generation stage file mode is invalid",
                ));
            }
        }
        let mut expected_directories = BTreeSet::from([transaction.generation_stage.clone()]);
        for file in &snapshot.files {
            let mut parent = file.path.parent();
            while let Some(directory) = parent {
                if !directory.starts_with(&transaction.generation_stage) {
                    break;
                }
                expected_directories.insert(directory.to_path_buf());
                parent = directory.parent();
            }
        }
        let staged_directories: BTreeSet<PathBuf> = snapshot
            .directories
            .iter()
            .map(|directory| directory.path.clone())
            .collect();
        if !transaction.generation_created
            || staged_files != generation_files
            || staged_directories != expected_directories
        {
            return Err(ManagedError::new(
                "recovery_needed",
                "transaction generation stage inventory is not phase-exact",
            ));
        }
    }
    if let Some(snapshot) = &transaction.plugin_stage_snapshot {
        validate_stage_snapshot_semantics(&transaction.plugin_stage, snapshot)?;
        let paths: BTreeSet<&Path> = snapshot
            .directories
            .iter()
            .map(|directory| directory.path.as_path())
            .collect();
        let staged_libexec = transaction.plugin_stage.join("libexec");
        let expected =
            BTreeSet::from([transaction.plugin_stage.as_path(), staged_libexec.as_path()]);
        let residual_inventory = snapshot.files.is_empty() && paths == expected;
        let staged_helper = transaction.plugin_stage.join("libexec/herdr-a2a-dispatch");
        let staged_pointer = transaction.plugin_stage.join("stable-bin-path");
        let stable_binary = transaction.generation.join("bin/herdr-a2a");
        let pointer_digest = sha256_bytes(format!("{}\n", path_text(&stable_binary)?).as_bytes());
        let full_inventory = paths == expected
            && snapshot.files.len() == 2
            && snapshot.files.iter().any(|file| {
                file.path == staged_helper
                    && file.mode == 0o700
                    && file.sha256 == transaction.broker_digest
            })
            && snapshot.files.iter().any(|file| {
                file.path == staged_pointer && file.mode == 0o600 && file.sha256 == pointer_digest
            });
        let valid_for_phase = if matches!(
            transaction.phase,
            TransactionPhase::PluginPublishing
                | TransactionPhase::PluginBackingUpHelper
                | TransactionPhase::PluginBackingUpPointer
                | TransactionPhase::PluginPublishingHelper
                | TransactionPhase::PluginPublishingPointer
        ) {
            full_inventory
        } else {
            residual_inventory
        };
        if !valid_for_phase {
            return Err(ManagedError::new(
                "recovery_needed",
                "transaction plugin stage inventory is not phase-exact",
            ));
        }
    }
    let phase_requires_new_record = matches!(
        transaction.phase,
        TransactionPhase::RescuePublishing
            | TransactionPhase::RecordCommitting
            | TransactionPhase::RecordRenaming
            | TransactionPhase::RecordCommitted
    );
    if transaction.new_record.is_some() != phase_requires_new_record {
        return Err(ManagedError::new(
            "recovery_needed",
            "transaction phase and new record are inconsistent",
        ));
    }
    let prior_with_rescue = transaction
        .prior_record
        .as_ref()
        .filter(|record| record.state != InstallState::Removed);
    match (
        &transaction.prior_rescue_notice,
        &transaction.prior_rescue_marker,
    ) {
        (None, None) => {
            if transaction.phase == TransactionPhase::RescuePublishing
                && prior_with_rescue.is_some()
            {
                return Err(ManagedError::new(
                    "recovery_needed",
                    "rescue publication transaction has no prior rescue snapshot",
                ));
            }
        }
        (Some(notice), Some(marker_bytes)) => {
            let prior = prior_with_rescue.ok_or_else(|| {
                ManagedError::new(
                    "recovery_needed",
                    "transaction rescue snapshot has no live prior ownership",
                )
            })?;
            if !phase_requires_new_record
                || notice.len() > MAX_EVENT_BYTES
                || marker_bytes.len() > MAX_EVENT_BYTES
            {
                return Err(ManagedError::new(
                    "recovery_needed",
                    "transaction rescue snapshot is invalid for its phase or size",
                ));
            }
            let rescue = stable_root.join(RESCUE_DIRECTORY).join("uninstall.sh");
            let marker = stable_root.join(RESCUE_DIRECTORY).join(RESCUE_MARKER);
            let prior_rescue = record_owned_file(prior, &rescue).ok_or_else(|| {
                ManagedError::new("recovery_needed", "prior record has no rescue notice")
            })?;
            let prior_marker = record_owned_file(prior, &marker).ok_or_else(|| {
                ManagedError::new("recovery_needed", "prior record has no rescue marker")
            })?;
            if prior_rescue.mode != 0o600
                || prior_marker.mode != 0o600
                || sha256_bytes(notice) != prior_rescue.sha256
                || !prior_rescue_marker_is_authenticated(prior, prior_marker, marker_bytes)
            {
                return Err(ManagedError::new(
                    "recovery_needed",
                    "transaction prior rescue snapshot is not authenticated",
                ));
            }
        }
        _ => {
            return Err(ManagedError::new(
                "recovery_needed",
                "transaction prior rescue snapshot is incomplete",
            ));
        }
    }
    if matches!(
        transaction.phase,
        TransactionPhase::Intent
            | TransactionPhase::GenerationPublishing
            | TransactionPhase::GenerationPublished
    ) && transaction.plugin_stage_snapshot.is_some()
    {
        return Err(ManagedError::new(
            "recovery_needed",
            "transaction phase and plugin stage snapshot are inconsistent",
        ));
    }
    let generation_snapshot_allowed = match transaction.phase {
        TransactionPhase::Intent => transaction.generation_stage_snapshot.is_none(),
        TransactionPhase::GenerationPublishing if transaction.generation_created => true,
        _ if transaction.generation_created => transaction.generation_stage_snapshot.is_some(),
        _ => transaction.generation_stage_snapshot.is_none(),
    };
    if !generation_snapshot_allowed {
        return Err(ManagedError::new(
            "recovery_needed",
            "transaction generation snapshot is inconsistent with its phase and provenance",
        ));
    }
    let pointer_digest = sha256_bytes(
        format!(
            "{}\n",
            path_text(&transaction.generation.join("bin/herdr-a2a"))?
        )
        .as_bytes(),
    );
    if let Some(record) = &transaction.prior_record {
        validate_record_semantics(record, stable_root, &plugin_root)?;
        if record.state == InstallState::Removed {
            if transaction.prior_generation_snapshot.is_some()
                || transaction.prior_helper_present
                || transaction.prior_pointer_present
                || transaction.prior_helper_snapshot.is_some()
                || transaction.prior_pointer_snapshot.is_some()
                || transaction.prior_owned_pi_entry.is_some()
            {
                return Err(ManagedError::new(
                    "recovery_needed",
                    "removed prior ownership claims live assets",
                ));
            }
        } else {
            let prior_generation_snapshot = transaction
                .prior_generation_snapshot
                .as_ref()
                .ok_or_else(|| {
                    ManagedError::new(
                        "recovery_needed",
                        "transaction has no authenticated prior generation snapshot",
                    )
                })?;
            validate_prior_generation_snapshot_semantics(record, prior_generation_snapshot)?;
            if !transaction.prior_helper_present
                || !transaction.prior_pointer_present
                || validate_owned_snapshot_semantics(
                    transaction.prior_helper_snapshot.as_ref(),
                    &transaction.helper,
                    0o700,
                    &record.broker_digest,
                )
                .is_err()
                || validate_owned_snapshot_semantics(
                    transaction.prior_pointer_snapshot.as_ref(),
                    &transaction.pointer,
                    0o600,
                    record_owned_file(record, &transaction.pointer)
                        .map(|owned| owned.sha256.as_str())
                        .unwrap_or(""),
                )
                .is_err()
                || transaction.prior_owned_pi_entry.as_ref() != Some(&record.pi_package_entry)
            {
                return Err(ManagedError::new(
                    "recovery_needed",
                    "transaction prior ownership relationships are invalid",
                ));
            }
        }
    } else if transaction.prior_helper_present
        || transaction.prior_pointer_present
        || transaction.prior_helper_snapshot.is_some()
        || transaction.prior_pointer_snapshot.is_some()
        || transaction.prior_generation_snapshot.is_some()
    {
        return Err(ManagedError::new(
            "recovery_needed",
            "first-install transaction claims prior plugin assets",
        ));
    }
    let phase_requires_new_snapshots = !matches!(
        transaction.phase,
        TransactionPhase::Intent
            | TransactionPhase::GenerationPublishing
            | TransactionPhase::GenerationPublished
            | TransactionPhase::PluginPublishing
            | TransactionPhase::PluginBackingUpHelper
            | TransactionPhase::PluginBackingUpPointer
            | TransactionPhase::PluginPublishingHelper
            | TransactionPhase::PluginPublishingPointer
    );
    if transaction.new_helper_snapshot.is_some() != phase_requires_new_snapshots
        || transaction.new_pointer_snapshot.is_some() != phase_requires_new_snapshots
        || (phase_requires_new_snapshots
            && (validate_owned_snapshot_semantics(
                transaction.new_helper_snapshot.as_ref(),
                &transaction.helper,
                0o700,
                &transaction.broker_digest,
            )
            .is_err()
                || validate_owned_snapshot_semantics(
                    transaction.new_pointer_snapshot.as_ref(),
                    &transaction.pointer,
                    0o600,
                    &pointer_digest,
                )
                .is_err()))
    {
        return Err(ManagedError::new(
            "recovery_needed",
            "transaction plugin inode snapshots are inconsistent",
        ));
    }
    if let Some(prior_owned) = &transaction.prior_owned_pi_entry {
        pi_entry_source(prior_owned).ok_or_else(|| {
            ManagedError::new(
                "recovery_needed",
                "transaction prior Pi entry has no source",
            )
        })?;
        let count = transaction
            .prior_pi_entries
            .iter()
            .filter(|entry| *entry == prior_owned)
            .count();
        if count != 1
            || (transaction.prior_record.is_none()
                && prior_owned
                    != &Value::String(path_text(&legacy_source(&plugin_root))?.to_owned()))
        {
            return Err(ManagedError::new(
                "recovery_needed",
                "transaction prior Pi ownership is invalid",
            ));
        }
    }
    let new_source_path = transaction.generation.join("pi");
    if !is_allowed_managed_pi_entry(
        &transaction.new_pi_entry,
        &transaction.pi_config_path,
        &new_source_path,
    )? {
        return Err(ManagedError::new(
            "recovery_needed",
            "transaction new Pi entry does not name its generation",
        ));
    }
    for entry in &transaction.prior_pi_entries {
        let source = pi_entry_source(entry).ok_or_else(|| {
            ManagedError::new("recovery_needed", "transaction prior Pi entry is invalid")
        })?;
        if source.contains(['\r', '\n']) {
            return Err(ManagedError::new(
                "recovery_needed",
                "transaction prior Pi source contains a line break",
            ));
        }
    }
    if let Some(record) = &transaction.new_record {
        validate_record_semantics(record, stable_root, &plugin_root)?;
        let record_generation_files: BTreeSet<PathBuf> = record
            .owned_files
            .iter()
            .map(|owned| owned.path.clone())
            .filter(|path| path.starts_with(&transaction.generation))
            .collect();
        if record.broker_digest != transaction.broker_digest
            || record.pi_package_digest != transaction.pi_package_digest
            || record.stable_binary != transaction.generation.join("bin/herdr-a2a")
            || record.pi_package_source != transaction.generation.join("pi")
            || record.pi_package_entry != transaction.new_pi_entry
            || record_generation_files != generation_files
        {
            return Err(ManagedError::new(
                "recovery_needed",
                "transaction new record does not match its planned generation",
            ));
        }
    }
    let has_authoritative_v2_endpoint = [&transaction.prior_record, &transaction.new_record]
        .into_iter()
        .flatten()
        .any(|record| record.schema_version == 2 && record.purge_authority);
    if has_authoritative_v2_endpoint
        && !authoritative_v2_transaction_endpoints_are_exact_migration(
            transaction.prior_record.as_ref(),
            transaction.new_record.as_ref(),
        )
    {
        return Err(ManagedError::new(
            "recovery_needed",
            "authoritative schema v2 transaction records are not an exact schema v3 migration",
        ));
    }
    Ok(())
}

fn authoritative_v2_transaction_endpoints_are_exact_migration(
    prior: Option<&OwnershipRecord>,
    current: Option<&OwnershipRecord>,
) -> bool {
    let (Some(prior), Some(current)) = (prior, current) else {
        return false;
    };
    exact_schema_v2_to_v3_migration_adjacency(prior, current)
}

fn exact_schema_v2_to_v3_migration_adjacency(
    prior: &OwnershipRecord,
    current: &OwnershipRecord,
) -> bool {
    if prior.schema_version != 2
        || !prior.purge_authority
        || current.schema_version != OWNERSHIP_SCHEMA
    {
        return false;
    }
    let mut expected = prior.clone();
    expected.schema_version = OWNERSHIP_SCHEMA;
    expected == *current
}

fn write_transaction(stable_root: &Path, transaction: &InstallTransaction) -> ManagedResult<()> {
    let path = stable_root.join(TRANSACTION_FILE);
    let temporary = stable_root.join(format!(".transaction-{}", random_hex()?));
    let bytes = serde_json::to_vec_pretty(transaction)
        .map_err(|error| ManagedError::new("recovery_needed", error.to_string()))?;
    write_new_file(&temporary, &bytes, 0o600)?;
    fs::rename(&temporary, &path).map_err(|error| {
        ManagedError::io(
            "recovery_needed",
            "cannot publish install transaction",
            error,
        )
    })?;
    sync_directory(stable_root)?;
    validate_owned_regular_file(&path, 0o600, "recovery_needed")
}

fn clear_transaction(stable_root: &Path) -> ManagedResult<()> {
    remove_if_exists(&stable_root.join(TRANSACTION_FILE))?;
    sync_directory(stable_root)
}

async fn rollback_transaction_error<T>(
    stable_root: &Path,
    original: ManagedError,
) -> ManagedResult<T> {
    match reconcile_transaction(stable_root).await {
        Ok(()) => Err(original),
        Err(rollback) => Err(ManagedError::new(
            "recovery_needed",
            format!("{original}; rollback remains incomplete: {rollback}"),
        )),
    }
}

fn validate_transaction_recovery_state(
    stable_root: &Path,
    transaction: &InstallTransaction,
) -> ManagedResult<()> {
    validate_live_record_state(stable_root, transaction)?;
    validate_live_generation_state(transaction)?;
    validate_live_plugin_state(transaction)?;
    validate_live_pi_state(transaction)?;
    Ok(())
}

fn validate_live_record_state(
    stable_root: &Path,
    transaction: &InstallTransaction,
) -> ManagedResult<()> {
    let current = read_record_optional(stable_root)?;
    let allowed = match transaction.phase {
        TransactionPhase::RecordCommitted => current.as_ref() == transaction.new_record.as_ref(),
        TransactionPhase::RecordCommitting if is_predecessor_forward_commit(transaction) => {
            current.as_ref() == transaction.prior_record.as_ref()
                || current.as_ref() == transaction.new_record.as_ref()
        }
        TransactionPhase::RecordRenaming => {
            current.as_ref() == transaction.prior_record.as_ref()
                || current.as_ref() == transaction.new_record.as_ref()
        }
        _ => current.as_ref() == transaction.prior_record.as_ref(),
    };
    if !allowed {
        return Err(ManagedError::new(
            "recovery_needed",
            "live ownership record is not an exact state allowed by the transaction phase",
        ));
    }
    Ok(())
}

fn validate_live_generation_state(transaction: &InstallTransaction) -> ManagedResult<()> {
    if transaction.generation_stage.exists() {
        let snapshot = transaction
            .generation_stage_snapshot
            .as_ref()
            .ok_or_else(|| {
                ManagedError::new(
                    "recovery_needed",
                    "an unauthenticated generation stage is present",
                )
            })?;
        if transaction.phase != TransactionPhase::GenerationPublishing
            || transaction.generation.exists()
        {
            return Err(ManagedError::new(
                "recovery_needed",
                "generation stage is not allowed for the transaction phase",
            ));
        }
        validate_stage_snapshot_live(&transaction.generation_stage, snapshot)?;
        if digest_file(&transaction.generation_stage.join("bin/herdr-a2a"))?
            != transaction.broker_digest
            || digest_tree(&transaction.generation_stage.join("pi"))?
                != transaction.pi_package_digest
        {
            return Err(ManagedError::new(
                "recovery_needed",
                "generation stage content does not match the transaction digests",
            ));
        }
        return validate_prior_generation_state(transaction);
    }
    let present = fs::symlink_metadata(&transaction.generation).is_ok();
    let may_be_absent = matches!(
        transaction.phase,
        TransactionPhase::Intent | TransactionPhase::GenerationPublishing
    ) && transaction.generation_created;
    if !present {
        if may_be_absent {
            return validate_prior_generation_state(transaction);
        }
        return Err(ManagedError::new(
            "recovery_needed",
            "planned generation is absent for the transaction phase",
        ));
    }
    validate_private_directory(&transaction.generation, 0o700)?;
    let mut expected = transaction.generation_files.clone();
    expected.sort();
    if tree_files(&transaction.generation)? != expected
        || digest_file(&transaction.generation.join("bin/herdr-a2a"))? != transaction.broker_digest
        || digest_tree(&transaction.generation.join("pi"))? != transaction.pi_package_digest
    {
        return Err(ManagedError::new(
            "recovery_needed",
            "planned generation is not the exact transaction generation",
        ));
    }
    for file in expected {
        let mode = if file == transaction.generation.join("bin/herdr-a2a") {
            0o700
        } else {
            0o600
        };
        validate_owned_regular_file(&file, mode, "recovery_needed")?;
    }
    if let Some(snapshot) = &transaction.generation_stage_snapshot {
        for staged in &snapshot.files {
            let relative = staged
                .path
                .strip_prefix(&transaction.generation_stage)
                .map_err(|_| {
                    ManagedError::new(
                        "recovery_needed",
                        "generation snapshot file escaped its authenticated stage",
                    )
                })?;
            if !exact_snapshot_file_state(&transaction.generation.join(relative), Some(staged)) {
                return Err(ManagedError::new(
                    "recovery_needed",
                    "published generation file does not match its authenticated stage inode",
                ));
            }
        }
    }
    validate_prior_generation_state(transaction)
}

fn validate_prior_generation_state(transaction: &InstallTransaction) -> ManagedResult<()> {
    if let Some(prior) = &transaction.prior_record {
        let prior_generation = prior.pi_package_source.parent().unwrap();
        let prior_present = fs::symlink_metadata(prior_generation).is_ok();
        if prior.state == InstallState::Removed {
            if prior_present && prior_generation != transaction.generation {
                return Err(ManagedError::new(
                    "recovery_needed",
                    "removed prior generation reappeared during reinstall",
                ));
            }
            return Ok(());
        }
        let may_be_removed = prior_generation != transaction.generation
            && transaction.phase == TransactionPhase::RecordCommitted;
        if !prior_present && !may_be_removed {
            return Err(ManagedError::new(
                "recovery_needed",
                "prior generation disappeared before transaction commit",
            ));
        }
        if prior_present {
            let snapshot = transaction
                .prior_generation_snapshot
                .as_ref()
                .ok_or_else(|| {
                    ManagedError::new(
                        "recovery_needed",
                        "transaction has no prior generation inode snapshot",
                    )
                })?;
            validate_stage_snapshot_live(prior_generation, snapshot)?;
        }
    }
    Ok(())
}

fn validate_prior_generation_snapshot_semantics(
    record: &OwnershipRecord,
    snapshot: &StageSnapshot,
) -> ManagedResult<()> {
    let generation = record.pi_package_source.parent().unwrap();
    validate_stage_snapshot_semantics(generation, snapshot)?;
    let expected_files: BTreeSet<PathBuf> = record
        .owned_files
        .iter()
        .map(|owned| owned.path.clone())
        .filter(|path| path.starts_with(generation))
        .collect();
    let snapshot_files: BTreeSet<PathBuf> = snapshot
        .files
        .iter()
        .map(|file| file.path.clone())
        .collect();
    if snapshot_files != expected_files {
        return Err(ManagedError::new(
            "recovery_needed",
            "prior generation snapshot file inventory is not exact",
        ));
    }
    let mut expected_directories = BTreeSet::from([generation.to_path_buf()]);
    for expected in &expected_files {
        let owned = record_owned_file(record, expected).unwrap();
        let snapshot_file = snapshot
            .files
            .iter()
            .find(|file| file.path == *expected)
            .unwrap();
        if snapshot_file.mode != owned.mode || snapshot_file.sha256 != owned.sha256 {
            return Err(ManagedError::new(
                "recovery_needed",
                "prior generation snapshot file metadata is not exact",
            ));
        }
        let mut parent = expected.parent();
        while let Some(directory) = parent {
            if !directory.starts_with(generation) {
                break;
            }
            expected_directories.insert(directory.to_path_buf());
            parent = directory.parent();
        }
    }
    let snapshot_directories: BTreeSet<PathBuf> = snapshot
        .directories
        .iter()
        .map(|directory| directory.path.clone())
        .collect();
    if snapshot_directories != expected_directories {
        return Err(ManagedError::new(
            "recovery_needed",
            "prior generation snapshot directory inventory is not exact",
        ));
    }
    Ok(())
}

fn record_owned_file<'a>(record: &'a OwnershipRecord, path: &Path) -> Option<&'a OwnedFile> {
    record.owned_files.iter().find(|owned| owned.path == path)
}

fn exact_snapshot_file_state(path: &Path, expected: Option<&OwnedStageFile>) -> bool {
    match expected {
        Some(expected) => snapshot_owned_file(path, expected.mode).is_ok_and(|actual| {
            actual.device == expected.device
                && actual.inode == expected.inode
                && actual.mode == expected.mode
                && actual.sha256 == expected.sha256
        }),
        None => {
            fs::symlink_metadata(path).is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
        }
    }
}

fn validate_live_plugin_state(transaction: &InstallTransaction) -> ManagedResult<()> {
    let prior_helper = transaction.prior_helper_snapshot.as_ref();
    let prior_pointer = transaction.prior_pointer_snapshot.as_ref();
    let new_helper = transaction.new_helper_snapshot.as_ref();
    let new_pointer = transaction.new_pointer_snapshot.as_ref();
    let prior_targets = exact_snapshot_file_state(&transaction.helper, prior_helper)
        && exact_snapshot_file_state(&transaction.pointer, prior_pointer)
        && !transaction.helper_backup.exists()
        && !transaction.pointer_backup.exists();
    let full_stage = transaction
        .plugin_stage_snapshot
        .as_ref()
        .is_some_and(|snapshot| exact_plugin_stage_subset(transaction, snapshot, true, true));
    let pointer_stage = transaction
        .plugin_stage_snapshot
        .as_ref()
        .is_some_and(|snapshot| exact_plugin_stage_subset(transaction, snapshot, false, true));
    let residual_stage = transaction
        .plugin_stage_snapshot
        .as_ref()
        .is_some_and(|snapshot| exact_plugin_stage_subset(transaction, snapshot, false, false));
    let exact_residual_stage = if transaction.plugin_stage_snapshot.is_some() {
        residual_stage
    } else {
        !transaction.plugin_stage.exists()
    };
    let residual_stage_or_absent = exact_residual_stage
        || (transaction.plugin_stage_snapshot.is_some() && !transaction.plugin_stage.exists());
    let helper_staged = transaction
        .plugin_stage_snapshot
        .as_ref()
        .and_then(|snapshot| plugin_staged_file(transaction, snapshot, true))
        .is_some_and(|snapshot| exact_snapshot_file_state(&transaction.helper, Some(snapshot)));
    let pointer_staged = transaction
        .plugin_stage_snapshot
        .as_ref()
        .and_then(|snapshot| plugin_staged_file(transaction, snapshot, false))
        .is_some_and(|snapshot| exact_snapshot_file_state(&transaction.pointer, Some(snapshot)));
    let helper_backed_up = exact_snapshot_file_state(&transaction.helper, None)
        && exact_snapshot_file_state(&transaction.helper_backup, prior_helper);
    let pointer_backed_up = exact_snapshot_file_state(&transaction.pointer, None)
        && exact_snapshot_file_state(&transaction.pointer_backup, prior_pointer);
    let state_0 = prior_targets && full_stage;
    let state_1 = helper_backed_up
        && exact_snapshot_file_state(&transaction.pointer, prior_pointer)
        && exact_snapshot_file_state(&transaction.pointer_backup, None)
        && full_stage;
    let state_2 = helper_backed_up && pointer_backed_up && full_stage;
    let state_3 = helper_staged
        && exact_snapshot_file_state(&transaction.helper_backup, prior_helper)
        && pointer_backed_up
        && pointer_stage;
    let state_4 = helper_staged
        && pointer_staged
        && exact_snapshot_file_state(&transaction.helper_backup, prior_helper)
        && exact_snapshot_file_state(&transaction.pointer_backup, prior_pointer)
        && residual_stage;
    let published_state = new_helper.is_some()
        && new_pointer.is_some()
        && exact_snapshot_file_state(&transaction.helper, new_helper)
        && exact_snapshot_file_state(&transaction.pointer, new_pointer)
        && exact_snapshot_file_state(&transaction.helper_backup, prior_helper)
        && exact_snapshot_file_state(&transaction.pointer_backup, prior_pointer)
        && exact_residual_stage;
    let committed_state = new_helper.is_some()
        && new_pointer.is_some()
        && exact_snapshot_file_state(&transaction.helper, new_helper)
        && exact_snapshot_file_state(&transaction.pointer, new_pointer)
        && exact_snapshot_or_absent(&transaction.helper_backup, prior_helper)
        && exact_snapshot_or_absent(&transaction.pointer_backup, prior_pointer)
        && residual_stage_or_absent;
    let allowed = match transaction.phase {
        TransactionPhase::Intent
        | TransactionPhase::GenerationPublishing
        | TransactionPhase::GenerationPublished => {
            prior_targets && !transaction.plugin_stage.exists()
        }
        TransactionPhase::PluginPublishing => {
            (transaction.plugin_stage_snapshot.is_none()
                && !transaction.plugin_stage.exists()
                && prior_targets)
                || state_0
        }
        TransactionPhase::PluginBackingUpHelper => state_0 || state_1,
        TransactionPhase::PluginBackingUpPointer => state_1 || state_2,
        TransactionPhase::PluginPublishingHelper => state_2 || state_3,
        TransactionPhase::PluginPublishingPointer => state_3 || state_4,
        TransactionPhase::RecordCommitted => committed_state,
        _ => published_state,
    };
    if !allowed {
        return Err(ManagedError::new(
            "recovery_needed",
            "live plugin assets are not an exact state allowed by the transaction phase",
        ));
    }
    Ok(())
}

fn plugin_staged_file<'a>(
    transaction: &InstallTransaction,
    snapshot: &'a StageSnapshot,
    helper: bool,
) -> Option<&'a OwnedStageFile> {
    let path = if helper {
        transaction.plugin_stage.join("libexec/herdr-a2a-dispatch")
    } else {
        transaction.plugin_stage.join("stable-bin-path")
    };
    snapshot.files.iter().find(|file| file.path == path)
}

fn plugin_stage_subset(
    transaction: &InstallTransaction,
    snapshot: &StageSnapshot,
    helper: bool,
    pointer: bool,
) -> StageSnapshot {
    StageSnapshot {
        directories: snapshot.directories.clone(),
        files: snapshot
            .files
            .iter()
            .filter(|file| {
                (helper && file.path == transaction.plugin_stage.join("libexec/herdr-a2a-dispatch"))
                    || (pointer && file.path == transaction.plugin_stage.join("stable-bin-path"))
            })
            .cloned()
            .collect(),
    }
}

fn exact_plugin_stage_subset(
    transaction: &InstallTransaction,
    snapshot: &StageSnapshot,
    helper: bool,
    pointer: bool,
) -> bool {
    transaction.plugin_stage.exists()
        && validate_stage_snapshot_live(
            &transaction.plugin_stage,
            &plugin_stage_subset(transaction, snapshot, helper, pointer),
        )
        .is_ok()
}

fn exact_snapshot_or_absent(path: &Path, expected: Option<&OwnedStageFile>) -> bool {
    fs::symlink_metadata(path).is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
        || expected.is_some_and(|snapshot| exact_snapshot_file_state(path, Some(snapshot)))
}

fn expected_post_pi_entries(transaction: &InstallTransaction, new_entry: &Value) -> Vec<Value> {
    let mut expected = transaction.prior_pi_entries.clone();
    if let Some(prior_owned) = &transaction.prior_owned_pi_entry
        && prior_owned != new_entry
        && let Some(index) = expected.iter().position(|entry| entry == prior_owned)
    {
        expected.remove(index);
    }
    if !expected.iter().any(|entry| entry == new_entry) {
        expected.push(new_entry.clone());
    }
    expected
}

fn validate_live_pi_state(transaction: &InstallTransaction) -> ManagedResult<()> {
    let current = read_pi_settings()?;
    if current.path != transaction.pi_config_path {
        return Err(ManagedError::new(
            "recovery_needed",
            "Pi settings path changed during transaction recovery",
        ));
    }
    let prior = same_json_multiset(&current.entries, &transaction.prior_pi_entries)?;
    let post = same_json_multiset(
        &current.entries,
        &expected_post_pi_entries(transaction, &transaction.new_pi_entry),
    )?;
    let mutating_source = transaction.generation.join("pi");
    let mutating_entries =
        allowed_managed_pi_entries(&transaction.pi_config_path, &mutating_source)?;
    let mutating_post = mutating_entries.iter().try_fold(false, |matched, entry| {
        Ok::<_, ManagedError>(
            matched
                || same_json_multiset(
                    &current.entries,
                    &expected_post_pi_entries(transaction, entry),
                )?,
        )
    })?;
    let mutating_intermediate = mutating_entries.iter().try_fold(false, |matched, entry| {
        let mut entries = transaction.prior_pi_entries.clone();
        if !entries.iter().any(|existing| existing == entry) {
            entries.push(entry.clone());
        }
        Ok::<_, ManagedError>(matched || same_json_multiset(&current.entries, &entries)?)
    })?;
    let allowed = match transaction.phase {
        TransactionPhase::Intent
        | TransactionPhase::GenerationPublishing
        | TransactionPhase::GenerationPublished
        | TransactionPhase::PluginPublishing
        | TransactionPhase::PluginBackingUpHelper
        | TransactionPhase::PluginBackingUpPointer
        | TransactionPhase::PluginPublishingHelper
        | TransactionPhase::PluginPublishingPointer
        | TransactionPhase::PluginPublished => prior,
        TransactionPhase::PiMutating => prior || mutating_intermediate || mutating_post,
        TransactionPhase::PiMutated => post,
        TransactionPhase::RescuePublishing
        | TransactionPhase::RecordCommitting
        | TransactionPhase::RecordRenaming
        | TransactionPhase::RecordCommitted => {
            transaction
                .new_record
                .as_ref()
                .is_some_and(|record| match record.state {
                    InstallState::Ready => post,
                    InstallState::PiAdapterPending => prior,
                    InstallState::Failed
                    | InstallState::Removing
                    | InstallState::UnregisterPending
                    | InstallState::Unregistering
                    | InstallState::FinalizingRemoval
                    | InstallState::Removed => false,
                })
        }
    };
    if !allowed {
        return Err(ManagedError::new(
            "recovery_needed",
            "live Pi settings are not an exact state allowed by the transaction phase",
        ));
    }
    Ok(())
}

async fn reconcile_transaction(stable_root: &Path) -> ManagedResult<()> {
    let Some(transaction) = read_transaction(stable_root)? else {
        return Ok(());
    };
    validate_transaction_recovery_state(stable_root, &transaction)?;
    if transaction.schema_version == LEGACY_TRANSACTION_SCHEMA
        && transaction.phase == TransactionPhase::PiMutated
        && transaction.new_record.is_none()
        && transaction.prior_record.is_some()
    {
        match classify_legacy_pi_mutated_rescue_state(stable_root, &transaction)? {
            LegacyPiMutatedRescueState::PublishedNew => {
                return complete_predecessor_pi_mutated_transaction(stable_root, transaction);
            }
            LegacyPiMutatedRescueState::LivePrior => {}
        }
    }
    if is_predecessor_forward_commit(&transaction) {
        return complete_predecessor_forward_commit(stable_root, transaction);
    }
    if transaction.phase == TransactionPhase::RecordCommitted {
        let current = transaction.new_record.as_ref().ok_or_else(|| {
            ManagedError::new("recovery_needed", "committed transaction has no new record")
        })?;
        validate_record(current, stable_root)?;
        cleanup_transaction_artifacts(&transaction)?;
        if let Some(prior) = &transaction.prior_record {
            remove_superseded_generation(
                stable_root,
                prior,
                current,
                transaction.prior_generation_snapshot.as_ref(),
            )?;
        }
        return clear_transaction(stable_root);
    }

    if transaction.schema_version == LEGACY_TRANSACTION_SCHEMA
        && transaction.phase == TransactionPhase::PiMutating
        && transaction.new_record.is_none()
        && transaction.prior_record.is_some()
    {
        restore_predecessor_pi_mutating_rescue(stable_root, &transaction)?;
    }
    restore_prior_record(stable_root, transaction.prior_record.as_ref())?;
    restore_pi_snapshot(&transaction).await?;
    restore_plugin_snapshot(&transaction)?;
    restore_prior_rescue_assets(stable_root, &transaction)?;
    if transaction.generation_created {
        remove_created_generation(&transaction)?;
    }
    prove_prior_state(stable_root, &transaction)?;
    clear_transaction(stable_root)
}

fn complete_predecessor_pi_mutated_transaction(
    stable_root: &Path,
    mut transaction: InstallTransaction,
) -> ManagedResult<()> {
    let prior = transaction.prior_record.as_ref().ok_or_else(|| {
        ManagedError::new(
            "recovery_needed",
            "predecessor Pi transaction has no prior ownership",
        )
    })?;
    if prior.state == InstallState::Removed {
        return Err(ManagedError::new(
            "recovery_needed",
            "predecessor Pi transaction cannot update removed ownership",
        ));
    }
    let plugin_root = required_plugin_root()?;
    let generation = PreparedGeneration {
        binary: transaction.generation.join("bin/herdr-a2a"),
        package: transaction.generation.join("pi"),
    };
    let mut record = build_record(
        stable_root,
        &plugin_root,
        &generation,
        Some(prior),
        transaction.broker_digest.clone(),
        transaction.pi_package_digest.clone(),
        InstallState::Ready,
        prior.install_kind.clone(),
    )?;
    record.pi_package_entry = transaction.new_pi_entry.clone();
    let expected_rescue = prepare_rescue_assets(stable_root, &plugin_root, &mut record)?;
    authenticate_published_rescue_assets(stable_root, &record, &expected_rescue)?;
    validate_record(&record, stable_root)?;
    validate_ready_pi(&record)?;

    transaction.new_record = Some(record);
    transaction.phase = TransactionPhase::RecordCommitting;
    write_transaction(stable_root, &transaction)?;
    complete_predecessor_forward_commit(stable_root, transaction)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LegacyPiMutatedRescueState {
    PublishedNew,
    LivePrior,
}

fn classify_legacy_pi_mutated_rescue_state(
    stable_root: &Path,
    transaction: &InstallTransaction,
) -> ManagedResult<LegacyPiMutatedRescueState> {
    let prior = transaction.prior_record.as_ref().ok_or_else(|| {
        ManagedError::new(
            "recovery_needed",
            "legacy Pi transaction has no prior ownership",
        )
    })?;
    let plugin_root = required_plugin_root()?;
    let generation = PreparedGeneration {
        binary: transaction.generation.join("bin/herdr-a2a"),
        package: transaction.generation.join("pi"),
    };
    let mut record = build_record(
        stable_root,
        &plugin_root,
        &generation,
        Some(prior),
        transaction.broker_digest.clone(),
        transaction.pi_package_digest.clone(),
        InstallState::Ready,
        prior.install_kind.clone(),
    )?;
    record.pi_package_entry = transaction.new_pi_entry.clone();
    let expected_new = prepare_rescue_assets(stable_root, &plugin_root, &mut record)?;
    let published_new =
        authenticate_published_rescue_assets(stable_root, &record, &expected_new).is_ok();
    let live_prior = authenticate_live_prior_rescue_assets(stable_root, prior).is_ok();
    match (published_new, live_prior) {
        (true, false) => Ok(LegacyPiMutatedRescueState::PublishedNew),
        (false, true) => Ok(LegacyPiMutatedRescueState::LivePrior),
        (true, true) => Err(ManagedError::new(
            "recovery_needed",
            "legacy Pi transaction rescue state is ambiguous",
        )),
        (false, false) => Err(ManagedError::new(
            "recovery_needed",
            "legacy Pi transaction rescue state is not authenticated",
        )),
    }
}

fn authenticate_live_prior_rescue_assets(
    stable_root: &Path,
    prior: &OwnershipRecord,
) -> ManagedResult<()> {
    let rescue_directory = stable_root.join(RESCUE_DIRECTORY);
    let mut expected_paths = [
        rescue_directory.join("uninstall.sh"),
        rescue_directory.join(RESCUE_MARKER),
    ];
    expected_paths.sort();
    if tree_files(&rescue_directory)? != expected_paths {
        return Err(ManagedError::new(
            "recovery_needed",
            "legacy Pi transaction prior rescue inventory is not exact",
        ));
    }
    capture_prior_rescue_assets(stable_root, Some(prior)).map(|_| ())
}

fn authenticate_published_rescue_assets(
    stable_root: &Path,
    record: &OwnershipRecord,
    expected: &PreparedRescueAssets,
) -> ManagedResult<()> {
    let rescue_directory = stable_root.join(RESCUE_DIRECTORY);
    let mut expected_paths = [expected.rescue.clone(), expected.marker.clone()];
    expected_paths.sort();
    if tree_files(&rescue_directory)? != expected_paths {
        return Err(ManagedError::new(
            "recovery_needed",
            "predecessor rescue publication inventory is not exact",
        ));
    }
    for (path, bytes) in [
        (&expected.rescue, &expected.notice),
        (&expected.marker, &expected.marker_bytes),
    ] {
        let owned = record_owned_file(record, path).ok_or_else(|| {
            ManagedError::new(
                "recovery_needed",
                "predecessor rescue publication has no ownership entry",
            )
        })?;
        if owned.mode != 0o600
            || sha256_bytes(bytes) != owned.sha256
            || validate_owned_file_digest(path, 0o600, &owned.sha256, "recovery_needed").is_err()
        {
            return Err(ManagedError::new(
                "recovery_needed",
                "predecessor rescue publication is not authenticated",
            ));
        }
    }
    Ok(())
}

fn is_predecessor_forward_commit(transaction: &InstallTransaction) -> bool {
    transaction.schema_version == LEGACY_TRANSACTION_SCHEMA
        && transaction.phase == TransactionPhase::RecordCommitting
        && transaction
            .prior_record
            .as_ref()
            .is_some_and(|record| record.state != InstallState::Removed)
        && transaction.new_record.is_some()
        && transaction.prior_rescue_notice.is_none()
        && transaction.prior_rescue_marker.is_none()
}

fn complete_predecessor_forward_commit(
    stable_root: &Path,
    mut transaction: InstallTransaction,
) -> ManagedResult<()> {
    let current = transaction.new_record.as_ref().ok_or_else(|| {
        ManagedError::new(
            "recovery_needed",
            "predecessor forward transaction has no new ownership",
        )
    })?;
    validate_record(current, stable_root)?;
    validate_ready_pi(current)?;
    let live = read_record_optional(stable_root)?;
    if live.as_ref() == transaction.prior_record.as_ref() {
        write_record(stable_root, current)?;
    } else if live.as_ref() != Some(current) {
        return Err(ManagedError::new(
            "recovery_needed",
            "predecessor forward transaction has an unexpected live record",
        ));
    }
    transaction.phase = TransactionPhase::RecordCommitted;
    write_transaction(stable_root, &transaction)?;
    cleanup_transaction_artifacts(&transaction)?;
    if let Some(prior) = &transaction.prior_record {
        remove_superseded_generation(
            stable_root,
            prior,
            current,
            transaction.prior_generation_snapshot.as_ref(),
        )?;
    }
    clear_transaction(stable_root)
}

fn restore_prior_record(stable_root: &Path, prior: Option<&OwnershipRecord>) -> ManagedResult<()> {
    let path = stable_root.join(OWNERSHIP_FILE);
    match prior {
        Some(record) => {
            let temporary = stable_root.join(format!(".ownership-restore-{}", random_hex()?));
            let bytes = serialize_ownership_record(record, "recovery_needed")?;
            write_new_file(&temporary, &bytes, 0o600)?;
            fs::rename(&temporary, &path).map_err(|error| {
                ManagedError::io("recovery_needed", "cannot restore prior record", error)
            })?;
        }
        None => remove_if_exists(&path)?,
    }
    sync_directory(stable_root)
}

fn restore_prior_rescue_assets(
    stable_root: &Path,
    transaction: &InstallTransaction,
) -> ManagedResult<()> {
    let Some(new_record) = transaction.new_record.as_ref() else {
        if transaction.schema_version == LEGACY_TRANSACTION_SCHEMA
            && transaction.phase == TransactionPhase::PiMutating
            && transaction.prior_record.is_some()
        {
            return restore_predecessor_pi_mutating_rescue(stable_root, transaction);
        }
        return Ok(());
    };
    let rescue_directory = stable_root.join(RESCUE_DIRECTORY);
    let rescue = rescue_directory.join("uninstall.sh");
    let marker = rescue_directory.join(RESCUE_MARKER);
    let mut expected_paths = [rescue.clone(), marker.clone()];
    expected_paths.sort();
    let live_paths = if rescue_directory.exists() {
        tree_files(&rescue_directory)?
    } else {
        Vec::new()
    };
    let prior = transaction
        .prior_record
        .as_ref()
        .filter(|record| record.state != InstallState::Removed);
    if live_paths.iter().any(|path| !expected_paths.contains(path))
        || (prior.is_some() && live_paths.len() != expected_paths.len())
    {
        return Err(ManagedError::new(
            "recovery_needed",
            "rescue rollback inventory is not exact",
        ));
    }
    for path in &live_paths {
        let exact_variant = [transaction.prior_record.as_ref(), Some(new_record)]
            .into_iter()
            .flatten()
            .filter_map(|record| record_owned_file(record, path))
            .any(|owned| {
                validate_owned_file_digest(
                    &owned.path,
                    owned.mode,
                    &owned.sha256,
                    "recovery_needed",
                )
                .is_ok()
            });
        if !exact_variant {
            return Err(ManagedError::new(
                "recovery_needed",
                "rescue rollback encountered an unauthenticated file",
            ));
        }
    }

    let Some(prior) = prior else {
        for path in [&marker, &rescue] {
            if !live_paths.contains(path) {
                continue;
            }
            let owned = record_owned_file(new_record, path).ok_or_else(|| {
                ManagedError::new("recovery_needed", "new record has no rescue rollback entry")
            })?;
            unlink_recorded_owned_file(owned)?;
        }
        if rescue_directory.exists() {
            fs::remove_dir(&rescue_directory).map_err(|error| {
                ManagedError::io(
                    "recovery_needed",
                    "cannot retire the transaction-created rescue directory",
                    error,
                )
            })?;
        }
        return sync_directory(stable_root);
    };

    let prior_rescue = record_owned_file(prior, &rescue)
        .ok_or_else(|| ManagedError::new("recovery_needed", "prior record has no rescue notice"))?;
    let prior_marker = record_owned_file(prior, &marker)
        .ok_or_else(|| ManagedError::new("recovery_needed", "prior record has no rescue marker"))?;
    let live_is_prior = live_paths.len() == expected_paths.len()
        && validate_owned_file_digest(
            &rescue,
            prior_rescue.mode,
            &prior_rescue.sha256,
            "recovery_needed",
        )
        .is_ok()
        && validate_owned_file_digest(
            &marker,
            prior_marker.mode,
            &prior_marker.sha256,
            "recovery_needed",
        )
        .is_ok();
    if live_is_prior {
        return Ok(());
    }

    let (notice, marker_bytes) = match (
        &transaction.prior_rescue_notice,
        &transaction.prior_rescue_marker,
    ) {
        (Some(notice), Some(marker_bytes)) => (notice.clone(), marker_bytes.clone()),
        (None, None)
            if matches!(
                transaction.phase,
                TransactionPhase::RecordCommitting | TransactionPhase::RecordRenaming
            ) =>
        {
            let notice = read_rescue_notice(&prior.plugin_root.join("scripts/uninstall.sh"))?;
            let mut marker_record = prior.clone();
            marker_record
                .owned_files
                .retain(|owned| owned.path != marker);
            let marker_bytes = rescue_marker(&marker_record, stable_root)?.into_bytes();
            (notice, marker_bytes)
        }
        _ => {
            return Err(ManagedError::new(
                "recovery_needed",
                "transaction has no authenticated prior rescue snapshot",
            ));
        }
    };
    if prior_rescue.mode != 0o600
        || prior_marker.mode != 0o600
        || sha256_bytes(&notice) != prior_rescue.sha256
        || !prior_rescue_marker_is_authenticated(prior, prior_marker, &marker_bytes)
    {
        return Err(ManagedError::new(
            "recovery_needed",
            "prior rescue snapshot cannot be restored exactly",
        ));
    }
    replace_owned_bytes(&rescue, &notice, 0o600)?;
    replace_owned_bytes(&marker, &marker_bytes, 0o600)?;
    validate_owned_file_digest(
        &rescue,
        prior_rescue.mode,
        &prior_rescue.sha256,
        "recovery_needed",
    )?;
    validate_owned_file_digest(
        &marker,
        prior_marker.mode,
        &prior_marker.sha256,
        "recovery_needed",
    )
}

fn restore_predecessor_pi_mutating_rescue(
    stable_root: &Path,
    transaction: &InstallTransaction,
) -> ManagedResult<()> {
    let prior = transaction.prior_record.as_ref().ok_or_else(|| {
        ManagedError::new(
            "recovery_needed",
            "predecessor Pi mutation has no prior ownership",
        )
    })?;
    if prior.state == InstallState::Removed {
        return Err(ManagedError::new(
            "recovery_needed",
            "predecessor Pi mutation cannot restore removed ownership",
        ));
    }
    let rescue = stable_root.join(RESCUE_DIRECTORY).join("uninstall.sh");
    let marker = stable_root.join(RESCUE_DIRECTORY).join(RESCUE_MARKER);
    let prior_rescue = record_owned_file(prior, &rescue)
        .ok_or_else(|| ManagedError::new("recovery_needed", "prior record has no rescue notice"))?;
    let prior_marker = record_owned_file(prior, &marker)
        .ok_or_else(|| ManagedError::new("recovery_needed", "prior record has no rescue marker"))?;
    let live_is_prior = validate_owned_file_digest(
        &rescue,
        prior_rescue.mode,
        &prior_rescue.sha256,
        "recovery_needed",
    )
    .is_ok()
        && validate_owned_file_digest(
            &marker,
            prior_marker.mode,
            &prior_marker.sha256,
            "recovery_needed",
        )
        .is_ok();
    if live_is_prior {
        return Ok(());
    }

    let plugin_root = required_plugin_root()?;
    let generation = PreparedGeneration {
        binary: transaction.generation.join("bin/herdr-a2a"),
        package: transaction.generation.join("pi"),
    };
    let mut interrupted_record = build_record(
        stable_root,
        &plugin_root,
        &generation,
        Some(prior),
        transaction.broker_digest.clone(),
        transaction.pi_package_digest.clone(),
        InstallState::PiAdapterPending,
        prior.install_kind.clone(),
    )?;
    let interrupted_rescue =
        prepare_rescue_assets(stable_root, &plugin_root, &mut interrupted_record)?;
    authenticate_published_rescue_assets(stable_root, &interrupted_record, &interrupted_rescue)?;

    let notice = read_rescue_notice(&prior.plugin_root.join("scripts/uninstall.sh"))?;
    let mut marker_record = prior.clone();
    marker_record
        .owned_files
        .retain(|owned| owned.path != marker);
    let marker_bytes = rescue_marker(&marker_record, stable_root)?.into_bytes();
    if prior_rescue.mode != 0o600
        || prior_marker.mode != 0o600
        || sha256_bytes(&notice) != prior_rescue.sha256
        || !prior_rescue_marker_is_authenticated(prior, prior_marker, &marker_bytes)
    {
        return Err(ManagedError::new(
            "recovery_needed",
            "predecessor prior rescue assets cannot be reconstructed exactly",
        ));
    }
    replace_owned_bytes(&rescue, &notice, 0o600)?;
    replace_owned_bytes(&marker, &marker_bytes, 0o600)?;
    validate_owned_file_digest(
        &rescue,
        prior_rescue.mode,
        &prior_rescue.sha256,
        "recovery_needed",
    )?;
    validate_owned_file_digest(
        &marker,
        prior_marker.mode,
        &prior_marker.sha256,
        "recovery_needed",
    )
}

fn serialize_ownership_record(
    record: &OwnershipRecord,
    code: &'static str,
) -> ManagedResult<Vec<u8>> {
    let mut value =
        serde_json::to_value(record).map_err(|error| ManagedError::new(code, error.to_string()))?;
    if record.schema_version == 2 {
        value
            .as_object_mut()
            .ok_or_else(|| ManagedError::new(code, "ownership record is not an object"))?
            .remove("purge_authority");
    }
    serde_json::to_vec_pretty(&value).map_err(|error| ManagedError::new(code, error.to_string()))
}

async fn restore_pi_snapshot(transaction: &InstallTransaction) -> ManagedResult<()> {
    let mut current = read_pi_settings()?;
    if current.path != transaction.pi_config_path {
        return Err(ManagedError::new(
            "recovery_needed",
            "Pi settings path changed during recovery",
        ));
    }
    if same_json_multiset(&current.entries, &transaction.prior_pi_entries)? {
        return Ok(());
    }
    let Some(program) = find_in_path("pi") else {
        return Err(ManagedError::new(
            "recovery_needed",
            "Pi is unavailable for transaction rollback",
        ));
    };
    let new_source = transaction.generation.join("pi");
    let prior_owned_source = transaction
        .prior_owned_pi_entry
        .as_ref()
        .map(|entry| resolve_pi_entry_path(&transaction.pi_config_path, entry))
        .transpose()?;
    let unrelated = |entries: &[Value]| {
        entries
            .iter()
            .filter(|entry| {
                !pi_entry_matches_path(entry, &transaction.pi_config_path, &new_source)
                    && !prior_owned_source.as_deref().is_some_and(|source| {
                        pi_entry_matches_path(entry, &transaction.pi_config_path, source)
                    })
            })
            .cloned()
            .collect::<Vec<_>>()
    };
    if !same_json_multiset(
        &unrelated(&current.entries),
        &unrelated(&transaction.prior_pi_entries),
    )? {
        return Err(ManagedError::new(
            "recovery_needed",
            "unrelated Pi entries changed during the transaction",
        ));
    }
    let current_new: Vec<&Value> = current
        .entries
        .iter()
        .filter(|entry| pi_entry_matches_path(entry, &transaction.pi_config_path, &new_source))
        .collect();
    let prior_has_exact_new = transaction
        .prior_pi_entries
        .iter()
        .any(|entry| entry == &transaction.new_pi_entry);
    if !prior_has_exact_new && !current_new.is_empty() {
        if current_new.len() != 1
            || !is_allowed_managed_pi_entry(
                current_new[0],
                &transaction.pi_config_path,
                &new_source,
            )?
        {
            return Err(ManagedError::new(
                "recovery_needed",
                "new Pi entry was externally modified",
            ));
        }
        run_pi_checked(&program, "remove", &new_source).await?;
    }
    current = read_pi_settings()?;
    if let Some(prior_owned) = &transaction.prior_owned_pi_entry {
        let source = prior_owned_source
            .as_deref()
            .ok_or_else(|| ManagedError::new("recovery_needed", "prior Pi source is missing"))?;
        let matching: Vec<&Value> = current
            .entries
            .iter()
            .filter(|entry| pi_entry_matches_path(entry, &transaction.pi_config_path, source))
            .collect();
        if matching.is_empty() {
            run_pi_checked(&program, "install", source).await?;
        } else if matching.len() != 1 || matching[0] != prior_owned {
            return Err(ManagedError::new(
                "recovery_needed",
                "prior owned Pi entry was externally modified",
            ));
        }
    }
    let final_settings = read_pi_settings()?;
    if !same_json_multiset(&final_settings.entries, &transaction.prior_pi_entries)? {
        return Err(ManagedError::new(
            "recovery_needed",
            "Pi settings are not the exact pre-transaction snapshot",
        ));
    }
    Ok(())
}

fn same_json_multiset(left: &[Value], right: &[Value]) -> ManagedResult<bool> {
    let mut left: Vec<Vec<u8>> = left
        .iter()
        .map(serde_json::to_vec)
        .collect::<Result<_, _>>()
        .map_err(|error| ManagedError::new("recovery_needed", error.to_string()))?;
    let mut right: Vec<Vec<u8>> = right
        .iter()
        .map(serde_json::to_vec)
        .collect::<Result<_, _>>()
        .map_err(|error| ManagedError::new("recovery_needed", error.to_string()))?;
    left.sort();
    right.sort();
    Ok(left == right)
}

fn snapshot_owned_file(path: &Path, mode: u32) -> ManagedResult<OwnedStageFile> {
    let mut file = open_validated_absolute_file(path)?;
    let metadata = file.metadata().map_err(|error| {
        ManagedError::io(
            "recovery_needed",
            "cannot inspect transaction-owned file",
            error,
        )
    })?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != mode
    {
        return Err(ManagedError::new(
            "recovery_needed",
            "transaction-owned file metadata is unsafe",
        ));
    }
    Ok(OwnedStageFile {
        path: path.to_path_buf(),
        device: metadata.dev(),
        inode: metadata.ino(),
        mode,
        sha256: digest_opened_owned_file(&mut file, metadata.len(), "recovery_needed")?,
    })
}

fn snapshot_stage(root: &Path) -> ManagedResult<StageSnapshot> {
    let opened = open_validated_absolute_directory(root, true)
        .map_err(|error| ManagedError::new("recovery_needed", error.to_string()))?;
    snapshot_opened_stage(opened, root)
}

struct StageWalkState {
    entries: usize,
    total_bytes: u64,
    directories: Vec<OwnedDirectory>,
    files: Vec<OwnedStageFile>,
}

fn snapshot_opened_stage(root: File, root_path: &Path) -> ManagedResult<StageSnapshot> {
    require_absolute_normal(root_path, "transaction stage root")?;
    let metadata = root.metadata().map_err(|error| {
        ManagedError::io(
            "recovery_needed",
            "cannot inspect opened transaction stage root",
            error,
        )
    })?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(ManagedError::new(
            "recovery_needed",
            "transaction stage contains an unsafe root directory",
        ));
    }
    let mut state = StageWalkState {
        entries: 1,
        total_bytes: 0,
        directories: vec![OwnedDirectory {
            path: root_path.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: 0o700,
        }],
        files: Vec::new(),
    };
    snapshot_opened_stage_directory(&root, root_path, Path::new(""), 0, &mut state)?;
    state
        .directories
        .sort_by(|left, right| left.path.cmp(&right.path));
    state
        .files
        .sort_by(|left, right| left.path.cmp(&right.path));
    Ok(StageSnapshot {
        directories: state.directories,
        files: state.files,
    })
}

fn snapshot_opened_stage_directory(
    directory: &File,
    root_path: &Path,
    relative: &Path,
    depth: usize,
    state: &mut StageWalkState,
) -> ManagedResult<()> {
    let entries = Dir::read_from(directory).map_err(|error| {
        ManagedError::new(
            "recovery_needed",
            format!("cannot open transaction stage directory stream: {error}"),
        )
    })?;
    let mut names = Vec::<Vec<u8>>::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            ManagedError::new(
                "recovery_needed",
                format!("cannot enumerate opened transaction stage: {error}"),
            )
        })?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        state.entries = state.entries.checked_add(1).ok_or_else(|| {
            ManagedError::new(
                "recovery_needed",
                "transaction stage entry count overflowed",
            )
        })?;
        if state.entries > MAX_PURGE_ENTRIES {
            return Err(ManagedError::new(
                "recovery_needed",
                "transaction stage exceeds bounded traversal limits",
            ));
        }
        names.push(name.to_vec());
    }
    names.sort();

    for name in names {
        let name = OsStr::from_bytes(&name);
        let opened = File::from(
            openat(
                directory,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|error| {
                ManagedError::new(
                    "recovery_needed",
                    format!("cannot open transaction stage entry: {error}"),
                )
            })?,
        );
        let metadata = opened.metadata().map_err(|error| {
            ManagedError::io(
                "recovery_needed",
                "cannot inspect opened transaction stage entry",
                error,
            )
        })?;
        let child_relative = relative.join(name);
        let path = root_path.join(&child_relative);
        if metadata.is_dir() {
            let child_depth = depth.checked_add(1).ok_or_else(|| {
                ManagedError::new("recovery_needed", "transaction stage depth overflowed")
            })?;
            if child_depth > MAX_PURGE_DEPTH
                || metadata.uid() != rustix::process::getuid().as_raw()
                || metadata.mode() & 0o777 != 0o700
            {
                return Err(ManagedError::new(
                    "recovery_needed",
                    "transaction stage contains an unsafe or over-depth directory",
                ));
            }
            state.directories.push(OwnedDirectory {
                path,
                device: metadata.dev(),
                inode: metadata.ino(),
                mode: 0o700,
            });
            snapshot_opened_stage_directory(
                &opened,
                root_path,
                &child_relative,
                child_depth,
                state,
            )?;
        } else if metadata.is_file()
            && metadata.uid() == rustix::process::getuid().as_raw()
            && metadata.nlink() == 1
            && matches!(metadata.mode() & 0o777, 0o600 | 0o700)
            && metadata.len() <= MAX_OWNED_FILE_BYTES
        {
            let mut opened = opened;
            let digest = digest_bounded_stage_file(
                &mut opened,
                MAX_OWNED_FILE_BYTES,
                &mut state.total_bytes,
                MAX_PURGE_BYTES,
                "recovery_needed",
            )?;
            if digest.bytes != metadata.len() {
                return Err(ManagedError::new(
                    "recovery_needed",
                    "transaction stage file size changed while it was read",
                ));
            }
            state.files.push(OwnedStageFile {
                path,
                device: metadata.dev(),
                inode: metadata.ino(),
                mode: metadata.mode() & 0o777,
                sha256: digest.sha256,
            });
        } else {
            return Err(ManagedError::new(
                "recovery_needed",
                "transaction stage contains an unsafe entry",
            ));
        }
    }
    Ok(())
}

#[derive(Debug)]
struct BoundedDigest {
    bytes: u64,
    sha256: String,
}

fn digest_bounded_stage_file<R: Read>(
    reader: &mut R,
    file_limit: u64,
    total: &mut u64,
    total_limit: u64,
    code: &'static str,
) -> ManagedResult<BoundedDigest> {
    let mut file_bytes = 0_u64;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let permitted = file_limit
            .saturating_sub(file_bytes)
            .min(total_limit.saturating_sub(*total));
        let request = usize::try_from(permitted.saturating_add(1).min(buffer.len() as u64))
            .unwrap_or(buffer.len());
        let read = reader.read(&mut buffer[..request]).map_err(|error| {
            ManagedError::io(code, "cannot read opened transaction stage file", error)
        })?;
        if read == 0 {
            break;
        }
        if read as u64 > permitted {
            return Err(ManagedError::new(
                code,
                "transaction stage exceeds its actual-read byte limit",
            ));
        }
        file_bytes += read as u64;
        *total += read as u64;
        hasher.update(&buffer[..read]);
    }
    Ok(BoundedDigest {
        bytes: file_bytes,
        sha256: format!("{:x}", hasher.finalize()),
    })
}

fn validate_stage_snapshot_semantics(root: &Path, snapshot: &StageSnapshot) -> ManagedResult<()> {
    let mut paths = BTreeSet::new();
    if snapshot.directories.is_empty()
        || snapshot
            .directories
            .iter()
            .all(|directory| directory.path != root)
    {
        return Err(ManagedError::new(
            "recovery_needed",
            "transaction stage snapshot has no root directory",
        ));
    }
    for directory in &snapshot.directories {
        require_absolute_normal(&directory.path, "transaction stage directory")?;
        if directory.mode != 0o700
            || !directory.path.starts_with(root)
            || !paths.insert(directory.path.clone())
        {
            return Err(ManagedError::new(
                "recovery_needed",
                "transaction stage directory inventory is invalid",
            ));
        }
    }
    for file in &snapshot.files {
        require_absolute_normal(&file.path, "transaction stage file")?;
        if !matches!(file.mode, 0o600 | 0o700)
            || file.sha256.len() != 64
            || !file.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !file.path.starts_with(root)
            || !paths.insert(file.path.clone())
        {
            return Err(ManagedError::new(
                "recovery_needed",
                "transaction stage file inventory is invalid",
            ));
        }
    }
    Ok(())
}

fn validate_owned_snapshot_semantics(
    snapshot: Option<&OwnedStageFile>,
    path: &Path,
    mode: u32,
    digest: &str,
) -> ManagedResult<()> {
    let snapshot = snapshot.ok_or_else(|| {
        ManagedError::new("recovery_needed", "transaction inode snapshot is absent")
    })?;
    require_absolute_normal(&snapshot.path, "transaction-owned file")?;
    path_text(&snapshot.path)?;
    if snapshot.path != path
        || snapshot.mode != mode
        || snapshot.sha256 != digest
        || snapshot.sha256.len() != 64
        || !snapshot
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ManagedError::new(
            "recovery_needed",
            "transaction inode snapshot is not exact",
        ));
    }
    Ok(())
}

fn validate_stage_snapshot_live(root: &Path, snapshot: &StageSnapshot) -> ManagedResult<()> {
    validate_stage_snapshot_semantics(root, snapshot)?;
    if snapshot_stage(root)? != *snapshot {
        return Err(ManagedError::new(
            "recovery_needed",
            "the managed transaction stage changed",
        ));
    }
    Ok(())
}

fn open_validated_absolute_directory(path: &Path, private: bool) -> ManagedResult<File> {
    require_absolute_normal(path, "directory")?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory =
        File::from(open(Path::new("/"), flags, Mode::empty()).map_err(|error| {
            ManagedError::new(
                "recovery_needed",
                format!("cannot open root directory: {error}"),
            )
        })?);
    validate_opened_directory(&directory, false)?;
    let names = normal_components(path)?;
    for (index, name) in names.iter().enumerate() {
        directory = File::from(openat(&directory, *name, flags, Mode::empty()).map_err(
            |error| {
                ManagedError::new(
                    "recovery_needed",
                    format!("cannot open a directory component: {error}"),
                )
            },
        )?);
        validate_opened_directory(&directory, private && index + 1 == names.len())?;
    }
    Ok(directory)
}

fn stage_snapshot_root(snapshot: &StageSnapshot) -> ManagedResult<&Path> {
    snapshot
        .directories
        .iter()
        .map(|directory| directory.path.as_path())
        .min_by_key(|path| path.components().count())
        .ok_or_else(|| ManagedError::new("recovery_needed", "stage snapshot is empty"))
}

fn stage_is_exact_subset(expected: &StageSnapshot, current: &StageSnapshot) -> bool {
    let Ok(expected_root) = stage_snapshot_root(expected) else {
        return false;
    };
    let Ok(current_root) = stage_snapshot_root(current) else {
        return false;
    };
    expected_root == current_root
        && current
            .directories
            .iter()
            .all(|directory| expected.directories.contains(directory))
        && current
            .files
            .iter()
            .all(|file| expected.files.contains(file))
}

fn planned_stage_is_exact_subset(planned: &StageSnapshot, current: &StageSnapshot) -> bool {
    let Ok(planned_root) = stage_snapshot_root(planned) else {
        return false;
    };
    let Ok(current_root) = stage_snapshot_root(current) else {
        return false;
    };
    rescue_stage_snapshot_is_planned(planned)
        && planned_root == current_root
        && current.directories.iter().all(|directory| {
            planned
                .directories
                .iter()
                .any(|owned| owned.path == directory.path && owned.mode == directory.mode)
        })
        && current.files.iter().all(|file| {
            planned
                .files
                .iter()
                .any(|owned| owned.path == file.path && owned.mode == file.mode)
        })
}

fn remove_remaining_exact_stage(snapshot: &StageSnapshot, cleanup: &str) -> ManagedResult<()> {
    let root = stage_snapshot_root(snapshot)?;
    let Some(current) = stage_snapshot_if_present(root)? else {
        return Ok(());
    };
    if !stage_is_exact_subset(snapshot, &current) {
        return Err(inexact_rescue_migration_state());
    }
    remove_exact_stage_with_progress(&current, Some(cleanup))
}

fn remove_remaining_planned_stage(snapshot: &StageSnapshot, cleanup: &str) -> ManagedResult<()> {
    let root = stage_snapshot_root(snapshot)?;
    let Some(current) = stage_snapshot_if_present(root)? else {
        return Ok(());
    };
    if !planned_stage_is_exact_subset(snapshot, &current) {
        return Err(inexact_rescue_migration_state());
    }
    remove_exact_stage_with_progress(&current, Some(cleanup))
}

fn remove_exact_stage(snapshot: &StageSnapshot) -> ManagedResult<()> {
    remove_exact_stage_with_progress(snapshot, None)
}

fn remove_exact_stage_with_progress(
    snapshot: &StageSnapshot,
    cleanup: Option<&str>,
) -> ManagedResult<()> {
    let mut cleanup_step = 0_usize;
    let root = snapshot
        .directories
        .iter()
        .map(|directory| &directory.path)
        .min_by_key(|path| path.components().count())
        .ok_or_else(|| ManagedError::new("recovery_needed", "stage snapshot is empty"))?;
    match fs::symlink_metadata(root) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(ManagedError::io(
                "recovery_needed",
                "cannot inspect transaction stage",
                error,
            ));
        }
        Ok(_) => validate_stage_snapshot_live(root, snapshot)?,
    }
    for expected in &snapshot.files {
        let parent = open_validated_absolute_directory(expected.path.parent().unwrap(), true)?;
        let name = expected.path.file_name().unwrap();
        let opened = File::from(
            openat(
                &parent,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|error| {
                ManagedError::new(
                    "recovery_needed",
                    format!("cannot reopen stage file: {error}"),
                )
            })?,
        );
        let metadata = opened.metadata().map_err(|error| {
            ManagedError::io(
                "recovery_needed",
                "cannot inspect reopened stage file",
                error,
            )
        })?;
        if metadata.dev() != expected.device
            || metadata.ino() != expected.inode
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != expected.mode
        {
            return Err(ManagedError::new(
                "recovery_needed",
                "transaction stage file changed before unlink",
            ));
        }
        unlinkat(&parent, name, AtFlags::empty()).map_err(|error| {
            ManagedError::new(
                "recovery_needed",
                format!("cannot unlink stage file: {error}"),
            )
        })?;
        if let Some(cleanup) = cleanup {
            cleanup_step += 1;
            test_abort_rescue_cleanup(cleanup, cleanup_step);
        }
    }
    let mut directories = snapshot.directories.clone();
    directories.sort_by_key(|directory| std::cmp::Reverse(directory.path.components().count()));
    for expected in directories {
        let parent = open_validated_absolute_directory(expected.path.parent().unwrap(), false)?;
        let name = expected.path.file_name().unwrap();
        let opened = File::from(
            openat(
                &parent,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| {
                ManagedError::new(
                    "recovery_needed",
                    format!("cannot reopen stage directory: {error}"),
                )
            })?,
        );
        let metadata = opened.metadata().map_err(|error| {
            ManagedError::io(
                "recovery_needed",
                "cannot inspect reopened stage directory",
                error,
            )
        })?;
        if metadata.dev() != expected.device
            || metadata.ino() != expected.inode
            || metadata.mode() & 0o777 != expected.mode
        {
            return Err(ManagedError::new(
                "recovery_needed",
                "transaction stage directory changed before removal",
            ));
        }
        unlinkat(&parent, name, AtFlags::REMOVEDIR).map_err(|error| {
            ManagedError::new(
                "recovery_needed",
                format!("cannot remove expected-empty stage directory: {error}"),
            )
        })?;
        if let Some(cleanup) = cleanup {
            cleanup_step += 1;
            test_abort_rescue_cleanup(cleanup, cleanup_step);
        }
    }
    sync_directory(root.parent().unwrap())
}

fn restore_plugin_snapshot(transaction: &InstallTransaction) -> ManagedResult<()> {
    let plugin_stage_cleanup = authenticated_live_plugin_stage(transaction)?;
    for (target, backup, existed) in [
        (
            &transaction.helper,
            &transaction.helper_backup,
            transaction.prior_helper_present,
        ),
        (
            &transaction.pointer,
            &transaction.pointer_backup,
            transaction.prior_pointer_present,
        ),
    ] {
        if backup.exists() {
            remove_if_exists(target)?;
            fs::rename(backup, target).map_err(|error| {
                ManagedError::io("recovery_needed", "cannot restore plugin backup", error)
            })?;
        } else if !existed {
            remove_if_exists(target)?;
        } else if !target.exists() {
            return Err(ManagedError::new(
                "recovery_needed",
                "prior plugin asset has no backup",
            ));
        }
    }
    if let Some(snapshot) = &plugin_stage_cleanup {
        remove_exact_stage(snapshot)?;
    } else if transaction.plugin_stage.exists() {
        return Err(ManagedError::new(
            "recovery_needed",
            "transaction has an unauthenticated plugin stage",
        ));
    }
    if transaction.generation_stage.exists() {
        let snapshot = transaction
            .generation_stage_snapshot
            .as_ref()
            .ok_or_else(|| {
                ManagedError::new(
                    "recovery_needed",
                    "transaction has an unauthenticated generation stage",
                )
            })?;
        remove_exact_stage(snapshot)?;
    }
    if transaction.helper.parent().unwrap().exists() {
        sync_directory(transaction.helper.parent().unwrap())?;
    }
    sync_directory(transaction.pointer.parent().unwrap())
}

fn authenticated_live_plugin_stage(
    transaction: &InstallTransaction,
) -> ManagedResult<Option<StageSnapshot>> {
    if !transaction.plugin_stage.exists() {
        return Ok(None);
    }
    let snapshot = transaction.plugin_stage_snapshot.as_ref().ok_or_else(|| {
        ManagedError::new(
            "recovery_needed",
            "transaction has an unauthenticated plugin stage",
        )
    })?;
    for (helper, pointer) in [(true, true), (false, true), (false, false)] {
        let candidate = plugin_stage_subset(transaction, snapshot, helper, pointer);
        if validate_stage_snapshot_live(&transaction.plugin_stage, &candidate).is_ok() {
            return Ok(Some(candidate));
        }
    }
    Err(ManagedError::new(
        "recovery_needed",
        "live plugin stage is not an exact reachable transaction subset",
    ))
}

fn cleanup_transaction_artifacts(transaction: &InstallTransaction) -> ManagedResult<()> {
    for backup in [&transaction.helper_backup, &transaction.pointer_backup] {
        remove_if_exists(backup)?;
    }
    if let Some(snapshot) = &transaction.plugin_stage_snapshot {
        remove_exact_stage(snapshot)?;
    } else if transaction.plugin_stage.exists() {
        return Err(ManagedError::new(
            "recovery_needed",
            "transaction has an unauthenticated plugin stage",
        ));
    }
    Ok(())
}

fn prove_prior_state(stable_root: &Path, transaction: &InstallTransaction) -> ManagedResult<()> {
    match &transaction.prior_record {
        Some(record) if record.state == InstallState::Removed => {
            validate_removed_record_for_reinstall(record, stable_root)
        }
        Some(record) => validate_record(record, stable_root),
        None if !stable_root.join(OWNERSHIP_FILE).exists()
            && !transaction.helper.exists()
            && !transaction.pointer.exists() =>
        {
            Ok(())
        }
        None => Err(ManagedError::new(
            "recovery_needed",
            "first-install rollback is not exact",
        )),
    }
}

fn clean_stale_stages(stable_root: &Path) -> ManagedResult<()> {
    let generations = stable_root.join("generations");
    if !generations.exists() {
        return Ok(());
    }
    validate_private_directory(&generations, 0o700)?;
    for entry in fs::read_dir(&generations).map_err(|error| {
        ManagedError::io("generation_failed", "cannot inspect generations", error)
    })? {
        let entry = entry.map_err(|error| {
            ManagedError::io(
                "generation_failed",
                "cannot inspect generation entry",
                error,
            )
        })?;
        if entry.file_name().to_string_lossy().starts_with(".stage-") {
            return Err(ManagedError::new(
                "ownership_conflict",
                "an unauthenticated generation stage was found",
            ));
        }
    }
    sync_directory(&generations)
}

fn remove_superseded_generation(
    stable_root: &Path,
    prior: &OwnershipRecord,
    current: &OwnershipRecord,
    snapshot: Option<&StageSnapshot>,
) -> ManagedResult<()> {
    if prior.state == InstallState::Removed {
        return Ok(());
    }
    if prior.pi_package_source == current.pi_package_source {
        return Ok(());
    }
    let Some(directory) = prior.pi_package_source.parent() else {
        return Ok(());
    };
    if directory.parent() != Some(stable_root.join("generations").as_path()) {
        return Err(ManagedError::new(
            "ownership_record_invalid",
            "prior generation is outside the managed generations root",
        ));
    }
    let snapshot = snapshot.ok_or_else(|| {
        ManagedError::new(
            "recovery_needed",
            "superseded generation has no authenticated inode snapshot",
        )
    })?;
    validate_prior_generation_snapshot_semantics(prior, snapshot)?;
    validate_stage_snapshot_live(directory, snapshot)?;
    remove_exact_stage(snapshot)
}

fn remove_created_generation(transaction: &InstallTransaction) -> ManagedResult<()> {
    match fs::symlink_metadata(&transaction.generation) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(ManagedError::io(
                "recovery_needed",
                "cannot inspect transaction-created generation",
                error,
            ));
        }
        Ok(_) => {}
    }
    let staged = transaction
        .generation_stage_snapshot
        .as_ref()
        .ok_or_else(|| {
            ManagedError::new(
                "recovery_needed",
                "transaction-created generation has no authenticated inode snapshot",
            )
        })?;
    let published = relocate_stage_snapshot(
        staged,
        &transaction.generation_stage,
        &transaction.generation,
    )?;
    validate_stage_snapshot_semantics(&transaction.generation, &published)?;
    validate_stage_snapshot_live(&transaction.generation, &published)?;
    remove_exact_stage(&published)
}

fn relocate_stage_snapshot(
    snapshot: &StageSnapshot,
    source: &Path,
    destination: &Path,
) -> ManagedResult<StageSnapshot> {
    let relocate = |path: &Path| {
        path.strip_prefix(source)
            .map(|relative| destination.join(relative))
            .map_err(|_| {
                ManagedError::new(
                    "recovery_needed",
                    "transaction snapshot path escaped its publication source",
                )
            })
    };
    Ok(StageSnapshot {
        directories: snapshot
            .directories
            .iter()
            .map(|directory| {
                Ok(OwnedDirectory {
                    path: relocate(&directory.path)?,
                    device: directory.device,
                    inode: directory.inode,
                    mode: directory.mode,
                })
            })
            .collect::<ManagedResult<_>>()?,
        files: snapshot
            .files
            .iter()
            .map(|file| {
                Ok(OwnedStageFile {
                    path: relocate(&file.path)?,
                    device: file.device,
                    inode: file.inode,
                    mode: file.mode,
                    sha256: file.sha256.clone(),
                })
            })
            .collect::<ManagedResult<_>>()?,
    })
}

fn owned_file(path: &Path, mode: u32) -> ManagedResult<OwnedFile> {
    validate_owned_regular_file(path, mode, "generation_failed")?;
    Ok(OwnedFile {
        path: path.to_path_buf(),
        sha256: digest_file(path)?,
        mode,
    })
}

fn validate_owned_regular_file(path: &Path, mode: u32, code: &'static str) -> ManagedResult<()> {
    let file = open_validated_absolute_file(path)?;
    validate_opened_owned_regular_file(&file, mode, code).map(|_| ())
}

fn validate_opened_owned_regular_file(
    file: &File,
    mode: u32,
    code: &'static str,
) -> ManagedResult<fs::Metadata> {
    let metadata = file
        .metadata()
        .map_err(|error| ManagedError::io(code, "cannot inspect opened owned file", error))?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != mode
    {
        return Err(ManagedError::new(
            code,
            "opened owned file has unsafe identity or permissions",
        ));
    }
    Ok(metadata)
}

fn validate_owned_file_digest(
    path: &Path,
    mode: u32,
    expected_digest: &str,
    code: &'static str,
) -> ManagedResult<()> {
    let mut file = open_validated_absolute_file(path)?;
    let metadata = validate_opened_owned_regular_file(&file, mode, code)?;
    if metadata.len() > MAX_OWNED_FILE_BYTES {
        return Err(ManagedError::new(
            code,
            "owned file exceeds the hashing limit",
        ));
    }
    if digest_opened_owned_file(&mut file, metadata.len(), code)? != expected_digest {
        return Err(ManagedError::new(code, "a recorded owned file changed"));
    }
    Ok(())
}

fn copy_owned_file(source: &Path, destination: &Path, mode: u32) -> ManagedResult<()> {
    let mut input = open_validated_absolute_file(source)?;
    let metadata = validate_opened_external_file(&input, mode & 0o100 != 0)?;
    if metadata.len() > MAX_OWNED_FILE_BYTES {
        return Err(ManagedError::new(
            "bundle_invalid",
            "bundle file exceeds the copy limit",
        ));
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(destination)
        .map_err(|error| {
            ManagedError::io("generation_failed", "cannot create owned file", error)
        })?;
    let mut total = 0_u64;
    let mut hasher = Sha256::new();
    let copied = copy_bounded_reader(
        &mut input,
        &mut output,
        MAX_OWNED_FILE_BYTES,
        &mut total,
        MAX_OWNED_FILE_BYTES,
        &mut hasher,
    )?;
    if copied != metadata.len() {
        return Err(ManagedError::new(
            "bundle_invalid",
            "bundle file size changed while it was copied",
        ));
    }
    output
        .sync_all()
        .map_err(|error| ManagedError::io("generation_failed", "cannot sync owned file", error))?;
    fs::set_permissions(destination, fs::Permissions::from_mode(mode)).map_err(|error| {
        ManagedError::io("generation_failed", "cannot set owned file mode", error)
    })?;
    validate_owned_regular_file(destination, mode, "generation_failed")
}

fn copy_owned_tree(source: &Path, destination: &Path) -> ManagedResult<String> {
    let source = open_validated_absolute_directory(source, false)
        .map_err(|error| ManagedError::new("bundle_invalid", error.to_string()))?;
    copy_opened_tree(source, destination).map(|snapshot| snapshot.digest)
}

fn copy_opened_tree(source: File, destination: &Path) -> ManagedResult<TreeSnapshot> {
    fs::create_dir(destination).map_err(|error| {
        ManagedError::io("generation_failed", "cannot create owned tree", error)
    })?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700)).map_err(|error| {
        ManagedError::io("generation_failed", "cannot protect owned tree", error)
    })?;
    let destination = open_validated_absolute_directory(destination, true)?;
    let mut state = TreeWalkState {
        entries: 0,
        total_bytes: 0,
        files: Vec::new(),
        tree_hasher: Sha256::new(),
    };
    copy_opened_directory(&source, &destination, Path::new(""), 0, &mut state)?;
    Ok(TreeSnapshot {
        files: state.files,
        digest: format!("{:x}", state.tree_hasher.finalize()),
    })
}

fn copy_opened_directory(
    source: &File,
    destination: &File,
    relative: &Path,
    depth: usize,
    state: &mut TreeWalkState,
) -> ManagedResult<()> {
    let entries = Dir::read_from(source).map_err(|error| {
        ManagedError::new(
            "bundle_invalid",
            format!("cannot open bundle directory stream: {error}"),
        )
    })?;
    let mut names = Vec::<Vec<u8>>::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            ManagedError::new(
                "bundle_invalid",
                format!("cannot enumerate opened bundle directory: {error}"),
            )
        })?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        state.entries = state
            .entries
            .checked_add(1)
            .ok_or_else(|| ManagedError::new("bundle_invalid", "bundle entry count overflowed"))?;
        if state.entries > MAX_PURGE_ENTRIES {
            return Err(ManagedError::new(
                "bundle_invalid",
                "bundle tree exceeds bounded traversal limits",
            ));
        }
        names.push(name.to_vec());
    }
    names.sort();

    for name in names {
        let name = OsStr::from_bytes(&name);
        let opened = File::from(
            openat(
                source,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|error| {
                ManagedError::new(
                    "bundle_invalid",
                    format!("cannot open bundle tree entry: {error}"),
                )
            })?,
        );
        let metadata = opened.metadata().map_err(|error| {
            ManagedError::io(
                "bundle_invalid",
                "cannot inspect opened bundle entry",
                error,
            )
        })?;
        let child_relative = relative.join(name);
        if metadata.is_dir() {
            let child_depth = depth.checked_add(1).ok_or_else(|| {
                ManagedError::new("bundle_invalid", "bundle tree depth overflowed")
            })?;
            if child_depth > MAX_PURGE_DEPTH {
                return Err(ManagedError::new(
                    "bundle_invalid",
                    "bundle tree exceeds bounded traversal limits",
                ));
            }
            validate_opened_directory(&opened, false)
                .map_err(|error| ManagedError::new("bundle_invalid", error.to_string()))?;
            mkdirat(destination, name, Mode::from_bits_retain(0o700)).map_err(|error| {
                ManagedError::new(
                    "generation_failed",
                    format!("cannot create owned tree directory: {error}"),
                )
            })?;
            let target = File::from(
                openat(
                    destination,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|error| {
                    ManagedError::new(
                        "generation_failed",
                        format!("cannot open owned tree directory: {error}"),
                    )
                })?,
            );
            validate_opened_directory(&target, true)?;
            copy_opened_directory(&opened, &target, &child_relative, child_depth, state)?;
            target.sync_all().map_err(|error| {
                ManagedError::io(
                    "generation_failed",
                    "cannot sync owned tree directory",
                    error,
                )
            })?;
        } else if metadata.is_file() {
            if metadata.uid() != rustix::process::getuid().as_raw()
                || metadata.nlink() != 1
                || metadata.mode() & 0o022 != 0
                || metadata.len() > MAX_OWNED_FILE_BYTES
            {
                return Err(ManagedError::new(
                    "bundle_invalid",
                    "opened bundle file has unsafe identity, mode, link count, or size",
                ));
            }
            let mut target = File::from(
                openat(
                    destination,
                    name,
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::from_bits_retain(0o600),
                )
                .map_err(|error| {
                    ManagedError::new(
                        "generation_failed",
                        format!("cannot create owned tree file: {error}"),
                    )
                })?,
            );
            let path_bytes = child_relative.as_os_str().as_encoded_bytes();
            state
                .tree_hasher
                .update((path_bytes.len() as u64).to_be_bytes());
            state.tree_hasher.update(path_bytes);
            let mut opened = opened;
            let copied = copy_bounded_reader(
                &mut opened,
                &mut target,
                MAX_OWNED_FILE_BYTES,
                &mut state.total_bytes,
                MAX_PURGE_BYTES,
                &mut state.tree_hasher,
            )?;
            if copied != metadata.len() {
                return Err(ManagedError::new(
                    "bundle_invalid",
                    "bundle file size changed while it was copied",
                ));
            }
            fchmod(&target, Mode::from_bits_retain(0o600)).map_err(|error| {
                ManagedError::new(
                    "generation_failed",
                    format!("cannot protect owned tree file: {error}"),
                )
            })?;
            target.sync_all().map_err(|error| {
                ManagedError::io("generation_failed", "cannot sync owned tree file", error)
            })?;
            state.files.push(TreeSnapshotFile {
                relative: child_relative,
            });
        } else {
            return Err(ManagedError::new(
                "bundle_invalid",
                "bundle tree contains an unsupported entry",
            ));
        }
    }
    Ok(())
}

fn copy_bounded_reader<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    file_limit: u64,
    total: &mut u64,
    total_limit: u64,
    tree_hasher: &mut Sha256,
) -> ManagedResult<u64> {
    let mut file_bytes = 0_u64;
    let mut buffer = [0_u8; 8192];
    loop {
        let permitted = file_limit
            .saturating_sub(file_bytes)
            .min(total_limit.saturating_sub(*total));
        let request = usize::try_from(permitted.saturating_add(1).min(buffer.len() as u64))
            .unwrap_or(buffer.len());
        let read = reader.read(&mut buffer[..request]).map_err(|error| {
            ManagedError::io("bundle_invalid", "cannot read opened bundle file", error)
        })?;
        if read == 0 {
            break;
        }
        if read as u64 > permitted {
            return Err(ManagedError::new(
                "bundle_invalid",
                "bundle tree exceeds its actual-copy byte limit",
            ));
        }
        writer.write_all(&buffer[..read]).map_err(|error| {
            ManagedError::io("generation_failed", "cannot write owned tree file", error)
        })?;
        file_bytes += read as u64;
        *total += read as u64;
        tree_hasher.update(&buffer[..read]);
    }
    Ok(file_bytes)
}

fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> ManagedResult<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|error| ManagedError::io("generation_failed", "cannot create file", error))?;
    file.write_all(bytes)
        .map_err(|error| ManagedError::io("generation_failed", "cannot write file", error))?;
    file.sync_all()
        .map_err(|error| ManagedError::io("generation_failed", "cannot sync file", error))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| ManagedError::io("generation_failed", "cannot set file mode", error))?;
    validate_owned_regular_file(path, mode, "generation_failed")
}

fn tree_files(root: &Path) -> ManagedResult<Vec<PathBuf>> {
    Ok(snapshot_tree(root)?
        .files
        .into_iter()
        .map(|file| root.join(file.relative))
        .collect())
}

fn digest_tree(root: &Path) -> ManagedResult<String> {
    Ok(snapshot_tree(root)?.digest)
}

struct TreeSnapshotFile {
    relative: PathBuf,
}

struct TreeSnapshot {
    files: Vec<TreeSnapshotFile>,
    digest: String,
}

struct TreeWalkState {
    entries: usize,
    total_bytes: u64,
    files: Vec<TreeSnapshotFile>,
    tree_hasher: Sha256,
}

fn snapshot_tree(root: &Path) -> ManagedResult<TreeSnapshot> {
    let root = open_validated_absolute_directory(root, false)
        .map_err(|error| ManagedError::new("bundle_invalid", error.to_string()))?;
    snapshot_opened_tree(root)
}

fn snapshot_opened_tree(root: File) -> ManagedResult<TreeSnapshot> {
    let mut state = TreeWalkState {
        entries: 0,
        total_bytes: 0,
        files: Vec::new(),
        tree_hasher: Sha256::new(),
    };
    snapshot_opened_directory(&root, Path::new(""), 0, &mut state)?;
    Ok(TreeSnapshot {
        files: state.files,
        digest: format!("{:x}", state.tree_hasher.finalize()),
    })
}

fn snapshot_opened_directory(
    directory: &File,
    relative: &Path,
    depth: usize,
    state: &mut TreeWalkState,
) -> ManagedResult<()> {
    let entries = Dir::read_from(directory).map_err(|error| {
        ManagedError::new(
            "bundle_invalid",
            format!("cannot open package directory stream: {error}"),
        )
    })?;
    let mut names = Vec::<Vec<u8>>::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            ManagedError::new(
                "bundle_invalid",
                format!("cannot enumerate opened package directory: {error}"),
            )
        })?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        state.entries = state.entries.checked_add(1).ok_or_else(|| {
            ManagedError::new("bundle_invalid", "package tree entry count overflowed")
        })?;
        if state.entries > MAX_PURGE_ENTRIES {
            return Err(ManagedError::new(
                "bundle_invalid",
                "package tree exceeds bounded traversal limits",
            ));
        }
        names.push(name.to_vec());
    }
    names.sort();

    for name in names {
        let name = OsStr::from_bytes(&name);
        let opened = File::from(
            openat(
                directory,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|error| {
                ManagedError::new(
                    "bundle_invalid",
                    format!("cannot open package tree entry: {error}"),
                )
            })?,
        );
        let metadata = opened.metadata().map_err(|error| {
            ManagedError::io(
                "bundle_invalid",
                "cannot inspect opened package entry",
                error,
            )
        })?;
        let child_relative = relative.join(name);
        if metadata.is_dir() {
            let child_depth = depth.checked_add(1).ok_or_else(|| {
                ManagedError::new("bundle_invalid", "package tree depth overflowed")
            })?;
            if child_depth > MAX_PURGE_DEPTH {
                return Err(ManagedError::new(
                    "bundle_invalid",
                    "package tree exceeds bounded traversal limits",
                ));
            }
            validate_opened_directory(&opened, false)
                .map_err(|error| ManagedError::new("bundle_invalid", error.to_string()))?;
            snapshot_opened_directory(&opened, &child_relative, child_depth, state)?;
        } else if metadata.is_file() {
            if metadata.uid() != rustix::process::getuid().as_raw()
                || metadata.nlink() != 1
                || metadata.mode() & 0o022 != 0
                || metadata.len() > MAX_OWNED_FILE_BYTES
            {
                return Err(ManagedError::new(
                    "bundle_invalid",
                    "opened package file has unsafe identity, mode, link count, or size",
                ));
            }
            let path_bytes = child_relative.as_os_str().as_encoded_bytes();
            state
                .tree_hasher
                .update((path_bytes.len() as u64).to_be_bytes());
            state.tree_hasher.update(path_bytes);
            let mut opened = opened;
            let read = digest_bounded_reader_with_tree(
                &mut opened,
                MAX_OWNED_FILE_BYTES,
                &mut state.total_bytes,
                MAX_PURGE_BYTES,
                Some(&mut state.tree_hasher),
            )?;
            if read.bytes != metadata.len() {
                return Err(ManagedError::new(
                    "bundle_invalid",
                    "package file size changed while it was read",
                ));
            }
            state.files.push(TreeSnapshotFile {
                relative: child_relative,
            });
        } else {
            return Err(ManagedError::new(
                "bundle_invalid",
                "package tree contains an unsupported entry",
            ));
        }
    }
    Ok(())
}

struct BoundedRead {
    bytes: u64,
}

#[cfg(test)]
fn digest_bounded_reader<R: Read>(
    reader: &mut R,
    file_limit: u64,
    total: &mut u64,
    total_limit: u64,
) -> ManagedResult<u64> {
    digest_bounded_reader_with_tree(reader, file_limit, total, total_limit, None)
        .map(|value| value.bytes)
}

fn digest_bounded_reader_with_tree<R: Read>(
    reader: &mut R,
    file_limit: u64,
    total: &mut u64,
    total_limit: u64,
    mut tree_hasher: Option<&mut Sha256>,
) -> ManagedResult<BoundedRead> {
    let mut file_bytes = 0_u64;
    let mut buffer = [0_u8; 8192];
    loop {
        let file_remaining = file_limit.saturating_sub(file_bytes);
        let total_remaining = total_limit.saturating_sub(*total);
        let permitted = file_remaining.min(total_remaining);
        let request = usize::try_from(permitted.saturating_add(1).min(buffer.len() as u64))
            .unwrap_or(buffer.len());
        let read = reader.read(&mut buffer[..request]).map_err(|error| {
            ManagedError::io("bundle_invalid", "cannot read opened package file", error)
        })?;
        if read == 0 {
            break;
        }
        if read as u64 > permitted {
            return Err(ManagedError::new(
                "bundle_invalid",
                "package tree exceeds its actual-read byte limit",
            ));
        }
        file_bytes += read as u64;
        *total += read as u64;
        if let Some(tree_hasher) = tree_hasher.as_deref_mut() {
            tree_hasher.update(&buffer[..read]);
        }
    }
    Ok(BoundedRead { bytes: file_bytes })
}

fn digest_file(path: &Path) -> ManagedResult<String> {
    let mut file = open_validated_absolute_file(path)?;
    let metadata = file.metadata().map_err(|error| {
        ManagedError::io("owned_asset_modified", "cannot inspect owned file", error)
    })?;
    digest_opened_owned_file(&mut file, metadata.len(), "owned_asset_modified")
}

fn read_bounded_opened_utf8<R: Read>(
    file: &mut R,
    expected_len: u64,
    limit: u64,
    code: &'static str,
) -> ManagedResult<String> {
    let bytes = read_bounded_opened_bytes(file, expected_len, limit, code)?;
    String::from_utf8(bytes)
        .map_err(|_| ManagedError::new(code, "managed text file is not valid UTF-8"))
}

fn read_bounded_opened_bytes<R: Read>(
    file: &mut R,
    expected_len: u64,
    limit: u64,
    code: &'static str,
) -> ManagedResult<Vec<u8>> {
    if expected_len > limit {
        return Err(ManagedError::new(code, "managed file exceeds its limit"));
    }
    let capacity = usize::try_from(expected_len)
        .map_err(|_| ManagedError::new(code, "managed text file size cannot be represented"))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| ManagedError::io(code, "cannot read a managed text file", error))?;
    if bytes.len() as u64 != expected_len {
        return Err(ManagedError::new(
            code,
            "managed file size changed while it was read",
        ));
    }
    Ok(bytes)
}

fn parse_bounded_opened_json<T: DeserializeOwned, R: Read>(
    file: &mut R,
    expected_len: u64,
    limit: u64,
    code: &'static str,
) -> ManagedResult<T> {
    let bytes = read_bounded_opened_bytes(file, expected_len, limit, code)?;
    serde_json::from_slice(&bytes).map_err(|error| ManagedError::new(code, error.to_string()))
}

fn digest_opened_owned_file(
    file: &mut File,
    expected_len: u64,
    code: &'static str,
) -> ManagedResult<String> {
    if expected_len > MAX_OWNED_FILE_BYTES {
        return Err(ManagedError::new(
            code,
            "owned file exceeds the hashing limit",
        ));
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    let mut total = 0_u64;
    loop {
        let permitted = MAX_OWNED_FILE_BYTES.saturating_sub(total);
        let request = usize::try_from(permitted.saturating_add(1).min(buffer.len() as u64))
            .unwrap_or(buffer.len());
        let read = file
            .read(&mut buffer[..request])
            .map_err(|error| ManagedError::io(code, "cannot hash an owned file", error))?;
        if read == 0 {
            break;
        }
        if read as u64 > permitted {
            return Err(ManagedError::new(
                code,
                "owned file exceeds the actual-read hashing limit",
            ));
        }
        total += read as u64;
        hasher.update(&buffer[..read]);
    }
    if total != expected_len {
        return Err(ManagedError::new(
            code,
            "owned file size changed while it was hashed",
        ));
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn sync_tree(root: &Path) -> ManagedResult<()> {
    for file in tree_files(root)? {
        File::open(&file)
            .and_then(|file| file.sync_all())
            .map_err(|error| {
                ManagedError::io("generation_failed", "cannot sync tree file", error)
            })?;
    }
    let mut directories = BTreeSet::new();
    directories.insert(root.to_path_buf());
    for file in tree_files(root)? {
        let mut parent = file.parent();
        while let Some(directory) = parent {
            if !directory.starts_with(root) {
                break;
            }
            directories.insert(directory.to_path_buf());
            parent = directory.parent();
        }
    }
    for directory in directories.into_iter().rev() {
        sync_directory(&directory)?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> ManagedResult<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            ManagedError::io(
                "generation_failed",
                "cannot sync a managed directory",
                error,
            )
        })
}

fn random_hex() -> ManagedResult<String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| {
        ManagedError::new(
            "generation_failed",
            format!("randomness unavailable: {error}"),
        )
    })?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn legacy_source(plugin_root: &Path) -> PathBuf {
    plugin_root
        .parent()
        .and_then(Path::parent)
        .unwrap_or(plugin_root)
        .join("integrations/pi")
}

fn path_text(path: &Path) -> ManagedResult<&str> {
    let value = path.to_str().ok_or_else(|| {
        ManagedError::new("unsafe_install_path", "persisted paths must be valid UTF-8")
    })?;
    if value.is_empty() || value.contains(['\r', '\n']) || value.len() + 1 > MAX_POINTER_BYTES {
        return Err(ManagedError::new(
            "unsafe_install_path",
            "persisted paths must be non-empty, one-line, and pointer-bounded",
        ));
    }
    Ok(value)
}

fn remove_if_exists(path: &Path) -> ManagedResult<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ManagedError::io(
            "removal_failed",
            "cannot remove the recorded managed asset",
            error,
        )),
    }
}

fn print_state(state: &InstallState) {
    match state {
        InstallState::Ready => println!("ready"),
        InstallState::PiAdapterPending => println!("Pi adapter pending"),
        InstallState::Failed => println!("failed"),
        InstallState::Removing => println!("removing"),
        InstallState::UnregisterPending => println!("unregister pending"),
        InstallState::Unregistering => println!("unregistering"),
        InstallState::FinalizingRemoval => println!("finalizing removal"),
        InstallState::Removed => println!("removed"),
    }
}

#[cfg(test)]
mod compatibility_tests {
    use super::{parse_pi_version, pi_version_supported};

    #[test]
    fn interface_version_parser_rejects_arbitrary_or_prerelease_suffixes() {
        // Break caught: trimming every non-digit suffix accepted malformed output such as
        // `0.84.2garbage` as a compatible installed Pi interface.
        assert_eq!(parse_pi_version(b"0.84.2\n"), Some((0, 84, 2)));
        for malformed in [
            b"garbage 0.84.2".as_slice(),
            b"pi 0.84.2".as_slice(),
            b"pi 0.84.2garbage".as_slice(),
            b"pi 0.84.2-beta".as_slice(),
            b"pi 0.84".as_slice(),
            b"pi 0.84.2.1".as_slice(),
        ] {
            assert_eq!(parse_pi_version(malformed), None, "{malformed:?}");
        }
    }

    #[test]
    fn pi_compatibility_has_a_minimum_without_an_upper_ceiling() {
        // Break caught: managed install accepts Pi 0.84.1 or older, whose supported dependency
        // graph contains the audited vulnerable paths.
        assert!(!pi_version_supported((0, 84, 1)));
        assert!(pi_version_supported((0, 84, 2)));
        assert!(pi_version_supported((1, 0, 0)));
    }
}

#[cfg(test)]
mod process_drain_deadline_tests {
    use super::{PROCESS_DRAIN_TIMEOUT, bounded_stop_deadline, ensure_drain_deadline};

    #[test]
    fn shared_deadline_prevents_multiple_entries_from_summing_retirement_windows() {
        let shared = tokio::time::Instant::now() + std::time::Duration::from_millis(10);
        let first_entry = bounded_stop_deadline(shared, PROCESS_DRAIN_TIMEOUT).unwrap();
        let second_entry = bounded_stop_deadline(shared, PROCESS_DRAIN_TIMEOUT).unwrap();
        assert!(
            first_entry <= shared && second_entry <= shared,
            "multiple retirement entries received fresh per-entry drain windows"
        );
        assert_eq!(first_entry, shared);
        assert_eq!(second_entry, shared);
    }

    #[test]
    fn expired_shared_deadline_rejects_empty_registry_after_work_began() {
        let expired = tokio::time::Instant::now() - std::time::Duration::from_millis(1);
        assert!(ensure_drain_deadline(expired, true).is_err());
    }
}

#[cfg(test)]
mod descriptor_tree_tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn predecessor_record(schema_version: u32) -> Value {
        let digest = "a".repeat(64);
        let mut value = serde_json::json!({
            "schema_version": schema_version,
            "state": "Ready",
            "plugin_version": "1.0.0",
            "broker_digest": digest,
            "pi_package_digest": "b".repeat(64),
            "pi_package_source": "/stable/generations/one/pi",
            "pi_config_path": "/home/.pi/agent/settings.json",
            "pi_package_entry": "/stable/generations/one/pi",
            "rescue_path": "/stable/rescue/uninstall.sh",
            "install_kind": "managed",
            "plugin_root": "/plugin",
            "stable_binary": "/stable/generations/one/bin/herdr-a2a",
            "ownership_path": "/stable/ownership.json",
            "owned_files": []
        });
        if schema_version == OWNERSHIP_SCHEMA {
            value["plugin_state_root"] = serde_json::json!("/plugin-state");
            value["rescue_marker_digest"] = serde_json::json!("c".repeat(64));
        }
        value
    }

    #[test]
    fn embedded_schema_v2_record_without_purge_fields_decodes_without_authority() {
        // Break caught: a pre-Round-3 journal embeds OwnershipRecord directly and cannot recover
        // when the newly mandatory purge_authority field is absent.
        let record: OwnershipRecord =
            serde_json::from_value(predecessor_record(2)).expect("schema v2 must decode");
        assert!(!record.purge_authority);
        assert!(record.plugin_state_root.as_os_str().is_empty());
    }

    #[test]
    fn embedded_schema_v2_record_with_internal_false_authority_decodes_safely() {
        // Break caught: current transaction serialization includes the in-memory false flag for
        // a v2 prior record even though the root v2 wire format must continue to omit it.
        let mut value = predecessor_record(2);
        value["purge_authority"] = serde_json::json!(false);
        let record: OwnershipRecord =
            serde_json::from_value(value).expect("embedded schema v2 false must decode");
        assert!(!record.purge_authority);
        assert!(record.plugin_state_root.as_os_str().is_empty());
    }

    #[test]
    fn prior_rescue_marker_proof_preserves_only_the_legacy_no_authority_exception() {
        // Break caught: requiring a v3-only duplicate digest strands schema v2, while accepting an
        // owned digest without classifying the record weakens authoritative-v2/v3 marker proof.
        let marker_bytes = b"authenticated legacy marker\n";
        let marker = OwnedFile {
            path: PathBuf::from("/stable/rescue/owner-v1"),
            sha256: sha256_bytes(marker_bytes),
            mode: 0o600,
        };
        let legacy: OwnershipRecord = serde_json::from_value(predecessor_record(2)).unwrap();
        assert!(prior_rescue_marker_is_authenticated(
            &legacy,
            &marker,
            marker_bytes
        ));
        assert!(!prior_rescue_marker_is_authenticated(
            &legacy,
            &marker,
            b"changed marker\n"
        ));

        let mut authoritative_v2 = legacy.clone();
        authoritative_v2.purge_authority = true;
        authoritative_v2.plugin_state_root = PathBuf::from("/plugin-state");
        assert!(!prior_rescue_marker_is_authenticated(
            &authoritative_v2,
            &marker,
            marker_bytes
        ));
        authoritative_v2.rescue_marker_digest = marker.sha256.clone();
        assert!(prior_rescue_marker_is_authenticated(
            &authoritative_v2,
            &marker,
            marker_bytes
        ));

        let mut current: OwnershipRecord =
            serde_json::from_value(predecessor_record(OWNERSHIP_SCHEMA)).unwrap();
        assert!(!prior_rescue_marker_is_authenticated(
            &current,
            &marker,
            marker_bytes
        ));
        current.rescue_marker_digest = marker.sha256.clone();
        assert!(prior_rescue_marker_is_authenticated(
            &current,
            &marker,
            marker_bytes
        ));
    }

    #[test]
    fn embedded_legacy_schema_v3_record_derives_its_recorded_purge_authority() {
        // Break caught: compatibility either rejects an exact old v3 journal or strips authority
        // that its authenticated state-root shape already established.
        let record: OwnershipRecord = serde_json::from_value(predecessor_record(OWNERSHIP_SCHEMA))
            .expect("legacy schema v3 must decode");
        assert!(record.purge_authority);
        assert_eq!(record.plugin_state_root, Path::new("/plugin-state"));
    }

    #[test]
    fn embedded_legacy_schema_v3_record_rejects_incomplete_authority_shapes() {
        let mut missing_root = predecessor_record(OWNERSHIP_SCHEMA);
        missing_root
            .as_object_mut()
            .expect("record is an object")
            .remove("plugin_state_root");

        let mut empty_root = predecessor_record(OWNERSHIP_SCHEMA);
        empty_root["plugin_state_root"] = serde_json::json!("");

        let mut invalid_marker = predecessor_record(OWNERSHIP_SCHEMA);
        invalid_marker["rescue_marker_digest"] = serde_json::json!("not-a-digest");

        for incompatible in [missing_root, empty_root, invalid_marker] {
            assert!(serde_json::from_value::<OwnershipRecord>(incompatible).is_err());
        }
    }

    #[test]
    fn opened_tree_root_cannot_be_redirected_by_a_later_path_replacement() {
        let fixture = tempfile::tempdir().unwrap();
        let fixture_root = fixture.path().canonicalize().unwrap();
        let root = fixture_root.join("package");
        let moved = fixture_root.join("moved-package");
        let outside = fixture_root.join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.join("inside.txt"), "inside\n").unwrap();
        fs::write(outside.join("outside.txt"), "outside\n").unwrap();
        let opened = open_validated_absolute_directory(&root, false).unwrap();
        fs::rename(&root, &moved).unwrap();
        symlink(&outside, &root).unwrap();

        let snapshot = snapshot_opened_tree(opened).unwrap();

        assert_eq!(snapshot.files.len(), 1);
        assert_eq!(snapshot.files[0].relative, Path::new("inside.txt"));

        let destination = fixture_root.join("copied-package");
        let opened = open_validated_absolute_directory(&moved, false).unwrap();
        copy_opened_tree(opened, &destination).unwrap();
        assert_eq!(
            fs::read_to_string(destination.join("inside.txt")).unwrap(),
            "inside\n"
        );
        assert!(!destination.join("outside.txt").exists());
    }

    #[test]
    fn opened_stage_root_cannot_be_redirected_by_a_later_path_replacement() {
        // Break caught: purge/transaction snapshotting saved a child pathname and later followed
        // a replacement directory outside the authenticated root.
        let fixture = tempfile::tempdir().unwrap();
        let fixture_root = fixture.path().canonicalize().unwrap();
        let root = fixture_root.join("stage");
        let moved = fixture_root.join("moved-stage");
        let outside = fixture_root.join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.join("inside.txt"), "inside\n").unwrap();
        fs::write(outside.join("outside.txt"), "outside\n").unwrap();
        fs::set_permissions(root.join("inside.txt"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(
            outside.join("outside.txt"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let opened = open_validated_absolute_directory(&root, true).unwrap();
        fs::rename(&root, &moved).unwrap();
        symlink(&outside, &root).unwrap();

        let snapshot = snapshot_opened_stage(opened, &root).unwrap();

        assert_eq!(snapshot.files.len(), 1);
        assert_eq!(snapshot.files[0].path, root.join("inside.txt"));
        assert!(
            snapshot
                .files
                .iter()
                .all(|file| file.path != root.join("outside.txt"))
        );
    }

    struct EndlessReader;

    impl Read for EndlessReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            buffer.fill(b'x');
            Ok(buffer.len())
        }
    }

    #[test]
    fn actual_tree_reads_stop_at_the_shared_byte_budget_without_eof() {
        let mut total = 0_u64;
        let error = digest_bounded_reader(&mut EndlessReader, 16, &mut total, 24).unwrap_err();
        assert_eq!(error.code, "bundle_invalid");
        assert!(total <= 24);
    }

    #[test]
    fn actual_stage_reads_stop_at_the_shared_byte_budget_without_eof() {
        // Break caught: charging stale pathname metadata lets repeated stage-file replacement
        // drive actual purge/transaction reads beyond the aggregate budget.
        let mut total = 0_u64;
        let error =
            digest_bounded_stage_file(&mut EndlessReader, 16, &mut total, 24, "bounded_stage")
                .unwrap_err();
        assert_eq!(error.code, "bounded_stage");
        assert!(total <= 24);
    }

    #[test]
    fn bounded_text_reads_fail_closed_when_the_source_grows_past_fstat_length() {
        let error = read_bounded_opened_utf8(&mut EndlessReader, 1, 16, "bounded_text")
            .expect_err("a growing text file must not be accepted");
        assert_eq!(error.code, "bounded_text");
    }

    #[test]
    fn bounded_json_reads_fail_closed_when_the_source_grows_past_fstat_length() {
        // Break caught: parsing JSON directly from a same-handle file after fstat lets a growing
        // ownership, journal, Pi, or adapter input consume unbounded memory before removal.
        let error =
            parse_bounded_opened_json::<Value, _>(&mut EndlessReader, 1, 16, "bounded_json")
                .expect_err("a growing JSON file must not be accepted");
        assert_eq!(error.code, "bounded_json");
    }

    #[test]
    fn rescue_migration_recovery_phase_table_covers_every_adjacent_crash_state() {
        use RescueMigrationPhase::*;
        use RescueRecordState::{New as NewRecord, Other as OtherRecord, Prior as PriorRecord};
        use RescueRecoveryRoute::{
            BeforeNotice, Committed, NoticeCleanup, NoticeRollback, PriorRestore, StageCleanup,
        };
        use RescueTreeState::*;

        let live = |record, rescue, stage, backup| RescueMigrationLiveState {
            record,
            rescue,
            stage,
            backup,
        };
        let cases = [
            (
                Intent,
                live(PriorRecord, Prior, Absent, Absent),
                RescueRecoveryRoute::Intent,
            ),
            (
                Intent,
                live(PriorRecord, Prior, PlannedSubset, Absent),
                RescueRecoveryRoute::Intent,
            ),
            (
                Prepared,
                live(PriorRecord, Prior, New, Absent),
                BeforeNotice,
            ),
            (
                Prepared,
                live(PriorRecord, Absent, New, Prior),
                BeforeNotice,
            ),
            (
                PriorBackingUp,
                live(PriorRecord, Prior, New, Absent),
                BeforeNotice,
            ),
            (
                PriorBackingUp,
                live(PriorRecord, Absent, New, Prior),
                BeforeNotice,
            ),
            (
                PriorBackedUp,
                live(PriorRecord, Absent, New, Prior),
                BeforeNotice,
            ),
            (
                PriorBackedUp,
                live(PriorRecord, New, Absent, Prior),
                NoticeRollback,
            ),
            (
                NoticePublishing,
                live(PriorRecord, Absent, New, Prior),
                BeforeNotice,
            ),
            (
                NoticePublishing,
                live(PriorRecord, New, Absent, Prior),
                NoticeRollback,
            ),
            (
                NoticePublished,
                live(PriorRecord, New, Absent, Prior),
                NoticeRollback,
            ),
            (
                NoticePublished,
                live(NewRecord, New, Absent, Prior),
                Committed,
            ),
            (
                RecordCommitting,
                live(PriorRecord, New, Absent, Prior),
                NoticeRollback,
            ),
            (
                RecordCommitting,
                live(NewRecord, New, Absent, Prior),
                Committed,
            ),
            (
                RecordCommitted,
                live(NewRecord, New, Absent, Prior),
                Committed,
            ),
            (
                RecordCommitted,
                live(NewRecord, New, Absent, PriorSubset),
                Committed,
            ),
            (
                RecordCommitted,
                live(NewRecord, New, Absent, Absent),
                Committed,
            ),
            (
                BackupRetiring,
                live(NewRecord, New, Absent, Prior),
                Committed,
            ),
            (
                BackupRetiring,
                live(NewRecord, New, Absent, PriorSubset),
                Committed,
            ),
            (
                BackupRetiring,
                live(NewRecord, New, Absent, Absent),
                Committed,
            ),
            (
                NoticeCleaning,
                live(PriorRecord, New, Absent, Prior),
                NoticeCleanup,
            ),
            (
                NoticeCleaning,
                live(PriorRecord, NewSubset, Absent, Prior),
                NoticeCleanup,
            ),
            (
                NoticeCleaning,
                live(PriorRecord, Absent, Absent, Prior),
                NoticeCleanup,
            ),
            (
                PriorRestoring,
                live(PriorRecord, Absent, New, Prior),
                PriorRestore,
            ),
            (
                PriorRestoring,
                live(PriorRecord, Absent, NewSubset, Prior),
                PriorRestore,
            ),
            (
                PriorRestoring,
                live(PriorRecord, Absent, Absent, Prior),
                PriorRestore,
            ),
            (
                PriorRestoring,
                live(PriorRecord, Prior, New, Absent),
                PriorRestore,
            ),
            (
                PriorRestoring,
                live(PriorRecord, Prior, NewSubset, Absent),
                PriorRestore,
            ),
            (
                PriorRestoring,
                live(PriorRecord, Prior, Absent, Absent),
                PriorRestore,
            ),
            (
                StageCleaning,
                live(PriorRecord, Prior, New, Absent),
                StageCleanup,
            ),
            (
                StageCleaning,
                live(PriorRecord, Prior, NewSubset, Absent),
                StageCleanup,
            ),
            (
                StageCleaning,
                live(PriorRecord, Prior, PlannedSubset, Absent),
                StageCleanup,
            ),
            (
                StageCleaning,
                live(PriorRecord, Prior, Absent, Absent),
                StageCleanup,
            ),
        ];
        for (phase, state, expected) in cases {
            assert_eq!(rescue_recovery_route(phase, state).unwrap(), expected);
        }

        for phase in [
            Intent,
            Prepared,
            PriorBackingUp,
            PriorBackedUp,
            NoticePublishing,
            NoticePublished,
            RecordCommitting,
            RecordCommitted,
            BackupRetiring,
            NoticeCleaning,
            PriorRestoring,
            StageCleaning,
        ] {
            assert!(cases.iter().any(|case| case.0 == phase));
            assert!(rescue_migration_schema_phase_is_known(
                RESCUE_MIGRATION_SCHEMA,
                phase
            ));
            assert_eq!(
                rescue_migration_schema_phase_is_known(LEGACY_RESCUE_MIGRATION_SCHEMA, phase),
                matches!(
                    phase,
                    Prepared | PriorBackedUp | NoticePublished | RecordCommitted
                )
            );
            assert!(
                rescue_recovery_route(phase, live(PriorRecord, Prior, Other, Absent)).is_err(),
                "phase {phase:?} accepted an unowned stage entry"
            );
        }
        assert!(!rescue_migration_schema_phase_is_known(
            RESCUE_MIGRATION_SCHEMA + 1,
            Intent
        ));
        assert!(
            rescue_recovery_route(BackupRetiring, live(NewRecord, New, Absent, Other)).is_err()
        );
        assert!(
            rescue_recovery_route(NoticeCleaning, live(PriorRecord, Other, Absent, Prior)).is_err()
        );
        assert!(
            rescue_recovery_route(RecordCommitted, live(OtherRecord, New, Absent, Prior)).is_err()
        );
    }

    fn rescue_cleanup_fixture(root: &Path, file_count: usize) -> StageSnapshot {
        fs::create_dir(root).unwrap();
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        for index in 0..file_count {
            let file = root.join(format!("asset-{index}"));
            fs::write(&file, format!("owned-{index}\n")).unwrap();
            fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        }
        snapshot_stage(root).unwrap()
    }

    #[test]
    fn rescue_migration_recovery_cleanup_resumes_each_subset_and_preserves_unowned_entries() {
        let fixture = tempfile::tempdir().unwrap();
        let base = fixture.path().canonicalize().unwrap();

        for removed in 0..=3 {
            let root = base.join(format!("exact-subset-{removed}"));
            let expected = rescue_cleanup_fixture(&root, 3);
            for file in expected.files.iter().take(removed) {
                fs::remove_file(&file.path).unwrap();
            }
            remove_remaining_exact_stage(&expected, "unit-exact").unwrap();
            assert!(
                !root.exists(),
                "exact cleanup stopped after {removed} files"
            );
            remove_remaining_exact_stage(&expected, "unit-exact").unwrap();
        }

        let absent_root = base.join("already-absent");
        let absent = rescue_cleanup_fixture(&absent_root, 1);
        fs::remove_file(&absent.files[0].path).unwrap();
        fs::remove_dir(&absent_root).unwrap();
        remove_remaining_exact_stage(&absent, "unit-exact").unwrap();

        let planned_root = base.join("planned-subset");
        let mut planned = rescue_cleanup_fixture(&planned_root, 2);
        for directory in &mut planned.directories {
            directory.device = 0;
            directory.inode = 0;
        }
        for file in &mut planned.files {
            file.device = 0;
            file.inode = 0;
        }
        fs::write(&planned.files[0].path, "partial").unwrap();
        fs::remove_file(&planned.files[1].path).unwrap();
        remove_remaining_planned_stage(&planned, "unit-planned").unwrap();
        assert!(!planned_root.exists());

        let exact_unowned_root = base.join("exact-unowned");
        let exact_unowned = rescue_cleanup_fixture(&exact_unowned_root, 2);
        let exact_extra = exact_unowned_root.join("user-extra");
        fs::write(&exact_extra, "unowned\n").unwrap();
        fs::set_permissions(&exact_extra, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(remove_remaining_exact_stage(&exact_unowned, "unit-exact").is_err());
        assert_eq!(fs::read_to_string(&exact_extra).unwrap(), "unowned\n");
        assert!(exact_unowned.files.iter().all(|file| file.path.exists()));

        let planned_unowned_root = base.join("planned-unowned");
        let mut planned_unowned = rescue_cleanup_fixture(&planned_unowned_root, 1);
        for directory in &mut planned_unowned.directories {
            directory.device = 0;
            directory.inode = 0;
        }
        for file in &mut planned_unowned.files {
            file.device = 0;
            file.inode = 0;
        }
        let planned_extra = planned_unowned_root.join("user-extra");
        fs::write(&planned_extra, "unowned\n").unwrap();
        fs::set_permissions(&planned_extra, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(remove_remaining_planned_stage(&planned_unowned, "unit-planned").is_err());
        assert_eq!(fs::read_to_string(&planned_extra).unwrap(), "unowned\n");
        assert!(planned_unowned.files.iter().all(|file| file.path.exists()));
    }

    #[test]
    fn rescue_migration_recovery_rejects_unjournaled_artifacts_without_deleting_them() {
        let fixture = tempfile::tempdir().unwrap();
        let stable_root = fixture.path().canonicalize().unwrap();
        fs::set_permissions(&stable_root, fs::Permissions::from_mode(0o700)).unwrap();
        let orphan = stable_root.join(format!(".rescue-migration-stage-{}", "a".repeat(32)));
        fs::create_dir(&orphan).unwrap();
        fs::set_permissions(&orphan, fs::Permissions::from_mode(0o700)).unwrap();
        let unowned = orphan.join("user-extra");
        fs::write(&unowned, "unowned\n").unwrap();

        let error = reconcile_rescue_migration(&stable_root).unwrap_err();

        assert_eq!(error.code, "recovery_needed");
        assert_eq!(fs::read_to_string(unowned).unwrap(), "unowned\n");
    }
}
#[cfg(test)]
mod schema_v2_migration_adjacency_tests {
    use super::*;

    fn authoritative_v2_record() -> OwnershipRecord {
        serde_json::from_value(serde_json::json!({
            "schema_version": 2,
            "state": "Ready",
            "plugin_version": "1.0.0",
            "broker_digest": "a".repeat(64),
            "pi_package_digest": "b".repeat(64),
            "pi_package_source": "/stable/generations/one/pi",
            "pi_config_path": "/pi/settings.json",
            "pi_package_entry": "/stable/generations/one/pi",
            "purge_authority": true,
            "plugin_state_root": "/plugin-state",
            "rescue_path": "/stable/rescue/uninstall.sh",
            "rescue_marker_digest": "c".repeat(64),
            "install_kind": "managed",
            "plugin_root": "/plugin",
            "stable_binary": "/stable/generations/one/bin/herdr-a2a",
            "ownership_path": "/stable/ownership.json",
            "owned_files": [{
                "path": "/stable/generations/one/bin/herdr-a2a",
                "sha256": "a".repeat(64),
                "mode": 0o700
            }]
        }))
        .unwrap()
    }

    #[test]
    fn authoritative_v2_transaction_neighbor_must_be_the_exact_v3_representation() {
        // Break caught: journal recovery independently accepted an authoritative v2 record and
        // an unrelated v3 record instead of admitting only a schema-version rewrite.
        let prior = authoritative_v2_record();
        let mut current = prior.clone();
        current.schema_version = OWNERSHIP_SCHEMA;
        assert!(exact_schema_v2_to_v3_migration_adjacency(&prior, &current));

        let mut mutations: Vec<OwnershipRecord> = Vec::new();
        let mut record = current.clone();
        record.state = InstallState::Failed;
        mutations.push(record);
        let mut record = current.clone();
        record.plugin_version = "1.0.1".to_owned();
        mutations.push(record);
        let mut record = current.clone();
        record.broker_digest = "d".repeat(64);
        mutations.push(record);
        let mut record = current.clone();
        record.pi_package_digest = "e".repeat(64);
        mutations.push(record);
        let mut record = current.clone();
        record.pi_package_source = PathBuf::from("/other/pi");
        mutations.push(record);
        let mut record = current.clone();
        record.pi_config_path = PathBuf::from("/other/settings.json");
        mutations.push(record);
        let mut record = current.clone();
        record.pi_package_entry = serde_json::json!("/other/pi");
        mutations.push(record);
        let mut record = current.clone();
        record.purge_authority = false;
        record.plugin_state_root = PathBuf::new();
        mutations.push(record);
        let mut record = current.clone();
        record.plugin_state_root = PathBuf::from("/other-state");
        mutations.push(record);
        let mut record = current.clone();
        record.rescue_path = PathBuf::from("/other/rescue.sh");
        mutations.push(record);
        let mut record = current.clone();
        record.rescue_marker_digest = "f".repeat(64);
        mutations.push(record);
        let mut record = current.clone();
        record.install_kind = "linked-dev".to_owned();
        mutations.push(record);
        let mut record = current.clone();
        record.plugin_root = PathBuf::from("/other-plugin");
        mutations.push(record);
        let mut record = current.clone();
        record.stable_binary = PathBuf::from("/other/herdr-a2a");
        mutations.push(record);
        let mut record = current.clone();
        record.ownership_path = PathBuf::from("/other/ownership.json");
        mutations.push(record);
        let mut record = current.clone();
        record.owned_files.push(OwnedFile {
            path: PathBuf::from("/stable/generations/one/pi/package.json"),
            sha256: "b".repeat(64),
            mode: 0o600,
        });
        mutations.push(record);
        let mut record = current.clone();
        record.last_error = Some("interrupted".to_owned());
        mutations.push(record);

        for mutation in mutations {
            assert!(
                !exact_schema_v2_to_v3_migration_adjacency(&prior, &mutation),
                "non-schema migration neighbor mutation was accepted: {mutation:?}"
            );
        }
    }

    #[test]
    fn authoritative_v2_transaction_endpoints_are_ordered_and_complete() {
        // Break caught: transaction validation checked only a v2 prior endpoint and admitted a
        // schema-2 new endpoint, reversed pair, second v2 endpoint, or absent neighbor.
        let prior = authoritative_v2_record();
        let mut current = prior.clone();
        current.schema_version = OWNERSHIP_SCHEMA;
        assert!(authoritative_v2_transaction_endpoints_are_exact_migration(
            Some(&prior),
            Some(&current)
        ));
        assert!(!authoritative_v2_transaction_endpoints_are_exact_migration(
            Some(&current),
            Some(&prior)
        ));
        assert!(!authoritative_v2_transaction_endpoints_are_exact_migration(
            Some(&prior),
            Some(&prior)
        ));
        assert!(!authoritative_v2_transaction_endpoints_are_exact_migration(
            Some(&prior),
            None
        ));
        assert!(!authoritative_v2_transaction_endpoints_are_exact_migration(
            None,
            Some(&prior)
        ));
    }

    #[test]
    fn removal_authorization_uses_unconditional_current_executable_identity() {
        // Break caught: a test-named environment variable selected an executable other than the
        // remover itself in ordinary debug product builds.
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/managed.rs"));
        let authorization = &source[source.find("fn validate_removal_executable").unwrap()..];
        let authorization = &authorization[..authorization.find("\n}\n\n").unwrap()];
        assert!(
            authorization.contains("let current = env::current_exe()"),
            "removal authorization must derive identity directly from the running executable"
        );
        let forbidden = ["HERDR", "A2A", "TEST", "CURRENT", "EXECUTABLE", "IDENTITY"].join("_");
        assert!(
            !source.contains(&forbidden),
            "product source must not expose a test-named executable identity override"
        );
    }
}
