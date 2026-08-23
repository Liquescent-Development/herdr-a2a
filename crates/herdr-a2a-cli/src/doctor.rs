use std::{env, fs, io, path::PathBuf};

use herdr_a2a_broker::{RuntimeDescriptor, RuntimePaths, SqliteTaskStore, read_descriptor};
use serde::{Deserialize, Serialize};

use crate::{managed, status};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DoctorIssue {
    PiOwnedEntryModified,
    PiAdapterPending,
    BrokerDescriptorStale,
    BrokerProofFailed,
    StorageReconciliationFailed,
    LegacySessionDataPresent,
    UnsafeStatePermissions,
    IncompatibleVersion,
    AdapterRegistrationMissing,
    BrokerNotRunning,
    BrokerUnavailable,
    BrokerStatusInvalid,
    ManagedOwnershipInvalid,
    ManagedBinaryModified,
    ManagedAdapterModified,
    PluginVersionIncompatible,
    BinaryVersionIncompatible,
    AdapterMetadataIncompatible,
    AdapterVersionIncompatible,
    PiVersionIncompatible,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DoctorEvidence {
    issues: Vec<DoctorIssue>,
}

#[cfg_attr(test, allow(dead_code))]
impl DoctorEvidence {
    #[cfg(test)]
    pub fn with_issue(issue: DoctorIssue) -> Self {
        Self {
            issues: vec![issue],
        }
    }

    fn push(&mut self, issue: DoctorIssue) {
        if !self.issues.contains(&issue) {
            self.issues.push(issue);
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorState {
    Healthy,
    Warning,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorCheck {
    pub code: String,
    pub state: DoctorState,
    pub summary: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorReport {
    pub overall: DoctorState,
    pub checks: Vec<DoctorCheck>,
}

#[cfg_attr(test, allow(dead_code))]
impl DoctorReport {
    #[cfg(test)]
    pub fn primary_code(&self) -> Option<&str> {
        self.checks
            .iter()
            .find(|check| check.state != DoctorState::Healthy)
            .map(|check| check.code.as_str())
    }
}

pub fn evaluate_evidence(evidence: &DoctorEvidence) -> DoctorReport {
    if evidence.issues.is_empty() {
        return DoctorReport {
            overall: DoctorState::Healthy,
            checks: vec![check(
                "workspace_a2a_healthy",
                DoctorState::Healthy,
                "Workspace A2A checks passed.",
            )],
        };
    }
    let checks = evidence
        .issues
        .iter()
        .copied()
        .map(issue_check)
        .collect::<Vec<_>>();
    let overall = if checks
        .iter()
        .any(|check| check.state == DoctorState::Failed)
    {
        DoctorState::Failed
    } else {
        DoctorState::Warning
    };
    DoctorReport { overall, checks }
}

fn issue_check(issue: DoctorIssue) -> DoctorCheck {
    match issue {
        DoctorIssue::PiOwnedEntryModified => check(
            "pi_owned_entry_modified",
            DoctorState::Failed,
            "The managed Pi package entry differs from its ownership record.",
        ),
        DoctorIssue::PiAdapterPending => check(
            "pi_adapter_pending",
            DoctorState::Warning,
            "Pi is not installed; adapter configuration remains pending.",
        ),
        DoctorIssue::BrokerDescriptorStale => check(
            "broker_descriptor_stale",
            DoctorState::Failed,
            "The workspace broker descriptor is stale or malformed.",
        ),
        DoctorIssue::BrokerProofFailed => check(
            "broker_proof_failed",
            DoctorState::Failed,
            "The listener did not prove the descriptor-bound broker identity.",
        ),
        DoctorIssue::StorageReconciliationFailed => check(
            "storage_reconciliation_failed",
            DoctorState::Failed,
            "Durable workspace storage failed read-only validation.",
        ),
        DoctorIssue::LegacySessionDataPresent => check(
            "legacy_session_data_present",
            DoctorState::Warning,
            "Legacy session-scoped A2A data is retained and was not adopted.",
        ),
        DoctorIssue::UnsafeStatePermissions => check(
            "unsafe_state_permissions",
            DoctorState::Failed,
            "Workspace A2A state permissions or ownership are unsafe.",
        ),
        DoctorIssue::IncompatibleVersion => check(
            "incompatible_version",
            DoctorState::Failed,
            "Installed plugin, binary, or ownership versions are incompatible.",
        ),
        DoctorIssue::AdapterRegistrationMissing => check(
            "adapter_registration_missing",
            DoctorState::Warning,
            "The broker is healthy but no adapter is currently registered.",
        ),
        DoctorIssue::BrokerNotRunning => check(
            "broker_not_running",
            DoctorState::Warning,
            "No workspace broker is currently running; the next operation starts one.",
        ),
        DoctorIssue::BrokerUnavailable => check(
            "broker_unavailable",
            DoctorState::Failed,
            "The proved workspace broker became unavailable.",
        ),
        DoctorIssue::BrokerStatusInvalid => check(
            "broker_status_invalid",
            DoctorState::Failed,
            "The workspace broker returned an invalid status response.",
        ),
        DoctorIssue::ManagedOwnershipInvalid => check(
            "managed_ownership_invalid",
            DoctorState::Failed,
            "The managed installation ownership record is missing or invalid.",
        ),
        DoctorIssue::ManagedBinaryModified => check(
            "managed_binary_modified",
            DoctorState::Failed,
            "The managed native binary assets differ from their ownership record.",
        ),
        DoctorIssue::ManagedAdapterModified => check(
            "managed_adapter_modified",
            DoctorState::Failed,
            "The managed Pi adapter assets differ from their ownership record.",
        ),
        DoctorIssue::PluginVersionIncompatible => check(
            "plugin_version_incompatible",
            DoctorState::Failed,
            format!(
                "The installed plugin must match managed release version {}.",
                env!("CARGO_PKG_VERSION")
            ),
        ),
        DoctorIssue::BinaryVersionIncompatible => check(
            "binary_version_incompatible",
            DoctorState::Failed,
            format!(
                "The native binary must match managed release version {}.",
                env!("CARGO_PKG_VERSION")
            ),
        ),
        DoctorIssue::AdapterMetadataIncompatible => check(
            "adapter_metadata_incompatible",
            DoctorState::Failed,
            format!(
                "The managed Pi adapter must declare Pi {} and Typebox {}.",
                managed::SUPPORTED_PI_PEER_RANGE,
                managed::SUPPORTED_TYPEBOX_PEER_RANGE
            ),
        ),
        DoctorIssue::AdapterVersionIncompatible => check(
            "adapter_version_incompatible",
            DoctorState::Failed,
            format!(
                "The managed Pi adapter must match release version {}.",
                env!("CARGO_PKG_VERSION")
            ),
        ),
        DoctorIssue::PiVersionIncompatible => check(
            "pi_version_incompatible",
            DoctorState::Failed,
            format!(
                "The installed Pi version must satisfy {}.",
                managed::SUPPORTED_PI_PEER_RANGE
            ),
        ),
    }
}

fn check(code: &str, state: DoctorState, summary: impl Into<String>) -> DoctorCheck {
    DoctorCheck {
        code: code.to_owned(),
        state,
        summary: summary.into(),
    }
}

pub async fn collect() -> DoctorReport {
    let mut evidence = DoctorEvidence::default();
    inspect_managed_ownership(&mut evidence).await;
    inspect_workspace_state(&mut evidence);
    inspect_broker(&mut evidence).await;
    evaluate_evidence(&evidence)
}

async fn inspect_managed_ownership(evidence: &mut DoctorEvidence) {
    for issue in managed::inspect_read_only().await {
        evidence.push(match issue {
            managed::ReadOnlyManagedIssue::OwnershipInvalid => DoctorIssue::ManagedOwnershipInvalid,
            managed::ReadOnlyManagedIssue::OwnershipVersionIncompatible => {
                DoctorIssue::IncompatibleVersion
            }
            managed::ReadOnlyManagedIssue::BinaryModified => DoctorIssue::ManagedBinaryModified,
            managed::ReadOnlyManagedIssue::AdapterModified => DoctorIssue::ManagedAdapterModified,
            managed::ReadOnlyManagedIssue::PiEntryModified => DoctorIssue::PiOwnedEntryModified,
            managed::ReadOnlyManagedIssue::PiAdapterPending => DoctorIssue::PiAdapterPending,
            managed::ReadOnlyManagedIssue::PluginVersionIncompatible => {
                DoctorIssue::PluginVersionIncompatible
            }
            managed::ReadOnlyManagedIssue::BinaryVersionIncompatible => {
                DoctorIssue::BinaryVersionIncompatible
            }
            managed::ReadOnlyManagedIssue::AdapterMetadataIncompatible => {
                DoctorIssue::AdapterMetadataIncompatible
            }
            managed::ReadOnlyManagedIssue::AdapterVersionIncompatible => {
                DoctorIssue::AdapterVersionIncompatible
            }
            managed::ReadOnlyManagedIssue::PiVersionIncompatible => {
                DoctorIssue::PiVersionIncompatible
            }
        });
    }
}

fn inspect_workspace_state(evidence: &mut DoctorEvidence) {
    let Ok(paths) = RuntimePaths::discover() else {
        evidence.push(DoctorIssue::UnsafeStatePermissions);
        return;
    };
    let Some(plugin_state) = env::var_os("HERDR_PLUGIN_STATE_DIR").map(PathBuf::from) else {
        evidence.push(DoctorIssue::UnsafeStatePermissions);
        return;
    };
    if !private_directory_if_present(&plugin_state) {
        evidence.push(DoctorIssue::UnsafeStatePermissions);
    }
    let state_root = plugin_state.join("herdr-a2a");
    let legacy = state_root
        .join(&paths.scope.session_key)
        .join("tasks.sqlite3");
    if legacy.exists() {
        evidence.push(DoctorIssue::LegacySessionDataPresent);
    }
    let database = state_root
        .join(&paths.scope.scope_key)
        .join("tasks.sqlite3");
    if database.exists()
        && let Some(issue) = inspect_database(&database)
    {
        evidence.push(issue);
    }
}

pub fn inspect_database(path: &std::path::Path) -> Option<DoctorIssue> {
    match SqliteTaskStore::validate_read_only(path) {
        Ok(()) => None,
        Err(herdr_a2a_broker::StoreError::UnsafeFile(_)) => {
            Some(DoctorIssue::UnsafeStatePermissions)
        }
        Err(_) => Some(DoctorIssue::StorageReconciliationFailed),
    }
}

async fn inspect_broker(evidence: &mut DoctorEvidence) {
    let Ok(paths) = RuntimePaths::discover() else {
        return;
    };
    if !paths.descriptor.exists() {
        evidence.push(DoctorIssue::BrokerNotRunning);
        return;
    }
    let Ok(descriptor) = read_descriptor(&paths) else {
        evidence.push(DoctorIssue::BrokerDescriptorStale);
        return;
    };
    if let Some(issue) = inspect_descriptor(&descriptor).await {
        evidence.push(issue);
    }
}

pub async fn inspect_descriptor(descriptor: &RuntimeDescriptor) -> Option<DoctorIssue> {
    match status::collect_from_descriptor(descriptor).await {
        Ok(status) if status.registrations == 0 => Some(DoctorIssue::AdapterRegistrationMissing),
        Ok(_) => None,
        Err(error) => Some(issue_for_operations_error(error)),
    }
}

pub fn issue_for_operations_error(error: status::OperationsError) -> DoctorIssue {
    match error {
        status::OperationsError::BrokerUnavailable => DoctorIssue::BrokerUnavailable,
        status::OperationsError::BrokerProofFailed => DoctorIssue::BrokerProofFailed,
        status::OperationsError::InvalidResponse => DoctorIssue::BrokerStatusInvalid,
        status::OperationsError::StorageReconciliationFailed => {
            DoctorIssue::StorageReconciliationFailed
        }
    }
}

fn private_directory_if_present(path: &PathBuf) -> bool {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => true,
        Err(_) => false,
        Ok(_) => managed::validate_directory_chain(path, true).is_ok(),
    }
}

pub async fn run(json: bool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let report = collect().await;
    if json {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        println!("Doctor: {:?}", report.overall);
        for check in report.checks {
            println!("{}: {}", check.code, check.summary);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    use super::private_directory_if_present;
    use super::{DoctorEvidence, DoctorIssue, evaluate_evidence};

    #[test]
    fn optional_private_directory_distinguishes_absence_and_validates_the_opened_chain() {
        // Break caught: Doctor treated dangling links, mode 0755, and unsafe ancestors as a safe
        // absent/private plugin-state directory.
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().canonicalize().unwrap();
        let absent = root.join("absent");
        assert!(private_directory_if_present(&absent));

        let private = root.join("private");
        fs::create_dir(&private).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(private_directory_if_present(&private));

        fs::set_permissions(&private, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!private_directory_if_present(&private));

        let dangling = root.join("dangling");
        symlink(root.join("missing-target"), &dangling).unwrap();
        assert!(!private_directory_if_present(&dangling));

        let unsafe_parent = root.join("unsafe-parent");
        let private_child = unsafe_parent.join("private-child");
        fs::create_dir(&unsafe_parent).unwrap();
        fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777)).unwrap();
        fs::create_dir(&private_child).unwrap();
        fs::set_permissions(&private_child, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!private_directory_if_present(&private_child));
    }

    #[test]
    fn compatibility_diagnostics_name_the_exact_supported_interfaces() {
        // Break caught: Doctor reported only a generic incompatibility even though install must
        // tell the user which exact Pi and Typebox interfaces can recover it.
        let pi = evaluate_evidence(&DoctorEvidence::with_issue(
            DoctorIssue::PiVersionIncompatible,
        ));
        assert!(pi.checks[0].summary.contains(">=0.84.2"));

        let adapter = evaluate_evidence(&DoctorEvidence::with_issue(
            DoctorIssue::AdapterMetadataIncompatible,
        ));
        assert!(adapter.checks[0].summary.contains(">=1.3.7 <1.4.0"));
    }
}
