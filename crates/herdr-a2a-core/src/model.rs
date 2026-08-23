use std::path::PathBuf;

use serde::{Deserialize, Deserializer, Serialize};

use crate::validation::DomainError;

pub const MAX_TASK_ID_BYTES: usize = 256;
pub const MAX_ROLE_LABEL_BYTES: usize = 256;

pub fn validate_task_id(task_id: &str) -> Result<(), DomainError> {
    let bytes = task_id.as_bytes();
    if !(1..=MAX_TASK_ID_BYTES).contains(&bytes.len())
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'))
    {
        return Err(DomainError::InvalidTaskId);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct AgentName(pub(crate) String);

impl<'de> Deserialize<'de> for AgentName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = String::deserialize(deserializer)?;
        Self::parse(&name).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RoleLabel(pub(crate) String);

impl<'de> Deserialize<'de> for RoleLabel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let role = String::deserialize(deserializer)?;
        Self::parse(&role).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifiedPane {
    pub pane_id: String,
    pub workspace_id: String,
    pub role: RoleLabel,
    pub harness: String,
    pub workspace_path: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentIdentity {
    pub canonical_name: AgentName,
    pub original_role_slug: String,
    pub current_role: RoleLabel,
    pub pane_id: String,
    pub harness: String,
    pub harness_session_id: String,
    pub workspace_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifiedAgent {
    pub name: AgentName,
    pub pane_id: String,
    pub harness: String,
    pub workspace: PathBuf,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RegistrationId(pub(crate) String);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RegistrationEpoch(u64);

impl RegistrationEpoch {
    pub fn parse(value: &str) -> Option<Self> {
        if value.is_empty()
            || !value.bytes().all(|byte| byte.is_ascii_digit())
            || (value.len() > 1 && value.starts_with('0'))
        {
            return None;
        }
        let value = value.parse::<u64>().ok()?;
        (value > 0).then_some(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RegistrationCredentials {
    pub id: RegistrationId,
    pub epoch: RegistrationEpoch,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Registration {
    pub id: RegistrationId,
    pub epoch: RegistrationEpoch,
    pub agent: VerifiedAgent,
    pub harness_session_id: String,
    pub expires_unix_ms: i64,
}

impl Registration {
    pub fn credentials(&self) -> RegistrationCredentials {
        RegistrationCredentials {
            id: self.id.clone(),
            epoch: self.epoch,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct DeliveryId(pub(crate) String);

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct FileReference {
    pub path: PathBuf,
    pub media_type: Option<String>,
    pub label: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MessagePayload {
    pub text: String,
    pub metadata: serde_json::Value,
    pub file_refs: Vec<FileReference>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ValidatedPayload {
    pub text: String,
    pub metadata: serde_json::Value,
    pub file_refs: Vec<FileReference>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct QueuedDelivery {
    pub task_id: String,
    pub context_id: String,
    pub sender: AgentName,
    pub recipient: AgentName,
    pub payload: ValidatedPayload,
    pub created_unix_ms: i64,
    pub attempt: u32,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DeliveredMessage {
    pub delivery_id: DeliveryId,
    pub task_id: String,
    pub context_id: String,
    pub sender: AgentName,
    pub recipient: AgentName,
    pub payload: ValidatedPayload,
    pub leased_until_unix_ms: i64,
    pub attempt: u32,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ReplyPayload {
    pub text: String,
    pub metadata: serde_json::Value,
    pub file_refs: Vec<FileReference>,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        AgentIdentity, AgentName, MAX_ROLE_LABEL_BYTES, MAX_TASK_ID_BYTES, RoleLabel, VerifiedPane,
        validate_task_id,
    };

    #[test]
    fn task_ids_follow_the_shared_ascii_grammar() {
        for valid in ["a", "A-Z_0", &"x".repeat(MAX_TASK_ID_BYTES)] {
            assert!(validate_task_id(valid).is_ok(), "{valid:?}");
        }
        for invalid in [
            ".",
            "..",
            "task/child",
            r"task\child",
            "task?query",
            "task#fragment",
            "%2e%2e",
            "",
            "tâsk",
            &"x".repeat(MAX_TASK_ID_BYTES + 1),
        ] {
            assert!(validate_task_id(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn identity_role_labels_are_bounded_control_free_utf8() {
        // Break caught: mutable display roles become an unbounded/control-bearing transport field.
        for valid in [
            "reviewer",
            "Réviewer",
            "---",
            &"x".repeat(MAX_ROLE_LABEL_BYTES),
        ] {
            assert_eq!(RoleLabel::parse(valid).unwrap().as_str(), valid);
        }
        for invalid in [
            "",
            "reviewer\nadmin",
            "reviewer\u{7f}",
            &"é".repeat(MAX_ROLE_LABEL_BYTES / 2 + 1),
        ] {
            assert!(RoleLabel::parse(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn identity_models_keep_canonical_authority_separate_from_role() {
        // Break caught: a mutable role is reused as the durable authority-bearing agent name.
        let pane = VerifiedPane {
            pane_id: "w1:p2".to_owned(),
            workspace_id: "workspace-1".to_owned(),
            role: RoleLabel::parse("reviewer").unwrap(),
            harness: "pi".to_owned(),
            workspace_path: PathBuf::from("/repo"),
        };
        let identity = AgentIdentity {
            canonical_name: AgentName::parse("reviewer-k7m2").unwrap(),
            original_role_slug: "reviewer".to_owned(),
            current_role: pane.role.clone(),
            pane_id: pane.pane_id.clone(),
            harness: pane.harness.clone(),
            harness_session_id: "pi-session-a".to_owned(),
            workspace_id: pane.workspace_id.clone(),
        };

        assert_eq!(identity.canonical_name.as_str(), "reviewer-k7m2");
        assert_eq!(identity.current_role.as_str(), "reviewer");
        assert_ne!(
            identity.canonical_name.as_str(),
            identity.current_role.as_str()
        );
    }
}
