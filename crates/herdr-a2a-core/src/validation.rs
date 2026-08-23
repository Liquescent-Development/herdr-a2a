use std::{
    error::Error,
    fmt,
    path::{Path, PathBuf},
};

use crate::model::{
    AgentName, DeliveryId, FileReference, MAX_ROLE_LABEL_BYTES, MessagePayload, RegistrationId,
    RoleLabel, ValidatedPayload,
};
use serde::Deserialize;

pub const MAX_TEXT_BYTES: usize = 64 * 1024;
pub const MAX_METADATA_BYTES: usize = 32 * 1024;
pub const MAX_METADATA_DEPTH: usize = 8;
pub const MAX_METADATA_ENTRIES: usize = 256;
pub const MAX_FILE_REFS: usize = 32;
pub const MAX_PATH_BYTES: usize = 4 * 1024;
pub const MAX_FILE_LABEL_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DomainError {
    InvalidAgentName,
    InvalidRoleLabel,
    InvalidRegistrationId,
    InvalidDeliveryId,
    InvalidTaskId,
    TextTooLarge,
    MetadataTooLarge,
    MetadataTooDeep,
    TooManyMetadataEntries,
    TooManyFileReferences,
    PathTooLong,
    FileLabelTooLong,
    FileNotFound(PathBuf),
    WorkspaceNotFound(PathBuf),
    FileOutsideWorkspace { path: PathBuf, workspace: PathBuf },
    RegistrationNotFound,
    RegistrationExpired,
    AgentNotRegistered,
    SenderMismatch,
    WaitAlreadyActive,
    WaitTimedOut,
    DeliveryNotFound,
    DeliveryNotOwned,
    TaskNotFound,
    TaskNotOwned,
    DuplicateTask,
    ReplyWaitAlreadyActive,
    ReplyAlreadySubmitted,
    TaskCanceled,
    TaskExpired,
    TaskFailed,
    TaskRejected,
    TaskAlreadyCompleted,
    TooManyActiveTasks,
    TooManyRetainedTasks,
    PersistenceUnavailable,
}

impl fmt::Display for DomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAgentName => formatter.write_str("invalid agent name"),
            Self::InvalidRoleLabel => formatter.write_str("invalid role label"),
            Self::InvalidRegistrationId => formatter.write_str("invalid registration ID"),
            Self::InvalidDeliveryId => formatter.write_str("invalid delivery ID"),
            Self::InvalidTaskId => formatter.write_str("invalid task ID"),
            Self::TextTooLarge => formatter.write_str("message text exceeds the size limit"),
            Self::MetadataTooLarge => {
                formatter.write_str("message metadata exceeds the size limit")
            }
            Self::MetadataTooDeep => {
                formatter.write_str("message metadata exceeds the nesting limit")
            }
            Self::TooManyMetadataEntries => {
                formatter.write_str("message metadata exceeds the entry limit")
            }
            Self::TooManyFileReferences => {
                formatter.write_str("message has too many file references")
            }
            Self::PathTooLong => formatter.write_str("file reference path exceeds the size limit"),
            Self::FileLabelTooLong => {
                formatter.write_str("file reference label exceeds the size limit")
            }
            Self::FileNotFound(path) => write!(
                formatter,
                "file reference does not exist: {}",
                path.display()
            ),
            Self::WorkspaceNotFound(path) => {
                write!(formatter, "workspace does not exist: {}", path.display())
            }
            Self::FileOutsideWorkspace { path, workspace } => write!(
                formatter,
                "file reference {} is outside workspace {}",
                path.display(),
                workspace.display()
            ),
            Self::RegistrationNotFound => formatter.write_str("registration not found"),
            Self::RegistrationExpired => formatter.write_str("registration expired"),
            Self::AgentNotRegistered => formatter.write_str("agent is not registered"),
            Self::SenderMismatch => {
                formatter.write_str("authenticated sender does not match delivery sender")
            }
            Self::WaitAlreadyActive => {
                formatter.write_str("registration already has an active wait")
            }
            Self::WaitTimedOut => formatter.write_str("wait timed out"),
            Self::DeliveryNotFound => formatter.write_str("delivery not found"),
            Self::DeliveryNotOwned => {
                formatter.write_str("delivery is owned by another registration")
            }
            Self::TaskNotFound => formatter.write_str("task not found"),
            Self::TaskNotOwned => formatter.write_str("task is owned by another registration"),
            Self::DuplicateTask => formatter.write_str("task already exists"),
            Self::ReplyWaitAlreadyActive => formatter.write_str("task already has a reply waiter"),
            Self::ReplyAlreadySubmitted => {
                formatter.write_str("a conflicting reply already exists")
            }
            Self::TaskCanceled => formatter.write_str("task was canceled"),
            Self::TaskExpired => formatter.write_str("task delivery deadline expired"),
            Self::TaskFailed => formatter.write_str("task failed"),
            Self::TaskRejected => formatter.write_str("task was rejected"),
            Self::TaskAlreadyCompleted => formatter.write_str("task is already completed"),
            Self::TooManyActiveTasks => {
                formatter.write_str("registration has too many active outbound tasks")
            }
            Self::TooManyRetainedTasks => {
                formatter.write_str("retained task capacity is exhausted")
            }
            Self::PersistenceUnavailable => formatter.write_str("broker persistence unavailable"),
        }
    }
}

impl Error for DomainError {}

impl AgentName {
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let bytes = value.as_bytes();
        if !(1..=32).contains(&bytes.len())
            || !bytes[0].is_ascii_lowercase()
            || !bytes[1..].iter().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(*byte, b'_' | b'-')
            })
        {
            return Err(DomainError::InvalidAgentName);
        }

        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl RoleLabel {
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        if value.is_empty()
            || value.len() > MAX_ROLE_LABEL_BYTES
            || value.chars().any(|character| {
                character.is_control() || matches!(character, '\u{2028}' | '\u{2029}')
            })
        {
            return Err(DomainError::InvalidRoleLabel);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RoleLabel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Display for AgentName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl RegistrationId {
    pub fn new() -> Self {
        Self(uuid::Uuid::now_v7().to_string())
    }

    pub fn parse(value: &str) -> Result<Self, DomainError> {
        parse_uuid_v7(value, DomainError::InvalidRegistrationId).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for RegistrationId {
    fn default() -> Self {
        Self::new()
    }
}

impl DeliveryId {
    pub fn new() -> Self {
        Self(uuid::Uuid::now_v7().to_string())
    }

    pub fn parse(value: &str) -> Result<Self, DomainError> {
        parse_uuid_v7(value, DomainError::InvalidDeliveryId).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for DeliveryId {
    fn default() -> Self {
        Self::new()
    }
}

impl<'de> Deserialize<'de> for RegistrationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

impl<'de> Deserialize<'de> for DeliveryId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

fn parse_uuid_v7(value: &str, error: DomainError) -> Result<String, DomainError> {
    let id = uuid::Uuid::parse_str(value).map_err(|_| error.clone())?;
    if id.get_version_num() != 7 || id.get_variant() != uuid::Variant::RFC4122 {
        return Err(error);
    }

    Ok(id.to_string())
}

impl FileReference {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            media_type: None,
            label: None,
        }
    }
}

impl MessagePayload {
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            metadata: serde_json::Value::Object(serde_json::Map::new()),
            file_refs: Vec::new(),
        }
    }
}

pub fn validate_payload(
    payload: &MessagePayload,
    workspace: &Path,
) -> Result<ValidatedPayload, DomainError> {
    if payload.text.len() > MAX_TEXT_BYTES {
        return Err(DomainError::TextTooLarge);
    }
    validate_metadata(&payload.metadata)?;

    if payload.file_refs.len() > MAX_FILE_REFS {
        return Err(DomainError::TooManyFileReferences);
    }

    let canonical_workspace = workspace.canonicalize();
    let workspace_for_check = canonical_workspace
        .as_ref()
        .map_or_else(|_| workspace.to_path_buf(), Clone::clone);
    let mut file_refs = Vec::with_capacity(payload.file_refs.len());

    for file_ref in &payload.file_refs {
        validate_file_reference_shape(file_ref)?;
        let canonical_path = file_ref
            .path
            .canonicalize()
            .map_err(|_| DomainError::FileNotFound(file_ref.path.clone()))?;
        validate_canonical_path(&canonical_path)?;
        if !canonical_path.starts_with(&workspace_for_check) {
            return Err(DomainError::FileOutsideWorkspace {
                path: canonical_path,
                workspace: workspace_for_check.clone(),
            });
        }
        canonical_workspace
            .as_ref()
            .map_err(|_| DomainError::WorkspaceNotFound(workspace.to_path_buf()))?;

        file_refs.push(FileReference {
            path: canonical_path,
            media_type: file_ref.media_type.clone(),
            label: file_ref.label.clone(),
        });
    }

    Ok(ValidatedPayload {
        text: payload.text.clone(),
        metadata: payload.metadata.clone(),
        file_refs,
    })
}

pub fn validate_persisted_payload(payload: &ValidatedPayload) -> Result<(), DomainError> {
    if payload.text.len() > MAX_TEXT_BYTES {
        return Err(DomainError::TextTooLarge);
    }
    validate_metadata(&payload.metadata)?;
    if payload.file_refs.len() > MAX_FILE_REFS {
        return Err(DomainError::TooManyFileReferences);
    }
    for file_ref in &payload.file_refs {
        if file_ref.path.to_string_lossy().len() > MAX_PATH_BYTES {
            return Err(DomainError::PathTooLong);
        }
        if file_ref
            .label
            .as_ref()
            .is_some_and(|label| label.len() > MAX_FILE_LABEL_BYTES)
        {
            return Err(DomainError::FileLabelTooLong);
        }
    }
    Ok(())
}

fn validate_metadata(metadata: &serde_json::Value) -> Result<(), DomainError> {
    if serde_json::to_vec(metadata)
        .expect("serializing serde_json::Value cannot fail")
        .len()
        > MAX_METADATA_BYTES
    {
        return Err(DomainError::MetadataTooLarge);
    }

    let mut entries = 0;
    validate_metadata_node(metadata, 0, &mut entries)
}

fn validate_metadata_node(
    value: &serde_json::Value,
    depth: usize,
    entries: &mut usize,
) -> Result<(), DomainError> {
    match value {
        serde_json::Value::Array(items) => {
            let next_depth = depth + 1;
            if next_depth > MAX_METADATA_DEPTH {
                return Err(DomainError::MetadataTooDeep);
            }
            *entries += items.len();
            if *entries > MAX_METADATA_ENTRIES {
                return Err(DomainError::TooManyMetadataEntries);
            }
            for item in items {
                validate_metadata_node(item, next_depth, entries)?;
            }
        }
        serde_json::Value::Object(map) => {
            let next_depth = depth + 1;
            if next_depth > MAX_METADATA_DEPTH {
                return Err(DomainError::MetadataTooDeep);
            }
            *entries += map.len();
            if *entries > MAX_METADATA_ENTRIES {
                return Err(DomainError::TooManyMetadataEntries);
            }
            for value in map.values() {
                validate_metadata_node(value, next_depth, entries)?;
            }
        }
        _ => {}
    }

    Ok(())
}

fn validate_file_reference_shape(file_ref: &FileReference) -> Result<(), DomainError> {
    if file_ref.path.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES {
        return Err(DomainError::PathTooLong);
    }
    if file_ref
        .label
        .as_ref()
        .is_some_and(|label| label.len() > MAX_FILE_LABEL_BYTES)
    {
        return Err(DomainError::FileLabelTooLong);
    }

    Ok(())
}

fn validate_canonical_path(path: &Path) -> Result<(), DomainError> {
    if path.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES {
        return Err(DomainError::PathTooLong);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use crate::{
        model::{AgentName, DeliveryId, FileReference, MessagePayload, RegistrationId, RoleLabel},
        validation::{
            DomainError, MAX_FILE_LABEL_BYTES, MAX_FILE_REFS, MAX_METADATA_BYTES,
            MAX_METADATA_DEPTH, MAX_METADATA_ENTRIES, MAX_PATH_BYTES, MAX_TEXT_BYTES,
            validate_payload,
        },
    };

    #[test]
    fn role_labels_share_the_256_byte_control_and_separator_contract() {
        // Break caught: Rust accepted Unicode line separators that Pi rejected, while one Pi
        // status parser imposed a different 128-byte bound.
        assert!(RoleLabel::parse(&"é".repeat(128)).is_ok());
        assert_eq!(
            RoleLabel::parse("reviewer\u{2028}forged").unwrap_err(),
            DomainError::InvalidRoleLabel
        );
        assert_eq!(
            RoleLabel::parse("reviewer\u{2029}forged").unwrap_err(),
            DomainError::InvalidRoleLabel
        );
        assert_eq!(
            RoleLabel::parse(&format!("{}x", "é".repeat(128))).unwrap_err(),
            DomainError::InvalidRoleLabel
        );
    }

    struct TestWorkspace(PathBuf);

    impl TestWorkspace {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("herdr-a2a-validation-{}", uuid::Uuid::now_v7()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestWorkspace {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn agent_names_follow_herdr_grammar() {
        assert!(AgentName::parse("reviewer").is_ok());
        assert!(AgentName::parse("pi_2").is_ok());
        assert!(AgentName::parse("pi-2").is_ok());
        assert!(AgentName::parse("Reviewer").is_err());
        assert!(AgentName::parse("2reviewer").is_err());
        assert!(AgentName::parse(&"a".repeat(33)).is_err());
    }

    #[test]
    fn serialized_agent_names_must_follow_herdr_grammar() {
        assert!(serde_json::from_str::<AgentName>("\"reviewer\"").is_ok());
        assert!(serde_json::from_str::<AgentName>("\"pi-2\"").is_ok());
        assert!(serde_json::from_str::<AgentName>("\"Reviewer\"").is_err());
    }

    #[test]
    fn payload_rejects_oversized_text() {
        let payload = MessagePayload::text("x".repeat(MAX_TEXT_BYTES + 1));
        assert_eq!(
            validate_payload(&payload, Path::new("/workspace")).unwrap_err(),
            DomainError::TextTooLarge
        );
    }

    #[test]
    fn payload_accepts_text_at_the_byte_limit() {
        let payload = MessagePayload::text("x".repeat(MAX_TEXT_BYTES));
        assert!(validate_payload(&payload, Path::new("/workspace")).is_ok());
    }

    #[test]
    fn payload_rejects_oversized_metadata() {
        let payload = MessagePayload {
            text: String::new(),
            metadata: serde_json::json!("x".repeat(MAX_METADATA_BYTES)),
            file_refs: vec![],
        };
        assert_eq!(
            validate_payload(&payload, Path::new("/workspace")).unwrap_err(),
            DomainError::MetadataTooLarge
        );
    }

    #[test]
    fn payload_rejects_metadata_deeper_than_eight_containers() {
        let mut metadata = serde_json::json!(null);
        for _ in 0..=MAX_METADATA_DEPTH {
            metadata = serde_json::Value::Array(vec![metadata]);
        }
        let payload = MessagePayload {
            text: String::new(),
            metadata,
            file_refs: vec![],
        };
        assert_eq!(
            validate_payload(&payload, Path::new("/workspace")).unwrap_err(),
            DomainError::MetadataTooDeep
        );
    }

    #[test]
    fn payload_rejects_more_than_256_metadata_entries() {
        let payload = MessagePayload {
            text: String::new(),
            metadata: serde_json::Value::Array(vec![
                serde_json::json!(null);
                MAX_METADATA_ENTRIES + 1
            ]),
            file_refs: vec![],
        };
        assert_eq!(
            validate_payload(&payload, Path::new("/workspace")).unwrap_err(),
            DomainError::TooManyMetadataEntries
        );
    }

    #[test]
    fn payload_rejects_more_than_32_file_references() {
        let payload = MessagePayload {
            text: String::new(),
            metadata: serde_json::json!({}),
            file_refs: vec![FileReference::new("ignored"); MAX_FILE_REFS + 1],
        };
        assert_eq!(
            validate_payload(&payload, Path::new("/workspace")).unwrap_err(),
            DomainError::TooManyFileReferences
        );
    }

    #[test]
    fn payload_rejects_an_overlong_file_reference_path() {
        let payload = MessagePayload {
            text: String::new(),
            metadata: serde_json::json!({}),
            file_refs: vec![FileReference::new("x".repeat(MAX_PATH_BYTES + 1))],
        };
        assert_eq!(
            validate_payload(&payload, Path::new("/workspace")).unwrap_err(),
            DomainError::PathTooLong
        );
    }

    #[test]
    fn canonical_file_paths_over_the_limit_are_rejected() {
        let canonical_path = PathBuf::from("x".repeat(MAX_PATH_BYTES + 1));
        assert_eq!(
            super::validate_canonical_path(&canonical_path).unwrap_err(),
            DomainError::PathTooLong
        );
    }

    #[test]
    fn payload_rejects_an_overlong_file_label() {
        let payload = MessagePayload {
            text: String::new(),
            metadata: serde_json::json!({}),
            file_refs: vec![FileReference {
                path: PathBuf::from("ignored"),
                media_type: None,
                label: Some("x".repeat(MAX_FILE_LABEL_BYTES + 1)),
            }],
        };
        assert_eq!(
            validate_payload(&payload, Path::new("/workspace")).unwrap_err(),
            DomainError::FileLabelTooLong
        );
    }

    #[test]
    fn file_reference_must_stay_inside_workspace() {
        let payload = MessagePayload {
            text: "review this".into(),
            metadata: serde_json::json!({}),
            file_refs: vec![FileReference::new("/etc/passwd")],
        };
        assert!(matches!(
            validate_payload(&payload, Path::new("/workspace")),
            Err(DomainError::FileOutsideWorkspace { .. })
        ));
    }

    #[test]
    fn file_reference_is_replaced_with_its_canonical_workspace_path() {
        let workspace = TestWorkspace::new();
        let docs = workspace.path().join("docs");
        fs::create_dir(&docs).unwrap();
        let file = docs.join("review.md");
        fs::write(&file, "review").unwrap();
        let payload = MessagePayload {
            text: "review this".into(),
            metadata: serde_json::json!({}),
            file_refs: vec![FileReference::new(docs.join("..").join("docs/review.md"))],
        };

        let validated = validate_payload(&payload, workspace.path()).unwrap();

        assert_eq!(validated.file_refs[0].path, fs::canonicalize(file).unwrap());
    }

    #[test]
    fn file_references_accept_media_types_longer_than_file_labels() {
        let workspace = TestWorkspace::new();
        let file = workspace.path().join("review.md");
        fs::write(&file, "review").unwrap();
        let payload = MessagePayload {
            text: "review this".into(),
            metadata: serde_json::json!({}),
            file_refs: vec![FileReference {
                path: file,
                media_type: Some("x".repeat(MAX_FILE_LABEL_BYTES + 1)),
                label: None,
            }],
        };

        assert!(validate_payload(&payload, workspace.path()).is_ok());
    }

    #[test]
    fn registration_and_delivery_ids_only_accept_uuid_v7_strings() {
        let registration = RegistrationId::new();
        let delivery = DeliveryId::new();

        assert_eq!(
            uuid::Uuid::parse_str(registration.as_str())
                .unwrap()
                .get_version_num(),
            7
        );
        assert_eq!(
            uuid::Uuid::parse_str(delivery.as_str())
                .unwrap()
                .get_version_num(),
            7
        );
        assert!(RegistrationId::parse(registration.as_str()).is_ok());
        assert!(DeliveryId::parse(delivery.as_str()).is_ok());

        let v4 = "550e8400-e29b-41d4-a716-446655440000";
        let non_rfc_v7 = "00000000-0000-7000-0000-000000000000";
        assert!(RegistrationId::parse(v4).is_err());
        assert!(RegistrationId::parse(non_rfc_v7).is_err());
        assert!(DeliveryId::parse("not-a-uuid").is_err());
        assert!(serde_json::from_str::<RegistrationId>(&format!("\"{v4}\"")).is_err());
        assert!(serde_json::from_str::<DeliveryId>("\"not-a-uuid\"").is_err());
    }
}
