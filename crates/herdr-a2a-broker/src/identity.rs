use std::{
    collections::HashSet,
    fmt,
    path::Path,
    sync::{Arc, Mutex},
};

use herdr_a2a_core::{AgentIdentity, AgentName, RegistrationId, RoleLabel, VerifiedPane};
use rusqlite::{Connection, ErrorCode, OptionalExtension, TransactionBehavior, params};

const MAX_IDENTITY_FIELD_BYTES: usize = 1_024;
const MAX_WORKSPACE_ID_BYTES: usize = 256;
const RANDOM_SUFFIX_BYTES: usize = 6;
const MAX_ALLOCATION_ATTEMPTS: usize = 8;
const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

const IDENTITY_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS agent_identities (
  workspace_id TEXT NOT NULL,
  pane_id TEXT NOT NULL,
  harness TEXT NOT NULL,
  harness_session_id TEXT NOT NULL,
  canonical_name TEXT NOT NULL UNIQUE,
  original_role_slug TEXT NOT NULL,
  current_role TEXT NOT NULL,
  PRIMARY KEY (workspace_id, pane_id, harness, harness_session_id)
);";

#[derive(Debug)]
pub enum IdentityError {
    Sqlite(rusqlite::Error),
    InvalidData(String),
    WorkspaceMismatch,
    AllocationExhausted,
    WorkerFailed,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(error) => write!(formatter, "identity database failed: {error}"),
            Self::InvalidData(message) => write!(formatter, "identity data is invalid: {message}"),
            Self::WorkspaceMismatch => {
                formatter.write_str("identity workspace does not match broker workspace")
            }
            Self::AllocationExhausted => {
                formatter.write_str("canonical identity collision retry limit reached")
            }
            Self::WorkerFailed => formatter.write_str("identity database worker failed"),
        }
    }
}

impl std::error::Error for IdentityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for IdentityError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

trait SuffixSource: Send + Sync {
    fn suffix(&self) -> Result<String, IdentityError>;
}

#[derive(Debug)]
struct RandomSuffix;

impl SuffixSource for RandomSuffix {
    fn suffix(&self) -> Result<String, IdentityError> {
        let id = RegistrationId::new();
        let nibbles = id
            .as_str()
            .bytes()
            .rev()
            .filter_map(|byte| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            })
            .take(RANDOM_SUFFIX_BYTES)
            .collect::<Vec<_>>();
        if nibbles.len() != RANDOM_SUFFIX_BYTES {
            return Err(IdentityError::InvalidData(
                "random UUID did not contain enough entropy".to_owned(),
            ));
        }
        Ok(nibbles
            .into_iter()
            .map(|nibble| char::from(BASE32[usize::from(nibble)]))
            .collect())
    }
}

#[derive(Clone)]
pub struct IdentityStore {
    connection: Arc<Mutex<Connection>>,
    suffix_source: Arc<dyn SuffixSource>,
    expected_workspace_id: Option<String>,
}

impl IdentityStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let connection = Arc::new(Mutex::new(Connection::open(path)?));
        Self::from_shared_connection(connection)
    }

    pub(crate) fn from_shared_connection(
        connection: Arc<Mutex<Connection>>,
    ) -> Result<Self, IdentityError> {
        Self::from_shared_connection_with_suffix(connection, Arc::new(RandomSuffix))
    }

    fn from_shared_connection_with_suffix(
        connection: Arc<Mutex<Connection>>,
        suffix_source: Arc<dyn SuffixSource>,
    ) -> Result<Self, IdentityError> {
        {
            let connection = connection
                .lock()
                .map_err(|_| IdentityError::InvalidData("database mutex is poisoned".to_owned()))?;
            connection.execute_batch(IDENTITY_SCHEMA)?;
            validate_rows(&connection, None)?;
        }
        Ok(Self {
            connection,
            suffix_source,
            expected_workspace_id: None,
        })
    }

    #[cfg(test)]
    fn open_with_suffix_source(
        path: impl AsRef<Path>,
        suffix_source: impl SuffixSource + 'static,
    ) -> Result<Self, IdentityError> {
        let connection = Arc::new(Mutex::new(Connection::open(path)?));
        Self::from_shared_connection_with_suffix(connection, Arc::new(suffix_source))
    }

    pub fn for_workspace(&self, workspace_id: &str) -> Result<Self, IdentityError> {
        validate_workspace_id(workspace_id)?;
        {
            let connection = self
                .connection
                .lock()
                .map_err(|_| IdentityError::InvalidData("database mutex is poisoned".to_owned()))?;
            validate_rows(&connection, Some(workspace_id))?;
        }
        Ok(Self {
            connection: Arc::clone(&self.connection),
            suffix_source: Arc::clone(&self.suffix_source),
            expected_workspace_id: Some(workspace_id.to_owned()),
        })
    }

    pub async fn resolve_or_create(
        &self,
        pane: &VerifiedPane,
        harness_session_id: &str,
    ) -> Result<AgentIdentity, IdentityError> {
        validate_pane(pane, harness_session_id)?;
        if self
            .expected_workspace_id
            .as_deref()
            .is_some_and(|workspace_id| workspace_id != pane.workspace_id)
        {
            return Err(IdentityError::WorkspaceMismatch);
        }
        let connection = Arc::clone(&self.connection);
        let suffix_source = Arc::clone(&self.suffix_source);
        let pane = pane.clone();
        let harness_session_id = harness_session_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let mut connection = connection
                .lock()
                .map_err(|_| IdentityError::InvalidData("database mutex is poisoned".to_owned()))?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let existing_workspace = transaction
                .query_row(
                    "SELECT workspace_id FROM agent_identities LIMIT 1",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if existing_workspace
                .as_deref()
                .is_some_and(|workspace_id| workspace_id != pane.workspace_id)
            {
                return Err(IdentityError::WorkspaceMismatch);
            }
            if let Some(existing) = transaction
                .query_row(
                    "SELECT canonical_name, original_role_slug, current_role
                     FROM agent_identities
                     WHERE workspace_id = ?1 AND pane_id = ?2 AND harness = ?3
                       AND harness_session_id = ?4",
                    params![
                        pane.workspace_id,
                        pane.pane_id,
                        pane.harness,
                        harness_session_id
                    ],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .optional()?
            {
                transaction.execute(
                    "UPDATE agent_identities SET current_role = ?1
                     WHERE workspace_id = ?2 AND pane_id = ?3 AND harness = ?4
                       AND harness_session_id = ?5",
                    params![
                        pane.role.as_str(),
                        pane.workspace_id,
                        pane.pane_id,
                        pane.harness,
                        harness_session_id
                    ],
                )?;
                transaction.commit()?;
                return identity_from_parts(
                    &pane,
                    &harness_session_id,
                    existing.0,
                    existing.1,
                    pane.role.as_str().to_owned(),
                );
            }

            let slug = canonical_slug(Some(pane.role.as_str()));
            for _ in 0..MAX_ALLOCATION_ATTEMPTS {
                let suffix = suffix_source.suffix()?;
                let canonical_name = canonical_name_from_parts(&slug, &suffix)?;
                match transaction.execute(
                    "INSERT INTO agent_identities
                     (workspace_id, pane_id, harness, harness_session_id, canonical_name,
                      original_role_slug, current_role)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        pane.workspace_id,
                        pane.pane_id,
                        pane.harness,
                        harness_session_id,
                        canonical_name.as_str(),
                        slug,
                        pane.role.as_str()
                    ],
                ) {
                    Ok(_) => {
                        transaction.commit()?;
                        return Ok(AgentIdentity {
                            canonical_name,
                            original_role_slug: slug,
                            current_role: pane.role,
                            pane_id: pane.pane_id,
                            harness: pane.harness,
                            harness_session_id,
                            workspace_id: pane.workspace_id,
                        });
                    }
                    Err(error) if is_constraint_violation(&error) => continue,
                    Err(error) => return Err(error.into()),
                }
            }
            Err(IdentityError::AllocationExhausted)
        })
        .await
        .map_err(|_| IdentityError::WorkerFailed)?
    }

    pub async fn find_by_canonical(
        &self,
        canonical_name: &AgentName,
    ) -> Result<Option<AgentIdentity>, IdentityError> {
        let connection = Arc::clone(&self.connection);
        let canonical_name = canonical_name.clone();
        tokio::task::spawn_blocking(move || {
            let connection = connection
                .lock()
                .map_err(|_| IdentityError::InvalidData("database mutex is poisoned".to_owned()))?;
            connection
                .query_row(
                    "SELECT workspace_id, pane_id, harness, harness_session_id,
                            original_role_slug, current_role
                     FROM agent_identities WHERE canonical_name = ?1",
                    [canonical_name.as_str()],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, String>(5)?,
                        ))
                    },
                )
                .optional()?
                .map(|row| {
                    let role = RoleLabel::parse(&row.5).map_err(|_| {
                        IdentityError::InvalidData("stored role is invalid".to_owned())
                    })?;
                    Ok(AgentIdentity {
                        canonical_name,
                        original_role_slug: row.4,
                        current_role: role,
                        pane_id: row.1,
                        harness: row.2,
                        harness_session_id: row.3,
                        workspace_id: row.0,
                    })
                })
                .transpose()
        })
        .await
        .map_err(|_| IdentityError::WorkerFailed)?
    }
}

pub fn canonical_slug(label: Option<&str>) -> String {
    let mut slug = String::new();
    let mut separator = false;
    for character in label.unwrap_or_default().chars() {
        if character.is_ascii_alphanumeric() {
            if separator && !slug.is_empty() && slug.len() < 25 {
                slug.push('-');
            }
            separator = false;
            if slug.len() < 25 {
                slug.push(character.to_ascii_lowercase());
            }
        } else {
            separator = true;
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug
        .as_bytes()
        .first()
        .is_none_or(|byte| !byte.is_ascii_lowercase())
    {
        "agent".to_owned()
    } else {
        slug
    }
}

fn validate_rows(
    connection: &Connection,
    expected_workspace: Option<&str>,
) -> Result<(), IdentityError> {
    let mut statement = connection.prepare(
        "SELECT workspace_id, pane_id, harness, harness_session_id, canonical_name,
                original_role_slug, current_role FROM agent_identities",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
        ))
    })?;
    let mut workspaces = HashSet::new();
    for row in rows {
        let row = row?;
        validate_workspace_id(&row.0)?;
        validate_field("pane ID", &row.1, MAX_IDENTITY_FIELD_BYTES)?;
        validate_field("harness", &row.2, MAX_IDENTITY_FIELD_BYTES)?;
        validate_field("harness session ID", &row.3, MAX_IDENTITY_FIELD_BYTES)?;
        validate_canonical_name(&row.4, &row.5)?;
        RoleLabel::parse(&row.6)
            .map_err(|_| IdentityError::InvalidData("stored role is invalid".to_owned()))?;
        if expected_workspace.is_some_and(|workspace| workspace != row.0) {
            return Err(IdentityError::WorkspaceMismatch);
        }
        workspaces.insert(row.0);
    }
    if workspaces.len() > 1 {
        return Err(IdentityError::WorkspaceMismatch);
    }
    Ok(())
}

fn validate_pane(pane: &VerifiedPane, harness_session_id: &str) -> Result<(), IdentityError> {
    validate_workspace_id(&pane.workspace_id)?;
    validate_field("pane ID", &pane.pane_id, MAX_IDENTITY_FIELD_BYTES)?;
    validate_field("harness", &pane.harness, MAX_IDENTITY_FIELD_BYTES)?;
    validate_field(
        "harness session ID",
        harness_session_id,
        MAX_IDENTITY_FIELD_BYTES,
    )?;
    Ok(())
}

fn validate_workspace_id(workspace_id: &str) -> Result<(), IdentityError> {
    validate_field("workspace ID", workspace_id, MAX_WORKSPACE_ID_BYTES)
}

fn validate_field(label: &str, value: &str, maximum: usize) -> Result<(), IdentityError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(IdentityError::InvalidData(format!("{label} is invalid")));
    }
    Ok(())
}

fn validate_suffix(suffix: &str) -> Result<(), IdentityError> {
    if !(4..=8).contains(&suffix.len())
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || matches!(byte, b'2'..=b'7'))
    {
        return Err(IdentityError::InvalidData(
            "identity suffix is not bounded base32".to_owned(),
        ));
    }
    Ok(())
}

fn canonical_name_from_parts(
    original_role_slug: &str,
    suffix: &str,
) -> Result<AgentName, IdentityError> {
    if canonical_slug(Some(original_role_slug)) != original_role_slug {
        return Err(IdentityError::InvalidData(
            "identity original role slug is invalid".to_owned(),
        ));
    }
    validate_suffix(suffix)?;
    AgentName::parse(&format!("{original_role_slug}-{suffix}"))
        .map_err(|_| IdentityError::InvalidData("constructed canonical name is invalid".to_owned()))
}

fn validate_canonical_name(
    canonical_name: &str,
    original_role_slug: &str,
) -> Result<(), IdentityError> {
    let suffix = canonical_name
        .strip_prefix(original_role_slug)
        .and_then(|remainder| remainder.strip_prefix('-'))
        .ok_or_else(|| {
            IdentityError::InvalidData(
                "stored canonical name does not match its original role slug".to_owned(),
            )
        })?;
    let expected = canonical_name_from_parts(original_role_slug, suffix)?;
    if expected.as_str() != canonical_name {
        return Err(IdentityError::InvalidData(
            "stored canonical name is not in allocator form".to_owned(),
        ));
    }
    Ok(())
}

fn identity_from_parts(
    pane: &VerifiedPane,
    harness_session_id: &str,
    canonical_name: String,
    original_role_slug: String,
    current_role: String,
) -> Result<AgentIdentity, IdentityError> {
    Ok(AgentIdentity {
        canonical_name: AgentName::parse(&canonical_name).map_err(|_| {
            IdentityError::InvalidData("stored canonical name is invalid".to_owned())
        })?,
        original_role_slug,
        current_role: RoleLabel::parse(&current_role)
            .map_err(|_| IdentityError::InvalidData("stored role is invalid".to_owned()))?,
        pane_id: pane.pane_id.clone(),
        harness: pane.harness.clone(),
        harness_session_id: harness_session_id.to_owned(),
        workspace_id: pane.workspace_id.clone(),
    })
}

fn is_constraint_violation(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == ErrorCode::ConstraintViolation
    )
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        path::PathBuf,
        sync::{Arc, Mutex},
    };

    use herdr_a2a_core::{RoleLabel, VerifiedPane};

    use super::{IdentityStore, SuffixSource, canonical_slug};

    fn pane(role: &str, pane_id: &str, workspace_id: &str) -> VerifiedPane {
        VerifiedPane {
            pane_id: pane_id.to_owned(),
            workspace_id: workspace_id.to_owned(),
            role: RoleLabel::parse(role).unwrap(),
            harness: "pi".to_owned(),
            workspace_path: PathBuf::from("/repo"),
        }
    }

    #[derive(Clone)]
    struct SequenceSuffixes(Arc<Mutex<VecDeque<&'static str>>>);

    impl SequenceSuffixes {
        fn new(values: impl IntoIterator<Item = &'static str>) -> Self {
            Self(Arc::new(Mutex::new(values.into_iter().collect())))
        }
    }

    impl SuffixSource for SequenceSuffixes {
        fn suffix(&self) -> Result<String, super::IdentityError> {
            Ok(self.0.lock().unwrap().pop_front().unwrap().to_owned())
        }
    }

    #[tokio::test]
    async fn same_process_keeps_canonical_identity_across_broker_restart() {
        // Break caught: canonical authority is regenerated after the broker reopens its database.
        let directory = tempfile::tempdir().unwrap();
        let db = directory.path().join("identity.sqlite3");
        let store = IdentityStore::open(&db).unwrap();
        let first = store
            .resolve_or_create(&pane("worker", "w1:p2", "w1"), "pi-session-a")
            .await
            .unwrap();
        drop(store);

        let reopened = IdentityStore::open(&db).unwrap();
        let second = reopened
            .resolve_or_create(&pane("reviewer", "w1:p2", "w1"), "pi-session-a")
            .await
            .unwrap();

        assert_eq!(first.canonical_name, second.canonical_name);
        assert_eq!(second.current_role.as_str(), "reviewer");
    }

    #[tokio::test]
    async fn new_process_with_old_role_gets_new_identity() {
        // Break caught: lookup omits harness_session_id and transfers retained authority.
        let store = IdentityStore::open(":memory:").unwrap();
        let old = store
            .resolve_or_create(&pane("worker", "w1:p2", "w1"), "pi-session-a")
            .await
            .unwrap();
        let new = store
            .resolve_or_create(&pane("worker", "w1:p2", "w1"), "pi-session-b")
            .await
            .unwrap();

        assert_ne!(old.canonical_name, new.canonical_name);
    }

    #[test]
    fn identity_slugs_are_ascii_bounded_and_have_safe_fallbacks() {
        // Break caught: display Unicode/punctuation leaks into canonical authority names.
        for (label, expected) in [
            (None, "agent"),
            (Some("Réviewer"), "r-viewer"),
            (Some("---"), "agent"),
        ] {
            assert_eq!(canonical_slug(label), expected);
        }
    }

    #[tokio::test]
    async fn identity_allocation_retries_a_sqlite_uniqueness_collision() {
        // Break caught: the allocator gives up or duplicates a canonical name on one collision.
        let suffixes = SequenceSuffixes::new(["a2b3", "a2b3", "c3d4"]);
        let store = IdentityStore::open_with_suffix_source(":memory:", suffixes).unwrap();
        let first = store
            .resolve_or_create(&pane("worker", "w1:p1", "w1"), "session-a")
            .await
            .unwrap();
        let second = store
            .resolve_or_create(&pane("worker", "w1:p2", "w1"), "session-b")
            .await
            .unwrap();

        assert_eq!(first.canonical_name.as_str(), "worker-a2b3");
        assert_eq!(second.canonical_name.as_str(), "worker-c3d4");
    }

    #[tokio::test]
    async fn identity_store_rejects_another_workspace() {
        // Break caught: one scoped identity database accepts principals from another workspace.
        let store = IdentityStore::open(":memory:").unwrap();
        store
            .resolve_or_create(&pane("worker", "w1:p1", "workspace-left"), "session-a")
            .await
            .unwrap();

        assert!(
            store
                .resolve_or_create(&pane("worker", "w2:p1", "workspace-right"), "session-b")
                .await
                .is_err()
        );
    }

    #[test]
    fn identity_store_fails_closed_on_malformed_persisted_rows() {
        // Break caught: startup publishes a broker after accepting malformed durable authority.
        let directory = tempfile::tempdir().unwrap();
        let db = directory.path().join("identity.sqlite3");
        drop(IdentityStore::open(&db).unwrap());
        let connection = rusqlite::Connection::open(&db).unwrap();
        connection
            .execute(
                "INSERT INTO agent_identities
                 (workspace_id, pane_id, harness, harness_session_id, canonical_name,
                  original_role_slug, current_role)
                 VALUES ('w1', 'w1:p1', 'pi', 'session-a', 'INVALID', 'worker', 'worker')",
                [],
            )
            .unwrap();
        drop(connection);

        assert!(IdentityStore::open(&db).is_err());
    }

    #[test]
    fn identity_store_rejects_canonical_names_outside_allocator_shape() {
        // Break caught: independently valid name/slug fields bypass the allocator's
        // `<original-role-slug>-<bounded-base32-suffix>` durable authority grammar.
        for (canonical_name, original_role_slug) in [
            ("worker", "worker"),
            ("other-abcd", "worker"),
            ("worker_abcd", "worker"),
            ("worker-ab10", "worker"),
            ("worker-abc", "worker"),
            ("worker-abcdefghi", "worker"),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let db = directory.path().join("identity.sqlite3");
            drop(IdentityStore::open(&db).unwrap());
            let connection = rusqlite::Connection::open(&db).unwrap();
            connection
                .execute(
                    "INSERT INTO agent_identities
                     (workspace_id, pane_id, harness, harness_session_id, canonical_name,
                      original_role_slug, current_role)
                     VALUES (?1, 'w1:p1', 'pi', 'session-a', ?2, ?3, 'worker')",
                    rusqlite::params!["w1", canonical_name, original_role_slug],
                )
                .unwrap();
            drop(connection);

            assert!(
                IdentityStore::open(&db).is_err(),
                "startup accepted canonical={canonical_name:?}, slug={original_role_slug:?}"
            );
        }
    }
}
