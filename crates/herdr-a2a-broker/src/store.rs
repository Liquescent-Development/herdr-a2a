use std::{
    ffi::OsString,
    fmt, fs,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
};

use a2a::{A2AError, ListTasksRequest, ListTasksResponse, Task, TaskState};
use a2a_server::TaskStore;
use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use herdr_a2a_core::{AgentName, MAX_RETAINED_TASKS, RegistrationId, TERMINAL_RETENTION_MS};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use rustix::fs::{Mode, OFlags, open, openat};
use serde::{Deserialize, Serialize};

use crate::IdentityStore;

const DEFAULT_PAGE_SIZE: i32 = 50;
const MIN_PAGE_SIZE: i32 = 1;
const MAX_PAGE_SIZE: i32 = 100;
const PAGE_CURSOR_VERSION: u8 = 3;
const MAX_PAGE_TOKEN_BYTES: usize = 2 * 1024;
const MAX_READ_ONLY_SNAPSHOT_BYTES: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Debug)]
pub enum StoreError {
    Sqlite(rusqlite::Error),
    InvalidData(String),
    UnsafeFile(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(error) => write!(formatter, "failed to open task store: {error}"),
            Self::InvalidData(message) => {
                write!(formatter, "task store data is invalid: {message}")
            }
            Self::UnsafeFile(message) => write!(formatter, "task store file is unsafe: {message}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sqlite(error) => Some(error),
            Self::InvalidData(_) | Self::UnsafeFile(_) => None,
        }
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

#[derive(Clone)]
pub struct SqliteTaskStore {
    pub(crate) connection: Arc<Mutex<Connection>>,
    identity_store: IdentityStore,
    #[cfg(test)]
    allow_uncoordinated_sdk_writes: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskPrincipal {
    pub sender: AgentName,
    pub recipient: AgentName,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StoreRecoveryReport {
    pub pruned_quarantined_tasks: usize,
    pub repaired_projections: usize,
    pub quarantined_legacy_tasks: usize,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TaskOwnerClaim {
    pub(crate) registration_id: RegistrationId,
    pub(crate) recipient: AgentName,
}

impl SqliteTaskStore {
    pub fn validate_read_only(path: impl AsRef<Path>) -> Result<(), StoreError> {
        validate_read_only_impl(path.as_ref(), || {}, || {})
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let connection = Connection::open(path)?;
        connection.execute_batch(
            "PRAGMA busy_timeout = 5000;
             CREATE TABLE IF NOT EXISTS tasks (
                 task_id TEXT PRIMARY KEY,
                 context_id TEXT NOT NULL,
                 state TEXT NOT NULL,
                 status_timestamp TEXT NOT NULL,
                 version INTEGER NOT NULL CHECK (version >= 1),
                 task_json TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS tasks_list_order
                 ON tasks(status_timestamp DESC, task_id DESC);
             CREATE TABLE IF NOT EXISTS task_owners (
                 task_id TEXT PRIMARY KEY,
                 registration_id TEXT NOT NULL,
                 recipient TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS task_owners_registration
                 ON task_owners(registration_id, task_id);",
        )?;
        let has_recipient_column = {
            let mut statement = connection.prepare("PRAGMA table_info(task_owners)")?;
            statement
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<Result<Vec<_>, _>>()?
                .iter()
                .any(|column| column == "recipient")
        };
        if !has_recipient_column {
            connection.execute("ALTER TABLE task_owners ADD COLUMN recipient TEXT", [])?;
        }
        let connection = Arc::new(Mutex::new(connection));
        let identity_store = IdentityStore::from_shared_connection(Arc::clone(&connection))
            .map_err(|error| StoreError::InvalidData(error.to_string()))?;
        Ok(Self {
            connection,
            identity_store,
            #[cfg(test)]
            allow_uncoordinated_sdk_writes: false,
        })
    }

    pub fn identity_store(&self) -> IdentityStore {
        self.identity_store.clone()
    }

    #[cfg(test)]
    pub(crate) fn with_uncoordinated_sdk_writes_for_legacy_tests(mut self) -> Self {
        self.allow_uncoordinated_sdk_writes = true;
        self
    }

    #[cfg(test)]
    async fn apply_uncoordinated_test_projection(
        &self,
        task: Task,
        create: bool,
    ) -> Result<u64, A2AError> {
        let columns = TaskColumns::from_task(&task)?;
        self.run_blocking(move |connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| database_error())?;
            let version = if create {
                transaction.execute(
                    "INSERT INTO tasks (task_id, context_id, state, status_timestamp, version, task_json)
                     VALUES (?1, ?2, ?3, ?4, 1, ?5)",
                    params![columns.task_id, columns.context_id, columns.state, columns.status_timestamp, columns.task_json],
                ).map_err(|_| database_error())?;
                1
            } else {
                let changed = transaction.execute(
                    "UPDATE tasks SET context_id=?1, state=?2, status_timestamp=?3,
                                      version=version+1, task_json=?4 WHERE task_id=?5",
                    params![columns.context_id, columns.state, columns.status_timestamp, columns.task_json, columns.task_id],
                ).map_err(|_| database_error())?;
                if changed == 0 {
                    return Err(A2AError::task_not_found(&columns.task_id));
                }
                let version = transaction.query_row(
                    "SELECT version FROM tasks WHERE task_id=?1",
                    [&columns.task_id],
                    |row| row.get::<_, i64>(0),
                ).map_err(|_| database_error())?;
                u64::try_from(version).map_err(|_| database_error())?
            };
            transaction.commit().map_err(|_| database_error())?;
            Ok(version)
        }).await
    }

    pub(crate) async fn run_blocking<T, F>(&self, operation: F) -> Result<T, A2AError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, A2AError> + Send + 'static,
    {
        let connection = Arc::clone(&self.connection);
        tokio::task::spawn_blocking(move || {
            let mut connection = connection
                .lock()
                .map_err(|_| A2AError::internal("task store is unavailable"))?;
            operation(&mut connection)
        })
        .await
        .map_err(|_| A2AError::internal("task store worker failed"))?
    }

    async fn apply_sdk_projection(&self, task: Task) -> Result<u64, A2AError> {
        let columns = TaskColumns::from_task(&task)?;
        self.run_blocking(move |connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| database_error())?;
            let version = crate::ledger::apply_authorized_projection(&transaction, &columns)
                .map_err(projection_error)?;
            transaction.commit().map_err(|_| database_error())?;
            Ok(version)
        })
        .await
    }

    pub async fn claim_task_owner(
        &self,
        task_id: &str,
        registration_id: &RegistrationId,
        recipient: &AgentName,
        now_unix_ms: i64,
    ) -> Result<bool, A2AError> {
        let task_id = task_id.to_owned();
        let registration_id = registration_id.as_str().to_owned();
        let recipient = recipient.as_str().to_owned();
        let cutoff_unix_ms = now_unix_ms.saturating_sub(TERMINAL_RETENTION_MS);
        let cutoff = Utc
            .timestamp_millis_opt(cutoff_unix_ms)
            .single()
            .ok_or_else(|| A2AError::internal("retained task cutoff is invalid"))?
            .to_rfc3339_opts(SecondsFormat::Nanos, true);
        let terminal_states = [
            serialized_string(&TaskState::Completed, "task state serialization failed")?,
            serialized_string(&TaskState::Canceled, "task state serialization failed")?,
            serialized_string(&TaskState::Failed, "task state serialization failed")?,
            serialized_string(&TaskState::Rejected, "task state serialization failed")?,
        ];
        self.run_blocking(move |connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| database_error())?;
            let schema_version: i64 = transaction
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .map_err(|_| database_error())?;
            if schema_version == 1 {
                let retained = transaction
                    .query_row(
                        "SELECT legacy_quarantined FROM delivery_tasks WHERE task_id = ?1",
                        [&task_id],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()
                    .map_err(|_| database_error())?;
                if retained.is_some() {
                    return Err(A2AError::invalid_params("task ID is already retained"));
                }
            }
            transaction
                .execute(
                    "DELETE FROM task_owners
                     WHERE task_id IN (
                         SELECT task_id FROM tasks
                         WHERE state IN (?1, ?2, ?3, ?4) AND status_timestamp <= ?5
                     )",
                    params![
                        terminal_states[0],
                        terminal_states[1],
                        terminal_states[2],
                        terminal_states[3],
                        cutoff,
                    ],
                )
                .map_err(|_| database_error())?;
            transaction
                .execute(
                    "DELETE FROM tasks
                     WHERE state IN (?1, ?2, ?3, ?4) AND status_timestamp <= ?5",
                    params![
                        terminal_states[0],
                        terminal_states[1],
                        terminal_states[2],
                        terminal_states[3],
                        cutoff,
                    ],
                )
                .map_err(|_| database_error())?;
            let existing = transaction
                .query_row(
                    "SELECT registration_id, recipient FROM task_owners WHERE task_id = ?1",
                    [&task_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
                )
                .optional()
                .map_err(|_| database_error())?;
            if let Some((existing_owner, existing_recipient)) = existing {
                if existing_owner != registration_id {
                    return Err(A2AError::invalid_params(
                        "task is owned by another registration",
                    ));
                }
                if existing_recipient.as_deref() != Some(recipient.as_str()) {
                    return Err(A2AError::invalid_params(
                        "task recipient does not match established recipient",
                    ));
                }
                transaction.commit().map_err(|_| database_error())?;
                return Ok(false);
            }
            let retained_owners: i64 = if schema_version == 1 {
                transaction
                    .query_row(
                        "SELECT COUNT(*) FROM (
                             SELECT task_id FROM delivery_tasks
                             UNION ALL
                             SELECT task_owners.task_id FROM task_owners
                             WHERE NOT EXISTS (
                                 SELECT 1 FROM delivery_tasks
                                 WHERE delivery_tasks.task_id = task_owners.task_id
                             )
                         )",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(|_| database_error())?
            } else {
                transaction
                    .query_row("SELECT COUNT(*) FROM task_owners", [], |row| row.get(0))
                    .map_err(|_| database_error())?
            };
            if retained_owners >= MAX_RETAINED_TASKS as i64 {
                transaction.commit().map_err(|_| database_error())?;
                return Err(A2AError::invalid_request(
                    "retained task capacity is exhausted",
                ));
            }
            let task_exists = transaction
                .query_row("SELECT 1 FROM tasks WHERE task_id = ?1", [&task_id], |_| {
                    Ok(())
                })
                .optional()
                .map_err(|_| database_error())?
                .is_some();
            if task_exists {
                return Err(A2AError::invalid_params(
                    "existing task has no established sender owner",
                ));
            }
            transaction
                .execute(
                    "INSERT INTO task_owners (task_id, registration_id, recipient)
                     VALUES (?1, ?2, ?3)",
                    params![task_id, registration_id, recipient],
                )
                .map_err(|_| database_error())?;
            transaction.commit().map_err(|_| database_error())?;
            Ok(true)
        })
        .await
    }

    pub async fn remove_task_owner_if_unpersisted(
        &self,
        task_id: &str,
        registration_id: &RegistrationId,
    ) -> Result<bool, A2AError> {
        let task_id = task_id.to_owned();
        let registration_id = registration_id.as_str().to_owned();
        self.run_blocking(move |connection| {
            let changed = connection
                .execute(
                    "DELETE FROM task_owners
                     WHERE task_id = ?1
                       AND registration_id = ?2
                       AND NOT EXISTS (
                           SELECT 1 FROM tasks WHERE tasks.task_id = task_owners.task_id
                       )",
                    params![task_id, registration_id],
                )
                .map_err(|_| database_error())?;
            Ok(changed == 1)
        })
        .await
    }

    pub async fn task_owner(&self, task_id: &str) -> Result<Option<RegistrationId>, A2AError> {
        let task_id = task_id.to_owned();
        self.run_blocking(move |connection| {
            connection
                .query_row(
                    "SELECT registration_id FROM task_owners WHERE task_id = ?1",
                    [&task_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|_| database_error())?
                .map(|value| {
                    RegistrationId::parse(&value)
                        .map_err(|_| A2AError::internal("stored task owner is invalid"))
                })
                .transpose()
        })
        .await
    }

    #[cfg(test)]
    pub(crate) async fn task_owner_claim(
        &self,
        task_id: &str,
    ) -> Result<Option<TaskOwnerClaim>, A2AError> {
        let task_id = task_id.to_owned();
        self.run_blocking(move |connection| {
            connection
                .query_row(
                    "SELECT registration_id, recipient FROM task_owners WHERE task_id = ?1",
                    [&task_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
                )
                .optional()
                .map_err(|_| database_error())?
                .map(|(registration_id, recipient)| {
                    let registration_id = RegistrationId::parse(&registration_id)
                        .map_err(|_| A2AError::internal("stored task owner is invalid"))?;
                    let recipient = recipient
                        .ok_or_else(|| A2AError::internal("stored task recipient is missing"))?;
                    let recipient = AgentName::parse(&recipient)
                        .map_err(|_| A2AError::internal("stored task recipient is invalid"))?;
                    Ok(TaskOwnerClaim {
                        registration_id,
                        recipient,
                    })
                })
                .transpose()
        })
        .await
    }

    pub async fn list_owned(
        &self,
        sender: &AgentName,
        request: &ListTasksRequest,
    ) -> Result<ListTasksResponse, A2AError> {
        let cursor = decode_cursor(request.page_token.as_deref())?;
        let owner = sender.as_str().to_owned();
        let context_id = request.context_id.clone();
        let state = request
            .status
            .as_ref()
            .map(|state| serialized_string(state, "task state serialization failed"))
            .transpose()?;
        let timestamp_after = request
            .status_timestamp_after
            .as_ref()
            .map(sortable_timestamp);
        let page_size = match request.page_size {
            Some(page_size) if !(MIN_PAGE_SIZE..=MAX_PAGE_SIZE).contains(&page_size) => {
                return Err(A2AError::invalid_params(
                    "page size must be between 1 and 100",
                ));
            }
            Some(page_size) => page_size,
            None => DEFAULT_PAGE_SIZE,
        };
        let result = self
            .run_blocking(move |connection| {
                let cursor_boundary = match cursor {
                    Some(cursor) => {
                        let task_id = connection
                            .query_row(
                                "SELECT tasks.task_id
                                 FROM tasks
                                 JOIN delivery_tasks ON delivery_tasks.task_id = tasks.task_id
                                 WHERE tasks.rowid = ?1
                                   AND delivery_tasks.sender_agent = ?2
                                   AND delivery_tasks.legacy_quarantined = 0",
                                params![cursor.row_id, owner],
                                |row| row.get::<_, String>(0),
                            )
                            .optional()
                            .map_err(|_| database_error())?
                            .ok_or_else(|| A2AError::invalid_params("invalid page token"))?;
                        Some((cursor.status_timestamp, task_id, cursor.row_id))
                    }
                    None => None,
                };
                let total_size: i32 = connection
                    .query_row(
                        "SELECT COUNT(*)
                         FROM tasks
                         JOIN delivery_tasks ON delivery_tasks.task_id = tasks.task_id
                         WHERE delivery_tasks.sender_agent = ?1
                           AND delivery_tasks.legacy_quarantined = 0
                           AND (?2 IS NULL OR tasks.context_id = ?2)
                           AND (?3 IS NULL OR tasks.state = ?3)
                           AND (?4 IS NULL OR tasks.status_timestamp >= ?4)",
                        params![owner, context_id, state, timestamp_after],
                        |row| row.get(0),
                    )
                    .map_err(|_| database_error())?;
                let cursor_timestamp = cursor_boundary
                    .as_ref()
                    .map(|(timestamp, _, _)| timestamp.as_str());
                let cursor_task_id = cursor_boundary
                    .as_ref()
                    .map(|(_, task_id, _)| task_id.as_str());
                let cursor_row_id = cursor_boundary.as_ref().map(|(_, _, row_id)| *row_id);
                let mut statement = connection
                    .prepare(
                        "SELECT tasks.task_json, tasks.status_timestamp,
                                tasks.task_id, tasks.rowid
                         FROM tasks
                         JOIN delivery_tasks ON delivery_tasks.task_id = tasks.task_id
                         WHERE delivery_tasks.sender_agent = ?1
                           AND delivery_tasks.legacy_quarantined = 0
                           AND (?2 IS NULL OR tasks.context_id = ?2)
                           AND (?3 IS NULL OR tasks.state = ?3)
                           AND (?4 IS NULL OR tasks.status_timestamp >= ?4)
                           AND (
                               ?5 IS NULL
                               OR tasks.status_timestamp < ?5
                               OR (tasks.status_timestamp = ?5 AND tasks.task_id < ?6)
                           )
                           AND (?7 IS NULL OR tasks.rowid != ?7)
                         ORDER BY tasks.status_timestamp DESC, tasks.task_id DESC
                         LIMIT ?8",
                    )
                    .map_err(|_| database_error())?;
                let rows = statement
                    .query_map(
                        params![
                            owner,
                            context_id,
                            state,
                            timestamp_after,
                            cursor_timestamp,
                            cursor_task_id,
                            cursor_row_id,
                            i64::from(page_size) + 1,
                        ],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, i64>(3)?,
                            ))
                        },
                    )
                    .map_err(|_| database_error())?;
                let mut tasks = Vec::new();
                for row in rows {
                    let (task_json, status_timestamp, task_id, row_id) =
                        row.map_err(|_| database_error())?;
                    tasks.push((decode_task(task_json)?, status_timestamp, task_id, row_id));
                }
                let has_more = tasks.len() > page_size as usize;
                tasks.truncate(page_size as usize);
                let next_page_token = if has_more {
                    let (_, status_timestamp, _, row_id) = tasks
                        .last()
                        .expect("a page with more results contains a cursor row");
                    encode_cursor(*row_id, status_timestamp.clone())?
                } else {
                    String::new()
                };
                Ok((tasks, next_page_token, total_size))
            })
            .await?;
        let (rows, next_page_token, total_size) = result;
        let tasks = rows
            .into_iter()
            .map(|(mut task, _, _, _)| {
                shape_listed_task(&mut task, request);
                task
            })
            .collect();
        Ok(ListTasksResponse {
            tasks,
            next_page_token,
            page_size,
            total_size,
        })
    }
}

impl StoreError {
    fn from_io(error: std::io::Error) -> Self {
        Self::UnsafeFile(error.to_string())
    }
}

fn validate_read_only_identity(metadata: &fs::Metadata) -> Result<(), StoreError> {
    if !metadata.is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
    {
        return Err(StoreError::UnsafeFile(
            "task store is not a private owned regular file".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
        }
    }
}

struct OpenedDatabaseFile {
    file: File,
    identity: FileIdentity,
}

struct OpenedPrivateDatabase {
    parent: File,
    file_name: OsString,
    main: OpenedDatabaseFile,
    wal: Option<OpenedDatabaseFile>,
    shm: Option<OpenedDatabaseFile>,
}

impl OpenedPrivateDatabase {
    fn open(path: &Path) -> Result<Self, StoreError> {
        let (parent, file_name) = open_private_database_parent(path)?;
        let main = open_database_file(&parent, &file_name)?
            .ok_or_else(|| StoreError::UnsafeFile("task store file does not exist".to_owned()))?;
        let wal = open_database_file(&parent, &wal_name(&file_name))?;
        let shm = open_database_file(&parent, &shm_name(&file_name))?;
        Ok(Self {
            parent,
            file_name,
            main,
            wal,
            shm,
        })
    }

    fn recheck(&self) -> Result<(), StoreError> {
        recheck_database_file(&self.parent, &self.file_name, Some(&self.main))?;
        recheck_database_file(&self.parent, &wal_name(&self.file_name), self.wal.as_ref())?;
        recheck_database_file(&self.parent, &shm_name(&self.file_name), self.shm.as_ref())
    }
}

struct ReadOnlySqliteSnapshot {
    _directory: tempfile::TempDir,
    path: PathBuf,
}

impl ReadOnlySqliteSnapshot {
    fn capture(opened: &OpenedPrivateDatabase) -> Result<Self, StoreError> {
        let snapshot_bytes = opened
            .wal
            .as_ref()
            .map_or(Some(opened.main.identity.length), |wal| {
                opened.main.identity.length.checked_add(wal.identity.length)
            })
            .ok_or_else(|| {
                StoreError::InvalidData("task store snapshot byte count overflowed".to_owned())
            })?;
        if snapshot_bytes > MAX_READ_ONLY_SNAPSHOT_BYTES {
            return Err(StoreError::InvalidData(
                "task store snapshot exceeds its byte limit".to_owned(),
            ));
        }
        let directory = tempfile::Builder::new()
            .prefix("herdr-a2a-doctor-")
            .tempdir()
            .map_err(snapshot_error)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .map_err(snapshot_error)?;
        validate_private_directory_identity(&directory.path().metadata().map_err(snapshot_error)?)?;
        let path = directory.path().join("tasks.sqlite3");
        copy_opened_file(&opened.main, &path)?;
        if let Some(wal) = &opened.wal {
            copy_opened_file(wal, &directory.path().join("tasks.sqlite3-wal"))?;
        }
        Ok(Self {
            _directory: directory,
            path,
        })
    }

    fn validate(&self) -> Result<(), StoreError> {
        let connection = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.pragma_update(None, "query_only", true)?;
        let query_only: i64 = connection.query_row("PRAGMA query_only", [], |row| row.get(0))?;
        if query_only != 1 {
            return Err(StoreError::InvalidData(
                "task store snapshot is not query-only".to_owned(),
            ));
        }
        let quick_check: String =
            connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        if quick_check != "ok" {
            return Err(StoreError::InvalidData(
                "task store quick check failed".to_owned(),
            ));
        }
        crate::ledger::validate_store(&connection)
    }
}

fn validate_read_only_impl(
    path: &Path,
    before_snapshot: impl FnOnce(),
    after_snapshot: impl FnOnce(),
) -> Result<(), StoreError> {
    let opened = OpenedPrivateDatabase::open(path)?;
    before_snapshot();
    let snapshot = ReadOnlySqliteSnapshot::capture(&opened);
    after_snapshot();
    let snapshot = snapshot?;
    opened.recheck()?;
    snapshot.validate()
}

fn copy_opened_file(source: &OpenedDatabaseFile, destination: &Path) -> Result<(), StoreError> {
    if source.identity.length > MAX_READ_ONLY_SNAPSHOT_BYTES {
        return Err(StoreError::InvalidData(
            "task store snapshot exceeds its byte limit".to_owned(),
        ));
    }
    let mut reader = source.file.try_clone().map_err(snapshot_error)?;
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)
        .map_err(snapshot_error)?;
    let copied = std::io::copy(
        &mut Read::by_ref(&mut reader).take(source.identity.length + 1),
        &mut destination,
    )
    .map_err(snapshot_error)?;
    destination.flush().map_err(snapshot_error)?;
    if copied != source.identity.length
        || FileIdentity::from_metadata(&source.file.metadata().map_err(snapshot_error)?)
            != source.identity
    {
        return Err(StoreError::InvalidData(
            "task store changed while its read-only snapshot was captured".to_owned(),
        ));
    }
    Ok(())
}

fn snapshot_error(error: std::io::Error) -> StoreError {
    StoreError::InvalidData(format!(
        "cannot capture read-only task store snapshot: {error}"
    ))
}

fn open_private_database_parent(path: &Path) -> Result<(File, OsString), StoreError> {
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err(StoreError::UnsafeFile(
            "task store path is not absolute".to_owned(),
        ));
    }
    let names = components
        .map(|component| match component {
            Component::Normal(name) => Ok(name),
            _ => Err(StoreError::UnsafeFile(
                "task store path is not normalized".to_owned(),
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (file_name, parents) = names
        .split_last()
        .ok_or_else(|| StoreError::UnsafeFile("task store path has no file name".to_owned()))?;
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = File::from(
        open(Path::new("/"), directory_flags, Mode::empty())
            .map_err(|error| StoreError::UnsafeFile(error.to_string()))?,
    );
    validate_private_directory_identity(&directory.metadata().map_err(StoreError::from_io)?)?;
    for name in parents {
        directory = File::from(
            openat(&directory, *name, directory_flags, Mode::empty())
                .map_err(|error| StoreError::UnsafeFile(error.to_string()))?,
        );
        validate_private_directory_identity(&directory.metadata().map_err(StoreError::from_io)?)?;
    }
    Ok((directory, (*file_name).to_owned()))
}

fn open_database_file(
    parent: &File,
    name: &std::ffi::OsStr,
) -> Result<Option<OpenedDatabaseFile>, StoreError> {
    let file = match openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(file) => File::from(file),
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
        Err(error) => return Err(StoreError::UnsafeFile(error.to_string())),
    };
    let metadata = file.metadata().map_err(StoreError::from_io)?;
    validate_read_only_identity(&metadata)?;
    Ok(Some(OpenedDatabaseFile {
        file,
        identity: FileIdentity::from_metadata(&metadata),
    }))
}

fn recheck_database_file(
    parent: &File,
    name: &std::ffi::OsStr,
    expected: Option<&OpenedDatabaseFile>,
) -> Result<(), StoreError> {
    let actual = open_database_file(parent, name)?;
    match (expected, actual) {
        (None, None) => Ok(()),
        (Some(expected), Some(actual))
            if expected.identity == actual.identity
                && expected.identity
                    == FileIdentity::from_metadata(
                        &expected.file.metadata().map_err(StoreError::from_io)?,
                    ) =>
        {
            Ok(())
        }
        _ => Err(StoreError::InvalidData(
            "task store inode changed during read-only validation".to_owned(),
        )),
    }
}

fn wal_name(file_name: &std::ffi::OsStr) -> OsString {
    let mut bytes = file_name.as_bytes().to_vec();
    bytes.extend_from_slice(b"-wal");
    OsString::from_vec(bytes)
}

fn shm_name(file_name: &std::ffi::OsStr) -> OsString {
    let mut bytes = file_name.as_bytes().to_vec();
    bytes.extend_from_slice(b"-shm");
    OsString::from_vec(bytes)
}

fn validate_private_directory_identity(metadata: &fs::Metadata) -> Result<(), StoreError> {
    let uid = rustix::process::getuid().as_raw();
    let secure_sticky_root = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
    if !metadata.is_dir()
        || (metadata.uid() != 0 && metadata.uid() != uid)
        || (metadata.mode() & 0o022 != 0 && !secure_sticky_root)
    {
        return Err(StoreError::UnsafeFile(
            "task store directory chain is unsafe".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct TaskColumns {
    pub(crate) task_id: String,
    pub(crate) context_id: String,
    pub(crate) state: String,
    pub(crate) status_timestamp: String,
    pub(crate) task_json: String,
}

impl TaskColumns {
    pub(crate) fn from_task(task: &Task) -> Result<Self, A2AError> {
        let state = serialized_string(&task.status.state, "task state serialization failed")?;
        let status_timestamp = task
            .status
            .timestamp
            .as_ref()
            .map(sortable_timestamp)
            .unwrap_or_default();
        let canonical_value = serde_json::to_value(task)
            .map_err(|_| A2AError::internal("task serialization failed"))?;
        let task_json = serde_json::to_string(&canonical_value)
            .map_err(|_| A2AError::internal("task serialization failed"))?;
        Ok(Self {
            task_id: task.id.clone(),
            context_id: task.context_id.clone(),
            state,
            status_timestamp,
            task_json,
        })
    }
}

fn serialized_string<T: Serialize>(value: &T, message: &'static str) -> Result<String, A2AError> {
    serde_json::to_value(value)
        .map_err(|_| A2AError::internal(message))?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| A2AError::internal(message))
}

fn sortable_timestamp(timestamp: &DateTime<Utc>) -> String {
    timestamp.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

pub(crate) fn database_error() -> A2AError {
    A2AError::internal("task store database operation failed")
}

fn projection_error(error: StoreError) -> A2AError {
    match error {
        StoreError::InvalidData(message) if message == "task projection is not authorized" => {
            A2AError::internal(message)
        }
        _ => database_error(),
    }
}

fn decode_task(task_json: String) -> Result<Task, A2AError> {
    serde_json::from_str(&task_json).map_err(|_| A2AError::internal("stored task is invalid"))
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PageCursor {
    version: u8,
    row_id: i64,
    status_timestamp: String,
}

fn decode_cursor(token: Option<&str>) -> Result<Option<PageCursor>, A2AError> {
    token
        .filter(|token| !token.is_empty())
        .map(|token| {
            if token.len() > MAX_PAGE_TOKEN_BYTES {
                return Err(A2AError::invalid_params("invalid page token"));
            }
            let cursor: PageCursor = serde_json::from_str(token)
                .map_err(|_| A2AError::invalid_params("invalid page token"))?;
            if !valid_cursor(&cursor) {
                return Err(A2AError::invalid_params("invalid page token"));
            }
            Ok(cursor)
        })
        .transpose()
}

fn encode_cursor(row_id: i64, status_timestamp: String) -> Result<String, A2AError> {
    let cursor = PageCursor {
        version: PAGE_CURSOR_VERSION,
        row_id,
        status_timestamp,
    };
    if !valid_cursor(&cursor) {
        return Err(A2AError::internal("page token serialization failed"));
    }
    let token = serde_json::to_string(&cursor)
        .map_err(|_| A2AError::internal("page token serialization failed"))?;
    if token.len() > MAX_PAGE_TOKEN_BYTES {
        return Err(A2AError::internal("page token serialization failed"));
    }
    Ok(token)
}

fn valid_cursor(cursor: &PageCursor) -> bool {
    cursor.version == PAGE_CURSOR_VERSION
        && cursor.row_id > 0
        && (cursor.status_timestamp.is_empty()
            || DateTime::parse_from_rfc3339(&cursor.status_timestamp)
                .map(|timestamp| sortable_timestamp(&timestamp.with_timezone(&Utc)))
                .is_ok_and(|normalized| normalized == cursor.status_timestamp))
}

fn shape_listed_task(task: &mut Task, request: &ListTasksRequest) {
    if request.include_artifacts != Some(true) {
        task.artifacts = None;
    }
    if let (Some(history_length), Some(history)) = (request.history_length, task.history.as_mut()) {
        if history_length == 0 {
            history.clear();
        } else if history_length > 0 {
            let history_length = history_length as usize;
            if history.len() > history_length {
                history.drain(..history.len() - history_length);
            }
        }
    }
}

#[async_trait]
impl TaskStore for SqliteTaskStore {
    async fn create(&self, task: Task) -> Result<u64, A2AError> {
        #[cfg(test)]
        if self.allow_uncoordinated_sdk_writes {
            return self.apply_uncoordinated_test_projection(task, true).await;
        }
        self.apply_sdk_projection(task).await
    }

    async fn update(&self, task: Task) -> Result<u64, A2AError> {
        #[cfg(test)]
        if self.allow_uncoordinated_sdk_writes {
            return self.apply_uncoordinated_test_projection(task, false).await;
        }
        self.apply_sdk_projection(task).await
    }

    async fn get(&self, task_id: &str) -> Result<Option<Task>, A2AError> {
        let task_id = task_id.to_owned();
        self.run_blocking(move |connection| {
            let task_json = connection
                .query_row(
                    "SELECT task_json FROM tasks WHERE task_id = ?1",
                    [&task_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|_| database_error())?;
            task_json.map(decode_task).transpose()
        })
        .await
    }

    async fn list(&self, request: &ListTasksRequest) -> Result<ListTasksResponse, A2AError> {
        let cursor = decode_cursor(request.page_token.as_deref())?;
        let context_id = request.context_id.clone();
        let state = request
            .status
            .as_ref()
            .map(|state| serialized_string(state, "task state serialization failed"))
            .transpose()?;
        let timestamp_after = request
            .status_timestamp_after
            .as_ref()
            .map(sortable_timestamp);
        let page_size = match request.page_size {
            Some(page_size) if !(MIN_PAGE_SIZE..=MAX_PAGE_SIZE).contains(&page_size) => {
                return Err(A2AError::invalid_params(
                    "page size must be between 1 and 100",
                ));
            }
            Some(page_size) => page_size,
            None => DEFAULT_PAGE_SIZE,
        };
        let result = self
            .run_blocking(move |connection| {
                let cursor_boundary = match cursor {
                    Some(cursor) => {
                        let task_id = connection
                            .query_row(
                                "SELECT task_id FROM tasks WHERE rowid = ?1",
                                [cursor.row_id],
                                |row| row.get::<_, String>(0),
                            )
                            .optional()
                            .map_err(|_| database_error())?
                            .ok_or_else(|| A2AError::invalid_params("invalid page token"))?;
                        Some((cursor.status_timestamp, task_id, cursor.row_id))
                    }
                    None => None,
                };
                let total_size: i32 = connection
                    .query_row(
                        "SELECT COUNT(*) FROM tasks
                         WHERE (?1 IS NULL OR context_id = ?1)
                           AND (?2 IS NULL OR state = ?2)
                           AND (?3 IS NULL OR status_timestamp >= ?3)",
                        params![context_id, state, timestamp_after],
                        |row| row.get(0),
                    )
                    .map_err(|_| database_error())?;
                let cursor_timestamp = cursor_boundary
                    .as_ref()
                    .map(|(timestamp, _, _)| timestamp.as_str());
                let cursor_task_id = cursor_boundary
                    .as_ref()
                    .map(|(_, task_id, _)| task_id.as_str());
                let cursor_row_id = cursor_boundary.as_ref().map(|(_, _, row_id)| *row_id);
                let mut statement = connection
                    .prepare(
                        "SELECT task_json, status_timestamp, task_id, rowid
                         FROM tasks
                         WHERE (?1 IS NULL OR context_id = ?1)
                           AND (?2 IS NULL OR state = ?2)
                           AND (?3 IS NULL OR status_timestamp >= ?3)
                           AND (
                               ?4 IS NULL
                               OR status_timestamp < ?4
                               OR (status_timestamp = ?4 AND task_id < ?5)
                           )
                           AND (?6 IS NULL OR rowid != ?6)
                         ORDER BY status_timestamp DESC, task_id DESC
                         LIMIT ?7",
                    )
                    .map_err(|_| database_error())?;
                let rows = statement
                    .query_map(
                        params![
                            context_id,
                            state,
                            timestamp_after,
                            cursor_timestamp,
                            cursor_task_id,
                            cursor_row_id,
                            i64::from(page_size) + 1,
                        ],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, i64>(3)?,
                            ))
                        },
                    )
                    .map_err(|_| database_error())?;
                let mut tasks = Vec::new();
                for row in rows {
                    let (task_json, status_timestamp, task_id, row_id) =
                        row.map_err(|_| database_error())?;
                    tasks.push((decode_task(task_json)?, status_timestamp, task_id, row_id));
                }
                let has_more = tasks.len() > page_size as usize;
                tasks.truncate(page_size as usize);
                let next_page_token = if has_more {
                    let (_, status_timestamp, _, row_id) = tasks
                        .last()
                        .expect("a page with more results contains a cursor row");
                    encode_cursor(*row_id, status_timestamp.clone())?
                } else {
                    String::new()
                };
                Ok((tasks, next_page_token, total_size))
            })
            .await?;
        let (rows, next_page_token, total_size) = result;
        let tasks = rows
            .into_iter()
            .map(|(mut task, _, _, _)| {
                shape_listed_task(&mut task, request);
                task
            })
            .collect();
        Ok(ListTasksResponse {
            tasks,
            next_page_token,
            page_size,
            total_size,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::Arc;

    use a2a::{Artifact, ListTasksRequest, Part, Task, TaskState, TaskStatus, error_code};
    use a2a_server::TaskStore;
    use chrono::{TimeZone, Utc};
    use herdr_a2a_core::{
        AgentName, BrokerPersistence, MAX_RETAINED_TASKS, RegistrationId, TERMINAL_RETENTION_MS,
    };
    use rusqlite::params;
    use serde_json::json;
    use tokio::sync::Barrier;

    use super::{SqliteTaskStore, StoreError};

    #[tokio::test]
    async fn read_only_validation_rejects_an_intermediate_symlink() {
        // Break caught: O_NOFOLLOW applies only to the database basename, so an intermediate
        // symlink redirects SQLite and the safety checks into an attacker-selected directory.
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let real = root.join("real/scope");
        fs::create_dir_all(&real).unwrap();
        fs::set_permissions(root.join("real"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let path = real.join("tasks.sqlite3");
        let store = SqliteTaskStore::open(&path).unwrap();
        store.prepare_startup(1).await.unwrap();
        drop(store);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(root.join("real"), root.join("linked")).unwrap();

        let error = SqliteTaskStore::validate_read_only(root.join("linked/scope/tasks.sqlite3"))
            .unwrap_err();

        assert!(matches!(error, StoreError::UnsafeFile(_)), "{error}");
    }

    #[tokio::test]
    async fn read_only_validation_uses_the_verified_inode_after_an_a_b_a_swap() {
        // Break caught: SQLite reopens the pathname after A is verified, validates B, and then a
        // restored A satisfies the final pathname identity comparison.
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let scope = root.join("scope");
        fs::create_dir(&scope).unwrap();
        fs::set_permissions(&scope, fs::Permissions::from_mode(0o700)).unwrap();
        let path = scope.join("tasks.sqlite3");
        let store = SqliteTaskStore::open(&path).unwrap();
        store.prepare_startup(1).await.unwrap();
        drop(store);
        let valid_replacement = scope.join("replacement.sqlite3");
        fs::copy(&path, &valid_replacement).unwrap();
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection.pragma_update(None, "user_version", 999).unwrap();
        drop(connection);
        for file in [&path, &valid_replacement] {
            fs::set_permissions(file, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let original_bytes = fs::read(&path).unwrap();
        let held_original = scope.join("original.sqlite3");
        let swap_path = path.clone();
        let swap_replacement = valid_replacement.clone();
        let swap_held = held_original.clone();
        let restore_path = path.clone();
        let restore_replacement = valid_replacement.clone();
        let restore_held = held_original.clone();

        let result = super::validate_read_only_impl(
            &path,
            move || {
                fs::rename(&swap_path, &swap_held).unwrap();
                fs::rename(&swap_replacement, &swap_path).unwrap();
            },
            move || {
                fs::rename(&restore_path, &restore_replacement).unwrap();
                fs::rename(&restore_held, &restore_path).unwrap();
            },
        );

        assert!(
            matches!(result, Err(StoreError::InvalidData(_))),
            "{result:?}"
        );
        assert_eq!(fs::read(&path).unwrap(), original_bytes);
    }

    #[tokio::test]
    async fn read_only_validation_includes_stable_wal_bytes_without_mutating_the_source() {
        // Break caught: the verified snapshot copies only the main file, so committed WAL state
        // is ignored or SQLite opens and mutates the original WAL/SHM files.
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let scope = root.join("scope");
        fs::create_dir(&scope).unwrap();
        fs::set_permissions(&scope, fs::Permissions::from_mode(0o700)).unwrap();
        let path = scope.join("tasks.sqlite3");
        let store = SqliteTaskStore::open(&path).unwrap();
        store.prepare_startup(1).await.unwrap();
        drop(store);
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .unwrap();
        connection
            .pragma_update(None, "wal_autocheckpoint", 0)
            .unwrap();
        let main_before_update = fs::read(&path).unwrap();
        connection
            .execute_batch("PRAGMA user_version = 999;")
            .unwrap();
        assert_eq!(fs::read(&path).unwrap(), main_before_update);
        assert_eq!(
            connection
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            999
        );
        let wal = scope.join("tasks.sqlite3-wal");
        let shm = scope.join("tasks.sqlite3-shm");
        assert!(wal.exists());
        assert!(shm.exists());
        for file in [&path, &wal, &shm] {
            fs::set_permissions(file, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let main_before = fs::read(&path).unwrap();
        let wal_before = fs::read(&wal).unwrap();
        let shm_before = fs::read(&shm).unwrap();

        let result = SqliteTaskStore::validate_read_only(&path);

        assert!(
            matches!(result, Err(StoreError::InvalidData(_))),
            "{result:?}"
        );
        assert_eq!(fs::read(&path).unwrap(), main_before);
        assert_eq!(fs::read(&wal).unwrap(), wal_before);
        assert_eq!(fs::read(&shm).unwrap(), shm_before);
        drop(connection);
    }

    fn task(id: &str, state: TaskState) -> Task {
        task_at(id, state, 1_000)
    }

    fn task_at(id: &str, state: TaskState, unix_ms: i64) -> Task {
        Task {
            id: id.to_owned(),
            context_id: format!("context-{id}"),
            status: TaskStatus {
                state,
                message: None,
                timestamp: Some(Utc.timestamp_millis_opt(unix_ms).single().unwrap()),
            },
            artifacts: None,
            history: None,
            metadata: None,
        }
    }

    fn list_request(page_size: i32, page_token: Option<String>) -> ListTasksRequest {
        ListTasksRequest {
            context_id: None,
            status: None,
            page_size: Some(page_size),
            page_token,
            history_length: None,
            status_timestamp_after: None,
            include_artifacts: None,
            tenant: None,
        }
    }

    fn test_store() -> SqliteTaskStore {
        SqliteTaskStore::open(":memory:")
            .unwrap()
            .with_uncoordinated_sdk_writes_for_legacy_tests()
    }

    fn recipient(name: &str) -> AgentName {
        AgentName::parse(name).unwrap()
    }

    async fn stored_task_count(store: &SqliteTaskStore) -> i64 {
        store
            .run_blocking(|connection| {
                connection
                    .query_row("SELECT COUNT(*) FROM tasks", [], |row| row.get(0))
                    .map_err(|_| super::database_error())
            })
            .await
            .unwrap()
    }

    async fn stored_owner_count(store: &SqliteTaskStore) -> i64 {
        store
            .run_blocking(|connection| {
                connection
                    .query_row("SELECT COUNT(*) FROM task_owners", [], |row| row.get(0))
                    .map_err(|_| super::database_error())
            })
            .await
            .unwrap()
    }

    async fn stored_task_exists(store: &SqliteTaskStore, task_id: &str) -> bool {
        let task_id = task_id.to_owned();
        store
            .run_blocking(move |connection| {
                connection
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM tasks WHERE task_id = ?1)",
                        [task_id],
                        |row| row.get(0),
                    )
                    .map_err(|_| super::database_error())
            })
            .await
            .unwrap()
    }

    async fn seed_stable_principal(store: &SqliteTaskStore, task_id: &str, sender: &str) {
        let task_id = task_id.to_owned();
        let sender = sender.to_owned();
        store
            .run_blocking(move |connection| {
                let context_id = format!("context-{task_id}");
                connection
                    .execute(
                        "INSERT INTO delivery_tasks (
                     task_id, context_id, sender_agent, recipient_agent, request_json,
                     created_unix_ms, deadline_unix_ms, state, state_version, attempt,
                     legacy_quarantined
                 ) VALUES (?1, ?2, ?3, 'reviewer',
                           '{\"text\":\"fixture\",\"metadata\":{},\"file_refs\":[]}',
                           1000, 86401000, 'queued', 1, 0, 0)",
                        params![task_id, context_id, sender],
                    )
                    .map_err(|_| super::database_error())?;
                Ok(())
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn legacy_rows_are_quarantined_without_identity_guessing_or_projection_rewrite() {
        // Break caught: converting Milestone 1 registration IDs into stable sender names would
        // grant a newly registered principal authority over ambiguous retained work.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.sqlite3");
        let store = SqliteTaskStore::open(&path)
            .unwrap()
            .with_uncoordinated_sdk_writes_for_legacy_tests();
        let now = 4_000_000_000_i64;
        let cutoff = now - TERMINAL_RETENTION_MS;
        let fixtures = [
            ("legacy-working", TaskState::Working, now - 1_000),
            ("legacy-terminal", TaskState::Completed, now - 2_000),
            ("legacy-before-cutoff", TaskState::Failed, cutoff - 1),
            ("legacy-at-cutoff", TaskState::Rejected, cutoff),
        ];
        let original =
            serde_json::to_string(&task_at("legacy-working", TaskState::Working, now - 1_000))
                .unwrap();
        store
            .run_blocking(move |connection| {
                let transaction = connection.transaction().unwrap();
                for (task_id, state, timestamp) in fixtures {
                    let task = task_at(task_id, state.clone(), timestamp);
                    let task_json = serde_json::to_string(&task).unwrap();
                    transaction.execute(
                        "INSERT INTO tasks (task_id, context_id, state, status_timestamp, version, task_json)
                         VALUES (?1, ?2, ?3, ?4, 1, ?5)",
                        params![
                            task_id,
                            task.context_id,
                            super::serialized_string(&state, "state").unwrap(),
                            super::sortable_timestamp(task.status.timestamp.as_ref().unwrap()),
                            task_json,
                        ],
                    ).unwrap();
                    transaction.execute(
                        "INSERT INTO task_owners (task_id, registration_id, recipient)
                         VALUES (?1, '018f47d7-7b31-7cc4-98ef-87a57b028b55', 'reviewer')",
                        [task_id],
                    ).unwrap();
                }
                transaction.execute(
                    "INSERT INTO task_owners (task_id, registration_id, recipient)
                     VALUES ('legacy-owner-only', '018f47d7-7b31-7cc4-98ef-87a57b028b55', 'reviewer')",
                    [],
                ).unwrap();
                transaction.commit().unwrap();
                Ok(())
            })
            .await
            .unwrap();

        let report = store.prepare_startup(now).await.unwrap();
        assert_eq!(report.quarantined_legacy_tasks, 3);
        assert_eq!(report.pruned_quarantined_tasks, 2);
        assert!(
            store
                .task_principal("legacy-working")
                .await
                .unwrap()
                .is_none()
        );
        let preserved = store
            .run_blocking(|connection| {
                connection
                    .query_row(
                        "SELECT task_json FROM tasks WHERE task_id='legacy-working'",
                        [],
                        |row| row.get::<_, String>(0),
                    )
                    .map_err(|_| super::database_error())
            })
            .await
            .unwrap();
        assert_eq!(preserved, original);
        let retained: i64 = store
            .run_blocking(|connection| {
                connection
                    .query_row("SELECT COUNT(*) FROM delivery_tasks", [], |row| row.get(0))
                    .map_err(|_| super::database_error())
            })
            .await
            .unwrap();
        assert_eq!(retained, 3);
        assert!(
            BrokerPersistence::load(&store, now)
                .await
                .unwrap()
                .tasks
                .is_empty()
        );
        assert!(
            store
                .claim_task_owner(
                    "legacy-working",
                    &RegistrationId::new(),
                    &recipient("reviewer"),
                    now,
                )
                .await
                .is_err()
        );

        let before_terminal_expiry = store
            .prepare_startup(now + TERMINAL_RETENTION_MS - 2_000 - 1)
            .await
            .unwrap();
        assert_eq!(before_terminal_expiry.pruned_quarantined_tasks, 0);
        let at_terminal_expiry = store
            .prepare_startup(now + TERMINAL_RETENTION_MS - 2_000)
            .await
            .unwrap();
        assert_eq!(at_terminal_expiry.pruned_quarantined_tasks, 1);
        let before_task_expiry = store
            .prepare_startup(now + TERMINAL_RETENTION_MS - 1_000 - 1)
            .await
            .unwrap();
        assert_eq!(before_task_expiry.pruned_quarantined_tasks, 0);
        let at_task_expiry = store
            .prepare_startup(now + TERMINAL_RETENTION_MS - 1_000)
            .await
            .unwrap();
        assert_eq!(at_task_expiry.pruned_quarantined_tasks, 1);
        assert!(store.get("legacy-working").await.unwrap().is_none());
        assert!(store.task_owner("legacy-working").await.unwrap().is_none());

        let before_tombstone_expiry = store
            .prepare_startup(now + TERMINAL_RETENTION_MS - 1)
            .await
            .unwrap();
        assert_eq!(before_tombstone_expiry.pruned_quarantined_tasks, 0);
        assert!(
            store
                .claim_task_owner(
                    "legacy-owner-only",
                    &RegistrationId::new(),
                    &recipient("reviewer"),
                    now,
                )
                .await
                .is_err()
        );
        let at_tombstone_expiry = store
            .prepare_startup(now + TERMINAL_RETENTION_MS)
            .await
            .unwrap();
        assert_eq!(at_tombstone_expiry.pruned_quarantined_tasks, 1);
        assert!(
            store
                .task_owner("legacy-owner-only")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn owner_claim_rejects_one_over_retained_capacity_without_persisting_owner() {
        // Break caught: admitting an owner after the finite reservation capacity is full leaves
        // a durable pre-persistence claim that prevents future retries from owning its task.
        let store = test_store();
        let owner = RegistrationId::new();
        let now_unix_ms = 2_592_010_000;
        for index in 0..MAX_RETAINED_TASKS {
            let task_id = format!("retained-{index}");
            assert!(
                store
                    .claim_task_owner(&task_id, &owner, &recipient("reviewer"), now_unix_ms)
                    .await
                    .unwrap()
            );
            store
                .create(task_at(&task_id, TaskState::Submitted, now_unix_ms))
                .await
                .unwrap();
        }

        let error = store
            .claim_task_owner("over-cap", &owner, &recipient("reviewer"), now_unix_ms)
            .await
            .unwrap_err();
        assert_eq!(error.message, "retained task capacity is exhausted");
        assert_eq!(stored_task_count(&store).await, MAX_RETAINED_TASKS as i64);
        assert_eq!(stored_owner_count(&store).await, MAX_RETAINED_TASKS as i64);
        assert!(store.task_owner("over-cap").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn owner_claim_prunes_expired_terminal_task_and_owner_atomically() {
        // Break caught: pruning only one durable table or applying the cutoff after inserting the
        // owner leaves expired replay state or an unbounded reservation behind.
        let store = test_store();
        let owner = RegistrationId::new();
        let now_unix_ms = 2_592_010_000;
        let cutoff_unix_ms = now_unix_ms - TERMINAL_RETENTION_MS;
        assert_eq!(cutoff_unix_ms, 10_000);

        assert!(
            store
                .claim_task_owner("expired", &owner, &recipient("reviewer"), now_unix_ms)
                .await
                .unwrap()
        );
        store
            .create(task_at("expired", TaskState::Completed, cutoff_unix_ms))
            .await
            .unwrap();
        assert!(
            store
                .claim_task_owner("younger", &owner, &recipient("reviewer"), now_unix_ms)
                .await
                .unwrap()
        );
        let younger = task_at("younger", TaskState::Failed, cutoff_unix_ms + 1);
        store.create(younger.clone()).await.unwrap();

        assert!(
            store
                .claim_task_owner("replacement", &owner, &recipient("reviewer"), now_unix_ms)
                .await
                .unwrap()
        );
        assert!(store.get("expired").await.unwrap().is_none());
        assert!(store.task_owner("expired").await.unwrap().is_none());
        assert_eq!(
            store.task_owner("replacement").await.unwrap(),
            Some(owner.clone())
        );
        assert_eq!(store.get("younger").await.unwrap(), Some(younger));
    }

    #[tokio::test]
    async fn owner_claim_commits_expired_pruning_when_capacity_remains_exhausted() {
        // Break caught: returning the capacity error before committing rolls back expired task
        // and owner deletion in a legacy database that remains full after pruning.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks.sqlite3");
        let store = SqliteTaskStore::open(&path)
            .unwrap()
            .with_uncoordinated_sdk_writes_for_legacy_tests();
        store
            .run_blocking(|connection| {
                let transaction = connection.transaction().unwrap();
                for index in 0..MAX_RETAINED_TASKS {
                    let task_id = format!("live-{index}");
                    transaction
                        .execute(
                            "INSERT INTO tasks (
                                 task_id, context_id, state, status_timestamp, version, task_json
                             ) VALUES (?1, ?2, 'TASK_STATE_SUBMITTED',
                                 '1970-01-31T00:00:10.000000000Z', 1, '{}')",
                            params![task_id, format!("context-live-{index}")],
                        )
                        .unwrap();
                    transaction
                        .execute(
                            "INSERT INTO task_owners (task_id, registration_id, recipient)
                             VALUES (?1, 'legacy-owner', 'reviewer')",
                            [task_id],
                        )
                        .unwrap();
                }
                for index in 0..2 {
                    let task_id = format!("expired-{index}");
                    transaction
                        .execute(
                            "INSERT INTO tasks (
                                 task_id, context_id, state, status_timestamp, version, task_json
                             ) VALUES (?1, ?2, 'TASK_STATE_COMPLETED',
                                 '1970-01-01T00:00:10.000000000Z', 1, '{}')",
                            params![task_id, format!("context-expired-{index}")],
                        )
                        .unwrap();
                    transaction
                        .execute(
                            "INSERT INTO task_owners (task_id, registration_id, recipient)
                             VALUES (?1, 'legacy-owner', 'reviewer')",
                            [task_id],
                        )
                        .unwrap();
                }
                transaction.commit().unwrap();
                Ok(())
            })
            .await
            .unwrap();

        let error = store
            .claim_task_owner(
                "still-over-cap",
                &RegistrationId::new(),
                &recipient("reviewer"),
                2_592_010_000,
            )
            .await
            .unwrap_err();

        assert_eq!(error.message, "retained task capacity is exhausted");
        assert_eq!(stored_task_count(&store).await, MAX_RETAINED_TASKS as i64);
        assert_eq!(stored_owner_count(&store).await, MAX_RETAINED_TASKS as i64);
        assert!(!stored_task_exists(&store, "expired-0").await);
        assert!(!stored_task_exists(&store, "expired-1").await);
        assert!(store.task_owner("expired-0").await.unwrap().is_none());
        assert!(store.task_owner("expired-1").await.unwrap().is_none());
        assert!(store.task_owner("still-over-cap").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn owner_claim_keeps_younger_terminal_tasks_replayable() {
        // Break caught: using a strict or rounded cutoff prunes a terminal task one millisecond
        // inside its replay window, so a same-ID retry can execute again.
        let store = test_store();
        let owner = RegistrationId::new();
        let now_unix_ms = 2_592_010_000;
        let younger = task_at(
            "younger-terminal",
            TaskState::Rejected,
            now_unix_ms - TERMINAL_RETENTION_MS + 1,
        );
        assert!(
            store
                .claim_task_owner(
                    "younger-terminal",
                    &owner,
                    &recipient("reviewer"),
                    now_unix_ms,
                )
                .await
                .unwrap()
        );
        store.create(younger.clone()).await.unwrap();

        assert!(
            store
                .claim_task_owner("new-claim", &owner, &recipient("reviewer"), now_unix_ms)
                .await
                .unwrap()
        );
        assert_eq!(store.get("younger-terminal").await.unwrap(), Some(younger));
        assert!(
            !store
                .claim_task_owner(
                    "younger-terminal",
                    &owner,
                    &recipient("reviewer"),
                    now_unix_ms,
                )
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn concurrent_owner_claims_cannot_reserve_more_than_retained_capacity() {
        // Break caught: claims serialized only by one store handle's mutex can over-reserve when
        // independent broker connections race against the durable SQLite capacity boundary.
        const AVAILABLE_SLOTS: usize = 4;
        const RACING_CLAIMS: usize = 12;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks.sqlite3");
        let observer = SqliteTaskStore::open(&path).unwrap();
        observer
            .run_blocking(|connection| {
                let transaction = connection.transaction().unwrap();
                for index in 0..MAX_RETAINED_TASKS - AVAILABLE_SLOTS {
                    transaction
                        .execute(
                            "INSERT INTO task_owners (task_id, registration_id, recipient)
                             VALUES (?1, 'prefilled-owner', 'reviewer')",
                            [format!("prefilled-{index}")],
                        )
                        .unwrap();
                }
                transaction.commit().unwrap();
                Ok(())
            })
            .await
            .unwrap();
        let now_unix_ms = 2_592_010_000;
        let start = Arc::new(Barrier::new(RACING_CLAIMS));
        let claims = (0..RACING_CLAIMS).map(|index| {
            let store = SqliteTaskStore::open(&path).unwrap();
            let start = Arc::clone(&start);
            tokio::spawn(async move {
                start.wait().await;
                store
                    .claim_task_owner(
                        &format!("concurrent-{index}"),
                        &RegistrationId::new(),
                        &recipient("reviewer"),
                        now_unix_ms,
                    )
                    .await
            })
        });
        let mut inserted = 0;
        for claim in futures::future::join_all(claims).await {
            match claim.unwrap() {
                Ok(true) => inserted += 1,
                Err(error) => assert_eq!(error.message, "retained task capacity is exhausted"),
                Ok(false) => panic!("unique concurrent task ID was unexpectedly idempotent"),
            }
        }
        assert_eq!(inserted, AVAILABLE_SLOTS);
        assert_eq!(
            stored_owner_count(&observer).await,
            MAX_RETAINED_TASKS as i64
        );
    }

    #[tokio::test]
    async fn task_owner_claim_is_bound_to_its_original_recipient() {
        let store = test_store();
        let owner = RegistrationId::new();
        let reviewer = recipient("reviewer");
        let observer = recipient("observer");

        assert!(
            store
                .claim_task_owner("bound", &owner, &reviewer, 1_000)
                .await
                .unwrap()
        );
        assert!(
            !store
                .claim_task_owner("bound", &owner, &reviewer, 1_000)
                .await
                .unwrap()
        );
        let error = store
            .claim_task_owner("bound", &owner, &observer, 1_000)
            .await
            .unwrap_err();
        assert!(error.message.contains("recipient"), "{error:?}");

        let claim = store.task_owner_claim("bound").await.unwrap().unwrap();
        assert_eq!(claim.registration_id, owner);
        assert_eq!(claim.recipient, reviewer);
    }

    #[tokio::test]
    async fn opening_legacy_owner_schema_migrates_without_rebinding_existing_tasks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy-owner.sqlite3");
        let owner = RegistrationId::new();
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE task_owners (
                     task_id TEXT PRIMARY KEY,
                     registration_id TEXT NOT NULL
                 );",
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO task_owners (task_id, registration_id) VALUES (?1, ?2)",
                params!["legacy", owner.as_str()],
            )
            .unwrap();
        drop(connection);

        let store = SqliteTaskStore::open(&path)
            .unwrap()
            .with_uncoordinated_sdk_writes_for_legacy_tests();
        assert_eq!(
            store.task_owner("legacy").await.unwrap(),
            Some(owner.clone())
        );
        let error = store.task_owner_claim("legacy").await.unwrap_err();
        assert!(error.message.contains("recipient"), "{error:?}");
        assert!(
            store
                .claim_task_owner("legacy", &owner, &recipient("reviewer"), 1_000)
                .await
                .is_err(),
            "a legacy claim must not be rebound from caller-supplied tenant data"
        );

        store
            .claim_task_owner("new", &owner, &recipient("reviewer"), 1_000)
            .await
            .unwrap();
        drop(store);
        let reopened = SqliteTaskStore::open(path).unwrap();
        assert_eq!(
            reopened
                .task_owner_claim("new")
                .await
                .unwrap()
                .unwrap()
                .recipient,
            recipient("reviewer")
        );
    }

    #[tokio::test]
    async fn owned_list_uses_stable_keyset_across_mixed_owners_and_live_changes() {
        let store = test_store();
        store.prepare_startup(1_000).await.unwrap();
        let owner = RegistrationId::new();
        let other = RegistrationId::new();
        let owner_name = recipient("implementer");
        for index in 0..105 {
            let task_id = format!("owner-{index:03}");
            store
                .claim_task_owner(&task_id, &owner, &recipient("reviewer"), 1_000)
                .await
                .unwrap();
            store
                .create(task_at(&task_id, TaskState::Submitted, 1_000))
                .await
                .unwrap();
            seed_stable_principal(&store, &task_id, "implementer").await;
            let task_id = format!("other-{index:03}");
            store
                .claim_task_owner(&task_id, &other, &recipient("reviewer"), 1_000)
                .await
                .unwrap();
            store
                .create(task_at(&task_id, TaskState::Submitted, 1_000))
                .await
                .unwrap();
            seed_stable_principal(&store, &task_id, "observer").await;
        }
        let mut request = list_request(100, None);
        request.status = Some(TaskState::Submitted);
        let first = store.list_owned(&owner_name, &request).await.unwrap();
        assert_eq!(first.total_size, 105);
        assert_eq!(first.tasks.len(), 100);
        assert!(first.tasks.iter().all(|task| task.id.starts_with("owner-")));
        assert_eq!(first.tasks.first().unwrap().id, "owner-104");
        assert_eq!(first.tasks.last().unwrap().id, "owner-005");

        store
            .update(task_at("owner-005", TaskState::Working, 2_000))
            .await
            .unwrap();
        store
            .claim_task_owner("owner-new", &owner, &recipient("reviewer"), 1_000)
            .await
            .unwrap();
        store
            .create(task_at("owner-new", TaskState::Submitted, 3_000))
            .await
            .unwrap();
        seed_stable_principal(&store, "owner-new", "implementer").await;
        request.page_token = Some(first.next_page_token);
        let second = store.list_owned(&owner_name, &request).await.unwrap();

        assert_eq!(second.total_size, 105);
        assert_eq!(second.tasks.len(), 5);
        assert_eq!(
            second
                .tasks
                .iter()
                .map(|task| task.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "owner-004",
                "owner-003",
                "owner-002",
                "owner-001",
                "owner-000"
            ]
        );
        assert!(!second.tasks.iter().any(|task| task.id == "owner-new"));
    }

    #[tokio::test]
    async fn existing_unowned_task_cannot_be_claimed_by_a_new_registration() {
        let store = test_store();
        store
            .create(task("unowned", TaskState::Submitted))
            .await
            .unwrap();

        let error = store
            .claim_task_owner(
                "unowned",
                &RegistrationId::new(),
                &recipient("reviewer"),
                1_000,
            )
            .await
            .unwrap_err();

        assert!(error.message.contains("no established sender owner"));
        assert!(store.task_owner("unowned").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn reopened_store_does_not_give_old_task_to_a_new_registration() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("owned-tasks.sqlite3");
        let old_owner = RegistrationId::new();
        let store = SqliteTaskStore::open(&path)
            .unwrap()
            .with_uncoordinated_sdk_writes_for_legacy_tests();
        store
            .claim_task_owner("old", &old_owner, &recipient("reviewer"), 1_000)
            .await
            .unwrap();
        store
            .create(task("old", TaskState::Submitted))
            .await
            .unwrap();
        drop(store);
        let reopened = SqliteTaskStore::open(path).unwrap();
        reopened.prepare_startup(1_000).await.unwrap();
        let new_owner = RegistrationId::new();
        let new_owner_name = recipient("implementer");

        assert_eq!(
            reopened
                .list_owned(&new_owner_name, &list_request(10, None))
                .await
                .unwrap()
                .total_size,
            0
        );
        assert!(
            reopened
                .claim_task_owner("old", &new_owner, &recipient("reviewer"), 1_000)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn task_survives_store_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks.sqlite3");
        let store = SqliteTaskStore::open(&path)
            .unwrap()
            .with_uncoordinated_sdk_writes_for_legacy_tests();
        store
            .create(task("task-1", TaskState::Submitted))
            .await
            .unwrap();
        drop(store);

        let reopened = SqliteTaskStore::open(&path).unwrap();
        assert_eq!(reopened.get("task-1").await.unwrap().unwrap().id, "task-1");
    }

    #[tokio::test]
    async fn list_tasks_orders_newest_first_and_returns_cursor() {
        let store = test_store();
        store
            .create(task_at("old", TaskState::Submitted, 1_000))
            .await
            .unwrap();
        store
            .create(task_at("new", TaskState::Submitted, 2_000))
            .await
            .unwrap();

        let page = store.list(&list_request(1, None)).await.unwrap();

        assert_eq!(page.tasks[0].id, "new");
        assert!(!page.next_page_token.is_empty());
        assert_eq!(page.total_size, 2);
    }

    #[tokio::test]
    async fn list_orders_fractional_timestamp_after_exact_second() {
        let store = test_store();
        store
            .create(task_at("exact", TaskState::Submitted, 1_000))
            .await
            .unwrap();
        store
            .create(task_at("fractional", TaskState::Submitted, 1_500))
            .await
            .unwrap();

        let page = store.list(&list_request(2, None)).await.unwrap();

        assert_eq!(
            page.tasks
                .iter()
                .map(|task| task.id.as_str())
                .collect::<Vec<_>>(),
            vec!["fractional", "exact"]
        );
    }

    #[tokio::test]
    async fn cursor_continues_after_equal_timestamp_using_descending_task_id() {
        let store = test_store();
        store
            .create(task_at("a", TaskState::Submitted, 1_000))
            .await
            .unwrap();
        store
            .create(task_at("b", TaskState::Submitted, 1_000))
            .await
            .unwrap();

        let first = store.list(&list_request(1, None)).await.unwrap();
        let second = store
            .list(&list_request(1, Some(first.next_page_token)))
            .await
            .unwrap();

        assert_eq!(first.tasks[0].id, "b");
        assert_eq!(second.tasks[0].id, "a");
        assert!(second.next_page_token.is_empty());
    }

    #[tokio::test]
    async fn cursor_boundary_moved_newer_does_not_duplicate_seen_tasks() {
        let store = test_store();
        store
            .create(task_at("seen-top", TaskState::Submitted, 3_000))
            .await
            .unwrap();
        store
            .create(task_at("boundary", TaskState::Submitted, 2_000))
            .await
            .unwrap();
        store
            .create(task_at("unseen", TaskState::Submitted, 1_000))
            .await
            .unwrap();
        let first_page = store.list(&list_request(2, None)).await.unwrap();
        assert_eq!(
            first_page
                .tasks
                .iter()
                .map(|task| task.id.as_str())
                .collect::<Vec<_>>(),
            vec!["seen-top", "boundary"]
        );
        store
            .update(task_at("boundary", TaskState::Working, 4_000))
            .await
            .unwrap();

        let second_page = store
            .list(&list_request(2, Some(first_page.next_page_token)))
            .await
            .unwrap();

        assert_eq!(
            second_page
                .tasks
                .iter()
                .map(|task| task.id.as_str())
                .collect::<Vec<_>>(),
            vec!["unseen"]
        );
    }

    #[tokio::test]
    async fn cursor_boundary_moved_older_does_not_skip_unseen_tasks() {
        let store = test_store();
        store
            .create(task_at("seen-top", TaskState::Submitted, 3_000))
            .await
            .unwrap();
        store
            .create(task_at("boundary", TaskState::Submitted, 2_000))
            .await
            .unwrap();
        store
            .create(task_at("unseen-near", TaskState::Submitted, 1_500))
            .await
            .unwrap();
        store
            .create(task_at("unseen-old", TaskState::Submitted, 1_000))
            .await
            .unwrap();
        let first_page = store.list(&list_request(2, None)).await.unwrap();
        assert_eq!(
            first_page
                .tasks
                .iter()
                .map(|task| task.id.as_str())
                .collect::<Vec<_>>(),
            vec!["seen-top", "boundary"]
        );
        store
            .update(task_at("boundary", TaskState::Working, 500))
            .await
            .unwrap();

        let second_page = store
            .list(&list_request(3, Some(first_page.next_page_token)))
            .await
            .unwrap();

        assert_eq!(
            second_page
                .tasks
                .iter()
                .map(|task| task.id.as_str())
                .collect::<Vec<_>>(),
            vec!["unseen-near", "unseen-old"]
        );
    }

    #[tokio::test]
    async fn update_atomically_replaces_task_and_increments_version() {
        let store = test_store();
        assert_eq!(
            store
                .create(task("task-1", TaskState::Submitted))
                .await
                .unwrap(),
            1
        );

        let version = store
            .update(task("task-1", TaskState::Working))
            .await
            .unwrap();

        assert_eq!(version, 2);
        assert_eq!(
            store.get("task-1").await.unwrap().unwrap().status.state,
            TaskState::Working
        );
    }

    #[tokio::test]
    async fn update_missing_task_returns_official_task_not_found_error() {
        let store = test_store();

        let error = store
            .update(task("missing", TaskState::Working))
            .await
            .unwrap_err();

        assert_eq!(error.code, error_code::TASK_NOT_FOUND);
        assert_eq!(error.message, "task not found: missing");
    }

    #[test]
    fn new_schema_rejects_nonpositive_task_versions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks.sqlite3");
        drop(SqliteTaskStore::open(&path).unwrap());
        let connection = rusqlite::Connection::open(path).unwrap();

        for (task_id, version) in [("zero", 0), ("negative", -1)] {
            let error = connection
                .execute(
                    "INSERT INTO tasks (
                         task_id, context_id, state, status_timestamp, version, task_json
                     ) VALUES (?1, 'context', 'TASK_STATE_SUBMITTED', '', ?2, '{}')",
                    rusqlite::params![task_id, version],
                )
                .unwrap_err();

            assert!(matches!(
                error,
                rusqlite::Error::SqliteFailure(ref failure, _)
                    if failure.code == rusqlite::ErrorCode::ConstraintViolation
            ));
        }
    }

    #[tokio::test]
    async fn nonpositive_legacy_version_rolls_back_entire_update() {
        for malformed_version in [-2_i64, -1] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("tasks.sqlite3");
            let original = task("task-1", TaskState::Submitted);
            let original_json =
                serde_json::to_string(&serde_json::to_value(&original).unwrap()).unwrap();
            let connection = rusqlite::Connection::open(&path).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE tasks (
                         task_id TEXT PRIMARY KEY,
                         context_id TEXT NOT NULL,
                         state TEXT NOT NULL,
                         status_timestamp TEXT NOT NULL,
                         version INTEGER NOT NULL,
                         task_json TEXT NOT NULL
                     );",
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO tasks (
                         task_id, context_id, state, status_timestamp, version, task_json
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![
                        original.id,
                        original.context_id,
                        "TASK_STATE_SUBMITTED",
                        "1970-01-01T00:00:01.000000000Z",
                        malformed_version,
                        original_json,
                    ],
                )
                .unwrap();
            drop(connection);
            let store = SqliteTaskStore::open(&path).unwrap();

            let error = store
                .update(task("task-1", TaskState::Working))
                .await
                .unwrap_err();
            assert_eq!(error.code, error_code::INTERNAL_ERROR);
            drop(store);
            let connection = rusqlite::Connection::open(path).unwrap();
            let (version, state, task_json): (i64, String, String) = connection
                .query_row(
                    "SELECT version, state, task_json FROM tasks WHERE task_id = 'task-1'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            let stored: Task = serde_json::from_str(&task_json).unwrap();

            assert_eq!(version, malformed_version);
            assert_eq!(state, "TASK_STATE_SUBMITTED");
            assert_eq!(stored.status.state, TaskState::Submitted);
        }
    }

    #[tokio::test]
    async fn list_filters_by_context_state_and_timestamp() {
        let store = test_store();
        let mut matching = task_at("matching", TaskState::Working, 3_000);
        matching.context_id = "conversation".into();
        let mut too_old = task_at("too-old", TaskState::Working, 1_000);
        too_old.context_id = "conversation".into();
        let mut wrong_state = task_at("wrong-state", TaskState::Completed, 4_000);
        wrong_state.context_id = "conversation".into();
        store.create(matching).await.unwrap();
        store.create(too_old).await.unwrap();
        store.create(wrong_state).await.unwrap();
        let mut request = list_request(50, None);
        request.context_id = Some("conversation".into());
        request.status = Some(TaskState::Working);
        request.status_timestamp_after = Some(Utc.timestamp_millis_opt(2_000).single().unwrap());

        let page = store.list(&request).await.unwrap();

        assert_eq!(
            page.tasks
                .iter()
                .map(|task| task.id.as_str())
                .collect::<Vec<_>>(),
            vec!["matching"]
        );
        assert_eq!(page.total_size, 1);
    }

    #[tokio::test]
    async fn timestamp_after_includes_tasks_exactly_at_boundary_in_total() {
        let store = test_store();
        store
            .create(task_at("boundary", TaskState::Working, 2_000))
            .await
            .unwrap();
        store
            .create(task_at("newer", TaskState::Working, 3_000))
            .await
            .unwrap();
        store
            .create(task_at("older", TaskState::Working, 1_000))
            .await
            .unwrap();
        let mut request = list_request(50, None);
        request.status_timestamp_after = Some(Utc.timestamp_millis_opt(2_000).single().unwrap());

        let page = store.list(&request).await.unwrap();

        assert_eq!(
            page.tasks
                .iter()
                .map(|task| task.id.as_str())
                .collect::<Vec<_>>(),
            vec!["newer", "boundary"]
        );
        assert_eq!(page.total_size, 2);
    }

    #[tokio::test]
    async fn list_includes_artifacts_only_when_explicitly_requested() {
        let store = test_store();
        let mut stored = task("task-1", TaskState::Completed);
        stored.artifacts = Some(vec![Artifact {
            artifact_id: "artifact-1".into(),
            name: Some("result".into()),
            description: None,
            parts: vec![Part::text("sensitive result")],
            metadata: None,
            extensions: None,
        }]);
        store.create(stored).await.unwrap();

        for (include_artifacts, expected_artifact_id) in [
            (None, None),
            (Some(false), None),
            (Some(true), Some("artifact-1")),
        ] {
            let mut request = list_request(50, None);
            request.include_artifacts = include_artifacts;

            let page = store.list(&request).await.unwrap();
            let artifact_id = page.tasks[0]
                .artifacts
                .as_ref()
                .and_then(|artifacts| artifacts.first())
                .map(|artifact| artifact.artifact_id.as_str());

            assert_eq!(artifact_id, expected_artifact_id);
        }
    }

    #[tokio::test]
    async fn page_size_at_official_maximum_returns_at_most_100_tasks() {
        let store = test_store();
        for index in 0..101 {
            store
                .create(task_at(
                    &format!("task-{index:03}"),
                    TaskState::Submitted,
                    i64::from(index),
                ))
                .await
                .unwrap();
        }

        let page = store.list(&list_request(100, None)).await.unwrap();

        assert_eq!(page.tasks.len(), 100);
        assert_eq!(page.page_size, 100);
        assert_eq!(page.total_size, 101);
        assert!(!page.next_page_token.is_empty());
    }

    #[tokio::test]
    async fn page_size_above_official_maximum_is_rejected_before_querying() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks.sqlite3");
        let store = SqliteTaskStore::open(&path).unwrap();
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection.execute("DROP TABLE tasks", []).unwrap();

        let error = store.list(&list_request(101, None)).await.unwrap_err();

        assert_eq!(error.code, error_code::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn explicit_page_size_below_official_minimum_is_rejected_before_querying() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks.sqlite3");
        let store = SqliteTaskStore::open(&path).unwrap();
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection.execute("DROP TABLE tasks", []).unwrap();

        let error = store.list(&list_request(0, None)).await.unwrap_err();

        assert_eq!(error.code, error_code::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn malformed_page_token_returns_invalid_params() {
        let store = test_store();

        let error = store
            .list(&list_request(1, Some("not-a-cursor".into())))
            .await
            .unwrap_err();

        assert_eq!(error.code, error_code::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn cursor_rejects_missing_or_unknown_fields() {
        let store = test_store();
        for token in [
            r#"{"version":3,"row_id":1}"#,
            r#"{"version":3,"row_id":1,"status_timestamp":"","extra":true}"#,
        ] {
            let error = store
                .list(&list_request(1, Some(token.into())))
                .await
                .unwrap_err();

            assert_eq!(error.code, error_code::INVALID_PARAMS);
        }
    }

    #[tokio::test]
    async fn cursor_rejects_unsupported_version() {
        let store = test_store();
        let token = r#"{"version":2,"row_id":1,"status_timestamp":""}"#;

        let error = store
            .list(&list_request(1, Some(token.into())))
            .await
            .unwrap_err();

        assert_eq!(error.code, error_code::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn cursor_rejects_oversized_token() {
        let store = test_store();
        let token = format!(
            r#"{{"version":3,"row_id":1,"status_timestamp":"","padding":"{}"}}"#,
            "x".repeat(4 * 1024)
        );

        let error = store.list(&list_request(1, Some(token))).await.unwrap_err();

        assert_eq!(error.code, error_code::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn cursor_rejects_nonpositive_row_id() {
        let store = test_store();
        for token in [
            r#"{"version":3,"row_id":0,"status_timestamp":""}"#,
            r#"{"version":3,"row_id":-1,"status_timestamp":""}"#,
        ] {
            let error = store
                .list(&list_request(1, Some(token.into())))
                .await
                .unwrap_err();

            assert_eq!(error.code, error_code::INVALID_PARAMS);
        }
    }

    #[tokio::test]
    async fn cursor_rejects_unknown_row_id() {
        let store = test_store();
        let token = r#"{"version":3,"row_id":9223372036854775807,"status_timestamp":""}"#;

        let error = store
            .list(&list_request(1, Some(token.into())))
            .await
            .unwrap_err();

        assert_eq!(error.code, error_code::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn cursor_rejects_malformed_or_non_normalized_timestamp() {
        let store = test_store();
        for token in [
            r#"{"version":3,"row_id":1,"status_timestamp":"not-a-timestamp"}"#,
            r#"{"version":3,"row_id":1,"status_timestamp":"1970-01-01T00:00:01Z"}"#,
        ] {
            let error = store
                .list(&list_request(1, Some(token.into())))
                .await
                .unwrap_err();

            assert_eq!(error.code, error_code::INVALID_PARAMS);
        }
    }

    async fn assert_accepted_task_id_can_be_cursor_boundary(task_id: String) {
        let store = test_store();
        store
            .create(task_at(&task_id, TaskState::Submitted, 2_000))
            .await
            .unwrap();
        store
            .create(task_at("older", TaskState::Submitted, 1_000))
            .await
            .unwrap();

        let first_page = store.list(&list_request(1, None)).await.unwrap();
        let second_page = store
            .list(&list_request(1, Some(first_page.next_page_token.clone())))
            .await
            .unwrap();

        assert_eq!(first_page.tasks[0].id, task_id);
        assert!(first_page.next_page_token.len() < 256);
        assert_eq!(second_page.tasks[0].id, "older");
    }

    #[tokio::test]
    async fn accepted_empty_task_id_can_be_cursor_boundary() {
        assert_accepted_task_id_can_be_cursor_boundary(String::new()).await;
    }

    #[tokio::test]
    async fn accepted_very_long_task_id_can_be_cursor_boundary() {
        assert_accepted_task_id_can_be_cursor_boundary("x".repeat(8 * 1024)).await;
    }

    #[tokio::test]
    async fn accepted_heavily_escaped_task_id_can_be_cursor_boundary() {
        assert_accepted_task_id_can_be_cursor_boundary("\\\"".repeat(1024)).await;
    }

    #[tokio::test]
    async fn cursor_continues_tasks_without_status_timestamp() {
        let store = test_store();
        let mut first = task("a", TaskState::Submitted);
        first.status.timestamp = None;
        let mut second = task("b", TaskState::Submitted);
        second.status.timestamp = None;
        store.create(first).await.unwrap();
        store.create(second).await.unwrap();

        let first_page = store.list(&list_request(1, None)).await.unwrap();
        let second_page = store
            .list(&list_request(1, Some(first_page.next_page_token)))
            .await
            .unwrap();

        assert_eq!(first_page.tasks[0].id, "b");
        assert_eq!(second_page.tasks[0].id, "a");
    }

    #[tokio::test]
    async fn duplicate_create_reports_internal_error_without_task_content() {
        let store = test_store();
        let mut sensitive = task("task-1", TaskState::Submitted);
        sensitive.context_id = "secret-context-value".into();
        store.create(sensitive.clone()).await.unwrap();

        let error = store.create(sensitive).await.unwrap_err();

        assert_eq!(error.code, error_code::INTERNAL_ERROR);
        assert!(!error.message.contains("secret-context-value"));
    }

    #[tokio::test]
    async fn stored_task_json_is_canonical() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks.sqlite3");
        let store = SqliteTaskStore::open(&path)
            .unwrap()
            .with_uncoordinated_sdk_writes_for_legacy_tests();
        let mut stored = task("task-1", TaskState::Submitted);
        stored.metadata = Some(HashMap::from([
            ("z".into(), json!(2)),
            ("a".into(), json!(1)),
        ]));
        store.create(stored).await.unwrap();
        drop(store);
        let connection = rusqlite::Connection::open(path).unwrap();

        let task_json: String = connection
            .query_row("SELECT task_json FROM tasks", [], |row| row.get(0))
            .unwrap();

        assert_eq!(
            task_json,
            r#"{"contextId":"context-task-1","id":"task-1","metadata":{"a":1,"z":2},"status":{"state":"TASK_STATE_SUBMITTED","timestamp":"1970-01-01T00:00:01Z"}}"#
        );
    }
}
