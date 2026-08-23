use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use a2a::{A2AError, Message, Part, Role, Task, TaskState, TaskStatus};
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use herdr_a2a_core::{
    AgentName, BrokerPersistence, DeliveryId, DomainError, DurableBrokerSnapshot, DurableLease,
    DurableTask, DurableTaskState, MAX_RETAINED_TASKS, PersistenceBatch, PersistenceCommitOutcome,
    RegistrationEpoch, ReplyPayload, TERMINAL_RETENTION_MS, ValidatedPayload,
    validate_persisted_payload, validate_task_id,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};

use crate::store::{
    SqliteTaskStore, StoreError, StoreRecoveryReport, TaskColumns, TaskPrincipal, database_error,
};

const SCHEMA_VERSION: i64 = 1;
const DELIVERY_TTL_MS: i64 = 24 * 60 * 60 * 1_000;
const DELIVERY_LEASE_MS: i64 = 60_000;

const M2A_SCHEMA: &str = "
CREATE TABLE delivery_tasks (
  task_id TEXT PRIMARY KEY,
  context_id TEXT,
  sender_agent TEXT,
  recipient_agent TEXT NOT NULL,
  request_json TEXT,
  created_unix_ms INTEGER NOT NULL,
  deadline_unix_ms INTEGER NOT NULL,
  state TEXT NOT NULL,
  state_version INTEGER NOT NULL CHECK (state_version >= 1),
  delivery_id TEXT,
  lease_expires_unix_ms INTEGER,
  attempt INTEGER NOT NULL CHECK (attempt >= 0),
  acknowledged_unix_ms INTEGER,
  reply_json TEXT,
  terminal_unix_ms INTEGER,
  retain_until_unix_ms INTEGER,
  legacy_quarantined INTEGER NOT NULL DEFAULT 0 CHECK (legacy_quarantined IN (0, 1))
);
CREATE INDEX delivery_tasks_recipient_state
  ON delivery_tasks(recipient_agent, state, created_unix_ms, task_id);
CREATE INDEX delivery_tasks_sender_state
  ON delivery_tasks(sender_agent, state, created_unix_ms, task_id);
CREATE INDEX delivery_tasks_retention
  ON delivery_tasks(retain_until_unix_ms, task_id);
CREATE TABLE broker_meta (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  last_registration_epoch TEXT NOT NULL,
  first_m2a_start_unix_ms INTEGER NOT NULL
);
CREATE TABLE projection_outbox (
  task_id TEXT PRIMARY KEY,
  state_version INTEGER NOT NULL CHECK (state_version >= 1),
  task_json TEXT NOT NULL
);";

#[derive(Debug)]
struct StoredTaskRow {
    task_id: String,
    context_id: Option<String>,
    sender_agent: Option<String>,
    recipient_agent: String,
    request_json: Option<String>,
    created_unix_ms: i64,
    deadline_unix_ms: i64,
    state: String,
    state_version: i64,
    delivery_id: Option<String>,
    lease_expires_unix_ms: Option<i64>,
    attempt: i64,
    acknowledged_unix_ms: Option<i64>,
    reply_json: Option<String>,
    terminal_unix_ms: Option<i64>,
    retain_until_unix_ms: Option<i64>,
    legacy_quarantined: i64,
}

impl StoredTaskRow {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            task_id: row.get(0)?,
            context_id: row.get(1)?,
            sender_agent: row.get(2)?,
            recipient_agent: row.get(3)?,
            request_json: row.get(4)?,
            created_unix_ms: row.get(5)?,
            deadline_unix_ms: row.get(6)?,
            state: row.get(7)?,
            state_version: row.get(8)?,
            delivery_id: row.get(9)?,
            lease_expires_unix_ms: row.get(10)?,
            attempt: row.get(11)?,
            acknowledged_unix_ms: row.get(12)?,
            reply_json: row.get(13)?,
            terminal_unix_ms: row.get(14)?,
            retain_until_unix_ms: row.get(15)?,
            legacy_quarantined: row.get(16)?,
        })
    }
}

impl SqliteTaskStore {
    async fn ledger_blocking<T, F>(&self, operation: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, StoreError> + Send + 'static,
    {
        let connection = Arc::clone(&self.connection);
        tokio::task::spawn_blocking(move || {
            let mut connection = connection
                .lock()
                .map_err(|_| invalid("task store mutex is poisoned"))?;
            operation(&mut connection)
        })
        .await
        .map_err(|_| invalid("task store worker failed"))?
    }

    pub async fn prepare_startup(
        &self,
        now_unix_ms: i64,
    ) -> Result<StoreRecoveryReport, StoreError> {
        if now_unix_ms < 0 {
            return Err(invalid("startup timestamp is negative"));
        }
        let (quarantined_legacy_tasks, pruned_quarantined_tasks) = self
            .ledger_blocking(move |connection| {
                let migrated = migrate_schema(connection, now_unix_ms)?;
                let newly_quarantined = quarantine_owner_only_rows(connection)?;
                let pruned = prune_quarantined(connection, now_unix_ms)?;
                validate_store(connection)?;
                let retained_quarantine = if migrated > 0 || newly_quarantined > 0 {
                    connection.query_row(
                        "SELECT COUNT(*) FROM delivery_tasks WHERE legacy_quarantined = 1",
                        [],
                        |row| row.get::<_, i64>(0),
                    )?
                } else {
                    0
                };
                Ok((usize_from_i64(retained_quarantine)?, pruned))
            })
            .await?;
        let repaired_projections = self.apply_pending_projections().await?;
        Ok(StoreRecoveryReport {
            pruned_quarantined_tasks,
            repaired_projections,
            quarantined_legacy_tasks,
        })
    }

    pub async fn apply_pending_projections(&self) -> Result<usize, StoreError> {
        self.ledger_blocking(|connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let pending = {
                let mut statement = transaction.prepare(
                    "SELECT task_id, state_version, task_json
                     FROM projection_outbox ORDER BY task_id",
                )?;
                statement
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    })?
                    .collect::<Result<Vec<_>, _>>()?
            };
            for (task_id, state_version, task_json) in &pending {
                let task: Task = serde_json::from_str(task_json)
                    .map_err(|_| invalid("projection outbox contains invalid task JSON"))?;
                if task.id != *task_id {
                    return Err(invalid("projection task ID does not match outbox key"));
                }
                let columns = TaskColumns::from_task(&task)
                    .map_err(|_| invalid("projection task cannot be encoded"))?;
                let applied_version = apply_authorized_projection(&transaction, &columns)?;
                if applied_version
                    != u64::try_from(*state_version)
                        .map_err(|_| invalid("projection state version is invalid"))?
                {
                    return Err(invalid("intended task projection was not applied"));
                }
            }
            transaction.commit()?;
            Ok(pending.len())
        })
        .await
    }

    pub async fn task_principal(&self, task_id: &str) -> Result<Option<TaskPrincipal>, A2AError> {
        let task_id = task_id.to_owned();
        self.run_blocking(move |connection| {
            let version: i64 = connection
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .map_err(|_| database_error())?;
            if version != SCHEMA_VERSION {
                return Ok(None);
            }
            connection
                .query_row(
                    "SELECT sender_agent, recipient_agent
                     FROM delivery_tasks
                     WHERE task_id = ?1 AND legacy_quarantined = 0",
                    [&task_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()
                .map_err(|_| database_error())?
                .map(|(sender, recipient)| {
                    Ok(TaskPrincipal {
                        sender: AgentName::parse(&sender)
                            .map_err(|_| A2AError::internal("stored task sender is invalid"))?,
                        recipient: AgentName::parse(&recipient)
                            .map_err(|_| A2AError::internal("stored task recipient is invalid"))?,
                    })
                })
                .transpose()
        })
        .await
    }

    #[cfg(test)]
    pub(crate) fn test_execute<P: rusqlite::Params>(
        &self,
        sql: &str,
        params: P,
    ) -> rusqlite::Result<usize> {
        self.connection.lock().unwrap().execute(sql, params)
    }

    #[cfg(test)]
    pub(crate) fn test_text(&self, sql: &str) -> rusqlite::Result<String> {
        self.connection
            .lock()
            .unwrap()
            .query_row(sql, [], |row| row.get(0))
    }

    #[cfg(test)]
    pub(crate) fn test_i64(&self, sql: &str) -> rusqlite::Result<i64> {
        self.connection
            .lock()
            .unwrap()
            .query_row(sql, [], |row| row.get(0))
    }

    #[cfg(test)]
    pub(crate) fn test_prefill_delivery_tasks(&self, count: usize) -> rusqlite::Result<()> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction()?;
        for index in 0..count {
            transaction.execute(
                "INSERT INTO delivery_tasks (
                    task_id, context_id, sender_agent, recipient_agent, request_json,
                    created_unix_ms, deadline_unix_ms, state, state_version, attempt
                 ) VALUES (?1, ?2, 'implementer', 'reviewer', ?3, 1, 86400001, 'queued', 1, 0)",
                params![
                    format!("prefilled-{index}"),
                    format!("context-prefilled-{index}"),
                    r#"{"text":"request","metadata":{},"file_refs":[]}"#,
                ],
            )?;
        }
        transaction.commit()
    }
}

pub(crate) fn apply_authorized_projection(
    transaction: &Transaction<'_>,
    columns: &TaskColumns,
) -> Result<u64, StoreError> {
    let outbox = transaction
        .query_row(
            "SELECT state_version, task_json FROM projection_outbox WHERE task_id = ?1",
            [&columns.task_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((state_version, task_json)) = outbox else {
        let stored = transaction
            .query_row(
                "SELECT version, task_json FROM tasks WHERE task_id = ?1",
                [&columns.task_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        return match stored {
            Some((version, task_json)) if task_json == columns.task_json => u64::try_from(version)
                .ok()
                .filter(|version| *version > 0)
                .ok_or_else(|| invalid("stored task version is invalid")),
            _ => Err(invalid("task projection is not authorized")),
        };
    };
    validate_outbox_entry(transaction, &columns.task_id, state_version, &task_json)?;
    if task_json != columns.task_json {
        return Err(invalid("task projection is not authorized"));
    }
    transaction.execute(
        "INSERT INTO tasks (
             task_id, context_id, state, status_timestamp, version, task_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(task_id) DO UPDATE SET
             context_id = excluded.context_id,
             state = excluded.state,
             status_timestamp = excluded.status_timestamp,
             version = excluded.version,
             task_json = excluded.task_json
         WHERE excluded.version >= tasks.version",
        params![
            &columns.task_id,
            &columns.context_id,
            &columns.state,
            &columns.status_timestamp,
            state_version,
            &columns.task_json,
        ],
    )?;
    let applied = transaction.query_row(
        "SELECT context_id, state, status_timestamp, version, task_json
         FROM tasks WHERE task_id = ?1",
        [&columns.task_id],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
            ))
        },
    )?;
    if applied
        != (
            columns.context_id.clone(),
            columns.state.clone(),
            columns.status_timestamp.clone(),
            state_version,
            columns.task_json.clone(),
        )
    {
        return Err(invalid("intended task projection was not applied"));
    }
    transaction.execute(
        "DELETE FROM projection_outbox WHERE task_id = ?1 AND state_version = ?2",
        params![&columns.task_id, state_version],
    )?;
    u64::try_from(state_version)
        .ok()
        .filter(|version| *version > 0)
        .ok_or_else(|| invalid("projection state version is invalid"))
}

#[async_trait]
impl BrokerPersistence for SqliteTaskStore {
    async fn load(&self, _now_unix_ms: i64) -> Result<DurableBrokerSnapshot, DomainError> {
        self.ledger_blocking(|connection| {
            validate_store(connection)?;
            let epoch_text: String = connection.query_row(
                "SELECT last_registration_epoch FROM broker_meta WHERE singleton = 1",
                [],
                |row| row.get(0),
            )?;
            let epoch = parse_canonical_u64(&epoch_text, "registration epoch")?;
            let rows = {
                let mut statement = connection.prepare(
                    "SELECT task_id, context_id, sender_agent, recipient_agent, request_json,
                            created_unix_ms, deadline_unix_ms, state, state_version, delivery_id,
                            lease_expires_unix_ms, attempt, acknowledged_unix_ms, reply_json,
                            terminal_unix_ms, retain_until_unix_ms, legacy_quarantined
                     FROM delivery_tasks WHERE legacy_quarantined = 0 ORDER BY task_id",
                )?;
                statement
                    .query_map([], StoredTaskRow::from_row)?
                    .collect::<Result<Vec<_>, _>>()?
            };
            let tasks = rows
                .into_iter()
                .map(decode_durable_task)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(DurableBrokerSnapshot {
                last_registration_epoch: RegistrationEpoch::from_u64(epoch),
                tasks,
            })
        })
        .await
        .map_err(|_| DomainError::PersistenceUnavailable)
    }

    async fn commit(
        &self,
        batch: PersistenceBatch,
    ) -> Result<PersistenceCommitOutcome, DomainError> {
        let encoded = batch
            .upsert_tasks
            .iter()
            .map(|task| Ok((task.clone(), projection_json(task)?)))
            .collect::<Result<Vec<_>, StoreError>>()
            .map_err(|_| DomainError::PersistenceUnavailable)?;
        let ledger_outcome = self
            .ledger_blocking(move |connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            require_schema(&transaction)?;
            if let Some(epoch) = batch.registration_epoch_high_watermark {
                let current: String = transaction.query_row(
                    "SELECT last_registration_epoch FROM broker_meta WHERE singleton = 1",
                    [],
                    |row| row.get(0),
                )?;
                let current = parse_canonical_u64(&current, "registration epoch")?;
                if epoch.get() > current {
                    transaction.execute(
                        "UPDATE broker_meta SET last_registration_epoch = ?1 WHERE singleton = 1",
                        [epoch.get().to_string()],
                    )?;
                }
            }

            for task_id in &batch.delete_task_ids {
                validate_task_id(task_id).map_err(|_| invalid("delete task ID is invalid"))?;
                transaction.execute("DELETE FROM projection_outbox WHERE task_id = ?1", [task_id])?;
                transaction.execute("DELETE FROM delivery_tasks WHERE task_id = ?1", [task_id])?;
                transaction.execute("DELETE FROM task_owners WHERE task_id = ?1", [task_id])?;
                transaction.execute("DELETE FROM tasks WHERE task_id = ?1", [task_id])?;
            }

            let retained: i64 = transaction.query_row(
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
            )?;
            let mut incoming_ids = HashSet::new();
            let new_ids = encoded.iter().try_fold(0_i64, |count, (task, _)| {
                if !incoming_ids.insert(task.task_id.as_str()) {
                    return Ok(count);
                }
                let exists = transaction
                    .query_row(
                        "SELECT 1 FROM delivery_tasks WHERE task_id = ?1
                         UNION ALL
                         SELECT 1 FROM task_owners WHERE task_id = ?1
                         LIMIT 1",
                        [&task.task_id],
                        |_| Ok(()),
                    )
                    .optional()?
                    .is_some();
                Ok::<_, StoreError>(count + i64::from(!exists))
            })?;
            if retained
                .checked_add(new_ids)
                .is_none_or(|count| count > MAX_RETAINED_TASKS as i64)
            {
                return Err(invalid("retained task capacity is exhausted"));
            }

            for (task, task_json) in encoded {
                validate_durable_for_store(&task)?;
                let existing_quarantine = transaction
                    .query_row(
                        "SELECT legacy_quarantined FROM delivery_tasks WHERE task_id = ?1",
                        [&task.task_id],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()?;
                if existing_quarantine == Some(1) {
                    return Err(invalid("task ID belongs to a quarantined legacy row"));
                }
                let state_version = i64::try_from(task.state_version)
                    .map_err(|_| invalid("state version exceeds SQLite integer range"))?;
                let request_json = canonical_json(&task.payload, "request payload")?;
                let reply_json = task
                    .reply
                    .as_ref()
                    .map(|reply| canonical_json(reply, "reply payload"))
                    .transpose()?;
                let (delivery_id, lease_expires_unix_ms) = task
                    .lease
                    .as_ref()
                    .map(|lease| {
                        (
                            Some(lease.delivery_id.as_str().to_owned()),
                            Some(lease.leased_until_unix_ms),
                        )
                    })
                    .unwrap_or((None, None));
                let affected = transaction.execute(
                    "INSERT INTO delivery_tasks (
                         task_id, context_id, sender_agent, recipient_agent, request_json,
                         created_unix_ms, deadline_unix_ms, state, state_version, delivery_id,
                         lease_expires_unix_ms, attempt, acknowledged_unix_ms, reply_json,
                         terminal_unix_ms, retain_until_unix_ms, legacy_quarantined
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, 0)
                     ON CONFLICT(task_id) DO UPDATE SET
                         context_id = excluded.context_id,
                         sender_agent = excluded.sender_agent,
                         recipient_agent = excluded.recipient_agent,
                         request_json = excluded.request_json,
                         created_unix_ms = excluded.created_unix_ms,
                         deadline_unix_ms = excluded.deadline_unix_ms,
                         state = excluded.state,
                         state_version = excluded.state_version,
                         delivery_id = excluded.delivery_id,
                         lease_expires_unix_ms = excluded.lease_expires_unix_ms,
                         attempt = excluded.attempt,
                         acknowledged_unix_ms = excluded.acknowledged_unix_ms,
                         reply_json = excluded.reply_json,
                         terminal_unix_ms = excluded.terminal_unix_ms,
                         retain_until_unix_ms = excluded.retain_until_unix_ms
                     WHERE excluded.state_version > delivery_tasks.state_version
                       AND delivery_tasks.legacy_quarantined = 0",
                    params![
                        task.task_id,
                        task.context_id,
                        task.sender.as_str(),
                        task.recipient.as_str(),
                        request_json,
                        task.created_unix_ms,
                        task.delivery_deadline_unix_ms,
                        encode_state(&task.state),
                        state_version,
                        delivery_id,
                        lease_expires_unix_ms,
                        i64::from(task.attempt),
                        task.acknowledged_unix_ms,
                        reply_json,
                        task.terminal_unix_ms,
                        task.retention_deadline_unix_ms,
                    ],
                )?;
                if affected == 0 {
                    let stored = stored_task_row(&transaction, &task.task_id)?
                        .ok_or_else(|| invalid("version-suppressed task row is missing"))?;
                    if stored.legacy_quarantined != 0 || decode_durable_task(stored)? != task {
                        return Ok(PersistenceCommitOutcome::ReconciliationRequired);
                    }
                } else {
                    transaction.execute(
                        "INSERT INTO projection_outbox (task_id, state_version, task_json)
                         VALUES (?1, ?2, ?3)
                         ON CONFLICT(task_id) DO UPDATE SET
                             state_version = excluded.state_version,
                             task_json = excluded.task_json
                         WHERE excluded.state_version > projection_outbox.state_version",
                        params![task.task_id, state_version, task_json],
                    )?;
                }
            }
            transaction.commit()?;
            Ok(PersistenceCommitOutcome::Complete)
        })
            .await
            .map_err(|_| DomainError::PersistenceUnavailable)?;
        let projection_outcome = self
            .apply_pending_projections()
            .await
            .map(|_| PersistenceCommitOutcome::Complete)
            .unwrap_or(PersistenceCommitOutcome::ReconciliationRequired);
        if ledger_outcome == PersistenceCommitOutcome::ReconciliationRequired
            || projection_outcome == PersistenceCommitOutcome::ReconciliationRequired
        {
            Ok(PersistenceCommitOutcome::ReconciliationRequired)
        } else {
            Ok(PersistenceCommitOutcome::Complete)
        }
    }
}

fn quarantine_owner_only_rows(connection: &mut Connection) -> Result<usize, StoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_schema(&transaction)?;
    let first_m2a_start_unix_ms: i64 = transaction.query_row(
        "SELECT first_m2a_start_unix_ms FROM broker_meta WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    if first_m2a_start_unix_ms < 0 {
        return Err(invalid("first M2A start timestamp is negative"));
    }
    let retain_until_unix_ms = first_m2a_start_unix_ms
        .checked_add(TERMINAL_RETENTION_MS)
        .ok_or_else(|| invalid("legacy tombstone retention timestamp overflows"))?;
    let owner_only = {
        let mut statement = transaction.prepare(
            "SELECT task_owners.task_id, task_owners.recipient
             FROM task_owners
             LEFT JOIN tasks ON tasks.task_id = task_owners.task_id
             LEFT JOIN delivery_tasks ON delivery_tasks.task_id = task_owners.task_id
             WHERE tasks.task_id IS NULL AND delivery_tasks.task_id IS NULL
             ORDER BY task_owners.task_id",
        )?;
        statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    let retained: i64 =
        transaction.query_row("SELECT COUNT(*) FROM delivery_tasks", [], |row| row.get(0))?;
    if retained
        .checked_add(
            i64::try_from(owner_only.len()).map_err(|_| invalid("owner count exceeds i64"))?,
        )
        .is_none_or(|count| count > MAX_RETAINED_TASKS as i64)
    {
        return Err(invalid(
            "retained task capacity is exhausted by owner quarantine",
        ));
    }
    for (task_id, recipient) in &owner_only {
        validate_task_id(task_id).map_err(|_| invalid("owner-only task ID is invalid"))?;
        let recipient = recipient
            .as_deref()
            .ok_or_else(|| invalid("owner-only recipient is missing"))?;
        AgentName::parse(recipient).map_err(|_| invalid("owner-only recipient is invalid"))?;
        transaction.execute(
            "INSERT INTO delivery_tasks (
                 task_id, context_id, sender_agent, recipient_agent, request_json,
                 created_unix_ms, deadline_unix_ms, state, state_version, attempt,
                 terminal_unix_ms, retain_until_unix_ms, legacy_quarantined
             ) VALUES (?1, NULL, NULL, ?2, NULL, ?3, ?3,
                       'legacy_identity_unavailable', 1, 0, ?3, ?4, 1)",
            params![
                task_id,
                recipient,
                first_m2a_start_unix_ms,
                retain_until_unix_ms
            ],
        )?;
    }
    transaction.commit()?;
    Ok(owner_only.len())
}

fn migrate_schema(connection: &mut Connection, now_unix_ms: i64) -> Result<usize, StoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version: i64 = transaction.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == SCHEMA_VERSION {
        transaction.commit()?;
        return Ok(0);
    }
    if version != 0 {
        return Err(invalid("unsupported SQLite schema version"));
    }
    transaction.execute_batch(M2A_SCHEMA)?;
    transaction.execute(
        "INSERT INTO broker_meta (singleton, last_registration_epoch, first_m2a_start_unix_ms)
         VALUES (1, '0', ?1)",
        [now_unix_ms],
    )?;

    let legacy_tasks = {
        let mut statement = transaction.prepare(
            "SELECT tasks.task_id, tasks.context_id, tasks.status_timestamp, tasks.version,
                    tasks.task_json, task_owners.recipient
             FROM tasks LEFT JOIN task_owners ON task_owners.task_id = tasks.task_id
             ORDER BY tasks.task_id",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    for (task_id, context_id, timestamp, version, task_json, recipient) in legacy_tasks {
        validate_task_id(&task_id).map_err(|_| invalid("legacy task ID is invalid"))?;
        validate_task_id(&context_id).map_err(|_| invalid("legacy context ID is invalid"))?;
        let recipient = recipient.ok_or_else(|| invalid("legacy task recipient is missing"))?;
        AgentName::parse(&recipient).map_err(|_| invalid("legacy task recipient is invalid"))?;
        if version < 1 {
            return Err(invalid("legacy task version is invalid"));
        }
        let decoded: Task =
            serde_json::from_str(&task_json).map_err(|_| invalid("legacy task JSON is invalid"))?;
        if decoded.id != task_id || decoded.context_id != context_id {
            return Err(invalid(
                "legacy task JSON identity does not match its columns",
            ));
        }
        let status_unix_ms = DateTime::parse_from_rfc3339(&timestamp)
            .map_err(|_| invalid("legacy task status timestamp is invalid"))?
            .timestamp_millis();
        let retain_until = status_unix_ms
            .checked_add(TERMINAL_RETENTION_MS)
            .ok_or_else(|| invalid("legacy task retention timestamp overflows"))?;
        transaction.execute(
            "INSERT INTO delivery_tasks (
                 task_id, context_id, sender_agent, recipient_agent, request_json,
                 created_unix_ms, deadline_unix_ms, state, state_version, attempt,
                 terminal_unix_ms, retain_until_unix_ms, legacy_quarantined
             ) VALUES (?1, ?2, NULL, ?3, NULL, ?4, ?4,
                       'legacy_identity_unavailable', ?5, 0, ?4, ?6, 1)",
            params![
                task_id,
                context_id,
                recipient,
                status_unix_ms,
                version,
                retain_until
            ],
        )?;
    }

    let owner_only = {
        let mut statement = transaction.prepare(
            "SELECT task_owners.task_id, task_owners.recipient
             FROM task_owners LEFT JOIN tasks ON tasks.task_id = task_owners.task_id
             WHERE tasks.task_id IS NULL ORDER BY task_owners.task_id",
        )?;
        statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    let tombstone_retention = now_unix_ms
        .checked_add(TERMINAL_RETENTION_MS)
        .ok_or_else(|| invalid("legacy tombstone retention timestamp overflows"))?;
    for (task_id, recipient) in owner_only {
        validate_task_id(&task_id).map_err(|_| invalid("legacy owner task ID is invalid"))?;
        let recipient = recipient.ok_or_else(|| invalid("legacy owner recipient is missing"))?;
        AgentName::parse(&recipient).map_err(|_| invalid("legacy owner recipient is invalid"))?;
        transaction.execute(
            "INSERT INTO delivery_tasks (
                 task_id, context_id, sender_agent, recipient_agent, request_json,
                 created_unix_ms, deadline_unix_ms, state, state_version, attempt,
                 terminal_unix_ms, retain_until_unix_ms, legacy_quarantined
             ) VALUES (?1, NULL, NULL, ?2, NULL, ?3, ?3,
                       'legacy_identity_unavailable', 1, 0, ?3, ?4, 1)",
            params![task_id, recipient, now_unix_ms, tombstone_retention],
        )?;
    }
    let count: i64 =
        transaction.query_row("SELECT COUNT(*) FROM delivery_tasks", [], |row| row.get(0))?;
    if count > MAX_RETAINED_TASKS as i64 {
        return Err(invalid("legacy retained task capacity exceeds 4096"));
    }
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    transaction.commit()?;
    usize_from_i64(count)
}

fn prune_quarantined(connection: &mut Connection, now_unix_ms: i64) -> Result<usize, StoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let task_ids = {
        let mut statement = transaction.prepare(
            "SELECT task_id FROM delivery_tasks
             WHERE legacy_quarantined = 1 AND retain_until_unix_ms <= ?1
             ORDER BY task_id",
        )?;
        statement
            .query_map([now_unix_ms], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };
    for task_id in &task_ids {
        transaction.execute(
            "DELETE FROM projection_outbox WHERE task_id = ?1",
            [task_id],
        )?;
        transaction.execute("DELETE FROM task_owners WHERE task_id = ?1", [task_id])?;
        transaction.execute("DELETE FROM tasks WHERE task_id = ?1", [task_id])?;
        transaction.execute(
            "DELETE FROM delivery_tasks
             WHERE task_id = ?1 AND legacy_quarantined = 1 AND retain_until_unix_ms <= ?2",
            params![task_id, now_unix_ms],
        )?;
    }
    transaction.commit()?;
    Ok(task_ids.len())
}

pub(crate) fn validate_store(connection: &Connection) -> Result<(), StoreError> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version != SCHEMA_VERSION {
        return Err(invalid("M2A schema has not been prepared"));
    }
    let count: i64 =
        connection.query_row("SELECT COUNT(*) FROM delivery_tasks", [], |row| row.get(0))?;
    if count > MAX_RETAINED_TASKS as i64 {
        return Err(invalid("retained task capacity exceeds 4096"));
    }
    let invalid_quarantine: i64 = connection.query_row(
        "SELECT COUNT(*) FROM delivery_tasks
         WHERE legacy_quarantined = 1 AND (
             sender_agent IS NOT NULL OR state != 'legacy_identity_unavailable'
             OR retain_until_unix_ms IS NULL
         )",
        [],
        |row| row.get(0),
    )?;
    if invalid_quarantine != 0 {
        return Err(invalid("legacy quarantine invariant is invalid"));
    }
    let outbox_count: i64 =
        connection.query_row("SELECT COUNT(*) FROM projection_outbox", [], |row| {
            row.get(0)
        })?;
    if outbox_count > count {
        return Err(invalid("projection outbox exceeds retained task count"));
    }
    let outbox = {
        let mut statement = connection.prepare(
            "SELECT task_id, state_version, task_json FROM projection_outbox ORDER BY task_id",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    let mut pending_projection_tasks = HashSet::with_capacity(outbox.len());
    for (task_id, state_version, task_json) in outbox {
        validate_outbox_entry(connection, &task_id, state_version, &task_json)?;
        pending_projection_tasks.insert(task_id);
    }
    let retained = {
        let mut statement = connection.prepare(
            "SELECT task_id, context_id, sender_agent, recipient_agent, request_json,
                    created_unix_ms, deadline_unix_ms, state, state_version, delivery_id,
                    lease_expires_unix_ms, attempt, acknowledged_unix_ms, reply_json,
                    terminal_unix_ms, retain_until_unix_ms, legacy_quarantined
             FROM delivery_tasks
             WHERE legacy_quarantined = 0
             ORDER BY task_id",
        )?;
        statement
            .query_map([], StoredTaskRow::from_row)?
            .collect::<Result<Vec<_>, _>>()?
    };
    for row in retained {
        let task_id = row.task_id.clone();
        let durable = decode_durable_task(row)?;
        let projection_json = projection_json(&durable)?;
        let projection: Task = serde_json::from_str(&projection_json)
            .map_err(|_| invalid("ledger task projection cannot be decoded"))?;
        let expected = TaskColumns::from_task(&projection)
            .map_err(|_| invalid("ledger task projection cannot be encoded"))?;
        let durable_version = i64::try_from(durable.state_version)
            .map_err(|_| invalid("ledger state version exceeds SQLite integer range"))?;
        let stored_projection = connection
            .query_row(
                "SELECT context_id, state, status_timestamp, version, task_json
                 FROM tasks WHERE task_id = ?1",
                [&task_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()?;
        let projection_is_current = stored_projection.is_some_and(
            |(context_id, state, status_timestamp, version, task_json)| {
                context_id == expected.context_id
                    && state == expected.state
                    && status_timestamp == expected.status_timestamp
                    && version == durable_version
                    && task_json == expected.task_json
            },
        );
        if !projection_is_current && !pending_projection_tasks.contains(&task_id) {
            return Err(invalid(
                "task projection differs from the retained ledger without a pending repair",
            ));
        }
    }
    Ok(())
}

fn validate_outbox_entry(
    connection: &Connection,
    task_id: &str,
    state_version: i64,
    task_json: &str,
) -> Result<(), StoreError> {
    let row = stored_task_row(connection, task_id)?
        .ok_or_else(|| invalid("projection outbox has no retained ledger task"))?;
    if row.legacy_quarantined != 0 {
        return Err(invalid("projection outbox references a quarantined task"));
    }
    let durable = decode_durable_task(row)?;
    let durable_version = i64::try_from(durable.state_version)
        .map_err(|_| invalid("ledger state version exceeds SQLite integer range"))?;
    if state_version != durable_version {
        return Err(invalid(
            "projection outbox state version differs from ledger",
        ));
    }
    if task_json != projection_json(&durable)? {
        return Err(invalid(
            "projection outbox JSON differs from ledger projection",
        ));
    }
    Ok(())
}

fn stored_task_row(
    connection: &Connection,
    task_id: &str,
) -> Result<Option<StoredTaskRow>, StoreError> {
    connection
        .query_row(
            "SELECT task_id, context_id, sender_agent, recipient_agent, request_json,
                    created_unix_ms, deadline_unix_ms, state, state_version, delivery_id,
                    lease_expires_unix_ms, attempt, acknowledged_unix_ms, reply_json,
                    terminal_unix_ms, retain_until_unix_ms, legacy_quarantined
             FROM delivery_tasks WHERE task_id = ?1",
            [task_id],
            StoredTaskRow::from_row,
        )
        .optional()
        .map_err(StoreError::from)
}

fn require_schema(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    let version: i64 = transaction.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    (version == SCHEMA_VERSION)
        .then_some(())
        .ok_or_else(|| invalid("M2A schema has not been prepared"))
}

fn validate_durable_for_store(task: &DurableTask) -> Result<(), StoreError> {
    validate_task_id(&task.task_id).map_err(|_| invalid("task ID is invalid"))?;
    validate_task_id(&task.context_id).map_err(|_| invalid("context ID is invalid"))?;
    AgentName::parse(task.sender.as_str()).map_err(|_| invalid("sender is invalid"))?;
    AgentName::parse(task.recipient.as_str()).map_err(|_| invalid("recipient is invalid"))?;
    validate_persisted_payload(&task.payload)
        .map_err(|_| invalid("request payload violates persisted payload bounds"))?;
    if !task.payload.file_refs.is_empty() {
        return Err(invalid(
            "M2A request payload cannot contain file references",
        ));
    }
    if let Some(reply) = &task.reply {
        validate_persisted_payload(&ValidatedPayload {
            text: reply.text.clone(),
            metadata: reply.metadata.clone(),
            file_refs: reply.file_refs.clone(),
        })
        .map_err(|_| invalid("reply payload violates persisted payload bounds"))?;
        if !reply.file_refs.is_empty() {
            return Err(invalid("M2A reply payload cannot contain file references"));
        }
    }
    let expected_deadline = task
        .created_unix_ms
        .checked_add(DELIVERY_TTL_MS)
        .ok_or_else(|| invalid("delivery deadline overflows"))?;
    if task.created_unix_ms < 0
        || task.delivery_deadline_unix_ms != expected_deadline
        || task.state_version == 0
    {
        return Err(invalid("durable task integer bounds are invalid"));
    }
    if task.acknowledged_unix_ms.is_some_and(|acknowledged| {
        acknowledged < task.created_unix_ms || acknowledged > task.delivery_deadline_unix_ms
    }) {
        return Err(invalid("acknowledgement timestamp is out of bounds"));
    }
    if let Some(lease) = &task.lease {
        let leased_unix_ms = lease
            .leased_until_unix_ms
            .checked_sub(DELIVERY_LEASE_MS)
            .ok_or_else(|| invalid("lease transition timestamp underflows"))?;
        if leased_unix_ms < task.created_unix_ms
            || lease.owner != task.recipient
            || lease.attempt != task.attempt
            || task.acknowledged_unix_ms.is_some_and(|acknowledged| {
                acknowledged < leased_unix_ms || acknowledged >= lease.leased_until_unix_ms
            })
        {
            return Err(invalid(
                "durable lease owner, attempt, or timestamp is invalid",
            ));
        }
    }
    match (task.terminal_unix_ms, task.retention_deadline_unix_ms) {
        (None, None) => {}
        (Some(terminal), Some(retention))
            if terminal >= task.created_unix_ms
                && terminal
                    .checked_add(TERMINAL_RETENTION_MS)
                    .is_some_and(|expected| expected == retention) => {}
        _ => return Err(invalid("terminal retention timestamps are invalid")),
    }
    let valid = match task.state {
        DurableTaskState::Queued => {
            task.lease.is_none()
                && task.acknowledged_unix_ms.is_none()
                && task.reply.is_none()
                && task.terminal_unix_ms.is_none()
                && task.retention_deadline_unix_ms.is_none()
        }
        DurableTaskState::Leased => {
            task.lease.is_some()
                && task.acknowledged_unix_ms.is_none()
                && task.reply.is_none()
                && task.terminal_unix_ms.is_none()
                && task.retention_deadline_unix_ms.is_none()
        }
        DurableTaskState::Acknowledged => {
            task.lease.is_some()
                && task.acknowledged_unix_ms.is_some()
                && task.reply.is_none()
                && task.terminal_unix_ms.is_none()
                && task.retention_deadline_unix_ms.is_none()
        }
        DurableTaskState::Replied | DurableTaskState::Failed | DurableTaskState::Rejected => {
            task.lease.is_none()
                && task.acknowledged_unix_ms.is_none()
                && task.reply.is_some()
                && task.terminal_unix_ms.is_some()
                && task.retention_deadline_unix_ms.is_some()
        }
        DurableTaskState::Canceled | DurableTaskState::Expired => {
            task.lease.is_none()
                && task.acknowledged_unix_ms.is_none()
                && task.reply.is_none()
                && task.terminal_unix_ms.is_some()
                && task.retention_deadline_unix_ms.is_some()
        }
    };
    if !valid {
        return Err(invalid("durable task state-specific columns are invalid"));
    }
    Ok(())
}

fn decode_durable_task(row: StoredTaskRow) -> Result<DurableTask, StoreError> {
    if row.legacy_quarantined != 0 {
        return Err(invalid("quarantined task entered recoverable load"));
    }
    let context_id = row
        .context_id
        .ok_or_else(|| invalid("task context ID is missing"))?;
    let sender = row
        .sender_agent
        .ok_or_else(|| invalid("task sender is missing"))?;
    let request_json = row
        .request_json
        .ok_or_else(|| invalid("task request is missing"))?;
    let state_version = u64::try_from(row.state_version)
        .ok()
        .filter(|version| *version > 0)
        .ok_or_else(|| invalid("stored state version is invalid"))?;
    let attempt = u32::try_from(row.attempt).map_err(|_| invalid("stored attempt is invalid"))?;
    let sender = AgentName::parse(&sender).map_err(|_| invalid("stored sender is invalid"))?;
    let recipient = AgentName::parse(&row.recipient_agent)
        .map_err(|_| invalid("stored recipient is invalid"))?;
    let payload: ValidatedPayload = canonical_decode(&request_json, "stored request payload")?;
    let reply: Option<ReplyPayload> = row
        .reply_json
        .as_deref()
        .map(|json| canonical_decode(json, "stored reply payload"))
        .transpose()?;
    let state = decode_state(&row.state)?;
    let lease = match (&row.delivery_id, row.lease_expires_unix_ms) {
        (None, None) => None,
        (Some(delivery_id), Some(leased_until_unix_ms)) => Some(DurableLease {
            delivery_id: DeliveryId::parse(delivery_id)
                .map_err(|_| invalid("stored delivery ID is invalid"))?,
            owner: recipient.clone(),
            leased_until_unix_ms,
            attempt,
        }),
        _ => return Err(invalid("stored lease columns are incomplete")),
    };
    let task = DurableTask {
        task_id: row.task_id,
        context_id,
        sender,
        recipient,
        payload,
        created_unix_ms: row.created_unix_ms,
        delivery_deadline_unix_ms: row.deadline_unix_ms,
        state_version,
        state,
        lease,
        attempt,
        acknowledged_unix_ms: row.acknowledged_unix_ms,
        reply,
        terminal_unix_ms: row.terminal_unix_ms,
        retention_deadline_unix_ms: row.retain_until_unix_ms,
    };
    validate_durable_for_store(&task)?;
    Ok(task)
}

fn projection_json(task: &DurableTask) -> Result<String, StoreError> {
    validate_durable_for_store(task)?;
    let timestamp_ms = match task.state {
        DurableTaskState::Queued => task.created_unix_ms,
        DurableTaskState::Leased => task
            .lease
            .as_ref()
            .ok_or_else(|| invalid("leased transition is missing its lease"))?
            .leased_until_unix_ms
            .checked_sub(DELIVERY_LEASE_MS)
            .ok_or_else(|| invalid("lease transition timestamp underflows"))?,
        DurableTaskState::Acknowledged => task
            .acknowledged_unix_ms
            .ok_or_else(|| invalid("acknowledged transition timestamp is missing"))?,
        DurableTaskState::Replied
        | DurableTaskState::Failed
        | DurableTaskState::Rejected
        | DurableTaskState::Canceled
        | DurableTaskState::Expired => task
            .terminal_unix_ms
            .ok_or_else(|| invalid("terminal transition timestamp is missing"))?,
    };
    let timestamp = Utc
        .timestamp_millis_opt(timestamp_ms)
        .single()
        .ok_or_else(|| invalid("projection timestamp is invalid"))?;
    let request = Message {
        message_id: format!("{}-request", task.task_id),
        context_id: Some(task.context_id.clone()),
        task_id: Some(task.task_id.clone()),
        role: Role::User,
        parts: vec![Part::text(task.payload.text.clone())],
        metadata: json_object(&task.payload.metadata, "request metadata")?,
        extensions: None,
        reference_task_ids: None,
    };
    let reply_message = task
        .reply
        .as_ref()
        .map(|reply| {
            Ok::<Message, StoreError>(Message {
                message_id: format!("{}-reply", task.task_id),
                context_id: Some(task.context_id.clone()),
                task_id: Some(task.task_id.clone()),
                role: Role::Agent,
                parts: vec![Part::text(reply.text.clone())],
                metadata: json_object(&reply.metadata, "reply metadata")?,
                extensions: None,
                reference_task_ids: None,
            })
        })
        .transpose()?;
    let state = match task.state {
        DurableTaskState::Queued => TaskState::Submitted,
        DurableTaskState::Leased | DurableTaskState::Acknowledged => TaskState::Working,
        DurableTaskState::Replied => TaskState::Completed,
        DurableTaskState::Failed => TaskState::Failed,
        DurableTaskState::Rejected => TaskState::Rejected,
        DurableTaskState::Canceled => TaskState::Canceled,
        DurableTaskState::Expired => TaskState::Failed,
    };
    canonical_json(
        &Task {
            id: task.task_id.clone(),
            context_id: task.context_id.clone(),
            status: TaskStatus {
                state,
                message: reply_message,
                timestamp: Some(timestamp),
            },
            artifacts: None,
            history: Some(vec![request]),
            metadata: None,
        },
        "task projection",
    )
}

fn json_object(
    value: &serde_json::Value,
    label: &'static str,
) -> Result<Option<HashMap<String, serde_json::Value>>, StoreError> {
    if value.is_null() {
        return Ok(None);
    }
    serde_json::from_value(value.clone())
        .map(Some)
        .map_err(|_| invalid(format!("{label} is not an object")))
}

fn encode_state(state: &DurableTaskState) -> &'static str {
    match state {
        DurableTaskState::Queued => "queued",
        DurableTaskState::Leased => "leased",
        DurableTaskState::Acknowledged => "acknowledged",
        DurableTaskState::Replied => "replied",
        DurableTaskState::Failed => "failed",
        DurableTaskState::Rejected => "rejected",
        DurableTaskState::Canceled => "canceled",
        DurableTaskState::Expired => "expired",
    }
}

fn decode_state(state: &str) -> Result<DurableTaskState, StoreError> {
    match state {
        "queued" => Ok(DurableTaskState::Queued),
        "leased" => Ok(DurableTaskState::Leased),
        "acknowledged" => Ok(DurableTaskState::Acknowledged),
        "replied" => Ok(DurableTaskState::Replied),
        "failed" => Ok(DurableTaskState::Failed),
        "rejected" => Ok(DurableTaskState::Rejected),
        "canceled" => Ok(DurableTaskState::Canceled),
        "expired" => Ok(DurableTaskState::Expired),
        _ => Err(invalid("stored durable task state is invalid")),
    }
}

fn canonical_json<T: serde::Serialize>(
    value: &T,
    label: &'static str,
) -> Result<String, StoreError> {
    let value = serde_json::to_value(value).map_err(|_| invalid(format!("{label} is invalid")))?;
    serde_json::to_string(&value).map_err(|_| invalid(format!("{label} is invalid")))
}

fn canonical_decode<T: serde::de::DeserializeOwned + serde::Serialize>(
    value: &str,
    label: &'static str,
) -> Result<T, StoreError> {
    let decoded =
        serde_json::from_str(value).map_err(|_| invalid(format!("{label} is invalid")))?;
    if canonical_json(&decoded, label)? != value {
        return Err(invalid(format!("{label} is not canonical JSON")));
    }
    Ok(decoded)
}

fn parse_canonical_u64(value: &str, label: &'static str) -> Result<u64, StoreError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(invalid(format!(
            "{label} is not canonical unsigned decimal"
        )));
    }
    value
        .parse()
        .map_err(|_| invalid(format!("{label} exceeds u64")))
}

fn usize_from_i64(value: i64) -> Result<usize, StoreError> {
    usize::try_from(value).map_err(|_| invalid("stored count is invalid"))
}

fn invalid(message: impl Into<String>) -> StoreError {
    StoreError::InvalidData(message.into())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    };

    use a2a::Task;
    use a2a_server::TaskStore;
    use herdr_a2a_core::{
        AgentName, BrokerClock, BrokerPersistence, BrokerState, DeliveryId, DurableLease,
        DurableTask, DurableTaskState, FileReference, MAX_RETAINED_TASKS, PersistenceBatch,
        PersistenceCommitOutcome, QueuedDelivery, Registration, RegistrationEpoch, RegistrationId,
        ReplyPayload, StartOrResume, TERMINAL_RETENTION_MS, ValidatedPayload, VerifiedAgent,
    };
    use rusqlite::{Connection, params};
    use serde_json::json;
    use tokio::sync::Barrier;

    use super::projection_json;
    use crate::{SqliteTaskStore, store::TaskColumns};

    const NOW: i64 = 4_000_000_000;
    const DELIVERY_TTL_MS: i64 = 24 * 60 * 60 * 1_000;

    #[derive(Clone)]
    struct ManualClock(Arc<AtomicI64>);

    impl ManualClock {
        fn at(unix_ms: i64) -> Self {
            Self(Arc::new(AtomicI64::new(unix_ms)))
        }

        fn advance(&self, millis: i64) {
            self.0.fetch_add(millis, Ordering::SeqCst);
        }
    }

    impl BrokerClock for ManualClock {
        fn now_unix_ms(&self) -> i64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn name(value: &str) -> AgentName {
        AgentName::parse(value).unwrap()
    }

    fn durable(task_id: &str, state_version: u64, state: DurableTaskState) -> DurableTask {
        let terminal = matches!(
            state,
            DurableTaskState::Replied | DurableTaskState::Canceled | DurableTaskState::Expired
        );
        let leased = matches!(
            state,
            DurableTaskState::Leased | DurableTaskState::Acknowledged
        );
        DurableTask {
            task_id: task_id.to_owned(),
            context_id: format!("context-{task_id}"),
            sender: name("implementer"),
            recipient: name("reviewer"),
            payload: ValidatedPayload {
                text: "exact request".to_owned(),
                metadata: json!({"b": 2, "a": 1}),
                file_refs: Vec::<FileReference>::new(),
            },
            created_unix_ms: NOW,
            delivery_deadline_unix_ms: NOW + DELIVERY_TTL_MS,
            state_version,
            state: state.clone(),
            lease: leased.then(|| DurableLease {
                delivery_id: DeliveryId::new(),
                owner: name("reviewer"),
                leased_until_unix_ms: NOW + 60_000,
                attempt: 1,
            }),
            attempt: usize::from(leased) as u32,
            acknowledged_unix_ms: (state == DurableTaskState::Acknowledged).then_some(NOW + 1),
            reply: (state == DurableTaskState::Replied).then(|| ReplyPayload {
                text: "exact reply".to_owned(),
                metadata: json!({"answer": true}),
                file_refs: Vec::new(),
            }),
            terminal_unix_ms: terminal.then_some(NOW + 2),
            retention_deadline_unix_ms: terminal.then_some(NOW + 2 + TERMINAL_RETENTION_MS),
        }
    }

    fn batch(task: DurableTask) -> PersistenceBatch {
        PersistenceBatch {
            registration_epoch_high_watermark: None,
            upsert_tasks: vec![task],
            delete_task_ids: Vec::new(),
        }
    }

    fn verified_agent(agent_name: &str, pane_id: &str) -> VerifiedAgent {
        VerifiedAgent {
            name: name(agent_name),
            pane_id: pane_id.to_owned(),
            harness: "pi".to_owned(),
            workspace: PathBuf::from("/workspace"),
        }
    }

    fn queued_delivery(task_id: &str, text: &str) -> QueuedDelivery {
        QueuedDelivery {
            task_id: task_id.to_owned(),
            context_id: format!("context-{task_id}"),
            sender: name("implementer"),
            recipient: name("reviewer"),
            payload: ValidatedPayload {
                text: text.to_owned(),
                metadata: json!({"priority": "high"}),
                file_refs: Vec::new(),
            },
            created_unix_ms: 0,
            attempt: 0,
        }
    }

    fn reply_payload(text: &str) -> ReplyPayload {
        ReplyPayload {
            text: text.to_owned(),
            metadata: json!({"source": "test"}),
            file_refs: Vec::new(),
        }
    }

    async fn recovered_broker(
        store: &SqliteTaskStore,
        clock: ManualClock,
    ) -> (BrokerState, Registration, Registration) {
        let (broker, _) = BrokerState::recover(clock, store.clone()).await.unwrap();
        let sender = broker
            .register(verified_agent("implementer", "w1:p1"), "sender-session")
            .await
            .unwrap();
        let recipient = broker
            .register(verified_agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        (broker, sender, recipient)
    }

    fn block_projection(store: &SqliteTaskStore) {
        store
            .test_execute(
                "CREATE TRIGGER block_projection BEFORE INSERT ON tasks
                 BEGIN SELECT RAISE(ABORT, 'projection blocked'); END",
                [],
            )
            .unwrap();
    }

    fn unblock_projection(store: &SqliteTaskStore) {
        store
            .test_execute("DROP TRIGGER block_projection", [])
            .unwrap();
    }

    async fn assert_live_ledger_and_projection_match(
        broker: &BrokerState,
        store: &SqliteTaskStore,
        sender: &Registration,
        task_id: &str,
    ) -> DurableTask {
        let live = broker
            .task_snapshot(&sender.credentials(), task_id)
            .await
            .unwrap();
        let durable = BrokerPersistence::load(store, NOW)
            .await
            .unwrap()
            .tasks
            .into_iter()
            .find(|task| task.task_id == task_id)
            .unwrap();
        assert_eq!(live, durable);
        assert!(store.get(task_id).await.unwrap().is_some());
        assert_eq!(
            store
                .test_i64("SELECT COUNT(*) FROM projection_outbox")
                .unwrap(),
            0
        );
        live
    }

    fn scalar_i64(path: &std::path::Path, sql: &str) -> i64 {
        Connection::open(path)
            .unwrap()
            .query_row(sql, [], |row| row.get(0))
            .unwrap()
    }

    #[tokio::test]
    async fn m2a_schema_is_created_transactionally_and_reopens_idempotently() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("schema.sqlite3");
        let store = SqliteTaskStore::open(&path).unwrap();
        let first = store.prepare_startup(NOW).await.unwrap();
        assert_eq!(first.quarantined_legacy_tasks, 0);
        assert_eq!(scalar_i64(&path, "PRAGMA user_version"), 1);
        drop(store);
        let reopened = SqliteTaskStore::open(&path).unwrap();
        let second = reopened.prepare_startup(NOW + 1).await.unwrap();
        assert_eq!(second.quarantined_legacy_tasks, 0);
        assert_eq!(second.repaired_projections, 0);
        assert_eq!(scalar_i64(&path, "PRAGMA user_version"), 1);
        for table in ["delivery_tasks", "broker_meta", "projection_outbox"] {
            assert_eq!(
                Connection::open(&path)
                    .unwrap()
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                        [table],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                1
            );
        }
    }

    #[tokio::test]
    async fn migration_failure_rolls_back_and_retries_without_partial_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("retry.sqlite3");
        let store = SqliteTaskStore::open(&path).unwrap();
        let task_json = serde_json::to_string(&a2a::Task {
            id: "legacy".to_owned(),
            context_id: "context-legacy".to_owned(),
            status: a2a::TaskStatus {
                state: a2a::TaskState::Working,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        })
        .unwrap();
        store.test_execute(
            "INSERT INTO tasks (task_id, context_id, state, status_timestamp, version, task_json) VALUES (?1, ?2, ?3, ?4, 1, ?5)",
            params!["legacy", "context-legacy", "TASK_STATE_WORKING", "invalid", task_json],
        ).unwrap();
        store.test_execute(
            "INSERT INTO task_owners (task_id, registration_id, recipient) VALUES ('legacy', '018f47d7-7b31-7cc4-98ef-87a57b028b55', 'reviewer')",
            [],
        ).unwrap();
        assert!(store.prepare_startup(NOW).await.is_err());
        assert_eq!(scalar_i64(&path, "PRAGMA user_version"), 0);
        assert_eq!(
            scalar_i64(
                &path,
                "SELECT COUNT(*) FROM sqlite_master WHERE name='delivery_tasks'"
            ),
            0
        );
        store.test_execute(
            "UPDATE tasks SET status_timestamp='1970-02-16T07:06:40.000000000Z' WHERE task_id='legacy'",
            [],
        ).unwrap();
        let report = store.prepare_startup(NOW).await.unwrap();
        assert_eq!(report.quarantined_legacy_tasks, 1);
        assert_eq!(scalar_i64(&path, "PRAGMA user_version"), 1);
    }

    #[tokio::test]
    async fn enqueue_retry_after_projection_failure_keeps_live_ledger_and_projection_equal() {
        // Break caught: the first enqueue commits time A to the ledger, then a same-version retry
        // publishes time B only in memory after repairing projection A.
        let store = SqliteTaskStore::open(":memory:").unwrap();
        store.prepare_startup(NOW).await.unwrap();
        let clock = ManualClock::at(NOW);
        let (broker, sender, _) = recovered_broker(&store, clock.clone()).await;
        block_projection(&store);

        assert_eq!(
            broker
                .enqueue(
                    &sender.credentials(),
                    queued_delivery("task-enqueue-retry", "first attempt"),
                )
                .await
                .unwrap_err(),
            herdr_a2a_core::DomainError::PersistenceUnavailable
        );
        let retained_after_failure = store
            .test_i64("SELECT COUNT(*) FROM delivery_tasks WHERE task_id='task-enqueue-retry'")
            .unwrap();
        unblock_projection(&store);
        clock.advance(1);

        let retry = broker
            .start_or_resume(
                &sender.credentials(),
                queued_delivery("task-enqueue-retry", "first attempt"),
            )
            .await
            .unwrap();
        let StartOrResume::Active(retried) = retry else {
            panic!("enqueue retry did not resume the committed task");
        };
        let live =
            assert_live_ledger_and_projection_match(&broker, &store, &sender, "task-enqueue-retry")
                .await;
        let projected = store.get("task-enqueue-retry").await.unwrap().unwrap();

        assert_eq!(retained_after_failure, 1);
        assert_eq!(retried.created_unix_ms, NOW);
        assert_eq!(live.created_unix_ms, NOW);
        assert_eq!(projected.status.timestamp.unwrap().timestamp_millis(), NOW);
        assert_eq!(projected.history.unwrap()[0].text(), Some("first attempt"));
    }

    #[tokio::test]
    async fn list_agents_fails_closed_while_reconciliation_remains_blocked() {
        let store = SqliteTaskStore::open(":memory:").unwrap();
        store.prepare_startup(NOW).await.unwrap();
        let clock = ManualClock::at(NOW);
        let (broker, sender, _) = recovered_broker(&store, clock).await;
        block_projection(&store);
        broker
            .enqueue(
                &sender.credentials(),
                queued_delivery("task-list-barrier", "blocked"),
            )
            .await
            .unwrap_err();

        assert!(broker.list_agents().await.is_empty());
        unblock_projection(&store);
        assert_eq!(broker.list_agents().await.len(), 2);
    }

    #[tokio::test]
    async fn lease_retry_after_projection_failure_keeps_live_ledger_and_projection_equal() {
        // Break caught: a failed projection leaves lease A durable, while a retry returns a fresh
        // delivery ID B and installs only B in the live delivery index.
        let store = SqliteTaskStore::open(":memory:").unwrap();
        store.prepare_startup(NOW).await.unwrap();
        let clock = ManualClock::at(NOW);
        let (broker, sender, recipient) = recovered_broker(&store, clock).await;
        broker
            .enqueue(
                &sender.credentials(),
                queued_delivery("task-lease-retry", "lease me"),
            )
            .await
            .unwrap();
        block_projection(&store);

        assert_eq!(
            broker
                .wait_next(&recipient.credentials(), None)
                .await
                .unwrap_err(),
            herdr_a2a_core::DomainError::PersistenceUnavailable
        );
        let state_after_failure = store
            .test_text("SELECT state FROM delivery_tasks WHERE task_id='task-lease-retry'")
            .unwrap();
        unblock_projection(&store);

        let delivered = broker
            .wait_next(&recipient.credentials(), None)
            .await
            .unwrap();
        let live =
            assert_live_ledger_and_projection_match(&broker, &store, &sender, "task-lease-retry")
                .await;
        let projected = store.get("task-lease-retry").await.unwrap().unwrap();

        assert_eq!(state_after_failure, "leased");
        assert_eq!(live.state_version, 4);
        assert_eq!(
            live.lease.as_ref().unwrap().delivery_id,
            delivered.delivery_id
        );
        assert_eq!(projected.status.state, a2a::TaskState::Working);
    }

    #[tokio::test]
    async fn ack_retry_after_projection_failure_rebinds_the_live_recipient() {
        // Break caught: in-process reconciliation restores an acknowledged lease with no live
        // registration owner, so an exact ACK retry loses its idempotent success behavior.
        let store = SqliteTaskStore::open(":memory:").unwrap();
        store.prepare_startup(NOW).await.unwrap();
        let clock = ManualClock::at(NOW);
        let (broker, sender, recipient) = recovered_broker(&store, clock).await;
        broker
            .enqueue(
                &sender.credentials(),
                queued_delivery("task-ack-retry", "ack me"),
            )
            .await
            .unwrap();
        let delivered = broker
            .wait_next(&recipient.credentials(), None)
            .await
            .unwrap();
        block_projection(&store);

        assert_eq!(
            broker
                .ack_delivery(&recipient.credentials(), &delivered.delivery_id)
                .await
                .unwrap_err(),
            herdr_a2a_core::DomainError::PersistenceUnavailable
        );
        let state_after_failure = store
            .test_text("SELECT state FROM delivery_tasks WHERE task_id='task-ack-retry'")
            .unwrap();
        unblock_projection(&store);

        broker
            .ack_delivery(&recipient.credentials(), &delivered.delivery_id)
            .await
            .unwrap();
        let live =
            assert_live_ledger_and_projection_match(&broker, &store, &sender, "task-ack-retry")
                .await;

        assert_eq!(state_after_failure, "acknowledged");
        assert_eq!(live.state, DurableTaskState::Acknowledged);
        assert_eq!(live.state_version, 3);
    }

    #[tokio::test]
    async fn reply_retry_after_projection_failure_keeps_live_ledger_and_projection_equal() {
        // Break caught: reply A remains authoritative after its projection fails, but a retry with
        // reply B is acknowledged and published only to live waiters.
        let store = SqliteTaskStore::open(":memory:").unwrap();
        store.prepare_startup(NOW).await.unwrap();
        let clock = ManualClock::at(NOW);
        let (broker, sender, recipient) = recovered_broker(&store, clock).await;
        broker
            .enqueue(
                &sender.credentials(),
                queued_delivery("task-reply-retry", "reply to me"),
            )
            .await
            .unwrap();
        let waiter = tokio::spawn({
            let broker = broker.clone();
            let sender = sender.clone();
            async move {
                broker
                    .wait_for_reply(&sender.credentials(), "task-reply-retry")
                    .await
            }
        });
        tokio::task::yield_now().await;
        block_projection(&store);

        assert_eq!(
            broker
                .reply(
                    &recipient.credentials(),
                    "task-reply-retry",
                    reply_payload("reply A"),
                )
                .await
                .unwrap_err(),
            herdr_a2a_core::DomainError::PersistenceUnavailable
        );
        let state_after_failure = store
            .test_text("SELECT state FROM delivery_tasks WHERE task_id='task-reply-retry'")
            .unwrap();
        unblock_projection(&store);

        assert_eq!(
            broker
                .reply(
                    &recipient.credentials(),
                    "task-reply-retry",
                    reply_payload("reply B"),
                )
                .await
                .unwrap_err(),
            herdr_a2a_core::DomainError::ReplyAlreadySubmitted
        );
        broker
            .reply(
                &recipient.credentials(),
                "task-reply-retry",
                reply_payload("reply A"),
            )
            .await
            .unwrap();
        assert_eq!(waiter.await.unwrap().unwrap().text, "reply A");
        let live =
            assert_live_ledger_and_projection_match(&broker, &store, &sender, "task-reply-retry")
                .await;
        let projected = store.get("task-reply-retry").await.unwrap().unwrap();

        assert_eq!(state_after_failure, "replied");
        assert_eq!(live.reply.as_ref().unwrap().text, "reply A");
        assert_eq!(
            projected.status.message.as_ref().unwrap().text(),
            Some("reply A")
        );
    }

    #[tokio::test]
    async fn equal_version_idempotency_requires_canonical_complete_durable_row_equality() {
        // Break caught: an equal state_version suppresses a conflicting row without checking the
        // identity, payload, timing, lease, ACK, or terminal columns.
        let store = SqliteTaskStore::open(":memory:").unwrap();
        store.prepare_startup(NOW).await.unwrap();

        let queued = durable("equal-queued", 2, DurableTaskState::Queued);
        let mut queued_conflicts = Vec::new();
        let mut changed = queued.clone();
        changed.context_id = "context-other".to_owned();
        queued_conflicts.push(changed);
        let mut changed = queued.clone();
        changed.sender = name("alternate");
        queued_conflicts.push(changed);
        let mut changed = queued.clone();
        changed.recipient = name("auditor");
        queued_conflicts.push(changed);
        let mut changed = queued.clone();
        changed.payload.text = "different request".to_owned();
        changed.payload.metadata = json!({"different": true});
        queued_conflicts.push(changed);
        let mut changed = queued.clone();
        changed.created_unix_ms += 1;
        changed.delivery_deadline_unix_ms += 1;
        queued_conflicts.push(changed);
        let mut changed = queued.clone();
        changed.attempt = 7;
        queued_conflicts.push(changed);
        let mut changed = durable("equal-queued", 2, DurableTaskState::Leased);
        changed.context_id = queued.context_id.clone();
        queued_conflicts.push(changed);

        let leased = durable("equal-leased", 3, DurableTaskState::Leased);
        let mut leased_conflicts = Vec::new();
        let mut changed = leased.clone();
        changed.lease.as_mut().unwrap().delivery_id = DeliveryId::new();
        leased_conflicts.push(changed);
        let mut changed = leased.clone();
        changed.lease.as_mut().unwrap().leased_until_unix_ms += 1;
        leased_conflicts.push(changed);
        let mut changed = leased.clone();
        changed.attempt += 1;
        changed.lease.as_mut().unwrap().attempt = changed.attempt;
        leased_conflicts.push(changed);

        let acknowledged = durable("equal-ack", 4, DurableTaskState::Acknowledged);
        let mut changed_acknowledged = acknowledged.clone();
        changed_acknowledged.acknowledged_unix_ms = Some(NOW + 2);

        let replied = durable("equal-replied", 5, DurableTaskState::Replied);
        let mut replied_conflicts = Vec::new();
        let mut changed = replied.clone();
        changed.reply.as_mut().unwrap().text = "different reply".to_owned();
        replied_conflicts.push(changed);
        let mut changed = replied.clone();
        changed.terminal_unix_ms = Some(NOW + 3);
        changed.retention_deadline_unix_ms = Some(NOW + 3 + TERMINAL_RETENTION_MS);
        replied_conflicts.push(changed);

        for (canonical, conflicts) in [
            (queued, queued_conflicts),
            (leased, leased_conflicts),
            (acknowledged, vec![changed_acknowledged]),
            (replied, replied_conflicts),
        ] {
            assert_eq!(
                BrokerPersistence::commit(&store, batch(canonical.clone()))
                    .await
                    .unwrap(),
                PersistenceCommitOutcome::Complete
            );
            assert_eq!(
                BrokerPersistence::commit(&store, batch(canonical.clone()))
                    .await
                    .unwrap(),
                PersistenceCommitOutcome::Complete
            );
            for conflict in conflicts {
                assert_eq!(
                    BrokerPersistence::commit(&store, batch(conflict))
                        .await
                        .unwrap(),
                    PersistenceCommitOutcome::ReconciliationRequired
                );
            }
            let stored = BrokerPersistence::load(&store, NOW)
                .await
                .unwrap()
                .tasks
                .into_iter()
                .find(|task| task.task_id == canonical.task_id)
                .unwrap();
            assert_eq!(stored, canonical);
        }
    }

    #[tokio::test]
    async fn commit_writes_task_and_coalesced_outbox_in_one_immediate_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("atomic.sqlite3");
        let store = SqliteTaskStore::open(&path).unwrap();
        store.prepare_startup(NOW).await.unwrap();
        store.test_execute("CREATE TRIGGER block_projection BEFORE INSERT ON tasks BEGIN SELECT RAISE(ABORT, 'projection blocked'); END", []).unwrap();
        let durable = durable("atomic", 1, DurableTaskState::Queued);
        assert_eq!(
            BrokerPersistence::commit(&store, batch(durable.clone()))
                .await
                .unwrap(),
            PersistenceCommitOutcome::ReconciliationRequired
        );
        assert_eq!(scalar_i64(&path, "SELECT COUNT(*) FROM delivery_tasks"), 1);
        assert_eq!(
            scalar_i64(&path, "SELECT COUNT(*) FROM projection_outbox"),
            1
        );
        store
            .test_execute("DROP TRIGGER block_projection", [])
            .unwrap();
        drop(store);
        let reopened = SqliteTaskStore::open(&path).unwrap();
        assert_eq!(
            reopened
                .prepare_startup(NOW + 1)
                .await
                .unwrap()
                .repaired_projections,
            1
        );
        let repaired = reopened.get("atomic").await.unwrap().unwrap();
        let expected: a2a::Task =
            serde_json::from_str(&projection_json(&durable).unwrap()).unwrap();
        assert_eq!(repaired, expected);
        assert_eq!(
            scalar_i64(&path, "SELECT COUNT(*) FROM projection_outbox"),
            0
        );
    }

    #[tokio::test]
    async fn startup_fails_closed_when_clean_outbox_projection_is_missing() {
        // Break caught: startup publishes a broker whose authoritative task has no A2A
        // projection after the already-applied outbox row was removed.
        let store = SqliteTaskStore::open(":memory:").unwrap();
        store.prepare_startup(NOW).await.unwrap();
        BrokerPersistence::commit(
            &store,
            batch(durable(
                "missing-startup-projection",
                1,
                DurableTaskState::Queued,
            )),
        )
        .await
        .unwrap();
        assert_eq!(
            store
                .test_i64("SELECT COUNT(*) FROM projection_outbox")
                .unwrap(),
            0
        );
        store
            .test_execute(
                "DELETE FROM tasks WHERE task_id = 'missing-startup-projection'",
                [],
            )
            .unwrap();

        let error = store.prepare_startup(NOW + 1).await.unwrap_err();

        assert!(
            error
                .to_string()
                .contains("task projection differs from the retained ledger"),
            "unexpected startup error: {error}"
        );
    }

    #[tokio::test]
    async fn startup_fails_closed_when_clean_outbox_projection_is_mismatched() {
        // Break caught: startup accepts a byte-valid same-version A2A projection for a different
        // state after the outbox was applied and removed.
        let store = SqliteTaskStore::open(":memory:").unwrap();
        store.prepare_startup(NOW).await.unwrap();
        let current = durable("mismatched-startup-projection", 2, DurableTaskState::Leased);
        BrokerPersistence::commit(&store, batch(current))
            .await
            .unwrap();
        assert_eq!(
            store
                .test_i64("SELECT COUNT(*) FROM projection_outbox")
                .unwrap(),
            0
        );
        let mismatched: Task = serde_json::from_str(
            &projection_json(&durable(
                "mismatched-startup-projection",
                2,
                DurableTaskState::Queued,
            ))
            .unwrap(),
        )
        .unwrap();
        let mismatched = TaskColumns::from_task(&mismatched).unwrap();
        store
            .test_execute(
                "UPDATE tasks
                 SET context_id = ?1, state = ?2, status_timestamp = ?3,
                     version = 2, task_json = ?4
                 WHERE task_id = ?5",
                params![
                    mismatched.context_id,
                    mismatched.state,
                    mismatched.status_timestamp,
                    mismatched.task_json,
                    mismatched.task_id,
                ],
            )
            .unwrap();

        let error = store.prepare_startup(NOW + 1).await.unwrap_err();

        assert!(
            error
                .to_string()
                .contains("task projection differs from the retained ledger"),
            "unexpected startup error: {error}"
        );
    }

    #[tokio::test]
    async fn newer_state_version_replaces_pending_projection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("newer.sqlite3");
        let store = SqliteTaskStore::open(&path).unwrap();
        store.prepare_startup(NOW).await.unwrap();
        store.test_execute("CREATE TRIGGER block_projection BEFORE INSERT ON tasks BEGIN SELECT RAISE(ABORT, 'projection blocked'); END", []).unwrap();
        assert_eq!(
            BrokerPersistence::commit(
                &store,
                batch(durable("versioned", 1, DurableTaskState::Queued))
            )
            .await
            .unwrap(),
            PersistenceCommitOutcome::ReconciliationRequired
        );
        assert_eq!(
            BrokerPersistence::commit(
                &store,
                batch(durable("versioned", 2, DurableTaskState::Leased))
            )
            .await
            .unwrap(),
            PersistenceCommitOutcome::ReconciliationRequired
        );
        assert_eq!(
            scalar_i64(
                &path,
                "SELECT state_version FROM projection_outbox WHERE task_id='versioned'"
            ),
            2
        );
        assert_eq!(
            scalar_i64(&path, "SELECT COUNT(*) FROM projection_outbox"),
            1
        );
    }

    #[tokio::test]
    async fn only_exact_equal_state_version_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("older.sqlite3");
        let store = SqliteTaskStore::open(&path).unwrap();
        store.prepare_startup(NOW).await.unwrap();
        assert_eq!(
            BrokerPersistence::commit(
                &store,
                batch(durable("versioned", 2, DurableTaskState::Leased)),
            )
            .await
            .unwrap(),
            PersistenceCommitOutcome::Complete
        );
        assert_eq!(
            BrokerPersistence::commit(
                &store,
                batch(durable("versioned", 2, DurableTaskState::Queued)),
            )
            .await
            .unwrap(),
            PersistenceCommitOutcome::ReconciliationRequired
        );
        assert_eq!(
            BrokerPersistence::commit(
                &store,
                batch(durable("versioned", 1, DurableTaskState::Queued)),
            )
            .await
            .unwrap(),
            PersistenceCommitOutcome::ReconciliationRequired
        );
        assert_eq!(
            store
                .test_text("SELECT state FROM delivery_tasks WHERE task_id='versioned'")
                .unwrap(),
            "leased"
        );
        assert_eq!(
            store
                .test_i64("SELECT state_version FROM delivery_tasks WHERE task_id='versioned'")
                .unwrap(),
            2
        );
        assert_eq!(
            store.get("versioned").await.unwrap().unwrap().status.state,
            a2a::TaskState::Working
        );
    }

    #[tokio::test]
    async fn failed_transaction_writes_neither_ledger_nor_outbox() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rollback.sqlite3");
        let store = SqliteTaskStore::open(&path).unwrap();
        store.prepare_startup(NOW).await.unwrap();
        store.test_execute("CREATE TRIGGER reject_outbox BEFORE INSERT ON projection_outbox BEGIN SELECT RAISE(ABORT, 'injected'); END", []).unwrap();
        assert!(
            BrokerPersistence::commit(
                &store,
                batch(durable("rollback", 1, DurableTaskState::Queued))
            )
            .await
            .is_err()
        );
        assert_eq!(scalar_i64(&path, "SELECT COUNT(*) FROM delivery_tasks"), 0);
        assert_eq!(
            scalar_i64(&path, "SELECT COUNT(*) FROM projection_outbox"),
            0
        );
    }

    #[tokio::test]
    async fn sdk_projection_write_requires_matching_outbox_version_and_json() {
        // Break caught: an SDK create/update can write a projection that was never authorized by
        // the durable ledger's current outbox entry.
        let store = SqliteTaskStore::open(":memory:").unwrap();
        store.prepare_startup(NOW).await.unwrap();
        store.test_execute(
            "CREATE TRIGGER block_projection BEFORE INSERT ON tasks BEGIN SELECT RAISE(ABORT, 'projection blocked'); END",
            [],
        ).unwrap();
        let queued = durable("sdk-guard", 1, DurableTaskState::Queued);
        assert_eq!(
            BrokerPersistence::commit(&store, batch(queued.clone()))
                .await
                .unwrap(),
            PersistenceCommitOutcome::ReconciliationRequired
        );
        store
            .test_execute("DROP TRIGGER block_projection", [])
            .unwrap();
        let expected: a2a::Task = serde_json::from_str(&projection_json(&queued).unwrap()).unwrap();
        let mut mismatched = expected.clone();
        mismatched.context_id = "unauthorized-context".to_owned();

        let error = store.create(mismatched).await.unwrap_err();

        assert_eq!(error.message, "task projection is not authorized");
        assert_eq!(
            store
                .test_i64("SELECT state_version FROM delivery_tasks WHERE task_id='sdk-guard'")
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .test_i64("SELECT COUNT(*) FROM tasks WHERE task_id='sdk-guard'")
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .test_i64("SELECT COUNT(*) FROM projection_outbox WHERE task_id='sdk-guard'")
                .unwrap(),
            1
        );
        assert_eq!(store.create(expected.clone()).await.unwrap(), 1);
        assert_eq!(store.get("sdk-guard").await.unwrap(), Some(expected));
        assert_eq!(
            store
                .test_i64("SELECT COUNT(*) FROM projection_outbox WHERE task_id='sdk-guard'")
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn stale_sdk_projection_cannot_overwrite_newer_terminal_state() {
        // Break caught: an executor's stale working update overwrites a terminal projection after
        // the recipient reply has already advanced the durable ledger.
        let store = SqliteTaskStore::open(":memory:").unwrap();
        store.prepare_startup(NOW).await.unwrap();
        let terminal = durable("sdk-stale", 2, DurableTaskState::Replied);
        BrokerPersistence::commit(&store, batch(terminal.clone()))
            .await
            .unwrap();
        let retained = store.get("sdk-stale").await.unwrap().unwrap();
        let stale: a2a::Task = serde_json::from_str(
            &projection_json(&durable("sdk-stale", 1, DurableTaskState::Queued)).unwrap(),
        )
        .unwrap();

        let error = store.update(stale).await.unwrap_err();

        assert_eq!(error.message, "task projection is not authorized");
        assert_eq!(
            store
                .test_text("SELECT state FROM delivery_tasks WHERE task_id='sdk-stale'")
                .unwrap(),
            "replied"
        );
        assert_eq!(store.get("sdk-stale").await.unwrap(), Some(retained));
    }

    #[tokio::test]
    async fn quarantined_id_upsert_is_rejected_without_ledger_outbox_or_projection_mutation() {
        // Break caught: a version-equal upsert against an identifier-only quarantine can enqueue
        // and expose a projection even though the authoritative row has no stable principal.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("quarantine-collision.sqlite3");
        let store = SqliteTaskStore::open(&path).unwrap();
        store
            .claim_task_owner(
                "quarantine-collision",
                &RegistrationId::new(),
                &name("reviewer"),
                NOW,
            )
            .await
            .unwrap();
        store.prepare_startup(NOW).await.unwrap();

        let error = BrokerPersistence::commit(
            &store,
            batch(durable("quarantine-collision", 1, DurableTaskState::Queued)),
        )
        .await
        .unwrap_err();

        assert_eq!(error, herdr_a2a_core::DomainError::PersistenceUnavailable);
        assert_eq!(
            store
                .test_i64(
                    "SELECT legacy_quarantined FROM delivery_tasks
                     WHERE task_id='quarantine-collision'"
                )
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .test_i64("SELECT COUNT(*) FROM projection_outbox")
                .unwrap(),
            0
        );
        assert_eq!(store.test_i64("SELECT COUNT(*) FROM tasks").unwrap(), 0);
    }

    #[tokio::test]
    async fn leased_projection_uses_checked_lease_transition_timestamp() {
        // Break caught: using creation time hides later delivery attempts and accepting a lease
        // whose derived start predates creation admits an impossible durable snapshot.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lease-transition.sqlite3");
        let store = SqliteTaskStore::open(&path).unwrap();
        store.prepare_startup(NOW).await.unwrap();
        let mut leased = durable("leased-transition", 1, DurableTaskState::Leased);
        leased.created_unix_ms = NOW - 1_000;
        leased.delivery_deadline_unix_ms = leased.created_unix_ms + DELIVERY_TTL_MS;
        leased.lease.as_mut().unwrap().leased_until_unix_ms = NOW + 60_000;
        BrokerPersistence::commit(&store, batch(leased.clone()))
            .await
            .unwrap();
        assert_eq!(
            store
                .get("leased-transition")
                .await
                .unwrap()
                .unwrap()
                .status
                .timestamp
                .unwrap()
                .timestamp_millis(),
            NOW
        );

        let mut impossible = durable("impossible-lease", 1, DurableTaskState::Leased);
        impossible.lease.as_mut().unwrap().leased_until_unix_ms = NOW + 59_999;
        assert!(
            BrokerPersistence::commit(&store, batch(impossible))
                .await
                .is_err()
        );
        assert_eq!(
            store
                .test_i64("SELECT COUNT(*) FROM delivery_tasks WHERE task_id='impossible-lease'")
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn acknowledged_timestamp_must_be_inside_the_lease_interval() {
        // Break caught: an ACK before lease acquisition or after lease expiry cannot prove the
        // active delivery attempt and must not become recoverable state.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ack-interval.sqlite3");
        let store = SqliteTaskStore::open(&path).unwrap();
        store.prepare_startup(NOW).await.unwrap();
        for (task_id, acknowledged_unix_ms) in [
            ("ack-before-lease", NOW - 1),
            ("ack-at-expiry", NOW + 60_000),
        ] {
            let mut acknowledged = durable(task_id, 1, DurableTaskState::Acknowledged);
            acknowledged.lease.as_mut().unwrap().leased_until_unix_ms = NOW + 60_000;
            acknowledged.acknowledged_unix_ms = Some(acknowledged_unix_ms);
            assert!(
                BrokerPersistence::commit(&store, batch(acknowledged))
                    .await
                    .is_err()
            );
        }
        assert_eq!(
            store
                .test_i64("SELECT COUNT(*) FROM delivery_tasks")
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .test_i64("SELECT COUNT(*) FROM projection_outbox")
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn equal_version_corrupted_projection_is_repaired_before_outbox_delete() {
        // Break caught: `excluded.version > tasks.version` skips an equal-version repair and the
        // old code nevertheless deletes the only durable repair instruction.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("equal-version-repair.sqlite3");
        let store = SqliteTaskStore::open(&path).unwrap();
        store.prepare_startup(NOW).await.unwrap();
        BrokerPersistence::commit(
            &store,
            batch(durable("equal-repair", 1, DurableTaskState::Queued)),
        )
        .await
        .unwrap();
        let intended = store
            .test_text("SELECT task_json FROM tasks WHERE task_id='equal-repair'")
            .unwrap();
        store
            .test_execute(
                "UPDATE tasks SET state='TASK_STATE_FAILED', task_json='{}'
                 WHERE task_id='equal-repair'",
                [],
            )
            .unwrap();
        store
            .test_execute(
                "INSERT INTO projection_outbox (task_id, state_version, task_json)
                 VALUES ('equal-repair', 1, ?1)",
                [&intended],
            )
            .unwrap();

        assert_eq!(store.apply_pending_projections().await.unwrap(), 1);
        assert_eq!(
            store
                .test_text("SELECT task_json FROM tasks WHERE task_id='equal-repair'")
                .unwrap(),
            intended
        );
        assert_eq!(
            store
                .test_i64("SELECT COUNT(*) FROM projection_outbox")
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn orphan_or_mismatched_outbox_fails_closed_without_projection_mutation() {
        // Break caught: count-only validation accepts one orphan outbox row alongside one retained
        // task, and application can expose it as an SDK task with no durable authority.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invalid-outbox.sqlite3");
        let store = SqliteTaskStore::open(&path).unwrap();
        store.prepare_startup(NOW).await.unwrap();
        BrokerPersistence::commit(
            &store,
            batch(durable("retained", 1, DurableTaskState::Queued)),
        )
        .await
        .unwrap();
        let retained_json = store
            .test_text("SELECT task_json FROM tasks WHERE task_id='retained'")
            .unwrap();
        let orphan_json = retained_json.replace("retained", "orphan");
        store
            .test_execute(
                "INSERT INTO projection_outbox (task_id, state_version, task_json)
                 VALUES ('orphan', 1, ?1)",
                [&orphan_json],
            )
            .unwrap();
        assert!(store.prepare_startup(NOW).await.is_err());
        assert_eq!(store.test_i64("SELECT COUNT(*) FROM tasks").unwrap(), 1);
        assert_eq!(
            store
                .test_i64("SELECT COUNT(*) FROM projection_outbox")
                .unwrap(),
            1
        );

        store
            .test_execute("DELETE FROM projection_outbox", [])
            .unwrap();
        let mismatched = retained_json.replace("TASK_STATE_SUBMITTED", "TASK_STATE_FAILED");
        store
            .test_execute(
                "INSERT INTO projection_outbox (task_id, state_version, task_json)
                 VALUES ('retained', 1, ?1)",
                [&mismatched],
            )
            .unwrap();
        assert!(store.prepare_startup(NOW).await.is_err());
        assert_eq!(
            store
                .test_text("SELECT task_json FROM tasks WHERE task_id='retained'")
                .unwrap(),
            retained_json
        );
        assert_eq!(
            store
                .test_i64("SELECT COUNT(*) FROM projection_outbox")
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn commit_rejects_payload_bounds_and_file_refs_without_mutation() {
        // Break caught: projection construction currently drops file references and accepts text
        // that the shared bounded-payload contract rejects.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("commit-payload-policy.sqlite3");
        let store = SqliteTaskStore::open(&path).unwrap();
        store.prepare_startup(NOW).await.unwrap();

        let mut oversized_request = durable("oversized-request", 1, DurableTaskState::Queued);
        oversized_request.payload.text = "x".repeat(herdr_a2a_core::validation::MAX_TEXT_BYTES + 1);
        assert!(
            BrokerPersistence::commit(&store, batch(oversized_request))
                .await
                .is_err()
        );
        let mut file_request = durable("file-request", 1, DurableTaskState::Queued);
        file_request.payload.file_refs.push(FileReference {
            path: PathBuf::from("artifact.txt"),
            media_type: Some("text/plain".to_owned()),
            label: Some("artifact".to_owned()),
        });
        assert!(
            BrokerPersistence::commit(&store, batch(file_request))
                .await
                .is_err()
        );
        let mut oversized_reply = durable("oversized-reply", 1, DurableTaskState::Replied);
        oversized_reply.reply.as_mut().unwrap().text =
            "x".repeat(herdr_a2a_core::validation::MAX_TEXT_BYTES + 1);
        assert!(
            BrokerPersistence::commit(&store, batch(oversized_reply))
                .await
                .is_err()
        );

        assert_eq!(
            store
                .test_i64("SELECT COUNT(*) FROM delivery_tasks")
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .test_i64("SELECT COUNT(*) FROM projection_outbox")
                .unwrap(),
            0
        );
        assert_eq!(store.test_i64("SELECT COUNT(*) FROM tasks").unwrap(), 0);
    }

    #[tokio::test]
    async fn load_rejects_out_of_policy_request_reply_and_file_refs() {
        // Break caught: canonical serde JSON can still decode payloads that exceed domain bounds
        // or contain file references M2A cannot project without loss.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("load-payload-policy.sqlite3");
        let store = SqliteTaskStore::open(&path).unwrap();
        store.prepare_startup(NOW).await.unwrap();

        for (task_id, mutate_request) in [("load-oversized", true), ("load-file-ref", false)] {
            let task = durable(task_id, 1, DurableTaskState::Queued);
            BrokerPersistence::commit(&store, batch(task.clone()))
                .await
                .unwrap();
            let mut payload = task.payload;
            if mutate_request {
                payload.text = "x".repeat(herdr_a2a_core::validation::MAX_TEXT_BYTES + 1);
            } else {
                payload.file_refs.push(FileReference {
                    path: PathBuf::from("artifact.txt"),
                    media_type: None,
                    label: None,
                });
            }
            let request_json = super::canonical_json(&payload, "test request").unwrap();
            store
                .test_execute(
                    "UPDATE delivery_tasks SET request_json=?1 WHERE task_id=?2",
                    params![request_json, task_id],
                )
                .unwrap();
            assert!(BrokerPersistence::load(&store, NOW).await.is_err());
            store
                .test_execute("DELETE FROM delivery_tasks WHERE task_id=?1", [task_id])
                .unwrap();
            store
                .test_execute("DELETE FROM tasks WHERE task_id=?1", [task_id])
                .unwrap();
        }

        let task = durable("load-reply", 1, DurableTaskState::Replied);
        BrokerPersistence::commit(&store, batch(task.clone()))
            .await
            .unwrap();
        let mut reply = task.reply.unwrap();
        reply.text = "x".repeat(herdr_a2a_core::validation::MAX_TEXT_BYTES + 1);
        let reply_json = super::canonical_json(&reply, "test reply").unwrap();
        store
            .test_execute(
                "UPDATE delivery_tasks SET reply_json=?1 WHERE task_id='load-reply'",
                [reply_json],
            )
            .unwrap();
        assert!(BrokerPersistence::load(&store, NOW).await.is_err());
    }

    #[tokio::test]
    async fn post_v1_owner_only_reservation_is_quarantined_at_first_start_anchor() {
        // Break caught: the version-1 fast path skips claim-before-create reservations made after
        // migration, leaving them outside durable capacity and retention forever after a crash.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("post-v1-owner.sqlite3");
        let store = SqliteTaskStore::open(&path).unwrap();
        store.prepare_startup(NOW).await.unwrap();
        store
            .claim_task_owner(
                "post-v1-owner",
                &RegistrationId::new(),
                &name("reviewer"),
                NOW + 1_000,
            )
            .await
            .unwrap();

        let report = store.prepare_startup(NOW + 2_000).await.unwrap();
        assert_eq!(report.quarantined_legacy_tasks, 1);
        assert_eq!(
            store
                .test_i64(
                    "SELECT retain_until_unix_ms FROM delivery_tasks
                     WHERE task_id='post-v1-owner'"
                )
                .unwrap(),
            NOW + TERMINAL_RETENTION_MS
        );
        assert!(
            store
                .task_principal("post-v1-owner")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            BrokerPersistence::load(&store, NOW)
                .await
                .unwrap()
                .tasks
                .is_empty()
        );

        let repeated = store.prepare_startup(NOW + 3_000).await.unwrap();
        assert_eq!(repeated.quarantined_legacy_tasks, 0);
        assert_eq!(repeated.pruned_quarantined_tasks, 0);
        assert_eq!(
            store
                .test_i64("SELECT COUNT(*) FROM delivery_tasks")
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .prepare_startup(NOW + TERMINAL_RETENTION_MS - 1)
                .await
                .unwrap()
                .pruned_quarantined_tasks,
            0
        );
        assert_eq!(
            store
                .prepare_startup(NOW + TERMINAL_RETENTION_MS)
                .await
                .unwrap()
                .pruned_quarantined_tasks,
            1
        );
        assert!(store.task_owner("post-v1-owner").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn post_v1_owner_claim_counts_delivery_ledger_capacity() {
        // Break caught: counting only task_owners after migration admits a new crash-window
        // reservation even when the authoritative 4,096-row delivery ledger is already full.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("post-v1-capacity.sqlite3");
        let store = SqliteTaskStore::open(&path).unwrap();
        store.prepare_startup(NOW).await.unwrap();
        store
            .test_prefill_delivery_tasks(MAX_RETAINED_TASKS)
            .unwrap();

        let error = store
            .claim_task_owner(
                "over-cap-owner",
                &RegistrationId::new(),
                &name("reviewer"),
                NOW,
            )
            .await
            .unwrap_err();
        assert_eq!(error.message, "retained task capacity is exhausted");
        assert!(store.task_owner("over-cap-owner").await.unwrap().is_none());
        assert_eq!(
            store
                .test_i64("SELECT COUNT(*) FROM delivery_tasks")
                .unwrap(),
            MAX_RETAINED_TASKS as i64
        );
    }

    #[tokio::test]
    async fn commit_capacity_counts_owner_only_reservations_in_retained_union() {
        // Break caught: commit admission counting only delivery_tasks can admit a 4,097th
        // retained ID while a distinct claim-before-create reservation is waiting for quarantine.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("commit-owner-capacity.sqlite3");
        let observer = SqliteTaskStore::open(&path).unwrap();
        observer.prepare_startup(NOW).await.unwrap();
        observer
            .test_prefill_delivery_tasks(MAX_RETAINED_TASKS - 1)
            .unwrap();
        let claimant = SqliteTaskStore::open(&path).unwrap();
        claimant
            .claim_task_owner(
                "owner-only-slot",
                &RegistrationId::new(),
                &name("reviewer"),
                NOW,
            )
            .await
            .unwrap();
        let committer = SqliteTaskStore::open(&path).unwrap();

        let error = BrokerPersistence::commit(
            &committer,
            batch(durable("over-cap-commit", 1, DurableTaskState::Queued)),
        )
        .await
        .unwrap_err();

        assert_eq!(error, herdr_a2a_core::DomainError::PersistenceUnavailable);
        assert_eq!(
            observer
                .test_i64(
                    "SELECT COUNT(*) FROM (
                         SELECT task_id FROM delivery_tasks
                         UNION
                         SELECT task_id FROM task_owners
                     )"
                )
                .unwrap(),
            MAX_RETAINED_TASKS as i64
        );
        assert_eq!(
            observer
                .test_i64("SELECT COUNT(*) FROM delivery_tasks WHERE task_id='over-cap-commit'")
                .unwrap(),
            0
        );
        assert_eq!(
            observer
                .test_i64("SELECT COUNT(*) FROM projection_outbox WHERE task_id='over-cap-commit'")
                .unwrap(),
            0
        );
        assert_eq!(
            observer
                .test_i64("SELECT COUNT(*) FROM tasks WHERE task_id='over-cap-commit'")
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn commit_capacity_does_not_double_count_owner_matching_ledger_task() {
        // Break caught: counting every task_owners row in addition to delivery_tasks rejects the
        // valid final slot when an SDK owner row names an already retained ledger task.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("commit-owner-dedup.sqlite3");
        let store = SqliteTaskStore::open(&path).unwrap();
        store.prepare_startup(NOW).await.unwrap();
        store
            .test_prefill_delivery_tasks(MAX_RETAINED_TASKS - 1)
            .unwrap();
        store
            .test_execute(
                "INSERT INTO task_owners (task_id, registration_id, recipient)
                 VALUES ('prefilled-0', ?1, 'reviewer')",
                [RegistrationId::new().as_str()],
            )
            .unwrap();

        BrokerPersistence::commit(
            &store,
            batch(durable("final-ledger-slot", 1, DurableTaskState::Queued)),
        )
        .await
        .unwrap();

        assert_eq!(
            store
                .test_i64(
                    "SELECT COUNT(*) FROM (
                         SELECT task_id FROM delivery_tasks
                         UNION
                         SELECT task_id FROM task_owners
                     )"
                )
                .unwrap(),
            MAX_RETAINED_TASKS as i64
        );
    }

    #[tokio::test]
    async fn load_rejects_invalid_state_specific_columns() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invalid.sqlite3");
        let store = SqliteTaskStore::open(&path).unwrap();
        store.prepare_startup(NOW).await.unwrap();
        BrokerPersistence::commit(
            &store,
            batch(durable("invalid", 1, DurableTaskState::Queued)),
        )
        .await
        .unwrap();
        store
            .test_execute(
                "UPDATE delivery_tasks SET acknowledged_unix_ms=?1 WHERE task_id='invalid'",
                [NOW],
            )
            .unwrap();
        assert!(BrokerPersistence::load(&store, NOW).await.is_err());
    }

    #[tokio::test]
    async fn load_rejects_noncanonical_deadline_and_json_encodings() {
        // Break caught: accepting a reset deadline or noncanonical JSON makes recovery depend on
        // a representation that differs from the domain transition the broker committed.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("noncanonical.sqlite3");
        let store = SqliteTaskStore::open(&path).unwrap();
        store.prepare_startup(NOW).await.unwrap();
        BrokerPersistence::commit(
            &store,
            batch(durable("noncanonical", 1, DurableTaskState::Queued)),
        )
        .await
        .unwrap();
        store
            .test_execute(
                "UPDATE delivery_tasks SET deadline_unix_ms = deadline_unix_ms + 1
                 WHERE task_id='noncanonical'",
                [],
            )
            .unwrap();
        assert!(BrokerPersistence::load(&store, NOW).await.is_err());

        store
            .test_execute(
                "UPDATE delivery_tasks SET deadline_unix_ms=?1, request_json=?2
                 WHERE task_id='noncanonical'",
                params![
                    NOW + DELIVERY_TTL_MS,
                    r#"{"text":"exact request","metadata":{"a":1,"b":2},"file_refs":[]}"#,
                ],
            )
            .unwrap();
        assert!(BrokerPersistence::load(&store, NOW).await.is_err());
    }

    #[tokio::test]
    async fn outbox_never_exceeds_retained_task_count() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bounded.sqlite3");
        let store = SqliteTaskStore::open(&path).unwrap();
        store.prepare_startup(NOW).await.unwrap();
        store.test_execute("CREATE TRIGGER block_projection BEFORE INSERT ON tasks BEGIN SELECT RAISE(ABORT, 'projection blocked'); END", []).unwrap();
        for version in 1..=8 {
            assert_eq!(
                BrokerPersistence::commit(
                    &store,
                    batch(durable("bounded", version, DurableTaskState::Queued))
                )
                .await
                .unwrap(),
                PersistenceCommitOutcome::ReconciliationRequired
            );
        }
        assert_eq!(
            scalar_i64(&path, "SELECT COUNT(*) FROM projection_outbox"),
            1
        );
        assert_eq!(scalar_i64(&path, "SELECT COUNT(*) FROM delivery_tasks"), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_capacity_admission_never_exceeds_4096_rows() {
        const RACES: usize = 12;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capacity.sqlite3");
        let observer = SqliteTaskStore::open(&path).unwrap();
        observer.prepare_startup(NOW).await.unwrap();
        observer
            .test_prefill_delivery_tasks(MAX_RETAINED_TASKS - 4)
            .unwrap();
        let barrier = Arc::new(Barrier::new(RACES));
        let jobs = (0..RACES).map(|index| {
            let store = SqliteTaskStore::open(&path).unwrap();
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                barrier.wait().await;
                BrokerPersistence::commit(
                    &store,
                    batch(durable(
                        &format!("race-{index}"),
                        1,
                        DurableTaskState::Queued,
                    )),
                )
                .await
            })
        });
        let results = futures::future::join_all(jobs).await;
        assert_eq!(
            results
                .iter()
                .filter(|result| result.as_ref().unwrap().is_ok())
                .count(),
            4
        );
        assert_eq!(
            scalar_i64(&path, "SELECT COUNT(*) FROM delivery_tasks"),
            MAX_RETAINED_TASKS as i64
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_registration_epoch_updates_remain_monotonic() {
        const RACES: usize = 24;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("epoch.sqlite3");
        SqliteTaskStore::open(&path)
            .unwrap()
            .prepare_startup(NOW)
            .await
            .unwrap();
        let barrier = Arc::new(Barrier::new(RACES));
        let jobs = (0..RACES).map(|index| {
            let store = SqliteTaskStore::open(&path).unwrap();
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                barrier.wait().await;
                BrokerPersistence::commit(
                    &store,
                    PersistenceBatch {
                        registration_epoch_high_watermark: Some(RegistrationEpoch::from_u64(
                            (index + 1) as u64,
                        )),
                        upsert_tasks: Vec::new(),
                        delete_task_ids: Vec::new(),
                    },
                )
                .await
            })
        });
        for result in futures::future::join_all(jobs).await {
            result.unwrap().unwrap();
        }
        let snapshot = BrokerPersistence::load(&SqliteTaskStore::open(&path).unwrap(), NOW)
            .await
            .unwrap();
        assert_eq!(snapshot.last_registration_epoch.get(), RACES as u64);
        let canonical = Connection::open(&path)
            .unwrap()
            .query_row(
                "SELECT last_registration_epoch FROM broker_meta WHERE singleton=1",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        assert_eq!(canonical, RACES.to_string());
    }

    #[tokio::test]
    async fn full_u64_registration_epoch_round_trips_as_canonical_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("u64.sqlite3");
        let store = SqliteTaskStore::open(&path).unwrap();
        store.prepare_startup(NOW).await.unwrap();
        BrokerPersistence::commit(
            &store,
            PersistenceBatch {
                registration_epoch_high_watermark: Some(RegistrationEpoch::from_u64(u64::MAX)),
                upsert_tasks: Vec::new(),
                delete_task_ids: Vec::new(),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            BrokerPersistence::load(&store, NOW)
                .await
                .unwrap()
                .last_registration_epoch
                .get(),
            u64::MAX
        );
        assert_eq!(
            store
                .test_text("SELECT last_registration_epoch FROM broker_meta")
                .unwrap(),
            u64::MAX.to_string()
        );
    }

    #[tokio::test]
    async fn projection_is_deterministic_and_preserves_request_reply_and_transition_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("projection.sqlite3");
        let store = SqliteTaskStore::open(&path).unwrap();
        store.prepare_startup(NOW).await.unwrap();
        let task = durable("projected", 7, DurableTaskState::Replied);
        BrokerPersistence::commit(&store, batch(task.clone()))
            .await
            .unwrap();
        let projected = store.get("projected").await.unwrap().unwrap();
        assert_eq!(
            store.task_principal("projected").await.unwrap().unwrap(),
            crate::TaskPrincipal {
                sender: name("implementer"),
                recipient: name("reviewer"),
            }
        );
        assert_eq!(projected.context_id, task.context_id);
        assert_eq!(projected.status.state, a2a::TaskState::Completed);
        assert_eq!(
            projected.history.as_ref().unwrap()[0].text(),
            Some("exact request")
        );
        assert_eq!(
            projected.status.message.as_ref().unwrap().text(),
            Some("exact reply")
        );
        assert_eq!(
            projected.status.timestamp.unwrap().timestamp_millis(),
            NOW + 2
        );
        let original = store
            .test_text("SELECT task_json FROM tasks WHERE task_id='projected'")
            .unwrap();
        store.test_execute("INSERT INTO projection_outbox SELECT task_id, state_version, task_json FROM projection_outbox WHERE 0", []).unwrap();
        assert_eq!(store.apply_pending_projections().await.unwrap(), 0);
        assert_eq!(
            store
                .test_text("SELECT task_json FROM tasks WHERE task_id='projected'")
                .unwrap(),
            original
        );
    }
}
