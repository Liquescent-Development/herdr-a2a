use serde::{Deserialize, Serialize};

use crate::{
    AgentName, DeliveryId, DomainError, RegistrationEpoch, ReplyPayload, ValidatedPayload,
};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DurableBrokerSnapshot {
    pub last_registration_epoch: RegistrationEpoch,
    pub tasks: Vec<DurableTask>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PersistenceBatch {
    pub registration_epoch_high_watermark: Option<RegistrationEpoch>,
    pub upsert_tasks: Vec<DurableTask>,
    pub delete_task_ids: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistenceCommitOutcome {
    Complete,
    ReconciliationRequired,
}

impl PersistenceBatch {
    pub(crate) fn is_empty(&self) -> bool {
        self.registration_epoch_high_watermark.is_none()
            && self.upsert_tasks.is_empty()
            && self.delete_task_ids.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DurableTask {
    pub task_id: String,
    pub context_id: String,
    pub sender: AgentName,
    pub recipient: AgentName,
    pub payload: ValidatedPayload,
    pub created_unix_ms: i64,
    pub delivery_deadline_unix_ms: i64,
    pub state_version: u64,
    pub state: DurableTaskState,
    pub lease: Option<DurableLease>,
    pub attempt: u32,
    pub acknowledged_unix_ms: Option<i64>,
    pub reply: Option<ReplyPayload>,
    pub terminal_unix_ms: Option<i64>,
    pub retention_deadline_unix_ms: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DurableTaskState {
    Queued,
    Leased,
    Acknowledged,
    Replied,
    Failed,
    Rejected,
    Canceled,
    Expired,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DurableLease {
    pub delivery_id: DeliveryId,
    pub owner: AgentName,
    pub leased_until_unix_ms: i64,
    pub attempt: u32,
}

#[async_trait::async_trait]
pub trait BrokerPersistence: Send + Sync + 'static {
    async fn load(&self, now_unix_ms: i64) -> Result<DurableBrokerSnapshot, DomainError>;
    async fn commit(
        &self,
        batch: PersistenceBatch,
    ) -> Result<PersistenceCommitOutcome, DomainError>;
}

#[derive(Debug, Default)]
pub(crate) struct VolatilePersistence;

#[async_trait::async_trait]
impl BrokerPersistence for VolatilePersistence {
    async fn load(&self, _now_unix_ms: i64) -> Result<DurableBrokerSnapshot, DomainError> {
        Ok(DurableBrokerSnapshot {
            last_registration_epoch: RegistrationEpoch::from_u64(0),
            tasks: Vec::new(),
        })
    }

    async fn commit(
        &self,
        _batch: PersistenceBatch,
    ) -> Result<PersistenceCommitOutcome, DomainError> {
        Ok(PersistenceCommitOutcome::Complete)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use serde_json::json;

    use super::*;
    use crate::{BrokerClock, BrokerState, FileReference, TERMINAL_RETENTION_MS, VerifiedAgent};

    const DELIVERY_TTL_MS: i64 = 24 * 60 * 60 * 1_000;

    #[derive(Clone, Copy)]
    struct FixedClock(i64);

    impl BrokerClock for FixedClock {
        fn now_unix_ms(&self) -> i64 {
            self.0
        }
    }

    #[derive(Clone)]
    struct MemoryPersistence {
        snapshot: Arc<Mutex<DurableBrokerSnapshot>>,
    }

    impl MemoryPersistence {
        fn with_tasks(tasks: Vec<DurableTask>) -> Self {
            Self {
                snapshot: Arc::new(Mutex::new(DurableBrokerSnapshot {
                    last_registration_epoch: RegistrationEpoch::from_u64(7),
                    tasks,
                })),
            }
        }

        fn tasks(&self) -> Vec<DurableTask> {
            self.snapshot.lock().unwrap().tasks.clone()
        }
    }

    #[async_trait::async_trait]
    impl BrokerPersistence for MemoryPersistence {
        async fn load(&self, _now_unix_ms: i64) -> Result<DurableBrokerSnapshot, DomainError> {
            Ok(self.snapshot.lock().unwrap().clone())
        }

        async fn commit(
            &self,
            batch: PersistenceBatch,
        ) -> Result<PersistenceCommitOutcome, DomainError> {
            let mut snapshot = self.snapshot.lock().unwrap();
            if let Some(epoch) = batch.registration_epoch_high_watermark {
                snapshot.last_registration_epoch = epoch;
            }
            for task in batch.upsert_tasks {
                if let Some(existing) = snapshot
                    .tasks
                    .iter_mut()
                    .find(|existing| existing.task_id == task.task_id)
                {
                    *existing = task;
                } else {
                    snapshot.tasks.push(task);
                }
            }
            snapshot
                .tasks
                .retain(|task| !batch.delete_task_ids.contains(&task.task_id));
            Ok(PersistenceCommitOutcome::Complete)
        }
    }

    fn name(value: &str) -> AgentName {
        AgentName::parse(value).unwrap()
    }

    fn durable_task(task_id: &str, state: DurableTaskState, now: i64) -> DurableTask {
        let created = now - 1_000;
        let lease = matches!(
            state,
            DurableTaskState::Leased | DurableTaskState::Acknowledged
        )
        .then(|| DurableLease {
            delivery_id: DeliveryId::new(),
            owner: name("reviewer"),
            leased_until_unix_ms: now + 60_000,
            attempt: 2,
        });
        DurableTask {
            task_id: task_id.to_owned(),
            context_id: "context-1".to_owned(),
            sender: name("implementer"),
            recipient: name("reviewer"),
            payload: ValidatedPayload {
                text: "request".to_owned(),
                metadata: json!({"exact": true}),
                file_refs: vec![FileReference {
                    path: PathBuf::from("artifact.txt"),
                    media_type: Some("text/plain".to_owned()),
                    label: Some("artifact".to_owned()),
                }],
            },
            created_unix_ms: created,
            delivery_deadline_unix_ms: created + DELIVERY_TTL_MS,
            state_version: 3,
            state: state.clone(),
            lease,
            attempt: 2,
            acknowledged_unix_ms: (state == DurableTaskState::Acknowledged).then_some(now - 500),
            reply: None,
            terminal_unix_ms: None,
            retention_deadline_unix_ms: None,
        }
    }

    fn agent(name_value: &str) -> VerifiedAgent {
        VerifiedAgent {
            name: name(name_value),
            pane_id: "w1:p1".to_owned(),
            harness: "pi".to_owned(),
            workspace: PathBuf::from("/workspace"),
        }
    }

    #[tokio::test]
    async fn recovery_requeues_unacknowledged_leases_and_preserves_acknowledged_tasks() {
        let now = 10_000;
        let persistence = MemoryPersistence::with_tasks(vec![
            durable_task("task-leased", DurableTaskState::Leased, now),
            durable_task("task-acknowledged", DurableTaskState::Acknowledged, now),
        ]);
        let (broker, report) = BrokerState::recover(FixedClock(now), persistence.clone())
            .await
            .unwrap();
        assert_eq!(report.requeued, 1);
        assert_eq!(report.expired, 0);
        assert_eq!(report.pruned, 0);
        assert_eq!(report.restored, 2);
        let tasks = persistence.tasks();
        assert_eq!(
            tasks
                .iter()
                .find(|task| task.task_id == "task-leased")
                .unwrap()
                .state,
            DurableTaskState::Queued
        );
        assert_eq!(
            tasks
                .iter()
                .find(|task| task.task_id == "task-acknowledged")
                .unwrap()
                .state,
            DurableTaskState::Acknowledged
        );

        let recipient = broker.register(agent("reviewer"), "session").await.unwrap();
        assert_eq!(recipient.epoch.get(), 8);
        let delivered = broker
            .wait_next(&recipient.credentials(), Some(Duration::from_millis(1)))
            .await
            .unwrap();
        assert_eq!(delivered.task_id, "task-leased");
    }

    #[tokio::test]
    async fn recovery_expires_every_nonterminal_state_at_original_deadline() {
        let now = DELIVERY_TTL_MS + 1_000;
        let mut queued = durable_task("task-queued", DurableTaskState::Queued, now);
        let mut leased = durable_task("task-leased", DurableTaskState::Leased, now);
        let mut acknowledged =
            durable_task("task-acknowledged", DurableTaskState::Acknowledged, now);
        for task in [&mut queued, &mut leased, &mut acknowledged] {
            task.created_unix_ms = 1_000;
            task.delivery_deadline_unix_ms = now;
        }
        acknowledged.acknowledged_unix_ms = Some(now - 1);
        let persistence = MemoryPersistence::with_tasks(vec![queued, leased, acknowledged]);
        let (_broker, report) = BrokerState::recover(FixedClock(now), persistence.clone())
            .await
            .unwrap();
        assert_eq!(report.expired, 3);
        assert_eq!(report.requeued, 0);
        assert_eq!(report.restored, 3);
        for task in persistence.tasks() {
            assert_eq!(task.state, DurableTaskState::Expired);
            assert_eq!(task.terminal_unix_ms, Some(now));
            assert_eq!(
                task.retention_deadline_unix_ms,
                Some(now + TERMINAL_RETENTION_MS)
            );
        }
    }

    #[tokio::test]
    async fn recovery_prunes_terminal_state_at_exact_retention_boundary() {
        let now = 50 * 24 * 60 * 60 * 1_000;
        let terminal = now - TERMINAL_RETENTION_MS;
        let mut task = durable_task("task-terminal", DurableTaskState::Canceled, now);
        task.created_unix_ms = terminal - 1_000;
        task.delivery_deadline_unix_ms = task.created_unix_ms + DELIVERY_TTL_MS;
        task.lease = None;
        task.terminal_unix_ms = Some(terminal);
        task.retention_deadline_unix_ms = Some(now);
        let persistence = MemoryPersistence::with_tasks(vec![task]);
        let (_broker, report) = BrokerState::recover(FixedClock(now), persistence.clone())
            .await
            .unwrap();
        assert_eq!(report.pruned, 1);
        assert_eq!(report.restored, 0);
        assert!(persistence.tasks().is_empty());
    }

    #[tokio::test]
    async fn recovery_rejects_more_than_4096_loaded_tasks() {
        let now = 10_000;
        let tasks = (0..=crate::MAX_RETAINED_TASKS)
            .map(|index| durable_task(&format!("task-cap-{index}"), DurableTaskState::Queued, now))
            .collect();
        let persistence = MemoryPersistence::with_tasks(tasks);
        let error = BrokerState::recover(FixedClock(now), persistence)
            .await
            .err()
            .unwrap();
        assert_eq!(error, DomainError::PersistenceUnavailable);
    }

    #[tokio::test]
    async fn recovery_rejects_registration_epoch_overflow() {
        let now = 10_000;
        let persistence = MemoryPersistence::with_tasks(Vec::new());
        persistence.snapshot.lock().unwrap().last_registration_epoch =
            RegistrationEpoch::from_u64(u64::MAX);
        let error = BrokerState::recover(FixedClock(now), persistence)
            .await
            .err()
            .unwrap();
        assert_eq!(error, DomainError::PersistenceUnavailable);
    }

    #[tokio::test]
    async fn recovery_rejects_acknowledged_task_without_lease() {
        let now = 10_000;
        let mut task = durable_task("task-acknowledged", DurableTaskState::Acknowledged, now);
        task.lease = None;
        let persistence = MemoryPersistence::with_tasks(vec![task]);
        let error = BrokerState::recover(FixedClock(now), persistence)
            .await
            .err()
            .unwrap();
        assert_eq!(error, DomainError::PersistenceUnavailable);
    }

    #[tokio::test]
    async fn recovery_rejects_duplicate_delivery_ids() {
        let now = 10_000;
        let first = durable_task("task-first", DurableTaskState::Leased, now);
        let mut second = durable_task("task-second", DurableTaskState::Acknowledged, now);
        second.lease.as_mut().unwrap().delivery_id =
            first.lease.as_ref().unwrap().delivery_id.clone();
        let persistence = MemoryPersistence::with_tasks(vec![first, second]);
        let error = BrokerState::recover(FixedClock(now), persistence)
            .await
            .err()
            .unwrap();
        assert_eq!(error, DomainError::PersistenceUnavailable);
    }

    #[tokio::test]
    async fn recovery_rejects_unrepresentable_delivery_deadline() {
        let now = 10_000;
        let mut task = durable_task("task-overflow", DurableTaskState::Queued, now);
        task.created_unix_ms = i64::MAX - DELIVERY_TTL_MS + 1;
        task.delivery_deadline_unix_ms = i64::MAX;
        let persistence = MemoryPersistence::with_tasks(vec![task]);
        let error = BrokerState::recover(FixedClock(now), persistence)
            .await
            .err()
            .unwrap();
        assert_eq!(error, DomainError::PersistenceUnavailable);
    }

    #[tokio::test]
    async fn recovery_rejects_unrepresentable_terminal_retention() {
        let now = 10_000;
        let mut task = durable_task("task-overflow", DurableTaskState::Canceled, now);
        task.lease = None;
        task.terminal_unix_ms = Some(i64::MAX - TERMINAL_RETENTION_MS + 1);
        task.retention_deadline_unix_ms = Some(i64::MAX);
        let persistence = MemoryPersistence::with_tasks(vec![task]);
        let error = BrokerState::recover(FixedClock(now), persistence)
            .await
            .err()
            .unwrap();
        assert_eq!(error, DomainError::PersistenceUnavailable);
    }

    #[tokio::test]
    async fn recovered_requeue_rejects_attempt_overflow_without_mutation() {
        let now = 10_000;
        let mut task = durable_task("task-attempt-max", DurableTaskState::Queued, now);
        task.attempt = u32::MAX;
        task.state_version = 4;
        let persistence = MemoryPersistence::with_tasks(vec![task]);
        let (broker, _) = BrokerState::recover(FixedClock(now), persistence.clone())
            .await
            .unwrap();
        let recipient = broker.register(agent("reviewer"), "session").await.unwrap();
        let error = broker
            .wait_next(&recipient.credentials(), Some(Duration::from_millis(1)))
            .await
            .unwrap_err();
        assert_eq!(error, DomainError::PersistenceUnavailable);
        let stored = persistence.tasks();
        assert_eq!(stored[0].state, DurableTaskState::Queued);
        assert_eq!(stored[0].attempt, u32::MAX);
        assert_eq!(stored[0].state_version, 4);
    }

    #[tokio::test]
    async fn recovery_rejects_expiry_retention_overflow_without_commit() {
        let now = i64::MAX;
        let mut task = durable_task("task-expiry-overflow", DurableTaskState::Queued, 10_000);
        task.created_unix_ms = now - DELIVERY_TTL_MS;
        task.delivery_deadline_unix_ms = now;
        let persistence = MemoryPersistence::with_tasks(vec![task]);
        let error = BrokerState::recover(FixedClock(now), persistence.clone())
            .await
            .err()
            .unwrap();
        assert_eq!(error, DomainError::PersistenceUnavailable);
        let stored = persistence.tasks();
        assert_eq!(stored[0].state, DurableTaskState::Queued);
        assert_eq!(stored[0].state_version, 3);
    }
}
