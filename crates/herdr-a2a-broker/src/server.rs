use axum::{Router, middleware};
use herdr_a2a_core::{BrokerClock, BrokerRecoveryReport, BrokerState, DomainError};

use crate::{
    ApiState, SqliteTaskStore, StoreError, StoreRecoveryReport, a2a_router, api::require_bearer,
    private_router,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerStartupReport {
    pub store: StoreRecoveryReport,
    pub broker: BrokerRecoveryReport,
    pub repaired_after_recovery: usize,
}

#[derive(Debug)]
pub enum BrokerStartupError {
    StorePrepare(StoreError),
    CoreReconcile(DomainError),
    ProjectionDrain(StoreError),
}

impl BrokerStartupError {
    pub fn stage(&self) -> &'static str {
        match self {
            Self::StorePrepare(_) => "store_prepare",
            Self::CoreReconcile(_) => "core_reconcile",
            Self::ProjectionDrain(_) => "projection_drain",
        }
    }
}

impl std::fmt::Display for BrokerStartupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "broker startup failed at {}", self.stage())
    }
}

impl std::error::Error for BrokerStartupError {}

pub async fn recover_broker_state(
    clock: impl BrokerClock,
    store: &SqliteTaskStore,
) -> Result<(BrokerState, BrokerStartupReport), BrokerStartupError> {
    let store_report = store
        .prepare_startup(clock.now_unix_ms())
        .await
        .map_err(BrokerStartupError::StorePrepare)?;
    let (broker, broker_report) = BrokerState::recover(clock, store.clone())
        .await
        .map_err(BrokerStartupError::CoreReconcile)?;
    let repaired_after_recovery = store
        .apply_pending_projections()
        .await
        .map_err(BrokerStartupError::ProjectionDrain)?;
    Ok((
        broker,
        BrokerStartupReport {
            store: store_report,
            broker: broker_report,
            repaired_after_recovery,
        },
    ))
}

pub fn server_router(
    api_state: ApiState,
    task_store: SqliteTaskStore,
    jsonrpc_url: impl Into<String>,
) -> Router {
    let a2a = a2a_router(api_state.broker().clone(), task_store, jsonrpc_url).layer(
        middleware::from_fn_with_state(api_state.clone(), require_bearer),
    );
    private_router(api_state).merge(a2a)
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, time::Duration};

    use herdr_a2a_core::{
        AgentName, DomainError, QueuedDelivery, SystemClock, ValidatedPayload, VerifiedAgent,
    };
    use serde_json::json;

    use crate::{SqliteTaskStore, server::recover_broker_state};

    fn agent(name: &str, pane_id: &str) -> VerifiedAgent {
        VerifiedAgent {
            name: AgentName::parse(name).unwrap(),
            pane_id: pane_id.to_owned(),
            harness: "pi".to_owned(),
            workspace: PathBuf::from("/repo"),
        }
    }

    fn delivery(task_id: &str) -> QueuedDelivery {
        QueuedDelivery {
            task_id: task_id.to_owned(),
            context_id: format!("context-{task_id}"),
            sender: AgentName::parse("implementer").unwrap(),
            recipient: AgentName::parse("reviewer").unwrap(),
            payload: ValidatedPayload {
                text: format!("payload-{task_id}"),
                metadata: json!({}),
                file_refs: vec![],
            },
            created_unix_ms: 0,
            attempt: 0,
        }
    }

    #[tokio::test]
    async fn startup_requeues_unacknowledged_but_not_acknowledged_delivery() {
        // Break caught: the production startup sequence either loses an unacknowledged lease or
        // makes an acknowledged delivery visible after reopening the same durable database.
        let temporary = tempfile::tempdir().unwrap();
        let database = temporary.path().join("tasks.sqlite3");
        let first_store = SqliteTaskStore::open(&database).unwrap();
        let (first, _) = recover_broker_state(SystemClock, &first_store)
            .await
            .unwrap();
        let sender = first
            .register(agent("implementer", "w1:p1"), "sender-session")
            .await
            .unwrap();
        let recipient = first
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        first
            .enqueue(&sender.credentials(), delivery("task-unacked"))
            .await
            .unwrap();
        let unacknowledged = first
            .wait_next(&recipient.credentials(), Some(Duration::from_secs(1)))
            .await
            .unwrap();
        first
            .enqueue(&sender.credentials(), delivery("task-acked"))
            .await
            .unwrap();
        let acknowledged = first
            .wait_next(&recipient.credentials(), Some(Duration::from_secs(1)))
            .await
            .unwrap();
        first
            .ack_delivery(&recipient.credentials(), &acknowledged.delivery_id)
            .await
            .unwrap();
        let old_credentials = recipient.credentials();
        drop(first);
        drop(first_store);

        let second_store = SqliteTaskStore::open(&database).unwrap();
        let (second, _) = recover_broker_state(SystemClock, &second_store)
            .await
            .unwrap();
        assert!(matches!(
            second.renew(&old_credentials).await,
            Err(DomainError::RegistrationNotFound)
        ));
        let replacement = second
            .register(agent("reviewer", "w2:p2"), "replacement-session")
            .await
            .unwrap();
        let redelivered = second
            .wait_next(&replacement.credentials(), Some(Duration::from_secs(1)))
            .await
            .unwrap();
        assert_eq!(redelivered.task_id, unacknowledged.task_id);
        assert!(matches!(
            second
                .wait_next(&replacement.credentials(), Some(Duration::from_millis(20)),)
                .await,
            Err(DomainError::WaitTimedOut)
        ));
    }
}
