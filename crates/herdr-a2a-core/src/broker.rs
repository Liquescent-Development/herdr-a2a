use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, HashSet, VecDeque},
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::sync::{Mutex, Notify, oneshot};

#[cfg(test)]
use std::sync::atomic::AtomicUsize;

use crate::{
    AgentName, BrokerPersistence, DeliveredMessage, DeliveryId, DomainError, DurableBrokerSnapshot,
    DurableLease, DurableTask, DurableTaskState, PersistenceBatch, PersistenceCommitOutcome,
    QueuedDelivery, Registration, RegistrationCredentials, RegistrationEpoch, RegistrationId,
    ReplyPayload, VerifiedAgent, durability::VolatilePersistence, validate_task_id,
};

const REGISTRATION_TTL_MS: i64 = 30_000;
const DELIVERY_LEASE_MS: i64 = 60_000;
const DELIVERY_TTL_MS: i64 = 24 * 60 * 60 * 1_000;
pub const TERMINAL_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1_000;
pub const MAX_RETAINED_TASKS: usize = 4096;
const MAX_RETIRED_REGISTRATION_IDS: usize = MAX_RETAINED_TASKS;
const MAX_ACTIVE_OUTBOUND_TASKS: usize = 32;

pub trait BrokerClock: Send + Sync + 'static {
    fn now_unix_ms(&self) -> i64;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl BrokerClock for SystemClock {
    fn now_unix_ms(&self) -> i64 {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        i64::try_from(millis).unwrap_or(i64::MAX)
    }
}

#[derive(Clone)]
pub struct BrokerState {
    inner: Arc<BrokerInner>,
}

struct BrokerInner {
    clock: Arc<dyn BrokerClock>,
    persistence: Arc<dyn BrokerPersistence>,
    state: Mutex<State>,
    directory: Arc<DirectoryChanges>,
}

#[derive(Default)]
struct State {
    directory: Arc<DirectoryChanges>,
    reconciliation_required: bool,
    last_event: Option<BrokerStatusEvent>,
    next_registration_epoch: u64,
    next_task_sequence: u64,
    registrations: HashMap<RegistrationId, RegistrationState>,
    registrations_by_agent: HashMap<AgentName, RegistrationId>,
    retired_registration_ids: HashSet<RegistrationId>,
    retired_registration_order: VecDeque<RegistrationId>,
    active_tasks_by_agent: HashMap<AgentName, HashSet<String>>,
    outbound_tasks_by_agent: HashMap<AgentName, HashSet<String>>,
    tasks_by_sender: HashMap<AgentName, HashSet<String>>,
    tasks_by_recipient: HashMap<AgentName, HashSet<String>>,
    tasks: HashMap<String, TaskRecord>,
    tasks_by_delivery: HashMap<DeliveryId, String>,
    delivery_deadlines: BinaryHeap<Reverse<(i64, String)>>,
    terminal_deadlines: BinaryHeap<Reverse<(i64, String)>>,
}

#[derive(Default)]
struct DirectoryChanges {
    generation: AtomicU64,
    notify: Notify,
}

impl DirectoryChanges {
    fn record(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.notify.notify_waiters();
    }
}

struct RegistrationState {
    registration: Registration,
    inbox: VecDeque<String>,
    notify: Arc<Notify>,
    wait_active: Arc<AtomicBool>,
    #[cfg(test)]
    inbox_pushes: Arc<AtomicUsize>,
}

struct TaskRecord {
    enqueue_sequence: u64,
    state_version: u64,
    original_delivery: QueuedDelivery,
    delivery: Option<QueuedDelivery>,
    recipient: AgentName,
    sender: AgentName,
    lease: Option<DeliveryLease>,
    last_delivery_attempt: Option<u32>,
    acknowledged: bool,
    acknowledged_unix_ms: Option<i64>,
    reply: Option<ReplyPayload>,
    reply_waiters: Vec<ReplyWaiter>,
    failed: bool,
    rejected: bool,
    canceled: bool,
    expired: bool,
    terminal_unix_ms: Option<i64>,
    terminal_deadline_unix_ms: Option<i64>,
    #[cfg(test)]
    lease_applications: Arc<AtomicUsize>,
    #[cfg(test)]
    ack_applications: Arc<AtomicUsize>,
}

type ReplyResult = Result<ReplyPayload, DomainError>;
type ReplyWaiter = oneshot::Sender<ReplyResult>;
type ReplyResolution = (ReplyWaiter, ReplyResult);

struct DeliveryLease {
    delivery_id: DeliveryId,
    owner: Option<RegistrationCredentials>,
    leased_until_unix_ms: i64,
    attempt: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryHandle {
    pub task_id: String,
    pub context_id: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum StartOrResume {
    Started(DurableTask),
    Active(DurableTask),
    Terminal(DurableTask),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BrokerRecoveryReport {
    pub requeued: usize,
    pub expired: usize,
    pub pruned: usize,
    pub restored: usize,
}

#[derive(Clone, Debug)]
pub struct AgentDirectoryWait {
    pub generation: u64,
    pub registrations: Vec<Registration>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct BrokerTaskCounts {
    pub queued: usize,
    pub leased: usize,
    pub waiting_reply: usize,
    pub terminal: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct BrokerStatusEvent {
    pub kind: String,
    pub canonical_name: AgentName,
    /// Whole seconds deliberately avoid exposing high-resolution activity timing.
    pub unix_time: i64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct BrokerOperationsSnapshot {
    pub registrations: usize,
    pub agents: Vec<BrokerOperationsAgent>,
    pub tasks: BrokerTaskCounts,
    pub last_event: Option<BrokerStatusEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct BrokerOperationsAgent {
    pub canonical_name: AgentName,
}

pub struct WaitGuard {
    active: Arc<AtomicBool>,
}

impl fmt::Debug for WaitGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WaitGuard")
    }
}

impl Drop for WaitGuard {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}

enum DeliveryPoll {
    Ready(Box<DeliveredMessage>),
    Pending { next_deadline_unix_ms: i64 },
}

impl BrokerState {
    pub fn new() -> Self {
        Self::with_clock(SystemClock)
    }

    pub fn with_clock(clock: impl BrokerClock) -> Self {
        let directory = Arc::new(DirectoryChanges::default());
        Self {
            inner: Arc::new(BrokerInner {
                clock: Arc::new(clock),
                persistence: Arc::new(VolatilePersistence),
                state: Mutex::new(State {
                    directory: directory.clone(),
                    ..State::default()
                }),
                directory,
            }),
        }
    }

    pub async fn recover(
        clock: impl BrokerClock,
        persistence: impl BrokerPersistence,
    ) -> Result<(Self, BrokerRecoveryReport), DomainError> {
        let clock: Arc<dyn BrokerClock> = Arc::new(clock);
        let persistence: Arc<dyn BrokerPersistence> = Arc::new(persistence);
        let now = clock.now_unix_ms();
        let DurableBrokerSnapshot {
            last_registration_epoch,
            tasks,
        } = persistence.load(now).await?;
        let mut report = BrokerRecoveryReport::default();
        let (mut tasks, batch) = validate_and_reconcile_snapshot(tasks, now, &mut report)?;
        if last_registration_epoch.get() == u64::MAX {
            return Err(DomainError::PersistenceUnavailable);
        }
        if !batch.is_empty()
            && persistence.commit(batch).await? != PersistenceCommitOutcome::Complete
        {
            return Err(DomainError::PersistenceUnavailable);
        }

        tasks.retain(|task| {
            task.retention_deadline_unix_ms
                .is_none_or(|deadline| deadline > now)
        });
        let directory = Arc::new(DirectoryChanges::default());
        let mut state = State {
            directory: directory.clone(),
            next_registration_epoch: last_registration_epoch.get(),
            ..State::default()
        };
        tasks.sort_by(|left, right| {
            left.created_unix_ms
                .cmp(&right.created_unix_ms)
                .then_with(|| left.task_id.cmp(&right.task_id))
        });
        for task in tasks {
            state.next_task_sequence = state
                .next_task_sequence
                .checked_add(1)
                .ok_or(DomainError::PersistenceUnavailable)?;
            restore_task(&mut state, task)?;
            report.restored += 1;
        }
        Ok((
            Self {
                inner: Arc::new(BrokerInner {
                    clock,
                    persistence,
                    state: Mutex::new(state),
                    directory,
                }),
            },
            report,
        ))
    }

    pub async fn register(
        &self,
        agent: VerifiedAgent,
        harness_session_id: &str,
    ) -> Result<Registration, DomainError> {
        let mut state = self.inner.state.lock().await;
        let now = self.now_unix_ms();
        maintain_state(&mut state, self.inner.persistence.as_ref(), now).await?;
        let registration_expiry = now
            .checked_add(REGISTRATION_TTL_MS)
            .ok_or(DomainError::PersistenceUnavailable)?;
        let next_registration_epoch = state
            .next_registration_epoch
            .checked_add(1)
            .ok_or(DomainError::PersistenceUnavailable)?;
        let registration = Registration {
            id: RegistrationId::new(),
            epoch: RegistrationEpoch::from_u64(next_registration_epoch),
            agent,
            harness_session_id: harness_session_id.to_owned(),
            expires_unix_ms: registration_expiry,
        };
        let state_entry = RegistrationState {
            registration: registration.clone(),
            inbox: VecDeque::new(),
            notify: Arc::new(Notify::new()),
            wait_active: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            inbox_pushes: Arc::new(AtomicUsize::new(0)),
        };

        let old_registration_id = state
            .registrations_by_agent
            .get(&registration.agent.name)
            .cloned();
        let requeued_tasks = old_registration_id
            .as_ref()
            .and_then(|id| state.registrations.get(id))
            .map(|entry| entry.registration.credentials())
            .into_iter()
            .flat_map(|credentials| {
                state
                    .tasks
                    .iter()
                    .filter(move |(_, task)| {
                        !task.acknowledged
                            && task
                                .lease
                                .as_ref()
                                .is_some_and(|lease| lease.owner.as_ref() == Some(&credentials))
                    })
                    .map(|(task_id, task)| durable_requeued_task(task_id, task))
            })
            .collect::<Result<Vec<_>, _>>()?;
        commit_transition(
            &mut state,
            self.inner.persistence.as_ref(),
            PersistenceBatch {
                registration_epoch_high_watermark: Some(RegistrationEpoch::from_u64(
                    next_registration_epoch,
                )),
                upsert_tasks: requeued_tasks,
                delete_task_ids: Vec::new(),
            },
        )
        .await?;
        state.next_registration_epoch = next_registration_epoch;
        let old_registration = old_registration_id.and_then(|id| {
            if let Some(credentials) = state
                .registrations
                .get(&id)
                .map(|entry| entry.registration.credentials())
            {
                bump_requeued_versions_for_credentials(&mut state, &credentials);
            }
            detach_registration(&mut state, &id, true)
        });
        let mut state_entry = state_entry;
        let mut queued_task_ids = state
            .active_tasks_by_agent
            .get(&registration.agent.name)
            .into_iter()
            .flatten()
            .filter_map(|task_id| {
                let task = state
                    .tasks
                    .get(task_id)
                    .expect("active task index must reference a task");
                (task.recipient == registration.agent.name
                    && !task.acknowledged
                    && !task.canceled
                    && !task.expired
                    && task.reply.is_none())
                .then(|| {
                    task.delivery
                        .as_ref()
                        .map(|_| (task.enqueue_sequence, task_id.clone()))
                })
                .flatten()
            })
            .collect::<Vec<_>>();
        queued_task_ids.sort_unstable();
        for (_, task_id) in queued_task_ids {
            state_entry.inbox.push_back(task_id);
        }
        state
            .registrations_by_agent
            .insert(registration.agent.name.clone(), registration.id.clone());
        state
            .registrations
            .insert(registration.id.clone(), state_entry);
        record_status_event(&mut state, "registered", &registration.agent.name, now);
        drop(state);

        self.inner.directory.record();

        if let Some(old_registration) = old_registration {
            old_registration.notify.notify_one();
        }
        Ok(registration)
    }

    pub async fn renew(
        &self,
        credentials: &RegistrationCredentials,
    ) -> Result<Registration, DomainError> {
        let mut state = self.inner.state.lock().await;
        let now = self.now_unix_ms();
        validate_registration_and_maintain(
            &mut state,
            self.inner.persistence.as_ref(),
            credentials,
            now,
        )
        .await?;
        let registration_expiry = now
            .checked_add(REGISTRATION_TTL_MS)
            .ok_or(DomainError::PersistenceUnavailable)?;
        let registration = state
            .registrations
            .get_mut(&credentials.id)
            .expect("validated registration must remain active");
        registration.registration.expires_unix_ms = registration_expiry;
        Ok(registration.registration.clone())
    }

    pub async fn remove_registration(
        &self,
        credentials: &RegistrationCredentials,
    ) -> Result<(), DomainError> {
        let mut state = self.inner.state.lock().await;
        let now = self.now_unix_ms();
        validate_registration_and_maintain(
            &mut state,
            self.inner.persistence.as_ref(),
            credentials,
            now,
        )
        .await?;
        let requeued_tasks = state
            .tasks
            .iter()
            .filter(|(_, task)| {
                !task.acknowledged
                    && task
                        .lease
                        .as_ref()
                        .is_some_and(|lease| lease.owner.as_ref() == Some(credentials))
            })
            .map(|(task_id, task)| durable_requeued_task(task_id, task))
            .collect::<Result<Vec<_>, _>>()?;
        if !requeued_tasks.is_empty() {
            commit_transition(
                &mut state,
                self.inner.persistence.as_ref(),
                PersistenceBatch {
                    registration_epoch_high_watermark: None,
                    upsert_tasks: requeued_tasks,
                    delete_task_ids: Vec::new(),
                },
            )
            .await?;
        }
        bump_requeued_versions_for_credentials(&mut state, credentials);
        let registration = detach_registration(&mut state, &credentials.id, false)
            .expect("validated registration must remain active");
        drop(state);
        self.inner.directory.record();
        registration.notify.notify_one();
        Ok(())
    }

    pub async fn authenticate(
        &self,
        credentials: &RegistrationCredentials,
    ) -> Result<Registration, DomainError> {
        let mut state = self.inner.state.lock().await;
        let now = self.now_unix_ms();
        validate_registration_and_maintain(
            &mut state,
            self.inner.persistence.as_ref(),
            credentials,
            now,
        )
        .await?;
        Ok(state
            .registrations
            .get(&credentials.id)
            .expect("validated registration must remain active")
            .registration
            .clone())
    }

    pub async fn list_agents(&self) -> Vec<Registration> {
        let mut state = self.inner.state.lock().await;
        let now = self.now_unix_ms();
        if maintain_state(&mut state, self.inner.persistence.as_ref(), now)
            .await
            .is_err()
        {
            return Vec::new();
        }
        let mut registrations = state
            .registrations
            .values()
            .filter(|entry| entry.registration.expires_unix_ms > now)
            .map(|entry| entry.registration.clone())
            .collect::<Vec<_>>();
        registrations.sort_by(|left, right| {
            left.agent
                .name
                .as_str()
                .cmp(right.agent.name.as_str())
                .then_with(|| left.id.as_str().cmp(right.id.as_str()))
        });
        registrations
    }

    pub async fn operations_snapshot(&self) -> Result<BrokerOperationsSnapshot, DomainError> {
        let mut state = self.inner.state.lock().await;
        let now = self.now_unix_ms();
        maintain_state(&mut state, self.inner.persistence.as_ref(), now).await?;
        let mut agents = state
            .registrations
            .values()
            .filter(|entry| entry.registration.expires_unix_ms > now)
            .map(|entry| BrokerOperationsAgent {
                canonical_name: entry.registration.agent.name.clone(),
            })
            .collect::<Vec<_>>();
        agents.sort_by(|left, right| {
            left.canonical_name
                .as_str()
                .cmp(right.canonical_name.as_str())
        });
        let registrations = agents.len();
        let mut tasks = BrokerTaskCounts::default();
        for task in state.tasks.values() {
            if task.reply.is_some() || task.failed || task.rejected || task.canceled || task.expired
            {
                tasks.terminal += 1;
            } else if task.acknowledged {
                tasks.waiting_reply += 1;
            } else if task.lease.is_some() {
                tasks.leased += 1;
            } else {
                tasks.queued += 1;
            }
        }
        Ok(BrokerOperationsSnapshot {
            registrations,
            agents,
            tasks,
            last_event: state.last_event.clone(),
        })
    }

    pub async fn wait_for_agents(
        &self,
        pane_ids: &[String],
        timeout: Duration,
    ) -> AgentDirectoryWait {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.inner.directory.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let snapshot = self.directory_snapshot(pane_ids).await;
            if snapshot.registrations.len() == pane_ids.len() {
                return snapshot;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return self.directory_snapshot(pane_ids).await;
            }
        }
    }

    async fn directory_snapshot(&self, pane_ids: &[String]) -> AgentDirectoryWait {
        let agents = self.list_agents().await;
        let generation = self.inner.directory.generation.load(Ordering::Acquire);
        let by_pane = agents
            .into_iter()
            .map(|registration| (registration.agent.pane_id.clone(), registration))
            .collect::<HashMap<_, _>>();
        AgentDirectoryWait {
            generation,
            registrations: pane_ids
                .iter()
                .filter_map(|pane_id| by_pane.get(pane_id).cloned())
                .collect(),
        }
    }

    pub async fn task_snapshot(
        &self,
        credentials: &RegistrationCredentials,
        task_id: &str,
    ) -> Result<DurableTask, DomainError> {
        let mut state = self.inner.state.lock().await;
        let now = self.now_unix_ms();
        validate_registration_and_maintain(
            &mut state,
            self.inner.persistence.as_ref(),
            credentials,
            now,
        )
        .await?;
        let sender = state
            .registrations
            .get(&credentials.id)
            .expect("validated registration must exist")
            .registration
            .agent
            .name
            .clone();
        let task = state.tasks.get(task_id).ok_or(DomainError::TaskNotFound)?;
        if task.sender != sender {
            return Err(DomainError::TaskNotOwned);
        }
        durable_task(task_id, task)
    }

    /// Loads a task after an outer transport layer has authenticated `sender`.
    ///
    /// This deliberately authorizes by the durable agent principal rather than an ephemeral
    /// registration ID. Callers must not expose it directly to untrusted request input.
    pub async fn task_snapshot_for_sender(
        &self,
        sender: &AgentName,
        task_id: &str,
    ) -> Result<DurableTask, DomainError> {
        let mut state = self.inner.state.lock().await;
        let now = self.now_unix_ms();
        maintain_state(&mut state, self.inner.persistence.as_ref(), now).await?;
        let task = state.tasks.get(task_id).ok_or(DomainError::TaskNotFound)?;
        if &task.sender != sender {
            return Err(DomainError::TaskNotOwned);
        }
        durable_task(task_id, task)
    }

    pub async fn start_or_resume(
        &self,
        credentials: &RegistrationCredentials,
        delivery: QueuedDelivery,
    ) -> Result<StartOrResume, DomainError> {
        for _ in 0..2 {
            {
                let mut state = self.inner.state.lock().await;
                let now = self.now_unix_ms();
                validate_registration_and_maintain(
                    &mut state,
                    self.inner.persistence.as_ref(),
                    credentials,
                    now,
                )
                .await?;
                let sender = state
                    .registrations
                    .get(&credentials.id)
                    .expect("validated registration must exist")
                    .registration
                    .agent
                    .name
                    .clone();
                if sender != delivery.sender {
                    return Err(DomainError::SenderMismatch);
                }
                if let Some(task) = state.tasks.get(&delivery.task_id) {
                    if task.sender != delivery.sender
                        || task.recipient != delivery.recipient
                        || task.original_delivery.context_id != delivery.context_id
                        || task.original_delivery.payload != delivery.payload
                    {
                        return Err(DomainError::DuplicateTask);
                    }
                    let snapshot = durable_task(&delivery.task_id, task)?;
                    return Ok(
                        if matches!(
                            snapshot.state,
                            DurableTaskState::Replied
                                | DurableTaskState::Failed
                                | DurableTaskState::Rejected
                                | DurableTaskState::Canceled
                                | DurableTaskState::Expired
                        ) {
                            StartOrResume::Terminal(snapshot)
                        } else {
                            StartOrResume::Active(snapshot)
                        },
                    );
                }
                active_registration_id(&state, &delivery.recipient, now)
                    .ok_or(DomainError::AgentNotRegistered)?;
            }
            match self.enqueue(credentials, delivery.clone()).await {
                Ok(_) => {
                    return self
                        .task_snapshot(credentials, &delivery.task_id)
                        .await
                        .map(StartOrResume::Started);
                }
                Err(DomainError::DuplicateTask) => continue,
                Err(error) => return Err(error),
            }
        }
        Err(DomainError::DuplicateTask)
    }

    pub async fn enqueue(
        &self,
        sender_credentials: &RegistrationCredentials,
        mut delivery: QueuedDelivery,
    ) -> Result<DeliveryHandle, DomainError> {
        let mut state = self.inner.state.lock().await;
        let now = self.now_unix_ms();
        validate_registration_and_maintain(
            &mut state,
            self.inner.persistence.as_ref(),
            sender_credentials,
            now,
        )
        .await?;
        if state.tasks.contains_key(&delivery.task_id) {
            return Err(DomainError::DuplicateTask);
        }
        if state.tasks.len() >= MAX_RETAINED_TASKS {
            return Err(DomainError::TooManyRetainedTasks);
        }

        let sender = state
            .registrations
            .get(&sender_credentials.id)
            .expect("validated sender registration must exist");
        if sender.registration.agent.name != delivery.sender {
            return Err(DomainError::SenderMismatch);
        }
        let sender_name = sender.registration.agent.name.clone();
        if state
            .outbound_tasks_by_agent
            .get(&sender_name)
            .map_or(0, HashSet::len)
            >= MAX_ACTIVE_OUTBOUND_TASKS
        {
            return Err(DomainError::TooManyActiveTasks);
        }

        let recipient_registration_id = active_registration_id(&state, &delivery.recipient, now)
            .ok_or(DomainError::AgentNotRegistered)?;

        delivery.created_unix_ms = now;
        let enqueue_sequence = state
            .next_task_sequence
            .checked_add(1)
            .ok_or(DomainError::PersistenceUnavailable)?;
        let handle = DeliveryHandle {
            task_id: delivery.task_id.clone(),
            context_id: delivery.context_id.clone(),
        };
        let task_id = delivery.task_id.clone();
        let recipient_name = delivery.recipient.clone();
        let delivery_deadline_unix_ms = delivery
            .created_unix_ms
            .checked_add(DELIVERY_TTL_MS)
            .ok_or(DomainError::PersistenceUnavailable)?;
        let durable = DurableTask {
            task_id: task_id.clone(),
            context_id: delivery.context_id.clone(),
            sender: sender_name.clone(),
            recipient: recipient_name.clone(),
            payload: delivery.payload.clone(),
            created_unix_ms: delivery.created_unix_ms,
            delivery_deadline_unix_ms,
            state_version: 1,
            state: DurableTaskState::Queued,
            lease: None,
            attempt: delivery.attempt,
            acknowledged_unix_ms: None,
            reply: None,
            terminal_unix_ms: None,
            retention_deadline_unix_ms: None,
        };
        commit_transition(
            &mut state,
            self.inner.persistence.as_ref(),
            PersistenceBatch {
                registration_epoch_high_watermark: None,
                upsert_tasks: vec![durable],
                delete_task_ids: Vec::new(),
            },
        )
        .await?;
        state.next_task_sequence = enqueue_sequence;
        let recipient = state
            .registrations
            .get_mut(&recipient_registration_id)
            .expect("active registration index must reference a registration");
        push_inbox(recipient, task_id.clone());
        let notify = recipient.notify.clone();

        state
            .active_tasks_by_agent
            .entry(sender_name.clone())
            .or_default()
            .insert(task_id.clone());
        state
            .tasks_by_sender
            .entry(sender_name.clone())
            .or_default()
            .insert(task_id.clone());
        state
            .tasks_by_recipient
            .entry(recipient_name.clone())
            .or_default()
            .insert(task_id.clone());
        state
            .outbound_tasks_by_agent
            .entry(sender_name.clone())
            .or_default()
            .insert(task_id.clone());
        state
            .active_tasks_by_agent
            .entry(recipient_name.clone())
            .or_default()
            .insert(task_id.clone());
        state.tasks.insert(
            task_id.clone(),
            TaskRecord {
                enqueue_sequence,
                state_version: 1,
                original_delivery: delivery.clone(),
                delivery: Some(delivery),
                recipient: recipient_name,
                sender: sender_name.clone(),
                lease: None,
                last_delivery_attempt: None,
                acknowledged: false,
                acknowledged_unix_ms: None,
                reply: None,
                reply_waiters: Vec::new(),
                failed: false,
                rejected: false,
                canceled: false,
                expired: false,
                terminal_unix_ms: None,
                terminal_deadline_unix_ms: None,
                #[cfg(test)]
                lease_applications: Arc::new(AtomicUsize::new(0)),
                #[cfg(test)]
                ack_applications: Arc::new(AtomicUsize::new(0)),
            },
        );
        state
            .delivery_deadlines
            .push(Reverse((delivery_deadline_unix_ms, task_id)));
        record_status_event(&mut state, "task_queued", &sender_name, now);
        drop(state);
        notify.notify_one();
        Ok(handle)
    }

    pub async fn begin_wait(
        &self,
        credentials: &RegistrationCredentials,
    ) -> Result<WaitGuard, DomainError> {
        let mut state = self.inner.state.lock().await;
        let now = self.now_unix_ms();
        validate_registration_and_maintain(
            &mut state,
            self.inner.persistence.as_ref(),
            credentials,
            now,
        )
        .await?;
        let registration = state
            .registrations
            .get(&credentials.id)
            .expect("validated registration must remain active");
        let active = registration.wait_active.clone();
        active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| DomainError::WaitAlreadyActive)?;
        Ok(WaitGuard { active })
    }

    pub async fn wait_next(
        &self,
        credentials: &RegistrationCredentials,
        timeout: Option<Duration>,
    ) -> Result<DeliveredMessage, DomainError> {
        let _guard = self.begin_wait(credentials).await?;
        let notify = {
            let state = self.inner.state.lock().await;
            state
                .registrations
                .get(&credentials.id)
                .ok_or(DomainError::RegistrationNotFound)?
                .notify
                .clone()
        };
        let timeout_deadline = timeout.map(|duration| tokio::time::Instant::now() + duration);

        loop {
            let notified = notify.notified();
            let next_deadline_unix_ms = match self.poll_delivery(credentials).await? {
                DeliveryPoll::Ready(delivery) => return Ok(*delivery),
                DeliveryPoll::Pending {
                    next_deadline_unix_ms,
                } => next_deadline_unix_ms,
            };
            let until_broker_deadline = duration_until(self.now_unix_ms(), next_deadline_unix_ms);
            let broker_deadline = tokio::time::Instant::now() + until_broker_deadline;

            match timeout_deadline {
                Some(timeout_deadline) => {
                    tokio::select! {
                        _ = notified => {}
                        _ = tokio::time::sleep_until(broker_deadline) => {}
                        _ = tokio::time::sleep_until(timeout_deadline) => {
                            return Err(DomainError::WaitTimedOut);
                        }
                    }
                }
                None => {
                    tokio::select! {
                        _ = notified => {}
                        _ = tokio::time::sleep_until(broker_deadline) => {}
                    }
                }
            }
        }
    }

    pub async fn ack_delivery(
        &self,
        credentials: &RegistrationCredentials,
        delivery_id: &DeliveryId,
    ) -> Result<(), DomainError> {
        let mut state = self.inner.state.lock().await;
        let now = self.now_unix_ms();
        validate_registration_and_maintain(
            &mut state,
            self.inner.persistence.as_ref(),
            credentials,
            now,
        )
        .await?;
        let registered_agent = state
            .registrations
            .get(&credentials.id)
            .expect("validated registration must remain active")
            .registration
            .agent
            .name
            .clone();
        let task_id = state
            .tasks_by_delivery
            .get(delivery_id)
            .cloned()
            .ok_or(DomainError::DeliveryNotFound)?;
        let task = state
            .tasks
            .get(&task_id)
            .expect("delivery lookup must reference a task");
        let valid_delivery = task.lease.as_ref().is_some_and(|lease| {
            &lease.delivery_id == delivery_id
                && (task.acknowledged || lease.leased_until_unix_ms > now)
                && task.delivery.is_some()
                && !task.canceled
                && !task.expired
                && task.reply.is_none()
        });
        if !valid_delivery {
            return Err(DomainError::DeliveryNotFound);
        }
        if task.acknowledged {
            return (task.recipient == registered_agent)
                .then_some(())
                .ok_or(DomainError::DeliveryNotOwned);
        }
        if task.lease.as_ref().and_then(|lease| lease.owner.as_ref()) != Some(credentials) {
            return Err(DomainError::DeliveryNotOwned);
        }
        let durable = durable_acknowledged_task(&task_id, task, now)?;
        commit_transition(
            &mut state,
            self.inner.persistence.as_ref(),
            single_task_batch(durable),
        )
        .await?;
        let task = state
            .tasks
            .get_mut(&task_id)
            .expect("delivery lookup must reference a task");
        task.state_version = task
            .state_version
            .checked_add(1)
            .ok_or(DomainError::PersistenceUnavailable)?;
        task.acknowledged = true;
        task.acknowledged_unix_ms = Some(now);
        #[cfg(test)]
        task.ack_applications.fetch_add(1, Ordering::SeqCst);
        state
            .registrations
            .get_mut(&credentials.id)
            .expect("validated registration must exist")
            .inbox
            .retain(|queued_task_id| queued_task_id != &task_id);
        Ok(())
    }

    pub async fn wait_for_reply(
        &self,
        sender_credentials: &RegistrationCredentials,
        task_id: &str,
    ) -> Result<ReplyPayload, DomainError> {
        let sender_name = {
            let mut state = self.inner.state.lock().await;
            let now = self.now_unix_ms();
            validate_registration_and_maintain(
                &mut state,
                self.inner.persistence.as_ref(),
                sender_credentials,
                now,
            )
            .await?;
            state
                .registrations
                .get(&sender_credentials.id)
                .expect("validated registration must remain active")
                .registration
                .agent
                .name
                .clone()
        };
        self.wait_for_reply_for_sender(&sender_name, task_id).await
    }

    /// Waits after an outer transport layer has authenticated `sender` for this task.
    pub async fn wait_for_reply_for_sender(
        &self,
        sender_name: &AgentName,
        task_id: &str,
    ) -> Result<ReplyPayload, DomainError> {
        let mut receiver = {
            let mut state = self.inner.state.lock().await;
            let now = self.now_unix_ms();
            maintain_state(&mut state, self.inner.persistence.as_ref(), now).await?;
            let task = state
                .tasks
                .get_mut(task_id)
                .ok_or(DomainError::TaskNotFound)?;
            if &task.sender != sender_name {
                return Err(DomainError::TaskNotOwned);
            }
            if task.canceled {
                return Err(DomainError::TaskCanceled);
            }
            if task.expired {
                return Err(DomainError::TaskExpired);
            }
            if task.failed {
                return Err(DomainError::TaskFailed);
            }
            if task.rejected {
                return Err(DomainError::TaskRejected);
            }
            if let Some(reply) = &task.reply {
                return Ok(reply.clone());
            }
            task.reply_waiters.retain(|waiter| !waiter.is_closed());
            let (sender, receiver) = oneshot::channel();
            task.reply_waiters.push(sender);
            receiver
        };

        loop {
            let delivery_deadline = {
                let state = self.inner.state.lock().await;
                let task = state.tasks.get(task_id).ok_or(DomainError::TaskNotFound)?;
                if task.canceled {
                    return Err(DomainError::TaskCanceled);
                }
                if task.expired {
                    return Err(DomainError::TaskExpired);
                }
                if task.failed {
                    return Err(DomainError::TaskFailed);
                }
                if task.rejected {
                    return Err(DomainError::TaskRejected);
                }
                if let Some(reply) = &task.reply {
                    return Ok(reply.clone());
                }
                task.delivery
                    .as_ref()
                    .map(|delivery| {
                        delivery
                            .created_unix_ms
                            .checked_add(DELIVERY_TTL_MS)
                            .ok_or(DomainError::PersistenceUnavailable)
                    })
                    .transpose()?
            };

            let Some(delivery_deadline) = delivery_deadline else {
                return self.resolve_reply_wait(task_id, receiver.await).await;
            };
            let deadline =
                tokio::time::Instant::now() + duration_until(self.now_unix_ms(), delivery_deadline);
            tokio::select! {
                result = &mut receiver => return self.resolve_reply_wait(task_id, result).await,
                _ = tokio::time::sleep_until(deadline) => {
                    let mut state = self.inner.state.lock().await;
                    maintain_state(
                        &mut state,
                        self.inner.persistence.as_ref(),
                        self.now_unix_ms(),
                    )
                    .await?;
                }
            }
        }
    }

    async fn resolve_reply_wait(
        &self,
        task_id: &str,
        result: Result<ReplyResult, oneshot::error::RecvError>,
    ) -> Result<ReplyPayload, DomainError> {
        match result {
            Ok(result) => result,
            Err(_) => {
                let state = self.inner.state.lock().await;
                let task = state.tasks.get(task_id).ok_or(DomainError::TaskNotFound)?;
                if task.canceled {
                    Err(DomainError::TaskCanceled)
                } else if task.expired {
                    Err(DomainError::TaskExpired)
                } else if task.failed {
                    Err(DomainError::TaskFailed)
                } else if task.rejected {
                    Err(DomainError::TaskRejected)
                } else if let Some(reply) = &task.reply {
                    Ok(reply.clone())
                } else {
                    Err(DomainError::TaskNotFound)
                }
            }
        }
    }

    pub async fn reply(
        &self,
        credentials: &RegistrationCredentials,
        task_id: &str,
        reply: ReplyPayload,
    ) -> Result<(), DomainError> {
        let mut state = self.inner.state.lock().await;
        let now = self.now_unix_ms();
        validate_registration_and_maintain(
            &mut state,
            self.inner.persistence.as_ref(),
            credentials,
            now,
        )
        .await?;
        let recipient_name = state
            .registrations
            .get(&credentials.id)
            .expect("validated registration must remain active")
            .registration
            .agent
            .name
            .clone();

        {
            let task = state
                .tasks
                .get_mut(task_id)
                .ok_or(DomainError::TaskNotFound)?;
            if task.recipient != recipient_name {
                return Err(DomainError::TaskNotOwned);
            }
            if task.canceled {
                return Err(DomainError::TaskCanceled);
            }
            if task.expired {
                return Err(DomainError::TaskExpired);
            }
            if task.failed || task.rejected {
                return Err(DomainError::TaskAlreadyCompleted);
            }
            if let Some(existing) = &task.reply {
                return if existing == &reply {
                    Ok(())
                } else {
                    Err(DomainError::ReplyAlreadySubmitted)
                };
            }
        }
        let durable = durable_terminal_task(
            task_id,
            state.tasks.get(task_id).expect("validated task must exist"),
            now,
            DurableTaskState::Replied,
            Some(reply.clone()),
        )?;
        commit_transition(
            &mut state,
            self.inner.persistence.as_ref(),
            single_task_batch(durable),
        )
        .await?;
        let reply_waiters = terminalize_task(
            &mut state,
            task_id,
            now,
            TerminalState::Replied(reply.clone()),
        )?;
        drop(state);
        for reply_waiter in reply_waiters {
            let _ = reply_waiter.send(Ok(reply.clone()));
        }
        Ok(())
    }

    pub async fn fail_task(
        &self,
        credentials: &RegistrationCredentials,
        task_id: &str,
        message: ReplyPayload,
    ) -> Result<(), DomainError> {
        self.recipient_terminal(
            credentials,
            task_id,
            message,
            RecipientTerminalState::Failed,
        )
        .await
    }

    pub async fn reject_task(
        &self,
        credentials: &RegistrationCredentials,
        task_id: &str,
        message: ReplyPayload,
    ) -> Result<(), DomainError> {
        self.recipient_terminal(
            credentials,
            task_id,
            message,
            RecipientTerminalState::Rejected,
        )
        .await
    }

    async fn recipient_terminal(
        &self,
        credentials: &RegistrationCredentials,
        task_id: &str,
        message: ReplyPayload,
        outcome: RecipientTerminalState,
    ) -> Result<(), DomainError> {
        let mut state = self.inner.state.lock().await;
        let now = self.now_unix_ms();
        validate_registration_and_maintain(
            &mut state,
            self.inner.persistence.as_ref(),
            credentials,
            now,
        )
        .await?;
        let recipient_name = state
            .registrations
            .get(&credentials.id)
            .expect("validated registration must remain active")
            .registration
            .agent
            .name
            .clone();
        {
            let task = state.tasks.get(task_id).ok_or(DomainError::TaskNotFound)?;
            if task.recipient != recipient_name {
                return Err(DomainError::TaskNotOwned);
            }
            let same_outcome = match outcome {
                RecipientTerminalState::Failed => task.failed,
                RecipientTerminalState::Rejected => task.rejected,
            };
            if same_outcome && task.reply.as_ref() == Some(&message) {
                return Ok(());
            }
            if task.canceled || task.expired || task.failed || task.rejected || task.reply.is_some()
            {
                return Err(DomainError::TaskAlreadyCompleted);
            }
        }
        let durable_state = match outcome {
            RecipientTerminalState::Failed => DurableTaskState::Failed,
            RecipientTerminalState::Rejected => DurableTaskState::Rejected,
        };
        let durable = durable_terminal_task(
            task_id,
            state.tasks.get(task_id).expect("validated task must exist"),
            now,
            durable_state,
            Some(message.clone()),
        )?;
        commit_transition(
            &mut state,
            self.inner.persistence.as_ref(),
            single_task_batch(durable),
        )
        .await?;
        let terminal_state = match outcome {
            RecipientTerminalState::Failed => TerminalState::Failed(message),
            RecipientTerminalState::Rejected => TerminalState::Rejected(message),
        };
        let waiters = terminalize_task(&mut state, task_id, now, terminal_state)?;
        drop(state);
        let error = match outcome {
            RecipientTerminalState::Failed => DomainError::TaskFailed,
            RecipientTerminalState::Rejected => DomainError::TaskRejected,
        };
        for waiter in waiters {
            let _ = waiter.send(Err(error.clone()));
        }
        Ok(())
    }

    pub async fn cancel_task(
        &self,
        sender_credentials: &RegistrationCredentials,
        task_id: &str,
    ) -> Result<(), DomainError> {
        let mut state = self.inner.state.lock().await;
        let now = self.now_unix_ms();
        validate_registration_and_maintain(
            &mut state,
            self.inner.persistence.as_ref(),
            sender_credentials,
            now,
        )
        .await?;
        let sender_name = state
            .registrations
            .get(&sender_credentials.id)
            .expect("validated registration must remain active")
            .registration
            .agent
            .name
            .clone();
        {
            let task = state
                .tasks
                .get_mut(task_id)
                .ok_or(DomainError::TaskNotFound)?;
            if task.sender != sender_name {
                return Err(DomainError::TaskNotOwned);
            }
            if task.canceled {
                return Ok(());
            }
            if task.expired {
                return Err(DomainError::TaskExpired);
            }
            if task.reply.is_some() {
                return Err(DomainError::TaskAlreadyCompleted);
            }
        }
        let durable = durable_terminal_task(
            task_id,
            state.tasks.get(task_id).expect("validated task must exist"),
            now,
            DurableTaskState::Canceled,
            None,
        )?;
        commit_transition(
            &mut state,
            self.inner.persistence.as_ref(),
            single_task_batch(durable),
        )
        .await?;
        let reply_waiters = terminalize_task(&mut state, task_id, now, TerminalState::Canceled)?;
        drop(state);
        for reply_waiter in reply_waiters {
            let _ = reply_waiter.send(Err(DomainError::TaskCanceled));
        }
        Ok(())
    }

    async fn poll_delivery(
        &self,
        credentials: &RegistrationCredentials,
    ) -> Result<DeliveryPoll, DomainError> {
        let mut state = self.inner.state.lock().await;
        let now = self.now_unix_ms();
        validate_registration_and_maintain(
            &mut state,
            self.inner.persistence.as_ref(),
            credentials,
            now,
        )
        .await?;
        let (task_ids, registration_expiry) = {
            let registration = state
                .registrations
                .get(&credentials.id)
                .expect("validated registration must remain active");
            (
                registration.inbox.iter().cloned().collect::<Vec<_>>(),
                registration.registration.expires_unix_ms,
            )
        };

        let mut next_deadline_unix_ms = registration_expiry;
        for task_id in task_ids {
            let (delivered, old_delivery_id, lease, durable) = {
                let Some(task) = state.tasks.get(&task_id) else {
                    continue;
                };
                if task.canceled || task.expired || task.reply.is_some() || task.acknowledged {
                    continue;
                }
                let Some(delivery) = task.delivery.as_ref() else {
                    continue;
                };
                let delivery_deadline_unix_ms = delivery
                    .created_unix_ms
                    .checked_add(DELIVERY_TTL_MS)
                    .ok_or(DomainError::PersistenceUnavailable)?;
                next_deadline_unix_ms = next_deadline_unix_ms.min(delivery_deadline_unix_ms);
                if let Some(lease) = &task.lease
                    && lease.leased_until_unix_ms > now
                {
                    next_deadline_unix_ms = next_deadline_unix_ms.min(lease.leased_until_unix_ms);
                    continue;
                }

                let attempt = match task.last_delivery_attempt {
                    Some(attempt) => attempt
                        .checked_add(1)
                        .ok_or(DomainError::PersistenceUnavailable)?,
                    None => delivery.attempt,
                };
                let old_delivery_id = task.lease.as_ref().map(|lease| lease.delivery_id.clone());
                let lease = DeliveryLease {
                    delivery_id: DeliveryId::new(),
                    owner: Some(credentials.clone()),
                    leased_until_unix_ms: now
                        .checked_add(DELIVERY_LEASE_MS)
                        .ok_or(DomainError::PersistenceUnavailable)?,
                    attempt,
                };
                let delivered = DeliveredMessage {
                    delivery_id: lease.delivery_id.clone(),
                    task_id: delivery.task_id.clone(),
                    context_id: delivery.context_id.clone(),
                    sender: delivery.sender.clone(),
                    recipient: delivery.recipient.clone(),
                    payload: delivery.payload.clone(),
                    leased_until_unix_ms: lease.leased_until_unix_ms,
                    attempt: lease.attempt,
                };
                let durable = durable_leased_task(&task_id, task, &lease)?;
                (delivered, old_delivery_id, lease, durable)
            };
            commit_transition(
                &mut state,
                self.inner.persistence.as_ref(),
                single_task_batch(durable),
            )
            .await?;
            let new_delivery_id = lease.delivery_id.clone();
            let task = state
                .tasks
                .get_mut(&task_id)
                .expect("selected task must remain present");
            task.state_version = task
                .state_version
                .checked_add(1)
                .ok_or(DomainError::PersistenceUnavailable)?;
            task.last_delivery_attempt = Some(lease.attempt);
            task.lease = Some(lease);
            #[cfg(test)]
            task.lease_applications.fetch_add(1, Ordering::SeqCst);
            if let Some(old_delivery_id) = old_delivery_id
                && state.tasks_by_delivery.get(&old_delivery_id) == Some(&task_id)
            {
                state.tasks_by_delivery.remove(&old_delivery_id);
            }
            state
                .tasks_by_delivery
                .insert(new_delivery_id, task_id.clone());
            return Ok(DeliveryPoll::Ready(Box::new(delivered)));
        }

        Ok(DeliveryPoll::Pending {
            next_deadline_unix_ms,
        })
    }

    pub fn now_unix_ms(&self) -> i64 {
        self.inner.clock.now_unix_ms()
    }
}

fn record_status_event(state: &mut State, kind: &str, canonical_name: &AgentName, unix_ms: i64) {
    state.last_event = Some(BrokerStatusEvent {
        kind: kind.to_owned(),
        canonical_name: canonical_name.clone(),
        unix_time: unix_ms.div_euclid(1_000),
    });
}

impl Default for BrokerState {
    fn default() -> Self {
        Self::new()
    }
}

fn active_registration_id(
    state: &State,
    agent_name: &AgentName,
    now: i64,
) -> Option<RegistrationId> {
    let registration_id = state.registrations_by_agent.get(agent_name)?;
    let registration = state.registrations.get(registration_id)?;
    (registration.registration.expires_unix_ms > now).then(|| registration_id.clone())
}

fn push_inbox(registration: &mut RegistrationState, task_id: String) {
    registration.inbox.push_back(task_id);
    #[cfg(test)]
    registration.inbox_pushes.fetch_add(1, Ordering::SeqCst);
}

fn validate_active_registration(
    state: &State,
    credentials: &RegistrationCredentials,
    now: i64,
) -> Result<(), DomainError> {
    let Some(registration) = state.registrations.get(&credentials.id) else {
        return if state.retired_registration_ids.contains(&credentials.id) {
            Err(DomainError::RegistrationExpired)
        } else {
            Err(DomainError::RegistrationNotFound)
        };
    };
    if registration.registration.epoch != credentials.epoch
        || registration.registration.expires_unix_ms <= now
        || state
            .registrations_by_agent
            .get(&registration.registration.agent.name)
            != Some(&credentials.id)
    {
        return Err(DomainError::RegistrationExpired);
    }
    Ok(())
}

async fn validate_registration_and_maintain(
    state: &mut State,
    persistence: &dyn BrokerPersistence,
    credentials: &RegistrationCredentials,
    now_unix_ms: i64,
) -> Result<(), DomainError> {
    let validation = validate_active_registration(state, credentials, now_unix_ms);
    maintain_state(state, persistence, now_unix_ms).await?;
    validation
}

#[derive(Clone, Copy)]
enum RecipientTerminalState {
    Failed,
    Rejected,
}

enum TerminalState {
    Replied(ReplyPayload),
    Failed(ReplyPayload),
    Rejected(ReplyPayload),
    Canceled,
    Expired,
}

fn terminalize_task(
    state: &mut State,
    task_id: &str,
    now_unix_ms: i64,
    terminal_state: TerminalState,
) -> Result<Vec<ReplyWaiter>, DomainError> {
    let terminal_deadline_unix_ms = now_unix_ms
        .checked_add(TERMINAL_RETENTION_MS)
        .ok_or(DomainError::PersistenceUnavailable)?;
    let (recipient, sender, delivery_id, reply_waiters) = {
        let task = state
            .tasks
            .get_mut(task_id)
            .expect("active task index must reference a task");
        if task.terminal_deadline_unix_ms.is_some() {
            return Ok(Vec::new());
        }

        let delivery_id = task.lease.as_ref().map(|lease| lease.delivery_id.clone());
        let reply_waiters = std::mem::take(&mut task.reply_waiters);
        task.state_version = task
            .state_version
            .checked_add(1)
            .expect("validated durable state version must advance");
        task.delivery = None;
        task.lease = None;
        task.acknowledged = false;
        task.acknowledged_unix_ms = None;
        task.reply = None;
        task.failed = false;
        task.rejected = false;
        task.canceled = false;
        task.expired = false;
        match terminal_state {
            TerminalState::Replied(reply) => task.reply = Some(reply),
            TerminalState::Failed(message) => {
                task.reply = Some(message);
                task.failed = true;
            }
            TerminalState::Rejected(message) => {
                task.reply = Some(message);
                task.rejected = true;
            }
            TerminalState::Canceled => task.canceled = true,
            TerminalState::Expired => task.expired = true,
        }
        task.terminal_unix_ms = Some(now_unix_ms);
        task.terminal_deadline_unix_ms = Some(terminal_deadline_unix_ms);
        (
            task.recipient.clone(),
            task.sender.clone(),
            delivery_id,
            reply_waiters,
        )
    };

    if let Some(delivery_id) = delivery_id
        && state
            .tasks_by_delivery
            .get(&delivery_id)
            .map(String::as_str)
            == Some(task_id)
    {
        state.tasks_by_delivery.remove(&delivery_id);
    }
    if let Some(recipient_registration_id) = state.registrations_by_agent.get(&recipient).cloned()
        && let Some(registration) = state.registrations.get_mut(&recipient_registration_id)
    {
        registration
            .inbox
            .retain(|queued_task_id| queued_task_id != task_id);
    }
    for agent_name in [&recipient, &sender] {
        if let Some(active_tasks) = state.active_tasks_by_agent.get_mut(agent_name) {
            active_tasks.remove(task_id);
            if active_tasks.is_empty() {
                state.active_tasks_by_agent.remove(agent_name);
            }
        }
    }
    if let Some(outbound_tasks) = state.outbound_tasks_by_agent.get_mut(&sender) {
        outbound_tasks.remove(task_id);
        if outbound_tasks.is_empty() {
            state.outbound_tasks_by_agent.remove(&sender);
        }
    }
    if let Some(tasks) = state.tasks_by_sender.get_mut(&sender) {
        tasks.remove(task_id);
        if tasks.is_empty() {
            state.tasks_by_sender.remove(&sender);
        }
    }
    if let Some(tasks) = state.tasks_by_recipient.get_mut(&recipient) {
        tasks.remove(task_id);
        if tasks.is_empty() {
            state.tasks_by_recipient.remove(&recipient);
        }
    }
    state
        .terminal_deadlines
        .push(Reverse((terminal_deadline_unix_ms, task_id.to_owned())));
    Ok(reply_waiters)
}

fn detach_registration(
    state: &mut State,
    registration_id: &RegistrationId,
    retire: bool,
) -> Option<RegistrationState> {
    let registration = state.registrations.remove(registration_id)?;
    if state
        .registrations_by_agent
        .get(&registration.registration.agent.name)
        == Some(registration_id)
    {
        state
            .registrations_by_agent
            .remove(&registration.registration.agent.name);
    }
    if retire {
        retire_registration_id(state, registration_id.clone());
    }
    let credentials = registration.registration.credentials();
    let leased_task_ids = state
        .tasks
        .iter()
        .filter(|(_, task)| {
            !task.acknowledged
                && task
                    .lease
                    .as_ref()
                    .is_some_and(|lease| lease.owner.as_ref() == Some(&credentials))
        })
        .map(|(task_id, _)| task_id.clone())
        .collect::<Vec<_>>();
    for task_id in leased_task_ids {
        let delivery_id = state
            .tasks
            .get_mut(&task_id)
            .and_then(|task| task.lease.take())
            .map(|lease| lease.delivery_id);
        if let Some(delivery_id) = delivery_id
            && state.tasks_by_delivery.get(&delivery_id) == Some(&task_id)
        {
            state.tasks_by_delivery.remove(&delivery_id);
        }
    }
    Some(registration)
}

fn retire_registration_id(state: &mut State, registration_id: RegistrationId) {
    if state
        .retired_registration_ids
        .insert(registration_id.clone())
    {
        state.retired_registration_order.push_back(registration_id);
    }
    while state.retired_registration_order.len() > MAX_RETIRED_REGISTRATION_IDS {
        if let Some(expired_id) = state.retired_registration_order.pop_front() {
            state.retired_registration_ids.remove(&expired_id);
        }
    }
}

fn prune_terminal_tasks(state: &mut State, now_unix_ms: i64) {
    while let Some(Reverse((deadline_unix_ms, _))) = state.terminal_deadlines.peek()
        && *deadline_unix_ms <= now_unix_ms
    {
        let Reverse((deadline_unix_ms, task_id)) = state
            .terminal_deadlines
            .pop()
            .expect("peeked deadline must be present");
        let task_is_due = state
            .tasks
            .get(&task_id)
            .is_some_and(|task| task.terminal_deadline_unix_ms == Some(deadline_unix_ms));
        if task_is_due {
            state.tasks.remove(&task_id);
        }
    }
}

fn prune_delivery_deadlines(state: &mut State, now_unix_ms: i64) {
    while let Some(Reverse((deadline_unix_ms, _))) = state.delivery_deadlines.peek()
        && *deadline_unix_ms <= now_unix_ms
    {
        state.delivery_deadlines.pop();
    }
}

fn resolve_reply_waiters(reply_resolutions: Vec<ReplyResolution>) {
    for (reply_waiter, result) in reply_resolutions {
        let _ = reply_waiter.send(result);
    }
}

async fn commit_transition(
    state: &mut State,
    persistence: &dyn BrokerPersistence,
    batch: PersistenceBatch,
) -> Result<(), DomainError> {
    match persistence.commit(batch).await? {
        PersistenceCommitOutcome::Complete => Ok(()),
        PersistenceCommitOutcome::ReconciliationRequired => {
            state.reconciliation_required = true;
            Err(DomainError::PersistenceUnavailable)
        }
    }
}

fn reply_result_for_task(task: &TaskRecord) -> Option<ReplyResult> {
    if task.canceled {
        Some(Err(DomainError::TaskCanceled))
    } else if task.expired {
        Some(Err(DomainError::TaskExpired))
    } else if task.failed {
        Some(Err(DomainError::TaskFailed))
    } else if task.rejected {
        Some(Err(DomainError::TaskRejected))
    } else {
        task.reply.clone().map(Ok)
    }
}

async fn reconcile_state_if_required(
    state: &mut State,
    persistence: &dyn BrokerPersistence,
    now_unix_ms: i64,
) -> Result<(), DomainError> {
    if !state.reconciliation_required {
        return Ok(());
    }

    let repair = persistence
        .commit(PersistenceBatch {
            registration_epoch_high_watermark: None,
            upsert_tasks: Vec::new(),
            delete_task_ids: Vec::new(),
        })
        .await?;
    if repair == PersistenceCommitOutcome::ReconciliationRequired {
        return Err(DomainError::PersistenceUnavailable);
    }

    let DurableBrokerSnapshot {
        last_registration_epoch,
        tasks,
    } = persistence.load(now_unix_ms).await?;
    if last_registration_epoch.get() == u64::MAX {
        return Err(DomainError::PersistenceUnavailable);
    }
    let mut report = BrokerRecoveryReport::default();
    let (mut tasks, recovery_batch) =
        validate_and_reconcile_snapshot(tasks, now_unix_ms, &mut report)?;
    if !recovery_batch.is_empty()
        && persistence.commit(recovery_batch).await?
            == PersistenceCommitOutcome::ReconciliationRequired
    {
        return Err(DomainError::PersistenceUnavailable);
    }
    tasks.retain(|task| {
        task.retention_deadline_unix_ms
            .is_none_or(|deadline| deadline > now_unix_ms)
    });
    tasks.sort_by(|left, right| {
        left.created_unix_ms
            .cmp(&right.created_unix_ms)
            .then_with(|| left.task_id.cmp(&right.task_id))
    });

    let mut retained_waiters = state
        .tasks
        .iter_mut()
        .map(|(task_id, task)| (task_id.clone(), std::mem::take(&mut task.reply_waiters)))
        .filter(|(_, waiters)| !waiters.is_empty())
        .collect::<HashMap<_, _>>();
    state.next_registration_epoch = state
        .next_registration_epoch
        .max(last_registration_epoch.get());
    state.next_task_sequence = 0;
    state.active_tasks_by_agent.clear();
    state.outbound_tasks_by_agent.clear();
    state.tasks_by_sender.clear();
    state.tasks_by_recipient.clear();
    state.tasks.clear();
    state.tasks_by_delivery.clear();
    state.delivery_deadlines.clear();
    state.terminal_deadlines.clear();
    for registration in state.registrations.values_mut() {
        registration.inbox.clear();
    }

    for task in tasks {
        state.next_task_sequence = state
            .next_task_sequence
            .checked_add(1)
            .ok_or(DomainError::PersistenceUnavailable)?;
        restore_task(state, task)?;
    }

    let active_credentials = state
        .registrations_by_agent
        .iter()
        .filter_map(|(agent_name, registration_id)| {
            state
                .registrations
                .get(registration_id)
                .filter(|registration| registration.registration.expires_unix_ms > now_unix_ms)
                .map(|registration| (agent_name.clone(), registration.registration.credentials()))
        })
        .collect::<HashMap<_, _>>();
    for task in state.tasks.values_mut() {
        if let Some(lease) = &mut task.lease {
            lease.owner = active_credentials.get(&task.recipient).cloned();
        }
    }

    let mut reply_resolutions = Vec::new();
    for (task_id, waiters) in retained_waiters.drain() {
        match state.tasks.get_mut(&task_id) {
            Some(task) => match reply_result_for_task(task) {
                Some(result) => reply_resolutions
                    .extend(waiters.into_iter().map(|waiter| (waiter, result.clone()))),
                None => task.reply_waiters.extend(waiters),
            },
            None => reply_resolutions.extend(
                waiters
                    .into_iter()
                    .map(|waiter| (waiter, Err(DomainError::TaskNotFound))),
            ),
        }
    }

    let mut inbox_entries = Vec::new();
    for (task_id, task) in &state.tasks {
        if task.delivery.is_some()
            && !task.acknowledged
            && !task.canceled
            && !task.expired
            && task.reply.is_none()
            && task.lease.is_none()
            && let Some(registration_id) = state.registrations_by_agent.get(&task.recipient)
            && state
                .registrations
                .get(registration_id)
                .is_some_and(|registration| registration.registration.expires_unix_ms > now_unix_ms)
        {
            inbox_entries.push((
                registration_id.clone(),
                task.enqueue_sequence,
                task_id.clone(),
            ));
        }
    }
    inbox_entries.sort_by(|left, right| {
        left.0
            .as_str()
            .cmp(right.0.as_str())
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(&right.2))
    });
    let mut notify = Vec::new();
    for (registration_id, _, task_id) in inbox_entries {
        if let Some(registration) = state.registrations.get_mut(&registration_id) {
            push_inbox(registration, task_id);
            notify.push(registration.notify.clone());
        }
    }
    state.reconciliation_required = false;
    resolve_reply_waiters(reply_resolutions);
    for registration in notify {
        registration.notify_one();
    }
    Ok(())
}

async fn maintain_state(
    state: &mut State,
    persistence: &dyn BrokerPersistence,
    now_unix_ms: i64,
) -> Result<(), DomainError> {
    reconcile_state_if_required(state, persistence, now_unix_ms).await?;
    let mut due_task_ids = Vec::new();
    for (task_id, task) in &state.tasks {
        if task.terminal_deadline_unix_ms.is_none()
            && let Some(delivery) = &task.delivery
        {
            let deadline = delivery
                .created_unix_ms
                .checked_add(DELIVERY_TTL_MS)
                .ok_or(DomainError::PersistenceUnavailable)?;
            if deadline <= now_unix_ms {
                due_task_ids.push(task_id.clone());
            }
        }
    }
    let expired_registration_ids = state
        .registrations
        .iter()
        .filter(|(_, registration)| registration.registration.expires_unix_ms <= now_unix_ms)
        .map(|(registration_id, _)| registration_id.clone())
        .collect::<Vec<_>>();

    let expired_credentials = expired_registration_ids
        .iter()
        .filter_map(|id| state.registrations.get(id))
        .map(|entry| entry.registration.credentials())
        .collect::<HashSet<_>>();
    let mut upserts = Vec::new();
    for task_id in &due_task_ids {
        let task = state.tasks.get(task_id).expect("selected task must exist");
        upserts.push(durable_terminal_task(
            task_id,
            task,
            now_unix_ms,
            DurableTaskState::Expired,
            None,
        )?);
    }
    for (task_id, task) in &state.tasks {
        if !due_task_ids.contains(task_id)
            && !task.acknowledged
            && task.lease.as_ref().is_some_and(|lease| {
                lease
                    .owner
                    .as_ref()
                    .is_some_and(|owner| expired_credentials.contains(owner))
            })
        {
            upserts.push(durable_requeued_task(task_id, task)?);
        }
    }
    let delete_task_ids = state
        .tasks
        .iter()
        .filter(|(_, task)| {
            task.terminal_deadline_unix_ms
                .is_some_and(|deadline| deadline <= now_unix_ms)
        })
        .map(|(task_id, _)| task_id.clone())
        .collect::<Vec<_>>();
    let batch = PersistenceBatch {
        registration_epoch_high_watermark: None,
        upsert_tasks: upserts,
        delete_task_ids,
    };
    if !batch.is_empty() {
        commit_transition(state, persistence, batch).await?;
    }

    let mut reply_resolutions = Vec::new();
    for task_id in due_task_ids {
        for reply_waiter in terminalize_task(state, &task_id, now_unix_ms, TerminalState::Expired)?
        {
            reply_resolutions.push((reply_waiter, Err(DomainError::TaskExpired)));
        }
    }
    for credentials in &expired_credentials {
        bump_requeued_versions_for_credentials(state, credentials);
    }
    for registration_id in expired_registration_ids {
        let registration = detach_registration(state, &registration_id, true);
        if let Some(registration) = registration {
            registration.notify.notify_one();
        }
    }
    if !expired_credentials.is_empty() {
        state.directory.record();
    }
    prune_delivery_deadlines(state, now_unix_ms);
    prune_terminal_tasks(state, now_unix_ms);
    resolve_reply_waiters(reply_resolutions);
    Ok(())
}

fn single_task_batch(task: DurableTask) -> PersistenceBatch {
    PersistenceBatch {
        registration_epoch_high_watermark: None,
        upsert_tasks: vec![task],
        delete_task_ids: Vec::new(),
    }
}

fn next_state_version(task: &TaskRecord) -> Result<u64, DomainError> {
    task.state_version
        .checked_add(1)
        .ok_or(DomainError::PersistenceUnavailable)
}

fn durable_task(task_id: &str, task: &TaskRecord) -> Result<DurableTask, DomainError> {
    let state = if task.failed {
        DurableTaskState::Failed
    } else if task.rejected {
        DurableTaskState::Rejected
    } else if task.reply.is_some() {
        DurableTaskState::Replied
    } else if task.canceled {
        DurableTaskState::Canceled
    } else if task.expired {
        DurableTaskState::Expired
    } else if task.acknowledged {
        DurableTaskState::Acknowledged
    } else if task.lease.is_some() {
        DurableTaskState::Leased
    } else {
        DurableTaskState::Queued
    };
    let lease = task.lease.as_ref().map(|lease| DurableLease {
        delivery_id: lease.delivery_id.clone(),
        owner: task.recipient.clone(),
        leased_until_unix_ms: lease.leased_until_unix_ms,
        attempt: lease.attempt,
    });
    Ok(DurableTask {
        task_id: task_id.to_owned(),
        context_id: task.original_delivery.context_id.clone(),
        sender: task.sender.clone(),
        recipient: task.recipient.clone(),
        payload: task.original_delivery.payload.clone(),
        created_unix_ms: task.original_delivery.created_unix_ms,
        delivery_deadline_unix_ms: task
            .original_delivery
            .created_unix_ms
            .checked_add(DELIVERY_TTL_MS)
            .ok_or(DomainError::PersistenceUnavailable)?,
        state_version: task.state_version,
        state,
        lease,
        attempt: task
            .last_delivery_attempt
            .unwrap_or(task.original_delivery.attempt),
        acknowledged_unix_ms: task.acknowledged_unix_ms,
        reply: task.reply.clone(),
        terminal_unix_ms: task.terminal_unix_ms,
        retention_deadline_unix_ms: task.terminal_deadline_unix_ms,
    })
}

fn durable_requeued_task(task_id: &str, task: &TaskRecord) -> Result<DurableTask, DomainError> {
    let mut durable = durable_task(task_id, task)?;
    durable.state_version = next_state_version(task)?;
    durable.state = DurableTaskState::Queued;
    durable.lease = None;
    durable.acknowledged_unix_ms = None;
    Ok(durable)
}

fn durable_leased_task(
    task_id: &str,
    task: &TaskRecord,
    lease: &DeliveryLease,
) -> Result<DurableTask, DomainError> {
    let mut durable = durable_task(task_id, task)?;
    durable.state_version = next_state_version(task)?;
    durable.state = DurableTaskState::Leased;
    durable.lease = Some(DurableLease {
        delivery_id: lease.delivery_id.clone(),
        owner: task.recipient.clone(),
        leased_until_unix_ms: lease.leased_until_unix_ms,
        attempt: lease.attempt,
    });
    durable.attempt = lease.attempt;
    durable.acknowledged_unix_ms = None;
    Ok(durable)
}

fn durable_acknowledged_task(
    task_id: &str,
    task: &TaskRecord,
    now_unix_ms: i64,
) -> Result<DurableTask, DomainError> {
    let mut durable = durable_task(task_id, task)?;
    durable.state_version = next_state_version(task)?;
    durable.state = DurableTaskState::Acknowledged;
    durable.acknowledged_unix_ms = Some(now_unix_ms);
    Ok(durable)
}

fn durable_terminal_task(
    task_id: &str,
    task: &TaskRecord,
    now_unix_ms: i64,
    state: DurableTaskState,
    reply: Option<ReplyPayload>,
) -> Result<DurableTask, DomainError> {
    let mut durable = durable_task(task_id, task)?;
    durable.state_version = next_state_version(task)?;
    durable.state = state;
    durable.lease = None;
    durable.acknowledged_unix_ms = None;
    durable.reply = reply;
    durable.terminal_unix_ms = Some(now_unix_ms);
    durable.retention_deadline_unix_ms = Some(
        now_unix_ms
            .checked_add(TERMINAL_RETENTION_MS)
            .ok_or(DomainError::PersistenceUnavailable)?,
    );
    Ok(durable)
}

fn bump_requeued_versions_for_credentials(
    state: &mut State,
    credentials: &RegistrationCredentials,
) {
    for task in state.tasks.values_mut() {
        if !task.acknowledged
            && task
                .lease
                .as_ref()
                .is_some_and(|lease| lease.owner.as_ref() == Some(credentials))
        {
            task.state_version = task
                .state_version
                .checked_add(1)
                .expect("persisted requeue version must have advanced");
        }
    }
}

fn validate_and_reconcile_snapshot(
    tasks: Vec<DurableTask>,
    now_unix_ms: i64,
    report: &mut BrokerRecoveryReport,
) -> Result<(Vec<DurableTask>, PersistenceBatch), DomainError> {
    if tasks.len() > MAX_RETAINED_TASKS {
        return Err(DomainError::PersistenceUnavailable);
    }
    let mut task_ids = HashSet::new();
    let mut delivery_ids = HashSet::new();
    let mut restored = Vec::with_capacity(tasks.len());
    let mut upsert_tasks = Vec::new();
    let mut delete_task_ids = Vec::new();
    for mut task in tasks {
        validate_durable_task(&task)?;
        if !task_ids.insert(task.task_id.clone()) {
            return Err(DomainError::PersistenceUnavailable);
        }
        if let Some(lease) = &task.lease
            && !delivery_ids.insert(lease.delivery_id.clone())
        {
            return Err(DomainError::PersistenceUnavailable);
        }
        if task
            .retention_deadline_unix_ms
            .is_some_and(|deadline| deadline <= now_unix_ms)
        {
            delete_task_ids.push(task.task_id.clone());
            report.pruned += 1;
            continue;
        }
        let nonterminal = matches!(
            task.state,
            DurableTaskState::Queued | DurableTaskState::Leased | DurableTaskState::Acknowledged
        );
        if nonterminal && task.delivery_deadline_unix_ms <= now_unix_ms {
            let retention_deadline_unix_ms = now_unix_ms
                .checked_add(TERMINAL_RETENTION_MS)
                .ok_or(DomainError::PersistenceUnavailable)?;
            task.state_version = task
                .state_version
                .checked_add(1)
                .ok_or(DomainError::PersistenceUnavailable)?;
            task.state = DurableTaskState::Expired;
            task.lease = None;
            task.acknowledged_unix_ms = None;
            task.reply = None;
            task.terminal_unix_ms = Some(now_unix_ms);
            task.retention_deadline_unix_ms = Some(retention_deadline_unix_ms);
            upsert_tasks.push(task.clone());
            report.expired += 1;
        } else if task.state == DurableTaskState::Leased {
            task.state_version = task
                .state_version
                .checked_add(1)
                .ok_or(DomainError::PersistenceUnavailable)?;
            task.state = DurableTaskState::Queued;
            task.lease = None;
            upsert_tasks.push(task.clone());
            report.requeued += 1;
        }
        restored.push(task);
    }
    Ok((
        restored,
        PersistenceBatch {
            registration_epoch_high_watermark: None,
            upsert_tasks,
            delete_task_ids,
        },
    ))
}

fn validate_durable_task(task: &DurableTask) -> Result<(), DomainError> {
    validate_task_id(&task.task_id).map_err(|_| DomainError::PersistenceUnavailable)?;
    validate_task_id(&task.context_id).map_err(|_| DomainError::PersistenceUnavailable)?;
    AgentName::parse(task.sender.as_str()).map_err(|_| DomainError::PersistenceUnavailable)?;
    AgentName::parse(task.recipient.as_str()).map_err(|_| DomainError::PersistenceUnavailable)?;
    crate::validation::validate_persisted_payload(&task.payload)
        .map_err(|_| DomainError::PersistenceUnavailable)?;
    if let Some(reply) = &task.reply {
        crate::validation::validate_persisted_payload(&crate::ValidatedPayload {
            text: reply.text.clone(),
            metadata: reply.metadata.clone(),
            file_refs: reply.file_refs.clone(),
        })
        .map_err(|_| DomainError::PersistenceUnavailable)?;
    }
    let delivery_deadline_unix_ms = task
        .created_unix_ms
        .checked_add(DELIVERY_TTL_MS)
        .ok_or(DomainError::PersistenceUnavailable)?;
    if task.created_unix_ms < 0
        || task.delivery_deadline_unix_ms != delivery_deadline_unix_ms
        || task.state_version == 0
    {
        return Err(DomainError::PersistenceUnavailable);
    }
    if let Some(lease) = &task.lease
        && (lease.owner != task.recipient
            || lease.attempt != task.attempt
            || lease.leased_until_unix_ms < task.created_unix_ms)
    {
        return Err(DomainError::PersistenceUnavailable);
    }
    if task
        .acknowledged_unix_ms
        .is_some_and(|ack| ack < task.created_unix_ms || ack > task.delivery_deadline_unix_ms)
    {
        return Err(DomainError::PersistenceUnavailable);
    }
    let terminal_times_valid = match (task.terminal_unix_ms, task.retention_deadline_unix_ms) {
        (None, None) => true,
        (Some(terminal), Some(retention)) => {
            terminal >= task.created_unix_ms
                && terminal
                    .checked_add(TERMINAL_RETENTION_MS)
                    .is_some_and(|deadline| retention == deadline)
        }
        _ => false,
    };
    if !terminal_times_valid {
        return Err(DomainError::PersistenceUnavailable);
    }
    let valid_state = match task.state {
        DurableTaskState::Queued => {
            task.lease.is_none()
                && task.acknowledged_unix_ms.is_none()
                && task.reply.is_none()
                && task.terminal_unix_ms.is_none()
        }
        DurableTaskState::Leased => {
            task.lease.is_some()
                && task.acknowledged_unix_ms.is_none()
                && task.reply.is_none()
                && task.terminal_unix_ms.is_none()
        }
        DurableTaskState::Acknowledged => {
            task.lease.is_some()
                && task.acknowledged_unix_ms.is_some()
                && task.reply.is_none()
                && task.terminal_unix_ms.is_none()
        }
        DurableTaskState::Replied | DurableTaskState::Failed | DurableTaskState::Rejected => {
            task.lease.is_none()
                && task.acknowledged_unix_ms.is_none()
                && task.reply.is_some()
                && task.terminal_unix_ms.is_some()
        }
        DurableTaskState::Canceled | DurableTaskState::Expired => {
            task.lease.is_none()
                && task.acknowledged_unix_ms.is_none()
                && task.reply.is_none()
                && task.terminal_unix_ms.is_some()
        }
    };
    valid_state
        .then_some(())
        .ok_or(DomainError::PersistenceUnavailable)
}

fn restore_task(state: &mut State, task: DurableTask) -> Result<(), DomainError> {
    let task_id = task.task_id.clone();
    let terminal = matches!(
        task.state,
        DurableTaskState::Replied
            | DurableTaskState::Failed
            | DurableTaskState::Rejected
            | DurableTaskState::Canceled
            | DurableTaskState::Expired
    );
    let acknowledged = task.state == DurableTaskState::Acknowledged;
    let original_delivery = QueuedDelivery {
        task_id: task.task_id.clone(),
        context_id: task.context_id.clone(),
        sender: task.sender.clone(),
        recipient: task.recipient.clone(),
        payload: task.payload.clone(),
        created_unix_ms: task.created_unix_ms,
        attempt: task.attempt,
    };
    let restored_lease = task.lease.as_ref().map(|lease| DeliveryLease {
        delivery_id: lease.delivery_id.clone(),
        owner: None,
        leased_until_unix_ms: lease.leased_until_unix_ms,
        attempt: lease.attempt,
    });
    let restored_delivery_id = restored_lease
        .as_ref()
        .map(|lease| lease.delivery_id.clone());
    let record = TaskRecord {
        enqueue_sequence: state.next_task_sequence,
        state_version: task.state_version,
        original_delivery: original_delivery.clone(),
        delivery: (!terminal).then_some(original_delivery),
        recipient: task.recipient.clone(),
        sender: task.sender.clone(),
        lease: restored_lease,
        last_delivery_attempt: (task.state_version > 1).then_some(task.attempt),
        acknowledged,
        acknowledged_unix_ms: task.acknowledged_unix_ms,
        reply: task.reply,
        reply_waiters: Vec::new(),
        failed: task.state == DurableTaskState::Failed,
        rejected: task.state == DurableTaskState::Rejected,
        canceled: task.state == DurableTaskState::Canceled,
        expired: task.state == DurableTaskState::Expired,
        terminal_unix_ms: task.terminal_unix_ms,
        terminal_deadline_unix_ms: task.retention_deadline_unix_ms,
        #[cfg(test)]
        lease_applications: Arc::new(AtomicUsize::new(0)),
        #[cfg(test)]
        ack_applications: Arc::new(AtomicUsize::new(0)),
    };
    if terminal {
        state.terminal_deadlines.push(Reverse((
            record
                .terminal_deadline_unix_ms
                .ok_or(DomainError::PersistenceUnavailable)?,
            task_id.clone(),
        )));
    } else {
        if let Some(delivery_id) = restored_delivery_id {
            state.tasks_by_delivery.insert(delivery_id, task_id.clone());
        }
        state
            .delivery_deadlines
            .push(Reverse((task.delivery_deadline_unix_ms, task_id.clone())));
        for agent in [&record.sender, &record.recipient] {
            state
                .active_tasks_by_agent
                .entry(agent.clone())
                .or_default()
                .insert(task_id.clone());
        }
        state
            .outbound_tasks_by_agent
            .entry(record.sender.clone())
            .or_default()
            .insert(task_id.clone());
        state
            .tasks_by_sender
            .entry(record.sender.clone())
            .or_default()
            .insert(task_id.clone());
        state
            .tasks_by_recipient
            .entry(record.recipient.clone())
            .or_default()
            .insert(task_id.clone());
    }
    state.tasks.insert(task_id, record);
    Ok(())
}

fn duration_until(now_unix_ms: i64, deadline_unix_ms: i64) -> Duration {
    let millis = i128::from(deadline_unix_ms) - i128::from(now_unix_ms);
    Duration::from_millis(u64::try_from(millis.max(0)).expect("i64 difference fits in u64"))
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::{
            Arc, Condvar, Mutex as StdMutex,
            atomic::{AtomicBool, AtomicI64, Ordering},
        },
        time::Duration,
    };

    use serde_json::json;
    use tokio::sync::Semaphore;

    use super::*;
    use crate::{
        AgentName, DomainError, QueuedDelivery, ReplyPayload, ValidatedPayload, VerifiedAgent,
    };

    #[derive(Clone)]
    struct RecordingPersistence {
        snapshot: Arc<StdMutex<DurableBrokerSnapshot>>,
        gate: Arc<StdMutex<Option<Arc<Semaphore>>>>,
        entered: Arc<Notify>,
        fail_next: Arc<AtomicBool>,
    }

    impl RecordingPersistence {
        fn new() -> Self {
            Self {
                snapshot: Arc::new(StdMutex::new(DurableBrokerSnapshot {
                    last_registration_epoch: RegistrationEpoch::from_u64(0),
                    tasks: Vec::new(),
                })),
                gate: Arc::new(StdMutex::new(None)),
                entered: Arc::new(Notify::new()),
                fail_next: Arc::new(AtomicBool::new(false)),
            }
        }

        fn block_next_commit(&self) {
            *self.gate.lock().unwrap() = Some(Arc::new(Semaphore::new(0)));
        }

        async fn wait_until_commit_blocked(&self) {
            self.entered.notified().await;
        }

        fn release_commit(&self) {
            if let Some(gate) = self.gate.lock().unwrap().take() {
                gate.add_permits(1);
            }
        }

        fn fail_next_commit(&self) {
            self.fail_next.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait::async_trait]
    impl BrokerPersistence for RecordingPersistence {
        async fn load(&self, _now_unix_ms: i64) -> Result<DurableBrokerSnapshot, DomainError> {
            Ok(self.snapshot.lock().unwrap().clone())
        }

        async fn commit(
            &self,
            batch: PersistenceBatch,
        ) -> Result<PersistenceCommitOutcome, DomainError> {
            let gate = self.gate.lock().unwrap().clone();
            if let Some(gate) = gate {
                self.entered.notify_one();
                gate.acquire_owned()
                    .await
                    .map_err(|_| DomainError::PersistenceUnavailable)?
                    .forget();
            }
            if self.fail_next.swap(false, Ordering::SeqCst) {
                return Err(DomainError::PersistenceUnavailable);
            }
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

    async fn broker_with_persistence(
        persistence: RecordingPersistence,
    ) -> (BrokerState, Registration, Registration) {
        let (broker, _) = BrokerState::recover(TestClock::at(1_000), persistence)
            .await
            .unwrap();
        let sender = register_sender(&broker).await;
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        (broker, sender, recipient)
    }

    #[tokio::test]
    async fn enqueue_commit_precedes_inbox_wakeup() {
        let persistence = RecordingPersistence::new();
        let (broker, sender, recipient) = broker_with_persistence(persistence.clone()).await;
        let inbox_pushes = broker.inner.state.lock().await.registrations[&recipient.id]
            .inbox_pushes
            .clone();
        let waiter = tokio::spawn({
            let broker = broker.clone();
            let credentials = recipient.credentials();
            async move { broker.wait_next(&credentials, None).await }
        });
        tokio::task::yield_now().await;
        persistence.block_next_commit();
        let enqueue = tokio::spawn({
            let broker = broker.clone();
            let credentials = sender.credentials();
            async move {
                broker
                    .enqueue(
                        &credentials,
                        delivery("implementer", "reviewer", "ordered-enqueue"),
                    )
                    .await
            }
        });
        persistence.wait_until_commit_blocked().await;
        assert!(!enqueue.is_finished());
        assert!(!waiter.is_finished());
        assert_eq!(inbox_pushes.load(Ordering::SeqCst), 0);
        assert!(broker.inner.state.try_lock().is_err());
        persistence.release_commit();
        enqueue.await.unwrap().unwrap();
        assert_eq!(inbox_pushes.load(Ordering::SeqCst), 1);
        assert_eq!(
            waiter.await.unwrap().unwrap().task_id,
            "task-ordered-enqueue"
        );
    }

    #[tokio::test]
    async fn lease_commit_precedes_delivery_return() {
        let persistence = RecordingPersistence::new();
        let (broker, sender, recipient) = broker_with_persistence(persistence.clone()).await;
        broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "ordered-lease"),
            )
            .await
            .unwrap();
        let lease_applications = broker.inner.state.lock().await.tasks["task-ordered-lease"]
            .lease_applications
            .clone();
        persistence.block_next_commit();
        let lease = tokio::spawn({
            let broker = broker.clone();
            let credentials = recipient.credentials();
            async move { broker.wait_next(&credentials, None).await }
        });
        persistence.wait_until_commit_blocked().await;
        assert!(!lease.is_finished());
        assert_eq!(lease_applications.load(Ordering::SeqCst), 0);
        assert!(broker.inner.state.try_lock().is_err());
        persistence.release_commit();
        assert_eq!(lease.await.unwrap().unwrap().task_id, "task-ordered-lease");
        assert_eq!(lease_applications.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn ack_commit_precedes_success() {
        let persistence = RecordingPersistence::new();
        let (broker, sender, recipient) = broker_with_persistence(persistence.clone()).await;
        broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "ordered-ack"),
            )
            .await
            .unwrap();
        let delivered = broker
            .wait_next(&recipient.credentials(), None)
            .await
            .unwrap();
        let ack_applications = broker.inner.state.lock().await.tasks["task-ordered-ack"]
            .ack_applications
            .clone();
        persistence.block_next_commit();
        let ack = tokio::spawn({
            let broker = broker.clone();
            let credentials = recipient.credentials();
            async move {
                broker
                    .ack_delivery(&credentials, &delivered.delivery_id)
                    .await
            }
        });
        persistence.wait_until_commit_blocked().await;
        assert!(!ack.is_finished());
        assert_eq!(ack_applications.load(Ordering::SeqCst), 0);
        assert!(broker.inner.state.try_lock().is_err());
        persistence.release_commit();
        ack.await.unwrap().unwrap();
        assert_eq!(ack_applications.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn terminal_commit_precedes_waiter_resolution() {
        let persistence = RecordingPersistence::new();
        let (broker, sender, recipient) = broker_with_persistence(persistence.clone()).await;
        let handle = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "ordered-terminal"),
            )
            .await
            .unwrap();
        let waiter = tokio::spawn({
            let broker = broker.clone();
            let credentials = sender.credentials();
            let task_id = handle.task_id.clone();
            async move { broker.wait_for_reply(&credentials, &task_id).await }
        });
        tokio::task::yield_now().await;
        persistence.block_next_commit();
        let reply_task = tokio::spawn({
            let broker = broker.clone();
            let credentials = recipient.credentials();
            let task_id = handle.task_id.clone();
            async move { broker.reply(&credentials, &task_id, reply("done")).await }
        });
        persistence.wait_until_commit_blocked().await;
        assert!(!reply_task.is_finished());
        assert!(!waiter.is_finished());
        assert!(broker.inner.state.try_lock().is_err());
        persistence.release_commit();
        reply_task.await.unwrap().unwrap();
        assert_eq!(waiter.await.unwrap().unwrap().text, "done");
    }

    #[tokio::test]
    async fn persistence_failure_leaves_scheduler_state_unchanged() {
        let persistence = RecordingPersistence::new();
        let (broker, sender, recipient) = broker_with_persistence(persistence.clone()).await;
        let before = {
            let state = broker.inner.state.lock().await;
            (
                state.tasks.len(),
                state.active_tasks_by_agent.len(),
                state.outbound_tasks_by_agent.len(),
                state.tasks_by_sender.len(),
                state.tasks_by_recipient.len(),
                state.delivery_deadlines.len(),
                state.registrations[&recipient.id].inbox.len(),
            )
        };
        persistence.fail_next_commit();
        assert_eq!(
            broker
                .enqueue(
                    &sender.credentials(),
                    delivery("implementer", "reviewer", "failed-enqueue"),
                )
                .await
                .unwrap_err(),
            DomainError::PersistenceUnavailable
        );
        let after = {
            let state = broker.inner.state.lock().await;
            (
                state.tasks.len(),
                state.active_tasks_by_agent.len(),
                state.outbound_tasks_by_agent.len(),
                state.tasks_by_sender.len(),
                state.tasks_by_recipient.len(),
                state.delivery_deadlines.len(),
                state.registrations[&recipient.id].inbox.len(),
            )
        };
        assert_eq!(after, before);

        let handle = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "failed-terminal"),
            )
            .await
            .unwrap();
        let delivered = broker
            .wait_next(&recipient.credentials(), None)
            .await
            .unwrap();
        let delivery_indexes_before = {
            let state = broker.inner.state.lock().await;
            (
                state.tasks_by_delivery.len(),
                state.registrations[&recipient.id].inbox.len(),
            )
        };
        persistence.fail_next_commit();
        assert_eq!(
            broker
                .ack_delivery(&recipient.credentials(), &delivered.delivery_id)
                .await
                .unwrap_err(),
            DomainError::PersistenceUnavailable
        );
        {
            let state = broker.inner.state.lock().await;
            assert_eq!(
                (
                    state.tasks_by_delivery.len(),
                    state.registrations[&recipient.id].inbox.len(),
                ),
                delivery_indexes_before
            );
            assert!(!state.tasks[&handle.task_id].acknowledged);
        }
        let waiter = tokio::spawn({
            let broker = broker.clone();
            let credentials = sender.credentials();
            let task_id = handle.task_id.clone();
            async move { broker.wait_for_reply(&credentials, &task_id).await }
        });
        tokio::task::yield_now().await;
        persistence.fail_next_commit();
        assert_eq!(
            broker
                .reply(
                    &recipient.credentials(),
                    &handle.task_id,
                    reply("not-committed")
                )
                .await
                .unwrap_err(),
            DomainError::PersistenceUnavailable
        );
        {
            let state = broker.inner.state.lock().await;
            let task = &state.tasks[&handle.task_id];
            assert!(task.reply.is_none());
            assert_eq!(task.reply_waiters.len(), 1);
            assert!(task.terminal_deadline_unix_ms.is_none());
        }
        assert!(!waiter.is_finished());
        broker
            .cancel_task(&sender.credentials(), &handle.task_id)
            .await
            .unwrap();
        assert_eq!(
            waiter.await.unwrap().unwrap_err(),
            DomainError::TaskCanceled
        );
    }

    #[tokio::test]
    async fn registration_ttl_overflow_fails_before_epoch_commit() {
        let persistence = RecordingPersistence::new();
        let clock = TestClock::at(i64::MAX - REGISTRATION_TTL_MS + 1);
        let (broker, _) = BrokerState::recover(clock, persistence.clone())
            .await
            .unwrap();
        let error = broker
            .register(agent("reviewer", "w1:p2"), "session")
            .await
            .unwrap_err();
        assert_eq!(error, DomainError::PersistenceUnavailable);
        assert_eq!(
            persistence
                .snapshot
                .lock()
                .unwrap()
                .last_registration_epoch
                .get(),
            0
        );
        assert!(broker.inner.state.lock().await.registrations.is_empty());
    }

    #[tokio::test]
    async fn renewal_ttl_overflow_leaves_registration_unchanged() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let registration = broker
            .register(agent("reviewer", "w1:p2"), "session")
            .await
            .unwrap();
        let original_expiry = i64::MAX - 1;
        broker
            .inner
            .state
            .lock()
            .await
            .registrations
            .get_mut(&registration.id)
            .unwrap()
            .registration
            .expires_unix_ms = original_expiry;
        clock.set(i64::MAX - REGISTRATION_TTL_MS + 1);
        let error = broker.renew(&registration.credentials()).await.unwrap_err();
        assert_eq!(error, DomainError::PersistenceUnavailable);
        assert_eq!(
            broker.inner.state.lock().await.registrations[&registration.id]
                .registration
                .expires_unix_ms,
            original_expiry
        );
    }

    #[tokio::test]
    async fn enqueue_deadline_overflow_leaves_scheduler_unchanged() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let sender = register_sender(&broker).await;
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "session")
            .await
            .unwrap();
        prevent_registration_expiry(&broker).await;
        clock.set(i64::MAX - DELIVERY_TTL_MS + 1);
        let error = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "deadline-overflow"),
            )
            .await
            .unwrap_err();
        assert_eq!(error, DomainError::PersistenceUnavailable);
        let state = broker.inner.state.lock().await;
        assert!(state.tasks.is_empty());
        assert!(state.delivery_deadlines.is_empty());
        assert!(state.registrations[&recipient.id].inbox.is_empty());
    }

    #[tokio::test]
    async fn terminal_retention_overflow_leaves_task_and_waiter_unchanged() {
        let persistence = RecordingPersistence::new();
        let clock = TestClock::at(i64::MAX - DELIVERY_TTL_MS);
        let (broker, _) = BrokerState::recover(clock, persistence.clone())
            .await
            .unwrap();
        let sender = register_sender(&broker).await;
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "session")
            .await
            .unwrap();
        let handle = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "retention-overflow"),
            )
            .await
            .unwrap();
        let waiter = tokio::spawn({
            let broker = broker.clone();
            let credentials = sender.credentials();
            let task_id = handle.task_id.clone();
            async move { broker.wait_for_reply(&credentials, &task_id).await }
        });
        tokio::task::yield_now().await;
        let error = broker
            .cancel_task(&sender.credentials(), &handle.task_id)
            .await
            .unwrap_err();
        assert_eq!(error, DomainError::PersistenceUnavailable);
        let state = broker.inner.state.lock().await;
        let task = &state.tasks[&handle.task_id];
        assert!(!task.canceled);
        assert_eq!(task.reply_waiters.len(), 1);
        assert!(task.terminal_deadline_unix_ms.is_none());
        drop(state);
        assert!(!waiter.is_finished());
        drop(waiter);
        assert_eq!(
            persistence.snapshot.lock().unwrap().tasks[0].state,
            DurableTaskState::Queued
        );
        drop(recipient);
    }

    #[derive(Clone)]
    struct TestClock {
        unix_ms: Arc<AtomicI64>,
    }

    impl TestClock {
        fn at(unix_ms: i64) -> Self {
            Self {
                unix_ms: Arc::new(AtomicI64::new(unix_ms)),
            }
        }

        fn advance(&self, duration: Duration) {
            let millis = i64::try_from(duration.as_millis()).unwrap();
            self.unix_ms.fetch_add(millis, Ordering::SeqCst);
        }

        fn set(&self, unix_ms: i64) {
            self.unix_ms.store(unix_ms, Ordering::SeqCst);
        }
    }

    impl BrokerClock for TestClock {
        fn now_unix_ms(&self) -> i64 {
            self.unix_ms.load(Ordering::SeqCst)
        }
    }

    #[tokio::test]
    async fn registration_expiry_advances_directory_generation_and_notifies() {
        // Break caught: TTL expiry removes a live agent without advancing/waking the directory.
        let clock = TestClock::at(0);
        let broker = BrokerState::with_clock(clock.clone());
        broker
            .register(agent("worker", "opaque-worker"), "worker-session")
            .await
            .unwrap();
        let before = broker.inner.directory.generation.load(Ordering::Acquire);
        let notified = broker.inner.directory.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        clock.advance(Duration::from_millis(
            u64::try_from(REGISTRATION_TTL_MS).unwrap() + 1,
        ));
        assert!(broker.list_agents().await.is_empty());

        tokio::time::timeout(Duration::from_millis(20), notified)
            .await
            .expect("directory expiry did not notify waiters");
        assert_eq!(
            broker.inner.directory.generation.load(Ordering::Acquire),
            before + 1
        );
    }

    #[derive(Clone)]
    struct TokioClock {
        base_unix_ms: i64,
        started_at: tokio::time::Instant,
    }

    impl TokioClock {
        fn at(base_unix_ms: i64) -> Self {
            Self {
                base_unix_ms,
                started_at: tokio::time::Instant::now(),
            }
        }
    }

    impl BrokerClock for TokioClock {
        fn now_unix_ms(&self) -> i64 {
            let elapsed_ms = i64::try_from(self.started_at.elapsed().as_millis()).unwrap();
            self.base_unix_ms.saturating_add(elapsed_ms)
        }
    }

    #[derive(Clone)]
    struct GatedClock {
        unix_ms: Arc<AtomicI64>,
        gate: Arc<(StdMutex<GateState>, Condvar)>,
        entered: Arc<Notify>,
    }

    #[derive(Default)]
    struct GateState {
        remaining_reads: Option<usize>,
        released: bool,
    }

    impl GatedClock {
        fn at(unix_ms: i64) -> Self {
            Self {
                unix_ms: Arc::new(AtomicI64::new(unix_ms)),
                gate: Arc::new((StdMutex::new(GateState::default()), Condvar::new())),
                entered: Arc::new(Notify::new()),
            }
        }

        fn block_on_read(&self, read_number: usize) {
            let mut gate = self.gate.0.lock().unwrap();
            gate.remaining_reads = Some(read_number);
            gate.released = false;
        }

        async fn wait_until_blocked(&self) {
            self.entered.notified().await;
        }

        fn release(&self) {
            let mut gate = self.gate.0.lock().unwrap();
            gate.released = true;
            self.gate.1.notify_one();
        }
    }

    impl BrokerClock for GatedClock {
        fn now_unix_ms(&self) -> i64 {
            let mut gate = self.gate.0.lock().unwrap();
            if let Some(remaining_reads) = &mut gate.remaining_reads {
                *remaining_reads -= 1;
                if *remaining_reads == 0 {
                    gate.remaining_reads = None;
                    self.entered.notify_one();
                    while !gate.released {
                        gate = self.gate.1.wait(gate).unwrap();
                    }
                }
            }
            drop(gate);
            self.unix_ms.load(Ordering::SeqCst)
        }
    }

    fn agent(name: &str, pane_id: &str) -> VerifiedAgent {
        VerifiedAgent {
            name: AgentName::parse(name).unwrap(),
            pane_id: pane_id.to_owned(),
            harness: "pi".to_owned(),
            workspace: PathBuf::from("/workspace"),
        }
    }

    #[tokio::test]
    async fn public_operations_snapshot_serialization_is_redacted_by_construction() {
        // Break caught: the public serializable status snapshot embeds Registration and exposes
        // IDs, epochs, pane/session identifiers, expiry, harness data, and workspace paths.
        let broker = BrokerState::new();
        let registration = broker
            .register(
                VerifiedAgent {
                    name: AgentName::parse("reviewer-safe").unwrap(),
                    pane_id: "pane-private-7".to_owned(),
                    harness: "harness-private-8".to_owned(),
                    workspace: PathBuf::from("/workspace/private-nine"),
                },
                "session-private-10",
            )
            .await
            .unwrap();

        let encoded = serde_json::to_string(&broker.operations_snapshot().await.unwrap()).unwrap();

        assert!(encoded.contains("reviewer-safe"), "{encoded}");
        for forbidden in [
            registration.id.as_str(),
            "pane-private-7",
            "harness-private-8",
            "session-private-10",
            "/workspace/private-nine",
            "\"epoch\"",
            "\"expires_unix_ms\"",
        ] {
            assert!(
                !encoded.contains(forbidden),
                "leaked {forbidden:?}: {encoded}"
            );
        }
    }

    fn delivery(sender: &str, recipient: &str, text: &str) -> QueuedDelivery {
        QueuedDelivery {
            task_id: format!("task-{text}"),
            context_id: "context-1".to_owned(),
            sender: AgentName::parse(sender).unwrap(),
            recipient: AgentName::parse(recipient).unwrap(),
            payload: ValidatedPayload {
                text: text.to_owned(),
                metadata: json!({}),
                file_refs: vec![],
            },
            created_unix_ms: 1_000,
            attempt: 0,
        }
    }

    fn reply(text: &str) -> ReplyPayload {
        ReplyPayload {
            text: text.to_owned(),
            metadata: json!({}),
            file_refs: vec![],
        }
    }

    fn unknown_credentials() -> RegistrationCredentials {
        RegistrationCredentials {
            id: RegistrationId::new(),
            epoch: RegistrationEpoch::from_u64(1),
        }
    }

    async fn register_sender(broker: &BrokerState) -> Registration {
        broker
            .register(agent("implementer", "w1:p1"), "sender-session")
            .await
            .unwrap()
    }

    async fn prevent_registration_expiry(broker: &BrokerState) {
        let mut state = broker.inner.state.lock().await;
        for registration in state.registrations.values_mut() {
            registration.registration.expires_unix_ms = i64::MAX;
        }
    }

    #[tokio::test]
    async fn replacing_registration_detaches_without_canceling_tasks() {
        let broker = BrokerState::with_clock(TestClock::at(1_000));
        let sender = register_sender(&broker).await;
        let first = broker
            .register(agent("reviewer", "w1:p2"), "reviewer-session-1")
            .await
            .unwrap();
        broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "survives-replacement"),
            )
            .await
            .unwrap();

        let second = broker
            .register(agent("reviewer", "w1:p3"), "reviewer-session-2")
            .await
            .unwrap();
        let first_epoch = serde_json::to_value(first.epoch).unwrap().as_u64().unwrap();
        let second_epoch = serde_json::to_value(second.epoch)
            .unwrap()
            .as_u64()
            .unwrap();
        assert_eq!(second_epoch, first_epoch + 1);

        let delivered = broker
            .wait_next(&second.credentials(), Some(Duration::from_millis(10)))
            .await
            .unwrap();
        assert_eq!(delivered.task_id, "task-survives-replacement");
    }

    #[tokio::test]
    async fn recipient_replacement_preserves_queued_delivery_order() {
        let broker = BrokerState::with_clock(TestClock::at(1_000));
        let sender = register_sender(&broker).await;
        broker
            .register(agent("reviewer", "w1:p2"), "reviewer-session-1")
            .await
            .unwrap();
        for index in (0..16).rev() {
            broker
                .enqueue(
                    &sender.credentials(),
                    delivery("implementer", "reviewer", &format!("ordered-{index:02}")),
                )
                .await
                .unwrap();
        }

        let replacement = broker
            .register(agent("reviewer", "w1:p3"), "reviewer-session-2")
            .await
            .unwrap();
        for index in (0..16).rev() {
            let delivered = broker
                .wait_next(&replacement.credentials(), None)
                .await
                .unwrap();
            assert_eq!(delivered.task_id, format!("task-ordered-{index:02}"));
            broker
                .ack_delivery(&replacement.credentials(), &delivered.delivery_id)
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn stale_epoch_cannot_ack_reply_renew_or_unregister() {
        let broker = BrokerState::with_clock(TestClock::at(1_000));
        let sender = register_sender(&broker).await;
        let first = broker
            .register(agent("reviewer", "w1:p2"), "reviewer-session-1")
            .await
            .unwrap();
        let handle = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "stale-epoch"),
            )
            .await
            .unwrap();
        let delivered = broker.wait_next(&first.credentials(), None).await.unwrap();
        broker
            .register(agent("reviewer", "w1:p3"), "reviewer-session-2")
            .await
            .unwrap();

        assert_eq!(
            broker.renew(&first.credentials()).await.unwrap_err(),
            DomainError::RegistrationExpired
        );
        assert_eq!(
            broker
                .ack_delivery(&first.credentials(), &delivered.delivery_id)
                .await
                .unwrap_err(),
            DomainError::RegistrationExpired
        );
        assert_eq!(
            broker
                .reply(&first.credentials(), &handle.task_id, reply("stale"))
                .await
                .unwrap_err(),
            DomainError::RegistrationExpired
        );
        assert_eq!(
            broker
                .remove_registration(&first.credentials())
                .await
                .unwrap_err(),
            DomainError::RegistrationExpired
        );
    }

    #[tokio::test]
    async fn unacknowledged_lease_requeues_with_a_fresh_delivery_id() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let sender = register_sender(&broker).await;
        let first_recipient = broker
            .register(agent("reviewer", "w1:p2"), "reviewer-session-1")
            .await
            .unwrap();
        broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "fresh-delivery-id"),
            )
            .await
            .unwrap();
        let first = broker
            .wait_next(&first_recipient.credentials(), None)
            .await
            .unwrap();

        let second_recipient = broker
            .register(agent("reviewer", "w1:p3"), "reviewer-session-2")
            .await
            .unwrap();
        let second = broker
            .wait_next(&second_recipient.credentials(), None)
            .await
            .unwrap();
        assert_eq!(second.task_id, first.task_id);
        assert_ne!(second.delivery_id, first.delivery_id);
        assert_eq!(second.attempt, first.attempt + 1);
    }

    #[tokio::test(start_paused = true)]
    async fn acknowledged_task_survives_recipient_replacement_without_redelivery() {
        let broker = BrokerState::with_clock(TestClock::at(1_000));
        let sender = register_sender(&broker).await;
        let first_recipient = broker
            .register(agent("reviewer", "w1:p2"), "reviewer-session-1")
            .await
            .unwrap();
        let handle = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "acknowledged-replacement"),
            )
            .await
            .unwrap();
        let delivered = broker
            .wait_next(&first_recipient.credentials(), None)
            .await
            .unwrap();
        broker
            .ack_delivery(&first_recipient.credentials(), &delivered.delivery_id)
            .await
            .unwrap();

        let second_recipient = broker
            .register(agent("reviewer", "w1:p3"), "reviewer-session-2")
            .await
            .unwrap();
        assert_eq!(
            broker
                .wait_next(
                    &second_recipient.credentials(),
                    Some(Duration::from_millis(1)),
                )
                .await
                .unwrap_err(),
            DomainError::WaitTimedOut
        );
        broker
            .reply(
                &second_recipient.credentials(),
                &handle.task_id,
                reply("approved"),
            )
            .await
            .unwrap();
        assert_eq!(
            broker
                .wait_for_reply(&sender.credentials(), &handle.task_id)
                .await
                .unwrap()
                .text,
            "approved"
        );
    }

    #[tokio::test]
    async fn acknowledged_delivery_retry_succeeds_after_same_principal_replacement() {
        // Break caught: ACK committed with the first registration, but retrying its exact
        // delivery ID after a same-principal registration refresh is rejected by the retired
        // ephemeral lease owner.
        let broker = BrokerState::with_clock(TestClock::at(1_000));
        let sender = register_sender(&broker).await;
        let first_recipient = broker
            .register(agent("reviewer", "w1:p2"), "reviewer-session-1")
            .await
            .unwrap();
        broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "ack-refresh-retry"),
            )
            .await
            .unwrap();
        let delivered = broker
            .wait_next(&first_recipient.credentials(), None)
            .await
            .unwrap();
        broker
            .ack_delivery(&first_recipient.credentials(), &delivered.delivery_id)
            .await
            .unwrap();

        let refreshed_recipient = broker
            .register(agent("reviewer", "w1:p2"), "reviewer-session-2")
            .await
            .unwrap();
        let other = broker
            .register(agent("observer", "w1:p3"), "observer-session")
            .await
            .unwrap();

        broker
            .ack_delivery(&refreshed_recipient.credentials(), &delivered.delivery_id)
            .await
            .unwrap();
        assert_eq!(
            broker
                .ack_delivery(&first_recipient.credentials(), &delivered.delivery_id)
                .await
                .unwrap_err(),
            DomainError::RegistrationExpired
        );
        assert_eq!(
            broker
                .ack_delivery(&other.credentials(), &delivered.delivery_id)
                .await
                .unwrap_err(),
            DomainError::DeliveryNotOwned
        );
    }

    #[tokio::test]
    async fn acknowledged_delivery_retry_succeeds_for_fresh_recipient_after_recovery() {
        // Break caught: cold recovery restores the exact acknowledged delivery with no ephemeral
        // owner, so a fresh registration of its durable recipient cannot finish an ambiguous ACK.
        let persistence = RecordingPersistence::new();
        let (broker, sender, recipient) = broker_with_persistence(persistence.clone()).await;
        broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "ack-restart-retry"),
            )
            .await
            .unwrap();
        let delivered = broker
            .wait_next(&recipient.credentials(), None)
            .await
            .unwrap();
        broker
            .ack_delivery(&recipient.credentials(), &delivered.delivery_id)
            .await
            .unwrap();

        let (recovered, _) = BrokerState::recover(TestClock::at(1_001), persistence)
            .await
            .unwrap();
        let fresh_recipient = recovered
            .register(agent("reviewer", "w1:p2"), "reviewer-session-2")
            .await
            .unwrap();
        let other = recovered
            .register(agent("observer", "w1:p3"), "observer-session")
            .await
            .unwrap();

        recovered
            .ack_delivery(&fresh_recipient.credentials(), &delivered.delivery_id)
            .await
            .unwrap();
        assert_eq!(
            recovered
                .ack_delivery(&other.credentials(), &delivered.delivery_id)
                .await
                .unwrap_err(),
            DomainError::DeliveryNotOwned
        );
        assert_eq!(
            recovered
                .ack_delivery(&fresh_recipient.credentials(), &DeliveryId::new())
                .await
                .unwrap_err(),
            DomainError::DeliveryNotFound
        );
    }

    #[tokio::test]
    async fn sender_replacement_can_wait_cancel_and_observe_reply() {
        let broker = BrokerState::with_clock(TestClock::at(1_000));
        let first_sender = register_sender(&broker).await;
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "reviewer-session")
            .await
            .unwrap();
        for text in ["wait", "cancel", "observe"] {
            broker
                .enqueue(
                    &first_sender.credentials(),
                    delivery("implementer", "reviewer", text),
                )
                .await
                .unwrap();
        }
        broker
            .reply(
                &recipient.credentials(),
                "task-observe",
                reply("already-finished"),
            )
            .await
            .unwrap();

        let second_sender = broker
            .register(agent("implementer", "w1:p4"), "sender-session-2")
            .await
            .unwrap();
        let waiter = tokio::spawn({
            let broker = broker.clone();
            let credentials = second_sender.credentials();
            async move { broker.wait_for_reply(&credentials, "task-wait").await }
        });
        tokio::task::yield_now().await;
        broker
            .reply(&recipient.credentials(), "task-wait", reply("finished"))
            .await
            .unwrap();
        assert_eq!(waiter.await.unwrap().unwrap().text, "finished");

        broker
            .cancel_task(&second_sender.credentials(), "task-cancel")
            .await
            .unwrap();
        assert_eq!(
            broker
                .wait_for_reply(&second_sender.credentials(), "task-cancel")
                .await
                .unwrap_err(),
            DomainError::TaskCanceled
        );
        assert_eq!(
            broker
                .wait_for_reply(&second_sender.credentials(), "task-observe")
                .await
                .unwrap()
                .text,
            "already-finished"
        );
    }

    #[tokio::test]
    async fn acknowledged_task_expires_at_its_original_twenty_four_hour_deadline() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let sender = register_sender(&broker).await;
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "reviewer-session")
            .await
            .unwrap();
        let handle = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "acknowledged-expiry"),
            )
            .await
            .unwrap();
        let delivered = broker
            .wait_next(&recipient.credentials(), None)
            .await
            .unwrap();
        broker
            .ack_delivery(&recipient.credentials(), &delivered.delivery_id)
            .await
            .unwrap();
        prevent_registration_expiry(&broker).await;

        clock.advance(Duration::from_millis(
            u64::try_from(DELIVERY_TTL_MS - 1).unwrap(),
        ));
        broker.list_agents().await;
        assert!(!broker.inner.state.lock().await.tasks[&handle.task_id].expired);

        clock.advance(Duration::from_millis(1));
        assert_eq!(
            broker
                .wait_for_reply(&sender.credentials(), &handle.task_id)
                .await
                .unwrap_err(),
            DomainError::TaskExpired
        );
    }

    #[tokio::test(start_paused = true)]
    async fn waiting_recipient_receives_one_enqueued_delivery_without_polling() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let sender = register_sender(&broker).await;
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "pi-session-2")
            .await
            .unwrap();

        let waiter = tokio::spawn({
            let broker = broker.clone();
            let credentials = recipient.credentials();
            async move { broker.wait_next(&credentials, None).await }
        });

        tokio::task::yield_now().await;
        let handle = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "review this"),
            )
            .await
            .unwrap();
        let delivered = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(delivered.task_id, handle.task_id);
        assert_eq!(delivered.payload.text, "review this");
    }

    #[tokio::test]
    async fn second_wait_for_same_registration_is_rejected() {
        let broker = BrokerState::with_clock(TestClock::at(1_000));
        let registration = broker
            .register(agent("reviewer", "w1:p2"), "session")
            .await
            .unwrap();
        let first = broker
            .begin_wait(&registration.credentials())
            .await
            .unwrap();
        assert_eq!(
            broker
                .begin_wait(&registration.credentials())
                .await
                .unwrap_err(),
            DomainError::WaitAlreadyActive
        );
        drop(first);
        assert!(broker.begin_wait(&registration.credentials()).await.is_ok());
    }

    #[tokio::test]
    async fn registration_expires_at_thirty_seconds_and_renewal_resets_the_deadline() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let registration = broker
            .register(agent("reviewer", "w1:p2"), "session")
            .await
            .unwrap();
        assert_eq!(registration.expires_unix_ms, 31_000);

        clock.advance(Duration::from_secs(29));
        let renewed = broker.renew(&registration.credentials()).await.unwrap();
        assert_eq!(renewed.expires_unix_ms, 60_000);

        clock.advance(Duration::from_secs(30));
        assert_eq!(
            broker.renew(&registration.credentials()).await.unwrap_err(),
            DomainError::RegistrationExpired
        );
        assert!(broker.list_agents().await.is_empty());
    }

    #[tokio::test]
    async fn retired_registration_fences_are_bounded() {
        let broker = BrokerState::with_clock(TestClock::at(1_000));
        for index in 0..(MAX_RETAINED_TASKS + 2) {
            broker
                .register(
                    agent("reviewer", &format!("w1:p{index}")),
                    &format!("session-{index}"),
                )
                .await
                .unwrap();
        }

        assert!(
            broker
                .inner
                .state
                .lock()
                .await
                .retired_registration_ids
                .len()
                <= MAX_RETAINED_TASKS
        );
    }

    #[tokio::test]
    async fn unacknowledged_delivery_is_redelivered_after_sixty_second_lease() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let sender = register_sender(&broker).await;
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "session")
            .await
            .unwrap();
        broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "lease"),
            )
            .await
            .unwrap();

        let first = broker
            .wait_next(&recipient.credentials(), None)
            .await
            .unwrap();
        assert_eq!(first.leased_until_unix_ms, 61_000);
        assert_eq!(first.attempt, 0);

        clock.advance(Duration::from_secs(20));
        broker.renew(&sender.credentials()).await.unwrap();
        broker.renew(&recipient.credentials()).await.unwrap();
        clock.advance(Duration::from_secs(20));
        broker.renew(&sender.credentials()).await.unwrap();
        broker.renew(&recipient.credentials()).await.unwrap();
        clock.advance(Duration::from_secs(20));
        let second = broker
            .wait_next(&recipient.credentials(), None)
            .await
            .unwrap();
        assert_ne!(second.delivery_id, first.delivery_id);
        assert_eq!(second.task_id, first.task_id);
        assert_eq!(second.attempt, 1);
        assert_eq!(second.leased_until_unix_ms, 121_000);
    }

    #[tokio::test]
    async fn expired_delivery_lease_rejects_stale_acknowledgement() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let sender = register_sender(&broker).await;
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "session")
            .await
            .unwrap();
        broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "stale-ack"),
            )
            .await
            .unwrap();
        let delivered = broker
            .wait_next(&recipient.credentials(), None)
            .await
            .unwrap();

        clock.advance(Duration::from_secs(20));
        broker.renew(&recipient.credentials()).await.unwrap();
        clock.advance(Duration::from_secs(20));
        broker.renew(&recipient.credentials()).await.unwrap();
        clock.advance(Duration::from_secs(20));

        assert_eq!(
            broker
                .ack_delivery(&recipient.credentials(), &delivered.delivery_id)
                .await
                .unwrap_err(),
            DomainError::DeliveryNotFound
        );
    }

    #[tokio::test]
    async fn queued_delivery_expires_after_twenty_four_hours_and_wakes_sender() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "session")
            .await
            .unwrap();
        let sender = register_sender(&broker).await;
        let handle = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "expired"),
            )
            .await
            .unwrap();
        let waiter = tokio::spawn({
            let broker = broker.clone();
            let sender_credentials = sender.credentials();
            let task_id = handle.task_id.clone();
            async move { broker.wait_for_reply(&sender_credentials, &task_id).await }
        });
        tokio::task::yield_now().await;

        prevent_registration_expiry(&broker).await;
        clock.advance(Duration::from_millis(
            u64::try_from(DELIVERY_TTL_MS - 1).unwrap(),
        ));
        for index in 0..31 {
            broker
                .enqueue(
                    &sender.credentials(),
                    delivery("implementer", "reviewer", &format!("still-active-{index}")),
                )
                .await
                .unwrap();
        }
        clock.advance(Duration::from_millis(1));
        let delivered = broker
            .wait_next(&recipient.credentials(), Some(Duration::from_millis(10)))
            .await
            .unwrap();
        assert_eq!(delivered.task_id, "task-still-active-0");
        assert_eq!(waiter.await.unwrap().unwrap_err(), DomainError::TaskExpired);
        assert!(
            broker
                .enqueue(
                    &sender.credentials(),
                    delivery("implementer", "reviewer", "replacement-slot"),
                )
                .await
                .is_ok()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn unacknowledged_lease_cannot_redeliver_past_the_delivery_deadline() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let sender = register_sender(&broker).await;
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "session")
            .await
            .unwrap();
        let handle = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "leased-expiry"),
            )
            .await
            .unwrap();
        let first = broker
            .wait_next(&recipient.credentials(), None)
            .await
            .unwrap();
        assert_eq!(first.task_id, handle.task_id);

        prevent_registration_expiry(&broker).await;
        clock.advance(Duration::from_millis(
            u64::try_from(DELIVERY_TTL_MS).unwrap(),
        ));
        assert_eq!(
            broker
                .wait_next(&recipient.credentials(), Some(Duration::from_millis(1)))
                .await
                .unwrap_err(),
            DomainError::WaitTimedOut
        );
        assert_eq!(
            tokio::time::timeout(
                Duration::from_millis(50),
                broker.wait_for_reply(&sender.credentials(), &handle.task_id)
            )
            .await
            .unwrap()
            .unwrap_err(),
            DomainError::TaskExpired
        );
    }

    #[tokio::test(start_paused = true)]
    async fn acknowledged_delivery_is_not_redelivered() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let sender = register_sender(&broker).await;
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "session")
            .await
            .unwrap();
        broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "ack"),
            )
            .await
            .unwrap();
        let delivered = broker
            .wait_next(&recipient.credentials(), None)
            .await
            .unwrap();

        broker
            .ack_delivery(&recipient.credentials(), &delivered.delivery_id)
            .await
            .unwrap();
        clock.advance(Duration::from_secs(20));
        broker.renew(&recipient.credentials()).await.unwrap();
        clock.advance(Duration::from_secs(20));
        broker.renew(&recipient.credentials()).await.unwrap();
        clock.advance(Duration::from_secs(20));
        assert_eq!(
            broker
                .wait_next(&recipient.credentials(), Some(Duration::from_millis(1)))
                .await
                .unwrap_err(),
            DomainError::WaitTimedOut
        );
    }

    #[tokio::test]
    async fn delivery_acknowledgement_and_reply_require_recipient_ownership() {
        let broker = BrokerState::with_clock(TestClock::at(1_000));
        let sender = register_sender(&broker).await;
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "reviewer-session")
            .await
            .unwrap();
        let other = broker
            .register(agent("observer", "w1:p3"), "observer-session")
            .await
            .unwrap();
        let handle = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "owned"),
            )
            .await
            .unwrap();
        let delivered = broker
            .wait_next(&recipient.credentials(), None)
            .await
            .unwrap();

        assert_eq!(
            broker
                .ack_delivery(&other.credentials(), &delivered.delivery_id)
                .await
                .unwrap_err(),
            DomainError::DeliveryNotOwned
        );
        assert_eq!(
            broker
                .reply(&other.credentials(), &handle.task_id, reply("no"))
                .await
                .unwrap_err(),
            DomainError::TaskNotOwned
        );
    }

    #[tokio::test]
    async fn one_reply_wakes_all_sender_subscribers_and_conflicting_duplicate_is_rejected() {
        let broker = BrokerState::with_clock(TestClock::at(1_000));
        let sender = register_sender(&broker).await;
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "session")
            .await
            .unwrap();
        let handle = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "reply"),
            )
            .await
            .unwrap();

        let first_waiter = tokio::spawn({
            let broker = broker.clone();
            let sender_credentials = sender.credentials();
            let task_id = handle.task_id.clone();
            async move { broker.wait_for_reply(&sender_credentials, &task_id).await }
        });
        tokio::task::yield_now().await;
        let second_waiter = tokio::spawn({
            let broker = broker.clone();
            let sender_credentials = sender.credentials();
            let task_id = handle.task_id.clone();
            async move { broker.wait_for_reply(&sender_credentials, &task_id).await }
        });
        tokio::task::yield_now().await;

        broker
            .reply(&recipient.credentials(), &handle.task_id, reply("approved"))
            .await
            .unwrap();
        assert_eq!(first_waiter.await.unwrap().unwrap().text, "approved");
        assert_eq!(second_waiter.await.unwrap().unwrap().text, "approved");
        assert!(
            broker
                .reply(&recipient.credentials(), &handle.task_id, reply("approved"))
                .await
                .is_ok()
        );
        assert_eq!(
            broker
                .reply(&recipient.credentials(), &handle.task_id, reply("changes"))
                .await
                .unwrap_err(),
            DomainError::ReplyAlreadySubmitted
        );
    }

    #[tokio::test]
    async fn failed_and_rejected_are_distinct_retained_terminal_states() {
        let broker = BrokerState::with_clock(TestClock::at(1_000));
        let sender = register_sender(&broker).await;
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "session")
            .await
            .unwrap();
        for outcome in ["failed", "rejected"] {
            broker
                .enqueue(
                    &sender.credentials(),
                    delivery("implementer", "reviewer", outcome),
                )
                .await
                .unwrap();
        }

        broker
            .fail_task(
                &recipient.credentials(),
                "task-failed",
                reply("execution failed"),
            )
            .await
            .unwrap();
        broker
            .reject_task(
                &recipient.credentials(),
                "task-rejected",
                reply("request rejected"),
            )
            .await
            .unwrap();

        let failed = broker
            .task_snapshot(&sender.credentials(), "task-failed")
            .await
            .unwrap();
        let rejected = broker
            .task_snapshot(&sender.credentials(), "task-rejected")
            .await
            .unwrap();
        assert_eq!(failed.state, DurableTaskState::Failed);
        assert_eq!(failed.reply.as_ref().unwrap().text, "execution failed");
        assert_eq!(rejected.state, DurableTaskState::Rejected);
        assert_eq!(rejected.reply.as_ref().unwrap().text, "request rejected");
        assert_eq!(
            broker
                .wait_for_reply(&sender.credentials(), "task-failed")
                .await
                .unwrap_err(),
            DomainError::TaskFailed
        );
        assert_eq!(
            broker
                .wait_for_reply(&sender.credentials(), "task-rejected")
                .await
                .unwrap_err(),
            DomainError::TaskRejected
        );
        assert_eq!(
            failed.retention_deadline_unix_ms,
            Some(1_000 + TERMINAL_RETENTION_MS)
        );
        assert_eq!(
            rejected.retention_deadline_unix_ms,
            Some(1_000 + TERMINAL_RETENTION_MS)
        );
        assert_eq!(
            broker
                .wait_next(&recipient.credentials(), Some(Duration::from_millis(1)),)
                .await
                .unwrap_err(),
            DomainError::WaitTimedOut
        );
        assert!(matches!(
            broker
                .start_or_resume(
                    &sender.credentials(),
                    delivery("implementer", "reviewer", "failed"),
                )
                .await
                .unwrap(),
            StartOrResume::Terminal(task) if task == failed
        ));
        assert!(matches!(
            broker
                .start_or_resume(
                    &sender.credentials(),
                    delivery("implementer", "reviewer", "rejected"),
                )
                .await
                .unwrap(),
            StartOrResume::Terminal(task) if task == rejected
        ));
    }

    #[tokio::test]
    async fn cancellation_wakes_sender_and_is_idempotent() {
        let broker = BrokerState::with_clock(TestClock::at(1_000));
        let sender = register_sender(&broker).await;
        broker
            .register(agent("reviewer", "w1:p2"), "session")
            .await
            .unwrap();
        let handle = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "cancel"),
            )
            .await
            .unwrap();
        let waiter = tokio::spawn({
            let broker = broker.clone();
            let sender_credentials = sender.credentials();
            let task_id = handle.task_id.clone();
            async move { broker.wait_for_reply(&sender_credentials, &task_id).await }
        });
        tokio::task::yield_now().await;

        broker
            .cancel_task(&sender.credentials(), &handle.task_id)
            .await
            .unwrap();
        broker
            .cancel_task(&sender.credentials(), &handle.task_id)
            .await
            .unwrap();
        assert_eq!(
            waiter.await.unwrap().unwrap_err(),
            DomainError::TaskCanceled
        );
    }

    #[tokio::test]
    async fn registration_allows_at_most_thirty_two_active_outbound_tasks() {
        let broker = BrokerState::with_clock(TestClock::at(1_000));
        let sender = broker
            .register(agent("implementer", "w1:p1"), "sender-session")
            .await
            .unwrap();
        broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();

        for index in 0..32 {
            broker
                .enqueue(
                    &sender.credentials(),
                    delivery("implementer", "reviewer", &format!("message-{index}")),
                )
                .await
                .unwrap();
        }
        assert_eq!(
            broker
                .enqueue(
                    &sender.credentials(),
                    delivery("implementer", "reviewer", "message-32"),
                )
                .await
                .unwrap_err(),
            DomainError::TooManyActiveTasks
        );

        broker
            .cancel_task(&sender.credentials(), "task-message-0")
            .await
            .unwrap();
        assert!(
            broker
                .enqueue(
                    &sender.credentials(),
                    delivery("implementer", "reviewer", "message-32"),
                )
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn inbound_tasks_do_not_consume_the_outbound_task_limit() {
        let broker = BrokerState::with_clock(TestClock::at(1_000));
        let implementer = register_sender(&broker).await;
        let reviewer = broker
            .register(agent("reviewer", "w1:p2"), "reviewer-session")
            .await
            .unwrap();
        broker
            .register(agent("observer", "w1:p3"), "observer-session")
            .await
            .unwrap();
        for index in 0..MAX_ACTIVE_OUTBOUND_TASKS {
            broker
                .enqueue(
                    &reviewer.credentials(),
                    delivery("reviewer", "implementer", &format!("inbound-{index}")),
                )
                .await
                .unwrap();
        }

        assert!(
            broker
                .enqueue(
                    &implementer.credentials(),
                    delivery("implementer", "observer", "outbound"),
                )
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn remove_registration_updates_the_sorted_agent_listing() {
        let broker = BrokerState::with_clock(TestClock::at(1_000));
        let reviewer = broker
            .register(agent("reviewer", "w1:p2"), "reviewer-session")
            .await
            .unwrap();
        broker
            .register(agent("implementer", "w1:p1"), "implementer-session")
            .await
            .unwrap();

        let listed = broker.list_agents().await;
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].agent.name.as_str(), "implementer");
        assert_eq!(listed[1].agent.name.as_str(), "reviewer");

        broker
            .remove_registration(&reviewer.credentials())
            .await
            .unwrap();
        let listed = broker.list_agents().await;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].agent.name.as_str(), "implementer");
    }

    #[tokio::test(start_paused = true)]
    async fn removing_recipient_detaches_and_a_replacement_can_finish_the_task() {
        let broker = BrokerState::with_clock(TestClock::at(1_000));
        let sender = register_sender(&broker).await;
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        let handle = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "removed"),
            )
            .await
            .unwrap();
        let waiter = tokio::spawn({
            let broker = broker.clone();
            let sender_credentials = sender.credentials();
            let task_id = handle.task_id.clone();
            async move { broker.wait_for_reply(&sender_credentials, &task_id).await }
        });
        tokio::task::yield_now().await;

        broker
            .remove_registration(&recipient.credentials())
            .await
            .unwrap();
        let replacement = broker
            .register(agent("reviewer", "w1:p3"), "replacement-session")
            .await
            .unwrap();
        let delivered = broker
            .wait_next(&replacement.credentials(), None)
            .await
            .unwrap();
        assert_eq!(delivered.task_id, handle.task_id);
        broker
            .reply(
                &replacement.credentials(),
                &handle.task_id,
                reply("finished"),
            )
            .await
            .unwrap();
        assert_eq!(waiter.await.unwrap().unwrap().text, "finished");
    }

    #[tokio::test(start_paused = true)]
    async fn natural_registration_expiry_detaches_without_canceling_tasks() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let sender = register_sender(&broker).await;
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        let handle = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "expired-recipient"),
            )
            .await
            .unwrap();
        let waiter = tokio::spawn({
            let broker = broker.clone();
            let sender_credentials = sender.credentials();
            let task_id = handle.task_id.clone();
            async move { broker.wait_for_reply(&sender_credentials, &task_id).await }
        });
        tokio::task::yield_now().await;

        clock.advance(Duration::from_secs(30));
        assert_eq!(
            broker.renew(&recipient.credentials()).await.unwrap_err(),
            DomainError::RegistrationExpired
        );
        let replacement = broker
            .register(agent("reviewer", "w1:p3"), "replacement-session")
            .await
            .unwrap();
        broker
            .reply(
                &replacement.credentials(),
                &handle.task_id,
                reply("finished"),
            )
            .await
            .unwrap();
        assert_eq!(waiter.await.unwrap().unwrap().text, "finished");
    }

    #[tokio::test]
    async fn enqueue_rejects_delivery_sender_that_does_not_match_authenticated_registration() {
        let broker = BrokerState::with_clock(TestClock::at(1_000));
        let sender = broker
            .register(agent("implementer", "w1:p1"), "sender-session")
            .await
            .unwrap();
        broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();

        assert_eq!(
            broker
                .enqueue(
                    &sender.credentials(),
                    delivery("observer", "reviewer", "spoofed")
                )
                .await
                .unwrap_err(),
            DomainError::SenderMismatch
        );
    }

    #[tokio::test]
    async fn identical_start_resumes_but_identity_or_payload_mismatch_conflicts() {
        // Break caught: a retry either duplicates recipient work or accepts a changed request
        // under an already-retained idempotency key.
        let broker = BrokerState::with_clock(TestClock::at(1_000));
        let sender = register_sender(&broker).await;
        broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        let request = delivery("implementer", "reviewer", "idempotent");

        assert!(matches!(
            broker
                .start_or_resume(&sender.credentials(), request.clone())
                .await
                .unwrap(),
            StartOrResume::Started(_)
        ));
        assert!(matches!(
            broker
                .start_or_resume(&sender.credentials(), request.clone())
                .await
                .unwrap(),
            StartOrResume::Active(_)
        ));
        let mut mismatch = request;
        mismatch.payload.text = "changed".to_owned();
        assert_eq!(
            broker
                .start_or_resume(&sender.credentials(), mismatch)
                .await
                .unwrap_err(),
            DomainError::DuplicateTask
        );
    }

    #[tokio::test]
    async fn retained_exact_retry_does_not_require_live_recipient() {
        // Break caught: recipient liveness is ephemeral admission state. It must not override the
        // retained idempotency record for an already-admitted task.
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let sender = register_sender(&broker).await;
        broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        let request = delivery("implementer", "reviewer", "offline-idempotent");
        broker
            .start_or_resume(&sender.credentials(), request.clone())
            .await
            .unwrap();

        clock.advance(Duration::from_secs(31));
        let replacement_sender = register_sender(&broker).await;
        assert!(matches!(
            broker
                .start_or_resume(&replacement_sender.credentials(), request.clone())
                .await
                .unwrap(),
            StartOrResume::Active(_)
        ));

        let mut mismatch = request;
        mismatch.payload.text = "changed".to_owned();
        assert_eq!(
            broker
                .start_or_resume(&replacement_sender.credentials(), mismatch)
                .await
                .unwrap_err(),
            DomainError::DuplicateTask
        );
    }

    #[tokio::test]
    async fn sender_reply_wait_and_cancellation_reject_a_different_registration() {
        let broker = BrokerState::with_clock(TestClock::at(1_000));
        let sender = broker
            .register(agent("implementer", "w1:p1"), "sender-session")
            .await
            .unwrap();
        let other = broker
            .register(agent("observer", "w1:p3"), "other-session")
            .await
            .unwrap();
        broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        let handle = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "owned-by-sender"),
            )
            .await
            .unwrap();

        assert_eq!(
            broker
                .wait_for_reply(&other.credentials(), &handle.task_id)
                .await
                .unwrap_err(),
            DomainError::TaskNotOwned
        );
        assert_eq!(
            broker
                .cancel_task(&other.credentials(), &handle.task_id)
                .await
                .unwrap_err(),
            DomainError::TaskNotOwned
        );
    }

    #[tokio::test]
    async fn enqueue_rejects_missing_replaced_and_expired_sender_registrations() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let old_sender = broker
            .register(agent("implementer", "w1:p1"), "old-session")
            .await
            .unwrap();
        let current_sender = broker
            .register(agent("implementer", "w1:p3"), "new-session")
            .await
            .unwrap();
        broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();

        assert_eq!(
            broker
                .enqueue(
                    &unknown_credentials(),
                    delivery("implementer", "reviewer", "missing"),
                )
                .await
                .unwrap_err(),
            DomainError::RegistrationNotFound
        );
        assert_eq!(
            broker
                .enqueue(
                    &old_sender.credentials(),
                    delivery("implementer", "reviewer", "replaced"),
                )
                .await
                .unwrap_err(),
            DomainError::RegistrationExpired
        );

        clock.advance(Duration::from_secs(30));
        assert_eq!(
            broker
                .enqueue(
                    &current_sender.credentials(),
                    delivery("implementer", "reviewer", "expired"),
                )
                .await
                .unwrap_err(),
            DomainError::RegistrationExpired
        );
    }

    #[tokio::test]
    async fn replacing_sender_registration_preserves_an_existing_reply_waiter() {
        let broker = BrokerState::with_clock(TestClock::at(1_000));
        let sender = broker
            .register(agent("implementer", "w1:p1"), "old-session")
            .await
            .unwrap();
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        let handle = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "replace-sender"),
            )
            .await
            .unwrap();
        let waiter = tokio::spawn({
            let broker = broker.clone();
            let sender_credentials = sender.credentials();
            let task_id = handle.task_id.clone();
            async move { broker.wait_for_reply(&sender_credentials, &task_id).await }
        });
        tokio::task::yield_now().await;

        broker
            .register(agent("implementer", "w1:p3"), "new-session")
            .await
            .unwrap();
        broker
            .reply(&recipient.credentials(), &handle.task_id, reply("finished"))
            .await
            .unwrap();
        assert_eq!(waiter.await.unwrap().unwrap().text, "finished");
    }

    #[tokio::test]
    async fn sender_side_operations_reject_missing_and_replaced_registrations() {
        let broker = BrokerState::with_clock(TestClock::at(1_000));
        let sender = register_sender(&broker).await;
        broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        let handle = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "stale-owner"),
            )
            .await
            .unwrap();
        broker
            .register(agent("implementer", "w1:p3"), "replacement-session")
            .await
            .unwrap();

        assert_eq!(
            broker
                .wait_for_reply(&sender.credentials(), &handle.task_id)
                .await
                .unwrap_err(),
            DomainError::RegistrationExpired
        );
        assert_eq!(
            broker
                .cancel_task(&unknown_credentials(), &handle.task_id)
                .await
                .unwrap_err(),
            DomainError::RegistrationNotFound
        );
    }

    #[tokio::test]
    async fn reply_wait_rejects_expired_sender_registration() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let sender = register_sender(&broker).await;
        broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        let handle = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "expired-wait-owner"),
            )
            .await
            .unwrap();

        clock.advance(Duration::from_secs(30));
        assert_eq!(
            broker
                .wait_for_reply(&sender.credentials(), &handle.task_id)
                .await
                .unwrap_err(),
            DomainError::RegistrationExpired
        );
    }

    #[tokio::test]
    async fn cancellation_rejects_expired_sender_registration() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let sender = register_sender(&broker).await;
        broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        let handle = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "expired-cancel-owner"),
            )
            .await
            .unwrap();

        clock.advance(Duration::from_secs(30));
        assert_eq!(
            broker
                .cancel_task(&sender.credentials(), &handle.task_id)
                .await
                .unwrap_err(),
            DomainError::RegistrationExpired
        );
    }

    #[tokio::test(start_paused = true)]
    async fn removing_sender_registration_preserves_task_and_reply_waiter() {
        let broker = BrokerState::with_clock(TestClock::at(1_000));
        let sender = register_sender(&broker).await;
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        let handle = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "removed-sender"),
            )
            .await
            .unwrap();
        let waiter = tokio::spawn({
            let broker = broker.clone();
            let sender_credentials = sender.credentials();
            let task_id = handle.task_id.clone();
            async move { broker.wait_for_reply(&sender_credentials, &task_id).await }
        });
        tokio::task::yield_now().await;

        broker
            .remove_registration(&sender.credentials())
            .await
            .unwrap();
        broker
            .reply(&recipient.credentials(), &handle.task_id, reply("finished"))
            .await
            .unwrap();
        assert_eq!(waiter.await.unwrap().unwrap().text, "finished");
    }

    #[tokio::test(start_paused = true)]
    async fn expiring_sender_registration_preserves_task_and_reply_waiter() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let sender = register_sender(&broker).await;
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        let handle = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "expired-sender"),
            )
            .await
            .unwrap();
        let waiter = tokio::spawn({
            let broker = broker.clone();
            let sender_credentials = sender.credentials();
            let task_id = handle.task_id.clone();
            async move { broker.wait_for_reply(&sender_credentials, &task_id).await }
        });
        tokio::task::yield_now().await;

        clock.advance(Duration::from_secs(20));
        broker.renew(&recipient.credentials()).await.unwrap();
        clock.advance(Duration::from_secs(10));
        broker.list_agents().await;
        broker
            .reply(&recipient.credentials(), &handle.task_id, reply("finished"))
            .await
            .unwrap();
        assert_eq!(waiter.await.unwrap().unwrap().text, "finished");
    }

    #[tokio::test(start_paused = true)]
    async fn reply_waiter_remains_active_across_sender_expiry() {
        let broker = BrokerState::with_clock(TokioClock::at(1_000));
        let sender = register_sender(&broker).await;
        tokio::time::advance(Duration::from_secs(10)).await;
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        let handle = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "sender-deadline"),
            )
            .await
            .unwrap();
        let waiter = tokio::spawn({
            let broker = broker.clone();
            let sender_credentials = sender.credentials();
            let task_id = handle.task_id.clone();
            async move { broker.wait_for_reply(&sender_credentials, &task_id).await }
        });
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(20)).await;
        tokio::task::yield_now().await;

        assert!(!waiter.is_finished());
        broker
            .reply(&recipient.credentials(), &handle.task_id, reply("finished"))
            .await
            .unwrap();
        assert_eq!(waiter.await.unwrap().unwrap().text, "finished");
    }

    #[tokio::test]
    async fn register_samples_clock_after_waiting_for_state_lock() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let state_lock = broker.inner.state.lock().await;
        let registration = tokio::spawn({
            let broker = broker.clone();
            async move { broker.register(agent("reviewer", "w1:p2"), "session").await }
        });
        tokio::task::yield_now().await;

        clock.advance(Duration::from_secs(30));
        drop(state_lock);

        assert_eq!(registration.await.unwrap().unwrap().expires_unix_ms, 61_000);
    }

    #[tokio::test]
    async fn renew_samples_clock_after_waiting_for_state_lock() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let registration = broker
            .register(agent("reviewer", "w1:p2"), "session")
            .await
            .unwrap();
        let state_lock = broker.inner.state.lock().await;
        let renewal = tokio::spawn({
            let broker = broker.clone();
            let registration_credentials = registration.credentials();
            async move { broker.renew(&registration_credentials).await }
        });
        tokio::task::yield_now().await;

        clock.advance(Duration::from_secs(30));
        drop(state_lock);

        assert_eq!(
            renewal.await.unwrap().unwrap_err(),
            DomainError::RegistrationExpired
        );
    }

    #[tokio::test]
    async fn enqueue_samples_clock_after_waiting_for_state_lock() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let sender = register_sender(&broker).await;
        broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        let state_lock = broker.inner.state.lock().await;
        let enqueue = tokio::spawn({
            let broker = broker.clone();
            let sender_credentials = sender.credentials();
            async move {
                broker
                    .enqueue(
                        &sender_credentials,
                        delivery("implementer", "reviewer", "boundary"),
                    )
                    .await
            }
        });
        tokio::task::yield_now().await;

        clock.advance(Duration::from_secs(30));
        drop(state_lock);

        assert_eq!(
            enqueue.await.unwrap().unwrap_err(),
            DomainError::RegistrationExpired
        );
    }

    #[tokio::test]
    async fn begin_wait_samples_clock_after_waiting_for_state_lock() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let registration = broker
            .register(agent("reviewer", "w1:p2"), "session")
            .await
            .unwrap();
        let state_lock = broker.inner.state.lock().await;
        let wait = tokio::spawn({
            let broker = broker.clone();
            let registration_credentials = registration.credentials();
            async move { broker.begin_wait(&registration_credentials).await }
        });
        tokio::task::yield_now().await;

        clock.advance(Duration::from_secs(30));
        drop(state_lock);

        assert_eq!(
            wait.await.unwrap().unwrap_err(),
            DomainError::RegistrationExpired
        );
    }

    #[tokio::test]
    async fn acknowledgement_samples_clock_after_waiting_for_state_lock() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let sender = register_sender(&broker).await;
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "ack-boundary"),
            )
            .await
            .unwrap();
        let delivered = broker
            .wait_next(&recipient.credentials(), None)
            .await
            .unwrap();
        clock.advance(Duration::from_secs(20));
        broker.renew(&sender.credentials()).await.unwrap();
        broker.renew(&recipient.credentials()).await.unwrap();
        clock.advance(Duration::from_secs(20));
        broker.renew(&sender.credentials()).await.unwrap();
        broker.renew(&recipient.credentials()).await.unwrap();

        let state_lock = broker.inner.state.lock().await;
        let acknowledgement = tokio::spawn({
            let broker = broker.clone();
            let recipient_credentials = recipient.credentials();
            let delivery_id = delivered.delivery_id.clone();
            async move {
                broker
                    .ack_delivery(&recipient_credentials, &delivery_id)
                    .await
            }
        });
        tokio::task::yield_now().await;
        clock.advance(Duration::from_secs(20));
        drop(state_lock);

        assert_eq!(
            acknowledgement.await.unwrap().unwrap_err(),
            DomainError::DeliveryNotFound
        );
    }

    #[tokio::test]
    async fn reply_samples_clock_after_waiting_for_state_lock() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let sender = register_sender(&broker).await;
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        let handle = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "reply-boundary"),
            )
            .await
            .unwrap();
        let state_lock = broker.inner.state.lock().await;
        let reply_call = tokio::spawn({
            let broker = broker.clone();
            let recipient_credentials = recipient.credentials();
            let task_id = handle.task_id.clone();
            async move {
                broker
                    .reply(&recipient_credentials, &task_id, reply("too-late"))
                    .await
            }
        });
        tokio::task::yield_now().await;

        clock.advance(Duration::from_secs(30));
        drop(state_lock);

        assert_eq!(
            reply_call.await.unwrap().unwrap_err(),
            DomainError::RegistrationExpired
        );
    }

    #[tokio::test]
    async fn delivery_selection_samples_clock_after_waiting_for_state_lock() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let sender = register_sender(&broker).await;
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "delivery-boundary"),
            )
            .await
            .unwrap();
        let state_lock = broker.inner.state.lock().await;
        let selection = tokio::spawn({
            let broker = broker.clone();
            let recipient_credentials = recipient.credentials();
            async move { broker.poll_delivery(&recipient_credentials).await }
        });
        tokio::task::yield_now().await;

        clock.advance(Duration::from_secs(30));
        drop(state_lock);

        assert!(matches!(
            selection.await.unwrap(),
            Err(DomainError::RegistrationExpired)
        ));
    }

    #[tokio::test]
    async fn expiry_maintenance_removes_registration_from_both_indexes() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let registration = broker
            .register(agent("reviewer", "w1:p2"), "session")
            .await
            .unwrap();

        clock.advance(Duration::from_secs(30));
        assert!(broker.list_agents().await.is_empty());

        let state = broker.inner.state.lock().await;
        assert!(!state.registrations.contains_key(&registration.id));
        assert!(
            !state
                .registrations_by_agent
                .contains_key(&registration.agent.name)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn enqueue_between_queue_check_and_notification_await_wakes_recipient() {
        let clock = GatedClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let sender = register_sender(&broker).await;
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        clock.block_on_read(3);
        let waiter = tokio::spawn({
            let broker = broker.clone();
            let recipient_credentials = recipient.credentials();
            async move { broker.wait_next(&recipient_credentials, None).await }
        });
        clock.wait_until_blocked().await;

        let handle = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "window-enqueue"),
            )
            .await
            .unwrap();
        clock.release();

        assert_eq!(waiter.await.unwrap().unwrap().task_id, handle.task_id);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn removal_between_queue_check_and_notification_await_wakes_recipient() {
        let clock = GatedClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        clock.block_on_read(3);
        let waiter = tokio::spawn({
            let broker = broker.clone();
            let recipient_credentials = recipient.credentials();
            async move { broker.wait_next(&recipient_credentials, None).await }
        });
        clock.wait_until_blocked().await;

        broker
            .remove_registration(&recipient.credentials())
            .await
            .unwrap();
        clock.release();

        assert_eq!(
            waiter.await.unwrap().unwrap_err(),
            DomainError::RegistrationNotFound
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replacement_between_queue_check_and_notification_await_wakes_old_recipient() {
        let clock = GatedClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "old-session")
            .await
            .unwrap();
        clock.block_on_read(3);
        let waiter = tokio::spawn({
            let broker = broker.clone();
            let recipient_credentials = recipient.credentials();
            async move { broker.wait_next(&recipient_credentials, None).await }
        });
        clock.wait_until_blocked().await;

        broker
            .register(agent("reviewer", "w1:p4"), "new-session")
            .await
            .unwrap();
        clock.release();

        assert_eq!(
            waiter.await.unwrap().unwrap_err(),
            DomainError::RegistrationExpired
        );
    }

    #[tokio::test]
    async fn dropped_blocked_receive_releases_wait_slot_immediately() {
        let broker = BrokerState::with_clock(TestClock::at(1_000));
        let sender = register_sender(&broker).await;
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        let recipient_credentials = recipient.credentials();
        let mut first_wait = Box::pin(broker.wait_next(&recipient_credentials, None));
        tokio::select! {
            biased;
            result = &mut first_wait => panic!("wait unexpectedly completed: {result:?}"),
            _ = tokio::task::yield_now() => {}
        }

        drop(first_wait);
        let handle = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "after-drop"),
            )
            .await
            .unwrap();

        assert_eq!(
            broker
                .wait_next(&recipient.credentials(), None)
                .await
                .unwrap()
                .task_id,
            handle.task_id
        );
    }

    #[tokio::test]
    async fn completed_canceled_and_expired_tasks_release_all_live_state() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let sender = register_sender(&broker).await;
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();

        let completed = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "compact-complete"),
            )
            .await
            .unwrap();
        let completed_delivery = broker
            .wait_next(&recipient.credentials(), None)
            .await
            .unwrap();
        broker
            .reply(
                &recipient.credentials(),
                &completed.task_id,
                reply("approved"),
            )
            .await
            .unwrap();

        let canceled = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "compact-cancel"),
            )
            .await
            .unwrap();
        let canceled_delivery = broker
            .wait_next(&recipient.credentials(), None)
            .await
            .unwrap();
        broker
            .cancel_task(&sender.credentials(), &canceled.task_id)
            .await
            .unwrap();

        let expired = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "compact-expire"),
            )
            .await
            .unwrap();
        let expired_delivery = broker
            .wait_next(&recipient.credentials(), None)
            .await
            .unwrap();
        prevent_registration_expiry(&broker).await;
        clock.advance(Duration::from_millis(
            u64::try_from(DELIVERY_TTL_MS).unwrap(),
        ));
        broker.list_agents().await;

        let terminal_task_ids = [
            completed.task_id.clone(),
            canceled.task_id.clone(),
            expired.task_id.clone(),
        ];
        {
            let state = broker.inner.state.lock().await;
            assert!(state.tasks_by_delivery.is_empty());
            assert!(!state.active_tasks_by_agent.contains_key(&sender.agent.name));
            assert!(
                !state
                    .active_tasks_by_agent
                    .contains_key(&recipient.agent.name)
            );
            for task_id in &terminal_task_ids {
                let task = state.tasks.get(task_id).unwrap();
                assert!(task.delivery.is_none());
                assert!(task.lease.is_none());
                assert!(task.reply_waiters.is_empty());
            }
            assert_eq!(
                state.tasks[&completed.task_id].reply,
                Some(reply("approved"))
            );
            assert!(state.tasks[&canceled.task_id].canceled);
            assert!(state.tasks[&expired.task_id].expired);
            for delivery_id in [
                completed_delivery.delivery_id,
                canceled_delivery.delivery_id,
                expired_delivery.delivery_id,
            ] {
                assert!(!state.tasks_by_delivery.contains_key(&delivery_id));
            }
        }

        clock.advance(Duration::from_millis(
            u64::try_from(TERMINAL_RETENTION_MS).unwrap() + 1,
        ));
        broker.list_agents().await;
        let state = broker.inner.state.lock().await;
        for task_id in terminal_task_ids {
            assert!(!state.tasks.contains_key(&task_id));
        }
    }

    #[tokio::test]
    async fn registration_detach_requeues_near_limit_tasks_without_releasing_sender_capacity() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let sender = register_sender(&broker).await;
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        let mut task_ids = Vec::new();
        let mut delivery_ids = Vec::new();

        for index in 0..MAX_ACTIVE_OUTBOUND_TASKS {
            let handle = broker
                .enqueue(
                    &sender.credentials(),
                    delivery(
                        "implementer",
                        "reviewer",
                        &format!("registration-cancel-{index}"),
                    ),
                )
                .await
                .unwrap();
            task_ids.push(handle.task_id);
            delivery_ids.push(
                broker
                    .wait_next(&recipient.credentials(), None)
                    .await
                    .unwrap()
                    .delivery_id,
            );
        }

        broker
            .remove_registration(&recipient.credentials())
            .await
            .unwrap();

        {
            let state = broker.inner.state.lock().await;
            assert_eq!(
                state.active_tasks_by_agent[&sender.agent.name].len(),
                MAX_ACTIVE_OUTBOUND_TASKS
            );
            assert_eq!(
                state.active_tasks_by_agent[&recipient.agent.name].len(),
                MAX_ACTIVE_OUTBOUND_TASKS
            );
            assert!(state.tasks_by_delivery.is_empty());
            for delivery_id in &delivery_ids {
                assert!(!state.tasks_by_delivery.contains_key(delivery_id));
            }
            for task_id in &task_ids {
                let task = state.tasks.get(task_id).unwrap();
                assert!(!task.canceled);
                assert!(task.delivery.is_some());
                assert!(task.lease.is_none());
                assert!(task.reply_waiters.is_empty());
            }
        }

        let replacement = broker
            .register(agent("reviewer", "w1:p3"), "replacement-session")
            .await
            .unwrap();
        assert_eq!(
            broker
                .enqueue(
                    &sender.credentials(),
                    delivery("implementer", "reviewer", "slot-after-registration-cancel"),
                )
                .await
                .unwrap_err(),
            DomainError::TooManyActiveTasks
        );
        for task_id in &task_ids {
            broker
                .cancel_task(&sender.credentials(), task_id)
                .await
                .unwrap();
        }
        assert!(
            broker
                .enqueue(
                    &sender.credentials(),
                    delivery("implementer", "reviewer", "slot-after-registration-cancel"),
                )
                .await
                .is_ok()
        );
        broker
            .remove_registration(&replacement.credentials())
            .await
            .unwrap();

        clock.advance(Duration::from_millis(
            u64::try_from(TERMINAL_RETENTION_MS).unwrap() + 1,
        ));
        broker.list_agents().await;
        let state = broker.inner.state.lock().await;
        for task_id in task_ids {
            assert!(!state.tasks.contains_key(&task_id));
        }
    }

    #[tokio::test]
    async fn lease_replacement_keeps_only_the_current_delivery_index() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let sender = register_sender(&broker).await;
        let recipient = broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        let handle = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "indexed-lease-rollover"),
            )
            .await
            .unwrap();
        let first = broker
            .wait_next(&recipient.credentials(), None)
            .await
            .unwrap();

        clock.advance(Duration::from_secs(20));
        broker.renew(&sender.credentials()).await.unwrap();
        broker.renew(&recipient.credentials()).await.unwrap();
        clock.advance(Duration::from_secs(20));
        broker.renew(&sender.credentials()).await.unwrap();
        broker.renew(&recipient.credentials()).await.unwrap();
        clock.advance(Duration::from_secs(20));
        let second = broker
            .wait_next(&recipient.credentials(), None)
            .await
            .unwrap();

        {
            let state = broker.inner.state.lock().await;
            assert_eq!(state.tasks_by_delivery.len(), 1);
            assert!(!state.tasks_by_delivery.contains_key(&first.delivery_id));
            assert_eq!(
                state.tasks_by_delivery.get(&second.delivery_id),
                Some(&handle.task_id)
            );
        }
        assert_eq!(
            broker
                .ack_delivery(&recipient.credentials(), &first.delivery_id)
                .await
                .unwrap_err(),
            DomainError::DeliveryNotFound
        );
        broker
            .ack_delivery(&recipient.credentials(), &second.delivery_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn self_delivery_is_indexed_once_and_terminalized_once() {
        let broker = BrokerState::with_clock(TestClock::at(1_000));
        let registration = broker
            .register(agent("implementer", "w1:p1"), "self-session")
            .await
            .unwrap();
        let handle = broker
            .enqueue(
                &registration.credentials(),
                delivery("implementer", "implementer", "self-delivery"),
            )
            .await
            .unwrap();

        {
            let state = broker.inner.state.lock().await;
            let active_tasks = state
                .active_tasks_by_agent
                .get(&registration.agent.name)
                .unwrap();
            assert_eq!(active_tasks.len(), 1);
            assert!(active_tasks.contains(&handle.task_id));
        }

        let delivered = broker
            .wait_next(&registration.credentials(), None)
            .await
            .unwrap();
        broker
            .reply(
                &registration.credentials(),
                &handle.task_id,
                reply("self-approved"),
            )
            .await
            .unwrap();

        let state = broker.inner.state.lock().await;
        assert!(
            !state
                .active_tasks_by_agent
                .contains_key(&registration.agent.name)
        );
        assert!(!state.tasks_by_delivery.contains_key(&delivered.delivery_id));
    }

    #[tokio::test]
    async fn canceled_waiter_resolves_even_if_its_tombstone_is_pruned_first() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let sender = register_sender(&broker).await;
        broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        let handle = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "waiter-before-prune"),
            )
            .await
            .unwrap();
        let waiter = tokio::spawn({
            let broker = broker.clone();
            let sender_credentials = sender.credentials();
            let task_id = handle.task_id.clone();
            async move { broker.wait_for_reply(&sender_credentials, &task_id).await }
        });
        tokio::task::yield_now().await;

        broker
            .cancel_task(&sender.credentials(), &handle.task_id)
            .await
            .unwrap();
        clock.advance(Duration::from_millis(
            u64::try_from(TERMINAL_RETENTION_MS).unwrap() + 1,
        ));
        broker.list_agents().await;
        assert!(
            !broker
                .inner
                .state
                .lock()
                .await
                .tasks
                .contains_key(&handle.task_id)
        );

        assert_eq!(
            waiter.await.unwrap().unwrap_err(),
            DomainError::TaskCanceled
        );
    }

    #[tokio::test]
    async fn terminal_task_tombstones_are_pruned_after_thirty_days() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let sender = register_sender(&broker).await;
        broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        let handle = broker
            .enqueue(
                &sender.credentials(),
                delivery("implementer", "reviewer", "retained-cancel"),
            )
            .await
            .unwrap();

        broker
            .cancel_task(&sender.credentials(), &handle.task_id)
            .await
            .unwrap();
        assert!(
            broker
                .inner
                .state
                .lock()
                .await
                .tasks
                .contains_key(&handle.task_id)
        );

        clock.advance(Duration::from_millis(30 * 24 * 60 * 60 * 1_000 + 1));
        broker.list_agents().await;

        assert!(
            !broker
                .inner
                .state
                .lock()
                .await
                .tasks
                .contains_key(&handle.task_id)
        );
    }

    #[tokio::test]
    async fn retained_task_capacity_rejects_one_over_limit_without_growing_state() {
        // Break caught: removing or changing the retained-task admission check admits a
        // terminal tombstone beyond the bounded replay window.
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock);
        let sender = register_sender(&broker).await;
        broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        prevent_registration_expiry(&broker).await;

        for index in 0..MAX_RETAINED_TASKS {
            let handle = broker
                .enqueue(
                    &sender.credentials(),
                    delivery("implementer", "reviewer", &format!("retained-{index}")),
                )
                .await
                .unwrap();
            broker
                .cancel_task(&sender.credentials(), &handle.task_id)
                .await
                .unwrap();
        }
        let (tasks, terminal_deadlines, delivery_deadlines) = {
            let state = broker.inner.state.lock().await;
            (
                state.tasks.len(),
                state.terminal_deadlines.len(),
                state.delivery_deadlines.len(),
            )
        };

        assert_eq!(
            broker
                .enqueue(
                    &sender.credentials(),
                    delivery("implementer", "reviewer", "one-over-retained-capacity"),
                )
                .await
                .unwrap_err(),
            DomainError::TooManyRetainedTasks
        );
        let state = broker.inner.state.lock().await;
        assert_eq!(state.tasks.len(), tasks);
        assert_eq!(state.terminal_deadlines.len(), terminal_deadlines);
        assert_eq!(state.delivery_deadlines.len(), delivery_deadlines);
    }

    #[tokio::test]
    async fn expired_terminal_task_releases_retained_capacity() {
        // Break caught: retained tombstones that are not pruned at their exact deadline
        // permanently exhaust the bounded task capacity.
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());
        let sender = register_sender(&broker).await;
        broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        prevent_registration_expiry(&broker).await;

        for index in 0..MAX_RETAINED_TASKS {
            let handle = broker
                .enqueue(
                    &sender.credentials(),
                    delivery("implementer", "reviewer", &format!("expired-{index}")),
                )
                .await
                .unwrap();
            broker
                .cancel_task(&sender.credentials(), &handle.task_id)
                .await
                .unwrap();
        }

        clock.advance(Duration::from_millis(
            u64::try_from(TERMINAL_RETENTION_MS).unwrap() + 1,
        ));
        assert!(
            broker
                .enqueue(
                    &sender.credentials(),
                    delivery("implementer", "reviewer", "after-expiry"),
                )
                .await
                .is_ok()
        );
        let state = broker.inner.state.lock().await;
        assert_eq!(state.tasks.len(), 1);
        assert_eq!(state.terminal_deadlines.len(), 0);
        assert_eq!(state.delivery_deadlines.len(), 1);
    }

    #[tokio::test]
    async fn repeated_far_future_cancellations_do_not_outlive_delivery_ttl() {
        let clock = TestClock::at(1_000);
        let broker = BrokerState::with_clock(clock.clone());

        for round in 0..3 {
            let sender = register_sender(&broker).await;
            broker
                .register(
                    agent("reviewer", "w1:p2"),
                    &format!("recipient-session-{round}"),
                )
                .await
                .unwrap();

            for index in 0..8 {
                let mut queued = delivery(
                    "implementer",
                    "reviewer",
                    &format!("far-future-{round}-{index}"),
                );
                queued.created_unix_ms = i64::MAX;
                let handle = broker.enqueue(&sender.credentials(), queued).await.unwrap();
                broker
                    .cancel_task(&sender.credentials(), &handle.task_id)
                    .await
                    .unwrap();
            }

            clock.advance(Duration::from_millis(
                u64::try_from(DELIVERY_TTL_MS).unwrap(),
            ));
            broker.list_agents().await;

            {
                let state = broker.inner.state.lock().await;
                assert_eq!(state.tasks.len(), 8);
                assert!(state.delivery_deadlines.is_empty());
                assert_eq!(state.terminal_deadlines.len(), 8);
            }

            clock.advance(Duration::from_millis(
                u64::try_from(TERMINAL_RETENTION_MS - DELIVERY_TTL_MS).unwrap() + 1,
            ));
            broker.list_agents().await;

            let state = broker.inner.state.lock().await;
            assert!(state.tasks.is_empty());
            assert!(state.delivery_deadlines.is_empty());
            assert!(state.terminal_deadlines.is_empty());
        }
    }
}
