use std::{
    fmt, io,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use a2a::SendMessageRequest;
use async_trait::async_trait;
use herdr_a2a_broker::{RuntimeDescriptor, RuntimePaths, read_descriptor, runtime::RuntimeError};
use herdr_a2a_core::{AgentName, RegistrationCredentials, RegistrationEpoch, RegistrationId};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{Mutex, Notify, RwLock};

use crate::{
    DynError,
    coordinator::{BrokerLauncher, LaunchError},
    health::verify_broker_proof,
};

const REGISTRATION_HEADER: &str = "x-herdr-a2a-registration";
const REGISTRATION_EPOCH_HEADER: &str = "x-herdr-a2a-registration-epoch";
const LIFECYCLE_CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const LIFECYCLE_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_RECOVERY_RESPONSE_BYTES: usize = 1024 * 1024;
const BACKOFF_MS: [u64; 6] = [50, 100, 200, 400, 800, 1_000];
const RECOVERY_LAUNCH_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TaskWaitMode {
    Immediate,
    Terminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryMode {
    BrokerReplacement,
    RegistrationRefresh,
}

#[derive(Clone, Debug)]
pub(crate) struct TaskOperation {
    pub requested_agent: String,
    pub agent: String,
    pub tenant: String,
    pub task_id: String,
    pub context_id: Option<String>,
    pub normalized_request: Option<SendMessageRequest>,
    pub wait_mode: TaskWaitMode,
    pub deadline: tokio::time::Instant,
}

#[derive(Clone, Debug)]
pub(crate) struct SessionIdentity {
    pub paths: RuntimePaths,
    pub executable: PathBuf,
    pub pane_id: String,
    pub harness_session_id: String,
    pub agent_name: Option<AgentName>,
}

#[derive(Debug)]
pub(crate) struct BrokerConnection {
    pub descriptor: RuntimeDescriptor,
    pub registration: RegistrationCredentials,
    pub agent_name: AgentName,
    pub http: reqwest::Client,
    pub lifecycle_http: reqwest::Client,
}

pub(crate) struct ConnectionManager {
    identity: SessionIdentity,
    current: RwLock<Arc<BrokerConnection>>,
    recovery_gate: Mutex<()>,
    shutdown: CancellationSignal,
    backend: Arc<dyn RecoveryBackend>,
    launcher: Arc<dyn BrokerLauncher>,
}

#[derive(Clone, Debug)]
pub(crate) struct CancellationSignal {
    cancelled: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl CancellationSignal {
    pub(crate) fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }

    pub(crate) fn cancel(&self) {
        if !self.cancelled.swap(true, Ordering::AcqRel) {
            self.notify.notify_waiters();
        }
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub(crate) async fn cancelled(&self) {
        loop {
            if self.is_cancelled() {
                return;
            }
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

impl Default for CancellationSignal {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub(crate) enum RecoveryError {
    Unavailable(String),
    DescriptorInvalid(String),
    ProofInvalid(String),
    RegistrationRejected(String),
    Deadline,
    Shutdown,
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(reason) => write!(formatter, "broker unavailable: {reason}"),
            Self::DescriptorInvalid(reason) => {
                write!(formatter, "runtime descriptor is invalid: {reason}")
            }
            Self::ProofInvalid(reason) => write!(formatter, "broker proof is invalid: {reason}"),
            Self::RegistrationRejected(reason) => {
                write!(formatter, "broker registration was rejected: {reason}")
            }
            Self::Deadline => formatter.write_str("broker recovery deadline expired"),
            Self::Shutdown => formatter.write_str("broker recovery stopped for shutdown"),
        }
    }
}

impl std::error::Error for RecoveryError {}

#[derive(Debug)]
pub(crate) enum RequestError {
    Recoverable { mode: RecoveryMode, reason: String },
    Final(DynError),
}

impl fmt::Display for RequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Recoverable { reason, .. } => formatter.write_str(reason),
            Self::Final(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for RequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Recoverable { .. } => None,
            Self::Final(error) => Some(error.as_ref()),
        }
    }
}

#[async_trait]
pub(crate) trait RecoveryBackend: Send + Sync {
    async fn read_valid_descriptor(
        &self,
        identity: &SessionIdentity,
    ) -> Result<RuntimeDescriptor, RecoveryError>;

    async fn prove_and_register(
        &self,
        identity: &SessionIdentity,
        descriptor: &RuntimeDescriptor,
    ) -> Result<BrokerConnection, RecoveryError>;

    async fn sleep(
        &self,
        duration: Duration,
        shutdown: &CancellationSignal,
    ) -> Result<(), RecoveryError>;

    fn now(&self) -> tokio::time::Instant;

    fn jitter_percent(&self) -> u8;
}

impl ConnectionManager {
    pub(crate) async fn connect(
        identity: SessionIdentity,
        backend: Arc<dyn RecoveryBackend>,
        launcher: Arc<dyn BrokerLauncher>,
        shutdown: CancellationSignal,
    ) -> Result<Arc<Self>, RecoveryError> {
        let mut identity = identity;
        let connection = establish(
            &identity,
            backend.as_ref(),
            launcher.as_ref(),
            &shutdown,
            None,
            None,
            None,
        )
        .await?;
        identity.agent_name = Some(connection.agent_name.clone());
        Ok(Arc::new(Self {
            identity,
            current: RwLock::new(connection),
            recovery_gate: Mutex::new(()),
            shutdown,
            backend,
            launcher,
        }))
    }

    pub(crate) async fn current(&self) -> Arc<BrokerConnection> {
        self.current.read().await.clone()
    }

    pub(crate) async fn recover(
        &self,
        observed: &Arc<BrokerConnection>,
        mode: RecoveryMode,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<Arc<BrokerConnection>, RecoveryError> {
        let _gate = self.lock_recovery(deadline).await?;
        self.recover_locked(observed, mode, deadline, None).await
    }

    async fn lock_recovery(
        &self,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<tokio::sync::MutexGuard<'_, ()>, RecoveryError> {
        if self.shutdown.is_cancelled() {
            return Err(RecoveryError::Shutdown);
        }
        match deadline {
            Some(deadline) => {
                let remaining = deadline.saturating_duration_since(self.backend.now());
                if remaining.is_zero() {
                    return Err(RecoveryError::Deadline);
                }
                tokio::select! {
                    biased;
                    _ = self.shutdown.cancelled() => Err(RecoveryError::Shutdown),
                    gate = self.recovery_gate.lock() => Ok(gate),
                    elapsed = self.backend.sleep(remaining, &self.shutdown) => {
                        match elapsed {
                            Ok(()) => Err(RecoveryError::Deadline),
                            Err(error) => Err(error),
                        }
                    }
                }
            }
            None => tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => Err(RecoveryError::Shutdown),
                gate = self.recovery_gate.lock() => Ok(gate),
            },
        }
    }

    async fn recover_locked(
        &self,
        observed: &Arc<BrokerConnection>,
        mode: RecoveryMode,
        deadline: Option<tokio::time::Instant>,
        initial_descriptor: Option<RuntimeDescriptor>,
    ) -> Result<Arc<BrokerConnection>, RecoveryError> {
        let installed = self.current().await;
        if !Arc::ptr_eq(&installed, observed)
            && (mode == RecoveryMode::RegistrationRefresh
                || installed.descriptor.broker_instance_id
                    != observed.descriptor.broker_instance_id)
        {
            return Ok(installed);
        }
        let rejected_instance_id = match mode {
            RecoveryMode::BrokerReplacement => {
                Some(observed.descriptor.broker_instance_id.as_str())
            }
            RecoveryMode::RegistrationRefresh => None,
        };
        let replacement = establish(
            &self.identity,
            self.backend.as_ref(),
            self.launcher.as_ref(),
            &self.shutdown,
            rejected_instance_id,
            deadline,
            initial_descriptor,
        )
        .await?;
        *self.current.write().await = replacement.clone();
        Ok(replacement)
    }

    #[cfg(test)]
    async fn recover_replacement(
        &self,
        observed_instance_id: &str,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<Arc<BrokerConnection>, RecoveryError> {
        let observed = self.current().await;
        if observed.descriptor.broker_instance_id != observed_instance_id {
            return Ok(observed);
        }
        self.recover(&observed, RecoveryMode::BrokerReplacement, deadline)
            .await
    }

    pub(crate) async fn recover_if_replaced(
        &self,
        observed_instance_id: &str,
        deadline: tokio::time::Instant,
    ) -> Result<Option<Arc<BrokerConnection>>, RecoveryError> {
        let _gate = self.lock_recovery(Some(deadline)).await?;
        let installed = self.current().await;
        if installed.descriptor.broker_instance_id != observed_instance_id {
            return Ok(Some(installed));
        }
        let descriptor = match await_attempt(
            async {
                self.launcher
                    .ensure(&self.identity.paths.scope, deadline)
                    .await
                    .map_err(map_launch_error)?;
                self.backend.read_valid_descriptor(&self.identity).await
            },
            self.backend.as_ref(),
            &self.shutdown,
            Some(deadline),
        )
        .await
        {
            Ok(descriptor) => descriptor,
            Err(RecoveryError::Unavailable(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        validate_recovered_descriptor(&self.identity, &descriptor)?;
        if descriptor.broker_instance_id == observed_instance_id {
            return Ok(None);
        }
        self.recover_locked(
            &installed,
            RecoveryMode::BrokerReplacement,
            Some(deadline),
            Some(descriptor),
        )
        .await
        .map(Some)
    }

    pub(crate) fn cancel_recovery(&self) {
        self.shutdown.cancel();
    }
}

async fn establish(
    identity: &SessionIdentity,
    backend: &dyn RecoveryBackend,
    launcher: &dyn BrokerLauncher,
    shutdown: &CancellationSignal,
    observed_instance_id: Option<&str>,
    deadline: Option<tokio::time::Instant>,
    mut initial_descriptor: Option<RuntimeDescriptor>,
) -> Result<Arc<BrokerConnection>, RecoveryError> {
    let mut backoff_index = 0_usize;
    loop {
        if shutdown.is_cancelled() {
            return Err(RecoveryError::Shutdown);
        }
        if deadline.is_some_and(|deadline| backend.now() >= deadline) {
            return Err(RecoveryError::Deadline);
        }
        let descriptor = initial_descriptor.take();
        let attempt = async {
            let descriptor = match descriptor {
                Some(descriptor) => descriptor,
                None => {
                    let launch_deadline =
                        deadline.unwrap_or_else(|| backend.now() + RECOVERY_LAUNCH_TIMEOUT);
                    launcher
                        .ensure(&identity.paths.scope, launch_deadline)
                        .await
                        .map_err(map_launch_error)?;
                    backend.read_valid_descriptor(identity).await?
                }
            };
            validate_recovered_descriptor(identity, &descriptor)?;
            if observed_instance_id == Some(descriptor.broker_instance_id.as_str()) {
                return Err(RecoveryError::Unavailable(
                    "runtime descriptor still names the observed broker instance".to_owned(),
                ));
            }
            let connection = backend.prove_and_register(identity, &descriptor).await?;
            if connection.descriptor != descriptor {
                return Err(RecoveryError::ProofInvalid(
                    "proof or registration changed the discovered broker origin or instance"
                        .to_owned(),
                ));
            }
            if identity
                .agent_name
                .as_ref()
                .is_some_and(|expected| expected != &connection.agent_name)
            {
                return Err(RecoveryError::RegistrationRejected(
                    "Herdr verified a different agent name during recovery".to_owned(),
                ));
            }
            Ok(Arc::new(connection))
        };
        let result = await_attempt(attempt, backend, shutdown, deadline).await;
        match result {
            Ok(connection) => return Ok(connection),
            Err(RecoveryError::Unavailable(_)) => {}
            Err(error) => return Err(error),
        }

        let base = Duration::from_millis(BACKOFF_MS[backoff_index.min(BACKOFF_MS.len() - 1)]);
        backoff_index = backoff_index.saturating_add(1);
        let jitter = u32::from(backend.jitter_percent().min(25));
        let delay = base + base.mul_f64(f64::from(jitter) / 100.0);
        let delay = match deadline {
            Some(deadline) => {
                let remaining = deadline.saturating_duration_since(backend.now());
                if remaining.is_zero() {
                    return Err(RecoveryError::Deadline);
                }
                delay.min(remaining)
            }
            None => delay,
        };
        backend.sleep(delay, shutdown).await?;
    }
}

fn map_launch_error(error: LaunchError) -> RecoveryError {
    match error {
        LaunchError::Deadline => RecoveryError::Deadline,
        LaunchError::InvalidScope => {
            RecoveryError::DescriptorInvalid("broker launcher scope changed".to_owned())
        }
        LaunchError::ProofInvalid(reason) => RecoveryError::ProofInvalid(reason),
        LaunchError::Unavailable(reason) => RecoveryError::Unavailable(reason),
    }
}

async fn await_attempt<T>(
    future: impl std::future::Future<Output = Result<T, RecoveryError>>,
    backend: &dyn RecoveryBackend,
    shutdown: &CancellationSignal,
    deadline: Option<tokio::time::Instant>,
) -> Result<T, RecoveryError> {
    match deadline {
        Some(deadline) => {
            let remaining = deadline.saturating_duration_since(backend.now());
            if remaining.is_zero() {
                return Err(RecoveryError::Deadline);
            }
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => Err(RecoveryError::Shutdown),
                result = future => result,
                elapsed = backend.sleep(remaining, shutdown) => match elapsed {
                    Ok(()) => Err(RecoveryError::Deadline),
                    Err(error) => Err(error),
                },
            }
        }
        None => tokio::select! {
            biased;
            _ = shutdown.cancelled() => Err(RecoveryError::Shutdown),
            result = future => result,
        },
    }
}

fn validate_recovered_descriptor(
    identity: &SessionIdentity,
    descriptor: &RuntimeDescriptor,
) -> Result<(), RecoveryError> {
    if descriptor.session_key != identity.paths.scope.session_key {
        return Err(RecoveryError::DescriptorInvalid(
            "session identity changed during recovery".to_owned(),
        ));
    }
    if descriptor.workspace_id != identity.paths.scope.workspace_id {
        return Err(RecoveryError::DescriptorInvalid(
            "workspace identity changed during recovery".to_owned(),
        ));
    }
    if descriptor.executable_path != identity.executable {
        return Err(RecoveryError::DescriptorInvalid(
            "executable identity changed during recovery".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) struct ProductionRecoveryBackend;

impl ProductionRecoveryBackend {
    pub(crate) fn new() -> Self {
        Self
    }
}

#[derive(Deserialize)]
struct RegistrationResponse {
    registration_id: RegistrationId,
    registration_epoch: RegistrationEpoch,
    canonical_name: AgentName,
}

#[derive(Serialize)]
struct RegistrationRequest<'a> {
    pane_id: &'a str,
    harness_session_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_agent_name: Option<&'a AgentName>,
}

#[async_trait]
impl RecoveryBackend for ProductionRecoveryBackend {
    async fn read_valid_descriptor(
        &self,
        identity: &SessionIdentity,
    ) -> Result<RuntimeDescriptor, RecoveryError> {
        read_descriptor(&identity.paths).map_err(|error| match error {
            RuntimeError::Io(error) => RecoveryError::Unavailable(error.to_string()),
            error => RecoveryError::DescriptorInvalid(error.to_string()),
        })
    }

    async fn prove_and_register(
        &self,
        identity: &SessionIdentity,
        descriptor: &RuntimeDescriptor,
    ) -> Result<BrokerConnection, RecoveryError> {
        let proof_http = reqwest::Client::builder()
            .connect_timeout(LIFECYCLE_CONNECT_TIMEOUT)
            .timeout(LIFECYCLE_REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| RecoveryError::Unavailable(error.to_string()))?;
        verify_broker_proof(
            &proof_http,
            &descriptor.base_url,
            &descriptor.bearer_token,
            &descriptor.broker_instance_id,
        )
        .await
        .map_err(classify_proof_error)?;

        let registration_http = authenticated_http(&descriptor.bearer_token, None, true)
            .map_err(|error| RecoveryError::RegistrationRejected(error.to_string()))?;
        let health = registration_http
            .get(format!("{}/health", descriptor.base_url))
            .send()
            .await
            .map_err(|error| RecoveryError::Unavailable(error.to_string()))?;
        if !health.status().is_success() {
            return Err(RecoveryError::RegistrationRejected(format!(
                "health returned HTTP {}",
                health.status()
            )));
        }
        let response = registration_http
            .post(format!("{}/v1/register", descriptor.base_url))
            .json(&RegistrationRequest {
                pane_id: &identity.pane_id,
                harness_session_id: &identity.harness_session_id,
                expected_agent_name: identity.agent_name.as_ref(),
            })
            .send()
            .await
            .map_err(|error| RecoveryError::Unavailable(error.to_string()))?;
        let registration: RegistrationResponse = decode_registration(response).await?;
        if identity
            .agent_name
            .as_ref()
            .is_some_and(|expected| expected != &registration.canonical_name)
        {
            return Err(RecoveryError::RegistrationRejected(
                "Herdr verified a different agent name during recovery".to_owned(),
            ));
        }
        let agent_name = registration.canonical_name;
        let registration = RegistrationCredentials {
            id: registration.registration_id,
            epoch: registration.registration_epoch,
        };
        let epoch = registration.epoch.get().to_string();
        let credentials = Some((registration.id.as_str(), epoch.as_str()));
        let http = authenticated_http(&descriptor.bearer_token, credentials, false)
            .map_err(|error| RecoveryError::RegistrationRejected(error.to_string()))?;
        let lifecycle_http = authenticated_http(&descriptor.bearer_token, credentials, true)
            .map_err(|error| RecoveryError::RegistrationRejected(error.to_string()))?;
        Ok(BrokerConnection {
            descriptor: descriptor.clone(),
            registration,
            agent_name,
            http,
            lifecycle_http,
        })
    }

    async fn sleep(
        &self,
        duration: Duration,
        shutdown: &CancellationSignal,
    ) -> Result<(), RecoveryError> {
        tokio::select! {
            _ = tokio::time::sleep(duration) => Ok(()),
            _ = shutdown.cancelled() => Err(RecoveryError::Shutdown),
        }
    }

    fn now(&self) -> tokio::time::Instant {
        tokio::time::Instant::now()
    }

    fn jitter_percent(&self) -> u8 {
        let mut byte = [0_u8; 1];
        if getrandom::fill(&mut byte).is_ok() {
            byte[0] % 26
        } else {
            0
        }
    }
}

fn classify_proof_error(error: DynError) -> RecoveryError {
    if error
        .downcast_ref::<reqwest::Error>()
        .is_some_and(|error| error.is_connect() || error.is_timeout() || error.is_request())
    {
        RecoveryError::Unavailable(error.to_string())
    } else {
        RecoveryError::ProofInvalid(error.to_string())
    }
}

async fn decode_registration(
    mut response: reqwest::Response,
) -> Result<RegistrationResponse, RecoveryError> {
    let status = response.status();
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| RecoveryError::Unavailable(error.to_string()))?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_RECOVERY_RESPONSE_BYTES {
            return Err(RecoveryError::RegistrationRejected(
                "registration response exceeded its bound".to_owned(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        return Err(decode_registration_error(status, &bytes));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| RecoveryError::RegistrationRejected(error.to_string()))
}

fn decode_registration_error(status: reqwest::StatusCode, encoded: &[u8]) -> RecoveryError {
    let parsed = serde_json::from_slice::<Value>(encoded).ok();
    let code = parsed
        .as_ref()
        .and_then(|value| value.pointer("/error/code"))
        .and_then(Value::as_str);
    let message = parsed
        .as_ref()
        .and_then(|value| value.pointer("/error/message"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| format!("broker returned HTTP {status}"));
    if code == Some("verification_failed") {
        RecoveryError::Unavailable(message)
    } else {
        RecoveryError::RegistrationRejected(message)
    }
}

fn authenticated_http(
    token: &str,
    registration: Option<(&str, &str)>,
    lifecycle: bool,
) -> Result<reqwest::Client, DynError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))?,
    );
    if let Some((registration_id, registration_epoch)) = registration {
        headers.insert(
            HeaderName::from_static(REGISTRATION_HEADER),
            HeaderValue::from_str(registration_id)?,
        );
        headers.insert(
            HeaderName::from_static(REGISTRATION_EPOCH_HEADER),
            HeaderValue::from_str(registration_epoch)?,
        );
    }
    let mut builder = reqwest::Client::builder()
        .default_headers(headers)
        .redirect(reqwest::redirect::Policy::none());
    if lifecycle {
        builder = builder
            .connect_timeout(LIFECYCLE_CONNECT_TIMEOUT)
            .timeout(LIFECYCLE_REQUEST_TIMEOUT);
    }
    builder.build().map_err(|error| {
        io::Error::other(format!("HTTP client construction failed: {error}")).into()
    })
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        path::{Path, PathBuf},
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use async_trait::async_trait;
    use herdr_a2a_broker::{RuntimeDescriptor, RuntimePaths, RuntimeScope};
    use herdr_a2a_core::{AgentName, RegistrationCredentials, RegistrationEpoch, RegistrationId};
    use tokio::time::Instant;

    use super::{
        BrokerConnection, CancellationSignal, ConnectionManager, RecoveryBackend, RecoveryError,
        RecoveryMode, SessionIdentity,
    };
    use crate::coordinator::{BrokerLauncher, LaunchError};

    const FIRST_INSTANCE: &str = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI";
    const SECOND_INSTANCE: &str = "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM";

    struct ReadyLauncher {
        calls: AtomicUsize,
        observed: Mutex<Vec<(RuntimeScope, Instant)>>,
        block_next: AtomicBool,
        entered: tokio::sync::Semaphore,
        release: tokio::sync::Semaphore,
    }

    impl ReadyLauncher {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                observed: Mutex::new(Vec::new()),
                block_next: AtomicBool::new(false),
                entered: tokio::sync::Semaphore::new(0),
                release: tokio::sync::Semaphore::new(0),
            }
        }

        fn observed(&self) -> Vec<(RuntimeScope, Instant)> {
            self.observed.lock().unwrap().clone()
        }

        fn block_next(&self) {
            self.block_next.store(true, Ordering::SeqCst);
        }

        async fn wait_until_entered(&self) {
            self.entered.acquire().await.unwrap().forget();
        }

        fn release(&self) {
            self.release.add_permits(1);
        }
    }

    #[async_trait]
    impl BrokerLauncher for ReadyLauncher {
        async fn ensure(
            &self,
            scope: &RuntimeScope,
            deadline: Instant,
        ) -> Result<RuntimeDescriptor, LaunchError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.observed
                .lock()
                .unwrap()
                .push((scope.clone(), deadline));
            if self.block_next.swap(false, Ordering::SeqCst) {
                self.entered.add_permits(1);
                self.release.acquire().await.unwrap().forget();
            }
            let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
            let mut ready = descriptor(FIRST_INSTANCE, &executable);
            ready.session_key = scope.session_key.clone();
            ready.workspace_id = scope.workspace_id.clone();
            Ok(ready)
        }
    }

    #[derive(Clone)]
    struct ScriptedBackend {
        state: Arc<Mutex<ScriptedState>>,
        block_proof: Arc<tokio::sync::Semaphore>,
        block_sleep: Arc<tokio::sync::Semaphore>,
    }

    struct ScriptedState {
        descriptors: VecDeque<Result<RuntimeDescriptor, RecoveryError>>,
        registrations: VecDeque<Result<BrokerConnection, RecoveryError>>,
        reads: usize,
        proofs: usize,
        sleeps: Vec<Duration>,
        bearer_before_proof: bool,
        observed_identities: Vec<(String, String)>,
        observed_agent_names: Vec<Option<String>>,
        block_next_proof: bool,
        hold_sleeps: bool,
        now: Instant,
    }

    impl ScriptedBackend {
        fn new(descriptors: Vec<RuntimeDescriptor>, registrations: Vec<BrokerConnection>) -> Self {
            Self {
                state: Arc::new(Mutex::new(ScriptedState {
                    descriptors: descriptors.into_iter().map(Ok).collect(),
                    registrations: registrations.into_iter().map(Ok).collect(),
                    reads: 0,
                    proofs: 0,
                    sleeps: Vec::new(),
                    bearer_before_proof: false,
                    observed_identities: Vec::new(),
                    observed_agent_names: Vec::new(),
                    block_next_proof: false,
                    hold_sleeps: false,
                    now: Instant::now(),
                })),
                block_proof: Arc::new(tokio::sync::Semaphore::new(0)),
                block_sleep: Arc::new(tokio::sync::Semaphore::new(0)),
            }
        }

        fn counts(&self) -> (usize, usize) {
            let state = self.state.lock().unwrap();
            (state.reads, state.proofs)
        }

        fn sleeps(&self) -> Vec<Duration> {
            self.state.lock().unwrap().sleeps.clone()
        }

        fn current_time(&self) -> Instant {
            self.state.lock().unwrap().now
        }

        fn observed_agent_names(&self) -> Vec<Option<String>> {
            self.state.lock().unwrap().observed_agent_names.clone()
        }

        fn hold_sleeps(&self) {
            self.state.lock().unwrap().hold_sleeps = true;
        }
    }

    #[async_trait]
    impl RecoveryBackend for ScriptedBackend {
        async fn read_valid_descriptor(
            &self,
            identity: &SessionIdentity,
        ) -> Result<RuntimeDescriptor, RecoveryError> {
            let mut state = self.state.lock().unwrap();
            state.reads += 1;
            state.observed_identities.push((
                identity.pane_id.clone(),
                identity.harness_session_id.clone(),
            ));
            state
                .descriptors
                .pop_front()
                .unwrap_or_else(|| Err(RecoveryError::Unavailable("no descriptor".to_owned())))
        }

        async fn prove_and_register(
            &self,
            identity: &SessionIdentity,
            descriptor: &RuntimeDescriptor,
        ) -> Result<BrokerConnection, RecoveryError> {
            let block = {
                let mut state = self.state.lock().unwrap();
                state.proofs += 1;
                state.observed_identities.push((
                    identity.pane_id.clone(),
                    identity.harness_session_id.clone(),
                ));
                state.observed_agent_names.push(
                    identity
                        .agent_name
                        .as_ref()
                        .map(|name| name.as_str().to_owned()),
                );
                state.bearer_before_proof |= false;
                std::mem::take(&mut state.block_next_proof)
            };
            if block {
                self.block_proof.acquire().await.unwrap().forget();
            }
            let result = self
                .state
                .lock()
                .unwrap()
                .registrations
                .pop_front()
                .unwrap_or_else(|| Err(RecoveryError::Unavailable("no registration".to_owned())));
            let _ = descriptor;
            result
        }

        async fn sleep(
            &self,
            duration: Duration,
            shutdown: &CancellationSignal,
        ) -> Result<(), RecoveryError> {
            if shutdown.is_cancelled() {
                return Err(RecoveryError::Shutdown);
            }
            let hold = {
                let mut state = self.state.lock().unwrap();
                state.sleeps.push(duration);
                if !state.hold_sleeps {
                    state.now += duration;
                }
                state.hold_sleeps
            };
            if hold {
                self.block_sleep.acquire().await.unwrap().forget();
            }
            tokio::task::yield_now().await;
            if shutdown.is_cancelled() {
                Err(RecoveryError::Shutdown)
            } else {
                Ok(())
            }
        }

        fn now(&self) -> Instant {
            self.current_time()
        }

        fn jitter_percent(&self) -> u8 {
            0
        }
    }

    #[test]
    fn registration_verification_pending_is_transient() {
        let error = super::decode_registration_error(
            reqwest::StatusCode::FORBIDDEN,
            br#"{"error":{"code":"verification_failed","message":"Herdr could not verify this pane"}}"#,
        );

        assert!(matches!(
            error,
            RecoveryError::Unavailable(message)
                if message == "Herdr could not verify this pane"
        ));
    }

    #[test]
    fn registration_rejections_other_than_verification_pending_remain_final() {
        for encoded in [
            br#"{"error":{"code":"agent_identity_changed","message":"Herdr could not verify this pane"}}"#.as_slice(),
            br#"{"error":{"code":"unknown","message":"rejected"}}"#.as_slice(),
            b"not-json".as_slice(),
        ] {
            assert!(matches!(
                super::decode_registration_error(reqwest::StatusCode::FORBIDDEN, encoded),
                RecoveryError::RegistrationRejected(_)
            ));
        }
    }

    #[tokio::test]
    async fn initial_connection_retries_transient_registration_failure() {
        let executable = identity().executable;
        let expected = connection(FIRST_INSTANCE, &executable);
        let backend = Arc::new(ScriptedBackend::new(
            vec![expected.descriptor.clone(), expected.descriptor.clone()],
            vec![expected],
        ));
        backend
            .state
            .lock()
            .unwrap()
            .registrations
            .push_front(Err(RecoveryError::Unavailable(
                "verification pending".to_owned(),
            )));

        ConnectionManager::connect(
            identity(),
            backend.clone(),
            Arc::new(ReadyLauncher::new()),
            CancellationSignal::new(),
        )
        .await
        .unwrap();

        assert_eq!(backend.counts(), (2, 2));
        assert_eq!(backend.sleeps(), [Duration::from_millis(50)]);
    }

    fn identity() -> SessionIdentity {
        SessionIdentity {
            paths: RuntimePaths::for_test(
                PathBuf::from("/tmp").as_path(),
                "test-session",
                "test-workspace",
            ),
            executable: std::env::current_exe().unwrap().canonicalize().unwrap(),
            pane_id: "w1:p1".to_owned(),
            harness_session_id: "pi-session-1".to_owned(),
            agent_name: None,
        }
    }

    fn descriptor(instance: &str, executable: &Path) -> RuntimeDescriptor {
        RuntimeDescriptor {
            session_key: "test-session".to_owned(),
            workspace_id: "test-workspace".to_owned(),
            base_url: "http://127.0.0.1:4312".to_owned(),
            bearer_token: "REREREREREREREREREREREREREREREREREREREREREQ".to_owned(),
            broker_instance_id: instance.to_owned(),
            executable_path: executable.to_path_buf(),
            broker_pid: std::process::id(),
            created_unix_ms: 1,
        }
    }

    fn connection(instance: &str, executable: &Path) -> BrokerConnection {
        BrokerConnection {
            descriptor: descriptor(instance, executable),
            registration: RegistrationCredentials {
                id: RegistrationId::new(),
                epoch: RegistrationEpoch::from_u64(if instance == FIRST_INSTANCE { 1 } else { 2 }),
            },
            agent_name: AgentName::parse("implementer").unwrap(),
            http: reqwest::Client::new(),
            lifecycle_http: reqwest::Client::new(),
        }
    }

    async fn connected(
        backend: Arc<ScriptedBackend>,
        shutdown: CancellationSignal,
    ) -> Arc<ConnectionManager> {
        ConnectionManager::connect(
            identity(),
            backend,
            Arc::new(ReadyLauncher::new()),
            shutdown,
        )
        .await
        .unwrap()
    }

    async fn connected_with_launcher(
        backend: Arc<ScriptedBackend>,
        launcher: Arc<ReadyLauncher>,
        shutdown: CancellationSignal,
    ) -> Arc<ConnectionManager> {
        ConnectionManager::connect(identity(), backend, launcher, shutdown)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn launcher_runs_before_initial_and_recovery_descriptor_reads_with_original_deadline() {
        // Break caught: initial connect omits lazy launch, or replacement resets a caller's
        // absolute deadline before asking the coordinator for a broker.
        let executable = identity().executable;
        let first = connection(FIRST_INSTANCE, &executable);
        let second = connection(SECOND_INSTANCE, &executable);
        let backend = Arc::new(ScriptedBackend::new(
            vec![first.descriptor.clone(), second.descriptor.clone()],
            vec![first, second],
        ));
        let launcher = Arc::new(ReadyLauncher::new());
        let manager =
            connected_with_launcher(backend.clone(), launcher.clone(), CancellationSignal::new())
                .await;
        assert_eq!(backend.counts().0, 1);
        assert_eq!(launcher.observed().len(), 1);

        let observed = manager.current().await;
        let original_deadline = backend.current_time() + Duration::from_secs(3);
        manager
            .recover(
                &observed,
                RecoveryMode::BrokerReplacement,
                Some(original_deadline),
            )
            .await
            .unwrap();

        let launcher_calls = launcher.observed();
        assert_eq!(launcher_calls.len(), 2);
        assert_eq!(launcher_calls[1].0, identity().paths.scope);
        assert_eq!(launcher_calls[1].1, original_deadline);
        assert_eq!(backend.counts().0, 2);
    }

    #[tokio::test]
    async fn concurrent_replacement_observation_is_single_flight_under_the_recovery_gate() {
        // Break caught: recover_if_replaced launches and reads before taking the recovery gate,
        // so concurrent transport failures invoke multiple launchers and registrations.
        let executable = identity().executable;
        let first = connection(FIRST_INSTANCE, &executable);
        let second = connection(SECOND_INSTANCE, &executable);
        let backend = Arc::new(ScriptedBackend::new(
            vec![
                first.descriptor.clone(),
                second.descriptor.clone(),
                second.descriptor.clone(),
                second.descriptor.clone(),
            ],
            vec![first, second],
        ));
        let launcher = Arc::new(ReadyLauncher::new());
        let manager =
            connected_with_launcher(backend.clone(), launcher.clone(), CancellationSignal::new())
                .await;
        let observed = manager.current().await;
        let deadline = backend.current_time() + Duration::from_secs(3);
        backend.hold_sleeps();
        launcher.block_next();

        let first_recovery = tokio::spawn({
            let manager = manager.clone();
            let observed = observed.clone();
            async move {
                manager
                    .recover_if_replaced(&observed.descriptor.broker_instance_id, deadline)
                    .await
            }
        });
        launcher.wait_until_entered().await;
        let second_recovery = tokio::spawn({
            let manager = manager.clone();
            let observed = observed.clone();
            async move {
                manager
                    .recover_if_replaced(&observed.descriptor.broker_instance_id, deadline)
                    .await
            }
        });
        tokio::task::yield_now().await;
        launcher.release();

        let (left, right) = tokio::time::timeout(Duration::from_secs(2), async {
            (
                first_recovery.await.unwrap(),
                second_recovery.await.unwrap(),
            )
        })
        .await
        .expect("concurrent replacement observation did not remain bounded");
        let left = left.unwrap().unwrap();
        let right = right.unwrap().unwrap();
        assert!(Arc::ptr_eq(&left, &right));
        assert_eq!(launcher.observed().len(), 2);
        assert_eq!(launcher.observed()[1].1, deadline);
        assert_eq!(backend.counts(), (2, 2));
    }

    #[tokio::test]
    async fn queued_replacement_observation_expires_without_resetting_or_launching() {
        // Break caught: waiting for the recovery gate resets the absolute deadline or performs a
        // second launch after the queued caller's original deadline has elapsed.
        let executable = identity().executable;
        let first = connection(FIRST_INSTANCE, &executable);
        let second = connection(SECOND_INSTANCE, &executable);
        let backend = Arc::new(ScriptedBackend::new(
            vec![first.descriptor.clone(), second.descriptor.clone()],
            vec![first, second],
        ));
        let launcher = Arc::new(ReadyLauncher::new());
        let manager =
            connected_with_launcher(backend.clone(), launcher.clone(), CancellationSignal::new())
                .await;
        let observed = manager.current().await;
        launcher.block_next();
        let winner_deadline = backend.current_time() + Duration::from_secs(3);
        let winner = tokio::spawn({
            let manager = manager.clone();
            let instance = observed.descriptor.broker_instance_id.clone();
            async move {
                manager
                    .recover_if_replaced(&instance, winner_deadline)
                    .await
            }
        });
        launcher.wait_until_entered().await;

        let queued_deadline = backend.current_time() + Duration::from_millis(50);
        assert!(matches!(
            manager
                .recover_if_replaced(&observed.descriptor.broker_instance_id, queued_deadline,)
                .await,
            Err(RecoveryError::Deadline)
        ));
        assert_eq!(launcher.observed().len(), 2);
        assert_eq!(launcher.observed()[1].1, winner_deadline);

        launcher.release();
        assert!(matches!(
            winner.await.unwrap(),
            Ok(Some(_)) | Err(RecoveryError::Deadline)
        ));
    }

    #[tokio::test]
    async fn queued_replacement_observation_cancels_before_launching() {
        // Break caught: cancellation is checked only after a queued observer acquires the gate and
        // invokes the launcher, allowing shutdown to create a replacement broker.
        let executable = identity().executable;
        let first = connection(FIRST_INSTANCE, &executable);
        let second = connection(SECOND_INSTANCE, &executable);
        let backend = Arc::new(ScriptedBackend::new(
            vec![first.descriptor.clone(), second.descriptor.clone()],
            vec![first, second],
        ));
        backend.hold_sleeps();
        let launcher = Arc::new(ReadyLauncher::new());
        let shutdown = CancellationSignal::new();
        let manager = connected_with_launcher(backend, launcher.clone(), shutdown.clone()).await;
        let observed = manager.current().await;
        launcher.block_next();
        let deadline = Instant::now() + Duration::from_secs(3);
        let winner = tokio::spawn({
            let manager = manager.clone();
            let instance = observed.descriptor.broker_instance_id.clone();
            async move { manager.recover_if_replaced(&instance, deadline).await }
        });
        launcher.wait_until_entered().await;
        let queued = tokio::spawn({
            let manager = manager.clone();
            let instance = observed.descriptor.broker_instance_id.clone();
            async move { manager.recover_if_replaced(&instance, deadline).await }
        });
        tokio::task::yield_now().await;
        shutdown.cancel();

        assert!(matches!(
            winner.await.unwrap(),
            Err(RecoveryError::Shutdown)
        ));
        assert!(matches!(
            queued.await.unwrap(),
            Err(RecoveryError::Shutdown)
        ));
        assert_eq!(launcher.observed().len(), 2);
    }

    #[tokio::test]
    async fn recovery_discards_old_credentials_and_requires_a_new_instance() {
        // Break caught: recovery republishes the observed instance or mutates credentials in an
        // existing snapshot instead of atomically installing a new immutable connection.
        let executable = identity().executable;
        let first = connection(FIRST_INSTANCE, &executable);
        let first_registration = first.registration.clone();
        let second = connection(SECOND_INSTANCE, &executable);
        let second_registration = second.registration.clone();
        let backend = Arc::new(ScriptedBackend::new(
            vec![
                first.descriptor.clone(),
                first.descriptor.clone(),
                second.descriptor.clone(),
            ],
            vec![first, second],
        ));
        let manager = connected(backend.clone(), CancellationSignal::new()).await;
        let old = manager.current().await;

        let recovered = manager
            .recover_replacement(FIRST_INSTANCE, None)
            .await
            .unwrap();

        assert_eq!(old.registration, first_registration);
        assert_eq!(old.descriptor.broker_instance_id, FIRST_INSTANCE);
        assert_eq!(recovered.registration, second_registration);
        assert_eq!(recovered.descriptor.broker_instance_id, SECOND_INSTANCE);
        assert!(!Arc::ptr_eq(&old, &recovered));
        assert_eq!(manager.current().await.registration, second_registration);
    }

    #[tokio::test]
    async fn registration_refresh_reproves_and_accepts_the_verified_same_instance() {
        let executable = identity().executable;
        let first = connection(FIRST_INSTANCE, &executable);
        let refreshed = connection(FIRST_INSTANCE, &executable);
        let refreshed_registration = refreshed.registration.clone();
        let backend = Arc::new(ScriptedBackend::new(
            vec![first.descriptor.clone(), refreshed.descriptor.clone()],
            vec![first, refreshed],
        ));
        let manager = connected(backend.clone(), CancellationSignal::new()).await;
        let observed = manager.current().await;

        let recovered = manager
            .recover(&observed, RecoveryMode::RegistrationRefresh, None)
            .await
            .unwrap();

        assert_eq!(recovered.descriptor.broker_instance_id, FIRST_INSTANCE);
        assert_eq!(recovered.registration, refreshed_registration);
        assert_ne!(recovered.registration, observed.registration);
        assert!(!Arc::ptr_eq(&observed, &recovered));
        assert_eq!(backend.counts(), (2, 2));
        assert_eq!(
            backend.observed_agent_names(),
            vec![None, Some("implementer".to_owned())]
        );
    }

    #[tokio::test]
    async fn replacement_recovery_still_fences_a_same_instance_refresh() {
        // Break caught: a registration refresh installs a new connection pointer for the same
        // broker before a queued replacement recovery checks the single-flight result.
        let executable = identity().executable;
        let first = connection(FIRST_INSTANCE, &executable);
        let refreshed = connection(FIRST_INSTANCE, &executable);
        let second = connection(SECOND_INSTANCE, &executable);
        let backend = Arc::new(ScriptedBackend::new(
            vec![
                first.descriptor.clone(),
                refreshed.descriptor.clone(),
                second.descriptor.clone(),
            ],
            vec![first, refreshed, second],
        ));
        let manager = connected(backend.clone(), CancellationSignal::new()).await;
        let observed = manager.current().await;
        let refreshed = manager
            .recover(&observed, RecoveryMode::RegistrationRefresh, None)
            .await
            .unwrap();

        let recovered = manager
            .recover(&observed, RecoveryMode::BrokerReplacement, None)
            .await
            .unwrap();

        assert_eq!(refreshed.descriptor.broker_instance_id, FIRST_INSTANCE);
        assert_eq!(recovered.descriptor.broker_instance_id, SECOND_INSTANCE);
        assert_eq!(backend.counts(), (3, 3));
    }

    #[tokio::test]
    async fn concurrent_recovery_is_single_flight() {
        // Break caught: callers queued behind recovery perform duplicate proof/registration after
        // the first caller has already installed a replacement instance.
        let executable = identity().executable;
        let first = connection(FIRST_INSTANCE, &executable);
        let second = connection(SECOND_INSTANCE, &executable);
        let backend = Arc::new(ScriptedBackend::new(
            vec![first.descriptor.clone(), second.descriptor.clone()],
            vec![first, second],
        ));
        let manager = connected(backend.clone(), CancellationSignal::new()).await;
        backend.state.lock().unwrap().block_next_proof = true;
        let first_recovery = tokio::spawn({
            let manager = manager.clone();
            async move {
                manager
                    .recover_replacement(FIRST_INSTANCE, None)
                    .await
                    .unwrap()
            }
        });
        tokio::task::yield_now().await;
        let second_recovery = tokio::spawn({
            let manager = manager.clone();
            async move {
                manager
                    .recover_replacement(FIRST_INSTANCE, None)
                    .await
                    .unwrap()
            }
        });
        backend.block_proof.add_permits(1);

        let a = first_recovery.await.unwrap();
        let b = second_recovery.await.unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(backend.counts(), (2, 2));
    }

    #[tokio::test]
    async fn recovery_never_sends_bearer_before_proof() {
        // Break caught: reconnection reuses the old authenticated client for descriptor proof.
        let executable = identity().executable;
        let first = connection(FIRST_INSTANCE, &executable);
        let second = connection(SECOND_INSTANCE, &executable);
        let backend = Arc::new(ScriptedBackend::new(
            vec![first.descriptor.clone(), second.descriptor.clone()],
            vec![first, second],
        ));
        let manager = connected(backend.clone(), CancellationSignal::new()).await;

        manager
            .recover_replacement(FIRST_INSTANCE, None)
            .await
            .unwrap();

        assert!(!backend.state.lock().unwrap().bearer_before_proof);
    }

    #[tokio::test]
    async fn recovery_rejects_redirect_origin_executable_and_session_changes() {
        // Break caught: recovery accepts a descriptor for a different executable/session or lets
        // a proof/backend substitute a different origin after protected discovery.
        let expected = identity();
        let first = connection(FIRST_INSTANCE, &expected.executable);
        let mut changed_executable = descriptor(SECOND_INSTANCE, &expected.executable);
        changed_executable.executable_path = PathBuf::from("/different/executable");
        let backend = Arc::new(ScriptedBackend::new(
            vec![first.descriptor.clone(), changed_executable],
            vec![first],
        ));
        let manager = connected(backend, CancellationSignal::new()).await;
        assert!(matches!(
            manager.recover_replacement(FIRST_INSTANCE, None).await,
            Err(RecoveryError::DescriptorInvalid(_))
        ));

        let first = connection(FIRST_INSTANCE, &expected.executable);
        let second = connection(SECOND_INSTANCE, &expected.executable);
        let mut substituted = second;
        substituted.descriptor.base_url = "http://127.0.0.1:5999".to_owned();
        let backend = Arc::new(ScriptedBackend::new(
            vec![
                first.descriptor.clone(),
                descriptor(SECOND_INSTANCE, &expected.executable),
            ],
            vec![first, substituted],
        ));
        let manager = connected(backend, CancellationSignal::new()).await;
        assert!(matches!(
            manager.recover_replacement(FIRST_INSTANCE, None).await,
            Err(RecoveryError::ProofInvalid(_))
        ));
    }

    #[test]
    fn recovery_rejects_a_descriptor_from_another_workspace() {
        // Break caught: recovery re-discovers by session alone and replaces the connection with
        // a descriptor carrying another workspace's identity and credentials.
        let identity = identity();
        let mut replacement = descriptor(SECOND_INSTANCE, &identity.executable);
        replacement.workspace_id = "other-workspace".to_owned();

        assert!(matches!(
            super::validate_recovered_descriptor(&identity, &replacement),
            Err(RecoveryError::DescriptorInvalid(_))
        ));
    }

    #[tokio::test]
    async fn recovery_backoff_is_50_100_200_400_800_1000_ms_without_jitter() {
        // Break caught: retry delays start at the wrong value, fail to double, or exceed the cap.
        let executable = identity().executable;
        let first = connection(FIRST_INSTANCE, &executable);
        let second = connection(SECOND_INSTANCE, &executable);
        let backend = Arc::new(ScriptedBackend::new(
            std::iter::once(first.descriptor.clone())
                .chain(std::iter::repeat_n(second.descriptor.clone(), 8))
                .collect(),
            vec![first],
        ));
        backend.state.lock().unwrap().registrations.extend(
            (0..7)
                .map(|_| Err(RecoveryError::Unavailable("offline".to_owned())))
                .chain(std::iter::once(Ok(second))),
        );
        let manager = connected(backend.clone(), CancellationSignal::new()).await;
        let virtual_started = backend.current_time();

        manager
            .recover_replacement(FIRST_INSTANCE, None)
            .await
            .unwrap();

        assert_eq!(
            backend.sleeps(),
            [50, 100, 200, 400, 800, 1_000, 1_000].map(Duration::from_millis)
        );
        assert_eq!(backend.counts(), (9, 9));
        assert_eq!(
            backend.current_time(),
            virtual_started + Duration::from_millis(3_550)
        );
    }

    #[tokio::test]
    async fn bounded_recovery_stops_at_the_original_deadline() {
        // Break caught: each reconnect attempt resets a finite operation deadline.
        let executable = identity().executable;
        let first = connection(FIRST_INSTANCE, &executable);
        let backend = Arc::new(ScriptedBackend::new(
            vec![first.descriptor.clone()],
            vec![first],
        ));
        let manager = connected(backend.clone(), CancellationSignal::new()).await;
        let deadline = backend.current_time() + Duration::from_millis(175);

        let error = manager
            .recover_replacement(FIRST_INSTANCE, Some(deadline))
            .await
            .unwrap_err();

        assert!(matches!(error, RecoveryError::Deadline));
        let completed = backend.current_time();
        assert_eq!(completed, deadline);

        let held_gate = manager.recovery_gate.lock().await;
        let queued_deadline = backend.current_time() + Duration::from_millis(25);
        let queued = manager
            .recover_replacement(FIRST_INSTANCE, Some(queued_deadline))
            .await;
        assert!(matches!(queued, Err(RecoveryError::Deadline)));
        assert_eq!(backend.current_time(), queued_deadline);
        drop(held_gate);
    }

    #[tokio::test]
    async fn unbounded_recovery_stops_only_on_shutdown() {
        // Break caught: omitted deadlines impose a hidden retry limit or miss a cancellation wake.
        let executable = identity().executable;
        let first = connection(FIRST_INSTANCE, &executable);
        let backend = Arc::new(ScriptedBackend::new(
            vec![first.descriptor.clone()],
            vec![first],
        ));
        let shutdown = CancellationSignal::new();
        let manager = connected(backend, shutdown.clone()).await;
        let recovering = tokio::spawn({
            let manager = manager.clone();
            async move { manager.recover_replacement(FIRST_INSTANCE, None).await }
        });
        tokio::task::yield_now().await;

        shutdown.cancel();

        assert!(matches!(
            recovering.await.unwrap(),
            Err(RecoveryError::Shutdown)
        ));
    }
}
