use std::{
    collections::{HashMap, HashSet, VecDeque},
    error::Error,
    io::{self, Read},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicI64, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use axum::{
    Json,
    body::{Body, Bytes, to_bytes},
    extract::{Request, State},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::StreamExt;
use herdr_a2a_core::{
    BrokerClock, BrokerState, Registration, ReplyPayload, RoleLabel, VerifiedPane,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::{
    net::TcpListener,
    sync::{Semaphore, oneshot},
    task::JoinHandle,
};

use crate::runtime::remove_descriptor_if_instance;
#[cfg(test)]
use crate::runtime::remove_descriptor_if_instance_with_observed_hook;
use crate::{
    ApiState, HerdrVerifier, RuntimeDescriptor, RuntimePaths, SqliteTaskStore,
    herdr::HerdrVerificationError, server::recover_broker_state, server_router, write_descriptor,
};

const MAX_METRICS_BODY_BYTES: usize = 1024 * 1024;
type TestBrokerError = Box<dyn Error + Send + Sync>;

fn fill_random(bytes: &mut [u8]) -> std::io::Result<()> {
    std::fs::File::open("/dev/urandom")?.read_exact(bytes)
}

#[derive(Clone)]
struct TestClock(Arc<AtomicI64>);

impl TestClock {
    fn now() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        Self(Arc::new(AtomicI64::new(
            i64::try_from(now).unwrap_or(i64::MAX),
        )))
    }

    fn advance(&self, duration: Duration) {
        let millis = i64::try_from(duration.as_millis()).unwrap_or(i64::MAX);
        self.0.fetch_add(millis, Ordering::SeqCst);
    }
}

impl BrokerClock for TestClock {
    fn now_unix_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Clone, Default)]
struct TestVerifier {
    agents: Arc<tokio::sync::Mutex<HashMap<String, VerifiedPane>>>,
}

#[async_trait]
impl HerdrVerifier for TestVerifier {
    async fn verify(&self, pane_id: &str) -> Result<VerifiedPane, HerdrVerificationError> {
        self.agents
            .lock()
            .await
            .get(pane_id)
            .cloned()
            .ok_or(HerdrVerificationError::CommandFailed)
    }
}

#[derive(Clone, Default)]
struct Metrics {
    task_polls: Arc<AtomicUsize>,
    task_gets: Arc<AtomicUsize>,
    task_lists: Arc<AtomicUsize>,
    task_subscriptions: Arc<AtomicUsize>,
    registrations: Arc<AtomicUsize>,
    renewals: Arc<AtomicUsize>,
    unregistrations: Arc<AtomicUsize>,
    acknowledgements: Arc<AtomicUsize>,
    deliveries: Arc<AtomicUsize>,
    send_messages: Arc<AtomicUsize>,
    streaming_sends: Arc<AtomicUsize>,
}

#[derive(Clone, Default)]
struct TestMiddleware {
    metrics: Metrics,
    stalls: Arc<tokio::sync::Mutex<HashMap<String, Arc<EndpointStallState>>>>,
    failures: Arc<tokio::sync::Mutex<HashSet<String>>>,
    registration_lost_requests: Arc<tokio::sync::Mutex<HashSet<String>>>,
    truncated_endpoints: Arc<tokio::sync::Mutex<HashSet<String>>>,
    truncated_streams: Arc<tokio::sync::Mutex<HashSet<String>>>,
    truncated_responses: Arc<tokio::sync::Mutex<HashSet<String>>>,
    registration_lost_responses: Arc<tokio::sync::Mutex<HashSet<String>>>,
    captured_requests: Arc<tokio::sync::Mutex<HashMap<String, VecDeque<Value>>>>,
    application_errors: Arc<tokio::sync::Mutex<HashMap<String, String>>>,
}

struct EndpointStallState {
    entered: Semaphore,
    released: Semaphore,
}

impl Default for EndpointStallState {
    fn default() -> Self {
        Self {
            entered: Semaphore::new(0),
            released: Semaphore::new(0),
        }
    }
}

#[derive(Clone)]
pub struct EndpointStall(Arc<EndpointStallState>);

impl EndpointStall {
    pub async fn wait_until_entered(&self) {
        self.0.entered.acquire().await.unwrap().forget();
    }

    pub fn release_one(&self) {
        self.0.released.add_permits(1);
    }
}

async fn record_metrics(
    State(state): State<TestMiddleware>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_owned();
    if path == "/v1/register" {
        state.metrics.registrations.fetch_add(1, Ordering::SeqCst);
    }
    if path == "/v1/renew" {
        state.metrics.renewals.fetch_add(1, Ordering::SeqCst);
    }
    if path == "/v1/unregister" {
        state.metrics.unregistrations.fetch_add(1, Ordering::SeqCst);
    }
    let stall = state.stalls.lock().await.get(&path).cloned();
    if let Some(stall) = stall {
        stall.entered.add_permits(1);
        stall.released.acquire().await.unwrap().forget();
    }
    if state.registration_lost_requests.lock().await.remove(&path) {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": {
                    "code": "invalid_registration",
                    "message": "test registration expired before request handling"
                }
            })),
        )
            .into_response();
    }
    if state.truncated_endpoints.lock().await.remove(&path) {
        let truncated = futures::stream::once(async {
            Err::<Bytes, io::Error>(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "test endpoint response was truncated",
            ))
        });
        return Response::new(Body::from_stream(truncated));
    }
    if state.failures.lock().await.contains(&path) {
        return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if path != "/jsonrpc" {
        let response = next.run(request).await;
        let response_stall = state
            .stalls
            .lock()
            .await
            .remove(&format!("/response{path}"));
        if let Some(stall) = response_stall {
            stall.entered.add_permits(1);
            stall.released.acquire().await.unwrap().forget();
        }
        if response.status().is_success()
            && state.registration_lost_responses.lock().await.remove(&path)
        {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": {
                        "code": "invalid_registration",
                        "message": "test response lost after registration expiry"
                    }
                })),
            )
                .into_response();
        }
        if path == "/v1/inbox/ack" && response.status().is_success() {
            state
                .metrics
                .acknowledgements
                .fetch_add(1, Ordering::SeqCst);
        }
        if path == "/v1/inbox/wait" && response.status().is_success() {
            state.metrics.deliveries.fetch_add(1, Ordering::SeqCst);
        }
        return response;
    }
    let (parts, body) = request.into_parts();
    let Ok(bytes) = to_bytes(body, MAX_METRICS_BODY_BYTES).await else {
        return next.run(Request::from_parts(parts, Body::empty())).await;
    };
    let request_value = serde_json::from_slice::<serde_json::Value>(&bytes).ok();
    let method = request_value
        .as_ref()
        .and_then(|value| value.get("method"))
        .and_then(|method| method.as_str())
        .map(str::to_owned);
    if let (Some(method), Some(value)) = (method.as_ref(), request_value.as_ref()) {
        state
            .captured_requests
            .lock()
            .await
            .entry(method.clone())
            .or_default()
            .push_back(value.clone());
    }
    match method.as_deref() {
        Some("SendMessage") => {
            state.metrics.send_messages.fetch_add(1, Ordering::SeqCst);
        }
        Some("SendStreamingMessage") => {
            state.metrics.streaming_sends.fetch_add(1, Ordering::SeqCst);
        }
        Some("GetTask") => {
            state.metrics.task_gets.fetch_add(1, Ordering::SeqCst);
            state.metrics.task_polls.fetch_add(1, Ordering::SeqCst);
        }
        Some("ListTasks") => {
            state.metrics.task_lists.fetch_add(1, Ordering::SeqCst);
            state.metrics.task_polls.fetch_add(1, Ordering::SeqCst);
        }
        Some("SubscribeToTask") => {
            state
                .metrics
                .task_subscriptions
                .fetch_add(1, Ordering::SeqCst);
        }
        _ => {}
    }
    let method_stall = match method.as_deref() {
        Some(method) => state
            .stalls
            .lock()
            .await
            .get(&format!("/jsonrpc:{method}"))
            .cloned(),
        None => None,
    };
    if let Some(stall) = method_stall {
        stall.entered.add_permits(1);
        stall.released.acquire().await.unwrap().forget();
    }
    if let Some(message) = match method.as_deref() {
        Some(method) => state.application_errors.lock().await.remove(method),
        None => None,
    } {
        let id = request_value
            .as_ref()
            .and_then(|value| value.get("id"))
            .cloned()
            .unwrap_or(Value::Null);
        let error = a2a::A2AError::internal(message).to_jsonrpc_error();
        return Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": error,
        }))
        .into_response();
    }
    let response = next
        .run(Request::from_parts(parts, Body::from(bytes)))
        .await;
    let response_stall = match method.as_deref() {
        Some(method) => state
            .stalls
            .lock()
            .await
            .remove(&format!("/jsonrpc-response:{method}")),
        None => None,
    };
    if let Some(stall) = response_stall {
        stall.entered.add_permits(1);
        stall.released.acquire().await.unwrap().forget();
    }
    let truncate_response = match method.as_deref() {
        Some(method) => state.truncated_responses.lock().await.remove(method),
        None => false,
    };
    if truncate_response {
        let (parts, _) = response.into_parts();
        let truncated = futures::stream::once(async {
            Err::<Bytes, io::Error>(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "test JSON-RPC response was truncated after commit",
            ))
        });
        return Response::from_parts(parts, Body::from_stream(truncated));
    }
    let truncate = match method {
        Some(method) => state.truncated_streams.lock().await.remove(&method),
        None => false,
    };
    if truncate {
        let (parts, body) = response.into_parts();
        Response::from_parts(parts, Body::from_stream(body.into_data_stream().take(1)))
    } else {
        response
    }
}

struct TestBrokerRuntimeInner {
    runtime: Arc<TempDir>,
    paths: RuntimePaths,
    database_path: PathBuf,
    socket_path: PathBuf,
    clock: TestClock,
    verifier: TestVerifier,
    reconciliation_stall: tokio::sync::Mutex<Option<Arc<EndpointStallState>>>,
    publication_stall: tokio::sync::Mutex<Option<Arc<EndpointStallState>>>,
    deliveries: Arc<AtomicUsize>,
}

#[derive(Clone)]
pub struct TestBrokerRuntime {
    inner: Arc<TestBrokerRuntimeInner>,
}

impl Default for TestBrokerRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl TestBrokerRuntime {
    pub fn new() -> Self {
        let runtime = Arc::new(tempfile::tempdir().unwrap());
        let socket_path = runtime.path().join("herdr.sock");
        let socket_bytes = socket_path.as_os_str().as_encoded_bytes();
        let session_key = format!("{:x}", Sha256::digest(socket_bytes));
        Self::for_scope(runtime, socket_path, &session_key, "test-workspace")
    }

    pub fn workspace_pair() -> (Self, Self) {
        let runtime = Arc::new(tempfile::tempdir().unwrap());
        let socket_path = runtime.path().join("herdr.sock");
        let socket_bytes = socket_path.as_os_str().as_encoded_bytes();
        let session_key = format!("{:x}", Sha256::digest(socket_bytes));
        (
            Self::for_scope(
                runtime.clone(),
                socket_path.clone(),
                &session_key,
                "workspace-left",
            ),
            Self::for_scope(runtime, socket_path, &session_key, "workspace-right"),
        )
    }

    fn for_scope(
        runtime: Arc<TempDir>,
        socket_path: PathBuf,
        session_key: &str,
        workspace_id: &str,
    ) -> Self {
        let paths =
            RuntimePaths::for_test(&runtime.path().join("herdr-a2a"), session_key, workspace_id);
        let database_path = runtime
            .path()
            .join("state")
            .join(&paths.scope.scope_key)
            .join("tasks.sqlite3");
        std::fs::create_dir_all(database_path.parent().unwrap()).unwrap();
        Self {
            inner: Arc::new(TestBrokerRuntimeInner {
                runtime,
                paths,
                database_path,
                socket_path,
                clock: TestClock::now(),
                verifier: TestVerifier::default(),
                reconciliation_stall: tokio::sync::Mutex::new(None),
                publication_stall: tokio::sync::Mutex::new(None),
                deliveries: Arc::new(AtomicUsize::new(0)),
            }),
        }
    }

    pub fn descriptor_path(&self) -> &Path {
        &self.inner.paths.descriptor
    }

    pub fn database_path(&self) -> &Path {
        &self.inner.database_path
    }

    pub async fn task_count(&self) -> usize {
        let store = SqliteTaskStore::open(&self.inner.database_path).unwrap();
        let count: i64 = store
            .connection
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM tasks", [], |row| row.get(0))
            .unwrap();
        usize::try_from(count).unwrap()
    }

    pub async fn stall_reconciliation(&self) -> EndpointStall {
        let state = Arc::new(EndpointStallState::default());
        *self.inner.reconciliation_stall.lock().await = Some(state.clone());
        EndpointStall(state)
    }

    pub async fn stall_publication(&self) -> EndpointStall {
        let state = Arc::new(EndpointStallState::default());
        *self.inner.publication_stall.lock().await = Some(state.clone());
        EndpointStall(state)
    }

    pub async fn poison_reconciliation(&self) {
        let store = SqliteTaskStore::open(&self.inner.database_path).unwrap();
        store
            .prepare_startup(self.inner.clock.now_unix_ms())
            .await
            .unwrap();
        store
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE broker_meta SET last_registration_epoch = ?1 WHERE singleton = 1",
                [u64::MAX.to_string()],
            )
            .unwrap();
    }

    pub async fn start_broker(&self) -> RunningTestBroker {
        self.try_start_broker().await.unwrap()
    }

    pub async fn try_start_broker(&self) -> Result<RunningTestBroker, TestBrokerError> {
        self.try_start_broker_with_executable(None).await
    }

    pub async fn start_broker_for_executable(&self, executable: &Path) -> RunningTestBroker {
        self.try_start_broker_with_executable(Some(executable))
            .await
            .unwrap()
    }

    async fn try_start_broker_with_executable(
        &self,
        executable: Option<&Path>,
    ) -> Result<RunningTestBroker, TestBrokerError> {
        let store = SqliteTaskStore::open(&self.inner.database_path)?;
        if let Some(stall) = self.inner.reconciliation_stall.lock().await.take() {
            stall.entered.add_permits(1);
            stall.released.acquire().await?.forget();
        }
        let (broker, _) = recover_broker_state(self.inner.clock.clone(), &store).await?;
        if let Some(stall) = self.inner.publication_stall.lock().await.take() {
            stall.entered.add_permits(1);
            stall.released.acquire().await?.forget();
        }

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let base_url = format!("http://{address}");
        let mut token_bytes = [0_u8; 32];
        fill_random(&mut token_bytes)?;
        let token = URL_SAFE_NO_PAD.encode(token_bytes);
        let mut instance_bytes = [0_u8; 32];
        fill_random(&mut instance_bytes)?;
        let metrics = Metrics {
            deliveries: self.inner.deliveries.clone(),
            ..Metrics::default()
        };
        let middleware_state = TestMiddleware {
            metrics: metrics.clone(),
            ..TestMiddleware::default()
        };
        let state = ApiState::new(
            broker.clone(),
            Arc::new(self.inner.verifier.clone()),
            store.identity_store(),
            &self.inner.paths.scope.workspace_id,
            &token,
            instance_bytes,
        )?;
        let broker_instance_id = state.broker_instance_id().to_owned();
        let app = server_router(state, store, format!("{base_url}/jsonrpc")).layer(
            middleware::from_fn_with_state(middleware_state.clone(), record_metrics),
        );
        let descriptor = RuntimeDescriptor {
            session_key: self.inner.paths.scope.session_key.clone(),
            workspace_id: self.inner.paths.scope.workspace_id.clone(),
            base_url: base_url.clone(),
            bearer_token: token.clone(),
            broker_instance_id: broker_instance_id.clone(),
            executable_path: match executable {
                Some(executable) => executable.canonicalize()?,
                None => std::env::current_exe()?.canonicalize()?,
            },
            broker_pid: std::process::id(),
            created_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_millis()
                .try_into()?,
        };
        write_descriptor(&self.inner.paths, &descriptor)?;

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });
        Ok(TestBroker {
            base_url,
            token,
            broker_instance_id,
            broker,
            clock: self.inner.clock.clone(),
            verifier: self.inner.verifier.clone(),
            metrics,
            middleware: middleware_state,
            runtime: self.clone(),
            shutdown: Some(shutdown_tx),
            server: Some(server),
        })
    }
}

pub struct TestBroker {
    base_url: String,
    token: String,
    broker_instance_id: String,
    broker: BrokerState,
    clock: TestClock,
    verifier: TestVerifier,
    metrics: Metrics,
    middleware: TestMiddleware,
    runtime: TestBrokerRuntime,
    shutdown: Option<oneshot::Sender<()>>,
    server: Option<JoinHandle<()>>,
}

pub type RunningTestBroker = TestBroker;

impl TestBroker {
    pub async fn start() -> Self {
        TestBrokerRuntime::new().start_broker().await
    }

    pub async fn add_agent(&self, name: &str, pane_id: &str) {
        self.verifier.agents.lock().await.insert(
            pane_id.to_owned(),
            VerifiedPane {
                pane_id: pane_id.to_owned(),
                workspace_id: self.runtime.inner.paths.scope.workspace_id.clone(),
                role: RoleLabel::parse(name).unwrap(),
                harness: "pi".to_owned(),
                workspace_path: PathBuf::from("/repo"),
            },
        );
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn bearer_token(&self) -> &str {
        &self.token
    }

    pub fn broker_instance_id(&self) -> &str {
        &self.broker_instance_id
    }

    pub async fn registration_count(&self) -> usize {
        self.metrics.registrations.load(Ordering::SeqCst)
    }

    pub async fn active_registration_count(&self) -> usize {
        self.broker.list_agents().await.len()
    }

    pub async fn registration_for_agent(&self, name: &str) -> Registration {
        let panes = self.verifier.agents.lock().await.clone();
        self.broker
            .list_agents()
            .await
            .into_iter()
            .find(|registration| {
                registration.agent.name.as_str() == name
                    || panes.get(&registration.agent.pane_id).is_some_and(|pane| {
                        pane.role.as_str() == name && pane.harness == registration.agent.harness
                    })
            })
            .unwrap()
    }

    pub async fn advance_broker_time(&self, duration: Duration) {
        let mut remaining = duration;
        while !remaining.is_zero() {
            let step = remaining.min(Duration::from_secs(20));
            self.clock.advance(step);
            let registrations = self.broker.list_agents().await;
            for registration in registrations {
                self.broker
                    .renew(&registration.credentials())
                    .await
                    .unwrap();
            }
            remaining = remaining.saturating_sub(step);
        }
    }

    pub fn advance_broker_time_without_renewal(&self, duration: Duration) {
        self.clock.advance(duration);
    }

    pub async fn fail_task(&self, recipient: &Registration, task_id: &str, text: &str) {
        self.broker
            .fail_task(
                &recipient.credentials(),
                task_id,
                ReplyPayload {
                    text: text.to_owned(),
                    metadata: serde_json::json!({}),
                    file_refs: Vec::new(),
                },
            )
            .await
            .unwrap();
    }

    pub async fn reject_task(&self, recipient: &Registration, task_id: &str, text: &str) {
        self.broker
            .reject_task(
                &recipient.credentials(),
                task_id,
                ReplyPayload {
                    text: text.to_owned(),
                    metadata: serde_json::json!({}),
                    file_refs: Vec::new(),
                },
            )
            .await
            .unwrap();
    }

    pub fn task_poll_count(&self) -> usize {
        self.metrics.task_polls.load(Ordering::SeqCst)
    }

    pub fn task_get_count(&self) -> usize {
        self.metrics.task_gets.load(Ordering::SeqCst)
    }

    pub fn task_list_count(&self) -> usize {
        self.metrics.task_lists.load(Ordering::SeqCst)
    }

    pub fn task_subscription_count(&self) -> usize {
        self.metrics.task_subscriptions.load(Ordering::SeqCst)
    }

    pub fn renewal_count(&self) -> usize {
        self.metrics.renewals.load(Ordering::SeqCst)
    }

    pub fn unregistration_count(&self) -> usize {
        self.metrics.unregistrations.load(Ordering::SeqCst)
    }

    pub fn acknowledgement_count(&self) -> usize {
        self.metrics.acknowledgements.load(Ordering::SeqCst)
    }

    pub fn delivery_count(&self) -> usize {
        self.metrics.deliveries.load(Ordering::SeqCst)
    }

    pub fn send_message_count(&self) -> usize {
        self.metrics.send_messages.load(Ordering::SeqCst)
    }

    pub fn streaming_send_count(&self) -> usize {
        self.metrics.streaming_sends.load(Ordering::SeqCst)
    }

    pub async fn take_jsonrpc_request(&self, method: &str) -> Value {
        self.middleware
            .captured_requests
            .lock()
            .await
            .get_mut(method)
            .and_then(VecDeque::pop_front)
            .unwrap_or_else(|| panic!("no captured {method} request"))
    }

    pub async fn fail_jsonrpc_method_once(&self, method: &str, message: &str) {
        self.middleware
            .application_errors
            .lock()
            .await
            .insert(method.to_owned(), message.to_owned());
    }

    pub async fn stall_endpoint(&self, path: &str) -> EndpointStall {
        let state = Arc::new(EndpointStallState::default());
        self.middleware
            .stalls
            .lock()
            .await
            .insert(path.to_owned(), state.clone());
        EndpointStall(state)
    }

    pub async fn stall_endpoint_response_once(&self, path: &str) -> EndpointStall {
        self.stall_endpoint(&format!("/response{path}")).await
    }

    pub async fn stall_jsonrpc_method(&self, method: &str) -> EndpointStall {
        self.stall_endpoint(&format!("/jsonrpc:{method}")).await
    }

    pub async fn stall_jsonrpc_response_once(&self, method: &str) -> EndpointStall {
        self.stall_endpoint(&format!("/jsonrpc-response:{method}"))
            .await
    }

    pub async fn truncate_jsonrpc_stream_once(&self, method: &str) {
        self.middleware
            .truncated_streams
            .lock()
            .await
            .insert(method.to_owned());
    }

    pub async fn truncate_jsonrpc_response_once(&self, method: &str) {
        self.middleware
            .truncated_responses
            .lock()
            .await
            .insert(method.to_owned());
    }

    pub async fn truncate_endpoint_response_once(&self, path: &str) {
        self.middleware
            .truncated_endpoints
            .lock()
            .await
            .insert(path.to_owned());
    }

    pub async fn lose_success_to_registration_expiry_once(&self, path: &str) {
        self.middleware
            .registration_lost_responses
            .lock()
            .await
            .insert(path.to_owned());
    }

    pub async fn expire_registration_before_request_once(&self, path: &str) {
        self.middleware
            .registration_lost_requests
            .lock()
            .await
            .insert(path.to_owned());
    }

    pub async fn fail_endpoint(&self, path: &str) {
        self.middleware
            .failures
            .lock()
            .await
            .insert(path.to_owned());
    }

    pub async fn restore_endpoint(&self, path: &str) {
        self.middleware.failures.lock().await.remove(path);
    }

    pub fn configure_client(&self, command: &mut std::process::Command, executable: &Path) {
        let executable_path = executable.canonicalize().unwrap();
        let created_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .try_into()
            .unwrap();
        write_descriptor(
            &self.runtime.inner.paths,
            &RuntimeDescriptor {
                session_key: self.runtime.inner.paths.scope.session_key.clone(),
                workspace_id: self.runtime.inner.paths.scope.workspace_id.clone(),
                base_url: self.base_url.clone(),
                bearer_token: self.token.clone(),
                broker_instance_id: self.broker_instance_id.clone(),
                executable_path,
                broker_pid: std::process::id(),
                created_unix_ms,
            },
        )
        .unwrap();
        command
            .env("HERDR_SOCKET_PATH", &self.runtime.inner.socket_path)
            .env(
                "HERDR_WORKSPACE_ID",
                &self.runtime.inner.paths.scope.workspace_id,
            )
            .env("TMPDIR", self.runtime.inner.runtime.path())
            .env("XDG_RUNTIME_DIR", self.runtime.inner.runtime.path());
    }

    pub async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(server) = self.server.take() {
            let _ = server.await;
        }
        self.remove_own_descriptor();
    }

    fn remove_own_descriptor(&self) {
        let _ = remove_descriptor_if_instance(&self.runtime.inner.paths, &self.broker_instance_id);
    }
}

#[cfg(test)]
fn remove_test_descriptor_with_hook<F>(
    paths: &RuntimePaths,
    broker_instance_id: &str,
    observed_hook: F,
) where
    F: FnOnce(),
{
    let _ =
        remove_descriptor_if_instance_with_observed_hook(paths, broker_instance_id, observed_hook);
}

impl Drop for TestBroker {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(server) = self.server.take() {
            server.abort();
        }
        self.remove_own_descriptor();
    }
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::mpsc, thread, time::Duration};

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use herdr_a2a_core::{AgentName, DomainError, QueuedDelivery, ValidatedPayload, VerifiedAgent};
    use serde_json::json;

    use super::{TestBrokerRuntime, remove_test_descriptor_with_hook, write_descriptor};
    use crate::read_descriptor;

    #[tokio::test]
    async fn persistent_harness_cleanup_does_not_remove_a_replacement_descriptor() {
        let runtime = TestBrokerRuntime::new();
        let broker = runtime.start_broker().await;
        let paths = runtime.inner.paths.clone();
        let original_instance = broker.broker_instance_id.clone();
        let mut replacement = read_descriptor(&paths).unwrap();
        replacement.broker_instance_id = URL_SAFE_NO_PAD.encode([0x44; 32]);

        let cleanup_paths = paths.clone();
        let (observed_tx, observed_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let cleanup = thread::spawn(move || {
            remove_test_descriptor_with_hook(&cleanup_paths, &original_instance, || {
                observed_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            });
        });
        observed_rx.recv().unwrap();

        let publisher_paths = paths.clone();
        let replacement_to_publish = replacement.clone();
        let (published_tx, published_rx) = mpsc::channel();
        let publisher = thread::spawn(move || {
            write_descriptor(&publisher_paths, &replacement_to_publish).unwrap();
            published_tx.send(()).unwrap();
        });
        let published_before_release = published_rx
            .recv_timeout(Duration::from_millis(100))
            .is_ok();
        release_tx.send(()).unwrap();
        if !published_before_release {
            published_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        }
        cleanup.join().unwrap();
        publisher.join().unwrap();

        assert_eq!(read_descriptor(&paths).unwrap(), replacement);
        drop(broker);
        assert_eq!(read_descriptor(&paths).unwrap(), replacement);
    }

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
        // Break caught: recovery either drops a leased unacknowledged delivery or requeues work
        // whose ACK committed before the old broker stopped.
        let runtime = TestBrokerRuntime::new();
        let first = runtime.start_broker().await;
        let sender = first
            .broker
            .register(agent("implementer", "w1:p1"), "sender-session")
            .await
            .unwrap();
        let recipient = first
            .broker
            .register(agent("reviewer", "w1:p2"), "recipient-session")
            .await
            .unwrap();
        first
            .broker
            .enqueue(&sender.credentials(), delivery("task-unacked"))
            .await
            .unwrap();
        let unacknowledged = first
            .broker
            .wait_next(&recipient.credentials(), Some(Duration::from_secs(1)))
            .await
            .unwrap();
        first
            .broker
            .enqueue(&sender.credentials(), delivery("task-acked"))
            .await
            .unwrap();
        let acknowledged = first
            .broker
            .wait_next(&recipient.credentials(), Some(Duration::from_secs(1)))
            .await
            .unwrap();
        first
            .broker
            .ack_delivery(&recipient.credentials(), &acknowledged.delivery_id)
            .await
            .unwrap();
        let old_credentials = recipient.credentials();
        first.stop().await;

        let second = runtime.start_broker().await;
        assert!(matches!(
            second.broker.renew(&old_credentials).await,
            Err(DomainError::RegistrationNotFound)
        ));
        let replacement = second
            .broker
            .register(agent("reviewer", "w2:p2"), "replacement-session")
            .await
            .unwrap();
        let redelivered = second
            .broker
            .wait_next(&replacement.credentials(), Some(Duration::from_secs(1)))
            .await
            .unwrap();
        assert_eq!(redelivered.task_id, unacknowledged.task_id);
        assert!(matches!(
            second
                .broker
                .wait_next(&replacement.credentials(), Some(Duration::from_millis(20)),)
                .await,
            Err(DomainError::WaitTimedOut)
        ));
        second.stop().await;
    }
}
