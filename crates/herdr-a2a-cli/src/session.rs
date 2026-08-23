use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    env, fmt,
    future::Future,
    io::{self, BufRead, BufReader},
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use a2a::{
    AgentCard, GetTaskRequest, Message, Part, Role, SendMessageConfiguration, SendMessageRequest,
    SendMessageResponse, StreamResponse, SubscribeToTaskRequest, TRANSPORT_PROTOCOL_JSONRPC, Task,
    TaskState, new_context_id, new_task_id,
};
use async_trait::async_trait;
use futures::{StreamExt, TryStreamExt, stream::BoxStream};
use herdr_a2a_broker::RuntimePaths;
use herdr_a2a_core::{
    AgentName, RoleLabel, validate_task_id,
    validation::{MAX_METADATA_BYTES, MAX_TEXT_BYTES},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use tokio::{
    io::AsyncWriteExt,
    sync::{Mutex, Semaphore, mpsc, oneshot},
    task::JoinSet,
    time::sleep,
};

use crate::{
    DynError, ProcessRunner, ShutdownSignals,
    coordinator::ProductionBrokerLauncher,
    doctor, managed,
    recovery::{
        BrokerConnection, CancellationSignal, ConnectionManager, ProductionRecoveryBackend,
        RecoveryMode, RequestError, SessionIdentity, TaskOperation, TaskWaitMode,
    },
    required_path, status,
    team::{AgentRegistrationWaiter, RegisteredTeamAgent, TeamOrchestrator, TeamRequest},
    validate_herdr_executable,
};

const MAX_ACTIVE_OUTBOUND_TASKS: usize = 32;
const REGISTRATION_HEADER: &str = "x-herdr-a2a-registration";
const REGISTRATION_EPOCH_HEADER: &str = "x-herdr-a2a-registration-epoch";
const MAX_IN_FLIGHT_REQUESTS: usize = 64;
const MAX_NDJSON_LINE_BYTES: usize = 512 * 1024;
const MAX_REQUEST_ID_BYTES: usize = 256;
const MAX_METHOD_BYTES: usize = 64;
const MAX_PARAMS_BYTES: usize = 511 * 1024;
// The empty ID is reserved for protocol errors whose input has no valid bounded string ID.
const PROTOCOL_SENTINEL_ID: &str = "";
const RENEWAL_BASE_MS: u64 = 10_000;
const RENEWAL_JITTER_MS: u64 = 2_000;
const OUTPUT_QUEUE_CAPACITY: usize = 32;
const REQUEST_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
const WRITER_DRAIN_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_PRIVATE_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_IDENTITY_BYTES: usize = 1024;
const MAX_SESSION_ERROR_CANDIDATES: usize = 1_024;
const MIN_SEND_WAIT_MS: u64 = 1_000;
const DEFAULT_SEND_WAIT_MS: u64 = 60_000;
const MAX_SEND_WAIT_MS: u64 = 86_400_000;
const RECOVERY_AGENT_CARD_RETRY_BASE: Duration = Duration::from_millis(50);
const RECOVERY_AGENT_CARD_RETRY_MAX: Duration = Duration::from_secs(1);
const REGISTRATION_AUTH_LOST_TYPE_URL: &str = "type.herdr.dev/herdr.a2a.RegistrationAuthLost";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionRequest {
    id: String,
    method: String,
    params: Value,
}

#[derive(Deserialize, Serialize)]
struct SessionResponse {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<SessionError>,
}

#[derive(Deserialize, Serialize)]
struct SessionError {
    code: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<SessionErrorDetails>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionErrorDetails {
    candidates: Vec<AgentName>,
}

impl SessionResponse {
    fn success(id: String, result: Value) -> Self {
        Self {
            id,
            result: Some(result),
            error: None,
        }
    }

    fn failure(id: String, code: &str, message: impl Into<String>) -> Self {
        Self {
            id,
            result: None,
            error: Some(SessionError {
                code: code.to_owned(),
                message: message.into(),
                details: None,
            }),
        }
    }

    fn failure_with_candidates(
        id: String,
        code: &str,
        message: impl Into<String>,
        candidates: Vec<AgentName>,
    ) -> Self {
        Self {
            id,
            result: None,
            error: Some(SessionError {
                code: code.to_owned(),
                message: message.into(),
                details: Some(SessionErrorDetails { candidates }),
            }),
        }
    }
}

#[derive(Debug)]
struct PrivateBrokerError {
    code: String,
    message: String,
    candidates: Vec<AgentName>,
}

impl fmt::Display for PrivateBrokerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for PrivateBrokerError {}

#[derive(Debug)]
struct AcknowledgementError(String);

impl fmt::Display for AcknowledgementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for AcknowledgementError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateErrorEnvelope {
    error: PrivateErrorBody,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateErrorBody {
    code: String,
    message: String,
    #[serde(default)]
    candidates: Vec<AgentName>,
}

#[derive(Clone)]
struct SessionContext {
    connections: Arc<ConnectionManager>,
    outbound: Arc<Semaphore>,
    inbox_wait: Arc<Semaphore>,
    caller_pane_id: String,
    workspace_id: String,
    cwd: PathBuf,
}

#[derive(Clone)]
struct SessionOutput {
    sender: mpsc::Sender<OutputRecord>,
    in_flight: Arc<std::sync::Mutex<HashSet<String>>>,
}

impl SessionOutput {
    fn start() -> (Self, tokio::task::JoinHandle<io::Result<()>>) {
        let (sender, receiver) = mpsc::channel(OUTPUT_QUEUE_CAPACITY);
        let in_flight = Arc::new(std::sync::Mutex::new(HashSet::new()));
        let writer = tokio::spawn(writer_loop(
            tokio::io::stdout(),
            receiver,
            in_flight.clone(),
        ));
        (Self { sender, in_flight }, writer)
    }

    async fn write(&self, response: SessionResponse) -> io::Result<()> {
        self.write_record(response, None).await
    }

    async fn write_request(&self, response: SessionResponse) -> io::Result<()> {
        let release_id = response.id.clone();
        self.write_record(response, Some(release_id)).await
    }

    async fn write_record(
        &self,
        response: SessionResponse,
        release_id: Option<String>,
    ) -> io::Result<()> {
        let (completed, completion) = oneshot::channel();
        self.sender
            .send(OutputRecord {
                response,
                release_id,
                completed,
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "stdout writer stopped"))?;
        completion
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "stdout writer stopped"))?
    }

    fn reserve_id(&self, id: &str) -> Result<(), ReserveIdError> {
        let mut ids = self
            .in_flight
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if ids.contains(id) {
            return Err(ReserveIdError::Duplicate);
        }
        if ids.len() >= MAX_IN_FLIGHT_REQUESTS {
            return Err(ReserveIdError::Full);
        }
        ids.insert(id.to_owned());
        Ok(())
    }
}

enum ReserveIdError {
    Duplicate,
    Full,
}

struct OutputRecord {
    response: SessionResponse,
    release_id: Option<String>,
    completed: oneshot::Sender<io::Result<()>>,
}

type PendingOutput = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

fn pending_output(output: &SessionOutput, response: SessionResponse) -> PendingOutput {
    let output = output.clone();
    Box::pin(async move { output.write(response).await })
}

async fn writer_loop<W>(
    mut writer: W,
    mut records: mpsc::Receiver<OutputRecord>,
    in_flight: Arc<std::sync::Mutex<HashSet<String>>>,
) -> io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    while let Some(record) = records.recv().await {
        let OutputRecord {
            response,
            release_id,
            completed,
        } = record;
        let mut encoded = serde_json::to_vec(&response).map_err(io::Error::other)?;
        encoded.push(b'\n');
        if let Some(id) = release_id {
            in_flight
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .remove(&id);
        }
        if let Err(error) = writer.write_all(&encoded).await {
            let _ = completed.send(Err(io::Error::new(error.kind(), error.to_string())));
            return Err(error);
        }
        if let Err(error) = writer.flush().await {
            let _ = completed.send(Err(io::Error::new(error.kind(), error.to_string())));
            return Err(error);
        }
        let _ = completed.send(Ok(()));
    }
    Ok(())
}

struct OrderedListState {
    next_sequence: u64,
    pending: BTreeMap<u64, SessionResponse>,
}

#[derive(Clone)]
struct OrderedListOutput {
    output: SessionOutput,
    state: Arc<Mutex<OrderedListState>>,
}

impl OrderedListOutput {
    fn new(output: SessionOutput) -> Self {
        Self {
            output,
            state: Arc::new(Mutex::new(OrderedListState {
                next_sequence: 0,
                pending: BTreeMap::new(),
            })),
        }
    }

    async fn write(&self, sequence: u64, response: SessionResponse) -> io::Result<()> {
        let mut state = self.state.lock().await;
        state.pending.insert(sequence, response);
        loop {
            let sequence = state.next_sequence;
            let Some(response) = state.pending.remove(&sequence) else {
                break;
            };
            self.output.write_request(response).await?;
            state.next_sequence += 1;
        }
        Ok(())
    }
}

pub async fn run(harness_session_id: String) -> Result<(), DynError> {
    if harness_session_id.is_empty() || harness_session_id.len() > MAX_IDENTITY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--harness-session-id must be non-empty and bounded",
        )
        .into());
    }
    let pane_id = env::var("HERDR_PANE_ID")
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "HERDR_PANE_ID is required"))?;
    if pane_id.is_empty() || pane_id.len() > MAX_IDENTITY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HERDR_PANE_ID must be non-empty and bounded",
        )
        .into());
    }
    let paths = RuntimePaths::discover()?;
    let workspace_id = paths.scope.workspace_id.clone();
    let cwd = env::current_dir()?;
    let current_executable = env::current_exe()?.canonicalize()?;
    let shutdown = ShutdownSignals::install()?;

    let shutdown = shutdown.wait();
    tokio::pin!(shutdown);
    let identity = SessionIdentity {
        paths,
        executable: current_executable,
        pane_id: pane_id.clone(),
        harness_session_id,
        agent_name: None,
    };
    let recovery_shutdown = CancellationSignal::new();
    let connecting = ConnectionManager::connect(
        identity,
        Arc::new(ProductionRecoveryBackend::new()),
        Arc::new(ProductionBrokerLauncher::new()),
        recovery_shutdown.clone(),
    );
    tokio::pin!(connecting);
    let connections = tokio::select! {
        _ = &mut shutdown => {
            recovery_shutdown.cancel();
            return Ok(());
        }
        connection = &mut connecting => connection?,
    };
    let context = SessionContext {
        connections,
        outbound: Arc::new(Semaphore::new(MAX_ACTIVE_OUTBOUND_TASKS)),
        inbox_wait: Arc::new(Semaphore::new(1)),
        caller_pane_id: pane_id,
        workspace_id,
        cwd,
    };

    let result = run_loop(context.clone(), shutdown.as_mut()).await;
    context.connections.cancel_recovery();
    let unregister_result = unregister(&context).await;
    if let Err(error) = unregister_result {
        eprintln!("herdr-a2a: bounded unregister did not complete: {error}");
    }
    result
}

async fn run_loop<F>(context: SessionContext, mut shutdown: Pin<&mut F>) -> Result<(), DynError>
where
    F: Future<Output = ()>,
{
    let mut lines = stdin_lines();
    let (output, mut writer) = SessionOutput::start();
    let list_output = OrderedListOutput::new(output.clone());
    let mut list_sequence = 0_u64;
    let mut requests = JoinSet::new();
    let mut renewal = renewal_attempt(context.clone());
    let mut control_output: Option<PendingOutput> = None;

    let primary_result: Result<(), DynError> = 'session: loop {
        tokio::select! {
            line = lines.recv(), if control_output.is_none() => {
                let Some(line) = line else { break 'session Ok(()); };
                let request = match line {
                    InputFrame::Line(line) => match parse_session_request(&line) {
                        Ok(request) => request,
                        Err(response) => {
                            control_output = Some(pending_output(&output, *response));
                            continue;
                        }
                    },
                    InputFrame::Oversized => {
                        control_output = Some(pending_output(&output, SessionResponse::failure(
                            PROTOCOL_SENTINEL_ID.to_owned(),
                            "protocol_error",
                            "NDJSON request exceeds the bounded envelope size",
                        )));
                        continue;
                    }
                    InputFrame::Io(error) => break 'session Err(error.into()),
                };
                match output.reserve_id(&request.id) {
                    Ok(()) => {}
                    Err(ReserveIdError::Duplicate) => {
                        control_output = Some(pending_output(&output, SessionResponse::failure(
                            request.id,
                            "duplicate_id",
                            "request ID is already in flight",
                        )));
                        continue;
                    }
                    Err(ReserveIdError::Full) => {
                        control_output = Some(pending_output(&output, SessionResponse::failure(
                            request.id,
                            "too_many_requests",
                            "too many requests are in flight",
                        )));
                        continue;
                    }
                }
                let request_context = context.clone();
                let request_output = output.clone();
                if request.method == "list_agents" {
                    let request_list_output = list_output.clone();
                    let request_sequence = list_sequence;
                    let Some(next_sequence) = list_sequence.checked_add(1) else {
                        break 'session Err(
                            io::Error::other("list request sequence exhausted").into()
                        );
                    };
                    list_sequence = next_sequence;
                    requests.spawn(async move {
                        let response = execute_request(request_context, request).await;
                        request_list_output.write(request_sequence, response).await
                    });
                    continue;
                }
                requests.spawn(async move {
                    let response = execute_request(request_context, request).await;
                    request_output.write_request(response).await
                });
            }
            completed = async {
                control_output
                    .as_mut()
                    .expect("select guard requires pending output")
                    .await
            }, if control_output.is_some() => {
                control_output = None;
                if let Err(error) = completed {
                    break 'session Err(error.into());
                }
            }
            _ = shutdown.as_mut() => {
                context.connections.cancel_recovery();
                break 'session Ok(());
            }
            renewed = &mut renewal => {
                if let Err(error) = renewed {
                    eprintln!("herdr-a2a: registration renewal did not complete: {error}");
                }
                renewal = renewal_attempt(context.clone());
            }
            completed = requests.join_next(), if !requests.is_empty() => {
                match completed {
                    Some(Ok(Ok(()))) => {}
                    Some(Ok(Err(error))) => break 'session Err(error.into()),
                    Some(Err(error)) => break 'session Err(error.into()),
                    None => {}
                }
            }
        }
    };

    context.connections.cancel_recovery();
    // One epilogue owns every exit. The loop's primary error wins; on a clean exit,
    // the first non-cancellation producer error wins, followed by the writer result.
    drop(lines);
    drop(control_output);
    let mut producer_error = None;
    let drained = tokio::time::timeout(REQUEST_DRAIN_TIMEOUT, async {
        while let Some(completed) = requests.join_next().await {
            match completed {
                Ok(Err(error)) if producer_error.is_none() => {
                    producer_error = Some(error.into());
                }
                Err(error) if !error.is_cancelled() && producer_error.is_none() => {
                    producer_error = Some(error.into());
                }
                Ok(Ok(())) | Ok(Err(_)) | Err(_) => {}
            }
        }
    })
    .await;
    if drained.is_err() {
        requests.abort_all();
        while let Some(completed) = requests.join_next().await {
            if let Err(error) = completed
                && !error.is_cancelled()
                && producer_error.is_none()
            {
                producer_error = Some(error.into());
            }
        }
    }
    drop(list_output);
    drop(output);
    let writer_result = match tokio::time::timeout(WRITER_DRAIN_TIMEOUT, &mut writer).await {
        Ok(Ok(result)) => result.map_err(Into::into),
        Ok(Err(error)) => Err(error.into()),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "stdout writer did not finish its bounded drain",
        )
        .into()),
    };
    resolve_run_loop_result(primary_result, producer_error, writer_result)
}

fn resolve_run_loop_result(
    primary_result: Result<(), DynError>,
    producer_error: Option<DynError>,
    writer_result: Result<(), DynError>,
) -> Result<(), DynError> {
    match primary_result {
        Err(error) => Err(error),
        Ok(()) => match producer_error {
            Some(error) => Err(error),
            None => writer_result,
        },
    }
}

async fn execute_request(context: SessionContext, request: SessionRequest) -> SessionResponse {
    let id = request.id.clone();
    match handle_request(context.clone(), request).await {
        Ok(value) => SessionResponse::success(id, value),
        Err(error) => {
            if let Some(acknowledgement) = error.downcast_ref::<AcknowledgementError>() {
                SessionResponse::failure(id, "acknowledgement_failed", acknowledgement.to_string())
            } else if let Some(private) = error.downcast_ref::<PrivateBrokerError>()
                && !private.candidates.is_empty()
            {
                SessionResponse::failure_with_candidates(
                    id,
                    &private.code,
                    &private.message,
                    private.candidates.clone(),
                )
            } else {
                SessionResponse::failure(id, "request_failed", error.to_string())
            }
        }
    }
}

enum InputFrame {
    Line(Vec<u8>),
    Oversized,
    Io(io::Error),
}

enum BoundedLine {
    Line(Vec<u8>),
    Oversized,
    Eof,
}

fn read_bounded_line(reader: &mut impl BufRead) -> io::Result<BoundedLine> {
    let mut line = Vec::new();
    let mut oversized = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if oversized {
                Ok(BoundedLine::Oversized)
            } else if line.is_empty() {
                Ok(BoundedLine::Eof)
            } else {
                Ok(BoundedLine::Line(line))
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |position| position + 1);
        let content_len = newline.unwrap_or(available.len());
        if !oversized {
            if line.len().saturating_add(content_len) > MAX_NDJSON_LINE_BYTES {
                line.clear();
                oversized = true;
            } else {
                line.extend_from_slice(&available[..content_len]);
            }
        }
        reader.consume(consumed);
        if newline.is_some() {
            if oversized {
                return Ok(BoundedLine::Oversized);
            }
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(BoundedLine::Line(line));
        }
    }
}

fn stdin_lines() -> mpsc::Receiver<InputFrame> {
    let (sender, receiver) = mpsc::channel(64);
    std::thread::spawn(move || {
        let stdin = io::stdin();
        let mut reader = BufReader::new(stdin.lock());
        loop {
            let frame = match read_bounded_line(&mut reader) {
                Ok(BoundedLine::Line(line)) => InputFrame::Line(line),
                Ok(BoundedLine::Oversized) => InputFrame::Oversized,
                Ok(BoundedLine::Eof) => break,
                Err(error) => InputFrame::Io(error),
            };
            if sender.blocking_send(frame).is_err() {
                return;
            }
        }
    });
    receiver
}

fn parse_session_request(line: &[u8]) -> Result<SessionRequest, Box<SessionResponse>> {
    let value: Value = serde_json::from_slice(line).map_err(|error| {
        Box::new(SessionResponse::failure(
            PROTOCOL_SENTINEL_ID.to_owned(),
            "protocol_error",
            format!("invalid JSON request: {error}"),
        ))
    })?;
    let recovered_id = value
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty() && id.len() <= MAX_REQUEST_ID_BYTES)
        .map(str::to_owned);
    let request: SessionRequest = serde_json::from_value(value).map_err(|error| {
        Box::new(SessionResponse::failure(
            recovered_id
                .clone()
                .unwrap_or_else(|| PROTOCOL_SENTINEL_ID.to_owned()),
            "protocol_error",
            format!("invalid request envelope: {error}"),
        ))
    })?;
    if request.id.is_empty() || request.id.len() > MAX_REQUEST_ID_BYTES {
        return Err(Box::new(SessionResponse::failure(
            PROTOCOL_SENTINEL_ID.to_owned(),
            "protocol_error",
            "request ID must be a non-empty bounded string",
        )));
    }
    if request.method.is_empty() || request.method.len() > MAX_METHOD_BYTES {
        return Err(Box::new(SessionResponse::failure(
            request.id,
            "protocol_error",
            "request method must be a non-empty bounded string",
        )));
    }
    if !request.params.is_object()
        || serde_json::to_vec(&request.params).is_ok_and(|bytes| bytes.len() > MAX_PARAMS_BYTES)
    {
        return Err(Box::new(SessionResponse::failure(
            request.id,
            "protocol_error",
            "request params must be a bounded object",
        )));
    }
    Ok(request)
}

fn renewal_delay() -> Duration {
    let mut bytes = [0_u8; 2];
    let jitter = if getrandom::fill(&mut bytes).is_ok() {
        u64::from(u16::from_ne_bytes(bytes)) % (RENEWAL_JITTER_MS + 1)
    } else {
        0
    };
    Duration::from_millis(RENEWAL_BASE_MS + jitter)
}

async fn renew(context: &SessionContext) -> Result<(), DynError> {
    loop {
        let connection = context.connections.current().await;
        match post_empty::<Value>(
            &connection,
            &connection.lifecycle_http,
            &format!("{}/v1/renew", connection.descriptor.base_url),
        )
        .await
        {
            Ok(_) => return Ok(()),
            Err(RequestError::Recoverable { mode, .. }) => {
                context.connections.recover(&connection, mode, None).await?;
            }
            Err(RequestError::Final(error)) => return Err(error),
        }
    }
}

fn renewal_attempt(
    context: SessionContext,
) -> Pin<Box<dyn Future<Output = Result<(), DynError>> + Send>> {
    Box::pin(async move {
        sleep(renewal_delay()).await;
        renew(&context).await
    })
}

async fn unregister(context: &SessionContext) -> Result<(), DynError> {
    let connection = context.connections.current().await;
    post_empty::<Value>(
        &connection,
        &connection.lifecycle_http,
        &format!("{}/v1/unregister", connection.descriptor.base_url),
    )
    .await
    .map(|_| ())
    .map_err(request_error_into_dyn)
}

async fn handle_request(
    context: SessionContext,
    request: SessionRequest,
) -> Result<Value, DynError> {
    match request.method.as_str() {
        "list_agents" => list_agents(&context, request.params).await,
        "create_team" => create_team(&context, request.params).await,
        "status" => workspace_status(&context, request.params).await,
        "doctor" => doctor_report(request.params).await,
        "managed_remove" => managed_remove(request.params).await,
        "send_message" => send_message(&context, request.params).await,
        "wait_for_message" => wait_for_message(&context, request.params).await,
        "reply" => reply(&context, request.params).await,
        "cancel_task" => cancel_task(&context, request.params).await,
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "unknown session method").into()),
    }
}

async fn workspace_status(context: &SessionContext, params: Value) -> Result<Value, DynError> {
    let _: EmptyParams = serde_json::from_value(params)?;
    let connection = context.connections.current().await;
    let result = status::collect_from_descriptor(&connection.descriptor).await?;
    Ok(serde_json::to_value(result)?)
}

async fn doctor_report(params: Value) -> Result<Value, DynError> {
    let _: EmptyParams = serde_json::from_value(params)?;
    Ok(serde_json::to_value(doctor::collect().await)?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedRemoveParams {
    purge: bool,
}

async fn managed_remove(params: Value) -> Result<Value, DynError> {
    let request: ManagedRemoveParams = serde_json::from_value(params)?;
    Ok(serde_json::to_value(
        managed::remove_for_session(request.purge).await?,
    )?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateTeamParams {
    roles: Vec<String>,
    self_role: Option<String>,
}

#[derive(Clone)]
struct SessionAgentWaiter {
    connections: Arc<ConnectionManager>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WaitedAgents {
    generation: u64,
    agents: Vec<BrokerDirectoryAgent>,
}

#[async_trait]
impl AgentRegistrationWaiter for SessionAgentWaiter {
    async fn wait_for_agents(
        &self,
        pane_ids: &[String],
        timeout: Duration,
    ) -> io::Result<Vec<RegisteredTeamAgent>> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if tokio::time::Instant::now() >= deadline {
                return Ok(Vec::new());
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let millis = remaining.as_millis();
            let rounded_up = millis + u128::from(Duration::from_millis(millis as u64) < remaining);
            let timeout_ms = u64::try_from(rounded_up).unwrap_or(u64::MAX).max(1_000);
            let connection = self.connections.current().await;
            let wait_url = format!("{}/v1/agents/wait", connection.descriptor.base_url);
            let wait_body = json!({"pane_ids": pane_ids, "timeout_ms": timeout_ms});
            let request =
                post_json::<WaitedAgents>(&connection, &connection.http, &wait_url, &wait_body);
            let result = match tokio::time::timeout_at(deadline, request).await {
                Ok(result) => result,
                Err(_) => return Ok(Vec::new()),
            };
            match result {
                Ok(waited) => {
                    let _generation = waited.generation;
                    return waited
                        .agents
                        .into_iter()
                        .map(|agent| {
                            if agent.status != "live"
                                || !is_bounded_control_free(&agent.pane_id, MAX_IDENTITY_BYTES)
                                || !is_bounded_control_free(&agent.harness, MAX_IDENTITY_BYTES)
                                || !pane_ids.contains(&agent.pane_id)
                            {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "broker returned an invalid team directory",
                                ));
                            }
                            Ok(RegisteredTeamAgent {
                                pane_id: agent.pane_id,
                                canonical_name: agent.canonical_name,
                            })
                        })
                        .collect();
                }
                Err(RequestError::Recoverable { mode, .. }) => {
                    self.connections
                        .recover(&connection, mode, Some(deadline))
                        .await
                        .map_err(|error| io::Error::other(error.to_string()))?;
                }
                Err(RequestError::Final(error)) => {
                    return Err(io::Error::other(error.to_string()));
                }
            }
        }
    }
}

async fn create_team(context: &SessionContext, params: Value) -> Result<Value, DynError> {
    let params: CreateTeamParams = serde_json::from_value(params)?;
    let request = TeamRequest::new(
        context.caller_pane_id.clone(),
        context.workspace_id.clone(),
        context.cwd.clone(),
        params.self_role,
        params.roles,
    )?;
    let herdr = validate_herdr_executable(&required_path("HERDR_BIN_PATH")?)?;
    let runner = ProcessRunner::with_limits(1, Duration::from_secs(35), 64 * 1024);
    let waiter = SessionAgentWaiter {
        connections: context.connections.clone(),
    };
    let result = TeamOrchestrator::new(herdr, runner, waiter)
        .create_team(request)
        .await?;
    Ok(serde_json::to_value(result)?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyParams {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerAgentDirectory {
    agents: Vec<BrokerDirectoryAgent>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerDirectoryAgent {
    canonical_name: AgentName,
    role: RoleLabel,
    pane_id: String,
    harness: String,
    status: String,
}

#[derive(Serialize)]
struct WorkspaceAgentDirectory {
    agents: Vec<WorkspaceDirectoryAgent>,
}

#[derive(Serialize)]
struct WorkspaceDirectoryAgent {
    canonical_name: AgentName,
    role: RoleLabel,
    pane_id: String,
    harness: String,
    status: String,
    workspace_id: String,
}

async fn list_agents(context: &SessionContext, params: Value) -> Result<Value, DynError> {
    let _: EmptyParams = serde_json::from_value(params)?;
    loop {
        let connection = context.connections.current().await;
        match get_json(
            &connection,
            &connection.http,
            &format!("{}/v1/agents", connection.descriptor.base_url),
        )
        .await
        {
            Ok(value) => {
                let directory: BrokerAgentDirectory = serde_json::from_value(value)?;
                let mut agents = Vec::with_capacity(directory.agents.len());
                for agent in directory.agents {
                    if agent.status != "live"
                        || !is_bounded_control_free(&agent.pane_id, MAX_IDENTITY_BYTES)
                        || !is_bounded_control_free(&agent.harness, MAX_IDENTITY_BYTES)
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "broker returned an invalid agent directory",
                        )
                        .into());
                    }
                    agents.push(WorkspaceDirectoryAgent {
                        canonical_name: agent.canonical_name,
                        role: agent.role,
                        pane_id: agent.pane_id,
                        harness: agent.harness,
                        status: agent.status,
                        workspace_id: connection.descriptor.workspace_id.clone(),
                    });
                }
                return Ok(serde_json::to_value(WorkspaceAgentDirectory { agents })?);
            }
            Err(RequestError::Recoverable { mode, .. }) => {
                context.connections.recover(&connection, mode, None).await?;
            }
            Err(RequestError::Final(error)) => return Err(error),
        }
    }
}

fn is_bounded_control_free(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= maximum_bytes && !value.chars().any(char::is_control)
}

#[derive(Deserialize)]
#[serde(untagged)]
enum SendParams {
    New(NewSendParams),
    Resume(ResumeSendParams),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewSendParams {
    #[serde(alias = "to")]
    agent: String,
    text: String,
    #[serde(default = "empty_object")]
    metadata: Value,
    conversation_id: Option<String>,
    #[serde(default = "default_wait")]
    wait: bool,
    timeout_ms: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResumeSendParams {
    #[serde(alias = "to")]
    agent: String,
    resume_task_id: String,
    timeout_ms: Option<u64>,
}

fn empty_object() -> Value {
    json!({})
}

const fn default_wait() -> bool {
    true
}

async fn send_message(context: &SessionContext, params: Value) -> Result<Value, DynError> {
    let params: SendParams = serde_json::from_value(params)?;
    match params {
        SendParams::New(params) => send_new_message(context, params).await,
        SendParams::Resume(params) => resume_message(context, params).await,
    }
}

fn validate_agent(agent: &str) -> Result<(), DynError> {
    AgentName::parse(agent)
        .map(|_| ())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "agent name is invalid").into())
}

fn send_wait_duration(timeout_ms: Option<u64>) -> Result<Duration, DynError> {
    let timeout_ms = timeout_ms.unwrap_or(DEFAULT_SEND_WAIT_MS);
    if !(MIN_SEND_WAIT_MS..=MAX_SEND_WAIT_MS).contains(&timeout_ms) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "send wait timeout must be between {MIN_SEND_WAIT_MS} and {MAX_SEND_WAIT_MS} milliseconds"
            ),
        )
        .into());
    }
    Ok(Duration::from_millis(timeout_ms))
}

async fn send_new_message(
    context: &SessionContext,
    params: NewSendParams,
) -> Result<Value, DynError> {
    validate_agent_target(&params.agent)?;
    validate_text(&params.text)?;
    if let Some(conversation_id) = params.conversation_id.as_deref() {
        validate_task_id(conversation_id).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "conversation ID is invalid")
        })?;
    }
    let deadline = tokio::time::Instant::now() + send_wait_duration(params.timeout_ms)?;
    let canonical_agent = resolve_new_target(context, &params.agent, deadline).await?;
    let metadata = object_metadata(params.metadata)?;
    let _permit = context
        .outbound
        .clone()
        .try_acquire_owned()
        .map_err(|_| io::Error::other("too many active outbound tasks"))?;
    let mut message = Message::new(Role::User, vec![Part::text(params.text)]);
    let task_id = new_task_id();
    let conversation_id = params.conversation_id.unwrap_or_else(new_context_id);
    message.task_id = Some(task_id.clone());
    message.context_id = Some(conversation_id.clone());
    message.metadata = metadata;
    let tenant = canonical_agent.as_str().to_owned();
    let request = SendMessageRequest {
        message,
        configuration: (!params.wait).then_some(SendMessageConfiguration {
            accepted_output_modes: Some(vec!["text/plain".to_owned()]),
            task_push_notification_config: None,
            history_length: None,
            return_immediately: Some(true),
        }),
        metadata: None,
        tenant: Some(tenant.clone()),
    };
    let operation = TaskOperation {
        requested_agent: params.agent,
        agent: canonical_agent.as_str().to_owned(),
        tenant,
        task_id,
        context_id: Some(conversation_id),
        normalized_request: Some(request),
        wait_mode: if params.wait {
            TaskWaitMode::Terminal
        } else {
            TaskWaitMode::Immediate
        },
        deadline,
    };
    execute_new_task_operation(context, &operation).await
}

fn validate_agent_target(target: &str) -> Result<(), DynError> {
    if target.is_empty() || target.len() > 1_024 || target.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "agent target must be non-empty, bounded, and control-free",
        )
        .into());
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveAgentResponse {
    canonical_name: AgentName,
}

async fn resolve_new_target(
    context: &SessionContext,
    target: &str,
    deadline: tokio::time::Instant,
) -> Result<AgentName, DynError> {
    loop {
        let connection = context.connections.current().await;
        let mut url = reqwest::Url::parse(&connection.descriptor.base_url)?;
        url.path_segments_mut()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "base URL cannot be a base"))?
            .pop_if_empty()
            .push("v1")
            .push("agents")
            .push("resolve")
            .push(target);
        match tokio::time::timeout_at(
            deadline,
            get_json(&connection, &connection.http, url.as_str()),
        )
        .await
        {
            Ok(Ok(value)) => {
                return serde_json::from_value::<ResolveAgentResponse>(value)
                    .map(|response| response.canonical_name)
                    .map_err(Into::into);
            }
            Ok(Err(RequestError::Recoverable { mode, .. })) => {
                context
                    .connections
                    .recover(&connection, mode, Some(deadline))
                    .await?;
            }
            Ok(Err(RequestError::Final(error))) => return Err(error),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "operation deadline expired during agent resolution",
                )
                .into());
            }
        }
    }
}

async fn execute_new_task_operation(
    context: &SessionContext,
    operation: &TaskOperation,
) -> Result<Value, DynError> {
    let connection = context.connections.current().await;
    let client = match operation_client(&connection, operation).await {
        Ok(client) => client,
        Err(error) if a2a_error_is_recoverable(&error) => {
            return recover_task_after_connection_loss(
                context,
                operation,
                connection,
                a2a_error_recovery_mode(&error).expect("recoverable error must have a mode"),
                false,
                None,
                false,
            )
            .await;
        }
        Err(error) => return Err(error.into()),
    };
    let request = operation
        .normalized_request
        .as_ref()
        .expect("new task operation has a normalized request");
    match operation.wait_mode {
        TaskWaitMode::Immediate => {
            match tokio::time::timeout_at(operation.deadline, client.send_message(request)).await {
                Ok(Ok(response)) => immediate_result(operation, response),
                Ok(Err(error)) if a2a_error_is_recoverable(&error) => {
                    recover_task_after_connection_loss(
                        context,
                        operation,
                        connection,
                        a2a_error_recovery_mode(&error)
                            .expect("recoverable error must have a mode"),
                        false,
                        None,
                        false,
                    )
                    .await
                }
                Ok(Err(error)) => Err(error.into()),
                Err(_) => Ok(operation_timeout_result(
                    operation,
                    false,
                    None,
                    "deadline_expired",
                )),
            }
        }
        TaskWaitMode::Terminal => {
            let stream = match tokio::time::timeout_at(
                operation.deadline,
                client.send_streaming_message(request),
            )
            .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) if a2a_error_is_recoverable(&error) => {
                    return recover_task_after_connection_loss(
                        context,
                        operation,
                        connection,
                        a2a_error_recovery_mode(&error)
                            .expect("recoverable error must have a mode"),
                        false,
                        None,
                        false,
                    )
                    .await;
                }
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => {
                    return Ok(operation_timeout_result(
                        operation,
                        false,
                        None,
                        "deadline_expired",
                    ));
                }
            };
            run_task_attempts(
                context,
                operation,
                TaskAttemptState::Stream {
                    connection,
                    client,
                    stream,
                },
                TaskAttemptMemory {
                    task_confirmed: false,
                    last_task: None,
                    resend_attempted: false,
                },
            )
            .await
        }
    }
}

enum TaskAttemptState {
    Recover {
        failed_connection: Arc<BrokerConnection>,
        mode: RecoveryMode,
    },
    Inspect {
        connection: Arc<BrokerConnection>,
        client: SessionA2AClient,
    },
    Resolve {
        connection: Arc<BrokerConnection>,
        retry_delay: Duration,
    },
    Resend {
        connection: Arc<BrokerConnection>,
        client: SessionA2AClient,
    },
    Stream {
        connection: Arc<BrokerConnection>,
        client: SessionA2AClient,
        stream: BoxStream<'static, Result<StreamResponse, OperationClientError>>,
    },
    Subscribe {
        connection: Arc<BrokerConnection>,
        client: SessionA2AClient,
    },
    CheckReplacement {
        connection: Arc<BrokerConnection>,
        client: SessionA2AClient,
        resubscribe_if_working: bool,
    },
    FinalGet {
        connection: Arc<BrokerConnection>,
        client: SessionA2AClient,
        resubscribe_if_working: bool,
    },
}

fn recovery_state(
    connection: Arc<BrokerConnection>,
    error: &OperationClientError,
) -> TaskAttemptState {
    TaskAttemptState::Recover {
        failed_connection: connection,
        mode: a2a_error_recovery_mode(error).expect("recoverable error must have a mode"),
    }
}

struct TaskAttemptMemory {
    task_confirmed: bool,
    last_task: Option<Task>,
    resend_attempted: bool,
}

async fn run_task_attempts(
    context: &SessionContext,
    operation: &TaskOperation,
    mut state: TaskAttemptState,
    mut memory: TaskAttemptMemory,
) -> Result<Value, DynError> {
    loop {
        state = match state {
            TaskAttemptState::Recover {
                failed_connection,
                mode,
            } => {
                let connection = match context
                    .connections
                    .recover(&failed_connection, mode, Some(operation.deadline))
                    .await
                {
                    Ok(connection) => connection,
                    Err(crate::recovery::RecoveryError::Deadline) => {
                        return Ok(operation_timeout_result(
                            operation,
                            memory.task_confirmed,
                            memory.last_task.as_ref(),
                            "broker_unavailable",
                        ));
                    }
                    Err(error) => return Err(error.into()),
                };
                TaskAttemptState::Resolve {
                    connection,
                    retry_delay: RECOVERY_AGENT_CARD_RETRY_BASE,
                }
            }
            TaskAttemptState::Resolve {
                connection,
                retry_delay,
            } => match operation_client(&connection, operation).await {
                Ok(client) => TaskAttemptState::Inspect { connection, client },
                Err(OperationClientError::AgentUnavailable(_)) => {
                    let remaining = operation
                        .deadline
                        .saturating_duration_since(tokio::time::Instant::now());
                    if remaining.is_zero() {
                        return Ok(operation_timeout_result(
                            operation,
                            memory.task_confirmed,
                            memory.last_task.as_ref(),
                            "agent_unavailable",
                        ));
                    }
                    sleep(retry_delay.min(remaining)).await;
                    TaskAttemptState::Resolve {
                        connection: context.connections.current().await,
                        retry_delay: retry_delay
                            .saturating_mul(2)
                            .min(RECOVERY_AGENT_CARD_RETRY_MAX),
                    }
                }
                Err(error) if a2a_error_is_recoverable(&error) => {
                    recovery_state(connection, &error)
                }
                Err(error) => return Err(error.into()),
            },
            TaskAttemptState::Inspect { connection, client } => {
                match tokio::time::timeout_at(
                    operation.deadline,
                    get_owned_task_a2a(&client, &operation.tenant, &operation.task_id),
                )
                .await
                {
                    Ok(Ok(task)) => {
                        validate_operation_task(operation, &task)?;
                        memory.task_confirmed = true;
                        memory.last_task = Some(task.clone());
                        if task.status.state.is_terminal()
                            || operation.wait_mode == TaskWaitMode::Immediate
                        {
                            return Ok(task_result(&task));
                        }
                        TaskAttemptState::Subscribe { connection, client }
                    }
                    Ok(Err(error))
                        if a2a_task_is_definitely_missing(&error)
                            && operation.normalized_request.is_some()
                            && !memory.resend_attempted =>
                    {
                        memory.resend_attempted = true;
                        TaskAttemptState::Resend { connection, client }
                    }
                    Ok(Err(error)) if a2a_error_is_recoverable(&error) => {
                        recovery_state(connection, &error)
                    }
                    Ok(Err(error)) => return Err(error.into()),
                    Err(_) => {
                        return Ok(operation_timeout_result(
                            operation,
                            memory.task_confirmed,
                            memory.last_task.as_ref(),
                            "deadline_expired",
                        ));
                    }
                }
            }
            TaskAttemptState::Resend { connection, client } => {
                let request = operation
                    .normalized_request
                    .as_ref()
                    .expect("resend state requires a normalized request");
                match operation.wait_mode {
                    TaskWaitMode::Immediate => {
                        match tokio::time::timeout_at(
                            operation.deadline,
                            client.send_message(request),
                        )
                        .await
                        {
                            Ok(Ok(response)) => return immediate_result(operation, response),
                            Ok(Err(error)) if a2a_error_is_recoverable(&error) => {
                                recovery_state(connection, &error)
                            }
                            Ok(Err(error)) => return Err(error.into()),
                            Err(_) => {
                                return Ok(operation_timeout_result(
                                    operation,
                                    memory.task_confirmed,
                                    memory.last_task.as_ref(),
                                    "deadline_expired",
                                ));
                            }
                        }
                    }
                    TaskWaitMode::Terminal => {
                        match tokio::time::timeout_at(
                            operation.deadline,
                            client.send_streaming_message(request),
                        )
                        .await
                        {
                            Ok(Ok(stream)) => TaskAttemptState::Stream {
                                connection,
                                client,
                                stream,
                            },
                            Ok(Err(error)) if a2a_error_is_recoverable(&error) => {
                                recovery_state(connection, &error)
                            }
                            Ok(Err(error)) => return Err(error.into()),
                            Err(_) => {
                                return Ok(operation_timeout_result(
                                    operation,
                                    memory.task_confirmed,
                                    memory.last_task.as_ref(),
                                    "deadline_expired",
                                ));
                            }
                        }
                    }
                }
            }
            TaskAttemptState::Stream {
                connection,
                client,
                mut stream,
            } => loop {
                match tokio::time::timeout_at(operation.deadline, stream.try_next()).await {
                    Ok(Ok(Some(event))) => {
                        if let StreamResponse::Task(task) = &event {
                            validate_operation_task(operation, task)?;
                            memory.task_confirmed = true;
                            memory.last_task = Some(task.clone());
                        } else if working_stream_event(&event, &operation.task_id) {
                            memory.task_confirmed = true;
                        }
                        if let Some(result) = terminal_stream_result(&event) {
                            return Ok(result);
                        }
                    }
                    Ok(Err(error)) if !a2a_error_is_recoverable(&error) => {
                        return Err(error.into());
                    }
                    Ok(Ok(None)) | Ok(Err(_)) => {
                        break TaskAttemptState::CheckReplacement {
                            connection,
                            client,
                            resubscribe_if_working: true,
                        };
                    }
                    Err(_) => {
                        return Ok(operation_timeout_result(
                            operation,
                            memory.task_confirmed,
                            memory.last_task.as_ref(),
                            "deadline_expired",
                        ));
                    }
                }
            },
            TaskAttemptState::Subscribe { connection, client } => {
                let mut subscription = match tokio::time::timeout_at(
                    operation.deadline,
                    client.subscribe_to_task(&SubscribeToTaskRequest {
                        id: operation.task_id.clone(),
                        tenant: Some(operation.tenant.clone()),
                    }),
                )
                .await
                {
                    Ok(Ok(subscription)) => subscription,
                    Ok(Err(error)) if a2a_error_is_recoverable(&error) => {
                        state = TaskAttemptState::CheckReplacement {
                            connection,
                            client,
                            resubscribe_if_working: false,
                        };
                        continue;
                    }
                    Ok(Err(error)) => return Err(error.into()),
                    Err(_) => {
                        return Ok(operation_timeout_result(
                            operation,
                            memory.task_confirmed,
                            memory.last_task.as_ref(),
                            "deadline_expired",
                        ));
                    }
                };
                loop {
                    match tokio::time::timeout_at(operation.deadline, subscription.try_next()).await
                    {
                        Ok(Ok(Some(event))) => {
                            if let StreamResponse::Task(task) = &event {
                                validate_operation_task(operation, task)?;
                                memory.last_task = Some(task.clone());
                            }
                            if let Some(result) = terminal_stream_result(&event) {
                                return Ok(result);
                            }
                        }
                        Ok(Err(error)) if !a2a_error_is_recoverable(&error) => {
                            return Err(error.into());
                        }
                        Ok(Ok(None)) | Ok(Err(_)) => {
                            break TaskAttemptState::CheckReplacement {
                                connection,
                                client,
                                resubscribe_if_working: false,
                            };
                        }
                        Err(_) => {
                            return Ok(operation_timeout_result(
                                operation,
                                memory.task_confirmed,
                                memory.last_task.as_ref(),
                                "deadline_expired",
                            ));
                        }
                    }
                }
            }
            TaskAttemptState::CheckReplacement {
                connection,
                client,
                resubscribe_if_working,
            } => {
                match context
                    .connections
                    .recover_if_replaced(
                        &connection.descriptor.broker_instance_id,
                        operation.deadline,
                    )
                    .await
                {
                    Ok(Some(replacement)) => TaskAttemptState::Resolve {
                        connection: replacement,
                        retry_delay: RECOVERY_AGENT_CARD_RETRY_BASE,
                    },
                    Ok(None) | Err(crate::recovery::RecoveryError::Unavailable(_)) => {
                        TaskAttemptState::FinalGet {
                            connection,
                            client,
                            resubscribe_if_working,
                        }
                    }
                    Err(crate::recovery::RecoveryError::Deadline) => {
                        return Ok(operation_timeout_result(
                            operation,
                            memory.task_confirmed,
                            memory.last_task.as_ref(),
                            "deadline_expired",
                        ));
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            TaskAttemptState::FinalGet {
                connection,
                client,
                resubscribe_if_working,
            } => {
                match tokio::time::timeout_at(
                    operation.deadline,
                    get_owned_task_a2a(&client, &operation.tenant, &operation.task_id),
                )
                .await
                {
                    Ok(Ok(task)) => {
                        validate_operation_task(operation, &task)?;
                        if task.status.state.is_terminal() {
                            return Ok(task_result(&task));
                        }
                        if resubscribe_if_working {
                            memory.task_confirmed = true;
                            memory.last_task = Some(task);
                            TaskAttemptState::Subscribe { connection, client }
                        } else {
                            return Ok(reachable_stream_lost_result(operation, &task));
                        }
                    }
                    Ok(Err(error)) if a2a_error_is_recoverable(&error) => {
                        recovery_state(connection, &error)
                    }
                    Ok(Err(error)) => return Err(error.into()),
                    Err(_) => {
                        return Ok(operation_timeout_result(
                            operation,
                            memory.task_confirmed,
                            memory.last_task.as_ref(),
                            "deadline_expired",
                        ));
                    }
                }
            }
        };
    }
}

async fn recover_task_after_connection_loss(
    context: &SessionContext,
    operation: &TaskOperation,
    failed_connection: Arc<BrokerConnection>,
    mode: RecoveryMode,
    task_confirmed: bool,
    last_task: Option<Task>,
    resend_attempted: bool,
) -> Result<Value, DynError> {
    run_task_attempts(
        context,
        operation,
        TaskAttemptState::Recover {
            failed_connection,
            mode,
        },
        TaskAttemptMemory {
            task_confirmed,
            last_task,
            resend_attempted,
        },
    )
    .await
}

async fn operation_client(
    connection: &Arc<BrokerConnection>,
    operation: &TaskOperation,
) -> Result<SessionA2AClient, OperationClientError> {
    let card = tokio::time::timeout_at(
        operation.deadline,
        resolve_card(connection, &operation.agent),
    )
    .await
    .map_err(|_| {
        OperationClientError::Deadline("operation deadline expired during Agent Card resolution")
    })??;
    let interface = card
        .supported_interfaces
        .iter()
        .find(|interface| interface.protocol_binding == TRANSPORT_PROTOCOL_JSONRPC)
        .ok_or_else(|| {
            OperationClientError::Protocol("agent card has no JSON-RPC interface".to_owned())
        })?;
    let tenant = interface
        .tenant
        .as_deref()
        .ok_or_else(|| OperationClientError::Protocol("agent card has no tenant".to_owned()))?;
    if tenant != operation.tenant {
        return Err(OperationClientError::Protocol(
            "agent card tenant changed during operation".to_owned(),
        ));
    }
    Ok(SessionA2AClient {
        http: connection.http.clone(),
        endpoint: interface.wire_url(),
        bearer_token: connection.descriptor.bearer_token.clone(),
        registration_id: connection.registration.id.as_str().to_owned(),
        registration_epoch: connection.registration.epoch.get(),
    })
}

fn validate_operation_task(operation: &TaskOperation, task: &Task) -> Result<(), DynError> {
    if task.id != operation.task_id
        || operation
            .context_id
            .as_deref()
            .is_some_and(|context_id| task.context_id != context_id)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "recovered task identity does not match the original operation",
        )
        .into());
    }
    Ok(())
}

fn a2a_error_is_recoverable(error: &OperationClientError) -> bool {
    a2a_error_recovery_mode(error).is_some()
}

fn a2a_error_recovery_mode(error: &OperationClientError) -> Option<RecoveryMode> {
    match error {
        OperationClientError::RegistrationAuthLost(_) => Some(RecoveryMode::RegistrationRefresh),
        OperationClientError::Connection(_) | OperationClientError::Deadline(_) => {
            Some(RecoveryMode::BrokerReplacement)
        }
        OperationClientError::AgentUnavailable(_)
        | OperationClientError::Application(_)
        | OperationClientError::Protocol(_) => None,
    }
}

fn a2a_task_is_definitely_missing(error: &OperationClientError) -> bool {
    matches!(
        error,
        OperationClientError::Application(error)
            if error.code == a2a::error_code::TASK_NOT_FOUND
    )
}

fn operation_timeout_result(
    operation: &TaskOperation,
    task_confirmed: bool,
    last_task: Option<&Task>,
    recovery_reason: &str,
) -> Value {
    let conversation_id = last_task
        .map(|task| Value::String(task.context_id.clone()))
        .or_else(|| operation.context_id.clone().map(Value::String))
        .unwrap_or(Value::Null);
    json!({
        "requested_agent": operation.requested_agent,
        "agent": operation.agent,
        "task_id": operation.task_id,
        "conversation_id": conversation_id,
        "resume_task_id": operation.task_id,
        "state": last_task.map(|task| state_name(&task.status.state)).unwrap_or(if task_confirmed { "working" } else { "unknown" }),
        "timed_out": true,
        "task_confirmed": task_confirmed,
        "task_reachable": task_confirmed,
        "recovery_reason": recovery_reason,
    })
}

async fn resume_message(
    context: &SessionContext,
    params: ResumeSendParams,
) -> Result<Value, DynError> {
    validate_agent(&params.agent)?;
    validate_task_id(&params.resume_task_id)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let _permit = context
        .outbound
        .clone()
        .try_acquire_owned()
        .map_err(|_| io::Error::other("too many active outbound tasks"))?;
    let operation = TaskOperation {
        requested_agent: params.agent.clone(),
        agent: params.agent.clone(),
        tenant: params.agent,
        task_id: params.resume_task_id,
        context_id: None,
        normalized_request: None,
        wait_mode: TaskWaitMode::Terminal,
        deadline: tokio::time::Instant::now() + send_wait_duration(params.timeout_ms)?,
    };
    let connection = context.connections.current().await;
    let client = match operation_client(&connection, &operation).await {
        Ok(client) => client,
        Err(error) if a2a_error_is_recoverable(&error) => {
            return recover_task_after_connection_loss(
                context,
                &operation,
                connection,
                a2a_error_recovery_mode(&error).expect("recoverable error must have a mode"),
                false,
                None,
                false,
            )
            .await;
        }
        Err(error) => return Err(error.into()),
    };
    let task = match tokio::time::timeout_at(
        operation.deadline,
        get_owned_task_a2a(&client, &operation.tenant, &operation.task_id),
    )
    .await
    {
        Ok(Ok(task)) => task,
        Ok(Err(error)) if a2a_error_is_recoverable(&error) => {
            return recover_task_after_connection_loss(
                context,
                &operation,
                connection,
                a2a_error_recovery_mode(&error).expect("recoverable error must have a mode"),
                false,
                None,
                false,
            )
            .await;
        }
        Ok(Err(error)) => return Err(error.into()),
        Err(_) => {
            return Ok(operation_timeout_result(
                &operation,
                false,
                None,
                "deadline_expired",
            ));
        }
    };
    validate_operation_task(&operation, &task)?;
    if task.status.state.is_terminal() {
        return Ok(task_result(&task));
    }
    run_task_attempts(
        context,
        &operation,
        TaskAttemptState::Subscribe { connection, client },
        TaskAttemptMemory {
            task_confirmed: true,
            last_task: Some(task),
            resend_attempted: false,
        },
    )
    .await
}

#[derive(Debug)]
enum OperationClientError {
    Connection(String),
    AgentUnavailable(String),
    RegistrationAuthLost(String),
    Application(a2a::A2AError),
    Protocol(String),
    Deadline(&'static str),
}

impl fmt::Display for OperationClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(message)
            | Self::AgentUnavailable(message)
            | Self::RegistrationAuthLost(message)
            | Self::Protocol(message) => formatter.write_str(message),
            Self::Application(error) => error.fmt(formatter),
            Self::Deadline(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for OperationClientError {}

struct SessionA2AClient {
    http: reqwest::Client,
    endpoint: String,
    bearer_token: String,
    registration_id: String,
    registration_epoch: u64,
}

impl SessionA2AClient {
    fn post(&self) -> reqwest::RequestBuilder {
        self.http
            .post(&self.endpoint)
            .bearer_auth(&self.bearer_token)
            .header(REGISTRATION_HEADER, &self.registration_id)
            .header(REGISTRATION_EPOCH_HEADER, self.registration_epoch)
    }

    async fn call<Req, Resp>(
        &self,
        method: &str,
        request: &Req,
    ) -> Result<Resp, OperationClientError>
    where
        Req: Serialize,
        Resp: DeserializeOwned,
    {
        let params = serde_json::to_value(request).map_err(|error| {
            OperationClientError::Protocol(format!("failed to serialize A2A request: {error}"))
        })?;
        let envelope = a2a::JsonRpcRequest::new(
            a2a::JsonRpcId::String("herdr-a2a-client-session".to_owned()),
            method,
            Some(params),
        );
        let response = self
            .post()
            .json(&envelope)
            .send()
            .await
            .map_err(|error| OperationClientError::Connection(error.to_string()))?;
        validate_a2a_http_status(&response)?;
        let bytes = collect_operation_response(response).await?;
        let response: a2a::JsonRpcResponse = serde_json::from_slice(&bytes).map_err(|error| {
            OperationClientError::Connection(format!("A2A response body failed: {error}"))
        })?;
        decode_jsonrpc_response(response)
    }

    async fn call_streaming<Req>(
        &self,
        method: &str,
        request: &Req,
    ) -> Result<
        BoxStream<'static, Result<StreamResponse, OperationClientError>>,
        OperationClientError,
    >
    where
        Req: Serialize,
    {
        let params = serde_json::to_value(request).map_err(|error| {
            OperationClientError::Protocol(format!("failed to serialize A2A request: {error}"))
        })?;
        let envelope = a2a::JsonRpcRequest::new(
            a2a::JsonRpcId::String("herdr-a2a-client-session".to_owned()),
            method,
            Some(params),
        );
        let response = self
            .post()
            .header("Accept", "text/event-stream")
            .json(&envelope)
            .send()
            .await
            .map_err(|error| OperationClientError::Connection(error.to_string()))?;
        validate_a2a_http_status(&response)?;
        match operation_response_kind(&response)? {
            OperationResponseKind::EventStream => Ok(parse_operation_sse(response.bytes_stream())),
            OperationResponseKind::Json => {
                let bytes = collect_operation_response(response).await?;
                let response =
                    serde_json::from_slice::<a2a::JsonRpcResponse>(&bytes).map_err(|error| {
                        OperationClientError::Connection(format!(
                            "A2A JSON-RPC response body failed: {error}"
                        ))
                    })?;
                let event = decode_jsonrpc_response::<StreamResponse>(response)?;
                Ok(Box::pin(futures::stream::once(async move { Ok(event) })))
            }
        }
    }

    async fn send_message(
        &self,
        request: &SendMessageRequest,
    ) -> Result<SendMessageResponse, OperationClientError> {
        self.call(a2a::jsonrpc::methods::SEND_MESSAGE, request)
            .await
    }

    async fn send_streaming_message(
        &self,
        request: &SendMessageRequest,
    ) -> Result<
        BoxStream<'static, Result<StreamResponse, OperationClientError>>,
        OperationClientError,
    > {
        self.call_streaming(a2a::jsonrpc::methods::SEND_STREAMING_MESSAGE, request)
            .await
    }

    async fn get_task(&self, request: &GetTaskRequest) -> Result<Task, OperationClientError> {
        self.call(a2a::jsonrpc::methods::GET_TASK, request).await
    }

    async fn subscribe_to_task(
        &self,
        request: &SubscribeToTaskRequest,
    ) -> Result<
        BoxStream<'static, Result<StreamResponse, OperationClientError>>,
        OperationClientError,
    > {
        self.call_streaming(a2a::jsonrpc::methods::SUBSCRIBE_TO_TASK, request)
            .await
    }
}

#[derive(Clone, Copy)]
enum OperationResponseKind {
    EventStream,
    Json,
}

fn operation_response_kind(
    response: &reqwest::Response,
) -> Result<OperationResponseKind, OperationClientError> {
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .ok_or_else(|| {
            OperationClientError::Protocol("A2A streaming response has no Content-Type".to_owned())
        })?
        .to_str()
        .map_err(|error| {
            OperationClientError::Protocol(format!(
                "A2A streaming response Content-Type is invalid: {error}"
            ))
        })?;
    let media_type = content_type.split(';').next().unwrap_or_default().trim();
    if media_type.eq_ignore_ascii_case("text/event-stream") {
        return Ok(OperationResponseKind::EventStream);
    }
    if media_type.eq_ignore_ascii_case("application/json")
        || media_type
            .to_ascii_lowercase()
            .strip_prefix("application/")
            .is_some_and(|subtype| subtype.ends_with("+json"))
    {
        return Ok(OperationResponseKind::Json);
    }
    Err(OperationClientError::Protocol(format!(
        "A2A streaming response has unsupported Content-Type {content_type}"
    )))
}

async fn collect_operation_body<Stream, Bytes>(
    stream: Stream,
) -> Result<Vec<u8>, OperationClientError>
where
    Stream: futures::Stream<Item = Result<Bytes, reqwest::Error>>,
    Bytes: AsRef<[u8]>,
{
    futures::pin_mut!(stream);
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| OperationClientError::Connection(error.to_string()))?;
        if body.len().saturating_add(chunk.as_ref().len()) > MAX_PRIVATE_RESPONSE_BYTES {
            return Err(OperationClientError::Protocol(format!(
                "A2A response body exceeds {MAX_PRIVATE_RESPONSE_BYTES} bytes"
            )));
        }
        body.extend_from_slice(chunk.as_ref());
    }
    Ok(body)
}

async fn collect_operation_response(
    response: reqwest::Response,
) -> Result<Vec<u8>, OperationClientError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_PRIVATE_RESPONSE_BYTES as u64)
    {
        return Err(OperationClientError::Protocol(format!(
            "A2A response body exceeds {MAX_PRIVATE_RESPONSE_BYTES} bytes"
        )));
    }
    collect_operation_body(response.bytes_stream()).await
}

fn validate_a2a_http_status(response: &reqwest::Response) -> Result<(), OperationClientError> {
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(OperationClientError::Connection(format!(
            "A2A connection credentials were rejected with HTTP {status}"
        )));
    }
    if !status.is_success() {
        return Err(OperationClientError::Protocol(format!(
            "A2A endpoint returned HTTP {status}"
        )));
    }
    Ok(())
}

fn jsonrpc_application_error(error: a2a::JsonRpcError) -> OperationClientError {
    let details = error
        .data
        .and_then(|data| data.as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|detail| serde_json::from_value(detail).ok())
        .collect::<Vec<a2a::TypedDetail>>();
    if details
        .iter()
        .any(|detail| detail.type_url == REGISTRATION_AUTH_LOST_TYPE_URL)
    {
        return OperationClientError::RegistrationAuthLost(error.message);
    }
    OperationClientError::Application(a2a::A2AError {
        code: error.code,
        message: error.message,
        details: (!details.is_empty()).then_some(details),
    })
}

fn decode_jsonrpc_response<T: DeserializeOwned>(
    response: a2a::JsonRpcResponse,
) -> Result<T, OperationClientError> {
    if let Some(error) = response.error {
        return Err(jsonrpc_application_error(error));
    }
    let result = response.result.ok_or_else(|| {
        OperationClientError::Protocol("A2A JSON-RPC response has no result".to_owned())
    })?;
    serde_json::from_value(result)
        .map_err(|error| OperationClientError::Protocol(format!("A2A result is invalid: {error}")))
}

fn operation_sse_event(event_bytes: &[u8]) -> Option<Result<StreamResponse, OperationClientError>> {
    let event_text = match std::str::from_utf8(event_bytes) {
        Ok(event) => event,
        Err(error) => {
            return Some(Err(OperationClientError::Connection(format!(
                "A2A stream body is not UTF-8: {error}"
            ))));
        }
    };
    let mut data = String::new();
    for line in event_text.lines() {
        if let Some(value) = line
            .strip_prefix("data: ")
            .or_else(|| line.strip_prefix("data:"))
        {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(value);
        }
    }
    if data.is_empty() {
        return None;
    }
    let response = match serde_json::from_str::<a2a::JsonRpcResponse>(&data) {
        Ok(response) => response,
        Err(error) => {
            return Some(Err(OperationClientError::Connection(format!(
                "A2A stream body failed: {error}"
            ))));
        }
    };
    Some(decode_jsonrpc_response(response))
}

fn operation_sse_boundary(buffer: &[u8]) -> Option<(usize, usize)> {
    for index in 0..buffer.len().saturating_sub(1) {
        if buffer[index..].starts_with(b"\n\n") || buffer[index..].starts_with(b"\r\r") {
            return Some((index, index + 2));
        }
        if buffer[index..].starts_with(b"\r\n\r\n") {
            return Some((index, index + 4));
        }
    }
    None
}

fn parse_operation_sse<Stream, Bytes>(
    stream: Stream,
) -> BoxStream<'static, Result<StreamResponse, OperationClientError>>
where
    Stream: futures::Stream<Item = Result<Bytes, reqwest::Error>> + Send + 'static,
    Bytes: AsRef<[u8]> + Send + 'static,
{
    let stream = futures::stream::unfold(
        (
            Box::pin(stream),
            Vec::<u8>::new(),
            VecDeque::<Result<StreamResponse, OperationClientError>>::new(),
        ),
        |(mut stream, mut buffer, mut pending)| async move {
            loop {
                if let Some(item) = pending.pop_front() {
                    return Some((item, (stream, buffer, pending)));
                }
                match stream.next().await {
                    Some(Ok(bytes)) => {
                        buffer.extend_from_slice(bytes.as_ref());
                        while let Some((start, end)) = operation_sse_boundary(&buffer) {
                            if end > MAX_PRIVATE_RESPONSE_BYTES {
                                pending.push_back(Err(OperationClientError::Protocol(format!(
                                    "A2A stream event exceeds {MAX_PRIVATE_RESPONSE_BYTES} bytes"
                                ))));
                                buffer.clear();
                                break;
                            }
                            let event = buffer.drain(..end).collect::<Vec<_>>();
                            if let Some(item) = operation_sse_event(&event[..start]) {
                                pending.push_back(item);
                            }
                        }
                        if buffer.len() > MAX_PRIVATE_RESPONSE_BYTES {
                            pending.push_back(Err(OperationClientError::Protocol(format!(
                                "A2A stream event exceeds {MAX_PRIVATE_RESPONSE_BYTES} bytes"
                            ))));
                            buffer.clear();
                        }
                    }
                    Some(Err(error)) => {
                        return Some((
                            Err(OperationClientError::Connection(error.to_string())),
                            (stream, buffer, pending),
                        ));
                    }
                    None => return None,
                }
            }
        },
    );
    Box::pin(stream)
}

async fn get_owned_task_a2a(
    client: &SessionA2AClient,
    tenant: &str,
    task_id: &str,
) -> Result<Task, OperationClientError> {
    client
        .get_task(&GetTaskRequest {
            id: task_id.to_owned(),
            history_length: None,
            tenant: Some(tenant.to_owned()),
        })
        .await
}

fn terminal_stream_result(event: &StreamResponse) -> Option<Value> {
    match event {
        StreamResponse::Task(task) if task.status.state.is_terminal() => Some(task_result(task)),
        _ => None,
    }
}

fn working_stream_event(event: &StreamResponse, expected_task_id: &str) -> bool {
    match event {
        StreamResponse::Task(task) => {
            task.id == expected_task_id && task.status.state == TaskState::Working
        }
        StreamResponse::StatusUpdate(update) => {
            update.task_id == expected_task_id && update.status.state == TaskState::Working
        }
        _ => false,
    }
}

fn immediate_result(
    operation: &TaskOperation,
    response: SendMessageResponse,
) -> Result<Value, DynError> {
    match response {
        SendMessageResponse::Task(task) => {
            validate_operation_task(operation, &task)?;
            Ok(json!({
                "agent": operation.agent,
                "task_id": task.id,
                "conversation_id": task.context_id,
                "state": state_name(&task.status.state),
            }))
        }
        SendMessageResponse::Message(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "nonblocking send returned no task identifiers",
        )
        .into()),
    }
}

fn reachable_stream_lost_result(operation: &TaskOperation, task: &Task) -> Value {
    json!({
        "agent": operation.agent,
        "task_id": operation.task_id,
        "conversation_id": task.context_id,
        "resume_task_id": operation.task_id,
        "state": state_name(&task.status.state),
        "stream_lost": true,
        "task_confirmed": true,
        "task_reachable": true,
    })
}

fn task_result(task: &Task) -> Value {
    json!({
        "task_id": task.id,
        "conversation_id": task.context_id,
        "state": state_name(&task.status.state),
        "text": task.status.message.as_ref().and_then(Message::text),
        "metadata": task.status.message.as_ref().and_then(|message| message.metadata.clone()).unwrap_or_default(),
    })
}

fn state_name(state: &TaskState) -> &'static str {
    match state {
        TaskState::Unspecified => "unspecified",
        TaskState::Submitted => "submitted",
        TaskState::Working => "working",
        TaskState::Completed => "completed",
        TaskState::Failed => "failed",
        TaskState::Canceled => "canceled",
        TaskState::InputRequired => "input_required",
        TaskState::Rejected => "rejected",
        TaskState::AuthRequired => "auth_required",
    }
}

async fn resolve_card(
    connection: &BrokerConnection,
    agent: &str,
) -> Result<AgentCard, OperationClientError> {
    let response = connection
        .http
        .get(format!(
            "{}/agents/{agent}/.well-known/agent-card.json",
            connection.descriptor.base_url
        ))
        .send()
        .await
        .map_err(|error| OperationClientError::Connection(error.to_string()))?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(OperationClientError::AgentUnavailable(format!(
            "agent card for {agent} is temporarily unavailable with HTTP {}",
            response.status()
        )));
    }
    validate_a2a_http_status(&response)?;
    let bytes = collect_operation_response(response).await?;
    serde_json::from_slice(&bytes).map_err(|error| {
        OperationClientError::Connection(format!("Agent Card response body failed: {error}"))
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WaitParams {
    timeout_ms: Option<u64>,
}

async fn wait_for_message(context: &SessionContext, params: Value) -> Result<Value, DynError> {
    let params: WaitParams = serde_json::from_value(params)?;
    let _permit = context
        .inbox_wait
        .clone()
        .try_acquire_owned()
        .map_err(|_| io::Error::other("wait_for_message is already active"))?;
    let deadline = params
        .timeout_ms
        .map(|timeout_ms| tokio::time::Instant::now() + Duration::from_millis(timeout_ms));
    loop {
        let remaining_timeout_ms = deadline.map(|deadline| {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let millis = remaining.as_millis();
            let rounded_up = millis + u128::from(Duration::from_millis(millis as u64) < remaining);
            u64::try_from(rounded_up).unwrap_or(u64::MAX).max(1_000)
        });
        if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "inbox wait timed out").into());
        }
        let connection = context.connections.current().await;
        let wait_url = format!("{}/v1/inbox/wait", connection.descriptor.base_url);
        let wait_body = json!({"timeout_ms": remaining_timeout_ms});
        let request = post_json::<Value>(&connection, &connection.http, &wait_url, &wait_body);
        let result = match deadline {
            Some(deadline) => tokio::time::timeout_at(deadline, request)
                .await
                .map_err(|_| {
                    RequestError::Final(
                        io::Error::new(io::ErrorKind::TimedOut, "inbox wait timed out").into(),
                    )
                })?,
            None => request.await,
        };
        match result {
            Ok(delivery) => {
                let delivery_id = delivery
                    .get("delivery_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "delivery has no identifier")
                    })?
                    .to_owned();
                acknowledge_delivery(context, &delivery_id, deadline)
                    .await
                    .map_err(|error| AcknowledgementError(error.to_string()))?;
                return Ok(delivery);
            }
            Err(RequestError::Recoverable { mode, .. }) => {
                context
                    .connections
                    .recover(&connection, mode, deadline)
                    .await?;
            }
            Err(RequestError::Final(error)) => return Err(error),
        }
    }
}

async fn acknowledge_delivery(
    context: &SessionContext,
    delivery_id: &str,
    deadline: Option<tokio::time::Instant>,
) -> Result<(), DynError> {
    loop {
        if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "delivery acknowledgement timed out",
            )
            .into());
        }
        let connection = context.connections.current().await;
        let ack_url = format!("{}/v1/inbox/ack", connection.descriptor.base_url);
        let ack_body = json!({"delivery_id": delivery_id});
        let request =
            post_json::<Value>(&connection, &connection.lifecycle_http, &ack_url, &ack_body);
        let result = match deadline {
            Some(deadline) => tokio::time::timeout_at(deadline, request)
                .await
                .map_err(|_| {
                    RequestError::Final(
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "delivery acknowledgement timed out",
                        )
                        .into(),
                    )
                })?,
            None => request.await,
        };
        match result {
            Ok(_) => return Ok(()),
            Err(RequestError::Recoverable { mode, .. }) => {
                context
                    .connections
                    .recover(&connection, mode, deadline)
                    .await?;
            }
            Err(RequestError::Final(error)) => return Err(error),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplyParams {
    task_id: String,
    text: String,
    #[serde(default = "empty_object")]
    metadata: Value,
}

async fn reply(context: &SessionContext, params: Value) -> Result<Value, DynError> {
    let params: ReplyParams = serde_json::from_value(params)?;
    validate_text(&params.text)?;
    validate_metadata(&params.metadata)?;
    loop {
        let connection = context.connections.current().await;
        let url = task_action_url(&connection.descriptor.base_url, &params.task_id, "reply")?;
        match post_json::<Value>(
            &connection,
            &connection.http,
            url.as_str(),
            &json!({"text": params.text, "metadata": params.metadata, "file_refs": []}),
        )
        .await
        {
            Ok(_) => return Ok(json!({"task_id": params.task_id, "state": "completed"})),
            Err(RequestError::Recoverable { mode, .. }) => {
                context.connections.recover(&connection, mode, None).await?;
            }
            Err(RequestError::Final(error)) => return Err(error),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelParams {
    task_id: String,
}

async fn cancel_task(context: &SessionContext, params: Value) -> Result<Value, DynError> {
    let params: CancelParams = serde_json::from_value(params)?;
    loop {
        let connection = context.connections.current().await;
        let url = task_action_url(&connection.descriptor.base_url, &params.task_id, "cancel")?;
        match post_empty::<Value>(&connection, &connection.http, url.as_str()).await {
            Ok(_) => return Ok(json!({"task_id": params.task_id, "state": "canceled"})),
            Err(RequestError::Recoverable { mode, .. }) => {
                context.connections.recover(&connection, mode, None).await?;
            }
            Err(RequestError::Final(error)) => return Err(error),
        }
    }
}

fn task_action_url(base_url: &str, task_id: &str, action: &str) -> Result<reqwest::Url, DynError> {
    validate_task_id(task_id)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mut url = reqwest::Url::parse(base_url)?;
    url.path_segments_mut()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "base URL cannot be a base"))?
        .pop_if_empty()
        .push("v1")
        .push("tasks")
        .push(task_id)
        .push(action);
    Ok(url)
}

fn object_metadata(value: Value) -> Result<Option<HashMap<String, Value>>, DynError> {
    validate_metadata(&value)?;
    match value {
        Value::Object(map) if map.is_empty() => Ok(None),
        Value::Object(map) => Ok(Some(map.into_iter().collect())),
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "metadata must be an object").into()),
    }
}

fn validate_metadata(value: &Value) -> Result<(), DynError> {
    if !value.is_object() || serde_json::to_vec(value)?.len() > MAX_METADATA_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "metadata must be a bounded object",
        )
        .into());
    }
    Ok(())
}

fn validate_text(text: &str) -> Result<(), DynError> {
    if text.len() > MAX_TEXT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message text exceeds the size limit",
        )
        .into());
    }
    Ok(())
}

async fn get_json(
    connection: &BrokerConnection,
    client: &reqwest::Client,
    url: &str,
) -> Result<Value, RequestError> {
    send_and_decode(connection, client.get(url)).await
}

async fn post_json<T: for<'de> Deserialize<'de>>(
    connection: &BrokerConnection,
    client: &reqwest::Client,
    url: &str,
    body: &Value,
) -> Result<T, RequestError> {
    send_and_decode(connection, client.post(url).json(body)).await
}

async fn post_empty<T: for<'de> Deserialize<'de>>(
    connection: &BrokerConnection,
    client: &reqwest::Client,
    url: &str,
) -> Result<T, RequestError> {
    send_and_decode(connection, client.post(url)).await
}

async fn send_and_decode<T: for<'de> Deserialize<'de>>(
    _connection: &BrokerConnection,
    request: reqwest::RequestBuilder,
) -> Result<T, RequestError> {
    let response = request.send().await.map_err(|error| {
        if transport_is_recoverable(&error) {
            RequestError::Recoverable {
                mode: RecoveryMode::BrokerReplacement,
                reason: error.to_string(),
            }
        } else {
            RequestError::Final(error.into())
        }
    })?;
    decode_response(response).await
}

async fn decode_response<T: for<'de> Deserialize<'de>>(
    mut response: reqwest::Response,
) -> Result<T, RequestError> {
    decode_response_for_instance(&mut response).await
}

async fn decode_response_for_instance<T: for<'de> Deserialize<'de>>(
    response: &mut reqwest::Response,
) -> Result<T, RequestError> {
    let status = response.status();
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        if transport_is_recoverable(&error) {
            RequestError::Recoverable {
                mode: RecoveryMode::BrokerReplacement,
                reason: error.to_string(),
            }
        } else {
            RequestError::Final(error.into())
        }
    })? {
        if bytes.len().saturating_add(chunk.len()) > MAX_PRIVATE_RESPONSE_BYTES {
            return Err(RequestError::Final(
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "broker response exceeded its bound",
                )
                .into(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        let value = serde_json::from_slice::<Value>(&bytes).ok();
        let private_error = decode_private_error(&bytes);
        let error_code = private_error
            .as_ref()
            .map(|error| error.code.clone())
            .or_else(|| {
                value
                    .as_ref()
                    .and_then(|value| value.pointer("/error/code"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            });
        let message = private_error
            .as_ref()
            .map(|error| error.message.clone())
            .or_else(|| {
                value
                    .as_ref()
                    .and_then(|value| value.pointer("/error/message"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| format!("broker returned HTTP {status}"));
        let recovery_mode = match error_code.as_deref() {
            Some("invalid_registration") => Some(RecoveryMode::RegistrationRefresh),
            Some("stale_registration" | "broker_instance_mismatch") => {
                Some(RecoveryMode::BrokerReplacement)
            }
            _ if status == reqwest::StatusCode::UNAUTHORIZED => {
                Some(RecoveryMode::BrokerReplacement)
            }
            _ => None,
        };
        if let Some(mode) = recovery_mode {
            return Err(RequestError::Recoverable {
                mode,
                reason: message,
            });
        }
        if let Some(error) = private_error {
            return Err(RequestError::Final(Box::new(error)));
        }
        return Err(RequestError::Final(io::Error::other(message).into()));
    }
    serde_json::from_slice(&bytes).map_err(|error| RequestError::Final(error.into()))
}

fn decode_private_error(bytes: &[u8]) -> Option<PrivateBrokerError> {
    let envelope = serde_json::from_slice::<PrivateErrorEnvelope>(bytes).ok()?;
    let error = envelope.error;
    if !is_bounded_control_free(&error.code, MAX_METHOD_BYTES)
        || !is_bounded_control_free(&error.message, MAX_PRIVATE_RESPONSE_BYTES)
        || error.candidates.len() > MAX_SESSION_ERROR_CANDIDATES
        || error
            .candidates
            .windows(2)
            .any(|pair| pair[0].as_str() >= pair[1].as_str())
    {
        return None;
    }
    Some(PrivateBrokerError {
        code: error.code,
        message: error.message,
        candidates: error.candidates,
    })
}

fn transport_is_recoverable(error: &reqwest::Error) -> bool {
    error.is_connect()
        || error.is_timeout()
        || error.is_request()
        || error.is_body()
        || error.is_decode()
}

fn request_error_into_dyn(error: RequestError) -> DynError {
    match error {
        RequestError::Recoverable { reason, .. } => io::Error::other(reason).into(),
        RequestError::Final(error) => error,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        io,
        path::PathBuf,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context, Poll},
    };

    use a2a::{SendMessageResponse, Task, TaskState, TaskStatus};
    use futures::{StreamExt, TryStreamExt};
    use herdr_a2a_broker::{RuntimeDescriptor, agent_card};
    use herdr_a2a_core::{AgentName, RegistrationCredentials, RegistrationEpoch, RegistrationId};
    use tokio::{
        io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
        net::TcpListener,
        sync::{mpsc, oneshot},
    };

    use super::{
        DEFAULT_SEND_WAIT_MS, MAX_PRIVATE_RESPONSE_BYTES, OperationClientError, OutputRecord,
        SessionA2AClient, SessionResponse, a2a_error_is_recoverable, immediate_result,
        operation_timeout_result, parse_operation_sse, resolve_card, resolve_run_loop_result,
        send_wait_duration, task_action_url, writer_loop,
    };
    use crate::recovery::{BrokerConnection, TaskOperation, TaskWaitMode};

    struct ReservationInspectingWriter {
        in_flight: Arc<std::sync::Mutex<HashSet<String>>>,
        observed_reserved_id: Arc<AtomicBool>,
    }

    fn task_sse_event(task_id: &str, padding_bytes: usize) -> Vec<u8> {
        let event = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "raw-parser-test",
            "result": a2a::StreamResponse::Task(Task {
                id: task_id.to_owned(),
                context_id: "raw-parser-context".to_owned(),
                status: TaskStatus {
                    state: TaskState::Working,
                    message: None,
                    timestamp: None,
                },
                artifacts: None,
                history: None,
                metadata: Some(HashMap::from([(
                    "padding".to_owned(),
                    serde_json::Value::String("x".repeat(padding_bytes)),
                )])),
            }),
        });
        format!("data: {event}\n\n").into_bytes()
    }

    fn pad_json_to_response_bound(mut body: Vec<u8>, extra_bytes: usize) -> Vec<u8> {
        assert!(body.len() <= MAX_PRIVATE_RESPONSE_BYTES);
        body.resize(MAX_PRIVATE_RESPONSE_BYTES + extra_bytes, b' ');
        body
    }

    async fn serve_one_response(body: Vec<u8>, chunked: bool) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut connection, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut read_buffer = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = connection.read(&mut read_buffer).await.unwrap();
                assert!(read > 0, "request ended before its headers");
                request.extend_from_slice(&read_buffer[..read]);
            }
            if chunked {
                connection
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
                for chunk in body.chunks(64 * 1024) {
                    connection
                        .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                        .await
                        .unwrap();
                    connection.write_all(chunk).await.unwrap();
                    connection.write_all(b"\r\n").await.unwrap();
                }
                connection.write_all(b"0\r\n\r\n").await.unwrap();
            } else {
                connection
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                connection.write_all(&body).await.unwrap();
            }
        });
        base_url
    }

    fn test_a2a_client(endpoint: String) -> SessionA2AClient {
        SessionA2AClient {
            http: reqwest::Client::new(),
            endpoint,
            bearer_token: "test-bearer".to_owned(),
            registration_id: "test-registration".to_owned(),
            registration_epoch: 1,
        }
    }

    fn test_connection(base_url: String) -> BrokerConnection {
        BrokerConnection {
            descriptor: RuntimeDescriptor {
                session_key: "test-session".to_owned(),
                workspace_id: "test-workspace".to_owned(),
                base_url,
                bearer_token: "test-bearer".to_owned(),
                broker_instance_id: "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI".to_owned(),
                executable_path: PathBuf::from("/test/herdr-a2a"),
                broker_pid: 1,
                created_unix_ms: 1,
            },
            registration: RegistrationCredentials {
                id: RegistrationId::new(),
                epoch: RegistrationEpoch::from_u64(1),
            },
            agent_name: AgentName::parse("implementer").unwrap(),
            http: reqwest::Client::new(),
            lifecycle_http: reqwest::Client::new(),
        }
    }

    #[tokio::test]
    async fn unary_jsonrpc_accepts_content_length_body_exactly_at_response_bound() {
        let body = pad_json_to_response_bound(
            br#"{"jsonrpc":"2.0","id":"test","result":{"ok":true}}"#.to_vec(),
            0,
        );
        let endpoint = serve_one_response(body, false).await;

        let result: serde_json::Value = test_a2a_client(endpoint)
            .call("test/method", &serde_json::json!({}))
            .await
            .expect("an exactly bounded unary JSON-RPC body remains valid");

        assert_eq!(result, serde_json::json!({"ok": true}));
    }

    #[tokio::test]
    async fn unary_jsonrpc_rejects_chunked_body_one_byte_over_response_bound() {
        let body = pad_json_to_response_bound(
            br#"{"jsonrpc":"2.0","id":"test","result":{"ok":true}}"#.to_vec(),
            1,
        );
        let endpoint = serve_one_response(body, true).await;

        let error = test_a2a_client(endpoint)
            .call::<_, serde_json::Value>("test/method", &serde_json::json!({}))
            .await
            .expect_err("an oversized unary JSON-RPC body must be rejected");

        assert!(
            matches!(error, OperationClientError::Protocol(message) if message.contains("response body exceeds"))
        );
    }

    #[tokio::test]
    async fn agent_card_accepts_chunked_body_exactly_at_response_bound() {
        let body = pad_json_to_response_bound(
            serde_json::to_vec(&agent_card("reviewer", "http://127.0.0.1/jsonrpc")).unwrap(),
            0,
        );
        let base_url = serve_one_response(body, true).await;

        let card = resolve_card(&test_connection(base_url), "reviewer")
            .await
            .expect("an exactly bounded Agent Card body remains valid");

        assert_eq!(card.name, "reviewer");
    }

    #[tokio::test]
    async fn agent_card_rejects_content_length_body_one_byte_over_response_bound() {
        let body = pad_json_to_response_bound(
            serde_json::to_vec(&agent_card("reviewer", "http://127.0.0.1/jsonrpc")).unwrap(),
            1,
        );
        let base_url = serve_one_response(body, false).await;

        let error = resolve_card(&test_connection(base_url), "reviewer")
            .await
            .expect_err("an oversized Agent Card body must be rejected");

        assert!(
            matches!(error, OperationClientError::Protocol(message) if message.contains("response body exceeds"))
        );
    }

    #[tokio::test]
    async fn sse_chunk_may_contain_multiple_individually_bounded_events() {
        let first = task_sse_event("first-task", MAX_PRIVATE_RESPONSE_BYTES / 2 + 1_024);
        let second = task_sse_event("second-task", MAX_PRIVATE_RESPONSE_BYTES / 2 + 1_024);
        assert!(first.len() <= MAX_PRIVATE_RESPONSE_BYTES);
        assert!(second.len() <= MAX_PRIVATE_RESPONSE_BYTES);
        let chunk = [first, second].concat();
        assert!(chunk.len() > MAX_PRIVATE_RESPONSE_BYTES);

        let events =
            parse_operation_sse(futures::stream::iter(vec![Ok::<_, reqwest::Error>(chunk)]))
                .try_collect::<Vec<_>>()
                .await
                .expect("each complete event is independently within the framing bound");

        assert_eq!(events.len(), 2);
        assert!(matches!(&events[0], a2a::StreamResponse::Task(task) if task.id == "first-task"));
        assert!(matches!(&events[1], a2a::StreamResponse::Task(task) if task.id == "second-task"));
    }

    #[tokio::test]
    async fn sse_rejects_one_complete_event_over_the_response_bound() {
        let oversized = task_sse_event("oversized-task", MAX_PRIVATE_RESPONSE_BYTES + 1);
        let mut events = parse_operation_sse(futures::stream::iter(vec![Ok::<_, reqwest::Error>(
            oversized,
        )]));

        let error = events
            .next()
            .await
            .expect("oversized event produces an error")
            .expect_err("oversized event cannot decode");
        assert!(
            matches!(error, OperationClientError::Protocol(message) if message.contains("stream event exceeds"))
        );
    }

    #[tokio::test]
    async fn sse_rejects_one_incomplete_pending_event_over_the_response_bound() {
        let mut oversized =
            task_sse_event("oversized-pending-task", MAX_PRIVATE_RESPONSE_BYTES + 1);
        oversized.truncate(oversized.len() - 2);
        assert!(oversized.len() > MAX_PRIVATE_RESPONSE_BYTES);
        assert!(!oversized.ends_with(b"\n\n"));

        let mut events = parse_operation_sse(futures::stream::iter(vec![Ok::<_, reqwest::Error>(
            oversized,
        )]));

        let error = tokio::time::timeout(std::time::Duration::from_secs(1), events.next())
            .await
            .expect("pending-event bound must complete within the watchdog")
            .expect("incomplete oversized event produces an error before EOF")
            .expect_err("incomplete oversized event cannot decode");
        assert!(
            matches!(error, OperationClientError::Protocol(message) if message.contains("stream event exceeds"))
        );
    }

    #[tokio::test]
    async fn sse_delimiter_split_across_chunks_preserves_bound_and_decoding() {
        let event = task_sse_event("split-task", 32);
        let delimiter_tail = event.len() - 1;
        let chunks = vec![
            Ok::<_, reqwest::Error>(event[..delimiter_tail].to_vec()),
            Ok::<_, reqwest::Error>(event[delimiter_tail..].to_vec()),
        ];

        let events = parse_operation_sse(futures::stream::iter(chunks))
            .try_collect::<Vec<_>>()
            .await
            .expect("split delimiter remains valid framing");
        assert!(
            matches!(events.as_slice(), [a2a::StreamResponse::Task(task)] if task.id == "split-task")
        );
    }

    #[test]
    fn omitted_send_timeout_uses_the_sixty_second_default() {
        assert_eq!(
            send_wait_duration(None).unwrap(),
            std::time::Duration::from_millis(DEFAULT_SEND_WAIT_MS)
        );
    }

    #[test]
    fn task_id_action_urls_validate_before_appending_structured_segments() {
        // Break caught: task actions accept path syntax or interpolate an ID into the URL string.
        assert!(task_action_url("http://127.0.0.1:4312", "../unregister#", "cancel").is_err());
        assert_eq!(
            task_action_url("http://127.0.0.1:4312/", "task_A-1", "reply")
                .unwrap()
                .as_str(),
            "http://127.0.0.1:4312/v1/tasks/task_A-1/reply"
        );
    }

    #[test]
    fn application_error_text_never_supplies_transport_provenance() {
        let error = OperationClientError::Application(a2a::A2AError::internal(
            "application detail mentions HTTP request failed: but is not a transport failure",
        ));

        assert!(!a2a_error_is_recoverable(&error));
    }

    #[test]
    fn immediate_result_rejects_mismatched_operation_identity() {
        let operation = TaskOperation {
            requested_agent: "reviewer".to_owned(),
            agent: "reviewer".to_owned(),
            tenant: "reviewer".to_owned(),
            task_id: "expected-task".to_owned(),
            context_id: Some("expected-context".to_owned()),
            normalized_request: None,
            wait_mode: TaskWaitMode::Immediate,
            deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(1),
        };
        let response = SendMessageResponse::Task(Task {
            id: "different-task".to_owned(),
            context_id: "expected-context".to_owned(),
            status: TaskStatus {
                state: TaskState::Working,
                message: None,
                timestamp: None,
            },
            artifacts: None,
            history: None,
            metadata: None,
        });

        assert_eq!(
            immediate_result(&operation, response)
                .unwrap_err()
                .to_string(),
            "recovered task identity does not match the original operation"
        );
    }

    #[test]
    fn timeout_result_preserves_requested_and_resolved_agent_identity() {
        // Break caught: a role is resolved before dispatch, but recovery serializes only the
        // canonical identity and loses the target the caller can validate.
        let operation = TaskOperation {
            requested_agent: "reviewer".to_owned(),
            agent: "reviewer-k7m2".to_owned(),
            tenant: "reviewer-k7m2".to_owned(),
            task_id: "task-role-targeted".to_owned(),
            context_id: Some("conversation-role-targeted".to_owned()),
            normalized_request: None,
            wait_mode: TaskWaitMode::Terminal,
            deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(1),
        };

        let result = operation_timeout_result(&operation, false, None, "broker_unavailable");

        assert_eq!(result["requested_agent"], "reviewer");
        assert_eq!(result["agent"], "reviewer-k7m2");
        assert_eq!(result["task_id"], "task-role-targeted");
        assert_eq!(result["conversation_id"], "conversation-role-targeted");
        assert_eq!(result["resume_task_id"], "task-role-targeted");
    }

    impl AsyncWrite for ReservationInspectingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            let reserved = self
                .in_flight
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .contains("reuse");
            self.observed_reserved_id.store(reserved, Ordering::SeqCst);
            Poll::Ready(Ok(buffer.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn request_id_is_released_before_response_bytes_become_visible() {
        let in_flight = Arc::new(std::sync::Mutex::new(HashSet::from(["reuse".to_owned()])));
        let observed_reserved_id = Arc::new(AtomicBool::new(false));
        let writer = ReservationInspectingWriter {
            in_flight: in_flight.clone(),
            observed_reserved_id: observed_reserved_id.clone(),
        };
        let (sender, receiver) = mpsc::channel(1);
        let (completed, completion) = oneshot::channel();
        sender
            .send(OutputRecord {
                response: SessionResponse::success("reuse".to_owned(), serde_json::json!({})),
                release_id: Some("reuse".to_owned()),
                completed,
            })
            .await
            .unwrap();
        drop(sender);

        writer_loop(writer, receiver, in_flight).await.unwrap();
        completion.await.unwrap().unwrap();

        assert!(
            !observed_reserved_id.load(Ordering::SeqCst),
            "a client can reuse an ID as soon as its response bytes are observable"
        );
    }

    #[test]
    fn primary_loop_error_wins_over_producer_and_writer_cleanup_errors() {
        let result = resolve_run_loop_result(
            Err(io::Error::other("renewal failed").into()),
            Some(io::Error::other("producer failed").into()),
            Err(io::Error::other("writer failed").into()),
        );

        assert_eq!(result.unwrap_err().to_string(), "renewal failed");
    }
}
