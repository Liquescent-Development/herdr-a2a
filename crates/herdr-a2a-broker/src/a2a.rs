use std::{
    collections::HashMap,
    sync::{Arc, Mutex as StdMutex, Weak},
};

use a2a::{
    A2AError, AgentCapabilities, AgentCard, AgentInterface, AgentSkill, CancelTaskRequest,
    DeleteTaskPushNotificationConfigRequest, GetExtendedAgentCardRequest,
    GetTaskPushNotificationConfigRequest, GetTaskRequest, ListTaskPushNotificationConfigsRequest,
    ListTaskPushNotificationConfigsResponse, ListTasksRequest, ListTasksResponse, Message,
    PartContent, SendMessageRequest, SendMessageResponse, StreamResponse, SubscribeToTaskRequest,
    TRANSPORT_PROTOCOL_JSONRPC, Task, TaskPushNotificationConfig, TypedDetail, new_context_id,
    new_task_id,
};
use a2a_server::{
    AgentExecutor, DefaultRequestHandler, ExecutorContext, RequestHandler, ServiceParams, TaskStore,
};
use async_trait::async_trait;
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Path, Request, State},
    http::{HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use futures::{FutureExt, StreamExt, future::BoxFuture, stream, stream::BoxStream};
use herdr_a2a_core::{
    AgentName, BrokerState, DomainError, MessagePayload, QueuedDelivery, Registration,
    RegistrationCredentials, RegistrationEpoch, RegistrationId, StartOrResume, ValidatedPayload,
    validate_payload, validate_task_id,
};
use serde_json::Value;
use tokio::sync::{Mutex, oneshot};

use crate::{SqliteTaskStore, api::MAX_JSON_BODY_BYTES};

const REGISTRATION_HEADER: &str = "x-herdr-a2a-registration";
const REGISTRATION_EPOCH_HEADER: &str = "x-herdr-a2a-registration-epoch";
const EXPLICIT_EMPTY_TASK_ID_HEADER: &str = "x-herdr-a2a-explicit-empty-task-id";
const EXPLICIT_EMPTY_CONTEXT_ID_HEADER: &str = "x-herdr-a2a-explicit-empty-context-id";
const EXECUTION_ADMISSION_HEADER: &str = "x-herdr-a2a-internal-execution-admission";
const TEXT_MODE: &str = "text/plain";
const UNSUPPORTED_FILE_REFERENCES_MESSAGE: &str =
    "Herdr file references are not supported in this milestone";
const REGISTRATION_AUTH_LOST_TYPE_URL: &str = "type.herdr.dev/herdr.a2a.RegistrationAuthLost";

#[derive(Clone)]
pub struct HerdrAgentExecutor {
    broker: BrokerState,
    store: SqliteTaskStore,
    admissions: ExecutionAdmissions,
}

impl HerdrAgentExecutor {
    pub fn new(broker: BrokerState, store: SqliteTaskStore) -> Self {
        Self {
            broker,
            store,
            admissions: ExecutionAdmissions::default(),
        }
    }

    fn with_admissions(
        broker: BrokerState,
        store: SqliteTaskStore,
        admissions: ExecutionAdmissions,
    ) -> Self {
        Self {
            broker,
            store,
            admissions,
        }
    }
}

#[derive(Clone, Default)]
struct ExecutionAdmissions {
    pending: Arc<StdMutex<HashMap<String, herdr_a2a_core::DurableTask>>>,
}

struct ExecutionAdmissionLease {
    admissions: ExecutionAdmissions,
    token: String,
}

impl Drop for ExecutionAdmissionLease {
    fn drop(&mut self) {
        self.admissions
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.token);
    }
}

impl ExecutionAdmissions {
    async fn issue(
        &self,
        params: &mut ServiceParams,
        task: &herdr_a2a_core::DurableTask,
    ) -> ExecutionAdmissionLease {
        let token = RegistrationId::new().as_str().to_owned();
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(token.clone(), task.clone());
        params.insert(EXECUTION_ADMISSION_HEADER.to_owned(), vec![token.clone()]);
        ExecutionAdmissionLease {
            admissions: self.clone(),
            token,
        }
    }

    async fn consume(
        &self,
        params: &ServiceParams,
    ) -> Result<herdr_a2a_core::DurableTask, A2AError> {
        let values = params
            .get(EXECUTION_ADMISSION_HEADER)
            .ok_or_else(|| A2AError::invalid_request("durable execution admission is required"))?;
        if values.len() != 1 {
            return Err(A2AError::invalid_request(
                "exactly one durable execution admission is required",
            ));
        }
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&values[0])
            .ok_or_else(|| {
                A2AError::invalid_request("durable execution admission is invalid or already used")
            })
    }

    #[cfg(test)]
    async fn pending_len(&self) -> usize {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

impl AgentExecutor for HerdrAgentExecutor {
    fn execute(
        &self,
        context: ExecutorContext,
    ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
        let broker = self.broker.clone();
        let store = self.store.clone();
        let admissions = self.admissions.clone();
        Box::pin(
            stream::once(async move { begin_execution(broker, store, admissions, context).await })
                .flat_map(move |result| match result {
                    Ok((working, completion)) => stream::iter(vec![Ok(working)])
                        .chain(stream::once(completion))
                        .boxed(),
                    Err(error) => stream::iter(vec![Err(error)]).boxed(),
                }),
        )
    }

    fn cancel(
        &self,
        context: ExecutorContext,
    ) -> BoxStream<'static, Result<StreamResponse, A2AError>> {
        let broker = self.broker.clone();
        let store = self.store.clone();
        Box::pin(stream::once(async move {
            let sender = authenticated_sender(&broker, &context).await?;
            broker
                .cancel_task(&sender.credentials(), &context.task_id)
                .await
                .map_err(domain_error)?;
            let task = store
                .get(&context.task_id)
                .await?
                .ok_or_else(|| A2AError::task_not_found(&context.task_id))?;
            Ok(StreamResponse::Task(task))
        }))
    }
}

async fn begin_execution(
    broker: BrokerState,
    store: SqliteTaskStore,
    admissions: ExecutionAdmissions,
    context: ExecutorContext,
) -> Result<
    (
        StreamResponse,
        BoxFuture<'static, Result<StreamResponse, A2AError>>,
    ),
    A2AError,
> {
    let admission = admissions.consume(&context.service_params).await?;
    let task_id = admission.task_id.clone();
    if context.task_id != admission.task_id || context.context_id != admission.context_id {
        return Err(A2AError::invalid_request(
            "execution context does not match durable admission",
        ));
    }
    let durable = broker
        .task_snapshot_for_sender(&admission.sender, &task_id)
        .await
        .map_err(domain_error)?;
    if durable.context_id != admission.context_id
        || durable.sender != admission.sender
        || durable.recipient != admission.recipient
        || durable.payload != admission.payload
        || durable.created_unix_ms != admission.created_unix_ms
    {
        return Err(A2AError::invalid_request(
            "durable execution identity does not match admission",
        ));
    }
    let projection = store
        .get(&task_id)
        .await?
        .ok_or_else(|| A2AError::task_not_found(&task_id))?;
    if matches!(
        durable.state,
        herdr_a2a_core::DurableTaskState::Replied
            | herdr_a2a_core::DurableTaskState::Failed
            | herdr_a2a_core::DurableTaskState::Rejected
            | herdr_a2a_core::DurableTaskState::Canceled
            | herdr_a2a_core::DurableTaskState::Expired
    ) {
        let terminal = projection.clone();
        return Ok((
            StreamResponse::Task(projection),
            async move { Ok(StreamResponse::Task(terminal)) }.boxed(),
        ));
    }
    let working = StreamResponse::Task(projection);
    let sender = admission.sender;
    let completion = async move {
        match broker.wait_for_reply_for_sender(&sender, &task_id).await {
            Ok(_)
            | Err(
                DomainError::TaskCanceled
                | DomainError::TaskExpired
                | DomainError::TaskFailed
                | DomainError::TaskRejected,
            ) => {}
            Err(error) => return Err(domain_error(error)),
        }
        let task = store
            .get(&task_id)
            .await?
            .ok_or_else(|| A2AError::task_not_found(&task_id))?;
        Ok(StreamResponse::Task(task))
    };

    Ok((working, completion.boxed()))
}

async fn authenticated_registration(
    broker: &BrokerState,
    params: &ServiceParams,
) -> Result<Registration, A2AError> {
    let values = params
        .get(REGISTRATION_HEADER)
        .ok_or_else(|| A2AError::invalid_request("sender registration header is required"))?;
    if values.len() != 1 {
        return Err(A2AError::invalid_request(
            "exactly one sender registration header is required",
        ));
    }
    let registration_id = RegistrationId::parse(&values[0])
        .map_err(|_| A2AError::invalid_request("sender registration header is invalid"))?;
    let epochs = params
        .get(REGISTRATION_EPOCH_HEADER)
        .ok_or_else(|| A2AError::invalid_request("sender registration epoch header is required"))?;
    if epochs.len() != 1 {
        return Err(A2AError::invalid_request(
            "exactly one sender registration epoch header is required",
        ));
    }
    let epoch = RegistrationEpoch::parse(&epochs[0])
        .ok_or_else(|| A2AError::invalid_request("sender registration epoch header is invalid"))?;
    broker
        .authenticate(&RegistrationCredentials {
            id: registration_id,
            epoch,
        })
        .await
        .map_err(|error| match error {
            DomainError::RegistrationExpired => {
                registration_auth_lost("sender registration is stale")
            }
            DomainError::RegistrationNotFound => {
                registration_auth_lost("sender registration is not active")
            }
            _ => A2AError::invalid_request("sender registration could not be authenticated"),
        })
}

fn registration_auth_lost(message: &str) -> A2AError {
    A2AError::invalid_request(message).with_details(vec![TypedDetail::new(
        REGISTRATION_AUTH_LOST_TYPE_URL,
        HashMap::new(),
    )])
}

async fn authenticated_sender(
    broker: &BrokerState,
    context: &ExecutorContext,
) -> Result<Registration, A2AError> {
    authenticated_registration(broker, &context.service_params).await
}

fn reserved_file_references(metadata: Option<&HashMap<String, Value>>) -> bool {
    metadata
        .and_then(|metadata| metadata.get("herdr"))
        .and_then(Value::as_object)
        .is_some_and(|herdr| {
            ["file_refs", "fileRefs", "file_references", "fileReferences"]
                .iter()
                .any(|field| herdr.contains_key(*field))
        })
}

fn validate_message_parts(message: &Message) -> Result<(), A2AError> {
    for part in &message.parts {
        if !matches!(part.content, PartContent::Text(_)) {
            return Err(A2AError::content_type_not_supported());
        }
        if part.filename.is_some() || part.media_type.is_some() {
            return Err(A2AError::invalid_params(
                UNSUPPORTED_FILE_REFERENCES_MESSAGE,
            ));
        }
        if part.metadata.is_some() {
            return Err(A2AError::invalid_params(
                "A2A part metadata is not supported in this milestone",
            ));
        }
    }
    if message.parts.len() != 1 {
        return Err(A2AError::invalid_params(
            "A2A messages must contain exactly one text part",
        ));
    }
    Ok(())
}

fn validate_metadata_channel(
    metadata: Option<&HashMap<String, Value>>,
    workspace: &std::path::Path,
) -> Result<(), A2AError> {
    let metadata = metadata
        .cloned()
        .map(|metadata| Value::Object(metadata.into_iter().collect()))
        .unwrap_or_else(|| Value::Object(Default::default()));
    validate_payload(
        &MessagePayload {
            text: String::new(),
            metadata,
            file_refs: Vec::new(),
        },
        workspace,
    )
    .map(|_| ())
    .map_err(domain_error)
}

async fn preflight_send(
    broker: &BrokerState,
    params: &ServiceParams,
    request: &SendMessageRequest,
) -> Result<(Registration, AgentName, ValidatedPayload), A2AError> {
    let sender = authenticated_registration(broker, params).await?;
    if params.get(EXPLICIT_EMPTY_TASK_ID_HEADER).is_some() {
        return Err(domain_error(DomainError::InvalidTaskId));
    }
    if let Some(task_id) = request.message.task_id.as_deref() {
        validate_task_id(task_id).map_err(domain_error)?;
    }
    if params.get(EXPLICIT_EMPTY_CONTEXT_ID_HEADER).is_some() {
        return Err(A2AError::invalid_params("invalid context ID"));
    }
    if let Some(context_id) = request.message.context_id.as_deref() {
        validate_task_id(context_id).map_err(|_| A2AError::invalid_params("invalid context ID"))?;
    }
    if request
        .configuration
        .as_ref()
        .and_then(|configuration| configuration.task_push_notification_config.as_ref())
        .is_some()
    {
        return Err(A2AError::push_notification_not_supported());
    }
    let tenant = request
        .tenant
        .as_deref()
        .ok_or_else(|| A2AError::invalid_params("recipient tenant is required"))?;
    let recipient = AgentName::parse(tenant)
        .map_err(|_| A2AError::invalid_params("recipient tenant is invalid"))?;
    let claim = request
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("herdr"))
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("recipient"));
    if let Some(claim) = claim {
        let claim = claim
            .as_str()
            .ok_or_else(|| A2AError::invalid_params("Herdr recipient claim must be a string"))?;
        if claim != recipient.as_str() {
            return Err(A2AError::invalid_params(
                "Herdr recipient claim does not match tenant",
            ));
        }
    }
    if reserved_file_references(request.metadata.as_ref())
        || reserved_file_references(request.message.metadata.as_ref())
    {
        return Err(A2AError::invalid_params(
            UNSUPPORTED_FILE_REFERENCES_MESSAGE,
        ));
    }

    validate_message_parts(&request.message)?;
    validate_metadata_channel(request.metadata.as_ref(), &sender.agent.workspace)?;

    let text = request
        .message
        .text()
        .ok_or_else(A2AError::content_type_not_supported)?;
    let metadata = request
        .message
        .metadata
        .clone()
        .map(|metadata| Value::Object(metadata.into_iter().collect()))
        .unwrap_or_else(|| Value::Object(Default::default()));
    let payload = validate_payload(
        &MessagePayload {
            text: text.to_owned(),
            metadata,
            file_refs: Vec::new(),
        },
        &sender.agent.workspace,
    )
    .map_err(domain_error)?;
    Ok((sender, recipient, payload))
}

#[derive(Clone)]
struct AuthenticatedRequestHandler {
    inner: Arc<dyn RequestHandler>,
    broker: BrokerState,
    store: SqliteTaskStore,
    send_gates: Arc<Mutex<HashMap<String, Weak<Mutex<()>>>>>,
    admissions: ExecutionAdmissions,
}

impl AuthenticatedRequestHandler {
    #[cfg(test)]
    fn new(inner: impl RequestHandler, broker: BrokerState, store: SqliteTaskStore) -> Self {
        Self::with_admissions(inner, broker, store, ExecutionAdmissions::default())
    }

    fn with_admissions(
        inner: impl RequestHandler,
        broker: BrokerState,
        store: SqliteTaskStore,
        admissions: ExecutionAdmissions,
    ) -> Self {
        Self {
            inner: Arc::new(inner),
            broker,
            store,
            send_gates: Arc::new(Mutex::new(HashMap::new())),
            admissions,
        }
    }

    async fn admit_execution(
        &self,
        params: &mut ServiceParams,
        decision: &StartOrResume,
    ) -> ExecutionAdmissionLease {
        let task = match decision {
            StartOrResume::Started(task)
            | StartOrResume::Active(task)
            | StartOrResume::Terminal(task) => task,
        };
        self.admissions.issue(params, task).await
    }

    async fn run_admitted_unary(
        &self,
        mut params: ServiceParams,
        request: SendMessageRequest,
        decision: &StartOrResume,
    ) -> Result<SendMessageResponse, A2AError> {
        let _admission = self.admit_execution(&mut params, decision).await;
        self.inner.send_message(&params, request).await
    }

    async fn run_admitted_streaming(
        &self,
        mut params: ServiceParams,
        request: SendMessageRequest,
        decision: &StartOrResume,
    ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError> {
        let admission = self.admit_execution(&mut params, decision).await;
        self.inner
            .send_streaming_message(&params, request)
            .await
            .map(|stream| {
                stream
                    .map(move |event| {
                        let _keep_admission_alive = &admission;
                        event
                    })
                    .boxed()
            })
    }

    async fn send_gate(&self, task_id: &str) -> Arc<Mutex<()>> {
        let mut gates = self.send_gates.lock().await;
        if let Some(gate) = gates.get(task_id).and_then(Weak::upgrade) {
            return gate;
        }
        let gate = Arc::new(Mutex::new(()));
        gates.insert(task_id.to_owned(), Arc::downgrade(&gate));
        gate
    }

    async fn release_send_gate(&self, task_id: &str, gate: &Arc<Mutex<()>>) {
        let mut gates = self.send_gates.lock().await;
        let is_current = gates
            .get(task_id)
            .and_then(Weak::upgrade)
            .is_some_and(|current| Arc::ptr_eq(&current, gate));
        if is_current && Arc::strong_count(gate) == 1 {
            gates.remove(task_id);
        }
    }

    async fn require_owner(
        &self,
        params: &ServiceParams,
        task_id: &str,
    ) -> Result<Registration, A2AError> {
        validate_task_id(task_id).map_err(domain_error)?;
        let sender = authenticated_registration(&self.broker, params).await?;
        let principal = self.store.task_principal(task_id).await?;
        if principal.as_ref().map(|principal| &principal.sender) != Some(&sender.agent.name) {
            return Err(A2AError::invalid_params("task is owned by another agent"));
        }
        Ok(sender)
    }

    async fn require_owner_and_recipient(
        &self,
        params: &ServiceParams,
        task_id: &str,
        tenant: Option<&str>,
    ) -> Result<Registration, A2AError> {
        validate_task_id(task_id).map_err(domain_error)?;
        let sender = authenticated_registration(&self.broker, params).await?;
        let tenant =
            tenant.ok_or_else(|| A2AError::invalid_params("recipient tenant is required"))?;
        let recipient = AgentName::parse(tenant)
            .map_err(|_| A2AError::invalid_params("recipient tenant is invalid"))?;
        let principal = self.store.task_principal(task_id).await?;
        let Some(principal) = principal else {
            return Err(A2AError::task_not_found(task_id));
        };
        if principal.sender != sender.agent.name {
            return Err(A2AError::invalid_params("task is owned by another agent"));
        }
        if principal.recipient != recipient {
            return Err(A2AError::invalid_params(
                "task recipient does not match tenant",
            ));
        }
        Ok(sender)
    }

    async fn prepare_send(
        &self,
        params: &ServiceParams,
        request: &mut SendMessageRequest,
    ) -> Result<(String, StartOrResume), A2AError> {
        let (sender, recipient, payload) = preflight_send(&self.broker, params, request).await?;
        let task_id = request.message.task_id.clone().unwrap_or_else(new_task_id);
        request.message.task_id = Some(task_id.clone());
        let context_id = match request.message.context_id.clone() {
            Some(context_id) => context_id,
            None => match self
                .broker
                .task_snapshot(&sender.credentials(), &task_id)
                .await
            {
                Ok(snapshot) => snapshot.context_id,
                Err(DomainError::TaskNotFound) => new_context_id(),
                Err(error) => return Err(domain_error(error)),
            },
        };
        request.message.context_id = Some(context_id.clone());
        let decision = self
            .broker
            .start_or_resume(
                &sender.credentials(),
                QueuedDelivery {
                    task_id: task_id.clone(),
                    context_id,
                    sender: sender.agent.name,
                    recipient,
                    payload,
                    created_unix_ms: self.broker.now_unix_ms(),
                    attempt: 0,
                },
            )
            .await
            .map_err(domain_error)?;
        Ok((task_id, decision))
    }

    async fn run_unary_send(
        self,
        params: ServiceParams,
        mut request: SendMessageRequest,
    ) -> Result<SendMessageResponse, A2AError> {
        let task_id = request
            .message
            .task_id
            .clone()
            .expect("send workflow assigns a task ID before spawning");
        let gate = self.send_gate(&task_id).await;
        let guard = gate.lock().await;
        let result = match self.prepare_send(&params, &mut request).await {
            Ok((_, decision @ StartOrResume::Started(_))) => {
                self.run_admitted_unary(params.clone(), request, &decision)
                    .await
            }
            Ok((task_id, StartOrResume::Terminal(_))) => self
                .store
                .get(&task_id)
                .await?
                .map(SendMessageResponse::Task)
                .ok_or_else(|| A2AError::task_not_found(&task_id)),
            Ok((task_id, StartOrResume::Active(_)))
                if request
                    .configuration
                    .as_ref()
                    .and_then(|configuration| configuration.return_immediately)
                    == Some(true) =>
            {
                self.store
                    .get(&task_id)
                    .await?
                    .map(SendMessageResponse::Task)
                    .ok_or_else(|| A2AError::task_not_found(&task_id))
            }
            Ok((task_id, decision @ StartOrResume::Active(_))) => {
                let subscription = self
                    .inner
                    .subscribe_to_task(
                        &params,
                        SubscribeToTaskRequest {
                            id: task_id,
                            tenant: request.tenant.clone(),
                        },
                    )
                    .await;
                match subscription {
                    Ok(mut stream) => {
                        let mut last = None;
                        while let Some(event) = stream.next().await {
                            last = Some(event?);
                        }
                        match last {
                            Some(StreamResponse::Task(task)) => Ok(SendMessageResponse::Task(task)),
                            _ => {
                                self.run_admitted_unary(params.clone(), request, &decision)
                                    .await
                            }
                        }
                    }
                    Err(_) => {
                        self.run_admitted_unary(params.clone(), request, &decision)
                            .await
                    }
                }
            }
            Err(error) => Err(error),
        };
        drop(guard);
        self.release_send_gate(&task_id, &gate).await;
        result
    }

    async fn run_streaming_send(
        self,
        params: ServiceParams,
        mut request: SendMessageRequest,
    ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError> {
        let task_id = request
            .message
            .task_id
            .clone()
            .expect("send workflow assigns a task ID before spawning");
        let gate = self.send_gate(&task_id).await;
        let guard = gate.lock().await;
        let result = match self.prepare_send(&params, &mut request).await {
            Ok((_, decision @ StartOrResume::Started(_))) => {
                self.run_admitted_streaming(params.clone(), request, &decision)
                    .await
            }
            Ok((task_id, StartOrResume::Terminal(_))) => {
                let task = self
                    .store
                    .get(&task_id)
                    .await?
                    .ok_or_else(|| A2AError::task_not_found(&task_id))?;
                Ok(stream::iter(vec![Ok(StreamResponse::Task(task))]).boxed())
            }
            Ok((task_id, decision @ StartOrResume::Active(_))) => {
                match self
                    .inner
                    .subscribe_to_task(
                        &params,
                        SubscribeToTaskRequest {
                            id: task_id,
                            tenant: request.tenant.clone(),
                        },
                    )
                    .await
                {
                    Ok(stream) => Ok(stream),
                    Err(_) => {
                        self.run_admitted_streaming(params.clone(), request, &decision)
                            .await
                    }
                }
            }
            Err(error) => Ok(stream::iter(vec![Err(error)]).boxed()),
        };
        drop(guard);
        self.release_send_gate(&task_id, &gate).await;
        result
    }
}

#[async_trait]
impl RequestHandler for AuthenticatedRequestHandler {
    async fn send_message(
        &self,
        params: &ServiceParams,
        mut request: SendMessageRequest,
    ) -> Result<SendMessageResponse, A2AError> {
        request.message.task_id.get_or_insert_with(new_task_id);
        let (sender, receiver) = oneshot::channel();
        let handler = self.clone();
        let params = params.clone();
        tokio::spawn(async move {
            let _ = sender.send(handler.run_unary_send(params, request).await);
        });
        receiver
            .await
            .map_err(|_| A2AError::internal("send workflow stopped unexpectedly"))?
    }

    async fn send_streaming_message(
        &self,
        params: &ServiceParams,
        mut request: SendMessageRequest,
    ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError> {
        request.message.task_id.get_or_insert_with(new_task_id);
        let (sender, receiver) = oneshot::channel();
        let handler = self.clone();
        let params = params.clone();
        tokio::spawn(async move {
            let _ = sender.send(handler.run_streaming_send(params, request).await);
        });
        receiver
            .await
            .map_err(|_| A2AError::internal("send workflow stopped unexpectedly"))?
    }

    async fn get_task(
        &self,
        params: &ServiceParams,
        request: GetTaskRequest,
    ) -> Result<Task, A2AError> {
        self.require_owner_and_recipient(params, &request.id, request.tenant.as_deref())
            .await?;
        self.inner.get_task(params, request).await
    }

    async fn list_tasks(
        &self,
        params: &ServiceParams,
        request: ListTasksRequest,
    ) -> Result<ListTasksResponse, A2AError> {
        let sender = authenticated_registration(&self.broker, params).await?;
        self.store.list_owned(&sender.agent.name, &request).await
    }

    async fn cancel_task(
        &self,
        params: &ServiceParams,
        request: CancelTaskRequest,
    ) -> Result<Task, A2AError> {
        self.require_owner_and_recipient(params, &request.id, request.tenant.as_deref())
            .await?;
        self.inner.cancel_task(params, request).await
    }

    async fn subscribe_to_task(
        &self,
        params: &ServiceParams,
        request: SubscribeToTaskRequest,
    ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError> {
        let sender = match self
            .require_owner_and_recipient(params, &request.id, request.tenant.as_deref())
            .await
        {
            Ok(sender) => sender,
            Err(error) => return Ok(stream::iter(vec![Err(error)]).boxed()),
        };
        match self.inner.subscribe_to_task(params, request.clone()).await {
            Ok(stream) => Ok(stream),
            Err(_) => {
                let task = self
                    .store
                    .get(&request.id)
                    .await?
                    .ok_or_else(|| A2AError::task_not_found(&request.id))?;
                if task.status.state.is_terminal() {
                    return Ok(stream::iter(vec![Ok(StreamResponse::Task(task))]).boxed());
                }
                let broker = self.broker.clone();
                let store = self.store.clone();
                let task_id = request.id;
                let sender_name = sender.agent.name;
                let completion = async move {
                    match broker
                        .wait_for_reply_for_sender(&sender_name, &task_id)
                        .await
                    {
                        Ok(_)
                        | Err(
                            DomainError::TaskCanceled
                            | DomainError::TaskExpired
                            | DomainError::TaskFailed
                            | DomainError::TaskRejected,
                        ) => {}
                        Err(error) => return Err(domain_error(error)),
                    }
                    store
                        .get(&task_id)
                        .await?
                        .map(StreamResponse::Task)
                        .ok_or_else(|| A2AError::task_not_found(&task_id))
                };
                Ok(stream::iter(vec![Ok(StreamResponse::Task(task))])
                    .chain(stream::once(completion))
                    .boxed())
            }
        }
    }

    async fn create_push_config(
        &self,
        params: &ServiceParams,
        request: TaskPushNotificationConfig,
    ) -> Result<TaskPushNotificationConfig, A2AError> {
        self.require_owner(params, &request.task_id).await?;
        self.inner.create_push_config(params, request).await
    }

    async fn get_push_config(
        &self,
        params: &ServiceParams,
        request: GetTaskPushNotificationConfigRequest,
    ) -> Result<TaskPushNotificationConfig, A2AError> {
        self.require_owner(params, &request.task_id).await?;
        self.inner.get_push_config(params, request).await
    }

    async fn list_push_configs(
        &self,
        params: &ServiceParams,
        request: ListTaskPushNotificationConfigsRequest,
    ) -> Result<ListTaskPushNotificationConfigsResponse, A2AError> {
        self.require_owner(params, &request.task_id).await?;
        self.inner.list_push_configs(params, request).await
    }

    async fn delete_push_config(
        &self,
        params: &ServiceParams,
        request: DeleteTaskPushNotificationConfigRequest,
    ) -> Result<(), A2AError> {
        self.require_owner(params, &request.task_id).await?;
        self.inner.delete_push_config(params, request).await
    }

    async fn get_extended_agent_card(
        &self,
        params: &ServiceParams,
        request: GetExtendedAgentCardRequest,
    ) -> Result<AgentCard, A2AError> {
        authenticated_registration(&self.broker, params).await?;
        self.inner.get_extended_agent_card(params, request).await
    }
}

fn domain_error(error: DomainError) -> A2AError {
    match error {
        DomainError::TaskNotFound => A2AError::task_not_found("unknown"),
        DomainError::TaskAlreadyCompleted
        | DomainError::TaskCanceled
        | DomainError::TaskExpired => A2AError::task_not_cancelable("task"),
        DomainError::AgentNotRegistered
        | DomainError::InvalidAgentName
        | DomainError::InvalidRegistrationId
        | DomainError::InvalidTaskId
        | DomainError::SenderMismatch
        | DomainError::RegistrationNotFound
        | DomainError::RegistrationExpired
        | DomainError::TaskNotOwned => A2AError::invalid_params(error.to_string()),
        DomainError::DuplicateTask => A2AError::invalid_params("task idempotency conflict"),
        _ => A2AError::invalid_request(error.to_string()),
    }
}

#[derive(Clone)]
struct CardState {
    broker: BrokerState,
    jsonrpc_url: Arc<str>,
}

pub fn agent_card(name: &str, jsonrpc_url: &str) -> AgentCard {
    let mut interface = AgentInterface::new(jsonrpc_url, TRANSPORT_PROTOCOL_JSONRPC);
    interface.tenant = Some(name.to_owned());
    AgentCard {
        name: name.to_owned(),
        description: format!("Herdr agent {name}"),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        supported_interfaces: vec![interface],
        capabilities: AgentCapabilities {
            streaming: Some(true),
            push_notifications: Some(false),
            extensions: None,
            extended_agent_card: None,
        },
        default_input_modes: vec![TEXT_MODE.to_owned()],
        default_output_modes: vec![TEXT_MODE.to_owned()],
        skills: vec![AgentSkill {
            id: "collaborate".to_owned(),
            name: "Collaborate".to_owned(),
            description: "Exchange a task and reply with another named Herdr agent".to_owned(),
            tags: vec!["collaboration".to_owned()],
            examples: None,
            input_modes: Some(vec![TEXT_MODE.to_owned()]),
            output_modes: Some(vec![TEXT_MODE.to_owned()]),
            security_requirements: None,
        }],
        provider: None,
        documentation_url: None,
        icon_url: None,
        security_schemes: None,
        security_requirements: None,
        signatures: None,
    }
}

pub fn a2a_router(
    broker: BrokerState,
    task_store: SqliteTaskStore,
    jsonrpc_url: impl Into<String>,
) -> Router {
    let admissions = ExecutionAdmissions::default();
    let default_handler = DefaultRequestHandler::new(
        HerdrAgentExecutor::with_admissions(broker.clone(), task_store.clone(), admissions.clone()),
        task_store.clone(),
    );
    let handler = Arc::new(AuthenticatedRequestHandler::with_admissions(
        default_handler,
        broker.clone(),
        task_store,
        admissions,
    ));
    let card_state = CardState {
        broker,
        jsonrpc_url: Arc::from(jsonrpc_url.into()),
    };
    let jsonrpc = a2a_server::jsonrpc::jsonrpc_router(handler)
        .layer(middleware::from_fn(preserve_explicit_empty_task_id));

    Router::new()
        .route(
            "/agents/{name}/.well-known/agent-card.json",
            get(dynamic_agent_card),
        )
        .with_state(card_state)
        .merge(Router::new().nest("/jsonrpc", jsonrpc))
}

async fn preserve_explicit_empty_task_id(mut request: Request, next: Next) -> Response {
    request.headers_mut().remove(EXPLICIT_EMPTY_TASK_ID_HEADER);
    request
        .headers_mut()
        .remove(EXPLICIT_EMPTY_CONTEXT_ID_HEADER);
    let (mut parts, body) = request.into_parts();
    let bytes = match to_bytes(body, MAX_JSON_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    if has_explicit_empty_task_id(&bytes) {
        parts
            .headers
            .insert(EXPLICIT_EMPTY_TASK_ID_HEADER, HeaderValue::from_static("1"));
    }
    if has_explicit_empty_context_id(&bytes) {
        parts.headers.insert(
            EXPLICIT_EMPTY_CONTEXT_ID_HEADER,
            HeaderValue::from_static("1"),
        );
    }
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

fn has_explicit_empty_task_id(bytes: &[u8]) -> bool {
    has_explicit_empty_message_field(bytes, &["taskId", "task_id"])
}

fn has_explicit_empty_context_id(bytes: &[u8]) -> bool {
    has_explicit_empty_message_field(bytes, &["contextId", "context_id"])
}

fn has_explicit_empty_message_field(bytes: &[u8], fields: &[&str]) -> bool {
    let Ok(request) = serde_json::from_slice::<Value>(bytes) else {
        return false;
    };
    if !matches!(
        request.get("method").and_then(Value::as_str),
        Some(a2a::methods::SEND_MESSAGE | a2a::methods::SEND_STREAMING_MESSAGE)
    ) {
        return false;
    }
    let Some(message) = request
        .get("params")
        .and_then(|params| params.get("message"))
        .and_then(Value::as_object)
    else {
        return false;
    };
    fields.iter().any(|field| {
        message
            .get(*field)
            .is_some_and(|task_id| task_id.as_str() == Some(""))
    })
}

async fn dynamic_agent_card(
    State(state): State<CardState>,
    Path(name): Path<String>,
) -> Result<Json<AgentCard>, StatusCode> {
    let registration = state
        .broker
        .list_agents()
        .await
        .into_iter()
        .find(|registration| registration.agent.name.as_str() == name)
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(agent_card(
        registration.agent.name.as_str(),
        &state.jsonrpc_url,
    )))
}

#[cfg(test)]
mod workflow_tests {
    use std::{
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use a2a::{Part, Role, TaskState, TaskStatus};
    use a2a_server::TaskStore;
    use chrono::Utc;
    use futures::stream::BoxStream;
    use tokio::sync::Notify;

    use super::*;
    use herdr_a2a_core::{SystemClock, VerifiedAgent};

    #[tokio::test]
    async fn forged_terminal_stored_task_cannot_bypass_durable_identity() {
        // Break caught: ExecutorContext is request-derived. Trusting its cached task lets a caller
        // return arbitrary terminal data without authentication or a ledger-backed identity.
        for state in [
            TaskState::Completed,
            TaskState::Canceled,
            TaskState::Failed,
            TaskState::Rejected,
        ] {
            let status_message = Message::new(Role::Agent, vec![Part::text("original response")]);
            let history_message = Message::new(Role::User, vec![Part::text("original request")]);
            let expected = Task {
                id: "terminal-resend".to_owned(),
                context_id: "original-context".to_owned(),
                status: TaskStatus {
                    state: state.clone(),
                    message: Some(status_message),
                    timestamp: Some(Utc::now()),
                },
                artifacts: None,
                history: Some(vec![history_message]),
                metadata: Some(HashMap::from([(
                    "result".to_owned(),
                    serde_json::json!("original"),
                )])),
            };
            let context = ExecutorContext {
                message: Some(Message::new(
                    Role::User,
                    vec![Part::text("duplicate request")],
                )),
                task_id: expected.id.clone(),
                stored_task: Some(expected.clone()),
                context_id: "incoming-context".to_owned(),
                metadata: None,
                user: None,
                service_params: ServiceParams::new(),
                tenant: Some("recipient".to_owned()),
            };

            let events = HerdrAgentExecutor::new(
                BrokerState::new(),
                SqliteTaskStore::open(":memory:")
                    .unwrap()
                    .with_uncoordinated_sdk_writes_for_legacy_tests(),
            )
            .execute(context)
            .collect::<Vec<_>>()
            .await;
            assert_eq!(events.len(), 1, "{state:?}");
            let error = events.into_iter().next().unwrap().unwrap_err();
            assert!(
                error
                    .message
                    .contains("durable execution admission is required"),
                "{state:?}: {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn post_admission_registration_replacement_does_not_fail_or_duplicate_execution() {
        // Break caught: the handler has already durably admitted the task, but the executor
        // authenticates the now-retired registration again and turns a successful admission into
        // an error. This explicit boundary is the deterministic pause between those two phases.
        let store = SqliteTaskStore::open(":memory:").unwrap();
        store
            .prepare_startup(Utc::now().timestamp_millis())
            .await
            .unwrap();
        let (broker, _) = BrokerState::recover(SystemClock, store.clone())
            .await
            .unwrap();
        let sender = broker
            .register(
                VerifiedAgent {
                    name: AgentName::parse("sender").unwrap(),
                    pane_id: "p1".to_owned(),
                    harness: "pi".to_owned(),
                    workspace: PathBuf::from("/repo"),
                },
                "sender-1",
            )
            .await
            .unwrap();
        broker
            .register(
                VerifiedAgent {
                    name: AgentName::parse("recipient").unwrap(),
                    pane_id: "p2".to_owned(),
                    harness: "pi".to_owned(),
                    workspace: PathBuf::from("/repo"),
                },
                "recipient-1",
            )
            .await
            .unwrap();
        let fake = ControlledHandler {
            store: store.clone(),
            entered: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
            started: Arc::new(Notify::new()),
            persist_submitted_before_wait: false,
            return_unpolled_stream: false,
        };
        let handler = AuthenticatedRequestHandler::new(fake, broker.clone(), store.clone());
        let mut params = ServiceParams::new();
        params.insert(
            REGISTRATION_HEADER.to_owned(),
            vec![sender.id.as_str().to_owned()],
        );
        params.insert(
            REGISTRATION_EPOCH_HEADER.to_owned(),
            vec![sender.epoch.get().to_string()],
        );
        let mut send = request("admitted-before-replacement");
        let (_, decision) = handler.prepare_send(&params, &mut send).await.unwrap();
        let StartOrResume::Started(admitted) = decision else {
            panic!("first admission did not start the task")
        };

        let replacement_sender = broker
            .register(
                VerifiedAgent {
                    name: AgentName::parse("sender").unwrap(),
                    pane_id: "p3".to_owned(),
                    harness: "pi".to_owned(),
                    workspace: PathBuf::from("/repo"),
                },
                "sender-2",
            )
            .await
            .unwrap();
        broker
            .register(
                VerifiedAgent {
                    name: AgentName::parse("recipient").unwrap(),
                    pane_id: "p4".to_owned(),
                    harness: "pi".to_owned(),
                    workspace: PathBuf::from("/repo"),
                },
                "recipient-2",
            )
            .await
            .unwrap();

        let admission_lease = handler
            .admit_execution(&mut params, &StartOrResume::Started(admitted.clone()))
            .await;
        let context = ExecutorContext {
            message: Some(send.message.clone()),
            task_id: admitted.task_id.clone(),
            stored_task: Some(Task {
                id: admitted.task_id.clone(),
                context_id: admitted.context_id.clone(),
                status: TaskStatus {
                    state: TaskState::Completed,
                    message: Some(Message::new(Role::Agent, vec![Part::text("forged")])),
                    timestamp: Some(Utc::now()),
                },
                artifacts: None,
                history: None,
                metadata: None,
            }),
            context_id: admitted.context_id.clone(),
            metadata: send.metadata.clone(),
            user: None,
            service_params: params,
            tenant: send.tenant.clone(),
        };
        let first =
            HerdrAgentExecutor::with_admissions(broker.clone(), store, handler.admissions.clone())
                .execute(context)
                .next()
                .await
                .unwrap()
                .unwrap();
        drop(admission_lease);
        let StreamResponse::Task(task) = first else {
            panic!("executor did not return the durable task projection")
        };
        assert_eq!(task.id, admitted.task_id);
        assert_eq!(task.status.state, TaskState::Submitted);

        let resumed = broker
            .start_or_resume(
                &replacement_sender.credentials(),
                QueuedDelivery {
                    task_id: admitted.task_id.clone(),
                    context_id: admitted.context_id.clone(),
                    sender: admitted.sender.clone(),
                    recipient: admitted.recipient.clone(),
                    payload: admitted.payload.clone(),
                    created_unix_ms: admitted.created_unix_ms,
                    attempt: admitted.attempt,
                },
            )
            .await
            .unwrap();
        let StartOrResume::Active(resumed) = resumed else {
            panic!("exact retry did not resume the admitted task")
        };
        assert_eq!(resumed.state_version, admitted.state_version);
    }

    #[tokio::test]
    async fn unpolled_execution_admission_is_revoked_with_handler_lifecycle() {
        // Break caught: if the SDK returns/rejects without polling the executor, a token retained
        // only for executor consumption leaks one map entry per request forever.
        let admissions = ExecutionAdmissions::default();
        let mut params = ServiceParams::new();
        let task = durable_admission("unpolled");
        let admission_lease = admissions.issue(&mut params, &task).await;
        drop(params);
        drop(admission_lease);

        assert_eq!(admissions.pending_len().await, 0);
    }

    #[tokio::test]
    async fn canceled_rejected_and_disconnected_handlers_revoke_execution_admissions() {
        let fake = ControlledHandler {
            store: SqliteTaskStore::open(":memory:")
                .unwrap()
                .with_uncoordinated_sdk_writes_for_legacy_tests(),
            entered: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
            started: Arc::new(Notify::new()),
            persist_submitted_before_wait: false,
            return_unpolled_stream: false,
        };
        let (handler, params, _sender, _store) = fixture(fake.clone(), fake.store.clone()).await;
        let decision = StartOrResume::Started(durable_admission("canceled-handler"));
        let call = tokio::spawn({
            let handler = handler.clone();
            async move {
                handler
                    .run_admitted_unary(params, request("canceled-handler"), &decision)
                    .await
            }
        });
        fake.entered.notified().await;
        assert_eq!(handler.admissions.pending_len().await, 1);
        call.abort();
        assert!(call.await.unwrap_err().is_cancelled());
        assert_eq!(handler.admissions.pending_len().await, 0);

        let rejecting = ControlledHandler {
            return_unpolled_stream: false,
            ..fake.clone()
        };
        let (rejecting_handler, params, _, _) =
            fixture(rejecting.clone(), rejecting.store.clone()).await;
        assert!(
            rejecting_handler
                .run_admitted_streaming(
                    params,
                    request("rejected-before-poll"),
                    &StartOrResume::Started(durable_admission("rejected-before-poll")),
                )
                .await
                .is_err()
        );
        assert_eq!(rejecting_handler.admissions.pending_len().await, 0);

        let unpolled = ControlledHandler {
            return_unpolled_stream: true,
            ..fake
        };
        let (unpolled_handler, params, _, _) =
            fixture(unpolled.clone(), unpolled.store.clone()).await;
        let stream = unpolled_handler
            .run_admitted_streaming(
                params,
                request("disconnected-before-poll"),
                &StartOrResume::Started(durable_admission("disconnected-before-poll")),
            )
            .await
            .unwrap();
        assert_eq!(unpolled_handler.admissions.pending_len().await, 1);
        drop(stream);
        assert_eq!(unpolled_handler.admissions.pending_len().await, 0);
    }

    #[derive(Clone)]
    struct ControlledHandler {
        store: SqliteTaskStore,
        entered: Arc<Notify>,
        release: Arc<Notify>,
        started: Arc<Notify>,
        persist_submitted_before_wait: bool,
        return_unpolled_stream: bool,
    }

    #[derive(Clone)]
    struct SequencedHandler {
        store: SqliteTaskStore,
        calls: Arc<AtomicUsize>,
        first_entered: Arc<Notify>,
        release_first: Arc<Notify>,
        second_entered: Arc<Notify>,
    }

    fn task(request: &SendMessageRequest, state: TaskState) -> Task {
        Task {
            id: request.message.task_id.clone().unwrap(),
            context_id: "controlled-context".to_owned(),
            status: TaskStatus {
                state,
                message: None,
                timestamp: Some(Utc::now()),
            },
            artifacts: None,
            history: Some(vec![request.message.clone()]),
            metadata: None,
        }
    }

    fn durable_admission(task_id: &str) -> herdr_a2a_core::DurableTask {
        herdr_a2a_core::DurableTask {
            task_id: task_id.to_owned(),
            context_id: "context".to_owned(),
            sender: AgentName::parse("sender").unwrap(),
            recipient: AgentName::parse("recipient").unwrap(),
            payload: validate_payload(
                &MessagePayload {
                    text: "work".to_owned(),
                    metadata: serde_json::json!({}),
                    file_refs: Vec::new(),
                },
                std::path::Path::new("/repo"),
            )
            .unwrap(),
            created_unix_ms: 1,
            delivery_deadline_unix_ms: 2,
            state_version: 1,
            state: herdr_a2a_core::DurableTaskState::Queued,
            lease: None,
            attempt: 0,
            acknowledged_unix_ms: None,
            reply: None,
            terminal_unix_ms: None,
            retention_deadline_unix_ms: None,
        }
    }

    #[async_trait]
    impl RequestHandler for ControlledHandler {
        async fn send_message(
            &self,
            _params: &ServiceParams,
            request: SendMessageRequest,
        ) -> Result<SendMessageResponse, A2AError> {
            let submitted = task(&request, TaskState::Submitted);
            if self.persist_submitted_before_wait {
                self.store.create(submitted.clone()).await?;
            }
            self.entered.notify_one();
            self.release.notified().await;
            let working = task(&request, TaskState::Working);
            if self.persist_submitted_before_wait {
                self.store.update(working.clone()).await?;
            } else {
                self.store.create(working.clone()).await?;
            }
            self.started.notify_one();
            Ok(SendMessageResponse::Task(working))
        }

        async fn send_streaming_message(
            &self,
            _params: &ServiceParams,
            _request: SendMessageRequest,
        ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError> {
            if self.return_unpolled_stream {
                return Ok(stream::pending().boxed());
            }
            Err(A2AError::unsupported_operation("unused"))
        }

        async fn get_task(&self, _: &ServiceParams, _: GetTaskRequest) -> Result<Task, A2AError> {
            Err(A2AError::unsupported_operation("unused"))
        }
        async fn list_tasks(
            &self,
            _: &ServiceParams,
            _: ListTasksRequest,
        ) -> Result<ListTasksResponse, A2AError> {
            Err(A2AError::unsupported_operation("unused"))
        }
        async fn cancel_task(
            &self,
            _: &ServiceParams,
            _: CancelTaskRequest,
        ) -> Result<Task, A2AError> {
            Err(A2AError::unsupported_operation("unused"))
        }
        async fn subscribe_to_task(
            &self,
            _: &ServiceParams,
            _: SubscribeToTaskRequest,
        ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError> {
            Err(A2AError::unsupported_operation("unused"))
        }
        async fn create_push_config(
            &self,
            _: &ServiceParams,
            _: TaskPushNotificationConfig,
        ) -> Result<TaskPushNotificationConfig, A2AError> {
            Err(A2AError::unsupported_operation("unused"))
        }
        async fn get_push_config(
            &self,
            _: &ServiceParams,
            _: GetTaskPushNotificationConfigRequest,
        ) -> Result<TaskPushNotificationConfig, A2AError> {
            Err(A2AError::unsupported_operation("unused"))
        }
        async fn list_push_configs(
            &self,
            _: &ServiceParams,
            _: ListTaskPushNotificationConfigsRequest,
        ) -> Result<ListTaskPushNotificationConfigsResponse, A2AError> {
            Err(A2AError::unsupported_operation("unused"))
        }
        async fn delete_push_config(
            &self,
            _: &ServiceParams,
            _: DeleteTaskPushNotificationConfigRequest,
        ) -> Result<(), A2AError> {
            Err(A2AError::unsupported_operation("unused"))
        }
        async fn get_extended_agent_card(
            &self,
            _: &ServiceParams,
            _: GetExtendedAgentCardRequest,
        ) -> Result<AgentCard, A2AError> {
            Err(A2AError::unsupported_operation("unused"))
        }
    }

    #[async_trait]
    impl RequestHandler for SequencedHandler {
        async fn send_message(
            &self,
            _params: &ServiceParams,
            request: SendMessageRequest,
        ) -> Result<SendMessageResponse, A2AError> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                self.first_entered.notify_one();
                self.release_first.notified().await;
                let working = task(&request, TaskState::Working);
                self.store.create(working.clone()).await?;
                Ok(SendMessageResponse::Task(working))
            } else {
                self.second_entered.notify_one();
                Ok(SendMessageResponse::Task(
                    self.store
                        .get(request.message.task_id.as_deref().unwrap())
                        .await?
                        .unwrap(),
                ))
            }
        }

        async fn send_streaming_message(
            &self,
            _: &ServiceParams,
            _: SendMessageRequest,
        ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError> {
            Err(A2AError::unsupported_operation("unused"))
        }
        async fn get_task(&self, _: &ServiceParams, _: GetTaskRequest) -> Result<Task, A2AError> {
            Err(A2AError::unsupported_operation("unused"))
        }
        async fn list_tasks(
            &self,
            _: &ServiceParams,
            _: ListTasksRequest,
        ) -> Result<ListTasksResponse, A2AError> {
            Err(A2AError::unsupported_operation("unused"))
        }
        async fn cancel_task(
            &self,
            _: &ServiceParams,
            _: CancelTaskRequest,
        ) -> Result<Task, A2AError> {
            Err(A2AError::unsupported_operation("unused"))
        }
        async fn subscribe_to_task(
            &self,
            _: &ServiceParams,
            _: SubscribeToTaskRequest,
        ) -> Result<BoxStream<'static, Result<StreamResponse, A2AError>>, A2AError> {
            Err(A2AError::unsupported_operation("unused"))
        }
        async fn create_push_config(
            &self,
            _: &ServiceParams,
            _: TaskPushNotificationConfig,
        ) -> Result<TaskPushNotificationConfig, A2AError> {
            Err(A2AError::unsupported_operation("unused"))
        }
        async fn get_push_config(
            &self,
            _: &ServiceParams,
            _: GetTaskPushNotificationConfigRequest,
        ) -> Result<TaskPushNotificationConfig, A2AError> {
            Err(A2AError::unsupported_operation("unused"))
        }
        async fn list_push_configs(
            &self,
            _: &ServiceParams,
            _: ListTaskPushNotificationConfigsRequest,
        ) -> Result<ListTaskPushNotificationConfigsResponse, A2AError> {
            Err(A2AError::unsupported_operation("unused"))
        }
        async fn delete_push_config(
            &self,
            _: &ServiceParams,
            _: DeleteTaskPushNotificationConfigRequest,
        ) -> Result<(), A2AError> {
            Err(A2AError::unsupported_operation("unused"))
        }
        async fn get_extended_agent_card(
            &self,
            _: &ServiceParams,
            _: GetExtendedAgentCardRequest,
        ) -> Result<AgentCard, A2AError> {
            Err(A2AError::unsupported_operation("unused"))
        }
    }

    async fn fixture<H: RequestHandler>(
        inner: H,
        store: SqliteTaskStore,
    ) -> (
        AuthenticatedRequestHandler,
        ServiceParams,
        Registration,
        SqliteTaskStore,
    ) {
        let broker = BrokerState::new();
        let sender = broker
            .register(
                VerifiedAgent {
                    name: AgentName::parse("sender").unwrap(),
                    pane_id: "p1".to_owned(),
                    harness: "pi".to_owned(),
                    workspace: PathBuf::from("/repo"),
                },
                "session",
            )
            .await
            .unwrap();
        broker
            .register(
                VerifiedAgent {
                    name: AgentName::parse("recipient").unwrap(),
                    pane_id: "p2".to_owned(),
                    harness: "pi".to_owned(),
                    workspace: PathBuf::from("/repo"),
                },
                "session",
            )
            .await
            .unwrap();
        let mut params = ServiceParams::new();
        params.insert(
            REGISTRATION_HEADER.to_owned(),
            vec![sender.id.as_str().to_owned()],
        );
        params.insert(
            REGISTRATION_EPOCH_HEADER.to_owned(),
            vec![sender.epoch.get().to_string()],
        );
        (
            AuthenticatedRequestHandler::new(inner, broker, store.clone()),
            params,
            sender,
            store,
        )
    }

    fn request(id: &str) -> SendMessageRequest {
        let mut request = SendMessageRequest {
            message: Message::new(Role::User, vec![Part::text("work")]),
            configuration: None,
            metadata: None,
            tenant: Some("recipient".to_owned()),
        };
        request.message.task_id = Some(id.to_owned());
        request
    }

    async fn ready<F: std::future::Future>(future: F) -> F::Output {
        tokio::pin!(future);
        for _ in 0..10_000 {
            tokio::select! { biased; output = &mut future => return output, _ = tokio::task::yield_now() => {} }
        }
        panic!("controlled workflow did not become ready")
    }

    async fn wait_gate_removed(handler: &AuthenticatedRequestHandler, task_id: &str) {
        ready(async {
            loop {
                if !handler.send_gates.lock().await.contains_key(task_id) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
    }

    #[tokio::test]
    async fn empty_task_id_is_rejected_before_owner_claim() {
        // Break caught: an explicit empty ID reaches the SQLite owner claim when the handler is
        // invoked by a transport that preserves Some("").
        let fake = ControlledHandler {
            store: SqliteTaskStore::open(":memory:")
                .unwrap()
                .with_uncoordinated_sdk_writes_for_legacy_tests(),
            entered: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
            started: Arc::new(Notify::new()),
            persist_submitted_before_wait: false,
            return_unpolled_stream: false,
        };
        let (handler, params, _sender, store) = fixture(fake.clone(), fake.store.clone()).await;
        let mut request = request("");

        let error = handler
            .prepare_send(&params, &mut request)
            .await
            .unwrap_err();

        assert!(error.message.contains("invalid task ID"), "{error:?}");
        assert_eq!(store.task_owner("").await.unwrap(), None);
    }

    #[tokio::test]
    async fn abort_while_same_id_waits_before_claim_does_not_cancel_workflow() {
        let fake = SequencedHandler {
            store: SqliteTaskStore::open(":memory:")
                .unwrap()
                .with_uncoordinated_sdk_writes_for_legacy_tests(),
            calls: Arc::new(AtomicUsize::new(0)),
            first_entered: Arc::new(Notify::new()),
            release_first: Arc::new(Notify::new()),
            second_entered: Arc::new(Notify::new()),
        };
        let (handler, params, _sender, store) = fixture(fake.clone(), fake.store.clone()).await;
        let handler = Arc::new(handler);
        let first = {
            let handler = Arc::clone(&handler);
            let params = params.clone();
            tokio::spawn(async move { handler.send_message(&params, request("same")).await })
        };
        fake.first_entered.notified().await;
        let second = {
            let handler = Arc::clone(&handler);
            let params = params.clone();
            tokio::spawn(async move { handler.send_message(&params, request("same")).await })
        };
        ready(async {
            loop {
                let waiting = handler
                    .send_gates
                    .lock()
                    .await
                    .get("same")
                    .and_then(Weak::upgrade)
                    .is_some_and(|gate| Arc::strong_count(&gate) >= 3);
                if waiting {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        second.abort();
        fake.release_first.notify_one();
        first.await.unwrap().unwrap();
        ready(fake.second_entered.notified()).await;
        wait_gate_removed(&handler, "same").await;
        assert_eq!(store.task_owner("same").await.unwrap(), None);
        assert_eq!(
            store.get("same").await.unwrap().unwrap().status.state,
            TaskState::Working
        );
    }

    #[tokio::test]
    async fn concurrent_same_owner_sends_cannot_change_the_claimed_recipient() {
        // Break caught: recipient preflight and owner claim could race for the same caller/task,
        // leaving the task addressable through whichever caller-supplied tenant was used later.
        let fake = ControlledHandler {
            store: SqliteTaskStore::open(":memory:")
                .unwrap()
                .with_uncoordinated_sdk_writes_for_legacy_tests(),
            entered: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
            started: Arc::new(Notify::new()),
            persist_submitted_before_wait: false,
            return_unpolled_stream: false,
        };
        let (handler, params, sender, _store) = fixture(fake.clone(), fake.store.clone()).await;
        handler
            .broker
            .register(
                VerifiedAgent {
                    name: AgentName::parse("alternate").unwrap(),
                    pane_id: "p3".to_owned(),
                    harness: "pi".to_owned(),
                    workspace: PathBuf::from("/repo"),
                },
                "session",
            )
            .await
            .unwrap();
        let handler = Arc::new(handler);
        let first = {
            let handler = Arc::clone(&handler);
            let params = params.clone();
            tokio::spawn(async move {
                handler
                    .send_message(&params, request("recipient-race"))
                    .await
            })
        };
        fake.entered.notified().await;
        let second = {
            let handler = Arc::clone(&handler);
            let params = params.clone();
            tokio::spawn(async move {
                let mut request = request("recipient-race");
                request.tenant = Some("alternate".to_owned());
                handler.send_message(&params, request).await
            })
        };
        ready(async {
            loop {
                let waiting = handler
                    .send_gates
                    .lock()
                    .await
                    .get("recipient-race")
                    .and_then(Weak::upgrade)
                    .is_some_and(|gate| Arc::strong_count(&gate) >= 3);
                if waiting {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;

        fake.release.notify_one();
        first.await.unwrap().unwrap();
        let error = second.await.unwrap().unwrap_err();
        assert!(error.message.contains("idempotency conflict"), "{error:?}");
        assert_eq!(
            handler
                .broker
                .task_snapshot(&sender.credentials(), "recipient-race")
                .await
                .unwrap()
                .recipient,
            AgentName::parse("recipient").unwrap(),
        );
        wait_gate_removed(&handler, "recipient-race").await;
    }

    async fn abort_at_controlled_stage(persist_submitted: bool, id: &str) {
        let fake = ControlledHandler {
            store: SqliteTaskStore::open(":memory:")
                .unwrap()
                .with_uncoordinated_sdk_writes_for_legacy_tests(),
            entered: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
            started: Arc::new(Notify::new()),
            persist_submitted_before_wait: persist_submitted,
            return_unpolled_stream: false,
        };
        let (handler, params, _sender, store) = fixture(fake.clone(), fake.store.clone()).await;
        let handler = Arc::new(handler);
        let call_handler = Arc::clone(&handler);
        let owned_id = id.to_owned();
        let call =
            tokio::spawn(
                async move { call_handler.send_message(&params, request(&owned_id)).await },
            );
        fake.entered.notified().await;
        call.abort();
        assert_eq!(store.task_owner(id).await.unwrap(), None);
        if persist_submitted {
            assert_eq!(
                store.get(id).await.unwrap().unwrap().status.state,
                TaskState::Submitted
            );
        } else {
            assert!(store.get(id).await.unwrap().is_none());
        }
        fake.release.notify_one();
        ready(fake.started.notified()).await;
        wait_gate_removed(&handler, id).await;
        assert_eq!(
            store.get(id).await.unwrap().unwrap().status.state,
            TaskState::Working
        );
    }

    #[tokio::test]
    async fn abort_after_owner_claim_before_create_does_not_leave_owner_only_row() {
        abort_at_controlled_stage(false, "after-owner").await;
    }

    #[tokio::test]
    async fn abort_after_submitted_before_start_continues_to_working() {
        abort_at_controlled_stage(true, "after-submitted").await;
    }
}
