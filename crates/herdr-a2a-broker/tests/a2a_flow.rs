use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::Duration,
};

use a2a::{
    AgentCard, CancelTaskRequest, GetTaskRequest, ListTasksRequest, Message, Part, Role,
    SendMessageConfiguration, SendMessageRequest, SendMessageResponse, StreamResponse,
    SubscribeToTaskRequest, TaskPushNotificationConfig, TaskState, error_code,
};
use a2a_client::{
    A2AClient, A2AClientFactory, agent_card::AgentCardResolver, auth::AuthInterceptor,
    transport::Transport,
};
use a2a_server::TaskStore;
use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use futures::TryStreamExt;
use herdr_a2a_broker::{
    ApiState, HerdrVerifier, RuntimePaths, SqliteTaskStore, api::MAX_JSON_BODY_BYTES,
    herdr::HerdrVerificationError, server_router,
};
#[cfg(feature = "test-support")]
use herdr_a2a_broker::{
    agent_card,
    test_support::{RunningTestBroker, TestBrokerRuntime},
};
use herdr_a2a_core::{
    AgentName, BrokerClock, BrokerState, DeliveredMessage, DomainError, Registration, RoleLabel,
    VerifiedAgent, VerifiedPane,
};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::json;
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};

const TOKEN: &str = "test-a2a-bearer-token";
const REGISTRATION_HEADER: &str = "x-herdr-a2a-registration";
const REGISTRATION_EPOCH_HEADER: &str = "x-herdr-a2a-registration-epoch";

#[test]
fn workspace_runtime_artifacts_are_distinct_for_one_session() {
    // Break caught: the package-level A2A surface aliases descriptor or ownership files when
    // separate workspaces happen to inherit the same Herdr socket session.
    let root = tempfile::tempdir().unwrap();
    let left = RuntimePaths::for_test(root.path(), "shared-session", "workspace-left");
    let right = RuntimePaths::for_test(root.path(), "shared-session", "workspace-right");

    assert_ne!(left.descriptor, right.descriptor);
    assert_ne!(left.lock, right.lock);
}

#[derive(Clone, Default)]
struct TestVerifier {
    agents: Arc<tokio::sync::Mutex<HashMap<String, VerifiedPane>>>,
}

impl TestVerifier {
    async fn add(&self, name: &str, pane_id: &str) {
        self.add_in_workspace(name, pane_id, "w1").await;
    }

    async fn add_in_workspace(&self, role: &str, pane_id: &str, workspace_id: &str) {
        self.agents.lock().await.insert(
            pane_id.to_owned(),
            VerifiedPane {
                pane_id: pane_id.to_owned(),
                workspace_id: workspace_id.to_owned(),
                role: RoleLabel::parse(role).unwrap(),
                harness: "pi".to_owned(),
                workspace_path: PathBuf::from("/repo"),
            },
        );
    }
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

struct TestBroker {
    base_url: String,
    broker: BrokerState,
    verifier: TestVerifier,
    store: SqliteTaskStore,
    shutdown: Option<oneshot::Sender<()>>,
    server: JoinHandle<()>,
}

#[derive(Clone)]
struct TestClock(Arc<AtomicI64>);

impl TestClock {
    fn at(now_unix_ms: i64) -> Self {
        Self(Arc::new(AtomicI64::new(now_unix_ms)))
    }

    fn advance(&self, milliseconds: i64) {
        self.0.fetch_add(milliseconds, Ordering::SeqCst);
    }
}

impl BrokerClock for TestClock {
    fn now_unix_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Deserialize)]
struct RegistrationResponse {
    registration_id: herdr_a2a_core::RegistrationId,
    registration_epoch: herdr_a2a_core::RegistrationEpoch,
    canonical_name: AgentName,
    role: RoleLabel,
    pane_id: String,
    harness: String,
    workspace: PathBuf,
    harness_session_id: String,
    expires_unix_ms: i64,
}

impl From<RegistrationResponse> for Registration {
    fn from(response: RegistrationResponse) -> Self {
        Self {
            id: response.registration_id,
            epoch: response.registration_epoch,
            agent: VerifiedAgent {
                name: response.canonical_name,
                pane_id: response.pane_id,
                harness: response.harness,
                workspace: response.workspace,
            },
            harness_session_id: response.harness_session_id,
            expires_unix_ms: response.expires_unix_ms,
        }
    }
}

impl TestBroker {
    async fn start() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        Self::start_with_clock(TestClock::at(now)).await
    }

    async fn start_with_clock(clock: TestClock) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let base_url = format!("http://{address}");
        let verifier = TestVerifier::default();
        let store = SqliteTaskStore::open(":memory:").unwrap();
        store.prepare_startup(clock.now_unix_ms()).await.unwrap();
        let (broker, _) = BrokerState::recover(clock, store.clone()).await.unwrap();
        let state = ApiState::new(
            broker.clone(),
            Arc::new(verifier.clone()),
            store.identity_store(),
            "w1",
            TOKEN,
            [0x22; 32],
        )
        .unwrap();
        let app = server_router(state, store.clone(), format!("{base_url}/jsonrpc"));
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });

        Self {
            base_url,
            broker,
            verifier,
            store,
            shutdown: Some(shutdown_tx),
            server,
        }
    }

    async fn register(&self, name: &str, pane_id: &str) -> Registration {
        self.register_with_session(name, pane_id, &format!("session-{name}"))
            .await
    }

    async fn register_with_session(
        &self,
        role: &str,
        pane_id: &str,
        harness_session_id: &str,
    ) -> Registration {
        self.verifier.add(role, pane_id).await;
        let response = reqwest::Client::new()
            .post(format!("{}/v1/register", self.base_url))
            .bearer_auth(TOKEN)
            .json(&json!({"pane_id": pane_id, "harness_session_id": harness_session_id}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let response = response.json::<RegistrationResponse>().await.unwrap();
        assert_eq!(response.role.as_str(), role);
        response.into()
    }

    async fn resolve_card(&self, name: &str) -> AgentCard {
        let canonical_name = self.resolve_name(name).await;
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {TOKEN}")).unwrap(),
        );
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .unwrap();
        AgentCardResolver::new(Some(client))
            .resolve(&format!("{}/agents/{canonical_name}", self.base_url))
            .await
            .unwrap()
    }

    async fn resolve_name(&self, target: &str) -> String {
        let mut url = reqwest::Url::parse(&self.base_url).unwrap();
        url.path_segments_mut()
            .unwrap()
            .extend(["v1", "agents", "resolve", target]);
        let response = reqwest::Client::new()
            .get(url)
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        response.json::<serde_json::Value>().await.unwrap()["canonical_name"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    async fn a2a_client(
        &self,
        card: &AgentCard,
        sender: &Registration,
    ) -> A2AClient<Box<dyn Transport>> {
        let epoch = sender.epoch.get().to_string();
        self.a2a_client_with_epoch(card, sender.id.as_str(), Some(&epoch))
            .await
    }

    async fn a2a_client_with_registration(
        &self,
        card: &AgentCard,
        registration_id: &str,
    ) -> A2AClient<Box<dyn Transport>> {
        A2AClientFactory::builder()
            .with_interceptor(Arc::new(AuthInterceptor::bearer(TOKEN)))
            .with_interceptor(Arc::new(AuthInterceptor::custom(
                REGISTRATION_HEADER,
                registration_id,
            )))
            .with_interceptor(Arc::new(AuthInterceptor::custom(
                REGISTRATION_EPOCH_HEADER,
                "1",
            )))
            .build()
            .create_from_card(card)
            .await
            .unwrap()
    }

    async fn a2a_client_with_epoch(
        &self,
        card: &AgentCard,
        registration_id: &str,
        epoch: Option<&str>,
    ) -> A2AClient<Box<dyn Transport>> {
        let mut factory = A2AClientFactory::builder()
            .with_interceptor(Arc::new(AuthInterceptor::bearer(TOKEN)))
            .with_interceptor(Arc::new(AuthInterceptor::custom(
                REGISTRATION_HEADER,
                registration_id,
            )));
        if let Some(epoch) = epoch {
            factory = factory.with_interceptor(Arc::new(AuthInterceptor::custom(
                REGISTRATION_EPOCH_HEADER,
                epoch,
            )));
        }
        factory.build().create_from_card(card).await.unwrap()
    }

    async fn a2a_client_without_registration(
        &self,
        card: &AgentCard,
    ) -> A2AClient<Box<dyn Transport>> {
        A2AClientFactory::builder()
            .with_interceptor(Arc::new(AuthInterceptor::bearer(TOKEN)))
            .build()
            .create_from_card(card)
            .await
            .unwrap()
    }

    async fn stored_task_count(&self) -> i32 {
        self.store
            .list(&list_request(None, None))
            .await
            .unwrap()
            .total_size
    }

    async fn wait_message(&self, recipient: &Registration) -> DeliveredMessage {
        reqwest::Client::new()
            .post(format!("{}/v1/inbox/wait", self.base_url))
            .bearer_auth(TOKEN)
            .header(REGISTRATION_HEADER, recipient.id.as_str())
            .header(REGISTRATION_EPOCH_HEADER, recipient.epoch.get())
            .json(&json!({"timeout_ms": 5_000}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    async fn reply(&self, recipient: &Registration, task_id: &str, text: &str) {
        reqwest::Client::new()
            .post(format!("{}/v1/tasks/{task_id}/reply", self.base_url))
            .bearer_auth(TOKEN)
            .header(REGISTRATION_HEADER, recipient.id.as_str())
            .header(REGISTRATION_EPOCH_HEADER, recipient.epoch.get())
            .json(&json!({"text": text, "metadata": {}, "file_refs": []}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
    }

    async fn acknowledge(
        &self,
        recipient: &Registration,
        delivery_id: &herdr_a2a_core::DeliveryId,
    ) {
        reqwest::Client::new()
            .post(format!("{}/v1/inbox/ack", self.base_url))
            .bearer_auth(TOKEN)
            .header(REGISTRATION_HEADER, recipient.id.as_str())
            .header(REGISTRATION_EPOCH_HEADER, recipient.epoch.get())
            .json(&json!({"delivery_id": delivery_id}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
    }
}

impl Drop for TestBroker {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.server.abort();
    }
}

fn request_for(recipient: &str, text: &str) -> SendMessageRequest {
    SendMessageRequest {
        message: Message::new(Role::User, vec![Part::text(text)]),
        configuration: None,
        metadata: None,
        tenant: Some(recipient.to_owned()),
    }
}

fn immediate_request_for(recipient: &str, text: &str) -> SendMessageRequest {
    let mut request = request_for(recipient, text);
    request.configuration = Some(SendMessageConfiguration {
        accepted_output_modes: Some(vec!["text/plain".to_owned()]),
        task_push_notification_config: None,
        history_length: None,
        return_immediately: Some(true),
    });
    request
}

fn named_immediate_request(recipient: &str, task_id: &str) -> SendMessageRequest {
    let mut request = immediate_request_for(recipient, task_id);
    request.message.task_id = Some(task_id.to_owned());
    request
}

fn named_request(recipient: &str, task_id: &str) -> SendMessageRequest {
    let mut request = request_for(recipient, task_id);
    request.message.task_id = Some(task_id.to_owned());
    request
}

fn list_request(page_size: Option<i32>, page_token: Option<String>) -> ListTasksRequest {
    ListTasksRequest {
        context_id: None,
        status: None,
        page_size,
        page_token,
        history_length: None,
        status_timestamp_after: None,
        include_artifacts: None,
        tenant: Some("reviewer".to_owned()),
    }
}

fn list_request_for(
    recipient: &Registration,
    page_size: Option<i32>,
    page_token: Option<String>,
) -> ListTasksRequest {
    let mut request = list_request(page_size, page_token);
    request.tenant = Some(recipient.agent.name.as_str().to_owned());
    request
}

fn task_id(event: &StreamResponse) -> Option<&str> {
    match event {
        StreamResponse::Task(task) => Some(&task.id),
        StreamResponse::StatusUpdate(update) => Some(&update.task_id),
        StreamResponse::ArtifactUpdate(update) => Some(&update.task_id),
        StreamResponse::Message(_) => None,
    }
}

#[cfg(feature = "test-support")]
async fn runtime_register(running: &RunningTestBroker, name: &str, pane_id: &str) -> Registration {
    running.add_agent(name, pane_id).await;
    reqwest::Client::new()
        .post(format!("{}/v1/register", running.base_url()))
        .bearer_auth(running.bearer_token())
        .json(&json!({"pane_id": pane_id, "harness_session_id": format!("session-{pane_id}")}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<RegistrationResponse>()
        .await
        .unwrap()
        .into()
}

#[tokio::test]
async fn wait_for_agents_blocks_once_for_exact_opaque_pane_ids() {
    // Break caught: team registration uses polling, returns an unrelated agent, or predicts IDs.
    let broker = TestBroker::start().await;
    let client = reqwest::Client::new();
    let url = format!("{}/v1/agents/wait", broker.base_url);
    let waiting = tokio::spawn(async move {
        client
            .post(url)
            .bearer_auth(TOKEN)
            .json(&json!({
                "pane_ids": ["opaque::worker#1", "opaque::reviewer#2"],
                "timeout_ms": 2_000
            }))
            .send()
            .await
            .unwrap()
    });

    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!waiting.is_finished());
    broker.register("observer", "opaque::unrelated#3").await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!waiting.is_finished());
    let worker = broker.register("worker", "opaque::worker#1").await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!waiting.is_finished());
    let reviewer = broker.register("reviewer", "opaque::reviewer#2").await;

    let response = waiting.await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body = response.json::<serde_json::Value>().await.unwrap();
    assert!(body["generation"].as_u64().is_some());
    assert_eq!(body["agents"].as_array().unwrap().len(), 2);
    assert_eq!(body["agents"][0]["pane_id"], "opaque::worker#1");
    assert_eq!(
        body["agents"][0]["canonical_name"],
        worker.agent.name.as_str()
    );
    assert_eq!(body["agents"][1]["pane_id"], "opaque::reviewer#2");
    assert_eq!(
        body["agents"][1]["canonical_name"],
        reviewer.agent.name.as_str()
    );
}

#[tokio::test]
async fn wait_for_agents_rejects_duplicate_or_unbounded_pane_sets() {
    // Break caught: the private wait admits ambiguous or unbounded team registration work.
    let broker = TestBroker::start().await;
    for pane_ids in [
        json!([]),
        json!(["same", "same"]),
        json!(["x".repeat(1_025)]),
        json!(
            (0..9)
                .map(|index| format!("pane-{index}"))
                .collect::<Vec<_>>()
        ),
    ] {
        let response = reqwest::Client::new()
            .post(format!("{}/v1/agents/wait", broker.base_url))
            .bearer_auth(TOKEN)
            .json(&json!({"pane_ids": pane_ids, "timeout_ms": 1_000}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    }
}

#[cfg(feature = "test-support")]
async fn runtime_client(
    running: &RunningTestBroker,
    sender: &Registration,
) -> A2AClient<Box<dyn Transport>> {
    let card = agent_card("reviewer", &format!("{}/jsonrpc", running.base_url()));
    A2AClientFactory::builder()
        .with_interceptor(Arc::new(AuthInterceptor::bearer(running.bearer_token())))
        .with_interceptor(Arc::new(AuthInterceptor::custom(
            REGISTRATION_HEADER,
            sender.id.as_str(),
        )))
        .with_interceptor(Arc::new(AuthInterceptor::custom(
            REGISTRATION_EPOCH_HEADER,
            sender.epoch.get().to_string(),
        )))
        .build()
        .create_from_card(&card)
        .await
        .unwrap()
}

#[cfg(feature = "test-support")]
async fn runtime_wait(
    running: &RunningTestBroker,
    recipient: &Registration,
) -> Result<DeliveredMessage, reqwest::Error> {
    reqwest::Client::new()
        .post(format!("{}/v1/inbox/wait", running.base_url()))
        .bearer_auth(running.bearer_token())
        .header(REGISTRATION_HEADER, recipient.id.as_str())
        .header(REGISTRATION_EPOCH_HEADER, recipient.epoch.get())
        .json(&json!({"timeout_ms": 1_000}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
}

#[cfg(feature = "test-support")]
async fn runtime_ack(
    running: &RunningTestBroker,
    recipient: &Registration,
    delivery: &DeliveredMessage,
) {
    reqwest::Client::new()
        .post(format!("{}/v1/inbox/ack", running.base_url()))
        .bearer_auth(running.bearer_token())
        .header(REGISTRATION_HEADER, recipient.id.as_str())
        .header(REGISTRATION_EPOCH_HEADER, recipient.epoch.get())
        .json(&json!({"delivery_id": delivery.delivery_id}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
}

#[cfg(feature = "test-support")]
async fn runtime_reply(
    running: &RunningTestBroker,
    recipient: &Registration,
    task_id: &str,
    text: &str,
) {
    reqwest::Client::new()
        .post(format!("{}/v1/tasks/{task_id}/reply", running.base_url()))
        .bearer_auth(running.bearer_token())
        .header(REGISTRATION_HEADER, recipient.id.as_str())
        .header(REGISTRATION_EPOCH_HEADER, recipient.epoch.get())
        .json(&json!({"text": text, "metadata": {}, "file_refs": []}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
}

#[tokio::test]
async fn role_ambiguity_returns_sorted_canonical_candidates_without_enqueue() {
    // Break caught: a role collision guesses a recipient and creates durable work.
    let broker = TestBroker::start().await;
    let first = broker
        .register_with_session("reviewer", "w1:p1", "session-a")
        .await;
    let second = broker
        .register_with_session("reviewer", "w1:p2", "session-b")
        .await;
    let mut expected = vec![
        first.agent.name.as_str().to_owned(),
        second.agent.name.as_str().to_owned(),
    ];
    expected.sort();

    let response = reqwest::Client::new()
        .get(format!("{}/v1/agents/resolve/reviewer", broker.base_url))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::CONFLICT);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "ambiguous_agent");
    assert_eq!(body["error"]["candidates"], json!(expected));
    assert_eq!(broker.stored_task_count().await, 0);

    assert_eq!(
        broker.resolve_name(first.agent.name.as_str()).await,
        first.agent.name.as_str()
    );
}

#[tokio::test]
async fn role_workspace_mismatch_is_rejected_before_registration() {
    // Break caught: a verified pane from another workspace enters this broker's live directory.
    let broker = TestBroker::start().await;
    broker
        .verifier
        .add_in_workspace("reviewer", "w2:p1", "w2")
        .await;
    let response = reqwest::Client::new()
        .post(format!("{}/v1/register", broker.base_url))
        .bearer_auth(TOKEN)
        .json(&json!({"pane_id":"w2:p1","harness_session_id":"session-a"}))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(broker.broker.list_agents().await.is_empty());
}

#[tokio::test]
async fn role_rename_preserves_canonical_identity_and_task_recipient() {
    // Break caught: changing a pane label reallocates identity or retargets an existing task.
    let broker = TestBroker::start().await;
    let sender = broker
        .register_with_session("implementer", "w1:p1", "sender-session")
        .await;
    let recipient = broker
        .register_with_session("reviewer", "w1:p2", "recipient-session")
        .await;
    let canonical = recipient.agent.name.clone();
    let card = broker.resolve_card(canonical.as_str()).await;
    let client = broker.a2a_client(&card, &sender).await;
    client
        .send_message(&named_immediate_request(canonical.as_str(), "rename-task"))
        .await
        .unwrap();

    let refreshed = broker
        .register_with_session("auditor", "w1:p2", "recipient-session")
        .await;
    assert_eq!(refreshed.agent.name, canonical);
    assert_eq!(
        broker
            .store
            .task_principal("rename-task")
            .await
            .unwrap()
            .unwrap()
            .recipient,
        canonical
    );
    assert_eq!(broker.resolve_name("auditor").await, canonical.as_str());
}

#[tokio::test]
#[cfg(feature = "test-support")]
async fn workspace_task_directories_have_no_cross_visibility() {
    // Break caught: sharing the durable session directory across workspace scopes makes a task
    // created in one workspace visible after opening the other workspace's broker state.
    let (left_runtime, right_runtime) = TestBrokerRuntime::workspace_pair();
    assert_ne!(
        left_runtime.descriptor_path(),
        right_runtime.descriptor_path()
    );
    assert_ne!(left_runtime.database_path(), right_runtime.database_path());

    let left = left_runtime.start_broker().await;
    let right = right_runtime.start_broker().await;
    let sender = runtime_register(&left, "implementer", "w1:p1").await;
    let recipient = runtime_register(&left, "reviewer", "w1:p2").await;
    runtime_register(&right, "reviewer", "w2:p1").await;
    runtime_client(&left, &sender)
        .await
        .send_message(&named_immediate_request(
            recipient.agent.name.as_str(),
            "workspace-left-task",
        ))
        .await
        .unwrap();

    assert_eq!(left_runtime.task_count().await, 1);
    assert_eq!(right_runtime.task_count().await, 0);
    left.stop().await;
    right.stop().await;
}

#[tokio::test]
#[cfg(feature = "test-support")]
async fn restart_queued_delivery_replays_once_and_requires_a_live_recipient_for_new_send() {
    // Break caught: restart either loses queued work or treats a historical durable principal as
    // proof that the recipient is currently live for a brand-new send.
    let runtime = TestBrokerRuntime::new();
    let first = runtime.start_broker().await;
    let sender = runtime_register(&first, "implementer", "w1:p1").await;
    let recipient = runtime_register(&first, "reviewer", "w1:p2").await;
    let recipient_name = recipient.agent.name.as_str().to_owned();
    let client = runtime_client(&first, &sender).await;
    client
        .send_message(&named_immediate_request(&recipient_name, "restart-queued"))
        .await
        .unwrap();
    first.stop().await;

    let second = runtime.start_broker().await;
    let replacement_sender = runtime_register(&second, "implementer", "w1:p1").await;
    let replacement_client = runtime_client(&second, &replacement_sender).await;
    let SendMessageResponse::Task(resumed) = replacement_client
        .send_message(&named_immediate_request(&recipient_name, "restart-queued"))
        .await
        .unwrap()
    else {
        panic!("exact retained retry did not return its task")
    };
    assert_eq!(resumed.id, "restart-queued");
    let mut mismatch = named_immediate_request(&recipient_name, "restart-queued");
    mismatch.message.parts = vec![Part::text("changed while offline")];
    assert!(replacement_client.send_message(&mismatch).await.is_err());
    assert!(
        replacement_client
            .send_message(&named_immediate_request(
                &recipient_name,
                "restart-no-live-recipient"
            ))
            .await
            .is_err()
    );
    let replacement_recipient = runtime_register(&second, "reviewer", "w1:p2").await;
    assert_eq!(replacement_recipient.agent.name.as_str(), recipient_name);
    let delivery = runtime_wait(&second, &replacement_recipient).await.unwrap();
    assert_eq!(delivery.task_id, "restart-queued");
    runtime_ack(&second, &replacement_recipient, &delivery).await;
    assert!(runtime_wait(&second, &replacement_recipient).await.is_err());
    replacement_client
        .cancel_task(&CancelTaskRequest {
            id: delivery.task_id,
            metadata: None,
            tenant: Some(recipient_name),
        })
        .await
        .unwrap();
    second.stop().await;
}

#[tokio::test]
#[cfg(feature = "test-support")]
async fn restart_identical_send_resumes_once_but_changed_request_conflicts() {
    // Break caught: recovered active retries enqueue twice, while changed payload/context values
    // are incorrectly treated as equivalent uses of the same idempotency key.
    let runtime = TestBrokerRuntime::new();
    let first = runtime.start_broker().await;
    let sender = runtime_register(&first, "implementer", "w1:p1").await;
    let original_recipient = runtime_register(&first, "reviewer", "w1:p2").await;
    let recipient_name = original_recipient.agent.name.as_str().to_owned();
    let client = runtime_client(&first, &sender).await;
    let original = named_immediate_request(&recipient_name, "restart-idempotent");
    let SendMessageResponse::Task(before) = client.send_message(&original).await.unwrap() else {
        panic!("expected task")
    };
    first.stop().await;

    let second = runtime.start_broker().await;
    let sender = runtime_register(&second, "implementer", "w1:p1").await;
    let recipient = runtime_register(&second, "reviewer", "w1:p2").await;
    assert_eq!(recipient.agent.name.as_str(), recipient_name);
    let client = runtime_client(&second, &sender).await;
    let SendMessageResponse::Task(resumed) = client.send_message(&original).await.unwrap() else {
        panic!("expected task")
    };
    assert_eq!(resumed, before);
    let delivery = runtime_wait(&second, &recipient).await.unwrap();
    assert_eq!(delivery.task_id, "restart-idempotent");
    assert!(runtime_wait(&second, &recipient).await.is_err());
    let mut changed = original;
    changed.message.parts = vec![Part::text("changed payload")];
    assert!(client.send_message(&changed).await.is_err());
    client
        .cancel_task(&CancelTaskRequest {
            id: delivery.task_id,
            metadata: None,
            tenant: Some(recipient_name),
        })
        .await
        .unwrap();
    second.stop().await;
}

#[tokio::test]
#[cfg(feature = "test-support")]
async fn restart_leased_unacknowledged_delivery_gets_a_fresh_delivery_id() {
    // Break caught: recovery retains the crashed process's lease identity or redelivers the same
    // lease token, allowing an obsolete acknowledgement to mutate the recovered task.
    let runtime = TestBrokerRuntime::new();
    let first = runtime.start_broker().await;
    let sender = runtime_register(&first, "implementer", "w1:p1").await;
    let recipient = runtime_register(&first, "reviewer", "w1:p2").await;
    let recipient_name = recipient.agent.name.as_str().to_owned();
    let client = runtime_client(&first, &sender).await;
    client
        .send_message(&named_immediate_request(&recipient_name, "restart-leased"))
        .await
        .unwrap();
    let old = runtime_wait(&first, &recipient).await.unwrap();
    first.stop().await;

    let second = runtime.start_broker().await;
    let replacement_sender = runtime_register(&second, "implementer", "w1:p1").await;
    let replacement_recipient = runtime_register(&second, "reviewer", "w1:p2").await;
    assert_eq!(replacement_recipient.agent.name.as_str(), recipient_name);
    let redelivered = runtime_wait(&second, &replacement_recipient).await.unwrap();
    assert_eq!(redelivered.task_id, "restart-leased");
    assert_ne!(redelivered.delivery_id, old.delivery_id);
    runtime_ack(&second, &replacement_recipient, &redelivered).await;
    runtime_reply(
        &second,
        &replacement_recipient,
        &redelivered.task_id,
        "replayed",
    )
    .await;
    let client = runtime_client(&second, &replacement_sender).await;
    assert_eq!(
        client
            .get_task(&GetTaskRequest {
                id: redelivered.task_id,
                history_length: None,
                tenant: Some(recipient_name),
            })
            .await
            .unwrap()
            .status
            .state,
        TaskState::Completed
    );
    second.stop().await;
}

#[tokio::test]
#[cfg(feature = "test-support")]
async fn restart_acknowledged_task_does_not_redeliver_and_accepts_reply() {
    // Break caught: startup rebuilds every nonterminal row into the recipient inbox instead of
    // preserving the acknowledged-awaiting-reply state.
    let runtime = TestBrokerRuntime::new();
    let first = runtime.start_broker().await;
    let sender = runtime_register(&first, "implementer", "w1:p1").await;
    let recipient = runtime_register(&first, "reviewer", "w1:p2").await;
    let recipient_name = recipient.agent.name.as_str().to_owned();
    let client = runtime_client(&first, &sender).await;
    client
        .send_message(&named_immediate_request(
            &recipient_name,
            "restart-acknowledged",
        ))
        .await
        .unwrap();
    let delivery = runtime_wait(&first, &recipient).await.unwrap();
    runtime_ack(&first, &recipient, &delivery).await;
    first.stop().await;

    let second = runtime.start_broker().await;
    let replacement_sender = runtime_register(&second, "implementer", "w1:p1").await;
    let replacement_recipient = runtime_register(&second, "reviewer", "w1:p2").await;
    assert_eq!(replacement_recipient.agent.name.as_str(), recipient_name);
    assert!(runtime_wait(&second, &replacement_recipient).await.is_err());
    let client = runtime_client(&second, &replacement_sender).await;
    let recovered = client
        .get_task(&GetTaskRequest {
            id: "restart-acknowledged".to_owned(),
            history_length: None,
            tenant: Some(recipient_name.clone()),
        })
        .await
        .unwrap();
    assert_eq!(recovered.status.state, TaskState::Working);
    let first_subscription = client
        .subscribe_to_task(&SubscribeToTaskRequest {
            id: "restart-acknowledged".to_owned(),
            tenant: Some(recipient_name.clone()),
        })
        .await
        .unwrap();
    let second_subscription = client
        .subscribe_to_task(&SubscribeToTaskRequest {
            id: "restart-acknowledged".to_owned(),
            tenant: Some(recipient_name.clone()),
        })
        .await
        .unwrap();
    let first_events =
        tokio::spawn(async move { first_subscription.try_collect::<Vec<_>>().await });
    let second_events =
        tokio::spawn(async move { second_subscription.try_collect::<Vec<_>>().await });
    tokio::task::yield_now().await;
    assert_eq!(second.task_list_count(), 0);
    runtime_reply(
        &second,
        &replacement_recipient,
        "restart-acknowledged",
        "after restart",
    )
    .await;
    let first_events = first_events.await.unwrap().unwrap();
    let second_events = second_events.await.unwrap().unwrap();
    for events in [&first_events, &second_events] {
        assert!(
            events
                .iter()
                .any(|event| completed_with_text(event, "after restart"))
        );
    }
    assert_eq!(
        client
            .get_task(&GetTaskRequest {
                id: "restart-acknowledged".to_owned(),
                history_length: None,
                tenant: Some(recipient_name),
            })
            .await
            .unwrap()
            .status
            .state,
        TaskState::Completed
    );
    assert_eq!(second.task_list_count(), 0);
    second.stop().await;
}

#[tokio::test]
#[cfg(feature = "test-support")]
async fn restart_all_terminal_states_retain_exact_distinct_projections() {
    // Break caught: restart reconstructs terminal A2A JSON with fresh timestamps/history instead
    // of returning the byte-identical durable projection retained before shutdown.
    let runtime = TestBrokerRuntime::new();
    let first = runtime.start_broker().await;
    let sender = runtime_register(&first, "implementer", "w1:p1").await;
    let recipient = runtime_register(&first, "reviewer", "w1:p2").await;
    let recipient_name = recipient.agent.name.as_str().to_owned();
    let client = runtime_client(&first, &sender).await;

    client
        .send_message(&named_immediate_request(
            &recipient_name,
            "restart-completed",
        ))
        .await
        .unwrap();
    let completed_delivery = runtime_wait(&first, &recipient).await.unwrap();
    runtime_reply(&first, &recipient, &completed_delivery.task_id, "complete").await;
    let completed = client
        .get_task(&GetTaskRequest {
            id: "restart-completed".to_owned(),
            history_length: None,
            tenant: Some(recipient_name.clone()),
        })
        .await
        .unwrap();

    client
        .send_message(&named_immediate_request(
            &recipient_name,
            "restart-canceled",
        ))
        .await
        .unwrap();
    let canceled = client
        .cancel_task(&CancelTaskRequest {
            id: "restart-canceled".to_owned(),
            metadata: None,
            tenant: Some(recipient_name.clone()),
        })
        .await
        .unwrap();

    client
        .send_message(&named_immediate_request(&recipient_name, "restart-failed"))
        .await
        .unwrap();
    first
        .fail_task(&recipient, "restart-failed", "execution failed")
        .await;
    let failed = client
        .get_task(&GetTaskRequest {
            id: "restart-failed".to_owned(),
            history_length: None,
            tenant: Some(recipient_name.clone()),
        })
        .await
        .unwrap();
    assert_eq!(failed.status.state, TaskState::Failed);
    assert_eq!(
        failed.status.message.as_ref().and_then(Message::text),
        Some("execution failed")
    );

    client
        .send_message(&named_immediate_request(
            &recipient_name,
            "restart-rejected",
        ))
        .await
        .unwrap();
    first
        .reject_task(&recipient, "restart-rejected", "request rejected")
        .await;
    let rejected = client
        .get_task(&GetTaskRequest {
            id: "restart-rejected".to_owned(),
            history_length: None,
            tenant: Some(recipient_name.clone()),
        })
        .await
        .unwrap();
    assert_eq!(rejected.status.state, TaskState::Rejected);
    assert_eq!(
        rejected.status.message.as_ref().and_then(Message::text),
        Some("request rejected")
    );

    client
        .send_message(&named_immediate_request(&recipient_name, "restart-expired"))
        .await
        .unwrap();
    first
        .advance_broker_time(Duration::from_secs(24 * 60 * 60))
        .await;
    let expired = client
        .get_task(&GetTaskRequest {
            id: "restart-expired".to_owned(),
            history_length: None,
            tenant: Some(recipient_name.clone()),
        })
        .await
        .unwrap();
    assert_eq!(expired.status.state, TaskState::Failed);
    first.stop().await;

    let second = runtime.start_broker().await;
    let replacement_sender = runtime_register(&second, "implementer", "w1:p1").await;
    let replacement_recipient = runtime_register(&second, "reviewer", "w1:p2").await;
    assert_eq!(replacement_recipient.agent.name.as_str(), recipient_name);
    let client = runtime_client(&second, &replacement_sender).await;
    for expected in [completed, canceled, failed, rejected, expired] {
        let actual = client
            .get_task(&GetTaskRequest {
                id: expected.id.clone(),
                history_length: None,
                tenant: Some(recipient_name.clone()),
            })
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_vec(&actual).unwrap(),
            serde_json::to_vec(&expected).unwrap()
        );
    }
    second.stop().await;
}

#[tokio::test]
#[cfg(feature = "test-support")]
async fn quarantined_legacy_task_is_inaccessible_and_never_executes() {
    // Break caught: an identity-less legacy projection is authorized from task_owners or enters
    // the recovered recipient inbox even though no stable sender principal exists.
    let runtime = TestBrokerRuntime::new();
    let store = SqliteTaskStore::open(runtime.database_path()).unwrap();
    drop(store);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let legacy = a2a::Task {
        id: "quarantined-a2a".to_owned(),
        context_id: "quarantined-context".to_owned(),
        status: a2a::TaskStatus {
            state: TaskState::Working,
            message: None,
            timestamp: Some(Utc.timestamp_millis_opt(now_ms).single().unwrap()),
        },
        artifacts: None,
        history: None,
        metadata: None,
    };
    let connection = rusqlite::Connection::open(runtime.database_path()).unwrap();
    connection
        .execute(
            "INSERT INTO tasks (task_id, context_id, state, status_timestamp, version, task_json)
         VALUES (?1, ?2, ?3, ?4, 1, ?5)",
            rusqlite::params![
                legacy.id,
                legacy.context_id,
                serde_json::to_value(&legacy.status.state)
                    .unwrap()
                    .as_str()
                    .unwrap(),
                legacy
                    .status
                    .timestamp
                    .unwrap()
                    .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
                serde_json::to_string(&legacy).unwrap(),
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO task_owners (task_id, registration_id, recipient)
         VALUES ('quarantined-a2a', '018f47d7-7b31-7cc4-98ef-87a57b028b55', 'reviewer')",
            [],
        )
        .unwrap();
    drop(connection);

    let running = runtime.start_broker().await;
    let sender = runtime_register(&running, "implementer", "w1:p1").await;
    let recipient = runtime_register(&running, "reviewer", "w1:p2").await;
    let client = runtime_client(&running, &sender).await;
    assert!(
        runtime_wait(&running, &recipient).await.is_err(),
        "quarantined legacy work entered the recipient inbox"
    );
    assert!(
        client
            .get_task(&GetTaskRequest {
                id: "quarantined-a2a".to_owned(),
                history_length: None,
                tenant: Some("reviewer".to_owned()),
            })
            .await
            .is_err()
    );
    let listed = client
        .list_tasks(&list_request(10.into(), None))
        .await
        .unwrap();
    assert!(listed.tasks.iter().all(|task| task.id != "quarantined-a2a"));
    assert!(
        client
            .send_message(&named_immediate_request("reviewer", "quarantined-a2a"))
            .await
            .is_err()
    );
    running.stop().await;
}

fn completed_with_text(event: &StreamResponse, text: &str) -> bool {
    let StreamResponse::Task(task) = event else {
        return false;
    };
    task.status.state == TaskState::Completed
        && task
            .status
            .message
            .as_ref()
            .is_some_and(|message| message.role == Role::Agent && message.text() == Some(text))
}

async fn ready_after_scheduler_turns<F: std::future::Future>(future: F) -> F::Output {
    tokio::pin!(future);
    for _ in 0..10_000 {
        tokio::select! {
            biased;
            result = &mut future => return result,
            _ = tokio::task::yield_now() => {}
        }
    }
    panic!("operation did not become ready after deterministic scheduler turns")
}

#[tokio::test]
async fn official_client_streams_reply_from_named_recipient() {
    let running = TestBroker::start().await;
    let sender = running.register("implementer", "w1:p1").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let client = running.a2a_client(&card, &sender).await;

    let stream = client
        .send_streaming_message(&request_for(recipient.agent.name.as_str(), "review this"))
        .await
        .unwrap();
    let inbound = running.wait_message(&recipient).await;
    running
        .reply(&recipient, &inbound.task_id, "looks good")
        .await;

    let events: Vec<_> = stream.try_collect().await.unwrap();
    assert!(
        events
            .iter()
            .any(|event| completed_with_text(event, "looks good"))
    );
    let completed = events
        .iter()
        .find_map(|event| match event {
            StreamResponse::Task(task) if task.status.state == TaskState::Completed => Some(task),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        completed
            .history
            .as_ref()
            .and_then(|history| history.first())
            .and_then(Message::text),
        Some("review this")
    );
}

#[tokio::test]
async fn terminal_task_id_is_reserved_until_retention_expires() {
    // Break caught: terminal IDs that never expire prevent an intentional same-ID retry from
    // starting a new delivery after the durable replay window ends.
    let clock = TestClock::at(1_000);
    let running = TestBroker::start_with_clock(clock.clone()).await;
    let sender = running.register("implementer", "w1:p1").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let client = running.a2a_client(&card, &sender).await;
    let task_id = "terminal-resend-after-prune";
    let mut stream = client
        .send_streaming_message(&named_request(recipient.agent.name.as_str(), task_id))
        .await
        .unwrap();
    assert!(matches!(
        stream.try_next().await.unwrap().unwrap(),
        StreamResponse::Task(task) if task.status.state == TaskState::Submitted
    ));
    let inbound = running.wait_message(&recipient).await;
    running
        .reply(&recipient, &inbound.task_id, "original terminal response")
        .await;
    let original = stream
        .try_collect::<Vec<_>>()
        .await
        .unwrap()
        .into_iter()
        .find_map(|event| match event {
            StreamResponse::Task(task) if task.status.state.is_terminal() => Some(task),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        running.store.get(task_id).await.unwrap(),
        Some(original.clone())
    );

    let response = client
        .send_message(&named_immediate_request(
            recipient.agent.name.as_str(),
            task_id,
        ))
        .await
        .unwrap();
    let SendMessageResponse::Task(replay) = response else {
        panic!("terminal replay returned a message")
    };
    assert_eq!(replay, original);
    assert_eq!(
        running
            .broker
            .wait_next(&recipient.credentials(), Some(Duration::from_millis(1)))
            .await,
        Err(DomainError::WaitTimedOut)
    );
    let mut stored_terminal = running.store.get(task_id).await.unwrap().unwrap();
    stored_terminal.status.timestamp = Some(Utc.timestamp_millis_opt(1_000).single().unwrap());
    running.store.update(stored_terminal).await.unwrap();

    let mut remaining_ms = 30 * 24 * 60 * 60 * 1_000 + 1;
    while remaining_ms > 0 {
        let step_ms = remaining_ms.min(29_000);
        clock.advance(step_ms);
        running.broker.renew(&sender.credentials()).await.unwrap();
        running
            .broker
            .renew(&recipient.credentials())
            .await
            .unwrap();
        remaining_ms -= step_ms;
    }
    assert_eq!(running.broker.list_agents().await.len(), 2);

    let response = client
        .send_message(&named_immediate_request(
            recipient.agent.name.as_str(),
            task_id,
        ))
        .await
        .unwrap();
    let SendMessageResponse::Task(resent) = response else {
        panic!("terminal resend returned a message")
    };
    assert!(!resent.status.state.is_terminal());
    let redelivered = running.wait_message(&recipient).await;
    assert_eq!(redelivered.task_id, task_id);
}

#[tokio::test]
async fn unanswered_unary_send_does_not_block_a_different_task_start() {
    let running = TestBroker::start().await;
    let sender = running.register("implementer", "w1:p1").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let client = Arc::new(running.a2a_client(&card, &sender).await);
    let unary = {
        let client = Arc::clone(&client);
        let recipient_name = recipient.agent.name.as_str().to_owned();
        tokio::spawn(async move {
            client
                .send_message(&request_for(&recipient_name, "blocking unary"))
                .await
        })
    };
    let first = running.wait_message(&recipient).await;

    let stream = ready_after_scheduler_turns(client.send_streaming_message(
        &named_immediate_request(recipient.agent.name.as_str(), "unrelated-task"),
    ))
    .await
    .unwrap();
    let second = running.wait_message(&recipient).await;
    assert_eq!(second.task_id, "unrelated-task");

    running
        .reply(&recipient, &first.task_id, "first done")
        .await;
    running
        .reply(&recipient, &second.task_id, "second done")
        .await;
    unary.await.unwrap().unwrap();
    stream.try_collect::<Vec<_>>().await.unwrap();
}

#[tokio::test]
async fn aborted_unary_client_can_resubscribe_and_receive_terminal_reply() {
    let running = TestBroker::start().await;
    let sender = running.register("implementer", "w1:p1").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let client = Arc::new(running.a2a_client(&card, &sender).await);
    let unary = {
        let client = Arc::clone(&client);
        let recipient_name = recipient.agent.name.as_str().to_owned();
        tokio::spawn(async move {
            client
                .send_message(&named_request(&recipient_name, "aborted-unary"))
                .await
        })
    };
    let inbound = running.wait_message(&recipient).await;
    unary.abort();

    let stream = client
        .subscribe_to_task(&SubscribeToTaskRequest {
            id: inbound.task_id.clone(),
            tenant: Some(recipient.agent.name.as_str().to_owned()),
        })
        .await
        .unwrap();
    running
        .reply(&recipient, &inbound.task_id, "continued after abort")
        .await;
    let events = stream.try_collect::<Vec<_>>().await.unwrap();

    assert!(
        events
            .iter()
            .any(|event| completed_with_text(event, "continued after abort"))
    );
}

#[tokio::test]
async fn dynamic_card_describes_named_jsonrpc_streaming_agent() {
    let running = TestBroker::start().await;
    let recipient = running.register("reviewer", "w1:p2").await;

    let card = running.resolve_card("reviewer").await;

    assert_eq!(card.name, recipient.agent.name.as_str());
    assert_eq!(card.supported_interfaces.len(), 1);
    let interface = &card.supported_interfaces[0];
    assert_eq!(interface.url, format!("{}/jsonrpc", running.base_url));
    assert_eq!(interface.protocol_binding, "JSONRPC");
    assert_eq!(
        interface.tenant.as_deref(),
        Some(recipient.agent.name.as_str())
    );
    assert_eq!(card.capabilities.streaming, Some(true));
    assert_eq!(card.capabilities.push_notifications, Some(false));
    assert_eq!(card.default_input_modes, ["text/plain"]);
    assert_eq!(card.default_output_modes, ["text/plain"]);
    assert_eq!(card.skills.len(), 1);
    assert_eq!(card.skills[0].id, "collaborate");
}

#[tokio::test]
async fn agent_cards_require_bearer_and_unknown_names_are_not_advertised() {
    let running = TestBroker::start().await;

    let unauthorized = reqwest::get(format!(
        "{}/agents/reviewer/.well-known/agent-card.json",
        running.base_url
    ))
    .await
    .unwrap();
    let unknown = reqwest::Client::new()
        .get(format!(
            "{}/agents/reviewer/.well-known/agent-card.json",
            running.base_url
        ))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap();

    assert_eq!(unauthorized.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(unknown.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn jsonrpc_requires_the_same_bearer_as_agent_cards() {
    let running = TestBroker::start().await;

    let response = reqwest::Client::new()
        .post(format!("{}/jsonrpc", running.base_url))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": "unauthorized",
            "method": "MessageSend",
            "params": {}
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unknown_tenant_is_rejected_by_official_client_call() {
    let running = TestBroker::start().await;
    let sender = running.register("implementer", "w1:p1").await;
    running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let client = running.a2a_client(&card, &sender).await;

    let error = client
        .send_message(&request_for("missing", "review this"))
        .await
        .unwrap_err();

    assert!(error.message.contains("agent is not registered"));
    assert_eq!(running.stored_task_count().await, 0);
}

#[tokio::test]
async fn unregistered_sender_header_is_rejected_by_official_client_call() {
    let running = TestBroker::start().await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let unknown = herdr_a2a_core::RegistrationId::new();
    let client = running
        .a2a_client_with_registration(&card, unknown.as_str())
        .await;

    let error = client
        .send_message(&request_for(recipient.agent.name.as_str(), "review this"))
        .await
        .unwrap_err();

    assert!(error.message.contains("sender registration is not active"));
    assert_eq!(running.stored_task_count().await, 0);
}

#[tokio::test]
async fn replaced_epoch_rejects_a2a_send_before_task_state_changes() {
    let running = TestBroker::start().await;
    running.register("implementer", "w1:p1").await;
    let current = running.register("implementer", "w1:p3").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let client = A2AClientFactory::builder()
        .with_interceptor(Arc::new(AuthInterceptor::bearer(TOKEN)))
        .with_interceptor(Arc::new(AuthInterceptor::custom(
            REGISTRATION_HEADER,
            current.id.as_str(),
        )))
        .with_interceptor(Arc::new(AuthInterceptor::custom(
            "x-herdr-a2a-registration-epoch",
            "1",
        )))
        .build()
        .create_from_card(&card)
        .await
        .unwrap();

    let result = client
        .send_message(&named_immediate_request(
            recipient.agent.name.as_str(),
            "stale-epoch-red",
        ))
        .await;

    assert!(result.is_err(), "SendMessage accepted replaced epoch");
    assert_eq!(running.stored_task_count().await, 0);
}

#[tokio::test]
async fn missing_malformed_and_replaced_epochs_reject_send_get_and_subscribe_without_mutation() {
    let running = TestBroker::start().await;
    let first = running.register("implementer", "w1:p1").await;
    let current = running.register("implementer", "w1:p3").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let valid = running.a2a_client(&card, &current).await;
    let response = valid
        .send_message(&named_immediate_request(
            recipient.agent.name.as_str(),
            "epoch-owned",
        ))
        .await
        .unwrap();
    let SendMessageResponse::Task(task) = response else {
        panic!("return_immediately returned a message")
    };
    assert_eq!(running.stored_task_count().await, 1);

    let current_epoch = current.epoch.get().to_string();
    let replaced_epoch = first.epoch.get().to_string();
    for (label, epoch) in [
        ("missing", None),
        ("alpha", Some("abc")),
        ("zero", Some("0")),
        ("leading-zero", Some("01")),
        ("replaced", Some(replaced_epoch.as_str())),
    ] {
        let client = running
            .a2a_client_with_epoch(&card, current.id.as_str(), epoch)
            .await;
        assert!(
            client
                .send_message(&named_immediate_request(
                    recipient.agent.name.as_str(),
                    &format!("epoch-invalid-{label}"),
                ))
                .await
                .is_err(),
            "SendMessage accepted {label} epoch"
        );
        assert!(
            client
                .get_task(&GetTaskRequest {
                    id: task.id.clone(),
                    history_length: None,
                    tenant: Some(recipient.agent.name.as_str().to_owned()),
                })
                .await
                .is_err(),
            "GetTask accepted {label} epoch"
        );
        match client
            .subscribe_to_task(&SubscribeToTaskRequest {
                id: task.id.clone(),
                tenant: Some(recipient.agent.name.as_str().to_owned()),
            })
            .await
        {
            Err(_) => {}
            Ok(mut stream) => assert!(
                stream.try_next().await.is_err(),
                "SubscribeToTask accepted {label} epoch"
            ),
        }
        assert_eq!(running.stored_task_count().await, 1);
    }

    let valid_epoch_client = running
        .a2a_client_with_epoch(&card, current.id.as_str(), Some(current_epoch.as_str()))
        .await;
    assert!(
        valid_epoch_client
            .get_task(&GetTaskRequest {
                id: task.id,
                history_length: None,
                tenant: Some(recipient.agent.name.as_str().to_owned()),
            })
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn herdr_recipient_claim_must_match_a2a_tenant() {
    let running = TestBroker::start().await;
    let sender = running.register("implementer", "w1:p1").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let client = running.a2a_client(&card, &sender).await;
    let mut request = request_for(recipient.agent.name.as_str(), "review this");
    request.metadata = Some(HashMap::from([(
        "herdr".to_owned(),
        json!({"recipient": "implementer"}),
    )]));
    request.configuration = immediate_request_for("reviewer", "unused").configuration;

    let error = client.send_message(&request).await.unwrap_err();

    assert!(
        error
            .message
            .contains("recipient claim does not match tenant")
    );
    assert_eq!(running.stored_task_count().await, 0);
}

#[tokio::test]
async fn reserved_herdr_file_references_are_rejected_before_persistence() {
    let running = TestBroker::start().await;
    let sender = running.register("implementer", "w1:p1").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let client = running.a2a_client(&card, &sender).await;
    let mut request = immediate_request_for(recipient.agent.name.as_str(), "review this");
    request.metadata = Some(HashMap::from([(
        "herdr".to_owned(),
        json!({"file_refs": [{"path": "/repo/review.txt"}]}),
    )]));

    let error = client.send_message(&request).await.unwrap_err();

    assert!(error.message.contains("file references are not supported"));
    assert_eq!(running.stored_task_count().await, 0);
}

#[tokio::test]
async fn invalid_task_ids_are_rejected_before_owner_or_task_persistence() {
    // Break caught: attacker-controlled A2A task IDs reach the SQLite owner claim and task store.
    let invalid_ids = [
        ".".to_owned(),
        "..".to_owned(),
        "task/child".to_owned(),
        r"task\child".to_owned(),
        "task?query".to_owned(),
        "task#fragment".to_owned(),
        "%2e%2e".to_owned(),
        "tâsk".to_owned(),
        "x".repeat(257),
    ];

    for task_id in invalid_ids {
        let running = TestBroker::start().await;
        let sender = running.register("implementer", "w1:p1").await;
        running.register("reviewer", "w1:p2").await;
        let card = running.resolve_card("reviewer").await;
        let client = running.a2a_client(&card, &sender).await;

        let error = client
            .send_message(&named_immediate_request("reviewer", &task_id))
            .await
            .unwrap_err();

        assert!(
            error.message.contains("invalid task ID"),
            "{task_id:?}: {error:?}"
        );
        assert_eq!(running.store.task_owner(&task_id).await.unwrap(), None);
        assert_eq!(running.stored_task_count().await, 0);
    }
}

#[tokio::test]
async fn raw_a2a_explicit_empty_task_id_is_rejected_but_omitted_id_is_generated() {
    // Break caught: ProtoJSON collapses explicit taskId:"" into an absent ID before preflight.
    let running = TestBroker::start().await;
    let sender = running.register("implementer", "w1:p1").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let recipient_name = recipient.agent.name.as_str().to_owned();
    let client = reqwest::Client::new();
    let request = |id: &str, method: &str, task_id: Option<(&str, &str)>| {
        let mut message = json!({
            "messageId": format!("message-{id}"),
            "role": "ROLE_USER",
            "parts": [{"text": "review this"}]
        });
        if let Some((field, task_id)) = task_id {
            message[field] = json!(task_id);
        }
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": {
                "tenant": recipient_name,
                "message": message,
                "configuration": {"returnImmediately": true}
            }
        })
    };

    for method in ["SendMessage", "SendStreamingMessage"] {
        for field in ["taskId", "task_id"] {
            let label = format!("{method}-{field}");
            let explicit_empty = tokio::time::timeout(Duration::from_secs(2), async {
                client
                    .post(format!("{}/jsonrpc", running.base_url))
                    .bearer_auth(TOKEN)
                    .header(REGISTRATION_HEADER, sender.id.as_str())
                    .header(REGISTRATION_EPOCH_HEADER, sender.epoch.get())
                    .json(&request(&label, method, Some((field, ""))))
                    .send()
                    .await
                    .unwrap()
                    .error_for_status()
                    .unwrap()
                    .text()
                    .await
                    .unwrap()
            })
            .await
            .unwrap_or_else(|_| panic!("explicit empty task ID started work: {label}"));

            assert_eq!(running.stored_task_count().await, 0, "{label}");
            assert!(explicit_empty.contains("invalid task ID"), "{label}");
            assert_eq!(running.store.task_owner("").await.unwrap(), None, "{label}");
        }
    }

    let omitted: serde_json::Value = client
        .post(format!("{}/jsonrpc", running.base_url))
        .bearer_auth(TOKEN)
        .header(REGISTRATION_HEADER, sender.id.as_str())
        .header(REGISTRATION_EPOCH_HEADER, sender.epoch.get())
        .json(&request("omitted", "SendMessage", None))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let generated_id = omitted["result"]["task"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("omitted task ID was not generated: {omitted}"));

    assert!(herdr_a2a_core::validate_task_id(generated_id).is_ok());
    assert_eq!(
        running
            .store
            .task_principal(generated_id)
            .await
            .unwrap()
            .unwrap()
            .sender,
        sender.agent.name
    );
    assert_eq!(running.stored_task_count().await, 1);
}

#[tokio::test]
async fn raw_explicit_context_ids_are_preflighted_for_unary_and_streaming_sends() {
    // Break caught: explicit public context IDs bypassed preflight and failed only after a task
    // transition reached durable validation, with unstable persistence/domain errors.
    for method in ["SendMessage", "SendStreamingMessage"] {
        for field in ["contextId", "context_id"] {
            for context_id in ["", ".", "..", "context/child", "tâsk"] {
                let running = TestBroker::start().await;
                let sender = running.register("implementer", "w1:p1").await;
                let recipient = running.register("reviewer", "w1:p2").await;
                let mut message = json!({
                    "messageId": "context-preflight",
                    "role": "ROLE_USER",
                    "parts": [{"text": "review this"}]
                });
                message[field] = json!(context_id);
                let response = reqwest::Client::new()
                    .post(format!("{}/jsonrpc", running.base_url))
                    .bearer_auth(TOKEN)
                    .header(REGISTRATION_HEADER, sender.id.as_str())
                    .header(REGISTRATION_EPOCH_HEADER, sender.epoch.get())
                    .json(&json!({
                        "jsonrpc": "2.0",
                        "id": format!("{method}-{field}-{context_id}"),
                        "method": method,
                        "params": {
                            "tenant": recipient.agent.name.as_str(),
                            "message": message,
                            "configuration": {"returnImmediately": true}
                        }
                    }))
                    .send()
                    .await
                    .unwrap()
                    .error_for_status()
                    .unwrap()
                    .text()
                    .await
                    .unwrap();

                assert!(
                    response.contains("invalid context ID"),
                    "{method}/{field}/{context_id:?}: {response}"
                );
                assert_eq!(
                    running.stored_task_count().await,
                    0,
                    "{method}/{field}/{context_id:?}"
                );
            }
        }
    }
}

#[tokio::test]
async fn raw_a2a_presence_inspection_keeps_the_jsonrpc_body_bounded() {
    // Break caught: inspecting taskId buffers an unbounded JSON-RPC body before official parsing.
    let running = TestBroker::start().await;
    let sender = running.register("implementer", "w1:p1").await;

    let response = reqwest::Client::new()
        .post(format!("{}/jsonrpc", running.base_url))
        .bearer_auth(TOKEN)
        .header(REGISTRATION_HEADER, sender.id.as_str())
        .header(REGISTRATION_EPOCH_HEADER, sender.epoch.get())
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(vec![b' '; MAX_JSON_BODY_BYTES + 1])
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(running.stored_task_count().await, 0);
}

#[tokio::test]
async fn task_id_owner_lookup_rejects_invalid_ids_before_store_access() {
    // Break caught: non-send A2A methods use attacker-controlled IDs for owner lookups.
    let running = TestBroker::start().await;
    let sender = running.register("implementer", "w1:p1").await;
    let _recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let client = running.a2a_client(&card, &sender).await;

    let error = client
        .get_task(&GetTaskRequest {
            id: "../task".to_owned(),
            history_length: None,
            tenant: Some("reviewer".to_owned()),
        })
        .await
        .unwrap_err();

    assert!(error.message.contains("invalid task ID"), "{error:?}");
}

#[tokio::test]
async fn mixed_text_and_non_text_parts_are_rejected_before_persistence() {
    for unsupported in [
        Part::url("file:///repo/review.txt"),
        Part::raw(b"review material".to_vec()),
        Part::data(json!({"path": "/repo/review.txt"})),
    ] {
        let running = TestBroker::start().await;
        let sender = running.register("implementer", "w1:p1").await;
        let recipient = running.register("reviewer", "w1:p2").await;
        let card = running.resolve_card("reviewer").await;
        let client = running.a2a_client(&card, &sender).await;
        let mut request = immediate_request_for(recipient.agent.name.as_str(), "review this");
        request.message.parts.push(unsupported);

        let error = client.send_message(&request).await.unwrap_err();

        assert_eq!(error.code, error_code::CONTENT_TYPE_NOT_SUPPORTED);
        assert_eq!(running.stored_task_count().await, 0);
    }
}

#[tokio::test]
async fn multipart_two_text_parts_are_rejected_before_persistence() {
    // Break caught: Message::text() silently selects one of multiple accepted text parts.
    let running = TestBroker::start().await;
    let sender = running.register("implementer", "w1:p1").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let client = running.a2a_client(&card, &sender).await;
    let mut request = immediate_request_for(recipient.agent.name.as_str(), "first");
    request.message.parts.push(Part::text("second"));

    let error = client.send_message(&request).await.unwrap_err();

    assert!(error.message.contains("exactly one text part"), "{error:?}");
    assert_eq!(running.stored_task_count().await, 0);
}

#[tokio::test]
async fn multipart_oversized_second_text_part_is_rejected_before_persistence() {
    // Break caught: an oversized trailing text part is silently discarded after validation.
    let running = TestBroker::start().await;
    let sender = running.register("implementer", "w1:p1").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let client = running.a2a_client(&card, &sender).await;
    let mut request = immediate_request_for(recipient.agent.name.as_str(), "first");
    request
        .message
        .parts
        .push(Part::text("x".repeat(64 * 1024 + 1)));

    let error = client.send_message(&request).await.unwrap_err();

    assert!(error.message.contains("exactly one text part"), "{error:?}");
    assert_eq!(running.stored_task_count().await, 0);
}

#[tokio::test]
async fn multipart_single_bounded_text_part_succeeds() {
    // Break caught: the exact-one-part rule accidentally rejects the supported text-only shape.
    let running = TestBroker::start().await;
    let sender = running.register("implementer", "w1:p1").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let client = running.a2a_client(&card, &sender).await;

    let response = client
        .send_message(&named_immediate_request(
            recipient.agent.name.as_str(),
            &"x".repeat(256),
        ))
        .await
        .unwrap();

    assert!(matches!(response, SendMessageResponse::Task(_)));
    assert_eq!(running.stored_task_count().await, 1);
}

#[tokio::test]
async fn file_like_text_part_fields_are_rejected_before_persistence() {
    for unsupported in [
        Part::text("review this").with_filename("review.txt"),
        Part::text("review this").with_media_type("text/markdown"),
    ] {
        let running = TestBroker::start().await;
        let sender = running.register("implementer", "w1:p1").await;
        let recipient = running.register("reviewer", "w1:p2").await;
        let card = running.resolve_card("reviewer").await;
        let client = running.a2a_client(&card, &sender).await;
        let mut request = immediate_request_for(recipient.agent.name.as_str(), "unused");
        request.message.parts = vec![unsupported];

        let error = client.send_message(&request).await.unwrap_err();

        assert!(error.message.contains("file references are not supported"));
        assert_eq!(running.stored_task_count().await, 0);
    }
}

#[tokio::test]
async fn part_metadata_is_rejected_before_persistence() {
    for metadata in [
        HashMap::from([(
            "herdr".to_owned(),
            json!({"fileRefs": [{"path": "/repo/review.txt"}]}),
        )]),
        HashMap::from([("oversized".to_owned(), json!("x".repeat(32 * 1024)))]),
        HashMap::from([("priority".to_owned(), json!("high"))]),
    ] {
        let running = TestBroker::start().await;
        let sender = running.register("implementer", "w1:p1").await;
        let recipient = running.register("reviewer", "w1:p2").await;
        let card = running.resolve_card("reviewer").await;
        let client = running.a2a_client(&card, &sender).await;
        let mut request = immediate_request_for(recipient.agent.name.as_str(), "review this");
        request.message.parts[0].metadata = Some(metadata);

        let error = client.send_message(&request).await.unwrap_err();

        assert!(error.message.contains("part metadata is not supported"));
        assert_eq!(running.stored_task_count().await, 0);
    }
}

#[tokio::test]
async fn oversized_text_is_rejected_before_persistence() {
    let running = TestBroker::start().await;
    let sender = running.register("implementer", "w1:p1").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let client = running.a2a_client(&card, &sender).await;
    let request = immediate_request_for(recipient.agent.name.as_str(), &"x".repeat(64 * 1024 + 1));

    let error = client.send_message(&request).await.unwrap_err();

    assert!(error.message.contains("text exceeds"));
    assert_eq!(running.stored_task_count().await, 0);
}

#[tokio::test]
async fn oversized_metadata_is_rejected_before_persistence() {
    let running = TestBroker::start().await;
    let sender = running.register("implementer", "w1:p1").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let client = running.a2a_client(&card, &sender).await;
    let mut request = immediate_request_for(recipient.agent.name.as_str(), "review this");
    request.message.metadata = Some(HashMap::from([(
        "oversized".to_owned(),
        json!("x".repeat(32 * 1024)),
    )]));

    let error = client.send_message(&request).await.unwrap_err();

    assert!(error.message.contains("metadata exceeds"));
    assert_eq!(running.stored_task_count().await, 0);
}

#[tokio::test]
async fn claimed_sender_name_cannot_override_authenticated_registration() {
    let running = TestBroker::start().await;
    let sender = running.register("implementer", "w1:p1").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let client = running.a2a_client(&card, &sender).await;
    let mut request = request_for(recipient.agent.name.as_str(), "review this");
    request.metadata = Some(HashMap::from([(
        "herdr".to_owned(),
        json!({"sender": "reviewer", "recipient": recipient.agent.name.as_str()}),
    )]));

    let response = client
        .send_message(&immediate_request_with_metadata(request))
        .await
        .unwrap();
    let inbound = running.wait_message(&recipient).await;

    let SendMessageResponse::Task(task) = response else {
        panic!("return_immediately returned a message")
    };
    assert_eq!(inbound.sender, sender.agent.name);
    client
        .cancel_task(&CancelTaskRequest {
            id: task.id,
            metadata: None,
            tenant: Some(recipient.agent.name.as_str().to_owned()),
        })
        .await
        .unwrap();
}

fn immediate_request_with_metadata(mut request: SendMessageRequest) -> SendMessageRequest {
    request.configuration = immediate_request_for("reviewer", "unused").configuration;
    request
}

#[tokio::test]
async fn non_streaming_return_immediately_yields_working_task() {
    let running = TestBroker::start().await;
    let sender = running.register("implementer", "w1:p1").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let client = running.a2a_client(&card, &sender).await;

    let response = client
        .send_message(&immediate_request_for(
            recipient.agent.name.as_str(),
            "review this",
        ))
        .await
        .unwrap();
    let SendMessageResponse::Task(task) = response else {
        panic!("return_immediately returned a message")
    };

    assert_eq!(task.status.state, TaskState::Submitted);
    let inbound = running.wait_message(&recipient).await;
    assert_eq!(inbound.task_id, task.id);
    client
        .cancel_task(&CancelTaskRequest {
            id: task.id,
            metadata: None,
            tenant: Some(recipient.agent.name.as_str().to_owned()),
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn message_metadata_is_preserved_in_recipient_delivery() {
    let running = TestBroker::start().await;
    let sender = running.register("implementer", "w1:p1").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let client = running.a2a_client(&card, &sender).await;
    let mut request = immediate_request_for(recipient.agent.name.as_str(), "review this");
    request.message.metadata = Some(HashMap::from([("priority".to_owned(), json!("high"))]));

    let response = client.send_message(&request).await.unwrap();
    let SendMessageResponse::Task(task) = response else {
        panic!("return_immediately returned a message")
    };
    let inbound = running.wait_message(&recipient).await;

    assert_eq!(inbound.payload.metadata, json!({"priority": "high"}));
    client
        .cancel_task(&CancelTaskRequest {
            id: task.id,
            metadata: None,
            tenant: Some(recipient.agent.name.as_str().to_owned()),
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn authenticated_sender_can_cancel_its_streaming_task() {
    let running = TestBroker::start().await;
    let sender = running.register("implementer", "w1:p1").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let client = running.a2a_client(&card, &sender).await;
    let mut stream = client
        .send_streaming_message(&request_for(recipient.agent.name.as_str(), "review this"))
        .await
        .unwrap();
    let working = stream.try_next().await.unwrap().unwrap();
    let task_id = task_id(&working).unwrap().to_owned();

    let canceled = client
        .cancel_task(&CancelTaskRequest {
            id: task_id.clone(),
            metadata: None,
            tenant: Some(recipient.agent.name.as_str().to_owned()),
        })
        .await
        .unwrap();

    assert_eq!(canceled.id, task_id);
    assert_eq!(canceled.status.state, TaskState::Canceled);
    let events: Vec<_> = stream.try_collect().await.unwrap();
    assert!(events.iter().any(|event| {
        matches!(event, StreamResponse::Task(task) if task.status.state == TaskState::Canceled)
    }));
}

#[tokio::test]
async fn a_different_registered_sender_cannot_cancel_the_task() {
    let running = TestBroker::start().await;
    let sender = running.register("implementer", "w1:p1").await;
    let intruder = running.register("observer", "w1:p3").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let owner_client = running.a2a_client(&card, &sender).await;
    let intruder_client = running.a2a_client(&card, &intruder).await;
    let mut stream = owner_client
        .send_streaming_message(&request_for(recipient.agent.name.as_str(), "review this"))
        .await
        .unwrap();
    let working = stream.try_next().await.unwrap().unwrap();
    let task_id = task_id(&working).unwrap().to_owned();

    let error = intruder_client
        .cancel_task(&CancelTaskRequest {
            id: task_id.clone(),
            metadata: None,
            tenant: Some(recipient.agent.name.as_str().to_owned()),
        })
        .await
        .unwrap_err();

    assert!(error.message.contains("owned by another agent"));
    owner_client
        .cancel_task(&CancelTaskRequest {
            id: task_id,
            metadata: None,
            tenant: Some(recipient.agent.name.as_str().to_owned()),
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn a_different_registration_cannot_get_an_owned_task() {
    let running = TestBroker::start().await;
    let owner = running.register("implementer", "w1:p1").await;
    let intruder = running.register("observer", "w1:p3").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let owner_client = running.a2a_client(&card, &owner).await;
    let intruder_client = running.a2a_client(&card, &intruder).await;
    let response = owner_client
        .send_message(&named_immediate_request(
            recipient.agent.name.as_str(),
            "owner-get",
        ))
        .await
        .unwrap();
    let SendMessageResponse::Task(task) = response else {
        panic!("return_immediately returned a message")
    };

    let result = intruder_client
        .get_task(&GetTaskRequest {
            id: task.id.clone(),
            history_length: None,
            tenant: Some(recipient.agent.name.as_str().to_owned()),
        })
        .await;

    assert!(result.is_err());
    owner_client
        .cancel_task(&CancelTaskRequest {
            id: task.id,
            metadata: None,
            tenant: Some(recipient.agent.name.as_str().to_owned()),
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn a_different_registration_cannot_subscribe_to_an_owned_task() {
    let running = TestBroker::start().await;
    let owner = running.register("implementer", "w1:p1").await;
    let intruder = running.register("observer", "w1:p3").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let owner_client = running.a2a_client(&card, &owner).await;
    let intruder_client = running.a2a_client(&card, &intruder).await;
    let mut stream = owner_client
        .send_streaming_message(&request_for(
            recipient.agent.name.as_str(),
            "subscribe-owner",
        ))
        .await
        .unwrap();
    let working = stream.try_next().await.unwrap().unwrap();
    let task_id = task_id(&working).unwrap().to_owned();

    let mut result = intruder_client
        .subscribe_to_task(&SubscribeToTaskRequest {
            id: task_id.clone(),
            tenant: Some(recipient.agent.name.as_str().to_owned()),
        })
        .await
        .unwrap();

    assert!(result.try_next().await.is_err());
    owner_client
        .cancel_task(&CancelTaskRequest {
            id: task_id,
            metadata: None,
            tenant: Some(recipient.agent.name.as_str().to_owned()),
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn same_owner_must_use_the_original_recipient_for_task_operations() {
    let running = TestBroker::start().await;
    let owner = running.register("implementer", "w1:p1").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let owner_client = running.a2a_client(&card, &owner).await;
    let response = owner_client
        .send_message(&named_immediate_request(
            recipient.agent.name.as_str(),
            "recipient-bound",
        ))
        .await
        .unwrap();
    let SendMessageResponse::Task(task) = response else {
        panic!("return_immediately returned a message")
    };

    let wrong_get = owner_client
        .get_task(&GetTaskRequest {
            id: task.id.clone(),
            history_length: None,
            tenant: Some("implementer".to_owned()),
        })
        .await;
    let mut wrong_subscribe = owner_client
        .subscribe_to_task(&SubscribeToTaskRequest {
            id: task.id.clone(),
            tenant: Some("implementer".to_owned()),
        })
        .await
        .unwrap();
    let wrong_cancel = owner_client
        .cancel_task(&CancelTaskRequest {
            id: task.id.clone(),
            metadata: None,
            tenant: Some("implementer".to_owned()),
        })
        .await;

    assert!(wrong_get.is_err());
    assert!(wrong_subscribe.try_next().await.is_err());
    assert!(wrong_cancel.is_err());

    let fetched = owner_client
        .get_task(&GetTaskRequest {
            id: task.id.clone(),
            history_length: None,
            tenant: Some(recipient.agent.name.as_str().to_owned()),
        })
        .await
        .unwrap();
    assert_eq!(fetched.id, task.id);
    let subscription = owner_client
        .subscribe_to_task(&SubscribeToTaskRequest {
            id: task.id.clone(),
            tenant: Some(recipient.agent.name.as_str().to_owned()),
        })
        .await
        .unwrap();
    let canceled = owner_client
        .cancel_task(&CancelTaskRequest {
            id: task.id,
            metadata: None,
            tenant: Some(recipient.agent.name.as_str().to_owned()),
        })
        .await
        .unwrap();
    assert_eq!(canceled.status.state, TaskState::Canceled);
    assert!(
        subscription
            .try_collect::<Vec<_>>()
            .await
            .unwrap()
            .iter()
            .any(|event| matches!(event, StreamResponse::Task(task) if task.status.state == TaskState::Canceled))
    );
}

#[tokio::test]
async fn missing_registration_is_denied_for_every_task_operation() {
    let running = TestBroker::start().await;
    let owner = running.register("implementer", "w1:p1").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let owner_client = running.a2a_client(&card, &owner).await;
    let anonymous = running.a2a_client_without_registration(&card).await;
    let response = owner_client
        .send_message(&named_immediate_request(
            recipient.agent.name.as_str(),
            "missing-auth",
        ))
        .await
        .unwrap();
    let SendMessageResponse::Task(task) = response else {
        panic!("return_immediately returned a message")
    };

    let get = anonymous
        .get_task(&GetTaskRequest {
            id: task.id.clone(),
            history_length: None,
            tenant: Some(recipient.agent.name.as_str().to_owned()),
        })
        .await;
    let list = anonymous
        .list_tasks(&list_request_for(&recipient, None, None))
        .await;
    let mut subscribe = anonymous
        .subscribe_to_task(&SubscribeToTaskRequest {
            id: task.id.clone(),
            tenant: Some(recipient.agent.name.as_str().to_owned()),
        })
        .await
        .unwrap();
    let cancel = anonymous
        .cancel_task(&CancelTaskRequest {
            id: task.id.clone(),
            metadata: None,
            tenant: Some(recipient.agent.name.as_str().to_owned()),
        })
        .await;

    assert!(get.is_err());
    assert!(list.is_err());
    assert!(subscribe.try_next().await.is_err());
    assert!(cancel.is_err());
    owner_client
        .cancel_task(&CancelTaskRequest {
            id: task.id,
            metadata: None,
            tenant: Some(recipient.agent.name.as_str().to_owned()),
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn replaced_registration_and_replacement_cannot_read_old_task() {
    let running = TestBroker::start().await;
    let old_owner = running.register("implementer", "w1:p1").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let old_client = running.a2a_client(&card, &old_owner).await;
    let response = old_client
        .send_message(&named_immediate_request(
            recipient.agent.name.as_str(),
            "replaced-owner",
        ))
        .await
        .unwrap();
    let SendMessageResponse::Task(task) = response else {
        panic!("return_immediately returned a message")
    };
    let replacement = running.register("implementer", "w1:p9").await;
    let replacement_client = running.a2a_client(&card, &replacement).await;
    let request = GetTaskRequest {
        id: task.id,
        history_length: None,
        tenant: Some(recipient.agent.name.as_str().to_owned()),
    };

    let old_result = old_client.get_task(&request).await;
    let replacement_result = replacement_client.get_task(&request).await;
    let replacement_list = replacement_client
        .list_tasks(&list_request_for(&recipient, None, None))
        .await
        .unwrap();

    assert!(old_result.is_ok());
    assert!(replacement_result.is_err());
    assert_eq!(replacement_list.total_size, 0);
}

#[tokio::test]
async fn expired_registration_cannot_read_or_list_its_task() {
    let clock = TestClock::at(1_000);
    let running = TestBroker::start_with_clock(clock.clone()).await;
    let owner = running.register("implementer", "w1:p1").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let client = running.a2a_client(&card, &owner).await;
    let response = client
        .send_message(&named_immediate_request(
            recipient.agent.name.as_str(),
            "expired-owner",
        ))
        .await
        .unwrap();
    let SendMessageResponse::Task(task) = response else {
        panic!("return_immediately returned a message")
    };
    clock.advance(30_000);

    let get = client
        .get_task(&GetTaskRequest {
            id: task.id,
            history_length: None,
            tenant: Some(recipient.agent.name.as_str().to_owned()),
        })
        .await;
    let list = client
        .list_tasks(&list_request_for(&recipient, None, None))
        .await;

    assert!(get.is_err());
    assert!(list.is_err());
}

#[tokio::test]
async fn owner_filtered_list_has_correct_pages_and_totals() {
    let running = TestBroker::start().await;
    let owner = running.register("implementer", "w1:p1").await;
    let other = running.register("observer", "w1:p3").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let owner_client = running.a2a_client(&card, &owner).await;
    let other_client = running.a2a_client(&card, &other).await;
    for task_id in ["owner-1", "owner-2", "owner-3"] {
        owner_client
            .send_message(&named_immediate_request(
                recipient.agent.name.as_str(),
                task_id,
            ))
            .await
            .unwrap();
    }
    for task_id in ["other-1", "other-2", "other-3"] {
        other_client
            .send_message(&named_immediate_request(
                recipient.agent.name.as_str(),
                task_id,
            ))
            .await
            .unwrap();
    }
    let mut first_request = list_request_for(&recipient, Some(2), None);
    first_request.status = Some(TaskState::Submitted);

    let first = owner_client.list_tasks(&first_request).await.unwrap();
    let mut second_request =
        list_request_for(&recipient, Some(2), Some(first.next_page_token.clone()));
    second_request.status = Some(TaskState::Submitted);
    let second = owner_client.list_tasks(&second_request).await.unwrap();

    assert_eq!(first.total_size, 3);
    assert_eq!(first.page_size, 2);
    assert_eq!(first.tasks.len(), 2);
    assert!(first.tasks.iter().all(|task| task.id.starts_with("owner-")));
    assert!(!first.next_page_token.is_empty());
    assert_eq!(second.total_size, 3);
    assert_eq!(second.tasks.len(), 1);
    assert!(second.tasks[0].id.starts_with("owner-"));
    assert!(second.next_page_token.is_empty());
}

#[tokio::test]
async fn push_configuration_is_rejected_before_task_or_owner_persistence() {
    let running = TestBroker::start().await;
    let owner = running.register("implementer", "w1:p1").await;
    running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let client = running.a2a_client(&card, &owner).await;
    let mut request = named_immediate_request("reviewer", "push-orphan");
    request
        .configuration
        .as_mut()
        .unwrap()
        .task_push_notification_config = Some(TaskPushNotificationConfig {
        url: "https://example.invalid/push".to_owned(),
        id: None,
        task_id: String::new(),
        token: None,
        authentication: None,
        tenant: None,
    });

    let error = client.send_message(&request).await.unwrap_err();

    assert_eq!(error.code, error_code::PUSH_NOTIFICATION_NOT_SUPPORTED);
    assert_eq!(running.stored_task_count().await, 0);
    assert!(
        running
            .store
            .task_owner("push-orphan")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn streaming_preflight_failures_are_observable_as_official_sse_errors() {
    let running = TestBroker::start().await;
    let stale = running.register("stale", "w1:p4").await;
    running.register("stale", "w1:p4").await;
    let wrong = running.register("observer", "w1:p3").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let unknown = herdr_a2a_core::RegistrationId::new();
    let clients = [
        running.a2a_client_without_registration(&card).await,
        running.a2a_client(&card, &stale).await,
        running
            .a2a_client_with_registration(&card, unknown.as_str())
            .await,
    ];
    for client in &clients {
        let request = request_for(recipient.agent.name.as_str(), "invalid auth");
        let mut stream = client.send_streaming_message(&request).await.unwrap();
        assert!(stream.try_next().await.is_err());
    }

    let valid = running.a2a_client(&card, &wrong).await;
    let invalid_tenant = request_for("missing-recipient", "invalid tenant");
    let mut stream = valid.send_streaming_message(&invalid_tenant).await.unwrap();
    assert!(stream.try_next().await.is_err());
    let mut invalid_payload =
        request_for(recipient.agent.name.as_str(), &"x".repeat(64 * 1024 + 1));
    invalid_payload.message.task_id = Some("stream-invalid-payload".to_owned());
    let mut stream = valid
        .send_streaming_message(&invalid_payload)
        .await
        .unwrap();
    assert!(stream.try_next().await.is_err());
    assert_eq!(running.stored_task_count().await, 0);
}

#[tokio::test]
async fn concurrent_same_id_never_changes_sender_ownership() {
    let running = TestBroker::start().await;
    let owner = running.register("implementer", "w1:p1").await;
    let intruder = running.register("observer", "w1:p3").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let owner_client = Arc::new(running.a2a_client(&card, &owner).await);
    let intruder_client = running.a2a_client(&card, &intruder).await;
    let task_id = "concurrent-stable-owner";
    let recipient_name = recipient.agent.name.as_str().to_owned();
    let first = {
        let client = Arc::clone(&owner_client);
        let recipient_name = recipient_name.clone();
        tokio::spawn(async move {
            client
                .send_message(&named_immediate_request(&recipient_name, task_id))
                .await
        })
    };
    let second = {
        let client = Arc::clone(&owner_client);
        let recipient_name = recipient_name.clone();
        tokio::spawn(async move {
            client
                .send_message(&named_immediate_request(&recipient_name, task_id))
                .await
        })
    };
    let (first, second) = tokio::join!(first, second);
    let outcomes = [first.unwrap(), second.unwrap()];
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 2);
    assert_eq!(running.stored_task_count().await, 1);

    let intruder_send = intruder_client
        .send_message(&named_immediate_request(&recipient_name, task_id))
        .await;
    let intruder_get = intruder_client
        .get_task(&GetTaskRequest {
            id: task_id.to_owned(),
            history_length: None,
            tenant: Some(recipient_name.clone()),
        })
        .await;
    let mut intruder_subscribe = intruder_client
        .subscribe_to_task(&SubscribeToTaskRequest {
            id: task_id.to_owned(),
            tenant: Some(recipient_name.clone()),
        })
        .await
        .unwrap();
    let intruder_cancel = intruder_client
        .cancel_task(&CancelTaskRequest {
            id: task_id.to_owned(),
            metadata: None,
            tenant: Some(recipient_name.clone()),
        })
        .await;
    let intruder_list = intruder_client
        .list_tasks(&list_request_for(&recipient, None, None))
        .await
        .unwrap();
    assert!(intruder_send.is_err());
    assert!(intruder_get.is_err());
    assert!(intruder_subscribe.try_next().await.is_err());
    assert!(intruder_cancel.is_err());
    assert!(intruder_list.tasks.iter().all(|task| task.id != task_id));
    assert_eq!(
        running
            .store
            .task_principal(task_id)
            .await
            .unwrap()
            .unwrap()
            .sender,
        owner.agent.name
    );

    let owner_subscription = owner_client
        .subscribe_to_task(&SubscribeToTaskRequest {
            id: task_id.to_owned(),
            tenant: Some(recipient_name.clone()),
        })
        .await
        .unwrap();
    let inbound = running.wait_message(&recipient).await;
    running
        .reply(&recipient, &inbound.task_id, "finished")
        .await;
    let terminal = owner_subscription
        .try_collect::<Vec<_>>()
        .await
        .unwrap()
        .into_iter()
        .find_map(|event| match event {
            StreamResponse::Task(task) if task.status.state.is_terminal() => Some(task),
            _ => None,
        })
        .unwrap();
    assert_eq!(terminal.status.state, TaskState::Completed);
    let task = owner_client
        .get_task(&GetTaskRequest {
            id: task_id.to_owned(),
            history_length: None,
            tenant: Some(recipient_name.clone()),
        })
        .await
        .unwrap();
    assert_eq!(task.id, task_id);
    assert!(
        intruder_client
            .get_task(&GetTaskRequest {
                id: task_id.to_owned(),
                history_length: None,
                tenant: Some(recipient_name.clone()),
            })
            .await
            .is_err()
    );
    let mut after_subscribe = intruder_client
        .subscribe_to_task(&SubscribeToTaskRequest {
            id: task_id.to_owned(),
            tenant: Some(recipient_name.clone()),
        })
        .await
        .unwrap();
    assert!(after_subscribe.try_next().await.is_err());
    assert!(
        intruder_client
            .send_message(&named_immediate_request(&recipient_name, task_id))
            .await
            .is_err()
    );
    assert!(
        intruder_client
            .list_tasks(&list_request_for(&recipient, None, None))
            .await
            .unwrap()
            .tasks
            .iter()
            .all(|task| task.id != task_id)
    );
    assert!(
        intruder_client
            .cancel_task(&CancelTaskRequest {
                id: task_id.to_owned(),
                metadata: None,
                tenant: Some(recipient_name),
            })
            .await
            .is_err()
    );
}

#[tokio::test]
async fn pre_persistence_quota_rejection_does_not_create_an_a2a_projection() {
    let running = TestBroker::start().await;
    let owner = running.register("implementer", "w1:p1").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let client = running.a2a_client(&card, &owner).await;
    for index in 0..32 {
        client
            .send_message(&named_immediate_request(
                recipient.agent.name.as_str(),
                &format!("quota-{index:02}"),
            ))
            .await
            .unwrap();
    }

    let error = client
        .send_message(&named_immediate_request(
            recipient.agent.name.as_str(),
            "quota-failed",
        ))
        .await
        .unwrap_err();
    assert!(error.message.contains("too many active outbound tasks"));
    let durable_rows = running.stored_task_count().await;
    assert!(
        client
            .get_task(&GetTaskRequest {
                id: "quota-failed".to_owned(),
                history_length: None,
                tenant: Some(recipient.agent.name.as_str().to_owned()),
            })
            .await
            .is_err()
    );
    assert_eq!(running.stored_task_count().await, durable_rows);

    client
        .cancel_task(&CancelTaskRequest {
            id: "quota-00".to_owned(),
            metadata: None,
            tenant: Some(recipient.agent.name.as_str().to_owned()),
        })
        .await
        .unwrap();
    let response = client
        .send_message(&named_immediate_request(
            recipient.agent.name.as_str(),
            "quota-fresh",
        ))
        .await
        .unwrap();
    let SendMessageResponse::Task(fresh) = response else {
        panic!("fresh quota task returned a message")
    };
    assert!(!fresh.status.state.is_terminal());
}

#[tokio::test]
async fn delivery_expiry_is_a_terminal_failed_task_with_history() {
    let clock = TestClock::at(1_000);
    let running = TestBroker::start_with_clock(clock.clone()).await;
    let owner = running.register("implementer", "w1:p1").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let client = running.a2a_client(&card, &owner).await;
    let mut stream = client
        .send_streaming_message(&request_for(recipient.agent.name.as_str(), "expire me"))
        .await
        .unwrap();
    assert!(matches!(
        stream.try_next().await.unwrap().unwrap(),
        StreamResponse::Task(task) if task.status.state == TaskState::Submitted
    ));

    clock.advance(24 * 60 * 60 * 1_000);
    running.broker.list_agents().await;
    let terminal = tokio::time::timeout(std::time::Duration::from_secs(1), stream.try_next())
        .await
        .expect("expiry must wake the A2A reply waiter")
        .unwrap()
        .unwrap();
    let StreamResponse::Task(task) = terminal else {
        panic!("expiry did not produce a terminal task")
    };
    assert_eq!(task.status.state, TaskState::Failed);
    assert_eq!(
        task.history
            .as_ref()
            .and_then(|history| history.first())
            .and_then(Message::text),
        Some("expire me")
    );
}

#[tokio::test]
async fn recipient_replacement_can_finish_task_and_preserves_history() {
    let running = TestBroker::start().await;
    let owner = running.register("implementer", "w1:p1").await;
    let original = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let client = running.a2a_client(&card, &owner).await;
    let mut stream = client
        .send_streaming_message(&request_for(
            original.agent.name.as_str(),
            "recipient teardown",
        ))
        .await
        .unwrap();
    assert!(matches!(
        stream.try_next().await.unwrap().unwrap(),
        StreamResponse::Task(task) if task.status.state == TaskState::Submitted
    ));

    let replacement = running.register("reviewer", "w1:p2").await;
    let inbound = running.wait_message(&replacement).await;
    running
        .reply(&replacement, &inbound.task_id, "finished")
        .await;
    let terminal = stream
        .try_collect::<Vec<_>>()
        .await
        .unwrap()
        .into_iter()
        .find_map(|event| match event {
            StreamResponse::Task(task) if task.status.state.is_terminal() => Some(task),
            _ => None,
        })
        .unwrap();

    assert_eq!(terminal.status.state, TaskState::Completed);
    assert_eq!(
        terminal
            .history
            .as_ref()
            .and_then(|history| history.first())
            .and_then(Message::text),
        Some("recipient teardown")
    );
}

#[tokio::test]
async fn sender_replacement_preserves_active_stream_with_history() {
    let running = TestBroker::start().await;
    let owner = running.register("implementer", "w1:p1").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let client = running.a2a_client(&card, &owner).await;
    let mut stream = client
        .send_streaming_message(&request_for(
            recipient.agent.name.as_str(),
            "sender teardown",
        ))
        .await
        .unwrap();
    assert!(matches!(
        stream.try_next().await.unwrap().unwrap(),
        StreamResponse::Task(task) if task.status.state == TaskState::Submitted
    ));

    let inbound = running.wait_message(&recipient).await;
    running.register("implementer", "w1:p1").await;
    running
        .reply(&recipient, &inbound.task_id, "finished")
        .await;
    let terminal = stream
        .try_collect::<Vec<_>>()
        .await
        .unwrap()
        .into_iter()
        .find_map(|event| match event {
            StreamResponse::Task(task) if task.status.state.is_terminal() => Some(task),
            _ => None,
        })
        .unwrap();

    assert_eq!(terminal.status.state, TaskState::Completed);
    assert_eq!(
        terminal
            .history
            .as_ref()
            .and_then(|history| history.first())
            .and_then(Message::text),
        Some("sender teardown")
    );
}

#[tokio::test]
async fn new_registration_for_same_sender_can_get_subscribe_and_cancel() {
    // Break caught: A2A authorization binds retained work to a superseded registration UUID
    // instead of the verified sender agent name.
    let running = TestBroker::start().await;
    let original = running.register("implementer", "w1:p1").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let original_client = running.a2a_client(&card, &original).await;
    let response = original_client
        .send_message(&named_immediate_request(
            recipient.agent.name.as_str(),
            "stable-sender",
        ))
        .await
        .unwrap();
    let SendMessageResponse::Task(task) = response else {
        panic!("expected task")
    };

    let replacement = running.register("implementer", "w1:p1").await;
    let replacement_client = running.a2a_client(&card, &replacement).await;
    assert_eq!(
        replacement_client
            .get_task(&GetTaskRequest {
                id: task.id.clone(),
                history_length: None,
                tenant: Some(recipient.agent.name.as_str().to_owned()),
            })
            .await
            .unwrap()
            .id,
        task.id,
    );
    assert!(
        replacement_client
            .list_tasks(&list_request_for(&recipient, Some(10), None))
            .await
            .unwrap()
            .tasks
            .iter()
            .any(|listed| listed.id == task.id)
    );
    let subscription = replacement_client
        .subscribe_to_task(&SubscribeToTaskRequest {
            id: task.id.clone(),
            tenant: Some(recipient.agent.name.as_str().to_owned()),
        })
        .await
        .unwrap();
    let canceled = replacement_client
        .cancel_task(&CancelTaskRequest {
            id: task.id.clone(),
            metadata: None,
            tenant: Some(recipient.agent.name.as_str().to_owned()),
        })
        .await
        .unwrap();
    assert_eq!(canceled.status.state, TaskState::Canceled);
    let events = subscription.try_collect::<Vec<_>>().await.unwrap();
    assert!(events.iter().any(|event| matches!(event, StreamResponse::Task(task) if task.status.state == TaskState::Canceled)));
}

#[tokio::test]
async fn new_registration_for_same_recipient_can_reply_to_acknowledged_task() {
    // Break caught: durable recipient authority is incorrectly tied to the lease's obsolete
    // registration UUID after a same-name recipient replacement.
    let running = TestBroker::start().await;
    let sender = running.register("implementer", "w1:p1").await;
    let original_recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let client = running.a2a_client(&card, &sender).await;
    let mut stream = client
        .send_streaming_message(&named_request(
            original_recipient.agent.name.as_str(),
            "stable-recipient",
        ))
        .await
        .unwrap();
    let _ = stream.try_next().await.unwrap().unwrap();
    let delivery = running.wait_message(&original_recipient).await;
    running
        .acknowledge(&original_recipient, &delivery.delivery_id)
        .await;

    let replacement = running.register("reviewer", "w1:p2").await;
    running
        .reply(&replacement, &delivery.task_id, "replacement reply")
        .await;
    let events = stream.try_collect::<Vec<_>>().await.unwrap();
    assert!(
        events
            .iter()
            .any(|event| completed_with_text(event, "replacement reply"))
    );
}

#[tokio::test]
async fn saved_pi_session_reopened_by_new_process_cannot_reply_to_prior_retained_task() {
    // Break caught: reopening one persisted Pi conversation reuses the prior process-incarnation
    // identity, so a later OS process acquires the old canonical principal and reply authority.
    let running = TestBroker::start().await;
    let sender = running.register("implementer", "w1:p1").await;
    let original = running
        .register_with_session("reviewer", "w1:p2", "volatile-process-incarnation-a")
        .await;
    let card = running.resolve_card("reviewer").await;
    let client = running.a2a_client(&card, &sender).await;
    let mut stream = client
        .send_streaming_message(&named_request(
            original.agent.name.as_str(),
            "saved-session-retained-authority",
        ))
        .await
        .unwrap();
    let _ = stream.try_next().await.unwrap().unwrap();
    let delivery = running.wait_message(&original).await;
    running.acknowledge(&original, &delivery.delivery_id).await;

    // Both registrations model the same persisted conversation file. Only the volatile adapter
    // incarnation changes when Pi is reopened in a new OS process.
    let replacement = running
        .register_with_session("reviewer", "w1:p2", "volatile-process-incarnation-b")
        .await;
    assert_ne!(original.agent.name, replacement.agent.name);
    let response = reqwest::Client::new()
        .post(format!(
            "{}/v1/tasks/{}/reply",
            running.base_url, delivery.task_id
        ))
        .bearer_auth(TOKEN)
        .header(REGISTRATION_HEADER, replacement.id.as_str())
        .header(
            REGISTRATION_EPOCH_HEADER,
            replacement.epoch.get().to_string(),
        )
        .json(&json!({"text":"stolen reply","metadata":{},"file_refs":[]}))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn different_agent_name_cannot_claim_restarted_task() {
    // Break caught: replacing registration-ID authorization with a mere "currently registered"
    // check allows another verified agent name to control retained work.
    let running = TestBroker::start().await;
    let sender = running.register("implementer", "w1:p1").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let intruder = running.register("intruder", "w1:p3").await;
    let card = running.resolve_card("reviewer").await;
    let owner = running.a2a_client(&card, &sender).await;
    owner
        .send_message(&named_immediate_request(
            recipient.agent.name.as_str(),
            "stable-intruder",
        ))
        .await
        .unwrap();
    let intruder_client = running.a2a_client(&card, &intruder).await;

    assert!(
        intruder_client
            .get_task(&GetTaskRequest {
                id: "stable-intruder".to_owned(),
                history_length: None,
                tenant: Some(recipient.agent.name.as_str().to_owned()),
            })
            .await
            .is_err()
    );
    assert!(
        intruder_client
            .cancel_task(&CancelTaskRequest {
                id: "stable-intruder".to_owned(),
                metadata: None,
                tenant: Some(recipient.agent.name.as_str().to_owned()),
            })
            .await
            .is_err()
    );
}

#[tokio::test]
async fn dropped_stream_can_resubscribe_without_losing_reply_wait() {
    let running = TestBroker::start().await;
    let sender = running.register("implementer", "w1:p1").await;
    let recipient = running.register("reviewer", "w1:p2").await;
    let card = running.resolve_card("reviewer").await;
    let client = running.a2a_client(&card, &sender).await;
    let mut stream = client
        .send_streaming_message(&request_for(recipient.agent.name.as_str(), "review this"))
        .await
        .unwrap();
    let working = stream.try_next().await.unwrap().unwrap();
    let task_id = task_id(&working).unwrap().to_owned();
    drop(stream);
    let resumed = client
        .subscribe_to_task(&SubscribeToTaskRequest {
            id: task_id,
            tenant: Some(recipient.agent.name.as_str().to_owned()),
        })
        .await
        .unwrap();

    let inbound = running.wait_message(&recipient).await;
    running.reply(&recipient, &inbound.task_id, "resumed").await;
    let events: Vec<_> = resumed.try_collect().await.unwrap();

    assert!(
        events
            .iter()
            .any(|event| completed_with_text(event, "resumed"))
    );
}
