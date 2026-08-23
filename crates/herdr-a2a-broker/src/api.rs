use std::{collections::HashSet, path::PathBuf, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    body::to_bytes,
    extract::{FromRequest, Path, Request, State, rejection::PathRejection},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use herdr_a2a_core::{
    AgentName, BrokerState, DeliveryId, DomainError, MessagePayload, Registration,
    RegistrationCredentials, RegistrationEpoch, RegistrationId, ReplyPayload, RoleLabel,
    VerifiedAgent,
    broker::{BrokerOperationsAgent, BrokerStatusEvent, BrokerTaskCounts},
    validate_payload, validate_task_id,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{HerdrVerifier, IdentityError, IdentityStore};

pub const MAX_JSON_BODY_BYTES: usize = 512 * 1024;
pub const MIN_WAIT_TIMEOUT_MS: u64 = 1_000;
pub const MAX_WAIT_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1_000;
const MAX_IDENTITY_FIELD_BYTES: usize = 1_024;
const REGISTRATION_HEADER: &str = "x-herdr-a2a-registration";
const REGISTRATION_EPOCH_HEADER: &str = "x-herdr-a2a-registration-epoch";
const HEALTH_PROOF_HEADER: &str = "x-herdr-a2a-health-proof";
const HEALTH_INSTANCE_HEADER: &str = "x-herdr-a2a-instance";
const HEALTH_PROOF_DOMAIN: &[u8] = b"herdr-a2a-proof-v2\0";
const STATUS_PROOF_HEADER: &str = "x-herdr-a2a-status-proof";
const STATUS_PROOF_DOMAIN: &[u8] = b"herdr-a2a-status-v1\0";
const UNSUPPORTED_FILE_REFERENCES_MESSAGE: &str =
    "Herdr file references are not supported in this milestone";

#[derive(Clone)]
pub struct ApiState {
    broker: BrokerState,
    verifier: Arc<dyn HerdrVerifier>,
    identities: IdentityStore,
    workspace_id: String,
    bearer_token_digest: [u8; 32],
    broker_instance_id: String,
}

impl ApiState {
    pub fn new(
        broker: BrokerState,
        verifier: Arc<dyn HerdrVerifier>,
        identities: IdentityStore,
        workspace_id: impl Into<String>,
        bearer_token: impl AsRef<[u8]>,
        broker_instance_id: [u8; 32],
    ) -> Result<Self, IdentityError> {
        let workspace_id = workspace_id.into();
        let identities = identities.for_workspace(&workspace_id)?;
        Ok(Self {
            broker,
            verifier,
            identities,
            workspace_id,
            bearer_token_digest: Sha256::digest(bearer_token.as_ref()).into(),
            broker_instance_id: URL_SAFE_NO_PAD.encode(broker_instance_id),
        })
    }

    pub fn broker(&self) -> &BrokerState {
        &self.broker
    }

    pub fn broker_instance_id(&self) -> &str {
        &self.broker_instance_id
    }
}

pub fn private_router(state: ApiState) -> Router {
    let authenticated = Router::new()
        .route("/health", get(health))
        .route("/v1/register", post(register))
        .route("/v1/renew", post(renew))
        .route("/v1/unregister", post(unregister))
        .route("/v1/agents", get(list_agents).post(list_agents))
        .route("/v1/agents/wait", post(wait_agents))
        .route("/v1/agents/resolve/{target}", get(resolve_agent))
        .route("/v1/inbox/wait", post(wait_inbox))
        .route("/v1/inbox/ack", post(ack_inbox))
        .route("/v1/tasks/{task_id}/reply", post(reply_task))
        .route("/v1/tasks/{task_id}/cancel", post(cancel_task))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_bearer,
        ));
    Router::new()
        .route("/health/proof/{nonce}", get(health_proof))
        .route("/health/status/{nonce}", get(status_challenge))
        .merge(authenticated)
        .with_state(state)
}

pub(crate) async fn require_bearer(
    State(state): State<ApiState>,
    request: Request,
    next: Next,
) -> Response {
    let authenticated = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|token| !token.is_empty())
        .is_some_and(|token| {
            let presented: [u8; 32] = Sha256::digest(token.as_bytes()).into();
            bool::from(
                presented
                    .as_slice()
                    .ct_eq(state.bearer_token_digest.as_slice()),
            )
        });

    if authenticated {
        next.run(request).await
    } else {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "a valid bearer token is required",
        )
        .into_response()
    }
}

struct BoundedJson<T>(T);

impl<S, T> FromRequest<S> for BoundedJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let bytes = to_bytes(request.into_body(), MAX_JSON_BODY_BYTES)
            .await
            .map_err(|_| {
                ApiError::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "body_too_large",
                    "request body exceeds the size limit",
                )
            })?;
        serde_json::from_slice(&bytes).map(Self).map_err(|_| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_json",
                "request body is not valid for this endpoint",
            )
        })
    }
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    candidates: Vec<AgentName>,
}

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    error: ErrorBody<'a>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'a str,
    message: &'a str,
    #[serde(skip_serializing_if = "<[AgentName]>::is_empty")]
    candidates: &'a [AgentName],
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            candidates: Vec::new(),
        }
    }

    fn with_candidates(mut self, candidates: Vec<AgentName>) -> Self {
        self.candidates = candidates;
        self
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(ErrorEnvelope {
            error: ErrorBody {
                code: self.code,
                message: &self.message,
                candidates: &self.candidates,
            },
        });
        (self.status, body).into_response()
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn health_proof(
    State(state): State<ApiState>,
    Path(nonce): Path<String>,
) -> Result<HeaderMap, ApiError> {
    let nonce_bytes = URL_SAFE_NO_PAD.decode(&nonce).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_health_nonce",
            "health nonce must be canonical base64url",
        )
    })?;
    if nonce_bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&nonce_bytes) != nonce {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_health_nonce",
            "health nonce must encode exactly 32 bytes",
        ));
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(&state.bearer_token_digest)
        .expect("SHA-256 digest is a valid HMAC key");
    mac.update(HEALTH_PROOF_DOMAIN);
    mac.update(state.broker_instance_id.as_bytes());
    mac.update(&nonce_bytes);
    let proof = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    let mut headers = HeaderMap::new();
    headers.insert(
        HEALTH_PROOF_HEADER,
        proof
            .parse()
            .expect("base64url proof is a valid HTTP header value"),
    );
    headers.insert(
        HEALTH_INSTANCE_HEADER,
        state
            .broker_instance_id
            .parse()
            .expect("base64url instance ID is a valid HTTP header value"),
    );
    Ok(headers)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterRequest {
    pane_id: String,
    harness_session_id: String,
    expected_agent_name: Option<herdr_a2a_core::AgentName>,
}

#[derive(Serialize)]
struct RegistrationResponse {
    registration_id: RegistrationId,
    registration_epoch: RegistrationEpoch,
    canonical_name: herdr_a2a_core::AgentName,
    role: RoleLabel,
    pane_id: String,
    harness: String,
    workspace: PathBuf,
    harness_session_id: String,
    expires_unix_ms: i64,
}

impl RegistrationResponse {
    fn from_registration(registration: Registration, role: RoleLabel) -> Self {
        Self {
            registration_id: registration.id,
            registration_epoch: registration.epoch,
            canonical_name: registration.agent.name,
            role,
            pane_id: registration.agent.pane_id,
            harness: registration.agent.harness,
            workspace: registration.agent.workspace,
            harness_session_id: registration.harness_session_id,
            expires_unix_ms: registration.expires_unix_ms,
        }
    }
}

async fn register(
    State(state): State<ApiState>,
    BoundedJson(request): BoundedJson<RegisterRequest>,
) -> Result<Json<RegistrationResponse>, ApiError> {
    if request.pane_id.is_empty()
        || request.pane_id.len() > MAX_IDENTITY_FIELD_BYTES
        || request.harness_session_id.is_empty()
        || request.harness_session_id.len() > MAX_IDENTITY_FIELD_BYTES
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_registration_request",
            "pane and harness session identifiers must be non-empty and bounded",
        ));
    }
    let verified = state.verifier.verify(&request.pane_id).await.map_err(|_| {
        ApiError::new(
            StatusCode::FORBIDDEN,
            "verification_failed",
            "Herdr could not verify this pane",
        )
    })?;
    if verified.workspace_id != state.workspace_id {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "workspace_mismatch",
            "verified pane belongs to another workspace",
        ));
    }
    let identity = state
        .identities
        .resolve_or_create(&verified, &request.harness_session_id)
        .await
        .map_err(ApiError::from)?;
    if request
        .expected_agent_name
        .as_ref()
        .is_some_and(|expected| expected != &identity.canonical_name)
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "agent_identity_changed",
            "Herdr verified a different canonical identity for this pane",
        ));
    }
    let agent = VerifiedAgent {
        name: identity.canonical_name,
        pane_id: verified.pane_id,
        harness: verified.harness,
        workspace: verified.workspace_path,
    };
    let registration = state
        .broker
        .register(agent, &request.harness_session_id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(RegistrationResponse::from_registration(
        registration,
        identity.current_role,
    )))
}

async fn renew(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<RegistrationResponse>, ApiError> {
    let credentials = registration_credentials(&headers)?;
    let current = state
        .broker
        .authenticate(&credentials)
        .await
        .map_err(ApiError::from)?;
    let verified = state
        .verifier
        .verify(&current.agent.pane_id)
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::FORBIDDEN,
                "verification_failed",
                "Herdr could not re-verify this pane",
            )
        })?;
    if verified.workspace_id != state.workspace_id
        || verified.pane_id != current.agent.pane_id
        || verified.harness != current.agent.harness
        || verified.workspace_path != current.agent.workspace
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "agent_identity_changed",
            "verified pane identity changed during refresh",
        ));
    }
    let identity = state
        .identities
        .resolve_or_create(&verified, &current.harness_session_id)
        .await
        .map_err(ApiError::from)?;
    if identity.canonical_name != current.agent.name {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "agent_identity_changed",
            "canonical identity changed during refresh",
        ));
    }
    let registration = state
        .broker
        .renew(&credentials)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(RegistrationResponse::from_registration(
        registration,
        identity.current_role,
    )))
}

async fn unregister(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<OkResponse>, ApiError> {
    let credentials = registration_credentials(&headers)?;
    match state.broker.remove_registration(&credentials).await {
        Ok(()) | Err(DomainError::RegistrationNotFound) => {}
        Err(error) => return Err(ApiError::from(error)),
    }
    Ok(Json(OkResponse { ok: true }))
}

#[derive(Serialize)]
struct AgentListResponse {
    agents: Vec<AgentResponse>,
}

#[derive(Serialize)]
struct AgentResponse {
    canonical_name: herdr_a2a_core::AgentName,
    role: RoleLabel,
    pane_id: String,
    harness: String,
    status: &'static str,
}

async fn list_agents(State(state): State<ApiState>) -> Result<Json<AgentListResponse>, ApiError> {
    Ok(Json(AgentListResponse {
        agents: live_directory(&state).await?,
    }))
}

#[derive(Serialize)]
struct WorkspaceStatusResponse {
    workspace_id: String,
    broker: &'static str,
    storage: &'static str,
    registrations: usize,
    agents: Vec<StatusAgentResponse>,
    tasks: BrokerTaskCounts,
    last_event: Option<BrokerStatusEvent>,
}

#[derive(Serialize)]
struct StatusAgentResponse {
    role: RoleLabel,
    canonical_name: AgentName,
    status: &'static str,
}

async fn workspace_status_response(state: &ApiState) -> Result<WorkspaceStatusResponse, ApiError> {
    let snapshot = state
        .broker
        .operations_snapshot()
        .await
        .map_err(ApiError::from)?;
    let registrations = snapshot.registrations;
    let agents = status_directory_from_roster(state, snapshot.agents).await?;
    Ok(WorkspaceStatusResponse {
        workspace_id: state.workspace_id.clone(),
        broker: "healthy",
        storage: "reconciled",
        registrations,
        agents,
        tasks: snapshot.tasks,
        last_event: snapshot.last_event,
    })
}

async fn status_directory_from_roster(
    state: &ApiState,
    roster: Vec<BrokerOperationsAgent>,
) -> Result<Vec<StatusAgentResponse>, ApiError> {
    let mut agents = Vec::with_capacity(roster.len());
    for agent in roster {
        let identity = state
            .identities
            .find_by_canonical(&agent.canonical_name)
            .await
            .map_err(ApiError::from)?
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "identity_unavailable",
                    "live status agent has no durable identity",
                )
            })?;
        if identity.workspace_id != state.workspace_id
            || identity.canonical_name != agent.canonical_name
        {
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "identity_mismatch",
                "live status agent does not match durable identity",
            ));
        }
        agents.push(StatusAgentResponse {
            role: identity.current_role,
            canonical_name: agent.canonical_name,
            status: "connected",
        });
    }
    Ok(agents)
}

async fn status_challenge(
    State(state): State<ApiState>,
    Path(nonce): Path<String>,
) -> Result<Response, ApiError> {
    let nonce_bytes = URL_SAFE_NO_PAD.decode(&nonce).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_status_nonce",
            "status nonce must be canonical base64url",
        )
    })?;
    if nonce_bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&nonce_bytes) != nonce {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_status_nonce",
            "status nonce must encode exactly 32 bytes",
        ));
    }
    let (status, body) = match workspace_status_response(&state).await {
        Ok(status) => (
            StatusCode::OK,
            serde_json::to_vec(&status).expect("status response must serialize"),
        ),
        Err(error) => {
            let body = serde_json::to_vec(&ErrorEnvelope {
                error: ErrorBody {
                    code: error.code,
                    message: &error.message,
                    candidates: &error.candidates,
                },
            })
            .expect("status error response must serialize");
            (error.status, body)
        }
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(&state.bearer_token_digest)
        .expect("SHA-256 digest is a valid HMAC key");
    mac.update(STATUS_PROOF_DOMAIN);
    mac.update(state.broker_instance_id.as_bytes());
    mac.update(&nonce_bytes);
    mac.update(&body);
    let proof = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    let mut response = (status, [(header::CONTENT_TYPE, "application/json")], body).into_response();
    response.headers_mut().insert(
        STATUS_PROOF_HEADER,
        proof
            .parse()
            .expect("base64url proof is a valid HTTP header value"),
    );
    response.headers_mut().insert(
        HEALTH_INSTANCE_HEADER,
        state
            .broker_instance_id
            .parse()
            .expect("base64url instance ID is a valid HTTP header value"),
    );
    Ok(response)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WaitAgentsRequest {
    pane_ids: Vec<String>,
    timeout_ms: u64,
}

#[derive(Serialize)]
struct WaitAgentsResponse {
    generation: u64,
    agents: Vec<AgentResponse>,
}

async fn wait_agents(
    State(state): State<ApiState>,
    BoundedJson(request): BoundedJson<WaitAgentsRequest>,
) -> Result<Json<WaitAgentsResponse>, ApiError> {
    let unique = request.pane_ids.iter().collect::<HashSet<_>>();
    if request.pane_ids.is_empty()
        || request.pane_ids.len() > 8
        || unique.len() != request.pane_ids.len()
        || request.pane_ids.iter().any(|pane_id| {
            pane_id.is_empty()
                || pane_id.len() > MAX_IDENTITY_FIELD_BYTES
                || pane_id.chars().any(char::is_control)
        })
        || !(MIN_WAIT_TIMEOUT_MS..=MAX_WAIT_TIMEOUT_MS).contains(&request.timeout_ms)
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_agent_wait",
            "agent wait requires 1-8 unique bounded pane IDs and a bounded timeout",
        ));
    }

    let waited = state
        .broker
        .wait_for_agents(&request.pane_ids, Duration::from_millis(request.timeout_ms))
        .await;
    let mut agents = Vec::with_capacity(waited.registrations.len());
    for registration in waited.registrations {
        agents.push(directory_agent(&state, registration).await?);
    }
    Ok(Json(WaitAgentsResponse {
        generation: waited.generation,
        agents,
    }))
}

#[derive(Serialize)]
struct ResolveAgentResponse {
    canonical_name: AgentName,
}

async fn resolve_agent(
    State(state): State<ApiState>,
    Path(target): Path<String>,
) -> Result<Json<ResolveAgentResponse>, ApiError> {
    if target.is_empty()
        || target.len() > MAX_IDENTITY_FIELD_BYTES
        || target.chars().any(char::is_control)
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_agent_target",
            "agent target must be non-empty, bounded, and control-free",
        ));
    }
    let directory = live_directory(&state).await?;
    if let Ok(canonical) = AgentName::parse(&target)
        && directory
            .iter()
            .any(|agent| agent.canonical_name == canonical)
    {
        return Ok(Json(ResolveAgentResponse {
            canonical_name: canonical,
        }));
    }
    let mut candidates = directory
        .into_iter()
        .filter(|agent| agent.role.as_str() == target)
        .map(|agent| agent.canonical_name)
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    match candidates.len() {
        0 => Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "agent_not_found",
            "no live agent matches this target",
        )),
        1 => Ok(Json(ResolveAgentResponse {
            canonical_name: candidates.pop().expect("one candidate must exist"),
        })),
        _ => Err(ApiError::new(
            StatusCode::CONFLICT,
            "ambiguous_agent",
            "multiple live agents have this role",
        )
        .with_candidates(candidates)),
    }
}

async fn live_directory(state: &ApiState) -> Result<Vec<AgentResponse>, ApiError> {
    let registrations = state.broker.list_agents().await;
    live_directory_from_registrations(state, registrations).await
}

async fn live_directory_from_registrations(
    state: &ApiState,
    registrations: Vec<Registration>,
) -> Result<Vec<AgentResponse>, ApiError> {
    let mut agents = Vec::with_capacity(registrations.len());
    for registration in registrations {
        agents.push(directory_agent(state, registration).await?);
    }
    agents.sort_by(|left, right| {
        left.canonical_name
            .as_str()
            .cmp(right.canonical_name.as_str())
    });
    Ok(agents)
}

async fn directory_agent(
    state: &ApiState,
    registration: Registration,
) -> Result<AgentResponse, ApiError> {
    let identity = state
        .identities
        .find_by_canonical(&registration.agent.name)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "identity_unavailable",
                "live registration has no durable identity",
            )
        })?;
    if identity.workspace_id != state.workspace_id
        || identity.pane_id != registration.agent.pane_id
        || identity.harness != registration.agent.harness
    {
        return Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "identity_mismatch",
            "live registration does not match durable identity",
        ));
    }
    Ok(AgentResponse {
        canonical_name: identity.canonical_name,
        role: identity.current_role,
        pane_id: identity.pane_id,
        harness: identity.harness,
        status: "live",
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WaitRequest {
    timeout_ms: Option<u64>,
}

async fn wait_inbox(
    State(state): State<ApiState>,
    headers: HeaderMap,
    BoundedJson(request): BoundedJson<WaitRequest>,
) -> Result<Json<herdr_a2a_core::DeliveredMessage>, ApiError> {
    if request.timeout_ms.is_some_and(|timeout_ms| {
        !(MIN_WAIT_TIMEOUT_MS..=MAX_WAIT_TIMEOUT_MS).contains(&timeout_ms)
    }) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_timeout",
            format!(
                "timeout_ms must be omitted or between {MIN_WAIT_TIMEOUT_MS} and {MAX_WAIT_TIMEOUT_MS}"
            ),
        ));
    }
    let credentials = registration_credentials(&headers)?;
    state
        .broker
        .wait_next(&credentials, request.timeout_ms.map(Duration::from_millis))
        .await
        .map(Json)
        .map_err(ApiError::from)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AckRequest {
    delivery_id: DeliveryId,
}

#[derive(Serialize)]
struct OkResponse {
    ok: bool,
}

async fn ack_inbox(
    State(state): State<ApiState>,
    headers: HeaderMap,
    BoundedJson(request): BoundedJson<AckRequest>,
) -> Result<Json<OkResponse>, ApiError> {
    let credentials = registration_credentials(&headers)?;
    state
        .broker
        .ack_delivery(&credentials, &request.delivery_id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(OkResponse { ok: true }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplyRequest {
    text: String,
    metadata: serde_json::Value,
    file_refs: Vec<herdr_a2a_core::FileReference>,
}

async fn reply_task(
    State(state): State<ApiState>,
    path: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
    BoundedJson(request): BoundedJson<ReplyRequest>,
) -> Result<Json<OkResponse>, ApiError> {
    let task_id = task_id(path)?;
    let credentials = registration_credentials(&headers)?;
    let registration = state.broker.authenticate(&credentials).await?;
    if !request.file_refs.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "unsupported_file_references",
            UNSUPPORTED_FILE_REFERENCES_MESSAGE,
        ));
    }
    let validated = validate_payload(
        &MessagePayload {
            text: request.text,
            metadata: request.metadata,
            file_refs: request.file_refs,
        },
        &registration.agent.workspace,
    )
    .map_err(ApiError::from)?;
    state
        .broker
        .reply(
            &credentials,
            &task_id,
            ReplyPayload {
                text: validated.text,
                metadata: validated.metadata,
                file_refs: validated.file_refs,
            },
        )
        .await
        .map_err(ApiError::from)?;
    Ok(Json(OkResponse { ok: true }))
}

async fn cancel_task(
    State(state): State<ApiState>,
    path: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
) -> Result<Json<OkResponse>, ApiError> {
    let task_id = task_id(path)?;
    let credentials = registration_credentials(&headers)?;
    state
        .broker
        .cancel_task(&credentials, &task_id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(OkResponse { ok: true }))
}

fn task_id(path: Result<Path<String>, PathRejection>) -> Result<String, ApiError> {
    let Path(task_id) = path.map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_path",
            "task path is invalid",
        )
    })?;
    validate_task_id(&task_id).map_err(ApiError::from)?;
    Ok(task_id)
}

fn registration_credentials(headers: &HeaderMap) -> Result<RegistrationCredentials, ApiError> {
    let raw = headers
        .get(REGISTRATION_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNAUTHORIZED,
                "missing_registration",
                "an authenticated registration is required",
            )
        })?;
    let id = RegistrationId::parse(raw).map_err(|_| {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_registration",
            "the registration identifier is invalid",
        )
    })?;
    let epoch = headers
        .get(REGISTRATION_EPOCH_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNAUTHORIZED,
                "missing_registration_epoch",
                "an authenticated registration epoch is required",
            )
        })
        .and_then(|raw| {
            RegistrationEpoch::parse(raw).ok_or_else(|| {
                ApiError::new(
                    StatusCode::UNAUTHORIZED,
                    "invalid_registration",
                    "the registration epoch is invalid",
                )
            })
        })?;
    Ok(RegistrationCredentials { id, epoch })
}

async fn not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "not_found", "endpoint not found")
}

async fn method_not_allowed() -> ApiError {
    ApiError::new(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "method not allowed for this endpoint",
    )
}

impl From<DomainError> for ApiError {
    fn from(error: DomainError) -> Self {
        let (status, code) = match error {
            DomainError::InvalidAgentName
            | DomainError::InvalidRoleLabel
            | DomainError::InvalidRegistrationId
            | DomainError::InvalidDeliveryId
            | DomainError::InvalidTaskId
            | DomainError::TooManyRetainedTasks => (StatusCode::BAD_REQUEST, "invalid_request"),
            DomainError::RegistrationNotFound | DomainError::RegistrationExpired => {
                (StatusCode::UNAUTHORIZED, "invalid_registration")
            }
            DomainError::AgentNotRegistered
            | DomainError::DeliveryNotFound
            | DomainError::TaskNotFound => (StatusCode::NOT_FOUND, "not_found"),
            DomainError::SenderMismatch
            | DomainError::DeliveryNotOwned
            | DomainError::TaskNotOwned => (StatusCode::FORBIDDEN, "forbidden"),
            DomainError::WaitAlreadyActive => (StatusCode::CONFLICT, "wait_already_active"),
            DomainError::WaitTimedOut => (StatusCode::REQUEST_TIMEOUT, "wait_timed_out"),
            DomainError::TextTooLarge
            | DomainError::MetadataTooLarge
            | DomainError::TooManyFileReferences
            | DomainError::PathTooLong
            | DomainError::FileLabelTooLong => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
            DomainError::MetadataTooDeep
            | DomainError::TooManyMetadataEntries
            | DomainError::FileNotFound(_)
            | DomainError::WorkspaceNotFound(_)
            | DomainError::FileOutsideWorkspace { .. } => {
                (StatusCode::BAD_REQUEST, "invalid_payload")
            }
            DomainError::DuplicateTask
            | DomainError::ReplyWaitAlreadyActive
            | DomainError::ReplyAlreadySubmitted
            | DomainError::TaskCanceled
            | DomainError::TaskExpired
            | DomainError::TaskFailed
            | DomainError::TaskRejected
            | DomainError::TaskAlreadyCompleted
            | DomainError::TooManyActiveTasks => (StatusCode::CONFLICT, "conflict"),
            DomainError::PersistenceUnavailable => {
                (StatusCode::SERVICE_UNAVAILABLE, "persistence_unavailable")
            }
        };
        let message = error.to_string();
        Self::new(status, code, message)
    }
}

impl From<IdentityError> for ApiError {
    fn from(error: IdentityError) -> Self {
        match error {
            IdentityError::WorkspaceMismatch => ApiError::new(
                StatusCode::FORBIDDEN,
                "workspace_mismatch",
                error.to_string(),
            ),
            IdentityError::AllocationExhausted => ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "identity_allocation_unavailable",
                error.to_string(),
            ),
            IdentityError::Sqlite(_)
            | IdentityError::InvalidData(_)
            | IdentityError::WorkerFailed => ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "identity_unavailable",
                error.to_string(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    use async_trait::async_trait;
    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Method, Request, StatusCode, header},
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use herdr_a2a_core::{
        AgentName, BrokerState, DeliveryId, DomainError, QueuedDelivery, Registration,
        ReplyPayload, RoleLabel, ValidatedPayload, VerifiedAgent, VerifiedPane,
    };
    use hmac::{Hmac, Mac};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;

    use crate::{HerdrVerifier, IdentityStore, herdr::HerdrVerificationError};

    use super::{ApiError, ApiState, MAX_JSON_BODY_BYTES, MAX_WAIT_TIMEOUT_MS, private_router};

    const TOKEN: &str = "test-private-bearer-token";
    const REGISTRATION_HEADER: &str = "x-herdr-a2a-registration";
    const REGISTRATION_EPOCH_HEADER: &str = "x-herdr-a2a-registration-epoch";

    #[derive(Clone)]
    struct FixedVerifier {
        verified: VerifiedPane,
    }

    #[async_trait]
    impl HerdrVerifier for FixedVerifier {
        async fn verify(&self, _pane_id: &str) -> Result<VerifiedPane, HerdrVerificationError> {
            Ok(self.verified.clone())
        }
    }

    fn pane(role: &str, pane_id: &str) -> VerifiedPane {
        VerifiedPane {
            pane_id: pane_id.to_owned(),
            workspace_id: "w1".to_owned(),
            role: RoleLabel::parse(role).unwrap(),
            harness: "pi".to_owned(),
            workspace_path: PathBuf::from("/repo"),
        }
    }

    fn agent(name: &str, pane_id: &str) -> VerifiedAgent {
        VerifiedAgent {
            name: AgentName::parse(name).unwrap(),
            pane_id: pane_id.to_owned(),
            harness: "pi".to_owned(),
            workspace: PathBuf::from("/repo"),
        }
    }

    fn test_router() -> (Router, BrokerState) {
        test_router_with_verified(pane("reviewer", "w1:p2"))
    }

    fn test_router_with_verified(verified: VerifiedPane) -> (Router, BrokerState) {
        let broker = BrokerState::new();
        let state = ApiState::new(
            broker.clone(),
            Arc::new(FixedVerifier { verified }),
            IdentityStore::open(":memory:").unwrap(),
            "w1",
            TOKEN,
            [0x22; 32],
        )
        .unwrap();
        (private_router(state), broker)
    }

    fn request(
        method: Method,
        path: &str,
        body: Body,
        registration: Option<&Registration>,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"));
        if let Some(registration) = registration {
            builder = builder
                .header(REGISTRATION_HEADER, registration.id.as_str())
                .header(
                    REGISTRATION_EPOCH_HEADER,
                    registration.epoch.get().to_string(),
                );
        }
        builder.body(body).unwrap()
    }

    fn json_request(
        method: Method,
        path: &str,
        value: Value,
        registration: Option<&Registration>,
    ) -> Request<Body> {
        request(method, path, Body::from(value.to_string()), registration)
    }

    fn credential_request(
        method: Method,
        path: &str,
        body: Value,
        registration: &Registration,
        epoch: Option<&str>,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
            .header(REGISTRATION_HEADER, registration.id.as_str());
        if let Some(epoch) = epoch {
            builder = builder.header(REGISTRATION_EPOCH_HEADER, epoch);
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    async fn json_body(response: axum::response::Response) -> Value {
        let bytes = to_bytes(response.into_body(), MAX_JSON_BODY_BYTES + 1)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn register(app: Router, pane_id: &str, session_id: &str) -> Value {
        let response = app
            .oneshot(json_request(
                Method::POST,
                "/v1/register",
                json!({"pane_id": pane_id, "harness_session_id": session_id}),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        json_body(response).await
    }

    async fn register_direct(broker: &BrokerState, name: &str, pane_id: &str) -> Registration {
        broker
            .register(agent(name, pane_id), "pi-test")
            .await
            .unwrap()
    }

    async fn enqueue(
        broker: &BrokerState,
        sender: &Registration,
        recipient: &Registration,
        task_id: &str,
    ) {
        let created_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        broker
            .enqueue(
                &sender.credentials(),
                QueuedDelivery {
                    task_id: task_id.to_owned(),
                    context_id: format!("context-{task_id}"),
                    sender: sender.agent.name.clone(),
                    recipient: recipient.agent.name.clone(),
                    payload: ValidatedPayload {
                        text: "review this".to_owned(),
                        metadata: json!({}),
                        file_refs: vec![],
                    },
                    created_unix_ms,
                    attempt: 0,
                },
            )
            .await
            .unwrap();
    }

    #[test]
    fn persistence_unavailable_maps_to_service_unavailable() {
        let error = ApiError::from(DomainError::PersistenceUnavailable);
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error.code, "persistence_unavailable");
        assert_eq!(error.message, "broker persistence unavailable");
    }

    #[tokio::test]
    async fn every_private_endpoint_rejects_missing_bearer_token_with_json() {
        let (app, _) = test_router();
        let endpoints = [
            (Method::GET, "/health"),
            (Method::POST, "/v1/register"),
            (Method::POST, "/v1/renew"),
            (Method::POST, "/v1/unregister"),
            (Method::POST, "/v1/agents"),
            (Method::POST, "/v1/inbox/wait"),
            (Method::POST, "/v1/inbox/ack"),
            (Method::POST, "/v1/tasks/task-1/reply"),
            (Method::POST, "/v1/tasks/task-1/cancel"),
        ];

        for (method, path) in endpoints {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
            assert_eq!(json_body(response).await["error"]["code"], "unauthorized");
        }
    }

    #[tokio::test]
    async fn health_proof_is_unauthenticated_and_matches_the_protocol_vector() {
        // Break caught: the broker either protects the proof route with the bearer it is meant
        // to authenticate, or signs a different nonce/domain/key than descriptor clients verify.
        let (app, _) = test_router();
        let nonce = "ERERERERERERERERERERERERERERERERERERERERERE";

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/health/proof/{nonce}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("x-herdr-a2a-health-proof").unwrap(),
            "iCUUJsJp_Vu75rupynVWPU4WuJj6dFQcV7DGxOnvZrc"
        );
        assert_eq!(
            response.headers().get("x-herdr-a2a-instance").unwrap(),
            "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"
        );

        let health = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::UNAUTHORIZED);

        let authenticated_health = app
            .oneshot(request(Method::GET, "/health", Body::empty(), None))
            .await
            .unwrap();
        assert_eq!(authenticated_health.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn status_reports_only_redacted_workspace_operations() {
        // Break caught: the bearer-free challenge response is unsigned, is not bound to its exact
        // redacted body, or returns credentials, paths, task identities, or payloads.
        let (app, _) = test_router();
        register(app.clone(), "w1:p2", "pi-session-a").await;
        let nonce = "ERERERERERERERERERERERERERERERERERERERERERE";

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/health/status/{nonce}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("x-herdr-a2a-instance").unwrap(),
            "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"
        );
        let proof = response
            .headers()
            .get("x-herdr-a2a-status-proof")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let body = to_bytes(response.into_body(), MAX_JSON_BODY_BYTES + 1)
            .await
            .unwrap();
        let key = Sha256::digest(TOKEN.as_bytes());
        let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        mac.update(b"herdr-a2a-status-v1\0");
        mac.update(b"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI");
        mac.update(&URL_SAFE_NO_PAD.decode(nonce).unwrap());
        mac.update(&body);
        assert_eq!(proof, URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()));
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["workspace_id"], "w1");
        assert_eq!(value["broker"], "healthy");
        assert_eq!(value["storage"], "reconciled");
        assert_eq!(value["registrations"], 1);
        assert_eq!(value["agents"][0]["role"], "reviewer");
        assert_eq!(value["tasks"]["terminal"], 0);
        let encoded = value.to_string();
        for forbidden in [TOKEN, "task-", "payload", "descriptor", "/repo"] {
            assert!(
                !encoded.contains(forbidden),
                "leaked {forbidden:?}: {encoded}"
            );
        }
    }

    #[tokio::test]
    async fn health_proof_rejects_noncanonical_or_wrong_length_nonces() {
        // Break caught: attacker-controlled path text is signed without first proving it is the
        // canonical encoding of exactly 32 nonce bytes.
        let (app, _) = test_router();
        for nonce in [
            "short",
            "ERERERERERERERERERERERERERERERERERERERERERE=",
            "ERERERERERERERERERERERERERERERERERERERERER!",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/health/proof/{nonce}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{nonce}");
        }
    }

    #[tokio::test]
    async fn unregister_is_authenticated_and_idempotent() {
        let (app, broker) = test_router();
        let registration = register_direct(&broker, "reviewer", "w1:p2").await;

        for attempt in 0..2 {
            let response = app
                .clone()
                .oneshot(request(
                    Method::POST,
                    "/v1/unregister",
                    Body::empty(),
                    Some(&registration),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "attempt {attempt}");
            assert_eq!(json_body(response).await, json!({"ok": true}));
        }
    }

    #[tokio::test]
    async fn authenticated_routing_errors_are_structured_json() {
        let (app, _) = test_router();
        for (method, path, expected_status, expected_code) in [
            (Method::GET, "/unknown", StatusCode::NOT_FOUND, "not_found"),
            (
                Method::POST,
                "/health",
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
            ),
        ] {
            let response = app
                .clone()
                .oneshot(request(method, path, Body::empty(), None))
                .await
                .unwrap();
            assert_eq!(response.status(), expected_status);
            assert_eq!(json_body(response).await["error"]["code"], expected_code);
        }
    }

    #[tokio::test]
    async fn bearer_auth_accepts_only_the_exact_token() {
        let (app, _) = test_router();
        for value in [
            "Bearer test-private-bearer-tokem",
            "Bearer test-private-bearer-token-extra",
            "test-private-bearer-token",
            "bearer test-private-bearer-token",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/health")
                        .header(header::AUTHORIZATION, value)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{value}");
        }

        let response = app
            .oneshot(request(Method::GET, "/health", Body::empty(), None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn registration_uses_verified_identity_and_rejects_claimed_identity_fields() {
        let (app, _) = test_router_with_verified(pane("reviewer", "w1:p2"));
        let registered = register(app.clone(), "w1:p2", "pi-2").await;
        assert!(
            registered["canonical_name"]
                .as_str()
                .unwrap()
                .starts_with("reviewer-")
        );
        assert_eq!(registered["role"], "reviewer");
        assert_eq!(registered["pane_id"], "w1:p2");

        let response = app
            .oneshot(json_request(
                Method::POST,
                "/v1/register",
                json!({
                    "pane_id": "w1:p2",
                    "harness_session_id": "pi-2",
                    "claimed_name": "attacker"
                }),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"]["code"], "invalid_json");
    }

    #[tokio::test]
    async fn expected_agent_name_mismatch_is_rejected_before_registration_replacement() {
        // Break caught: a recovery registration for a reassigned pane mutates the registry under
        // the verifier's new name before proving it is still the client's pinned principal.
        let (app, broker) = test_router_with_verified(pane("observer", "w1:p2"));
        let reviewer = register_direct(&broker, "reviewer", "w1:p2").await;
        let observer = register_direct(&broker, "observer", "w1:p3").await;

        let response = app
            .oneshot(json_request(
                Method::POST,
                "/v1/register",
                json!({
                    "pane_id": "w1:p2",
                    "harness_session_id": "reviewer-recovery",
                    "expected_agent_name": "reviewer"
                }),
                None,
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            json_body(response).await["error"]["code"],
            "agent_identity_changed"
        );
        let registrations = broker.list_agents().await;
        assert_eq!(registrations.len(), 2);
        assert!(registrations.iter().any(|registration| {
            registration.agent.name.as_str() == "reviewer"
                && registration.credentials() == reviewer.credentials()
        }));
        assert!(registrations.iter().any(|registration| {
            registration.agent.name.as_str() == "observer"
                && registration.credentials() == observer.credentials()
        }));
    }

    #[tokio::test]
    async fn registration_response_contains_a_positive_epoch() {
        let (app, _) = test_router();
        let registered = register(app, "w1:p2", "pi-2").await;
        assert!(registered["registration_epoch"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn missing_malformed_and_stale_epochs_cannot_mutate_private_state() {
        let (app, broker) = test_router();
        let sender = register_direct(&broker, "implementer", "w1:p1").await;
        let first = register_direct(&broker, "reviewer", "w1:p2").await;
        enqueue(&broker, &sender, &first, "epoch-fenced").await;
        let first_delivery = broker.wait_next(&first.credentials(), None).await.unwrap();
        let second = register_direct(&broker, "reviewer", "w1:p3").await;
        let valid_epoch = second.epoch.get().to_string();

        for epoch in [
            None,
            Some(""),
            Some("abc"),
            Some("+1"),
            Some("-1"),
            Some("0"),
            Some("01"),
            Some("18446744073709551616"),
        ] {
            for (path, body) in [
                ("/v1/renew", json!({})),
                ("/v1/inbox/wait", json!({"timeout_ms": 1_000})),
                (
                    "/v1/inbox/ack",
                    json!({"delivery_id": first_delivery.delivery_id}),
                ),
                (
                    "/v1/tasks/epoch-fenced/reply",
                    json!({"text": "stale", "metadata": {}, "file_refs": []}),
                ),
                ("/v1/tasks/epoch-fenced/cancel", json!({})),
            ] {
                let response = app
                    .clone()
                    .oneshot(credential_request(Method::POST, path, body, &second, epoch))
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    StatusCode::UNAUTHORIZED,
                    "{path} {epoch:?}"
                );
                let body = json_body(response).await;
                assert!(
                    matches!(
                        body["error"]["code"].as_str(),
                        Some("missing_registration_epoch" | "invalid_registration")
                    ),
                    "{path} {epoch:?}: {body}"
                );
                assert!(serde_json::to_vec(&body).unwrap().len() <= 1_024);
            }
        }

        for (path, body) in [
            ("/v1/renew", json!({})),
            ("/v1/inbox/wait", json!({"timeout_ms": 1_000})),
            (
                "/v1/inbox/ack",
                json!({"delivery_id": first_delivery.delivery_id}),
            ),
            (
                "/v1/tasks/epoch-fenced/reply",
                json!({"text": "stale", "metadata": {}, "file_refs": []}),
            ),
            ("/v1/tasks/epoch-fenced/cancel", json!({})),
        ] {
            let stale_epoch = first.epoch.get().to_string();
            let response = app
                .clone()
                .oneshot(credential_request(
                    Method::POST,
                    path,
                    body,
                    &second,
                    Some(&stale_epoch),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
            assert_eq!(
                json_body(response).await["error"]["code"],
                "invalid_registration"
            );
        }
        assert_eq!(
            broker
                .authenticate(&second.credentials())
                .await
                .unwrap()
                .expires_unix_ms,
            second.expires_unix_ms
        );

        let delivered = app
            .clone()
            .oneshot(credential_request(
                Method::POST,
                "/v1/inbox/wait",
                json!({"timeout_ms": 1_000}),
                &second,
                Some(&valid_epoch),
            ))
            .await
            .unwrap();
        assert_eq!(delivered.status(), StatusCode::OK);
        assert_eq!(json_body(delivered).await["task_id"], "epoch-fenced");
    }

    #[tokio::test]
    async fn renewal_and_agent_listing_use_the_active_registration() {
        let (app, _) = test_router();
        let registered = register(app.clone(), "w1:p2", "pi-2").await;
        let registration_id = registered["registration_id"].as_str().unwrap();
        let registration_epoch = registered["registration_epoch"].as_u64().unwrap();

        let list = app
            .clone()
            .oneshot(request(Method::GET, "/v1/agents", Body::empty(), None))
            .await
            .unwrap();
        assert_eq!(list.status(), StatusCode::OK);
        let listed = json_body(list).await;
        assert_eq!(
            listed["agents"][0]["canonical_name"],
            registered["canonical_name"]
        );
        assert_eq!(listed["agents"][0]["role"], "reviewer");
        assert_eq!(listed["agents"][0]["pane_id"], "w1:p2");
        assert_eq!(listed["agents"][0]["harness"], "pi");
        assert_eq!(listed["agents"][0]["status"], "live");
        assert_eq!(listed["agents"][0].as_object().unwrap().len(), 5);
        assert!(listed["agents"][0].get("registration_id").is_none());
        assert!(listed["agents"][0].get("harness_session_id").is_none());
        assert!(listed["agents"][0].get("workspace").is_none());

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/renew")
                    .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .header(REGISTRATION_HEADER, registration_id)
                    .header(REGISTRATION_EPOCH_HEADER, registration_epoch)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            json_body(response).await["registration_id"],
            registration_id
        );
    }

    #[tokio::test]
    async fn lease_bound_endpoints_reject_missing_registration_with_json() {
        let (app, _) = test_router();
        for (path, body) in [
            ("/v1/renew", json!({})),
            ("/v1/inbox/wait", json!({"timeout_ms": 1_000})),
            ("/v1/inbox/ack", json!({"delivery_id": DeliveryId::new()})),
            (
                "/v1/tasks/task-1/reply",
                json!({"text": "ok", "metadata": {}, "file_refs": []}),
            ),
            ("/v1/tasks/task-1/cancel", json!({})),
        ] {
            let response = app
                .clone()
                .oneshot(json_request(Method::POST, path, body, None))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
            assert_eq!(
                json_body(response).await["error"]["code"],
                "missing_registration"
            );
        }
    }

    #[tokio::test]
    async fn aborted_http_wait_drops_the_single_wait_guard() {
        let (app, broker) = test_router();
        let recipient = register_direct(&broker, "recipient", "p2").await;
        let first_app = app.clone();
        let first_registration = recipient.clone();
        let first = tokio::spawn(async move {
            first_app
                .oneshot(json_request(
                    Method::POST,
                    "/v1/inbox/wait",
                    json!({"timeout_ms": MAX_WAIT_TIMEOUT_MS}),
                    Some(&first_registration),
                ))
                .await
        });
        tokio::task::yield_now().await;

        let concurrent = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                "/v1/inbox/wait",
                json!({"timeout_ms": 1_000}),
                Some(&recipient),
            ))
            .await
            .unwrap();
        assert_eq!(concurrent.status(), StatusCode::CONFLICT);
        assert_eq!(
            json_body(concurrent).await["error"]["code"],
            "wait_already_active"
        );

        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        tokio::task::yield_now().await;
        let after_abort = app
            .oneshot(json_request(
                Method::POST,
                "/v1/inbox/wait",
                json!({"timeout_ms": 1_000}),
                Some(&recipient),
            ))
            .await
            .unwrap();
        assert_eq!(after_abort.status(), StatusCode::REQUEST_TIMEOUT);
    }

    #[tokio::test]
    async fn wait_timeout_and_json_body_are_bounded() {
        let (app, broker) = test_router();
        let recipient = register_direct(&broker, "recipient", "p2").await;
        for timeout_ms in [999, 86_400_001] {
            let response = app
                .clone()
                .oneshot(json_request(
                    Method::POST,
                    "/v1/inbox/wait",
                    json!({"timeout_ms": timeout_ms}),
                    Some(&recipient),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                json_body(response).await["error"]["code"],
                "invalid_timeout"
            );
        }

        let response = app
            .oneshot(request(
                Method::POST,
                "/v1/register",
                Body::from(vec![b'x'; MAX_JSON_BODY_BYTES + 1]),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(json_body(response).await["error"]["code"], "body_too_large");
    }

    #[tokio::test]
    async fn wait_timeout_is_optional_and_accepts_the_twenty_four_hour_boundary() {
        let (app, broker) = test_router();
        let sender = register_direct(&broker, "sender", "p1").await;
        let first_recipient = register_direct(&broker, "first", "p2").await;
        enqueue(&broker, &sender, &first_recipient, "task-no-timeout").await;

        let no_timeout = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                "/v1/inbox/wait",
                json!({}),
                Some(&first_recipient),
            ))
            .await
            .unwrap();
        assert_eq!(no_timeout.status(), StatusCode::OK);

        let second_recipient = register_direct(&broker, "second", "p3").await;
        enqueue(&broker, &sender, &second_recipient, "task-max-timeout").await;
        let max_timeout = app
            .oneshot(json_request(
                Method::POST,
                "/v1/inbox/wait",
                json!({"timeout_ms": 86_400_000}),
                Some(&second_recipient),
            ))
            .await
            .unwrap();
        assert_eq!(max_timeout.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn invalid_task_path_is_a_structured_error() {
        let (app, broker) = test_router();
        let registration = register_direct(&broker, "sender", "p1").await;
        let response = app
            .oneshot(request(
                Method::POST,
                "/v1/tasks/%FF/cancel",
                Body::empty(),
                Some(&registration),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["error"]["code"], "invalid_path");
    }

    #[tokio::test]
    async fn encoded_malicious_task_id_cannot_unregister_caller() {
        // Break caught: percent-decoded task IDs bypass the private route boundary unchecked.
        let (app, broker) = test_router();
        let registration = register_direct(&broker, "sender", "p1").await;
        let response = app
            .oneshot(request(
                Method::POST,
                "/v1/tasks/..%2Funregister%23/cancel",
                Body::empty(),
                Some(&registration),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            json_body(response).await["error"]["code"],
            "invalid_request"
        );
        assert_eq!(broker.list_agents().await.len(), 1);
    }

    #[tokio::test]
    async fn delivery_acknowledgement_is_explicit_and_registration_owned() {
        let (app, broker) = test_router();
        let sender = register_direct(&broker, "sender", "p1").await;
        let recipient = register_direct(&broker, "recipient", "p2").await;
        enqueue(&broker, &sender, &recipient, "task-ack").await;

        let response = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                "/v1/inbox/wait",
                json!({"timeout_ms": 1_000}),
                Some(&recipient),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let delivered = json_body(response).await;

        let wrong_owner = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                "/v1/inbox/ack",
                json!({"delivery_id": delivered["delivery_id"]}),
                Some(&sender),
            ))
            .await
            .unwrap();
        assert_eq!(wrong_owner.status(), StatusCode::FORBIDDEN);

        let acknowledged = app
            .oneshot(json_request(
                Method::POST,
                "/v1/inbox/ack",
                json!({"delivery_id": delivered["delivery_id"]}),
                Some(&recipient),
            ))
            .await
            .unwrap();
        assert_eq!(acknowledged.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn task_reply_is_recipient_registration_owned() {
        let (app, broker) = test_router();
        let sender = register_direct(&broker, "sender", "p1").await;
        let recipient = register_direct(&broker, "recipient", "p2").await;
        enqueue(&broker, &sender, &recipient, "task-reply").await;
        let reply = json!({"text": "looks good", "metadata": {}, "file_refs": []});

        let wrong_owner = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                "/v1/tasks/task-reply/reply",
                reply.clone(),
                Some(&sender),
            ))
            .await
            .unwrap();
        assert_eq!(wrong_owner.status(), StatusCode::FORBIDDEN);

        let accepted = app
            .oneshot(json_request(
                Method::POST,
                "/v1/tasks/task-reply/reply",
                reply,
                Some(&recipient),
            ))
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);
        assert_eq!(
            broker
                .wait_for_reply(&sender.credentials(), "task-reply")
                .await
                .unwrap(),
            ReplyPayload {
                text: "looks good".to_owned(),
                metadata: json!({}),
                file_refs: vec![],
            }
        );
    }

    #[tokio::test]
    async fn task_reply_rejects_supported_workspace_file_reference_in_this_milestone() {
        let workspace = tempfile::tempdir().unwrap();
        let referenced = workspace.path().join("review.txt");
        std::fs::write(&referenced, "review material").unwrap();
        let mut verified = pane("reviewer", "w1:p2");
        verified.workspace_path = workspace.path().to_path_buf();
        let (app, broker) = test_router_with_verified(verified.clone());
        let sender = register_direct(&broker, "sender", "w1:p1").await;
        let mut recipient_agent = agent("reviewer", "w1:p2");
        recipient_agent.workspace = verified.workspace_path;
        let recipient = broker.register(recipient_agent, "pi-test").await.unwrap();
        enqueue(&broker, &sender, &recipient, "task-file-reply").await;

        let response = app
            .oneshot(json_request(
                Method::POST,
                "/v1/tasks/task-file-reply/reply",
                json!({
                    "text": "looks good",
                    "metadata": {},
                    "file_refs": [{"path": referenced, "media_type": "text/plain", "label": "review"}]
                }),
                Some(&recipient),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = json_body(response).await;
        assert_eq!(body["error"]["code"], "unsupported_file_references");
        assert_eq!(
            body["error"]["message"],
            "Herdr file references are not supported in this milestone"
        );
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                broker.wait_for_reply(&sender.credentials(), "task-file-reply")
            )
            .await
            .is_err(),
            "rejected file reply must not be submitted"
        );
    }

    #[tokio::test]
    async fn task_cancellation_requires_the_authenticated_sender_registration() {
        let (app, broker) = test_router();
        let sender = register_direct(&broker, "sender", "p1").await;
        let recipient = register_direct(&broker, "recipient", "p2").await;
        let attacker = register_direct(&broker, "attacker", "p3").await;
        enqueue(&broker, &sender, &recipient, "task-cancel").await;

        let wrong_sender = app
            .clone()
            .oneshot(request(
                Method::POST,
                "/v1/tasks/task-cancel/cancel",
                Body::empty(),
                Some(&attacker),
            ))
            .await
            .unwrap();
        assert_eq!(wrong_sender.status(), StatusCode::FORBIDDEN);

        let canceled = app
            .oneshot(request(
                Method::POST,
                "/v1/tasks/task-cancel/cancel",
                Body::empty(),
                Some(&sender),
            ))
            .await
            .unwrap();
        assert_eq!(canceled.status(), StatusCode::OK);
        assert_eq!(
            broker
                .wait_for_reply(&sender.credentials(), "task-cancel")
                .await
                .unwrap_err()
                .to_string(),
            "task was canceled"
        );
    }
}
