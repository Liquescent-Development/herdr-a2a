use std::{collections::HashSet, fmt, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::StreamExt;
use herdr_a2a_broker::{RuntimeDescriptor, RuntimePaths, read_descriptor};
#[cfg(test)]
use herdr_a2a_core::broker::BrokerOperationsSnapshot;
use herdr_a2a_core::{
    AgentName, RoleLabel,
    broker::{BrokerStatusEvent, BrokerTaskCounts},
};
use hmac::{Hmac, Mac};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const MAX_STATUS_BYTES: usize = 256 * 1024;
const STATUS_TIMEOUT: Duration = Duration::from_secs(3);
const STATUS_PROOF_HEADER: &str = "x-herdr-a2a-status-proof";
const INSTANCE_HEADER: &str = "x-herdr-a2a-instance";
const STATUS_PROOF_DOMAIN: &[u8] = b"herdr-a2a-status-v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentStatus {
    pub role: RoleLabel,
    pub canonical_name: AgentName,
    pub status: String,
}

#[cfg_attr(test, allow(dead_code))]
impl AgentStatus {
    #[cfg(test)]
    pub fn new(role: &str, canonical_name: &str, status: &str) -> Result<Self, OperationsError> {
        let role = RoleLabel::parse(role).map_err(|_| OperationsError::InvalidResponse)?;
        let canonical_name =
            AgentName::parse(canonical_name).map_err(|_| OperationsError::InvalidResponse)?;
        if status != "connected" {
            return Err(OperationsError::InvalidResponse);
        }
        Ok(Self {
            role,
            canonical_name,
            status: status.to_owned(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceStatus {
    pub workspace_id: String,
    pub broker: String,
    pub storage: String,
    pub registrations: usize,
    pub agents: Vec<AgentStatus>,
    pub tasks: BrokerTaskCounts,
    pub last_event: Option<BrokerStatusEvent>,
}

#[cfg_attr(test, allow(dead_code))]
impl WorkspaceStatus {
    #[cfg(test)]
    pub fn from_broker(
        workspace_id: &str,
        agents: Vec<AgentStatus>,
        snapshot: BrokerOperationsSnapshot,
    ) -> Result<Self, OperationsError> {
        let status = Self {
            workspace_id: workspace_id.to_owned(),
            broker: "healthy".to_owned(),
            storage: "reconciled".to_owned(),
            registrations: snapshot.registrations,
            agents,
            tasks: snapshot.tasks,
            last_event: snapshot.last_event,
        };
        status.validate()?;
        Ok(status)
    }

    fn validate(&self) -> Result<(), OperationsError> {
        if self.workspace_id.is_empty()
            || self.workspace_id.len() > 1_024
            || self.workspace_id.chars().any(char::is_control)
            || self.broker != "healthy"
            || self.storage != "reconciled"
            || self.agents.len() > self.registrations
        {
            return Err(OperationsError::InvalidResponse);
        }
        let mut canonical = HashSet::new();
        if self.agents.iter().any(|agent| {
            agent.status != "connected" || !canonical.insert(agent.canonical_name.clone())
        }) {
            return Err(OperationsError::InvalidResponse);
        }
        if let Some(event) = &self.last_event
            && (event.kind.is_empty()
                || event.kind.len() > 64
                || !event
                    .kind
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_'))
        {
            return Err(OperationsError::InvalidResponse);
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn healthy_fixture(workspace_id: &str) -> Self {
        Self {
            workspace_id: workspace_id.to_owned(),
            broker: "healthy".to_owned(),
            storage: "reconciled".to_owned(),
            registrations: 1,
            agents: vec![AgentStatus::new("worker", "worker-k7m2", "connected").unwrap()],
            tasks: BrokerTaskCounts::default(),
            last_event: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationsError {
    BrokerUnavailable,
    BrokerProofFailed,
    InvalidResponse,
    StorageReconciliationFailed,
}

impl fmt::Display for OperationsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::BrokerUnavailable => "workspace broker is unavailable",
            Self::BrokerProofFailed => "workspace broker proof failed",
            Self::InvalidResponse => "workspace broker returned invalid redacted status",
            Self::StorageReconciliationFailed => "workspace broker storage reconciliation failed",
        })
    }
}

impl std::error::Error for OperationsError {}

fn client() -> Result<Client, OperationsError> {
    Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| OperationsError::BrokerUnavailable)
}

pub async fn collect() -> Result<WorkspaceStatus, OperationsError> {
    let paths = RuntimePaths::discover().map_err(|_| OperationsError::BrokerUnavailable)?;
    let descriptor = read_descriptor(&paths).map_err(|_| OperationsError::BrokerUnavailable)?;
    collect_from_descriptor(&descriptor).await
}

pub(crate) async fn collect_from_descriptor(
    descriptor: &RuntimeDescriptor,
) -> Result<WorkspaceStatus, OperationsError> {
    let client = client()?;
    tokio::time::timeout(STATUS_TIMEOUT, collect_transaction(&client, descriptor))
        .await
        .map_err(|_| OperationsError::BrokerUnavailable)?
}

async fn collect_transaction(
    client: &Client,
    descriptor: &RuntimeDescriptor,
) -> Result<WorkspaceStatus, OperationsError> {
    validate_instance_id(descriptor)?;
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| OperationsError::BrokerProofFailed)?;
    let encoded_nonce = URL_SAFE_NO_PAD.encode(nonce);
    let url = format!("{}/health/status/{encoded_nonce}", descriptor.base_url);
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|_| OperationsError::BrokerUnavailable)?;
    if response.url().as_str() != url {
        return Err(OperationsError::InvalidResponse);
    }
    let response_status = response.status();
    let response_headers = response.headers().clone();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_STATUS_BYTES as u64)
    {
        return Err(OperationsError::InvalidResponse);
    }
    let body = bounded_body(response).await?;
    verify_status_response(descriptor, &nonce, &response_headers, &body)?;
    if response_status == StatusCode::SERVICE_UNAVAILABLE {
        let error: StatusErrorEnvelope =
            serde_json::from_slice(&body).map_err(|_| OperationsError::InvalidResponse)?;
        return if error.error.code == "persistence_unavailable" {
            Err(OperationsError::StorageReconciliationFailed)
        } else {
            Err(OperationsError::InvalidResponse)
        };
    }
    if response_status != StatusCode::OK {
        return Err(OperationsError::InvalidResponse);
    }
    let status: WorkspaceStatus =
        serde_json::from_slice(&body).map_err(|_| OperationsError::InvalidResponse)?;
    if status.workspace_id != descriptor.workspace_id {
        return Err(OperationsError::InvalidResponse);
    }
    status.validate()?;
    Ok(status)
}

fn validate_instance_id(descriptor: &RuntimeDescriptor) -> Result<Vec<u8>, OperationsError> {
    let decoded_instance = URL_SAFE_NO_PAD
        .decode(&descriptor.broker_instance_id)
        .map_err(|_| OperationsError::BrokerProofFailed)?;
    if descriptor.broker_instance_id.len() != 43
        || decoded_instance.len() != 32
        || URL_SAFE_NO_PAD.encode(&decoded_instance) != descriptor.broker_instance_id
    {
        return Err(OperationsError::BrokerProofFailed);
    }
    Ok(decoded_instance)
}

fn verify_status_response(
    descriptor: &RuntimeDescriptor,
    nonce: &[u8],
    headers: &reqwest::header::HeaderMap,
    body: &[u8],
) -> Result<(), OperationsError> {
    if single_header(headers, INSTANCE_HEADER)? != descriptor.broker_instance_id {
        return Err(OperationsError::BrokerProofFailed);
    }
    let proof_text = single_header(headers, STATUS_PROOF_HEADER)?;
    let proof = URL_SAFE_NO_PAD
        .decode(proof_text)
        .map_err(|_| OperationsError::BrokerProofFailed)?;
    if proof.len() != 32 || URL_SAFE_NO_PAD.encode(&proof) != proof_text {
        return Err(OperationsError::BrokerProofFailed);
    }
    let key = Sha256::digest(descriptor.bearer_token.as_bytes());
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("SHA-256 digest is a valid key");
    mac.update(STATUS_PROOF_DOMAIN);
    mac.update(descriptor.broker_instance_id.as_bytes());
    mac.update(nonce);
    mac.update(body);
    let expected = mac.finalize().into_bytes();
    if !bool::from(proof.as_slice().ct_eq(expected.as_slice())) {
        return Err(OperationsError::BrokerProofFailed);
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusErrorEnvelope {
    error: StatusErrorBody,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusErrorBody {
    code: String,
    #[serde(rename = "message")]
    _message: String,
}

async fn bounded_body(response: reqwest::Response) -> Result<Vec<u8>, OperationsError> {
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| OperationsError::InvalidResponse)?;
        if body.len().saturating_add(chunk.len()) > MAX_STATUS_BYTES {
            return Err(OperationsError::InvalidResponse);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn single_header<'a>(
    headers: &'a reqwest::header::HeaderMap,
    name: &str,
) -> Result<&'a str, OperationsError> {
    let mut values = headers.get_all(name).iter();
    values
        .next()
        .and_then(|value| value.to_str().ok())
        .filter(|_| values.next().is_none())
        .ok_or(OperationsError::BrokerProofFailed)
}

pub async fn run(json: bool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let status = collect().await?;
    if json {
        println!("{}", serde_json::to_string(&status)?);
    } else {
        println!(
            "{}",
            crate::status_tui::render(&crate::status_tui::TuiState::new(status))
        );
    }
    Ok(())
}
