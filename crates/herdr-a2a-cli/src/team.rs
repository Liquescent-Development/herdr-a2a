use std::{
    collections::{HashMap, HashSet},
    ffi::OsString,
    io,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use async_trait::async_trait;
use herdr_a2a_broker::herdr::{CommandOutput, HerdrCommandRunner};
use herdr_a2a_core::{AgentName, RoleLabel};
use serde::{Deserialize, Serialize};

const MAX_TEAM_MEMBERS: usize = 8;
const MAX_OPAQUE_ID_BYTES: usize = 1_024;
const DEFAULT_REGISTRATION_TIMEOUT: Duration = Duration::from_secs(30);
const AGENT_START_WINDOW: Duration = Duration::from_secs(30);
const AGENT_START_COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const AGENT_START_OBSERVE_DELAY: Duration = Duration::from_millis(50);
const AGENT_START_BUSY_BACKOFF_MAX: Duration = Duration::from_secs(1);
const HERDR_AGENT_START_MIN_TIMEOUT_MS: u64 = 3_001;

#[derive(Clone, Debug)]
pub struct TeamRequest {
    pub caller_pane_id: String,
    pub workspace_id: String,
    pub cwd: PathBuf,
    pub self_role: Option<RoleLabel>,
    pub roles: Vec<RoleLabel>,
}

impl TeamRequest {
    pub fn new(
        caller_pane_id: impl Into<String>,
        workspace_id: impl Into<String>,
        cwd: PathBuf,
        self_role: Option<String>,
        roles: Vec<String>,
    ) -> io::Result<Self> {
        let caller_pane_id = caller_pane_id.into();
        let workspace_id = workspace_id.into();
        if !bounded_control_free(&caller_pane_id, MAX_OPAQUE_ID_BYTES)
            || !bounded_control_free(&workspace_id, 256)
            || !safe_cwd(&cwd)
            || roles.is_empty()
            || roles.len() > MAX_TEAM_MEMBERS
        {
            return Err(invalid_request());
        }

        let self_role = self_role.map(parse_team_role).transpose()?;
        let roles = roles
            .into_iter()
            .map(parse_team_role)
            .collect::<io::Result<Vec<_>>>()?;
        let mut unique = HashSet::with_capacity(roles.len() + usize::from(self_role.is_some()));
        if let Some(role) = &self_role {
            unique.insert(role.as_str().to_owned());
        }
        if roles
            .iter()
            .any(|role| !unique.insert(role.as_str().to_owned()))
        {
            return Err(invalid_request());
        }

        Ok(Self {
            caller_pane_id,
            workspace_id,
            cwd,
            self_role,
            roles,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamMemberState {
    Started,
    Registered,
    TimedOut,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TeamMemberResult {
    pub requested_role: RoleLabel,
    pub pane_id: Option<String>,
    pub canonical_name: Option<AgentName>,
    pub state: TeamMemberState,
    pub error_code: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TeamResult {
    pub members: Vec<TeamMemberResult>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredTeamAgent {
    pub pane_id: String,
    pub canonical_name: AgentName,
}

#[async_trait]
pub trait AgentRegistrationWaiter: Send + Sync {
    async fn wait_for_agents(
        &self,
        pane_ids: &[String],
        timeout: Duration,
    ) -> io::Result<Vec<RegisteredTeamAgent>>;
}

pub struct TeamOrchestrator<R, W> {
    herdr: PathBuf,
    runner: R,
    waiter: W,
    registration_timeout: Duration,
}

impl<R, W> TeamOrchestrator<R, W>
where
    R: HerdrCommandRunner,
    W: AgentRegistrationWaiter,
{
    pub fn new(herdr: PathBuf, runner: R, waiter: W) -> Self {
        Self {
            herdr,
            runner,
            waiter,
            registration_timeout: DEFAULT_REGISTRATION_TIMEOUT,
        }
    }

    pub async fn create_team(&self, request: TeamRequest) -> io::Result<TeamResult> {
        if let Some(self_role) = &request.self_role {
            let rename_succeeded = self
                .run([
                    "agent".into(),
                    "rename".into(),
                    request.caller_pane_id.clone().into(),
                    self_role.as_str().into(),
                ])
                .await
                .is_ok_and(|output| output.success);
            if !rename_succeeded {
                return Ok(TeamResult {
                    members: request
                        .roles
                        .into_iter()
                        .map(|role| {
                            failed_member(role, None, "not_attempted_after_self_rename_failure")
                        })
                        .collect(),
                });
            }
        }

        let mut members = Vec::with_capacity(request.roles.len());
        let mut created_pane_ids = HashSet::with_capacity(request.roles.len());
        for (index, role) in request.roles.iter().enumerate() {
            let member = self
                .create_member(&request, role.clone(), &created_pane_ids)
                .await;
            let failed = member.state == TeamMemberState::Failed;
            if let Some(pane_id) = &member.pane_id {
                created_pane_ids.insert(pane_id.clone());
            }
            members.push(member);
            if failed {
                members.extend(
                    request.roles[index + 1..]
                        .iter()
                        .cloned()
                        .map(|role| failed_member(role, None, "not_attempted_after_failure")),
                );
                break;
            }
        }

        let pane_ids = members
            .iter()
            .filter(|member| member.state == TeamMemberState::Started)
            .filter_map(|member| member.pane_id.clone())
            .collect::<Vec<_>>();
        if !pane_ids.is_empty() {
            match self
                .waiter
                .wait_for_agents(&pane_ids, self.registration_timeout)
                .await
            {
                Ok(registered) => {
                    let by_pane = registered
                        .into_iter()
                        .map(|agent| (agent.pane_id, agent.canonical_name))
                        .collect::<HashMap<_, _>>();
                    for member in &mut members {
                        if member.state != TeamMemberState::Started {
                            continue;
                        }
                        if let Some(canonical_name) = member
                            .pane_id
                            .as_ref()
                            .and_then(|pane_id| by_pane.get(pane_id))
                        {
                            member.canonical_name = Some(canonical_name.clone());
                            member.state = TeamMemberState::Registered;
                        } else {
                            member.state = TeamMemberState::TimedOut;
                            member.error_code = Some("registration_timed_out".to_owned());
                        }
                    }
                }
                Err(_) => {
                    for member in &mut members {
                        if member.state == TeamMemberState::Started {
                            member.state = TeamMemberState::Failed;
                            member.error_code = Some("registration_wait_failed".to_owned());
                        }
                    }
                }
            }
        }

        Ok(TeamResult { members })
    }

    async fn create_member(
        &self,
        request: &TeamRequest,
        role: RoleLabel,
        created_pane_ids: &HashSet<String>,
    ) -> TeamMemberResult {
        let layout = match self
            .run([
                "pane".into(),
                "layout".into(),
                "--pane".into(),
                request.caller_pane_id.clone().into(),
            ])
            .await
        {
            Ok(output) if output.success => output,
            _ => return failed_member(role, None, "pane_layout_failed"),
        };
        let selection = match parse_split_candidate(&layout.stdout, &request.workspace_id) {
            Ok(selection) => selection,
            Err(_) => return failed_member(role, None, "pane_layout_invalid"),
        };
        let direction = if selection.candidate.width >= selection.candidate.height {
            "right"
        } else {
            "down"
        };
        let split = match self
            .run([
                "pane".into(),
                "split".into(),
                selection.candidate.pane_id.into(),
                "--direction".into(),
                direction.into(),
                "--cwd".into(),
                request.cwd.as_os_str().to_owned(),
                "--no-focus".into(),
            ])
            .await
        {
            Ok(output) if output.success => output,
            _ => return failed_member(role, None, "pane_split_failed"),
        };
        let pane_id = match parse_split_pane_id(&split.stdout) {
            Ok(pane_id) => pane_id,
            Err(_) => return failed_member(role, None, "pane_split_invalid"),
        };
        if pane_id == request.caller_pane_id
            || selection.pane_ids.contains(&pane_id)
            || created_pane_ids.contains(&pane_id)
        {
            return failed_member(role, None, "pane_split_not_new");
        }
        let rename = self
            .run([
                "pane".into(),
                "rename".into(),
                pane_id.clone().into(),
                role.as_str().into(),
            ])
            .await;
        if !matches!(rename, Ok(output) if output.success) {
            return failed_member(role, Some(pane_id), "pane_rename_failed");
        }
        if !self.start_agent(&role, &pane_id).await {
            return failed_member(role, Some(pane_id), "agent_start_failed");
        }

        TeamMemberResult {
            requested_role: role,
            pane_id: Some(pane_id),
            canonical_name: None,
            state: TeamMemberState::Started,
            error_code: None,
        }
    }

    async fn run<const N: usize>(&self, args: [OsString; N]) -> io::Result<CommandOutput> {
        self.runner.run(&self.herdr, &args).await
    }

    async fn run_before_deadline(
        &self,
        args: &[OsString],
        deadline: tokio::time::Instant,
    ) -> io::Result<CommandOutput> {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "team agent-start deadline expired",
            ));
        }
        self.runner
            .run_with_timeout(&self.herdr, args, remaining)
            .await
    }

    async fn start_agent(&self, role: &RoleLabel, pane_id: &str) -> bool {
        let deadline = tokio::time::Instant::now() + AGENT_START_WINDOW;
        loop {
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            if self
                .run_before_deadline(
                    &[
                        "pane".into(),
                        "process-info".into(),
                        "--pane".into(),
                        pane_id.into(),
                    ],
                    deadline,
                )
                .await
                .is_ok_and(|output| {
                    output.success && parse_ready_shell(&output.stdout, pane_id).unwrap_or(false)
                })
            {
                break;
            }
            tokio::time::sleep(AGENT_START_OBSERVE_DELAY).await;
        }
        let mut busy_attempt = 0_u32;
        loop {
            let start_timeout = deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .min(AGENT_START_COMMAND_TIMEOUT);
            let remaining_ms = u64::try_from(start_timeout.as_millis()).unwrap_or(u64::MAX);
            if remaining_ms < HERDR_AGENT_START_MIN_TIMEOUT_MS {
                return false;
            }
            let args = [
                "agent".into(),
                "start".into(),
                role.as_str().into(),
                "--kind".into(),
                "pi".into(),
                "--pane".into(),
                pane_id.into(),
                "--timeout".into(),
                remaining_ms.to_string().into(),
            ];
            match self
                .runner
                .run_with_timeout(&self.herdr, &args, start_timeout)
                .await
            {
                Ok(output) if output.success => return true,
                Ok(output) if parse_agent_pane_busy(&output.stdout, &output.stderr) => {
                    let multiplier = 1_u32 << busy_attempt.min(4);
                    busy_attempt = busy_attempt.saturating_add(1);
                    let delay = AGENT_START_OBSERVE_DELAY
                        .saturating_mul(multiplier)
                        .min(AGENT_START_BUSY_BACKOFF_MAX)
                        .min(deadline.saturating_duration_since(tokio::time::Instant::now()));
                    if delay.is_zero() {
                        return false;
                    }
                    tokio::time::sleep(delay).await;
                }
                _ => break,
            }
        }
        loop {
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            if self
                .run_before_deadline(&["agent".into(), "get".into(), pane_id.into()], deadline)
                .await
                .is_ok_and(|output| {
                    output.success && parse_started_pi(&output.stdout, pane_id).unwrap_or(false)
                })
            {
                return true;
            }
            tokio::time::sleep(AGENT_START_OBSERVE_DELAY).await;
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentStartErrorEnvelope {
    error: AgentStartError,
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentStartError {
    code: String,
    message: String,
}

fn parse_agent_pane_busy(stdout: &[u8], stderr: &[u8]) -> bool {
    let encoded = match (stdout.is_empty(), stderr.is_empty()) {
        (false, true) => stdout,
        (true, false) => stderr,
        _ => return false,
    };
    serde_json::from_slice::<AgentStartErrorEnvelope>(encoded).is_ok_and(|envelope| {
        envelope.id == "cli:agent:start"
            && envelope.error.code == "agent_pane_busy"
            && bounded_control_free(&envelope.error.message, 1_024)
    })
}

#[derive(Deserialize)]
struct ProcessInfoEnvelope {
    result: ProcessInfoResult,
}

#[derive(Deserialize)]
struct ProcessInfoResult {
    process_info: ProcessInfoRecord,
}

#[derive(Deserialize)]
struct ProcessInfoRecord {
    pane_id: String,
    shell_pid: u32,
}

fn parse_ready_shell(stdout: &[u8], pane_id: &str) -> io::Result<bool> {
    let envelope: ProcessInfoEnvelope = serde_json::from_slice(stdout).map_err(io::Error::other)?;
    Ok(envelope.result.process_info.pane_id == pane_id
        && bounded_control_free(&envelope.result.process_info.pane_id, MAX_OPAQUE_ID_BYTES)
        && envelope.result.process_info.shell_pid > 0)
}

#[derive(Deserialize)]
struct AgentInfoEnvelope {
    result: AgentInfoResult,
}

#[derive(Deserialize)]
struct AgentInfoResult {
    agent: AgentInfoRecord,
}

#[derive(Deserialize)]
struct AgentInfoRecord {
    pane_id: String,
    agent: String,
}

fn parse_started_pi(stdout: &[u8], pane_id: &str) -> io::Result<bool> {
    let envelope: AgentInfoEnvelope = serde_json::from_slice(stdout).map_err(io::Error::other)?;
    Ok(envelope.result.agent.pane_id == pane_id
        && bounded_control_free(&envelope.result.agent.pane_id, MAX_OPAQUE_ID_BYTES)
        && envelope.result.agent.agent == "pi")
}

fn parse_team_role(value: String) -> io::Result<RoleLabel> {
    let valid = (1..=32).contains(&value.len())
        && value.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' => true,
            b'0'..=b'9' | b'_' | b'-' => index > 0,
            _ => false,
        });
    if !valid {
        return Err(invalid_request());
    }
    RoleLabel::parse(&value).map_err(|_| invalid_request())
}

fn safe_cwd(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && path
            .components()
            .all(|component| !matches!(component, Component::CurDir | Component::ParentDir))
}

fn bounded_control_free(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

fn invalid_request() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid bounded team request")
}

fn failed_member(
    role: RoleLabel,
    pane_id: Option<String>,
    error_code: &'static str,
) -> TeamMemberResult {
    TeamMemberResult {
        requested_role: role,
        pane_id,
        canonical_name: None,
        state: TeamMemberState::Failed,
        error_code: Some(error_code.to_owned()),
    }
}

#[derive(Deserialize)]
struct LayoutEnvelope {
    result: LayoutResult,
}

#[derive(Deserialize)]
struct LayoutResult {
    layout: Layout,
}

#[derive(Deserialize)]
struct Layout {
    workspace_id: String,
    panes: Vec<LayoutPane>,
}

#[derive(Deserialize)]
struct LayoutPane {
    pane_id: String,
    rect: LayoutRect,
}

#[derive(Deserialize)]
struct LayoutRect {
    width: u64,
    height: u64,
}

struct SplitCandidate {
    pane_id: String,
    width: u64,
    height: u64,
}

struct SplitSelection {
    candidate: SplitCandidate,
    pane_ids: HashSet<String>,
}

fn parse_split_candidate(stdout: &[u8], workspace_id: &str) -> io::Result<SplitSelection> {
    let envelope: LayoutEnvelope = serde_json::from_slice(stdout).map_err(io::Error::other)?;
    if envelope.result.layout.workspace_id != workspace_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "workspace mismatch",
        ));
    }
    let panes = envelope.result.layout.panes;
    if panes.iter().any(|pane| {
        !bounded_control_free(&pane.pane_id, MAX_OPAQUE_ID_BYTES)
            || pane.rect.width == 0
            || pane.rect.height == 0
    }) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid pane layout",
        ));
    }
    let pane_ids = panes
        .iter()
        .map(|pane| pane.pane_id.clone())
        .collect::<HashSet<_>>();
    if pane_ids.len() != panes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "duplicate pane layout ID",
        ));
    }
    let candidate = panes
        .into_iter()
        .max_by_key(|pane| pane.rect.width.saturating_mul(pane.rect.height))
        .map(|pane| SplitCandidate {
            pane_id: pane.pane_id,
            width: pane.rect.width,
            height: pane.rect.height,
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no pane to split"))?;
    Ok(SplitSelection {
        candidate,
        pane_ids,
    })
}

#[derive(Deserialize)]
struct SplitEnvelope {
    result: SplitResult,
}

#[derive(Deserialize)]
struct SplitResult {
    pane: SplitPane,
}

#[derive(Deserialize)]
struct SplitPane {
    pane_id: String,
}

fn parse_split_pane_id(stdout: &[u8]) -> io::Result<String> {
    let pane_id = serde_json::from_slice::<SplitEnvelope>(stdout)
        .map_err(io::Error::other)?
        .result
        .pane
        .pane_id;
    if bounded_control_free(&pane_id, MAX_OPAQUE_ID_BYTES) {
        Ok(pane_id)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid pane ID",
        ))
    }
}
