#[path = "../src/team.rs"]
mod team;

use std::{
    collections::{HashMap, VecDeque},
    ffi::OsString,
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use herdr_a2a_broker::herdr::{CommandOutput, HerdrCommandRunner};
use herdr_a2a_core::AgentName;
use team::{
    AgentRegistrationWaiter, RegisteredTeamAgent, TeamMemberState, TeamOrchestrator, TeamRequest,
};

#[derive(Clone)]
struct FakeRunner {
    calls: Arc<Mutex<Vec<Vec<OsString>>>>,
    outputs: Arc<Mutex<VecDeque<io::Result<CommandOutput>>>>,
    delays: Arc<Mutex<VecDeque<Duration>>>,
}

impl FakeRunner {
    fn new(outputs: impl IntoIterator<Item = CommandOutput>) -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            outputs: Arc::new(Mutex::new(outputs.into_iter().map(Ok).collect())),
            delays: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    fn with_results(outputs: impl IntoIterator<Item = io::Result<CommandOutput>>) -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            outputs: Arc::new(Mutex::new(outputs.into_iter().collect())),
            delays: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    fn with_delays(
        outputs: impl IntoIterator<Item = CommandOutput>,
        delays: impl IntoIterator<Item = Duration>,
    ) -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            outputs: Arc::new(Mutex::new(outputs.into_iter().map(Ok).collect())),
            delays: Arc::new(Mutex::new(delays.into_iter().collect())),
        }
    }

    fn calls(&self) -> Vec<Vec<OsString>> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl HerdrCommandRunner for FakeRunner {
    async fn run(&self, _program: &Path, args: &[OsString]) -> io::Result<CommandOutput> {
        self.calls.lock().unwrap().push(args.to_vec());
        let delay = self.delays.lock().unwrap().pop_front().unwrap_or_default();
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        self.outputs
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| io::Error::other("unexpected Herdr call"))?
    }
}

#[derive(Clone, Default)]
struct PermanentlyBusyRunner {
    calls: Arc<Mutex<Vec<Vec<OsString>>>>,
}

#[async_trait]
impl HerdrCommandRunner for PermanentlyBusyRunner {
    async fn run(&self, _program: &Path, args: &[OsString]) -> io::Result<CommandOutput> {
        self.calls.lock().unwrap().push(args.to_vec());
        let words = args
            .iter()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>();
        match words.as_slice() {
            [pane, layout_arg, ..] if pane == "pane" && layout_arg == "layout" => {
                Ok(layout(&[("opaque-caller", 120, 40)]))
            }
            [pane, split_arg, ..] if pane == "pane" && split_arg == "split" => {
                Ok(split("opaque-worker"))
            }
            [pane, rename, ..] if pane == "pane" && rename == "rename" => {
                Ok(success(serde_json::json!({"result": {}})))
            }
            [pane, process_info_arg, ..]
                if pane == "pane" && process_info_arg == "process-info" =>
            {
                Ok(process_info("opaque-worker", 43_001))
            }
            [agent, start, ..] if agent == "agent" && start == "start" => Ok(agent_pane_busy()),
            _ => Err(io::Error::other("unexpected Herdr call")),
        }
    }
}

#[derive(Clone, Default)]
struct FakeWaiter {
    calls: Arc<Mutex<Vec<Vec<String>>>>,
    agents: Arc<Mutex<HashMap<String, AgentName>>>,
}

impl FakeWaiter {
    fn with_agents(agents: impl IntoIterator<Item = (&'static str, &'static str)>) -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            agents: Arc::new(Mutex::new(
                agents
                    .into_iter()
                    .map(|(pane, name)| (pane.to_owned(), AgentName::parse(name).unwrap()))
                    .collect(),
            )),
        }
    }
}

#[async_trait]
impl AgentRegistrationWaiter for FakeWaiter {
    async fn wait_for_agents(
        &self,
        pane_ids: &[String],
        _timeout: Duration,
    ) -> io::Result<Vec<RegisteredTeamAgent>> {
        self.calls.lock().unwrap().push(pane_ids.to_vec());
        let agents = self.agents.lock().unwrap();
        Ok(pane_ids
            .iter()
            .filter_map(|pane_id| {
                agents
                    .get(pane_id)
                    .cloned()
                    .map(|canonical_name| RegisteredTeamAgent {
                        pane_id: pane_id.clone(),
                        canonical_name,
                    })
            })
            .collect())
    }
}

fn success(value: serde_json::Value) -> CommandOutput {
    CommandOutput {
        success: true,
        stdout: serde_json::to_vec(&value).unwrap(),
        stderr: Vec::new(),
    }
}

fn failure() -> CommandOutput {
    CommandOutput {
        success: false,
        stdout: Vec::new(),
        stderr: b"bounded failure".to_vec(),
    }
}

fn agent_pane_busy() -> CommandOutput {
    CommandOutput {
        success: false,
        stdout: Vec::new(),
        stderr: serde_json::to_vec(&serde_json::json!({
            "error": {
                "code": "agent_pane_busy",
                "message": "agent target pane opaque-worker is not an available shell"
            },
            "id": "cli:agent:start"
        }))
        .unwrap(),
    }
}

fn layout(panes: &[(&str, u64, u64)]) -> CommandOutput {
    success(serde_json::json!({
        "result": {"layout": {
            "workspace_id": "w1",
            "focused_pane_id": "opaque-caller",
            "panes": panes.iter().map(|(pane_id, width, height)| serde_json::json!({
                "pane_id": pane_id,
                "rect": {"width": width, "height": height, "x": 0, "y": 0}
            })).collect::<Vec<_>>()
        }}
    }))
}

fn split(pane_id: &str) -> CommandOutput {
    success(serde_json::json!({"result": {"pane": {"pane_id": pane_id}}}))
}

fn process_info(pane_id: &str, shell_pid: u32) -> CommandOutput {
    success(serde_json::json!({
        "result": {"process_info": {"pane_id": pane_id, "shell_pid": shell_pid}}
    }))
}

fn agent_info(pane_id: &str, agent: &str) -> CommandOutput {
    success(serde_json::json!({
        "result": {"agent": {"pane_id": pane_id, "agent": agent}}
    }))
}

fn request(self_role: Option<&str>, roles: &[&str]) -> TeamRequest {
    TeamRequest::new(
        "opaque-caller",
        "w1",
        PathBuf::from("/repo with spaces"),
        self_role.map(str::to_owned),
        roles.iter().map(|role| (*role).to_owned()).collect(),
    )
    .unwrap()
}

#[tokio::test]
async fn invalid_second_role_makes_zero_herdr_or_wait_calls() {
    // Break caught: moving validation into the creation loop creates the first pane before failure.
    let runner = FakeRunner::new([]);
    let waiter = FakeWaiter::default();
    let invalid = TeamRequest::new(
        "opaque-caller",
        "w1",
        PathBuf::from("/repo"),
        None,
        vec!["worker".to_owned(), "Reviewer".to_owned()],
    );

    if let Ok(request) = invalid {
        let _ = TeamOrchestrator::new(
            PathBuf::from("/absolute/herdr"),
            runner.clone(),
            waiter.clone(),
        )
        .create_team(request)
        .await;
    }
    assert!(runner.calls().is_empty());
    assert!(waiter.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn self_rename_and_each_opaque_pane_use_exact_bounded_argv() {
    // Break caught: a pane ID is predicted, focus is stolen, cwd is omitted, or terminal input is used.
    let runner = FakeRunner::new([
        success(serde_json::json!({"result": {}})),
        layout(&[("opaque-caller", 120, 40), ("opaque-existing", 70, 50)]),
        split("opaque::pane#1"),
        success(serde_json::json!({"result": {}})),
        process_info("opaque::pane#1", 41_001),
        success(serde_json::json!({"result": {}})),
        layout(&[("opaque-caller", 61, 40), ("opaque::pane#1", 60, 40)]),
        split("opaque::pane#2"),
        success(serde_json::json!({"result": {}})),
        process_info("opaque::pane#2", 41_002),
        success(serde_json::json!({"result": {}})),
    ]);
    let waiter = FakeWaiter::with_agents([
        ("opaque::pane#1", "worker-k7m2"),
        ("opaque::pane#2", "reviewer-r8c1"),
    ]);
    let orchestrator = TeamOrchestrator::new(
        PathBuf::from("/absolute/herdr"),
        runner.clone(),
        waiter.clone(),
    );

    let result = orchestrator
        .create_team(request(Some("coordinator"), &["worker", "reviewer"]))
        .await
        .unwrap();

    let observed_calls = runner.calls();
    assert_eq!(
        observed_calls,
        vec![
            vec!["agent", "rename", "opaque-caller", "coordinator"],
            vec!["pane", "layout", "--pane", "opaque-caller"],
            vec![
                "pane",
                "split",
                "opaque-caller",
                "--direction",
                "right",
                "--cwd",
                "/repo with spaces",
                "--no-focus"
            ],
            vec!["pane", "rename", "opaque::pane#1", "worker"],
            vec!["pane", "process-info", "--pane", "opaque::pane#1"],
            vec![
                "agent",
                "start",
                "worker",
                "--kind",
                "pi",
                "--pane",
                "opaque::pane#1",
                "--timeout",
                "TIMEOUT"
            ],
            vec!["pane", "layout", "--pane", "opaque-caller"],
            vec![
                "pane",
                "split",
                "opaque-caller",
                "--direction",
                "right",
                "--cwd",
                "/repo with spaces",
                "--no-focus"
            ],
            vec!["pane", "rename", "opaque::pane#2", "reviewer"],
            vec!["pane", "process-info", "--pane", "opaque::pane#2"],
            vec![
                "agent",
                "start",
                "reviewer",
                "--kind",
                "pi",
                "--pane",
                "opaque::pane#2",
                "--timeout",
                "TIMEOUT"
            ],
        ]
        .into_iter()
        .map(|args| args.into_iter().map(OsString::from).collect::<Vec<_>>())
        .collect::<Vec<_>>()
        .into_iter()
        .enumerate()
        .map(|(index, mut args)| {
            if args.last().is_some_and(|arg| arg == "TIMEOUT") {
                let observed = observed_calls[index].last().unwrap().to_string_lossy();
                let millis = observed.parse::<u64>().expect("timeout must be numeric");
                assert_eq!(millis, 15_000);
                *args.last_mut().unwrap() = OsString::from(observed.as_ref());
            }
            args
        })
        .collect::<Vec<_>>()
    );
    assert_eq!(
        waiter.calls.lock().unwrap().as_slice(),
        &[vec![
            "opaque::pane#1".to_owned(),
            "opaque::pane#2".to_owned(),
        ]]
    );
    assert_eq!(result.members.len(), 2);
    assert_eq!(result.members[0].state, TeamMemberState::Registered);
    assert_eq!(
        result.members[0].canonical_name.as_ref().unwrap().as_str(),
        "worker-k7m2"
    );
    assert_eq!(
        result.members[1].canonical_name.as_ref().unwrap().as_str(),
        "reviewer-r8c1"
    );
    let advertised = runner
        .calls()
        .iter()
        .flatten()
        .map(|arg| arg.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(!advertised.contains("send-text"));
    assert!(!advertised.contains("send-keys"));
    assert!(!advertised.contains("prompt"));
}

#[tokio::test]
async fn partial_failure_reports_success_without_replacement_creation() {
    // Break caught: a failed second member discards the first or retries by opening a replacement.
    let runner = FakeRunner::new([
        layout(&[("opaque-caller", 40, 100)]),
        split("opaque-worker"),
        success(serde_json::json!({"result": {}})),
        process_info("opaque-worker", 42_001),
        success(serde_json::json!({"result": {}})),
        layout(&[("opaque-caller", 40, 50), ("opaque-worker", 40, 50)]),
        failure(),
    ]);
    let waiter = FakeWaiter::with_agents([("opaque-worker", "worker-k7m2")]);
    let orchestrator =
        TeamOrchestrator::new(PathBuf::from("/absolute/herdr"), runner.clone(), waiter);

    let result = orchestrator
        .create_team(request(None, &["worker", "reviewer", "observer"]))
        .await
        .unwrap();

    assert_eq!(runner.calls().len(), 7);
    assert_eq!(result.members.len(), 3);
    assert_eq!(result.members[0].state, TeamMemberState::Registered);
    assert_eq!(result.members[1].state, TeamMemberState::Failed);
    assert_eq!(result.members[1].pane_id, None);
    assert_eq!(
        result.members[1].error_code.as_deref(),
        Some("pane_split_failed")
    );
    assert_eq!(result.members[2].requested_role.as_str(), "observer");
    assert_eq!(result.members[2].state, TeamMemberState::Failed);
    assert_eq!(
        result.members[2].error_code.as_deref(),
        Some("not_attempted_after_failure")
    );
}

#[tokio::test]
async fn self_rename_failure_accounts_all_roles_without_teammate_creation() {
    // Break caught: a failed self rename escapes as a session error and hides requested roles.
    let runner = FakeRunner::new([failure()]);
    let waiter = FakeWaiter::default();
    let orchestrator = TeamOrchestrator::new(
        PathBuf::from("/absolute/herdr"),
        runner.clone(),
        waiter.clone(),
    );

    let result = orchestrator
        .create_team(request(Some("coordinator"), &["worker", "reviewer"]))
        .await
        .unwrap();

    assert_eq!(
        runner.calls(),
        vec![vec![
            OsString::from("agent"),
            OsString::from("rename"),
            OsString::from("opaque-caller"),
            OsString::from("coordinator"),
        ]]
    );
    assert!(waiter.calls.lock().unwrap().is_empty());
    assert_eq!(result.members.len(), 2);
    for member in result.members {
        assert_eq!(member.state, TeamMemberState::Failed);
        assert_eq!(
            member.error_code.as_deref(),
            Some("not_attempted_after_self_rename_failure")
        );
    }
}

#[tokio::test]
async fn shell_readiness_is_observed_before_one_exact_agent_start() {
    // Break caught: pane split completed before its shell was interactive, and retrying the
    // mutating agent-start command after failure could duplicate an ambiguously started Pi.
    let runner = FakeRunner::new([
        layout(&[("opaque-caller", 120, 40)]),
        split("opaque-worker"),
        success(serde_json::json!({"result": {}})),
        process_info("opaque-worker", 0),
        process_info("opaque-worker", 43_001),
        success(serde_json::json!({"result": {}})),
    ]);
    let waiter = FakeWaiter::with_agents([("opaque-worker", "worker-k7m2")]);
    let orchestrator =
        TeamOrchestrator::new(PathBuf::from("/absolute/herdr"), runner.clone(), waiter);

    let result = orchestrator
        .create_team(request(None, &["worker"]))
        .await
        .unwrap();

    let calls = runner.calls();
    assert_eq!(
        calls
            .iter()
            .filter(|args| args.starts_with(&[OsString::from("agent"), OsString::from("start")]))
            .count(),
        1,
        "shell readiness replayed agent start"
    );
    assert_eq!(
        calls
            .iter()
            .filter(|args| {
                args.starts_with(&[OsString::from("pane"), OsString::from("process-info")])
            })
            .count(),
        2
    );
    assert_eq!(result.members[0].state, TeamMemberState::Registered);
    assert_eq!(result.members[0].pane_id.as_deref(), Some("opaque-worker"));
}

#[tokio::test(start_paused = true)]
async fn exact_agent_pane_busy_is_the_only_start_failure_that_may_be_retried() {
    // Break caught: a newly split pane has a shell PID before Herdr publishes it as an available
    // shell, so the first start is rejected before mutation and must be retried on the same pane.
    let runner = FakeRunner::new([
        layout(&[("opaque-caller", 120, 40)]),
        split("opaque-worker"),
        success(serde_json::json!({"result": {}})),
        process_info("opaque-worker", 43_001),
        agent_pane_busy(),
        agent_pane_busy(),
        success(serde_json::json!({"result": {}})),
    ]);
    let waiter = FakeWaiter::with_agents([("opaque-worker", "worker-k7m2")]);
    let orchestrator =
        TeamOrchestrator::new(PathBuf::from("/absolute/herdr"), runner.clone(), waiter);

    let result = orchestrator
        .create_team(request(None, &["worker"]))
        .await
        .unwrap();

    let calls = runner.calls();
    let starts = calls
        .iter()
        .filter(|args| args.starts_with(&[OsString::from("agent"), OsString::from("start")]))
        .collect::<Vec<_>>();
    assert_eq!(starts.len(), 3, "exact pre-mutation busy was not retried");
    assert!(starts.windows(2).all(|pair| pair[0] == pair[1]));
    assert_eq!(result.members[0].state, TeamMemberState::Registered);
}

#[tokio::test(start_paused = true)]
async fn permanent_agent_pane_busy_expires_inside_the_one_start_window() {
    // Break caught: retrying a proven pre-mutation rejection acquires a fresh timeout forever.
    let runner = PermanentlyBusyRunner::default();
    let waiter = FakeWaiter::default();
    let orchestrator =
        TeamOrchestrator::new(PathBuf::from("/absolute/herdr"), runner.clone(), waiter);
    let started = tokio::time::Instant::now();

    let result = orchestrator
        .create_team(request(None, &["worker"]))
        .await
        .unwrap();

    let calls = runner.calls.lock().unwrap();
    let start_count = calls
        .iter()
        .filter(|args| args.starts_with(&[OsString::from("agent"), OsString::from("start")]))
        .count();
    assert!(start_count > 2, "busy response was not retried");
    assert!(
        calls
            .iter()
            .all(|args| { !args.starts_with(&[OsString::from("agent"), OsString::from("get")]) })
    );
    assert!(started.elapsed() <= Duration::from_secs(30));
    assert_eq!(result.members[0].state, TeamMemberState::Failed);
}

#[tokio::test]
async fn agent_start_satisfies_herdr_timeout_floor_within_one_monotonic_window() {
    // Break caught: Herdr requires an agent-start timeout strictly greater than 3000ms, while the
    // A2A process runner must still enforce its independent bounded monotonic deadline.
    let runner = FakeRunner::new([
        layout(&[("opaque-caller", 120, 40)]),
        split("opaque-worker"),
        success(serde_json::json!({"result": {}})),
        process_info("opaque-worker", 43_001),
        success(serde_json::json!({"result": {}})),
    ]);
    let waiter = FakeWaiter::with_agents([("opaque-worker", "worker-k7m2")]);
    let orchestrator =
        TeamOrchestrator::new(PathBuf::from("/absolute/herdr"), runner.clone(), waiter);
    let started = std::time::Instant::now();

    let result = orchestrator
        .create_team(request(None, &["worker"]))
        .await
        .unwrap();

    let calls = runner.calls();
    let starts = calls
        .iter()
        .filter(|args| args.starts_with(&[OsString::from("agent"), OsString::from("start")]))
        .collect::<Vec<_>>();
    assert_eq!(starts.len(), 1, "agent start must remain non-replayed");
    let timeout_index = starts[0]
        .iter()
        .position(|value| value == "--timeout")
        .expect("agent start omitted its bounded Herdr timeout");
    let timeout_ms = starts[0][timeout_index + 1]
        .to_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert!(
        timeout_ms > 3_000,
        "Herdr rejects agent-start timeout {timeout_ms}; it must exceed 3000ms"
    );
    assert_eq!(timeout_ms, 15_000);
    assert!(
        started.elapsed() <= Duration::from_millis(3_500),
        "agent start exceeded its independent monotonic window"
    );
    assert_eq!(result.members[0].state, TeamMemberState::Registered);
}

#[tokio::test]
async fn lost_start_response_observes_the_exact_pane_without_replaying_start() {
    // Break caught: agent start mutated the pane but its response was lost, so replaying the
    // non-idempotent command could start a duplicate Pi process.
    let runner = FakeRunner::with_results([
        Ok(layout(&[("opaque-caller", 120, 40)])),
        Ok(split("opaque-worker")),
        Ok(success(serde_json::json!({"result": {}}))),
        Ok(process_info("opaque-worker", 44_001)),
        Err(io::Error::new(io::ErrorKind::TimedOut, "response lost")),
        Ok(agent_info("opaque-worker", "pi")),
    ]);
    let waiter = FakeWaiter::with_agents([("opaque-worker", "worker-k7m2")]);
    let orchestrator =
        TeamOrchestrator::new(PathBuf::from("/absolute/herdr"), runner.clone(), waiter);

    let result = orchestrator
        .create_team(request(None, &["worker"]))
        .await
        .unwrap();

    let calls = runner.calls();
    assert_eq!(
        calls
            .iter()
            .filter(|args| args.starts_with(&[OsString::from("agent"), OsString::from("start")]))
            .count(),
        1,
        "ambiguous success replayed a mutating agent start"
    );
    assert!(calls.iter().any(|args| {
        args == &[
            OsString::from("pane"),
            OsString::from("process-info"),
            OsString::from("--pane"),
            OsString::from("opaque-worker"),
        ]
    }));
    assert!(calls.iter().any(|args| {
        args == &[
            OsString::from("agent"),
            OsString::from("get"),
            OsString::from("opaque-worker"),
        ]
    }));
    assert_eq!(result.members[0].state, TeamMemberState::Registered);
}

#[tokio::test]
async fn slow_ambiguous_start_gets_a_generous_read_only_reconciliation_window() {
    // Break caught: a three-second global window expired at Herdr's minimum startup timeout, so a
    // Pi process that started successfully on a slower machine was reported failed without the
    // required exact-pane read-only reconciliation.
    let runner = FakeRunner::with_delays(
        [
            layout(&[("opaque-caller", 120, 40)]),
            split("opaque-worker"),
            success(serde_json::json!({"result": {}})),
            process_info("opaque-worker", 44_001),
            CommandOutput {
                success: false,
                stdout: Vec::new(),
                stderr: b"timed out waiting for agent startup".to_vec(),
            },
            agent_info("opaque-worker", "pi"),
        ],
        [
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
            Duration::from_secs(4),
            Duration::ZERO,
        ],
    );
    let waiter = FakeWaiter::with_agents([("opaque-worker", "worker-k7m2")]);
    let orchestrator =
        TeamOrchestrator::new(PathBuf::from("/absolute/herdr"), runner.clone(), waiter);

    let result = orchestrator
        .create_team(request(None, &["worker"]))
        .await
        .unwrap();

    let calls = runner.calls();
    assert_eq!(
        calls
            .iter()
            .filter(|args| args.starts_with(&[OsString::from("agent"), OsString::from("start")]))
            .count(),
        1,
        "slow ambiguous startup replayed the mutating command"
    );
    assert!(calls.iter().any(|args| {
        args == &[
            OsString::from("agent"),
            OsString::from("get"),
            OsString::from("opaque-worker"),
        ]
    }));
    assert_eq!(result.members[0].state, TeamMemberState::Registered);
}

#[tokio::test(start_paused = true)]
async fn shell_readiness_observation_respects_one_monotonic_start_window() {
    // Break caught: each Herdr command inherited a fresh 35-second process timeout, so a nominal
    // thirty-second readiness window could block for minutes before classifying failure.
    let runner = FakeRunner::with_delays(
        [
            layout(&[("opaque-caller", 120, 40)]),
            split("opaque-worker"),
            success(serde_json::json!({"result": {}})),
            process_info("opaque-worker", 44_001),
        ],
        [
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
            Duration::from_secs(31),
        ],
    );
    let waiter = FakeWaiter::default();
    let orchestrator =
        TeamOrchestrator::new(PathBuf::from("/absolute/herdr"), runner.clone(), waiter);
    let started = tokio::time::Instant::now();

    let result = orchestrator
        .create_team(request(None, &["worker"]))
        .await
        .unwrap();

    let elapsed = started.elapsed();
    assert!(
        (Duration::from_secs(30)..=Duration::from_secs(31)).contains(&elapsed),
        "readiness observation escaped its one monotonic window: {elapsed:?}"
    );
    assert_eq!(
        runner
            .calls()
            .iter()
            .filter(|args| args.starts_with(&[OsString::from("agent"), OsString::from("start")]))
            .count(),
        0,
        "agent start ran without a bounded shell-readiness proof"
    );
    assert_eq!(result.members[0].state, TeamMemberState::Failed);
}

#[tokio::test]
async fn split_must_return_a_new_opaque_pane_before_rename_or_start() {
    // Break caught: caller, candidate, or another pre-split pane is mutated as the new teammate.
    for returned in ["opaque-caller", "opaque-candidate", "opaque-existing"] {
        let runner = FakeRunner::new([
            layout(&[
                ("opaque-caller", 40, 40),
                ("opaque-candidate", 120, 40),
                ("opaque-existing", 30, 30),
            ]),
            split(returned),
        ]);
        let waiter = FakeWaiter::default();
        let orchestrator = TeamOrchestrator::new(
            PathBuf::from("/absolute/herdr"),
            runner.clone(),
            waiter.clone(),
        );

        let result = orchestrator
            .create_team(request(None, &["worker", "reviewer"]))
            .await
            .unwrap();

        assert_eq!(runner.calls().len(), 2, "returned ID: {returned}");
        assert!(waiter.calls.lock().unwrap().is_empty());
        assert_eq!(result.members[0].state, TeamMemberState::Failed);
        assert_eq!(
            result.members[0].error_code.as_deref(),
            Some("pane_split_not_new")
        );
        assert_eq!(
            result.members[1].error_code.as_deref(),
            Some("not_attempted_after_failure")
        );
    }
}

#[tokio::test]
async fn repeated_created_pane_id_stops_before_second_rename_or_start() {
    // Break caught: a later split reuses a prior created pane and mutates it for another role.
    let runner = FakeRunner::new([
        layout(&[("opaque-caller", 120, 40)]),
        split("opaque-worker"),
        success(serde_json::json!({"result": {}})),
        process_info("opaque-worker", 45_001),
        success(serde_json::json!({"result": {}})),
        layout(&[("opaque-caller", 60, 40), ("opaque-worker", 60, 40)]),
        split("opaque-worker"),
    ]);
    let waiter = FakeWaiter::with_agents([("opaque-worker", "worker-k7m2")]);
    let orchestrator = TeamOrchestrator::new(
        PathBuf::from("/absolute/herdr"),
        runner.clone(),
        waiter.clone(),
    );

    let result = orchestrator
        .create_team(request(None, &["worker", "reviewer"]))
        .await
        .unwrap();

    assert_eq!(runner.calls().len(), 7);
    assert_eq!(result.members[0].state, TeamMemberState::Registered);
    assert_eq!(result.members[1].state, TeamMemberState::Failed);
    assert_eq!(
        result.members[1].error_code.as_deref(),
        Some("pane_split_not_new")
    );
}
