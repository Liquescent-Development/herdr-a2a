use std::{
    ffi::OsString,
    fmt, io,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use async_trait::async_trait;
use herdr_a2a_core::{DomainError, RoleLabel, VerifiedPane};
use serde::Deserialize;

use crate::canonical_slug;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandOutput {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[async_trait]
pub trait HerdrCommandRunner: Send + Sync {
    async fn run(&self, program: &Path, args: &[OsString]) -> io::Result<CommandOutput>;

    async fn run_with_timeout(
        &self,
        program: &Path,
        args: &[OsString],
        timeout: Duration,
    ) -> io::Result<CommandOutput> {
        tokio::time::timeout(timeout, self.run(program, args))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "Herdr command deadline expired")
            })?
    }
}

#[derive(Debug)]
pub enum HerdrVerificationError {
    Command(io::Error),
    CommandFailed,
    MalformedResponse(serde_json::Error),
    InvalidName(DomainError),
    PaneMismatch,
    UnsupportedHarness,
    UnsafeWorkspace,
}

impl fmt::Display for HerdrVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Command(error) => write!(formatter, "Herdr verification command failed: {error}"),
            Self::CommandFailed => formatter.write_str("Herdr rejected the agent lookup"),
            Self::MalformedResponse(error) => {
                write!(formatter, "Herdr returned an invalid agent record: {error}")
            }
            Self::InvalidName(_) => formatter.write_str("Herdr agent has no valid explicit name"),
            Self::PaneMismatch => formatter.write_str("Herdr returned a different pane"),
            Self::UnsupportedHarness => formatter.write_str("Herdr agent is not a Pi agent"),
            Self::UnsafeWorkspace => formatter.write_str("Herdr returned an unsafe workspace"),
        }
    }
}

impl std::error::Error for HerdrVerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Command(error) => Some(error),
            Self::MalformedResponse(error) => Some(error),
            Self::InvalidName(error) => Some(error),
            _ => None,
        }
    }
}

#[async_trait]
pub trait HerdrVerifier: Send + Sync {
    async fn verify(&self, pane_id: &str) -> Result<VerifiedPane, HerdrVerificationError>;
}

pub struct CommandHerdrVerifier<R> {
    executable: PathBuf,
    runner: R,
}

impl<R> CommandHerdrVerifier<R> {
    pub fn new(executable: impl Into<PathBuf>, runner: R) -> Self {
        Self {
            executable: executable.into(),
            runner,
        }
    }
}

#[derive(Deserialize)]
struct HerdrEnvelope {
    result: HerdrResult,
}

#[derive(Deserialize)]
struct HerdrResult {
    agent: HerdrAgentRecord,
}

#[derive(Deserialize)]
struct HerdrAgentRecord {
    pane_id: String,
    name: Option<String>,
    agent: String,
    workspace_id: String,
    cwd: String,
}

#[async_trait]
impl<R> HerdrVerifier for CommandHerdrVerifier<R>
where
    R: HerdrCommandRunner,
{
    async fn verify(&self, pane_id: &str) -> Result<VerifiedPane, HerdrVerificationError> {
        let args = [
            OsString::from("agent"),
            OsString::from("get"),
            OsString::from(pane_id),
        ];
        let output = self
            .runner
            .run(&self.executable, &args)
            .await
            .map_err(HerdrVerificationError::Command)?;
        if !output.success {
            return Err(HerdrVerificationError::CommandFailed);
        }

        let envelope: HerdrEnvelope = serde_json::from_slice(&output.stdout)
            .map_err(HerdrVerificationError::MalformedResponse)?;
        let record = envelope.result.agent;
        if record.pane_id != pane_id {
            return Err(HerdrVerificationError::PaneMismatch);
        }
        if record.agent != "pi" {
            return Err(HerdrVerificationError::UnsupportedHarness);
        }
        let role = match record.name.as_deref() {
            None | Some("") => RoleLabel::parse("agent"),
            Some(name) => RoleLabel::parse(name).and_then(|role| {
                if canonical_slug(Some(role.as_str())) == "agent" {
                    RoleLabel::parse("agent")
                } else {
                    Ok(role)
                }
            }),
        }
        .map_err(HerdrVerificationError::InvalidName)?;
        if record.workspace_id.is_empty()
            || record.workspace_id.len() > 256
            || record.workspace_id.chars().any(char::is_control)
        {
            return Err(HerdrVerificationError::UnsafeWorkspace);
        }
        if !safe_workspace(&record.cwd) {
            return Err(HerdrVerificationError::UnsafeWorkspace);
        }
        let workspace = PathBuf::from(record.cwd);

        Ok(VerifiedPane {
            pane_id: record.pane_id,
            workspace_id: record.workspace_id,
            role,
            harness: record.agent,
            workspace_path: workspace,
        })
    }
}

fn safe_workspace(raw_path: &str) -> bool {
    let path = Path::new(raw_path);
    path.is_absolute()
        && path != Path::new("/")
        && !path.as_os_str().as_encoded_bytes().contains(&0)
        && !raw_path
            .as_bytes()
            .split(|byte| *byte == b'/')
            .any(|component| matches!(component, b"." | b".."))
        && path
            .components()
            .all(|component| !matches!(component, Component::CurDir | Component::ParentDir))
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, io, path::Path, sync::Arc};

    use async_trait::async_trait;
    use serde_json::{Value, json};

    use super::{CommandHerdrVerifier, CommandOutput, HerdrCommandRunner, HerdrVerifier};

    #[derive(Clone)]
    struct FakeRunner {
        expected_program: Arc<OsString>,
        expected_args: Arc<Vec<OsString>>,
        output: CommandOutput,
    }

    impl FakeRunner {
        fn returning(pane_id: &str, value: Value) -> Self {
            Self {
                expected_program: Arc::new(OsString::from("herdr")),
                expected_args: Arc::new(vec![
                    OsString::from("agent"),
                    OsString::from("get"),
                    OsString::from(pane_id),
                ]),
                output: CommandOutput {
                    success: true,
                    stdout: value.to_string().into_bytes(),
                    stderr: Vec::new(),
                },
            }
        }

        fn returning_bytes(pane_id: &str, stdout: &[u8]) -> Self {
            let mut runner = Self::returning(pane_id, Value::Null);
            runner.output.stdout = stdout.to_vec();
            runner
        }
    }

    #[async_trait]
    impl HerdrCommandRunner for FakeRunner {
        async fn run(&self, program: &Path, args: &[OsString]) -> io::Result<CommandOutput> {
            if program.as_os_str() != self.expected_program.as_ref().as_os_str()
                || args != self.expected_args.as_slice()
            {
                return Err(io::Error::other(format!(
                    "unexpected command: {:?} {:?}",
                    program, args
                )));
            }
            Ok(self.output.clone())
        }
    }

    fn agent(pane_id: &str, name: Value, harness: &str, workspace: &str) -> Value {
        json!({
            "result": {
                "agent": {
                    "pane_id": pane_id,
                    "name": name,
                    "agent": harness,
                    "workspace_id": "w1",
                    "cwd": workspace
                }
            }
        })
    }

    #[tokio::test]
    async fn identity_verifier_returns_role_workspace_and_matching_pane() {
        let runner =
            FakeRunner::returning("w1:p2", agent("w1:p2", json!("reviewer"), "pi", "/repo"));

        let verified = CommandHerdrVerifier::new("herdr", runner)
            .verify("w1:p2")
            .await
            .unwrap();

        assert_eq!(verified.role.as_str(), "reviewer");
        assert_eq!(verified.pane_id, "w1:p2");
        assert_eq!(verified.harness, "pi");
        assert_eq!(verified.workspace_id, "w1");
        assert_eq!(verified.workspace_path, Path::new("/repo"));
    }

    #[tokio::test]
    async fn pane_ids_are_passed_to_agent_get_without_interpretation() {
        let pane_id = "opaque::pane#1";
        let runner =
            FakeRunner::returning(pane_id, agent(pane_id, json!("reviewer"), "pi", "/repo"));

        let verified = CommandHerdrVerifier::new("herdr", runner)
            .verify(pane_id)
            .await
            .unwrap();

        assert_eq!(verified.pane_id, pane_id);
    }

    #[tokio::test]
    async fn verifier_accepts_additive_herdr_json_fields() {
        let runner = FakeRunner::returning(
            "p1",
            json!({
                "protocol_version": 8,
                "result": {
                    "request_id": "opaque-request",
                    "agent": {
                        "pane_id": "p1",
                        "name": "reviewer",
                        "agent": "pi",
                        "workspace_id": "w1",
                        "cwd": "/repo",
                        "future_field": {"nested": true}
                    }
                }
            }),
        );

        let verified = CommandHerdrVerifier::new("herdr", runner)
            .verify("p1")
            .await
            .unwrap();

        assert_eq!(verified.role.as_str(), "reviewer");
        assert_eq!(verified.workspace_id, "w1");
        assert_eq!(verified.workspace_path, Path::new("/repo"));
    }

    #[tokio::test]
    async fn verifier_rejects_obsolete_workspace_cwd_without_cwd() {
        let runner = FakeRunner::returning(
            "p1",
            json!({
                "result": {
                    "agent": {
                        "pane_id": "p1",
                        "name": "reviewer",
                        "agent": "pi",
                        "workspace_id": "w1",
                        "workspace_cwd": "/repo"
                    }
                }
            }),
        );

        assert!(
            CommandHerdrVerifier::new("herdr", runner)
                .verify("p1")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn identity_verifier_defaults_missing_null_and_unusable_names() {
        // Break caught: enrollment fails instead of assigning the safe `agent` display fallback.
        let fixtures = [
            json!({
                "result": {"agent": {
                    "pane_id": "p1", "agent": "pi", "workspace_id": "w1", "cwd": "/repo"
                }}
            }),
            agent("p1", Value::Null, "pi", "/repo"),
            agent("p1", json!(""), "pi", "/repo"),
            agent("p1", json!("---"), "pi", "/repo"),
        ];

        for fixture in fixtures {
            let verified = CommandHerdrVerifier::new("herdr", FakeRunner::returning("p1", fixture))
                .verify("p1")
                .await
                .unwrap();
            assert_eq!(verified.role.as_str(), "agent");
        }
    }

    #[tokio::test]
    async fn identity_verifier_preserves_unicode_role_and_rejects_controls_or_oversize() {
        // Break caught: unsafe or unbounded Herdr display labels enter directory responses.
        let unicode = CommandHerdrVerifier::new(
            "herdr",
            FakeRunner::returning("p1", agent("p1", json!("Réviewer"), "pi", "/repo")),
        )
        .verify("p1")
        .await
        .unwrap();
        assert_eq!(unicode.role.as_str(), "Réviewer");

        for name in ["reviewer\nadmin".to_owned(), "é".repeat(129)] {
            let result = CommandHerdrVerifier::new(
                "herdr",
                FakeRunner::returning("p1", agent("p1", json!(name), "pi", "/repo")),
            )
            .verify("p1")
            .await;
            assert!(result.is_err());
        }
    }

    #[tokio::test]
    async fn identity_verifier_requires_workspace_id() {
        // Break caught: a pane without authenticated workspace membership is enrolled.
        let fixture = json!({
            "result": {"agent": {
                "pane_id": "p1", "name": "reviewer", "agent": "pi", "cwd": "/repo"
            }}
        });
        assert!(
            CommandHerdrVerifier::new("herdr", FakeRunner::returning("p1", fixture))
                .verify("p1")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn verifier_rejects_a_different_reported_pane() {
        let runner =
            FakeRunner::returning("pane-a", agent("pane-b", json!("reviewer"), "pi", "/repo"));

        assert!(
            CommandHerdrVerifier::new("herdr", runner)
                .verify("pane-a")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn verifier_accepts_only_the_pi_harness() {
        for harness in ["claude", "codex", "", "PI"] {
            let runner =
                FakeRunner::returning("p1", agent("p1", json!("reviewer"), harness, "/repo"));
            assert!(
                CommandHerdrVerifier::new("herdr", runner)
                    .verify("p1")
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn verifier_rejects_malformed_json_and_failed_commands() {
        let malformed = FakeRunner::returning_bytes("p1", b"not json");
        assert!(
            CommandHerdrVerifier::new("herdr", malformed)
                .verify("p1")
                .await
                .is_err()
        );

        let mut failed = FakeRunner::returning("p1", agent("p1", json!("reviewer"), "pi", "/repo"));
        failed.output.success = false;
        failed.output.stderr = b"agent not found".to_vec();
        assert!(
            CommandHerdrVerifier::new("herdr", failed)
                .verify("p1")
                .await
                .is_err()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn verifier_rejects_workspace_values_that_could_escape_scope() {
        for workspace in [
            "",
            "repo",
            "/",
            "/repo/../etc",
            "/repo/./docs",
            "/repo\0docs",
        ] {
            let runner =
                FakeRunner::returning("p1", agent("p1", json!("reviewer"), "pi", workspace));
            assert!(
                CommandHerdrVerifier::new("herdr", runner)
                    .verify("p1")
                    .await
                    .is_err(),
                "unsafe workspace was accepted: {workspace:?}"
            );
        }
    }
}
