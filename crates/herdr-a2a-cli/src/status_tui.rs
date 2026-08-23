use std::{
    fmt::Write as _,
    io::{self, Write},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use crossterm::{
    cursor::{Hide, Show},
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{
        Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode,
        enable_raw_mode,
    },
};

use crate::{doctor::DoctorReport, status::WorkspaceStatus};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TuiView {
    Status,
    Doctor,
    Logs,
    RestartConfirmation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TuiCommand {
    None,
    RunDoctor,
    ShowLogs,
    ConfirmRestart,
    RestartBroker,
    Quit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TuiState {
    pub status: WorkspaceStatus,
    pub view: TuiView,
    pub quit: bool,
    details: Vec<String>,
}

impl TuiState {
    pub fn new(status: WorkspaceStatus) -> Self {
        Self {
            status,
            view: TuiView::Status,
            quit: false,
            details: Vec::new(),
        }
    }

    pub fn handle_key(&mut self, key: char) -> TuiCommand {
        match key {
            'd' => {
                self.view = TuiView::Doctor;
                TuiCommand::RunDoctor
            }
            'l' => {
                self.view = TuiView::Logs;
                TuiCommand::ShowLogs
            }
            'r' if self.view == TuiView::RestartConfirmation => TuiCommand::RestartBroker,
            'r' => {
                self.view = TuiView::RestartConfirmation;
                TuiCommand::ConfirmRestart
            }
            'q' => {
                self.quit = true;
                TuiCommand::Quit
            }
            _ => TuiCommand::None,
        }
    }

    fn show_lines(&mut self, view: TuiView, lines: Vec<String>) {
        self.view = view;
        self.details = lines
            .into_iter()
            .take(100)
            .map(|line| sanitize_line(&line))
            .collect();
    }

    pub fn show_logs(&mut self, lines: Vec<String>) {
        self.view = TuiView::Logs;
        self.details = lines
            .into_iter()
            .take(100)
            .map(|_| "[redacted operational log line]".to_owned())
            .collect();
        if self.details.is_empty() {
            self.details
                .push("No plugin log entries are available.".to_owned());
        }
    }
}

pub fn render(state: &TuiState) -> String {
    let mut output = String::new();
    let _ = writeln!(
        output,
        "Herdr A2A · workspace: {}",
        state.status.workspace_id
    );
    let _ = writeln!(output, "Broker     ● {}", state.status.broker);
    let _ = writeln!(output, "Storage    ● {}", state.status.storage);
    output.push_str("\nAgents\n");
    if state.status.agents.is_empty() {
        output.push_str("none connected\n");
    } else {
        for agent in &state.status.agents {
            let _ = writeln!(
                output,
                "{} · {} · {}",
                agent.role.as_str(),
                agent.canonical_name.as_str(),
                agent.status
            );
        }
    }
    let _ = writeln!(
        output,
        "\nTasks\nqueued {} · leased {} · waiting reply {} · terminal {}",
        state.status.tasks.queued,
        state.status.tasks.leased,
        state.status.tasks.waiting_reply,
        state.status.tasks.terminal
    );
    output.push_str("\nLast event\n");
    match &state.status.last_event {
        Some(event) => {
            let _ = writeln!(
                output,
                "{} {} · {}",
                event.canonical_name.as_str(),
                event.kind,
                event.unix_time
            );
        }
        None => output.push_str("none\n"),
    }
    match state.view {
        TuiView::Doctor | TuiView::Logs => {
            output.push('\n');
            for line in &state.details {
                let _ = writeln!(output, "{line}");
            }
        }
        TuiView::RestartConfirmation => {
            output.push_str("\nPress [r] again to restart the proved workspace broker.\n");
        }
        TuiView::Status => {}
    }
    output.push_str("\n[d] Doctor  [l] Logs  [r] Restart broker  [q] Close");
    output
}

fn sanitize_line(line: &str) -> String {
    let lowered = line.to_ascii_lowercase();
    if [
        "bearer",
        "token",
        "payload",
        "message",
        "descriptor",
        "task_id",
        "task-",
    ]
    .iter()
    .any(|needle| lowered.contains(needle))
    {
        return "[redacted operational log line]".to_owned();
    }
    line.chars()
        .filter(|character| !character.is_control() || *character == '\t')
        .take(512)
        .collect()
}

#[async_trait]
pub trait TuiBackend {
    async fn status(&self) -> Result<WorkspaceStatus, String>;
    async fn doctor(&self) -> DoctorReport;
    async fn restart(&self) -> Result<WorkspaceStatus, String>;
    async fn logs(&self) -> Vec<String>;
}

struct TerminalGuard {
    raw: bool,
    alternate: bool,
    hidden: bool,
}

impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut guard = Self {
            raw: true,
            alternate: false,
            hidden: false,
        };
        execute!(io::stdout(), EnterAlternateScreen)?;
        guard.alternate = true;
        execute!(io::stdout(), Hide)?;
        guard.hidden = true;
        Ok(guard)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if self.hidden {
            let _ = execute!(io::stdout(), Show);
        }
        if self.alternate {
            let _ = execute!(io::stdout(), LeaveAlternateScreen);
        }
        if self.raw {
            let _ = disable_raw_mode();
        }
    }
}

pub async fn dispatch_key_event(
    state: &mut TuiState,
    key: KeyEvent,
    backend: &dyn TuiBackend,
) -> bool {
    if key.kind != KeyEventKind::Press || key.modifiers != KeyModifiers::NONE {
        return false;
    }
    let KeyCode::Char(character) = key.code else {
        return false;
    };
    match state.handle_key(character) {
        TuiCommand::RunDoctor => {
            let report = backend.doctor().await;
            state.show_lines(
                TuiView::Doctor,
                report
                    .checks
                    .into_iter()
                    .map(|check| format!("{} · {}", check.code, check.summary))
                    .collect(),
            );
        }
        TuiCommand::ShowLogs => state.show_logs(backend.logs().await),
        TuiCommand::RestartBroker => match backend.restart().await {
            Ok(status) => *state = TuiState::new(status),
            Err(_) => state.show_lines(
                TuiView::Status,
                vec!["Broker restart failed closed.".to_owned()],
            ),
        },
        TuiCommand::Quit => return true,
        TuiCommand::None | TuiCommand::ConfirmRestart => {}
    }
    false
}

pub async fn run(backend: &dyn TuiBackend) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let status = backend
        .status()
        .await
        .map_err(|_| io::Error::other("redacted workspace status is unavailable"))?;
    let _guard = TerminalGuard::enter()?;
    let mut state = TuiState::new(status);
    let mut last_refresh = Instant::now();
    loop {
        execute!(
            io::stdout(),
            Clear(ClearType::All),
            crossterm::cursor::MoveTo(0, 0)
        )?;
        print!("{}", render(&state));
        io::stdout().flush()?;
        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
            && dispatch_key_event(&mut state, key, backend).await
        {
            break;
        }
        if last_refresh.elapsed() >= Duration::from_secs(1) {
            if let Ok(status) = backend.status().await {
                state.status = status;
            }
            last_refresh = Instant::now();
        }
        if state.quit {
            break;
        }
    }
    Ok(())
}
