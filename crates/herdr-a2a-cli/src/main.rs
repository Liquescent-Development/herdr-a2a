#[cfg(all(feature = "test-harness", not(debug_assertions)))]
compile_error!("the test-harness feature is forbidden in release builds");

mod coordinator;
mod doctor;
mod health;
mod managed;
mod recovery;
mod session;
mod status;
mod status_tui;
mod team;

use std::{
    env,
    ffi::{OsStr, OsString},
    fs::{self, File},
    future::{Future, IntoFuture},
    io::{self, Read},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::fd::FromRawFd;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand};
#[cfg(not(test))]
use herdr_a2a_broker::runtime::remove_descriptor_if_instance;
#[cfg(test)]
use herdr_a2a_broker::runtime::{
    remove_descriptor_if_instance_with_observed_hook, write_descriptor_with_post_rename_hook,
};
use herdr_a2a_broker::server::recover_broker_state;
use herdr_a2a_broker::{
    ApiState, CommandHerdrVerifier, HerdrVerifier, RuntimeDescriptor, RuntimePaths, SessionLock,
    SqliteTaskStore,
    herdr::{CommandOutput, HerdrCommandRunner},
    server_router, write_descriptor,
};
use herdr_a2a_core::SystemClock;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    net::TcpListener,
    process::Command,
    sync::Semaphore,
};

type DynError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Parser)]
#[command(name = "herdr-a2a", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Broker,
    Doctor {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        repair: bool,
    },
    Status {
        #[arg(long)]
        json: bool,
    },
    StatusTui,
    Restart,
    #[command(hide = true)]
    Coordinator {
        #[command(subcommand)]
        command: CoordinatorCommands,
    },
    Managed {
        #[command(subcommand)]
        command: ManagedCommands,
    },
    ClientSession {
        #[arg(long)]
        harness_session_id: String,
    },
}

#[derive(Subcommand)]
enum ManagedCommands {
    Install {
        #[arg(long)]
        bundle: PathBuf,
    },
    Repair {
        #[arg(long, conflicts_with = "event")]
        startup: bool,
        #[arg(long, conflicts_with = "startup")]
        event: bool,
    },
    Status {
        #[arg(long)]
        json: bool,
    },
    Remove {
        #[arg(long)]
        purge: bool,
        #[arg(long)]
        skip_herdr_unregister: bool,
    },
    #[command(hide = true)]
    ExtractRelease {
        #[arg(long)]
        archive: PathBuf,
        #[arg(long)]
        destination: PathBuf,
    },
    #[command(hide = true)]
    ValidatePluginRoot {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        managed_install: bool,
    },
}

#[derive(Subcommand)]
enum CoordinatorCommands {
    Serve,
    Ensure,
    Stop,
    Restart,
    #[command(hide = true)]
    DispatchExec {
        #[arg(long)]
        pointer: Option<PathBuf>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
    },
}

const VERIFIER_CONCURRENCY: usize = 8;
const VERIFIER_TIMEOUT: Duration = Duration::from_secs(2);
const VERIFIER_OUTPUT_BYTES: usize = 64 * 1024;
const BROKER_SHUTDOWN_DRAIN: Duration = Duration::from_millis(2_500);

#[derive(Clone)]
struct ProcessRunner {
    permits: Arc<Semaphore>,
    timeout: Duration,
    max_output_bytes: usize,
}

impl ProcessRunner {
    fn production() -> Self {
        Self::with_limits(
            VERIFIER_CONCURRENCY,
            VERIFIER_TIMEOUT,
            VERIFIER_OUTPUT_BYTES,
        )
    }

    fn with_limits(concurrency: usize, timeout: Duration, max_output_bytes: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(concurrency)),
            timeout,
            max_output_bytes,
        }
    }

    async fn run_with_process_timeout(
        &self,
        program: &Path,
        args: &[OsString],
        timeout: Duration,
    ) -> io::Result<CommandOutput> {
        let permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| io::Error::other("verifier runner stopped"))?;
        let program = program.to_owned();
        let args = args.to_vec();
        let max_output_bytes = self.max_output_bytes;
        tokio::spawn(async move {
            let _permit = permit;
            run_verifier_process(&program, &args, timeout, max_output_bytes).await
        })
        .await
        .map_err(|error| io::Error::other(format!("verifier supervisor stopped: {error}")))?
    }

    #[cfg(test)]
    fn available_permits(&self) -> usize {
        self.permits.available_permits()
    }
}

#[async_trait]
impl HerdrCommandRunner for ProcessRunner {
    async fn run(&self, program: &Path, args: &[OsString]) -> io::Result<CommandOutput> {
        self.run_with_process_timeout(program, args, self.timeout)
            .await
    }

    async fn run_with_timeout(
        &self,
        program: &Path,
        args: &[OsString],
        timeout: Duration,
    ) -> io::Result<CommandOutput> {
        self.run_with_process_timeout(program, args, timeout.min(self.timeout))
            .await
    }
}

async fn run_verifier_process(
    program: &Path,
    args: &[OsString],
    timeout: Duration,
    max_output_bytes: usize,
) -> io::Result<CommandOutput> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("verifier stdout is unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("verifier stderr is unavailable"))?;
    let execution = async {
        let (status, stdout, stderr) = tokio::try_join!(
            child.wait(),
            read_process_output(stdout, max_output_bytes),
            read_process_output(stderr, max_output_bytes),
        )?;
        Ok::<_, io::Error>(CommandOutput {
            success: status.success(),
            stdout,
            stderr,
        })
    };
    match tokio::time::timeout(timeout, execution).await {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(error)) => {
            terminate_and_reap(&mut child).await;
            Err(error)
        }
        Err(_) => {
            terminate_and_reap(&mut child).await;
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Herdr verifier timed out",
            ))
        }
    }
}

async fn read_process_output(
    mut reader: impl AsyncRead + Unpin,
    max_bytes: usize,
) -> io::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(max_bytes.min(8 * 1024));
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            return Ok(output);
        }
        if output.len().saturating_add(read) > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Herdr verifier output exceeded its limit",
            ));
        }
        output.extend_from_slice(&buffer[..read]);
    }
}

async fn terminate_and_reap(child: &mut tokio::process::Child) {
    let _ = child.start_kill();
    let _ = child.wait().await;
}

struct DescriptorGuard {
    paths: RuntimePaths,
    broker_instance_id: String,
    published: bool,
}

impl DescriptorGuard {
    fn published(paths: RuntimePaths, broker_instance_id: String) -> Self {
        Self {
            paths,
            broker_instance_id,
            published: true,
        }
    }

    fn remove(&mut self) -> Result<(), DynError> {
        self.remove_with_hook(|| {})
    }

    fn remove_with_hook<F>(&mut self, observed_hook: F) -> Result<(), DynError>
    where
        F: FnOnce(),
    {
        if self.published {
            #[cfg(not(test))]
            let result = {
                let _ = observed_hook;
                remove_descriptor_if_instance(&self.paths, &self.broker_instance_id)
            };
            #[cfg(test)]
            let result = remove_descriptor_if_instance_with_observed_hook(
                &self.paths,
                &self.broker_instance_id,
                observed_hook,
            );
            match result {
                Ok(_) => {}
                Err(herdr_a2a_broker::runtime::RuntimeError::Io(error))
                    if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
            self.published = false;
        }
        Ok(())
    }
}

impl Drop for DescriptorGuard {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

struct PreparedBrokerServer {
    listener: TcpListener,
    app: axum::Router,
    descriptor_guard: DescriptorGuard,
}

struct BrokerStartupHooks<BeforeRecovery, BeforePublication, PublishDescriptor> {
    before_recovery: BeforeRecovery,
    before_publication: BeforePublication,
    publish_descriptor: PublishDescriptor,
}

async fn prepare_broker_server<BeforeRecovery, BeforePublication, PublishDescriptor>(
    paths: RuntimePaths,
    broker_pid: u32,
    executable_path: PathBuf,
    store: SqliteTaskStore,
    verifier: Arc<dyn HerdrVerifier>,
    hooks: BrokerStartupHooks<BeforeRecovery, BeforePublication, PublishDescriptor>,
) -> Result<PreparedBrokerServer, DynError>
where
    BeforeRecovery: Future<Output = ()>,
    BeforePublication: Future<Output = ()>,
    PublishDescriptor: FnOnce(
        &RuntimePaths,
        &RuntimeDescriptor,
    ) -> Result<(), herdr_a2a_broker::runtime::RuntimeError>,
{
    hooks.before_recovery.await;
    let (broker, recovery_report) = match recover_broker_state(SystemClock, &store).await {
        Ok(recovered) => recovered,
        Err(error) => {
            eprintln!("herdr-a2a: broker recovery failed stage={}", error.stage());
            return Err(io::Error::other("broker recovery failed").into());
        }
    };
    eprintln!(
        "herdr-a2a: broker recovery counts quarantined={} pruned_quarantine={} repaired_before={} requeued={} expired={} pruned={} restored={} repaired_after={}",
        recovery_report.store.quarantined_legacy_tasks,
        recovery_report.store.pruned_quarantined_tasks,
        recovery_report.store.repaired_projections,
        recovery_report.broker.requeued,
        recovery_report.broker.expired,
        recovery_report.broker.pruned,
        recovery_report.broker.restored,
        recovery_report.repaired_after_recovery,
    );

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let mut token_bytes = [0_u8; 32];
    getrandom::fill(&mut token_bytes)
        .map_err(|error| io::Error::other(format!("secure randomness unavailable: {error}")))?;
    let mut instance_bytes = [0_u8; 32];
    getrandom::fill(&mut instance_bytes)
        .map_err(|error| io::Error::other(format!("secure randomness unavailable: {error}")))?;
    let bearer_token = URL_SAFE_NO_PAD.encode(token_bytes);
    let address = listener.local_addr()?;
    let base_url = format!("http://{address}");
    let api_state = ApiState::new(
        broker,
        verifier,
        store.identity_store(),
        paths.scope.workspace_id.clone(),
        &bearer_token,
        instance_bytes,
    )?;
    let broker_instance_id = api_state.broker_instance_id().to_owned();
    let app = server_router(api_state, store, format!("{base_url}/jsonrpc"));
    let created_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    hooks.before_publication.await;
    (hooks.publish_descriptor)(
        &paths,
        &RuntimeDescriptor {
            session_key: paths.scope.session_key.clone(),
            workspace_id: paths.scope.workspace_id.clone(),
            base_url,
            bearer_token,
            broker_instance_id: broker_instance_id.clone(),
            executable_path,
            broker_pid,
            created_unix_ms,
        },
    )?;
    Ok(PreparedBrokerServer {
        listener,
        app,
        descriptor_guard: DescriptorGuard::published(paths, broker_instance_id),
    })
}

#[tokio::main]
async fn main() {
    let result = match Cli::parse().command {
        Commands::Broker => run_broker().await,
        Commands::Doctor { json, repair } => run_doctor(json, repair).await,
        Commands::Status { json } => status::run(json).await,
        Commands::StatusTui => {
            let backend = ProductionTuiBackend;
            status_tui::run(&backend).await
        }
        Commands::Restart => coordinator::restart().await,
        Commands::Coordinator { command } => match command {
            CoordinatorCommands::Serve => coordinator::serve().await,
            CoordinatorCommands::Ensure => coordinator::ensure().await,
            CoordinatorCommands::Stop => coordinator::stop().await,
            CoordinatorCommands::Restart => coordinator::restart().await,
            CoordinatorCommands::DispatchExec { pointer, args } => {
                coordinator::dispatch_exec(pointer.as_deref(), &args)
            }
        },
        Commands::Managed { command } => match command {
            ManagedCommands::Install { bundle } => managed::install(&bundle).await,
            ManagedCommands::Repair { startup, event } => managed::repair(startup, event).await,
            ManagedCommands::Status { json } => managed::status(json).await,
            ManagedCommands::Remove {
                purge,
                skip_herdr_unregister,
            } => managed::remove(purge, skip_herdr_unregister)
                .await
                .map(|_| ()),
            ManagedCommands::ExtractRelease {
                archive,
                destination,
            } => managed::extract_release(&archive, &destination).await,
            ManagedCommands::ValidatePluginRoot {
                path,
                managed_install,
            } => managed::validate_plugin_root(&path, managed_install),
        },
        Commands::ClientSession { harness_session_id } => session::run(harness_session_id).await,
    };
    if let Err(error) = result {
        eprintln!("herdr-a2a: {error}");
        std::process::exit(1);
    }
}

async fn run_doctor(json: bool, repair: bool) -> Result<(), DynError> {
    if repair {
        managed::repair(false, false).await?;
    }
    doctor::run(json).await
}

struct ProductionTuiBackend;

const MAX_PLUGIN_LOG_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PluginLogReadError {
    Missing,
    Unsafe,
    Unavailable,
}

fn read_plugin_log(path: &Path) -> Result<Vec<String>, PluginLogReadError> {
    read_plugin_log_with_hook(path, || {})
}

fn read_plugin_log_with_hook<F>(
    path: &Path,
    after_validation: F,
) -> Result<Vec<String>, PluginLogReadError>
where
    F: FnOnce(),
{
    use rustix::fs::{Mode, OFlags, open};

    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::NOENT {
            PluginLogReadError::Missing
        } else if error == rustix::io::Errno::LOOP {
            PluginLogReadError::Unsafe
        } else {
            PluginLogReadError::Unavailable
        }
    })?;
    let mut file = File::from(descriptor);
    let initial = file
        .metadata()
        .map_err(|_| PluginLogReadError::Unavailable)?;
    validate_plugin_log_metadata(&initial)?;

    after_validation();

    let mut bytes = Vec::with_capacity(initial.len() as usize + 1);
    (&mut file)
        .take((MAX_PLUGIN_LOG_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| PluginLogReadError::Unavailable)?;
    if bytes.len() > MAX_PLUGIN_LOG_BYTES || bytes.len() as u64 != initial.len() {
        return Err(PluginLogReadError::Unsafe);
    }
    let final_metadata = file
        .metadata()
        .map_err(|_| PluginLogReadError::Unavailable)?;
    validate_plugin_log_metadata(&final_metadata)?;
    if final_metadata.len() != initial.len() {
        return Err(PluginLogReadError::Unsafe);
    }
    let contents = String::from_utf8(bytes).map_err(|_| PluginLogReadError::Unavailable)?;
    Ok(contents
        .lines()
        .rev()
        .take(100)
        .map(str::to_owned)
        .collect())
}

fn validate_plugin_log_metadata(metadata: &fs::Metadata) -> Result<(), PluginLogReadError> {
    if !metadata.is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || metadata.len() > MAX_PLUGIN_LOG_BYTES as u64
    {
        return Err(PluginLogReadError::Unsafe);
    }
    Ok(())
}

#[async_trait]
impl status_tui::TuiBackend for ProductionTuiBackend {
    async fn status(&self) -> Result<status::WorkspaceStatus, String> {
        status::collect().await.map_err(|error| error.to_string())
    }

    async fn doctor(&self) -> doctor::DoctorReport {
        doctor::collect().await
    }

    async fn restart(&self) -> Result<status::WorkspaceStatus, String> {
        coordinator::restart()
            .await
            .map_err(|_| "broker restart failed closed".to_owned())?;
        status::collect().await.map_err(|error| error.to_string())
    }

    async fn logs(&self) -> Vec<String> {
        let Some(root) = env::var_os("HERDR_PLUGIN_STATE_DIR").map(PathBuf::from) else {
            return vec!["Plugin logs are unavailable.".to_owned()];
        };
        let path = root.join("herdr-a2a/plugin.log");
        match read_plugin_log(&path) {
            Ok(lines) => lines,
            Err(PluginLogReadError::Missing) => {
                vec!["No plugin log entries are available.".to_owned()]
            }
            Err(PluginLogReadError::Unsafe) => {
                vec!["Plugin logs failed ownership validation.".to_owned()]
            }
            Err(PluginLogReadError::Unavailable) => {
                vec!["Plugin logs are unavailable.".to_owned()]
            }
        }
    }
}

async fn run_broker() -> Result<(), DynError> {
    let paths = RuntimePaths::discover()?;
    let broker_pid = std::process::id();
    let session_lock = SessionLock::acquire(&paths, broker_pid, descriptor_is_healthy)?;
    let run_result = run_broker_while_locked(&paths, broker_pid).await;
    finish_broker_session(session_lock, run_result)
}

fn finish_broker_session(
    session_lock: SessionLock,
    run_result: Result<(), DynError>,
) -> Result<(), DynError> {
    if session_lock.release_nonblocking().is_err() {
        eprintln!("herdr-a2a: session lock release deferred to stale-owner recovery");
    }
    run_result
}

async fn run_broker_while_locked(paths: &RuntimePaths, broker_pid: u32) -> Result<(), DynError> {
    let executable_path = env::current_exe()?.canonicalize()?;

    let herdr_bin = validate_herdr_executable(&required_path("HERDR_BIN_PATH")?)?;
    let plugin_state = required_path("HERDR_PLUGIN_STATE_DIR")?;
    let prepared_database = prepare_database(&plugin_state, &paths.scope.scope_key)?;
    let store = prepared_database.open_store()?;
    let shutdown = ShutdownSignals::install()?;
    let coordinator_liveness = coordinator_liveness();
    let verifier: Arc<dyn HerdrVerifier> = Arc::new(CommandHerdrVerifier::new(
        herdr_bin,
        ProcessRunner::production(),
    ));
    let PreparedBrokerServer {
        listener,
        app,
        mut descriptor_guard,
    } = prepare_broker_server(
        paths.clone(),
        broker_pid,
        executable_path,
        store,
        verifier,
        BrokerStartupHooks {
            before_recovery: std::future::ready(()),
            before_publication: std::future::ready(()),
            publish_descriptor: write_descriptor,
        },
    )
    .await?;
    let (stop_server, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = stopped.await;
        })
        .into_future();
    tokio::pin!(server);
    let run_result: Result<(), DynError> = tokio::select! {
        result = &mut server => result.map_err(Into::into),
        _ = shutdown.wait() => {
            let descriptor_result = descriptor_guard.remove();
            let _ = stop_server.send(());
            if tokio::time::timeout(BROKER_SHUTDOWN_DRAIN, &mut server).await.is_err() {
                eprintln!("herdr-a2a: broker graceful shutdown drain expired");
            }
            descriptor_result
        }
        liveness = coordinator_liveness => {
            liveness?;
            let descriptor_result = descriptor_guard.remove();
            let _ = stop_server.send(());
            if tokio::time::timeout(BROKER_SHUTDOWN_DRAIN, &mut server).await.is_err() {
                eprintln!("herdr-a2a: broker graceful shutdown drain expired");
            }
            descriptor_result
        }
    };
    run_result
}

#[cfg(unix)]
async fn coordinator_liveness() -> io::Result<()> {
    if env::var_os("HERDR_A2A_LIVENESS_STDIN").as_deref() != Some(OsStr::new("1")) {
        std::future::pending::<()>().await;
        return Ok(());
    }
    // SAFETY: the marker is set only by the coordinator, which installs one endpoint of its
    // private Unix socket pair as the broker's stdin.
    let liveness = unsafe { std::os::unix::net::UnixStream::from_raw_fd(0) };
    liveness.set_nonblocking(true)?;
    let mut liveness = tokio::net::UnixStream::from_std(liveness)?;
    let mut byte = [0_u8; 1];
    match liveness.read(&mut byte).await? {
        0 => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected coordinator liveness data",
        )),
    }
}

#[cfg(not(unix))]
async fn coordinator_liveness() -> io::Result<()> {
    std::future::pending::<()>().await;
    Ok(())
}

fn descriptor_is_healthy(descriptor: &RuntimeDescriptor) -> bool {
    let timeout = Duration::from_millis(250);
    health::verify_broker_proof_sync(
        &descriptor.base_url,
        &descriptor.bearer_token,
        &descriptor.broker_instance_id,
        timeout,
    )
}

#[cfg(unix)]
pub(crate) struct ShutdownSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl ShutdownSignals {
    pub(crate) fn install() -> io::Result<Self> {
        Ok(Self {
            interrupt: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?,
            terminate: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
        })
    }

    pub(crate) async fn wait(mut self) {
        tokio::select! {
            _ = self.interrupt.recv() => {}
            _ = self.terminate.recv() => {}
        }
    }
}

#[cfg(not(unix))]
pub(crate) struct ShutdownSignals;

#[cfg(not(unix))]
impl ShutdownSignals {
    pub(crate) fn install() -> io::Result<Self> {
        Ok(Self)
    }

    pub(crate) async fn wait(self) {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn required_path(name: &'static str) -> Result<PathBuf, DynError> {
    let value = env::var_os(name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("{name} is required"))
        })?;
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be an absolute path"),
        )
        .into());
    }
    Ok(path)
}

fn validate_herdr_executable(path: &Path) -> Result<PathBuf, DynError> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HERDR_BIN_PATH must be absolute",
        )
        .into());
    }
    let canonical = path.canonicalize()?;
    let metadata = canonical.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HERDR_BIN_PATH must name a regular file",
        )
        .into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if metadata.mode() & 0o111 == 0
            || rustix::fs::accessat(
                rustix::fs::CWD,
                &canonical,
                rustix::fs::Access::EXEC_OK,
                rustix::fs::AtFlags::EACCESS,
            )
            .is_err()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "HERDR_BIN_PATH is not executable by this process",
            )
            .into());
        }
    }
    Ok(canonical)
}

struct PreparedDatabase {
    path: PathBuf,
    handle: File,
}

impl PreparedDatabase {
    fn open_store(&self) -> Result<SqliteTaskStore, DynError> {
        let expected = self.handle.metadata()?;
        let store = SqliteTaskStore::open(&self.path)?;
        let actual = fs::symlink_metadata(&self.path)?;
        validate_private_file(&self.path, &actual)?;
        #[cfg(unix)]
        if expected.dev() != actual.dev() || expected.ino() != actual.ino() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "task database changed while SQLite opened it",
            )
            .into());
        }
        Ok(store)
    }
}

fn prepare_database(plugin_state: &Path, scope_key: &str) -> Result<PreparedDatabase, DynError> {
    if scope_key.is_empty()
        || scope_key.len() > 128
        || !scope_key.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        return Err(
            io::Error::new(io::ErrorKind::InvalidInput, "invalid runtime scope key").into(),
        );
    }
    fs::create_dir_all(plugin_state)?;
    let plugin_state = plugin_state.canonicalize()?;
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags, open, openat};

        let directory_flags =
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let root = File::from(
            open(&plugin_state, directory_flags, Mode::empty()).map_err(io::Error::from)?,
        );
        validate_plugin_state_root(&plugin_state, &root.metadata()?)?;
        let state_root_path = plugin_state.join("herdr-a2a");
        let state_root =
            open_or_create_private_directory(&root, OsStr::new("herdr-a2a"), &state_root_path)?;
        let state_dir = state_root_path.join(scope_key);
        let scope =
            open_or_create_private_directory(&state_root, OsStr::new(scope_key), &state_dir)?;
        let database_path = state_dir.join("tasks.sqlite3");
        let file_flags = OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let handle = File::from(
            openat(
                &scope,
                OsStr::new("tasks.sqlite3"),
                file_flags,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(io::Error::from)?,
        );
        validate_private_file_identity(&database_path, &handle.metadata()?)?;
        rustix::fs::fchmod(&handle, Mode::RUSR | Mode::WUSR).map_err(io::Error::from)?;
        validate_private_file(&database_path, &handle.metadata()?)?;
        Ok(PreparedDatabase {
            path: database_path,
            handle,
        })
    }

    #[cfg(not(unix))]
    let state_dir = plugin_state.join("herdr-a2a").join(scope_key);
    #[cfg(not(unix))]
    fs::create_dir_all(&state_dir)?;
    #[cfg(not(unix))]
    let database_path = state_dir.join("tasks.sqlite3");
    #[cfg(not(unix))]
    let handle = fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&database_path)?;
    #[cfg(not(unix))]
    return Ok(PreparedDatabase {
        path: database_path,
        handle,
    });
}

#[cfg(unix)]
fn validate_plugin_state_root(_path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    if !metadata.file_type().is_dir() || metadata.uid() != rustix::process::getuid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "plugin state root is not an owned directory",
        ));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "plugin state root has unsafe permissions",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn open_or_create_private_directory(parent: &File, name: &OsStr, _path: &Path) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags, mkdirat, openat};

    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let descriptor = match openat(parent, name, flags, Mode::empty()) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => {
            match mkdirat(parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(io::Error::from(error)),
            }
            openat(parent, name, flags, Mode::empty()).map_err(io::Error::from)?
        }
        Err(error) => return Err(io::Error::from(error)),
    };
    let directory = File::from(descriptor);
    let metadata = directory.metadata()?;
    if !metadata.file_type().is_dir() || metadata.uid() != rustix::process::getuid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "state path is not an owned directory",
        ));
    }
    rustix::fs::fchmod(&directory, Mode::RUSR | Mode::WUSR | Mode::XUSR)
        .map_err(io::Error::from)?;
    let metadata = directory.metadata()?;
    if metadata.mode() & 0o777 != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "state directory is not private",
        ));
    }
    Ok(directory)
}

fn validate_private_file(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    validate_private_file_identity(path, metadata)?;
    #[cfg(unix)]
    if metadata.mode() & 0o777 != 0o600 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "task database is not private",
        ));
    }
    Ok(())
}

fn validate_private_file_identity(_path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "task database must be a regular file",
        ));
    }
    #[cfg(unix)]
    if metadata.uid() != rustix::process::getuid().as_raw() || metadata.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "task database is not a private owned file",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn prepare_database_path(plugin_state: &Path, scope_key: &str) -> Result<PathBuf, DynError> {
    Ok(prepare_database(plugin_state, scope_key)?.path)
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::OsString,
        fs::{self, OpenOptions},
        io::{self, Write as _},
        path::Path,
        process::Command as StdCommand,
        sync::{Arc, mpsc},
        thread,
        time::{Duration, Instant},
    };

    use base64::Engine as _;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use herdr_a2a_broker::{HerdrVerifier, herdr::HerdrCommandRunner};
    use tempfile::tempdir;
    use tokio::sync::Semaphore;

    use super::{
        BrokerStartupHooks, CommandHerdrVerifier, DescriptorGuard, MAX_PLUGIN_LOG_BYTES,
        PreparedBrokerServer, ProcessRunner, RuntimeDescriptor, RuntimePaths, SessionLock,
        SqliteTaskStore, finish_broker_session, prepare_broker_server, prepare_database_path,
        read_plugin_log, read_plugin_log_with_hook, validate_herdr_executable, write_descriptor,
        write_descriptor_with_post_rename_hook,
    };

    #[test]
    fn tui_log_reader_keeps_the_validated_descriptor_across_path_replacement() {
        // Break caught: validation and reading opened the pathname twice, so a replacement could
        // redirect the supposedly bounded read to an unvalidated inode.
        let temporary = tempdir().unwrap();
        let log = temporary.path().join("plugin.log");
        let original = temporary.path().join("original.log");
        fs::write(&log, "before replacement\n").unwrap();

        let lines = read_plugin_log_with_hook(&log, || {
            fs::rename(&log, &original).unwrap();
            fs::write(&log, vec![b'x'; MAX_PLUGIN_LOG_BYTES + 1]).unwrap();
        })
        .unwrap();

        assert_eq!(lines, vec!["before replacement"]);
    }

    #[test]
    fn tui_log_reader_rejects_a_fifo_without_blocking() {
        // Break caught: read_to_string on a pathname replaced with a FIFO blocked the TUI.
        let temporary = tempdir().unwrap();
        let fifo = temporary.path().join("plugin.log");
        assert!(
            StdCommand::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );

        let started = Instant::now();
        assert!(read_plugin_log(&fifo).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn tui_log_reader_detects_growth_within_its_fixed_read_cap() {
        // Break caught: a regular file could grow after the size check and make the actual read
        // allocate without the advertised 256 KiB bound.
        let temporary = tempdir().unwrap();
        let log = temporary.path().join("plugin.log");
        fs::write(&log, "initial\n").unwrap();

        let result = read_plugin_log_with_hook(&log, || {
            let mut file = OpenOptions::new().append(true).open(&log).unwrap();
            file.write_all(&vec![b'x'; MAX_PLUGIN_LOG_BYTES]).unwrap();
            file.sync_all().unwrap();
        });

        assert!(result.is_err());
    }

    fn descriptor_for(paths: &RuntimePaths, instance_byte: u8) -> RuntimeDescriptor {
        RuntimeDescriptor {
            session_key: paths.scope.session_key.clone(),
            workspace_id: paths.scope.workspace_id.clone(),
            base_url: "http://127.0.0.1:41321".to_owned(),
            bearer_token: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x11; 32]),
            broker_instance_id: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode([instance_byte; 32]),
            executable_path: std::env::current_exe().unwrap().canonicalize().unwrap(),
            broker_pid: std::process::id(),
            created_unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
                .try_into()
                .unwrap(),
        }
    }

    #[test]
    fn production_cleanup_does_not_remove_a_replacement_descriptor() {
        let temporary = tempdir().unwrap();
        let paths = RuntimePaths::for_test(
            &temporary.path().join("runtime"),
            "session-1",
            "test-workspace",
        );
        let original = descriptor_for(&paths, 0x22);
        let replacement = descriptor_for(&paths, 0x33);
        write_descriptor(&paths, &original).unwrap();

        let (observed_tx, observed_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let mut guard =
            DescriptorGuard::published(paths.clone(), original.broker_instance_id.clone());
        let cleanup = thread::spawn(move || {
            guard
                .remove_with_hook(|| {
                    observed_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                })
                .unwrap();
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

        assert_eq!(
            herdr_a2a_broker::read_descriptor(&paths).unwrap(),
            replacement
        );
    }

    #[tokio::test]
    async fn descriptor_is_not_published_until_reconciliation_finishes() {
        // Break caught: the actual production launch path writes discovery before core recovery
        // or before the final pending-projection drain returns.
        let temporary = tempdir().unwrap();
        let paths = RuntimePaths::for_test(
            &temporary.path().join("runtime"),
            "session-1",
            "test-workspace",
        );
        let store = SqliteTaskStore::open(temporary.path().join("tasks.sqlite3")).unwrap();
        let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
        let verifier: Arc<dyn HerdrVerifier> = Arc::new(CommandHerdrVerifier::new(
            executable.clone(),
            ProcessRunner::production(),
        ));
        let recovery_entered = Arc::new(Semaphore::new(0));
        let recovery_release = Arc::new(Semaphore::new(0));
        let publication_entered = Arc::new(Semaphore::new(0));
        let publication_release = Arc::new(Semaphore::new(0));
        let starting = tokio::spawn({
            let recovery_entered = Arc::clone(&recovery_entered);
            let recovery_release = Arc::clone(&recovery_release);
            let publication_entered = Arc::clone(&publication_entered);
            let publication_release = Arc::clone(&publication_release);
            let paths = paths.clone();
            async move {
                prepare_broker_server(
                    paths,
                    std::process::id(),
                    executable,
                    store,
                    verifier,
                    BrokerStartupHooks {
                        before_recovery: async move {
                            recovery_entered.add_permits(1);
                            recovery_release.acquire().await.unwrap().forget();
                        },
                        before_publication: async move {
                            publication_entered.add_permits(1);
                            publication_release.acquire().await.unwrap().forget();
                        },
                        publish_descriptor: write_descriptor,
                    },
                )
                .await
            }
        });

        recovery_entered.acquire().await.unwrap().forget();
        assert!(!paths.descriptor.exists());
        recovery_release.add_permits(1);
        publication_entered.acquire().await.unwrap().forget();
        assert!(!paths.descriptor.exists());
        publication_release.add_permits(1);
        let PreparedBrokerServer {
            descriptor_guard, ..
        } = starting.await.unwrap().unwrap();
        assert!(paths.descriptor.exists());
        drop(descriptor_guard);
        assert!(!paths.descriptor.exists());
    }

    #[tokio::test]
    async fn post_rename_publication_failure_leaves_no_descriptor_and_preserves_database() {
        let temporary = tempdir().unwrap();
        let paths = RuntimePaths::for_test(
            &temporary.path().join("runtime"),
            "session-1",
            "test-workspace",
        );
        let database_path = temporary.path().join("tasks.sqlite3");
        let store = SqliteTaskStore::open(&database_path).unwrap();
        let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
        let verifier: Arc<dyn HerdrVerifier> = Arc::new(CommandHerdrVerifier::new(
            executable.clone(),
            ProcessRunner::production(),
        ));

        let result = prepare_broker_server(
            paths.clone(),
            std::process::id(),
            executable,
            store,
            verifier,
            BrokerStartupHooks {
                before_recovery: std::future::ready(()),
                before_publication: std::future::ready(()),
                publish_descriptor: |paths: &RuntimePaths, descriptor: &RuntimeDescriptor| {
                    write_descriptor_with_post_rename_hook(paths, descriptor, || {
                        Err(herdr_a2a_broker::runtime::RuntimeError::Io(
                            io::Error::other("injected post-rename failure"),
                        ))
                    })
                },
            },
        )
        .await;

        assert!(result.is_err());
        assert!(!paths.descriptor.exists());
        assert!(database_path.is_file());
        SqliteTaskStore::open(database_path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn herdr_executable_must_be_canonical_regular_and_effectively_executable() {
        let temporary = tempdir().unwrap();
        let executable = temporary.path().join("herdr");
        fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(validate_herdr_executable(&executable).is_err());
        assert!(validate_herdr_executable(temporary.path()).is_err());

        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            validate_herdr_executable(&executable).unwrap(),
            executable.canonicalize().unwrap()
        );
    }

    #[tokio::test]
    async fn verifier_runner_caps_output_and_kills_and_reaps_on_timeout() {
        let capped = ProcessRunner::with_limits(1, Duration::from_secs(2), 1024);
        let output_error = capped
            .run(Path::new("/usr/bin/yes"), &[])
            .await
            .unwrap_err();
        assert_eq!(output_error.kind(), std::io::ErrorKind::InvalidData);

        let temporary = tempdir().unwrap();
        let pid_file = temporary.path().join("pid");
        let script = format!("echo $$ > '{}'; while :; do :; done", pid_file.display());
        let timed = ProcessRunner::with_limits(1, Duration::from_millis(100), 1024);
        let timeout_error = timed
            .run(
                Path::new("/bin/sh"),
                &[OsString::from("-c"), OsString::from(script)],
            )
            .await
            .unwrap_err();
        assert_eq!(timeout_error.kind(), std::io::ErrorKind::TimedOut);
        let pid: i32 = fs::read_to_string(pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(
            rustix::process::test_kill_process(rustix::process::Pid::from_raw(pid).unwrap())
                .is_err(),
            "timed-out verifier child still exists"
        );
    }

    #[tokio::test]
    async fn verifier_runner_enforces_its_concurrency_limit() {
        let temporary = tempdir().unwrap();
        let release = temporary.path().join("release");
        let script = format!("while [ ! -f '{}' ]; do :; done", release.display());
        let args = vec![OsString::from("-c"), OsString::from(script)];
        let runner = ProcessRunner::with_limits(1, Duration::from_secs(2), 1024);

        let first = tokio::spawn({
            let runner = runner.clone();
            let args = args.clone();
            async move { runner.run(Path::new("/bin/sh"), &args).await }
        });
        while runner.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
        let mut second = tokio::spawn({
            let runner = runner.clone();
            async move { runner.run(Path::new("/bin/sh"), &args).await }
        });
        tokio::select! {
            result = &mut second => panic!("second verifier bypassed the limit: {result:?}"),
            _ = tokio::task::yield_now() => {}
        }

        fs::write(release, "go").unwrap();
        assert!(first.await.unwrap().unwrap().success);
        assert!(second.await.unwrap().unwrap().success);
    }

    #[tokio::test]
    async fn canceled_verifier_request_still_kills_and_reaps_its_child() {
        let temporary = tempdir().unwrap();
        let pid_file = temporary.path().join("pid");
        let started_file = temporary.path().join("started");
        let script = format!(
            ": > '{}'; : > '{}'; sleep 0.5; echo $$ > '{}'; while :; do :; done",
            pid_file.display(),
            started_file.display(),
            pid_file.display()
        );
        let runner = ProcessRunner::with_limits(1, Duration::from_millis(700), 1024);
        let request = tokio::spawn(async move {
            runner
                .run(
                    Path::new("/bin/sh"),
                    &[OsString::from("-c"), OsString::from(script)],
                )
                .await
        });
        let pid = tokio::time::timeout(Duration::from_secs(1), async {
            while !started_file.exists() {
                tokio::task::yield_now().await;
            }
            loop {
                if let Ok(contents) = fs::read_to_string(&pid_file)
                    && let Ok(pid) = contents.trim().parse::<i32>()
                    && pid > 0
                {
                    break pid;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("verifier child did not start");
        request.abort();

        tokio::time::timeout(Duration::from_secs(1), async {
            while rustix::process::test_kill_process(rustix::process::Pid::from_raw(pid).unwrap())
                .is_ok()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("canceled verifier child was not reaped by its supervisor");
    }

    #[cfg(unix)]
    #[test]
    fn database_directories_and_file_have_private_modes() {
        let plugin_state = tempdir().unwrap();

        let database = prepare_database_path(plugin_state.path(), "session-1").unwrap();

        assert_eq!(
            fs::metadata(plugin_state.path().join("herdr-a2a"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(database.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(database).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn database_path_rejects_symlink_components_without_chmod_or_escape() {
        let plugin_state = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::set_permissions(outside.path(), fs::Permissions::from_mode(0o750)).unwrap();
        std::os::unix::fs::symlink(outside.path(), plugin_state.path().join("herdr-a2a")).unwrap();

        assert!(prepare_database_path(plugin_state.path(), "session-1").is_err());
        assert_eq!(
            fs::metadata(outside.path()).unwrap().permissions().mode() & 0o777,
            0o750
        );
        assert!(!outside.path().join("session-1/tasks.sqlite3").exists());
    }

    #[cfg(unix)]
    #[test]
    fn database_path_rejects_session_and_database_symlinks() {
        let plugin_state = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let state_root = plugin_state.path().join("herdr-a2a");
        fs::create_dir(&state_root).unwrap();
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(outside.path(), state_root.join("session-link")).unwrap();
        assert!(prepare_database_path(plugin_state.path(), "session-link").is_err());

        let session = state_root.join("session-file");
        fs::create_dir(&session).unwrap();
        fs::set_permissions(&session, fs::Permissions::from_mode(0o700)).unwrap();
        let outside_file = outside.path().join("outside.sqlite3");
        fs::write(&outside_file, "untouched").unwrap();
        fs::set_permissions(&outside_file, fs::Permissions::from_mode(0o640)).unwrap();
        std::os::unix::fs::symlink(&outside_file, session.join("tasks.sqlite3")).unwrap();

        assert!(prepare_database_path(plugin_state.path(), "session-file").is_err());
        assert_eq!(
            fs::metadata(outside_file).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[test]
    fn startup_error_cleanup_never_blocks_on_the_transition_guard() {
        let runtime = tempdir().unwrap();
        let paths = RuntimePaths::for_test(runtime.path(), "session-1", "test-workspace");
        let lock = SessionLock::acquire(&paths, std::process::id(), |_| false).unwrap();
        let transition_guard = fs::OpenOptions::new()
            .read(true)
            .open(
                paths
                    .root
                    .join(format!(".{}.acquire", paths.scope.scope_key)),
            )
            .unwrap();
        rustix::fs::flock(&transition_guard, rustix::fs::FlockOperation::LockExclusive).unwrap();

        let result = finish_broker_session(
            lock,
            Err(std::io::Error::other("injected startup failure").into()),
        );

        assert!(result.is_err());
        assert!(paths.lock.exists());
    }
}
