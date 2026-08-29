use std::{
    env,
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    net::Ipv4Addr,
    os::unix::net::UnixStream as StdUnixStream,
    path::{Component, Path, PathBuf},
    process::Stdio,
    thread,
    time::Duration,
};

#[cfg(target_os = "linux")]
use std::fs;

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::{ffi::OsStrExt, fs::MetadataExt, process::CommandExt};

use async_trait::async_trait;
use herdr_a2a_broker::{RuntimeDescriptor, RuntimePaths, RuntimeScope, read_descriptor};
use rustix::{
    fs::{FlockOperation, Mode, OFlags, flock, open},
    process::{Pid, Signal, kill_process},
};
use serde::{Deserialize, Serialize};
use tokio::process::{Child, Command};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::{
    DynError, ShutdownSignals, health::verify_broker_proof, managed, required_path,
    validate_herdr_executable,
};

const ACTION_ID: &str = "herdr.a2a.ensure-broker";
const DEFAULT_ENSURE_TIMEOUT: Duration = Duration::from_secs(10);
const DESCRIPTOR_RECHECK: Duration = Duration::from_millis(25);
const STOP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_COORDINATOR_RECORD_BYTES: u64 = 4 * 1024;
const MAX_STABLE_POINTER_BYTES: u64 = 4 * 1024;

#[derive(Debug)]
pub(crate) enum LaunchError {
    Deadline,
    InvalidScope,
    ProofInvalid(String),
    Unavailable(String),
}

impl std::fmt::Display for LaunchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deadline => formatter.write_str("broker launch deadline expired"),
            Self::InvalidScope => formatter.write_str("broker launch scope changed"),
            Self::ProofInvalid(reason) => write!(formatter, "broker proof is invalid: {reason}"),
            Self::Unavailable(reason) => write!(formatter, "broker launch unavailable: {reason}"),
        }
    }
}

impl std::error::Error for LaunchError {}

#[async_trait]
pub(crate) trait BrokerLauncher: Send + Sync {
    async fn ensure(
        &self,
        scope: &RuntimeScope,
        deadline: tokio::time::Instant,
    ) -> Result<RuntimeDescriptor, LaunchError>;
}

pub(crate) struct ProductionBrokerLauncher;

impl ProductionBrokerLauncher {
    pub(crate) fn new() -> Self {
        Self
    }
}

#[async_trait]
impl BrokerLauncher for ProductionBrokerLauncher {
    async fn ensure(
        &self,
        scope: &RuntimeScope,
        deadline: tokio::time::Instant,
    ) -> Result<RuntimeDescriptor, LaunchError> {
        let paths = RuntimePaths::discover().map_err(launch_unavailable)?;
        if &paths.scope != scope {
            return Err(LaunchError::InvalidScope);
        }
        if let Some(descriptor) = protected_descriptor(&paths, deadline).await? {
            return Ok(descriptor);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(LaunchError::Deadline);
        }
        let watcher = DescriptorWatcher::new(&paths.root).map_err(launch_unavailable)?;

        let herdr = validate_herdr_executable(
            &required_path("HERDR_BIN_PATH")
                .map_err(|error| LaunchError::Unavailable(error.to_string()))?,
        )
        .map_err(|error| LaunchError::Unavailable(error.to_string()))?;
        let mut action = Command::new(herdr);
        action
            .args(["plugin", "action", "invoke", ACTION_ID])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(false);
        let mut action = action.spawn().map_err(launch_unavailable)?;
        tokio::spawn(async move {
            let _ = action.wait().await;
        });

        wait_for_protected_descriptor(&paths, deadline, Some(&watcher)).await
    }
}

pub(crate) async fn ensure() -> Result<(), DynError> {
    let paths = RuntimePaths::discover()?;
    let deadline = tokio::time::Instant::now() + DEFAULT_ENSURE_TIMEOUT;
    ProductionBrokerLauncher::new()
        .ensure(&paths.scope, deadline)
        .await?;
    Ok(())
}

pub(crate) async fn restart() -> Result<(), DynError> {
    let paths = RuntimePaths::discover()?;
    let deadline = tokio::time::Instant::now() + DEFAULT_ENSURE_TIMEOUT;
    let original = read_descriptor(&paths)?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(2))
        .build()?;
    verify_broker_proof(
        &client,
        &original.base_url,
        &original.bearer_token,
        &original.broker_instance_id,
    )
    .await?;
    let original_coordinator =
        wait_for_coordinator_record_for_descriptor(&paths, &original, deadline).await?;
    let stop_result = stop_expected(Some(&original.broker_instance_id)).await;
    pause_starting_boundary("after-restart-stop-before-replacement-deadline").await?;
    let replacement_deadline = tokio::time::Instant::now() + DEFAULT_ENSURE_TIMEOUT;
    let mut recovered_replacement = match stop_result {
        Ok(()) => None,
        Err(stop_error) => match proved_replacement_after_retirement(
            &paths,
            &original,
            &original_coordinator,
            replacement_deadline,
        )
        .await?
        {
            Some(replacement) => Some(replacement),
            None => return Err(stop_error),
        },
    };
    while recovered_replacement.is_none() && paths.descriptor.exists() {
        let observed = read_descriptor(&paths).map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "broker descriptor changed during coordinated restart",
            )
        })?;
        if observed.broker_instance_id != original.broker_instance_id {
            recovered_replacement = proved_replacement_after_retirement(
                &paths,
                &original,
                &original_coordinator,
                replacement_deadline,
            )
            .await?;
            if recovered_replacement.is_some() {
                break;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "broker descriptor removal deadline expired",
            )
            .into());
        }
        tokio::time::sleep(DESCRIPTOR_RECHECK).await;
    }
    pause_starting_boundary("after-restart-descriptor-absence-before-ensure").await?;
    let replacement = match recovered_replacement {
        Some(replacement) => replacement,
        None => {
            ProductionBrokerLauncher::new()
                .ensure(&paths.scope, replacement_deadline)
                .await?
        }
    };
    validate_replacement_after_retirement(
        &paths,
        &original,
        &original_coordinator,
        &replacement,
        replacement_deadline,
    )
    .await?;
    Ok(())
}

async fn wait_for_coordinator_record_for_descriptor(
    paths: &RuntimePaths,
    descriptor: &RuntimeDescriptor,
    deadline: tokio::time::Instant,
) -> Result<CoordinatorRecord, DynError> {
    loop {
        let mut file = CoordinatorLock::open(paths, false)?;
        match flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "broker descriptor has no owning coordinator",
                )
                .into());
            }
            Err(rustix::io::Errno::WOULDBLOCK) => {}
            Err(error) => return Err(io::Error::from(error).into()),
        }
        let record = read_record(&mut file)?;
        validate_control_record(&record)?;
        if record.scope_key != paths.scope.scope_key {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "coordinator and broker descriptor scopes do not match",
            )
            .into());
        }
        match record.broker_instance_id.as_deref() {
            Some(instance) if instance == descriptor.broker_instance_id => {
                let broker_start = record.broker_start_identity.as_deref().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "coordinator has no broker process proof",
                    )
                })?;
                require_process_proof(
                    record.pid,
                    &record.start_identity,
                    &descriptor.executable_path,
                )?;
                require_process_proof(
                    descriptor.broker_pid,
                    broker_start,
                    &descriptor.executable_path,
                )?;
                return Ok(record);
            }
            Some(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "coordinator and broker descriptor generations do not match",
                )
                .into());
            }
            None if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(DESCRIPTOR_RECHECK).await;
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "coordinator broker proof publication deadline expired",
                )
                .into());
            }
        }
    }
}

async fn proved_replacement_after_retirement(
    paths: &RuntimePaths,
    original: &RuntimeDescriptor,
    original_coordinator: &CoordinatorRecord,
    deadline: tokio::time::Instant,
) -> Result<Option<RuntimeDescriptor>, DynError> {
    require_original_processes_retired(original, original_coordinator)?;
    protected_descriptor(paths, deadline)
        .await
        .map_err(Into::into)
}

fn require_original_processes_retired(
    original: &RuntimeDescriptor,
    original_coordinator: &CoordinatorRecord,
) -> Result<(), DynError> {
    require_registered_process_retired(
        original_coordinator.pid,
        &original_coordinator.start_identity,
        &original.executable_path,
    )?;
    let original_broker_start = original_coordinator
        .broker_start_identity
        .as_deref()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "original coordinator has no broker process proof",
            )
        })?;
    require_registered_process_retired(
        original.broker_pid,
        original_broker_start,
        &original.executable_path,
    )?;
    Ok(())
}

async fn validate_replacement_after_retirement(
    paths: &RuntimePaths,
    original: &RuntimeDescriptor,
    original_coordinator: &CoordinatorRecord,
    candidate: &RuntimeDescriptor,
    deadline: tokio::time::Instant,
) -> Result<RuntimeDescriptor, DynError> {
    require_original_processes_retired(original, original_coordinator)?;
    let replacement = protected_descriptor(paths, deadline)
        .await?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "automatic broker replacement descriptor is unavailable",
            )
        })?;
    if &replacement != candidate {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "automatic broker replacement changed before final validation",
        )
        .into());
    }
    if replacement.broker_instance_id == original.broker_instance_id
        || replacement.session_key != paths.scope.session_key
        || replacement.workspace_id != paths.scope.workspace_id
        || replacement.executable_path != original.executable_path
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "automatic broker replacement identity does not match the retired scope",
        )
        .into());
    }
    wait_for_coordinator_record_for_descriptor(paths, &replacement, deadline).await?;
    Ok(replacement)
}

pub(crate) fn dispatch_exec(
    configured_pointer: Option<&Path>,
    args: &[OsString],
) -> Result<(), DynError> {
    let invoked_path = env::args_os().next().map(PathBuf::from).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "dispatcher argv0 is missing")
    })?;
    let invoked_path = if invoked_path.is_absolute() {
        invoked_path
    } else {
        env::current_dir()?.join(invoked_path)
    };
    let _trusted_helper = open_private_dispatch_file(&invoked_path, DispatchFileKind::Executable)?;
    let plugin_root = invoked_path
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "dispatcher must be installed under plugin/libexec",
            )
        })?;
    let default_pointer;
    let pointer_path = match configured_pointer {
        Some(pointer) => pointer,
        None => {
            default_pointer = plugin_root.join("stable-bin-path");
            &default_pointer
        }
    };
    let mut pointer = open_private_dispatch_file(pointer_path, DispatchFileKind::Pointer)?;
    let mut encoded_path = Vec::new();
    Read::by_ref(&mut pointer)
        .take(MAX_STABLE_POINTER_BYTES + 1)
        .read_to_end(&mut encoded_path)?;
    if encoded_path.is_empty()
        || encoded_path.len() as u64 > MAX_STABLE_POINTER_BYTES
        || encoded_path.last() != Some(&b'\n')
        || encoded_path[..encoded_path.len() - 1].contains(&b'\n')
        || encoded_path.len() == 1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stable pointer must contain exactly one non-empty newline-terminated path",
        )
        .into());
    }
    encoded_path.pop();
    if encoded_path.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stable pointer path contains a NUL byte",
        )
        .into());
    }
    let stable_path = PathBuf::from(OsStr::from_bytes(&encoded_path));
    let stable = open_private_dispatch_file(&stable_path, DispatchFileKind::Executable)?;
    #[cfg(target_os = "macos")]
    let execution_path = {
        // macOS exposes no fexecve. Recheck the final directory entry against the already-open
        // inode immediately before exec; every parent was opened no-follow and rejected when
        // writable by group/other, so an untrusted user cannot replace the checked entry.
        let opened = stable.metadata()?;
        let current = std::fs::symlink_metadata(&stable_path)?;
        validate_dispatch_file(&current, DispatchFileKind::Executable)?;
        if opened.dev() != current.dev() || opened.ino() != current.ino() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "stable binary changed after validation",
            )
            .into());
        }
        stable_path.clone()
    };
    #[cfg(target_os = "linux")]
    let execution_path = {
        rustix::io::fcntl_setfd(&stable, rustix::io::FdFlags::empty()).map_err(io::Error::from)?;
        PathBuf::from(format!("/proc/self/fd/{}", stable.as_raw_fd()))
    };
    let error = std::process::Command::new(execution_path)
        .arg0(stable_path.as_os_str())
        .env("HERDR_A2A_PLUGIN_ROOT", plugin_root)
        .args(args)
        .exec();
    Err(error.into())
}

#[derive(Clone, Copy)]
enum DispatchFileKind {
    Pointer,
    Executable,
}

fn open_private_dispatch_file(path: &Path, kind: DispatchFileKind) -> io::Result<File> {
    if !path.is_absolute()
        || path.as_os_str().as_bytes().contains(&0)
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "dispatch path must be normalized and absolute",
        ));
    }
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "dispatch path has no root",
        ));
    }
    let mut names = components
        .map(|component| match component {
            Component::Normal(name) => Ok(name),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "dispatch path contains an unsupported component",
            )),
        })
        .collect::<io::Result<Vec<_>>>()?;
    let final_name = names.pop().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "dispatch path has no file name",
        )
    })?;
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory =
        File::from(open(Path::new("/"), directory_flags, Mode::empty()).map_err(io::Error::from)?);
    validate_dispatch_directory(&directory.metadata()?)?;
    for name in names {
        directory = File::from(
            rustix::fs::openat(&directory, name, directory_flags, Mode::empty())
                .map_err(io::Error::from)?,
        );
        validate_dispatch_directory(&directory.metadata()?)?;
    }
    let file = File::from(
        rustix::fs::openat(
            &directory,
            final_name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(io::Error::from)?,
    );
    validate_dispatch_file(&file.metadata()?, kind)?;
    Ok(file)
}

fn validate_dispatch_directory(metadata: &std::fs::Metadata) -> io::Result<()> {
    let uid = rustix::process::getuid().as_raw();
    if !metadata.is_dir()
        || (metadata.uid() != 0 && metadata.uid() != uid)
        || metadata.mode() & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "dispatch path contains an unsafe directory",
        ));
    }
    Ok(())
}

fn validate_dispatch_file(metadata: &std::fs::Metadata, kind: DispatchFileKind) -> io::Result<()> {
    let permissions = metadata.mode() & 0o777;
    let safe_permissions = match kind {
        DispatchFileKind::Pointer => permissions == 0o600,
        DispatchFileKind::Executable => permissions & 0o022 == 0 && permissions & 0o111 != 0,
    };
    if !metadata.is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.nlink() != 1
        || !safe_permissions
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "dispatch file is not private, owned, and safe",
        ));
    }
    Ok(())
}

struct ManagedStartingReservation {
    entry: managed::ManagedStartingProcessEntry,
    active: bool,
}

impl ManagedStartingReservation {
    fn reserve(entry: managed::ManagedStartingProcessEntry) -> Result<Self, DynError> {
        let active = managed::reserve_managed_process_start(entry.clone())?;
        Ok(Self { entry, active })
    }

    fn bind_broker(&mut self, broker: managed::ManagedStartingBrokerProof) -> Result<(), DynError> {
        if self.active {
            managed::bind_managed_process_start_broker(&self.entry, broker.clone())?;
            self.entry.broker = Some(broker);
        }
        Ok(())
    }

    fn commit(&mut self) {
        self.active = false;
    }
}

impl Drop for ManagedStartingReservation {
    fn drop(&mut self) {
        if self.active {
            let _ = managed::unregister_managed_process_start(&self.entry);
        }
    }
}

pub(crate) async fn serve() -> Result<(), DynError> {
    let paths = RuntimePaths::discover()?;
    let lock = match CoordinatorLock::acquire(&paths)? {
        LockAcquisition::Owned(lock) => lock,
        LockAcquisition::Busy => {
            wait_for_protected_descriptor(
                &paths,
                tokio::time::Instant::now() + DEFAULT_ENSURE_TIMEOUT,
                None,
            )
            .await?;
            return Ok(());
        }
    };

    // This proof recheck is deliberately after lock acquisition. It is the cross-process
    // single-flight boundary: a waiter must adopt the winner rather than spawn another child.
    if protected_descriptor(&paths, tokio::time::Instant::now() + DEFAULT_ENSURE_TIMEOUT)
        .await?
        .is_some()
    {
        return Ok(());
    }

    // Every fallible piece of coordinator supervision is installed before the broker exists.
    // The broker inherits only the read end. Coordinator death closes the write end even when
    // no async cleanup runs (panic/SIGKILL), making EOF an unforgeable lifetime signal.
    let shutdown = ShutdownSignals::install()?;
    let control = ControlServer::bind().await?;
    let (liveness_read, liveness_write) = StdUnixStream::pair()?;
    let executable = env::current_exe()?.canonicalize()?;
    let coordinator_pid = std::process::id();
    let coordinator_proof =
        registration_process_proof(coordinator_pid, &control.nonce, &executable)?.ok_or_else(
            || {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "coordinator process identity disappeared before publication",
                )
            },
        )?;
    let executable_digest = managed::managed_executable_digest(&executable)?;
    let expected_generation = managed_generation_id(&executable)?;
    let starting_entry = managed::ManagedStartingProcessEntry {
        runtime_root: paths.root.clone(),
        session_key: paths.scope.session_key.clone(),
        workspace_id: paths.scope.workspace_id.clone(),
        scope_key: paths.scope.scope_key.clone(),
        coordinator_pid,
        coordinator_start: coordinator_proof.start_identity.clone(),
        executable_path: executable.clone(),
        executable_digest: executable_digest.clone(),
        expected_generation,
        control_port: control.port,
        control_nonce: control.nonce.clone(),
        broker: None,
    };
    let mut starting_reservation = ManagedStartingReservation::reserve(starting_entry)?;
    pause_starting_boundary("after-coordinator-reservation").await?;
    lock.publish(&paths, &control, &coordinator_proof.start_identity)?;
    let inherited = validated_broker_environment(&paths)?;
    let mut command = Command::new(&executable);
    command
        .arg("broker")
        .env_clear()
        .envs(inherited)
        .env("HERDR_A2A_LIVENESS_STDIN", "1")
        .stdin(Stdio::from(File::from(std::os::fd::OwnedFd::from(
            liveness_read,
        ))))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(false);
    let mut child = command.spawn()?;
    let child_pid = child
        .id()
        .ok_or_else(|| io::Error::other("broker child has no process ID"))?;
    let executable_path = executable.canonicalize()?;
    let broker_proof = registration_process_proof(child_pid, &control.nonce, &executable_path)?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "broker process identity disappeared before starting proof publication",
            )
        })?;
    let starting_broker = managed::ManagedStartingBrokerProof {
        broker_pid: child_pid,
        broker_start: broker_proof.start_identity.clone(),
        executable_path: executable_path.clone(),
        executable_digest: executable_digest.clone(),
    };
    starting_reservation.bind_broker(starting_broker)?;
    pause_starting_boundary("after-broker-proof-before-descriptor").await?;
    let descriptor = match wait_for_owned_descriptor(
        &paths,
        &mut child,
        child_pid,
        tokio::time::Instant::now() + DEFAULT_ENSURE_TIMEOUT,
    )
    .await
    {
        Ok(descriptor) => descriptor,
        Err(error) => {
            cleanup_descriptor_for_child(&paths, child_pid)?;
            return Err(error);
        }
    };
    if coordinator_proof
        .executable
        .as_ref()
        .is_some_and(|observed| observed != &executable_path)
        || broker_proof
            .executable
            .as_ref()
            .is_some_and(|observed| observed != &executable_path)
        || descriptor.executable_path != executable_path
        || descriptor.broker_pid != child_pid
    {
        terminate_child(&mut child).await?;
        cleanup_descriptor_for_child(&paths, child_pid)?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed process executable or descriptor identity changed",
        )
        .into());
    }
    let process_entry = managed::ManagedProcessEntry {
        runtime_root: paths.root.clone(),
        session_key: paths.scope.session_key.clone(),
        workspace_id: paths.scope.workspace_id.clone(),
        scope_key: paths.scope.scope_key.clone(),
        coordinator_pid,
        coordinator_start: coordinator_proof.start_identity.clone(),
        broker_pid: child_pid,
        broker_start: broker_proof.start_identity.clone(),
        broker_instance_id: descriptor.broker_instance_id.clone(),
        executable_path,
        executable_digest,
        control_port: control.port,
        control_nonce: control.nonce.clone(),
    };
    lock.bind_broker(
        &paths,
        &control,
        &descriptor,
        &coordinator_proof.start_identity,
        &broker_proof.start_identity,
    )?;
    pause_starting_boundary("after-descriptor-before-registration").await?;
    let registered = match managed::register_managed_process(process_entry.clone()) {
        Ok(value) => value,
        Err(error) => {
            terminate_child(&mut child).await?;
            cleanup_descriptor_for_child(&paths, child_pid)?;
            return Err(error.into());
        }
    };
    starting_reservation.commit();

    let child_result = tokio::select! {
        status = child.wait() => status.map(|_| ()),
        _ = shutdown.wait() => terminate_child(&mut child).await,
        result = control.wait() => {
            result?;
            terminate_child(&mut child).await
        }
    };
    drop(liveness_write);
    let cleanup = herdr_a2a_broker::runtime::remove_descriptor_if_instance(
        &paths,
        &descriptor.broker_instance_id,
    );
    child_result?;
    cleanup?;
    if registered {
        managed::unregister_managed_process(&process_entry)?;
    }
    drop(lock);
    Ok(())
}

async fn pause_starting_boundary(_boundary: &str) -> Result<(), DynError> {
    #[cfg(feature = "test-harness")]
    if env::var_os("HERDR_A2A_TEST_STARTING_BOUNDARY").as_deref()
        == Some(std::ffi::OsStr::new(_boundary))
    {
        let marker = env::var_os("HERDR_A2A_TEST_STARTING_MARKER")
            .filter(|marker| !marker.is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "starting-process test boundary has no marker",
                )
            })?;
        std::fs::write(&marker, b"paused\n").map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "cannot write starting-process test marker {}: {error}",
                    marker.display()
                ),
            )
        })?;
        let release = marker.with_extension("release");
        while !release.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    Ok(())
}

fn managed_generation_id(executable: &Path) -> Result<String, DynError> {
    #[cfg(feature = "test-harness")]
    if let Some(generation_id) =
        env::var_os("HERDR_A2A_TEST_GENERATION_ID").and_then(|value| value.into_string().ok())
    {
        if generation_id.len() == 32
            && generation_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Ok(generation_id);
        }
        return Err(
            io::Error::new(io::ErrorKind::InvalidInput, "test generation ID is invalid").into(),
        );
    }
    let Some(bin) = executable.parent() else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed executable has no bin parent",
        )
        .into());
    };
    let Some(generation) = bin.parent() else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed executable has no generation parent",
        )
        .into());
    };
    let Some(generation_id) = generation.file_name().and_then(|name| name.to_str()) else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed executable generation name is invalid",
        )
        .into());
    };
    if executable.file_name() != Some(std::ffi::OsStr::new("herdr-a2a"))
        || bin.file_name() != Some(std::ffi::OsStr::new("bin"))
        || generation.parent().and_then(Path::file_name)
            != Some(std::ffi::OsStr::new("generations"))
        || generation_id.len() != 32
        || !generation_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed executable generation layout is invalid",
        )
        .into());
    }
    Ok(generation_id.to_owned())
}

fn cleanup_descriptor_for_child(paths: &RuntimePaths, child_pid: u32) -> Result<(), DynError> {
    if let Ok(descriptor) = read_descriptor(paths)
        && descriptor.broker_pid == child_pid
    {
        herdr_a2a_broker::runtime::remove_descriptor_if_instance(
            paths,
            &descriptor.broker_instance_id,
        )?;
    }
    Ok(())
}

pub(crate) async fn stop() -> Result<(), DynError> {
    stop_expected(None).await
}

#[cfg(not(test))]
pub(crate) async fn stop_registered_process(
    entry: &managed::ManagedProcessEntry,
    deadline: tokio::time::Instant,
) -> Result<(), DynError> {
    ensure_stop_deadline(deadline)?;
    let paths =
        RuntimePaths::for_test(&entry.runtime_root, &entry.session_key, &entry.workspace_id);
    if paths.scope.scope_key != entry.scope_key {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "registered runtime scope is inconsistent",
        )
        .into());
    }
    let coordinator_observed = observed_process_proof(entry.coordinator_pid)?;
    let broker_observed = observed_process_proof(entry.broker_pid)?;
    if coordinator_observed.is_none() && broker_observed.is_none() {
        match read_descriptor(&paths) {
            Err(herdr_a2a_broker::runtime::RuntimeError::Io(error))
                if error.kind() == io::ErrorKind::NotFound => {}
            Ok(descriptor) => {
                if descriptor.session_key != entry.session_key
                    || descriptor.workspace_id != entry.workspace_id
                    || descriptor.broker_pid != entry.broker_pid
                    || descriptor.broker_instance_id != entry.broker_instance_id
                    || descriptor.executable_path != entry.executable_path
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "retired registered broker descriptor identity changed",
                    )
                    .into());
                }
                if managed::managed_executable_digest(&entry.executable_path)?
                    != entry.executable_digest
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "retired registered executable digest changed",
                    )
                    .into());
                }
                let mut lock_file = CoordinatorLock::open(&paths, false)?;
                match flock(&lock_file, FlockOperation::NonBlockingLockExclusive) {
                    Ok(()) => {}
                    Err(rustix::io::Errno::WOULDBLOCK) => {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "retired registered coordinator lock is still held",
                        )
                        .into());
                    }
                    Err(error) => return Err(io::Error::from(error).into()),
                }
                let coordinator = read_record(&mut lock_file)?;
                if coordinator.pid != entry.coordinator_pid
                    || coordinator.start_identity != entry.coordinator_start
                    || coordinator.scope_key != entry.scope_key
                    || coordinator.control_port != entry.control_port
                    || coordinator.control_nonce != entry.control_nonce
                    || coordinator.broker_instance_id.as_deref() != Some(&entry.broker_instance_id)
                    || coordinator.broker_start_identity.as_deref() != Some(&entry.broker_start)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "retired registered coordinator control generation changed",
                    )
                    .into());
                }
                herdr_a2a_broker::runtime::remove_descriptor_if_instance(
                    &paths,
                    &entry.broker_instance_id,
                )?;
            }
            Err(error) => return Err(error.into()),
        }
        ensure_stop_deadline(deadline)?;
        managed::unregister_managed_process(entry)?;
        return Ok(());
    }
    validate_registered_process(entry.coordinator_pid, &entry.coordinator_start, entry)?;
    validate_registered_process(entry.broker_pid, &entry.broker_start, entry)?;
    let descriptor = read_descriptor(&paths)?;
    if descriptor.session_key != entry.session_key
        || descriptor.workspace_id != entry.workspace_id
        || descriptor.broker_pid != entry.broker_pid
        || descriptor.broker_instance_id != entry.broker_instance_id
        || descriptor.executable_path != entry.executable_path
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "registered broker descriptor identity changed",
        )
        .into());
    }
    if managed::managed_executable_digest(&entry.executable_path)? != entry.executable_digest {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "registered executable digest changed",
        )
        .into());
    }

    let mut lock_file = CoordinatorLock::open(&paths, false)?;
    match flock(&lock_file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "registered coordinator is no longer holding its lock",
            )
            .into());
        }
        Err(rustix::io::Errno::WOULDBLOCK) => {}
        Err(error) => return Err(io::Error::from(error).into()),
    }
    let coordinator = read_record(&mut lock_file)?;
    if coordinator.pid != entry.coordinator_pid
        || coordinator.start_identity != entry.coordinator_start
        || coordinator.scope_key != entry.scope_key
        || coordinator.control_port != entry.control_port
        || coordinator.control_nonce != entry.control_nonce
        || coordinator.broker_instance_id.as_deref() != Some(&entry.broker_instance_id)
        || coordinator.broker_start_identity.as_deref() != Some(&entry.broker_start)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "registered coordinator control generation changed",
        )
        .into());
    }

    loop {
        ensure_stop_deadline(deadline)?;
        let _ = request_stop(&coordinator, deadline).await;
        match flock(&lock_file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {
                ensure_stop_deadline(deadline)?;
                break;
            }
            Err(rustix::io::Errno::WOULDBLOCK) => {}
            Err(error) => return Err(io::Error::from(error).into()),
        }
        sleep_until_stop_recheck(deadline, deadline).await?;
    }
    match read_descriptor(&paths) {
        Err(herdr_a2a_broker::runtime::RuntimeError::Io(error))
            if error.kind() == io::ErrorKind::NotFound => {}
        Ok(observed) if observed.broker_instance_id != entry.broker_instance_id => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "broker instance changed while registered coordinator stopped",
            )
            .into());
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "registered broker descriptor remained after stop",
            )
            .into());
        }
        Err(error) => return Err(error.into()),
    }
    let coordinator_retired = require_registered_process_retired(
        entry.coordinator_pid,
        &entry.coordinator_start,
        &entry.executable_path,
    );
    let broker_retired = require_registered_process_retired(
        entry.broker_pid,
        &entry.broker_start,
        &entry.executable_path,
    );
    coordinator_retired?;
    broker_retired?;
    ensure_stop_deadline(deadline)?;
    Ok(())
}

#[cfg_attr(test, allow(dead_code))]
pub(crate) async fn stop_starting_process(
    entry: &managed::ManagedStartingProcessEntry,
    deadline: tokio::time::Instant,
) -> Result<(), DynError> {
    ensure_stop_deadline(deadline)?;
    let paths =
        RuntimePaths::for_test(&entry.runtime_root, &entry.session_key, &entry.workspace_id);
    if paths.scope.scope_key != entry.scope_key {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "starting runtime scope is inconsistent",
        )
        .into());
    }
    if managed::managed_executable_digest(&entry.executable_path)? != entry.executable_digest {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "starting executable digest changed",
        )
        .into());
    }
    validate_reserved_process(
        entry.coordinator_pid,
        &entry.coordinator_start,
        &entry.executable_path,
    )?;
    let coordinator_absent = observed_process_proof(entry.coordinator_pid)?.is_none();
    if coordinator_absent {
        wait_for_unheld_starting_coordinator_lock(&paths, entry, deadline).await?;
    }
    if let Some(broker) = &entry.broker {
        validate_reserved_process(
            broker.broker_pid,
            &broker.broker_start,
            &broker.executable_path,
        )?;
        starting_descriptor(&paths, entry, broker)?;
    }

    force_retire_reserved_process(
        entry.coordinator_pid,
        &entry.coordinator_start,
        &entry.executable_path,
        deadline,
    )
    .await?;
    if let Some(broker) = &entry.broker {
        force_retire_reserved_process(
            broker.broker_pid,
            &broker.broker_start,
            &broker.executable_path,
            deadline,
        )
        .await?;
        if let Some(descriptor) = starting_descriptor(&paths, entry, broker)? {
            herdr_a2a_broker::runtime::remove_descriptor_if_instance(
                &paths,
                &descriptor.broker_instance_id,
            )?;
        }
    }
    wait_for_unheld_starting_coordinator_lock(&paths, entry, deadline).await?;
    ensure_stop_deadline(deadline)?;
    Ok(())
}

fn starting_descriptor(
    paths: &RuntimePaths,
    entry: &managed::ManagedStartingProcessEntry,
    broker: &managed::ManagedStartingBrokerProof,
) -> Result<Option<RuntimeDescriptor>, DynError> {
    match read_descriptor(paths) {
        Ok(descriptor)
            if descriptor.session_key == entry.session_key
                && descriptor.workspace_id == entry.workspace_id
                && descriptor.broker_pid == broker.broker_pid
                && descriptor.executable_path == broker.executable_path =>
        {
            Ok(Some(descriptor))
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "starting broker descriptor identity changed",
        )
        .into()),
        Err(herdr_a2a_broker::runtime::RuntimeError::Io(error))
            if error.kind() == io::ErrorKind::NotFound =>
        {
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}

async fn wait_for_unheld_starting_coordinator_lock(
    paths: &RuntimePaths,
    entry: &managed::ManagedStartingProcessEntry,
    deadline: tokio::time::Instant,
) -> Result<(), DynError> {
    loop {
        let mut file = match CoordinatorLock::open(paths, false) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        match flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {
                return match read_record(&mut file) {
                    Ok(record)
                        if record.scope_key == entry.scope_key
                            && record.pid == entry.coordinator_pid
                            && record.start_identity == entry.coordinator_start =>
                    {
                        Ok(())
                    }
                    Ok(_) => Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "starting coordinator lock identity changed",
                    )
                    .into()),
                    Err(error) if error.kind() == io::ErrorKind::InvalidData => Ok(()),
                    Err(error) => Err(error.into()),
                };
            }
            Err(rustix::io::Errno::WOULDBLOCK) => {}
            Err(error) => return Err(io::Error::from(error).into()),
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "starting coordinator lock remains held",
            )
            .into());
        }
        tokio::time::sleep(remaining.min(DESCRIPTOR_RECHECK)).await;
    }
}

#[cfg_attr(test, allow(dead_code))]
fn validate_reserved_process(pid: u32, start: &str, executable: &Path) -> io::Result<()> {
    let Some(observed) = observed_process_proof(pid)? else {
        return Ok(());
    };
    if observed.start_identity != start || observed.executable.as_deref() != Some(executable) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "reserved process start identity or executable changed",
        ));
    }
    Ok(())
}

#[cfg_attr(test, allow(dead_code))]
async fn force_retire_reserved_process(
    pid: u32,
    start: &str,
    executable: &Path,
    deadline: tokio::time::Instant,
) -> io::Result<()> {
    ensure_stop_deadline(deadline)?;
    let Some(observed) = observed_process_proof(pid)? else {
        ensure_stop_deadline(deadline)?;
        return Ok(());
    };
    if observed.start_identity != start || observed.executable.as_deref() != Some(executable) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "reserved process identity changed before retirement",
        ));
    }
    let raw_pid = i32::try_from(pid)
        .ok()
        .and_then(Pid::from_raw)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "reserved PID is invalid"))?;
    let _ = kill_process(raw_pid, Signal::TERM);
    let term_deadline = bounded_stop_deadline(deadline, Duration::from_secs(1))?;
    while tokio::time::Instant::now() < term_deadline {
        if observed_process_proof(pid)?.is_none() {
            ensure_stop_deadline(deadline)?;
            return Ok(());
        }
        sleep_until_stop_recheck(deadline, term_deadline).await?;
    }
    ensure_stop_deadline(deadline)?;
    validate_reserved_process(pid, start, executable)?;
    let _ = kill_process(raw_pid, Signal::KILL);
    let kill_deadline = bounded_stop_deadline(deadline, Duration::from_secs(3))?;
    while tokio::time::Instant::now() < kill_deadline {
        if observed_process_proof(pid)?.is_none() {
            ensure_stop_deadline(deadline)?;
            return Ok(());
        }
        sleep_until_stop_recheck(deadline, kill_deadline).await?;
    }
    ensure_stop_deadline(deadline)?;
    require_registered_process_retired(pid, start, executable)
}

fn ensure_stop_deadline(deadline: tokio::time::Instant) -> io::Result<()> {
    if tokio::time::Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "managed process drain deadline expired",
        ));
    }
    Ok(())
}

fn bounded_stop_deadline(
    shared_deadline: tokio::time::Instant,
    phase_limit: Duration,
) -> io::Result<tokio::time::Instant> {
    ensure_stop_deadline(shared_deadline)?;
    Ok(shared_deadline.min(tokio::time::Instant::now() + phase_limit))
}

async fn sleep_until_stop_recheck(
    shared_deadline: tokio::time::Instant,
    wake_deadline: tokio::time::Instant,
) -> io::Result<()> {
    ensure_stop_deadline(shared_deadline)?;
    let remaining = wake_deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        return Ok(());
    }
    tokio::time::sleep(remaining.min(DESCRIPTOR_RECHECK)).await;
    ensure_stop_deadline(shared_deadline)
}

struct ProcessProof {
    start_identity: String,
    executable: Option<PathBuf>,
}

#[cfg(all(not(test), target_os = "linux"))]
fn validate_registered_process(
    pid: u32,
    expected_start: &str,
    entry: &managed::ManagedProcessEntry,
) -> io::Result<()> {
    let observed = observed_process_proof(pid)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "registered process is absent",
        )
    })?;
    if observed.start_identity != expected_start
        || observed
            .executable
            .as_ref()
            .is_some_and(|path| path != &entry.executable_path)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "registered process start identity or executable changed",
        ));
    }
    Ok(())
}

#[cfg(all(not(test), target_os = "macos"))]
fn validate_registered_process(
    pid: u32,
    expected_start: &str,
    entry: &managed::ManagedProcessEntry,
) -> io::Result<()> {
    require_process_proof(pid, expected_start, &entry.executable_path)
}

#[cfg(target_os = "linux")]
fn registration_process_proof(
    pid: u32,
    _fallback_start: &str,
    _executable: &Path,
) -> io::Result<Option<ProcessProof>> {
    observed_process_proof(pid)
}

#[cfg(target_os = "macos")]
fn registration_process_proof(
    pid: u32,
    _fallback_start: &str,
    _executable: &Path,
) -> io::Result<Option<ProcessProof>> {
    observed_process_proof(pid)
}

#[cfg(target_os = "linux")]
fn observed_process_proof(pid: u32) -> io::Result<Option<ProcessProof>> {
    let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let after_name = stat
        .rsplit_once(") ")
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "process stat identity is malformed",
            )
        })?
        .1;
    let fields: Vec<&str> = after_name.split_whitespace().collect();
    if fields.len() <= 19 || fields[0] == "Z" {
        return Ok(None);
    }
    let start_identity = fields[19].to_owned();
    if !start_identity.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "process start identity is malformed",
        ));
    }
    let executable = match fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(path) => path.canonicalize()?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    Ok(Some(ProcessProof {
        start_identity,
        executable: Some(executable),
    }))
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct ProcBsdInfo {
    pbi_flags: u32,
    pbi_status: u32,
    pbi_xstatus: u32,
    pbi_pid: u32,
    pbi_ppid: u32,
    pbi_uid: u32,
    pbi_gid: u32,
    pbi_ruid: u32,
    pbi_rgid: u32,
    pbi_svuid: u32,
    pbi_svgid: u32,
    rfu_1: u32,
    pbi_comm: [std::ffi::c_char; 16],
    pbi_name: [std::ffi::c_char; 32],
    pbi_nfiles: u32,
    pbi_pgid: u32,
    pbi_pjobc: u32,
    e_tdev: u32,
    e_tpgid: u32,
    pbi_nice: i32,
    pbi_start_tvsec: u64,
    pbi_start_tvusec: u64,
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn proc_pidinfo(
        pid: std::ffi::c_int,
        flavor: std::ffi::c_int,
        arg: u64,
        buffer: *mut std::ffi::c_void,
        buffersize: std::ffi::c_int,
    ) -> std::ffi::c_int;
    fn proc_pidpath(
        pid: std::ffi::c_int,
        buffer: *mut std::ffi::c_void,
        buffersize: u32,
    ) -> std::ffi::c_int;
}

#[cfg(target_os = "macos")]
fn observed_process_proof(pid: u32) -> io::Result<Option<ProcessProof>> {
    const PROC_PIDTBSDINFO: std::ffi::c_int = 3;
    const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;
    let native_pid = std::ffi::c_int::try_from(pid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "process PID is invalid"))?;
    if native_pid <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "process PID is invalid",
        ));
    }
    let mut info = std::mem::MaybeUninit::<ProcBsdInfo>::zeroed();
    // SAFETY: both libproc calls receive correctly sized writable buffers for the duration of
    // each call. A short/zero return is treated as absence and the uninitialized value is not read.
    let info_size = unsafe {
        proc_pidinfo(
            native_pid,
            PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            std::mem::size_of::<ProcBsdInfo>() as std::ffi::c_int,
        )
    };
    if info_size == 0 {
        return Ok(None);
    }
    if info_size as usize != std::mem::size_of::<ProcBsdInfo>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native process start proof is incomplete",
        ));
    }
    // SAFETY: the exact structure size was returned above.
    let info = unsafe { info.assume_init() };
    if info.pbi_pid != pid || info.pbi_start_tvsec == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native process start proof is invalid",
        ));
    }
    let mut path_buffer = [0_u8; PROC_PIDPATHINFO_MAXSIZE];
    // SAFETY: path_buffer is writable and its exact capacity is supplied to libproc.
    let path_length = unsafe {
        proc_pidpath(
            native_pid,
            path_buffer.as_mut_ptr().cast(),
            path_buffer.len() as u32,
        )
    };
    if path_length == 0 {
        return Ok(None);
    }
    let path_length = usize::try_from(path_length).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "native executable path is invalid",
        )
    })?;
    if path_length >= path_buffer.len() || path_buffer[path_length..].first() != Some(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native executable path is oversized",
        ));
    }
    let executable =
        PathBuf::from(OsStr::from_bytes(&path_buffer[..path_length])).canonicalize()?;
    Ok(Some(ProcessProof {
        start_identity: format!("{}:{}", info.pbi_start_tvsec, info.pbi_start_tvusec),
        executable: Some(executable),
    }))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn require_registered_process_retired(
    pid: u32,
    expected_start: &str,
    expected_executable: &Path,
) -> io::Result<()> {
    let Some(observed) = observed_process_proof(pid)? else {
        return Ok(());
    };
    let message = if observed.start_identity == expected_start
        && observed.executable.as_deref() == Some(expected_executable)
    {
        "registered process remained alive after coordinated stop"
    } else {
        "registered PID identity changed before retirement was proven"
    };
    Err(io::Error::new(io::ErrorKind::PermissionDenied, message))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn require_process_proof(
    pid: u32,
    expected_start: &str,
    expected_executable: &Path,
) -> io::Result<()> {
    let observed = observed_process_proof(pid)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "registered process is absent",
        )
    })?;
    if observed.start_identity != expected_start
        || observed.executable.as_deref() != Some(expected_executable)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "registered process start identity or executable changed",
        ));
    }
    Ok(())
}

async fn stop_expected(expected_instance: Option<&str>) -> Result<(), DynError> {
    let paths = RuntimePaths::discover()?;
    let mut file = match CoordinatorLock::open(&paths, false) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    match flock(&file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => return Ok(()),
        Err(rustix::io::Errno::WOULDBLOCK) => {}
        Err(error) => return Err(io::Error::from(error).into()),
    }

    let deadline = tokio::time::Instant::now() + STOP_TIMEOUT;
    loop {
        match flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(()),
            Err(rustix::io::Errno::WOULDBLOCK) => {}
            Err(error) => return Err(io::Error::from(error).into()),
        }
        match read_record(&mut file) {
            Ok(record) if record.scope_key == paths.scope.scope_key => {
                if let Some(expected) = expected_instance {
                    if record.broker_instance_id.as_deref() != Some(expected) {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "coordinator owns a different broker instance",
                        )
                        .into());
                    }
                    match read_descriptor(&paths) {
                        Ok(descriptor) if descriptor.broker_instance_id == expected => {}
                        Err(herdr_a2a_broker::runtime::RuntimeError::Io(error))
                            if error.kind() == io::ErrorKind::NotFound => {}
                        _ => {
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "broker instance changed before coordinated stop",
                            )
                            .into());
                        }
                    }
                }
                // The record is a generation-specific capability, not merely a reusable PID.
                // Re-read it on every busy iteration so an A -> B lock turnover cannot be lost.
                let _ = request_stop(&record, deadline).await;
                pause_starting_boundary("after-stop-request-before-lock-check").await?;
            }
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "coordinator lock belongs to another runtime scope",
                )
                .into());
            }
            Err(_) if tokio::time::Instant::now() < deadline => {}
            Err(error) => return Err(error.into()),
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "coordinator stop deadline expired",
            )
            .into());
        }
        tokio::time::sleep(DESCRIPTOR_RECHECK).await;
    }
}

async fn request_stop(
    record: &CoordinatorRecord,
    deadline: tokio::time::Instant,
) -> io::Result<()> {
    validate_control_record(record)?;
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "coordinator stop deadline expired",
        ));
    }
    tokio::time::timeout(remaining.min(Duration::from_millis(250)), async {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, record.control_port)).await?;
        stream.write_all(record.control_nonce.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        stream.shutdown().await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "coordinator control timed out"))?
}

struct ControlServer {
    listener: TcpListener,
    port: u16,
    nonce: String,
}

impl ControlServer {
    async fn bind() -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let mut random = [0_u8; 32];
        getrandom::fill(&mut random)
            .map_err(|error| io::Error::other(format!("secure randomness unavailable: {error}")))?;
        let nonce = random.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(Self {
            listener,
            port,
            nonce,
        })
    }

    async fn wait(&self) -> io::Result<()> {
        loop {
            let (mut stream, peer) = self.listener.accept().await?;
            if !peer.ip().is_loopback() {
                continue;
            }
            let mut request = [0_u8; 65];
            if tokio::time::timeout(Duration::from_millis(250), stream.read_exact(&mut request))
                .await
                .is_ok_and(|result| result.is_ok())
                && request[64] == b'\n'
                && request[..64] == *self.nonce.as_bytes()
            {
                return Ok(());
            }
        }
    }
}

fn validate_control_record(record: &CoordinatorRecord) -> io::Result<()> {
    if record.control_port == 0
        || record.start_identity.is_empty()
        || record.start_identity.len() > 128
        || record
            .broker_start_identity
            .as_ref()
            .is_some_and(|identity| identity.is_empty() || identity.len() > 256)
        || record.control_nonce.len() != 64
        || !record
            .control_nonce
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || record.broker_instance_id.as_ref().is_some_and(|instance| {
            instance.len() != 43
                || !instance
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid coordinator control generation",
        ));
    }
    Ok(())
}

async fn wait_for_owned_descriptor(
    paths: &RuntimePaths,
    child: &mut Child,
    child_pid: u32,
    deadline: tokio::time::Instant,
) -> Result<RuntimeDescriptor, DynError> {
    loop {
        if tokio::time::Instant::now() >= deadline {
            terminate_child(child).await?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "broker descriptor publication timed out",
            )
            .into());
        }
        if let Some(descriptor) = protected_descriptor(paths, deadline).await? {
            if descriptor.broker_pid != child_pid {
                terminate_child(child).await?;
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "published broker descriptor does not belong to the owned child",
                )
                .into());
            }
            return Ok(descriptor);
        }
        tokio::select! {
            status = child.wait() => {
                return Err(io::Error::other(format!(
                    "broker exited before descriptor publication: {}",
                    status?
                )).into());
            }
            _ = tokio::time::sleep(DESCRIPTOR_RECHECK) => {}
        }
    }
}

async fn wait_for_protected_descriptor(
    paths: &RuntimePaths,
    deadline: tokio::time::Instant,
    watcher: Option<&DescriptorWatcher>,
) -> Result<RuntimeDescriptor, LaunchError> {
    loop {
        if let Some(descriptor) = protected_descriptor(paths, deadline).await? {
            return Ok(descriptor);
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(LaunchError::Deadline);
        }
        let bounded_recheck = tokio::time::sleep(DESCRIPTOR_RECHECK.min(remaining));
        tokio::pin!(bounded_recheck);
        match watcher {
            Some(watcher) => tokio::select! {
                _ = &mut bounded_recheck => {}
                _ = watcher.changed() => {}
            },
            None => bounded_recheck.await,
        }
    }
}

struct DescriptorWatcher {
    changes: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<()>>,
}

impl DescriptorWatcher {
    fn new(root: &Path) -> io::Result<Self> {
        let (changes, receiver) = tokio::sync::mpsc::channel(1);
        spawn_descriptor_watcher(root.to_path_buf(), changes)?;
        Ok(Self {
            changes: tokio::sync::Mutex::new(receiver),
        })
    }

    async fn changed(&self) {
        let mut receiver = self.changes.lock().await;
        let _ = receiver.recv().await;
    }
}

#[cfg(target_os = "linux")]
fn spawn_descriptor_watcher(
    root: PathBuf,
    changes: tokio::sync::mpsc::Sender<()>,
) -> io::Result<()> {
    use std::mem::MaybeUninit;

    use rustix::fs::inotify;

    let inotify = inotify::init(inotify::CreateFlags::CLOEXEC | inotify::CreateFlags::NONBLOCK)
        .map_err(io::Error::from)?;
    inotify::add_watch(
        &inotify,
        &root,
        inotify::WatchFlags::CREATE
            | inotify::WatchFlags::CLOSE_WRITE
            | inotify::WatchFlags::MOVED_TO
            | inotify::WatchFlags::DELETE,
    )
    .map_err(io::Error::from)?;
    thread::spawn(move || {
        let mut buffer = [MaybeUninit::uninit(); 1024];
        while !changes.is_closed() {
            let mut reader = inotify::Reader::new(&inotify, &mut buffer);
            let mut observed = false;
            loop {
                match reader.next() {
                    Ok(_) => observed = true,
                    Err(rustix::io::Errno::WOULDBLOCK) => break,
                    Err(_) => return,
                }
            }
            if observed {
                let _ = changes.try_send(());
            }
            thread::sleep(DESCRIPTOR_RECHECK);
        }
    });
    Ok(())
}

#[cfg(target_os = "macos")]
fn spawn_descriptor_watcher(
    root: PathBuf,
    changes: tokio::sync::mpsc::Sender<()>,
) -> io::Result<()> {
    use std::{mem::MaybeUninit, os::fd::AsRawFd, ptr};

    use rustix::event::kqueue::{Event, EventFilter, EventFlags, VnodeEvents, kevent, kqueue};

    let directory = open(
        &root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let queue = kqueue().map_err(io::Error::from)?;
    thread::spawn(move || {
        let change = Event::new(
            EventFilter::Vnode {
                vnode: directory.as_raw_fd(),
                flags: VnodeEvents::WRITE
                    | VnodeEvents::EXTEND
                    | VnodeEvents::RENAME
                    | VnodeEvents::ATTRIBUTES,
            },
            EventFlags::ADD | EventFlags::CLEAR,
            ptr::null_mut(),
        );
        let mut register = true;
        loop {
            if changes.is_closed() {
                return;
            }
            let mut events = [MaybeUninit::<Event>::uninit(); 1];
            let changelist = if register {
                register = false;
                std::slice::from_ref(&change)
            } else {
                &[]
            };
            let observed = unsafe {
                kevent(
                    &queue,
                    changelist,
                    &mut events[..],
                    Some(DESCRIPTOR_RECHECK),
                )
            };
            match observed {
                Ok(events) if !events.0.is_empty() => {
                    let _ = changes.try_send(());
                }
                Ok(_) => {}
                Err(_) => return,
            }
        }
    });
    Ok(())
}

async fn protected_descriptor(
    paths: &RuntimePaths,
    deadline: tokio::time::Instant,
) -> Result<Option<RuntimeDescriptor>, LaunchError> {
    let descriptor = match read_descriptor(paths) {
        Ok(descriptor) => descriptor,
        Err(herdr_a2a_broker::runtime::RuntimeError::Io(error))
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::WouldBlock
            ) =>
        {
            return Ok(None);
        }
        Err(_) => return Ok(None),
    };
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        return Err(LaunchError::Deadline);
    }
    let client = reqwest::Client::builder()
        .connect_timeout(remaining.min(Duration::from_millis(500)))
        .timeout(remaining.min(Duration::from_secs(2)))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(launch_unavailable)?;
    match tokio::time::timeout(
        remaining,
        verify_broker_proof(
            &client,
            &descriptor.base_url,
            &descriptor.bearer_token,
            &descriptor.broker_instance_id,
        ),
    )
    .await
    {
        Ok(Ok(())) => Ok(Some(descriptor)),
        Ok(Err(error)) if error.downcast_ref::<reqwest::Error>().is_some() => Ok(None),
        Ok(Err(error)) => Err(LaunchError::ProofInvalid(error.to_string())),
        Err(_) => Err(LaunchError::Deadline),
    }
}

async fn terminate_child(child: &mut Child) -> io::Result<()> {
    if let Some(raw_pid) = child
        .id()
        .and_then(|pid| i32::try_from(pid).ok())
        .and_then(Pid::from_raw)
    {
        let _ = kill_process(raw_pid, Signal::TERM);
    }
    match tokio::time::timeout(Duration::from_secs(3), child.wait()).await {
        Ok(result) => result.map(|_| ()),
        Err(_) => {
            child.start_kill()?;
            child.wait().await.map(|_| ())
        }
    }
}

fn validated_broker_environment(
    paths: &RuntimePaths,
) -> Result<Vec<(OsString, OsString)>, DynError> {
    let socket = required_environment_path("HERDR_SOCKET_PATH")?;
    validate_absolute(&socket, "HERDR_SOCKET_PATH")?;
    let workspace = env::var_os("HERDR_WORKSPACE_ID")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "HERDR_WORKSPACE_ID is required",
            )
        })?;
    if workspace != OsStr::new(&paths.scope.workspace_id) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "HERDR_WORKSPACE_ID changed after runtime discovery",
        )
        .into());
    }
    let herdr = validate_herdr_executable(&required_path("HERDR_BIN_PATH")?)?;
    let plugin_state = required_environment_path("HERDR_PLUGIN_STATE_DIR")?;
    validate_absolute(&plugin_state, "HERDR_PLUGIN_STATE_DIR")?;

    let mut inherited = vec![
        (OsString::from("HERDR_SOCKET_PATH"), socket.into_os_string()),
        (OsString::from("HERDR_WORKSPACE_ID"), workspace),
        (OsString::from("HERDR_BIN_PATH"), herdr.into_os_string()),
        (
            OsString::from("HERDR_PLUGIN_STATE_DIR"),
            plugin_state.into_os_string(),
        ),
    ];
    #[cfg(target_os = "macos")]
    inherited.push((
        OsString::from("TMPDIR"),
        required_environment_path("TMPDIR")?.into_os_string(),
    ));
    #[cfg(target_os = "linux")]
    if let Some(value) = env::var_os("XDG_RUNTIME_DIR").filter(|value| !value.is_empty()) {
        inherited.push((OsString::from("XDG_RUNTIME_DIR"), value));
    }
    Ok(inherited)
}

fn required_environment_path(name: &'static str) -> Result<PathBuf, DynError> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("{name} is required")).into()
        })
}

fn validate_absolute(path: &Path, name: &'static str) -> Result<(), DynError> {
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().contains(&0)
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be a normalized absolute path"),
        )
        .into());
    }
    Ok(())
}

fn launch_unavailable(error: impl std::fmt::Display) -> LaunchError {
    LaunchError::Unavailable(error.to_string())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CoordinatorRecord {
    pid: u32,
    start_identity: String,
    scope_key: String,
    control_port: u16,
    control_nonce: String,
    broker_instance_id: Option<String>,
    broker_start_identity: Option<String>,
}

struct CoordinatorLock {
    _file: File,
}

enum LockAcquisition {
    Owned(CoordinatorLock),
    Busy,
}

impl CoordinatorLock {
    fn acquire(paths: &RuntimePaths) -> Result<LockAcquisition, DynError> {
        let file = Self::open(paths, true)?;
        match flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {}
            Err(rustix::io::Errno::WOULDBLOCK) => return Ok(LockAcquisition::Busy),
            Err(error) => return Err(io::Error::from(error).into()),
        }
        Ok(LockAcquisition::Owned(Self { _file: file }))
    }

    fn open(paths: &RuntimePaths, create: bool) -> io::Result<File> {
        match read_descriptor(paths) {
            Ok(_) => {}
            Err(herdr_a2a_broker::runtime::RuntimeError::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::WouldBlock
                ) => {}
            Err(
                herdr_a2a_broker::runtime::RuntimeError::Json(_)
                | herdr_a2a_broker::runtime::RuntimeError::InvalidDescriptor(_)
                | herdr_a2a_broker::runtime::RuntimeError::SessionMismatch
                | herdr_a2a_broker::runtime::RuntimeError::WorkspaceMismatch,
            ) => {}
            Err(error) => return Err(io::Error::other(error)),
        }
        let path = paths
            .root
            .join(format!("{}.coordinator.lock", paths.scope.scope_key));
        let mut flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        if create {
            flags |= OFlags::CREATE;
        }
        let file =
            File::from(open(&path, flags, Mode::RUSR | Mode::WUSR).map_err(io::Error::from)?);
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.uid() != rustix::process::getuid().as_raw()
            || metadata.nlink() != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "coordinator lock is not a private owned file",
            ));
        }
        rustix::fs::fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(io::Error::from)?;
        if file.metadata()?.mode() & 0o777 != 0o600 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "coordinator lock permissions are unsafe",
            ));
        }
        Ok(file)
    }

    fn publish(
        &self,
        paths: &RuntimePaths,
        control: &ControlServer,
        start_identity: &str,
    ) -> io::Result<()> {
        let mut file = self._file.try_clone()?;
        write_record(
            &mut file,
            &CoordinatorRecord {
                pid: std::process::id(),
                start_identity: start_identity.to_owned(),
                scope_key: paths.scope.scope_key.clone(),
                control_port: control.port,
                control_nonce: control.nonce.clone(),
                broker_instance_id: None,
                broker_start_identity: None,
            },
        )
    }

    fn bind_broker(
        &self,
        paths: &RuntimePaths,
        control: &ControlServer,
        descriptor: &RuntimeDescriptor,
        start_identity: &str,
        broker_start_identity: &str,
    ) -> io::Result<()> {
        let mut file = self._file.try_clone()?;
        write_record(
            &mut file,
            &CoordinatorRecord {
                pid: std::process::id(),
                start_identity: start_identity.to_owned(),
                scope_key: paths.scope.scope_key.clone(),
                control_port: control.port,
                control_nonce: control.nonce.clone(),
                broker_instance_id: Some(descriptor.broker_instance_id.clone()),
                broker_start_identity: Some(broker_start_identity.to_owned()),
            },
        )
    }
}

fn write_record(file: &mut File, record: &CoordinatorRecord) -> io::Result<()> {
    let encoded = serde_json::to_vec(record).map_err(io::Error::other)?;
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&encoded)?;
    file.sync_all()
}

fn read_record(file: &mut File) -> io::Result<CoordinatorRecord> {
    file.seek(SeekFrom::Start(0))?;
    let mut encoded = Vec::new();
    file.take(MAX_COORDINATOR_RECORD_BYTES + 1)
        .read_to_end(&mut encoded)?;
    if encoded.is_empty() || encoded.len() as u64 > MAX_COORDINATOR_RECORD_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "coordinator lock record is empty or oversized",
        ));
    }
    serde_json::from_slice(&encoded).map_err(io::Error::other)
}

#[cfg(test)]
mod deadline_configuration_tests {
    use super::*;

    #[test]
    fn default_ensure_timeout_never_exceeds_ten_seconds() {
        // Break caught: broad restart tests retain scheduler-tolerant outer deadlines after the
        // configured launch cap is relaxed above the product's strict ten-second maximum.
        assert!(
            DEFAULT_ENSURE_TIMEOUT <= Duration::from_secs(10),
            "configured broker launch cap exceeds ten seconds"
        );
    }
}

#[cfg(all(test, target_os = "macos"))]
mod macos_process_proof_tests {
    use super::*;

    struct ChildGuard(std::process::Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn native_process_proof_rejects_executable_substitution_and_pid_reuse() {
        let child = std::process::Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .expect("spawn private proof fixture");
        let mut child = ChildGuard(child);
        let pid = child.0.id();
        let proof = observed_process_proof(pid)
            .expect("query native process proof")
            .expect("live child proof");
        assert_eq!(
            proof.executable,
            Some(
                Path::new("/bin/sleep")
                    .canonicalize()
                    .expect("canonical sleep")
            )
        );
        require_process_proof(
            pid,
            &proof.start_identity,
            proof.executable.as_ref().unwrap(),
        )
        .expect("exact native proof");
        assert!(require_process_proof(pid, &proof.start_identity, Path::new("/bin/sh")).is_err());
        assert!(require_process_proof(pid, "0:0", proof.executable.as_ref().unwrap()).is_err());
        assert!(
            require_registered_process_retired(
                pid,
                &proof.start_identity,
                proof.executable.as_ref().unwrap(),
            )
            .is_err()
        );
        child.0.kill().expect("stop private proof fixture");
        child.0.wait().expect("retire private proof fixture");
        require_registered_process_retired(
            pid,
            &proof.start_identity,
            proof.executable.as_ref().unwrap(),
        )
        .expect("exact native retirement proof");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_process_proof_tests {
    use super::*;

    struct ChildGuard(std::process::Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    async fn wait_for_exec_proof(pid: u32, executable: &Path) -> ProcessProof {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let proof = observed_process_proof(pid)
                .expect("query /proc process proof")
                .expect("live child proof");
            if proof.executable.as_deref() == Some(executable) {
                return proof;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "private /proc fixture did not exec the expected executable; observed {:?}",
                proof.executable
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test]
    async fn proc_proof_signals_only_the_exact_process_and_proves_positive_retirement() {
        // Break caught: the supported Linux signal path had no positive gate covering exact
        // retirement alongside stale, PID-substituted, and executable-substituted proofs.
        let child = std::process::Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .expect("spawn private /proc proof fixture");
        let mut child = ChildGuard(child);
        let pid = child.0.id();
        let executable = Path::new("/bin/sleep")
            .canonicalize()
            .expect("canonical sleep");
        let proof = wait_for_exec_proof(pid, &executable).await;
        assert_eq!(proof.executable, Some(executable.clone()));
        require_process_proof(pid, &proof.start_identity, &executable)
            .expect("exact /proc process proof");
        assert!(
            require_process_proof(pid, "0", &executable).is_err(),
            "PID/starttime substitution was accepted by exact proof"
        );
        assert!(
            require_process_proof(pid, &proof.start_identity, Path::new("/bin/sh")).is_err(),
            "executable substitution was accepted by exact proof"
        );

        assert!(
            force_retire_reserved_process(
                pid,
                "0",
                &executable,
                tokio::time::Instant::now() + STOP_TIMEOUT,
            )
            .await
            .is_err(),
            "PID/starttime substitution was accepted"
        );
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "stale proof signalled child"
        );
        assert!(
            force_retire_reserved_process(
                pid,
                &proof.start_identity,
                Path::new("/bin/sh"),
                tokio::time::Instant::now() + STOP_TIMEOUT,
            )
            .await
            .is_err(),
            "executable substitution was accepted"
        );
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "executable mismatch signalled child"
        );
        force_retire_reserved_process(
            pid,
            &proof.start_identity,
            &executable,
            tokio::time::Instant::now() + STOP_TIMEOUT,
        )
        .await
        .expect("exact /proc proof retirement");
        child.0.wait().expect("reap exact /proc fixture");
        require_registered_process_retired(pid, &proof.start_identity, &executable)
            .expect("positive /proc retirement proof");

        force_retire_reserved_process(
            u32::MAX,
            "stale",
            &executable,
            tokio::time::Instant::now() + STOP_TIMEOUT,
        )
        .await
        .expect("an absent stale PID is already retired");
    }
}
