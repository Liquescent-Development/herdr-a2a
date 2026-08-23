use std::{
    env,
    ffi::OsStr,
    fmt,
    fs::{self, File},
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddrV4},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rustix::{
    fs::{
        Access, AtFlags, CWD, FlockOperation, Mode, OFlags, accessat, fchmod, flock, linkat,
        mkdirat, open, openat, renameat, unlinkat,
    },
    process::{Pid, getuid, test_kill_process},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_DESCRIPTOR_BYTES: u64 = 64 * 1024;
const MAX_LOCK_BYTES: u64 = 4 * 1024;
static FILE_NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeScope {
    pub session_key: String,
    pub workspace_id: String,
    pub scope_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimePaths {
    pub root: PathBuf,
    pub scope: RuntimeScope,
    pub descriptor: PathBuf,
    pub lock: PathBuf,
}

impl RuntimePaths {
    pub fn discover() -> Result<Self, RuntimeError> {
        let socket_path = env::var_os("HERDR_SOCKET_PATH")
            .ok_or(RuntimeError::MissingEnvironment("HERDR_SOCKET_PATH"))?;
        if socket_path.is_empty() {
            return Err(RuntimeError::UnsafePath(PathBuf::new()));
        }
        let workspace_id = env::var("HERDR_WORKSPACE_ID").map_err(|error| match error {
            env::VarError::NotPresent => RuntimeError::MissingEnvironment("HERDR_WORKSPACE_ID"),
            env::VarError::NotUnicode(_) => RuntimeError::InvalidWorkspaceId,
        })?;
        Self::for_socket_at(
            &platform_runtime_root()?,
            Path::new(&socket_path),
            &workspace_id,
        )
    }

    pub fn for_test(root: &Path, session_key: &str, workspace_id: &str) -> Self {
        let scope = scope_from_session_key(session_key, workspace_id)
            .expect("test runtime scope must be valid");
        Self::from_scope(root.to_path_buf(), scope)
    }

    fn for_socket_at(
        root: &Path,
        socket_path: &Path,
        workspace_id: &str,
    ) -> Result<Self, RuntimeError> {
        Ok(Self::from_scope(
            root.to_path_buf(),
            scope_key(socket_path, workspace_id)?,
        ))
    }

    fn from_scope(root: PathBuf, scope: RuntimeScope) -> Self {
        let descriptor = root.join(format!("{}.json", scope.scope_key));
        let lock = root.join(format!("{}.lock", scope.scope_key));
        Self {
            root,
            scope,
            descriptor,
            lock,
        }
    }
}

fn scope_key(socket_path: &Path, workspace_id: &str) -> Result<RuntimeScope, RuntimeError> {
    validate_workspace_id(workspace_id)?;
    let session_key = digest_path(socket_path);
    scope_from_session_key(&session_key, workspace_id)
}

fn scope_from_session_key(
    session_key: &str,
    workspace_id: &str,
) -> Result<RuntimeScope, RuntimeError> {
    validate_session_key(session_key)?;
    validate_workspace_id(workspace_id)?;
    let scope_key = digest_bytes(&[session_key.as_bytes(), b"\0", workspace_id.as_bytes()]);
    Ok(RuntimeScope {
        session_key: session_key.to_owned(),
        workspace_id: workspace_id.to_owned(),
        scope_key,
    })
}

fn digest_path(path: &Path) -> String {
    #[cfg(unix)]
    let bytes = path.as_os_str().as_bytes();
    #[cfg(not(unix))]
    let bytes = path.to_string_lossy();
    #[cfg(not(unix))]
    let bytes = bytes.as_bytes();
    digest_bytes(&[bytes])
}

fn digest_bytes(parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    format!("{:x}", hasher.finalize())
}

fn validate_workspace_id(workspace_id: &str) -> Result<(), RuntimeError> {
    if workspace_id.is_empty()
        || workspace_id.len() > 256
        || workspace_id.chars().any(char::is_control)
    {
        return Err(RuntimeError::InvalidWorkspaceId);
    }
    Ok(())
}

fn validate_session_key(session_key: &str) -> Result<(), RuntimeError> {
    let valid = !session_key.is_empty()
        && session_key.len() <= 128
        && session_key.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        });
    if !valid {
        return Err(RuntimeError::UnsafePath(PathBuf::from(session_key)));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn platform_runtime_root() -> Result<PathBuf, RuntimeError> {
    let xdg_runtime_dir = env::var_os("XDG_RUNTIME_DIR");
    linux_runtime_root(xdg_runtime_dir.as_deref(), getuid().as_raw())
}

#[cfg(target_os = "macos")]
fn platform_runtime_root() -> Result<PathBuf, RuntimeError> {
    let temp_dir = env::var_os("TMPDIR");
    macos_runtime_root(temp_dir.as_deref())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn platform_runtime_root() -> Result<PathBuf, RuntimeError> {
    Err(RuntimeError::UnsupportedPlatform)
}

#[cfg(any(target_os = "linux", test))]
fn linux_runtime_root(xdg_runtime_dir: Option<&OsStr>, uid: u32) -> Result<PathBuf, RuntimeError> {
    match xdg_runtime_dir.filter(|value| !value.is_empty()) {
        Some(value) => {
            let base = PathBuf::from(value);
            validate_absolute_path(&base)?;
            Ok(base.join("herdr-a2a"))
        }
        None => Ok(PathBuf::from(format!("/tmp/herdr-a2a-{uid}"))),
    }
}

#[cfg(any(target_os = "macos", test))]
fn macos_runtime_root(temp_dir: Option<&OsStr>) -> Result<PathBuf, RuntimeError> {
    let base = temp_dir.ok_or(RuntimeError::MissingEnvironment("TMPDIR"))?;
    let base = PathBuf::from(base);
    validate_absolute_path(&base)?;
    Ok(base.join("herdr-a2a"))
}

fn validate_absolute_path(path: &Path) -> Result<(), RuntimeError> {
    if !path.is_absolute()
        || path.as_os_str().is_empty()
        || path.as_os_str().as_encoded_bytes().contains(&0)
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(RuntimeError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeDescriptor {
    pub session_key: String,
    pub workspace_id: String,
    pub base_url: String,
    pub bearer_token: String,
    pub broker_instance_id: String,
    pub executable_path: PathBuf,
    pub broker_pid: u32,
    pub created_unix_ms: i64,
}

impl fmt::Debug for RuntimeDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeDescriptor")
            .field("session_key", &self.session_key)
            .field("workspace_id", &self.workspace_id)
            .field("base_url", &self.base_url)
            .field("bearer_token", &"<redacted>")
            .field("broker_instance_id", &self.broker_instance_id)
            .field("executable_path", &self.executable_path)
            .field("broker_pid", &self.broker_pid)
            .field("created_unix_ms", &self.created_unix_ms)
            .finish()
    }
}

#[derive(Debug)]
pub enum RuntimeError {
    Io(io::Error),
    Json(serde_json::Error),
    MissingEnvironment(&'static str),
    UnsupportedPlatform,
    UnsafePath(PathBuf),
    UnsafePermissions(PathBuf),
    WrongOwner(PathBuf),
    InvalidWorkspaceId,
    SessionMismatch,
    WorkspaceMismatch,
    InvalidDescriptor(&'static str),
    SessionAlreadyOwned(u32),
    InvalidLock,
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "runtime discovery I/O failed: {error}"),
            Self::Json(error) => write!(formatter, "runtime discovery JSON is invalid: {error}"),
            Self::MissingEnvironment(name) => {
                write!(formatter, "required environment variable {name} is missing")
            }
            Self::UnsupportedPlatform => formatter.write_str("runtime discovery is unsupported"),
            Self::UnsafePath(path) => write!(formatter, "unsafe runtime path: {}", path.display()),
            Self::UnsafePermissions(path) => {
                write!(
                    formatter,
                    "runtime permissions are unsafe: {}",
                    path.display()
                )
            }
            Self::WrongOwner(path) => {
                write!(
                    formatter,
                    "runtime path has the wrong owner: {}",
                    path.display()
                )
            }
            Self::InvalidWorkspaceId => formatter.write_str("Herdr workspace ID is invalid"),
            Self::SessionMismatch => formatter.write_str("runtime descriptor session mismatch"),
            Self::WorkspaceMismatch => formatter.write_str("runtime descriptor workspace mismatch"),
            Self::InvalidDescriptor(reason) => {
                write!(formatter, "runtime descriptor is invalid: {reason}")
            }
            Self::SessionAlreadyOwned(pid) => {
                write!(formatter, "runtime session is already owned by PID {pid}")
            }
            Self::InvalidLock => formatter.write_str("runtime lock is invalid"),
        }
    }
}

impl std::error::Error for RuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for RuntimeError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for RuntimeError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

pub fn write_descriptor(
    paths: &RuntimePaths,
    descriptor: &RuntimeDescriptor,
) -> Result<(), RuntimeError> {
    write_descriptor_with(paths, descriptor, || Ok(()))
}

#[doc(hidden)]
#[cfg(any(test, feature = "test-support"))]
pub fn write_descriptor_with_post_rename_hook<F>(
    paths: &RuntimePaths,
    descriptor: &RuntimeDescriptor,
    post_rename_hook: F,
) -> Result<(), RuntimeError>
where
    F: FnOnce() -> Result<(), RuntimeError>,
{
    write_descriptor_with(paths, descriptor, post_rename_hook)
}

fn write_descriptor_with<F>(
    paths: &RuntimePaths,
    descriptor: &RuntimeDescriptor,
    post_rename_hook: F,
) -> Result<(), RuntimeError>
where
    F: FnOnce() -> Result<(), RuntimeError>,
{
    validate_runtime_paths(paths)?;
    let root = open_private_root(&paths.root)?;
    let _transition_guard = acquire_transition_guard_blocking_at(paths, &root)?;
    validate_descriptor(paths, descriptor)?;
    let encoded = serde_json::to_vec(descriptor)?;
    if encoded.len() as u64 > MAX_DESCRIPTOR_BYTES {
        return Err(RuntimeError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "runtime descriptor is too large",
        )));
    }

    let nonce = FILE_NONCE.fetch_add(1, Ordering::Relaxed);
    let temporary = format!(
        ".{}.tmp-{}-{nonce}",
        paths.scope.scope_key,
        std::process::id()
    );
    let descriptor_name = descriptor_name(paths);
    let mut renamed = false;
    let result = (|| {
        let mut file = open_new_private_at(&root, OsStr::new(&temporary))?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        renameat(
            &root,
            OsStr::new(&temporary),
            &root,
            OsStr::new(&descriptor_name),
        )
        .map_err(io::Error::from)?;
        renamed = true;
        post_rename_hook()?;
        sync_directory(&root)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = unlinkat(&root, OsStr::new(&temporary), AtFlags::empty());
        if renamed {
            let _ = remove_descriptor_if_instance_at(
                &root,
                paths,
                &descriptor.broker_instance_id,
                || {},
            );
        }
    }
    result
}

pub fn remove_descriptor_if_instance(
    paths: &RuntimePaths,
    broker_instance_id: &str,
) -> Result<bool, RuntimeError> {
    remove_descriptor_if_instance_with(paths, broker_instance_id, || {})
}

#[doc(hidden)]
#[cfg(any(test, feature = "test-support"))]
pub fn remove_descriptor_if_instance_with_observed_hook<F>(
    paths: &RuntimePaths,
    broker_instance_id: &str,
    observed_hook: F,
) -> Result<bool, RuntimeError>
where
    F: FnOnce(),
{
    remove_descriptor_if_instance_with(paths, broker_instance_id, observed_hook)
}

fn remove_descriptor_if_instance_with<F>(
    paths: &RuntimePaths,
    broker_instance_id: &str,
    observed_hook: F,
) -> Result<bool, RuntimeError>
where
    F: FnOnce(),
{
    validate_runtime_paths(paths)?;
    let root = open_private_root(&paths.root)?;
    let _transition_guard = acquire_transition_guard_at(paths, &root)?;
    remove_descriptor_if_instance_at(&root, paths, broker_instance_id, observed_hook)
}

fn remove_descriptor_if_instance_at<F>(
    root: &File,
    paths: &RuntimePaths,
    broker_instance_id: &str,
    observed_hook: F,
) -> Result<bool, RuntimeError>
where
    F: FnOnce(),
{
    if !read_descriptor_at(paths, root)
        .is_ok_and(|descriptor| descriptor.broker_instance_id == broker_instance_id)
    {
        return Ok(false);
    }
    observed_hook();
    remove_descriptor_at(root, paths)?;
    Ok(true)
}

pub fn read_descriptor(paths: &RuntimePaths) -> Result<RuntimeDescriptor, RuntimeError> {
    validate_runtime_paths(paths)?;
    let root = open_private_root(&paths.root)?;
    read_descriptor_at(paths, &root)
}

fn read_descriptor_at(
    paths: &RuntimePaths,
    root: &File,
) -> Result<RuntimeDescriptor, RuntimeError> {
    let file = open_private_read_at(
        root,
        OsStr::new(&descriptor_name(paths)),
        MAX_DESCRIPTOR_BYTES,
    )?;
    let encoded = read_limited(file, MAX_DESCRIPTOR_BYTES)?;
    let descriptor: RuntimeDescriptor = serde_json::from_slice(&encoded)?;
    validate_descriptor(paths, &descriptor)?;
    Ok(descriptor)
}

fn validate_descriptor(
    paths: &RuntimePaths,
    descriptor: &RuntimeDescriptor,
) -> Result<(), RuntimeError> {
    if descriptor.session_key != paths.scope.session_key {
        return Err(RuntimeError::SessionMismatch);
    }
    if descriptor.workspace_id != paths.scope.workspace_id {
        return Err(RuntimeError::WorkspaceMismatch);
    }

    let valid_origin = descriptor
        .base_url
        .strip_prefix("http://")
        .and_then(|origin| origin.parse::<SocketAddrV4>().ok())
        .is_some_and(|address| {
            *address.ip() == Ipv4Addr::LOCALHOST
                && address.port() != 0
                && descriptor.base_url == format!("http://{address}")
        });
    if !valid_origin {
        return Err(RuntimeError::InvalidDescriptor(
            "base URL must be a loopback HTTP origin",
        ));
    }

    let decoded_token = URL_SAFE_NO_PAD
        .decode(descriptor.bearer_token.as_bytes())
        .map_err(|_| RuntimeError::InvalidDescriptor("bearer token encoding"))?;
    if decoded_token.len() != 32
        || URL_SAFE_NO_PAD.encode(&decoded_token) != descriptor.bearer_token
    {
        return Err(RuntimeError::InvalidDescriptor(
            "bearer token must encode 256 bits",
        ));
    }

    let decoded_instance_id = URL_SAFE_NO_PAD
        .decode(descriptor.broker_instance_id.as_bytes())
        .map_err(|_| RuntimeError::InvalidDescriptor("broker instance ID encoding"))?;
    if descriptor.broker_instance_id.len() != 43
        || decoded_instance_id.len() != 32
        || URL_SAFE_NO_PAD.encode(&decoded_instance_id) != descriptor.broker_instance_id
    {
        return Err(RuntimeError::InvalidDescriptor(
            "broker instance ID must encode 256 bits",
        ));
    }

    validate_absolute_path(&descriptor.executable_path)?;
    let canonical = descriptor
        .executable_path
        .canonicalize()
        .map_err(|_| RuntimeError::InvalidDescriptor("executable path does not exist"))?;
    if canonical != descriptor.executable_path {
        return Err(RuntimeError::InvalidDescriptor(
            "executable path is not canonical",
        ));
    }
    let executable_metadata = canonical
        .metadata()
        .map_err(|_| RuntimeError::InvalidDescriptor("executable metadata unavailable"))?;
    if !executable_metadata.is_file() {
        return Err(RuntimeError::InvalidDescriptor(
            "executable path is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        if executable_metadata.mode() & 0o111 == 0
            || accessat(CWD, &canonical, Access::EXEC_OK, AtFlags::EACCESS).is_err()
        {
            return Err(RuntimeError::InvalidDescriptor(
                "executable file is not executable by this process",
            ));
        }
    }

    if platform_pid(descriptor.broker_pid).is_none() {
        return Err(RuntimeError::InvalidDescriptor(
            "broker PID is not representable",
        ));
    }
    let now_unix_ms: i64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RuntimeError::InvalidDescriptor("system time is before Unix epoch"))?
        .as_millis()
        .try_into()
        .map_err(|_| RuntimeError::InvalidDescriptor("system time is out of range"))?;
    if descriptor.created_unix_ms <= 0 || descriptor.created_unix_ms > now_unix_ms + 300_000 {
        return Err(RuntimeError::InvalidDescriptor(
            "creation timestamp is not sensible",
        ));
    }
    Ok(())
}

pub fn remove_descriptor(paths: &RuntimePaths) -> Result<(), RuntimeError> {
    validate_runtime_paths(paths)?;
    let root = open_private_root(&paths.root)?;
    let _transition_guard = acquire_transition_guard_blocking_at(paths, &root)?;
    remove_descriptor_at(&root, paths)
}

fn remove_descriptor_at(root: &File, paths: &RuntimePaths) -> Result<(), RuntimeError> {
    match unlinkat(root, OsStr::new(&descriptor_name(paths)), AtFlags::empty()) {
        Ok(()) => {
            sync_directory(root)?;
            Ok(())
        }
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(error) => Err(io::Error::from(error).into()),
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LockRecord {
    pid: u32,
    nonce: u64,
}

pub struct SessionLock {
    paths: RuntimePaths,
    root: File,
    record: LockRecord,
    release_on_drop: bool,
}

impl SessionLock {
    pub fn acquire<F>(
        paths: &RuntimePaths,
        broker_pid: u32,
        descriptor_health: F,
    ) -> Result<Self, RuntimeError>
    where
        F: Fn(&RuntimeDescriptor) -> bool,
    {
        Self::acquire_with_probes(paths, broker_pid, process_is_alive, descriptor_health)
    }

    fn acquire_with_probes<P, H>(
        paths: &RuntimePaths,
        broker_pid: u32,
        owner_is_alive: P,
        descriptor_is_healthy: H,
    ) -> Result<Self, RuntimeError>
    where
        P: Fn(u32) -> bool,
        H: Fn(&RuntimeDescriptor) -> bool,
    {
        Self::acquire_with_probes_and_hook(
            paths,
            broker_pid,
            owner_is_alive,
            descriptor_is_healthy,
            |_| Ok(()),
        )
    }

    #[cfg(test)]
    fn acquire_with_publish_hook<F>(
        paths: &RuntimePaths,
        broker_pid: u32,
        publish_hook: F,
    ) -> Result<Self, RuntimeError>
    where
        F: Fn(LockPublishStage) -> Result<(), RuntimeError> + Copy,
    {
        Self::acquire_with_probes_and_hook(
            paths,
            broker_pid,
            process_is_alive,
            |_| false,
            publish_hook,
        )
    }

    fn acquire_with_probes_and_hook<P, H, F>(
        paths: &RuntimePaths,
        broker_pid: u32,
        owner_is_alive: P,
        descriptor_is_healthy: H,
        publish_hook: F,
    ) -> Result<Self, RuntimeError>
    where
        P: Fn(u32) -> bool,
        H: Fn(&RuntimeDescriptor) -> bool,
        F: Fn(LockPublishStage) -> Result<(), RuntimeError> + Copy,
    {
        validate_runtime_paths(paths)?;
        if platform_pid(broker_pid).is_none() {
            return Err(RuntimeError::InvalidLock);
        }
        let root = open_private_root(&paths.root)?;
        let _transition_guard = acquire_transition_guard_at(paths, &root)?;
        let record = LockRecord {
            pid: broker_pid,
            nonce: FILE_NONCE.fetch_add(1, Ordering::Relaxed),
        };

        for _ in 0..2 {
            match write_lock_create_with_hook(&root, paths, &record, publish_hook) {
                Ok(()) => {
                    if let Err(error) = remove_stale_descriptor_at(&root, paths) {
                        let _ = unlinkat(&root, OsStr::new(&lock_name(paths)), AtFlags::empty());
                        let _ = sync_directory(&root);
                        return Err(error);
                    }
                    return Ok(Self {
                        paths: paths.clone(),
                        root,
                        record,
                        release_on_drop: true,
                    });
                }
                Err(RuntimeError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }

            let stale = read_lock(&root, paths)?;
            if owner_is_alive(stale.pid) {
                return Err(RuntimeError::SessionAlreadyOwned(stale.pid));
            }
            if read_descriptor_at(paths, &root)
                .ok()
                .is_some_and(|descriptor| descriptor_is_healthy(&descriptor))
            {
                return Err(RuntimeError::SessionAlreadyOwned(stale.pid));
            }

            if read_lock(&root, paths)? != stale {
                continue;
            }
            remove_stale_descriptor_at(&root, paths)?;
            unlinkat(&root, OsStr::new(&lock_name(paths)), AtFlags::empty())
                .map_err(io::Error::from)?;
            sync_directory(&root)?;
        }

        Err(RuntimeError::Io(io::Error::new(
            io::ErrorKind::WouldBlock,
            "runtime lock changed during acquisition",
        )))
    }

    pub fn owner_pid(&self) -> u32 {
        self.record.pid
    }

    /// Attempts release without waiting for another transition owner.
    ///
    /// A failed attempt deliberately leaves the lock record in place for the
    /// normal stale-PID/health recovery path instead of blocking process exit.
    pub fn release_nonblocking(mut self) -> Result<(), RuntimeError> {
        self.release_on_drop = false;
        let _transition_guard = acquire_transition_guard_at(&self.paths, &self.root)?;
        self.remove_if_owned()
    }

    fn remove_if_owned(&self) -> Result<(), RuntimeError> {
        if read_lock(&self.root, &self.paths).ok().as_ref() == Some(&self.record) {
            unlinkat(
                &self.root,
                OsStr::new(&lock_name(&self.paths)),
                AtFlags::empty(),
            )
            .map_err(io::Error::from)?;
            sync_directory(&self.root)?;
        }
        Ok(())
    }
}

impl Drop for SessionLock {
    fn drop(&mut self) {
        if !self.release_on_drop {
            return;
        }
        let Ok(_transition_guard) = acquire_transition_guard_blocking_at(&self.paths, &self.root)
        else {
            return;
        };
        let _ = self.remove_if_owned();
    }
}

fn open_private_root(root: &Path) -> Result<File, RuntimeError> {
    validate_absolute_path(root)?;
    let parent_path = root
        .parent()
        .ok_or_else(|| RuntimeError::UnsafePath(root.to_path_buf()))?;
    let leaf = root
        .file_name()
        .filter(|leaf| !leaf.is_empty())
        .ok_or_else(|| RuntimeError::UnsafePath(root.to_path_buf()))?;
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let parent =
        File::from(open(parent_path, directory_flags, Mode::empty()).map_err(io::Error::from)?);
    validate_runtime_parent(parent_path, &parent.metadata()?)?;

    let root_fd = match openat(&parent, leaf, directory_flags, Mode::empty()) {
        Ok(root_fd) => root_fd,
        Err(rustix::io::Errno::NOENT) => {
            match mkdirat(&parent, leaf, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(io::Error::from(error).into()),
            }
            openat(&parent, leaf, directory_flags, Mode::empty()).map_err(io::Error::from)?
        }
        Err(error) => return Err(io::Error::from(error).into()),
    };
    let root_handle = File::from(root_fd);
    let metadata = root_handle.metadata()?;
    validate_private_identity(root, &metadata, true)?;
    if metadata.mode() & 0o777 != 0o700 {
        fchmod(&root_handle, Mode::RUSR | Mode::WUSR | Mode::XUSR).map_err(io::Error::from)?;
    }
    validate_private_metadata(root, &root_handle.metadata()?, true)?;
    Ok(root_handle)
}

fn validate_runtime_parent(path: &Path, metadata: &fs::Metadata) -> Result<(), RuntimeError> {
    if !metadata.file_type().is_dir() {
        return Err(RuntimeError::UnsafePath(path.to_path_buf()));
    }
    let owner = metadata.uid();
    let current = getuid().as_raw();
    let mode = metadata.mode();
    if owner == current {
        if mode & 0o022 != 0 {
            return Err(RuntimeError::UnsafePermissions(path.to_path_buf()));
        }
    } else if owner == 0 {
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            return Err(RuntimeError::UnsafePermissions(path.to_path_buf()));
        }
    } else {
        return Err(RuntimeError::WrongOwner(path.to_path_buf()));
    }
    Ok(())
}

fn validate_runtime_paths(paths: &RuntimePaths) -> Result<(), RuntimeError> {
    validate_session_key(&paths.scope.session_key)?;
    validate_workspace_id(&paths.scope.workspace_id)?;
    if scope_from_session_key(&paths.scope.session_key, &paths.scope.workspace_id)? != paths.scope {
        return Err(RuntimeError::UnsafePath(paths.root.clone()));
    }
    if paths.descriptor != paths.root.join(format!("{}.json", paths.scope.scope_key)) {
        return Err(RuntimeError::UnsafePath(paths.descriptor.clone()));
    }
    if paths.lock != paths.root.join(format!("{}.lock", paths.scope.scope_key)) {
        return Err(RuntimeError::UnsafePath(paths.lock.clone()));
    }
    Ok(())
}

fn descriptor_name(paths: &RuntimePaths) -> String {
    format!("{}.json", paths.scope.scope_key)
}

fn remove_stale_descriptor_at(root: &File, paths: &RuntimePaths) -> Result<(), RuntimeError> {
    match unlinkat(root, OsStr::new(&descriptor_name(paths)), AtFlags::empty()) {
        Ok(()) => sync_directory(root),
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(error) => Err(io::Error::from(error).into()),
    }
}

fn lock_name(paths: &RuntimePaths) -> String {
    format!("{}.lock", paths.scope.scope_key)
}

fn guard_name(paths: &RuntimePaths) -> String {
    format!(".{}.acquire", paths.scope.scope_key)
}

fn validate_private_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    directory: bool,
) -> Result<(), RuntimeError> {
    validate_private_identity(path, metadata, directory)?;
    #[cfg(unix)]
    {
        let expected_mode = if directory { 0o700 } else { 0o600 };
        if metadata.mode() & 0o777 != expected_mode {
            return Err(RuntimeError::UnsafePermissions(path.to_path_buf()));
        }
    }
    Ok(())
}

fn validate_private_identity(
    path: &Path,
    metadata: &fs::Metadata,
    directory: bool,
) -> Result<(), RuntimeError> {
    let correct_kind = if directory {
        metadata.file_type().is_dir()
    } else {
        metadata.file_type().is_file()
    };
    if !correct_kind || metadata.file_type().is_symlink() {
        return Err(RuntimeError::UnsafePath(path.to_path_buf()));
    }
    #[cfg(unix)]
    {
        if metadata.uid() != getuid().as_raw() {
            return Err(RuntimeError::WrongOwner(path.to_path_buf()));
        }
    }
    Ok(())
}

fn open_new_private_at(root: &File, name: &OsStr) -> Result<File, RuntimeError> {
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let file =
        File::from(openat(root, name, flags, Mode::RUSR | Mode::WUSR).map_err(io::Error::from)?);
    fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(io::Error::from)?;
    validate_private_metadata(Path::new(name), &file.metadata()?, false)?;
    Ok(file)
}

fn open_private_read_at(root: &File, name: &OsStr, max_bytes: u64) -> Result<File, RuntimeError> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let file = File::from(openat(root, name, flags, Mode::empty()).map_err(io::Error::from)?);
    let metadata = file.metadata()?;
    validate_private_metadata(Path::new(name), &metadata, false)?;
    if metadata.len() > max_bytes {
        return Err(RuntimeError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "runtime file is too large",
        )));
    }
    Ok(file)
}

#[cfg(test)]
fn acquire_transition_guard(paths: &RuntimePaths) -> Result<File, RuntimeError> {
    let root = open_private_root(&paths.root)?;
    acquire_transition_guard_at(paths, &root)
}

fn acquire_transition_guard_at(paths: &RuntimePaths, root: &File) -> Result<File, RuntimeError> {
    acquire_transition_guard_with(paths, root, FlockOperation::NonBlockingLockExclusive)
}

fn acquire_transition_guard_blocking_at(
    paths: &RuntimePaths,
    root: &File,
) -> Result<File, RuntimeError> {
    acquire_transition_guard_with(paths, root, FlockOperation::LockExclusive)
}

fn acquire_transition_guard_with(
    paths: &RuntimePaths,
    root: &File,
    operation: FlockOperation,
) -> Result<File, RuntimeError> {
    let guard_name = guard_name(paths);
    let file = match open_new_private_at(root, OsStr::new(&guard_name)) {
        Ok(file) => file,
        Err(RuntimeError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {
            open_private_read_at(root, OsStr::new(&guard_name), 0)?
        }
        Err(error) => return Err(error),
    };
    flock(&file, operation).map_err(io::Error::from)?;
    Ok(file)
}

#[cfg(test)]
fn write_lock_create(
    root: &File,
    paths: &RuntimePaths,
    record: &LockRecord,
) -> Result<(), RuntimeError> {
    write_lock_create_with_hook(root, paths, record, |_| Ok(()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LockPublishStage {
    BeforeLink,
    AfterLinkBeforeSync,
    BeforeInitialDirectorySync,
    AfterDurableLinkBeforeCleanup,
}

fn write_lock_create_with_hook<F>(
    root: &File,
    paths: &RuntimePaths,
    record: &LockRecord,
    publish_hook: F,
) -> Result<(), RuntimeError>
where
    F: Fn(LockPublishStage) -> Result<(), RuntimeError> + Copy,
{
    for _ in 0..128 {
        let temporary = format!(
            ".{}.lock-tmp-{}-{}",
            paths.scope.scope_key,
            std::process::id(),
            FILE_NONCE.fetch_add(1, Ordering::Relaxed)
        );
        match write_lock_create_at_name_with_hook(
            root,
            paths,
            record,
            OsStr::new(&temporary),
            publish_hook,
        ) {
            Ok(()) => return Ok(()),
            Err(LockPublishAttemptError::TempExists) => continue,
            Err(LockPublishAttemptError::Runtime(error)) => return Err(error),
        }
    }
    Err(RuntimeError::Io(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a private lock temporary",
    )))
}

enum LockPublishAttemptError {
    TempExists,
    Runtime(RuntimeError),
}

fn write_lock_create_at_name_with_hook<F>(
    root: &File,
    paths: &RuntimePaths,
    record: &LockRecord,
    temporary: &OsStr,
    publish_hook: F,
) -> Result<(), LockPublishAttemptError>
where
    F: Fn(LockPublishStage) -> Result<(), RuntimeError> + Copy,
{
    let encoded = serde_json::to_vec(record)
        .map_err(RuntimeError::from)
        .map_err(LockPublishAttemptError::Runtime)?;
    let lock_name = lock_name(paths);
    let mut file = match open_new_private_at(root, temporary) {
        Ok(file) => file,
        Err(RuntimeError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {
            return Err(LockPublishAttemptError::TempExists);
        }
        Err(error) => return Err(LockPublishAttemptError::Runtime(error)),
    };
    let prepared = (|| {
        file.write_all(&encoded)?;
        file.sync_all()?;
        publish_hook(LockPublishStage::BeforeLink)?;
        Ok(())
    })();
    if let Err(error) = prepared {
        let _ = unlinkat(root, temporary, AtFlags::empty());
        return Err(LockPublishAttemptError::Runtime(error));
    }

    if let Err(error) = linkat(
        root,
        temporary,
        root,
        OsStr::new(&lock_name),
        AtFlags::empty(),
    ) {
        let _ = unlinkat(root, temporary, AtFlags::empty());
        return Err(LockPublishAttemptError::Runtime(
            io::Error::from(error).into(),
        ));
    }

    // The successful no-clobber link is the ownership commit point. The final
    // name is complete and visible from here onward, so all later failures are
    // best-effort and must return the SessionLock cleanup owner.
    let _ = publish_hook(LockPublishStage::AfterLinkBeforeSync);

    let initial_sync = publish_hook(LockPublishStage::BeforeInitialDirectorySync)
        .and_then(|()| sync_directory(root));
    if initial_sync.is_ok() {
        let _ = publish_hook(LockPublishStage::AfterDurableLinkBeforeCleanup);
    }

    let _ = unlinkat(root, temporary, AtFlags::empty());
    let _ = sync_directory(root);
    Ok(())
}

fn read_lock(root: &File, paths: &RuntimePaths) -> Result<LockRecord, RuntimeError> {
    let lock_name = lock_name(paths);
    let file = open_private_read_at(root, OsStr::new(&lock_name), MAX_LOCK_BYTES)?;
    let encoded = read_limited(file, MAX_LOCK_BYTES)?;
    let record: LockRecord =
        serde_json::from_slice(&encoded).map_err(|_| RuntimeError::InvalidLock)?;
    if record.pid == 0 {
        return Err(RuntimeError::InvalidLock);
    }
    Ok(record)
}

fn read_limited(reader: impl Read, max_bytes: u64) -> Result<Vec<u8>, RuntimeError> {
    let mut encoded = Vec::new();
    reader.take(max_bytes + 1).read_to_end(&mut encoded)?;
    if encoded.len() as u64 > max_bytes {
        return Err(RuntimeError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "runtime file is too large",
        )));
    }
    Ok(encoded)
}

fn process_is_alive(pid: u32) -> bool {
    let Some(pid) = platform_pid(pid) else {
        return true;
    };
    match test_kill_process(pid) {
        Ok(()) => true,
        Err(rustix::io::Errno::SRCH) => false,
        Err(_) => true,
    }
}

fn platform_pid(pid: u32) -> Option<Pid> {
    i32::try_from(pid).ok().and_then(Pid::from_raw)
}

fn sync_directory(root: &File) -> Result<(), RuntimeError> {
    root.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        env as process_env,
        ffi::OsStr,
        fs,
        io::{self, BufRead, BufReader, Cursor, Read, Write},
        panic::{AssertUnwindSafe, catch_unwind},
        path::{Path, PathBuf},
        process::{Child, ChildStdout, Command as ProcessCommand, Stdio},
        sync::mpsc,
        thread,
        time::Duration,
    };

    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use super::{
        AtFlags, LockPublishStage, RuntimeDescriptor, RuntimeError, RuntimePaths, SessionLock,
        linkat, linux_runtime_root, lock_name, macos_runtime_root, open_new_private_at,
        open_private_root, read_descriptor, read_limited, read_lock, remove_descriptor,
        write_descriptor, write_descriptor_with_post_rename_hook, write_lock_create,
        write_lock_create_at_name_with_hook, write_lock_create_with_hook,
    };

    fn test_executable(root: &Path) -> PathBuf {
        let path = root.join("herdr-a2a-test-executable");
        fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::canonicalize(path).unwrap()
    }

    fn descriptor(session_key: &str, root: &Path) -> RuntimeDescriptor {
        RuntimeDescriptor {
            session_key: session_key.to_owned(),
            workspace_id: "test-workspace".to_owned(),
            base_url: "http://127.0.0.1:41321".to_owned(),
            bearer_token: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            broker_instance_id: "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI".to_owned(),
            executable_path: test_executable(root),
            broker_pid: 4242,
            created_unix_ms: 1_765_000_000_000,
        }
    }

    #[test]
    fn runtime_paths_partition_same_session_by_workspace() {
        // Break caught: omitting workspace identity from scope derivation makes two Herdr
        // workspaces sharing one session collide on runtime ownership and discovery artifacts.
        let root = tempfile::tempdir().unwrap();
        let left = RuntimePaths::for_test(root.path(), "session", "w1");
        let right = RuntimePaths::for_test(root.path(), "session", "w2");

        assert_ne!(left.descriptor, right.descriptor);
        assert_ne!(left.lock, right.lock);
        assert_ne!(left.scope.scope_key, right.scope.scope_key);
    }

    #[test]
    fn runtime_scope_rejects_unsafe_workspace_ids() {
        // Break caught: accepting empty, control-bearing, or unbounded workspace identities
        // permits ambiguous scope derivation or attacker-controlled resource consumption.
        let socket = Path::new("/tmp/herdr.sock");
        for workspace_id in ["", "workspace\0other", "workspace\nother"] {
            assert!(matches!(
                super::scope_key(socket, workspace_id),
                Err(RuntimeError::InvalidWorkspaceId)
            ));
        }
        let oversized = "w".repeat(257);
        assert!(matches!(
            super::scope_key(socket, &oversized),
            Err(RuntimeError::InvalidWorkspaceId)
        ));
    }

    #[test]
    fn descriptor_rejects_another_workspace() {
        // Break caught: validating only session identity allows one workspace to publish a
        // descriptor into another workspace's scoped runtime.
        let root = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(root.path(), "session", "w1");
        let mut value = descriptor("session", root.path());
        value.workspace_id = "w2".into();

        assert!(matches!(
            write_descriptor(&paths, &value),
            Err(RuntimeError::WorkspaceMismatch)
        ));
    }

    #[test]
    fn a_post_rename_descriptor_failure_does_not_leave_discovery_visible() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");
        let error = write_descriptor_with_post_rename_hook(
            &paths,
            &descriptor("session-key", dir.path()),
            || {
                Err(RuntimeError::Io(io::Error::other(
                    "injected post-rename failure",
                )))
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("injected post-rename failure"));
        assert!(!paths.descriptor.exists());
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().mode() & 0o777
    }

    const CHILD_ACTION: &str = "HERDR_A2A_RUNTIME_TEST_ACTION";
    const CHILD_ROOT: &str = "HERDR_A2A_RUNTIME_TEST_ROOT";
    const CHILD_STAGE: &str = "HERDR_A2A_RUNTIME_TEST_STAGE";

    struct RuntimeTestChild {
        child: Child,
        output: BufReader<ChildStdout>,
    }

    impl RuntimeTestChild {
        fn spawn(root: &Path, action: &str) -> Self {
            Self::spawn_with_stage(root, action, None)
        }

        fn spawn_with_stage(root: &Path, action: &str, stage: Option<&str>) -> Self {
            let mut command = ProcessCommand::new(process_env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "runtime::tests::runtime_subprocess_helper",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD_ACTION, action)
                .env(CHILD_ROOT, root)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped());
            if let Some(stage) = stage {
                command.env(CHILD_STAGE, stage);
            }
            let mut child = command.spawn().unwrap();
            let output = BufReader::new(child.stdout.take().unwrap());
            Self { child, output }
        }

        fn id(&self) -> u32 {
            self.child.id()
        }

        fn send(&mut self, bytes: &[u8]) {
            self.child.stdin.as_mut().unwrap().write_all(bytes).unwrap();
            self.child.stdin.as_mut().unwrap().flush().unwrap();
        }

        fn wait_for_any(&mut self, markers: &[&str]) -> String {
            let mut observed = String::new();
            loop {
                let mut line = String::new();
                let read = self.output.read_line(&mut line).unwrap();
                assert!(read != 0, "child exited before marker; output: {observed}");
                observed.push_str(&line);
                if let Some(marker) = markers.iter().find(|marker| line.contains(**marker)) {
                    return (*marker).to_owned();
                }
            }
        }

        fn wait_for(&mut self, marker: &str) {
            self.wait_for_any(&[marker]);
        }

        fn terminate(&mut self) {
            if self.child.try_wait().unwrap().is_none() {
                self.child.kill().unwrap();
            }
            self.child.wait().unwrap();
        }
    }

    impl Drop for RuntimeTestChild {
        fn drop(&mut self) {
            if self.child.try_wait().ok().flatten().is_none() {
                let _ = self.child.kill();
            }
            let _ = self.child.wait();
        }
    }

    #[test]
    fn runtime_subprocess_helper() {
        let Some(action) = process_env::var_os(CHILD_ACTION) else {
            return;
        };
        let root = PathBuf::from(process_env::var_os(CHILD_ROOT).unwrap());
        let paths = RuntimePaths::for_test(&root, "session-key", "test-workspace");

        match action.to_str().unwrap() {
            "hold" => {
                let lock = SessionLock::acquire(&paths, std::process::id(), |_| false).unwrap();
                println!("RUNTIME_CHILD_ACQUIRED");
                io::stdout().flush().unwrap();
                let _ = io::stdin().read(&mut [0_u8; 1]);
                drop(lock);
            }
            "race" => {
                println!("RUNTIME_CHILD_READY");
                io::stdout().flush().unwrap();
                io::stdin().read_exact(&mut [0_u8; 1]).unwrap();
                match SessionLock::acquire(&paths, std::process::id(), |_| false) {
                    Ok(lock) => {
                        println!("RUNTIME_CHILD_WON");
                        io::stdout().flush().unwrap();
                        let _ = io::stdin().read(&mut [0_u8; 1]);
                        drop(lock);
                    }
                    Err(RuntimeError::SessionAlreadyOwned(_)) => {
                        println!("RUNTIME_CHILD_LOST");
                        io::stdout().flush().unwrap();
                    }
                    Err(RuntimeError::Io(error))
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::AlreadyExists
                        ) =>
                    {
                        println!("RUNTIME_CHILD_LOST");
                        io::stdout().flush().unwrap();
                    }
                    Err(error) => panic!("unexpected race result: {error}"),
                }
            }
            "crash" => {
                let selected = match process_env::var(CHILD_STAGE).unwrap().as_str() {
                    "before-link" => LockPublishStage::BeforeLink,
                    "after-link" => LockPublishStage::AfterLinkBeforeSync,
                    "after-durable-link" => LockPublishStage::AfterDurableLinkBeforeCleanup,
                    stage => panic!("unknown crash stage: {stage}"),
                };
                let _ =
                    SessionLock::acquire_with_publish_hook(&paths, std::process::id(), |stage| {
                        if stage == selected {
                            std::process::exit(91);
                        }
                        Ok(())
                    });
                panic!("publication did not reach selected crash stage");
            }
            action => panic!("unknown child action: {action}"),
        }
    }

    #[test]
    fn socket_identity_is_hashed_into_an_opaque_descriptor_name() {
        let dir = tempfile::tempdir().unwrap();
        let paths =
            RuntimePaths::for_socket_at(dir.path(), Path::new("/tmp/herdr.sock"), "test-workspace")
                .unwrap();

        assert_eq!(
            paths.scope.session_key,
            "0cb0c5e4a7465217744578c86057f3feaf79bb7077b3bfe3ca8018892ad01d35"
        );
        assert_eq!(
            paths.descriptor.file_name().unwrap().to_str().unwrap(),
            format!("{}.json", paths.scope.scope_key)
        );
        assert!(!paths.descriptor.to_string_lossy().contains("herdr.sock"));
    }

    #[test]
    fn platform_roots_follow_the_documented_per_user_locations() {
        assert_eq!(
            linux_runtime_root(Some(OsStr::new("/run/user/42")), 42).unwrap(),
            Path::new("/run/user/42/herdr-a2a")
        );
        assert_eq!(
            linux_runtime_root(None, 42).unwrap(),
            Path::new("/tmp/herdr-a2a-42")
        );
        assert_eq!(
            linux_runtime_root(Some(OsStr::new("/tmp/herdr-a2a-custom")), 42).unwrap(),
            Path::new("/tmp/herdr-a2a-custom/herdr-a2a")
        );
        assert_eq!(
            macos_runtime_root(Some(OsStr::new("/private/tmp/session"))).unwrap(),
            Path::new("/private/tmp/session/herdr-a2a")
        );
    }

    #[test]
    fn descriptor_path_cannot_be_redirected_outside_the_private_root() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let mut paths = RuntimePaths::for_test(root.path(), "session-key", "test-workspace");
        paths.descriptor = outside.path().join("escaped.json");

        assert!(write_descriptor(&paths, &descriptor("session-key", root.path())).is_err());
        assert!(!paths.descriptor.exists());
    }

    #[cfg(unix)]
    #[test]
    fn runtime_root_rejects_a_parent_writable_by_other_users() {
        let parent = tempfile::tempdir().unwrap();
        let executable = descriptor("session-key", parent.path());
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o777)).unwrap();
        let paths = RuntimePaths::for_test(
            &parent.path().join("runtime"),
            "session-key",
            "test-workspace",
        );

        assert!(write_descriptor(&paths, &executable).is_err());
        assert!(!paths.root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn open_root_handle_cannot_be_redirected_by_path_substitution() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("runtime");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let root_handle = open_private_root(&root).unwrap();
        let moved_root = parent.path().join("original-runtime");
        let outside = parent.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::rename(&root, &moved_root).unwrap();
        symlink(&outside, &root).unwrap();

        let mut file = open_new_private_at(&root_handle, OsStr::new("probe")).unwrap();
        file.write_all(b"anchored").unwrap();
        file.sync_all().unwrap();

        assert_eq!(fs::read(moved_root.join("probe")).unwrap(), b"anchored");
        assert!(!outside.join("probe").exists());
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_lock_and_parent_are_private() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");
        let _lock = SessionLock::acquire_with_probes(&paths, 42, |_| false, |_| false).unwrap();
        write_descriptor(&paths, &descriptor("session-key", dir.path())).unwrap();

        assert_eq!(mode(&paths.root), 0o700);
        assert_eq!(mode(&paths.descriptor), 0o600);
        assert_eq!(mode(&paths.lock), 0o600);
    }

    #[test]
    fn descriptor_round_trip_preserves_discovery_fields() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");
        let expected = descriptor("session-key", dir.path());

        write_descriptor(&paths, &expected).unwrap();

        assert_eq!(read_descriptor(&paths).unwrap(), expected);
        remove_descriptor(&paths).unwrap();
        assert!(!paths.descriptor.exists());
    }

    #[test]
    fn descriptor_must_match_the_socket_derived_session() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-a", "test-workspace");

        assert!(write_descriptor(&paths, &descriptor("session-b", dir.path())).is_err());
    }

    #[test]
    fn descriptor_rejects_non_loopback_or_non_origin_urls() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");
        for base_url in [
            "https://127.0.0.1:41321",
            "http://127.0.0.1:41321/",
            "http://127.0.0.1:0",
            "http://localhost:41321",
            "http://192.0.2.10:41321",
        ] {
            let mut invalid = descriptor("session-key", dir.path());
            invalid.base_url = base_url.to_owned();
            assert!(
                write_descriptor(&paths, &invalid).is_err(),
                "unsafe URL was accepted: {base_url}"
            );
        }
    }

    #[test]
    fn descriptor_requires_an_unpadded_256_bit_base64url_token() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");
        for bearer_token in [
            "",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+",
        ] {
            let mut invalid = descriptor("session-key", dir.path());
            invalid.bearer_token = bearer_token.to_owned();
            assert!(
                write_descriptor(&paths, &invalid).is_err(),
                "invalid token was accepted: {bearer_token:?}"
            );
        }
    }

    #[test]
    fn descriptor_requires_an_unpadded_256_bit_base64url_instance_id() {
        // Break caught: a descriptor without one exact canonical 32-byte instance identity can
        // authenticate a replacement broker with a proof from a different process instance.
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");
        for broker_instance_id in [
            "",
            "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi",
            "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=",
            "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi+",
            "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi",
        ] {
            let mut invalid = descriptor("session-key", dir.path());
            invalid.broker_instance_id = broker_instance_id.to_owned();
            assert!(
                write_descriptor(&paths, &invalid).is_err(),
                "invalid broker instance ID was accepted: {broker_instance_id:?}"
            );
        }
    }

    #[test]
    fn descriptor_reader_rejects_a_missing_instance_id() {
        // Break caught: an old descriptor without process-instance identity reaches protected
        // discovery and lets a token-only proof authenticate the wrong broker generation.
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");
        let descriptor = descriptor("session-key", dir.path());
        write_descriptor(&paths, &descriptor).unwrap();
        let mut encoded = serde_json::to_value(descriptor).unwrap();
        encoded
            .as_object_mut()
            .unwrap()
            .remove("broker_instance_id");
        fs::write(&paths.descriptor, serde_json::to_vec(&encoded).unwrap()).unwrap();

        assert!(read_descriptor(&paths).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_requires_a_canonical_regular_executable_file() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");

        let mut relative = descriptor("session-key", dir.path());
        relative.executable_path = PathBuf::from("herdr-a2a");
        assert!(write_descriptor(&paths, &relative).is_err());

        let non_executable_path = dir.path().join("not-executable");
        fs::write(&non_executable_path, b"data").unwrap();
        fs::set_permissions(&non_executable_path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut non_executable = descriptor("session-key", dir.path());
        non_executable.executable_path = fs::canonicalize(non_executable_path).unwrap();
        assert!(write_descriptor(&paths, &non_executable).is_err());

        let wrong_identity_mode_path = dir.path().join("other-only-executable");
        fs::write(&wrong_identity_mode_path, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&wrong_identity_mode_path, fs::Permissions::from_mode(0o001)).unwrap();
        let mut wrong_identity_mode = descriptor("session-key", dir.path());
        wrong_identity_mode.executable_path = fs::canonicalize(wrong_identity_mode_path).unwrap();
        assert!(write_descriptor(&paths, &wrong_identity_mode).is_err());

        let mut directory = descriptor("session-key", dir.path());
        directory.executable_path = fs::canonicalize(dir.path()).unwrap();
        assert!(write_descriptor(&paths, &directory).is_err());

        let target = test_executable(dir.path());
        let link = dir.path().join("linked-executable");
        symlink(target, &link).unwrap();
        let mut linked = descriptor("session-key", dir.path());
        linked.executable_path = link;
        assert!(write_descriptor(&paths, &linked).is_err());
    }

    #[test]
    fn descriptor_requires_nonzero_pid_and_sensible_positive_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");

        let mut zero_pid = descriptor("session-key", dir.path());
        zero_pid.broker_pid = 0;
        assert!(write_descriptor(&paths, &zero_pid).is_err());

        let mut unrepresentable_pid = descriptor("session-key", dir.path());
        unrepresentable_pid.broker_pid = u32::MAX;
        assert!(write_descriptor(&paths, &unrepresentable_pid).is_err());

        for created_unix_ms in [0, -1, i64::MAX] {
            let mut invalid = descriptor("session-key", dir.path());
            invalid.created_unix_ms = created_unix_ms;
            assert!(
                write_descriptor(&paths, &invalid).is_err(),
                "invalid timestamp was accepted: {created_unix_ms}"
            );
        }
    }

    #[test]
    fn descriptor_reader_revalidates_untrusted_json() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");
        let mut invalid = descriptor("session-key", dir.path());
        write_descriptor(&paths, &invalid).unwrap();
        invalid.base_url = "http://192.0.2.10:41321".to_owned();
        fs::write(&paths.descriptor, serde_json::to_vec(&invalid).unwrap()).unwrap();

        assert!(read_descriptor(&paths).is_err());
    }

    #[test]
    fn stale_health_check_never_receives_an_invalid_descriptor() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");
        let mut invalid = descriptor("session-key", dir.path());
        write_descriptor(&paths, &invalid).unwrap();
        let first = SessionLock::acquire_with_probes(&paths, 41, |_| false, |_| false).unwrap();
        std::mem::forget(first);
        invalid.base_url = "http://192.0.2.10:41321".to_owned();
        fs::write(&paths.descriptor, serde_json::to_vec(&invalid).unwrap()).unwrap();
        let health_called = Cell::new(false);

        let replacement = SessionLock::acquire_with_probes(
            &paths,
            42,
            |_| false,
            |_| {
                health_called.set(true);
                true
            },
        )
        .unwrap();

        assert_eq!(replacement.owner_pid(), 42);
        assert!(!health_called.get());
    }

    #[test]
    fn descriptor_debug_redacts_the_bearer_token() {
        let dir = tempfile::tempdir().unwrap();
        let descriptor = descriptor("session-key", dir.path());

        let debug = format!("{descriptor:?}");

        assert!(!debug.contains(&descriptor.bearer_token));
        assert!(debug.contains("<redacted>"));
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_reader_rejects_group_or_world_readable_files() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");
        write_descriptor(&paths, &descriptor("session-key", dir.path())).unwrap();
        fs::set_permissions(&paths.descriptor, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(read_descriptor(&paths).is_err());
    }

    #[test]
    fn a_live_lock_owner_cannot_be_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");
        let first = SessionLock::acquire_with_probes(&paths, 41, |_| false, |_| false).unwrap();

        let second = SessionLock::acquire_with_probes(&paths, 42, |pid| pid == 41, |_| false);

        assert!(matches!(second, Err(RuntimeError::SessionAlreadyOwned(41))));
        drop(first);
    }

    #[test]
    fn an_absent_owner_with_a_healthy_descriptor_cannot_be_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");
        let first = SessionLock::acquire_with_probes(&paths, 41, |_| false, |_| false).unwrap();
        write_descriptor(&paths, &descriptor("session-key", dir.path())).unwrap();
        std::mem::forget(first);

        let second = SessionLock::acquire_with_probes(
            &paths,
            42,
            |_| false,
            |found| found.base_url == "http://127.0.0.1:41321",
        );

        assert!(matches!(second, Err(RuntimeError::SessionAlreadyOwned(41))));
    }

    #[test]
    fn an_absent_owner_and_unhealthy_descriptor_allow_stale_lock_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");
        let first = SessionLock::acquire_with_probes(&paths, 41, |_| false, |_| false).unwrap();
        write_descriptor(&paths, &descriptor("session-key", dir.path())).unwrap();
        std::mem::forget(first);

        let replacement =
            SessionLock::acquire_with_probes(&paths, 42, |_| false, |_| false).unwrap();

        assert_eq!(replacement.owner_pid(), 42);
        assert!(
            !paths.descriptor.exists(),
            "stale discovery remained visible after ownership transfer"
        );
    }

    #[test]
    fn acquiring_an_unlocked_session_removes_a_stale_descriptor() {
        // Break caught: a prior process releases its lock but leaves an unreadable or otherwise
        // stale descriptor visible while the replacement performs durable reconciliation.
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");
        write_descriptor(&paths, &descriptor("session-key", dir.path())).unwrap();

        let owner = SessionLock::acquire_with_probes(&paths, 42, |_| false, |_| false).unwrap();

        assert_eq!(owner.owner_pid(), 42);
        assert!(!paths.descriptor.exists());
    }

    #[test]
    fn malformed_lock_ownership_is_never_assumed_stale() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");
        fs::create_dir_all(&paths.root).unwrap();
        fs::write(&paths.lock, b"not a lock record").unwrap();
        #[cfg(unix)]
        fs::set_permissions(&paths.lock, fs::Permissions::from_mode(0o600)).unwrap();

        let result = SessionLock::acquire_with_probes(&paths, 42, |_| false, |_| false);

        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn production_probe_refuses_a_live_subprocess_owner() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");
        let mut child = RuntimeTestChild::spawn(dir.path(), "hold");
        child.wait_for("RUNTIME_CHILD_ACQUIRED");

        let result = SessionLock::acquire(&paths, std::process::id(), |_| false);

        assert!(matches!(
            result,
            Err(RuntimeError::SessionAlreadyOwned(pid)) if pid == child.id()
        ));
        child.terminate();
        let recovered = SessionLock::acquire(&paths, std::process::id(), |_| false).unwrap();
        assert_eq!(recovered.owner_pid(), std::process::id());
    }

    #[cfg(unix)]
    #[test]
    fn production_probe_replaces_a_terminated_subprocess_owner() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");
        let mut child = RuntimeTestChild::spawn(dir.path(), "hold");
        child.wait_for("RUNTIME_CHILD_ACQUIRED");
        child.terminate();

        let recovered = SessionLock::acquire(&paths, std::process::id(), |_| false).unwrap();

        assert_eq!(recovered.owner_pid(), std::process::id());
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_production_acquisition_has_exactly_one_winner() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");
        let mut first = RuntimeTestChild::spawn(dir.path(), "race");
        let mut second = RuntimeTestChild::spawn(dir.path(), "race");
        first.wait_for("RUNTIME_CHILD_READY");
        second.wait_for("RUNTIME_CHILD_READY");

        first.send(b"g");
        second.send(b"g");
        let first_result = first.wait_for_any(&["RUNTIME_CHILD_WON", "RUNTIME_CHILD_LOST"]);
        let second_result = second.wait_for_any(&["RUNTIME_CHILD_WON", "RUNTIME_CHILD_LOST"]);

        assert_eq!(
            [first_result.as_str(), second_result.as_str()]
                .into_iter()
                .filter(|result| *result == "RUNTIME_CHILD_WON")
                .count(),
            1
        );
        assert!(SessionLock::acquire(&paths, std::process::id(), |_| false).is_err());
        first.terminate();
        second.terminate();
        assert!(SessionLock::acquire(&paths, std::process::id(), |_| false).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn abrupt_publication_exit_never_wedges_the_next_owner() {
        for stage in ["before-link", "after-link", "after-durable-link"] {
            let dir = tempfile::tempdir().unwrap();
            let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");
            let mut child = RuntimeTestChild::spawn_with_stage(dir.path(), "crash", Some(stage));
            child.child.stdin.take();
            let status = child.child.wait().unwrap();

            assert_eq!(
                status.code(),
                Some(91),
                "crash stage {stage} was not reached"
            );
            let replacement = SessionLock::acquire(&paths, std::process::id(), |_| false).unwrap();
            assert!(SessionLock::acquire(&paths, std::process::id(), |_| false).is_err());
            drop(replacement);
        }
    }

    #[test]
    fn possible_pid_reuse_is_conservatively_refused() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");
        let root = open_private_root(&paths.root).unwrap();
        write_lock_create(
            &root,
            &paths,
            &super::LockRecord {
                pid: std::process::id(),
                nonce: 1,
            },
        )
        .unwrap();

        let result = SessionLock::acquire(&paths, std::process::id(), |_| false);

        assert!(matches!(
            result,
            Err(RuntimeError::SessionAlreadyOwned(pid)) if pid == std::process::id()
        ));
    }

    #[test]
    fn public_acquisition_rejects_unrepresentable_pid_before_publication() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");

        let result = SessionLock::acquire(&paths, u32::MAX, |_| false);

        assert!(matches!(result, Err(RuntimeError::InvalidLock)));
        assert!(!paths.lock.exists());
    }

    #[test]
    fn unrepresentable_pid_liveness_is_conservatively_ambiguous() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");
        let root = open_private_root(&paths.root).unwrap();
        write_lock_create(
            &root,
            &paths,
            &super::LockRecord {
                pid: u32::MAX,
                nonce: 1,
            },
        )
        .unwrap();

        let result = SessionLock::acquire(&paths, std::process::id(), |_| false);

        assert!(matches!(
            result,
            Err(RuntimeError::SessionAlreadyOwned(u32::MAX))
        ));
    }

    #[test]
    fn interruption_before_lock_publication_does_not_wedge_the_session() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");
        let root = open_private_root(&paths.root).unwrap();
        let record = super::LockRecord { pid: 41, nonce: 1 };

        let interrupted = catch_unwind(AssertUnwindSafe(|| {
            let _ = write_lock_create_with_hook(&root, &paths, &record, |stage| {
                if stage == LockPublishStage::BeforeLink {
                    panic!("simulated crash before lock publication");
                }
                Ok(())
            });
        }));

        assert!(interrupted.is_err());
        assert!(!paths.lock.exists());
        let replacement =
            SessionLock::acquire_with_probes(&paths, 42, |_| false, |_| false).unwrap();
        assert_eq!(replacement.owner_pid(), 42);
    }

    #[test]
    fn post_link_hook_failure_returns_a_visible_matching_cleanup_owner() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");

        let lock = SessionLock::acquire_with_publish_hook(&paths, std::process::id(), |stage| {
            if stage == LockPublishStage::AfterLinkBeforeSync {
                return Err(RuntimeError::Io(io::Error::other(
                    "injected post-link hook failure",
                )));
            }
            Ok(())
        })
        .unwrap();

        let root = open_private_root(&paths.root).unwrap();
        assert_eq!(read_lock(&root, &paths).unwrap(), lock.record);
        assert!(SessionLock::acquire(&paths, std::process::id(), |_| false).is_err());
        drop(lock);
        assert!(!paths.lock.exists());
    }

    #[test]
    fn post_link_conflict_cannot_replace_the_committed_owner() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");
        let root = open_private_root(&paths.root).unwrap();
        let conflicting_name = OsStr::new(".conflicting-complete-lock");
        let mut conflicting = open_new_private_at(&root, conflicting_name).unwrap();
        conflicting
            .write_all(&serde_json::to_vec(&super::LockRecord { pid: 1, nonce: 1 }).unwrap())
            .unwrap();
        conflicting.sync_all().unwrap();
        drop(conflicting);

        let lock = SessionLock::acquire_with_publish_hook(&paths, std::process::id(), |stage| {
            if stage == LockPublishStage::AfterLinkBeforeSync {
                let conflict = linkat(
                    &root,
                    conflicting_name,
                    &root,
                    OsStr::new(&lock_name(&paths)),
                    AtFlags::empty(),
                );
                assert_eq!(conflict, Err(rustix::io::Errno::EXIST));
                return Err(RuntimeError::Io(io::Error::other(
                    "injected post-link hook failure",
                )));
            }
            Ok(())
        })
        .unwrap();

        assert_eq!(read_lock(&root, &paths).unwrap(), lock.record);
        assert!(SessionLock::acquire(&paths, std::process::id(), |_| false).is_err());
        drop(lock);
        assert!(!paths.lock.exists());
    }

    #[test]
    fn initial_directory_sync_failure_returns_a_visible_cleanup_owner() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");

        let lock = SessionLock::acquire_with_publish_hook(&paths, std::process::id(), |stage| {
            if stage == LockPublishStage::BeforeInitialDirectorySync {
                return Err(RuntimeError::Io(io::Error::other(
                    "injected initial directory-sync failure",
                )));
            }
            Ok(())
        })
        .unwrap();

        let root = open_private_root(&paths.root).unwrap();
        assert_eq!(read_lock(&root, &paths).unwrap(), lock.record);
        assert!(SessionLock::acquire(&paths, std::process::id(), |_| false).is_err());
        drop(lock);
        assert!(!paths.lock.exists());
    }

    #[test]
    fn failure_after_durable_publication_still_returns_the_cleanup_owner() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");

        let lock = SessionLock::acquire_with_publish_hook(&paths, std::process::id(), |stage| {
            if stage == LockPublishStage::AfterDurableLinkBeforeCleanup {
                return Err(RuntimeError::Io(io::Error::other(
                    "injected post-commit cleanup failure",
                )));
            }
            Ok(())
        })
        .unwrap();

        assert!(paths.lock.exists());
        assert!(SessionLock::acquire(&paths, std::process::id(), |_| false).is_err());
        drop(lock);
        assert!(!paths.lock.exists());
    }

    #[test]
    fn failed_temp_creation_never_removes_a_file_it_did_not_create() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");
        let root = open_private_root(&paths.root).unwrap();
        let temporary = OsStr::new(".preexisting-lock-temp");
        let mut preexisting = open_new_private_at(&root, temporary).unwrap();
        preexisting.write_all(b"not owned by this attempt").unwrap();
        preexisting.sync_all().unwrap();
        drop(preexisting);

        let result = write_lock_create_at_name_with_hook(
            &root,
            &paths,
            &super::LockRecord { pid: 41, nonce: 1 },
            temporary,
            |_| Ok(()),
        );

        assert!(result.is_err());
        assert_eq!(
            fs::read(dir.path().join(temporary)).unwrap(),
            b"not owned by this attempt"
        );
        assert!(!paths.lock.exists());
    }

    #[test]
    fn lock_drop_waits_for_an_in_progress_ownership_transition() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RuntimePaths::for_test(dir.path(), "session-key", "test-workspace");
        let lock = SessionLock::acquire_with_probes(&paths, 41, |_| false, |_| false).unwrap();
        let holder_paths = paths.clone();
        let (guard_ready_tx, guard_ready_rx) = mpsc::channel();
        let (release_guard_tx, release_guard_rx) = mpsc::channel();
        let guard_holder = thread::spawn(move || {
            let _guard = super::acquire_transition_guard(&holder_paths).unwrap();
            guard_ready_tx.send(()).unwrap();
            release_guard_rx.recv().unwrap();
        });
        guard_ready_rx.recv().unwrap();

        let (drop_done_tx, drop_done_rx) = mpsc::channel();
        let dropper = thread::spawn(move || {
            drop(lock);
            drop_done_tx.send(()).unwrap();
        });

        assert!(
            drop_done_rx
                .recv_timeout(Duration::from_millis(50))
                .is_err()
        );
        release_guard_tx.send(()).unwrap();
        drop_done_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        guard_holder.join().unwrap();
        dropper.join().unwrap();
        assert!(!paths.lock.exists());
    }

    #[test]
    fn bounded_reader_rejects_content_beyond_the_limit() {
        assert!(read_limited(Cursor::new(b"12345"), 4).is_err());
        assert_eq!(read_limited(Cursor::new(b"1234"), 4).unwrap(), b"1234");
    }
}
