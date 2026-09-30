//! Private registry publication adapter. Indexed active graphs may never become fresh graphs.

use super::types::{LiveWorkflowError, RegistryIndex};
use iteron_workflow::live_scheduler::WorkflowStoreError;
use iteron_workflow::live_scheduler::file_journal::WorkflowFileJournal;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
#[cfg(not(unix))]
use std::path::PathBuf;

const MAX_INDEX_BYTES: usize = 128 * 1_024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    digest: String,
    index: RegistryIndex,
}

pub(super) struct RegistryStore {
    #[cfg(not(unix))]
    root: PathBuf,
    platform: PlatformStore,
}

impl RegistryStore {
    pub fn open(root: &Path) -> Result<Self, LiveWorkflowError> {
        if !root.is_absolute() {
            return Err(LiveWorkflowError::Invalid(
                "state root must be host-absolute",
            ));
        }
        provision(root)?;
        Ok(Self {
            #[cfg(not(unix))]
            root: root.into(),
            platform: PlatformStore::open(root)?,
        })
    }
    pub fn load(&mut self) -> Result<Option<RegistryIndex>, LiveWorkflowError> {
        let Some(bytes) = self.platform.load()? else {
            return Ok(None);
        };
        if bytes.len() > MAX_INDEX_BYTES {
            return Err(WorkflowStoreError::Unavailable.into());
        }
        let envelope: Envelope =
            serde_json::from_slice(&bytes).map_err(|_| WorkflowStoreError::Unavailable)?;
        let payload =
            serde_json::to_vec(&envelope.index).map_err(|_| WorkflowStoreError::Unavailable)?;
        if envelope.version != 1 || envelope.digest != hex_digest(&payload) {
            return Err(WorkflowStoreError::Unavailable.into());
        }
        Ok(Some(envelope.index))
    }
    pub fn commit(
        &mut self,
        expected: Option<u64>,
        next: &RegistryIndex,
    ) -> Result<(), LiveWorkflowError> {
        let current = self.load()?.map(|index| index.revision);
        let revision = match expected {
            Some(value) => value.checked_add(1),
            None => Some(0),
        };
        if current != expected || revision != Some(next.revision) {
            return Err(WorkflowStoreError::Conflict.into());
        }
        let payload = serde_json::to_vec(next).map_err(|_| WorkflowStoreError::Unavailable)?;
        let bytes = serde_json::to_vec(&Envelope {
            version: 1,
            digest: hex_digest(&payload),
            index: next.clone(),
        })
        .map_err(|_| WorkflowStoreError::Unavailable)?;
        if bytes.len() > MAX_INDEX_BYTES {
            return Err(WorkflowStoreError::Unavailable.into());
        }
        self.platform.publish(&bytes, expected.is_none())?;
        Ok(())
    }
    #[cfg(not(unix))]
    fn graph_path(&self, workflow_id: &str) -> PathBuf {
        self.root
            .join(format!("wf_{}", hex_digest(workflow_id.as_bytes())))
    }
    #[cfg(not(unix))]
    fn provision_graph(&self, workflow_id: &str) -> Result<PathBuf, LiveWorkflowError> {
        let path = self.graph_path(workflow_id);
        provision(&path)?;
        self.platform.sync_directory()?;
        Ok(path)
    }
    pub fn graph_journal(
        &self,
        workflow_id: &str,
        active: bool,
    ) -> Result<WorkflowFileJournal, LiveWorkflowError> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let component =
                std::ffi::CString::new(format!("wf_{}", hex_digest(workflow_id.as_bytes())))
                    .map_err(|_| WorkflowStoreError::Unavailable)?;
            if !active {
                // SAFETY: generated single component and pinned live directory; no path traversal.
                let created = unsafe {
                    libc::mkdirat(
                        self.platform.directory.as_raw_fd(),
                        component.as_ptr(),
                        0o700,
                    )
                };
                if created != 0
                    && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
                {
                    return Err(WorkflowStoreError::Unavailable.into());
                }
                self.platform.sync_directory()?;
            }
            return WorkflowFileJournal::open_relative(&self.platform.directory, &component)
                .map_err(|error| {
                    if active && error == WorkflowStoreError::Unavailable {
                        WorkflowStoreError::OutcomeUnknown.into()
                    } else {
                        error.into()
                    }
                });
        }
        #[cfg(not(unix))]
        {
            let path = if active {
                self.graph_path(workflow_id)
            } else {
                self.provision_graph(workflow_id)?
            };
            WorkflowFileJournal::open(&path).map_err(|error| {
                if active && error == WorkflowStoreError::Unavailable {
                    WorkflowStoreError::OutcomeUnknown.into()
                } else {
                    error.into()
                }
            })
        }
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn provision(path: &Path) -> Result<(), WorkflowStoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder
            .create(path)
            .map_err(|_| WorkflowStoreError::Unavailable)?;
        Ok(())
    }
    #[cfg(windows)]
    {
        // The trusted host supplies a nested namespace (.live-workflows/session). Provision only
        // absent components, each with a protected current-user DACL; never rewrite existing ACLs.
        let mut absent = Vec::new();
        let mut current = path;
        loop {
            match std::fs::symlink_metadata(current) {
                Ok(_) => break,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if absent.len() >= 32 {
                        return Err(WorkflowStoreError::Unavailable);
                    }
                    absent.push(current);
                    current = current.parent().ok_or(WorkflowStoreError::Unavailable)?;
                }
                Err(_) => return Err(WorkflowStoreError::Unavailable),
            }
        }
        for component in absent.into_iter().rev() {
            iteron_support::durable_windows_state::provision_private_directory(component)
                .map_err(windows_error)?;
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(WorkflowStoreError::Unavailable)
    }
}

#[cfg(windows)]
fn windows_error(
    error: iteron_support::durable_windows_state::WindowsStateError,
) -> WorkflowStoreError {
    use iteron_support::durable_windows_state::WindowsStateError;
    match error {
        WindowsStateError::Unavailable => WorkflowStoreError::Unavailable,
        WindowsStateError::Conflict => WorkflowStoreError::Conflict,
        WindowsStateError::OutcomeUnknown => WorkflowStoreError::OutcomeUnknown,
    }
}

#[cfg(windows)]
struct PlatformStore(iteron_support::durable_windows_state::WindowsSnapshotStore);
#[cfg(windows)]
impl PlatformStore {
    fn open(root: &Path) -> Result<Self, WorkflowStoreError> {
        Ok(Self(
            iteron_support::durable_windows_state::WindowsSnapshotStore::open(root, "registry")
                .map_err(windows_error)?,
        ))
    }
    fn load(&mut self) -> Result<Option<Vec<u8>>, WorkflowStoreError> {
        self.0.load().map_err(windows_error)
    }
    fn publish(&mut self, bytes: &[u8], first: bool) -> Result<(), WorkflowStoreError> {
        self.0.publish(bytes, first).map_err(windows_error)
    }
    fn sync_directory(&self) -> Result<(), WorkflowStoreError> {
        // Child journal and registry both use supported NTFS write-through publication. Native
        // device-fault evidence remains required; no portable directory fsync is invented here.
        Ok(())
    }
}

#[cfg(unix)]
struct PlatformStore {
    directory: std::fs::File,
    lease: std::fs::File,
    poisoned: bool,
}

#[cfg(unix)]
impl PlatformStore {
    fn open(root: &Path) -> Result<Self, WorkflowStoreError> {
        use std::os::fd::FromRawFd;
        use std::os::unix::fs::MetadataExt;
        let path = std::ffi::CString::new(root.as_os_str().as_encoded_bytes())
            .map_err(|_| WorkflowStoreError::Unavailable)?;
        // SAFETY: path is terminated; a new descriptor transfers to File exactly once.
        let raw = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(WorkflowStoreError::Unavailable);
        }
        // SAFETY: successful open returned a fresh owned descriptor.
        let directory = unsafe { std::fs::File::from_raw_fd(raw) };
        let metadata = directory
            .metadata()
            .map_err(|_| WorkflowStoreError::Unavailable)?;
        // SAFETY: geteuid has no preconditions.
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(WorkflowStoreError::Unavailable);
        }
        let lease = open_at(&directory, c"registry.lock", libc::O_RDWR | libc::O_CREAT)
            .map_err(|_| WorkflowStoreError::Unavailable)?;
        match lease.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Err(WorkflowStoreError::Conflict),
            Err(std::fs::TryLockError::Error(_)) => return Err(WorkflowStoreError::Unavailable),
        }
        Ok(Self {
            directory,
            lease,
            poisoned: false,
        })
    }
    fn load(&mut self) -> Result<Option<Vec<u8>>, WorkflowStoreError> {
        use std::io::Read;
        if self.poisoned {
            return Err(WorkflowStoreError::OutcomeUnknown);
        }
        let mut file = match open_at(&self.directory, c"registry.json", libc::O_RDONLY) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if self
                    .lease
                    .metadata()
                    .map_err(|_| WorkflowStoreError::Unavailable)?
                    .len()
                    != 0
                {
                    self.poisoned = true;
                    return Err(WorkflowStoreError::OutcomeUnknown);
                }
                return Ok(None);
            }
            Err(_) => return Err(WorkflowStoreError::Unavailable),
        };
        if file
            .metadata()
            .map_err(|_| WorkflowStoreError::Unavailable)?
            .len()
            > MAX_INDEX_BYTES as u64
        {
            return Err(WorkflowStoreError::Unavailable);
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_INDEX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| WorkflowStoreError::Unavailable)?;
        if bytes.len() > MAX_INDEX_BYTES {
            return Err(WorkflowStoreError::Unavailable);
        }
        Ok(Some(bytes))
    }
    fn publish(&mut self, bytes: &[u8], first: bool) -> Result<(), WorkflowStoreError> {
        use std::io::Write;
        use std::os::fd::AsRawFd;
        if self.poisoned {
            return Err(WorkflowStoreError::OutcomeUnknown);
        }
        if first
            && self
                .lease
                .write_all(b"live-registry-genesis-v1")
                .and_then(|_| self.lease.sync_all())
                .and_then(|_| self.directory.sync_all())
                .is_err()
        {
            self.poisoned = true;
            return Err(WorkflowStoreError::OutcomeUnknown);
        }
        // SAFETY: fixed relative name and live pinned directory; unlink never follows a symlink.
        let removed =
            unsafe { libc::unlinkat(self.directory.as_raw_fd(), c"registry.pending".as_ptr(), 0) };
        if removed != 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::NotFound {
            return Err(WorkflowStoreError::Unavailable);
        }
        let mut pending = open_at(
            &self.directory,
            c"registry.pending",
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )
        .map_err(|_| WorkflowStoreError::Unavailable)?;
        pending
            .write_all(bytes)
            .and_then(|_| pending.sync_all())
            .map_err(|_| WorkflowStoreError::Unavailable)?;
        // SAFETY: fixed names relative to the same pinned directory, atomic same-filesystem rename.
        let renamed = unsafe {
            libc::renameat(
                self.directory.as_raw_fd(),
                c"registry.pending".as_ptr(),
                self.directory.as_raw_fd(),
                c"registry.json".as_ptr(),
            )
        };
        if renamed != 0 || self.directory.sync_all().is_err() {
            self.poisoned = true;
            return Err(WorkflowStoreError::OutcomeUnknown);
        }
        Ok(())
    }
    fn sync_directory(&self) -> Result<(), WorkflowStoreError> {
        self.directory
            .sync_all()
            .map_err(|_| WorkflowStoreError::OutcomeUnknown)
    }
}

#[cfg(unix)]
fn open_at(
    directory: &std::fs::File,
    name: &std::ffi::CStr,
    flags: libc::c_int,
) -> std::io::Result<std::fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;
    // SAFETY: borrowed live directory and fixed terminated name; successful descriptor owned once.
    let raw = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0o600,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fresh owned successful openat result.
    let file = unsafe { std::fs::File::from_raw_fd(raw) };
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no preconditions.
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(std::io::Error::other(
            "private regular registry file required",
        ));
    }
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
struct PlatformStore;
#[cfg(not(any(unix, windows)))]
impl PlatformStore {
    fn open(_: &Path) -> Result<Self, WorkflowStoreError> {
        Err(WorkflowStoreError::Unavailable)
    }
    fn load(&mut self) -> Result<Option<Vec<u8>>, WorkflowStoreError> {
        Err(WorkflowStoreError::Unavailable)
    }
    fn publish(&mut self, _: &[u8], _: bool) -> Result<(), WorkflowStoreError> {
        Err(WorkflowStoreError::Unavailable)
    }
    fn sync_directory(&self) -> Result<(), WorkflowStoreError> {
        Err(WorkflowStoreError::Unavailable)
    }
}
