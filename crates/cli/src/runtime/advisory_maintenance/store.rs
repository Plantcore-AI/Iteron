//! Private handle-relative journal. A lease genesis marker forbids a missing snapshot from being
//! silently replaced after any possible first publication. The owner supplies schema/identity.
use super::{MAX_JOURNAL_BYTES, MaintenanceReadError, Snapshot, hash};
use serde::{Deserialize, Serialize};
use std::path::Path;
#[cfg(unix)]
use std::{
    fs::File,
    io::{Read, Write},
};

pub(super) trait MaintenanceJournal: Send {
    fn load(&mut self) -> Result<Option<Snapshot>, MaintenanceReadError>;
    fn commit(
        &mut self,
        expected: Option<u64>,
        next: &Snapshot,
    ) -> Result<(), MaintenanceReadError>;
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    sha256: String,
    snapshot: Snapshot,
}

pub(super) struct FileJournal {
    #[cfg(unix)]
    directory: File,
    #[cfg(unix)]
    lease: File,
    #[cfg(windows)]
    windows: iteron_support::durable_windows_state::WindowsSnapshotStore,
}
impl FileJournal {
    pub(super) fn open(path: &Path) -> Result<Self, MaintenanceReadError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let directory = super::directory::provision(path)?;
            let metadata = directory
                .metadata()
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
            // SAFETY: geteuid has no memory preconditions.
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
                return Err(MaintenanceReadError::ReconciliationNeeded);
            }
            let lease = open_at(
                &directory,
                c"maintenance.lock",
                libc::O_RDWR | libc::O_CREAT,
            )
            .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
            lease
                .try_lock()
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
            Ok(Self { directory, lease })
        }
        #[cfg(windows)]
        {
            super::directory::provision_windows(path)?;
            Ok(Self {
                windows: iteron_support::durable_windows_state::WindowsSnapshotStore::open(
                    path,
                    "maintenance",
                )
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(MaintenanceReadError::Unavailable)
        }
    }
    fn read_bytes(&mut self) -> Result<Option<Vec<u8>>, MaintenanceReadError> {
        #[cfg(unix)]
        {
            let mut file = match open_at(&self.directory, c"maintenance.json", libc::O_RDONLY) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if self
                        .lease
                        .metadata()
                        .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?
                        .len()
                        == 0
                    {
                        return Ok(None);
                    }
                    return Err(MaintenanceReadError::ReconciliationNeeded);
                }
                Err(_) => return Err(MaintenanceReadError::ReconciliationNeeded),
            };
            let length = file
                .metadata()
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?
                .len();
            if length > MAX_JOURNAL_BYTES as u64 {
                return Err(MaintenanceReadError::ReconciliationNeeded);
            }
            let mut bytes = Vec::with_capacity(length as usize);
            Read::by_ref(&mut file)
                .take(MAX_JOURNAL_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
            if bytes.len() > MAX_JOURNAL_BYTES {
                return Err(MaintenanceReadError::ReconciliationNeeded);
            }
            Ok(Some(bytes))
        }
        #[cfg(windows)]
        {
            let bytes = self
                .windows
                .load()
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
            if bytes
                .as_ref()
                .is_some_and(|bytes| bytes.len() > MAX_JOURNAL_BYTES)
            {
                return Err(MaintenanceReadError::ReconciliationNeeded);
            }
            Ok(bytes)
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(MaintenanceReadError::Unavailable)
        }
    }
    fn write_bytes(&mut self, bytes: &[u8], first: bool) -> Result<(), MaintenanceReadError> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if first {
                self.lease
                    .write_all(b"maintenance-genesis-v1")
                    .and_then(|()| self.lease.sync_all())
                    .and_then(|()| self.directory.sync_all())
                    .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
            }
            // SAFETY: pinned live descriptor and static C string; unlink does not follow a link.
            let removed = unsafe {
                libc::unlinkat(
                    self.directory.as_raw_fd(),
                    c"maintenance.pending".as_ptr(),
                    0,
                )
            };
            if removed != 0
                && std::io::Error::last_os_error().kind() != std::io::ErrorKind::NotFound
            {
                return Err(MaintenanceReadError::ReconciliationNeeded);
            }
            let mut staging = open_at(
                &self.directory,
                c"maintenance.pending",
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            )
            .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
            staging
                .write_all(bytes)
                .and_then(|()| staging.sync_all())
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
            // SAFETY: both fixed names live under the retained private directory descriptor.
            if unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    c"maintenance.pending".as_ptr(),
                    self.directory.as_raw_fd(),
                    c"maintenance.json".as_ptr(),
                )
            } != 0
            {
                return Err(MaintenanceReadError::ReconciliationNeeded);
            }
            self.directory
                .sync_all()
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)
        }
        #[cfg(windows)]
        {
            self.windows
                .publish(bytes, first)
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (bytes, first);
            Err(MaintenanceReadError::Unavailable)
        }
    }
}
impl MaintenanceJournal for FileJournal {
    fn load(&mut self) -> Result<Option<Snapshot>, MaintenanceReadError> {
        let Some(bytes) = self.read_bytes()? else {
            return Ok(None);
        };
        let envelope: Envelope = serde_json::from_slice(&bytes)
            .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
        let payload = serde_json::to_vec(&envelope.snapshot)
            .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
        if envelope.version != 1 || envelope.sha256 != hash(&payload) {
            return Err(MaintenanceReadError::ReconciliationNeeded);
        }
        Ok(Some(envelope.snapshot))
    }
    fn commit(
        &mut self,
        expected: Option<u64>,
        next: &Snapshot,
    ) -> Result<(), MaintenanceReadError> {
        let actual = self.load()?.map(|snapshot| snapshot.revision);
        let revision = expected.map_or(Some(1), |revision| revision.checked_add(1));
        if actual != expected || revision != Some(next.revision) {
            return Err(MaintenanceReadError::ReconciliationNeeded);
        }
        let payload =
            serde_json::to_vec(next).map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
        let bytes = serde_json::to_vec(&Envelope {
            version: 1,
            sha256: hash(&payload),
            snapshot: next.clone(),
        })
        .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
        if bytes.len() > MAX_JOURNAL_BYTES {
            return Err(MaintenanceReadError::ReconciliationNeeded);
        }
        self.write_bytes(&bytes, expected.is_none())
    }
}

#[cfg(unix)]
fn open_at(directory: &File, name: &std::ffi::CStr, flags: libc::c_int) -> std::io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;
    // SAFETY: valid live borrowed descriptor, fixed terminated name and transfer of new fd.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: successful openat returned this new owned fd exactly once.
    let file = unsafe { File::from_raw_fd(descriptor) };
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no memory preconditions.
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(std::io::Error::other(
            "maintenance requires a private regular file",
        ));
    }
    Ok(file)
}
