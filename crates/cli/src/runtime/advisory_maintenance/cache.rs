//! The actual cache mutation, with a host-only payload and pinned target parent. It is invoked
//! after a durable Running receipt, and returns success only after the cache's own barrier.
use super::{MAX_INPUT_BYTES, MaintenanceKindV1, MaintenanceReadError, hash};
use std::path::Path;
#[cfg(unix)]
use std::{ffi::CString, fs::File, io::Write};

pub(super) struct CacheLease {
    #[cfg(unix)]
    directory: File,
    #[cfg(unix)]
    lease: File,
    #[cfg(unix)]
    target: CString,
    #[cfg(unix)]
    pending: CString,
    #[cfg(windows)]
    windows: iteron_support::durable_windows_state::WindowsSnapshotStore,
    #[cfg(windows)]
    quarantine_guard: iteron_support::durable_windows_state::WindowsSnapshotStore,
}
impl CacheLease {
    pub(super) fn open(
        target: &Path,
        kind: MaintenanceKindV1,
    ) -> Result<Self, MaintenanceReadError> {
        let expected = match kind {
            MaintenanceKindV1::LastSuccessfulRoute => "last-success-route-v1.json",
            MaintenanceKindV1::TokenCalibration => "token-calibration-v1.json",
        };
        if target.file_name().is_none_or(|name| name != expected) {
            return Err(MaintenanceReadError::ReconciliationNeeded);
        }
        let parent = target
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .ok_or(MaintenanceReadError::ReconciliationNeeded)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            super::store::provision_directory(parent)?;
            let directory = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
                .open(parent)
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
            let metadata = directory
                .metadata()
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
            // SAFETY: geteuid has no memory preconditions.
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
                return Err(MaintenanceReadError::ReconciliationNeeded);
            }
            let digest = hash(expected.as_bytes());
            let lock_name = CString::new(format!(".advisory-{}.lock", &digest[7..]))
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
            let lease = open_at(&directory, &lock_name, libc::O_RDWR | libc::O_CREAT, true)
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
            lease
                .try_lock()
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
            // An absorbing uncertainty marker survives releasing the process's file lock.
            if lease
                .metadata()
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?
                .len()
                != 0
            {
                return Err(MaintenanceReadError::ReconciliationNeeded);
            }
            let target =
                CString::new(expected).map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
            match open_at(&directory, &target, libc::O_RDONLY, false) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(MaintenanceReadError::ReconciliationNeeded),
            }
            let pending = CString::new(format!(".advisory-{}.pending", &digest[7..]))
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
            Ok(Self {
                directory,
                lease,
                target,
                pending,
            })
        }
        #[cfg(windows)]
        {
            // The native platform store refuses reparse points, shared/non-NTFS filesystems and
            // an inherited public DACL. Never claim Windows completion through Unix dir-sync.
            iteron_support::durable_windows_state::provision_private_directory(parent)
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
            let digest = hash(expected.as_bytes());
            let mut quarantine_guard =
                iteron_support::durable_windows_state::WindowsSnapshotStore::open(
                    parent,
                    &format!("advisory-cache-writer-{}", &digest[7..]),
                )
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
            if quarantine_guard
                .load()
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?
                .is_some()
            {
                return Err(MaintenanceReadError::ReconciliationNeeded);
            }
            Ok(Self {
                windows: iteron_support::durable_windows_state::WindowsSnapshotStore::open(
                    parent,
                    expected.trim_end_matches(".json"),
                )
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?,
                quarantine_guard,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(MaintenanceReadError::Unavailable)
        }
    }
    pub(super) fn publish(&mut self, bytes: &[u8]) -> Result<(), MaintenanceReadError> {
        if bytes.len() > MAX_INPUT_BYTES {
            return Err(MaintenanceReadError::ReconciliationNeeded);
        }
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: fixed private staging name and retained target directory descriptor.
            let removed =
                unsafe { libc::unlinkat(self.directory.as_raw_fd(), self.pending.as_ptr(), 0) };
            if removed != 0
                && std::io::Error::last_os_error().kind() != std::io::ErrorKind::NotFound
            {
                return Err(MaintenanceReadError::ReconciliationNeeded);
            }
            let mut file = open_at(
                &self.directory,
                &self.pending,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                true,
            )
            .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
            // SAFETY: both names are bound to the pinned directory; rename never follows target.
            if unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    self.pending.as_ptr(),
                    self.directory.as_raw_fd(),
                    self.target.as_ptr(),
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
            // Existing advisory data can predate this writer's lease genesis. The native store
            // verifies and pins the exact cache file; its first flag means absent data only.
            let first = self
                .windows
                .load()
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?
                .is_none();
            self.windows
                .publish(bytes, first)
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = bytes;
            Err(MaintenanceReadError::Unavailable)
        }
    }
    pub(super) fn quarantine(&mut self) -> Result<(), MaintenanceReadError> {
        #[cfg(unix)]
        {
            self.lease
                .write_all(b"cache-outcome-unknown-v1")
                .and_then(|()| self.lease.sync_all())
                .and_then(|()| self.directory.sync_all())
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)
        }
        #[cfg(windows)]
        {
            self.quarantine_guard
                .publish(b"cache-outcome-unknown-v1", true)
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(MaintenanceReadError::Unavailable)
        }
    }
}
#[cfg(unix)]
fn open_at(
    directory: &File,
    name: &std::ffi::CStr,
    flags: libc::c_int,
    private: bool,
) -> std::io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;
    // SAFETY: the live directory and valid terminated name remain borrowed through openat.
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
    // SAFETY: transfer ownership exactly once from a successful openat descriptor.
    let file = unsafe { File::from_raw_fd(descriptor) };
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no memory preconditions.
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & (if private { 0o077 } else { 0o022 }) != 0
    {
        return Err(std::io::Error::other(
            "cache writer requires an owned regular file",
        ));
    }
    Ok(file)
}
