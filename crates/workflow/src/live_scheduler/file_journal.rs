//! Private application-state adapter. The untrusted workspace is never a journal directory.
//!
//! Unix pins an owner-only directory and holds an independent writer lease across atomic snapshot
//! replacement. Windows delegates only byte publication to the private local NTFS adapter;
//! snapshot schema, integrity and compare-and-commit remain owned by this workflow domain.

#[cfg(not(windows))]
use std::path::Path;

use super::{WorkflowPlanJournal, WorkflowSchedulerSnapshotV1, WorkflowStoreError};

#[cfg(unix)]
mod unix {
    use std::ffi::CString;
    use std::fs::{File, TryLockError};
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;

    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::live_scheduler::MAX_PLAN_STORE_BYTES;

    const SNAPSHOT: &[u8] = b"workflow.json\0";
    const PENDING: &[u8] = b"workflow.pending\0";
    const LEASE: &[u8] = b"workflow.lock\0";

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Envelope {
        version: u32,
        digest: String,
        snapshot: WorkflowSchedulerSnapshotV1,
    }

    pub struct WorkflowFileJournal {
        directory: File,
        lease: File,
    }

    impl WorkflowFileJournal {
        pub fn open(directory: &Path) -> Result<Self, WorkflowStoreError> {
            let path = CString::new(directory.as_os_str().as_encoded_bytes())
                .map_err(|_| WorkflowStoreError::Unavailable)?;
            // SAFETY: NUL-terminated path, owned fd on success, no-follow prevents final symlink.
            let raw = unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if raw < 0 {
                return Err(WorkflowStoreError::Unavailable);
            }
            // SAFETY: `open` returned a fresh valid descriptor and ownership transfers once.
            let directory = unsafe { File::from_raw_fd(raw) };
            Self::from_directory(directory)
        }

        /// Open one host-computed component relative to the pinned private registry directory.
        /// No absolute path lookup can redirect graph admission after a namespace rename.
        pub fn open_relative(
            parent: &File,
            component: &std::ffi::CStr,
        ) -> Result<Self, WorkflowStoreError> {
            if component.to_bytes().is_empty()
                || component
                    .to_bytes()
                    .iter()
                    .any(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
            {
                return Err(WorkflowStoreError::Unavailable);
            }
            // SAFETY: terminated single component and live borrowed parent; no final-link follow.
            let raw = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    component.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if raw < 0 {
                return Err(WorkflowStoreError::Unavailable);
            }
            // SAFETY: successful openat transfers its new descriptor once.
            Self::from_directory(unsafe { File::from_raw_fd(raw) })
        }

        fn from_directory(directory: File) -> Result<Self, WorkflowStoreError> {
            let metadata = directory
                .metadata()
                .map_err(|_| WorkflowStoreError::Unavailable)?;
            // SAFETY: geteuid has no preconditions.
            let uid = unsafe { libc::geteuid() };
            if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
                return Err(WorkflowStoreError::Unavailable);
            }
            let lease = open_at(&directory, LEASE, libc::O_RDWR | libc::O_CREAT)?;
            match lease.try_lock() {
                Ok(()) => {}
                Err(TryLockError::WouldBlock) => return Err(WorkflowStoreError::Conflict),
                Err(TryLockError::Error(_)) => return Err(WorkflowStoreError::Unavailable),
            }
            Ok(Self { directory, lease })
        }
    }

    impl WorkflowPlanJournal for WorkflowFileJournal {
        fn load(&mut self) -> Result<Option<WorkflowSchedulerSnapshotV1>, WorkflowStoreError> {
            let mut file = match open_at(&self.directory, SNAPSHOT, libc::O_RDONLY) {
                Ok(file) => file,
                Err(WorkflowStoreError::Unavailable) => {
                    // Missing and unreadable are distinct. A durable genesis marker forbids a
                    // lost snapshot from masquerading as an empty workflow after restart.
                    // SAFETY: fixed NUL-terminated component and valid pinned directory fd.
                    let missing = unsafe {
                        libc::faccessat(
                            self.directory.as_raw_fd(),
                            SNAPSHOT.as_ptr().cast(),
                            libc::F_OK,
                            libc::AT_SYMLINK_NOFOLLOW,
                        )
                    } < 0
                        && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound;
                    if !missing {
                        return Err(WorkflowStoreError::Unavailable);
                    }
                    if self
                        .lease
                        .metadata()
                        .map_err(|_| WorkflowStoreError::Unavailable)?
                        .len()
                        != 0
                    {
                        return Err(WorkflowStoreError::OutcomeUnknown);
                    }
                    return Ok(None);
                }
                Err(error) => return Err(error),
            };
            let length = file
                .metadata()
                .map_err(|_| WorkflowStoreError::Unavailable)?
                .len();
            if length > MAX_PLAN_STORE_BYTES {
                return Err(WorkflowStoreError::Unavailable);
            }
            let mut bytes = Vec::with_capacity(length as usize);
            Read::by_ref(&mut file)
                .take(MAX_PLAN_STORE_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| WorkflowStoreError::Unavailable)?;
            if bytes.len() as u64 > MAX_PLAN_STORE_BYTES {
                return Err(WorkflowStoreError::Unavailable);
            }
            let envelope: Envelope =
                serde_json::from_slice(&bytes).map_err(|_| WorkflowStoreError::Unavailable)?;
            let payload = serde_json::to_vec(&envelope.snapshot)
                .map_err(|_| WorkflowStoreError::Unavailable)?;
            if envelope.version != 1 || envelope.digest != hex::encode(Sha256::digest(payload)) {
                return Err(WorkflowStoreError::Unavailable);
            }
            Ok(Some(envelope.snapshot))
        }

        fn commit(
            &mut self,
            expected: Option<u64>,
            next: &WorkflowSchedulerSnapshotV1,
        ) -> Result<(), WorkflowStoreError> {
            let current = self.load()?.map(|snapshot| snapshot.sequence());
            if current != expected {
                return Err(WorkflowStoreError::Conflict);
            }
            let payload = serde_json::to_vec(next).map_err(|_| WorkflowStoreError::Unavailable)?;
            let envelope = Envelope {
                version: 1,
                digest: hex::encode(Sha256::digest(payload)),
                snapshot: next.clone(),
            };
            let encoded =
                serde_json::to_vec(&envelope).map_err(|_| WorkflowStoreError::Unavailable)?;
            if encoded.len() as u64 > MAX_PLAN_STORE_BYTES {
                return Err(WorkflowStoreError::Unavailable);
            }
            if expected.is_none() {
                self.lease
                    .write_all(b"workflow-genesis-v1")
                    .and_then(|_| self.lease.sync_all())
                    .and_then(|_| self.directory.sync_all())
                    .map_err(|_| WorkflowStoreError::OutcomeUnknown)?;
            }
            // Remove a stale staging name only inside the pinned private directory. unlinkat does
            // not follow symlinks; publication itself uses create-new and rename within that fd.
            // SAFETY: fixed NUL-terminated name and valid pinned directory descriptor.
            unsafe {
                libc::unlinkat(self.directory.as_raw_fd(), PENDING.as_ptr().cast(), 0);
            }
            let mut pending = open_at(
                &self.directory,
                PENDING,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            )?;
            pending
                .write_all(&encoded)
                .and_then(|_| pending.sync_all())
                .map_err(|_| WorkflowStoreError::Unavailable)?;
            // SAFETY: both fixed components are NUL-terminated and share a pinned directory fd.
            let renamed = unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    PENDING.as_ptr().cast(),
                    self.directory.as_raw_fd(),
                    SNAPSHOT.as_ptr().cast(),
                )
            };
            if renamed != 0 {
                return Err(WorkflowStoreError::OutcomeUnknown);
            }
            self.directory
                .sync_all()
                .map_err(|_| WorkflowStoreError::OutcomeUnknown)
        }
    }

    fn open_at(
        directory: &File,
        name: &[u8],
        flags: libc::c_int,
    ) -> Result<File, WorkflowStoreError> {
        // SAFETY: all callers pass static NUL-terminated names and a valid pinned directory fd.
        let raw = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr().cast(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if raw < 0 {
            return Err(WorkflowStoreError::Unavailable);
        }
        // SAFETY: openat returned a fresh descriptor transferred exactly once.
        let file = unsafe { File::from_raw_fd(raw) };
        let metadata = file
            .metadata()
            .map_err(|_| WorkflowStoreError::Unavailable)?;
        // SAFETY: geteuid has no preconditions.
        let uid = unsafe { libc::geteuid() };
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != uid
            || metadata.mode() & 0o077 != 0
        {
            return Err(WorkflowStoreError::Unavailable);
        }
        Ok(file)
    }
}

#[cfg(unix)]
pub use unix::WorkflowFileJournal;

#[cfg(windows)]
#[path = "file_journal_windows.rs"]
mod windows;
#[cfg(windows)]
pub use windows::WorkflowFileJournal;

#[cfg(not(any(unix, windows)))]
pub struct WorkflowFileJournal;

#[cfg(not(any(unix, windows)))]
impl WorkflowFileJournal {
    pub fn open(_: &Path) -> Result<Self, WorkflowStoreError> {
        Err(WorkflowStoreError::Unavailable)
    }
}

#[cfg(not(any(unix, windows)))]
impl WorkflowPlanJournal for WorkflowFileJournal {
    fn load(&mut self) -> Result<Option<WorkflowSchedulerSnapshotV1>, WorkflowStoreError> {
        Err(WorkflowStoreError::Unavailable)
    }
    fn commit(
        &mut self,
        _: Option<u64>,
        _: &WorkflowSchedulerSnapshotV1,
    ) -> Result<(), WorkflowStoreError> {
        Err(WorkflowStoreError::Unavailable)
    }
}
