//! Filesystem adapter for the controller's compare-and-commit journal.
//!
//! The composition root supplies an already durable, private application-state directory.
//! All namespace operations are relative to its pinned directory handle. A uncertain post-rename
//! sync poisons the controller; it must reopen and reconcile before any execution resumes.

use crate::{AgentControllerJournal, AgentControllerSnapshot, ControllerStoreError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

const MAX_FILE_BYTES: usize = 32 * 1024 * 1024 + 1_024;
const FILE_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    sha256: String,
    snapshot: AgentControllerSnapshot,
}

pub struct AgentFileJournal {
    #[cfg(unix)]
    directory: File,
    #[cfg(unix)]
    _lease: File,
}

impl AgentFileJournal {
    /// Unix currently supplies the required atomic namespace + directory fsync contract.
    /// Other platforms return a typed refusal before opening state, never a weaker journal.
    pub fn open(directory: &Path) -> Result<Self, ControllerStoreError> {
        #[cfg(unix)]
        {
            use std::fs::OpenOptions;
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            let directory = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
                .open(directory)
                .map_err(|_| ControllerStoreError::Unavailable)?;
            let metadata = directory
                .metadata()
                .map_err(|_| ControllerStoreError::Unavailable)?;
            // SAFETY: geteuid has no parameters or memory preconditions.
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
                return Err(ControllerStoreError::Unavailable);
            }
            let lease = open_at(&directory, c"agents.lock", libc::O_RDWR | libc::O_CREAT)
                .map_err(|_| ControllerStoreError::Unavailable)?;
            lease
                .try_lock()
                .map_err(|_| ControllerStoreError::Conflict)?;
            Ok(Self {
                directory,
                _lease: lease,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = directory;
            Err(ControllerStoreError::Unavailable)
        }
    }
}

impl AgentControllerJournal for AgentFileJournal {
    fn load(&mut self) -> Result<Option<AgentControllerSnapshot>, ControllerStoreError> {
        #[cfg(unix)]
        {
            let mut file = match open_at(&self.directory, c"agents.json", libc::O_RDONLY) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    // A durable genesis intent forbids treating a lost snapshot as a new tree.
                    if self
                        ._lease
                        .metadata()
                        .map_err(|_| ControllerStoreError::Unavailable)?
                        .len()
                        != 0
                    {
                        return Err(ControllerStoreError::OutcomeUnknown);
                    }
                    return Ok(None);
                }
                Err(_) => return Err(ControllerStoreError::Unavailable),
            };
            let length = file
                .metadata()
                .map_err(|_| ControllerStoreError::Unavailable)?
                .len();
            if length > MAX_FILE_BYTES as u64 {
                return Err(ControllerStoreError::Unavailable);
            }
            let mut bytes = Vec::with_capacity(length as usize);
            Read::by_ref(&mut file)
                .take(MAX_FILE_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| ControllerStoreError::Unavailable)?;
            if bytes.len() > MAX_FILE_BYTES {
                return Err(ControllerStoreError::Unavailable);
            }
            let envelope: Envelope =
                serde_json::from_slice(&bytes).map_err(|_| ControllerStoreError::Unavailable)?;
            let snapshot_bytes = serde_json::to_vec(&envelope.snapshot)
                .map_err(|_| ControllerStoreError::Unavailable)?;
            if envelope.version != FILE_VERSION
                || envelope.sha256 != format!("{:x}", Sha256::digest(&snapshot_bytes))
            {
                return Err(ControllerStoreError::Unavailable);
            }
            Ok(Some(envelope.snapshot))
        }
        #[cfg(not(unix))]
        {
            Err(ControllerStoreError::Unavailable)
        }
    }

    fn commit(
        &mut self,
        expected: Option<u64>,
        next: &AgentControllerSnapshot,
    ) -> Result<(), ControllerStoreError> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let previous = self.load()?.map(|snapshot| snapshot.revision());
            if previous != expected {
                return Err(ControllerStoreError::Conflict);
            }
            if next.revision() != expected.map_or(0, |revision| revision.saturating_add(1)) {
                return Err(ControllerStoreError::Conflict);
            }
            let snapshot_bytes =
                serde_json::to_vec(next).map_err(|_| ControllerStoreError::Unavailable)?;
            let envelope = Envelope {
                version: FILE_VERSION,
                sha256: format!("{:x}", Sha256::digest(&snapshot_bytes)),
                snapshot: next.clone(),
            };
            let bytes =
                serde_json::to_vec(&envelope).map_err(|_| ControllerStoreError::Unavailable)?;
            if bytes.len() > MAX_FILE_BYTES {
                return Err(ControllerStoreError::Unavailable);
            }
            if expected.is_none() {
                self._lease
                    .write_all(b"agent-genesis-v1")
                    .and_then(|()| self._lease.sync_all())
                    .and_then(|()| self.directory.sync_all())
                    .map_err(|_| ControllerStoreError::OutcomeUnknown)?;
            }
            // A left-over staging name has never been a committed namespace. Only our private
            // directory is touched; unlinkat never follows a symlink or deletes its target.
            // SAFETY: the live directory fd and static NUL-terminated name are valid throughout.
            let removed = unsafe {
                libc::unlinkat(self.directory.as_raw_fd(), c"agents.pending".as_ptr(), 0)
            };
            if removed != 0
                && std::io::Error::last_os_error().kind() != std::io::ErrorKind::NotFound
            {
                return Err(ControllerStoreError::Unavailable);
            }
            let mut staging = open_at(
                &self.directory,
                c"agents.pending",
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            )
            .map_err(|_| ControllerStoreError::Unavailable)?;
            staging
                .write_all(&bytes)
                .and_then(|()| staging.sync_all())
                .map_err(|_| ControllerStoreError::Unavailable)?;
            // SAFETY: both names are static C strings relative to the pinned private directory.
            let renamed = unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    c"agents.pending".as_ptr(),
                    self.directory.as_raw_fd(),
                    c"agents.json".as_ptr(),
                )
            };
            if renamed != 0 {
                return Err(ControllerStoreError::OutcomeUnknown);
            }
            self.directory
                .sync_all()
                .map_err(|_| ControllerStoreError::OutcomeUnknown)
        }
        #[cfg(not(unix))]
        {
            let _ = (expected, next);
            Err(ControllerStoreError::Unavailable)
        }
    }
}

#[cfg(unix)]
fn open_at(directory: &File, name: &std::ffi::CStr, flags: libc::c_int) -> std::io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;
    // SAFETY: openat receives a borrowed live directory descriptor and a valid C string; a
    // successful descriptor is transferred exactly once to File.
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
    // SAFETY: descriptor is a newly owned successful openat result.
    let file = unsafe { File::from_raw_fd(descriptor) };
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no parameters or memory preconditions.
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(std::io::Error::other(
            "controller state requires a private regular file",
        ));
    }
    Ok(file)
}
