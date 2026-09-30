//! The same directory handle validates ancestry and performs the actual snapshot publication.
use super::MAX_RECORD_SNAPSHOT_BYTES;
#[cfg(unix)]
use std::{
    fs::File,
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd},
};
use std::{io, path::Path};

pub(super) struct Journal {
    poisoned: bool,
    #[cfg(unix)]
    directory: File,
    #[cfg(unix)]
    lease: File,
    #[cfg(windows)]
    windows: iteron_support::durable_windows_state::WindowsSnapshotStore,
}

impl Journal {
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            let directory = pin(path, true)?;
            let lease = open_at(&directory, c"records-v1.lock", libc::O_RDWR | libc::O_CREAT)?;
            lease.try_lock().map_err(|error| match error {
                std::fs::TryLockError::WouldBlock => {
                    io::Error::new(io::ErrorKind::WouldBlock, "memory writer lease is busy")
                }
                std::fs::TryLockError::Error(error) => error,
            })?;
            Ok(Self {
                poisoned: false,
                directory,
                lease,
            })
        }
        #[cfg(windows)]
        {
            provision_windows(path, 0)?;
            let windows = iteron_support::durable_windows_state::WindowsSnapshotStore::open(
                path,
                "records-v1",
            )
            .map_err(platform_error)?;
            Ok(Self {
                poisoned: false,
                windows,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = path;
            Err(unsupported())
        }
    }
    pub(super) fn load(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.poisoned {
            return Err(unknown());
        }
        #[cfg(unix)]
        {
            read_at(&self.directory)
        }
        #[cfg(windows)]
        {
            let bytes = self.windows.load().map_err(platform_error)?;
            if bytes
                .as_ref()
                .is_some_and(|bytes| bytes.len() > MAX_RECORD_SNAPSHOT_BYTES)
            {
                return Err(super::invalid());
            }
            Ok(bytes)
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(unsupported())
        }
    }
    pub(super) fn publish(&mut self, bytes: &[u8], first: bool) -> io::Result<()> {
        if self.poisoned || bytes.is_empty() || bytes.len() > MAX_RECORD_SNAPSHOT_BYTES {
            return Err(unknown());
        }
        let result = self.publish_inner(bytes, first);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn publish_inner(&mut self, bytes: &[u8], first: bool) -> io::Result<()> {
        #[cfg(unix)]
        {
            if first {
                self.lease.write_all(b"memory-records-v1")?;
                self.lease.sync_all()?;
                self.directory.sync_all()?;
            }
            // Only stale staging is removed; committed records are never discarded on retry.
            // SAFETY: direct child of the retained directory; unlink does not follow a symlink.
            if unsafe {
                libc::unlinkat(
                    self.directory.as_raw_fd(),
                    c"records-v1.pending".as_ptr(),
                    0,
                )
            } != 0
                && io::Error::last_os_error().kind() != io::ErrorKind::NotFound
            {
                return Err(unknown());
            }
            let mut staging = open_at(
                &self.directory,
                c"records-v1.pending",
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            )?;
            staging.write_all(bytes)?;
            staging.sync_all()?;
            // SAFETY: both bounded static filenames are relative to the same retained directory.
            if unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    c"records-v1.pending".as_ptr(),
                    self.directory.as_raw_fd(),
                    c"records-v1.json".as_ptr(),
                )
            } != 0
            {
                return Err(unknown());
            }
            self.directory.sync_all().map_err(|_| unknown())
        }
        #[cfg(windows)]
        {
            self.windows.publish(bytes, first).map_err(platform_error)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (bytes, first);
            Err(unsupported())
        }
    }
}

pub(super) fn read(path: &Path) -> io::Result<Option<Vec<u8>>> {
    #[cfg(unix)]
    {
        let directory = match pin(path, false) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        read_at(&directory)
    }
    #[cfg(windows)]
    {
        if !path.exists() {
            return Ok(None);
        }
        let mut windows =
            iteron_support::durable_windows_state::WindowsSnapshotStore::open(path, "records-v1")
                .map_err(platform_error)?;
        let bytes = windows.load().map_err(platform_error)?;
        if bytes
            .as_ref()
            .is_some_and(|bytes| bytes.len() > MAX_RECORD_SNAPSHOT_BYTES)
        {
            return Err(super::invalid());
        }
        Ok(bytes)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(unsupported())
    }
}

#[cfg(unix)]
fn read_at(directory: &File) -> io::Result<Option<Vec<u8>>> {
    let mut file = match open_at(directory, c"records-v1.json", libc::O_RDONLY) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match open_at(directory, c"records-v1.lock", libc::O_RDONLY) {
                Ok(lease) if lease.metadata()?.len() != 0 => return Err(unknown()),
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    if file.metadata()?.len() > MAX_RECORD_SNAPSHOT_BYTES as u64 {
        return Err(super::invalid());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_RECORD_SNAPSHOT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_RECORD_SNAPSHOT_BYTES {
        return Err(super::invalid());
    }
    Ok(Some(bytes))
}

#[cfg(unix)]
fn open_at(directory: &File, name: &std::ffi::CStr, flags: i32) -> io::Result<File> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: retained fd and static NUL-terminated child name, no path traversal.
    let raw = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful newly allocated fd is transferred exactly once.
    let file = unsafe { File::from_raw_fd(raw) };
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no pointer preconditions.
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "memory journal must be private and regular",
        ));
    }
    Ok(file)
}

#[cfg(unix)]
fn pin(path: &Path, create: bool) -> io::Result<File> {
    use std::{
        ffi::CString,
        os::unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
        path::Component,
    };
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    if absolute.as_os_str().as_bytes().len() > 16 * 1024 || absolute.components().count() > 64 {
        return Err(super::invalid());
    }
    let mut directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open("/")?;
    for component in absolute.components() {
        let name = match component {
            Component::RootDir => continue,
            Component::Normal(name) => {
                CString::new(name.as_bytes()).map_err(|_| super::invalid())?
            }
            _ => return Err(super::invalid()),
        };
        // SAFETY: one direct component under the retained live parent fd.
        let mut raw = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
            )
        };
        let mut created = false;
        if raw < 0 && create && io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
            // SAFETY: bounded single child component; no link followed.
            if unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) } != 0
                && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
            {
                return Err(io::Error::last_os_error());
            }
            created = true;
            // SAFETY: reopen same component without following a substituted link.
            raw = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
                )
            };
        }
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful newly allocated fd is transferred exactly once.
        let child = unsafe { File::from_raw_fd(raw) };
        if created {
            child.sync_all()?;
            directory.sync_all()?;
        }
        directory = child;
    }
    let metadata = directory.metadata()?;
    // Existing legacy directories may be readable; no other principal may modify the store.
    // SAFETY: geteuid has no pointer preconditions.
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "memory store has an unsafe writer",
        ));
    }
    Ok(directory)
}

#[cfg(windows)]
fn provision_windows(path: &Path, depth: usize) -> io::Result<()> {
    if depth > 64 {
        return Err(super::invalid());
    }
    if !path.exists() {
        let parent = path.parent().ok_or_else(super::invalid)?;
        if !parent.exists() {
            provision_windows(parent, depth + 1)?;
        }
    }
    iteron_support::durable_windows_state::provision_private_directory(path).map_err(platform_error)
}
#[cfg(windows)]
fn platform_error(_: iteron_support::durable_windows_state::WindowsStateError) -> io::Error {
    unknown()
}
fn unknown() -> io::Error {
    io::Error::other(
        "memory publication unavailable or uncertain; reopen and inspect durable record",
    )
}
#[cfg(not(any(unix, windows)))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "durable memory is unavailable on this platform",
    )
}
