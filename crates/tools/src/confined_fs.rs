//! Descriptor-relative mutations for the ordinary confined workspace posture.
//! A symlink or replaced parent cannot redirect a transaction through a pathname.

use std::ffi::{CString, OsStr, OsString};
use std::fs::{File, Metadata};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

#[derive(Debug)]
pub(crate) struct ConfinedTarget {
    root: File,
    parents: Vec<(OsString, File)>,
    leaf: OsString,
}

fn c_name(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

fn owned(fd: libc::c_int) -> io::Result<File> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: a successful open/openat returns exactly one owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn open_dir_at(parent: &File, name: &OsStr) -> io::Result<File> {
    let name = c_name(name)?;
    // SAFETY: the descriptor and NUL-terminated name remain live during the call.
    owned(unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })
}

fn same_dir(left: &File, right: &File) -> io::Result<bool> {
    let left = left.metadata()?;
    let right = right.metadata()?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

impl ConfinedTarget {
    pub(crate) fn open(root: &Path, target: &Path, create_parents: bool) -> io::Result<Self> {
        let canonical_root = root.canonicalize()?;
        let relative = target.strip_prefix(&canonical_root).map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "target is outside workspace",
            )
        })?;
        let mut names = Vec::new();
        for component in relative.components() {
            match component {
                Component::Normal(name) if !name.to_string_lossy().eq_ignore_ascii_case(".git") => {
                    names.push(name.to_os_string());
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "invalid workspace component",
                    ));
                }
            }
        }
        let leaf = names.pop().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "target is workspace root")
        })?;
        let path = c_name(canonical_root.as_os_str())?;
        // SAFETY: path is live and a successful open owns the returned descriptor.
        let root = owned(unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })?;
        let mut current = root.try_clone()?;
        let mut parents = Vec::with_capacity(names.len());
        for name in names {
            let next = match open_dir_at(&current, &name) {
                Ok(next) => next,
                Err(error) if create_parents && error.kind() == io::ErrorKind::NotFound => {
                    let name_c = c_name(&name)?;
                    // SAFETY: current is a retained directory descriptor and name is live.
                    let result =
                        unsafe { libc::mkdirat(current.as_raw_fd(), name_c.as_ptr(), 0o777) };
                    if result < 0
                        && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
                    {
                        return Err(io::Error::last_os_error());
                    }
                    open_dir_at(&current, &name)?
                }
                Err(error) => return Err(error),
            };
            current = next.try_clone()?;
            parents.push((name, next));
        }
        Ok(Self {
            root,
            parents,
            leaf,
        })
    }

    fn parent(&self) -> &File {
        self.parents.last().map_or(&self.root, |(_, file)| file)
    }

    pub(crate) fn still_visible(&self) -> io::Result<bool> {
        let mut current = self.root.try_clone()?;
        for (name, expected) in &self.parents {
            let reopened = match open_dir_at(&current, name) {
                Ok(file) => file,
                Err(_) => return Ok(false),
            };
            if !same_dir(expected, &reopened)? {
                return Ok(false);
            }
            current = reopened;
        }
        Ok(true)
    }

    pub(crate) fn require_visible(&self) -> io::Result<()> {
        if self.still_visible()? {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "outside workspace: parent changed",
            ))
        }
    }

    pub(crate) fn metadata(&self) -> io::Result<Option<Metadata>> {
        let name = c_name(&self.leaf)?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: stat points to writable storage; the retained descriptor and name are live.
        let rc = unsafe {
            libc::fstatat(
                self.parent().as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(error)
            };
        }
        // Open the leaf to obtain a Rust Metadata and reject symlinks/FIFOs/devices.
        let file = self.open_existing()?;
        Ok(Some(file.metadata()?))
    }

    pub(crate) fn open_existing(&self) -> io::Result<File> {
        self.require_visible()?;
        let name = c_name(&self.leaf)?;
        // O_NONBLOCK prevents a swapped FIFO from blocking admission.
        // SAFETY: the retained parent descriptor and NUL-terminated name remain live.
        let file = owned(unsafe {
            libc::openat(
                self.parent().as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        })?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "target is not a regular file",
            ));
        }
        self.require_visible()?;
        Ok(file)
    }

    pub(crate) fn create_temporary(&self, name: &OsStr) -> io::Result<File> {
        self.require_visible()?;
        let name = c_name(name)?;
        // The temporary belongs to the stable workspace root. A hostile rename of the target
        // parent cannot carry already-open transaction bytes outside the allowed hierarchy.
        // SAFETY: the retained root descriptor and NUL-terminated name remain live.
        owned(unsafe {
            libc::openat(
                self.root.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        })
    }

    pub(crate) fn rename_temporary(&self, name: &OsStr) -> io::Result<()> {
        self.require_visible()?;
        let temporary = c_name(name)?;
        let target = c_name(&self.leaf)?;
        // SAFETY: both names and the retained parent descriptor remain live.
        let rc = unsafe {
            libc::renameat(
                self.root.as_raw_fd(),
                temporary.as_ptr(),
                self.parent().as_raw_fd(),
                target.as_ptr(),
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(crate) fn sync_parent(&self) -> io::Result<()> {
        #[cfg(debug_assertions)]
        if std::env::var_os("ITERON_HELPER_FAIL_PARENT_SYNC").is_some() {
            return Err(io::Error::other(
                "injected parent sync failure after rename",
            ));
        }
        self.parent().sync_all()?;
        self.root.sync_all()
    }

    pub(crate) fn remove_temporary(&self, name: &OsStr) {
        if let Ok(name) = c_name(name) {
            // SAFETY: name and retained root descriptor remain live.
            let _ = unsafe { libc::unlinkat(self.root.as_raw_fd(), name.as_ptr(), 0) };
        }
    }
}
