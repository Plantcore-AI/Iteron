//! Linux filesystem capabilities shared by pathname-facing TUI effects.
//!
//! Every component is opened relative to a retained directory descriptor with `O_NOFOLLOW`.
//! Reopening the complete path chain lets a caller prove that a held capability still denotes the
//! operator-visible workspace path immediately before it consumes or publishes data.

use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path};

const MAX_CAPABILITY_PATH_BYTES: usize = 4 * 1024;
const MAX_CAPABILITY_COMPONENTS: usize = 128;
/// Identity verdict when `stat` itself fails during rebinding. Fail-closed: an unprovable match is
/// treated as a changed path, so a broken check can only refuse, never admit. Not a tunable.
const SAME_FILE_UNPROVEN: bool = false;

fn c_string(value: &OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

fn open_path(path: &Path) -> io::Result<File> {
    let path = c_string(path.as_os_str())?;
    // SAFETY: `path` is a live NUL-terminated string; returned ownership is checked below.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful `open` returns one owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_dir(parent: &File, name: &OsStr) -> io::Result<File> {
    let name = c_string(name)?;
    // SAFETY: both descriptor and NUL-terminated component remain live for the call.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful `openat` returns one owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(super) fn traverse(root: &File, parents: &[String]) -> io::Result<File> {
    let mut current = root.try_clone()?;
    for component in parents {
        current = open_dir(&current, OsStr::new(component))?;
    }
    Ok(current)
}

/// Open a leaf without following it and without allowing a FIFO/device/socket to block the TUI.
/// The returned descriptor is accepted only when `fstat` identifies the held inode as regular.
pub(super) fn open_regular_nonblocking(parent: &File, leaf: &str) -> io::Result<File> {
    let leaf = c_string(OsStr::new(leaf))?;
    // SAFETY: the held parent descriptor and NUL-terminated leaf remain live for this call.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful `openat` returns one owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    if metadata.mode() & libc::S_IFMT != libc::S_IFREG {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "leaf is not a regular file",
        ));
    }
    Ok(file)
}

/// Stable binding for every component of the operator-visible workspace pathname.
///
/// Holding only the workspace descriptor is insufficient: an ancestor can be renamed, unlinked,
/// or replaced while that descriptor remains valid. Start at the process's filesystem root,
/// retain every directory capability in the chain, and reopen the entire chain for revalidation.
pub(super) struct RootBinding {
    anchor: File,
    components: Vec<OsString>,
    chain: Vec<File>,
}

impl RootBinding {
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        if absolute.as_os_str().as_bytes().len()
            > iteron_tunables::param_integer(
                "cli.tui.capability_fs.max_capability_path_bytes",
                MAX_CAPABILITY_PATH_BYTES,
            )
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "workspace path is too long",
            ));
        }
        let mut saw_root = false;
        let mut components = Vec::new();
        for component in absolute.components() {
            match component {
                Component::RootDir => saw_root = true,
                Component::CurDir => {}
                Component::Normal(component) if saw_root => {
                    components.push(component.to_os_string());
                    if components.len()
                        > iteron_tunables::param_integer(
                            "cli.tui.capability_fs.max_capability_components",
                            MAX_CAPABILITY_COMPONENTS,
                        )
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "workspace path has too many components",
                        ));
                    }
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "workspace path is not an absolute ordinary-component path",
                    ));
                }
            }
        }
        if !saw_root {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "workspace path has no filesystem root",
            ));
        }

        let anchor = open_path(Path::new("/"))?;
        let mut chain = Vec::with_capacity(components.len());
        let mut current = anchor.try_clone()?;
        for component in &components {
            current = open_dir(&current, component)?;
            chain.push(current.try_clone()?);
        }
        Ok(Self {
            anchor,
            components,
            chain,
        })
    }

    pub(super) fn root(&self) -> &File {
        self.chain.last().unwrap_or(&self.anchor)
    }

    pub(super) fn still_bound(&self) -> bool {
        let Ok(mut current) = self.anchor.try_clone() else {
            return false;
        };
        for (component, expected) in self.components.iter().zip(&self.chain) {
            let Ok(reopened) = open_dir(&current, component) else {
                return false;
            };
            if !same_file(expected, &reopened).unwrap_or(SAME_FILE_UNPROVEN) {
                return false;
            }
            current = reopened;
        }
        true
    }
}

pub(super) fn same_file(left: &File, right: &File) -> io::Result<bool> {
    let left = left.metadata()?;
    let right = right.metadata()?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}
