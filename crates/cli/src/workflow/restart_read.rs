//! Retained sidecar directory capability. Enumeration and every child read use this same held
//! root; a root symlink/reparse point is never canonicalized into an authorized foreign directory.
use std::fs::File;
use std::io::{self, Read};
use std::path::{Component, Path};

pub(super) struct RestartDirectory {
    root: File,
    ancestors: Vec<File>,
    #[cfg(windows)]
    path: std::path::PathBuf,
}

impl RestartDirectory {
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        if absolute.as_os_str().len() > 16384 || absolute.components().count() > 128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "workflow root exceeds its bound",
            ));
        }
        open_directory(&absolute)
    }
    pub(super) fn child(&self, run: &str) -> io::Result<Self> {
        if !super::valid_run_id(run) {
            return Err(invalid());
        }
        let root = open_child_directory(self, run)?;
        let mut ancestors = self
            .ancestors
            .iter()
            .map(File::try_clone)
            .collect::<io::Result<Vec<_>>>()?;
        ancestors.push(self.root.try_clone()?);
        Ok(Self {
            root,
            ancestors,
            #[cfg(windows)]
            path: self.path.join(run),
        })
    }
    pub(super) fn read(&self, name: &str, maximum: usize) -> io::Result<Vec<u8>> {
        if !matches!(
            name,
            "run.json" | "script.js" | "result.json" | "journal.jsonl"
        ) {
            return Err(invalid());
        }
        let file = open_leaf(self, name)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > maximum as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sidecar is not a finite regular file",
            ));
        }
        let mut bytes = Vec::with_capacity((metadata.len() as usize).min(maximum));
        file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > maximum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sidecar exceeds its bound",
            ));
        }
        Ok(bytes)
    }
    pub(super) fn entries(&self) -> io::Result<RestartEntries<'_>> {
        entries(self)
    }
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid ordinary workflow path",
    )
}

#[cfg(unix)]
fn open_directory(path: &Path) -> io::Result<RestartDirectory> {
    use std::os::fd::FromRawFd;
    let root_name = std::ffi::CString::new("/").expect("static root");
    // SAFETY: the static root is NUL terminated; ownership is transferred exactly once.
    let fd = unsafe {
        libc::open(
            root_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is owned by this successful open.
    let mut root = unsafe { File::from_raw_fd(fd) };
    let mut ancestors = Vec::new();
    for part in path.components() {
        match part {
            Component::RootDir => {}
            Component::Normal(name) => {
                let child = unix_open(&root, name, true)?;
                ancestors.push(root);
                root = child;
            }
            _ => return Err(invalid()),
        }
    }
    Ok(RestartDirectory { root, ancestors })
}
#[cfg(unix)]
fn unix_open(parent: &File, name: &std::ffi::OsStr, directory: bool) -> io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| invalid())?;
    let flags = libc::O_RDONLY
        | libc::O_NOFOLLOW
        | libc::O_CLOEXEC
        | if directory {
            libc::O_DIRECTORY
        } else {
            libc::O_NONBLOCK
        };
    // SAFETY: the held parent and NUL-terminated ordinary component remain live through openat.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is an owned successful openat result.
    Ok(unsafe { File::from_raw_fd(fd) })
}
#[cfg(unix)]
fn open_child_directory(parent: &RestartDirectory, name: &str) -> io::Result<File> {
    unix_open(&parent.root, std::ffi::OsStr::new(name), true)
}
#[cfg(unix)]
fn open_leaf(parent: &RestartDirectory, name: &str) -> io::Result<File> {
    unix_open(&parent.root, std::ffi::OsStr::new(name), false)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) struct RestartEntries<'a> {
    stream: std::ptr::NonNull<libc::DIR>,
    _root: &'a RestartDirectory,
    finished: bool,
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn entries(root: &RestartDirectory) -> io::Result<RestartEntries<'_>> {
    use std::os::fd::{AsRawFd, IntoRawFd};
    // A fresh open of the fixed dot component creates an independent enumeration offset while
    // retaining the exact held directory. dup would share the parent's directory offset.
    let owned = unix_open(&root.root, std::ffi::OsStr::new("."), true)?;
    let fd = owned.as_raw_fd();
    // SAFETY: this is a held directory descriptor, valid until the directory stream closes.
    let stream = unsafe { libc::fdopendir(fd) };
    let Some(stream) = std::ptr::NonNull::new(stream) else {
        return Err(io::Error::last_os_error());
    };
    let _ = owned.into_raw_fd();
    Ok(RestartEntries {
        stream,
        _root: root,
        finished: false,
    })
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Iterator for RestartEntries<'_> {
    type Item = io::Result<std::ffi::OsString>;
    fn next(&mut self) -> Option<Self::Item> {
        use std::os::unix::ffi::OsStringExt;
        if self.finished {
            return None;
        }
        #[cfg(target_os = "linux")]
        // SAFETY: libc exposes this thread's errno slot; no other call intervenes before readdir.
        let errno = unsafe { libc::__errno_location() };
        #[cfg(target_os = "macos")]
        // SAFETY: libc exposes this thread's errno slot; no other call intervenes before readdir.
        let errno = unsafe { libc::__error() };
        // SAFETY: errno is a live thread-local slot and stream is the owned directory stream.
        let entry = unsafe {
            *errno = 0;
            libc::readdir(self.stream.as_ptr())
        };
        if entry.is_null() {
            self.finished = true;
            // SAFETY: errno still refers to the same thread-local readdir result.
            return (unsafe { *errno } != 0).then(|| Err(io::Error::last_os_error()));
        }
        // SAFETY: readdir's current entry contains a NUL-terminated name until the next call.
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        Some(Ok(std::ffi::OsString::from_vec(name.to_bytes().to_vec())))
    }
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for RestartEntries<'_> {
    fn drop(&mut self) {
        // SAFETY: this instance uniquely owns the directory stream and closes it exactly once.
        unsafe {
            libc::closedir(self.stream.as_ptr());
        }
    }
}

#[cfg(windows)]
fn windows_open(path: &Path, directory: bool) -> io::Result<File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(
            FILE_FLAG_OPEN_REPARSE_POINT
                | if directory {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    0
                },
        )
        .open(path)?;
    let metadata = file.metadata()?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (directory && !metadata.is_dir())
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "sidecar namespace is not an ordinary retained directory",
        ));
    }
    Ok(file)
}
#[cfg(windows)]
fn open_directory(path: &Path) -> io::Result<RestartDirectory> {
    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err(invalid());
    };
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(invalid());
    }
    let mut anchor = std::path::PathBuf::from(prefix.as_os_str());
    anchor.push(std::path::MAIN_SEPARATOR_STR);
    let mut root = windows_open(&anchor, true)?;
    // Resolve the volume namespace immediately from a retained handle. All subsequent component
    // opens use this same volume identity rather than a mutable DOS drive mapping.
    let mut held_path = windows_final_path(&root)?;
    let mut held = Vec::new();
    for part in components {
        match part {
            Component::Normal(name) => {
                held_path.push(name);
                let next = windows_open(&held_path, true)?;
                held.push(root);
                root = next;
            }
            _ => return Err(invalid()),
        }
    }
    Ok(RestartDirectory {
        root,
        ancestors: held,
        path: held_path,
    })
}
#[cfg(windows)]
fn windows_final_path(root: &File) -> io::Result<std::path::PathBuf> {
    use std::os::windows::{ffi::OsStringExt, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{GetFinalPathNameByHandleW, VOLUME_NAME_GUID};
    let mut name = vec![0u16; 16384];
    // SAFETY: the retained directory handle and initialized bounded output buffer are live.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            root.as_raw_handle(),
            name.as_mut_ptr(),
            name.len() as u32,
            VOLUME_NAME_GUID,
        )
    } as usize;
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    if length >= name.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "retained directory name exceeds its bound",
        ));
    }
    name.truncate(length);
    // Retain the no-delete-share chain, and enumerate a volume-GUID namespace derived from the
    // held root handle. A later DOS drive mapping cannot substitute another volume's directory.
    Ok(std::path::PathBuf::from(std::ffi::OsString::from_wide(
        &name,
    )))
}
#[cfg(windows)]
fn open_child_directory(parent: &RestartDirectory, name: &str) -> io::Result<File> {
    windows_open(&parent.path.join(name), true)
}
#[cfg(windows)]
fn open_leaf(parent: &RestartDirectory, name: &str) -> io::Result<File> {
    windows_open(&parent.path.join(name), false)
}
#[cfg(windows)]
pub(super) struct RestartEntries<'a> {
    iterator: std::fs::ReadDir,
    _root: &'a RestartDirectory,
}
#[cfg(windows)]
fn entries(root: &RestartDirectory) -> io::Result<RestartEntries<'_>> {
    Ok(RestartEntries {
        iterator: std::fs::read_dir(&root.path)?,
        _root: root,
    })
}
#[cfg(windows)]
impl Iterator for RestartEntries<'_> {
    type Item = io::Result<std::ffi::OsString>;
    fn next(&mut self) -> Option<Self::Item> {
        self.iterator
            .next()
            .map(|entry| entry.map(|entry| entry.file_name()))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub(super) struct RestartEntries<'a>(std::marker::PhantomData<&'a RestartDirectory>);
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn entries(_root: &RestartDirectory) -> io::Result<RestartEntries<'_>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "retained workflow enumeration is unavailable",
    ))
}
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
impl Iterator for RestartEntries<'_> {
    type Item = io::Result<std::ffi::OsString>;
    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}
#[cfg(not(any(unix, windows)))]
fn open_directory(_path: &Path) -> io::Result<RestartDirectory> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "retained workflow directories are unavailable",
    ))
}
#[cfg(not(any(unix, windows)))]
fn open_child_directory(_parent: &RestartDirectory, _name: &str) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "retained workflow children are unavailable",
    ))
}
#[cfg(not(any(unix, windows)))]
fn open_leaf(_parent: &RestartDirectory, _name: &str) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "retained workflow reads are unavailable",
    ))
}
