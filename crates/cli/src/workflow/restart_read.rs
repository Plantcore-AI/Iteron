//! Bounded regular-file reads beneath a host-owned sidecar directory. Every ancestor is retained
//! while bytes are read; symlinks/reparse points and special files cannot redirect/block a read.
use std::fs::File;
use std::io::{self, Read};
use std::path::{Component, Path};

pub(super) fn read(root: &Path, run: &str, name: &str, maximum: usize) -> io::Result<Vec<u8>> {
    if !super::valid_run_id(run)
        || !matches!(
            name,
            "run.json" | "script.js" | "result.json" | "journal.jsonl"
        )
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid workflow sidecar identity",
        ));
    }
    let path = root.join(run).join(name);
    let absolute = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };
    if absolute.as_os_str().len() > 16384 || absolute.components().count() > 128 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "workflow sidecar path exceeds its bound",
        ));
    }
    let (file, _ancestors) = open(&absolute)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > maximum as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "workflow sidecar is unavailable or exceeds its bound",
        ));
    }
    let mut bytes = Vec::with_capacity((file.metadata()?.len() as usize).min(maximum));
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "workflow sidecar exceeds its bound",
        ));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open(path: &Path) -> io::Result<(File, Vec<File>)> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    let parts = path
        .components()
        .filter_map(|part| match part {
            Component::Normal(part) => Some(Ok(part)),
            Component::RootDir => None,
            _ => Some(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "nonordinary sidecar path",
            ))),
        })
        .collect::<io::Result<Vec<_>>>()?;
    let root = CString::new("/").expect("static root");
    // SAFETY: the root string is NUL terminated; ownership of a successful fd is transferred once.
    let root_fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: root_fd is an owned descriptor returned by open.
    let mut ancestors = vec![unsafe { File::from_raw_fd(root_fd) }];
    for (index, part) in parts.iter().enumerate() {
        let leaf = index + 1 == parts.len();
        let name = CString::new(part.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL sidecar component"))?;
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | if leaf {
                libc::O_NONBLOCK
            } else {
                libc::O_DIRECTORY
            };
        // SAFETY: the parent descriptor and component remain live through openat.
        let fd = unsafe {
            libc::openat(
                ancestors.last().expect("root retained").as_raw_fd(),
                name.as_ptr(),
                flags,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is a successful owned openat descriptor.
        let file = unsafe { File::from_raw_fd(fd) };
        if leaf {
            return Ok((file, ancestors));
        }
        ancestors.push(file);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "sidecar leaf is absent",
    ))
}

#[cfg(windows)]
fn open(path: &Path) -> io::Result<(File, Vec<File>)> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let mut ancestors = Vec::new();
    let mut prefix = std::path::PathBuf::new();
    let parts = path.components().collect::<Vec<_>>();
    for (index, part) in parts.iter().enumerate() {
        match part {
            Component::Prefix(_) | Component::RootDir => {
                prefix.push(part.as_os_str());
                continue;
            }
            Component::Normal(_) => prefix.push(part.as_os_str()),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "nonordinary sidecar path",
                ));
            }
        }
        let leaf = index + 1 == parts.len();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(
                FILE_FLAG_OPEN_REPARSE_POINT | if leaf { 0 } else { FILE_FLAG_BACKUP_SEMANTICS },
            )
            .open(&prefix)?;
        let metadata = file.metadata()?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || (!leaf && !metadata.is_dir())
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "sidecar ancestor is not a retained ordinary directory",
            ));
        }
        // FILE_SHARE_DELETE is absent: each held ancestor/leaf stays bound through this read.
        if leaf {
            return Ok((file, ancestors));
        }
        ancestors.push(file);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "sidecar leaf is absent",
    ))
}

#[cfg(not(any(unix, windows)))]
fn open(_path: &Path) -> io::Result<(File, Vec<File>)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "retained sidecar reads are unavailable",
    ))
}
