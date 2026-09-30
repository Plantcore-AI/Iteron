//! Bounded Unix state namespace admission. Every component is opened from a retained parent
//! descriptor; generic symlink canonicalization is never an authority check. The same leaf pin
//! is transferred to the journal, and every child/parent link receives a real sync barrier.
use crate::ControllerStoreError;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path};

const MAX_PATH_BYTES: usize = 16 * 1024;
const MAX_COMPONENTS: usize = 64;
const MAX_PINS: usize = MAX_COMPONENTS + 2;

pub(super) struct DirectoryPin {
    pub(super) directory: File,
    pub(super) ancestors: Vec<File>,
}

pub(super) fn pin(path: &Path, create_final: bool) -> Result<DirectoryPin, ControllerStoreError> {
    pin_with_barrier(path, create_final, |file, _, _| file.sync_all())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BarrierSide {
    Child,
    Parent,
}

fn pin_with_barrier(
    path: &Path,
    create_final: bool,
    mut barrier: impl FnMut(&File, bool, BarrierSide) -> std::io::Result<()>,
) -> Result<DirectoryPin, ControllerStoreError> {
    if path.as_os_str().as_bytes().len() > MAX_PATH_BYTES {
        return Err(ControllerStoreError::Unavailable);
    }
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|_| ControllerStoreError::Unavailable)?
            .join(path)
    };
    if absolute.as_os_str().as_bytes().len() > MAX_PATH_BYTES {
        return Err(ControllerStoreError::Unavailable);
    }
    let components: Vec<_> = absolute.components().collect();
    if components.len() > MAX_COMPONENTS || components.is_empty() {
        return Err(ControllerStoreError::Unavailable);
    }
    let root = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open("/")
        .map_err(|_| ControllerStoreError::Unavailable)?;
    let mut pins = vec![root];
    let mut created_final = false;
    for (index, component) in components.iter().enumerate() {
        let name = match component {
            Component::RootDir => continue,
            Component::Normal(name) => {
                CString::new(name.as_bytes()).map_err(|_| ControllerStoreError::Unavailable)?
            }
            _ => return Err(ControllerStoreError::Unavailable),
        };
        let parent = pins.last().ok_or(ControllerStoreError::Unavailable)?;
        let mut child = open_child(parent, &name);
        #[cfg(target_os = "macos")]
        if child.is_err() && pins.len() == 1 {
            if let Some((private, target)) = protected_system_alias(parent, &name)? {
                pins.push(private);
                pins.push(target);
                continue;
            }
        }
        if child
            .as_ref()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
            && create_final
            && index + 1 == components.len()
        {
            // SAFETY: retained live parent and a single validated, terminated component.
            let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
            if result == 0 {
                created_final = true;
            } else if std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists {
                return Err(ControllerStoreError::Unavailable);
            }
            child = open_child(parent, &name);
        }
        let child = child.map_err(|_| {
            if created_final {
                ControllerStoreError::OutcomeUnknown
            } else {
                ControllerStoreError::Unavailable
            }
        })?;
        pins.push(child);
        if pins.len() > MAX_PINS {
            return Err(ControllerStoreError::Unavailable);
        }
    }
    let leaf = pins.last().ok_or(ControllerStoreError::Unavailable)?;
    let metadata = leaf.metadata().map_err(|_| {
        if created_final {
            ControllerStoreError::OutcomeUnknown
        } else {
            ControllerStoreError::Unavailable
        }
    })?;
    // SAFETY: geteuid has no pointer or memory preconditions.
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(if created_final {
            ControllerStoreError::OutcomeUnknown
        } else {
            ControllerStoreError::Unavailable
        });
    }
    // Existing links are also synced: reopening a path that was recently provisioned elsewhere
    // must not assume a descendant snapshot fsync establishes the entire ancestor namespace.
    for index in 1..pins.len() {
        let created = created_final && index + 1 == pins.len();
        barrier(&pins[index], created, BarrierSide::Child)
            .and_then(|()| barrier(&pins[index - 1], created, BarrierSide::Parent))
            .map_err(|_| ControllerStoreError::OutcomeUnknown)?;
    }
    let directory = pins.pop().ok_or(ControllerStoreError::Unavailable)?;
    Ok(DirectoryPin {
        directory,
        ancestors: pins,
    })
}

fn open_child(parent: &File, name: &CStr) -> std::io::Result<File> {
    // SAFETY: borrowed live directory fd and validated single terminated name; successful new fd
    // is transferred exactly once to File. NONBLOCK prevents a non-directory device open hang.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | libc::O_DIRECTORY
                | libc::O_NONBLOCK,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: newly owned successful openat descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(target_os = "macos")]
fn protected_system_alias(
    root: &File,
    name: &CStr,
) -> Result<Option<(File, File)>, ControllerStoreError> {
    // macOS /tmp and /var are protected root aliases used by native temp directories. Accept
    // only their exact shipped /private targets; no arbitrary user/state symlink gets followed.
    let target = match name.to_bytes() {
        b"tmp" => c"tmp",
        b"var" => c"var",
        _ => return Ok(None),
    };
    let root_metadata = root
        .metadata()
        .map_err(|_| ControllerStoreError::Unavailable)?;
    if root_metadata.uid() != 0 || root_metadata.mode() & 0o022 != 0 {
        return Err(ControllerStoreError::Unavailable);
    }
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: valid root/name and a writable stat result; only read on successful initialization.
    if unsafe {
        libc::fstatat(
            root.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(ControllerStoreError::Unavailable);
    }
    // SAFETY: fstatat returned successful initialization.
    let metadata = unsafe { metadata.assume_init() };
    if metadata.st_uid != 0
        || (metadata.st_mode as u32 & libc::S_IFMT as u32) != libc::S_IFLNK as u32
    {
        return Err(ControllerStoreError::Unavailable);
    }
    let mut bytes = [0_u8; 128];
    // SAFETY: valid descriptor/name and bounded writable buffer; readlinkat has no trailing NUL.
    let length = unsafe {
        libc::readlinkat(
            root.as_raw_fd(),
            name.as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if length < 0 || length as usize >= bytes.len() {
        return Err(ControllerStoreError::Unavailable);
    }
    let relative = if target.to_bytes() == b"tmp" {
        b"private/tmp".as_slice()
    } else {
        b"private/var".as_slice()
    };
    let absolute = if target.to_bytes() == b"tmp" {
        b"/private/tmp".as_slice()
    } else {
        b"/private/var".as_slice()
    };
    if &bytes[..length as usize] != relative && &bytes[..length as usize] != absolute {
        return Err(ControllerStoreError::Unavailable);
    }
    let private = open_child(root, c"private").map_err(|_| ControllerStoreError::Unavailable)?;
    let metadata = private
        .metadata()
        .map_err(|_| ControllerStoreError::Unavailable)?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(ControllerStoreError::Unavailable);
    }
    let target = open_child(&private, target).map_err(|_| ControllerStoreError::Unavailable)?;
    Ok(Some((private, target)))
}

#[cfg(test)]
#[path = "controller_directory_tests.rs"]
mod tests;
