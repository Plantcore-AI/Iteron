//! One bounded, descriptor-relative ancestor walk. The returned final directory is the same pin
//! used by journal/cache publication; validating then reopening a pathname would admit a race.
#[cfg(any(unix, windows))]
use super::MaintenanceReadError;
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::path::Component;
#[cfg(any(unix, windows))]
use std::path::Path;

#[cfg(unix)]
pub(super) fn provision(path: &Path) -> Result<File, MaintenanceReadError> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?
            .join(path)
    };
    if absolute.as_os_str().as_bytes().len() > 16 * 1024 {
        return Err(MaintenanceReadError::ReconciliationNeeded);
    }
    let components = absolute.components().collect::<Vec<_>>();
    if components.len() > 64 {
        return Err(MaintenanceReadError::ReconciliationNeeded);
    }
    let mut directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open("/")
        .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
    for component in components {
        let name = match component {
            Component::RootDir => continue,
            Component::Normal(name) => CString::new(name.as_bytes())
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?,
            _ => return Err(MaintenanceReadError::ReconciliationNeeded),
        };
        // SAFETY: retained parent descriptor and one bounded NUL-terminated component.
        let mut raw = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
            )
        };
        if raw < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
            // SAFETY: mkdirat creates only this direct child in the already pinned parent.
            if unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) } != 0
                && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
            {
                return Err(MaintenanceReadError::ReconciliationNeeded);
            }
            // SAFETY: the same component is reopened without following a newly substituted link.
            raw = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
                )
            };
            if raw < 0 {
                return Err(MaintenanceReadError::ReconciliationNeeded);
            }
            // SAFETY: successful new fd is owned and transferred exactly once.
            let child = unsafe { File::from_raw_fd(raw) };
            child
                .sync_all()
                .and_then(|()| directory.sync_all())
                .map_err(|_| MaintenanceReadError::ReconciliationNeeded)?;
            directory = child;
        } else {
            if raw < 0 {
                return Err(MaintenanceReadError::ReconciliationNeeded);
            }
            // SAFETY: successful new fd is owned and transferred exactly once.
            directory = unsafe { File::from_raw_fd(raw) };
        }
    }
    Ok(directory)
}

#[cfg(windows)]
pub(super) fn provision_windows(path: &Path) -> Result<(), MaintenanceReadError> {
    use std::os::windows::ffi::OsStrExt;
    if path.as_os_str().encode_wide().count() > 16 * 1024 || path.components().count() > 64 {
        return Err(MaintenanceReadError::ReconciliationNeeded);
    }
    fn ensure(path: &Path, depth: usize) -> Result<(), MaintenanceReadError> {
        if depth > 64 {
            return Err(MaintenanceReadError::ReconciliationNeeded);
        }
        match std::fs::symlink_metadata(path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let parent = path
                    .parent()
                    .ok_or(MaintenanceReadError::ReconciliationNeeded)?;
                if std::fs::symlink_metadata(parent).is_err() {
                    ensure(parent, depth + 1)?;
                }
            }
            Err(_) => return Err(MaintenanceReadError::ReconciliationNeeded),
        }
        // Existing paths also pass through the native pinned non-reparse walk. Each new
        // component is published only after its own child and immediate-parent flush barriers.
        iteron_support::durable_windows_state::provision_private_directory(path)
            .map_err(|_| MaintenanceReadError::ReconciliationNeeded)
    }
    ensure(path, 0)
}
