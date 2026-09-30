//! Confirmed registry publication follows durable package bytes and every new directory link.
use super::PackageError;
#[cfg(unix)]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::Read;
#[cfg(unix)]
use std::io::Write;
use std::path::Path;

const MAX_DEPTH: usize = 32;
const MAX_ENTRIES: usize = 8192;
const MAX_FILE_BYTES: usize = 8 * 1024 * 1024;
const MAX_TREE_BYTES: usize = 64 * 1024 * 1024;

pub(super) fn ensure_directory_chain(path: &Path) -> Result<(), PackageError> {
    let mut absent = Vec::new();
    let mut current = path;
    loop {
        match fs::symlink_metadata(current) {
            Ok(metadata) if metadata.is_dir() && !metadata.is_symlink() => break,
            Ok(_) => return Err(invalid(current, "store directory is not a real directory")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if absent.len() >= MAX_DEPTH {
                    return Err(invalid(path, "store directory depth exceeds bound"));
                }
                absent.push(current.to_path_buf());
                current = current
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                    .unwrap_or(Path::new("."));
            }
            Err(error) => return Err(error.into()),
        }
    }
    // Reconcile an existing nearest component too: a prior failed parent barrier may have left
    // this directory visible without confirmation. Its ancestor preceded its own creation.
    #[cfg(windows)]
    iteron_support::durable_windows_state::sync_directory_namespace(&std::path::absolute(current)?)
        .map_err(|_| invalid(current, "store ancestor-link publication unconfirmed"))?;
    #[cfg(not(windows))]
    sync_dir(current)?;
    sync_parent(current)?;
    for directory in absent.into_iter().rev() {
        create_directory(&directory)?;
        sync_dir(&directory)?;
        sync_parent(&directory)?;
    }
    Ok(())
}

fn sync_parent(path: &Path) -> Result<(), PackageError> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    #[cfg(unix)]
    {
        sync_dir(parent)
    }
    #[cfg(windows)]
    {
        iteron_support::durable_windows_state::sync_directory_namespace(&std::path::absolute(
            parent,
        )?)
        .map_err(|_| invalid(path, "store parent-link publication unconfirmed"))
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(invalid(
            path,
            "durable plugin store is unavailable on this platform",
        ))
    }
}

#[cfg(unix)]
fn create_directory(path: &Path) -> Result<(), PackageError> {
    use std::os::unix::fs::DirBuilderExt as _;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path)?;
    Ok(())
}

#[cfg(windows)]
fn create_directory(path: &Path) -> Result<(), PackageError> {
    iteron_support::durable_windows_state::provision_private_directory(&std::path::absolute(path)?)
        .map_err(|_| invalid(path, "private directory publication unconfirmed"))
}

#[cfg(not(any(unix, windows)))]
fn create_directory(path: &Path) -> Result<(), PackageError> {
    Err(invalid(
        path,
        "durable plugin store is unavailable on this platform",
    ))
}

pub(super) fn copy_tree(source: &Path, destination: &Path) -> Result<(), PackageError> {
    let mut entries = 0usize;
    let mut bytes = 0usize;
    copy_directory(source, destination, 0, &mut entries, &mut bytes)
}

/// Existing content-addressed trees can be leftovers of a publication whose barrier failed.
/// Verification precedes this reconciliation; byte and namespace barriers precede registry use.
pub(super) fn sync_existing_tree(root: &Path) -> Result<(), PackageError> {
    let mut entries = 0usize;
    let mut bytes = 0usize;
    sync_tree(root, 0, &mut entries, &mut bytes)?;
    sync_parent(root)
}
fn sync_tree(
    root: &Path,
    depth: usize,
    entries: &mut usize,
    bytes: &mut usize,
) -> Result<(), PackageError> {
    if depth >= MAX_DEPTH {
        return Err(invalid(root, "package directory depth exceeds bound"));
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        *entries += 1;
        if *entries > MAX_ENTRIES {
            return Err(invalid(root, "package entry count exceeds bound"));
        }
        let kind = entry.file_type()?;
        if kind.is_dir() {
            sync_tree(&entry.path(), depth + 1, entries, bytes)?;
        } else if kind.is_file() {
            let length = entry.metadata()?.len();
            if length > MAX_FILE_BYTES as u64 {
                return Err(invalid(root, "package file exceeds byte bound"));
            }
            *bytes = bytes
                .checked_add(length as usize)
                .ok_or_else(|| invalid(root, "package byte count overflow"))?;
            if *bytes > MAX_TREE_BYTES {
                return Err(invalid(root, "package exceeds byte bound"));
            }
            #[cfg(unix)]
            {
                File::open(entry.path())?.sync_all()?;
            }
            #[cfg(windows)]
            {
                iteron_support::durable_windows_state::sync_private_file(&std::path::absolute(
                    entry.path(),
                )?)
                .map_err(|_| {
                    invalid(
                        &entry.path(),
                        "existing package file publication unconfirmed",
                    )
                })?;
            }
        } else {
            return Err(invalid(
                &entry.path(),
                "symlinks and special files are not admitted",
            ));
        }
    }
    sync_dir(root)
}

fn copy_directory(
    source: &Path,
    destination: &Path,
    depth: usize,
    entries: &mut usize,
    bytes: &mut usize,
) -> Result<(), PackageError> {
    if depth >= MAX_DEPTH {
        return Err(invalid(source, "package directory depth exceeds bound"));
    }
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        *entries += 1;
        if *entries > MAX_ENTRIES {
            return Err(invalid(source, "package entry count exceeds bound"));
        }
        let kind = entry.file_type()?;
        let target = destination.join(entry.file_name());
        if kind.is_dir() {
            create_directory(&target)?;
            copy_directory(&entry.path(), &target, depth + 1, entries, bytes)?;
        } else if kind.is_file() {
            let file = File::open(entry.path())?;
            if !file.metadata()?.is_file() {
                return Err(invalid(&entry.path(), "package source changed type"));
            }
            let mut body = Vec::new();
            file.take((MAX_FILE_BYTES + 1) as u64)
                .read_to_end(&mut body)?;
            *bytes = bytes
                .checked_add(body.len())
                .ok_or_else(|| invalid(source, "package byte count overflow"))?;
            if body.len() > MAX_FILE_BYTES || *bytes > MAX_TREE_BYTES {
                return Err(invalid(source, "copied package exceeds byte bound"));
            }
            write_new_private(&target, &body)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = fs::metadata(entry.path())?.permissions().mode() & 0o700;
                fs::set_permissions(&target, fs::Permissions::from_mode(mode | 0o600))?;
                File::open(&target)?.sync_all()?;
            }
        } else {
            return Err(invalid(
                &entry.path(),
                "symlinks and special files are not admitted",
            ));
        }
    }
    // Postorder: child bytes and directories precede their parent namespace barrier.
    sync_dir(destination)
}

#[cfg(unix)]
pub(super) fn write_new_private(path: &Path, bytes: &[u8]) -> Result<(), PackageError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(windows)]
pub(super) fn write_new_private(path: &Path, bytes: &[u8]) -> Result<(), PackageError> {
    iteron_support::durable_windows_state::publish_private_file(&std::path::absolute(path)?, bytes)
        .map_err(|_| invalid(path, "private file publication unconfirmed"))
}

#[cfg(not(any(unix, windows)))]
pub(super) fn write_new_private(path: &Path, _bytes: &[u8]) -> Result<(), PackageError> {
    Err(invalid(
        path,
        "durable plugin store is unavailable on this platform",
    ))
}

#[cfg(unix)]
pub(super) fn sync_dir(path: &Path) -> Result<(), PackageError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
pub(super) fn sync_dir(path: &Path) -> Result<(), PackageError> {
    iteron_support::durable_windows_state::sync_private_directory(&std::path::absolute(path)?)
        .map_err(|_| invalid(path, "private directory publication unconfirmed"))
}

#[cfg(not(any(unix, windows)))]
pub(super) fn sync_dir(path: &Path) -> Result<(), PackageError> {
    Err(invalid(
        path,
        "durable plugin store is unavailable on this platform",
    ))
}

fn invalid(path: &Path, reason: &str) -> PackageError {
    PackageError::InvalidPackage {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}
