//! Capability-relative, bounded transcript snapshot export.
//!
//! Unix export opens the workspace and each parent directory with `O_NOFOLLOW`, then performs the
//! temporary create, durable write, exclusive final link, cleanup, and directory fsync relative to
//! the held parent descriptor. No checked pathname is reopened for the write. Other platforms fail
//! closed until an equivalent reparse-resistant relative-handle implementation is available.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use crate::block;

pub(crate) const MAX_TRANSCRIPT_EXPORT_BYTES: usize = 8 * 1024 * 1024;
const MAX_EXPORT_PATH_BYTES: usize = 4 * 1024;
const MAX_EXPORT_COMPONENTS: usize = 128;
const MAX_VERSION_ATTEMPTS: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CollisionPolicy {
    Refuse,
    Versioned,
}

pub(crate) fn body(
    blocks: &[Arc<block::Block>],
    selected_ids: Option<&[u64]>,
) -> Result<Vec<u8>, String> {
    let selected = selected_ids.map(|ids| ids.iter().copied().collect::<HashSet<_>>());
    let mut body = String::from("# Core Code transcript\n\n");
    for block in blocks {
        if selected
            .as_ref()
            .is_some_and(|selected| !selected.contains(&block.id))
        {
            continue;
        }
        let text = block.to_text();
        if body.len().saturating_add(text.len()).saturating_add(1) > MAX_TRANSCRIPT_EXPORT_BYTES {
            return Err("transcript export exceeds the 8 MiB limit".into());
        }
        body.push_str(&text);
        body.push('\n');
    }
    Ok(body.into_bytes())
}

pub(crate) fn export(
    workspace: &Path,
    blocks: &[Arc<block::Block>],
    selected_ids: Option<&[u64]>,
    requested: &str,
    collision: CollisionPolicy,
) -> Result<PathBuf, String> {
    let bytes = body(blocks, selected_ids)?;
    export_bytes(workspace, requested, &bytes, collision)
}

#[cfg(unix)]
fn export_bytes(
    workspace: &Path,
    requested: &str,
    bytes: &[u8],
    collision: CollisionPolicy,
) -> Result<PathBuf, String> {
    export_bytes_with_hook(workspace, requested, bytes, collision, || {})
}

#[cfg(not(unix))]
fn export_bytes(
    _workspace: &Path,
    _requested: &str,
    _bytes: &[u8],
    _collision: CollisionPolicy,
) -> Result<PathBuf, String> {
    Err("secure transcript export is unavailable on this platform".into())
}

fn parse_relative(requested: &str) -> Result<(Vec<String>, String), String> {
    if requested.is_empty()
        || requested.len() > MAX_EXPORT_PATH_BYTES
        || requested.chars().any(char::is_control)
    {
        return Err("export path must be non-empty, control-free, and at most 4 KiB".into());
    }
    let mut components = Vec::new();
    for component in Path::new(requested).components() {
        let Component::Normal(component) = component else {
            return Err(
                "export path must contain only ordinary workspace-relative components".into(),
            );
        };
        let component = component
            .to_str()
            .ok_or_else(|| "export path components must be valid UTF-8".to_string())?;
        if component.is_empty() {
            return Err("export path contains an empty component".into());
        }
        components.push(component.to_string());
        if components.len() > MAX_EXPORT_COMPONENTS {
            return Err("export path contains too many components".into());
        }
    }
    let leaf = components
        .pop()
        .ok_or_else(|| "export path has no file name".to_string())?;
    Ok((components, leaf))
}

fn versioned_leaf(leaf: &str, attempt: usize) -> String {
    if attempt == 1 {
        return leaf.to_string();
    }
    let path = Path::new(leaf);
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or(leaf);
    match path.extension().and_then(|extension| extension.to_str()) {
        Some(extension) if !extension.is_empty() => format!("{stem}-{attempt}.{extension}"),
        _ => format!("{stem}-{attempt}"),
    }
}

#[cfg(unix)]
mod unix {
    use std::ffi::{CStr, CString, OsStr};
    use std::fs::File;
    use std::io::{self, Write as _};
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum WriteError {
        Exists,
        Known,
        OutcomeUnknown,
    }

    fn c_string(value: &OsStr) -> io::Result<CString> {
        CString::new(value.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
    }

    pub(super) fn open_root(path: &std::path::Path) -> io::Result<File> {
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

    pub(super) fn open_dir(parent: &File, name: &str) -> io::Result<File> {
        let name = c_string(OsStr::new(name))?;
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
            current = open_dir(&current, component)?;
        }
        Ok(current)
    }

    pub(super) fn same_directory(left: &File, right: &File) -> io::Result<bool> {
        let left = left.metadata()?;
        let right = right.metadata()?;
        Ok(left.dev() == right.dev() && left.ino() == right.ino())
    }

    fn unlink(parent: &File, name: &CStr) -> io::Result<()> {
        // SAFETY: descriptor and component are live; `unlinkat` does not follow a leaf symlink.
        let result = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn create(parent: &File, name: &CStr) -> io::Result<File> {
        // SAFETY: descriptor and component are live; flags create one non-followed exclusive file.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a successful `openat` returns one owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    pub(super) fn write_exclusive(
        parent: &File,
        leaf: &str,
        bytes: &[u8],
    ) -> Result<(), WriteError> {
        let leaf = c_string(OsStr::new(leaf)).map_err(|_| WriteError::Known)?;
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = CString::new(format!(
            ".core-export-{}-{sequence}.tmp",
            std::process::id()
        ))
        .map_err(|_| WriteError::Known)?;
        let mut file = create(parent, &temporary).map_err(|_| WriteError::Known)?;
        if file.write_all(bytes).is_err() || file.sync_all().is_err() {
            drop(file);
            return if unlink(parent, &temporary).is_ok() {
                Err(WriteError::Known)
            } else {
                Err(WriteError::OutcomeUnknown)
            };
        }
        drop(file);

        // A hard link publishes the fully-synced inode atomically and fails with EEXIST rather than
        // replacing an existing file. Both names are relative to the same held directory handle.
        // SAFETY: both live C strings and the held descriptor remain valid for the call.
        let linked = unsafe {
            libc::linkat(
                parent.as_raw_fd(),
                temporary.as_ptr(),
                parent.as_raw_fd(),
                leaf.as_ptr(),
                0,
            )
        };
        if linked != 0 {
            let error = io::Error::last_os_error();
            let cleaned = unlink(parent, &temporary).is_ok();
            return if !cleaned {
                Err(WriteError::OutcomeUnknown)
            } else if error.kind() == io::ErrorKind::AlreadyExists {
                Err(WriteError::Exists)
            } else {
                Err(WriteError::Known)
            };
        }
        if unlink(parent, &temporary).is_err() || parent.sync_all().is_err() {
            return Err(WriteError::OutcomeUnknown);
        }
        Ok(())
    }

    pub(super) fn remove_final(parent: &File, leaf: &str) {
        if let Ok(leaf) = c_string(OsStr::new(leaf)) {
            let _ = unlink(parent, &leaf);
            let _ = parent.sync_all();
        }
    }
}

#[cfg(unix)]
fn export_bytes_with_hook<F>(
    workspace: &Path,
    requested: &str,
    bytes: &[u8],
    collision: CollisionPolicy,
    acquired: F,
) -> Result<PathBuf, String>
where
    F: FnOnce(),
{
    let (parents, leaf) = parse_relative(requested)?;
    let root = unix::open_root(workspace)
        .map_err(|_| "workspace is unavailable or is a symlink".to_string())?;
    let parent = unix::traverse(&root, &parents)
        .map_err(|_| "export parent is unavailable, non-directory, or symlinked".to_string())?;
    acquired();
    let rebound = unix::traverse(&root, &parents)
        .and_then(|current| unix::same_directory(&parent, &current))
        .unwrap_or(false);
    if !rebound {
        return Err("export parent changed after its directory capability was acquired".into());
    }

    let attempts = match collision {
        CollisionPolicy::Refuse => 1,
        CollisionPolicy::Versioned => MAX_VERSION_ATTEMPTS,
    };
    for attempt in 1..=attempts {
        let candidate = versioned_leaf(&leaf, attempt);
        match unix::write_exclusive(&parent, &candidate, bytes) {
            Ok(()) => {
                let still_bound = unix::traverse(&root, &parents)
                    .and_then(|current| unix::same_directory(&parent, &current))
                    .unwrap_or(false);
                if !still_bound {
                    unix::remove_final(&parent, &candidate);
                    return Err(
                        "export parent changed during dispatch; output was removed and outcome is unknown"
                            .into(),
                    );
                }
                let mut display = workspace.to_path_buf();
                for component in &parents {
                    display.push(component);
                }
                display.push(candidate);
                return Ok(display);
            }
            Err(unix::WriteError::Exists) if collision == CollisionPolicy::Versioned => continue,
            Err(unix::WriteError::Exists) => {
                return Err("export target already exists; choose a new path".into());
            }
            Err(unix::WriteError::Known) => {
                return Err("export failed before the final file was published".into());
            }
            Err(unix::WriteError::OutcomeUnknown) => {
                return Err("export was dispatched but durability outcome is unknown".into());
            }
        }
    }
    Err("could not allocate a unique export filename within 100 attempts".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(id: u64, text: &str) -> Arc<block::Block> {
        Arc::new(block::Block::new(id, block::BlockKind::User(text.into())))
    }

    fn scratch(label: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "core-transcript-export-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[cfg(unix)]
    #[test]
    fn capability_export_is_exclusive_atomic_and_versions_fixed_names() {
        let root = scratch("exclusive");
        std::fs::create_dir_all(root.join("reports")).unwrap();
        let blocks = vec![user(1, "semantic")];
        let first = export(
            &root,
            &blocks,
            None,
            "reports/session.md",
            CollisionPolicy::Versioned,
        )
        .unwrap();
        let second = export(
            &root,
            &blocks,
            None,
            "reports/session.md",
            CollisionPolicy::Versioned,
        )
        .unwrap();
        assert_eq!(first, root.join("reports/session.md"));
        assert_eq!(second, root.join("reports/session-2.md"));
        assert_eq!(std::fs::read(first).unwrap(), body(&blocks, None).unwrap());
        assert!(
            export(
                &root,
                &blocks,
                None,
                "reports/session.md",
                CollisionPolicy::Refuse,
            )
            .is_err()
        );
        std::fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn parent_symlink_swap_cannot_redirect_the_capability() {
        use std::os::unix::fs::symlink;

        let root = scratch("swap-root");
        let outside = scratch("swap-outside");
        std::fs::create_dir_all(root.join("reports")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let (start_tx, start_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let attack_root = root.clone();
        let attack_outside = outside.clone();
        let attacker = std::thread::spawn(move || {
            start_rx.recv().unwrap();
            std::fs::rename(
                attack_root.join("reports"),
                attack_root.join("reports-held"),
            )
            .unwrap();
            symlink(&attack_outside, attack_root.join("reports")).unwrap();
            done_tx.send(()).unwrap();
        });
        let result = export_bytes_with_hook(
            &root,
            "reports/session.md",
            b"must stay confined",
            CollisionPolicy::Refuse,
            || {
                start_tx.send(()).unwrap();
                done_rx.recv().unwrap();
            },
        );
        attacker.join().unwrap();
        assert!(result.is_err());
        assert!(!outside.join("session.md").exists());
        assert!(!root.join("reports-held/session.md").exists());
        std::fs::remove_dir_all(root).ok();
        std::fs::remove_dir_all(outside).ok();
    }

    #[test]
    fn filtered_and_all_snapshots_share_exact_bounded_bytes() {
        let blocks = vec![user(1, "first"), user(2, "second needle")];
        let all = String::from_utf8(body(&blocks, None).unwrap()).unwrap();
        let filtered = String::from_utf8(body(&blocks, Some(&[2])).unwrap()).unwrap();
        assert!(all.contains("first") && all.contains("second needle"));
        assert!(!filtered.contains("first"));
        assert!(filtered.contains("second needle"));
    }
}
