//! Capability-relative, bounded transcript snapshot export.
//!
//! Linux export opens the workspace and each parent directory with `O_NOFOLLOW`, writes and syncs
//! an anonymous `O_TMPFILE` inode, and publishes that held inode with an exclusive `linkat` before
//! syncing the directory. There is no temporary pathname for another process to replace and no
//! cleanup unlink that could remove somebody else's replacement. Other platforms fail closed until
//! they provide an equivalent inode-relative, atomically published implementation.

use std::collections::HashSet;
use std::fmt;
#[cfg(target_os = "linux")]
use std::path::Component;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(target_os = "linux")]
use super::capability_fs;
use crate::block;

pub(crate) const MAX_TRANSCRIPT_EXPORT_BYTES: usize = 8 * 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_EXPORT_PATH_BYTES: usize = 4 * 1024;
#[cfg(target_os = "linux")]
const MAX_EXPORT_COMPONENTS: usize = 128;
#[cfg(target_os = "linux")]
const MAX_VERSION_ATTEMPTS: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CollisionPolicy {
    Refuse,
    Versioned,
}

/// Export failures retain whether publication is known not to have happened. This distinction is
/// carried over the helper protocol; callers must never turn an uncertain post-publication
/// durability result into an ordinary retryable failure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) enum ExportError {
    KnownFailure(String),
    OutcomeUnknown(String),
}

impl fmt::Display for ExportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KnownFailure(message) | Self::OutcomeUnknown(message) => {
                formatter.write_str(message)
            }
        }
    }
}

impl ExportError {
    fn known(message: impl Into<String>) -> Self {
        Self::KnownFailure(message.into())
    }

    #[cfg(target_os = "linux")]
    fn unknown(message: impl Into<String>) -> Self {
        Self::OutcomeUnknown(message.into())
    }
}

pub(crate) fn body(
    blocks: &[Arc<block::Block>],
    selected_ids: Option<&[u64]>,
) -> Result<Vec<u8>, String> {
    let selected = selected_ids.map(|ids| ids.iter().copied().collect::<HashSet<_>>());
    let mut body = String::from("# Iteron transcript\n\n");
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

#[cfg(target_os = "linux")]
pub(super) fn export_bytes(
    workspace: &Path,
    requested: &str,
    bytes: &[u8],
    collision: CollisionPolicy,
) -> Result<PathBuf, ExportError> {
    export_bytes_with_hooks(workspace, requested, bytes, collision, || {}, || {})
}

#[cfg(not(target_os = "linux"))]
pub(super) fn export_bytes(
    _workspace: &Path,
    _requested: &str,
    _bytes: &[u8],
    _collision: CollisionPolicy,
) -> Result<PathBuf, ExportError> {
    Err(ExportError::known(
        "secure transcript export requires Linux anonymous-inode publication",
    ))
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
mod unix {
    use std::ffi::{CStr, CString, OsStr};
    use std::fs::File;
    use std::io::{self, Write as _};
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::OsStrExt as _;

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

    fn create_anonymous(parent: &File) -> io::Result<File> {
        let current = c".";
        // SAFETY: the held directory descriptor and static component remain live for the call.
        // `O_TMPFILE` creates an inode with no directory entry, so there is no pathname race or
        // cleanup pathname. Omitting `O_EXCL` deliberately permits the later `linkat` publication.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                current.as_ptr(),
                libc::O_WRONLY | libc::O_TMPFILE | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a successful `openat` returns one owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn publish_held_inode(file: &File, parent: &File, leaf: &CStr) -> io::Result<()> {
        let empty = c"";
        // SAFETY: both descriptors and C strings remain live. `AT_EMPTY_PATH` names the source by
        // descriptor, never by a mutable workspace pathname; the destination is exclusive.
        let direct = unsafe {
            libc::linkat(
                file.as_raw_fd(),
                empty.as_ptr(),
                parent.as_raw_fd(),
                leaf.as_ptr(),
                libc::AT_EMPTY_PATH,
            )
        };
        if direct == 0 {
            return Ok(());
        }
        let direct_error = io::Error::last_os_error();
        if direct_error.kind() == io::ErrorKind::AlreadyExists {
            return Err(direct_error);
        }

        // Unprivileged kernels can reject `AT_EMPTY_PATH`. `/proc/self/fd/N` is still a reference
        // to this process's held descriptor, not a workspace-controlled name. If procfs is absent
        // or refuses the operation, fail closed; never fall back to a named temporary file.
        if !matches!(
            direct_error.raw_os_error(),
            Some(libc::EPERM) | Some(libc::EINVAL) | Some(libc::ENOENT)
        ) {
            return Err(direct_error);
        }
        let descriptor_path = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid descriptor path"))?;
        // SAFETY: the process-owned procfs descriptor path, destination descriptor, and leaf are
        // live. Following this symlink resolves exactly to the still-open anonymous inode.
        let via_proc = unsafe {
            libc::linkat(
                libc::AT_FDCWD,
                descriptor_path.as_ptr(),
                parent.as_raw_fd(),
                leaf.as_ptr(),
                libc::AT_SYMLINK_FOLLOW,
            )
        };
        if via_proc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn write_exclusive(
        parent: &File,
        leaf: &str,
        bytes: &[u8],
        before_publish: &mut dyn FnMut(),
    ) -> Result<(), WriteError> {
        let leaf = c_string(OsStr::new(leaf)).map_err(|_| WriteError::Known)?;
        let mut file = create_anonymous(parent).map_err(|_| WriteError::Known)?;
        if file.write_all(bytes).is_err() || file.sync_all().is_err() {
            return Err(WriteError::Known);
        }
        before_publish();

        if let Err(error) = publish_held_inode(&file, parent, &leaf) {
            return if error.kind() == io::ErrorKind::AlreadyExists {
                Err(WriteError::Exists)
            } else {
                Err(WriteError::Known)
            };
        }
        if parent.sync_all().is_err() {
            return Err(WriteError::OutcomeUnknown);
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn export_bytes_with_hooks<A, P>(
    workspace: &Path,
    requested: &str,
    bytes: &[u8],
    collision: CollisionPolicy,
    acquired: A,
    mut before_publish: P,
) -> Result<PathBuf, ExportError>
where
    A: FnOnce(),
    P: FnMut(),
{
    let (parents, leaf) = parse_relative(requested).map_err(ExportError::known)?;
    let root_binding = capability_fs::RootBinding::open(workspace)
        .map_err(|_| ExportError::known("workspace is unavailable or is a symlink"))?;
    let root = root_binding.root();
    let parent = capability_fs::traverse(root, &parents).map_err(|_| {
        ExportError::known("export parent is unavailable, non-directory, or symlinked")
    })?;
    acquired();
    let rebound = root_binding.still_bound()
        && capability_fs::traverse(root, &parents)
            .and_then(|current| capability_fs::same_file(&parent, &current))
            .unwrap_or(false);
    if !rebound {
        return Err(ExportError::known(
            "workspace root or export parent changed after its directory capability was acquired",
        ));
    }

    let attempts = match collision {
        CollisionPolicy::Refuse => 1,
        CollisionPolicy::Versioned => MAX_VERSION_ATTEMPTS,
    };
    for attempt in 1..=attempts {
        let candidate = versioned_leaf(&leaf, attempt);
        match unix::write_exclusive(&parent, &candidate, bytes, &mut before_publish) {
            Ok(()) => {
                let still_bound = root_binding.still_bound()
                    && capability_fs::traverse(root, &parents)
                        .and_then(|current| capability_fs::same_file(&parent, &current))
                        .unwrap_or(false);
                if !still_bound {
                    return Err(ExportError::unknown(
                        "workspace root or export parent changed during dispatch; publication outcome is unknown",
                    ));
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
                return Err(ExportError::known(
                    "export target already exists; choose a new path",
                ));
            }
            Err(unix::WriteError::Known) => {
                return Err(ExportError::known(
                    "export failed before the final file was published",
                ));
            }
            Err(unix::WriteError::OutcomeUnknown) => {
                return Err(ExportError::unknown(
                    "export was dispatched but durability outcome is unknown",
                ));
            }
        }
    }
    Err(ExportError::known(
        "could not allocate a unique export filename within 100 attempts",
    ))
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

    #[cfg(target_os = "linux")]
    fn export_fixture(
        workspace: &Path,
        blocks: &[Arc<block::Block>],
        selected_ids: Option<&[u64]>,
        requested: &str,
        collision: CollisionPolicy,
    ) -> Result<PathBuf, String> {
        let bytes = body(blocks, selected_ids)?;
        export_bytes(workspace, requested, &bytes, collision).map_err(|error| error.to_string())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn capability_export_is_exclusive_atomic_and_versions_fixed_names() {
        let root = scratch("exclusive");
        std::fs::create_dir_all(root.join("reports")).unwrap();
        let blocks = vec![user(1, "semantic")];
        let first = export_fixture(
            &root,
            &blocks,
            None,
            "reports/session.md",
            CollisionPolicy::Versioned,
        )
        .unwrap();
        let second = export_fixture(
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
            export_fixture(
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

    #[cfg(target_os = "linux")]
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
        let result = export_bytes_with_hooks(
            &root,
            "reports/session.md",
            b"must stay confined",
            CollisionPolicy::Refuse,
            || {
                start_tx.send(()).unwrap();
                done_rx.recv().unwrap();
            },
            || {},
        );
        attacker.join().unwrap();
        assert!(result.is_err());
        assert!(!outside.join("session.md").exists());
        assert!(!root.join("reports-held/session.md").exists());
        std::fs::remove_dir_all(root).ok();
        std::fs::remove_dir_all(outside).ok();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn workspace_root_replacement_before_publication_is_a_known_non_publish() {
        let root = scratch("root-rebind-before");
        let detached = scratch("root-rebind-before-detached");
        std::fs::create_dir_all(root.join("reports")).unwrap();
        let attack_root = root.clone();
        let attack_detached = detached.clone();

        let result = export_bytes_with_hooks(
            &root,
            "reports/session.md",
            b"must not publish",
            CollisionPolicy::Refuse,
            move || {
                std::fs::rename(&attack_root, &attack_detached).unwrap();
                std::fs::create_dir_all(attack_root.join("reports")).unwrap();
            },
            || {},
        );

        assert!(matches!(result, Err(ExportError::KnownFailure(_))));
        assert!(!root.join("reports/session.md").exists());
        assert!(!detached.join("reports/session.md").exists());
        std::fs::remove_dir_all(root).ok();
        std::fs::remove_dir_all(detached).ok();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn workspace_root_replacement_at_publish_can_never_report_success() {
        let root = scratch("root-rebind-publish");
        let detached = scratch("root-rebind-publish-detached");
        std::fs::create_dir_all(root.join("reports")).unwrap();
        let attack_root = root.clone();
        let attack_detached = detached.clone();

        let result = export_bytes_with_hooks(
            &root,
            "reports/session.md",
            b"detached publication evidence",
            CollisionPolicy::Refuse,
            || {},
            move || {
                std::fs::rename(&attack_root, &attack_detached).unwrap();
                std::fs::create_dir_all(attack_root.join("reports")).unwrap();
            },
        );

        assert!(matches!(result, Err(ExportError::OutcomeUnknown(_))));
        assert!(!root.join("reports/session.md").exists());
        assert_eq!(
            std::fs::read(detached.join("reports/session.md")).unwrap(),
            b"detached publication evidence"
        );
        std::fs::remove_dir_all(root).ok();
        std::fs::remove_dir_all(detached).ok();
    }

    #[cfg(target_os = "linux")]
    #[derive(Clone, Copy, Debug)]
    enum AncestorAttack {
        Rename,
        Replace,
        Unlink,
    }

    #[cfg(target_os = "linux")]
    fn attack_workspace_parent(
        attack: AncestorAttack,
        visible_parent: &Path,
        workspace: &Path,
        detached_parent: &Path,
        detached_workspace: &Path,
    ) -> PathBuf {
        match attack {
            AncestorAttack::Rename => {
                std::fs::rename(visible_parent, detached_parent).unwrap();
                detached_parent.join("workspace")
            }
            AncestorAttack::Replace => {
                std::fs::rename(visible_parent, detached_parent).unwrap();
                std::fs::create_dir_all(workspace.join("reports")).unwrap();
                detached_parent.join("workspace")
            }
            AncestorAttack::Unlink => {
                std::fs::rename(workspace, detached_workspace).unwrap();
                std::fs::remove_dir(visible_parent).unwrap();
                detached_workspace.to_path_buf()
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parent_of_workspace_rename_replacement_and_unlink_before_publish_are_known_non_publishes() {
        for attack in [
            AncestorAttack::Rename,
            AncestorAttack::Replace,
            AncestorAttack::Unlink,
        ] {
            let base = scratch(&format!("ancestor-before-{attack:?}"));
            let visible_parent = base.join("visible-parent");
            let workspace = visible_parent.join("workspace");
            let detached_parent = base.join("detached-parent");
            let detached_workspace = base.join("detached-workspace");
            std::fs::create_dir_all(workspace.join("reports")).unwrap();
            let mut publication_root = None;

            let result = export_bytes_with_hooks(
                &workspace,
                "reports/session.md",
                b"must not publish through a detached ancestor",
                CollisionPolicy::Refuse,
                || {
                    publication_root = Some(attack_workspace_parent(
                        attack,
                        &visible_parent,
                        &workspace,
                        &detached_parent,
                        &detached_workspace,
                    ));
                },
                || {},
            );

            assert!(matches!(result, Err(ExportError::KnownFailure(_))));
            assert!(
                !publication_root
                    .expect("attack reports the held workspace")
                    .join("reports/session.md")
                    .exists(),
                "{attack:?} published before the full path-chain revalidation"
            );
            assert!(!workspace.join("reports/session.md").exists());
            std::fs::remove_dir_all(base).ok();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parent_of_workspace_rename_replacement_and_unlink_at_publish_are_never_success() {
        for attack in [
            AncestorAttack::Rename,
            AncestorAttack::Replace,
            AncestorAttack::Unlink,
        ] {
            let base = scratch(&format!("ancestor-publish-{attack:?}"));
            let visible_parent = base.join("visible-parent");
            let workspace = visible_parent.join("workspace");
            let detached_parent = base.join("detached-parent");
            let detached_workspace = base.join("detached-workspace");
            std::fs::create_dir_all(workspace.join("reports")).unwrap();
            let mut publication_root = None;

            let result = export_bytes_with_hooks(
                &workspace,
                "reports/session.md",
                b"detached ancestor publication evidence",
                CollisionPolicy::Refuse,
                || {},
                || {
                    publication_root = Some(attack_workspace_parent(
                        attack,
                        &visible_parent,
                        &workspace,
                        &detached_parent,
                        &detached_workspace,
                    ));
                },
            );

            assert!(matches!(result, Err(ExportError::OutcomeUnknown(_))));
            assert_eq!(
                std::fs::read(
                    publication_root
                        .expect("attack reports the held workspace")
                        .join("reports/session.md")
                )
                .unwrap(),
                b"detached ancestor publication evidence",
                "{attack:?} must expose the detached publication only as unknown"
            );
            assert!(!workspace.join("reports/session.md").exists());
            std::fs::remove_dir_all(base).ok();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn synced_inode_has_no_temporary_name_for_an_attacker_to_replace() {
        let root = scratch("anonymous-race");
        std::fs::create_dir_all(root.join("reports")).unwrap();
        let predictable = format!(".core-export-{}-0.tmp", std::process::id());
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let attack_parent = root.join("reports");
        let attack_name = predictable.clone();
        let attacker = std::thread::spawn(move || {
            ready_rx.recv().unwrap();
            assert!(
                std::fs::read_dir(&attack_parent)
                    .unwrap()
                    .all(|entry| !entry
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".core-export-")),
                "the fully-synced source inode must not have a workspace pathname"
            );
            std::fs::write(
                attack_parent.join(attack_name),
                b"attacker-owned replacement",
            )
            .unwrap();
            done_tx.send(()).unwrap();
        });

        let result = export_bytes_with_hooks(
            &root,
            "reports/session.md",
            b"held-inode bytes",
            CollisionPolicy::Refuse,
            || {},
            || {
                ready_tx.send(()).unwrap();
                done_rx.recv().unwrap();
            },
        )
        .unwrap();
        attacker.join().unwrap();

        assert_eq!(std::fs::read(result).unwrap(), b"held-inode bytes");
        assert_eq!(
            std::fs::read(root.join("reports").join(predictable)).unwrap(),
            b"attacker-owned replacement",
            "export cleanup must never unlink an attacker replacement"
        );
        std::fs::remove_dir_all(root).ok();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn final_symlink_installed_at_the_publish_barrier_is_never_followed_or_unlinked() {
        use std::os::unix::fs::symlink;

        let root = scratch("leaf-race-root");
        let outside = scratch("leaf-race-outside");
        std::fs::create_dir_all(root.join("reports")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let outside_target = outside.join("target.md");
        std::fs::write(&outside_target, b"outside stays intact").unwrap();

        let result = export_bytes_with_hooks(
            &root,
            "reports/session.md",
            b"must not follow the replacement",
            CollisionPolicy::Refuse,
            || {},
            || symlink(&outside_target, root.join("reports/session.md")).unwrap(),
        );

        assert!(result.is_err());
        assert_eq!(
            std::fs::read(&outside_target).unwrap(),
            b"outside stays intact"
        );
        assert!(
            std::fs::symlink_metadata(root.join("reports/session.md"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        std::fs::remove_dir_all(root).ok();
        std::fs::remove_dir_all(outside).ok();
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn platforms_without_inode_relative_atomic_publication_fail_closed() {
        let root = scratch("unsupported");
        std::fs::create_dir_all(&root).unwrap();
        let result = export_bytes(
            &root,
            "session.md",
            b"not published",
            CollisionPolicy::Refuse,
        );
        assert!(result.is_err());
        assert!(!root.join("session.md").exists());
        std::fs::remove_dir_all(root).ok();
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
