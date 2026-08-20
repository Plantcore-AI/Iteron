//! Native workspace file creation and replacement.
//! `write_file` is the safe alternative to routing ordinary source creation through `bash`: it
//! stays inside the canonical workspace, rejects deceptive Unicode, creates parent directories,
//! and replaces the destination with a same-directory transaction file.

use crate::edit::suspicious_unicode;
use crate::{Registry, ToolError, boxfut, err_result, ok_result, resolve_in_root};
use iteron_protocol::{Capability, Purity, ToolSpec};
use sha2::{Digest, Sha256};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(crate) const MAX_FILE_TRANSACTION_BYTES: usize = 4 * 1024 * 1024;
const MAX_WRITE_BYTES: usize = MAX_FILE_TRANSACTION_BYTES;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_TEMP_ATTEMPTS: usize = 32;
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, PartialEq, Eq)]
struct MetadataStamp {
    len: u64,
    modified: Option<SystemTime>,
    created: Option<SystemTime>,
    readonly: bool,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    change_time_seconds: i64,
    #[cfg(unix)]
    change_time_nanoseconds: i64,
    #[cfg(unix)]
    mode: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExistingTarget {
    stamp: MetadataStamp,
    digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TargetSnapshot {
    Missing,
    Existing(ExistingTarget),
}

pub(crate) struct ExistingFileSnapshot {
    pub(crate) bytes: Vec<u8>,
    pub(crate) target: TargetSnapshot,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SnapshotError {
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("target exceeds the {MAX_FILE_TRANSACTION_BYTES}-byte transaction limit")]
    TooLarge,
    #[error("target is not a regular file")]
    NotRegular,
    #[error("target changed while its snapshot was being read")]
    ChangedDuringRead,
}

struct CapturedTarget {
    state: TargetSnapshot,
    bytes: Vec<u8>,
}

pub(crate) async fn read_existing_snapshot(
    target: &Path,
) -> Result<ExistingFileSnapshot, SnapshotError> {
    let captured = capture_target(target).await?;
    if matches!(captured.state, TargetSnapshot::Missing) {
        return Err(SnapshotError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "target does not exist",
        )));
    }
    Ok(ExistingFileSnapshot {
        bytes: captured.bytes,
        target: captured.state,
    })
}

pub(crate) async fn capture_target_snapshot(
    target: &Path,
) -> Result<TargetSnapshot, SnapshotError> {
    Ok(capture_target(target).await?.state)
}

async fn capture_target(target: &Path) -> Result<CapturedTarget, SnapshotError> {
    let path_before = match tokio::fs::symlink_metadata(target).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(CapturedTarget {
                state: TargetSnapshot::Missing,
                bytes: Vec::new(),
            });
        }
        Err(error) => return Err(SnapshotError::Io(error)),
    };
    if !path_before.is_file() || path_before.file_type().is_symlink() {
        return Err(SnapshotError::NotRegular);
    }
    let max_transaction_bytes = iteron_tunables::param_usize(
        "tools.write_file.max_file_transaction_bytes",
        iteron_tunables::param_integer(
            "tools.write_file.max_file_transaction_bytes",
            MAX_FILE_TRANSACTION_BYTES,
        ),
    );
    if path_before.len() > max_transaction_bytes as u64 {
        return Err(SnapshotError::TooLarge);
    }

    let mut options = tokio::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options.open(target).await.map_err(SnapshotError::Io)?;
    let opened_before = file.metadata().await.map_err(SnapshotError::Io)?;
    if !opened_before.is_file() || metadata_stamp(&path_before) != metadata_stamp(&opened_before) {
        return Err(SnapshotError::ChangedDuringRead);
    }

    let capacity = usize::try_from(opened_before.len())
        .unwrap_or(max_transaction_bytes)
        .min(max_transaction_bytes)
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(capacity);
    let mut limited = file.take(max_transaction_bytes.saturating_add(1) as u64);
    limited
        .read_to_end(&mut bytes)
        .await
        .map_err(SnapshotError::Io)?;
    if bytes.len() > max_transaction_bytes {
        return Err(SnapshotError::TooLarge);
    }
    let opened_after = limited
        .into_inner()
        .metadata()
        .await
        .map_err(SnapshotError::Io)?;
    let path_after = tokio::fs::symlink_metadata(target)
        .await
        .map_err(SnapshotError::Io)?;
    let stamp = metadata_stamp(&opened_after);
    if metadata_stamp(&opened_before) != stamp || metadata_stamp(&path_after) != stamp {
        return Err(SnapshotError::ChangedDuringRead);
    }
    let digest = Sha256::digest(&bytes).into();
    Ok(CapturedTarget {
        state: TargetSnapshot::Existing(ExistingTarget { stamp, digest }),
        bytes,
    })
}

fn metadata_stamp(metadata: &std::fs::Metadata) -> MetadataStamp {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    MetadataStamp {
        len: metadata.len(),
        modified: metadata.modified().ok(),
        created: metadata.created().ok(),
        readonly: metadata.permissions().readonly(),
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
        #[cfg(unix)]
        change_time_seconds: metadata.ctime(),
        #[cfg(unix)]
        change_time_nanoseconds: metadata.ctime_nsec(),
        #[cfg(unix)]
        mode: metadata.mode(),
    }
}

struct TemporaryFile(PathBuf);

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A fully-written, fsynced same-directory replacement that has not touched its destination yet.
/// Multi-file patching stages every member before committing the first one.
pub(crate) struct StagedWrite {
    target: PathBuf,
    temporary: TemporaryFile,
}

#[derive(Debug)]
pub(crate) struct CommitFailure {
    pub(crate) error: io::Error,
    /// True when rename succeeded but syncing the containing directory failed.
    pub(crate) target_replaced: bool,
}

#[derive(Debug)]
pub(crate) enum GuardedCommitFailure {
    Changed,
    Inspect(io::Error),
    Commit(CommitFailure),
}

impl StagedWrite {
    pub(crate) async fn prepare(target: &Path, content: &[u8]) -> io::Result<Self> {
        let max_transaction_bytes = iteron_tunables::param_usize(
            "tools.write_file.max_file_transaction_bytes",
            iteron_tunables::param_integer(
                "tools.write_file.max_file_transaction_bytes",
                MAX_FILE_TRANSACTION_BYTES,
            ),
        );
        if content.len() > max_transaction_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("replacement exceeds the {max_transaction_bytes}-byte transaction limit"),
            ));
        }
        let parent = target
            .parent()
            .ok_or_else(|| io::Error::other("write target has no parent directory"))?;
        let existing_permissions = match tokio::fs::metadata(target).await {
            Ok(metadata) => Some(metadata.permissions()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let (temporary_path, opened_file) = allocate_temporary(parent).await?;
        // Declared before `file`, so cancellation drops the open handle first and then removes the
        // transaction path (important on platforms that cannot unlink an open file).
        let staged = Self {
            target: target.to_path_buf(),
            temporary: TemporaryFile(temporary_path),
        };
        let mut file = opened_file;
        file.write_all(content).await?;
        file.flush().await?;
        if let Some(permissions) = existing_permissions {
            tokio::fs::set_permissions(&staged.temporary.0, permissions).await?;
        }
        file.sync_all().await?;
        drop(file);
        Ok(staged)
    }

    pub(crate) async fn commit(self) -> Result<(), CommitFailure> {
        self.commit_inner(false).await
    }

    pub(crate) async fn commit_if_unchanged(
        self,
        expected: &TargetSnapshot,
    ) -> Result<(), GuardedCommitFailure> {
        let actual = match capture_target_snapshot(&self.target).await {
            Ok(snapshot) => snapshot,
            Err(SnapshotError::Io(error)) => {
                return Err(GuardedCommitFailure::Inspect(error));
            }
            Err(
                SnapshotError::TooLarge
                | SnapshotError::NotRegular
                | SnapshotError::ChangedDuringRead,
            ) => return Err(GuardedCommitFailure::Changed),
        };
        if &actual != expected {
            return Err(GuardedCommitFailure::Changed);
        }
        self.commit().await.map_err(GuardedCommitFailure::Commit)
    }

    async fn commit_inner(self, inject_before_rename: bool) -> Result<(), CommitFailure> {
        #[cfg(unix)]
        let parent = self
            .target
            .parent()
            .expect("staging requires a destination parent");
        if inject_before_rename {
            return Err(CommitFailure {
                error: io::Error::other("injected fault before atomic rename"),
                target_replaced: false,
            });
        }
        if let Err(error) = tokio::fs::rename(&self.temporary.0, &self.target).await {
            return Err(CommitFailure {
                error,
                target_replaced: false,
            });
        }
        #[cfg(unix)]
        if let Err(error) = std::fs::File::open(parent).and_then(|directory| directory.sync_all()) {
            return Err(CommitFailure {
                error,
                target_replaced: true,
            });
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn commit_with_fault_before_rename(self) -> Result<(), CommitFailure> {
        self.commit_inner(true).await
    }

    #[cfg(test)]
    pub(crate) fn temporary_path(&self) -> &Path {
        &self.temporary.0
    }
}

pub(crate) fn register(registry: &mut Registry) -> Result<(), ToolError> {
    registry.push_tool(
        ToolSpec {
            name: "write_file".into(),
            description: "Create or replace one UTF-8 text file inside the workspace. Missing \
                          parent directories are created. The same-directory replacement is \
                          fsynced, atomic, bounded to 4 MiB, and refused if the destination changes \
                          while staging. Use this instead of bash for new source/config files. \
                          Paths and content containing bidi or zero-width controls are refused."
                .into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "destination path relative to the workspace root"
                    },
                    "content": {
                        "type": "string",
                        "description": "complete UTF-8 file content, up to 4 MiB"
                    }
                },
                "required": ["path", "content"]
            }),
            purity: Purity::Effecting,
            capability: Capability::ReversibleLocal,
        },
        |call, root| {
            boxfut::box_it(async move {
                let id = call.id.clone();
                let Some(path) = call.input.get("path").and_then(|value| value.as_str()) else {
                    return err_result(id, "write_file: missing string field `path`".into());
                };
                let Some(content) = call.input.get("content").and_then(|value| value.as_str())
                else {
                    return err_result(id, "write_file: missing string field `content`".into());
                };
                match write_workspace_file(&root, path, content).await {
                    Ok(()) => ok_result(id, format!("wrote {path} ({} bytes)", content.len())),
                    Err(error) => err_result(id, error),
                }
            })
        },
    )
}

async fn write_workspace_file(root: &Path, path: &str, content: &str) -> Result<(), String> {
    write_workspace_file_with_hook(root, path, content, |_| {}).await
}

pub(crate) async fn write_workspace_file_with_hook<F>(
    root: &Path,
    path: &str,
    content: &str,
    before_commit: F,
) -> Result<(), String>
where
    F: FnOnce(&Path),
{
    validate_input(path, content)?;

    // First resolution follows symlinks and yields the absolute location whose parents may need
    // creating. It no longer refuses a destination outside the workspace (owner-directed
    // 2026-08-05); what survives is the dangling-symlink refusal below, which is a data-loss
    // guard — a link we cannot resolve is one we must not silently replace — not containment.
    let initial_target = resolve_in_root(root, path)?;
    reject_dangling_target_symlink(root, path)?;
    let initial_parent = target_parent(&initial_target, path)?;
    tokio::fs::create_dir_all(initial_parent)
        .await
        .map_err(|error| format!("create parent directories for {path}: {error}"))?;

    // Re-resolve after directory creation: a parent that changed between the two operations must
    // not leave the transaction pointed at the pre-creation location.
    let target = resolve_in_root(root, path)?;
    reject_dangling_target_symlink(root, path)?;
    if tokio::fs::metadata(&target)
        .await
        .is_ok_and(|metadata| metadata.is_dir())
    {
        return Err(format!("write_file target is a directory: {path}"));
    }
    let expected = capture_target_snapshot(&target)
        .await
        .map_err(|error| format!("snapshot {path}: {error}"))?;
    let staged = StagedWrite::prepare(&target, content.as_bytes())
        .await
        .map_err(|error| format!("stage {path}: {error}"))?;
    before_commit(&target);
    match staged.commit_if_unchanged(&expected).await {
        Ok(()) => Ok(()),
        Err(GuardedCommitFailure::Changed) => Err(file_changed_json("write_file", path)),
        Err(GuardedCommitFailure::Inspect(error)) => {
            Err(format!("inspect {path} before commit: {error}"))
        }
        Err(GuardedCommitFailure::Commit(failure)) => {
            Err(format!("write {path}: {}", failure.error))
        }
    }
}

pub(crate) fn file_changed_json(tool: &str, path: &str) -> String {
    serde_json::json!({
        "error": format!("{tool}_failed"),
        "kind": "file_changed",
        "phase": "precommit",
        "path": path,
        "message": "file changed underneath you; re-read and retry",
    })
    .to_string()
}

fn validate_input(path: &str, content: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("write_file: `path` must not be empty".into());
    }
    if path.len()
        > iteron_tunables::param_integer("tools.write_file.max_path_bytes", MAX_PATH_BYTES)
    {
        return Err(format!(
            "write_file: path exceeds the {MAX_PATH_BYTES}-byte limit"
        ));
    }
    let max_write_bytes = MAX_WRITE_BYTES;
    if content.len() > max_write_bytes {
        return Err(format!(
            "write_file: content exceeds the {max_write_bytes}-byte limit"
        ));
    }
    if let Some(codepoint) = suspicious_unicode(path) {
        return Err(format!(
            "write_file refused: suspicious Unicode (U+{codepoint:04X}) in path"
        ));
    }
    if let Some(codepoint) = suspicious_unicode(content) {
        return Err(format!(
            "write_file refused: suspicious Unicode (U+{codepoint:04X}) in content"
        ));
    }
    Ok(())
}

fn target_parent<'a>(target: &'a Path, requested_path: &str) -> Result<&'a Path, String> {
    target
        .parent()
        .ok_or_else(|| format!("write_file target has no parent: {requested_path}"))
}

/// `resolve_in_root` follows every symlink whose destination currently canonicalizes. A dangling
/// final symlink cannot be canonicalized, so refuse it explicitly instead of silently replacing a
/// link whose intended destination we cannot see. This survives the move to host-wide paths: it
/// never was a containment rule, it is the guard against destroying a link by writing through it.
fn reject_dangling_target_symlink(root: &Path, requested_path: &str) -> Result<(), String> {
    let canonical_root = root
        .canonicalize()
        .map_err(|error| format!("workspace root: {error}"))?;
    let lexical_target = canonical_root.join(requested_path);
    let Ok(metadata) = std::fs::symlink_metadata(&lexical_target) else {
        return Ok(());
    };
    if metadata.file_type().is_symlink() && lexical_target.canonicalize().is_err() {
        return Err(format!(
            "write_file refused a dangling symlink target: {requested_path}"
        ));
    }
    Ok(())
}

pub(crate) async fn atomic_replace(target: &Path, content: &[u8]) -> io::Result<()> {
    StagedWrite::prepare(target, content)
        .await?
        .commit()
        .await
        .map_err(|failure| failure.error)
}

async fn allocate_temporary(parent: &Path) -> io::Result<(PathBuf, tokio::fs::File)> {
    let max_temp_attempts =
        iteron_tunables::param_usize("tools.write_file.max_temp_attempts", MAX_TEMP_ATTEMPTS);
    for _ in 0..max_temp_attempts {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(".core-write-{}-{id}.tmp", std::process::id()));
        match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .await
        {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("could not allocate a transaction file after {max_temp_attempts} attempts"),
    ))
}

#[cfg(test)]
#[path = "write_file_tests.rs"]
mod tests;
