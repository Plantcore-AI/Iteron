//! Host-owned isolated writer worktrees and validating serialized merge mechanics.

use std::ffi::OsStr;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use core_verify::Oracle as _;
use sha2::{Digest as _, Sha256};

const MAX_GIT_MESSAGE_BYTES: usize = 16 * 1024;
const MAX_WRITER_PATCH_BYTES: u64 = 128 * 1024 * 1024;
const VERIFY_TIMEOUT_SECS: u64 = 600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MergeFailureKind {
    ParentNotRepository,
    ParentDirty,
    ParentAdvanced,
    WorktreeProvision,
    WorktreeState,
    PatchTooLarge,
    VerificationUnavailable,
    VerificationFailed,
    VerificationMutatedWorkspace,
    PatchConflict,
    ApplyFailed,
    CleanupFailed,
}

impl MergeFailureKind {
    const fn code(self) -> &'static str {
        match self {
            Self::ParentNotRepository => "parent_not_repository",
            Self::ParentDirty => "parent_dirty",
            Self::ParentAdvanced => "parent_advanced",
            Self::WorktreeProvision => "worktree_provision_failed",
            Self::WorktreeState => "worktree_state_invalid",
            Self::PatchTooLarge => "patch_too_large",
            Self::VerificationUnavailable => "verification_unavailable",
            Self::VerificationFailed => "verification_failed",
            Self::VerificationMutatedWorkspace => "verification_mutated_workspace",
            Self::PatchConflict => "patch_conflict",
            Self::ApplyFailed => "apply_failed",
            Self::CleanupFailed => "cleanup_failed",
        }
    }
}

#[derive(Debug)]
pub(super) struct MergeFailure {
    pub(super) kind: MergeFailureKind,
    detail: String,
}

impl MergeFailure {
    fn new(kind: MergeFailureKind, detail: impl AsRef<str>) -> Self {
        Self {
            kind,
            detail: bounded_detail(detail.as_ref()),
        }
    }

    pub(super) fn public_summary(&self) -> String {
        format!(
            "writer merge requires human resolution [{}]: {}",
            self.kind.code(),
            self.detail
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MergeReceipt {
    pub(super) patch_digest_sha256: Option<String>,
    pub(super) patch_bytes: u64,
}

/// An exact Git worktree registered under the parent repository. The path is derived below the
/// runtime-owned state directory and never accepted from the model.
pub(super) struct WriterWorktree {
    parent: PathBuf,
    path: PathBuf,
    patch_path: PathBuf,
    base_head: String,
    active: bool,
}

impl WriterWorktree {
    pub(super) async fn provision(
        parent: PathBuf,
        runtime_state: PathBuf,
        child_id: String,
    ) -> Result<Self, MergeFailure> {
        tokio::task::spawn_blocking(move || provision_sync(parent, runtime_state, &child_id))
            .await
            .map_err(|_| {
                MergeFailure::new(
                    MergeFailureKind::WorktreeProvision,
                    "worktree provisioning task did not complete",
                )
            })?
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// Stage the child's bounded registry edits and materialize a content-addressable patch before
    /// verification. Verification may create ignored build output, but may not alter tracked or
    /// non-ignored source after this point.
    pub(super) async fn prepare_patch(&self) -> Result<MergeReceipt, MergeFailure> {
        let path = self.path.clone();
        let patch_path = self.patch_path.clone();
        let base_head = self.base_head.clone();
        tokio::task::spawn_blocking(move || prepare_patch_sync(&path, &patch_path, &base_head))
            .await
            .map_err(|_| {
                MergeFailure::new(
                    MergeFailureKind::WorktreeState,
                    "patch preparation task did not complete",
                )
            })?
    }

    pub(super) async fn verify(
        &self,
        command: Option<&str>,
        sensitive_env_names: &[String],
    ) -> Result<(), MergeFailure> {
        let Some(command) = command.filter(|command| !command.trim().is_empty()) else {
            return Err(MergeFailure::new(
                MergeFailureKind::VerificationUnavailable,
                "an isolated writer cannot merge without an operator-admitted verification command",
            ));
        };
        let oracle = core_verify::TestOracle::new(
            core_sandbox::platform_sandbox(),
            self.path.clone(),
            command.to_owned(),
        )
        .with_timeout_secs(VERIFY_TIMEOUT_SECS)
        .with_sensitive_env_names(sensitive_env_names.to_vec());
        let verdict = oracle.evaluate().await;
        if !verdict.passed() {
            return Err(MergeFailure::new(
                MergeFailureKind::VerificationFailed,
                format!("{}: {}", verdict.outcome.label(), verdict.detail),
            ));
        }
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || ensure_verification_did_not_mutate(&path))
            .await
            .map_err(|_| {
                MergeFailure::new(
                    MergeFailureKind::VerificationMutatedWorkspace,
                    "verification mutation audit did not complete",
                )
            })?
    }

    /// Apply the prepared patch only after revalidating the parent HEAD and cleanliness while the
    /// caller holds the session-wide writer mutex.
    pub(super) async fn merge(&mut self) -> Result<(), MergeFailure> {
        let parent = self.parent.clone();
        let patch_path = self.patch_path.clone();
        let base_head = self.base_head.clone();
        tokio::task::spawn_blocking(move || merge_sync(&parent, &patch_path, &base_head))
            .await
            .map_err(|_| {
                MergeFailure::new(
                    MergeFailureKind::ApplyFailed,
                    "serialized merge task did not complete",
                )
            })??;
        self.cleanup().await
    }

    pub(super) async fn discard(&mut self) -> Result<(), MergeFailure> {
        self.cleanup().await
    }

    async fn cleanup(&mut self) -> Result<(), MergeFailure> {
        if !self.active {
            return Ok(());
        }
        let parent = self.parent.clone();
        let path = self.path.clone();
        let patch_path = self.patch_path.clone();
        tokio::task::spawn_blocking(move || cleanup_sync(&parent, &path, &patch_path))
            .await
            .map_err(|_| {
                MergeFailure::new(
                    MergeFailureKind::CleanupFailed,
                    "worktree cleanup task did not complete",
                )
            })??;
        self.active = false;
        Ok(())
    }
}

impl Drop for WriterWorktree {
    fn drop(&mut self) {
        if self.active {
            let _ = cleanup_sync(&self.parent, &self.path, &self.patch_path);
            self.active = false;
        }
    }
}

fn provision_sync(
    parent: PathBuf,
    runtime_state: PathBuf,
    child_id: &str,
) -> Result<WriterWorktree, MergeFailure> {
    let canonical_parent = repository_root(&parent)?;
    require_clean(&canonical_parent)?;
    let base_head = head(&canonical_parent)?;

    let owner = runtime_state.join("writer-worktrees");
    std::fs::create_dir_all(&owner).map_err(|error| {
        MergeFailure::new(MergeFailureKind::WorktreeProvision, error.to_string())
    })?;
    reject_symlink(&owner)?;
    set_private_directory(&owner)?;

    let mut digest = Sha256::new();
    digest.update(canonical_parent.as_os_str().as_encoded_bytes());
    digest.update([0]);
    digest.update(child_id.as_bytes());
    let identity = hex::encode(digest.finalize());
    let path = owner.join(&identity[..32]);
    if path.exists() {
        return Err(MergeFailure::new(
            MergeFailureKind::WorktreeProvision,
            "the exact writer worktree already exists and requires orphan reconciliation",
        ));
    }

    let output = git_capture(
        &canonical_parent,
        [
            OsStr::new("worktree"),
            OsStr::new("add"),
            OsStr::new("--detach"),
            path.as_os_str(),
            OsStr::new(&base_head),
        ],
    )?;
    if !output.status.success() {
        return Err(MergeFailure::new(
            MergeFailureKind::WorktreeProvision,
            output.message(),
        ));
    }
    set_private_directory(&path)?;
    Ok(WriterWorktree {
        parent: canonical_parent,
        patch_path: owner.join(format!("{}.patch", &identity[..32])),
        path,
        base_head,
        active: true,
    })
}

fn prepare_patch_sync(
    worktree: &Path,
    patch_path: &Path,
    base_head: &str,
) -> Result<MergeReceipt, MergeFailure> {
    require_head(worktree, base_head, MergeFailureKind::WorktreeState)?;
    require_git_success(
        worktree,
        [OsStr::new("add"), OsStr::new("-A"), OsStr::new("--")],
    )?;
    let output_arg = format!("--output={}", patch_path.display());
    require_git_success(
        worktree,
        [
            OsStr::new("diff"),
            OsStr::new("--cached"),
            OsStr::new("--binary"),
            OsStr::new("--full-index"),
            OsStr::new(&output_arg),
            OsStr::new(base_head),
            OsStr::new("--"),
        ],
    )?;
    let metadata = std::fs::metadata(patch_path)
        .map_err(|error| MergeFailure::new(MergeFailureKind::WorktreeState, error.to_string()))?;
    if metadata.len() > MAX_WRITER_PATCH_BYTES {
        return Err(MergeFailure::new(
            MergeFailureKind::PatchTooLarge,
            format!(
                "writer patch is {} bytes; maximum is {MAX_WRITER_PATCH_BYTES}",
                metadata.len()
            ),
        ));
    }
    let digest = if metadata.len() == 0 {
        None
    } else {
        let bytes = std::fs::read(patch_path).map_err(|error| {
            MergeFailure::new(MergeFailureKind::WorktreeState, error.to_string())
        })?;
        Some(format!("sha256:{:x}", Sha256::digest(bytes)))
    };
    Ok(MergeReceipt {
        patch_digest_sha256: digest,
        patch_bytes: metadata.len(),
    })
}

fn ensure_verification_did_not_mutate(worktree: &Path) -> Result<(), MergeFailure> {
    if !git_quiet(worktree, ["diff", "--quiet", "--"])? || has_untracked(worktree)? {
        return Err(MergeFailure::new(
            MergeFailureKind::VerificationMutatedWorkspace,
            "verification changed tracked or non-ignored files after the writer patch was sealed",
        ));
    }
    Ok(())
}

fn merge_sync(parent: &Path, patch_path: &Path, base_head: &str) -> Result<(), MergeFailure> {
    require_head(parent, base_head, MergeFailureKind::ParentAdvanced)?;
    require_clean(parent)?;
    let check = git_capture(
        parent,
        [
            OsStr::new("apply"),
            OsStr::new("--check"),
            OsStr::new("--binary"),
            OsStr::new("--whitespace=nowarn"),
            patch_path.as_os_str(),
        ],
    )?;
    if !check.status.success() {
        return Err(MergeFailure::new(
            MergeFailureKind::PatchConflict,
            check.message(),
        ));
    }
    let apply = git_capture(
        parent,
        [
            OsStr::new("apply"),
            OsStr::new("--binary"),
            OsStr::new("--whitespace=nowarn"),
            patch_path.as_os_str(),
        ],
    )?;
    if !apply.status.success() {
        return Err(MergeFailure::new(
            MergeFailureKind::ApplyFailed,
            apply.message(),
        ));
    }
    Ok(())
}

fn cleanup_sync(parent: &Path, path: &Path, patch_path: &Path) -> Result<(), MergeFailure> {
    let output = git_capture(
        parent,
        [
            OsStr::new("worktree"),
            OsStr::new("remove"),
            OsStr::new("--force"),
            path.as_os_str(),
        ],
    )?;
    if output.status.success() {
        match std::fs::remove_file(patch_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(MergeFailure::new(
                MergeFailureKind::CleanupFailed,
                error.to_string(),
            )),
        }
    } else {
        Err(MergeFailure::new(
            MergeFailureKind::CleanupFailed,
            output.message(),
        ))
    }
}

fn repository_root(path: &Path) -> Result<PathBuf, MergeFailure> {
    let output = git_capture(
        path,
        [OsStr::new("rev-parse"), OsStr::new("--show-toplevel")],
    )?;
    if !output.status.success() {
        return Err(MergeFailure::new(
            MergeFailureKind::ParentNotRepository,
            output.message(),
        ));
    }
    let reported = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    let canonical = reported.canonicalize().map_err(|error| {
        MergeFailure::new(MergeFailureKind::ParentNotRepository, error.to_string())
    })?;
    let requested = path.canonicalize().map_err(|error| {
        MergeFailure::new(MergeFailureKind::ParentNotRepository, error.to_string())
    })?;
    if canonical != requested {
        return Err(MergeFailure::new(
            MergeFailureKind::ParentNotRepository,
            "workflow workspace must be the exact Git repository root",
        ));
    }
    Ok(canonical)
}

fn head(path: &Path) -> Result<String, MergeFailure> {
    let output = git_capture(
        path,
        [
            OsStr::new("rev-parse"),
            OsStr::new("--verify"),
            OsStr::new("HEAD"),
        ],
    )?;
    if !output.status.success() {
        return Err(MergeFailure::new(
            MergeFailureKind::WorktreeState,
            output.message(),
        ));
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if value.len() != 40 && value.len() != 64 {
        return Err(MergeFailure::new(
            MergeFailureKind::WorktreeState,
            "Git HEAD has an invalid object identity",
        ));
    }
    Ok(value)
}

fn require_head(path: &Path, expected: &str, kind: MergeFailureKind) -> Result<(), MergeFailure> {
    let actual = head(path)?;
    if actual == expected {
        Ok(())
    } else {
        Err(MergeFailure::new(
            kind,
            "repository HEAD changed after writer isolation",
        ))
    }
}

fn require_clean(path: &Path) -> Result<(), MergeFailure> {
    if !git_quiet(path, ["diff", "--quiet", "--"])?
        || !git_quiet(path, ["diff", "--cached", "--quiet", "--"])?
        || has_untracked(path)?
    {
        return Err(MergeFailure::new(
            MergeFailureKind::ParentDirty,
            "parent workspace must be clean before an isolated writer starts or merges",
        ));
    }
    Ok(())
}

fn has_untracked(path: &Path) -> Result<bool, MergeFailure> {
    let output = git_capture(
        path,
        [
            OsStr::new("ls-files"),
            OsStr::new("--others"),
            OsStr::new("--exclude-standard"),
        ],
    )?;
    if !output.status.success() {
        return Err(MergeFailure::new(
            MergeFailureKind::WorktreeState,
            output.message(),
        ));
    }
    Ok(!output.stdout.is_empty())
}

fn git_quiet<const N: usize>(path: &Path, args: [&str; N]) -> Result<bool, MergeFailure> {
    let status = git_command(path)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| MergeFailure::new(MergeFailureKind::WorktreeState, error.to_string()))?;
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(MergeFailure::new(
            MergeFailureKind::WorktreeState,
            "Git cleanliness check failed",
        )),
    }
}

fn require_git_success<I, S>(path: &Path, args: I) -> Result<(), MergeFailure>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = git_capture(path, args)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(MergeFailure::new(
            MergeFailureKind::WorktreeState,
            output.message(),
        ))
    }
}

struct GitOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl GitOutput {
    fn message(&self) -> String {
        let bytes = if self.stderr.is_empty() {
            &self.stdout
        } else {
            &self.stderr
        };
        bounded_detail(&String::from_utf8_lossy(bytes))
    }
}

fn git_capture<I, S>(path: &Path, args: I) -> Result<GitOutput, MergeFailure>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut child = git_command(path)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| MergeFailure::new(MergeFailureKind::WorktreeState, error.to_string()))?;
    let stdout = child.stdout.take().ok_or_else(|| {
        MergeFailure::new(MergeFailureKind::WorktreeState, "Git stdout was not piped")
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        MergeFailure::new(MergeFailureKind::WorktreeState, "Git stderr was not piped")
    })?;
    let out = std::thread::spawn(move || read_bounded(stdout));
    let err = std::thread::spawn(move || read_bounded(stderr));
    let status = child
        .wait()
        .map_err(|error| MergeFailure::new(MergeFailureKind::WorktreeState, error.to_string()))?;
    let stdout = out.join().unwrap_or_default();
    let stderr = err.join().unwrap_or_default();
    Ok(GitOutput {
        status,
        stdout,
        stderr,
    })
}

fn git_command(path: &Path) -> Command {
    let mut command = Command::new("git");
    command
        .arg("-c")
        .arg("core.hooksPath=/dev/null")
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("-c")
        .arg("credential.helper=")
        .arg("-C")
        .arg(path)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_PAGER", "cat")
        .stdin(Stdio::null());
    command
}

fn read_bounded(mut reader: impl Read) -> Vec<u8> {
    let mut bytes = Vec::new();
    let _ = reader
        .by_ref()
        .take((MAX_GIT_MESSAGE_BYTES + 1) as u64)
        .read_to_end(&mut bytes);
    bytes.truncate(MAX_GIT_MESSAGE_BYTES);
    bytes
}

fn bounded_detail(value: &str) -> String {
    let one_line = value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    let mut bytes = one_line.into_bytes();
    bytes.truncate(MAX_GIT_MESSAGE_BYTES);
    while std::str::from_utf8(&bytes).is_err() {
        bytes.pop();
    }
    let value = String::from_utf8(bytes).unwrap_or_default();
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "operation failed without a diagnostic".into()
    } else {
        trimmed.into()
    }
}

fn reject_symlink(path: &Path) -> Result<(), MergeFailure> {
    if std::fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(true)
    {
        return Err(MergeFailure::new(
            MergeFailureKind::WorktreeProvision,
            "writer worktree owner directory may not be a symlink",
        ));
    }
    Ok(())
}

fn set_private_directory(path: &Path) -> Result<(), MergeFailure> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(
            |error| MergeFailure::new(MergeFailureKind::WorktreeProvision, error.to_string()),
        )?;
    }
    Ok(())
}
