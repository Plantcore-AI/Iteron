//! Workspace checkpoint and rewind on an internal git shadow ref (SESS-2, R5 design §2.7).
//!
//! Conversation rewind is `fork` (session.rs); this module is the *file* layer. It snapshots the
//! working tree so a `/rewind` can restore files, keyed to a record `Seq` (the snapshot ledger is
//! recorded as `EventKind::Checkpoint`). The snapshot is a git object on a private ref
//! `refs/core/<run>/<seq>`, taken with git PLUMBING only — `write-tree`/`commit-tree`/
//! `update-ref`, and a private temp index so the operator's own index is never touched.
//!
//! It is external hook/filter-command-free by construction (ADR-007 §4): every Git invocation
//! redirects hooks to the platform null device, and every content-transforming command runs with a
//! fresh Core-owned Git directory rather than repository/global config. Thus `.gitattributes`
//! cannot activate a repository-configured clean/smudge/process command. Commands are allowlisted,
//! deadline-bounded, and output-bounded. External effects (push/publish/DB writes) are NOT
//! rewindable — a tree restore cannot undo them (ADR-008 §5); only the working tree is restored here.

use crate::RecordError;
use core_protocol::{RunId, Seq};
use std::collections::HashSet;
use std::ffi::OsStr;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// A workspace checkpoint: the git tree object capturing the working tree at record `Seq` `at`.
/// `tree_ref` is a git object id; `created_at` is snapshot-time metadata (operational, not part of
/// the deterministic replay chain).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Snapshot {
    pub run: RunId,
    pub at: Seq,
    pub tree_ref: String,
    pub created_at: u64,
}

const GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const GIT_OUTPUT_LIMIT: usize = 8 * 1024 * 1024;
const GIT_EXCLUDE_LIMIT: u64 = 1024 * 1024;
const MAX_TEMP_ATTEMPTS: u64 = 32;
const INTERNAL_EXCLUDE_PREFIX: &str = ":(top,literal,exclude)";
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct CapturedStream {
    bytes: Vec<u8>,
    overflowed: bool,
}

#[derive(Debug)]
struct CapturedProcess {
    status: ExitStatus,
    stdout: CapturedStream,
    stderr: CapturedStream,
}

fn drain_bounded(mut stream: impl Read, limit: usize) -> io::Result<CapturedStream> {
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    let mut overflowed = false;
    let mut chunk = [0u8; 8192];
    loop {
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        let remaining = limit.saturating_sub(bytes.len());
        bytes.extend_from_slice(&chunk[..count.min(remaining)]);
        overflowed |= count > remaining;
    }
    Ok(CapturedStream { bytes, overflowed })
}

/// Execute a child with a wall-clock deadline while continuously draining both pipes. Output past
/// `limit` is discarded and turns the command into an error, so neither a broken Git installation
/// nor an unexpectedly large repository can grow memory without bound.
fn run_command_bounded(
    command: &mut Command,
    timeout: Duration,
    limit: usize,
) -> io::Result<CapturedProcess> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io::Error::other("child stdout pipe unavailable"));
    };
    let Some(stderr) = child.stderr.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io::Error::other("child stderr pipe unavailable"));
    };
    let stdout_thread = std::thread::spawn(move || drain_bounded(stdout, limit));
    let stderr_thread = std::thread::spawn(move || drain_bounded(stderr, limit));
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                return Err(error);
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            // No repository-controlled child process is permitted by the isolated Git config.
            // Joining is therefore bounded by the killed Git process closing its two pipes.
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("git command exceeded {} seconds", timeout.as_secs()),
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let stdout = stdout_thread
        .join()
        .map_err(|_| io::Error::other("git stdout reader panicked"))??;
    let stderr = stderr_thread
        .join()
        .map_err(|_| io::Error::other("git stderr reader panicked"))??;
    if stdout.overflowed || stderr.overflowed {
        return Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            format!("git output exceeded the {limit}-byte capture limit"),
        ));
    }
    Ok(CapturedProcess {
        status,
        stdout,
        stderr,
    })
}

#[cfg(windows)]
const NULL_DEVICE: &str = "NUL";
#[cfg(not(windows))]
const NULL_DEVICE: &str = "/dev/null";

/// Resolve Git only through absolute PATH entries; a repository-local `git` reached through `.` is
/// executable content and therefore outside the checkpoint trust boundary.
fn resolve_git_executable(path: Option<&OsStr>) -> Option<PathBuf> {
    let path = path?;
    for directory in std::env::split_paths(path) {
        // A relative PATH entry such as `.` would let the opened repository replace the Git binary.
        if !directory.is_absolute() {
            continue;
        }
        #[cfg(windows)]
        let candidates = [directory.join("git.exe")];
        #[cfg(not(windows))]
        let candidates = [directory.join("git")];
        for candidate in candidates {
            if std::fs::metadata(&candidate).is_ok_and(|metadata| metadata.is_file())
                && let Ok(canonical) = candidate.canonicalize()
            {
                return Some(canonical);
            }
        }
    }
    None
}

/// Start Git with ambient configuration and command-injection variables removed. Local repository
/// config is still visible for the small allowlisted control-plane commands below; every setting
/// which could launch a hook, fsmonitor, signer, pager, editor, or maintenance child is overridden.
fn hardened_git_command() -> Command {
    let path = std::env::var_os("PATH");
    let executable =
        resolve_git_executable(path.as_deref()).unwrap_or_else(|| PathBuf::from(NULL_DEVICE));
    let mut command = Command::new(executable);
    command.env_clear();
    if let Some(path) = path {
        command.env("PATH", path);
    }
    command
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", NULL_DEVICE)
        .env("GIT_CONFIG_GLOBAL", NULL_DEVICE)
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", NULL_DEVICE)
        .env("SSH_ASKPASS", NULL_DEVICE)
        .env("GIT_PAGER", "cat")
        .env("PAGER", "cat")
        .env("GIT_EDITOR", NULL_DEVICE)
        .arg("-c")
        .arg(format!("core.hooksPath={NULL_DEVICE}"))
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            "user.name=core",
            "-c",
            "user.email=core@localhost",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "tag.gpgsign=false",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=false",
        ]);
    command
}

fn finish_git(command: &mut Command, operation: &str) -> Result<String, RecordError> {
    let captured = run_command_bounded(command, GIT_COMMAND_TIMEOUT, GIT_OUTPUT_LIMIT)?;
    if !captured.status.success() {
        let stderr = String::from_utf8_lossy(&captured.stderr.bytes);
        return Err(io::Error::other(format!("git {operation}: {}", stderr.trim())).into());
    }
    String::from_utf8(captured.stdout.bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("git {operation} returned a non-UTF-8 path"),
        )
        .into()
    })
}

fn valid_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Repository-configured Git is restricted to commands which do not run content filters. This
/// allowlist is intentional: adding `add`, `checkout`, `diff`, or another content-transforming
/// command here is a security review, not a convenience change.
fn run_repo_git(ws: &Path, args: &[&str]) -> Result<String, RecordError> {
    let allowed = matches!(
        args,
        ["rev-parse", "--is-inside-work-tree"]
            | ["rev-parse", "--git-path", "objects"]
            | ["rev-parse", "--git-path", "info/exclude"]
            | ["rev-parse", "--show-object-format"]
            | ["ls-files", "-z", "-o", "-c", "--exclude-standard"]
    ) || matches!(args, ["update-ref", reference, object]
        if reference.starts_with("refs/core/") && valid_object_id(object));
    if !allowed {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Git subcommand is not allowed against repository-controlled config",
        )
        .into());
    }
    let mut command = hardened_git_command();
    command.current_dir(ws).args(args);
    finish_git(&mut command, args.first().copied().unwrap_or("unknown"))
}

struct IsolatedGit {
    root: PathBuf,
    git_dir: PathBuf,
    index: PathBuf,
    object_dir: PathBuf,
    exclude_file: Option<PathBuf>,
    workspace: PathBuf,
}

impl IsolatedGit {
    fn create(run: &RunId, at: Seq, workspace: &Path) -> Result<Self, RecordError> {
        let object_dir = run_repo_git(workspace, &["rev-parse", "--git-path", "objects"])?;
        let object_dir = PathBuf::from(object_dir.trim());
        let object_dir = if object_dir.is_absolute() {
            object_dir
        } else {
            workspace.join(object_dir)
        };
        let object_dir = object_dir.canonicalize()?;
        if !object_dir.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Git object directory is not a directory",
            )
            .into());
        }
        let object_format = run_repo_git(workspace, &["rev-parse", "--show-object-format"])?;
        let object_format = object_format.trim();
        if !matches!(object_format, "sha1" | "sha256") {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported Git object format {object_format:?}"),
            )
            .into());
        }
        let exclude_file = run_repo_git(workspace, &["rev-parse", "--git-path", "info/exclude"])?;
        let exclude_file = PathBuf::from(exclude_file.trim());
        let exclude_file = if exclude_file.is_absolute() {
            exclude_file
        } else {
            workspace.join(exclude_file)
        };
        let exclude_file = match std::fs::symlink_metadata(&exclude_file) {
            Ok(metadata)
                if metadata.file_type().is_file() && metadata.len() <= GIT_EXCLUDE_LIMIT =>
            {
                Some(exclude_file)
            }
            Ok(metadata) if metadata.len() > GIT_EXCLUDE_LIMIT => {
                return Err(io::Error::new(
                    io::ErrorKind::FileTooLarge,
                    "Git info/exclude exceeds the 1 MiB checkpoint limit",
                )
                .into());
            }
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Git info/exclude must be a regular file, not a symlink or special file",
                )
                .into());
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };

        let root = create_private_temp_dir(run, at)?;
        let git_dir = root.join("git");
        let template = root.join("empty-template");
        if let Err(error) = std::fs::create_dir(&template) {
            let _ = std::fs::remove_dir_all(&root);
            return Err(error.into());
        }
        let mut init = hardened_git_command();
        init.current_dir(&root)
            .arg("init")
            .arg("--bare")
            .arg("--quiet")
            .arg(format!("--object-format={object_format}"))
            .arg(format!("--template={}", template.display()))
            .arg(&git_dir);
        if let Err(error) = finish_git(&mut init, "init isolated checkpoint repository") {
            let _ = std::fs::remove_dir_all(&root);
            return Err(error);
        }
        Ok(Self {
            index: root.join("index"),
            root,
            git_dir,
            object_dir,
            exclude_file,
            workspace: workspace.to_path_buf(),
        })
    }

    fn run(&self, args: &[&str]) -> Result<String, RecordError> {
        let allowed = matches!(
            args,
            ["add", "-A", "--", "."]
                | ["write-tree"]
                | ["checkout-index", "-a", "-f"]
                | ["ls-files", "-z"]
        ) || matches!(args, ["add", "-A", "--", ".", exclusion]
            if valid_internal_exclusion(exclusion))
            || matches!(args, ["commit-tree", object, "-m", _] if valid_object_id(object))
            || matches!(args, ["read-tree", object] if valid_object_id(object));
        if !allowed {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Git subcommand is not allowed in the isolated checkpoint repository",
            )
            .into());
        }
        let mut command = hardened_git_command();
        command
            .current_dir(&self.workspace)
            .env("GIT_DIR", &self.git_dir)
            .env("GIT_WORK_TREE", &self.workspace)
            .env("GIT_INDEX_FILE", &self.index)
            .env("GIT_OBJECT_DIRECTORY", &self.object_dir);
        if let Some(exclude_file) = &self.exclude_file {
            command
                .arg("-c")
                .arg(format!("core.excludesFile={}", exclude_file.display()));
        }
        command.args(args);
        finish_git(&mut command, args.first().copied().unwrap_or("unknown"))
    }

    fn stage_all(&self, excluded_runtime_dir: Option<&str>) -> Result<(), RecordError> {
        match excluded_runtime_dir {
            Some(relative) => {
                let exclusion = format!("{INTERNAL_EXCLUDE_PREFIX}{relative}");
                self.run(&["add", "-A", "--", ".", &exclusion])?;
            }
            None => {
                self.run(&["add", "-A", "--", "."])?;
            }
        }
        Ok(())
    }
}

impl Drop for IsolatedGit {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Restrict a run id to characters that are safe in a git ref path / temp filename.
fn sanitize(s: &str) -> String {
    let mut sanitized: String = s
        .chars()
        .take(80)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.is_empty() || matches!(sanitized.as_str(), "." | "..") {
        sanitized = "_".into();
    }
    sanitized
}

fn shadow_ref(run: &RunId, at: Seq) -> String {
    format!("refs/core/{}/{}", sanitize(&run.0), at.0)
}

fn valid_internal_exclusion(exclusion: &str) -> bool {
    let Some(relative) = exclusion.strip_prefix(INTERNAL_EXCLUDE_PREFIX) else {
        return false;
    };
    !relative.is_empty()
        && Path::new(relative)
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

/// Resolve an existing runtime-state directory to a Git-root-relative, UTF-8 path. State outside
/// the workspace cannot enter the snapshot and needs no exclusion. A state directory equal to the
/// workspace would make a meaningful checkpoint impossible and is rejected instead of silently
/// producing an empty tree.
fn runtime_state_relative(
    workspace: &Path,
    runtime_state_dir: &Path,
) -> Result<Option<String>, RecordError> {
    let workspace = workspace.canonicalize()?;
    let runtime_state_dir = runtime_state_dir.canonicalize()?;
    let Ok(relative) = runtime_state_dir.strip_prefix(&workspace) else {
        return Ok(None);
    };
    if relative.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "checkpoint runtime-state directory cannot be the workspace root",
        )
        .into());
    }
    let mut parts = Vec::new();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "checkpoint runtime-state path is not workspace-relative",
            )
            .into());
        };
        let component = component.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "checkpoint runtime-state path is not valid UTF-8",
            )
        })?;
        parts.push(component);
    }
    Ok(Some(parts.join("/")))
}

fn create_private_temp_dir(run: &RunId, at: Seq) -> io::Result<PathBuf> {
    for _ in 0..MAX_TEMP_ATTEMPTS {
        let nonce = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "core-ckpt-{}-{}-{}-{nanos:x}-{nonce:x}",
            sanitize(&run.0),
            at.0,
            std::process::id()
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Err(error) =
                        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                    {
                        let _ = std::fs::remove_dir(&path);
                        return Err(error);
                    }
                }
                return Ok(path);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a private checkpoint directory",
    ))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn nul_path_set(raw: &str) -> Result<HashSet<String>, RecordError> {
    if raw.is_empty() {
        return Ok(HashSet::new());
    }
    if !raw.ends_with('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "git path list was not NUL-terminated",
        )
        .into());
    }
    let mut paths = HashSet::new();
    for path in raw.split_terminator('\0') {
        if path.is_empty()
            || !Path::new(path)
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Git returned an unsafe workspace path {path:?}"),
            )
            .into());
        }
        paths.insert(path.to_string());
    }
    Ok(paths)
}

/// Resolve a Git-relative file without following a pre-existing symlink in any parent component.
/// This narrows the deletion blast radius; a concurrent rename can still race this check, so
/// checkpoint/rewind must not run beside an untrusted writer.
fn checked_workspace_path(workspace: &Path, relative: &str) -> Result<PathBuf, RecordError> {
    let relative = Path::new(relative);
    let mut parent = workspace.to_path_buf();
    if let Some(components) = relative.parent() {
        for component in components.components() {
            let std::path::Component::Normal(component) = component else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsafe workspace path component",
                )
                .into());
            };
            parent.push(component);
            match std::fs::symlink_metadata(&parent) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("refusing to delete through symlink {}", parent.display()),
                    )
                    .into());
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => break,
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(workspace.join(relative))
}

/// Snapshot the working tree at record `Seq` `at` onto the private shadow ref `refs/core/<run>/
/// <seq>` (SESS-2). Requires `workspace` to be a git work tree. Uses only plumbing against a
/// private temp index, so the operator's index/HEAD are untouched and no hook runs (ADR-007 §4).
/// `.gitignore`d files are excluded (standard git snapshot semantics), matching CC's files-only,
/// separate-from-your-git checkpoint.
pub fn checkpoint_supported(workspace: &Path) -> bool {
    run_repo_git(workspace, &["rev-parse", "--is-inside-work-tree"])
        .is_ok_and(|inside| inside.trim() == "true")
}

pub fn checkpoint(run: &RunId, at: Seq, workspace: &Path) -> Result<Snapshot, RecordError> {
    checkpoint_inner(run, at, workspace, None)
}

/// Snapshot a workspace while unconditionally excluding Core's mutable rollout/session-state
/// directory when it lives under that workspace. This exclusion is independent of repository
/// `.gitignore` and `info/exclude`: rewinding a workspace checkpoint must never overwrite the
/// append-only audit record that authorizes the rewind.
pub fn checkpoint_excluding_runtime_state(
    run: &RunId,
    at: Seq,
    workspace: &Path,
    runtime_state_dir: &Path,
) -> Result<Snapshot, RecordError> {
    checkpoint_inner(run, at, workspace, Some(runtime_state_dir))
}

fn checkpoint_inner(
    run: &RunId,
    at: Seq,
    workspace: &Path,
    runtime_state_dir: Option<&Path>,
) -> Result<Snapshot, RecordError> {
    if !checkpoint_supported(workspace) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} is not a git work tree; checkpoint requires one",
                workspace.display()
            ),
        )
        .into());
    }

    // `git add` reads `.gitattributes`, and repository config may bind an attribute's clean filter
    // to an arbitrary process. Run all content-transforming commands against a fresh Git dir whose
    // only config was created by Core. It shares the real object database, but never reads the real
    // `.git/config`; an attribute naming an unavailable external driver therefore remains inert.
    let excluded_runtime_dir = runtime_state_dir
        .map(|path| runtime_state_relative(workspace, path))
        .transpose()?
        .flatten();
    let isolated = IsolatedGit::create(run, at, workspace)?;
    isolated.stage_all(excluded_runtime_dir.as_deref())?;
    let tree = isolated.run(&["write-tree"])?;
    let tree = tree.trim();
    if !valid_object_id(tree) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "git write-tree returned an invalid object id",
        )
        .into());
    }
    let msg = format!("core checkpoint {}@{}", sanitize(&run.0), at.0);
    let commit = isolated.run(&["commit-tree", tree, "-m", &msg])?;
    let commit = commit.trim();
    if !valid_object_id(commit) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "git commit-tree returned an invalid object id",
        )
        .into());
    }
    run_repo_git(workspace, &["update-ref", &shadow_ref(run, at), commit])?;

    Ok(Snapshot {
        run: run.clone(),
        at,
        tree_ref: tree.to_string(),
        created_at: now_secs(),
    })
}

/// Restore the working tree to `snap` (SESS-2). Materializes the snapshot tree via a private temp
/// index (plumbing: `read-tree` + `checkout-index`), then removes files that exist now but were not
/// in the snapshot, so the rewind is a faithful restore rather than an overlay. `.gitignore`d files
/// are left untouched. External effects are NOT undone by this (ADR-008 §5). Hook-free (ADR-007 §4).
pub fn rewind_workspace(snap: &Snapshot, workspace: &Path) -> Result<(), RecordError> {
    if !valid_object_id(&snap.tree_ref) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "checkpoint tree_ref is not a full Git object id",
        )
        .into());
    }
    let isolated = IsolatedGit::create(&snap.run, snap.at, workspace)?;
    isolated.run(&["read-tree", &snap.tree_ref])?;
    // Inventory and validate the complete deletion plan before checkout starts mutating files. A
    // path/output-limit failure therefore leaves the workspace untouched.
    let snap_files = nul_path_set(&isolated.run(&["ls-files", "-z"])?)?;
    let current = run_repo_git(
        workspace,
        &["ls-files", "-z", "-o", "-c", "--exclude-standard"],
    )?;
    let mut removals: Vec<String> = nul_path_set(&current)?
        .into_iter()
        .filter(|path| !snap_files.contains(path))
        .collect();
    removals.sort_unstable();
    for path in &removals {
        checked_workspace_path(workspace, path)?;
    }

    // checkout-index can invoke smudge/process filters. Keep it in the same config-isolated Git
    // context as add, so repository-controlled filter commands and hooks are unavailable.
    isolated.run(&["checkout-index", "-a", "-f"])?;
    for relative in removals {
        // Re-check after checkout to narrow symlink-swap races across the mutation boundary.
        let path = checked_workspace_path(workspace, &relative)?;
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_git(ws: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .current_dir(ws)
            .args(args)
            .output()
            .expect("test git starts");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("test git output is UTF-8")
            .trim()
            .to_string()
    }

    fn git_available() -> bool {
        std::process::Command::new("git")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn tmp_repo(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "core-ckpt-repo-{tag}-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn checkpoint_then_rewind_restores_the_working_tree() {
        if !git_available() {
            eprintln!("skipping: git not available");
            return;
        }
        let ws = tmp_repo("roundtrip");
        test_git(&ws, &["init", "-q"]);
        assert!(checkpoint_supported(&ws));
        std::fs::write(ws.join("a.txt"), "one").unwrap();
        test_git(&ws, &["add", "a.txt"]);
        // commit-tree-free initial commit is not needed; checkpoint snapshots the working tree.

        let run = RunId("ck1".into());
        let snap = checkpoint(&run, Seq(1), &ws).unwrap();
        assert!(!snap.tree_ref.is_empty(), "snapshot has a tree object id");

        // Mutate: change a tracked file and add a new untracked file.
        std::fs::write(ws.join("a.txt"), "two").unwrap();
        std::fs::write(ws.join("c.txt"), "new").unwrap();

        rewind_workspace(&snap, &ws).unwrap();
        assert_eq!(std::fs::read_to_string(ws.join("a.txt")).unwrap(), "one");
        assert!(
            !ws.join("c.txt").exists(),
            "a post-snapshot file must be removed by rewind"
        );
        std::fs::remove_dir_all(&ws).ok();
    }

    #[test]
    fn checkpoint_errors_on_a_non_repo() {
        if !git_available() {
            eprintln!("skipping: git not available");
            return;
        }
        let ws = tmp_repo("norepo");
        assert!(!checkpoint_supported(&ws));
        let err = checkpoint(&RunId("ck2".into()), Seq(0), &ws).unwrap_err();
        assert!(matches!(err, RecordError::Io(_)));
        std::fs::remove_dir_all(&ws).ok();
    }

    #[test]
    fn checkpoint_preserves_repository_info_exclude_semantics() {
        if !git_available() {
            eprintln!("skipping: git not available");
            return;
        }
        let ws = tmp_repo("info-exclude");
        test_git(&ws, &["init", "-q"]);
        std::fs::write(ws.join("kept.txt"), "kept").unwrap();
        std::fs::write(ws.join("secret.txt"), "not checkpointed").unwrap();
        std::fs::write(ws.join(".git/info/exclude"), "secret.txt\n").unwrap();

        let snapshot = checkpoint(&RunId("exclude".into()), Seq(1), &ws).unwrap();
        let listing = test_git(&ws, &["ls-tree", "-r", "--name-only", &snapshot.tree_ref]);
        assert!(listing.lines().any(|path| path == "kept.txt"));
        assert!(!listing.lines().any(|path| path == "secret.txt"));
        std::fs::remove_dir_all(&ws).ok();
    }

    #[test]
    fn checkpoint_unconditionally_excludes_in_workspace_runtime_state() {
        if !git_available() {
            eprintln!("skipping: git not available");
            return;
        }
        let ws = tmp_repo("runtime-state-exclude");
        test_git(&ws, &["init", "-q"]);
        std::fs::write(ws.join("kept.txt"), "kept").unwrap();
        std::fs::create_dir_all(ws.join(".core/runs")).unwrap();
        std::fs::write(ws.join(".core/config.json"), "{}\n").unwrap();
        std::fs::write(ws.join(".core/runs/live.jsonl"), "authoritative\n").unwrap();
        std::fs::write(ws.join(".core/runs/sessions.index"), "mutable\n").unwrap();

        let snapshot = checkpoint_excluding_runtime_state(
            &RunId("runtime-state".into()),
            Seq(2),
            &ws,
            &ws.join(".core/runs"),
        )
        .unwrap();
        let listing = test_git(&ws, &["ls-tree", "-r", "--name-only", &snapshot.tree_ref]);
        assert!(listing.lines().any(|path| path == "kept.txt"));
        assert!(listing.lines().any(|path| path == ".core/config.json"));
        assert!(
            !listing.lines().any(|path| path.starts_with(".core/runs/")),
            "runtime journals and projections must never enter a workspace checkpoint"
        );
        std::fs::remove_dir_all(&ws).ok();
    }

    #[test]
    fn repository_config_cannot_execute_clean_smudge_or_reference_hooks() {
        if !git_available() {
            eprintln!("skipping: git not available");
            return;
        }
        let ws = tmp_repo("hostile-filter");
        test_git(&ws, &["init", "-q"]);
        std::fs::write(ws.join(".gitattributes"), "*.txt filter=owned\n").unwrap();
        std::fs::write(ws.join("a.txt"), "original\n").unwrap();
        test_git(
            &ws,
            &[
                "config",
                "filter.owned.clean",
                "sh -c 'printf clean > clean-ran; cat'",
            ],
        );
        test_git(
            &ws,
            &[
                "config",
                "filter.owned.smudge",
                "sh -c 'printf smudge > smudge-ran; cat'",
            ],
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let hooks = ws.join("hostile-hooks");
            std::fs::create_dir(&hooks).unwrap();
            let hook = hooks.join("reference-transaction");
            std::fs::write(
                &hook,
                "#!/bin/sh\nprintf hook > hook-ran\ncat >/dev/null\nexit 0\n",
            )
            .unwrap();
            std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
            test_git(&ws, &["config", "core.hooksPath", "hostile-hooks"]);
        }

        let snap = checkpoint(&RunId("hostile".into()), Seq(4), &ws).unwrap();
        assert!(!ws.join("clean-ran").exists());
        assert!(!ws.join("hook-ran").exists());

        std::fs::write(ws.join("a.txt"), "changed\n").unwrap();
        rewind_workspace(&snap, &ws).unwrap();
        assert_eq!(
            std::fs::read_to_string(ws.join("a.txt")).unwrap(),
            "original\n"
        );
        assert!(!ws.join("smudge-ran").exists());
        assert!(!ws.join("hook-ran").exists());
        std::fs::remove_dir_all(&ws).ok();
    }

    #[test]
    fn repository_config_scope_rejects_content_transforming_commands() {
        let ws = tmp_repo("allowlist");
        let error = run_repo_git(&ws, &["add", "-A", "--", "."]).unwrap_err();
        assert!(
            matches!(error, RecordError::Io(error) if error.kind() == io::ErrorKind::PermissionDenied)
        );
        std::fs::remove_dir_all(&ws).ok();
    }

    #[test]
    fn rewind_rejects_an_option_shaped_or_abbreviated_tree_ref() {
        let ws = tmp_repo("bad-tree");
        for tree_ref in ["--reset", "deadbeef"] {
            let snapshot = Snapshot {
                run: RunId("bad-tree".into()),
                at: Seq(1),
                tree_ref: tree_ref.into(),
                created_at: 0,
            };
            let error = rewind_workspace(&snapshot, &ws).unwrap_err();
            assert!(
                matches!(error, RecordError::Io(error) if error.kind() == io::ErrorKind::InvalidInput)
            );
        }
        std::fs::remove_dir_all(&ws).ok();
    }

    #[test]
    fn bounded_stream_discards_excess_without_growing_the_capture() {
        let captured = drain_bounded(io::Cursor::new(vec![b'x'; 4096]), 128).unwrap();
        assert_eq!(captured.bytes.len(), 128);
        assert!(captured.overflowed);
    }

    #[test]
    fn git_resolver_rejects_relative_path_entries() {
        let path = std::env::join_paths([PathBuf::from("."), PathBuf::from("relative/bin")])
            .expect("relative PATH joins");
        assert!(resolve_git_executable(Some(&path)).is_none());
    }

    #[test]
    fn bounded_command_rejects_output_past_the_capture_limit() {
        if !git_available() {
            eprintln!("skipping: git not available");
            return;
        }
        let mut command = hardened_git_command();
        command.args(["help", "-a"]);
        let error = run_command_bounded(&mut command, Duration::from_secs(5), 64).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::FileTooLarge);
    }

    #[cfg(unix)]
    #[test]
    fn nul_delimited_path_inventory_preserves_newlines_in_filenames() {
        if !git_available() {
            eprintln!("skipping: git not available");
            return;
        }
        let ws = tmp_repo("newline-path");
        test_git(&ws, &["init", "-q"]);
        let path = ws.join("line\nbreak.txt");
        std::fs::write(&path, "before").unwrap();
        let snapshot = checkpoint(&RunId("newline".into()), Seq(1), &ws).unwrap();
        std::fs::write(&path, "after").unwrap();
        rewind_workspace(&snapshot, &ws).unwrap();
        assert_eq!(std::fs::read_to_string(path).unwrap(), "before");
        std::fs::remove_dir_all(&ws).ok();
    }

    #[cfg(unix)]
    #[test]
    fn bounded_command_kills_a_child_at_the_deadline() {
        let mut command = Command::new("sleep");
        command.arg("2");
        let started = Instant::now();
        let error = run_command_bounded(&mut command, Duration::from_millis(20), 128).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "timeout must not wait for normal child completion"
        );
    }
}
