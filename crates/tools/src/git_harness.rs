//! Shared confinement for read-only Git observations.
//!
//! All production Git subprocesses pass through this module. It resolves an absolute executable
//! outside the workspace, pins the repository layout, removes ambient configuration, neutralizes
//! repository-selected executable filters, disables optional writes and lazy fetches, and bounds
//! time plus both output streams.

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) const GIT_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const STDERR_LIMIT: usize = 16 * 1024;
const POST_KILL_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

#[cfg(windows)]
pub(crate) const NULL_DEVICE: &str = "NUL";
#[cfg(not(windows))]
pub(crate) const NULL_DEVICE: &str = "/dev/null";

#[derive(Debug)]
pub(crate) struct ResolvedGit {
    pub(crate) executable: PathBuf,
    pub(crate) safe_path: Option<OsString>,
}

#[derive(Debug)]
pub(crate) struct RepositoryLayout {
    pub(crate) work_tree: PathBuf,
    pub(crate) git_dir: PathBuf,
}

/// Establish the repository boundary without asking Git to discover it from attacker-controlled
/// configuration. Linked worktrees and submodules are refused because their `.git` file points at
/// authority outside the workspace.
pub(crate) fn resolve_repository_layout(workspace: &Path) -> Result<RepositoryLayout, String> {
    let work_tree = workspace
        .canonicalize()
        .map_err(|error| format!("workspace root: {error}"))?;
    if !work_tree.is_dir() {
        return Err("workspace root is not a directory".to_owned());
    }

    let dot_git = work_tree.join(".git");
    let metadata = std::fs::symlink_metadata(&dot_git).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            "workspace root is not an ordinary Git worktree (.git directory missing); nested and \
             bare repositories fail closed"
                .to_owned()
        } else {
            format!("could not inspect workspace .git entry: {error}")
        }
    })?;
    if metadata.file_type().is_symlink() {
        return Err(
            "workspace .git entry is a symlink; refusing an uncontained git-dir".to_owned(),
        );
    }
    if metadata.is_file() {
        return Err(
            "linked worktrees and submodule worktrees (.git files) are not supported by the \
             confined Git observation path"
                .to_owned(),
        );
    }
    if !metadata.is_dir() {
        return Err("workspace .git entry is not a directory".to_owned());
    }

    let git_dir = dot_git
        .canonicalize()
        .map_err(|error| format!("could not canonicalize workspace .git directory: {error}"))?;
    if !git_dir.starts_with(&work_tree) {
        return Err("workspace git-dir escapes the canonical workspace".to_owned());
    }
    match std::fs::symlink_metadata(git_dir.join("commondir")) {
        Ok(_) => {
            return Err(
                "alternate Git common-directory semantics are not supported by the confined \
                 Git observation path"
                    .to_owned(),
            );
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "could not inspect Git common-directory marker: {error}"
            ));
        }
    }

    Ok(RepositoryLayout { work_tree, git_dir })
}

/// Resolve Git through absolute PATH entries only and never admit a binary stored in the opened
/// workspace. The returned canonical path is what `Command` executes; PATH is not consulted at
/// spawn time.
pub(crate) fn resolve_git_executable(
    path: Option<&OsStr>,
    workspace: &Path,
) -> io::Result<ResolvedGit> {
    let workspace = workspace.canonicalize()?;
    let mut safe_directories = Vec::new();

    for directory in path.into_iter().flat_map(std::env::split_paths) {
        if !directory.is_absolute() {
            continue;
        }
        let Ok(directory) = directory.canonicalize() else {
            continue;
        };
        if directory.starts_with(&workspace) {
            continue;
        }
        safe_directories.push(directory.clone());

        #[cfg(windows)]
        let candidates = [directory.join("git.exe")];
        #[cfg(not(windows))]
        let candidates = [directory.join("git")];

        for candidate in candidates {
            let Ok(metadata) = std::fs::metadata(&candidate) else {
                continue;
            };
            if !metadata.is_file() || !is_executable(&metadata) {
                continue;
            }
            let Ok(executable) = candidate.canonicalize() else {
                continue;
            };
            if executable.starts_with(&workspace) {
                continue;
            }
            return Ok(ResolvedGit {
                executable,
                safe_path: std::env::join_paths(&safe_directories).ok(),
            });
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no trusted Git executable was found in an absolute PATH entry outside the workspace",
    ))
}

#[cfg(unix)]
fn is_executable(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &std::fs::Metadata) -> bool {
    true
}

/// Prepend command-scoped safety settings to a fixed Git observation. Executable filter keys are
/// discovered separately, then every entry point is shadowed at the highest config precedence.
pub(crate) fn hardened_args(
    filter_drivers: &[String],
    operation: impl IntoIterator<Item = OsString>,
) -> Vec<OsString> {
    let mut args: Vec<OsString> = [
        "--no-pager",
        "-c",
        &format!("core.hooksPath={NULL_DEVICE}"),
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        &format!("iteron.attributesFile={NULL_DEVICE}"),
        "-c",
        "diff.external=",
        "-c",
        "diff.submodule=short",
        "-c",
        "submodule.recurse=false",
        "-c",
        "fetch.recurseSubmodules=false",
        "-c",
        "credential.helper=",
        "-c",
        "gc.auto=0",
        "-c",
        "maintenance.auto=false",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    for driver in filter_drivers {
        for (entry, value) in [
            ("clean", ""),
            ("smudge", ""),
            ("process", ""),
            ("required", "false"),
        ] {
            args.push("-c".into());
            args.push(format!("{driver}.{entry}={value}").into());
        }
    }
    args.extend(operation);
    args
}

pub(crate) fn hardened_git_command(
    git: &ResolvedGit,
    repository: &RepositoryLayout,
    args: &[OsString],
) -> tokio::process::Command {
    let mut git_dir_arg = OsString::from("--git-dir=");
    git_dir_arg.push(&repository.git_dir);
    let mut work_tree_arg = OsString::from("--work-tree=");
    work_tree_arg.push(&repository.work_tree);

    let mut command = tokio::process::Command::new(&git.executable);
    command.env_clear();
    if let Some(path) = &git.safe_path {
        command.env("PATH", path);
    }
    command
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_SYSTEM",
            iteron_tunables::param_str("tools.git_harness.null_device", NULL_DEVICE),
        )
        .env(
            "GIT_CONFIG_GLOBAL",
            iteron_tunables::param_str("tools.git_harness.null_device", NULL_DEVICE),
        )
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env(
            "GIT_ASKPASS",
            iteron_tunables::param_str("tools.git_harness.null_device", NULL_DEVICE),
        )
        .env(
            "SSH_ASKPASS",
            iteron_tunables::param_str("tools.git_harness.null_device", NULL_DEVICE),
        )
        .env("GIT_PAGER", "cat")
        .env("PAGER", "cat")
        .env(
            "GIT_EDITOR",
            iteron_tunables::param_str("tools.git_harness.null_device", NULL_DEVICE),
        )
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_CEILING_DIRECTORIES", &repository.work_tree)
        .arg(git_dir_arg)
        .arg(work_tree_arg)
        .args(args)
        .current_dir(&repository.work_tree)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    command
}

#[derive(Debug)]
pub(crate) struct BoundedCapture {
    pub(crate) head: Vec<u8>,
    pub(crate) tail: Vec<u8>,
    pub(crate) limit: usize,
    pub(crate) total: usize,
}

impl BoundedCapture {
    fn new(limit: usize) -> Self {
        Self {
            head: Vec::with_capacity(limit / 2),
            tail: Vec::with_capacity(limit - limit / 2),
            limit,
            total: 0,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        self.total = self.total.saturating_add(bytes.len());
        let head_limit = self.limit / 2;
        let head_remaining = head_limit.saturating_sub(self.head.len());
        let head_bytes = head_remaining.min(bytes.len());
        self.head.extend_from_slice(&bytes[..head_bytes]);

        let bytes = &bytes[head_bytes..];
        let tail_limit = self.limit.saturating_sub(head_limit);
        if tail_limit == 0 || bytes.is_empty() {
            return;
        }
        if bytes.len() >= tail_limit {
            self.tail.clear();
            self.tail
                .extend_from_slice(&bytes[bytes.len().saturating_sub(tail_limit)..]);
            return;
        }
        let overflow = self
            .tail
            .len()
            .saturating_add(bytes.len())
            .saturating_sub(tail_limit);
        if overflow > 0 {
            self.tail.drain(..overflow);
        }
        self.tail.extend_from_slice(bytes);
    }

    pub(crate) fn truncated(&self) -> bool {
        self.total > self.limit
    }

    pub(crate) fn render(&self, label: &str) -> String {
        if !self.truncated() {
            return String::from_utf8_lossy(&self.retained_bytes()).into_owned();
        }
        format!(
            "{}\n[{label} truncated: retained {} of {} source bytes]\n{}",
            String::from_utf8_lossy(&self.head),
            self.limit,
            self.total,
            String::from_utf8_lossy(&self.tail)
        )
    }

    pub(crate) fn retained_bytes(&self) -> Vec<u8> {
        let mut bytes = self.head.clone();
        bytes.extend_from_slice(&self.tail);
        bytes
    }
}

async fn drain_bounded<R: AsyncRead + Unpin>(
    reader: &mut R,
    capture: &mut BoundedCapture,
) -> io::Result<()> {
    let mut chunk = [0_u8; 8 * 1024];
    loop {
        let read = reader.read(&mut chunk).await?;
        if read == 0 {
            return Ok(());
        }
        capture.push(&chunk[..read]);
    }
}

#[cfg(unix)]
fn kill_process_group(pid: Option<u32>) {
    if let Some(pid) = pid.and_then(|pid| i32::try_from(pid).ok()) {
        // SAFETY: every command is spawned with process_group(0), so `-pid` is confined to the
        // command's group. SIGKILL is used only for timeout/cancellation cleanup.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
}

#[cfg(not(unix))]
fn kill_process_group(_pid: Option<u32>) {}

struct ProcessGroupGuard {
    pid: Option<u32>,
    armed: bool,
}

impl ProcessGroupGuard {
    fn new(pid: Option<u32>) -> Self {
        Self { pid, armed: true }
    }

    fn kill(&self) {
        kill_process_group(self.pid);
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        if self.armed {
            self.kill();
        }
    }
}

#[derive(Debug)]
pub(crate) struct CapturedProcess {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: BoundedCapture,
    pub(crate) stderr: BoundedCapture,
}

pub(crate) async fn run_command_bounded(
    command: &mut tokio::process::Command,
    timeout: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
) -> io::Result<CapturedProcess> {
    let mut child = command.spawn()?;
    let mut group = ProcessGroupGuard::new(child.id());
    let Some(mut stdout) = child.stdout.take() else {
        let _ = child.start_kill();
        let _ = child.wait().await;
        return Err(io::Error::other("Git stdout pipe unavailable"));
    };
    let Some(mut stderr) = child.stderr.take() else {
        let _ = child.start_kill();
        let _ = child.wait().await;
        return Err(io::Error::other("Git stderr pipe unavailable"));
    };
    let mut stdout_capture = BoundedCapture::new(stdout_limit);
    let mut stderr_capture = BoundedCapture::new(stderr_limit);

    let completed = tokio::time::timeout(timeout, async {
        let (stdout_result, stderr_result, wait_result) = tokio::join!(
            drain_bounded(&mut stdout, &mut stdout_capture),
            drain_bounded(&mut stderr, &mut stderr_capture),
            child.wait(),
        );
        stdout_result?;
        stderr_result?;
        wait_result
    })
    .await;

    let status = match completed {
        Ok(result) => {
            let status = result?;
            group.disarm();
            status
        }
        Err(_) => {
            group.kill();
            let _ = child.start_kill();
            let _ = child.wait().await;
            group.disarm();
            let _ = tokio::time::timeout(
                iteron_tunables::param_duration(
                    "tools.git_harness.post_kill_drain_timeout",
                    POST_KILL_DRAIN_TIMEOUT,
                ),
                async {
                    let _ = tokio::join!(
                        drain_bounded(&mut stdout, &mut stdout_capture),
                        drain_bounded(&mut stderr, &mut stderr_capture),
                    );
                },
            )
            .await;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("Git command exceeded {} seconds", timeout.as_secs_f64()),
            ));
        }
    };

    Ok(CapturedProcess {
        status,
        stdout: stdout_capture,
        stderr: stderr_capture,
    })
}

/// Build a Git command string that runs a fixture script through a stable interpreter.
///
/// Fixtures write a script and then ask Git to run it. Naming the script directly makes Git
/// `execve` an inode this process only just closed, and on Linux `execve` returns `ETXTBSY`
/// while any process holds a write descriptor to the target — including a descriptor some
/// unrelated concurrent test binary inherited across a `fork`. Naming `/bin/sh` instead means
/// the executed image is a file nobody is writing, so the race cannot arise (#54, #55, #97).
///
/// Production never writes a program and then executes it, which is why this is test-only.
#[cfg(test)]
pub(crate) fn shell_script_command(path: &Path) -> OsString {
    let path = path
        .to_str()
        .expect("Git test fixture paths must be valid UTF-8");
    let quoted = path.replace('\'', "'\\''");
    format!("/bin/sh '{quoted}'").into()
}
