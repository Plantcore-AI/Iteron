//! `git_diff` — a bounded, read-only view of the working tree's uncommitted changes.
//!
//! Starting a process is an observable effect even when the Git operation itself is read-only, so
//! this tool is deliberately `Effecting`/`ReadOnly`: it remains available to read-only subagents,
//! but the kernel must defer it until after the provider turn and route it through the effect WAL.
//! Git is resolved to an absolute executable outside the workspace before `current_dir` changes,
//! the repository is required to have a contained `.git` directory, every invocation pins both
//! `--git-dir` and `--work-tree`, ambient Git configuration is removed, repository executable
//! extension points are disabled, dirty submodules are not descended into, and the child is
//! supervised with bounded output, a deadline, and process-group teardown. Linked worktrees and
//! submodule worktrees use an external git-dir through a `.git` file and currently fail closed.

use crate::{Registry, ToolError, boxfut, err_result, ok_result, resolve_in_root};
use core_protocol::{Capability, Purity, ToolSpec};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};

const GIT_TIMEOUT: Duration = Duration::from_secs(30);
const POST_KILL_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
const STDOUT_LIMIT: usize = 40_000;
const STDERR_LIMIT: usize = 16_000;
const FILTER_CONFIG_LIMIT: usize = 64 * 1024;
const MAX_FILTER_DRIVERS: usize = 128;
const MAX_FILTER_DRIVER_BYTES: usize = 4 * 1024;
const FILTER_CONFIG_PATTERN: &str = r"^filter\..*\.(clean|smudge|process|required)$";

#[cfg(windows)]
const NULL_DEVICE: &str = "NUL";
#[cfg(not(windows))]
const NULL_DEVICE: &str = "/dev/null";

#[derive(Debug)]
struct ResolvedGit {
    executable: PathBuf,
    safe_path: Option<OsString>,
}

#[derive(Debug)]
struct RepositoryLayout {
    work_tree: PathBuf,
    git_dir: PathBuf,
}

/// Establish the repository boundary without asking Git to discover it from attacker-controlled
/// configuration. An ordinary worktree has a real `.git` directory under the canonical workspace.
/// A `.git` file can legitimately describe a linked worktree or submodule, but its git-dir lives
/// outside that worktree; until Core has an explicit trust contract for that shared repository,
/// following it would silently expand the read boundary and therefore fails closed.
fn resolve_repository_layout(workspace: &Path) -> Result<RepositoryLayout, String> {
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
             confined git_diff path"
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
                 git_diff path"
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
/// workspace. The returned canonical path is what `Command` executes; PATH is no longer consulted
/// at spawn time. Keeping operator-supplied absolute toolchain roots matches checkpoint's trust
/// boundary while rejecting `.` and an absolute `<repo>/bin` entry.
fn resolve_git_executable(path: Option<&OsStr>, workspace: &Path) -> io::Result<ResolvedGit> {
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

fn git_diff_args(stat: bool, path: Option<&Path>, filter_drivers: &[String]) -> Vec<OsString> {
    let mut args: Vec<OsString> = [
        "--no-pager",
        "-c",
        &format!("core.hooksPath={NULL_DEVICE}"),
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "diff.external=",
        "-c",
        "diff.submodule=short",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    // `--no-textconv` does not disable clean/process filters selected by `.gitattributes`.
    // Enumerate every effective local filter driver first and override every executable entry at
    // command scope (which has higher precedence than repository/worktree config). This keeps the
    // static untrusted-repository case genuinely ReadOnly rather than merely labelling it so.
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
    args.extend(
        [
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            // Inspecting a dirty submodule runs another Git against submodule-controlled config;
            // that nested status can execute the submodule's own clean/process filter. Keep the
            // safe superproject boundary explicit and render gitlinks only in short form.
            "--ignore-submodules=dirty",
            "--submodule=short",
        ]
        .into_iter()
        .map(OsString::from),
    );
    if stat {
        args.push("--stat".into());
    }
    if let Some(path) = path {
        args.push("--".into());
        args.push(path.as_os_str().to_owned());
    }
    args
}

fn hardened_git_command(
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
        .env("GIT_CONFIG_SYSTEM", NULL_DEVICE)
        .env("GIT_CONFIG_GLOBAL", NULL_DEVICE)
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", NULL_DEVICE)
        .env("SSH_ASKPASS", NULL_DEVICE)
        .env("GIT_PAGER", "cat")
        .env("PAGER", "cat")
        .env("GIT_EDITOR", NULL_DEVICE)
        // Suppress optional index refresh/lock writes for a read-only observation.
        .env("GIT_OPTIONAL_LOCKS", "0")
        // A partial clone may otherwise fetch a missing object during an apparently read-only
        // diff, invoking repository-selected remotes/helpers and crossing the workspace/network
        // boundary. Missing promisor objects must make this observation fail instead.
        .env("GIT_NO_LAZY_FETCH", "1")
        // These command-line bindings outrank a malicious local `core.worktree` and prevent Git
        // repository discovery from walking above the workspace. Keep them on every invocation,
        // including the defensive config inspection.
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
struct BoundedCapture {
    head: Vec<u8>,
    tail: Vec<u8>,
    limit: usize,
    total: usize,
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

    fn truncated(&self) -> bool {
        self.total > self.limit
    }

    fn render(&self, label: &str) -> String {
        if !self.truncated() {
            let mut bytes = self.head.clone();
            bytes.extend_from_slice(&self.tail);
            return String::from_utf8_lossy(&bytes).into_owned();
        }
        format!(
            "{}\n[{label} truncated: retained {} of {} source bytes]\n{}",
            String::from_utf8_lossy(&self.head),
            self.limit,
            self.total,
            String::from_utf8_lossy(&self.tail)
        )
    }

    fn retained_bytes(&self) -> Vec<u8> {
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
        // SAFETY: every command is spawned with process_group(0), so `-pid` addresses only the
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
struct CapturedProcess {
    status: ExitStatus,
    stdout: BoundedCapture,
    stderr: BoundedCapture,
}

async fn run_command_bounded(
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
            let _ = tokio::time::timeout(POST_KILL_DRAIN_TIMEOUT, async {
                let _ = tokio::join!(
                    drain_bounded(&mut stdout, &mut stdout_capture),
                    drain_bounded(&mut stderr, &mut stderr_capture),
                );
            })
            .await;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("Git diff exceeded {} seconds", timeout.as_secs_f64()),
            ));
        }
    };

    Ok(CapturedProcess {
        status,
        stdout: stdout_capture,
        stderr: stderr_capture,
    })
}

/// Parse `git config --null --name-only` output into `filter.<driver>` prefixes. The driver count
/// and aggregate key size are capped so a repository cannot turn the defensive command-scope
/// overrides into an `ARG_MAX`/Windows command-line explosion.
fn parse_filter_drivers(bytes: &[u8]) -> Result<Vec<String>, String> {
    let mut drivers = BTreeSet::new();
    let mut driver_bytes = 0_usize;

    for raw_key in bytes.split(|byte| *byte == 0).filter(|key| !key.is_empty()) {
        let key = std::str::from_utf8(raw_key)
            .map_err(|_| "Git filter config contained a non-UTF-8 key".to_owned())?;
        if key.chars().any(char::is_control) || key.contains('=') {
            return Err("Git filter config contained an unsafe key".to_owned());
        }
        let normalized = key.to_ascii_lowercase();
        let Some((normalized_driver, entry)) = normalized.rsplit_once('.') else {
            return Err(format!("unexpected Git filter config key: {key}"));
        };
        if !normalized_driver.starts_with("filter.")
            || normalized_driver == "filter."
            || !matches!(entry, "clean" | "smudge" | "process" | "required")
        {
            return Err(format!("unexpected Git filter config key: {key}"));
        }
        // ASCII case folding preserves byte length, so this boundary is also valid in `key`.
        let driver = key[..key.len() - entry.len() - 1].to_owned();
        if drivers.insert(driver.clone()) {
            driver_bytes = driver_bytes.saturating_add(driver.len());
            if drivers.len() > MAX_FILTER_DRIVERS || driver_bytes > MAX_FILTER_DRIVER_BYTES {
                return Err(format!(
                    "Git filter config exceeds the defensive limit ({MAX_FILTER_DRIVERS} drivers, \
                     {MAX_FILTER_DRIVER_BYTES} key bytes)"
                ));
            }
        }
    }

    Ok(drivers.into_iter().collect())
}

/// Read the effective repository/worktree filter keys without evaluating file content. Global and
/// system config are already removed by `hardened_git_command`; `--includes` is explicit so an
/// executable filter hidden behind a local include cannot evade the command-scope overrides.
async fn discover_filter_drivers(
    git: &ResolvedGit,
    repository: &RepositoryLayout,
) -> Result<Vec<String>, String> {
    let args: Vec<OsString> = [
        "--no-pager",
        "config",
        "--null",
        "--name-only",
        "--includes",
        "--get-regexp",
        FILTER_CONFIG_PATTERN,
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let mut command = hardened_git_command(git, repository, &args);
    let captured =
        run_command_bounded(&mut command, GIT_TIMEOUT, FILTER_CONFIG_LIMIT, STDERR_LIMIT)
            .await
            .map_err(|error| format!("could not inspect Git filter config: {error}"))?;

    // `git config --get-regexp` returns 1 when there were no matching keys.
    if captured.status.code() == Some(1) && captured.stdout.total == 0 {
        return Ok(Vec::new());
    }
    if !captured.status.success() {
        return Err(format!(
            "could not inspect Git filter config (exit {}): {}",
            captured.status.code().unwrap_or(-1),
            captured.stderr.render("Git config stderr").trim()
        ));
    }
    if captured.stdout.truncated() {
        return Err(format!(
            "Git filter config exceeded the {FILTER_CONFIG_LIMIT}-byte inspection limit"
        ));
    }
    parse_filter_drivers(&captured.stdout.retained_bytes())
}

async fn run_git_diff_inner(
    root: &Path,
    stat: bool,
    requested_path: Option<&str>,
) -> Result<String, String> {
    let root = root
        .canonicalize()
        .map_err(|error| format!("workspace root: {error}"))?;
    let relative_path = requested_path
        .map(|path| {
            resolve_in_root(&root, path).and_then(|resolved| {
                resolved
                    .strip_prefix(&root)
                    .map(|relative| {
                        if relative.as_os_str().is_empty() {
                            PathBuf::from(".")
                        } else {
                            relative.to_path_buf()
                        }
                    })
                    .map_err(|_| format!("path escapes the workspace: {path}"))
            })
        })
        .transpose()?;
    let repository = resolve_repository_layout(&root)?;
    let git = resolve_git_executable(std::env::var_os("PATH").as_deref(), &root)
        .map_err(|error| format!("could not resolve trusted Git: {error}"))?;
    let filter_drivers = discover_filter_drivers(&git, &repository).await?;
    let args = git_diff_args(stat, relative_path.as_deref(), &filter_drivers);
    let mut command = hardened_git_command(&git, &repository, &args);
    let captured = run_command_bounded(&mut command, GIT_TIMEOUT, STDOUT_LIMIT, STDERR_LIMIT)
        .await
        .map_err(|error| format!("could not run bounded Git diff: {error}"))?;

    if !captured.status.success() {
        let stderr = captured.stderr.render("Git stderr");
        return Err(format!(
            "Git diff failed (exit {}): {}",
            captured.status.code().unwrap_or(-1),
            stderr.trim()
        ));
    }
    let output = captured.stdout.render("Git diff output");
    Ok(if output.trim().is_empty() {
        "(no uncommitted changes)".into()
    } else {
        output
    })
}

pub(crate) async fn run_git_diff(
    root: &Path,
    stat: bool,
    requested_path: Option<&str>,
) -> Result<String, String> {
    // The filter-config inspection and diff share one end-to-end deadline. Dropping either active
    // command invokes `ProcessGroupGuard`, so outer timeout/caller cancellation tears down the
    // whole Unix process group rather than leaking a repository-triggered descendant.
    tokio::time::timeout(GIT_TIMEOUT, run_git_diff_inner(root, stat, requested_path))
        .await
        .map_err(|_| format!("Git diff exceeded {} seconds", GIT_TIMEOUT.as_secs()))?
}

pub(crate) fn register(r: &mut Registry) -> Result<(), ToolError> {
    r.push_tool(
        ToolSpec {
            name: "git_diff".into(),
            description: "Show uncommitted changes in the working tree (git diff). Optional \
                          `stat` for a summary, or `path` to limit to one file/dir. Runs a fixed, \
                          bounded, hook/filter-disabled Git command after the model turn; dirty \
                          submodule worktrees are intentionally not descended into."
                .into(),
            input_schema: serde_json::json!({
                "type":"object",
                "properties":{
                    "stat":{"type":"boolean","description":"summary (--stat) instead of full diff"},
                    "path":{"type":"string","description":"limit to this path (relative to repo root)"}
                }
            }),
            purity: Purity::Effecting,
            capability: Capability::ReadOnly,
        },
        |call, root| {
            boxfut::box_it(async move {
                let id = call.id.clone();
                let stat = call
                    .input
                    .get("stat")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false);
                let path = call
                    .input
                    .get("path")
                    .and_then(|value| value.as_str())
                    .map(str::to_owned);
                match run_git_diff(&root, stat, path.as_deref()).await {
                    Ok(output) => ok_result(id, output),
                    Err(error) => err_result(id, error),
                }
            })
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_protocol::ToolUse;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "core-git-diff-{label}-{}-{nonce:x}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    fn script(path: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[cfg(unix)]
    async fn setup_git(git: &ResolvedGit, workspace: &Path, args: &[&OsStr]) {
        let args: Vec<OsString> = args.iter().map(|arg| (*arg).to_owned()).collect();
        // Fixtures need to run `git init` before a RepositoryLayout exists and deliberately need
        // to activate dangerous repository settings to prove the production boundary. This raw
        // command builder is therefore test-only; production Git always uses
        // `hardened_git_command` with an already-validated layout.
        let mut command = tokio::process::Command::new(&git.executable);
        command.env_clear();
        if let Some(path) = &git.safe_path {
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
            .env("GIT_OPTIONAL_LOCKS", "0")
            .args(args)
            .current_dir(workspace)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);
        let captured = run_command_bounded(&mut command, Duration::from_secs(5), 4096, 4096)
            .await
            .unwrap();
        assert!(
            captured.status.success(),
            "setup Git failed: {}",
            captured.stderr.render("setup stderr")
        );
    }

    #[test]
    fn git_diff_is_effecting_readonly_and_cannot_early_dispatch() {
        let dir = std::env::temp_dir();
        let registry = Registry::read_only(&dir).unwrap();
        assert_eq!(registry.purity_of("git_diff"), Some(Purity::Effecting));
        assert_eq!(
            registry.capability_of("git_diff"),
            Some(Capability::ReadOnly)
        );
    }

    #[test]
    fn fixed_arguments_disable_extension_points_and_guard_paths() {
        let args = git_diff_args(
            true,
            Some(Path::new("-looks-like-an-option")),
            &["filter.Evil".to_owned()],
        );
        let args: Vec<String> = args
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        assert!(
            args.windows(2)
                .any(|pair| pair == ["-c", "core.fsmonitor=false"])
        );
        assert!(args.windows(2).any(|pair| pair == ["-c", "diff.external="]));
        assert!(
            args.windows(2)
                .any(|pair| pair == ["-c", "filter.Evil.clean="])
        );
        assert!(
            args.windows(2)
                .any(|pair| pair == ["-c", "filter.Evil.process="])
        );
        assert!(
            args.windows(2)
                .any(|pair| pair == ["-c", "filter.Evil.required=false"])
        );
        assert!(args.iter().any(|argument| argument == "--no-ext-diff"));
        assert!(args.iter().any(|argument| argument == "--no-textconv"));
        assert!(args.iter().any(|argument| argument == "--no-color"));
        assert!(
            args.iter()
                .any(|argument| argument == "--ignore-submodules=dirty")
        );
        assert!(args.iter().any(|argument| argument == "--submodule=short"));
        assert!(args.iter().any(|argument| argument == "--stat"));
        let separator = args.iter().position(|argument| argument == "--").unwrap();
        assert_eq!(args[separator + 1], "-looks-like-an-option");
    }

    #[test]
    fn filter_driver_parser_is_nul_safe_deduplicated_and_bounded() {
        let parsed =
            parse_filter_drivers(b"filter.alpha.clean\0filter.alpha.process\0filter.Case.smudge\0")
                .unwrap();
        assert_eq!(parsed, ["filter.Case", "filter.alpha"]);
        assert!(parse_filter_drivers(b"filter.bad.clean\nkey\0").is_err());

        let too_many = (0..=MAX_FILTER_DRIVERS)
            .map(|index| format!("filter.f{index}.clean\0"))
            .collect::<String>();
        assert!(parse_filter_drivers(too_many.as_bytes()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn resolver_ignores_relative_and_workspace_git_entries() {
        let temp = TestDir::new("resolver");
        let workspace = temp.0.join("workspace");
        let trusted = temp.0.join("trusted-bin");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&trusted).unwrap();
        script(&workspace.join("git"), "exit 99");
        script(&trusted.join("git"), "exit 0");
        let path =
            std::env::join_paths([Path::new("."), workspace.as_path(), trusted.as_path()]).unwrap();

        let resolved = resolve_git_executable(Some(&path), &workspace).unwrap();
        assert_eq!(
            resolved.executable,
            trusted.join("git").canonicalize().unwrap()
        );
        assert!(resolved.executable.is_absolute());
        assert!(
            !resolved
                .executable
                .starts_with(workspace.canonicalize().unwrap())
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runner_bounds_both_output_streams() {
        let temp = TestDir::new("bounded");
        let executable = temp.0.join("flood");
        script(
            &executable,
            "i=0; while [ \"$i\" -lt 5000 ]; do printf 0123456789; printf abcdefghij >&2; i=$((i + 1)); done",
        );
        let mut command = tokio::process::Command::new(&executable);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);

        let captured = run_command_bounded(&mut command, Duration::from_secs(5), 1024, 512)
            .await
            .unwrap();
        assert!(captured.status.success());
        assert!(captured.stdout.truncated());
        assert!(captured.stderr.truncated());
        assert_eq!(
            captured.stdout.head.len() + captured.stdout.tail.len(),
            1024
        );
        assert_eq!(captured.stderr.head.len() + captured.stderr.tail.len(), 512);
        assert!(
            captured
                .stdout
                .render("stdout")
                .contains("stdout truncated")
        );
        assert!(
            captured
                .stderr
                .render("stderr")
                .contains("stderr truncated")
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_kills_the_process_group_and_waits() {
        let temp = TestDir::new("timeout");
        let executable = temp.0.join("linger");
        let marker = temp.0.join("escaped-descendant");
        script(
            &executable,
            "(/bin/sleep 1; printf escaped > \"$1\") & wait",
        );
        let mut command = tokio::process::Command::new(&executable);
        command
            .arg(&marker)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);

        let error = run_command_bounded(&mut command, Duration::from_millis(50), 1024, 1024)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(
            !marker.exists(),
            "a timed-out descendant survived its process group"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn repository_clean_filter_is_neutralized_before_diff() {
        let temp = TestDir::new("clean-filter");
        let workspace = temp.0.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let git = resolve_git_executable(std::env::var_os("PATH").as_deref(), &workspace).unwrap();
        let filter = temp.0.join("filter");
        let marker = temp.0.join("filter-ran");
        script(
            &filter,
            &format!("printf hit > \"{}\"\n/bin/cat", marker.display()),
        );

        setup_git(
            &git,
            &workspace,
            &[OsStr::new("init"), OsStr::new("--quiet")],
        )
        .await;
        setup_git(
            &git,
            &workspace,
            &[
                OsStr::new("config"),
                OsStr::new("filter.evil.clean"),
                filter.as_os_str(),
            ],
        )
        .await;
        std::fs::write(workspace.join(".gitattributes"), "* filter=evil\n").unwrap();
        std::fs::write(workspace.join("tracked"), "before\n").unwrap();
        setup_git(
            &git,
            &workspace,
            &[
                OsStr::new("add"),
                OsStr::new("--"),
                OsStr::new(".gitattributes"),
                OsStr::new("tracked"),
            ],
        )
        .await;
        assert!(
            marker.exists(),
            "test setup did not activate the clean filter"
        );
        std::fs::remove_file(&marker).unwrap();
        std::fs::write(workspace.join("tracked"), "after\n").unwrap();

        let output = run_git_diff(&workspace, false, None).await.unwrap();
        assert!(output.contains("tracked"));
        assert!(
            !marker.exists(),
            "git_diff executed a repository-configured clean filter"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn malicious_core_worktree_cannot_leak_an_outside_file() {
        let temp = TestDir::new("core-worktree-escape");
        let workspace = temp.0.join("workspace");
        let outside = temp.0.join("outside");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let git = resolve_git_executable(std::env::var_os("PATH").as_deref(), &workspace).unwrap();

        setup_git(
            &git,
            &workspace,
            &[OsStr::new("init"), OsStr::new("--quiet")],
        )
        .await;
        std::fs::write(workspace.join("tracked"), "safe workspace contents\n").unwrap();
        setup_git(
            &git,
            &workspace,
            &[OsStr::new("add"), OsStr::new("--"), OsStr::new("tracked")],
        )
        .await;

        let outside_marker = "CORE_OUTSIDE_WORKTREE_SECRET_MARKER";
        std::fs::write(outside.join("tracked"), format!("{outside_marker}\n")).unwrap();
        setup_git(
            &git,
            &workspace,
            &[
                OsStr::new("config"),
                OsStr::new("core.worktree"),
                outside.as_os_str(),
            ],
        )
        .await;

        // Prove the fixture reaches the vulnerable behavior: an unpinned Git invocation honors
        // local core.worktree and emits contents read from outside the workspace.
        let raw_args = [
            OsStr::new("--no-pager"),
            OsStr::new("diff"),
            OsStr::new("--no-ext-diff"),
            OsStr::new("--no-textconv"),
            OsStr::new("--no-color"),
        ];
        let raw_args: Vec<OsString> = raw_args.iter().map(|arg| (*arg).to_owned()).collect();
        let mut raw_command = tokio::process::Command::new(&git.executable);
        raw_command
            .env_clear()
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", NULL_DEVICE)
            .args(raw_args)
            .current_dir(&workspace)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);
        let vulnerable = run_command_bounded(
            &mut raw_command,
            Duration::from_secs(5),
            STDOUT_LIMIT,
            STDERR_LIMIT,
        )
        .await
        .unwrap();
        assert!(vulnerable.status.success());
        assert!(
            vulnerable
                .stdout
                .render("raw Git output")
                .contains(outside_marker),
            "test setup did not reproduce the unpinned core.worktree disclosure"
        );

        let output = run_git_diff(&workspace, false, None).await.unwrap();
        assert_eq!(output, "(no uncommitted changes)");
        assert!(
            !output.contains(outside_marker),
            "confined git_diff disclosed contents from core.worktree outside the workspace"
        );
    }

    #[test]
    fn linked_worktree_git_file_fails_closed() {
        let temp = TestDir::new("linked-worktree");
        let workspace = temp.0.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(
            workspace.join(".git"),
            "gitdir: /outside/shared/.git/worktrees/w1\n",
        )
        .unwrap();

        let error = resolve_repository_layout(&workspace).unwrap_err();
        assert!(error.contains("linked worktrees"));
    }

    #[test]
    fn alternate_git_common_directory_fails_closed() {
        let temp = TestDir::new("common-dir");
        let workspace = temp.0.join("workspace");
        std::fs::create_dir_all(workspace.join(".git")).unwrap();
        std::fs::write(workspace.join(".git/commondir"), "/outside/shared/.git\n").unwrap();

        let error = resolve_repository_layout(&workspace).unwrap_err();
        assert!(error.contains("common-directory"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hardened_command_disables_partial_clone_lazy_fetch() {
        let temp = TestDir::new("no-lazy-fetch");
        let workspace = temp.0.join("workspace");
        std::fs::create_dir_all(workspace.join(".git")).unwrap();
        let executable = temp.0.join("git-env-probe");
        script(&executable, "printf '%s' \"$GIT_NO_LAZY_FETCH\"");
        let git = ResolvedGit {
            executable,
            safe_path: None,
        };
        let repository = resolve_repository_layout(&workspace).unwrap();

        let mut command = hardened_git_command(&git, &repository, &[]);
        let captured = run_command_bounded(&mut command, Duration::from_secs(5), 128, 128)
            .await
            .unwrap();
        assert!(captured.status.success());
        assert_eq!(captured.stdout.render("probe stdout"), "1");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dirty_submodule_filter_is_not_descended_into() {
        let temp = TestDir::new("submodule-filter");
        let source = temp.0.join("source");
        let workspace = temp.0.join("workspace");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&workspace).unwrap();
        let git = resolve_git_executable(std::env::var_os("PATH").as_deref(), &workspace).unwrap();

        setup_git(&git, &source, &[OsStr::new("init"), OsStr::new("--quiet")]).await;
        for (key, value) in [("user.name", "core-test"), ("user.email", "core@test")] {
            setup_git(
                &git,
                &source,
                &[OsStr::new("config"), OsStr::new(key), OsStr::new(value)],
            )
            .await;
        }
        std::fs::write(source.join(".gitattributes"), "* filter=evil\n").unwrap();
        std::fs::write(source.join("tracked"), "before\n").unwrap();
        setup_git(
            &git,
            &source,
            &[OsStr::new("add"), OsStr::new("--"), OsStr::new(".")],
        )
        .await;
        setup_git(
            &git,
            &source,
            &[
                OsStr::new("commit"),
                OsStr::new("--quiet"),
                OsStr::new("-m"),
                OsStr::new("base"),
            ],
        )
        .await;

        setup_git(
            &git,
            &workspace,
            &[OsStr::new("init"), OsStr::new("--quiet")],
        )
        .await;
        for (key, value) in [("user.name", "core-test"), ("user.email", "core@test")] {
            setup_git(
                &git,
                &workspace,
                &[OsStr::new("config"), OsStr::new(key), OsStr::new(value)],
            )
            .await;
        }
        setup_git(
            &git,
            &workspace,
            &[
                OsStr::new("-c"),
                OsStr::new("protocol.file.allow=always"),
                OsStr::new("submodule"),
                OsStr::new("add"),
                OsStr::new("--quiet"),
                source.as_os_str(),
                OsStr::new("sub"),
            ],
        )
        .await;
        setup_git(
            &git,
            &workspace,
            &[
                OsStr::new("commit"),
                OsStr::new("--quiet"),
                OsStr::new("-m"),
                OsStr::new("submodule"),
            ],
        )
        .await;

        let filter = temp.0.join("submodule-filter");
        let marker = temp.0.join("submodule-filter-ran");
        script(
            &filter,
            &format!("printf hit > \"{}\"\n/bin/cat", marker.display()),
        );
        let submodule = workspace.join("sub");
        setup_git(
            &git,
            &submodule,
            &[
                OsStr::new("config"),
                OsStr::new("filter.evil.clean"),
                filter.as_os_str(),
            ],
        )
        .await;
        std::fs::write(submodule.join("tracked"), "after\n").unwrap();

        // Prove this fixture reaches the dangerous nested-status path without the production
        // submodule guard; otherwise a passing marker assertion below would be vacuous.
        setup_git(
            &git,
            &workspace,
            &[
                OsStr::new("--no-pager"),
                OsStr::new("diff"),
                OsStr::new("--no-ext-diff"),
                OsStr::new("--no-textconv"),
            ],
        )
        .await;
        assert!(
            marker.exists(),
            "test setup did not activate the submodule clean filter"
        );
        std::fs::remove_file(&marker).unwrap();

        run_git_diff(&workspace, false, None).await.unwrap();
        assert!(
            !marker.exists(),
            "git_diff descended into a dirty submodule and executed its filter"
        );
    }

    #[tokio::test]
    async fn registry_rejects_a_path_escape_before_spawning_git() {
        let temp = TestDir::new("path-escape");
        let registry = Registry::read_only(&temp.0).unwrap();
        let result = registry
            .run(ToolUse {
                id: "git-path-escape".into(),
                name: "git_diff".into(),
                input: serde_json::json!({"path":"../outside"}),
            })
            .await;
        assert!(result.is_error);
        assert!(result.content.contains("escapes the workspace"));
    }
}
