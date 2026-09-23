//! One-shot, process-isolated native file mutation. The child installs a kernel write policy
//! before opening a writable file descriptor; unrelated provider/runtime I/O stays in the parent.

use crate::{ToolExecution, err_result, ok_result};
use iteron_protocol::{ToolResult, ToolUse};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Stdio;
#[cfg(target_os = "linux")]
use std::time::Duration;
#[cfg(all(not(test), target_os = "linux"))]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Serialize, Deserialize)]
struct Request {
    root: PathBuf,
    call: ToolUse,
    #[cfg(target_os = "linux")]
    root_device: u64,
    #[cfg(target_os = "linux")]
    root_inode: u64,
}

#[derive(Serialize, Deserialize)]
struct Response {
    result: ToolResult,
    outcome_unknown: bool,
}

pub(crate) async fn execute(root: &Path, call: ToolUse, test_helper_thread: bool) -> ToolExecution {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = root;
        let _ = test_helper_thread;
        return ToolExecution::Definite(err_result(
            call.id,
            "confined native writes require the Linux Landlock helper".into(),
        ));
    }
    #[cfg(all(test, target_os = "linux"))]
    {
        let _ = test_helper_thread;
        execute_in_test_landlock_thread(root.to_path_buf(), call).await
    }
    #[cfg(all(not(test), target_os = "linux"))]
    {
        #[cfg(feature = "test-helper")]
        if test_helper_thread {
            return execute_in_test_landlock_thread(root.to_path_buf(), call).await;
        }
        #[cfg(not(feature = "test-helper"))]
        let _ = test_helper_thread;
        use std::os::unix::fs::MetadataExt;
        let id = call.id.clone();
        let root = match root.canonicalize().and_then(|path| {
            let metadata = path.metadata()?;
            Ok((path, metadata.dev(), metadata.ino()))
        }) {
            Ok(root) => root,
            Err(error) => {
                return ToolExecution::Definite(err_result(
                    id,
                    format!("workspace root unavailable: {error}"),
                ));
            }
        };
        let request = Request {
            root: root.0,
            call,
            root_device: root.1,
            root_inode: root.2,
        };
        let bytes = match serde_json::to_vec(&request) {
            Ok(bytes) if bytes.len() <= 64 * 1024 * 1024 => bytes,
            _ => {
                return ToolExecution::Definite(err_result(
                    id,
                    "confined helper request exceeds its fixed byte limit".into(),
                ));
            }
        };
        let executable = match std::env::current_exe() {
            Ok(path) => path,
            Err(error) => {
                return ToolExecution::Definite(err_result(
                    id,
                    format!("confined helper executable unavailable: {error}"),
                ));
            }
        };
        let mut command = tokio::process::Command::new(executable);
        command
            .arg("--internal-confined-write")
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        #[cfg(debug_assertions)]
        if std::env::var_os("ITERON_HELPER_EXIT_AFTER_EFFECT").is_some() {
            command.env("ITERON_HELPER_EXIT_AFTER_EFFECT", "1");
        }
        #[cfg(debug_assertions)]
        if std::env::var_os("ITERON_HELPER_FAIL_PARENT_SYNC").is_some() {
            command.env("ITERON_HELPER_FAIL_PARENT_SYNC", "1");
        }
        let child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                return ToolExecution::Definite(err_result(
                    id,
                    format!("confined helper launch refused: {error}"),
                ));
            }
        };
        let mut guard = ChildGuard::new(child);
        let attempt = tokio::time::timeout(
            Duration::from_secs(120),
            transact(guard.child.as_mut().expect("helper child owned"), &bytes),
        )
        .await;
        match attempt {
            Ok(Ok(response)) => {
                if response.result.tool_use_id != id {
                    return unknown(id, "confined helper identity mismatch");
                }
                if response.outcome_unknown {
                    ToolExecution::Unknown(response.result)
                } else {
                    ToolExecution::Definite(response.result)
                }
            }
            Ok(Err(reason)) => {
                guard.kill_and_reap().await;
                unknown(id, &format!("confined helper outcome unknown: {reason}"))
            }
            Err(_) => {
                guard.kill_and_reap().await;
                unknown(id, "confined helper timed out; write outcome unknown")
            }
        }
    }
}

#[cfg(target_os = "linux")]
struct ChildGuard {
    child: Option<tokio::process::Child>,
}

#[cfg(target_os = "linux")]
impl ChildGuard {
    fn new(child: tokio::process::Child) -> Self {
        Self { child: Some(child) }
    }

    #[cfg(not(test))]
    async fn kill_and_reap(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        let _ = child.start_kill();
        // Cancellation drops the async parent future. A dedicated reaper retains the owned
        // child even if that runtime is shutting down.
        let _ = std::thread::Builder::new()
            .name("iteron-write-reaper".into())
            .spawn(move || {
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                loop {
                    if child.try_wait().ok().flatten().is_some() {
                        break;
                    }
                    if std::time::Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            });
    }
}

#[cfg(all(test, target_os = "linux"))]
mod child_guard_tests {
    use super::*;

    #[tokio::test]
    async fn cancellation_kills_and_reaps_owned_helper_child() {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let child = tokio::process::Command::new("/bin/sleep")
                .arg("30")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let pid = child.id().unwrap();
            let _guard = ChildGuard::new(child);
            let _ = sender.send(pid);
            std::future::pending::<()>().await;
        });
        let pid = receiver.await.unwrap();
        task.abort();
        let _ = task.await;
        let proc_path = format!("/proc/{pid}");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::path::Path::new(&proc_path).exists() && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            !std::path::Path::new(&proc_path).exists(),
            "cancelled helper PID {pid} was not reaped"
        );
    }
}

#[cfg(all(any(test, feature = "test-helper"), target_os = "linux"))]
async fn execute_in_test_landlock_thread(root: PathBuf, call: ToolUse) -> ToolExecution {
    let id = call.id.clone();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let result = (|| -> io::Result<Response> {
            use std::os::unix::fs::MetadataExt;
            let root = root.canonicalize()?;
            let metadata = root.metadata()?;
            install_landlock(&root, metadata.dev(), metadata.ino())?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            Ok(runtime.block_on(async {
                let before = effect_snapshot(&root, &call).await;
                let result = run_request(&root, call).await;
                let outcome_unknown =
                    result.is_error && error_effect_unknown(before, &result).await;
                Response {
                    result,
                    outcome_unknown,
                }
            }))
        })();
        let _ = sender.send(result);
    });
    match receiver.await {
        Ok(Ok(response)) if response.outcome_unknown => ToolExecution::Unknown(response.result),
        Ok(Ok(response)) => ToolExecution::Definite(response.result),
        Ok(Err(error)) => ToolExecution::Definite(err_result(
            id,
            format!("confined test helper refused: {error}"),
        )),
        Err(_) => unknown(id, "confined test helper exited without a result"),
    }
}

#[cfg(target_os = "linux")]
fn unknown(id: String, message: &str) -> ToolExecution {
    ToolExecution::Unknown(err_result(id, message.into()))
}

#[cfg(all(not(test), target_os = "linux"))]
async fn transact(child: &mut tokio::process::Child, request: &[u8]) -> io::Result<Response> {
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("helper stdin missing"))?;
    stdin.write_all(request).await?;
    stdin.shutdown().await?;
    drop(stdin);
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("helper stdout missing"))?;
    let mut response = Vec::new();
    stdout
        .take(1024 * 1024 + 1)
        .read_to_end(&mut response)
        .await?;
    if response.len() > 1024 * 1024 {
        return Err(io::Error::other("helper response exceeds fixed byte limit"));
    }
    let status = child.wait().await?;
    if !status.success() {
        return Err(io::Error::other(format!("helper exited with {status}")));
    }
    serde_json::from_slice(&response).map_err(io::Error::other)
}

/// Called by the CLI's hidden early dispatch, before it creates any Tokio worker threads.
/// All errors leave the child with nonzero status and are treated as an unknown write outcome by
/// the parent once process dispatch has begun.
pub fn confined_helper_entry() -> i32 {
    #[cfg(not(target_os = "linux"))]
    {
        70
    }
    #[cfg(target_os = "linux")]
    {
        match helper_entry_inner() {
            Ok(()) => 0,
            Err(_) => 70,
        }
    }
}

#[cfg(target_os = "linux")]
fn helper_entry_inner() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin()
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut input)?;
    if input.len() > 64 * 1024 * 1024 {
        return Err(io::Error::other("helper request exceeds fixed byte limit"));
    }
    let request: Request = serde_json::from_slice(&input).map_err(io::Error::other)?;
    if !matches!(
        request.call.name.as_str(),
        "write_file" | "edit" | "apply_patch"
    ) {
        return Err(io::Error::other("unsupported helper operation"));
    }
    close_inherited_descriptors()?;
    #[cfg(debug_assertions)]
    debug_pause_if("ITERON_HELPER_PAUSE_BEFORE_LANDLOCK");
    let root = request.root.canonicalize()?;
    install_landlock(&root, request.root_device, request.root_inode)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let response = runtime.block_on(async {
        let before = effect_snapshot(&root, &request.call).await;
        let result = run_request(&root, request.call).await;
        let outcome_unknown = result.is_error && error_effect_unknown(before, &result).await;
        Response {
            result,
            outcome_unknown,
        }
    });
    #[cfg(debug_assertions)]
    if std::env::var_os("ITERON_HELPER_EXIT_AFTER_EFFECT").is_some() {
        std::process::exit(91);
    }
    let bytes = serde_json::to_vec(&response).map_err(io::Error::other)?;
    if bytes.len() > 1024 * 1024 {
        return Err(io::Error::other("helper response exceeds fixed byte limit"));
    }
    io::stdout().write_all(&bytes)?;
    io::stdout().flush()
}

#[cfg(target_os = "linux")]
struct EffectSnapshot {
    targets: Vec<(PathBuf, crate::write_file::TargetSnapshot)>,
    parent_was_missing: bool,
}

#[cfg(target_os = "linux")]
async fn effect_snapshot(root: &Path, call: &ToolUse) -> io::Result<EffectSnapshot> {
    let paths: Vec<&str> = if call.name == "apply_patch" {
        call.input
            .get("files")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| io::Error::other("patch files missing"))?
            .iter()
            .map(|item| {
                item.get("path")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| io::Error::other("patch path missing"))
            })
            .collect::<io::Result<_>>()?
    } else {
        vec![
            call.input
                .get("path")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| io::Error::other("target path missing"))?,
        ]
    };
    if paths.is_empty() || paths.len() > 64 {
        return Err(io::Error::other("invalid target count"));
    }
    let mut targets = Vec::with_capacity(paths.len());
    let mut parent_was_missing = false;
    for path in paths {
        let target = crate::resolve_in_root(root, path).map_err(io::Error::other)?;
        if call.name == "write_file" {
            let mut ancestor = target.parent();
            while let Some(parent) = ancestor {
                if parent == root {
                    break;
                }
                if !parent.exists() {
                    parent_was_missing = true;
                }
                ancestor = parent.parent();
            }
        }
        let snapshot = crate::write_file::capture_target_snapshot(&target)
            .await
            .map_err(io::Error::other)?;
        targets.push((target, snapshot));
    }
    Ok(EffectSnapshot {
        targets,
        parent_was_missing,
    })
}

#[cfg(target_os = "linux")]
async fn error_effect_unknown(before: io::Result<EffectSnapshot>, result: &ToolResult) -> bool {
    if serde_json::from_str::<serde_json::Value>(&result.content)
        .ok()
        .and_then(|value| {
            value
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .as_deref()
        == Some("rollback_failed")
    {
        return true;
    }
    let Ok(before) = before else {
        return true;
    };
    if before.parent_was_missing {
        return true;
    }
    for (path, expected) in before.targets {
        let Ok(actual) = crate::write_file::capture_target_snapshot(&path).await else {
            return true;
        };
        if actual != expected {
            return true;
        }
    }
    false
}

#[cfg(all(target_os = "linux", debug_assertions))]
pub(crate) fn debug_pause_if(name: &str) {
    if std::env::var_os(name).is_some() {
        // SAFETY: SIGSTOP has no handler and resumes only after the external test controller
        // sends SIGCONT. Normal registry launch clears this environment variable.
        unsafe {
            libc::raise(libc::SIGSTOP);
        }
    }
}

#[cfg(not(all(target_os = "linux", debug_assertions)))]
pub(crate) fn debug_pause_if(_name: &str) {}

#[cfg(target_os = "linux")]
async fn run_request(root: &Path, call: ToolUse) -> ToolResult {
    let id = call.id;
    match call.name.as_str() {
        "write_file" => {
            let Some(path) = call.input.get("path").and_then(|value| value.as_str()) else {
                return err_result(id, "write_file: missing string field `path`".into());
            };
            let Some(content) = call.input.get("content").and_then(|value| value.as_str()) else {
                return err_result(id, "write_file: missing string field `content`".into());
            };
            match crate::write_file::write_workspace_file(root, path, content, true).await {
                Ok(()) => ok_result(id, format!("wrote {path} ({} bytes)", content.len())),
                Err(error) => err_result(id, error),
            }
        }
        "edit" => {
            let path = call
                .input
                .get("path")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let old = call
                .input
                .get("old")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let new = call
                .input
                .get("new")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            match crate::edit::edit_workspace_file(root, path, old, new, true).await {
                Ok(()) => ok_result(id, format!("edited {path} (1 replacement)")),
                Err(error) => err_result(id, error),
            }
        }
        "apply_patch" => {
            match crate::multi_file_patch::apply_patch_confined(root, &call.input).await {
                Ok(message) => ok_result(id, message),
                Err(error) => err_result(id, error),
            }
        }
        _ => err_result(id, "unsupported helper operation".into()),
    }
}

#[cfg(target_os = "linux")]
fn install_landlock(root: &Path, expected_device: u64, expected_inode: u64) -> io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    #[repr(C)]
    struct Ruleset {
        handled_access_fs: u64,
    }
    #[repr(C, packed)]
    struct PathBeneath {
        allowed_access: u64,
        parent_fd: i32,
    }
    // Handle every writable filesystem operation supported by ABI 3. Read and execute remain
    // outside this helper's policy; a rule grants only the mutations the native tools need.
    let handled = (1u64 << 1) | (4..=14).map(|bit| 1u64 << bit).sum::<u64>();
    let allowed =
        (1u64 << 1) | (1u64 << 5) | (1u64 << 7) | (1u64 << 8) | (1u64 << 13) | (1u64 << 14);
    // SAFETY: the syscall arguments are the documented Landlock ABI structures and live here.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0,
            1,
        )
    };
    if abi < 3 {
        return Err(io::Error::other("Landlock ABI 3 or newer is required"));
    }
    let canonical = root.canonicalize()?;
    let c_root = std::ffi::CString::new(canonical.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "workspace root contains NUL"))?;
    // SAFETY: c_root is a live NUL-terminated path.
    let rootfd = unsafe {
        libc::open(
            c_root.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if rootfd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: rootfd is newly owned by this process.
    let rootfd = unsafe { std::fs::File::from_raw_fd(rootfd) };
    let actual = rootfd.metadata()?;
    if actual.dev() != expected_device || actual.ino() != expected_inode {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "workspace root identity changed before helper admission",
        ));
    }
    let ruleset = Ruleset {
        handled_access_fs: handled,
    };
    // SAFETY: ruleset is live and initialized.
    let rulesetfd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &ruleset,
            std::mem::size_of::<Ruleset>(),
            0,
        )
    };
    if rulesetfd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: rulesetfd is newly owned by this process.
    let rulesetfd = unsafe { std::fs::File::from_raw_fd(rulesetfd as i32) };
    let rule = PathBeneath {
        allowed_access: allowed,
        parent_fd: rootfd.as_raw_fd(),
    };
    // SAFETY: rule and the two descriptors are live.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            rulesetfd.as_raw_fd(),
            1,
            &rule,
            0,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: prctl takes integer arguments only for this command.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: rulesetfd is valid and flags are zero.
    let rc = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, rulesetfd.as_raw_fd(), 0) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn close_inherited_descriptors() -> io::Result<()> {
    // SAFETY: close_range does not dereference user pointers; only stdio remains. The helper is
    // still single-threaded here, before root binding, Landlock, or Tokio initialization.
    let rc = unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // This first descriptor is a canary for the whole close_range operation.
    // SAFETY: fcntl reads descriptor metadata only.
    if unsafe { libc::fcntl(3, libc::F_GETFD) } >= 0 {
        return Err(io::Error::other("inherited descriptor remained open"));
    }
    if io::Error::last_os_error().raw_os_error() != Some(libc::EBADF) {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
