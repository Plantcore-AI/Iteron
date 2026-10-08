//! Host-owned bounded operator shell execution. Presentation supplies only a command and cancellation.

use crate::semantic_text::ui_safe_text;
use iteron_protocol::{Capability, PermissionMode, PermissionRules, Verdict};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(120);
const HEAD_BYTES: usize = 48 * 1024;
const TAIL_BYTES: usize = 16 * 1024;
/// How long the last pipe drain may run after the process group was killed. The writers are already
/// dead, so this only bounds a stuck reader; exceeding it costs partial output, never a hang.
const POST_KILL_DRAIN: Duration = Duration::from_secs(1);
/// Reported exit code when the process left no code of its own (signalled, or never reaped). `-1`
/// is outside the 0..=255 wait-status range, so it cannot collide with a real exit status.
const NO_EXIT_CODE: i32 = -1;

#[cfg(not(windows))]
type ShellChild = tokio::process::Child;
#[cfg(windows)]
type ShellChild = iteron_support::owned_windows_job::OwnedWindowsChild;

#[cfg(windows)]
pub(crate) enum WindowsShellCustody {
    Launch(Box<iteron_support::owned_windows_job::WindowsJobLaunchError>),
    Job(std::sync::Arc<iteron_support::owned_windows_job::OwnedWindowsJob>),
}
#[cfg(windows)]
impl std::fmt::Debug for WindowsShellCustody {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Launch(error) => formatter
                .debug_tuple("WindowsLaunchCustody")
                .field(error)
                .finish(),
            Self::Job(job) => formatter
                .debug_tuple("WindowsJobCustody")
                .field(job)
                .finish(),
        }
    }
}

#[derive(serde::Serialize)]
pub(crate) struct ShellCompletion {
    pub(crate) source_run: Option<iteron_protocol::RunId>,
    pub(crate) command: String,
    pub(crate) body: String,
    pub(crate) ok: bool,
    pub(crate) code: i32,
    pub(crate) outcome: ShellOutcome,
    pub(crate) cleanup: ShellCleanup,
    #[cfg(windows)]
    #[serde(skip)]
    pub(crate) windows_custody: Option<WindowsShellCustody>,
}
impl std::fmt::Debug for ShellCompletion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut view = formatter.debug_struct("ShellCompletion");
        view.field("source_run", &self.source_run)
            .field("command_bytes", &self.command.len())
            .field("body_bytes", &self.body.len())
            .field("ok", &self.ok)
            .field("code", &self.code)
            .field("outcome", &self.outcome)
            .field("cleanup", &self.cleanup);
        #[cfg(windows)]
        view.field("windows_custody", &self.windows_custody);
        view.finish()
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ShellOutcome {
    NotStarted,
    Completed,
    OutcomeUnknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ShellCleanup {
    NotDispatched,
    Reaped,
    Unobserved,
}

/// This value has no path-taking or deserializing constructor. The actual resident host captures
/// permission/environment truth; a frontend snapshot cannot supply a grant or executable root.
pub(crate) struct NativeShellScope {
    workspace: PathBuf,
    run: iteron_protocol::RunId,
    mode: PermissionMode,
    rules: PermissionRules,
    credential_env_names: Vec<String>,
    admitted: bool,
    command: String,
}
impl NativeShellScope {
    pub(crate) fn capture(agent: &crate::runtime::Agent, command: String) -> Self {
        Self {
            workspace: agent.workspace.clone(),
            run: agent.rollout.run_id().clone(),
            mode: agent.permission_mode(),
            rules: agent.permission_rules().clone(),
            credential_env_names: agent.operator_child_environment_names().to_vec(),
            admitted: agent.admit_operator_shell(&command),
            command,
        }
    }
    pub(crate) async fn execute(
        self,
        mut cancelled: tokio::sync::watch::Receiver<bool>,
    ) -> ShellCompletion {
        let command = self.command;
        let mut result = if !self.admitted {
            failed(
                &command,
                "actual host permission policy refuses this command".into(),
            )
        } else {
            execute(
                &self.workspace,
                &command,
                &self.credential_env_names,
                self.mode,
                &self.rules,
                &mut cancelled,
            )
            .await
        };
        result.source_run = Some(self.run);
        result
    }
}

fn failed(command: &str, body: String) -> ShellCompletion {
    ShellCompletion {
        source_run: None,
        command: display(command, 32 * 1024),
        body: display(&body, 256 * 1024),
        ok: false,
        code: -1,
        outcome: ShellOutcome::NotStarted,
        cleanup: ShellCleanup::NotDispatched,
        #[cfg(windows)]
        windows_custody: None,
    }
}

#[derive(Default)]
struct Capture {
    head: Vec<u8>,
    tail: VecDeque<u8>,
    total: u64,
}

impl Capture {
    fn push(&mut self, bytes: &[u8]) {
        self.total = self.total.saturating_add(bytes.len() as u64);
        let head_len = bytes.len().min(
            iteron_tunables::param_integer("cli.tui.inline_shell.head_bytes", HEAD_BYTES)
                .min(HEAD_BYTES)
                .saturating_sub(self.head.len()),
        );
        self.head.extend_from_slice(&bytes[..head_len]);
        let remainder = &bytes[head_len..];
        if remainder.len()
            >= iteron_tunables::param_integer("cli.tui.inline_shell.tail_bytes", TAIL_BYTES)
                .clamp(1, TAIL_BYTES)
        {
            self.tail.clear();
            self.tail.extend(
                &remainder[remainder.len()
                    - iteron_tunables::param_integer(
                        "cli.tui.inline_shell.tail_bytes",
                        TAIL_BYTES,
                    )
                    .clamp(1, TAIL_BYTES)..],
            );
            return;
        }
        let overflow = self
            .tail
            .len()
            .saturating_add(remainder.len())
            .saturating_sub(
                iteron_tunables::param_integer("cli.tui.inline_shell.tail_bytes", TAIL_BYTES)
                    .clamp(1, TAIL_BYTES),
            );
        if overflow > 0 {
            self.tail.drain(..overflow);
        }
        self.tail.extend(remainder);
    }

    fn finish(self, stream: &str) -> String {
        let retained = self.head.len().saturating_add(self.tail.len()) as u64;
        let omitted = self.total.saturating_sub(retained);
        let mut bytes = self.head;
        if omitted > 0 {
            bytes.extend_from_slice(
                format!("\n[… {stream} truncated: {omitted} bytes omitted …]\n").as_bytes(),
            );
        }
        bytes.extend(self.tail);
        ui_safe_text(&decode(bytes))
    }
}

fn decode(bytes: Vec<u8>) -> String {
    match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(error) => {
            let mut text = String::from("[invalid UTF-8 escaped]\n");
            for byte in error.into_bytes() {
                match byte {
                    b'\n' => text.push('\n'),
                    b'\t' => text.push('\t'),
                    0x20..=0x7e => text.push(char::from(byte)),
                    byte => text.push_str(&format!("\\x{byte:02x}")),
                }
            }
            text
        }
    }
}

async fn drain<R>(reader: &mut R, capture: &mut Capture) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut chunk = [0_u8; 8 * 1024];
    loop {
        let read = reader.read(&mut chunk).await?;
        if read == 0 {
            return Ok(());
        }
        capture.push(&chunk[..read]);
    }
}

/// Run an operator command through the same code-execution capability gate as model tools.
async fn execute(
    repo: &Path,
    cmd: &str,
    credential_env_names: &[String],
    mode: PermissionMode,
    rules: &PermissionRules,
    cancelled: &mut tokio::sync::watch::Receiver<bool>,
) -> ShellCompletion {
    if *cancelled.borrow() || cmd.is_empty() || cmd.len() > 64 * 1024 {
        return failed(
            cmd,
            "shell cancelled or command exceeds its finite bound before dispatch".into(),
        );
    }
    if iteron_protocol::gate(mode, rules, "bash", Capability::CodeExecuting) == Verdict::Deny {
        return failed(
            cmd,
            ui_safe_text(&format!(
                "{} mode denies code execution; the operator `!` shell routes through the same capability gate as the agent. blocked command: {cmd}",
                mode.label()
            )),
        );
    }

    let mut command = tokio::process::Command::new("bash");
    command
        .arg("--noprofile")
        .arg("--norc")
        .arg("-c")
        .arg(cmd)
        .current_dir(repo)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    iteron_sandbox::clear_to_safe_child_env_with_exact(&mut command, credential_env_names);

    #[cfg(not(windows))]
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return failed(
                cmd,
                ui_safe_text(&format!("shell failed to launch: {error}")),
            );
        }
    };
    #[cfg(windows)]
    let mut child = match ShellChild::spawn(command.as_std_mut()).await {
        Ok(child) => child,
        Err(error) => {
            if error.not_dispatched() {
                return failed(cmd, error.to_string());
            }
            return ShellCompletion {
                source_run: None,
                command: display(cmd, 32 * 1024),
                body: display(&error.to_string(), 256 * 1024),
                ok: false,
                code: NO_EXIT_CODE,
                outcome: ShellOutcome::OutcomeUnknown,
                cleanup: ShellCleanup::Unobserved,
                windows_custody: Some(WindowsShellCustody::Launch(Box::new(error))),
            };
        }
    };
    #[cfg(not(windows))]
    let mut group = OwnedProcessGroup::new(child.id());
    #[cfg(windows)]
    let mut group = OwnedProcessGroup::new(child.id(), child.job());
    let Some(mut stdout) = child.stdout.take() else {
        group.terminate(&mut child).await;
        return unobserved(cmd, "shell stdout pipe was unavailable".into(), &group);
    };
    let Some(mut stderr) = child.stderr.take() else {
        group.terminate(&mut child).await;
        return unobserved(cmd, "shell stderr pipe was unavailable".into(), &group);
    };

    let mut out = Capture::default();
    let mut err = Capture::default();
    let deadline =
        iteron_tunables::param_duration("cli.tui.inline_shell.timeout", TIMEOUT).min(TIMEOUT);
    let completed = {
        let running = tokio::time::timeout(deadline, async {
            // Keep the direct child unreaped until both pipes close. A cancelled drain can
            // still signal its exact owned process group without a reusable pgid window.
            #[cfg(not(windows))]
            {
                let (out_result, err_result) =
                    tokio::join!(drain(&mut stdout, &mut out), drain(&mut stderr, &mut err));
                out_result?;
                err_result?;
                group.wait_and_close(&mut child).await
            }
            #[cfg(windows)]
            {
                // Actual leader completion closes its owned Job concurrently with pipe drain,
                // including redirected or pipe-holding descendants. EOF alone cannot do this.
                let (out_result, err_result, status) = tokio::join!(
                    drain(&mut stdout, &mut out),
                    drain(&mut stderr, &mut err),
                    group.wait_and_close(&mut child),
                );
                out_result?;
                err_result?;
                group.pipes_closed = true;
                status
            }
        });
        tokio::pin!(running);
        tokio::select! {
            result = &mut running => Some(result),
            changed = cancelled.changed() => {
                let _ = changed;
                None
            }
        }
    };
    if completed.is_none() {
        group.terminate(&mut child).await;
        let drained = tokio::time::timeout(
            iteron_tunables::param_duration(
                "cli.tui.inline_shell.post_kill_drain",
                POST_KILL_DRAIN,
            )
            .min(POST_KILL_DRAIN),
            async { tokio::join!(drain(&mut stdout, &mut out), drain(&mut stderr, &mut err)) },
        )
        .await;
        #[cfg(windows)]
        {
            group.pipes_closed = matches!(drained, Ok((Ok(()), Ok(()))));
        }
        #[cfg(not(windows))]
        let _ = drained;
        return unobserved(
            cmd,
            "[cancelled by operator; dispatched shell effects may have occurred]".into(),
            &group,
        );
    }
    let (status, timed_out) = match completed {
        Some(Ok(Ok(status))) => (Some(status), false),
        Some(Ok(Err(error))) => {
            group.terminate(&mut child).await;
            return unobserved(
                cmd,
                ui_safe_text(&format!("shell output failed after dispatch: {error}")),
                &group,
            );
        }
        Some(Err(_)) => {
            group.terminate(&mut child).await;
            let status = child.try_wait().ok().flatten();
            if status.is_some() {
                group.pid = None;
                group.observe_closed_group().await;
            }
            let drained = tokio::time::timeout(
                iteron_tunables::param_duration(
                    "cli.tui.inline_shell.post_kill_drain",
                    POST_KILL_DRAIN,
                )
                .min(POST_KILL_DRAIN),
                async { tokio::join!(drain(&mut stdout, &mut out), drain(&mut stderr, &mut err)) },
            )
            .await;
            #[cfg(windows)]
            {
                group.pipes_closed = matches!(drained, Ok((Ok(()), Ok(()))));
            }
            #[cfg(not(windows))]
            let _ = drained;
            (status, true)
        }
        None => unreachable!("cancelled returned above"),
    };

    let code = status
        .and_then(|status| status.code())
        .unwrap_or(NO_EXIT_CODE);
    let mut body = out.finish("stdout");
    let stderr = err.finish("stderr");
    if !stderr.trim().is_empty() {
        if !body.trim().is_empty() {
            body.push_str("\n[stderr]\n");
        }
        body.push_str(&stderr);
    }
    if timed_out {
        body.insert_str(
            0,
            &format!("[timed out after {}ms]\n", deadline.as_millis()),
        );
    }
    let cleanup_confirmed = group.cleanup_confirmed();
    if !cleanup_confirmed {
        body.insert_str(
            0,
            "[owned process-group cleanup remains unobserved; host admission retained]\n",
        );
    }
    let ok = !timed_out && cleanup_confirmed && status.is_some_and(|status| status.success());
    ShellCompletion {
        source_run: None,
        command: display(cmd, 32 * 1024),
        body: display(&body, 256 * 1024),
        ok,
        code,
        outcome: if timed_out || !cleanup_confirmed {
            ShellOutcome::OutcomeUnknown
        } else {
            ShellOutcome::Completed
        },
        cleanup: if group.cleanup_confirmed() {
            ShellCleanup::Reaped
        } else {
            ShellCleanup::Unobserved
        },
        #[cfg(windows)]
        windows_custody: (!group.cleanup_confirmed())
            .then(|| WindowsShellCustody::Job(group.job.clone())),
    }
}

fn display(text: &str, limit: usize) -> String {
    let safe = ui_safe_text(text);
    if safe.len() <= limit {
        return safe;
    }
    let mut end = limit.saturating_sub(32);
    while !safe.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n[display truncated]", &safe[..end])
}
fn unobserved(command: &str, body: String, group: &OwnedProcessGroup) -> ShellCompletion {
    ShellCompletion {
        source_run: None,
        command: display(command, 32 * 1024),
        body: display(&body, 256 * 1024),
        ok: false,
        code: NO_EXIT_CODE,
        outcome: ShellOutcome::OutcomeUnknown,
        cleanup: if group.cleanup_confirmed() {
            ShellCleanup::Reaped
        } else {
            ShellCleanup::Unobserved
        },
        #[cfg(windows)]
        windows_custody: (!group.cleanup_confirmed())
            .then(|| WindowsShellCustody::Job(group.job.clone())),
    }
}
#[cfg(test)]
pub(crate) async fn run_fixture(
    repo: &Path,
    command: &str,
    mode: PermissionMode,
    rules: &PermissionRules,
    cancelled: &mut tokio::sync::watch::Receiver<bool>,
) -> ShellCompletion {
    execute(repo, command, &[], mode, rules, cancelled).await
}

/// A retained unreaped leader protects group identity until the last signal. After actual reap,
/// numeric group identity is observation-only: no later cleanup can signal a reused process group.
struct OwnedProcessGroup {
    pid: Option<u32>,
    #[cfg(unix)]
    group: Option<i32>,
    confirmed: bool,
    #[cfg(windows)]
    job: std::sync::Arc<iteron_support::owned_windows_job::OwnedWindowsJob>,
    #[cfg(windows)]
    pipes_closed: bool,
}
impl OwnedProcessGroup {
    fn new(
        pid: Option<u32>,
        #[cfg(windows)] job: std::sync::Arc<iteron_support::owned_windows_job::OwnedWindowsJob>,
    ) -> Self {
        Self {
            pid,
            #[cfg(unix)]
            group: pid.and_then(|pid| i32::try_from(pid).ok()),
            confirmed: false,
            #[cfg(windows)]
            job,
            #[cfg(windows)]
            pipes_closed: false,
        }
    }
    fn cleanup_confirmed(&self) -> bool {
        #[cfg(windows)]
        {
            self.confirmed && self.pipes_closed
        }
        #[cfg(not(windows))]
        {
            self.confirmed
        }
    }
    fn signal_retained_group(&self) {
        #[cfg(windows)]
        {
            let _ = self.job.terminate();
        }
        #[cfg(unix)]
        if let Some(pid) = self.pid.and_then(|pid| i32::try_from(pid).ok()) {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
    }
    async fn wait_and_close(
        &mut self,
        child: &mut ShellChild,
    ) -> std::io::Result<std::process::ExitStatus> {
        #[cfg(unix)]
        {
            let pid = self
                .pid
                .ok_or_else(|| std::io::Error::other("shell leader identity unavailable"))?;
            loop {
                // WNOWAIT observes exit without freeing the leader/group ID. Pipe EOF alone is
                // not exit: redirected foreground work must still be allowed to finish.
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                let result = unsafe {
                    libc::waitid(
                        libc::P_PID,
                        pid as libc::id_t,
                        &mut info,
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    )
                };
                if result != 0 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    // An unexpectedly reaped leader cannot authorize a raw numeric signal.
                    if error.raw_os_error() == Some(libc::ECHILD) {
                        self.pid = None;
                    }
                    return Err(error);
                }
                if unsafe { info.si_pid() } == pid as i32 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            // The leader is exited but still retained. Kill remaining members, including those
            // that redirected all pipes, before consuming the exact leader wait receipt.
            self.signal_retained_group();
        }
        let status = match child.wait().await {
            Ok(status) => status,
            Err(error) => {
                self.pid = None;
                return Err(error);
            }
        };
        self.pid = None;
        #[cfg(windows)]
        {
            let _ = self.job.terminate();
        }
        self.observe_closed_group().await;
        Ok(status)
    }
    async fn terminate(&mut self, child: &mut ShellChild) {
        self.signal_retained_group();
        let _ = child.start_kill();
        match tokio::time::timeout(Duration::from_secs(1), child.wait()).await {
            Ok(Ok(_)) => {
                self.pid = None;
                self.observe_closed_group().await;
            }
            Ok(Err(_)) => self.pid = None,
            Err(_) => {}
        }
    }
    async fn observe_closed_group(&mut self) {
        #[cfg(unix)]
        if let Some(group) = self.group {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
            loop {
                // Zero signal never kills a possibly reused group. Only ESRCH is absence proof;
                // permission refusal, retained zombies and any other ambiguity keep custody.
                if unsafe { libc::kill(-group, 0) } == -1
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
                {
                    self.confirmed = true;
                    return;
                }
                if tokio::time::Instant::now() >= deadline {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        #[cfg(windows)]
        {
            self.confirmed = self.job.confirm_empty(Duration::from_secs(1)).await;
        }
        // No unsupported platform infers descendant cleanup from its leader alone.
    }
}
impl Drop for OwnedProcessGroup {
    fn drop(&mut self) {
        self.signal_retained_group();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[tokio::test]
    async fn dispatched_cancel_keeps_unknown_effects_after_actual_marker_and_child_reap() {
        let root = std::env::temp_dir().join(format!(
            "iteron-shell-cancel-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let (cancel, mut cancelled) = tokio::sync::watch::channel(false);
        let directory = root.clone();
        let work = tokio::spawn(async move {
            execute(
                &directory,
                "printf actual > marker; exec sleep 30",
                &[],
                PermissionMode::Default,
                &PermissionRules::new(),
                &mut cancelled,
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            while !root.join("marker").exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        cancel.send(true).unwrap();
        let receipt = tokio::time::timeout(Duration::from_secs(3), work)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(receipt.outcome, ShellOutcome::OutcomeUnknown);
        assert_eq!(receipt.cleanup, ShellCleanup::Reaped);
        assert_eq!(std::fs::read(root.join("marker")).unwrap(), b"actual");
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(all(test, windows))]
#[path = "shell/windows_tests.rs"]
mod windows_tests;
