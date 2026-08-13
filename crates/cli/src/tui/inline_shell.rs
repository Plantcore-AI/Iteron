//! Bounded operator `!command` execution.

use crate::semantic_text::ui_safe_text;
use iteron_protocol::{Capability, PermissionMode, PermissionRules, Verdict};
use std::collections::VecDeque;
use std::path::Path;
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

#[derive(Debug)]
pub(crate) struct ShellCompletion {
    pub(crate) command: String,
    pub(crate) body: String,
    pub(crate) ok: bool,
    pub(crate) code: i32,
}

fn failed(command: &str, body: String) -> ShellCompletion {
    ShellCompletion {
        command: command.to_owned(),
        body,
        ok: false,
        code: -1,
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
        let head_len = bytes.len().min(HEAD_BYTES.saturating_sub(self.head.len()));
        self.head.extend_from_slice(&bytes[..head_len]);
        let remainder = &bytes[head_len..];
        if remainder.len() >= TAIL_BYTES {
            self.tail.clear();
            self.tail.extend(&remainder[remainder.len() - TAIL_BYTES..]);
            return;
        }
        let overflow = self
            .tail
            .len()
            .saturating_add(remainder.len())
            .saturating_sub(TAIL_BYTES);
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
pub(super) async fn run_bash_inline(
    repo: &Path,
    cmd: &str,
    credential_env_names: &[String],
    mode: PermissionMode,
    rules: &PermissionRules,
    cancelled: &mut tokio::sync::watch::Receiver<bool>,
) -> ShellCompletion {
    if cmd.is_empty() {
        return failed(cmd, "empty shell command".into());
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
    for name in credential_env_names {
        command.env_remove(name);
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return failed(
                cmd,
                ui_safe_text(&format!("shell failed to launch: {error}")),
            );
        }
    };
    let Some(mut stdout) = child.stdout.take() else {
        iteron_sandbox::terminate_process_group_and_reap(&mut child).await;
        return failed(cmd, "shell stdout pipe was unavailable".into());
    };
    let Some(mut stderr) = child.stderr.take() else {
        iteron_sandbox::terminate_process_group_and_reap(&mut child).await;
        return failed(cmd, "shell stderr pipe was unavailable".into());
    };

    let mut out = Capture::default();
    let mut err = Capture::default();
    let completed = {
        let running = tokio::time::timeout(TIMEOUT, async {
            let (out_result, err_result, status) = tokio::join!(
                drain(&mut stdout, &mut out),
                drain(&mut stderr, &mut err),
                child.wait(),
            );
            out_result?;
            err_result?;
            status
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
        iteron_sandbox::terminate_process_group_and_reap(&mut child).await;
        let _ = tokio::time::timeout(POST_KILL_DRAIN, async {
            let _ = tokio::join!(drain(&mut stdout, &mut out), drain(&mut stderr, &mut err));
        })
        .await;
        return failed(cmd, "[cancelled by operator]".into());
    }
    let (status, timed_out) = match completed {
        Some(Ok(Ok(status))) => (Some(status), false),
        Some(Ok(Err(error))) => {
            return failed(cmd, ui_safe_text(&format!("shell output failed: {error}")));
        }
        Some(Err(_)) => {
            iteron_sandbox::terminate_process_group_and_reap(&mut child).await;
            let status = child.try_wait().ok().flatten();
            let _ = tokio::time::timeout(POST_KILL_DRAIN, async {
                let _ = tokio::join!(drain(&mut stdout, &mut out), drain(&mut stderr, &mut err),);
            })
            .await;
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
        body.insert_str(0, "[timed out after 120s]\n");
    }
    let ok = !timed_out && status.is_some_and(|status| status.success());
    ShellCompletion {
        command: cmd.to_owned(),
        body,
        ok,
        code,
    }
}
