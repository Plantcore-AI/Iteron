//! Lifecycle hooks for the CLI-composed concrete runtime (Claude Code parity, R5). A hook is an operator-configured command run at a
//! harness lifecycle point: `PreToolUse` (can BLOCK a tool), `PostToolUse` (observe), `Stop`
//! (run finished), `UserPromptSubmit`, `SessionStart`.
//!
//! SECURITY (the load-bearing decision, and why the R5 review deferred external hooks): a hook runs
//! an ARBITRARY COMMAND. It is therefore honored ONLY from the operator's USER config
//! (`~/.core/config.json`) — NEVER from a project/`.core/config.json` that could arrive with a
//! cloned repo. This is the same trust-by-origin discipline as skills/memory/agents (ADR-007 §6):
//! tree-discovered config is untrusted and must not be able to run code. Hooks are the operator's
//! own infrastructure (like the git hooks they wrote), so they run un-sandboxed but with a
//! default-deny, credential-sanitized helper environment — and only because their PROVENANCE is
//! the trusted user config. Each run is bounded by a timeout (invariant #1). A `PreToolUse` hook
//! that exits with code 2 DENIES the tool.
//!
//! Security caveats a hook AUTHOR must know (surfaced per the adversarial review, not hidden):
//! - **Fail-OPEN.** Only exit code **2** blocks. A hook that times out (bounded at 30s), fails to
//!   spawn, or exits with any other code (1, 127 from a typo) is "no opinion" → the tool RUNS. A
//!   PreToolUse hook is a best-effort guardrail, not an airtight sandbox: do not rely on a hook
//!   whose cost scales with its (model-controlled) input — crafted input can push it past the
//!   timeout → bypass. The capability gate (ADR-014), not the hook, is the load-bearing control;
//!   hooks only *tighten* it.
//! - **Coverage.** PreToolUse fires for every EFFECTING tool. For pure/read-only tools it fires
//!   ONLY when a `PreToolUse` hook is configured — which then disables their mid-stream early
//!   dispatch so the hook can speak before the read runs (the kernel handles this). With no
//!   `PreToolUse` hook, reads early-dispatch ungated (the flagship overlap); a hook bound to some
//!   OTHER event says nothing about reads and never costs the session that overlap.
//! - **Un-redacted context.** The JSON on the hook's stdin carries the LIVE tool input/result — a
//!   hook that logs its stdin captures secrets the rollout's redaction would mask. The hook is
//!   operator-authored (trusted), so this is the operator's responsibility.

use serde::Deserialize;
use std::collections::{BTreeMap, VecDeque};
use std::path::Path;
use std::time::Duration;

const HOOK_CAPTURE_HEAD_BYTES: usize = 32 * 1024;
const HOOK_CAPTURE_TAIL_BYTES: usize = 32 * 1024;
const HOOK_READ_CHUNK_BYTES: usize = 8 * 1024;

/// A lifecycle event a hook can bind to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Config accepts the complete lifecycle vocabulary before every site emits it.
pub enum HookEvent {
    PreToolUse,
    PostToolUse,
    Stop,
    UserPromptSubmit,
    SessionStart,
}

impl HookEvent {
    /// The wire name of this lifecycle event. Public because the effect boundary records it as the
    /// audit projection of a hook dispatch (#16).
    pub const fn key(self) -> &'static str {
        match self {
            HookEvent::PreToolUse => "PreToolUse",
            HookEvent::PostToolUse => "PostToolUse",
            HookEvent::Stop => "Stop",
            HookEvent::UserPromptSubmit => "UserPromptSubmit",
            HookEvent::SessionStart => "SessionStart",
        }
    }
}

/// The `hooks` block of the USER config: event name -> list of shell commands.
#[derive(Debug, Clone, Default, Deserialize)]
struct HooksFile {
    #[serde(default)]
    hooks: BTreeMap<String, Vec<String>>,
}

/// The loaded hooks (from the user config only) plus a per-hook timeout.
#[derive(Debug, Clone, Default)]
pub struct Hooks {
    by_event: BTreeMap<String, Vec<String>>,
    timeout_secs: u64,
    sensitive_env_names: Vec<String>,
}

/// What a `PreToolUse` hook decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookDecision {
    /// No hook, or the hook allowed (exit 0 / errored / timed out — a broken hook does not wedge).
    Allow,
    /// A hook deliberately blocked the tool; the string is the reason (its stderr).
    Deny(String),
}

impl Hooks {
    /// Load hooks from the USER config `<home>/.core/config.json` only. A project config is
    /// NEVER read here — a cloned repo must not be able to run a command (trust-by-origin). A
    /// missing/malformed file yields no hooks (hooks are opt-in; a broken config does not brick).
    pub fn load_user(home: &Path) -> Hooks {
        let path = core_protocol::home::path(home, "config.json");
        let by_event = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<HooksFile>(&s).ok())
            .map(|f| f.hooks)
            .unwrap_or_default();
        Hooks {
            by_event,
            timeout_secs: 30,
            sensitive_env_names: Vec::new(),
        }
    }

    /// Remove these exact credential indirections from every hook process. Hook commands are
    /// operator-authored, but they do not need provider or pricing signing keys.
    pub fn set_sensitive_env_names(&mut self, mut names: Vec<String>) {
        names.sort();
        names.dedup();
        self.sensitive_env_names = names;
    }

    pub fn is_empty(&self) -> bool {
        self.by_event.values().all(|v| v.is_empty())
    }

    /// True when no command is bound to this exact lifecycle event.
    ///
    /// The whole-map [`Self::is_empty`] is the wrong question at a dispatch site: it answers "does
    /// this operator use hooks at all", and a dispatch site needs "does anything actually run
    /// here". Asking the coarse question made one configured `Stop` hook route every `PreToolUse`
    /// and `PostToolUse` through the effect broker — an intent append, a terminal append and their
    /// fsyncs per tool call — to invoke nothing.
    pub fn is_empty_for(&self, event: HookEvent) -> bool {
        self.commands(event).is_empty()
    }

    /// The commands bound to exactly one lifecycle event. `pub(crate)` because the kernel's
    /// early-dispatch decision is about `PreToolUse` alone: asking "is anything configured?" made a
    /// single `Stop` cleanup hook cost the whole session its concurrent reads.
    pub(crate) fn commands(&self, event: HookEvent) -> &[String] {
        self.by_event
            .get(event.key())
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Run every command bound to `event`, passing `context_json` on stdin. For `PreToolUse` the
    /// FIRST command that exits 2 DENIES the tool (its bounded stderr is the reason). All other
    /// events are observational (the exit code is ignored). Bounded by the per-hook timeout.
    pub async fn run(&self, event: HookEvent, context_json: &str) -> HookDecision {
        for cmd in self.commands(event) {
            let out = run_one(
                cmd,
                context_json,
                self.timeout_secs,
                &self.sensitive_env_names,
            )
            .await;
            // DENY convention (matches the leading agent): ONLY exit code 2 blocks. exit 0 allows;
            // any OTHER non-zero (1, 127 from a typo'd command, a spawn error, a timeout) is a hook
            // ERROR, treated as "no opinion" -> allow. This makes a misconfigured hook fail SAFE
            // (it does not wedge every tool), while a deliberate `exit 2` is respected.
            if event == HookEvent::PreToolUse
                && let Some(out) = out
                && out.code == 2
            {
                return HookDecision::Deny(if out.stderr.trim().is_empty() {
                    "blocked by a PreToolUse hook (exit 2)".to_string()
                } else {
                    out.stderr.trim().to_string()
                });
            }
        }
        HookDecision::Allow
    }
}

#[derive(Debug)]
struct HookRunOutput {
    code: i32,
    // stdout remains observational, but retaining its bounded rendering makes the capture contract
    // testable and leaves room for future diagnostics without reintroducing `wait_with_output`.
    #[allow(dead_code)]
    stdout: String,
    stderr: String,
}

/// Fixed-memory head/tail capture. Bytes between the two windows are drained and counted but never
/// retained, so a hook can flood either pipe without growing the parent process.
#[derive(Debug, Default)]
struct BoundedCapture {
    head: Vec<u8>,
    tail: VecDeque<u8>,
    total: u64,
}

impl BoundedCapture {
    fn push(&mut self, bytes: &[u8]) {
        self.total = self.total.saturating_add(bytes.len() as u64);

        let head_bytes = bytes
            .len()
            .min(HOOK_CAPTURE_HEAD_BYTES.saturating_sub(self.head.len()));
        self.head.extend_from_slice(&bytes[..head_bytes]);
        let remainder = &bytes[head_bytes..];
        if remainder.len() >= HOOK_CAPTURE_TAIL_BYTES {
            self.tail.clear();
            self.tail
                .extend(&remainder[remainder.len() - HOOK_CAPTURE_TAIL_BYTES..]);
            return;
        }

        let overflow = self
            .tail
            .len()
            .saturating_add(remainder.len())
            .saturating_sub(HOOK_CAPTURE_TAIL_BYTES);
        if overflow > 0 {
            self.tail.drain(..overflow);
        }
        self.tail.extend(remainder);
    }

    fn into_marked_string(self, stream: &str) -> String {
        let retained = self.head.len().saturating_add(self.tail.len()) as u64;
        let omitted = self.total.saturating_sub(retained);

        let (mut rendered, invalid_utf8) = if omitted == 0 {
            let mut bytes = self.head;
            bytes.extend(self.tail);
            decode_lossy(bytes)
        } else {
            let (head, head_invalid) = decode_lossy(self.head);
            let (tail, tail_invalid) = decode_lossy(self.tail.into_iter().collect());
            (
                format!(
                    "{head}\n[... hook {stream} truncated: {omitted} bytes omitted ...]\n{tail}"
                ),
                head_invalid || tail_invalid,
            )
        };

        if invalid_utf8 {
            rendered.insert_str(
                0,
                &format!("[hook {stream} contained invalid UTF-8; invalid bytes replaced]\n"),
            );
        }
        rendered
    }
}

fn decode_lossy(bytes: Vec<u8>) -> (String, bool) {
    match String::from_utf8(bytes) {
        Ok(text) => (text, false),
        Err(error) => (String::from_utf8_lossy(error.as_bytes()).into_owned(), true),
    }
}

async fn capture_pipe<R>(mut reader: R) -> std::io::Result<BoundedCapture>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut capture = BoundedCapture::default();
    let mut chunk = [0u8; HOOK_READ_CHUNK_BYTES];
    // This loop's memory is fixed by `BoundedCapture`; its wall-clock lifetime is bounded by the
    // outer per-hook timeout, which cancels the read and then kills/reaps the producer.
    loop {
        let read = reader.read(&mut chunk).await?;
        if read == 0 {
            return Ok(capture);
        }
        capture.push(&chunk[..read]);
    }
}

/// Run one hook command with `ctx` on stdin, bounded by `timeout_secs`. Returns its exit and
/// bounded, marked output if it ran to completion; spawn/read/wait errors and timeouts are no
/// opinion, preserving the existing fail-open hook semantics.
async fn run_one(
    cmd: &str,
    ctx: &str,
    timeout_secs: u64,
    sensitive_env_names: &[String],
) -> Option<HookRunOutput> {
    run_one_with_sensitive_env_names(
        cmd,
        ctx,
        Duration::from_secs(timeout_secs),
        sensitive_env_names,
    )
    .await
}

#[cfg(test)]
async fn run_one_with_timeout(cmd: &str, ctx: &str, timeout: Duration) -> Option<HookRunOutput> {
    run_one_with_sensitive_env_names(cmd, ctx, timeout, &[]).await
}

async fn run_one_with_sensitive_env_names(
    cmd: &str,
    ctx: &str,
    timeout: Duration,
    sensitive_env_names: &[String],
) -> Option<HookRunOutput> {
    use tokio::io::AsyncWriteExt;

    let mut command = tokio::process::Command::new("/bin/bash");
    core_sandbox::clear_to_safe_child_env_with_exact(&mut command, sensitive_env_names);
    core_sandbox::configure_process_group(&mut command);
    let mut child = command
        .arg("-c")
        .arg(cmd)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .ok()?;

    let Some(mut stdin) = child.stdin.take() else {
        terminate_and_reap(&mut child).await;
        return None;
    };
    let Some(stdout) = child.stdout.take() else {
        terminate_and_reap(&mut child).await;
        return None;
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_and_reap(&mut child).await;
        return None;
    };

    // Stdin, stdout and stderr progress concurrently. Unlike `wait_with_output`, both readers
    // continuously drain their pipes while retaining a fixed-size head/tail only.
    let work = async {
        let writer = async move {
            let _ = stdin.write_all(ctx.as_bytes()).await;
            // `stdin` drops with this future, closing the pipe so hooks reading to EOF proceed.
        };
        let ((), stdout, stderr, status) = tokio::join!(
            writer,
            capture_pipe(stdout),
            capture_pipe(stderr),
            child.wait()
        );
        let stdout = stdout.ok()?.into_marked_string("stdout");
        let stderr = stderr.ok()?.into_marked_string("stderr");
        Some(HookRunOutput {
            code: status.ok()?.code().unwrap_or(-1),
            stdout,
            stderr,
        })
    };

    match tokio::time::timeout(timeout, work).await {
        Ok(output) => output,
        Err(_) => {
            // Do not rely on `kill_on_drop`: a timed-out hook is explicitly killed and waited so
            // the direct child cannot survive the decision or remain as a zombie.
            terminate_and_reap(&mut child).await;
            None
        }
    }
}

async fn terminate_and_reap(child: &mut tokio::process::Child) {
    core_sandbox::terminate_process_group_and_reap(child).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("core-hooks-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(d.join(".core")).unwrap();
        d
    }

    #[tokio::test]
    async fn pretooluse_hook_can_deny_a_tool() {
        let home = tmp("deny");
        std::fs::write(
            home.join(".core").join("config.json"),
            r#"{"hooks":{"PreToolUse":["grep -q secret && echo 'no secrets' >&2 && exit 2 || exit 0"]}}"#,
        )
        .unwrap();
        let hooks = Hooks::load_user(&home);
        assert!(!hooks.is_empty());
        // context mentions "secret" -> the hook exits non-zero -> deny
        let d = hooks
            .run(
                HookEvent::PreToolUse,
                r#"{"tool":"edit","input":{"path":"secret.rs"}}"#,
            )
            .await;
        assert!(
            matches!(d, HookDecision::Deny(_)),
            "hook should deny: {d:?}"
        );
        // context without the trigger -> allow
        let d2 = hooks
            .run(
                HookEvent::PreToolUse,
                r#"{"tool":"edit","input":{"path":"main.rs"}}"#,
            )
            .await;
        assert_eq!(d2, HookDecision::Allow);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[tokio::test]
    async fn a_broken_hook_does_not_wedge_allows() {
        let home = tmp("broken");
        std::fs::write(
            home.join(".core").join("config.json"),
            r#"{"hooks":{"PreToolUse":["/nonexistent/command/xyz"]}}"#,
        )
        .unwrap();
        let hooks = Hooks::load_user(&home);
        // the command cannot spawn -> "no opinion" -> allow (a broken hook must not brick the agent)
        assert_eq!(
            hooks.run(HookEvent::PreToolUse, "{}").await,
            HookDecision::Allow
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[tokio::test]
    async fn hook_child_gets_toolchain_env_but_no_exact_pricing_credential() {
        unsafe {
            std::env::set_var(
                "CORE_TEST_PRICING_KEY",
                "hook-pricing-sentinel-must-not-cross",
            );
            std::env::set_var("XDG_CONFIG_HOME", "hook-allowlist-sentinel-must-not-cross");
        }
        let sensitive = vec!["CORE_TEST_PRICING_KEY".into(), "XDG_CONFIG_HOME".into()];
        let output = run_one_with_sensitive_env_names(
            "test -z \"${CORE_TEST_PRICING_KEY+x}\" && test -z \"${XDG_CONFIG_HOME+x}\" && command -v sh >/dev/null",
            "",
            Duration::from_secs(2),
            &sensitive,
        )
        .await
        .expect("hook should run");
        unsafe {
            std::env::remove_var("CORE_TEST_PRICING_KEY");
            std::env::remove_var("XDG_CONFIG_HOME");
        }
        assert_eq!(output.code, 0);
        assert!(!output.stdout.contains("sentinel"));
        assert!(!output.stderr.contains("sentinel"));
    }

    #[test]
    fn no_user_config_means_no_hooks() {
        let home = tmp("empty");
        assert!(Hooks::load_user(&home).is_empty());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[tokio::test]
    async fn stdout_and_stderr_floods_are_drained_with_bounded_marked_capture() {
        let command = concat!(
            "i=0; while [ \"$i\" -lt 12000 ]; do ",
            "printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\\n'; ",
            "printf 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\\n' >&2; ",
            "i=$((i + 1)); done; ",
            "printf 'stdout-tail-marker'; printf 'stderr-tail-marker' >&2; exit 2"
        );
        let output = run_one_with_timeout(command, "", Duration::from_secs(10))
            .await
            .expect("flooding hook should complete while both pipes are drained");

        assert_eq!(output.code, 2);
        assert!(output.stdout.contains("hook stdout truncated"));
        assert!(output.stderr.contains("hook stderr truncated"));
        assert!(output.stdout.contains("stdout-tail-marker"));
        assert!(output.stderr.contains("stderr-tail-marker"));
        let rendered_ceiling = HOOK_CAPTURE_HEAD_BYTES + HOOK_CAPTURE_TAIL_BYTES + 512;
        assert!(output.stdout.len() <= rendered_ceiling);
        assert!(output.stderr.len() <= rendered_ceiling);
    }

    #[test]
    fn invalid_utf8_is_lossy_with_an_explicit_marker() {
        let mut capture = BoundedCapture::default();
        capture.push(b"before\xffafter");
        let rendered = capture.into_marked_string("stderr");
        assert!(rendered.contains("invalid UTF-8; invalid bytes replaced"));
        assert!(rendered.contains('\u{fffd}'));
    }

    #[cfg(unix)]
    fn process_exists(pid: u32) -> bool {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    #[cfg(unix)]
    fn shell_quote(path: &Path) -> String {
        format!("'{}'", path.to_string_lossy().replace('\'', "'\"'\"'"))
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_explicitly_kills_and_reaps_hook() {
        let pid_path = std::env::temp_dir().join(format!(
            "core-hook-timeout-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let command = format!("echo $$ > {}; exec sleep 60", shell_quote(&pid_path));
        let output = run_one_with_timeout(&command, "", Duration::from_millis(500)).await;
        assert!(output.is_none(), "timed-out hook must have no opinion");

        let pid: u32 = std::fs::read_to_string(&pid_path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(!process_exists(pid), "timed-out hook {pid} was not reaped");
        let _ = std::fs::remove_file(pid_path);
    }
}
