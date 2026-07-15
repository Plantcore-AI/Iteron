//! core-sandbox — capability confinement.
//!
//! A sandbox confines capability, never judgment (`docs/intake/sandbox-and-security.md`). Its
//! job here is ADR-007: run repo-controlled code (bash/build/test) with **egress OFF by default**
//! and writes confined to the workspace, so the child cannot directly send data over the network
//! or overwrite arbitrary host files. It does not govern data a caller later relays to a provider.
//!
//! Backends:
//!   - **macOS Seatbelt** (`sandbox-exec` + an SBPL profile): implemented. Denies network by
//!     default, allowlists the workspace, system runtime/toolchain roots, and explicit user
//!     toolchain/cache roots, and confines writes to the workspace + temp. It is still not a
//!     complete taint or information-flow system, but it does not grant ambient HOME reads.
//!   - **Linux** (Landlock + seccomp + namespaces / bwrap): designed, returns a clear
//!     "unsupported on this build" so nothing silently runs UNconfined. Deny-by-default means
//!     the absence of a backend is a refusal, not a fallthrough.
//!
//! `egress` is a capability the caller must explicitly request, and granting it is an operator
//! decision recorded above this crate (ADR-007 §2: network tests are a separate, gated escalation).

use std::path::PathBuf;
use tokio::io::{AsyncRead, AsyncReadExt};

pub mod bubblewrap;
pub mod seatbelt;

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error(
        "sandbox unsupported on this platform build; refusing to run code UNconfined (ADR-007)"
    )]
    Unsupported,
    #[error("sandbox spawn: {0}")]
    Spawn(String),
    #[error("profile: {0}")]
    Profile(String),
}

/// What a confined command is allowed to do. Deny-by-default: everything not granted is denied.
#[derive(Debug, Clone)]
pub struct Confinement {
    /// The workspace root; writes are confined here (+ temp).
    pub workspace: PathBuf,
    /// Whether the command may reach the network. OFF by default (ADR-007 R13). Turning it on
    /// is an explicit, recorded operator escalation, not a default.
    pub allow_egress: bool,
    /// Wall-clock ceiling (bounded invariant #1).
    pub timeout_secs: u64,
    /// Maximum source bytes retained from EACH of stdout and stderr. Both pipes are still drained
    /// to EOF after this limit so a noisy child cannot deadlock on a full pipe. The total retained
    /// payload is therefore at most twice this value, plus fixed per-stream truncation markers.
    pub max_output_bytes: usize,
    /// Exact credential-variable names supplied by the trusted provider directory. Heuristic
    /// secret detection intentionally remains a second layer; custom names such as `GATEWAY_KEY`
    /// must also be removed from model-driven child processes.
    pub sensitive_env_names: Vec<String>,
}

impl Confinement {
    pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 256 * 1024;

    /// The default posture for running repo code: no egress, writes confined to the workspace.
    pub fn egress_off(workspace: impl Into<PathBuf>) -> Self {
        Confinement {
            workspace: workspace.into(),
            allow_egress: false,
            timeout_secs: 120,
            max_output_bytes: Self::DEFAULT_MAX_OUTPUT_BYTES,
            sensitive_env_names: Vec::new(),
        }
    }
}

/// The result of a confined run.
#[derive(Debug, Clone)]
pub struct RunOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    /// True when stdout exceeded `Confinement::max_output_bytes`. `stdout` also ends with a fixed
    /// human-readable marker so callers that predate this field cannot silently miss truncation.
    pub stdout_truncated: bool,
    /// True when stderr exceeded `Confinement::max_output_bytes`; see `stdout_truncated`.
    pub stderr_truncated: bool,
    pub timed_out: bool,
}

const POST_KILL_DRAIN_SECS: u64 = 1;

#[derive(Default)]
struct BoundedCapture {
    bytes: Vec<u8>,
    truncated: bool,
}

impl BoundedCapture {
    fn with_limit(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit.min(8 * 1024)),
            truncated: false,
        }
    }

    fn push(&mut self, chunk: &[u8], limit: usize) {
        let remaining = limit.saturating_sub(self.bytes.len());
        let keep = remaining.min(chunk.len());
        self.bytes.extend_from_slice(&chunk[..keep]);
        self.truncated |= keep < chunk.len();
    }

    fn finish(self, stream: &str, limit: usize) -> (String, bool) {
        // If the byte ceiling split a final UTF-8 scalar, discard only that incomplete tail. For
        // genuinely invalid interior bytes, preserve a readable representation lossily.
        let mut text = match std::str::from_utf8(&self.bytes) {
            Ok(valid) => valid.to_owned(),
            Err(error) if error.error_len().is_none() => {
                String::from_utf8_lossy(&self.bytes[..error.valid_up_to()]).into_owned()
            }
            Err(_) => String::from_utf8_lossy(&self.bytes).into_owned(),
        };
        if self.truncated {
            text.push_str(&format!(
                "\n[{stream} truncated after {limit} bytes; remaining output was drained]\n"
            ));
        }
        (text, self.truncated)
    }
}

/// Drain one pipe completely while retaining at most `limit` source bytes. Reaching the memory
/// ceiling never stops reads: continuing to drain is what prevents stdout/stderr pipe deadlocks.
async fn drain_bounded<R: AsyncRead + Unpin>(
    reader: &mut R,
    capture: &mut BoundedCapture,
    limit: usize,
) -> std::io::Result<()> {
    let mut chunk = [0_u8; 8 * 1024];
    loop {
        let read = reader.read(&mut chunk).await?;
        if read == 0 {
            return Ok(());
        }
        capture.push(&chunk[..read], limit);
    }
}

/// Put the backend process in its own group so a timeout can terminate ordinary descendants, not
/// just the shell. Bubblewrap additionally uses `--die-with-parent`; Seatbelt descendants inherit
/// this group. `kill_on_drop` remains the final fallback.
pub fn configure_process_group(command: &mut tokio::process::Command) {
    #[cfg(unix)]
    command.process_group(0);
}

#[cfg(unix)]
fn kill_process_group(pid: Option<u32>) {
    if let Some(pid) = pid.and_then(|pid| i32::try_from(pid).ok()) {
        // SAFETY: the child was spawned with process_group(0), so `-pid` addresses the child's
        // group and cannot target the harness's own process group.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
}

#[cfg(not(unix))]
fn kill_process_group(_pid: Option<u32>) {}

/// Kill the entire child process group and reap the direct child. Helper processes such as hooks
/// and stdio MCP servers must not leave daemonized descendants after timeout/drop.
pub async fn terminate_process_group_and_reap(child: &mut tokio::process::Child) {
    kill_process_group(child.id());
    let _ = child.start_kill();
    let _ = child.wait().await;
}

/// Shared child collector for Seatbelt and bubblewrap. stdout and stderr are drained concurrently
/// for the entire run. On timeout we kill the process group, explicitly kill/wait the direct child,
/// then give the now-closed pipes a short bounded window to flush already-written bytes.
pub(crate) async fn collect_child_output(
    mut child: tokio::process::Child,
    mut stdout: tokio::process::ChildStdout,
    mut stderr: tokio::process::ChildStderr,
    conf: &Confinement,
) -> Result<RunOutput, SandboxError> {
    let mut out = BoundedCapture::with_limit(conf.max_output_bytes);
    let mut err = BoundedCapture::with_limit(conf.max_output_bytes);
    let child_group = child.id();

    let completed =
        tokio::time::timeout(std::time::Duration::from_secs(conf.timeout_secs), async {
            let (stdout_result, stderr_result, wait_result) = tokio::join!(
                drain_bounded(&mut stdout, &mut out, conf.max_output_bytes),
                drain_bounded(&mut stderr, &mut err, conf.max_output_bytes),
                child.wait(),
            );
            stdout_result.map_err(|e| SandboxError::Spawn(format!("read stdout: {e}")))?;
            stderr_result.map_err(|e| SandboxError::Spawn(format!("read stderr: {e}")))?;
            wait_result.map_err(|e| SandboxError::Spawn(format!("wait: {e}")))
        })
        .await;

    let (timed_out, status) = match completed {
        Ok(status) => (false, Some(status?)),
        Err(_) => {
            kill_process_group(child_group);
            let _ = child.start_kill();
            let status = child.wait().await.ok();
            // The first drain futures were cancelled with the timeout, but their captures live
            // outside it. Resume both drains concurrently to retain buffered tail bytes and close
            // the pipes. This cleanup itself is bounded in case a hostile daemon escaped the group.
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(POST_KILL_DRAIN_SECS),
                async {
                    let _ = tokio::join!(
                        drain_bounded(&mut stdout, &mut out, conf.max_output_bytes),
                        drain_bounded(&mut stderr, &mut err, conf.max_output_bytes),
                    );
                },
            )
            .await;
            (true, status)
        }
    };

    let (stdout, stdout_truncated) = out.finish("stdout", conf.max_output_bytes);
    let (stderr, stderr_truncated) = err.finish("stderr", conf.max_output_bytes);
    Ok(RunOutput {
        exit_code: status.and_then(|status| status.code()).unwrap_or(-1),
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        timed_out,
    })
}

#[cfg(test)]
mod output_tests {
    use super::*;
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn huge_single_line_is_fully_drained_but_memory_retention_is_bounded() {
        let limit = 4 * 1024;
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        let producer = tokio::spawn(async move {
            let flood = vec![b'x'; 1024 * 1024];
            writer.write_all(&flood).await.unwrap();
        });
        let mut capture = BoundedCapture::with_limit(limit);
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            drain_bounded(&mut reader, &mut capture, limit),
        )
        .await
        .expect("reader must continue draining after the retention ceiling")
        .unwrap();
        producer.await.unwrap();

        let (text, truncated) = capture.finish("stdout", limit);
        assert!(truncated);
        assert_eq!(text.matches('x').count(), limit);
        assert!(text.ends_with("remaining output was drained]\n"));
        assert!(
            text.len() <= limit + 96,
            "only the bounded payload plus a fixed marker is retained"
        );
    }

    #[tokio::test]
    async fn utf8_scalar_split_at_the_byte_ceiling_is_safe() {
        let bytes = b"abc\xF0\x9F\x98\x80tail"; // `abc`, then a four-byte emoji.
        let mut reader = &bytes[..];
        let mut capture = BoundedCapture::with_limit(5); // retain only the first two emoji bytes
        drain_bounded(&mut reader, &mut capture, 5).await.unwrap();
        let (text, truncated) = capture.finish("stdout", 5);

        assert!(truncated);
        assert!(text.starts_with("abc\n[stdout truncated"));
        assert!(
            !text.contains('\u{FFFD}'),
            "an incomplete boundary scalar is dropped, not corrupted"
        );
    }

    #[cfg(unix)]
    fn piped_grouped_bash(script: &str) -> tokio::process::Child {
        let mut command = tokio::process::Command::new("bash");
        command
            .arg("-lc")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        configure_process_group(&mut command);
        command.spawn().unwrap()
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn simultaneous_stdout_and_stderr_floods_are_bounded_without_deadlock() {
        let mut child =
            piped_grouped_bash("(yes O | head -c 1048576) & (yes E | head -c 1048576 >&2) & wait");
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let mut conf = Confinement::egress_off(std::env::temp_dir());
        conf.timeout_secs = 5;
        conf.max_output_bytes = 8 * 1024;

        let output = collect_child_output(child, stdout, stderr, &conf)
            .await
            .unwrap();

        assert!(
            !output.timed_out,
            "finite dual-stream flood must drain to completion"
        );
        assert!(output.stdout_truncated);
        assert!(output.stderr_truncated);
        assert!(output.stdout.contains("[stdout truncated after 8192 bytes"));
        assert!(output.stderr.contains("[stderr truncated after 8192 bytes"));
        assert!(output.stdout.len() <= conf.max_output_bytes + 96);
        assert!(output.stderr.len() <= conf.max_output_bytes + 96);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_kills_descendants_waits_and_preserves_partial_output() {
        let pid = std::process::id();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("core-output-timeout-{pid}-{nonce:x}"));
        std::fs::create_dir_all(&root).unwrap();
        let marker = root.join("escaped-descendant");

        let mut command = tokio::process::Command::new("bash");
        command
            .arg("-c")
            .arg("(sleep 2; printf leaked > \"$1\") & echo child-started; wait")
            .arg("sandbox-timeout-test")
            .arg(&marker)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        configure_process_group(&mut command);
        let mut child = command.spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let mut conf = Confinement::egress_off(&root);
        conf.timeout_secs = 1;
        conf.max_output_bytes = 1024;

        let output = collect_child_output(child, stdout, stderr, &conf)
            .await
            .unwrap();
        assert!(output.timed_out);
        assert!(
            output.stdout.contains("child-started"),
            "bytes read before timeout must be retained"
        );

        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        assert!(
            !marker.exists(),
            "the background descendant must die with the timed-out group"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}

/// A sandbox backend that can run a shell command under a confinement.
#[async_trait::async_trait]
pub trait Sandbox: Send + Sync {
    async fn run(&self, command: &str, conf: &Confinement) -> Result<RunOutput, SandboxError>;
}

/// Pick the best backend for this platform. Deny-by-default: on an unsupported platform this
/// returns a backend whose `run` refuses, so `--allow-code` cannot silently run UNconfined.
pub fn platform_sandbox() -> Box<dyn Sandbox> {
    #[cfg(target_os = "macos")]
    {
        Box::new(seatbelt::Seatbelt::new())
    }
    #[cfg(target_os = "linux")]
    {
        // bwrap on Linux; if it is not installed we refuse (deny-by-default), never run
        // code unconfined — the Bubblewrap backend's own run() returns Unsupported when bwrap
        // is absent, so it is safe to select here.
        Box::new(bubblewrap::Bubblewrap::new())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Box::new(Unsupported)
    }
}

/// True if an environment variable name looks like it holds a credential. Case-insensitive
/// substring/prefix match over the common secret shapes.
pub fn is_secret_env_key(key: &str) -> bool {
    let k = key.to_ascii_uppercase();
    [
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "PASSWD",
        "CREDENTIAL",
        "API_KEY",
        "APIKEY",
        "ACCESS_KEY",
        "PRIVATE_KEY",
        "SESSION_KEY",
        "AUTH",
    ]
    .iter()
    .any(|p| k.contains(p))
        || [
            "AWS_",
            "AZURE_",
            "GCP_",
            "GOOGLE_",
            "GH_",
            "GITHUB_",
            "NPM_",
            "SLACK_",
            "STRIPE_",
            "OPENAI_",
            "ANTHROPIC_",
        ]
        .iter()
        .any(|p| k.starts_with(p))
}

/// Confine the child's ENVIRONMENT: inherit the parent's env (so the operator's real toolchain —
/// PATH, HOME, venvs, PYTHONPATH, cargo/node/go homes — resolves and their build/test commands
/// actually run) but REMOVE every secret-shaped variable (ANTHROPIC_API_KEY, *_TOKEN, AWS_*, …).
///
/// Rationale (fix-verification / live-e2e review): the earlier `env_clear` + `HOME=/tmp` made the
/// sandbox unusable for real projects (Python's user site-packages, venvs, and toolchains all live
/// under the real HOME). EGRESS-OFF blocks the confined child's direct network access, while the
/// Seatbelt profile separately denies common credential paths. Neither mechanism proves that
/// arbitrary output later relayed by the harness is untainted. Stripping secret-shaped environment
/// keys adds another narrow layer while preserving the toolchain. Pager/progress vars are set
/// additively by the caller after this.
pub fn confine_env(cmd: &mut tokio::process::Command) {
    confine_env_with_exact(cmd, &[]);
}

pub fn confine_env_with_exact(cmd: &mut tokio::process::Command, exact: &[String]) {
    for (k, _) in std::env::vars() {
        if is_secret_env_key(&k) || exact.iter().any(|name| name == &k) {
            cmd.env_remove(&k);
        }
    }
}

/// Default-deny environment for trusted-config helper processes (MCP servers and hooks). These
/// helpers may need the operator's executable/toolchain paths, locale, and HOME-based package
/// caches, but receive no ambient application/provider credentials. A future broker can add an
/// explicit per-helper secret grant; inheriting every variable is never that grant.
pub fn clear_to_safe_child_env(cmd: &mut tokio::process::Command) {
    const EXACT: &[&str] = &[
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "TMPDIR",
        "LANG",
        "TERM",
        "COLORTERM",
        "CARGO_HOME",
        "RUSTUP_HOME",
        "NVM_DIR",
        "PYENV_ROOT",
        "VIRTUAL_ENV",
        "GOPATH",
        "GOROOT",
        "JAVA_HOME",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
    ];
    let retained: Vec<_> = std::env::vars_os()
        .filter(|(key, _)| {
            let Some(key) = key.to_str() else {
                return false;
            };
            !is_secret_env_key(key) && (EXACT.contains(&key) || key.starts_with("LC_"))
        })
        .collect();
    cmd.env_clear();
    cmd.envs(retained);
}

/// A backend that refuses (Linux until Landlock/seccomp/bwrap is wired). Refusal, not fallthrough.
pub struct Unsupported;

#[async_trait::async_trait]
impl Sandbox for Unsupported {
    async fn run(&self, _command: &str, _conf: &Confinement) -> Result<RunOutput, SandboxError> {
        Err(SandboxError::Unsupported)
    }
}

#[cfg(test)]
mod env_tests {
    use super::is_secret_env_key;

    #[test]
    fn secret_shapes_are_detected_toolchain_vars_are_not() {
        for k in [
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN",
            "MY_PASSWORD",
            "DB_CREDENTIAL",
            "SLACK_BOT_TOKEN",
            "x_private_key",
        ] {
            assert!(is_secret_env_key(k), "{k} must be treated as secret");
        }
        // toolchain / dev vars must be preserved (not flagged secret)
        for k in [
            "PATH",
            "HOME",
            "LANG",
            "PYTHONPATH",
            "VIRTUAL_ENV",
            "CARGO_HOME",
            "NVM_DIR",
            "TERM",
            "PWD",
        ] {
            assert!(
                !is_secret_env_key(k),
                "{k} must NOT be treated as secret (toolchain needs it)"
            );
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod seatbelt_env_tests {
    use super::*;

    #[tokio::test]
    async fn sandbox_strips_secrets_but_keeps_home_and_path() {
        // A secret in the parent env must NOT reach the sandbox; HOME/PATH must (so the toolchain
        // resolves). This is the live posture the e2e review corrected.
        // SAFETY: single-threaded test setter for a process-global; scoped to this test.
        unsafe {
            std::env::set_var("ANTHROPIC_API_KEY", "sk-ant-should-not-leak");
            std::env::set_var("GATEWAY_KEY", "custom-should-not-leak");
        }
        let dir = std::env::temp_dir();
        let sb = seatbelt::Seatbelt::new();
        let mut conf = Confinement::egress_off(&dir);
        conf.sensitive_env_names.push("GATEWAY_KEY".into());
        let out = sb
            .run(
                "echo home=$HOME; echo key=[${ANTHROPIC_API_KEY:-EMPTY}]; echo custom=[${GATEWAY_KEY:-EMPTY}]; echo path=$PATH",
                &conf,
            )
            .await
            .unwrap();
        assert!(
            out.stdout.contains("key=[EMPTY]"),
            "the secret must be stripped: {}",
            out.stdout
        );
        assert!(
            !out.stdout.contains("should-not-leak"),
            "the secret value must not appear"
        );
        assert!(out.stdout.contains("custom=[EMPTY]"));
        assert!(
            out.stdout.contains("home=/") && !out.stdout.contains("home=/tmp\n"),
            "real HOME preserved: {}",
            out.stdout
        );
        assert!(out.stdout.contains("path=/"), "PATH preserved");
        unsafe {
            std::env::remove_var("ANTHROPIC_API_KEY");
            std::env::remove_var("GATEWAY_KEY");
        }
    }
}
