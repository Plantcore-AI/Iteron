//! iteron-sandbox — capability confinement.
//!
//! A sandbox confines capability, never judgment (`docs/intake/sandbox-and-security.md`). Its
//! job here is ADR-007: run repo-controlled code (bash/build/test) with writes confined to the
//! workspace and egress denied, so the child cannot directly send data over the network or
//! overwrite arbitrary host files. It does not govern data a caller later relays to a provider.
//!
//! **The default posture is no longer confinement (owner-directed, 2026-08-05).** A confinement
//! now carries an explicit `unconfined` bit, and the harness constructs it set: `bash` runs with
//! the operator's own authority, reaching the whole filesystem and the network. The confined
//! posture below is fully retained, exercised by the same tests it always was, and selected by
//! `--confine`; it is a choice the operator makes, not a floor the crate imposes. Read
//! `Confinement::unconfined` for what that surrenders.
//!
//! Backends (used only when the confinement is NOT `unconfined`):
//!   - **macOS Seatbelt** (`sandbox-exec` + an SBPL profile): implemented. Denies network by
//!     default, allowlists the workspace, system runtime/toolchain roots, and explicit user
//!     toolchain/cache roots, and confines writes to the workspace + a capability-private scratch
//!     directory. It is still not a complete taint or information-flow system, but it does not
//!     grant ambient HOME reads.
//!   - **Linux** (bubblewrap mount/PID/network namespaces): implemented when a trusted system
//!     `bwrap` can create the required namespaces; otherwise it refuses closed. Seccomp and
//!     Landlock defense-in-depth are not implemented yet and must not be inferred from this API.
//!
//! `egress` is a capability the caller must explicitly request, and granting it is an operator
//! decision recorded above this crate (ADR-007 §2: network tests are a separate, gated escalation).

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::{Notify, mpsc, watch};

pub mod bubblewrap;
mod persistent;
/// Pseudo-terminal transport for confined children. Unix-only: the whole module is `libc` ioctls,
/// and the Windows equivalent is ConPTY (`CreatePseudoConsole`), a different API with different
/// lifetime rules rather than a port of this one.
#[cfg(unix)]
pub mod pty;
#[cfg(unix)]
mod pty_async;
pub mod seatbelt;

pub use persistent::{
    ConfinedProcess, ConfinedProcessControl, PersistentBackend, spawn_confined_process,
    spawn_confined_process_from_workspace,
};
#[cfg(unix)]
pub use persistent_pty::{
    ConfinedPtyInput, ConfinedPtyOutput, ConfinedPtyProcess, ConfinedPtyResize,
    spawn_confined_pty_process,
};

#[cfg(unix)]
mod persistent_pty;

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error(
        "sandbox unsupported on this platform build; refusing to run code UNconfined (ADR-007). \
         Linux needs the `bubblewrap` package (a root-owned /usr/bin/bwrap) AND permission to \
         create unprivileged user namespaces; macOS needs /usr/bin/sandbox-exec. See \
         docs/reference/platforms.md for the exact remedy."
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
    /// A capability-private temporary directory. Backends expose this exact path (or an isolated
    /// in-namespace `/tmp`), never the host's ambient temp tree.
    pub scratch: PathBuf,
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
    /// Exact, session-pinned environment inherited by process tools. `None` preserves the legacy
    /// caller-owned ambient filtering used by ordinary shell execution; `Some` is immutable and
    /// always applied with `env_clear` before backend-specific presentation variables are added.
    pub child_environment: Option<Vec<(OsString, OsString)>>,
    /// Run with the operator's own authority: no `sandbox-exec`, no `bwrap`, no profile. Every
    /// other field except the ceilings and `sensitive_env_names` becomes inert, because there is
    /// no backend left to enforce them. This is the harness default (owner-directed, 2026-08-05).
    pub unconfined: bool,
    /// Optional bounded, content-carrying progress observer. It is deliberately private so a
    /// command can only install one through [`Confinement::with_output_observer`], which keeps
    /// the observer's identity/attempt metadata immutable for the whole child lifetime.
    output_observer: Option<OutputObserver>,
}

impl Confinement {
    pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 256 * 1024;
    /// Wall-clock ceiling for a confined run. A confined child is a build or a test step, so two
    /// minutes is the bound that catches a wedged child without failing ordinary work; the
    /// unconfined posture raises it deliberately (`UNCONFINED_TIMEOUT_SECS`).
    pub const DEFAULT_TIMEOUT_SECS: u64 = 120;
    /// Retained bytes per stream once the sandbox is not the thing bounding the run. A confined
    /// child is a build or a test; an unconfined one is routinely a full log the operator asked
    /// for, and truncating it at 256 KiB was the ceiling this change exists to remove.
    pub const UNCONFINED_MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
    /// One hour. Still a ceiling — invariant #1 does not have an off switch, and a wedged child
    /// with host authority is exactly the case that must not run forever — but no longer a number
    /// that a release build or a large test suite trips over.
    pub const UNCONFINED_TIMEOUT_SECS: u64 = 3_600;

    /// The confined posture for running repo code: no egress, writes confined to the workspace.
    /// Selected by `--confine`; see `unconfined` for what the harness does by default.
    pub fn egress_off(workspace: impl Into<PathBuf>) -> Self {
        Self::new(workspace, false)
    }

    /// The harness default: the child runs with the operator's own authority.
    ///
    /// This is not a widened sandbox, it is the absence of one. The child can read `~/.ssh`, write
    /// outside the workspace, and reach the network, because that is what the operator asked for
    /// when they chose this posture. Two things deliberately survive: the wall-clock and output
    /// ceilings (invariant #1 is a liveness property, not a security one), and the exact-name
    /// credential scrub, which is not a restriction on what the tool may DO — the operator can
    /// still read any file holding the same secret — and whose removal was not asked for.
    pub fn unconfined(workspace: impl Into<PathBuf>) -> Self {
        let mut conf = Self::new(workspace, true);
        conf.allow_egress = true;
        conf.timeout_secs = iteron_tunables::param_integer(
            "sandbox.lib.unconfined_timeout_secs",
            Self::UNCONFINED_TIMEOUT_SECS,
        );
        conf.max_output_bytes = iteron_tunables::param_integer(
            "sandbox.lib.unconfined_max_output_bytes",
            Self::UNCONFINED_MAX_OUTPUT_BYTES,
        );
        conf
    }

    fn new(workspace: impl Into<PathBuf>, unconfined: bool) -> Self {
        static NEXT_SCRATCH: AtomicU64 = AtomicU64::new(0);
        let serial = NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        Confinement {
            workspace: workspace.into(),
            scratch: std::env::temp_dir().join(format!(
                "iteron-sandbox-private-{}-{nanos:x}-{serial:x}",
                std::process::id()
            )),
            allow_egress: false,
            timeout_secs: iteron_tunables::param_integer(
                "sandbox.lib.default_timeout_secs",
                Self::DEFAULT_TIMEOUT_SECS,
            ),
            max_output_bytes: iteron_tunables::param_integer(
                "sandbox.lib.default_max_output_bytes",
                Self::DEFAULT_MAX_OUTPUT_BYTES,
            ),
            sensitive_env_names: Vec::new(),
            child_environment: None,
            unconfined,
            output_observer: None,
        }
    }

    /// Attach a non-blocking observer for verifier/process progress. The final [`RunOutput`]
    /// remains authoritative; observation backpressure can drop intermediate chunks but never
    /// turns into child-process backpressure.
    pub fn with_output_observer(mut self, observer: OutputObserver) -> Self {
        self.output_observer = Some(observer);
        self
    }
}

/// Which child pipe produced an observed output chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputStream {
    Stdout,
    Stderr,
}

/// One bounded verifier/process output delta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputChunk {
    pub command_identity: Arc<str>,
    pub attempt: u32,
    pub stream: OutputStream,
    pub bytes: Arc<[u8]>,
    pub retained_limit_bytes: usize,
    /// Chunks suppressed by cadence or receiver backpressure since the previous delivered chunk.
    pub dropped_chunks: u64,
}

/// Authoritative end state for an observed child. This travels on a watch channel separate from
/// the lossy chunk queue, so a full/slow progress consumer cannot hide termination or truncation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputTerminal {
    pub command_identity: Arc<str>,
    pub attempt: u32,
    pub exit_code: i32,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub timed_out: bool,
    pub cancelled: bool,
    pub reason: OutputTerminalReason,
    pub dropped_chunks: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputTerminalReason {
    Completed,
    TimedOut,
    Cancelled,
    IoFailure,
}

/// Items yielded by [`OutputObserverReceiver::recv`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputObservation {
    Chunk(OutputChunk),
    Terminal(OutputTerminal),
}

#[derive(Debug)]
struct OutputObserverInner {
    command_identity: Arc<str>,
    attempt: u32,
    chunk_tx: mpsc::Sender<OutputChunk>,
    terminal_tx: watch::Sender<Option<OutputTerminal>>,
    terminal_published: AtomicBool,
    dropped_chunks: AtomicU64,
    cancelled: AtomicBool,
    cancel_notify: Notify,
    last_emit: Mutex<[std::time::Instant; 2]>,
    cadence: std::time::Duration,
}

/// Cloneable control/observation handle for one process attempt.
///
/// The chunk queue is hard-bounded to 4..=256 entries, each item is at most 8 KiB, and emissions
/// are capped at 10 Hz per stream. Cancellation is an atomic notification consumed by the same
/// process collector that owns timeout/kill/reap, avoiding a second process-lifecycle model.
#[derive(Debug, Clone)]
pub struct OutputObserver {
    inner: Arc<OutputObserverInner>,
}

/// Single-consumer bounded output stream. Clone the [`OutputObserver`] control handle, not this
/// receiver; one renderer should own ordering and translate observations into UI activity.
pub struct OutputObserverReceiver {
    chunks: mpsc::Receiver<OutputChunk>,
    terminal: watch::Receiver<Option<OutputTerminal>>,
    terminal_delivered: bool,
}

impl OutputObserver {
    pub const MAX_CHUNK_BYTES: usize = 8 * 1024;
    pub const DEFAULT_QUEUE_CAPACITY: usize = 32;
    pub const DEFAULT_CADENCE_MS: u64 = 100;

    fn max_chunk_bytes() -> usize {
        iteron_tunables::param_usize(
            "sandbox.lib.max_chunk_bytes",
            iteron_tunables::param_integer("sandbox.lib.max_chunk_bytes", Self::MAX_CHUNK_BYTES),
        )
        .clamp(1, Self::MAX_CHUNK_BYTES)
    }

    fn default_queue_capacity() -> usize {
        iteron_tunables::param_usize(
            "sandbox.lib.default_queue_capacity",
            Self::DEFAULT_QUEUE_CAPACITY,
        )
        .clamp(4, 256)
    }

    fn default_cadence_ms() -> u64 {
        iteron_tunables::param_u64("sandbox.lib.default_cadence_ms", Self::DEFAULT_CADENCE_MS)
            .clamp(Self::DEFAULT_CADENCE_MS, 1_000)
    }

    /// Create one observer/receiver pair for a stable command identity and attempt number.
    pub fn bounded(
        command_identity: impl Into<Arc<str>>,
        attempt: u32,
        queue_capacity: usize,
    ) -> (Self, OutputObserverReceiver) {
        let queue_capacity = if queue_capacity == Self::DEFAULT_QUEUE_CAPACITY {
            Self::default_queue_capacity()
        } else {
            queue_capacity.clamp(4, 256)
        };
        let (chunk_tx, chunks) = mpsc::channel(queue_capacity);
        let (terminal_tx, terminal) = watch::channel(None);
        let cadence = std::time::Duration::from_millis(Self::default_cadence_ms());
        let initial = std::time::Instant::now()
            .checked_sub(cadence)
            .unwrap_or_else(std::time::Instant::now);
        let observer = Self {
            inner: Arc::new(OutputObserverInner {
                command_identity: command_identity.into(),
                attempt,
                chunk_tx,
                terminal_tx,
                terminal_published: AtomicBool::new(false),
                dropped_chunks: AtomicU64::new(0),
                cancelled: AtomicBool::new(false),
                cancel_notify: Notify::new(),
                last_emit: Mutex::new([initial; 2]),
                cadence,
            }),
        };
        (
            observer,
            OutputObserverReceiver {
                chunks,
                terminal,
                terminal_delivered: false,
            },
        )
    }

    /// Request cancellation of the observed command. The sandbox collector performs the same
    /// bounded TERM/KILL/reap sequence used for timeout, and reports `cancelled=true` terminally.
    pub fn cancel(&self) {
        if !self.inner.cancelled.swap(true, Ordering::AcqRel) {
            self.inner.cancel_notify.notify_waiters();
        }
    }

    fn try_chunk(&self, stream: OutputStream, bytes: &[u8], retained_limit_bytes: usize) {
        if bytes.is_empty() {
            return;
        }
        let stream_index = match stream {
            OutputStream::Stdout => 0,
            OutputStream::Stderr => 1,
        };
        let now = std::time::Instant::now();
        let mut last_emit = self
            .inner
            .last_emit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if now.duration_since(last_emit[stream_index]) < self.inner.cadence {
            self.inner.dropped_chunks.fetch_add(1, Ordering::Relaxed);
            return;
        }
        last_emit[stream_index] = now;
        drop(last_emit);

        let dropped = self.inner.dropped_chunks.swap(0, Ordering::AcqRel);
        let chunk = OutputChunk {
            command_identity: Arc::clone(&self.inner.command_identity),
            attempt: self.inner.attempt,
            stream,
            bytes: Arc::from(&bytes[..bytes.len().min(Self::max_chunk_bytes())]),
            retained_limit_bytes,
            dropped_chunks: dropped,
        };
        if self.inner.chunk_tx.try_send(chunk).is_err() {
            self.inner
                .dropped_chunks
                .fetch_add(dropped.saturating_add(1), Ordering::Relaxed);
        }
    }

    async fn cancelled(&self) {
        loop {
            if self.inner.cancelled.load(Ordering::Acquire) {
                return;
            }
            let notified = self.inner.cancel_notify.notified();
            if self.inner.cancelled.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }

    fn publish_terminal(&self, terminal: OutputTerminal) {
        if self
            .inner
            .terminal_published
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.inner.terminal_tx.send_replace(Some(terminal));
        }
    }

    fn finish(&self, output: &RunOutput, cancelled: bool) {
        let reason = if cancelled {
            OutputTerminalReason::Cancelled
        } else if output.timed_out {
            OutputTerminalReason::TimedOut
        } else {
            OutputTerminalReason::Completed
        };
        self.publish_terminal(OutputTerminal {
            command_identity: Arc::clone(&self.inner.command_identity),
            attempt: self.inner.attempt,
            exit_code: output.exit_code,
            stdout_truncated: output.stdout_truncated,
            stderr_truncated: output.stderr_truncated,
            timed_out: output.timed_out,
            cancelled,
            reason,
            dropped_chunks: self.inner.dropped_chunks.swap(0, Ordering::AcqRel),
        });
    }

    fn finish_io_failure(&self, stream: Option<OutputStream>, truncated: bool) {
        self.publish_terminal(OutputTerminal {
            command_identity: Arc::clone(&self.inner.command_identity),
            attempt: self.inner.attempt,
            exit_code: SIGNALLED_EXIT_CODE,
            stdout_truncated: stream == Some(OutputStream::Stdout) && truncated,
            stderr_truncated: stream == Some(OutputStream::Stderr) && truncated,
            timed_out: false,
            cancelled: false,
            reason: OutputTerminalReason::IoFailure,
            dropped_chunks: self.inner.dropped_chunks.swap(0, Ordering::AcqRel),
        });
    }
}

impl OutputObserverReceiver {
    /// Receive the next bounded chunk or the authoritative terminal state. Intermediate chunks
    /// may be suppressed; terminal delivery is independent of chunk-queue pressure.
    pub async fn recv(&mut self) -> Option<OutputObservation> {
        if self.terminal_delivered {
            return None;
        }
        match self.chunks.try_recv() {
            Ok(chunk) => return Some(OutputObservation::Chunk(chunk)),
            Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {}
        }
        if let Some(terminal) = self.terminal.borrow().clone() {
            self.terminal_delivered = true;
            return Some(OutputObservation::Terminal(terminal));
        }
        tokio::select! {
            biased;
            chunk = self.chunks.recv() => {
                match chunk {
                    Some(chunk) => Some(OutputObservation::Chunk(chunk)),
                    None => {
                        let terminal = self.terminal.borrow().clone();
                        self.terminal_delivered = terminal.is_some();
                        terminal.map(OutputObservation::Terminal)
                    }
                }
            }
            changed = self.terminal.changed() => {
                if changed.is_ok()
                    && let Some(terminal) = self.terminal.borrow().clone()
                {
                    self.terminal_delivered = true;
                    return Some(OutputObservation::Terminal(terminal));
                }
                None
            },
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
const TERMINATION_GRACE_MS: u64 = 50;
/// Poll interval of the blocking reap fallback. It runs on a thread with no runtime to yield to,
/// so the interval trades reap latency directly against spinning on `try_wait`.
const BLOCKING_REAP_POLL_MS: u64 = 10;
/// Exit code reported when the child left no wait-status code of its own — the signalled case,
/// including the sandbox's own KILL after a timeout.
const SIGNALLED_EXIT_CODE: i32 = -1;
/// Bytes read per `read` while draining a child pipe. One page-sized chunk keeps the syscall count
/// down without holding a large buffer per stream for the whole run.
const DRAIN_CHUNK_BYTES: usize = 8 * 1024;
/// Upper bound on the capture buffer preallocated per stream. The output ceiling can be megabytes,
/// and most children never approach it, so the allocation grows on demand instead.
const INITIAL_CAPTURE_CAPACITY_BYTES: usize = 8 * 1024;

/// Immutable process-group termination policy consumed by every sandbox backend.
///
/// Keeping the policy typed and exported lets the runtime resolver attest the exact physical
/// owner rather than restating an unrelated enum literal. The implementation below reads these
/// same fields for TERM -> grace -> KILL -> bounded reap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessSignalKillEscalationPolicy {
    pub term_grace_milliseconds: u64,
    pub post_kill_reap_seconds: u64,
}

impl ProcessSignalKillEscalationPolicy {
    pub const ID: &'static str = "term_grace_kill_reap";
}

pub fn process_signal_kill_escalation_policy() -> ProcessSignalKillEscalationPolicy {
    ProcessSignalKillEscalationPolicy {
        term_grace_milliseconds: iteron_tunables::param_integer(
            "sandbox.lib.termination_grace_ms",
            TERMINATION_GRACE_MS,
        ),
        post_kill_reap_seconds: iteron_tunables::param_integer(
            "sandbox.lib.post_kill_drain_secs",
            POST_KILL_DRAIN_SECS,
        ),
    }
}

#[derive(Default)]
struct BoundedCapture {
    bytes: Vec<u8>,
    truncated: bool,
}

impl BoundedCapture {
    fn with_limit(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit.min(iteron_tunables::param_integer(
                "sandbox.lib.initial_capture_capacity_bytes",
                INITIAL_CAPTURE_CAPACITY_BYTES,
            ))),
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
    observer: Option<&OutputObserver>,
    stream: OutputStream,
) -> std::io::Result<()> {
    let mut chunk =
        vec![
            0_u8;
            iteron_tunables::param_integer("sandbox.lib.drain_chunk_bytes", DRAIN_CHUNK_BYTES,)
                .clamp(1, OutputObserver::MAX_CHUNK_BYTES)
        ];
    loop {
        let read = match reader.read(&mut chunk).await {
            Ok(read) => read,
            Err(error) => {
                if let Some(observer) = observer {
                    observer.finish_io_failure(Some(stream), capture.truncated);
                }
                return Err(error);
            }
        };
        if read == 0 {
            return Ok(());
        }
        if let Some(observer) = observer {
            observer.try_chunk(stream, &chunk[..read], limit);
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
    // No Windows equivalent is wired yet: process groups there mean job objects, which is #39's
    // territory and unbuilt. Bind the parameter so a `-D warnings` build on windows-msvc does not
    // fail on an unused argument.
    #[cfg(not(unix))]
    let _ = command;
}

#[cfg(unix)]
fn signal_process_group(pid: Option<u32>, signal: libc::c_int) {
    if let Some(pid) = pid.and_then(|pid| i32::try_from(pid).ok()) {
        // SAFETY: the child was spawned with process_group(0), so `-pid` addresses the child's
        // group and cannot target the harness's own process group.
        unsafe {
            libc::kill(-pid, signal);
        }
    }
}

/// Last-resort cleanup for cancellation-by-future-drop. Tokio's `kill_on_drop` targets the direct
/// child only; a shell can already have launched background descendants in the dedicated process
/// group. The normal timeout path below remains graceful. This guard is armed only while the
/// collector owns a live group and force-kills that group if an upper runtime layer drops the
/// collector in response to Ctrl-C/Esc.
struct ProcessGroupDropGuard {
    pid: Option<u32>,
    armed: bool,
}

impl ProcessGroupDropGuard {
    fn new(pid: Option<u32>) -> Self {
        Self { pid, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ProcessGroupDropGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        if self.armed {
            signal_process_group(self.pid, libc::SIGKILL);
        }
    }
}

async fn terminate_with_grace(
    child: &mut tokio::process::Child,
    observer: Option<&OutputObserver>,
) -> Option<std::process::ExitStatus> {
    let policy = process_signal_kill_escalation_policy();
    #[cfg(unix)]
    {
        signal_process_group(child.id(), libc::SIGTERM);
        match tokio::time::timeout(
            std::time::Duration::from_millis(policy.term_grace_milliseconds),
            child.wait(),
        )
        .await
        {
            Ok(Ok(status)) => return Some(status),
            Ok(Err(_)) => {
                if let Some(observer) = observer {
                    observer.finish_io_failure(None, false);
                }
            }
            Err(_) => {}
        }
        signal_process_group(child.id(), libc::SIGKILL);
    }

    // `start_kill` is the direct-child fallback on Unix and the only admitted primitive on other
    // platforms. The fixed reap ceiling prevents a hostile child from wedging shutdown forever.
    let _ = child.start_kill();
    match tokio::time::timeout(
        std::time::Duration::from_secs(policy.post_kill_reap_seconds),
        child.wait(),
    )
    .await
    {
        Ok(Ok(status)) => Some(status),
        Ok(Err(_)) => {
            if let Some(observer) = observer {
                observer.finish_io_failure(None, false);
            }
            None
        }
        Err(_) => None,
    }
}

/// Ask the entire child process group to terminate, then force-kill and reap after a fixed grace.
/// Helper processes such as hooks and stdio MCP servers must not wait without a ceiling.
pub async fn terminate_process_group_and_reap(child: &mut tokio::process::Child) {
    let _ = terminate_with_grace(child, None).await;
}

/// Shared child collector for Seatbelt and bubblewrap. stdout and stderr are drained concurrently
/// for the entire run. On timeout we signal the process group, force-kill/reap after one bounded
/// grace, then give the now-closed pipes a short bounded window to flush already-written bytes.
pub(crate) async fn collect_child_output(
    mut child: tokio::process::Child,
    mut stdout: tokio::process::ChildStdout,
    mut stderr: tokio::process::ChildStderr,
    conf: &Confinement,
) -> Result<RunOutput, SandboxError> {
    let mut group_drop_guard = ProcessGroupDropGuard::new(child.id());
    let mut out = BoundedCapture::with_limit(conf.max_output_bytes);
    let mut err = BoundedCapture::with_limit(conf.max_output_bytes);
    let observer = conf.output_observer.clone();
    enum CollectionStop {
        Completed(Result<std::process::ExitStatus, SandboxError>),
        TimedOut,
        Cancelled,
    }
    // Keep every future borrowing the child/pipes/captures inside this scope. Once select returns,
    // all losing futures are dropped before timeout/error cleanup re-borrows the same owners.
    let completed = {
        let collection = async {
            let (stdout_result, stderr_result, wait_result) = tokio::join!(
                drain_bounded(
                    &mut stdout,
                    &mut out,
                    conf.max_output_bytes,
                    observer.as_ref(),
                    OutputStream::Stdout,
                ),
                drain_bounded(
                    &mut stderr,
                    &mut err,
                    conf.max_output_bytes,
                    observer.as_ref(),
                    OutputStream::Stderr,
                ),
                child.wait(),
            );
            stdout_result.map_err(|e| SandboxError::Spawn(format!("read stdout: {e}")))?;
            stderr_result.map_err(|e| SandboxError::Spawn(format!("read stderr: {e}")))?;
            wait_result.map_err(|e| SandboxError::Spawn(format!("wait: {e}")))
        };
        tokio::pin!(collection);
        let deadline = tokio::time::sleep(std::time::Duration::from_secs(conf.timeout_secs));
        tokio::pin!(deadline);
        let cancellation = async {
            match observer.as_ref() {
                Some(observer) => observer.cancelled().await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::pin!(cancellation);
        tokio::select! {
            result = &mut collection => CollectionStop::Completed(result),
            _ = &mut deadline => CollectionStop::TimedOut,
            _ = &mut cancellation => CollectionStop::Cancelled,
        }
    };

    let (timed_out, cancelled, status) = match completed {
        CollectionStop::Completed(status) => match status {
            Ok(status) => {
                group_drop_guard.disarm();
                (false, false, Some(status))
            }
            Err(error) => {
                if let Some(observer) = observer.as_ref() {
                    observer.finish_io_failure(None, false);
                }
                let _ = terminate_with_grace(&mut child, observer.as_ref()).await;
                group_drop_guard.disarm();
                return Err(error);
            }
        },
        reason @ (CollectionStop::TimedOut | CollectionStop::Cancelled) => {
            let status = terminate_with_grace(&mut child, observer.as_ref()).await;
            group_drop_guard.disarm();
            // The first drain futures were cancelled with the timeout, but their captures live
            // outside it. Resume both drains concurrently to retain buffered tail bytes and close
            // the pipes. This cleanup itself is bounded in case a hostile daemon escaped the group.
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(iteron_tunables::param_integer(
                    "sandbox.lib.post_kill_drain_secs",
                    POST_KILL_DRAIN_SECS,
                )),
                async {
                    let _ = tokio::join!(
                        drain_bounded(
                            &mut stdout,
                            &mut out,
                            conf.max_output_bytes,
                            observer.as_ref(),
                            OutputStream::Stdout,
                        ),
                        drain_bounded(
                            &mut stderr,
                            &mut err,
                            conf.max_output_bytes,
                            observer.as_ref(),
                            OutputStream::Stderr,
                        ),
                    );
                },
            )
            .await;
            (
                matches!(reason, CollectionStop::TimedOut),
                matches!(reason, CollectionStop::Cancelled),
                status,
            )
        }
    };

    let (stdout, stdout_truncated) = out.finish("stdout", conf.max_output_bytes);
    let (stderr, stderr_truncated) = err.finish("stderr", conf.max_output_bytes);
    let output = RunOutput {
        exit_code: status
            .and_then(|status| status.code())
            .unwrap_or(SIGNALLED_EXIT_CODE),
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        timed_out,
    };
    if let Some(observer) = observer {
        observer.finish(&output, cancelled);
    }
    Ok(output)
}

pub(crate) fn publish_output_io_failure(conf: &Confinement, stream: Option<OutputStream>) {
    if let Some(observer) = conf.output_observer.as_ref() {
        observer.finish_io_failure(stream, false);
    }
}

#[cfg(test)]
#[path = "output_tests.rs"]
mod output_tests;

/// A sandbox backend that can run a shell command under a confinement.
#[async_trait::async_trait]
pub trait Sandbox: Send + Sync {
    async fn run(&self, command: &str, conf: &Confinement) -> Result<RunOutput, SandboxError>;
}

/// Run a command with no backend at all, under the operator's own authority.
///
/// Every backend delegates here when `conf.unconfined` is set, which is why an absent
/// `sandbox-exec` or `bwrap` stops being a refusal in that posture — there is nothing left for
/// them to enforce. What this still does is exactly what a sandbox never provided: it bounds the
/// wall clock and the retained output, keeps the child in its own process group so a timeout can
/// reap the whole tree, and strips the exact credential names the provider directory declared.
///
/// The confined path is not a superset of this one and this one is not a widened version of it.
/// They are two postures, and `Confinement::unconfined` documents what selecting this surrenders.
pub(crate) async fn run_direct(
    command: &str,
    conf: &Confinement,
) -> Result<RunOutput, SandboxError> {
    let mut cmd = tokio::process::Command::new(confined_shell());
    cmd.arg("-c").arg(command).current_dir(&conf.workspace);
    // No scratch redirection: an unconfined child shares the operator's own temp directory, since
    // a private scratch exists to keep a CONFINED child out of the ambient one.
    apply_confinement_environment(&mut cmd, conf);
    cmd.env("TERM", "dumb")
        .env("PAGER", "cat")
        .env("MANPAGER", "cat")
        .env("GIT_PAGER", "cat")
        .env("PIP_PROGRESS_BAR", "off")
        .env("TQDM_DISABLE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    configure_process_group(&mut cmd);
    let mut child = cmd.spawn().map_err(|e| {
        publish_output_io_failure(conf, None);
        SandboxError::Spawn(e.to_string())
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        publish_output_io_failure(conf, Some(OutputStream::Stdout));
        SandboxError::Spawn("child stdout was not piped".into())
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        publish_output_io_failure(conf, Some(OutputStream::Stderr));
        SandboxError::Spawn("child stderr was not piped".into())
    })?;
    collect_child_output(child, stdout, stderr, conf).await
}

/// Pick the best backend for this platform. An unconfined confinement never reaches a backend's
/// enforcement path, so on an unsupported platform this still returns a backend whose `run`
/// refuses any request that asked to BE confined, rather than silently running it unconfined.
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

const PREFERRED_CONFINED_SHELL: &str = "/bin/bash";
const FALLBACK_CONFINED_SHELL: &str = "/bin/sh";

/// Pick the shell a confined command is executed with. `/bin/bash` stays the preference — the tool
/// prompt and the model's habits assume its builtins — but the musl release artifact's natural
/// home is exactly the image that does not have it: Alpine and other BusyBox userlands ship only
/// `/bin/sh`. Hardcoding bash there turned every `bash` tool call into a bare spawn failure inside
/// an otherwise perfectly usable namespace, so resolve the interpreter instead of assuming it.
fn select_confined_shell(preferred_exists: bool) -> &'static str {
    if preferred_exists {
        iteron_tunables::param_str(
            "sandbox.lib.preferred_confined_shell",
            PREFERRED_CONFINED_SHELL,
        )
    } else {
        iteron_tunables::param_str(
            "sandbox.lib.fallback_confined_shell",
            FALLBACK_CONFINED_SHELL,
        )
    }
}

/// The resolved confined shell for this host, probed once. Both backends run the command inside a
/// namespace/profile that exposes the host's own `/bin`, so the host answer is the confined answer.
pub fn confined_shell() -> &'static str {
    static SHELL: OnceLock<&'static str> = OnceLock::new();
    SHELL.get_or_init(|| {
        select_confined_shell(
            std::path::Path::new(iteron_tunables::param_str(
                "sandbox.lib.preferred_confined_shell",
                PREFERRED_CONFINED_SHELL,
            ))
            .exists(),
        )
    })
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
    // Remove declared names even when a caller explicitly placed a synthetic or broker-provided
    // value on this Command rather than inheriting it from the current process.
    for name in exact {
        cmd.env_remove(name);
    }
    for (k, _) in std::env::vars() {
        if is_secret_env_key(&k) {
            cmd.env_remove(&k);
        }
    }
}

/// Capture the exact ambient environment admitted by an immutable child-process policy.
///
/// Values never appear in an error or durable policy record. A ceiling violation refuses the
/// whole snapshot instead of silently dropping entries, because a partial PATH/HOME/toolchain
/// environment would make resumed executions behave differently from the pinned owner.
pub fn bounded_child_environment(
    reuse: bool,
    max_entries: usize,
    max_bytes: usize,
    blocked_names: &[String],
    sensitive_env_names: &[String],
) -> Result<Vec<(OsString, OsString)>, &'static str> {
    if !reuse {
        return Ok(Vec::new());
    }
    let mut retained = std::env::vars_os()
        .filter(|(key, _)| {
            let Some(key) = key.to_str() else {
                return false;
            };
            !is_secret_env_key(key)
                && !blocked_names.iter().any(|name| name == key)
                && !sensitive_env_names.iter().any(|name| name == key)
        })
        .collect::<Vec<_>>();
    retained.sort_by(|left, right| left.0.cmp(&right.0));
    let encoded_bytes = retained.iter().try_fold(0_usize, |total, (key, value)| {
        total
            .checked_add(encoded_len(key.as_os_str()))?
            .checked_add(1)?
            .checked_add(encoded_len(value.as_os_str()))
    });
    if retained.len() > max_entries || encoded_bytes.is_none_or(|bytes| bytes > max_bytes) {
        return Err("ambient child environment exceeds its immutable entry or byte ceiling");
    }
    Ok(retained)
}

fn encoded_len(value: &OsStr) -> usize {
    value.as_encoded_bytes().len()
}

pub(crate) fn apply_confinement_environment(cmd: &mut tokio::process::Command, conf: &Confinement) {
    if let Some(environment) = &conf.child_environment {
        cmd.env_clear();
        cmd.envs(environment.iter().cloned());
    } else {
        confine_env_with_exact(cmd, &conf.sensitive_env_names);
    }
}

/// Default-deny environment for trusted-config helper processes (MCP servers and hooks). These
/// helpers may need the operator's executable/toolchain paths, locale, and HOME-based package
/// caches, but receive no ambient application/provider credentials. A future broker can add an
/// explicit per-helper secret grant; inheriting every variable is never that grant.
pub fn clear_to_safe_child_env(cmd: &mut tokio::process::Command) {
    clear_to_safe_child_env_with_exact(cmd, &[]);
}

/// Default-deny helper environment with an additional exact deny-list. Exact names take
/// precedence over the toolchain allowlist; this is required when an operator deliberately uses
/// an otherwise-benign name such as `XDG_CONFIG_HOME` as a credential indirection.
pub fn clear_to_safe_child_env_with_exact(
    cmd: &mut tokio::process::Command,
    sensitive_env_names: &[String],
) {
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
            !is_secret_env_key(key)
                && !sensitive_env_names.iter().any(|name| name == key)
                && (EXACT.contains(&key) || key.starts_with("LC_"))
        })
        .collect();
    cmd.env_clear();
    cmd.envs(retained);
}

/// A backend that refuses on unsupported platforms. Refusal, not fallthrough — for a request that
/// asked to be confined. An unconfined request has nothing to fall through to and runs directly.
pub struct Unsupported;

#[async_trait::async_trait]
impl Sandbox for Unsupported {
    async fn run(&self, command: &str, conf: &Confinement) -> Result<RunOutput, SandboxError> {
        if conf.unconfined {
            return run_direct(command, conf).await;
        }
        Err(SandboxError::Unsupported)
    }
}

#[cfg(test)]
#[path = "env_tests.rs"]
mod env_tests;
