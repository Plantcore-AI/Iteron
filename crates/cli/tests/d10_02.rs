#![cfg(unix)]
//! D10-02 — the operator `!cmd` inline shell must pass the SAME capability/effect broker as the
//! agent's own `bash` tool, instead of spawning a process directly.
//!
//! This is a process-level PTY test: it launches the real `core` TUI in **Plan mode** — a HARD
//! read-only overlay that `core_protocol::gate` denies for every capability above `ReadOnly`,
//! including `CodeExecuting` — and then types `!echo BROKER-$((21+21))` at the composer.
//!
//! The marker `BROKER-42` is produced ONLY by shell arithmetic evaluation; it can never appear in
//! the echoed command text (`echo BROKER-$((21+21))`), so its presence on screen is proof that a
//! process actually ran.
//!
//!   * base (bug): the `!` parser spawns `bash` directly, bypassing the gate — `BROKER-42` appears.
//!   * fixed:      `run_bash_inline` consults the capability broker, gets a `Deny` verdict for Plan
//!                 mode, refuses the spawn, and shows "operator shell blocked by permission mode".
//!
//! A brand-new session must never let a read-only posture be punched through by the operator escape
//! hatch, so this asserts BOTH the leak is absent AND the broker's denial is visible.

use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const READY_TIMEOUT: Duration = Duration::from_secs(25);
const STEP_TIMEOUT: Duration = Duration::from_secs(12);
/// crossterm's startup keyboard-capability probe; the harness answers "unsupported" so the TUI
/// finishes negotiation immediately instead of waiting for a real terminal to reply.
const KEYBOARD_ENHANCEMENT_QUERY: &[u8] = b"\x1b[?u\x1b[c";
const KEYBOARD_ENHANCEMENT_REPLY: &[u8] = b"\x1b[?1;2c";
static SCRATCH_ID: AtomicU64 = AtomicU64::new(0);

/// An isolated HOME + repo + rollout tree for one hermetic `core` launch.
struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        let id = SCRATCH_ID.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("core-cli-d10-02-{}-{id}", std::process::id()));
        std::fs::create_dir_all(root.join("home")).expect("create isolated HOME");
        std::fs::create_dir_all(root.join("repo")).expect("create isolated repository");
        Self { root }
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn repo(&self) -> PathBuf {
        self.root.join("repo")
    }

    fn runs(&self) -> PathBuf {
        self.root.join("runs")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A minimal PTY driver: spawns the binary, parses its output with a vt100 grid, and lets the test
/// send keystrokes and wait for on-screen conditions.
struct Pty {
    child: Option<Box<dyn Child + Send + Sync>>,
    writer: Box<dyn Write + Send>,
    // Kept alive so the master fd stays open for the whole session.
    _master: Box<dyn MasterPty + Send>,
    chunks: Receiver<Vec<u8>>,
    reader_thread: Option<JoinHandle<()>>,
    parser: vt100::Parser,
    capture: Vec<u8>,
    keyboard_answered: bool,
}

impl Pty {
    fn spawn(scratch: &Scratch, cols: u16, rows: u16) -> Self {
        let pair = native_pty_system()
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("open a deterministic PTY");

        let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_core"));
        // Direct binary launch: `env_clear` guarantees no real provider credential can be inherited,
        // and a fixed terminal identity (CORE_THEME=terminal) skips the background-color probe.
        command.env_clear();
        command.env("HOME", scratch.home().as_os_str());
        command.env("PATH", "/usr/bin:/bin");
        command.env("TERM", "xterm-256color");
        command.env("COLORTERM", "truecolor");
        command.env("CORE_THEME", "terminal");
        command.env("LANG", "C.UTF-8");
        command.env("CORE_PROVIDER", "glm");
        command.env("CORE_MODEL", "glm-5.2");
        command.cwd(scratch.repo());
        command.arg("--tui");
        command.arg("--repo");
        command.arg(scratch.repo());
        command.arg("--runs-dir");
        command.arg(scratch.runs());
        command.arg("--provider");
        command.arg("glm");
        command.arg("--model");
        command.arg("glm-5.2");
        command.arg("--effort");
        command.arg("low");
        // The whole point: start in the read-only overlay so CodeExecuting is a hard Deny.
        command.arg("--mode");
        command.arg("plan");

        let child = pair
            .slave
            .spawn_command(command)
            .expect("spawn core directly in the PTY");
        // Our own slave handle is redundant once the child owns its controlling terminal; dropping it
        // lets the master reader observe EOF when the child exits.
        drop(pair.slave);

        let mut reader = pair.master.try_clone_reader().expect("clone the PTY reader");
        let writer = pair.master.take_writer().expect("take the PTY writer");
        let (tx, chunks) = mpsc::channel();
        let reader_thread = thread::spawn(move || {
            let mut buf = [0_u8; 8 * 1024];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(read) => {
                        if tx.send(buf[..read].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
        });

        Self {
            child: Some(child),
            writer,
            _master: pair.master,
            chunks,
            reader_thread: Some(reader_thread),
            parser: vt100::Parser::new(rows, cols, 0),
            capture: Vec::new(),
            keyboard_answered: false,
        }
    }

    fn ingest(&mut self, chunk: Vec<u8>) {
        self.parser.process(&chunk);
        self.capture.extend_from_slice(&chunk);
        if !self.keyboard_answered
            && self
                .capture
                .windows(KEYBOARD_ENHANCEMENT_QUERY.len())
                .any(|window| window == KEYBOARD_ENHANCEMENT_QUERY)
        {
            self.keyboard_answered = true;
            self.send(KEYBOARD_ENHANCEMENT_REPLY);
        }
    }

    fn drain_ready(&mut self) {
        loop {
            match self.chunks.try_recv() {
                Ok(chunk) => self.ingest(chunk),
                Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
            }
        }
    }

    fn screen_text(&self) -> String {
        self.parser.screen().contents()
    }

    fn send(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).expect("write PTY input");
        self.writer.flush().expect("flush PTY input");
    }

    fn wait_until(&mut self, label: &str, timeout: Duration, predicate: impl Fn(&str) -> bool) {
        let deadline = Instant::now() + timeout;
        loop {
            self.drain_ready();
            if predicate(&self.screen_text()) {
                return;
            }
            if Instant::now() >= deadline {
                panic!(
                    "timed out waiting for {label}; current terminal:\n{}",
                    self.screen_text()
                );
            }
            match self.chunks.recv_timeout(Duration::from_millis(50)) {
                Ok(chunk) => self.ingest(chunk),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    self.drain_ready();
                    if predicate(&self.screen_text()) {
                        return;
                    }
                    panic!(
                        "the core process exited before {label}; current terminal:\n{}",
                        self.screen_text()
                    );
                }
            }
        }
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(handle) = self.reader_thread.take() {
            let _ = handle.join();
        }
    }
}

#[test]
fn operator_bang_shell_is_gated_by_the_capability_broker_in_plan_mode() {
    let scratch = Scratch::new();
    let mut pty = Pty::spawn(&scratch, 100, 30);

    // Startup: the composer frame carries the "Plan request" title only in the read-only overlay
    // (`--mode plan` took effect), and the status line shows the resolved model. Without Plan mode
    // the whole premise of the test is void, so we require it here rather than trusting the flag.
    pty.wait_until("the core TUI ready in plan mode", READY_TIMEOUT, |screen| {
        screen.contains("Plan request")
            && screen.contains("glm-5.2")
            && !screen.contains('\u{fffd}')
    });

    // Type the operator escape hatch. The arithmetic-evaluated `BROKER-42` can only appear if a
    // real process ran; the literal command text carries `BROKER-$((21+21))` instead.
    pty.send(b"!echo BROKER-$((21+21))\r");

    // Settle into exactly one outcome before asserting, so a slow base run cannot pass vacuously:
    // either the leaked output (base) or the broker's denial (fixed) becomes visible.
    pty.wait_until(
        "the inline shell to run or be blocked",
        STEP_TIMEOUT,
        |screen| screen.contains("BROKER-42") || screen.contains("shell blocked"),
    );

    let screen = pty.screen_text();
    assert!(
        !screen.contains("BROKER-42"),
        "Plan mode is a hard read-only overlay, yet the operator `!cmd` executed and leaked \
         `BROKER-42`: the inline shell spawned a process outside the capability broker.\n{screen}"
    );
    assert!(
        screen.contains("shell blocked"),
        "expected the capability broker to refuse the operator shell in Plan mode with a visible \
         denial, but no block notice was shown.\n{screen}"
    );
}
