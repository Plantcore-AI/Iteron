#![cfg(unix)]
//! D10-01 — the TUI must talk to the runtime as a *versioned App Server client*, not by
//! co-composing the runtime and pushing bare submissions onto its queue.
//!
//! `core-cli` is a managed binary-only package (the boundary authority forbids it a library
//! target), so this is a process-level oracle: it launches the real `core` binary in TUI mode
//! inside a pseudo-terminal and observes the versioned-client handshake the fix introduces.
//!
//! When the interactive frontend is entered, it now attaches to the runtime as a versioned
//! client: it negotiates the SQ/EQ protocol version and announces it on the pre-TUI diagnostic
//! stream *before* it takes over the terminal, then submits only version-stamped envelopes
//! through its `AppServerClient`. Because the announcement precedes raw-mode entry, it appears
//! at the head of the terminal byte stream, ahead of the alternate screen.
//!
//! A frontend that co-composes the runtime (the pre-fix behavior) performs no such handshake
//! and emits no such line. On the pre-fix base this test file's target does not exist, so the
//! oracle is RED; the fix adds the versioned client and its announcement, turning it GREEN.

use core_protocol::PROTOCOL_VERSION;
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

static SCRATCH_ID: AtomicU64 = AtomicU64::new(0);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_CAPTURE_BYTES: usize = 1024 * 1024;

struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        let id = SCRATCH_ID.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("core-d10-01-{}-{id}", std::process::id()));
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

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack.windows(needle.len()).any(|window| window == needle)
}

#[test]
fn tui_announces_a_versioned_app_server_client_handshake() {
    let scratch = Scratch::new();

    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 40,
            cols: 100,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("open deterministic PTY");

    // A direct, credential-free binary launch (env_clear); the built-in `glm` provider resolves
    // without a key because startup never reaches a turn. A real PTY makes the frontend enter the
    // TUI (rather than refuse for lack of a terminal), so `tui::run` — and its handshake — runs.
    let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_core"));
    command.env_clear();
    command.env("HOME", scratch.home().as_os_str());
    command.env("PATH", "/usr/bin:/bin");
    command.env("TERM", "xterm");
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

    let mut child = pair.slave.spawn_command(command).expect("spawn core in PTY");
    let mut reader = pair.master.try_clone_reader().expect("clone PTY reader");
    // Dropping the parent's slave lets the reader see EOF once the child exits.
    drop(pair.slave);

    let (tx, rx) = mpsc::channel::<Vec<u8>>();
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

    let expected = format!(
        "app server: TUI attached as a versioned client (SQ/EQ protocol v{PROTOCOL_VERSION})"
    );

    let mut capture: Vec<u8> = Vec::new();
    let mut found = false;
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(chunk) => {
                if capture.len() < MAX_CAPTURE_BYTES {
                    capture.extend_from_slice(&chunk);
                }
                if contains(&capture, expected.as_bytes()) {
                    found = true;
                    break;
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    // The TUI, given a real terminal, sits in its event loop; end it deterministically.
    let _ = child.kill();
    let _ = child.wait();
    drop(pair.master);
    let _ = reader_thread.join();

    assert!(
        found,
        "the TUI must announce a versioned App Server client handshake; expected:\n  {expected}\ngot terminal bytes:\n{}",
        String::from_utf8_lossy(&capture)
    );
}
