#![cfg(unix)]
//! D10-01 — the TUI must talk to the runtime as a *versioned App Server client*, not by
//! co-composing the runtime and pushing bare submissions onto its queue.
//!
//! `core-cli` is a managed binary-only package (the boundary authority forbids it a library
//! target), so this is a process-level oracle: it launches the real `core` binary in TUI mode
//! and observes the versioned-client handshake the fix introduces.
//!
//! When the interactive frontend is selected, it now attaches to the runtime as a versioned
//! client: it negotiates the SQ/EQ protocol version and announces it on the pre-TUI diagnostic
//! stream *before* the terminal requirement is enforced, then (inside the TUI) submits only
//! version-stamped envelopes through its `AppServerClient`. Because the announcement precedes
//! that requirement, it is observable even when `--tui` is launched without a real terminal: the
//! process announces the handshake, then exits because no interactive terminal is present.
//!
//! A frontend that co-composes the runtime (the pre-fix behavior) performs no such handshake
//! and emits no such line. On the pre-fix base this test file's target does not exist, so the
//! oracle is RED; the fix adds the versioned client and its announcement, turning it GREEN.

use core_protocol::PROTOCOL_VERSION;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static SCRATCH_ID: AtomicU64 = AtomicU64::new(0);
const LAUNCH_TIMEOUT: Duration = Duration::from_secs(20);

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

#[test]
fn tui_announces_a_versioned_app_server_client_handshake() {
    let scratch = Scratch::new();

    // A direct, credential-free binary launch (env_clear); the built-in `glm` provider resolves
    // without a key because startup never reaches a turn. stdout/stderr are pipes, not a TTY.
    let mut command = Command::new(env!("CARGO_BIN_EXE_core"));
    command
        .env_clear()
        .env("HOME", scratch.home())
        .env("PATH", "/usr/bin:/bin")
        .env("TERM", "xterm")
        .env("LANG", "C.UTF-8")
        .env("CORE_PROVIDER", "glm")
        .env("CORE_MODEL", "glm-5.2")
        .current_dir(scratch.repo())
        .arg("--tui")
        .arg("--repo")
        .arg(scratch.repo())
        .arg("--runs-dir")
        .arg(scratch.runs())
        .arg("--provider")
        .arg("glm")
        .arg("--model")
        .arg("glm-5.2")
        .arg("--effort")
        .arg("low")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().expect("spawn core --tui");

    // Read the whole pre-TUI diagnostic stream; it EOFs when the process exits.
    let mut err_pipe = child.stderr.take().expect("capture stderr");
    let reader = thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = err_pipe.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    });

    // With no controlling terminal the interactive frontend announces the handshake and then
    // exits on its own; poll for that, killing on the deadline so a host that *does* grant a
    // controlling terminal (and would enter the TUI event loop) cannot hang us.
    let deadline = Instant::now() + LAUNCH_TIMEOUT;
    loop {
        if child.try_wait().expect("poll core exit").is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    let stderr = reader.join().expect("join stderr reader");
    let expected = format!(
        "app server: TUI attaching as a versioned client (SQ/EQ protocol v{PROTOCOL_VERSION})"
    );
    assert!(
        stderr.contains(&expected),
        "the TUI must announce a versioned App Server client handshake; expected:\n  {expected}\ngot stderr:\n{stderr}"
    );
}
