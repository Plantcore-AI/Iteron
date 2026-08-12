#![cfg(unix)]
//! D10-01 — the TUI must talk to the runtime as a *versioned App Server client*, not by
//! co-composing the runtime and pushing bare submissions onto its queue.
//!
//! `iteron-cli` is a managed binary-only package (the boundary authority forbids it a library
//! target), so this is a process-level oracle: it launches the real `iteron` binary in TUI mode
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

use iteron_protocol::PROTOCOL_VERSION;
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

static SCRATCH_ID: AtomicU64 = AtomicU64::new(0);
const FIXTURE_PROVIDER_ID: &str = "glm";
const FIXTURE_MODEL_ID: &str = "glm-5.2";
const FIXTURE_KEY_ENV: &str = "GLM_API_KEY";
const FIXTURE_KEY: &str = "bounded-offline-placeholder";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_CAPTURE_BYTES: usize = 1024 * 1024;

struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        let id = SCRATCH_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("core-d10-01-{}-{id}", std::process::id()));
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
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Launch the real binary in TUI mode inside a PTY and collect terminal bytes until `needle`
/// appears or the deadline passes. Returns everything captured plus whether the needle was seen.
fn capture_until(scratch: &Scratch, server_version: Option<u32>, needle: &str) -> (Vec<u8>, bool) {
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 40,
            cols: 100,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("open deterministic PTY");

    // A direct binary launch with a cleared environment and one inert, test-only GLM credential.
    // No developer credential can enter the process, and no provider request is made because this
    // oracle stops at the handshake. The real static GLM route exercises the OpenAI-compatible
    // adapter's physical no-cache capability instead of bypassing it with a test-only provider.
    let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_iteron"));
    command.env_clear();
    if let Some(version) = server_version {
        command.env("ITERON_APP_SERVER_PROTOCOL_VERSION", version.to_string());
    }
    command.env("HOME", scratch.home().as_os_str());
    command.env("PATH", "/usr/bin:/bin");
    command.env("TERM", "xterm");
    command.env("LANG", "C.UTF-8");
    command.env(FIXTURE_KEY_ENV, FIXTURE_KEY);
    command.cwd(scratch.repo());
    command.arg("--tui");
    command.arg("--repo");
    command.arg(scratch.repo());
    command.arg("--runs-dir");
    command.arg(scratch.runs());
    command.arg("--provider");
    command.arg(FIXTURE_PROVIDER_ID);
    command.arg("--model");
    command.arg(FIXTURE_MODEL_ID);
    command.arg("--effort");
    command.arg("low");

    let mut child = pair
        .slave
        .spawn_command(command)
        .expect("spawn iteron in PTY");
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

    let mut capture: Vec<u8> = Vec::new();
    let mut found = false;
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(chunk) => {
                if capture.len() < MAX_CAPTURE_BYTES {
                    capture.extend_from_slice(&chunk);
                }
                if contains(&capture, needle.as_bytes()) {
                    found = true;
                    break;
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    // The TUI, given a real terminal, sits in its event loop; end it deterministically. Capture the
    // exit status first: if the child died on its own before printing anything, that status is the
    // only evidence of why, and without it this test fails with an empty buffer and no reason —
    // which is how it reads on a machine whose PTY the child rejects.
    let early_exit = child
        .try_wait()
        .ok()
        .flatten()
        .map(|status| status.exit_code());
    let _ = child.kill();
    let _ = child.wait();
    drop(pair.master);
    let _ = reader_thread.join();
    if capture.is_empty() {
        eprintln!(
            "d10_01: the child produced no terminal bytes; early exit status = {early_exit:?}. \
             An empty capture with a non-None status means the binary refused this PTY rather \
             than failing the handshake."
        );
    }
    (capture, found)
}

#[test]
fn tui_announces_a_versioned_app_server_client_handshake() {
    let scratch = Scratch::new();
    let expected = format!(
        "app server: TUI attached as a versioned client (SQ/EQ protocol v{PROTOCOL_VERSION})"
    );
    let (capture, found) = capture_until(&scratch, None, &expected);

    assert!(
        found,
        "the TUI must announce a versioned App Server client handshake; expected:\n  {expected}\ngot terminal bytes:\n{}",
        String::from_utf8_lossy(&capture)
    );
}

/// A versioned client is only a client if it can *refuse*. Pointed at a runtime that advertises a
/// protocol it does not speak, the frontend must decline to attach, say so in plain text, and never
/// take over the terminal — a diagnostic printed from inside the alternate screen is a diagnostic
/// the operator never sees, because the terminal guard restores the screen on the way out and takes
/// the message with it.
///
/// A frontend that co-composes the runtime cannot fail this way at all: there is no handshake to
/// refuse, so it would enter the TUI regardless of what version the runtime speaks.
#[test]
fn tui_refuses_to_attach_on_version_skew_before_touching_the_terminal() {
    let scratch = Scratch::new();
    let skewed = PROTOCOL_VERSION + 1;
    let expected = format!(
        "app server: refusing to attach — unsupported SQ/EQ protocol version {skewed}; expected {PROTOCOL_VERSION}"
    );
    let (capture, found) = capture_until(&scratch, Some(skewed), &expected);

    assert!(
        found,
        "a frontend that cannot speak the runtime's protocol must refuse to attach and say why; expected:\n  {expected}\ngot terminal bytes:\n{}",
        String::from_utf8_lossy(&capture)
    );

    // Ordering is the other half of the criterion: the refusal must reach the operator on the
    // pre-TUI diagnostic stream. Nothing may have switched to the alternate screen (CSI ?1049h)
    // or enabled mouse reporting (CSI ?1000h) before it.
    for (sequence, what) in [
        (b"\x1b[?1049h".as_slice(), "the alternate screen"),
        (b"\x1b[?1000h".as_slice(), "mouse reporting"),
    ] {
        assert!(
            !contains(&capture, sequence),
            "the refusal must precede terminal takeover, but {what} was entered; terminal bytes:\n{}",
            String::from_utf8_lossy(&capture)
        );
    }

    // And the announcement of a *successful* attachment must not appear: refusing and attaching are
    // mutually exclusive outcomes.
    assert!(
        !contains(&capture, b"app server: TUI attached as a versioned client"),
        "a refused handshake must not also announce a successful attachment; terminal bytes:\n{}",
        String::from_utf8_lossy(&capture)
    );
}
