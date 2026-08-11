//! `iteron workflow run` must be interruptible from the keyboard.
//!
//! The live tree enables crossterm raw mode, which clears `ISIG`: the terminal stops turning Ctrl-C
//! into `SIGINT`, so the operator's only interrupt is an ordinary key event that the render loop has
//! to act on. Before this was wired up, Ctrl-C did nothing at all and the only way out of a running
//! workflow was to kill the terminal.
//!
//! This drives the REAL binary inside a real PTY, because the three things that matter cannot be
//! observed from inside the process: that the key reaches a run which then stops, that the terminal
//! is handed back exactly as it was found (raw mode off, alternate screen left, cursor shown), and
//! that the process reports the interruption in its exit status.
//!
//! The fixture workflow spins forever in synchronous JS and never calls `agent()`, so nothing here
//! contacts a provider: cancellation has to arrive through the engine's interrupt handler.

#![cfg(unix)]

use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};
use serde_json::json;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const FIXTURE_PROVIDER_ID: &str = "workflow-interrupt-fixture";
const FIXTURE_MODEL_ID: &str = "workflow-interrupt-model";
const FIXTURE_KEY_ENV: &str = "ITERON_WORKFLOW_INTERRUPT_TEST_KEY";
const FIXTURE_KEY: &str = "integration-test-placeholder";
/// The default-folded card's affordance — proof that a real live frame is on screen and therefore
/// that raw mode is already on and SIGINT already suppressed. Narrator logs intentionally remain
/// hidden until the operator expands the run.
const LIVE_FRAME_MARKER: &str = "ctrl+o expand";
const CTRL_C: &[u8] = b"\x03";
const ENTER_ALTERNATE_SCREEN: &str = "\u{1b}[?1049h";
const LEAVE_ALTERNATE_SCREEN: &str = "\u{1b}[?1049l";
const SHOW_CURSOR: &str = "\u{1b}[?25h";
const STEP_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CAPTURE_BYTES: usize = 2 * 1024 * 1024;

/// A workflow that cannot finish on its own: the only way out is cancellation reaching the engine's
/// QuickJS interrupt handler. `log()` before the loop guarantees the card has content to render.
const SPIN_FOREVER: &str = r#"export const meta = {
  name: 'interrupt-fixture',
  description: 'spins until the operator interrupts it',
  phases: ['spin'],
};
phase('spin');
log('spinning until interrupted');
for (;;) {}
"#;

/// A workflow that finishes on its own, calling no agents. The interrupt work rerouted `run` through
/// the background `launch` path and made `stopped` decide the exit status, so an ordinary completed
/// run must still render, settle and report success.
const COMPLETES_IMMEDIATELY: &str = r#"export const meta = {
  name: 'completes-fixture',
  description: 'returns without interruption',
  phases: ['spin'],
};
phase('spin');
log('spinning until interrupted');
return { ok: 1 };
"#;

struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "iteron-workflow-interrupt-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock is after the epoch")
                .as_nanos()
        ));
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

    /// A provider entry that RESOLVES but is never contacted: the fixture script calls no agents,
    /// and the api_root is a port nothing listens on.
    fn configure_offline_provider(&self) {
        let config_dir = self.home().join(".iteron");
        std::fs::create_dir_all(&config_dir).expect("create isolated Core config directory");
        let config = json!({
            "provider": FIXTURE_PROVIDER_ID,
            "model": FIXTURE_MODEL_ID,
            "effort": "low",
            "providers": [{
                "id": FIXTURE_PROVIDER_ID,
                "display_name": "workflow interrupt fixture provider",
                "adapter": "openai_chat",
                "error_profile": "custom",
                "api_root": "http://127.0.0.1:9",
                "key_env": FIXTURE_KEY_ENV,
                "enabled": true,
                "catalog": false,
                "models": [FIXTURE_MODEL_ID]
            }]
        });
        std::fs::write(
            config_dir.join("config.json"),
            serde_json::to_vec(&config).expect("encode isolated provider config"),
        )
        .expect("write isolated provider config");
    }

    fn write_script(&self, source: &str) -> PathBuf {
        let path = self.repo().join("workflow.js");
        std::fs::write(&path, source).expect("write fixture workflow script");
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// The termios settings raw mode changes, and therefore the ones a well-behaved process restores.
/// Comparing whole `libc::termios` values would be nondeterministic: it carries private padding.
#[derive(Debug, Eq, PartialEq)]
struct RawModeTermiosState {
    input_flags: libc::tcflag_t,
    output_flags: libc::tcflag_t,
    control_flags: libc::tcflag_t,
    local_flags: libc::tcflag_t,
    minimum_read_bytes: libc::cc_t,
    read_timeout: libc::cc_t,
}

fn raw_mode_termios_state(master: &(dyn MasterPty + Send)) -> RawModeTermiosState {
    let termios = master
        .get_termios()
        .expect("PTY must expose its termios state");
    RawModeTermiosState {
        input_flags: termios.input_flags.bits(),
        output_flags: termios.output_flags.bits(),
        control_flags: termios.control_flags.bits(),
        local_flags: termios.local_flags.bits(),
        minimum_read_bytes: termios.control_chars[libc::VMIN],
        read_timeout: termios.control_chars[libc::VTIME],
    }
}

struct WorkflowPty {
    master: Option<Box<dyn MasterPty + Send>>,
    slave: Option<Box<dyn portable_pty::SlavePty>>,
    child: Option<Box<dyn Child + Send + Sync>>,
    writer: Option<Box<dyn Write + Send>>,
    chunks: Receiver<Vec<u8>>,
    reader_thread: Option<JoinHandle<()>>,
    capture: Vec<u8>,
    baseline_termios: RawModeTermiosState,
}

impl WorkflowPty {
    fn spawn(scratch: &Scratch, script: &PathBuf) -> Self {
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 100,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("open deterministic PTY");
        let baseline_termios = raw_mode_termios_state(pair.master.as_ref());

        let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_iteron"));
        // A direct binary launch with a cleared environment: no credential-loading launcher and no
        // inherited real provider key can enter this process tree.
        command.env_clear();
        command.env("HOME", scratch.home().as_os_str());
        command.env("PATH", "/usr/bin:/bin");
        command.env("TERM", "xterm-256color");
        command.env("COLORTERM", "truecolor");
        command.env("ITERON_THEME", "terminal");
        command.env("LANG", "C.UTF-8");
        command.env(FIXTURE_KEY_ENV, FIXTURE_KEY);
        command.cwd(scratch.repo());
        command.arg("--repo");
        command.arg(scratch.repo());
        command.arg("--runs-dir");
        command.arg(scratch.runs());
        command.arg("--provider");
        command.arg(FIXTURE_PROVIDER_ID);
        command.arg("--model");
        command.arg(FIXTURE_MODEL_ID);
        command.arg("workflow");
        command.arg("run");
        command.arg(script);

        let child = pair
            .slave
            .spawn_command(command)
            .expect("spawn iteron directly in PTY");
        let mut reader = pair.master.try_clone_reader().expect("clone PTY reader");
        let writer = pair.master.take_writer().expect("take PTY writer");
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
            master: Some(pair.master),
            slave: Some(pair.slave),
            child: Some(child),
            writer: Some(writer),
            chunks,
            reader_thread: Some(reader_thread),
            capture: Vec::new(),
            baseline_termios,
        }
    }

    fn pump(&mut self, timeout: Duration) -> bool {
        match self.chunks.recv_timeout(timeout) {
            Ok(chunk) => {
                assert!(
                    self.capture.len().saturating_add(chunk.len()) <= MAX_CAPTURE_BYTES,
                    "workflow PTY output exceeded the deterministic capture bound"
                );
                self.capture.extend_from_slice(&chunk);
                true
            }
            Err(RecvTimeoutError::Timeout) => false,
            Err(RecvTimeoutError::Disconnected) => false,
        }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.capture).into_owned()
    }

    fn wait_for_text(&mut self, needle: &str) {
        let deadline = Instant::now() + STEP_TIMEOUT;
        while Instant::now() < deadline {
            if self.text().contains(needle) {
                return;
            }
            self.pump(Duration::from_millis(100));
        }
        panic!(
            "timed out waiting for {needle:?} in workflow PTY output:\n{}",
            self.text()
        );
    }

    fn send(&mut self, bytes: &[u8]) {
        let writer = self.writer.as_mut().expect("PTY writer is open");
        writer.write_all(bytes).expect("write to PTY");
        writer.flush().expect("flush PTY");
    }

    fn wait_for_exit(&mut self) -> portable_pty::ExitStatus {
        let deadline = Instant::now() + STEP_TIMEOUT;
        let mut child = self.child.take().expect("PTY child is running");
        loop {
            if let Some(status) = child.try_wait().expect("poll PTY child") {
                // Drain whatever the child wrote on its way out (the restore sequences live here).
                while self.pump(Duration::from_millis(50)) {}
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "workflow did not exit after Ctrl-C:\n{}",
                self.text()
            );
            self.pump(Duration::from_millis(100));
        }
    }

    fn current_termios(&self) -> RawModeTermiosState {
        raw_mode_termios_state(self.master.as_deref().expect("PTY master is open"))
    }
}

impl Drop for WorkflowPty {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        drop(self.writer.take());
        drop(self.slave.take());
        drop(self.master.take());
        if let Some(thread) = self.reader_thread.take() {
            let _ = thread.join();
        }
    }
}

#[test]
fn ctrl_c_stops_a_running_workflow_restores_the_terminal_and_exits_non_zero() {
    let scratch = Scratch::new("ctrl-c");
    scratch.configure_offline_provider();
    let script = scratch.write_script(SPIN_FOREVER);
    let mut pty = WorkflowPty::spawn(&scratch, &script);

    // Wait for a real live frame, not just the pre-run banner: only once the alternate screen is up
    // and the tree has rendered is raw mode on, and only then is Ctrl-C a key event rather than a
    // SIGINT the terminal would deliver for us.
    pty.wait_for_text(ENTER_ALTERNATE_SCREEN);
    pty.wait_for_text(LIVE_FRAME_MARKER);

    pty.send(CTRL_C);
    let status = pty.wait_for_exit();

    let transcript = pty.text();
    assert!(
        transcript.contains("cancel"),
        "the operator must be told the run was cancelled, not left with a frozen tree:\n{transcript}"
    );
    assert_eq!(
        status.exit_code(),
        130,
        "an interrupted run must not report success:\n{transcript}"
    );
    assert!(
        transcript.contains(LEAVE_ALTERNATE_SCREEN) && transcript.contains(SHOW_CURSOR),
        "the cancel path must leave the alternate screen and show the cursor:\n{transcript:?}"
    );
    assert_eq!(
        pty.current_termios(),
        pty.baseline_termios,
        "the cancel path must hand the terminal back exactly as it was found (raw mode off)"
    );
}

#[test]
fn a_workflow_nobody_interrupted_still_settles_clean_and_exits_zero() {
    let scratch = Scratch::new("completes");
    scratch.configure_offline_provider();
    let script = scratch.write_script(COMPLETES_IMMEDIATELY);
    let mut pty = WorkflowPty::spawn(&scratch, &script);

    let status = pty.wait_for_exit();

    let transcript = pty.text();
    assert_eq!(
        status.exit_code(),
        0,
        "routing `run` through the cancellable launch path must not make ordinary runs fail:\n{transcript}"
    );
    assert!(
        !transcript.contains("cancel"),
        "a run nobody interrupted must never claim it was cancelled:\n{transcript}"
    );
    assert!(
        transcript.contains(LEAVE_ALTERNATE_SCREEN) && transcript.contains(SHOW_CURSOR),
        "the success path restores the terminal too:\n{transcript:?}"
    );
    assert_eq!(
        pty.current_termios(),
        pty.baseline_termios,
        "the success path must hand the terminal back exactly as it was found"
    );
}
