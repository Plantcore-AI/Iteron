#![cfg(unix)]

use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, SlavePty, native_pty_system};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const STEP_TIMEOUT: Duration = Duration::from_secs(6);
const MAX_CAPTURE_BYTES: usize = 2 * 1024 * 1024;
static SCRATCH_ID: AtomicU64 = AtomicU64::new(0);

struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(label: &str) -> Self {
        let id = SCRATCH_ID.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("core-tui-pty-{label}-{}-{id}", std::process::id()));
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

struct PtyHarness {
    master: Option<Box<dyn MasterPty + Send>>,
    slave: Option<Box<dyn SlavePty + Send>>,
    child: Option<Box<dyn Child + Send + Sync>>,
    writer: Option<Box<dyn Write + Send>>,
    chunks: Receiver<Vec<u8>>,
    reader_thread: Option<JoinHandle<()>>,
    reader_closed: bool,
    parser: vt100::Parser,
    capture: Vec<u8>,
    baseline_termios: String,
}

impl PtyHarness {
    fn spawn(scratch: &Scratch, cols: u16, rows: u16) -> Self {
        let pair = native_pty_system()
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("open deterministic PTY");
        let baseline_termios = format!(
            "{:?}",
            pair.master
                .get_termios()
                .expect("PTY must expose its initial termios")
        );

        let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_core"));
        // This is deliberately a direct binary launch. No credential-loading launcher ever
        // enter this process tree, and env_clear means no real provider credential can be inherited.
        command.env_clear();
        command.env("HOME", scratch.home().as_os_str());
        command.env("PATH", "/usr/bin:/bin");
        command.env("TERM", "xterm-256color");
        command.env("COLORTERM", "truecolor");
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

        let child = pair
            .slave
            .spawn_command(command)
            .expect("spawn core directly in PTY");
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
            reader_closed: false,
            parser: vt100::Parser::new(rows, cols, 0),
            capture: Vec::new(),
            baseline_termios,
        }
    }

    fn ingest(&mut self, chunk: Vec<u8>) {
        assert!(
            self.capture.len().saturating_add(chunk.len()) <= MAX_CAPTURE_BYTES,
            "TUI PTY output exceeded the deterministic capture bound"
        );
        self.parser.process(&chunk);
        self.capture.extend_from_slice(&chunk);
    }

    fn pump_once(&mut self, wait: Duration) -> bool {
        match self.chunks.recv_timeout(wait) {
            Ok(chunk) => {
                self.ingest(chunk);
                true
            }
            Err(RecvTimeoutError::Timeout) => false,
            Err(RecvTimeoutError::Disconnected) => {
                self.reader_closed = true;
                false
            }
        }
    }

    fn drain_ready(&mut self) {
        loop {
            match self.chunks.try_recv() {
                Ok(chunk) => self.ingest(chunk),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.reader_closed = true;
                    break;
                }
            }
        }
    }

    fn wait_until(&mut self, label: &str, predicate: impl Fn(&Self) -> bool) {
        let deadline = Instant::now() + STEP_TIMEOUT;
        while Instant::now() < deadline {
            let _ = self.pump_once(Duration::from_millis(25));
            self.drain_ready();
            if predicate(self) {
                return;
            }
        }
        panic!(
            "timed out waiting for {label}; current terminal:\n{}",
            self.screen_text()
        );
    }

    fn screen_text(&self) -> String {
        self.parser.screen().contents()
    }

    fn send(&mut self, bytes: &[u8]) {
        let writer = self.writer.as_mut().expect("PTY writer is open");
        writer.write_all(bytes).expect("write PTY input");
        writer.flush().expect("flush PTY input");
    }

    fn resize(&mut self, cols: u16, rows: u16) {
        self.drain_ready();
        let before = self.capture.len();
        self.parser.set_size(rows, cols);
        self.master
            .as_ref()
            .expect("PTY master is open")
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("resize PTY and deliver SIGWINCH");
        self.wait_until(&format!("redraw at {cols}x{rows}"), |pty| {
            pty.capture.len() > before
                && pty.parser.screen().size() == (rows, cols)
                && pty.screen_text().contains("请检查")
                && !pty.screen_text().contains('�')
        });
        let (cursor_row, cursor_col) = self.parser.screen().cursor_position();
        assert!(cursor_row < rows, "cursor row escaped {cols}x{rows}");
        assert!(cursor_col < cols, "cursor column escaped {cols}x{rows}");
    }

    fn current_termios(&self) -> String {
        format!(
            "{:?}",
            self.master
                .as_ref()
                .expect("PTY master is open")
                .get_termios()
                .expect("read PTY termios")
        )
    }

    fn process_id(&self) -> u32 {
        self.child
            .as_ref()
            .and_then(|child| child.process_id())
            .expect("PTY child has a process id")
    }

    fn wait_for_exit(&mut self) -> portable_pty::ExitStatus {
        let deadline = Instant::now() + STEP_TIMEOUT;
        while Instant::now() < deadline {
            let status = self
                .child
                .as_mut()
                .expect("PTY child exists")
                .try_wait()
                .expect("poll PTY child");
            if let Some(status) = status {
                self.drain_ready();
                return status;
            }
            let _ = self.pump_once(Duration::from_millis(25));
        }
        panic!(
            "core did not exit before the PTY deadline; current terminal:\n{}",
            self.screen_text()
        );
    }

    fn close_and_drain(&mut self) {
        drop(self.writer.take());
        drop(self.slave.take());
        drop(self.master.take());
        let deadline = Instant::now() + Duration::from_secs(2);
        while !self.reader_closed && Instant::now() < deadline {
            let _ = self.pump_once(Duration::from_millis(25));
            self.drain_ready();
        }
        assert!(self.reader_closed, "PTY reader did not reach EOF");
        if let Some(reader) = self.reader_thread.take() {
            reader.join().expect("join PTY reader");
        }
    }

    fn assert_terminal_restored(&self) {
        let screen = self.parser.screen();
        assert!(!screen.alternate_screen(), "alternate screen leaked");
        assert!(!screen.bracketed_paste(), "bracketed paste leaked");
        assert_eq!(
            screen.mouse_protocol_mode(),
            vt100::MouseProtocolMode::None,
            "mouse capture leaked"
        );
        assert!(!screen.hide_cursor(), "shell cursor remained hidden");
        assert_eq!(screen.fgcolor(), vt100::Color::Default);
        assert_eq!(screen.bgcolor(), vt100::Color::Default);
        assert!(!screen.bold(), "bold style leaked");
        assert!(!screen.italic(), "italic style leaked");
        assert!(!screen.underline(), "underline style leaked");
        assert!(!screen.inverse(), "inverse style leaked");
        let capture = std::str::from_utf8(&self.capture).expect("terminal stream is valid UTF-8");
        assert!(
            !capture.contains('�'),
            "replacement glyph leaked into output"
        );
    }
}

impl Drop for PtyHarness {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut()
            && child.try_wait().ok().flatten().is_none()
        {
            let _ = child.kill();
            let _ = child.wait();
        }
        drop(self.writer.take());
        drop(self.slave.take());
        drop(self.master.take());
        // A join handle is intentionally detached on assertion failure. Closing the slave/master
        // above makes its blocking read reach EOF without risking a second hang during unwinding.
        drop(self.reader_thread.take());
    }
}

fn wait_for_ready(pty: &mut PtyHarness) {
    pty.wait_until("the initial terminal-native Core surface", |pty| {
        let screen = pty.parser.screen();
        let text = screen.contents();
        screen.alternate_screen()
            && screen.bracketed_paste()
            && screen.mouse_protocol_mode() != vt100::MouseProtocolMode::None
            && text.contains("██████╗")
            && text.contains("Prompt")
            && text.contains("glm-5.2")
            && text.contains("○ low")
            && !text.contains('�')
    });
    assert_ne!(
        pty.current_termios(),
        pty.baseline_termios,
        "the live fixture must actually observe raw mode"
    );
}

fn assert_termios_restored(pty: &PtyHarness) {
    assert_eq!(
        pty.current_termios(),
        pty.baseline_termios,
        "the PTY termios did not return to its exact pre-Core state"
    );
}

#[test]
fn picker_permission_resize_cjk_and_normal_exit_restore() {
    let scratch = Scratch::new("normal");
    let mut pty = PtyHarness::spawn(&scratch, 80, 24);
    wait_for_ready(&mut pty);

    pty.send(b"/effort\r");
    pty.wait_until("Effort picker", |pty| {
        let screen = pty.screen_text();
        screen.contains("Effort") && screen.contains("enter select")
    });
    pty.send(b"\r");
    pty.wait_until("one-Enter Effort selection", |pty| {
        let screen = pty.screen_text();
        !screen.contains("enter select") && screen.contains("effort set to")
    });
    assert_eq!(pty.screen_text().matches("effort set to").count(), 1);

    pty.send(b"/permissions\r");
    pty.wait_until("Permissions picker", |pty| {
        let screen = pty.screen_text();
        screen.contains("Permissions") && screen.contains("enter select")
    });
    pty.send(b"\r");
    pty.wait_until("one-Enter permission selection", |pty| {
        let screen = pty.screen_text();
        !screen.contains("enter select") && screen.contains("permission rule:")
    });
    assert_eq!(pty.screen_text().matches("permission rule:").count(), 1);

    let draft = "请检查 e\u{301} 🙂";
    pty.send(draft.as_bytes());
    pty.wait_until("CJK/combining/emoji composer text", |pty| {
        let screen = pty.screen_text();
        screen.contains(draft) && !screen.contains('�')
    });
    for (cols, rows) in [(40, 12), (120, 32), (200, 40), (80, 24), (40, 12)] {
        pty.resize(cols, rows);
    }

    // First Esc preserves shell semantics by clearing the non-empty draft; the second exits.
    pty.send(b"\x1b");
    pty.wait_until("Esc clearing the draft", |pty| {
        !pty.screen_text().contains("请检查")
    });
    pty.send(b"\x1b");
    let status = pty.wait_for_exit();
    assert!(status.success(), "normal TUI exit failed: {status}");
    assert_termios_restored(&pty);
    pty.close_and_drain();
    pty.assert_terminal_restored();
}

#[test]
fn sigterm_from_open_picker_restores_terminal() {
    let scratch = Scratch::new("sigterm");
    let mut pty = PtyHarness::spawn(&scratch, 80, 24);
    wait_for_ready(&mut pty);

    pty.send(b"/effort\r");
    pty.wait_until("cursor-owning Effort picker", |pty| {
        let screen = pty.parser.screen();
        screen.contents().contains("Effort") && screen.hide_cursor()
    });
    let pid = i32::try_from(pty.process_id()).expect("child pid fits pid_t");
    // SAFETY: `pid` is the direct child returned by portable-pty and is still live here.
    let sent = unsafe { libc::kill(pid, libc::SIGTERM) };
    assert_eq!(
        sent,
        0,
        "send SIGTERM to Core: {}",
        std::io::Error::last_os_error()
    );

    let status = pty.wait_for_exit();
    assert_eq!(status.exit_code(), 143, "unexpected SIGTERM exit: {status}");
    assert_termios_restored(&pty);
    pty.close_and_drain();
    pty.assert_terminal_restored();
}
