#![cfg(unix)]

use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, SlavePty, native_pty_system};
use serde_json::json;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const STEP_TIMEOUT: Duration = Duration::from_secs(6);
const PROVIDER_TIMEOUT: Duration = Duration::from_secs(10);
const PROVIDER_IO_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_CAPTURE_BYTES: usize = 2 * 1024 * 1024;
const MAX_PROVIDER_REQUEST_BYTES: usize = 1024 * 1024;
const LINK_PROVIDER_ID: &str = "tui-link-fixture";
const LINK_MODEL_ID: &str = "tui-link-model";
const LINK_TEST_KEY_ENV: &str = "CORE_TUI_LINK_TEST_KEY";
const LINK_TEST_KEY: &str = "integration-test-placeholder";
const LINK_TARGET: &str = "https://example.com/core-guide";
const TERMINAL_BELL: u8 = b'\x07';
const OSC9_RUN_COMPLETE: &[u8] = b"\x1b]9;Core Code: run complete\x07";
const KEYBOARD_ENHANCEMENT_QUERY: &[u8] = b"\x1b[?u\x1b[c";
const KEYBOARD_ENHANCEMENT_PUSH: &[u8] = b"\x1b[>1u";
const KEYBOARD_ENHANCEMENT_POP: &[u8] = b"\x1b[<1u";
const OSC11_QUERY: &[u8] = b"\x1b]11;?\x1b\\";
/// A glyph from the startup banner, i.e. proof that a real frame reached the terminal.
const FIRST_FRAME_MARKER: &[u8] = "██████╗".as_bytes();
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

    fn initialize_git_workspace(&self) {
        let status = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(self.repo())
            .status()
            .expect("git is available for drain checkpoint fixture");
        assert!(status.success(), "initialize drain checkpoint repository");
    }

    fn configure_link_provider(&self, api_root: &str) {
        self.configure_link_provider_with_notifications(api_root, None);
    }

    fn configure_link_provider_with_notifications(
        &self,
        api_root: &str,
        completion_notifications: Option<bool>,
    ) {
        let config_dir = self.home().join(".core");
        std::fs::create_dir_all(&config_dir).expect("create isolated Core config directory");
        let mut config = json!({
            "provider": LINK_PROVIDER_ID,
            "model": LINK_MODEL_ID,
            "effort": "low",
            "max_wall_secs": 10,
            "providers": [{
                "id": LINK_PROVIDER_ID,
                "display_name": "TUI link fixture provider",
                "adapter": "openai_chat",
                "error_profile": "custom",
                "api_root": api_root,
                "key_env": LINK_TEST_KEY_ENV,
                "enabled": true,
                "catalog": false,
                "models": [LINK_MODEL_ID]
            }]
        });
        if let Some(enabled) = completion_notifications {
            config["schema_version"] = json!(2);
            config["completion_notifications"] = json!(enabled);
        }
        std::fs::write(
            config_dir.join("config.json"),
            serde_json::to_vec(&config).expect("encode isolated provider config"),
        )
        .expect("write isolated provider config");
    }

    fn configure_project_notifications(&self, enabled: bool) {
        let config_dir = self.repo().join(".core");
        std::fs::create_dir_all(&config_dir).expect("create isolated project config directory");
        let config = json!({
            "schema_version": 2,
            "completion_notifications": enabled
        });
        std::fs::write(
            config_dir.join("config.json"),
            serde_json::to_vec(&config).expect("encode isolated project config"),
        )
        .expect("write isolated project config");
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct LinkProvider {
    api_root: String,
    handle: Option<JoinHandle<()>>,
}

impl LinkProvider {
    fn spawn() -> Self {
        Self::spawn_with_content(format!("Read [the guide]({LINK_TARGET}) now."), true)
    }

    fn spawn_notification_fixture() -> Self {
        Self::spawn_with_content("Notification fixture row remains intact.".into(), true)
    }

    fn spawn_missing_usage_notification_fixture() -> Self {
        Self::spawn_with_content("Missing-usage completion still notifies.".into(), false)
    }

    fn spawn_with_content(content: String, include_usage: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback TUI provider");
        listener
            .set_nonblocking(true)
            .expect("make TUI provider accept bounded");
        let address = listener.local_addr().expect("read TUI provider address");
        let handle = thread::spawn(move || {
            let mut stream = accept_provider_connection(&listener);
            read_provider_request(&mut stream);
            stream
                .set_write_timeout(Some(PROVIDER_IO_TIMEOUT))
                .expect("bound TUI provider write");
            let content = serde_json::to_string(&content).expect("encode fixture content");
            let usage = if include_usage {
                "data: {\"id\":\"chatcmpl-tui-link\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":4,\"total_tokens\":15,\"prompt_tokens_details\":{\"cached_tokens\":0},\"completion_tokens_details\":{\"reasoning_tokens\":0}}}\n\n"
            } else {
                ""
            };
            let body = format!(
                concat!(
                    "data: {{\"id\":\"chatcmpl-tui-link\",\"object\":\"chat.completion.chunk\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\",\"content\":{}}},\"finish_reason\":null}}],\"usage\":null}}\n\n",
                    "data: {{\"id\":\"chatcmpl-tui-link\",\"object\":\"chat.completion.chunk\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}],\"usage\":null}}\n\n",
                    "{}",
                    "data: [DONE]\n\n"
                ),
                content, usage,
            );
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .expect("write TUI provider response");
            stream.flush().expect("flush TUI provider response");
        });
        Self {
            api_root: format!("http://{address}/v1"),
            handle: Some(handle),
        }
    }

    fn finish(mut self) {
        self.handle
            .take()
            .expect("TUI provider thread exists")
            .join()
            .expect("TUI provider completed cleanly");
    }
}

struct BlockingLinkProvider {
    api_root: String,
    started: Receiver<()>,
    release: mpsc::Sender<()>,
    handle: Option<JoinHandle<()>>,
}

impl BlockingLinkProvider {
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind drain fixture provider");
        listener
            .set_nonblocking(true)
            .expect("make drain fixture accept bounded");
        let address = listener.local_addr().expect("read drain fixture address");
        let (started_tx, started) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let mut stream = accept_provider_connection(&listener);
            read_provider_request(&mut stream);
            started_tx.send(()).expect("signal admitted provider turn");
            release_rx
                .recv_timeout(PROVIDER_TIMEOUT)
                .expect("drain test releases provider");
            let body = concat!(
                "data: {\"id\":\"chatcmpl-drain\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Provider turn quiesced.\"},\"finish_reason\":null}],\"usage\":null}\n\n",
                "data: {\"id\":\"chatcmpl-drain\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":null}\n\n",
                "data: {\"id\":\"chatcmpl-drain\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":3,\"total_tokens\":10}}\n\n",
                "data: [DONE]\n\n"
            );
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .expect("write drain fixture response");
            stream.flush().expect("flush drain fixture response");
        });
        Self {
            api_root: format!("http://{address}/v1"),
            started,
            release,
            handle: Some(handle),
        }
    }

    fn finish(mut self) {
        self.handle
            .take()
            .expect("drain provider thread exists")
            .join()
            .expect("drain provider completed cleanly");
    }
}

fn accept_provider_connection(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + PROVIDER_TIMEOUT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                // Some Unix targets inherit the listener's O_NONBLOCK status on accept. The
                // request reader below is deliberately timeout-bounded blocking I/O, so normalize
                // the accepted socket instead of racing the first request bytes.
                stream
                    .set_nonblocking(false)
                    .expect("make accepted TUI provider connection blocking");
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "Core never connected to the TUI provider"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("TUI provider accept failed: {error}"),
        }
    }
}

fn read_provider_request(stream: &mut TcpStream) {
    stream
        .set_read_timeout(Some(PROVIDER_IO_TIMEOUT))
        .expect("bound TUI provider read");
    let mut request = Vec::new();
    let mut expected = None;
    loop {
        let mut chunk = [0u8; 8 * 1024];
        let read = stream.read(&mut chunk).expect("read TUI provider request");
        assert!(read > 0, "TUI provider request ended before its body");
        request.extend_from_slice(&chunk[..read]);
        assert!(
            request.len() <= MAX_PROVIDER_REQUEST_BYTES,
            "TUI provider request exceeded its test bound"
        );
        if expected.is_none()
            && let Some(headers_end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n")
        {
            let headers = std::str::from_utf8(&request[..headers_end])
                .expect("TUI provider headers are UTF-8");
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().expect("valid content-length"))
                })
                .expect("TUI provider request has content-length");
            expected = Some(headers_end + 4 + content_length);
        }
        if expected.is_some_and(|expected| request.len() >= expected) {
            return;
        }
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
    baseline_termios: RawModeTermiosState,
    keyboard_fixture: KeyboardFixture,
    keyboard_query_answered: bool,
}

#[derive(Clone, Copy)]
enum ThemeFixture {
    /// Existing lifecycle scenarios are about terminal state, so skip an unrelated startup query.
    TerminalOverride,
    /// No theme/background hint: the harness acts as the terminal and answers OSC 11.
    Osc11Auto,
    /// The harness deliberately ignores OSC 11 so startup must fall back to COLORFGBG.
    Osc11Timeout,
    /// Explicit dark palette on a terminal with only the base ANSI color set.
    Ansi16Dark,
}

#[derive(Clone, Copy)]
enum KeyboardFixture {
    Unsupported,
    Kitty,
}

/// The subset of terminal state that Core changes when it enters raw mode.
///
/// `libc::termios` contains platform-private padding and unused control-character slots. Linux
/// musl leaves some of those bytes unspecified when reading a PTY, so comparing its debug
/// representation would make this lifecycle test nondeterministic. These are the public termios
/// settings that raw mode changes and therefore the settings that must be restored by Core.
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

impl PtyHarness {
    fn spawn(scratch: &Scratch, cols: u16, rows: u16) -> Self {
        Self::spawn_configured(scratch, cols, rows, false)
    }

    fn spawn_link_fixture(scratch: &Scratch, cols: u16, rows: u16) -> Self {
        Self::spawn_configured(scratch, cols, rows, true)
    }

    fn spawn_osc11_fixture(scratch: &Scratch, cols: u16, rows: u16) -> Self {
        Self::spawn_with_theme(scratch, cols, rows, false, ThemeFixture::Osc11Auto)
    }

    fn spawn_osc11_timeout_fixture(scratch: &Scratch, cols: u16, rows: u16) -> Self {
        Self::spawn_with_theme(scratch, cols, rows, false, ThemeFixture::Osc11Timeout)
    }

    fn spawn_ansi16_fixture(scratch: &Scratch, cols: u16, rows: u16) -> Self {
        Self::spawn_with_theme(scratch, cols, rows, false, ThemeFixture::Ansi16Dark)
    }

    fn spawn_kitty_keyboard_fixture(scratch: &Scratch, cols: u16, rows: u16) -> Self {
        Self::spawn_with_terminal(
            scratch,
            cols,
            rows,
            false,
            ThemeFixture::TerminalOverride,
            KeyboardFixture::Kitty,
        )
    }

    fn spawn_configured(scratch: &Scratch, cols: u16, rows: u16, link_fixture: bool) -> Self {
        Self::spawn_with_theme(
            scratch,
            cols,
            rows,
            link_fixture,
            ThemeFixture::TerminalOverride,
        )
    }

    fn spawn_with_theme(
        scratch: &Scratch,
        cols: u16,
        rows: u16,
        link_fixture: bool,
        theme_fixture: ThemeFixture,
    ) -> Self {
        Self::spawn_with_terminal(
            scratch,
            cols,
            rows,
            link_fixture,
            theme_fixture,
            KeyboardFixture::Unsupported,
        )
    }

    fn spawn_with_terminal(
        scratch: &Scratch,
        cols: u16,
        rows: u16,
        link_fixture: bool,
        theme_fixture: ThemeFixture,
        keyboard_fixture: KeyboardFixture,
    ) -> Self {
        let pair = native_pty_system()
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("open deterministic PTY");
        let baseline_termios = raw_mode_termios_state(pair.master.as_ref());

        let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_core"));
        // This is deliberately a direct binary launch. No credential-loading launcher ever
        // enter this process tree, and env_clear means no real provider credential can be inherited.
        command.env_clear();
        command.env("HOME", scratch.home().as_os_str());
        command.env("PATH", "/usr/bin:/bin");
        match theme_fixture {
            ThemeFixture::TerminalOverride => {
                command.env("TERM", "xterm-256color");
                command.env("COLORTERM", "truecolor");
                command.env("CORE_THEME", "terminal");
            }
            ThemeFixture::Osc11Auto => {
                command.env("TERM", "xterm-direct");
                command.env("COLORTERM", "truecolor");
            }
            ThemeFixture::Osc11Timeout => {
                command.env("TERM", "xterm-direct");
                command.env("COLORTERM", "truecolor");
                command.env("COLORFGBG", "0;15");
            }
            ThemeFixture::Ansi16Dark => {
                command.env("TERM", "xterm");
                command.env("CORE_THEME", "dark");
            }
        }
        if matches!(keyboard_fixture, KeyboardFixture::Kitty) {
            command.env("TERM", "xterm-kitty");
        }
        command.env("LANG", "C.UTF-8");
        command.cwd(scratch.repo());
        command.arg("--tui");
        command.arg("--repo");
        command.arg(scratch.repo());
        command.arg("--runs-dir");
        command.arg(scratch.runs());
        command.arg("--provider");
        command.arg(if link_fixture {
            LINK_PROVIDER_ID
        } else {
            "glm"
        });
        command.arg("--model");
        command.arg(if link_fixture {
            LINK_MODEL_ID
        } else {
            "glm-5.2"
        });
        command.arg("--effort");
        command.arg("low");
        if link_fixture {
            command.env("TERM_PROGRAM", "WezTerm");
            command.env("NO_PROXY", "127.0.0.1,localhost");
            command.env(LINK_TEST_KEY_ENV, LINK_TEST_KEY);
            command.arg("render the deterministic link fixture");
        } else {
            command.env("CORE_PROVIDER", "glm");
            command.env("CORE_MODEL", "glm-5.2");
        }

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
            keyboard_fixture,
            keyboard_query_answered: false,
        }
    }

    fn ingest(&mut self, chunk: Vec<u8>) {
        assert!(
            self.capture.len().saturating_add(chunk.len()) <= MAX_CAPTURE_BYTES,
            "TUI PTY output exceeded the deterministic capture bound"
        );
        self.parser.process(&chunk);
        self.capture.extend_from_slice(&chunk);
        if !self.keyboard_query_answered
            && self
                .capture
                .windows(KEYBOARD_ENHANCEMENT_QUERY.len())
                .any(|window| window == KEYBOARD_ENHANCEMENT_QUERY)
        {
            self.keyboard_query_answered = true;
            let response = match self.keyboard_fixture {
                KeyboardFixture::Unsupported => b"\x1b[?1;2c".as_slice(),
                KeyboardFixture::Kitty => b"\x1b[?1u\x1b[?1;2c".as_slice(),
            };
            self.send(response);
        }
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
            let (cursor_row, cursor_col) = pty.parser.screen().cursor_position();
            pty.capture.len() > before
                && pty.parser.screen().size() == (rows, cols)
                && pty.screen_text().contains("请检查")
                && !pty.screen_text().contains('�')
                && cursor_row < rows
                && cursor_col < cols
        });
        let (cursor_row, cursor_col) = self.parser.screen().cursor_position();
        assert!(cursor_row < rows, "cursor row escaped {cols}x{rows}");
        assert!(cursor_col < cols, "cursor column escaped {cols}x{rows}");
    }

    fn current_termios(&self) -> RawModeTermiosState {
        raw_mode_termios_state(self.master.as_deref().expect("PTY master is open"))
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
        assert_eq!(
            sequence_count(&self.capture, KEYBOARD_ENHANCEMENT_PUSH),
            sequence_count(&self.capture, KEYBOARD_ENHANCEMENT_POP),
            "Kitty keyboard enhancement stack frame leaked"
        );
    }

    fn assert_keyboard_enhanced_and_restored(&self) {
        assert_eq!(
            sequence_count(&self.capture, KEYBOARD_ENHANCEMENT_PUSH),
            1,
            "capable fixture must receive exactly one keyboard-enhancement push"
        );
        assert_eq!(
            sequence_count(&self.capture, KEYBOARD_ENHANCEMENT_POP),
            1,
            "Core must pop exactly the keyboard-enhancement frame it pushed"
        );
        let push = find_sequence(&self.capture, KEYBOARD_ENHANCEMENT_PUSH).unwrap();
        let pop = find_sequence(&self.capture, KEYBOARD_ENHANCEMENT_POP).unwrap();
        assert!(
            push < pop,
            "keyboard enhancement was popped before it was pushed"
        );
    }
}

fn find_sequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn sequence_count(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

fn assert_draft_rows(screen: &str, first: &str, second: &str) {
    let first_row = screen
        .lines()
        .position(|line| line.contains(first))
        .expect("first composer row is visible");
    let second_row = screen
        .lines()
        .position(|line| line.contains(second))
        .expect("second composer row is visible");
    assert_ne!(
        first_row, second_row,
        "modified Enter did not create a distinct composer row"
    );
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
        "Core did not restore the raw-mode terminal settings it changed"
    );
}

#[test]
fn osc11_light_background_selects_the_light_truecolor_palette_without_colorfgbg() {
    let scratch = Scratch::new("osc11-light-theme");
    let mut pty = PtyHarness::spawn_osc11_fixture(&scratch, 80, 24);

    pty.wait_until("the bounded OSC 11 background query", |pty| {
        pty.capture
            .windows(b"\x1b]11;?\x1b\\".len())
            .any(|window| window == b"\x1b]11;?\x1b\\")
    });
    // Input arriving while the query is outstanding must be replayed into the normal TUI path.
    pty.send(b"preprobe42");
    pty.send(b"\x1b]11;rgb:ffff/ffff/ffff\x1b\\");
    wait_for_ready(&mut pty);
    pty.wait_until("startup input replay after OSC demultiplexing", |pty| {
        pty.screen_text().contains("preprobe42")
    });

    let capture = std::str::from_utf8(&pty.capture).expect("terminal stream is valid UTF-8");
    assert!(
        capture.contains("38;2;52;91;209;"),
        "light-theme accent RGB was not emitted after the OSC 11 reply"
    );
    assert!(
        !capture.contains("38;2;122;162;247;"),
        "dark-theme accent must not win over a light OSC 11 reply"
    );

    pty.send(b"\x15\x1b"); // Ctrl-U clears the replayed draft, then Esc exits.
    let status = pty.wait_for_exit();
    assert!(status.success(), "normal TUI exit failed: {status}");
    assert_termios_restored(&pty);
    pty.close_and_drain();
    pty.assert_terminal_restored();
}

#[test]
fn unanswered_osc11_query_times_out_to_colorfgbg_without_blocking_startup() {
    let scratch = Scratch::new("osc11-timeout-theme");
    let started = Instant::now();
    let mut pty = PtyHarness::spawn_osc11_timeout_fixture(&scratch, 80, 24);
    wait_for_ready(&mut pty);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "an unanswered terminal query must not hold TUI startup"
    );
    // The query is now issued BEHIND the first frame, so a painted surface no longer implies the
    // probe has been written. Wait for the real bytes before asserting anything about the timeout.
    pty.wait_until("the deferred OSC 11 background query", |pty| {
        find_sequence(&pty.capture, OSC11_QUERY).is_some()
    });

    let capture = std::str::from_utf8(&pty.capture).expect("terminal stream is valid UTF-8");
    assert!(
        capture.contains("\x1b]11;?\x1b\\"),
        "the unanswered fixture must exercise the real OSC 11 query"
    );
    assert!(
        capture.contains("38;2;52;91;209;"),
        "COLORFGBG light fallback was not emitted after the timeout"
    );

    // A pathological late response must still be swallowed instead of becoming Alt+] + text.
    pty.send(b"\x1b]11;rgb:0000/0000/0000\x1b\\late-input-42");
    pty.wait_until("ordinary input after a late OSC reply", |pty| {
        pty.screen_text().contains("late-input-42")
    });
    assert!(
        !pty.screen_text().contains("11;rgb:"),
        "late OSC response bytes leaked into the composer"
    );

    pty.send(b"\x15\x1b");
    let status = pty.wait_for_exit();
    assert!(status.success(), "normal TUI exit failed: {status}");
    assert_termios_restored(&pty);
    pty.close_and_drain();
    pty.assert_terminal_restored();
}

#[test]
fn capability_probes_are_written_after_the_first_painted_frame() {
    // Both probes used to sit between EnterAlternateScreen and the first draw: the progressive
    // keyboard query blocks up to 2000 ms and OSC 11 another 80 ms, so a terminal that answered
    // neither held a freshly blanked screen for two seconds before anything appeared.
    //
    // Byte order is the durable statement of the fix, and it is the STRONGER one: a query that is
    // written after the frame cannot delay the frame no matter how long the terminal takes to
    // answer it, or whether it answers at all. A wall-clock bound would instead mostly measure how
    // loaded the machine running this suite happens to be.
    let scratch = Scratch::new("probe-after-first-frame");
    let mut pty = PtyHarness::spawn_osc11_fixture(&scratch, 80, 24);
    pty.wait_until("both deferred capability probes", |pty| {
        find_sequence(&pty.capture, KEYBOARD_ENHANCEMENT_QUERY).is_some()
            && find_sequence(&pty.capture, OSC11_QUERY).is_some()
    });
    let frame =
        find_sequence(&pty.capture, FIRST_FRAME_MARKER).expect("the first frame reaches the PTY");
    let keyboard = find_sequence(&pty.capture, KEYBOARD_ENHANCEMENT_QUERY).unwrap();
    let background = find_sequence(&pty.capture, OSC11_QUERY).unwrap();
    assert!(
        frame < keyboard,
        "the blocking keyboard probe was written before the first frame ({keyboard} < {frame})"
    );
    assert!(
        frame < background,
        "the OSC 11 probe was written before the first frame ({background} < {frame})"
    );

    // An answering terminal still gets the background it reported, now as a repaint behind the
    // frame rather than as a precondition for it.
    pty.send(b"\x1b]11;rgb:ffff/ffff/ffff\x1b\\");
    wait_for_ready(&mut pty);
    pty.wait_until("the late OSC 11 reply repaints the light palette", |pty| {
        std::str::from_utf8(&pty.capture).is_ok_and(|capture| capture.contains("38;2;52;91;209;"))
    });

    pty.send(b"\x1b");
    let status = pty.wait_for_exit();
    assert!(status.success(), "normal TUI exit failed: {status}");
    assert_termios_restored(&pty);
    pty.close_and_drain();
    pty.assert_terminal_restored();
}

#[test]
fn ansi16_terminal_receives_only_base_palette_indices() {
    let scratch = Scratch::new("ansi16-theme");
    let mut pty = PtyHarness::spawn_ansi16_fixture(&scratch, 80, 24);
    wait_for_ready(&mut pty);

    let capture = std::str::from_utf8(&pty.capture).expect("terminal stream is valid UTF-8");
    for forbidden in ["38;2;", "48;2;"] {
        assert!(
            !capture.contains(forbidden),
            "16-color projection leaked unsupported SGR form {forbidden}"
        );
    }
    // Crossterm encodes even named ANSI colors as `38/48;5;n`; the capability guarantee is that
    // `n` remains inside the base 0..=15 palette, never the 256-color cube.
    for marker in ["38;5;", "48;5;"] {
        let mut rest = capture;
        while let Some(start) = rest.find(marker) {
            rest = &rest[start + marker.len()..];
            let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
            let index = rest[..digits]
                .parse::<u16>()
                .expect("crossterm palette index is numeric");
            assert!(
                index <= 15,
                "16-color projection leaked palette index {index}"
            );
            rest = &rest[digits..];
        }
    }

    pty.send(b"\x1b");
    let status = pty.wait_for_exit();
    assert!(status.success(), "normal TUI exit failed: {status}");
    assert_termios_restored(&pty);
    pty.close_and_drain();
    pty.assert_terminal_restored();
}

#[test]
fn capable_terminal_receives_clickable_markdown_link_with_unchanged_visible_text() {
    let provider = LinkProvider::spawn();
    let scratch = Scratch::new("osc8-link");
    scratch.configure_link_provider(&provider.api_root);
    let mut pty = PtyHarness::spawn_link_fixture(&scratch, 80, 24);

    pty.wait_until("OSC 8 Markdown response", |pty| {
        let screen = pty.screen_text();
        screen.contains("Read the guide now.") && screen.contains("done")
    });
    let capture = std::str::from_utf8(&pty.capture).expect("terminal stream is valid UTF-8");
    let opener = format!("\u{1b}]8;;{LINK_TARGET}\u{7}");
    assert!(
        capture.contains(&format!("{opener}th\u{1b}]8;;\u{7}")),
        "PTY stream did not carry the exact self-closing OSC 8 sequence"
    );
    assert!(
        !pty.screen_text().contains(&format!("({LINK_TARGET})")),
        "capable terminal must keep only the Markdown label visible"
    );
    assert!(
        !capture.contains("\u{1b}]8;;javascript:"),
        "only the admitted fixture target may enter OSC 8"
    );

    pty.send(b"\x1b");
    let status = pty.wait_for_exit();
    assert!(status.success(), "normal TUI exit failed: {status}");
    assert_termios_restored(&pty);
    pty.close_and_drain();
    pty.assert_terminal_restored();
    provider.finish();
}

#[test]
fn capable_terminal_receives_one_bounded_osc9_notification_per_run() {
    let provider = LinkProvider::spawn_notification_fixture();
    let scratch = Scratch::new("completion-notification-enabled");
    scratch.configure_link_provider_with_notifications(&provider.api_root, Some(true));
    let mut pty = PtyHarness::spawn_link_fixture(&scratch, 80, 24);

    pty.wait_until("completed run and its OSC 9 notification", |pty| {
        pty.screen_text()
            .contains("Notification fixture row remains intact.")
            && pty.screen_text().contains("done")
            && sequence_count(&pty.capture, OSC9_RUN_COMPLETE) > 0
    });
    pty.drain_ready();
    let notifications = pty
        .capture
        .iter()
        .filter(|byte| **byte == TERMINAL_BELL)
        .count();
    assert_eq!(
        notifications, 1,
        "one streamed run must carry one terminated OSC frame at its authoritative boundary"
    );
    assert_eq!(
        sequence_count(&pty.capture, OSC9_RUN_COMPLETE),
        1,
        "the capable production transport must emit exactly one complete OSC 9 frame"
    );
    let screen = pty.screen_text();
    assert!(
        screen
            .lines()
            .any(|line| line.contains("Notification fixture row remains intact.")),
        "the visible response row was corrupted by the out-of-band notification"
    );
    assert!(
        !screen.contains('\x07'),
        "the terminal bell leaked into the visible terminal rows"
    );

    pty.send(b"\x1b");
    let status = pty.wait_for_exit();
    assert!(status.success(), "normal TUI exit failed: {status}");
    assert_termios_restored(&pty);
    pty.close_and_drain();
    pty.assert_terminal_restored();
    provider.finish();
}

#[test]
fn missing_usage_completion_uses_the_server_run_boundary_without_double_notification() {
    let provider = LinkProvider::spawn_missing_usage_notification_fixture();
    let scratch = Scratch::new("completion-notification-missing-usage");
    scratch.configure_link_provider_with_notifications(&provider.api_root, Some(true));
    let mut pty = PtyHarness::spawn_link_fixture(&scratch, 80, 24);

    pty.wait_until("missing-usage run completion and OSC 9 frame", |pty| {
        pty.screen_text()
            .contains("Missing-usage completion still notifies.")
            && pty.screen_text().contains("done")
            && sequence_count(&pty.capture, OSC9_RUN_COMPLETE) > 0
    });
    pty.drain_ready();
    assert_eq!(
        pty.capture
            .iter()
            .filter(|byte| **byte == TERMINAL_BELL)
            .count(),
        1,
        "the App Server RunEnded boundary must notify exactly once even without provider usage"
    );
    assert_eq!(sequence_count(&pty.capture, OSC9_RUN_COMPLETE), 1);
    assert!(
        pty.screen_text()
            .contains("Missing-usage completion still notifies."),
        "run-complete notification corrupted the completed response row"
    );

    pty.send(b"\x1b");
    let status = pty.wait_for_exit();
    assert!(status.success(), "normal TUI exit failed: {status}");
    assert_termios_restored(&pty);
    pty.close_and_drain();
    pty.assert_terminal_restored();
    provider.finish();
}

#[test]
fn default_off_ignores_project_attempt_to_enable_completion_notifications() {
    let provider = LinkProvider::spawn_notification_fixture();
    let scratch = Scratch::new("completion-notification-project-ignored");
    scratch.configure_link_provider_with_notifications(&provider.api_root, None);
    scratch.configure_project_notifications(true);
    let mut pty = PtyHarness::spawn_link_fixture(&scratch, 80, 24);

    pty.wait_until("completed turn with notifications disabled", |pty| {
        pty.screen_text()
            .contains("Notification fixture row remains intact.")
            && pty.screen_text().contains("done")
    });
    pty.drain_ready();
    assert!(
        !pty.capture.contains(&TERMINAL_BELL),
        "repository configuration must not enable terminal control output"
    );
    assert!(
        std::str::from_utf8(&pty.capture)
            .expect("terminal stream is UTF-8")
            .contains("ignoring `completion_notifications` in the project config"),
        "the untrusted project preference was not surfaced as ignored"
    );
    assert!(
        pty.screen_text()
            .contains("Notification fixture row remains intact."),
        "disabled notification handling changed the visible row"
    );

    pty.send(b"\x1b");
    let status = pty.wait_for_exit();
    assert!(status.success(), "normal TUI exit failed: {status}");
    assert_termios_restored(&pty);
    pty.close_and_drain();
    pty.assert_terminal_restored();
    provider.finish();
}

#[test]
fn active_ctrl_d_drains_to_a_checkpoint_and_idle_ctrl_d_still_exits() {
    let provider = BlockingLinkProvider::spawn();
    let scratch = Scratch::new("ctrl-d-drain");
    scratch.initialize_git_workspace();
    std::fs::write(scratch.repo().join("state.txt"), "state visible at drain\n")
        .expect("write checkpoint fixture state");
    scratch.configure_link_provider(&provider.api_root);
    let mut pty = PtyHarness::spawn_link_fixture(&scratch, 86, 24);

    provider
        .started
        .recv_timeout(PROVIDER_TIMEOUT)
        .expect("provider turn is admitted before Ctrl-D");
    pty.send(b"\x04");
    pty.wait_until("active Ctrl-D drain status", |pty| {
        let screen = pty.screen_text();
        screen.contains("draining") && screen.contains("checkpoint")
    });
    provider
        .release
        .send(())
        .expect("release the admitted provider turn");
    pty.wait_until("durable drained terminal", |pty| {
        pty.screen_text().contains("drained")
    });

    // Once idle again, Ctrl-D retains its shell-like exit behavior.
    pty.send(b"\x04");
    let status = pty.wait_for_exit();
    assert!(status.success(), "idle Ctrl-D exit failed: {status}");
    assert_termios_restored(&pty);
    pty.close_and_drain();
    pty.assert_terminal_restored();
    provider.finish();

    let rollout_path = std::fs::read_dir(scratch.runs())
        .expect("read drain rollout directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "jsonl")
        })
        .expect("drain rollout exists");
    let events = core_record::replay(&rollout_path).expect("drain rollout replays");
    let checkpoints = events
        .iter()
        .filter_map(|event| match &event.kind {
            core_protocol::EventKind::Checkpoint { tree_ref, .. } => Some(tree_ref),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(checkpoints.len(), 1, "active Ctrl-D makes one checkpoint");
    assert!(events.iter().any(|event| matches!(
        &event.kind,
        core_protocol::EventKind::Done { outcome } if outcome == "Drained"
    )));
    let tree = std::process::Command::new("git")
        .args(["ls-tree", "-r", "--name-only", checkpoints[0]])
        .current_dir(scratch.repo())
        .output()
        .expect("inspect drain checkpoint tree");
    assert!(tree.status.success());
    assert!(String::from_utf8_lossy(&tree.stdout).contains("state.txt"));
}

#[test]
fn mouse_capture_toggle_releases_selection_and_restores_wheel_and_fold() {
    let scratch = Scratch::new("mouse-toggle");
    let mut pty = PtyHarness::spawn(&scratch, 80, 24);
    wait_for_ready(&mut pty);

    // Ctrl-T releases terminal mouse protocols, which is the PTY-observable condition for native
    // terminal selection/copy owning drag events again.
    pty.send(b"\x14");
    pty.wait_until("native terminal selection mode", |pty| {
        let screen = pty.parser.screen();
        screen.mouse_protocol_mode() == vt100::MouseProtocolMode::None
            && screen.contents().contains("selection:on")
            && screen.contents().contains("ctrl+t mouse")
    });

    pty.send(b"\x14");
    pty.wait_until("mouse capture re-enabled", |pty| {
        let screen = pty.parser.screen();
        screen.mouse_protocol_mode() != vt100::MouseProtocolMode::None
            && screen.contents().contains("mouse:on")
            && screen.contents().contains("ctrl+t select")
    });

    // A long local-only shell card gives both mouse behaviors a real transcript target. SGR wheel
    // input must leave follow mode, then an SGR click on a visible body row must fold that card.
    pty.send(b"!seq 1 80 | sed 's/^/fold-me-/'\r");
    pty.wait_until("long shell card", |pty| {
        pty.screen_text().contains("fold-me-80")
    });
    pty.send(b"\x1b[<64;2;2M");
    pty.wait_until("wheel scrolling transcript history", |pty| {
        pty.screen_text().contains("reading history")
    });

    let (row, visible_marker) = pty
        .screen_text()
        .lines()
        .enumerate()
        .find_map(|(row, line)| {
            (2..80)
                .map(|index| format!("fold-me-{index}"))
                .find(|marker| line.contains(marker))
                .map(|marker| (row, marker))
        })
        .expect("wheel-scrolled tool body exposes a numbered row");
    let click = format!("\x1b[<0;2;{}M", row + 1);
    pty.send(click.as_bytes());
    pty.wait_until("click-to-fold after capture was re-enabled", |pty| {
        !pty.screen_text().contains(&visible_marker)
    });

    // Teardown also starts from the operator-released state; the other lifecycle tests exercise
    // normal and signal exits while capture is still active.
    pty.send(b"\x14");
    pty.wait_until("selection mode before teardown", |pty| {
        pty.parser.screen().mouse_protocol_mode() == vt100::MouseProtocolMode::None
    });
    pty.send(b"\x1b");
    let status = pty.wait_for_exit();
    assert!(status.success(), "normal TUI exit failed: {status}");
    assert_termios_restored(&pty);
    pty.close_and_drain();
    pty.assert_terminal_restored();
}

#[test]
fn kitty_keyboard_shift_enter_inserts_newline_and_drop_pops_flags() {
    let scratch = Scratch::new("kitty-shift-enter");
    let mut pty = PtyHarness::spawn_kitty_keyboard_fixture(&scratch, 80, 24);
    wait_for_ready(&mut pty);
    // Negotiation runs behind the first frame now, so the push follows the painted surface instead
    // of preceding it. Waiting keeps this assertion about the OUTCOME of negotiation; the ordering
    // itself is pinned by `capability_probes_are_written_after_the_first_painted_frame`.
    pty.wait_until("positive keyboard-enhancement negotiation", |pty| {
        sequence_count(&pty.capture, KEYBOARD_ENHANCEMENT_PUSH) == 1
    });
    assert_eq!(
        sequence_count(&pty.capture, KEYBOARD_ENHANCEMENT_POP),
        0,
        "the live TUI must retain its keyboard-enhancement stack frame"
    );

    pty.send(b"enhanced-first");
    // Kitty CSI-u: CR (13), modifier mask 2 (Shift). Crossterm must surface this as
    // KeyCode::Enter + KeyModifiers::SHIFT, not as an ordinary submitting Enter.
    pty.send(b"\x1b[13;2u");
    pty.send(b"enhanced-second");
    pty.wait_until("Shift+Enter multiline composer", |pty| {
        let screen = pty.screen_text();
        screen.contains("enhanced-first") && screen.contains("enhanced-second")
    });
    assert_draft_rows(&pty.screen_text(), "enhanced-first", "enhanced-second");

    pty.send(b"\x1b[27u");
    pty.wait_until("enhanced Esc clears the multiline draft", |pty| {
        !pty.screen_text().contains("enhanced-first")
    });
    pty.send(b"\x1b[27u");
    let status = pty.wait_for_exit();
    assert!(status.success(), "normal TUI exit failed: {status}");
    assert_termios_restored(&pty);
    pty.close_and_drain();
    pty.assert_terminal_restored();
    pty.assert_keyboard_enhanced_and_restored();
}

#[test]
fn unsupported_keyboard_keeps_ctrl_j_fallback_without_stack_sequences() {
    let scratch = Scratch::new("ctrl-j-keyboard-fallback");
    let mut pty = PtyHarness::spawn(&scratch, 80, 24);
    wait_for_ready(&mut pty);
    // Same deferral as the Kitty fixture: the query is written after the frame, so the answer is
    // waited for rather than assumed to have already happened by the time the surface appears.
    pty.wait_until("the deferred keyboard capability query", |pty| {
        pty.keyboard_query_answered
    });
    assert_eq!(
        sequence_count(&pty.capture, KEYBOARD_ENHANCEMENT_PUSH),
        0,
        "negative negotiation must not push keyboard flags"
    );

    pty.send(b"fallback-first\x0afallback-second");
    pty.wait_until("Ctrl-J multiline fallback", |pty| {
        let screen = pty.screen_text();
        screen.contains("fallback-first") && screen.contains("fallback-second")
    });
    let screen = pty.screen_text();
    assert_draft_rows(&screen, "fallback-first", "fallback-second");
    for leaked in ["[?u", "[>1u", "[<1u"] {
        assert!(
            !screen.contains(leaked),
            "keyboard protocol bytes leaked into the fallback terminal snapshot: {leaked}"
        );
    }

    pty.send(b"\x1b");
    pty.wait_until("fallback Esc clears the multiline draft", |pty| {
        !pty.screen_text().contains("fallback-first")
    });
    pty.send(b"\x1b");
    let status = pty.wait_for_exit();
    assert!(status.success(), "normal TUI exit failed: {status}");
    assert_termios_restored(&pty);
    pty.close_and_drain();
    pty.assert_terminal_restored();
    assert_eq!(
        sequence_count(&pty.capture, KEYBOARD_ENHANCEMENT_POP),
        0,
        "unsupported terminal must not receive a stack pop"
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
    let mut pty = PtyHarness::spawn_kitty_keyboard_fixture(&scratch, 80, 24);
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
    pty.assert_keyboard_enhanced_and_restored();
}

#[test]
fn sighup_from_open_picker_restores_keyboard_and_terminal_modes() {
    let scratch = Scratch::new("sighup");
    let mut pty = PtyHarness::spawn_kitty_keyboard_fixture(&scratch, 80, 24);
    wait_for_ready(&mut pty);

    pty.send(b"/effort\r");
    pty.wait_until("cursor-owning Effort picker", |pty| {
        let screen = pty.parser.screen();
        screen.contents().contains("Effort") && screen.hide_cursor()
    });
    let pid = i32::try_from(pty.process_id()).expect("child pid fits pid_t");
    // SAFETY: `pid` is the direct child returned by portable-pty and is still live here.
    let sent = unsafe { libc::kill(pid, libc::SIGHUP) };
    assert_eq!(
        sent,
        0,
        "send SIGHUP to Core: {}",
        std::io::Error::last_os_error()
    );

    let status = pty.wait_for_exit();
    assert_eq!(status.exit_code(), 143, "unexpected SIGHUP exit: {status}");
    assert_termios_restored(&pty);
    pty.close_and_drain();
    pty.assert_terminal_restored();
    pty.assert_keyboard_enhanced_and_restored();
}
