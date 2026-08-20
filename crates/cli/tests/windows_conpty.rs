#![cfg(windows)]

//! Native Windows terminal oracle.
//!
//! `portable-pty::native_pty_system` is the ConPTY implementation on Windows. This launches the
//! integration-test executable as a same-console wrapper, which launches the real binary, observes
//! the shared App Server version handshake, drives Unicode VT input, resizes the pseudoconsole, and
//! records the exact console input mode before, during, and after Core. The protocol types and
//! composition root are exactly the ones exercised by the Unix PTY oracle.

use iteron_protocol::PROTOCOL_VERSION;
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, SlavePty, native_pty_system};
use serde_json::json;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const STEP_TIMEOUT: Duration = Duration::from_secs(20);
const PROVIDER_TIMEOUT: Duration = Duration::from_secs(20);
const PROVIDER_IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CAPTURE_BYTES: usize = 2 * 1024 * 1024;
const MAX_PROVIDER_REQUEST_BYTES: usize = 1024 * 1024;
const LINK_PROVIDER_ID: &str = "windows-conpty-fixture";
const LINK_MODEL_ID: &str = "windows-conpty-model";
const LINK_TEST_KEY_ENV: &str = "ITERON_WINDOWS_CONPTY_TEST_KEY";
const LINK_TEST_KEY: &str = "bounded-loopback-placeholder";
const LINK_TARGET: &str = "https://example.com/windows-conpty";
const LINK_RESPONSE: &str = "Read [the Windows guide](https://example.com/windows-conpty) now.";
const LINK_TASK: &str = "Return the bounded Windows ConPTY fixture.";
const OSC9_RUN_COMPLETE: &[u8] = b"\x1b]9;Iteron: run complete\x07";
const OSC777_RUN_COMPLETE: &[u8] = b"\x1b]777;notify;Iteron;Run complete\x07";
const KEYBOARD_ENHANCEMENT_QUERY: &[u8] = b"\x1b[?u\x1b[c";
const KEYBOARD_ENHANCEMENT_PUSH: &[u8] = b"\x1b[>1u";
const KEYBOARD_ENHANCEMENT_POP: &[u8] = b"\x1b[<1u";
const CURSOR_POSITION_QUERY: &[u8] = b"\x1b[6n";
const UNICODE_DRAFT: &str = "请检查 Windows ConPTY 😀";
const WRAPPER_ACTIVE_ENV: &str = "ITERON_WINDOWS_CONPTY_WRAPPER_ACTIVE";
const WRAPPER_ITERON_BINARY_ENV: &str = "ITERON_WINDOWS_CONPTY_WRAPPER_ITERON_BINARY";
const WRAPPER_REPO_ENV: &str = "ITERON_WINDOWS_CONPTY_WRAPPER_REPO";
const WRAPPER_RUNS_ENV: &str = "ITERON_WINDOWS_CONPTY_WRAPPER_RUNS";
const WRAPPER_PROVIDER_ENV: &str = "ITERON_WINDOWS_CONPTY_WRAPPER_PROVIDER";
const WRAPPER_MODEL_ENV: &str = "ITERON_WINDOWS_CONPTY_WRAPPER_MODEL";
const WRAPPER_TASK_ENV: &str = "ITERON_WINDOWS_CONPTY_WRAPPER_TASK";
const WRAPPER_EXPECT_RAW_ENV: &str = "ITERON_WINDOWS_CONPTY_WRAPPER_EXPECT_RAW";
const CONSOLE_MODE_BEFORE: &[u8] = b"ITERON_CONSOLE_INPUT_MODE_BEFORE=";
const CONSOLE_MODE_DURING: &[u8] = b"ITERON_CONSOLE_INPUT_MODE_DURING=";
const CONSOLE_MODE_AFTER: &[u8] = b"ITERON_CONSOLE_INPUT_MODE_AFTER=";
const CONSOLE_MODE_RESTORED: &[u8] = b"ITERON_CONSOLE_INPUT_MODE_RESTORED=";
const CONSOLE_MODE_EVIDENCE_PATH_ENV: &str = "ITERON_CONSOLE_MODE_EVIDENCE_PATH";
const COOKED_INPUT_MODE_MASK: u32 = 0x0001 | 0x0002 | 0x0004;
const RAW_MODE_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a drop may wait for the reader thread. It is short on purpose: by the time this
/// matters the test has already failed, and the only question left is whether the failure gets
/// reported or replaced by a step timeout.
const READER_JOIN_TIMEOUT: Duration = Duration::from_secs(5);
static NEXT_ID: AtomicU64 = AtomicU64::new(0);

const WRAPPER_CONTROL_ENV: &[&str] = &[
    WRAPPER_ACTIVE_ENV,
    WRAPPER_ITERON_BINARY_ENV,
    WRAPPER_REPO_ENV,
    WRAPPER_RUNS_ENV,
    WRAPPER_PROVIDER_ENV,
    WRAPPER_MODEL_ENV,
    WRAPPER_TASK_ENV,
    WRAPPER_EXPECT_RAW_ENV,
];

#[link(name = "kernel32")]
unsafe extern "system" {
    #[link_name = "GetConsoleMode"]
    fn get_console_mode(console: *mut std::ffi::c_void, mode: *mut u32) -> i32;
}

struct ConsoleInput {
    handle: std::fs::File,
}

impl ConsoleInput {
    fn current() -> std::io::Result<Self> {
        let handle = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("CONIN$")?;
        Ok(Self { handle })
    }

    fn mode(&self) -> std::io::Result<u32> {
        use std::os::windows::io::AsRawHandle as _;

        let mut mode = 0_u32;
        // SAFETY: `handle` is an open `CONIN$` handle owned by this wrapper and `mode` points to
        // initialized writable storage for the duration of the call.
        let result = unsafe { get_console_mode(self.handle.as_raw_handle(), &mut mode) };
        if result == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(mode)
        }
    }
}

fn required_wrapper_variable(name: &str) -> std::ffi::OsString {
    std::env::var_os(name)
        .unwrap_or_else(|| panic!("missing native ConPTY wrapper variable {name}"))
}

fn wrapped_core_command() -> Command {
    let binary = required_wrapper_variable(WRAPPER_ITERON_BINARY_ENV);
    let repo = required_wrapper_variable(WRAPPER_REPO_ENV);
    let runs = required_wrapper_variable(WRAPPER_RUNS_ENV);
    let provider = required_wrapper_variable(WRAPPER_PROVIDER_ENV);
    let model = required_wrapper_variable(WRAPPER_MODEL_ENV);
    let task = std::env::var_os(WRAPPER_TASK_ENV);

    let mut command = Command::new(binary);
    for name in WRAPPER_CONTROL_ENV {
        command.env_remove(name);
    }
    command
        .arg("--tui")
        .arg("--repo")
        .arg(repo)
        .arg("--runs-dir")
        .arg(runs)
        .arg("--provider")
        .arg(provider)
        .arg("--model")
        .arg(model)
        .arg("--effort")
        .arg("low")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if let Some(task) = task {
        command.arg(task);
    }
    command
}

fn emit_console_input_modes(before: u32, during: Option<u32>, after: u32, restored: Option<u32>) {
    let during = during.map_or_else(|| "missing".to_owned(), |mode| format!("{mode:08x}"));
    let restored = restored.map_or_else(|| "missing".to_owned(), |mode| format!("{mode:08x}"));
    let evidence = format!(
        "\r\n{}{:08x}\r\n{}{during}\r\n{}{:08x}\r\n{}{restored}\r\n",
        std::str::from_utf8(CONSOLE_MODE_BEFORE).expect("mode marker is ASCII"),
        before,
        std::str::from_utf8(CONSOLE_MODE_DURING).expect("mode marker is ASCII"),
        std::str::from_utf8(CONSOLE_MODE_AFTER).expect("mode marker is ASCII"),
        after,
        std::str::from_utf8(CONSOLE_MODE_RESTORED).expect("mode marker is ASCII"),
    );
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(evidence.as_bytes())
        .expect("write native console-mode evidence");
    stdout.flush().expect("flush native console-mode evidence");
}

/// The outer test executable launches this one filtered test through ConPTY. This process owns the
/// console while Core is its child, so all three `GetConsoleMode` observations refer to the same
/// input buffer. A normal `cargo test` invocation leaves the control variable absent and this
/// helper returns without recursively launching Core.
#[test]
fn native_console_mode_wrapper_process() {
    let Some(active) = std::env::var_os(WRAPPER_ACTIVE_ENV) else {
        return;
    };
    assert_eq!(active.to_str(), Some("1"), "{WRAPPER_ACTIVE_ENV} must be 1");

    let expect_raw = required_wrapper_variable(WRAPPER_EXPECT_RAW_ENV);
    let expect_raw = match expect_raw.to_str() {
        Some("0") => false,
        Some("1") => true,
        _ => panic!("{WRAPPER_EXPECT_RAW_ENV} must be 0 or 1"),
    };
    let console_input = ConsoleInput::current().expect("open the current ConPTY input buffer");
    let before = console_input
        .mode()
        .expect("read cooked ConPTY input mode before Core");
    let mut child = wrapped_core_command()
        .spawn()
        .expect("launch Core inside the same native console");

    let mut exited = None;
    let during = if expect_raw {
        let deadline = Instant::now() + RAW_MODE_OBSERVATION_TIMEOUT;
        loop {
            let mode = console_input
                .mode()
                .expect("observe live ConPTY input mode");
            if mode & COOKED_INPUT_MODE_MASK == 0 {
                break Some(mode);
            }
            if let Some(status) = child.try_wait().expect("poll wrapped Core process") {
                exited = Some(status);
                break None;
            }
            if Instant::now() >= deadline {
                break None;
            }
            thread::sleep(Duration::from_millis(5));
        }
    } else {
        None
    };

    let status = match exited {
        Some(status) => status,
        None => child.wait().expect("wait for wrapped Core process"),
    };
    let after = console_input
        .mode()
        .expect("read ConPTY input mode after Core");
    let restored = std::env::var_os(CONSOLE_MODE_EVIDENCE_PATH_ENV)
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|text| {
            text.trim()
                .strip_prefix("ITERON_CONSOLE_INPUT_MODE_RESTORED=")
                .and_then(|value| u32::from_str_radix(value, 16).ok())
        });
    emit_console_input_modes(before, during, after, restored);
    std::process::exit(status.code().unwrap_or(1));
}

struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("core-windows-conpty-{}-{id}", std::process::id()));
        std::fs::create_dir_all(root.join("home")).expect("create isolated Core home");
        std::fs::create_dir_all(root.join("repo")).expect("create isolated repository");
        std::fs::create_dir_all(root.join("runs")).expect("create isolated rollout directory");
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

    fn console_mode_evidence(&self) -> PathBuf {
        self.root.join("console-mode-evidence.txt")
    }

    fn configure_link_provider_with_notifications(&self, api_root: &str) {
        let config_dir = self.home().join(".iteron");
        std::fs::create_dir_all(&config_dir).expect("create isolated Core config directory");
        let config = json!({
            "schema_version": 2,
            "provider": LINK_PROVIDER_ID,
            "model": LINK_MODEL_ID,
            "effort": "low",
            "max_wall_secs": 10,
            "completion_notifications": true,
            "providers": [{
                "id": LINK_PROVIDER_ID,
                "display_name": "Windows ConPTY fixture provider",
                "adapter": "openai_chat",
                "error_profile": "custom",
                "api_root": api_root,
                "key_env": LINK_TEST_KEY_ENV,
                "enabled": true,
                "catalog": false,
                "models": [LINK_MODEL_ID]
            }]
        });
        std::fs::write(
            config_dir.join("config.json"),
            serde_json::to_vec(&config).expect("encode isolated provider config"),
        )
        .expect("write isolated provider config");
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
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("bind bounded loopback Windows provider");
        listener
            .set_nonblocking(true)
            .expect("make Windows provider accept bounded");
        let address = listener
            .local_addr()
            .expect("read Windows provider address");
        let handle = thread::spawn(move || {
            let mut stream = accept_provider_connection(&listener);
            read_provider_request(&mut stream);
            stream
                .set_write_timeout(Some(PROVIDER_IO_TIMEOUT))
                .expect("bound Windows provider write");
            let content =
                serde_json::to_string(LINK_RESPONSE).expect("encode Windows fixture content");
            let body = format!(
                concat!(
                    "data: {{\"id\":\"chatcmpl-windows-conpty\",\"object\":\"chat.completion.chunk\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\",\"content\":{}}},\"finish_reason\":null}}],\"usage\":null}}\n\n",
                    "data: {{\"id\":\"chatcmpl-windows-conpty\",\"object\":\"chat.completion.chunk\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}],\"usage\":null}}\n\n",
                    "data: {{\"id\":\"chatcmpl-windows-conpty\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{{\"prompt_tokens\":9,\"completion_tokens\":8,\"total_tokens\":17,\"prompt_tokens_details\":{{\"cached_tokens\":0}},\"completion_tokens_details\":{{\"reasoning_tokens\":0}}}}}}\n\n",
                    "data: [DONE]\n\n"
                ),
                content,
            );
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .expect("write Windows provider response");
            stream.flush().expect("flush Windows provider response");
        });
        Self {
            api_root: format!("http://{address}/v1"),
            handle: Some(handle),
        }
    }

    fn finish(mut self) {
        self.handle
            .take()
            .expect("Windows provider thread exists")
            .join()
            .expect("Windows provider completed cleanly");
    }
}

fn accept_provider_connection(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + PROVIDER_TIMEOUT;
    loop {
        match listener.accept() {
            Ok((stream, address)) => {
                assert!(
                    address.ip().is_loopback(),
                    "Windows fixture accepted a non-loopback peer"
                );
                stream
                    .set_nonblocking(false)
                    .expect("make accepted Windows provider stream blocking");
                stream
                    .set_read_timeout(Some(PROVIDER_IO_TIMEOUT))
                    .expect("bound Windows provider read");
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "Core never connected to the bounded Windows provider"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("Windows provider accept failed: {error}"),
        }
    }
}

fn read_provider_request(stream: &mut TcpStream) {
    let mut request = Vec::new();
    let mut expected = None;
    loop {
        let mut chunk = [0_u8; 8 * 1024];
        let read = stream
            .read(&mut chunk)
            .expect("read Windows provider request");
        assert!(read > 0, "Windows provider request ended before its body");
        request.extend_from_slice(&chunk[..read]);
        assert!(
            request.len() <= MAX_PROVIDER_REQUEST_BYTES,
            "Windows provider request exceeded its deterministic bound"
        );
        if expected.is_none()
            && let Some(headers_end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n")
        {
            let headers = std::str::from_utf8(&request[..headers_end])
                .expect("Windows provider headers are UTF-8");
            let lowercase_headers = headers.to_ascii_lowercase();
            assert!(
                lowercase_headers.contains("authorization: bearer bounded-loopback-placeholder"),
                "Windows fixture did not receive the inert loopback credential"
            );
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().expect("valid content-length"))
                })
                .expect("Windows provider request has content-length");
            expected = Some(headers_end + 4 + content_length);
        }
        if expected.is_some_and(|expected| request.len() >= expected) {
            assert!(
                contains(&request, LINK_TASK.as_bytes()),
                "Windows provider did not receive the scripted fixture task"
            );
            return;
        }
    }
}

struct ConPty {
    master: Option<Box<dyn MasterPty + Send>>,
    slave: Option<Box<dyn SlavePty + Send>>,
    child: Option<Box<dyn Child + Send + Sync>>,
    writer: Option<Box<dyn Write + Send>>,
    chunks: Receiver<Vec<u8>>,
    reader_thread: Option<JoinHandle<()>>,
    reader_closed: bool,
    parser: vt100::Parser,
    capture: Vec<u8>,
    cursor_queries_answered: usize,
}

#[derive(Clone, Copy)]
enum TerminalFixture {
    WindowsTerminal,
    Conhost,
}

impl ConPty {
    fn spawn_keyboard_supported(scratch: &Scratch, cols: u16, rows: u16) -> Self {
        Self::spawn_configured(
            scratch,
            cols,
            rows,
            None,
            false,
            TerminalFixture::WindowsTerminal,
        )
    }

    fn spawn_link_fixture(
        scratch: &Scratch,
        cols: u16,
        rows: u16,
        terminal: TerminalFixture,
    ) -> Self {
        Self::spawn_configured(scratch, cols, rows, None, true, terminal)
    }

    fn spawn_with_server_version(
        scratch: &Scratch,
        cols: u16,
        rows: u16,
        server_version: Option<u32>,
    ) -> Self {
        Self::spawn_configured(
            scratch,
            cols,
            rows,
            server_version,
            false,
            TerminalFixture::WindowsTerminal,
        )
    }

    fn spawn_configured(
        scratch: &Scratch,
        cols: u16,
        rows: u16,
        server_version: Option<u32>,
        link_fixture: bool,
        terminal: TerminalFixture,
    ) -> Self {
        let pair = native_pty_system()
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("open native Windows ConPTY");
        let provider = if link_fixture {
            LINK_PROVIDER_ID
        } else {
            "glm"
        };
        let model = if link_fixture {
            LINK_MODEL_ID
        } else {
            "glm-5.2"
        };
        let wrapper =
            std::env::current_exe().expect("resolve the native ConPTY integration-test executable");
        let mut command = CommandBuilder::new(wrapper);
        command.env_clear();
        copy_host_variable(&mut command, "PATH");
        copy_host_variable(&mut command, "SystemRoot");
        copy_host_variable(&mut command, "WINDIR");
        // A stock native Windows process has USERPROFILE but need not have HOME. Keep HOME absent so
        // the oracle also proves operator-owned configuration resolves through the native spelling.
        command.env("USERPROFILE", scratch.home().as_os_str());
        command.env("TEMP", std::env::temp_dir().as_os_str());
        command.env("TMP", std::env::temp_dir().as_os_str());
        command.env("TERM", "xterm-256color");
        if matches!(terminal, TerminalFixture::WindowsTerminal) {
            command.env("WT_SESSION", "core-native-conpty-oracle");
        }
        command.env("ITERON_THEME", "terminal");
        // ConPTY cannot deliver a harness-injected CSI-u reply as Crossterm key events; the probe
        // response leaks into the composer and prevents the run from completing. Disable the probe
        // so the Windows oracle exercises links, notifications, Unicode, resize, and console-mode
        // restoration without relying on a response the transport cannot faithfully simulate.
        command.env("ITERON_NO_KBD_ENHANCEMENT", "1");
        command.env(
            CONSOLE_MODE_EVIDENCE_PATH_ENV,
            scratch.console_mode_evidence().as_os_str(),
        );
        if let Some(version) = server_version {
            command.env("ITERON_APP_SERVER_PROTOCOL_VERSION", version.to_string());
        }
        command.env(WRAPPER_ACTIVE_ENV, "1");
        command.env(WRAPPER_ITERON_BINARY_ENV, env!("CARGO_BIN_EXE_iteron"));
        command.env(WRAPPER_REPO_ENV, scratch.repo().as_os_str());
        command.env(WRAPPER_RUNS_ENV, scratch.runs().as_os_str());
        command.env(WRAPPER_PROVIDER_ENV, provider);
        command.env(WRAPPER_MODEL_ENV, model);
        let expect_raw = match server_version {
            Some(version) => version == PROTOCOL_VERSION,
            None => true,
        };
        command.env(WRAPPER_EXPECT_RAW_ENV, if expect_raw { "1" } else { "0" });
        if link_fixture {
            command.env(WRAPPER_TASK_ENV, LINK_TASK);
        }
        command.cwd(scratch.repo());
        command.arg("native_console_mode_wrapper_process");
        command.arg("--exact");
        command.arg("--nocapture");
        command.arg("--test-threads=1");
        if link_fixture {
            command.env("NO_PROXY", "127.0.0.1,localhost");
            command.env(LINK_TEST_KEY_ENV, LINK_TEST_KEY);
        } else {
            command.env("ITERON_PROVIDER", "glm");
            command.env("ITERON_MODEL", "glm-5.2");
        }

        let child = pair
            .slave
            .spawn_command(command)
            .expect("spawn the same-console Core wrapper through ConPTY");
        let mut reader = pair.master.try_clone_reader().expect("clone ConPTY reader");
        let writer = pair.master.take_writer().expect("take ConPTY writer");
        let (sender, chunks) = mpsc::channel();
        let reader_thread = thread::spawn(move || {
            let mut buffer = [0_u8; 8 * 1024];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => {
                        if sender.send(buffer[..read].to_vec()).is_err() {
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
            cursor_queries_answered: 0,
        }
    }

    fn ingest(&mut self, chunk: Vec<u8>) {
        assert!(
            self.capture.len().saturating_add(chunk.len()) <= MAX_CAPTURE_BYTES,
            "ConPTY output exceeded the deterministic capture bound"
        );
        self.parser.process(&chunk);
        self.capture.extend_from_slice(&chunk);
        let cursor_query_count = sequence_count(&self.capture, CURSOR_POSITION_QUERY);
        while self.cursor_queries_answered < cursor_query_count {
            self.cursor_queries_answered += 1;
            let (row, column) = self.parser.screen().cursor_position();
            self.send(format!("\x1b[{};{}R", row + 1, column + 1).as_bytes());
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
        let writer = self.writer.as_mut().expect("ConPTY writer is open");
        writer.write_all(bytes).expect("write ConPTY input");
        writer.flush().expect("flush ConPTY input");
    }

    fn resize(&mut self, cols: u16, rows: u16) {
        self.drain_ready();
        let before = self.capture.len();
        self.parser.set_size(rows, cols);
        self.master
            .as_ref()
            .expect("ConPTY master is open")
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("resize native ConPTY");
        self.wait_until(&format!("redraw at {cols}x{rows}"), |pty| {
            pty.capture.len() > before
                && pty.parser.screen().size() == (rows, cols)
                && pty.screen_text().contains("请检查 Windows")
                && !pty.screen_text().contains('�')
        });
        let (cursor_row, cursor_col) = self.parser.screen().cursor_position();
        assert!(cursor_row < rows, "cursor row escaped the resized viewport");
        assert!(
            cursor_col < cols,
            "cursor column escaped the resized viewport"
        );
    }

    fn wait_for_exit(&mut self) -> portable_pty::ExitStatus {
        let deadline = Instant::now() + STEP_TIMEOUT;
        while Instant::now() < deadline {
            if let Some(status) = self
                .child
                .as_mut()
                .expect("ConPTY child exists")
                .try_wait()
                .expect("poll ConPTY child")
            {
                self.drain_ready();
                return status;
            }
            let _ = self.pump_once(Duration::from_millis(25));
        }
        panic!(
            "Core did not exit before the ConPTY deadline; current terminal:\n{}",
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
        assert!(self.reader_closed, "ConPTY reader did not reach EOF");
        if let Some(reader) = self.reader_thread.take() {
            reader.join().expect("join ConPTY reader");
        }
    }

    fn assert_console_input_mode_restored(&self, expect_raw_observation: bool) {
        let before = console_mode_marker(&self.capture, CONSOLE_MODE_BEFORE, "before")
            .expect("same-console wrapper did not report its initial input mode");
        let during = console_mode_marker(&self.capture, CONSOLE_MODE_DURING, "during");
        let after = console_mode_marker(&self.capture, CONSOLE_MODE_AFTER, "after")
            .expect("same-console wrapper did not report its final input mode");
        let restored = restored_console_mode(&self.capture);

        assert_eq!(
            before & COOKED_INPUT_MODE_MASK,
            COOKED_INPUT_MODE_MASK,
            "same-console wrapper did not start with processed, line, and echo input enabled \
             (mode 0x{before:08x})"
        );

        if expect_raw_observation {
            let during =
                during.expect("same-console wrapper never observed Core's live raw input mode");
            assert_eq!(
                during & COOKED_INPUT_MODE_MASK,
                0,
                "Core's live input mode retained a cooked-input flag (mode 0x{during:08x})"
            );
            assert_ne!(
                during, before,
                "same-console wrapper did not observe an input-mode transition"
            );
            let restored =
                restored.expect("Core did not report its restored input mode before exiting");
            assert_eq!(
                restored, before,
                "Core did not restore the shared console input mode before exit \
                 (before 0x{before:08x}, restored 0x{restored:08x})"
            );
            // ConPTY resets the shared input mode after the last attached client disconnects, so
            // the wrapper's post-exit observation may legitimately differ from the mode Core left.
            // The child-reported restored value above is the authoritative check.
            let _ = after;
        } else {
            assert!(
                during.is_none(),
                "the pre-takeover refusal unexpectedly reported a live raw input mode"
            );
            assert!(
                restored.is_none(),
                "Core reported a restored input mode but never took over the terminal"
            );
            assert_eq!(
                after, before,
                "the pre-takeover refusal changed the shared console input mode \
                 (before 0x{before:08x}, after 0x{after:08x})"
            );
        }
    }
}

impl Drop for ConPty {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            // `kill` signals the wrapper and nothing below it. The wrapper launches the real
            // binary as a grandchild inside this same pseudoconsole, so signalling only the
            // wrapper leaves that grandchild holding the ConPTY write handle open. The reader
            // below then blocks forever — `read` returns 0 only once every writer is gone — and
            // the abandoned process keeps its console host spinning on a core. A failing
            // assertion would stop reporting the failure and hang the whole test binary
            // instead. Take the console's process tree down before waiting on anything.
            if let Some(pid) = child.process_id() {
                let _ = Command::new("taskkill")
                    .args(["/T", "/F", "/PID", &pid.to_string()])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        drop(self.writer.take());
        drop(self.slave.take());
        drop(self.master.take());
        if let Some(reader) = self.reader_thread.take() {
            // Bounded. `read` returns 0 only once every writer is gone, and the pseudoconsole host
            // is a child of *this* process rather than of the wrapper, so the tree kill above does
            // not necessarily reach it -- a `conhost --headless` was measured on the self-hosted
            // runner sitting at 100% of a core with no client under it, still holding the write
            // end. A reader thread left behind in a process that is about to exit costs nothing; a
            // join with no deadline costs the whole job and replaces a reported assertion failure
            // with a step timeout.
            let (finished, joined) = mpsc::channel();
            thread::spawn(move || {
                let _ = reader.join();
                let _ = finished.send(());
            });
            let _ = joined.recv_timeout(READER_JOIN_TIMEOUT);
        }
    }
}

/// Terminate the `conhost --headless` processes this test process owns.
///
/// Deliberately narrow: it matches only console hosts whose parent is this process, so a host
/// belonging to another job on the same machine is left alone. Shelling out keeps this to the
/// same mechanism the wrapper kill above already uses, rather than introducing process
/// enumeration through a new dependency for a path that only runs while a test is failing.
fn copy_host_variable(command: &mut CommandBuilder, name: &str) {
    if let Some(value) = std::env::var_os(name) {
        command.env(name, value);
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn sequence_count(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

fn console_mode_marker(capture: &[u8], prefix: &[u8], label: &str) -> Option<u32> {
    assert_eq!(
        sequence_count(capture, prefix),
        1,
        "same-console wrapper emitted {label} mode marker an unexpected number of times"
    );
    let offset = capture
        .windows(prefix.len())
        .position(|window| window == prefix)
        .expect("mode marker count and position disagree");
    let payload = &capture[offset + prefix.len()..];
    // The wrapper emits either an 8-digit hex value or the literal "missing". ConPTY can append
    // additional terminal controls (e.g. EL 0) immediately after the value, so stop at the first
    // character that is not part of either form.
    if payload.starts_with(b"missing") {
        return None;
    }
    let hex_end = payload
        .iter()
        .position(|byte| !(*byte).is_ascii_hexdigit())
        .unwrap_or(payload.len());
    let payload = &payload[..hex_end];
    assert_eq!(
        payload.len(),
        8,
        "same-console {label} mode was not an eight-digit hexadecimal value: {:?}",
        std::str::from_utf8(payload).unwrap_or("<invalid UTF-8>")
    );
    let payload =
        std::str::from_utf8(payload).expect("same-console mode marker value must be ASCII");
    Some(
        u32::from_str_radix(payload, 16)
            .unwrap_or_else(|_| panic!("same-console {label} mode was not hexadecimal: {payload}")),
    )
}

fn restored_console_mode(capture: &[u8]) -> Option<u32> {
    let offset = capture
        .windows(CONSOLE_MODE_RESTORED.len())
        .position(|window| window == CONSOLE_MODE_RESTORED)?;
    let payload = &capture[offset + CONSOLE_MODE_RESTORED.len()..];
    if payload.starts_with(b"missing") {
        return None;
    }
    let hex_end = payload
        .iter()
        .position(|byte| !(*byte).is_ascii_hexdigit())
        .unwrap_or(payload.len());
    let payload = &payload[..hex_end];
    assert_eq!(
        payload.len(),
        8,
        "restored mode marker was not an eight-digit hexadecimal value: {:?}",
        std::str::from_utf8(payload).unwrap_or("<invalid UTF-8>")
    );
    let payload = std::str::from_utf8(payload).expect("restored mode marker value must be ASCII");
    u32::from_str_radix(payload, 16).ok()
}

#[test]
fn native_conpty_projects_link_and_exactly_one_capability_selected_notification() {
    let provider = LinkProvider::spawn();
    let scratch = Scratch::new();
    scratch.configure_link_provider_with_notifications(&provider.api_root);
    let mut pty = ConPty::spawn_link_fixture(&scratch, 100, 32, TerminalFixture::WindowsTerminal);
    let osc8_opener = format!("\x1b]8;;{LINK_TARGET}\x07");

    pty.wait_until(
        "linked response and Windows Terminal completion notification",
        |pty| {
            let screen = pty.screen_text();
            screen.contains("Read the Windows guide now.") && screen.contains("idle · input ready")
        },
    );
    pty.drain_ready();
    assert!(
        contains(&pty.capture, osc8_opener.as_bytes()),
        "ConPTY did not receive an OSC 8 opener for the admitted target"
    );
    assert_eq!(
        sequence_count(&pty.capture, OSC9_RUN_COMPLETE),
        1,
        "Windows Terminal must receive exactly one terminated OSC 9 run notification"
    );

    let completed_screen = pty.screen_text();
    assert!(
        !completed_screen.contains(&format!("({LINK_TARGET})")),
        "an admitted HTTPS link leaked its fallback target into visible text"
    );
    assert!(
        !completed_screen.contains('\x07'),
        "an out-of-band terminal control leaked into visible rows"
    );

    pty.send(b"\x1b");
    let status = pty.wait_for_exit();
    assert_eq!(status.exit_code(), 0, "unexpected Core exit: {status}");
    pty.close_and_drain();
    pty.assert_console_input_mode_restored(true);

    let target_openers = sequence_count(&pty.capture, osc8_opener.as_bytes());
    let all_osc8_markers = sequence_count(&pty.capture, b"\x1b]8;;");
    let osc8_closers = sequence_count(&pty.capture, b"\x1b]8;;\x07");
    assert!(
        target_openers > 0,
        "the admitted HTTPS target was not linked"
    );
    assert_eq!(
        target_openers, osc8_closers,
        "every admitted OSC 8 opener must have its own terminator"
    );
    assert_eq!(
        all_osc8_markers,
        target_openers + osc8_closers,
        "an unadmitted OSC 8 target entered the ConPTY stream"
    );

    // WT_SESSION is the explicit capability signal installed in the sanitized child environment.
    // It selects OSC 9 on Windows Terminal; OSC 777 must not be emitted in the same session.
    assert_eq!(
        sequence_count(&pty.capture, b"\x1b]9;") + sequence_count(&pty.capture, b"\x1b]777;"),
        1,
        "one run emitted other, duplicate, or unterminated notification controls"
    );
    assert_eq!(
        sequence_count(&pty.capture, OSC9_RUN_COMPLETE),
        1,
        "Windows Terminal must receive exactly one terminated OSC 9 run notification"
    );
    assert_eq!(
        sequence_count(&pty.capture, OSC777_RUN_COMPLETE),
        0,
        "the OSC 777 fallback was emitted despite the Windows Terminal capability signal"
    );

    // ConTTY may absorb or synthesize alternate-screen restoration itself as the last client
    // disconnects, so the exact escape sequence is not a reliable signal on Windows. The parser
    // state below is the authoritative check that the TUI did not leak the alternate screen.
    assert_eq!(
        sequence_count(&pty.capture, KEYBOARD_ENHANCEMENT_QUERY),
        0,
        "the disabled keyboard-enhancement probe must not emit a query through ConPTY"
    );
    let terminal = pty.parser.screen();
    assert!(!terminal.alternate_screen(), "alternate screen leaked");
    assert!(!terminal.bracketed_paste(), "bracketed paste leaked");
    assert_eq!(
        terminal.mouse_protocol_mode(),
        vt100::MouseProtocolMode::None,
        "mouse capture leaked"
    );
    assert!(!terminal.hide_cursor(), "shell cursor remained hidden");
    assert_eq!(
        sequence_count(&pty.capture, KEYBOARD_ENHANCEMENT_PUSH),
        0,
        "the unsupported terminal received a keyboard-enhancement push"
    );
    assert_eq!(
        sequence_count(&pty.capture, KEYBOARD_ENHANCEMENT_POP),
        0,
        "Core popped a keyboard-enhancement frame it never pushed"
    );
    provider.finish();
}

#[test]
fn native_conpty_conhost_signal_degrades_links_notifications_and_keyboard() {
    let provider = LinkProvider::spawn();
    let scratch = Scratch::new();
    scratch.configure_link_provider_with_notifications(&provider.api_root);
    let mut pty = ConPty::spawn_link_fixture(&scratch, 100, 32, TerminalFixture::Conhost);
    let visible_fallback = format!("Read the Windows guide ({LINK_TARGET}) now.");

    pty.wait_until("conhost-like plain link and BEL completion", |pty| {
        pty.screen_text().contains(&visible_fallback)
            && pty.screen_text().contains("idle · input ready")
    });
    pty.drain_ready();
    let completed_screen = pty.screen_text();

    assert!(
        completed_screen.contains(&visible_fallback),
        "the conhost-like screen did not retain the visible link target"
    );
    assert_eq!(
        sequence_count(&pty.capture, b"\x1b]8;;"),
        0,
        "conhost-like capability fallback emitted OSC 8"
    );
    assert_eq!(
        sequence_count(&pty.capture, b"\x1b]9;") + sequence_count(&pty.capture, b"\x1b]777;"),
        0,
        "conhost-like capability fallback emitted a desktop notification OSC"
    );
    assert!(
        pty.capture.iter().filter(|byte| **byte == b'\x07').count() >= 1,
        "conhost-like completion must degrade to at least one BEL"
    );
    assert_eq!(
        sequence_count(&pty.capture, KEYBOARD_ENHANCEMENT_PUSH),
        0,
        "unsupported conhost-like input received a keyboard-enhancement push"
    );

    pty.send(b"\x1b");
    let status = pty.wait_for_exit();
    assert_eq!(status.exit_code(), 0, "unexpected Core exit: {status}");
    pty.close_and_drain();
    pty.assert_console_input_mode_restored(true);
    assert_eq!(
        sequence_count(&pty.capture, KEYBOARD_ENHANCEMENT_POP),
        0,
        "unsupported conhost-like input received a keyboard-enhancement pop"
    );
    assert_eq!(
        sequence_count(&pty.capture, KEYBOARD_ENHANCEMENT_QUERY),
        0,
        "the disabled keyboard-enhancement probe must not emit a query through ConPTY"
    );
    assert!(!pty.parser.screen().alternate_screen());
    assert!(!pty.parser.screen().bracketed_paste());
    provider.finish();
}

#[test]
fn native_conpty_rejects_version_skew_before_terminal_takeover() {
    let scratch = Scratch::new();
    let skewed = PROTOCOL_VERSION + 1;
    let mut pty = ConPty::spawn_with_server_version(&scratch, 100, 32, Some(skewed));
    let status = pty.wait_for_exit();
    pty.close_and_drain();
    assert!(
        contains(&pty.capture, b"app server: refusing to attach"),
        "native Windows version-skew refusal header was not captured; terminal:\n{}",
        pty.screen_text()
    );
    assert!(
        contains(
            &pty.capture,
            format!("unsupported SQ/EQ protocol version {skewed}; expected {PROTOCOL_VERSION}")
                .as_bytes(),
        ),
        "native Windows version-skew refusal detail was not captured"
    );
    assert_ne!(status.exit_code(), 0, "version-skewed TUI attached");
    pty.assert_console_input_mode_restored(false);

    assert!(
        !contains(&pty.capture, b"\x1b[?1049h"),
        "version refusal happened after alternate-screen takeover"
    );
    assert!(
        !contains(
            &pty.capture,
            b"app server: TUI attached as a versioned client"
        ),
        "the refused Windows client also announced a successful attachment"
    );
    assert_eq!(
        sequence_count(&pty.capture, KEYBOARD_ENHANCEMENT_QUERY),
        0,
        "version refusal queried terminal capabilities before attachment"
    );
    assert!(!pty.parser.screen().alternate_screen());
}

#[test]
fn native_conpty_handshake_unicode_resize_and_keyboard_disabled() {
    let scratch = Scratch::new();
    let mut pty = ConPty::spawn_keyboard_supported(&scratch, 100, 32);
    pty.wait_until("first frame after App Server version handshake", |pty| {
        pty.screen_text()
            .contains("ask about this codebase or describe a task")
    });
    assert_eq!(
        sequence_count(&pty.capture, KEYBOARD_ENHANCEMENT_POP),
        0,
        "the live TUI popped a keyboard-enhancement frame it never pushed"
    );

    pty.send(UNICODE_DRAFT.as_bytes());
    pty.wait_until("Unicode ConPTY input", |pty| {
        pty.screen_text().contains("请检查 Windows")
    });
    assert!(!pty.screen_text().contains('�'));
    pty.resize(72, 24);

    // The ConPTY transport cannot faithfully deliver a harness-injected CSI-u reply as Crossterm
    // key events; the probe is disabled in this fixture so the oracle exercises the handshake,
    // Unicode input, resize, and teardown paths without a negotiated keyboard frame.
    assert_eq!(
        sequence_count(&pty.capture, KEYBOARD_ENHANCEMENT_PUSH),
        0,
        "keyboard enhancement is disabled; Core must not push a CSI-u frame"
    );
    assert_eq!(
        sequence_count(&pty.capture, KEYBOARD_ENHANCEMENT_POP),
        0,
        "Core popped a keyboard-enhancement frame it never pushed"
    );

    // First Esc clears the non-empty draft; second Esc exits the idle TUI.
    pty.send(b"\x1b");
    pty.wait_until("draft clear", |pty| {
        !pty.screen_text().contains("请检查 Windows")
    });
    pty.send(b"\x1b");
    let status = pty.wait_for_exit();
    assert_eq!(status.exit_code(), 0, "unexpected Core exit: {status}");
    pty.close_and_drain();
    pty.assert_console_input_mode_restored(true);

    let screen = pty.parser.screen();
    assert!(!screen.alternate_screen(), "alternate screen leaked");
    assert!(!screen.bracketed_paste(), "bracketed paste leaked");
    assert_eq!(
        screen.mouse_protocol_mode(),
        vt100::MouseProtocolMode::None,
        "mouse capture leaked"
    );
    assert!(!screen.hide_cursor(), "shell cursor remained hidden");
    assert_eq!(
        sequence_count(&pty.capture, KEYBOARD_ENHANCEMENT_PUSH),
        0,
        "keyboard enhancement is disabled; Core must not push a CSI-u frame"
    );
    assert_eq!(
        sequence_count(&pty.capture, KEYBOARD_ENHANCEMENT_POP),
        0,
        "Core popped a keyboard-enhancement frame it never pushed"
    );
    assert_eq!(
        sequence_count(&pty.capture, KEYBOARD_ENHANCEMENT_QUERY),
        0,
        "the disabled keyboard-enhancement probe must not emit a query through ConPTY"
    );
    assert!(
        std::str::from_utf8(&pty.capture)
            .expect("ConPTY terminal stream is UTF-8")
            .find('�')
            .is_none(),
        "replacement glyph leaked into ConPTY output"
    );
}
