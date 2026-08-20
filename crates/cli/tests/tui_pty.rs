#![cfg(unix)]

use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, SlavePty, native_pty_system};
use serde_json::json;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::ffi::OsStrExt as _;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError};
use std::sync::{Condvar, LazyLock, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

// A PTY step may include a separately scheduled process startup while the all-target suite is
// running many test binaries. Causal latency properties below use byte ordering; this remains only
// the bounded harness watchdog for observing their terminal effects.
//
// It is a liveness bound, not an assertion: no predicate weakens when it grows. Fifteen seconds
// held on a dedicated machine and did not hold on the shared arm64 runner, where a pull-request
// build compiles a second worktree on the same cores and the child's redraw is simply descheduled
// past the deadline. The failure that produces is indistinguishable from a real hang in the log
// and costs a full re-run to diagnose, so the watchdog is set where only a genuine hang trips it.
// Raising this constant is what was tried last time, from fifteen seconds to forty-five, and
// forty-five has now missed twice on the shared runner as well. A constant cannot be picked that
// is right for both a dedicated machine and one compiling another worktree on the same cores, so
// the machine says how slow it is instead -- the same `ITERON_TEST_TIMEOUT_SCALE` that
// headless_serve.rs already reads, and that the release workflow already sets to 10. Still a
// liveness bound, not an assertion: no predicate weakens when it grows.
const BASE_STEP_TIMEOUT: Duration = Duration::from_secs(45);
const BASE_PROVIDER_TIMEOUT: Duration = Duration::from_secs(15);

/// Parsed strictly and clamped, so a malformed or absurd value falls back to native timing rather
/// than disabling a timeout.
fn timeout_scale() -> u32 {
    static SCALE: OnceLock<u32> = OnceLock::new();
    *SCALE.get_or_init(|| {
        std::env::var("ITERON_TEST_TIMEOUT_SCALE")
            .ok()
            .and_then(|raw| raw.trim().parse::<u32>().ok())
            .filter(|scale| (1..=60).contains(scale))
            .unwrap_or(1)
    })
}

fn step_timeout() -> Duration {
    BASE_STEP_TIMEOUT * timeout_scale()
}

fn provider_timeout() -> Duration {
    BASE_PROVIDER_TIMEOUT * timeout_scale()
}
// Provider fixtures are created before `PtyHarness` acquires its process-wide permit. A full
// all-target run can therefore leave a fixture waiting behind several batches of live PTYs even
// though its own request completes immediately once admitted. Keep that scheduler-only wait
// separate from the per-request/release watchdog above.
const PROVIDER_ACCEPT_TIMEOUT: Duration = Duration::from_secs(120);
const PROVIDER_IO_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_CAPTURE_BYTES: usize = 2 * 1024 * 1024;
const MAX_PROVIDER_REQUEST_BYTES: usize = 1024 * 1024;
const LINK_PROVIDER_ID: &str = "tui-link-fixture";
const LINK_MODEL_ID: &str = "tui-link-model";
const LINK_TEST_KEY_ENV: &str = "ITERON_TUI_LINK_TEST_KEY";
const LINK_TEST_KEY: &str = "integration-test-placeholder";
const LINK_CONTEXT_WINDOW_TOKENS: u64 = 1_000_000;
const INERT_GLM_API_KEY: &str = "integration-test-inert-never-requested";
const LINK_TARGET: &str = "https://example.com/core-guide";
const OSC9_RUN_COMPLETE: &[u8] = b"\x1b]9;Iteron: run complete\x07";
const CLIENT_PARITY_TASK: &str = include_str!("fixtures/client-parity-task.txt");
const KEYBOARD_ENHANCEMENT_QUERY: &[u8] = b"\x1b[?u\x1b[c";
const KEYBOARD_ENHANCEMENT_PUSH: &[u8] = b"\x1b[>1u";
const KEYBOARD_ENHANCEMENT_POP: &[u8] = b"\x1b[<1u";
const OSC11_QUERY: &[u8] = b"\x1b]11;?\x1b\\";
const CURSOR_POSITION_QUERY: &[u8] = b"\x1b[6n";
/// A glyph from the startup banner, i.e. proof that a real frame reached the terminal.
const FIRST_FRAME_MARKER: &[u8] = "ask about this codebase or describe a task".as_bytes();
static SCRATCH_ID: AtomicU64 = AtomicU64::new(0);
const MAX_CONCURRENT_PTYS: usize = 4;
static PTY_CAPACITY: LazyLock<(Mutex<usize>, Condvar)> =
    LazyLock::new(|| (Mutex::new(0), Condvar::new()));

/// Whole-workspace test runs otherwise launch all 24 PTYs, provider fixtures, parsers and reader
/// threads together. That scheduler storm measures host contention instead of terminal behavior
/// and used to miss bounded protocol deadlines that pass in isolation. Hold a small process-wide
/// permit for each live harness while keeping every production timeout unchanged.
struct PtyPermit;

impl PtyPermit {
    fn acquire() -> Self {
        let (active, ready) = &*PTY_CAPACITY;
        let mut active = active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while *active >= MAX_CONCURRENT_PTYS {
            active = ready
                .wait(active)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        *active += 1;
        Self
    }
}

impl Drop for PtyPermit {
    fn drop(&mut self) {
        let (active, ready) = &*PTY_CAPACITY;
        let mut active = active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *active = active.saturating_sub(1);
        ready.notify_one();
    }
}

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

    fn create_fifo(&self, relative: &str) {
        let path = self.repo().join(relative);
        let path = std::ffi::CString::new(path.as_os_str().as_bytes())
            .expect("PTY FIFO path contains no NUL");
        // SAFETY: `path` remains live and names a test-only location in the scratch repository.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    }

    fn configure_link_provider(&self, api_root: &str) {
        self.configure_link_provider_with_notifications(api_root, None);
    }

    fn configure_link_provider_with_notifications(
        &self,
        api_root: &str,
        completion_notifications: Option<bool>,
    ) {
        let config_dir = self.home().join(".iteron");
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
                "models": [LINK_MODEL_ID],
                "model_capabilities": {
                    (LINK_MODEL_ID): {
                        "context_window_tokens": LINK_CONTEXT_WINDOW_TOKENS,
                        "image_input": false
                    }
                }
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
        let config_dir = self.repo().join(".iteron");
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

    fn configure_external_editor(&self) {
        let config_dir = self.home().join(".iteron");
        std::fs::create_dir_all(&config_dir).expect("create isolated Core config directory");
        let config = json!({
            "schema_version": 2,
            "tui_keymap": {
                "mode": "standard",
                "bindings": { "external_editor": "alt+e" }
            },
            "external_editor": [
                "/bin/sh",
                "-c",
                "printf 'edited safely in native terminal' > \"$1\"",
                "core-editor-fixture"
            ]
        });
        std::fs::write(
            config_dir.join("config.json"),
            serde_json::to_vec(&config).expect("encode external-editor config"),
        )
        .expect("write external-editor config");
    }

    fn configure_vim_keymap(&self) {
        let config_dir = self.home().join(".iteron");
        std::fs::create_dir_all(&config_dir).expect("create isolated Core config directory");
        let config = json!({
            "schema_version": 2,
            "tui_keymap": { "mode": "vim" }
        });
        std::fs::write(
            config_dir.join("config.json"),
            serde_json::to_vec(&config).expect("encode Vim keymap config"),
        )
        .expect("write Vim keymap config");
    }

    fn configure_invalid_keymap(&self) {
        let config = json!({
            "schema_version": 2,
            "tui_keymap": {
                "bindings": { "external_editor": "ctrl+c" }
            }
        });
        std::fs::write(
            self.home().join(".iteron/config.json"),
            serde_json::to_vec(&config).expect("encode invalid hot-reload fixture"),
        )
        .expect("write invalid hot-reload fixture");
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

    fn spawn_client_parity_fixture() -> Self {
        Self::spawn_with_content("parity reply".into(), true)
    }

    fn spawn_with_content(content: String, include_usage: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback TUI provider");
        listener
            .set_nonblocking(true)
            .expect("make TUI provider accept bounded");
        let address = listener.local_addr().expect("read TUI provider address");
        let handle = thread::spawn(move || {
            let mut stream = accept_provider_connection(&listener);
            let _ = read_provider_request(&mut stream);
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
            let _ = read_provider_request(&mut stream);
            started_tx.send(()).expect("signal admitted provider turn");
            release_rx
                .recv_timeout(provider_timeout())
                .expect("drain test releases provider");
            let body = concat!(
                "data: {\"id\":\"chatcmpl-drain\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Provider turn quiesced.\"},\"finish_reason\":null}],\"usage\":null}\n\n",
                "data: {\"id\":\"chatcmpl-drain\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":null}\n\n",
                "data: {\"id\":\"chatcmpl-drain\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":3,\"total_tokens\":10}}\n\n",
                "data: [DONE]\n\n"
            );
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.flush();
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

/// Two provider turns with an operator-controlled boundary between them. The first request keeps
/// the TUI active long enough to send Esc + a new prompt through the real PTY; the second request
/// is captured so the test can prove the queued bytes reached a fresh turn exactly once.
struct InterruptHandoffProvider {
    api_root: String,
    first_started: Receiver<()>,
    release_first: mpsc::Sender<()>,
    second_request: Receiver<Vec<u8>>,
    handle: Option<JoinHandle<()>>,
}

impl InterruptHandoffProvider {
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind interrupt fixture provider");
        listener
            .set_nonblocking(true)
            .expect("make interrupt fixture accept bounded");
        let address = listener.local_addr().expect("read provider address");
        let (first_started_tx, first_started) = mpsc::channel();
        let (release_first, release_first_rx) = mpsc::channel();
        let (second_request_tx, second_request) = mpsc::channel();
        let handle = thread::spawn(move || {
            let mut first = accept_provider_connection(&listener);
            let _ = read_provider_request(&mut first);
            first_started_tx
                .send(())
                .expect("signal first provider turn");
            release_first_rx
                .recv_timeout(provider_timeout())
                .expect("interrupt test releases first provider turn");
            let first_body = concat!(
                "data: {\"id\":\"chatcmpl-interrupt-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"First turn reached its boundary.\"},\"finish_reason\":null}],\"usage\":null}\n\n",
                "data: {\"id\":\"chatcmpl-interrupt-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":null}\n\n",
                "data: [DONE]\n\n"
            );
            let _ = write!(
                first,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{first_body}",
                first_body.len()
            );
            let _ = first.flush();
            // The response advertises `Connection: close`; release the socket before waiting for
            // the queued turn so the fake has the same terminal boundary as a real HTTP/1.1
            // server instead of keeping the interrupted request artificially live.
            drop(first);

            let mut second = accept_provider_connection(&listener);
            let request = read_provider_request(&mut second);
            second_request_tx
                .send(request)
                .expect("capture the queued next prompt");
            let second_body = concat!(
                "data: {\"id\":\"chatcmpl-interrupt-2\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Next prompt completed.\"},\"finish_reason\":null}],\"usage\":null}\n\n",
                "data: {\"id\":\"chatcmpl-interrupt-2\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":null}\n\n",
                "data: [DONE]\n\n"
            );
            write!(
                second,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{second_body}",
                second_body.len()
            )
            .expect("write second provider response");
            second.flush().expect("flush second provider response");
        });
        Self {
            api_root: format!("http://{address}/v1"),
            first_started,
            release_first,
            second_request,
            handle: Some(handle),
        }
    }

    fn finish(mut self) {
        self.handle
            .take()
            .expect("interrupt provider thread exists")
            .join()
            .expect("interrupt provider completed cleanly");
    }
}

/// Emits one real `bash` tool call whose shell and background descendant both remain live until
/// the terminal sends Ctrl-C or Esc. The marker files let the PTY test distinguish "the key was
/// painted" from "the admitted child process tree was actually cancelled".
struct BlockingBashToolProvider {
    api_root: String,
    started: PathBuf,
    escaped: PathBuf,
    handle: Option<JoinHandle<()>>,
}

impl BlockingBashToolProvider {
    fn spawn(repo: &std::path::Path) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind bash-tool fixture provider");
        listener
            .set_nonblocking(true)
            .expect("make bash-tool fixture accept bounded");
        let address = listener.local_addr().expect("read provider address");
        let started = repo.join("bash-tool-started");
        let escaped = repo.join("bash-tool-escaped");
        let command = format!(
            "printf started > {}; (sleep 2; printf escaped > {}) & wait",
            started.display(),
            escaped.display()
        );
        let handle = thread::spawn(move || {
            let mut stream = accept_provider_connection(&listener);
            let _ = read_provider_request(&mut stream);
            stream
                .set_write_timeout(Some(PROVIDER_IO_TIMEOUT))
                .expect("bound bash-tool provider write");
            let delta = json!({
                "id": "chatcmpl-bash-tool",
                "object": "chat.completion.chunk",
                "choices": [{
                    "index": 0,
                    "delta": {
                        "role": "assistant",
                        "tool_calls": [{
                            "index": 0,
                            "id": "call-blocking-bash",
                            "type": "function",
                            "function": {
                                "name": "bash",
                                "arguments": serde_json::to_string(&json!({"command": command}))
                                    .expect("encode bash-tool arguments")
                            }
                        }]
                    },
                    "finish_reason": null
                }],
                "usage": null
            });
            let terminal = json!({
                "id": "chatcmpl-bash-tool",
                "object": "chat.completion.chunk",
                "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}],
                "usage": null
            });
            let usage = json!({
                "id": "chatcmpl-bash-tool",
                "object": "chat.completion.chunk",
                "choices": [],
                "usage": {"prompt_tokens": 9, "completion_tokens": 6, "total_tokens": 15}
            });
            let body =
                format!("data: {delta}\n\ndata: {terminal}\n\ndata: {usage}\n\ndata: [DONE]\n\n");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .expect("write bash-tool provider response");
            stream.flush().expect("flush bash-tool provider response");
        });
        Self {
            api_root: format!("http://{address}/v1"),
            started,
            escaped,
            handle: Some(handle),
        }
    }

    fn finish(mut self) {
        self.handle
            .take()
            .expect("bash-tool provider thread exists")
            .join()
            .expect("bash-tool provider completed cleanly");
    }
}

fn accept_provider_connection(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + PROVIDER_ACCEPT_TIMEOUT;
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

fn read_provider_request(stream: &mut TcpStream) -> Vec<u8> {
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
            return request;
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
    cursor_queries_answered: usize,
    _permit: PtyPermit,
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
    Silent,
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

    fn spawn_silent_keyboard_link_fixture(scratch: &Scratch, cols: u16, rows: u16) -> Self {
        Self::spawn_with_terminal(
            scratch,
            cols,
            rows,
            true,
            ThemeFixture::TerminalOverride,
            KeyboardFixture::Silent,
        )
    }

    fn spawn_kitty_osc11_fixture(scratch: &Scratch, cols: u16, rows: u16) -> Self {
        Self::spawn_with_terminal(
            scratch,
            cols,
            rows,
            false,
            ThemeFixture::Osc11Auto,
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
        Self::spawn_with_terminal_options(
            scratch,
            cols,
            rows,
            link_fixture,
            theme_fixture,
            keyboard_fixture,
            None,
            true,
        )
    }

    fn spawn_resume_fixture(scratch: &Scratch, run_id: &str, cols: u16, rows: u16) -> Self {
        Self::spawn_with_terminal_options(
            scratch,
            cols,
            rows,
            true,
            ThemeFixture::TerminalOverride,
            KeyboardFixture::Unsupported,
            Some(run_id),
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_with_terminal_options(
        scratch: &Scratch,
        cols: u16,
        rows: u16,
        link_fixture: bool,
        theme_fixture: ThemeFixture,
        keyboard_fixture: KeyboardFixture,
        resume_run: Option<&str>,
        submit_initial_task: bool,
    ) -> Self {
        let permit = PtyPermit::acquire();
        let pair = native_pty_system()
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("open deterministic PTY");
        let baseline_termios = raw_mode_termios_state(pair.master.as_ref());

        let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_iteron"));
        // This is deliberately a direct binary launch. No credential-loading launcher ever
        // enter this process tree, and env_clear means no real provider credential can be inherited.
        command.env_clear();
        command.env("HOME", scratch.home().as_os_str());
        command.env("PATH", "/usr/bin:/bin");
        match theme_fixture {
            ThemeFixture::TerminalOverride => {
                command.env("TERM", "xterm-256color");
                command.env("COLORTERM", "truecolor");
                command.env("ITERON_THEME", "terminal");
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
                command.env("ITERON_THEME", "dark");
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
        if let Some(run_id) = resume_run {
            command.arg("--resume");
            command.arg(run_id);
        }
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
            if submit_initial_task {
                command.arg(CLIENT_PARITY_TASK.trim());
            }
        } else {
            // These fixtures exercise only terminal and local-tool paths, but production route
            // admission still requires the bundled GLM credential owner to be present. Keep the
            // fixed inert value inside the env-cleared child; no fixture in this branch submits a
            // provider request.
            command.env("GLM_API_KEY", INERT_GLM_API_KEY);
            command.env("ITERON_PROVIDER", "glm");
            command.env("ITERON_MODEL", "glm-5.2");
        }

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
            reader_closed: false,
            parser: vt100::Parser::new(rows, cols, 4096),
            capture: Vec::new(),
            baseline_termios,
            keyboard_fixture,
            keyboard_query_answered: false,
            cursor_queries_answered: 0,
            _permit: permit,
        }
    }

    fn ingest(&mut self, chunk: Vec<u8>) {
        assert!(
            self.capture.len().saturating_add(chunk.len()) <= MAX_CAPTURE_BYTES,
            "TUI PTY output exceeded the deterministic capture bound"
        );
        self.parser.process(&chunk);
        self.capture.extend_from_slice(&chunk);
        let cursor_query_count = sequence_count(&self.capture, CURSOR_POSITION_QUERY);
        while self.cursor_queries_answered < cursor_query_count {
            self.cursor_queries_answered += 1;
            let (row, column) = self.parser.screen().cursor_position();
            self.send(format!("\x1b[{};{}R", row + 1, column + 1).as_bytes());
        }
        if !self.keyboard_query_answered
            && self
                .capture
                .windows(KEYBOARD_ENHANCEMENT_QUERY.len())
                .any(|window| window == KEYBOARD_ENHANCEMENT_QUERY)
        {
            self.keyboard_query_answered = true;
            let response = match self.keyboard_fixture {
                KeyboardFixture::Unsupported => Some(b"\x1b[?1;2c".as_slice()),
                KeyboardFixture::Kitty => Some(b"\x1b[?1u\x1b[?1;2c".as_slice()),
                KeyboardFixture::Silent => None,
            };
            if let Some(response) = response {
                self.send(response);
            }
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
        let deadline = Instant::now() + step_timeout();
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
                && (pty.screen_text().contains("请检查")
                    || pty.screen_text().contains("Transcript")
                    || pty.screen_text().contains("Iteron")
                    || pty.screen_text().contains("ready"))
                && !pty.screen_text().contains('�')
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
        let deadline = Instant::now() + step_timeout();
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
            "iteron did not exit before the PTY deadline; current terminal:\n{}",
            self.screen_text()
        );
    }

    fn close_and_drain(&mut self) {
        drop(self.writer.take());
        drop(self.slave.take());
        drop(self.master.take());
        // Scaled like every other bound in this file. Two seconds is generous on a dedicated
        // machine and not generous on a runner compiling another worktree on the same cores; the
        // assertion below turns that into a failure indistinguishable from a reader that never
        // reached EOF.
        let deadline = Instant::now() + Duration::from_secs(2) * timeout_scale();
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
    pty.wait_until("the initial Core full-screen surface", |pty| {
        let screen = pty.parser.screen();
        let text = screen.contents();
        screen.alternate_screen()
            && screen.bracketed_paste()
            && screen.mouse_protocol_mode() != vt100::MouseProtocolMode::None
            && text.contains("▄██")
            && text.contains("ask about this codebase")
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
fn custom_external_editor_round_trip_restores_tui_and_preserves_terminal_cleanup() {
    let scratch = Scratch::new("external-editor");
    scratch.configure_external_editor();
    let mut pty = PtyHarness::spawn(&scratch, 80, 24);
    wait_for_ready(&mut pty);

    pty.send(b"original draft");
    pty.wait_until("the original composer draft", |pty| {
        pty.screen_text().contains("original draft")
    });
    pty.send(b"\x1be"); // configured Alt-E, proving the default Ctrl-G was actually remapped.
    pty.wait_until("the external-editor draft after terminal resume", |pty| {
        let screen = pty.screen_text();
        screen.contains("edited safely in native terminal")
            && screen.contains("external editor applied")
            && pty.parser.screen().alternate_screen()
            && pty.parser.screen().bracketed_paste()
            && pty.parser.screen().mouse_protocol_mode() != vt100::MouseProtocolMode::None
    });
    let tmp = scratch.home().join(".iteron/tmp");
    assert_eq!(
        std::fs::read_dir(tmp)
            .expect("private temp directory exists")
            .count(),
        0,
        "external-editor draft must be removed after the round trip"
    );

    scratch.configure_invalid_keymap();
    // Production watches config metadata off the input/render path at a bounded 100 ms cadence.
    // Let that background watcher publish its atomic change bit before the first fallback key.
    thread::sleep(Duration::from_millis(150));
    pty.send(b"\x07"); // first key after the rewrite must route through the safe built-in map.
    pty.wait_until("invalid hot reload and built-in keymap fallback", |pty| {
        let screen = pty.screen_text();
        screen.contains("keymap reload failed; using built-in bindings")
            && screen.contains("no external editor configured")
    });

    pty.send(b"\x15\x1b"); // clear the draft, then exit.
    let status = pty.wait_for_exit();
    assert!(status.success(), "normal TUI exit failed: {status}");
    assert_termios_restored(&pty);
    pty.close_and_drain();
    pty.assert_terminal_restored();
}

#[test]
fn vim_composer_routes_insert_normal_delete_and_return_to_insert() {
    let scratch = Scratch::new("vim-composer");
    scratch.configure_vim_keymap();
    let mut pty = PtyHarness::spawn(&scratch, 100, 24);
    wait_for_ready(&mut pty);
    pty.wait_until("visible Vim insert mode", |pty| {
        pty.screen_text().contains("vim:insert")
    });

    pty.send(b"unique-draft");
    pty.wait_until("insert-mode draft", |pty| {
        pty.screen_text().contains("unique-draft")
    });
    pty.send(b"\x1b0x");
    pty.wait_until("normal-mode cursor and delete", |pty| {
        let screen = pty.screen_text();
        screen.contains("vim:normal")
            && screen.contains("nique-draft")
            && !screen.contains("unique-draft")
    });
    pty.send(b"I+");
    pty.wait_until("return to insert at line start", |pty| {
        let screen = pty.screen_text();
        screen.contains("vim:insert") && screen.contains("+nique-draft")
    });

    pty.send(b"\x05\x15"); // move to end, then readline-clear the whole insert-mode draft.
    pty.wait_until("the empty insert-mode composer", |pty| {
        pty.screen_text().contains("ask about this codebase")
    });
    pty.send(b"\x03"); // Ctrl-C exits the empty TUI.
    let status = pty.wait_for_exit();
    assert!(status.success(), "normal TUI exit failed: {status}");
    assert_termios_restored(&pty);
    pty.close_and_drain();
    pty.assert_terminal_restored();
}

#[test]
fn tunables_registry_search_and_detail_are_terminal_real() {
    let scratch = Scratch::new("tunables-registry");
    scratch.create_fifo("request.fifo");
    let mut pty = PtyHarness::spawn(&scratch, 110, 30);
    wait_for_ready(&mut pty);

    pty.send(b"/tunables load request.fifo\r");
    pty.wait_until(
        "nonblocking FIFO refusal leaves the event loop responsive",
        |pty| {
            pty.screen_text()
                .contains("tunables simulation refused: request could not be loaded safely")
        },
    );

    pty.send(b"/tunables registry\r");
    pty.wait_until("searchable 160-family tunables registry", |pty| {
        let screen = pty.screen_text();
        screen.contains("tunables · catalog")
            && screen.contains("provider")
            && screen.contains("simulation only")
    });
    pty.send(b"\x1b[200~definitely-no-tunable\x1b[201~");
    pty.wait_until("picker-owned paste has an explicit no-match state", |pty| {
        pty.screen_text().contains("No matches")
    });
    pty.send(b"\x1b"); // clear the pasted picker query without closing the picker.
    pty.wait_until("first picker escape clears the pasted query", |pty| {
        let screen = pty.screen_text();
        screen.contains("tunables · catalog")
            && screen.contains("type to filter")
            && screen.contains("1/160")
            && !screen.contains("No matches")
    });
    pty.send(b"\x1b[200~route_selection\x1b[201~");
    pty.wait_until("picker-owned paste filters the tunables registry", |pty| {
        let screen = pty.screen_text();
        screen.contains("route_selection") && !screen.contains("No matches")
    });
    pty.send(b"\r");
    pty.wait_until("read-only tunable detail", |pty| {
        let screen = pty.screen_text();
        screen.contains("Read-only catalog") && screen.contains("SWE-bench Pro")
    });
    for _ in 0..10 {
        pty.send(b"\x1b[<64;1;1M");
    }
    pty.wait_until("tunable detail scrolls inside the application", |pty| {
        let screen = pty.screen_text();
        screen.contains("iteron.control.provider.route_selection")
            && screen.contains("runtime_bound=false")
            && screen.contains("not supplied (no frozen request loaded)")
    });
    let history = pty.screen_text();
    assert!(
        history.contains("iteron.control.provider.route_selection"),
        "{history}"
    );
    assert!(history.contains("runtime_bound=false"), "{history}");
    assert!(
        history.contains("not supplied (no frozen request loaded)"),
        "{history}"
    );
    for _ in 0..10 {
        pty.send(b"\x1b[<65;1;1M");
    }

    pty.send(b"\x03");
    let status = pty.wait_for_exit();
    assert!(status.success(), "normal TUI exit failed: {status}");
    assert_termios_restored(&pty);
    pty.close_and_drain();
    pty.assert_terminal_restored();
}

#[test]
fn experiment_lab_is_terminal_real_read_only_by_default_and_blocks_promotion() {
    let scratch = Scratch::new("experiment-lab");
    let mut pty = PtyHarness::spawn(&scratch, 110, 30);
    wait_for_ready(&mut pty);

    pty.send(b"/lab\r");
    pty.wait_until("offline experiment lab panel", |pty| {
        let screen = pty.screen_text();
        screen.contains("experiment lab")
            && screen.contains("offline · train-only")
            && screen.contains("external human authority only")
            && screen.contains("No runtime setting changes")
    });
    assert!(
        !scratch.repo().join(".iteron/experiments").exists(),
        "opening the lab must not create state"
    );
    assert_ne!(
        pty.parser.screen().mouse_protocol_mode(),
        vt100::MouseProtocolMode::None,
        "the full-screen lab must preserve application mouse ownership"
    );

    pty.send(b"/lab promote\r");
    pty.wait_until("promotion authority boundary panel", |pty| {
        let screen = pty.screen_text();
        screen.contains("experiment lab · promotion boundary")
            && screen.contains("blocked by design")
            && screen.contains("unavailable from /lab")
    });

    pty.send(b"\x03");
    let status = pty.wait_for_exit();
    assert!(status.success(), "normal TUI exit failed: {status}");
    assert_termios_restored(&pty);
    pty.close_and_drain();
    pty.assert_terminal_restored();
}

#[test]
fn transcript_viewer_search_raw_resize_export_and_both_entry_paths_are_terminal_real() {
    let scratch = Scratch::new("transcript-viewer");
    let mut pty = PtyHarness::spawn(&scratch, 100, 28);
    wait_for_ready(&mut pty);

    let command = "!printf 'needle 你好 😀\\n\\033]52;bad\\a\\n'\r";
    pty.send(command.as_bytes());
    pty.wait_until("safe multilingual transcript source", |pty| {
        let screen = pty.screen_text();
        screen.contains("needle")
            && screen.contains('你')
            && screen.contains('好')
            && !screen.contains('�')
    });
    assert!(
        !pty.capture
            .windows(b"\x1b]52;bad".len())
            .any(|window| window == b"\x1b]52;bad"),
        "transcript output injected an OSC 52 clipboard command"
    );

    pty.send(b"\x06"); // default typed transcript_viewer action: Ctrl-F
    pty.wait_until("fullscreen viewer through typed keymap action", |pty| {
        let screen = pty.screen_text();
        screen.contains("Transcript · block") && screen.contains("y copy block")
    });
    pty.send("/你好\r".as_bytes());
    pty.wait_until("deterministic CJK match", |pty| {
        let screen = pty.screen_text();
        screen.contains("match 1/") && screen.contains("filter: 你好")
    });
    pty.send(b"r");
    pty.wait_until("raw semantic projection", |pty| {
        pty.screen_text().contains(" · raw · match")
    });
    pty.resize(56, 18);
    pty.wait_until("transcript viewer remains open after resize", |pty| {
        pty.screen_text().contains("Transcript")
    });
    assert!(!pty.screen_text().contains('�'));

    pty.send(b"e");
    #[cfg(target_os = "linux")]
    {
        pty.wait_until("filtered atomic transcript export", |pty| {
            pty.screen_text().contains("exported ->")
        });
        let filtered = std::fs::read_to_string(scratch.repo().join("core-transcript-filtered.md"))
            .expect("filtered viewer export is durable in the workspace");
        assert!(filtered.starts_with("# Iteron transcript\n\n"));
        assert!(filtered.contains("needle 你好 😀"));
    }
    #[cfg(not(target_os = "linux"))]
    pty.wait_until("truthful fail-closed export diagnostic", |pty| {
        pty.screen_text().contains("export failed before dispatch:")
            && !scratch.repo().join("core-transcript-filtered.md").exists()
    });

    pty.send(b"\x1b");
    pty.wait_until("return from fullscreen viewer", |pty| {
        pty.screen_text().contains("ask about this codebase")
            && !pty.screen_text().contains("y copy block")
    });
    pty.send(b"/transcript needle\r");
    pty.wait_until("fullscreen viewer through slash command", |pty| {
        let screen = pty.screen_text();
        screen.contains("Transcript · block") && screen.contains("search> needle")
    });
    pty.send(b"\r\x1b"); // accept the initial slash query, then close the viewer.
    pty.wait_until("viewer closed after slash entry", |pty| {
        pty.screen_text().contains("ask about this codebase")
            && !pty.screen_text().contains("y copy block")
    });
    let slash_export = scratch.repo().join("core-transcript.md");
    let slash_export_2 = scratch.repo().join("core-transcript-2.md");
    pty.send(b"/export\r");
    #[cfg(target_os = "linux")]
    {
        // The file appearing is not the export finishing: the writer creates it before the app
        // clears its pending flag, and a second `/export` inside that window is refused with
        // "export already pending" -- so the versioned file below never appears and this test times
        // out. On an M-series Mac the window is submillisecond; on Linux/aarch64 it is wide enough
        // to lose the race every time. Wait for the app to *say* it finished, which is the signal
        // that actually orders the two commands.
        pty.wait_until("slash export completes off the input path", |pty| {
            slash_export.is_file() && pty.screen_text().contains("exported ->")
        });
        let second_export_capture_start = pty.capture.len();
        pty.send(b"/export\r");
        pty.wait_until("default export versions instead of overwriting", |pty| {
            slash_export_2.is_file()
                && pty.capture[second_export_capture_start..]
                    .windows(b"exported ->".len())
                    .any(|window| window == b"exported ->")
        });
    }
    #[cfg(not(target_os = "linux"))]
    pty.wait_until(
        "slash export fails closed without filesystem mutation",
        |pty| {
            pty.screen_text().contains("export failed before dispatch:")
                && !slash_export.exists()
                && !slash_export_2.exists()
        },
    );
    pty.send(b"\x03");
    let status = pty.wait_for_exit();
    assert!(status.success(), "normal TUI exit failed: {status}");
    assert_termios_restored(&pty);
    pty.close_and_drain();
    pty.assert_terminal_restored();
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
    let mut pty = PtyHarness::spawn_osc11_timeout_fixture(&scratch, 80, 24);
    wait_for_ready(&mut pty);
    // The query is now issued BEHIND the first frame, so a painted surface no longer implies the
    // probe has been written. Wait for the real bytes before asserting anything about the timeout.
    pty.wait_until("the deferred OSC 11 background query", |pty| {
        find_sequence(&pty.capture, OSC11_QUERY).is_some()
    });
    let first_frame = find_sequence(&pty.capture, FIRST_FRAME_MARKER)
        .expect("the initial surface reaches the terminal");
    let background_query =
        find_sequence(&pty.capture, OSC11_QUERY).expect("the deferred OSC 11 query is written");
    assert!(
        first_frame < background_query,
        "an unanswered OSC 11 query must be written after, and therefore cannot block, the first frame"
    );

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
    // Both probes used to sit between terminal-mode entry and the first draw: the progressive
    // keyboard query blocks up to 2000 ms and OSC 11 another 80 ms, so a terminal that answered
    // neither held the initial surface for two seconds before anything appeared.
    //
    // Byte order is the durable statement of the fix, and it is the STRONGER one: a query that is
    // written after the frame cannot delay the frame no matter how long the terminal takes to
    // answer it, or whether it answers at all. A wall-clock bound would instead mostly measure how
    // loaded the machine running this suite happens to be.
    let scratch = Scratch::new("probe-after-first-frame");
    let mut pty = PtyHarness::spawn_kitty_osc11_fixture(&scratch, 80, 24);
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
fn unanswered_keyboard_probe_does_not_delay_initial_submission() {
    let provider = LinkProvider::spawn_client_parity_fixture();
    let scratch = Scratch::new("silent-keyboard-initial-submit");
    scratch.configure_link_provider(&provider.api_root);
    let mut pty = PtyHarness::spawn_silent_keyboard_link_fixture(&scratch, 80, 24);

    pty.wait_until(
        "initial task completes while keyboard probe is unanswered",
        |pty| {
            let screen = pty.screen_text();
            screen.contains("parity reply")
                && screen.contains("idle · input ready")
                && find_sequence(&pty.capture, KEYBOARD_ENHANCEMENT_QUERY).is_some()
        },
    );
    let first_frame = find_sequence(&pty.capture, FIRST_FRAME_MARKER).expect("first frame painted");
    let query = find_sequence(&pty.capture, KEYBOARD_ENHANCEMENT_QUERY).expect("query written");
    assert!(
        first_frame < query,
        "probe is emitted only after first paint"
    );
    assert!(
        sequence_count(&pty.capture, KEYBOARD_ENHANCEMENT_PUSH) <= 1,
        "family evidence may enable exactly one enhancement frame without waiting for the reply"
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
fn input_ready_does_not_wait_for_rebuildable_session_index() {
    let provider = LinkProvider::spawn_client_parity_fixture();
    let scratch = Scratch::new("input-ready-before-reindex");
    scratch.configure_link_provider(&provider.api_root);
    // A directory at the rebuildable index path makes both reading and atomic replacement fail,
    // while leaving the authoritative rollout directory writable. The initial task must still
    // reach its RunEnded/input-ready boundary; an index repair is never run authority.
    std::fs::create_dir_all(scratch.runs().join("sessions.index"))
        .expect("install an intentionally unrebuildable index fixture");
    let mut pty = PtyHarness::spawn_link_fixture(&scratch, 80, 24);

    pty.wait_until(
        "input-ready is independent of session-index repair",
        |pty| {
            let screen = pty.screen_text();
            screen.contains("parity reply") && screen.contains("idle · input ready")
        },
    );
    assert!(
        scratch.runs().join("sessions.index").is_dir(),
        "the assertion must precede any successful rebuild of the fixture"
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
        screen.contains("Read the guide now.") && screen.contains("idle · input ready")
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
fn client_parity_scripted_task_reaches_tui_done_presentation() {
    let provider = LinkProvider::spawn_client_parity_fixture();
    let scratch = Scratch::new("client-parity-tui");
    scratch.configure_link_provider(&provider.api_root);
    let mut pty = PtyHarness::spawn_link_fixture(&scratch, 80, 24);

    pty.wait_until("shared client-parity task completion", |pty| {
        let screen = pty.screen_text();
        screen.contains("parity reply") && screen.contains("idle · input ready")
    });
    assert!(
        String::from_utf8_lossy(&pty.capture).contains("Iteron · Return exactly: parity reply"),
        "the first submitted prompt becomes the terminal session title"
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
            && pty.screen_text().contains("idle · input ready")
            && sequence_count(&pty.capture, OSC9_RUN_COMPLETE) > 0
    });
    pty.drain_ready();
    assert_eq!(
        sequence_count(&pty.capture, OSC9_RUN_COMPLETE),
        1,
        "the capable production transport must emit exactly one complete OSC 9 frame; other BEL-terminated terminal controls such as the title are independent"
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
            && pty.screen_text().contains("idle · input ready")
            && sequence_count(&pty.capture, OSC9_RUN_COMPLETE) > 0
    });
    pty.drain_ready();
    assert_eq!(
        sequence_count(&pty.capture, OSC9_RUN_COMPLETE),
        1,
        "the App Server RunEnded boundary must notify exactly once even without provider usage"
    );
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
            && pty.screen_text().contains("idle · input ready")
    });
    pty.drain_ready();
    assert_eq!(
        sequence_count(&pty.capture, OSC9_RUN_COMPLETE),
        0,
        "repository configuration must not enable the run-complete terminal notification"
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
        .recv_timeout(provider_timeout())
        .expect("provider turn is admitted before Ctrl-D");
    pty.send(b"\x06");
    pty.wait_until("viewer remains reachable during a running turn", |pty| {
        pty.screen_text().contains("Transcript · block")
    });
    pty.send(b"\x04");
    pty.wait_until("active Ctrl-D drain status", |pty| {
        let screen = pty.screen_text();
        screen.contains("draining active work now") || screen.contains("last: drained")
    });
    pty.wait_until("durable drained terminal returns input", |pty| {
        pty.screen_text().contains("idle · input ready")
    });
    provider
        .release
        .send(())
        .expect("release the cancelled provider fixture thread");

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
    let events = iteron_record::replay(&rollout_path).expect("drain rollout replays");
    let checkpoints = events
        .iter()
        .filter_map(|event| match &event.kind {
            iteron_protocol::EventKind::Checkpoint { tree_ref, .. } => Some(tree_ref),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(checkpoints.len(), 1, "active Ctrl-D makes one checkpoint");
    assert!(events.iter().any(|event| matches!(
        &event.kind,
        iteron_protocol::EventKind::Done { outcome } if outcome == "Drained"
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
fn esc_interrupt_keeps_real_pty_input_live_dispatches_the_next_prompt_and_then_exits() {
    const NEXT_PROMPT: &str = "continue with the queued next prompt";
    let provider = InterruptHandoffProvider::spawn();
    let scratch = Scratch::new("interrupt-handoff");
    scratch.configure_link_provider(&provider.api_root);
    let mut pty = PtyHarness::spawn_link_fixture(&scratch, 96, 26);

    provider
        .first_started
        .recv_timeout(provider_timeout())
        .expect("the first turn is awaiting the provider");

    // One physical input burst exercises the actual terminal ordering: Esc asks the current run
    // to stop, printable bytes immediately continue into the still-focused composer, and Enter
    // commits them as the next prompt.
    let mut input = Vec::from(b"\x1b".as_slice());
    input.extend_from_slice(NEXT_PROMPT.as_bytes());
    input.push(b'\r');
    pty.send(&input);
    pty.wait_until(
        "the post-interrupt prompt remains visible before the old provider returns",
        |pty| pty.screen_text().contains(NEXT_PROMPT),
    );

    provider
        .release_first
        .send(())
        .expect("release the interrupted provider request");
    let second_request = provider
        .second_request
        .recv_timeout(provider_timeout())
        .unwrap_or_else(|error| {
            panic!(
                "the next prompt starts a fresh provider request: {error}; screen:\n{}",
                pty.screen_text(),
            )
        });
    let second_request = String::from_utf8(second_request).expect("provider request is UTF-8");
    assert!(
        second_request.contains(NEXT_PROMPT),
        "the post-interrupt composer bytes reached the next provider turn; screen:\n{}",
        pty.screen_text()
    );
    pty.wait_until("the queued next turn reaches its terminal event", |pty| {
        let screen = pty.screen_text();
        screen.contains("Next prompt completed.")
            && screen.contains("idle")
            && !screen.contains(" pending")
    });

    // The authoritative terminal event has returned the app to idle, so Esc is now a real exit.
    pty.send(b"\x1b");
    let status = pty.wait_for_exit();
    assert!(
        status.success(),
        "post-interrupt idle exit failed: {status}"
    );
    assert_termios_restored(&pty);
    pty.close_and_drain();
    pty.assert_terminal_restored();
    provider.finish();
}

#[test]
fn startup_resume_projects_the_recorded_conversation_into_the_real_terminal() {
    let provider = LinkProvider::spawn_client_parity_fixture();
    let scratch = Scratch::new("resume-history");
    scratch.configure_link_provider(&provider.api_root);
    let mut first = PtyHarness::spawn_link_fixture(&scratch, 96, 26);
    first.wait_until("the first session records an assistant answer", |pty| {
        pty.screen_text().contains("parity reply") && pty.screen_text().contains("idle")
    });
    first.send(b"\x1b");
    assert!(first.wait_for_exit().success());
    assert_termios_restored(&first);
    first.close_and_drain();
    first.assert_terminal_restored();
    provider.finish();

    let run_id = std::fs::read_dir(scratch.runs())
        .expect("read resume fixture rollouts")
        .filter_map(Result::ok)
        .find_map(|entry| {
            (entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "jsonl"))
            .then(|| entry.path().file_stem()?.to_str().map(str::to_owned))
            .flatten()
        })
        .expect("the first session persisted one rollout");
    let mut resumed = PtyHarness::spawn_resume_fixture(&scratch, &run_id, 96, 26);
    resumed.wait_until("the resumed first frame contains the prior answer", |pty| {
        let screen = pty.screen_text();
        screen.contains("parity reply") && screen.contains(CLIENT_PARITY_TASK.trim())
    });
    assert!(
        !resumed
            .screen_text()
            .contains("Iteron · Build, explain, and verify"),
        "the fresh-session welcome must be replaced by durable history:\n{}",
        resumed.screen_text()
    );
    resumed.send(b"\x1b");
    assert!(resumed.wait_for_exit().success());
    assert_termios_restored(&resumed);
    resumed.close_and_drain();
    resumed.assert_terminal_restored();
}

fn interrupt_running_bash_tool_from_real_pty(key: &[u8], label: &str) {
    let scratch = Scratch::new(label);
    let provider = BlockingBashToolProvider::spawn(&scratch.repo());
    scratch.configure_link_provider(&provider.api_root);
    let mut pty = PtyHarness::spawn_link_fixture(&scratch, 96, 26);

    pty.wait_until("the model-declared bash child is running", |pty| {
        provider.started.is_file() && pty.screen_text().contains("Bash")
    });
    pty.send(key);
    pty.wait_until("the interrupted tool returns the composer to idle", |pty| {
        pty.screen_text().contains("idle · input ready")
    });

    // The shell intentionally launched a delayed background descendant. Waiting past that delay
    // proves cancellation killed the process group, not merely the direct shell future.
    thread::sleep(Duration::from_millis(2200));
    pty.drain_ready();
    assert!(
        !provider.escaped.exists(),
        "the interrupted bash descendant survived the process-group cancellation"
    );

    pty.send(b"\x1b");
    let status = pty.wait_for_exit();
    assert!(status.success(), "post-interrupt TUI exit failed: {status}");
    assert_termios_restored(&pty);
    pty.close_and_drain();
    pty.assert_terminal_restored();
    provider.finish();

    let interrupted = std::fs::read_dir(scratch.runs())
        .expect("read interrupted rollout directory")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "jsonl")
        })
        .any(|entry| {
            iteron_record::replay(&entry.path())
                .expect("interrupted rollout replays")
                .iter()
                .any(|event| {
                    matches!(
                        &event.kind,
                        iteron_protocol::EventKind::Done { outcome } if outcome == "Interrupted"
                    )
                })
        });
    assert!(
        interrupted,
        "the durable terminal authority must retain the interrupted outcome"
    );
}

#[test]
fn ctrl_c_interrupts_a_running_bash_tool_and_kills_its_descendants() {
    interrupt_running_bash_tool_from_real_pty(b"\x03", "ctrl-c-bash-tool");
}

#[test]
fn double_ctrl_c_forces_exit_while_a_bash_tool_is_still_running() {
    let scratch = Scratch::new("double-ctrl-c-bash-tool");
    let provider = BlockingBashToolProvider::spawn(&scratch.repo());
    let escaped = provider.escaped.clone();
    scratch.configure_link_provider(&provider.api_root);
    let mut pty = PtyHarness::spawn_link_fixture(&scratch, 96, 26);
    pty.wait_until("the model-declared bash child is running", |pty| {
        provider.started.is_file() && pty.screen_text().contains("Bash")
    });

    let forced_at = Instant::now();
    pty.send(b"\x03\x03");
    let status = pty.wait_for_exit();
    assert!(status.success(), "forced TUI exit failed: {status}");
    // The claim is that a second Ctrl-C skips the shutdown grace -- not that this machine is fast.
    //
    // The normal path waits `workflow::SHUTDOWN_GRACE` (5s) plus `SHUTDOWN_WAIT_SLACK` (1s), so
    // the property is "well under six seconds". The bound was a hardcoded 2s, which measured
    // process teardown and PTY drain as well as the grace, and had no relation to the 5s it was
    // supposed to be proving the absence of. Locally it failed roughly one run in three at
    // 2.4-3.1s -- every one of those runs having correctly skipped the grace. Four seconds is
    // comfortably below the six the slow path costs and comfortably above the teardown, so it
    // fails only if the grace is actually taken, and it scales like every other bound here.
    const GRACE_PLUS_SLACK: Duration = Duration::from_secs(6);
    let forced_budget = Duration::from_secs(4) * timeout_scale();
    let forced_elapsed = forced_at.elapsed();
    assert!(
        forced_elapsed < forced_budget,
        "double Ctrl-C waited through the normal workflow shutdown grace \
         ({GRACE_PLUS_SLACK:?}): took {forced_elapsed:?}, budget {forced_budget:?}"
    );
    assert_termios_restored(&pty);
    pty.close_and_drain();
    pty.assert_terminal_restored();
    provider.finish();

    thread::sleep(Duration::from_millis(2200));
    assert!(
        !escaped.exists(),
        "bounded forced shutdown left the bash descendant alive"
    );
}

#[test]
fn esc_interrupts_a_running_bash_tool_and_kills_its_descendants() {
    interrupt_running_bash_tool_from_real_pty(b"\x1b", "esc-bash-tool");
}

#[test]
fn fullscreen_wheel_scrolls_session_and_ctrl_t_toggles_native_selection() {
    let scratch = Scratch::new("fullscreen-session-scroll");
    let mut pty = PtyHarness::spawn(&scratch, 110, 24);
    wait_for_ready(&mut pty);

    // The default is a real alternate-screen application. Mouse reporting keeps the wheel inside
    // the current session instead of exposing shell scrollback from before Core started.
    pty.wait_until("full-screen application mouse mode", |pty| {
        let screen = pty.parser.screen();
        screen.alternate_screen() && screen.mouse_protocol_mode() != vt100::MouseProtocolMode::None
    });
    let (cursor_row, _) = pty.parser.screen().cursor_position();
    assert!(
        (10..=20).contains(&cursor_row),
        "the full-height landing must vertically group its centered welcome and composer instead \
         of rendering as a bottom terminal dock; cursor row was {cursor_row}"
    );
    let alternate = find_sequence(&pty.capture, b"\x1b[?1049h")
        .expect("full-screen launch enters the alternate screen");
    let first_frame = find_sequence(&pty.capture, FIRST_FRAME_MARKER)
        .expect("the full-screen landing frame reaches the terminal");
    assert!(
        alternate < first_frame,
        "alternate-screen ownership must precede the landing frame"
    );
    // This ordinary xterm fixture is outside the closed progressive-keyboard allowlist, so there
    // is no capability query to synchronize with. Dedicated kitty/silent fixtures cover the
    // post-paint query and unanswered-query paths.
    assert!(!pty.keyboard_query_answered);

    // A long local-only shell card must overflow Core's own transcript viewport.
    pty.send(b"!seq 1 80 | sed 's/^/fold-me-/'");
    pty.wait_until(
        "long shell command reaches the full-height composer",
        |pty| pty.screen_text().contains("fold-me-"),
    );
    pty.send(b"\r");
    pty.wait_until("long shell card", |pty| {
        pty.capture
            .windows(b"fold-me-80".len())
            .any(|window| window == b"fold-me-80")
    });
    const DRAFT: &str = "wheel-must-not-touch-draft";
    pty.send(DRAFT.as_bytes());
    pty.wait_until("unsent draft in the live viewport", |pty| {
        pty.screen_text().contains(DRAFT)
    });

    for _ in 0..24 {
        pty.send(b"\x1b[<64;1;1M"); // SGR wheel up
    }
    pty.wait_until("wheel reveals older in-session transcript", |pty| {
        let screen = pty.screen_text();
        screen.contains("fold-me-1") && screen.contains(DRAFT)
    });

    // Ctrl-T releases only mouse reporting. The alternate-screen application stays intact, so a
    // zero-modifier drag belongs to native terminal selection; another Ctrl-T restores app scroll.
    pty.send(b"\x14");
    pty.wait_until("Ctrl-T native selection mode", |pty| {
        let screen = pty.parser.screen();
        screen.alternate_screen() && screen.mouse_protocol_mode() == vt100::MouseProtocolMode::None
    });
    pty.send(b"\x14");
    pty.wait_until("Ctrl-T restores application mouse mode", |pty| {
        let screen = pty.parser.screen();
        screen.alternate_screen() && screen.mouse_protocol_mode() != vt100::MouseProtocolMode::None
    });
    for _ in 0..24 {
        pty.send(b"\x1b[<65;1;1M"); // SGR wheel down
    }
    pty.wait_until("wheel returns to current-session tail", |pty| {
        let screen = pty.screen_text();
        screen.contains("fold-me-80") && screen.contains(DRAFT)
    });
    pty.send(b"\x1b");
    pty.wait_until("clear unchanged draft", |pty| {
        !pty.screen_text().contains(DRAFT)
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
    // Unknown terminal families take the portable path immediately instead of paying the
    // capability detector's two-second negative timeout.
    assert!(find_sequence(&pty.capture, KEYBOARD_ENHANCEMENT_QUERY).is_none());
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
    pty.wait_until("keyboard enhancement is active before SIGTERM", |pty| {
        sequence_count(&pty.capture, KEYBOARD_ENHANCEMENT_PUSH) == 1
    });

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
    pty.wait_until("keyboard enhancement is active before SIGHUP", |pty| {
        sequence_count(&pty.capture, KEYBOARD_ENHANCEMENT_PUSH) == 1
    });

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
