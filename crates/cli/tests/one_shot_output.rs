use serde_json::{Value, json};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::process::CommandExt;

const PROCESS_TIMEOUT: Duration = Duration::from_secs(15);
const SERVER_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_CAPTURE_BYTES: usize = 256 * 1024;
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
#[cfg(unix)]
const MAX_PROXY_REQUEST_BYTES: usize = 16 * 1024;
#[cfg(unix)]
const MAX_PROXY_CONNECTIONS: usize = 8;
const PROVIDER_ID: &str = "golden";
const MODEL_ID: &str = "golden-model";
const TEST_KEY_ENV: &str = "CORE_GOLDEN_TEST_KEY";
const TEST_KEY: &str = "integration-test-placeholder";

static NEXT_SCRATCH_ID: AtomicU64 = AtomicU64::new(0);

struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(label: &str, api_root: &str) -> Self {
        let id = NEXT_SCRATCH_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "core-cli-one-shot-{label}-{}-{id}",
            std::process::id()
        ));
        let scratch = Self { root };
        fs::create_dir_all(scratch.repo()).expect("create isolated repository");
        fs::create_dir_all(scratch.home().join(".core")).expect("create isolated Core home");
        fs::create_dir_all(scratch.runs()).expect("create isolated rollout directory");

        let config = json!({
            "provider": PROVIDER_ID,
            "model": MODEL_ID,
            "effort": "low",
            "max_wall_secs": 10,
            "providers": [{
                "id": PROVIDER_ID,
                "display_name": "Golden fixture provider",
                "adapter": "openai_chat",
                "error_profile": "custom",
                "api_root": api_root,
                "key_env": TEST_KEY_ENV,
                "enabled": true,
                "catalog": false,
                "models": [MODEL_ID]
            }]
        });
        fs::write(
            scratch.home().join(".core/config.json"),
            serde_json::to_vec(&config).expect("encode test config"),
        )
        .expect("write isolated test config");
        scratch
    }

    #[cfg(unix)]
    fn new_glm(label: &str) -> Self {
        let scratch = Self::new(label, "http://127.0.0.1:9/v1");
        let config = json!({
            "provider": "glm",
            "model": "glm-5.2",
            "effort": "low",
            "max_wall_secs": 5
        });
        fs::write(
            scratch.home().join(".core/config.json"),
            serde_json::to_vec(&config).expect("encode isolated GLM config"),
        )
        .expect("write isolated GLM config");
        scratch
    }

    #[cfg(unix)]
    fn install_glm_operator_metadata(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock is after the Unix epoch")
            .as_secs();
        let captured = now.saturating_sub(42 * 24 * 60 * 60);
        let mut document: Value = serde_json::from_str(include_str!(
            "../../provider/static-provider-metadata-v1.json"
        ))
        .expect("embedded provider metadata fixture is valid JSON");
        document["bundle_revision"] = json!("cli-process-evidence@v2");
        document["glm_standard_chat"]["version"] = json!("glm-cli-process-catalog@v2");
        document["glm_standard_chat"]["captured_at_unix_secs"] = json!(captured);
        document["glm_standard_chat"]["capabilities"]["glm-5.2"]["version"] =
            json!("glm-5.2-cli-process-capability@v2");
        document["glm_standard_chat"]["capabilities"]["glm-5.2"]["captured_at_unix_secs"] =
            json!(captured);
        core_provider::StaticProviderMetadata::stamp_content_versions(&mut document)
            .expect("stamp operator metadata content versions");

        let path = self.home().join(".core/provider-metadata.json");
        let bytes = serde_json::to_vec(&document).expect("encode operator metadata");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .expect("create owner-only operator metadata without following a link");
        file.write_all(&bytes).expect("write operator metadata");
        file.sync_all().expect("persist operator metadata fixture");
        drop(file);

        let metadata = fs::symlink_metadata(&path).expect("inspect operator metadata fixture");
        assert!(metadata.is_file());
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.mode() & 0o077, 0, "metadata must be owner-only");
        assert_eq!(metadata.nlink(), 1, "metadata must have one hard link");
        // SAFETY: geteuid has no preconditions and only reads the process identity.
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
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

    fn seed_redacted_resume(&self, run_id: &str) {
        let run = core_protocol::RunId(run_id.into());
        let mut rollout =
            core_record::Rollout::open(&self.runs(), &run, core_protocol::TenantId::default())
                .expect("open diagnostic resume fixture");
        rollout
            .append(&core_protocol::Event {
                seq: core_protocol::Seq::ZERO,
                turn: core_protocol::TurnId(0),
                kind: core_protocol::EventKind::RunStart {
                    cwd: self.repo().display().to_string(),
                    model: MODEL_ID.into(),
                    effort: core_protocol::Effort::Low,
                    created_at: 1,
                    environment: None,
                    parent_run: None,
                    forked_at: None,
                    parent_hash_at_seq: None,
                    config_digest: String::new(),
                    max_usd: None,
                },
            })
            .expect("append diagnostic fixture genesis");
        rollout
            .append(&core_protocol::Event {
                seq: core_protocol::Seq::ZERO,
                turn: core_protocol::TurnId(0),
                kind: core_protocol::EventKind::Message {
                    message: core_protocol::Message {
                        role: core_protocol::Role::Assistant,
                        content: vec![core_protocol::Block::ToolUse(core_protocol::ToolUse {
                            id: "resume-secret-read".into(),
                            name: "read_file".into(),
                            input: json!({"path":"fixture.txt"}),
                        })],
                    },
                },
            })
            .expect("append diagnostic fixture tool request");
        let secret = "sk-ant-api03-SuperSecretResumeTokenValue12345";
        rollout
            .append(&core_protocol::Event {
                seq: core_protocol::Seq::ZERO,
                turn: core_protocol::TurnId(0),
                kind: core_protocol::EventKind::Message {
                    message: core_protocol::Message {
                        role: core_protocol::Role::User,
                        content: vec![core_protocol::Block::ToolResult(
                            core_protocol::ToolResult {
                                tool_use_id: "resume-secret-read".into(),
                                content: format!("provider returned {secret}"),
                                is_error: false,
                                trust: core_protocol::Trust::Workspace,
                                latency_ms: 1,
                            },
                        )],
                    },
                },
            })
            .expect("append redacted diagnostic fixture result");
        drop(rollout);

        let raw = fs::read_to_string(self.runs().join(format!("{run_id}.jsonl")))
            .expect("read redacted diagnostic fixture");
        assert!(!raw.contains(secret));
        assert!(raw.contains("[REDACTED"));
    }
}

#[cfg(unix)]
struct FailingHttpsProxy {
    api_root: String,
    cancelled: Arc<AtomicBool>,
    result: Receiver<Result<Vec<String>, String>>,
    handle: Option<thread::JoinHandle<()>>,
}

#[cfg(unix)]
impl FailingHttpsProxy {
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback HTTPS proxy");
        listener
            .set_nonblocking(true)
            .expect("make proxy accept bounded");
        let address = listener.local_addr().expect("read loopback proxy address");
        let cancelled = Arc::new(AtomicBool::new(false));
        let thread_cancelled = cancelled.clone();
        let (result_tx, result) = sync_channel(1);
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + SERVER_TIMEOUT;
            let mut requests = Vec::new();
            let outcome = loop {
                let stopping = thread_cancelled.load(Ordering::Acquire);
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        if requests.len() >= MAX_PROXY_CONNECTIONS {
                            break Err("HTTPS proxy observed too many physical connections".into());
                        }
                        if let Err(error) = stream.set_nonblocking(false) {
                            break Err(format!(
                                "make accepted HTTPS proxy socket blocking: {error}"
                            ));
                        }
                        match reject_glm_connect(&mut stream) {
                            Ok(request) => requests.push(request),
                            Err(error) => break Err(error),
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && stopping => {
                        // `finish` sets the stop flag only after the child exits. Drain every
                        // connection already queued in the listener before closing the evidence
                        // window, so a concurrent retry cannot hide behind cancellation.
                        break Ok(requests);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if requests.is_empty() && Instant::now() >= deadline {
                            break Err("core never connected to the loopback HTTPS proxy".into());
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => {
                        break Err(format!("loopback HTTPS proxy accept failed: {error}"));
                    }
                }
            };
            let _ = result_tx.send(outcome);
        });
        Self {
            api_root: format!("http://{address}"),
            cancelled,
            result,
            handle: Some(handle),
        }
    }

    fn finish(mut self) -> Vec<String> {
        // The Core child has exited before this call. Keep accepting until then so an accidental
        // discovery request or transparent transport retry cannot hide behind the first CONNECT.
        self.cancelled.store(true, Ordering::Release);
        let outcome = self
            .result
            .recv_timeout(SERVER_TIMEOUT)
            .expect("loopback HTTPS proxy reports within its bound");
        self.handle
            .take()
            .expect("proxy thread exists")
            .join()
            .expect("loopback HTTPS proxy thread did not panic");
        outcome.unwrap_or_else(|error| panic!("{error}"))
    }
}

#[cfg(unix)]
impl Drop for FailingHttpsProxy {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(unix)]
fn reject_glm_connect(stream: &mut TcpStream) -> Result<String, String> {
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("bound proxy request read: {error}"))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("bound proxy response write: {error}"))?;
    let mut request = Vec::new();
    loop {
        let mut chunk = [0_u8; 2 * 1024];
        let read = stream
            .read(&mut chunk)
            .map_err(|error| format!("read HTTPS CONNECT request: {error}"))?;
        if read == 0 {
            return Err("HTTPS proxy request ended before its headers".into());
        }
        request.extend_from_slice(&chunk[..read]);
        if request.len() > MAX_PROXY_REQUEST_BYTES {
            return Err("HTTPS CONNECT request exceeded its test bound".into());
        }
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let headers = std::str::from_utf8(&request)
        .map_err(|_| "HTTPS CONNECT request was not UTF-8".to_string())?;
    let request_line = headers
        .lines()
        .next()
        .ok_or_else(|| "HTTPS CONNECT request had no request line".to_string())?;
    if request_line != "CONNECT open.bigmodel.cn:443 HTTP/1.1" {
        return Err(format!(
            "built-in GLM did not target its exact official HTTPS authority: {request_line}"
        ));
    }
    if headers.to_ascii_lowercase().contains("authorization:") {
        return Err("the inert origin key must not be exposed to the CONNECT proxy".into());
    }
    stream
        .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .map_err(|error| format!("write bounded proxy failure: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("flush bounded proxy failure: {error}"))?;
    Ok(request_line.into())
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Clone, Copy)]
enum Reply {
    Success,
    InvalidStream,
    FailingRead { index: u32 },
}

struct MockProvider {
    api_root: String,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockProvider {
    fn spawn(reply: Reply) -> Self {
        Self::spawn_script(vec![reply])
    }

    fn spawn_script(replies: Vec<Reply>) -> Self {
        Self::spawn_script_with_capture(replies, None)
    }

    fn spawn_capturing_script(replies: Vec<Reply>) -> (Self, Receiver<Value>) {
        let (sender, receiver) = sync_channel(replies.len().max(1));
        (
            Self::spawn_script_with_capture(replies, Some(sender)),
            receiver,
        )
    }

    fn spawn_script_with_capture(
        replies: Vec<Reply>,
        request_capture: Option<SyncSender<Value>>,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback provider stub");
        listener
            .set_nonblocking(true)
            .expect("make provider accept bounded");
        let address = listener.local_addr().expect("read provider stub address");
        let handle = thread::spawn(move || {
            for reply in replies {
                let mut stream = accept_connection(&listener);
                let request = assert_request(&mut stream);
                if let Some(sender) = &request_capture {
                    sender
                        .send(request)
                        .expect("capture provider request within the bounded test channel");
                }
                write_reply(&mut stream, reply);
            }
        });
        Self {
            api_root: format!("http://{address}/v1"),
            handle: Some(handle),
        }
    }

    #[cfg(unix)]
    fn spawn_paused_success() -> (Self, Receiver<()>, SyncSender<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback provider stub");
        listener
            .set_nonblocking(true)
            .expect("make provider accept bounded");
        let address = listener.local_addr().expect("read provider stub address");
        let (request_seen_tx, request_seen_rx) = sync_channel(1);
        let (release_tx, release_rx) = sync_channel(1);
        let handle = thread::spawn(move || {
            let mut stream = accept_connection(&listener);
            assert_request(&mut stream);
            request_seen_tx
                .send(())
                .expect("notify test that provider turn is in flight");
            release_rx
                .recv_timeout(SERVER_TIMEOUT)
                .expect("test releases the bounded provider turn");
            write_reply(&mut stream, Reply::Success);
        });
        (
            Self {
                api_root: format!("http://{address}/v1"),
                handle: Some(handle),
            },
            request_seen_rx,
            release_tx,
        )
    }

    fn finish(mut self) {
        self.handle
            .take()
            .expect("provider thread exists")
            .join()
            .expect("provider stub completed cleanly");
    }
}

fn accept_connection(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + SERVER_TIMEOUT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .expect("make accepted provider socket blocking");
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "core never connected to the loopback provider stub"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("provider stub accept failed: {error}"),
        }
    }
}

fn assert_request(stream: &mut TcpStream) -> Value {
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("bound provider request read");
    let request = read_http_request(stream);
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("request has complete headers");
    let headers = std::str::from_utf8(&request[..header_end]).expect("request headers are UTF-8");
    let mut lines = headers.lines();
    assert_eq!(
        lines.next(),
        Some("POST /v1/chat/completions HTTP/1.1"),
        "core must exercise the real chat-completions adapter"
    );
    let lowercase_headers = headers.to_ascii_lowercase();
    assert!(
        lowercase_headers.contains("authorization: bearer integration-test-placeholder"),
        "the isolated placeholder credential was not used"
    );

    let body: Value =
        serde_json::from_slice(&request[header_end + 4..]).expect("provider request body is JSON");
    assert_eq!(body["model"], MODEL_ID);
    assert_eq!(body["stream"], true);
    assert_eq!(body["stream_options"]["include_usage"], true);
    body
}

fn request_system(request: &Value) -> &str {
    request["messages"]
        .as_array()
        .expect("provider messages are an array")
        .iter()
        .find(|message| message["role"] == "system")
        .and_then(|message| message["content"].as_str())
        .expect("provider request has one textual system message")
}

#[cfg(unix)]
fn git_fixture(root: &std::path::Path, args: &[&str]) {
    let output = Command::new("git")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .current_dir(root)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run fixture Git");
    assert!(
        output.status.success(),
        "fixture Git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut content_length = None;
    loop {
        let mut chunk = [0_u8; 8 * 1024];
        let read = stream.read(&mut chunk).expect("read provider request");
        assert!(read > 0, "provider request ended before its body");
        request.extend_from_slice(&chunk[..read]);
        assert!(
            request.len() <= MAX_REQUEST_BYTES,
            "provider request exceeded the integration-test bound"
        );

        if content_length.is_none()
            && let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n")
        {
            let headers = std::str::from_utf8(&request[..header_end])
                .expect("provider request headers are UTF-8");
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().expect("valid content-length"))
                })
                .expect("provider request has content-length");
            content_length = Some((header_end + 4, length));
        }
        if let Some((body_start, length)) = content_length
            && request.len() >= body_start.saturating_add(length)
        {
            assert_eq!(request.len(), body_start + length);
            return request;
        }
    }
}

fn write_reply(stream: &mut TcpStream, reply: Reply) {
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .expect("bound provider response write");
    let body = match reply {
        Reply::Success => concat!(
            "data: {\"id\":\"chatcmpl-golden\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"golden reply\"},\"finish_reason\":null}],\"usage\":null}\n\n",
            "data: {\"id\":\"chatcmpl-golden\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":null}\n\n",
            "data: {\"id\":\"chatcmpl-golden\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":2,\"total_tokens\":13,\"prompt_tokens_details\":{\"cached_tokens\":0},\"completion_tokens_details\":{\"reasoning_tokens\":0}}}\n\n",
            "data: [DONE]\n\n",
        )
        .to_string(),
        Reply::InvalidStream => "data: this-is-not-json\n\n".to_string(),
        Reply::FailingRead { index } => format!(
            concat!(
                "data: {{\"id\":\"chatcmpl-stuck-{index}\",\"object\":\"chat.completion.chunk\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\",\"tool_calls\":[{{\"index\":0,\"id\":\"call-stuck-{index}\",\"type\":\"function\",\"function\":{{\"name\":\"read_file\",\"arguments\":\"{{\\\"path\\\":\\\"missing-fixture-{index}\\\"}}\"}}}}]}},\"finish_reason\":null}}],\"usage\":null}}\n\n",
                "data: {{\"id\":\"chatcmpl-stuck-{index}\",\"object\":\"chat.completion.chunk\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"tool_calls\"}}],\"usage\":null}}\n\n",
                "data: {{\"id\":\"chatcmpl-stuck-{index}\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{{\"prompt_tokens\":11,\"completion_tokens\":1,\"total_tokens\":12,\"prompt_tokens_details\":{{\"cached_tokens\":0}},\"completion_tokens_details\":{{\"reasoning_tokens\":0}}}}}}\n\n",
                "data: [DONE]\n\n",
            ),
            index = index,
        ),
    };
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .expect("write provider response");
    stream.flush().expect("flush provider response");
}

fn core_command(scratch: &Scratch, format: &str, max_turns: u32, extra_args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_core"));
    // Never inherit a developer credential, proxy, user config, or launcher. The only credential
    // visible to the child is the inert placeholder consumed by the loopback-only provider.
    command
        .env_clear()
        .env("HOME", scratch.home())
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env(TEST_KEY_ENV, TEST_KEY)
        .current_dir(scratch.repo())
        .arg("-p")
        .arg("return the deterministic fixture response")
        .arg("--output-format")
        .arg(format)
        .arg("--repo")
        .arg(scratch.repo())
        .arg("--runs-dir")
        .arg(scratch.runs())
        .arg("--provider")
        .arg(PROVIDER_ID)
        .arg("--model")
        .arg(MODEL_ID)
        .arg("--effort")
        .arg("low")
        .arg("--max-turns")
        .arg(max_turns.to_string())
        .args(extra_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(unix)]
    command.process_group(0);

    command
}

fn sessions_command(scratch: &Scratch) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_core"));
    command
        .env_clear()
        .env("HOME", scratch.home())
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .current_dir(scratch.repo())
        .arg("--repo")
        .arg(scratch.repo())
        .arg("--runs-dir")
        .arg(scratch.runs())
        .arg("--sessions")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(unix)]
    command.process_group(0);

    command
}

#[cfg(unix)]
fn glm_core_command(scratch: &Scratch, format: &str, proxy_url: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_core"));
    // Exercise the built-in official GLM route without inheriting developer network state. Both
    // conventional proxy spellings point at the same loopback-only CONNECT rejector, so no DNS or
    // public connection is needed and the inert key can never reach an origin.
    command
        .env_clear()
        .env("HOME", scratch.home())
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("HTTPS_PROXY", proxy_url)
        .env("https_proxy", proxy_url)
        .env("HTTP_PROXY", proxy_url)
        .env("http_proxy", proxy_url)
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .env("GLM_API_KEY", TEST_KEY)
        .current_dir(scratch.repo())
        .arg("-p")
        .arg("exercise the operator metadata notice before the local proxy failure")
        .arg("--output-format")
        .arg(format)
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
        .arg("--max-turns")
        .arg("1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    command
}

fn spawn_core(scratch: &Scratch, format: &str, max_turns: u32, extra_args: &[&str]) -> Child {
    core_command(scratch, format, max_turns, extra_args)
        .spawn()
        .expect("spawn the real core binary")
}

#[cfg(unix)]
fn spawn_glm_core(scratch: &Scratch, format: &str, proxy_url: &str) -> Child {
    glm_core_command(scratch, format, proxy_url)
        .spawn()
        .expect("spawn the real core binary for built-in GLM")
}

#[cfg(unix)]
struct ChildGuard {
    child: Option<Child>,
}

#[cfg(unix)]
impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn child(&self) -> &Child {
        self.child.as_ref().expect("guard owns the child")
    }

    fn into_child(mut self) -> Child {
        self.child.take().expect("guard owns the child")
    }
}

#[cfg(unix)]
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if !matches!(child.try_wait(), Ok(Some(_))) {
            kill_child_group(&mut child);
        }
        let _ = child.wait_with_output();
    }
}

fn run_core(scratch: &Scratch, format: &str, extra_args: &[&str]) -> Output {
    collect_core(spawn_core(scratch, format, 1, extra_args))
}

#[cfg(unix)]
fn only_rollout_path(scratch: &Scratch) -> PathBuf {
    let mut paths = fs::read_dir(scratch.runs())
        .expect("read rollout directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "jsonl")
        })
        .collect::<Vec<_>>();
    paths.sort();
    assert_eq!(paths.len(), 1, "real process creates exactly one rollout");
    paths.pop().expect("one rollout path")
}

fn collect_core(mut child: Child) -> Output {
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    loop {
        match child.try_wait().expect("poll core child") {
            Some(_) => {
                let output = child.wait_with_output().expect("collect core output");
                assert_bounded_capture(&output);
                return output;
            }
            None if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            None => {
                kill_child_group(&mut child);
                let output = child
                    .wait_with_output()
                    .expect("collect timed-out core output");
                panic!(
                    "core exceeded the {PROCESS_TIMEOUT:?} process bound; stderr:\n{}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }
}

fn kill_child_group(child: &mut Child) {
    #[cfg(unix)]
    // The child is its own process-group leader. A timeout must not leave any provider/tool helper
    // it may have started behind after the integration-test process moves on.
    // SAFETY: the negated live child pid identifies only the process group created in `core_command`.
    unsafe {
        let _ = libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
    }
    let _ = child.kill();
}

#[cfg(unix)]
fn send_sigint(child: &Child) {
    // SAFETY: `child.id()` is the live pid returned by `spawn`; SIGINT neither aliases memory nor
    // transfers ownership. The child remains owned and is collected by `collect_core`.
    let result = unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGINT) };
    assert_eq!(result, 0, "send exactly one SIGINT to the one-shot child");
}

fn assert_bounded_capture(output: &Output) {
    assert!(
        output.stdout.len() <= MAX_CAPTURE_BYTES,
        "stdout exceeded the process-test bound"
    );
    assert!(
        output.stderr.len() <= MAX_CAPTURE_BYTES,
        "stderr exceeded the process-test bound"
    );
}

fn json_lines(stdout: &[u8]) -> Vec<Value> {
    assert!(!stdout.is_empty(), "machine stdout must not be empty");
    assert_eq!(stdout.last(), Some(&b'\n'), "stdout needs a final newline");
    assert_ne!(
        stdout.get(stdout.len().saturating_sub(2)),
        Some(&b'\n'),
        "stdout must not contain a trailing blank line"
    );
    let text = std::str::from_utf8(stdout).expect("machine stdout is UTF-8");
    assert!(!text.contains('\r'), "machine stdout uses LF line endings");
    text.strip_suffix('\n')
        .expect("final newline already checked")
        .split('\n')
        .map(|line| {
            assert!(
                !line.is_empty(),
                "machine stdout has no blank JSONL records"
            );
            serde_json::from_str(line).expect("every stdout line is one JSON object")
        })
        .collect()
}

fn structured_kernel_diagnostics(stderr: &[u8]) -> Vec<Value> {
    std::str::from_utf8(stderr)
        .expect("stderr is UTF-8")
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|value| value["type"] == "kernel_diagnostic")
        .collect()
}

fn normalize_runtime_fields(values: &mut [Value]) {
    for value in values {
        if let Some(run_id) = value.get_mut("run_id") {
            *run_id = json!("<RUN_ID>");
        }
        if value.get("type") == Some(&json!("turn_end"))
            && let Some(context) = value.get_mut("context").and_then(Value::as_object_mut)
        {
            for field in [
                "input_tokens",
                "system_tokens",
                "tool_tokens",
                "transcript_tokens",
                "framing_tokens",
                "reserved_output_tokens",
                "compaction_trigger_tokens",
            ] {
                if let Some(slot) = context.get_mut(field) {
                    *slot = json!(0);
                }
            }
        }
    }
}

fn golden_lines(path: &str, contents: &str) -> Vec<Value> {
    contents
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            serde_json::from_str(line)
                .unwrap_or_else(|error| panic!("invalid golden {path} line {}: {error}", index + 1))
        })
        .collect()
}

fn assert_diagnostics_on_stderr(output: &Output, outcome: &str) {
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    let stderr = std::str::from_utf8(&output.stderr).expect("stderr is UTF-8");
    assert!(stderr.contains("core · repo="));
    assert!(stderr.contains("record: "));
    assert!(stderr.contains(&format!("outcome: {outcome}")));
    assert!(!stdout.contains("core · repo="));
    assert!(!stdout.contains("record: "));
    assert!(
        !stderr.contains("\"schema_version\":4"),
        "machine result records belong exclusively on stdout"
    );
    assert!(!stderr.contains("golden reply"));
}

fn assert_terminal_result(value: &Value, expected_exit: i32, expected_outcome: &str) {
    assert!(value.is_object(), "terminal result is a JSON object");
    assert_eq!(value["schema_version"], 4);
    assert_eq!(value["type"], "result");
    assert_eq!(value["outcome"], expected_outcome);
    assert_eq!(value["exit_code"], expected_exit);
    assert_eq!(value["success"], expected_exit == 0);
    assert!(
        value["run_id"]
            .as_str()
            .is_some_and(|run_id| run_id.starts_with("run-") && run_id.len() > 4),
        "terminal result carries the actual non-empty run id"
    );
}

fn assert_machine_failure(
    value: &Value,
    expected_exit: i32,
    expected_outcome: &str,
    expected_cost_status: &str,
    expected_cost_reason: Option<&str>,
) {
    assert_terminal_result(value, expected_exit, expected_outcome);
    assert_eq!(value["cost_status"], expected_cost_status);
    match expected_cost_status {
        "zero" => assert_eq!(value["cost_usd"], 0.0),
        "unknown" => assert_eq!(value["cost_usd"], Value::Null),
        other => panic!("unexpected process-test cost status: {other}"),
    }
    assert_eq!(
        value["cost_reason"],
        expected_cost_reason.map_or(Value::Null, |reason| json!(reason))
    );
}

#[test]
fn d9_01_g1_g2_real_cli_sessions_and_continue_use_the_runtime_cache() {
    let server = MockProvider::spawn_script(vec![Reply::Success, Reply::Success]);
    let scratch = Scratch::new("d9-01-session-fast-path", &server.api_root);

    let first = run_core(&scratch, "json", &[]);
    assert_eq!(first.status.code(), Some(0));
    let mut rollout_paths: Vec<PathBuf> = fs::read_dir(scratch.runs())
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "jsonl")
        })
        .collect();
    rollout_paths.sort();
    assert_eq!(rollout_paths.len(), 1);
    let run_id = rollout_paths[0]
        .file_stem()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(scratch.runs().join(format!("{run_id}.meta.json")).is_file());
    assert!(scratch.runs().join("sessions.index").is_file());

    // Listing is deliberately credential-free and exits before provider construction. The
    // core-record unit gate instruments this same `list` call and proves covered runs execute zero
    // `meta_from_replay` calls; this process gate freezes the CLI routing to that fast path.
    let sessions = collect_core(sessions_command(&scratch).spawn().unwrap());
    assert_eq!(sessions.status.code(), Some(0));
    let sessions_stdout = String::from_utf8(sessions.stdout).unwrap();
    assert!(sessions_stdout.contains(&run_id));
    assert!(sessions_stdout.contains("return the deterministic fixture response"));

    let continued = collect_core(spawn_core(&scratch, "json", 2, &["--continue"]));
    server.finish();
    assert_eq!(continued.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&continued.stderr).contains(&format!(
            "continuing most recent session in this repo: {run_id}"
        ))
    );
    let meta = core_record::meta(&scratch.runs(), &core_protocol::RunId(run_id.clone())).unwrap();
    assert_eq!(meta.turns, 2);
    let index = fs::read_to_string(scratch.runs().join("sessions.index")).unwrap();
    let indexed: Vec<core_record::SessionMeta> = index
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(indexed.len(), 1);
    assert_eq!(indexed[0].run_id.0, run_id);
}

#[test]
fn text_one_shot_process_contract_is_byte_exact() {
    let server = MockProvider::spawn(Reply::Success);
    let scratch = Scratch::new("text-success", &server.api_root);
    let output = run_core(&scratch, "text", &[]);
    server.finish();

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stdout,
        include_bytes!("golden/one_shot_text_success.txt"),
        "text stdout is a byte-exact stable contract"
    );
    assert_diagnostics_on_stderr(&output, "Done");
}

#[test]
fn json_one_shot_process_contract_matches_golden() {
    let server = MockProvider::spawn(Reply::Success);
    let scratch = Scratch::new("json-success", &server.api_root);
    let output = run_core(&scratch, "json", &[]);
    server.finish();

    assert_eq!(output.status.code(), Some(0));
    let mut actual = json_lines(&output.stdout);
    assert_eq!(actual.len(), 1, "json mode emits exactly one object");
    assert_terminal_result(&actual[0], 0, "done");
    assert_diagnostics_on_stderr(&output, "Done");
    normalize_runtime_fields(&mut actual);
    assert_eq!(
        actual,
        golden_lines(
            "one_shot_json_success_v4.json",
            include_str!("golden/one_shot_json_success_v4.json")
        )
    );
}

#[test]
fn stream_json_one_shot_process_contract_matches_golden() {
    let server = MockProvider::spawn(Reply::Success);
    let scratch = Scratch::new("stream-json-success", &server.api_root);
    let output = run_core(&scratch, "stream-json", &[]);
    server.finish();

    assert_eq!(output.status.code(), Some(0));
    let mut actual = json_lines(&output.stdout);
    assert!(actual.len() > 1, "stream-json emits lifecycle records");
    assert_eq!(
        actual
            .iter()
            .filter(|value| value["type"] == "result")
            .count(),
        1,
        "stream-json has exactly one terminal result"
    );
    assert_terminal_result(actual.last().expect("terminal record"), 0, "done");
    assert_diagnostics_on_stderr(&output, "Done");
    normalize_runtime_fields(&mut actual);
    assert_eq!(
        actual,
        golden_lines(
            "one_shot_stream_json_success_v4.jsonl",
            include_str!("golden/one_shot_stream_json_success_v4.jsonl")
        )
    );
}

#[cfg(unix)]
#[test]
fn d2_24_operator_glm_metadata_notice_is_loaded_surfaced_and_durable_before_attempt() {
    for format in ["text", "json", "stream-json"] {
        let proxy = FailingHttpsProxy::spawn();
        let scratch = Scratch::new_glm(&format!("d2-24-{format}"));
        scratch.install_glm_operator_metadata();

        let output = collect_core(spawn_glm_core(&scratch, format, &proxy.api_root));
        let connect_lines = proxy.finish();

        assert_eq!(
            connect_lines,
            ["CONNECT open.bigmodel.cn:443 HTTP/1.1"],
            "one durable TurnStart must correspond to exactly one physical CONNECT"
        );
        assert_eq!(
            output.status.code(),
            Some(2),
            "the deliberately rejected local proxy produces a harness failure"
        );

        let events = core_record::replay(&only_rollout_path(&scratch))
            .expect("built-in GLM rollout remains hash-valid after transport failure");
        let notices = events
            .iter()
            .enumerate()
            .filter_map(|(index, event)| match &event.kind {
                core_protocol::EventKind::Notice { text } => Some((index, text.as_str())),
                _ => None,
            })
            .collect::<Vec<_>>();
        let turn_starts = events
            .iter()
            .enumerate()
            .filter(|(_, event)| matches!(event.kind, core_protocol::EventKind::TurnStart))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        assert_eq!(
            notices.len(),
            1,
            "the operator metadata produces exactly one durable Notice"
        );
        assert_eq!(
            turn_starts.len(),
            1,
            "the failed physical provider attempt has one durable TurnStart"
        );
        let (notice_index, notice) = notices[0];
        assert_eq!(
            notice_index + 1,
            turn_starts[0],
            "the metadata Notice is durably adjacent to and before TurnStart"
        );
        assert!(notice.starts_with("provider run notice [key=sha256:"));
        assert!(notice.contains(
            "; code=static_metadata]: static provider metadata: provider revision changed;"
        ));
        assert!(notice.contains("catalog is 42 days old (stale)"));
        assert!(notice.contains("capability is 42 days old (stale)"));
        assert!(notice.contains("catalog=glm-cli-process-catalog@v2+sha256:"));
        assert!(notice.contains("capability=glm-5.2-cli-process-capability@v2+sha256:"));
        assert!(
            !notice.contains(TEST_KEY),
            "the inert key is absent from durable metadata evidence"
        );

        let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
        let stderr = std::str::from_utf8(&output.stderr).expect("stderr is UTF-8");
        match format {
            "text" | "json" => {
                let expected = format!("notice: {notice}");
                assert_eq!(
                    stderr.lines().filter(|line| *line == expected).count(),
                    1,
                    "{format} emits the metadata notice exactly once on stderr"
                );
                assert!(
                    !stdout.contains(notice)
                        && !stdout.contains("static provider metadata")
                        && !stdout.contains("glm-cli-process-catalog@v2"),
                    "{format} keeps notices off stdout"
                );
                if format == "json" {
                    let records = json_lines(&output.stdout);
                    assert_eq!(records.len(), 1, "json emits only its terminal result");
                    assert!(records.iter().all(|record| record["type"] != "notice"));
                    assert_terminal_result(
                        records.last().expect("terminal JSON result"),
                        2,
                        "harness_error",
                    );
                }
            }
            "stream-json" => {
                let records = json_lines(&output.stdout);
                let surfaced = records
                    .iter()
                    .filter(|record| record["type"] == "notice")
                    .collect::<Vec<_>>();
                assert_eq!(surfaced.len(), 1);
                assert_eq!(surfaced[0]["message"], notice);
                assert_terminal_result(
                    records.last().expect("terminal stream-json result"),
                    2,
                    "harness_error",
                );
                assert!(
                    !stderr.contains(notice)
                        && !stderr.contains("static provider metadata")
                        && !stderr.contains("glm-cli-process-catalog@v2"),
                    "stream-json keeps the metadata notice on stdout"
                );
            }
            _ => unreachable!("closed output-format fixture set"),
        }
    }
}

#[test]
fn d6_11_resume_uses_durable_instruction_bytes_once_after_live_file_changes() {
    let (server, requests) =
        MockProvider::spawn_capturing_script(vec![Reply::Success, Reply::Success]);
    let scratch = Scratch::new("durable-instructions", &server.api_root);
    let original = "D6-11 original instruction bytes";
    let changed = "D6-11 changed live instruction bytes";
    fs::write(scratch.repo().join("AGENTS.md"), original).expect("seed original instructions");

    let first = collect_core(spawn_core(&scratch, "json", 2, &[]));
    assert_eq!(first.status.code(), Some(0));
    let first_request = requests
        .recv_timeout(SERVER_TIMEOUT)
        .expect("capture the fresh provider request");
    let first_system = request_system(&first_request);
    assert_eq!(first_system.matches(original).count(), 1);
    assert!(!first_system.contains(changed));

    let mut rollout_paths = fs::read_dir(scratch.runs())
        .expect("read fresh rollout directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "jsonl")
        })
        .collect::<Vec<_>>();
    rollout_paths.sort();
    assert_eq!(rollout_paths.len(), 1, "fresh process creates one rollout");
    let rollout_path = rollout_paths.pop().unwrap();
    let run_id = rollout_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .expect("rollout has a UTF-8 run id")
        .to_string();

    fs::write(scratch.repo().join("AGENTS.md"), changed).expect("change live instructions");
    let resumed = collect_core(spawn_core(&scratch, "json", 2, &["--resume", &run_id]));
    assert_eq!(resumed.status.code(), Some(0));
    let resumed_request = requests
        .recv_timeout(SERVER_TIMEOUT)
        .expect("capture the resumed provider request");
    server.finish();

    let resumed_system = request_system(&resumed_request);
    assert_eq!(
        resumed_system, first_system,
        "resume reuses the exact durable frontend prefix"
    );
    assert_eq!(resumed_system.matches(original).count(), 1);
    assert!(!resumed_system.contains(changed));
    let injections = core_record::replay(&rollout_path)
        .expect("resume rollout replays")
        .into_iter()
        .filter_map(|event| match event.kind {
            core_protocol::EventKind::ContextInjection {
                text,
                trust,
                instructions,
            } => Some((text, trust, instructions)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(injections.len(), 1);
    let (legacy_text, legacy_trust, instructions) = &injections[0];
    assert!(legacy_text.is_empty());
    assert_eq!(*legacy_trust, core_protocol::Trust::Trusted);
    let instructions = instructions.as_ref().expect("durable frontend context");
    assert_eq!(instructions.text, core_ctx::framed("AGENTS.md", original));
    assert_eq!(instructions.trust, core_protocol::Trust::Untrusted);
    let environment = instructions
        .environment
        .as_ref()
        .expect("fresh environment snapshot");
    assert_eq!(environment.trust, core_protocol::Trust::Workspace);
    assert_eq!(first_system.matches(&environment.text).count(), 1);
    assert!(environment.text.contains("workspace_cwd:"));
    assert!(environment.text.contains("date_utc:"));
    assert!(environment.text.contains("captured_at_unix_secs:"));
    assert!(environment.text.contains("platform:"));
    assert!(environment.text.contains("git: unavailable"));
}

#[cfg(unix)]
#[test]
fn d6_02_environment_snapshot_is_bounded_durable_and_resume_does_not_invoke_git() {
    let (server, requests) =
        MockProvider::spawn_capturing_script(vec![Reply::Success, Reply::Success]);
    let scratch = Scratch::new("environment-facts", &server.api_root);
    git_fixture(&scratch.repo(), &["init", "--quiet"]);
    fs::write(scratch.repo().join("tracked-private-name"), "base\n").unwrap();
    git_fixture(&scratch.repo(), &["add", "--", "tracked-private-name"]);
    git_fixture(
        &scratch.repo(),
        &[
            "-c",
            "user.name=Core Environment Test",
            "-c",
            "user.email=environment@test.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "base",
        ],
    );
    git_fixture(&scratch.repo(), &["branch", "-M", "facts-original"]);
    fs::write(scratch.repo().join("untracked-private-name"), "untracked\n").unwrap();

    let first = collect_core(spawn_core(&scratch, "json", 2, &[]));
    assert_eq!(first.status.code(), Some(0));
    let first_request = requests
        .recv_timeout(SERVER_TIMEOUT)
        .expect("capture fresh provider request");
    let first_system = request_system(&first_request).to_owned();
    let canonical_cwd = scratch.repo().canonicalize().unwrap();
    assert!(first_system.contains(&format!("workspace_cwd: {}", canonical_cwd.display())));
    assert!(first_system.contains("date_utc:"));
    assert!(first_system.contains(&format!(
        "platform: {}/{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    )));
    assert!(first_system.contains(
        "git: branch=facts-original; status=staged:0,modified:0,untracked:1,conflicts:0"
    ));
    assert!(!first_system.contains("untracked-private-name"));

    let rollout_path = only_rollout_path(&scratch);
    let first_events = core_record::replay(&rollout_path).expect("replay fresh rollout");
    let created_at = first_events
        .iter()
        .find_map(|event| match event.kind {
            core_protocol::EventKind::RunStart { created_at, .. } => Some(created_at),
            _ => None,
        })
        .expect("fresh genesis timestamp");
    let environment = first_events
        .iter()
        .find_map(|event| match &event.kind {
            core_protocol::EventKind::ContextInjection {
                instructions: Some(instructions),
                ..
            } => instructions.environment.as_ref(),
            _ => None,
        })
        .expect("durable environment snapshot");
    let genesis_environment = first_events
        .iter()
        .find_map(|event| match &event.kind {
            core_protocol::EventKind::RunStart { environment, .. } => environment.as_ref(),
            _ => None,
        })
        .expect("crash-safe genesis environment snapshot");
    assert_eq!(genesis_environment, environment);
    assert_eq!(environment.trust, core_protocol::Trust::Workspace);
    assert!(environment.text.len() <= core_protocol::MAX_DURABLE_ENVIRONMENT_CONTEXT_BYTES);
    assert!(
        environment
            .text
            .contains(&format!("captured_at_unix_secs: {created_at}"))
    );
    assert_eq!(first_system.matches(&environment.text).count(), 1);

    let run_id = rollout_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .expect("UTF-8 run id")
        .to_owned();
    git_fixture(&scratch.repo(), &["branch", "-M", "facts-changed"]);
    fs::write(
        scratch.repo().join("tracked-private-name"),
        "changed after snapshot\n",
    )
    .unwrap();

    let fake_bin = scratch.root.join("fake-bin");
    fs::create_dir_all(&fake_bin).unwrap();
    let marker = scratch.root.join("git-called-on-resume");
    let fake_git = fake_bin.join("git");
    fs::write(
        &fake_git,
        format!(
            "#!/bin/sh\nprintf called > \"{}\"\nexit 97\n",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_git, fs::Permissions::from_mode(0o700)).unwrap();

    let mut resume_command = core_command(&scratch, "json", 2, &["--resume", &run_id]);
    resume_command.env("PATH", format!("{}:/usr/bin:/bin", fake_bin.display()));
    let resumed = collect_core(resume_command.spawn().expect("spawn resumed Core"));
    assert_eq!(resumed.status.code(), Some(0));
    let resumed_request = requests
        .recv_timeout(SERVER_TIMEOUT)
        .expect("capture resumed provider request");
    server.finish();

    assert!(
        !marker.exists(),
        "resume must not invoke the live Git collector"
    );
    let resumed_system = request_system(&resumed_request);
    assert_eq!(resumed_system, first_system);
    assert!(!resumed_system.contains("facts-changed"));
    let injections = core_record::replay(&rollout_path)
        .unwrap()
        .into_iter()
        .filter(|event| {
            matches!(
                event.kind,
                core_protocol::EventKind::ContextInjection { .. }
            )
        })
        .count();
    assert_eq!(injections, 1, "resume reuses one recorded snapshot");
}

#[test]
fn d13_16_resume_diagnostic_preserves_json_and_stream_json_stdout_contracts() {
    for format in ["json", "stream-json"] {
        let server = MockProvider::spawn(Reply::Success);
        let scratch = Scratch::new(&format!("diagnostic-{format}"), &server.api_root);
        let run_id = format!("run-diagnostic-{format}");
        scratch.seed_redacted_resume(&run_id);

        let output = run_core(&scratch, format, &["--resume", &run_id]);
        server.finish();

        assert_eq!(output.status.code(), Some(0));
        let stdout_records = json_lines(&output.stdout);
        assert_terminal_result(stdout_records.last().expect("terminal result"), 0, "done");
        assert_diagnostics_on_stderr(&output, "Done");
        assert!(
            !std::str::from_utf8(&output.stdout)
                .unwrap()
                .contains("resume_redaction_degraded"),
            "kernel diagnostics must never enter machine stdout"
        );

        let diagnostics = structured_kernel_diagnostics(&output.stderr);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0]["schema_version"], 1);
        assert_eq!(
            diagnostics[0]["diagnostic"],
            json!({
                "code": "resume_redaction_degraded",
                "redacted_tool_results": 1,
                "count_saturated": false
            })
        );
        let stderr = std::str::from_utf8(&output.stderr).unwrap();
        assert!(!stderr.contains("SuperSecretResumeTokenValue"));
        assert!(!stderr.contains("[REDACTED"));
    }
}

#[test]
fn non_success_process_exit_codes_match_terminal_results() {
    let scratch = Scratch::new("budget", "http://127.0.0.1:9/v1");
    let budget = run_core(&scratch, "json", &["--max-usd", "0"]);
    assert_eq!(budget.status.code(), Some(3));
    let budget_lines = json_lines(&budget.stdout);
    assert_eq!(budget_lines.len(), 1);
    assert_machine_failure(&budget_lines[0], 3, "budget_exhausted", "zero", None);
    assert_eq!(budget_lines[0]["reason"], "max_usd");
    assert_diagnostics_on_stderr(&budget, "BudgetExhausted(\"max_usd\")");

    let server = MockProvider::spawn(Reply::InvalidStream);
    let scratch = Scratch::new("harness-error", &server.api_root);
    let harness = run_core(&scratch, "json", &[]);
    server.finish();
    assert_eq!(harness.status.code(), Some(2));
    let harness_lines = json_lines(&harness.stdout);
    assert_eq!(harness_lines.len(), 1);
    assert_machine_failure(
        &harness_lines[0],
        2,
        "harness_error",
        "unknown",
        Some("billing_evidence_missing"),
    );
    assert_eq!(
        harness_lines[0]["error"],
        "provider: provider response was invalid"
    );
    assert_diagnostics_on_stderr(&harness, "HarnessError");
}

#[test]
fn consecutive_real_tool_failures_exit_stuck_with_terminal_result() {
    let server = MockProvider::spawn_script(vec![
        Reply::FailingRead { index: 1 },
        Reply::FailingRead { index: 2 },
        Reply::FailingRead { index: 3 },
    ]);
    let scratch = Scratch::new("stuck", &server.api_root);
    let output = collect_core(spawn_core(&scratch, "json", 4, &[]));
    server.finish();

    assert_eq!(output.status.code(), Some(4));
    let lines = json_lines(&output.stdout);
    assert_eq!(
        lines.len(),
        1,
        "json mode emits exactly one terminal object"
    );
    assert_machine_failure(
        &lines[0],
        4,
        "stuck",
        "unknown",
        Some("no_verified_rate_card"),
    );
    assert_eq!(lines[0]["assistant_text"], "");
    assert_eq!(lines[0]["turns"], 3);
    assert_diagnostics_on_stderr(&output, "Stuck");
}

#[cfg(unix)]
#[test]
fn one_sigint_cancels_the_in_flight_provider_turn_then_exits_interrupted() {
    let (server, request_seen, release_provider) = MockProvider::spawn_paused_success();
    let scratch = Scratch::new("sigint", &server.api_root);
    // Keep cleanup armed across every coordination assertion below; if the provider handshake or
    // signal delivery fails, unwinding still kills and collects the child's entire process group.
    let child = ChildGuard::new(spawn_core(&scratch, "json", 2, &[]));

    request_seen
        .recv_timeout(SERVER_TIMEOUT)
        .expect("real one-shot child starts its provider turn");
    send_sigint(child.child());
    // Let Tokio's installed signal listener set the graceful-interrupt flag while the current
    // provider turn is deliberately still in flight. This remains far inside the outer bound.
    // CONTRACT (decided 2026-07-27, implemented by D1-16 / ac1e0c6): a cooperative interrupt
    // cancels the provider turn MID-STREAM. The in-flight future is dropped and the transport is
    // closed rather than the turn being allowed to finish. The turn is therefore no longer atomic
    // with respect to Ctrl-C, and because the stream never completes, no usage record arrives -
    // so cost reporting degrades to `billing_evidence_missing`, not `no_verified_rate_card`.
    thread::sleep(Duration::from_millis(100));
    release_provider
        .send(())
        .expect("release the current provider turn after SIGINT");

    let output = collect_core(child.into_child());
    server.finish();
    assert_eq!(output.status.code(), Some(130));
    let lines = json_lines(&output.stdout);
    assert_eq!(
        lines.len(),
        1,
        "json mode emits exactly one terminal object"
    );
    assert_machine_failure(
        &lines[0],
        130,
        "interrupted",
        "unknown",
        Some("billing_evidence_missing"),
    );
    // The turn was cancelled before the provider finished streaming, so there is no assistant
    // text and no completed turn to report. Under the previous finish-the-turn contract these
    // were "golden reply" and 1; that difference IS the behaviour change.
    assert_eq!(lines[0]["assistant_text"], "");
    assert_eq!(lines[0]["turns"], 0);
    assert_diagnostics_on_stderr(&output, "Interrupted");
    assert!(
        std::str::from_utf8(&output.stderr)
            .expect("stderr is UTF-8")
            .contains("interrupt: stopping at the next safe point"),
        "the real signal handler acknowledges the graceful interrupt"
    );
}
