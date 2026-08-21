use iteron_protocol::wire::PROTOCOL_VERSION;
use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread;
use std::time::{Duration, Instant};

const PROVIDER_ID: &str = "headless-fixture";
const MODEL_ID: &str = "headless-model";
const KEY_ENV: &str = "ITERON_HEADLESS_TEST_KEY";
const KEY: &str = "bounded-loopback-placeholder";
const CLIENT_PARITY_TASK: &str = include_str!("fixtures/client-parity-task.txt");
const BASE_TIMEOUT: Duration = Duration::from_secs(10);
const BASE_IO_TIMEOUT: Duration = Duration::from_secs(3);
const BASE_QUIET_TIMEOUT: Duration = Duration::from_millis(250);

/// How much longer than native hardware this run is allowed to take.
///
/// The release proof runs the whole x86_64 musl test binary — server child included — under
/// `qemu-x86_64-static` on an aarch64 host, where every syscall and instruction is emulated. The
/// waits below are ceilings, not sleeps, so scaling them costs nothing on a passing native run
/// and stops emulation from being reported as a protocol failure. The scale is parsed strictly
/// and clamped, so a malformed or absurd value falls back to native timing rather than disabling
/// a timeout.
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

fn timeout() -> Duration {
    BASE_TIMEOUT * timeout_scale()
}

fn io_timeout() -> Duration {
    BASE_IO_TIMEOUT * timeout_scale()
}

/// The ceiling on "and then nothing else arrives" assertions. Scaling this one strengthens the
/// assertion under emulation: a late duplicate frame gets proportionally longer to show up.
fn quiet_timeout() -> Duration {
    BASE_QUIET_TIMEOUT * timeout_scale()
}
static NEXT_ID: AtomicU64 = AtomicU64::new(0);

struct CoreProcess {
    child: Child,
    listening: Receiver<Result<SocketAddr, String>>,
    stderr: Option<thread::JoinHandle<Vec<u8>>>,
}

struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(api_root: &str) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("core-headless-serve-{}-{id}", std::process::id()));
        let scratch = Self { root };
        fs::create_dir_all(scratch.repo()).unwrap();
        fs::create_dir_all(scratch.home().join(".iteron")).unwrap();
        fs::create_dir_all(scratch.runs()).unwrap();
        let config = json!({
            "provider": PROVIDER_ID,
            "model": MODEL_ID,
            "effort": "low",
            "max_wall_secs": 10,
            "providers": [{
                "id": PROVIDER_ID,
                "display_name": "Headless fixture",
                "adapter": "openai_chat",
                "error_profile": "custom",
                "api_root": api_root,
                "key_env": KEY_ENV,
                "enabled": true,
                "catalog": false,
                "models": [MODEL_ID],
                "model_capabilities": {
                    // The loopback fixture owns this synthetic model, so its bounded context
                    // window is operator evidence rather than an invented vendor capability.
                    // Declaring it keeps the production composition path intact: the request
                    // output reserve remains Core's conservative unknown-model default.
                    (MODEL_ID): {
                        "context_window_tokens": 1000000,
                        "image_input": true
                    }
                }
            }]
        });
        fs::write(
            scratch.home().join(".iteron/config.json"),
            serde_json::to_vec(&config).unwrap(),
        )
        .unwrap();
        scratch
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
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct PausedProvider {
    api_root: String,
    request_seen: Receiver<()>,
    release: SyncSender<()>,
    thread: Option<thread::JoinHandle<()>>,
}

impl PausedProvider {
    fn spawn() -> Self {
        Self::spawn_with_chunks(1)
    }

    fn spawn_with_chunks(chunks: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (seen_tx, request_seen) = sync_channel(1);
        let (release, release_rx) = sync_channel(1);
        // The replay-fallback fixture must exceed the ring's aggregate byte bound even though
        // production now coalesces adjacent deltas. Single-response parity keeps its exact text;
        // the flood uses bounded 4 KiB chunks for a ~17 MiB logical answer, below the 32 MiB
        // provider-output ceiling and above the 16 MiB replay-byte budget.
        let content = if chunks == 1 {
            "parity reply".to_owned()
        } else {
            "x".repeat(4 * 1024)
        };
        let thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("provider accepts one request");
            stream.set_read_timeout(Some(io_timeout())).unwrap();
            read_http_request(&mut stream);
            seen_tx.send(()).unwrap();
            release_rx
                .recv_timeout(timeout())
                .expect("test releases the provider response");
            write_success(&mut stream, chunks, &content);
        });
        Self {
            api_root: format!("http://{address}/v1"),
            request_seen,
            release,
            thread: Some(thread),
        }
    }

    fn finish(mut self) {
        self.thread
            .take()
            .unwrap()
            .join()
            .expect("provider thread completes");
    }
}

fn read_http_request(stream: &mut TcpStream) {
    let mut request = Vec::new();
    let mut expected = None;
    loop {
        let mut chunk = [0_u8; 8192];
        let read = stream.read(&mut chunk).expect("read provider request");
        assert!(read > 0);
        request.extend_from_slice(&chunk[..read]);
        assert!(request.len() <= 1024 * 1024);
        if expected.is_none()
            && let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n")
        {
            let headers = std::str::from_utf8(&request[..header_end]).unwrap();
            assert_eq!(
                headers.lines().next(),
                Some("POST /v1/chat/completions HTTP/1.1")
            );
            assert!(
                headers
                    .to_ascii_lowercase()
                    .contains("authorization: bearer bounded-loopback-placeholder")
            );
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            expected = Some(header_end + 4 + length);
        }
        if expected.is_some_and(|length| request.len() >= length) {
            return;
        }
    }
}

fn write_success(stream: &mut TcpStream, chunks: usize, content: &str) {
    let mut body = String::new();
    for _ in 0..chunks {
        body.push_str(&format!(
            "data: {{\"id\":\"headless\",\"object\":\"chat.completion.chunk\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\",\"content\":\"{content}\"}},\"finish_reason\":null}}],\"usage\":null}}\n\n"
        ));
    }
    body.push_str(concat!(
        "data: {\"id\":\"headless\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":null}\n\n",
        "data: {\"id\":\"headless\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":2,\"total_tokens\":13,\"prompt_tokens_details\":{\"cached_tokens\":0},\"completion_tokens_details\":{\"reasoning_tokens\":0}}}\n\n",
        "data: [DONE]\n\n",
    ));
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    stream.flush().unwrap();
}

fn fresh_bearer_token() -> String {
    let mut random = [0_u8; 32];
    getrandom::fill(&mut random).expect("generate a fresh per-server bearer token");
    let mut encoded = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in random {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn core_command(scratch: &Scratch) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_iteron"));
    command
        .env_clear()
        .env("HOME", scratch.home())
        .env("USERPROFILE", scratch.home())
        .env(
            "PATH",
            if cfg!(windows) {
                std::env::var_os("PATH").unwrap_or_default()
            } else {
                "/usr/bin:/bin".into()
            },
        )
        .env("LANG", "C.UTF-8")
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env(KEY_ENV, KEY)
        .current_dir(scratch.repo())
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
        .arg("1")
        .arg("serve")
        .arg("--listen")
        .arg("127.0.0.1:0")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if cfg!(windows) {
        for name in ["SystemRoot", "WINDIR"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
    }
    command
}

fn spawn_core_with_token_input(scratch: &Scratch, token_input: &[u8]) -> CoreProcess {
    let mut child = core_command(scratch)
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn real headless iteron process");
    let stderr = child.stderr.take().expect("headless stderr pipe");
    let (listening_tx, listening) = sync_channel(1);
    let stderr = thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut captured = Vec::new();
        loop {
            let mut line = Vec::new();
            let read = reader
                .read_until(b'\n', &mut line)
                .expect("read headless stderr");
            if read == 0 {
                break;
            }
            if let Ok(event) = serde_json::from_slice::<Value>(&line)
                && event.get("component").and_then(Value::as_str) == Some("app_server")
                && event.get("event").and_then(Value::as_str) == Some("listening")
            {
                let address = event
                    .get("listen")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "listening event omitted its string `listen` field".to_owned())
                    .and_then(|listen| {
                        listen.parse::<SocketAddr>().map_err(|error| {
                            format!("invalid listening address {listen:?}: {error}")
                        })
                    });
                let _ = listening_tx.try_send(address);
            }
            captured.extend_from_slice(&line);
        }
        captured
    });
    let mut stdin = child.stdin.take().expect("headless token pipe");
    stdin
        .write_all(token_input)
        .expect("write headless bearer token");
    drop(stdin);
    CoreProcess {
        child,
        listening,
        stderr: Some(stderr),
    }
}

fn spawn_core(scratch: &Scratch) -> (CoreProcess, String, SocketAddr) {
    let token = fresh_bearer_token();
    let mut child = spawn_core_with_token_input(scratch, token.as_bytes());
    let address = wait_for_listening(&mut child);
    (child, token, address)
}

fn wait_for_listening(process: &mut CoreProcess) -> SocketAddr {
    let timeout = timeout();
    let readiness = process.listening.recv_timeout(timeout);
    match readiness {
        Ok(Ok(address)) => address,
        Ok(Err(error)) => {
            terminate_after_readiness_failure(process);
            panic!("invalid app_server listening log while waiting for bound address: {error}");
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            terminate_after_readiness_failure(process);
            panic!(
                "timed out after {timeout:?} waiting for app_server listening log with bound address"
            );
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            terminate_after_readiness_failure(process);
            panic!(
                "headless stderr closed while waiting for app_server listening log with bound address"
            );
        }
    }
}

fn terminate_after_readiness_failure(process: &mut CoreProcess) {
    let _ = process.child.kill();
    let _ = process.child.wait();
    let _ = take_stderr(process);
}

fn connect(address: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect(address).unwrap_or_else(|error| {
        panic!("connect to headless listener at child-reported address {address}: {error}")
    });
    stream.set_read_timeout(Some(io_timeout())).unwrap();
    stream.set_write_timeout(Some(io_timeout())).unwrap();
    stream
}

fn send(stream: &mut TcpStream, value: Value) {
    serde_json::to_writer(&mut *stream, &value).unwrap();
    stream.write_all(b"\n").unwrap();
    stream.flush().unwrap();
}

fn receive(reader: &mut BufReader<TcpStream>) -> Value {
    let mut line = String::new();
    reader.read_line(&mut line).expect("read server frame");
    assert!(!line.is_empty(), "server closed before the expected frame");
    assert!(line.len() <= 1024 * 1024 + 1);
    serde_json::from_str(&line).expect("server frame is JSON")
}

fn hello(token: &str, protocol_version: u32, resume_from: u64) -> Value {
    json!({
        "type": "hello",
        "bearer_token": token,
        "protocol_version": protocol_version,
        "resume_from": resume_from,
    })
}

fn control(request_id: u64, protocol_version: u32, control: Value) -> Value {
    json!({
        "type": "control",
        "protocol_version": protocol_version,
        "request_id": request_id,
        "control": control,
    })
}

fn assert_closed_without_frame(stream: TcpStream) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof
            ) => {}
        Ok(_) => panic!("unauthorized connection received a server frame: {line:?}"),
        Err(error) => panic!("unexpected unauthorized connection error: {error}"),
    }
}

/// The one rollout this run wrote, waited for rather than assumed.
///
/// The server creates it asynchronously, so reading the directory the instant the client returns
/// is a race the test lost only under `--workspace` load: the assertion saw zero files and read as
/// "the run produced no record". Polling to a deadline keeps the assertion exactly as strong —
/// still EXACTLY one, never more — while letting a machine under contention finish the write.
fn only_rollout(runs: &Path) -> PathBuf {
    let timeout = timeout();
    let deadline = Instant::now() + timeout;
    loop {
        let mut paths = fs::read_dir(runs)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
            .collect::<Vec<_>>();
        paths.sort();
        if paths.len() == 1 {
            return paths.pop().unwrap();
        }
        assert!(
            paths.len() <= 1,
            "expected one rollout under {}, found {}: {paths:?}",
            runs.display(),
            paths.len()
        );
        assert!(
            Instant::now() < deadline,
            "no rollout appeared under {} within {timeout:?}",
            runs.display()
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

fn take_stderr(process: &mut CoreProcess) -> Vec<u8> {
    process
        .stderr
        .take()
        .expect("headless stderr reader")
        .join()
        .expect("headless stderr reader completes")
}

fn wait_for_exit(mut process: CoreProcess) -> (std::process::ExitStatus, Vec<u8>) {
    let deadline = Instant::now() + timeout();
    loop {
        if let Some(status) = process.child.try_wait().unwrap() {
            return (status, take_stderr(&mut process));
        }
        if Instant::now() >= deadline {
            let _ = process.child.kill();
            let _ = process.child.wait();
            let _ = take_stderr(&mut process);
            panic!("headless process did not exit after rejecting its startup token");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn stop(mut process: CoreProcess) -> Vec<u8> {
    #[cfg(unix)]
    unsafe {
        let _ = libc::kill(process.child.id() as libc::pid_t, libc::SIGINT);
    }
    #[cfg(not(unix))]
    let _ = process.child.kill();

    let deadline = Instant::now() + timeout();
    loop {
        if process.child.try_wait().unwrap().is_some() {
            return take_stderr(&mut process);
        }
        if Instant::now() >= deadline {
            let _ = process.child.kill();
            let _ = process.child.wait();
            let _ = take_stderr(&mut process);
            panic!("headless process did not stop after interrupt");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn malformed_parent_token_fails_before_the_listener_binds_and_is_not_disclosed() {
    let scratch = Scratch::new("http://127.0.0.1:9/v1");
    let token = fresh_bearer_token();
    let overlong = format!("{token}0");
    let child = spawn_core_with_token_input(&scratch, overlong.as_bytes());
    let (status, stderr) = wait_for_exit(child);
    assert!(!status.success());
    let stderr = String::from_utf8(stderr).unwrap();
    assert!(stderr.contains("invalid headless bearer token on stdin"));
    assert!(!stderr.contains("\"event\":\"listening\""));
    assert!(!stderr.contains(&token));
    assert!(!stderr.contains(&overlong));
}

#[test]
fn authentication_precedes_version_replay_and_submission_behavior_without_token_leaks() {
    let scratch = Scratch::new("http://127.0.0.1:9/v1");
    let (child, token, address) = spawn_core(&scratch);

    let mut wrong = token.as_bytes().to_vec();
    wrong[0] = if wrong[0] == b'0' { b'1' } else { b'0' };
    let wrong = String::from_utf8(wrong).unwrap();

    let mut unauthorized = connect(address);
    let rollout = only_rollout(&scratch.runs());
    let before = fs::read(&rollout).unwrap();
    send(&mut unauthorized, hello(&wrong, 999, 0));
    assert_closed_without_frame(unauthorized);

    let mut missing = connect(address);
    send(
        &mut missing,
        json!({"type":"hello","protocol_version":PROTOCOL_VERSION,"resume_from":0}),
    );
    assert_closed_without_frame(missing);

    let mut submit_first = connect(address);
    send(
        &mut submit_first,
        json!({
            "type":"submit",
            "protocol_version":PROTOCOL_VERSION,
            "op":{"op":"user_input","text":"must not be admitted"}
        }),
    );
    assert_closed_without_frame(submit_first);
    assert_eq!(fs::read(&rollout).unwrap(), before);

    let mut authorized = connect(address);
    send(&mut authorized, hello(&token, PROTOCOL_VERSION, 0));
    let mut reader = BufReader::new(authorized);
    assert_eq!(receive(&mut reader)["type"], "hello");
    assert_eq!(fs::read(&rollout).unwrap(), before);

    let stderr = String::from_utf8(stop(child)).unwrap();
    assert!(!stderr.contains(&token));
    assert!(!stderr.contains(&wrong));
}

#[test]
fn connection_limit_drops_rejects_without_tasks_and_completed_connections_are_reaped() {
    let scratch = Scratch::new("http://127.0.0.1:9/v1");
    let (child, token, address) = spawn_core(&scratch);

    let mut blockers = Vec::new();
    for _ in 0..32 {
        let mut connection = connect(address);
        send(&mut connection, hello(&token, PROTOCOL_VERSION, 0));
        let mut reader = BufReader::new(connection.try_clone().unwrap());
        assert_eq!(receive(&mut reader)["type"], "hello");
        blockers.push(connection);
    }

    let rejected = connect(address);
    assert_closed_without_frame(rejected);
    drop(blockers);
    thread::sleep(Duration::from_millis(100));

    // Repeatedly complete more than one full permit set. A JoinSet that only accumulated finished
    // entries would grow here even though active connection concurrency remains one.
    for _ in 0..96 {
        let mut connection = connect(address);
        send(&mut connection, hello(&token, PROTOCOL_VERSION, 0));
        let mut reader = BufReader::new(connection);
        assert_eq!(receive(&mut reader)["type"], "hello");
    }

    let stderr = String::from_utf8(stop(child)).unwrap();
    assert!(!stderr.contains(&token));
}

#[test]
fn background_job_inventory_and_attach_control_survive_client_restart() {
    let scratch = Scratch::new("http://127.0.0.1:9/v1");
    let (child, token, address) = spawn_core(&scratch);

    let mut first = connect(address);
    send(&mut first, hello(&token, PROTOCOL_VERSION, 0));
    let mut first_reader = BufReader::new(first.try_clone().unwrap());
    assert_eq!(receive(&mut first_reader)["type"], "hello");
    send(
        &mut first,
        control(70, PROTOCOL_VERSION, json!({"type":"jobs_list"})),
    );
    let inventory = receive(&mut first_reader);
    assert_eq!(inventory["type"], "control_reply");
    assert_eq!(inventory["request_id"], 70);
    assert_eq!(inventory["reply"]["type"], "jobs");
    assert_eq!(inventory["reply"]["value"], json!([]));
    drop(first_reader);
    drop(first);

    // A new presentation client reaches the same resident supervisor. An unknown job is a typed
    // refusal, not a disconnected control channel or an invented stale process record.
    let mut restarted = connect(address);
    send(&mut restarted, hello(&token, PROTOCOL_VERSION, 0));
    let mut restarted_reader = BufReader::new(restarted.try_clone().unwrap());
    assert_eq!(receive(&mut restarted_reader)["type"], "hello");
    send(
        &mut restarted,
        control(
            71,
            PROTOCOL_VERSION,
            json!({
                "type":"jobs_attach",
                "job_id":"job-0123456789abcdef-00000001",
                "stdout_cursor":0,
                "stderr_cursor":0
            }),
        ),
    );
    let refused = receive(&mut restarted_reader);
    assert_eq!(refused["type"], "control_reply");
    assert_eq!(refused["request_id"], 71);
    assert_eq!(refused["reply"]["type"], "refused");
    assert!(
        refused["reply"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("job_id")),
        "unexpected typed refusal: {refused}"
    );

    send(
        &mut restarted,
        control(72, PROTOCOL_VERSION, json!({"type":"jobs_list"})),
    );
    let reattached_inventory = receive(&mut restarted_reader);
    assert_eq!(reattached_inventory["request_id"], 72);
    assert_eq!(reattached_inventory["reply"]["value"], json!([]));

    let stderr = String::from_utf8(stop(child)).unwrap();
    assert!(!stderr.contains(&token));
}

#[test]
fn no_tty_skew_reconnect_and_current_result_share_one_headless_server() {
    let provider = PausedProvider::spawn();
    let scratch = Scratch::new(&provider.api_root);
    let (child, token, address) = spawn_core(&scratch);

    // A skewed hello is refused before any SQ submission or Rollout mutation.
    let mut skewed = connect(address);
    let rollout = only_rollout(&scratch.runs());
    let before = fs::read(&rollout).unwrap();
    send(&mut skewed, hello(&token, PROTOCOL_VERSION + 1, 0));
    let mut skewed_reader = BufReader::new(skewed);
    let refusal = receive(&mut skewed_reader);
    assert_eq!(refusal["type"], "error");
    assert_eq!(refusal["code"], "protocol_version_mismatch");
    assert_eq!(fs::read(&rollout).unwrap(), before);

    // Start through the real SQ, disconnect mid-turn, then resume from the last live cursor.
    let mut first = connect(address);
    send(&mut first, hello(&token, PROTOCOL_VERSION, 0));
    let mut first_reader = BufReader::new(first.try_clone().unwrap());
    assert_eq!(receive(&mut first_reader)["type"], "hello");
    send(
        &mut first,
        json!({
            "type":"submit",
            "protocol_version":PROTOCOL_VERSION,
            "op":{
                "op":"user_input_v2",
                "segments":[
                    {"type":"text","text":CLIENT_PARITY_TASK.trim()},
                    {
                        "type":"image",
                        "image":{
                            "media_type":"image/png",
                            "data":"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
                        }
                    }
                ]
            }
        }),
    );
    let first_event = receive(&mut first_reader);
    assert_eq!(first_event["type"], "event", "{first_event}");
    let mut last_seq = first_event["seq"].as_u64().unwrap();
    provider
        .request_seen
        .recv_timeout(timeout())
        .expect("provider turn reached the in-flight point");
    drop(first_reader);
    drop(first);
    provider.release.send(()).unwrap();

    let mut resumed = connect(address);
    send(&mut resumed, hello(&token, PROTOCOL_VERSION, last_seq));
    let mut resumed_reader = BufReader::new(resumed);
    let hello = receive(&mut resumed_reader);
    assert_eq!(hello["type"], "hello");
    assert_eq!(hello["replay_source"], "ring");

    let mut results = Vec::new();
    loop {
        let frame = receive(&mut resumed_reader);
        if let Some(seq) = frame.get("seq").and_then(Value::as_u64) {
            assert_eq!(seq, last_seq + 1, "live cursor has a gap or duplicate");
            last_seq = seq;
        }
        if frame["type"] == "result" {
            results.push(frame["result"].clone());
            break;
        }
    }
    assert_eq!(results.len(), 1);
    let result = &results[0];
    assert_eq!(result["schema_version"], 6);
    assert_eq!(result["type"], "result");
    assert_eq!(result["assistant_text"], "parity reply");
    assert_eq!(result["outcome"], "done");
    assert_eq!(result["exit_code"], 0);

    resumed_reader
        .get_mut()
        .set_read_timeout(Some(quiet_timeout()))
        .unwrap();
    let mut unexpected = String::new();
    match resumed_reader.read_line(&mut unexpected) {
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) => {}
        Ok(0) => {}
        Ok(_) => panic!("a duplicate post-result frame was delivered: {unexpected}"),
        Err(error) => panic!("unexpected post-result read failure: {error}"),
    }

    let stderr = stop(child);
    let stderr = String::from_utf8(stderr).unwrap();
    assert!(stderr.contains("\"event\":\"listening\""));
    assert!(stderr.contains("\"transport\":\"loopback_tcp_jsonl\""));
    assert!(!stderr.contains(&token));
    provider.finish();
}

#[test]
fn a_cursor_older_than_the_live_ring_receives_rollout_fallback() {
    // More deltas than the production ring holds force the real fallback path without a
    // test-only capacity override.
    let provider = PausedProvider::spawn_with_chunks(4200);
    let scratch = Scratch::new(&provider.api_root);
    let (child, token, address) = spawn_core(&scratch);

    let mut client = connect(address);
    send(&mut client, hello(&token, PROTOCOL_VERSION, 0));
    let mut reader = BufReader::new(client.try_clone().unwrap());
    assert_eq!(receive(&mut reader)["type"], "hello");
    send(
        &mut client,
        json!({
            "type":"submit",
            "protocol_version":PROTOCOL_VERSION,
            "op":{"op":"user_input","text":"produce a bounded replay-ring flood"}
        }),
    );
    provider
        .request_seen
        .recv_timeout(timeout())
        .expect("provider received the flood turn");
    drop(reader);
    drop(client);
    provider.release.send(()).unwrap();
    provider.finish();

    let deadline = Instant::now() + timeout();
    let mut fallback_reader = loop {
        let mut candidate = connect(address);
        send(&mut candidate, hello(&token, PROTOCOL_VERSION, 0));
        let mut candidate = BufReader::new(candidate);
        let hello = receive(&mut candidate);
        if hello["replay_source"] == "rollout" {
            break candidate;
        }
        assert!(
            Instant::now() < deadline,
            "the live cursor never advanced beyond the bounded replay ring"
        );
        thread::sleep(Duration::from_millis(20));
    };
    let durable = receive(&mut fallback_reader);
    assert_eq!(durable["type"], "rollout");
    assert_eq!(durable["protocol_version"], PROTOCOL_VERSION);
    assert!(durable["rollout_seq"].as_u64().is_some());
    assert!(durable["event"].is_object());

    let stderr = stop(child);
    let stderr = String::from_utf8(stderr).unwrap();
    assert!(stderr.contains("\"event\":\"listening\""));
    assert!(!stderr.contains(&token));
}
