use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread;
use std::time::{Duration, Instant};

const PROVIDER_ID: &str = "headless-fixture";
const MODEL_ID: &str = "headless-model";
const KEY_ENV: &str = "CORE_HEADLESS_TEST_KEY";
const KEY: &str = "bounded-loopback-placeholder";
const CLIENT_PARITY_TASK: &str = include_str!("fixtures/client-parity-task.txt");
const TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(3);
static NEXT_ID: AtomicU64 = AtomicU64::new(0);

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
        fs::create_dir_all(scratch.home().join(".core")).unwrap();
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
                "models": [MODEL_ID]
            }]
        });
        fs::write(
            scratch.home().join(".core/config.json"),
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
        let thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("provider accepts one request");
            stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
            read_http_request(&mut stream);
            seen_tx.send(()).unwrap();
            release_rx
                .recv_timeout(TIMEOUT)
                .expect("test releases the provider response");
            write_success(&mut stream, chunks);
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

fn write_success(stream: &mut TcpStream, chunks: usize) {
    let mut body = String::new();
    let content = if chunks == 1 { "parity reply" } else { "x" };
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

fn reserve_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
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

fn core_command(scratch: &Scratch, address: SocketAddr) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_core"));
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
        .arg(address.to_string())
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

fn spawn_core_with_token_input(
    scratch: &Scratch,
    address: SocketAddr,
    token_input: &[u8],
) -> Child {
    let mut child = core_command(scratch, address)
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn real headless core process");
    let mut stdin = child.stdin.take().expect("headless token pipe");
    stdin
        .write_all(token_input)
        .expect("write headless bearer token");
    drop(stdin);
    child
}

fn spawn_core(scratch: &Scratch, address: SocketAddr) -> (Child, String) {
    let token = fresh_bearer_token();
    let child = spawn_core_with_token_input(scratch, address, token.as_bytes());
    (child, token)
}

fn connect(address: SocketAddr) -> TcpStream {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        match TcpStream::connect(address) {
            Ok(stream) => {
                stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
                stream.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
                return stream;
            }
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Err(error) => panic!("headless listener did not start: {error}"),
        }
    }
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

fn only_rollout(runs: &Path) -> PathBuf {
    let mut paths = fs::read_dir(runs)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
        .collect::<Vec<_>>();
    paths.sort();
    assert_eq!(paths.len(), 1);
    paths.pop().unwrap()
}

fn wait_for_exit(mut child: Child) -> (std::process::ExitStatus, Vec<u8>) {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            let mut stderr = Vec::new();
            child
                .stderr
                .take()
                .unwrap()
                .read_to_end(&mut stderr)
                .unwrap();
            return (status, stderr);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("headless process did not exit after rejecting its startup token");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn stop(mut child: Child) -> Vec<u8> {
    #[cfg(unix)]
    unsafe {
        let _ = libc::kill(child.id() as libc::pid_t, libc::SIGINT);
    }
    #[cfg(not(unix))]
    let _ = child.kill();

    let deadline = Instant::now() + TIMEOUT;
    loop {
        if child.try_wait().unwrap().is_some() {
            let mut stderr = Vec::new();
            child
                .stderr
                .take()
                .unwrap()
                .read_to_end(&mut stderr)
                .unwrap();
            return stderr;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("headless process did not stop after interrupt");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn malformed_parent_token_fails_before_the_listener_binds_and_is_not_disclosed() {
    let scratch = Scratch::new("http://127.0.0.1:9/v1");
    let address = reserve_address();
    let token = fresh_bearer_token();
    let overlong = format!("{token}0");
    let child = spawn_core_with_token_input(&scratch, address, overlong.as_bytes());
    let (status, stderr) = wait_for_exit(child);
    assert!(!status.success());
    let _listener = TcpListener::bind(address).expect("invalid token must fail before bind");
    let stderr = String::from_utf8(stderr).unwrap();
    assert!(stderr.contains("invalid headless bearer token on stdin"));
    assert!(!stderr.contains(&token));
    assert!(!stderr.contains(&overlong));
}

#[test]
fn authentication_precedes_version_replay_and_submission_behavior_without_token_leaks() {
    let scratch = Scratch::new("http://127.0.0.1:9/v1");
    let address = reserve_address();
    let (child, token) = spawn_core(&scratch, address);

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
        json!({"type":"hello","protocol_version":1,"resume_from":0}),
    );
    assert_closed_without_frame(missing);

    let mut submit_first = connect(address);
    send(
        &mut submit_first,
        json!({
            "type":"submit",
            "protocol_version":1,
            "op":{"op":"user_input","text":"must not be admitted"}
        }),
    );
    assert_closed_without_frame(submit_first);
    assert_eq!(fs::read(&rollout).unwrap(), before);

    let mut authorized = connect(address);
    send(&mut authorized, hello(&token, 1, 0));
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
    let address = reserve_address();
    let (child, token) = spawn_core(&scratch, address);

    let mut blockers = Vec::new();
    for _ in 0..32 {
        let mut connection = connect(address);
        send(&mut connection, hello(&token, 1, 0));
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
        send(&mut connection, hello(&token, 1, 0));
        let mut reader = BufReader::new(connection);
        assert_eq!(receive(&mut reader)["type"], "hello");
    }

    let stderr = String::from_utf8(stop(child)).unwrap();
    assert!(!stderr.contains(&token));
}

#[test]
fn no_tty_skew_reconnect_and_result_v5_share_one_headless_server() {
    let provider = PausedProvider::spawn();
    let scratch = Scratch::new(&provider.api_root);
    let address = reserve_address();
    let (child, token) = spawn_core(&scratch, address);

    // A skewed hello is refused before any SQ submission or Rollout mutation.
    let mut skewed = connect(address);
    let rollout = only_rollout(&scratch.runs());
    let before = fs::read(&rollout).unwrap();
    send(&mut skewed, hello(&token, 2, 0));
    let mut skewed_reader = BufReader::new(skewed);
    let refusal = receive(&mut skewed_reader);
    assert_eq!(refusal["type"], "error");
    assert_eq!(refusal["code"], "protocol_version_mismatch");
    assert_eq!(fs::read(&rollout).unwrap(), before);

    // Start through the real SQ, disconnect mid-turn, then resume from the last live cursor.
    let mut first = connect(address);
    send(&mut first, hello(&token, 1, 0));
    let mut first_reader = BufReader::new(first.try_clone().unwrap());
    assert_eq!(receive(&mut first_reader)["type"], "hello");
    send(
        &mut first,
        json!({
            "type":"submit",
            "protocol_version":1,
            "op":{
                "op":"user_input_v2",
                "segments":[
                    {"type":"text","text":CLIENT_PARITY_TASK.trim()},
                    {
                        "type":"image",
                        "image":{"media_type":"image/png","data":"iVBORw0KGgo="}
                    }
                ]
            }
        }),
    );
    let first_event = receive(&mut first_reader);
    assert_eq!(first_event["type"], "event");
    let mut last_seq = first_event["seq"].as_u64().unwrap();
    provider
        .request_seen
        .recv_timeout(TIMEOUT)
        .expect("provider turn reached the in-flight point");
    drop(first_reader);
    drop(first);
    provider.release.send(()).unwrap();

    let mut resumed = connect(address);
    send(&mut resumed, hello(&token, 1, last_seq));
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
    assert_eq!(result["schema_version"], 5);
    assert_eq!(result["type"], "result");
    assert_eq!(result["assistant_text"], "parity reply");
    assert_eq!(result["outcome"], "done");
    assert_eq!(result["exit_code"], 0);

    resumed_reader
        .get_mut()
        .set_read_timeout(Some(Duration::from_millis(250)))
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
    let address = reserve_address();
    let (child, token) = spawn_core(&scratch, address);

    let mut client = connect(address);
    send(&mut client, hello(&token, 1, 0));
    let mut reader = BufReader::new(client.try_clone().unwrap());
    assert_eq!(receive(&mut reader)["type"], "hello");
    send(
        &mut client,
        json!({
            "type":"submit",
            "protocol_version":1,
            "op":{"op":"user_input","text":"produce a bounded replay-ring flood"}
        }),
    );
    provider
        .request_seen
        .recv_timeout(TIMEOUT)
        .expect("provider received the flood turn");
    drop(reader);
    drop(client);
    provider.release.send(()).unwrap();
    provider.finish();

    let deadline = Instant::now() + TIMEOUT;
    let mut fallback_reader = loop {
        let mut candidate = connect(address);
        send(&mut candidate, hello(&token, 1, 0));
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
    assert_eq!(durable["protocol_version"], 1);
    assert!(durable["rollout_seq"].as_u64().is_some());
    assert!(durable["event"].is_object());

    let stderr = stop(child);
    let stderr = String::from_utf8(stderr).unwrap();
    assert!(stderr.contains("\"event\":\"listening\""));
    assert!(!stderr.contains(&token));
}
