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

fn spawn_core(scratch: &Scratch, address: SocketAddr) -> Child {
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
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if cfg!(windows) {
        for name in ["SystemRoot", "WINDIR"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
    }
    command.spawn().expect("spawn real headless core process")
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
fn no_tty_skew_reconnect_and_result_v5_share_one_headless_server() {
    let provider = PausedProvider::spawn();
    let scratch = Scratch::new(&provider.api_root);
    let address = reserve_address();
    let child = spawn_core(&scratch, address);

    // A skewed hello is refused before any SQ submission or Rollout mutation.
    let mut skewed = connect(address);
    let rollout = only_rollout(&scratch.runs());
    let before = fs::read(&rollout).unwrap();
    send(
        &mut skewed,
        json!({"type":"hello","protocol_version":2,"resume_from":0}),
    );
    let mut skewed_reader = BufReader::new(skewed);
    let refusal = receive(&mut skewed_reader);
    assert_eq!(refusal["type"], "error");
    assert_eq!(refusal["code"], "protocol_version_mismatch");
    assert_eq!(fs::read(&rollout).unwrap(), before);

    // Start through the real SQ, disconnect mid-turn, then resume from the last live cursor.
    let mut first = connect(address);
    send(
        &mut first,
        json!({"type":"hello","protocol_version":1,"resume_from":0}),
    );
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
    send(
        &mut resumed,
        json!({"type":"hello","protocol_version":1,"resume_from":last_seq}),
    );
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

    let stderr = stop(child);
    let stderr = String::from_utf8(stderr).unwrap();
    assert!(stderr.contains("\"event\":\"listening\""));
    assert!(stderr.contains("\"transport\":\"loopback_tcp_jsonl\""));
    provider.finish();
}

#[test]
fn a_cursor_older_than_the_live_ring_receives_rollout_fallback() {
    // More deltas than the production ring holds force the real fallback path without a
    // test-only capacity override.
    let provider = PausedProvider::spawn_with_chunks(4200);
    let scratch = Scratch::new(&provider.api_root);
    let address = reserve_address();
    let child = spawn_core(&scratch, address);

    let mut client = connect(address);
    send(
        &mut client,
        json!({"type":"hello","protocol_version":1,"resume_from":0}),
    );
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
        send(
            &mut candidate,
            json!({"type":"hello","protocol_version":1,"resume_from":0}),
        );
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
    assert!(
        String::from_utf8(stderr)
            .unwrap()
            .contains("\"event\":\"listening\"")
    );
}
