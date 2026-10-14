//! Public V2 retries cross a real TCP service and reopened durable admission authority.
use super::*;
use iteron_protocol::product_contract::PRODUCT_CONTRACT_VERSION;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::{Arc, Barrier};
use std::time::{SystemTime, UNIX_EPOCH};

/// Construct the specified client identity independently of the server's parser/digest code.
pub(super) fn request_key(thread: &str, text: &str) -> String {
    let mut uuid = [0_u8; 16];
    getrandom::fill(&mut uuid).unwrap();
    let millis = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    uuid[..6].copy_from_slice(&millis.to_be_bytes()[2..]);
    uuid[6] = (uuid[6] & 0x0f) | 0x70;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    let mut digest = Sha256::new();
    digest.update(uuid);
    digest.update((thread.len() as u64).to_be_bytes());
    digest.update(thread.as_bytes());
    digest.update((text.len() as u64).to_be_bytes());
    digest.update(text.as_bytes());
    let uuid = hex::encode(uuid);
    format!(
        "{}-{}-{}-{}-{}:{:x}",
        &uuid[..8],
        &uuid[8..12],
        &uuid[12..16],
        &uuid[16..20],
        &uuid[20..],
        digest.finalize()
    )
}

struct RetainedCore(Option<CoreProcess>);
impl RetainedCore {
    fn crash(&mut self) {
        let mut process = self.0.take().unwrap();
        process.child.kill().unwrap();
        process.child.wait().unwrap();
        let _ = take_stderr(&mut process);
    }
}
impl Drop for RetainedCore {
    fn drop(&mut self) {
        if let Some(mut process) = self.0.take() {
            let _ = process.child.kill();
            let _ = process.child.wait();
            let _ = take_stderr(&mut process);
        }
    }
}

/// Keep accepting after the first response so a duplicate physical request cannot hide behind
/// a closed fixture listener. No provider credentials or external endpoint are involved.
struct CountingProvider {
    api_root: String,
    seen: Receiver<()>,
    release: SyncSender<()>,
    count: Arc<AtomicUsize>,
    stopping: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl CountingProvider {
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let api_root = format!("http://{}/v1", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let (seen_tx, seen) = sync_channel(1);
        let (release, release_rx) = sync_channel(1);
        let count = Arc::new(AtomicUsize::new(0));
        let stopping = Arc::new(AtomicBool::new(false));
        let observed = count.clone();
        let stop = stopping.clone();
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + timeout() * 6;
            while !stop.load(Ordering::SeqCst) {
                assert!(
                    Instant::now() < deadline,
                    "provider fixture exceeded its deadline"
                );
                let (mut socket, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("bounded loopback accept failed: {error}"),
                };
                socket.set_nonblocking(false).unwrap();
                socket.set_read_timeout(Some(io_timeout())).unwrap();
                socket.set_write_timeout(Some(io_timeout())).unwrap();
                read_http_request(&mut socket);
                let previous = observed.fetch_add(1, Ordering::SeqCst);
                assert!(previous < 16, "unexpected repeated physical requests");
                if previous == 0 {
                    seen_tx.send(()).unwrap();
                    release_rx.recv_timeout(timeout()).unwrap();
                }
                write_success(&mut socket, 1, "one durable product turn");
            }
        });
        Self {
            api_root,
            seen,
            release,
            count,
            stopping,
            worker: Some(worker),
        }
    }
    fn finish(mut self) -> usize {
        self.stopping.store(true, Ordering::SeqCst);
        self.worker.take().unwrap().join().unwrap();
        self.count.load(Ordering::SeqCst)
    }
}
impl Drop for CountingProvider {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
        let _ = self.release.try_send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn attach(address: SocketAddr, token: &str) -> (TcpStream, BufReader<TcpStream>, String) {
    let mut socket = connect(address);
    let mut greeting = hello(token, PROTOCOL_VERSION, 0);
    greeting["product_contract_version"] = json!(PRODUCT_CONTRACT_VERSION);
    greeting["live_only"] = json!(true);
    send(&mut socket, greeting);
    let mut reader = BufReader::new(socket.try_clone().unwrap());
    let greeted = receive(&mut reader);
    assert_eq!(greeted["type"], "hello");
    assert_eq!(
        greeted["product_contract_version"],
        PRODUCT_CONTRACT_VERSION
    );
    let thread = greeted["session_id"].as_str().unwrap().to_owned();
    (socket, reader, thread)
}
fn start(id: u64, key: &str, thread: &str, text: &str) -> Value {
    control(
        id,
        PROTOCOL_VERSION,
        json!({"type":"product_v1","command":{
            "type":"turn_start","request_key":key,"thread_id":thread,"text":text
        }}),
    )
}
fn reply(reader: &mut BufReader<TcpStream>, id: u64) -> Value {
    let deadline = Instant::now() + timeout();
    for _ in 0..4096 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "missing bounded TurnStart reply");
        reader.get_mut().set_read_timeout(Some(remaining)).unwrap();
        let frame = receive(reader);
        assert_ne!(frame["type"], "error", "{frame}");
        if frame["type"] == "control_reply" && frame["request_id"] == id {
            return frame["reply"].clone();
        }
    }
    panic!("TurnStart reply exceeded the finite frame budget");
}
fn identity(receipt: &Value, key: &str, thread: &str) -> Value {
    assert_eq!(receipt["type"], "turn_start_receipt_v2", "{receipt}");
    assert_eq!(receipt["contract_version"], 2);
    assert_eq!(receipt["request_key"], key);
    assert_eq!(receipt["thread_id"], thread);
    assert_eq!(receipt["window_closed"], false);
    for name in ["run_id", "submission_id", "turn_id"] {
        assert!(
            !receipt[name].is_null(),
            "proven admission lacks {name}: {receipt}"
        );
    }
    json!([
        receipt["run_id"],
        receipt["submission_id"],
        receipt["turn_id"]
    ])
}

#[cfg(unix)]
fn assert_prompt_hook_ran_once(scratch: &Scratch) {
    assert_eq!(
        fs::read(scratch.repo().join("turn-start-hook-marker.txt"))
            .expect("the admitted prompt must execute its configured hook"),
        b"one admitted prompt\n",
        "a retry, refusal or restart must not repeat the prompt hook's file effect"
    );
}

#[test]
fn turn_start_v2_retries_share_one_physical_request_and_survive_service_restart() {
    let provider = CountingProvider::spawn();
    let scratch = Scratch::new(&provider.api_root);
    #[cfg(unix)]
    {
        assert!(!scratch.repo().join("turn-start-hook-marker.txt").exists());
        // FileConfig.hooks is a map of command lists in the isolated trusted user config.
        // The process and its hook inherit this fixture's repository as their working directory;
        // no request text, dynamic path or user environment is interpolated into the shell.
        scratch.configure_hooks(json!({
            "UserPromptSubmit": [
                "cat > /dev/null && printf '%s\\n' 'one admitted prompt' >> './turn-start-hook-marker.txt'"
            ]
        }));
    }
    let (process, token, address) = spawn_core(&scratch);
    let mut server = RetainedCore(Some(process));
    let mut old_client = connect(address);
    let mut old_hello = hello(&token, PROTOCOL_VERSION, 0);
    old_hello["product_contract_version"] = json!(1);
    send(&mut old_client, old_hello);
    let mut old_reader = BufReader::new(old_client.try_clone().unwrap());
    let refused = receive(&mut old_reader);
    assert_eq!(refused["type"], "error");
    assert_eq!(refused["code"], "product_contract_version_mismatch");
    drop(old_reader);
    drop(old_client);
    let (mut first, mut first_reader, thread_id) = attach(address, &token);
    let (mut second, mut second_reader, second_thread) = attach(address, &token);
    assert_eq!(thread_id, second_thread);
    let text = "  同一请求\nKeep the original UTF-8 bytes.\n";
    let key = request_key(&thread_id, text);
    send(&mut first, start(10, "invalid", &thread_id, text));
    let invalid = reply(&mut first_reader, 10);
    assert_eq!(invalid["type"], "turn_start_refused_v2");
    assert_eq!(invalid["reason_code"], "invalid_request_key");
    assert!(invalid["request_key"].is_null());
    #[cfg(unix)]
    assert!(!scratch.repo().join("turn-start-hook-marker.txt").exists());
    let barrier = Barrier::new(2);
    thread::scope(|scope| {
        scope.spawn(|| {
            barrier.wait();
            send(&mut first, start(1, &key, &thread_id, text));
        });
        scope.spawn(|| {
            barrier.wait();
            send(&mut second, start(2, &key, &thread_id, text));
        });
    });
    let a = reply(&mut first_reader, 1);
    let b = reply(&mut second_reader, 2);
    for receipt in [&a, &b] {
        assert_eq!(receipt["type"], "turn_start_receipt_v2", "{receipt}");
        assert!(matches!(
            receipt["state"].as_str(),
            Some("pending" | "admitted" | "running")
        ));
        if receipt["state"] == "pending" {
            assert!(receipt["submission_id"].is_null());
            assert!(receipt["run_id"].is_null());
            assert!(receipt["turn_id"].is_null());
        }
    }
    provider.seen.recv_timeout(timeout()).unwrap();
    #[cfg(unix)]
    assert_prompt_hook_ran_once(&scratch);
    send(&mut first, start(3, &key, &thread_id, text));
    let running = reply(&mut first_reader, 3);
    let admitted = identity(&running, &key, &thread_id);
    assert!(matches!(
        running["state"].as_str(),
        Some("admitted" | "running")
    ));
    send(
        &mut second,
        start(11, &request_key(&thread_id, text), &thread_id, text),
    );
    let active = reply(&mut second_reader, 11);
    assert_eq!(active["type"], "turn_start_refused_v2");
    assert_eq!(active["reason_code"], "turn_active");
    for receipt in [&a, &b] {
        if receipt["state"] != "pending" {
            assert_eq!(identity(receipt, &key, &thread_id), admitted);
        }
    }
    for (id, target, body) in [
        (4, thread_id.as_str(), text.trim()),
        (5, "another-thread", text),
    ] {
        send(&mut second, start(id, &key, target, body));
        let refused = reply(&mut second_reader, id);
        assert_eq!(refused["type"], "turn_start_refused_v2");
        assert_eq!(refused["reason_code"], "request_conflict");
        assert_eq!(refused["definitely_unregistered"], false);
        assert!(refused.get("turn_id").is_none());
    }
    #[cfg(unix)]
    assert_prompt_hook_ran_once(&scratch);
    provider.release.send(()).unwrap();
    let result = receive_result_within_timeout(&mut first_reader);
    assert_eq!(result["result"]["outcome"], "done");
    send(&mut first, start(6, &key, &thread_id, text));
    let completed = reply(&mut first_reader, 6);
    assert_eq!(identity(&completed, &key, &thread_id), admitted);
    assert_eq!(completed["state"], "completed");
    #[cfg(unix)]
    assert_prompt_hook_ran_once(&scratch);
    drop(first_reader);
    drop(second_reader);
    drop(first);
    drop(second);
    // A new OS process must reopen the receipt, not reuse the old resident projection.
    server.crash();
    let run = admitted[0].as_str().unwrap();
    let command = core_command_with_launch(&scratch, &scratch.repo(), 1, &["--resume", run]);
    let new_token = fresh_bearer_token();
    let mut process = spawn_core_command_with_token_input(command, new_token.as_bytes());
    let address = wait_for_listening(&mut process);
    server.0 = Some(process);
    let (mut reopened, mut reader, _) = attach(address, &new_token);
    send(&mut reopened, start(7, &key, &thread_id, text));
    let retained = reply(&mut reader, 7);
    assert_eq!(identity(&retained, &key, &thread_id), admitted);
    assert_eq!(retained["state"], "completed");
    drop(reader);
    drop(reopened);
    stop(server.0.take().unwrap());
    #[cfg(unix)]
    assert_prompt_hook_ran_once(&scratch);
    assert_eq!(
        provider.finish(),
        1,
        "retries must not perform a second physical POST"
    );
    // The admitted run owns this primary WAL; configured hooks have a separate .hooks.jsonl.
    let events = iteron_record::replay(&scratch.runs().join(format!("{run}.jsonl"))).unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                &event.kind,
                iteron_protocol::EventKind::EffectIntent {
                    provider_route_attempt: Some(_),
                    ..
                }
            ))
            .count(),
        1,
        "retries must not admit another billed effect"
    );
}
