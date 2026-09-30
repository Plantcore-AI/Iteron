//! Real native tool producer -> retained public bytes -> restarted TCP download -> CLI erasure.

use super::*;
use base64::Engine;
use iteron_protocol::{EventKind, RunId};
use sha2::{Digest, Sha256};

#[path = "maintenance_journey.rs"]
mod maintenance_journey;
#[path = "turn_publication_journey.rs"]
mod turn_publication_journey;

struct OwnedCore(Option<CoreProcess>);

impl OwnedCore {
    fn stop(mut self) {
        stop(self.0.take().expect("owned core still available"));
    }
}

impl Drop for OwnedCore {
    fn drop(&mut self) {
        if let Some(mut process) = self.0.take() {
            let _ = process.child.kill();
            let _ = process.child.wait();
            if let Some(stderr) = process.stderr.take() {
                let _ = stderr.join();
            }
        }
    }
}

fn accept_before_deadline(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + timeout();
    loop {
        match listener.accept() {
            Ok((stream, _)) => return stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "actual provider request timed out"
                );
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("accept actual provider request: {error}"),
        }
    }
}

struct ToolProvider {
    api_root: String,
    completed: Receiver<()>,
    thread: Option<thread::JoinHandle<()>>,
}

impl ToolProvider {
    fn spawn() -> Self {
        Self::spawn_for_calls(
            vec![json!({
                "index":0,"id":"artifact-large-read","type":"function",
                "function":{"name":"read_file","arguments":json!({"path":"large-output.txt"}).to_string()}
            })],
            true,
        )
    }

    fn spawn_for_calls(calls: Vec<Value>, final_answer: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let (completed_tx, completed) = sync_channel(1);
        let thread = thread::spawn(move || {
            let mut first = accept_before_deadline(&listener);
            first.set_read_timeout(Some(timeout())).unwrap();
            read_http_request(&mut first);
            let tool = json!({
                "id":"artifact-provider", "object":"chat.completion.chunk",
                "choices":[{"index":0,"delta":{"role":"assistant","tool_calls":calls},"finish_reason":null}],"usage":null
            });
            let finish = json!({
                "id":"artifact-provider", "object":"chat.completion.chunk",
                "choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}],
                "usage":{"prompt_tokens":11,"completion_tokens":2,"total_tokens":13}
            });
            let body = format!("data: {tool}\n\ndata: {finish}\n\ndata: [DONE]\n\n");
            write!(first, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            first.flush().unwrap();
            drop(first);

            if final_answer {
                let mut second = accept_before_deadline(&listener);
                second.set_read_timeout(Some(timeout())).unwrap();
                read_http_request(&mut second);
                write_success(&mut second, 1, "retained native tool complete");
            }
            completed_tx.send(()).unwrap();
        });
        Self {
            api_root: format!("http://{address}/v1"),
            completed,
            thread: Some(thread),
        }
    }

    fn finish(mut self) {
        self.completed
            .recv_timeout(timeout())
            .expect("two actual provider requests complete");
        self.thread
            .take()
            .unwrap()
            .join()
            .expect("tool provider fixture exits");
    }
}

fn launch(
    scratch: &Scratch,
    workspace: &Path,
    turns: u32,
    arguments: &[&str],
) -> (OwnedCore, String, SocketAddr) {
    let token = fresh_bearer_token();
    let mut child = spawn_core_command_with_token_input(
        core_command_with_launch(scratch, workspace, turns, arguments),
        token.as_bytes(),
    );
    let address = wait_for_listening(&mut child);
    (OwnedCore(Some(child)), token, address)
}

fn matching_control(reader: &mut BufReader<TcpStream>, request_id: u64) -> Value {
    let deadline = Instant::now() + timeout();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "artifact control {request_id} timed out"
        );
        reader.get_mut().set_read_timeout(Some(remaining)).unwrap();
        let frame = receive(reader);
        if frame["type"] == "control_reply" && frame["request_id"] == request_id {
            return frame["reply"].clone();
        }
    }
}

fn artifact_list(
    connection: &mut TcpStream,
    reader: &mut BufReader<TcpStream>,
    thread_id: &str,
    request_id: u64,
) -> Value {
    send(
        connection,
        control(
            request_id,
            PROTOCOL_VERSION,
            json!({"type":"artifacts_v1","command":{"type":"list","thread_id":thread_id}}),
        ),
    );
    matching_control(reader, request_id)
}

fn artifact_read(
    connection: &mut TcpStream,
    reader: &mut BufReader<TcpStream>,
    thread_id: &str,
    id: &str,
    request_id: u64,
    offset: u64,
) -> Value {
    send(
        connection,
        control(
            request_id,
            PROTOCOL_VERSION,
            json!({"type":"artifacts_v1","command":{"type":"read","thread_id":thread_id,
            "artifact_id":id,"offset":offset,"max_bytes":65536}}),
        ),
    );
    matching_control(reader, request_id)
}

#[test]
fn native_large_output_is_complete_after_restart_scoped_and_removed_by_verified_cli_erasure() {
    let provider = ToolProvider::spawn();
    let scratch = Scratch::new(&provider.api_root);
    let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
    let mut lines = (0..280)
        .map(|index| {
            format!(
                "retained line {index:03} {}",
                "safe output fragment ".repeat(70)
            )
        })
        .collect::<Vec<_>>();
    lines.push(format!("api_key={secret}"));
    lines.push("the exact retained tail survives context preview and process restart".into());
    let source = lines.join("\n");
    fs::write(scratch.repo().join("large-output.txt"), &source).unwrap();
    let numbered = lines
        .iter()
        .enumerate()
        .map(|(index, line)| format!("{:>6}\t{line}", index + 1))
        .collect::<Vec<_>>()
        .join("\n");
    let expected = iteron_record::redact::scrub(&numbered).into_bytes();
    assert!(
        expected.len() > 256 * 1024,
        "fixture exceeds the resident fallback ceiling"
    );
    assert!(!String::from_utf8_lossy(&expected).contains(secret));
    let id = hex::encode(Sha256::digest(&expected));
    // This explicit operator parameter is captured in the real genesis checkpoint. The test
    // checks complete native result retention, not a claim that default source paging vanished.
    let (child, token, address) = launch(
        &scratch,
        &scratch.repo(),
        2,
        &[
            "--set",
            "read_file_limits={\"source_max_bytes\":8388608,\"output_max_bytes\":524288,\"max_lines\":400}",
        ],
    );
    let mut connection = connect(address);
    send(&mut connection, hello(&token, PROTOCOL_VERSION, 0));
    let mut reader = BufReader::new(connection.try_clone().unwrap());
    let accepted = receive(&mut reader);
    let thread_id = accepted["session_id"].as_str().unwrap().to_owned();
    send(
        &mut connection,
        json!({"type":"submit","protocol_version":PROTOCOL_VERSION,
        "op":{"op":"user_input","text":"read the complete large-output.txt native window"}}),
    );
    let terminal = receive_result_within_timeout(&mut reader);
    assert_eq!(terminal["result"]["outcome"], "done", "{terminal}");
    provider.finish();
    let listing = artifact_list(&mut connection, &mut reader, &thread_id, 301);
    let descriptor = listing["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["artifact_id"] == id)
        .expect("raw native output was retained before the resident preview cap")
        .clone();
    assert_eq!(descriptor["schema"], "iteron.tool-output.v1");
    assert_eq!(descriptor["bytes"], expected.len() as u64);
    assert_eq!(descriptor["complete"], true);
    assert_eq!(
        listing["provenance"],
        "retained_owner_manifest_or_resident_public_event"
    );
    assert!(
        !listing["resident_artifact_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|resident| resident == &id),
        "the complete artifact is retained, not resident fallback"
    );
    let first = artifact_read(&mut connection, &mut reader, &thread_id, &id, 302, 0);
    assert_eq!(first["provenance"], "retained_owner_manifest");
    let first_bytes = base64::engine::general_purpose::STANDARD
        .decode(first["content_base64"].as_str().unwrap())
        .unwrap();
    assert_eq!(first_bytes, expected[..65536]);
    let resume_offset = first["next_offset"].as_u64().unwrap();
    assert_eq!(first["eof"], false);
    drop(reader);
    drop(connection);
    child.stop();

    let run_id = thread_id.strip_prefix("session-").unwrap().to_owned();
    let recorded = iteron_record::load_forked(&scratch.runs(), &RunId(run_id.clone())).unwrap();
    let intent = recorded
        .iter()
        .find(|event| {
            matches!(&event.kind,
            EventKind::ToolReady { tool, .. } if tool.id == "artifact-large-read")
        })
        .expect("pure result origin binds the actual durable ToolReady event");
    assert_eq!(descriptor["source_event_seq"], intent.seq.0);
    let public_owners = fs::read_dir(scratch.runs().join(".public-artifacts"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    assert_eq!(public_owners.len(), 1);
    let owner_path = public_owners[0].clone();

    let (restarted, token, address) = launch(&scratch, &scratch.repo(), 2, &["--resume", &run_id]);
    let mut connection = connect(address);
    send(&mut connection, hello(&token, PROTOCOL_VERSION, 0));
    let mut reader = BufReader::new(connection.try_clone().unwrap());
    assert_eq!(receive(&mut reader)["session_id"], thread_id);
    let listing = artifact_list(&mut connection, &mut reader, &thread_id, 303);
    let resumed = listing["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["artifact_id"] == id)
        .expect("retained owner restores artifact");
    assert_eq!(
        resumed, &descriptor,
        "restart cannot relabel the source origin"
    );
    let mut downloaded = first_bytes;
    let mut offset = resume_offset;
    for request_id in 304..320 {
        let chunk = artifact_read(
            &mut connection,
            &mut reader,
            &thread_id,
            &id,
            request_id,
            offset,
        );
        assert_eq!(chunk["type"], "artifact_chunk_v1", "{chunk}");
        assert_eq!(chunk["artifact"], descriptor);
        assert_eq!(chunk["offset"], offset);
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(chunk["content_base64"].as_str().unwrap())
            .unwrap();
        assert!(!bytes.is_empty() && bytes.len() <= 65536);
        downloaded.extend(bytes);
        let next = chunk["next_offset"].as_u64().unwrap();
        assert!(next > offset);
        offset = next;
        if chunk["eof"] == true {
            break;
        }
    }
    assert_eq!(
        downloaded, expected,
        "all actual served bytes survive process restart"
    );
    assert_eq!(hex::encode(Sha256::digest(&downloaded)), id);
    assert_eq!(offset, expected.len() as u64);
    let refused = artifact_read(
        &mut connection,
        &mut reader,
        "different-thread",
        &id,
        320,
        0,
    );
    assert_eq!(refused["type"], "artifact_refused_v1");
    drop(reader);
    drop(connection);
    restarted.stop();

    // Same authenticated record store, actual different canonical workspace and new resident.
    let foreign_workspace = scratch.root.join("other-workspace");
    fs::create_dir(&foreign_workspace).unwrap();
    let (foreign, token, address) = launch(&scratch, &foreign_workspace, 1, &[]);
    let mut connection = connect(address);
    send(&mut connection, hello(&token, PROTOCOL_VERSION, 0));
    let mut reader = BufReader::new(connection.try_clone().unwrap());
    let foreign_thread = receive(&mut reader)["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let refused = artifact_read(&mut connection, &mut reader, &foreign_thread, &id, 321, 0);
    assert_eq!(refused["type"], "artifact_refused_v1");
    drop(reader);
    drop(connection);
    foreign.stop();

    let mut erase = Command::new(env!("CARGO_BIN_EXE_iteron"));
    erase
        .env_clear()
        .env("HOME", scratch.home())
        .env("USERPROFILE", scratch.home())
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .current_dir(scratch.repo())
        .arg("--repo")
        .arg(scratch.repo())
        .arg("--runs-dir")
        .arg(scratch.runs())
        .args([
            "record",
            "delete",
            &run_id,
            "--operation-id",
            "artifact-journey-delete",
        ]);
    if cfg!(windows) {
        for name in ["SystemRoot", "WINDIR"] {
            if let Some(value) = std::env::var_os(name) {
                erase.env(name, value);
            }
        }
    }
    let erased = erase.output().expect("real record delete process");
    assert!(
        erased.status.success(),
        "{}",
        String::from_utf8_lossy(&erased.stderr)
    );
    let receipt: Value = serde_json::from_slice(&erased.stdout).unwrap();
    assert_eq!(receipt["state"], "verified", "{receipt}");
    assert!(
        !owner_path.exists(),
        "verified CLI deletion clears the exact retained owner index"
    );
    assert!(
        iteron_record::load_forked(&scratch.runs(), &RunId(run_id)).is_err(),
        "verified erasure forbids reopening the removed content lineage"
    );
    assert!(
        scratch.repo().join("large-output.txt").exists(),
        "erasure scope is retained data"
    );
}

#[cfg(unix)]
#[path = "native_diff_journey.rs"]
mod native_diff_journey;
