//! Actual HTTP MCP request -> shared callback -> authenticated TCP answer, without retained values.
use super::*;
const PRIVATE_INPUT: &str = "operator-field-value-must-not-be-retained";

struct OwnedInputService(Option<CoreProcess>);
impl Drop for OwnedInputService {
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
fn accept(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + timeout();
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_read_timeout(Some(io_timeout())).unwrap();
                stream.set_write_timeout(Some(io_timeout())).unwrap();
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "actual fixture accept deadline");
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("fixture accept: {error}"),
        }
    }
}
fn request(stream: &mut TcpStream) -> Value {
    let mut data = Vec::new();
    let mut chunk = [0_u8; 4096];
    let deadline = Instant::now() + timeout();
    loop {
        stream
            .set_read_timeout(Some(deadline.saturating_duration_since(Instant::now())))
            .unwrap();
        let read = stream.read(&mut chunk).unwrap();
        assert!(read > 0);
        data.extend_from_slice(&chunk[..read]);
        assert!(data.len() <= 1024 * 1024);
        if let Some(end) = data.windows(4).position(|v| v == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&data[..end]).unwrap();
            let length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|value| value.trim().parse::<usize>().ok())
                })
                .unwrap();
            if data.len() >= end + 4 + length {
                return serde_json::from_slice(&data[end + 4..end + 4 + length]).unwrap();
            }
        }
    }
}
fn json_response(stream: &mut TcpStream, request: &Value, result: Value) {
    let body = json!({"jsonrpc":"2.0","id":request["id"],"result":result}).to_string();
    write!(stream,"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",body.len()).unwrap();
    stream.flush().unwrap();
}
fn tool_response(stream: &mut TcpStream, index: usize, name: &str, input: Value) {
    let call = json!({"id":"input-provider","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":format!("input-call-{index}"),"type":"function","function":{"name":name,"arguments":input.to_string()}}]},"finish_reason":null}]});
    let finish = json!({"id":"input-provider","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":11,"completion_tokens":2,"total_tokens":13,"prompt_tokens_details":{"cached_tokens":0,"cache_creation_tokens":0},"completion_tokens_details":{"reasoning_tokens":0}}});
    let body = format!("data: {call}\n\ndata: {finish}\n\ndata: [DONE]\n\n");
    write!(stream,"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",body.len()).unwrap();
    stream.flush().unwrap();
}
fn input_control(
    stream: &mut TcpStream,
    reader: &mut BufReader<TcpStream>,
    id: u64,
    thread: &str,
    run: &str,
    action: Value,
    terminal: &mut Option<Value>,
) -> Value {
    send(
        stream,
        control(
            id,
            PROTOCOL_VERSION,
            json!({"type":"mcp_inputs_v1","command":{"thread_id":thread,"run_id":run,"command":action}}),
        ),
    );
    let deadline = Instant::now() + timeout();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "real input control reply deadline");
        reader.get_mut().set_read_timeout(Some(remaining)).unwrap();
        let frame = receive(reader);
        if frame["type"] == "result" {
            *terminal = Some(frame);
            continue;
        }
        if frame["type"] == "control_reply" && frame["request_id"] == id {
            return frame["reply"].clone();
        }
    }
}
#[test]
fn actual_remote_mcp_form_can_be_answered_after_client_loss_without_value_retention() {
    let mcp = TcpListener::bind("127.0.0.1:0").unwrap();
    mcp.set_nonblocking(true).unwrap();
    let mcp_address = mcp.local_addr().unwrap();
    let (asked, question_seen) = sync_channel(1);
    let (finished, mcp_finished) = sync_channel(1);
    let mcp_thread = thread::spawn(move || {
        let mut socket = accept(&mcp);
        let first = request(&mut socket);
        assert_eq!(first["method"], "server/discover");
        assert!(first["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["elicitation"]["form"].is_object());
        json_response(
            &mut socket,
            &first,
            json!({"resultType":"complete","supportedVersions":[iteron_mcp::MODERN_PROTOCOL_VERSION],"capabilities":{"tools":{}},"serverInfo":{"name":"input-fixture","version":"1"}}),
        );
        let mut socket = accept(&mcp);
        let list = request(&mut socket);
        assert_eq!(list["method"], "tools/list");
        json_response(
            &mut socket,
            &list,
            json!({"tools":[{"name":"choose","description":"Ask the operator for a label","inputSchema":{"type":"object","properties":{}}}]}),
        );
        let mut socket = accept(&mcp);
        let call = request(&mut socket);
        assert_eq!(call["method"], "tools/call");
        assert_eq!(call["params"]["name"], "choose");
        json_response(
            &mut socket,
            &call,
            json!({"resultType":"input_required","requestState":"private-state-for-real-callback","inputRequests":{"opaque-private-request":{"method":"elicitation/create","params":{"message":"Choose a label","requestedSchema":{"type":"object","properties":{"label":{"type":"string"}},"required":["label"]}}}}}),
        );
        asked.send(()).unwrap();
        let mut socket = accept(&mcp);
        let continuation = request(&mut socket);
        assert_eq!(continuation["method"], "tools/call");
        assert_eq!(
            continuation["params"]["requestState"],
            "private-state-for-real-callback"
        );
        assert_eq!(
            continuation["params"]["inputResponses"]["opaque-private-request"],
            json!({"action":"accept","content":{"label":PRIVATE_INPUT}})
        );
        json_response(
            &mut socket,
            &continuation,
            json!({"resultType":"complete","content":[{"type":"text","text":"Input accepted without retaining its fields"}]}),
        );
        finished.send(()).unwrap();
    });
    let provider = TcpListener::bind("127.0.0.1:0").unwrap();
    provider.set_nonblocking(true).unwrap();
    let provider_address = provider.local_addr().unwrap();
    let provider_thread = thread::spawn(move || {
        let mut first = accept(&provider);
        let submitted = request(&mut first);
        assert!(!submitted.to_string().contains(PRIVATE_INPUT));
        tool_response(
            &mut first,
            0,
            "forms__tool_search",
            json!({"query":"choose","limit":1}),
        );
        let mut second = accept(&provider);
        let prepared = request(&mut second);
        assert!(!prepared.to_string().contains(PRIVATE_INPUT));
        tool_response(
            &mut second,
            1,
            "forms__tool_call",
            json!({"name":"choose","arguments":{}}),
        );
        let mut third = accept(&provider);
        let final_request = request(&mut third);
        assert!(!final_request.to_string().contains(PRIVATE_INPUT));
        write_success(&mut third, 1, "The operator form was resolved.");
    });
    let scratch = Scratch::new(&format!("http://{provider_address}/v1"));
    let config_path = scratch.home().join(".iteron/config.json");
    let mut config: Value = serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
    config["schema_version"] = json!(2);
    // The admitted callback survives client loss, two reconnects and authenticated controls.
    // This finite operator journey has a distinct ceiling from an ordinary one-shot reply.
    config["max_wall_secs"] = json!(30);
    config["mcp_servers"] =
        json!([{"name":"forms","transport":"http","url":format!("http://{mcp_address}/mcp")}]);
    fs::write(config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    let (process, token, address) = launch(
        &scratch,
        &scratch.repo(),
        6,
        &["--dangerously-bypass-permissions"],
    );
    let mut service = OwnedInputService(Some(process));
    let mut stream = connect(address);
    send(&mut stream, hello(&token, PROTOCOL_VERSION, 0));
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let greeting = receive(&mut reader);
    let thread = greeting["session_id"].as_str().unwrap().to_owned();
    let run = thread.strip_prefix("session-").unwrap().to_owned();
    send(
        &mut stream,
        json!({"type":"submit","protocol_version":PROTOCOL_VERSION,"op":{"op":"user_input","text":"Ask the forms tool for a label"}}),
    );
    question_seen.recv_timeout(timeout()).unwrap();
    drop(reader);
    drop(stream);
    let mut stream = connect(address);
    send(&mut stream, hello(&token, PROTOCOL_VERSION, 0));
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    assert_eq!(receive(&mut reader)["session_id"], thread);
    let mut observed_terminal = None;
    // Subscribe by bounded state-wait; this is the same callback, not a replayed tool call.
    let snapshot = input_control(
        &mut stream,
        &mut reader,
        3000,
        &thread,
        &run,
        json!({"action":"wait","after_revision":0,"timeout_ms":2000}),
        &mut observed_terminal,
    );
    assert_eq!(snapshot["type"], "mcp_inputs_snapshot_v1");
    assert_eq!(snapshot["snapshot"]["pending"].as_array().unwrap().len(), 1);
    let id = snapshot["snapshot"]["pending"][0]["request_id"]
        .as_u64()
        .unwrap();
    assert_eq!(
        snapshot["snapshot"]["pending"][0]["fields"][0]["field_index"],
        0
    );
    assert_eq!(snapshot["snapshot"]["pending"][0]["prompt_complete"], true);
    assert!(
        !snapshot.to_string().contains("opaque-private-request")
            && !snapshot
                .to_string()
                .contains("private-state-for-real-callback")
    );
    let foreign = input_control(
        &mut stream,
        &mut reader,
        3001,
        &thread,
        "foreign",
        json!({"action":"respond","request_id":id,"answer":{"action":"reject"}}),
        &mut observed_terminal,
    );
    assert_eq!(foreign["reason_code"], "scope_mismatch");
    let mut observer = connect(address);
    send(
        &mut observer,
        json!({"type":"hello","bearer_token":token,"protocol_version":PROTOCOL_VERSION-1,"observation_only":true}),
    );
    let mut observed = BufReader::new(observer.try_clone().unwrap());
    assert_eq!(receive(&mut observed)["type"], "hello");
    send(
        &mut observer,
        control(
            3002,
            PROTOCOL_VERSION - 1,
            json!({"type":"mcp_inputs_v1","command":{"thread_id":thread,"run_id":run,"command":{"action":"respond","request_id":id,"answer":{"action":"reject"}}}}),
        ),
    );
    assert_eq!(receive(&mut observed)["code"], "observer_authority");
    drop(observed);
    drop(observer);
    let answer = json!({"action":"respond","request_id":id,"answer":{"action":"approve","values":[{"field_index":0,"content":{"label":PRIVATE_INPUT}}]}});
    let reply = input_control(
        &mut stream,
        &mut reader,
        3003,
        &thread,
        &run,
        answer.clone(),
        &mut observed_terminal,
    );
    assert_eq!(reply["state"], "answered");
    assert!(!reply.to_string().contains(PRIVATE_INPUT));
    mcp_finished.recv_timeout(timeout()).unwrap();
    let duplicate = input_control(
        &mut stream,
        &mut reader,
        3004,
        &thread,
        &run,
        answer,
        &mut observed_terminal,
    );
    assert_eq!(duplicate["type"], "mcp_input_refused_v1");
    let status = input_control(
        &mut stream,
        &mut reader,
        3005,
        &thread,
        &run,
        json!({"action":"read"}),
        &mut observed_terminal,
    );
    assert!(status["snapshot"]["pending"].as_array().unwrap().is_empty());
    assert_eq!(status["snapshot"]["closed"][0]["state"], "answered");
    assert!(!status.to_string().contains(PRIVATE_INPUT));
    let terminal = observed_terminal.unwrap_or_else(|| receive_result_within_timeout(&mut reader));
    assert_eq!(terminal["result"]["outcome"], "done");
    drop(reader);
    drop(stream);
    stop(service.0.take().unwrap());
    mcp_thread.join().unwrap();
    provider_thread.join().unwrap();
    for path in fs::read_dir(scratch.runs())
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "jsonl")
        })
    {
        let bytes = fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains(PRIVATE_INPUT));
        let events = iteron_record::replay(&path).unwrap();
        let calls=events.iter().filter(|event|matches!(&event.kind,iteron_protocol::EventKind::EffectIntent{tool,..} if tool=="forms__tool_call")).count();
        assert_eq!(
            calls, 1,
            "responses/reconnects cannot redispatch the admitted tool"
        );
    }
}
