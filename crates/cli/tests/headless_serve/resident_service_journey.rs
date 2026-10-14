//! Real independent backend process; TCP clients own no runtime task or server handle.
use super::{
    CoreProcess, PROTOCOL_VERSION, PausedProvider, Scratch, connect, control, hello, only_rollout,
    receive, send, spawn_core, take_stderr, timeout,
};
use serde_json::{Value, json};
use std::io::BufReader;
use std::net::TcpStream;
use std::time::{Duration, Instant};

struct RetainedCore(Option<CoreProcess>);
impl Drop for RetainedCore {
    fn drop(&mut self) {
        if let Some(mut process) = self.0.take() {
            let _ = process.child.kill();
            let _ = process.child.wait();
            let _ = take_stderr(&mut process);
        }
    }
}
fn reply(reader: &mut BufReader<TcpStream>, request: u64) -> Value {
    let deadline = Instant::now() + timeout();
    for _ in 0..4096 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "actual service reply was not observed"
        );
        reader.get_mut().set_read_timeout(Some(remaining)).unwrap();
        let frame = receive(reader);
        if frame["type"] == "control_reply" && frame["request_id"] == request {
            return frame["reply"].clone();
        }
        assert_ne!(
            frame["type"], "error",
            "service refused a current scoped client"
        );
    }
    panic!("service reply exceeded finite frame budget");
}
fn read_service(
    connection: &mut TcpStream,
    reader: &mut BufReader<TcpStream>,
    request: u64,
) -> Value {
    send(
        connection,
        control(
            request,
            PROTOCOL_VERSION,
            json!({"type":"resident_service_v1","command":{"action":"read"}}),
        ),
    );
    reply(reader, request)
}
#[test]
fn disconnected_client_leaves_paid_turn_live_and_new_client_reuses_the_same_service_before_explicit_stop()
 {
    let provider = PausedProvider::spawn();
    let scratch = Scratch::new(&provider.api_root);
    let (process, token, endpoint) = spawn_core(&scratch);
    let mut core = RetainedCore(Some(process));
    let mut first = connect(endpoint);
    let mut first_reader = BufReader::new(first.try_clone().unwrap());
    let mut initial = hello(&token, PROTOCOL_VERSION, 0);
    initial["product_contract_version"] =
        json!(iteron_protocol::product_contract::PRODUCT_CONTRACT_VERSION);
    initial["live_only"] = json!(true);
    send(&mut first, initial);
    let greeting = receive(&mut first_reader);
    assert_eq!(greeting["type"], "hello");
    let before = read_service(&mut first, &mut first_reader, 1);
    let scope = before["service"]["scope"].clone();
    assert_eq!(before["service"]["endpoint"], endpoint.to_string());
    let run = before["service"]["current_run_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let text = "continue after the UI disconnects";
    let request_key =
        super::turn_start_journey::request_key(scope["thread_id"].as_str().unwrap(), text);
    send(
        &mut first,
        control(
            2,
            PROTOCOL_VERSION,
            json!({"type":"product_v1","command":{"type":"turn_start","request_key":request_key,"thread_id":scope["thread_id"],"text":text}}),
        ),
    );
    assert_eq!(reply(&mut first_reader, 2)["type"], "turn_start_receipt_v2");
    provider.request_seen.recv_timeout(timeout()).unwrap();
    drop(first_reader);
    drop(first);
    assert!(core.0.as_mut().unwrap().child.try_wait().unwrap().is_none());
    let mut reopened = connect(endpoint);
    let mut reader = BufReader::new(reopened.try_clone().unwrap());
    let mut attach = hello(&token, PROTOCOL_VERSION, 0);
    attach["product_contract_version"] =
        json!(iteron_protocol::product_contract::PRODUCT_CONTRACT_VERSION);
    attach["live_only"] = json!(true);
    send(&mut reopened, attach);
    assert_eq!(receive(&mut reader)["session_id"], greeting["session_id"]);
    let current = read_service(&mut reopened, &mut reader, 3);
    assert_eq!(current["service"]["scope"], scope);
    assert_eq!(current["service"]["current_run_id"], run);
    assert_eq!(current["service"]["stopping"], false);
    assert_eq!(current["service"]["shutdown_completed"], false);
    let mut wrong = scope.clone();
    wrong["workspace_sha256"] = json!("0".repeat(64));
    send(
        &mut reopened,
        control(
            4,
            PROTOCOL_VERSION,
            json!({"type":"resident_service_v1","command":{"action":"stop","scope":wrong}}),
        ),
    );
    assert_eq!(reply(&mut reader, 4)["reason_code"], "scope_mismatch");
    assert!(core.0.as_mut().unwrap().child.try_wait().unwrap().is_none());
    provider.release.send(()).unwrap();
    let result = super::receive_result_within_timeout(&mut reader);
    assert_eq!(result["result"]["run_id"], run);
    assert_eq!(result["result"]["outcome"], "done");
    assert_eq!(result["result"]["assistant_text"], "parity reply");
    send(
        &mut reopened,
        control(
            5,
            PROTOCOL_VERSION,
            json!({"type":"product_v1","command":{"type":"events_read","thread_id":scope["thread_id"],"after":0}}),
        ),
    );
    let page = reply(&mut reader, 5);
    assert!(
        page["page"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["run_id"] == run && event["event"]["type"] == "turn_ended")
    );
    send(
        &mut reopened,
        control(
            6,
            PROTOCOL_VERSION,
            json!({"type":"resident_service_v1","command":{"action":"stop","scope":scope}}),
        ),
    );
    let stopped = reply(&mut reader, 6);
    assert_eq!(stopped["status"], "requested");
    assert_eq!(stopped["shutdown_completed"], false);
    drop(reader);
    drop(reopened);
    let deadline = Instant::now() + timeout();
    loop {
        if let Some(status) = core.0.as_mut().unwrap().child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "explicit service stop lacked an actual exit receipt"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let logs = take_stderr(core.0.as_mut().unwrap());
    core.0 = None;
    assert!(
        !logs
            .windows(token.len())
            .any(|window| window == token.as_bytes())
    );
    provider.finish();
    let events = iteron_record::replay(&only_rollout(&scratch.runs())).unwrap();
    let provider_intents = events
        .iter()
        .filter(|event| {
            matches!(
                &event.kind,
                iteron_protocol::EventKind::EffectIntent {
                    provider_route_attempt: Some(_),
                    ..
                }
            )
        })
        .count();
    assert_eq!(
        provider_intents, 1,
        "reopening a UI must not repeat the physical request"
    );
    let message = events.iter().find(|event| match &event.kind {
        iteron_protocol::EventKind::Message { message } => message.role == iteron_protocol::Role::Assistant && message.content.iter().any(|block| matches!(block,iteron_protocol::Block::Text {text} if text == "parity reply")),
        _ => false,
    }).expect("actual assistant message");
    assert!(events.iter().any(|event| event.seq > message.seq
        && event.turn == message.turn
        && matches!(&event.kind,iteron_protocol::EventKind::Done{outcome}if outcome=="Done")));
}

#[cfg(unix)]
#[path = "resident_service_journey/tui_attach_journey.rs"]
mod tui_attach_journey;
