//! Actual provider EndTurn, existing terminal WAL source and public recovery observations.

use super::*;
use iteron_protocol::turn_publication::{
    TURN_PUBLICATION_VERSION, TurnPublicationEventV1, TurnPublicationFactV1,
};
use iteron_protocol::{Block, Role};

fn publications(
    connection: &mut TcpStream,
    reader: &mut BufReader<TcpStream>,
    thread_id: &str,
    request_id: u64,
    subscribe: bool,
) -> Value {
    send(
        connection,
        control(
            request_id,
            PROTOCOL_VERSION,
            json!({
                "type":"turn_publications_v1", "command":{
                    "type":if subscribe {"subscribe"} else {"read"}, "thread_id":thread_id
                }
            }),
        ),
    );
    matching_control(reader, request_id)
}

#[test]
fn actual_final_answer_and_done_sources_survive_process_restart_without_legacy_stream_drift() {
    let provider = ToolProvider::spawn();
    let scratch = Scratch::new(&provider.api_root);
    fs::write(
        scratch.repo().join("large-output.txt"),
        "a small actual native read",
    )
    .unwrap();
    let (child, token, address) = launch(&scratch, &scratch.repo(), 2, &[]);
    let mut connection = connect(address);
    send(&mut connection, hello(&token, PROTOCOL_VERSION, 0));
    let mut reader = BufReader::new(connection.try_clone().unwrap());
    let accepted = receive(&mut reader);
    let thread_id = accepted["session_id"].as_str().unwrap().to_owned();
    let initial = publications(&mut connection, &mut reader, &thread_id, 601, true);
    assert_eq!(initial["type"], "turn_publications_v1");
    assert!(initial["snapshot"]["events"].as_array().unwrap().is_empty());

    let mut legacy = connect(address);
    send(&mut legacy, hello(&token, PROTOCOL_VERSION, 0));
    let mut legacy_reader = BufReader::new(legacy.try_clone().unwrap());
    assert_eq!(receive(&mut legacy_reader)["type"], "hello");

    send(
        &mut connection,
        json!({"type":"submit","protocol_version":PROTOCOL_VERSION,
        "op":{"op":"user_input","text":"read large-output.txt and answer"}}),
    );
    let deadline = Instant::now() + timeout();
    let mut observations = Vec::new();
    let terminal = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "actual answer/finalization journey timed out"
        );
        reader.get_mut().set_read_timeout(Some(remaining)).unwrap();
        let frame = receive(&mut reader);
        if frame["type"] == "turn_publication_v1" {
            let event: TurnPublicationEventV1 =
                serde_json::from_value(frame["publication"].clone()).unwrap();
            event.validate().unwrap();
            assert_eq!(event.contract_version, TURN_PUBLICATION_VERSION);
            observations.push(event);
        } else if frame["type"] == "result" {
            break frame;
        }
    };
    assert_eq!(terminal["result"]["outcome"], "done", "{terminal}");
    assert_eq!(
        observations.len(),
        2,
        "tool turns do not publish final answer availability"
    );
    assert!(matches!(
        observations[0].fact,
        TurnPublicationFactV1::AnswerAvailable { .. }
    ));
    assert!(matches!(
        observations[1].fact,
        TurnPublicationFactV1::TurnFinalized { .. }
    ));
    assert!(observations[0].source_seq < observations[1].source_seq);
    assert_eq!(observations[0].turn_id, observations[1].turn_id);
    provider.finish();

    // A sibling without Subscribe keeps its existing dense presentation cursor and result shape.
    let mut previous = 0;
    loop {
        let frame = receive(&mut legacy_reader);
        assert_ne!(frame["type"], "turn_publication_v1");
        if matches!(frame["type"].as_str(), Some("event" | "result")) {
            let seq = frame["seq"].as_u64().unwrap();
            assert_eq!(seq, previous + 1);
            previous = seq;
        }
        if frame["type"] == "result" {
            assert_eq!(frame["result"], terminal["result"]);
            break;
        }
    }
    let snapshot = publications(&mut connection, &mut reader, &thread_id, 602, false);
    let recorded_observations: Vec<TurnPublicationEventV1> =
        serde_json::from_value(snapshot["snapshot"]["events"].clone()).unwrap();
    assert_eq!(recorded_observations, observations);
    let refusal = publications(&mut connection, &mut reader, "another-thread", 603, true);
    assert_eq!(refusal["reason_code"], "thread_mismatch");
    drop(reader);
    drop(connection);
    drop(legacy_reader);
    drop(legacy);
    child.stop();

    let run_id = thread_id.strip_prefix("session-").unwrap().to_owned();
    let events = iteron_record::load_forked(&scratch.runs(), &RunId(run_id.clone())).unwrap();
    let answer = events
        .iter()
        .find(|event| event.seq.0 == observations[0].source_seq)
        .unwrap();
    let EventKind::TurnPublicationV1 {
        fact: TurnPublicationFactV1::AnswerAvailable { message_seq },
    } = &answer.kind
    else {
        panic!("availability must bind the actual durable typed producer, not Activity/UI text");
    };
    let message = events
        .iter()
        .find(|event| event.seq.0 == *message_seq)
        .unwrap();
    assert_eq!(message.turn, answer.turn);
    let EventKind::Message { message } = &message.kind else {
        panic!("availability source is not Message");
    };
    assert_eq!(message.role, Role::Assistant);
    assert!(message.content.iter().any(|block| matches!(block, Block::Text { text } if text.contains("retained native tool complete"))));
    assert!(
        !message
            .content
            .iter()
            .any(|block| matches!(block, Block::ToolUse(_)))
    );
    let done = events
        .iter()
        .find(|event| event.seq.0 == observations[1].source_seq)
        .unwrap();
    assert!(matches!(&done.kind, EventKind::Done { outcome } if outcome == "Done"));
    assert_eq!(done.turn, observations[1].turn_id);

    let (restarted, token, address) = launch(&scratch, &scratch.repo(), 2, &["--resume", &run_id]);
    let mut connection = connect(address);
    send(&mut connection, hello(&token, PROTOCOL_VERSION, 0));
    let mut reader = BufReader::new(connection.try_clone().unwrap());
    assert_eq!(receive(&mut reader)["session_id"], thread_id);
    let recovered = publications(&mut connection, &mut reader, &thread_id, 604, false);
    assert_eq!(recovered["snapshot"]["recovery"], "verified_record");
    let recovered_events: Vec<TurnPublicationEventV1> =
        serde_json::from_value(recovered["snapshot"]["events"].clone()).unwrap();
    assert_eq!(
        recovered_events, observations,
        "restart cannot replace record sources with presentation cursors"
    );
    drop(reader);
    drop(connection);
    restarted.stop();
}
