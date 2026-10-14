//! A public read consumes the actual finalized host owner and joins its exact physical Done.
use super::*;
#[test]
fn public_final_evidence_uses_the_actual_done_source_and_does_not_claim_tests_passed() {
    let provider = PausedProvider::spawn();
    let scratch = Scratch::new(&provider.api_root);
    let (process, token, address) = launch(&scratch, &scratch.repo(), 2, &[]);
    let mut service = Service(Some(process));
    let mut connection = connect(address);
    send(&mut connection, hello(&token, PROTOCOL_VERSION, 0));
    let mut reader = BufReader::new(connection.try_clone().unwrap());
    let greeting = receive(&mut reader);
    let thread = greeting["session_id"].as_str().unwrap().to_owned();
    let run = thread.strip_prefix("session-").unwrap().to_owned();
    let query =
        json!({"type":"host_final_evidence_v1","command":{"thread_id":thread,"run_id":run}});
    send(
        &mut connection,
        control(3700, PROTOCOL_VERSION, query.clone()),
    );
    let absent = matching_control(&mut reader, 3700);
    assert_eq!(absent["availability"], "no_live_invocation_receipt");
    assert!(absent["evidence"].is_null());
    send(
        &mut connection,
        json!({"type":"submit","protocol_version":PROTOCOL_VERSION,"op":{"op":"user_input","text":"Return an ordinary answer without running checks"}}),
    );
    provider.request_seen.recv_timeout(timeout()).unwrap();
    provider.release.send(()).unwrap();
    assert_eq!(
        receive_result_within_timeout(&mut reader)["result"]["outcome"],
        "done"
    );
    provider.finish();
    send(&mut connection, control(3701, PROTOCOL_VERSION, query));
    let evidence = matching_control(&mut reader, 3701);
    assert_eq!(evidence["availability"], "available");
    assert_eq!(evidence["evidence"]["configured_check"], "not_observed");
    assert_eq!(evidence["evidence"]["test_suite_identity_verified"], false);
    assert_eq!(evidence["evidence"]["observed_tool_completions"], 0);
    let seq = evidence["evidence"]["source_seq"].as_u64().unwrap();
    let turn = evidence["evidence"]["final_turn"].as_u64().unwrap();
    send(
        &mut connection,
        control(
            3702,
            PROTOCOL_VERSION,
            json!({"type":"host_final_evidence_v1","command":{"thread_id":thread,"run_id":"foreign"}}),
        ),
    );
    assert_eq!(
        matching_control(&mut reader, 3702)["type"],
        "host_final_evidence_refused_v1"
    );
    drop(reader);
    drop(connection);
    stop(service.0.take().unwrap());
    let events = iteron_record::replay(&scratch.runs().join(format!("{run}.jsonl"))).unwrap();
    assert!(
        events.iter().any(|event| event.seq.0 == seq
            && u64::from(event.turn.0) == turn
            && matches!(event.kind, iteron_protocol::EventKind::Done { .. })),
        "evidence must join actual same-run Done, not a UI or guessed source sequence"
    );
}
struct Service(Option<CoreProcess>);
impl Drop for Service {
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
