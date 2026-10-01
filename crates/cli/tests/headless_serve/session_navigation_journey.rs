//! Actual public New/Resume/Fork controls, verified physical lineage and native process restart.
use super::*;
use iteron_protocol::session_navigation::SessionNavigationReplyV1;
use iteron_protocol::{RunId, TenantId};

fn navigate(
    connection: &mut TcpStream,
    reader: &mut BufReader<TcpStream>,
    id: u64,
    command: Value,
) -> Value {
    send(
        connection,
        control(
            id,
            PROTOCOL_VERSION,
            json!({"type":"session_navigate_v1","command":command}),
        ),
    );
    matching_control(reader, id)
}
fn confirmed(value: &Value) -> SessionNavigationReplyV1 {
    assert_eq!(value["type"], "session_navigated_v1", "{value}");
    serde_json::from_value(value["navigation"].clone()).unwrap()
}
fn run_count(runs: &Path) -> usize {
    fs::read_dir(runs)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "jsonl")
        })
        .count()
}
#[test]
fn tcp_navigation_uses_host_ids_checked_origin_and_reopened_physical_fork() {
    let provider = PausedProvider::spawn();
    let scratch = Scratch::new(&provider.api_root);
    let (process, token, address) = launch(&scratch, &scratch.repo(), 4, &[]);
    let mut connection = connect(address);
    send(&mut connection, hello(&token, PROTOCOL_VERSION, 0));
    let mut reader = BufReader::new(connection.try_clone().unwrap());
    let accepted = receive(&mut reader);
    let thread = accepted["session_id"].as_str().unwrap().to_owned();
    let origin = thread.strip_prefix("session-").unwrap().to_owned();
    send(
        &mut connection,
        json!({"type":"submit","protocol_version":PROTOCOL_VERSION,"op":{"op":"user_input","text":"retained navigation origin"}}),
    );
    provider.request_seen.recv_timeout(timeout()).unwrap();
    provider.release.send(()).unwrap();
    assert_eq!(
        receive_result_within_timeout(&mut reader)["result"]["outcome"],
        "done"
    );
    provider.finish();

    let before = run_count(&scratch.runs());
    let foreign = navigate(
        &mut connection,
        &mut reader,
        901,
        json!({"action":"new","thread_id":"another-thread","run_id":origin}),
    );
    assert_eq!(foreign["type"], "refused");
    assert_eq!(
        run_count(&scratch.runs()),
        before,
        "scope refusal occurs before native record creation"
    );

    let mut observer = connect(address);
    let mut greeting = hello(&token, PROTOCOL_VERSION - 1, 0);
    greeting["observation_only"] = json!(true);
    send(&mut observer, greeting);
    let mut observed = BufReader::new(observer.try_clone().unwrap());
    assert_eq!(receive(&mut observed)["type"], "hello");
    send(
        &mut observer,
        control(
            902,
            PROTOCOL_VERSION,
            json!({"type":"session_navigate_v1","command":{"action":"new","thread_id":thread,"run_id":origin}}),
        ),
    );
    let denied = (0..256)
        .find_map(|_| {
            let value = receive(&mut observed);
            (value["type"] == "error").then_some(value)
        })
        .expect("bounded observer replay reaches authority refusal");
    assert_eq!(denied["code"], "observer_authority");
    assert_eq!(run_count(&scratch.runs()), before);

    let created = confirmed(&navigate(
        &mut connection,
        &mut reader,
        903,
        json!({"action":"new","thread_id":thread,"run_id":origin}),
    ));
    assert!(created.fresh);
    assert_eq!(created.origin_run_id.0, origin);
    assert_ne!(created.run_id.0, origin);
    assert_eq!(created.provider_id, PROVIDER_ID);
    assert_eq!(created.model_id, MODEL_ID);
    assert!(created.transcript.blocks.is_empty());
    let created_events =
        iteron_record::replay(&scratch.runs().join(format!("{}.jsonl", created.run_id.0))).unwrap();
    assert_eq!(
        iteron_record::tunables_checkpoint_from_events(&created_events)
            .unwrap()
            .unwrap()
            .snapshot_digest_sha256(),
        created.checkpoint_digest_sha256
    );
    let after_create = run_count(&scratch.runs());
    let stale = navigate(
        &mut connection,
        &mut reader,
        904,
        json!({"action":"new","thread_id":thread,"run_id":origin}),
    );
    assert_eq!(stale["type"], "refused");
    assert_eq!(run_count(&scratch.runs()), after_create);

    let resumed = confirmed(&navigate(
        &mut connection,
        &mut reader,
        905,
        json!({"action":"resume","thread_id":thread,"run_id":created.run_id,"target_run_id":origin}),
    ));
    assert!(!resumed.fresh);
    assert_eq!(resumed.run_id.0, origin);
    assert!(resumed.transcript.blocks.iter().any(|row| matches!(&row.content, iteron_protocol::session_navigation::SessionTranscriptContentV1::User {text} if text == "retained navigation origin")));
    assert!(
        resumed
            .transcript
            .blocks
            .iter()
            .all(|row| row.source_run_id.0 == origin)
    );

    let forked = confirmed(&navigate(
        &mut connection,
        &mut reader,
        906,
        json!({"action":"fork","thread_id":thread,"run_id":origin}),
    ));
    assert_ne!(forked.run_id.0, origin);
    assert!(
        forked
            .transcript
            .blocks
            .iter()
            .any(|row| row.source_run_id.0 == origin)
    );
    let physical =
        iteron_record::replay(&scratch.runs().join(format!("{}.jsonl", forked.run_id.0))).unwrap();
    assert!(
        matches!(&physical[0].kind, EventKind::RunStart {parent_run:Some(parent),parent_hash_at_seq:Some(_),..} if parent == &origin)
    );
    assert!(
        iteron_record::Rollout::open_existing(&scratch.runs(), &forked.run_id, TenantId::default())
            .is_err(),
        "selected physical writer remains exclusively host owned"
    );
    drop(reader);
    drop(connection);
    drop(observed);
    drop(observer);
    process.stop();
    let reopened =
        iteron_record::Rollout::open_existing(&scratch.runs(), &forked.run_id, TenantId::default())
            .unwrap();
    drop(reopened);
    let (restarted, token, address) = launch(
        &scratch,
        &scratch.repo(),
        4,
        &["--resume", &forked.run_id.0],
    );
    let mut connection = connect(address);
    send(&mut connection, hello(&token, PROTOCOL_VERSION, 0));
    let mut reader = BufReader::new(connection.try_clone().unwrap());
    let greeting = receive(&mut reader);
    let new_thread = greeting["session_id"].as_str().unwrap().to_owned();
    let resumed_again = confirmed(&navigate(
        &mut connection,
        &mut reader,
        907,
        json!({"action":"resume","thread_id":new_thread,"run_id":forked.run_id,"target_run_id":origin}),
    ));
    assert_eq!(resumed_again.run_id, RunId(origin));
    assert_eq!(
        resumed_again.transcript.blocks.len(),
        resumed.transcript.blocks.len()
    );
    assert_eq!(
        serde_json::to_value(&resumed_again.transcript.blocks).unwrap(),
        serde_json::to_value(&resumed.transcript.blocks).unwrap()
    );
    drop(reader);
    drop(connection);
    restarted.stop();
}
