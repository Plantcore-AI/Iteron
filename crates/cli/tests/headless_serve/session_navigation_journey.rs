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
    for (id, action) in [(896, "first_frame"), (897, "refresh")] {
        send(
            &mut connection,
            control(
                id,
                PROTOCOL_VERSION,
                json!({"type":"provider_catalog_v1","command":{"action":action}}),
            ),
        );
        let catalog = matching_control(&mut reader, id);
        assert_eq!(catalog["type"], "provider_catalog_v1");
        assert_eq!(
            catalog["inventory_digest_sha256"].as_str().unwrap().len(),
            64
        );
        assert!(catalog["providers"].as_u64().unwrap() > 0);
        assert_eq!(catalog["source"], "host_captured_inventory");
    }
    send(
        &mut connection,
        control(
            898,
            PROTOCOL_VERSION,
            json!({"type":"provider_catalog_v1","command":{"action":"retry","selection":{"inventory_digest_sha256":"0".repeat(64),"provider_id":PROVIDER_ID,"model_id":MODEL_ID,"catalog_digest_sha256":"0".repeat(64),"capability_digest_sha256":"0".repeat(64)}}}),
        ),
    );
    assert_eq!(matching_control(&mut reader, 898)["type"], "refused");
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

    send(
        &mut connection,
        control(
            899,
            PROTOCOL_VERSION,
            json!({"type":"thread_lifecycle_v1","command":{"type":"reindex","thread_id":thread,"run_id":origin}}),
        ),
    );
    let repaired = matching_control(&mut reader, 899);
    assert_eq!(repaired["type"], "thread_reindexed_v1");
    assert!(repaired["indexed"].as_u64().unwrap() >= 1);
    send(
        &mut connection,
        control(
            900,
            PROTOCOL_VERSION,
            json!({"type":"thread_lifecycle_v1","command":{"type":"list","limit":25}}),
        ),
    );
    let listed = matching_control(&mut reader, 900);
    assert_eq!(listed["index_ready"], true);
    assert!(
        listed["threads"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["run_id"] == origin)
    );

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
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    {
        let export = |run: &str, path: &str, collision: &str| json!({"type":"transcript_export_v1","command":{"thread_id":thread,"run_id":run,"text":"# Native client export\nexact rendered bytes\n","requested":path,"collision":collision}});
        send(
            &mut connection,
            control(
                907,
                PROTOCOL_VERSION,
                export(&origin, "stale-export.md", "refuse"),
            ),
        );
        assert_eq!(matching_control(&mut reader, 907)["type"], "refused");
        assert!(!scratch.repo().join("stale-export.md").exists());
        send(
            &mut observer,
            control(
                908,
                PROTOCOL_VERSION,
                export(&forked.run_id.0, "observer-export.md", "refuse"),
            ),
        );
        assert_eq!(matching_control(&mut observed, 908)["type"], "refused");
        assert!(!scratch.repo().join("observer-export.md").exists());
        send(
            &mut connection,
            control(
                909,
                PROTOCOL_VERSION,
                export(&forked.run_id.0, "../outside-export.md", "refuse"),
            ),
        );
        assert_eq!(matching_control(&mut reader, 909)["type"], "refused");
        send(
            &mut connection,
            control(
                910,
                PROTOCOL_VERSION,
                export(&forked.run_id.0, "client-transcript.md", "refuse"),
            ),
        );
        let published = matching_control(&mut reader, 910);
        assert_eq!(published["type"], "transcript_export_v1", "{published}");
        assert_eq!(published["receipt"]["status"], "published", "{published}");
        assert_eq!(published["receipt"]["path"], "client-transcript.md");
        assert_eq!(
            published["receipt"]["private_content_cleanup"], "released",
            "{published}"
        );
        assert_eq!(
            fs::read(scratch.repo().join("client-transcript.md")).unwrap(),
            b"# Native client export\nexact rendered bytes\n"
        );
        send(
            &mut connection,
            control(
                911,
                PROTOCOL_VERSION,
                export(&forked.run_id.0, "client-transcript.md", "refuse"),
            ),
        );
        assert_eq!(
            matching_control(&mut reader, 911)["receipt"]["status"],
            "not_published"
        );
        send(
            &mut connection,
            control(
                912,
                PROTOCOL_VERSION,
                export(&forked.run_id.0, "client-transcript.md", "versioned"),
            ),
        );
        let next = matching_control(&mut reader, 912);
        assert_eq!(next["receipt"]["status"], "published", "{next}");
        assert_eq!(next["receipt"]["path"], "client-transcript-2.md");
        assert_eq!(
            fs::read(scratch.repo().join("client-transcript-2.md")).unwrap(),
            fs::read(scratch.repo().join("client-transcript.md")).unwrap()
        );
    }
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
