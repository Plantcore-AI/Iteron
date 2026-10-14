use super::{Pause, Summary, start_read};
use crate::app_server::AppServerClient;
use iteron_protocol::{
    PROTOCOL_VERSION, RunId, SessionId, client_artifact::ClientArtifactCommandV1,
};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Semaphore, mpsc, oneshot};

fn listing() -> Value {
    let entry = |id: char, schema: &str, complete: bool| {
        json!({"artifact_id":id.to_string().repeat(64),"schema":schema,
            "mime_type":"application/json","bytes":123,"complete":complete,
            "source_event_seq":17,"required_capability":"read_only"})
    };
    json!({"type":"artifacts_v1","contract_version":1,"thread_id":"thread","run_id":"run",
    "retained_catalog_available":true,"resident_artifact_ids":["b".repeat(64)],
    "evicted_artifacts":7,"artifacts":[
        entry('a',"iteron.file-diff.v1",true),
        entry('b',"iteron.file-diff.v1",true),
        entry('c',"iteron.file-diff.v1",false),
        entry('d',"iteron.file-snapshot.v1",true)
    ]})
}
fn wire() -> AppServerClient {
    let (sender, _received) = mpsc::channel(1);
    let client = AppServerClient::connect(PROTOCOL_VERSION, sender).unwrap();
    client.seed_contract_identity_for_test(SessionId("thread".into()), RunId("run".into()));
    client
}
#[test]
fn only_complete_retained_diffs_count_without_claiming_a_current_workspace_scan() {
    let summary = Summary::capture(
        &listing(),
        &SessionId("thread".into()),
        &RunId("run".into()),
    )
    .unwrap();
    assert_eq!(summary.complete_diffs, 1);
    assert_eq!(summary.evicted_objects, 7);
    assert!(summary.label().contains("retained diff snapshots 1"));
    assert!(summary.label().contains("current workspace not scanned"));
    let mut duplicate = listing();
    let entry = duplicate["artifacts"][0].clone();
    duplicate["artifacts"].as_array_mut().unwrap().push(entry);
    assert!(
        Summary::capture(
            &duplicate,
            &SessionId("thread".into()),
            &RunId("run".into())
        )
        .is_err()
    );
}
#[test]
fn unavailable_scope_and_forged_sources_never_become_zero_change_facts() {
    for (key, value) in [
        ("thread_id", json!("foreign")),
        ("run_id", json!("foreign")),
        ("contract_version", json!(2)),
        ("retained_catalog_available", json!(false)),
        ("evicted_artifacts", json!(null)),
        ("resident_artifact_ids", json!(["invalid"])),
    ] {
        let mut reply = listing();
        reply[key] = value;
        assert!(
            Summary::capture(&reply, &SessionId("thread".into()), &RunId("run".into())).is_err()
        );
    }
    for (key, value) in [
        ("source_event_seq", json!(0)),
        ("bytes", json!(8 * 1024 * 1024 + 1)),
        ("artifact_id", json!("x".repeat(64))),
        ("schema", json!("a".repeat(257))),
        ("required_capability", json!("invented")),
    ] {
        let mut reply = listing();
        reply["artifacts"][0][key] = value;
        assert!(
            Summary::capture(&reply, &SessionId("thread".into()), &RunId("run".into())).is_err()
        );
    }
}
#[test]
fn actual_shared_listing_reports_unavailable_retention_separately_from_empty_resident_entries() {
    let client = wire();
    let reply = client.artifacts_v1(ClientArtifactCommandV1::List {
        thread_id: SessionId("thread".into()),
    });
    assert_eq!(reply["thread_id"], "thread");
    assert_eq!(reply["run_id"], "run");
    assert_eq!(reply["retained_catalog_available"], false);
    assert_eq!(reply["artifacts"], json!([]));
    assert!(Summary::capture(&reply, &SessionId("thread".into()), &RunId("run".into())).is_err());
}
#[tokio::test]
async fn dropped_observer_cannot_reuse_the_native_slot_or_rebind_a_held_read() {
    let client = wire();
    let capacity = Arc::new(Semaphore::new(1));
    let permit = capacity.clone().try_acquire_owned().unwrap();
    let (started, observed) = oneshot::channel();
    let (resume, wait) = std::sync::mpsc::channel();
    let reader = start_read(
        client.clone(),
        SessionId("thread".into()),
        RunId("run".into()),
        permit,
        Some(Pause {
            started,
            resume: wait,
        }),
    );
    tokio::time::timeout(Duration::from_secs(3), observed)
        .await
        .unwrap()
        .unwrap();
    drop(reader);
    assert!(capacity.clone().try_acquire_owned().is_err());
    client.seed_contract_identity_for_test(SessionId("thread".into()), RunId("other-run".into()));
    assert!(capacity.clone().try_acquire_owned().is_err());
    resume.send(()).unwrap();
    let completed = tokio::time::timeout(Duration::from_secs(3), capacity.acquire_owned())
        .await
        .unwrap()
        .unwrap();
    drop(completed);
    assert_eq!(client.thread_snapshot_v1().unwrap().run_id.0, "other-run");
}
