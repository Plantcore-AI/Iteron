use super::*;
use crate::tui::session_picker::spawn_host_session_page_load;
use iteron_protocol::PROTOCOL_VERSION;
use serde_json::json;

fn wire() -> (
    AppServerClient,
    HistoryClient,
    mpsc::Receiver<ControlRequest>,
) {
    let (submissions, _received) = mpsc::channel(1);
    let client = AppServerClient::connect(PROTOCOL_VERSION, submissions).unwrap();
    client.seed_contract_identity_for_test(
        SessionId("selected-thread".into()),
        RunId("selected-run".into()),
    );
    let (sender, received) = mpsc::channel(8);
    let history = HistoryClient::capture(client.clone(), sender).unwrap();
    (client, history, received)
}

#[tokio::test]
async fn list_repair_list_observes_actual_host_receipts_and_keeps_opaque_cursor() {
    let (_client, history, mut received) = wire();
    let page = spawn_host_session_page_load(
        history,
        std::path::PathBuf::new(),
        "selected-run".into(),
        7,
        None,
        25,
        true,
    );
    let first = received.recv().await.unwrap();
    assert!(matches!(
        first.control,
        Control::ThreadLifecycle(ThreadLifecycleCommandV1::List { .. })
    ));
    first
        .reply
        .send(ControlReply::ThreadLifecycle(
            json!({"type":"thread_list_v1","index_ready":false,"rebuild_recommended":true}),
        ))
        .unwrap();
    let repair = received.recv().await.unwrap();
    assert!(matches!(
        repair.control,
        Control::ThreadLifecycle(ThreadLifecycleCommandV1::Reindex { .. })
    ));
    repair
        .reply
        .send(ControlReply::ThreadLifecycle(
            json!({"type":"thread_reindexed_v1","indexed":1,"unavailable":1}),
        ))
        .unwrap();
    let reread = received.recv().await.unwrap();
    assert!(matches!(
        reread.control,
        Control::ThreadLifecycle(ThreadLifecycleCommandV1::List { cursor: None, .. })
    ));
    reread.reply.send(ControlReply::ThreadLifecycle(json!({"type":"thread_list_v1","index_ready":true,"threads":[{"run_id":"selected-run","title":"Saved","cost_usd":null,"recorded_outcome":"interrupted","provider_id":"route","model":"model","workspace":"display only"}],"next_cursor":"opaque-host-cursor","has_more":true}))).unwrap();
    let page = page.await.unwrap();
    assert_eq!(page.next_cursor.as_deref(), Some("opaque-host-cursor"));
    assert!(page.items[0].is_current);
    assert!(page.items[0].hint.contains("cost unknown"));
    assert!(page.items[0].hint.contains("recorded interrupted"));
    assert!(page.warning.is_some());
}

#[tokio::test]
async fn stale_scope_refuses_before_send_and_after_real_reply() {
    let (client, history, mut received) = wire();
    client.seed_contract_identity_for_test(
        SessionId("another-thread".into()),
        RunId("another-run".into()),
    );
    assert!(history.repair_index().await.is_err());
    assert!(received.try_recv().is_err());
    let current = HistoryClient::capture(client.clone(), history.control.clone()).unwrap();
    let pending = tokio::spawn(async move {
        current
            .request(ThreadLifecycleCommandV1::List {
                cursor: None,
                limit: 1,
            })
            .await
    });
    let request = received.recv().await.unwrap();
    client.seed_contract_identity_for_test(
        SessionId("third-thread".into()),
        RunId("third-run".into()),
    );
    request
        .reply
        .send(ControlReply::ThreadLifecycle(
            json!({"type":"thread_list_v1"}),
        ))
        .unwrap();
    assert!(pending.await.unwrap().unwrap_err().contains("changed"));
}

#[tokio::test]
async fn transient_index_observation_never_dispatches_repair() {
    let (_client, history, mut received) = wire();
    let page = spawn_host_session_page_load(
        history,
        std::path::PathBuf::new(),
        "selected-run".into(),
        8,
        None,
        25,
        true,
    );
    let first = received.recv().await.unwrap();
    first
        .reply
        .send(ControlReply::ThreadLifecycle(
            json!({"type":"thread_list_v1","index_ready":false,"rebuild_recommended":false}),
        ))
        .unwrap();
    assert!(
        page.await.unwrap().items[0]
            .hint
            .contains("temporarily unavailable")
    );
    assert!(received.try_recv().is_err());
}
