use super::*;
use crate::tui::picker::PickerEvent;
use crossterm::event::{KeyCode, KeyModifiers};
use iteron_protocol::{SessionId, product_contract::ThreadSnapshotV1};
use ratatui::{Terminal, backend::TestBackend};
use serde_json::json;

fn page(rows: &[&str], cursor: Option<&str>) -> Value {
    json!({"type":"thread_list_v1","index_ready":true,
        "threads":rows.iter().map(|run| json!({"run_id":run,"title":format!("saved {run}"),
            "workspace":"read-only host observation","provider_id":"route","model":"model",
            "cost_usd":null,"recorded_outcome":"done"})).collect::<Vec<_>>(),
        "next_cursor":cursor,"has_more":cursor.is_some()})
}
fn snapshot() -> ThreadSnapshotV1 {
    ThreadSnapshotV1 {
        contract_version: 1,
        thread_id: SessionId("thread".into()),
        run_id: RunId("current".into()),
        source_event_seq: 17,
        turn: None,
        submissions: vec![],
        evicted_submissions: 0,
    }
}
#[test]
fn actual_picker_filter_and_selection_return_the_same_host_run_id_without_mutating_the_draft() {
    let mut app = App::new();
    app.editor.insert_str("retained operator draft");
    let mut sessions = Sessions::default();
    let generation = sessions.begin(&mut app, RunId("current".into()));
    assert!(sessions.matches(&app, &RunId("current".into()), generation));
    assert!(matches!(
        sessions.page(&mut app, &page(&["current", "older"], None), false),
        Ok(Page::Applied)
    ));
    assert!(app.pickers.paste("older"));
    let accepted = app.pickers.key(KeyCode::Enter, KeyModifiers::NONE).unwrap();
    assert!(
        matches!(accepted.event, PickerEvent::Accept(PickAction::AdoptRun(run)) if run == "older")
    );
    assert_eq!(app.editor.text(), "retained operator draft");
    assert!(!sessions.matches(&app, &RunId("current".into()), generation));
}
#[test]
fn actual_shared_picker_rows_keep_recorded_and_live_provenance_distinct_in_terminal_frames() {
    let mut app = App::new();
    let mut sessions = Sessions::default();
    sessions.begin(&mut app, RunId("current".into()));
    sessions
        .page(&mut app, &page(&["current", "older"], None), false)
        .unwrap();
    sessions.activity(
        &mut app,
        &json!({"type":"activity_center_v1","thread_id":"thread","run_id":"current",
        "data":{"omitted":2,"activities":[{"target":{"kind":"process"},"state":{"kind":"running"},
        "owner_scope":{"kind":"resident_session","thread_id":"thread","creation_run_id":null}}]}}),
        &snapshot(),
    );
    let changes = json!({"type":"artifacts_v1","contract_version":1,
        "thread_id":"thread","run_id":"current","retained_catalog_available":true,
        "resident_artifact_ids":[],"evicted_artifacts":0,"artifacts":[{
            "artifact_id":"a".repeat(64),"schema":"iteron.file-diff.v1","mime_type":"application/json",
            "bytes":100,"complete":true,"source_event_seq":17,"required_capability":"read_only"}]});
    let retained = super::super::session_changes::Summary::capture(
        &changes,
        &snapshot().thread_id,
        &snapshot().run_id,
    )
    .unwrap();
    assert!(retained.label().contains("retained diff snapshots 1"));
    assert!(retained.label().contains("current workspace not scanned"));
    sessions.changes(&mut app, &changes, &snapshot());
    let picker = app.pickers.view().unwrap();
    assert!(picker.items[0].hint.contains("recorded done"));
    assert!(picker.items[0].hint.contains("resident session tasks 1"));
    assert!(picker.items[0].hint.contains("0 unresolved · 2 omitted"));
    assert!(!picker.items[0].hint.contains("retained diff snapshots"));
    assert!(!picker.items[1].hint.contains("resident session tasks"));
    let mut terminal = Terminal::new(TestBackend::new(180, 28)).unwrap();
    terminal
        .draw(|frame| crate::tui::draw(frame, &mut app))
        .unwrap();
    let frame = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(frame.contains(super::super::picker_owner::REMOTE_SESSION_TITLE));
    assert!(frame.contains("saved current"));
    sessions.activity(
        &mut app,
        &json!({"type":"activity_center_v1","thread_id":"foreign"}),
        &snapshot(),
    );
    assert!(
        app.pickers.view().unwrap().items[0]
            .hint
            .contains("live activity unavailable")
    );
}
#[test]
fn opaque_pagination_is_bounded_and_repair_restart_never_loop_indefinitely() {
    let mut app = App::new();
    let mut sessions = Sessions::default();
    sessions.begin(&mut app, RunId("current".into()));
    sessions
        .page(
            &mut app,
            &page(&["current"], Some("opaque.host.cursor")),
            false,
        )
        .unwrap();
    assert_eq!(
        sessions.next_page(&app).as_deref(),
        Some("opaque.host.cursor")
    );
    assert!(sessions.next_page(&app).is_none());
    sessions
        .page(&mut app, &page(&["current", "older"], None), true)
        .unwrap();
    assert_eq!(
        app.pickers.view().unwrap().items.len(),
        2,
        "duplicate page identity remains one row"
    );
    let repair = json!({"type":"thread_list_v1","index_ready":false,"rebuild_recommended":true});
    assert!(matches!(
        sessions.page(&mut app, &repair, false),
        Ok(Page::Repair)
    ));
    assert!(sessions.page(&mut app, &repair, false).is_err());
    let stale = json!({"type":"thread_list_v1","index_ready":true,"cursor_stale":true});
    assert!(matches!(
        sessions.page(&mut app, &stale, false),
        Ok(Page::Restart)
    ));
    assert!(sessions.page(&mut app, &stale, false).is_err());
    let old = sessions.generation();
    sessions.clear(&mut app);
    assert!(!sessions.matches(&app, &RunId("current".into()), old));
    assert!(!app.pickers.is_open());
}
