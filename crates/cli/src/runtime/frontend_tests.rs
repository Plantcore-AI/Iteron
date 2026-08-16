use super::*;

#[test]
fn saturation_preserves_structural_order_and_only_omits_stream_bytes() {
    let health = FrontendChannelHealth::default();
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    assert!(health.try_send_ui(&tx, UiEvent::Text("before".into())));

    let structural = UiEvent::ToolStart {
        id: "tool-1".into(),
        name: "read".into(),
        args: serde_json::json!({"path": "bounded"}),
    };
    assert!(
        health.try_send_ui(&tx, structural),
        "structural saturation is preserved, not reported as a failed send"
    );
    assert!(
        !health.try_send_ui(&tx, UiEvent::Thinking("reconciled later".into())),
        "stream bytes may be omitted while structural order is pending"
    );

    assert!(matches!(rx.try_recv(), Ok(UiEvent::Text(text)) if text == "before"));
    assert!(matches!(
        health.try_pop_authoritative(),
        Some(UiEvent::ToolStart { id, .. }) if id == "tool-1"
    ));
    assert!(health.try_pop_authoritative().is_none());
    health.release_ui_event(&UiEvent::Text("before".into()));
    health.release_ui_event(&UiEvent::ToolStart {
        id: "tool-1".into(),
        name: "read".into(),
        args: serde_json::json!({"path": "bounded"}),
    });
    assert_eq!(health.ui_saturation_count(), 2);
    assert_eq!(health.ui_bytes.used(), 0);
}

#[test]
fn one_byte_budget_bounds_both_runtime_ui_lanes_together() {
    let health = FrontendChannelHealth {
        ui_bytes: std::sync::Arc::new(FrontendUiByteBudget::new(2_500)),
        ..FrontendChannelHealth::default()
    };
    health.ui_bytes.enable();
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let first = UiEvent::Text("x".repeat(600));
    assert!(health.try_send_ui(&tx, first));
    let structural = UiEvent::ToolStart {
        id: "tool-1".into(),
        name: "read".into(),
        args: serde_json::json!({"path": "bounded"}),
    };
    assert!(health.try_send_ui(&tx, structural));
    assert!(
        !health.try_send_ui(&tx, UiEvent::Thinking("y".repeat(600))),
        "a variable payload cannot exceed the byte ceiling shared with structural overflow"
    );

    let delivered = rx.try_recv().unwrap();
    health.release_ui_event(&delivered);
    let delivered = health.try_pop_authoritative().unwrap();
    health.release_ui_event(&delivered);
    assert_eq!(health.ui_bytes.used(), 0);
}

#[test]
fn same_task_structural_saturation_returns_instead_of_waiting_for_its_consumer() {
    let health = FrontendChannelHealth::default();
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    assert!(health.try_send_ui(&tx, UiEvent::Done("channel".into())));

    for sequence in 0..authoritative_ui_backlog_capacity() {
        assert!(health.try_send_ui(
            &tx,
            UiEvent::ToolStart {
                id: format!("overflow-{sequence}"),
                name: "read".into(),
                args: serde_json::json!({}),
            },
        ));
    }
    assert!(
        !health.try_send_ui(
            &tx,
            UiEvent::ToolStart {
                id: "exact-refusal".into(),
                name: "read".into(),
                args: serde_json::json!({}),
            },
        ),
        "a producer sharing the consumer task must fail fast at the hard ceiling"
    );
    assert!(
        health.take_structural_refusal(),
        "an ignored provider callback return still leaves a fail-stop receipt"
    );
}

#[test]
fn a_single_event_larger_than_the_shared_budget_is_exactly_refused() {
    let health = FrontendChannelHealth {
        ui_bytes: std::sync::Arc::new(FrontendUiByteBudget::new(1_024)),
        ..FrontendChannelHealth::default()
    };
    health.ui_bytes.enable();
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    assert!(!health.try_send_ui(&tx, UiEvent::Done("x".repeat(1_024))));
    assert!(
        !health.take_structural_refusal(),
        "RunEnded reconciles the final Done projection"
    );
    assert_eq!(health.ui_bytes.used(), 0);
}
