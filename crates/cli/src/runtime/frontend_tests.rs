use super::*;

#[test]
fn oversized_stream_delta_is_split_into_v7_safe_utf8_events_without_data_loss() {
    let health = FrontendChannelHealth::default();
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let original = "🙂\\".repeat(3_000);

    assert!(health.try_send_ui(&tx, UiEvent::Text(original.clone())));
    drop(tx);

    let mut reassembled = String::new();
    let mut turn = 0;
    while let Ok(event) = rx.try_recv() {
        let UiEvent::Text(fragment) = &event else {
            panic!("stream splitter must preserve the event kind")
        };
        assert!(fragment.len() <= crate::machine_projection::max_stream_ui_delta_bytes());
        reassembled.push_str(fragment);
        crate::machine_projection::stream_event_for_schema(
            event,
            &mut turn,
            crate::machine_projection::V7_SCHEMA_VERSION,
        )
        .expect("every emitted fragment fits one canonical v7 logical object");
    }
    assert_eq!(reassembled, original);
}

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
        Some(RuntimeFrontendEvent::Ui(UiEvent::ToolStart { id, .. })) if id == "tool-1"
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
fn resident_ingress_preserves_ui_and_plantcore_order_across_overflow() {
    let health = FrontendChannelHealth::default();
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    assert!(health.try_send_runtime(
        &tx,
        RuntimeFrontendEvent::Ui(UiEvent::Text("before".into())),
    ));
    assert!(health.try_send_runtime(
        &tx,
        RuntimeFrontendEvent::Plantcore(PlantcoreUiEvent::RunAdmitted {
            profile_digest_sha256: iteron_protocol::HexSha256::digest(b"profile"),
        }),
    ));
    assert!(health.try_send_runtime(&tx, RuntimeFrontendEvent::Ui(UiEvent::Text("after".into())),));

    assert!(matches!(
        rx.try_recv(),
        Ok(RuntimeFrontendEvent::Ui(UiEvent::Text(text))) if text == "before"
    ));
    assert!(matches!(
        health.try_pop_authoritative(),
        Some(RuntimeFrontendEvent::Plantcore(
            PlantcoreUiEvent::RunAdmitted { .. }
        ))
    ));
    assert!(matches!(
        health.try_pop_authoritative(),
        Some(RuntimeFrontendEvent::Ui(UiEvent::Text(text))) if text == "after"
    ));
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
    health.release_ui_bytes(health.runtime_event_bytes(&delivered));
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

#[test]
fn confirmed_final_evidence_refusal_does_not_poison_the_run_or_leak_queue_bytes() {
    use iteron_protocol::final_evidence::{
        HostConfiguredCheckV1, HostFinalCoverageV1, HostFinalEvidenceV1,
    };
    let fact = HostFinalEvidenceV1 {
        tenant: iteron_protocol::TenantId::default(),
        run_id: iteron_protocol::RunId("retained-run".into()),
        first_turn: iteron_protocol::TurnId(0),
        final_turn: iteron_protocol::TurnId(0),
        source_seq: iteron_protocol::Seq(9),
        observed_tool_completions: 0,
        observed_tool_failures: 0,
        configured_check: HostConfiguredCheckV1::NotObserved,
        configured_check_source_seq: None,
        effects_known: true,
        write_capable_effect_admitted: false,
        coverage: HostFinalCoverageV1::LiveInvocation,
        workspace_diff_inspected: false,
        test_suite_identity_verified: false,
        correction: None,
    };
    // Real byte admission refuses the observation while the independently retained host
    // receipt remains unchanged. This presentation-only refusal must not alter Done.
    let health = FrontendChannelHealth {
        ui_bytes: std::sync::Arc::new(FrontendUiByteBudget::new(1)),
        ..FrontendChannelHealth::default()
    };
    health.ui_bytes.enable();
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    assert!(!health.try_send_runtime(&tx, RuntimeFrontendEvent::HostFinalEvidence(fact.clone())));
    assert!(!health.take_structural_refusal());
    assert_eq!(health.ui_bytes.used(), 0);
    assert_eq!(fact.source_seq, iteron_protocol::Seq(9));
    drop(rx);
    let health = FrontendChannelHealth::default();
    assert!(!health.try_send_runtime(&tx, RuntimeFrontendEvent::HostFinalEvidence(fact)));
    assert!(!health.take_structural_refusal());
}

#[test]
fn native_refusal_presentation_failure_does_not_change_the_run_or_authority() {
    use iteron_protocol::refusal::{HostRefusalV1, RefusalReasonV1};
    let refusal = HostRefusalV1::unscoped(RefusalReasonV1::SandboxUnavailable);
    let health = FrontendChannelHealth {
        ui_bytes: std::sync::Arc::new(FrontendUiByteBudget::new(1)),
        ..FrontendChannelHealth::default()
    };
    health.ui_bytes.enable();
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    assert!(!health.try_send_runtime(&tx, RuntimeFrontendEvent::Refusal(refusal.clone())));
    assert!(!health.take_structural_refusal());
    assert_eq!(health.ui_bytes.used(), 0);
    assert!(refusal.source.is_none());
    drop(rx);
    let health = FrontendChannelHealth::default();
    assert!(!health.try_send_runtime(&tx, RuntimeFrontendEvent::Refusal(refusal)));
    assert!(!health.take_structural_refusal());
}
