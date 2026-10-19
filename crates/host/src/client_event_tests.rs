use super::*;

fn workflow_variants() -> Vec<WorkflowUiEvent> {
    vec![
        WorkflowUiEvent::RunStarted {
            run_id: "wf-1".into(),
            name: "review".into(),
            class: "analysis".into(),
        },
        WorkflowUiEvent::PlanReady {
            run_id: "wf-1".into(),
            tasks: vec![WorkflowTaskUi {
                id: 3,
                label: "read the diff".into(),
            }],
            dropped: 1,
            duplicates_removed: 2,
            invalid_removed: 3,
            execution_mode: WorkflowExecutionModeUi::Concurrent,
            fan_turn_budget: 11,
            writer_turn_reserve: 4,
            fan_wall_secs: 600,
            writer_wall_reserve_secs: 120,
        },
        WorkflowUiEvent::PhaseChanged {
            run_id: "wf-1".into(),
            phase: WorkflowPhaseUi::Synthesizing,
        },
        WorkflowUiEvent::AgentStarted {
            run_id: "wf-1".into(),
            agent_id: 2,
            sub_run: "wf-1-a2".into(),
            turn_budget: 7,
        },
        WorkflowUiEvent::AgentActivity {
            run_id: "wf-1".into(),
            agent_id: 2,
            activity: "reading crates/cli".into(),
        },
        WorkflowUiEvent::AgentFinished {
            run_id: "wf-1".into(),
            agent_id: 2,
            outcome: WorkflowAgentOutcomeUi::SkippedBudget,
            turns: 5,
            tokens: 900,
            tool_calls: 12,
            elapsed_ms: 4321,
            summary_preview: Some("found three".into()),
            error_preview: None,
        },
        WorkflowUiEvent::RunFinished {
            run_id: "wf-1".into(),
            outcome: WorkflowRunOutcomeUi::Degraded,
            reason: Some("one lane failed".into()),
            elapsed_ms: 99_000,
            provider_attempts: 3,
            turns: 20,
            tokens: 55_555,
            tool_calls: 41,
            failed_tasks: 1,
            skipped_tasks: 2,
        },
    ]
}

/// Every `UiEvent` variant, with every field populated to something distinguishable.
fn ui_variants() -> Vec<UiEvent> {
    let mut all = vec![
        UiEvent::Text("hello".into()),
        UiEvent::Thinking("pondering".into()),
        UiEvent::ToolStart {
            id: "call_1".into(),
            name: "read_file".into(),
            args: serde_json::json!({"path": "notes.txt"}),
        },
        UiEvent::ToolEnd {
            id: "call_1".into(),
            ok: false,
            exit_code: Some(2),
            output: "boom".into(),
            diff: Some(FileDiff {
                path: "src/lib.rs".into(),
                adds: 4,
                dels: 1,
                hunks: Vec::new(),
            }),
        },
        UiEvent::Phase(Phase::Tools),
        UiEvent::TurnEnd {
            cost: iteron_obs::CostState::Unknown {
                reason: iteron_obs::CostUnknownReason::BillingEvidenceMissing,
            },
            usage: Usage {
                input: 10,
                output: 20,
                cache_creation: 30,
                cache_read: 40,
                thinking: 50,
            },
            context: iteron_ctx::ContextEstimate {
                system_tokens: 1,
                tool_tokens: 2,
                conversation_tokens: 3,
                tool_result_tokens: 0,
                lsp_result_tokens: 0,
                transcript_tokens: 3,
                framing_tokens: 4,
                total_tokens: 10,
                provenance: iteron_ctx::TokenEstimateProvenance::HeuristicBytesPerToken35,
                components: None,
            },
            model_context_window: Some(200_000),
            reserved_output_tokens: 8_192,
            compaction_trigger_tokens: 150_000,
            effort: iteron_provider::EffortApplication::BudgetBased {
                requested: ReasoningEffort::High,
                budget_tokens: 4_096,
            },
        },
        UiEvent::SteerApplied { count: 3 },
        UiEvent::Notice("heads up".into()),
        UiEvent::ApprovalRequest {
            id: iteron_protocol::SubmissionId(77),
            tool: "edit".into(),
            capability: Capability::TrustMutating,
            reason: "touches CLAUDE.md".into(),
            arguments: serde_json::json!({"path": "CLAUDE.md"}),
            workspace: "/repo".into(),
        },
        UiEvent::Done("done".into()),
    ];
    all.extend(workflow_variants().into_iter().map(UiEvent::Workflow));
    all
}

/// Every variant encodes and decodes with nothing dropped.
#[test]
fn every_variant_round_trips_through_the_envelope() {
    for event in ui_variants() {
        let wire = ClientEvent::from(&event);
        let encoded = serde_json::to_string(&ClientEventEnvelope::current(wire.clone()))
            .expect("the envelope encodes");
        let decoded: ClientEventEnvelope =
            serde_json::from_str(&encoded).expect("the envelope decodes");
        let back = decoded.into_current().expect("the version is current");
        assert_eq!(back, wire, "round trip changed the event: {encoded}");
    }
}

/// The four documented losses, asserted field by field rather than by variant count.
#[test]
fn the_four_documented_losses_survive_a_round_trip() {
    let turn_end = ui_variants()
        .into_iter()
        .find(|event| matches!(event, UiEvent::TurnEnd { .. }))
        .expect("the fixture carries TurnEnd");
    let ClientEvent::TurnEnd {
        cost,
        usage,
        context,
        model_context_window,
        reserved_output_tokens,
        compaction_trigger_tokens,
        effort,
    } = ClientEvent::from(&turn_end)
    else {
        panic!("TurnEnd did not map to TurnEnd");
    };
    // All seven, not one.
    assert_eq!(
        cost,
        ClientCost::Unknown {
            reason: "billing_evidence_missing".into()
        }
    );
    assert_eq!(usage.thinking, 50);
    assert_eq!(context.total_tokens, 10);
    assert_eq!(model_context_window, Some(200_000));
    assert_eq!(reserved_output_tokens, 8_192);
    assert_eq!(compaction_trigger_tokens, 150_000);
    assert_eq!(
        effort,
        ClientEffortApplication::BudgetBased {
            requested: ReasoningEffort::High,
            budget_tokens: 4_096
        }
    );

    // SteerApplied.count — the variant that had no counterpart at all.
    assert_eq!(
        ClientEvent::from(&UiEvent::SteerApplied { count: 3 }),
        ClientEvent::SteerApplied { count: 3 }
    );

    // ToolEnd.diff — the field that had no home.
    let tool_end = ui_variants()
        .into_iter()
        .find(|event| matches!(event, UiEvent::ToolEnd { .. }))
        .expect("the fixture carries ToolEnd");
    let ClientEvent::ToolEnd { diff, .. } = ClientEvent::from(&tool_end) else {
        panic!("ToolEnd did not map to ToolEnd");
    };
    assert_eq!(diff.expect("the diff survives").adds, 4);

    // ApprovalRequest.reason — the operator-facing justification.
    let approval = ui_variants()
        .into_iter()
        .find(|event| matches!(event, UiEvent::ApprovalRequest { .. }))
        .expect("the fixture carries ApprovalRequest");
    let ClientEvent::ApprovalRequest {
        reason, capability, ..
    } = ClientEvent::from(&approval)
    else {
        panic!("ApprovalRequest did not map to ApprovalRequest");
    };
    assert_eq!(reason, "touches CLAUDE.md");
    assert_eq!(capability, Capability::TrustMutating);
}

/// All seven workflow variants, named individually so a dropped one is visible in the failure.
#[test]
fn all_seven_workflow_variants_have_a_wire_form() {
    let tags: Vec<String> = workflow_variants()
        .iter()
        .map(|event| {
            let value = serde_json::to_value(ClientWorkflowEvent::from(event)).unwrap();
            value["kind"].as_str().expect("tagged").to_owned()
        })
        .collect();
    assert_eq!(
        tags,
        vec![
            "run_started",
            "plan_ready",
            "phase_changed",
            "agent_started",
            "agent_activity",
            "agent_finished",
            "run_finished",
        ]
    );
}

/// Skew is a typed refusal before decoding, not a decode failure a caller has to interpret.
#[test]
fn version_skew_is_refused_with_a_typed_error() {
    let event = ClientEvent::Text {
        text: "hi".to_owned(),
    };
    let skewed = ClientEventEnvelope::with_version(PROTOCOL_VERSION + 1, event.clone());
    let encoded = serde_json::to_string(&skewed).unwrap();
    // It decodes as a document — the refusal is about the version, not about the bytes.
    let decoded: ClientEventEnvelope = serde_json::from_str(&encoded).unwrap();
    let error = decoded.into_current().unwrap_err();
    assert_eq!(error.expected, PROTOCOL_VERSION);
    assert_eq!(error.actual, PROTOCOL_VERSION + 1);

    assert_eq!(
        ClientEventEnvelope::current(event.clone())
            .into_current()
            .unwrap(),
        event
    );
}

/// Golden JSON. A breaking diff to any variant's shape shows up here as a failing assertion.
#[test]
fn the_wire_shape_of_every_variant_is_pinned() {
    let mut pinned = Vec::new();
    for event in ui_variants() {
        let value = serde_json::to_value(ClientEvent::from(&event)).unwrap();
        pinned.push(
            value["kind"]
                .as_str()
                .expect("every variant is tagged")
                .to_owned(),
        );
    }
    assert_eq!(
        pinned,
        vec![
            "text",
            "thinking",
            "tool_start",
            "tool_end",
            "phase",
            "turn_end",
            "steer_applied",
            "notice",
            "approval_request",
            "done",
            "workflow",
            "workflow",
            "workflow",
            "workflow",
            "workflow",
            "workflow",
            "workflow",
        ],
        "a variant was added, removed, or renamed without updating the pinned wire shape"
    );

    // One full document, pinned exactly, so a field rename cannot pass as a tag-only change.
    let steer = serde_json::to_string(&ClientEventEnvelope::current(ClientEvent::SteerApplied {
        count: 3,
    }))
    .unwrap();
    assert_eq!(
        steer,
        format!(
            r#"{{"protocol_version":{PROTOCOL_VERSION},"event":{{"kind":"steer_applied","count":3}}}}"#
        )
    );
}

/// Cost is state, not a number: `Zero`, `Known` and `Unknown` stay distinguishable on the wire.
#[test]
fn cost_keeps_its_three_states_apart() {
    assert_eq!(
        ClientCost::from(&iteron_obs::CostState::Zero),
        ClientCost::Zero
    );
    assert_eq!(
        ClientCost::from(&iteron_obs::CostState::Unknown {
            reason: iteron_obs::CostUnknownReason::NoVerifiedRateCard
        }),
        ClientCost::Unknown {
            reason: "no_verified_rate_card".into()
        }
    );
    let known = iteron_obs::CostState::Known {
        amount_microusd: 1_500_000,
        rate_card_digest: "sha256:abc".into(),
    };
    assert_eq!(ClientCost::from(&known), ClientCost::Known { usd: 1.5 });
}

/// The client half of #78: a run declaring a product, on the same vocabulary a socket consumes.
#[test]
fn an_artifact_declaration_round_trips_on_the_client_vocabulary() {
    use iteron_protocol::artifact::{ArtifactRef, ArtifactSchema, Producer, Provenance};
    let declared = ArtifactRef {
        hash: format!("{:064x}", 1),
        schema: ArtifactSchema::FileDiff,
        producer: Producer::Tool {
            tool: "edit".into(),
        },
        provenance: Provenance {
            run_id: iteron_protocol::RunId("run-1".into()),
            parent_hashes: Vec::new(),
            effect_id: None,
        },
        permissions: iteron_protocol::capability_set::CapabilitySet::only(Capability::ReadOnly),
        locator: "reports/summary.md".into(),
    };
    let event = ClientEvent::from(&declared);
    let encoded = serde_json::to_string(&ClientEventEnvelope::current(event.clone())).unwrap();
    let decoded: ClientEventEnvelope = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded.into_current().unwrap(), event);

    let value = serde_json::to_value(&event).unwrap();
    assert_eq!(value["kind"], "artifact_produced");
    // The content address is what makes the product resolvable; it must survive verbatim.
    assert_eq!(value["artifact"]["hash"], declared.hash);
}
