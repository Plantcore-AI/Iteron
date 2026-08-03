use super::*;
use crate::{CostState, CostUnknownReason, Ledger};
use core_protocol::{
    CostAttribution, CostProjectionIdentity, EffectId, Event, EventKind, RunId, Seq, TenantId,
    ToolResult, Trust, TurnId, WorkflowCostEvidence, WorkflowMetrics,
};
use std::sync::Arc;

const NOW: u64 = 1_800_000_000;
const TENANT: &str = "tenant-a";
const RUN: &str = "run-a";

fn identity(
    run_id: &str,
    turn_id: u32,
    provider_attempt: u32,
    attribution: Option<CostAttribution>,
) -> CostProjectionIdentity {
    CostProjectionIdentity {
        tenant_id: TENANT.into(),
        run_id: run_id.into(),
        turn_id,
        provider_attempt,
        attribution,
    }
}

fn local_identity() -> CostProjectionIdentity {
    identity(RUN, 0, 1, None)
}

fn direct_identity(sub_run: &str) -> CostProjectionIdentity {
    identity(
        sub_run,
        0,
        1,
        Some(CostAttribution::DirectSubagent {
            parent_run_id: RUN.into(),
            sub_run: sub_run.into(),
        }),
    )
}

fn workflow_identity(workflow_id: &str, task_id: u32, sub_run: &str) -> CostProjectionIdentity {
    identity(
        sub_run,
        0,
        1,
        Some(CostAttribution::WorkflowChild {
            parent_run_id: RUN.into(),
            workflow_id: workflow_id.into(),
            task_id,
            sub_run: sub_run.into(),
        }),
    )
}

fn event_at(turn: u32, kind: EventKind) -> Event {
    Event {
        seq: Seq::ZERO,
        turn: TurnId(turn),
        kind,
    }
}

fn event(kind: EventKind) -> Event {
    event_at(0, kind)
}

fn observe(
    replay: &mut PricingReplay,
    event: &Event,
    ledger: &mut Ledger,
) -> Result<(), PricingError> {
    replay.observe(event, &TenantId(TENANT.into()), &RunId(RUN.into()), ledger)
}

fn route() -> PricingRoute {
    PricingRoute {
        provider_id: "provider-a".into(),
        model_id: "model-a".into(),
        catalog_digest: format!("sha256:{}", "a".repeat(64)),
        capability_digest: format!("sha256:{}", "b".repeat(64)),
    }
}

#[test]
fn replay_reconstructs_only_durable_counters_and_marks_wall_time_unknown() {
    let usage = Usage {
        input: 13,
        output: 5,
        cache_creation: 2,
        cache_read: 8,
        thinking: 3,
    };
    let results = [
        ToolResult {
            tool_use_id: "read-ok".into(),
            content: "ok".into(),
            is_error: false,
            trust: Trust::Workspace,
            latency_ms: 17,
        },
        ToolResult {
            tool_use_id: "read-error".into(),
            content: "failed".into(),
            is_error: true,
            trust: Trust::Workspace,
            latency_ms: 29,
        },
    ];

    let mut live = Ledger::new();
    live.phase_context(11);
    live.attempt();
    live.turn(&usage, 23);
    live.tool(results[0].latency_ms, 7, results[0].is_error);
    live.tool(results[1].latency_ms, 0, results[1].is_error);
    live.tool(41, 0, true);
    live.phase_tools(31);
    live.phase_verify(37);
    let live_bytes = serde_json::to_vec(&live.reproducible_counters()).unwrap();

    let mut replay = PricingReplay::default();
    let mut restored = Ledger::new();
    for event in [
        event(EventKind::TurnStart),
        event(EventKind::TurnEnd {
            usage,
            ttft_ms: None,
            decode_ms: None,
            stream_items: None,
        }),
        event(EventKind::ToolDone {
            result: results[0].clone(),
            effect_id: None,
            tool: Some("read_file".into()),
        }),
        event(EventKind::ToolDone {
            result: results[1].clone(),
            effect_id: None,
            tool: Some("edit".into()),
        }),
        event(EventKind::EffectUnknown {
            id: EffectId("unknown-effect".into()),
            tool: "remote_write".into(),
            reason: "typed fixture".into(),
        }),
    ] {
        observe(&mut replay, &event, &mut restored).unwrap();
    }

    assert_eq!(
        serde_json::to_vec(&restored.reproducible_counters()).unwrap(),
        live_bytes,
        "tokens, admitted attempts, completed turns, and tool outcomes are replay-derived"
    );
    assert!(matches!(
        restored.timings(),
        crate::TimingSnapshot::UnknownAfterReplay { observed_partial }
            if observed_partial == crate::EphemeralTimings::default()
    ));
    assert!(restored.summary().contains("timing=unknown_after_replay"));
    assert!(!restored.summary().contains("phase_ms context=0"));
    assert_eq!(restored.attributed_phase_ms(), None);
    let workflow = restored.workflow_metrics();
    assert_eq!(workflow.model_ms, None);
    assert_eq!(workflow.tools_ms, None);

    let mut restored_child = Ledger::new();
    restored_child.merge_workflow_metrics(&WorkflowMetrics {
        provider_attempts: 1,
        completed_turns: 1,
        usage,
        tool_calls: 1,
        tool_errors: 0,
        model_ms: Some(91),
        tools_ms: Some(17),
        cost: None,
    });
    assert!(matches!(
        restored_child.timings(),
        crate::TimingSnapshot::UnknownAfterReplay { .. }
    ));
    assert_eq!(restored_child.attributed_phase_ms(), None);
}

fn card() -> RateCard {
    RateCard {
        version: PricingVersion::V1,
        route: route(),
        provenance: "operator-manifest@v7".into(),
        issued_at_unix_secs: NOW - 60,
        expires_at_unix_secs: NOW + 60,
        rates: TokenRateCard {
            input_microusd_per_million: 1_000_000,
            output_microusd_per_million: 2_000_000,
            cache_creation_microusd_per_million: 1_250_000,
            cache_read_microusd_per_million: 100_000,
            thinking_microusd_per_million: 3_000_000,
        },
    }
}

fn authority(key: [u8; 32]) -> (Arc<HmacPricingAuthority>, SignedRateCard) {
    let signed = sign_rate_card(card(), "pricing-root-v1", key).unwrap();
    let authority =
        HmacPricingAuthority::new(vec![(signed.clone(), HmacPricingKey::from_bytes(key))]).unwrap();
    (Arc::new(authority), signed)
}

#[test]
fn trusted_card_is_full_route_bound_and_tamper_evident() {
    let key = [7; 32];
    let signed = sign_rate_card(card(), "pricing-root-v1", key).unwrap();
    let trusted =
        HmacPricingAuthority::new(vec![(signed.clone(), HmacPricingKey::from_bytes(key))]).unwrap();
    assert_eq!(
        trusted.resolve_rate_card(&route(), NOW).unwrap(),
        Some(signed.clone())
    );

    let mut tampered = signed;
    tampered.rate_card.route.capability_digest = format!("sha256:{}", "c".repeat(64));
    assert_eq!(
        trusted.verify_rate_card(&tampered).unwrap_err(),
        PricingError::DigestMismatch
    );
}

#[test]
fn signed_rate_card_rejects_missing_route_provenance_digests() {
    let mut missing_catalog = card();
    missing_catalog.route.catalog_digest.clear();
    assert_eq!(
        sign_rate_card(missing_catalog, "pricing-root-v1", [6; 32]).unwrap_err(),
        PricingError::InvalidField("catalog_digest")
    );

    let mut missing_capability = card();
    missing_capability.route.capability_digest.clear();
    assert_eq!(
        sign_rate_card(missing_capability, "pricing-root-v1", [6; 32]).unwrap_err(),
        PricingError::InvalidField("capability_digest")
    );
}

#[test]
fn stale_and_overlapping_cards_are_rejected_for_live_resolution() {
    let key = [8; 32];
    let mut stale = card();
    stale.issued_at_unix_secs = NOW - 120;
    stale.expires_at_unix_secs = NOW;
    let stale = sign_rate_card(stale, "pricing-root-v1", key).unwrap();
    let authority =
        HmacPricingAuthority::new(vec![(stale, HmacPricingKey::from_bytes(key))]).unwrap();
    assert_eq!(
        authority.resolve_rate_card(&route(), NOW).unwrap_err(),
        PricingError::RateCardExpired
    );

    let first = sign_rate_card(card(), "pricing-root-v1", key).unwrap();
    let mut second_card = card();
    second_card.provenance = "operator-manifest@v8".into();
    let second = sign_rate_card(second_card, "pricing-root-v1", key).unwrap();
    let overlapping = HmacPricingAuthority::new(vec![
        (first, HmacPricingKey::from_bytes(key)),
        (second, HmacPricingKey::from_bytes(key)),
    ])
    .unwrap();
    assert_eq!(
        overlapping.resolve_rate_card(&route(), NOW).unwrap_err(),
        PricingError::AmbiguousRateCard
    );
}

#[test]
fn projection_is_fixed_point_ceil_rounded_and_hmac_verified() {
    let key = [9; 32];
    let (trusted, signed) = authority(key);
    let projection = trusted
        .project(
            &signed,
            local_identity(),
            Usage {
                input: 1,
                output: 3,
                cache_creation: 1,
                cache_read: 1,
                thinking: 1,
            },
            NOW,
        )
        .unwrap();
    assert_eq!(projection.amount_microusd, 11);
    trusted.verify_projection(&signed, &projection).unwrap();

    let mut forged = projection;
    forged.signature = format!("hmac-sha256:{}", "0".repeat(64));
    assert_eq!(
        trusted.verify_projection(&signed, &forged).unwrap_err(),
        PricingError::SignatureMismatch
    );
}

#[test]
fn pricing_replay_matches_the_committed_golden() {
    let key = [9; 32];
    let (trusted, signed) = authority(key);
    let usage = Usage {
        input: 1,
        output: 3,
        cache_creation: 1,
        cache_read: 1,
        thinking: 1,
    };
    let projection = trusted
        .project(&signed, local_identity(), usage, NOW)
        .unwrap();
    let events = [
        event(EventKind::ModelSelected {
            provider_id: route().provider_id,
            model_id: route().model_id,
            catalog_digest: route().catalog_digest,
            capability_digest: route().capability_digest,
        }),
        event(EventKind::RateCardBound {
            rate_card: signed.clone(),
        }),
        event(EventKind::TurnStart),
        event(EventKind::TurnEnd {
            usage,
            ttft_ms: None,
            decode_ms: None,
            stream_items: None,
        }),
        event(EventKind::CostProjected {
            projection: projection.clone(),
        }),
    ];
    let mut replay = PricingReplay::trusted(trusted);
    let mut ledger = Ledger::new();
    for event in &events {
        observe(&mut replay, event, &mut ledger).unwrap();
    }
    let actual = serde_json::json!({
        "schema_version": 1,
        "cost_state": ledger.cost_state(),
        "projection_amount_microusd": projection.amount_microusd,
        "rate_card_digest": projection.rate_card_digest,
    });
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/pricing-replay-golden-v1.json"
    ))
    .unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn projection_amount_overflow_is_typed_instead_of_clamped_known() {
    let key = [24; 32];
    let mut overflow_card = card();
    overflow_card.rates.input_microusd_per_million = u64::MAX;
    let signed = sign_rate_card(overflow_card, "pricing-root-v1", key).unwrap();
    let authority =
        HmacPricingAuthority::new(vec![(signed.clone(), HmacPricingKey::from_bytes(key))]).unwrap();
    assert_eq!(
        authority
            .project(
                &signed,
                local_identity(),
                Usage {
                    input: u64::MAX,
                    ..Usage::default()
                },
                NOW,
            )
            .unwrap_err(),
        PricingError::AmountOverflow
    );
}

#[test]
fn signed_workflow_aggregate_overflow_degrades_to_unknown() {
    let key = [25; 32];
    let mut large_card = card();
    large_card.rates = TokenRateCard {
        input_microusd_per_million: u64::MAX,
        output_microusd_per_million: 0,
        cache_creation_microusd_per_million: 0,
        cache_read_microusd_per_million: 0,
        thinking_microusd_per_million: 0,
    };
    let signed = sign_rate_card(large_card, "pricing-root-v1", key).unwrap();
    let authority = Arc::new(
        HmacPricingAuthority::new(vec![(signed.clone(), HmacPricingKey::from_bytes(key))]).unwrap(),
    );
    let usage = Usage {
        input: 600_000,
        ..Usage::default()
    };
    let attribution = CostAttribution::DirectSubagent {
        parent_run_id: RUN.into(),
        sub_run: "overflow-child".into(),
    };
    let first = authority
        .project(
            &signed,
            identity("overflow-child", 0, 1, Some(attribution.clone())),
            usage,
            NOW,
        )
        .unwrap();
    let second = authority
        .project(
            &signed,
            identity("overflow-child", 1, 2, Some(attribution)),
            usage,
            NOW,
        )
        .unwrap();
    assert!(
        first
            .amount_microusd
            .checked_add(second.amount_microusd)
            .is_none()
    );
    let mut total_usage = usage;
    total_usage.add(&usage);
    let terminal = event(EventKind::SubagentFinishedV2 {
        version: core_protocol::WorkflowEventVersion::V2,
        sub_run: "overflow-child".into(),
        outcome: core_protocol::WorkflowChildOutcome::Done,
        metrics: WorkflowMetrics {
            provider_attempts: 2,
            completed_turns: 2,
            usage: total_usage,
            cost: Some(WorkflowCostEvidence {
                amount_microusd: u64::MAX,
                rate_card_digest: signed.rate_card_digest,
                projections: vec![first, second],
            }),
            ..WorkflowMetrics::default()
        },
        error_code: None,
        error_detail: None,
        summary_digest: None,
        evidence_bytes: 0,
    });
    let mut replay = PricingReplay::trusted(authority);
    let mut ledger = Ledger::new();
    observe(&mut replay, &terminal, &mut ledger).unwrap();
    assert_eq!(
        ledger.cost_state(),
        CostState::Unknown {
            reason: CostUnknownReason::AmountOverflow,
        }
    );
}

#[test]
fn replay_requires_trust_both_hmacs_and_adjacency() {
    let key = [11; 32];
    let (trusted, signed) = authority(key);
    let usage = Usage {
        input: 10,
        output: 5,
        ..Usage::default()
    };
    let projection = trusted
        .project(&signed, local_identity(), usage, NOW)
        .unwrap();
    let selection = EventKind::ModelSelected {
        provider_id: route().provider_id,
        model_id: route().model_id,
        catalog_digest: route().catalog_digest,
        capability_digest: route().capability_digest,
    };
    let events = [
        event(selection),
        event(EventKind::RateCardBound {
            rate_card: signed.clone(),
        }),
        event(EventKind::TurnStart),
        event(EventKind::TurnEnd {
            usage,
            ttft_ms: None,
            decode_ms: None,
            stream_items: None,
        }),
        event(EventKind::CostProjected {
            projection: projection.clone(),
        }),
    ];

    let mut trusted_ledger = Ledger::new();
    let mut trusted_replay = PricingReplay::trusted(trusted);
    for event in &events {
        observe(&mut trusted_replay, event, &mut trusted_ledger).unwrap();
    }
    assert!(matches!(
        trusted_ledger.cost_state(),
        CostState::Known { .. }
    ));

    let mut untrusted_ledger = Ledger::new();
    let mut untrusted_replay = PricingReplay::default();
    for event in &events {
        observe(&mut untrusted_replay, event, &mut untrusted_ledger).unwrap();
    }
    assert_eq!(
        untrusted_ledger.cost_state(),
        CostState::Unknown {
            reason: CostUnknownReason::NoVerifiedRateCard,
        }
    );

    let mut forged_events = events;
    if let EventKind::CostProjected { projection } = &mut forged_events[4].kind {
        projection.signature = format!("hmac-sha256:{}", "0".repeat(64));
    }
    let (authority, _) = authority(key);
    let mut forged_replay = PricingReplay::trusted(authority);
    let mut forged_ledger = Ledger::new();
    let error = forged_events
        .iter()
        .find_map(|event| observe(&mut forged_replay, event, &mut forged_ledger).err())
        .unwrap();
    assert_eq!(error, PricingError::SignatureMismatch);
}

#[test]
fn duplicate_local_projection_occurrence_is_rejected_without_double_charge() {
    let key = [26; 32];
    let (authority, signed) = authority(key);
    let usage = Usage {
        input: 10,
        output: 5,
        ..Usage::default()
    };
    let projection = authority
        .project(&signed, local_identity(), usage, NOW)
        .unwrap();
    let prefix = [
        event(EventKind::ModelSelected {
            provider_id: route().provider_id,
            model_id: route().model_id,
            catalog_digest: route().catalog_digest,
            capability_digest: route().capability_digest,
        }),
        event(EventKind::RateCardBound { rate_card: signed }),
        event(EventKind::TurnStart),
        event(EventKind::TurnEnd {
            usage,
            ttft_ms: None,
            decode_ms: None,
            stream_items: None,
        }),
        event(EventKind::CostProjected {
            projection: projection.clone(),
        }),
    ];
    let mut replay = PricingReplay::trusted(authority);
    let mut ledger = Ledger::new();
    for event in &prefix {
        observe(&mut replay, event, &mut ledger).unwrap();
    }
    let charged_once = ledger.amount_microusd;
    assert_eq!(ledger.cost_projections.len(), 1);

    // No second TurnStart means provider_attempt remains 1, reproducing the original identity
    // collision exactly. The duplicate projection must be consumed only once.
    observe(
        &mut replay,
        &event(EventKind::TurnEnd {
            usage,
            ttft_ms: None,
            decode_ms: None,
            stream_items: None,
        }),
        &mut ledger,
    )
    .unwrap();
    assert_eq!(
        observe(
            &mut replay,
            &event(EventKind::CostProjected { projection }),
            &mut ledger,
        )
        .unwrap_err(),
        PricingError::DuplicateProjection
    );
    assert_eq!(ledger.provider_attempts, 1);
    assert_eq!(ledger.turns, 2);
    assert_eq!(ledger.amount_microusd, charged_once);
    assert_eq!(ledger.cost_projections.len(), 1);
    assert!(matches!(ledger.cost_state(), CostState::Unknown { .. }));
}

#[test]
fn provider_turn_identity_is_bound_to_the_exact_open_turn_and_attempt() {
    let key = [28; 32];
    let (authority, signed) = authority(key);
    let usage = Usage {
        input: 3,
        output: 2,
        ..Usage::default()
    };
    let projection = authority
        .project(&signed, identity(RUN, 1, 1, None), usage, NOW)
        .unwrap();
    let events = [
        event(EventKind::ModelSelected {
            provider_id: route().provider_id,
            model_id: route().model_id,
            catalog_digest: route().catalog_digest,
            capability_digest: route().capability_digest,
        }),
        event(EventKind::RateCardBound { rate_card: signed }),
        event_at(0, EventKind::TurnStart),
        event_at(
            1,
            EventKind::TurnEnd {
                usage,
                ttft_ms: None,
                decode_ms: None,
                stream_items: None,
            },
        ),
        event_at(1, EventKind::CostProjected { projection }),
    ];
    let mut replay = PricingReplay::trusted(authority);
    let mut ledger = Ledger::new();
    let error = events
        .iter()
        .find_map(|event| observe(&mut replay, event, &mut ledger).err())
        .unwrap();
    assert_eq!(error, PricingError::ProjectionNotAdjacent);
    assert!(!matches!(ledger.cost_state(), CostState::Known { .. }));
}

#[test]
fn one_start_cannot_price_two_turn_ends_with_the_same_attempt_number() {
    let key = [29; 32];
    let (authority, signed) = authority(key);
    let usage = Usage {
        input: 3,
        output: 2,
        ..Usage::default()
    };
    let first = authority
        .project(&signed, identity(RUN, 0, 1, None), usage, NOW)
        .unwrap();
    let second = authority
        .project(&signed, identity(RUN, 1, 1, None), usage, NOW)
        .unwrap();
    let mut replay = PricingReplay::trusted(authority);
    let mut ledger = Ledger::new();
    for event in [
        event(EventKind::ModelSelected {
            provider_id: route().provider_id,
            model_id: route().model_id,
            catalog_digest: route().catalog_digest,
            capability_digest: route().capability_digest,
        }),
        event(EventKind::RateCardBound { rate_card: signed }),
        event_at(0, EventKind::TurnStart),
        event_at(
            0,
            EventKind::TurnEnd {
                usage,
                ttft_ms: None,
                decode_ms: None,
                stream_items: None,
            },
        ),
        event_at(0, EventKind::CostProjected { projection: first }),
        event_at(
            1,
            EventKind::TurnEnd {
                usage,
                ttft_ms: None,
                decode_ms: None,
                stream_items: None,
            },
        ),
    ] {
        observe(&mut replay, &event, &mut ledger).unwrap();
    }
    assert_eq!(
        observe(
            &mut replay,
            &event_at(1, EventKind::CostProjected { projection: second }),
            &mut ledger,
        )
        .unwrap_err(),
        PricingError::ProjectionNotAdjacent
    );
    assert_eq!(ledger.provider_attempts, 1);
    assert_eq!(ledger.turns, 2);
    assert_eq!(
        ledger.cost_state(),
        CostState::Unknown {
            reason: CostUnknownReason::BillingEvidenceMissing,
        }
    );
}

#[test]
fn route_or_binding_change_during_open_turn_cannot_reprice_the_dispatch() {
    let key_a = [30; 32];
    let (authority_a, signed_a) = authority(key_a);
    let mut route_b = route();
    route_b.model_id = "model-b".into();
    let card_b = {
        let mut card = card();
        card.route = route_b.clone();
        card
    };
    let signed_b = sign_rate_card(card_b, "pricing-root-v1", [31; 32]).unwrap();
    let authority = Arc::new(
        HmacPricingAuthority::new(vec![
            (signed_a.clone(), HmacPricingKey::from_bytes(key_a)),
            (signed_b.clone(), HmacPricingKey::from_bytes([31; 32])),
        ])
        .unwrap(),
    );
    let usage = Usage {
        input: 2,
        output: 1,
        ..Usage::default()
    };
    let projection_b = authority
        .project(&signed_b, local_identity(), usage, NOW)
        .unwrap();
    let selection = |route: &PricingRoute| EventKind::ModelSelected {
        provider_id: route.provider_id.clone(),
        model_id: route.model_id.clone(),
        catalog_digest: route.catalog_digest.clone(),
        capability_digest: route.capability_digest.clone(),
    };
    let events = [
        event(selection(&route())),
        event(EventKind::RateCardBound {
            rate_card: signed_a,
        }),
        event(EventKind::TurnStart),
        event(selection(&route_b)),
        event(EventKind::RateCardBound {
            rate_card: signed_b,
        }),
        event(EventKind::TurnEnd {
            usage,
            ttft_ms: None,
            decode_ms: None,
            stream_items: None,
        }),
        event(EventKind::CostProjected {
            projection: projection_b,
        }),
    ];
    let mut replay = PricingReplay::trusted(authority);
    let mut ledger = Ledger::new();
    let error = events
        .iter()
        .find_map(|event| observe(&mut replay, event, &mut ledger).err())
        .unwrap();
    assert_eq!(error, PricingError::ProjectionNotAdjacent);
    assert!(!matches!(ledger.cost_state(), CostState::Known { .. }));
    drop(authority_a);
}

#[test]
fn dangling_child_admissions_are_unknown_and_duplicate_start_forms_resolve_once() {
    let direct_spawn = event(EventKind::SubagentSpawned {
        sub_run: "child-open".into(),
        agent: "investigator".into(),
    });
    let workflow_start = event(EventKind::WorkflowV2 {
        version: core_protocol::WorkflowEventVersion::V2,
        workflow_id: "workflow-open".into(),
        event: core_protocol::WorkflowEvent::ChildStarted {
            task_id: 7,
            sub_run: "child-open".into(),
            spawn_seq: Seq(1),
            budget: core_protocol::Budget::default(),
        },
    });

    for admission in [&direct_spawn, &workflow_start] {
        let mut replay = PricingReplay::default();
        let mut ledger = Ledger::new();
        observe(&mut replay, admission, &mut ledger).unwrap();
        assert_eq!(ledger.provider_attempts, 0);
        assert_eq!(
            ledger.cost_state(),
            CostState::Unknown {
                reason: CostUnknownReason::BillingEvidenceMissing,
            }
        );
    }

    let terminal = event(EventKind::WorkflowV2 {
        version: core_protocol::WorkflowEventVersion::V2,
        workflow_id: "workflow-open".into(),
        event: core_protocol::WorkflowEvent::ChildFinished {
            task_id: 7,
            sub_run: Some("child-open".into()),
            outcome: core_protocol::WorkflowChildOutcome::Done,
            metrics: WorkflowMetrics::default(),
            error_code: None,
            error_detail: None,
            summary_digest: None,
            evidence_bytes: 0,
        },
    });
    let mut replay = PricingReplay::default();
    let mut ledger = Ledger::new();
    for admission in [&direct_spawn, &workflow_start] {
        observe(&mut replay, admission, &mut ledger).unwrap();
    }
    observe(&mut replay, &terminal, &mut ledger).unwrap();
    assert_eq!(ledger.cost_state(), CostState::Zero);

    let missing_sub_run_terminal = event(EventKind::WorkflowV2 {
        version: core_protocol::WorkflowEventVersion::V2,
        workflow_id: "workflow-open".into(),
        event: core_protocol::WorkflowEvent::ChildFinished {
            task_id: 7,
            sub_run: None,
            outcome: core_protocol::WorkflowChildOutcome::Failed,
            metrics: WorkflowMetrics::default(),
            error_code: Some("lost-child".into()),
            error_detail: None,
            summary_digest: None,
            evidence_bytes: 0,
        },
    });
    let mut replay = PricingReplay::default();
    let mut ledger = Ledger::new();
    observe(&mut replay, &workflow_start, &mut ledger).unwrap();
    assert_eq!(
        observe(&mut replay, &missing_sub_run_terminal, &mut ledger).unwrap_err(),
        PricingError::WorkflowEvidenceMismatch
    );
    assert!(matches!(ledger.cost_state(), CostState::Unknown { .. }));
}

#[test]
fn workflow_sub_run_cannot_be_reused_by_two_started_tasks() {
    let started = |task_id| {
        event(EventKind::Workflow {
            version: core_protocol::WorkflowEventVersion::V1,
            workflow_id: "workflow-unique".into(),
            event: core_protocol::WorkflowEvent::ChildStarted {
                task_id,
                sub_run: "shared-started-child".into(),
                spawn_seq: Seq(task_id as u64),
                budget: core_protocol::Budget::default(),
            },
        })
    };
    let mut replay = PricingReplay::default();
    let mut ledger = Ledger::new();
    observe(&mut replay, &started(1), &mut ledger).unwrap();
    assert_eq!(
        observe(&mut replay, &started(2), &mut ledger).unwrap_err(),
        PricingError::WorkflowEvidenceMismatch
    );
    assert_eq!(
        ledger.cost_state(),
        CostState::Unknown {
            reason: CostUnknownReason::BillingEvidenceMissing,
        }
    );
}

#[test]
fn pricing_authority_rejects_manifest_above_fixed_bound_before_validation() {
    let signed = sign_rate_card(card(), "pricing-root-v1", [27; 32]).unwrap();
    let entries = (0..=MAX_TRUSTED_RATE_CARDS)
        .map(|_| (signed.clone(), HmacPricingKey::from_bytes([27; 32])))
        .collect();
    assert!(matches!(
        HmacPricingAuthority::new(entries),
        Err(PricingError::RateCardManifestTooLarge)
    ));
}

#[test]
fn replay_rejects_cross_tenant_run_and_turn_projection_transplants() {
    let key = [21; 32];
    let (authority, signed) = authority(key);
    let usage = Usage {
        input: 4,
        output: 2,
        ..Usage::default()
    };
    let projection = authority
        .project(&signed, local_identity(), usage, NOW)
        .unwrap();

    let replay_in_scope = |tenant: &str, run: &str, turn: u32| {
        let events = [
            event_at(
                turn,
                EventKind::ModelSelected {
                    provider_id: route().provider_id,
                    model_id: route().model_id,
                    catalog_digest: route().catalog_digest,
                    capability_digest: route().capability_digest,
                },
            ),
            event_at(
                turn,
                EventKind::RateCardBound {
                    rate_card: signed.clone(),
                },
            ),
            event_at(turn, EventKind::TurnStart),
            event_at(
                turn,
                EventKind::TurnEnd {
                    usage,
                    ttft_ms: None,
                    decode_ms: None,
                    stream_items: None,
                },
            ),
            event_at(
                turn,
                EventKind::CostProjected {
                    projection: projection.clone(),
                },
            ),
        ];
        let mut replay = PricingReplay::trusted(authority.clone());
        let mut ledger = Ledger::new();
        events
            .iter()
            .find_map(|event| {
                replay
                    .observe(
                        event,
                        &TenantId(tenant.into()),
                        &RunId(run.into()),
                        &mut ledger,
                    )
                    .err()
            })
            .unwrap()
    };

    assert_eq!(
        replay_in_scope("tenant-b", RUN, 0),
        PricingError::ProjectionIdentityMismatch
    );
    assert_eq!(
        replay_in_scope(TENANT, "run-b", 0),
        PricingError::ProjectionIdentityMismatch
    );
    assert_eq!(
        replay_in_scope(TENANT, RUN, 7),
        PricingError::ProjectionIdentityMismatch
    );
}

#[test]
fn legacy_identityless_projection_stays_readable_but_unknown() {
    use super::codec::{projection_auth_bytes, projection_content_bytes, sha256_label, sign_mac};

    let key = [22; 32];
    let (authority, signed) = authority(key);
    let usage = Usage {
        input: 1,
        output: 1,
        ..Usage::default()
    };
    let mut legacy = authority
        .project(&signed, local_identity(), usage, NOW)
        .unwrap();
    legacy.identity = None;
    legacy.projection_digest = sha256_label(&projection_content_bytes(&legacy));
    legacy.signature = sign_mac(&key, &projection_auth_bytes(&legacy));
    let events = [
        event(EventKind::ModelSelected {
            provider_id: route().provider_id,
            model_id: route().model_id,
            catalog_digest: route().catalog_digest,
            capability_digest: route().capability_digest,
        }),
        event(EventKind::RateCardBound { rate_card: signed }),
        event(EventKind::TurnStart),
        event(EventKind::TurnEnd {
            usage,
            ttft_ms: None,
            decode_ms: None,
            stream_items: None,
        }),
        event(EventKind::CostProjected { projection: legacy }),
    ];
    let mut replay = PricingReplay::trusted(authority);
    let mut ledger = Ledger::new();
    for event in &events {
        observe(&mut replay, event, &mut ledger).unwrap();
    }
    assert_eq!(
        ledger.cost_state(),
        CostState::Unknown {
            reason: CostUnknownReason::LegacyUnattributed,
        }
    );
}

#[test]
fn replay_requires_a_fresh_binding_epoch_after_a_route_switch() {
    let key = [12; 32];
    let (authority, signed) = authority(key);
    let usage = Usage {
        input: 1,
        output: 1,
        ..Usage::default()
    };
    let first_projection = authority
        .project(&signed, local_identity(), usage, NOW)
        .unwrap();
    let second_projection = authority
        .project(&signed, identity(RUN, 1, 2, None), usage, NOW)
        .unwrap();
    let selection = |route: PricingRoute| EventKind::ModelSelected {
        provider_id: route.provider_id,
        model_id: route.model_id,
        catalog_digest: route.catalog_digest,
        capability_digest: route.capability_digest,
    };
    let mut other = route();
    other.capability_digest = format!("sha256:{}", "c".repeat(64));
    let events = [
        event(selection(route())),
        event(EventKind::RateCardBound { rate_card: signed }),
        event(EventKind::TurnStart),
        event(EventKind::TurnEnd {
            usage,
            ttft_ms: None,
            decode_ms: None,
            stream_items: None,
        }),
        event(EventKind::CostProjected {
            projection: first_projection,
        }),
        event(selection(other)),
        event(selection(route())),
        event_at(1, EventKind::TurnStart),
        event_at(
            1,
            EventKind::TurnEnd {
                usage,
                ttft_ms: None,
                decode_ms: None,
                stream_items: None,
            },
        ),
        event_at(
            1,
            EventKind::CostProjected {
                projection: second_projection,
            },
        ),
    ];
    let mut replay = PricingReplay::trusted(authority);
    let mut ledger = Ledger::new();
    for event in &events {
        observe(&mut replay, event, &mut ledger).unwrap();
    }
    assert_eq!(
        ledger.cost_state(),
        CostState::Unknown {
            reason: CostUnknownReason::NoVerifiedRateCard,
        }
    );
}

#[test]
fn signed_child_projections_are_required_for_known_workflow_cost() {
    let key = [13; 32];
    let (authority, signed) = authority(key);
    let usage = Usage {
        input: 2,
        output: 1,
        ..Usage::default()
    };
    let projection = authority
        .project(&signed, direct_identity("child"), usage, NOW)
        .unwrap();
    let metrics = WorkflowMetrics {
        provider_attempts: 1,
        completed_turns: 1,
        usage,
        cost: Some(WorkflowCostEvidence {
            amount_microusd: projection.amount_microusd,
            rate_card_digest: projection.rate_card_digest.clone(),
            projections: vec![projection],
        }),
        ..WorkflowMetrics::default()
    };
    let terminal = event(EventKind::SubagentFinished {
        sub_run: "child".into(),
        outcome: core_protocol::WorkflowChildOutcome::Done,
        metrics,
        error_code: None,
        error_detail: None,
        summary_digest: None,
        evidence_bytes: 0,
    });
    let mut ledger = Ledger::new();
    observe(
        &mut PricingReplay::trusted(authority),
        &terminal,
        &mut ledger,
    )
    .unwrap();
    assert!(matches!(ledger.cost_state(), CostState::Known { .. }));
}

#[test]
fn duplicate_direct_child_terminal_cannot_double_count_signed_cost() {
    let key = [15; 32];
    let (authority, signed) = authority(key);
    let usage = Usage {
        input: 2,
        output: 1,
        ..Usage::default()
    };
    let projection = authority
        .project(&signed, direct_identity("child-duplicate"), usage, NOW)
        .unwrap();
    let metrics = WorkflowMetrics {
        provider_attempts: 1,
        completed_turns: 1,
        usage,
        cost: Some(WorkflowCostEvidence {
            amount_microusd: projection.amount_microusd,
            rate_card_digest: projection.rate_card_digest.clone(),
            projections: vec![projection],
        }),
        ..WorkflowMetrics::default()
    };
    let terminal = event(EventKind::SubagentFinished {
        sub_run: "child-duplicate".into(),
        outcome: core_protocol::WorkflowChildOutcome::Done,
        metrics,
        error_code: None,
        error_detail: None,
        summary_digest: None,
        evidence_bytes: 0,
    });
    let mut replay = PricingReplay::trusted(authority);
    let mut ledger = Ledger::new();
    observe(&mut replay, &terminal, &mut ledger).unwrap();
    let once = ledger.cost_state();
    assert_eq!(
        observe(&mut replay, &terminal, &mut ledger).unwrap_err(),
        PricingError::DuplicateWorkflowTerminal
    );
    assert_eq!(ledger.cost_state(), once);
}

#[test]
fn workflow_task_and_sub_run_cannot_repeat_or_mix_terminal_forms() {
    let key = [16; 32];
    let (authority, signed) = authority(key);
    let usage = Usage {
        input: 2,
        output: 1,
        ..Usage::default()
    };
    let projection = authority
        .project(
            &signed,
            workflow_identity("workflow-1", 7, "shared-child"),
            usage,
            NOW,
        )
        .unwrap();
    let metrics = WorkflowMetrics {
        provider_attempts: 1,
        completed_turns: 1,
        usage,
        cost: Some(WorkflowCostEvidence {
            amount_microusd: projection.amount_microusd,
            rate_card_digest: projection.rate_card_digest.clone(),
            projections: vec![projection],
        }),
        ..WorkflowMetrics::default()
    };
    let workflow_terminal = event(EventKind::Workflow {
        version: core_protocol::WorkflowEventVersion::V1,
        workflow_id: "workflow-1".into(),
        event: core_protocol::WorkflowEvent::ChildFinished {
            task_id: 7,
            sub_run: Some("shared-child".into()),
            outcome: core_protocol::WorkflowChildOutcome::Done,
            metrics: metrics.clone(),
            error_code: None,
            error_detail: None,
            summary_digest: None,
            evidence_bytes: 0,
        },
    });
    let direct_terminal = event(EventKind::SubagentFinished {
        sub_run: "shared-child".into(),
        outcome: core_protocol::WorkflowChildOutcome::Done,
        metrics,
        error_code: None,
        error_detail: None,
        summary_digest: None,
        evidence_bytes: 0,
    });
    let mut replay = PricingReplay::trusted(authority);
    let mut ledger = Ledger::new();
    observe(&mut replay, &workflow_terminal, &mut ledger).unwrap();
    let once = ledger.cost_state();
    assert_eq!(
        observe(&mut replay, &workflow_terminal, &mut ledger).unwrap_err(),
        PricingError::DuplicateWorkflowTerminal
    );
    assert_eq!(
        observe(&mut replay, &direct_terminal, &mut ledger).unwrap_err(),
        PricingError::DuplicateWorkflowTerminal
    );
    assert_eq!(ledger.cost_state(), once);
}

#[test]
fn workflow_projection_cannot_move_to_another_task_or_sub_run() {
    let key = [23; 32];
    let (authority, signed) = authority(key);
    let usage = Usage {
        input: 2,
        output: 1,
        ..Usage::default()
    };
    let projection = authority
        .project(
            &signed,
            workflow_identity("workflow-1", 7, "child-a"),
            usage,
            NOW,
        )
        .unwrap();
    let metrics = WorkflowMetrics {
        provider_attempts: 1,
        completed_turns: 1,
        usage,
        cost: Some(WorkflowCostEvidence {
            amount_microusd: projection.amount_microusd,
            rate_card_digest: projection.rate_card_digest.clone(),
            projections: vec![projection],
        }),
        ..WorkflowMetrics::default()
    };
    let terminal = |task_id, sub_run: &str| {
        event(EventKind::Workflow {
            version: core_protocol::WorkflowEventVersion::V1,
            workflow_id: "workflow-1".into(),
            event: core_protocol::WorkflowEvent::ChildFinished {
                task_id,
                sub_run: Some(sub_run.into()),
                outcome: core_protocol::WorkflowChildOutcome::Done,
                metrics: metrics.clone(),
                error_code: None,
                error_detail: None,
                summary_digest: None,
                evidence_bytes: 0,
            },
        })
    };
    for forged in [terminal(8, "child-a"), terminal(7, "child-b")] {
        let mut replay = PricingReplay::trusted(authority.clone());
        assert_eq!(
            observe(&mut replay, &forged, &mut Ledger::new()).unwrap_err(),
            PricingError::ProjectionIdentityMismatch
        );
    }
}

#[test]
fn oversized_child_evidence_is_rejected_before_any_hmac_work() {
    let key = [14; 32];
    let (authority, signed) = authority(key);
    let mut forged = authority
        .project(
            &signed,
            direct_identity("oversized-child"),
            Usage {
                input: 1,
                output: 1,
                ..Usage::default()
            },
            NOW,
        )
        .unwrap();
    forged.signature = format!("hmac-sha256:{}", "0".repeat(64));
    let projection_count = core_protocol::MAX_WORKFLOW_COST_PROJECTIONS + 1;
    let metrics = WorkflowMetrics {
        provider_attempts: projection_count as u32,
        completed_turns: projection_count as u32,
        cost: Some(WorkflowCostEvidence {
            amount_microusd: 0,
            rate_card_digest: forged.rate_card_digest.clone(),
            projections: vec![forged; projection_count],
        }),
        ..WorkflowMetrics::default()
    };
    let terminal = event(EventKind::SubagentFinished {
        sub_run: "oversized-child".into(),
        outcome: core_protocol::WorkflowChildOutcome::Done,
        metrics,
        error_code: None,
        error_detail: None,
        summary_digest: None,
        evidence_bytes: 0,
    });
    let mut ledger = Ledger::new();
    let error = observe(
        &mut PricingReplay::trusted(authority),
        &terminal,
        &mut ledger,
    )
    .unwrap_err();
    assert_eq!(error, PricingError::WorkflowEvidenceMismatch);
    assert_eq!(ledger.cost_state(), CostState::Zero);
}
