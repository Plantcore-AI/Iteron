use super::{
    HmacPricingAuthority, HmacPricingKey, PricingError, PricingPort, PricingReplay, sign_rate_card,
};
use crate::{CostState, Ledger};
use iteron_protocol::{
    Capability, CostProjection, CostProjectionIdentity, EffectId, Event, EventKind, PricingRoute,
    PricingVersion, ProviderRouteAttemptAccounting, ProviderRouteAttemptAccountingVersion,
    ProviderRouteAttemptIdentity, ProviderRouteCostTruth, ProviderRouteUsageTruth, RateCard, RunId,
    Seq, SignedRateCard, TenantId, TokenRateCard, TurnId, Usage,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

fn card(model: &str, issued: u64, expires: u64) -> SignedRateCard {
    sign_rate_card(
        RateCard {
            version: PricingVersion::V1,
            route: PricingRoute {
                provider_id: "native".into(),
                model_id: model.into(),
                catalog_digest: format!("sha256:{}", "a".repeat(64)),
                capability_digest: format!("sha256:{}", "b".repeat(64)),
            },
            provenance: "physical-replay-fixture".into(),
            issued_at_unix_secs: issued,
            expires_at_unix_secs: expires,
            rates: TokenRateCard {
                input_microusd_per_million: 1_000_000,
                output_microusd_per_million: 1_000_000,
                cache_creation_microusd_per_million: 0,
                cache_read_microusd_per_million: 0,
                thinking_microusd_per_million: 1_000_000,
            },
        },
        "fixture",
        [81; 32],
    )
    .unwrap()
}
fn authority(cards: &[SignedRateCard]) -> Arc<HmacPricingAuthority> {
    Arc::new(
        HmacPricingAuthority::new(
            cards
                .iter()
                .cloned()
                .map(|card| (card, HmacPricingKey::from_bytes([81; 32])))
                .collect(),
        )
        .unwrap(),
    )
}
fn selection(card: &SignedRateCard) -> EventKind {
    let r = &card.rate_card.route;
    EventKind::ModelSelected {
        provider_id: r.provider_id.clone(),
        model_id: r.model_id.clone(),
        catalog_digest: r.catalog_digest.clone(),
        capability_digest: r.capability_digest.clone(),
    }
}
fn identity(card: &SignedRateCard, physical: u32) -> ProviderRouteAttemptIdentity {
    let mut hash = Sha256::new();
    hash.update(b"iteron-provider-route-attempt-v1\0");
    hash.update(
        format!(
            "{}:{}",
            card.rate_card.route.provider_id, card.rate_card.route.model_id
        )
        .as_bytes(),
    );
    ProviderRouteAttemptIdentity {
        version: ProviderRouteAttemptAccountingVersion::V1,
        route_id: format!("sha256:{:x}", hash.finalize()),
        physical_attempt: physical,
        max_cost_reservation_microusd: Some(100),
    }
}
fn intent(card: &SignedRateCard, physical: u32, now: u64) -> EventKind {
    EventKind::EffectIntent {
        id: EffectId(format!("physical-{physical}")),
        tool_use_id: format!("physical-{physical}"),
        tool: "provider".into(),
        capability: Capability::IrreversibleExternal,
        arguments: serde_json::json!({"provider_pricing_at_unix_secs":now}),
        workspace: "fixture".into(),
        provider_route_attempt: Some(identity(card, physical)),
    }
}
fn projection(
    port: &dyn PricingPort,
    card: &SignedRateCard,
    physical: u32,
    now: u64,
) -> CostProjection {
    port.project(
        card,
        CostProjectionIdentity {
            tenant_id: "tenant".into(),
            run_id: "run".into(),
            turn_id: 7,
            provider_attempt: physical,
            attribution: None,
        },
        Usage {
            input: 2,
            output: 3,
            ..Usage::default()
        },
        now,
    )
    .unwrap()
}
fn terminal(card: &SignedRateCard, physical: u32, projection: CostProjection) -> EventKind {
    let id = identity(card, physical);
    EventKind::EffectDone {
        id: EffectId(format!("physical-{physical}")),
        tool: "provider".into(),
        duration_ms: Some(1),
        provider_route_attempt: Some(ProviderRouteAttemptAccounting {
            version: id.version,
            route_id: id.route_id,
            physical_attempt: physical,
            max_cost_reservation_microusd: id.max_cost_reservation_microusd,
            usage: ProviderRouteUsageTruth::Known {
                usage: projection.usage,
            },
            cost: ProviderRouteCostTruth::Known {
                amount_microusd: projection.amount_microusd,
                rate_card_digest: projection.rate_card_digest.clone(),
                projection: Some(Box::new(projection)),
            },
        }),
    }
}
fn turn_end() -> EventKind {
    EventKind::TurnEnd {
        usage: Usage {
            input: 2,
            output: 3,
            ..Usage::default()
        },
        ttft_ms: None,
        decode_ms: None,
        stream_items: None,
    }
}
fn observe(
    replay: &mut PricingReplay,
    ledger: &mut Ledger,
    kind: EventKind,
) -> Result<(), PricingError> {
    replay.observe(
        &Event {
            seq: Seq::ZERO,
            turn: TurnId(7),
            kind,
        },
        &TenantId("tenant".into()),
        &RunId("run".into()),
        ledger,
    )
}
#[test]
fn fallback_uses_exact_physical_stamp_and_per_turn_ordinal_across_card_rebind() {
    let first = card("first", 1, 20);
    let fallback = card("fallback", 30, 60);
    let port = authority(&[first.clone(), fallback.clone()]);
    let proof = projection(port.as_ref(), &fallback, 2, 40);
    let first_id = identity(&first, 1);
    let zero = EventKind::EffectFailed {
        id: EffectId("physical-1".into()),
        tool: "provider".into(),
        reason: "known no IO".into(),
        duration_ms: None,
        provider_route_attempt: Some(ProviderRouteAttemptAccounting {
            version: first_id.version,
            route_id: first_id.route_id,
            physical_attempt: 1,
            max_cost_reservation_microusd: first_id.max_cost_reservation_microusd,
            usage: ProviderRouteUsageTruth::NotDispatched,
            cost: ProviderRouteCostTruth::NotDispatched,
        }),
    };
    let rows = vec![
        selection(&first),
        EventKind::RateCardBound {
            rate_card: first.clone(),
        },
        intent(&first, 1, 10),
        EventKind::TurnStart,
        zero,
        selection(&fallback),
        EventKind::RateCardBound {
            rate_card: fallback.clone(),
        },
        intent(&fallback, 2, 40),
        terminal(&fallback, 2, proof.clone()),
        turn_end(),
        EventKind::CostProjected {
            projection: proof.clone(),
        },
    ];
    let mut replay = PricingReplay::trusted(port);
    let mut ledger = Ledger::new();
    for row in rows {
        observe(&mut replay, &mut ledger, row).unwrap();
    }
    assert_eq!(ledger.provider_attempts, 1);
    assert_eq!(
        ledger.cost_state(),
        CostState::Known {
            amount_microusd: proof.amount_microusd,
            rate_card_digest: proof.rate_card_digest.clone()
        }
    );
    assert_eq!(
        observe(
            &mut replay,
            &mut ledger,
            EventKind::CostProjected { projection: proof }
        )
        .unwrap_err(),
        PricingError::DuplicateProjection
    );
}
#[test]
fn modern_missing_terminal_cannot_use_legacy_counter_projection() {
    let card = card("model", 1, 100);
    let port = authority(std::slice::from_ref(&card));
    let proof = projection(port.as_ref(), &card, 1, 10);
    let mut replay = PricingReplay::trusted(port);
    let mut ledger = Ledger::new();
    for row in [
        selection(&card),
        EventKind::RateCardBound {
            rate_card: card.clone(),
        },
        intent(&card, 1, 10),
        EventKind::TurnStart,
        turn_end(),
    ] {
        observe(&mut replay, &mut ledger, row).unwrap();
    }
    assert_eq!(
        observe(
            &mut replay,
            &mut ledger,
            EventKind::CostProjected { projection: proof }
        )
        .unwrap_err(),
        PricingError::ProjectionIdentityMismatch
    );
    assert!(matches!(ledger.cost_state(), CostState::Unknown { .. }));
}
#[test]
fn signed_terminal_with_different_time_scope_or_ordinal_does_not_authorize_logical_cost() {
    let card = card("model", 1, 100);
    let port = authority(std::slice::from_ref(&card));
    for variant in 0..3 {
        let mut replay = PricingReplay::trusted(port.clone());
        let mut ledger = Ledger::new();
        for row in [
            selection(&card),
            EventKind::RateCardBound {
                rate_card: card.clone(),
            },
            intent(&card, 1, 10),
            EventKind::TurnStart,
        ] {
            observe(&mut replay, &mut ledger, row).unwrap();
        }
        let mut id = CostProjectionIdentity {
            tenant_id: "tenant".into(),
            run_id: "run".into(),
            turn_id: 7,
            provider_attempt: 1,
            attribution: None,
        };
        if variant == 1 {
            id.run_id = "foreign".into();
        }
        if variant == 2 {
            id.provider_attempt = 2;
        }
        let proof = port
            .project(
                &card,
                id,
                Usage {
                    input: 2,
                    output: 3,
                    ..Usage::default()
                },
                if variant == 0 { 11 } else { 10 },
            )
            .unwrap();
        assert_eq!(
            observe(&mut replay, &mut ledger, terminal(&card, 1, proof)).unwrap_err(),
            PricingError::ProjectionIdentityMismatch
        );
    }
}
#[test]
fn physical_candidates_remain_bounded_and_no_trust_port_does_not_restore_money() {
    let card = card("model", 1, 100);
    let port = authority(std::slice::from_ref(&card));
    let proof = projection(port.as_ref(), &card, 1, 10);
    let mut replay = PricingReplay::default();
    let mut ledger = Ledger::new();
    for row in [
        selection(&card),
        EventKind::RateCardBound {
            rate_card: card.clone(),
        },
        intent(&card, 1, 10),
        EventKind::TurnStart,
        terminal(&card, 1, proof.clone()),
        turn_end(),
        EventKind::CostProjected { projection: proof },
    ] {
        observe(&mut replay, &mut ledger, row).unwrap();
    }
    assert!(matches!(ledger.cost_state(), CostState::Unknown { .. }));
    let mut replay = PricingReplay::trusted(port);
    let mut ledger = Ledger::new();
    observe(&mut replay, &mut ledger, selection(&card)).unwrap();
    observe(
        &mut replay,
        &mut ledger,
        EventKind::RateCardBound {
            rate_card: card.clone(),
        },
    )
    .unwrap();
    for physical in 1..=256 {
        observe(&mut replay, &mut ledger, intent(&card, physical, 10)).unwrap();
    }
    assert!(observe(&mut replay, &mut ledger, intent(&card, 257, 10)).is_err());
}

#[test]
fn child_terminal_physical_ordinal_is_not_a_logical_attempt_count() {
    use iteron_protocol::{CostAttribution, WorkflowCostEvidence, WorkflowMetrics};
    let card = card("model", 1, 100);
    let port = authority(std::slice::from_ref(&card));
    let proof = port
        .project(
            &card,
            CostProjectionIdentity {
                tenant_id: "tenant".into(),
                run_id: "child".into(),
                turn_id: 7,
                provider_attempt: 2,
                attribution: Some(CostAttribution::DirectSubagent {
                    parent_run_id: "run".into(),
                    sub_run: "child".into(),
                }),
            },
            Usage {
                input: 2,
                output: 3,
                ..Usage::default()
            },
            10,
        )
        .unwrap();
    let metrics = WorkflowMetrics {
        provider_attempts: 1,
        completed_turns: 1,
        usage: proof.usage,
        cost: Some(WorkflowCostEvidence {
            amount_microusd: proof.amount_microusd,
            rate_card_digest: proof.rate_card_digest.clone(),
            projections: vec![proof],
        }),
        ..WorkflowMetrics::default()
    };
    let mut replay = PricingReplay::trusted(port);
    let mut ledger = Ledger::new();
    observe(
        &mut replay,
        &mut ledger,
        EventKind::SubagentSpawned {
            agent: "fixture".into(),
            sub_run: "child".into(),
        },
    )
    .unwrap();
    observe(
        &mut replay,
        &mut ledger,
        EventKind::SubagentFinished {
            sub_run: "child".into(),
            outcome: iteron_protocol::WorkflowChildOutcome::Done,
            metrics,
            error_code: None,
            error_detail: None,
            summary_digest: None,
            evidence_bytes: 0,
        },
    )
    .unwrap();
    assert!(matches!(
        ledger.cost_state(),
        CostState::Known {
            amount_microusd: 5,
            ..
        }
    ));
}
