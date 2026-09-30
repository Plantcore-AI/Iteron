use super::{LogicalUsageScope, exact_projection};
use crate::runtime::provider_attempt_journal::{
    ProviderIntent, ProviderLogicalUsageEvidence, ProviderObservedAttempt,
};
use crate::runtime::{Agent, KernelError};
use iteron_protocol::{Capability, StopReason, TurnId, UsageReport};
use iteron_provider::TurnResult;

/// Existing direct-accounting fixtures cross the real physical intent/terminal barriers. Only the
/// physical journal can mint the receipt; there is no test/public constructor for a sealed proof.
pub(in crate::runtime) fn durable_evidence(
    agent: &mut Agent,
    turn: TurnId,
    report: UsageReport,
    admitted_at: u64,
) -> Result<ProviderLogicalUsageEvidence, KernelError> {
    let route = agent
        .provider_selection
        .card()
        .map(|card| {
            format!(
                "{}:{}",
                card.rate_card.route.provider_id, card.rate_card.route.model_id
            )
        })
        .unwrap_or_else(|| format!("fixture:{}", agent.model));
    agent.guard_unresolved_effects()?;
    if let Some(budget) = &agent.usd_budget
        && budget.requires_pricing()
        && budget.active_reservation_microusd().is_none()
    {
        let signed = agent
            .provider_selection
            .card()
            .ok_or(KernelError::UnpricedUsdCeiling)?;
        let reservation = iteron_obs::pricing::projected_amount_microusd(
            signed.rate_card.rates,
            match report {
                UsageReport::Complete(usage) | UsageReport::CacheCreationUnreported(usage) => usage,
                UsageReport::Incomplete { .. } => iteron_protocol::Usage::default(),
            },
        )?;
        budget
            .reserve_provider_attempt(reservation)
            .map_err(KernelError::PricingLedger)?;
    }
    let (ordinal, physical) = agent.next_provider_effect_identity(turn)?;
    let workspace = agent.workspace.clone();
    let ticket = {
        let mut journal = agent.provider_attempt_journal();
        journal.pricing_now = admitted_at;
        journal.open(&workspace, ProviderIntent {
            turn, ordinal, capability: Capability::IrreversibleExternal,
            audit: serde_json::json!({"route_id":route,"physical_attempt":physical,"max_tokens":16}),
        })?
    };
    let result = Ok(TurnResult {
        blocks: vec![],
        stop_reason: StopReason::EndTurn,
        usage: report,
    });
    let (_, _, receipt) = agent.provider_attempt_journal().settle_observed(
        ticket,
        ProviderObservedAttempt {
            route_id: &route,
            result: &result,
        },
    )?;
    Ok(ProviderLogicalUsageEvidence::Single(receipt))
}

#[test]
fn aggregate_and_unproven_usage_never_mint_a_single_physical_projection() {
    let tenant = iteron_protocol::TenantId("tenant".into());
    let run = iteron_protocol::RunId("run".into());
    for evidence in [
        ProviderLogicalUsageEvidence::HedgedAggregate,
        ProviderLogicalUsageEvidence::Unproven,
    ] {
        assert!(
            exact_projection(
                &evidence,
                LogicalUsageScope {
                    tenant: &tenant,
                    run: &run,
                    turn: TurnId(0),
                    attribution: &None
                },
                iteron_protocol::Usage::default(),
                None
            )
            .unwrap()
            .is_none()
        );
    }
}

#[tokio::test]
async fn durable_fallback_terminal_projects_exact_second_physical_receipt_and_reopens() {
    use crate::runtime::effect_journal_owner::EffectJournalOwner;
    use crate::runtime::provider_attempt_journal::ProviderAttemptJournal;
    use crate::runtime::provider_financial_context::{
        ProviderFinancialContext, ProviderFinancialOwners, ProviderFinancialScope,
        ProviderPricingEvidence,
    };
    use crate::runtime::provider_transport_attempt::{
        ProviderCancellation, execute_admitted_provider_turn_observed,
    };
    use iteron_kernel::diagnostics::DiagnosticEmitter;
    use iteron_obs::pricing::{HmacPricingAuthority, HmacPricingKey, sign_rate_card};
    use iteron_obs::{CostState, Ledger, PricingPort, PricingReplay};
    use iteron_protocol::{
        Event, EventKind, PricingRoute, PricingVersion, RateCard, RunId, Seq, SignedRateCard,
        TenantId, TokenRateCard, Usage,
    };
    use iteron_provider::{Provider, ProviderError, StreamItem, TurnRequest};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use std::time::{Duration, Instant};
    struct ActualFixture(Arc<AtomicUsize>);
    #[async_trait::async_trait]
    impl Provider for ActualFixture {
        fn attempt_semantics(&self) -> iteron_provider::ProviderAttemptSemantics {
            iteron_provider::ProviderAttemptSemantics::Single
        }
        async fn turn(
            &self,
            _: &TurnRequest,
            _: &mut (dyn FnMut(StreamItem) + Send),
        ) -> Result<TurnResult, ProviderError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(TurnResult {
                blocks: vec![],
                stop_reason: StopReason::EndTurn,
                usage: UsageReport::complete(Usage {
                    input: 2,
                    output: 3,
                    ..Usage::default()
                }),
            })
        }
    }
    fn card(model: &str, issued: u64, expires: u64) -> SignedRateCard {
        sign_rate_card(
            RateCard {
                version: PricingVersion::V1,
                route: PricingRoute {
                    provider_id: "fixture".into(),
                    model_id: model.into(),
                    catalog_digest: format!("sha256:{}", "a".repeat(64)),
                    capability_digest: format!("sha256:{}", "b".repeat(64)),
                },
                provenance: "actual-physical-fixture".into(),
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
            [82; 32],
        )
        .unwrap()
    }
    let directory = std::env::temp_dir().join(format!(
        "iteron-logical-physical-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let tenant = TenantId("tenant".into());
    let run = RunId("physical-fallback".into());
    let turn = TurnId(7);
    let first = card("first", 1, 20);
    let fallback = card("fallback", 30, 60);
    let pricing = Arc::new(
        HmacPricingAuthority::new(vec![
            (first.clone(), HmacPricingKey::from_bytes([82; 32])),
            (fallback.clone(), HmacPricingKey::from_bytes([82; 32])),
        ])
        .unwrap(),
    );
    let mut rollout = iteron_record::Rollout::open(&directory, &run, tenant.clone()).unwrap();
    let mut effects = EffectJournalOwner::default();
    let mut ledger = Ledger::new();
    effects.guard_recovery(&mut rollout, &mut ledger).unwrap();
    let mut failed = false;
    let diagnostics = DiagnosticEmitter::default();
    let mut fault = None;
    let financial = |card: &SignedRateCard| {
        ProviderFinancialContext::new(
            ProviderFinancialScope {
                tenant: tenant.clone(),
                run_id: run.clone(),
                attribution: None,
            },
            ProviderPricingEvidence {
                port: Some(pricing.clone()),
                card: Some(card.clone()),
                context_window: Some(16),
                usage_bounds: iteron_provider::ProviderUsageBoundSemantics::IndependentClasses,
            },
            ProviderFinancialOwners {
                usd: None,
                cohort: Ok(None),
            },
        )
    };
    let bind = |rollout: &mut iteron_record::Rollout, card: &SignedRateCard| {
        let route = &card.rate_card.route;
        for kind in [
            EventKind::ModelSelected {
                provider_id: route.provider_id.clone(),
                model_id: route.model_id.clone(),
                catalog_digest: route.catalog_digest.clone(),
                capability_digest: route.capability_digest.clone(),
            },
            EventKind::RateCardBound {
                rate_card: card.clone(),
            },
        ] {
            rollout
                .append(&Event {
                    seq: Seq::ZERO,
                    turn,
                    kind,
                })
                .unwrap();
        }
    };
    bind(&mut rollout, &first);
    let first_ticket=ProviderAttemptJournal{rollout:&mut rollout,effects:&mut effects,ledger:&mut ledger,
        record_failed:&mut failed,diagnostics:&diagnostics,financial:financial(&first),pricing_now:10,fault:&mut fault}
        .open(&directory,ProviderIntent{turn,ordinal:0,capability:Capability::IrreversibleExternal,
            audit:serde_json::json!({"route_id":"fixture:first","physical_attempt":1,"max_tokens":16})}).unwrap();
    rollout
        .append(&Event {
            seq: Seq::ZERO,
            turn,
            kind: EventKind::TurnStart,
        })
        .unwrap();
    ledger.attempt();
    let refusal = Err(KernelError::Provider(
        ProviderError::RequestCaptureRefusedBeforeDispatch,
    ));
    ProviderAttemptJournal {
        rollout: &mut rollout,
        effects: &mut effects,
        ledger: &mut ledger,
        record_failed: &mut failed,
        diagnostics: &diagnostics,
        financial: financial(&first),
        pricing_now: 1000,
        fault: &mut fault,
    }
    .settle_observed(
        first_ticket,
        ProviderObservedAttempt {
            route_id: "fixture:first",
            result: &refusal,
        },
    )
    .unwrap();
    bind(&mut rollout, &fallback);
    let fallback_ticket=ProviderAttemptJournal{rollout:&mut rollout,effects:&mut effects,ledger:&mut ledger,
        record_failed:&mut failed,diagnostics:&diagnostics,financial:financial(&fallback),pricing_now:40,fault:&mut fault}
        .open(&directory,ProviderIntent{turn,ordinal:1,capability:Capability::IrreversibleExternal,
            audit:serde_json::json!({"route_id":"fixture:fallback","physical_attempt":2,"max_tokens":16})}).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let result = execute_admitted_provider_turn_observed(
        Arc::new(ActualFixture(calls.clone())),
        Instant::now() + Duration::from_secs(3),
        ProviderCancellation {
            interrupt: None,
            force_cancel: Arc::new(AtomicBool::new(false)),
            drain: Arc::new(AtomicBool::new(false)),
            attempt: None,
            allow_in_flight_past_deadline: false,
        },
        &TurnRequest {
            model: "fallback".into(),
            system: "fixture".into(),
            messages: vec![],
            input_images: vec![],
            tools: vec![].into(),
            max_tokens: 16,
            cache_system: false,
            thinking_budget: 0,
            reasoning_effort: iteron_protocol::ReasoningEffort::Low,
            controls: Default::default(),
        },
        &mut |_| {},
        None,
    )
    .await;
    let (_, _, receipt) = ProviderAttemptJournal {
        rollout: &mut rollout,
        effects: &mut effects,
        ledger: &mut ledger,
        record_failed: &mut failed,
        diagnostics: &diagnostics,
        financial: financial(&fallback),
        pricing_now: 1000,
        fault: &mut fault,
    }
    .settle_observed(
        fallback_ticket,
        ProviderObservedAttempt {
            route_id: "fixture:fallback",
            result: &result,
        },
    )
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(receipt.pricing_at_unix_secs(), Some(40));
    let evidence = ProviderLogicalUsageEvidence::Single(receipt);
    let usage = Usage {
        input: 2,
        output: 3,
        ..Usage::default()
    };
    let projection = exact_projection(
        &evidence,
        LogicalUsageScope {
            tenant: &tenant,
            run: &run,
            turn,
            attribution: &None,
        },
        usage,
        Some(pricing.as_ref()),
    )
    .unwrap()
    .unwrap();
    assert_eq!(projection.identity.as_ref().unwrap().provider_attempt, 2);
    assert_eq!(projection.projected_at_unix_secs, 40);
    assert!(
        exact_projection(
            &evidence,
            LogicalUsageScope {
                tenant: &tenant,
                run: &run,
                turn: TurnId(8),
                attribution: &None
            },
            usage,
            Some(pricing.as_ref())
        )
        .is_err()
    );
    assert!(
        exact_projection(
            &evidence,
            LogicalUsageScope {
                tenant: &tenant,
                run: &run,
                turn,
                attribution: &None
            },
            Usage { input: 3, ..usage },
            Some(pricing.as_ref())
        )
        .is_err()
    );
    rollout
        .append(&Event {
            seq: Seq::ZERO,
            turn,
            kind: EventKind::TurnEnd {
                usage,
                ttft_ms: None,
                decode_ms: None,
                stream_items: None,
            },
        })
        .unwrap();
    ledger.turn(&usage, 0);
    rollout
        .append(&Event {
            seq: Seq::ZERO,
            turn,
            kind: EventKind::CostProjected {
                projection: projection.clone(),
            },
        })
        .unwrap();
    iteron_obs::admit_verified_projection_by_digest(
        pricing.as_ref(),
        projection.identity.as_ref().unwrap(),
        &projection,
        &mut ledger,
    )
    .unwrap();
    let path = rollout.path().to_path_buf();
    drop(rollout);
    let mut replay = PricingReplay::trusted(pricing);
    let mut restored = Ledger::new();
    for row in iteron_record::replay(&path).unwrap() {
        replay.observe(&row, &tenant, &run, &mut restored).unwrap();
    }
    assert_eq!(restored.cost_state(), ledger.cost_state());
    assert!(matches!(
        restored.cost_state(),
        CostState::Known {
            amount_microusd: 5,
            ..
        }
    ));
    // Actual scope/intent data from the reopened journal must retain the timestamp seal. A
    // differently signed timestamp or an Unknown label cannot release a pending monetary bound.
    let mut scoped: Vec<iteron_record::ScopedEvent> = iteron_record::replay(&path)
        .unwrap()
        .into_iter()
        .map(|event| iteron_record::ScopedEvent {
            tenant: tenant.clone(),
            run_id: run.clone(),
            event,
        })
        .collect();
    let original =
        crate::runtime::provider_charge_evidence::replay_evidence::ProviderReplayEvidence::inspect(
            &scoped,
        );
    assert!(!original.has_unknown());
    let (effect, identity) = scoped
        .iter()
        .find_map(|row| match &row.event.kind {
            EventKind::EffectIntent {
                id,
                provider_route_attempt: Some(identity),
                ..
            } if identity.physical_attempt == 2 => Some((id.0.clone(), identity.clone())),
            _ => None,
        })
        .unwrap();
    assert!(
        original
            .matching_terminal(&tenant, &run, &effect, turn.0, &identity)
            .is_some()
    );
    drop(original);
    for row in &mut scoped {
        if let EventKind::EffectIntent {
            arguments,
            provider_route_attempt: Some(identity),
            ..
        } = &mut row.event.kind
            && identity.physical_attempt == 2
        {
            arguments["provider_pricing_at_unix_secs"] = 41.into();
        }
    }
    let tampered =
        crate::runtime::provider_charge_evidence::replay_evidence::ProviderReplayEvidence::inspect(
            &scoped,
        );
    assert!(tampered.has_unknown());
    assert!(
        tampered
            .matching_terminal(&tenant, &run, &effect, turn.0, &identity)
            .is_none()
    );
    std::fs::remove_dir_all(directory).unwrap();
}
