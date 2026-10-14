use crate::runtime::DurableAppendFault;
use crate::runtime::gate_integration_tests::{agent_for, record_test_genesis, temp_ws};
use crate::runtime::provider_attempt_journal::ProviderLogicalUsageEvidence;
use crate::runtime::provider_logical_usage::tests::durable_evidence;
use crate::runtime::stream_progress::StreamTiming;
use iteron_protocol::{EventKind, TurnId, Usage};
use iteron_provider::UsageReport;

#[test]
fn logical_usage_retains_actual_physical_terminal_and_one_durable_turn_end() {
    let directory = temp_ws("logical-usage-owned-journal");
    let mut agent = agent_for(&directory);
    record_test_genesis(&mut agent, &directory);
    let usage = Usage {
        input: 2,
        output: 3,
        ..Usage::default()
    };
    let report = UsageReport::complete(usage);
    let evidence = durable_evidence(&mut agent, TurnId(0), report, 10).unwrap();
    let prior = agent.ledger.turns;
    assert_eq!(
        agent
            .provider_usage_journal(TurnId(0))
            .record(TurnId(0), report, 1, &evidence, StreamTiming::default(),)
            .unwrap(),
        Some(usage)
    );
    assert_eq!(agent.ledger.turns, prior + 1);
    let path = agent.rollout.path().to_path_buf();
    drop(agent);
    let events = iteron_record::replay(&path).unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.kind, EventKind::TurnEnd { .. }))
            .count(),
        1
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event.kind, EventKind::EffectIntent { .. }))
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn incomplete_usage_notice_refusal_leaves_no_logical_turn_and_poison_cannot_append() {
    let directory = temp_ws("logical-usage-refused-journal");
    let mut agent = agent_for(&directory);
    record_test_genesis(&mut agent, &directory);
    let prior = agent.ledger.turns;
    agent.fail_next_durable_append = Some(DurableAppendFault::Notice);
    assert!(
        agent
            .provider_usage_journal(TurnId(0))
            .record(
                TurnId(0),
                UsageReport::provider_omitted(),
                1,
                &ProviderLogicalUsageEvidence::Unproven,
                StreamTiming::default(),
            )
            .is_err()
    );
    assert!(agent.record_failed);
    assert_eq!(agent.ledger.turns, prior);
    assert!(
        agent
            .provider_usage_journal(TurnId(0))
            .record(
                TurnId(0),
                UsageReport::complete(Usage::default()),
                1,
                &ProviderLogicalUsageEvidence::Unproven,
                StreamTiming::default(),
            )
            .is_err()
    );
    assert_eq!(agent.ledger.turns, prior);
    let path = agent.rollout.path().to_path_buf();
    drop(agent);
    let events = iteron_record::replay(&path).unwrap();
    assert!(
        !events
            .iter()
            .any(|event| matches!(event.kind, EventKind::TurnEnd { .. }))
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn missing_cache_creation_notice_requires_the_same_physical_receipts_paid_tariff() {
    use iteron_obs::{CostState, HmacPricingAuthority, HmacPricingKey, sign_rate_card};
    use iteron_protocol::{
        PricingRoute, PricingVersion, ProviderRouteCostTruth, ProviderRouteCostUnknownReason,
        RateCard, TokenRateCard,
    };
    use std::sync::Arc;
    for tariff in [None, Some(0), Some(1)] {
        let directory = temp_ws(&format!("logical-cache-tariff-{tariff:?}"));
        let mut agent = agent_for(&directory);
        record_test_genesis(&mut agent, &directory);
        if let Some(tariff) = tariff {
            let route = PricingRoute {
                provider_id: "fixture-provider".into(),
                model_id: agent.model.clone(),
                catalog_digest: format!("sha256:{}", "a".repeat(64)),
                capability_digest: format!("sha256:{}", "b".repeat(64)),
            };
            agent
                .record_model_selection(
                    route.provider_id.clone(),
                    route.model_id.clone(),
                    route.catalog_digest.clone(),
                    route.capability_digest.clone(),
                )
                .unwrap();
            let signed = sign_rate_card(
                RateCard {
                    version: PricingVersion::V1,
                    route,
                    provenance: "actual-cache-tariff-fixture".into(),
                    issued_at_unix_secs: 1,
                    expires_at_unix_secs: 100,
                    rates: TokenRateCard {
                        input_microusd_per_million: 1,
                        output_microusd_per_million: 1,
                        cache_creation_microusd_per_million: tariff,
                        cache_read_microusd_per_million: 1,
                        thinking_microusd_per_million: 1,
                    },
                },
                "cache-tariff-fixture",
                [51; 32],
            )
            .unwrap();
            agent.set_pricing_port(Arc::new(
                HmacPricingAuthority::new(vec![(signed, HmacPricingKey::from_bytes([51; 32]))])
                    .unwrap(),
            ));
            agent.pricing_now_unix_secs = Some(10);
            assert!(agent.bind_selected_rate_card().unwrap());
        }
        let usage = Usage {
            input: 2,
            output: 3,
            ..Usage::default()
        };
        let report = UsageReport::cache_creation_unreported(usage);
        let evidence = durable_evidence(&mut agent, TurnId(0), report, 10).unwrap();
        let ProviderLogicalUsageEvidence::Single(receipt) = &evidence else {
            panic!("real physical terminal must mint its receipt")
        };
        assert_eq!(receipt.cache_creation_tariff_nonzero(), tariff == Some(1));
        assert!(matches!(
            receipt.accounting().cost,
            ProviderRouteCostTruth::Unknown {
                reason: ProviderRouteCostUnknownReason::UsageIncomplete
            }
        ));
        // Mutating the later host selection cannot change which physical tariff was witnessed.
        agent.set_pricing_port(Arc::new(HmacPricingAuthority::new(vec![]).unwrap()));
        assert!(agent.provider_selection.card().is_none());
        agent
            .provider_usage_journal(TurnId(0))
            .record(TurnId(0), report, 1, &evidence, StreamTiming::default())
            .unwrap();
        assert!(matches!(
            agent.ledger.cost_state(),
            CostState::Unknown { .. }
        ));
        let events = iteron_record::replay(agent.rollout.path()).unwrap();
        let notices = events
            .iter()
            .filter(|event| {
                matches!(&event.kind,
            EventKind::Notice { text } if text == super::UNPRICEABLE_CACHE_CREATION_NOTICE)
            })
            .count();
        assert_eq!(notices, usize::from(tariff == Some(1)));
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event.kind, EventKind::TurnEnd { .. }))
                .count(),
            1
        );
        drop(agent);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
