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
