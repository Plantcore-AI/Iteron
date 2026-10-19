use crate::runtime::KernelError;
use crate::runtime::gate_integration_tests::{agent_for, record_test_genesis, temp_ws};

#[test]
fn real_missing_history_then_repaired_path_cannot_install_an_empty_ceiling_on_retry() {
    let directory = temp_ws("funding-physical-history-refusal");
    let mut agent = agent_for(&directory);
    record_test_genesis(&mut agent, &directory);
    agent.budget.max_usd = Some(1.0);
    assert!(agent.usd_budget.is_none());
    let path = agent.rollout.path().to_owned();
    let held = path.with_extension("held-for-recovery-refusal");
    // The real writer retains its descriptor and can commit the ceiling. Recovery of the
    // authoritative namespace then fails, which is the actual install-before-replay window.
    std::fs::rename(&path, &held).unwrap();
    assert!(matches!(
        agent.synchronize_usd_budget(),
        Err(KernelError::Record(_))
    ));
    assert!(agent.usd_budget.is_none());
    assert!(agent.record_failed);
    assert!(agent.usd_budget_persisted_microusd.is_some());
    std::fs::rename(&held, &path).unwrap();
    // Repairing a path is not admission to continue using a poisoned physical record owner.
    assert!(matches!(
        agent.synchronize_usd_budget(),
        Err(KernelError::Record(_))
    ));
    assert!(agent.usd_budget.is_none());
    assert!(agent.ensure_record_healthy().is_err());
    assert_eq!(agent.ledger.provider_attempts, 0);
    drop(agent);
    assert!(
        iteron_record::replay(&path)
            .unwrap()
            .iter()
            .any(|event| matches!(
                event.kind,
                iteron_protocol::EventKind::UsdCeilingChanged { .. }
            ))
    );
    std::fs::remove_dir_all(directory).unwrap();
}
