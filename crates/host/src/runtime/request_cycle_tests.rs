use super::RequestCycle;
use crate::runtime::DurableAppendFault;
use crate::runtime::agent_loop::AgentLoopGuard;
use crate::runtime::context_runtime::ContextBudgetRecoveryGuard;
use crate::runtime::gate_integration_tests::{agent_for, record_test_genesis, temp_ws};
use crate::runtime::investigation_convergence::InvestigationConvergence;
use crate::runtime::request_recovery_driver::RequestRecoveryWork;
use iteron_protocol::{EventKind, Message, TurnId};
use std::time::Instant;

#[test]
fn real_model_phase_refusal_poison_does_not_rearm_the_consumed_request_cycle() {
    let directory = temp_ws("request-cycle-actual-phase-refusal");
    let mut agent = agent_for(&directory);
    record_test_genesis(&mut agent, &directory);
    let mut messages = vec![Message::user_text("read the implementation")];
    let convergence = InvestigationConvergence::for_general_run();
    let recipe = agent
        .request_cycle_recipe(
            TurnId(0),
            &mut messages,
            &[],
            "read the implementation",
            &convergence,
            Instant::now(),
        )
        .unwrap();
    let mut guard = ContextBudgetRecoveryGuard::default();
    let mut cycle = RequestCycle::new(
        recipe,
        &mut guard,
        &mut agent.context_estimator,
        AgentLoopGuard::begin(TurnId(0)),
    );
    assert!(matches!(
        cycle.next_recovery().unwrap(),
        RequestRecoveryWork::Complete
    ));
    let output = agent
        .funded_provider_output_ceiling(iteron_provider::output_ceiling::ProviderOutputBudget {
            model: &agent.model,
            requested_max_tokens: cycle.requested_output(),
            thinking_budget: 0,
        })
        .unwrap();
    let (mut cycle, _) = cycle
        .bind_after_recovery(TurnId(0), agent.execution_context_window(), output)
        .unwrap();
    agent.fail_next_durable_append = Some(DurableAppendFault::BestEffort);
    let (journal, events) = agent.request_admission_ports(TurnId(0));
    assert!(cycle.validate(journal, &events).is_err());
    assert!(agent.record_failed);
    let (journal, events) = agent.request_admission_ports(TurnId(0));
    assert!(cycle.validate(journal, &events).is_err());
    assert!(cycle.request_gate().is_err());
    drop(cycle);
    let path = agent.rollout.path().to_path_buf();
    drop(agent);
    let events = iteron_record::replay(&path).unwrap();
    assert!(!events.iter().any(|event| matches!(
        event.kind,
        EventKind::EffectIntent { .. } | EventKind::TurnStart
    )));
    std::fs::remove_dir_all(directory).unwrap();
}
