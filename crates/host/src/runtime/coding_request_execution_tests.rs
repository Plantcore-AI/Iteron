use super::super::coding_run_driver::CodingRunDriver;
use super::super::gate_integration_tests::{agent_for, record_test_genesis, temp_ws};
use super::super::{DurableAppendFault, HookDecision};
use iteron_protocol::{EventKind, Message, TurnId};
use std::time::Instant;

fn owned_request(agent: &mut super::super::Agent, messages: Vec<Message>) -> CodingRunDriver {
    let mut driver = CodingRunDriver::new(messages);
    driver.begin_iteration(TurnId(0)).unwrap();
    let seed = agent
        .request_cycle_seed(
            TurnId(0),
            &[],
            "read implementation",
            driver.convergence(),
            Instant::now(),
        )
        .unwrap();
    driver
        .prepare_request(seed, &mut agent.context_estimator)
        .unwrap();
    assert!(matches!(
        driver.request_mut().unwrap().next_recovery().unwrap(),
        super::super::request_recovery_driver::RequestRecoveryWork::Complete
    ));
    let output = agent
        .funded_provider_output_ceiling(iteron_provider::output_ceiling::ProviderOutputBudget {
            model: &agent.model,
            requested_max_tokens: driver.request().unwrap().requested_output().unwrap(),
            thinking_budget: 0,
        })
        .unwrap();
    driver
        .request_mut()
        .unwrap()
        .bind(TurnId(0), agent.execution_context_window(), output)
        .unwrap();
    driver
}

#[test]
fn actual_phase_append_refusal_retains_owned_transcript_without_dispatch() {
    let directory = temp_ws("owned-coding-request-phase-refusal");
    let mut agent = agent_for(&directory);
    record_test_genesis(&mut agent, &directory);
    let messages = vec![Message::user_text("continue the admitted working history")];
    let expected = serde_json::to_vec(&messages).unwrap();
    let mut driver = owned_request(&mut agent, messages);
    agent.fail_next_durable_append = Some(DurableAppendFault::BestEffort);
    let (journal, events) = agent.request_admission_ports(TurnId(0));
    assert!(
        driver
            .request_mut()
            .unwrap()
            .validate(journal, &events)
            .is_err()
    );
    assert!(agent.record_failed);
    assert_eq!(
        serde_json::to_vec(&driver.into_messages().unwrap()).unwrap(),
        expected
    );
    let path = agent.rollout.path().to_path_buf();
    drop(agent);
    assert!(
        !iteron_record::replay(&path)
            .unwrap()
            .iter()
            .any(|event| matches!(
                event.kind,
                EventKind::TurnStart | EventKind::EffectIntent { .. }
            ))
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn denied_actual_context_gate_keeps_the_same_owned_working_set_and_cannot_complete() {
    let directory = temp_ws("owned-coding-request-denied-gate");
    let mut agent = agent_for(&directory);
    record_test_genesis(&mut agent, &directory);
    let messages = vec![Message::user_text("keep previous admitted turns")];
    let expected = serde_json::to_vec(&messages).unwrap();
    let mut driver = owned_request(&mut agent, messages);
    let (journal, events) = agent.request_admission_ports(TurnId(0));
    driver
        .request_mut()
        .unwrap()
        .validate(journal, &events)
        .unwrap();
    driver.request_mut().unwrap().request_gate().unwrap();
    assert!(
        driver
            .request_mut()
            .unwrap()
            .gate_completed(HookDecision::Deny("fixture refusal".into()))
            .is_err()
    );
    assert!(driver.request_mut().unwrap().control_passed().is_err());
    assert_eq!(
        serde_json::to_vec(&driver.into_messages().unwrap()).unwrap(),
        expected
    );
    let path = agent.rollout.path().to_path_buf();
    drop(agent);
    assert!(
        !iteron_record::replay(&path)
            .unwrap()
            .iter()
            .any(|event| matches!(
                event.kind,
                EventKind::TurnStart | EventKind::EffectIntent { .. }
            ))
    );
    std::fs::remove_dir_all(directory).unwrap();
}
