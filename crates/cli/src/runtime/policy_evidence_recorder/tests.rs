use super::*;
use iteron_protocol::{
    PolicyActionId, PolicyDecisionDisposition, PolicyTerminalOutcome, PolicyVerifierOutcome,
    TenantId, policy_evidence::PolicyEvidenceError, slot::SlotId,
};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

fn digest(seed: char) -> String {
    std::iter::repeat_n(seed, 64).collect()
}

fn bindings() -> Vec<FrozenSlotPolicyBinding> {
    FROZEN_POLICY_SLOT_NAMES
        .iter()
        .enumerate()
        .map(|(index, slot)| FrozenSlotPolicyBinding {
            slot: SlotId((*slot).to_owned()),
            policy: PolicyRuntimeIdentity {
                bundle_id: "iteron:runtime-bundle-v1".into(),
                bundle_digest_sha256: digest('a'),
                policy_id: format!("iteron:policy:{index}"),
                policy_version: "1.0.0".into(),
                policy_digest_sha256: digest('b'),
            },
        })
        .collect()
}

fn recorder(run: &str) -> PolicyEvidenceRecorder {
    PolicyEvidenceRecorder::new(RunId(run.into()), digest('f'), bindings()).unwrap()
}

fn rollout(label: &str, run: &str) -> (std::path::PathBuf, iteron_record::Rollout) {
    let root = std::env::temp_dir().join(format!(
        "core-policy-evidence-{label}-{}-{}",
        std::process::id(),
        NEXT_TEST.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).unwrap();
    let rollout =
        iteron_record::Rollout::open(&root, &RunId(run.into()), TenantId::default()).unwrap();
    (root, rollout)
}

fn decision(action: &str) -> PolicyDecisionInput {
    PolicyDecisionInput {
        eligible_actions: vec![PolicyActionId(action.into())],
        selected_action: Some(PolicyActionId(action.into())),
        disposition: PolicyDecisionDisposition::Selected,
        selected_score_micros: Some(42),
        propensity_ppm: Some(1_000_000),
        feature_schema_id: "iteron:policy-features-v1".into(),
        feature_digest_sha256: digest('c'),
        fixed_invariants_digest_sha256: digest('d'),
    }
}

fn outcome() -> PolicyOutcomeInput {
    PolicyOutcomeInput {
        terminal: PolicyTerminalOutcome::Succeeded,
        quality_micros: Some(900_000),
        cost_microusd: Some(15),
        input_tokens: Some(100),
        output_tokens: Some(20),
        latency_us: 10_000,
        verifier: PolicyVerifierOutcome::Passed,
        harness_error_code: None,
    }
}

fn aggregate_outcome(recorder: &PolicyEvidenceRecorder) -> PolicyOutcomeInput {
    let aggregate = recorder.run_aggregate();
    PolicyOutcomeInput {
        terminal: aggregate.terminal,
        quality_micros: aggregate.quality_micros,
        cost_microusd: Some(15),
        input_tokens: Some(100),
        output_tokens: Some(20),
        latency_us: aggregate.latency_us,
        verifier: aggregate.verifier,
        harness_error_code: aggregate.has_harness_error.then(|| "turn_failure".into()),
    }
}

fn append_selected(
    recorder: &mut PolicyEvidenceRecorder,
    rollout: &mut iteron_record::Rollout,
    slot: &str,
    turn: TurnId,
    action: &str,
) -> iteron_protocol::PolicyDecisionEvidence {
    let opportunity = recorder
        .begin_opportunity(&SlotId(slot.into()), Some(turn))
        .unwrap();
    recorder
        .append_decision(rollout, &opportunity, decision(action))
        .unwrap();
    let events = iteron_record::replay(rollout.path()).unwrap();
    let EventKind::PolicyDecision { evidence } = events.last().unwrap().kind.clone() else {
        panic!("last durable event is not a policy decision")
    };
    evidence
}

#[test]
fn every_frozen_slot_is_durable_unique_and_monotone() {
    let run = "run-nine-slots";
    let (root, mut rollout) = rollout("nine", run);
    let mut recorder = recorder(run);
    let mut ids = BTreeSet::new();
    let mut previous_timestamp = None;

    for (ordinal, slot) in FROZEN_POLICY_SLOT_NAMES.iter().enumerate() {
        let evidence = append_selected(&mut recorder, &mut rollout, slot, TurnId(7), "baseline");
        assert!(evidence.opportunity_id.0.len() <= iteron_protocol::MAX_POLICY_MACHINE_ID_BYTES);
        assert!(ids.insert(evidence.opportunity_id.0.clone()));
        assert_eq!(evidence.slot.as_persisted_str(), *slot);
        assert_eq!(evidence.decision_ordinal, ordinal as u64);
        assert_eq!(evidence.run_id, RunId(run.into()));
        assert_eq!(evidence.tunables_digest_sha256, digest('f'));
        assert_eq!(evidence.policy.bundle_digest_sha256, digest('a'));
        if let Some(previous) = previous_timestamp {
            assert!(evidence.decided_at_us > previous);
        }
        previous_timestamp = Some(evidence.decided_at_us);
        evidence.validate().unwrap();
    }

    assert_eq!(ids.len(), FROZEN_POLICY_SLOT_COUNT);
    assert_eq!(
        recorder.turn_join(TurnId(7)).opportunity_count,
        FROZEN_POLICY_SLOT_COUNT as u32
    );
    assert_eq!(recorder.run_join(), recorder.turn_join(TurnId(7)));
    drop(rollout);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn invalid_or_duplicate_decisions_do_not_consume_an_opportunity() {
    let run = "run-invalid";
    let (root, mut rollout) = rollout("invalid", run);
    let mut recorder = recorder(run);
    assert!(matches!(
        recorder.begin_opportunity(&SlotId("core/not_frozen".into()), Some(TurnId(1))),
        Err(PolicyEvidenceRecorderError::UnknownSlot(_))
    ));

    let opportunity = recorder
        .begin_opportunity(&SlotId("core/router".into()), Some(TurnId(1)))
        .unwrap();
    let mut invalid_selection = decision("eligible");
    invalid_selection.selected_action = Some(PolicyActionId("not-eligible".into()));
    assert!(matches!(
        recorder.append_decision(&mut rollout, &opportunity, invalid_selection),
        Err(PolicyEvidenceRecorderError::SelectedActionNotEligible(_))
    ));
    let mut invalid_set = decision("eligible");
    invalid_set
        .eligible_actions
        .push(PolicyActionId("eligible".into()));
    assert!(matches!(
        recorder.append_decision(&mut rollout, &opportunity, invalid_set),
        Err(PolicyEvidenceRecorderError::InvalidEvidence(
            PolicyEvidenceError::InvalidActionSet
        ))
    ));
    recorder
        .append_decision(&mut rollout, &opportunity, decision("eligible"))
        .unwrap();
    assert!(matches!(
        recorder.append_decision(&mut rollout, &opportunity, decision("eligible")),
        Err(PolicyEvidenceRecorderError::DuplicateOpportunity(_))
    ));
    drop(rollout);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn opportunity_tokens_are_bound_to_one_run_and_recorder() {
    let (root, mut rollout) = rollout("ownership", "run-first");
    let mut first = recorder("run-first");
    let token = first
        .begin_opportunity(&SlotId("core/context".into()), Some(TurnId(1)))
        .unwrap();
    let mut other_run = recorder("run-second");
    assert!(matches!(
        other_run.append_decision(&mut rollout, &token, decision("baseline")),
        Err(PolicyEvidenceRecorderError::CrossRunOpportunity)
    ));
    let mut same_run_other_recorder = recorder("run-first");
    assert!(matches!(
        same_run_other_recorder.append_decision(&mut rollout, &token, decision("baseline")),
        Err(PolicyEvidenceRecorderError::CrossRecorderOpportunity)
    ));
    drop(rollout);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn pending_opportunities_block_terminal_outcomes() {
    let run = "run-pending";
    let (root, mut rollout) = rollout("pending", run);
    let mut recorder = recorder(run);
    let opportunity = recorder
        .begin_opportunity(&SlotId("core/memory".into()), Some(TurnId(1)))
        .unwrap();
    let empty_turn = recorder.turn_join(TurnId(1));
    assert!(matches!(
        recorder.append_turn_outcome(&mut rollout, TurnId(1), &empty_turn, outcome()),
        Err(PolicyEvidenceRecorderError::PendingOpportunities)
    ));
    let empty_run = recorder.run_join();
    assert!(matches!(
        recorder.append_run_outcome(&mut rollout, TurnId(1), &empty_run, outcome()),
        Err(PolicyEvidenceRecorderError::PendingOpportunities)
    ));

    recorder
        .append_decision(&mut rollout, &opportunity, decision("recall"))
        .unwrap();
    let turn_join = recorder.turn_join(TurnId(1));
    recorder
        .append_turn_outcome(&mut rollout, TurnId(1), &turn_join, outcome())
        .unwrap();
    let run_join = recorder.run_join();
    let run_outcome = aggregate_outcome(&recorder);
    recorder
        .append_run_outcome(&mut rollout, TurnId(1), &run_join, run_outcome)
        .unwrap();
    assert!(recorder.is_run_terminal());
    drop(rollout);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn replay_restores_joins_ordinals_and_terminal_guards() {
    let run = "run-restore";
    let (root, mut rollout) = rollout("restore", run);
    let mut first = recorder(run);
    append_selected(&mut first, &mut rollout, "core/router", TurnId(1), "direct");
    let turn_one = first.turn_join(TurnId(1));
    first
        .append_turn_outcome(&mut rollout, TurnId(1), &turn_one, outcome())
        .unwrap();
    let path = rollout.path().to_path_buf();
    drop(rollout);

    let events = iteron_record::replay_timed(&path).unwrap();
    let mut restored =
        PolicyEvidenceRecorder::restore(RunId(run.into()), digest('f'), bindings(), &events)
            .unwrap();
    assert!(restored.is_turn_terminal(TurnId(1)));
    assert!(matches!(
        restored.begin_opportunity(&SlotId("core/router".into()), Some(TurnId(1))),
        Err(PolicyEvidenceRecorderError::TurnAlreadyTerminal(TurnId(1)))
    ));

    let mut reopened =
        iteron_record::Rollout::open(&root, &RunId(run.into()), TenantId::default()).unwrap();
    let evidence = append_selected(
        &mut restored,
        &mut reopened,
        "core/context",
        TurnId(2),
        "materialize",
    );
    assert_eq!(evidence.decision_ordinal, 1);
    assert_eq!(restored.run_join().opportunity_count, 2);
    drop(reopened);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn turn_and_run_outcomes_commit_exact_order_once() {
    let run = "run-outcome-join";
    let (root, mut rollout) = rollout("outcomes", run);
    let mut recorder = recorder(run);
    append_selected(
        &mut recorder,
        &mut rollout,
        "core/router",
        TurnId(1),
        "direct",
    );
    append_selected(
        &mut recorder,
        &mut rollout,
        "core/context",
        TurnId(2),
        "workspace",
    );
    append_selected(
        &mut recorder,
        &mut rollout,
        "core/planner",
        TurnId(1),
        "fan",
    );

    let turn_one = recorder.turn_join(TurnId(1));
    let mut wrong = turn_one.clone();
    wrong.opportunity_count += 1;
    assert!(matches!(
        recorder.append_turn_outcome(&mut rollout, TurnId(1), &wrong, outcome()),
        Err(PolicyEvidenceRecorderError::OutcomeJoinMismatch)
    ));
    recorder
        .append_turn_outcome(&mut rollout, TurnId(1), &turn_one, outcome())
        .unwrap();
    assert!(matches!(
        recorder.append_turn_outcome(&mut rollout, TurnId(1), &turn_one, outcome()),
        Err(PolicyEvidenceRecorderError::TurnAlreadyTerminal(TurnId(1)))
    ));
    let run_join = recorder.run_join();
    assert!(matches!(
        recorder.append_run_outcome(&mut rollout, TurnId(2), &run_join, outcome()),
        Err(PolicyEvidenceRecorderError::MissingTurnOutcome(TurnId(2)))
    ));
    let turn_two = recorder.turn_join(TurnId(2));
    recorder
        .append_turn_outcome(&mut rollout, TurnId(2), &turn_two, outcome())
        .unwrap();
    let run_outcome = aggregate_outcome(&recorder);
    recorder
        .append_run_outcome(&mut rollout, TurnId(2), &run_join, run_outcome.clone())
        .unwrap();
    assert!(matches!(
        recorder.append_run_outcome(&mut rollout, TurnId(2), &run_join, run_outcome),
        Err(PolicyEvidenceRecorderError::RunAlreadyTerminal)
    ));

    let serialized =
        serde_json::to_string(&iteron_record::replay(rollout.path()).unwrap()).unwrap();
    for forbidden in ["prompt", "path", "arguments", "tool_args", "source_text"] {
        assert!(!serialized.contains(forbidden));
    }
    drop(rollout);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn graceful_close_begins_a_new_policy_run_while_crash_restore_keeps_the_open_one() {
    let run = RunId("run-segments".into());
    let (root, mut rollout) = rollout("segments", &run.0);
    let mut first = recorder(&run.0);
    append_selected(&mut first, &mut rollout, "core/router", TurnId(1), "direct");
    let path = rollout.path().to_path_buf();
    drop(rollout);

    let events = iteron_record::replay_timed(&path).unwrap();
    let mut crash_restored =
        PolicyEvidenceRecorder::restore_or_begin(&run, digest('f'), bindings(), &events).unwrap();
    assert_eq!(crash_restored.run_id, run);
    assert_eq!(crash_restored.next_decision_ordinal, 1);

    let mut reopened = iteron_record::Rollout::open(&root, &run, TenantId::default()).unwrap();
    let turn_join = crash_restored.turn_join(TurnId(1));
    crash_restored
        .append_turn_outcome(&mut reopened, TurnId(1), &turn_join, outcome())
        .unwrap();
    let run_join = crash_restored.run_join();
    let run_outcome = aggregate_outcome(&crash_restored);
    crash_restored
        .append_run_outcome(&mut reopened, TurnId(1), &run_join, run_outcome)
        .unwrap();
    drop(reopened);

    let events = iteron_record::replay_timed(&path).unwrap();
    let next =
        PolicyEvidenceRecorder::restore_or_begin(&run, digest('f'), bindings(), &events).unwrap();
    assert_ne!(next.run_id, run);
    assert_eq!(next.next_decision_ordinal, 0);
    assert!(!next.is_run_terminal());
    std::fs::remove_dir_all(root).unwrap();
}
