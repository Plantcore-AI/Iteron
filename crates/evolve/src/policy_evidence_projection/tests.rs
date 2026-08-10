use super::*;
use crate::{
    DataClass, RetentionTrainingUse, TrainingConsent, TrajectoryIngest, TrajectoryRegistry,
};
use core_protocol::{
    POLICY_DECISION_EVIDENCE_SCHEMA_VERSION, POLICY_OUTCOME_EVIDENCE_SCHEMA_VERSION,
    PolicyActionId, PolicyDecisionDisposition, PolicyOpportunityId, PolicyOutcomeScope,
    PolicyRuntimeIdentity, TurnId, slot::SlotId,
};
use std::path::PathBuf;

const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn training_policy() -> TrainingAdmissionPolicy {
    TrainingAdmissionPolicy::new(
        ["apache-2.0".to_owned()].into(),
        [("training-v1".to_owned(), RetentionTrainingUse::Allowed)].into(),
    )
    .unwrap()
}

fn identity() -> PolicyRuntimeIdentity {
    PolicyRuntimeIdentity {
        bundle_id: "bundle-v1".into(),
        bundle_digest_sha256: DIGEST_A.into(),
        policy_id: "core-router-baseline-v1".into(),
        policy_version: "1.0.0".into(),
        policy_digest_sha256: DIGEST_B.into(),
    }
}

fn decision(ordinal: u64, turn: u32) -> PolicyDecisionEvidence {
    PolicyDecisionEvidence {
        schema_version: POLICY_DECISION_EVIDENCE_SCHEMA_VERSION,
        opportunity_id: PolicyOpportunityId(format!("route:{ordinal}")),
        run_id: RunId("run-policy-1".into()),
        turn_id: Some(TurnId(turn)),
        slot: SlotId("core/router".into()),
        policy: identity(),
        eligible_actions: vec![
            PolicyActionId("direct".into()),
            PolicyActionId("fan".into()),
        ],
        selected_action: Some(PolicyActionId("direct".into())),
        disposition: PolicyDecisionDisposition::Selected,
        selected_score_micros: Some(-3),
        propensity_ppm: Some(750_000),
        feature_schema_id: "core:router-features-v1".into(),
        feature_digest_sha256: DIGEST_C.into(),
        fixed_invariants_digest_sha256: DIGEST_A.into(),
        tunables_digest_sha256: DIGEST_B.into(),
        decision_ordinal: ordinal,
        decided_at_us: ordinal + 5,
    }
}

fn joined_outcome(
    scope: PolicyOutcomeScope,
    turn: Option<u32>,
    decisions: &[PolicyDecisionEvidence],
    ordinal: u64,
    terminal: PolicyTerminalOutcome,
) -> PolicyOutcomeEvidence {
    let mut join = PolicyOpportunityJoinDigest::default();
    for decision in decisions
        .iter()
        .filter(|decision| turn.is_none() || decision.turn_id.map(|id| id.0) == turn)
    {
        join.append(&decision.opportunity_id).unwrap();
    }
    PolicyOutcomeEvidence {
        schema_version: POLICY_OUTCOME_EVIDENCE_SCHEMA_VERSION,
        scope,
        run_id: RunId("run-policy-1".into()),
        turn_id: turn.map(TurnId),
        terminal,
        opportunity_count: join.count(),
        opportunities_digest_sha256: join.digest_sha256(),
        quality_micros: Some(if terminal == PolicyTerminalOutcome::Succeeded {
            900_000
        } else {
            0
        }),
        cost_microusd: Some(45),
        input_tokens: Some(100),
        output_tokens: Some(10),
        latency_us: 1_500,
        verifier: if terminal == PolicyTerminalOutcome::Succeeded {
            PolicyVerifierOutcome::Passed
        } else {
            PolicyVerifierOutcome::TestFailure
        },
        harness_error_code: (terminal != PolicyTerminalOutcome::Succeeded)
            .then(|| "turn_failure".into()),
        outcome_ordinal: ordinal,
    }
}

fn fixture(terminal: PolicyTerminalOutcome) -> PolicyEvidenceRunFixture {
    let decisions = vec![decision(0, 1), decision(1, 1)];
    let turn = joined_outcome(PolicyOutcomeScope::Turn, Some(1), &decisions, 0, terminal);
    let mut run = joined_outcome(PolicyOutcomeScope::Run, None, &decisions, 1, terminal);
    run.quality_micros = turn.quality_micros;
    run.latency_us = turn.latency_us;
    run.verifier = turn.verifier;
    run.harness_error_code = turn.harness_error_code.clone();
    let mut fixture = PolicyEvidenceRunFixture {
        schema_version: POLICY_EVIDENCE_RUN_SCHEMA_VERSION,
        rollout_digest: DIGEST_A.into(),
        checkpoint_digest: DIGEST_C.into(),
        run_id: RunId("run-policy-1".into()),
        tenant_id: TenantId::default(),
        task_id: "task-policy-1".into(),
        domain: "coding".into(),
        bundle: PolicyBundle {
            bundle_id: "bundle-v1".into(),
            digest: DIGEST_A.into(),
            policies: vec![PolicyRef {
                slot: StrategySlot::router(),
                policy_id: "core-router-baseline-v1".into(),
                version: "1.0.0".into(),
                digest: DIGEST_B.into(),
            }],
            rollback_to: None,
        },
        decisions,
        outcomes: vec![turn, run],
        reward_context: PolicyProjectionRewardContext {
            safety_violations: 0,
            policy_violations: 0,
            human_acceptance: None,
            domain: BTreeMap::new(),
        },
        governance: DataGovernance {
            class: DataClass::Public,
            consent: TrainingConsent::Allowed,
            content_license: Some("apache-2.0".into()),
            contains_secret_material: false,
            retention_policy: "training-v1".into(),
        },
        training_revoked: false,
    };
    fixture.rollout_digest = fixture.canonical_rollout_digest().unwrap();
    fixture
}

fn scratch() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "core-evolve-policy-evidence-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn projection_preserves_exact_decision_and_outcome_join() {
    let fixture = fixture(PolicyTerminalOutcome::Succeeded);
    let digest = fixture.rollout_digest.clone();
    let projector =
        PolicyEvidenceRunProjector::new(vec![fixture.clone()], training_policy()).unwrap();
    let envelope = projector.project_by_digest(&digest).unwrap().unwrap();
    assert_eq!(envelope.decisions.len(), 2);
    assert_eq!(envelope.terminal_outcome, "succeeded");
    let action = &envelope.decisions[0].action;
    assert_eq!(
        action["policy_decision_evidence"]["opportunity_id"],
        fixture.decisions[0].opportunity_id.0
    );
    assert_eq!(
        action["turn_outcome_evidence"]["opportunities_digest_sha256"],
        fixture.outcomes[0].opportunities_digest_sha256
    );
    assert_eq!(
        action["run_outcome_evidence"]["input_tokens"],
        fixture.outcomes[1].input_tokens.unwrap()
    );
}

#[test]
fn missing_duplicate_cross_run_and_join_tampering_fail_closed() {
    let mut missing = fixture(PolicyTerminalOutcome::Succeeded);
    missing.outcomes.remove(0);
    missing.rollout_digest = missing.canonical_rollout_digest().unwrap();
    assert!(matches!(
        PolicyEvidenceRunProjector::new(vec![missing], training_policy()),
        Err(PolicyEvidenceRunProjectorError::InvalidOutcomeOrder)
    ));

    let mut duplicate = fixture(PolicyTerminalOutcome::Succeeded);
    duplicate.decisions[1].opportunity_id = duplicate.decisions[0].opportunity_id.clone();
    duplicate.rollout_digest = duplicate.canonical_rollout_digest().unwrap();
    assert!(matches!(
        PolicyEvidenceRunProjector::new(vec![duplicate], training_policy()),
        Err(PolicyEvidenceRunProjectorError::InvalidDecisionOrder)
    ));

    let mut cross_run = fixture(PolicyTerminalOutcome::Succeeded);
    cross_run.decisions[1].run_id = RunId("run-other".into());
    cross_run.rollout_digest = cross_run.canonical_rollout_digest().unwrap();
    assert!(matches!(
        PolicyEvidenceRunProjector::new(vec![cross_run], training_policy()),
        Err(PolicyEvidenceRunProjectorError::CrossRunIdentity)
    ));

    let mut bad_join = fixture(PolicyTerminalOutcome::Succeeded);
    bad_join.outcomes[0].opportunity_count = 1;
    bad_join.rollout_digest = bad_join.canonical_rollout_digest().unwrap();
    assert!(matches!(
        PolicyEvidenceRunProjector::new(vec![bad_join], training_policy()),
        Err(PolicyEvidenceRunProjectorError::OutcomeJoinMismatch)
    ));
}

#[test]
fn failed_trajectory_is_retained_and_ingests_into_governed_registry() {
    let fixture = fixture(PolicyTerminalOutcome::Failed);
    let digest = fixture.rollout_digest.clone();
    let projector = PolicyEvidenceRunProjector::new(vec![fixture], training_policy()).unwrap();
    let envelope = projector.project_by_digest(&digest).unwrap().unwrap();
    assert_eq!(envelope.terminal_outcome, "failed");
    assert_eq!(envelope.reward.task_score, 0.0);

    let root = scratch();
    let mut registry = TrajectoryRegistry::open(&root).unwrap();
    assert!(matches!(
        registry.ingest(&envelope).unwrap(),
        TrajectoryIngest::Stored(_)
    ));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn revoked_evidence_is_not_projected() {
    let mut fixture = fixture(PolicyTerminalOutcome::Failed);
    fixture.training_revoked = true;
    let digest = fixture.rollout_digest.clone();
    let projector = PolicyEvidenceRunProjector::new(vec![fixture], training_policy()).unwrap();
    assert!(projector.project_by_digest(&digest).unwrap().is_none());
}
