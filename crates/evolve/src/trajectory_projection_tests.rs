use super::*;
use crate::{
    DataClass, DataGovernance, EvidenceRecorder, PolicyRef, RetentionTrainingUse, StrategySlot,
    TrainingConsent, TrajectoryIngest, TrajectoryRegistry,
};
use serde_json::json;
use std::path::PathBuf;

const ROLLOUT: &str = "3edacf248f211a90619068507b7cc46fa5707f17649c74819f2fefd60d9e5145";
const CHECKPOINT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const POLICY: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "iteron-evolve-record-projection-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn training_policy() -> TrainingAdmissionPolicy {
    TrainingAdmissionPolicy::new(
        ["apache-2.0".to_owned()].into(),
        [("training-v1".to_owned(), RetentionTrainingUse::Allowed)].into(),
    )
    .unwrap()
}

fn policy() -> PolicyRef {
    PolicyRef {
        slot: StrategySlot::router(),
        policy_id: "router-v1".into(),
        version: "1.0.0".into(),
        digest: POLICY.into(),
    }
}

fn fixture() -> RecordedRunFixture {
    let policy = policy();
    RecordedRunFixture {
        schema_version: RECORDED_RUN_FIXTURE_SCHEMA_VERSION,
        rollout_digest: ROLLOUT.into(),
        checkpoint_digest: CHECKPOINT.into(),
        run_id: RunId("run-recorded-1".into()),
        tenant_id: TenantId::default(),
        task_id: "training-task-1".into(),
        domain: "coding".into(),
        bundle: PolicyBundle {
            bundle_id: "training-bundle".into(),
            digest: POLICY.into(),
            policies: vec![policy.clone()],
            rollback_to: None,
        },
        decisions: vec![RecordedDecision {
            decision_id: "decision-0".into(),
            ordinal: 0,
            policy,
            observation_digest: CHECKPOINT.into(),
            candidate_set_digest: POLICY.into(),
            action: json!({"route": "safe"}),
            propensity: Some(1.0),
        }],
        terminal_outcome: "completed".into(),
        reward: RewardVector {
            task_score: 1.0,
            correctness: 1.0,
            safety_violations: 0,
            policy_violations: 0,
            cost_usd: 0.01,
            wall_time_ms: 10,
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
    }
}

fn rebind_digest(fixture: &mut RecordedRunFixture) {
    fixture.rollout_digest = fixture.canonical_rollout_digest().unwrap();
}

#[test]
fn recorded_run_fixture_projects_to_valid_envelope() {
    let projector = RecordedRunProjector::new(vec![fixture()], training_policy()).unwrap();
    let envelope = projector.project(ROLLOUT).unwrap().unwrap();
    assert_eq!(envelope.environment_digest, CHECKPOINT);
    assert_eq!(envelope.decisions.len(), 1);
    assert_ne!(envelope.decisions[0].action_digest, "0".repeat(64));
    EvidenceRecorder::new()
        .verify_trajectory(&envelope)
        .unwrap();
}

#[test]
fn projected_envelope_ingests_and_chain_verifies() {
    let projector = RecordedRunProjector::new(vec![fixture()], training_policy()).unwrap();
    let envelope = projector.project(ROLLOUT).unwrap().unwrap();
    let root = scratch("registry");
    let mut registry = TrajectoryRegistry::open(&root).unwrap();
    let stored = registry.ingest(&envelope).unwrap();
    assert!(matches!(stored, TrajectoryIngest::Stored(_)));
    assert_eq!(registry.len().unwrap(), 1);
    assert_eq!(
        registry
            .get_by_run(&envelope.run_id)
            .unwrap()
            .unwrap()
            .envelope,
        envelope
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn revoked_or_denied_consent_run_is_not_projected() {
    let mut revoked = fixture();
    revoked.training_revoked = true;
    let projector = RecordedRunProjector::new(vec![revoked], training_policy()).unwrap();
    assert!(projector.project(ROLLOUT).unwrap().is_none());

    let mut denied = fixture();
    denied.governance.consent = TrainingConsent::Denied;
    rebind_digest(&mut denied);
    let denied_digest = denied.rollout_digest.clone();
    let projector = RecordedRunProjector::new(vec![denied], training_policy()).unwrap();
    assert!(projector.project(&denied_digest).unwrap().is_none());
}

#[test]
fn recorded_fixture_digest_is_canonical_and_content_bound() {
    let fixture = fixture();
    assert_eq!(fixture.canonical_rollout_digest().unwrap(), ROLLOUT);

    let committed: RecordedRunFixture = serde_json::from_slice(include_bytes!(
        "../tests/fixtures/recorded-run-clean-v1.json"
    ))
    .unwrap();
    assert_eq!(
        committed.canonical_rollout_digest().unwrap(),
        "0722b7c0b2b2f35b340557421165459ab748e6bfa1355d30e398ebc9270439f9"
    );
}

#[test]
fn fixture_size_is_rejected_before_json_parsing() {
    assert!(matches!(
        RecordedRunFixture::from_json(&vec![b' '; MAX_RECORDED_RUN_FIXTURE_JSON_BYTES]),
        Err(RecordedRunProjectorError::InvalidFixtureJson(_))
    ));
    assert!(matches!(
        RecordedRunFixture::from_json(&vec![b' '; MAX_RECORDED_RUN_FIXTURE_JSON_BYTES + 1]),
        Err(RecordedRunProjectorError::FixtureTooLarge { .. })
    ));
}

#[test]
fn rollout_digest_rejects_mutated_record_content() {
    let mut reward = fixture();
    reward.reward.task_score = 0.5;
    let mut governance = fixture();
    governance.governance.content_license = Some("mit".into());
    let mut decision = fixture();
    decision.decisions[0].action = json!({"route": "changed"});
    let mut checkpoint = fixture();
    checkpoint.checkpoint_digest = "d".repeat(64);

    for mutated in [reward, governance, decision, checkpoint] {
        assert!(matches!(
            RecordedRunProjector::new(vec![mutated], training_policy()),
            Err(RecordedRunProjectorError::RolloutDigestMismatch)
        ));
    }
}

#[test]
fn decision_ids_and_ordinals_are_unique_and_canonical() {
    let mut duplicate_id = fixture();
    let mut second = duplicate_id.decisions[0].clone();
    second.ordinal = 1;
    duplicate_id.decisions.push(second);
    assert!(matches!(
        RecordedRunProjector::new(vec![duplicate_id], training_policy()),
        Err(RecordedRunProjectorError::DuplicateDecisionIdentity)
    ));

    let mut duplicate_ordinal = fixture();
    let mut second = duplicate_ordinal.decisions[0].clone();
    second.decision_id = "decision-1".into();
    duplicate_ordinal.decisions.push(second);
    assert!(matches!(
        RecordedRunProjector::new(vec![duplicate_ordinal], training_policy()),
        Err(RecordedRunProjectorError::DuplicateDecisionIdentity)
    ));

    let mut out_of_order = fixture();
    out_of_order.decisions[0].ordinal = 1;
    rebind_digest(&mut out_of_order);
    assert!(matches!(
        RecordedRunProjector::new(vec![out_of_order], training_policy()),
        Err(RecordedRunProjectorError::NonCanonicalDecisionOrder)
    ));
}
