use super::*;
use crate::{
    DataClass, DataGovernance, GovernedDatasetError, PolicyBundle, RetentionTrainingUse,
    RewardVector, StrategySlot, TrainingAdmissionPolicy, TrainingConsent, TrajectoryEnvelope,
};
use iteron_protocol::{RunId, TenantId};
use std::collections::BTreeMap;

const D: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const EVAL_D: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

fn training_policy() -> TrainingAdmissionPolicy {
    TrainingAdmissionPolicy::new(
        ["apache-2.0".to_owned()].into(),
        [("training-v1".to_owned(), RetentionTrainingUse::Allowed)].into(),
    )
    .unwrap()
}

fn envelope(run_id: &str, license: &str, domain: &str, outcome: &str) -> TrajectoryEnvelope {
    let policy = PolicyRef {
        slot: StrategySlot::router(),
        policy_id: "router-a".into(),
        version: "1.0.0".into(),
        digest: D.into(),
    };
    TrajectoryEnvelope {
        schema_version: crate::EVOLUTION_SCHEMA_VERSION,
        run_id: RunId(run_id.into()),
        tenant_id: TenantId::default(),
        task_id: format!("task-{run_id}"),
        domain: domain.into(),
        environment_digest: D.into(),
        bundle: PolicyBundle {
            bundle_id: "bundle-a".into(),
            digest: D.into(),
            policies: vec![policy],
            rollback_to: None,
        },
        decisions: Vec::new(),
        terminal_outcome: outcome.into(),
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
            content_license: Some(license.into()),
            contains_secret_material: false,
            retention_policy: "training-v1".into(),
        },
    }
}

fn governed_dataset<'a>(envelopes: &'a [TrajectoryEnvelope]) -> GovernedTrainingDataset<'a> {
    let policy = training_policy();
    let proofs: Vec<_> = envelopes
        .iter()
        .map(|envelope| policy.admit(envelope).unwrap())
        .collect();
    GovernedTrainingDataset::new(&proofs).unwrap()
}

fn candidates() -> Vec<OfflineRuleCandidate> {
    vec![
        OfflineRuleCandidate::new("prefer-completed", "coding", "completed").unwrap(),
        OfflineRuleCandidate::new("prefer-failed", "coding", "failed").unwrap(),
    ]
}

/// A real, admissible base model. The producer refuses the migration sentinel: a candidate being
/// minted now knows what it searched against, unlike a document recovered from schema 2.
fn base_model() -> BaseModelId {
    BaseModelId {
        model_family: "anthropic/claude".into(),
        model_id: "claude-opus-5".into(),
        model_digest: "b".repeat(64),
    }
}

fn spec(required: &[Capability], evaluation_digest: &str) -> OfflineRuleSearchSpec {
    OfflineRuleSearchSpec::new(
        "searched-router",
        base_model(),
        "1.0.0",
        None,
        ProtocolRange { min: 1, max: 1 },
        required.iter().copied().collect(),
        evaluation_digest,
        candidates(),
    )
    .unwrap()
}

fn admission_policy() -> ManifestAdmissionPolicy {
    ManifestAdmissionPolicy::new(StrategySlot::router(), [Capability::ReadOnly].into())
}

#[test]
fn producer_requires_governed_training_proofs() {
    let noncompliant = envelope("run-bad", "proprietary", "coding", "completed");
    assert!(matches!(
        training_policy().admit(&noncompliant),
        Err(crate::TrainingEligibilityError::LicenseNotAllowed { .. })
    ));
    assert!(matches!(
        GovernedTrainingDataset::new(&[]),
        Err(GovernedDatasetError::Empty)
    ));
}

#[test]
fn producer_rejects_capabilities_above_trusted_slot_ceiling() {
    let envelopes = [envelope("run-a", "apache-2.0", "coding", "completed")];
    let dataset = governed_dataset(&envelopes);
    let overprivileged = spec(&[Capability::IrreversibleExternal], EVAL_D);
    assert!(matches!(
        OfflineRuleSearchProducer::new().produce(&dataset, &admission_policy(), &overprivileged),
        Err(OfflineProducerError::CapabilityAdmission(
            CapabilityAdmissionError::ExceedsSlotCeiling { .. }
        ))
    ));
}

#[test]
fn same_governed_input_reproduces_artifact_and_candidate_digest() {
    let first_order = [
        envelope("run-b", "apache-2.0", "coding", "completed"),
        envelope("run-a", "apache-2.0", "docs", "completed"),
    ];
    let reverse_order = [first_order[1].clone(), first_order[0].clone()];
    let first_dataset = governed_dataset(&first_order);
    let second_dataset = governed_dataset(&reverse_order);
    assert_eq!(first_dataset.digest(), second_dataset.digest());

    let producer = OfflineRuleSearchProducer::new();
    let spec = spec(&[Capability::ReadOnly], EVAL_D);
    let first = producer
        .produce(&first_dataset, &admission_policy(), &spec)
        .unwrap();
    let second = producer
        .produce(&second_dataset, &admission_policy(), &spec)
        .unwrap();

    assert_eq!(first.artifact_bytes(), second.artifact_bytes());
    assert_eq!(first.candidate_digest(), second.candidate_digest());
    assert_eq!(first.selected_candidate_id(), "prefer-completed");
    assert_eq!(first.manifest().method, EvolutionMethod::Search);
    assert_eq!(first.manifest().artifact_kind, ArtifactKind::Rules);
    assert_eq!(
        first.manifest().training_dataset_digest.as_deref(),
        Some(first_dataset.digest())
    );
    assert_eq!(first.manifest().evaluation_suite_digest, EVAL_D);
    assert_eq!(
        first.manifest().required_capabilities,
        [Capability::ReadOnly].into()
    );
    assert_eq!(first.candidate_digest(), sha256_hex(first.artifact_bytes()));
    assert!(first.manifest().validate().is_ok());
}

#[test]
fn artifact_is_bounded_and_eval_digest_must_be_independent() {
    let envelopes = [envelope("run-a", "apache-2.0", "coding", "completed")];
    let dataset = governed_dataset(&envelopes);
    let producer = OfflineRuleSearchProducer::new();
    let output = producer
        .produce(
            &dataset,
            &admission_policy(),
            &spec(&[Capability::ReadOnly], EVAL_D),
        )
        .unwrap();
    assert!(output.artifact_bytes().len() <= MAX_INERT_RULE_ARTIFACT_BYTES);
    let artifact: serde_json::Value = serde_json::from_slice(output.artifact_bytes()).unwrap();
    assert_eq!(artifact["producer"], "offline_rule_search_v1");

    let same_as_training = spec(&[Capability::ReadOnly], dataset.digest());
    assert!(matches!(
        producer.produce(&dataset, &admission_policy(), &same_as_training),
        Err(OfflineProducerError::EvaluationSuiteMatchesTrainingDataset)
    ));
}
