use super::*;
use crate::{
    DataClass, DataGovernance, EVOLUTION_SCHEMA_VERSION, PolicyBundle, RetentionTrainingUse,
    RewardVector, StrategyDecision, StrategySlot, TrainingAdmissionPolicy, TrainingConsent,
    TrajectoryEnvelope,
};
use iteron_protocol::{RunId, TenantId};
use serde_json::json;
use std::collections::BTreeMap;

const D: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const E: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn model() -> BaseModelId {
    BaseModelId {
        model_family: "anthropic/claude".into(),
        model_id: "claude-fable-5".into(),
        model_digest: "c".repeat(64),
    }
}

fn training_policy() -> TrainingAdmissionPolicy {
    TrainingAdmissionPolicy::new(
        ["apache-2.0".to_owned()].into(),
        [("training-v1".to_owned(), RetentionTrainingUse::Allowed)].into(),
    )
    .unwrap()
}

fn envelope() -> TrajectoryEnvelope {
    let policy = PolicyRef {
        slot: StrategySlot::tool_policy(),
        policy_id: "baseline".into(),
        version: "1.0.0".into(),
        digest: D.into(),
    };
    let mut envelope = TrajectoryEnvelope {
        schema_version: EVOLUTION_SCHEMA_VERSION,
        run_id: RunId("run-preference".into()),
        tenant_id: TenantId::default(),
        task_id: "train-preference".into(),
        domain: "coding".into(),
        environment_digest: D.into(),
        bundle: PolicyBundle {
            bundle_id: "baseline-bundle".into(),
            digest: D.into(),
            policies: vec![policy.clone()],
            rollback_to: None,
        },
        decisions: Vec::new(),
        terminal_outcome: "completed".into(),
        reward: RewardVector {
            task_score: 1.0,
            correctness: 1.0,
            safety_violations: 0,
            policy_violations: 0,
            cost_usd: 0.01,
            wall_time_ms: 10,
            human_acceptance: Some(0.9),
            domain: BTreeMap::new(),
        },
        governance: DataGovernance {
            class: DataClass::Public,
            consent: TrainingConsent::Allowed,
            content_license: Some("apache-2.0".into()),
            contains_secret_material: false,
            retention_policy: "training-v1".into(),
        },
    };
    crate::EvidenceRecorder::new()
        .record_decision(
            &mut envelope,
            StrategyDecision {
                decision_id: "decision-0".into(),
                ordinal: 0,
                policy,
                observation_digest: D.into(),
                candidate_set_digest: D.into(),
                action: json!({"tool":"grep"}),
                action_digest: D.into(),
                propensity: Some(1.0),
            },
        )
        .unwrap();
    envelope
}

#[test]
fn second_producer_emits_frozen_prompt_and_preference_variants() {
    let envelope = envelope();
    let proof = training_policy().admit(&envelope).unwrap();
    let dataset = GovernedTrainingDataset::new(&[proof]).unwrap();
    let baseline = envelope.bundle.policies[0].clone();
    let admission =
        ManifestAdmissionPolicy::new(StrategySlot::tool_policy(), [Capability::ReadOnly].into())
            .with_parent_ceiling(crate::ParentCapabilityCeiling::new(
                baseline.clone(),
                [Capability::ReadOnly].into(),
            ));
    let spec = PromptPreferenceSpec::new(
        "prompt-policy",
        model(),
        "1.0.0",
        Some(baseline),
        ProtocolRange { min: 1, max: 1 },
        [Capability::ReadOnly].into(),
        E,
        vec![
            PromptPreferenceCandidate::new(
                "preferred",
                "coding",
                "completed",
                "Prefer repository-native read-only search.",
            )
            .unwrap(),
            PromptPreferenceCandidate::new(
                "unused",
                "support",
                "completed",
                "Use the support escalation template.",
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let produced = PromptPreferenceProducer::new()
        .produce(&dataset, &admission, &spec)
        .unwrap();
    assert_eq!(produced.manifest().artifact_kind, ArtifactKind::Prompt);
    assert_eq!(
        produced.manifest().method,
        EvolutionMethod::PreferenceOptimization
    );
    assert_eq!(produced.selected_candidate_id(), "preferred");
    assert!(produced.manifest().validate().is_ok());
    assert_eq!(
        produced.capability_admission().required(),
        &[Capability::ReadOnly].into()
    );
}
