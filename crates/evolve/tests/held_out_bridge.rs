use core_evolve::{
    BaseModelId, DeploymentStage, EvaluationSuite, EvaluationTask, GovernedTrainingDataset,
    HeldOutEvalReport, HeldOutEvidenceBridge, HeldOutEvidenceRegistration, HeldOutEvidenceStore,
    HeldOutTrainingCorpus, IndependentEvaluator, PromotionAssessment, PromotionAuthorityKey,
    PromotionGate, RecordedRunFixture, RecordedRunProjector, RetentionTrainingUse,
    TrainingAdmissionPolicy, TrajectoryProjection, VerifiedCandidateInputs,
};
use std::collections::{BTreeMap, BTreeSet};

const REPORT: &[u8] = include_bytes!("fixtures/held-out-report-clean-v1.json");
const TRAINING_RUN: &[u8] = include_bytes!("fixtures/recorded-run-clean-v1.json");

#[test]
fn fixture_drives_independent_evaluator_to_signed_evidence_to_promotion_gate() {
    let report = HeldOutEvalReport::from_json(REPORT).unwrap();
    let suite = EvaluationSuite::new(
        "held-out-owner",
        "fixture-v1",
        report
            .pairs
            .iter()
            .map(|pair| EvaluationTask {
                task_id: pair.task_id.clone(),
                fixture_digest: pair.fixture_digest.clone(),
            })
            .collect(),
    )
    .unwrap();
    let base_model = BaseModelId {
        model_family: "anthropic/claude".into(),
        model_id: "claude-fable-5".into(),
        model_digest: "5".repeat(64),
    };
    let training_policy = TrainingAdmissionPolicy::new(
        BTreeSet::from(["apache-2.0".to_owned()]),
        BTreeMap::from([("training-v1".to_owned(), RetentionTrainingUse::Allowed)]),
    )
    .unwrap();
    let training_fixture = RecordedRunFixture::from_json(TRAINING_RUN).unwrap();
    let rollout_digest = training_fixture.rollout_digest.clone();
    let projector =
        RecordedRunProjector::new(vec![training_fixture], training_policy.clone()).unwrap();
    let training_envelope = projector.project(&rollout_digest).unwrap().unwrap();
    let admitted = training_policy.admit(&training_envelope).unwrap();
    let governed = GovernedTrainingDataset::new(&[admitted]).unwrap();
    let corpus = HeldOutTrainingCorpus::from_governed(&governed);
    let verified = VerifiedCandidateInputs {
        artifact_digest: report.candidate.digest.clone(),
        training_dataset_digest: Some(governed.digest().to_owned()),
        evaluation_suite_digest: suite.digest().into(),
        base_model: base_model.clone(),
    };
    let candidate = report.candidate.clone();
    let evaluator = IndependentEvaluator::new(
        "independent-evaluator",
        PromotionAuthorityKey::new(vec![0x22; 32]).unwrap(),
    )
    .unwrap();
    let mut bridge = HeldOutEvidenceStore::new();
    assert_eq!(
        bridge
            .register(
                report,
                &candidate,
                &verified,
                Some(&corpus),
                &suite,
                &evaluator,
                &BTreeSet::from(["release-owner".to_owned()]),
            )
            .unwrap(),
        HeldOutEvidenceRegistration::Stored
    );

    let signed = bridge
        .evidence_for(&candidate.digest, &base_model)
        .unwrap()
        .unwrap();
    assert_eq!(signed.evaluator_id(), "independent-evaluator");
    assert_eq!(signed.report().evidence().paired_tasks, 2);
    assert!((signed.report().evidence().task_score_delta.estimate - 0.45).abs() < f64::EPSILON);

    let gate = PromotionGate {
        min_paired_tasks: 2,
        ..PromotionGate::default()
    };
    assert_eq!(
        gate.assess(DeploymentStage::Candidate, signed.report().evidence()),
        PromotionAssessment::EligibleForReleaseReview {
            suggested_next: DeploymentStage::Shadow
        }
    );
}
