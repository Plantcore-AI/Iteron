use super::*;
use crate::promotion_evaluation::{evaluation_signature, held_out_domain};
use crate::{
    DeploymentStage, EvaluationTask, EvaluatorTrustAnchor, PromotionAssessment,
    PromotionAuthorityKey, PromotionGate, StrategySlot,
};

const BASELINE_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const CANDIDATE_DIGEST: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const TRAINING_DIGEST: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const FIXTURE_DIGEST: &str = "4444444444444444444444444444444444444444444444444444444444444444";

fn model() -> BaseModelId {
    BaseModelId {
        model_family: "anthropic/claude".into(),
        model_id: "claude-fable-5".into(),
        model_digest: "5".repeat(64),
    }
}

fn policy(id: &str, digest: &str) -> PolicyRef {
    PolicyRef {
        slot: StrategySlot::tool_policy(),
        policy_id: id.into(),
        version: "1.0.0".into(),
        digest: digest.into(),
    }
}

fn reward(score: f64) -> RewardVector {
    RewardVector {
        task_score: score,
        correctness: score,
        safety_violations: 0,
        policy_violations: 0,
        cost_usd: 0.01,
        wall_time_ms: 10,
        human_acceptance: None,
        domain: BTreeMap::new(),
    }
}

fn suite(count: usize) -> EvaluationSuite {
    EvaluationSuite::new(
        "held-out-owner",
        "suite-v1",
        (0..count)
            .map(|index| EvaluationTask {
                task_id: format!("held-out-{index:03}"),
                fixture_digest: FIXTURE_DIGEST.into(),
            })
            .collect(),
    )
    .unwrap()
}

fn report(count: usize) -> HeldOutEvalReport {
    HeldOutEvalReport {
        schema_version: HELD_OUT_REPORT_SCHEMA_VERSION,
        baseline: policy("baseline", BASELINE_DIGEST),
        candidate: policy("candidate", CANDIDATE_DIGEST),
        pairs: (0..count)
            .map(|index| HeldOutTaskPair {
                task_id: format!("held-out-{index:03}"),
                fixture_digest: FIXTURE_DIGEST.into(),
                baseline: reward(0.0),
                candidate: reward(1.0),
            })
            .collect(),
        intervals: HeldOutReportIntervals {
            task_score_delta: HeldOutMetricBounds {
                lower: 0.5,
                upper: 1.0,
            },
            cost_delta_usd: HeldOutMetricBounds {
                lower: 0.0,
                upper: 0.0,
            },
            latency_delta_ms: HeldOutMetricBounds {
                lower: 0.0,
                upper: 0.0,
            },
        },
        replay_equivalence_passed: true,
        sandbox_suite_passed: true,
        invariant_suites: [
            ("runtime".into(), true),
            ("security".into(), true),
            ("durability".into(), true),
        ]
        .into(),
        reported_train_eval_overlap: Some(false),
    }
}

fn verified(suite: &EvaluationSuite) -> VerifiedCandidateInputs {
    VerifiedCandidateInputs {
        artifact_digest: CANDIDATE_DIGEST.into(),
        training_dataset_digest: Some(TRAINING_DIGEST.into()),
        evaluation_suite_digest: suite.digest().into(),
        base_model: model(),
    }
}

fn evaluator(byte: u8) -> IndependentEvaluator {
    IndependentEvaluator::new(
        "independent-evaluator",
        PromotionAuthorityKey::new(vec![byte; 32]).unwrap(),
    )
    .unwrap()
}

fn corpus(task_ids: impl IntoIterator<Item = String>) -> HeldOutTrainingCorpus {
    HeldOutTrainingCorpus {
        digest: TRAINING_DIGEST.into(),
        task_ids: task_ids.into_iter().collect(),
    }
}

fn register(
    report: HeldOutEvalReport,
    training: &HeldOutTrainingCorpus,
    suite: &EvaluationSuite,
) -> SignedHeldOutEvaluation {
    let candidate = report.candidate.clone();
    let mut store = HeldOutEvidenceStore::new();
    assert_eq!(
        store
            .register(
                report,
                &candidate,
                &verified(suite),
                Some(training),
                suite,
                &evaluator(0x22),
                &["release-owner".to_owned()].into(),
            )
            .unwrap(),
        HeldOutEvidenceRegistration::Stored
    );
    store
        .evidence_for(CANDIDATE_DIGEST, &model())
        .unwrap()
        .unwrap()
}

#[test]
fn overlapping_train_eval_sets_force_reject() {
    let suite = suite(100);
    let training = corpus(["held-out-000".to_owned()]);
    let signed = register(report(100), &training, &suite);
    assert!(signed.report().evidence().train_eval_overlap);
    assert!(matches!(
        PromotionGate::default().assess(
            DeploymentStage::Candidate,
            signed.report().evidence()
        ),
        PromotionAssessment::Reject { reasons }
            if reasons.iter().any(|reason| reason.contains("overlap"))
    ));
}

#[test]
fn disjoint_sets_pass_and_sign() {
    let suite = suite(100);
    let training = corpus(["train-only".to_owned()]);
    let signed = register(report(100), &training, &suite);
    assert!(!signed.report().evidence().train_eval_overlap);
    assert_eq!(
        PromotionGate::default().assess(DeploymentStage::Candidate, signed.report().evidence()),
        PromotionAssessment::EligibleForReleaseReview {
            suggested_next: DeploymentStage::Shadow
        }
    );
}

#[test]
fn producer_anchor_cannot_sign_held_out() {
    let suite = suite(1);
    let report = report(1);
    let candidate = report.candidate.clone();
    let mut store = HeldOutEvidenceStore::new();
    assert!(matches!(
        store.register(
            report,
            &candidate,
            &verified(&suite),
            Some(&corpus(["train-only".to_owned()])),
            &suite,
            &evaluator(0x11),
            &["independent-evaluator".to_owned()].into(),
        ),
        Err(HeldOutBridgeError::EvaluatorIsPromotionParty(id))
            if id == "independent-evaluator"
    ));
}

#[test]
fn intervals_are_finite_ordered_and_carried_from_eval_stats() {
    let suite = suite(1);
    let training = corpus(["train-only".to_owned()]);
    let mut observed = report(1);
    observed.pairs[0].baseline.cost_usd = 0.0;
    observed.pairs[0].candidate.cost_usd = 0.03125;
    observed.pairs[0].candidate.wall_time_ms = 25;
    observed.intervals.cost_delta_usd = HeldOutMetricBounds {
        lower: 0.015625,
        upper: 0.046875,
    };
    observed.intervals.latency_delta_ms = HeldOutMetricBounds {
        lower: 10.0,
        upper: 20.0,
    };
    let signed = register(observed, &training, &suite);
    let evidence = signed.report().evidence();
    assert_eq!(
        evidence.task_score_delta,
        Interval {
            estimate: 1.0,
            lower: 0.5,
            upper: 1.0,
        }
    );
    assert_eq!(
        evidence.cost_delta_usd,
        Interval {
            estimate: 0.03125,
            lower: 0.015625,
            upper: 0.046875,
        }
    );
    assert_eq!(
        evidence.latency_delta_ms,
        Interval {
            estimate: 15.0,
            lower: 10.0,
            upper: 20.0,
        }
    );
    assert!(evidence.validate_contract().is_ok());
}

#[test]
fn safety_or_policy_violation_in_reward_forces_reject() {
    let suite = suite(100);
    let training = corpus(["train-only".to_owned()]);
    for mutate in [
        |reward: &mut RewardVector| reward.safety_violations = 1,
        |reward: &mut RewardVector| reward.policy_violations = 1,
    ] {
        let mut report = report(100);
        mutate(&mut report.pairs[0].candidate);
        let signed = register(report, &training, &suite);
        assert!(matches!(
            PromotionGate::default().assess(DeploymentStage::Candidate, signed.report().evidence()),
            PromotionAssessment::Reject { .. }
        ));
    }
}

#[test]
fn a_lying_false_overlap_assertion_is_recomputed() {
    let suite = suite(1);
    let training = corpus(["held-out-000".to_owned()]);
    let report = report(1);
    assert_eq!(report.reported_train_eval_overlap, Some(false));
    let signed = register(report, &training, &suite);
    assert!(signed.report().evidence().train_eval_overlap);
}

#[test]
fn signed_evidence_matches_the_independent_key_not_the_promotion_key() {
    let suite = suite(1);
    let signed = register(report(1), &corpus(["train-only".to_owned()]), &suite);
    let independent = EvaluatorTrustAnchor::new(
        "independent-evaluator",
        "held-out-owner",
        PromotionAuthorityKey::new(vec![0x22; 32]).unwrap(),
    )
    .unwrap();
    let promotion_key_disguised_as_evaluator = EvaluatorTrustAnchor::new(
        "independent-evaluator",
        "held-out-owner",
        PromotionAuthorityKey::new(vec![0x11; 32]).unwrap(),
    )
    .unwrap();
    let expected = evaluation_signature(&independent, held_out_domain(), &signed.report).unwrap();
    let wrong = evaluation_signature(
        &promotion_key_disguised_as_evaluator,
        held_out_domain(),
        &signed.report,
    )
    .unwrap();
    assert_eq!(signed.signature, expected);
    assert_ne!(signed.signature, wrong);
}

#[test]
fn pair_order_does_not_change_the_signed_aggregate() {
    let suite = suite(100);
    let training = corpus(["train-only".to_owned()]);
    let forward = register(report(100), &training, &suite);
    let mut reversed = report(100);
    reversed.pairs.reverse();
    let backward = register(reversed, &training, &suite);
    assert_eq!(forward, backward);
}

#[test]
fn report_size_is_rejected_before_json_parsing() {
    assert!(matches!(
        HeldOutEvalReport::from_json(&vec![b' '; MAX_HELD_OUT_REPORT_JSON_BYTES]),
        Err(HeldOutBridgeError::InvalidReportJson(_))
    ));
    assert!(matches!(
        HeldOutEvalReport::from_json(&vec![b' '; MAX_HELD_OUT_REPORT_JSON_BYTES + 1]),
        Err(HeldOutBridgeError::ReportTooLarge { .. })
    ));
}
