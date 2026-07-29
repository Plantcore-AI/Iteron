use crate::verifier_crypto::sha256_hex;
use crate::{
    ArtifactKind, AttestationKey, BaseModelId, ConsentAwareDatasetRegistry, DeploymentBundle,
    DeploymentStage, EvaluationSuite, EvaluationTask, EvaluatorTrustAnchor, EvolutionMethod,
    EvolutionVerifier, GovernedTrainingDataset, HeldOutEvalReport, HeldOutMetricBounds,
    HeldOutReportIntervals, HeldOutTaskPair, IndependentEvaluator, ManifestAdmissionPolicy,
    OfflineRuleCandidate, OfflineRuleSearchProducer, OfflineRuleSearchSpec,
    ParentCapabilityCeiling, PolicyCheckpoint, PolicyManifest, PolicyRef, ProducedPolicyCandidate,
    PromotionAuthority, PromotionAuthorityError, PromotionAuthorityKey, PromotionAuthorizer,
    PromotionControlPolicy, PromotionEvidence, PromotionRequest, PromotionRole,
    PromotionTrustAnchor, PromptPreferenceCandidate, PromptPreferenceProducer,
    PromptPreferenceSpec, ProtocolRange, RewardVector, SignedHeldOutEvaluation, StageLimits,
    StageObservation, StagePermit, StrategySlot, TrainingAdmissionPolicy, TranscriptRunError,
    VerifiedTrainingDataset,
};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const AUTHORITY_ID: &str = "offline-evolution-demo";
pub(super) const TARGET_AUTHORITY_ID: &str = "offline-evolution-demo-target";
pub(super) const PROMOTION_PARTY: &str = "release-owner";
pub(super) const EVALUATOR_ID: &str = "independent-evaluator";
pub(super) const SUITE_OWNER: &str = "held-out-owner";
pub(super) const PRODUCER_ID: &str = "record-producer";
pub(super) const SECURITY_DIGEST: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub(super) const DURABILITY_DIGEST: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

pub(super) fn key(byte: u8) -> PromotionAuthorityKey {
    PromotionAuthorityKey::new(vec![byte; 32]).expect("fixed demo key is valid")
}

pub(super) fn attestation_key() -> AttestationKey {
    AttestationKey::new(vec![0x44; 32]).expect("fixed demo key is valid")
}

pub(super) fn model_a() -> BaseModelId {
    BaseModelId {
        model_family: "demo/frozen".into(),
        model_id: "model-a".into(),
        model_digest: "1".repeat(64),
    }
}

pub(super) fn model_b() -> BaseModelId {
    BaseModelId {
        model_family: "demo/frozen".into(),
        model_id: "model-b".into(),
        model_digest: "2".repeat(64),
    }
}

pub(super) fn training_policy() -> TrainingAdmissionPolicy {
    TrainingAdmissionPolicy::new(
        ["apache-2.0".to_owned()].into(),
        [(
            "training-v1".to_owned(),
            crate::RetentionTrainingUse::Allowed,
        )]
        .into(),
    )
    .expect("fixed training policy is valid")
}

pub(super) fn verifier() -> EvolutionVerifier {
    EvolutionVerifier::new(
        vec![
            crate::ProducerTrustAnchor::new(
                PRODUCER_ID,
                crate::TenantId::default(),
                attestation_key(),
            )
            .expect("fixed producer anchor is valid"),
        ],
        training_policy(),
    )
    .expect("fixed verifier configuration is valid")
}

pub(super) fn evaluation_suite() -> EvaluationSuite {
    let tasks = (0..100)
        .map(|index| EvaluationTask {
            task_id: format!("held-out-{index:03}"),
            fixture_digest: format!("{:064x}", index + 1),
        })
        .collect();
    EvaluationSuite::new(SUITE_OWNER, "suite-v1", tasks).expect("fixed suite is valid")
}

pub(super) fn control_policy() -> PromotionControlPolicy {
    PromotionControlPolicy::new(
        crate::PromotionGate::default(),
        StageLimits::new(20, 2, 5_000, 0, 2_000).expect("fixed shadow limits are valid"),
        StageLimits::new(10, 1, 2_000, 500, 1_000).expect("fixed canary limits are valid"),
        SECURITY_DIGEST,
        DURABILITY_DIGEST,
    )
    .expect("fixed promotion policy is valid")
}

pub(super) fn promotion_anchor() -> PromotionTrustAnchor {
    let roles = [
        PromotionRole::Bootstrap,
        PromotionRole::AdmitCandidate,
        PromotionRole::AdvanceStage,
        PromotionRole::Rollback,
    ]
    .into();
    PromotionTrustAnchor::new(PROMOTION_PARTY, roles, key(0x11))
        .expect("fixed promotion anchor is valid")
}

pub(super) fn evaluator_anchor() -> EvaluatorTrustAnchor {
    EvaluatorTrustAnchor::new(EVALUATOR_ID, SUITE_OWNER, key(0x22))
        .expect("fixed evaluator anchor is valid")
}

pub(super) fn evaluator() -> IndependentEvaluator {
    IndependentEvaluator::new(EVALUATOR_ID, key(0x22)).expect("fixed evaluator is valid")
}

pub(super) fn authorizer(
    policy: &PromotionControlPolicy,
) -> Result<PromotionAuthorizer, PromotionAuthorityError> {
    authorizer_for(AUTHORITY_ID, policy)
}

pub(super) fn target_authorizer(
    policy: &PromotionControlPolicy,
) -> Result<PromotionAuthorizer, PromotionAuthorityError> {
    authorizer_for(TARGET_AUTHORITY_ID, policy)
}

fn authorizer_for(
    authority_id: &str,
    policy: &PromotionControlPolicy,
) -> Result<PromotionAuthorizer, PromotionAuthorityError> {
    PromotionAuthorizer::new(authority_id, policy.digest()?, PROMOTION_PARTY, key(0x11))
}

pub(super) fn baseline() -> Result<(PolicyRef, DeploymentBundle), PromotionAuthorityError> {
    let bytes = b"offline-evolution-demo-baseline-v1".to_vec();
    let policy = PolicyRef {
        slot: StrategySlot::router(),
        policy_id: "baseline-router".into(),
        version: "1.0.0".into(),
        digest: sha256_hex(b"baseline-router-policy"),
    };
    let bundle = crate::PolicyBundle {
        bundle_id: "baseline-bundle".into(),
        digest: sha256_hex(&bytes),
        policies: vec![policy.clone()],
        rollback_to: None,
    };
    Ok((policy, DeploymentBundle::new(bundle, bytes)?))
}

pub(super) fn admission(parent: &PolicyRef) -> ManifestAdmissionPolicy {
    ManifestAdmissionPolicy::new(StrategySlot::router(), BTreeSet::new()).with_parent_ceiling(
        ParentCapabilityCeiling::new(parent.clone(), BTreeSet::new()),
    )
}

pub(super) fn rule_candidate(
    dataset: &GovernedTrainingDataset<'_>,
    admission: &ManifestAdmissionPolicy,
    suite: &EvaluationSuite,
    parent: &PolicyRef,
    base_model: BaseModelId,
    label: &str,
) -> Result<ProducedPolicyCandidate, crate::OfflineProducerError> {
    let spec = OfflineRuleSearchSpec::new(
        format!("{label}-router"),
        base_model,
        "1.0.0",
        Some(parent.clone()),
        ProtocolRange { min: 1, max: 1 },
        BTreeSet::new(),
        suite.digest(),
        vec![
            OfflineRuleCandidate::new(format!("{label}-fallback"), "general", "completed")?,
            OfflineRuleCandidate::new(format!("{label}-safe"), "coding", "completed")?,
        ],
    )?;
    OfflineRuleSearchProducer::new().produce(dataset, admission, &spec)
}

pub(super) fn prompt_candidate(
    dataset: &GovernedTrainingDataset<'_>,
    admission: &ManifestAdmissionPolicy,
    suite: &EvaluationSuite,
    parent: &PolicyRef,
    base_model: BaseModelId,
    label: &str,
) -> Result<ProducedPolicyCandidate, crate::PromptPreferenceError> {
    let spec = PromptPreferenceSpec::new(
        format!("{label}-router"),
        base_model,
        "1.0.0",
        Some(parent.clone()),
        ProtocolRange { min: 1, max: 1 },
        BTreeSet::new(),
        suite.digest(),
        vec![
            PromptPreferenceCandidate::new(
                "prompt-concise",
                "coding",
                "completed",
                "Route conservatively and explain the selected path.",
            )?,
            PromptPreferenceCandidate::new(
                "prompt-fallback",
                "general",
                "completed",
                "Use the governed fallback route.",
            )?,
        ],
    )?;
    PromptPreferenceProducer::new().produce(dataset, admission, &spec)
}

pub(super) fn produce_candidate(
    kind: crate::TranscriptProducerKind,
    dataset: &GovernedTrainingDataset<'_>,
    admission: &ManifestAdmissionPolicy,
    suite: &EvaluationSuite,
    parent: &PolicyRef,
    base_model: BaseModelId,
    label: &str,
) -> Result<ProducedPolicyCandidate, crate::TranscriptRunError> {
    match kind {
        crate::TranscriptProducerKind::RuleSearch => Ok(rule_candidate(
            dataset, admission, suite, parent, base_model, label,
        )?),
        crate::TranscriptProducerKind::PromptPreference => Ok(prompt_candidate(
            dataset, admission, suite, parent, base_model, label,
        )?),
    }
}

pub(super) fn checkpoint(
    bundle_id: &str,
    manifest: &PolicyManifest,
) -> Result<PolicyCheckpoint, crate::CheckpointAlgebraError> {
    PolicyCheckpoint::build(
        bundle_id,
        Some("baseline-bundle".into()),
        [(manifest.policy.slot.clone(), manifest.clone())].into(),
    )
}

pub(super) fn held_out_report(
    suite: &EvaluationSuite,
    baseline: &PolicyRef,
    candidate: &PolicyRef,
    delta: f64,
    safety_violations: u32,
) -> HeldOutEvalReport {
    let pairs = suite
        .tasks()
        .iter()
        .enumerate()
        .map(|(index, task)| HeldOutTaskPair {
            task_id: task.task_id.clone(),
            fixture_digest: task.fixture_digest.clone(),
            baseline: reward(0.5, 0),
            candidate: reward(0.5 + delta, if index == 0 { safety_violations } else { 0 }),
        })
        .collect();
    HeldOutEvalReport {
        schema_version: crate::HELD_OUT_REPORT_SCHEMA_VERSION,
        baseline: baseline.clone(),
        candidate: candidate.clone(),
        pairs,
        intervals: HeldOutReportIntervals {
            task_score_delta: HeldOutMetricBounds {
                // Exactly representable binary fractions keep the signed fixture journal
                // byte-stable across deserialize/re-serialize verification.
                lower: delta,
                upper: delta,
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

fn reward(score: f64, safety_violations: u32) -> RewardVector {
    RewardVector {
        task_score: score,
        correctness: score,
        safety_violations,
        policy_violations: 0,
        cost_usd: 0.01,
        wall_time_ms: 10,
        human_acceptance: Some(score),
        domain: BTreeMap::new(),
    }
}

pub(super) fn stage_observation(
    permit: &StagePermit,
    evidence: &PromotionEvidence,
) -> Result<crate::SignedStageObservation, PromotionAuthorityError> {
    let traffic = match permit.stage() {
        DeploymentStage::Shadow => 0,
        DeploymentStage::Canary => 500,
        _ => return Err(PromotionAuthorityError::InvalidRequestTransition),
    };
    evaluator().sign_stage(StageObservation::new(
        permit,
        2,
        1,
        100,
        traffic,
        100,
        SECURITY_DIGEST,
        DURABILITY_DIGEST,
        evidence.clone(),
    )?)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn promote_and_rollback<'a>(
    label: &str,
    authority: &mut PromotionAuthority,
    authorizer: &PromotionAuthorizer,
    verifier: &EvolutionVerifier,
    datasets: &ConsentAwareDatasetRegistry,
    dataset: &VerifiedTrainingDataset<'a>,
    suite: &EvaluationSuite,
    manifest: &PolicyManifest,
    artifact: &[u8],
    held_out: &SignedHeldOutEvaluation,
    deployment: DeploymentBundle,
    events: &mut Vec<crate::TranscriptEvent>,
) -> Result<(), PromotionAuthorityError> {
    let digest = deployment.bundle().digest.clone();
    let evidence = held_out.report().evidence().clone();
    let admit = PromotionRequest::admit_candidate(format!("{label}-admit"), &digest)?;
    authority.admit_candidate(
        &admit,
        &authorizer.authorize(&admit)?,
        verifier,
        datasets,
        manifest,
        artifact,
        Some(dataset),
        suite,
        held_out.clone(),
        deployment,
    )?;
    events.push(crate::TranscriptEvent::CandidateAdmitted {
        label: label.into(),
        bundle_digest: digest.clone(),
    });

    let shadow_request = PromotionRequest::enter_shadow(format!("{label}-shadow"), &digest)?;
    let shadow =
        authority.enter_shadow(&shadow_request, &authorizer.authorize(&shadow_request)?)?;
    events.push(crate::TranscriptEvent::StageReached {
        label: label.into(),
        stage: DeploymentStage::Shadow,
    });

    let mut unsafe_stage_evidence = evidence.clone();
    unsafe_stage_evidence.candidate_safety_violations = 1;
    let unsafe_stage_request =
        PromotionRequest::complete_shadow(format!("{label}-unsafe-shadow"), &digest)?;
    match authority.complete_shadow(
        &unsafe_stage_request,
        &authorizer.authorize(&unsafe_stage_request)?,
        stage_observation(&shadow, &unsafe_stage_evidence)?,
    ) {
        Err(PromotionAuthorityError::StageRefused) => {
            events.push(crate::TranscriptEvent::CandidateRefused {
                label: format!("{label}-unsafe-shadow"),
                reason: "stage_safety_violation".into(),
            });
        }
        Err(error) => return Err(error),
        Ok(_) => {
            return Err(PromotionAuthorityError::InvalidRequestTransition);
        }
    }

    let canary_request = PromotionRequest::complete_shadow(format!("{label}-canary"), &digest)?;
    let canary = authority.complete_shadow(
        &canary_request,
        &authorizer.authorize(&canary_request)?,
        stage_observation(&shadow, &evidence)?,
    )?;
    events.push(crate::TranscriptEvent::StageReached {
        label: label.into(),
        stage: DeploymentStage::Canary,
    });

    let active_request = PromotionRequest::complete_canary(format!("{label}-active"), &digest)?;
    authority.complete_canary(
        &active_request,
        &authorizer.authorize(&active_request)?,
        stage_observation(&canary, &evidence)?,
    )?;
    events.push(crate::TranscriptEvent::StageReached {
        label: label.into(),
        stage: DeploymentStage::Active,
    });

    let rollback = PromotionRequest::rollback(
        format!("{label}-rollback"),
        &digest,
        DeploymentStage::Active,
    )?;
    let restored = authority.rollback(&rollback, &authorizer.authorize(&rollback)?)?;
    events.push(crate::TranscriptEvent::RolledBack {
        label: label.into(),
        restored_bundle_digest: restored.bundle().digest.clone(),
    });
    Ok(())
}

pub(super) fn require_restored_baseline(
    authority: &mut PromotionAuthority,
    baseline: &DeploymentBundle,
) -> Result<DeploymentBundle, TranscriptRunError> {
    let active = authority
        .active_bundle()?
        .ok_or(TranscriptRunError::Invariant(
            "promotion authority lost its active baseline",
        ))?;
    if &active != baseline {
        return Err(TranscriptRunError::Invariant(
            "promotion authority did not restore exact baseline bytes",
        ));
    }
    authority.audit()?;
    Ok(active)
}

pub(super) fn method_and_kind(
    candidate: &ProducedPolicyCandidate,
) -> (EvolutionMethod, ArtifactKind) {
    (
        candidate.manifest().method,
        candidate.manifest().artifact_kind,
    )
}
