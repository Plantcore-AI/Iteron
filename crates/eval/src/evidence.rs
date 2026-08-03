//! Eval-side projection into independently signed `core-evolve` held-out evidence.

use crate::measurement::{
    KernelTaxLine, MeasurementError, PairedEvaluationReport, compare_manifests,
};
use crate::types::{EvaluationManifest, EvaluationPurpose, Partition};
use core_evolve::{
    HeldOutEvaluation, IndependentEvaluator, Interval, PolicyRef, PromotionAuthorityError,
    PromotionEvidence, SignedHeldOutEvaluation, VerifiedCandidateInputs,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceIdentityPolicy {
    pub evaluator_id: String,
    pub producer_anchor_ids: BTreeSet<String>,
    pub promotion_anchor_ids: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionInvariantClaims {
    pub candidate_safety_violations: u64,
    pub candidate_policy_violations: u64,
    pub train_eval_overlap: bool,
    pub replay_equivalence_passed: bool,
    pub sandbox_suite_passed: bool,
    pub invariant_suites: BTreeMap<String, bool>,
}

#[derive(Debug, thiserror::Error)]
pub enum EvidenceProjectionError {
    #[error(transparent)]
    Measurement(#[from] MeasurementError),
    #[error(transparent)]
    Evolve(#[from] PromotionAuthorityError),
    #[error("held-out evidence cannot be projected from a tune/train manifest")]
    NotHeldOut,
    #[error("evaluator id `{0}` overlaps a producer, candidate, or promotion authority")]
    IdentityOverlap(String),
    #[error("the supplied IndependentEvaluator does not have the declared evaluator id")]
    EvaluatorIdentityMismatch,
    #[error("verified evaluation-suite digest does not match the scored corpus digest")]
    EvaluationSuiteMismatch,
    #[error("candidate policy digest does not match the verifier-bound artifact digest")]
    CandidateArtifactMismatch,
    #[error("candidate evaluation manifest does not bind the verifier-bound policy bundle")]
    CandidateBundleMismatch,
    #[error("verified base-model id does not match the frozen model in the evaluation manifest")]
    BaseModelMismatch,
    #[error("signed promotion evidence requires every attempted cell to be explicitly priced")]
    Unpriced,
    #[error("latency evidence could not be computed from the paired arms")]
    MissingLatency,
}

#[allow(clippy::too_many_arguments)]
pub fn sign_held_out_evidence(
    baseline_manifest: &EvaluationManifest,
    baseline_arm: &str,
    candidate_manifest: &EvaluationManifest,
    candidate_arm: &str,
    minimum_pairs: u64,
    baseline_policy: PolicyRef,
    candidate_policy: PolicyRef,
    verified: &VerifiedCandidateInputs,
    evaluator: &IndependentEvaluator,
    identities: &EvidenceIdentityPolicy,
    claims: PromotionInvariantClaims,
) -> Result<SignedHeldOutEvaluation, EvidenceProjectionError> {
    validate_manifest(baseline_manifest)?;
    validate_manifest(candidate_manifest)?;
    validate_identity_separation(&candidate_policy, identities)?;
    if verified.evaluation_suite_digest != digest_hex(&candidate_manifest.dataset_digest)? {
        return Err(EvidenceProjectionError::EvaluationSuiteMismatch);
    }
    if candidate_policy.digest != verified.artifact_digest {
        return Err(EvidenceProjectionError::CandidateArtifactMismatch);
    }
    if candidate_manifest
        .bundle_digest
        .as_deref()
        .and_then(|digest| digest.strip_prefix("sha256:"))
        != Some(verified.artifact_digest.as_str())
    {
        return Err(EvidenceProjectionError::CandidateBundleMismatch);
    }
    if verified.base_model.model_id != candidate_manifest.model {
        return Err(EvidenceProjectionError::BaseModelMismatch);
    }

    let paired = compare_manifests(
        baseline_manifest,
        baseline_arm,
        candidate_manifest,
        candidate_arm,
        minimum_pairs,
        "promotion_evidence_projection",
        KernelTaxLine::reserved(),
    )?;
    let cost_delta = paired
        .comparison
        .cost_delta_usd
        .ok_or(EvidenceProjectionError::Unpriced)?;
    let latency_delta = latency_delta_ms(
        baseline_manifest,
        baseline_arm,
        candidate_manifest,
        candidate_arm,
    )
    .ok_or(EvidenceProjectionError::MissingLatency)?;

    let evidence = PromotionEvidence {
        baseline: baseline_policy,
        candidate: candidate_policy.clone(),
        base_model: verified.base_model.clone(),
        paired_tasks: paired.comparison.matched_pairs,
        task_score_delta: Interval {
            estimate: paired.comparison.resolved_rate_delta,
            lower: paired.comparison.paired_ci95[0],
            upper: paired.comparison.paired_ci95[1],
        },
        cost_delta_usd: point_interval(cost_delta),
        latency_delta_ms: point_interval(latency_delta),
        candidate_safety_violations: claims.candidate_safety_violations,
        candidate_policy_violations: claims.candidate_policy_violations,
        train_eval_overlap: claims.train_eval_overlap,
        replay_equivalence_passed: claims.replay_equivalence_passed,
        sandbox_suite_passed: claims.sandbox_suite_passed,
        invariant_suites: claims.invariant_suites,
    };
    let report = HeldOutEvaluation::new(candidate_policy, verified, evidence)?;
    let signed = evaluator.sign_held_out(report)?;
    if signed.evaluator_id() != identities.evaluator_id {
        return Err(EvidenceProjectionError::EvaluatorIdentityMismatch);
    }
    Ok(signed)
}

pub fn paired_projection_report(
    baseline_manifest: &EvaluationManifest,
    baseline_arm: &str,
    candidate_manifest: &EvaluationManifest,
    candidate_arm: &str,
    minimum_pairs: u64,
) -> Result<PairedEvaluationReport, EvidenceProjectionError> {
    validate_manifest(baseline_manifest)?;
    validate_manifest(candidate_manifest)?;
    Ok(compare_manifests(
        baseline_manifest,
        baseline_arm,
        candidate_manifest,
        candidate_arm,
        minimum_pairs,
        "promotion_evidence_projection",
        KernelTaxLine::reserved(),
    )?)
}

fn validate_manifest(manifest: &EvaluationManifest) -> Result<(), EvidenceProjectionError> {
    if manifest.purpose != EvaluationPurpose::Score
        || manifest
            .cells
            .iter()
            .any(|cell| cell.partition != Partition::HeldOut)
    {
        return Err(EvidenceProjectionError::NotHeldOut);
    }
    Ok(())
}

fn validate_identity_separation(
    candidate: &PolicyRef,
    identities: &EvidenceIdentityPolicy,
) -> Result<(), EvidenceProjectionError> {
    let evaluator_id = identities.evaluator_id.as_str();
    if evaluator_id == candidate.policy_id
        || identities.producer_anchor_ids.contains(evaluator_id)
        || identities.promotion_anchor_ids.contains(evaluator_id)
    {
        return Err(EvidenceProjectionError::IdentityOverlap(
            identities.evaluator_id.clone(),
        ));
    }
    Ok(())
}

fn digest_hex(value: &str) -> Result<String, EvidenceProjectionError> {
    let Some(value) = value.strip_prefix("sha256:") else {
        return Err(EvidenceProjectionError::EvaluationSuiteMismatch);
    };
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(value.to_owned())
    } else {
        Err(EvidenceProjectionError::EvaluationSuiteMismatch)
    }
}

fn point_interval(value: f64) -> Interval {
    Interval {
        estimate: value,
        lower: value,
        upper: value,
    }
}

fn latency_delta_ms(
    baseline_manifest: &EvaluationManifest,
    baseline_arm: &str,
    candidate_manifest: &EvaluationManifest,
    candidate_arm: &str,
) -> Option<f64> {
    let average = |manifest: &EvaluationManifest, arm: &str| {
        let values = manifest
            .cells
            .iter()
            .filter(|cell| cell.config == arm)
            .map(|cell| cell.elapsed_ms as f64)
            .collect::<Vec<_>>();
        (!values.is_empty()).then(|| values.iter().sum::<f64>() / values.len() as f64)
    };
    Some(average(candidate_manifest, candidate_arm)? - average(baseline_manifest, baseline_arm)?)
}
