//! Cross-model checkpoint transfer with independently authenticated held-out evidence.

use crate::checkpoint_algebra::readmit_all;
use crate::{
    AlgebraOutput, AuthenticatedHeldOutEvaluation, BaseModelId, CheckpointAlgebraError,
    CheckpointEvent, DeploymentStage, ManifestAdmissionPolicy, PolicyCheckpoint,
    PromotionAssessment, PromotionGate, StrategySlot,
};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TransferSlotMetric {
    pub slot: StrategySlot,
    pub source_delta: f64,
    pub target_delta: f64,
    pub retained_delta: f64,
    pub portable_fraction: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TransferMetric {
    pub source_delta: f64,
    pub target_delta: f64,
    pub retained_delta: f64,
    pub portable_fraction: f64,
    pub slots: Vec<TransferSlotMetric>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TransferResult {
    pub output: AlgebraOutput,
    pub metric: TransferMetric,
    /// The metric is reported beside this decision and never changes it.
    pub target_assessment: PromotionAssessment,
}

#[allow(clippy::too_many_arguments)]
pub fn transfer(
    source: &PolicyCheckpoint,
    from: &BaseModelId,
    to: &BaseModelId,
    evaluations_a: &BTreeMap<StrategySlot, AuthenticatedHeldOutEvaluation>,
    evaluations_b: &BTreeMap<StrategySlot, AuthenticatedHeldOutEvaluation>,
    admissions: &BTreeMap<StrategySlot, ManifestAdmissionPolicy>,
    gate: &PromotionGate,
) -> Result<TransferResult, CheckpointAlgebraError> {
    source.validate()?;
    if from == to {
        return Err(CheckpointAlgebraError::SameBaseModel);
    }
    let expected_slots: Vec<_> = source.manifests().keys().cloned().collect();
    let supplied_a: Vec<_> = evaluations_a.keys().cloned().collect();
    let supplied_b: Vec<_> = evaluations_b.keys().cloned().collect();
    if supplied_a != expected_slots || supplied_b != expected_slots {
        return Err(CheckpointAlgebraError::TransferEvaluationSetMismatch);
    }

    let mut slot_metrics = Vec::with_capacity(expected_slots.len());
    let mut first_rejection = None;
    for slot in &expected_slots {
        let evaluation_a = evaluations_a
            .get(slot)
            .ok_or(CheckpointAlgebraError::TransferEvaluationSetMismatch)?;
        let evaluation_b = evaluations_b
            .get(slot)
            .ok_or(CheckpointAlgebraError::TransferEvaluationSetMismatch)?;
        if evaluation_a.report().base_model() != from || evaluation_b.report().base_model() != to {
            return Err(CheckpointAlgebraError::EvaluationBaseModelMismatch);
        }
        let evidence_a = evaluation_a.report().evidence();
        let evidence_b = evaluation_b.report().evidence();
        evidence_a.validate_contract()?;
        evidence_b.validate_contract()?;
        let source_manifest = source
            .manifest_for(slot)
            .ok_or_else(|| CheckpointAlgebraError::MissingManifest(slot.clone()))?;
        if &source_manifest.base_model != from {
            return Err(CheckpointAlgebraError::ManifestBaseModelMismatch(
                slot.clone(),
            ));
        }
        if evidence_a.baseline != evidence_b.baseline
            || evidence_a.candidate != evidence_b.candidate
            || evidence_a.candidate != source_manifest.policy
        {
            return Err(CheckpointAlgebraError::TransferIdentityMismatch);
        }
        for evaluation in [evaluation_a, evaluation_b] {
            let report = evaluation.report();
            if report.candidate != source_manifest.policy
                || report.artifact_digest != source_manifest.policy.digest
                || report.training_dataset_digest != source_manifest.training_dataset_digest
                || report.evaluation_suite_digest != source_manifest.evaluation_suite_digest
                || evaluation.evaluator_id() == source_manifest.policy.policy_id
                || evaluation.evaluator_id() == source.bundle().bundle_id
            {
                return Err(CheckpointAlgebraError::TransferIdentityMismatch);
            }
        }
        let source_delta = evidence_a.task_score_delta.estimate;
        let target_delta = evidence_b.task_score_delta.estimate;
        if !source_delta.is_finite() || source_delta <= 0.0 || !target_delta.is_finite() {
            return Err(CheckpointAlgebraError::InvalidTransferDelta);
        }
        let retained_delta = target_delta.clamp(0.0, source_delta);
        let target_assessment = gate.assess(DeploymentStage::Candidate, evidence_b);
        match target_assessment {
            PromotionAssessment::Reject { reasons } => {
                if first_rejection.is_none() {
                    first_rejection = Some((slot.clone(), reasons));
                }
            }
            PromotionAssessment::EligibleForReleaseReview {
                suggested_next: DeploymentStage::Shadow,
            } => {}
            PromotionAssessment::EligibleForReleaseReview { .. } => {
                return Err(CheckpointAlgebraError::UnexpectedTargetAssessment);
            }
        }
        slot_metrics.push(TransferSlotMetric {
            slot: slot.clone(),
            source_delta,
            target_delta,
            retained_delta,
            portable_fraction: retained_delta / source_delta,
        });
    }
    let source_delta = finite_sum(slot_metrics.iter().map(|metric| metric.source_delta))?;
    let target_delta = finite_sum(slot_metrics.iter().map(|metric| metric.target_delta))?;
    let retained_delta = finite_sum(slot_metrics.iter().map(|metric| metric.retained_delta))?;
    let portable_fraction = retained_delta / source_delta;
    if !(0.0..=1.0).contains(&portable_fraction) {
        return Err(CheckpointAlgebraError::InvalidTransferDelta);
    }
    let metric = TransferMetric {
        source_delta,
        target_delta,
        retained_delta,
        portable_fraction,
        slots: slot_metrics,
    };
    if let Some((slot, reasons)) = first_rejection {
        return Err(CheckpointAlgebraError::TargetGateRejected {
            slot,
            metric,
            reasons,
        });
    }

    let mut manifests = source.manifests().clone();
    for manifest in manifests.values_mut() {
        manifest.base_model = to.clone();
    }
    readmit_all(&manifests, admissions)?;
    Ok(TransferResult {
        output: AlgebraOutput {
            checkpoint: PolicyCheckpoint::build(
                source.bundle().bundle_id.clone(),
                source.bundle().rollback_to.clone(),
                manifests,
            )?,
            events: vec![CheckpointEvent::Transferred {
                slots: expected_slots,
                from: from.clone(),
                to: to.clone(),
                portable_fraction,
            }],
            // `evaluation_b` is the required fresh target-model held-out result. It is returned
            // beside the output as `target_assessment`; no source-model pass is inherited.
            fresh_held_out_required: false,
        },
        metric,
        target_assessment: PromotionAssessment::EligibleForReleaseReview {
            suggested_next: DeploymentStage::Shadow,
        },
    })
}

fn finite_sum(mut values: impl Iterator<Item = f64>) -> Result<f64, CheckpointAlgebraError> {
    values.try_fold(0.0, |total, value| {
        let next = total + value;
        next.is_finite()
            .then_some(next)
            .ok_or(CheckpointAlgebraError::InvalidTransferDelta)
    })
}
