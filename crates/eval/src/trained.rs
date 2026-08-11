//! Held-out trained-bundle, cross-model transfer, and isolated kernel-tax reporting.

use crate::measurement::{
    KernelTaxLine, MeasurementError, PairedEvaluationReport, compare_manifests,
};
use crate::types::{CostStatus, EvaluationManifest, EvaluationPurpose, Partition};
use iteron_evolve::{ArtifactKind, EvolutionMethod};
use serde::{Deserialize, Serialize};

pub const TRAINED_REPORT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainedBundleDescriptor {
    pub bundle_digest: String,
    pub training_dataset_digest: String,
    pub producer_id: String,
    pub method: EvolutionMethod,
    pub artifact_kind: ArtifactKind,
}

impl TrainedBundleDescriptor {
    pub fn validate(&self) -> Result<(), TrainedEvaluationError> {
        validate_sha256(&self.bundle_digest, "bundle_digest")?;
        validate_sha256(&self.training_dataset_digest, "training_dataset_digest")?;
        if self.producer_id.trim().is_empty() || self.producer_id.len() > 256 {
            return Err(TrainedEvaluationError::InvalidDescriptor(
                "producer_id must contain 1..=256 bytes".into(),
            ));
        }
        if self.method == EvolutionMethod::Unknown || self.artifact_kind == ArtifactKind::Unknown {
            return Err(TrainedEvaluationError::InvalidDescriptor(
                "unknown producer vocabulary fails closed".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableFractionReport {
    pub bundle_digest: String,
    pub original_model: String,
    pub rebound_model: String,
    pub original_held_out_gain: f64,
    pub retained_held_out_gain: f64,
    pub portable_fraction: f64,
    /// Cross-model portability is descriptive evidence and never edits a promotion threshold.
    pub applied_to_promotion_threshold: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainedEvaluationReport {
    pub schema_version: u32,
    pub report_type: String,
    pub bundle: TrainedBundleDescriptor,
    pub trained_vs_untrained: PairedEvaluationReport,
    pub cross_model_transfer: Option<PortableFractionReport>,
}

#[derive(Debug, thiserror::Error)]
pub enum TrainedEvaluationError {
    #[error(transparent)]
    Measurement(#[from] MeasurementError),
    #[error("invalid trained-bundle descriptor: {0}")]
    InvalidDescriptor(String),
    #[error("trained-bundle scoring is restricted to score/held-out manifests")]
    Contamination,
    #[error("trained manifest does not record the descriptor's immutable bundle digest")]
    BundleMismatch,
    #[error("training and held-out evaluation dataset digests must differ")]
    TrainEvalDigestOverlap,
    #[error("cross-model transfer requires two different frozen base models")]
    SameModel,
    #[error("cross-model transfer requires the identical bundle in both trained arms")]
    ReboundBundleMismatch,
    #[error("cross-model transfer must reuse the same held-out corpus")]
    TransferCorpusMismatch,
    #[error("portable_fraction is undefined when the original held-out gain is zero")]
    ZeroOriginalGain,
    #[error("kernel-tax arms must bind the identical policy bundle")]
    KernelTaxBundleMismatch,
    #[error("kernel-tax arms must contain the same task/seed cells")]
    KernelTaxCellMismatch,
}

#[allow(clippy::too_many_arguments)]
pub fn trained_vs_untrained_report(
    untrained: &EvaluationManifest,
    untrained_arm: &str,
    trained: &EvaluationManifest,
    trained_arm: &str,
    minimum_pairs: u64,
    bundle: TrainedBundleDescriptor,
    kernel_tax: KernelTaxLine,
) -> Result<TrainedEvaluationReport, TrainedEvaluationError> {
    bundle.validate()?;
    validate_trained_manifest(trained, &bundle)?;
    validate_held_out(untrained)?;
    let paired = compare_manifests(
        untrained,
        untrained_arm,
        trained,
        trained_arm,
        minimum_pairs,
        "trained_vs_untrained",
        kernel_tax,
    )?;
    Ok(TrainedEvaluationReport {
        schema_version: TRAINED_REPORT_SCHEMA_VERSION,
        report_type: "trained_bundle_held_out".into(),
        bundle,
        trained_vs_untrained: paired,
        cross_model_transfer: None,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn attach_cross_model_transfer(
    report: &mut TrainedEvaluationReport,
    second_untrained: &EvaluationManifest,
    second_untrained_arm: &str,
    second_trained: &EvaluationManifest,
    second_trained_arm: &str,
    minimum_pairs: u64,
) -> Result<(), TrainedEvaluationError> {
    validate_trained_manifest(second_trained, &report.bundle)?;
    validate_held_out(second_untrained)?;
    if report.trained_vs_untrained.corpus_version != second_trained.corpus_version
        || report.trained_vs_untrained.dataset_digest != second_trained.dataset_digest
    {
        return Err(TrainedEvaluationError::TransferCorpusMismatch);
    }
    if report.trained_vs_untrained.model == second_trained.model {
        return Err(TrainedEvaluationError::SameModel);
    }
    let second = compare_manifests(
        second_untrained,
        second_untrained_arm,
        second_trained,
        second_trained_arm,
        minimum_pairs,
        "cross_model_rebound",
        KernelTaxLine::reserved(),
    )?;
    let original_gain = report.trained_vs_untrained.comparison.resolved_rate_delta;
    if original_gain == 0.0 {
        return Err(TrainedEvaluationError::ZeroOriginalGain);
    }
    let retained_gain = second.comparison.resolved_rate_delta;
    report.cross_model_transfer = Some(PortableFractionReport {
        bundle_digest: report.bundle.bundle_digest.clone(),
        original_model: report.trained_vs_untrained.model.clone(),
        rebound_model: second.model,
        original_held_out_gain: original_gain,
        retained_held_out_gain: retained_gain,
        portable_fraction: retained_gain / original_gain,
        applied_to_promotion_threshold: false,
    });
    Ok(())
}

pub fn measure_kernel_tax(
    bare: &EvaluationManifest,
    bare_arm: &str,
    governed: &EvaluationManifest,
    governed_arm: &str,
) -> Result<KernelTaxLine, TrainedEvaluationError> {
    validate_held_out(bare)?;
    validate_held_out(governed)?;
    if bare.model != governed.model {
        return Err(MeasurementError::ModelMismatch.into());
    }
    if bare.provider != governed.provider {
        return Err(MeasurementError::ProviderMismatch.into());
    }
    if bare.corpus_version != governed.corpus_version
        || bare.dataset_digest != governed.dataset_digest
    {
        return Err(MeasurementError::CorpusMismatch.into());
    }
    if bare.bundle_digest != governed.bundle_digest {
        return Err(TrainedEvaluationError::KernelTaxBundleMismatch);
    }
    let bare_cells = arm_cells(bare, bare_arm)?;
    let governed_cells = arm_cells(governed, governed_arm)?;
    let cell_keys = |cells: &[&crate::CellResult]| {
        cells
            .iter()
            .map(|cell| (cell.task.clone(), cell.seed))
            .collect::<std::collections::BTreeSet<_>>()
    };
    if bare_cells.len() != governed_cells.len()
        || cell_keys(&bare_cells) != cell_keys(&governed_cells)
    {
        return Err(TrainedEvaluationError::KernelTaxCellMismatch);
    }
    Ok(KernelTaxLine::measured(
        average_turns(&governed_cells)
            .zip(average_turns(&bare_cells))
            .map(|(governed, bare)| governed - bare),
        average_cost(&governed_cells)
            .zip(average_cost(&bare_cells))
            .map(|(governed, bare)| governed - bare),
        Some(average_latency(&governed_cells) - average_latency(&bare_cells)),
    ))
}

fn validate_trained_manifest(
    manifest: &EvaluationManifest,
    bundle: &TrainedBundleDescriptor,
) -> Result<(), TrainedEvaluationError> {
    validate_held_out(manifest)?;
    if manifest.bundle_digest.as_deref() != Some(bundle.bundle_digest.as_str()) {
        return Err(TrainedEvaluationError::BundleMismatch);
    }
    if digest_body(&manifest.dataset_digest) == digest_body(&bundle.training_dataset_digest) {
        return Err(TrainedEvaluationError::TrainEvalDigestOverlap);
    }
    Ok(())
}

fn validate_held_out(manifest: &EvaluationManifest) -> Result<(), TrainedEvaluationError> {
    if manifest.purpose != EvaluationPurpose::Score
        || manifest
            .cells
            .iter()
            .any(|cell| cell.partition != Partition::HeldOut)
    {
        return Err(TrainedEvaluationError::Contamination);
    }
    Ok(())
}

fn validate_sha256(value: &str, field: &str) -> Result<(), TrainedEvaluationError> {
    let Some(digest) = value.strip_prefix("sha256:") else {
        return Err(TrainedEvaluationError::InvalidDescriptor(format!(
            "{field} must be sha256:<64 lowercase hex>"
        )));
    };
    if digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(TrainedEvaluationError::InvalidDescriptor(format!(
            "{field} must be sha256:<64 lowercase hex>"
        )))
    }
}

fn digest_body(value: &str) -> &str {
    value.strip_prefix("sha256:").unwrap_or(value)
}

fn arm_cells<'a>(
    manifest: &'a EvaluationManifest,
    arm: &str,
) -> Result<Vec<&'a crate::CellResult>, TrainedEvaluationError> {
    let cells = manifest
        .cells
        .iter()
        .filter(|cell| cell.config == arm)
        .collect::<Vec<_>>();
    if cells.is_empty() {
        Err(MeasurementError::MissingArm(arm.to_owned()).into())
    } else {
        Ok(cells)
    }
}

fn average_turns(cells: &[&crate::CellResult]) -> Option<f64> {
    let values = cells
        .iter()
        .map(|cell| cell.turns.map(f64::from))
        .collect::<Option<Vec<_>>>()?;
    (!values.is_empty()).then(|| values.iter().sum::<f64>() / values.len() as f64)
}

fn average_cost(cells: &[&crate::CellResult]) -> Option<f64> {
    let values = cells
        .iter()
        .map(|cell| {
            (cell.cost_status == CostStatus::Known)
                .then_some(cell.cost_usd)
                .flatten()
        })
        .collect::<Option<Vec<_>>>()?;
    (!values.is_empty()).then(|| values.iter().sum::<f64>() / values.len() as f64)
}

fn average_latency(cells: &[&crate::CellResult]) -> f64 {
    cells.iter().map(|cell| cell.elapsed_ms as f64).sum::<f64>() / cells.len() as f64
}
