//! Matched-instance evaluation reports shared by open-harness and trained-bundle comparisons.

use crate::report::{InsufficientPowerReason, StatisticalConclusion};
use crate::statistics::{paired_bootstrap_interval, rate};
use crate::types::{
    CellResult, CostStatus, EvaluationManifest, EvaluationPurpose, Partition, RunStatus,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

pub const MEASUREMENT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MeasurementError {
    #[error("paired evidence can only be produced from score/held-out manifests")]
    NotHeldOut,
    #[error("paired arms must use the same frozen model")]
    ModelMismatch,
    #[error("paired arms must use the same provider route")]
    ProviderMismatch,
    #[error("paired arms must use the same corpus version and dataset digest")]
    CorpusMismatch,
    #[error("paired arm `{0}` is missing")]
    MissingArm(String),
    #[error("paired arm `{arm}` has an invalid sampling control at `{task}`/{seed}")]
    InvalidSamplingControl {
        arm: String,
        task: String,
        seed: u64,
    },
    #[error("paired arm `{arm}` contains duplicate task/seed key `{task}`/{seed}")]
    DuplicateCell {
        arm: String,
        task: String,
        seed: u64,
    },
    #[error("paired arms must contain the same attempted task/seed cells")]
    PairingMismatch,
    #[error("minimum paired observations must be at least one")]
    InvalidMinimumPairs,
    #[error("cannot encode paired evaluation artifact: {0}")]
    Encode(String),
    #[error("cannot write paired evaluation artifact `{path}`: {reason}")]
    Write { path: String, reason: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairedArmSummary {
    pub name: String,
    pub attempted: u64,
    pub completed: u64,
    pub resolved: u64,
    pub resolved_rate: f64,
    pub failed_runs: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairedComparison {
    pub baseline: PairedArmSummary,
    pub treatment: PairedArmSummary,
    pub matched_pairs: u64,
    pub minimum_pairs: u64,
    pub resolved_rate_delta: f64,
    pub paired_ci95: [f64; 2],
    pub statistical_conclusion: StatisticalConclusion,
    pub statistically_significant: bool,
    /// Present only when every attempted cell in both arms carries an explicit numeric rate card.
    pub cost_delta_usd: Option<f64>,
    pub cost_delta_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelTaxLine {
    pub label: String,
    pub status: String,
    pub turns_delta: Option<f64>,
    pub cost_delta_usd: Option<f64>,
    pub latency_delta_ms: Option<f64>,
    /// This is a schema invariant, not caller-selectable report decoration.
    pub included_in_resolved_rate: bool,
}

impl KernelTaxLine {
    pub fn reserved() -> Self {
        Self {
            label: "kernel_tax".into(),
            status: "reserved".into(),
            turns_delta: None,
            cost_delta_usd: None,
            latency_delta_ms: None,
            included_in_resolved_rate: false,
        }
    }

    pub fn measured(
        turns_delta: Option<f64>,
        cost_delta_usd: Option<f64>,
        latency_delta_ms: Option<f64>,
    ) -> Self {
        Self {
            label: "kernel_tax".into(),
            status: "measured".into(),
            turns_delta,
            cost_delta_usd,
            latency_delta_ms,
            included_in_resolved_rate: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairedEvaluationReport {
    pub schema_version: u32,
    pub report_type: String,
    pub corpus_version: String,
    pub dataset_digest: String,
    pub model: String,
    pub provider: Option<String>,
    pub comparison: PairedComparison,
    pub kernel_tax: KernelTaxLine,
}

impl PairedEvaluationReport {
    pub fn write_atomic(&self, path: &Path) -> Result<(), MeasurementError> {
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| MeasurementError::Encode(error.to_string()))?;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent).map_err(|error| MeasurementError::Write {
            path: parent.display().to_string(),
            reason: error.to_string(),
        })?;
        let temporary = parent.join(format!(
            ".{}.tmp-{}",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("core-eval-measurement"),
            std::process::id()
        ));
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| MeasurementError::Write {
                path: temporary.display().to_string(),
                reason: error.to_string(),
            })?;
        file.write_all(&bytes)
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .map_err(|error| MeasurementError::Write {
                path: temporary.display().to_string(),
                reason: error.to_string(),
            })?;
        std::fs::rename(&temporary, path).map_err(|error| MeasurementError::Write {
            path: path.display().to_string(),
            reason: error.to_string(),
        })
    }
}

pub fn compare_manifest_arms(
    manifest: &EvaluationManifest,
    baseline: &str,
    treatment: &str,
    minimum_pairs: u64,
) -> Result<PairedEvaluationReport, MeasurementError> {
    compare_manifests(
        manifest,
        baseline,
        manifest,
        treatment,
        minimum_pairs,
        "untrained_vs_open_harness",
        KernelTaxLine::reserved(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn compare_manifests(
    baseline_manifest: &EvaluationManifest,
    baseline: &str,
    treatment_manifest: &EvaluationManifest,
    treatment: &str,
    minimum_pairs: u64,
    report_type: &str,
    kernel_tax: KernelTaxLine,
) -> Result<PairedEvaluationReport, MeasurementError> {
    if minimum_pairs == 0 {
        return Err(MeasurementError::InvalidMinimumPairs);
    }
    validate_held_out(baseline_manifest)?;
    validate_held_out(treatment_manifest)?;
    if baseline_manifest.model != treatment_manifest.model {
        return Err(MeasurementError::ModelMismatch);
    }
    if baseline_manifest.provider != treatment_manifest.provider {
        return Err(MeasurementError::ProviderMismatch);
    }
    if baseline_manifest.corpus_version != treatment_manifest.corpus_version
        || baseline_manifest.dataset_digest != treatment_manifest.dataset_digest
    {
        return Err(MeasurementError::CorpusMismatch);
    }

    let baseline_cells = cells_for_arm(baseline_manifest, baseline);
    let treatment_cells = cells_for_arm(treatment_manifest, treatment);
    validate_sampling_controls(baseline, &baseline_cells)?;
    validate_sampling_controls(treatment, &treatment_cells)?;
    let missing_arm = baseline_cells.is_empty() || treatment_cells.is_empty();
    let baseline_by_key = keyed_cells(baseline, &baseline_cells)?;
    let treatment_by_key = keyed_cells(treatment, &treatment_cells)?;
    if !missing_arm && baseline_by_key.keys().ne(treatment_by_key.keys()) {
        return Err(MeasurementError::PairingMismatch);
    }
    let pairs = baseline_by_key
        .iter()
        .filter_map(|(key, baseline_cell)| {
            let treatment_cell = treatment_by_key.get(key)?;
            match (
                completed_resolution(baseline_cell),
                completed_resolution(treatment_cell),
            ) {
                (Some(baseline), Some(treatment)) => Some((baseline, treatment)),
                _ => None,
            }
        })
        .collect::<Vec<_>>();

    let baseline_resolved = pairs.iter().filter(|(resolved, _)| *resolved).count() as u64;
    let treatment_resolved = pairs.iter().filter(|(_, resolved)| *resolved).count() as u64;
    let matched_pairs = pairs.len() as u64;
    let delta = rate(treatment_resolved, matched_pairs) - rate(baseline_resolved, matched_pairs);
    let ci = paired_bootstrap_interval(&pairs);
    let statistical_conclusion = if missing_arm {
        StatisticalConclusion::InsufficientPower(InsufficientPowerReason::MissingComparisonArm)
    } else if matched_pairs < minimum_pairs {
        StatisticalConclusion::InsufficientPower(InsufficientPowerReason::BelowMinimumSeeds)
    } else if ci[0] > 0.0 {
        StatisticalConclusion::SignificantIncrease
    } else if ci[1] < 0.0 {
        StatisticalConclusion::SignificantDecrease
    } else {
        StatisticalConclusion::NotSignificant
    };
    let (cost_delta_usd, cost_delta_reason) = priced_delta(&baseline_cells, &treatment_cells);

    Ok(PairedEvaluationReport {
        schema_version: MEASUREMENT_SCHEMA_VERSION,
        report_type: report_type.to_owned(),
        corpus_version: baseline_manifest.corpus_version.clone(),
        dataset_digest: baseline_manifest.dataset_digest.clone(),
        model: baseline_manifest.model.clone(),
        provider: baseline_manifest.provider.clone(),
        comparison: PairedComparison {
            baseline: arm_summary(baseline, &baseline_cells),
            treatment: arm_summary(treatment, &treatment_cells),
            matched_pairs,
            minimum_pairs,
            resolved_rate_delta: delta,
            paired_ci95: ci,
            statistically_significant: statistical_conclusion.is_significant(),
            statistical_conclusion,
            cost_delta_usd,
            cost_delta_reason,
        },
        kernel_tax,
    })
}

fn validate_held_out(manifest: &EvaluationManifest) -> Result<(), MeasurementError> {
    if manifest.purpose != EvaluationPurpose::Score
        || manifest
            .cells
            .iter()
            .any(|cell| cell.partition != Partition::HeldOut)
    {
        return Err(MeasurementError::NotHeldOut);
    }
    Ok(())
}

fn cells_for_arm<'a>(manifest: &'a EvaluationManifest, arm: &str) -> Vec<&'a CellResult> {
    manifest
        .cells
        .iter()
        .filter(|cell| cell.config == arm)
        .collect()
}

fn validate_sampling_controls(arm: &str, cells: &[&CellResult]) -> Result<(), MeasurementError> {
    for cell in cells {
        let reason_is_valid = cell.sampling.enforcement != "uncontrolled"
            || cell
                .sampling
                .reason
                .as_deref()
                .is_some_and(|reason| !reason.trim().is_empty());
        if cell.sampling.requested_seed != cell.seed
            || cell.sampling.enforcement.trim().is_empty()
            || !reason_is_valid
        {
            return Err(MeasurementError::InvalidSamplingControl {
                arm: arm.to_owned(),
                task: cell.task.clone(),
                seed: cell.seed,
            });
        }
    }
    Ok(())
}

fn keyed_cells<'a>(
    arm: &str,
    cells: &[&'a CellResult],
) -> Result<BTreeMap<(&'a str, u64), &'a CellResult>, MeasurementError> {
    let mut keyed = BTreeMap::new();
    for cell in cells {
        let key = (cell.task.as_str(), cell.seed);
        if keyed.insert(key, *cell).is_some() {
            return Err(MeasurementError::DuplicateCell {
                arm: arm.to_owned(),
                task: cell.task.clone(),
                seed: cell.seed,
            });
        }
    }
    Ok(keyed)
}

fn completed_resolution(cell: &CellResult) -> Option<bool> {
    (cell.run_status == RunStatus::Completed)
        .then_some(cell.resolved)
        .flatten()
}

fn arm_summary(name: &str, cells: &[&CellResult]) -> PairedArmSummary {
    let completed = cells
        .iter()
        .filter_map(|cell| completed_resolution(cell))
        .collect::<Vec<_>>();
    let resolved = completed.iter().filter(|resolved| **resolved).count() as u64;
    PairedArmSummary {
        name: name.to_owned(),
        attempted: cells.len() as u64,
        completed: completed.len() as u64,
        resolved,
        resolved_rate: rate(resolved, completed.len() as u64),
        failed_runs: cells
            .iter()
            .filter(|cell| matches!(cell.run_status, RunStatus::Errored | RunStatus::TimedOut))
            .count() as u64,
    }
}

fn priced_delta(
    baseline: &[&CellResult],
    treatment: &[&CellResult],
) -> (Option<f64>, Option<String>) {
    let prices = |cells: &[&CellResult]| {
        cells
            .iter()
            .map(|cell| {
                (cell.cost_status == CostStatus::Known)
                    .then_some(cell.cost_usd)
                    .flatten()
                    .filter(|cost| cost.is_finite() && *cost >= 0.0)
            })
            .collect::<Option<Vec<_>>>()
    };
    match (prices(baseline), prices(treatment)) {
        (Some(baseline), Some(treatment)) if !baseline.is_empty() && !treatment.is_empty() => {
            let baseline = baseline.iter().sum::<f64>() / baseline.len() as f64;
            let treatment = treatment.iter().sum::<f64>() / treatment.len() as f64;
            (Some(treatment - baseline), None)
        }
        _ => (
            None,
            Some("every_attempted_cell_must_have_an_explicit_numeric_rate_card".into()),
        ),
    }
}
