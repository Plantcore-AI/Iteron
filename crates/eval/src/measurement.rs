//! Matched-instance evaluation reports shared by open-harness and trained-bundle comparisons.

use crate::report::{InsufficientPowerReason, StatisticalConclusion};
use crate::statistics::{paired_bootstrap_interval, paired_mean_delta_interval, rate};
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
    #[error("performance thresholds must be finite and inside their documented ranges")]
    InvalidPerformanceThresholds,
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

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerformanceThresholds {
    pub minimum_pairs: u64,
    /// Maximum admitted lower confidence bound loss in resolved rate, in `[0, 1]`.
    pub resolution_noninferiority_margin: f64,
    /// Required fractional reduction relative to the baseline mean, in `[0, 1)`.
    pub minimum_latency_reduction_ratio: f64,
    /// Required fractional reduction relative to the baseline mean, in `[0, 1)`.
    pub minimum_token_reduction_ratio: f64,
}

impl PerformanceThresholds {
    fn validate(self) -> Result<(), MeasurementError> {
        if self.minimum_pairs == 0
            || !self.resolution_noninferiority_margin.is_finite()
            || !(0.0..=1.0).contains(&self.resolution_noninferiority_margin)
            || !self.minimum_latency_reduction_ratio.is_finite()
            || !(0.0..1.0).contains(&self.minimum_latency_reduction_ratio)
            || !self.minimum_token_reduction_ratio.is_finite()
            || !(0.0..1.0).contains(&self.minimum_token_reduction_ratio)
        {
            return Err(MeasurementError::InvalidPerformanceThresholds);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerformanceArmSummary {
    pub name: String,
    pub attempted: u64,
    /// Resolved rate uses every attempted cell as its denominator. Fast failures therefore cannot
    /// improve either the completion score or the efficiency comparison's eligibility.
    pub resolved: u64,
    pub resolved_rate: f64,
    pub harness_failures: u64,
    pub complete_metric_cells: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairedMetricComparison {
    pub matched_success_pairs: u64,
    pub baseline_mean: f64,
    pub treatment_mean: f64,
    pub mean_delta: f64,
    pub paired_delta_ci95: [f64; 2],
    pub reduction_ratio: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceDecision {
    Outperforms,
    BelowMinimumPairs,
    HarnessFailures,
    MissingMetrics,
    CompletionRegressed,
    BelowMinimumMatchedSuccesses,
    LatencyNotImproved,
    TokenUseNotImproved,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerformanceEvaluationReport {
    pub schema_version: u32,
    pub report_type: String,
    pub corpus_version: String,
    pub dataset_digest: String,
    pub model: String,
    pub provider: Option<String>,
    pub thresholds: PerformanceThresholds,
    pub baseline: PerformanceArmSummary,
    pub treatment: PerformanceArmSummary,
    pub paired_attempts: u64,
    pub resolved_rate_delta: f64,
    pub resolved_rate_paired_ci95: [f64; 2],
    pub latency_ms: Option<PairedMetricComparison>,
    pub total_tokens: Option<PairedMetricComparison>,
    pub decision: PerformanceDecision,
    pub outperforms: bool,
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
                .unwrap_or("iteron-eval-measurement"),
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

/// Compare two harness arms without embedding either harness identity in the evaluator.
///
/// Completion is paired over every attempt. Latency and token use are paired only where both arms
/// resolved the same task, while metric coverage is still required for every attempt. A result can
/// therefore be faster and cheaper without earning `outperforms` when it failed fast, omitted
/// usage, or changed the set of attempted cells.
pub fn compare_performance_manifests(
    baseline_manifest: &EvaluationManifest,
    baseline: &str,
    treatment_manifest: &EvaluationManifest,
    treatment: &str,
    thresholds: PerformanceThresholds,
) -> Result<PerformanceEvaluationReport, MeasurementError> {
    thresholds.validate()?;
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
    if baseline_cells.is_empty() {
        return Err(MeasurementError::MissingArm(baseline.to_owned()));
    }
    if treatment_cells.is_empty() {
        return Err(MeasurementError::MissingArm(treatment.to_owned()));
    }
    validate_sampling_controls(baseline, &baseline_cells)?;
    validate_sampling_controls(treatment, &treatment_cells)?;
    let baseline_by_key = keyed_cells(baseline, &baseline_cells)?;
    let treatment_by_key = keyed_cells(treatment, &treatment_cells)?;
    if baseline_by_key.keys().ne(treatment_by_key.keys()) {
        return Err(MeasurementError::PairingMismatch);
    }

    let mut outcomes = Vec::with_capacity(baseline_by_key.len());
    let mut latency_pairs = Vec::new();
    let mut token_pairs = Vec::new();
    for (key, baseline_cell) in &baseline_by_key {
        let treatment_cell = treatment_by_key[key];
        let baseline_resolved = resolved_attempt(baseline_cell);
        let treatment_resolved = resolved_attempt(treatment_cell);
        outcomes.push((baseline_resolved, treatment_resolved));
        if baseline_resolved
            && treatment_resolved
            && let (Some(baseline), Some(treatment)) =
                (baseline_cell.agent_metrics, treatment_cell.agent_metrics)
        {
            latency_pairs.push((baseline.elapsed_ms as f64, treatment.elapsed_ms as f64));
            if let (Some(baseline), Some(treatment)) =
                (baseline.total_tokens(), treatment.total_tokens())
            {
                token_pairs.push((baseline as f64, treatment as f64));
            }
        }
    }

    let baseline_summary = performance_arm_summary(baseline, &baseline_cells);
    let treatment_summary = performance_arm_summary(treatment, &treatment_cells);
    let paired_attempts = outcomes.len() as u64;
    let resolved_rate_delta = treatment_summary.resolved_rate - baseline_summary.resolved_rate;
    let resolved_rate_paired_ci95 = paired_bootstrap_interval(&outcomes);
    let latency_ms = paired_metric(&latency_pairs);
    let total_tokens = paired_metric(&token_pairs);
    let complete_metrics = baseline_summary.complete_metric_cells == baseline_summary.attempted
        && treatment_summary.complete_metric_cells == treatment_summary.attempted;
    let no_harness_failures =
        baseline_summary.harness_failures == 0 && treatment_summary.harness_failures == 0;
    let enough_success_pairs = latency_pairs.len() as u64 >= thresholds.minimum_pairs
        && token_pairs.len() as u64 >= thresholds.minimum_pairs;
    let completion_noninferior =
        resolved_rate_paired_ci95[0] >= -thresholds.resolution_noninferiority_margin;
    let latency_improved = latency_ms.as_ref().is_some_and(|metric| {
        metric.baseline_mean > 0.0
            && metric.reduction_ratio >= thresholds.minimum_latency_reduction_ratio
            && metric.paired_delta_ci95[1]
                <= -thresholds.minimum_latency_reduction_ratio * metric.baseline_mean
    });
    let tokens_improved = total_tokens.as_ref().is_some_and(|metric| {
        metric.baseline_mean > 0.0
            && metric.reduction_ratio >= thresholds.minimum_token_reduction_ratio
            && metric.paired_delta_ci95[1]
                <= -thresholds.minimum_token_reduction_ratio * metric.baseline_mean
    });
    let decision = if paired_attempts < thresholds.minimum_pairs {
        PerformanceDecision::BelowMinimumPairs
    } else if !no_harness_failures {
        PerformanceDecision::HarnessFailures
    } else if !complete_metrics {
        PerformanceDecision::MissingMetrics
    } else if !completion_noninferior {
        PerformanceDecision::CompletionRegressed
    } else if !enough_success_pairs {
        PerformanceDecision::BelowMinimumMatchedSuccesses
    } else if !latency_improved {
        PerformanceDecision::LatencyNotImproved
    } else if !tokens_improved {
        PerformanceDecision::TokenUseNotImproved
    } else {
        PerformanceDecision::Outperforms
    };

    Ok(PerformanceEvaluationReport {
        schema_version: 1,
        report_type: "matched_harness_performance".into(),
        corpus_version: baseline_manifest.corpus_version.clone(),
        dataset_digest: baseline_manifest.dataset_digest.clone(),
        model: baseline_manifest.model.clone(),
        provider: baseline_manifest.provider.clone(),
        thresholds,
        baseline: baseline_summary,
        treatment: treatment_summary,
        paired_attempts,
        resolved_rate_delta,
        resolved_rate_paired_ci95,
        latency_ms,
        total_tokens,
        decision,
        outperforms: decision == PerformanceDecision::Outperforms,
    })
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

fn resolved_attempt(cell: &CellResult) -> bool {
    cell.run_status == RunStatus::Completed && cell.resolved == Some(true)
}

fn performance_arm_summary(name: &str, cells: &[&CellResult]) -> PerformanceArmSummary {
    let attempted = cells.len() as u64;
    let resolved = cells.iter().filter(|cell| resolved_attempt(cell)).count() as u64;
    PerformanceArmSummary {
        name: name.to_owned(),
        attempted,
        resolved,
        resolved_rate: rate(resolved, attempted),
        harness_failures: cells
            .iter()
            .filter(|cell| matches!(cell.run_status, RunStatus::Errored | RunStatus::TimedOut))
            .count() as u64,
        complete_metric_cells: cells
            .iter()
            .filter(|cell| {
                cell.agent_metrics
                    .is_some_and(|metrics| metrics.total_tokens().is_some())
            })
            .count() as u64,
    }
}

fn paired_metric(pairs: &[(f64, f64)]) -> Option<PairedMetricComparison> {
    if pairs.is_empty() {
        return None;
    }
    let baseline_mean =
        pairs.iter().map(|(baseline, _)| *baseline).sum::<f64>() / pairs.len() as f64;
    let treatment_mean =
        pairs.iter().map(|(_, treatment)| *treatment).sum::<f64>() / pairs.len() as f64;
    let mean_delta = treatment_mean - baseline_mean;
    Some(PairedMetricComparison {
        matched_success_pairs: pairs.len() as u64,
        baseline_mean,
        treatment_mean,
        mean_delta,
        paired_delta_ci95: paired_mean_delta_interval(pairs)?,
        reduction_ratio: if baseline_mean > 0.0 {
            (baseline_mean - treatment_mean) / baseline_mean
        } else {
            0.0
        },
    })
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
