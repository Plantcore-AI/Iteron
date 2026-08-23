//! Deterministic multi-objective frontier for evaluation candidates.

use crate::types::{CostStatus, EvaluationManifest, RunStatus};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParetoPoint {
    pub candidate_id: String,
    /// Higher is better.
    pub resolved_rate: f64,
    /// Lower is better. Every attempted cell must have an explicit price.
    pub average_cost_usd: f64,
    /// Lower is better.
    pub average_latency_ms: f64,
    /// Agent-only latency for v4 evidence. Legacy points omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub average_agent_latency_ms: Option<f64>,
    /// Provider-accounted token use for v4 evidence. Legacy points omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub average_tokens: Option<f64>,
    /// Lower is better.
    pub failed_runs: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParetoReport {
    pub schema_version: u8,
    pub points: Vec<ParetoPoint>,
    pub frontier: Vec<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParetoError {
    #[error("candidate id must be non-empty and unique")]
    CandidateIdentity,
    #[error("candidate `{0}` has no cells for the selected arm")]
    MissingArm(String),
    #[error("candidate `{0}` has an unpriced cell")]
    Unpriced(String),
    #[error("candidate `{0}` has a non-finite or out-of-range metric")]
    InvalidMetric(String),
    #[error("candidate `{0}` has incomplete v4 agent metrics")]
    MissingPerformanceMetrics(String),
}

impl ParetoPoint {
    pub fn from_manifest_arm(
        candidate_id: impl Into<String>,
        manifest: &EvaluationManifest,
        arm: &str,
    ) -> Result<Self, ParetoError> {
        let candidate_id = candidate_id.into();
        let cells = manifest
            .cells
            .iter()
            .filter(|cell| cell.config == arm)
            .collect::<Vec<_>>();
        if cells.is_empty() {
            return Err(ParetoError::MissingArm(candidate_id));
        }
        let mut resolved = 0_u64;
        let mut completed = 0_u64;
        let mut cost = 0.0;
        let mut latency = 0.0;
        let mut agent_latency = 0.0;
        let mut tokens = 0.0;
        let mut failed = 0_u64;
        for cell in &cells {
            if cell.cost_status != CostStatus::Known {
                return Err(ParetoError::Unpriced(candidate_id));
            }
            let cell_cost = cell
                .cost_usd
                .filter(|value| value.is_finite() && *value >= 0.0)
                .ok_or_else(|| ParetoError::InvalidMetric(candidate_id.clone()))?;
            cost += cell_cost;
            latency += cell.elapsed_ms as f64;
            if manifest.schema_version >= 4 {
                let metrics = cell
                    .agent_metrics
                    .ok_or_else(|| ParetoError::MissingPerformanceMetrics(candidate_id.clone()))?;
                let cell_tokens = metrics
                    .total_tokens()
                    .ok_or_else(|| ParetoError::MissingPerformanceMetrics(candidate_id.clone()))?;
                agent_latency += metrics.elapsed_ms as f64;
                tokens += cell_tokens as f64;
            }
            if cell.run_status == RunStatus::Completed {
                completed += 1;
                resolved += u64::from(cell.resolved == Some(true));
            } else if matches!(cell.run_status, RunStatus::Errored | RunStatus::TimedOut) {
                failed += 1;
            }
        }
        let point = Self {
            candidate_id,
            resolved_rate: if completed == 0 {
                0.0
            } else {
                resolved as f64 / completed as f64
            },
            average_cost_usd: cost / cells.len() as f64,
            average_latency_ms: latency / cells.len() as f64,
            average_agent_latency_ms: (manifest.schema_version >= 4)
                .then_some(agent_latency / cells.len() as f64),
            average_tokens: (manifest.schema_version >= 4).then_some(tokens / cells.len() as f64),
            failed_runs: failed,
        };
        point.validate()?;
        Ok(point)
    }

    fn validate(&self) -> Result<(), ParetoError> {
        if self.candidate_id.trim().is_empty()
            || !self.resolved_rate.is_finite()
            || !(0.0..=1.0).contains(&self.resolved_rate)
            || !self.average_cost_usd.is_finite()
            || self.average_cost_usd < 0.0
            || !self.average_latency_ms.is_finite()
            || self.average_latency_ms < 0.0
            || self
                .average_agent_latency_ms
                .is_some_and(|value| !value.is_finite() || value < 0.0)
            || self
                .average_tokens
                .is_some_and(|value| !value.is_finite() || value < 0.0)
        {
            return Err(ParetoError::InvalidMetric(self.candidate_id.clone()));
        }
        Ok(())
    }
}

pub fn pareto_frontier(mut points: Vec<ParetoPoint>) -> Result<ParetoReport, ParetoError> {
    points.sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));
    let mut ids = BTreeSet::new();
    for point in &points {
        point.validate()?;
        if !ids.insert(point.candidate_id.clone()) {
            return Err(ParetoError::CandidateIdentity);
        }
    }
    let frontier = points
        .iter()
        .filter(|candidate| {
            !points.iter().any(|other| {
                other.candidate_id != candidate.candidate_id && dominates(other, candidate)
            })
        })
        .map(|point| point.candidate_id.clone())
        .collect();
    Ok(ParetoReport {
        schema_version: 1,
        points,
        frontier,
    })
}

fn dominates(left: &ParetoPoint, right: &ParetoPoint) -> bool {
    let no_worse = left.resolved_rate >= right.resolved_rate
        && left.average_cost_usd <= right.average_cost_usd
        && left.average_latency_ms <= right.average_latency_ms
        && optional_no_worse(
            left.average_agent_latency_ms,
            right.average_agent_latency_ms,
        )
        && optional_no_worse(left.average_tokens, right.average_tokens)
        && left.failed_runs <= right.failed_runs;
    let strictly_better = left.resolved_rate > right.resolved_rate
        || left.average_cost_usd < right.average_cost_usd
        || left.average_latency_ms < right.average_latency_ms
        || optional_strictly_better(
            left.average_agent_latency_ms,
            right.average_agent_latency_ms,
        )
        || optional_strictly_better(left.average_tokens, right.average_tokens)
        || left.failed_runs < right.failed_runs;
    no_worse && strictly_better
}

fn optional_no_worse(left: Option<f64>, right: Option<f64>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left <= right,
        (Some(_), None) | (None, None) => true,
        (None, Some(_)) => false,
    }
}

fn optional_strictly_better(left: Option<f64>, right: Option<f64>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left < right,
        (Some(_), None) => true,
        (None, Some(_)) | (None, None) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(id: &str, quality: f64, cost: f64, latency: f64) -> ParetoPoint {
        ParetoPoint {
            candidate_id: id.into(),
            resolved_rate: quality,
            average_cost_usd: cost,
            average_latency_ms: latency,
            average_agent_latency_ms: None,
            average_tokens: None,
            failed_runs: 0,
        }
    }

    #[test]
    fn frontier_keeps_tradeoffs_and_drops_a_dominated_candidate() {
        let report = pareto_frontier(vec![
            point("slow-strong", 0.9, 2.0, 8.0),
            point("dominated", 0.7, 2.0, 8.0),
            point("fast-cheap", 0.7, 1.0, 3.0),
        ])
        .unwrap();
        assert_eq!(report.frontier, ["fast-cheap", "slow-strong"]);
        assert_eq!(report.points[0].candidate_id, "dominated");
    }

    #[test]
    fn non_finite_metrics_and_duplicate_identities_are_refused() {
        assert!(pareto_frontier(vec![point("bad", f64::NAN, 1.0, 1.0)]).is_err());
        assert!(
            pareto_frontier(vec![
                point("same", 0.5, 1.0, 1.0),
                point("same", 0.6, 1.0, 1.0),
            ])
            .is_err()
        );
    }

    #[test]
    fn complete_agent_metrics_dominate_an_otherwise_equal_legacy_point() {
        let legacy = point("legacy", 0.8, 1.0, 10.0);
        let mut complete = point("complete", 0.8, 1.0, 10.0);
        complete.average_agent_latency_ms = Some(8.0);
        complete.average_tokens = Some(100.0);
        let report = pareto_frontier(vec![legacy, complete]).unwrap();
        assert_eq!(report.frontier, ["complete"]);
    }
}
