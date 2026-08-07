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
        && left.failed_runs <= right.failed_runs;
    let strictly_better = left.resolved_rate > right.resolved_rate
        || left.average_cost_usd < right.average_cost_usd
        || left.average_latency_ms < right.average_latency_ms
        || left.failed_runs < right.failed_runs;
    no_worse && strictly_better
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
}
