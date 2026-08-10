//! Deterministic aggregation for fixed-model component-toggle evaluations.

use crate::types::{CellResult, CostStatus, RunStatus};
use iteron_verify::{Candidate, OracleStrength};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigAggregate {
    pub config: String,
    pub cells: u64,
    pub completed: u64,
    pub resolved: u64,
    pub errored: u64,
    pub censored: u64,
    pub timed_out: u64,
    pub resolved_rate: f64,
    pub resolved_rate_ci95: [f64; 2],
    pub known_cost_cells: u64,
    pub zero_cost_cells: u64,
    pub unknown_cost_cells: u64,
    /// Average over cells carrying a verified numeric rate card only.
    pub average_known_cost_usd: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PassK {
    pub task: String,
    pub config: String,
    pub completed_seeds: u64,
    pub resolved_seeds: u64,
    pub all_completed_resolved: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Aggregate {
    pub total_cells: u64,
    pub minimum_seeds: u64,
    pub underpowered: bool,
    pub configs: Vec<ConfigAggregate>,
    pub pass_k: Vec<PassK>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Comparison {
    pub baseline: String,
    pub treatment: String,
    pub resolved_rate_delta: f64,
    pub delta_ci95: [f64; 2],
    pub statistical_conclusion: StatisticalConclusion,
    pub statistically_significant: bool,
    /// Present only when every attempted cell in both arms is explicitly priced.
    pub cost_delta_usd: Option<f64>,
    pub cost_delta_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InsufficientPowerReason {
    MissingComparisonArm,
    BelowMinimumSeeds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", content = "reason", rename_all = "snake_case")]
pub enum StatisticalConclusion {
    InsufficientPower(InsufficientPowerReason),
    NotSignificant,
    SignificantIncrease,
    SignificantDecrease,
}

impl StatisticalConclusion {
    pub fn is_significant(self) -> bool {
        matches!(self, Self::SignificantIncrease | Self::SignificantDecrease)
    }
}

impl fmt::Display for StatisticalConclusion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientPower(reason) => write!(formatter, "insufficient_power:{reason}"),
            Self::NotSignificant => formatter.write_str("not_significant"),
            Self::SignificantIncrease => formatter.write_str("significant_increase"),
            Self::SignificantDecrease => formatter.write_str("significant_decrease"),
        }
    }
}

impl fmt::Display for InsufficientPowerReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingComparisonArm => formatter.write_str("missing_comparison_arm"),
            Self::BelowMinimumSeeds => formatter.write_str("below_minimum_seeds"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionSummary {
    pub task: String,
    pub candidates: u64,
    pub chosen: Option<u64>,
    pub ceiling: bool,
    pub resolved: bool,
    pub resolve_vs_ceiling_gap: bool,
}

/// Aggregate completed cells without turning crashes, censorship, or timeouts into wrong patches.
pub fn aggregate(cells: &[CellResult], minimum_seeds: u64) -> Aggregate {
    let mut by_config: BTreeMap<&str, Vec<&CellResult>> = BTreeMap::new();
    let mut by_task_config: BTreeMap<(&str, &str), Vec<&CellResult>> = BTreeMap::new();
    let mut tasks = BTreeSet::new();
    for cell in cells {
        tasks.insert(cell.task.as_str());
        by_config.entry(&cell.config).or_default().push(cell);
        by_task_config
            .entry((&cell.task, &cell.config))
            .or_default()
            .push(cell);
    }

    let expected_groups = tasks.len().checked_mul(by_config.len());
    let mut underpowered =
        by_task_config.is_empty() || expected_groups != Some(by_task_config.len());

    let configs = by_config
        .into_iter()
        .map(|(config, group)| config_aggregate(config, &group))
        .collect();

    let pass_k = by_task_config
        .into_iter()
        .map(|((task, config), group)| {
            let completed: Vec<_> = group
                .iter()
                .filter(|cell| cell.run_status == RunStatus::Completed && cell.resolved.is_some())
                .collect();
            let seeds: BTreeSet<_> = completed.iter().map(|cell| cell.seed).collect();
            underpowered |= (seeds.len() as u64) < minimum_seeds;
            let resolved = completed
                .iter()
                .filter(|cell| cell.resolved == Some(true))
                .count();
            PassK {
                task: task.to_owned(),
                config: config.to_owned(),
                completed_seeds: completed.len() as u64,
                resolved_seeds: resolved as u64,
                all_completed_resolved: !completed.is_empty() && resolved == completed.len(),
            }
        })
        .collect();

    Aggregate {
        total_cells: cells.len() as u64,
        minimum_seeds,
        underpowered,
        configs,
        pass_k,
    }
}

fn config_aggregate(config: &str, cells: &[&CellResult]) -> ConfigAggregate {
    let completed: Vec<_> = cells
        .iter()
        .filter(|cell| cell.run_status == RunStatus::Completed && cell.resolved.is_some())
        .collect();
    let resolved = completed
        .iter()
        .filter(|cell| cell.resolved == Some(true))
        .count();
    let rate = crate::statistics::rate(resolved as u64, completed.len() as u64);
    let known_costs: Vec<_> = cells
        .iter()
        .filter_map(|cell| {
            (cell.cost_status == CostStatus::Known)
                .then_some(cell.cost_usd)
                .flatten()
        })
        .collect();

    ConfigAggregate {
        config: config.to_owned(),
        cells: cells.len() as u64,
        completed: completed.len() as u64,
        resolved: resolved as u64,
        errored: count_status(cells, RunStatus::Errored),
        censored: count_status(cells, RunStatus::Censored),
        timed_out: count_status(cells, RunStatus::TimedOut),
        resolved_rate: rate,
        resolved_rate_ci95: crate::statistics::wilson_interval(
            resolved as u64,
            completed.len() as u64,
        ),
        known_cost_cells: known_costs.len() as u64,
        zero_cost_cells: cells
            .iter()
            .filter(|cell| cell.cost_status == CostStatus::Zero)
            .count() as u64,
        unknown_cost_cells: cells
            .iter()
            .filter(|cell| cell.cost_status == CostStatus::Unknown)
            .count() as u64,
        average_known_cost_usd: (!known_costs.is_empty())
            .then(|| known_costs.iter().sum::<f64>() / known_costs.len() as f64),
    }
}

fn count_status(cells: &[&CellResult], status: RunStatus) -> u64 {
    cells
        .iter()
        .filter(|cell| cell.run_status == status)
        .count() as u64
}

pub fn compare(aggregate: &Aggregate, baseline: &str, treatment: &str) -> Comparison {
    let base = aggregate
        .configs
        .iter()
        .find(|item| item.config == baseline);
    let treated = aggregate
        .configs
        .iter()
        .find(|item| item.config == treatment);
    let (delta, ci) = match (base, treated) {
        (Some(base), Some(treated)) => (
            treated.resolved_rate - base.resolved_rate,
            crate::statistics::difference_interval(
                (base.resolved, base.completed),
                (treated.resolved, treated.completed),
            ),
        ),
        _ => (0.0, [-1.0, 1.0]),
    };

    let statistical_conclusion = match (base, treated) {
        (None, _) | (_, None) => {
            StatisticalConclusion::InsufficientPower(InsufficientPowerReason::MissingComparisonArm)
        }
        _ if aggregate.underpowered => {
            StatisticalConclusion::InsufficientPower(InsufficientPowerReason::BelowMinimumSeeds)
        }
        _ if ci[0] > 0.0 => StatisticalConclusion::SignificantIncrease,
        _ if ci[1] < 0.0 => StatisticalConclusion::SignificantDecrease,
        _ => StatisticalConclusion::NotSignificant,
    };

    let fully_priced = |item: &ConfigAggregate| {
        item.cells > 0
            && item.known_cost_cells == item.cells
            && item.average_known_cost_usd.is_some()
    };
    let (cost_delta_usd, cost_delta_reason) = match (base, treated) {
        (Some(base), Some(treated)) if fully_priced(base) && fully_priced(treated) => (
            Some(
                treated.average_known_cost_usd.unwrap_or_default()
                    - base.average_known_cost_usd.unwrap_or_default(),
            ),
            None,
        ),
        _ => (
            None,
            Some("unknown_or_non_numeric_cost_cells_present".to_owned()),
        ),
    };

    Comparison {
        baseline: baseline.to_owned(),
        treatment: treatment.to_owned(),
        resolved_rate_delta: delta,
        delta_ci95: ci,
        statistically_significant: statistical_conclusion.is_significant(),
        statistical_conclusion,
        cost_delta_usd,
        cost_delta_reason,
    }
}

/// Invoke the production selector over every task's completed candidate patches.
pub fn selection_summaries(cells: &[CellResult]) -> Vec<SelectionSummary> {
    let mut tasks: BTreeMap<&str, Vec<&CellResult>> = BTreeMap::new();
    for cell in cells
        .iter()
        .filter(|cell| cell.run_status == RunStatus::Completed && cell.candidate_diff.is_some())
    {
        tasks.entry(&cell.task).or_default().push(cell);
    }

    tasks
        .into_iter()
        .map(|(task, cells)| {
            let candidates = cells
                .iter()
                .map(|cell| Candidate {
                    content: cell.candidate_diff.clone().unwrap_or_default(),
                    verdicts: match cell.oracle_status {
                        crate::types::OracleStatus::Passed => {
                            vec![(OracleStrength::Strong, true)]
                        }
                        crate::types::OracleStatus::TestFailed => {
                            vec![(OracleStrength::Strong, false)]
                        }
                        _ => Vec::new(),
                    },
                    is_correct_oracle: cell.resolved,
                })
                .collect();
            let selection = iteron_verify::select::select(candidates);
            SelectionSummary {
                task: task.to_owned(),
                candidates: selection.deduped.len() as u64,
                chosen: selection.chosen.map(|index| index as u64),
                ceiling: selection.ceiling,
                resolved: selection.resolved,
                resolve_vs_ceiling_gap: selection.ceiling && !selection.resolved,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{OracleStatus, Partition, SamplingControl};
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct GoldenOutcome {
        task: String,
        config: String,
        seed: u64,
        run_status: RunStatus,
        resolved: Option<bool>,
    }

    fn cell(
        task: &str,
        config: &str,
        seed: u64,
        status: RunStatus,
        resolved: Option<bool>,
    ) -> CellResult {
        CellResult {
            task: task.into(),
            config: config.into(),
            seed,
            partition: Partition::HeldOut,
            repo_url: "https://example.invalid/repo.git".into(),
            commit: "0".repeat(40),
            benchmark: None,
            resolved,
            run_status: status,
            failure_phase: None,
            exit_code: Some(0),
            terminal_outcome: Some("done".into()),
            cost_status: CostStatus::Known,
            cost_usd: Some(1.0),
            cost_reason: None,
            turns: Some(1),
            kernel_tax: None,
            oracle_status: OracleStatus::Passed,
            oracle_detail: None,
            sampling: SamplingControl {
                requested_seed: seed,
                enforcement: "fixed".into(),
                reason: None,
            },
            elapsed_ms: 1,
            error: None,
            candidate_diff: Some(format!("patch-{task}-{config}-{seed}")),
        }
    }

    #[test]
    fn empty_and_hand_computed_delta_are_stable() {
        let empty = aggregate(&[], 3);
        assert_eq!(empty.total_cells, 0);
        assert!(empty.underpowered);
        assert_eq!(
            compare(&empty, "verify_OFF", "verify_ON").resolved_rate_delta,
            0.0
        );
        assert_eq!(
            compare(&empty, "verify_OFF", "verify_ON").statistical_conclusion,
            StatisticalConclusion::InsufficientPower(InsufficientPowerReason::MissingComparisonArm)
        );

        let cells = vec![
            cell("a", "verify_OFF", 0, RunStatus::Completed, Some(false)),
            cell("a", "verify_OFF", 1, RunStatus::Completed, Some(false)),
            cell("a", "verify_ON", 0, RunStatus::Completed, Some(true)),
            cell("a", "verify_ON", 1, RunStatus::Completed, Some(false)),
        ];
        let comparison = compare(&aggregate(&cells, 2), "verify_OFF", "verify_ON");
        assert_eq!(comparison.resolved_rate_delta, 0.5);
    }

    #[test]
    fn golden_outcome_sequence_pins_resolved_counts_and_delta_sign_and_value() {
        let outcomes: Vec<GoldenOutcome> =
            serde_json::from_str(include_str!("../tests/golden/d14_05_outcome_sequence.json"))
                .expect("D14-05 golden outcome sequence is valid JSON");
        let cells: Vec<_> = outcomes
            .into_iter()
            .map(|outcome| {
                cell(
                    &outcome.task,
                    &outcome.config,
                    outcome.seed,
                    outcome.run_status,
                    outcome.resolved,
                )
            })
            .collect();

        let aggregate = aggregate(&cells, 2);
        let baseline = aggregate
            .configs
            .iter()
            .find(|config| config.config == "verify_OFF")
            .expect("golden baseline aggregate");
        let treatment = aggregate
            .configs
            .iter()
            .find(|config| config.config == "verify_ON")
            .expect("golden treatment aggregate");
        assert_eq!(
            (
                baseline.cells,
                baseline.completed,
                baseline.resolved,
                baseline.errored,
                baseline.censored,
                baseline.timed_out,
            ),
            (4, 2, 0, 1, 1, 0),
            "the one golden sequence fixes the baseline denominator and resolved count"
        );
        assert_eq!(
            (
                treatment.cells,
                treatment.completed,
                treatment.resolved,
                treatment.errored,
                treatment.censored,
                treatment.timed_out,
            ),
            (4, 2, 1, 0, 1, 1),
            "the same golden sequence fixes the treatment denominator and resolved count"
        );

        let comparison = compare(&aggregate, "verify_OFF", "verify_ON");
        assert_eq!(comparison.resolved_rate_delta.signum(), 1.0);
        assert_eq!(comparison.resolved_rate_delta, 0.5);
    }

    #[test]
    fn failures_do_not_enter_the_resolved_denominator() {
        let cells = vec![
            cell("a", "verify_OFF", 0, RunStatus::Completed, Some(true)),
            cell("a", "verify_OFF", 1, RunStatus::Errored, None),
            cell("a", "verify_OFF", 2, RunStatus::Censored, None),
            cell("a", "verify_OFF", 3, RunStatus::TimedOut, None),
        ];
        let stats = aggregate(&cells, 1);
        let config = &stats.configs[0];
        assert_eq!(config.completed, 1);
        assert_eq!(config.resolved_rate, 1.0);
        assert_eq!(
            (config.errored, config.censored, config.timed_out),
            (1, 1, 1)
        );
    }

    #[test]
    fn unknown_cost_is_excluded_and_disables_cost_delta() {
        let mut cells = vec![
            cell("a", "verify_OFF", 0, RunStatus::Completed, Some(true)),
            cell("a", "verify_OFF", 1, RunStatus::Completed, Some(true)),
            cell("a", "verify_ON", 0, RunStatus::Completed, Some(true)),
        ];
        cells[1].cost_status = CostStatus::Unknown;
        cells[1].cost_usd = None;
        cells[0].cost_usd = Some(2.0);
        let stats = aggregate(&cells, 1);
        let off = stats
            .configs
            .iter()
            .find(|item| item.config == "verify_OFF")
            .unwrap();
        assert_eq!(off.average_known_cost_usd, Some(2.0));
        assert_eq!(off.unknown_cost_cells, 1);
        assert_eq!(
            compare(&stats, "verify_OFF", "verify_ON").cost_delta_usd,
            None
        );
    }

    #[test]
    fn pass_k_exposes_disagreeing_seeds() {
        let cells = vec![
            cell("task", "verify_ON", 0, RunStatus::Completed, Some(true)),
            cell("task", "verify_ON", 1, RunStatus::Completed, Some(false)),
        ];
        let pass = aggregate(&cells, 2).pass_k.pop().unwrap();
        assert_eq!(pass.completed_seeds, 2);
        assert_eq!(pass.resolved_seeds, 1);
        assert!(!pass.all_completed_resolved);
    }

    #[test]
    fn small_effect_with_variance_is_not_significant_and_is_reproducible() {
        let mut cells = Vec::new();
        for seed in 0..10 {
            cells.push(cell(
                "task",
                "verify_OFF",
                seed,
                RunStatus::Completed,
                Some(seed < 5),
            ));
            cells.push(cell(
                "task",
                "verify_ON",
                seed,
                RunStatus::Completed,
                Some(seed < 6),
            ));
        }
        let stats = aggregate(&cells, 3);
        let first = compare(&stats, "verify_OFF", "verify_ON");
        let second = compare(&stats, "verify_OFF", "verify_ON");
        assert_eq!(first, second);
        assert_eq!(
            first.statistical_conclusion,
            StatisticalConclusion::NotSignificant
        );
        assert!(!first.statistically_significant);
        assert!(first.delta_ci95[0] <= 0.0 && first.delta_ci95[1] >= 0.0);
    }

    #[test]
    fn production_selector_reports_resolve_vs_ceiling_gap() {
        let mut correct = cell("task", "verify_ON", 0, RunStatus::Completed, Some(true));
        correct.candidate_diff = Some("correct-but-vetoed".into());
        correct.oracle_status = OracleStatus::TestFailed;
        let mut wrong = cell("task", "verify_ON", 1, RunStatus::Completed, Some(false));
        wrong.candidate_diff = Some("wrong-but-passes".into());
        wrong.oracle_status = OracleStatus::Passed;

        let summary = selection_summaries(&[correct, wrong]).pop().unwrap();
        assert!(summary.ceiling);
        assert!(!summary.resolved);
        assert!(summary.resolve_vs_ceiling_gap);
        assert_eq!(summary.chosen, Some(1));
    }
}
