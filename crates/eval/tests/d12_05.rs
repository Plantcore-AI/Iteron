//! D12-05 oracle: the `core-eval` statistical *measurement machinery* is pinned by tests.
//!
//! The gap under closure is "Zero tests on the eval measurement machinery". The trustworthy part of
//! a fixed-model evaluation is not that it runs a subprocess — it is the arithmetic that turns raw
//! cell outcomes into a defensible claim: a resolved-rate over the correct denominator, a real
//! confidence interval around it, a difference-of-proportions interval between two configs, and a
//! significance / statistical-power verdict derived *from that interval* rather than asserted. That
//! layer — [`core_eval::aggregate`] + [`core_eval::compare`], backed by the Wilson score interval
//! and Newcombe's difference interval — had no test exercising it through the public surface the
//! binary (`main.rs`) consumes when it prints its summary and finalizes the run.
//!
//! These tests pin the measurement invariants that a placeholder or a naive re-implementation would
//! violate, so they are non-vacuous:
//!   * the resolved-rate interval is a *real* Wilson interval — strictly inside `(0, 1)` for an
//!     interior proportion (a `[0, 1]` placeholder or a Wald interval that clamps to `1.0` fails
//!     this), and it *narrows* as the completed-sample count grows (a constant interval fails this);
//!   * a totally-separated pair of arms is called a `SignificantIncrease` / `SignificantDecrease`
//!     with the difference interval on the correct side of zero, while a small noisy difference is
//!     `NotSignificant` with an interval that straddles zero;
//!   * statistical power gates the verdict: a pair whose raw difference interval *excludes* zero is
//!     still withheld as `InsufficientPower(BelowMinimumSeeds)` when the completed seeds fall below
//!     the minimum, and a missing comparison arm is `InsufficientPower(MissingComparisonArm)` with a
//!     neutral zero delta rather than a fabricated verdict;
//!   * the whole comparison is bit-for-bit reproducible for identical inputs.
//!
//! The whole target is a new file, absent on the INTEG base, so acceptance is RED there and GREEN
//! once this oracle runs against the real measurement machinery. Every assertion below encodes a
//! concrete numeric / categorical claim about that machinery, so none is a trivially-true check.

use core_eval::{
    CellResult, CostStatus, InsufficientPowerReason, OracleStatus, Partition, RunStatus,
    SamplingControl, StatisticalConclusion, aggregate, compare,
};

/// A single completed cell with a verified $1 cost. Aggregation reads only `run_status` + `resolved`
/// for the rate machinery; the cost fields keep the cell a well-formed, fully-priced completion.
fn completed(task: &str, config: &str, seed: u64, resolved: bool) -> CellResult {
    CellResult {
        task: task.into(),
        config: config.into(),
        seed,
        partition: Partition::HeldOut,
        repo_url: "https://example.invalid/repo.git".into(),
        commit: "0".repeat(40),
        benchmark: None,
        resolved: Some(resolved),
        run_status: RunStatus::Completed,
        failure_phase: None,
        exit_code: Some(0),
        terminal_outcome: Some("done".into()),
        cost_status: CostStatus::Known,
        cost_usd: Some(1.0),
        cost_reason: None,
        turns: Some(1),
        oracle_status: OracleStatus::Passed,
        oracle_detail: None,
        sampling: SamplingControl {
            requested_seed: seed,
            enforcement: "fixed".into(),
            reason: None,
        },
        elapsed_ms: 1,
        error: None,
        candidate_diff: None,
    }
}

/// Append one config's arm: one completed cell per `resolved_flags` entry, seeds `0..len`.
fn push_arm(cells: &mut Vec<CellResult>, config: &str, resolved_flags: &[bool]) {
    for (seed, &resolved) in resolved_flags.iter().enumerate() {
        cells.push(completed("t", config, seed as u64, resolved));
    }
}

/// A single-config aggregate over `resolved_flags` completed cells (used for CI-shape assertions).
fn single_config(config: &str, resolved_flags: &[bool]) -> core_eval::Aggregate {
    let mut cells = Vec::new();
    push_arm(&mut cells, config, resolved_flags);
    aggregate(&cells, 1)
}

#[test]
fn resolved_rate_and_wilson_ci_bound_an_interior_proportion() {
    // 8 resolved of 10 completed -> rate 0.8, and a *real* Wilson interval sits strictly inside
    // (0, 1) and strictly brackets the point estimate. A `[0, 1]` placeholder would violate the
    // strict-interior bounds; a Wald interval for 0.8 would clamp its upper bound to 1.0.
    let flags = [true, true, true, true, true, true, true, true, false, false];
    let stats = single_config("verify_ON", &flags);
    let config = &stats.configs[0];

    assert_eq!(config.completed, 10);
    assert_eq!(config.resolved, 8);
    assert!(
        (config.resolved_rate - 0.8).abs() < 1e-12,
        "rate is resolved/completed over the completed denominator"
    );

    let [lo, hi] = config.resolved_rate_ci95;
    assert!(lo.is_finite() && hi.is_finite());
    assert!(lo <= hi, "the interval must be ordered");
    assert!(lo > 0.0, "a real Wilson lower bound for 0.8 is strictly above 0");
    assert!(
        hi < 1.0,
        "a real Wilson upper bound for 0.8 is strictly below 1 (a Wald interval would clamp to 1.0)"
    );
    assert!(
        lo < config.resolved_rate && config.resolved_rate < hi,
        "the point estimate lies strictly inside its own confidence interval"
    );
}

#[test]
fn more_completed_samples_tighten_the_wilson_interval() {
    // Same proportion (0.8) at n=10 vs n=40. A trustworthy interval *responds* to sample size: the
    // width must strictly shrink. A constant placeholder interval would keep the same width.
    let small = single_config("c", &[vec![true; 8], vec![false; 2]].concat());
    let large = single_config("c", &[vec![true; 32], vec![false; 8]].concat());

    let width = |a: &core_eval::Aggregate| {
        let [lo, hi] = a.configs[0].resolved_rate_ci95;
        hi - lo
    };
    let (w_small, w_large) = (width(&small), width(&large));

    // Both arms describe the identical proportion...
    assert!((small.configs[0].resolved_rate - large.configs[0].resolved_rate).abs() < 1e-12);
    // ...yet the larger sample yields a strictly narrower interval.
    assert!(
        w_large < w_small,
        "quadrupling the completed samples must tighten the CI (got n=40 width {w_large} \
         vs n=10 width {w_small})"
    );
}

#[test]
fn a_total_positive_separation_is_a_significant_increase() {
    // Baseline never resolves (0/8), treatment always resolves (8/8), enough seeds to be powered.
    let mut cells = Vec::new();
    push_arm(&mut cells, "verify_OFF", &[false; 8]);
    push_arm(&mut cells, "verify_ON", &[true; 8]);
    let stats = aggregate(&cells, 4);
    assert!(!stats.underpowered, "8 seeds per arm clears minimum_seeds=4");

    let cmp = compare(&stats, "verify_OFF", "verify_ON");
    assert_eq!(cmp.resolved_rate_delta, 1.0, "0/8 -> 8/8 is a +1.0 delta");
    assert_eq!(
        cmp.statistical_conclusion,
        StatisticalConclusion::SignificantIncrease
    );
    assert!(cmp.statistically_significant);
    assert!(
        cmp.delta_ci95[0] > 0.0,
        "a significant increase has a difference interval entirely above zero"
    );
}

#[test]
fn a_total_negative_separation_is_a_significant_decrease() {
    // The mirror image: baseline always resolves, treatment never does.
    let mut cells = Vec::new();
    push_arm(&mut cells, "verify_OFF", &[true; 8]);
    push_arm(&mut cells, "verify_ON", &[false; 8]);
    let stats = aggregate(&cells, 4);

    let cmp = compare(&stats, "verify_OFF", "verify_ON");
    assert_eq!(cmp.resolved_rate_delta, -1.0, "8/8 -> 0/8 is a -1.0 delta");
    assert_eq!(
        cmp.statistical_conclusion,
        StatisticalConclusion::SignificantDecrease
    );
    assert!(cmp.statistically_significant);
    assert!(
        cmp.delta_ci95[1] < 0.0,
        "a significant decrease has a difference interval entirely below zero"
    );
}

#[test]
fn a_small_noisy_difference_is_not_significant() {
    // 5/10 vs 6/10: a real but small effect at modest n. The difference interval straddles zero, so
    // the honest verdict is NotSignificant even though the point delta is positive.
    let mut cells = Vec::new();
    push_arm(
        &mut cells,
        "verify_OFF",
        &[vec![true; 5], vec![false; 5]].concat(),
    );
    push_arm(
        &mut cells,
        "verify_ON",
        &[vec![true; 6], vec![false; 4]].concat(),
    );
    let stats = aggregate(&cells, 4);
    assert!(!stats.underpowered, "10 seeds per arm clears minimum_seeds=4");

    let cmp = compare(&stats, "verify_OFF", "verify_ON");
    assert!((cmp.resolved_rate_delta - 0.1).abs() < 1e-12, "point delta is +0.1");
    assert_eq!(
        cmp.statistical_conclusion,
        StatisticalConclusion::NotSignificant
    );
    assert!(!cmp.statistically_significant);
    assert!(
        cmp.delta_ci95[0] <= 0.0 && cmp.delta_ci95[1] >= 0.0,
        "a not-significant difference interval must contain zero: got {:?}",
        cmp.delta_ci95
    );
}

#[test]
fn total_separation_below_minimum_seeds_is_withheld_as_insufficient_power() {
    // The integrity test: 0/2 vs 2/2 is a *raw* difference interval that EXCLUDES zero (lower bound
    // ~ +0.07), so a machine that ignored power would call it a SignificantIncrease. With only two
    // completed seeds per arm and minimum_seeds=3 the run is underpowered, and the verdict must be
    // withheld — the point delta is still reported, but no significance is claimed.
    let mut cells = Vec::new();
    push_arm(&mut cells, "verify_OFF", &[false; 2]);
    push_arm(&mut cells, "verify_ON", &[true; 2]);
    let stats = aggregate(&cells, 3);
    assert!(stats.underpowered, "2 completed seeds < minimum_seeds=3");

    let cmp = compare(&stats, "verify_OFF", "verify_ON");
    assert_eq!(cmp.resolved_rate_delta, 1.0, "the point delta is still computed");
    assert_eq!(
        cmp.statistical_conclusion,
        StatisticalConclusion::InsufficientPower(InsufficientPowerReason::BelowMinimumSeeds),
        "an underpowered run must not be called significant even under total separation"
    );
    assert!(
        !cmp.statistically_significant,
        "insufficient power is never reported as a significant result"
    );
}

#[test]
fn a_missing_comparison_arm_yields_insufficient_power_not_a_zero_delta_verdict() {
    // Only the baseline config exists; the requested treatment arm is absent. The comparison must
    // report insufficient power (missing arm) with a neutral zero delta and the maximally
    // uninformative interval — never a fabricated NotSignificant / significant verdict.
    let mut cells = Vec::new();
    push_arm(&mut cells, "verify_OFF", &[true, false, true, false]);
    let stats = aggregate(&cells, 1);

    let cmp = compare(&stats, "verify_OFF", "verify_ON");
    assert_eq!(cmp.resolved_rate_delta, 0.0, "no treatment arm -> neutral zero delta");
    assert_eq!(cmp.delta_ci95, [-1.0, 1.0], "the interval is maximally uninformative");
    assert_eq!(
        cmp.statistical_conclusion,
        StatisticalConclusion::InsufficientPower(InsufficientPowerReason::MissingComparisonArm)
    );
    assert!(!cmp.statistically_significant);
}

#[test]
fn the_statistical_comparison_is_bit_for_bit_reproducible() {
    // Determinism is a load-bearing property of the measurement machine: identical inputs must yield
    // byte-identical delta and interval bounds, not merely values that compare approximately equal.
    let mut cells = Vec::new();
    push_arm(
        &mut cells,
        "verify_OFF",
        &[vec![true; 7], vec![false; 5]].concat(),
    );
    push_arm(
        &mut cells,
        "verify_ON",
        &[vec![true; 10], vec![false; 2]].concat(),
    );
    let stats = aggregate(&cells, 4);

    let first = compare(&stats, "verify_OFF", "verify_ON");
    let second = compare(&stats, "verify_OFF", "verify_ON");
    assert_eq!(
        first.resolved_rate_delta.to_bits(),
        second.resolved_rate_delta.to_bits(),
        "the delta must be bit-for-bit reproducible"
    );
    assert_eq!(
        first.delta_ci95.map(f64::to_bits),
        second.delta_ci95.map(f64::to_bits),
        "the difference interval must be bit-for-bit reproducible"
    );
    assert_eq!(first, second, "the whole comparison is deterministic");
}
