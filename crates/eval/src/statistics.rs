//! Deterministic, bounded confidence intervals for binary evaluation outcomes.

/// The two-sided normal quantile for a 95% confidence interval.
const Z_95: f64 = 1.959_963_984_540_054;

/// Wilson score interval for a binomial proportion.
///
/// The result is always finite, ordered, and bounded to `[0, 1]`. A missing
/// denominator deliberately reports the maximally uninformative interval.
pub(crate) fn wilson_interval(successes: u64, trials: u64) -> [f64; 2] {
    if trials == 0 {
        return [0.0, 1.0];
    }

    // Callers derive both values from the same completed-cell collection. Clamp
    // defensively so this leaf remains numerically safe if it is reused directly.
    let successes = successes.min(trials) as f64;
    let trials = trials as f64;
    let proportion = successes / trials;
    let z_squared = Z_95 * Z_95;
    let denominator = 1.0 + z_squared / trials;
    let center = (proportion + z_squared / (2.0 * trials)) / denominator;
    let variance = proportion * (1.0 - proportion) / trials + z_squared / (4.0 * trials * trials);
    let spread = Z_95 * variance.max(0.0).sqrt() / denominator;

    [
        (center - spread).clamp(0.0, 1.0),
        (center + spread).clamp(0.0, 1.0),
    ]
}

/// Newcombe's score interval for the difference of two independent proportions.
///
/// `baseline` and `treatment` are `(successes, trials)`. The result describes
/// `treatment - baseline`, is deterministic, and is bounded to `[-1, 1]`.
pub(crate) fn difference_interval(baseline: (u64, u64), treatment: (u64, u64)) -> [f64; 2] {
    if baseline.1 == 0 || treatment.1 == 0 {
        return [-1.0, 1.0];
    }

    let baseline_rate = rate(baseline.0, baseline.1);
    let treatment_rate = rate(treatment.0, treatment.1);
    let baseline_interval = wilson_interval(baseline.0, baseline.1);
    let treatment_interval = wilson_interval(treatment.0, treatment.1);
    let delta = treatment_rate - baseline_rate;

    let lower_treatment = treatment_rate - treatment_interval[0];
    let upper_baseline = baseline_interval[1] - baseline_rate;
    let upper_treatment = treatment_interval[1] - treatment_rate;
    let lower_baseline = baseline_rate - baseline_interval[0];
    let lower_spread = (lower_treatment * lower_treatment + upper_baseline * upper_baseline).sqrt();
    let upper_spread = (upper_treatment * upper_treatment + lower_baseline * lower_baseline).sqrt();

    [
        (delta - lower_spread).clamp(-1.0, 1.0),
        (delta + upper_spread).clamp(-1.0, 1.0),
    ]
}

pub(crate) fn rate(successes: u64, trials: u64) -> f64 {
    if trials == 0 {
        0.0
    } else {
        successes.min(trials) as f64 / trials as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intervals_are_finite_ordered_and_bounded_at_extremes() {
        for (successes, trials) in [(0, 0), (0, 1), (1, 1), (1, 3), (2, 3), (u64::MAX, u64::MAX)] {
            let interval = wilson_interval(successes, trials);
            assert!(interval.iter().all(|bound| bound.is_finite()));
            assert!((0.0..=1.0).contains(&interval[0]));
            assert!((0.0..=1.0).contains(&interval[1]));
            assert!(interval[0] <= interval[1]);
        }

        for interval in [
            difference_interval((0, 0), (0, 0)),
            difference_interval((0, 1), (1, 1)),
            difference_interval((u64::MAX, u64::MAX), (0, u64::MAX)),
        ] {
            assert!(interval.iter().all(|bound| bound.is_finite()));
            assert!((-1.0..=1.0).contains(&interval[0]));
            assert!((-1.0..=1.0).contains(&interval[1]));
            assert!(interval[0] <= interval[1]);
        }
    }

    #[test]
    fn score_intervals_are_bit_reproducible_for_identical_counts() {
        let first = difference_interval((7, 18), (10, 18));
        let second = difference_interval((7, 18), (10, 18));
        assert_eq!(first.map(f64::to_bits), second.map(f64::to_bits));
    }
}
