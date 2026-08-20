//! Deterministic, bounded confidence intervals for binary evaluation outcomes.

use sha2::{Digest, Sha256};

/// The two-sided normal quantile for a 95% confidence interval.
const Z_95: f64 = 1.959_963_984_540_054;
pub(crate) const PAIRED_BOOTSTRAP_SAMPLES: usize = 10_000;

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
    let z_squared = iteron_tunables::param_f64("eval.statistics.z_95", Z_95)
        * iteron_tunables::param_f64("eval.statistics.z_95", Z_95);
    let denominator = 1.0 + z_squared / trials;
    let center = (proportion + z_squared / (2.0 * trials)) / denominator;
    let variance = proportion * (1.0 - proportion) / trials + z_squared / (4.0 * trials * trials);
    let spread = iteron_tunables::param_f64("eval.statistics.z_95", Z_95)
        * variance.max(0.0).sqrt()
        / denominator;

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

/// Deterministic paired bootstrap for matched binary outcomes.
///
/// Each tuple is `(baseline, treatment)`. Resampling is over pairs, so instance-level covariance
/// is preserved. The PRNG seed is derived from the sorted indicators rather than process entropy;
/// identical inputs therefore produce bit-identical intervals on every worker count and run.
pub(crate) fn paired_bootstrap_interval(pairs: &[(bool, bool)]) -> [f64; 2] {
    if pairs.is_empty() {
        return [-1.0, 1.0];
    }

    let mut encoded = pairs
        .iter()
        .map(|(baseline, treatment)| (u8::from(*baseline) << 1) | u8::from(*treatment))
        .collect::<Vec<_>>();
    encoded.sort_unstable();
    let mut hasher = Sha256::new();
    hasher.update((encoded.len() as u64).to_le_bytes());
    hasher.update(&encoded);
    let digest = hasher.finalize();
    let mut state = u64::from_le_bytes(
        digest[..8]
            .try_into()
            .expect("a SHA-256 digest always contains eight seed bytes"),
    );
    if state == 0 {
        state = 0x9e37_79b9_7f4a_7c15;
    }

    let pair_deltas = encoded
        .into_iter()
        .map(|bits| i16::from(bits & 1) - i16::from((bits >> 1) & 1))
        .collect::<Vec<_>>();
    let mut samples = Vec::with_capacity(iteron_tunables::param_integer(
        "eval.statistics.paired_bootstrap_samples",
        PAIRED_BOOTSTRAP_SAMPLES,
    ));
    for _ in 0..iteron_tunables::param_integer(
        "eval.statistics.paired_bootstrap_samples",
        PAIRED_BOOTSTRAP_SAMPLES,
    ) {
        let mut sum = 0_i64;
        for _ in 0..pair_deltas.len() {
            state = xorshift64_star(state);
            let index = (state % pair_deltas.len() as u64) as usize;
            sum += i64::from(pair_deltas[index]);
        }
        samples.push(sum as f64 / pair_deltas.len() as f64);
    }
    samples.sort_by(f64::total_cmp);
    let last = samples.len() - 1;
    let lower = last * 25 / 1_000;
    let upper = last * 975 / 1_000;
    [samples[lower], samples[upper]]
}

/// Deterministic paired bootstrap for a mean `treatment - baseline` delta.
///
/// Invalid, negative, or missing measurements are rejected by the caller rather than being
/// silently coerced. Pair order does not influence either the seed or the resulting interval.
pub(crate) fn paired_mean_delta_interval(pairs: &[(f64, f64)]) -> Option<[f64; 2]> {
    if pairs.is_empty()
        || pairs.iter().any(|(baseline, treatment)| {
            !baseline.is_finite() || !treatment.is_finite() || *baseline < 0.0 || *treatment < 0.0
        })
    {
        return None;
    }
    let mut deltas = pairs
        .iter()
        .map(|(baseline, treatment)| treatment - baseline)
        .collect::<Vec<_>>();
    deltas.sort_by(f64::total_cmp);
    let mut hasher = Sha256::new();
    hasher.update((deltas.len() as u64).to_le_bytes());
    for delta in &deltas {
        hasher.update(delta.to_bits().to_le_bytes());
    }
    let digest = hasher.finalize();
    let mut state = u64::from_le_bytes(
        digest[..8]
            .try_into()
            .expect("a SHA-256 digest always contains eight seed bytes"),
    );
    if state == 0 {
        state = 0x9e37_79b9_7f4a_7c15;
    }
    let sample_count = iteron_tunables::param_integer(
        "eval.statistics.paired_bootstrap_samples",
        PAIRED_BOOTSTRAP_SAMPLES,
    );
    let mut samples = Vec::with_capacity(sample_count);
    for _ in 0..sample_count {
        let mut sum = 0.0;
        for _ in 0..deltas.len() {
            state = xorshift64_star(state);
            sum += deltas[(state % deltas.len() as u64) as usize];
        }
        samples.push(sum / deltas.len() as f64);
    }
    samples.sort_by(f64::total_cmp);
    let last = samples.len().checked_sub(1)?;
    Some([samples[last * 25 / 1_000], samples[last * 975 / 1_000]])
}

fn xorshift64_star(mut state: u64) -> u64 {
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    state.wrapping_mul(0x2545_f491_4f6c_dd1d)
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

    #[test]
    fn paired_bootstrap_is_bit_reproducible_and_order_independent() {
        let pairs = [
            (false, true),
            (true, true),
            (true, false),
            (false, true),
            (false, false),
            (true, true),
        ];
        let first = paired_bootstrap_interval(&pairs);
        let second = paired_bootstrap_interval(&pairs);
        let reversed = paired_bootstrap_interval(&pairs.into_iter().rev().collect::<Vec<_>>());
        assert_eq!(first.map(f64::to_bits), second.map(f64::to_bits));
        assert_eq!(first.map(f64::to_bits), reversed.map(f64::to_bits));
        assert!(first[0] <= first[1]);
        assert!(first.iter().all(|bound| (-1.0..=1.0).contains(bound)));
    }

    #[test]
    fn paired_mean_bootstrap_is_reproducible_order_independent_and_rejects_bad_input() {
        let pairs = [(10.0, 6.0), (20.0, 10.0), (8.0, 7.0)];
        let first = paired_mean_delta_interval(&pairs).unwrap();
        let second = paired_mean_delta_interval(&pairs).unwrap();
        let reversed =
            paired_mean_delta_interval(&pairs.into_iter().rev().collect::<Vec<_>>()).unwrap();
        assert_eq!(first.map(f64::to_bits), second.map(f64::to_bits));
        assert_eq!(first.map(f64::to_bits), reversed.map(f64::to_bits));
        assert!(first[1] < 0.0);
        assert!(paired_mean_delta_interval(&[]).is_none());
        assert!(paired_mean_delta_interval(&[(1.0, f64::NAN)]).is_none());
    }
}
