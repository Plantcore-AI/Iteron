//! Full-jitter exponential backoff. AWS Builders' Library shows full jitter minimizes both
//! contention and completion time versus equal/decorrelated jitter
//! (`docs/intake/tail-latency-and-reliability.md`: 3x -> 1.1x amplification, 57% fewer calls).
//!
//! `sleep = uniform_random(0, min(cap, base * 2^attempt))`.
//!
//! The jitter is nondeterministic on purpose (it must be, to break thundering-herd sync). It
//! is NOT in the replay-decision path: which attempt succeeds is recorded as a nondeterministic
//! input crossing the boundary (ADR-006); the jitter duration itself is timing, not a decision.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const GOLDEN_RATIO_64: u64 = 0x9E37_79B9_7F4A_7C15;
static JITTER_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy)]
pub struct BackoffPolicy {
    pub base_ms: u64,
    pub cap_ms: u64,
    pub max_attempts: u32,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        // Conservative: a handful of retries over ~30s, enough to ride out a rate-limit window
        // without hammering. Real values belong in config (R10).
        BackoffPolicy {
            base_ms: 500,
            cap_ms: 30_000,
            max_attempts: 6,
        }
    }
}

/// The exponential ceiling for a given attempt (0-indexed), before jitter, clamped to the cap.
pub fn ceiling_ms(policy: &BackoffPolicy, attempt: u32) -> u64 {
    policy
        .base_ms
        .saturating_mul(1u64 << attempt.min(20))
        .min(policy.cap_ms)
}

/// Full-jitter delay for an attempt: uniform in [0, ceiling]. `rand01` is a value in [0,1).
/// Passing the randomness in keeps this function pure and unit-testable; the caller supplies a
/// real random source (a nanos-seeded xorshift below, kept out of the decision path).
pub fn full_jitter(policy: &BackoffPolicy, attempt: u32, rand01: f64) -> Duration {
    // Resolved in microseconds, not milliseconds. `from_millis((rand01 * ceil_ms) as u64)`
    // truncates toward zero, which quietly removes the backoff exactly where it matters most:
    // with a 1 ms ceiling *every* draw below 1.0 becomes no delay at all, so the first retry
    // storms the provider that just rate-limited it. At a 4 ms ceiling one draw in four is still
    // zero. Microsecond resolution keeps the same uniform distribution over [0, ceiling] while
    // making a sub-millisecond wait representable -- which is what `RetryAccounting::backoff_us`
    // already documents itself as measuring, and could not previously observe.
    let ceil_us = (ceiling_ms(policy, attempt) as f64) * 1_000.0;
    Duration::from_micros((rand01.clamp(0.0, 1.0) * ceil_us) as u64)
}

/// A tiny, non-crypto RNG for jitter. Seeded from wall-clock nanos, process id, and a lock-free
/// per-process sequence — permitted because jitter is timing, not a recorded decision (ADR-006
/// rule 1 governs decisions).
pub struct Jitter {
    state: u64,
}

impl Jitter {
    pub fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(iteron_tunables::param_integer(
                "sched.backoff.golden_ratio_64",
                GOLDEN_RATIO_64,
            ));
        // Concurrent turns can observe the same clock tick. Mix in a lock-free process-local
        // sequence (and the process id for cross-process diversity) so their per-call jitter
        // streams do not start in sync after removing RetryProvider's shared RNG mutex.
        let sequence = JITTER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        Jitter {
            state: jitter_seed(nanos, u64::from(std::process::id()), sequence),
        }
    }
    /// xorshift64; returns a value in [0,1).
    pub fn next01(&mut self) -> f64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        (x >> 11) as f64 / (1u64 << 53) as f64
    }
}

fn jitter_seed(nanos: u64, process_id: u64, sequence: u64) -> u64 {
    // SplitMix64 finalizer: cheap diffusion for seed material, not a cryptographic RNG.
    let mut z = nanos
        .wrapping_add(process_id.rotate_left(32))
        .wrapping_add(sequence.wrapping_mul(iteron_tunables::param_integer(
            "sched.backoff.golden_ratio_64",
            GOLDEN_RATIO_64,
        )))
        .wrapping_add(iteron_tunables::param_integer(
            "sched.backoff.golden_ratio_64",
            GOLDEN_RATIO_64,
        ));
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    (z ^ (z >> 31)) | 1
}

impl Default for Jitter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ceiling_grows_exponentially_then_clamps() {
        let p = BackoffPolicy {
            base_ms: 500,
            cap_ms: 4000,
            max_attempts: 10,
        };
        assert_eq!(ceiling_ms(&p, 0), 500);
        assert_eq!(ceiling_ms(&p, 1), 1000);
        assert_eq!(ceiling_ms(&p, 2), 2000);
        assert_eq!(ceiling_ms(&p, 3), 4000);
        assert_eq!(ceiling_ms(&p, 4), 4000, "clamped at cap");
        assert_eq!(ceiling_ms(&p, 40), 4000, "no overflow at large attempt");
    }

    #[test]
    fn a_one_millisecond_ceiling_still_produces_a_real_delay() {
        // The defect this pins: resolving in whole milliseconds truncated toward zero, so with a
        // 1 ms ceiling every draw below 1.0 became *no delay at all* -- a retry that does not
        // back off, against the provider that just rate-limited it. `workflow::bindings` even
        // guards with `if !delay.is_zero()`, which is that outcome showing up in production code.
        let p = BackoffPolicy {
            base_ms: 1,
            cap_ms: 2,
            max_attempts: 6,
        };
        let mut zeros = 0;
        for i in 0..1000 {
            let r = f64::from(i) / 1000.0;
            if full_jitter(&p, 0, r).is_zero() {
                zeros += 1;
            }
        }
        assert!(
            zeros <= 1,
            "a 1ms ceiling produced {zeros}/1000 zero delays; whole-millisecond truncation \
             would produce 1000"
        );
    }

    #[test]
    fn a_sub_millisecond_wait_is_representable_rather_than_free() {
        // `RetryAccounting::backoff_us` documents itself as microseconds "because a jittered first
        // backoff is routinely under a millisecond". That was unobservable while the source could
        // only emit whole milliseconds.
        let p = BackoffPolicy {
            base_ms: 4,
            cap_ms: 8,
            max_attempts: 6,
        };
        let d = full_jitter(&p, 0, 0.1); // 10% of a 4ms ceiling = 400us
        assert!(!d.is_zero());
        assert!(d.as_micros() > 0 && d.as_millis() == 0, "{d:?}");
    }

    #[test]
    fn the_endpoints_are_unchanged_by_microsecond_resolution() {
        // Existing callers assert exact ceilings at rand01 = 1.0; those must not move.
        let p = BackoffPolicy {
            base_ms: 25,
            cap_ms: 40,
            max_attempts: 3,
        };
        assert_eq!(full_jitter(&p, 0, 1.0), Duration::from_millis(25));
        assert_eq!(full_jitter(&p, 1, 1.0), Duration::from_millis(40));
        assert!(full_jitter(&p, 0, 0.0).is_zero(), "zero draw is still zero");
    }

    #[test]
    fn full_jitter_stays_within_bounds() {
        let p = BackoffPolicy::default();
        // Extremes of the random draw map to the extremes of the window, never beyond.
        assert_eq!(full_jitter(&p, 2, 0.0).as_millis(), 0);
        let hi = full_jitter(&p, 2, 0.999).as_millis() as u64;
        assert!(hi <= ceiling_ms(&p, 2), "jitter never exceeds the ceiling");
    }

    #[test]
    fn jitter_is_in_unit_interval() {
        let mut j = Jitter {
            state: 0x1234_5678_9ABC_DEF1,
        };
        for _ in 0..1000 {
            let v = j.next01();
            assert!((0.0..1.0).contains(&v));
        }
    }

    #[test]
    fn same_clock_tick_gets_distinct_per_call_jitter_seeds() {
        let states: std::collections::BTreeSet<_> = (0..1_000)
            .map(|sequence| jitter_seed(123_456_789, 42, sequence))
            .collect();
        assert_eq!(
            states.len(),
            1_000,
            "a lock-free sequence diversifies turns created in the same clock tick"
        );
    }
}
