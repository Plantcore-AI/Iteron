//! Full-jitter exponential backoff. AWS Builders' Library shows full jitter minimizes both
//! contention and completion time versus equal/decorrelated jitter
//! (`docs/intake/tail-latency-and-reliability.md`: 3x -> 1.1x amplification, 57% fewer calls).
//!
//! `sleep = uniform_random(0, min(cap, base * 2^attempt))`.
//!
//! The jitter is nondeterministic on purpose (it must be, to break thundering-herd sync). It
//! is NOT in the replay-decision path: which attempt succeeds is recorded as a nondeterministic
//! input crossing the boundary (ADR-006); the jitter duration itself is timing, not a decision.

use std::time::Duration;

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
    let ceil = ceiling_ms(policy, attempt) as f64;
    Duration::from_millis((rand01.clamp(0.0, 1.0) * ceil) as u64)
}

/// Classify a bare API status as safe to retry for a potentially billable inference request.
/// Only 429 (rate limit) and 529 (overload) have sufficiently explicit semantics. A 408, 409, or
/// generic 5xx can arrive after the provider accepted work, so those statuses fail closed unless
/// a richer provider error supplies a documented rate-limit/overload code.
pub fn is_retryable(status: u16) -> bool {
    matches!(status, 429 | 529)
}

/// A tiny, non-crypto RNG for jitter. Seeded from wall-clock nanos at construction — permitted
/// here because jitter is timing, not a recorded decision (ADR-006 rule 1 governs decisions).
pub struct Jitter {
    state: u64,
}

impl Jitter {
    pub fn new() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E3779B97F4A7C15)
            | 1;
        Jitter { state: seed }
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
    fn full_jitter_stays_within_bounds() {
        let p = BackoffPolicy::default();
        // Extremes of the random draw map to the extremes of the window, never beyond.
        assert_eq!(full_jitter(&p, 2, 0.0).as_millis(), 0);
        let hi = full_jitter(&p, 2, 0.999).as_millis() as u64;
        assert!(hi <= ceiling_ms(&p, 2), "jitter never exceeds the ceiling");
    }

    #[test]
    fn retryable_classification() {
        assert!(is_retryable(429));
        assert!(is_retryable(529));
        assert!(!is_retryable(408));
        assert!(!is_retryable(409));
        assert!(!is_retryable(503));
        assert!(!is_retryable(400));
        assert!(!is_retryable(401));
        assert!(!is_retryable(200));
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
}
