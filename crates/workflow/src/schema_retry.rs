//! Bounded owner policy for schema-forced child retries.
//!
//! Provider transport retry and schema repair are different effects.  This policy belongs to the
//! workflow run and is pinned before QuickJS starts, so a resumed run cannot rediscover timing or
//! attempt defaults from the current binary.

use iteron_sched::BackoffPolicy;

/// Registry/schema ceiling.  It is intentionally independent of the provider retry ceiling.
pub const MAX_SCHEMA_RETRY_ATTEMPTS: u32 = 64;
pub const MAX_SCHEMA_RETRY_DELAY_MS: u64 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaRetryPolicy {
    max_attempts: u32,
    base_ms: u64,
    cap_ms: u64,
}

impl SchemaRetryPolicy {
    pub fn new(max_attempts: u32, base_ms: u64, cap_ms: u64) -> Result<Self, &'static str> {
        if max_attempts > MAX_SCHEMA_RETRY_ATTEMPTS {
            return Err("schema retry attempt ceiling exceeds 64");
        }
        if base_ms > cap_ms || cap_ms > MAX_SCHEMA_RETRY_DELAY_MS {
            return Err("schema retry delay must satisfy base <= cap <= 60000ms");
        }
        Ok(Self {
            max_attempts,
            base_ms,
            cap_ms,
        })
    }

    pub const fn max_attempts(self) -> u32 {
        self.max_attempts
    }

    pub const fn base_ms(self) -> u64 {
        self.base_ms
    }

    pub const fn cap_ms(self) -> u64 {
        self.cap_ms
    }

    pub(crate) const fn backoff(self) -> BackoffPolicy {
        BackoffPolicy {
            base_ms: self.base_ms,
            cap_ms: self.cap_ms,
            max_attempts: self.max_attempts,
        }
    }
}

impl Default for SchemaRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: crate::schema::RETRY_MAX,
            base_ms: 2,
            cap_ms: 20,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_is_bounded_and_keeps_schema_retry_separate_from_provider_retry() {
        assert!(SchemaRetryPolicy::new(64, 60_000, 60_000).is_ok());
        assert!(SchemaRetryPolicy::new(65, 0, 0).is_err());
        assert!(SchemaRetryPolicy::new(1, 2, 1).is_err());
        assert!(SchemaRetryPolicy::new(1, 0, 60_001).is_err());
        assert_eq!(SchemaRetryPolicy::default().max_attempts(), 5);
    }
}
