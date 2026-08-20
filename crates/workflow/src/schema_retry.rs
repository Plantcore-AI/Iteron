//! Bounded owner policy for schema-forced child retries.
//!
//! Provider transport retry and schema repair are different effects.  This policy belongs to the
//! workflow run and is pinned before QuickJS starts, so a resumed run cannot rediscover timing or
//! attempt defaults from the current binary.

use iteron_sched::BackoffPolicy;

/// Registry/schema ceiling.  It is intentionally independent of the provider retry ceiling.
pub const MAX_SCHEMA_RETRY_ATTEMPTS: u32 = 64;
pub const MAX_SCHEMA_RETRY_DELAY_MS: u64 = 60_000;
const DEFAULT_SCHEMA_RETRY_BASE_MS: u64 = 2;
const DEFAULT_SCHEMA_RETRY_CAP_MS: u64 = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaRetryPolicy {
    max_attempts: u32,
    base_ms: u64,
    cap_ms: u64,
}

impl SchemaRetryPolicy {
    pub fn new(max_attempts: u32, base_ms: u64, cap_ms: u64) -> Result<Self, &'static str> {
        if u64::from(max_attempts)
            > iteron_tunables::param_u64(
                "workflow.schema_retry.max_schema_retry_attempts",
                u64::from(iteron_tunables::param_integer(
                    "workflow.schema_retry.max_schema_retry_attempts",
                    MAX_SCHEMA_RETRY_ATTEMPTS,
                )),
            )
        {
            return Err("schema retry attempt ceiling exceeds 64");
        }
        if base_ms > cap_ms
            || cap_ms
                > iteron_tunables::param_u64(
                    "workflow.schema_retry.max_schema_retry_delay_ms",
                    iteron_tunables::param_integer(
                        "workflow.schema_retry.max_schema_retry_delay_ms",
                        MAX_SCHEMA_RETRY_DELAY_MS,
                    ),
                )
        {
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
        let max_attempts = u32::try_from(iteron_tunables::param_u64(
            "workflow.schema.retry_max",
            u64::from(crate::schema::RETRY_MAX),
        ))
        .unwrap_or(crate::schema::RETRY_MAX);
        let cap_ms = iteron_tunables::param_u64(
            "workflow.schema_retry.default_schema_retry_cap_ms",
            iteron_tunables::param_integer(
                "workflow.schema_retry.default_schema_retry_cap_ms",
                DEFAULT_SCHEMA_RETRY_CAP_MS,
            ),
        )
        .min(iteron_tunables::param_u64(
            "workflow.schema_retry.max_schema_retry_delay_ms",
            iteron_tunables::param_integer(
                "workflow.schema_retry.max_schema_retry_delay_ms",
                MAX_SCHEMA_RETRY_DELAY_MS,
            ),
        ));
        let base_ms = iteron_tunables::param_u64(
            "workflow.schema_retry.default_schema_retry_base_ms",
            iteron_tunables::param_integer(
                "workflow.schema_retry.default_schema_retry_base_ms",
                DEFAULT_SCHEMA_RETRY_BASE_MS,
            ),
        )
        .min(cap_ms);
        // The clamp must use the same ceiling `new` checks against. It used the compiled
        // constant while `new` reads the operator-resolved parameter, so tightening that
        // parameter left the built-in default above the ceiling and the `.expect()` below aborted
        // the process (exit 101) for a profile the catalog documents as legal.
        let max_attempts = max_attempts.min(
            u32::try_from(iteron_tunables::param_u64(
                "workflow.schema_retry.max_schema_retry_attempts",
                u64::from(iteron_tunables::param_integer::<u32>(
                    "workflow.schema_retry.max_schema_retry_attempts",
                    crate::schema_retry::MAX_SCHEMA_RETRY_ATTEMPTS,
                )),
            ))
            .unwrap_or(u32::MAX),
        );
        Self::new(max_attempts, base_ms, cap_ms)
            .expect("the resolved schema retry policy is clamped into its own configured ceilings")
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
