use iteron_protocol::Usage;

/// Provider-reported billing evidence for one otherwise successful model turn.
///
/// `Incomplete` deliberately carries no synthetic [`Usage`]. In particular, an omitted report is
/// not equivalent to a complete report whose counters happen to all be zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageReport {
    Complete(Usage),
    /// Every counter is authoritative except cache creation, which this route never reports.
    ///
    /// `Usage::cache_creation` has no `Option`, so an adapter with no vendor field to read has
    /// always left it at its default `0` — and pricing then multiplied that constant zero by a
    /// cache-write rate and called the result free (I-52). Silence about cache writes is not
    /// evidence that none happened: across 216 recorded turns on 7 OpenAI-compatible routes the
    /// counter was always zero while cache reads were 51.8% of all prompt tokens, which is only
    /// possible if something wrote those entries. This variant keeps the usage that *was*
    /// reported while naming the gap, so a rate card that charges for cache creation declines to
    /// price the turn instead of pricing it at zero.
    CacheCreationUnreported(Usage),
    Incomplete {
        reason: UsageIncompleteReason,
    },
}

/// Why an adapter could not produce complete billing evidence for a successful turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageIncompleteReason {
    /// The provider completed the response but omitted its usage report.
    ProviderOmitted,
}

impl UsageReport {
    pub const fn complete(usage: Usage) -> Self {
        Self::Complete(usage)
    }

    /// Authoritative for every class except cache creation, which this route does not report.
    pub const fn cache_creation_unreported(usage: Usage) -> Self {
        Self::CacheCreationUnreported(usage)
    }

    pub const fn provider_omitted() -> Self {
        Self::Incomplete {
            reason: UsageIncompleteReason::ProviderOmitted,
        }
    }

    pub const fn complete_usage(self) -> Option<Usage> {
        match self {
            Self::Complete(usage) | Self::CacheCreationUnreported(usage) => Some(usage),
            Self::Incomplete { .. } => None,
        }
    }

    /// Whether `Usage::cache_creation` on this report is a measurement rather than a default.
    ///
    /// A pricing authority must consult this before charging a cache-creation rate: `false` means
    /// the count is unknown, so the turn is unpriceable, not free.
    pub const fn cache_creation_reported(self) -> bool {
        match self {
            Self::Complete(_) => true,
            Self::CacheCreationUnreported(_) | Self::Incomplete { .. } => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_zero_and_omitted_usage_are_distinct() {
        assert_eq!(
            UsageReport::complete(Usage::default()).complete_usage(),
            Some(Usage::default())
        );
        assert_eq!(UsageReport::provider_omitted().complete_usage(), None);
    }

    /// I-52: a route that never reports cache creation still has authoritative input/output, so
    /// its usage must survive — but it must not be readable as "zero cache writes happened".
    #[test]
    fn unreported_cache_creation_keeps_its_usage_but_is_not_a_measured_zero() {
        let usage = Usage {
            input: 10,
            output: 5,
            cache_read: 100,
            ..Usage::default()
        };
        let report = UsageReport::cache_creation_unreported(usage);
        assert_eq!(report.complete_usage(), Some(usage));
        assert!(!report.cache_creation_reported());
        assert!(UsageReport::complete(usage).cache_creation_reported());
        assert!(!UsageReport::provider_omitted().cache_creation_reported());
    }
}
