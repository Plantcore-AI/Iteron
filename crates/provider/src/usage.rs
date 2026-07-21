use core_protocol::Usage;

/// Provider-reported billing evidence for one otherwise successful model turn.
///
/// `Incomplete` deliberately carries no synthetic [`Usage`]. In particular, an omitted report is
/// not equivalent to a complete report whose counters happen to all be zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageReport {
    Complete(Usage),
    Incomplete { reason: UsageIncompleteReason },
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

    pub const fn provider_omitted() -> Self {
        Self::Incomplete {
            reason: UsageIncompleteReason::ProviderOmitted,
        }
    }

    pub const fn complete_usage(self) -> Option<Usage> {
        match self {
            Self::Complete(usage) => Some(usage),
            Self::Incomplete { .. } => None,
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
}
