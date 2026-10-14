//! Billing identity is derived from the actual per-turn Provider effect ordinal. Auxiliary
//! compaction, Main, fallback, retries and hedges must all consume that same restored allocator.
use super::KernelError;

pub(super) fn physical_attempt_for_provider_ordinal(ordinal: usize) -> Result<u32, KernelError> {
    ordinal
        .checked_add(1)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(KernelError::InvalidRouteMetadata {
            field: "provider_route_attempt.physical_attempt",
            reason: "provider effect ordinal exceeds its one-based physical identity range",
        })
}

#[cfg(test)]
mod tests {
    use super::physical_attempt_for_provider_ordinal;
    #[test]
    fn one_based_identity_never_wraps_or_saturates_into_another_attempt() {
        assert_eq!(physical_attempt_for_provider_ordinal(0).unwrap(), 1);
        assert_eq!(
            physical_attempt_for_provider_ordinal(u32::MAX as usize - 1).unwrap(),
            u32::MAX
        );
        assert!(physical_attempt_for_provider_ordinal(u32::MAX as usize).is_err());
        assert!(physical_attempt_for_provider_ordinal(usize::MAX).is_err());
    }
}
