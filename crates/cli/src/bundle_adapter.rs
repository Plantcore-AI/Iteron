//! Composition-root adapter from the offline active pointer to the protocol-owned boot port.

use core_evolve::{ContractError, PromotionAuthority, PromotionAuthorityError};
use core_protocol::bundle::{BundleResolutionError, PolicyBundleResolver, ResolvedBundle};

/// A one-shot capture of the offline authority's active pointer.
///
/// The authority is queried only by [`capture`](Self::capture). The resolver then serves an
/// immutable protocol view and owns no journal, promotion, or replacement handle.
#[derive(Debug, Clone)]
pub(crate) struct ActivePromotionBundleResolver {
    captured: Result<Option<ResolvedBundle>, BundleResolutionError>,
}

impl ActivePromotionBundleResolver {
    pub(crate) fn capture(
        authority: &mut PromotionAuthority,
    ) -> Result<Self, PromotionAuthorityError> {
        let captured = authority
            .active_bundle()?
            .map(|deployment| deployment.bundle().resolve().map_err(map_projection_error));
        Ok(Self {
            captured: captured.transpose(),
        })
    }
}

impl PolicyBundleResolver for ActivePromotionBundleResolver {
    fn active_bundle(&self) -> Result<Option<ResolvedBundle>, BundleResolutionError> {
        self.captured.clone()
    }
}

fn map_projection_error(error: ContractError) -> BundleResolutionError {
    match error {
        ContractError::InvalidSlot => BundleResolutionError::UnrepresentableSlot,
        _ => BundleResolutionError::Malformed(
            "active promotion bundle cannot be represented by the boot view",
        ),
    }
}
