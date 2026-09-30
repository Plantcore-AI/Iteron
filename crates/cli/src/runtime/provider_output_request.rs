//! Actual adapter-attested output bound projected into the physical request. Policy requested
//! tokens remain separate; an absent bound is never evidence of zero or sufficient reservation.
use super::KernelError;
use iteron_provider::{Provider, ProviderOutputBudget, TurnRequest};

pub(super) struct PhysicalProviderRequest {
    pub(super) request: TurnRequest,
    pub(super) requested_max_tokens: u32,
}

pub(super) fn normalize(
    provider: &dyn Provider,
    mut request: TurnRequest,
    proof_required: bool,
) -> Result<PhysicalProviderRequest, KernelError> {
    let requested_max_tokens = request.max_tokens;
    match provider.physical_output_token_ceiling(ProviderOutputBudget::from(&request))? {
        Some(0) => {
            return Err(KernelError::InvalidRouteMetadata {
                field: "physical_output_token_ceiling",
                reason: "adapter attested a zero physical output bound",
            });
        }
        Some(physical) => request.max_tokens = physical,
        None if proof_required => {
            return Err(KernelError::InvalidRouteMetadata {
                field: "physical_output_token_ceiling",
                reason: "hard provider budget requires an adapter-attested physical output bound",
            });
        }
        None => {}
    }
    Ok(PhysicalProviderRequest {
        request,
        requested_max_tokens,
    })
}
