//! Actual adapter-attested output bound projected into the physical request. Policy requested
//! tokens remain separate; an absent bound is never evidence of zero or sufficient reservation.
use super::KernelError;
use iteron_provider::output_ceiling::ProviderOutputBudget;
use iteron_provider::{Provider, TurnRequest};

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
    request.max_tokens = ceiling(
        provider,
        ProviderOutputBudget::from(&request),
        proof_required,
    )?;
    Ok(PhysicalProviderRequest {
        request,
        requested_max_tokens,
    })
}

pub(super) fn ceiling(
    provider: &dyn Provider,
    budget: ProviderOutputBudget<'_>,
    proof_required: bool,
) -> Result<u32, KernelError> {
    match provider.physical_output_token_ceiling(budget)? {
        Some(0) => {
            return Err(KernelError::InvalidRouteMetadata {
                field: "physical_output_token_ceiling",
                reason: "adapter attested a zero physical output bound",
            });
        }
        Some(physical) => Ok(physical),
        None if proof_required => {
            return Err(KernelError::InvalidRouteMetadata {
                field: "physical_output_token_ceiling",
                reason: "hard provider budget requires an adapter-attested physical output bound",
            });
        }
        None => Ok(budget.requested_max_tokens),
    }
}
