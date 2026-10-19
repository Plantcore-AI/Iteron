//! Select a usable finite output limit from proved physical input/output envelopes and the
//! actual signed budget headroom. No local token estimate, JSON byte count or unpriced count IO.
use super::{KernelError, provider_output_request, provider_usage_reservation};
use iteron_protocol::TokenRateCard;
use iteron_provider::{
    Provider, ProviderUsageBoundSemantics, output_ceiling::ProviderOutputBudget,
};

pub(super) struct ProviderOutputFunding {
    pub(super) input: u64,
    pub(super) semantics: ProviderUsageBoundSemantics,
    pub(super) rates: TokenRateCard,
    pub(super) tokens: Option<u64>,
    pub(super) cost_microusd: u64,
}
impl ProviderOutputFunding {
    fn fits(&self, output: u32) -> Result<bool, KernelError> {
        let bounds = provider_usage_reservation::reservation(
            self.semantics,
            self.rates,
            self.input,
            u64::from(output),
        )?;
        Ok(bounds.cost_microusd <= self.cost_microusd
            && self.tokens.is_none_or(|tokens| bounds.tokens <= tokens))
    }
    /// Adapter limit calls are pure and bounded by 34 in this helper (35 including the initial cap read). The native serializer later uses this
    /// selected physical value; actual reservation CAS remains the sole admission authority.
    pub(super) fn ceiling(
        &self,
        provider: &dyn Provider,
        budget: ProviderOutputBudget<'_>,
        initial: u32,
    ) -> Result<u32, KernelError> {
        if self.fits(initial)? {
            return Ok(initial);
        }
        let physical = |requested| {
            provider_output_request::ceiling(
                provider,
                ProviderOutputBudget {
                    requested_max_tokens: requested,
                    ..budget
                },
                true,
            )
        };
        let minimum = physical(1)?;
        if minimum > initial || !self.fits(minimum)? {
            return Err(KernelError::InvalidRouteMetadata {
                field: "provider_budget_envelope",
                reason: "remaining hard budget cannot cover physical input and minimum output upper bounds",
            });
        }
        let (mut low, mut high, mut best) = (1_u32, budget.requested_max_tokens, minimum);
        // Native output normalization is monotone and idempotent. For any custom proof port,
        // every chosen candidate is independently checked and may never widen the original cap.
        for _ in 0..32 {
            if low > high {
                break;
            }
            let middle = low + (high - low) / 2;
            let candidate = physical(middle)?;
            if candidate <= initial && self.fits(candidate)? {
                best = best.max(candidate);
                let Some(next) = middle.checked_add(1) else {
                    break;
                };
                low = next;
            } else {
                if middle == 0 {
                    break;
                }
                high = middle - 1;
            }
        }
        // A repeated cap read may not secretly expand the newly admitted normalized request.
        if physical(best)? != best || best > initial || !self.fits(best)? {
            return Err(KernelError::InvalidRouteMetadata {
                field: "physical_output_token_ceiling",
                reason: "budget-constrained native output limit is not stable",
            });
        }
        Ok(best)
    }
}
#[cfg(test)]
#[path = "provider_output_funding_tests.rs"]
mod tests;
