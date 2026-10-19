//! Conservative physical usage envelope over adapter-attested normalization. Monetary state
//! stays with existing signed pricing and shared/cohort owners. This does not count request
//! tokens: the admitted model context window remains the hard input bound.
use super::KernelError;
use iteron_agents::ControllerError;
use iteron_protocol::{TokenRateCard, Usage};
use iteron_provider::ProviderUsageBoundSemantics;

pub(super) struct ProviderUsageReservation {
    pub(super) tokens: u64,
    pub(super) cost_microusd: u64,
}

pub(super) fn reservation(
    semantics: ProviderUsageBoundSemantics,
    rates: TokenRateCard,
    input: u64,
    output: u64,
) -> Result<ProviderUsageReservation, KernelError> {
    let input_multiplier = match semantics {
        ProviderUsageBoundSemantics::IndependentClasses => 3,
        ProviderUsageBoundSemantics::PartitionedInput => 1,
    };
    let tokens = input
        .checked_mul(input_multiplier)
        .and_then(|tokens| {
            output
                .checked_mul(2)
                .and_then(|out| tokens.checked_add(out))
        })
        .ok_or(KernelError::AgentControl(ControllerError::Budget))?;
    let cost_microusd = match semantics {
        ProviderUsageBoundSemantics::IndependentClasses => {
            iteron_obs::pricing::projected_amount_microusd(
                rates,
                Usage {
                    input,
                    output,
                    cache_creation: input,
                    cache_read: input,
                    thinking: if rates.thinking_microusd_per_million
                        > rates.output_microusd_per_million
                    {
                        output
                    } else {
                        0
                    },
                },
            )?
        }
        ProviderUsageBoundSemantics::PartitionedInput => {
            let input_cost = partition_cost(
                input,
                [
                    rates.input_microusd_per_million,
                    rates.cache_creation_microusd_per_million,
                    rates.cache_read_microusd_per_million,
                ],
            )?;
            let output_cost = partition_cost(
                output,
                [
                    rates.output_microusd_per_million,
                    rates.thinking_microusd_per_million,
                ],
            )?;
            input_cost
                .checked_add(output_cost)
                .ok_or(KernelError::AgentControl(ControllerError::Budget))?
        }
    };
    Ok(ProviderUsageReservation {
        tokens,
        cost_microusd,
    })
}

fn partition_cost<const N: usize>(tokens: u64, rates: [u64; N]) -> Result<u64, KernelError> {
    let max_rate = rates.iter().copied().max().unwrap_or(0);
    // Reuse the actual pricing owner's configured fixed-point arithmetic. If k nonempty
    // classes are each rounded upwards, sum(ceil(x_i)) <= ceil(sum(x_i)) + k - 1.
    // The integer token count also bounds k. All signed-zero rates remain exactly zero.
    let max_price = iteron_obs::pricing::projected_amount_microusd(
        TokenRateCard {
            input_microusd_per_million: max_rate,
            output_microusd_per_million: 0,
            cache_creation_microusd_per_million: 0,
            cache_read_microusd_per_million: 0,
            thinking_microusd_per_million: 0,
        },
        Usage {
            input: tokens,
            ..Usage::default()
        },
    )?;
    let nonempty = tokens.min(rates.into_iter().filter(|rate| *rate > 0).count() as u64);
    max_price
        .checked_add(nonempty.saturating_sub(1))
        .ok_or(KernelError::AgentControl(ControllerError::Budget))
}

#[cfg(test)]
#[path = "provider_usage_reservation_tests.rs"]
mod tests;
