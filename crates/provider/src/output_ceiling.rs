//! Adapter-owned physical output limits. These are pure wire limits, not an input tokenizer,
//! a predicted completion length or an assertion supplied by model/client JSON.
use crate::{ProviderError, TurnRequest};

#[derive(Debug, Clone, Copy)]
pub struct ProviderOutputBudget<'a> {
    pub model: &'a str,
    pub requested_max_tokens: u32,
    pub thinking_budget: u32,
}
impl<'a> From<&'a TurnRequest> for ProviderOutputBudget<'a> {
    fn from(request: &'a TurnRequest) -> Self {
        Self {
            model: &request.model,
            requested_max_tokens: request.max_tokens,
            thinking_budget: request.thinking_budget,
        }
    }
}
pub(crate) fn requested(budget: ProviderOutputBudget<'_>) -> Result<u32, ProviderError> {
    if budget.requested_max_tokens == 0 {
        return Err(ProviderError::Configuration(
            "physical output ceiling must be positive".into(),
        ));
    }
    Ok(budget.requested_max_tokens)
}
pub(crate) fn extended_thinking(
    budget: ProviderOutputBudget<'_>,
    enabled: bool,
    headroom: u32,
) -> Result<u32, ProviderError> {
    let requested = requested(budget)?;
    if !enabled || budget.thinking_budget == 0 {
        return Ok(requested);
    }
    let required = budget
        .thinking_budget
        .checked_add(headroom)
        .ok_or_else(|| {
            ProviderError::Configuration("physical thinking output ceiling overflowed".into())
        })?;
    Ok(requested.max(required))
}

#[cfg(test)]
mod tests {
    use super::{ProviderOutputBudget, extended_thinking};
    #[test]
    fn finite_wire_limits_refuse_overflow_and_do_not_assume_unknown_capabilities() {
        let mut budget = ProviderOutputBudget {
            model: "fixture",
            requested_max_tokens: 100,
            thinking_budget: 9000,
        };
        assert_eq!(extended_thinking(budget, true, 4096).unwrap(), 13096);
        assert_eq!(extended_thinking(budget, false, 4096).unwrap(), 100);
        budget.thinking_budget = u32::MAX;
        assert!(extended_thinking(budget, true, 4096).is_err());
        assert_eq!(extended_thinking(budget, false, 4096).unwrap(), 100);
        budget.requested_max_tokens = 0;
        assert!(extended_thinking(budget, false, 4096).is_err());
    }
}
