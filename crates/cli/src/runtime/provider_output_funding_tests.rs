use super::ProviderOutputFunding;
use crate::runtime::provider_output_request::{ceiling_funded, normalize_funded};
use iteron_protocol::TokenRateCard;
use iteron_provider::{
    Provider, ProviderError, ProviderUsageBoundSemantics, StreamItem, TurnRequest, TurnResult,
    output_ceiling::ProviderOutputBudget,
};
use std::sync::atomic::{AtomicUsize, Ordering};
struct Native {
    calls: AtomicUsize,
    headroom: u32,
    unknown: bool,
    unstable: bool,
}
impl Native {
    fn plain() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            headroom: 0,
            unknown: false,
            unstable: false,
        }
    }
}
#[async_trait::async_trait]
impl Provider for Native {
    fn physical_output_token_ceiling(
        &self,
        budget: ProviderOutputBudget<'_>,
    ) -> Result<Option<u32>, ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.unknown {
            return Ok(None);
        }
        let required = if budget.thinking_budget > 0 {
            budget
                .thinking_budget
                .checked_add(self.headroom)
                .ok_or_else(|| ProviderError::Configuration("overflow".into()))?
        } else {
            0
        };
        let cap = budget.requested_max_tokens.max(required);
        Ok(Some(if self.unstable {
            cap.checked_add(1)
                .ok_or_else(|| ProviderError::Configuration("overflow".into()))?
        } else {
            cap
        }))
    }
    async fn turn(
        &self,
        _: &TurnRequest,
        _: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        panic!("a physical budget projection cannot perform transport");
    }
}
fn funding(room: u64) -> ProviderOutputFunding {
    ProviderOutputFunding {
        input: 100_000,
        semantics: ProviderUsageBoundSemantics::IndependentClasses,
        rates: TokenRateCard {
            input_microusd_per_million: 100,
            output_microusd_per_million: 1000,
            cache_creation_microusd_per_million: 0,
            cache_read_microusd_per_million: 0,
            thinking_microusd_per_million: 0,
        },
        tokens: Some(4_000_000),
        cost_microusd: room,
    }
}
fn descriptor() -> ProviderOutputBudget<'static> {
    ProviderOutputBudget {
        model: "fixture",
        requested_max_tokens: 8192,
        thinking_budget: 0,
    }
}
fn request() -> TurnRequest {
    TurnRequest {
        model: "fixture".into(),
        system: "system".into(),
        messages: vec![],
        input_images: vec![],
        tools: Vec::<iteron_protocol::ToolSpec>::new().into(),
        max_tokens: 8192,
        thinking_budget: 0,
        cache_system: false,
        reasoning_effort: iteron_protocol::ReasoningEffort::Low,
        controls: iteron_provider::ProviderRequestControls::default(),
    }
}
#[test]
fn a_small_signed_wallet_uses_the_largest_finite_output_that_fits_exact_price_rounding() {
    let provider = Native::plain();
    let funding = funding(15);
    assert_eq!(
        ceiling_funded(&provider, descriptor(), true, Some(&funding)).unwrap(),
        5000
    );
    let physical = normalize_funded(&provider, request(), true, Some(&funding)).unwrap();
    assert_eq!(physical.request.max_tokens, 5000);
    assert_eq!(physical.requested_max_tokens, 8192);
    assert!(funding.fits(5000).unwrap());
    assert!(!funding.fits(5001).unwrap());
    assert!(
        provider.calls.load(Ordering::SeqCst) <= 70,
        "two independent projections stay bounded"
    );
}
#[test]
fn input_and_thinking_floors_are_not_lowered_to_local_estimates_or_weaker_effort() {
    let provider = Native::plain();
    assert!(ceiling_funded(&provider, descriptor(), true, Some(&funding(10))).is_err());
    let provider = Native {
        headroom: 4096,
        ..Native::plain()
    };
    let descriptor = ProviderOutputBudget {
        thinking_budget: 6000,
        ..descriptor()
    };
    assert!(ceiling_funded(&provider, descriptor, true, Some(&funding(15))).is_err());
}
#[test]
fn zero_price_and_no_financial_owner_preserve_the_ordinary_policy_cap() {
    let provider = Native::plain();
    let mut signed_zero = funding(0);
    signed_zero.rates = TokenRateCard {
        input_microusd_per_million: 0,
        output_microusd_per_million: 0,
        cache_creation_microusd_per_million: 0,
        cache_read_microusd_per_million: 0,
        thinking_microusd_per_million: 0,
    };
    assert_eq!(
        ceiling_funded(&provider, descriptor(), true, Some(&signed_zero)).unwrap(),
        8192
    );
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    let provider = Native {
        unknown: true,
        ..Native::plain()
    };
    assert_eq!(
        ceiling_funded(&provider, descriptor(), false, None).unwrap(),
        8192
    );
    assert!(ceiling_funded(&provider, descriptor(), true, Some(&signed_zero)).is_err());
}
#[test]
fn finite_token_headroom_and_repeated_native_output_proof_are_both_required() {
    let mut funding = funding(100);
    funding.tokens = Some(300_100);
    let provider = Native::plain();
    assert_eq!(
        ceiling_funded(&provider, descriptor(), true, Some(&funding)).unwrap(),
        50
    );
    funding.tokens = Some(300_000);
    assert!(ceiling_funded(&provider, descriptor(), true, Some(&funding)).is_err());
    let provider = Native {
        unstable: true,
        ..Native::plain()
    };
    assert!(ceiling_funded(&provider, descriptor(), true, Some(&funding_for_unstable())).is_err());
}

fn funding_for_unstable() -> ProviderOutputFunding {
    funding(15)
}
