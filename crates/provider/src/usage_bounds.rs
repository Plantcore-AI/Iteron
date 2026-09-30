//! Adapter evidence for normalized usage classes. This is a pure transport contract, never a
//! tokenizer estimate or an assertion that a compatibility endpoint follows vendor billing.
//! Native contract sources: https://developers.openai.com/api/docs/guides/prompt-caching
//! and https://platform.claude.com/docs/en/build-with-claude/prompt-caching .

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProviderUsageBoundSemantics {
    /// Each input/cache counter may consume its own full context-window bound.
    #[default]
    IndependentClasses,
    /// Native normalized ordinary input, cache creation and cache read partition the physical
    /// input total. Output includes thinking; the protocol's aggregate token ledger still counts
    /// output and its thinking subcounter independently, so admission reserves twice the cap.
    PartitionedInput,
}

/// Preserve the non-configurable physical baseline; host refreshes can increase it. A known
/// configured route without a shipped physical baseline cannot mint a financial ceiling.
pub(crate) fn physical_input_ceiling(
    configured: &crate::StaticProviderMetadata,
    api_root: &str,
    model: &str,
) -> Option<u64> {
    let baseline = crate::StaticProviderMetadata::shipped_physical_input_ceiling(api_root, model)?;
    let configured = configured
        .route_model_capabilities(api_root, model)
        .and_then(|caps| caps.context_window_tokens)
        .unwrap_or(0);
    Some(baseline.max(configured))
}

#[cfg(test)]
mod tests {
    use super::ProviderUsageBoundSemantics;
    use crate::{Anthropic, ApiRoot, OpenAiCompat, OpenAiResponses, Provider};

    #[test]
    fn only_exact_native_endpoints_attest_the_usage_partition() {
        let native = [
            Box::new(Anthropic::new("fixture".into(), None).unwrap()) as Box<dyn Provider>,
            Box::new(
                OpenAiCompat::with_root(
                    "fixture".into(),
                    ApiRoot::parse("https://api.openai.com/v1").unwrap(),
                )
                .unwrap(),
            ),
            Box::new(OpenAiResponses::new("fixture".into(), None).unwrap()),
        ];
        for provider in native {
            assert_eq!(
                provider.usage_bound_semantics(),
                ProviderUsageBoundSemantics::PartitionedInput
            );
        }
        let custom_root = ApiRoot::parse("https://gateway.invalid/v1").unwrap();
        let custom = [
            Box::new(Anthropic::with_root("fixture".into(), custom_root.clone()).unwrap())
                as Box<dyn Provider>,
            Box::new(OpenAiCompat::with_root("fixture".into(), custom_root.clone()).unwrap()),
            Box::new(OpenAiResponses::with_root("fixture".into(), custom_root).unwrap()),
        ];
        for provider in custom {
            assert_eq!(
                provider.usage_bound_semantics(),
                ProviderUsageBoundSemantics::IndependentClasses
            );
        }
    }
    #[test]
    fn physical_model_ceiling_is_immutable_and_unknown_models_have_no_proof() {
        let native = OpenAiResponses::new("fixture".into(), None).unwrap();
        assert!(
            native
                .physical_input_token_ceiling("gpt-5.6")
                .is_some_and(|cap| cap > 32)
        );
        assert_eq!(
            native.physical_input_token_ceiling("unknown-fixture-model"),
            None
        );
        let custom =
            OpenAiResponses::new("fixture".into(), Some("https://gateway.invalid/v1".into()))
                .unwrap();
        assert_eq!(custom.physical_input_token_ceiling("gpt-5.6"), None);
    }
}

#[cfg(test)]
#[path = "usage_bounds_tests.rs"]
mod baseline_tests;
