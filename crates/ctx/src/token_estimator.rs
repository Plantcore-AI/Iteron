//! Provider-aware, explicitly inexact request token estimation.
//!
//! Provider tokenizers are not interchangeable, but most providers do not expose a local,
//! versioned tokenizer contract.  This module therefore does not claim exact tokenization.  It
//! selects a stable calibration by the recorded provider/model route, accounts for non-ASCII
//! scalars separately, and gives every estimate a public identity that can be reconciled with the
//! provider's actual usage after a turn.

use crate::{TokenEstimateProvenance, TokenizerIdentity};

pub const ROUTE_AWARE_ESTIMATOR_POLICY_ID: &str = "iteron.request-estimator-route-aware-v2";

/// Immutable selector policy stored in the tunables checkpoint. The selected concrete profile is
/// still route-specific and is recorded in each ContextLedger tokenizer identity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TokenEstimatorPolicy {
    #[default]
    RouteAwareV2,
}

impl TokenEstimatorPolicy {
    pub const fn id(self) -> &'static str {
        match self {
            Self::RouteAwareV2 => ROUTE_AWARE_ESTIMATOR_POLICY_ID,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TokenEstimatorProfile {
    #[default]
    GenericBytesPerToken35,
    OpenAiBpeApprox,
    AnthropicBpeApprox,
    SentencePieceApprox,
}

impl TokenEstimatorProfile {
    pub fn for_route(provider_id: Option<&str>, model_id: &str) -> Self {
        let provider = provider_id.unwrap_or_default().to_ascii_lowercase();
        let model = model_id.to_ascii_lowercase();
        if provider.contains("anthropic") || model.starts_with("claude") {
            Self::AnthropicBpeApprox
        } else if provider.contains("openai")
            || provider.contains("azure")
            || model.starts_with("gpt-")
            || model.starts_with("o1")
            || model.starts_with("o3")
            || model.starts_with("o4")
        {
            Self::OpenAiBpeApprox
        } else if provider.contains("google")
            || provider.contains("gemini")
            || provider.contains("deepseek")
            || provider.contains("kimi")
            || provider.contains("fireworks")
            || provider.contains("openrouter")
            || model.contains("gemini")
            || model.contains("deepseek")
            || model.contains("kimi")
        {
            Self::SentencePieceApprox
        } else {
            Self::GenericBytesPerToken35
        }
    }

    pub fn estimate(self, text: &str) -> usize {
        if text.is_empty() {
            return 0;
        }
        // Unknown routes use the industry-compatible four-bytes-per-token baseline with a 15%
        // admission reserve. Multilingual text gets a separate scalar floor: UTF-8 byte length is
        // not a useful proxy for CJK/emoji tokenization and previously made the generic profile
        // either four times too pessimistic for ASCII or unsafe when simply divided by four.
        if self == Self::GenericBytesPerToken35 {
            let byte_estimate = text.len().saturating_mul(115).saturating_add(399) / 400;
            let unicode_floor = text
                .chars()
                .filter(|character| !character.is_ascii())
                .count()
                .saturating_mul(2);
            return byte_estimate.max(unicode_floor);
        }
        let ascii_bytes = text.bytes().filter(u8::is_ascii).count();
        let non_ascii = text
            .chars()
            .filter(|character| !character.is_ascii())
            .count();
        let (numerator, denominator): (usize, usize) = match self {
            Self::GenericBytesPerToken35 => unreachable!("generic fallback returned above"),
            // These are conservative route calibrations, not upstream tokenizer claims.
            Self::OpenAiBpeApprox => (5, 18),
            Self::AnthropicBpeApprox => (3, 10),
            Self::SentencePieceApprox => (5, 16),
        };
        let ascii_tokens = ascii_bytes
            .saturating_mul(numerator)
            .saturating_add(denominator.saturating_sub(1))
            / denominator;
        // CJK, emoji, and other non-ASCII scalars frequently consume more than one provider
        // token. Two per scalar is deliberately conservative and avoids the old UTF-8 byte/3.5
        // underestimate for short multilingual prompts.
        ascii_tokens.saturating_add(non_ascii.saturating_mul(2))
    }

    /// Conservative multimodal reserve when the neutral protocol has bytes but no pixel shape.
    /// Provider image tokenizers charge tiles/pixels rather than base64 characters, so applying a
    /// text tokenizer to the wire encoding rejects ordinary photographs by two orders of
    /// magnitude. Keep the estimate bounded and explicitly approximate until an adapter reports
    /// exact image dimensions/cost.
    pub fn estimate_image(self, encoded_base64_bytes: usize) -> usize {
        if encoded_base64_bytes == 0 {
            return 0;
        }
        let decoded_upper_bound = encoded_base64_bytes.saturating_mul(3).saturating_add(3) / 4;
        let size_buckets = decoded_upper_bound.saturating_add(65_535) / 65_536;
        512usize
            .saturating_add(size_buckets.saturating_mul(128))
            .min(4_096)
    }

    pub fn provenance(self) -> TokenEstimateProvenance {
        match self {
            Self::GenericBytesPerToken35 => TokenEstimateProvenance::ConservativeByteUpperBound,
            Self::OpenAiBpeApprox => TokenEstimateProvenance::OpenAiBpeApproximation,
            Self::AnthropicBpeApprox => TokenEstimateProvenance::AnthropicBpeApproximation,
            Self::SentencePieceApprox => TokenEstimateProvenance::SentencePieceApproximation,
        }
    }

    pub fn identity(self) -> TokenizerIdentity {
        let (catalog_id, version) = match self {
            Self::GenericBytesPerToken35 => ("iteron.generic-bpt4-reserve15", 3),
            Self::OpenAiBpeApprox => ("iteron.openai-bpe-approx", 1),
            Self::AnthropicBpeApprox => ("iteron.anthropic-bpe-approx", 1),
            Self::SentencePieceApprox => ("iteron.sentencepiece-approx", 1),
        };
        TokenizerIdentity {
            catalog_id: catalog_id.into(),
            version,
            exact: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_identity_selects_a_provider_profile_and_names_the_fallback() {
        let openai = TokenEstimatorProfile::for_route(Some("openai"), "gpt-5");
        let anthropic = TokenEstimatorProfile::for_route(Some("anthropic"), "claude-opus");
        let sentencepiece = TokenEstimatorProfile::for_route(Some("deepseek"), "deepseek-v4");
        let fallback = TokenEstimatorProfile::for_route(Some("unknown"), "custom-model");

        assert_eq!(openai, TokenEstimatorProfile::OpenAiBpeApprox);
        assert_eq!(anthropic, TokenEstimatorProfile::AnthropicBpeApprox);
        assert_eq!(sentencepiece, TokenEstimatorProfile::SentencePieceApprox);
        assert_eq!(fallback, TokenEstimatorProfile::GenericBytesPerToken35);
        assert_eq!(
            fallback.identity().catalog_id,
            "iteron.generic-bpt4-reserve15"
        );
        assert_eq!(fallback.identity().version, 3);
        assert!(!fallback.identity().exact);
        assert_eq!(fallback.estimate("a".repeat(400).as_str()), 115);
        assert_eq!(fallback.estimate("上下文"), 6);
        assert_eq!(
            fallback.provenance(),
            TokenEstimateProvenance::ConservativeByteUpperBound
        );
        let sample = "x".repeat(360);
        assert_ne!(openai.estimate(&sample), anthropic.estimate(&sample));
    }
}
