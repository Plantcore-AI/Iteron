//! Provider-aware, explicitly inexact request token estimation.
//!
//! Provider tokenizers are not interchangeable, but most providers do not expose a local,
//! versioned tokenizer contract.  This module therefore does not claim exact tokenization.  It
//! selects a stable calibration by the recorded provider/model route, accounts for non-ASCII
//! scalars separately, and gives every estimate a public identity that can be reconciled with the
//! provider's actual usage after a turn.

use crate::{TokenEstimateProvenance, TokenizerIdentity};

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
        let ascii_bytes = text.bytes().filter(u8::is_ascii).count();
        let non_ascii = text
            .chars()
            .filter(|character| !character.is_ascii())
            .count();
        let (numerator, denominator) = match self {
            // Preserve the historical 1/3.5 estimator exactly for an unidentified route.
            Self::GenericBytesPerToken35 => (2usize, 7usize),
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
            Self::GenericBytesPerToken35 => TokenEstimateProvenance::HeuristicBytesPerToken35,
            Self::OpenAiBpeApprox => TokenEstimateProvenance::OpenAiBpeApproximation,
            Self::AnthropicBpeApprox => TokenEstimateProvenance::AnthropicBpeApproximation,
            Self::SentencePieceApprox => TokenEstimateProvenance::SentencePieceApproximation,
        }
    }

    pub fn identity(self) -> TokenizerIdentity {
        let catalog_id = match self {
            Self::GenericBytesPerToken35 => "core.byte-heuristic",
            Self::OpenAiBpeApprox => "core.openai-bpe-approx",
            Self::AnthropicBpeApprox => "core.anthropic-bpe-approx",
            Self::SentencePieceApprox => "core.sentencepiece-approx",
        };
        TokenizerIdentity {
            catalog_id: catalog_id.into(),
            version: 1,
            exact: false,
        }
    }
}
