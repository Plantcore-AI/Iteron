//! Provider-independent, explicitly inexact request token estimation.
//!
//! A provider or model name is not a tokenizer capability. Gateways can rename models, compatible
//! APIs can front different tokenizers, and new routes should work without a release that adds
//! another string match. Admission therefore starts from one conservative neutral estimate. The
//! host reconciles that baseline with provider-accounted input usage in a bounded per-route
//! calibration store after each turn.

use crate::{TokenEstimateProvenance, TokenizerIdentity};

pub const OBSERVED_USAGE_ESTIMATOR_POLICY_ID: &str = "iteron.request-estimator-observed-usage-v3";

/// Immutable estimator policy stored in the tunables checkpoint. Route identity partitions
/// observations; it never selects an algorithm.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TokenEstimatorPolicy {
    #[default]
    ObservedUsageV3,
}

impl TokenEstimatorPolicy {
    pub const fn id(self) -> &'static str {
        match self {
            Self::ObservedUsageV3 => OBSERVED_USAGE_ESTIMATOR_POLICY_ID,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TokenEstimatorProfile {
    #[default]
    GenericBytesPerToken35,
}

impl TokenEstimatorProfile {
    pub fn estimate(self, text: &str) -> usize {
        if text.is_empty() {
            return 0;
        }
        // All routes use the industry-compatible four-bytes-per-token baseline with a 15%
        // admission reserve. Multilingual text gets a separate scalar floor: UTF-8 byte length is
        // not a useful proxy for CJK/emoji tokenization and previously made the generic profile
        // either four times too pessimistic for ASCII or unsafe when simply divided by four.
        let byte_estimate = text.len().saturating_mul(115).saturating_add(399) / 400;
        let unicode_floor = text
            .chars()
            .filter(|character| !character.is_ascii())
            .count()
            .saturating_mul(2);
        byte_estimate.max(unicode_floor)
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
        }
    }

    pub fn identity(self) -> TokenizerIdentity {
        let (catalog_id, version) = match self {
            Self::GenericBytesPerToken35 => ("iteron.generic-bpt4-reserve15", 3),
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
    fn neutral_profile_is_named_and_multilingual_safe() {
        let fallback = TokenEstimatorProfile::default();

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
        assert_eq!(
            TokenEstimatorPolicy::ObservedUsageV3.id(),
            OBSERVED_USAGE_ESTIMATOR_POLICY_ID
        );
    }
}
