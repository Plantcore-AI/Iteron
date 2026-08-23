//! Provider-independent, explicitly inexact request token estimation.
//!
//! A provider or model name is not a tokenizer capability. Gateways can rename models, compatible
//! APIs can front different tokenizers, and new routes should work without a release that adds
//! another string match. Admission therefore starts from one conservative neutral estimate. The
//! host reconciles that baseline with provider-accounted input usage in a bounded per-route
//! calibration store after each turn.

use crate::{TokenEstimateProvenance, TokenizerIdentity};

pub const OBSERVED_USAGE_ESTIMATOR_POLICY_ID: &str = "iteron.request-estimator-observed-usage-v3";
pub const DECODED_PIXEL_IMAGE_ESTIMATOR_POLICY_ID: &str =
    "iteron.image-estimator-decoded-pixels-conservative-v1";
pub const ENCODED_BYTES_IMAGE_ESTIMATOR_POLICY_ID: &str =
    "iteron.image-estimator-encoded-bytes-fallback-v1";

const IMAGE_BASE_TOKENS: usize = 512;
const IMAGE_BUCKET_TOKENS: usize = 128;
const IMAGE_PIXEL_BUCKET: u64 = 65_536;
const IMAGE_BYTE_BUCKET: usize = 65_536;
const MAX_IMAGE_ESTIMATE_TOKENS: usize = 32_768;

fn image_base_tokens() -> usize {
    iteron_tunables::param_usize("ctx.token_estimator.image_base_tokens", IMAGE_BASE_TOKENS).max(1)
}

fn image_bucket_tokens() -> usize {
    iteron_tunables::param_usize(
        "ctx.token_estimator.image_bucket_tokens",
        IMAGE_BUCKET_TOKENS,
    )
    .max(1)
}

fn image_pixel_bucket() -> u64 {
    iteron_tunables::param_u64("ctx.token_estimator.image_pixel_bucket", IMAGE_PIXEL_BUCKET).max(1)
}

fn image_byte_bucket() -> usize {
    iteron_tunables::param_usize("ctx.token_estimator.image_byte_bucket", IMAGE_BYTE_BUCKET).max(1)
}

fn max_image_estimate_tokens() -> usize {
    iteron_tunables::param_usize(
        "ctx.token_estimator.max_image_estimate_tokens",
        MAX_IMAGE_ESTIMATE_TOKENS,
    )
    .max(1)
}

/// Why an image reserve has its value. Both current policies are deliberately provider-neutral
/// and inexact; provider-accounted usage remains authoritative after dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageTokenEstimateProvenance {
    DecodedPixelsConservative,
    EncodedBytesConservativeFallback,
}

impl ImageTokenEstimateProvenance {
    pub const fn policy_id(self) -> &'static str {
        match self {
            Self::DecodedPixelsConservative => DECODED_PIXEL_IMAGE_ESTIMATOR_POLICY_ID,
            Self::EncodedBytesConservativeFallback => ENCODED_BYTES_IMAGE_ESTIMATOR_POLICY_ID,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageTokenEstimate {
    pub tokens: usize,
    pub provenance: ImageTokenEstimateProvenance,
}

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
    pub fn estimate_image_with_provenance(self, encoded_base64_bytes: usize) -> ImageTokenEstimate {
        if encoded_base64_bytes == 0 {
            return ImageTokenEstimate {
                tokens: 0,
                provenance: ImageTokenEstimateProvenance::EncodedBytesConservativeFallback,
            };
        }
        let decoded_upper_bound = encoded_base64_bytes.saturating_mul(3).saturating_add(3) / 4;
        let size_buckets = decoded_upper_bound
            .saturating_add(image_byte_bucket().saturating_sub(1))
            / image_byte_bucket();
        ImageTokenEstimate {
            tokens: image_base_tokens()
                .saturating_add(size_buckets.saturating_mul(image_bucket_tokens()))
                .min(max_image_estimate_tokens()),
            provenance: ImageTokenEstimateProvenance::EncodedBytesConservativeFallback,
        }
    }

    pub fn estimate_image(self, encoded_base64_bytes: usize) -> usize {
        self.estimate_image_with_provenance(encoded_base64_bytes)
            .tokens
    }

    /// Prefer decoder-proven aggregate pixels over compressed or base64 size. The safety decoder
    /// already bounded this work before this method is called; the fixed cap prevents animation
    /// metadata from turning token accounting into an unbounded arithmetic surface.
    pub fn estimate_decoded_image(self, total_pixels: u64) -> ImageTokenEstimate {
        if total_pixels == 0 {
            return ImageTokenEstimate {
                tokens: 0,
                provenance: ImageTokenEstimateProvenance::DecodedPixelsConservative,
            };
        }
        let buckets = total_pixels.saturating_add(image_pixel_bucket().saturating_sub(1))
            / image_pixel_bucket();
        ImageTokenEstimate {
            tokens: image_base_tokens()
                .saturating_add(
                    usize::try_from(buckets)
                        .unwrap_or(usize::MAX)
                        .saturating_mul(image_bucket_tokens()),
                )
                .min(max_image_estimate_tokens()),
            provenance: ImageTokenEstimateProvenance::DecodedPixelsConservative,
        }
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

    #[test]
    fn decoded_image_estimates_are_nonzero_monotonic_bounded_and_provenanced() {
        let estimator = TokenEstimatorProfile::default();
        let small = estimator.estimate_decoded_image(1);
        let large = estimator.estimate_decoded_image(8 * 1024 * 1024);
        let bounded = estimator.estimate_decoded_image(u64::MAX);
        let fallback = estimator.estimate_image_with_provenance(4);

        assert!(small.tokens > 0);
        assert!(large.tokens > small.tokens);
        assert_eq!(bounded.tokens, MAX_IMAGE_ESTIMATE_TOKENS);
        assert_eq!(
            small.provenance.policy_id(),
            DECODED_PIXEL_IMAGE_ESTIMATOR_POLICY_ID
        );
        assert!(fallback.tokens > 0);
        assert_eq!(
            fallback.provenance.policy_id(),
            ENCODED_BYTES_IMAGE_ESTIMATOR_POLICY_ID
        );
    }
}
