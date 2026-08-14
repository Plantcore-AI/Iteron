//! Runtime-effective, replayable memory retrieval controls.

use serde::{Deserialize, Serialize};

pub const SCORE_SCALE: u32 = 1_000_000;

/// Okapi BM25 k1 in thousandths. 1.2 is the standard term-saturation setting.
const DEFAULT_BM25_K1_MILLI: u32 = 1_200;
/// Okapi BM25 b in parts per million. 0.75 is the standard length-normalization setting.
const DEFAULT_BM25_B_PPM: u32 = 750_000;
/// Fact bodies one decision may select before the recall budget is the binding constraint.
const DEFAULT_RECALL_LIMIT: u32 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryRetrievalPolicy {
    /// Okapi BM25 k1 in thousandths (default 1.2 => 1200).
    #[serde(default = "default_bm25_k1_milli")]
    pub bm25_k1_milli: u32,
    /// Okapi BM25 b ratio.
    #[serde(default = "default_bm25_b_ppm")]
    pub bm25_b_ppm: u32,
    /// Maximum fact bodies one decision may select.
    #[serde(default = "default_recall_limit")]
    pub recall_limit: u32,
    pub lexical_weight_ppm: u32,
    pub structural_weight_ppm: u32,
    pub vector_weight_ppm: u32,
    pub reranker_weight_ppm: u32,
    /// Multiplicative score retained per 30-day age bucket.
    pub recency_decay_ppm: u32,
    /// Candidate-to-selected Jaccard similarity at or above this value is deduplicated.
    pub novelty_dedup_threshold_ppm: u32,
}

impl Default for MemoryRetrievalPolicy {
    fn default() -> Self {
        Self {
            bm25_k1_milli: default_bm25_k1_milli(),
            bm25_b_ppm: default_bm25_b_ppm(),
            recall_limit: default_recall_limit(),
            lexical_weight_ppm: iteron_tunables::param_integer(
                "ctx.memory_runtime.score_scale",
                SCORE_SCALE,
            ),
            structural_weight_ppm: iteron_tunables::param_integer(
                "ctx.memory_runtime.default_structural_weight_ppm",
                0,
            ),
            vector_weight_ppm: 0,
            reranker_weight_ppm: 0,
            recency_decay_ppm: iteron_tunables::param_integer(
                "ctx.memory_runtime.score_scale",
                SCORE_SCALE,
            ),
            novelty_dedup_threshold_ppm: iteron_tunables::param_integer(
                "ctx.memory_runtime.score_scale",
                SCORE_SCALE,
            ),
        }
    }
}

impl MemoryRetrievalPolicy {
    pub fn validate(self) -> Result<Self, &'static str> {
        let weights = [
            self.lexical_weight_ppm,
            self.structural_weight_ppm,
            self.vector_weight_ppm,
            self.reranker_weight_ppm,
        ];
        if weights.iter().any(|weight| {
            *weight > iteron_tunables::param_integer("ctx.memory_runtime.score_scale", SCORE_SCALE)
        }) || weights.iter().all(|weight| *weight == 0)
            || self.bm25_k1_milli == 0
            || self.bm25_k1_milli > 1_000_000
            || self.bm25_b_ppm
                > iteron_tunables::param_integer("ctx.memory_runtime.score_scale", SCORE_SCALE)
            || self.recall_limit == 0
            || usize::try_from(self.recall_limit)
                .map_or(true, |limit| limit > crate::MAX_MEMORY_CANDIDATES)
            || self.recency_decay_ppm
                > iteron_tunables::param_integer("ctx.memory_runtime.score_scale", SCORE_SCALE)
            || self.novelty_dedup_threshold_ppm
                > iteron_tunables::param_integer("ctx.memory_runtime.score_scale", SCORE_SCALE)
        {
            return Err("memory retrieval ratios must be in [0,1] with one non-zero signal");
        }
        // Vector/reranker features require a separately attested owner. Keeping a non-zero weight
        // without one would silently turn a requested hybrid policy into lexical-only ranking.
        if self.vector_weight_ppm != 0 || self.reranker_weight_ppm != 0 {
            return Err("vector/reranker memory weights require an attested feature owner");
        }
        Ok(self)
    }

    pub fn recency_multiplier(self, age_seconds: u64) -> u32 {
        const BUCKET_SECS: u64 = 30 * 24 * 60 * 60;
        const MAX_BUCKETS: u64 = 120;
        let bucket_secs =
            iteron_tunables::param_u64("ctx.memory_runtime.bucket_secs", BUCKET_SECS).max(1);
        let buckets = (age_seconds / bucket_secs).min(iteron_tunables::param_integer(
            "ctx.memory_runtime.max_buckets",
            MAX_BUCKETS,
        ));
        let mut value = u64::from(iteron_tunables::param_integer(
            "ctx.memory_runtime.score_scale",
            SCORE_SCALE,
        ));
        for _ in 0..buckets {
            value = value.saturating_mul(u64::from(self.recency_decay_ppm))
                / u64::from(iteron_tunables::param_integer(
                    "ctx.memory_runtime.score_scale",
                    SCORE_SCALE,
                ));
        }
        u32::try_from(value).unwrap_or(iteron_tunables::param_integer(
            "ctx.memory_runtime.score_scale",
            SCORE_SCALE,
        ))
    }
}

fn default_bm25_k1_milli() -> u32 {
    u32::try_from(iteron_tunables::param_i128(
        "ctx.memory_runtime.default_bm25_k1_milli",
        i128::from(iteron_tunables::param_integer(
            "ctx.memory_runtime.default_bm25_k1_milli",
            DEFAULT_BM25_K1_MILLI,
        )),
    ))
    .unwrap_or(iteron_tunables::param_integer(
        "ctx.memory_runtime.default_bm25_k1_milli",
        DEFAULT_BM25_K1_MILLI,
    ))
}

fn default_bm25_b_ppm() -> u32 {
    u32::try_from(iteron_tunables::param_i128(
        "ctx.memory_runtime.default_bm25_b_ppm",
        i128::from(iteron_tunables::param_integer(
            "ctx.memory_runtime.default_bm25_b_ppm",
            DEFAULT_BM25_B_PPM,
        )),
    ))
    .unwrap_or(iteron_tunables::param_integer(
        "ctx.memory_runtime.default_bm25_b_ppm",
        DEFAULT_BM25_B_PPM,
    ))
}

fn default_recall_limit() -> u32 {
    u32::try_from(iteron_tunables::param_i128(
        "ctx.memory_runtime.default_recall_limit",
        i128::from(iteron_tunables::param_integer(
            "ctx.memory_runtime.default_recall_limit",
            DEFAULT_RECALL_LIMIT,
        )),
    ))
    .unwrap_or(iteron_tunables::param_integer(
        "ctx.memory_runtime.default_recall_limit",
        DEFAULT_RECALL_LIMIT,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recency_decay_is_bounded_and_monotone() {
        let policy = MemoryRetrievalPolicy {
            recency_decay_ppm: 500_000,
            ..MemoryRetrievalPolicy::default()
        };
        assert_eq!(policy.recency_multiplier(0), SCORE_SCALE);
        assert_eq!(policy.recency_multiplier(30 * 24 * 60 * 60), 500_000);
        assert_eq!(policy.recency_multiplier(60 * 24 * 60 * 60), 250_000);
    }
}
