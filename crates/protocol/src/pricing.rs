//! Versioned, route-bound monetary evidence.
//!
//! These are wire types only. Signature verification and token-to-money projection belong to the
//! observability/pricing strategy layer; the kernel records the resulting evidence and enforces a
//! fixed-point ceiling without owning a price table or any network authority.

use crate::Usage;
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Hard wire bound for signed child-cost evidence. The replay layer independently checks that
/// cardinality matches completed turns, while this limit prevents a hostile record from first
/// materializing an unbounded `Vec` during typed deserialization.
pub const MAX_WORKFLOW_COST_PROJECTIONS: usize = 1_024;

pub(crate) fn deserialize_cost_projections<'de, D>(
    deserializer: D,
) -> Result<Vec<CostProjection>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct ProjectionVisitor;

    impl<'de> Visitor<'de> for ProjectionVisitor {
        type Value = Vec<CostProjection>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {MAX_WORKFLOW_COST_PROJECTIONS} signed cost projections"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let capacity = sequence
                .size_hint()
                .unwrap_or(0)
                .min(MAX_WORKFLOW_COST_PROJECTIONS);
            let mut projections = Vec::with_capacity(capacity);
            while let Some(projection) = sequence.next_element()? {
                if projections.len() == MAX_WORKFLOW_COST_PROJECTIONS {
                    return Err(de::Error::invalid_length(
                        projections.len().saturating_add(1),
                        &self,
                    ));
                }
                projections.push(projection);
            }
            Ok(projections)
        }
    }

    deserializer.deserialize_seq(ProjectionVisitor)
}

/// Schema version for rate cards and their per-turn projections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PricingVersion {
    V1,
}

/// Exact durable route provenance to which a rate card applies.
///
/// Provider/model identity alone is insufficient: an operator may repoint the same provider id at
/// another gateway or refresh its capability evidence. The two digests are therefore part of the
/// signed route and must match the preceding `ModelSelected` event byte-for-byte.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PricingRoute {
    pub provider_id: String,
    pub model_id: String,
    pub catalog_digest: String,
    pub capability_digest: String,
}

/// Fixed-point prices in micro-USD per one million tokens.
///
/// `output` prices non-thinking output tokens. `thinking` prices the reasoning subset separately,
/// preventing adapters that report thinking as part of total output from being double charged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRateCard {
    pub input_microusd_per_million: u64,
    pub output_microusd_per_million: u64,
    pub cache_creation_microusd_per_million: u64,
    pub cache_read_microusd_per_million: u64,
    pub thinking_microusd_per_million: u64,
}

/// Rate-card payload signed by a trusted pricing strategy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateCard {
    pub version: PricingVersion,
    pub route: PricingRoute,
    /// Stable, immutable, non-secret source revision (for example an operator manifest commit).
    pub provenance: String,
    /// Half-open validity interval `[issued_at_unix_secs, expires_at_unix_secs)`.
    pub issued_at_unix_secs: u64,
    pub expires_at_unix_secs: u64,
    pub rates: TokenRateCard,
}

/// Authenticated rate-card artifact. The digest is content-addressed; the HMAC signature proves
/// that the trusted strategy admitted those exact bytes for the exact route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRateCard {
    pub rate_card: RateCard,
    pub signer_id: String,
    pub rate_card_digest: String,
    pub signature: String,
}

/// Durable rollout identity authenticated by a [`CostProjection`]. Provider usage is meaningful
/// only inside one tenant/run/turn attempt; signing these fields prevents otherwise-valid cost
/// evidence from being transplanted into another journal or another completed turn.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CostProjectionIdentity {
    pub tenant_id: String,
    pub run_id: String,
    pub turn_id: u32,
    pub provider_attempt: u32,
    /// A child projection also authenticates the exact parent terminal that may aggregate it.
    #[serde(default)]
    pub attribution: Option<CostAttribution>,
}

/// Parent-side terminal identity for child cost evidence.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CostAttribution {
    DirectSubagent {
        parent_run_id: String,
        sub_run: String,
    },
    WorkflowChild {
        parent_run_id: String,
        workflow_id: String,
        task_id: u32,
        sub_run: String,
    },
}

/// Authenticated price of exactly one provider-reported usage sample.
///
/// The projection repeats route, usage, and rate-card digest deliberately: replay can bind the
/// amount to the preceding `TurnEnd` and `RateCardBound` evidence without consulting mutable
/// catalogs or fetching current prices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CostProjection {
    pub version: PricingVersion,
    /// Missing only on historical v1 evidence written before rollout identity was authenticated.
    /// Readers keep that evidence wire-compatible but must not restore a known monetary value.
    #[serde(default)]
    pub identity: Option<CostProjectionIdentity>,
    pub route: PricingRoute,
    pub usage: Usage,
    pub amount_microusd: u64,
    /// Strategy-observed wall time, authenticated by the projection HMAC. Replay checks it against
    /// the card's signed validity interval instead of consulting the current clock.
    pub projected_at_unix_secs: u64,
    pub rate_card_digest: String,
    pub signer_id: String,
    pub projection_digest: String,
    pub signature: String,
}
