//! Immutable, versioned run-genesis tunables checkpoints.
//!
//! V1 is the historical identity-only checkpoint. V2 is a separate top-level event payload so an
//! older serde reader sees an unknown event rather than trying to decode new fields inside the
//! known V1 tag. The V2 per-family projections contain configuration truth only: no prompt,
//! transcript, memory, source text, tool arguments, or credentials have a field in this schema.

use serde::{Deserialize, Serialize};

use crate::RunGenesisTunableState;

/// Maximum number of semantic families admitted in one genesis checkpoint.
pub const MAX_RUN_GENESIS_TUNABLE_ENTRIES: usize = 160;
/// Maximum UTF-8 bytes in stable registry/family/semantic/provenance identifiers.
pub const MAX_RUN_GENESIS_TUNABLE_ID_BYTES: usize = 256;
/// Maximum canonical JSON bytes committed by one V2 checkpoint.
pub const MAX_RUN_GENESIS_TUNABLES_V2_BYTES: usize = 2 * 1024 * 1024;
/// Maximum canonical JSON nodes across all V2 value and explanation projections.
pub const MAX_RUN_GENESIS_TUNABLES_V2_NODES: usize = 262_144;
/// Maximum nested value/provenance depth admitted by a V2 checkpoint.
pub const MAX_RUN_GENESIS_TUNABLES_V2_DEPTH: usize = 32;
/// Maximum applied ceiling projections retained for one family.
pub const MAX_RUN_GENESIS_TUNABLE_CEILINGS: usize = 16;

/// Canonical encoding committed by [`RunGenesisTunablesSnapshot::snapshot_digest_sha256`].
pub const RUN_GENESIS_TUNABLES_CANONICALIZATION: &str = "core-run-genesis-tunables-json-v1";
/// Canonical encoding committed by [`RunGenesisTunablesSnapshotV2::snapshot_digest_sha256`].
pub const RUN_GENESIS_TUNABLES_V2_CANONICALIZATION: &str = "core-run-genesis-tunables-json-v2";

/// Closed schema version carried by the additive V2 tunables checkpoint event.
///
/// V1 keeps its published [`crate::RunGenesisTunablesVersion`] type byte- and source-identical.
/// Giving the additive payload its own one-variant type prevents either event from accepting the
/// other's version while retaining the immediate-base public V1 contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunGenesisTunablesVersionV2 {
    V2,
}

/// Closed protocol projection of the fixed authorities registered by the tunables runtime. This
/// enum is duplicated at the protocol boundary intentionally: protocol cannot depend on the
/// higher-level registry crate, while a free-form string would let a forged authority survive
/// deserialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunGenesisFixedAuthorityIdV2 {
    StrategyInvariant,
    OperatorBoundary,
    GovernedArtifactBoundary,
    RuntimeInvariant,
    KernelInvariant,
    ProviderDiscoveryBootstrap,
    OperatorPromptInput,
    GovernedCatalogMaterialization,
    ChildOverlayMaterialization,
    McpConfigurationMaterialization,
}

/// Durable, content-free equality proof for one effective FixedHidden family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunGenesisFixedAuthorityBindingV2 {
    pub authority: RunGenesisFixedAuthorityIdV2,
    pub owner_value_digest_sha256: String,
}

/// Reconstructable V2 projection of one family.
///
/// The JSON sub-values are sealed by the outer schema, bounded and secret-shape checked at the
/// record boundary, and committed by both the effective-set digest and the checkpoint self-digest.
/// They deliberately mirror the resolver's canonical typed JSON without introducing a dependency
/// from `iteron-protocol` back to `iteron-tunables`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunGenesisTunableEntryV2 {
    pub ordinal: u16,
    pub family_id: String,
    pub semantic_key: String,
    pub state: RunGenesisTunableState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_value: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<serde_json::Value>,
    /// True only when this family's winning provenance came from the immutable named profile.
    #[serde(default)]
    pub profile_applied: bool,
    /// Exact applied adjustment/ceiling projections from the accepted resolution report.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ceiling_adjustments: Vec<serde_json::Value>,
    /// Exact inactive cause. Present if and only if `state == inactive`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inactive_reason: Option<serde_json::Value>,
    /// Present if and only if this is an effective FixedHidden family. The outer checkpoint
    /// digest commits this binding, and admission recomputes the digest from the effective value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed_authority_binding: Option<RunGenesisFixedAuthorityBindingV2>,
}

/// Immutable V2 checkpoint from which all runtime-effective family values and operator-facing
/// explanation fields can be reconstructed without consulting current machine defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunGenesisTunablesSnapshotV2 {
    pub version: RunGenesisTunablesVersionV2,
    pub canonicalization: String,
    pub resolution_schema_version: u16,
    pub registry_id: String,
    pub registry_schema_version: u16,
    pub family_schema_version: u16,
    pub registry_revision: u16,
    pub registry_digest_sha256: String,
    pub input_digest_sha256: String,
    pub effective_digest_sha256: String,
    pub resolution_digest_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_digest_sha256: Option<String>,
    pub entries: Vec<RunGenesisTunableEntryV2>,
    pub snapshot_digest_sha256: String,
}
