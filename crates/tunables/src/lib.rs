//! Versioned, non-authoritative metadata for Core's tunable semantic families.
//!
//! Boundary: this crate describes knobs; it does not read configuration, choose values, mutate the
//! runtime, load a policy bundle, or grant authority. Security, permission, durability, replay,
//! budget, and effect-ledger guarantees remain outside the learnable policy surface. Consumers may
//! use the registry for analysis and offline candidate generation, but the runtime remains the sole
//! authority for admitting any resulting value.
//!
//! Invariants:
//! - the public registry contains exactly [`EXPECTED_FAMILY_COUNT`] stable family identities;
//! - its canonical payload has one versioned byte representation and SHA-256 digest;
//! - every family declares a structured value domain, activation, source trust, requirements,
//!   StrategySlot bindings, implementation truth, benchmark relevance, and optimization class;
//! - metadata never silently turns an invariant or operator ceiling into an adaptive choice.

mod benchmark_metadata;
mod canonical;
mod families;
mod metadata;
mod requirements;
mod resolution_metadata;
mod schema_catalog;
mod strategy_slots;
mod types;
mod validate;
mod value_schemas;

pub use canonical::{
    CanonicalArtifact, CanonicalDigest, CanonicalFamily, CanonicalPayload, canonical_artifact,
    canonical_artifact_json, canonical_payload_json, family_semantic_digest, registry_digest,
};
pub use families::families;
pub use schema_catalog::{SCALAR_CATALOGS, ScalarCatalogDefinition};
pub use types::{
    ActivationPredicate, ActivationSpec, AuthorityClass, BenchmarkCausalPath, BenchmarkRelevance,
    CapabilityRequirement, CausalPath, CoreStrategySlot, CrossFieldRule, DecimalValue, DefaultKind,
    DefaultResolver, DefaultSpec, DefaultValueRequirement, Domain, ExternalCeiling, Family,
    FieldDomain, ImplementationStatus, InactiveReason, OptimizationClass, OptimizationSpec,
    ProviderRequirement, RelevanceLevel, RequirementSpec, RiskClass, RuleValue, ScalarDomain,
    SchemaField, SearchPhase, SourceBinding, SourceKind, SourceSpec, SourceTrust, StringFormat,
    StructuredValueDomain, TunableValue, TunableValueField, ValueKind, ValueSchema,
};
pub use validate::{RegistryError, validate_registry};

/// Registry DTO schema. A breaking field or semantic change requires a new version.
pub const REGISTRY_SCHEMA_VERSION: u16 = 2;
/// Schema version carried by every semantic family entry.
pub const FAMILY_SCHEMA_VERSION: u16 = 1;
/// Stable logical registry identity.
pub const REGISTRY_ID: &str = "core-tunables";
/// Revision of the family set under schema v2.
pub const REGISTRY_REVISION: u16 = 2;
/// Exact family cardinality required by the R0/R1 contract.
pub const EXPECTED_FAMILY_COUNT: usize = 160;
/// Canonical byte encoding used as the digest input.
pub const CANONICALIZATION: &str = "core-tunables-json-v2";
/// Canonical byte encoding used for each entry's semantic digest.
pub const FAMILY_CANONICALIZATION: &str = "core-tunable-family-json-v1";
/// Digest algorithm for canonical artifacts.
pub const DIGEST_ALGORITHM: &str = "sha256";
/// Golden digest for revision 2; metadata changes require an explicit revision and digest update.
pub const REGISTRY_DIGEST_SHA256: &str =
    "1d3d5787eb4b47c9428b264aad5d01dc74791427570643d32984824a3249f304";
