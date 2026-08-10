//! Versioned, non-authoritative metadata for Core's tunable semantic families.
//!
//! Boundary: the registry describes knobs, and the pure resolver deterministically evaluates an
//! explicit frozen request. This crate does not read configuration or ambient state, mutate the
//! runtime, load a policy bundle, authenticate evidence, or grant authority. A resolved set remains
//! an offline simulation until a production binding admits it and records run-genesis evidence.
//! Security, permission, durability, replay, budget, and effect-ledger guarantees remain outside
//! the learnable policy surface; the runtime remains the sole authority for admitting a value.
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
mod resolution;
mod resolution_constraints;
mod resolution_digest;
mod resolution_explain;
mod resolution_metadata;
mod resolution_prepare;
mod resolution_types;
mod resolution_value;
mod runtime_binding;
mod runtime_requirements;
mod schema_catalog;
mod semantic_keys;
mod strategy_slots;
mod types;
mod validate;
mod value_schemas;

pub use canonical::{
    CanonicalArtifact, CanonicalDigest, CanonicalFamily, CanonicalPayload, canonical_artifact,
    canonical_artifact_json, canonical_payload_json, family_semantic_digest, registry_digest,
};
pub use families::families;
pub use resolution::{resolve, resolve_json};
pub use resolution_explain::{ExplainError, explain_entry_json, explain_text};
pub use resolution_types::{
    ActivationEvidence, Adjustment, AdjustmentKind, CatalogSnapshot, ConstraintEvidence,
    ConstraintValue, DeclaredValue, DefaultEvidence, EntryOutcome, EntryState, EvidenceState,
    EvidenceSubject, FailureCode, FamilyFailure, InactiveCause, ProfileValue,
    RESOLUTION_INPUT_MAX_BYTES, RESOLUTION_SCHEMA_VERSION, RejectionReason,
    ResolutionFailureReport, ResolutionInput, ResolutionProfile, ResolutionProvenance,
    ResolutionReport, ResolutionSource, ResolutionValue, ResolvedEntry, ResolvedTunableSet,
    RouteCapabilities, RouteIdentity, RuntimeContext, ShadowedValue, UnresolvedReason,
};
pub use runtime_binding::{
    EffectiveValueError, RuntimeAuthoritySet, RuntimeProfile, RuntimeResolutionBuilder,
    RuntimeResolutionError, runtime_catalog_snapshot, runtime_profile_digest,
};
pub use runtime_requirements::{
    RuntimeActivationRequirement, RuntimeConstraintRequirement, RuntimeDefaultObservation,
    canonical_embedded_default, canonical_family, runtime_activation_requirements,
    runtime_constraint_requirements, runtime_default_observations,
};
pub use schema_catalog::{SCALAR_CATALOGS, ScalarCatalogDefinition};
pub use types::{
    ActivationPredicate, ActivationSpec, AuthorityClass, BenchmarkCausalPath, BenchmarkRelevance,
    CapabilityRequirement, CausalPath, ConstraintProjection, ConstraintRelation,
    ConstraintViolation, CoreStrategySlot, CrossFieldRule, DecimalValue, DefaultKind,
    DefaultResolver, DefaultSpec, DefaultValueRequirement, Domain, ExternalCeiling, Family,
    FieldDomain, ImplementationStatus, InactiveReason, OptimizationClass, OptimizationSpec,
    ProviderRequirement, RelevanceLevel, RequirementSpec, RiskClass, RuleValue, ScalarDomain,
    SchemaField, SearchPhase, SourceBinding, SourceKind, SourceMergePolicy, SourceSpec,
    SourceTrust, StringFormat, StructuredValueDomain, TunableValue, TunableValueField, ValueKind,
    ValueSchema,
};
pub use validate::{RegistryError, validate_registry};

/// Registry DTO schema. A breaking field or semantic change requires a new version.
pub const REGISTRY_SCHEMA_VERSION: u16 = 3;
/// Schema version carried by every semantic family entry.
pub const FAMILY_SCHEMA_VERSION: u16 = 2;
/// Stable logical registry identity.
pub const REGISTRY_ID: &str = "core-tunables";
/// Revision of the family set under schema v3.
pub const REGISTRY_REVISION: u16 = 7;
/// Exact family cardinality required by the R0/R1 contract.
pub const EXPECTED_FAMILY_COUNT: usize = 160;
/// Canonical byte encoding used as the digest input.
pub const CANONICALIZATION: &str = "core-tunables-json-v3";
/// Canonical byte encoding used for each entry's semantic digest.
pub const FAMILY_CANONICALIZATION: &str = "core-tunable-family-json-v2";
/// Digest algorithm for canonical artifacts.
pub const DIGEST_ALGORITHM: &str = "sha256";
/// Golden digest for revision 7; metadata changes require an explicit revision and digest update.
pub const REGISTRY_DIGEST_SHA256: &str =
    "adf934b1342d56fc86107d9d7d4bb8394c94c1d565ed3198066fff00dbd516bd";
