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
mod binding_metadata;
mod canonical;
pub mod export;
mod families;
mod metadata;
mod modules;
mod param_runtime;
mod params;
mod profile_io;
mod requirements;
mod resolution;
mod resolution_constraints;
mod resolution_digest;
mod resolution_explain;
mod resolution_metadata;
mod resolution_prepare;
mod resolution_types;
mod resolution_value;
mod resolved_set_rules;
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
pub use export::{
    PROMPT_ARTIFACTS, PromptArtifact, SURFACE_SCHEMA_VERSION, SurfaceExport, surface, surface_json,
};
pub use families::families;
pub use modules::{ModuleId, ModuleKind, family_module};
pub use param_runtime::{
    ParamInstallError, PromptArtifactInstallError, install_param_overrides,
    install_prompt_artifact_overrides, installed_param_count, installed_prompt_artifact_count,
    param_bool, param_bytes, param_char, param_duration, param_f32, param_f64, param_i128,
    param_integer, param_is_overridden, param_str, param_str_list, param_u64, param_usize,
    param_value, prompt_artifact,
};
pub use params::{
    PARAM_REGISTRY_ID, PARAM_SCHEMA_VERSION, Param, ParamClass, ParamDomain, ParamDomainViolation,
    ParamType, ParamUnit, ParamValueViolation, param, param_count, param_registry_digest_sha256,
    params,
};
pub use profile_io::{
    ArtifactOverride, MAX_ARTIFACT_TEXT_BYTES, MAX_PROFILE_BYTES, PROFILE_DOCUMENT_SCHEMA_VERSION,
    ParamAssignment, ProfileDocument, ProfileLoadError, artifact_override, document_digest,
    emit_profile, load_profile, render_profile, validate_profile,
};
pub use resolution::{resolve, resolve_json};
pub use resolution_explain::{ExplainError, explain_entry_json, explain_text};
pub use resolution_types::{
    ActivationEvidence, Adjustment, AdjustmentKind, CatalogSnapshot, ConstraintEvidence,
    ConstraintValue, DeclaredValue, DefaultEvidence, EntryOutcome, EntryState, EvidenceState,
    EvidenceSubject, FailureCode, FamilyFailure, FixedAuthorityAttestation, InactiveCause,
    ProfileValue, RESOLUTION_INPUT_MAX_BYTES, RESOLUTION_SCHEMA_VERSION, RejectionReason,
    ResolutionFailureReport, ResolutionInput, ResolutionProfile, ResolutionProvenance,
    ResolutionReport, ResolutionSource, ResolutionValue, ResolvedEntry, ResolvedTunableSet,
    RouteCapabilities, RouteIdentity, RuntimeContext, ShadowedValue, UnresolvedReason,
};
#[cfg(feature = "test-fixtures")]
pub use runtime_binding::with_synthetic_fixed_authority_attestations_for_test;
pub use runtime_binding::{
    EffectiveValueError, RuntimeAuthoritySet, RuntimeOwnerReceipt, RuntimeProfile,
    RuntimeResolutionBuilder, RuntimeResolutionError, fixed_authority_value_digest_sha256,
    runtime_catalog_snapshot, runtime_profile_digest,
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
    DefaultResolver, DefaultSpec, DefaultValueRequirement, Domain, EvidenceProjectionId,
    ExternalCeiling, Family, FieldDomain, FixedAuthorityId, ImplementationStatus, InactiveReason,
    OptimizationClass, OptimizationSpec, ProductionOwnerId, ProductionOwnerSymbolId,
    ProviderRequirement, RelevanceLevel, RequirementSpec, ResolvedValuePath, RiskClass, RuleValue,
    RuntimeBindingSpec, RuntimeGetterId, ScalarDomain, SchemaField, SearchPhase, SourceBinding,
    SourceKind, SourceMergePolicy, SourceSpec, SourceTrust, StringFormat, StructuredValueDomain,
    TunableValue, TunableValueField, ValueKind, ValueSchema,
};
pub use validate::{RegistryError, validate_registry};

/// Registry DTO schema. A breaking field or semantic change requires a new version.
pub const REGISTRY_SCHEMA_VERSION: u16 = 4;
/// Schema version carried by every semantic family entry.
pub const FAMILY_SCHEMA_VERSION: u16 = 3;
/// Stable logical registry identity.
pub const REGISTRY_ID: &str = "iteron-tunables";
/// Revision of the family set under schema v4. Revision 17 gives fifty-eight implemented
/// families a `UserConfig` source binding: they were reachable by the runtime but by no operator,
/// so the registry described a control nobody could exercise.
pub const REGISTRY_REVISION: u16 = 17;
/// Exact family cardinality required by the R0/R1 contract.
pub const EXPECTED_FAMILY_COUNT: usize = 160;
/// Canonical byte encoding used as the digest input.
pub const CANONICALIZATION: &str = "iteron-tunables-json-v4";
/// Canonical byte encoding used for each entry's semantic digest.
pub const FAMILY_CANONICALIZATION: &str = "core-tunable-family-json-v3";
/// Digest algorithm for canonical artifacts.
pub const DIGEST_ALGORITHM: &str = "sha256";
/// Golden digest for revision 17; metadata changes require an explicit revision and digest update.
pub const REGISTRY_DIGEST_SHA256: &str =
    "fee22a629e6bb95f190c75ec25e63e198a2eb44a7dfb1bf839828e5c397d93db";
