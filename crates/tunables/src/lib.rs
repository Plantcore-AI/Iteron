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
mod capability_graph;
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
mod service_graph;
mod strategy_slots;
mod tool_text;
mod types;
mod validate;
mod value_schemas;

pub use canonical::{
    CanonicalArtifact, CanonicalDigest, CanonicalFamily, CanonicalPayload, canonical_artifact,
    canonical_artifact_json, canonical_payload_json, family_semantic_digest, registry_digest,
};
pub use capability_graph::{
    CAPABILITY_SEAM_GRAPH_SCHEMA_VERSION, CapabilitySeamGraph, CapabilitySeamGraphError,
    CapabilitySeamNode, ContractRef, HostInvariant, LifecycleContracts,
    MAX_CAPABILITY_SEAM_GRAPH_BYTES, MAX_CAPABILITY_SEAMS, MAX_SEAM_DEPENDENCIES,
    ProviderFailureSemantics, capability_seam_graph, validate_capability_seam_graph,
};
pub use export::{
    PROMPT_ARTIFACTS, PromptArtifact, SURFACE_SCHEMA_VERSION, SurfaceExport, surface, surface_json,
};
pub use families::families;
pub use modules::{ModuleId, ModuleKind, family_module};
pub use param_runtime::{
    FamilyInstallError, ParamInstallError, PromptArtifactInstallError, family_bool, family_enum,
    family_integer, family_value, install_family_overrides, install_param_overrides,
    install_prompt_artifact_overrides, installed_param_count, installed_prompt_artifact_count,
    param_bool, param_bytes, param_char, param_duration, param_enum, param_f32, param_f64,
    param_i128, param_integer, param_is_overridden, param_list, param_map, param_object, param_str,
    param_str_list, param_u64, param_usize, param_value, prompt_artifact, tool_description,
};
pub use params::{
    PARAM_REGISTRY_ID, PARAM_SCHEMA_VERSION, Param, ParamCandidateKind, ParamClass,
    ParamDisposition, ParamDomain, ParamDomainViolation, ParamInvariantReason, ParamOwner,
    ParamType, ParamUnit, ParamUseSite, ParamValueViolation, param, param_count,
    param_registry_digest_sha256, params,
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
    fixed_authority_value_digest_sha256_at_registry, runtime_catalog_snapshot,
    runtime_profile_digest,
};
pub use runtime_requirements::{
    RuntimeActivationRequirement, RuntimeConstraintRequirement, RuntimeDefaultObservation,
    canonical_embedded_default, canonical_family, runtime_activation_requirements,
    runtime_constraint_requirements, runtime_default_observations,
};
pub use schema_catalog::{SCALAR_CATALOGS, ScalarCatalogDefinition};
pub use service_graph::{
    MAX_RUNTIME_SERVICE_GRAPH_BYTES, ProductionPortId, RUNTIME_CRATE_IDS,
    RUNTIME_SERVICE_GRAPH_SCHEMA_VERSION, RUNTIME_SERVICE_NODE_COUNT, RuntimeServiceDisposition,
    RuntimeServiceGraph, RuntimeServiceGraphError, RuntimeServiceImplementationStatus,
    RuntimeServiceLayer, RuntimeServiceNode, module_port, runtime_service_graph,
    validate_runtime_service_graph,
};
pub use tool_text::{
    TOOL_TEXT_ARTIFACTS, TOOL_TEXT_REGISTRY_ID, TOOL_TEXT_SCHEMA_VERSION, ToolTextArtifact,
    tool_text_artifact, tool_text_artifact_by_id, tool_text_registry_digest_sha256,
};
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
/// Revision of the family set under schema v4. Revision 20 converts fifteen literal-defaulted
/// families to derived defaults so the Tier-2 parameters that own their production values can
/// actually be set: a literal default is compared byte-for-byte against the compiled constant, and
/// overriding that constant through its Tier-2 handle is precisely what makes the comparison fail.
/// Revision 19 externalized every non-Pin governed family through the universal profile seam while
/// retaining immutable Pin admission rules.
pub const REGISTRY_REVISION: u16 = 20;
/// Exact family cardinality required by the R0/R1 contract.
pub const EXPECTED_FAMILY_COUNT: usize = 160;
/// Canonical byte encoding used as the digest input.
pub const CANONICALIZATION: &str = "iteron-tunables-json-v4";
/// Canonical byte encoding used for each entry's semantic digest.
pub const FAMILY_CANONICALIZATION: &str = "core-tunable-family-json-v3";
/// Digest algorithm for canonical artifacts.
pub const DIGEST_ALGORITHM: &str = "sha256";
/// Golden digest for revision 20; metadata changes require an explicit revision and digest update.
pub const REGISTRY_DIGEST_SHA256: &str =
    "487c554cdcc97e7e86d9af2ae4c6f588e4e250fdefb868a9755c7201ad9e5fd6";
