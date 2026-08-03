use serde::Serialize;

/// One coarse subsystem owning a semantic tuning decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Domain {
    Provider,
    Reasoning,
    Budget,
    Context,
    Memory,
    Tooling,
    Verification,
    Orchestration,
    Runtime,
    Extensibility,
    Observability,
    Interface,
    Evaluation,
    Governance,
}

/// How the effective default is obtained. This is deliberately independent of implementation
/// status: a missing control still has a target default in the formal registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultKind {
    Literal,
    Derived,
    Dynamic,
    Catalog,
    OperatorRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultResolutionSource {
    Literal,
    BuiltinDerivation,
    ModelMetadata,
    ProviderCapability,
    Transport,
    RuntimeObservation,
    GovernedCatalog,
    Operator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DefaultSpec {
    pub kind: DefaultKind,
    pub value: &'static str,
    pub resolution_source: DefaultResolutionSource,
}

/// Trust attached to the source evidence, not authority granted to a candidate policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceTrust {
    Operator,
    Repository,
    Builtin,
    RuntimeObservation,
    ProviderAttested,
    GovernedBundle,
    RegistryDeclaration,
}

/// Primary provenance of the effective value. `locator` points to the current authority or seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Cli,
    UserConfig,
    ProjectConfig,
    Environment,
    Builtin,
    DerivedPolicy,
    Catalog,
    RuntimeObservation,
    ExternalProvider,
    GovernedBundle,
    /// Contract-only declaration with no active runtime seam yet.
    Registry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SourceSpec {
    pub kind: SourceKind,
    pub trust: SourceTrust,
    pub locator: &'static str,
}

/// Machine-discriminated shape of a family value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueKind {
    Bool,
    Enum,
    Count,
    Duration,
    Bytes,
    Ratio,
    Decimal,
    String,
    List,
    Map,
    Policy,
    Catalog,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NumericType {
    Integer,
    Decimal,
}

/// Tagged, resolver-consumable value domain. Cross-field and authority conditions live separately
/// in `ValueSchema::constraints`; this enum carries shape and local bounds only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StructuredValueDomain {
    Boolean,
    Numeric {
        numeric_type: NumericType,
        min: Option<i64>,
        max: Option<i64>,
        unit: &'static str,
    },
    FiniteEnum {
        values: &'static [&'static str],
        open_catalog: bool,
        catalog_ref: Option<&'static str>,
    },
    Text {
        min_bytes: u64,
        max_bytes: Option<u64>,
        format: &'static str,
    },
    List {
        min_items: u64,
        max_items: Option<u64>,
        item_schema: &'static str,
        unique_items: bool,
    },
    Map {
        min_entries: u64,
        max_entries: Option<u64>,
        key_schema: &'static str,
        value_schema: &'static str,
    },
    Composite {
        schema_ref: &'static str,
        max_bytes: u64,
        max_nodes: u64,
        max_depth: u64,
    },
    Catalog {
        min_entries: u64,
        max_entries: Option<u64>,
        entry_schema: &'static str,
        open_catalog: bool,
    },
}

/// Typed value-domain contract consumed by resolution and clamping layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ValueSchema {
    pub kind: ValueKind,
    pub domain: StructuredValueDomain,
    /// Explanatory representation text; not used as a substitute for bounds or tags.
    pub description: &'static str,
    /// Cross-field, admission, and authority conditions preserved by a resolver.
    pub constraints: &'static [&'static str],
}

/// Executable structural definition for every `core://` reference emitted by a value domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferencedSchemaShape {
    NamespacedId,
    BoundedScalarOrObject,
    BoundedPolicyObject,
    VersionedCatalogEntry,
    AdmittedCatalogValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ReferencedSchema {
    pub id: &'static str,
    pub shape: ReferencedSchemaShape,
    pub max_bytes: u64,
    pub max_nodes: u64,
    pub max_depth: u64,
}

/// Formal benchmark relevance. There is intentionally no `None` or causal-path vocabulary here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelevanceLevel {
    Low,
    Medium,
    High,
}

/// Optional causal-path annotation, kept separate from formal relevance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalPath {
    None,
    Conditional,
    Indirect,
    Direct,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BenchmarkCausalPath {
    pub swe_bench_pro: CausalPath,
    pub terminal_bench_2_1: CausalPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BenchmarkRelevance {
    /// Formal ordering is SWE-bench Pro first, then Terminal-Bench 2.1.
    pub swe_bench_pro: RelevanceLevel,
    pub terminal_bench_2_1: RelevanceLevel,
    pub causal_path: BenchmarkCausalPath,
    pub rationale: &'static str,
}

/// Current implementation truth, independent of default and optimization eligibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImplementationStatus {
    /// Independently exposed and consumed by production code.
    Full,
    /// A grouped or incomplete production seam exists.
    Partial,
    /// No production seam exists.
    Missing,
    /// Production behavior exists only as a fixed or derived hidden choice.
    FixedHidden,
}

/// Structured activation test. `Unavailable` is reserved for `Missing` entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ActivationPredicate {
    Always,
    Configured { source: SourceKind },
    RuntimeDerived { seam: &'static str },
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ActivationSpec {
    pub predicate: ActivationPredicate,
    pub inactive_reason: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderRequirement {
    None,
    AnyAdmittedRoute,
    SelectedRoute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityRequirement {
    Inference,
    ProviderCatalog,
    ProviderStreaming,
    ProviderServiceTier,
    ProviderPromptCache,
    ProviderMultimodal,
    ProviderRequestCompression,
    RateLimitObservation,
    Reasoning,
    BudgetAccounting,
    ContextRead,
    MemoryReadWrite,
    ToolExecution,
    PersistentProcess,
    BackgroundJob,
    InteractiveStdin,
    ProcessSignal,
    FileSystemWrite,
    BinaryInspection,
    LanguageServer,
    ToolResultCache,
    Verification,
    WorkspaceCheckpoint,
    AgentSpawn,
    AgentMessaging,
    WorktreeIsolation,
    RuntimeObservation,
    ExtensionDiscovery,
    McpTransport,
    McpResource,
    OAuth,
    EvidenceObservation,
    ReplayEvidence,
    OperatorInteraction,
    Evaluation,
    AuthorityConfiguration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RequirementSpec {
    pub provider: ProviderRequirement,
    pub capabilities: &'static [CapabilityRequirement],
}

/// The nine formal core StrategySlot bindings. Every family binds one or more of these exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum CoreStrategySlot {
    #[serde(rename = "core/router")]
    Router,
    #[serde(rename = "core/planner")]
    Planner,
    #[serde(rename = "core/context")]
    Context,
    #[serde(rename = "core/memory")]
    Memory,
    #[serde(rename = "core/scheduler")]
    Scheduler,
    #[serde(rename = "core/tool_policy")]
    ToolPolicy,
    #[serde(rename = "core/verifier")]
    Verifier,
    #[serde(rename = "core/model_router")]
    ModelRouter,
    #[serde(rename = "core/collaboration")]
    Collaboration,
}

/// Formal optimization category. `C*` variants retain the distinction between structured policy,
/// artifact, and component work; they are not collapsed into catalog curation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OptimizationClass {
    P1,
    P2,
    CStructured,
    CArtifact,
    CComponent,
    Pin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchPhase {
    P1,
    P2,
    Conditional,
    Pinned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct OptimizationSpec {
    pub class: OptimizationClass,
    pub search_phase: SearchPhase,
    pub pin_reason: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityClass {
    Strategy,
    Operator,
    GovernedArtifact,
    RuntimeInvariant,
    KernelInvariant,
}

/// One stable semantic family. Multiple scalar exposures with the same meaning share one identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Family {
    pub schema_version: u16,
    pub ordinal: u16,
    pub id: &'static str,
    pub aliases: &'static [&'static str],
    pub domain: Domain,
    pub summary: &'static str,
    pub activation: ActivationSpec,
    pub requirements: RequirementSpec,
    pub strategy_slots: &'static [CoreStrategySlot],
    pub default: DefaultSpec,
    pub source: SourceSpec,
    pub value_schema: ValueSchema,
    pub benchmark_relevance: BenchmarkRelevance,
    pub implementation_status: ImplementationStatus,
    pub optimization: OptimizationSpec,
    pub risk_class: RiskClass,
    pub authority_class: AuthorityClass,
}
