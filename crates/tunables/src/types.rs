use serde::{Deserialize, Serialize};

mod schema;
pub use schema::*;

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
}

/// Machine-readable resolver invoked when a literal is not embedded directly in the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DefaultResolver {
    Literal,
    Builtin { resolver_id: &'static str },
    ModelMetadata { field: &'static str },
    ProviderCapability { capability: &'static str },
    Transport { field: &'static str },
    RuntimeObservation { field: &'static str },
    GovernedCatalog { catalog_id: &'static str },
    Operator { input_id: &'static str },
}

/// Whether resolution may proceed without an operator-supplied value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultValueRequirement {
    Optional,
    Required,
}

/// Exact decimal representation used by schemas and defaults; no binary floating-point values
/// enter canonical artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecimalValue {
    pub coefficient: i64,
    pub scale: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TunableValueField {
    pub name: &'static str,
    pub value: TunableValue,
}

/// Typed default/fallback value. Derived and dynamic defaults may omit `DefaultSpec::value`, but
/// may never encode an executable default as prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TunableValue {
    Boolean {
        value: bool,
    },
    Integer {
        value: i64,
    },
    Decimal {
        value: DecimalValue,
    },
    Text {
        value: &'static str,
    },
    Enum {
        value: &'static str,
    },
    List {
        items: &'static [TunableValue],
    },
    Map {
        entries: &'static [TunableValueField],
    },
    Object {
        fields: &'static [TunableValueField],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DefaultSpec {
    pub kind: DefaultKind,
    pub resolver: DefaultResolver,
    pub requirement: DefaultValueRequirement,
    /// Literal value or typed fallback. `None` means the named resolver must produce the value.
    pub value: Option<TunableValue>,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Cli,
    OperatorInput,
    RustBuilder,
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

/// How a source participates in resolution after its value has been authenticated and validated.
///
/// This is deliberately metadata, not frontend convention. In particular, repository-owned
/// configuration is never an ordinary override: it may suggest a route when the operator did not
/// select one, narrow a ceiling/grant, or contribute bounded repository-scoped content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceMergePolicy {
    /// First value in registry precedence order wins.
    Override,
    /// Used only when no operator-owned source selected a route.
    RouteSuggestion,
    /// Numeric minimum: a repository value may introduce or lower, never raise, a ceiling.
    TightenMaximum,
    /// Boolean intersection: a repository `false` may revoke, while `true` never grants.
    TightenBooleanGrant,
    /// Set intersection for allow-lists; it can remove members but cannot add authority.
    IntersectAllowSet,
    /// Bounded repository content scoped to the current repository, not operator authority.
    RepositoryScoped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SourceBinding {
    pub kind: SourceKind,
    pub trust: SourceTrust,
    pub locator: &'static str,
    pub merge: SourceMergePolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SourceSpec {
    /// Ordered effective-value precedence, highest authority/precedence first.
    pub bindings: &'static [SourceBinding],
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
    Configured { sources: &'static [SourceKind] },
    RuntimeDerived { seam: &'static str },
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InactiveReason {
    ConfigurationAbsent,
    GroupedOrIncompleteSeam,
    NotImplemented,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ActivationSpec {
    pub predicate: ActivationPredicate,
    pub inactive_reason: Option<InactiveReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderRequirement {
    None,
    AnyAdmittedRoute,
    SelectedRoute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityRequirement {
    Inference,
    ProviderCatalog,
    ProviderStreaming,
    ProviderServiceTier,
    ProviderPromptCache,
    ProviderMultimodal,
    ProviderRequestCompression,
    ProviderTransport,
    ProviderModelMetadata,
    ProviderReasoningControl,
    ProviderDiscovery,
    ProviderFailover,
    ProviderHealth,
    ProviderHedging,
    ProviderRequestDeadline,
    ProviderResponseVerbosity,
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
    /// Canonical runtime-control ownership key from the independent control-key ledger. It is not
    /// derived from the display ID or ordinal, so either can change without creating a new owner.
    pub semantic_key: &'static str,
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
