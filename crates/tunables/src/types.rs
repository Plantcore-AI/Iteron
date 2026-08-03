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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SourceBinding {
    pub kind: SourceKind,
    pub trust: SourceTrust,
    pub locator: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SourceSpec {
    /// Ordered effective-value precedence, highest authority/precedence first.
    pub bindings: &'static [SourceBinding],
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
pub enum StringFormat {
    Utf8,
    Identifier,
    NamespacedId,
    Uri,
    Command,
    Path,
    Regex,
    Sha256,
    Semver,
}

/// Scalar leaf accepted by a resolver-executable schema AST.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScalarDomain {
    Boolean,
    Integer {
        min: i64,
        max: i64,
        unit: &'static str,
    },
    Decimal {
        min: DecimalValue,
        max: DecimalValue,
        max_scale: u8,
        unit: &'static str,
    },
    Text {
        min_bytes: u64,
        max_bytes: u64,
        format: StringFormat,
    },
    Enum {
        values: &'static [&'static str],
        /// Open/admitted enums name their exact catalog; finite enums set this to `None`.
        catalog_id: Option<&'static str>,
    },
}

/// Field-level AST. Collections are bounded and their leaves are typed; nested object structure is
/// represented by dotted field names so every accepted leaf remains explicit and auditable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FieldDomain {
    Scalar {
        domain: ScalarDomain,
    },
    List {
        min_items: u64,
        max_items: u64,
        unique_items: bool,
        item: ScalarDomain,
    },
    Map {
        min_entries: u64,
        max_entries: u64,
        key: ScalarDomain,
        value: ScalarDomain,
    },
    Object {
        fields: &'static [SchemaField],
        additional_fields: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SchemaField {
    pub name: &'static str,
    pub required: bool,
    pub domain: FieldDomain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalCeiling {
    OperatorAuthority,
    ParentTurns,
    ParentTokens,
    ParentWall,
    ParentCost,
    ProviderCapability,
    ContextWindow,
    ToolBudget,
    ProcessBudget,
    VerificationFloor,
    TenantScope,
    RunBudget,
    BenchmarkProtocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleValue {
    Boolean { value: bool },
    Integer { value: i64 },
    Enum { value: &'static str },
}

/// Typed cross-field/admission rules. Field names are validated against the schema AST; there is
/// no prose escape hatch in the canonical contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CrossFieldRule {
    LessOrEqual {
        left: &'static str,
        right: &'static str,
    },
    SumLessOrEqual {
        terms: &'static [&'static str],
        limit: &'static str,
    },
    Requires {
        if_field: &'static str,
        equals: RuleValue,
        then_field: &'static str,
    },
    MutuallyExclusive {
        fields: &'static [&'static str],
    },
    ExternalCeiling {
        field: &'static str,
        ceiling: ExternalCeiling,
    },
}

/// Tagged, resolver-consumable value schema root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StructuredValueDomain {
    Scalar {
        domain: ScalarDomain,
    },
    List {
        min_items: u64,
        max_items: u64,
        item: ScalarDomain,
        unique_items: bool,
    },
    Map {
        min_entries: u64,
        max_entries: u64,
        key: ScalarDomain,
        value: FieldDomain,
    },
    Object {
        fields: &'static [SchemaField],
        additional_fields: bool,
    },
    Catalog {
        catalog_id: &'static str,
        min_entries: u64,
        max_entries: u64,
        entry_fields: &'static [SchemaField],
    },
}

/// Typed value-domain contract consumed by resolution and clamping layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ValueSchema {
    pub schema_id: &'static str,
    pub kind: ValueKind,
    pub domain: StructuredValueDomain,
    pub rules: &'static [CrossFieldRule],
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
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
    /// Canonical runtime-control ownership key. Renaming an ID or moving an ordinal does not
    /// create a second semantic owner for the same control.
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
