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

/// How the effective default is obtained; the string value remains human- and machine-auditable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultKind {
    Literal,
    Derived,
    Catalog,
    OperatorRequired,
    Inactive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DefaultSpec {
    pub kind: DefaultKind,
    pub value: &'static str,
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
    pub locator: &'static str,
}

/// Machine-discriminated shape of a family value. Composite policies retain textual constraints
/// until a later schema revision introduces structured sub-fields.
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

/// Typed value-domain contract consumed by future resolution and clamping layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ValueSchema {
    pub kind: ValueKind,
    /// Human- and machine-auditable choice set or accepted representation.
    pub admissible: &'static str,
    /// Bounds and cross-field conditions that a resolver must preserve.
    pub constraint: &'static str,
    /// Stable unit label; dimensionless and composite values still name their semantic unit.
    pub unit: &'static str,
}

/// Causal relevance to one fixed benchmark harness, not a promised score delta.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkImpact {
    None,
    Conditional,
    Indirect,
    Direct,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BenchmarkRelevance {
    pub terminal_bench_2_1: BenchmarkImpact,
    pub swe_bench_pro: BenchmarkImpact,
    pub rationale: &'static str,
}

/// The maximum adaptation authority the registry permits a consumer to infer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Trainability {
    /// Frozen safety, protocol, evidence, or resource invariant; never optimized.
    FixedInvariant,
    /// Only an operator may choose or relax the value.
    OperatorOnly,
    /// An offline optimizer may propose a bounded candidate for held-out evaluation.
    OfflineSearch,
    /// A runtime policy may choose inside an immutable operator-owned envelope.
    RuntimeAdaptive,
    /// Curated data or catalog content, not a scalar optimizer parameter.
    CatalogCurated,
    /// Declared but not active in the current runtime.
    Inactive,
}

/// Whether current production code consumes the family as an independent semantic control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    /// Independently consumed by the production runtime.
    Active,
    /// A staged, grouped, or incompletely wired seam exists in production code.
    Partial,
    /// Contract only; there is no current runtime seam.
    Declared,
}

/// One stable semantic family. Multiple scalar exposures with the same meaning share one identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Family {
    pub ordinal: u16,
    pub id: &'static str,
    pub domain: Domain,
    pub summary: &'static str,
    pub default: DefaultSpec,
    pub source: SourceSpec,
    pub value_schema: ValueSchema,
    pub benchmark: BenchmarkRelevance,
    pub trainability: Trainability,
    pub availability: Availability,
}
