use super::DecimalValue;
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

/// Source-controlled comparison between one family field and attested external evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintRelation {
    /// Evidence supplies a numeric upper bound.
    UpperBound,
    /// Evidence supplies an admitted typed domain (range, allowlist, or required subset).
    AttestedDomain,
    /// Evidence supplies the one exact protocol value.
    Exact,
}

/// Source-controlled projection of a constraint onto its target. Revision 3 admits whole field or
/// family values plus whole-catalog attestations; collection item/key/value projections require a
/// future registry revision with dedicated semantics and adversarial coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintProjection {
    WholeValue,
    /// The named catalog-entry field is governed through an attestation over the complete inline
    /// catalog or content-addressed catalog reference. R2 does not claim to materialize entries.
    WholeCatalog,
}

/// Source-controlled response to a violated external constraint. Evidence never chooses this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConstraintViolation {
    Reject,
    ClampNumeric,
    /// Use only the authority-attested preferred value, and only after it validates against the
    /// same admitted domain. There is no lexical or first-item fallback.
    DegradeAttested {
        policy_id: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleValue {
    Boolean { value: bool },
    Integer { value: i64 },
    Decimal { value: DecimalValue },
    Enum { value: &'static str },
}

/// One exact numeric value inside the effective resolved-set. Unlike a local schema path, this
/// path names both the stable family authority and the value below that family's schema root.
/// Keeping this typed and canonical prevents composition code from inventing hidden joins between
/// independently valid families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ResolvedValuePath {
    pub family: &'static str,
    pub path: &'static str,
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
    /// Require a set of numeric fields or closed-map entries to sum to one exact fixed-point
    /// total. This captures normalized runtime policies without inventing a hidden fourth field.
    SumEquals {
        terms: &'static [&'static str],
        total: DecimalValue,
    },
    /// When the trigger matches, the required field must be present and truthy. Truthy is a
    /// closed typed predicate: boolean `true` or a non-zero integer/decimal.
    Requires {
        if_field: &'static str,
        equals: RuleValue,
        then_field: &'static str,
    },
    MutuallyExclusive {
        fields: &'static [&'static str],
    },
    /// Override the homogeneous value domain for one key in a closed map. The override must be a
    /// subset of the map's base value domain and is enforced for defaults and resolved values.
    MapEntryDomain {
        key: &'static str,
        domain: ScalarDomain,
    },
    /// At least one named numeric object field or closed-map key must be non-zero. Missing optional
    /// entries count as zero.
    AtLeastOneNonZero {
        fields: &'static [&'static str],
    },
    /// When the named field/map entry is present, it must equal the typed literal.
    Equals {
        field: &'static str,
        value: RuleValue,
    },
    /// Sum numeric values across independently owned families and reject the complete resolution
    /// when the result exceeds the named authority. The rule is attached to the limit family's
    /// schema; registry validation rejects a rule whose `limit.family` is not that owner.
    ResolvedSetSumLessOrEqual {
        rule_id: &'static str,
        terms: &'static [ResolvedValuePath],
        limit: ResolvedValuePath,
    },
    ExternalCeiling {
        field: &'static str,
        ceiling: ExternalCeiling,
        projection: ConstraintProjection,
        relation: ConstraintRelation,
        violation: ConstraintViolation,
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
    /// Version of this family's value shape. This is deliberately independent of
    /// [`crate::Family::schema_version`], which versions the family metadata envelope.
    pub version: u16,
    pub schema_id: &'static str,
    pub kind: ValueKind,
    pub domain: StructuredValueDomain,
    pub rules: &'static [CrossFieldRule],
}
