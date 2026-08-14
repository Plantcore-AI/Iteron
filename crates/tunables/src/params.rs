//! Tier-2 exposed parameters.
//!
//! The 160-entry family registry carries nineteen fields per entry and is hand-authored. That is
//! the right cost for a control that the evolution plane may *promote*, and the wrong cost for the
//! much larger compiled-constant surface that shapes behaviour: hand-authoring those would not
//! be a larger version of the same job, and it would multiply the surface every schema-compat
//! fixture has to freeze by an order of magnitude.
//!
//! So there are two tiers. Tier 1 is [`crate::families`]: governed, promotable, hand-authored.
//! Tier 2 is this module: harvested from the source declarations by
//! `cargo run -p iteron-xtask -- tunables generate-params`, addressable by a profile, and
//! **never promotable** — a tier-2 parameter must be lifted into tier 1 before the evolution plane
//! may change it. That asymmetry is what lets the whole surface be exposed without widening what a
//! learned strategy is allowed to touch.
//!
//! The catalog is embedded as JSON rather than generated Rust. Thousands of generated items
//! would be paid for on every build of this crate; the JSON is parsed once, on demand.

use crate::modules::ModuleId;
use crate::resolution_types::ResolutionValue;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// The generated catalog. Regenerate with `xtask tunables generate-params`; the drift test in
/// `xtask` fails when this file and the source declarations disagree.
const PARAMS_JSON: &str = include_str!("../../../governance/tunables-params.json");

/// What an outside caller is allowed to do with a parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamClass {
    /// Free to move inside its declared domain. An optimizer may search it.
    Searchable,
    /// A safety bound. It may be *tightened* freely and *loosened* only up to a declared ceiling,
    /// so exposing it cannot make the system less bounded than it was.
    Bounded,
    /// Identity, protocol version, digest, wire name. Exposed read-only; never settable.
    Structural,
}

/// The value shape, as declared at the definition site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamType {
    Integer,
    Float,
    Boolean,
    Text,
    Enum,
    Array,
    Map,
    Object,
    Duration,
}

/// Syntax-level declaration kind recorded by the authoritative source census.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamCandidateKind {
    Const,
    Static,
    AssociatedConst,
}

/// Reviewed disposition of a production optimization candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamDisposition {
    RuntimeSettable,
    InvariantReadOnly,
}

/// Closed reason vocabulary for parameters which must remain read-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamInvariantReason {
    Identity,
    WireCompatibility,
    CapabilityAuthority,
    Security,
    DurabilityReplay,
    HardBudgetEffectLedger,
    RuntimeStateNotAValue,
}

/// Exact production owner named by the generated census.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParamOwner {
    pub krate: String,
    pub path: String,
    pub symbol: String,
}

/// One syntax-proven production read of a parameter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParamUseSite {
    pub path: String,
    pub line: usize,
    pub evidence: String,
}

/// Unit used by an integral duration override. It is derived from the declaration constructor and
/// published so a harness never has to guess whether `5` means milliseconds or seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamUnit {
    Nanoseconds,
    Microseconds,
    Milliseconds,
    Seconds,
}

impl ParamType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Integer => "integer",
            Self::Float => "float",
            Self::Boolean => "boolean",
            Self::Text => "text",
            Self::Enum => "enum",
            Self::Array => "array",
            Self::Map => "map",
            Self::Object => "object",
            Self::Duration => "duration",
        }
    }
}

/// The admissible range. `min`/`max` are inclusive; absent means unbounded on that side, which is
/// only legal for `Searchable` and `Structural` — a `Bounded` parameter without a ceiling would be
/// a safety bound that no longer bounds anything, and the generator refuses to emit one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ParamDomain {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<i128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<i128>,
}

/// One exposed parameter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Param {
    /// Stable addressing identity, `<crate>.<module-path>.<lower_snake_const>`.
    pub id: String,
    pub module: ModuleId,
    pub class: ParamClass,
    #[serde(rename = "type")]
    pub ty: ParamType,
    /// Exact Rust declaration type. The coarse `type` drives profile shape; this field preserves
    /// signed width, array element type and concrete object identity for a research harness.
    pub rust_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<ParamUnit>,
    /// The declared default, rendered exactly as written in source.
    pub default: String,
    #[serde(default)]
    pub domain: ParamDomain,
    /// Owning crate, for grouping and for the per-crate census.
    pub krate: String,
    /// Declaration site, so a reader can go straight to the source of truth.
    pub decl: String,
    /// Whether a use site actually consults the override table for this parameter.
    ///
    /// This diagnostic field makes drift visible in exports. The checked-in exposure gate requires
    /// every settable parameter to be applied, so a release cannot advertise an inert value.
    #[serde(default)]
    pub applied: bool,
    pub candidate_kind: ParamCandidateKind,
    pub disposition: ParamDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invariant_reason: Option<ParamInvariantReason>,
    pub owner: ParamOwner,
    pub use_sites: Vec<ParamUseSite>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behavior_oracle: Option<String>,
}

impl Param {
    /// Whether a profile may carry a value for this parameter. `Structural` never may.
    pub fn is_settable(&self) -> bool {
        !matches!(self.class, ParamClass::Structural)
    }

    /// Check a candidate integer against the declared domain. Returns the reason on refusal, so
    /// the caller can name it rather than reporting a bare failure.
    pub fn admits_integer(&self, value: i128) -> Result<(), ParamDomainViolation> {
        if let Some(min) = self.domain.min
            && value < min
        {
            return Err(ParamDomainViolation::BelowMinimum { min, value });
        }
        if let Some(max) = self.domain.max
            && value > max
        {
            return Err(ParamDomainViolation::AboveClamp { max, value });
        }
        Ok(())
    }

    /// Validate the typed value at both profile admission and runtime installation boundaries.
    /// Keeping the rule here prevents either boundary from accepting a value the other drops.
    pub fn admits_value(&self, value: &ResolutionValue) -> Result<(), ParamValueViolation> {
        let type_matches = matches!(
            (self.ty, value),
            (ParamType::Integer, ResolutionValue::Integer { .. })
                | (ParamType::Float, ResolutionValue::Decimal { .. })
                | (ParamType::Boolean, ResolutionValue::Boolean { .. })
                | (ParamType::Text, ResolutionValue::Text { .. })
                | (ParamType::Enum, ResolutionValue::Enum { .. })
                | (ParamType::Array, ResolutionValue::List { .. })
                | (ParamType::Map, ResolutionValue::Map { .. })
                | (ParamType::Object, ResolutionValue::Object { .. })
                | (ParamType::Duration, ResolutionValue::Integer { .. })
        );
        if !type_matches {
            return Err(ParamValueViolation::WrongType {
                expected: self.ty,
                actual: resolution_value_type(value),
            });
        }
        if let ResolutionValue::Integer { value } = value {
            self.admits_integer(i128::from(*value))
                .map_err(ParamValueViolation::Domain)?;
        }
        if let ResolutionValue::List { items } = value {
            self.admits_list(items)?;
        }
        if let ResolutionValue::Object { fields } = value
            && self.rust_type.trim() == "LangSpec"
        {
            admits_lang_spec(fields)?;
        }
        Ok(())
    }

    fn admits_list(&self, items: &[ResolutionValue]) -> Result<(), ParamValueViolation> {
        if self.id == "cli.theme.capabilities.ansi16" {
            if items.len() != 16 || items.iter().any(|item| !is_ansi_color_entry(item)) {
                return Err(ParamValueViolation::Shape(
                    "expected 16 objects with `color` text and byte-valued `r`, `g`, `b` fields",
                ));
            }
            return Ok(());
        }
        if let Some(length) = fixed_array_length(&self.rust_type)
            && items.len() != length
        {
            return Err(ParamValueViolation::Shape(
                "list length does not match the declared fixed Rust array length",
            ));
        }
        if self.rust_type.contains("str")
            && items
                .iter()
                .any(|item| !matches!(item, ResolutionValue::Text { .. }))
        {
            return Err(ParamValueViolation::Shape(
                "expected every list item to be text",
            ));
        }
        if self.rust_type.contains("u8")
            && items.iter().any(|item| {
                !matches!(item, ResolutionValue::Integer { value } if u8::try_from(*value).is_ok())
            })
        {
            return Err(ParamValueViolation::Shape(
                "expected every list item to be an integer from 0 through 255",
            ));
        }
        Ok(())
    }
}

fn fixed_array_length(rust_type: &str) -> Option<usize> {
    let (_, suffix) = rust_type.rsplit_once(';')?;
    suffix
        .trim()
        .strip_suffix(']')?
        .trim()
        .parse::<usize>()
        .ok()
}

fn is_ansi_color_entry(value: &ResolutionValue) -> bool {
    let ResolutionValue::Object { fields } = value else {
        return false;
    };
    fields.len() == 4
        && matches!(fields.get("color"), Some(ResolutionValue::Text { value }) if ansi_color(value))
        && ["r", "g", "b"].into_iter().all(|field| {
            matches!(fields.get(field), Some(ResolutionValue::Integer { value }) if u8::try_from(*value).is_ok())
        })
}

fn ansi_color(value: &str) -> bool {
    matches!(
        value,
        "black"
            | "red"
            | "green"
            | "yellow"
            | "blue"
            | "magenta"
            | "cyan"
            | "gray"
            | "dark_gray"
            | "light_red"
            | "light_green"
            | "light_yellow"
            | "light_blue"
            | "light_magenta"
            | "light_cyan"
            | "white"
    )
}

fn admits_lang_spec(
    fields: &std::collections::BTreeMap<String, ResolutionValue>,
) -> Result<(), ParamValueViolation> {
    const EXPECTED: [&str; 7] = [
        "block",
        "keywords",
        "line_comments",
        "nest_block",
        "strings",
        "triple",
        "types_capitalized",
    ];
    if fields.len() != EXPECTED.len()
        || EXPECTED
            .into_iter()
            .any(|field| !fields.contains_key(field))
    {
        return Err(ParamValueViolation::Shape(
            "LangSpec requires exactly block, keywords, line_comments, nest_block, strings, triple, and types_capitalized",
        ));
    }
    for field in ["line_comments", "keywords"] {
        if !matches!(fields.get(field), Some(ResolutionValue::List { items }) if items.iter().all(|item| matches!(item, ResolutionValue::Text { .. })))
        {
            return Err(ParamValueViolation::Shape(
                "LangSpec line_comments and keywords must be text lists",
            ));
        }
    }
    if !matches!(fields.get("block"), Some(ResolutionValue::List { items }) if (items.is_empty() || items.len() == 2) && items.iter().all(|item| matches!(item, ResolutionValue::Text { .. })))
    {
        return Err(ParamValueViolation::Shape(
            "LangSpec block must be an empty or two-item text list",
        ));
    }
    if !matches!(fields.get("strings"), Some(ResolutionValue::List { items }) if items.iter().all(|item| matches!(item, ResolutionValue::Text { value } if value.chars().count() == 1)))
    {
        return Err(ParamValueViolation::Shape(
            "LangSpec strings must be a list of one-character text values",
        ));
    }
    if ["nest_block", "triple", "types_capitalized"]
        .into_iter()
        .any(|field| !matches!(fields.get(field), Some(ResolutionValue::Boolean { .. })))
    {
        return Err(ParamValueViolation::Shape(
            "LangSpec nest_block, triple, and types_capitalized must be boolean",
        ));
    }
    Ok(())
}

fn resolution_value_type(value: &ResolutionValue) -> &'static str {
    match value {
        ResolutionValue::Boolean { .. } => "boolean",
        ResolutionValue::Integer { .. } => "integer",
        ResolutionValue::Decimal { .. } => "decimal",
        ResolutionValue::Text { .. } => "text",
        ResolutionValue::Enum { .. } => "enum",
        ResolutionValue::List { .. } => "list",
        ResolutionValue::Map { .. } => "map",
        ResolutionValue::Object { .. } => "object",
        ResolutionValue::CatalogRef { .. } => "catalog_ref",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamValueViolation {
    WrongType {
        expected: ParamType,
        actual: &'static str,
    },
    Domain(ParamDomainViolation),
    Shape(&'static str),
}

impl std::fmt::Display for ParamValueViolation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongType { expected, actual } => write!(
                formatter,
                "expected parameter type {}, got {actual}",
                expected.as_str()
            ),
            Self::Domain(violation) => violation.fmt(formatter),
            Self::Shape(reason) => formatter.write_str(reason),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamDomainViolation {
    BelowMinimum { min: i128, value: i128 },
    AboveClamp { max: i128, value: i128 },
}

impl std::fmt::Display for ParamDomainViolation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BelowMinimum { min, value } => {
                write!(
                    formatter,
                    "value {value} is below the declared minimum {min}"
                )
            }
            Self::AboveClamp { max, value } => write!(
                formatter,
                "value {value} exceeds the declared clamp {max}; a bounded parameter may be \
                 tightened but not loosened past its ceiling"
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParamCatalog {
    schema_version: u16,
    registry_id: String,
    revision: u16,
    params: Vec<Param>,
}

/// Schema version of the tier-2 catalog document.
pub const PARAM_SCHEMA_VERSION: u16 = 3;
/// Logical identity of the tier-2 registry, distinct from the family registry.
pub const PARAM_REGISTRY_ID: &str = "iteron-params";

fn catalog() -> &'static ParamCatalog {
    static CATALOG: OnceLock<ParamCatalog> = OnceLock::new();
    CATALOG.get_or_init(|| {
        serde_json::from_str(crate::param_str("tunables.params.params_json", PARAMS_JSON))
            .expect("embedded tier-2 parameter catalog is valid")
    })
}

/// Every exposed parameter, sorted by id. The order is part of the digest, so it is stable.
pub fn params() -> &'static [Param] {
    &catalog().params
}

/// Look one up by its addressing id.
pub fn param(id: &str) -> Option<&'static Param> {
    params().iter().find(|param| param.id == id)
}

/// Digest over the exact catalog bytes. A profile pins this the way it pins the family registry
/// digest, so a candidate computed against one catalog cannot be silently applied to another.
pub fn param_registry_digest_sha256() -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(
        crate::param_str("tunables.params.params_json", PARAMS_JSON).as_bytes(),
    ))
}

/// Count of exposed parameters.
pub fn param_count() -> usize {
    params().len()
}
