//! Tier-2 exposed parameters.
//!
//! The 160-entry family registry carries nineteen fields per entry and is hand-authored. That is
//! the right cost for a control that the evolution plane may *promote*, and the wrong cost for the
//! roughly 1,670 remaining compiled constants that shape behaviour: hand-authoring those would not
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
//! The catalog is embedded as JSON rather than generated Rust. Sixteen hundred generated items
//! would be paid for on every build of this crate; the JSON is parsed once, on demand.

use crate::modules::ModuleId;
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
    Array,
    Duration,
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
    /// The declared default, rendered exactly as written in source.
    pub default: String,
    #[serde(default)]
    pub domain: ParamDomain,
    /// Owning crate, for grouping and for the per-crate census.
    pub krate: String,
    /// Declaration site, so a reader can go straight to the source of truth.
    pub decl: String,
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
pub const PARAM_SCHEMA_VERSION: u16 = 1;
/// Logical identity of the tier-2 registry, distinct from the family registry.
pub const PARAM_REGISTRY_ID: &str = "iteron-params";

fn catalog() -> &'static ParamCatalog {
    static CATALOG: OnceLock<ParamCatalog> = OnceLock::new();
    CATALOG.get_or_init(|| {
        serde_json::from_str(PARAMS_JSON).expect("embedded tier-2 parameter catalog is valid")
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
    hex::encode(sha2::Sha256::digest(PARAMS_JSON.as_bytes()))
}

/// Count of exposed parameters.
pub fn param_count() -> usize {
    params().len()
}
