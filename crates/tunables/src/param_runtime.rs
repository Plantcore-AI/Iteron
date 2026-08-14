//! Applying tier-2 parameter overrides at the point a constant is read.
//!
//! The catalog makes eligible constants addressable. Addressable is not the same as applied: a
//! profile could carry a value for any of them and the runtime read the compiled constant anyway, which is
//! worse than refusing the value — an operator concludes the knob does not matter when in fact it
//! was never consulted.
//!
//! A `const` cannot read a runtime value, so applying an override means the *use site* has to ask.
//! This module is what it asks. The table is installed exactly once, before any work runs, and is
//! immutable afterwards: a parameter that could change mid-run would make the run's own evidence
//! unreproducible, and the profile digest recorded in the rollout would no longer describe what
//! actually executed.

use crate::params::{ParamClass, ParamUnit, ParamValueViolation};
use crate::{DecimalValue, ResolutionValue};
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

/// The installed overrides, or `None` when no profile supplied any.
static OVERRIDES: OnceLock<BTreeMap<String, ResolutionValue>> = OnceLock::new();
static FAMILY_OVERRIDES: OnceLock<BTreeMap<String, ResolutionValue>> = OnceLock::new();
static STRING_LISTS: OnceLock<Mutex<BTreeMap<String, &'static [&'static str]>>> = OnceLock::new();
static BYTE_LISTS: OnceLock<Mutex<BTreeMap<String, &'static [u8]>>> = OnceLock::new();
static PROMPT_ARTIFACTS: OnceLock<BTreeMap<String, String>> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamInstallError {
    /// Installed twice. The second caller would silently lose, so it is refused instead.
    AlreadyInstalled,
    UnknownParam(String),
    NotSettable(String),
    Domain {
        param: String,
        reason: String,
    },
    WrongType {
        param: String,
        reason: String,
    },
    DuplicateParam(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FamilyInstallError {
    AlreadyInstalled,
    UnknownFamily(String),
    SealedFamily(String),
    DuplicateFamily(String),
}

impl std::fmt::Display for FamilyInstallError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyInstalled => formatter
                .write_str("governed-family overrides were already installed for this process"),
            Self::UnknownFamily(id) => write!(formatter, "unknown tunable family `{id}`"),
            Self::SealedFamily(id) => write!(formatter, "tunable family `{id}` is Pin/read-only"),
            Self::DuplicateFamily(id) => {
                write!(formatter, "tunable family `{id}` is assigned twice")
            }
        }
    }
}

impl std::error::Error for FamilyInstallError {}

/// Install non-Pin Tier-1 candidates before any physical owner is constructed.
///
/// The pure resolver remains the type/domain/authority gate. This table exists so the owner it
/// samples and the later production use sites consult the same immutable candidate rather than a
/// compiled fallback while the resolver reports an override.
pub fn install_family_overrides(
    values: impl IntoIterator<Item = (String, ResolutionValue)>,
) -> Result<usize, FamilyInstallError> {
    let mut table = BTreeMap::new();
    for (id, value) in values {
        let family = crate::families()
            .iter()
            .find(|family| family.id == id || family.aliases.contains(&id.as_str()))
            .ok_or_else(|| FamilyInstallError::UnknownFamily(id.clone()))?;
        if !family.is_profile_addressable() {
            return Err(FamilyInstallError::SealedFamily(family.id.to_owned()));
        }
        if table.insert(family.id.to_owned(), value).is_some() {
            return Err(FamilyInstallError::DuplicateFamily(family.id.to_owned()));
        }
    }
    let installed = table.len();
    if installed > 0 {
        FAMILY_OVERRIDES
            .set(table)
            .map_err(|_| FamilyInstallError::AlreadyInstalled)?;
    }
    Ok(installed)
}

#[must_use]
pub fn family_value(id: &str) -> Option<&'static ResolutionValue> {
    let canonical = crate::families()
        .iter()
        .find(|family| family.id == id || family.aliases.contains(&id))?
        .id;
    FAMILY_OVERRIDES
        .get()
        .and_then(|table| table.get(canonical))
}

#[must_use]
pub fn family_bool(id: &str, compiled_default: bool) -> bool {
    match family_value(id) {
        Some(ResolutionValue::Boolean { value }) => *value,
        _ => compiled_default,
    }
}

#[must_use]
pub fn family_integer<T>(id: &str, compiled_default: T) -> T
where
    T: Copy + TryFrom<i64>,
{
    match family_value(id) {
        Some(ResolutionValue::Integer { value }) => T::try_from(*value).unwrap_or(compiled_default),
        _ => compiled_default,
    }
}

#[must_use]
pub fn family_enum(id: &str, compiled_default: &'static str) -> &'static str {
    match family_value(id) {
        Some(ResolutionValue::Enum { value }) => value.as_str(),
        _ => compiled_default,
    }
}

impl std::fmt::Display for ParamInstallError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyInstalled => formatter.write_str(
                "tier-2 parameter overrides were already installed for this process; installing \
                 twice would silently discard one of the two sets",
            ),
            Self::UnknownParam(id) => write!(formatter, "unknown parameter `{id}`"),
            Self::NotSettable(id) => write!(
                formatter,
                "parameter `{id}` is structural and is exposed read-only"
            ),
            Self::Domain { param, reason } => write!(formatter, "parameter `{param}`: {reason}"),
            Self::WrongType { param, reason } => write!(formatter, "parameter `{param}`: {reason}"),
            Self::DuplicateParam(id) => write!(formatter, "parameter `{id}` is assigned twice"),
        }
    }
}

impl std::error::Error for ParamInstallError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptArtifactInstallError {
    AlreadyInstalled,
    UnknownArtifact(String),
    NotOverridable(String),
    EmptyArtifact(String),
    ArtifactTooLarge { artifact: String, bytes: usize },
    DuplicateArtifact(String),
}

impl std::fmt::Display for PromptArtifactInstallError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyInstalled => formatter
                .write_str("prompt artifact overrides were already installed for this process"),
            Self::UnknownArtifact(id) => write!(formatter, "unknown prompt artifact `{id}`"),
            Self::NotOverridable(id) => {
                write!(
                    formatter,
                    "prompt artifact `{id}` has no runtime resolution site"
                )
            }
            Self::EmptyArtifact(id) => {
                write!(formatter, "prompt artifact `{id}` must not be blank")
            }
            Self::ArtifactTooLarge { artifact, bytes } => write!(
                formatter,
                "prompt artifact `{artifact}` is {bytes} bytes; maximum is {}",
                crate::MAX_ARTIFACT_TEXT_BYTES
            ),
            Self::DuplicateArtifact(id) => {
                write!(formatter, "prompt artifact `{id}` is assigned twice")
            }
        }
    }
}

impl std::error::Error for PromptArtifactInstallError {}

/// Install the model-visible prompt replacements once, before any registry or agent is built.
pub fn install_prompt_artifact_overrides(
    values: impl IntoIterator<Item = (String, String)>,
) -> Result<usize, PromptArtifactInstallError> {
    let mut table = BTreeMap::new();
    for (id, value) in values {
        let prompt_artifact = crate::PROMPT_ARTIFACTS
            .iter()
            .find(|artifact| artifact.id == id);
        let tool_artifact = crate::tool_text_artifact_by_id(&id);
        let overridable = prompt_artifact
            .map(|artifact| artifact.overridable)
            .or_else(|| tool_artifact.map(|artifact| artifact.overridable))
            .ok_or_else(|| PromptArtifactInstallError::UnknownArtifact(id.clone()))?;
        if !overridable {
            return Err(PromptArtifactInstallError::NotOverridable(id));
        }
        if value.trim().is_empty() {
            return Err(PromptArtifactInstallError::EmptyArtifact(id));
        }
        if value.len() > crate::MAX_ARTIFACT_TEXT_BYTES {
            return Err(PromptArtifactInstallError::ArtifactTooLarge {
                artifact: id,
                bytes: value.len(),
            });
        }
        if table.insert(id.clone(), value).is_some() {
            return Err(PromptArtifactInstallError::DuplicateArtifact(id));
        }
    }
    let count = table.len();
    PROMPT_ARTIFACTS
        .set(table)
        .map_err(|_| PromptArtifactInstallError::AlreadyInstalled)?;
    Ok(count)
}

/// Resolve one model-visible text artifact. Capabilities, tool names, schemas, and runtime policy
/// are not reachable through this function.
#[must_use]
pub fn prompt_artifact<'a>(id: &str, compiled_default: &'a str) -> &'a str {
    installed_artifact(id).unwrap_or(compiled_default)
}

fn installed_artifact(id: &str) -> Option<&'static str> {
    PROMPT_ARTIFACTS
        .get()
        .and_then(|table| table.get(id))
        .map(String::as_str)
}

/// Resolve one built-in tool's model-visible description.
///
/// An exact per-tool artifact wins over the legacy aggregate. Unknown names are external/dynamic
/// by definition and receive neither override, so MCP-provided descriptions remain untrusted
/// runtime input rather than silently entering Iteron's optimization namespace.
#[must_use]
pub fn tool_description<'a>(canonical_name: &str, compiled_default: &'a str) -> &'a str {
    let Some(artifact) = crate::tool_text_artifact(canonical_name) else {
        return compiled_default;
    };
    installed_artifact(artifact.id)
        .or_else(|| installed_artifact("prompt/tool_description@v1"))
        .unwrap_or(compiled_default)
}

/// Install the tier-2 overrides for this process.
///
/// Every entry is re-checked here even though the profile loader already validated it: this is the
/// boundary that the rest of the process trusts, and a boundary that trusts its caller is not a
/// boundary. Returns how many were installed.
pub fn install_param_overrides(
    values: impl IntoIterator<Item = (String, ResolutionValue)>,
) -> Result<usize, ParamInstallError> {
    let mut table = BTreeMap::new();
    for (id, value) in values {
        let param =
            crate::params::param(&id).ok_or_else(|| ParamInstallError::UnknownParam(id.clone()))?;
        if matches!(param.class, ParamClass::Structural) {
            return Err(ParamInstallError::NotSettable(id));
        }
        param
            .admits_value(&value)
            .map_err(|violation| match violation {
                ParamValueViolation::WrongType { .. } => ParamInstallError::WrongType {
                    param: id.clone(),
                    reason: violation.to_string(),
                },
                ParamValueViolation::Shape(_) => ParamInstallError::WrongType {
                    param: id.clone(),
                    reason: violation.to_string(),
                },
                ParamValueViolation::Domain(_) => ParamInstallError::Domain {
                    param: id.clone(),
                    reason: violation.to_string(),
                },
            })?;
        if table.insert(id.clone(), value).is_some() {
            return Err(ParamInstallError::DuplicateParam(id));
        }
    }
    let count = table.len();
    OVERRIDES
        .set(table)
        .map_err(|_| ParamInstallError::AlreadyInstalled)?;
    Ok(count)
}

/// Read an integral parameter: the override if one was installed, otherwise the compiled default.
///
/// The default is passed in rather than looked up so the call site stays readable at a glance and
/// so a build with no profile pays nothing but a pointer check.
#[must_use]
pub fn param_i128(id: &str, compiled_default: i128) -> i128 {
    param_integer(id, compiled_default)
}

/// Read any primitive integer parameter without losing the declaration's Rust type.
///
/// Conversion failure is a catalog/admission defect and therefore fails loudly. Falling back to
/// the compiled default after accepting an override would turn a bad candidate into a fake success.
#[must_use]
pub fn param_integer<T>(id: &str, compiled_default: T) -> T
where
    T: Copy + TryFrom<i64>,
{
    OVERRIDES
        .get()
        .and_then(|table| table.get(id))
        .and_then(|value| match value {
            ResolutionValue::Integer { value } => Some(*value),
            _ => None,
        })
        .map_or(compiled_default, |value| {
            T::try_from(value).unwrap_or_else(|_| {
                panic!(
                    "parameter `{id}` value {value} passed admission but does not fit its declared integer type"
                )
            })
        })
}

/// `usize` convenience. Saturates rather than wrapping: an override is bounded by its declared
/// clamp already, and a negative value here would be a catalog defect, not a caller error.
#[must_use]
pub fn param_usize(id: &str, compiled_default: usize) -> usize {
    param_integer(id, compiled_default)
}

/// `u64` convenience.
#[must_use]
pub fn param_u64(id: &str, compiled_default: u64) -> u64 {
    param_integer(id, compiled_default)
}

#[must_use]
pub fn param_bool(id: &str, compiled_default: bool) -> bool {
    OVERRIDES
        .get()
        .and_then(|table| table.get(id))
        .and_then(|value| match value {
            ResolutionValue::Boolean { value } => Some(*value),
            _ => None,
        })
        .unwrap_or(compiled_default)
}

#[must_use]
pub fn param_f64(id: &str, compiled_default: f64) -> f64 {
    OVERRIDES
        .get()
        .and_then(|table| table.get(id))
        .and_then(|value| match value {
            ResolutionValue::Decimal { value } => Some(decimal_f64(*value)),
            _ => None,
        })
        .unwrap_or(compiled_default)
}

#[must_use]
pub fn param_f32(id: &str, compiled_default: f32) -> f32 {
    param_f64(id, f64::from(compiled_default)) as f32
}

fn decimal_f64(value: DecimalValue) -> f64 {
    value.coefficient as f64 / 10_f64.powi(i32::from(value.scale))
}

#[must_use]
pub fn param_duration(id: &str, compiled_default: std::time::Duration) -> std::time::Duration {
    let Some(value) =
        OVERRIDES
            .get()
            .and_then(|table| table.get(id))
            .and_then(|value| match value {
                ResolutionValue::Integer { value } => u64::try_from(*value).ok(),
                _ => None,
            })
    else {
        return compiled_default;
    };
    match crate::param(id).and_then(|param| param.unit) {
        Some(ParamUnit::Nanoseconds) => std::time::Duration::from_nanos(value),
        Some(ParamUnit::Microseconds) => std::time::Duration::from_micros(value),
        Some(ParamUnit::Milliseconds) => std::time::Duration::from_millis(value),
        Some(ParamUnit::Seconds) => std::time::Duration::from_secs(value),
        None => panic!("duration parameter `{id}` has no declared unit"),
    }
}

#[must_use]
pub fn param_str(id: &str, compiled_default: &'static str) -> &'static str {
    OVERRIDES
        .get()
        .and_then(|table| table.get(id))
        .and_then(|value| match value {
            ResolutionValue::Text { value } => Some(value.as_str()),
            _ => None,
        })
        .unwrap_or(compiled_default)
}

/// Read an enum parameter as its exact published variant spelling.
#[must_use]
pub fn param_enum(id: &str, compiled_default: &'static str) -> &'static str {
    OVERRIDES
        .get()
        .and_then(|table| table.get(id))
        .and_then(|value| match value {
            ResolutionValue::Enum { value } => Some(value.as_str()),
            _ => None,
        })
        .unwrap_or(compiled_default)
}

/// Read a heterogeneous list in its admitted, immutable runtime representation.
#[must_use]
pub fn param_list<'a>(id: &str, compiled_default: &'a [ResolutionValue]) -> &'a [ResolutionValue] {
    OVERRIDES
        .get()
        .and_then(|table| table.get(id))
        .and_then(|value| match value {
            ResolutionValue::List { items } => Some(items.as_slice()),
            _ => None,
        })
        .unwrap_or(compiled_default)
}

/// Read a map in its admitted, immutable runtime representation.
#[must_use]
pub fn param_map<'a>(
    id: &str,
    compiled_default: &'a BTreeMap<String, ResolutionValue>,
) -> &'a BTreeMap<String, ResolutionValue> {
    OVERRIDES
        .get()
        .and_then(|table| table.get(id))
        .and_then(|value| match value {
            ResolutionValue::Map { entries } => Some(entries),
            _ => None,
        })
        .unwrap_or(compiled_default)
}

/// Read an object in its admitted, immutable runtime representation.
#[must_use]
pub fn param_object<'a>(
    id: &str,
    compiled_default: &'a BTreeMap<String, ResolutionValue>,
) -> &'a BTreeMap<String, ResolutionValue> {
    OVERRIDES
        .get()
        .and_then(|table| table.get(id))
        .and_then(|value| match value {
            ResolutionValue::Object { fields } => Some(fields),
            _ => None,
        })
        .unwrap_or(compiled_default)
}

#[must_use]
pub fn param_char(id: &str, compiled_default: char) -> char {
    OVERRIDES
        .get()
        .and_then(|table| table.get(id))
        .and_then(|value| match value {
            ResolutionValue::Text { value } => {
                let mut chars = value.chars();
                let first = chars.next()?;
                chars.next().is_none().then_some(first)
            }
            _ => None,
        })
        .unwrap_or(compiled_default)
}

/// Read a list of UTF-8 strings without copying it on every use.
///
/// Overrides are immutable for the life of the process. The small projected slice is therefore
/// allocated once and deliberately lives for that same process lifetime; subsequent reads return
/// the cached slice. Admission has already proved every item is text.
#[must_use]
pub fn param_str_list(
    id: &str,
    compiled_default: &'static [&'static str],
) -> &'static [&'static str] {
    let Some(ResolutionValue::List { items }) = param_value(id) else {
        return compiled_default;
    };
    let cache = STRING_LISTS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut cache = cache
        .lock()
        .expect("parameter string-list projection lock is poisoned");
    if let Some(projected) = cache.get(id) {
        return projected;
    }
    let projected = items
        .iter()
        .map(|item| match item {
            ResolutionValue::Text { value } => value.as_str(),
            _ => panic!("parameter `{id}` passed list admission with a non-text item"),
        })
        .collect::<Vec<_>>();
    let projected = Box::leak(projected.into_boxed_slice());
    cache.insert(id.to_owned(), projected);
    projected
}

/// Read a byte list without repeatedly allocating its owned runtime representation.
#[must_use]
pub fn param_bytes(id: &str, compiled_default: &'static [u8]) -> &'static [u8] {
    let Some(ResolutionValue::List { items }) = param_value(id) else {
        return compiled_default;
    };
    let cache = BYTE_LISTS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut cache = cache
        .lock()
        .expect("parameter byte-list projection lock is poisoned");
    if let Some(projected) = cache.get(id) {
        return projected;
    }
    let projected = items
        .iter()
        .map(|item| match item {
            ResolutionValue::Integer { value } => u8::try_from(*value).unwrap_or_else(|_| {
                panic!("parameter `{id}` passed byte-list admission with out-of-range item {value}")
            }),
            _ => panic!("parameter `{id}` passed byte-list admission with a non-integer item"),
        })
        .collect::<Vec<_>>();
    let projected = Box::leak(projected.into_boxed_slice());
    cache.insert(id.to_owned(), projected);
    projected
}

/// The exact installed value for a specialized runtime projection.
///
/// Most call sites should use a typed helper above. This read-only escape hatch exists for the two
/// genuinely optimizable composite constants whose Rust shapes cannot be expressed by a generic
/// primitive helper (the syntax-highlighter fallback and ANSI palette).
#[must_use]
pub fn param_value(id: &str) -> Option<&'static ResolutionValue> {
    OVERRIDES.get().and_then(|table| table.get(id))
}

/// Whether any override is installed for this id. Used by the export to report, honestly, which
/// parameters a profile can actually move today.
#[must_use]
pub fn param_is_overridden(id: &str) -> bool {
    OVERRIDES.get().is_some_and(|table| table.contains_key(id))
}

/// How many overrides are installed. Zero when no profile carried any.
#[must_use]
pub fn installed_param_count() -> usize {
    OVERRIDES.get().map_or(0, BTreeMap::len)
}

#[must_use]
pub fn installed_prompt_artifact_count() -> usize {
    PROMPT_ARTIFACTS.get().map_or(0, BTreeMap::len)
}
