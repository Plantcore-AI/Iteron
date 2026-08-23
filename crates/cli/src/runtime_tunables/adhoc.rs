//! Ad-hoc tuning: the human loop.
//!
//! The profile channel was built for a machine that must prove what it changed — digest-pinned,
//! fail-closed, reproducible on another host. Every one of those properties is friction for someone
//! who wants to move one knob and see what happens, and the result was a six-step loop to change a
//! single integer.
//!
//! This module is the short path. It is deliberately *not* a second set of rules: an ad-hoc
//! override is turned into the same [`ProfileDocument`] the pinned path builds, and goes through
//! the identical validation. What differs is only how the document is obtained and whether its
//! bytes are pinned — and an unpinned document says so out loud, because a run whose inputs cannot
//! be reconstructed must not look like one whose inputs can.

use anyhow::{Context, Result, anyhow, bail};
use iteron_tunables::{
    DecimalValue, Param, ParamAssignment, ParamType, ProfileDocument, ProfileValue,
    ResolutionValue, SourceKind,
};
use std::path::Path;

/// Where a document came from, which decides whether pinning is meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProfileOrigin {
    /// Read from a file whose SHA-256 the caller pinned.
    PinnedFile,
    /// Read from stdin, an inline argument, or assembled from `--set`. There are no prior bytes to
    /// pin: the caller produced them in the same breath as the claim about them.
    Unpinned,
}

impl ProfileOrigin {
    pub(crate) const fn is_pinned(self) -> bool {
        matches!(self, Self::PinnedFile)
    }
}

/// Read a profile document from a path, `-` for stdin, or inline JSON.
///
/// The digest is required for a real file and refused as meaningless for the other two: you cannot
/// pin bytes you are producing at the same moment, and demanding a hash of them is ceremony rather
/// than safety.
pub(crate) fn load(
    path: Option<&Path>,
    inline: Option<&str>,
    digest: Option<&str>,
) -> Result<Option<(ProfileDocument, ProfileOrigin)>> {
    let (bytes, origin) = match (path, inline) {
        (Some(_), Some(_)) => {
            bail!("--tunables-profile and --tunables-profile-json are alternatives; pass one")
        }
        (Some(path), None) if path == Path::new("-") => {
            let mut buffer = Vec::new();
            std::io::Read::read_to_end(&mut std::io::stdin().lock(), &mut buffer)
                .context("reading the tunables profile from stdin")?;
            (buffer, ProfileOrigin::Unpinned)
        }
        (Some(path), None) => {
            let bytes = std::fs::read(path)
                .map_err(|error| anyhow!("reading tunables profile {}: {error}", path.display()))?;
            let digest = digest.ok_or_else(|| {
                anyhow!(
                    "--tunables-profile-digest is required for a profile read from a file: a \
                     candidate that can be edited between digesting and applying is not pinned to \
                     anything. Pass the profile on stdin (`-`) or via --tunables-profile-json for \
                     an explicitly unpinned ad-hoc run."
                )
            })?;
            let document = iteron_tunables::load_profile(&bytes, digest)
                .map_err(|error| anyhow!("tunables profile refused: {error}"))?;
            return Ok(Some((document, ProfileOrigin::PinnedFile)));
        }
        (None, Some(inline)) => (inline.as_bytes().to_vec(), ProfileOrigin::Unpinned),
        (None, None) => return Ok(None),
    };

    if digest.is_some() {
        bail!(
            "--tunables-profile-digest cannot pin a profile supplied on stdin or inline: those \
             bytes have no prior existence to pin to. Drop the flag, or write the profile to a \
             file first."
        );
    }
    if bytes.len() > iteron_tunables::MAX_PROFILE_BYTES {
        bail!(
            "profile document is {} bytes, over the {}-byte bound",
            bytes.len(),
            iteron_tunables::MAX_PROFILE_BYTES
        );
    }
    let document: ProfileDocument = serde_json::from_slice(&bytes)
        .map_err(|error| anyhow!("tunables profile is malformed: {error}"))?;
    iteron_tunables::validate_profile(&document)
        .map_err(|error| anyhow!("tunables profile refused: {error}"))?;
    Ok(Some((document, origin)))
}

/// Fold `--set key=value` assignments into a document, creating one if no profile was supplied.
///
/// `key` is a family id, a semantic key, a registered alias, or a tier-2 parameter id. The source
/// kind is inferred from the family's own declared bindings rather than demanded from the caller:
/// requiring an operator to know that `compaction_trigger` wants `user_config` is exactly the kind
/// of lookup that made the old loop six steps long.
pub(crate) fn apply_set_arguments(
    document: Option<ProfileDocument>,
    assignments: &[String],
) -> Result<Option<ProfileDocument>> {
    if assignments.is_empty() {
        return Ok(document);
    }
    let mut document = document.unwrap_or_else(empty_document);
    for assignment in assignments {
        let (key, raw) = assignment
            .split_once('=')
            .ok_or_else(|| anyhow!("--set expects `key=value`, got `{assignment}`"))?;
        let key = key.trim();
        let raw = raw.trim();
        if let Some(family) = resolve_family(key) {
            let source = profile_source(family).ok_or_else(|| {
                anyhow!(
                    "`{}` cannot be set by a profile: it declares no user_config or project_config \
                     binding. `iteron tunables export --format table` marks which families can.",
                    family.id
                )
            })?;
            document.values.push(ProfileValue {
                family: family.id.to_owned(),
                as_declared_source: source,
                value: parse_value(raw)?,
            });
        } else if let Some(param) = iteron_tunables::param(key) {
            document.params.push(ParamAssignment {
                param: key.to_owned(),
                value: parse_param_value(param, raw)?,
            });
        } else {
            bail!(
                "`{key}` is neither a tunable family nor an exposed parameter. Try \
                 `iteron tunables export --format table --filter {key}`."
            );
        }
    }
    iteron_tunables::validate_profile(&document)
        .map_err(|error| anyhow!("--set produced an invalid profile: {error}"))?;
    Ok(Some(document))
}

fn empty_document() -> ProfileDocument {
    ProfileDocument {
        schema_version: iteron_tunables::PROFILE_DOCUMENT_SCHEMA_VERSION,
        profile_id: "adhoc/--set".to_owned(),
        registry_revision: iteron_tunables::REGISTRY_REVISION,
        registry_digest: iteron_tunables::REGISTRY_DIGEST_SHA256.to_owned(),
        param_registry_digest: None,
        module_scope: None,
        values: Vec::new(),
        params: Vec::new(),
        artifacts: Vec::new(),
    }
}

fn resolve_family(key: &str) -> Option<&'static iteron_tunables::Family> {
    iteron_tunables::families().iter().find(|family| {
        family.id == key || family.semantic_key == key || family.aliases.contains(&key)
    })
}

fn profile_source(family: &iteron_tunables::Family) -> Option<SourceKind> {
    // Prefer project config when both are declared: an ad-hoc experiment belongs to the repository
    // being worked on, not to the operator's global configuration.
    let kinds: Vec<SourceKind> = family
        .source
        .bindings
        .iter()
        .map(|binding| binding.kind)
        .collect();
    kinds
        .iter()
        .copied()
        .find(|kind| matches!(kind, SourceKind::ProjectConfig))
        .or_else(|| {
            kinds
                .iter()
                .copied()
                .find(|kind| matches!(kind, SourceKind::UserConfig))
        })
}

/// Parse a `--set` right-hand side into a typed value.
///
/// Deliberately narrow: integers, booleans, and anything that parses as JSON. A bare word becomes
/// an enum, which is what the overwhelming majority of non-numeric families take. Guessing more
/// than this would turn a typo into a silently different value.
fn parse_value(raw: &str) -> Result<ResolutionValue> {
    if let Ok(value) = raw.parse::<i64>() {
        return Ok(ResolutionValue::Integer { value });
    }
    if let Ok(value) = raw.parse::<bool>() {
        return Ok(ResolutionValue::Boolean { value });
    }
    if raw.starts_with('{') || raw.starts_with('[') || raw.starts_with('"') {
        if let Ok(value) = serde_json::from_str::<ResolutionValue>(raw) {
            return Ok(value);
        }
        let value: serde_json::Value = serde_json::from_str(raw)
            .map_err(|error| anyhow!("`{raw}` is not a valid tunable value: {error}"))?;
        return json_value_to_resolution(value);
    }
    Ok(ResolutionValue::Enum {
        value: raw.to_owned(),
    })
}

fn parse_param_value(param: &Param, raw: &str) -> Result<ResolutionValue> {
    let invalid = |expected: &str| {
        anyhow!(
            "parameter `{}` expects {expected}, but `{raw}` cannot be parsed as {expected}",
            param.id
        )
    };
    match param.ty {
        ParamType::Integer | ParamType::Duration => raw
            .parse::<i64>()
            .map(|value| ResolutionValue::Integer { value })
            .map_err(|_| invalid(param.ty.as_str())),
        ParamType::Float => parse_decimal(raw)
            .map(|value| ResolutionValue::Decimal { value })
            .ok_or_else(|| invalid("a finite decimal")),
        ParamType::Boolean => raw
            .parse::<bool>()
            .map(|value| ResolutionValue::Boolean { value })
            .map_err(|_| invalid("boolean (`true` or `false`)")),
        ParamType::Text => {
            let value = if raw.starts_with('"') {
                serde_json::from_str::<String>(raw).map_err(|_| invalid("text"))?
            } else {
                raw.to_owned()
            };
            Ok(ResolutionValue::Text { value })
        }
        ParamType::Enum => Ok(ResolutionValue::Enum {
            value: raw.to_owned(),
        }),
        ParamType::Array => {
            let value: serde_json::Value =
                serde_json::from_str(raw).map_err(|_| invalid("a JSON array"))?;
            if !value.is_array() {
                return Err(invalid("a JSON array"));
            }
            json_value_to_resolution(value)
        }
        ParamType::Map => {
            let value: serde_json::Value =
                serde_json::from_str(raw).map_err(|_| invalid("a JSON map"))?;
            let serde_json::Value::Object(fields) = value else {
                return Err(invalid("a JSON map"));
            };
            Ok(ResolutionValue::Map {
                entries: fields
                    .into_iter()
                    .map(|(key, value)| Ok((key, json_value_to_resolution(value)?)))
                    .collect::<Result<_>>()?,
            })
        }
        ParamType::Object => {
            let value: serde_json::Value =
                serde_json::from_str(raw).map_err(|_| invalid("a JSON object"))?;
            if !value.is_object() {
                return Err(invalid("a JSON object"));
            }
            json_value_to_resolution(value)
        }
    }
}

fn parse_decimal(raw: &str) -> Option<DecimalValue> {
    let (significand, exponent) = match raw.split_once(['e', 'E']) {
        Some((significand, exponent)) => (significand, exponent.parse::<i32>().ok()?),
        None => (raw, 0_i32),
    };
    let negative = significand.starts_with('-');
    let unsigned = significand.strip_prefix(['-', '+']).unwrap_or(significand);
    let (whole, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    if (whole.is_empty() && fraction.is_empty())
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let digits = format!("{whole}{fraction}");
    let mut coefficient = digits.parse::<i128>().ok()?;
    if negative {
        coefficient = -coefficient;
    }
    let scale = i32::try_from(fraction.len()).ok()?.checked_sub(exponent)?;
    let mut scale = if scale < 0 {
        coefficient = coefficient.checked_mul(10_i128.checked_pow(scale.unsigned_abs())?)?;
        0
    } else {
        u8::try_from(scale).ok()?
    };
    while scale > 0 && coefficient % 10 == 0 {
        coefficient /= 10;
        scale -= 1;
    }
    Some(DecimalValue {
        coefficient: i64::try_from(coefficient).ok()?,
        scale,
    })
}

fn json_value_to_resolution(value: serde_json::Value) -> Result<ResolutionValue> {
    Ok(match value {
        serde_json::Value::Null => bail!("null is not a valid tunable value"),
        serde_json::Value::Bool(value) => ResolutionValue::Boolean { value },
        serde_json::Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                ResolutionValue::Integer { value }
            } else {
                ResolutionValue::Decimal {
                    value: parse_decimal(&value.to_string()).ok_or_else(|| {
                        anyhow!("JSON number `{value}` is outside the exact decimal range")
                    })?,
                }
            }
        }
        serde_json::Value::String(value) => ResolutionValue::Text { value },
        serde_json::Value::Array(items) => ResolutionValue::List {
            items: items
                .into_iter()
                .map(json_value_to_resolution)
                .collect::<Result<Vec<_>>>()?,
        },
        serde_json::Value::Object(fields) => ResolutionValue::Object {
            fields: fields
                .into_iter()
                .map(|(key, value)| Ok((key, json_value_to_resolution(value)?)))
                .collect::<Result<_>>()?,
        },
    })
}

/// Render what a profile will change, so an operator can see the effect before spending a run.
///
/// The column that matters is `applied`. The checked-in exposure gate requires every settable
/// tier-2 parameter to print `YES`; the explicit negative diagnostic remains so a stale or
/// independently produced catalog cannot hide an accepted-but-inert assignment.
pub(crate) fn render_effect(document: &ProfileDocument) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "profile `{}` — {} family value(s), {} parameter(s), {} artifact(s)\n",
        document.profile_id,
        document.values.len(),
        document.params.len(),
        document.artifacts.len()
    ));
    if !document.values.is_empty() {
        out.push_str("\nFAMILIES (tier 1 — always applied)\n");
        for value in &document.values {
            out.push_str(&format!(
                "  {:<44} <- {:?}  via {:?}\n",
                value.family, value.value, value.as_declared_source
            ));
        }
    }
    if !document.params.is_empty() {
        out.push_str("\nPARAMETERS (tier 2)\n");
        for assignment in &document.params {
            let param = iteron_tunables::param(&assignment.param);
            let applied = param.is_some_and(|param| param.applied);
            out.push_str(&format!(
                "  {:<44} <- {:?}  default {}  applied {}\n",
                assignment.param,
                assignment.value,
                param.map_or("?", |param| param.default.as_str()),
                if applied {
                    "YES"
                } else {
                    "NO  <- inert: no use site reads this yet"
                }
            ));
        }
    }
    if !document.artifacts.is_empty() {
        out.push_str("\nPROMPT ARTIFACTS\n");
        for artifact in &document.artifacts {
            out.push_str(&format!(
                "  {:<44} <- {} bytes\n",
                artifact.artifact,
                artifact.text.len()
            ));
        }
    }
    out
}

/// Explain an invocation that intentionally carries no overrides. `--tunables-explain` is a
/// standalone read, so the absence of a profile must not fall through into TUI startup and fail
/// merely because stdout is not a terminal.
pub(crate) fn render_noop_effect() -> String {
    let mut document = empty_document();
    document.profile_id = "adhoc/no-overrides".to_owned();
    render_effect(&document)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value_bearing_document() -> ProfileDocument {
        apply_set_arguments(
            None,
            &[
                "max_turns=10".to_owned(),
                "multimodal_token_budget=1024".to_owned(),
            ],
        )
        .expect("both Tier-1 assignments are valid")
        .expect("--set creates a profile document")
    }

    #[test]
    fn tier_one_set_arguments_remain_typed_profile_values() {
        let document = value_bearing_document();
        assert_eq!(document.values.len(), 2);
        assert!(document.values.iter().any(|value| {
            value.family == "max_turns"
                && matches!(&value.value, ResolutionValue::Integer { value: 10 })
        }));
        assert!(document.values.iter().any(|value| {
            value.family == "multimodal_token_budget"
                && matches!(&value.value, ResolutionValue::Integer { value: 1_024 })
        }));
    }

    #[test]
    fn inline_and_digest_pinned_files_accept_the_same_value_bearing_profile() {
        let document = value_bearing_document();
        let rendered = iteron_tunables::render_profile(&document).unwrap();
        let (inline, inline_origin) = load(None, Some(&rendered), None)
            .unwrap()
            .expect("inline profile is present");
        assert_eq!(inline_origin, ProfileOrigin::Unpinned);
        assert_eq!(inline, document);

        let path = std::env::temp_dir().join(format!(
            "iteron-value-bearing-profile-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, &rendered).unwrap();
        let digest = iteron_tunables::document_digest(&rendered);
        let loaded = load(Some(&path), None, Some(&digest));
        std::fs::remove_file(&path).unwrap();
        let (pinned, pinned_origin) = loaded.unwrap().expect("pinned profile is present");
        assert_eq!(pinned_origin, ProfileOrigin::PinnedFile);
        assert_eq!(pinned, document);
    }

    #[test]
    fn no_override_explain_is_a_complete_standalone_receipt() {
        assert_eq!(
            render_noop_effect(),
            "profile `adhoc/no-overrides` — 0 family value(s), 0 parameter(s), 0 artifact(s)\n"
        );
    }
}
