use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::Path;

#[cfg(test)]
pub(super) use super::fixtures::validate_cli_fixture_inventory;
pub(super) use super::fixtures::{read_bounded, validate_repo_path};

pub(super) const CONTRACT_PATH: &str = "governance/schema-compatibility.json";
pub(super) const MAX_CONTRACT_BYTES: u64 = 1024 * 1024;
pub(super) const MAX_FIXTURE_BYTES: u64 = 1024 * 1024;
// The source-complete durable ABI closure currently contains 130 top-level and dynamically
// discovered named surfaces. Keep bounded headroom for additive typed records; the whole contract
// remains separately capped at 1 MiB and every surface, fixture, field, and shim has its own cap.
const MAX_SURFACES: usize = 160;
const MAX_FIELDS: usize = 256;
const MAX_FIXTURES: usize = 64;
const MAX_SHIMS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Contract {
    pub(super) schema_version: u32,
    pub(super) release_ordinal: u32,
    pub(super) minimum_deprecation_releases: u32,
    pub(super) surfaces: Vec<Surface>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Surface {
    pub(super) id: String,
    pub(super) current_version: u32,
    pub(super) version_field: Option<String>,
    #[serde(default)]
    pub(super) selector: Option<Selector>,
    pub(super) fixtures: Vec<Fixture>,
    pub(super) fields: Vec<Field>,
    #[serde(default)]
    pub(super) compatibility_shims: Vec<CompatibilityShim>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Selector {
    pub(super) field: String,
    pub(super) value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Fixture {
    pub(super) path: String,
    pub(super) format: FixtureFormat,
    pub(super) schema_version: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum FixtureFormat {
    Json,
    Jsonl,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Field {
    pub(super) name: String,
    pub(super) introduced_release: u32,
    #[serde(default)]
    pub(super) deprecated_release: Option<u32>,
    /// An appended `Option` with `skip_serializing_if = "Option::is_none"` may be absent from
    /// every frozen pre-append fixture while remaining part of the current Rust shape.
    #[serde(default)]
    pub(super) optional: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CompatibilityShim {
    pub(super) old_field: String,
    pub(super) replacement: Option<String>,
    pub(super) deprecated_release: u32,
    pub(super) target_version: u32,
    pub(super) target_fields: Vec<String>,
    pub(super) fixtures: Vec<String>,
    pub(super) migrator: String,
}

pub(super) fn load_candidate(root: &Path) -> Result<Contract> {
    load_candidate_optional(root)?.context("candidate schema-compatibility contract is missing")
}

pub(super) fn load_candidate_optional(root: &Path) -> Result<Option<Contract>> {
    match std::fs::symlink_metadata(root.join(CONTRACT_PATH)) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("cannot inspect schema-compatibility contract"),
    }
    let bytes = read_bounded(root, CONTRACT_PATH, MAX_CONTRACT_BYTES)?;
    parse_contract(&bytes, "candidate schema-compatibility contract").map(Some)
}

pub(super) fn parse_contract(bytes: &[u8], label: &str) -> Result<Contract> {
    let value = super::fixtures::parse_json_no_duplicates(bytes)
        .with_context(|| format!("{label} is invalid JSON"))?;
    serde_json::from_value(value).with_context(|| format!("{label} has an invalid typed shape"))
}

pub(super) fn validate_contract(root: &Path, contract: &Contract) -> Result<()> {
    validate_contract_shape(contract)?;
    super::fixtures::validate_contract_files(root, contract)
}

pub(super) fn validate_contract_shape(contract: &Contract) -> Result<()> {
    if contract.schema_version != 1 {
        bail!("unsupported schema-compatibility contract version; expected 1");
    }
    if contract.release_ordinal == 0 || contract.minimum_deprecation_releases == 0 {
        bail!("release ordinal and deprecation runway must both be positive");
    }
    if contract.surfaces.is_empty() || contract.surfaces.len() > MAX_SURFACES {
        bail!("schema-compatibility contract must contain 1..={MAX_SURFACES} surfaces");
    }
    let mut surface_ids = BTreeSet::new();
    for surface in &contract.surfaces {
        validate_name("surface id", &surface.id)?;
        if !surface_ids.insert(surface.id.as_str()) {
            bail!("duplicate schema surface `{}`", surface.id);
        }
        if surface.current_version == 0 {
            bail!("schema surface `{}` has version zero", surface.id);
        }
        if surface.fixtures.is_empty() || surface.fixtures.len() > MAX_FIXTURES {
            bail!(
                "schema surface `{}` has an invalid fixture count",
                surface.id
            );
        }
        if surface.fields.is_empty() || surface.fields.len() > MAX_FIELDS {
            bail!("schema surface `{}` has an invalid field count", surface.id);
        }
        if surface.compatibility_shims.len() > MAX_SHIMS {
            bail!(
                "schema surface `{}` has too many compatibility shims",
                surface.id
            );
        }
        if let Some(version_field) = &surface.version_field {
            validate_name("version field", version_field)?;
        }
        if let Some(selector) = &surface.selector {
            validate_name("selector field", &selector.field)?;
            validate_name("selector value", &selector.value)?;
        }
        if surface.id.starts_with("cli.machine-stream.") {
            let selector = surface.selector.as_ref().with_context(|| {
                format!("CLI stream surface `{}` lacks a type selector", surface.id)
            })?;
            if selector.field != "type" {
                bail!(
                    "CLI stream surface `{}` must select on the `type` field",
                    surface.id
                );
            }
        }
        if surface.id == "cli.machine-result"
            && surface.selector.as_ref()
                != Some(&Selector {
                    field: "type".into(),
                    value: "result".into(),
                })
        {
            bail!("CLI machine-result surface must select `type=result`");
        }
        if surface
            .fixtures
            .iter()
            .any(|fixture| fixture.path.starts_with("crates/cli/tests/golden/"))
            && surface
                .selector
                .as_ref()
                .is_some_and(|selector| selector.field == "type")
            && surface.id != "cli.machine-result"
            && !surface.id.starts_with("cli.machine-stream.")
        {
            bail!("CLI golden type selector must belong to the declared machine-output family");
        }
        validate_surface_shape(contract, surface)?;
    }
    Ok(())
}

fn validate_surface_shape(contract: &Contract, surface: &Surface) -> Result<()> {
    let mut paths = BTreeSet::new();
    let mut has_current_fixture = false;
    for fixture in &surface.fixtures {
        super::fixtures::validate_fixture_path(&fixture.path)?;
        if fixture.schema_version == 0 || fixture.schema_version > surface.current_version {
            bail!(
                "fixture `{}` has an invalid pinned schema version",
                fixture.path
            );
        }
        has_current_fixture |= fixture.schema_version == surface.current_version;
        if !paths.insert(fixture.path.as_str()) {
            bail!(
                "schema surface `{}` repeats fixture `{}`",
                surface.id,
                fixture.path
            );
        }
    }
    if !has_current_fixture {
        bail!(
            "schema surface `{}` lacks a fixture for its current version",
            surface.id
        );
    }

    let mut fields = BTreeSet::new();
    for field in &surface.fields {
        validate_name("field", &field.name)?;
        if !fields.insert(field.name.as_str()) {
            bail!(
                "schema surface `{}` repeats field `{}`",
                surface.id,
                field.name
            );
        }
        if field.introduced_release == 0 || field.introduced_release > contract.release_ordinal {
            bail!(
                "field `{}.{}` has an invalid introduction release",
                surface.id,
                field.name
            );
        }
        if let Some(deprecated) = field.deprecated_release
            && (deprecated < field.introduced_release || deprecated > contract.release_ordinal)
        {
            bail!(
                "field `{}.{}` has an invalid deprecation release",
                surface.id,
                field.name
            );
        }
    }
    if let Some(selector) = &surface.selector
        && !fields.contains(selector.field.as_str())
    {
        bail!(
            "schema surface `{}` selector field `{}` is not an active field",
            surface.id,
            selector.field
        );
    }

    let mut shim_fields = BTreeSet::new();
    for shim in &surface.compatibility_shims {
        validate_name("shim field", &shim.old_field)?;
        if fields.contains(shim.old_field.as_str()) || !shim_fields.insert(shim.old_field.as_str())
        {
            bail!(
                "schema surface `{}` has a duplicate/live shim field `{}`",
                surface.id,
                shim.old_field
            );
        }
        if shim.deprecated_release == 0 || shim.deprecated_release > contract.release_ordinal {
            bail!(
                "schema surface `{}` has an invalid deprecation shim for `{}`",
                surface.id,
                shim.old_field
            );
        }
        if shim.fixtures.is_empty() || shim.fixtures.len() > MAX_FIXTURES {
            bail!(
                "shim `{}.{}` must cover 1..={MAX_FIXTURES} frozen fixtures",
                surface.id,
                shim.old_field
            );
        }
        let mut shim_fixture_paths = BTreeSet::new();
        for path in &shim.fixtures {
            if !shim_fixture_paths.insert(path.as_str()) {
                bail!(
                    "shim `{}.{}` repeats frozen fixture `{path}`",
                    surface.id,
                    shim.old_field
                );
            }
            if !paths.contains(path.as_str()) {
                bail!(
                    "shim `{}.{}` is tied to undeclared fixture `{path}`",
                    surface.id,
                    shim.old_field
                );
            }
            let shim_fixture = surface
                .fixtures
                .iter()
                .find(|fixture| fixture.path == *path)
                .context("shim fixture disappeared during shape validation")?;
            if shim_fixture.schema_version >= surface.current_version {
                bail!(
                    "shim `{}.{}` must migrate only prior-version fixtures",
                    surface.id,
                    shim.old_field
                );
            }
            if shim.target_version <= shim_fixture.schema_version
                || shim.target_version > surface.current_version
            {
                bail!(
                    "shim `{}.{}` has an invalid frozen target for fixture `{path}` at source version {}",
                    surface.id,
                    shim.old_field,
                    shim_fixture.schema_version
                );
            }
        }
        let mut target_fields = BTreeSet::new();
        for field in &shim.target_fields {
            validate_name("shim target field", field)?;
            if !target_fields.insert(field.as_str()) {
                bail!(
                    "shim `{}.{}` repeats target field `{field}`",
                    surface.id,
                    shim.old_field
                );
            }
        }
        if target_fields.is_empty() || target_fields.contains(shim.old_field.as_str()) {
            bail!(
                "shim `{}.{}` has an invalid frozen target field set",
                surface.id,
                shim.old_field
            );
        }
        if let Some(selector) = &surface.selector
            && !target_fields.contains(selector.field.as_str())
        {
            bail!(
                "shim `{}.{}` target omits immutable selector field `{}`",
                surface.id,
                shim.old_field,
                selector.field
            );
        }
        if let Some(replacement) = &shim.replacement {
            validate_name("shim replacement", replacement)?;
            if !target_fields.contains(replacement.as_str()) {
                bail!(
                    "shim `{}.{}` names a replacement outside its frozen target",
                    surface.id,
                    shim.old_field
                );
            }
        }
        validate_name("migrator id", &shim.migrator)?;
    }
    Ok(())
}

fn validate_name(kind: &str, name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        bail!("invalid {kind} `{name}`");
    }
    Ok(())
}
