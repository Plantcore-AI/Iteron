//! Build-plane compatibility policy for public JSON and JSONL surfaces.
//!
//! Runtime crates own deserialization. This module owns the independent release contract: frozen
//! fixtures are immutable, every shape change advances its surface version, and a removed name is
//! admitted only after a release of deprecation plus a still-live shim and named migrator.

#[path = "schema_compat_fixtures.rs"]
mod fixtures;
#[path = "schema_compat_git.rs"]
mod git;
#[path = "schema_compat_manifest.rs"]
mod manifest;
#[path = "schema_compat_migrations.rs"]
mod migrations;
#[path = "schema_compat_rust.rs"]
mod rust_shape;

use anyhow::{Context, Result, bail};
use git::git_object;
use manifest::{
    CONTRACT_PATH, Contract, MAX_CONTRACT_BYTES, MAX_FIXTURE_BYTES, Surface, load_candidate,
    load_candidate_optional, parse_contract, read_bounded, validate_contract,
    validate_contract_shape,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const CLI_INPUT_ATTACHMENT_SURFACE: &str = "cli.machine-stream.input-attachment";
const CLI_INPUT_ATTACHMENT_FIXTURE: &str =
    "crates/cli/tests/golden/input_attachment_stream_v5.jsonl";

pub(crate) fn parse_json_no_duplicates(bytes: &[u8], label: &str) -> Result<serde_json::Value> {
    fixtures::parse_json_no_duplicates(bytes).with_context(|| format!("{label} is invalid JSON"))
}

/// An opaque, reusable view of the fully validated current CLI result authority.
#[derive(Debug, Clone)]
pub(crate) struct CurrentCliResultSnapshot {
    available: bool,
    selector_field: String,
    selector_value: String,
    version_field: String,
    current_version: u32,
    allowed_fields: BTreeSet<String>,
    required_fields: BTreeSet<String>,
    kernel_tax_fields: Option<BTreeSet<String>>,
}

struct CliResultTopLevelAuthority<'a> {
    allowed_fields: &'a BTreeSet<String>,
    required_fields: &'a BTreeSet<String>,
    selector_field: &'a str,
    selector_value: &'a str,
    version_field: &'a str,
    current_version: u32,
}

impl CurrentCliResultSnapshot {
    pub(crate) fn validate(&self, value: &serde_json::Value) -> Result<()> {
        if !self.available {
            bail!("validated schema contract has no CLI machine-result authority");
        }
        validate_cli_result_top_level(
            value,
            "CLI result consumer record",
            &CliResultTopLevelAuthority {
                allowed_fields: &self.allowed_fields,
                required_fields: &self.required_fields,
                selector_field: &self.selector_field,
                selector_value: &self.selector_value,
                version_field: &self.version_field,
                current_version: self.current_version,
            },
        )?;

        let Some(kernel_tax_value) = value.get("kernel_tax") else {
            return Ok(());
        };
        let kernel_tax = kernel_tax_value
            .as_object()
            .context("CLI result consumer record `kernel_tax` is not an object")?;
        let expected_kernel_tax = self.kernel_tax_fields.as_ref().context(
            "CLI result consumer record carries `kernel_tax`, but canonical current fixtures do not",
        )?;
        let actual_kernel_tax = kernel_tax.keys().cloned().collect::<BTreeSet<_>>();
        if actual_kernel_tax != *expected_kernel_tax {
            bail!(
                "CLI result consumer record `kernel_tax` fields differ from canonical current fixtures: expected {:?}, found {actual_kernel_tax:?}",
                expected_kernel_tax
            );
        }
        for field in expected_kernel_tax {
            if kernel_tax
                .get(field)
                .and_then(serde_json::Value::as_u64)
                .is_none()
            {
                bail!("CLI result consumer record `kernel_tax.{field}` is not a u64");
            }
        }
        Ok(())
    }
}

fn current_cli_result_snapshot_from_validated(
    root: &Path,
    contract: &Contract,
) -> Result<CurrentCliResultSnapshot> {
    let Some(result) = contract
        .surfaces
        .iter()
        .find(|surface| surface.id == "cli.machine-result")
    else {
        return Ok(CurrentCliResultSnapshot {
            available: false,
            selector_field: String::new(),
            selector_value: String::new(),
            version_field: String::new(),
            current_version: 0,
            allowed_fields: BTreeSet::new(),
            required_fields: BTreeSet::new(),
            kernel_tax_fields: None,
        });
    };
    let selector = result
        .selector
        .as_ref()
        .context("canonical `cli.machine-result` lacks a selector")?;
    let version_field = result
        .version_field
        .as_ref()
        .context("canonical `cli.machine-result` lacks a version field")?;
    let allowed_fields = result
        .fields
        .iter()
        .map(|field| field.name.clone())
        .collect::<BTreeSet<_>>();
    let required_fields = result
        .fields
        .iter()
        .filter(|field| !field.optional)
        .map(|field| field.name.clone())
        .collect::<BTreeSet<_>>();
    let kernel_tax_fields = current_cli_result_kernel_tax_fields(root, contract)?;

    Ok(CurrentCliResultSnapshot {
        available: true,
        selector_field: selector.field.clone(),
        selector_value: selector.value.clone(),
        version_field: version_field.clone(),
        current_version: result.current_version,
        allowed_fields,
        required_fields,
        kernel_tax_fields,
    })
}

fn current_cli_result_surface(contract: &Contract) -> Result<&Surface> {
    contract
        .surfaces
        .iter()
        .find(|surface| surface.id == "cli.machine-result")
        .context("canonical schema-compatibility manifest lacks `cli.machine-result`")
}

fn validate_current_cli_result_top_level(
    value: &serde_json::Value,
    result: &Surface,
    label: &str,
) -> Result<()> {
    let allowed_fields = result
        .fields
        .iter()
        .map(|field| field.name.clone())
        .collect::<BTreeSet<_>>();
    let required_fields = result
        .fields
        .iter()
        .filter(|field| !field.optional)
        .map(|field| field.name.clone())
        .collect::<BTreeSet<_>>();
    let selector = result
        .selector
        .as_ref()
        .context("canonical `cli.machine-result` lacks a selector")?;
    let version_field = result
        .version_field
        .as_deref()
        .context("canonical `cli.machine-result` lacks a version field")?;
    validate_cli_result_top_level(
        value,
        label,
        &CliResultTopLevelAuthority {
            allowed_fields: &allowed_fields,
            required_fields: &required_fields,
            selector_field: &selector.field,
            selector_value: &selector.value,
            version_field,
            current_version: result.current_version,
        },
    )
}

fn validate_cli_result_top_level(
    value: &serde_json::Value,
    label: &str,
    authority: &CliResultTopLevelAuthority<'_>,
) -> Result<()> {
    let object = value
        .as_object()
        .with_context(|| format!("{label} is not an object"))?;
    let actual_fields = object.keys().cloned().collect::<BTreeSet<_>>();
    if !actual_fields.is_subset(authority.allowed_fields) {
        bail!(
            "{label} has fields outside canonical `cli.machine-result`: allowed {:?}, found {actual_fields:?}",
            authority.allowed_fields
        );
    }
    if !authority.required_fields.is_subset(&actual_fields) {
        bail!(
            "{label} lacks required canonical `cli.machine-result` fields: required {:?}, found {actual_fields:?}",
            authority.required_fields
        );
    }
    if value
        .get(authority.selector_field)
        .and_then(serde_json::Value::as_str)
        != Some(authority.selector_value)
    {
        bail!(
            "{label} does not match canonical selector {}={}",
            authority.selector_field,
            authority.selector_value
        );
    }
    if value
        .get(authority.version_field)
        .and_then(serde_json::Value::as_u64)
        != Some(u64::from(authority.current_version))
    {
        bail!(
            "{label} does not carry canonical {}={}",
            authority.version_field,
            authority.current_version
        );
    }
    Ok(())
}

fn current_cli_result_values(
    root: &Path,
    contract: &Contract,
) -> Result<Vec<(String, serde_json::Value)>> {
    let result = current_cli_result_surface(contract)?;
    let selector = result
        .selector
        .as_ref()
        .context("canonical `cli.machine-result` lacks a selector")?;
    let current_fixtures = result
        .fixtures
        .iter()
        .filter(|fixture| fixture.schema_version == result.current_version)
        .collect::<Vec<_>>();
    if current_fixtures.is_empty() {
        bail!(
            "canonical `cli.machine-result` lacks a fixture for current version {}",
            result.current_version
        );
    }

    let mut current_results = Vec::new();
    for fixture in current_fixtures {
        let source = read_bounded(root, &fixture.path, MAX_FIXTURE_BYTES)?;
        let values = match fixture.format {
            manifest::FixtureFormat::Json => vec![parse_json_no_duplicates(
                &source,
                &format!("canonical result fixture `{}`", fixture.path),
            )?],
            manifest::FixtureFormat::Jsonl => {
                let mut values = Vec::new();
                for (index, line) in source
                    .split(|byte| *byte == b'\n')
                    .filter(|line| !line.is_empty())
                    .enumerate()
                {
                    values.push(parse_json_no_duplicates(
                        line,
                        &format!(
                            "canonical result fixture `{}` line {}",
                            fixture.path,
                            index + 1
                        ),
                    )?);
                }
                if values.is_empty() {
                    bail!("canonical result fixture `{}` is empty", fixture.path);
                }
                values
            }
        };
        let mut found = false;
        for (index, value) in values.into_iter().enumerate() {
            if value
                .get(&selector.field)
                .and_then(serde_json::Value::as_str)
                != Some(selector.value.as_str())
            {
                continue;
            }
            found = true;
            let label = format!(
                "canonical result fixture `{}` record {}",
                fixture.path,
                index + 1
            );
            validate_current_cli_result_top_level(&value, result, &label)?;
            current_results.push((label, value));
        }
        if !found {
            bail!(
                "canonical result fixture `{}` lacks a record matching {}={}",
                fixture.path,
                selector.field,
                selector.value
            );
        }
    }
    Ok(current_results)
}

fn current_cli_result_kernel_tax_fields(
    root: &Path,
    contract: &Contract,
) -> Result<Option<BTreeSet<String>>> {
    let result_surface = current_cli_result_surface(contract)?;
    let kernel_tax_optional = result_surface
        .fields
        .iter()
        .find(|field| field.name == "kernel_tax")
        .context("canonical `cli.machine-result` lacks `kernel_tax`")?
        .optional;
    let mut expected = None;
    for (label, result) in current_cli_result_values(root, contract)? {
        let Some(kernel_tax_value) = result.get("kernel_tax") else {
            if kernel_tax_optional {
                continue;
            }
            bail!("{label} lacks required `kernel_tax`");
        };
        let kernel_tax = kernel_tax_value
            .as_object()
            .with_context(|| format!("{label} `kernel_tax` is not an object"))?;
        let fields = kernel_tax.keys().cloned().collect::<BTreeSet<_>>();
        if fields.is_empty()
            || kernel_tax
                .values()
                .any(|value| serde_json::Value::as_u64(value).is_none())
        {
            bail!("{label} `kernel_tax` must contain only named u64 fields");
        }
        if let Some(expected) = &expected {
            if fields != *expected {
                bail!(
                    "canonical current result fixtures disagree on `kernel_tax` fields: expected {expected:?}, found {fields:?} in {label}"
                );
            }
        } else {
            expected = Some(fields);
        }
    }
    if expected.is_none() && !kernel_tax_optional {
        bail!("canonical current result fixtures contain no `kernel_tax` shape");
    }
    Ok(expected)
}

pub(crate) fn read_candidate_file_bounded(
    root: &Path,
    relative: &str,
    limit: u64,
) -> Result<Vec<u8>> {
    read_bounded(root, relative, limit)
}

pub(crate) fn read_revision_file_bounded(
    root: &Path,
    revision: &str,
    relative: &str,
    limit: u64,
) -> Result<Option<Vec<u8>>> {
    git_object(root, revision, relative, limit)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HistoryBase {
    Provisional,
    Published,
}

pub(crate) fn validate_current(root: &Path) -> Result<CurrentCliResultSnapshot> {
    let contract = load_candidate(root)?;
    validate_candidate(root, &contract)?;
    let snapshot = current_cli_result_snapshot_from_validated(root, &contract)?;
    if snapshot.available {
        for (_, value) in current_cli_result_values(root, &contract)? {
            snapshot.validate(&value)?;
        }
    }
    Ok(snapshot)
}

pub(crate) fn validate_against_base(root: &Path, base: &str) -> Result<()> {
    let Some(base_bytes) = git_object(root, base, CONTRACT_PATH, MAX_CONTRACT_BYTES)? else {
        // One-time rollout: future pull requests compare against this committed contract.
        if let Some(candidate) = load_candidate_optional(root)? {
            validate_candidate(root, &candidate)?;
        }
        return Ok(());
    };
    let candidate = load_candidate(root)?;
    validate_candidate(root, &candidate)?;
    let previous = parse_contract(&base_bytes, "base schema-compatibility contract")?;
    validate_contract_shape(&previous)?;
    compare_contracts(root, base, &previous, &candidate, HistoryBase::Provisional)
}

/// True when a shape the trusted base already published has moved.
///
/// `PROTOCOL_VERSION` stamps the transport and the generation of contracts pinned to it
/// (docs/spec/abi.md §4.3(a) and (c)). §4.3(b) rules 2 and 3 make exactly two evolutions
/// byte-identical on the line: a brand-new top-level tag, and an appended `Option` field carrying
/// `skip_serializing_if`. Neither may oblige a bump, or the hard version-skew refusal in `wire.rs`
/// would fire between peers that write identical bytes. Everything else moves a published shape,
/// including any later change to the five `abi.*` contracts, which are published from the freeze on.
pub(crate) fn wire_line_format_changed(root: &Path, base: &str) -> Result<bool> {
    let Some(base_bytes) = git_object(root, base, CONTRACT_PATH, MAX_CONTRACT_BYTES)? else {
        return Ok(true);
    };
    let previous = parse_contract(&base_bytes, "base schema-compatibility contract")?;
    let candidate = load_candidate(root)?;
    Ok(line_format_moved(&previous, &candidate))
}

fn line_format_moved(previous: &Contract, candidate: &Contract) -> bool {
    let current: BTreeMap<&str, &Surface> = candidate
        .surfaces
        .iter()
        .map(|surface| (surface.id.as_str(), surface))
        .collect();
    previous.surfaces.iter().any(|old| {
        let Some(new) = current.get(old.id.as_str()) else {
            return true;
        };
        old.current_version != new.current_version
            || old.version_field != new.version_field
            || old.selector != new.selector
            || old.fixtures != new.fixtures
            || old.compatibility_shims != new.compatibility_shims
            || !old.fields.iter().all(|field| new.fields.contains(field))
    })
}

pub(crate) fn validate_bootstrap_release(root: &Path) -> Result<()> {
    let candidate = load_candidate(root)?;
    validate_candidate(root, &candidate)?;
    if candidate.release_ordinal != 1 {
        bail!("the first public schema contract must use release_ordinal 1");
    }
    for surface in &candidate.surfaces {
        if !surface.compatibility_shims.is_empty() {
            bail!(
                "bootstrap schema surface `{}` cannot claim a compatibility shim before a public release",
                surface.id
            );
        }
        for field in &surface.fields {
            if field.introduced_release != 1 || field.deprecated_release.is_some() {
                bail!(
                    "bootstrap field `{}.{}` must be introduced in release 1 and cannot already be deprecated",
                    surface.id,
                    field.name
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_release_against_base(root: &Path, base: &str) -> Result<()> {
    let base_bytes = git_object(root, base, CONTRACT_PATH, MAX_CONTRACT_BYTES)?
        .context("published release lacks the schema-compatibility contract")?;
    let candidate = load_candidate(root)?;
    validate_candidate(root, &candidate)?;
    let previous = parse_contract(&base_bytes, "published schema-compatibility contract")?;
    validate_contract_shape(&previous)?;
    let expected = previous
        .release_ordinal
        .checked_add(1)
        .context("published schema release ordinal overflowed")?;
    if candidate.release_ordinal != expected {
        bail!(
            "release schema ordinal must advance exactly once from published base {} to {expected}",
            previous.release_ordinal
        );
    }
    compare_contracts(root, base, &previous, &candidate, HistoryBase::Published)
}

fn validate_candidate(root: &Path, candidate: &Contract) -> Result<()> {
    validate_contract(root, candidate)?;
    rust_shape::validate(root, candidate)
}

fn compare_contracts(
    root: &Path,
    base: &str,
    previous: &Contract,
    candidate: &Contract,
    history_base: HistoryBase,
) -> Result<()> {
    rust_shape::compare(root, base, previous, candidate)?;
    if candidate.release_ordinal < previous.release_ordinal {
        bail!("schema compatibility release ordinal cannot decrease");
    }
    if candidate.minimum_deprecation_releases < previous.minimum_deprecation_releases {
        bail!("schema compatibility deprecation runway cannot be weakened");
    }
    let old = previous
        .surfaces
        .iter()
        .map(|surface| (surface.id.as_str(), surface))
        .collect::<BTreeMap<_, _>>();
    let new = candidate
        .surfaces
        .iter()
        .map(|surface| (surface.id.as_str(), surface))
        .collect::<BTreeMap<_, _>>();
    let previous_cli_stream_version = previous
        .surfaces
        .iter()
        .filter(|surface| surface.id.starts_with("cli.machine-stream."))
        .map(|surface| surface.current_version)
        .max();
    for (id, old_surface) in old {
        let new_surface = new
            .get(id)
            .with_context(|| format!("public schema surface `{id}` was removed"))?;
        compare_surface(
            root,
            base,
            previous,
            candidate,
            old_surface,
            new_surface,
            history_base,
        )?;
    }
    for (id, surface) in &new {
        if previous.surfaces.iter().any(|previous| previous.id == *id) {
            continue;
        }
        if !surface.compatibility_shims.is_empty() {
            bail!(
                "new schema surface `{id}` cannot claim compatibility shims before it has published history"
            );
        }
        if surface
            .fields
            .iter()
            .any(|field| field.introduced_release != candidate.release_ordinal)
        {
            bail!("new schema surface `{id}` must introduce every field in the candidate release");
        }
        if surface.fields.iter().any(|field| {
            field
                .deprecated_release
                .is_some_and(|release| release != candidate.release_ordinal)
        }) {
            bail!(
                "new schema surface `{id}` cannot claim field deprecation history before the candidate release"
            );
        }
        if id.starts_with("cli.machine-stream.")
            && previous_cli_stream_version.is_some_and(|version| surface.current_version <= version)
            && !is_v5_input_attachment_addition(surface, previous_cli_stream_version)
        {
            bail!("new CLI stream surface `{id}` requires a shared CLI schema version bump");
        }
    }
    Ok(())
}

/// One narrowly enumerated compatibility exception for metadata that old stream readers already
/// promise to skip as an unknown top-level tag. Existing v5 surfaces and fixtures remain frozen.
fn is_v5_input_attachment_addition(
    surface: &Surface,
    previous_cli_stream_version: Option<u32>,
) -> bool {
    let fields = surface
        .fields
        .iter()
        .map(|field| field.name.as_str())
        .collect::<BTreeSet<_>>();
    surface.id == CLI_INPUT_ATTACHMENT_SURFACE
        && previous_cli_stream_version == Some(5)
        && surface.current_version == 5
        && surface.version_field.as_deref() == Some("schema_version")
        && surface.selector.as_ref()
            == Some(&manifest::Selector {
                field: "type".into(),
                value: "input_attachment".into(),
            })
        && surface.fixtures.len() == 1
        && surface.fixtures[0].path == CLI_INPUT_ATTACHMENT_FIXTURE
        && surface.fixtures[0].format == manifest::FixtureFormat::Jsonl
        && surface.fixtures[0].schema_version == 5
        && fields
            == BTreeSet::from([
                "encoded_bytes",
                "media_type",
                "ordinal",
                "schema_version",
                "type",
            ])
        && surface.fields.iter().all(|field| {
            field.introduced_release == 1 && field.deprecated_release.is_none() && !field.optional
        })
        && surface.compatibility_shims.is_empty()
}

fn compare_surface(
    root: &Path,
    base: &str,
    previous_contract: &Contract,
    candidate_contract: &Contract,
    previous: &Surface,
    candidate: &Surface,
    history_base: HistoryBase,
) -> Result<()> {
    if candidate.selector != previous.selector {
        bail!(
            "schema surface `{}` changed its immutable record selector",
            previous.id
        );
    }
    if candidate.current_version < previous.current_version {
        bail!("schema surface `{}` version cannot decrease", previous.id);
    }
    if candidate != previous
        && candidate.current_version <= previous.current_version
        && !is_additive_optional_append(previous, candidate, candidate_contract.release_ordinal)
    {
        bail!(
            "schema surface `{}` changed without a version bump",
            previous.id
        );
    }
    let candidate_fixtures = candidate.fixtures.iter().collect::<BTreeSet<_>>();
    for fixture in &previous.fixtures {
        if !candidate_fixtures.contains(fixture) {
            bail!(
                "schema surface `{}` removed frozen fixture `{}`",
                previous.id,
                fixture.path
            );
        }
        let base_bytes = git_object(root, base, &fixture.path, MAX_FIXTURE_BYTES)?
            .with_context(|| format!("base lacks frozen fixture `{}`", fixture.path))?;
        let candidate_bytes = read_bounded(root, &fixture.path, MAX_FIXTURE_BYTES)?;
        if base_bytes != candidate_bytes {
            bail!(
                "frozen compatibility fixture `{}` was rewritten",
                fixture.path
            );
        }
    }

    let old_fields = previous
        .fields
        .iter()
        .map(|field| (field.name.as_str(), field))
        .collect::<BTreeMap<_, _>>();
    let new_fields = candidate
        .fields
        .iter()
        .map(|field| (field.name.as_str(), field))
        .collect::<BTreeMap<_, _>>();
    for (name, old_field) in old_fields {
        if let Some(new_field) = new_fields.get(name) {
            let introduction_changed = old_field.introduced_release != new_field.introduced_release
                && !(history_base == HistoryBase::Provisional
                    && old_field.introduced_release < new_field.introduced_release
                    && new_field.introduced_release == candidate_contract.release_ordinal);
            let deprecation_changed =
                match (old_field.deprecated_release, new_field.deprecated_release) {
                    (None, None) => false,
                    (None, Some(release)) => release != candidate_contract.release_ordinal,
                    (Some(old), Some(new)) => {
                        old != new
                            && !(history_base == HistoryBase::Provisional
                                && old < new
                                && new == candidate_contract.release_ordinal)
                    }
                    (Some(_), None) => true,
                };
            if introduction_changed || deprecation_changed {
                bail!(
                    "schema field `{}.{name}` rewrote its release history",
                    previous.id
                );
            }
            continue;
        }
        let deprecated = old_field.deprecated_release.with_context(|| {
            format!(
                "schema field `{}.{name}` was removed without prior deprecation",
                previous.id
            )
        })?;
        let elapsed = candidate_contract
            .release_ordinal
            .saturating_sub(deprecated);
        if elapsed < previous_contract.minimum_deprecation_releases {
            bail!(
                "schema field `{}.{name}` was removed before its deprecation runway elapsed",
                previous.id
            );
        }
        let shim = candidate
            .compatibility_shims
            .iter()
            .find(|shim| shim.old_field == name)
            .with_context(|| {
                format!(
                    "schema field `{}.{name}` was removed without a compatibility shim",
                    previous.id
                )
            })?;
        if shim.deprecated_release != deprecated
            || !shim.fixtures.iter().all(|path| {
                previous
                    .fixtures
                    .iter()
                    .any(|fixture| fixture.path == *path)
            })
        {
            bail!(
                "schema field `{}.{name}` has an ungrounded compatibility shim",
                previous.id
            );
        }
        let active_fields = candidate
            .fields
            .iter()
            .map(|field| field.name.as_str())
            .collect::<BTreeSet<_>>();
        let target_fields = shim
            .target_fields
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if shim.target_version != candidate.current_version || target_fields != active_fields {
            bail!(
                "new compatibility shim `{}.{name}` must freeze the removal version and active field shape",
                previous.id
            );
        }
    }
    for (name, new_field) in &new_fields {
        if !previous.fields.iter().any(|field| field.name == *name)
            && new_field.introduced_release != candidate_contract.release_ordinal
        {
            bail!(
                "new schema field `{}.{name}` must name the candidate release",
                previous.id
            );
        }
    }
    for old_shim in &previous.compatibility_shims {
        let retained = candidate
            .compatibility_shims
            .iter()
            .find(|shim| shim.old_field == old_shim.old_field)
            .with_context(|| {
                format!(
                    "compatibility shim `{}.{}` was removed",
                    previous.id, old_shim.old_field
                )
            })?;
        let old_fixture_paths = old_shim.fixtures.iter().collect::<BTreeSet<_>>();
        let retained_fixture_paths = retained.fixtures.iter().collect::<BTreeSet<_>>();
        if retained.deprecated_release != old_shim.deprecated_release
            || !old_fixture_paths.is_subset(&retained_fixture_paths)
            || retained.migrator != old_shim.migrator
            || retained.replacement != old_shim.replacement
            || retained.target_version != old_shim.target_version
            || retained.target_fields != old_shim.target_fields
        {
            bail!(
                "compatibility shim `{}.{}` was weakened",
                previous.id,
                old_shim.old_field
            );
        }
    }
    Ok(())
}

fn is_additive_optional_append(
    previous: &Surface,
    candidate: &Surface,
    release_ordinal: u32,
) -> bool {
    if candidate.current_version != previous.current_version
        || candidate.version_field != previous.version_field
        || candidate.selector != previous.selector
        || candidate.fixtures != previous.fixtures
        || candidate.compatibility_shims != previous.compatibility_shims
        || candidate.fields.len() <= previous.fields.len()
        || !previous
            .fields
            .iter()
            .all(|old| candidate.fields.iter().any(|new| new == old))
    {
        return false;
    }
    candidate
        .fields
        .iter()
        .filter(|field| !previous.fields.iter().any(|old| old.name == field.name))
        .all(|field| {
            field.optional
                && field.introduced_release == release_ordinal
                && field.deprecated_release.is_none()
        })
}

#[cfg(test)]
#[path = "schema_compat_tests.rs"]
mod tests;
