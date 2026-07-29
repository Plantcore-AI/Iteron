use super::manifest::{Contract, FixtureFormat, MAX_FIXTURE_BYTES, Selector, Surface};
use anyhow::{Context, Result, bail};
use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Read;
use std::path::{Component, Path};

const MAX_TOTAL_FIXTURE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_FIXTURE_OBJECTS: usize = 4096;
const MAX_PATH_BYTES: usize = 512;
const CLI_GOLDEN_DIR: &str = "crates/cli/tests/golden";
const CLI_GOLDEN_PREFIX: &str = "crates/cli/tests/golden/";
const MAX_CLI_GOLDEN_FILES: usize = 128;

pub(super) fn validate_contract_files(root: &Path, contract: &Contract) -> Result<()> {
    let mut total_bytes = 0u64;
    let mut counted_fixtures = BTreeSet::new();
    for surface in &contract.surfaces {
        validate_surface_files(
            root,
            contract,
            surface,
            &mut total_bytes,
            &mut counted_fixtures,
        )?;
    }
    validate_cli_fixture_inventory(root, contract)?;
    validate_selector_coverage(root, contract)
}

pub(super) fn validate_cli_fixture_inventory(root: &Path, contract: &Contract) -> Result<()> {
    let cli_surfaces = contract.surfaces.iter().filter(|surface| {
        surface.id == "cli.machine-result" || surface.id.starts_with("cli.machine-stream.")
    });
    let mut declared = BTreeSet::new();
    let mut has_cli_surface = false;
    for surface in cli_surfaces {
        has_cli_surface = true;
        for fixture in &surface.fixtures {
            if !fixture.path.starts_with(CLI_GOLDEN_PREFIX) {
                bail!(
                    "CLI machine fixture `{}` is outside `{CLI_GOLDEN_DIR}`",
                    fixture.path
                );
            }
            declared.insert(fixture.path.clone());
        }
    }
    if !has_cli_surface {
        return Ok(());
    }

    let canonical_root = std::fs::canonicalize(root).context("cannot resolve repository root")?;
    let mut original_directory = canonical_root.clone();
    for component in Path::new(CLI_GOLDEN_DIR).components() {
        original_directory.push(component.as_os_str());
        let metadata = std::fs::symlink_metadata(&original_directory)
            .context("cannot inspect CLI golden fixture directory")?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("CLI golden fixture directory must contain only real directories");
        }
    }
    let directory = std::fs::canonicalize(&original_directory)
        .context("cannot resolve CLI golden fixture directory")?;
    if !directory.starts_with(&canonical_root) || !directory.is_dir() {
        bail!("CLI golden fixture directory escapes the repository root");
    }
    let mut actual = BTreeSet::new();
    for entry in std::fs::read_dir(&directory).context("cannot enumerate CLI golden fixtures")? {
        let entry = entry.context("cannot inspect CLI golden fixture entry")?;
        if !entry
            .file_type()
            .context("cannot inspect CLI golden fixture type")?
            .is_file()
        {
            bail!(
                "CLI golden fixture entry `{}` is not a regular file",
                entry.path().display()
            );
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("CLI golden fixture name is not UTF-8"))?;
        if !name.ends_with(".json") && !name.ends_with(".jsonl") {
            continue;
        }
        if actual.len() >= MAX_CLI_GOLDEN_FILES {
            bail!("CLI golden fixture inventory exceeds {MAX_CLI_GOLDEN_FILES} files");
        }
        actual.insert(format!("{CLI_GOLDEN_PREFIX}{name}"));
    }
    if actual != declared {
        bail!(
            "CLI machine golden inventory differs from the compatibility manifest: declared {declared:?}, files {actual:?}"
        );
    }
    Ok(())
}

fn validate_surface_files(
    root: &Path,
    contract: &Contract,
    surface: &Surface,
    total_bytes: &mut u64,
    counted_fixtures: &mut BTreeSet<String>,
) -> Result<()> {
    let active_fields = surface
        .fields
        .iter()
        .map(|field| field.name.as_str())
        .collect::<BTreeSet<_>>();
    let required_active_fields = surface
        .fields
        .iter()
        .filter(|field| !field.optional)
        .map(|field| field.name.as_str())
        .collect::<BTreeSet<_>>();
    let expected = surface
        .fields
        .iter()
        .map(|field| field.name.clone())
        .chain(
            surface
                .compatibility_shims
                .iter()
                .map(|shim| shim.old_field.clone()),
        )
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    let mut fixture_objects_by_path = BTreeMap::new();
    for fixture in &surface.fixtures {
        let bytes = read_bounded(root, &fixture.path, MAX_FIXTURE_BYTES)?;
        if counted_fixtures.insert(fixture.path.clone()) {
            *total_bytes = total_bytes
                .checked_add(bytes.len() as u64)
                .context("compatibility fixture byte count overflowed")?;
            if *total_bytes > MAX_TOTAL_FIXTURE_BYTES {
                bail!("schema-compatibility fixtures exceed the 8 MiB aggregate limit");
            }
        }
        let objects = surface_fixture_objects(
            &bytes,
            fixture.format,
            &fixture.path,
            surface.selector.as_ref(),
        )?;
        for object in &objects {
            if let Some(version_field) = &surface.version_field {
                let actual_version = object
                    .get(version_field)
                    .and_then(serde_json::Value::as_u64);
                if actual_version != Some(u64::from(fixture.schema_version)) {
                    bail!(
                        "fixture `{}` is not pinned to schema version {}",
                        fixture.path,
                        fixture.schema_version
                    );
                }
            }
            if fixture.schema_version == surface.current_version {
                let current_fields = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
                if !required_active_fields.is_subset(&current_fields)
                    || !current_fields.is_subset(&active_fields)
                {
                    bail!(
                        "current fixture `{}` does not have the required active `{}` field shape",
                        fixture.path,
                        surface.id
                    );
                }
            }
            actual.extend(object.keys().cloned());
        }
        fixture_objects_by_path.insert(fixture.path.as_str(), (fixture, objects));
    }
    let required = surface
        .fields
        .iter()
        .filter(|field| !field.optional)
        .map(|field| field.name.as_str())
        .chain(
            surface
                .compatibility_shims
                .iter()
                .map(|shim| shim.old_field.as_str()),
        )
        .collect::<BTreeSet<_>>();
    let actual_names = actual.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let expected_names = expected.iter().map(String::as_str).collect::<BTreeSet<_>>();
    if !required.is_subset(&actual_names) || !actual_names.is_subset(&expected_names) {
        bail!(
            "schema surface `{}` fixture fields differ from its declared fields: declared {expected:?}, fixtures {actual:?}",
            surface.id
        );
    }
    for shim in &surface.compatibility_shims {
        let affected = fixture_objects_by_path
            .iter()
            .filter(|(_, (_, objects))| {
                objects
                    .iter()
                    .any(|object| object.contains_key(&shim.old_field))
            })
            .map(|(path, _)| *path)
            .collect::<BTreeSet<_>>();
        let declared = shim
            .fixtures
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if declared != affected {
            bail!(
                "shim `{}.{}` fixture coverage is not exhaustive: declared {declared:?}, affected {affected:?}",
                surface.id,
                shim.old_field
            );
        }
        for path in &shim.fixtures {
            let (fixture, objects) = fixture_objects_by_path
                .get(path.as_str())
                .context("shim fixture disappeared during validation")?;
            for object in objects {
                if !object.contains_key(&shim.old_field) {
                    bail!(
                        "shim fixture `{path}` has a selected record without old field `{}`",
                        shim.old_field
                    );
                }
                let mut canonical_target = object.clone();
                let old = canonical_target
                    .remove(&shim.old_field)
                    .expect("the shimmed object was just checked for its old field");
                if let Some(replacement) = &shim.replacement {
                    if canonical_target.contains_key(replacement) {
                        bail!(
                            "shim `{}.{}` would overwrite existing replacement field `{replacement}` in fixture `{path}`",
                            surface.id,
                            shim.old_field
                        );
                    }
                    canonical_target.insert(replacement.clone(), old);
                }
                if let Some(version_field) = &surface.version_field {
                    canonical_target.insert(
                        version_field.clone(),
                        serde_json::Value::from(shim.target_version),
                    );
                }
                let migrated = super::migrations::apply(
                    &shim.migrator,
                    &surface.id,
                    fixture.schema_version,
                    shim.target_version,
                    serde_json::Value::Object(object.clone()),
                )?;
                if migrated != serde_json::Value::Object(canonical_target) {
                    bail!(
                        "registered migrator `{}` did not preserve the canonical removal/rename semantics for `{}` source fixture `{path}`",
                        shim.migrator,
                        surface.id
                    );
                }
                let migrated = migrated.as_object().with_context(|| {
                    format!(
                        "registered migrator `{}` did not produce an object",
                        shim.migrator
                    )
                })?;
                let migrated_fields = migrated.keys().map(String::as_str).collect::<BTreeSet<_>>();
                let target_fields = shim
                    .target_fields
                    .iter()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>();
                if migrated_fields != target_fields {
                    bail!(
                        "registered migrator `{}` did not produce the frozen target field shape for `{}`",
                        shim.migrator,
                        surface.id
                    );
                }
                if let Some(selector) = &surface.selector
                    && !selector_matches(migrated, selector)
                {
                    bail!(
                        "registered migrator `{}` changed the immutable selector for `{}`",
                        shim.migrator,
                        surface.id
                    );
                }
                if let Some(version_field) = &surface.version_field
                    && migrated
                        .get(version_field)
                        .and_then(serde_json::Value::as_u64)
                        != Some(u64::from(shim.target_version))
                {
                    bail!(
                        "registered migrator `{}` did not stamp schema version {}",
                        shim.migrator,
                        shim.target_version
                    );
                }
            }
        }
        let elapsed = contract
            .release_ordinal
            .saturating_sub(shim.deprecated_release);
        if elapsed < contract.minimum_deprecation_releases {
            bail!(
                "shim `{}.{}` has not completed the {}-release runway",
                surface.id,
                shim.old_field,
                contract.minimum_deprecation_releases
            );
        }
    }
    Ok(())
}

fn validate_selector_coverage(root: &Path, contract: &Contract) -> Result<()> {
    let mut selected_files: BTreeMap<String, (FixtureFormat, Vec<Selector>)> = BTreeMap::new();
    for surface in &contract.surfaces {
        let Some(selector) = &surface.selector else {
            continue;
        };
        for fixture in &surface.fixtures {
            let entry = selected_files
                .entry(fixture.path.clone())
                .or_insert_with(|| (fixture.format, Vec::new()));
            if entry.0 != fixture.format {
                bail!(
                    "selected fixture `{}` is declared with conflicting formats",
                    fixture.path
                );
            }
            entry.1.push(selector.clone());
        }
    }

    for (path, (format, selectors)) in selected_files {
        let bytes = read_bounded(root, &path, MAX_FIXTURE_BYTES)?;
        for (index, object) in fixture_objects(&bytes, format, &path)?
            .into_iter()
            .enumerate()
        {
            let matches = selectors
                .iter()
                .filter(|selector| selector_matches(&object, selector))
                .count();
            if matches != 1 {
                bail!(
                    "selected fixture `{path}` object {} matches {matches} schema surfaces; expected exactly one",
                    index + 1
                );
            }
        }
    }
    Ok(())
}

fn surface_fixture_objects(
    bytes: &[u8],
    format: FixtureFormat,
    path: &str,
    selector: Option<&Selector>,
) -> Result<Vec<serde_json::Map<String, serde_json::Value>>> {
    let objects = fixture_objects(bytes, format, path)?;
    let Some(selector) = selector else {
        return Ok(objects);
    };
    let selected = objects
        .into_iter()
        .filter(|object| selector_matches(object, selector))
        .collect::<Vec<_>>();
    if selected.is_empty() {
        bail!(
            "fixture `{path}` has no object matching selector `{}={}`",
            selector.field,
            selector.value
        );
    }
    Ok(selected)
}

fn selector_matches(
    object: &serde_json::Map<String, serde_json::Value>,
    selector: &Selector,
) -> bool {
    object
        .get(&selector.field)
        .and_then(serde_json::Value::as_str)
        == Some(selector.value.as_str())
}

pub(super) fn parse_json_no_duplicates(bytes: &[u8]) -> serde_json::Result<serde_json::Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = FixtureValueSeed.deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

struct FixtureValueSeed;

impl<'de> DeserializeSeed<'de> for FixtureValueSeed {
    type Value = serde_json::Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(FixtureValueVisitor)
    }
}

struct FixtureValueVisitor;

impl<'de> Visitor<'de> for FixtureValueVisitor {
    type Value = serde_json::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a frozen JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(value.into())
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(value.into())
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(value.into())
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .ok_or_else(|| E::custom("JSON number is not finite"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(value.into())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(value.into())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(FixtureValueSeed)? {
            values.push(value);
        }
        Ok(serde_json::Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(A::Error::custom(format!(
                    "duplicate JSON object key '{key}'"
                )));
            }
            values.insert(key, map.next_value_seed(FixtureValueSeed)?);
        }
        Ok(serde_json::Value::Object(values))
    }
}

fn fixture_objects(
    bytes: &[u8],
    format: FixtureFormat,
    path: &str,
) -> Result<Vec<serde_json::Map<String, serde_json::Value>>> {
    let values = match format {
        FixtureFormat::Json => vec![
            parse_json_no_duplicates(bytes)
                .with_context(|| format!("fixture `{path}` is invalid JSON"))?,
        ],
        FixtureFormat::Jsonl => {
            let text = std::str::from_utf8(bytes)
                .with_context(|| format!("fixture `{path}` is not UTF-8 JSONL"))?;
            let mut values = Vec::new();
            for (index, line) in text.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                if values.len() >= MAX_FIXTURE_OBJECTS {
                    bail!("fixture `{path}` exceeds {MAX_FIXTURE_OBJECTS} JSONL objects");
                }
                values.push(parse_json_no_duplicates(line.as_bytes()).with_context(|| {
                    format!("fixture `{path}` line {} is invalid JSON", index + 1)
                })?);
            }
            values
        }
    };
    if values.is_empty() {
        bail!("fixture `{path}` contains no JSON objects");
    }
    values
        .into_iter()
        .map(|value| match value {
            serde_json::Value::Object(object) => Ok(object),
            _ => bail!("fixture `{path}` must contain only top-level JSON objects"),
        })
        .collect()
}

pub(super) fn read_bounded(root: &Path, relative: &str, limit: u64) -> Result<Vec<u8>> {
    validate_repo_path(relative)?;
    let root = std::fs::canonicalize(root).context("cannot resolve repository root")?;
    let mut path = root.clone();
    let components = Path::new(relative).components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        path.push(component.as_os_str());
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("cannot inspect compatibility path `{relative}`"))?;
        if metadata.file_type().is_symlink() {
            bail!("compatibility path `{relative}` contains a symbolic link");
        }
        if index + 1 == components.len() {
            if !metadata.is_file() || metadata.len() > limit {
                bail!(
                    "compatibility file `{relative}` is not a regular file within its byte limit"
                );
            }
        } else if !metadata.is_dir() {
            bail!("compatibility path `{relative}` has a non-directory parent");
        }
    }
    let resolved = std::fs::canonicalize(&path)
        .with_context(|| format!("cannot resolve compatibility file `{relative}`"))?;
    if !resolved.starts_with(&root) {
        bail!("compatibility file `{relative}` escapes the repository root");
    }
    let file = std::fs::File::open(&resolved)
        .with_context(|| format!("cannot open compatibility file `{relative}`"))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("cannot inspect compatibility file `{relative}`"))?;
    if !metadata.is_file() || metadata.len() > limit {
        bail!("compatibility file `{relative}` is not a regular file within its byte limit");
    }
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read compatibility file `{relative}`"))?;
    if bytes.len() as u64 > limit {
        bail!("compatibility file `{relative}` exceeds its byte limit while being read");
    }
    Ok(bytes)
}

pub(super) fn validate_fixture_path(path: &str) -> Result<()> {
    validate_repo_path(path)?;
    if !path.starts_with("governance/schema-compat/fixtures/")
        && !path.starts_with("crates/cli/tests/golden/")
    {
        bail!("compatibility fixture `{path}` is outside an admitted frozen-fixture directory");
    }
    Ok(())
}

pub(super) fn validate_repo_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || !path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
        || path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        bail!("invalid repository-relative compatibility path `{path}`");
    }
    if Path::new(path)
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("compatibility path `{path}` is not a normalized repository-relative path");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn d13_14_every_frozen_fixture_parser_rejects_duplicate_keys_at_any_depth() {
        for (bytes, format) in [
            (
                br#"{"type":"sample","nested":{"value":1,"value":2}}"#.as_slice(),
                FixtureFormat::Json,
            ),
            (
                br#"{"type":"sample","type":"other"}\n"#.as_slice(),
                FixtureFormat::Jsonl,
            ),
        ] {
            let error = fixture_objects(bytes, format, "fixture.json")
                .expect_err("duplicate fixture keys must fail closed");
            assert!(error.to_string().contains("invalid JSON"));
            assert!(format!("{error:#}").contains("duplicate JSON object key"));
        }

        assert!(
            fixture_objects(
                br#"{"type":"sample","nested":[{"value":1}]}"#,
                FixtureFormat::Json,
                "fixture.json",
            )
            .is_ok()
        );
    }
}
