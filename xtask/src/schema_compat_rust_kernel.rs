use super::super::manifest::{Contract, read_bounded};
use super::json::parse_json_no_duplicates;
use super::parse::{tagged_enum_fields, validate_wire_identifier};
use super::{KERNEL_DIAGNOSTIC_SOURCE, MAX_SOURCE_BYTES};
use crate::rust_source::{SerdeAuthority, require_serde_authority};
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub(super) fn validate(root: &Path, contract: &Contract) -> Result<()> {
    let surface = contract
        .surfaces
        .iter()
        .find(|surface| surface.id == "kernel.diagnostic");
    if surface.is_none() && !root.join(KERNEL_DIAGNOSTIC_SOURCE).is_file() {
        return Ok(());
    }
    let surface = surface.context("kernel diagnostic source requires its compatibility surface")?;
    let source = read_bounded(root, KERNEL_DIAGNOSTIC_SOURCE, MAX_SOURCE_BYTES)?;
    let source_text = std::str::from_utf8(&source)
        .with_context(|| format!("schema source `{KERNEL_DIAGNOSTIC_SOURCE}` is not UTF-8"))?;
    require_serde_authority(
        source_text,
        "pub enum KernelDiagnostic {",
        SerdeAuthority::Both,
    )?;
    crate::rust_source::require_serde_container_flag(
        source_text,
        "pub enum KernelDiagnostic {",
        "deny_unknown_fields",
    )?;
    let emitted = tagged_enum_fields(
        &source,
        "pub enum KernelDiagnostic {",
        "code",
        0,
        &BTreeMap::new(),
    )?;
    let declared_codes =
        crate::rust_source::public_string_array_const(&source, "KERNEL_DIAGNOSTIC_CODES")?;
    for code in &declared_codes {
        validate_wire_identifier("kernel diagnostic code", code)?;
    }
    let declared_codes = declared_codes.into_iter().collect::<BTreeSet<_>>();
    if emitted.keys().cloned().collect::<BTreeSet<_>>() != declared_codes {
        bail!("KERNEL_DIAGNOSTIC_CODES differs from the serialized diagnostic enum");
    }

    let mut fixture_shapes = BTreeMap::new();
    for fixture in surface
        .fixtures
        .iter()
        .filter(|fixture| fixture.schema_version == surface.current_version)
    {
        let bytes = read_bounded(root, &fixture.path, MAX_SOURCE_BYTES)?;
        let value = parse_json_no_duplicates(std::str::from_utf8(&bytes).with_context(|| {
            format!("kernel diagnostic fixture '{}' is not UTF-8", fixture.path)
        })?)?;
        let diagnostic = value
            .as_object()
            .and_then(|object| object.get("diagnostic"))
            .and_then(serde_json::Value::as_object)
            .with_context(|| {
                format!(
                    "kernel diagnostic fixture '{}' lacks a diagnostic object",
                    fixture.path
                )
            })?;
        let code = diagnostic
            .get("code")
            .and_then(serde_json::Value::as_str)
            .with_context(|| {
                format!("kernel diagnostic fixture '{}' lacks a code", fixture.path)
            })?;
        let fields = diagnostic.keys().cloned().collect::<BTreeSet<_>>();
        if fixture_shapes.insert(code.to_owned(), fields).is_some() {
            bail!("current kernel diagnostic fixtures repeat code '{code}'");
        }
    }
    if fixture_shapes != emitted {
        bail!(
            "kernel diagnostic source shapes differ from current fixtures: source {emitted:?}, fixtures {fixture_shapes:?}"
        );
    }
    Ok(())
}
