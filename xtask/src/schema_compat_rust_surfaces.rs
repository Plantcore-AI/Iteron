use super::super::manifest::{Contract, read_bounded};
use super::cli::validate_cli_source_bindings;
use super::cli_parse::cli_machine_record_shapes;
use super::parse::{decimal_constant, named_struct_fields};
use super::record::source_shape;
use super::{
    BLOCK_SURFACE_PREFIX, CLI_MACHINE_OUTPUT_SOURCE, COST_ATTRIBUTION_SURFACE_PREFIX,
    EVENT_KIND_SURFACE_PREFIX, KERNEL_DIAGNOSTIC_SOURCE, MAX_SOURCE_BYTES,
    NAMED_RECORD_SURFACE_PREFIX, OP_SURFACE_PREFIX, WORKFLOW_EVENT_SURFACE_PREFIX,
};
use crate::rust_source::{SerdeAuthority, require_serde_authority};
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub(super) fn validate(root: &Path, contract: &Contract) -> Result<()> {
    let protocol_version = if contract.surfaces.iter().any(|surface| {
        matches!(
            surface.id.as_str(),
            "protocol.sq-envelope" | "protocol.eq-envelope"
        ) || surface.id.starts_with(OP_SURFACE_PREFIX)
    }) {
        let source = read_bounded(
            root,
            crate::validate::PROTOCOL_VERSION_SOURCE,
            MAX_SOURCE_BYTES,
        )?;
        Some(crate::validate::protocol_version_from_source(&source)?)
    } else {
        None
    };
    let cli_machine_version = if root.join(CLI_MACHINE_OUTPUT_SOURCE).is_file()
        || contract.surfaces.iter().any(|surface| {
            surface.id == "cli.machine-result" || surface.id.starts_with("cli.machine-stream.")
        }) {
        let source = read_bounded(root, CLI_MACHINE_OUTPUT_SOURCE, MAX_SOURCE_BYTES)?;
        let emitted_shapes = cli_machine_record_shapes(&source)?;
        let mut declared_shapes = BTreeMap::new();
        for surface in contract.surfaces.iter().filter(|surface| {
            surface.id == "cli.machine-result" || surface.id.starts_with("cli.machine-stream.")
        }) {
            let selector = surface.selector.as_ref().with_context(|| {
                format!("CLI machine surface `{}` lacks a selector", surface.id)
            })?;
            if selector.field != "type" {
                bail!("CLI machine surface `{}` must select on `type`", surface.id);
            }
            let fields = surface
                .fields
                .iter()
                .map(|field| field.name.clone())
                .collect::<BTreeSet<_>>();
            if declared_shapes
                .insert(selector.value.clone(), fields)
                .is_some()
            {
                bail!("CLI machine compatibility surfaces repeat a literal type");
            }
        }
        if emitted_shapes != declared_shapes {
            bail!(
                "CLI machine record shapes differ from the compatibility surfaces: emitted {emitted_shapes:?}, declared {declared_shapes:?}"
            );
        }
        validate_cli_source_bindings(root, contract, &source, &emitted_shapes)?;
        Some(decimal_constant(&source, "SCHEMA_VERSION", "u32")?)
    } else {
        None
    };
    for surface in &contract.surfaces {
        let required_version_field = match surface.id.as_str() {
            "protocol.sq-envelope" | "protocol.eq-envelope" => Some("protocol_version"),
            id if id.starts_with(OP_SURFACE_PREFIX) => None,
            "kernel.diagnostic" => Some("schema_version"),
            "cli.machine-result" => Some("schema_version"),
            id if id.starts_with("cli.machine-stream.") => Some("schema_version"),
            "record.rollout" | "record.event-envelope" => None,
            id if id.starts_with(EVENT_KIND_SURFACE_PREFIX) => None,
            id if id.starts_with(BLOCK_SURFACE_PREFIX) => None,
            id if id.starts_with(WORKFLOW_EVENT_SURFACE_PREFIX) => None,
            id if id.starts_with(COST_ATTRIBUTION_SURFACE_PREFIX) => None,
            id if id.starts_with(NAMED_RECORD_SURFACE_PREFIX) => None,
            _ => continue,
        };
        if surface.version_field.as_deref() != required_version_field {
            bail!(
                "schema surface `{}` must retain version field {required_version_field:?}",
                surface.id
            );
        }
        if (matches!(
            surface.id.as_str(),
            "protocol.sq-envelope" | "protocol.eq-envelope"
        ) || surface.id.starts_with(OP_SURFACE_PREFIX))
            && Some(surface.current_version) != protocol_version
        {
            bail!(
                "schema surface `{}` version {} must equal PROTOCOL_VERSION {}",
                surface.id,
                surface.current_version,
                protocol_version.expect("protocol surfaces load a version")
            );
        }
        if surface.id == "kernel.diagnostic" {
            let source = read_bounded(root, KERNEL_DIAGNOSTIC_SOURCE, MAX_SOURCE_BYTES)?;
            let version = decimal_constant(&source, "KERNEL_DIAGNOSTIC_SCHEMA_VERSION", "u8")?;
            if surface.current_version != version {
                bail!(
                    "schema surface `{}` version {} must equal KERNEL_DIAGNOSTIC_SCHEMA_VERSION {version}",
                    surface.id,
                    surface.current_version
                );
            }
        }
        if (surface.id == "cli.machine-result" || surface.id.starts_with("cli.machine-stream."))
            && Some(surface.current_version) != cli_machine_version
        {
            bail!(
                "schema surface `{}` version {} must equal CLI SCHEMA_VERSION {}",
                surface.id,
                surface.current_version,
                cli_machine_version.expect("CLI machine surfaces load a version")
            );
        }
        let Some((source_path, signature)) = source_shape(&surface.id) else {
            continue;
        };
        let source = read_bounded(root, source_path, MAX_SOURCE_BYTES)?;
        let source = std::str::from_utf8(&source)
            .with_context(|| format!("schema source `{source_path}` is not UTF-8"))?;
        require_serde_authority(source, signature, SerdeAuthority::Both)?;
        let actual = named_struct_fields(source, signature)?;
        let expected = surface
            .fields
            .iter()
            .map(|field| field.name.clone())
            .collect::<BTreeSet<_>>();
        if actual != expected {
            bail!(
                "Rust shape for schema surface `{}` differs from its active fields: declared {expected:?}, source {actual:?}",
                surface.id
            );
        }
        validate_optional_fields(surface, source, signature)?;
    }
    Ok(())
}

fn validate_optional_fields(
    surface: &super::super::manifest::Surface,
    source: &str,
    signature: &str,
) -> Result<()> {
    let optional = surface
        .fields
        .iter()
        .filter(|field| field.optional)
        .map(|field| field.name.as_str())
        .collect::<BTreeSet<_>>();
    if optional.is_empty() {
        return Ok(());
    }
    let struct_name = signature
        .strip_prefix("pub struct ")
        .and_then(|rest| rest.strip_suffix(" {"))
        .context("named schema signature is not a public struct")?;
    let file = syn::parse_file(source)?;
    let item = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Struct(item) if item.ident == struct_name => Some(item),
            _ => None,
        })
        .with_context(|| format!("schema source lacks `{struct_name}`"))?;
    let syn::Fields::Named(fields) = &item.fields else {
        bail!("schema struct `{struct_name}` is not named-field");
    };
    for field in &fields.named {
        let Some(identifier) = &field.ident else {
            continue;
        };
        let mut wire_name = identifier.to_string();
        let mut has_default = false;
        let mut skips_none = false;
        for attribute in field
            .attrs
            .iter()
            .filter(|attribute| attribute.path().is_ident("serde"))
        {
            attribute.parse_nested_meta(|meta| {
                if meta.path.is_ident("default") {
                    has_default = true;
                } else if meta.path.is_ident("rename") {
                    wire_name = meta.value()?.parse::<syn::LitStr>()?.value();
                } else if meta.path.is_ident("skip_serializing_if") {
                    skips_none = meta.value()?.parse::<syn::LitStr>()?.value() == "Option::is_none";
                } else if meta.input.peek(syn::Token![=]) {
                    let _: syn::Expr = meta.value()?.parse()?;
                }
                Ok(())
            })?;
        }
        if !optional.contains(wire_name.as_str()) {
            continue;
        }
        let is_option = matches!(
            &field.ty,
            syn::Type::Path(path)
                if path.path.segments.last().is_some_and(|segment| segment.ident == "Option")
        );
        if !is_option || !has_default || !skips_none {
            bail!(
                "optional schema field `{}.{wire_name}` must be Option with serde default + skip_serializing_if=Option::is_none",
                surface.id
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod optional_field_tests {
    use super::*;

    fn surface() -> super::super::super::manifest::Surface {
        serde_json::from_value(serde_json::json!({
            "id": "record.named.fixture",
            "current_version": 1,
            "version_field": null,
            "fixtures": [{
                "path": "governance/schema-compat/fixtures/test/fixture.json",
                "format": "json",
                "schema_version": 1
            }],
            "fields": [{
                "name": "value",
                "introduced_release": 1,
                "optional": true
            }],
            "compatibility_shims": []
        }))
        .unwrap()
    }

    #[test]
    fn optional_manifest_fields_require_the_byte_compatible_rust_shape() {
        let good = r#"
            pub struct Wire {
                #[serde(default, skip_serializing_if = "Option::is_none")]
                pub value: Option<u64>,
            }
        "#;
        assert!(validate_optional_fields(&surface(), good, "pub struct Wire {").is_ok());

        for bad in [
            "pub struct Wire { pub value: Option<u64> }",
            r#"pub struct Wire {
                #[serde(default, skip_serializing_if = "String::is_empty")]
                pub value: String,
            }"#,
        ] {
            assert!(validate_optional_fields(&surface(), bad, "pub struct Wire {").is_err());
        }
    }
}
