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
    }
    Ok(())
}
