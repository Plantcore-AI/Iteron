use super::super::manifest::{Contract, read_bounded};
use super::parse::{named_struct_fields, serde_snake_case};
use super::record_types::{
    ProtocolTypeInventory, named_struct_type_identifiers, protocol_type_inventory,
    tagged_enum_type_identifiers,
};
use super::{
    BLOCK_SIGNATURE, BLOCK_SOURCE, COST_ATTRIBUTION_SIGNATURE, COST_ATTRIBUTION_SOURCE,
    EVENT_KIND_SIGNATURE, EVENT_SOURCE, KERNEL_DIAGNOSTIC_SOURCE, MAX_SOURCE_BYTES,
    NAMED_RECORD_SHAPES, NAMED_RECORD_SURFACE_PREFIX, OP_SIGNATURE, OP_SOURCE,
    WORKFLOW_EVENT_SIGNATURE,
};
use crate::rust_source::{SerdeAuthority, require_serde_authority};
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub(super) fn source_shape(surface: &str) -> Option<(&'static str, &'static str)> {
    if let Some((_, source, signature)) =
        NAMED_RECORD_SHAPES.iter().find(|(id, _, _)| *id == surface)
    {
        return Some((*source, *signature));
    }
    match surface {
        "protocol.sq-envelope" => Some(("crates/protocol/src/wire.rs", "pub struct SqEnvelope {")),
        "protocol.eq-envelope" => Some(("crates/protocol/src/wire.rs", "pub struct EqEnvelope {")),
        "record.rollout" => Some(("crates/record/src/lib.rs", "struct ChainLine {")),
        "record.event-envelope" => Some((EVENT_SOURCE, "pub struct Event {")),
        "kernel.diagnostic" => Some((
            KERNEL_DIAGNOSTIC_SOURCE,
            "pub struct KernelDiagnosticEnvelope {",
        )),
        _ => None,
    }
}

pub(super) fn validate_named_record_inventory(root: &Path, contract: &Contract) -> Result<()> {
    let declared = contract
        .surfaces
        .iter()
        .filter(|surface| surface.id.starts_with(NAMED_RECORD_SURFACE_PREFIX))
        .map(|surface| surface.id.clone())
        .collect::<BTreeSet<_>>();
    if declared.is_empty() && !root.join("crates/protocol/src").is_dir() {
        return Ok(());
    }
    let discovered = named_record_type_closure(root)?;
    let expected = discovered.keys().cloned().collect::<BTreeSet<_>>();
    if declared != expected {
        bail!(
            "named record compatibility surfaces are not source-complete: declared {declared:?}, expected {expected:?}"
        );
    }
    for surface in contract
        .surfaces
        .iter()
        .filter(|surface| surface.id.starts_with(NAMED_RECORD_SURFACE_PREFIX))
    {
        if surface.selector.is_some()
            || surface.version_field.is_some()
            || !surface.compatibility_shims.is_empty()
        {
            bail!(
                "named record surface `{}` is versionless nested inventory and cannot carry a selector, version field, or local compatibility shim; evolve it through retained top-level tagged variants",
                surface.id
            );
        }
        let (source_path, signature) = discovered
            .get(&surface.id)
            .expect("declared named inventory equals discovered closure");
        let source = read_bounded(root, source_path, MAX_SOURCE_BYTES)?;
        let source = std::str::from_utf8(&source)
            .with_context(|| format!("schema source `{source_path}` is not UTF-8"))?;
        require_serde_authority(source, signature, SerdeAuthority::Both)?;
        let actual = named_struct_fields(source, signature)?;
        let declared = surface
            .fields
            .iter()
            .map(|field| field.name.clone())
            .collect::<BTreeSet<_>>();
        if actual != declared {
            bail!(
                "named record surface `{}` differs from its dynamically discovered Rust struct: source {actual:?}, declared {declared:?}",
                surface.id
            );
        }
    }
    Ok(())
}

pub(super) fn validate_record_tagged_family(
    contract: &Contract,
    prefix: &str,
    selector_field: &str,
    family: &str,
    emitted: BTreeMap<String, BTreeSet<String>>,
) -> Result<()> {
    let mut declared = BTreeMap::new();
    for surface in contract
        .surfaces
        .iter()
        .filter(|surface| surface.id.starts_with(prefix))
    {
        if surface.version_field.is_some() || !surface.compatibility_shims.is_empty() {
            bail!(
                "record {family} surface `{}` is versionless nested inventory and cannot carry a version field or local compatibility shim; evolve it through retained top-level tagged variants",
                surface.id
            );
        }
        let id_tag = surface
            .id
            .strip_prefix(prefix)
            .expect("filtered record surface has its prefix");
        let selector = surface.selector.as_ref().with_context(|| {
            format!("record {family} surface `{}` lacks a selector", surface.id)
        })?;
        if selector.field != selector_field || selector.value != id_tag {
            bail!(
                "record {family} surface `{}` must select `{selector_field}={id_tag}`",
                surface.id
            );
        }
        let fields = surface
            .fields
            .iter()
            .map(|field| field.name.clone())
            .collect::<BTreeSet<_>>();
        if declared.insert(selector.value.clone(), fields).is_some() {
            bail!("record {family} compatibility surfaces repeat a wire tag");
        }
    }
    if emitted != declared {
        bail!(
            "record {family} Rust shapes differ from compatibility surfaces: emitted {emitted:?}, declared {declared:?}"
        );
    }
    Ok(())
}

fn named_record_type_closure(root: &Path) -> Result<BTreeMap<String, (String, String)>> {
    let ProtocolTypeInventory {
        definitions,
        leaves,
        aliases,
        sources,
        origins: _,
    } = protocol_type_inventory(root)?;
    let mut selected = BTreeMap::new();
    let mut pending = BTreeSet::new();
    let mut resolved = BTreeSet::new();

    for (surface_id, source_path, signature) in NAMED_RECORD_SHAPES {
        let name = named_struct_name(signature)?;
        let derived = named_surface_id(&name)?;
        if derived != *surface_id {
            bail!(
                "explicit named record root '{surface_id}' does not match derived id '{derived}'"
            );
        }
        let definition = definitions
            .get(&name)
            .with_context(|| format!("protocol source inventory lacks named struct '{name}'"))?;
        if definition.path != *source_path || definition.signature != *signature {
            bail!("named record root '{surface_id}' no longer resolves to its asserted source");
        }
        if selected.insert(name.clone(), definition.clone()).is_some() {
            bail!("named record roots repeat Rust struct '{name}'");
        }
        pending.extend(named_struct_type_identifiers(
            sources
                .get(*source_path)
                .expect("protocol inventory retains every source"),
            signature,
        )?);
    }

    for (source_path, signature) in [
        (OP_SOURCE, OP_SIGNATURE),
        (EVENT_SOURCE, EVENT_KIND_SIGNATURE),
        (BLOCK_SOURCE, BLOCK_SIGNATURE),
        (EVENT_SOURCE, WORKFLOW_EVENT_SIGNATURE),
        (COST_ATTRIBUTION_SOURCE, COST_ATTRIBUTION_SIGNATURE),
    ] {
        let source = sources.get(source_path).with_context(|| {
            format!("protocol source inventory lacks tagged root '{source_path}'")
        })?;
        pending.extend(tagged_enum_type_identifiers(source, signature)?);
    }

    while let Some(name) = pending.pop_first() {
        if !resolved.insert(name.clone()) {
            continue;
        }
        if let Some(definition) = definitions.get(&name) {
            if selected.contains_key(&name) {
                continue;
            }
            selected.insert(name.clone(), definition.clone());
            pending.extend(named_struct_type_identifiers(
                sources
                    .get(&definition.path)
                    .expect("protocol inventory retains every source"),
                &definition.signature,
            )?);
            continue;
        }
        if let Some(identifiers) = aliases.get(&name) {
            pending.extend(identifiers.iter().cloned());
            continue;
        }
        if leaves.contains(&name)
            || matches!(
                name.as_str(),
                "BTreeMap" | "Box" | "Option" | "String" | "Value" | "Vec"
            )
        {
            continue;
        }
        bail!("reachable protocol record type '{name}' has no fail-closed source classification");
    }

    let mut by_surface = BTreeMap::new();
    for (name, definition) in selected {
        let surface_id = named_surface_id(&name)?;
        if by_surface
            .insert(surface_id.clone(), (definition.path, definition.signature))
            .is_some()
        {
            bail!("protocol named structs collide on derived surface '{surface_id}'");
        }
    }
    Ok(by_surface)
}

fn named_struct_name(signature: &str) -> Result<String> {
    let name = signature
        .strip_prefix("pub struct ")
        .and_then(|value| value.strip_suffix(" {"))
        .context("named record signature is not one public named struct")?;
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        bail!("named record signature has an invalid Rust identifier");
    }
    Ok(name.to_owned())
}

fn named_surface_id(name: &str) -> Result<String> {
    let kebab = serde_snake_case(name).replace('_', "-");
    if kebab.is_empty()
        || !kebab
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        bail!("cannot derive one named record surface from Rust struct '{name}'");
    }
    Ok(format!("{NAMED_RECORD_SURFACE_PREFIX}{kebab}"))
}

#[cfg(test)]
mod tests {
    use super::super::super::manifest::read_bounded;
    use super::super::parse::{named_struct_fields, tagged_enum_fields};
    use super::super::{
        BLOCK_SIGNATURE, BLOCK_SOURCE, BLOCK_SURFACE_PREFIX, COST_ATTRIBUTION_SIGNATURE,
        COST_ATTRIBUTION_SOURCE, COST_ATTRIBUTION_SURFACE_PREFIX, EVENT_SOURCE, MAX_SOURCE_BYTES,
        NAMED_RECORD_SHAPES, NAMED_RECORD_SURFACE_PREFIX, WORKFLOW_EVENT_SIGNATURE,
        WORKFLOW_EVENT_SURFACE_PREFIX, validate_record_payload_shapes,
    };
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path;

    #[test]
    fn d13_14_record_payload_source_inventories_are_exact() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask is directly below the repository root");
        let block_source = read_bounded(root, BLOCK_SOURCE, MAX_SOURCE_BYTES).unwrap();
        let block_text = std::str::from_utf8(&block_source).unwrap();
        let tool_source =
            read_bounded(root, "crates/protocol/src/tool.rs", MAX_SOURCE_BYTES).unwrap();
        let tool_text = std::str::from_utf8(&tool_source).unwrap();
        let newtypes = BTreeMap::from([
            (
                "ProviderState".to_owned(),
                named_struct_fields(block_text, "pub struct ProviderState {").unwrap(),
            ),
            (
                "ToolUse".to_owned(),
                named_struct_fields(tool_text, "pub struct ToolUse {").unwrap(),
            ),
            (
                "ToolResult".to_owned(),
                named_struct_fields(tool_text, "pub struct ToolResult {").unwrap(),
            ),
        ]);
        let blocks =
            tagged_enum_fields(&block_source, BLOCK_SIGNATURE, "type", 0, &newtypes).unwrap();
        assert_eq!(blocks.len(), 5);
        assert_eq!(
            blocks["provider_state"],
            BTreeSet::from([
                "format".to_owned(),
                "payload".to_owned(),
                "route_scope".to_owned(),
                "type".to_owned(),
            ])
        );

        let event_source = read_bounded(root, EVENT_SOURCE, MAX_SOURCE_BYTES).unwrap();
        let workflow = tagged_enum_fields(
            &event_source,
            WORKFLOW_EVENT_SIGNATURE,
            "event",
            0,
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(workflow.len(), 7);
        assert!(workflow["child_finished"].contains("evidence_bytes"));

        let pricing_source = read_bounded(root, COST_ATTRIBUTION_SOURCE, MAX_SOURCE_BYTES).unwrap();
        let attribution = tagged_enum_fields(
            &pricing_source,
            COST_ATTRIBUTION_SIGNATURE,
            "kind",
            0,
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(attribution.len(), 2);
        assert_eq!(
            attribution["workflow_child"],
            BTreeSet::from([
                "kind".to_owned(),
                "parent_run_id".to_owned(),
                "sub_run".to_owned(),
                "task_id".to_owned(),
                "workflow_id".to_owned(),
            ])
        );
    }

    #[test]
    fn d13_14_named_record_source_inventory_handles_live_multiline_attributes() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask is directly below the repository root");
        assert_eq!(NAMED_RECORD_SHAPES.len(), 18);
        for (_, source_path, signature) in NAMED_RECORD_SHAPES {
            let source = read_bounded(root, source_path, MAX_SOURCE_BYTES).unwrap();
            let source = std::str::from_utf8(&source).unwrap();
            assert!(!named_struct_fields(source, signature).unwrap().is_empty());
        }
        let event_source = read_bounded(root, EVENT_SOURCE, MAX_SOURCE_BYTES).unwrap();
        assert_eq!(
            named_struct_fields(
                std::str::from_utf8(&event_source).unwrap(),
                "pub struct WorkflowCostEvidence {",
            )
            .unwrap(),
            BTreeSet::from([
                "amount_microusd".to_owned(),
                "projections".to_owned(),
                "rate_card_digest".to_owned(),
            ])
        );

        let future = "pub struct Root {\n    payload: Option<NewStruct>,\n}\n";
        let references = named_struct_type_identifiers(future, "pub struct Root {").unwrap();
        assert!(references.contains("NewStruct"));
        let tagged_future = "#[serde(tag = \"kind\", rename_all = \"snake_case\")]\npub enum Root {\n    Future { payload: Vec<NewStruct> },\n}\n";
        assert!(
            tagged_enum_type_identifiers(tagged_future, "pub enum Root {")
                .unwrap()
                .contains("NewStruct")
        );
        assert_eq!(
            named_surface_id("NewStruct").unwrap(),
            "record.named.new-struct"
        );
    }

    #[test]
    fn d13_14_versionless_nested_surfaces_reject_local_shims() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask is directly below the repository root");
        let base = super::super::super::manifest::load_candidate(root).unwrap();
        let shim = super::super::super::manifest::CompatibilityShim {
            old_field: "legacy".to_owned(),
            replacement: None,
            deprecated_release: 1,
            target_version: 2,
            target_fields: Vec::new(),
            fixtures: Vec::new(),
            migrator: "forbidden_nested_shim".to_owned(),
        };

        let mut named = base.clone();
        named
            .surfaces
            .iter_mut()
            .find(|surface| surface.id.starts_with(NAMED_RECORD_SURFACE_PREFIX))
            .unwrap()
            .compatibility_shims
            .push(shim.clone());
        assert!(validate_named_record_inventory(root, &named).is_err());

        let mut missing_named = base.clone();
        missing_named
            .surfaces
            .retain(|surface| surface.id != "record.named.provider-state");
        assert!(validate_named_record_inventory(root, &missing_named).is_err());

        for prefix in [
            BLOCK_SURFACE_PREFIX,
            WORKFLOW_EVENT_SURFACE_PREFIX,
            COST_ATTRIBUTION_SURFACE_PREFIX,
        ] {
            let mut contract = base.clone();
            contract
                .surfaces
                .iter_mut()
                .find(|surface| surface.id.starts_with(prefix))
                .unwrap()
                .compatibility_shims
                .push(shim.clone());
            assert!(validate_record_payload_shapes(root, &contract).is_err());
        }
    }
}
