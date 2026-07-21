use super::super::super::manifest::{Contract, Surface};
use super::graph::{
    ProtocolGraph, SourceView, file_attribute_fingerprints, import_fingerprints,
    module_fingerprints,
};
use super::serde_attrs::{
    attributes as serde_attributes, flag as serde_flag, rename as serde_rename,
    snake_case as serde_snake_case,
};
use anyhow::{Context, Result, bail};
use quote::ToTokens;
use std::collections::{BTreeMap, BTreeSet};

const RECORD_SOURCE: &str = "crates/record/src/lib.rs";
const KERNEL_SOURCE: &str = "crates/kernel/src/diagnostics.rs";

#[derive(Debug, PartialEq, Eq)]
struct FieldSemantic {
    ty: String,
    serde_attributes: Vec<String>,
}

#[derive(Debug)]
struct NamedShape {
    container_serde: Vec<String>,
    fields: BTreeMap<String, FieldSemantic>,
}

#[derive(Debug)]
struct EnumShape {
    container_serde: Vec<String>,
    variants: BTreeMap<String, VariantSemantic>,
}

#[derive(Debug)]
struct VariantSemantic {
    serde_attributes: Vec<String>,
    fields: VariantFields,
}

#[derive(Debug)]
enum VariantFields {
    Unit,
    Named(BTreeMap<String, FieldSemantic>),
    Unnamed(Vec<FieldSemantic>),
}

pub(super) fn compare_surfaces(
    base_view: SourceView<'_>,
    candidate_view: SourceView<'_>,
    base_graph: &ProtocolGraph,
    candidate_graph: &ProtocolGraph,
    previous: &Contract,
    candidate: &Contract,
) -> Result<()> {
    let candidate_surfaces = candidate
        .surfaces
        .iter()
        .map(|surface| (surface.id.as_str(), surface))
        .collect::<BTreeMap<_, _>>();
    let mut compared_enum_containers = BTreeSet::new();
    let mut standalone_imports = BTreeSet::new();

    for old_surface in &previous.surfaces {
        let new_surface = candidate_surfaces
            .get(old_surface.id.as_str())
            .with_context(|| format!("schema surface '{}' was removed", old_surface.id))?;
        if let Some(type_name) = named_surface_type(base_graph, old_surface)? {
            let candidate_type = named_surface_type(candidate_graph, new_surface)?
                .context("candidate named surface lost its Rust type")?;
            if candidate_type != type_name {
                bail!(
                    "schema surface '{}' redirected from Rust type '{type_name}' to '{candidate_type}'",
                    old_surface.id
                );
            }
            let base_item = base_graph.item(&type_name)?;
            let candidate_item = candidate_graph.item(&type_name)?;
            compare_named_surface(old_surface, new_surface, base_item, candidate_item)?;
            continue;
        }
        if let Some((path, item_name)) = standalone_named_surface(&old_surface.id) {
            compare_standalone_imports_once(
                path,
                base_view,
                candidate_view,
                &mut standalone_imports,
            )?;
            let base_file = base_view.parse_file(path)?;
            let candidate_file = candidate_view.parse_file(path)?;
            compare_named_surface(
                old_surface,
                new_surface,
                unique_type(&base_file, item_name)?,
                unique_type(&candidate_file, item_name)?,
            )?;
            continue;
        }
        let Some((type_name, _tag)) = tagged_surface(&old_surface.id) else {
            continue;
        };
        if compared_enum_containers.insert(type_name) {
            let base = enum_shape(base_graph.item(type_name)?)?;
            let current = enum_shape(candidate_graph.item(type_name)?)?;
            compare_container(type_name, &base, &current)?;
        }
        compare_tagged_surface(
            old_surface,
            new_surface,
            base_graph.item(type_name)?,
            candidate_graph.item(type_name)?,
        )?;
    }

    if previous
        .surfaces
        .iter()
        .any(|surface| surface.id == "kernel.diagnostic")
    {
        compare_standalone_imports_once(
            KERNEL_SOURCE,
            base_view,
            candidate_view,
            &mut standalone_imports,
        )?;
        let base = base_view.parse_file(KERNEL_SOURCE)?;
        let current = candidate_view.parse_file(KERNEL_SOURCE)?;
        compare_retained_enum(
            "KernelDiagnostic",
            unique_type(&base, "KernelDiagnostic")?,
            unique_type(&current, "KernelDiagnostic")?,
        )?;
    }
    Ok(())
}

fn named_surface_type(graph: &ProtocolGraph, surface: &Surface) -> Result<Option<String>> {
    let name = match surface.id.as_str() {
        "protocol.sq-envelope" => Some("SqEnvelope".to_owned()),
        "protocol.eq-envelope" => Some("EqEnvelope".to_owned()),
        "record.event-envelope" => Some("Event".to_owned()),
        id if id.starts_with("record.named.") => Some(graph.named_surface_type(id)?),
        _ => None,
    };
    Ok(name)
}

fn standalone_named_surface(surface: &str) -> Option<(&'static str, &'static str)> {
    match surface {
        "record.rollout" => Some((RECORD_SOURCE, "ChainLine")),
        "kernel.diagnostic" => Some((KERNEL_SOURCE, "KernelDiagnosticEnvelope")),
        _ => None,
    }
}

fn tagged_surface(surface: &str) -> Option<(&'static str, &'static str)> {
    if surface.starts_with("protocol.op.") {
        Some(("Op", "op"))
    } else if surface.starts_with("record.event-kind.") {
        Some(("EventKind", "kind"))
    } else if surface.starts_with("record.block.") {
        Some(("Block", "type"))
    } else if surface.starts_with("record.workflow-event.") {
        Some(("WorkflowEvent", "event"))
    } else if surface.starts_with("record.cost-attribution.") {
        Some(("CostAttribution", "kind"))
    } else {
        None
    }
}

fn compare_named_surface(
    old_surface: &Surface,
    new_surface: &Surface,
    base_item: &syn::Item,
    candidate_item: &syn::Item,
) -> Result<()> {
    let base = named_shape(base_item)?;
    let current = named_shape(candidate_item)?;
    if base.container_serde != current.container_serde {
        bail!(
            "schema surface '{}' changed its serde container semantics",
            old_surface.id
        );
    }
    let retained = retained_fields(old_surface, new_surface);
    for name in retained {
        let old_field = base.fields.get(name).with_context(|| {
            format!(
                "base Rust shape for '{}' lacks retained field '{name}'",
                old_surface.id
            )
        })?;
        let new_field = current.fields.get(name).with_context(|| {
            format!(
                "candidate Rust shape for '{}' lacks retained field '{name}'",
                old_surface.id
            )
        })?;
        if old_field != new_field {
            bail!(
                "schema surface '{}.{name}' changed its Rust type or serde field semantics",
                old_surface.id
            );
        }
    }
    Ok(())
}

fn compare_tagged_surface(
    old_surface: &Surface,
    new_surface: &Surface,
    base_item: &syn::Item,
    candidate_item: &syn::Item,
) -> Result<()> {
    let selector = old_surface
        .selector
        .as_ref()
        .with_context(|| format!("tagged surface '{}' lacks a selector", old_surface.id))?;
    let base = enum_shape(base_item)?;
    let current = enum_shape(candidate_item)?;
    let old_variant = base.variants.get(&selector.value).with_context(|| {
        format!(
            "base tagged Rust shape lacks '{}={}'",
            selector.field, selector.value
        )
    })?;
    let new_variant = current.variants.get(&selector.value).with_context(|| {
        format!(
            "candidate tagged Rust shape lacks '{}={}'",
            selector.field, selector.value
        )
    })?;
    if old_variant.serde_attributes != new_variant.serde_attributes {
        bail!(
            "tagged surface '{}' changed its serde variant semantics",
            old_surface.id
        );
    }
    compare_variant_fields(
        &old_surface.id,
        &retained_fields(old_surface, new_surface),
        Some(selector.field.as_str()),
        &old_variant.fields,
        &new_variant.fields,
    )
}

fn compare_retained_enum(
    name: &str,
    base_item: &syn::Item,
    current_item: &syn::Item,
) -> Result<()> {
    let base = enum_shape(base_item)?;
    let current = enum_shape(current_item)?;
    compare_container(name, &base, &current)?;
    for (tag, old_variant) in &base.variants {
        let new_variant = current
            .variants
            .get(tag)
            .with_context(|| format!("managed enum '{name}' removed wire variant '{tag}'"))?;
        if old_variant.serde_attributes != new_variant.serde_attributes {
            bail!("managed enum '{name}' variant '{tag}' changed serde semantics");
        }
        let retained = match &old_variant.fields {
            VariantFields::Named(fields) => fields.keys().map(String::as_str).collect(),
            _ => BTreeSet::new(),
        };
        compare_variant_fields(
            &format!("{name}.{tag}"),
            &retained,
            None,
            &old_variant.fields,
            &new_variant.fields,
        )?;
    }
    Ok(())
}

fn compare_container(name: &str, base: &EnumShape, current: &EnumShape) -> Result<()> {
    if base.container_serde != current.container_serde {
        bail!("managed tagged enum '{name}' changed its serde container semantics");
    }
    Ok(())
}

fn compare_variant_fields(
    label: &str,
    retained: &BTreeSet<&str>,
    synthetic_tag: Option<&str>,
    base: &VariantFields,
    current: &VariantFields,
) -> Result<()> {
    match (base, current) {
        (VariantFields::Unit, VariantFields::Unit) => Ok(()),
        (VariantFields::Unnamed(base), VariantFields::Unnamed(current)) if base == current => {
            Ok(())
        }
        (VariantFields::Named(base), VariantFields::Named(current)) => {
            for name in retained
                .iter()
                .copied()
                .filter(|name| Some(*name) != synthetic_tag)
            {
                let old = base
                    .get(name)
                    .with_context(|| format!("base tagged shape '{label}' lacks field '{name}'"))?;
                let new = current.get(name).with_context(|| {
                    format!("candidate tagged shape '{label}' lacks field '{name}'")
                })?;
                if old != new {
                    bail!("tagged field '{label}.{name}' changed Rust type or serde semantics");
                }
            }
            Ok(())
        }
        _ => bail!("managed tagged variant '{label}' changed its Rust field form"),
    }
}

fn named_shape(item: &syn::Item) -> Result<NamedShape> {
    let syn::Item::Struct(item) = item else {
        bail!("managed named schema item is not a struct");
    };
    let syn::Fields::Named(fields) = &item.fields else {
        bail!("managed named schema struct does not use named fields");
    };
    let mut output = BTreeMap::new();
    for field in &fields.named {
        let rust_name = field
            .ident
            .as_ref()
            .context("managed named schema field has no identifier")?
            .to_string();
        let wire_name = serde_rename(&field.attrs)?.unwrap_or(rust_name);
        if output
            .insert(wire_name.clone(), field_semantic(field))
            .is_some()
        {
            bail!("managed named schema repeats wire field '{wire_name}'");
        }
    }
    Ok(NamedShape {
        container_serde: serde_attributes(&item.attrs),
        fields: output,
    })
}

fn enum_shape(item: &syn::Item) -> Result<EnumShape> {
    let syn::Item::Enum(item) = item else {
        bail!("managed tagged schema item is not an enum");
    };
    let mut variants = BTreeMap::new();
    for variant in &item.variants {
        if serde_flag(&variant.attrs, "other")? {
            continue;
        }
        let tag = serde_rename(&variant.attrs)?
            .unwrap_or_else(|| serde_snake_case(&variant.ident.to_string()));
        let fields = match &variant.fields {
            syn::Fields::Unit => VariantFields::Unit,
            syn::Fields::Named(fields) => {
                let mut output = BTreeMap::new();
                for field in &fields.named {
                    let rust_name = field
                        .ident
                        .as_ref()
                        .context("managed tagged field has no identifier")?
                        .to_string();
                    let wire_name = serde_rename(&field.attrs)?.unwrap_or(rust_name);
                    if output
                        .insert(wire_name.clone(), field_semantic(field))
                        .is_some()
                    {
                        bail!("managed tagged variant repeats wire field '{wire_name}'");
                    }
                }
                VariantFields::Named(output)
            }
            syn::Fields::Unnamed(fields) => {
                VariantFields::Unnamed(fields.unnamed.iter().map(field_semantic).collect())
            }
        };
        let semantic = VariantSemantic {
            serde_attributes: serde_attributes(&variant.attrs),
            fields,
        };
        if variants.insert(tag.clone(), semantic).is_some() {
            bail!("managed tagged enum repeats wire variant '{tag}'");
        }
    }
    Ok(EnumShape {
        container_serde: serde_attributes(&item.attrs),
        variants,
    })
}

fn field_semantic(field: &syn::Field) -> FieldSemantic {
    FieldSemantic {
        ty: field.ty.to_token_stream().to_string(),
        serde_attributes: serde_attributes(&field.attrs),
    }
}

fn retained_fields<'a>(old: &'a Surface, current: &'a Surface) -> BTreeSet<&'a str> {
    let current = current
        .fields
        .iter()
        .map(|field| field.name.as_str())
        .collect::<BTreeSet<_>>();
    old.fields
        .iter()
        .map(|field| field.name.as_str())
        .filter(|name| current.contains(name))
        .collect()
}

fn unique_type<'a>(file: &'a syn::File, expected: &str) -> Result<&'a syn::Item> {
    let mut items = file.items.iter().filter(|item| match item {
        syn::Item::Struct(item) => item.ident == expected,
        syn::Item::Enum(item) => item.ident == expected,
        syn::Item::Type(item) => item.ident == expected,
        _ => false,
    });
    let item = items
        .next()
        .with_context(|| format!("managed source lacks Rust type '{expected}'"))?;
    if items.next().is_some() {
        bail!("managed source repeats Rust type '{expected}'");
    }
    Ok(item)
}

fn compare_standalone_imports_once(
    path: &str,
    base_view: SourceView<'_>,
    candidate_view: SourceView<'_>,
    compared: &mut BTreeSet<String>,
) -> Result<()> {
    if !compared.insert(path.to_owned()) {
        return Ok(());
    }
    let base = base_view.parse_file(path)?;
    let current = candidate_view.parse_file(path)?;
    if import_fingerprints(&base) != import_fingerprints(&current) {
        bail!("managed schema source '{path}' changed its import bindings");
    }
    if module_fingerprints(&base) != module_fingerprints(&current) {
        bail!("managed schema source '{path}' changed its module declarations");
    }
    if file_attribute_fingerprints(&base) != file_attribute_fingerprints(&current) {
        bail!("managed schema source '{path}' changed its file-level attributes");
    }
    Ok(())
}

#[cfg(test)]
#[path = "schema_compat_rust_semantics_surface_tests.rs"]
mod tests;
