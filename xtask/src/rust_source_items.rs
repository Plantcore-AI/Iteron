use super::attrs::{
    reject_manual_serde_impls_and_item_macros, serde_field_name, serde_options, serde_snake_case,
    validate_field_attributes, validate_managed_item_attributes, validate_variant_attributes,
    validate_wire_name,
};
use super::expected::{ExpectedItem, ExpectedKind, unique_expected_item};
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy)]
pub(crate) enum SerdeAuthority {
    Serialize,
    Deserialize,
    Both,
}

pub(crate) fn require_serde_authority(
    source: &str,
    signature: &str,
    authority: SerdeAuthority,
) -> Result<()> {
    let expected = ExpectedItem::from_signature(signature)?;
    if matches!(expected.kind, ExpectedKind::Function) {
        bail!("serde authority can be required only for a struct or enum");
    }
    let file = syn::parse_file(source).context("schema Rust source does not parse")?;
    let item = unique_expected_item(&file, &expected, signature)?;
    let attributes = match item {
        syn::Item::Enum(item) => &item.attrs,
        syn::Item::Struct(item) => &item.attrs,
        _ => unreachable!("serde authority targets only structs or enums"),
    };
    let derives = validate_managed_item_attributes(&file, attributes, &expected.name)?;
    let exact = match authority {
        SerdeAuthority::Serialize => derives.serialize && !derives.deserialize,
        SerdeAuthority::Deserialize => !derives.serialize && derives.deserialize,
        SerdeAuthority::Both => derives.serialize && derives.deserialize,
    };
    if !exact {
        bail!(
            "schema item '{signature}' does not retain its exact derived serde authority: Serialize={}, Deserialize={}",
            derives.serialize,
            derives.deserialize
        );
    }
    reject_manual_serde_impls_and_item_macros(&file.items, &expected.name)?;
    Ok(())
}

pub(crate) fn require_serde_container_flag(
    source: &str,
    signature: &str,
    flag: &str,
) -> Result<()> {
    let expected = ExpectedItem::from_signature(signature)?;
    if matches!(expected.kind, ExpectedKind::Function) {
        bail!("serde container flags can be required only for a struct or enum");
    }
    let file = syn::parse_file(source).context("schema Rust source does not parse")?;
    let item = unique_expected_item(&file, &expected, signature)?;
    let attributes = match item {
        syn::Item::Enum(item) => &item.attrs,
        syn::Item::Struct(item) => &item.attrs,
        _ => unreachable!("serde container flags target only structs or enums"),
    };
    let options = serde_options(attributes, "managed schema container")?;
    if options.get(flag) != Some(&None) {
        bail!("schema item '{signature}' must retain serde flag '{flag}'");
    }
    Ok(())
}

pub(crate) fn enum_variant_names(source: &str, signature: &str) -> Result<BTreeSet<String>> {
    enum_variant_names_with_shape(source, signature, false)
}

pub(crate) fn unit_enum_variant_names(source: &str, signature: &str) -> Result<BTreeSet<String>> {
    enum_variant_names_with_shape(source, signature, true)
}

fn enum_variant_names_with_shape(
    source: &str,
    signature: &str,
    require_unit: bool,
) -> Result<BTreeSet<String>> {
    let expected = ExpectedItem::from_signature(signature)?;
    let file = syn::parse_file(source).context("schema Rust source does not parse")?;
    let item = unique_expected_item(&file, &expected, signature)?;
    let syn::Item::Enum(item) = item else {
        bail!("schema item '{signature}' is not an enum");
    };
    validate_managed_item_attributes(&file, &item.attrs, &expected.name)?;
    if !serde_options(&item.attrs, "plain enum container")?.is_empty() {
        bail!("plain enum '{signature}' cannot transform its variant names with serde options");
    }
    let mut variants = BTreeSet::new();
    for variant in &item.variants {
        validate_variant_attributes(&variant.attrs, signature)?;
        if !serde_options(&variant.attrs, "plain enum variant")?.is_empty() {
            bail!("plain enum '{signature}' cannot transform one variant with serde options");
        }
        if require_unit && !matches!(variant.fields, syn::Fields::Unit) {
            bail!("plain enum '{signature}' must retain unit-only variants");
        }
        if !variants.insert(variant.ident.to_string()) {
            bail!("enum '{signature}' repeats a variant");
        }
    }
    if variants.is_empty() {
        bail!("enum '{signature}' has no variants");
    }
    Ok(variants)
}

pub(crate) fn named_struct_wire_fields(source: &str, signature: &str) -> Result<BTreeSet<String>> {
    let expected = ExpectedItem::from_signature(signature)?;
    let file = syn::parse_file(source).context("schema Rust source does not parse")?;
    let item = unique_expected_item(&file, &expected, signature)?;
    let syn::Item::Struct(item) = item else {
        bail!("schema item '{signature}' is not a named struct");
    };
    validate_managed_item_attributes(&file, &item.attrs, &expected.name)?;
    let container = serde_options(&item.attrs, "struct container")?;
    for option in container.keys() {
        if !matches!(option.as_str(), "deny_unknown_fields" | "default") {
            bail!(
                "schema struct '{signature}' uses serde container option '{option}' that can change its direct-field inventory"
            );
        }
    }
    let syn::Fields::Named(named) = &item.fields else {
        bail!("schema item '{signature}' is not a named struct");
    };
    let mut fields = BTreeSet::new();
    for field in &named.named {
        validate_field_attributes(&field.attrs, signature)?;
        let name = field
            .ident
            .as_ref()
            .context("named schema struct contains an unnamed field")?
            .to_string();
        let wire_name = serde_field_name(&field.attrs, &name, signature)?;
        validate_wire_name("schema struct field", &wire_name)?;
        if !fields.insert(wire_name.clone()) {
            bail!("schema struct '{signature}' repeats wire field '{wire_name}'");
        }
    }
    if fields.is_empty() {
        bail!("schema struct '{signature}' has no fields");
    }
    Ok(fields)
}

pub(crate) fn tagged_enum_wire_fields(
    source: &str,
    signature: &str,
    tag_field: &str,
    expected_other_variants: usize,
    newtype_fields: &BTreeMap<String, BTreeSet<String>>,
) -> Result<BTreeMap<String, BTreeSet<String>>> {
    validate_wire_name("tagged enum tag field", tag_field)?;
    let expected = ExpectedItem::from_signature(signature)?;
    let file = syn::parse_file(source).context("schema Rust source does not parse")?;
    let item = unique_expected_item(&file, &expected, signature)?;
    let syn::Item::Enum(item) = item else {
        bail!("schema item '{signature}' is not an enum");
    };
    validate_managed_item_attributes(&file, &item.attrs, &expected.name)?;
    let container = serde_options(&item.attrs, "tagged enum container")?;
    let expected_tag = container.get("tag").and_then(|value| value.as_deref());
    let rename_all = container
        .get("rename_all")
        .and_then(|value| value.as_deref());
    if expected_tag != Some(tag_field)
        || rename_all != Some("snake_case")
        || container.keys().any(|option| {
            !matches!(
                option.as_str(),
                "tag" | "rename_all" | "deny_unknown_fields"
            )
        })
    {
        bail!("tagged enum '{signature}' lacks its exact serde tag contract");
    }
    let mut variants = BTreeMap::new();
    let mut other_variants = 0usize;
    for variant in &item.variants {
        validate_variant_attributes(&variant.attrs, signature)?;
        let options = serde_options(&variant.attrs, "tagged enum variant")?;
        let is_other = options.contains_key("other");
        let renamed = options.get("rename").and_then(|value| value.as_deref());
        if options
            .keys()
            .any(|option| !matches!(option.as_str(), "other" | "rename"))
        {
            bail!("tagged enum '{signature}' has an unsupported serde variant option");
        }
        if is_other {
            if renamed.is_some() || !matches!(variant.fields, syn::Fields::Unit) {
                bail!("serde(other) tagged-enum sentinel must be an unrenamed unit variant");
            }
            other_variants = other_variants.saturating_add(1);
            continue;
        }
        let tag = renamed
            .map(str::to_owned)
            .unwrap_or_else(|| serde_snake_case(&variant.ident.to_string()));
        validate_wire_name("tagged enum variant", &tag)?;
        let mut fields = BTreeSet::from([tag_field.to_owned()]);
        match &variant.fields {
            syn::Fields::Unit => {}
            syn::Fields::Named(named) => {
                for field in &named.named {
                    validate_field_attributes(&field.attrs, signature)?;
                    let name = field
                        .ident
                        .as_ref()
                        .context("named enum variant contains an unnamed field")?
                        .to_string();
                    let wire_name = serde_field_name(&field.attrs, &name, signature)?;
                    validate_wire_name("tagged enum field", &wire_name)?;
                    if !fields.insert(wire_name.clone()) {
                        bail!("tagged enum repeats field '{wire_name}'");
                    }
                }
            }
            syn::Fields::Unnamed(unnamed) => {
                if unnamed.unnamed.len() != 1 {
                    bail!("tagged enum tuple variant must contain exactly one named newtype");
                }
                let field = unnamed
                    .unnamed
                    .first()
                    .expect("checked exactly one tagged-enum newtype field");
                if !field.attrs.is_empty() {
                    bail!("tagged enum newtype field cannot carry attributes");
                }
                let syn::Type::Path(path) = &field.ty else {
                    bail!("tagged enum tuple variant is not one named newtype");
                };
                if path.qself.is_some()
                    || path.path.leading_colon.is_some()
                    || path.path.segments.len() != 1
                    || !matches!(path.path.segments[0].arguments, syn::PathArguments::None)
                {
                    bail!("tagged enum tuple variant is not one unqualified named newtype");
                }
                let newtype = path.path.segments[0].ident.to_string();
                let expanded = newtype_fields.get(&newtype).with_context(|| {
                    format!(
                        "tagged-enum tuple variant '{}' uses unknown newtype '{newtype}'; source binding fails closed",
                        variant.ident
                    )
                })?;
                for field in expanded {
                    if !fields.insert(field.clone()) {
                        bail!("tagged enum repeats expanded field '{field}'");
                    }
                }
            }
        }
        if variants.insert(tag.clone(), fields).is_some() {
            bail!("tagged enum repeats wire variant '{tag}'");
        }
    }
    if other_variants != expected_other_variants || variants.is_empty() {
        bail!(
            "tagged enum has {other_variants} serde(other) sentinels instead of {expected_other_variants}, or no writable variants"
        );
    }
    Ok(variants)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_enum_inventory_rejects_data_carrying_spoofs() {
        let unit = "#[derive(serde::Serialize, serde::Deserialize)] enum Tag { Add, Remove }";
        assert_eq!(
            unit_enum_variant_names(unit, "enum Tag {").unwrap(),
            BTreeSet::from(["Add".to_owned(), "Remove".to_owned()])
        );
        let data =
            "#[derive(serde::Serialize, serde::Deserialize)] enum Tag { Add { evil: String } }";
        assert!(unit_enum_variant_names(data, "enum Tag {").is_err());
    }

    #[test]
    fn serde_authority_rejects_grouped_self_redirects() {
        let canonical =
            "use serde::{self}; #[derive(serde::Serialize)] struct Wire { value: String }";
        require_serde_authority(canonical, "struct Wire {", SerdeAuthority::Serialize).unwrap();
        let redirected = "mod evil { pub mod serde {} } use evil::serde::{self}; \
            #[derive(serde::Serialize)] struct Wire { value: String }";
        assert!(
            require_serde_authority(redirected, "struct Wire {", SerdeAuthority::Serialize)
                .is_err()
        );
    }
}
