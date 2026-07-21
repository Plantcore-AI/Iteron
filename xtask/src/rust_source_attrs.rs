use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;

pub(super) fn validate_field_attributes(
    attributes: &[syn::Attribute],
    signature: &str,
) -> Result<()> {
    if attributes.iter().any(|attribute| {
        !attribute.path().is_ident("doc")
            && !attribute.path().is_ident("serde")
            && !attribute.path().is_ident("allow")
    }) {
        bail!("schema item '{signature}' has a field with an unsupported active attribute");
    }
    Ok(())
}

pub(super) fn validate_variant_attributes(
    attributes: &[syn::Attribute],
    signature: &str,
) -> Result<()> {
    if attributes.iter().any(|attribute| {
        !attribute.path().is_ident("doc")
            && !attribute.path().is_ident("serde")
            && !attribute.path().is_ident("allow")
    }) {
        bail!("schema item '{signature}' has a variant with an unsupported active attribute");
    }
    Ok(())
}

pub(super) fn serde_field_name(
    attributes: &[syn::Attribute],
    default: &str,
    signature: &str,
) -> Result<String> {
    let options = serde_options(attributes, "field")?;
    for (option, value) in &options {
        match option.as_str() {
            "rename" => {
                if value.is_none() {
                    bail!("schema item '{signature}' has a valueless serde rename");
                }
            }
            "default" => {}
            "skip_serializing_if" | "deserialize_with" => {
                if value.is_none() {
                    bail!("schema item '{signature}' has a valueless serde option '{option}'");
                }
            }
            "serialize_with" | "with" => bail!(
                "schema item '{signature}' field uses '{option}', which can replace its source-bound wire value"
            ),
            _ => bail!("schema item '{signature}' field uses unsupported serde option '{option}'"),
        }
    }
    Ok(options
        .get("rename")
        .and_then(|value| value.clone())
        .unwrap_or_else(|| default.to_owned()))
}

pub(super) fn serde_options(
    attributes: &[syn::Attribute],
    context: &str,
) -> Result<BTreeMap<String, Option<String>>> {
    let mut serde_attributes = attributes
        .iter()
        .filter(|attribute| attribute.path().is_ident("serde"));
    let Some(attribute) = serde_attributes.next() else {
        return Ok(BTreeMap::new());
    };
    if serde_attributes.next().is_some() {
        bail!("{context} repeats its serde attribute");
    }
    let mut options = BTreeMap::new();
    attribute
        .parse_nested_meta(|meta| {
            let Some(identifier) = meta.path.get_ident() else {
                return Err(meta.error("serde option path must be one identifier"));
            };
            let name = identifier.to_string();
            let value = if meta.input.peek(syn::Token![=]) {
                let literal: syn::LitStr = meta.value()?.parse()?;
                Some(literal.value())
            } else if meta.input.peek(syn::token::Paren) {
                return Err(meta.error("nested serde option syntax is unsupported"));
            } else {
                None
            };
            if options.insert(name.clone(), value).is_some() {
                return Err(meta.error(format!("serde option '{name}' is repeated")));
            }
            Ok(())
        })
        .with_context(|| format!("{context} has an invalid serde attribute"))?;
    Ok(options)
}

pub(super) fn validate_wire_name(kind: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        bail!("invalid {kind} '{value}'");
    }
    Ok(())
}

pub(super) fn serde_snake_case(value: &str) -> String {
    let mut result = String::new();
    for (index, character) in value.chars().enumerate() {
        if character.is_ascii_uppercase() {
            if index > 0 {
                result.push('_');
            }
            result.push(character.to_ascii_lowercase());
        } else {
            result.push(character);
        }
    }
    result
}

#[derive(Default)]
pub(super) struct SerdeDerives {
    pub(super) serialize: bool,
    pub(super) deserialize: bool,
}

pub(super) fn validate_managed_item_attributes(
    file: &syn::File,
    attributes: &[syn::Attribute],
    item_name: &str,
) -> Result<SerdeDerives> {
    reject_serde_root_shadowing(file)?;
    let mut derives = SerdeDerives::default();
    for attribute in attributes {
        let path = attribute.path();
        if path.is_ident("doc")
            || path.is_ident("serde")
            || path.is_ident("allow")
            || path.is_ident("warn")
            || path.is_ident("deny")
            || path.is_ident("forbid")
        {
            continue;
        }
        if path.is_ident("derive") {
            let paths = attribute
                .parse_args_with(
                    syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
                )
                .context("managed schema item has an invalid derive attribute")?;
            for path in paths {
                classify_trusted_derive(file, &path, item_name, &mut derives)?;
            }
            continue;
        }
        bail!(
            "managed schema item '{item_name}' uses unsupported active attribute '{}'",
            path_to_string(path)
        );
    }
    Ok(derives)
}

fn reject_serde_root_shadowing(file: &syn::File) -> Result<()> {
    for item in &file.items {
        match item {
            syn::Item::Mod(module) if module.ident == "serde" => {
                bail!("managed schema source shadows the canonical serde crate with a module");
            }
            syn::Item::ExternCrate(extern_crate)
                if extern_crate.ident == "serde"
                    || extern_crate
                        .rename
                        .as_ref()
                        .is_some_and(|(_, rename)| rename == "serde") =>
            {
                bail!("managed schema source has an explicit extern-crate serde binding");
            }
            syn::Item::Use(import) => {
                let mut bindings = Vec::new();
                flatten_use_tree(&import.tree, &mut Vec::new(), &mut bindings)?;
                if bindings
                    .iter()
                    .any(|(binding, origin)| binding == "serde" && !exact_path(origin, &["serde"]))
                {
                    bail!("managed schema source shadows the canonical serde crate with an import");
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn classify_trusted_derive(
    file: &syn::File,
    path: &syn::Path,
    item_name: &str,
    derives: &mut SerdeDerives,
) -> Result<()> {
    let identifiers = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    if path.leading_colon.is_none()
        && identifiers.len() == 1
        && matches!(
            identifiers[0].as_str(),
            "Debug"
                | "Clone"
                | "Copy"
                | "Default"
                | "PartialEq"
                | "Eq"
                | "PartialOrd"
                | "Ord"
                | "Hash"
        )
    {
        return Ok(());
    }
    let authority = if exact_path(&identifiers, &["serde", "Serialize"])
        && path.leading_colon.is_none()
    {
        Some((true, false))
    } else if exact_path(&identifiers, &["serde", "Deserialize"]) && path.leading_colon.is_none() {
        Some((false, true))
    } else if exact_path(&identifiers, &["Serialize"])
        && path.leading_colon.is_none()
        && unqualified_derive_is_from_serde(file, "Serialize")?
    {
        Some((true, false))
    } else if exact_path(&identifiers, &["Deserialize"])
        && path.leading_colon.is_none()
        && unqualified_derive_is_from_serde(file, "Deserialize")?
    {
        Some((false, true))
    } else {
        None
    };
    let Some((serialize, deserialize)) = authority else {
        bail!(
            "managed schema item '{item_name}' uses untrusted derive '{}'",
            path_to_string(path)
        );
    };
    if serialize && std::mem::replace(&mut derives.serialize, true)
        || deserialize && std::mem::replace(&mut derives.deserialize, true)
    {
        bail!("managed schema item '{item_name}' repeats a serde authority derive");
    }
    Ok(())
}

fn exact_path(actual: &[String], expected: &[&str]) -> bool {
    actual.len() == expected.len()
        && actual
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual == expected)
}

fn unqualified_derive_is_from_serde(file: &syn::File, expected: &str) -> Result<bool> {
    let mut bindings = Vec::new();
    for item in &file.items {
        if let syn::Item::Use(item) = item {
            flatten_use_tree(&item.tree, &mut Vec::new(), &mut bindings)?;
        }
    }
    let origins = bindings
        .iter()
        .filter(|(binding, _)| binding == expected)
        .map(|(_, origin)| origin)
        .collect::<Vec<_>>();
    Ok(origins.len() == 1 && exact_path(origins[0], &["serde", expected]))
}

fn flatten_use_tree(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    bindings: &mut Vec<(String, Vec<String>)>,
) -> Result<()> {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            flatten_use_tree(&path.tree, prefix, bindings)?;
            prefix.pop();
        }
        syn::UseTree::Name(name) => {
            let ident = name.ident.to_string();
            if ident == "self" {
                let binding = prefix
                    .last()
                    .context("import has root-level `self`")?
                    .clone();
                bindings.push((binding, prefix.clone()));
            } else {
                let mut origin = prefix.clone();
                origin.push(ident.clone());
                bindings.push((ident, origin));
            }
        }
        syn::UseTree::Rename(rename) => {
            let mut origin = prefix.clone();
            if rename.ident != "self" {
                origin.push(rename.ident.to_string());
            }
            bindings.push((rename.rename.to_string(), origin));
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                flatten_use_tree(item, prefix, bindings)?;
            }
        }
        syn::UseTree::Glob(_) => {
            bail!("managed schema source uses a glob import with unprovable derive provenance");
        }
    }
    Ok(())
}

pub(super) fn reject_manual_serde_impls_and_item_macros(
    items: &[syn::Item],
    target: &str,
) -> Result<()> {
    for item in items {
        match item {
            syn::Item::Impl(item) => {
                let Some((_, trait_path, _)) = &item.trait_ else {
                    continue;
                };
                let trait_name = trait_path.segments.last().map(|segment| &segment.ident);
                let self_name = type_path_last_ident(&item.self_ty);
                if self_name.is_some_and(|name| name == target)
                    && trait_name.is_some_and(|name| name == "Serialize" || name == "Deserialize")
                {
                    bail!("managed schema item '{target}' has a manual serde authority impl");
                }
            }
            syn::Item::Macro(item) => {
                let trusted_thread_local = item.mac.path.leading_colon.is_none()
                    && item.mac.path.segments.len() == 2
                    && item.mac.path.segments[0].ident == "std"
                    && item.mac.path.segments[1].ident == "thread_local";
                if !trusted_thread_local {
                    bail!(
                        "managed schema source contains an item macro that could replace serde authority"
                    );
                }
            }
            syn::Item::Mod(module) => {
                if let Some((_, items)) = &module.content {
                    reject_manual_serde_impls_and_item_macros(items, target)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn type_path_last_ident(ty: &syn::Type) -> Option<&syn::Ident> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    path.path.segments.last().map(|segment| &segment.ident)
}

fn path_to_string(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}
