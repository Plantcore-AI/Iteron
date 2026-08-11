use super::record_types::ProtocolTypeInventory;
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;

#[derive(Clone)]
struct Binding {
    local: String,
    origin: Vec<String>,
    renamed: bool,
}

pub(super) fn validate_protocol_bindings(inventory: &ProtocolTypeInventory) -> Result<()> {
    let root_source = inventory
        .sources
        .get("crates/protocol/src/lib.rs")
        .context("protocol inventory lacks its canonical crate root")?;
    let root = syn::parse_file(root_source).context("protocol crate root does not parse")?;
    let mut root_exports = BTreeMap::new();
    for item in &root.items {
        let syn::Item::Use(item) = item else {
            continue;
        };
        validate_use_attributes(item, "crates/protocol/src/lib.rs")?;
        for binding in use_bindings(&item.tree)? {
            if binding.renamed {
                bail!("protocol imports and re-exports cannot rename bindings");
            }
            if matches!(item.vis, syn::Visibility::Public(_))
                && root_exports
                    .insert(binding.local.clone(), binding.origin)
                    .is_some()
            {
                bail!(
                    "protocol crate root repeats public binding '{}'",
                    binding.local
                );
            }
        }
    }

    for (relative, source) in &inventory.sources {
        let file = syn::parse_file(source)
            .with_context(|| format!("protocol source '{relative}' does not parse"))?;
        let module = module_path(relative)?;
        for item in &file.items {
            match item {
                syn::Item::Use(item) => {
                    validate_use_attributes(item, relative)?;
                    for binding in use_bindings(&item.tree)? {
                        validate_binding(inventory, &root_exports, &module, relative, binding)?;
                    }
                }
                syn::Item::ExternCrate(_) => {
                    bail!("protocol source '{relative}' uses unsupported extern crate binding")
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn validate_use_attributes(item: &syn::ItemUse, relative: &str) -> Result<()> {
    if item
        .attrs
        .iter()
        .any(|attribute| !attribute.path().is_ident("doc"))
    {
        bail!("protocol import in '{relative}' has an active or conditional attribute");
    }
    Ok(())
}

fn validate_binding(
    inventory: &ProtocolTypeInventory,
    root_exports: &BTreeMap<String, Vec<String>>,
    module: &[String],
    relative: &str,
    binding: Binding,
) -> Result<()> {
    if binding.renamed {
        bail!(
            "protocol import '{}' in '{relative}' renames a binding; wire resolution fails closed",
            binding.local
        );
    }
    if matches!(
        binding.local.as_str(),
        "BTreeMap" | "Box" | "Option" | "String" | "Value" | "Vec"
    ) {
        let trusted = match binding.local.as_str() {
            "BTreeMap" => binding.origin == ["std", "collections", "BTreeMap"],
            "Value" => binding.origin == ["serde_json", "Value"],
            // These names normally come from the standard prelude. An explicit import is admitted
            // only from its exact standard-library definition.
            "Box" => binding.origin == ["std", "boxed", "Box"],
            "Option" => binding.origin == ["std", "option", "Option"],
            "String" => binding.origin == ["std", "string", "String"],
            "Vec" => binding.origin == ["std", "vec", "Vec"],
            _ => unreachable!(),
        };
        if !trusted {
            bail!(
                "protocol source '{relative}' redirects reserved type '{}'",
                binding.local
            );
        }
    }
    let Some(origin_path) = inventory.origins.get(&binding.local) else {
        return Ok(());
    };
    let expected_module = module_path(origin_path)?;
    let actual_module = if expected_module.is_empty()
        && binding.origin == ["crate".to_owned(), binding.local.clone()]
    {
        Vec::new()
    } else {
        resolve_binding_module(&binding, module, root_exports)?
    };
    if actual_module != expected_module {
        bail!(
            "protocol binding '{}' in '{relative}' resolves to module {:?}, expected {:?}",
            binding.local,
            actual_module,
            expected_module
        );
    }
    Ok(())
}

fn resolve_binding_module(
    binding: &Binding,
    current: &[String],
    root_exports: &BTreeMap<String, Vec<String>>,
) -> Result<Vec<String>> {
    let mut origin = binding.origin.clone();
    if origin.last() != Some(&binding.local) {
        bail!("protocol import binding origin is ambiguous");
    }
    origin.pop();
    if origin.first().is_some_and(|segment| segment == "crate") {
        origin.remove(0);
        if origin.is_empty() {
            let exported = root_exports
                .get(&binding.local)
                .with_context(|| format!("crate root does not export '{}'", binding.local))?;
            let mut exported = exported.clone();
            if exported.last() != Some(&binding.local) {
                bail!("protocol root export has an ambiguous origin");
            }
            exported.pop();
            return Ok(exported);
        }
        return Ok(origin);
    }
    if origin.first().is_some_and(|segment| segment == "self") {
        origin.remove(0);
        let mut resolved = current.to_vec();
        resolved.extend(origin);
        return Ok(resolved);
    }
    if origin.first().is_some_and(|segment| segment == "super") {
        let mut resolved = current.to_vec();
        while origin.first().is_some_and(|segment| segment == "super") {
            origin.remove(0);
            resolved
                .pop()
                .context("protocol import escapes its crate root")?;
        }
        resolved.extend(origin);
        return Ok(resolved);
    }
    // Bare paths in the crate root are relative modules. Elsewhere they are external-prelude
    // paths and cannot authoritatively bind one of our internal record types.
    if current.is_empty() {
        Ok(origin)
    } else {
        bail!(
            "protocol internal import '{}' in module '{}' uses a non-crate-qualified path {:?}",
            binding.local,
            current.join("::"),
            binding.origin
        )
    }
}

fn module_path(relative: &str) -> Result<Vec<String>> {
    let suffix = relative
        .strip_prefix("crates/protocol/src/")
        .context("protocol source path is outside its canonical root")?;
    if suffix == "lib.rs" {
        return Ok(Vec::new());
    }
    let mut components = suffix.split('/').map(str::to_owned).collect::<Vec<_>>();
    let file = components
        .pop()
        .context("protocol source path lacks a file")?;
    if file != "mod.rs" {
        components.push(
            file.strip_suffix(".rs")
                .context("protocol source is not a Rust module")?
                .to_owned(),
        );
    }
    Ok(components)
}

fn use_bindings(tree: &syn::UseTree) -> Result<Vec<Binding>> {
    let mut bindings = Vec::new();
    flatten_use(tree, &mut Vec::new(), &mut bindings)?;
    Ok(bindings)
}

fn flatten_use(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    bindings: &mut Vec<Binding>,
) -> Result<()> {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            flatten_use(&path.tree, prefix, bindings)?;
            prefix.pop();
        }
        syn::UseTree::Name(name) if name.ident == "self" => {
            let local = prefix
                .last()
                .context("bare use self has no parent")?
                .clone();
            bindings.push(Binding {
                local,
                origin: prefix.clone(),
                renamed: false,
            });
        }
        syn::UseTree::Name(name) => {
            let local = name.ident.to_string();
            let mut origin = prefix.clone();
            origin.push(local.clone());
            bindings.push(Binding {
                local,
                origin,
                renamed: false,
            });
        }
        syn::UseTree::Rename(rename) => {
            let mut origin = prefix.clone();
            origin.push(rename.ident.to_string());
            bindings.push(Binding {
                local: rename.rename.to_string(),
                origin,
                renamed: true,
            });
        }
        syn::UseTree::Group(group) => {
            for tree in &group.items {
                flatten_use(tree, prefix, bindings)?;
            }
        }
        syn::UseTree::Glob(_) => bail!("protocol imports cannot use glob bindings"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::record_types::ProtocolTypeInventory;
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn d13_14_use_resolution_rejects_aliases_and_preserves_group_origins() {
        assert!(
            use_bindings(
                &syn::parse_str::<syn::ItemUse>("use evil::Actual as Usage;")
                    .unwrap()
                    .tree
            )
            .unwrap()[0]
                .renamed
        );
        let bindings = use_bindings(
            &syn::parse_str::<syn::ItemUse>("use crate::message::{Message, Usage};")
                .unwrap()
                .tree,
        )
        .unwrap();
        assert_eq!(bindings[1].origin, ["crate", "message", "Usage"]);

        let inventory = ProtocolTypeInventory {
            definitions: BTreeMap::new(),
            leaves: BTreeSet::new(),
            aliases: BTreeMap::new(),
            sources: BTreeMap::from([(
                "crates/protocol/src/lib.rs".to_owned(),
                "pub use evil::EvilEvent as Event;".to_owned(),
            )]),
            origins: BTreeMap::from([(
                "Event".to_owned(),
                "crates/protocol/src/event.rs".to_owned(),
            )]),
        };
        assert!(validate_protocol_bindings(&inventory).is_err());
    }
}
