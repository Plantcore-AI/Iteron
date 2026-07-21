use super::super::manifest::read_bounded;
use super::MAX_SOURCE_BYTES;
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub(super) struct ProtocolNamedDefinition {
    pub(super) path: String,
    pub(super) signature: String,
}

pub(super) struct ProtocolTypeInventory {
    pub(super) definitions: BTreeMap<String, ProtocolNamedDefinition>,
    pub(super) leaves: BTreeSet<String>,
    pub(super) aliases: BTreeMap<String, BTreeSet<String>>,
    pub(super) sources: BTreeMap<String, String>,
    pub(super) origins: BTreeMap<String, String>,
}

pub(super) fn protocol_type_inventory(root: &Path) -> Result<ProtocolTypeInventory> {
    const MAX_PROTOCOL_SOURCE_FILES: usize = 128;
    const MAX_PROTOCOL_TOTAL_BYTES: u64 = 16 * 1024 * 1024;

    let mut pending = vec![(
        "crates/protocol/src/lib.rs".to_owned(),
        PathBuf::from("crates/protocol/src"),
    )];
    let mut visited = BTreeSet::new();
    let mut inventory = ProtocolTypeInventory {
        definitions: BTreeMap::new(),
        leaves: BTreeSet::new(),
        aliases: BTreeMap::new(),
        sources: BTreeMap::new(),
        origins: BTreeMap::new(),
    };
    let mut files = 0usize;
    let mut total_bytes = 0u64;
    while let Some((relative, module_dir)) = pending.pop() {
        if !visited.insert(relative.clone()) {
            bail!("protocol module graph repeats source '{relative}'");
        }
        files = files.saturating_add(1);
        if files > MAX_PROTOCOL_SOURCE_FILES {
            bail!("protocol source inventory exceeds its file bound");
        }
        let bytes = read_bounded(root, &relative, MAX_SOURCE_BYTES)?;
        total_bytes = total_bytes.saturating_add(bytes.len() as u64);
        if total_bytes > MAX_PROTOCOL_TOTAL_BYTES {
            bail!("protocol source inventory exceeds its total byte bound");
        }
        let source = std::str::from_utf8(&bytes)
            .with_context(|| format!("protocol source '{relative}' is not UTF-8"))?
            .to_owned();
        add_top_level_declarations(&source, &relative, &mut inventory)?;
        pending.extend(out_of_line_modules(root, &source, &relative, &module_dir)?);
        inventory.sources.insert(relative, source);
    }
    super::record_resolve::validate_protocol_bindings(&inventory)?;
    Ok(inventory)
}

fn out_of_line_modules(
    root: &Path,
    source: &str,
    relative: &str,
    module_dir: &Path,
) -> Result<Vec<(String, PathBuf)>> {
    let file = syn::parse_file(source)
        .with_context(|| format!("protocol source '{relative}' does not parse as Rust"))?;
    if file
        .attrs
        .iter()
        .any(|attribute| !attribute.path().is_ident("doc"))
    {
        bail!("protocol source '{relative}' has an active crate/module attribute");
    }
    let mut modules = Vec::new();
    for item in &file.items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        if module.content.is_some() {
            if is_exact_cfg_test(&module.attrs) {
                continue;
            }
            bail!(
                "protocol source '{relative}' contains an inline production module; record discovery fails closed"
            );
        }
        if module
            .attrs
            .iter()
            .any(|attribute| !attribute.path().is_ident("doc"))
        {
            bail!(
                "protocol out-of-line module '{}' has an active/path attribute",
                module.ident
            );
        }
        let name = module.ident.to_string();
        let flat = module_dir.join(format!("{name}.rs"));
        let nested = module_dir.join(&name).join("mod.rs");
        let candidates = [flat, nested]
            .into_iter()
            .filter(|candidate| root.join(candidate).is_file())
            .collect::<Vec<_>>();
        let [path] = candidates.as_slice() else {
            bail!("protocol module '{name}' must resolve to exactly one default .rs module path");
        };
        let path = path
            .to_str()
            .context("protocol module path is not UTF-8")?
            .replace(std::path::MAIN_SEPARATOR, "/");
        modules.push((path, module_dir.join(name)));
    }
    Ok(modules)
}

fn is_exact_cfg_test(attributes: &[syn::Attribute]) -> bool {
    let [attribute] = attributes else {
        return false;
    };
    let syn::Meta::List(meta) = &attribute.meta else {
        return false;
    };
    meta.path.is_ident("cfg") && meta.tokens.to_string() == "test"
}

fn add_top_level_declarations(
    source: &str,
    path: &str,
    inventory: &mut ProtocolTypeInventory,
) -> Result<()> {
    let file = syn::parse_file(source)
        .with_context(|| format!("protocol source '{path}' does not parse as Rust"))?;
    for item in file.items {
        match item {
            syn::Item::Struct(item) => {
                reject_conditional(&item.attrs, "struct", &item.ident.to_string())?;
                reject_generics(&item.generics, "struct", &item.ident.to_string())?;
                let name = item.ident.to_string();
                record_type_origin(inventory, &name, path)?;
                if matches!(item.fields, syn::Fields::Named(_)) {
                    let signature = format!(
                        "{}struct {name} {{",
                        visibility_prefix(&item.vis, "struct", &name)?
                    );
                    let definition = ProtocolNamedDefinition {
                        path: path.to_owned(),
                        signature,
                    };
                    if inventory
                        .definitions
                        .insert(name.clone(), definition)
                        .is_some()
                    {
                        bail!("protocol source inventory repeats named struct '{name}'");
                    }
                } else if let syn::Fields::Unnamed(fields) = &item.fields {
                    let mut identifiers = BTreeSet::new();
                    for field in &fields.unnamed {
                        type_identifiers(&field.ty, &mut identifiers)?;
                    }
                    if inventory
                        .aliases
                        .insert(name.clone(), identifiers)
                        .is_some()
                    {
                        bail!("protocol source inventory repeats indirect type '{name}'");
                    }
                } else {
                    inventory.leaves.insert(name);
                }
            }
            syn::Item::Enum(item) => {
                reject_conditional(&item.attrs, "enum", &item.ident.to_string())?;
                reject_generics(&item.generics, "enum", &item.ident.to_string())?;
                let name = item.ident.to_string();
                record_type_origin(inventory, &name, path)?;
                if item
                    .variants
                    .iter()
                    .all(|variant| matches!(variant.fields, syn::Fields::Unit))
                {
                    inventory.leaves.insert(name);
                } else {
                    let mut identifiers = BTreeSet::new();
                    for variant in &item.variants {
                        for field in &variant.fields {
                            type_identifiers(&field.ty, &mut identifiers)?;
                        }
                    }
                    if inventory
                        .aliases
                        .insert(name.clone(), identifiers)
                        .is_some()
                    {
                        bail!("protocol source inventory repeats indirect type '{name}'");
                    }
                }
            }
            syn::Item::Type(item) => {
                reject_conditional(&item.attrs, "type alias", &item.ident.to_string())?;
                reject_generics(&item.generics, "type alias", &item.ident.to_string())?;
                let name = item.ident.to_string();
                record_type_origin(inventory, &name, path)?;
                let mut identifiers = BTreeSet::new();
                type_identifiers(&item.ty, &mut identifiers)?;
                if inventory
                    .aliases
                    .insert(name.clone(), identifiers)
                    .is_some()
                {
                    bail!("protocol source inventory repeats type alias '{name}'");
                }
            }
            syn::Item::Macro(_) => {
                bail!(
                    "protocol source '{path}' contains a top-level item macro; record type discovery fails closed"
                );
            }
            _ => {}
        }
    }
    Ok(())
}

fn record_type_origin(inventory: &mut ProtocolTypeInventory, name: &str, path: &str) -> Result<()> {
    if matches!(
        name,
        "BTreeMap" | "Box" | "Option" | "String" | "Value" | "Vec"
    ) {
        bail!("protocol module graph shadows reserved wire type '{name}'");
    }
    if inventory
        .origins
        .insert(name.to_owned(), path.to_owned())
        .is_some()
    {
        bail!("protocol module graph repeats Rust type name '{name}'");
    }
    Ok(())
}

fn reject_conditional(attrs: &[syn::Attribute], kind: &str, name: &str) -> Result<()> {
    if attrs
        .iter()
        .any(|attribute| attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr"))
    {
        bail!("protocol {kind} '{name}' cannot be conditional at the record boundary");
    }
    Ok(())
}

fn reject_generics(generics: &syn::Generics, kind: &str, name: &str) -> Result<()> {
    if !generics.params.is_empty() || generics.where_clause.is_some() {
        bail!("protocol {kind} '{name}' uses unsupported generics at the record boundary");
    }
    Ok(())
}

fn visibility_prefix(visibility: &syn::Visibility, kind: &str, name: &str) -> Result<&'static str> {
    match visibility {
        syn::Visibility::Public(_) => Ok("pub "),
        syn::Visibility::Inherited => Ok(""),
        syn::Visibility::Restricted(restricted) if restricted.path.is_ident("crate") => {
            Ok("pub(crate) ")
        }
        syn::Visibility::Restricted(restricted) if restricted.path.is_ident("super") => {
            Ok("pub(super) ")
        }
        _ => bail!("protocol {kind} '{name}' uses unsupported restricted visibility"),
    }
}

fn type_identifiers(ty: &syn::Type, identifiers: &mut BTreeSet<String>) -> Result<()> {
    match ty {
        syn::Type::Path(path) if path.qself.is_none() => {
            let segments = path.path.segments.iter().collect::<Vec<_>>();
            if segments.len() > 1 {
                let exact_crate_root = segments.len() == 2 && segments[0].ident == "crate";
                let exact_json_value = segments.len() == 2
                    && segments[0].ident == "serde_json"
                    && segments[1].ident == "Value";
                if !exact_crate_root && !exact_json_value {
                    bail!(
                        "protocol record type uses unresolvable qualified path '{}'; source binding fails closed",
                        segments
                            .iter()
                            .map(|segment| segment.ident.to_string())
                            .collect::<Vec<_>>()
                            .join("::")
                    );
                }
            }
            for (index, segment) in path.path.segments.iter().enumerate() {
                let name = segment.ident.to_string();
                if index + 1 == path.path.segments.len()
                    && !matches!(
                        name.as_str(),
                        "bool"
                            | "char"
                            | "str"
                            | "u8"
                            | "u16"
                            | "u32"
                            | "u64"
                            | "u128"
                            | "usize"
                            | "i8"
                            | "i16"
                            | "i32"
                            | "i64"
                            | "i128"
                            | "isize"
                            | "f32"
                            | "f64"
                    )
                {
                    identifiers.insert(name);
                }
                match &segment.arguments {
                    syn::PathArguments::None => {}
                    syn::PathArguments::AngleBracketed(arguments) => {
                        for argument in &arguments.args {
                            if let syn::GenericArgument::Type(ty) = argument {
                                type_identifiers(ty, identifiers)?;
                            }
                        }
                    }
                    syn::PathArguments::Parenthesized(_) => {
                        bail!("protocol type alias uses unsupported parenthesized path arguments");
                    }
                }
            }
        }
        syn::Type::Reference(ty) => type_identifiers(&ty.elem, identifiers)?,
        syn::Type::Array(ty) => type_identifiers(&ty.elem, identifiers)?,
        syn::Type::Slice(ty) => type_identifiers(&ty.elem, identifiers)?,
        syn::Type::Ptr(ty) => type_identifiers(&ty.elem, identifiers)?,
        syn::Type::Paren(ty) => type_identifiers(&ty.elem, identifiers)?,
        syn::Type::Group(ty) => type_identifiers(&ty.elem, identifiers)?,
        syn::Type::Tuple(tuple) => {
            for ty in &tuple.elems {
                type_identifiers(ty, identifiers)?;
            }
        }
        syn::Type::Never(_) => {}
        _ => bail!("protocol type alias uses an unsupported Rust type expression"),
    }
    Ok(())
}

pub(super) fn named_struct_type_identifiers(
    source: &str,
    signature: &str,
) -> Result<BTreeSet<String>> {
    let name = signature_type_name(signature, "struct")?;
    let file = syn::parse_file(source).context("protocol named-record source does not parse")?;
    let mut items = file.items.iter().filter_map(|item| match item {
        syn::Item::Struct(item) if item.ident == name => Some(item),
        _ => None,
    });
    let item = items
        .next()
        .with_context(|| format!("protocol source lacks explicit named struct '{name}'"))?;
    if items.next().is_some() {
        bail!("protocol source repeats named struct '{name}'");
    }
    let syn::Fields::Named(fields) = &item.fields else {
        bail!("protocol named record '{name}' is not a named-field struct");
    };
    let mut identifiers = BTreeSet::new();
    for field in &fields.named {
        type_identifiers(&field.ty, &mut identifiers)?;
    }
    Ok(identifiers)
}

pub(super) fn tagged_enum_type_identifiers(
    source: &str,
    signature: &str,
) -> Result<BTreeSet<String>> {
    let name = signature_type_name(signature, "enum")?;
    let file = syn::parse_file(source).context("protocol tagged-enum source does not parse")?;
    let mut items = file.items.iter().filter_map(|item| match item {
        syn::Item::Enum(item) if item.ident == name => Some(item),
        _ => None,
    });
    let item = items
        .next()
        .with_context(|| format!("protocol source lacks explicit tagged enum '{name}'"))?;
    if items.next().is_some() {
        bail!("protocol source repeats tagged enum '{name}'");
    }
    let mut identifiers = BTreeSet::new();
    for variant in &item.variants {
        for field in &variant.fields {
            type_identifiers(&field.ty, &mut identifiers)?;
        }
    }
    Ok(identifiers)
}

fn signature_type_name(signature: &str, kind: &str) -> Result<String> {
    let marker = format!("{kind} ");
    let name = signature
        .split_once(&marker)
        .map(|(_, declaration)| declaration)
        .and_then(|declaration| {
            declaration
                .split(|character: char| {
                    character == '<' || character == '{' || character.is_ascii_whitespace()
                })
                .next()
        })
        .unwrap_or_default();
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        bail!("protocol {kind} signature has an invalid type name");
    }
    Ok(name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_inventory() -> ProtocolTypeInventory {
        ProtocolTypeInventory {
            definitions: BTreeMap::new(),
            leaves: BTreeSet::new(),
            aliases: BTreeMap::new(),
            sources: BTreeMap::new(),
            origins: BTreeMap::new(),
        }
    }

    #[test]
    fn d13_14_protocol_type_inventory_is_ast_bound_and_fail_closed_on_macros() {
        let source = "/* enum Fake {} */\nconst RAW: &str = r#\"enum RawFake {}\"#;\nstruct Hidden { value: String }\npub(crate) struct Visible { nested: Alias }\ntype Alias = Hidden;\nenum Choice { A }\nstruct Newtype(String);\n";
        let mut inventory = empty_inventory();
        add_top_level_declarations(source, "sample.rs", &mut inventory).unwrap();
        assert_eq!(inventory.definitions["Hidden"].signature, "struct Hidden {");
        assert_eq!(
            inventory.definitions["Visible"].signature,
            "pub(crate) struct Visible {"
        );
        assert_eq!(
            inventory.aliases["Alias"],
            BTreeSet::from(["Hidden".to_owned()])
        );
        assert!(inventory.leaves.contains("Choice"));
        assert_eq!(
            inventory.aliases["Newtype"],
            BTreeSet::from(["String".to_owned()])
        );
        assert!(!inventory.leaves.contains("Fake"));
        assert!(!inventory.leaves.contains("RawFake"));

        let mut inventory = empty_inventory();
        assert!(
            add_top_level_declarations(
                "macro_rules! make_wire { () => { struct Wire { value: String } } }\nmake_wire!();",
                "macro.rs",
                &mut inventory,
            )
            .is_err()
        );

        let mut inventory = empty_inventory();
        add_top_level_declarations(
            "struct Payload { value: String }\nenum Envelope { Empty, Data(Payload) }\n",
            "payload.rs",
            &mut inventory,
        )
        .unwrap();
        assert_eq!(
            inventory.aliases["Envelope"],
            BTreeSet::from(["Payload".to_owned()])
        );

        assert!(
            named_struct_type_identifiers("struct Root { role: evil::Role }\n", "struct Root {",)
                .is_err()
        );
    }
}
