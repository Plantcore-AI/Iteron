use super::serde_attrs::snake_case as serde_snake_case;
use crate::schema_compat::{read_candidate_file_bounded, read_revision_file_bounded};
use anyhow::{Context, Result, bail};
use quote::ToTokens;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_PROTOCOL_FILES: usize = 128;
const MAX_PROTOCOL_BYTES: u64 = 16 * 1024 * 1024;
const PROTOCOL_ROOT: &str = "crates/protocol/src/lib.rs";

#[derive(Clone, Copy)]
pub(super) enum SourceView<'a> {
    Base { root: &'a Path, revision: &'a str },
    Candidate { root: &'a Path },
}

impl SourceView<'_> {
    pub(super) fn read_optional(&self, relative: &str) -> Result<Option<Vec<u8>>> {
        match self {
            Self::Base { root, revision } => {
                read_revision_file_bounded(root, revision, relative, MAX_FILE_BYTES)
            }
            Self::Candidate { root } => match std::fs::symlink_metadata(root.join(relative)) {
                Ok(_) => read_candidate_file_bounded(root, relative, MAX_FILE_BYTES).map(Some),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error)
                    .with_context(|| format!("cannot inspect candidate source '{relative}'")),
            },
        }
    }

    pub(super) fn read_text(&self, relative: &str) -> Result<String> {
        let bytes = self
            .read_optional(relative)?
            .with_context(|| format!("compatibility source '{relative}' is missing"))?;
        String::from_utf8(bytes)
            .with_context(|| format!("compatibility source '{relative}' is not UTF-8"))
    }

    pub(super) fn parse_file(&self, relative: &str) -> Result<syn::File> {
        let source = self.read_text(relative)?;
        syn::parse_file(&source)
            .with_context(|| format!("compatibility source '{relative}' does not parse as Rust"))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum TypeKind {
    NamedStruct,
    Frozen,
}

pub(super) struct TypeDefinition {
    pub(super) path: String,
    pub(super) kind: TypeKind,
    pub(super) references: BTreeSet<String>,
    pub(super) fingerprint: String,
}

pub(super) struct ProtocolGraph {
    pub(super) files: BTreeMap<String, syn::File>,
    pub(super) types: BTreeMap<String, TypeDefinition>,
    pub(super) manual_serde_impls: BTreeMap<String, String>,
    pub(super) manual_serde_support: BTreeMap<String, BTreeSet<String>>,
}

impl ProtocolGraph {
    pub(super) fn load(view: SourceView<'_>) -> Result<Self> {
        let mut pending = vec![(
            PROTOCOL_ROOT.to_owned(),
            PathBuf::from("crates/protocol/src"),
        )];
        let mut files = BTreeMap::new();
        let mut total_bytes = 0u64;
        while let Some((relative, module_dir)) = pending.pop() {
            if files.contains_key(&relative) {
                bail!("protocol module graph repeats source '{relative}'");
            }
            if files.len() >= MAX_PROTOCOL_FILES {
                bail!("protocol semantic graph exceeds its file bound");
            }
            let source = view.read_text(&relative)?;
            total_bytes = total_bytes.saturating_add(source.len() as u64);
            if total_bytes > MAX_PROTOCOL_BYTES {
                bail!("protocol semantic graph exceeds its total byte bound");
            }
            let file = syn::parse_file(&source)
                .with_context(|| format!("protocol source '{relative}' does not parse as Rust"))?;
            validate_file_shape(&file, &relative)?;
            pending.extend(out_of_line_modules(view, &file, &relative, &module_dir)?);
            files.insert(relative, file);
        }

        let mut graph = Self {
            files,
            types: BTreeMap::new(),
            manual_serde_impls: BTreeMap::new(),
            manual_serde_support: BTreeMap::new(),
        };
        graph.index_items()?;
        Ok(graph)
    }

    pub(super) fn imports(&self) -> BTreeMap<String, BTreeSet<String>> {
        self.files
            .iter()
            .map(|(path, file)| (path.clone(), import_fingerprints(file)))
            .collect()
    }

    pub(super) fn modules(&self) -> BTreeMap<String, Vec<String>> {
        self.files
            .iter()
            .map(|(path, file)| (path.clone(), module_fingerprints(file)))
            .collect()
    }

    pub(super) fn item(&self, type_name: &str) -> Result<&syn::Item> {
        let definition = self
            .types
            .get(type_name)
            .with_context(|| format!("protocol graph lacks type '{type_name}'"))?;
        let file = self
            .files
            .get(&definition.path)
            .expect("indexed protocol type retains its source file");
        let mut items = file
            .items
            .iter()
            .filter(|item| item_has_name(item, type_name));
        let item = items
            .next()
            .expect("indexed protocol type retains its item");
        if items.next().is_some() {
            bail!("protocol source repeats type '{type_name}'");
        }
        Ok(item)
    }

    pub(super) fn named_surface_type(&self, surface_id: &str) -> Result<String> {
        let mut matches = self.types.iter().filter_map(|(name, definition)| {
            (definition.kind == TypeKind::NamedStruct
                && format!("record.named.{}", serde_snake_case(name).replace('_', "-"))
                    == surface_id)
                .then_some(name.clone())
        });
        let name = matches
            .next()
            .with_context(|| format!("protocol graph lacks named surface '{surface_id}'"))?;
        if matches.next().is_some() {
            bail!("protocol types collide on named surface '{surface_id}'");
        }
        Ok(name)
    }

    fn index_items(&mut self) -> Result<()> {
        for (path, file) in &self.files {
            for item in &file.items {
                if let Some((name, kind, references)) = classify_type(item)? {
                    let definition = TypeDefinition {
                        path: path.clone(),
                        kind,
                        references,
                        fingerprint: semantic_item(item),
                    };
                    if self.types.insert(name.clone(), definition).is_some() {
                        bail!("protocol module graph repeats Rust type name '{name}'");
                    }
                }
                let syn::Item::Impl(item_impl) = item else {
                    continue;
                };
                let Some((_, trait_path, _)) = &item_impl.trait_ else {
                    continue;
                };
                let Some(trait_name) = trait_path
                    .segments
                    .last()
                    .map(|part| part.ident.to_string())
                else {
                    continue;
                };
                if !matches!(trait_name.as_str(), "Serialize" | "Deserialize") {
                    continue;
                }
                let target = type_last_ident(&item_impl.self_ty).with_context(|| {
                    format!("manual serde impl in '{path}' has an unsupported target")
                })?;
                let key = format!("{path}:{target}:{trait_name}");
                if self
                    .manual_serde_impls
                    .insert(key.clone(), semantic_impl(item_impl))
                    .is_some()
                {
                    bail!("protocol graph repeats manual serde authority '{key}'");
                }
            }
        }
        let manual_targets = self
            .manual_serde_impls
            .keys()
            .filter_map(|key| key.rsplit(':').nth(1))
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        for (path, file) in &self.files {
            for item in &file.items {
                let syn::Item::Impl(item_impl) = item else {
                    continue;
                };
                if item_impl.trait_.is_some() {
                    continue;
                }
                let Some(target) = type_last_ident(&item_impl.self_ty) else {
                    continue;
                };
                if manual_targets.contains(&target) {
                    self.manual_serde_support
                        .entry(target)
                        .or_default()
                        .insert(format!("{path}:{}", semantic_impl(item_impl)));
                }
            }
        }
        Ok(())
    }
}

fn validate_file_shape(file: &syn::File, relative: &str) -> Result<()> {
    if file.attrs.iter().any(|attribute| !is_doc(attribute)) {
        bail!("protocol source '{relative}' has an active crate/module attribute");
    }
    if file
        .items
        .iter()
        .any(|item| matches!(item, syn::Item::Macro(_)))
    {
        bail!("protocol source '{relative}' contains a top-level item macro");
    }
    Ok(())
}

fn out_of_line_modules(
    view: SourceView<'_>,
    file: &syn::File,
    relative: &str,
    module_dir: &Path,
) -> Result<Vec<(String, PathBuf)>> {
    let mut modules = Vec::new();
    for item in &file.items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        if module.content.is_some() {
            if exact_cfg_test(&module.attrs) {
                continue;
            }
            bail!("protocol source '{relative}' contains an inline production module");
        }
        if module.attrs.iter().any(|attribute| !is_doc(attribute)) {
            bail!(
                "protocol module '{}' has an active/path attribute",
                module.ident
            );
        }
        let name = module.ident.to_string();
        let flat = slash_path(&module_dir.join(format!("{name}.rs")))?;
        let nested = slash_path(&module_dir.join(&name).join("mod.rs"))?;
        let mut candidates = Vec::new();
        if view.read_optional(&flat)?.is_some() {
            candidates.push(flat);
        }
        if view.read_optional(&nested)?.is_some() {
            candidates.push(nested);
        }
        let [path] = candidates.as_slice() else {
            bail!("protocol module '{name}' must resolve to one default .rs path");
        };
        modules.push((path.clone(), module_dir.join(name)));
    }
    Ok(modules)
}

fn classify_type(item: &syn::Item) -> Result<Option<(String, TypeKind, BTreeSet<String>)>> {
    let (name, kind, types): (String, TypeKind, Vec<&syn::Type>) = match item {
        syn::Item::Struct(item) => {
            let kind = if matches!(item.fields, syn::Fields::Named(_)) {
                TypeKind::NamedStruct
            } else {
                TypeKind::Frozen
            };
            (
                item.ident.to_string(),
                kind,
                item.fields.iter().map(|field| &field.ty).collect(),
            )
        }
        syn::Item::Enum(item) => (
            item.ident.to_string(),
            TypeKind::Frozen,
            item.variants
                .iter()
                .flat_map(|variant| variant.fields.iter().map(|field| &field.ty))
                .collect(),
        ),
        syn::Item::Type(item) => (
            item.ident.to_string(),
            TypeKind::Frozen,
            vec![item.ty.as_ref()],
        ),
        _ => return Ok(None),
    };
    let mut references = BTreeSet::new();
    for ty in types {
        collect_type_references(ty, &mut references);
    }
    references.remove(&name);
    Ok(Some((name, kind, references)))
}

fn collect_type_references(ty: &syn::Type, output: &mut BTreeSet<String>) {
    struct Collector<'a>(&'a mut BTreeSet<String>);
    impl<'ast> syn::visit::Visit<'ast> for Collector<'_> {
        fn visit_type_path(&mut self, path: &'ast syn::TypePath) {
            if path.qself.is_none()
                && let Some(segment) = path.path.segments.last()
            {
                let name = segment.ident.to_string();
                if !is_builtin_type(&name) {
                    self.0.insert(name);
                }
            }
            syn::visit::visit_type_path(self, path);
        }
    }
    syn::visit::Visit::visit_type(&mut Collector(output), ty);
}

fn is_builtin_type(name: &str) -> bool {
    matches!(
        name,
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
}

pub(super) fn semantic_item(item: &syn::Item) -> String {
    let mut item = item.clone();
    strip_item_docs(&mut item);
    item.into_token_stream().to_string()
}

fn semantic_impl(item: &syn::ItemImpl) -> String {
    let mut item = item.clone();
    item.attrs.retain(|attribute| !is_doc(attribute));
    for impl_item in &mut item.items {
        if let syn::ImplItem::Fn(function) = impl_item {
            function.attrs.retain(|attribute| !is_doc(attribute));
        }
    }
    item.into_token_stream().to_string()
}

fn semantic_use(item: &syn::ItemUse) -> String {
    let mut item = item.clone();
    item.attrs.retain(|attribute| !is_doc(attribute));
    item.into_token_stream().to_string()
}

fn semantic_extern_crate(item: &syn::ItemExternCrate) -> String {
    let mut item = item.clone();
    item.attrs.retain(|attribute| !is_doc(attribute));
    item.into_token_stream().to_string()
}

pub(super) fn import_fingerprints(file: &syn::File) -> BTreeSet<String> {
    file.items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Use(item) => Some(semantic_use(item)),
            syn::Item::ExternCrate(item) => Some(semantic_extern_crate(item)),
            _ => None,
        })
        .collect()
}

pub(super) fn module_fingerprints(file: &syn::File) -> Vec<String> {
    file.items
        .iter()
        .filter_map(|item| {
            let syn::Item::Mod(module) = item else {
                return None;
            };
            let mut module = module.clone();
            module.attrs.retain(|attribute| !is_doc(attribute));
            if let Some((brace, _)) = module.content.take() {
                module.content = Some((brace, Vec::new()));
            }
            Some(module.into_token_stream().to_string())
        })
        .collect()
}

pub(super) fn file_attribute_fingerprints(file: &syn::File) -> Vec<String> {
    file.attrs
        .iter()
        .filter(|attribute| !is_doc(attribute))
        .map(|attribute| attribute.to_token_stream().to_string())
        .collect()
}

fn strip_item_docs(item: &mut syn::Item) {
    match item {
        syn::Item::Enum(item) => {
            item.attrs.retain(|attribute| !is_doc(attribute));
            for variant in &mut item.variants {
                variant.attrs.retain(|attribute| !is_doc(attribute));
                for field in &mut variant.fields {
                    field.attrs.retain(|attribute| !is_doc(attribute));
                }
            }
        }
        syn::Item::Struct(item) => {
            item.attrs.retain(|attribute| !is_doc(attribute));
            for field in &mut item.fields {
                field.attrs.retain(|attribute| !is_doc(attribute));
            }
        }
        syn::Item::Type(item) => item.attrs.retain(|attribute| !is_doc(attribute)),
        _ => {}
    }
}

fn item_has_name(item: &syn::Item, expected: &str) -> bool {
    match item {
        syn::Item::Struct(item) => item.ident == expected,
        syn::Item::Enum(item) => item.ident == expected,
        syn::Item::Type(item) => item.ident == expected,
        _ => false,
    }
}

fn type_last_ident(ty: &syn::Type) -> Option<String> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    path.path.segments.last().map(|part| part.ident.to_string())
}

fn exact_cfg_test(attributes: &[syn::Attribute]) -> bool {
    let [attribute] = attributes else {
        return false;
    };
    let syn::Meta::List(meta) = &attribute.meta else {
        return false;
    };
    meta.path.is_ident("cfg") && meta.tokens.to_string() == "test"
}

fn is_doc(attribute: &syn::Attribute) -> bool {
    attribute.path().is_ident("doc")
}

fn slash_path(path: &Path) -> Result<String> {
    Ok(path
        .to_str()
        .context("protocol module path is not UTF-8")?
        .replace(std::path::MAIN_SEPARATOR, "/"))
}
