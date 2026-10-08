//! Validation views for the common producer and its physical CLI writer. Every forwarding
//! binding is proved against the real owner before the two scopes are compared with old output.
use super::cli_main::flatten_use;
use super::cli_parse::parse_cli_output_source;
use super::semantics::graph::SourceView;
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;

const COMMON: &str = "crates/cli/src/machine_projection.rs";
const WRITER: &str = "crates/cli/src/output.rs";
const FORWARDED: &[&str] = &[
    "DEFAULT_SCHEMA_VERSION",
    "EXIT_HARNESS",
    "EXIT_INTERRUPTED",
    "EXIT_SUCCESS",
    "EXIT_WORKFLOW_FAILED",
    "SUPPORTED_SCHEMA_VERSIONS",
    "budget_remedy",
    "final_result",
    "outcome_exit_code",
    "LEGACY_SCHEMA_VERSION",
    "StreamingScrubber",
    "input_attachment_metadata",
    "project_schema",
    "stream_event",
];
fn exact_test(attrs: &[syn::Attribute]) -> bool {
    attrs.len() == 1
        && attrs[0].path().is_ident("cfg")
        && matches!(&attrs[0].meta,syn::Meta::List(m) if m.tokens.to_string()=="test")
}
fn doc_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().all(|a| a.path().is_ident("doc"))
}
fn bindings(file: &syn::File, omit_test: bool) -> Result<BTreeMap<String, Vec<String>>> {
    let mut result = BTreeMap::new();
    for item in &file.items {
        let syn::Item::Use(import) = item else {
            continue;
        };
        if omit_test && exact_test(&import.attrs) {
            continue;
        }
        if !doc_only(&import.attrs) {
            bail!("machine authority import is conditional or attributed")
        }
        let mut entries = Vec::new();
        flatten_use(&import.tree, &mut Vec::new(), &mut entries)?;
        for (mut name, mut origin, renamed) in entries {
            if renamed {
                bail!("machine authority import is renamed")
            }
            if name == "self" {
                origin.pop();
                name = origin.last().context("self import has no module")?.clone()
            }
            if result.insert(name.clone(), origin).is_some() {
                bail!("machine authority repeats import '{name}'")
            }
        }
    }
    Ok(result)
}
fn require_origin(
    imports: &BTreeMap<String, Vec<String>>,
    name: &str,
    expected: &[&str],
) -> Result<()> {
    let expected = expected.iter().map(|v| (*v).to_owned()).collect::<Vec<_>>();
    if imports.get(name) != Some(&expected) {
        bail!("machine writer '{name}' has redirected authority")
    }
    Ok(())
}
fn normalize_imports(file: &mut syn::File, imports: BTreeMap<String, Vec<String>>) -> Result<()> {
    file.items.retain(|item| !matches!(item, syn::Item::Use(_)));
    for (name, origin) in imports {
        if origin.last() != Some(&name) {
            bail!("normalized machine import has an ambiguous origin")
        }
        let import: syn::ItemUse = syn::parse_str(&format!("use {};", origin.join("::")))?;
        file.items.push(syn::Item::Use(import));
    }
    Ok(())
}
fn normalized_legacy(mut file: syn::File) -> Result<syn::File> {
    let imports = bindings(&file, true)?;
    normalize_imports(&mut file, imports)?;
    Ok(file)
}
fn require_common_module(view: SourceView<'_>) -> Result<()> {
    let main = view.parse_file("crates/cli/src/main.rs")?;
    let modules = main
        .items
        .iter()
        .filter_map(|i| match i {
            syn::Item::Mod(m) if m.ident == "machine_projection" => Some(m),
            _ => None,
        })
        .collect::<Vec<_>>();
    if modules.len() != 1 || modules[0].content.is_some() || !doc_only(&modules[0].attrs) {
        bail!("common machine owner is missing, conditional or redirected")
    }
    Ok(())
}
fn merge(mut common: syn::File, writer: syn::File) -> Result<syn::File> {
    if !doc_only(&writer.attrs) {
        bail!("physical writer has active crate authority")
    }
    let mut imports = bindings(&common, false)?;
    let writer_imports = bindings(&writer, true)?;
    for name in FORWARDED {
        require_origin(
            &writer_imports,
            name,
            &["crate", "machine_projection", name],
        )?;
    }
    for (name, origin) in writer_imports {
        if origin.first().is_some_and(|v| v == "crate")
            && origin.get(1).is_some_and(|v| v == "machine_projection")
        {
            if !FORWARDED.contains(&name.as_str()) {
                bail!("physical writer has an undeclared machine forwarding binding")
            }
            continue;
        }
        if let Some(old) = imports.get(&name) {
            if old != &origin {
                bail!("machine producer/writer bind '{name}' to different owners")
            }
        } else {
            imports.insert(name, origin);
        }
    }
    require_origin(&imports, "Write", &["std", "io", "Write"])?;
    require_origin(&imports, "Value", &["serde_json", "Value"])?;
    require_origin(&imports, "ValueEnum", &["clap", "ValueEnum"])?;
    require_origin(&imports, "UiEvent", &["crate", "runtime", "UiEvent"])?;
    for item in writer.items {
        if matches!(item, syn::Item::Use(_)) {
            continue;
        }
        if let syn::Item::Fn(f) = &item
            && FORWARDED.iter().any(|n| f.sig.ident == *n)
        {
            bail!("physical writer shadows a forwarded producer")
        }
        if let syn::Item::Struct(s) = &item
            && s.ident == "StreamingScrubber"
        {
            bail!("physical writer duplicates the redaction owner")
        }
        common.items.push(item);
    }
    // Visibility changed solely to let the actual writer borrow this existing private owner.
    // Its state fields, signature and executable bodies remain under the frozen comparison.
    for item in &mut common.items {
        if let syn::Item::Impl(i) = item
            && matches!(i.self_ty.as_ref(),syn::Type::Path(p) if p.qself.is_none() && p.path.is_ident("StreamingScrubber"))
        {
            for m in &mut i.items {
                if let syn::ImplItem::Fn(f) = m {
                    if !matches!(f.vis,syn::Visibility::Restricted(ref v) if v.path.is_ident("crate"))
                    {
                        bail!("shared scrubber method has changed visibility authority")
                    }
                    f.vis = syn::Visibility::Inherited;
                }
            }
        }
    }
    normalize_imports(&mut common, imports)?;
    Ok(common)
}
pub(super) fn scope(view: SourceView<'_>) -> Result<syn::File> {
    let writer = view.parse_file(WRITER)?;
    let Some(bytes) = view.read_optional(COMMON)? else {
        return normalized_legacy(writer);
    };
    require_common_module(view)?;
    let source = std::str::from_utf8(&bytes).context("common machine source is not UTF-8")?;
    merge(parse_cli_output_source(source)?, writer)
}
pub(super) fn current_scope(root: &std::path::Path, source: &[u8]) -> Result<syn::File> {
    let view = SourceView::Candidate { root };
    let source = std::str::from_utf8(source).context("machine source is not UTF-8")?;
    if view.read_optional(COMMON)?.is_none() {
        return normalized_legacy(parse_cli_output_source(source)?);
    }
    require_common_module(view)?;
    merge(parse_cli_output_source(source)?, view.parse_file(WRITER)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn writer() -> syn::File {
        let imports = FORWARDED
            .iter()
            .map(|name| format!("use crate::machine_projection::{name};"))
            .collect::<Vec<_>>()
            .join("\n");
        syn::parse_str(&format!("{imports} use std::io::Write; use serde_json::Value; use clap::ValueEnum; use crate::runtime::UiEvent;")).unwrap()
    }
    fn common() -> syn::File {
        syn::parse_quote!(
            use serde_json::{Value, json};
        )
    }
    #[test]
    fn actual_forwarding_refuses_redirected_producer_and_unnamed_trait_authority() {
        merge(common(), writer()).unwrap();
        let mut redirect = writer();
        redirect.items[0] = syn::parse_quote!(use crate::fake::DEFAULT_SCHEMA_VERSION);
        assert!(merge(common(), redirect).is_err());
        let mut conditional = writer();
        conditional.items[0] =
            syn::parse_quote!(#[cfg(unix)] use crate::machine_projection::DEFAULT_SCHEMA_VERSION);
        assert!(merge(common(), conditional).is_err());
        let mut fake = writer();
        fake.items.push(syn::parse_quote!(
            fn stream_event() {}
        ));
        assert!(merge(common(), fake).is_err());
        let mut trait_import = writer();
        trait_import
            .items
            .push(syn::parse_quote!(use evil::Write as _));
        assert!(merge(common(), trait_import).is_err());
        let mut duplicate = writer();
        duplicate.items.push(syn::parse_quote!(
            struct StreamingScrubber;
        ));
        assert!(merge(common(), duplicate).is_err());
    }
}
