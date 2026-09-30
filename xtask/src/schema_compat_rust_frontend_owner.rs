//! Resolve relocated public frontend contracts through their actual canonical re-export.
//! The synthetic scope is only a validation view; production continues to have one type owner.
use super::cli_main::flatten_use;
use super::semantics::graph::SourceView;
use anyhow::{Result, bail};
use std::collections::{BTreeMap, BTreeSet};

const RUNTIME: &str = "crates/cli/src/runtime.rs";
const OWNER: &str = "crates/cli/src/runtime/frontend_events.rs";

pub(super) fn runtime_scope(view: SourceView<'_>) -> Result<syn::File> {
    let mut runtime = view.parse_file(RUNTIME)?;
    if runtime
        .items
        .iter()
        .any(|item| matches!(item, syn::Item::Enum(e) if e.ident == "UiEvent"))
    {
        return Ok(runtime);
    }
    let declarations = runtime
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Mod(module) if module.ident == "frontend_events" => Some(module),
            _ => None,
        })
        .collect::<Vec<_>>();
    if declarations.len() != 1
        || declarations[0].content.is_some()
        || !declarations[0].attrs.is_empty()
    {
        bail!("runtime frontend type owner is missing, conditional or redirected");
    }
    let mut public = BTreeSet::new();
    for item in &runtime.items {
        if let syn::Item::Use(import) = item {
            let mut bindings = Vec::new();
            flatten_use(&import.tree, &mut Vec::new(), &mut bindings)?;
            for (name, origin, renamed) in bindings {
                if origin.first().is_some_and(|name| name == "frontend_events") {
                    if renamed
                        || !import.attrs.is_empty()
                        || origin != ["frontend_events".to_owned(), name.clone()]
                    {
                        bail!("runtime frontend contract re-export is conditional or renamed");
                    }
                    if matches!(import.vis, syn::Visibility::Public(_)) && !public.insert(name) {
                        bail!("runtime frontend contract has duplicate public re-exports");
                    }
                }
            }
        }
    }
    let expected = [
        "ApprovalResolution",
        "ControlSubmissionKind",
        "UiEvent",
        "WorkflowAgentOutcomeUi",
        "WorkflowExecutionModeUi",
        "WorkflowPhaseUi",
        "WorkflowRunOutcomeUi",
        "WorkflowTaskUi",
        "WorkflowUiEvent",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    if public != expected {
        bail!("runtime frontend contract public ownership differs from its canonical surface");
    }
    let owner = view.parse_file(OWNER)?;
    if owner.attrs.iter().any(|attr| !attr.path().is_ident("doc")) {
        bail!("runtime frontend owner has active crate authority");
    }
    let root_imports = origins(&runtime)?;
    let owner_imports = origins(&owner)?;
    for (name, origin) in owner_imports {
        if root_imports.get(&name) != Some(&origin) {
            bail!("runtime frontend type dependency '{name}' changes authority during relocation");
        }
    }
    for name in &expected {
        let definitions = owner
            .items
            .iter()
            .filter(|item| match item {
                syn::Item::Enum(item) => item.ident == name,
                syn::Item::Struct(item) => item.ident == name,
                _ => false,
            })
            .count();
        if definitions != 1 {
            bail!("runtime frontend owner lacks one definition of '{name}'");
        }
    }
    runtime.items.retain(|item| !matches!(item, syn::Item::Use(import) if starts_with(&import.tree, "frontend_events")));
    runtime.items.extend(
        owner
            .items
            .into_iter()
            .filter(|item| !matches!(item, syn::Item::Use(_))),
    );
    Ok(runtime)
}

fn starts_with(tree: &syn::UseTree, name: &str) -> bool {
    matches!(tree, syn::UseTree::Path(path) if path.ident == name)
}

fn origins(file: &syn::File) -> Result<BTreeMap<String, Vec<String>>> {
    let mut result = BTreeMap::new();
    for item in &file.items {
        if let syn::Item::Use(import) = item {
            let mut bindings = Vec::new();
            flatten_use(&import.tree, &mut Vec::new(), &mut bindings)?;
            for (name, origin, renamed) in bindings {
                if name == "_" {
                    continue;
                }
                // Unrelated renames stay in their production scope. Relocated type imports must
                // match exactly and are separately required to be ordinary below.
                let value = if renamed || !import.attrs.is_empty() {
                    vec!["<active-or-renamed>".into()]
                } else {
                    origin
                };
                if result.insert(name, value).is_some() {
                    bail!("runtime frontend import identity is ambiguous");
                }
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_contract_relocation_keeps_one_canonical_type_owner() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        let resolved = runtime_scope(SourceView::Candidate { root }).unwrap();
        assert_eq!(
            resolved
                .items
                .iter()
                .filter(|item| matches!(item, syn::Item::Enum(e) if e.ident == "UiEvent"))
                .count(),
            1
        );
    }

    #[test]
    fn redirected_owner_import_or_module_is_rejected() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        let temporary = std::env::temp_dir().join(format!(
            "iteron-frontend-owner-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(temporary.join("crates/cli/src/runtime")).unwrap();
        let runtime = std::fs::read_to_string(root.join(RUNTIME)).unwrap();
        let owner = std::fs::read_to_string(root.join(OWNER)).unwrap();
        std::fs::write(temporary.join(RUNTIME), &runtime).unwrap();
        std::fs::write(temporary.join(OWNER), &owner).unwrap();
        runtime_scope(SourceView::Candidate { root: &temporary }).unwrap();
        std::fs::write(
            temporary.join(OWNER),
            owner.replacen(
                "use iteron_ctx::ContextEstimate;",
                "use evil::ContextEstimate;",
                1,
            ),
        )
        .unwrap();
        assert!(runtime_scope(SourceView::Candidate { root: &temporary }).is_err());
        std::fs::write(temporary.join(OWNER), owner).unwrap();
        std::fs::write(
            temporary.join(RUNTIME),
            runtime.replacen(
                "mod frontend_events;",
                "#[path = \"evil.rs\"] mod frontend_events;",
                1,
            ),
        )
        .unwrap();
        assert!(runtime_scope(SourceView::Candidate { root: &temporary }).is_err());
        std::fs::remove_dir_all(temporary).unwrap();
    }
}
