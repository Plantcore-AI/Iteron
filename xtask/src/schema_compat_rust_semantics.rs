#[path = "schema_compat_rust_semantics_functions.rs"]
mod functions;
#[path = "schema_compat_rust_semantics_graph.rs"]
mod graph;
#[path = "schema_compat_rust_semantics_serde.rs"]
mod serde_attrs;
#[path = "schema_compat_rust_semantics_surface.rs"]
mod surface;

use super::super::manifest::Contract;
use anyhow::{Context, Result, bail};
use graph::{ProtocolGraph, SourceView, TypeKind};
use std::collections::BTreeSet;
use std::path::Path;

/// Compare source semantics with the trusted Git base after both contracts have been validated.
///
/// The manifest comparison decides which wire names remain live. This bridge independently binds
/// those retained names to their Rust types/serde behavior and freezes the small set of authority
/// functions that turn versions, records, and CLI output into enforceable runtime behavior.
pub(super) fn compare(
    root: &Path,
    base: &str,
    previous: &Contract,
    candidate: &Contract,
) -> Result<()> {
    if !previous
        .surfaces
        .iter()
        .any(|surface| managed_surface(&surface.id))
    {
        return Ok(());
    }
    let base_view = SourceView::Base {
        root,
        revision: base,
    };
    let candidate_view = SourceView::Candidate { root };
    let base_graph = ProtocolGraph::load(base_view)?;
    let candidate_graph = ProtocolGraph::load(candidate_view)?;

    surface::compare_surfaces(
        base_view,
        candidate_view,
        &base_graph,
        &candidate_graph,
        previous,
        candidate,
    )?;
    let binding_paths = compare_reachable_protocol_types(&base_graph, &candidate_graph, previous)?;
    compare_protocol_bindings(&base_graph, &candidate_graph, &binding_paths)?;
    functions::compare_critical_functions(base_view, candidate_view)
}

fn managed_surface(id: &str) -> bool {
    matches!(
        id,
        "protocol.sq-envelope"
            | "protocol.eq-envelope"
            | "record.rollout"
            | "record.event-envelope"
            | "kernel.diagnostic"
            | "cli.machine-result"
    ) || id.starts_with("protocol.op.")
        || id.starts_with("record.event-kind.")
        || id.starts_with("record.block.")
        || id.starts_with("record.workflow-event.")
        || id.starts_with("record.cost-attribution.")
        || id.starts_with("record.named.")
        || id.starts_with("cli.machine-stream.")
}

fn compare_protocol_bindings(
    base: &ProtocolGraph,
    candidate: &ProtocolGraph,
    binding_paths: &BTreeSet<String>,
) -> Result<()> {
    let current_imports = candidate.imports();
    let base_modules = base.modules();
    let current_modules = candidate.modules();
    for (path, old_imports) in base.imports() {
        if !binding_paths.contains(&path) {
            continue;
        }
        let new_imports = current_imports
            .get(&path)
            .with_context(|| format!("candidate protocol graph removed base module '{path}'"))?;
        if &old_imports != new_imports {
            bail!("protocol module '{path}' changed its import/re-export bindings");
        }
        if base_modules.get(&path) != current_modules.get(&path) {
            bail!("protocol module '{path}' changed its module declarations");
        }
    }
    if base.manual_serde_impls != candidate.manual_serde_impls {
        bail!("protocol manual Serialize/Deserialize authority changed from the trusted base");
    }
    if base.manual_serde_support != candidate.manual_serde_support {
        bail!("protocol manual serde support methods changed from the trusted base");
    }
    Ok(())
}

fn compare_reachable_protocol_types(
    base: &ProtocolGraph,
    candidate: &ProtocolGraph,
    previous: &Contract,
) -> Result<BTreeSet<String>> {
    let mut surfaced = BTreeSet::from([
        "SqEnvelope".to_owned(),
        "EqEnvelope".to_owned(),
        "Event".to_owned(),
        "Op".to_owned(),
        "EventKind".to_owned(),
        "Block".to_owned(),
        "WorkflowEvent".to_owned(),
        "CostAttribution".to_owned(),
    ]);
    for surface in &previous.surfaces {
        if surface.id.starts_with("record.named.") {
            surfaced.insert(base.named_surface_type(&surface.id)?);
        }
    }

    let mut pending = surfaced.clone();
    pending.extend([
        "DiffTag".to_owned(),
        "DiffLine".to_owned(),
        "Hunk".to_owned(),
        "FileDiff".to_owned(),
        "Outcome".to_owned(),
        "StopReasonCode".to_owned(),
    ]);
    let mut visited = BTreeSet::new();
    let mut binding_paths = BTreeSet::from(["crates/protocol/src/lib.rs".to_owned()]);
    while let Some(name) = pending.pop_first() {
        if !visited.insert(name.clone()) {
            continue;
        }
        let Some(old) = base.types.get(&name) else {
            if candidate.types.contains_key(&name) {
                bail!(
                    "candidate protocol graph shadows reachable external type '{name}' with a local declaration"
                );
            }
            continue;
        };
        let current = candidate
            .types
            .get(&name)
            .with_context(|| format!("candidate protocol graph removed reachable type '{name}'"))?;
        binding_paths.insert(old.path.clone());
        if old.path != current.path || old.kind != current.kind {
            bail!("reachable protocol type '{name}' changed its source identity");
        }
        let is_surface_item = surfaced.contains(&name)
            && (old.kind == TypeKind::NamedStruct
                || matches!(
                    name.as_str(),
                    "Op" | "EventKind" | "Block" | "WorkflowEvent" | "CostAttribution"
                ));
        if !is_surface_item && old.fingerprint != current.fingerprint {
            bail!("reachable non-surfaced protocol type '{name}' changed from the trusted base");
        }
        pending.extend(old.references.iter().cloned());
    }
    Ok(binding_paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn d13_14_semantic_compare_loads_the_candidate_protocol_graph() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask is directly below the repository root");
        let graph = ProtocolGraph::load(SourceView::Candidate { root }).unwrap();
        assert!(graph.types.contains_key("EventKind"));
        assert!(graph.types.contains_key("Role"));
        assert!(
            graph
                .manual_serde_impls
                .keys()
                .any(|key| key.contains("ProviderStateFormat"))
        );

        let base = ProtocolGraph::load(SourceView::Base {
            root,
            revision: "HEAD",
        })
        .unwrap();
        assert!(base.types.contains_key("EventKind"));
    }
}

#[cfg(test)]
#[path = "schema_compat_rust_semantics_adversarial_tests.rs"]
mod adversarial_tests;
