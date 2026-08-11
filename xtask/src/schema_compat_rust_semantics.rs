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
use graph::{ProtocolGraph, SourceView, TypeKind, identifier_occurrences};
use std::collections::{BTreeMap, BTreeSet};
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
    let binding_references =
        compare_reachable_protocol_types(&base_graph, &candidate_graph, previous)?;
    compare_protocol_bindings(&base_graph, &candidate_graph, &binding_references)?;
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
    binding_references: &BTreeMap<String, BTreeSet<String>>,
) -> Result<()> {
    for (path, referenced) in binding_references {
        if base.imports_reaching(path, referenced)?
            != candidate.imports_reaching(path, referenced)?
        {
            bail!("protocol module '{path}' changed its import/re-export bindings");
        }
        let base_modules = base.module_fingerprints(path)?;
        let candidate_modules = candidate.module_fingerprints(path)?;
        if !base_modules.is_subset(&candidate_modules) {
            bail!("protocol module '{path}' removed or changed a module declaration");
        }
    }
    // Same asymmetry as the module declarations above, for the same reason: a type the base never
    // declared cannot be a type the base put on the wire. Rewriting or dropping an authority the
    // base did publish stays fatal, and so does moving an existing type off `derive` onto a hand
    // written impl, which is how a shape would change while its fingerprint stood still.
    for (key, body) in &base.manual_serde_impls {
        if candidate.manual_serde_impls.get(key) != Some(body) {
            bail!("protocol manual Serialize/Deserialize authority changed from the trusted base");
        }
    }
    for key in candidate.manual_serde_impls.keys() {
        if base.manual_serde_impls.contains_key(key) {
            continue;
        }
        let Some(target) = key.rsplit(':').nth(1) else {
            continue;
        };
        if base.types.contains_key(target) {
            bail!(
                "protocol type '{target}' took over its own serde authority from the trusted base"
            );
        }
    }
    for (target, support) in &base.manual_serde_support {
        if candidate.manual_serde_support.get(target) != Some(support) {
            bail!("protocol manual serde support methods changed from the trusted base");
        }
    }
    for target in candidate.manual_serde_support.keys() {
        if !base.manual_serde_support.contains_key(target) && base.types.contains_key(target) {
            bail!("protocol type '{target}' gained manual serde support methods");
        }
    }
    Ok(())
}

fn compare_reachable_protocol_types(
    base: &ProtocolGraph,
    candidate: &ProtocolGraph,
    previous: &Contract,
) -> Result<BTreeMap<String, BTreeSet<String>>> {
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
    let mut binding_references = BTreeMap::<String, BTreeSet<String>>::new();
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
        identifier_occurrences(
            &old.fingerprint,
            binding_references.entry(old.path.clone()).or_default(),
        );
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
    Ok(binding_references)
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
