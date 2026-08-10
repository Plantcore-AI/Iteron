//! The composition root's `iteron-evolve` → `iteron-agents` bundle projection.
//!
//! This adapter exists so that `crates/agents` and `crates/kernel` never name the evolution crate.
//! Both sides already agree on a shape — `PolicyRef` and `ResolvedPolicy` carry the same four
//! fields — but agreeing on a shape is not the same as sharing a dependency, and the frozen-TCB
//! invariant is about the dependency. The projection is therefore done exactly here, in the one
//! crate whose job is to know about everything.
//!
//! The data contract is single-direction and read-only. Nothing here can train, promote, or roll
//! back a bundle: it projects the trusted user configuration's operator-selected active identity
//! snapshot, and the only thing it produces is a view with no policy bodies in it.
//!
//! # Only an already-promoted bundle can be resolved
//!
//! `FileConfig::active_policy_bundle` is the single composition-root input. Project configuration
//! is explicitly ignored, so workspace content cannot select a candidate. The snapshot must pass
//! `PolicyBundle::validate` before boot and is resolved once into an immutable `BootBundle`.

use iteron_protocol::bundle::{
    BundleResolutionError, PolicyBundleResolver, ResolvedBundle, ResolvedPolicy,
};
use iteron_protocol::slot::SlotId;

/// Project the offline authority's active bundle into the agents-local read-only view.
pub(crate) fn project(
    bundle: &iteron_evolve::PolicyBundle,
) -> Result<ResolvedBundle, BundleResolutionError> {
    let resolved = ResolvedBundle {
        bundle_id: bundle.bundle_id.clone(),
        digest: bundle.digest.clone(),
        policies: bundle
            .policies
            .iter()
            .map(|policy| ResolvedPolicy {
                // The slot grammars are separately validated on both sides; the projection carries
                // the string across and lets `ResolvedBundle::validate` refuse anything the
                // agents-local grammar does not accept, rather than assuming they agree.
                slot: SlotId(policy.slot.as_str().to_owned()),
                policy_id: policy.policy_id.clone(),
                version: policy.version.clone(),
                digest: policy.digest.clone(),
            })
            .collect(),
    };
    resolved.validate()?;
    Ok(resolved)
}

/// A resolver backed by the offline promotion authority's active-bundle pointer.
///
/// Boot-time only: the composition root builds one, resolves once, and drops it. It is not stored
/// anywhere a later caller could reach to ask again.
pub(crate) struct ActiveBundleResolver {
    active: Option<iteron_evolve::PolicyBundle>,
}

impl ActiveBundleResolver {
    /// Read the active pointer once. An authority that cannot answer yields no bundle rather than
    /// an error, because "no promotion has happened" and "promotion is not configured" are the same
    /// thing to a run: it proceeds ungoverned, on the hand-written baseline.
    pub(crate) fn from_active(active: Option<iteron_evolve::PolicyBundle>) -> Self {
        Self { active }
    }
}

impl PolicyBundleResolver for ActiveBundleResolver {
    fn active_bundle(&self) -> Result<Option<ResolvedBundle>, BundleResolutionError> {
        self.active.as_ref().map(project).transpose()
    }
}

/// Resolve the hand-written baseline when no trusted active snapshot was selected.
pub(crate) fn resolve_boot_bundle() -> std::sync::Arc<iteron_agents::BootBundle> {
    resolve_boot_bundle_from_active(None)
}

/// Resolve one operator-selected, already-active identity snapshot at process boot.
pub(crate) fn resolve_boot_bundle_from_active(
    active: Option<iteron_evolve::PolicyBundle>,
) -> std::sync::Arc<iteron_agents::BootBundle> {
    let resolver = ActiveBundleResolver::from_active(active);
    // A malformed projection is not a licence to improvise: fall to the baseline, like absence.
    std::sync::Arc::new(
        iteron_agents::BootBundle::resolve(&resolver)
            .unwrap_or_else(|_| iteron_agents::BootBundle::baseline()),
    )
}

/// Narrow a freshly built read-only registry into the child tool set the bundle in force governs.
///
/// This is where the promotion machinery stops being a ledger nobody reads. Both child paths (the
/// parent-internal fan-out and the workflow `AgentSpawner`) go through here, so the governed
/// selection cannot be applied on one path and forgotten on the other.
///
/// Two separate guarantees, both from `iteron-agents`:
/// - `narrow_under` decides the SET, and can only ever return a subset of what the definition's
///   filter already allowed — a promoted bundle can reorder what a worker reaches for and can
///   never hand it a tool the filter refused;
/// - `promoted_leading` decides the ORDER, and is empty for the baseline, so an ungoverned run
///   gets exactly the registration order `narrow_to` would have produced.
pub(crate) fn narrow_child_registry(
    registry: &mut iteron_tools::Registry,
    filter: &iteron_agents::ToolFilter,
    boot: &iteron_agents::BootBundle,
) -> Vec<String> {
    let preference = boot.tool_preference();
    registry.narrow_to_promoting(
        &iteron_agents::narrow_under(filter, preference),
        preference.promoted_leading(),
    )
}

#[cfg(test)]
#[path = "bundle_adapter_tests.rs"]
mod tests;
