//! The composition root's `core-evolve` → `core-agents` bundle projection.
//!
//! This adapter exists so that `crates/agents` and `crates/kernel` never name the evolution crate.
//! Both sides already agree on a shape — `PolicyRef` and `ResolvedPolicy` carry the same four
//! fields — but agreeing on a shape is not the same as sharing a dependency, and the frozen-TCB
//! invariant is about the dependency. The projection is therefore done exactly here, in the one
//! crate whose job is to know about everything.
//!
//! The data contract is single-direction and read-only. Nothing here can activate, admit, or roll
//! back a bundle: it reads the pointer the offline `PromotionAuthority` already wrote, and the only
//! thing it produces is a view with no policy bodies in it.
//!
//! # Only an already-promoted bundle can be resolved
//!
//! `PromotionAuthority::active_bundle` is the single source. A candidate or shadow bundle has no
//! path into this function, because there is no other input: the resolver holds an authority and
//! asks it for the active pointer. That is the structural form of "a candidate cannot be resolved
//! as active" — not a filter that could be forgotten, but an absence of any other way in.

use core_protocol::bundle::{
    BundleResolutionError, PolicyBundleResolver, ResolvedBundle, ResolvedPolicy,
};
use core_protocol::slot::SlotId;

/// Project the offline authority's active bundle into the agents-local read-only view.
pub(crate) fn project(
    bundle: &core_evolve::PolicyBundle,
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
    active: Option<core_evolve::PolicyBundle>,
}

impl ActiveBundleResolver {
    /// Read the active pointer once. An authority that cannot answer yields no bundle rather than
    /// an error, because "no promotion has happened" and "promotion is not configured" are the same
    /// thing to a run: it proceeds ungoverned, on the hand-written baseline.
    pub(crate) fn from_active(active: Option<core_evolve::PolicyBundle>) -> Self {
        Self { active }
    }
}

impl PolicyBundleResolver for ActiveBundleResolver {
    fn active_bundle(&self) -> Result<Option<ResolvedBundle>, BundleResolutionError> {
        self.active.as_ref().map(project).transpose()
    }
}

#[cfg(test)]
#[path = "bundle_adapter_tests.rs"]
mod tests;
