//! Boot-time policy-bundle consumption: a promoted bundle statically shifts agent behavior.
//!
//! This is the read side of the control plane. An offline `PromotionAuthority` decides, long before
//! this code runs, which bundle is active; a composition root projects that decision into a
//! [`ResolvedBundle`] once, at boot; and this module is where the projection finally changes what an
//! agent does. Without this last step the whole promotion machinery is a ledger nobody reads.
//!
//! # What is deliberately absent
//!
//! There is no create, admit, activate, promote, or swap here, and no way to reach the evolution
//! crate: `crates/agents` does not depend on `core-evolve`, and neither does `crates/kernel`. The
//! only thing that crosses is [`ResolvedBundle`], which carries policy *identities* and no policy
//! bodies. Live self-activation stays NO-GO because the surface that would perform it does not
//! exist, not because a comment asks for restraint.
//!
//! [`BootBundle`] is resolved once and hands out only shared borrows, so "static thereafter" is a
//! property of the type rather than a convention. `ResolvedBundle`'s own documentation is explicit
//! that its fields are `pub` and that whoever wires the composition root is the one who makes it
//! immutable in fact — this is that.
//!
//! # Fail-safe, in every direction
//!
//! Absent bundle, unreadable resolver, malformed view, a bundle that does not govern the slot, or a
//! policy identity this build has never heard of: every one of them lands on the hand-written
//! baseline. A promoted policy can only shift behavior it is recognised for. That asymmetry is the
//! point — an unknown policy must not be able to change what an agent does by being unrecognisable.

use crate::def::ToolFilter;
use core_protocol::bundle::{BundleResolutionError, PolicyBundleResolver, ResolvedBundle};
use core_protocol::slot::SlotId;

/// The slot whose promoted policy this module reads.
pub fn tool_policy_slot() -> SlotId {
    SlotId("core/tool_policy".into())
}

/// A recognised tool-preference behavior, chosen by promoted policy identity.
///
/// The identity is the whole input. `ResolvedPolicy` carries no payload by design — the runtime
/// never sees a policy body — so a promoted policy selects among behaviors this build already
/// implements rather than describing a new one. A build that does not recognise an identity falls
/// back rather than guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolPreference {
    /// The hand-written ordering: `READ_ONLY_TOOLS` as declared.
    Baseline,
    /// Prefer the fast structural searchers, then everything else in declared order.
    ///
    /// This is the behavior the promotion example names: a bundle whose `core/tool_policy` prefers
    /// a ripgrep-class searcher over a naive recursive grep.
    PreferStructuralSearch,
}

/// Policy identities this build recognises. Anything else is unknown, and unknown means baseline.
const RECOGNISED_POLICIES: &[(&str, ToolPreference)] = &[(
    "prefer-structural-search",
    ToolPreference::PreferStructuralSearch,
)];

/// The tools the structural-search preference floats to the front, in that order.
const STRUCTURAL_SEARCH_ORDER: &[&str] = &["glob", "grep", "repo_map"];

impl ToolPreference {
    /// Read the preference a resolved bundle governs this build into.
    ///
    /// Every failure mode collapses to [`ToolPreference::Baseline`]: no bundle, a bundle that does
    /// not govern `core/tool_policy`, a view that does not validate, or an identity this build does
    /// not recognise.
    pub fn from_bundle(bundle: Option<&ResolvedBundle>) -> Self {
        let Some(bundle) = bundle else {
            return Self::Baseline;
        };
        // A view that does not validate is not a licence to improvise. Duplicate slots, a bad
        // digest, or an out-of-bounds field all mean the projection cannot be trusted to say what
        // governed the run, so nothing governs it.
        if bundle.validate().is_err() {
            return Self::Baseline;
        }
        let Some(policy) = bundle.policy_for(&tool_policy_slot()) else {
            return Self::Baseline;
        };
        RECOGNISED_POLICIES
            .iter()
            .find(|(id, _)| *id == policy.policy_id)
            .map_or(Self::Baseline, |(_, preference)| *preference)
    }

    /// Resolve once from a port, then never ask again. Errors are baseline, like absence.
    ///
    /// A resolver that fails is deliberately *not* distinguished from one with no active bundle
    /// here. The distinction matters to an operator and is preserved by the port itself
    /// (`BundleResolutionError`); what an agent does about it is the same either way, and quietly
    /// running ungoverned is the only safe answer to "I could not tell".
    pub fn resolve_at_boot(resolver: &dyn PolicyBundleResolver) -> Self {
        match resolver.active_bundle() {
            Ok(bundle) => Self::from_bundle(bundle.as_ref()),
            Err(_) => Self::Baseline,
        }
    }

    /// The tools this preference promotes to the front of a child's tool set, in that order.
    ///
    /// [`narrow_under`] decides *what* a governed worker may reach; this decides *what it reaches
    /// for first* once a host has narrowed a real tool set. The two are separate because a host's
    /// tool registry owns its own ordering and only ever filters by membership, so the governed
    /// order has to be applied to the registry deliberately rather than inferred from an allowlist.
    ///
    /// [`ToolPreference::Baseline`] promotes nothing. That is the load-bearing half: an ungoverned
    /// run applies an empty promotion, which is the identity, so wiring this into a host cannot
    /// change a single ordering until a bundle is actually promoted.
    pub fn promoted_leading(self) -> &'static [&'static str] {
        match self {
            Self::Baseline => &[],
            Self::PreferStructuralSearch => STRUCTURAL_SEARCH_ORDER,
        }
    }
}

/// Apply a filter under a governed preference.
///
/// Narrowing runs first and is untouched: a promoted policy may reorder what an agent reaches for,
/// and may never widen what it is allowed to reach. `ToolFilter::narrow` can only ever return a
/// subset of `READ_ONLY_TOOLS`, and this reorders that subset — so no bundle, however promoted, can
/// hand a fan-out worker a tool the filter refused.
pub fn narrow_under(filter: &ToolFilter, preference: ToolPreference) -> Vec<String> {
    let narrowed = filter.narrow();
    match preference {
        ToolPreference::Baseline => narrowed,
        ToolPreference::PreferStructuralSearch => {
            let mut preferred: Vec<String> = STRUCTURAL_SEARCH_ORDER
                .iter()
                .filter(|name| narrowed.iter().any(|tool| tool == *name))
                .map(|name| (*name).to_owned())
                .collect();
            preferred.extend(
                narrowed
                    .into_iter()
                    .filter(|tool| !STRUCTURAL_SEARCH_ORDER.contains(&tool.as_str())),
            );
            preferred
        }
    }
}

/// The bundle in force for this process, resolved once.
///
/// Construction is the only way in, and it hands out shared borrows only. There is no `set`, no
/// `reload`, and no interior mutability, so "resolved once at boot, static thereafter" cannot be
/// violated by a caller that means well.
#[derive(Debug)]
pub struct BootBundle {
    bundle: Option<ResolvedBundle>,
    preference: ToolPreference,
}

impl BootBundle {
    /// Resolve at boot. This is the only call to the port for the process lifetime.
    pub fn resolve(resolver: &dyn PolicyBundleResolver) -> Result<Self, BundleResolutionError> {
        let bundle = resolver.active_bundle()?;
        if let Some(bundle) = &bundle {
            bundle.validate()?;
        }
        Ok(Self {
            preference: ToolPreference::from_bundle(bundle.as_ref()),
            bundle,
        })
    }

    /// The ungoverned baseline, for a process with no evolution control plane at all.
    pub fn baseline() -> Self {
        Self {
            bundle: None,
            preference: ToolPreference::Baseline,
        }
    }

    pub fn active(&self) -> Option<&ResolvedBundle> {
        self.bundle.as_ref()
    }

    pub fn tool_preference(&self) -> ToolPreference {
        self.preference
    }

    /// What the run record should name as having governed it: bundle and policy digests.
    ///
    /// The digest is opaque here and is never recomputed — this side never sees the artifact. It is
    /// carried so a third party can check the claim against the promotion journal afterwards.
    pub fn governance_receipt(&self) -> Option<(String, String)> {
        let bundle = self.bundle.as_ref()?;
        let policy = bundle.policy_for(&tool_policy_slot())?;
        Some((bundle.digest.clone(), policy.digest.clone()))
    }
}

/// Every tool a preference may float forward is a real read-only tool.
///
/// Without this, a typo in `STRUCTURAL_SEARCH_ORDER` would silently do nothing: the name would
/// match no narrowed tool, the reorder would be a no-op, and the promoted bundle would look
/// applied while changing nothing.
#[cfg(test)]
pub(crate) fn structural_search_order_is_grounded() -> bool {
    STRUCTURAL_SEARCH_ORDER
        .iter()
        .all(|name| crate::def::READ_ONLY_TOOLS.contains(name))
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
