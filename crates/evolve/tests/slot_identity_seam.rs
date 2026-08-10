//! The seam between the two things called "strategy slot".
//!
//! `iteron_protocol::slot::SlotId` is what the kernel calls a slot; `iteron_evolve::StrategySlot` is
//! how a policy bundle persists which slot an artefact is for. They are separate types with
//! separate jobs, and an adversarial review of the W1 ABI freeze found that an early doc comment
//! claimed they accept the same strings when in fact each accepted identities the other rejected.
//!
//! This test lives here rather than in `iteron-protocol` because only this crate can call both
//! validators: `iteron-protocol` cannot depend on `iteron-evolve`, the dependency runs the other way.
//!
//! What is pinned is a **direction**, not equality:
//!
//! > every valid `SlotId` is a valid `StrategySlot`.
//!
//! A bundle naming a slot the kernel does not have is inert. A kernel slot no bundle can name is
//! an ungovernable hole - it would silently fall back to the built-in strategy with nothing
//! reporting it - so that is the direction the freeze has to guarantee.

use iteron_evolve::StrategySlot;
use iteron_protocol::slot::SlotId;

/// Identities a vertical pack could plausibly mint, plus the built-ins.
const CANDIDATES: &[&str] = &[
    "iteron/tool_policy",
    "iteron/context",
    "iteron/router",
    "iteron/planner",
    "iteron/memory",
    "iteron/scheduler",
    "acme-verticals/triage_router",
    "acme/x",
    "a1/b2",
    "with-hyphen/and_underscore",
];

#[test]
fn every_valid_slot_id_is_a_valid_persisted_strategy_slot() {
    for candidate in CANDIDATES {
        let id = SlotId((*candidate).into());
        assert!(
            id.validate().is_ok(),
            "{candidate} should be a valid SlotId"
        );
        assert!(
            StrategySlot::new(id.as_persisted_str()).is_ok(),
            "{candidate} is a valid SlotId the evolve side cannot persist - that slot would be \
             ungovernable: no policy bundle could ever name it"
        );
    }
}

#[test]
fn the_subset_direction_holds_for_the_shapes_that_used_to_break_it() {
    // Before the fix these passed SlotId::validate and were rejected by StrategySlot::new, which
    // is precisely the ungovernable-slot case. They must now fail on both sides.
    for previously_accepted_here in ["Acme/Router", "iteron/toolPolicy", "CORE/CONTEXT"] {
        assert!(
            SlotId(previously_accepted_here.into()).validate().is_err(),
            "{previously_accepted_here} must no longer be a valid SlotId"
        );
        assert!(
            StrategySlot::new(previously_accepted_here).is_err(),
            "sanity: the evolve side rejects it too, which is why the pair was inconsistent"
        );
    }
}

#[test]
fn the_reverse_direction_is_deliberately_not_guaranteed() {
    // The evolve grammar is wider: it allows `.` and any number of `/`. That asymmetry is
    // intentional and safe, and is asserted here so nobody "fixes" it into a claim of equality.
    for evolve_only in [
        "db/query.planner",
        "acme/billing/router",
        "iteron/planner.v2",
    ] {
        assert!(
            StrategySlot::new(evolve_only).is_ok(),
            "{evolve_only} should still be persistable by a bundle"
        );
        assert!(
            SlotId(evolve_only.into()).validate().is_err(),
            "{evolve_only} is not a kernel slot identity; a bundle naming it is simply inert"
        );
    }
}
