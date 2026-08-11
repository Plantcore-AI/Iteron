//! `StrategySlot` — the injected-port seam the kernel calls a replaceable strategy through.
//!
//! # Two things are called "strategy slot" and they are not the same
//!
//! `iteron_evolve::StrategySlot` is a `#[serde(transparent)]` newtype over a `String`: the persisted
//! *identity* of a slot inside a policy bundle. It answers "which slot is this artefact for".
//!
//! This trait answers "what does the kernel call". They are deliberately separate types with
//! separate jobs, and [`SlotId`] is the identity that crosses between them, so a vertical pack can
//! introduce a slot with no kernel change. An adversarial review flagged the name collision as
//! permanent if frozen carelessly; naming the identity type explicitly is the resolution.
//!
//! # The two grammars are not equal, and the inequality has a direction
//!
//! A first cut of this module claimed the two types accept "the same string". They did not: this
//! side accepted `[A-Za-z0-9_-]` with exactly one `/`, while `iteron_evolve::StrategySlot` accepts
//! lowercase with `.` and any number of `/`. Each accepted identities the other rejected, in both
//! directions - `Acme/Router` here and `db/query.planner` there - so a pack could register a slot
//! the kernel honoured but no policy bundle could ever name. That slot would silently fall back to
//! the built-in strategy with nothing reporting it.
//!
//! The freeze therefore fixes a direction rather than a claim of equality. [`SlotId`] is a **strict
//! subset** of the evolve grammar, so:
//!
//! > every valid [`SlotId`] is a valid `iteron_evolve::StrategySlot`.
//!
//! That is the direction that has to hold. A bundle naming a slot the kernel does not have is
//! inert and harmless; a kernel slot no bundle can name is an ungovernable hole. The conversion is
//! therefore total in the direction that matters and is proved so by test.
//!
//! # Why `decide` is not `async`
//!
//! The kernel is async, and a real context or model-router slot will want to await. Making the
//! trait method async is not free: it forces either `async_trait` (a boxing allocation per call
//! on the hot path) or an associated future type (which makes the trait harder to store as
//! `dyn`). Rather than guess, the trait is **synchronous over already-gathered inputs**: the
//! caller performs any I/O and hands the slot a `SlotObservation`. A slot that needs to await is
//! then a caller-side concern, not a signature change.
//!
//! This is a real constraint, not a preference, so it is stated here rather than discovered
//! later: **a slot may not perform I/O.** If a future slot genuinely must, that is a signature
//! change and it should be made deliberately, with its first real caller present.

use crate::capability_set::CapabilitySet;
use serde::{Deserialize, Serialize};

/// Upper bound on a slot identity.
pub const MAX_SLOT_ID_BYTES: usize = 128;

/// The open identity of a strategy slot: `<domain>/<role>`.
///
/// The vocabulary is intentionally open. `core/tool_policy` and `acme-verticals/triage_router`
/// are equally valid; the kernel does not enumerate them, so adding a slot is not a kernel change.
///
/// The *grammar* is not open. It is deliberately the strict subset of `iteron_evolve::StrategySlot`
/// described in the module docs: lowercase only, so no pack can mint a kernel slot that no policy
/// bundle is able to name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SlotId(pub String);

impl SlotId {
    /// Validate the `<domain>/<role>` grammar without enumerating either half.
    ///
    /// Uppercase is rejected rather than normalised. Normalising would mean two distinct
    /// `SlotId`s comparing unequal here but colliding once persisted on the evolve side, which
    /// turns an identity into a near-identity. Better to refuse it at the boundary.
    pub fn validate(&self) -> Result<(), &'static str> {
        let raw = &self.0;
        if raw.is_empty() || raw.len() > MAX_SLOT_ID_BYTES {
            return Err("slot id must be 1..=128 bytes");
        }
        let mut halves = raw.split('/');
        let (domain, role, extra) = (halves.next(), halves.next(), halves.next());
        match (domain, role, extra) {
            (Some(d), Some(r), None) if !d.is_empty() && !r.is_empty() => {}
            _ => return Err("slot id must be exactly <domain>/<role>"),
        }
        // Lowercase only, and no `.`: both are what keep this a subset of the evolve grammar.
        // See the module docs for why the subset direction is the one that must hold.
        if !raw.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'/')
        }) {
            return Err("slot id may only contain [a-z0-9_-] and one /");
        }
        Ok(())
    }

    /// The `<domain>` half.
    pub fn domain(&self) -> &str {
        self.0.split('/').next().unwrap_or("")
    }

    /// The identity as the evolve side persists it.
    ///
    /// `iteron-protocol` cannot depend on `iteron-evolve` (the dependency runs the other way), so this
    /// hands back the borrowed string rather than constructing the evolve newtype. The guarantee
    /// is the one the module docs state: for any `SlotId` that passes [`SlotId::validate`], this
    /// string is accepted by `iteron_evolve::StrategySlot::new`. `crates/evolve` owns the test that
    /// proves it, because only that side can call both validators.
    pub fn as_persisted_str(&self) -> &str {
        &self.0
    }
}

/// Everything a slot is allowed to see when it decides.
///
/// The caller gathers this; the slot does not reach for anything else. That is what makes a slot
/// replaceable without auditing it for ambient authority.
/// Owned rather than borrowed on purpose: `iteron-xtask boundaries check` refuses generics,
/// including lifetimes, on any struct at the record boundary, because a borrowed field cannot be
/// serialised into the durable record the boundary exists to guarantee.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SlotObservation {
    /// Which slot is being asked.
    pub slot: SlotId,
    /// The authority ceiling in force. A slot may narrow within this; it can never widen.
    pub ceiling: CapabilitySet,
    /// The caller-supplied, already-gathered payload the decision is about.
    pub payload: serde_json::Value,
}

/// What a slot decided.
///
/// `admitted` is always intersected with the observation's ceiling by [`StrategySlot::decide`]'s
/// contract, so a slot cannot return more authority than it was shown — a slot is a policy, never
/// a source of authority.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SlotOutcome {
    /// The authority this decision admits, already narrowed.
    pub admitted: CapabilitySet,
    /// The slot's structured decision, interpreted by the caller.
    pub decision: serde_json::Value,
}

/// A replaceable strategy behind a versioned port.
///
/// Implementors must be `Send + Sync` so the kernel can hold them across await points, and the
/// trait is object-safe so the composition root can store `Arc<dyn StrategySlot>`.
pub trait StrategySlot: Send + Sync {
    /// Which slot this implements.
    fn slot(&self) -> &SlotId;

    /// Decide, given only what the caller gathered.
    ///
    /// Implementors **must not** perform I/O and **must not** return authority beyond
    /// `observation.ceiling`. [`decide_narrowed`] enforces the second of those for every
    /// implementor, so callers should use it rather than calling this directly.
    fn decide(&self, observation: &SlotObservation) -> SlotOutcome;
}

/// Call a slot and enforce the narrowing contract regardless of what the slot returned.
///
/// This exists because "the slot must not widen authority" is otherwise a rule in a doc comment
/// that every implementor has to remember. Here it is a function the caller uses instead.
pub fn decide_narrowed(slot: &dyn StrategySlot, observation: &SlotObservation) -> SlotOutcome {
    let outcome = slot.decide(observation);
    SlotOutcome {
        admitted: outcome.admitted.intersect(observation.ceiling),
        decision: outcome.decision,
    }
}

#[cfg(test)]
mod tests {
    use super::{SlotId, SlotObservation, SlotOutcome, StrategySlot, decide_narrowed};
    use crate::capability_set::CapabilitySet;
    use crate::tool::Capability;
    use serde_json::json;

    struct Greedy(SlotId);

    impl StrategySlot for Greedy {
        fn slot(&self) -> &SlotId {
            &self.0
        }
        // A deliberately misbehaving slot: it asks for everything.
        fn decide(&self, _observation: &SlotObservation) -> SlotOutcome {
            SlotOutcome {
                admitted: CapabilitySet::from_iter_capabilities([
                    Capability::ReadOnly,
                    Capability::CodeExecuting,
                    Capability::IrreversibleExternal,
                ]),
                decision: json!({ "choice": "everything" }),
            }
        }
    }

    #[test]
    fn a_slot_cannot_widen_authority_however_greedy_its_implementation() {
        let id = SlotId("core/tool_policy".into());
        let slot = Greedy(id.clone());
        let payload = json!({});
        let observation = SlotObservation {
            slot: id.clone(),
            ceiling: CapabilitySet::only(Capability::ReadOnly),
            payload,
        };

        let outcome = decide_narrowed(&slot, &observation);
        assert!(outcome.admitted.contains(Capability::ReadOnly));
        assert!(!outcome.admitted.contains(Capability::CodeExecuting));
        assert!(!outcome.admitted.contains(Capability::IrreversibleExternal));
        assert!(outcome.admitted.is_subset_of(observation.ceiling));
    }

    #[test]
    fn the_slot_vocabulary_is_open_but_the_grammar_is_not() {
        for good in [
            "core/tool_policy",
            "core/context",
            "acme-verticals/triage_router",
        ] {
            assert!(
                SlotId(good.into()).validate().is_ok(),
                "{good} should parse"
            );
        }
        for bad in [
            "",
            "iteron",
            "core/",
            "/role",
            "core/a/b",
            "core/tool policy",
        ] {
            assert!(
                SlotId(bad.into()).validate().is_err(),
                "{bad:?} should be rejected"
            );
        }
        assert_eq!(SlotId("acme/x".into()).domain(), "acme");
    }

    #[test]
    fn uppercase_is_refused_so_this_grammar_stays_a_subset_of_the_evolve_one() {
        // `iteron_evolve::StrategySlot::new` accepts lowercase only. While this side accepted
        // uppercase, a pack could register `Acme/Router`, have the kernel honour it, and leave it
        // ungovernable: no policy bundle could name it, so it would silently fall back to the
        // built-in strategy. `crates/evolve` owns the test that runs both validators together.
        for rejected in ["Acme/Router", "core/toolPolicy", "CORE/CONTEXT"] {
            assert!(
                SlotId(rejected.into()).validate().is_err(),
                "{rejected:?} is valid on neither side of the seam and must be refused here"
            );
        }
    }

    #[test]
    fn a_dot_is_refused_for_the_same_reason_from_the_other_direction() {
        // The evolve grammar allows `.` and multiple `/`; this one does not. That asymmetry is
        // fine - a bundle naming a slot the kernel lacks is inert - but it must not be mistaken
        // for the types accepting the same language, which is what the first cut of this module
        // claimed.
        for rejected in ["db/query.planner", "acme/billing/router"] {
            assert!(
                SlotId(rejected.into()).validate().is_err(),
                "{rejected:?} is valid on the evolve side only; this side must not accept it"
            );
        }
    }

    #[test]
    fn the_identity_is_a_transparent_string_so_it_matches_the_evolve_side_persisted_form() {
        let id = SlotId("core/context".into());
        assert_eq!(
            serde_json::to_string(&id).expect("SlotId serialises"),
            "\"core/context\"",
            "the wire form must stay a bare string so the two 'strategy slot' types share identity"
        );
    }

    #[test]
    fn the_trait_is_object_safe() {
        let id = SlotId("core/tool_policy".into());
        let boxed: Box<dyn StrategySlot> = Box::new(Greedy(id.clone()));
        assert_eq!(boxed.slot(), &id);
    }
}
