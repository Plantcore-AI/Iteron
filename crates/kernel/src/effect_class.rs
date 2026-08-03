//! The closed vocabulary of brokered effect classes, and the identity minting that keeps two
//! classes from colliding on one turn's write-ahead log.
//!
//! # Why identities are namespaced by class
//!
//! Before the boundary went universal, `effect_id(turn, ordinal)` had one caller and `ordinal` had
//! one meaning: the provider's bounded tool order inside the turn. The moment a provider request, a
//! hook, a subagent spawn, a verifier run and a checkpoint all mint identities inside the *same*
//! turn, a bare ordinal is no longer unique — the first tool call and the first hook would both ask
//! for `fx1-00000001-0000`, and `EffectJournal::replay` would reject the record as
//! `DuplicateIntent`. Each class therefore carries a short code that no hex ordinal can produce, so
//! two classes cannot collide however their ordinals are counted.
//!
//! Registry tools deliberately keep the original, code-free shape. Their identities are already on
//! disk in real records; renaming them would strand every rollout written before this change.

use core_protocol::{EffectId, TurnId};

/// Every externally-visible effect the kernel can dispatch.
///
/// This is constitutional mechanism, not an evolvable strategy: adding a class means adding a
/// dispatch path that crosses the boundary, and the boundary test in `crate::effects` refuses any
/// effect-producing call site that is not one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EffectClass {
    /// A `core_tools::Registry` call the model asked for. The only class that predates #16.
    RegistryTool,
    /// One paid inference request crossing the provider adapter.
    Provider,
    /// One operator lifecycle hook process.
    Hook,
    /// One subagent dispatch.
    Subagent,
    /// One verifier oracle run.
    Verify,
    /// One workspace checkpoint (a real tree write, not merely a durable marker).
    Checkpoint,
    /// One in-turn workflow launch.
    Workflow,
    /// One telemetry export (#105). Projecting the record outward is a network/file effect like any
    /// other, so it crosses the same boundary: a stalled collector is bounded and reaped, and a run
    /// with the exporter on still has a complete effect journal.
    Telemetry,
}

/// Namespace prefix for correlation ids the harness mints for itself.
///
/// `EffectProposal::validate` refuses an empty `tool_use_id`, because empty is reserved for reading
/// the first experimental WAL format. Classes with no model `tool_use` behind them therefore need a
/// correlation id of their own, and it must live in a namespace the model cannot enter — see
/// [`is_harness_correlation_id`], which `ToolCallAdmission` uses to refuse a model-supplied id that
/// tries to impersonate one.
pub const HARNESS_CORRELATION_PREFIX: &str = "hx1-";

/// Namespace prefix for harness-minted effect identities.
pub const EFFECT_ID_PREFIX: &str = "fx1-";

impl EffectClass {
    /// Every class, for exhaustive conformance tests. Kept beside the enum so a new class that
    /// forgets to register itself fails the boundary test rather than silently escaping it.
    pub const ALL: [EffectClass; 8] = [
        EffectClass::RegistryTool,
        EffectClass::Provider,
        EffectClass::Hook,
        EffectClass::Subagent,
        EffectClass::Verify,
        EffectClass::Checkpoint,
        EffectClass::Workflow,
        EffectClass::Telemetry,
    ];

    /// Stable, human-readable kind recorded in the durable intent and in any terminal.
    ///
    /// Registry tools return `None`: their recorded kind is the *tool name*, which is what every
    /// existing consumer already reads out of `EffectIntent.tool`.
    pub const fn label(self) -> Option<&'static str> {
        match self {
            EffectClass::RegistryTool => None,
            EffectClass::Provider => Some("provider"),
            EffectClass::Hook => Some("hook"),
            EffectClass::Subagent => Some("subagent"),
            EffectClass::Verify => Some("verify"),
            EffectClass::Checkpoint => Some("checkpoint"),
            EffectClass::Workflow => Some("workflow"),
            EffectClass::Telemetry => Some("telemetry"),
        }
    }

    /// The identity namespace code. `None` preserves the original registry-tool shape.
    ///
    /// Codes are two lowercase letters, which no `{:04x}` ordinal can spell, so a namespaced id can
    /// never be confused with a code-free one however large the ordinal grows.
    pub const fn code(self) -> Option<&'static str> {
        match self {
            EffectClass::RegistryTool => None,
            EffectClass::Provider => Some("pv"),
            EffectClass::Hook => Some("hk"),
            EffectClass::Subagent => Some("sa"),
            EffectClass::Verify => Some("vf"),
            EffectClass::Checkpoint => Some("cp"),
            EffectClass::Workflow => Some("wf"),
            EffectClass::Telemetry => Some("tm"),
        }
    }
}

/// Mint a deterministic, harness-owned effect identity for one class inside one turn.
///
/// Determinism is load-bearing twice over: `EffectJournal` correlates a terminal to its intent by
/// `(turn, id)`, and the pure reducer that #15 extracts has to be able to produce the exact same
/// bytes on replay. Nothing here reads a clock, a counter, or a random source.
pub fn effect_id(turn: TurnId, class: EffectClass, ordinal: usize) -> EffectId {
    match class.code() {
        None => EffectId(format!("{EFFECT_ID_PREFIX}{:08x}-{ordinal:04x}", turn.0)),
        Some(code) => EffectId(format!(
            "{EFFECT_ID_PREFIX}{:08x}-{code}-{ordinal:04x}",
            turn.0
        )),
    }
}

/// Mint the harness-scoped correlation id for a class that has no model `tool_use` behind it.
///
/// Distinct from the effect id on purpose. The effect id is the durable identity the WAL correlates
/// on; the correlation id is the audit field that says *what asked for this*. Collapsing them would
/// hand the legacy-format branch in `EffectJournal` a value it is entitled to treat as a model id.
pub fn harness_correlation_id(turn: TurnId, class: EffectClass, ordinal: usize) -> String {
    let code = class.code().unwrap_or("rt");
    format!(
        "{HARNESS_CORRELATION_PREFIX}{code}-{:08x}-{ordinal:04x}",
        turn.0
    )
}

/// Is this a correlation id only the harness may mint?
///
/// Used to refuse a model-supplied `ToolUse.id` in the harness namespace. Without it a provider
/// could name a tool call `hx1-cp-00000001-0000` and make its result correlate with the audit
/// record of a checkpoint it never performed.
pub fn is_harness_correlation_id(value: &str) -> bool {
    value.starts_with(HARNESS_CORRELATION_PREFIX)
}

/// Is this an identity only the harness may mint?
///
/// `EffectProposal::validate` documents the hole this closes: effect ids are fully predictable, and
/// a record whose `tool_use_id` is empty correlates its terminal by matching a `ToolResult`'s
/// `tool_use_id` against the *effect id string*. Minting is now gated so no new record can be
/// written that way, and this refuses the other half — a model call that adopts the shape.
pub fn is_harness_effect_id(value: &str) -> bool {
    value.starts_with(EFFECT_ID_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn no_two_classes_can_collide_on_one_turn() {
        let turn = TurnId(7);
        let mut seen = BTreeSet::new();
        for class in EffectClass::ALL {
            for ordinal in 0..64 {
                assert!(
                    seen.insert(effect_id(turn, class, ordinal).0),
                    "{class:?} ordinal {ordinal} collided with an already-minted identity"
                );
            }
        }
        assert_eq!(seen.len(), EffectClass::ALL.len() * 64);
    }

    #[test]
    fn registry_tool_identities_keep_the_shape_already_on_disk() {
        assert_eq!(
            effect_id(TurnId(1), EffectClass::RegistryTool, 0).0,
            "fx1-00000001-0000"
        );
    }

    #[test]
    fn a_large_ordinal_cannot_spell_a_class_code() {
        // The collision that namespacing exists to prevent: some ordinal rendering out to the same
        // bytes as a coded id. Hex has no letters past `f`, so no ordinal can produce `pv`/`hk`/…
        for ordinal in [0usize, 1, 0xffff, 0x10_000, usize::MAX] {
            let bare = effect_id(TurnId(3), EffectClass::RegistryTool, ordinal).0;
            for class in EffectClass::ALL {
                let Some(code) = class.code() else { continue };
                assert!(
                    !bare.contains(&format!("-{code}-")),
                    "bare ordinal {ordinal} rendered a class code: {bare}"
                );
            }
        }
    }

    #[test]
    fn every_class_that_is_not_a_registry_tool_has_a_label_and_a_code() {
        for class in EffectClass::ALL {
            assert_eq!(
                class.label().is_some(),
                class.code().is_some(),
                "{class:?} must declare both a durable label and an identity code, or neither"
            );
        }
    }

    #[test]
    fn harness_namespaces_are_recognisable_and_disjoint() {
        let correlation = harness_correlation_id(TurnId(2), EffectClass::Checkpoint, 0);
        assert!(is_harness_correlation_id(&correlation));
        assert!(!is_harness_effect_id(&correlation));
        let id = effect_id(TurnId(2), EffectClass::Checkpoint, 0).0;
        assert!(is_harness_effect_id(&id));
        assert!(!is_harness_correlation_id(&id));
    }
}
