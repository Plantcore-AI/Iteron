//! `EffectProposal` — the proposal an executor makes to the boundary, as a standalone type.
//!
//! # Why this is a struct beside `EventKind`, not a variant inside it
//!
//! Today the six fields of an effect proposal live inline on `EventKind::EffectIntent`
//! (`crates/protocol/src/event.rs`). That variant is written into an fsynced, hash-chained
//! write-ahead log and is matched by a live back-compatibility branch in
//! `crates/kernel/src/effects.rs` that recognises the first experimental WAL format by
//! `tool_use_id.is_empty()`.
//!
//! A blast-radius review of every consumer established that reshaping the variant into
//! `EffectIntent { proposal: EffectProposal }` would add a JSON level to that durable record and
//! strand the back-compat branch. So the proposal is promoted as a **standalone struct with
//! lossless conversions in both directions**: the durable bytes do not move, and callers that want
//! to reason about a proposal as one value now can.
//!
//! # Why the authority field is a set
//!
//! `EventKind::EffectIntent.capability` is a single `Capability`, and `Capability` derives `Ord`.
//! An adversarial review found that a ceiling compared with `<=` admits every class that sorts
//! below it, so an egress ceiling silently admits code execution. A proposal therefore carries a
//! [`CapabilitySet`]; [`EffectProposal::from_event_fields`] lifts the legacy single class into a
//! one-element set, which is exactly what the old value meant and nothing more.

use crate::capability_set::CapabilitySet;
use crate::event::EventKind;
use crate::ids::EffectId;
use crate::tool::Capability;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Upper bound on the workspace path carried with a proposal.
pub const MAX_EFFECT_WORKSPACE_BYTES: usize = 4_096;

/// One effect an executor proposes to perform, as admitted by the boundary.
///
/// This is the value form of `EventKind::EffectIntent`. Converting in either direction is
/// lossless except that the durable event carries one `Capability` where the proposal carries a
/// set; see [`EffectProposal::to_event_capability`] for how that is reconciled.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EffectProposal {
    /// Harness-minted, durable identity of this effect.
    pub id: EffectId,
    /// Provider/model correlation id. Empty for the first experimental WAL format and for
    /// effect classes that have no model tool-use behind them.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tool_use_id: String,
    /// The registry tool name. Empty for effect classes that are not registry tool calls.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tool: String,
    /// The authority this proposal was admitted under. A set, never a point on an order.
    pub admitted: CapabilitySet,
    /// The scrubbed argument projection recorded for audit.
    pub arguments: Value,
    /// Workspace root the effect is scoped to.
    pub workspace: String,
}

impl EffectProposal {
    /// Build a proposal from the fields of a durable `EventKind::EffectIntent`.
    ///
    /// The single legacy `capability` becomes a one-element set. That is a faithful reading: the
    /// old field named exactly one admitted class, and any wider reading of it was the defect.
    pub fn from_event_fields(
        id: EffectId,
        tool_use_id: String,
        tool: String,
        capability: Capability,
        arguments: Value,
        workspace: String,
    ) -> Self {
        Self {
            id,
            tool_use_id,
            tool,
            admitted: CapabilitySet::only(capability),
            arguments,
            workspace,
        }
    }

    /// The single `Capability` this proposal writes into the durable event.
    ///
    /// Returns `None` when the admitted set is empty (nothing was admitted, so there is no effect
    /// to record) or when it holds more than one class, which the current durable shape cannot
    /// express. A caller that hits `None` must NOT silently pick one; the durable format has to
    /// grow first. Refusing here is what keeps the WAL honest.
    pub fn to_event_capability(&self) -> Option<Capability> {
        let mut present = self.admitted.iter();
        match (present.next(), present.next()) {
            (Some(only), None) => Some(only),
            _ => None,
        }
    }

    /// Read a proposal out of a durable event, if that event is an effect intent.
    pub fn try_from_event(event: &EventKind) -> Option<Self> {
        match event {
            EventKind::EffectIntent {
                id,
                tool_use_id,
                tool,
                capability,
                arguments,
                workspace,
            } => Some(Self::from_event_fields(
                id.clone(),
                tool_use_id.clone(),
                tool.clone(),
                *capability,
                arguments.clone(),
                workspace.clone(),
            )),
            _ => None,
        }
    }

    /// Validate what the type system cannot. Pure: no I/O, no admission, no behaviour.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.admitted.is_empty() {
            return Err("an effect proposal must carry at least one admitted capability");
        }
        if self.workspace.is_empty() || self.workspace.len() > MAX_EFFECT_WORKSPACE_BYTES {
            return Err("effect workspace must be 1..=4096 bytes");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::EffectProposal;
    use crate::capability_set::CapabilitySet;
    use crate::event::EventKind;
    use crate::ids::EffectId;
    use crate::tool::Capability;
    use serde_json::json;

    fn intent() -> EventKind {
        EventKind::EffectIntent {
            id: EffectId("effect-1".into()),
            tool_use_id: "toolu_1".into(),
            tool: "write_file".into(),
            capability: Capability::ReversibleLocal,
            arguments: json!({ "path": "src/main.rs" }),
            workspace: "/repo".into(),
        }
    }

    #[test]
    fn a_durable_intent_round_trips_through_the_proposal_without_moving_the_event() {
        let event = intent();
        let before = serde_json::to_string(&event).expect("event serialises");

        let proposal = EffectProposal::try_from_event(&event).expect("intent yields a proposal");
        assert_eq!(proposal.tool, "write_file");
        assert_eq!(proposal.tool_use_id, "toolu_1");

        // The durable bytes are untouched by the existence of the proposal type.
        assert_eq!(
            serde_json::to_string(&event).expect("re-serialises"),
            before,
            "promoting the proposal must not perturb the write-ahead log format"
        );
    }

    #[test]
    fn the_legacy_single_capability_lifts_to_exactly_one_class_and_back() {
        let proposal = EffectProposal::try_from_event(&intent()).expect("proposal");
        assert!(proposal.admitted.contains(Capability::ReversibleLocal));
        assert!(!proposal.admitted.contains(Capability::CodeExecuting));
        assert_eq!(
            proposal.to_event_capability(),
            Some(Capability::ReversibleLocal)
        );
    }

    #[test]
    fn a_multi_class_admission_refuses_to_be_written_into_the_single_capability_field() {
        // The durable shape cannot express two classes. The proposal must NOT pick one.
        let mut proposal = EffectProposal::try_from_event(&intent()).expect("proposal");
        proposal.admitted = CapabilitySet::from_iter_capabilities([
            Capability::ReversibleLocal,
            Capability::CodeExecuting,
        ]);
        assert_eq!(
            proposal.to_event_capability(),
            None,
            "silently narrowing a two-class admission to one would forge the audit record"
        );
    }

    #[test]
    fn an_empty_admission_is_rejected_rather_than_recorded() {
        let mut proposal = EffectProposal::try_from_event(&intent()).expect("proposal");
        proposal.admitted = CapabilitySet::none();
        assert!(proposal.validate().is_err());
        assert_eq!(proposal.to_event_capability(), None);
    }

    #[test]
    fn a_non_effect_event_yields_no_proposal() {
        let other = EventKind::EffectUnknown {
            id: EffectId("effect-2".into()),
            tool: "write_file".into(),
            reason: "no terminal observed".into(),
        };
        assert!(EffectProposal::try_from_event(&other).is_none());
    }
}
