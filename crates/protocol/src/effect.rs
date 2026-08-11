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
//!
//! # Why `tool_use_id` and `tool` print even when empty
//!
//! Both carry `#[serde(default)]` and deliberately no `skip_serializing_if`. The freeze reserves
//! that attribute for fields *appended after* it, where absent and default genuinely have to be
//! indistinguishable (`crate::artifact` states the same rule for the same reason, and `abi.md`
//! §4.3(b) scopes it to appended `Option` fields). These two are part of the original shape, and
//! erasing them is not free: the kernel's back-compat branch recognises the first experimental WAL
//! format by `tool_use_id.is_empty()`, so a wire form where the field can be *missing* rather than
//! empty gives that branch a third state to guess at. The durable seed already prints both
//! unconditionally (`EventKind::EffectIntent`, `crate::event`); the struct that claims lossless
//! conversion with it has to as well.

use crate::capability_set::CapabilitySet;
use crate::event::{EventKind, ProviderRouteAttemptIdentity};
use crate::ids::EffectId;
use crate::tool::Capability;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Upper bound on the workspace path carried with a proposal.
pub const MAX_EFFECT_WORKSPACE_BYTES: usize = 4_096;

/// Upper bound on the serialised argument projection. Deliberately the same value as
/// `iteron_kernel::effects::MAX_TOOL_ARGUMENT_BYTES` (crates/kernel/src/effects.rs), which already
/// bounds these bytes at admission; the two MUST NOT diverge.
pub const MAX_EFFECT_ARGUMENTS_BYTES: usize = 1_048_576;

/// One effect an executor proposes to perform, as admitted by the boundary.
///
/// This is the value form of `EventKind::EffectIntent`. Converting in either direction is
/// lossless except that the durable event carries one `Capability` where the proposal carries a
/// set; see [`EffectProposal::to_event_capability`] for how that is reconciled.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EffectProposal {
    /// Harness-minted, durable identity of this effect.
    pub id: EffectId,
    /// Provider/model correlation id.
    ///
    /// **Empty is a read-only legacy affordance and must never be minted by a new proposal.**
    /// See [`EffectProposal::validate`] - an earlier draft of this field documented empty as
    /// legitimate for "effect classes that have no model tool-use behind them", which would have
    /// handed a live meaning to a value the WAL already uses for something else.
    #[serde(default)]
    pub tool_use_id: String,
    /// The registry tool name. Empty for effect classes that are not registry tool calls.
    #[serde(default)]
    pub tool: String,
    /// The authority this proposal was admitted under. A set, never a point on an order.
    pub admitted: CapabilitySet,
    /// The scrubbed argument projection recorded for audit.
    pub arguments: Value,
    /// Workspace root the effect is scoped to.
    pub workspace: String,
    /// Content-free pre-dispatch identity for a physical provider request. Historical intents may
    /// decode without it; [`Self::validate`] requires it exactly for newly minted provider effects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_route_attempt: Option<ProviderRouteAttemptIdentity>,
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
        provider_route_attempt: Option<ProviderRouteAttemptIdentity>,
    ) -> Self {
        Self {
            id,
            tool_use_id,
            tool,
            admitted: CapabilitySet::only(capability),
            arguments,
            workspace,
            provider_route_attempt,
        }
    }

    /// Is this proposal safe to mint as a NEW durable record?
    ///
    /// # Why an empty `tool_use_id` is refused
    ///
    /// `crates/kernel/src/effects.rs` recognises the first experimental WAL format by
    /// `tool_use_id.is_empty()`, and for such a record it sets `legacy_tool_use_id` to the
    /// **effect id string**. A later `ToolDone` carrying no `effect_id` is then correlated by
    /// matching `result.tool_use_id` against that value.
    ///
    /// Effect ids are `fx1-{turn:08x}-{ordinal:04x}` - fully predictable - and
    /// `ToolCallAdmission::admit` does not reject a model-supplied `ToolUse.id` of that shape. So
    /// any *new* record written with an empty `tool_use_id` becomes completable by a tool id the
    /// model chose, which is exactly what `ids.rs` forbids: "provider/model tool-call ids remain
    /// untrusted correlation metadata and must never be used as the durable effect identity".
    ///
    /// No live path writes such a record today - every current effect carries a real model
    /// tool-use id - so this is a hole that opens the moment #16 puts checkpoints, memory writes
    /// and subagents on the same WAL. Those are precisely the "effect classes that have no model
    /// tool-use behind them" the field's first draft invited. They must carry a harness-scoped
    /// correlation id instead; empty stays reserved for reading records already on disk.
    ///
    /// Decoding is deliberately still permissive: old records must remain readable. This is the
    /// mint-time gate, not the parse-time one.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.id.0.is_empty() {
            return Err("an effect proposal must carry a harness-minted identity");
        }
        if self.tool_use_id.is_empty() {
            return Err(
                "empty tool_use_id is reserved for reading the first experimental WAL format; a \
                 new effect must carry a correlation id, harness-scoped if there is no model call",
            );
        }
        if self.workspace.is_empty() || self.workspace.len() > MAX_EFFECT_WORKSPACE_BYTES {
            return Err("effect workspace must be 1..=4096 bytes");
        }
        if serde_json::to_vec(&self.arguments)
            .map(|bytes| bytes.len())
            .unwrap_or(usize::MAX)
            > MAX_EFFECT_ARGUMENTS_BYTES
        {
            return Err("effect arguments projection exceeds its declared bound");
        }
        if self.admitted.is_empty() {
            return Err("an effect proposal must carry at least one admitted capability");
        }
        if self.admitted.iter().count() > 1 {
            return Err(
                "the durable EffectIntent carries a single `capability`, so a proposal admitting \
                 more than one class cannot be recorded; widening needs a new top-level event tag \
                 first (abi.md 4.3(b)2, issue #16)",
            );
        }
        match (self.tool.as_str(), &self.provider_route_attempt) {
            ("provider", Some(identity)) => identity.validate()?,
            ("provider", None) => {
                return Err(
                    "a provider effect must durably identify its exact physical route attempt before dispatch",
                );
            }
            (_, Some(_)) => {
                return Err("only a provider effect may carry a provider route attempt identity");
            }
            (_, None) => {}
        }
        Ok(())
    }

    /// The single `Capability` this proposal writes into the durable event.
    ///
    /// Returns `None` when the admitted set is empty (nothing was admitted, so there is no effect
    /// to record) or when it holds more than one class, which the current durable shape cannot
    /// express. A caller that hits `None` must NOT silently pick one; the durable format has to
    /// grow first. Refusing here is what keeps the WAL honest.
    ///
    /// [`EffectProposal::validate`] now refuses a multi-class admission outright, so for anything
    /// that passed it the second arm is unreachable. It stays as defence in depth for values that
    /// never went through the mint-time gate — a decoded record, or a set widened after validation.
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
                provider_route_attempt,
            } => Some(Self::from_event_fields(
                id.clone(),
                tool_use_id.clone(),
                tool.clone(),
                *capability,
                arguments.clone(),
                workspace.clone(),
                provider_route_attempt.clone(),
            )),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EffectProposal, MAX_EFFECT_ARGUMENTS_BYTES};
    use crate::capability_set::CapabilitySet;
    use crate::event::EventKind;
    use crate::ids::EffectId;
    use crate::tool::Capability;
    use serde_json::{Value, json};

    /// Arguments whose serialised form is exactly `len` bytes. `{"text":"…"}` costs 11 bytes
    /// around the payload; the assertion keeps that arithmetic from silently rotting.
    fn arguments_of_serialised_len(len: usize) -> Value {
        let value = json!({ "text": "a".repeat(len - 11) });
        assert_eq!(
            serde_json::to_vec(&value).expect("serialises").len(),
            len,
            "the test's own framing bytes moved"
        );
        value
    }

    fn intent() -> EventKind {
        EventKind::EffectIntent {
            id: EffectId("effect-1".into()),
            tool_use_id: "toolu_1".into(),
            tool: "write_file".into(),
            capability: Capability::ReversibleLocal,
            arguments: json!({ "path": "src/main.rs" }),
            workspace: "/repo".into(),
            provider_route_attempt: None,
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
    fn provider_attempt_identity_round_trips_losslessly_and_is_required_only_for_provider() {
        let identity = crate::ProviderRouteAttemptIdentity {
            version: crate::ProviderRouteAttemptAccountingVersion::V1,
            route_id: format!("sha256:{}", "a".repeat(64)),
            physical_attempt: 2,
            max_cost_reservation_microusd: None,
        };
        let event = EventKind::EffectIntent {
            id: EffectId("fx1-pv-00000001-0000".into()),
            tool_use_id: "hx1-pv-00000001-0000".into(),
            tool: "provider".into(),
            capability: Capability::IrreversibleExternal,
            arguments: json!({"messages": 1}),
            workspace: "/repo".into(),
            provider_route_attempt: Some(identity.clone()),
        };
        let proposal = EffectProposal::try_from_event(&event).expect("provider intent");
        assert_eq!(proposal.provider_route_attempt, Some(identity));
        assert!(proposal.validate().is_ok());

        let mut missing = proposal.clone();
        missing.provider_route_attempt = None;
        assert!(missing.validate().is_err());

        let mut wrong_class = proposal;
        wrong_class.tool = "checkpoint".into();
        assert!(wrong_class.validate().is_err());
    }

    #[test]
    fn a_new_proposal_may_not_mint_the_empty_tool_use_id_the_wal_reserves() {
        // The kernel reads an empty tool_use_id as "first experimental WAL format" and correlates
        // such a record by its *effect id string* - which is `fx1-{turn:08x}-{ordinal:04x}`, fully
        // predictable, and not rejected by tool-call admission. So a new record with an empty
        // correlation id would be completable by an id the model chose. Legacy records must still
        // DECODE; they must not be re-minted.
        let mut proposal = EffectProposal::try_from_event(&intent()).expect("proposal");
        assert!(proposal.validate().is_ok());

        proposal.tool_use_id = String::new();
        let refused = proposal
            .validate()
            .expect_err("empty must be refused at mint time");
        assert!(
            refused.contains("experimental WAL format"),
            "the refusal must say why, or someone will delete the check: {refused}"
        );

        // Decoding is untouched: a record already on disk still reads back.
        let legacy = EventKind::EffectIntent {
            id: EffectId("fx1-00000003-0001".into()),
            tool_use_id: String::new(),
            tool: "write_file".into(),
            capability: Capability::ReversibleLocal,
            arguments: json!({}),
            workspace: "/repo".into(),
            provider_route_attempt: None,
        };
        let decoded = EffectProposal::try_from_event(&legacy);
        assert!(
            decoded.is_some(),
            "old records must stay readable; this is a mint-time gate, not a parse-time one"
        );
        assert!(
            decoded.expect("decoded").validate().is_err(),
            "readable is not the same as re-writable"
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

        // Refusing only at conversion time left the contradiction live: `validate()` called such a
        // proposal safe to mint, and the record it authorised could not be written.
        let refused = proposal
            .validate()
            .expect_err("a proposal that cannot be recorded is not valid to mint");
        assert!(
            refused.contains("single `capability`"),
            "the refusal must name the durable field that cannot hold two classes: {refused}"
        );
    }

    #[test]
    fn the_argument_projection_is_bounded_at_the_declared_ceiling() {
        let mut proposal = EffectProposal::try_from_event(&intent()).expect("proposal");

        proposal.arguments = arguments_of_serialised_len(MAX_EFFECT_ARGUMENTS_BYTES);
        assert!(
            proposal.validate().is_ok(),
            "the bound is inclusive; a producer sending exactly it must keep working"
        );

        proposal.arguments = arguments_of_serialised_len(MAX_EFFECT_ARGUMENTS_BYTES + 1);
        assert_eq!(
            proposal.validate(),
            Err("effect arguments projection exceeds its declared bound")
        );

        // Mint-time only: an oversized record already on disk still decodes.
        let oversized = EventKind::EffectIntent {
            id: EffectId("fx1-00000004-0001".into()),
            tool_use_id: "toolu_2".into(),
            tool: "write_file".into(),
            capability: Capability::ReversibleLocal,
            arguments: arguments_of_serialised_len(MAX_EFFECT_ARGUMENTS_BYTES + 1),
            workspace: "/repo".into(),
            provider_route_attempt: None,
        };
        assert!(EffectProposal::try_from_event(&oversized).is_some());
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
            provider_route_attempt: None,
        };
        assert!(EffectProposal::try_from_event(&other).is_none());
    }
}
