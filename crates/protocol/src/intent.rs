//! `ToolIntent` — a tool call plus the authority it was admitted under.
//!
//! # Why this wraps `ToolUse` instead of extending it
//!
//! `ToolUse { id, name, input }` is a plain struct with no `..` rest pattern available to its
//! constructors. A blast-radius review counted 28 kernel construction sites plus three in
//! `crates/cli`, all of which would fail with E0063 the moment a field were appended, and four
//! frozen fixtures (`struct-tool-use-v1.json`, `struct-tool-result-v1.json`,
//! `rollout-event-kinds-v4.jsonl`, `blocks-v1.jsonl`) whose bytes would move.
//!
//! So `ToolIntent` **owns** a `ToolUse` rather than replacing it. The model-emitted call keeps
//! its exact shape and its exact bytes; the intent adds the harness's admission decision beside
//! it. A caller that only has a `ToolUse` still works; a caller that needs to know what authority
//! was granted asks the intent.
//!
//! # Why the asking slot is a required field
//!
//! The other four frozen contracts already name the slot on both sides of an admission: a context
//! request carries the asking slot (`context.rs`, `pub slot: SlotId`) and an evolve artefact
//! carries the producing one (`Producer::Slot { slot: SlotId }`, pinned by
//! `crates/protocol/tests/abi_freeze.rs`). An intent with no author would be the only one of the
//! five where attribution is optional, and §4.3(b)3 of `docs/spec/abi.md` forbids adding a
//! *required* field after the freeze — so "add it later" means "nullable forever". Attribution is
//! what a policy bundle's evolution credits or blames, so it is required here from the start.
//!
//! It is harness-side, like everything else beside `call`: the model never names the slot whose
//! policy admitted its own request.
//!
//! # Why there is no `intent_id`
//!
//! A `ToolIntent` is not written to the fsynced WAL and mints no durable identity — the durable
//! identity is `EffectProposal.id` (`crate::effect`). Correlating a proposal that has not effected
//! anything is exactly the job `call.id` is allowed to do, because `ids.rs` bars a model-chosen id
//! only from becoming a *durable* one. If a harness-scoped id is ever genuinely needed it appends
//! as `Option<RequestId>` at zero wire cost under §4.3(b)3.

use crate::capability_set::CapabilitySet;
use crate::effect::MAX_EFFECT_ARGUMENTS_BYTES;
use crate::slot::SlotId;
use crate::tool::{Purity, ToolUse};
use crate::trust::Trust;
use serde::{Deserialize, Serialize};

/// A tool call as admitted by the harness.
///
/// `call` is the model's request, verbatim. Everything else is the harness's decision about it,
/// and none of it is derived from anything the model said — authority never travels in-band.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolIntent {
    /// The slot whose policy produced this intent. Harness-side attribution; never read from the
    /// model.
    pub proposed_by: SlotId,
    /// The model-emitted call, byte-identical to what `EventKind` already carries.
    pub call: ToolUse,
    /// Whether this tool has observable effects. Decided at registration, not by the model.
    pub purity: Purity,
    /// The authority classes the harness admitted for this call. A set, never a point on an
    /// order: see [`crate::capability_set`] for why an ordered ceiling is unsafe here.
    pub admitted: CapabilitySet,
    /// The trust tier the call's *arguments* carry. A tool invoked because some untrusted web
    /// content asked for it is `Untrusted` no matter how the tool itself is classified.
    pub argument_trust: Trust,
}

impl ToolIntent {
    /// Deny-by-default construction: an intent with no admitted authority.
    ///
    /// There is deliberately no constructor that takes a `Capability` and widens it. Admission
    /// is performed by the gate and handed in as a set.
    pub fn denied(
        proposed_by: SlotId,
        call: ToolUse,
        purity: Purity,
        argument_trust: Trust,
    ) -> Self {
        Self {
            proposed_by,
            call,
            purity,
            admitted: CapabilitySet::none(),
            argument_trust,
        }
    }

    /// Is this intent safe to hand to the gate?
    ///
    /// ToolIntent was the only one of the five frozen contracts with no `validate()`, which left
    /// its two variable-length fields — the slot identity and the argument projection — with no
    /// enforced ceiling. `abi.md` makes an explicit upper bound a MUST for every variable-length
    /// field on all five, and a bound minted after the freeze would refuse a value an older
    /// producer legally sent. So the numbers are named now, and the argument bound is deliberately
    /// the same one `EffectProposal` declares, because these bytes travel from one to the other.
    ///
    /// Mint-time only: nothing here touches a decode path.
    pub fn validate(&self) -> Result<(), &'static str> {
        self.proposed_by.validate()?;
        if serde_json::to_vec(&self.call.input)
            .map(|bytes| bytes.len())
            .unwrap_or(usize::MAX)
            > MAX_EFFECT_ARGUMENTS_BYTES
        {
            return Err("tool intent arguments exceed their declared bound");
        }
        Ok(())
    }

    /// Was anything admitted at all?
    pub fn is_admitted(&self) -> bool {
        !self.admitted.is_empty()
    }

    /// Narrow this intent's authority against a ceiling. Intersection only — the result can never
    /// admit anything the ceiling does not.
    pub fn narrowed_to(&self, ceiling: CapabilitySet) -> Self {
        Self {
            proposed_by: self.proposed_by.clone(),
            call: self.call.clone(),
            purity: self.purity,
            admitted: self.admitted.intersect(ceiling),
            argument_trust: self.argument_trust,
        }
    }

    /// May this run without a per-call human prompt?
    ///
    /// True only when every admitted class is itself unattended-safe AND the arguments are not
    /// untrusted. An empty admission is never unattended, because nothing was admitted.
    pub fn runs_unattended(&self) -> bool {
        self.is_admitted()
            && self.argument_trust > Trust::Untrusted
            && self.admitted.iter().all(|c| c.runs_unattended())
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_EFFECT_ARGUMENTS_BYTES, ToolIntent};
    use crate::capability_set::CapabilitySet;
    use crate::slot::SlotId;
    use crate::tool::{Capability, Purity, ToolUse};
    use crate::trust::Trust;
    use serde_json::{Value, json};

    fn slot() -> SlotId {
        SlotId("iteron/tool_policy".into())
    }

    fn call() -> ToolUse {
        ToolUse {
            id: "toolu_1".into(),
            name: "read_file".into(),
            input: json!({ "path": "README.md" }),
        }
    }

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

    #[test]
    fn the_wrapped_call_is_byte_identical_to_a_bare_tool_use() {
        let bare = serde_json::to_value(call()).expect("ToolUse serialises");
        let intent = ToolIntent::denied(slot(), call(), Purity::Pure, Trust::Workspace);
        let wrapped = serde_json::to_value(&intent).expect("ToolIntent serialises");
        assert_eq!(
            wrapped.get("call").expect("intent carries the call"),
            &bare,
            "wrapping must not perturb the model-emitted call, which is pinned by frozen fixtures"
        );
    }

    #[test]
    fn construction_is_deny_by_default() {
        let intent = ToolIntent::denied(slot(), call(), Purity::Pure, Trust::Trusted);
        assert!(!intent.is_admitted());
        assert!(!intent.runs_unattended());
    }

    #[test]
    fn narrowing_can_only_remove_authority() {
        let mut intent = ToolIntent::denied(slot(), call(), Purity::Effecting, Trust::Workspace);
        intent.admitted = CapabilitySet::from_iter_capabilities([
            Capability::ReadOnly,
            Capability::IrreversibleExternal,
        ]);

        let narrowed = intent.narrowed_to(CapabilitySet::only(Capability::ReadOnly));
        assert!(narrowed.admitted.is_subset_of(intent.admitted));
        assert!(!narrowed.admitted.contains(Capability::IrreversibleExternal));

        // Narrowing against a ceiling that grants more does not re-widen.
        let attempted_widen = narrowed.narrowed_to(CapabilitySet::from_iter_capabilities([
            Capability::ReadOnly,
            Capability::TrustMutating,
        ]));
        assert!(!attempted_widen.admitted.contains(Capability::TrustMutating));
    }

    #[test]
    fn untrusted_arguments_are_never_unattended_however_safe_the_capability() {
        let mut intent = ToolIntent::denied(slot(), call(), Purity::Pure, Trust::Untrusted);
        intent.admitted = CapabilitySet::only(Capability::ReadOnly);
        assert!(
            !intent.runs_unattended(),
            "a read requested by untrusted content is still a decision a human should see"
        );

        let mut trusted = intent.clone();
        trusted.argument_trust = Trust::Workspace;
        assert!(trusted.runs_unattended());
    }

    #[test]
    fn one_unattended_unsafe_class_disqualifies_the_whole_admission() {
        let mut intent = ToolIntent::denied(slot(), call(), Purity::Effecting, Trust::Trusted);
        intent.admitted = CapabilitySet::from_iter_capabilities([
            Capability::ReadOnly,
            Capability::CodeExecuting,
        ]);
        assert!(
            !intent.runs_unattended(),
            "the set is unattended-safe only if every member is"
        );
    }

    #[test]
    fn the_argument_projection_is_bounded_at_the_declared_ceiling() {
        let mut at_the_bound = call();
        at_the_bound.input = arguments_of_serialised_len(MAX_EFFECT_ARGUMENTS_BYTES);
        let intent = ToolIntent::denied(slot(), at_the_bound, Purity::Pure, Trust::Workspace);
        assert!(
            intent.validate().is_ok(),
            "the bound is inclusive; a producer sending exactly it must keep working"
        );

        let mut one_over = call();
        one_over.input = arguments_of_serialised_len(MAX_EFFECT_ARGUMENTS_BYTES + 1);
        let intent = ToolIntent::denied(slot(), one_over, Purity::Pure, Trust::Workspace);
        assert_eq!(
            intent.validate(),
            Err("tool intent arguments exceed their declared bound")
        );
    }

    #[test]
    fn an_ungrammatical_author_is_refused_before_the_gate_ever_sees_the_intent() {
        // A slot id no policy bundle can name would make the attribution unresolvable, which is
        // the whole reason the field is required.
        let intent = ToolIntent::denied(
            SlotId("Core/Tool_Policy".into()),
            call(),
            Purity::Pure,
            Trust::Workspace,
        );
        assert!(intent.validate().is_err());
    }
}
