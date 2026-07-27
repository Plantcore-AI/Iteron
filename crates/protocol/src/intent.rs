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

use crate::capability_set::CapabilitySet;
use crate::tool::{Purity, ToolUse};
use crate::trust::Trust;
use serde::{Deserialize, Serialize};

/// A tool call as admitted by the harness.
///
/// `call` is the model's request, verbatim. Everything else is the harness's decision about it,
/// and none of it is derived from anything the model said — authority never travels in-band.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolIntent {
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
    pub fn denied(call: ToolUse, purity: Purity, argument_trust: Trust) -> Self {
        Self {
            call,
            purity,
            admitted: CapabilitySet::none(),
            argument_trust,
        }
    }

    /// Was anything admitted at all?
    pub fn is_admitted(&self) -> bool {
        !self.admitted.is_empty()
    }

    /// Narrow this intent's authority against a ceiling. Intersection only — the result can never
    /// admit anything the ceiling does not.
    pub fn narrowed_to(&self, ceiling: CapabilitySet) -> Self {
        Self {
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
    use super::ToolIntent;
    use crate::capability_set::CapabilitySet;
    use crate::tool::{Capability, Purity, ToolUse};
    use crate::trust::Trust;
    use serde_json::json;

    fn call() -> ToolUse {
        ToolUse {
            id: "toolu_1".into(),
            name: "read_file".into(),
            input: json!({ "path": "README.md" }),
        }
    }

    #[test]
    fn the_wrapped_call_is_byte_identical_to_a_bare_tool_use() {
        let bare = serde_json::to_value(call()).expect("ToolUse serialises");
        let intent = ToolIntent::denied(call(), Purity::Pure, Trust::Workspace);
        let wrapped = serde_json::to_value(&intent).expect("ToolIntent serialises");
        assert_eq!(
            wrapped.get("call").expect("intent carries the call"),
            &bare,
            "wrapping must not perturb the model-emitted call, which is pinned by frozen fixtures"
        );
    }

    #[test]
    fn construction_is_deny_by_default() {
        let intent = ToolIntent::denied(call(), Purity::Pure, Trust::Trusted);
        assert!(!intent.is_admitted());
        assert!(!intent.runs_unattended());
    }

    #[test]
    fn narrowing_can_only_remove_authority() {
        let mut intent = ToolIntent::denied(call(), Purity::Effecting, Trust::Workspace);
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
        let mut intent = ToolIntent::denied(call(), Purity::Pure, Trust::Untrusted);
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
        let mut intent = ToolIntent::denied(call(), Purity::Effecting, Trust::Trusted);
        intent.admitted = CapabilitySet::from_iter_capabilities([
            Capability::ReadOnly,
            Capability::CodeExecuting,
        ]);
        assert!(
            !intent.runs_unattended(),
            "the set is unattended-safe only if every member is"
        );
    }
}
