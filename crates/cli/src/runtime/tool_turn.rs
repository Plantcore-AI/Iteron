//! Single mutable tool-turn declaration/routing owner. Only its typed stage transition releases
//! early task ownership and ordered deferred work to the physical settlement phase.
use super::KernelError;
use super::early_tool_executor::EarlyToolTask;
use super::policy_evidence::{self, PolicyDecisionDraft};
use iteron_kernel::effects::{EffectTicket, ToolCallAdmission, ToolCallContractError};
use iteron_protocol::{PolicyActionV1, ToolResult, ToolUse, Trust, intent::Purity};
use iteron_tools::{ToolPolicyError, ToolPolicyProposal};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

pub(super) type EarlyToolInFlight = (
    usize,
    ToolUse,
    EarlyToolTask,
    Instant,
    EarlyHookEffectTickets,
);
pub(super) type DeferredToolCall = (usize, ToolUse, Result<ToolPolicyProposal, ToolPolicyError>);

#[derive(Default)]
pub(super) struct EarlyHookEffectTickets {
    pub(super) tool: Option<EffectTicket>,
    pub(super) compatibility: Option<(usize, EffectTicket)>,
    pub(super) lifecycle: Option<(usize, EffectTicket)>,
}

#[derive(Default)]
pub(super) struct ToolTurnOwner {
    admission: ToolCallAdmission,
    next_index: usize,
    early: Vec<EarlyToolInFlight>,
    deferred: Vec<DeferredToolCall>,
    replayed: BTreeMap<usize, ToolResult>,
    effect_signatures: BTreeSet<String>,
    admission_closed: bool,
    contract_error: Option<ToolCallContractError>,
    record_error: Option<KernelError>,
}
pub(super) struct ToolTurnWork {
    pub(super) early: Vec<EarlyToolInFlight>,
    pub(super) deferred: Vec<DeferredToolCall>,
    pub(super) replayed: BTreeMap<usize, ToolResult>,
}

impl ToolTurnOwner {
    /// Validate once before the declaration crosses UI/journal/registry boundaries. A first
    /// structural or record failure closes all later admission in this logical provider turn.
    pub(super) fn admit(&mut self, call: &ToolUse) -> Option<usize> {
        if self.admission_closed {
            return None;
        }
        if let Err(error) = self.admission.admit(call) {
            self.admission_closed = true;
            self.contract_error = Some(error);
            return None;
        }
        let index = self.next_index;
        self.next_index += 1; // bounded by ToolCallAdmission's hard call count
        Some(index)
    }
    pub(super) fn latch_record_error(&mut self, error: KernelError) {
        self.admission_closed = true;
        if self.record_error.is_none() {
            self.record_error = Some(error);
        }
    }
    pub(super) fn take_record_error(&mut self) -> Option<KernelError> {
        self.record_error.take()
    }
    pub(super) fn has_contract_error(&self) -> bool {
        self.contract_error.is_some()
    }
    pub(super) fn take_contract_error(&mut self) -> Option<ToolCallContractError> {
        self.contract_error.take()
    }
    pub(super) fn defer(&mut self, call: DeferredToolCall) {
        self.deferred.push(call);
    }
    pub(super) fn retain_early(&mut self, call: EarlyToolInFlight) {
        self.early.push(call);
    }
    pub(super) fn retain_replay(&mut self, index: usize, result: ToolResult) {
        self.replayed.insert(index, result);
    }
    pub(super) fn effect_reserved(&self, signature: &str) -> bool {
        self.effect_signatures.contains(signature)
    }
    pub(super) fn reserve_effect(&mut self, signature: String) {
        self.effect_signatures.insert(signature);
    }
    pub(super) fn has_deferred(&self) -> bool {
        !self.deferred.is_empty()
    }
    pub(super) fn early(&self) -> &[EarlyToolInFlight] {
        &self.early
    }
    pub(super) fn deferred(&self) -> &[DeferredToolCall] {
        &self.deferred
    }
    pub(super) fn take_early_for_cleanup(&mut self) -> Vec<EarlyToolInFlight> {
        std::mem::take(&mut self.early)
    }
    pub(super) fn call_count(&self) -> usize {
        self.early.len() + self.deferred.len()
    }
    pub(super) fn into_work(self) -> ToolTurnWork {
        ToolTurnWork {
            early: self.early,
            deferred: self.deferred,
            replayed: self.replayed,
        }
    }

    /// This only constructs the immutable draft. The actual policy recorder must commit it before
    /// any execution task is retained or dispatched; no draft is an admission receipt.
    pub(super) fn decision_draft(
        call: &ToolUse,
        proposal: &Result<ToolPolicyProposal, ToolPolicyError>,
        argument_trust: Trust,
    ) -> Result<PolicyDecisionDraft, KernelError> {
        let eligible = &[
            PolicyActionV1::ToolPolicyPureCandidate,
            PolicyActionV1::ToolPolicyEffectCandidate,
        ];
        match proposal {
            Ok(proposal) => PolicyDecisionDraft::selected(
                policy_evidence::TOOL_POLICY_SLOT,
                eligible,
                if proposal.intent.purity == Purity::Pure {
                    PolicyActionV1::ToolPolicyPureCandidate
                } else {
                    PolicyActionV1::ToolPolicyEffectCandidate
                },
                "iteron:tool-policy-features-v1",
                &(call, proposal.intent.purity, proposal.intent.argument_trust),
                &"registry_metadata_and_authority_are_caller_owned",
            ),
            Err(_) => PolicyDecisionDraft::abstained(
                policy_evidence::TOOL_POLICY_SLOT,
                eligible,
                "iteron:tool-policy-features-v1",
                &(call, argument_trust),
                &"invalid_or_unknown_tools_are_not_eligible",
            ),
        }
    }
}
