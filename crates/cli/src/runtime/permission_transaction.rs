//! The actual remembered permission transaction. Exact mutable mode/rules remain the one
//! enforced state; provenance advances through the same live handle only after the WAL receipt.
use super::KernelError;
use super::approval_wait::ApprovalJournal;
use super::runtime_policy_overlay::{RuntimePolicyObservation, RuntimePolicyProvenance};
use iteron_protocol::{
    Capability, Effort, EventKind, PermissionMode, PermissionRules, RuntimePolicyEventVersion,
    RuntimePolicySource, TurnId,
};

pub(super) struct PermissionTransaction<'a> {
    pub(super) mode: &'a mut PermissionMode,
    pub(super) rules: &'a mut PermissionRules,
    pub(super) provenance: &'a mut RuntimePolicyProvenance,
    pub(super) effort: Effort,
    pub(super) max_turns: u32,
}
impl PermissionTransaction<'_> {
    pub(super) fn remember(
        &mut self,
        journal: &mut ApprovalJournal<'_>,
        turn: TurnId,
        capability: Capability,
    ) -> Result<(), KernelError> {
        let mut rules = self.rules.clone();
        rules.allow_cap(capability);
        if rules == *self.rules {
            return Ok(());
        }
        let kind = EventKind::PolicyChanged {
            version: RuntimePolicyEventVersion::V1,
            source: RuntimePolicySource::ApprovalRemember,
            mode: *self.mode,
            rules: rules.clone(),
        };
        let sequence = journal.append_receipt(turn, kind.clone())?;
        *self.rules = rules;
        self.provenance
            .observe(&kind, sequence, RuntimePolicyObservation::LiveCommit);
        let _ = self
            .provenance
            .publish(self.effort, *self.mode, self.rules, self.max_turns);
        Ok(())
    }
}
