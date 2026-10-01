//! Actual monetary policy transaction. The shared ceiling changes only after its existing
//! record barrier; newly created ceilings restore signed physical charges before paid admission.
use super::KernelError;
use super::pricing::{SharedUsdBudget, usd_to_microusd_ceiling};
use super::provider_charge_evidence::replay_route_charges;
use super::runtime_policy_overlay::{RuntimePolicyObservation, RuntimePolicyProvenance};
use super::session_transcript::TranscriptAdmissionJournal;
use iteron_obs::{CostState, PricingPort};
use iteron_protocol::{
    Budget, Effort, EventKind, PermissionMode, PermissionRules, RuntimePolicyEventVersion,
    RuntimePolicySource, TurnId,
};
use std::sync::Arc;

pub(super) struct InvocationFundingTransaction<'a> {
    pub(super) journal: TranscriptAdmissionJournal<'a>,
    pub(super) budget: &'a mut Budget,
    pub(super) usd: &'a mut Option<Arc<SharedUsdBudget>>,
    pub(super) persisted: &'a mut Option<u64>,
    pub(super) pricing: Option<&'a dyn PricingPort>,
    pub(super) provenance: &'a mut RuntimePolicyProvenance,
    pub(super) effort: Effort,
    pub(super) permission_mode: PermissionMode,
    pub(super) permission_rules: &'a PermissionRules,
}
impl InvocationFundingTransaction<'_> {
    pub(super) fn synchronize(&mut self, turn: TurnId) -> Result<(), KernelError> {
        let proposed = self.budget.max_usd.map(usd_to_microusd_ceiling);
        let current = self.usd.as_ref().map(|budget| budget.ceiling_microusd());
        let target = match (current, proposed) {
            (None, None) => return Ok(()),
            (Some(current), None) => current,
            (None, Some(proposed)) => proposed,
            (Some(current), Some(proposed)) => current.min(proposed),
        };
        if self.persisted.is_none_or(|ceiling| target < ceiling) {
            let kind = EventKind::UsdCeilingChanged {
                version: RuntimePolicyEventVersion::V1,
                source: if self.persisted.is_some() {
                    RuntimePolicySource::Operator
                } else {
                    RuntimePolicySource::Startup
                },
                max_microusd: target,
            };
            let sequence = self.journal.append(turn, kind.clone())?;
            *self.persisted = Some(target);
            self.provenance
                .observe(&kind, sequence, RuntimePolicyObservation::LiveCommit);
            let _ = self.provenance.publish(
                self.effort,
                self.permission_mode,
                self.permission_rules,
                self.budget.max_turns,
            );
        }
        let created = self.usd.is_none();
        if let Some(shared) = self.usd.as_ref() {
            shared.tighten_microusd(target);
        } else {
            *self.usd = Some(Arc::new(SharedUsdBudget::from_microusd(target)));
        }
        if created {
            let scoped = iteron_record::replay_scoped_rollout(self.journal.rollout.path())?;
            let replay = replay_route_charges(&scoped, self.pricing)?;
            self.usd
                .as_ref()
                .expect("created above")
                .restore_provider_route_charges(&self.journal.ledger.cost_state(), replay)
                .map_err(KernelError::PricingLedger)?;
        }
        self.budget.max_usd = self.usd.as_ref().map(|budget| budget.ceiling_usd());
        Ok(())
    }
    pub(super) fn close_unknown_cost(&self) {
        if let Some(budget) = self.usd.as_ref()
            && budget.requires_pricing()
            && matches!(self.journal.ledger.cost_state(), CostState::Unknown { .. })
        {
            budget.mark_unknown();
        }
    }
}
