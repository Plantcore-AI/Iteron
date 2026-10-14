//! Read-only physical attempt headroom. This is an advisory snapshot; the original durable
//! reserve CAS rechecks every ceiling after any sibling makes progress.
use super::{
    AgentController, AgentControllerJournal, AgentEpochV1, AgentIdV1, AgentStateV1,
    ControllerError, provider_budget, workflow_claim,
};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentProviderBudgetAllowance {
    pub turns: u32,
    pub tokens: u64,
    pub cost_microusd: u64,
}
impl<J: AgentControllerJournal> AgentController<J> {
    pub fn provider_budget_allowance(
        &self,
        id: AgentIdV1,
        epoch: Option<AgentEpochV1>,
    ) -> Result<AgentProviderBudgetAllowance, ControllerError> {
        self.check_live()?;
        if self.provider_budget_recovery_required() {
            return Err(ControllerError::RecoveryRequired);
        }
        let record = self
            .snapshot
            .agents
            .get(&id)
            .ok_or(ControllerError::UnknownAgent)?;
        match epoch {
            Some(epoch) if record.view.state == (AgentStateV1::Running { epoch }) => {}
            None if id == self.root_id() && record.view.state == AgentStateV1::Idle => {}
            _ => return Err(ControllerError::StaleEpoch),
        }
        let turns = record
            .view
            .budget
            .turns
            .checked_sub(record.turns_used)
            .and_then(|room| room.checked_sub(record.reserved_turns))
            .ok_or(ControllerError::Budget)?;
        // The actual logical lease already owns the first physical attempt slot. Retries and
        // compaction consume additional slots, including conservative NotDispatched receipts.
        let first = epoch.is_some() && !self.snapshot.has_provider_epoch_receipt(id, epoch);
        let turns = turns
            .checked_add(u32::from(first))
            .ok_or(ControllerError::Budget)?;
        let mut allowance = AgentProviderBudgetAllowance {
            turns,
            tokens: record
                .view
                .budget
                .tokens
                .checked_sub(record.tokens_used)
                .and_then(|room| room.checked_sub(record.reserved_tokens))
                .ok_or(ControllerError::Budget)?,
            cost_microusd: record
                .view
                .budget
                .cost_microusd
                .checked_sub(record.cost_used)
                .and_then(|room| room.checked_sub(record.reserved_cost))
                .ok_or(ControllerError::Budget)?,
        };
        if let Some(epoch) = epoch
            && let Some(budget) = workflow_claim::provider_task_budget(&self.snapshot, id, epoch)
        {
            let used = provider_budget::admitted_epoch_usage(&self.snapshot, id, epoch)?;
            allowance.turns = allowance.turns.min(
                budget
                    .turns
                    .checked_sub(used.turns)
                    .ok_or(ControllerError::Budget)?,
            );
            allowance.tokens = allowance.tokens.min(
                budget
                    .tokens
                    .checked_sub(used.tokens)
                    .ok_or(ControllerError::Budget)?,
            );
            allowance.cost_microusd = allowance.cost_microusd.min(
                budget
                    .cost_microusd
                    .checked_sub(used.cost_microusd)
                    .ok_or(ControllerError::Budget)?,
            );
        }
        Ok(allowance)
    }
}
