//! Durable epoch terminal publication preserves physical proof independently of accounting.
use super::workflow_claim::AgentWorkflowTerminal;
use super::{
    AgentController, AgentControllerJournal, ControllerError, MAX_AGENT_TEXT_BYTES, next_revision,
    provider_budget, workflow_claim,
};
use iteron_protocol::agent_control::{AgentEpochV1, AgentIdV1, AgentStateV1, AgentUsageV1};

#[derive(Debug, Clone, Copy)]
pub struct AgentTerminalObservation {
    pub effects_known: bool,
    pub accounting_known: bool,
}

impl<J: AgentControllerJournal> AgentController<J> {
    pub fn finish_turn_with_terminal(
        &mut self,
        id: AgentIdV1,
        epoch: AgentEpochV1,
        summary: &str,
        usage: AgentUsageV1,
        effects_known: bool,
        terminal: AgentWorkflowTerminal,
    ) -> Result<(), ControllerError> {
        self.finish_turn_with_observation(
            id,
            epoch,
            summary,
            usage,
            AgentTerminalObservation {
                effects_known,
                accounting_known: true,
            },
            terminal,
        )
    }

    /// Independent physical and accounting observations. Both must be confirmed for new budget
    /// admission; a known physical terminal remains known while its accounting is unavailable.
    pub fn finish_turn_with_observation(
        &mut self,
        id: AgentIdV1,
        epoch: AgentEpochV1,
        summary: &str,
        usage: AgentUsageV1,
        observation: AgentTerminalObservation,
        terminal: AgentWorkflowTerminal,
    ) -> Result<(), ControllerError> {
        let AgentTerminalObservation {
            effects_known,
            accounting_known,
        } = observation;
        self.check_live()?;
        if summary.len() > MAX_AGENT_TEXT_BYTES || summary.contains('\0') {
            return Err(ControllerError::Capacity);
        }
        let current = self
            .snapshot
            .agents
            .get(&id)
            .ok_or(ControllerError::UnknownAgent)?;
        if current.view.state.epoch() != Some(epoch)
            || matches!(current.view.state, AgentStateV1::RecoveryRequired { .. })
        {
            return Err(ControllerError::StaleEpoch);
        }
        let (usage, physical, receipts_known) =
            provider_budget::settlement_usage(&self.snapshot, id, epoch, usage)?;
        let accounting_known = accounting_known && receipts_known;
        let workflow_budget_fits =
            workflow_claim::settlement_fits(&self.snapshot, id, epoch, usage);
        let mut next = self.snapshot.clone();
        let record = next
            .agents
            .get_mut(&id)
            .ok_or(ControllerError::UnknownAgent)?;
        if !physical {
            record.turns_used = record
                .turns_used
                .checked_add(usage.turns.saturating_sub(1))
                .ok_or(ControllerError::Budget)?;
            record.tokens_used = record
                .tokens_used
                .checked_add(usage.tokens)
                .ok_or(ControllerError::Budget)?;
            record.cost_used = record
                .cost_used
                .checked_add(usage.cost_microusd)
                .ok_or(ControllerError::Budget)?;
        }
        record.wall_used_ms = record
            .wall_used_ms
            .checked_add(usage.wall_ms)
            .ok_or(ControllerError::Budget)?;
        let within_budget = workflow_budget_fits
            && record
                .turns_used
                .checked_add(record.reserved_turns)
                .is_some_and(|used| used <= record.view.budget.turns)
            && record
                .tokens_used
                .checked_add(record.reserved_tokens)
                .is_some_and(|used| used <= record.view.budget.tokens)
            && record
                .cost_used
                .checked_add(record.reserved_cost)
                .is_some_and(|used| used <= record.view.budget.cost_microusd)
            && record.wall_used_ms <= record.view.budget.wall_ms;
        record.view.last_summary = Some(summary.to_owned());
        record.view.state = if !effects_known || !accounting_known || !within_budget {
            AgentStateV1::RecoveryRequired { epoch }
        } else if matches!(record.view.state, AgentStateV1::Closing { .. }) {
            AgentStateV1::Closed
        } else {
            AgentStateV1::Idle
        };
        let active_task = record.active_task;
        if !matches!(record.view.state, AgentStateV1::RecoveryRequired { .. }) {
            record.active_task = None;
            record.runtime_started_at_unix_ms = None;
        }
        // Unconsumed inputs at a settled epoch have an explicit rejected outcome. They are not
        // mislabeled as consumed and are never delivered into a later turn.
        workflow_claim::record_completion(
            &mut next,
            id,
            epoch,
            summary,
            usage,
            effects_known,
            accounting_known && within_budget,
            terminal,
        );
        next.mailbox.settle_epoch(id, epoch, active_task);
        next.revision = next_revision(next.revision)?;
        self.commit(next)
    }
}
