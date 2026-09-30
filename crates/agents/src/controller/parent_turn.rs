//! Host-only lease for the already-running Main Agent. This never constructs a second resident.
use super::{
    AgentActor, AgentController, AgentControllerJournal, AgentEpochV1, AgentMessageKindV1,
    AgentStateV1, ControllerError, enqueue, next_revision,
};

impl<J: AgentControllerJournal> AgentController<J> {
    /// The authenticated runtime supplies an exact source descriptor from its actual submission.
    /// Public commands cannot call this entry point or claim another execution for the root id.
    pub fn begin_parent_runtime_turn(
        &mut self,
        source: String,
        started_at_unix_ms: u64,
    ) -> Result<AgentEpochV1, ControllerError> {
        self.check_live()?;
        if started_at_unix_ms == 0 {
            return Err(ControllerError::Invalid(
                "parent runtime clock anchor is missing",
            ));
        }
        if self.provider_budget_recovery_required() {
            return Err(ControllerError::RecoveryRequired);
        }
        let id = self.root_id();
        self.check_open(id)?;
        let record = self
            .snapshot
            .agents
            .get(&id)
            .ok_or(ControllerError::UnknownAgent)?;
        if record.view.state != AgentStateV1::Idle {
            return Err(
                if matches!(record.view.state, AgentStateV1::RecoveryRequired { .. }) {
                    ControllerError::RecoveryRequired
                } else {
                    ControllerError::StaleEpoch
                },
            );
        }
        if record
            .turns_used
            .checked_add(record.reserved_turns)
            .is_none_or(|used| used >= record.view.budget.turns)
            || record
                .tokens_used
                .checked_add(record.reserved_tokens)
                .is_none_or(|used| used >= record.view.budget.tokens)
            || record
                .cost_used
                .checked_add(record.reserved_cost)
                .is_none_or(|used| used > record.view.budget.cost_microusd)
            || record.wall_used_ms >= record.view.budget.wall_ms
        {
            return Err(ControllerError::Budget);
        }
        let mut next = self.snapshot.clone();
        let task = enqueue(
            &mut next,
            AgentActor::Operator,
            id,
            source,
            AgentMessageKindV1::Task,
            None,
        )?;
        let record = next
            .agents
            .get_mut(&id)
            .ok_or(ControllerError::UnknownAgent)?;
        let epoch = AgentEpochV1 {
            incarnation: record.view.incarnation,
            turn: record.next_turn,
        };
        record.next_turn = record
            .next_turn
            .checked_add(1)
            .ok_or(ControllerError::Capacity)?;
        record.turns_used = record
            .turns_used
            .checked_add(1)
            .ok_or(ControllerError::Budget)?;
        record.active_task = Some(task);
        record.runtime_started_at_unix_ms = Some(started_at_unix_ms);
        record.view.state = AgentStateV1::Running { epoch };
        next.revision = next_revision(next.revision)?;
        self.commit(next)?;
        Ok(epoch)
    }
}
