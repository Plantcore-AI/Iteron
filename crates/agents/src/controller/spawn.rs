//! One canonical child authority and lifetime reservation transition. Both public spawn and the
//! host workflow bridge use this same preflight before a single durable snapshot commit.
use super::{
    AgentActor, AgentCommandV1, AgentController, AgentControllerJournal, AgentControllerSnapshot,
    AgentIdV1, AgentMessageIdV1, AgentMessageKindV1, AgentStateV1, Capability, ControllerError,
    MAX_HIERARCHY_DEPTH, enqueue, path_within, record, reserve,
};
impl<J: AgentControllerJournal> AgentController<J> {
    pub(super) fn prepare_child_spawn(
        &self,
        next: &mut AgentControllerSnapshot,
        actor: AgentActor,
        command: AgentCommandV1,
    ) -> Result<(AgentIdV1, AgentMessageIdV1), ControllerError> {
        let AgentCommandV1::Spawn {
            parent_id,
            label,
            task,
            capabilities,
            budget,
            write_paths,
        } = command
        else {
            return Err(ControllerError::Invalid(
                "workflow child requires a spawn declaration",
            ));
        };
        if self.provider_budget_recovery_required() {
            return Err(ControllerError::RecoveryRequired);
        }
        if actor != AgentActor::Operator && actor != AgentActor::Agent(parent_id) {
            return Err(ControllerError::Permission);
        }
        self.check_open(parent_id)?;
        let parent = next
            .agents
            .get_mut(&parent_id)
            .ok_or(ControllerError::UnknownAgent)?;
        if !capabilities.is_subset_of(parent.view.capabilities)
            || !capabilities.contains(Capability::ReadOnly)
        {
            return Err(ControllerError::Permission);
        }
        if self.depth(parent_id)? >= MAX_HIERARCHY_DEPTH
            || next.agents.len() >= next.config.max_agents
        {
            return Err(ControllerError::Capacity);
        }
        let parent = next
            .agents
            .get_mut(&parent_id)
            .ok_or(ControllerError::UnknownAgent)?;
        if !budget.fits_within(parent.view.budget) {
            return Err(ControllerError::Budget);
        }
        reserve(parent, budget)?;
        if parent_id != self.root_id()
            && write_paths.iter().any(|path| {
                !parent
                    .view
                    .write_paths
                    .iter()
                    .any(|allowed| path_within(path, allowed))
            })
        {
            return Err(ControllerError::Permission);
        }
        if !write_paths.is_empty() && !capabilities.contains(Capability::ReversibleLocal) {
            return Err(ControllerError::Permission);
        }
        if next
            .agents
            .values()
            .filter(|agent| agent.view.state != AgentStateV1::Closed)
            .any(|agent| {
                agent.view.agent_id != parent_id
                    && agent.view.parent_id.is_some()
                    && agent.view.write_paths.iter().any(|existing| {
                        write_paths
                            .iter()
                            .any(|path| path_within(path, existing) || path_within(existing, path))
                    })
            })
        {
            return Err(ControllerError::Permission);
        }
        let id = AgentIdV1(next.next_agent);
        next.next_agent = next
            .next_agent
            .checked_add(1)
            .ok_or(ControllerError::Capacity)?;
        next.agents.insert(
            id,
            record(
                id,
                Some(parent_id),
                label,
                &next.config,
                capabilities,
                budget,
                write_paths,
            ),
        );
        let message = enqueue(next, actor, id, task, AgentMessageKindV1::Task, None)?;
        Ok((id, message))
    }
}
