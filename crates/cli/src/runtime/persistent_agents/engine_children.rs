//! Actual user-authored engine calls use the same durable identity, ancestor reservations and
//! physical runtime as public persistent agents. No second resident Agent is constructed here.
use super::{AgentActor, AgentControllerJournal, ControllerError, PersistentAgentHost};
use iteron_agents::{AgentWorkflowChildBinding, AgentWorkflowChildLease};
use iteron_protocol::agent_control::AgentCommandV1;
use std::time::{SystemTime, UNIX_EPOCH};

impl<J: AgentControllerJournal + Send + 'static> PersistentAgentHost<J> {
    pub(super) fn spawn_engine_child(
        &self,
        actor: AgentActor,
        request_id: &str,
        spawn: AgentCommandV1,
        binding: AgentWorkflowChildBinding,
    ) -> Result<AgentWorkflowChildLease, ControllerError> {
        self.shared.runtime.validate_spawn(&spawn)?;
        if let Some(execution) = &binding.execution {
            self.shared.runtime.validate_engine_child(execution)?;
        }
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| ControllerError::Invalid("workflow child clock is before epoch"))?
                .as_millis(),
        )
        .map_err(|_| ControllerError::Capacity)?;
        let (admission, permit) = {
            let mut controller = self
                .shared
                .controller
                .lock()
                .map_err(|_| ControllerError::Poisoned)?;
            if let Some(existing) =
                controller.existing_workflow_child(actor, request_id, &spawn, &binding)?
            {
                return Ok(existing);
            }
            let permit = self
                .shared
                .permits
                .clone()
                .try_acquire_owned()
                .map_err(|_| ControllerError::Capacity)?;
            let admitted =
                controller.spawn_workflow_child(actor, request_id, spawn, binding, now)?;
            self.notify(controller.revision());
            (admitted, permit)
        };
        if !admission.lease.replayed {
            self.start_execution_with_deadline(
                admission.lease.agent.clone(),
                admission.lease.epoch,
                admission.lease.initial.clone(),
                permit,
                Some(admission.claim.deadline_unix_ms),
            );
        }
        Ok(admission)
    }
}

#[cfg(test)]
#[path = "engine_children_tests.rs"]
mod tests;
