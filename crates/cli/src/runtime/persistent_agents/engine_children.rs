//! Actual user-authored engine calls use the same durable identity, ancestor reservations and
//! physical runtime as public persistent agents. No second resident Agent is constructed here.
use super::{
    AgentActor, AgentControlPort, AgentControllerJournal, ControllerError, PersistentAgentHost,
};
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
            self.start_execution(
                admission.lease.agent.clone(),
                admission.lease.epoch,
                admission.lease.initial.clone(),
                permit,
            );
        }
        Ok(admission)
    }
}
