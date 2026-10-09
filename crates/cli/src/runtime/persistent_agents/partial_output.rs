//! Observation assembly: the durable task/epoch authorizes attribution, never model content.
use super::{
    AgentActor, AgentControllerJournal, AgentEpochV1, AgentIdV1, AgentMailboxMessage,
    AgentMessageIdV1, AgentMessageStateV1, AgentViewV1, ControllerError, PersistentAgentHost,
};
use iteron_protocol::agent_control::AgentMessageKindV1;
use iteron_protocol::agent_output::AgentOutputSourceV1;

pub(super) fn task_id(initial: &[AgentMailboxMessage]) -> Option<AgentMessageIdV1> {
    initial
        .iter()
        .find(|input| input.kind == AgentMessageKindV1::Task)
        .map(|input| input.id)
}

impl<J: AgentControllerJournal + Send + 'static> PersistentAgentHost<J> {
    pub(super) fn decorate_outputs(
        &self,
        views: &mut [AgentViewV1],
    ) -> Result<(), ControllerError> {
        let outputs = self
            .shared
            .partial_outputs
            .lock()
            .map_err(|_| ControllerError::Poisoned)?;
        for view in views {
            outputs.decorate(view);
        }
        Ok(())
    }

    pub(super) fn append_partial_output(
        &self,
        id: AgentIdV1,
        epoch: AgentEpochV1,
        task: AgentMessageIdV1,
        source: &AgentOutputSourceV1,
        served_delta: &str,
    ) -> Result<(), ControllerError> {
        let controller = self
            .shared
            .controller
            .lock()
            .map_err(|_| ControllerError::Poisoned)?;
        let view = controller.inspect(AgentActor::Operator, id)?;
        let message = controller.message(AgentActor::Operator, task)?;
        if message.receiver != id
            || message.kind != AgentMessageKindV1::Task
            || !matches!(message.state, AgentMessageStateV1::Delivered { epoch: actual } | AgentMessageStateV1::Consumed { epoch: actual } if actual == epoch)
        {
            return Err(ControllerError::StaleEpoch);
        }
        let changed = self
            .shared
            .partial_outputs
            .lock()
            .map_err(|_| ControllerError::Poisoned)?
            .append(&view, epoch, task, source, served_delta)?;
        if changed {
            self.notify(controller.revision());
        }
        Ok(())
    }
}
