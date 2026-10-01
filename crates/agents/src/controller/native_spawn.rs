//! Atomic host-resolved default native lifetime binding for ordinary public Spawn.
use super::{
    AgentActor, AgentCommandV1, AgentControlReplyV1, AgentController, AgentControllerJournal,
    AgentEngineExecution, AgentIdV1, ControllerError,
};
impl<J: AgentControllerJournal> AgentController<J> {
    pub fn execute_with_native_child(
        &mut self,
        actor: AgentActor,
        request_id: &str,
        command: AgentCommandV1,
        binding: Option<AgentEngineExecution>,
    ) -> Result<AgentControlReplyV1, ControllerError> {
        if let Some(binding) = &binding {
            let AgentCommandV1::Spawn { parent_id, .. } = &command else {
                return Err(ControllerError::Permission);
            };
            self.validate_engine_origin(AgentActor::Agent(*parent_id), &binding.origin)?;
            binding.validate()?;
        }
        self.execute_inner(actor, request_id, command, binding)
    }
    pub fn ordinary_spawn_receipt(
        &self,
        actor: AgentActor,
        request_id: &str,
        command: &AgentCommandV1,
    ) -> Result<Option<AgentControlReplyV1>, ControllerError> {
        self.check_live()?;
        self.check_actor(actor)?;
        if !matches!(command, AgentCommandV1::Spawn { .. }) {
            return Ok(None);
        }
        command.validate().map_err(ControllerError::Invalid)?;
        let namespace = match actor {
            AgentActor::Operator => "operator".to_owned(),
            AgentActor::Agent(id) => format!("agent:{}", id.0),
        };
        let Some(prior) = self
            .snapshot
            .receipts
            .get(&format!("{namespace}:{request_id}"))
        else {
            return Ok(None);
        };
        if prior.digest != super::digest(command)? {
            return Err(ControllerError::RequestConflict);
        }
        let mut receipt = prior.reply.clone();
        receipt.replayed = true;
        Ok(Some(receipt))
    }
    pub fn ordinary_native_child(
        &self,
        id: AgentIdV1,
    ) -> Result<Option<AgentEngineExecution>, ControllerError> {
        self.check_live()?;
        Ok(self
            .snapshot
            .agents
            .get(&id)
            .ok_or(ControllerError::UnknownAgent)?
            .native_execution
            .clone())
    }
}
