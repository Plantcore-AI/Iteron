//! Native profile authority remains in the held spawner; proposals and durable identities are data.
use super::{AgentSettlement, KernelPersistentRuntime};
use crate::runtime::persistent_agents::AgentEngineRequest;
use iteron_agents::{AgentEngineExecution, AgentEngineOrigin, ControllerError};

impl KernelPersistentRuntime {
    pub(super) fn prepare_child_profile(
        &self,
        request: &AgentEngineRequest,
        origin: AgentEngineOrigin,
    ) -> Result<AgentEngineExecution, ControllerError> {
        self.spawner
            .lock()
            .map_err(|_| ControllerError::Poisoned)?
            .prepare_engine_execution(request, origin)
            .map_err(|_| {
                ControllerError::Invalid("child profile has no admitted native execution binding")
            })
    }
    pub(super) fn validate_child_profile(
        &self,
        execution: &AgentEngineExecution,
    ) -> Result<(), ControllerError> {
        self.spawner
            .lock()
            .map_err(|_| ControllerError::Poisoned)?
            .validate_engine_execution(execution)
            .map_err(|_| ControllerError::RequestConflict)
    }
}
pub(super) fn refused(reason: &str) -> AgentSettlement {
    AgentSettlement {
        turns: 0,
        summary: reason.into(),
        tokens: 0,
        cost_microusd: 0,
        effects_known: true,
        accounting_known: true,
        terminal: iteron_agents::AgentWorkflowTerminal::Failed,
    }
}
