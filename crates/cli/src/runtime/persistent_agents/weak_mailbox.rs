//! Mailbox callbacks retain no strong host/runtime/resident cycle across cancellation or restart.
use super::{
    AgentControlPort, AgentControllerJournal, AgentEpochV1, AgentIdV1, AgentMailboxMessage,
    AgentMessageIdV1, AgentStateV1, ControllerError, MailboxPort, PersistentAgentHost,
    RuntimeProviderBudgetPort, Shared,
};
use std::sync::{Arc, Weak};

pub(super) struct WeakMailbox<J> {
    shared: Weak<Shared<J>>,
}
impl<J> WeakMailbox<J> {
    pub(super) fn new(host: &PersistentAgentHost<J>) -> Self {
        Self {
            shared: Arc::downgrade(&host.shared),
        }
    }
    fn host(&self) -> Result<PersistentAgentHost<J>, ControllerError> {
        Ok(PersistentAgentHost {
            shared: self
                .shared
                .upgrade()
                .ok_or(ControllerError::RecoveryRequired)?,
        })
    }
}
impl<J: AgentControllerJournal + Send + 'static> MailboxPort for WeakMailbox<J> {
    fn engine_execution(
        &self,
        id: AgentIdV1,
        epoch: AgentEpochV1,
    ) -> Result<Option<iteron_agents::AgentEngineExecution>, ControllerError> {
        MailboxPort::engine_execution(&self.host()?, id, epoch)
    }
    fn admitted_deadline(
        &self,
        id: AgentIdV1,
        epoch: AgentEpochV1,
    ) -> Result<u64, ControllerError> {
        MailboxPort::admitted_deadline(&self.host()?, id, epoch)
    }

    fn controller_port(&self) -> Result<Arc<dyn AgentControlPort>, ControllerError> {
        Ok(Arc::new(self.host()?))
    }

    fn provider_budget_port(
        &self,
        id: AgentIdV1,
        epoch: AgentEpochV1,
    ) -> Result<Arc<dyn RuntimeProviderBudgetPort>, ControllerError> {
        MailboxPort::provider_budget_port(&self.host()?, id, epoch)
    }
    fn message(&self, id: AgentMessageIdV1) -> Result<AgentMailboxMessage, ControllerError> {
        MailboxPort::message(&self.host()?, id)
    }
    fn deliver(
        &self,
        id: AgentIdV1,
        epoch: AgentEpochV1,
    ) -> Result<Vec<AgentMailboxMessage>, ControllerError> {
        MailboxPort::deliver(&self.host()?, id, epoch)
    }
    fn consumed(
        &self,
        id: AgentIdV1,
        epoch: AgentEpochV1,
        messages: &[AgentMessageIdV1],
    ) -> Result<(), ControllerError> {
        MailboxPort::consumed(&self.host()?, id, epoch, messages)
    }
    fn state(&self, id: AgentIdV1) -> Result<AgentStateV1, ControllerError> {
        MailboxPort::state(&self.host()?, id)
    }
}
