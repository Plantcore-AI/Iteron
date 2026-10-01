//! Private runtime authority: the host mints the root or exact child epoch once. No actor,
//! agent id, epoch, run path or recovery assertion is accepted from model/client JSON.
use super::{
    AgentControllerJournal, AgentEpochV1, AgentIdV1, ControllerError, PersistentAgentHost,
};
use iteron_agents::{AgentProviderBudgetRequest, AgentProviderBudgetTerminal};
use iteron_protocol::ProviderRouteAttemptIdentity;

pub(crate) struct RuntimeProviderBudgetAdmission {
    pub scope_sha256: String,
    pub effect_id: String,
    pub turn: u32,
    pub route: ProviderRouteAttemptIdentity,
    pub max_tokens: u64,
    pub max_cost_microusd: u64,
}

pub(crate) trait RuntimeProviderBudgetPort: Send + Sync {
    fn allowance(&self) -> Result<iteron_agents::AgentProviderBudgetAllowance, ControllerError> {
        Err(ControllerError::Permission)
    }
    fn bind(&self, scope: &str) -> Result<(), ControllerError>;
    fn reserve(&self, admission: RuntimeProviderBudgetAdmission) -> Result<(), ControllerError>;
    fn reservation(
        &self,
        scope: &str,
        turn: u32,
        route: &ProviderRouteAttemptIdentity,
    ) -> Result<Option<u64>, ControllerError>;
    fn settle(
        &self,
        scope: &str,
        effect: &str,
        route: &ProviderRouteAttemptIdentity,
        terminal: AgentProviderBudgetTerminal,
        witness: &str,
    ) -> Result<(), ControllerError>;
}

pub(super) struct ProviderPort<J> {
    host: PersistentAgentHost<J>,
    id: AgentIdV1,
    epoch: Option<AgentEpochV1>,
}
impl<J> ProviderPort<J> {
    pub(super) fn new(
        host: PersistentAgentHost<J>,
        id: AgentIdV1,
        epoch: Option<AgentEpochV1>,
    ) -> Self {
        Self { host, id, epoch }
    }
}
impl<J: AgentControllerJournal + Send + 'static> RuntimeProviderBudgetPort for ProviderPort<J> {
    fn allowance(&self) -> Result<iteron_agents::AgentProviderBudgetAllowance, ControllerError> {
        self.host
            .shared
            .controller
            .lock()
            .map_err(|_| ControllerError::Poisoned)?
            .provider_budget_allowance(self.id, self.epoch)
    }
    fn bind(&self, scope: &str) -> Result<(), ControllerError> {
        let mut controller = self
            .host
            .shared
            .controller
            .lock()
            .map_err(|_| ControllerError::Poisoned)?;
        controller.bind_provider_budget(self.id, scope)?;
        self.host.notify(controller.revision());
        Ok(())
    }
    fn reserve(&self, admission: RuntimeProviderBudgetAdmission) -> Result<(), ControllerError> {
        let mut controller = self
            .host
            .shared
            .controller
            .lock()
            .map_err(|_| ControllerError::Poisoned)?;
        controller.reserve_provider_budget(AgentProviderBudgetRequest {
            agent_id: self.id,
            epoch: self.epoch,
            scope_sha256: admission.scope_sha256,
            effect_id: admission.effect_id,
            turn: admission.turn,
            route: admission.route,
            max_tokens: admission.max_tokens,
            max_cost_microusd: admission.max_cost_microusd,
        })?;
        self.host.notify(controller.revision());
        Ok(())
    }
    fn settle(
        &self,
        scope: &str,
        effect: &str,
        route: &ProviderRouteAttemptIdentity,
        terminal: AgentProviderBudgetTerminal,
        witness: &str,
    ) -> Result<(), ControllerError> {
        let mut controller = self
            .host
            .shared
            .controller
            .lock()
            .map_err(|_| ControllerError::Poisoned)?;
        let result =
            controller.settle_provider_budget(self.id, scope, effect, route, terminal, witness);
        self.host.notify(controller.revision());
        result
    }
    fn reservation(
        &self,
        scope: &str,
        turn: u32,
        route: &ProviderRouteAttemptIdentity,
    ) -> Result<Option<u64>, ControllerError> {
        self.host
            .shared
            .controller
            .lock()
            .map_err(|_| ControllerError::Poisoned)?
            .provider_budget_reservation(self.id, scope, turn, route)
    }
}
