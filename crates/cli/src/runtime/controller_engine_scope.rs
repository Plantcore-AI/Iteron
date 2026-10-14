//! Immutable composition-root source for actual controller-backed engine invocations.
use super::controller_engine_children::ControllerEngineChildren;
use super::persistent_agents::AgentControlPort;
use super::session_spawn_ledger::SessionSpawnLedger;
use super::workflow_spawner::KernelSpawnerContext;
use iteron_agents::AgentEngineParentSource;
use iteron_protocol::agent_control::{AgentBudgetV1, AgentIdV1};
use std::{sync::Arc, time::Instant};

pub(super) struct ControllerEngineScope {
    pub(super) control: Arc<dyn AgentControlPort>,
    pub(super) parent: AgentIdV1,
    pub(super) parent_source: AgentEngineParentSource,
    pub(super) spawn_ledger: Arc<SessionSpawnLedger>,
    pub(super) deadline: Instant,
}
impl ControllerEngineScope {
    pub(super) fn children(
        &self,
        context: &KernelSpawnerContext,
        workflow_id: &str,
    ) -> Result<Arc<ControllerEngineChildren>, String> {
        context.budget.validate().map_err(str::to_owned)?;
        let limits = self
            .control
            .host_limits()
            .map_err(|_| "controller budget evidence is unavailable")?;
        let money = limits
            .monetary_remaining
            .ok_or("controller monetary evidence is unavailable")?;
        let cost = context
            .budget
            .max_usd
            .map(super::pricing::usd_to_microusd_ceiling)
            .unwrap_or(money)
            .min(money);
        let budget = AgentBudgetV1 {
            turns: context.budget.max_turns.min(limits.remaining.turns),
            tokens: context
                .budget
                .max_tokens
                .unwrap_or(limits.remaining.tokens)
                .min(limits.remaining.tokens),
            wall_ms: context
                .budget
                .max_wall_secs
                .checked_mul(1_000)
                .ok_or("child wall budget overflow")?
                .min(limits.remaining.wall_ms),
            cost_microusd: cost.min(limits.remaining.cost_microusd),
        };
        ControllerEngineChildren::new(
            self.control.clone(),
            self.parent,
            workflow_id.to_owned(),
            context.model.clone(),
            context.default_effort,
            budget,
            self.deadline,
            self.spawn_ledger.clone(),
            self.parent_source.clone(),
        )
        .map(Arc::new)
        .map_err(|_| "controller child scope was refused".into())
    }
}
