//! Lifetime monetary ancestry and temporary executable node ceilings. A node cannot permanently
//! shrink its resident Agent; every physical charge still reaches the actual durable ancestors.

use super::*;
use std::ops::{Deref, DerefMut};

impl KernelPersistentRuntime {
    pub(super) fn monetary_pool(
        &self,
        view: &AgentViewV1,
    ) -> Result<Option<Arc<SharedUsdBudget>>, ControllerError> {
        let Some(root_pool) = &self.money else {
            return Ok(None);
        };
        let control = self
            .control
            .get()
            .and_then(Weak::upgrade)
            .ok_or(ControllerError::Closed)?;
        let mut chain = vec![view.clone()];
        while let Some(parent) = chain.last().and_then(|view| view.parent_id) {
            if chain.len() >= 16 {
                return Err(ControllerError::Capacity);
            }
            if chain.iter().any(|view| view.agent_id == parent) {
                return Err(ControllerError::Permission);
            }
            chain.push(control.inspect(AgentActor::Operator, parent)?);
        }
        self.install_monetary_chain(&chain, root_pool.clone())?;
        self.agent_money
            .lock()
            .map_err(|_| ControllerError::Poisoned)?
            .get(&view.agent_id)
            .cloned()
            .map(Some)
            .ok_or(ControllerError::UnknownAgent)
    }

    fn install_monetary_chain(
        &self,
        chain: &[AgentViewV1],
        root: Arc<SharedUsdBudget>,
    ) -> Result<(), ControllerError> {
        let mut pools = self
            .agent_money
            .lock()
            .map_err(|_| ControllerError::Poisoned)?;
        for view in chain.iter().rev() {
            if pools.contains_key(&view.agent_id) {
                continue;
            }
            let pool = match view.parent_id {
                None => root.clone(),
                Some(parent) => Arc::new(
                    SharedUsdBudget::child(
                        view.budget.cost_microusd,
                        pools
                            .get(&parent)
                            .ok_or(ControllerError::UnknownAgent)?
                            .clone(),
                    )
                    .map_err(|_| ControllerError::Capacity)?,
                ),
            };
            pools.insert(view.agent_id, pool);
        }
        Ok(())
    }

    pub(super) fn restore_monetary_chains(
        &self,
        views: &[AgentViewV1],
        root_id: AgentIdV1,
    ) -> Result<(), ControllerError> {
        let Some(root) = &self.money else {
            return Ok(());
        };
        let by_id: BTreeMap<_, _> = views.iter().map(|view| (view.agent_id, view)).collect();
        for view in views {
            let mut chain = vec![view.clone()];
            while let Some(parent) = chain.last().and_then(|view| view.parent_id) {
                if chain.len() >= 16 || chain.iter().any(|view| view.agent_id == parent) {
                    return Err(ControllerError::Permission);
                }
                chain.push((*by_id.get(&parent).ok_or(ControllerError::UnknownAgent)?).clone());
            }
            if chain.last().map(|view| view.agent_id) != Some(root_id) {
                return Err(ControllerError::Permission);
            }
            self.install_monetary_chain(&chain, root.clone())?;
        }
        Ok(())
    }
}

pub(super) struct TurnBudget<'a> {
    child: &'a mut Agent,
    original: iteron_protocol::Budget,
    original_money: Option<Arc<SharedUsdBudget>>,
    turn_money: Option<Arc<SharedUsdBudget>>,
    attempts_before: u32,
}
impl<'a> TurnBudget<'a> {
    pub(super) fn admit(child: &'a mut Agent, view: &AgentViewV1) -> Result<Self, ControllerError> {
        let original = child.budget.clone();
        let original_money = child.usd_budget.clone();
        // begin_turn reserves one turn before IO; this execution may use that already admitted
        // slot, while additional physical requests still count against the lifetime ceiling.
        let relative_turns = view
            .budget
            .turns
            .saturating_sub(view.usage.turns.saturating_sub(1))
            .saturating_sub(view.reserved.turns);
        let relative_tokens = view
            .budget
            .tokens
            .saturating_sub(view.usage.tokens)
            .saturating_sub(view.reserved.tokens);
        let relative_cost = view
            .budget
            .cost_microusd
            .saturating_sub(view.usage.cost_microusd)
            .saturating_sub(view.reserved.cost_microusd);
        let turn_money = original_money
            .as_ref()
            .map(|parent| SharedUsdBudget::child(relative_cost, parent.clone()).map(Arc::new))
            .transpose()
            .map_err(|_| ControllerError::Capacity)?;
        let mut narrowed = original.clone();
        narrowed.max_turns = narrowed.max_turns.min(
            child
                .ledger
                .provider_attempts
                .saturating_add(relative_turns),
        );
        narrowed.max_tokens = Some(
            narrowed
                .max_tokens
                .unwrap_or(u64::MAX)
                .min(total_tokens(child.ledger.usage).saturating_add(relative_tokens)),
        );
        let logical =
            known_cost(&child.ledger.cost_state()).ok_or(ControllerError::RecoveryRequired)?;
        narrowed.max_usd = Some(
            narrowed
                .max_usd
                .unwrap_or(f64::MAX)
                .min(logical.saturating_add(relative_cost) as f64 / 1_000_000.0),
        );
        narrowed.max_wall_secs = narrowed.max_wall_secs.min(
            view.budget
                .wall_ms
                .saturating_sub(view.usage.wall_ms)
                .div_ceil(1000),
        );
        let attempts_before = child.ledger.provider_attempts;
        child.budget = narrowed;
        child.usd_budget = turn_money.clone();
        Ok(Self {
            child,
            original,
            original_money,
            turn_money,
            attempts_before,
        })
    }
    pub(super) fn attempts(&self) -> u32 {
        self.child
            .ledger
            .provider_attempts
            .saturating_sub(self.attempts_before)
    }
    pub(super) fn physical_cost(&self) -> Option<u64> {
        self.turn_money.as_ref().and_then(|pool| {
            pool.remaining_microusd()
                .ok()
                .map(|_| pool.spent_microusd())
        })
    }
}
impl Deref for TurnBudget<'_> {
    type Target = Agent;
    fn deref(&self) -> &Agent {
        self.child
    }
}
impl DerefMut for TurnBudget<'_> {
    fn deref_mut(&mut self) -> &mut Agent {
        self.child
    }
}
impl Drop for TurnBudget<'_> {
    fn drop(&mut self) {
        self.child.budget = self.original.clone();
        self.child.usd_budget = self.original_money.clone();
    }
}
