//! One durable owner for physical provider admission across root and retained children. Token
//! and cost reservations share the same record/CAS as descendant lifetime reservations.
use super::{
    AgentController, AgentControllerJournal, AgentControllerSnapshot, AgentEpochV1, AgentIdV1,
    AgentStateV1, AgentUsageV1, ControllerError, next_revision, workflow_claim,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const MAX_PROVIDER_RECEIPTS: usize = 8192;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProviderBudgetRequest {
    pub agent_id: AgentIdV1,
    pub scope_sha256: String,
    pub epoch: Option<AgentEpochV1>,
    pub effect_id: String,
    pub turn: u32,
    pub route: iteron_protocol::ProviderRouteAttemptIdentity,
    pub max_tokens: u64,
    pub max_cost_microusd: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "truth", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentProviderBudgetTerminal {
    Known { tokens: u64, cost_microusd: u64 },
    NotDispatched,
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProviderBudgetBaseline {
    pub usage: AgentUsageV1,
    pub through_sequence: u64,
    pub history_sha256: String,
    pub financial_room_microusd: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    scope_sha256: String,
    #[serde(default)]
    baseline: Option<AgentProviderBudgetBaseline>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    request: AgentProviderBudgetRequest,
    turn_debit: u32,
    terminal: Option<AgentProviderBudgetTerminal>,
    terminal_sha256: Option<String>,
}
impl Receipt {
    fn unresolved(&self) -> bool {
        self.terminal.is_none() || self.terminal == Some(AgentProviderBudgetTerminal::Unknown)
    }
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProviderBudgetState {
    bindings: BTreeMap<AgentIdV1, Binding>,
    receipts: BTreeMap<String, Receipt>,
    #[serde(default)]
    recovery_required: bool,
}

fn valid_sha(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn key(scope: &str, effect: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"iteron-agent-provider-budget-v1\0");
    hash.update((scope.len() as u64).to_be_bytes());
    hash.update(scope.as_bytes());
    hash.update(effect.as_bytes());
    format!("sha256:{:x}", hash.finalize())
}
impl AgentControllerSnapshot {
    pub(super) fn has_provider_epoch_receipt(
        &self,
        id: AgentIdV1,
        epoch: Option<AgentEpochV1>,
    ) -> bool {
        self.provider_budget
            .receipts
            .values()
            .any(|receipt| receipt.request.agent_id == id && receipt.request.epoch == epoch)
    }
    pub(super) fn primary_provider_scope_owner(&self, scope: &str) -> Option<AgentIdV1> {
        self.provider_budget
            .bindings
            .iter()
            .find_map(|(id, binding)| (binding.scope_sha256 == scope).then_some(*id))
    }
    pub fn provider_budget_baseline(
        &self,
        scope: &str,
    ) -> Result<Option<AgentProviderBudgetBaseline>, ControllerError> {
        match self.provider_budget.bindings.get(&AgentIdV1(1)) {
            Some(binding) if binding.scope_sha256 != scope => Err(ControllerError::RequestConflict),
            binding => Ok(binding.and_then(|binding| binding.baseline.clone())),
        }
    }
}
impl AgentProviderBudgetRequest {
    fn validate(&self) -> Result<(), ControllerError> {
        if self.agent_id.0 == 0
            || !valid_sha(&self.scope_sha256)
            || self.effect_id.is_empty()
            || self.effect_id.len() > 256
            || self.effect_id.chars().any(char::is_control)
            || self.max_tokens > 1_000_000_000_000
            || self.max_cost_microusd > 1_000_000_000_000
        {
            return Err(ControllerError::Invalid(
                "invalid physical provider budget envelope",
            ));
        }
        self.route.validate().map_err(ControllerError::Invalid)?;
        if self.route.max_cost_reservation_microusd != Some(self.max_cost_microusd) {
            return Err(ControllerError::Invalid(
                "physical cost reservation is not bound to provider identity",
            ));
        }
        if let Some(epoch) = self.epoch {
            iteron_protocol::agent_control::validate_epoch(epoch)
                .map_err(ControllerError::Invalid)?;
        }
        Ok(())
    }
}

impl<J: AgentControllerJournal> AgentController<J> {
    pub(super) fn provider_budget_scope_owner(&self, scope: &str) -> Option<AgentIdV1> {
        self.snapshot
            .primary_provider_scope_owner(scope)
            .or_else(|| {
                self.snapshot
                    .cohort_root_scope(scope)
                    .then_some(self.root_id())
            })
    }

    /// Exact host run binding. Rebinding an existing identity to a new rollout cannot reset its
    /// budget or transplant outstanding receipts; model and WireControl cannot call this port.
    pub fn bind_provider_budget(
        &mut self,
        id: AgentIdV1,
        scope: &str,
    ) -> Result<(), ControllerError> {
        self.check_live()?;
        if !valid_sha(scope) || !self.snapshot.agents.contains_key(&id) {
            return Err(ControllerError::Invalid(
                "invalid provider budget run binding",
            ));
        }
        if let Some(binding) = self.snapshot.provider_budget.bindings.get(&id) {
            return if binding.scope_sha256 == scope
                || (id == self.root_id() && self.snapshot.cohort_root_scope(scope))
            {
                Ok(())
            } else {
                Err(ControllerError::RequestConflict)
            };
        }
        if self.snapshot.cohort_root_scope(scope)
            || self
                .snapshot
                .provider_budget
                .bindings
                .values()
                .any(|binding| binding.scope_sha256 == scope)
        {
            return Err(ControllerError::Permission);
        }
        let mut next = self.snapshot.clone();
        next.provider_budget.bindings.insert(
            id,
            Binding {
                scope_sha256: scope.into(),
                baseline: None,
            },
        );
        next.revision = next_revision(next.revision)?;
        self.commit(next)
    }

    pub fn reserve_provider_budget(
        &mut self,
        request: AgentProviderBudgetRequest,
    ) -> Result<(), ControllerError> {
        self.check_live()?;
        request.validate()?;
        if self.snapshot.provider_budget.recovery_required {
            return Err(ControllerError::RecoveryRequired);
        }
        if self
            .snapshot
            .provider_budget
            .bindings
            .get(&request.agent_id)
            .is_none_or(|binding| {
                binding.scope_sha256 != request.scope_sha256
                    && !(request.agent_id == self.root_id()
                        && self.snapshot.cohort_root_scope(&request.scope_sha256))
            })
        {
            return Err(ControllerError::Permission);
        }
        let identity = key(&request.scope_sha256, &request.effect_id);
        if self
            .snapshot
            .provider_budget
            .receipts
            .contains_key(&identity)
        {
            return Err(ControllerError::RequestConflict);
        }
        if self.snapshot.provider_budget.receipts.len() >= MAX_PROVIDER_RECEIPTS {
            return Err(ControllerError::Capacity);
        }
        let record = self
            .snapshot
            .agents
            .get(&request.agent_id)
            .ok_or(ControllerError::UnknownAgent)?;
        match request.epoch {
            Some(epoch) if record.view.state == (AgentStateV1::Running { epoch }) => {}
            None if request.agent_id == self.root_id()
                && record.view.state == AgentStateV1::Idle => {}
            _ => return Err(ControllerError::StaleEpoch),
        }
        let prior: Vec<_> = self
            .snapshot
            .provider_budget
            .receipts
            .values()
            .filter(|receipt| {
                receipt.request.agent_id == request.agent_id
                    && receipt.request.epoch == request.epoch
            })
            .collect();
        if self
            .snapshot
            .provider_budget
            .receipts
            .values()
            .any(|receipt| {
                receipt.request.scope_sha256 == request.scope_sha256
                    && receipt.request.turn == request.turn
                    && receipt.request.route.physical_attempt == request.route.physical_attempt
            })
        {
            return Err(ControllerError::RequestConflict);
        }
        let debit = if request.epoch.is_some() && prior.is_empty() {
            0
        } else {
            1
        };
        if record
            .turns_used
            .checked_add(record.reserved_turns)
            .and_then(|used| used.checked_add(debit))
            .is_none_or(|used| used > record.view.budget.turns)
            || record
                .tokens_used
                .checked_add(record.reserved_tokens)
                .and_then(|used| used.checked_add(request.max_tokens))
                .is_none_or(|used| used > record.view.budget.tokens)
            || record
                .cost_used
                .checked_add(record.reserved_cost)
                .and_then(|used| used.checked_add(request.max_cost_microusd))
                .is_none_or(|used| used > record.view.budget.cost_microusd)
        {
            return Err(ControllerError::Budget);
        }
        if let Some(epoch) = request.epoch
            && let Some(budget) =
                workflow_claim::provider_task_budget(&self.snapshot, request.agent_id, epoch)
        {
            let mut used = AgentUsageV1 {
                turns: prior.len() as u32,
                ..Default::default()
            };
            for receipt in &prior {
                let (tokens, cost) = match receipt.terminal {
                    Some(AgentProviderBudgetTerminal::Known {
                        tokens,
                        cost_microusd,
                    }) => (tokens, cost_microusd),
                    Some(AgentProviderBudgetTerminal::NotDispatched) => (0, 0),
                    _ => (
                        receipt.request.max_tokens,
                        receipt.request.max_cost_microusd,
                    ),
                };
                used.tokens = used
                    .tokens
                    .checked_add(tokens)
                    .ok_or(ControllerError::Budget)?;
                used.cost_microusd = used
                    .cost_microusd
                    .checked_add(cost)
                    .ok_or(ControllerError::Budget)?;
            }
            if used.turns >= budget.turns
                || used
                    .tokens
                    .checked_add(request.max_tokens)
                    .is_none_or(|tokens| tokens > budget.tokens)
                || used
                    .cost_microusd
                    .checked_add(request.max_cost_microusd)
                    .is_none_or(|cost| cost > budget.cost_microusd)
            {
                return Err(ControllerError::Budget);
            }
        }
        let mut next = self.snapshot.clone();
        let record = next
            .agents
            .get_mut(&request.agent_id)
            .ok_or(ControllerError::UnknownAgent)?;
        record.turns_used = record
            .turns_used
            .checked_add(debit)
            .ok_or(ControllerError::Budget)?;
        record.reserved_tokens = record
            .reserved_tokens
            .checked_add(request.max_tokens)
            .ok_or(ControllerError::Budget)?;
        record.reserved_cost = record
            .reserved_cost
            .checked_add(request.max_cost_microusd)
            .ok_or(ControllerError::Budget)?;
        next.provider_budget.receipts.insert(
            identity,
            Receipt {
                request,
                turn_debit: debit,
                terminal: None,
                terminal_sha256: None,
            },
        );
        next.revision = next_revision(next.revision)?;
        self.commit(next)
    }

    /// The independently durable provider terminal is the only release evidence. Unknown keeps
    /// the admitted upper bounds and closes further provider admission across the lineage.
    pub fn settle_provider_budget(
        &mut self,
        id: AgentIdV1,
        scope: &str,
        effect: &str,
        route: &iteron_protocol::ProviderRouteAttemptIdentity,
        terminal: AgentProviderBudgetTerminal,
        terminal_sha256: &str,
    ) -> Result<(), ControllerError> {
        self.check_live()?;
        if !valid_sha(scope) || !valid_sha(terminal_sha256) {
            return Err(ControllerError::Invalid(
                "invalid provider settlement witness",
            ));
        }
        let identity = key(scope, effect);
        let Some(prior) = self.snapshot.provider_budget.receipts.get(&identity) else {
            return if terminal == AgentProviderBudgetTerminal::NotDispatched {
                Ok(())
            } else {
                Err(ControllerError::RequestConflict)
            };
        };
        if prior.request.agent_id != id || prior.request.scope_sha256 != scope {
            return Err(ControllerError::Permission);
        }
        if prior.request.route.route_id != route.route_id
            || prior.request.route.physical_attempt != route.physical_attempt
            || (terminal != AgentProviderBudgetTerminal::NotDispatched
                && prior.request.route.max_cost_reservation_microusd
                    != route.max_cost_reservation_microusd)
        {
            return Err(ControllerError::RequestConflict);
        }
        if prior.terminal.as_ref() == Some(&terminal)
            && prior.terminal_sha256.as_deref() == Some(terminal_sha256)
        {
            return Ok(());
        }
        if prior.terminal.is_some() && prior.terminal != Some(AgentProviderBudgetTerminal::Unknown)
        {
            return Err(ControllerError::RequestConflict);
        }
        if let AgentProviderBudgetTerminal::Known {
            tokens,
            cost_microusd,
        } = terminal
            && (tokens > prior.request.max_tokens
                || cost_microusd > prior.request.max_cost_microusd)
        {
            let mut next = self.snapshot.clone();
            let receipt = next
                .provider_budget
                .receipts
                .get_mut(&identity)
                .ok_or(ControllerError::RequestConflict)?;
            receipt.terminal = Some(AgentProviderBudgetTerminal::Unknown);
            receipt.terminal_sha256 = Some(terminal_sha256.into());
            next.provider_budget.recovery_required = true;
            next.revision = next_revision(next.revision)?;
            self.commit(next)?;
            return Err(ControllerError::Budget);
        }
        let mut next = self.snapshot.clone();
        let receipt = next
            .provider_budget
            .receipts
            .get_mut(&identity)
            .ok_or(ControllerError::RequestConflict)?;
        if terminal != AgentProviderBudgetTerminal::Unknown {
            let record = next
                .agents
                .get_mut(&id)
                .ok_or(ControllerError::UnknownAgent)?;
            record.reserved_tokens = record
                .reserved_tokens
                .checked_sub(receipt.request.max_tokens)
                .ok_or(ControllerError::Budget)?;
            record.reserved_cost = record
                .reserved_cost
                .checked_sub(receipt.request.max_cost_microusd)
                .ok_or(ControllerError::Budget)?;
            if let AgentProviderBudgetTerminal::Known {
                tokens,
                cost_microusd,
            } = terminal
            {
                record.tokens_used = record
                    .tokens_used
                    .checked_add(tokens)
                    .ok_or(ControllerError::Budget)?;
                record.cost_used = record
                    .cost_used
                    .checked_add(cost_microusd)
                    .ok_or(ControllerError::Budget)?;
            }
        }
        receipt.terminal = Some(terminal);
        receipt.terminal_sha256 = Some(terminal_sha256.into());
        next.provider_budget.recovery_required = next
            .provider_budget
            .receipts
            .values()
            .any(|receipt| receipt.terminal == Some(AgentProviderBudgetTerminal::Unknown))
            || (self.snapshot.provider_budget.recovery_required
                && next
                    .provider_budget
                    .receipts
                    .values()
                    .any(Receipt::unresolved));
        next.revision = next_revision(next.revision)?;
        self.commit(next)
    }

    pub fn provider_budget_recovery_required(&self) -> bool {
        self.snapshot.provider_budget.recovery_required
    }

    /// Bounded host recovery inventory. These are durable physical envelopes, not proof that
    /// dispatch occurred. Only a matching authenticated rollout terminal can release them.
    pub fn pending_provider_budget_requests(
        &self,
    ) -> Result<Vec<AgentProviderBudgetRequest>, ControllerError> {
        self.check_live()?;
        Ok(self
            .snapshot
            .provider_budget
            .receipts
            .values()
            .filter(|receipt| receipt.unresolved())
            .map(|receipt| receipt.request.clone())
            .collect())
    }

    pub fn provider_budget_baseline(
        &self,
        scope: &str,
    ) -> Result<Option<AgentProviderBudgetBaseline>, ControllerError> {
        self.check_live()?;
        self.snapshot.provider_budget_baseline(scope)
    }

    pub fn bind_provider_budget_baseline(
        &mut self,
        scope: &str,
        baseline: AgentProviderBudgetBaseline,
    ) -> Result<(), ControllerError> {
        self.bind_provider_budget(self.root_id(), scope)?;
        if let Some(existing) = self.provider_budget_baseline(scope)? {
            return if existing == baseline {
                Ok(())
            } else {
                Err(ControllerError::RequestConflict)
            };
        }
        if self
            .snapshot
            .provider_budget
            .receipts
            .values()
            .any(|receipt| receipt.request.agent_id == self.root_id())
        {
            return Err(ControllerError::RecoveryRequired);
        }
        let mut next = self.snapshot.clone();
        next.provider_budget
            .bindings
            .get_mut(&self.root_id())
            .ok_or(ControllerError::RequestConflict)?
            .baseline = Some(baseline);
        next.revision = next_revision(next.revision)?;
        self.commit(next)
    }

    pub fn provider_budget_reservation(
        &self,
        id: AgentIdV1,
        scope: &str,
        turn: u32,
        route: &iteron_protocol::ProviderRouteAttemptIdentity,
    ) -> Result<Option<u64>, ControllerError> {
        self.check_live()?;
        Ok(self
            .snapshot
            .provider_budget
            .receipts
            .values()
            .find(|receipt| {
                receipt.request.agent_id == id
                    && receipt.request.scope_sha256 == scope
                    && receipt.request.turn == turn
                    && receipt.request.route.route_id == route.route_id
                    && receipt.request.route.physical_attempt == route.physical_attempt
            })
            .map(|receipt| receipt.request.max_cost_microusd))
    }

    pub fn pending_provider_usage(&self) -> Result<AgentUsageV1, ControllerError> {
        self.check_live()?;
        let mut usage = AgentUsageV1::default();
        for id in self.snapshot.agents.keys() {
            let (tokens, cost) = pending(&self.snapshot, *id)?;
            usage.tokens = usage
                .tokens
                .checked_add(tokens)
                .ok_or(ControllerError::Budget)?;
            usage.cost_microusd = usage
                .cost_microusd
                .checked_add(cost)
                .ok_or(ControllerError::Budget)?;
        }
        Ok(usage)
    }
}

pub(super) fn reopen(state: &mut ProviderBudgetState) -> bool {
    if state.receipts.values().any(Receipt::unresolved) && !state.recovery_required {
        state.recovery_required = true;
        true
    } else {
        false
    }
}
/// Same conservative per-task envelope used by actual admission, including live reservations.
pub(super) fn admitted_epoch_usage(
    snapshot: &AgentControllerSnapshot,
    id: AgentIdV1,
    epoch: AgentEpochV1,
) -> Result<AgentUsageV1, ControllerError> {
    let mut usage = AgentUsageV1::default();
    for receipt in snapshot
        .provider_budget
        .receipts
        .values()
        .filter(|receipt| receipt.request.agent_id == id && receipt.request.epoch == Some(epoch))
    {
        usage.turns = usage.turns.checked_add(1).ok_or(ControllerError::Budget)?;
        let (tokens, cost) = match receipt.terminal {
            Some(AgentProviderBudgetTerminal::Known {
                tokens,
                cost_microusd,
            }) => (tokens, cost_microusd),
            Some(AgentProviderBudgetTerminal::NotDispatched) => (0, 0),
            _ => (
                receipt.request.max_tokens,
                receipt.request.max_cost_microusd,
            ),
        };
        usage.tokens = usage
            .tokens
            .checked_add(tokens)
            .ok_or(ControllerError::Budget)?;
        usage.cost_microusd = usage
            .cost_microusd
            .checked_add(cost)
            .ok_or(ControllerError::Budget)?;
    }
    Ok(usage)
}
pub(super) fn epoch_usage(
    snapshot: &AgentControllerSnapshot,
    id: AgentIdV1,
    epoch: AgentEpochV1,
) -> Result<Option<AgentUsageV1>, ControllerError> {
    // `turns` measures conservatively consumed admission slots: a proved NotDispatched route
    // still used its reserved slot. This is not a claim about transport calls or remote processing.
    let receipts: Vec<_> = snapshot
        .provider_budget
        .receipts
        .values()
        .filter(|receipt| receipt.request.agent_id == id && receipt.request.epoch == Some(epoch))
        .collect();
    if receipts.is_empty() {
        return Ok(None);
    }
    let mut usage = AgentUsageV1 {
        turns: receipts.len() as u32,
        ..Default::default()
    };
    for receipt in receipts {
        if let Some(AgentProviderBudgetTerminal::Known {
            tokens,
            cost_microusd,
        }) = receipt.terminal
        {
            usage.tokens = usage
                .tokens
                .checked_add(tokens)
                .ok_or(ControllerError::Budget)?;
            usage.cost_microusd = usage
                .cost_microusd
                .checked_add(cost_microusd)
                .ok_or(ControllerError::Budget)?;
        }
    }
    Ok(Some(usage))
}
pub(super) fn settlement_usage(
    snapshot: &AgentControllerSnapshot,
    id: AgentIdV1,
    epoch: AgentEpochV1,
    supplied: AgentUsageV1,
) -> Result<(AgentUsageV1, bool, bool), ControllerError> {
    let Some(mut usage) = epoch_usage(snapshot, id, epoch)? else {
        return Ok((supplied, false, true));
    };
    usage.wall_ms = supplied.wall_ms;
    let known = !snapshot.provider_budget.receipts.values().any(|receipt| {
        receipt.request.agent_id == id
            && receipt.request.epoch == Some(epoch)
            && receipt.unresolved()
    });
    Ok((usage, true, known))
}
pub(super) fn validate_recovery(
    snapshot: &AgentControllerSnapshot,
    id: AgentIdV1,
    epoch: AgentEpochV1,
    supplied: AgentUsageV1,
) -> Result<(), ControllerError> {
    if epoch_usage(snapshot, id, epoch)?.is_some()
        && (supplied.turns != 0
            || supplied.tokens != 0
            || supplied.cost_microusd != 0
            || snapshot.provider_budget.receipts.values().any(|receipt| {
                receipt.request.agent_id == id
                    && receipt.request.epoch == Some(epoch)
                    && receipt.unresolved()
            }))
    {
        return Err(ControllerError::RecoveryRequired);
    }
    Ok(())
}
pub(super) fn pending(
    snapshot: &AgentControllerSnapshot,
    id: AgentIdV1,
) -> Result<(u64, u64), ControllerError> {
    let mut sum = (0u64, 0u64);
    for receipt in snapshot
        .provider_budget
        .receipts
        .values()
        .filter(|receipt| receipt.request.agent_id == id && receipt.unresolved())
    {
        sum.0 = sum
            .0
            .checked_add(receipt.request.max_tokens)
            .ok_or(ControllerError::Budget)?;
        sum.1 = sum
            .1
            .checked_add(receipt.request.max_cost_microusd)
            .ok_or(ControllerError::Budget)?;
    }
    Ok(sum)
}
pub(super) fn validate(snapshot: &AgentControllerSnapshot) -> Result<(), ControllerError> {
    let state = &snapshot.provider_budget;
    if state.bindings.len() > snapshot.config.max_agents
        || state.receipts.len() > MAX_PROVIDER_RECEIPTS
    {
        return Err(ControllerError::Capacity);
    }
    let mut scopes = std::collections::BTreeSet::new();
    for (id, binding) in &state.bindings {
        if !snapshot.agents.contains_key(id) || !valid_sha(&binding.scope_sha256) {
            return Err(ControllerError::Invalid("invalid provider scope binding"));
        }
        if !scopes.insert(&binding.scope_sha256) {
            return Err(ControllerError::Invalid(
                "provider run assigned to multiple agents",
            ));
        }
        if let Some(baseline) = &binding.baseline
            && (*id != AgentIdV1(1)
                || !valid_sha(&baseline.history_sha256)
                || baseline.usage.wall_ms != 0
                || baseline.usage.turns > 1_000_000
                || baseline.usage.tokens > 1_000_000_000_000
                || baseline.usage.cost_microusd > 1_000_000_000_000
                || snapshot.config.root_budget.cost_microusd > baseline.financial_room_microusd)
        {
            return Err(ControllerError::Invalid(
                "invalid immutable provider genesis baseline",
            ));
        }
    }
    let mut physical = std::collections::BTreeSet::new();
    let mut epochs = BTreeMap::<(AgentIdV1, Option<(u64, u64)>), (u32, u32)>::new();
    let mut known = BTreeMap::<AgentIdV1, (u64, u64)>::new();
    for (identity, receipt) in &state.receipts {
        receipt.request.validate()?;
        if identity != &key(&receipt.request.scope_sha256, &receipt.request.effect_id)
            || receipt.turn_debit > 1
            || !snapshot.agents.contains_key(&receipt.request.agent_id)
            || state
                .bindings
                .get(&receipt.request.agent_id)
                .is_none_or(|binding| {
                    binding.scope_sha256 != receipt.request.scope_sha256
                        && !(receipt.request.agent_id == AgentIdV1(1)
                            && snapshot.cohort_root_scope(&receipt.request.scope_sha256))
                })
            || receipt.terminal.is_some() != receipt.terminal_sha256.is_some()
            || receipt
                .terminal_sha256
                .as_ref()
                .is_some_and(|digest| !valid_sha(digest))
        {
            return Err(ControllerError::Invalid(
                "invalid physical provider budget receipt",
            ));
        }
        let record = snapshot
            .agents
            .get(&receipt.request.agent_id)
            .ok_or(ControllerError::UnknownAgent)?;
        match receipt.request.epoch {
            None if receipt.request.agent_id == AgentIdV1(1) && receipt.turn_debit == 1 => {}
            Some(epoch)
                if epoch.incarnation <= record.view.incarnation
                    && epoch.turn < record.next_turn => {}
            _ => {
                return Err(ControllerError::Invalid(
                    "physical receipt has invalid agent epoch ownership",
                ));
            }
        }
        if !physical.insert((
            &receipt.request.scope_sha256,
            receipt.request.turn,
            receipt.request.route.physical_attempt,
        )) {
            return Err(ControllerError::RequestConflict);
        }
        let group = epochs
            .entry((
                receipt.request.agent_id,
                receipt
                    .request
                    .epoch
                    .map(|epoch| (epoch.incarnation, epoch.turn)),
            ))
            .or_default();
        group.0 = group.0.checked_add(1).ok_or(ControllerError::Budget)?;
        group.1 = group
            .1
            .checked_add(receipt.turn_debit)
            .ok_or(ControllerError::Budget)?;
        if let Some(AgentProviderBudgetTerminal::Known {
            tokens,
            cost_microusd,
        }) = receipt.terminal
            && (tokens > receipt.request.max_tokens
                || cost_microusd > receipt.request.max_cost_microusd)
        {
            return Err(ControllerError::Budget);
        }
        if let Some(AgentProviderBudgetTerminal::Known {
            tokens,
            cost_microusd,
        }) = receipt.terminal
        {
            let total = known.entry(receipt.request.agent_id).or_default();
            total.0 = total.0.checked_add(tokens).ok_or(ControllerError::Budget)?;
            total.1 = total
                .1
                .checked_add(cost_microusd)
                .ok_or(ControllerError::Budget)?;
        }
    }
    let mut turns = BTreeMap::<AgentIdV1, u32>::new();
    for ((id, epoch), (count, debit)) in epochs {
        if debit
            != if epoch.is_some() {
                count.saturating_sub(1)
            } else {
                count
            }
        {
            return Err(ControllerError::Invalid(
                "physical turn debit disagrees with epoch claim",
            ));
        }
        let total = turns.entry(id).or_default();
        *total = total.checked_add(count).ok_or(ControllerError::Budget)?;
    }
    for (id, count) in turns {
        if count > snapshot.agents[&id].turns_used {
            return Err(ControllerError::Invalid(
                "physical turn receipts exceed durable usage",
            ));
        }
    }
    for (id, (tokens, cost)) in known {
        if tokens > snapshot.agents[&id].tokens_used || cost > snapshot.agents[&id].cost_used {
            return Err(ControllerError::Invalid(
                "physical terminals exceed durable usage",
            ));
        }
    }
    if state
        .receipts
        .values()
        .any(|receipt| receipt.terminal == Some(AgentProviderBudgetTerminal::Unknown))
        && !state.recovery_required
    {
        return Err(ControllerError::Invalid(
            "unknown provider usage reopened budget",
        ));
    }
    Ok(())
}
