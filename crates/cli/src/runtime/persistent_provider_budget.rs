//! Exact physical provider admission into the optional persistent cohort owner. Ordinary
//! sessions retain the existing path. A finite zero monetary cap still requires signed pricing.
use super::{
    Agent, KernelError, persistent_agents, replay_scoped_rollout, route_attempt_accounting,
};
use iteron_agents::ControllerError;
use iteron_protocol::{EventKind, ProviderRouteUsageTruth, TurnId};
use persistent_agents::RuntimeProviderBudgetPort;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub(super) use super::provider_financial_context::{checked_tokens, provider_scope_for};

impl Agent {
    /// A fork's root WAL cannot prove separate descendant controller journals and reservations.
    /// Refuse before opening a fresh cohort namespace until an owning ancestry closure can be
    /// authenticated. Ordinary single-agent forks retain their independent admission path.
    pub(super) fn require_complete_cohort_ancestry(&self) -> Result<(), KernelError> {
        let events = replay_scoped_rollout(self.rollout.path())?;
        if events.iter().any(|scoped| {
            scoped.run_id != *self.rollout.run_id()
                || matches!(
                    &scoped.event.kind,
                    EventKind::RunStart {
                        parent_run: Some(_),
                        ..
                    }
                )
        }) {
            return Err(KernelError::AgentControl(ControllerError::Invalid(
                "fork cohort ancestry is unproven; resume the owning run",
            )));
        }
        Ok(())
    }

    fn persistent_provider_port_evidence(
        &self,
    ) -> Result<Option<Arc<dyn RuntimeProviderBudgetPort>>, ControllerError> {
        let port = if let Some(mailbox) = &self.persistent_mailbox {
            Some(mailbox.provider_budget_port())
        } else {
            self.persistent_agents
                .as_ref()
                .map(|control| control.provider_budget_port())
        };
        port.transpose()
    }

    pub(super) fn provider_financial_context(
        &self,
    ) -> super::provider_financial_context::ProviderFinancialContext {
        use super::provider_financial_context::{
            ProviderFinancialContext, ProviderFinancialOwners, ProviderFinancialScope,
            ProviderPricingEvidence,
        };
        ProviderFinancialContext::new(
            ProviderFinancialScope {
                tenant: self.rollout.tenant().clone(),
                run_id: self.rollout.run_id().clone(),
                attribution: self.projection_attribution.clone(),
            },
            ProviderPricingEvidence {
                port: self.provider_selection.pricing_port().cloned(),
                card: self.provider_selection.card().cloned(),
                context_window: self.provider.physical_input_token_ceiling(&self.model),
                usage_bounds: self.provider.usage_bound_semantics(),
            },
            ProviderFinancialOwners {
                usd: self.usd_budget.clone(),
                cohort: self.persistent_provider_port_evidence(),
            },
        )
    }

    pub(super) fn provider_scope(&self) -> String {
        provider_scope_for(self.rollout.tenant(), self.rollout.run_id())
    }

    /// Trusted enable validates remaining ceilings against all exact physical receipts in the
    /// inherited rollout, including retry/hedge/compaction. Pending/unknown history closes enable.
    pub(super) fn physical_provider_history_baseline(
        &self,
        existing: Option<&iteron_agents::AgentProviderBudgetBaseline>,
        financial_room: u64,
    ) -> Result<iteron_agents::AgentProviderBudgetBaseline, KernelError> {
        let events = replay_scoped_rollout(self.rollout.path())?;
        let through_sequence = existing
            .map(|baseline| baseline.through_sequence)
            .unwrap_or_else(|| {
                events
                    .iter()
                    .filter(|event| {
                        event.run_id == *self.rollout.run_id()
                            && event.tenant == *self.rollout.tenant()
                    })
                    .map(|event| event.event.seq.0)
                    .max()
                    .unwrap_or(0)
            });
        let mut hash = Sha256::new();
        hash.update(b"iteron-provider-budget-genesis-history-v1\0");
        let mut intents = BTreeMap::new();
        let mut terminals = BTreeSet::new();
        let mut total = iteron_protocol::agent_control::AgentUsageV1::default();
        for scoped in events {
            if scoped.tenant == *self.rollout.tenant()
                && scoped.run_id == *self.rollout.run_id()
                && scoped.event.seq.0 > through_sequence
            {
                continue;
            }
            let key = match &scoped.event.kind {
                EventKind::EffectIntent { id, tool, .. }
                | EventKind::EffectDone { id, tool, .. }
                | EventKind::EffectFailed { id, tool, .. }
                | EventKind::EffectUnknown { id, tool, .. }
                    if tool == "provider" =>
                {
                    (
                        scoped.tenant.0.clone(),
                        scoped.run_id.0.clone(),
                        id.0.clone(),
                    )
                }
                _ => continue,
            };
            let encoded = serde_json::to_vec(&(&scoped.tenant, &scoped.run_id, &scoped.event))
                .map_err(|_| {
                    KernelError::AgentControl(ControllerError::Invalid(
                        "provider history cannot be encoded",
                    ))
                })?;
            hash.update((encoded.len() as u64).to_be_bytes());
            hash.update(encoded);
            match &scoped.event.kind {
                EventKind::EffectIntent {
                    provider_route_attempt: Some(identity),
                    ..
                } => {
                    if intents.len() >= 8192
                        || intents
                            .insert(key, (scoped.event.turn, identity.clone()))
                            .is_some()
                    {
                        return Err(KernelError::AgentControl(ControllerError::Capacity));
                    }
                }
                EventKind::EffectDone {
                    provider_route_attempt: Some(accounting),
                    ..
                }
                | EventKind::EffectFailed {
                    provider_route_attempt: Some(accounting),
                    ..
                }
                | EventKind::EffectUnknown {
                    provider_route_attempt: Some(accounting),
                    ..
                } => {
                    let Some((intent_turn, intent)) = intents.get(&key) else {
                        return Err(KernelError::AgentControl(ControllerError::RecoveryRequired));
                    };
                    if !terminals.insert(key)
                        || *intent_turn != scoped.event.turn
                        || intent.route_id != accounting.route_id
                        || intent.physical_attempt != accounting.physical_attempt
                    {
                        return Err(KernelError::AgentControl(ControllerError::RequestConflict));
                    }
                    match route_attempt_accounting::verified_charge(
                        accounting,
                        &scoped.tenant,
                        &scoped.run_id,
                        scoped.event.turn,
                        None,
                        self.provider_selection
                            .pricing_port()
                            .map(|port| port.as_ref()),
                    )? {
                        route_attempt_accounting::RouteChargeTruth::Known(charge) => {
                            let ProviderRouteUsageTruth::Known { usage } = accounting.usage else {
                                return Err(KernelError::AgentControl(
                                    ControllerError::RecoveryRequired,
                                ));
                            };
                            total.tokens = total
                                .tokens
                                .checked_add(checked_tokens(usage)?)
                                .ok_or(KernelError::AgentControl(ControllerError::Budget))?;
                            total.cost_microusd = total
                                .cost_microusd
                                .checked_add(charge.amount_microusd)
                                .ok_or(KernelError::AgentControl(ControllerError::Budget))?;
                        }
                        route_attempt_accounting::RouteChargeTruth::NotDispatched => {}
                        route_attempt_accounting::RouteChargeTruth::Unknown => {
                            return Err(KernelError::AgentControl(
                                ControllerError::RecoveryRequired,
                            ));
                        }
                    }
                    // Count admission slots, including proved local route refusals. Dispatch
                    // metrics remain separate and cannot be inferred from this conservative cap.
                    total.turns = total
                        .turns
                        .checked_add(1)
                        .ok_or(KernelError::AgentControl(ControllerError::Budget))?;
                }
                _ => return Err(KernelError::AgentControl(ControllerError::RecoveryRequired)),
            }
        }
        if intents.len() != terminals.len() {
            return Err(KernelError::AgentControl(ControllerError::RecoveryRequired));
        }
        let baseline = iteron_agents::AgentProviderBudgetBaseline {
            usage: total,
            through_sequence,
            history_sha256: format!("sha256:{:x}", hash.finalize()),
            financial_room_microusd: financial_room,
        };
        if existing.is_some_and(|existing| existing != &baseline) {
            return Err(KernelError::AgentControl(ControllerError::RequestConflict));
        }
        Ok(baseline)
    }
}
