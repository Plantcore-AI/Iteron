//! Exact physical provider admission into the optional persistent cohort owner. Ordinary
//! sessions retain the existing path. A finite zero monetary cap still requires signed pricing.
use super::{
    Agent, KernelError, persistent_agents, replay_scoped_rollout, route_attempt_accounting,
};
use iteron_agents::{AgentProviderBudgetTerminal, ControllerError};
use iteron_protocol::{
    EventKind, ProviderRouteAttemptAccounting, ProviderRouteAttemptIdentity,
    ProviderRouteUsageTruth, TurnId,
};
use persistent_agents::{RuntimeProviderBudgetAdmission, RuntimeProviderBudgetPort};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

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

    fn persistent_provider_port(
        &self,
    ) -> Result<Option<Arc<dyn RuntimeProviderBudgetPort>>, KernelError> {
        let port = if let Some(mailbox) = &self.persistent_mailbox {
            Some(mailbox.provider_budget_port())
        } else {
            self.persistent_agents
                .as_ref()
                .map(|control| control.provider_budget_port())
        };
        port.transpose().map_err(KernelError::AgentControl)
    }

    pub(super) fn provider_scope(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(b"iteron-persistent-provider-run-v1\0");
        for part in [&self.rollout.tenant().0, &self.rollout.run_id().0] {
            hash.update((part.len() as u64).to_be_bytes());
            hash.update(part.as_bytes());
        }
        format!("sha256:{:x}", hash.finalize())
    }

    /// Before intent creation, obtain an independently authenticated worst-case charge. Missing
    /// pricing never becomes zero. The signed route must match the exact selected physical route.
    pub(super) fn persistent_provider_bounds(
        &self,
        route_id: &str,
        max_output: u64,
    ) -> Result<Option<(u64, u64)>, KernelError> {
        if self.persistent_provider_port()?.is_none() {
            return Ok(None);
        }
        let (Some(pricing), Some(card)) = (&self.pricing_port, &self.pricing) else {
            return Err(KernelError::UnpricedUsdCeiling);
        };
        pricing.verify_rate_card(card)?;
        let now = self.pricing_now();
        if now < card.rate_card.issued_at_unix_secs
            || now >= card.rate_card.expires_at_unix_secs
            || format!(
                "{}:{}",
                card.rate_card.route.provider_id, card.rate_card.route.model_id
            ) != route_id
        {
            return Err(KernelError::UnpricedUsdCeiling);
        }
        let input = self
            .execution_context_window()
            .filter(|value| *value > 0)
            .ok_or(KernelError::InvalidRouteMetadata {
                field: "model_context_window",
                reason: "persistent provider admission needs a proven finite context window",
            })?;
        if max_output == 0 || max_output > u64::from(u32::MAX) {
            return Err(KernelError::AgentControl(ControllerError::Budget));
        }
        // Usage schemas report input/cache classes independently; output and thinking can also
        // overlap. Reserve each full class rather than relying on an approximate tokenizer.
        let tokens = input
            .checked_mul(3)
            .and_then(|value| {
                max_output
                    .checked_mul(2)
                    .and_then(|output| value.checked_add(output))
            })
            .ok_or(KernelError::AgentControl(ControllerError::Budget))?;
        let rates = card.rate_card.rates;
        let usage = iteron_protocol::Usage {
            input,
            output: max_output,
            cache_creation: input,
            cache_read: input,
            thinking: if rates.thinking_microusd_per_million > rates.output_microusd_per_million {
                max_output
            } else {
                0
            },
        };
        let cost = iteron_obs::pricing::projected_amount_microusd(rates, usage)?;
        Ok(Some((tokens, cost)))
    }

    /// The durable provider EffectIntent already exists; this second durable CAS must succeed
    /// before transport dispatch or model-input inclusion. The host mints agent id and epoch.
    pub(super) fn reserve_persistent_provider(
        &self,
        turn: TurnId,
        effect_id: &iteron_protocol::EffectId,
        route: &ProviderRouteAttemptIdentity,
        max_tokens: u64,
    ) -> Result<(), KernelError> {
        let Some(port) = self.persistent_provider_port()? else {
            return Ok(());
        };
        let scope = self.provider_scope();
        port.bind(&scope).map_err(KernelError::AgentControl)?;
        let cost = route
            .max_cost_reservation_microusd
            .ok_or(KernelError::UnpricedUsdCeiling)?;
        port.reserve(RuntimeProviderBudgetAdmission {
            scope_sha256: scope,
            effect_id: effect_id.0.clone(),
            turn: turn.0,
            route: route.clone(),
            max_tokens,
            max_cost_microusd: cost,
        })
        .map_err(KernelError::AgentControl)
    }

    /// Retrieve the exact pre-dispatch reservation for typed physical accounting. Root USD and
    /// child node USD pools can have different views; neither may replace controller evidence.
    pub(super) fn persistent_provider_cost_reservation(
        &self,
        turn: TurnId,
        route_id: &str,
        physical: u32,
    ) -> Result<Option<u64>, KernelError> {
        let Some(port) = self.persistent_provider_port()? else {
            return Ok(None);
        };
        let route = route_attempt_accounting::route_attempt_identity(route_id, physical, None)?;
        port.reservation(&self.provider_scope(), turn.0, &route)
            .map_err(KernelError::AgentControl)
    }

    /// Called only after the provider terminal became durable. A corrupt/unknown proof keeps
    /// conservative reservations; it cannot release the cohort's shared remaining budget.
    pub(super) fn settle_persistent_provider(
        &self,
        turn: TurnId,
        effect_id: &iteron_protocol::EffectId,
        accounting: &ProviderRouteAttemptAccounting,
    ) -> Result<(), KernelError> {
        let Some(port) = self.persistent_provider_port()? else {
            return Ok(());
        };
        let witness = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(accounting).map_err(|_| {
                KernelError::AgentControl(ControllerError::Invalid(
                    "provider terminal cannot be encoded",
                ))
            })?)
        );
        let truth = route_attempt_accounting::verified_charge(
            accounting,
            self.rollout.tenant(),
            self.rollout.run_id(),
            turn,
            Some(&self.projection_attribution),
            self.pricing_port.as_deref(),
        );
        let mut usage_error = None;
        let terminal = match &truth {
            Ok(route_attempt_accounting::RouteChargeTruth::Known(charge)) => match accounting.usage
            {
                ProviderRouteUsageTruth::Known { usage } => match checked_tokens(usage) {
                    Ok(tokens) => AgentProviderBudgetTerminal::Known {
                        tokens,
                        cost_microusd: charge.amount_microusd,
                    },
                    Err(error) => {
                        usage_error = Some(error);
                        AgentProviderBudgetTerminal::Unknown
                    }
                },
                _ => AgentProviderBudgetTerminal::Unknown,
            },
            Ok(route_attempt_accounting::RouteChargeTruth::NotDispatched) => {
                AgentProviderBudgetTerminal::NotDispatched
            }
            _ => AgentProviderBudgetTerminal::Unknown,
        };
        let unknown = terminal == AgentProviderBudgetTerminal::Unknown;
        let route = ProviderRouteAttemptIdentity {
            version: accounting.version,
            route_id: accounting.route_id.clone(),
            physical_attempt: accounting.physical_attempt,
            max_cost_reservation_microusd: accounting.max_cost_reservation_microusd,
        };
        port.settle(
            &self.provider_scope(),
            &effect_id.0,
            &route,
            terminal,
            &witness,
        )
        .map_err(KernelError::AgentControl)?;
        truth?;
        if let Some(error) = usage_error {
            return Err(error);
        }
        if unknown {
            return Err(KernelError::AgentControl(ControllerError::RecoveryRequired));
        }
        Ok(())
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
                        self.pricing_port.as_deref(),
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

fn checked_tokens(usage: iteron_protocol::Usage) -> Result<u64, KernelError> {
    [
        usage.input,
        usage.output,
        usage.cache_creation,
        usage.cache_read,
        usage.thinking,
    ]
    .into_iter()
    .try_fold(0u64, |sum, value| sum.checked_add(value))
    .ok_or(KernelError::AgentControl(ControllerError::Budget))
}
