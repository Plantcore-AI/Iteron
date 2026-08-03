use super::{PricingError, PricingPort, validate_projection_digest, validate_rate_card_digest};
use crate::Ledger;
use core_protocol::{
    CostAttribution, CostProjectionIdentity, Event, EventKind, MAX_WORKFLOW_COST_PROJECTIONS,
    PricingRoute, RunId, SignedRateCard, TenantId, Usage, WorkflowEvent, WorkflowMetrics,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

#[derive(Debug, Clone)]
struct OpenProviderTurn {
    provider_attempt: u32,
    route: Option<PricingRoute>,
    rate_card_digest: Option<String>,
    binding_epoch: u64,
}

/// Stateful semantic validator for cost replay. Without a trusted port it never restores `Known`.
/// With one, both HMACs, exact route provenance, amount, signed freshness timestamp, and adjacency
/// must verify before monetary state advances.
#[derive(Default)]
pub struct PricingReplay {
    pricing: Option<Arc<dyn PricingPort>>,
    selected_route: Option<PricingRoute>,
    bound_rate_cards: HashMap<String, SignedRateCard>,
    active_rate_card: Option<String>,
    binding_epoch: u64,
    open_provider_turns: HashMap<(String, String, u32), OpenProviderTurn>,
    pending_turn: Option<(Usage, PricingRoute, CostProjectionIdentity, Option<String>)>,
    open_sub_runs: HashSet<String>,
    workflow_admissions: HashMap<(String, u32), String>,
    workflow_sub_runs: HashMap<String, (String, u32)>,
    terminal_sub_runs: HashSet<String>,
    workflow_tasks: HashSet<(String, u32)>,
    consumed_projection_identities: HashSet<CostProjectionIdentity>,
    consumed_projection_digests: HashSet<String>,
}

impl std::fmt::Debug for PricingReplay {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PricingReplay")
            .field("trusted_pricing", &self.pricing.is_some())
            .field("selected_route", &self.selected_route)
            .field("bound_rate_cards", &self.bound_rate_cards.len())
            .field("active_rate_card", &self.active_rate_card)
            .field("binding_epoch", &self.binding_epoch)
            .field("open_provider_turns", &self.open_provider_turns.len())
            .field("pending_turn", &self.pending_turn)
            .field("open_sub_runs", &self.open_sub_runs.len())
            .field("workflow_admissions", &self.workflow_admissions.len())
            .field("workflow_sub_runs", &self.workflow_sub_runs.len())
            .field("terminal_sub_runs", &self.terminal_sub_runs.len())
            .field("workflow_tasks", &self.workflow_tasks.len())
            .field(
                "consumed_projection_identities",
                &self.consumed_projection_identities.len(),
            )
            .field(
                "consumed_projection_digests",
                &self.consumed_projection_digests.len(),
            )
            .finish()
    }
}

impl PricingReplay {
    pub fn trusted(pricing: Arc<dyn PricingPort>) -> Self {
        Self {
            pricing: Some(pricing),
            ..Self::default()
        }
    }

    pub fn observe(
        &mut self,
        event: &Event,
        tenant: &TenantId,
        run_id: &RunId,
        ledger: &mut Ledger,
    ) -> Result<(), PricingError> {
        ledger.mark_timing_unknown_after_replay();
        let kind = &event.kind;
        if !matches!(kind, EventKind::CostProjected { .. }) {
            self.pending_turn = None;
        }
        match kind {
            EventKind::TurnStart => {
                ledger.attempt();
                self.open_provider_turns
                    .entry((tenant.0.clone(), run_id.0.clone(), event.turn.0))
                    .or_insert_with(|| OpenProviderTurn {
                        provider_attempt: ledger.provider_attempts,
                        route: self.selected_route.clone(),
                        rate_card_digest: self.active_rate_card.clone(),
                        binding_epoch: self.binding_epoch,
                    });
            }
            // Replay folds token accounting only. The timing fields are process-local observations
            // of the run that happened, not reproducible counters, so replay reads past them and
            // leaves `TimingSnapshot` to report the history as unknown rather than reconstructing a
            // number it cannot prove.
            EventKind::TurnEnd { usage, .. } => {
                ledger.replay_turn(usage);
                let admitted_attempt = self.open_provider_turns.remove(&(
                    tenant.0.clone(),
                    run_id.0.clone(),
                    event.turn.0,
                ));
                self.pending_turn = admitted_attempt.and_then(|admission| {
                    (admission.binding_epoch == self.binding_epoch)
                        .then_some(admission)
                        .and_then(|admission| {
                            let OpenProviderTurn {
                                provider_attempt,
                                route,
                                rate_card_digest,
                                ..
                            } = admission;
                            route.map(|route| {
                                (
                                    *usage,
                                    route,
                                    CostProjectionIdentity {
                                        tenant_id: tenant.0.clone(),
                                        run_id: run_id.0.clone(),
                                        turn_id: event.turn.0,
                                        provider_attempt,
                                        attribution: None,
                                    },
                                    rate_card_digest,
                                )
                            })
                        })
                });
            }
            EventKind::ModelSelected {
                provider_id,
                model_id,
                catalog_digest,
                capability_digest,
            } => {
                self.binding_epoch = self.binding_epoch.saturating_add(1);
                self.selected_route = Some(PricingRoute {
                    provider_id: provider_id.clone(),
                    model_id: model_id.clone(),
                    catalog_digest: catalog_digest.clone(),
                    capability_digest: capability_digest.clone(),
                });
                // Every durable route selection starts a new binding epoch, even if it selects the
                // same bytes as an earlier epoch. A historical card cannot silently reactivate
                // after a route switch without a fresh RateCardBound event.
                self.active_rate_card = None;
            }
            EventKind::RateCardBound { rate_card } => {
                self.binding_epoch = self.binding_epoch.saturating_add(1);
                self.active_rate_card = None;
                validate_rate_card_digest(rate_card)?;
                if self.selected_route.as_ref() != Some(&rate_card.rate_card.route) {
                    return Ok(());
                }
                let Some(pricing) = &self.pricing else {
                    return Ok(());
                };
                match pricing.verify_rate_card(rate_card) {
                    Ok(()) => {
                        self.bound_rate_cards
                            .insert(rate_card.rate_card_digest.clone(), rate_card.clone());
                        self.active_rate_card = Some(rate_card.rate_card_digest.clone());
                    }
                    Err(PricingError::UntrustedRateCard) => return Ok(()),
                    Err(error) => return Err(error),
                }
            }
            EventKind::CostProjected { projection } => {
                validate_projection_digest(projection)?;
                if projection
                    .identity
                    .as_ref()
                    .is_some_and(|identity| self.consumed_projection_identities.contains(identity))
                    || self
                        .consumed_projection_digests
                        .contains(&projection.projection_digest)
                {
                    return Err(PricingError::DuplicateProjection);
                }
                let pending = self.pending_turn.take();
                let pending_matches = pending.as_ref().is_some_and(|(usage, route, _, _)| {
                    *usage == projection.usage && *route == projection.route
                });
                if !pending_matches {
                    return Err(PricingError::ProjectionNotAdjacent);
                }
                // Historical projections did not authenticate rollout identity. Keep them
                // readable, but leave this completed turn honestly unpriced.
                let Some(identity) = &projection.identity else {
                    ledger.mark_legacy_unattributed();
                    return Ok(());
                };
                let pending = pending.expect("adjacent projection has a pending turn");
                let expected = &pending.2;
                if identity.tenant_id != expected.tenant_id
                    || identity.run_id != expected.run_id
                    || identity.turn_id != expected.turn_id
                    || identity.provider_attempt != expected.provider_attempt
                {
                    return Err(PricingError::ProjectionIdentityMismatch);
                }
                // Consume the occurrence before trust/card branches. An unpriced historical
                // occurrence cannot later be replayed with a fabricated second TurnEnd merely
                // because a binding epoch was introduced in between.
                self.consumed_projection_identities.insert(identity.clone());
                self.consumed_projection_digests
                    .insert(projection.projection_digest.clone());
                if pending.3.as_deref() != Some(projection.rate_card_digest.as_str()) {
                    return Ok(());
                }
                let Some(rate_card) = self.bound_rate_cards.get(&projection.rate_card_digest)
                else {
                    return Ok(());
                };
                let Some(pricing) = &self.pricing else {
                    return Ok(());
                };
                pricing.verify_projection(rate_card, projection)?;
                ledger
                    .apply_cost_projection(projection)
                    .map_err(|_| PricingError::WorkflowEvidenceMismatch)?;
            }
            EventKind::ToolDone { result, .. } => ledger.replay_tool(result.is_error),
            EventKind::EffectUnknown { .. } => ledger.replay_tool(true),
            EventKind::SubagentSpawned { sub_run, .. }
                if self.open_sub_runs.insert(sub_run.clone()) =>
            {
                ledger.admit_child_attribution();
            }
            EventKind::Workflow {
                workflow_id,
                event:
                    WorkflowEvent::ChildStarted {
                        task_id, sub_run, ..
                    },
                ..
            }
            | EventKind::WorkflowV2 {
                workflow_id,
                event:
                    WorkflowEvent::ChildStarted {
                        task_id, sub_run, ..
                    },
                ..
            } => {
                let task_key = (workflow_id.clone(), *task_id);
                if let Some(existing) = self.workflow_admissions.get(&task_key)
                    && existing != sub_run
                {
                    return Err(PricingError::WorkflowEvidenceMismatch);
                }
                if let Some(existing_task) = self.workflow_sub_runs.get(sub_run)
                    && existing_task != &task_key
                {
                    return Err(PricingError::WorkflowEvidenceMismatch);
                }
                self.workflow_admissions.insert(task_key, sub_run.clone());
                self.workflow_sub_runs
                    .insert(sub_run.clone(), (workflow_id.clone(), *task_id));
                if self.open_sub_runs.insert(sub_run.clone()) {
                    ledger.admit_child_attribution();
                }
            }
            EventKind::SubagentFinished {
                sub_run, metrics, ..
            }
            | EventKind::SubagentFinishedV2 {
                sub_run, metrics, ..
            } => {
                if self.terminal_sub_runs.contains(sub_run) {
                    return Err(PricingError::DuplicateWorkflowTerminal);
                }
                let attribution = CostAttribution::DirectSubagent {
                    parent_run_id: run_id.0.clone(),
                    sub_run: sub_run.clone(),
                };
                self.observe_workflow_metrics(tenant, sub_run, &attribution, metrics, ledger)?;
                if self.open_sub_runs.remove(sub_run) {
                    ledger.resolve_child_attribution();
                }
                self.terminal_sub_runs.insert(sub_run.clone());
            }
            EventKind::Workflow {
                workflow_id,
                event:
                    WorkflowEvent::ChildFinished {
                        task_id,
                        sub_run,
                        metrics,
                        ..
                    },
                ..
            }
            | EventKind::WorkflowV2 {
                workflow_id,
                event:
                    WorkflowEvent::ChildFinished {
                        task_id,
                        sub_run,
                        metrics,
                        ..
                    },
                ..
            } => {
                let task_key = (workflow_id.clone(), *task_id);
                if self.workflow_tasks.contains(&task_key)
                    || sub_run
                        .as_ref()
                        .is_some_and(|run| self.terminal_sub_runs.contains(run))
                {
                    return Err(PricingError::DuplicateWorkflowTerminal);
                }
                if metrics.cost.is_some() && sub_run.is_none() {
                    return Err(PricingError::WorkflowEvidenceMismatch);
                }
                if self.workflow_admissions.contains_key(&task_key) && sub_run.is_none() {
                    return Err(PricingError::WorkflowEvidenceMismatch);
                }
                if let (Some(admitted), Some(terminal)) =
                    (self.workflow_admissions.get(&task_key), sub_run.as_ref())
                    && admitted != terminal
                {
                    return Err(PricingError::WorkflowEvidenceMismatch);
                }
                if let Some(sub_run) = sub_run {
                    let attribution = CostAttribution::WorkflowChild {
                        parent_run_id: run_id.0.clone(),
                        workflow_id: workflow_id.clone(),
                        task_id: *task_id,
                        sub_run: sub_run.clone(),
                    };
                    self.observe_workflow_metrics(tenant, sub_run, &attribution, metrics, ledger)?;
                } else {
                    self.observe_unpriced_workflow_metrics(metrics, ledger);
                }
                if let Some(resolved_sub_run) = sub_run.as_ref()
                    && self.open_sub_runs.remove(resolved_sub_run)
                {
                    ledger.resolve_child_attribution();
                }
                self.workflow_tasks.insert(task_key);
                if let Some(sub_run) = sub_run {
                    self.terminal_sub_runs.insert(sub_run.clone());
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn observe_workflow_metrics(
        &self,
        tenant: &TenantId,
        sub_run: &str,
        expected_attribution: &CostAttribution,
        metrics: &WorkflowMetrics,
        ledger: &mut Ledger,
    ) -> Result<(), PricingError> {
        let Some(cost) = &metrics.cost else {
            ledger.merge_workflow_metrics(metrics);
            return Ok(());
        };
        let Some(pricing) = &self.pricing else {
            ledger.merge_workflow_metrics(metrics);
            return Ok(());
        };
        let expected_projections = usize::try_from(metrics.completed_turns)
            .map_err(|_| PricingError::WorkflowEvidenceMismatch)?;
        if expected_projections == 0
            || expected_projections > MAX_WORKFLOW_COST_PROJECTIONS
            || cost.projections.len() != expected_projections
        {
            return Err(PricingError::WorkflowEvidenceMismatch);
        }
        // Legacy identity-less child projections remain readable, but cannot establish a known
        // aggregate. Restore only their non-monetary attribution.
        if cost
            .projections
            .iter()
            .any(|projection| projection.identity.is_none())
        {
            ledger.merge_workflow_metrics(metrics);
            return Ok(());
        }
        let mut attempts = HashSet::new();
        let mut projection_digests = HashSet::new();
        for projection in &cost.projections {
            let identity = projection
                .identity
                .as_ref()
                .ok_or(PricingError::MissingProjectionIdentity)?;
            if identity.tenant_id != tenant.0
                || identity.run_id != sub_run
                || identity.attribution.as_ref() != Some(expected_attribution)
                || identity.provider_attempt == 0
                || identity.provider_attempt > metrics.provider_attempts
                || !attempts.insert((identity.turn_id, identity.provider_attempt))
                || !projection_digests.insert(projection.projection_digest.as_str())
            {
                return Err(PricingError::ProjectionIdentityMismatch);
            }
            pricing.verify_projection_by_digest(projection)?;
        }
        ledger
            .merge_verified_workflow_metrics(metrics)
            .map_err(|_| PricingError::WorkflowEvidenceMismatch)
    }

    fn observe_unpriced_workflow_metrics(&self, metrics: &WorkflowMetrics, ledger: &mut Ledger) {
        ledger.merge_workflow_metrics(metrics);
    }
}
