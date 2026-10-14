//! Host-only replay of exact physical budget receipts and monetary ancestry. A controller
//! recovery label describes unmeasured execution; financial truth comes only from its actual WAL.
use super::KernelPersistentRuntime;
use crate::runtime::{
    KernelError, persistent_provider_budget, replay_scoped_rollout, route_attempt_accounting,
};
use iteron_agents::{
    AgentActor, AgentController, AgentControllerJournal, AgentProviderBudgetRequest,
    AgentProviderBudgetTerminal, ControllerError,
};
use iteron_protocol::agent_cohort::AgentCohortMainRunV1;
use iteron_protocol::{
    ProviderRouteAttemptIdentity, ProviderRouteUsageTruth, RunId, TenantId, TurnId,
};
use iteron_record::ScopedEvent;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

impl KernelPersistentRuntime {
    pub(super) fn pin_main_rollouts<J: AgentControllerJournal>(
        &self,
        controller: &AgentController<J>,
        state: &Path,
        current_run: &RunId,
    ) -> Result<(), KernelError> {
        let origin = controller
            .snapshot()
            .cohort_origin()
            .ok_or(KernelError::AgentControl(ControllerError::RecoveryRequired))?;
        let mut runs = vec![origin.run_id.clone()];
        runs.extend(
            controller
                .snapshot()
                .cohort_main_runs()
                .iter()
                .map(|run| run.run_id.clone()),
        );
        let mut leases = self
            .main_rollout_owners
            .lock()
            .map_err(|_| KernelError::AgentControl(ControllerError::Poisoned))?;
        if !leases.is_empty() {
            return Err(KernelError::AgentControl(ControllerError::RequestConflict));
        }
        for run in runs.iter().filter(|run| *run != current_run) {
            // A shared derivative read lease is insufficient: retain the actual exclusive WAL
            // writer lease so another process cannot execute the previous Main concurrently.
            let owner = iteron_record::Rollout::open_existing(state, run, origin.tenant.clone())?;
            let recovered =
                super::super::cold_cohort::CohortReplay::load(owner.path(), &origin.tenant, run)?;
            if recovered
                .installation
                .as_ref()
                .map(|installed| &installed.origin)
                != Some(origin)
            {
                return Err(KernelError::AgentControl(ControllerError::RequestConflict));
            }
            leases.push(owner);
        }
        Ok(())
    }

    pub(super) fn restore_provider_evidence<J: AgentControllerJournal>(
        &self,
        controller: &mut AgentController<J>,
        root_path: &Path,
        tenant: &TenantId,
        root_run: &RunId,
        baseline_sequence: u64,
    ) -> Result<(), KernelError> {
        let views = controller
            .list(AgentActor::Operator)
            .map_err(KernelError::AgentControl)?;
        let root = controller.root_id();
        self.restore_monetary_chains(&views, root)
            .map_err(KernelError::AgentControl)?;
        let mut pending = BTreeMap::new();
        for request in controller
            .pending_provider_budget_requests()
            .map_err(KernelError::AgentControl)?
        {
            pending
                .entry(request.agent_id)
                .or_insert_with(Vec::new)
                .push(request);
        }
        let root_requests = pending.remove(&root).unwrap_or_default();
        let aliases = controller.snapshot().cohort_main_runs();
        let mut physical_roots: Vec<(
            std::path::PathBuf,
            RunId,
            Option<u64>,
            Option<AgentCohortMainRunV1>,
        )> = vec![(
            root_path.to_path_buf(),
            root_run.clone(),
            Some(baseline_sequence),
            None,
        )];
        for alias in aliases {
            if alias.tenant != *tenant {
                return Err(KernelError::AgentControl(ControllerError::RequestConflict));
            }
            physical_roots.push((
                super::super::cold_cohort::main_rollout_path(&self.writer.state, &alias.run_id),
                alias.run_id.clone(),
                None,
                Some(alias),
            ));
        }
        let mut unmatched = root_requests;
        for (path, run, after, alias) in physical_roots {
            let replay = super::super::cold_cohort::CohortReplay::load(&path, tenant, &run)?;
            if let Some(alias) = &alias {
                replay.main_admission(tenant, &run, Some(alias))?;
            }
            let rows = own_rows(replay_scoped_rollout(&path)?, tenant, &run, after)?;
            let scope = persistent_provider_budget::provider_scope_for(tenant, &run);
            let (requests, remainder): (Vec<_>, Vec<_>) = unmatched
                .into_iter()
                .partition(|request| request.scope_sha256 == scope);
            unmatched = remainder;
            reconcile(
                controller,
                &rows,
                tenant,
                &run,
                requests,
                self.pricing.as_deref(),
            )?;
            let replay =
                route_attempt_accounting::replay_route_charges(&rows, self.pricing.as_deref())?;
            // A WAL intent may precede the controller reservation; absence of a controller
            // receipt does not turn unobserved provider IO into a zero-cost baseline.
            require_budget_quarantine(controller, replay.ledger.is_unknown())?;
            if let Some(pool) = &self.money {
                pool.merge_recovered_charges(&replay.ledger)
                    .map_err(KernelError::PricingLedger)?;
            }
        }
        if !unmatched.is_empty() {
            return Err(KernelError::AgentControl(ControllerError::RequestConflict));
        }
        for view in views.iter().filter(|view| view.agent_id != root) {
            let requests = pending.remove(&view.agent_id).unwrap_or_default();
            if view.usage.turns == 0 && requests.is_empty() {
                continue;
            }
            let run = self
                .generations
                .lock()
                .map_err(|_| KernelError::AgentControl(ControllerError::Poisoned))?
                .bootstrap()
                .mint_run_id(view.agent_id.0);
            let path = self
                .writer
                .state
                .join("subagents")
                .join(format!("{}.jsonl", run.0));
            let rows = own_rows(replay_scoped_rollout(&path)?, tenant, &run, None)?;
            reconcile(
                controller,
                &rows,
                tenant,
                &run,
                requests,
                self.pricing.as_deref(),
            )?;
            let replay =
                route_attempt_accounting::replay_route_charges(&rows, self.pricing.as_deref())?;
            require_budget_quarantine(controller, replay.ledger.is_unknown())?;
            // Parent-prefix records keep their original scope and are excluded. Child replay
            // reaches every actual ancestor once through the exact physical charge identity.
            let pool = self
                .agent_money
                .lock()
                .map_err(|_| KernelError::AgentControl(ControllerError::Poisoned))?
                .get(&view.agent_id)
                .cloned();
            if let Some(pool) = pool {
                pool.merge_recovered_charges(&replay.ledger)
                    .map_err(KernelError::PricingLedger)?;
            }
        }
        if !pending.is_empty() {
            return Err(KernelError::AgentControl(ControllerError::RequestConflict));
        }
        Ok(())
    }
}
fn own_rows(
    rows: Vec<ScopedEvent>,
    tenant: &TenantId,
    run: &RunId,
    after: Option<u64>,
) -> Result<Vec<ScopedEvent>, KernelError> {
    // An empty projection from a foreign physical journal is not evidence of zero spend.
    if !rows
        .iter()
        .any(|row| row.run_id == *run && row.tenant == *tenant)
        || rows
            .iter()
            .any(|row| row.run_id == *run && row.tenant != *tenant)
    {
        return Err(KernelError::AgentControl(ControllerError::RequestConflict));
    }
    Ok(rows
        .into_iter()
        .filter(|row| {
            row.tenant == *tenant
                && row.run_id == *run
                && after.is_none_or(|seq| row.event.seq.0 > seq)
        })
        .collect())
}
fn require_budget_quarantine<J: AgentControllerJournal>(
    controller: &AgentController<J>,
    monetary_unknown: bool,
) -> Result<(), KernelError> {
    if monetary_unknown && !controller.provider_budget_recovery_required() {
        return Err(KernelError::AgentControl(ControllerError::RecoveryRequired));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
fn reconcile<J: AgentControllerJournal>(
    controller: &mut AgentController<J>,
    rows: &[ScopedEvent],
    tenant: &TenantId,
    run: &RunId,
    requests: Vec<AgentProviderBudgetRequest>,
    pricing: Option<&dyn iteron_obs::PricingPort>,
) -> Result<(), KernelError> {
    let evidence = route_attempt_accounting::replay_evidence::ProviderReplayEvidence::inspect(rows);
    let scope = persistent_provider_budget::provider_scope_for(tenant, run);
    for request in requests {
        if request.scope_sha256 != scope {
            return Err(KernelError::AgentControl(ControllerError::RequestConflict));
        }
        let Some(accounting) = evidence.matching_terminal(
            tenant,
            run,
            &request.effect_id,
            request.turn,
            &request.route,
        ) else {
            // No matching terminal means no release, even if another attempt in this run has a
            // signed charge or a controller task reports effects-known.
            continue;
        };
        let terminal = match route_attempt_accounting::verified_charge(
            accounting,
            tenant,
            run,
            TurnId(request.turn),
            None,
            pricing,
        )? {
            route_attempt_accounting::RouteChargeTruth::Known(charge) => {
                let ProviderRouteUsageTruth::Known { usage } = accounting.usage else {
                    continue;
                };
                AgentProviderBudgetTerminal::Known {
                    tokens: persistent_provider_budget::checked_tokens(usage)?,
                    cost_microusd: charge.amount_microusd,
                }
            }
            route_attempt_accounting::RouteChargeTruth::NotDispatched => {
                AgentProviderBudgetTerminal::NotDispatched
            }
            route_attempt_accounting::RouteChargeTruth::Unknown => continue,
        };
        let witness = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(accounting).map_err(|_| {
                KernelError::AgentControl(ControllerError::Invalid(
                    "provider terminal cannot be encoded",
                ))
            })?)
        );
        let route = ProviderRouteAttemptIdentity {
            version: accounting.version,
            route_id: accounting.route_id.clone(),
            physical_attempt: accounting.physical_attempt,
            max_cost_reservation_microusd: accounting.max_cost_reservation_microusd,
        };
        controller
            .settle_provider_budget(
                request.agent_id,
                &scope,
                &request.effect_id,
                &route,
                terminal,
                &witness,
            )
            .map_err(KernelError::AgentControl)?;
        // This settles only billing/tokens. It never claims process cleanup, wall usage or
        // resurrects an agent epoch: the controller's execution recovery state is preserved.
    }
    Ok(())
}
