//! Host assembly adapters. Actual physical charge state, signed receipt validation and replay
//! belong to provider_charge_evidence; immutable admission/settlement to ProviderFinancialContext.
use super::provider_extension::ProviderExtensionTerminal;
use super::{Agent, KernelError};
use iteron_protocol::{ProviderRouteAttemptAccounting, TurnId};

pub(super) use super::provider_charge_evidence::{
    ProviderRouteChargeLedger, ProviderRouteChargeReplay, RouteChargeTruth,
    VerifiedProviderRouteCharge, crash_recovery_accounting, not_dispatched_accounting,
    replay_evidence, replay_route_charges, verified_charge,
};

impl Agent {
    #[cfg(test)]
    pub(super) fn route_attempt_accounting(
        &self,
        turn: TurnId,
        route_id: &str,
        physical_attempt: u32,
        result: &Result<iteron_provider::TurnResult, KernelError>,
        projected_at_unix_secs: u64,
    ) -> Result<ProviderRouteAttemptAccounting, KernelError> {
        self.provider_financial_context().route_attempt_accounting(
            turn,
            route_id,
            physical_attempt,
            result,
            projected_at_unix_secs,
        )
    }

    /// A positive monetary ceiling must never authorize another physical request after an
    /// earlier request's cost became unknown. The prior terminal is already durable when this is
    /// called, so refusal cannot erase the evidence that closed the gate.
    pub(super) fn admit_followup_after_route_attempt_set(
        &self,
        monetary_followup_safe: bool,
    ) -> Result<(), KernelError> {
        if let Some(terminal) = self.provider_extension_terminal() {
            return Err(KernelError::InferenceBudgetExhausted(match terminal {
                ProviderExtensionTerminal::Budget(reason) => reason,
                ProviderExtensionTerminal::UsageUnavailable => "usage_unavailable",
            }));
        }
        if self
            .usd_budget
            .as_ref()
            .is_some_and(|budget| budget.requires_pricing())
            && !monetary_followup_safe
        {
            self.mark_usd_unknown();
            return Err(KernelError::UnpricedUsdCeiling);
        }
        if self.usd_budget_exhausted() {
            return Err(KernelError::InferenceBudgetExhausted("max_usd"));
        }
        Ok(())
    }

    /// Reserve only after the governor, deadline, and interrupt gates have admitted the next
    /// physical request. A rejected/deferred-before-cancel route therefore never turns a known
    /// monetary state into an artificial unknown.
    pub(super) fn reserve_provider_followup_if_needed(
        &self,
        request: &iteron_provider::TurnRequest,
    ) -> Result<(), KernelError> {
        self.provider_financial_context()
            .reserve_provider_followup_if_needed(self.provider.as_ref(), request)
    }

    /// Conservative price for the exact request under the signed active card. The model context
    /// window bounds input; every cache class receives that full bound because adapters disagree
    /// about whether cached tokens are also included in `input`. Output and thinking share one
    /// output ceiling, assigned wholly to the more expensive class.
    pub(super) fn provider_request_cost_reservation(
        &self,
        request: &iteron_provider::TurnRequest,
    ) -> Result<Option<u64>, KernelError> {
        self.provider_financial_context()
            .provider_request_cost_reservation(self.provider.as_ref(), request)
    }

    /// Make one already-durable physical terminal load-bearing before any retry, fallback, child,
    /// or next logical turn can be admitted. A malformed or unverifiable known amount closes the
    /// shared ceiling; it is never treated as zero and never deferred until the logical winner.
    pub(super) fn commit_provider_route_charge(
        &self,
        turn: TurnId,
        accounting: &ProviderRouteAttemptAccounting,
    ) -> Result<(), KernelError> {
        self.provider_financial_context()
            .commit_provider_route_charge(turn, accounting)
    }

    pub(super) fn restore_usd_budget_from_route_receipts(
        &self,
        scoped_events: &[iteron_record::ScopedEvent],
    ) -> Result<(), KernelError> {
        let Some(budget) = &self.usd_budget else {
            return Ok(());
        };
        let replay = replay_route_charges(
            scoped_events,
            self.provider_selection
                .pricing_port()
                .map(|port| port.as_ref()),
        )?;
        budget
            .restore_provider_route_charges(&self.ledger.cost_state(), replay)
            .map_err(KernelError::PricingLedger)
    }
}

#[cfg(test)]
pub(super) use super::provider_charge_evidence::{route_accounting_id, route_attempt_identity};
