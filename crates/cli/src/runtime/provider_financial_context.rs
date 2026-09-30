//! Frozen host financial evidence for one selected physical provider route. Monetary state stays
//! solely in SharedUsdBudget and the persistent controller; this adapter authenticates exact
//! tenant/run/turn/attempt evidence and never owns a session or invents a second budget ledger.
use super::KernelError;
use super::persistent_agents::{RuntimeProviderBudgetAdmission, RuntimeProviderBudgetPort};
use super::pricing::SharedUsdBudget;
use super::provider_charge_evidence::{
    self as route_attempt_accounting, RouteChargeTruth, route_accounting_id, verified_charge,
};
use super::provider_route;
use iteron_agents::{AgentProviderBudgetTerminal, ControllerError};
use iteron_obs::PricingPort;
use iteron_protocol::{
    CostAttribution, CostProjectionIdentity, ProviderRouteAttemptAccounting,
    ProviderRouteAttemptAccountingVersion, ProviderRouteAttemptIdentity, ProviderRouteCostTruth,
    ProviderRouteCostUnknownReason, ProviderRouteUsageTruth, ProviderRouteUsageUnknownReason,
    RunId, SignedRateCard, TenantId, TurnId, UsageReport,
};
use iteron_provider::Provider;
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub(super) struct ProviderFinancialScope {
    pub(super) tenant: TenantId,
    pub(super) run_id: RunId,
    pub(super) attribution: Option<CostAttribution>,
}

pub(super) struct ProviderPricingEvidence {
    pub(super) port: Option<Arc<dyn PricingPort>>,
    pub(super) card: Option<SignedRateCard>,
    pub(super) context_window: Option<u64>,
}

pub(super) struct ProviderFinancialOwners {
    pub(super) usd: Option<Arc<SharedUsdBudget>>,
    pub(super) cohort: Result<Option<Arc<dyn RuntimeProviderBudgetPort>>, ControllerError>,
}

/// Minted from authenticated host state after actual route activation. Route changes require a
/// fresh adapter so an old signed card cannot be used to admit the replacement provider.
pub(super) struct ProviderFinancialContext {
    scope: ProviderFinancialScope,
    scope_sha256: String,
    pricing_port: Option<Arc<dyn PricingPort>>,
    pricing: Option<SignedRateCard>,
    context_window: Option<u64>,
    usd_budget: Option<Arc<SharedUsdBudget>>,
    cohort: Result<Option<Arc<dyn RuntimeProviderBudgetPort>>, ControllerError>,
}

impl ProviderFinancialContext {
    pub(super) fn new(
        scope: ProviderFinancialScope,
        pricing: ProviderPricingEvidence,
        owners: ProviderFinancialOwners,
    ) -> Self {
        let scope_sha256 = provider_scope_for(&scope.tenant, &scope.run_id);
        Self {
            scope,
            scope_sha256,
            pricing_port: pricing.port,
            pricing: pricing.card,
            context_window: pricing.context_window,
            usd_budget: owners.usd,
            cohort: owners.cohort,
        }
    }

    fn cohort(&self) -> Result<Option<&Arc<dyn RuntimeProviderBudgetPort>>, KernelError> {
        self.cohort
            .as_ref()
            .map(Option::as_ref)
            .map_err(|error| KernelError::AgentControl(error.clone()))
    }

    /// Used only for a route refused before transport. A physical Unknown never calls this port.
    pub(super) fn settle_usd_not_dispatched(&self) {
        if let Some(budget) = &self.usd_budget {
            budget.settle_not_dispatched();
        }
    }
    pub(super) fn route_attempt_accounting(
        &self,
        turn: TurnId,
        route_id: &str,
        physical_attempt: u32,
        result: &Result<iteron_provider::TurnResult, KernelError>,
        projected_at_unix_secs: u64,
    ) -> Result<ProviderRouteAttemptAccounting, KernelError> {
        let (usage, cost) = match result {
            Ok(result) => match result.usage {
                UsageReport::Complete(usage) => {
                    let cost = self.route_attempt_cost(
                        turn,
                        route_id,
                        physical_attempt,
                        usage,
                        projected_at_unix_secs,
                    );
                    (ProviderRouteUsageTruth::Known { usage }, cost)
                }
                UsageReport::CacheCreationUnreported(_) => (
                    ProviderRouteUsageTruth::Unknown {
                        reason: ProviderRouteUsageUnknownReason::CacheCreationUnreported,
                    },
                    ProviderRouteCostTruth::Unknown {
                        reason: ProviderRouteCostUnknownReason::UsageIncomplete,
                    },
                ),
                UsageReport::Incomplete { .. } => (
                    ProviderRouteUsageTruth::Unknown {
                        reason: ProviderRouteUsageUnknownReason::ProviderOmitted,
                    },
                    ProviderRouteCostTruth::Unknown {
                        reason: ProviderRouteCostUnknownReason::UsageIncomplete,
                    },
                ),
            },
            Err(KernelError::Provider(
                iteron_provider::ProviderError::KnownModelUnavailable { .. }
                | iteron_provider::ProviderError::KnownAccountUnavailable { .. }
                | iteron_provider::ProviderError::ConnectFailed
                | iteron_provider::ProviderError::RequestCaptureRefusedBeforeDispatch
                | iteron_provider::ProviderError::RequestDeadlineBeforeDispatch,
            )) => (
                ProviderRouteUsageTruth::NotDispatched,
                ProviderRouteCostTruth::NotDispatched,
            ),
            Err(KernelError::Provider(error))
                if provider_route::provider_outcome_is_unobservable(error) =>
            {
                (
                    ProviderRouteUsageTruth::Unknown {
                        reason: ProviderRouteUsageUnknownReason::OutcomeUnobservable,
                    },
                    ProviderRouteCostTruth::Unknown {
                        reason: ProviderRouteCostUnknownReason::OutcomeUnobservable,
                    },
                )
            }
            Err(_) => (
                ProviderRouteUsageTruth::Unknown {
                    reason: ProviderRouteUsageUnknownReason::ProvenFailureWithoutUsage,
                },
                ProviderRouteCostTruth::Unknown {
                    reason: ProviderRouteCostUnknownReason::ProvenFailureWithoutBillingEvidence,
                },
            ),
        };
        let accounting = ProviderRouteAttemptAccounting {
            version: ProviderRouteAttemptAccountingVersion::V1,
            route_id: route_accounting_id(route_id),
            physical_attempt,
            max_cost_reservation_microusd: self
                .cohort_reservation(turn, route_id, physical_attempt)?
                .or_else(|| self.active_provider_cost_reservation()),
            usage,
            cost,
        };
        accounting
            .validate()
            .map_err(|reason| KernelError::InvalidRouteMetadata {
                field: "provider_route_attempt",
                reason,
            })?;
        Ok(accounting)
    }

    fn route_attempt_cost(
        &self,
        turn: TurnId,
        route_id: &str,
        physical_attempt: u32,
        usage: iteron_protocol::Usage,
        projected_at_unix_secs: u64,
    ) -> ProviderRouteCostTruth {
        let (Some(port), Some(rate_card)) = (&self.pricing_port, &self.pricing) else {
            return ProviderRouteCostTruth::Unknown {
                reason: ProviderRouteCostUnknownReason::RateCardUnavailable,
            };
        };
        let bound_route_id = format!(
            "{}:{}",
            rate_card.rate_card.route.provider_id, rate_card.rate_card.route.model_id
        );
        if bound_route_id != route_id {
            return ProviderRouteCostTruth::Unknown {
                reason: ProviderRouteCostUnknownReason::RateCardUnavailable,
            };
        }
        let identity = CostProjectionIdentity {
            tenant_id: self.scope.tenant.0.clone(),
            run_id: self.scope.run_id.0.clone(),
            turn_id: turn.0,
            provider_attempt: physical_attempt,
            attribution: self.scope.attribution.clone(),
        };
        match port.project(rate_card, identity, usage, projected_at_unix_secs) {
            Ok(projection) => ProviderRouteCostTruth::Known {
                amount_microusd: projection.amount_microusd,
                rate_card_digest: projection.rate_card_digest.clone(),
                projection: Some(Box::new(projection)),
            },
            Err(_) => ProviderRouteCostTruth::Unknown {
                reason: ProviderRouteCostUnknownReason::ProjectionRejected,
            },
        }
    }

    pub(super) fn reserve_provider_followup_if_needed(
        &self,
        provider: &dyn Provider,
        request: &iteron_provider::TurnRequest,
    ) -> Result<(), KernelError> {
        if let Some(budget) = &self.usd_budget
            && budget.requires_pricing()
            && budget.active_reservation_microusd().is_none()
        {
            let reservation = self
                .provider_request_cost_reservation(provider, request)?
                .ok_or(KernelError::PricingLedger(
                    "positive USD followup has no conservative cost reservation",
                ))?;
            budget
                .reserve_provider_attempt(reservation)
                .map_err(KernelError::PricingLedger)?;
        }
        Ok(())
    }

    pub(super) fn active_provider_cost_reservation(&self) -> Option<u64> {
        self.usd_budget
            .as_ref()
            .and_then(|budget| budget.active_reservation_microusd())
    }

    pub(super) fn provider_request_cost_reservation(
        &self,
        provider: &dyn Provider,
        request: &iteron_provider::TurnRequest,
    ) -> Result<Option<u64>, KernelError> {
        let Some(budget) = &self.usd_budget else {
            return Ok(None);
        };
        if !budget.requires_pricing() {
            return Ok(None);
        }
        let signed = self
            .pricing
            .as_ref()
            .ok_or(KernelError::UnpricedUsdCeiling)?;
        let input_bound = self.context_window.filter(|bound| *bound > 0).ok_or(
            KernelError::InvalidRouteMetadata {
                field: "model_context_window",
                reason: "positive USD admission requires a bounded model context window",
            },
        )?;
        let output_bound = u64::from(
            provider
                .physical_output_token_ceiling(request.into())?
                .filter(|cap| *cap > 0)
                .ok_or(KernelError::InvalidRouteMetadata {
                    field: "physical_output_token_ceiling",
                    reason: "positive USD admission needs an adapter-attested physical output ceiling",
                })?,
        );
        let rates = signed.rate_card.rates;
        let thinking = if rates.thinking_microusd_per_million > rates.output_microusd_per_million {
            output_bound
        } else {
            0
        };
        let usage = iteron_protocol::Usage {
            input: input_bound,
            output: output_bound,
            cache_creation: input_bound,
            cache_read: input_bound,
            thinking,
        };
        iteron_obs::pricing::projected_amount_microusd(rates, usage)
            .map(Some)
            .map_err(KernelError::from)
    }

    pub(super) fn commit_provider_route_charge(
        &self,
        turn: TurnId,
        accounting: &ProviderRouteAttemptAccounting,
    ) -> Result<(), KernelError> {
        let Some(budget) = &self.usd_budget else {
            return Ok(());
        };
        if !budget.requires_pricing() {
            return Ok(());
        }
        match verified_charge(
            accounting,
            &self.scope.tenant,
            &self.scope.run_id,
            turn,
            Some(&self.scope.attribution),
            self.pricing_port.as_deref(),
        ) {
            Ok(RouteChargeTruth::Known(charge)) => budget
                .commit_provider_route_charge(charge)
                .map_err(KernelError::PricingLedger),
            Ok(RouteChargeTruth::NotDispatched) => {
                budget.settle_not_dispatched();
                Ok(())
            }
            Ok(RouteChargeTruth::Unknown) => {
                budget.mark_unknown();
                Err(KernelError::UnpricedUsdCeiling)
            }
            Err(error) => {
                budget.mark_unknown();
                Err(error)
            }
        }
    }

    pub(super) fn cohort_bounds(
        &self,
        route_id: &str,
        max_output: u64,
        now: u64,
    ) -> Result<Option<(u64, u64)>, KernelError> {
        if self.cohort()?.is_none() {
            return Ok(None);
        }
        let (Some(pricing), Some(card)) = (&self.pricing_port, &self.pricing) else {
            return Err(KernelError::UnpricedUsdCeiling);
        };
        pricing.verify_rate_card(card)?;
        if now < card.rate_card.issued_at_unix_secs
            || now >= card.rate_card.expires_at_unix_secs
            || format!(
                "{}:{}",
                card.rate_card.route.provider_id, card.rate_card.route.model_id
            ) != route_id
        {
            return Err(KernelError::UnpricedUsdCeiling);
        }
        let input = self.context_window.filter(|value| *value > 0).ok_or(
            KernelError::InvalidRouteMetadata {
                field: "model_context_window",
                reason: "persistent provider admission needs a proven finite context window",
            },
        )?;
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

    pub(super) fn reserve_cohort(
        &self,
        turn: TurnId,
        effect_id: &iteron_protocol::EffectId,
        route: &ProviderRouteAttemptIdentity,
        max_tokens: u64,
    ) -> Result<(), KernelError> {
        let Some(port) = self.cohort()? else {
            return Ok(());
        };
        let scope = self.scope_sha256.clone();
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

    pub(super) fn cohort_reservation(
        &self,
        turn: TurnId,
        route_id: &str,
        physical: u32,
    ) -> Result<Option<u64>, KernelError> {
        let Some(port) = self.cohort()? else {
            return Ok(None);
        };
        let route = route_attempt_accounting::route_attempt_identity(route_id, physical, None)?;
        port.reservation(&self.scope_sha256, turn.0, &route)
            .map_err(KernelError::AgentControl)
    }

    pub(super) fn settle_cohort(
        &self,
        turn: TurnId,
        effect_id: &iteron_protocol::EffectId,
        accounting: &ProviderRouteAttemptAccounting,
    ) -> Result<(), KernelError> {
        let Some(port) = self.cohort()? else {
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
            &self.scope.tenant,
            &self.scope.run_id,
            turn,
            Some(&self.scope.attribution),
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
        port.settle(&self.scope_sha256, &effect_id.0, &route, terminal, &witness)
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
}

/// Framed exact authenticated runtime scope; no route/model aliases or caller-supplied scope.
pub(super) fn provider_scope_for(tenant: &TenantId, run: &RunId) -> String {
    let mut hash = Sha256::new();
    hash.update(b"iteron-persistent-provider-run-v1\0");
    for part in [&tenant.0, &run.0] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part.as_bytes());
    }
    format!("sha256:{:x}", hash.finalize())
}

pub(super) fn checked_tokens(usage: iteron_protocol::Usage) -> Result<u64, KernelError> {
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

#[cfg(test)]
#[path = "provider_financial_context_tests.rs"]
mod tests;
