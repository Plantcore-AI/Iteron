//! Durable usage/cost truth for each physical provider route attempt.
//!
//! `TurnEnd` accounts for the eventual logical turn. It cannot describe a failed primary request
//! followed by a successful fallback, so every provider effect terminal carries this smaller
//! content-free receipt as well. Unknown billing is explicit and closes a positive USD ceiling
//! before any retry or fallback can dispatch.

use super::*;
use iteron_protocol::{
    CostProjection, CostProjectionIdentity, ProviderRouteAttemptAccounting,
    ProviderRouteAttemptAccountingVersion, ProviderRouteAttemptIdentity, ProviderRouteCostTruth,
    ProviderRouteCostUnknownReason, ProviderRouteUsageTruth, ProviderRouteUsageUnknownReason,
};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// Exact, idempotent monetary commits for physical provider attempts.
///
/// This is deliberately separate from the logical-turn ledger. A retry or fallback may have
/// consumed money even though only the eventual winner owns `TurnEnd`; charging that winner again
/// would be equally wrong. The signed projection identity is the durable idempotency key.
#[derive(Debug, Default)]
pub(super) struct ProviderRouteChargeLedger {
    identities: HashMap<CostProjectionIdentity, String>,
    projection_digests: HashSet<String>,
    amount_microusd: u64,
    unknown: bool,
}

#[derive(Debug, Clone)]
pub(super) struct VerifiedProviderRouteCharge {
    pub(super) identity: CostProjectionIdentity,
    pub(super) projection_digest: String,
    pub(super) amount_microusd: u64,
}

impl ProviderRouteChargeLedger {
    pub(super) fn admit(
        &mut self,
        charge: VerifiedProviderRouteCharge,
    ) -> Result<bool, &'static str> {
        if let Some(existing) = self.identities.get(&charge.identity) {
            return if existing == &charge.projection_digest {
                Ok(false)
            } else {
                self.unknown = true;
                Err("provider route charge identity was reused with different evidence")
            };
        }
        if !self
            .projection_digests
            .insert(charge.projection_digest.clone())
        {
            self.unknown = true;
            return Err("provider route charge projection was reused for another attempt");
        }
        let Some(amount_microusd) = self.amount_microusd.checked_add(charge.amount_microusd) else {
            self.unknown = true;
            return Err("provider route charge total overflowed");
        };
        self.identities
            .insert(charge.identity, charge.projection_digest);
        self.amount_microusd = amount_microusd;
        Ok(true)
    }

    pub(super) fn mark_unknown(&mut self) {
        self.unknown = true;
    }

    pub(super) fn amount_microusd(&self) -> u64 {
        self.amount_microusd
    }

    pub(super) fn is_unknown(&self) -> bool {
        self.unknown
    }

    pub(super) fn has_known_charge_for(
        &self,
        tenant: &iteron_protocol::TenantId,
        run_id: &iteron_protocol::RunId,
        turn: TurnId,
    ) -> bool {
        self.identities.keys().any(|identity| {
            identity.tenant_id == tenant.0
                && identity.run_id == run_id.0
                && identity.turn_id == turn.0
        })
    }
}

#[derive(Debug)]
pub(super) struct ProviderRouteChargeReplay {
    pub(super) ledger: ProviderRouteChargeLedger,
    /// Physical charges already represented by adjacent logical `CostProjected` events. Removing
    /// this exact subset is what prevents the winner from being charged twice on resume.
    pub(super) logical_winner_microusd: u64,
}

#[derive(Debug, Clone)]
struct ReplayedKnownCharge {
    tenant: iteron_protocol::TenantId,
    run_id: iteron_protocol::RunId,
    turn: TurnId,
    projection: CostProjection,
    matched_logical_winner: bool,
}

pub(super) fn route_accounting_id(route_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"iteron-provider-route-attempt-v1\0");
    hasher.update(route_id.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

pub(super) fn route_attempt_identity(
    route_id: &str,
    physical_attempt: u32,
    max_cost_reservation_microusd: Option<u64>,
) -> Result<ProviderRouteAttemptIdentity, KernelError> {
    let identity = ProviderRouteAttemptIdentity {
        version: ProviderRouteAttemptAccountingVersion::V1,
        route_id: route_accounting_id(route_id),
        physical_attempt,
        max_cost_reservation_microusd,
    };
    identity
        .validate()
        .map_err(|reason| KernelError::InvalidRouteMetadata {
            field: "provider_route_attempt",
            reason,
        })?;
    Ok(identity)
}

pub(super) fn crash_recovery_accounting(
    identity: ProviderRouteAttemptIdentity,
) -> ProviderRouteAttemptAccounting {
    ProviderRouteAttemptAccounting::outcome_unobservable(identity)
}

impl Agent {
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
                | iteron_provider::ProviderError::KnownAccountUnavailable { .. },
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
            max_cost_reservation_microusd: self.active_provider_cost_reservation(),
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
            tenant_id: self.rollout.tenant().0.clone(),
            run_id: self.rollout.run_id().0.clone(),
            turn_id: turn.0,
            provider_attempt: physical_attempt,
            attribution: self.projection_attribution.clone(),
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

    /// A positive monetary ceiling must never authorize another physical request after an
    /// earlier request's cost became unknown. The prior terminal is already durable when this is
    /// called, so refusal cannot erase the evidence that closed the gate.
    pub(super) fn admit_followup_after_route_attempt_set(
        &self,
        monetary_followup_safe: bool,
    ) -> Result<(), KernelError> {
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
        if let Some(budget) = &self.usd_budget
            && budget.requires_pricing()
            && budget.active_reservation_microusd().is_none()
        {
            let reservation = self.provider_request_cost_reservation(request)?.ok_or(
                KernelError::PricingLedger(
                    "positive USD followup has no conservative cost reservation",
                ),
            )?;
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

    /// Conservative price for the exact request under the signed active card. The model context
    /// window bounds input; every cache class receives that full bound because adapters disagree
    /// about whether cached tokens are also included in `input`. Output and thinking share one
    /// output ceiling, assigned wholly to the more expensive class.
    pub(super) fn provider_request_cost_reservation(
        &self,
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
        let input_bound =
            self.execution_context_window()
                .ok_or(KernelError::InvalidRouteMetadata {
                    field: "model_context_window",
                    reason: "positive USD admission requires a bounded model context window",
                })?;
        let output_bound = u64::from(request.max_tokens);
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

    /// Make one already-durable physical terminal load-bearing before any retry, fallback, child,
    /// or next logical turn can be admitted. A malformed or unverifiable known amount closes the
    /// shared ceiling; it is never treated as zero and never deferred until the logical winner.
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
            self.rollout.tenant(),
            self.rollout.run_id(),
            turn,
            Some(&self.projection_attribution),
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

    pub(super) fn restore_usd_budget_from_route_receipts(
        &self,
        scoped_events: &[iteron_record::ScopedEvent],
    ) -> Result<(), KernelError> {
        let Some(budget) = &self.usd_budget else {
            return Ok(());
        };
        let replay = replay_route_charges(scoped_events, self.pricing_port.as_deref())?;
        budget
            .restore_provider_route_charges(&self.ledger.cost_state(), replay)
            .map_err(KernelError::PricingLedger)
    }
}

#[derive(Debug)]
enum RouteChargeTruth {
    Known(VerifiedProviderRouteCharge),
    Unknown,
    NotDispatched,
}

fn verified_charge(
    accounting: &ProviderRouteAttemptAccounting,
    tenant: &iteron_protocol::TenantId,
    run_id: &iteron_protocol::RunId,
    turn: TurnId,
    expected_attribution: Option<&Option<iteron_protocol::CostAttribution>>,
    pricing: Option<&dyn iteron_obs::PricingPort>,
) -> Result<RouteChargeTruth, KernelError> {
    accounting
        .validate()
        .map_err(|reason| KernelError::InvalidRouteMetadata {
            field: "provider_route_attempt",
            reason,
        })?;
    match (&accounting.usage, &accounting.cost) {
        (ProviderRouteUsageTruth::NotDispatched, ProviderRouteCostTruth::NotDispatched) => {
            Ok(RouteChargeTruth::NotDispatched)
        }
        (_, ProviderRouteCostTruth::Unknown { .. }) => Ok(RouteChargeTruth::Unknown),
        (
            ProviderRouteUsageTruth::Known { usage },
            ProviderRouteCostTruth::Known {
                amount_microusd,
                rate_card_digest,
                projection: Some(projection),
            },
        ) => {
            let Some(identity) = projection.identity.as_ref() else {
                return Err(KernelError::PricingLedger(
                    "provider route charge proof lacks an authenticated identity",
                ));
            };
            if identity.tenant_id != tenant.0
                || identity.run_id != run_id.0
                || identity.turn_id != turn.0
                || identity.provider_attempt != accounting.physical_attempt
                || expected_attribution.is_some_and(|expected| &identity.attribution != expected)
            {
                return Err(KernelError::PricingLedger(
                    "provider route charge proof has the wrong attempt identity",
                ));
            }
            if route_accounting_id(&format!(
                "{}:{}",
                projection.route.provider_id, projection.route.model_id
            )) != accounting.route_id
                || projection.usage != *usage
                || projection.amount_microusd != *amount_microusd
                || projection.rate_card_digest != *rate_card_digest
            {
                return Err(KernelError::PricingLedger(
                    "provider route charge proof does not match its physical terminal",
                ));
            }
            let Some(pricing) = pricing else {
                return Ok(RouteChargeTruth::Unknown);
            };
            pricing.verify_projection_by_digest(projection)?;
            Ok(RouteChargeTruth::Known(VerifiedProviderRouteCharge {
                identity: identity.clone(),
                projection_digest: projection.projection_digest.clone(),
                amount_microusd: *amount_microusd,
            }))
        }
        (ProviderRouteUsageTruth::Known { .. }, ProviderRouteCostTruth::Known { .. }) => {
            // Historical v1 known summaries remain readable, but an unsigned amount is not a
            // monetary authority and therefore cannot reopen or consume a resumed hard ceiling.
            Ok(RouteChargeTruth::Unknown)
        }
        _ => Err(KernelError::PricingLedger(
            "provider route charge terminal has inconsistent usage/cost truth",
        )),
    }
}

pub(super) fn replay_route_charges(
    scoped_events: &[iteron_record::ScopedEvent],
    pricing: Option<&dyn iteron_obs::PricingPort>,
) -> Result<ProviderRouteChargeReplay, KernelError> {
    let mut ledger = ProviderRouteChargeLedger::default();
    let mut known = Vec::<ReplayedKnownCharge>::new();
    let mut logical = Vec::<(
        iteron_protocol::TenantId,
        iteron_protocol::RunId,
        TurnId,
        CostProjection,
    )>::new();
    let mut saw_typed_terminal = false;
    let mut saw_legacy_provider_terminal = false;

    for scoped in scoped_events {
        if let EventKind::CostProjected { projection } = &scoped.event.kind {
            logical.push((
                scoped.tenant.clone(),
                scoped.run_id.clone(),
                scoped.event.turn,
                projection.clone(),
            ));
        }
        let terminal = match &scoped.event.kind {
            EventKind::EffectDone {
                tool,
                provider_route_attempt,
                ..
            }
            | EventKind::EffectFailed {
                tool,
                provider_route_attempt,
                ..
            }
            | EventKind::EffectUnknown {
                tool,
                provider_route_attempt,
                ..
            } if tool == "provider" => Some(provider_route_attempt),
            _ => None,
        };
        let Some(terminal) = terminal else {
            continue;
        };
        let Some(accounting) = terminal.as_ref() else {
            saw_legacy_provider_terminal = true;
            continue;
        };
        saw_typed_terminal = true;
        match verified_charge(
            accounting,
            &scoped.tenant,
            &scoped.run_id,
            scoped.event.turn,
            None,
            pricing,
        )? {
            RouteChargeTruth::Known(charge) => {
                let projection = match &accounting.cost {
                    ProviderRouteCostTruth::Known {
                        projection: Some(projection),
                        ..
                    } => projection.as_ref().clone(),
                    _ => unreachable!("verified known charge owns its projection"),
                };
                ledger.admit(charge).map_err(KernelError::PricingLedger)?;
                known.push(ReplayedKnownCharge {
                    tenant: scoped.tenant.clone(),
                    run_id: scoped.run_id.clone(),
                    turn: scoped.event.turn,
                    projection,
                    matched_logical_winner: false,
                });
            }
            RouteChargeTruth::Unknown => ledger.mark_unknown(),
            RouteChargeTruth::NotDispatched => {}
        }
    }

    // A partially migrated journal is not legacy: once typed physical receipts exist, a missing
    // sibling receipt is missing monetary truth and closes the ceiling.
    if saw_typed_terminal && saw_legacy_provider_terminal {
        ledger.mark_unknown();
    }
    if !saw_typed_terminal {
        // Purely historical records restore through the already authenticated logical ledger.
        return Ok(ProviderRouteChargeReplay {
            ledger,
            logical_winner_microusd: 0,
        });
    }

    let mut logical_winner_microusd = 0u64;
    for (tenant, run_id, turn, projection) in logical {
        let matched = known.iter_mut().find(|known| {
            !known.matched_logical_winner
                && known.tenant == tenant
                && known.run_id == run_id
                && known.turn == turn
                && known.projection.route == projection.route
                && known.projection.usage == projection.usage
                && known.projection.amount_microusd == projection.amount_microusd
                && known.projection.rate_card_digest == projection.rate_card_digest
        });
        if let Some(matched) = matched {
            matched.matched_logical_winner = true;
            logical_winner_microusd = logical_winner_microusd
                .checked_add(matched.projection.amount_microusd)
                .ok_or(KernelError::PricingLedger(
                    "provider route logical-winner charge total overflowed",
                ))?;
        } else if scoped_events.iter().any(|scoped| {
            scoped.tenant == tenant
                && scoped.run_id == run_id
                && scoped.event.turn == turn
                && matches!(
                    &scoped.event.kind,
                    EventKind::EffectDone {
                        tool,
                        provider_route_attempt: Some(_),
                        ..
                    } | EventKind::EffectFailed {
                        tool,
                        provider_route_attempt: Some(_),
                        ..
                    } | EventKind::EffectUnknown {
                        tool,
                        provider_route_attempt: Some(_),
                        ..
                    } if tool == "provider"
                )
        }) {
            ledger.mark_unknown();
        }
    }

    Ok(ProviderRouteChargeReplay {
        ledger,
        logical_winner_microusd,
    })
}

pub(super) fn not_dispatched_accounting(
    route_id: &str,
    physical_attempt: u32,
) -> Result<ProviderRouteAttemptAccounting, KernelError> {
    let accounting = ProviderRouteAttemptAccounting {
        version: ProviderRouteAttemptAccountingVersion::V1,
        route_id: route_accounting_id(route_id),
        physical_attempt,
        max_cost_reservation_microusd: None,
        usage: ProviderRouteUsageTruth::NotDispatched,
        cost: ProviderRouteCostTruth::NotDispatched,
    };
    accounting
        .validate()
        .map_err(|reason| KernelError::InvalidRouteMetadata {
            field: "provider_route_attempt",
            reason,
        })?;
    Ok(accounting)
}

pub(super) fn monetary_followup_safe(accounting: &ProviderRouteAttemptAccounting) -> bool {
    !matches!(accounting.cost, ProviderRouteCostTruth::Unknown { .. })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_cost_is_never_encoded_as_zero() {
        let receipt = ProviderRouteAttemptAccounting {
            version: ProviderRouteAttemptAccountingVersion::V1,
            route_id: route_accounting_id("provider:model"),
            physical_attempt: 1,
            max_cost_reservation_microusd: None,
            usage: ProviderRouteUsageTruth::Unknown {
                reason: ProviderRouteUsageUnknownReason::ProvenFailureWithoutUsage,
            },
            cost: ProviderRouteCostTruth::Unknown {
                reason: ProviderRouteCostUnknownReason::ProvenFailureWithoutBillingEvidence,
            },
        };
        let value = serde_json::to_value(receipt).expect("serialize typed route receipt");
        assert_eq!(value["cost"]["state"], "unknown");
        assert!(value["cost"].get("amount_microusd").is_none());
    }
}
