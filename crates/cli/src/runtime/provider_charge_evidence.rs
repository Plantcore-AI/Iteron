//! Durable usage/cost truth for each physical provider route attempt.
//!
//! `TurnEnd` accounts for the eventual logical turn. It cannot describe a failed primary request
//! followed by a successful fallback, so every provider effect terminal carries this smaller
//! content-free receipt as well. Unknown billing is explicit and closes a positive USD ceiling
//! before any retry or fallback can dispatch.

use super::KernelError;
use iteron_protocol::{
    CostProjection, CostProjectionIdentity, ProviderRouteAttemptAccounting,
    ProviderRouteAttemptAccountingVersion, ProviderRouteAttemptIdentity, ProviderRouteCostTruth,
    ProviderRouteUsageTruth,
};
use iteron_protocol::{EventKind, TurnId};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

#[path = "route_attempt_accounting/replay_evidence.rs"]
pub(super) mod replay_evidence;

/// Exact, idempotent monetary commits for physical provider attempts.
///
/// This is deliberately separate from the logical-turn ledger. A retry or fallback may have
/// consumed money even though only the eventual winner owns `TurnEnd`; charging that winner again
/// would be equally wrong. The signed projection identity is the durable idempotency key.
#[derive(Debug, Default, Clone)]
pub(super) struct ProviderRouteChargeLedger {
    identities: HashMap<CostProjectionIdentity, String>,
    charges: HashMap<CostProjectionIdentity, VerifiedProviderRouteCharge>,
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
    pub(super) fn contains_exact(
        &self,
        charge: &VerifiedProviderRouteCharge,
    ) -> Result<bool, &'static str> {
        match self.charges.get(&charge.identity) {
            Some(prior)
                if prior.projection_digest == charge.projection_digest
                    && prior.amount_microusd == charge.amount_microusd =>
            {
                Ok(true)
            }
            Some(_) => Err("provider route identity conflicts with its exact physical charge"),
            None => Ok(false),
        }
    }
    pub(super) fn verified_charges(&self) -> impl Iterator<Item = &VerifiedProviderRouteCharge> {
        self.charges.values()
    }
    pub(super) fn admit(
        &mut self,
        charge: VerifiedProviderRouteCharge,
    ) -> Result<bool, &'static str> {
        if self.charges.len() >= 65_536 && !self.charges.contains_key(&charge.identity) {
            self.unknown = true;
            return Err("provider charge identity capacity exhausted");
        }
        if let Some(existing) = self.identities.get(&charge.identity) {
            return if existing == &charge.projection_digest && self.contains_exact(&charge)? {
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
        self.charges.insert(charge.identity.clone(), charge.clone());
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

#[derive(Debug)]
pub(super) enum RouteChargeTruth {
    Known(VerifiedProviderRouteCharge),
    Unknown,
    NotDispatched,
}

pub(super) fn verified_charge(
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
    let evidence = replay_evidence::ProviderReplayEvidence::inspect(scoped_events);
    if evidence.has_unknown() {
        // An intent without a matching physical terminal is missing billing evidence, including
        // the crash window before the optional controller reservation itself was appended.
        ledger.mark_unknown();
    }
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
        let sealed_turn = scoped_events.iter().any(|row| {
            row.tenant == tenant
                && row.run_id == run_id
                && row.event.turn == turn
                && matches!(&row.event.kind, EventKind::EffectIntent {tool,arguments,..}
                if tool == "provider" && arguments.get("provider_pricing_at_unix_secs").is_some())
        });
        let matched = known.iter_mut().find(|known| {
            !known.matched_logical_winner
                && known.tenant == tenant
                && known.run_id == run_id
                && known.turn == turn
                && known.projection.route == projection.route
                && known.projection.usage == projection.usage
                && known.projection.amount_microusd == projection.amount_microusd
                && known.projection.rate_card_digest == projection.rate_card_digest
                && (!sealed_turn || known.projection == projection)
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
#[path = "provider_charge_evidence_tests.rs"]
mod tests;
