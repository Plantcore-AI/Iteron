//! Physical provider WAL adapter. The one effect owner and Rollout writer remain authoritative;
//! signed financial admission follows intent, and controller settlement follows terminal sync.
#[cfg(test)]
use super::DurableAppendFault;
use super::KernelError;
use super::effect_descriptor::effect_workspace;
use super::effect_journal_owner::{EffectJournalOwner, UnknownCause};
use super::provider_charge_evidence::{monetary_followup_safe, route_attempt_identity};
use super::provider_financial_context::ProviderFinancialContext;
use super::provider_route::provider_settlement;
use iteron_kernel::diagnostics::{DiagnosticEmitter, KernelDiagnostic};
use iteron_kernel::{effect_class, effects};
use iteron_obs::Ledger;
use iteron_protocol::{Capability, EventKind, ProviderRouteAttemptAccounting, TurnId};
use iteron_record::Rollout;
use std::{path::Path, time::Instant};

pub(super) struct ProviderAttemptJournal<'a> {
    pub(super) rollout: &'a mut Rollout,
    pub(super) effects: &'a mut EffectJournalOwner,
    pub(super) ledger: &'a mut Ledger,
    pub(super) record_failed: &'a mut bool,
    pub(super) diagnostics: &'a DiagnosticEmitter,
    pub(super) financial: ProviderFinancialContext,
    pub(super) pricing_now: u64,
    #[cfg(test)]
    pub(super) fault: &'a mut Option<DurableAppendFault>,
}

pub(super) struct ProviderIntent {
    pub(super) turn: TurnId,
    pub(super) ordinal: usize,
    pub(super) capability: Capability,
    pub(super) audit: serde_json::Value,
}

pub(super) struct ProviderObservedAttempt<'a> {
    pub(super) route_id: &'a str,
    pub(super) physical_attempt: u32,
    pub(super) ordinal: usize,
    pub(super) result: &'a Result<iteron_provider::TurnResult, KernelError>,
    pub(super) projected_at_unix_secs: u64,
}

impl ProviderAttemptJournal<'_> {
    pub(super) fn open(
        &mut self,
        workspace: &Path,
        intent: ProviderIntent,
    ) -> Result<effects::EffectTicket, KernelError> {
        let ProviderIntent {
            turn,
            ordinal,
            capability,
            mut audit,
        } = intent;
        let route_id = audit
            .get("route_id")
            .and_then(serde_json::Value::as_str)
            .ok_or(KernelError::InvalidRouteMetadata {
                field: "provider_route_attempt.route_id",
                reason: "provider effect audit projection omitted the selected route",
            })?;
        let physical = audit
            .get("physical_attempt")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(KernelError::InvalidRouteMetadata {
                field: "provider_route_attempt.physical_attempt",
                reason: "provider effect audit projection omitted a bounded physical ordinal",
            })?;
        let bounds = self.financial.cohort_bounds(
            route_id,
            audit
                .get("max_tokens")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            self.pricing_now,
        )?;
        let identity = route_attempt_identity(
            route_id,
            physical,
            bounds
                .map(|(_, cost)| cost)
                .or_else(|| self.financial.active_provider_cost_reservation()),
        )?;
        // Only the typed hashed route identity is durable. Raw provider/model strings are not
        // allowed to create a second projection carrying operator paths or credential material.
        if let Some(arguments) = audit.as_object_mut() {
            arguments.remove("route_id");
            arguments.remove("model");
        }
        #[cfg(test)]
        self.inject_intent_failure()?;
        let class = effect_class::EffectClass::Provider;
        let started = Instant::now();
        let opened = self.effects.open(
            self.rollout,
            effects::BrokeredEffect {
                turn,
                effect_id: effect_class::effect_id(turn, class, ordinal),
                tool_use_id: effect_class::harness_correlation_id(turn, class, ordinal),
                kind: "provider".into(),
                capability,
                audit_arguments: audit,
                workspace: effect_workspace(workspace),
                provider_route_attempt: Some(identity.clone()),
            },
        );
        self.measure(started);
        let ticket = opened.map_err(|error| self.boundary_error(error))?;
        if let Some((tokens, _)) = bounds
            && let Err(error) =
                self.financial
                    .reserve_cohort(turn, ticket.effect_id(), &identity, tokens)
        {
            let id = ticket.effect_id().clone();
            let accounting = ProviderRouteAttemptAccounting {
                version: identity.version,
                route_id: identity.route_id,
                physical_attempt: identity.physical_attempt,
                max_cost_reservation_microusd: None,
                usage: iteron_protocol::ProviderRouteUsageTruth::NotDispatched,
                cost: iteron_protocol::ProviderRouteCostTruth::NotDispatched,
            };
            let closed = self.settle(
                ticket,
                effects::Settlement::Definite(EventKind::EffectFailed {
                    id,
                    tool: "provider".into(),
                    reason: "persistent budget refused before dispatch".into(),
                    duration_ms: None,
                    provider_route_attempt: Some(accounting),
                }),
                UnknownCause::Unobserved,
            );
            self.financial.settle_usd_not_dispatched();
            closed?;
            return Err(error);
        }
        Ok(ticket)
    }

    pub(super) fn settle_observed(
        &mut self,
        ticket: effects::EffectTicket,
        observed: ProviderObservedAttempt<'_>,
    ) -> Result<(ProviderRouteAttemptAccounting, bool), KernelError> {
        let accounting = self.financial.route_attempt_accounting(
            ticket.turn(),
            observed.route_id,
            observed.physical_attempt,
            observed.result,
            observed.projected_at_unix_secs,
        )?;
        let safe = monetary_followup_safe(&accounting);
        let settlement = provider_settlement(
            ticket.turn(),
            observed.ordinal,
            observed.result,
            accounting.clone(),
        );
        self.settle(ticket, settlement, UnknownCause::Unobserved)?;
        Ok((accounting, safe))
    }

    /// Even unavailable financial evidence cannot prevent the actual physical terminal append.
    /// A failed WAL terminal retains an admitted bound and sends Unknown to the cohort owner.
    pub(super) fn settle(
        &mut self,
        ticket: effects::EffectTicket,
        settlement: effects::Settlement,
        cause: UnknownCause,
    ) -> Result<(), KernelError> {
        let turn = ticket.turn();
        let id = ticket.effect_id().clone();
        let identity = ticket.provider_route_attempt().cloned();
        let accounting = identity.as_ref().map(|identity| match &settlement {
            effects::Settlement::Definite(
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
                },
            ) => accounting.clone(),
            _ => ProviderRouteAttemptAccounting::outcome_unobservable(identity.clone()),
        });
        let started = Instant::now();
        let committed = self.effects.settle(self.rollout, ticket, settlement, cause);
        self.measure(started);
        match committed {
            Ok(()) => {
                if let Some(accounting) = accounting {
                    self.financial.settle_cohort(turn, &id, &accounting)?;
                }
                Ok(())
            }
            Err(error) => {
                if let Some(identity) = identity {
                    let _ = self.financial.settle_cohort(
                        turn,
                        &id,
                        &ProviderRouteAttemptAccounting::outcome_unobservable(identity),
                    );
                }
                Err(self.boundary_error(error))
            }
        }
    }

    pub(super) fn commit_usd(
        &self,
        turn: TurnId,
        accounting: &ProviderRouteAttemptAccounting,
    ) -> Result<(), KernelError> {
        self.financial
            .commit_provider_route_charge(turn, accounting)
    }

    pub(super) fn measure_broker(&mut self, started: Instant) {
        self.ledger.record_broker_latency_us(
            u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
    }
    fn measure(&mut self, started: Instant) {
        self.ledger.record_fsync_latency_us(
            u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
    }
    fn boundary_error(&mut self, error: effects::BrokerError) -> KernelError {
        match error {
            effects::BrokerError::Record(error) => self.record_error(error),
            other => KernelError::EffectBoundary(other.to_string()),
        }
    }
    fn record_error(&mut self, error: iteron_record::RecordError) -> KernelError {
        *self.record_failed = true;
        self.diagnostics
            .emit(KernelDiagnostic::RecordAppendFailed {});
        KernelError::Record(error)
    }
    #[cfg(test)]
    fn inject_intent_failure(&mut self) -> Result<(), KernelError> {
        if *self.fault == Some(DurableAppendFault::EffectIntent) {
            *self.fault = None;
            return Err(
                self.record_error(iteron_record::RecordError::Io(std::io::Error::other(
                    "injected durable effect-intent append failure",
                ))),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "provider_attempt_journal_tests.rs"]
mod tests;
