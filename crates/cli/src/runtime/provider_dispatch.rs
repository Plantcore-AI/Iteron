//! Actual initial/retry physical admission coordinator. Its consumed journal/scope lifetime
//! orders namespace identity, provider intent and logical-start barriers before IO. Mailbox
//! consumption belongs to the actual native prepared-request proof, after serialization.
//! Transport, route selection and financial ledgers retain their separate owners.
#[cfg(test)]
use super::DurableAppendFault;
use super::KernelError;
use super::effect_journal_owner::UnknownCause;
use super::policy_evidence_recorder::PolicyEvidenceRecorder;
use super::provider_attempt_journal::{ProviderAttemptJournal, ProviderIntent};
use super::provider_extension::{self, ProviderDispatchExtension};
use super::provider_route_events::ProviderRouteEvents;
use super::provider_route_turn::ProviderRouteTurn;
use super::session_control::SessionControlState;
use super::terminal_record::TerminalRecordOwner;
use super::turn_publication::TurnPublicationOwner;
use iteron_kernel::diagnostics::KernelDiagnostic;
use iteron_kernel::{effect_class, effects};
use iteron_protocol::{
    Capability, Event, EventKind, LifecyclePayload, ProviderRouteAttemptAccounting,
    ProviderRouteCostTruth, ProviderRouteUsageTruth, Seq, TurnId,
};
use std::path::Path;
use std::time::Instant;

#[cfg(all(test, unix))]
#[path = "provider_dispatch_tests.rs"]
mod tests;

pub(super) struct ProviderAdmissionJournal<'a> {
    pub(super) physical: ProviderAttemptJournal<'a>,
    pub(super) terminal: &'a mut TerminalRecordOwner,
    pub(super) policy: Option<&'a mut PolicyEvidenceRecorder>,
    pub(super) publications: &'a mut TurnPublicationOwner,
}
pub(super) struct ProviderDispatchScope<'a> {
    pub(super) workspace: &'a Path,
    pub(super) extension: Option<&'a dyn ProviderDispatchExtension>,
    pub(super) events: &'a ProviderRouteEvents,
    pub(super) control: &'a SessionControlState,
    pub(super) deadline: Option<Instant>,
    #[cfg(test)]
    pub(super) pricing_now_unix_secs: Option<u64>,
}
pub(super) struct ProviderObjectiveEvidence {
    pub(super) score: Option<u32>,
    pub(super) digest: Option<String>,
}
pub(super) struct ProviderDispatchOwner<'a> {
    pub(super) journal: ProviderAdmissionJournal<'a>,
    pub(super) scope: ProviderDispatchScope<'a>,
}

impl ProviderDispatchOwner<'_> {
    /// The governor/USD gate has already admitted this request. This consumes the concrete
    /// local barrier lifetime; no later caller can re-enter it with the same opened ticket.
    pub(super) async fn initial(
        mut self,
        route: &mut ProviderRouteTurn,
        mut refusal: Option<KernelError>,
        hedged: bool,
        objective: ProviderObjectiveEvidence,
    ) -> Result<Option<KernelError>, KernelError> {
        if route.ticket().is_some() || !route.first_attempt() {
            return Err(KernelError::EffectBoundary(
                "initial provider admission is already consumed".into(),
            ));
        }
        if refusal.is_none() && !hedged {
            match provider_extension::enter_dispatch(self.scope.extension).await {
                Ok(permit) => route.assign_dispatch_permit(permit),
                Err(()) => refusal = Some(iteron_provider::ProviderError::Interrupted.into()),
            }
        }
        if refusal.is_some() {
            self.release_zero(route);
        }
        self.scope.events.emit(
            if refusal.is_some() {
                "model.route_rejected"
            } else {
                "model.route_selected"
            },
            LifecyclePayload {
                reason_code: refusal.as_ref().map(|_| "provider_dispatch_refused".into()),
                ..LifecyclePayload::default()
            },
        );
        if refusal.is_some() || hedged {
            return Ok(refusal);
        }
        if let Err(error) = self.open(route, objective) {
            self.release_zero(route);
            return Err(error);
        }
        if let Err(error) = self.journal.begin(self.scope.events.turn) {
            let settled = self.close_zero(
                route,
                "logical provider turn could not become durable before dispatch",
            );
            self.release_zero(route);
            settled?;
            return Err(error);
        }
        Ok(None)
    }

    /// Retry/fallback wait, route activation and real governor admission already completed.
    /// A fresh recovered physical identity is required; the logical-start prefix is retained.
    pub(super) async fn followup(
        mut self,
        route: &mut ProviderRouteTurn,
        hedged: bool,
        objective: ProviderObjectiveEvidence,
    ) -> Result<(), KernelError> {
        if route.ticket().is_some() || route.first_attempt() {
            // An unrelated pending effect is never refunded or labelled zero by this adapter.
            return Err(KernelError::EffectBoundary(
                "provider followup lacks a settled predecessor".into(),
            ));
        }
        if hedged {
            return Ok(());
        }
        match provider_extension::enter_dispatch(self.scope.extension).await {
            Ok(permit) => route.assign_dispatch_permit(permit),
            Err(()) => {
                self.release_zero(route);
                return Err(iteron_provider::ProviderError::Interrupted.into());
            }
        }
        if let Some(error) = self.scope.control.provider_refusal(self.scope.deadline) {
            self.release_zero(route);
            return Err(error);
        }
        if let Err(error) = self
            .journal
            .physical
            .financial
            .reserve_provider_followup_if_needed(route.provider().as_ref(), route.request())
        {
            self.release_zero(route);
            return Err(error);
        }
        if let Err(error) = self.open(route, objective) {
            self.release_zero(route);
            return Err(error);
        }
        Ok(())
    }

    fn open(
        &mut self,
        route: &mut ProviderRouteTurn,
        objective: ProviderObjectiveEvidence,
    ) -> Result<(), KernelError> {
        if route.ticket().is_some() {
            return Err(KernelError::EffectBoundary(
                "provider intent is already owned".into(),
            ));
        }
        let turn = self.scope.events.turn;
        let ordinal = self
            .journal
            .physical
            .effects
            .next_ordinal(turn, effect_class::EffectClass::Provider);
        let physical =
            super::provider_effect_identity::physical_attempt_for_provider_ordinal(ordinal)?;
        route.assign_identity(ordinal, physical);
        #[cfg(test)]
        let now = self
            .scope
            .pricing_now_unix_secs
            .unwrap_or_else(super::provider_accounting::unix_now_secs);
        #[cfg(not(test))]
        let now = super::provider_accounting::unix_now_secs();
        self.journal.physical.pricing_now = now;
        let started = Instant::now();
        let ticket = self.journal.physical.open(self.scope.workspace, ProviderIntent {
            turn, ordinal, capability: Capability::IrreversibleExternal,
            audit: serde_json::json!({
                "model": route.request().model, "route_id": route.route_id(),
                "route_transition": route.transition(), "messages": route.request().messages.len(),
                "tools": route.request().tools.len(), "max_tokens": route.request().max_tokens,
                "requested_max_tokens": route.requested_max_tokens(),
                "physical_attempt": route.physical_attempt(), "route_retry_index": route.retry_index(),
                "route_objective_score_millionths": objective.score,
                "route_objective_evidence": objective.digest,
            }),
        })?;
        self.journal.physical.measure_broker(started);
        route.assign_ticket(Some(ticket));
        Ok(())
    }
    fn close_zero(
        &mut self,
        route: &mut ProviderRouteTurn,
        reason: &'static str,
    ) -> Result<(), KernelError> {
        let Some(ticket) = route.take_ticket() else {
            return Ok(());
        };
        let identity = ticket.provider_route_attempt().ok_or_else(|| {
            KernelError::EffectBoundary("opened provider ticket lacks its admitted identity".into())
        })?;
        let accounting = ProviderRouteAttemptAccounting {
            version: identity.version,
            route_id: identity.route_id.clone(),
            physical_attempt: identity.physical_attempt,
            max_cost_reservation_microusd: None,
            usage: ProviderRouteUsageTruth::NotDispatched,
            cost: ProviderRouteCostTruth::NotDispatched,
        };
        let id = ticket.effect_id().clone();
        self.journal.physical.settle(
            ticket,
            effects::Settlement::Definite(EventKind::EffectFailed {
                id,
                tool: "provider".into(),
                reason: reason.into(),
                duration_ms: None,
                provider_route_attempt: Some(accounting),
            }),
            UnknownCause::Unobserved,
        )
    }
    fn release_zero(&mut self, route: &mut ProviderRouteTurn) {
        drop(route.take_route_permit());
        drop(route.take_dispatch_permit());
        self.journal.physical.financial.settle_usd_not_dispatched();
    }
}

impl ProviderAdmissionJournal<'_> {
    fn begin(&mut self, turn: TurnId) -> Result<(), KernelError> {
        if *self.physical.record_failed {
            return Err(
                self.record_error(iteron_record::RecordError::Io(std::io::Error::other(
                    "logical provider admission record is unavailable",
                ))),
            );
        }
        #[cfg(test)]
        if *self.physical.fault == Some(DurableAppendFault::TurnStart) {
            *self.physical.fault = None;
            return Err(
                self.record_error(iteron_record::RecordError::Io(std::io::Error::other(
                    "injected durable turn-start append refusal",
                ))),
            );
        }
        let started_at_us = self.physical.rollout.segment_elapsed_us();
        let mut event = Event {
            seq: Seq::ZERO,
            turn,
            kind: EventKind::TurnStart,
        };
        let started = Instant::now();
        let committed = self.physical.rollout.append(&event);
        self.physical
            .ledger
            .record_fsync_latency_us(super::provider_accounting::elapsed_us(started));
        event.seq = committed.map_err(|error| self.record_error(error))?;
        self.publications.observe_committed(&event);
        if let Some(policy) = self.policy.as_mut() {
            self.terminal
                .observe_start(policy, turn, started_at_us, self.physical.ledger);
        }
        self.physical.ledger.attempt();
        Ok(())
    }
    fn record_error(&mut self, error: iteron_record::RecordError) -> KernelError {
        *self.physical.record_failed = true;
        self.physical
            .diagnostics
            .emit(KernelDiagnostic::RecordAppendFailed {});
        KernelError::Record(error)
    }
}
