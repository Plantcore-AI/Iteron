//! Closed durable selection/card writer. No provider dispatch, financial settlement or policy grant.
#[cfg(test)]
use super::DurableAppendFault;
use super::KernelError;
use iteron_kernel::diagnostics::{DiagnosticEmitter, KernelDiagnostic};
use iteron_obs::Ledger;
use iteron_protocol::{Event, EventKind, PricingRoute, Seq, SignedRateCard, TurnId};
use iteron_record::{RecordError, Rollout};
use std::time::Instant;

pub(super) struct ProviderSelectionJournal<'a> {
    pub(super) rollout: &'a mut Rollout,
    pub(super) ledger: &'a mut Ledger,
    pub(super) record_failed: &'a mut bool,
    pub(super) diagnostics: &'a DiagnosticEmitter,
    #[cfg(test)]
    pub(super) fault: &'a mut Option<DurableAppendFault>,
}
impl ProviderSelectionJournal<'_> {
    pub(super) fn select(&mut self, turn: TurnId, route: &PricingRoute) -> Result<(), KernelError> {
        self.append(
            turn,
            EventKind::ModelSelected {
                provider_id: route.provider_id.clone(),
                model_id: route.model_id.clone(),
                catalog_digest: route.catalog_digest.clone(),
                capability_digest: route.capability_digest.clone(),
            },
        )
    }
    pub(super) fn bind(&mut self, turn: TurnId, card: &SignedRateCard) -> Result<(), KernelError> {
        self.append(
            turn,
            EventKind::RateCardBound {
                rate_card: card.clone(),
            },
        )
    }
    fn append(&mut self, turn: TurnId, kind: EventKind) -> Result<(), KernelError> {
        #[cfg(test)]
        if matches!(
            (*self.fault, &kind),
            (
                Some(DurableAppendFault::ModelSelected),
                EventKind::ModelSelected { .. }
            ) | (
                Some(DurableAppendFault::RateCardBound),
                EventKind::RateCardBound { .. }
            )
        ) {
            *self.fault = None;
            return Err(self.record_error(RecordError::Io(std::io::Error::other(
                "injected durable selection append refusal",
            ))));
        }
        let started = Instant::now();
        let result = self.rollout.append(&Event {
            seq: Seq::ZERO,
            turn,
            kind,
        });
        self.ledger.record_fsync_latency_us(
            u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
        result.map(|_| ()).map_err(|error| self.record_error(error))
    }
    fn record_error(&mut self, error: RecordError) -> KernelError {
        *self.record_failed = true;
        self.diagnostics
            .emit(KernelDiagnostic::RecordAppendFailed {});
        KernelError::Record(error)
    }
}
