//! Closed provider-governor observation writer. Quota/circuit truth comes from the actual governor;
//! this port cannot append a model selection, provider intent, logical turn or terminal outcome.
#[cfg(test)]
use super::DurableAppendFault;
use super::KernelError;
use iteron_kernel::diagnostics::{DiagnosticEmitter, KernelDiagnostic};
use iteron_obs::Ledger;
use iteron_protocol::{Event, EventKind, Seq, TurnId};
use iteron_provider::{CircuitTransition, RateLimitSnapshot};
use iteron_record::Rollout;
use std::time::Instant;

pub(super) struct ProviderRouteJournal<'a> {
    pub(super) rollout: &'a mut Rollout,
    pub(super) ledger: &'a mut Ledger,
    pub(super) record_failed: &'a mut bool,
    pub(super) diagnostics: &'a DiagnosticEmitter,
    #[cfg(test)]
    pub(super) fault: &'a mut Option<DurableAppendFault>,
}

impl ProviderRouteJournal<'_> {
    pub(super) fn observe(
        &mut self,
        turn: TurnId,
        route_id: &str,
        transition: CircuitTransition,
        quota: Option<RateLimitSnapshot>,
    ) -> Result<(), KernelError> {
        if transition == CircuitTransition::None && quota.is_none() {
            return Ok(());
        }
        let transition = match transition {
            CircuitTransition::None => "none",
            CircuitTransition::Opened => "opened",
            CircuitTransition::HalfOpened => "half_opened",
            CircuitTransition::Closed => "closed",
        };
        let quota = quota.unwrap_or_default();
        let text = serde_json::json!({
            "schema":"iteron-provider-governor-state-v1", "route_id":route_id,
            "circuit_transition":transition, "requests_remaining":quota.requests_remaining,
            "tokens_remaining":quota.tokens_remaining,
            "requests_reset_ms":quota.requests_reset.map(|value|u64::try_from(value.as_millis()).unwrap_or(u64::MAX)),
            "tokens_reset_ms":quota.tokens_reset.map(|value|u64::try_from(value.as_millis()).unwrap_or(u64::MAX)),
        }).to_string();
        #[cfg(test)]
        if *self.fault == Some(DurableAppendFault::Notice) {
            *self.fault = None;
            return Err(
                self.record_error(iteron_record::RecordError::Io(std::io::Error::other(
                    "injected durable append failure",
                ))),
            );
        }
        let started = Instant::now();
        let committed = self.rollout.append(&Event {
            seq: Seq::ZERO,
            turn,
            kind: EventKind::Notice { text },
        });
        self.ledger.record_fsync_latency_us(
            u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
        committed
            .map(|_| ())
            .map_err(|error| self.record_error(error))
    }
    fn record_error(&mut self, error: iteron_record::RecordError) -> KernelError {
        *self.record_failed = true;
        self.diagnostics
            .emit(KernelDiagnostic::RecordAppendFailed {});
        KernelError::Record(error)
    }
}
