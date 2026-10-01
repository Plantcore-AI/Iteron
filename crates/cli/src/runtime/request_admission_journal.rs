//! Actual bounded model-phase observation and token ledger. It owns no provider, capability,
//! transcript or durable effect admission; the next authoritative journal barrier flushes it.
#[cfg(test)]
use super::DurableAppendFault;
use super::KernelError;
use super::frontend_events::UiEvent;
use super::stream_tool_events::StreamToolEvents;
use iteron_kernel::diagnostics::{DiagnosticEmitter, KernelDiagnostic};
use iteron_obs::Ledger;
use iteron_protocol::{Event, EventKind, Phase, Seq, TurnId};
use iteron_record::{RecordError, Rollout};
use std::time::Instant;

pub(super) struct RequestAdmissionJournal<'a> {
    pub(super) rollout: &'a mut Rollout,
    pub(super) ledger: &'a mut Ledger,
    pub(super) record_failed: &'a mut bool,
    pub(super) diagnostics: &'a DiagnosticEmitter,
    pub(super) events: StreamToolEvents,
    #[cfg(test)]
    pub(super) fault: &'a mut Option<DurableAppendFault>,
}

impl RequestAdmissionJournal<'_> {
    pub(super) fn model_phase(&mut self, turn: TurnId) -> Result<(), KernelError> {
        if *self.record_failed {
            return Err(KernelError::Record(RecordError::Io(std::io::Error::other(
                "model preparation requires an available record writer",
            ))));
        }
        #[cfg(test)]
        if *self.fault == Some(DurableAppendFault::BestEffort) {
            *self.fault = None;
            return Err(self.failed(RecordError::Io(std::io::Error::other(
                "injected model phase observation refusal",
            ))));
        }
        let started = Instant::now();
        let result = self.rollout.queue_observation(Event {
            seq: Seq::ZERO,
            turn,
            kind: EventKind::Phase {
                phase: Phase::Model,
            },
        });
        match result {
            Ok(flushed) => {
                if flushed {
                    self.ledger
                        .record_fsync_latency_us(super::provider_accounting::elapsed_us(started));
                }
                self.events.present(UiEvent::Phase(Phase::Model));
                Ok(())
            }
            Err(error) => Err(self.failed(error)),
        }
    }
    pub(super) fn record_kernel_tokens(&mut self, tokens: usize) {
        self.ledger
            .record_kernel_tokens(u64::try_from(tokens).unwrap_or(u64::MAX));
    }
    fn failed(&mut self, error: RecordError) -> KernelError {
        *self.record_failed = true;
        self.diagnostics
            .emit(KernelDiagnostic::RecordAppendFailed {});
        KernelError::Record(error)
    }
}
