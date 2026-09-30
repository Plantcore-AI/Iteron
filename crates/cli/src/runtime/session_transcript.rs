//! One owner for the resident transcript returned by a run and its staged successor. Durable
//! intake commits before consuming a restored projection; a failed writer preserves that state.
#[cfg(test)]
use super::DurableAppendFault;
use super::KernelError;
use super::task_plan::TaskPlanOwner;
use super::transcript::merge_adjacent_user_message;
use super::turn_publication::TurnPublicationOwner;
use iteron_kernel::diagnostics::{DiagnosticEmitter, KernelDiagnostic};
use iteron_obs::Ledger;
use iteron_protocol::{Event, EventKind, Message, Seq, TurnId};
use iteron_record::{RecordError, Rollout};
use std::time::Instant;

#[derive(Default)]
pub(super) struct SessionTranscriptOwner {
    restored: Option<Vec<Message>>,
    working: Option<Vec<Message>>,
}

pub(super) struct TranscriptAdmissionJournal<'a> {
    pub(super) rollout: &'a mut Rollout,
    pub(super) ledger: &'a mut Ledger,
    pub(super) record_failed: &'a mut bool,
    pub(super) diagnostics: &'a DiagnosticEmitter,
    pub(super) publications: &'a mut TurnPublicationOwner,
    #[cfg(test)]
    pub(super) fault: &'a mut Option<DurableAppendFault>,
}

impl SessionTranscriptOwner {
    pub(super) fn restored(&self) -> &Option<Vec<Message>> {
        &self.restored
    }

    pub(super) fn working(&self) -> &Option<Vec<Message>> {
        &self.working
    }

    pub(super) fn take_working(&mut self) -> Option<Vec<Message>> {
        self.working.take()
    }

    pub(super) fn replace_restored(&mut self, messages: Option<Vec<Message>>) {
        if messages.is_some() {
            self.working = None;
        }
        self.restored = messages;
    }

    pub(super) fn replace_working(&mut self, messages: Option<Vec<Message>>) {
        if messages.is_some() {
            self.restored = None;
        }
        self.working = messages;
    }

    /// Existing verified projection enters as staged state. Only a real new instruction is
    /// recorded; empty recovery preserves the exact recorded transcript and creates no input.
    pub(super) fn admit_submission(
        &mut self,
        turn: TurnId,
        task: &str,
        journal: &mut TranscriptAdmissionJournal<'_>,
        plan: &mut TaskPlanOwner,
    ) -> Result<Vec<Message>, KernelError> {
        let new_instruction = self.restored.is_none() || !task.trim().is_empty();
        let instruction = new_instruction.then(|| Message::user_text(task));
        if let Some(instruction) = &instruction {
            let receipt = journal.message(turn, instruction.clone())?;
            plan.observe_submission(receipt);
        }
        // Do not take this state before a fallible append. A later caller can still inspect or
        // continue the identical restored projection after a predispatch refusal.
        let mut messages = self.restored.take().unwrap_or_default();
        if let Some(instruction) = instruction {
            merge_adjacent_user_message(&mut messages, instruction);
        }
        Ok(messages)
    }
}

impl TranscriptAdmissionJournal<'_> {
    fn message(&mut self, turn: TurnId, message: Message) -> Result<Seq, KernelError> {
        if *self.record_failed {
            return Err(KernelError::Record(RecordError::Io(std::io::Error::other(
                "transcript writer is unavailable",
            ))));
        }
        #[cfg(test)]
        if *self.fault == Some(DurableAppendFault::SteerMessage) {
            *self.fault = None;
            return Err(self.record_error(RecordError::Io(std::io::Error::other(
                "injected durable message append refusal",
            ))));
        }
        let mut event = Event {
            seq: Seq::ZERO,
            turn,
            kind: EventKind::Message { message },
        };
        let started = Instant::now();
        let committed = self.rollout.append(&event);
        self.ledger.record_fsync_latency_us(
            u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
        match committed {
            Ok(sequence) => {
                event.seq = sequence;
                self.publications.observe_committed(&event);
                Ok(sequence)
            }
            Err(error) => Err(self.record_error(error)),
        }
    }

    fn record_error(&mut self, error: RecordError) -> KernelError {
        *self.record_failed = true;
        self.diagnostics
            .emit(KernelDiagnostic::RecordAppendFailed {});
        KernelError::Record(error)
    }
}

#[cfg(all(test, unix))]
#[path = "session_transcript_tests.rs"]
mod tests;
