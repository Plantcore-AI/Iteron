//! One borrowed physical writer for a coding invocation. Domain journals are sequential
//! reborrows of these same state owners; no second WAL, ledger or terminal observer exists.
#[cfg(test)]
use super::DurableAppendFault;
use super::effect_journal_owner::EffectJournalOwner;
use super::failed_action_cache::FailedActionCache;
use super::policy_evidence_recorder::PolicyEvidenceRecorder;
use super::provider_turn_driver::ProviderTurnJournal;
use super::request_admission_journal::RequestAdmissionJournal;
use super::stream_tool_events::StreamToolEvents;
use super::terminal_record::TerminalRecordOwner;
use super::turn_publication::TurnPublicationOwner;
use iteron_kernel::diagnostics::DiagnosticEmitter;
use iteron_obs::Ledger;
use iteron_record::Rollout;

pub(super) struct CodingExecutionJournal<'a> {
    pub(super) rollout: &'a mut Rollout,
    pub(super) effects: &'a mut EffectJournalOwner,
    pub(super) ledger: &'a mut Ledger,
    pub(super) failed_actions: &'a mut FailedActionCache,
    pub(super) record_failed: &'a mut bool,
    pub(super) diagnostics: &'a DiagnosticEmitter,
    pub(super) policy: &'a mut Option<PolicyEvidenceRecorder>,
    pub(super) terminal: &'a mut TerminalRecordOwner,
    pub(super) publications: &'a mut TurnPublicationOwner,
    #[cfg(test)]
    pub(super) fault: &'a mut Option<DurableAppendFault>,
}
impl CodingExecutionJournal<'_> {
    pub(super) fn hooks<'a>(
        &'a mut self,
        scope: super::hook_execution::HookExecutionScope<'a>,
    ) -> super::hook_execution::HookExecution<'a> {
        super::hook_execution::HookExecution {
            rollout: &mut *self.rollout,
            effects: &mut *self.effects,
            ledger: &mut *self.ledger,
            record_failed: &mut *self.record_failed,
            diagnostics: self.diagnostics,
            #[cfg(test)]
            fault: &mut *self.fault,
            scope,
        }
    }
    pub(super) fn approval(&mut self) -> super::approval_wait::ApprovalJournal<'_> {
        super::approval_wait::ApprovalJournal {
            rollout: &mut *self.rollout,
            ledger: &mut *self.ledger,
            record_failed: &mut *self.record_failed,
            diagnostics: self.diagnostics,
            #[cfg(test)]
            fault: &mut *self.fault,
        }
    }
    pub(super) fn request(&mut self, events: StreamToolEvents) -> RequestAdmissionJournal<'_> {
        RequestAdmissionJournal {
            rollout: &mut *self.rollout,
            ledger: &mut *self.ledger,
            record_failed: &mut *self.record_failed,
            diagnostics: self.diagnostics,
            events,
            #[cfg(test)]
            fault: &mut *self.fault,
        }
    }
    pub(super) fn provider_and_failed(&mut self) -> (ProviderTurnJournal<'_>, &FailedActionCache) {
        (
            ProviderTurnJournal {
                rollout: &mut *self.rollout,
                effects: &mut *self.effects,
                ledger: &mut *self.ledger,
                record_failed: &mut *self.record_failed,
                diagnostics: self.diagnostics,
                policy: self.policy.as_mut(),
                terminal: &mut *self.terminal,
                publications: &mut *self.publications,
                #[cfg(test)]
                fault: &mut *self.fault,
            },
            &*self.failed_actions,
        )
    }
}
