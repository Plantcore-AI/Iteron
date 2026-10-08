//! Concrete completion safe-point ports. These borrow only transcript/control/verification
//! owners; no provider, arbitrary tool executor, session proxy or callback is available.
use super::KernelError;
use super::approval_wait::ApprovalJournal;
use super::bounded_verify::VerificationTaskRegistry;
use super::control_ingress::ControlIngress;
use super::effect_journal_owner::EffectJournalOwner;
use super::force_cancel::ForceCancelSeam;
use super::memory_request_exposure::MemoryVisibilityOwner;
use super::permission_transaction::PermissionTransaction;
use super::policy_evidence_recorder::PolicyEvidenceRecorder;
use super::pricing::SharedUsdBudget;
use super::session_control::{InboundControl, SessionControlState};
use super::session_inbox::SessionSubmissionInbox;
use super::session_transcript::TranscriptAdmissionJournal;
use super::steering_admission::{SteeringAdmission, SteeringScope};
use super::stream_tool_events::StreamToolEvents;
use super::strong_verification::{
    StrongVerificationGate, VerificationGateDisposition, VerificationScope,
};
use super::task_plan::TaskPlanOwner;
use super::terminal_record::TerminalRecordOwner;
use super::verification_journal::{VerificationJournal, VerificationPolicyBootstrap};
use super::verification_state::VerificationStateOwner;
use super::workspace_checkpoint::WorkspaceCheckpointOwner;
use iteron_ctx::RequestEstimator;
use iteron_protocol::{Block, EventKind, Message, Role, Trust};
use std::sync::Arc;
use std::time::Instant;

pub(super) struct CompletionJournal<'a> {
    pub(super) transcript: TranscriptAdmissionJournal<'a>,
    pub(super) effects: &'a mut EffectJournalOwner,
    pub(super) policy: &'a mut Option<PolicyEvidenceRecorder>,
    pub(super) terminal: &'a mut TerminalRecordOwner,
    pub(super) checkpoints: &'a mut WorkspaceCheckpointOwner,
}
pub(super) struct CompletionInput<'a> {
    pub(super) scope: SteeringScope<'a>,
    pub(super) inbox: &'a mut SessionSubmissionInbox,
    pub(super) control: &'a mut SessionControlState,
    pub(super) force_cancel: Option<&'a mut ForceCancelSeam>,
    pub(super) estimator: &'a mut RequestEstimator,
    pub(super) plan: &'a mut TaskPlanOwner,
    pub(super) trust: &'a mut Trust,
    pub(super) visibility: &'a mut MemoryVisibilityOwner,
}
/// Constructed only when the operator already configured verification. The ordinary path owns
/// None and performs no verifier scope/task/permission/bootstrap construction.
pub(super) struct CompletionVerification<'a> {
    pub(super) command: String,
    pub(super) scope: VerificationScope<'a>,
    pub(super) state: &'a mut VerificationStateOwner,
    pub(super) tasks: Arc<VerificationTaskRegistry>,
    pub(super) approval_sequence: &'a mut u64,
    pub(super) permission: PermissionTransaction<'a>,
    pub(super) bootstrap: Option<VerificationPolicyBootstrap>,
}
pub(super) struct CompletionBudget {
    pub(super) tokens: Option<u64>,
    pub(super) usd: Option<Arc<SharedUsdBudget>>,
    pub(super) deadline: Option<Instant>,
}
pub(super) struct CompletionSession<'a> {
    pub(super) journal: CompletionJournal<'a>,
    pub(super) input: CompletionInput<'a>,
    pub(super) verification: Option<CompletionVerification<'a>>,
    pub(super) budget: CompletionBudget,
}
impl CompletionSession<'_> {
    pub(super) fn poll(&mut self) -> InboundControl {
        let turn = self.input.scope.turn;
        ControlIngress {
            journal: ApprovalJournal {
                rollout: &mut *self.journal.transcript.rollout,
                ledger: &mut *self.journal.transcript.ledger,
                record_failed: &mut *self.journal.transcript.record_failed,
                diagnostics: self.journal.transcript.diagnostics,
                #[cfg(test)]
                fault: &mut *self.journal.transcript.fault,
            },
            inbox: &mut *self.input.inbox,
            control: &mut *self.input.control,
            force_cancel: self.input.force_cancel.as_deref_mut(),
            events: self.input.scope.events.clone(),
        }
        .poll(turn, super::inbound_control::inbound_poll_limit());
        self.input.control.requested()
    }
    pub(super) fn admit_steering(
        &mut self,
        messages: &mut Vec<Message>,
    ) -> Result<usize, KernelError> {
        self.poll();
        SteeringAdmission {
            scope: SteeringScope {
                turn: self.input.scope.turn,
                registry: self.input.scope.registry,
                mailbox: self.input.scope.mailbox,
                memory_workspace: self.input.scope.memory_workspace,
                max_bytes: self.input.scope.max_bytes,
                events: self.input.scope.events.clone(),
            },
            journal: TranscriptAdmissionJournal {
                rollout: &mut *self.journal.transcript.rollout,
                ledger: &mut *self.journal.transcript.ledger,
                record_failed: &mut *self.journal.transcript.record_failed,
                diagnostics: self.journal.transcript.diagnostics,
                publications: &mut *self.journal.transcript.publications,
                #[cfg(test)]
                fault: &mut *self.journal.transcript.fault,
            },
            inbox: &mut *self.input.inbox,
            estimator: &mut *self.input.estimator,
            plan: &mut *self.input.plan,
            trust: &mut *self.input.trust,
            visibility: &mut *self.input.visibility,
        }
        .admit(messages)
    }
    pub(super) fn requested(&self) -> bool {
        self.input.control.requested() != InboundControl::None
    }
    pub(super) fn events(&self) -> &StreamToolEvents {
        &self.input.scope.events
    }
    pub(super) fn message(
        &mut self,
        messages: &mut Vec<Message>,
        message: Message,
    ) -> Result<(), KernelError> {
        // Completion writes user guidance/tool results; assistant publication belongs to the
        // independent actual model-message/answer receipt owner.
        if message.role != Role::User {
            return Err(KernelError::ContextResolution(
                "completion guidance has invalid role".into(),
            ));
        }
        self.journal
            .transcript
            .message(self.input.scope.turn, message.clone())?;
        if let Some(trust) =
            Trust::governing(message.content.iter().filter_map(|block| match block {
                Block::ToolResult(result) => Some(result.trust),
                Block::ToolImage(image) => Some(image.trust()),
                _ => None,
            }))
        {
            *self.input.trust = (*self.input.trust).min(trust);
        }
        messages.push(message);
        Ok(())
    }
    pub(super) fn notice(&mut self, text: &'static str) {
        if *self.journal.transcript.record_failed {
            return;
        }
        #[cfg(test)]
        if *self.journal.transcript.fault == Some(super::DurableAppendFault::BestEffort) {
            *self.journal.transcript.fault = None;
            *self.journal.transcript.record_failed = true;
            self.journal
                .transcript
                .diagnostics
                .emit(iteron_kernel::diagnostics::KernelDiagnostic::RecordAppendFailed {});
            return;
        }
        let started = Instant::now();
        let result = self
            .journal
            .transcript
            .rollout
            .queue_observation(iteron_protocol::Event {
                seq: iteron_protocol::Seq::ZERO,
                turn: self.input.scope.turn,
                kind: EventKind::Notice { text: text.into() },
            });
        if !matches!(result, Ok(false)) {
            self.journal
                .transcript
                .ledger
                .record_fsync_latency_us(super::provider_accounting::elapsed_us(started));
        }
        if result.is_err() {
            *self.journal.transcript.record_failed = true;
            self.journal
                .transcript
                .diagnostics
                .emit(iteron_kernel::diagnostics::KernelDiagnostic::RecordAppendFailed {});
        }
    }
    pub(super) fn exhausted(&self) -> Option<&'static str> {
        let ledger = &self.journal.transcript.ledger;
        if self.budget.tokens.is_some_and(|ceiling| {
            ledger.provider_attempts > ledger.turns || super::ledger_tokens(ledger) >= ceiling
        }) {
            Some("max_tokens")
        } else if self.budget.usd.as_ref().is_some_and(|usd| usd.exhausted()) {
            Some("max_usd")
        } else if self
            .budget
            .deadline
            .is_some_and(|deadline| deadline <= Instant::now())
        {
            Some("max_wall_secs")
        } else {
            None
        }
    }
    pub(super) async fn verify(
        &mut self,
        candidate: super::investigation_convergence::CandidateDiffState,
        convergence: &mut super::investigation_convergence::InvestigationConvergence,
    ) -> Result<Option<VerificationGateDisposition>, KernelError> {
        let Some(verification) = self.verification.as_mut() else {
            return Ok(None);
        };
        let turn = self.input.scope.turn;
        let source = &verification.scope;
        let mut gate = StrongVerificationGate {
            scope: VerificationScope {
                turn,
                workspace: source.workspace,
                runtime_state: source.runtime_state,
                deadline: source.deadline,
                authority_ceiling: source.authority_ceiling,
                verifier: source.verifier,
                preconfined: source.preconfined,
                sensitive_env_names: source.sensitive_env_names,
                interactive: source.interactive,
                events: source.events.clone(),
                activity: source.activity.clone(),
                #[cfg(test)]
                oracle: source.oracle.clone(),
            },
            state: &mut *verification.state,
            journal: VerificationJournal {
                rollout: &mut *self.journal.transcript.rollout,
                ledger: &mut *self.journal.transcript.ledger,
                effects: &mut *self.journal.effects,
                record_failed: &mut *self.journal.transcript.record_failed,
                diagnostics: self.journal.transcript.diagnostics,
                policy: &mut *self.journal.policy,
                bootstrap: verification.bootstrap.take(),
                #[cfg(test)]
                fault: &mut *self.journal.transcript.fault,
            },
            inbox: &mut *self.input.inbox,
            control: &mut *self.input.control,
            force_cancel: self.input.force_cancel.as_deref_mut(),
            checkpoints: &mut *self.journal.checkpoints,
            terminal: &mut *self.journal.terminal,
            tasks: verification.tasks.clone(),
            approval_seq: &mut *verification.approval_sequence,
            permission: PermissionTransaction {
                mode: &mut *verification.permission.mode,
                rules: &mut *verification.permission.rules,
                provenance: &mut *verification.permission.provenance,
                effort: verification.permission.effort,
                max_turns: verification.permission.max_turns,
            },
        };
        gate.run(turn, &verification.command, candidate, convergence)
            .await
            .map(Some)
    }
}
