//! Concrete invocation intake and physical media lifetime. Recovery, frozen policy, queued
//! control and monetary synchronization use retained owners before a deadline can be staged.
use super::KernelError;
use super::approval_wait::ApprovalJournal;
use super::compaction_journal::CompactionStateOwner;
use super::control_ingress::ControlIngress;
use super::effect_journal_owner::EffectJournalOwner;
use super::execution_deadline::{DeadlineLease, ExecutionDeadlineOwner};
use super::file_submission::InputFileEvidence;
use super::force_cancel::ForceCancelSeam;
use super::invocation_funding::InvocationFundingTransaction;
use super::policy_evidence_recorder::{FrozenSlotPolicyBinding, PolicyEvidenceRecorder};
use super::pricing::SharedUsdBudget;
use super::provider_selection::ProviderSelectionOwner;
use super::request_context_evidence::RequestContextEvidenceOwner;
use super::session_control::SessionControlState;
use super::session_inbox::SessionSubmissionInbox;
use super::stream_tool_events::StreamToolEvents;
use super::submission_invocation::{InvocationScope, SubmissionInvocation};
use iteron_kernel::diagnostics::KernelDiagnostic;
use iteron_obs::{CostState, Ledger};
use iteron_protocol::{ImageContent, Outcome, Trust, TurnId};
use std::sync::Arc;

#[derive(Clone, Copy)]
pub(super) enum InvocationMode {
    Operator { allow_orchestration: bool },
    Leaf,
}
impl InvocationMode {
    fn operator(self) -> bool {
        matches!(self, Self::Operator { .. })
    }
}
pub(super) struct InvocationAdmissionSession<'a> {
    pub(super) funding: InvocationFundingTransaction<'a>,
    pub(super) effects: &'a mut EffectJournalOwner,
    pub(super) policy: &'a mut Option<PolicyEvidenceRecorder>,
    pub(super) policy_identity: Option<(&'a str, &'a [FrozenSlotPolicyBinding])>,
    pub(super) inbox: &'a mut SessionSubmissionInbox,
    pub(super) control: &'a mut SessionControlState,
    pub(super) force_cancel: Option<&'a mut ForceCancelSeam>,
    pub(super) events: StreamToolEvents,
    pub(super) file: &'a mut Option<InputFileEvidence>,
    pub(super) compaction_closed: bool,
}
impl InvocationAdmissionSession<'_> {
    pub(super) fn prepare(
        mut self,
        mode: InvocationMode,
        turn: TurnId,
        file: Option<InputFileEvidence>,
    ) -> Result<InvocationAdmission, KernelError> {
        if mode.operator() && self.compaction_closed {
            return Err(KernelError::ContextResolution(
                "the pinned compaction failure policy closed the run after an unproven summary"
                    .into(),
            ));
        }
        if mode.operator() {
            *self.file = file;
        }
        let recovered = self
            .effects
            .guard_recovery(self.funding.journal.rollout, self.funding.journal.ledger);
        if matches!(&recovered, Err(KernelError::Record(_))) {
            *self.funding.journal.record_failed = true;
            self.funding
                .journal
                .diagnostics
                .emit(KernelDiagnostic::RecordAppendFailed {});
        }
        recovered?;
        if self.policy.is_none()
            && let Some((digest, bindings)) = self.policy_identity
        {
            let events = iteron_record::replay_timed(self.funding.journal.rollout.path())?;
            let restored = PolicyEvidenceRecorder::restore_or_begin(
                self.funding.journal.rollout.run_id(),
                digest.to_owned(),
                bindings.to_vec(),
                &events,
            )
            .map_err(|error| match error.into_record_error() {
                Ok(error) => {
                    *self.funding.journal.record_failed = true;
                    self.funding
                        .journal
                        .diagnostics
                        .emit(KernelDiagnostic::RecordAppendFailed {});
                    KernelError::Record(error)
                }
                Err(error) => KernelError::PolicyEvidence(error.to_string()),
            })?;
            *self.policy = Some(restored);
        }
        if turn.0 == u32::MAX {
            return Err(KernelError::IdentityExhausted("turn"));
        }
        ControlIngress {
            journal: ApprovalJournal {
                rollout: self.funding.journal.rollout,
                ledger: self.funding.journal.ledger,
                record_failed: self.funding.journal.record_failed,
                diagnostics: self.funding.journal.diagnostics,
                #[cfg(test)]
                fault: self.funding.journal.fault,
            },
            inbox: self.inbox,
            control: self.control,
            force_cancel: self.force_cancel,
            events: self.events,
        }
        .poll(turn, super::inbound_control::inbound_poll_limit());
        self.funding
            .budget
            .validate()
            .map_err(KernelError::InvalidBudget)?;
        self.funding.synchronize(turn)?;
        self.funding.close_unknown_cost();
        Ok(InvocationAdmission {
            mode,
            phase: AdmissionPhase::Prepared,
            media: None,
            leaf_deadline: None,
        })
    }
}

pub(super) struct InvocationMemoryReset<'a> {
    pub(super) enabled: bool,
    pub(super) requested: &'a mut bool,
    pub(super) injected: &'a mut Option<String>,
    pub(super) trust: &'a mut Option<Trust>,
    pub(super) evidence: &'a mut RequestContextEvidenceOwner,
    pub(super) registry: &'a iteron_tools::Registry,
}
impl InvocationMemoryReset<'_> {
    fn begin(&mut self) {
        if self.enabled {
            *self.requested = true;
            *self.injected = None;
            *self.trust = None;
            self.evidence.clear();
            self.registry.invalidate_pure_cache();
        }
    }
}
pub(super) struct InvocationMediaSession<'a> {
    pub(super) scope: InvocationScope<'a>,
    pub(super) deadlines: &'a mut ExecutionDeadlineOwner,
    pub(super) compaction: &'a mut CompactionStateOwner,
    pub(super) memory: InvocationMemoryReset<'a>,
    pub(super) selection: &'a ProviderSelectionOwner,
    pub(super) usd: Option<&'a Arc<SharedUsdBudget>>,
    pub(super) ledger: &'a Ledger,
}
#[derive(PartialEq, Eq)]
enum AdmissionPhase {
    Prepared,
    Running,
}
pub(super) struct InvocationAdmission {
    mode: InvocationMode,
    phase: AdmissionPhase,
    media: Option<SubmissionInvocation>,
    leaf_deadline: Option<DeadlineLease>,
}
impl InvocationAdmission {
    pub(super) fn stage(
        mut self,
        task: &str,
        images: &[ImageContent],
        file: Option<InputFileEvidence>,
        mut session: InvocationMediaSession<'_>,
    ) -> Result<Self, KernelError> {
        if self.phase != AdmissionPhase::Prepared {
            return Err(KernelError::EffectBoundary(
                "invocation media already admitted".into(),
            ));
        }
        self.phase = AdmissionPhase::Running;
        if self.mode.operator()
            && (*session.memory.requested
                || (matches!(
                    self.mode,
                    InvocationMode::Operator {
                        allow_orchestration: true
                    }
                ) && (!task.trim().is_empty() || !images.is_empty() || file.is_some())))
        {
            session.memory.begin();
        }
        if session.usd.is_some_and(|budget| budget.requires_pricing())
            && (session.selection.pricing_port().is_none()
                || session.selection.card().is_none()
                || matches!(session.ledger.cost_state(), CostState::Unknown { .. }))
        {
            return Err(KernelError::UnpricedUsdCeiling);
        }
        if self.mode.operator() {
            session.compaction.begin_submission();
            self.media = Some(SubmissionInvocation::stage(
                session.scope,
                session.deadlines,
                images,
            )?);
        } else {
            self.leaf_deadline = Some(
                session
                    .deadlines
                    .begin_invocation(session.scope.wall_secs)?,
            );
        }
        Ok(self)
    }
    pub(super) fn images(&self) -> &[ImageContent] {
        self.media
            .as_ref()
            .map_or(&[], SubmissionInvocation::images)
    }
    pub(super) fn may_orchestrate(&self, requested: bool, nonempty: bool, active: bool) -> bool {
        matches!(
            self.mode,
            InvocationMode::Operator {
                allow_orchestration: true
            }
        ) && requested
            && nonempty
            && !active
    }
    pub(super) fn complete(
        mut self,
        outcome: Result<Outcome, KernelError>,
    ) -> Result<CompletedInvocation, KernelError> {
        if self.phase != AdmissionPhase::Running {
            return Err(KernelError::EffectBoundary(
                "invocation has no admitted execution".into(),
            ));
        }
        if let Some(media) = &mut self.media {
            media.release_deadline();
        }
        self.leaf_deadline.take();
        Ok(CompletedInvocation {
            admission: self,
            outcome,
        })
    }
}
pub(super) struct CompletedInvocation {
    admission: InvocationAdmission,
    outcome: Result<Outcome, KernelError>,
}
impl CompletedInvocation {
    pub(super) fn stop_context(&self) -> Option<String> {
        stop_context(&self.outcome)
    }
    pub(super) fn compact(&self) -> bool {
        self.admission.mode.operator() && matches!(self.outcome, Ok(Outcome::Done))
    }
    pub(super) fn into_outcome(self) -> Result<Outcome, KernelError> {
        self.outcome
    }
}
pub(super) fn stop_context(outcome: &Result<Outcome, KernelError>) -> Option<String> {
    outcome
        .as_ref()
        .ok()
        .filter(|outcome| **outcome != Outcome::Drained)
        .map(|outcome| {
            serde_json::json!({"event":"Stop","outcome":format!("{outcome:?}")}).to_string()
        })
}
