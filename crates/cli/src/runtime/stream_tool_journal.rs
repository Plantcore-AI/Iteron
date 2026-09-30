//! Physical admission ports for streamed declarations. This adapter borrows actual state owners;
//! it cannot execute a tool, approve authority, change provider budgets or replace a journal.
#[cfg(test)]
use super::DurableAppendFault;
use super::KernelError;
use super::effect_descriptor::{effect_class_label, effect_workspace};
use super::effect_journal_owner::EffectJournalOwner;
use super::policy_evidence::{PolicyDecisionDraft, TOOL_POLICY_SLOT};
use super::policy_evidence_recorder::{PolicyEvidenceRecorder, PolicyEvidenceRecorderError};
use iteron_kernel::diagnostics::{DiagnosticEmitter, KernelDiagnostic};
use iteron_kernel::{effect_class, effects};
use iteron_obs::Ledger;
use iteron_protocol::{Capability, Event, EventKind, Seq, ToolUse, TurnId, slot::SlotId};
use iteron_record::Rollout;
use std::{path::Path, time::Instant};

pub(super) struct StreamToolJournal<'a> {
    pub(super) rollout: &'a mut Rollout,
    pub(super) effects: &'a mut EffectJournalOwner,
    pub(super) policy: Option<&'a mut PolicyEvidenceRecorder>,
    pub(super) ledger: &'a mut Ledger,
    pub(super) record_failed: &'a mut bool,
    pub(super) diagnostics: &'a DiagnosticEmitter,
    #[cfg(test)]
    pub(super) fault: &'a mut Option<DurableAppendFault>,
}

impl StreamToolJournal<'_> {
    pub(super) fn record_decision(
        &mut self,
        turn: TurnId,
        draft: PolicyDecisionDraft,
    ) -> Result<(), KernelError> {
        let opportunity = self
            .policy
            .as_mut()
            .map(|recorder| {
                recorder.begin_opportunity(&SlotId(TOOL_POLICY_SLOT.into()), Some(turn))
            })
            .transpose()
            .map_err(|error| self.policy_error(error))?;
        #[cfg(test)]
        if *self.fault == Some(DurableAppendFault::ToolPolicyDecision) {
            *self.fault = None;
            return Err(
                self.record_error(iteron_record::RecordError::Io(std::io::Error::other(
                    "injected policy-decision sync failure",
                ))),
            );
        }
        let Some(opportunity) = opportunity else {
            // Legacy unpinned fixtures have no policy evidence recorder. A missing production
            // recorder must be decided by trusted initialization, never manufactured here.
            return Ok(());
        };
        let started = Instant::now();
        let appended = self
            .policy
            .as_mut()
            .expect("minted by retained recorder")
            .append_decision(self.rollout, &opportunity, draft.into_input());
        self.measure(started);
        appended
            .map(|_| ())
            .map_err(|error| self.policy_error(error))
    }

    pub(super) fn open_hook(
        &mut self,
        workspace: &Path,
        turn: TurnId,
        index: usize,
        event: &'static str,
    ) -> Result<(usize, effects::EffectTicket), KernelError> {
        let class = effect_class::EffectClass::Hook;
        let ordinal = self.effects.next_ordinal(turn, class);
        #[cfg(test)]
        if *self.fault == Some(DurableAppendFault::EffectIntent) {
            *self.fault = None;
            return Err(
                self.record_error(iteron_record::RecordError::Io(std::io::Error::other(
                    "injected durable effect-intent append failure",
                ))),
            );
        }
        let opened = self.effects.open(
            self.rollout,
            effects::BrokeredEffect {
                turn,
                effect_id: effect_class::effect_id(turn, class, ordinal),
                tool_use_id: effect_class::harness_correlation_id(turn, class, ordinal),
                kind: effect_class_label(class).into(),
                capability: Capability::CodeExecuting,
                audit_arguments: serde_json::json!({"event":event,"tool_index":index}),
                workspace: effect_workspace(workspace),
                provider_route_attempt: None,
            },
        );
        opened
            .map(|ticket| (ordinal, ticket))
            .map_err(|error| self.boundary_error(error))
    }

    pub(super) fn open_tool(
        &mut self,
        workspace: &Path,
        turn: TurnId,
        index: usize,
        call: &ToolUse,
        capability: Capability,
    ) -> Result<effects::EffectTicket, KernelError> {
        let opened = self
            .effects
            .open_tool(self.rollout, workspace, turn, index, call, capability);
        opened.map_err(|error| self.boundary_error(error))
    }

    pub(super) fn append_ready(
        &mut self,
        turn: TurnId,
        call: &ToolUse,
        pure: bool,
    ) -> Result<Seq, KernelError> {
        let started = Instant::now();
        let appended = self.rollout.append(&Event {
            seq: Seq::ZERO,
            turn,
            kind: EventKind::ToolReady {
                tool: call.clone(),
                purity_pure: pure,
            },
        });
        self.measure(started);
        appended.map_err(|error| self.record_error(error))
    }

    fn policy_error(&mut self, error: PolicyEvidenceRecorderError) -> KernelError {
        match error.into_record_error() {
            Ok(error) => self.record_error(error),
            Err(error) => KernelError::PolicyEvidence(error.to_string()),
        }
    }
    fn record_error(&mut self, error: iteron_record::RecordError) -> KernelError {
        *self.record_failed = true;
        self.diagnostics
            .emit(KernelDiagnostic::RecordAppendFailed {});
        KernelError::Record(error)
    }
    fn boundary_error(&mut self, error: effects::BrokerError) -> KernelError {
        match error {
            effects::BrokerError::Record(error) => {
                *self.record_failed = true;
                KernelError::Record(error)
            }
            other => KernelError::EffectBoundary(other.to_string()),
        }
    }
    fn measure(&mut self, started: Instant) {
        self.ledger.record_fsync_latency_us(
            u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
    }
}
