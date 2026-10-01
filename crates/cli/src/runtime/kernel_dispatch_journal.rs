//! Concrete special-tool record/effect port. One physical writer supplies intent, terminal, policy,
//! and control receipts; an executor cannot fabricate a committed sequence or bypass failure.
use super::KernelError;
use super::approval_wait::ApprovalJournal;
use super::effect_descriptor::{effect_class_label, effect_workspace};
use super::effect_journal_owner::{EffectJournalOwner, UnknownCause};
use super::frontend_events::UiEvent;
use super::policy_evidence::PolicyDecisionDraft;
use super::policy_evidence_recorder::{
    FrozenSlotPolicyBinding, PolicyEvidenceRecorder, PolicyEvidenceRecorderError, PolicyOpportunity,
};
use super::stream_tool_events::StreamToolEvents;
use iteron_kernel::diagnostics::{DiagnosticEmitter, KernelDiagnostic};
use iteron_kernel::{effect_class, effects};
use iteron_obs::Ledger;
use iteron_protocol::{Capability, Event, EventKind, Seq, TurnId, slot::SlotId};
use iteron_record::{RecordError, Rollout};
use std::{path::Path, time::Instant};

pub(super) struct KernelPolicyBootstrap {
    pub(super) digest: String,
    pub(super) bindings: Vec<FrozenSlotPolicyBinding>,
}
pub(super) struct KernelDispatchJournal<'a> {
    pub(super) workspace: &'a Path,
    pub(super) rollout: &'a mut Rollout,
    pub(super) ledger: &'a mut Ledger,
    pub(super) effects: &'a mut EffectJournalOwner,
    pub(super) record_failed: &'a mut bool,
    pub(super) money: Option<std::sync::Arc<super::pricing::SharedUsdBudget>>,
    pub(super) diagnostics: &'a DiagnosticEmitter,
    pub(super) policy: &'a mut Option<PolicyEvidenceRecorder>,
    pub(super) bootstrap: Option<KernelPolicyBootstrap>,
    #[cfg(test)]
    pub(super) fault: &'a mut Option<super::DurableAppendFault>,
}
impl KernelDispatchJournal<'_> {
    pub(super) fn tenant(&self) -> &iteron_protocol::TenantId {
        self.rollout.tenant()
    }
    pub(super) fn workspace(&self) -> &Path {
        self.workspace
    }
    pub(super) fn merge_child(&mut self, child: &Ledger) {
        let unknown = matches!(child.cost_state(), iteron_obs::CostState::Unknown { .. });
        self.ledger.merge(child);
        if (unknown
            || matches!(
                self.ledger.cost_state(),
                iteron_obs::CostState::Unknown { .. }
            ))
            && let Some(money) = &self.money
        {
            money.mark_unknown();
        }
    }
    pub(super) fn next_ordinal(&mut self, turn: TurnId, class: effect_class::EffectClass) -> usize {
        self.effects.next_ordinal(turn, class)
    }
    pub(super) fn healthy(&self) -> Result<(), KernelError> {
        self.require_healthy()
    }
    pub(super) fn append(
        &mut self,
        turn: TurnId,
        kind: EventKind,
    ) -> Result<iteron_protocol::Seq, KernelError> {
        #[cfg(test)]
        if *self.fault == Some(super::DurableAppendFault::SubagentFinished)
            && matches!(kind, EventKind::SubagentFinishedV2 { .. })
        {
            *self.fault = None;
            return Err(self.failed_record(RecordError::Io(std::io::Error::other(
                "injected child terminal append failure",
            ))));
        }
        self.record().append_receipt(turn, kind)
    }
    pub(super) fn hook<'a>(
        &'a mut self,
        scope: super::hook_execution::HookExecutionScope<'a>,
    ) -> super::hook_execution::HookExecution<'a> {
        super::hook_execution::HookExecution {
            rollout: self.rollout,
            effects: self.effects,
            record_failed: self.record_failed,
            ledger: self.ledger,
            diagnostics: self.diagnostics,
            #[cfg(test)]
            fault: self.fault,
            scope,
        }
    }
    pub(super) fn tool<'a>(
        &'a mut self,
        failed: &'a mut super::failed_action_cache::FailedActionCache,
    ) -> super::tool_execution_journal::ToolExecutionJournal<'a> {
        super::tool_execution_journal::ToolExecutionJournal {
            rollout: self.rollout,
            effects: self.effects,
            ledger: self.ledger,
            record_failed: self.record_failed,
            diagnostics: self.diagnostics,
            #[cfg(test)]
            fault: self.fault,
            failed_actions: failed,
        }
    }

    pub(super) fn record(&mut self) -> ApprovalJournal<'_> {
        ApprovalJournal {
            rollout: self.rollout,
            ledger: self.ledger,
            record_failed: self.record_failed,
            diagnostics: self.diagnostics,
            #[cfg(test)]
            fault: self.fault,
        }
    }
    fn require_healthy(&self) -> Result<(), KernelError> {
        if *self.record_failed {
            return Err(KernelError::Record(RecordError::Io(std::io::Error::other(
                "special tool execution cannot continue after the durable record failed",
            ))));
        }
        Ok(())
    }
    pub(super) fn observation(&mut self, turn: TurnId, kind: EventKind, events: &StreamToolEvents) {
        if self.require_healthy().is_err() {
            return;
        }
        #[cfg(test)]
        if *self.fault == Some(super::DurableAppendFault::BestEffort) {
            *self.fault = None;
            self.failed_record(RecordError::Io(std::io::Error::other(
                "injected durable observation failure",
            )));
            return;
        }
        let phase = match &kind {
            EventKind::Phase { phase } => Some(*phase),
            _ => None,
        };
        let buffered = matches!(
            &kind,
            EventKind::Phase { .. }
                | EventKind::Notice { .. }
                | EventKind::Text { .. }
                | EventKind::Thinking { .. }
        );
        let event = Event {
            seq: Seq::ZERO,
            turn,
            kind,
        };
        let started = Instant::now();
        let mut prefix_flushed = false;
        let appended = if buffered {
            self.rollout.queue_observation(event).map(|flushed| {
                prefix_flushed = flushed;
                Seq::ZERO
            })
        } else {
            self.rollout.append(&event)
        };
        if !buffered || prefix_flushed {
            self.measure(started);
        }
        match appended {
            Ok(_) => {
                if let Some(phase) = phase {
                    events.present(UiEvent::Phase(phase));
                }
            }
            Err(error) => {
                self.failed_record(error);
            }
        }
    }
    pub(super) fn open(
        &mut self,
        workspace: &Path,
        turn: TurnId,
        class: effect_class::EffectClass,
        ordinal: usize,
        capability: Capability,
        audit: serde_json::Value,
    ) -> Result<effects::EffectTicket, KernelError> {
        self.require_healthy()?;
        #[cfg(test)]
        if *self.fault == Some(super::DurableAppendFault::EffectIntent) {
            *self.fault = None;
            return Err(self.failed_record(RecordError::Io(std::io::Error::other(
                "injected durable effect-intent append failure",
            ))));
        }
        let started = Instant::now();
        let opened = self.effects.open(
            self.rollout,
            effects::BrokeredEffect {
                turn,
                effect_id: effect_class::effect_id(turn, class, ordinal),
                tool_use_id: effect_class::harness_correlation_id(turn, class, ordinal),
                kind: effect_class_label(class).into(),
                capability,
                audit_arguments: audit,
                workspace: effect_workspace(workspace),
                provider_route_attempt: None,
            },
        );
        self.measure(started);
        opened.map_err(|error| self.boundary_error(error))
    }
    pub(super) fn settle(
        &mut self,
        ticket: effects::EffectTicket,
        settlement: effects::Settlement,
    ) -> Result<(), KernelError> {
        self.require_healthy()?;
        let started = Instant::now();
        let result =
            self.effects
                .settle(self.rollout, ticket, settlement, UnknownCause::Unobserved);
        self.measure(started);
        result.map_err(|error| self.boundary_error(error))
    }
    pub(super) fn begin_policy_decision(
        &mut self,
        slot: &'static str,
        turn: Option<TurnId>,
    ) -> Result<Option<PolicyOpportunity>, KernelError> {
        self.require_healthy()?;
        if self.policy.is_none() {
            let Some(bootstrap) = self.bootstrap.as_ref() else {
                return Ok(None);
            };
            let events = iteron_record::replay_timed(self.rollout.path())?;
            let restored = PolicyEvidenceRecorder::restore_or_begin(
                self.rollout.run_id(),
                bootstrap.digest.clone(),
                bootstrap.bindings.clone(),
                &events,
            );
            *self.policy = Some(restored.map_err(|error| self.policy_error(error))?);
        }
        self.policy
            .as_mut()
            .expect("restored above")
            .begin_opportunity(&SlotId(slot.into()), turn)
            .map(Some)
            .map_err(|error| self.policy_error(error))
    }
    pub(super) fn append_policy_decision(
        &mut self,
        opportunity: Option<PolicyOpportunity>,
        draft: PolicyDecisionDraft,
    ) -> Result<(), KernelError> {
        let Some(opportunity) = opportunity else {
            return Ok(());
        };
        self.require_healthy()?;
        let recorder = self
            .policy
            .as_mut()
            .ok_or_else(|| KernelError::PolicyEvidence("recorder ownership was lost".into()))?;
        let started = Instant::now();
        let result = recorder.append_decision(self.rollout, &opportunity, draft.into_input());
        self.measure(started);
        result.map(|_| ()).map_err(|error| self.policy_error(error))
    }
    fn policy_error(&mut self, error: PolicyEvidenceRecorderError) -> KernelError {
        match error.into_record_error() {
            Ok(error) => self.failed_record(error),
            Err(error) => KernelError::PolicyEvidence(error.to_string()),
        }
    }
    fn boundary_error(&mut self, error: effects::BrokerError) -> KernelError {
        match error {
            effects::BrokerError::Record(error) => self.failed_record(error),
            other => KernelError::EffectBoundary(other.to_string()),
        }
    }
    fn failed_record(&mut self, error: RecordError) -> KernelError {
        *self.record_failed = true;
        self.diagnostics
            .emit(KernelDiagnostic::RecordAppendFailed {});
        KernelError::Record(error)
    }
    fn measure(&mut self, started: Instant) {
        self.ledger.record_fsync_latency_us(
            u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
    }
}
