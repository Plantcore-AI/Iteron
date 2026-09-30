//! Physical finalization coordinator over disjoint real writer/checkpoint/evidence owners.
//! It receives no Agent, callback proxy, policy setter or maintenance worker authority.
use super::KernelError;
use super::effect_journal_owner::EffectJournalOwner;
use super::policy_evidence_recorder::{PolicyEvidenceRecorder, PolicyEvidenceRecorderError};
use super::stream_tool_events::StreamToolEvents;
use super::terminal_record::TerminalRecordOwner;
use super::turn_activity::{ActivitySink, ActivityStage};
use super::turn_publication::TurnPublicationOwner;
use super::workspace_checkpoint::{CheckpointScope, WorkspaceCheckpoint, WorkspaceCheckpointOwner};
use iteron_kernel::diagnostics::{DiagnosticEmitter, KernelDiagnostic};
use iteron_obs::Ledger;
use iteron_protocol::turn_publication::TurnPublicationFactV1;
use iteron_protocol::{Event, EventKind, LifecyclePayload, Outcome, Seq, TurnId};
use iteron_record::{RecordError, Rollout};
use std::{path::Path, time::Instant};

pub(super) struct FinalizationScope<'a> {
    pub(super) turn: TurnId,
    pub(super) workspace: &'a Path,
    pub(super) runtime_state: &'a Path,
    pub(super) best_effort_checkpoint: bool,
    pub(super) usage_unavailable: bool,
    pub(super) activity: ActivitySink,
    pub(super) events: StreamToolEvents,
}
pub(super) struct RunFinalization<'a> {
    pub(super) rollout: &'a mut Rollout,
    pub(super) ledger: &'a mut Ledger,
    pub(super) record_failed: &'a mut bool,
    pub(super) diagnostics: &'a DiagnosticEmitter,
    pub(super) effects: &'a mut EffectJournalOwner,
    pub(super) checkpoints: &'a mut WorkspaceCheckpointOwner,
    pub(super) terminal: &'a mut TerminalRecordOwner,
    pub(super) policy: Option<&'a mut PolicyEvidenceRecorder>,
    pub(super) publications: &'a mut TurnPublicationOwner,
    #[cfg(test)]
    pub(super) fault: &'a mut Option<super::DurableAppendFault>,
    pub(super) scope: FinalizationScope<'a>,
}
/// Opaque successful physical terminal receipt. There is no DTO or predicted sequence constructor.
pub(super) struct FinalizedTurn {
    turn: TurnId,
    outcome: Outcome,
    source: Seq,
    fact: TurnPublicationFactV1,
}
impl FinalizedTurn {
    pub(super) fn turn(&self) -> TurnId {
        self.turn
    }
    pub(super) fn outcome(&self) -> &Outcome {
        &self.outcome
    }
    pub(super) fn source(&self) -> Seq {
        self.source
    }
    pub(super) fn fact(&self) -> TurnPublicationFactV1 {
        self.fact.clone()
    }
    pub(super) fn into_outcome(self) -> Outcome {
        self.outcome
    }
}
impl RunFinalization<'_> {
    pub(super) async fn commit(
        mut self,
        mut outcome: Outcome,
    ) -> Result<FinalizedTurn, KernelError> {
        let turn = self.scope.turn;
        if outcome == Outcome::Done {
            self.scope
                .activity
                .span(ActivityStage::AnswerComplete, Some(turn))
                .complete();
        }
        let activity = self
            .scope
            .activity
            .span(ActivityStage::FinalizingEvidence, Some(turn));
        // Let the same-task frontend paint the published answer boundary before synchronous fsync.
        tokio::task::yield_now().await;
        if self.scope.best_effort_checkpoint {
            let scope = CheckpointScope {
                turn,
                workspace: self.scope.workspace,
                runtime_state: self.scope.runtime_state,
                activity: self.scope.activity.clone(),
                lifecycle: self.scope.events.lifecycle.clone(),
                hooks: self.scope.events.lifecycle_hooks.clone(),
                correlation: self.scope.events.correlation.clone(),
            };
            if (WorkspaceCheckpoint {
                owner: self.checkpoints,
                rollout: self.rollout,
                effects: self.effects,
                ledger: self.ledger,
                record_failed: self.record_failed,
                diagnostics: self.diagnostics,
                #[cfg(test)]
                fault: self.fault,
                scope,
            })
            .create(false)
            .is_err()
            {
                // The checkpoint owner settled its real refusal; a best-effort snapshot cannot
                // retroactively erase a recorded successful answer. Record failure still prevents
                // the authoritative run terminal below from falsely succeeding.
                self.scope.events.emit(
                    "checkpoint.failed",
                    None,
                    LifecyclePayload {
                        reason_code: Some("best_effort_turn_boundary".into()),
                        ..Default::default()
                    },
                );
            }
        }
        if self.scope.events.frontend.take_structural_refusal() {
            self.notice("frontend structural event delivery exceeded its bounded queue; the run failed closed")?;
            self.scope.events.emit(
                "queue.overflow",
                None,
                LifecyclePayload {
                    count: Some(1),
                    reason_code: Some("runtime_ui_structural_refused".into()),
                    outcome_code: Some("failed_closed".into()),
                    ..Default::default()
                },
            );
            if outcome == Outcome::Done {
                outcome = Outcome::HarnessError;
            }
        }
        if *self.record_failed {
            return Err(KernelError::Record(RecordError::Io(std::io::Error::other(
                "run finalization cannot publish a terminal after the durable record failed",
            ))));
        }
        let (terminal, error) = self
            .terminal
            .classify_outcome(&outcome, self.scope.usage_unavailable);
        let verifier = self.terminal.verifier();
        if let Some(recorder) = self.policy.as_deref_mut() {
            let result = self.terminal.append_policy_outcome(
                recorder,
                self.rollout,
                self.ledger,
                turn,
                terminal,
                verifier,
                error,
            );
            result.map_err(|error| self.policy_error(error))?;
        }
        let fact = TurnPublicationFactV1::finalized(&outcome)
            .map_err(|reason| KernelError::ContextResolution(reason.into()))?;
        #[cfg(test)]
        if *self.fault == Some(super::DurableAppendFault::RunTerminal) {
            *self.fault = None;
            return Err(self.record_error(RecordError::Io(std::io::Error::other(
                "injected durable run-terminal append refusal",
            ))));
        }
        let outcome_label = format!("{outcome:?}");
        let source = self
            .terminal
            .append_visible_terminal(self.rollout, self.ledger, turn, outcome_label.clone())
            .map_err(|error| self.record_error(error))?;
        self.publications.observe_committed(&Event {
            seq: source,
            turn,
            kind: EventKind::Done {
                outcome: outcome_label,
            },
        });
        activity.complete();
        Ok(FinalizedTurn {
            turn,
            outcome,
            source,
            fact,
        })
    }
    fn notice(&mut self, text: &str) -> Result<(), KernelError> {
        #[cfg(test)]
        if *self.fault == Some(super::DurableAppendFault::Notice) {
            *self.fault = None;
            return Err(self.record_error(RecordError::Io(std::io::Error::other(
                "injected durable append failure",
            ))));
        }
        let started = Instant::now();
        let result = self.rollout.append(&Event {
            seq: Seq::ZERO,
            turn: self.scope.turn,
            kind: EventKind::Notice { text: text.into() },
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
    fn policy_error(&mut self, error: PolicyEvidenceRecorderError) -> KernelError {
        match error.into_record_error() {
            Ok(error) => self.record_error(error),
            Err(error) => KernelError::PolicyEvidence(error.to_string()),
        }
    }
}
