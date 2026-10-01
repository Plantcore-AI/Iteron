//! Configured strong verification state machine. Receives disjoint concrete ports, never Agent.
use super::KernelError;
use super::bounded_verify::VerificationTaskRegistry;
use super::force_cancel::ForceCancelSeam;
use super::frontend_events::UiEvent;
use super::investigation_convergence;
use super::permission_transaction::PermissionTransaction;
use super::policy_evidence;
use super::session_control::{InboundControl, SessionControlState};
use super::session_inbox::SessionSubmissionInbox;
use super::stream_tool_events::StreamToolEvents;
use super::terminal_record::TerminalRecordOwner;
use super::tool_presentation::truncate_tail;
use super::turn_activity::ActivitySink;
use super::verification_journal::VerificationJournal;
use super::verification_state::VerificationStateOwner;
use super::workspace_checkpoint::{CheckpointScope, WorkspaceCheckpoint, WorkspaceCheckpointOwner};
use iteron_obs::PhaseSpan;
use iteron_protocol::{
    Capability, CapabilitySet, EventKind, LifecyclePayload, Outcome, Phase, TurnId,
};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(super) enum VerificationGateDisposition {
    Passed,
    Retry(String),
    Finish {
        outcome: Outcome,
        guidance: Option<String>,
    },
    Drained,
    Cancelled(String),
}
/// The scope is frozen at an existing explicit --verify invocation. It cannot modify authority,
/// policy, route, budget, or the submitted task. Ordinary completion does not construct this owner.
pub(super) struct VerificationScope<'a> {
    pub(super) turn: TurnId,
    pub(super) workspace: &'a Path,
    pub(super) runtime_state: &'a Path,
    pub(super) deadline: Option<Instant>,
    pub(super) authority_ceiling: CapabilitySet,
    pub(super) verifier: &'a dyn iteron_protocol::slot::StrategySlot,
    pub(super) preconfined: bool,
    pub(super) sensitive_env_names: &'a [String],
    pub(super) interactive: bool,
    pub(super) events: StreamToolEvents,
    pub(super) activity: ActivitySink,
    #[cfg(test)]
    pub(super) oracle: Option<Arc<dyn iteron_verify::Oracle>>,
}
pub(super) struct StrongVerificationGate<'a> {
    pub(super) scope: VerificationScope<'a>,
    pub(super) state: &'a mut VerificationStateOwner,
    pub(super) journal: VerificationJournal<'a>,
    pub(super) inbox: &'a mut SessionSubmissionInbox,
    pub(super) control: &'a mut SessionControlState,
    pub(super) force_cancel: Option<&'a mut ForceCancelSeam>,
    pub(super) checkpoints: &'a mut WorkspaceCheckpointOwner,
    pub(super) terminal: &'a mut TerminalRecordOwner,
    pub(super) tasks: Arc<VerificationTaskRegistry>,
    pub(super) approval_seq: &'a mut u64,
    pub(super) permission: PermissionTransaction<'a>,
}
impl StrongVerificationGate<'_> {
    pub(super) async fn run(
        &mut self,
        turn: TurnId,
        command: &str,
        candidate_state: investigation_convergence::CandidateDiffState,
        convergence: &mut investigation_convergence::InvestigationConvergence,
    ) -> Result<VerificationGateDisposition, KernelError> {
        match convergence.guard_verification_candidate(candidate_state) {
            investigation_convergence::VerificationCandidateGuard::Verify => {}
            #[cfg(any(feature = "ticket-investigation", test))]
            investigation_convergence::VerificationCandidateGuard::RequireTransition(guidance) => {
                let notice =
                    "verify gate: unchanged rejected candidate; requesting a real transition";
                self.emit(
                    turn,
                    EventKind::Notice {
                        text: notice.into(),
                    },
                );
                self.ui(UiEvent::Notice(notice.into()));
                return Ok(VerificationGateDisposition::Retry(guidance.into()));
            }
            #[cfg(any(feature = "ticket-investigation", test))]
            investigation_convergence::VerificationCandidateGuard::Stop(guidance) => {
                let notice =
                    "verify gate: unchanged rejected candidate repeated; stopping without rerun";
                self.emit(
                    turn,
                    EventKind::Notice {
                        text: notice.into(),
                    },
                );
                self.ui(UiEvent::Notice(notice.into()));
                return Ok(VerificationGateDisposition::Finish {
                    outcome: Outcome::Stuck,
                    guidance: Some(guidance.into()),
                });
            }
        }
        self.journal.effects.note_workspace_mutation();
        let max_verify_attempts = self.state.policy().retry.max_attempts;
        if self.state.attempts() >= max_verify_attempts {
            self.verification_repair_exhausted(turn);
            let notice = format!(
                "verify gate: `{command}` did not pass within {max_verify_attempts} attempts; stopping"
            );
            self.emit(
                turn,
                EventKind::Notice {
                    text: notice.clone(),
                },
            );
            self.ui(UiEvent::Notice(notice));
            return Ok(VerificationGateDisposition::Finish {
                outcome: Outcome::BudgetExhausted("verify_attempts"),
                guidance: None,
            });
        }

        self.checkpoint_before_verification(turn)?;
        self.emit(
            turn,
            EventKind::Phase {
                phase: Phase::Verify,
            },
        );
        let verifier_observation = iteron_verify::VerifierSlotObservation::gating(true);
        let verifier_opportunity = self
            .journal
            .begin_policy_decision(policy_evidence::VERIFIER_SLOT, Some(turn))?;
        let verify_plan = match iteron_verify::VerifierStrategy::plan_with(
            self.scope.verifier,
            &verifier_observation,
            CapabilitySet::only(Capability::CodeExecuting).intersect(self.scope.authority_ceiling),
        ) {
            Ok(proposal) => {
                self.journal.append_policy_decision(
                    verifier_opportunity,
                    policy_evidence::PolicyDecisionDraft::selected(
                        policy_evidence::VERIFIER_SLOT,
                        &[iteron_protocol::PolicyActionV1::VerifierStrongWorkspacePlan],
                        iteron_protocol::PolicyActionV1::VerifierStrongWorkspacePlan,
                        "iteron:verifier-features-v1",
                        &(&verifier_observation, proposal.plan),
                        &"verification_may_only_strengthen_caller_floors",
                    )?,
                )?;
                proposal.plan
            }
            Err(error) => {
                self.journal.append_policy_decision(
                    verifier_opportunity,
                    policy_evidence::PolicyDecisionDraft::abstained(
                        policy_evidence::VERIFIER_SLOT,
                        &[iteron_protocol::PolicyActionV1::VerifierStrongWorkspacePlan],
                        "iteron:verifier-features-v1",
                        &verifier_observation,
                        &"invalid_verifier_plans_fail_closed",
                    )?,
                )?;
                return Err(KernelError::ContextResolution(format!(
                    "verifier strategy refused: {error}"
                )));
            }
        };
        if verify_plan.attempts > self.state.policy().verifier_strategy_max_attempts {
            return Err(KernelError::ContextResolution(
                "verifier strategy exceeded the pinned verifier_attempts ceiling".into(),
            ));
        }
        let verify_span = PhaseSpan::enter(Phase::Verify);
        let verdict = self.run_verification_policy(command, verify_plan).await?;
        self.terminal.observe_verifier(match verdict.outcome {
            iteron_verify::VerificationOutcome::Pass => {
                iteron_protocol::PolicyVerifierOutcome::Passed
            }
            iteron_verify::VerificationOutcome::TestFailure => {
                iteron_protocol::PolicyVerifierOutcome::TestFailure
            }
            iteron_verify::VerificationOutcome::TimedOut => {
                iteron_protocol::PolicyVerifierOutcome::TimedOut
            }
            iteron_verify::VerificationOutcome::InfrastructureFailure => {
                iteron_protocol::PolicyVerifierOutcome::InfrastructureFailure
            }
            iteron_verify::VerificationOutcome::Cancelled => {
                iteron_protocol::PolicyVerifierOutcome::Cancelled
            }
        });
        self.journal.ledger.phase_verify(verify_span.elapsed_ms());

        // Drain deliberately lets the already-admitted oracle reach a verdict, then checkpoints
        // before any failure/timeout branch can substitute a different terminal outcome.
        if self.control.requested() == InboundControl::Drain {
            return Ok(VerificationGateDisposition::Drained);
        }

        let detail = truncate_tail(&verdict.detail, 3000);
        let failure_classification = iteron_verify::classify_verification_failure(verdict.outcome);
        match verdict.outcome {
            iteron_verify::VerificationOutcome::Pass => {
                convergence.verification_passed();
                self.verification_repair_completed(turn);
                self.emit(
                    turn,
                    EventKind::Notice {
                        text: format!("verify gate: `{command}` passed"),
                    },
                );
                self.ui(UiEvent::Notice(format!("verify gate: `{command}` passed")));
                Ok(VerificationGateDisposition::Passed)
            }
            iteron_verify::VerificationOutcome::TestFailure => {
                let structural_regression = convergence.has_failed_verification_candidate()
                    && verification_detail_is_structural_failure(&detail);
                convergence.remember_verification_test_failure(candidate_state);
                let failure_class = failure_classification
                    .expect("every non-pass oracle outcome has a taxonomy entry")
                    .class();
                let recovery = self.state.policy().recovery_escalation.decide(
                    &self.state.policy().retry,
                    failure_class,
                    self.state.attempts(),
                );
                if recovery == iteron_verify::VerificationRecoveryAction::StopOperator {
                    self.emit(
                        turn,
                        EventKind::Notice {
                            text: format!(
                                "verify gate: `{command}` failed; recovery policy returned control to the operator"
                            ),
                        },
                    );
                    return Ok(VerificationGateDisposition::Finish {
                        outcome: Outcome::HarnessError,
                        guidance: None,
                    });
                }
                if recovery == iteron_verify::VerificationRecoveryAction::StopIneligible {
                    self.emit(
                        turn,
                        EventKind::Notice {
                            text: format!(
                                "verify gate: `{command}` test failure is not retry-eligible under the immutable policy; stopping"
                            ),
                        },
                    );
                    return Ok(VerificationGateDisposition::Finish {
                        outcome: Outcome::HarnessError,
                        guidance: None,
                    });
                }
                let rolled_back = self.rollback_after_verification_failure().await?;
                let convergence_request =
                    convergence.verification_failed(rolled_back, structural_regression);
                // Only a real candidate/test failure consumes the bounded model-fix allowance.
                self.state.consume_test_failure();
                if recovery == iteron_verify::VerificationRecoveryAction::StopExhausted {
                    self.verification_repair_exhausted(turn);
                    let notice = format!(
                        "verify gate: `{command}` test failure on attempt {} of {max_verify_attempts}; ceiling reached, stopping",
                        self.state.attempts()
                    );
                    self.emit(
                        turn,
                        EventKind::Notice {
                            text: notice.clone(),
                        },
                    );
                    self.ui(UiEvent::Notice(notice));
                    return Ok(VerificationGateDisposition::Finish {
                        outcome: Outcome::BudgetExhausted("verify_attempts"),
                        guidance: None,
                    });
                }

                debug_assert!(matches!(
                    recovery,
                    iteron_verify::VerificationRecoveryAction::RetryReplan
                        | iteron_verify::VerificationRecoveryAction::RetryRepair
                ));
                self.verification_repair_started(turn);
                let recovery_instruction =
                    if recovery == iteron_verify::VerificationRecoveryAction::RetryReplan {
                        "Replan as needed, fix the remaining issues, and continue."
                    } else {
                        "Keep the current plan, fix the failing candidate, and retry."
                    };
                let guidance = format!(
                    "Verification found a test failure: the harness ran `{command}` successfully, \
                     but the candidate did not pass. Do not claim the task is done. \
                     {recovery_instruction}{}{}\n\n{detail}",
                    if rolled_back {
                        " The operator-authorised workspace rollback was applied before this repair turn."
                    } else {
                        ""
                    },
                    convergence_request
                        .map(|request| format!("\n\n{}", request.instruction))
                        .unwrap_or_default()
                );
                self.emit(
                    turn,
                    EventKind::Notice {
                        text: format!(
                            "verify gate: `{command}` test failure, continuing (attempt {})",
                            self.state.attempts()
                        ),
                    },
                );
                self.ui(UiEvent::Notice(format!(
                    "verify gate: `{command}` test failure, continuing"
                )));
                Ok(VerificationGateDisposition::Retry(guidance))
            }
            iteron_verify::VerificationOutcome::TimedOut => {
                let deadline_exhausted = self.run_deadline_exhausted();
                let notice = if deadline_exhausted {
                    format!(
                        "verify gate: `{command}` timed out at the absolute run deadline; stopping"
                    )
                } else {
                    format!(
                        "verify gate: `{command}` timed out before producing a verdict; stopping without consuming a test-failure retry"
                    )
                };
                self.emit(
                    turn,
                    EventKind::Notice {
                        text: notice.clone(),
                    },
                );
                self.ui(UiEvent::Notice(notice));
                Ok(VerificationGateDisposition::Finish {
                    outcome: if deadline_exhausted {
                        Outcome::BudgetExhausted("max_wall_secs")
                    } else {
                        Outcome::HarnessError
                    },
                    guidance: Some(format!(
                        "Verification timed out while running `{command}`. This was not classified \
                         as a test failure and consumed no candidate-fix retry. On resume, re-check \
                         completion.\n\n{detail}"
                    )),
                })
            }
            iteron_verify::VerificationOutcome::InfrastructureFailure => {
                let notice = format!(
                    "verify gate: `{command}` infrastructure failure; stopping without consuming a test-failure retry"
                );
                self.emit(
                    turn,
                    EventKind::Notice {
                        text: notice.clone(),
                    },
                );
                self.ui(UiEvent::Notice(notice));
                Ok(VerificationGateDisposition::Finish {
                    outcome: Outcome::HarnessError,
                    guidance: Some(format!(
                        "Verification infrastructure could not run `{command}`. This was not a \
                         candidate test failure and consumed no candidate-fix retry. Fix the \
                         verification environment before resuming.\n\n{detail}"
                    )),
                })
            }
            iteron_verify::VerificationOutcome::Cancelled => {
                let notice = format!(
                    "verify gate: `{command}` cancelled; stopping at a resumable safe point without consuming a test-failure retry"
                );
                self.emit(
                    turn,
                    EventKind::Notice {
                        text: notice.clone(),
                    },
                );
                self.ui(UiEvent::Notice(notice));
                Ok(VerificationGateDisposition::Cancelled(format!(
                    "Verification of `{command}` was cancelled before a verdict. It consumed no \
                     candidate-fix retry. On resume, re-check completion.\n\n{detail}"
                )))
            }
        }
    }

    pub(super) fn prepare_rollback_point(&mut self, turn: TurnId) -> Result<(), KernelError> {
        if self.state.policy().restore.mode == iteron_verify::VerificationRollbackMode::Off {
            return Ok(());
        }
        self.checkpoint_at_turn_end(turn, true)?;
        self.state.capture_pre_submission(self.checkpoints);
        Ok(())
    }
    fn checkpoint_before_verification(&mut self, turn: TurnId) -> Result<(), KernelError> {
        if !self.state.policy().checkpoint.before_verification
            || !self
                .checkpoints
                .interval_elapsed(turn, self.state.policy().checkpoint.minimum_turn_interval)
        {
            return Ok(());
        }
        self.checkpoint_at_turn_end(turn, true)
    }
    pub(super) fn checkpoint_at_turn_end(
        &mut self,
        turn: TurnId,
        required: bool,
    ) -> Result<(), KernelError> {
        WorkspaceCheckpoint {
            owner: self.checkpoints,
            rollout: self.journal.rollout,
            effects: self.journal.effects,
            ledger: self.journal.ledger,
            record_failed: self.journal.record_failed,
            diagnostics: self.journal.diagnostics,
            #[cfg(test)]
            fault: self.journal.fault,
            scope: CheckpointScope {
                turn,
                workspace: self.scope.workspace,
                runtime_state: self.scope.runtime_state,
                activity: self.scope.activity.clone(),
                lifecycle: self.scope.events.lifecycle.clone(),
                hooks: self.scope.events.lifecycle_hooks.clone(),
                correlation: self.scope.events.correlation.clone(),
            },
        }
        .create(required)
    }
    pub(super) fn run_time_remaining(&self) -> Option<Duration> {
        self.scope
            .deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }
    fn run_deadline_exhausted(&self) -> bool {
        self.run_time_remaining()
            .is_some_and(|duration| duration.is_zero())
    }
    pub(super) fn ui(&self, event: UiEvent) {
        self.scope.events.present(event);
    }
    pub(super) fn emit(&mut self, turn: TurnId, kind: EventKind) {
        self.journal.observation(turn, kind, &self.scope.events);
    }
    pub(super) fn emit_durable(
        &mut self,
        turn: TurnId,
        kind: EventKind,
    ) -> Result<(), KernelError> {
        self.journal.approval().append(turn, kind)
    }
    pub(super) fn lifecycle_event(
        &self,
        id: &str,
        _turn: Option<TurnId>,
        payload: LifecyclePayload,
    ) {
        self.scope.events.emit(id, None, payload);
    }
    fn verification_repair_started(&self, turn: TurnId) {
        self.repair_event("verification.repair_started", turn);
    }
    fn verification_repair_completed(&self, turn: TurnId) {
        if self.state.attempts() > 0 {
            self.repair_event("verification.repair_completed", turn);
        }
    }
    fn verification_repair_exhausted(&self, turn: TurnId) {
        self.repair_event("verification.repair_exhausted", turn);
    }
    fn repair_event(&self, id: &str, turn: TurnId) {
        self.lifecycle_event(
            id,
            Some(turn),
            LifecyclePayload {
                count: Some(u64::from(self.state.attempts())),
                ..Default::default()
            },
        );
    }
}
/// Detect only verifier text that explicitly reports a parser/load/syntax failure. The signal is
/// used after an earlier executable candidate failed behaviorally, so generic assertion, type, or
/// test failures cannot open the structural-refresh path.
fn verification_detail_is_structural_failure(detail: &str) -> bool {
    let detail = detail.to_ascii_lowercase();
    [
        "syntaxerror",
        "syntax error",
        "parse error",
        "parser error",
        "failed to parse",
        "cannot parse",
        "invalid syntax",
        "unexpected token",
        "unexpected eof",
        "unterminated",
    ]
    .iter()
    .any(|marker| detail.contains(marker))
}

#[cfg(test)]
mod structural_failure_tests {
    use super::verification_detail_is_structural_failure;

    #[test]
    fn explicit_parser_diagnostics_are_structural() {
        for detail in [
            "SyntaxError: Unexpected token '{'",
            "parser error: unexpected EOF",
            "failed to parse module: unterminated string",
            "invalid syntax at line 4",
        ] {
            assert!(
                verification_detail_is_structural_failure(detail),
                "{detail}"
            );
        }
    }

    #[test]
    fn behavior_and_type_failures_are_not_structural() {
        for detail in [
            "expected project class, received delivery class",
            "assertion failed: prefix must be PB",
            "type mismatch: expected string",
            "test suite failed with exit code 2",
        ] {
            assert!(
                !verification_detail_is_structural_failure(detail),
                "{detail}"
            );
        }
    }
}
