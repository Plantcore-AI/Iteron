//! Thin composition for real approval, cancellation and finalization owners. These adapters bind
//! existing permission/checkpoint/maintenance ports; the asynchronous controllers do not borrow Agent.
use super::approval_wait::{ApprovalJournal, ApprovalRequest, ApprovalWait};
use super::control_terminal::ControlTerminal;
use super::run_finalization::{FinalizationScope, RunFinalization};
use super::session_control::InboundControl;
use super::tool_presentation::{
    strict_utf8_head, ui_approval_arguments, ui_verification_rollback_arguments,
};
use super::{Agent, KernelError, UiEvent, workspace_checkpoint};
use iteron_protocol::{
    Capability, LifecyclePayload, Outcome, Phase, RuntimePolicySource, SubmissionId, ToolUse,
    TurnId,
};
use std::sync::atomic::{AtomicBool, Ordering};

impl Agent {
    pub(super) async fn finish_requested_control(
        &mut self,
        turn: TurnId,
    ) -> Result<Option<Outcome>, KernelError> {
        let requested = self.control.requested();
        let events = self.tool_events(turn);
        let Some(terminal) = (ControlTerminal {
            seam: self.force_cancel_seam.as_mut(),
            activity: self.activity.clone(),
            events,
        })
        .resolve(turn, requested)
        .await
        else {
            return Ok(None);
        };
        let outcome = if terminal.drained() {
            self.finish_drained(turn).await?
        } else {
            self.finish(turn, terminal.outcome()).await?
        };
        terminal.acknowledge(turn, &outcome, &mut self.control);
        Ok(Some(outcome))
    }
    pub(super) fn requested_control(&self) -> InboundControl {
        self.control.requested()
    }
    pub(super) async fn collect_and_finish_requested_control(
        &mut self,
        turn: TurnId,
    ) -> Result<Option<Outcome>, KernelError> {
        let _ = self.collect_inbound_ops(turn);
        self.finish_requested_control(turn).await
    }
    /// Re-publish only this waiting turn's canonical stop onto its own children. Detached agents
    /// retain their separate lifetime controls and are never cancelled by this local handoff.
    pub(super) fn pump_child_stop(&mut self, stop: &AtomicBool) -> InboundControl {
        let _ = self.collect_inbound_ops(TurnId(self.seq_turn));
        let control = self.control.requested();
        if control.interrupts() {
            stop.store(true, Ordering::Relaxed);
        }
        control
    }
    pub(super) fn checkpoint_at_turn_end(
        &mut self,
        turn: TurnId,
        required: bool,
    ) -> Result<(), KernelError> {
        let scope = workspace_checkpoint::CheckpointScope {
            turn,
            workspace: &self.workspace,
            runtime_state: &self.runtime_state_dir,
            activity: self.activity.clone(),
            lifecycle: self.lifecycle_emitter.clone(),
            hooks: self.lifecycle_hooks.clone(),
            correlation: self.lifecycle_correlation(Some(turn)),
        };
        workspace_checkpoint::WorkspaceCheckpoint {
            owner: &mut self.workspace_checkpoints,
            rollout: &mut self.rollout,
            effects: &mut self.effect_journal,
            ledger: &mut self.ledger,
            record_failed: &mut self.record_failed,
            diagnostics: &self.diagnostics,
            #[cfg(test)]
            fault: &mut self.fail_next_durable_append,
            scope,
        }
        .create(required)
    }
    pub(super) async fn finish_drained(&mut self, turn: TurnId) -> Result<Outcome, KernelError> {
        // The Plantcore worker owns its durable outbox. An ordinary session must commit its
        // existing Git recovery point before the absorbing drain terminal can be acknowledged.
        if !self.plantcore_runtime_enabled() {
            if !self.verification_policy.checkpoint.before_drain {
                return Err(KernelError::ContextResolution("resolved verification checkpoint policy attempted to disable the mandatory drain recovery point".into()));
            }
            self.checkpoint_at_turn_end(turn, true)?;
        }
        let outcome = self.finish(turn, Outcome::Drained).await?;
        self.control.clear_drain_after_terminal();
        Ok(outcome)
    }
    pub(super) async fn finish(
        &mut self,
        turn: TurnId,
        mut outcome: Outcome,
    ) -> Result<Outcome, KernelError> {
        self.publish_captured_answer();
        if outcome == Outcome::Done && self.complete_plantcore_product().is_err() {
            outcome = Outcome::HarnessError;
        }
        let best_effort_checkpoint = outcome != Outcome::Drained
            && (self.verify_command.is_some() || outcome == Outcome::Interrupted)
            && self.verification_policy.checkpoint.turn_boundary
            && (self.effect_journal.workspace_mutated() || outcome == Outcome::Interrupted)
            && self.verification_checkpoint_interval_elapsed(turn);
        // Usually initialized by actual admission. The same physical recovery owner remains
        // authoritative for legacy fixtures/embedders; no new recorder or fresh budget is minted.
        let _ = self.ensure_policy_evidence()?;
        let events = self.tool_events(turn);
        let usage_unavailable = self.plantcore_terminal()
            == Some(super::plantcore::PlantcoreTerminal::UsageUnavailable);
        let finalized = (RunFinalization {
            rollout: &mut self.rollout,
            ledger: &mut self.ledger,
            record_failed: &mut self.record_failed,
            diagnostics: &self.diagnostics,
            effects: &mut self.effect_journal,
            checkpoints: &mut self.workspace_checkpoints,
            terminal: &mut self.terminal_record,
            policy: self.policy_evidence.as_mut(),
            publications: &mut self.turn_publications,
            #[cfg(test)]
            fault: &mut self.fail_next_durable_append,
            scope: FinalizationScope {
                turn,
                workspace: &self.workspace,
                runtime_state: &self.runtime_state_dir,
                best_effort_checkpoint,
                usage_unavailable,
                activity: self.activity.clone(),
                events,
            },
        })
        .commit(outcome)
        .await?;
        self.publish_finalized_turn(finalized.turn(), finalized.source(), finalized.fact());
        if finalized.outcome() == &Outcome::Done {
            self.persist_last_success_route(turn);
        }
        if !self.persist_token_calibration() {
            self.lifecycle_event(
                "context.tokenizer.error_calculated",
                Some(turn),
                LifecyclePayload {
                    outcome_code: Some("calibration_persist_failed".into()),
                    ..Default::default()
                },
            );
        }
        let activity = self.activity.span(
            super::turn_activity::ActivityStage::Finalization,
            Some(turn),
        );
        self.ui(UiEvent::Phase(Phase::Idle));
        self.ui(UiEvent::Done(format!("{:?}", finalized.outcome())));
        activity.complete();
        Ok(finalized.into_outcome())
    }
    pub(super) async fn await_approval(
        &mut self,
        turn: TurnId,
        call: &ToolUse,
        cap: Capability,
    ) -> Result<bool, KernelError> {
        self.approval_seq = self
            .approval_seq
            .checked_add(1)
            .ok_or(KernelError::IdentityExhausted("approval"))?;
        let arguments = if call.name == "verification_rollback" {
            ui_verification_rollback_arguments(&call.input).ok_or_else(|| {
                KernelError::ContextResolution(
                    "verification rollback approval carried an invalid structural binding".into(),
                )
            })?
        } else {
            match if self.ordinary_extensions.is_some() {
                self.registry.ordinary_call_projection(call)
            } else {
                Ok(None)
            } {
                Ok(Some(physical)) => ui_approval_arguments(&physical.input),
                Ok(None) => ui_approval_arguments(&call.input),
                Err(_) => {
                    return Err(KernelError::OrdinaryExtension(
                        "ordinary tool arguments could not be resolved for approval",
                    ));
                }
            }
        };
        let request = ApprovalRequest {
            turn,
            id: SubmissionId(self.approval_seq),
            call_id: strict_utf8_head(&call.id, 2048),
            tool: call.name.clone(),
            capability: cap,
            arguments,
            workspace: strict_utf8_head(
                &iteron_record::redact::scrub(&self.workspace.display().to_string()),
                2048,
            ),
            reason: self.registry.operation_effects(call).map_or_else(
                || {
                    "session policy requires an explicit operator decision before this effect"
                        .into()
                },
                |effects| {
                    format!(
                        "{}; required authority: {:?}",
                        effects.reason,
                        effects.required.iter().collect::<Vec<_>>()
                    )
                },
            ),
            interactive: self.interactive_approvals,
            deadline: self.run_deadline.current(),
            poll: iteron_tunables::param_duration(
                "cli.runtime.inbound_drain_poll_interval",
                super::INBOUND_DRAIN_POLL_INTERVAL,
            ),
        };
        let events = self.tool_events(turn);
        let wait_events = self.tool_events(turn);
        let decision = (ApprovalWait {
            journal: ApprovalJournal {
                rollout: &mut self.rollout,
                ledger: &mut self.ledger,
                record_failed: &mut self.record_failed,
                diagnostics: &self.diagnostics,
                #[cfg(test)]
                fault: &mut self.fail_next_durable_append,
            },
            inbox: &mut self.inbox,
            control: &mut self.control,
            force_cancel: self.force_cancel_seam.as_mut(),
            activity: self.activity.clone(),
            events: wait_events,
        })
        .run(request)
        .await?;
        if decision.remember {
            let mut rules = self.permission_rules.clone();
            rules.allow_cap(cap);
            if let Err(error) = self.transition_permission_policy(
                self.permission_mode,
                rules,
                RuntimePolicySource::ApprovalRemember,
            ) {
                decision.policy_persist_failed(&events);
                return Err(error);
            }
        }
        decision.publish(&events)
    }
}

#[cfg(test)]
#[path = "terminal_runtime_tests.rs"]
mod tests;
