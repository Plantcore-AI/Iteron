//! Actual Main Agent lease, mailbox safe points and terminal settlement. Authority stays in the
//! installed host; input envelopes are ordinary low-trust data in the real thread journal.
use super::persistent_agents::{AgentControlPort, AgentSettlement, ParentRuntimeTurn};
use super::{Agent, KernelError, merge_adjacent_user_message, persistent_agent_kernel};
use iteron_agents::{AgentWorkflowTerminal, ControllerError};
use iteron_protocol::{EventKind, Message, Outcome, Trust, TurnId};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

pub(super) struct ParentTurnGuard {
    control: Arc<dyn AgentControlPort>,
    turn: ParentRuntimeTurn,
    old_interrupt: super::session_control::InterruptSignalBinding,
    deadline: Option<super::execution_deadline::DeadlineLease>,
    settled: bool,
}
impl Drop for ParentTurnGuard {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        // Future drop/panic is not a cleanup proof. Keep the durable lease quarantined, including
        // physical reservations and Delivered envelopes, rather than silently resetting it.
        let _ = self.control.finish_parent_turn(
            &self.turn,
            &AgentSettlement {
                turns: 0,
                summary: "Main execution dropped; physical recovery is required".into(),
                tokens: 0,
                cost_microusd: 0,
                effects_known: false,
                accounting_known: false,
                terminal: AgentWorkflowTerminal::StoppedRecovery,
            },
            self.elapsed(),
        );
    }
}
impl ParentTurnGuard {
    fn elapsed(&self) -> u64 {
        self.turn.elapsed_ms()
    }
}
impl Agent {
    pub(super) fn begin_parent_runtime_bridge(
        &mut self,
        task: &str,
    ) -> Result<Option<ParentTurnGuard>, KernelError> {
        self.require_installed_cohort()?;
        let Some(control) = self.persistent_agents.clone() else {
            return Ok(None);
        };
        if self.persistent_mailbox.is_some() {
            return Err(KernelError::AgentControl(ControllerError::StaleEpoch));
        }
        let old_interrupt = self.control.interrupt_binding();
        let signal = old_interrupt
            .flag()
            .cloned()
            .unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
        // This exact descriptor identifies the existing thread submission. The original task is
        // admitted by the normal Message WAL; this marker adds no duplicate instruction authority.
        let source = format!(
            "Main thread task source sha256:{:x}; this descriptor carries no instruction authority.",
            Sha256::digest(task.as_bytes())
        );
        let turn = control
            .begin_parent_turn(source, signal.clone())
            .map_err(KernelError::AgentControl)?;
        let remaining = turn
            .view
            .budget
            .wall_ms
            .saturating_sub(turn.view.usage.wall_ms)
            .saturating_sub(turn.elapsed_ms());
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(remaining))
            .unwrap_or_else(Instant::now);
        let mut guard = ParentTurnGuard {
            control,
            turn,
            old_interrupt,
            deadline: None,
            settled: false,
        };
        guard.deadline = Some(self.run_deadline.tighten(deadline)?);
        if guard.old_interrupt.flag().is_none() {
            self.control.bind_interrupt(signal);
        }
        self.persistent_mailbox = Some(guard.turn.mailbox.clone());
        if let Err(error) = persistent_agent_kernel::expire_restored(self, &guard.turn.mailbox) {
            self.persistent_mailbox = None;
            self.control
                .restore_interrupt_binding(guard.old_interrupt.clone());
            return Err(error);
        }
        Ok(Some(guard))
    }

    /// Called at the real driver boundary before context projection. No UI queue is replaced.
    pub(super) fn admit_parent_mailbox(
        &mut self,
        turn: TurnId,
        messages: &mut Vec<Message>,
    ) -> Result<(), KernelError> {
        if self.persistent_agents.is_none() {
            return Ok(());
        }
        let Some(mailbox) = self.persistent_mailbox.clone() else {
            return Ok(());
        };
        if mailbox.stop_requested() {
            return Ok(());
        }
        let inputs = mailbox.receive().map_err(KernelError::AgentControl)?;
        for input in inputs {
            let text = mailbox.render(&input).map_err(KernelError::AgentControl)?;
            if let Some(admission) = mailbox
                .source_admission(std::slice::from_ref(&input), &text)
                .map_err(KernelError::AgentControl)?
            {
                self.emit_durable(
                    turn,
                    EventKind::AgentInputAdmittedV1 {
                        admission: admission.clone(),
                    },
                )?;
                self.observed_trust = self.observed_trust.min(Trust::Untrusted);
                mailbox
                    .confirm_source_admission(&admission)
                    .map_err(KernelError::AgentControl)?;
            }
            let message = Message::user_text(text);
            self.emit_durable(
                turn,
                EventKind::Message {
                    message: message.clone(),
                },
            )?;
            // Sibling/child text never creates operator, capability, tool or write authority.
            if input.sender.is_some() {
                self.observed_trust = self.observed_trust.min(Trust::Untrusted);
            }
            // Preserve the original task's component admission and provider role alternation.
            // This exact host envelope is still matched as an intact text block by the receipt.
            merge_adjacent_user_message(messages, message);
            self.context_estimator.invalidate_transcript();
        }
        Ok(())
    }

    /// Every controller-owned task proves physical process cleanup before returning a known
    /// settlement. A timeout or an Unknown terminal is retained as recovery, never as successful reap.
    pub(super) async fn settle_persistent_owned_processes(&self) -> bool {
        let Some(processes) = self.registry.process_control() else {
            return true;
        };
        if !matches!(
            tokio::time::timeout(Duration::from_secs(5), processes.clean()).await,
            Ok(Ok(_))
        ) {
            return false;
        }
        let health = processes.health();
        health.active_jobs == 0 && health.cleanup_unknown_jobs == 0
    }

    pub(super) async fn finish_parent_runtime_bridge(
        &mut self,
        guard: Option<ParentTurnGuard>,
        outcome: &Result<Outcome, KernelError>,
    ) -> Result<(), KernelError> {
        let Some(mut guard) = guard else {
            return Ok(());
        };
        let processes = self.settle_persistent_owned_processes().await;
        let expired =
            persistent_agent_kernel::expire_unrequested(self, &guard.turn.mailbox).is_ok();
        let terminal = match outcome {
            Ok(Outcome::Done) => AgentWorkflowTerminal::Succeeded,
            Ok(Outcome::Interrupted | Outcome::Drained) => AgentWorkflowTerminal::Cancelled,
            _ => AgentWorkflowTerminal::Failed,
        };
        let summary = match outcome {
            Ok(outcome) => format!("Main task settled: {outcome:?}"),
            Err(error) => error.public_summary(),
        };
        let result = guard.control.finish_parent_turn(
            &guard.turn,
            &AgentSettlement {
                turns: 0,
                tokens: 0,
                cost_microusd: 0,
                summary: super::strict_utf8_head(
                    &iteron_record::redact::scrub(&summary),
                    iteron_protocol::agent_control::MAX_AGENT_TEXT_BYTES,
                ),
                effects_known: processes && expired && self.parent_effects_known(),
                accounting_known: self.ledger.child_accounting_complete(),
                terminal,
            },
            guard.elapsed(),
        );
        // Even when durable terminalization fails, do not retain a mailbox from a prior epoch in
        // the current Agent. The controller's poisoned/active ownership remains fail-closed.
        self.persistent_mailbox = None;
        self.control
            .restore_interrupt_binding(guard.old_interrupt.clone());
        // The host retains this exact physical proof for bounded retry. Drop must never replace
        // a known terminal with an invented Unknown merely because its final append was refused.
        guard.settled = true;
        result.map_err(KernelError::AgentControl)
    }
}
