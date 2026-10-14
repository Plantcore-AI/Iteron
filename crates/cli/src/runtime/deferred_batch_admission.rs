//! Actual deferred group predispatch admission. One concrete control/Hook/journal boundary precedes
//! the existing physical batch owner; denied calls settle without a tool intent or executor.
use super::KernelError;
use super::approval_wait::ApprovalJournal;
use super::control_ingress::ControlIngress;
use super::deferred_tool_batch::{DeferredToolBatch, DeferredToolScope};
use super::deferred_tools::AutoApprovedCall;
use super::force_cancel::ForceCancelSeam;
use super::hook_execution::HookExecution;
use super::session_control::{InboundControl, SessionControlState};
use super::session_inbox::SessionSubmissionInbox;
use super::tool_execution_journal::ToolExecutionJournal;
use super::tool_images::PendingToolImageProjection;
use super::tool_presentation::tool_end_ui;
use iteron_protocol::{LifecyclePayload, ToolResult, Trust};
use std::time::Instant;

pub(super) struct DeferredBatchAdmission<'a> {
    pub(super) journal: ToolExecutionJournal<'a>,
    pub(super) scope: DeferredToolScope<'a>,
    pub(super) inbox: &'a mut SessionSubmissionInbox,
    pub(super) control: &'a mut SessionControlState,
    pub(super) force_cancel: Option<&'a mut ForceCancelSeam>,
    pub(super) deadline: Option<Instant>,
}

#[cfg(test)]
#[path = "deferred_batch_admission_tests.rs"]
mod tests;
impl DeferredBatchAdmission<'_> {
    pub(super) async fn run(
        mut self,
        batch: Vec<AutoApprovedCall>,
        results: &mut [Option<ToolResult>],
        any_error: &mut bool,
        images: &mut Vec<PendingToolImageProjection>,
    ) -> Result<(), KernelError> {
        self.poll_control();
        if self.refused() {
            return Ok(());
        }
        let admitted = HookExecution {
            rollout: &mut *self.journal.rollout,
            effects: &mut *self.journal.effects,
            record_failed: &mut *self.journal.record_failed,
            ledger: &mut *self.journal.ledger,
            diagnostics: self.journal.diagnostics,
            #[cfg(test)]
            fault: &mut *self.journal.fault,
            scope: self.scope.hooks.clone(),
        }
        .gate_batch(batch)
        .await?;
        for denied in admitted.denied {
            let admitted = denied.admitted;
            // The finite result envelope remains structural authority; no unchecked index can
            // publish a result or substitute another declaration after the hook has run.
            if admitted.index >= results.len() || results[admitted.index].is_some() {
                return Err(KernelError::EffectBoundary(
                    "hook-denied batch result has no empty admitted slot".into(),
                ));
            }
            let result = ToolResult {
                tool_use_id: admitted.call.id.clone(),
                content: format!(
                    "tool `{}` blocked by a tool gate hook: {}",
                    admitted.call.name, denied.reason
                ),
                is_error: true,
                trust: Trust::Workspace,
                latency_ms: 0,
            };
            self.journal.refused_result(
                self.scope.turn,
                &admitted.call.name,
                &result,
                "refused_before_dispatch",
                &self.scope.events,
            )?;
            self.scope
                .events
                .present(tool_end_ui(&admitted.call, &result));
            results[admitted.index] = Some(result);
            *any_error = true;
            self.scope
                .events
                .emit("hook.blocked", None, LifecyclePayload::default());
        }
        if admitted.allowed.is_empty() {
            return Ok(());
        }
        // An executable hook may have awaited long enough for real control/deadline state to
        // change. Refuse fresh group intents at that safe point; the ordered tail owns them.
        self.poll_control();
        if self.refused() {
            return Ok(());
        }
        DeferredToolBatch {
            journal: self.journal,
            scope: self.scope,
        }
        .execute(admitted.allowed, results, any_error, images)
        .await
    }
    fn refused(&self) -> bool {
        *self.journal.record_failed
            || self
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
            || self.control.requested() != InboundControl::None
    }
    fn poll_control(&mut self) {
        ControlIngress {
            journal: ApprovalJournal {
                rollout: &mut *self.journal.rollout,
                ledger: &mut *self.journal.ledger,
                record_failed: &mut *self.journal.record_failed,
                diagnostics: self.journal.diagnostics,
                #[cfg(test)]
                fault: &mut *self.journal.fault,
            },
            inbox: &mut *self.inbox,
            control: &mut *self.control,
            force_cancel: self.force_cancel.as_deref_mut(),
            events: self.scope.events.clone(),
        }
        .poll(
            self.scope.turn,
            super::inbound_control::inbound_poll_limit(),
        );
    }
}
