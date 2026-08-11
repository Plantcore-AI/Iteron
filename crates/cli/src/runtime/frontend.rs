use super::*;

/// Collapse, redact, and bound a workflow label before it crosses the frontend seam.
pub(super) fn ui_workflow_label(content: &str) -> String {
    let one_line = content.split_whitespace().collect::<Vec<_>>().join(" ");
    let scrubbed = iteron_record::redact::scrub(&one_line);
    strict_utf8_head(&scrubbed, 240)
}

impl Agent {
    pub(crate) fn current_turn_id(&self) -> iteron_protocol::TurnId {
        iteron_protocol::TurnId(self.seq_turn)
    }

    pub(crate) fn interrupt_handle(&self) -> Option<std::sync::Arc<std::sync::atomic::AtomicBool>> {
        self.interrupt.clone()
    }

    /// Settle the cooperative interrupt used by an idle, frontend-owned control request.
    ///
    /// `/compact` and `/side` can enter provider or Hook work without opening a normal turn. Their
    /// Ctrl-C path therefore has no `RunEnded` boundary to clear the shared flag. The App Server
    /// calls this only after that standalone request has produced its authoritative reply; normal
    /// turn interrupts remain owned by `finish_requested_control` and the EQ terminal event.
    pub(crate) fn settle_standalone_control_interrupt(&mut self) {
        self.interrupt_requested = false;
        if let Some(interrupt) = &self.interrupt {
            interrupt.store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }

    pub(crate) fn drain_handle(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        self.drain.clone()
    }

    /// Install a cooperative interrupt flag. When it flips true (e.g. from a Ctrl-C handler),
    /// any in-flight provider turn is cancelled mid-stream (D1-16) and the run then stops. No
    /// effect is left half-committed and the run is resumable; the turn is not atomic with
    /// respect to the interrupt.
    pub fn set_interrupt(&mut self, flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        self.interrupt = Some(flag);
    }

    /// Install the session drain flag. Provider streams and admitted tools race it at the same
    /// bounded polling boundary as interrupt; descendants also observe it at their safe points.
    pub fn set_drain(&mut self, flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        self.drain = flag;
        self.owns_drain = true;
    }

    /// Install a typed diagnostic evidence port. Payloads are content-free and emissions are
    /// capped across this agent and all descendants; the kernel itself performs no diagnostic IO.
    pub fn set_diagnostic_port(&mut self, port: diagnostics::DiagnosticPort) {
        self.diagnostics = self.diagnostics.with_port(port);
    }

    /// Route run events to a frontend. Presentation and stateful redaction belong at that seam.
    pub fn set_ui(&mut self, tx: tokio::sync::mpsc::UnboundedSender<UiEvent>) {
        self.ui_tx = Some(tx);
    }

    pub(super) fn ui(&self, e: UiEvent) {
        if let Some(tx) = &self.ui_tx {
            let _ = tx.send(e);
        }
    }

    /// Route QuickJS workflow-script progress to a frontend that renders the live phase→agent tree
    /// (ADR-0001 step 1). Separate from [`Self::set_ui`] because the two carry different contracts;
    /// see [`Self::workflow_progress_tx`]. A frontend that wants neither installs neither.
    pub fn set_workflow_progress(
        &mut self,
        tx: tokio::sync::mpsc::UnboundedSender<crate::workflow::WorkflowRunUiEvent>,
    ) {
        self.workflow_progress_tx = Some(tx);
    }

    pub(super) fn workflow_progress(&self, event: crate::workflow::WorkflowRunUiEvent) {
        if let Some(tx) = &self.workflow_progress_tx {
            let _ = tx.send(event);
        }
    }

    /// Install the owner that starts the runs the `Workflow` tool prepares.
    ///
    /// An embedder that installs nothing keeps the kernel's own in-turn start, which is exactly
    /// `WorkflowEngine::launch`; see [`Self::workflow_launcher`] for what a launcher can and cannot
    /// decide.
    ///
    /// `app_server::serve` installs [`crate::workflow::WorkflowSupervisor`] here. The one-shot and
    /// `--output-format` paths install nothing, and therefore keep in-turn runs — which is why a
    /// `background` request is a request and not a promise.
    pub fn set_workflow_launcher(
        &mut self,
        launcher: std::sync::Arc<dyn crate::workflow::WorkflowLauncher>,
    ) {
        self.workflow_launcher = Some(launcher);
    }

    /// The final assistant text from the most recently completed model turn. Frontends use this
    /// read-only view to build an authoritative terminal result without parsing streamed deltas.
    pub fn last_assistant_text(&self) -> &str {
        &self.last_assistant_text
    }

    /// Continue an already-run agent with a new operator message (TUI follow-up). The prior
    /// transcript is the one this process just produced. A follow-up is a new submission, not a
    /// crash-recovery continuation, so Ultracode may orchestrate it.
    pub async fn follow_up(&mut self, text: &str) -> Result<Outcome, KernelError> {
        self.stage_follow_up_transcript().await?;
        self.verify_attempts = 0;
        self.run(text).await
    }

    /// Continue from a supervisor-owned task notification. This is a model turn, but not a new
    /// operator task, so Ultracode must not recursively launch another workflow for it.
    pub async fn follow_up_runtime_notification(
        &mut self,
        text: &str,
    ) -> Result<Outcome, KernelError> {
        self.stage_follow_up_transcript().await?;
        self.verify_attempts = 0;
        self.run_with_images_mode(text, Vec::new(), false, None)
            .await
    }

    /// Stage the transcript a follow-up continues from.
    ///
    /// A follow-up is not a resume. This process ran the previous turns and still holds the exact
    /// working set they produced, so it continues from memory. Rebuilding it meant replaying and
    /// SHA-256-verifying the whole rollout, and then doing it a SECOND time inside `set_resume` — at
    /// the 64 MiB rollout ceiling roughly half a second of blocking parse and hashing between two
    /// operator messages, growing with the session. Every piece of state `set_resume` restores from
    /// the record (ledger, ceilings, runtime policy, turn/approval ids, taint) is already live and
    /// strictly richer here; the record stays the authority for the paths that cross a process
    /// boundary — `--resume`, fork, crash recovery — and those still call `set_resume`.
    pub(super) async fn stage_follow_up_transcript(&mut self) -> Result<(), KernelError> {
        let Some(working) = self.working_set.take() else {
            // Nothing has run in this process yet, so the record is the only transcript there is.
            let path = self.rollout.path().to_path_buf();
            let prior = Self::messages_from_rollout(&path)?;
            return self.set_resume(prior);
        };
        self.budget.validate().map_err(KernelError::InvalidBudget)?;
        // Turn ids are canonical effect/correlation identities, not an invocation-local counter, so
        // the follow-up must open a NEW one exactly as `set_resume` does when it continues after the
        // greatest durable id. In this process the live counter already IS that greatest id — the
        // run loop leaves it on the turn it finished — so the successor is one step on, no replay
        // needed. Skipping this reused the finished turn, and at-most-once dispatch then refused the
        // follow-up's first provider effect as an identity it had already admitted.
        self.advance_turn().await?;
        // An interrupted or errored run can leave a trailing assistant message whose tool_use was
        // never answered. Repair it exactly as the replay path does, or the provider rejects the
        // next request.
        self.resumed = Some(reconcile_transcript(working));
        Ok(())
    }
}
