use super::*;

/// Byte ceiling for a workflow label on the frontend seam: one collapsed line a terminal can show
/// without wrapping, not a transcript excerpt.
const WORKFLOW_LABEL_MAX_BYTES: usize = 240;

const AUTHORITATIVE_UI_BACKLOG_CAPACITY: usize = 256;
/// Shared heap ceiling for the normal runtime UI lane and its structural overflow lane. The EQ has
/// its own equal-sized budget; this one prevents the bridge *before* the EQ from multiplying that
/// bound by two variable-sized queues.
const FRONTEND_UI_BYTE_CAPACITY: usize = 64 * 1024 * 1024;

fn authoritative_ui_backlog_capacity() -> usize {
    iteron_tunables::param_integer(
        "cli.runtime.frontend.authoritative_ui_backlog_capacity",
        AUTHORITATIVE_UI_BACKLOG_CAPACITY,
    )
    .clamp(1, AUTHORITATIVE_UI_BACKLOG_CAPACITY)
}

fn frontend_ui_byte_capacity() -> usize {
    iteron_tunables::param_integer(
        "cli.runtime.frontend.frontend_ui_byte_capacity",
        FRONTEND_UI_BYTE_CAPACITY,
    )
    .clamp(1, FRONTEND_UI_BYTE_CAPACITY)
}

/// Fixed conservative heap-accounting term. Changing it through a profile could under-charge the
/// aggregate byte budget, so its distinct type makes the census retain it as read-only structure.
struct EnvelopeAccountingBytes(usize);
const ENVELOPE: EnvelopeAccountingBytes = EnvelopeAccountingBytes(512);

fn ui_event_heap_bytes(event: &UiEvent) -> usize {
    ENVELOPE.0.saturating_add(match event {
        UiEvent::Text(text)
        | UiEvent::Thinking(text)
        | UiEvent::Notice(text)
        | UiEvent::Done(text) => text.len(),
        UiEvent::ToolStart { id, name, args } => id
            .len()
            .saturating_add(name.len())
            .saturating_add(serde_json::to_vec(args).map_or(0, |bytes| bytes.len())),
        UiEvent::ToolEnd {
            id, output, diff, ..
        } => id
            .len()
            .saturating_add(output.len())
            .saturating_add(serde_json::to_vec(diff).map_or(0, |bytes| bytes.len())),
        UiEvent::Workflow(workflow) => {
            serde_json::to_vec(workflow).map_or(64 * 1024, |bytes| bytes.len())
        }
        UiEvent::ApprovalRequest {
            tool,
            reason,
            arguments,
            workspace,
            ..
        } => tool
            .len()
            .saturating_add(reason.len())
            .saturating_add(workspace.len())
            .saturating_add(serde_json::to_vec(arguments).map_or(0, |bytes| bytes.len())),
        UiEvent::Phase(_) | UiEvent::TurnEnd { .. } | UiEvent::SteerApplied { .. } => 4 * 1024,
    })
}

#[derive(Debug)]
struct FrontendUiByteBudget {
    capacity: usize,
    enabled: std::sync::atomic::AtomicBool,
    used: std::sync::Mutex<usize>,
}

impl FrontendUiByteBudget {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            enabled: std::sync::atomic::AtomicBool::new(false),
            used: std::sync::Mutex::new(0),
        }
    }

    fn enable(&self) {
        self.enabled
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Reserve bytes before either pre-EQ lane accepts an event. This producer seam is deliberately
    /// nonblocking: it can run on the same Tokio task that drains the AppServer consumer, so waiting
    /// for room here would deadlock the only task able to release it. A false return is an exact
    /// refusal; stream deltas are repaired by `RunEnded`, while structural callers observe failure.
    fn try_reserve(&self, bytes: usize) -> bool {
        if !self.enabled.load(std::sync::atomic::Ordering::Acquire) {
            return true;
        }
        if bytes > self.capacity {
            return false;
        }
        let mut used = self
            .used
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if used.saturating_add(bytes) > self.capacity {
            return false;
        }
        *used = used.saturating_add(bytes);
        true
    }

    fn release(&self, bytes: usize) {
        if !self.enabled.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        let mut used = self
            .used
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *used = used.saturating_sub(bytes);
    }

    #[cfg(test)]
    fn used(&self) -> usize {
        *self
            .used
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// The only UI payloads whose omission is repaired by the terminal `RunEnded` authority. Keep the
/// match exhaustive: adding a future structured `UiEvent` must make this policy fail to compile
/// until its delivery semantics are chosen deliberately.
fn is_authoritative_ui_event(event: &UiEvent) -> bool {
    match event {
        UiEvent::Text(_) | UiEvent::Thinking(_) => false,
        UiEvent::ToolStart { .. }
        | UiEvent::ToolEnd { .. }
        | UiEvent::Phase(_)
        | UiEvent::TurnEnd { .. }
        | UiEvent::Workflow(_)
        | UiEvent::SteerApplied { .. }
        | UiEvent::Notice(_)
        | UiEvent::ApprovalRequest { .. }
        | UiEvent::Done(_) => true,
    }
}

/// Structural payloads whose refusal would leave the live frontend with no authoritative account
/// of work that happened. The final Idle/Done pair is different: the App Server publishes the
/// independently authoritative `RunEnded` snapshot immediately afterwards, including the complete
/// assistant text and terminal outcome. Stream deltas have the same terminal reconciliation.
fn refusal_must_fail_run(event: &UiEvent) -> bool {
    match event {
        UiEvent::Text(_) | UiEvent::Thinking(_) | UiEvent::Done(_) => false,
        UiEvent::Phase(Phase::Idle) => false,
        UiEvent::ToolStart { .. }
        | UiEvent::ToolEnd { .. }
        | UiEvent::Phase(_)
        | UiEvent::TurnEnd { .. }
        | UiEvent::Workflow(_)
        | UiEvent::SteerApplied { .. }
        | UiEvent::Notice(_)
        | UiEvent::ApprovalRequest { .. } => true,
    }
}

#[derive(Debug)]
struct AuthoritativeUiBacklog {
    events: std::sync::Mutex<std::collections::VecDeque<UiEvent>>,
    available: tokio::sync::Notify,
}

impl Default for AuthoritativeUiBacklog {
    fn default() -> Self {
        Self {
            events: std::sync::Mutex::new(std::collections::VecDeque::with_capacity(
                authoritative_ui_backlog_capacity(),
            )),
            available: tokio::sync::Notify::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FrontendChannelHealth {
    ui_saturated: std::sync::Arc<std::sync::atomic::AtomicU64>,
    workflow_saturated: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Serializes routing at the producer seam. Once a structural event enters the overflow lane,
    /// later text/thinking cannot jump ahead through a newly freed Tokio slot.
    routing: std::sync::Arc<std::sync::Mutex<()>>,
    authoritative: std::sync::Arc<AuthoritativeUiBacklog>,
    ui_bytes: std::sync::Arc<FrontendUiByteBudget>,
    /// Fail-stop latch consumed before the durable run terminal. Producers may share the AppServer
    /// task and therefore cannot wait for their consumer, but a refused structural event must not
    /// disappear merely because a call site cannot return an error from a provider callback.
    structural_refused: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Default for FrontendChannelHealth {
    fn default() -> Self {
        Self {
            ui_saturated: Default::default(),
            workflow_saturated: Default::default(),
            routing: Default::default(),
            authoritative: Default::default(),
            ui_bytes: std::sync::Arc::new(FrontendUiByteBudget::new(frontend_ui_byte_capacity())),
            structural_refused: Default::default(),
        }
    }
}

impl FrontendChannelHealth {
    fn observe(counter: &std::sync::atomic::AtomicU64) -> u64 {
        counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .saturating_add(1)
    }

    fn ui_saturated(&self) -> u64 {
        Self::observe(&self.ui_saturated)
    }

    fn workflow_saturated(&self) -> u64 {
        Self::observe(&self.workflow_saturated)
    }

    fn ui_saturation_count(&self) -> u64 {
        self.ui_saturated.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn refuse(&self, fail_run: bool) -> bool {
        if fail_run {
            self.structural_refused
                .store(true, std::sync::atomic::Ordering::Release);
        }
        false
    }

    pub(super) fn take_structural_refusal(&self) -> bool {
        self.structural_refused
            .swap(false, std::sync::atomic::Ordering::AcqRel)
    }

    pub(super) fn try_send_ui(
        &self,
        tx: &tokio::sync::mpsc::Sender<UiEvent>,
        event: UiEvent,
    ) -> bool {
        let _routing = self
            .routing
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let authoritative = is_authoritative_ui_event(&event);
        let fail_run = refusal_must_fail_run(&event);
        if self.has_authoritative_pending() {
            if authoritative {
                let bytes = ui_event_heap_bytes(&event);
                if !self.ui_bytes.try_reserve(bytes) {
                    self.ui_saturated();
                    return self.refuse(fail_run);
                }
                if self.try_enqueue_authoritative(event) {
                    return true;
                }
                self.ui_bytes.release(bytes);
                self.ui_saturated();
                return self.refuse(fail_run);
            }
            self.ui_saturated();
            return self.refuse(fail_run);
        }
        let bytes = ui_event_heap_bytes(&event);
        if !self.ui_bytes.try_reserve(bytes) {
            self.ui_saturated();
            return self.refuse(fail_run);
        }
        match tx.try_send(event) {
            Ok(()) => true,
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                self.ui_bytes.release(bytes);
                self.refuse(fail_run)
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(event)) => {
                self.ui_saturated();
                if authoritative {
                    if self.try_enqueue_authoritative(event) {
                        true
                    } else {
                        self.ui_bytes.release(bytes);
                        self.refuse(fail_run)
                    }
                } else {
                    self.ui_bytes.release(bytes);
                    self.refuse(fail_run)
                }
            }
        }
    }

    fn has_authoritative_pending(&self) -> bool {
        !self
            .authoritative
            .events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty()
    }

    /// Try the independent structural overflow lane without ever parking its producer. The normal
    /// channel consumer also drains this queue; a fixed item ceiling plus the shared byte budget
    /// bounds both dimensions. Exhaustion is reported to the caller rather than silently dropping
    /// or synchronously waiting on the same AppServer task.
    fn try_enqueue_authoritative(&self, event: UiEvent) -> bool {
        let mut events = self
            .authoritative
            .events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if events.len() == authoritative_ui_backlog_capacity() {
            return false;
        }
        events.push_back(event);
        drop(events);
        self.authoritative.available.notify_one();
        true
    }

    pub(crate) fn try_pop_authoritative(&self) -> Option<UiEvent> {
        self.authoritative
            .events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop_front()
    }

    pub(crate) async fn recv_authoritative(&self) -> UiEvent {
        loop {
            let available = self.authoritative.available.notified();
            if let Some(event) = self.try_pop_authoritative() {
                return event;
            }
            available.await;
        }
    }

    /// Retain the charge across the App Server's awaited EQ publication even after the payload is
    /// moved into an envelope.
    pub(crate) fn ui_event_bytes(&self, event: &UiEvent) -> usize {
        ui_event_heap_bytes(event)
    }

    pub(crate) fn release_ui_bytes(&self, bytes: usize) {
        self.ui_bytes.release(bytes);
    }

    #[cfg(test)]
    fn release_ui_event(&self, event: &UiEvent) {
        self.release_ui_bytes(self.ui_event_bytes(event));
    }
}

/// Collapse, redact, and bound a workflow label before it crosses the frontend seam.
pub(super) fn ui_workflow_label(content: &str) -> String {
    let one_line = content.split_whitespace().collect::<Vec<_>>().join(" ");
    let scrubbed = iteron_record::redact::scrub(&one_line);
    strict_utf8_head(
        &scrubbed,
        iteron_tunables::param_integer(
            "cli.runtime.frontend.workflow_label_max_bytes",
            WORKFLOW_LABEL_MAX_BYTES,
        ),
    )
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
        self.force_cancel_requested = false;
        self.force_cancel
            .store(false, std::sync::atomic::Ordering::SeqCst);
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

    /// Install the distinct escalated-cancellation authority. A frontend must set this only for an
    /// explicit ForceCancel operation; cooperative Ctrl-C continues to use [`Self::set_interrupt`].
    pub fn set_force_cancel(&mut self, flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        self.force_cancel = flag;
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
    pub fn set_ui(&mut self, tx: tokio::sync::mpsc::Sender<UiEvent>) {
        self.ui_tx = Some(tx);
    }

    pub(crate) fn set_activity(
        &mut self,
        tx: tokio::sync::mpsc::Sender<super::activity::ActivityEvent>,
    ) {
        self.activity.install(tx);
    }

    pub(crate) fn take_pending_activity_terminals(&self) -> Vec<iteron_protocol::ActivityEvent> {
        self.activity.take_pending_terminals()
    }

    pub(crate) fn activity_overflow_port(&self) -> super::activity::ActivitySink {
        self.activity.clone()
    }

    pub(crate) fn activity_sender(
        &self,
    ) -> Option<tokio::sync::mpsc::Sender<iteron_protocol::ActivityEvent>> {
        self.activity.sender()
    }

    pub(super) fn ui(&self, e: UiEvent) -> bool {
        if let Some(tx) = &self.ui_tx {
            let before = self.frontend_saturation.ui_saturation_count();
            let sent = self.frontend_saturation.try_send_ui(tx, e);
            let after = self.frontend_saturation.ui_saturation_count();
            if after != before && after.is_power_of_two() {
                self.lifecycle_event(
                    "queue.overflow",
                    Some(self.current_turn_id()),
                    iteron_protocol::LifecyclePayload {
                        count: Some(after),
                        reason_code: Some("runtime_ui".into()),
                        ..Default::default()
                    },
                );
            }
            return sent;
        }
        true
    }

    /// Route QuickJS workflow-script progress to a frontend that renders the live phase→agent tree
    /// (ADR-0001 step 1). Separate from [`Self::set_ui`] because the two carry different contracts;
    /// see [`Self::workflow_progress_tx`]. A frontend that wants neither installs neither.
    pub fn set_workflow_progress(
        &mut self,
        tx: tokio::sync::mpsc::Sender<crate::workflow::WorkflowRunUiEvent>,
    ) {
        self.workflow_progress_tx = Some(tx);
    }

    pub(super) fn workflow_progress(&self, event: crate::workflow::WorkflowRunUiEvent) -> bool {
        if let Some(tx) = &self.workflow_progress_tx {
            match tx.try_send(event) {
                Ok(()) => return true,
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return false,
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    let count = self.frontend_saturation.workflow_saturated();
                    if count.is_power_of_two() {
                        self.lifecycle_event(
                            "queue.overflow",
                            Some(self.current_turn_id()),
                            iteron_protocol::LifecyclePayload {
                                count: Some(count),
                                reason_code: Some("runtime_workflow".into()),
                                ..Default::default()
                            },
                        );
                    }
                    return false;
                }
            }
        }
        true
    }

    pub(crate) fn frontend_channel_port(&self) -> FrontendChannelHealth {
        self.frontend_saturation.ui_bytes.enable();
        self.frontend_saturation.clone()
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
        // This transcript and its effect gate never crossed a process boundary. The next run must
        // not replay and re-hash the complete rollout merely because `resumed` is also the common
        // input slot used by explicit recovery.
        self.recovery_effect_replay_required = false;
        Ok(())
    }
}

#[cfg(test)]
#[path = "frontend_tests.rs"]
mod frontend_channel_tests;
