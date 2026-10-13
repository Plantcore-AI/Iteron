//! Client run lifetime. Only accepted host submissions/stops and actual RunEnded drive this
//! state; cosmetic activity, answer publication and local cancellation cannot release a turn.
use iteron_protocol::{SubmissionId, SubmissionLifecycleState};
use std::time::{Duration, Instant};

const MAX_RETRY_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy)]
enum StopRequest {
    None,
    Cooperative { at: Instant },
    Stronger,
}
struct ActiveRun {
    submission: SubmissionId,
    started: Instant,
    stop: StopRequest,
    drain_requested: bool,
    admitted: bool,
}
struct PendingReceipt {
    editor_revision: u64,
    clear_composer: bool,
    display_text: String,
}
pub(super) enum ReceiptObservation {
    None,
    Applied {
        display_text: String,
        editor_revision: u64,
        clear_composer: bool,
    },
    Refused,
}
#[derive(Default)]
pub(super) struct RunPresentation {
    active: Option<ActiveRun>,
    pending: Option<PendingReceipt>,
    last_latency: Option<Duration>,
    retry: Option<String>,
    /// Exactly one admitted draft, with already bounded attachment stores. It is never replayed.
    recovery: Option<crate::editor::OwnedComposerDraft>,
    recovery_ready: bool,
    recovery_applied: bool,
    result: Option<serde_json::Value>,
}
impl RunPresentation {
    pub(super) fn running(&self) -> bool {
        self.active.is_some()
    }
    pub(super) fn submission_id(&self) -> Option<SubmissionId> {
        self.active.as_ref().map(|active| active.submission)
    }
    pub(super) fn awaiting_composer_admission(&self, revision: u64) -> bool {
        self.pending
            .as_ref()
            .is_some_and(|pending| pending.clear_composer && pending.editor_revision == revision)
    }
    pub(super) fn interrupting(&self) -> bool {
        self.active
            .as_ref()
            .is_some_and(|active| !matches!(active.stop, StopRequest::None))
    }
    pub(super) fn force_cancelling(&self) -> bool {
        self.active
            .as_ref()
            .is_some_and(|active| matches!(active.stop, StopRequest::Stronger))
    }
    pub(super) fn draining(&self) -> bool {
        self.active
            .as_ref()
            .is_some_and(|active| active.drain_requested)
    }
    pub(super) fn started(&self) -> Option<Instant> {
        self.active.as_ref().map(|active| active.started)
    }
    #[cfg(test)]
    pub(super) fn last_latency(&self) -> Option<Duration> {
        self.last_latency
    }
    /// Called only after the real SQ has accepted this exact submission ID.
    pub(super) fn submission_accepted(&mut self, submission: SubmissionId, now: Instant) {
        self.active = Some(ActiveRun {
            submission,
            started: now,
            stop: StopRequest::None,
            drain_requested: false,
            admitted: false,
        });
        self.pending = None;
        self.recovery = None;
        self.recovery_ready = false;
        self.recovery_applied = false;
    }
    pub(super) fn interrupt_accepted(&mut self, now: Instant) {
        if let Some(active) = self.active.as_mut()
            && !matches!(active.stop, StopRequest::Stronger)
        {
            active.stop = StopRequest::Cooperative { at: now };
        }
    }
    pub(super) fn stronger_cancel_accepted(&mut self) {
        if let Some(active) = self.active.as_mut()
            && let StopRequest::Cooperative { .. } = active.stop
        {
            active.stop = StopRequest::Stronger;
        }
    }
    pub(super) fn drain_accepted(&mut self) {
        if let Some(active) = self.active.as_mut() {
            active.drain_requested = true;
        }
    }
    pub(super) fn retain_receipt(
        &mut self,
        id: SubmissionId,
        editor_revision: u64,
        clear_composer: bool,
        mut display_text: String,
    ) {
        if display_text.len() > MAX_RETRY_BYTES {
            display_text = "submission applied · full text omitted from display".into();
        } else if display_text.capacity() > MAX_RETRY_BYTES {
            display_text = display_text.into_boxed_str().into_string();
        }
        if self
            .active
            .as_ref()
            .is_some_and(|active| active.submission == id)
        {
            self.pending = Some(PendingReceipt {
                editor_revision,
                clear_composer,
                display_text,
            });
        }
    }
    pub(super) fn observe_receipt(
        &mut self,
        id: SubmissionId,
        state: SubmissionLifecycleState,
    ) -> ReceiptObservation {
        if !self
            .active
            .as_ref()
            .is_some_and(|active| active.submission == id)
        {
            return ReceiptObservation::None;
        }
        match state {
            SubmissionLifecycleState::Admitted => {
                if let Some(active) = self.active.as_mut() {
                    active.admitted = true;
                }
                ReceiptObservation::None
            }
            SubmissionLifecycleState::Applied => {
                self.recovery_applied = true;
                if let Some(active) = self.active.as_mut() {
                    active.admitted = true;
                }
                self.pending
                    .take()
                    .map_or(ReceiptObservation::None, |pending| {
                        ReceiptObservation::Applied {
                            display_text: pending.display_text,
                            editor_revision: pending.editor_revision,
                            clear_composer: pending.clear_composer,
                        }
                    })
            }
            SubmissionLifecycleState::Rejected | SubmissionLifecycleState::Expired => {
                if self.active.as_ref().is_some_and(|active| active.admitted) {
                    return ReceiptObservation::None;
                }
                self.active = None;
                self.pending = None;
                self.retry = None;
                self.recovery = None;
                self.recovery_ready = false;
                self.recovery_applied = false;
                ReceiptObservation::Refused
            }
            SubmissionLifecycleState::Received
            | SubmissionLifecycleState::Created
            | SubmissionLifecycleState::Enqueued
            | SubmissionLifecycleState::Requeued => ReceiptObservation::None,
        }
    }

    /// Actual resident completion is distinct from the durable answer/Done publications. This is
    /// the sole completion transition that records elapsed client latency and releases input.
    pub(super) fn run_ended(&mut self, now: Instant) {
        self.last_latency = self
            .active
            .take()
            .map(|active| now.saturating_duration_since(active.started));
        self.pending = None;
    }
    pub(super) fn retain_draft_recovery(&mut self, draft: crate::editor::OwnedComposerDraft) {
        self.recovery = draft
            .within_recovery_bound(MAX_RETRY_BYTES)
            .then_some(draft);
        self.recovery_ready = false;
    }
    pub(super) fn finish_draft_recovery(&mut self, succeeded: bool) {
        self.recovery_ready = !succeeded && self.recovery_applied && self.recovery.is_some();
        if succeeded || !self.recovery_applied {
            self.recovery = None;
        }
    }
    pub(super) fn has_draft_recovery(&self) -> bool {
        !self.running() && self.recovery_ready && self.recovery.is_some()
    }
    /// Restoring is an explicit editor action. Neither this owner nor the caller dispatches it.
    pub(super) fn restore_draft_recovery(&mut self, editor: &mut crate::editor::Editor) -> bool {
        if !self.has_draft_recovery() || !editor.can_restore_owned_draft() {
            return false;
        }
        let Some(draft) = self.recovery.take() else {
            return false;
        };
        match editor.restore_owned_draft(draft) {
            Ok(()) => {
                self.recovery_ready = false;
                self.retry = None;
                true
            }
            Err(draft) => {
                self.recovery = Some(*draft);
                false
            }
        }
    }
    pub(super) fn retain_plain_text_retry(&mut self, text: Option<String>) {
        self.retry =
            text.filter(|text| text.len() <= MAX_RETRY_BYTES && text.capacity() <= MAX_RETRY_BYTES);
    }
    pub(super) fn retry_text(&self) -> Option<&str> {
        self.retry.as_deref()
    }
    pub(super) fn clear_retry(&mut self) {
        self.retry = None;
    }
    pub(super) fn observe_terminal_result(&mut self, result: serde_json::Value) {
        self.result = Some(result);
    }
    #[cfg(test)]
    pub(super) fn terminal_result(&self) -> Option<&serde_json::Value> {
        self.result.as_ref()
    }
    pub(super) fn select_verified_run(&mut self) {
        *self = Self::default();
    }
    #[cfg(test)]
    pub(super) fn pending_id(&self) -> Option<SubmissionId> {
        self.pending
            .as_ref()
            .and(self.active.as_ref())
            .map(|active| active.submission)
    }
    pub(super) fn stop_requested_at(&self) -> Option<Instant> {
        match self.active.as_ref()?.stop {
            StopRequest::None => None,
            StopRequest::Cooperative { at } => Some(at),
            StopRequest::Stronger => None,
        }
    }
}
#[cfg(test)]
mod tests;
