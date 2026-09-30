//! Bounded EQ publisher, lifecycle projection and authoritative backpressure owner.

use super::{
    AppServerQueuePolicy, Arc, AssistantTextSpill, AuthoritativeOverflow, CosmeticOverflow,
    EventEnvelope, LifecycleHookRoute, LifecyclePayload, PROTOCOL_VERSION, RunId, Semaphore,
    ServerEvent, SessionId, SubmissionId, SubmissionLifecycleState, TurnId, UiEvent,
    dispatch_lifecycle_hook, event_heap_bytes, mpsc, product_contract,
};

/// The EQ publisher, held by the server side.
///
/// Owns the drop policy so no call site can bypass it.
pub(crate) struct EventPublisher {
    pub(super) events: mpsc::Sender<EventEnvelope>,
    pub(super) byte_budget: Arc<Semaphore>,
    pub(super) dropped: usize,
    pub(super) next_seq: u64,
    pub(super) lossless: bool,
    pub(super) lifecycle: iteron_obs::lifecycle::LifecycleEmitter,
    pub(super) lifecycle_hooks: LifecycleHookRoute,
    pub(super) session_id: Option<SessionId>,
    pub(super) run_id: Option<RunId>,
    pub(super) workflow_phases: std::collections::BTreeMap<String, String>,
    pub(super) queue_policy: AppServerQueuePolicy,
    pub(super) pending_cosmetic: PendingCosmetic,
    pub(super) contract: product_contract::ContractReader,
    pub(super) next_product_turn: u64,
}

const MAX_TRACKED_WORKFLOW_PHASES: usize = 256;
const EQ_BYTE_CAPACITY: usize = 64 * 1024 * 1024;
/// Memory held beside the bounded EQ while the frontend catches up. Reaching the ceiling applies
/// backpressure and flushes; it never turns assistant/reasoning bytes into a last-write-wins slot.
const MAX_PENDING_COSMETIC_BYTES: usize = 1024 * 1024;
const MAX_PENDING_COSMETIC_SEGMENTS: usize = 256;

pub(super) fn eq_byte_capacity() -> usize {
    iteron_tunables::param_integer("cli.app_server.eq_byte_capacity", EQ_BYTE_CAPACITY)
        .clamp(1, EQ_BYTE_CAPACITY)
}

#[derive(Debug, Default)]
pub(super) struct PendingCosmetic {
    pub(super) segments: std::collections::VecDeque<ServerEvent>,
    pub(super) bytes: usize,
}

impl PendingCosmetic {
    pub(super) fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    pub(super) fn len(&self) -> usize {
        self.segments.len()
    }

    pub(super) fn event_bytes(event: &ServerEvent) -> usize {
        match event {
            ServerEvent::Ui(UiEvent::Text(text) | UiEvent::Thinking(text)) => text.len(),
            // Activity ticks are snapshots. Their strings are bounded at their producer seams;
            // this conservative charge also accounts for maps/enums/channel allocation.
            ServerEvent::WorkflowRun(_) => 4 * 1024,
            ServerEvent::Activity(_) => 512,
            _ => 0,
        }
    }

    /// Merge an exact stream delta or replace a coalescible snapshot. `Some(event)` means the byte
    /// or segment ceiling would be crossed and the caller must flush before retrying.
    pub(super) fn push(&mut self, event: ServerEvent) -> Option<ServerEvent> {
        let bytes = Self::event_bytes(&event);
        if self.bytes.saturating_add(bytes)
            > iteron_tunables::param_integer(
                "cli.app_server.max_pending_cosmetic_bytes",
                MAX_PENDING_COSMETIC_BYTES,
            )
            .clamp(1, MAX_PENDING_COSMETIC_BYTES)
        {
            return Some(event);
        }

        match (self.segments.back_mut(), &event) {
            (
                Some(ServerEvent::Ui(UiEvent::Text(existing))),
                ServerEvent::Ui(UiEvent::Text(delta)),
            )
            | (
                Some(ServerEvent::Ui(UiEvent::Thinking(existing))),
                ServerEvent::Ui(UiEvent::Thinking(delta)),
            ) if existing.len().saturating_add(delta.len())
                <= crate::output::max_stream_ui_delta_bytes() =>
            {
                existing.push_str(delta);
                self.bytes = self.bytes.saturating_add(bytes);
                return None;
            }
            // Same-part workflow activity is already cumulative. Preserve only the newest
            // snapshot, while terminal/phase events remain authoritative and never enter here.
            (Some(ServerEvent::WorkflowRun(existing)), ServerEvent::WorkflowRun(next)) => {
                *existing = next.clone();
                return None;
            }
            (Some(ServerEvent::Activity(existing)), ServerEvent::Activity(next))
                if existing.id == next.id =>
            {
                *existing = next.clone();
                return None;
            }
            _ => {}
        }

        if self.segments.len()
            >= iteron_tunables::param_integer(
                "cli.app_server.max_pending_cosmetic_segments",
                MAX_PENDING_COSMETIC_SEGMENTS,
            )
            .clamp(1, MAX_PENDING_COSMETIC_SEGMENTS)
        {
            return Some(event);
        }
        self.bytes = self.bytes.saturating_add(bytes);
        self.segments.push_back(event);
        None
    }

    pub(super) fn pop_front(&mut self) -> Option<ServerEvent> {
        let event = self.segments.pop_front()?;
        self.bytes = self.bytes.saturating_sub(Self::event_bytes(&event));
        Some(event)
    }
}

impl EventPublisher {
    #[cfg(test)]
    pub(super) fn new(
        events: mpsc::Sender<EventEnvelope>,
        lossless: bool,
        lifecycle: iteron_obs::lifecycle::LifecycleEmitter,
    ) -> Self {
        Self::new_with_policy(events, lossless, lifecycle, AppServerQueuePolicy::owner())
    }

    #[cfg(test)]
    pub(super) fn new_with_policy(
        events: mpsc::Sender<EventEnvelope>,
        lossless: bool,
        lifecycle: iteron_obs::lifecycle::LifecycleEmitter,
        queue_policy: AppServerQueuePolicy,
    ) -> Self {
        Self::new_with_policy_and_hooks(
            events,
            lossless,
            lifecycle,
            queue_policy,
            Arc::new(std::sync::Mutex::new(None)),
        )
    }

    pub(super) fn new_with_policy_and_hooks(
        events: mpsc::Sender<EventEnvelope>,
        lossless: bool,
        lifecycle: iteron_obs::lifecycle::LifecycleEmitter,
        queue_policy: AppServerQueuePolicy,
        lifecycle_hooks: LifecycleHookRoute,
    ) -> Self {
        Self {
            events,
            byte_budget: Arc::new(Semaphore::new(eq_byte_capacity())),
            dropped: 0,
            next_seq: 1,
            lossless,
            lifecycle,
            lifecycle_hooks,
            session_id: None,
            run_id: None,
            workflow_phases: std::collections::BTreeMap::new(),
            queue_policy,
            pending_cosmetic: PendingCosmetic::default(),
            contract: product_contract::ContractReader::default(),
            next_product_turn: 0,
        }
    }

    pub(super) fn bind_lifecycle_identity(&mut self, session_id: SessionId, run_id: RunId) {
        self.contract
            .bind_identity(session_id.clone(), run_id.clone());
        self.session_id = Some(session_id);
        self.run_id = Some(run_id);
    }

    pub(super) fn begin_contract_turn(
        &mut self,
        run_id: RunId,
        submission_id: Option<SubmissionId>,
    ) {
        self.next_product_turn = self
            .next_product_turn
            .checked_add(1)
            .expect("product turn identity space exhausted");
        self.contract.begin_turn(
            run_id,
            iteron_protocol::product_contract::ProductTurnId(self.next_product_turn),
            submission_id,
        );
    }

    pub(super) fn rebind_contract_run(&mut self, run_id: RunId) -> bool {
        self.contract.rebind_run(run_id)
    }

    pub(super) fn can_rebind_contract_run(&self) -> bool {
        self.contract.can_rebind_run()
    }

    pub(super) fn bind_lifecycle_hooks(
        &mut self,
        dispatcher: crate::runtime::lifecycle_hooks::LifecycleHookDispatcher,
    ) {
        *self
            .lifecycle_hooks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(dispatcher);
    }

    pub(super) fn lifecycle_emitter(&self) -> iteron_obs::lifecycle::LifecycleEmitter {
        self.lifecycle.clone()
    }

    pub(super) fn lifecycle_correlation(
        &self,
        turn_id: Option<TurnId>,
        submission_id: Option<SubmissionId>,
    ) -> iteron_obs::lifecycle::LifecycleCorrelation {
        iteron_obs::lifecycle::LifecycleCorrelation {
            session_id: self.session_id.clone(),
            run_id: self.run_id.clone(),
            turn_id,
            submission_id,
            ..iteron_obs::lifecycle::LifecycleCorrelation::default()
        }
    }

    pub(super) fn record_lifecycle(
        &self,
        event_name: &str,
        turn_id: Option<TurnId>,
        submission_id: Option<SubmissionId>,
        payload: LifecyclePayload,
    ) {
        if let Ok(event) = self.lifecycle.emit(
            event_name,
            self.lifecycle_correlation(turn_id, submission_id),
            payload,
        ) {
            dispatch_lifecycle_hook(&self.lifecycle_hooks, event);
        }
    }

    pub(super) fn record_workflow_lifecycle(
        &self,
        event_name: &str,
        workflow_id: Option<&str>,
        payload: LifecyclePayload,
    ) {
        let mut correlation = self.lifecycle_correlation(None, None);
        correlation.workflow_id = workflow_id.map(|id| iteron_protocol::WorkflowId(id.to_owned()));
        if let Ok(event) = self.lifecycle.emit(event_name, correlation, payload) {
            dispatch_lifecycle_hook(&self.lifecycle_hooks, event);
        }
    }

    pub(super) fn record_job_lifecycle(
        &self,
        event_name: &str,
        job_id: &str,
        payload: LifecyclePayload,
    ) {
        let mut correlation = self.lifecycle_correlation(None, None);
        correlation.job_id = Some(iteron_protocol::JobId(job_id.to_owned()));
        if let Ok(event) = self.lifecycle.emit(event_name, correlation, payload) {
            dispatch_lifecycle_hook(&self.lifecycle_hooks, event);
        }
    }

    pub(super) fn record_workflow_child_lifecycle(
        &self,
        event_name: &str,
        workflow_id: &str,
        index: usize,
        payload: LifecyclePayload,
    ) {
        let mut correlation = self.lifecycle_correlation(None, None);
        correlation.workflow_id = Some(iteron_protocol::WorkflowId(workflow_id.to_owned()));
        correlation.subagent_id = Some(iteron_protocol::SubagentId(format!(
            "{workflow_id}:agent-{index}"
        )));
        if let Ok(event) = self.lifecycle.emit(event_name, correlation, payload) {
            dispatch_lifecycle_hook(&self.lifecycle_hooks, event);
        }
    }

    pub(super) fn transition_workflow_phase(&mut self, workflow_id: &str, next: &str) {
        let previous = self.workflow_phases.get(workflow_id).cloned();
        if previous.as_deref() == Some(next) {
            return;
        }
        if let Some(previous) = previous {
            self.record_workflow_lifecycle(
                if previous == "planning" {
                    "workflow.planning_completed"
                } else if previous == "reducing" {
                    "workflow.reduction_completed"
                } else {
                    "workflow.phase_completed"
                },
                Some(workflow_id),
                LifecyclePayload::default(),
            );
        }
        if self.workflow_phases.len()
            < iteron_tunables::param_integer(
                "cli.app_server.max_tracked_workflow_phases",
                MAX_TRACKED_WORKFLOW_PHASES,
            )
            || self.workflow_phases.contains_key(workflow_id)
        {
            self.workflow_phases
                .insert(workflow_id.to_owned(), next.to_owned());
        }
        self.record_workflow_lifecycle(
            if next == "planning" {
                "workflow.planning_started"
            } else if next == "reducing" {
                "workflow.reduction_started"
            } else {
                "workflow.phase_started"
            },
            Some(workflow_id),
            LifecyclePayload::default(),
        );
    }

    pub(super) fn finish_workflow_phase(
        &mut self,
        workflow_id: &str,
        terminal: crate::workflow::WorkflowRunTerminal,
    ) {
        let Some(previous) = self.workflow_phases.remove(workflow_id) else {
            return;
        };
        let event_id = if previous == "planning"
            && matches!(terminal, crate::workflow::WorkflowRunTerminal::Failed)
        {
            "workflow.planning_failed"
        } else if previous == "planning" {
            "workflow.planning_completed"
        } else if previous == "reducing" {
            "workflow.reduction_completed"
        } else {
            "workflow.phase_completed"
        };
        self.record_workflow_lifecycle(event_id, Some(workflow_id), LifecyclePayload::default());
    }

    pub(super) fn record_submission_lifecycle(
        &self,
        id: SubmissionId,
        state: SubmissionLifecycleState,
        reason_code: Option<&'static str>,
    ) {
        let event_name = match state {
            SubmissionLifecycleState::Created => "submission.created",
            SubmissionLifecycleState::Enqueued => "submission.enqueued",
            SubmissionLifecycleState::Received => "submission.received",
            SubmissionLifecycleState::Admitted => "submission.admitted",
            SubmissionLifecycleState::Applied => "submission.applied",
            SubmissionLifecycleState::Requeued => "submission.requeued",
            SubmissionLifecycleState::Rejected => "submission.rejected",
            SubmissionLifecycleState::Expired => "submission.expired",
        };
        self.record_lifecycle(
            event_name,
            None,
            Some(id),
            LifecyclePayload {
                reason_code: reason_code.map(str::to_owned),
                ..LifecyclePayload::default()
            },
        );
    }

    pub(super) async fn send(&mut self, mut event: ServerEvent) -> Result<(), ()> {
        let reject_authoritative = !self.lossless
            && event.is_authoritative()
            && self.queue_policy.authoritative_overflow() == AuthoritativeOverflow::Reject;
        let capacity = eq_byte_capacity();
        let mut assistant_text_spill = None;
        if event_heap_bytes(&event).max(1) > capacity {
            let ServerEvent::RunEnded { summary, .. } = &mut event else {
                // Exact refusal: a single inline payload may never borrow fewer permits than the
                // bytes it retains. Producer seams remain responsible for their typed bounds.
                return Err(());
            };
            let run_id = summary.run_id.clone();
            let text = std::mem::take(&mut summary.assistant_text);
            let spill =
                match tokio::task::spawn_blocking(move || AssistantTextSpill::create(run_id, text))
                    .await
                    .map_err(|_| ())?
                {
                    Ok(spill) => spill,
                    Err((_error, text)) => {
                        summary.assistant_text = text;
                        return Err(());
                    }
                };
            if event_heap_bytes(&event).max(1) > capacity {
                return Err(());
            }
            assistant_text_spill = Some(spill);
        }
        let charge = event_heap_bytes(&event).max(1);
        debug_assert!(charge <= capacity);
        let permit = if reject_authoritative {
            self.byte_budget
                .clone()
                .try_acquire_many_owned(u32::try_from(charge).map_err(|_| ())?)
                .map_err(|_| ())?
        } else {
            self.byte_budget
                .clone()
                .acquire_many_owned(u32::try_from(charge).map_err(|_| ())?)
                .await
                .map_err(|_| ())?
        };
        let seq = self.next_seq;
        self.next_seq = self.next_seq.checked_add(1).ok_or(())?;
        let terminal_spill_bytes = assistant_text_spill.as_ref().map(|spill| spill.bytes);
        let envelope = EventEnvelope {
            seq,
            protocol_version: PROTOCOL_VERSION,
            event,
            assistant_text_spill,
            _byte_permit: Some(permit),
        };
        if reject_authoritative {
            let slot = self.events.try_reserve().map_err(|_| ())?;
            self.contract
                .observe_with_spill(seq, &envelope.event, terminal_spill_bytes);
            slot.send(envelope);
            Ok(())
        } else {
            let slot = self.events.reserve().await.map_err(|_| ())?;
            self.contract
                .observe_with_spill(seq, &envelope.event, terminal_spill_bytes);
            slot.send(envelope);
            Ok(())
        }
    }

    pub(super) async fn flush_pending_cosmetic(&mut self) -> Result<(), ()> {
        if self.dropped > 0 {
            let dropped = std::mem::take(&mut self.dropped);
            self.send(ServerEvent::Lagged { dropped }).await?;
        }
        while let Some(event) = self.pending_cosmetic.pop_front() {
            self.send(event).await?;
        }
        Ok(())
    }

    pub(super) async fn retain_cosmetic(&mut self, event: ServerEvent) -> Result<(), ()> {
        let Some(event) = self.pending_cosmetic.push(event) else {
            return Ok(());
        };
        self.flush_pending_cosmetic().await?;
        match self.pending_cosmetic.push(event) {
            None => Ok(()),
            // A single delta larger than the side-buffer ceiling is delivered directly. This may
            // wait for the frontend, but it cannot consume unbounded memory or lose bytes.
            Some(event) => self.send(event).await,
        }
    }

    /// Publish one event, applying the bounded-queue policy.
    ///
    /// Authoritative events wait for room. The owner policy cumulatively coalesces cosmetic stream
    /// bytes; the legacy explicit Drop policy reports its gap as `Lagged`.
    pub(crate) async fn publish(&mut self, event: ServerEvent) -> Result<(), ()> {
        let authoritative = event.is_authoritative();
        let event_bytes = event_heap_bytes(&event).max(1);
        let byte_saturated = self.byte_budget.available_permits() < event_bytes;
        if !self.lossless && !authoritative && (self.events.capacity() == 0 || byte_saturated) {
            match self.queue_policy.cosmetic_overflow() {
                CosmeticOverflow::Drop => self.dropped += 1,
                CosmeticOverflow::Coalesce => {
                    self.retain_cosmetic(event).await?;
                }
            }
            return Ok(());
        }
        if !self.lossless
            && !authoritative
            && !self.pending_cosmetic.is_empty()
            && self.events.capacity() <= self.pending_cosmetic.len()
        {
            self.retain_cosmetic(event).await?;
            return Ok(());
        }
        if !self.pending_cosmetic.is_empty()
            && (authoritative || self.events.capacity() > self.pending_cosmetic.len())
        {
            self.flush_pending_cosmetic().await?;
        }
        // Report the gap immediately before the event that follows it. A cosmetic event only gets
        // to report when there is spare room — reporting a drop must never itself block the stream.
        // An authoritative event already waits for room, so the notice waits with it, and that is
        // what guarantees a run cannot end with an unreported gap: while the queue stays saturated
        // `capacity() > 1` is never true, so a policy that waited for slack alone would carry the
        // count silently past `RunEnded` and lose it.
        if self.dropped > 0 && (authoritative || self.events.capacity() > 1) {
            let dropped = std::mem::take(&mut self.dropped);
            self.send(ServerEvent::Lagged { dropped }).await?;
        }
        self.send(event).await
    }
}
