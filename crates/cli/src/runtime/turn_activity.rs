//! Runtime producer for the public, content-free live activity protocol.
//!
//! Durable [`iteron_protocol::Phase`] events remain replay authority. This module only builds the
//! additive live projection; the composition root forwards its receiver to each frontend.

pub(crate) use iteron_protocol::ActivityEvent;
use iteron_protocol::{
    ACTIVITY_SCHEMA_VERSION, ActivityCancelability, ActivityDetailCode, ActivityKind,
    ActivityOwner, ActivityState, TurnId,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum ActivityStage {
    LocalPrepare,
    AdmissionWait,
    Connect,
    AwaitingFirstToken,
    Decode,
    RetryBackoff,
    Failover,
    Hook,
    ToolProposed,
    ToolHook,
    AwaitingApproval,
    ToolQueued,
    ToolRunning,
    ToolPostProcessing,
    Verification,
    Checkpoint,
    AnswerComplete,
    Finalization,
    QueuedForProvider,
    RunningProvider,
    FinalizingEvidence,
    PreparingPatch,
    HostVerification,
    Merging,
    Discarding,
    Cancellation,
}

impl ActivityStage {
    const fn code(self) -> &'static str {
        match self {
            Self::LocalPrepare => "local_prepare",
            Self::AdmissionWait => "admission_wait",
            Self::Connect => "connect",
            Self::AwaitingFirstToken => "awaiting_first_token",
            Self::Decode => "decode",
            Self::RetryBackoff => "retry_backoff",
            Self::Failover => "failover",
            Self::Hook => "hook",
            Self::ToolProposed => "tool_proposed",
            Self::ToolHook => "tool_hook",
            Self::AwaitingApproval => "awaiting_approval",
            Self::ToolQueued => "tool_queued",
            Self::ToolRunning => "tool_running",
            Self::ToolPostProcessing => "tool_post_processing",
            Self::Verification => "verification",
            Self::Checkpoint => "checkpoint",
            Self::AnswerComplete => "answer_complete",
            Self::Finalization => "finalization",
            Self::QueuedForProvider => "queued_for_provider",
            Self::RunningProvider => "running_provider",
            Self::FinalizingEvidence => "finalizing_evidence",
            Self::PreparingPatch => "preparing_patch",
            Self::HostVerification => "host_verification",
            Self::Merging => "merging",
            Self::Discarding => "discarding",
            Self::Cancellation => "cancellation",
        }
    }

    const fn kind(self) -> ActivityKind {
        match self {
            Self::LocalPrepare
            | Self::AdmissionWait
            | Self::FinalizingEvidence
            | Self::PreparingPatch
            | Self::Merging
            | Self::Discarding => ActivityKind::Persistence,
            Self::Connect
            | Self::AwaitingFirstToken
            | Self::Decode
            | Self::RetryBackoff
            | Self::Failover
            | Self::QueuedForProvider
            | Self::RunningProvider => ActivityKind::ModelRequest,
            Self::Hook
            | Self::ToolProposed
            | Self::ToolHook
            | Self::AwaitingApproval
            | Self::ToolQueued
            | Self::ToolRunning
            | Self::ToolPostProcessing => ActivityKind::Tool,
            Self::Verification | Self::HostVerification => ActivityKind::Verification,
            Self::Checkpoint => ActivityKind::Persistence,
            Self::AnswerComplete | Self::Finalization => ActivityKind::Finalization,
            Self::Cancellation => ActivityKind::Cancellation,
        }
    }

    const fn detail(self) -> Option<ActivityDetailCode> {
        Some(match self {
            Self::LocalPrepare => ActivityDetailCode::ContextAssembly,
            Self::AdmissionWait | Self::QueuedForProvider => ActivityDetailCode::RoutePermit,
            Self::Connect => ActivityDetailCode::TransportConnect,
            Self::AwaitingFirstToken => ActivityDetailCode::WaitingFirstToken,
            Self::Decode => ActivityDetailCode::Responding,
            Self::RetryBackoff => ActivityDetailCode::RetryBackoff,
            Self::Failover => ActivityDetailCode::RouteFailover,
            Self::Hook => ActivityDetailCode::HookGate,
            Self::ToolProposed => ActivityDetailCode::ToolProposed,
            Self::ToolHook => ActivityDetailCode::ToolHook,
            Self::AwaitingApproval => ActivityDetailCode::ToolApproval,
            Self::ToolQueued => ActivityDetailCode::ToolQueued,
            Self::ToolRunning => ActivityDetailCode::ToolRunning,
            Self::ToolPostProcessing => ActivityDetailCode::ToolPostProcessing,
            Self::Verification => ActivityDetailCode::Verification,
            Self::Checkpoint => ActivityDetailCode::Checkpoint,
            Self::AnswerComplete => ActivityDetailCode::AnswerComplete,
            Self::Finalization => ActivityDetailCode::Finalizing,
            Self::RunningProvider => ActivityDetailCode::RequestSent,
            Self::FinalizingEvidence => ActivityDetailCode::RecordCommit,
            Self::PreparingPatch => ActivityDetailCode::Checkpoint,
            Self::HostVerification => ActivityDetailCode::Verification,
            Self::Merging => ActivityDetailCode::RecordCommit,
            Self::Discarding => ActivityDetailCode::WorkflowResultPersist,
            Self::Cancellation => return None,
        })
    }

    const fn owner(self) -> ActivityOwner {
        match self {
            Self::Connect
            | Self::AwaitingFirstToken
            | Self::Decode
            | Self::RetryBackoff
            | Self::Failover
            | Self::QueuedForProvider
            | Self::RunningProvider => ActivityOwner::Provider,
            Self::ToolProposed
            | Self::ToolHook
            | Self::ToolQueued
            | Self::ToolRunning
            | Self::ToolPostProcessing => ActivityOwner::Tool,
            Self::PreparingPatch | Self::HostVerification | Self::Merging | Self::Discarding => {
                ActivityOwner::Workflow
            }
            _ => ActivityOwner::Runtime,
        }
    }

    const fn cancelability(self) -> ActivityCancelability {
        match self {
            Self::ToolRunning | Self::RunningProvider | Self::Decode => {
                ActivityCancelability::Strong
            }
            Self::AwaitingApproval | Self::Cancellation => ActivityCancelability::None,
            _ => ActivityCancelability::Cooperative,
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct ActivitySink {
    tx: Option<tokio::sync::mpsc::Sender<ActivityEvent>>,
    saturated: std::sync::Arc<std::sync::atomic::AtomicU64>,
    last_emitted_ms: std::sync::Arc<std::sync::atomic::AtomicU64>,
    pending_terminals: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<ActivityEvent>>>,
    pending_live:
        std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<String, ActivityEvent>>>,
}

const MAX_PENDING_ACTIVITY_TERMINALS: usize = 256;
const MAX_PENDING_ACTIVITY_SNAPSHOTS: usize = 256;

impl ActivitySink {
    pub(crate) fn install(&mut self, tx: tokio::sync::mpsc::Sender<ActivityEvent>) {
        self.tx = Some(tx);
    }

    pub(crate) fn emit(&self, mut event: ActivityEvent) {
        // A strict local sequence lets the AppServer merge channel and saturation-side terminals
        // at the run boundary without resurrecting an older status after RunEnded.
        let now = unix_ms();
        let mut previous = self
            .last_emitted_ms
            .load(std::sync::atomic::Ordering::Acquire);
        let emitted_at = loop {
            let next = now.max(previous.saturating_add(1));
            match self.last_emitted_ms.compare_exchange_weak(
                previous,
                next,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            ) {
                Ok(_) => break next,
                Err(observed) => previous = observed,
            }
        };
        event.updated_at_unix_ms = emitted_at.max(event.started_at_unix_ms);
        debug_assert!(event.validate().is_ok());
        if let Some(tx) = &self.tx {
            let event_id = event.id.clone();
            match tx.try_send(event) {
                Ok(()) => {
                    self.pending_live
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&event_id);
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(event)) => {
                    self.saturated
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if event.state.is_terminal() {
                        self.pending_live
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .remove(&event.id);
                        let mut pending = self
                            .pending_terminals
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if let Some(existing) = pending.iter_mut().find(|item| item.id == event.id)
                        {
                            *existing = event;
                        } else {
                            if pending.len()
                                == iteron_tunables::param_integer(
                                    "cli.runtime.turn_activity.max_pending_activity_terminals",
                                    MAX_PENDING_ACTIVITY_TERMINALS,
                                )
                                .clamp(1, MAX_PENDING_ACTIVITY_TERMINALS)
                            {
                                pending.pop_front();
                            }
                            pending.push_back(event);
                        }
                    } else {
                        let mut pending = self
                            .pending_live
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let ceiling = iteron_tunables::param_integer(
                            "cli.runtime.turn_activity.max_pending_activity_snapshots",
                            MAX_PENDING_ACTIVITY_SNAPSHOTS,
                        )
                        .clamp(1, MAX_PENDING_ACTIVITY_SNAPSHOTS);
                        if !pending.contains_key(&event.id) && pending.len() == ceiling {
                            let oldest = pending
                                .iter()
                                .min_by_key(|(_, event)| event.updated_at_unix_ms)
                                .map(|(id, _)| id.clone());
                            if let Some(oldest) = oldest {
                                pending.remove(&oldest);
                            }
                        }
                        pending.insert(event.id.clone(), event);
                    }
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    self.saturated
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
    }

    pub(crate) fn take_pending_terminals(&self) -> Vec<ActivityEvent> {
        self.pending_terminals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
            .collect()
    }

    /// Drain the newest saturated live snapshot for each bounded activity identity. These are
    /// cosmetic state replacements, not a second event log; AppServer merges them by the monotonic
    /// runtime timestamp while the turn is running and once more before `RunEnded`.
    pub(crate) fn take_pending_snapshots(&self) -> Vec<ActivityEvent> {
        let mut pending = self
            .pending_live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut snapshots = std::mem::take(&mut *pending)
            .into_values()
            .collect::<Vec<_>>();
        snapshots.sort_by_key(|event| event.updated_at_unix_ms);
        snapshots
    }

    pub(crate) fn sender(&self) -> Option<tokio::sync::mpsc::Sender<ActivityEvent>> {
        self.tx.clone()
    }

    #[cfg(test)]
    pub(crate) fn saturated_count(&self) -> u64 {
        self.saturated.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) fn span(&self, stage: ActivityStage, turn_id: Option<TurnId>) -> ActivitySpan {
        let event = started_event(stage, turn_id, 0, 0, None, None, None);
        self.emit(event.clone());
        ActivitySpan {
            sink: self.clone(),
            event,
            started: Instant::now(),
            settled: false,
        }
    }

    pub(crate) fn span_attempt(
        &self,
        stage: ActivityStage,
        turn_id: TurnId,
        attempt: u32,
        limit: u32,
        deadline_after: Duration,
    ) -> ActivitySpan {
        let deadline = unix_ms().saturating_add(duration_ms(deadline_after));
        let event = started_event(
            stage,
            Some(turn_id),
            bounded_attempt(attempt),
            bounded_attempt(limit.max(attempt)),
            None,
            None,
            Some(deadline),
        );
        self.emit(event.clone());
        ActivitySpan {
            sink: self.clone(),
            event,
            started: Instant::now(),
            settled: false,
        }
    }

    pub(crate) fn retry(&self, turn_id: TurnId, attempt: u32, limit: u32, delay: Duration) {
        let now = unix_ms();
        let delay_ms = duration_ms(delay);
        let mut event = started_event(
            ActivityStage::RetryBackoff,
            Some(turn_id),
            bounded_attempt(attempt),
            bounded_attempt(limit.max(attempt)),
            Some(ActivityDetailCode::RetryBackoff),
            Some(now.saturating_add(delay_ms)),
            None,
        );
        event.state = ActivityState::Retrying;
        self.emit(event);
    }

    pub(crate) fn heartbeat(
        &self,
        stage: ActivityStage,
        turn_id: TurnId,
        completed: u64,
        total: u64,
        deadline_after: Duration,
    ) {
        if total == 0 {
            return;
        }
        let total = total.min(iteron_protocol::MAX_ACTIVITY_PROGRESS_UNITS);
        let mut event = started_event(
            stage,
            Some(turn_id),
            0,
            0,
            None,
            None,
            Some(unix_ms().saturating_add(duration_ms(deadline_after))),
        );
        event.progress = Some(iteron_protocol::ActivityProgress {
            completed: completed.min(total),
            total,
        });
        self.emit(event);
    }
}

pub(crate) struct ActivitySpan {
    sink: ActivitySink,
    event: ActivityEvent,
    started: Instant,
    settled: bool,
}

impl ActivitySpan {
    pub(crate) fn progress(&mut self, completed: u64, total: u64) {
        if total == 0 {
            return;
        }
        self.event.progress = Some(iteron_protocol::ActivityProgress {
            completed: completed.min(total),
            total,
        });
        self.event.updated_at_unix_ms = unix_ms().max(self.event.started_at_unix_ms);
        self.sink.emit(self.event.clone());
    }

    pub(crate) fn complete(mut self) {
        self.settle(ActivityState::Succeeded, None)
    }

    pub(crate) fn fail(mut self, detail_code: ActivityDetailCode) {
        self.settle(ActivityState::Failed, Some(detail_code))
    }

    pub(crate) fn fail_unclassified(mut self) {
        self.settle(ActivityState::Failed, None)
    }

    pub(crate) fn timeout(mut self, detail_code: ActivityDetailCode) {
        self.settle(ActivityState::Failed, Some(detail_code))
    }

    fn settle(&mut self, state: ActivityState, detail_code: Option<ActivityDetailCode>) {
        let elapsed_ms = duration_ms(self.started.elapsed());
        self.event.state = state;
        self.event.updated_at_unix_ms =
            unix_ms().max(self.event.started_at_unix_ms.saturating_add(elapsed_ms));
        self.event.next_retry_at_unix_ms = None;
        if let Some(code) = detail_code {
            self.event.detail_code = Some(code);
        }
        self.sink.emit(self.event.clone());
        self.settled = true;
    }
}

impl Drop for ActivitySpan {
    fn drop(&mut self) {
        if !self.settled {
            self.settle(ActivityState::Cancelled, None);
        }
    }
}

fn started_event(
    stage: ActivityStage,
    turn_id: Option<TurnId>,
    attempt: u16,
    limit: u16,
    detail_code: Option<ActivityDetailCode>,
    next_retry_at_unix_ms: Option<u64>,
    deadline_unix_ms: Option<u64>,
) -> ActivityEvent {
    let now = unix_ms();
    let id = match turn_id {
        Some(turn) => format!("turn-{}:{}", turn.0, stage.code()),
        None => format!("runtime:{}", stage.code()),
    };
    ActivityEvent {
        schema_version: ACTIVITY_SCHEMA_VERSION,
        id,
        parent_id: turn_id.map(|turn| format!("turn-{}", turn.0)),
        kind: stage.kind(),
        state: ActivityState::Running,
        owner: stage.owner(),
        started_at_unix_ms: now,
        updated_at_unix_ms: now,
        attempt,
        limit,
        next_retry_at_unix_ms,
        deadline_unix_ms,
        cancelability: stage.cancelability(),
        detail_code: detail_code.or_else(|| stage.detail()),
        progress: None,
    }
}

fn bounded_attempt(value: u32) -> u16 {
    u16::try_from(value)
        .unwrap_or(u16::MAX)
        .min(iteron_protocol::MAX_ACTIVITY_ATTEMPTS)
}

pub(crate) fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(duration_ms)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_activity_has_absolute_deadline_and_attempt_context() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        let mut sink = ActivitySink::default();
        sink.install(tx);
        sink.retry(TurnId(7), 2, 4, Duration::from_millis(900));
        let event = rx.try_recv().unwrap();
        assert_eq!(event.kind, ActivityKind::ModelRequest);
        assert_eq!(event.state, ActivityState::Retrying);
        assert_eq!(event.attempt, 2);
        assert_eq!(event.limit, 4);
        assert_eq!(event.detail_code, Some(ActivityDetailCode::RetryBackoff));
        assert!(
            event
                .next_retry_at_unix_ms
                .is_some_and(|next| next >= event.started_at_unix_ms + 900)
        );
        assert_eq!(event.deadline_unix_ms, None);
        assert_eq!(event.validate(), Ok(()));
    }

    #[test]
    fn attempt_deadline_is_not_misreported_as_retry_time() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        let mut sink = ActivitySink::default();
        sink.install(tx);
        let _span = sink.span_attempt(
            ActivityStage::Verification,
            TurnId(3),
            1,
            2,
            Duration::from_secs(5),
        );
        let event = rx.try_recv().unwrap();
        assert_eq!(event.next_retry_at_unix_ms, None);
        assert!(event.deadline_unix_ms.is_some());
        assert_eq!(event.validate(), Ok(()));
    }

    #[test]
    fn activity_queue_is_bounded_and_counts_saturation() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let mut sink = ActivitySink::default();
        sink.install(tx);
        sink.retry(TurnId(1), 1, 2, Duration::from_secs(1));
        sink.retry(TurnId(1), 2, 2, Duration::from_secs(1));
        assert_eq!(sink.saturated_count(), 1);
    }

    #[test]
    fn saturated_queue_retains_only_the_latest_live_snapshot_per_activity() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let mut sink = ActivitySink::default();
        sink.install(tx);
        sink.retry(TurnId(5), 1, 3, Duration::from_secs(1));
        sink.retry(TurnId(5), 2, 3, Duration::from_secs(1));
        sink.retry(TurnId(5), 3, 3, Duration::from_secs(1));

        let pending = sink.take_pending_snapshots();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, "turn-5:retry_backoff");
        assert_eq!(pending[0].attempt, 3);
        assert_eq!(pending[0].state, ActivityState::Retrying);
    }

    #[test]
    fn saturated_queue_retains_terminal_snapshots_for_run_boundary_drain() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let mut sink = ActivitySink::default();
        sink.install(tx);
        let answer = sink.span(ActivityStage::AnswerComplete, Some(TurnId(9)));
        answer.complete();
        let pending = sink.take_pending_terminals();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].detail_code,
            Some(ActivityDetailCode::AnswerComplete)
        );
        assert_eq!(pending[0].state, ActivityState::Succeeded);
        assert!(pending[0].updated_at_unix_ms > pending[0].started_at_unix_ms);
    }

    #[test]
    fn saturated_terminal_tail_keeps_answer_before_finalizing_barrier() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let mut sink = ActivitySink::default();
        sink.install(tx);
        sink.span(ActivityStage::AnswerComplete, Some(TurnId(11)))
            .complete();
        sink.span(ActivityStage::FinalizingEvidence, Some(TurnId(11)))
            .complete();

        let mut tail = sink.take_pending_terminals();
        while let Ok(event) = rx.try_recv() {
            tail.push(event);
        }
        tail.sort_by_key(|event| event.updated_at_unix_ms);
        let answer = tail
            .iter()
            .position(|event| {
                event.state.is_terminal()
                    && event.detail_code == Some(ActivityDetailCode::AnswerComplete)
            })
            .expect("answer-complete terminal retained");
        let finalizing = tail
            .iter()
            .position(|event| {
                event.state.is_terminal()
                    && event.detail_code == Some(ActivityDetailCode::RecordCommit)
            })
            .expect("finalizing terminal retained");
        assert!(answer < finalizing);
    }
}
