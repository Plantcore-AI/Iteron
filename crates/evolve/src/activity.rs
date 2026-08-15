//! Bounded publisher for the same content-free activity events used by everyday runtime work.

pub use iteron_protocol::{
    ACTIVITY_SCHEMA_VERSION, ActivityCancelability, ActivityDetailCode, ActivityEvent,
    ActivityKind, ActivityOwner, ActivityProgress, ActivityState,
};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};

const DEFAULT_ACTIVITY_CAPACITY: usize = 128;
const MAX_ACTIVITY_CAPACITY: usize = 1_024;
const MAX_ACTIVITY_STAGES: usize = 128;

#[derive(Clone, Debug, Default)]
pub struct ActivityCancellation(Arc<AtomicBool>);

impl ActivityCancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivityDelivery {
    Delivered,
    Coalesced,
    /// The renderer was closed or a semantic snapshot met a full presentation queue. Research
    /// execution remains authoritative; Activity is additive and cannot change its outcome.
    Dropped,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ActivityError {
    #[error("activity event does not satisfy the shared protocol contract")]
    InvalidEvent,
    #[error("activity stage table reached its bound")]
    TooManyStages,
    #[error("activity consumer is closed")]
    Closed,
    #[error("activity queue is full at a semantic boundary")]
    Backpressure,
}

/// Nonblocking publisher used by offline eval/evolve entry points. Token-like progress can
/// coalesce; a saturated or closed renderer reports `Dropped` but never changes the experiment's
/// authoritative result. Durable experiment evidence is owned by the evaluator/transcript, not by
/// this presentation queue.
#[derive(Clone)]
pub struct ActivityPublisher {
    sender: SyncSender<ActivityEvent>,
    cancellation: ActivityCancellation,
    starts: Arc<Mutex<BTreeMap<String, u64>>>,
}

impl ActivityPublisher {
    pub fn emit(&self, event: ActivityEvent) -> Result<ActivityDelivery, ActivityError> {
        event.validate().map_err(|_| ActivityError::InvalidEvent)?;
        let coalescible = event.progress.is_some() && !event.state.is_terminal();
        match self.sender.try_send(event) {
            Ok(()) => Ok(ActivityDelivery::Delivered),
            Err(TrySendError::Full(_)) if coalescible => Ok(ActivityDelivery::Coalesced),
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                Ok(ActivityDelivery::Dropped)
            }
        }
    }

    pub fn stage(
        &self,
        stage: &str,
        state: ActivityState,
        progress: Option<ActivityProgress>,
        detail_code: ActivityDetailCode,
    ) -> Result<ActivityDelivery, ActivityError> {
        let now = now_unix_ms();
        let mut starts = self
            .starts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let max_stages = iteron_tunables::param_usize(
            "evolve.activity.max_activity_stages",
            MAX_ACTIVITY_STAGES,
        )
        .clamp(1, MAX_ACTIVITY_STAGES);
        if !starts.contains_key(stage) && starts.len() == max_stages {
            return Err(ActivityError::TooManyStages);
        }
        let started = *starts.entry(stage.to_owned()).or_insert(now);
        if state.is_terminal() {
            starts.remove(stage);
        }
        drop(starts);
        self.emit(ActivityEvent {
            schema_version: ACTIVITY_SCHEMA_VERSION,
            id: stage.to_owned(),
            parent_id: None,
            kind: ActivityKind::Verification,
            state,
            owner: ActivityOwner::Runtime,
            started_at_unix_ms: started,
            updated_at_unix_ms: now.max(started),
            attempt: 0,
            limit: 0,
            next_retry_at_unix_ms: None,
            deadline_unix_ms: None,
            cancelability: ActivityCancelability::Cooperative,
            detail_code: Some(detail_code),
            progress,
        })
    }

    /// Publish one content-free evidence identity under its named stage using the shared event
    /// schema. The evidence id is an opaque code (normally a digest), never a path or result body.
    pub fn evidence(
        &self,
        stage: &str,
        evidence_id: &str,
    ) -> Result<ActivityDelivery, ActivityError> {
        let now = now_unix_ms();
        self.emit(ActivityEvent {
            schema_version: ACTIVITY_SCHEMA_VERSION,
            id: evidence_id.to_owned(),
            parent_id: Some(stage.to_owned()),
            kind: ActivityKind::Persistence,
            state: ActivityState::Succeeded,
            owner: ActivityOwner::Runtime,
            started_at_unix_ms: now,
            updated_at_unix_ms: now,
            attempt: 0,
            limit: 0,
            next_retry_at_unix_ms: None,
            deadline_unix_ms: None,
            cancelability: ActivityCancelability::None,
            detail_code: Some(ActivityDetailCode::Checkpoint),
            progress: None,
        })
    }

    pub fn cancellation(&self) -> ActivityCancellation {
        self.cancellation.clone()
    }
}

pub struct ActivityReceiver {
    receiver: Receiver<ActivityEvent>,
}

impl ActivityReceiver {
    pub fn recv(&self) -> Result<ActivityEvent, std::sync::mpsc::RecvError> {
        self.receiver.recv()
    }
}

pub fn activity_channel(capacity: Option<usize>) -> (ActivityPublisher, ActivityReceiver) {
    let max_capacity = iteron_tunables::param_usize(
        "evolve.activity.max_activity_capacity",
        MAX_ACTIVITY_CAPACITY,
    )
    .clamp(1, MAX_ACTIVITY_CAPACITY);
    let capacity = capacity
        .unwrap_or_else(|| {
            iteron_tunables::param_usize(
                "evolve.activity.default_activity_capacity",
                DEFAULT_ACTIVITY_CAPACITY,
            )
        })
        .clamp(1, max_capacity);
    let (sender, receiver) = std::sync::mpsc::sync_channel(capacity);
    let cancellation = ActivityCancellation::default();
    (
        ActivityPublisher {
            sender,
            cancellation: cancellation.clone(),
            starts: Arc::new(Mutex::new(BTreeMap::new())),
        },
        ActivityReceiver { receiver },
    )
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publisher_uses_shared_protocol_and_cancellation() {
        let (publisher, receiver) = activity_channel(Some(2));
        publisher
            .stage(
                "eval.score",
                ActivityState::Running,
                Some(ActivityProgress {
                    completed: 0,
                    total: 2,
                }),
                ActivityDetailCode::Verification,
            )
            .unwrap();
        let cancellation = publisher.cancellation();
        let event = receiver.recv().unwrap();
        assert_eq!(
            event.schema_version,
            iteron_protocol::ACTIVITY_SCHEMA_VERSION
        );
        assert_eq!(event.id, "eval.score");
        cancellation.cancel();
        assert!(publisher.cancellation().is_cancelled());
    }

    #[test]
    fn renderer_saturation_and_closure_are_additive() {
        let (publisher, receiver) = activity_channel(Some(1));
        publisher
            .stage(
                "eval.one",
                ActivityState::Running,
                None,
                ActivityDetailCode::Verification,
            )
            .unwrap();
        assert_eq!(
            publisher
                .stage(
                    "eval.two",
                    ActivityState::Succeeded,
                    None,
                    ActivityDetailCode::Verification,
                )
                .unwrap(),
            ActivityDelivery::Dropped
        );
        drop(receiver);
        assert_eq!(
            publisher
                .evidence("eval.one", "sha256:renderer-closed")
                .unwrap(),
            ActivityDelivery::Dropped
        );
    }
}
