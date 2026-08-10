//! Bounded content-free lifecycle flight recorder and fan-out bus.
//!
//! Durable state remains in `core-record`. This plane is deliberately lossy under contention or a
//! slow observer, but every loss is counted; no Hook/exporter can backpressure an agent turn.

use core_protocol::{
    EffectId, JobId, LifecycleEventEnvelope, LifecycleEventRef, LifecyclePayload, RunId, Seq,
    SessionId, SubagentId, SubmissionId, TurnId, WorkflowId,
};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, TryLockError, mpsc};
use std::time::Instant;

pub const DEFAULT_FLIGHT_RECORDER_EVENTS: usize = 4096;
pub const MAX_FLIGHT_RECORDER_EVENTS: usize = 65_536;
pub const MAX_LIFECYCLE_SUBSCRIBERS: usize = 32;
pub const MAX_SUBSCRIBER_QUEUE_EVENTS: usize = 4096;

#[derive(Debug, Clone)]
pub struct LifecycleBus {
    inner: Arc<Inner>,
}

/// Correlation carried by one lifecycle event. Callers fill only identities already owned by the
/// boundary they are instrumenting; the emitter never invents an effect, workflow, child or job.
#[derive(Debug, Clone, Default)]
pub struct LifecycleCorrelation {
    pub session_id: Option<SessionId>,
    pub run_id: Option<RunId>,
    pub turn_id: Option<TurnId>,
    pub submission_id: Option<SubmissionId>,
    pub effect_id: Option<EffectId>,
    pub workflow_id: Option<WorkflowId>,
    pub subagent_id: Option<SubagentId>,
    pub job_id: Option<JobId>,
    pub parent_event: Option<LifecycleEventRef>,
    pub durable_seq: Option<Seq>,
}

/// Cloneable content-free lifecycle writer. It supplies only ordering and monotonic time; all
/// authority and correlations come from the caller, and recording remains non-blocking.
#[derive(Debug, Clone)]
pub struct LifecycleEmitter {
    bus: LifecycleBus,
    started: Instant,
}

#[derive(Debug)]
struct Inner {
    capacity: usize,
    events: Mutex<VecDeque<LifecycleEventEnvelope>>,
    subscribers: Mutex<Vec<mpsc::SyncSender<LifecycleEventEnvelope>>>,
    next_ordinal: AtomicU64,
    dropped_oldest: AtomicU64,
    dropped_contention: AtomicU64,
    dropped_subscriber: AtomicU64,
    invalid: AtomicU64,
}

#[derive(Debug, Clone)]
pub struct FlightRecorderSnapshot {
    pub events: Vec<LifecycleEventEnvelope>,
    pub next_ordinal: u64,
    pub dropped_oldest: u64,
    pub dropped_contention: u64,
    pub dropped_subscriber: u64,
    pub invalid: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleRecordError {
    InvalidEnvelope(&'static str),
    RecorderBusy,
}

impl LifecycleBus {
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.clamp(1, MAX_FLIGHT_RECORDER_EVENTS);
        Self {
            inner: Arc::new(Inner {
                capacity,
                events: Mutex::new(VecDeque::with_capacity(capacity)),
                subscribers: Mutex::new(Vec::new()),
                next_ordinal: AtomicU64::new(0),
                dropped_oldest: AtomicU64::new(0),
                dropped_contention: AtomicU64::new(0),
                dropped_subscriber: AtomicU64::new(0),
                invalid: AtomicU64::new(0),
            }),
        }
    }

    /// Assign the next stream-local ordinal. Exhaustion is explicit; zero is never reused.
    pub fn next_ordinal(&self) -> Option<u64> {
        self.inner
            .next_ordinal
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .ok()
    }

    /// Record without waiting for a lock or observer. A contended local recorder is a counted
    /// telemetry loss, not a reason to delay the control path.
    pub fn record(&self, event: LifecycleEventEnvelope) -> Result<(), LifecycleRecordError> {
        if let Err(reason) = event.validate() {
            self.inner.invalid.fetch_add(1, Ordering::Relaxed);
            return Err(LifecycleRecordError::InvalidEnvelope(reason));
        }
        match self.inner.events.try_lock() {
            Ok(mut events) => {
                if events.len() == self.inner.capacity {
                    events.pop_front();
                    self.inner.dropped_oldest.fetch_add(1, Ordering::Relaxed);
                }
                events.push_back(event.clone());
            }
            Err(TryLockError::WouldBlock) | Err(TryLockError::Poisoned(_)) => {
                self.inner
                    .dropped_contention
                    .fetch_add(1, Ordering::Relaxed);
                return Err(LifecycleRecordError::RecorderBusy);
            }
        }

        if let Ok(mut subscribers) = self.inner.subscribers.try_lock() {
            subscribers.retain(|subscriber| match subscriber.try_send(event.clone()) {
                Ok(()) => true,
                Err(mpsc::TrySendError::Full(_)) => {
                    self.inner
                        .dropped_subscriber
                        .fetch_add(1, Ordering::Relaxed);
                    true
                }
                Err(mpsc::TrySendError::Disconnected(_)) => false,
            });
        } else {
            self.inner
                .dropped_subscriber
                .fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    pub fn subscribe(
        &self,
        capacity: usize,
    ) -> Result<mpsc::Receiver<LifecycleEventEnvelope>, &'static str> {
        let capacity = capacity.clamp(1, MAX_SUBSCRIBER_QUEUE_EVENTS);
        let (sender, receiver) = mpsc::sync_channel(capacity);
        let mut subscribers = self
            .inner
            .subscribers
            .try_lock()
            .map_err(|_| "lifecycle subscriber registry is busy")?;
        if subscribers.len() == MAX_LIFECYCLE_SUBSCRIBERS {
            return Err("lifecycle subscriber limit reached");
        }
        subscribers.push(sender);
        Ok(receiver)
    }

    pub fn snapshot(&self) -> FlightRecorderSnapshot {
        let events = self
            .inner
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect();
        FlightRecorderSnapshot {
            events,
            next_ordinal: self.inner.next_ordinal.load(Ordering::Relaxed),
            dropped_oldest: self.inner.dropped_oldest.load(Ordering::Relaxed),
            dropped_contention: self.inner.dropped_contention.load(Ordering::Relaxed),
            dropped_subscriber: self.inner.dropped_subscriber.load(Ordering::Relaxed),
            invalid: self.inner.invalid.load(Ordering::Relaxed),
        }
    }
}

impl LifecycleEmitter {
    pub fn new(bus: LifecycleBus) -> Self {
        Self {
            bus,
            started: Instant::now(),
        }
    }

    pub fn bus(&self) -> &LifecycleBus {
        &self.bus
    }

    /// Emit one registered event. Unknown ids and ordinal exhaustion are explicit errors; a busy
    /// recorder is returned as a counted [`LifecycleRecordError`] and never waits on the caller.
    pub fn emit(
        &self,
        event_id: &str,
        correlation: LifecycleCorrelation,
        payload: LifecyclePayload,
    ) -> Result<LifecycleEventEnvelope, LifecycleRecordError> {
        let event_id = core_protocol::lifecycle::registered_event_id(event_id).ok_or(
            LifecycleRecordError::InvalidEnvelope("unregistered lifecycle event id"),
        )?;
        let ordinal = self
            .bus
            .next_ordinal()
            .ok_or(LifecycleRecordError::InvalidEnvelope(
                "lifecycle ordinal exhausted",
            ))?;
        let event = LifecycleEventEnvelope {
            catalog_version: core_protocol::lifecycle::LIFECYCLE_CATALOG_VERSION,
            event_id,
            event_version: 1,
            ordinal,
            occurred_at_mono_ns: u64::try_from(self.started.elapsed().as_nanos())
                .unwrap_or(u64::MAX),
            session_id: correlation.session_id,
            run_id: correlation.run_id,
            turn_id: correlation.turn_id,
            submission_id: correlation.submission_id,
            effect_id: correlation.effect_id,
            workflow_id: correlation.workflow_id,
            subagent_id: correlation.subagent_id,
            job_id: correlation.job_id,
            parent_event: correlation.parent_event,
            durable_seq: correlation.durable_seq,
            payload,
        };
        self.bus.record(event.clone())?;
        Ok(event)
    }
}

impl Default for LifecycleBus {
    fn default() -> Self {
        Self::new(DEFAULT_FLIGHT_RECORDER_EVENTS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_protocol::lifecycle::{LIFECYCLE_CATALOG_VERSION, LifecycleEventId, LifecyclePayload};

    fn event(ordinal: u64) -> LifecycleEventEnvelope {
        LifecycleEventEnvelope {
            catalog_version: LIFECYCLE_CATALOG_VERSION,
            event_id: LifecycleEventId::new("session.created").unwrap(),
            event_version: 1,
            ordinal,
            occurred_at_mono_ns: ordinal,
            session_id: None,
            run_id: None,
            turn_id: None,
            submission_id: None,
            effect_id: None,
            workflow_id: None,
            subagent_id: None,
            job_id: None,
            parent_event: None,
            durable_seq: None,
            payload: LifecyclePayload::default(),
        }
    }

    #[test]
    fn ring_and_subscriber_overflow_are_bounded_and_counted() {
        let bus = LifecycleBus::new(2);
        let receiver = bus.subscribe(1).unwrap();
        bus.record(event(0)).unwrap();
        bus.record(event(1)).unwrap();
        bus.record(event(2)).unwrap();
        let snapshot = bus.snapshot();
        assert_eq!(snapshot.events.len(), 2);
        assert_eq!(snapshot.dropped_oldest, 1);
        assert_eq!(snapshot.dropped_subscriber, 2);
        assert_eq!(receiver.try_recv().unwrap().ordinal, 0);
    }

    #[test]
    fn invalid_ids_never_enter_the_recorder() {
        let bus = LifecycleBus::default();
        let mut bad = event(0);
        bad.event_id = LifecycleEventId::new("session.not_registered").unwrap();
        assert!(matches!(
            bus.record(bad),
            Err(LifecycleRecordError::InvalidEnvelope(_))
        ));
        assert_eq!(bus.snapshot().invalid, 1);
    }
}
