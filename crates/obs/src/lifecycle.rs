//! Bounded content-free lifecycle flight recorder and fan-out bus.
//!
//! Durable state remains in `iteron-record`. This plane is deliberately lossy under contention or a
//! slow observer, but every loss is counted; no Hook/exporter can backpressure an agent turn.

use iteron_protocol::{
    DurabilityClass, EffectId, ExportPolicy, JobId, LifecycleEventEnvelope, LifecycleEventRef,
    LifecyclePayload, RunId, Seq, SessionId, SubagentId, SubmissionId, TurnId, WorkflowId,
};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, TryLockError, Weak, mpsc};
use std::time::{Duration, Instant};

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
    events: Mutex<PriorityEventQueue>,
    subscribers: Mutex<Vec<Weak<SubscriberQueue>>>,
    next_ordinal: AtomicU64,
    dropped_oldest: AtomicU64,
    dropped_low_value: AtomicU64,
    dropped_contention: AtomicU64,
    dropped_subscriber: AtomicU64,
    invalid: AtomicU64,
}

#[derive(Debug, Clone)]
pub struct FlightRecorderSnapshot {
    pub events: Vec<LifecycleEventEnvelope>,
    pub next_ordinal: u64,
    pub dropped_oldest: u64,
    pub dropped_low_value: u64,
    pub dropped_contention: u64,
    pub dropped_subscriber: u64,
    pub invalid: u64,
}

#[derive(Debug)]
struct SubscriberQueue {
    capacity: usize,
    events: Mutex<PriorityEventQueue>,
    ready: Condvar,
}

/// Two FIFO classes preserve value-aware boundedness without scanning the whole recorder on every
/// overflow. Ordinals remain the single global order; reads merge the two queue heads. A low-value
/// progress row can never evict a decision/terminal, while a high-value row evicts low-value work
/// first and otherwise the oldest high-value row.
#[derive(Debug, Default)]
struct PriorityEventQueue {
    low: VecDeque<Arc<LifecycleEventEnvelope>>,
    high: VecDeque<Arc<LifecycleEventEnvelope>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PriorityPush {
    Stored,
    StoredAfterLowDrop,
    StoredAfterHighDrop,
    DroppedIncoming,
}

impl PriorityEventQueue {
    fn len(&self) -> usize {
        self.low.len().saturating_add(self.high.len())
    }

    fn is_empty(&self) -> bool {
        self.low.is_empty() && self.high.is_empty()
    }

    fn push(
        &mut self,
        event: Arc<LifecycleEventEnvelope>,
        low_value: bool,
        capacity: usize,
    ) -> PriorityPush {
        let displaced = if self.len() < capacity {
            PriorityPush::Stored
        } else if self.low.pop_front().is_some() {
            PriorityPush::StoredAfterLowDrop
        } else if low_value {
            return PriorityPush::DroppedIncoming;
        } else {
            let removed = self.high.pop_front();
            debug_assert!(removed.is_some(), "a full priority queue has an entry");
            PriorityPush::StoredAfterHighDrop
        };
        if low_value {
            self.low.push_back(event);
        } else {
            self.high.push_back(event);
        }
        displaced
    }

    fn pop_next(&mut self) -> Option<Arc<LifecycleEventEnvelope>> {
        match (self.low.front(), self.high.front()) {
            (Some(low), Some(high)) if low.ordinal < high.ordinal => self.low.pop_front(),
            (Some(_), Some(_)) => self.high.pop_front(),
            (Some(_), None) => self.low.pop_front(),
            (None, Some(_)) => self.high.pop_front(),
            (None, None) => None,
        }
    }

    fn ordered_arcs(&self) -> Vec<Arc<LifecycleEventEnvelope>> {
        let mut events = Vec::with_capacity(self.len());
        events.extend(self.low.iter().cloned());
        events.extend(self.high.iter().cloned());
        events.sort_unstable_by_key(|event| event.ordinal);
        events
    }
}

/// One bounded priority-aware subscriber. Producers never wait: high-frequency sampled events
/// may replace only another low-value event, while decisions/terminals can evict the oldest
/// low-value entry before falling back to ordinary FIFO eviction.
#[derive(Debug)]
pub struct LifecycleSubscriber {
    inner: Arc<SubscriberQueue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubscriberPush {
    Stored,
    StoredAfterDrop,
    Dropped,
    Busy,
}

impl SubscriberQueue {
    fn try_push(&self, event: Arc<LifecycleEventEnvelope>, low_value: bool) -> SubscriberPush {
        let Ok(mut events) = self.events.try_lock() else {
            return SubscriberPush::Busy;
        };
        let admitted = events.push(event, low_value, self.capacity);
        drop(events);
        match admitted {
            PriorityPush::Stored => {
                self.ready.notify_one();
                SubscriberPush::Stored
            }
            PriorityPush::StoredAfterLowDrop | PriorityPush::StoredAfterHighDrop => {
                self.ready.notify_one();
                SubscriberPush::StoredAfterDrop
            }
            PriorityPush::DroppedIncoming => SubscriberPush::Dropped,
        }
    }
}

impl LifecycleSubscriber {
    pub fn try_recv(&self) -> Result<Arc<LifecycleEventEnvelope>, mpsc::TryRecvError> {
        self.inner
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop_next()
            .ok_or(mpsc::TryRecvError::Empty)
    }

    pub fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Arc<LifecycleEventEnvelope>, mpsc::RecvTimeoutError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        let mut events = self
            .inner
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if let Some(event) = events.pop_next() {
                return Ok(event);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(mpsc::RecvTimeoutError::Timeout);
            }
            let (next, wait) = self
                .inner
                .ready
                .wait_timeout(events, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            events = next;
            if wait.timed_out() && events.is_empty() {
                return Err(mpsc::RecvTimeoutError::Timeout);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleRecordError {
    InvalidEnvelope(&'static str),
    RecorderBusy,
}

impl LifecycleBus {
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.clamp(
            1,
            iteron_tunables::param_integer(
                "obs.lifecycle.max_flight_recorder_events",
                MAX_FLIGHT_RECORDER_EVENTS,
            ),
        );
        Self {
            inner: Arc::new(Inner {
                capacity,
                events: Mutex::new(PriorityEventQueue::default()),
                subscribers: Mutex::new(Vec::new()),
                next_ordinal: AtomicU64::new(0),
                dropped_oldest: AtomicU64::new(0),
                dropped_low_value: AtomicU64::new(0),
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
        let event = Arc::new(event);
        let low_value = is_low_value(&event);
        match self.inner.events.try_lock() {
            Ok(mut events) => {
                match events.push(Arc::clone(&event), low_value, self.inner.capacity) {
                    PriorityPush::Stored => {}
                    PriorityPush::StoredAfterLowDrop => {
                        self.inner.dropped_oldest.fetch_add(1, Ordering::Relaxed);
                        self.inner.dropped_low_value.fetch_add(1, Ordering::Relaxed);
                    }
                    PriorityPush::StoredAfterHighDrop => {
                        self.inner.dropped_oldest.fetch_add(1, Ordering::Relaxed);
                    }
                    PriorityPush::DroppedIncoming => {
                        self.inner.dropped_low_value.fetch_add(1, Ordering::Relaxed);
                        return Ok(());
                    }
                }
            }
            Err(TryLockError::WouldBlock) | Err(TryLockError::Poisoned(_)) => {
                self.inner
                    .dropped_contention
                    .fetch_add(1, Ordering::Relaxed);
                return Err(LifecycleRecordError::RecorderBusy);
            }
        }

        if let Ok(mut subscribers) = self.inner.subscribers.try_lock() {
            subscribers.retain(|subscriber| {
                let Some(subscriber) = subscriber.upgrade() else {
                    return false;
                };
                match subscriber.try_push(Arc::clone(&event), low_value) {
                    SubscriberPush::Stored => true,
                    SubscriberPush::StoredAfterDrop
                    | SubscriberPush::Dropped
                    | SubscriberPush::Busy => {
                        self.inner
                            .dropped_subscriber
                            .fetch_add(1, Ordering::Relaxed);
                        true
                    }
                }
            });
        } else {
            self.inner
                .dropped_subscriber
                .fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    pub fn subscribe(&self, capacity: usize) -> Result<LifecycleSubscriber, &'static str> {
        let capacity = capacity.clamp(
            1,
            iteron_tunables::param_integer(
                "obs.lifecycle.max_subscriber_queue_events",
                MAX_SUBSCRIBER_QUEUE_EVENTS,
            ),
        );
        let subscriber = LifecycleSubscriber {
            inner: Arc::new(SubscriberQueue {
                capacity,
                events: Mutex::new(PriorityEventQueue::default()),
                ready: Condvar::new(),
            }),
        };
        let mut subscribers = self
            .inner
            .subscribers
            .try_lock()
            .map_err(|_| "lifecycle subscriber registry is busy")?;
        if subscribers.len()
            == iteron_tunables::param_integer(
                "obs.lifecycle.max_lifecycle_subscribers",
                MAX_LIFECYCLE_SUBSCRIBERS,
            )
        {
            return Err("lifecycle subscriber limit reached");
        }
        subscribers.push(Arc::downgrade(&subscriber.inner));
        Ok(subscriber)
    }

    pub fn snapshot(&self) -> FlightRecorderSnapshot {
        // Hold the producer-contended lock only while cloning Arcs. Deep-cloning every envelope
        // happens after release, so a maximum-capacity diagnostic snapshot cannot manufacture a
        // long burst of `RecorderBusy` losses.
        let retained = self
            .inner
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .ordered_arcs();
        let events = retained
            .into_iter()
            .map(|event| event.as_ref().clone())
            .collect();
        FlightRecorderSnapshot {
            events,
            next_ordinal: self.inner.next_ordinal.load(Ordering::Relaxed),
            dropped_oldest: self.inner.dropped_oldest.load(Ordering::Relaxed),
            dropped_low_value: self.inner.dropped_low_value.load(Ordering::Relaxed),
            dropped_contention: self.inner.dropped_contention.load(Ordering::Relaxed),
            dropped_subscriber: self.inner.dropped_subscriber.load(Ordering::Relaxed),
            invalid: self.inner.invalid.load(Ordering::Relaxed),
        }
    }
}

fn is_low_value(event: &LifecycleEventEnvelope) -> bool {
    event.event_id.spec().is_some_and(|spec| {
        spec.durability == DurabilityClass::FlightRecorderOnly
            || spec.default_export == ExportPolicy::Sampled
    })
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
        let event_id = iteron_protocol::lifecycle::registered_event_id(event_id).ok_or(
            LifecycleRecordError::InvalidEnvelope("unregistered lifecycle event id"),
        )?;
        let ordinal = self
            .bus
            .next_ordinal()
            .ok_or(LifecycleRecordError::InvalidEnvelope(
                "lifecycle ordinal exhausted",
            ))?;
        let event = LifecycleEventEnvelope {
            catalog_version: iteron_protocol::lifecycle::LIFECYCLE_CATALOG_VERSION,
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
        Self::new(iteron_tunables::param_integer(
            "obs.lifecycle.default_flight_recorder_events",
            DEFAULT_FLIGHT_RECORDER_EVENTS,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_protocol::lifecycle::{
        LIFECYCLE_CATALOG_VERSION, LifecycleEventId, LifecyclePayload,
    };

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

    fn named_event(ordinal: u64, id: &str) -> LifecycleEventEnvelope {
        let mut event = event(ordinal);
        event.event_id = LifecycleEventId::new(id).unwrap();
        event
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
        assert_eq!(receiver.try_recv().unwrap().ordinal, 2);
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

    #[test]
    fn sampled_progress_cannot_evict_decisions_or_terminals() {
        let bus = LifecycleBus::new(2);
        let receiver = bus.subscribe(2).unwrap();
        bus.record(named_event(0, "session.created")).unwrap();
        bus.record(named_event(1, "model.stream_item")).unwrap();
        bus.record(named_event(2, "model.stream_item")).unwrap();
        bus.record(named_event(3, "session.stopped")).unwrap();

        let snapshot = bus.snapshot();
        assert_eq!(snapshot.events.len(), 2);
        assert_eq!(snapshot.events[0].event_id.as_str(), "session.created");
        assert_eq!(snapshot.events[1].event_id.as_str(), "session.stopped");
        assert_eq!(snapshot.dropped_low_value, 2);

        assert_eq!(
            receiver.try_recv().unwrap().event_id.as_str(),
            "session.created"
        );
        assert_eq!(
            receiver.try_recv().unwrap().event_id.as_str(),
            "session.stopped"
        );
    }
}
