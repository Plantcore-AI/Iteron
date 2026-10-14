//! Read-only lossy fanout: the existing bus owns producer bounds and loss accounting.
use crate::{
    EventSubscriptionV1, ExtensionDispatchPolicy, ExtensionReadErrorV1, ExtensionSurfaceV1,
};
use iteron_obs::lifecycle::{LifecycleBus, LifecycleSubscriber};
use iteron_protocol::LifecycleEventEnvelope;
use serde::Serialize;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};
#[derive(Debug, Clone, Serialize)]
pub struct ExtensionEventBatchV1 {
    pub version: u32,
    pub events: Vec<LifecycleEventEnvelope>,
    pub scanned: u32,
    pub delivery: &'static str,
}
pub trait ExtensionEventsReadPort: Send + Sync {
    fn read(
        &self,
        limit: usize,
        timeout_ms: u64,
    ) -> Result<ExtensionEventBatchV1, ExtensionReadErrorV1>;
}
pub struct ExtensionEventReader {
    binding: EventSubscriptionV1,
    subscriber: LifecycleSubscriber,
    lease: Mutex<()>,
    policy: Option<Arc<dyn ExtensionDispatchPolicy>>,
}
impl ExtensionEventReader {
    /// Host supplies the already-owned bus after verified binding. The resulting handle cannot emit.
    pub fn bind(
        bus: &LifecycleBus,
        binding: EventSubscriptionV1,
        policy: Option<Arc<dyn ExtensionDispatchPolicy>>,
    ) -> Result<Self, ExtensionReadErrorV1> {
        if !binding.validate() {
            return Err(ExtensionReadErrorV1::InvalidRequest);
        }
        let subscriber = bus
            .subscribe(binding.queue_capacity)
            .map_err(|_| ExtensionReadErrorV1::Unavailable)?;
        Ok(Self {
            binding,
            subscriber,
            lease: Mutex::new(()),
            policy,
        })
    }
}
impl ExtensionEventsReadPort for ExtensionEventReader {
    fn read(
        &self,
        limit: usize,
        timeout_ms: u64,
    ) -> Result<ExtensionEventBatchV1, ExtensionReadErrorV1> {
        if !(1..=64).contains(&limit) || timeout_ms > 60_000 {
            return Err(ExtensionReadErrorV1::InvalidRequest);
        }
        let _lease = self
            .lease
            .try_lock()
            .map_err(|_| ExtensionReadErrorV1::Busy)?;
        let admitted = || {
            self.policy
                .as_ref()
                .is_none_or(|p| p.admits(ExtensionSurfaceV1::EventSubscription, &self.binding.name))
        };
        if !admitted() {
            return Err(ExtensionReadErrorV1::Revoked);
        }
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(timeout_ms))
            .ok_or(ExtensionReadErrorV1::InvalidRequest)?;
        let mut events = Vec::with_capacity(limit);
        let mut scanned = 0;
        while scanned < 64 && events.len() < limit {
            let received = if scanned == 0 && timeout_ms != 0 {
                self.subscriber
                    .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                    .map_err(|error| match error {
                        mpsc::RecvTimeoutError::Timeout => mpsc::TryRecvError::Empty,
                        mpsc::RecvTimeoutError::Disconnected => mpsc::TryRecvError::Disconnected,
                    })
            } else {
                self.subscriber.try_recv()
            };
            match received {
                Ok(event) => {
                    scanned += 1;
                    if self
                        .binding
                        .event_ids
                        .iter()
                        .any(|id| event.event_id.as_str() == id)
                    {
                        events.push((*event).clone());
                    }
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err(ExtensionReadErrorV1::Unavailable);
                }
            }
        }
        if !admitted() {
            return Err(ExtensionReadErrorV1::Revoked);
        }
        Ok(ExtensionEventBatchV1 {
            version: 1,
            events,
            scanned,
            delivery: "lossy_content_free_lifecycle_bus_not_durable_replay",
        })
    }
}
