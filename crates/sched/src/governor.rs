//! The bounded-concurrency governor. Little's Law says a concurrency limit is the only honest
//! knob against a queue you do not own (`docs/intake/scheduling-and-queueing-theory.md`): the
//! harness is a *source* doing admission in front of a black-box API. So we cap inflight work,
//! full stop — no clever cost-aware optimizer (ADR-003/004 refuse it).
//!
//! This is a thin wrapper over a Tokio semaphore, with the cap named and bounded (invariant #1).

use std::sync::Arc;
use tokio::sync::Semaphore;

#[derive(Clone)]
pub struct Governor {
    sem: Arc<Semaphore>,
    max: usize,
}

impl Governor {
    /// A governor allowing `max` concurrent inflight operations. `max` is a hard ceiling, cited
    /// at the call site (ADR-004: subagent fan-out ceiling is 4-6 by Amdahl; tool concurrency
    /// can be higher since pure reads are cheap).
    pub fn new(max: usize) -> Self {
        let max = max.max(1);
        Governor {
            sem: Arc::new(Semaphore::new(max)),
            max,
        }
    }

    /// Acquire a slot, blocking until one is free. The returned guard releases on drop, so a
    /// panic in the guarded work cannot leak a permit (bounded by construction).
    pub async fn acquire(&self) -> tokio::sync::OwnedSemaphorePermit {
        self.sem
            .clone()
            .acquire_owned()
            .await
            .expect("governor semaphore is never closed")
    }

    /// Try to acquire a slot without blocking. Returns None if at the cap — used where the
    /// caller (a sync context) must not await, and can fall back to running the work inline.
    pub fn try_acquire(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.sem.clone().try_acquire_owned().ok()
    }

    pub fn max(&self) -> usize {
        self.max
    }

    /// How many slots are free right now (for obs / backpressure signals).
    pub fn available(&self) -> usize {
        self.sem.available_permits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn never_exceeds_the_cap() {
        let gov = Governor::new(3);
        let inflight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..20 {
            let gov = gov.clone();
            let inflight = inflight.clone();
            let peak = peak.clone();
            handles.push(tokio::spawn(async move {
                let _permit = gov.acquire().await;
                let now = inflight.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                inflight.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert!(
            peak.load(Ordering::SeqCst) <= 3,
            "concurrency must never exceed the cap"
        );
    }
}
