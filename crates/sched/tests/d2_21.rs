//! D2-21 oracle — the scheduler's backoff wait is an *injected* time port, not a
//! direct `tokio::time::sleep`.
//!
//! Injecting a custom [`Clock`] must route every retry wait through it. This test
//! target is absent on the base branch, and its `RetryProvider::with_clock` /
//! `Clock` API does not exist there, so it is RED on base and GREEN once the
//! injected scheduler port lands.

use async_trait::async_trait;
use core_protocol::{ReasoningEffort, StopReason};
use core_provider::{
    Provider, ProviderError, StreamItem, TurnRequest, TurnResult, UsageReport,
};
use core_sched::{BackoffPolicy, Clock, RetryProvider, TokioClock};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

/// Fails with a retryable 429 `fail_n` times, then succeeds.
struct Flaky {
    calls: AtomicU32,
    fail_n: u32,
}

#[async_trait]
impl Provider for Flaky {
    async fn turn(
        &self,
        _req: &TurnRequest,
        _on_item: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if n < self.fail_n {
            Err(ProviderError::Api {
                status: 429,
                body: "rate limited".into(),
            })
        } else {
            Ok(TurnResult {
                blocks: vec![],
                stop_reason: StopReason::EndTurn,
                usage: UsageReport::complete(Default::default()),
            })
        }
    }
}

/// A brokered time port: it records every wait and returns immediately instead of
/// touching the runtime clock.
struct CountingClock {
    sleeps: Arc<AtomicU32>,
    last: std::sync::Mutex<Option<Duration>>,
}

#[async_trait]
impl Clock for CountingClock {
    async fn sleep(&self, dur: Duration) {
        self.sleeps.fetch_add(1, Ordering::SeqCst);
        *self.last.lock().unwrap() = Some(dur);
    }
}

fn req() -> TurnRequest {
    TurnRequest {
        model: "m".into(),
        system: "s".into(),
        messages: vec![],
        tools: vec![],
        max_tokens: 10,
        cache_system: false,
        thinking_budget: 0,
        reasoning_effort: ReasoningEffort::Low,
    }
}

#[tokio::test]
async fn scheduler_backoff_waits_through_the_injected_clock_port() {
    let sleeps = Arc::new(AtomicU32::new(0));
    let clock = Arc::new(CountingClock {
        sleeps: Arc::clone(&sleeps),
        last: std::sync::Mutex::new(None),
    });
    let clock_port: Arc<dyn Clock> = clock.clone();

    let provider = RetryProvider::with_clock(
        Box::new(Flaky {
            calls: AtomicU32::new(0),
            fail_n: 3,
        }),
        BackoffPolicy {
            base_ms: 1,
            cap_ms: 2,
            max_attempts: 6,
        },
        clock_port,
    );

    let result = provider.turn(&req(), &mut |_| {}).await;
    assert!(result.is_ok(), "run survives three retryable failures");

    // Three failures -> three brokered backoff waits, ALL through the injected
    // port. If the scheduler still reached for `tokio::time::sleep` directly, the
    // injected clock would never be consulted and this counter would stay 0.
    assert_eq!(
        sleeps.load(Ordering::SeqCst),
        3,
        "every backoff wait must route through the injected clock port"
    );
    assert!(
        clock.last.lock().unwrap().is_some(),
        "the injected port observed the actual backoff duration"
    );
}

#[tokio::test]
async fn default_clock_port_is_publicly_injectable() {
    // The default port is nameable and injectable: `new` is just `with_clock`
    // wired to `TokioClock`, so both paths are honest injections of the seam.
    let provider = RetryProvider::with_clock(
        Box::new(Flaky {
            calls: AtomicU32::new(0),
            fail_n: 0,
        }),
        BackoffPolicy::default(),
        Arc::new(TokioClock),
    );
    assert!(provider.turn(&req(), &mut |_| {}).await.is_ok());
}
