//! D2-21 oracle — provider network I/O and the scheduler are *injected* capability
//! ports, not direct-constructed dependencies.
//!
//! Two seams the architecture roadmap wants injected:
//!   * the scheduler's backoff wait — routed through an injected [`Clock`] instead
//!     of a direct `tokio::time::sleep`; and
//!   * a provider adapter's HTTP client — obtained from an injected
//!     [`HttpTransport`] instead of an inline `reqwest::Client::builder()`.
//!
//! This test target is absent on the base branch, and the `with_clock` / `Clock`
//! / `with_transport` / `HttpTransport` API it drives does not exist there, so it
//! is RED on base and GREEN once the injected ports land. Both ports are exercised
//! from `iteron-sched` (which depends on `iteron-provider`), keeping the oracle inside
//! the scheduler boundary tree.

use async_trait::async_trait;
use iteron_protocol::{ReasoningEffort, StopReason};
use iteron_provider::catalog::{DefaultHttpTransport, HttpClient, HttpTransport};
use iteron_provider::{
    Anthropic, ApiRoot, OpenAiResponses, Provider, ProviderError, StreamItem, TurnRequest,
    TurnResult, UsageReport,
};
use iteron_sched::{BackoffPolicy, Clock, RetryProvider, TokioClock};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

fn req() -> TurnRequest {
    TurnRequest {
        model: "m".into(),
        system: "s".into(),
        messages: vec![],
        input_images: Vec::new(),
        tools: vec![],
        max_tokens: 10,
        cache_system: false,
        thinking_budget: 0,
        reasoning_effort: ReasoningEffort::Low,
        controls: Default::default(),
    }
}

// ---------------------------------------------------------------------------
// Scheduler time port
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Provider network-I/O port
// ---------------------------------------------------------------------------

/// A transport whose client construction is observable and can be forced to fail.
struct ProbeTransport {
    built: AtomicU32,
    fail: bool,
}

impl HttpTransport for ProbeTransport {
    fn client(&self) -> Result<HttpClient, ProviderError> {
        self.built.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            Err(ProviderError::Configuration(
                "probe refused transport".into(),
            ))
        } else {
            // Delegate to the default secure client so the adapter is otherwise real.
            DefaultHttpTransport.client(iteron_provider::provider_transport_timeout_policy())
        }
    }
}

#[tokio::test]
async fn anthropic_obtains_its_client_from_the_injected_transport_port() {
    let transport = ProbeTransport {
        built: AtomicU32::new(0),
        fail: false,
    };
    let root = ApiRoot::parse("https://api.anthropic.com/v1").expect("valid root");

    let provider = Anthropic::with_transport("k".into(), root, &transport);
    assert!(
        provider.is_ok(),
        "adapter builds through the injected transport"
    );
    assert_eq!(
        transport.built.load(Ordering::SeqCst),
        1,
        "the client came from the injected transport port, not an inline reqwest builder"
    );
}

#[tokio::test]
async fn injected_transport_failure_fails_adapter_construction() {
    // A refused transport port must fail construction. This is only observable if
    // the adapter actually goes through the injected port for its network I/O; an
    // inline `reqwest::Client::builder()` could never surface this error.
    let transport = ProbeTransport {
        built: AtomicU32::new(0),
        fail: true,
    };
    let root = ApiRoot::parse("https://api.openai.com/v1").expect("valid root");

    let provider = OpenAiResponses::with_transport("k".into(), root, &transport);
    assert!(
        matches!(provider, Err(ProviderError::Configuration(_))),
        "a refused transport port must fail adapter construction"
    );
    assert_eq!(
        transport.built.load(Ordering::SeqCst),
        1,
        "the adapter consulted the injected transport port exactly once"
    );
}
