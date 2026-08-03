//! `RetryProvider` — wraps any `Provider` and rides out rate limits.
//!
//! A potentially billable turn is retried only when the provider explicitly reports rate
//! limiting or overload, and only before any stream content reaches the callback. Bare transport
//! errors, 408/409, and generic 5xx responses are ambiguous: the provider may already have
//! accepted or billed the request, while the common provider protocol has no portable
//! idempotency key. They therefore fail closed. If a stream dies after items were emitted,
//! retrying would also double-emit into an append-only transcript, so that error is propagated
//! (correctness over cleverness; ADR-006 R2).

use crate::backoff::{BackoffPolicy, Jitter, full_jitter};
use crate::clock::{Clock, TokioClock};
use async_trait::async_trait;
use core_provider::{
    EffortApplication, Provider, ProviderAttemptSemantics, ProviderError, RetryDisposition,
    StreamItem, TurnRequest, TurnResult,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// What a retrying decorator absorbed on behalf of its callers.
///
/// Before this existed the attempt counter was a `turn`-local `u32` and the waiting was a bare
/// `sleep`, so a turn that spent a second in backoff and a turn that answered immediately were
/// indistinguishable in every record and every summary (I-65). These two numbers are the whole
/// difference: how many attempts were paid for a single logical turn, and how long the scheduler
/// made the caller wait for them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetryAccounting {
    /// Retried attempts, i.e. one less than the attempts made for every turn that was retried.
    pub retries: u64,
    /// Total time slept in backoff. Microseconds, because a jittered first backoff is routinely
    /// under a millisecond and a millisecond counter would report it as free.
    pub backoff_us: u64,
}

impl RetryAccounting {
    /// Backoff in whole milliseconds, rounded up. A non-zero wait never reports as `0`.
    pub const fn backoff_ms_ceil(self) -> u64 {
        self.backoff_us.div_ceil(1_000)
    }
}

/// Cumulative, lock-free counters shared with whoever wants to read them. A retry decorator may
/// be shared by concurrent turns, so this is deliberately additive rather than per-turn state.
#[derive(Debug, Default)]
pub struct RetryObservations {
    retries: AtomicU64,
    backoff_us: AtomicU64,
}

impl RetryObservations {
    fn record_backoff(&self, delay: std::time::Duration) {
        self.retries.fetch_add(1, Ordering::Relaxed);
        self.backoff_us.fetch_add(
            u64::try_from(delay.as_micros()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    pub fn snapshot(&self) -> RetryAccounting {
        RetryAccounting {
            retries: self.retries.load(Ordering::Relaxed),
            backoff_us: self.backoff_us.load(Ordering::Relaxed),
        }
    }
}

pub struct RetryProvider {
    inner: Box<dyn Provider>,
    policy: BackoffPolicy,
    /// Injected time port: backoff waits go through this seam instead of a direct
    /// `tokio::time::sleep`, so scheduler time is brokered, not hard-wired (D2-21).
    clock: Arc<dyn Clock>,
    /// A synchronous probe so tests can observe backoff without sleeping. When set it
    /// short-circuits the clock; production paths leave it `None` and wait on the port.
    sleep_hook: Option<Box<dyn Fn(std::time::Duration) + Send + Sync>>,
    /// The trace backoff used to leave behind: every retried attempt and every microsecond
    /// waited, readable by a ledger without instrumenting the provider itself (I-65).
    observations: Arc<RetryObservations>,
}

impl RetryProvider {
    pub fn new(inner: Box<dyn Provider>, policy: BackoffPolicy) -> Self {
        Self::with_clock(inner, policy, Arc::new(TokioClock))
    }

    /// Construct with an injected time port. The scheduler waits between retry
    /// attempts through `clock` rather than the ambient runtime clock, so a host
    /// can broker, virtualize, or observe backoff (D2-21).
    pub fn with_clock(
        inner: Box<dyn Provider>,
        policy: BackoffPolicy,
        clock: Arc<dyn Clock>,
    ) -> Self {
        RetryProvider {
            inner,
            policy,
            clock,
            sleep_hook: None,
            observations: Arc::new(RetryObservations::default()),
        }
    }

    /// The live retry counters. Cloning the handle is how a host folds backoff into its ledger
    /// without owning the decorator or reaching through the `Provider` trait object.
    pub fn observations(&self) -> Arc<RetryObservations> {
        Arc::clone(&self.observations)
    }

    /// Cumulative retries and total waiting so far.
    pub fn accounting(&self) -> RetryAccounting {
        self.observations.snapshot()
    }

    async fn sleep(&self, d: std::time::Duration) {
        // Counted before the wait, not after: a turn cancelled mid-backoff still waited, and a
        // counter that only credited completed sleeps would report exactly the pathological case
        // as free.
        self.observations.record_backoff(d);
        if let Some(h) = &self.sleep_hook {
            h(d);
        } else {
            self.clock.sleep(d).await;
        }
    }
}

#[async_trait]
impl Provider for RetryProvider {
    fn provider_instance_id(&self) -> Option<&str> {
        self.inner.provider_instance_id()
    }

    fn attempt_semantics(&self) -> ProviderAttemptSemantics {
        if self.policy.max_attempts > 1 {
            ProviderAttemptSemantics::OpaqueInternalRetries
        } else {
            self.inner.attempt_semantics()
        }
    }

    fn supports_image_input(&self) -> bool {
        self.inner.supports_image_input()
    }

    fn effort_application(&self, req: &TurnRequest) -> EffortApplication {
        self.inner.effort_application(req)
    }

    fn run_notice(&self, req: &TurnRequest) -> Option<core_provider::ProviderNotice> {
        self.inner.run_notice(req)
    }

    fn preflight_notice(&self, req: &TurnRequest) -> Option<core_provider::ProviderNotice> {
        self.inner.preflight_notice(req)
    }

    async fn turn(
        &self,
        req: &TurnRequest,
        on_item: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        // Jitter belongs to this turn. Keeping it on the future removes shared lock contention
        // between concurrent turns and makes mutex poisoning structurally impossible.
        let mut jitter_source = Jitter::new();
        let mut attempt = 0u32;
        loop {
            // Guard: only forward items to the real callback once we are committed to this
            // attempt (i.e. content started). We wrap the callback to note "content emitted".
            let mut emitted = false;
            let mut guarded = |item: StreamItem| {
                emitted = true;
                on_item(item);
            };
            match self.inner.turn(req, &mut guarded).await {
                Ok(r) => return Ok(r),
                Err(e) => {
                    // RetryDisposition is deliberately conservative for paid inference: only a
                    // typed rate-limit/overload signal qualifies. "No content emitted" avoids
                    // transcript duplication but, by itself, says nothing about provider-side
                    // execution or billing.
                    let retryable = e.retry_disposition() == RetryDisposition::Transient;
                    if !retryable || emitted || attempt + 1 >= self.policy.max_attempts {
                        return Err(e);
                    }
                    let r01 = jitter_source.next01();
                    let jitter = full_jitter(&self.policy, attempt, r01);
                    // Retry-After is a server lower-bound hint. Respect it up to the configured
                    // cap so an untrusted or accidental multi-hour value cannot make a bounded
                    // agent run hang indefinitely.
                    let delay = e
                        .retry_after()
                        .map(|hint| {
                            hint.min(std::time::Duration::from_millis(self.policy.cap_ms))
                                .max(jitter)
                        })
                        .unwrap_or(jitter);
                    self.sleep(delay).await;
                    attempt += 1;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_protocol::StopReason;
    use core_provider::{
        AccountAvailability, AdapterKind, ApiResponseError, AvailabilityTransition, ErrorProfile,
        ErrorScope, NormalizedFailure, StreamError, UsageReport,
    };
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    /// A provider that fails with 429 for the first `fail_n` calls, then succeeds.
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

    #[derive(Debug, Clone, Copy)]
    enum ClassificationProbe {
        BareStatus(u16),
        TypedQuota429,
    }

    impl ClassificationProbe {
        fn error(self) -> ProviderError {
            match self {
                Self::BareStatus(status) => ProviderError::Api {
                    status,
                    body: "probe".into(),
                },
                Self::TypedQuota429 => ProviderError::ApiResponse(ApiResponseError {
                    status: 429,
                    body: "quota exhausted".into(),
                    body_truncated: false,
                    retry_after: None,
                    normalized: Box::new(NormalizedFailure {
                        adapter: AdapterKind::OpenAiCompatibleChat,
                        error_profile: ErrorProfile::OpenAi,
                        code: Some("insufficient_quota".into()),
                        public_message: "provider billing or quota is unavailable",
                        scope: ErrorScope::Account,
                        availability: AvailabilityTransition::Account(
                            AccountAvailability::BillingBlocked,
                        ),
                        retry: RetryDisposition::Never,
                        request_id: None,
                    }),
                }),
            }
        }
    }

    struct ClassificationProbeProvider {
        calls: Arc<AtomicU32>,
        failure: ClassificationProbe,
    }

    #[async_trait]
    impl Provider for ClassificationProbeProvider {
        async fn turn(
            &self,
            _req: &TurnRequest,
            _on_item: &mut (dyn FnMut(StreamItem) + Send),
        ) -> Result<TurnResult, ProviderError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(self.failure.error())
        }
    }

    #[tokio::test]
    async fn retry_provider_has_one_provider_error_classification_authority() {
        let cases = [
            (
                ClassificationProbe::BareStatus(429),
                RetryDisposition::Transient,
            ),
            (
                ClassificationProbe::BareStatus(529),
                RetryDisposition::Transient,
            ),
            (
                ClassificationProbe::BareStatus(503),
                RetryDisposition::Never,
            ),
            (ClassificationProbe::TypedQuota429, RetryDisposition::Never),
        ];

        for (failure, expected) in cases {
            assert_eq!(
                failure.error().retry_disposition(),
                expected,
                "the provider error owns classification for {failure:?}"
            );
            let calls = Arc::new(AtomicU32::new(0));
            let sleeps = Arc::new(AtomicU32::new(0));
            let sleeps_by_hook = Arc::clone(&sleeps);
            let mut provider = RetryProvider::new(
                Box::new(ClassificationProbeProvider {
                    calls: Arc::clone(&calls),
                    failure,
                }),
                BackoffPolicy {
                    base_ms: 1,
                    cap_ms: 2,
                    max_attempts: 2,
                },
            );
            provider.sleep_hook = Some(Box::new(move |_| {
                sleeps_by_hook.fetch_add(1, Ordering::SeqCst);
            }));
            let request = TurnRequest {
                model: "model".into(),
                system: "system".into(),
                messages: vec![],
                input_images: Vec::new(),
                tools: vec![],
                max_tokens: 10,
                cache_system: false,
                thinking_budget: 0,
                reasoning_effort: core_protocol::ReasoningEffort::Low,
            };

            assert!(provider.turn(&request, &mut |_| {}).await.is_err());
            let expected_calls = if expected == RetryDisposition::Transient {
                2
            } else {
                1
            };
            assert_eq!(calls.load(Ordering::SeqCst), expected_calls, "{failure:?}");
            assert_eq!(
                sleeps.load(Ordering::SeqCst),
                expected_calls - 1,
                "the scheduler follows retry_disposition for {failure:?}"
            );
        }
    }

    /// Holds every first attempt at one barrier, then rate-limits that whole wave. A shared retry
    /// decorator must allow all turns to reach the provider concurrently and independently retry.
    struct ConcurrentFirstWave {
        calls: Arc<AtomicU32>,
        turns: u32,
        first_wave: tokio::sync::Barrier,
    }

    #[async_trait]
    impl Provider for ConcurrentFirstWave {
        async fn turn(
            &self,
            _req: &TurnRequest,
            _on_item: &mut (dyn FnMut(StreamItem) + Send),
        ) -> Result<TurnResult, ProviderError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call < self.turns {
                self.first_wave.wait().await;
                return Err(ProviderError::Api {
                    status: 429,
                    body: "simultaneous rate limit".into(),
                });
            }
            Ok(TurnResult {
                blocks: vec![],
                stop_reason: StopReason::EndTurn,
                usage: UsageReport::complete(Default::default()),
            })
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shared_retry_provider_runs_concurrent_turns_without_jitter_locking_or_panic() {
        const TURNS: u32 = 64;

        let sleeps = Arc::new(AtomicU32::new(0));
        let sleeps_by_hook = Arc::clone(&sleeps);
        let calls = Arc::new(AtomicU32::new(0));
        let inner = ConcurrentFirstWave {
            calls: Arc::clone(&calls),
            turns: TURNS,
            first_wave: tokio::sync::Barrier::new(TURNS as usize),
        };
        let mut provider = RetryProvider::new(
            Box::new(inner),
            BackoffPolicy {
                base_ms: 1,
                cap_ms: 2,
                max_attempts: 2,
            },
        );
        provider.sleep_hook = Some(Box::new(move |_| {
            sleeps_by_hook.fetch_add(1, Ordering::SeqCst);
        }));
        let provider = Arc::new(provider);

        let mut tasks = Vec::with_capacity(TURNS as usize);
        for turn in 0..TURNS {
            let provider = Arc::clone(&provider);
            tasks.push(tokio::spawn(async move {
                let request = TurnRequest {
                    model: format!("model-{turn}"),
                    system: "system".into(),
                    messages: vec![],
                    input_images: Vec::new(),
                    tools: vec![],
                    max_tokens: 10,
                    cache_system: false,
                    thinking_budget: 0,
                    reasoning_effort: core_protocol::ReasoningEffort::Low,
                };
                provider.turn(&request, &mut |_| {}).await
            }));
        }

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            for task in tasks {
                assert!(
                    task.await
                        .expect("concurrent retry task must not panic")
                        .is_ok(),
                    "every simultaneous turn succeeds on its second attempt"
                );
            }
        })
        .await
        .expect("concurrent retries must not deadlock or serialize pathologically");

        assert_eq!(
            sleeps.load(Ordering::SeqCst),
            TURNS,
            "each turn owns exactly one independent backoff"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            TURNS * 2,
            "all first attempts and retries reached the inner provider"
        );
    }

    #[tokio::test]
    async fn retries_past_429_and_succeeds() {
        let flaky = Flaky {
            calls: AtomicU32::new(0),
            fail_n: 3,
        };
        let slept = Arc::new(AtomicU32::new(0));
        let s2 = slept.clone();
        let mut rp = RetryProvider::new(
            Box::new(flaky),
            BackoffPolicy {
                base_ms: 1,
                cap_ms: 2,
                max_attempts: 6,
            },
        );
        rp.sleep_hook = Some(Box::new(move |_| {
            s2.fetch_add(1, Ordering::SeqCst);
        }));
        let req = TurnRequest {
            model: "m".into(),
            system: "s".into(),
            messages: vec![],
            input_images: Vec::new(),
            tools: vec![],
            max_tokens: 10,
            cache_system: false,
            thinking_budget: 0,
            reasoning_effort: core_protocol::ReasoningEffort::Low,
        };
        let r = rp.turn(&req, &mut |_| {}).await;
        assert!(r.is_ok(), "a run must survive 3 consecutive 429s");
        assert_eq!(
            slept.load(Ordering::SeqCst),
            3,
            "backed off before each retry"
        );
    }

    /// I-65: the retried attempts and the waiting used to be a `turn`-local `u32` and a bare
    /// `sleep`, so a turn that survived three 429s reported exactly what an instant turn did.
    #[tokio::test]
    async fn a_retried_turn_reports_its_attempts_and_the_time_it_waited() {
        let mut rp = RetryProvider::new(
            Box::new(Flaky {
                calls: AtomicU32::new(0),
                fail_n: 3,
            }),
            BackoffPolicy {
                base_ms: 4,
                cap_ms: 8,
                max_attempts: 6,
            },
        );
        // Full jitter can pick a sub-millisecond delay, so pin the wait instead of racing a
        // real clock: the assertion is that waiting is counted at all, not how long it was.
        rp.sleep_hook = Some(Box::new(|_| {}));
        let observations = rp.observations();
        assert_eq!(observations.snapshot(), RetryAccounting::default());

        let req = TurnRequest {
            model: "m".into(),
            system: "s".into(),
            messages: vec![],
            input_images: Vec::new(),
            tools: vec![],
            max_tokens: 10,
            cache_system: false,
            thinking_budget: 0,
            reasoning_effort: core_protocol::ReasoningEffort::Low,
        };
        assert!(rp.turn(&req, &mut |_| {}).await.is_ok());

        let accounting = rp.accounting();
        assert_eq!(
            accounting.retries, 3,
            "three retried attempts were paid for one logical turn"
        );
        assert!(
            accounting.backoff_us > 0,
            "the turn waited in backoff and the record must be able to say so"
        );
        assert!(
            accounting.backoff_ms_ceil() >= 1,
            "a sub-millisecond wait rounds up rather than reporting as free"
        );
        assert_eq!(
            observations.snapshot(),
            accounting,
            "the shared handle and the decorator report the same counters"
        );
    }

    #[tokio::test]
    async fn a_turn_that_never_retried_reports_no_backoff() {
        let rp = RetryProvider::new(
            Box::new(Flaky {
                calls: AtomicU32::new(0),
                fail_n: 0,
            }),
            BackoffPolicy {
                base_ms: 1,
                cap_ms: 2,
                max_attempts: 6,
            },
        );
        let req = TurnRequest {
            model: "m".into(),
            system: "s".into(),
            messages: vec![],
            input_images: Vec::new(),
            tools: vec![],
            max_tokens: 10,
            cache_system: false,
            thinking_budget: 0,
            reasoning_effort: core_protocol::ReasoningEffort::Low,
        };
        assert!(rp.turn(&req, &mut |_| {}).await.is_ok());
        assert_eq!(rp.accounting(), RetryAccounting::default());
    }

    #[tokio::test]
    async fn gives_up_after_max_attempts() {
        let flaky = Flaky {
            calls: AtomicU32::new(0),
            fail_n: 100,
        };
        let mut rp = RetryProvider::new(
            Box::new(flaky),
            BackoffPolicy {
                base_ms: 1,
                cap_ms: 2,
                max_attempts: 4,
            },
        );
        rp.sleep_hook = Some(Box::new(|_| {}));
        let req = TurnRequest {
            model: "m".into(),
            system: "s".into(),
            messages: vec![],
            input_images: Vec::new(),
            tools: vec![],
            max_tokens: 10,
            cache_system: false,
            thinking_budget: 0,
            reasoning_effort: core_protocol::ReasoningEffort::Low,
        };
        assert!(
            rp.turn(&req, &mut |_| {}).await.is_err(),
            "must give up, not loop forever (bounded)"
        );
    }

    #[tokio::test]
    async fn does_not_retry_a_client_error() {
        struct Bad;
        #[async_trait]
        impl Provider for Bad {
            async fn turn(
                &self,
                _: &TurnRequest,
                _: &mut (dyn FnMut(StreamItem) + Send),
            ) -> Result<TurnResult, ProviderError> {
                Err(ProviderError::Api {
                    status: 400,
                    body: "bad request".into(),
                })
            }
        }
        let mut rp = RetryProvider::new(Box::new(Bad), BackoffPolicy::default());
        rp.sleep_hook = Some(Box::new(|_| panic!("must not back off on a 400")));
        let req = TurnRequest {
            model: "m".into(),
            system: "s".into(),
            messages: vec![],
            input_images: Vec::new(),
            tools: vec![],
            max_tokens: 10,
            cache_system: false,
            thinking_budget: 0,
            reasoning_effort: core_protocol::ReasoningEffort::Low,
        };
        assert!(rp.turn(&req, &mut |_| {}).await.is_err());
    }

    #[derive(Clone, Copy)]
    enum AmbiguousFailure {
        Transport,
        Status(u16),
    }

    struct AmbiguousThenOk {
        calls: Arc<AtomicU32>,
        failure: AmbiguousFailure,
    }

    #[async_trait]
    impl Provider for AmbiguousThenOk {
        async fn turn(
            &self,
            _: &TurnRequest,
            _: &mut (dyn FnMut(StreamItem) + Send),
        ) -> Result<TurnResult, ProviderError> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(match self.failure {
                    AmbiguousFailure::Transport => {
                        ProviderError::Http("response headers timed out".into())
                    }
                    AmbiguousFailure::Status(status) => ProviderError::Api {
                        status,
                        body: "ambiguous provider failure".into(),
                    },
                });
            }
            Ok(TurnResult {
                blocks: vec![],
                stop_reason: StopReason::EndTurn,
                usage: UsageReport::complete(Default::default()),
            })
        }
    }

    #[tokio::test]
    async fn ambiguous_pre_stream_failures_are_not_retried() {
        for failure in [
            AmbiguousFailure::Transport,
            AmbiguousFailure::Status(408),
            AmbiguousFailure::Status(409),
            AmbiguousFailure::Status(500),
            AmbiguousFailure::Status(503),
        ] {
            let calls = Arc::new(AtomicU32::new(0));
            let mut provider = RetryProvider::new(
                Box::new(AmbiguousThenOk {
                    calls: Arc::clone(&calls),
                    failure,
                }),
                BackoffPolicy {
                    base_ms: 1,
                    cap_ms: 2,
                    max_attempts: 6,
                },
            );
            provider.sleep_hook = Some(Box::new(|_| {
                panic!("an ambiguous paid request must fail closed")
            }));
            let request = TurnRequest {
                model: "m".into(),
                system: "s".into(),
                messages: vec![],
                input_images: Vec::new(),
                tools: vec![],
                max_tokens: 10,
                cache_system: false,
                thinking_budget: 0,
                reasoning_effort: core_protocol::ReasoningEffort::Low,
            };
            assert!(provider.turn(&request, &mut |_| {}).await.is_err());
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn respects_retry_after_hint_but_clamps_it_to_policy_cap() {
        struct HintThenOk {
            calls: AtomicU32,
        }
        #[async_trait]
        impl Provider for HintThenOk {
            async fn turn(
                &self,
                _: &TurnRequest,
                _: &mut (dyn FnMut(StreamItem) + Send),
            ) -> Result<TurnResult, ProviderError> {
                if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(ProviderError::ApiResponse(ApiResponseError {
                        status: 429,
                        body: "wait".into(),
                        body_truncated: false,
                        retry_after: Some(std::time::Duration::from_secs(60)),
                        normalized: Box::new(NormalizedFailure {
                            adapter: AdapterKind::OpenAiCompatibleChat,
                            error_profile: ErrorProfile::OpenAi,
                            code: Some("rate_limit_error".into()),
                            public_message: "provider rate limit reached",
                            scope: ErrorScope::Account,
                            availability: AvailabilityTransition::Account(
                                AccountAvailability::RateLimited,
                            ),
                            retry: RetryDisposition::Transient,
                            request_id: None,
                        }),
                    }))
                } else {
                    Ok(TurnResult {
                        blocks: vec![],
                        stop_reason: StopReason::EndTurn,
                        usage: UsageReport::complete(Default::default()),
                    })
                }
            }
        }

        let observed = Arc::new(Mutex::new(Vec::new()));
        let observed_by_hook = Arc::clone(&observed);
        let mut rp = RetryProvider::new(
            Box::new(HintThenOk {
                calls: AtomicU32::new(0),
            }),
            BackoffPolicy {
                base_ms: 1,
                cap_ms: 2_000,
                max_attempts: 2,
            },
        );
        rp.sleep_hook = Some(Box::new(move |delay| {
            observed_by_hook.lock().unwrap().push(delay)
        }));
        let req = TurnRequest {
            model: "m".into(),
            system: "s".into(),
            messages: vec![],
            input_images: Vec::new(),
            tools: vec![],
            max_tokens: 10,
            cache_system: false,
            thinking_budget: 0,
            reasoning_effort: core_protocol::ReasoningEffort::Low,
        };
        assert!(rp.turn(&req, &mut |_| {}).await.is_ok());
        assert_eq!(
            observed.lock().unwrap().as_slice(),
            &[std::time::Duration::from_secs(2)]
        );
    }

    struct InBandFailure {
        calls: AtomicU32,
        emit_first: bool,
    }

    #[async_trait]
    impl Provider for InBandFailure {
        async fn turn(
            &self,
            _: &TurnRequest,
            on_item: &mut (dyn FnMut(StreamItem) + Send),
        ) -> Result<TurnResult, ProviderError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                if self.emit_first {
                    on_item(StreamItem::TextDelta("partial".into()));
                }
                return Err(ProviderError::Stream(StreamError {
                    provider: "test",
                    code: Some("overloaded_error".into()),
                    message: "busy".into(),
                    status: Some(529),
                    retry_after: None,
                    normalized: Box::new(NormalizedFailure {
                        adapter: AdapterKind::AnthropicMessages,
                        error_profile: ErrorProfile::Anthropic,
                        code: Some("overloaded_error".into()),
                        public_message: "provider is temporarily unavailable",
                        scope: ErrorScope::Provider,
                        availability: AvailabilityTransition::Account(
                            AccountAvailability::Degraded,
                        ),
                        retry: RetryDisposition::Transient,
                        request_id: None,
                    }),
                }));
            }
            Ok(TurnResult {
                blocks: vec![],
                stop_reason: StopReason::EndTurn,
                usage: UsageReport::complete(Default::default()),
            })
        }
    }

    #[tokio::test]
    async fn retries_typed_in_band_error_only_before_content() {
        let provider = InBandFailure {
            calls: AtomicU32::new(0),
            emit_first: false,
        };
        let mut rp = RetryProvider::new(
            Box::new(provider),
            BackoffPolicy {
                base_ms: 1,
                cap_ms: 2,
                max_attempts: 2,
            },
        );
        rp.sleep_hook = Some(Box::new(|_| {}));
        let req = TurnRequest {
            model: "m".into(),
            system: "s".into(),
            messages: vec![],
            input_images: Vec::new(),
            tools: vec![],
            max_tokens: 10,
            cache_system: false,
            thinking_budget: 0,
            reasoning_effort: core_protocol::ReasoningEffort::Low,
        };
        assert!(rp.turn(&req, &mut |_| {}).await.is_ok());
    }

    #[tokio::test]
    async fn never_retries_after_stream_content_was_observed() {
        let provider = InBandFailure {
            calls: AtomicU32::new(0),
            emit_first: true,
        };
        let mut rp = RetryProvider::new(Box::new(provider), BackoffPolicy::default());
        rp.sleep_hook = Some(Box::new(|_| panic!("a committed stream must not retry")));
        let req = TurnRequest {
            model: "m".into(),
            system: "s".into(),
            messages: vec![],
            input_images: Vec::new(),
            tools: vec![],
            max_tokens: 10,
            cache_system: false,
            thinking_budget: 0,
            reasoning_effort: core_protocol::ReasoningEffort::Low,
        };
        let mut items = Vec::new();
        let result = rp.turn(&req, &mut |item| items.push(item)).await;
        assert!(matches!(result, Err(ProviderError::Stream(_))));
        assert_eq!(items, vec![StreamItem::TextDelta("partial".into())]);
    }

    #[tokio::test]
    async fn exhausted_quota_is_never_retried_despite_http_429() {
        struct Quota {
            calls: Arc<AtomicU32>,
        }
        #[async_trait]
        impl Provider for Quota {
            async fn turn(
                &self,
                _: &TurnRequest,
                _: &mut (dyn FnMut(StreamItem) + Send),
            ) -> Result<TurnResult, ProviderError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Err(ProviderError::ApiResponse(ApiResponseError {
                    status: 429,
                    body: r#"{"error":{"code":"insufficient_quota"}}"#.into(),
                    body_truncated: false,
                    retry_after: None,
                    normalized: Box::new(NormalizedFailure {
                        adapter: AdapterKind::OpenAiCompatibleChat,
                        error_profile: ErrorProfile::OpenAi,
                        code: Some("insufficient_quota".into()),
                        public_message: "provider billing or quota is unavailable",
                        scope: ErrorScope::Account,
                        availability: AvailabilityTransition::Account(
                            AccountAvailability::BillingBlocked,
                        ),
                        retry: RetryDisposition::Never,
                        request_id: Some("req_quota".into()),
                    }),
                }))
            }
        }

        let calls = Arc::new(AtomicU32::new(0));
        let mut provider = RetryProvider::new(
            Box::new(Quota {
                calls: Arc::clone(&calls),
            }),
            BackoffPolicy {
                base_ms: 1,
                cap_ms: 2,
                max_attempts: 10,
            },
        );
        provider.sleep_hook = Some(Box::new(|_| panic!("quota must not back off")));
        let request = TurnRequest {
            model: "m".into(),
            system: "s".into(),
            messages: vec![],
            input_images: Vec::new(),
            tools: vec![],
            max_tokens: 10,
            cache_system: false,
            thinking_budget: 0,
            reasoning_effort: core_protocol::ReasoningEffort::Low,
        };
        assert!(provider.turn(&request, &mut |_| {}).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
