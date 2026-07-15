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
use async_trait::async_trait;
use core_provider::{
    EffortApplication, Provider, ProviderError, RetryDisposition, StreamItem, TurnRequest,
    TurnResult,
};
use std::sync::Mutex;

pub struct RetryProvider {
    inner: Box<dyn Provider>,
    policy: BackoffPolicy,
    jitter: Mutex<Jitter>,
    /// A hook so tests can observe backoff without sleeping; None uses tokio::time::sleep.
    sleep_hook: Option<Box<dyn Fn(std::time::Duration) + Send + Sync>>,
}

impl RetryProvider {
    pub fn new(inner: Box<dyn Provider>, policy: BackoffPolicy) -> Self {
        RetryProvider {
            inner,
            policy,
            jitter: Mutex::new(Jitter::new()),
            sleep_hook: None,
        }
    }

    async fn sleep(&self, d: std::time::Duration) {
        if let Some(h) = &self.sleep_hook {
            h(d);
        } else {
            tokio::time::sleep(d).await;
        }
    }
}

#[async_trait]
impl Provider for RetryProvider {
    fn effort_application(&self, req: &TurnRequest) -> EffortApplication {
        self.inner.effort_application(req)
    }

    async fn turn(
        &self,
        req: &TurnRequest,
        on_item: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
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
                    let r01 = self.jitter.lock().unwrap().next01();
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
        ErrorScope, NormalizedFailure, StreamError,
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

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
                    usage: Default::default(),
                })
            }
        }
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
                usage: Default::default(),
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
                        usage: Default::default(),
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
                usage: Default::default(),
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
