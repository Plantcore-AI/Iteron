//! Integration evidence that the retry wrapper cannot re-issue a provider after a stream has
//! started and the caller interrupts it.

use async_trait::async_trait;
use iteron_protocol::{ReasoningEffort, StopReason};
use iteron_provider::{
    Provider, ProviderError, StreamItem, TurnRequest, TurnResult, UsageReport, turn_cancellable,
};
use iteron_sched::{BackoffPolicy, Clock, RetryProvider};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

struct HangingAfterContent {
    calls: Arc<AtomicUsize>,
    streaming: Arc<AtomicBool>,
}

#[async_trait]
impl Provider for HangingAfterContent {
    async fn turn(
        &self,
        _request: &TurnRequest,
        on_item: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        on_item(StreamItem::TextDelta("partial".into()));
        self.streaming.store(true, Ordering::SeqCst);
        std::future::pending::<()>().await;
        Ok(TurnResult {
            blocks: Vec::new(),
            stop_reason: StopReason::EndTurn,
            usage: UsageReport::complete(Default::default()),
        })
    }
}

#[derive(Default)]
struct CountingClock {
    sleeps: AtomicUsize,
}

#[async_trait]
impl Clock for CountingClock {
    async fn sleep(&self, _duration: Duration) {
        self.sleeps.fetch_add(1, Ordering::SeqCst);
    }
}

fn request() -> TurnRequest {
    TurnRequest {
        model: "fixture".into(),
        system: "system".into(),
        messages: Vec::new(),
        input_images: Vec::new(),
        tools: Vec::new().into(),
        max_tokens: 16,
        cache_system: false,
        thinking_budget: 0,
        reasoning_effort: ReasoningEffort::Low,
        controls: Default::default(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mid_stream_interrupt_never_reissues_the_provider() {
    let calls = Arc::new(AtomicUsize::new(0));
    let streaming = Arc::new(AtomicBool::new(false));
    let clock = Arc::new(CountingClock::default());
    let retry = RetryProvider::with_clock(
        Box::new(HangingAfterContent {
            calls: Arc::clone(&calls),
            streaming: Arc::clone(&streaming),
        }),
        BackoffPolicy {
            base_ms: 1,
            cap_ms: 2,
            max_attempts: 6,
        },
        clock.clone(),
    );
    let interrupted = Arc::new(AtomicBool::new(false));
    let interrupt_for_task = Arc::clone(&interrupted);
    let streaming_for_task = Arc::clone(&streaming);
    let flipper = tokio::spawn(async move {
        while !streaming_for_task.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
        interrupt_for_task.store(true, Ordering::SeqCst);
    });

    let mut seen = Vec::new();
    let mut on_item = |item| {
        if let StreamItem::TextDelta(text) = item {
            seen.push(text);
        }
    };
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        turn_cancellable(
            &retry,
            &request(),
            &mut on_item,
            Some(interrupted.as_ref()),
            Duration::from_millis(1),
        ),
    )
    .await
    .expect("interrupt must abort the in-flight retry wrapper");
    flipper.await.unwrap();

    assert!(matches!(result, Err(ProviderError::Interrupted)));
    assert_eq!(seen, ["partial"]);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(clock.sleeps.load(Ordering::SeqCst), 0);
}
