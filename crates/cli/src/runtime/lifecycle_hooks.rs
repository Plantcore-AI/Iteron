//! Bounded asynchronous dispatch for canonical lifecycle hooks.
//!
//! Gate hooks are invoked synchronously by the owning admission boundary. Observe and Augment
//! hooks enter this bounded worker so a slow operator hook cannot stall a turn or grow tasks
//! without limit.

use super::hooks::journal::HookEffectJournal;
use super::hooks::{HookDecision, Hooks, LifecycleHookReport};
use iteron_obs::lifecycle::{LifecycleCorrelation, LifecycleEmitter};
use iteron_protocol::{HookCapability, LifecycleEventEnvelope, LifecyclePayload};
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const HOOK_DISPATCH_QUEUE: usize = 256;
const HOOK_DISPATCH_CONCURRENCY: usize = 4;
const CIRCUIT_FAILURE_THRESHOLD: u8 = 3;
const CIRCUIT_OPEN_FOR: Duration = Duration::from_secs(30);

#[derive(Debug, Default)]
struct CircuitState {
    consecutive_failures: u8,
    open_until: Option<Instant>,
}

type Circuits = Arc<Mutex<HashMap<String, CircuitState>>>;

#[derive(Debug, Default)]
struct Counters {
    queued: AtomicU64,
    dropped: AtomicU64,
    completed: AtomicU64,
    failed: AtomicU64,
    timed_out: AtomicU64,
    blocked: AtomicU64,
    queue_depth: AtomicU64,
    open_circuits: AtomicU64,
}

#[derive(Debug, Clone, Default)]
pub struct LifecycleHookHealth {
    counters: Arc<Counters>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct LifecycleHookHealthSnapshot {
    pub queued: u64,
    pub dropped: u64,
    pub completed: u64,
    pub failed: u64,
    pub timed_out: u64,
    pub blocked: u64,
    pub queue_depth: u64,
    pub open_circuits: u64,
}

impl LifecycleHookHealth {
    pub fn snapshot(&self) -> LifecycleHookHealthSnapshot {
        LifecycleHookHealthSnapshot {
            queued: self.counters.queued.load(Ordering::Relaxed),
            dropped: self.counters.dropped.load(Ordering::Relaxed),
            completed: self.counters.completed.load(Ordering::Relaxed),
            failed: self.counters.failed.load(Ordering::Relaxed),
            timed_out: self.counters.timed_out.load(Ordering::Relaxed),
            blocked: self.counters.blocked.load(Ordering::Relaxed),
            queue_depth: self.counters.queue_depth.load(Ordering::Relaxed),
            open_circuits: self.counters.open_circuits.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LifecycleHookDispatcher {
    sender: mpsc::Sender<LifecycleEventEnvelope>,
    subscribed: Arc<BTreeSet<&'static str>>,
    counters: Arc<Counters>,
    emitter: LifecycleEmitter,
}

impl LifecycleHookDispatcher {
    pub fn start(
        hooks: Hooks,
        emitter: LifecycleEmitter,
        base: LifecycleCorrelation,
        journal: Option<HookEffectJournal>,
        drain: Arc<std::sync::atomic::AtomicBool>,
        health: LifecycleHookHealth,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let subscribed = Arc::new(
            hooks
                .subscribed_lifecycle_events()
                .into_iter()
                .collect::<BTreeSet<_>>(),
        );
        for _ in subscribed.iter() {
            let _ = emitter.emit(
                "hook.registered",
                base.clone(),
                LifecyclePayload {
                    count: Some(1),
                    ..LifecyclePayload::default()
                },
            );
        }
        let (sender, receiver) = mpsc::channel(HOOK_DISPATCH_QUEUE);
        let counters = health.counters;
        let circuits = Arc::new(Mutex::new(HashMap::with_capacity(subscribed.len())));
        let task = tokio::spawn(worker(
            receiver,
            hooks,
            emitter.clone(),
            counters.clone(),
            circuits,
            journal,
            drain,
        ));
        (
            Self {
                sender,
                subscribed,
                counters,
                emitter,
            },
            task,
        )
    }

    /// Queue one Observe/Augment event without waiting. Gate events stay with their owner and are
    /// never duplicated here.
    pub fn dispatch(&self, event: LifecycleEventEnvelope) {
        let id = event.event_id.as_str();
        if !self.subscribed.contains(id)
            || iteron_protocol::lifecycle::event_spec(id)
                .is_some_and(|spec| spec.hook_capability == HookCapability::Gate)
        {
            return;
        }
        match self.sender.try_send(event) {
            Ok(()) => {
                self.counters.queued.fetch_add(1, Ordering::Relaxed);
                self.counters.queue_depth.fetch_add(1, Ordering::Relaxed);
            }
            Err(error) => {
                self.counters.dropped.fetch_add(1, Ordering::Relaxed);
                let event = error.into_inner();
                let _ = self.emitter.emit(
                    "hook.failed",
                    correlation_of(&event),
                    LifecyclePayload {
                        count: Some(1),
                        reason_code: Some("dispatch_queue_full_or_closed".into()),
                        ..LifecyclePayload::default()
                    },
                );
            }
        }
    }
}

async fn worker(
    mut receiver: mpsc::Receiver<LifecycleEventEnvelope>,
    hooks: Hooks,
    emitter: LifecycleEmitter,
    counters: Arc<Counters>,
    circuits: Circuits,
    journal: Option<HookEffectJournal>,
    drain: Arc<std::sync::atomic::AtomicBool>,
) {
    let mut jobs = tokio::task::JoinSet::new();
    while let Some(event) = receiver.recv().await {
        counters.queue_depth.fetch_sub(1, Ordering::Relaxed);
        if circuit_is_open(&circuits, &counters, event.event_id.as_str()) {
            counters.failed.fetch_add(1, Ordering::Relaxed);
            let _ = emitter.emit(
                "hook.failed",
                correlation_of(&event),
                LifecyclePayload {
                    reason_code: Some("circuit_open".into()),
                    ..LifecyclePayload::default()
                },
            );
            continue;
        }
        while jobs.len() >= HOOK_DISPATCH_CONCURRENCY {
            let _ = jobs.join_next().await;
        }
        let hooks = hooks.clone();
        let emitter = emitter.clone();
        let counters = counters.clone();
        let circuits = circuits.clone();
        let journal = journal.clone();
        let drain = drain.clone();
        jobs.spawn(async move {
            dispatch_one(
                &hooks,
                &emitter,
                &counters,
                &circuits,
                journal.as_ref(),
                drain.as_ref(),
                event,
            )
            .await;
        });
    }
    while jobs.join_next().await.is_some() {}
}

async fn dispatch_one(
    hooks: &Hooks,
    emitter: &LifecycleEmitter,
    counters: &Counters,
    circuits: &Circuits,
    journal: Option<&HookEffectJournal>,
    drain: &std::sync::atomic::AtomicBool,
    event: LifecycleEventEnvelope,
) {
    let correlation = correlation_of(&event);
    let _ = emitter.emit(
        "hook.matched",
        correlation.clone(),
        LifecyclePayload::default(),
    );
    let _ = emitter.emit(
        "hook.started",
        correlation.clone(),
        LifecyclePayload::default(),
    );
    let context = serde_json::to_string(&event).unwrap_or_else(|_| "{}".into());
    let Some(journal) = journal else {
        counters.failed.fetch_add(1, Ordering::Relaxed);
        let _ = emitter.emit(
            "hook.failed",
            correlation,
            LifecyclePayload {
                reason_code: Some("durable_journal_unavailable".into()),
                ..LifecyclePayload::default()
            },
        );
        return;
    };
    match hooks
        .run_lifecycle_cancellable_journaled(
            event.event_id.as_str(),
            &context,
            None,
            Some(drain),
            journal,
        )
        .await
    {
        Ok(report) => {
            update_circuit(
                emitter,
                circuits,
                counters,
                event.event_id.as_str(),
                &correlation,
                report.failed > 0 || report.timed_out > 0,
            );
            record_report(emitter, counters, correlation, report);
        }
        Err(_) => {
            update_circuit(
                emitter,
                circuits,
                counters,
                event.event_id.as_str(),
                &correlation,
                true,
            );
            counters.failed.fetch_add(1, Ordering::Relaxed);
            let _ = emitter.emit(
                "hook.failed",
                correlation,
                LifecyclePayload {
                    reason_code: Some("invalid_dispatch".into()),
                    ..LifecyclePayload::default()
                },
            );
        }
    }
}

fn circuit_is_open(circuits: &Circuits, counters: &Counters, event_id: &str) -> bool {
    let Ok(mut circuits) = circuits.lock() else {
        return true;
    };
    let Some(state) = circuits.get_mut(event_id) else {
        return false;
    };
    match state.open_until {
        Some(until) if Instant::now() < until => true,
        Some(_) => {
            state.open_until = None;
            state.consecutive_failures = 0;
            counters.open_circuits.fetch_sub(1, Ordering::Relaxed);
            false
        }
        None => false,
    }
}

fn update_circuit(
    emitter: &LifecycleEmitter,
    circuits: &Circuits,
    counters: &Counters,
    event_id: &str,
    correlation: &LifecycleCorrelation,
    failed: bool,
) {
    let Ok(mut circuits) = circuits.lock() else {
        return;
    };
    let state = circuits.entry(event_id.to_owned()).or_default();
    if !failed {
        if state.open_until.take().is_some() {
            counters.open_circuits.fetch_sub(1, Ordering::Relaxed);
        }
        state.consecutive_failures = 0;
        return;
    }
    state.consecutive_failures = state.consecutive_failures.saturating_add(1);
    if state.consecutive_failures < CIRCUIT_FAILURE_THRESHOLD || state.open_until.is_some() {
        return;
    }
    state.open_until = Some(Instant::now() + CIRCUIT_OPEN_FOR);
    counters.open_circuits.fetch_add(1, Ordering::Relaxed);
    let _ = emitter.emit(
        "hook.circuit_opened",
        correlation.clone(),
        LifecyclePayload {
            count: Some(u64::from(state.consecutive_failures)),
            duration_us: Some(u64::try_from(CIRCUIT_OPEN_FOR.as_micros()).unwrap_or(u64::MAX)),
            reason_code: Some("consecutive_failures".into()),
            ..LifecyclePayload::default()
        },
    );
}

fn record_report(
    emitter: &LifecycleEmitter,
    counters: &Counters,
    correlation: LifecycleCorrelation,
    report: LifecycleHookReport,
) {
    counters
        .completed
        .fetch_add(u64::from(report.completed), Ordering::Relaxed);
    counters
        .failed
        .fetch_add(u64::from(report.failed), Ordering::Relaxed);
    counters
        .timed_out
        .fetch_add(u64::from(report.timed_out), Ordering::Relaxed);
    if report.timed_out > 0 {
        let _ = emitter.emit(
            "hook.timed_out",
            correlation.clone(),
            LifecyclePayload {
                count: Some(u64::from(report.timed_out)),
                ..LifecyclePayload::default()
            },
        );
    }
    if report.failed > 0 {
        let _ = emitter.emit(
            "hook.failed",
            correlation.clone(),
            LifecyclePayload {
                count: Some(u64::from(report.failed)),
                ..LifecyclePayload::default()
            },
        );
    }
    if matches!(report.decision, HookDecision::Deny(_)) {
        counters.blocked.fetch_add(1, Ordering::Relaxed);
        let _ = emitter.emit("hook.blocked", correlation, LifecyclePayload::default());
    } else {
        for augmentation in &report.augmentations {
            let _ = emitter.emit("hook.completed", correlation.clone(), augmentation.clone());
        }
        let _ = emitter.emit(
            "hook.completed",
            correlation,
            LifecyclePayload {
                count: Some(u64::from(report.completed)),
                magnitude: Some(u64::try_from(report.augmentations.len()).unwrap_or(u64::MAX)),
                ..LifecyclePayload::default()
            },
        );
    }
}

fn correlation_of(event: &LifecycleEventEnvelope) -> LifecycleCorrelation {
    LifecycleCorrelation {
        session_id: event.session_id.clone(),
        run_id: event.run_id.clone(),
        turn_id: event.turn_id,
        submission_id: event.submission_id,
        effect_id: event.effect_id.clone(),
        workflow_id: event.workflow_id.clone(),
        subagent_id: event.subagent_id.clone(),
        job_id: event.job_id.clone(),
        parent_event: Some(iteron_protocol::LifecycleEventRef {
            event_id: event.event_id.clone(),
            ordinal: event.ordinal,
        }),
        durable_seq: event.durable_seq,
    }
}
