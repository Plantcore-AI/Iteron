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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

const HOOK_DISPATCH_QUEUE: usize = 256;
const HOOK_DISPATCH_CONCURRENCY: usize = 4;
const HOOK_EXECUTION_CONCURRENCY: usize = 4;
const LIFECYCLE_OBSERVER_TIMEOUT: Duration = Duration::from_secs(10);
const WORKER_CLOSE_SLACK: Duration = Duration::from_millis(250);
const CLEANUP_SETTLEMENT_SLACK: Duration = Duration::from_secs(1);
const ABORT_JOIN_GRACE: Duration = Duration::from_millis(250);
const CIRCUIT_FAILURE_THRESHOLD: u8 = 3;
const CIRCUIT_OPEN_FOR: Duration = Duration::from_secs(30);

#[derive(Debug, Default)]
struct CircuitState {
    consecutive_failures: u8,
    open_until: Option<Instant>,
}

type Circuits = Arc<Mutex<HashMap<String, CircuitState>>>;

#[derive(Clone)]
struct DispatchRuntime {
    hooks: Hooks,
    emitter: LifecycleEmitter,
    counters: Arc<Counters>,
    circuits: Circuits,
    journal: Option<HookEffectJournal>,
    cancel: Arc<AtomicBool>,
    admission: Arc<Mutex<AdmissionState>>,
    subscribed: Arc<BTreeSet<&'static str>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkerPhase {
    Open,
    Draining,
    Cancelling,
}

#[derive(Debug)]
struct AdmissionState {
    phase: WorkerPhase,
    sender: mpsc::Sender<LifecycleEventEnvelope>,
}

#[derive(Debug, Default)]
struct Counters {
    queued: AtomicU64,
    dropped: AtomicU64,
    completed: AtomicU64,
    failed: AtomicU64,
    timed_out: AtomicU64,
    blocked: AtomicU64,
    queue_depth: AtomicU64,
    running_events: AtomicU64,
    admitted_events: AtomicU64,
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
    admission: Arc<Mutex<AdmissionState>>,
    subscribed: Arc<BTreeSet<&'static str>>,
    counters: Arc<Counters>,
    emitter: LifecycleEmitter,
}

/// Session-owned completion authority for the asynchronous Observe/Augment dispatcher.
///
/// Dropping public dispatchers closes normal admission. This handle then grants already-admitted
/// work a window derived from its configured command ceiling. If that window expires, it signals
/// cancellation before waiting through the hook executor's bounded TERM -> KILL -> reap path.
pub(crate) struct LifecycleHookRuntime {
    cancel: Arc<AtomicBool>,
    phase: watch::Sender<WorkerPhase>,
    task: tokio::task::JoinHandle<bool>,
    admission: Arc<Mutex<AdmissionState>>,
    counters: Arc<Counters>,
    dispatch_concurrency: usize,
    hook_concurrency: usize,
    max_commands_per_event: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LifecycleHookShutdown {
    Drained,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LifecycleHookShutdownError {
    WorkerFailed,
    CleanupUnproven,
}

impl LifecycleHookShutdownError {
    pub(crate) const fn reason_code(self) -> &'static str {
        match self {
            Self::WorkerFailed => "lifecycle_hook_worker_failed",
            Self::CleanupUnproven => "lifecycle_hook_cleanup_unproven",
        }
    }

    pub(crate) const fn public_summary(self) -> &'static str {
        match self {
            Self::WorkerFailed => {
                "canonical lifecycle hook worker failed before cleanup was proven"
            }
            Self::CleanupUnproven => {
                "canonical lifecycle hook cleanup exceeded its bounded cancellation window"
            }
        }
    }
}

impl LifecycleHookDispatcher {
    pub fn start(
        hooks: Hooks,
        emitter: LifecycleEmitter,
        base: LifecycleCorrelation,
        journal: Option<HookEffectJournal>,
        health: LifecycleHookHealth,
    ) -> (Self, LifecycleHookRuntime) {
        let subscribed = Arc::new(
            hooks
                .subscribed_lifecycle_events()
                .into_iter()
                .collect::<BTreeSet<_>>(),
        );
        let (sender, receiver) = mpsc::channel(
            iteron_tunables::param_integer(
                "cli.runtime.lifecycle_hooks.hook_dispatch_queue",
                HOOK_DISPATCH_QUEUE,
            )
            .clamp(1, HOOK_DISPATCH_QUEUE),
        );
        let counters = health.counters;
        let hook_concurrency = hook_execution_concurrency();
        let dispatch_concurrency = hook_dispatch_concurrency();
        // Every subscribed canonical event owns at least one catalog entry. Subtracting those
        // mandatory entries from the content-free catalog total gives a conservative upper bound
        // for the longest one-event chain without exposing command text or adding a second config
        // parser to this owner.
        let catalog_entries = hooks.catalog_identity().entry_count;
        let max_commands_per_event = if subscribed.is_empty() {
            0
        } else {
            catalog_entries
                .saturating_sub(subscribed.len().saturating_sub(1))
                .max(1)
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let admission = Arc::new(Mutex::new(AdmissionState {
            phase: WorkerPhase::Open,
            sender,
        }));
        let (phase, phase_rx) = watch::channel(WorkerPhase::Open);
        let circuits = Arc::new(Mutex::new(HashMap::with_capacity(subscribed.len())));
        let worker = worker(
            receiver,
            DispatchRuntime {
                hooks,
                emitter: emitter.clone(),
                counters: counters.clone(),
                circuits,
                journal,
                cancel: cancel.clone(),
                admission: admission.clone(),
                subscribed: subscribed.clone(),
            },
            phase_rx,
            dispatch_concurrency,
        );
        let dispatcher = Self {
            admission: admission.clone(),
            subscribed,
            counters: counters.clone(),
            emitter,
        };
        // Construct the complete dispatch path before announcing subscriptions. Keeping the worker
        // future unpolled until all announcements are queued also makes the fixed 256-entry bound
        // deterministic: the complete active catalog fits without producer/worker contention.
        for _ in dispatcher.subscribed.iter() {
            if let Ok(event) = dispatcher.emitter.emit(
                "hook.registered",
                base.clone(),
                LifecyclePayload {
                    count: Some(1),
                    ..LifecyclePayload::default()
                },
            ) {
                dispatcher.dispatch(event);
            }
        }
        let task = tokio::spawn(worker);
        (
            dispatcher,
            LifecycleHookRuntime {
                cancel,
                phase,
                task,
                admission,
                counters,
                dispatch_concurrency,
                hook_concurrency,
                max_commands_per_event,
            },
        )
    }

    /// Queue one Observe/Augment event without waiting. Gate events stay with their owner and are
    /// never duplicated here.
    pub fn dispatch(&self, event: LifecycleEventEnvelope) -> bool {
        let id = event.event_id.as_str();
        if !self.subscribed.contains(id)
            || iteron_protocol::lifecycle::event_spec(id)
                .is_some_and(|spec| spec.hook_capability == HookCapability::Gate)
        {
            return false;
        }
        enqueue(&self.admission, &self.counters, &self.emitter, event)
    }
}

impl LifecycleHookRuntime {
    /// Finish the dispatcher without abandoning a journal intent. The caller must release its
    /// own dispatcher references eventually, but leaked clones cannot delay shutdown: phase one
    /// atomically closes their shared admission port before measuring admitted work.
    pub(crate) async fn shutdown(
        self,
    ) -> Result<LifecycleHookShutdown, LifecycleHookShutdownError> {
        let admitted_events = self.begin_draining();
        let (graceful, cleanup) = self.shutdown_windows(admitted_events);
        self.shutdown_with_windows(graceful, cleanup).await
    }

    fn begin_draining(&self) -> usize {
        {
            let mut admission = self
                .admission
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            admission.phase = WorkerPhase::Draining;
        }
        let _ = self.phase.send(WorkerPhase::Draining);
        usize::try_from(self.counters.admitted_events.load(Ordering::Acquire)).unwrap_or(usize::MAX)
    }

    fn begin_cancelling(&self) {
        {
            let mut admission = self
                .admission
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            admission.phase = WorkerPhase::Cancelling;
        }
        self.cancel.store(true, Ordering::SeqCst);
        let _ = self.phase.send(WorkerPhase::Cancelling);
    }

    fn shutdown_windows(&self, admitted_events: usize) -> (Duration, Duration) {
        if admitted_events == 0 || self.max_commands_per_event == 0 {
            return (worker_close_slack(), cleanup_settlement_slack());
        }

        // Queue entries are already admitted work. Budget all of them, not only the first worker
        // batch: the command semaphore is shared across event jobs, so the truthful upper bound is
        // total admitted commands divided by that global concurrency.
        let admitted_commands = admitted_events.saturating_mul(self.max_commands_per_event);
        let graceful_waves = admitted_commands.div_ceil(self.hook_concurrency).max(1);
        // Phase two closes and rejects the receiver backlog without creating journal intents. Only
        // the at-most-concurrent event jobs can already own command intents at that point.
        let cleanup_commands = self
            .dispatch_concurrency
            .saturating_mul(self.max_commands_per_event);
        let cleanup_waves = cleanup_commands.div_ceil(self.hook_concurrency).max(1);
        let process_cleanup = hook_process_cleanup_ceiling();
        let minimum_graceful = duration_mul(
            lifecycle_observer_timeout().saturating_add(process_cleanup),
            graceful_waves,
        )
        .saturating_add(worker_close_slack());
        let minimum_cleanup =
            duration_mul(process_cleanup, cleanup_waves).saturating_add(cleanup_settlement_slack());
        (
            iteron_tunables::param_duration(
                "cli.app_server.lifecycle_hook_drain_grace",
                minimum_graceful,
            )
            .max(minimum_graceful),
            minimum_cleanup,
        )
    }

    async fn shutdown_with_windows(
        mut self,
        graceful: Duration,
        cleanup: Duration,
    ) -> Result<LifecycleHookShutdown, LifecycleHookShutdownError> {
        match tokio::time::timeout(graceful, &mut self.task).await {
            Ok(Ok(false)) => return Ok(LifecycleHookShutdown::Drained),
            Ok(Ok(true)) => return Err(LifecycleHookShutdownError::WorkerFailed),
            Ok(Err(_)) => return Err(LifecycleHookShutdownError::WorkerFailed),
            Err(_) => {}
        }

        self.begin_cancelling();
        match tokio::time::timeout(cleanup, &mut self.task).await {
            Ok(Ok(false)) => Ok(LifecycleHookShutdown::Cancelled),
            Ok(Ok(true)) => Err(LifecycleHookShutdownError::WorkerFailed),
            Ok(Err(_)) => Err(LifecycleHookShutdownError::WorkerFailed),
            Err(_) => {
                // The cooperative path has already been given enough time for every admitted
                // command wave to publish HookRun::Cancelled and append its journal terminal.
                // Abortion is deliberately last-resort and is reported as unproven by the owner.
                self.task.abort();
                let _ = tokio::time::timeout(abort_join_grace(), &mut self.task).await;
                Err(LifecycleHookShutdownError::CleanupUnproven)
            }
        }
    }
}

fn hook_dispatch_concurrency() -> usize {
    iteron_tunables::param_integer(
        "cli.runtime.lifecycle_hooks.hook_dispatch_concurrency",
        HOOK_DISPATCH_CONCURRENCY,
    )
    .clamp(1, HOOK_DISPATCH_CONCURRENCY)
}

/// The lifecycle executor's own concurrency, floored by the general hook runner's.
///
/// Both ids are read. `cli.runtime.hooks.max_parallel_hooks` supplies the default and remains the
/// ceiling -- lifecycle work must not out-schedule the runner it shares a process with -- while
/// the lifecycle-local id is what the catalog advertises, so setting it has to do something. Read
/// only through the shared id, the advertised one was inert: an operator set it, `--tunables-explain`
/// said applied, and the dispatcher kept the other value.
fn hook_execution_concurrency() -> usize {
    let shared = iteron_tunables::param_integer(
        "cli.runtime.hooks.max_parallel_hooks",
        HOOK_EXECUTION_CONCURRENCY,
    )
    .clamp(1, HOOK_EXECUTION_CONCURRENCY);
    iteron_tunables::param_integer(
        "cli.runtime.lifecycle_hooks.hook_execution_concurrency",
        shared,
    )
    .clamp(1, shared)
}

/// How long one lifecycle observer may run. Same two-id shape as the concurrency above: the shared
/// hook id supplies the default so an operator who tuned the runner still tunes this, and the
/// lifecycle-local id the catalog advertises is what actually takes effect when set.
fn lifecycle_observer_timeout() -> Duration {
    let shared = iteron_tunables::param_duration(
        "cli.runtime.hooks.lifecycle_observer_timeout",
        LIFECYCLE_OBSERVER_TIMEOUT,
    );
    iteron_tunables::param_duration(
        "cli.runtime.lifecycle_hooks.lifecycle_observer_timeout",
        shared,
    )
}

/// Slack added after the worker is asked to close. Advertised, therefore read.
fn worker_close_slack() -> Duration {
    iteron_tunables::param_duration(
        "cli.runtime.lifecycle_hooks.worker_close_slack",
        WORKER_CLOSE_SLACK,
    )
}

/// Slack for phase two to settle already-owned command intents. Advertised, therefore read.
fn cleanup_settlement_slack() -> Duration {
    iteron_tunables::param_duration(
        "cli.runtime.lifecycle_hooks.cleanup_settlement_slack",
        CLEANUP_SETTLEMENT_SLACK,
    )
}

/// How long an aborted dispatcher task is joined before it is abandoned. Advertised, therefore
/// read -- and bounded, because this runs on the shutdown path.
fn abort_join_grace() -> Duration {
    iteron_tunables::param_duration(
        "cli.runtime.lifecycle_hooks.abort_join_grace",
        ABORT_JOIN_GRACE,
    )
}

fn hook_process_cleanup_ceiling() -> Duration {
    let policy = iteron_sandbox::process_signal_kill_escalation_policy();
    Duration::from_millis(policy.term_grace_milliseconds)
        .saturating_add(Duration::from_secs(policy.post_kill_reap_seconds))
        .saturating_add(Duration::from_millis(25))
}

fn duration_mul(duration: Duration, multiplier: usize) -> Duration {
    duration
        .checked_mul(u32::try_from(multiplier).unwrap_or(u32::MAX))
        .unwrap_or(Duration::MAX)
}

fn enqueue(
    admission: &Arc<Mutex<AdmissionState>>,
    counters: &Counters,
    emitter: &LifecycleEmitter,
    event: LifecycleEventEnvelope,
) -> bool {
    let admission = admission
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if admission.phase != WorkerPhase::Open {
        drop(admission);
        counters.dropped.fetch_add(1, Ordering::Relaxed);
        let _ = emitter.emit(
            "hook.failed",
            correlation_of(&event),
            LifecyclePayload {
                count: Some(1),
                reason_code: Some("dispatcher_admission_closed".into()),
                ..LifecyclePayload::default()
            },
        );
        return false;
    }

    // Account the event before exposing it to the receiver. Shutdown closes admission under this
    // same mutex, so its admitted snapshot cannot race ahead of a successful send. A failed send
    // rolls both counters back before the rejection becomes observable.
    counters.queue_depth.fetch_add(1, Ordering::Relaxed);
    counters.admitted_events.fetch_add(1, Ordering::Relaxed);
    match admission.sender.try_send(event) {
        Ok(()) => {
            counters.queued.fetch_add(1, Ordering::Relaxed);
            true
        }
        Err(error) => {
            counters.queue_depth.fetch_sub(1, Ordering::Relaxed);
            counters.admitted_events.fetch_sub(1, Ordering::Relaxed);
            counters.dropped.fetch_add(1, Ordering::Relaxed);
            let event = error.into_inner();
            drop(admission);
            let _ = emitter.emit(
                "hook.failed",
                correlation_of(&event),
                LifecyclePayload {
                    count: Some(1),
                    reason_code: Some("dispatch_queue_full_or_closed".into()),
                    ..LifecyclePayload::default()
                },
            );
            false
        }
    }
}

async fn worker(
    mut receiver: mpsc::Receiver<LifecycleEventEnvelope>,
    runtime: DispatchRuntime,
    mut phase_rx: watch::Receiver<WorkerPhase>,
    concurrency: usize,
) -> bool {
    let mut jobs = tokio::task::JoinSet::new();
    let mut phase = WorkerPhase::Open;
    let mut job_failed = false;
    loop {
        if phase == WorkerPhase::Cancelling {
            receiver.close();
            while let Ok(event) = receiver.try_recv() {
                cancel_queued(&runtime, event);
            }
            break;
        }

        if jobs.len() >= concurrency {
            tokio::select! {
                biased;
                changed = phase_rx.changed() => {
                    phase = if changed.is_err() {
                        WorkerPhase::Cancelling
                    } else {
                        *phase_rx.borrow_and_update()
                    };
                    if phase != WorkerPhase::Open {
                        receiver.close();
                    }
                    if phase == WorkerPhase::Cancelling {
                        runtime.cancel.store(true, Ordering::SeqCst);
                    }
                }
                joined = jobs.join_next() => {
                    job_failed |= joined.is_some_and(|result| result.is_err());
                }
            }
            continue;
        }

        tokio::select! {
            biased;
            changed = phase_rx.changed() => {
                phase = if changed.is_err() {
                    WorkerPhase::Cancelling
                } else {
                    *phase_rx.borrow_and_update()
                };
                if phase != WorkerPhase::Open {
                    receiver.close();
                }
                if phase == WorkerPhase::Cancelling {
                    runtime.cancel.store(true, Ordering::SeqCst);
                }
            }
            joined = jobs.join_next(), if !jobs.is_empty() => {
                job_failed |= joined.is_some_and(|result| result.is_err());
            }
            event = receiver.recv() => {
                let Some(event) = event else {
                    break;
                };
                if circuit_is_open(
                    &runtime.circuits,
                    &runtime.counters,
                    event.event_id.as_str(),
                ) {
                    runtime.counters.queue_depth.fetch_sub(1, Ordering::Relaxed);
                    runtime
                        .counters
                        .admitted_events
                        .fetch_sub(1, Ordering::Relaxed);
                    runtime.counters.failed.fetch_add(1, Ordering::Relaxed);
                    let _ = runtime.emitter.emit(
                        "hook.failed",
                        correlation_of(&event),
                        LifecyclePayload {
                            reason_code: Some("circuit_open".into()),
                            ..LifecyclePayload::default()
                        },
                    );
                    continue;
                }
                runtime
                    .counters
                    .running_events
                    .fetch_add(1, Ordering::Relaxed);
                // Increment running before decrementing queued so teardown's admitted-work
                // snapshot cannot observe a transient zero and choose the close-only grace.
                runtime.counters.queue_depth.fetch_sub(1, Ordering::Relaxed);
                let runtime = runtime.clone();
                let running = RunningEventGuard(runtime.counters.clone());
                jobs.spawn(async move {
                    let _running = running;
                    dispatch_one(&runtime, event).await;
                });
            }
        }
    }
    while let Some(result) = jobs.join_next().await {
        job_failed |= result.is_err();
    }
    job_failed
}

struct RunningEventGuard(Arc<Counters>);

impl Drop for RunningEventGuard {
    fn drop(&mut self) {
        self.0.running_events.fetch_sub(1, Ordering::Relaxed);
        self.0.admitted_events.fetch_sub(1, Ordering::Relaxed);
    }
}

fn cancel_queued(runtime: &DispatchRuntime, event: LifecycleEventEnvelope) {
    runtime.counters.queue_depth.fetch_sub(1, Ordering::Relaxed);
    runtime
        .counters
        .admitted_events
        .fetch_sub(1, Ordering::Relaxed);
    runtime.counters.failed.fetch_add(1, Ordering::Relaxed);
    let _ = runtime.emitter.emit(
        "hook.failed",
        correlation_of(&event),
        LifecyclePayload {
            count: Some(1),
            reason_code: Some("dispatcher_shutdown_cancelled_before_start".into()),
            ..LifecyclePayload::default()
        },
    );
}

async fn dispatch_one(runtime: &DispatchRuntime, event: LifecycleEventEnvelope) {
    let correlation = correlation_of(&event);
    let _ = runtime.emitter.emit(
        "hook.matched",
        correlation.clone(),
        LifecyclePayload::default(),
    );
    let _ = runtime.emitter.emit(
        "hook.started",
        correlation.clone(),
        LifecyclePayload::default(),
    );
    let context = serde_json::to_string(&event).unwrap_or_else(|_| "{}".into());
    let Some(journal) = runtime.journal.as_ref() else {
        runtime.counters.failed.fetch_add(1, Ordering::Relaxed);
        let _ = runtime.emitter.emit(
            "hook.failed",
            correlation,
            LifecyclePayload {
                reason_code: Some("durable_journal_unavailable".into()),
                ..LifecyclePayload::default()
            },
        );
        return;
    };
    match runtime
        .hooks
        .run_lifecycle_cancellable_journaled(
            event.event_id.as_str(),
            &context,
            Some(runtime.cancel.as_ref()),
            None,
            journal,
        )
        .await
    {
        Ok(report) => {
            update_circuit(
                runtime,
                event.event_id.as_str(),
                &correlation,
                report.failed > 0 || report.timed_out > 0,
            );
            record_report(&runtime.emitter, &runtime.counters, correlation, report);
        }
        Err(_) => {
            update_circuit(runtime, event.event_id.as_str(), &correlation, true);
            runtime.counters.failed.fetch_add(1, Ordering::Relaxed);
            let _ = runtime.emitter.emit(
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
    runtime: &DispatchRuntime,
    event_id: &str,
    correlation: &LifecycleCorrelation,
    failed: bool,
) {
    let Ok(mut circuits) = runtime.circuits.lock() else {
        return;
    };
    let state = circuits.entry(event_id.to_owned()).or_default();
    if !failed {
        if state.open_until.take().is_some() {
            runtime
                .counters
                .open_circuits
                .fetch_sub(1, Ordering::Relaxed);
        }
        state.consecutive_failures = 0;
        return;
    }
    state.consecutive_failures = state.consecutive_failures.saturating_add(1);
    if state.consecutive_failures
        < iteron_tunables::param_integer(
            "cli.runtime.lifecycle_hooks.circuit_failure_threshold",
            CIRCUIT_FAILURE_THRESHOLD,
        )
        || state.open_until.is_some()
    {
        return;
    }
    state.open_until = Some(
        Instant::now()
            + iteron_tunables::param_duration(
                "cli.runtime.lifecycle_hooks.circuit_open_for",
                CIRCUIT_OPEN_FOR,
            ),
    );
    let consecutive_failures = state.consecutive_failures;
    let open_for = iteron_tunables::param_duration(
        "cli.runtime.lifecycle_hooks.circuit_open_for",
        CIRCUIT_OPEN_FOR,
    );
    runtime
        .counters
        .open_circuits
        .fetch_add(1, Ordering::Relaxed);
    drop(circuits);
    let opened = runtime.emitter.emit(
        "hook.circuit_opened",
        correlation.clone(),
        LifecyclePayload {
            count: Some(u64::from(consecutive_failures)),
            duration_us: Some(u64::try_from(open_for.as_micros()).unwrap_or(u64::MAX)),
            reason_code: Some("consecutive_failures".into()),
            ..LifecyclePayload::default()
        },
    );
    // Circuit feedback uses the same explicit admission phase as every public dispatcher clone. A
    // circuit-open handler may itself fail, so its own notification is recorded but never fed back
    // into the same handler.
    if event_id != "hook.circuit_opened"
        && runtime.subscribed.contains("hook.circuit_opened")
        && let Ok(event) = opened
    {
        enqueue(
            &runtime.admission,
            &runtime.counters,
            &runtime.emitter,
            event,
        );
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Liveness bounds for the tests below, scaled by the machine rather than fixed.
    ///
    /// Every `timeout` in this module waits for a state that will arrive -- the hook commands
    /// `sleep 30`, so the queue does not drain underneath the observation. The bound exists so a
    /// genuine hang fails as a test instead of hanging the suite, and nothing weakens when it
    /// grows.
    ///
    /// Two of them were nonetheless too small to survive a full-suite run: journalling 32 intents
    /// and spawning that many shells takes longer than five seconds on a host already running
    /// 1231 other tests, and `shutdown_cancels_started_and_queued_commands_and_settles_the_journal`
    /// failed on every full run while passing alone in 0.3s. That is a measurement artefact, not a
    /// dispatcher defect, and raising a liveness bound is the correct repair for it.
    ///
    /// `ITERON_TEST_TIMEOUT_SCALE` is the same variable `tui_pty.rs` and the release workflow
    /// already use to let a loaded runner say how slow it is.
    fn settle(base_secs: u64) -> Duration {
        static SCALE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
        let scale = *SCALE.get_or_init(|| {
            std::env::var("ITERON_TEST_TIMEOUT_SCALE")
                .ok()
                .and_then(|raw| raw.trim().parse::<u64>().ok())
                .filter(|scale| (1..=60).contains(scale))
                .unwrap_or(1)
        });
        Duration::from_secs(base_secs.saturating_mul(scale))
    }
    use iteron_obs::lifecycle::LifecycleBus;
    use iteron_protocol::lifecycle::LifecycleAvailability;
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicU64};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(tag: &str) -> Self {
            let nonce = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock after Unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "iteron-lifecycle-hooks-{tag}-{}-{timestamp}-{nonce}",
                std::process::id(),
            ));
            std::fs::create_dir_all(&path).expect("create lifecycle hook test directory");
            Self(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn shell_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }

    fn sentinel_command(evidence: &Path, event_id: &str) -> String {
        format!(
            "printf '%s\\n' {} >> {}",
            shell_quote(event_id),
            shell_quote(&evidence.to_string_lossy())
        )
    }

    async fn emit_canonical(emitter: &LifecycleEmitter, event_id: &str) -> LifecycleEventEnvelope {
        tokio::time::timeout(settle(12), async {
            loop {
                if let Ok(event) = emitter.emit(
                    event_id,
                    LifecycleCorrelation::default(),
                    LifecyclePayload::default(),
                ) {
                    return event;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out emitting {event_id}"))
    }

    fn read_lines(path: &Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn assert_completed_journal(path: &Path, expected_invocations: usize) -> Vec<String> {
        let contents = std::fs::read_to_string(path).expect("read hook effect journal");
        let mut pending = BTreeMap::<u64, String>::new();
        let mut completed = Vec::new();
        for line in contents.lines() {
            let entry: serde_json::Value = serde_json::from_str(line).expect("valid journal JSON");
            let invocation = entry["invocation"].as_u64().expect("journal invocation");
            let event_id = entry["event_id"]
                .as_str()
                .expect("journal event id")
                .to_owned();
            match entry["phase"].as_str().expect("journal phase") {
                "intent" => {
                    assert!(
                        pending.insert(invocation, event_id).is_none(),
                        "duplicate journal intent {invocation}"
                    );
                }
                "terminal" => {
                    assert_eq!(
                        entry["outcome"].as_str(),
                        Some("completed"),
                        "hook invocation {invocation} was not successful"
                    );
                    assert_eq!(
                        pending.remove(&invocation).as_deref(),
                        Some(event_id.as_str()),
                        "terminal did not match its intent"
                    );
                    completed.push(event_id);
                }
                phase => panic!("unexpected journal phase {phase}"),
            }
        }
        assert!(pending.is_empty(), "journal has unterminated intents");
        assert_eq!(completed.len(), expected_invocations);
        completed
    }

    fn journal_intent_count(path: &Path) -> usize {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|entry| entry["phase"].as_str() == Some("intent"))
            .count()
    }

    fn assert_cancelled_journal(path: &Path, expected_invocations: usize) {
        let contents = std::fs::read_to_string(path).expect("read hook effect journal");
        let mut pending = BTreeMap::<u64, String>::new();
        let mut cancelled = 0;
        for line in contents.lines() {
            let entry: serde_json::Value = serde_json::from_str(line).expect("valid journal JSON");
            let invocation = entry["invocation"].as_u64().expect("journal invocation");
            let event_id = entry["event_id"]
                .as_str()
                .expect("journal event id")
                .to_owned();
            match entry["phase"].as_str().expect("journal phase") {
                "intent" => {
                    assert!(
                        pending.insert(invocation, event_id).is_none(),
                        "duplicate journal intent {invocation}"
                    );
                }
                "terminal" => {
                    assert_eq!(
                        entry["outcome"].as_str(),
                        Some("cancelled"),
                        "shutdown hook invocation {invocation} did not settle as cancelled"
                    );
                    assert_eq!(
                        pending.remove(&invocation).as_deref(),
                        Some(event_id.as_str()),
                        "terminal did not match its intent"
                    );
                    cancelled += 1;
                }
                phase => panic!("unexpected journal phase {phase}"),
            }
        }
        assert!(pending.is_empty(), "journal has unterminated intents");
        assert_eq!(cancelled, expected_invocations);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shutdown_cancels_started_and_queued_commands_and_settles_the_journal() {
        let temp = TestDir::new("shutdown-cancel");
        let evidence_path = temp.join("started.txt");
        let journal_path = temp.join("journal.jsonl");
        let journal = HookEffectJournal::open(&journal_path).expect("open hook journal");
        let command = format!(
            "printf 'started\\n' >> {}; sleep 30",
            shell_quote(&evidence_path.to_string_lossy())
        );
        let commands_per_event = hook_execution_concurrency().saturating_mul(2);
        let hooks = Hooks::from_user_config(Some(&BTreeMap::from([(
            "session.created".to_owned(),
            vec![command; commands_per_event],
        )])));
        let bus = LifecycleBus::new(256);
        let emitter = LifecycleEmitter::new(bus.clone());
        let health = LifecycleHookHealth::default();
        let (dispatcher, runtime) = LifecycleHookDispatcher::start(
            hooks,
            emitter.clone(),
            LifecycleCorrelation::default(),
            Some(journal),
            health.clone(),
        );
        let active_events = hook_dispatch_concurrency();
        for _ in 0..=active_events {
            dispatcher.dispatch(emit_canonical(&emitter, "session.created").await);
        }
        let expected_intents = active_events.saturating_mul(commands_per_event);
        tokio::time::timeout(settle(20), async {
            loop {
                if journal_intent_count(&journal_path) == expected_intents
                    && !read_lines(&evidence_path).is_empty()
                    && health.snapshot().queue_depth > 0
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("started commands and queued work were not both observed");
        let started_before_shutdown = read_lines(&evidence_path).len();
        assert!(started_before_shutdown > 0);
        assert!(started_before_shutdown <= hook_execution_concurrency());

        let admitted = runtime.begin_draining();
        let cleanup = runtime.shutdown_windows(admitted).1;
        drop(dispatcher);
        let shutdown = tokio::time::timeout(
            cleanup.saturating_add(Duration::from_secs(2)),
            runtime.shutdown_with_windows(Duration::from_millis(25), cleanup),
        )
        .await
        .expect("cancelled lifecycle dispatcher exceeded its cleanup proof window")
        .expect("cancelled lifecycle dispatcher cleanup was unproven");
        assert_eq!(shutdown, LifecycleHookShutdown::Cancelled);

        assert_cancelled_journal(&journal_path, expected_intents);
        let snapshot = health.snapshot();
        assert_eq!(snapshot.queue_depth, 0);
        assert_eq!(
            snapshot.failed,
            u64::try_from(expected_intents.saturating_add(1)).unwrap()
        );
        assert_eq!(snapshot.completed, 0);
        assert!(bus.snapshot().events.iter().any(|event| {
            event.event_id.as_str() == "hook.failed"
                && event.payload.reason_code.as_deref()
                    == Some("dispatcher_shutdown_cancelled_before_start")
        }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn slow_observer_inside_its_budget_drains_normally() {
        let temp = TestDir::new("slow-normal-drain");
        let evidence_path = temp.join("completed.txt");
        let journal_path = temp.join("journal.jsonl");
        let journal = HookEffectJournal::open(&journal_path).expect("open hook journal");
        let command = format!(
            "sleep 3; printf 'session.created\\n' >> {}",
            shell_quote(&evidence_path.to_string_lossy())
        );
        let hooks = Hooks::from_user_config(Some(&BTreeMap::from([(
            "session.created".to_owned(),
            vec![command],
        )])));
        let bus = LifecycleBus::new(64);
        let emitter = LifecycleEmitter::new(bus);
        let health = LifecycleHookHealth::default();
        let (dispatcher, runtime) = LifecycleHookDispatcher::start(
            hooks,
            emitter.clone(),
            LifecycleCorrelation::default(),
            Some(journal),
            health.clone(),
        );
        dispatcher.dispatch(emit_canonical(&emitter, "session.created").await);
        drop(dispatcher);
        let shutdown = tokio::time::timeout(settle(20), runtime.shutdown())
            .await
            .expect("slow observer exceeded its configured graceful drain")
            .expect("slow observer cleanup was unproven");
        assert_eq!(shutdown, LifecycleHookShutdown::Drained);
        assert_eq!(read_lines(&evidence_path), ["session.created"]);
        assert_eq!(
            assert_completed_journal(&journal_path, 1),
            ["session.created"]
        );
        let snapshot = health.snapshot();
        assert_eq!(snapshot.completed, 1);
        assert_eq!(snapshot.failed, 0);
        assert_eq!(snapshot.queue_depth, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_dispatch_and_immediate_shutdown_settle_every_admitted_event() {
        let temp = TestDir::new("admission-race");
        let journal_path = temp.join("journal.jsonl");
        let journal = HookEffectJournal::open(&journal_path).expect("open hook journal");
        let hooks = Hooks::from_user_config(Some(&BTreeMap::from([(
            "session.created".to_owned(),
            vec!["true".to_owned()],
        )])));
        let bus = LifecycleBus::new(8192);
        let emitter = LifecycleEmitter::new(bus);
        let health = LifecycleHookHealth::default();
        let (dispatcher, runtime) = LifecycleHookDispatcher::start(
            hooks,
            emitter.clone(),
            LifecycleCorrelation::default(),
            Some(journal),
            health.clone(),
        );

        assert!(dispatcher.dispatch(emit_canonical(&emitter, "session.created").await));
        let mut producers = Vec::new();
        for _ in 0..8 {
            let dispatcher = dispatcher.clone();
            let emitter = emitter.clone();
            producers.push(tokio::spawn(async move {
                let mut accepted = 0usize;
                let mut rejected = 0usize;
                for _ in 0..32 {
                    if dispatcher.dispatch(emit_canonical(&emitter, "session.created").await) {
                        accepted += 1;
                    } else {
                        rejected += 1;
                    }
                }
                (accepted, rejected)
            }));
        }

        let shutdown = tokio::time::timeout(settle(30), runtime.shutdown())
            .await
            .expect("admission race dispatcher did not drain")
            .expect("admission race cleanup was unproven");
        assert_eq!(shutdown, LifecycleHookShutdown::Drained);

        let mut accepted = 1usize;
        let mut rejected = 0usize;
        for producer in producers {
            let (producer_accepted, producer_rejected) =
                producer.await.expect("dispatch producer panicked");
            accepted = accepted.saturating_add(producer_accepted);
            rejected = rejected.saturating_add(producer_rejected);
        }
        assert!(!dispatcher.dispatch(emit_canonical(&emitter, "session.created").await));
        rejected = rejected.saturating_add(1);
        assert!(rejected > 0);
        drop(dispatcher);

        assert_eq!(
            assert_completed_journal(&journal_path, accepted).len(),
            accepted
        );
        let snapshot = health.snapshot();
        assert_eq!(snapshot.queued, u64::try_from(accepted).unwrap());
        assert_eq!(snapshot.completed, u64::try_from(accepted).unwrap());
        assert_eq!(snapshot.dropped, u64::try_from(rejected).unwrap());
        assert_eq!(snapshot.failed, 0);
        assert_eq!(snapshot.timed_out, 0);
        assert_eq!(snapshot.queue_depth, 0);
        assert!(
            snapshot.queue_depth < u64::MAX / 2,
            "queue depth underflowed"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn business_drain_does_not_cancel_a_canonical_observer() {
        let temp = TestDir::new("business-drain-isolation");
        let evidence_path = temp.join("completed.txt");
        let journal_path = temp.join("journal.jsonl");
        let journal = HookEffectJournal::open(&journal_path).expect("open hook journal");
        let operator_drain = Arc::new(AtomicBool::new(true));
        let command = format!(
            "sleep 1; printf 'drain.requested\\n' >> {}",
            shell_quote(&evidence_path.to_string_lossy())
        );
        let hooks = Hooks::from_user_config(Some(&BTreeMap::from([(
            "drain.requested".to_owned(),
            vec![command],
        )])));
        let bus = LifecycleBus::new(64);
        let emitter = LifecycleEmitter::new(bus);
        let health = LifecycleHookHealth::default();
        // The production dispatcher intentionally has no operator-drain input. Its only stop
        // authority is the runtime-owned cancellation flag exercised by two-phase shutdown.
        let (dispatcher, runtime) = LifecycleHookDispatcher::start(
            hooks,
            emitter.clone(),
            LifecycleCorrelation::default(),
            Some(journal),
            health.clone(),
        );
        assert!(operator_drain.load(Ordering::Acquire));
        assert!(dispatcher.dispatch(emit_canonical(&emitter, "drain.requested").await));
        let shutdown = tokio::time::timeout(settle(15), runtime.shutdown())
            .await
            .expect("business-drain observer did not finish")
            .expect("business-drain observer cleanup was unproven");
        assert_eq!(shutdown, LifecycleHookShutdown::Drained);
        assert_eq!(read_lines(&evidence_path), ["drain.requested"]);
        assert_eq!(
            assert_completed_journal(&journal_path, 1),
            ["drain.requested"]
        );
        assert_eq!(health.snapshot().completed, 1);
        drop(dispatcher);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn every_active_canonical_hook_reaches_the_shell_runner() {
        let temp = TestDir::new("all-active");
        let evidence_path = temp.join("evidence.txt");
        let journal_path = temp.join("journal.jsonl");
        let journal = HookEffectJournal::open(&journal_path).expect("open hook journal");
        let specs = iteron_protocol::lifecycle::events().collect::<Vec<_>>();
        let active = specs
            .iter()
            .copied()
            .filter(|spec| matches!(spec.availability, LifecycleAvailability::Active))
            .collect::<Vec<_>>();
        let reserved = specs
            .iter()
            .filter(|spec| matches!(spec.availability, LifecycleAvailability::Reserved(_)))
            .map(|spec| spec.id)
            .collect::<BTreeSet<_>>();
        let gates = active
            .iter()
            .filter(|spec| spec.hook_capability == HookCapability::Gate)
            .map(|spec| spec.id)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            active.len(),
            193,
            "the ACTIVE lifecycle canary must stay exact"
        );
        assert_eq!(gates.len(), 12, "the Gate lifecycle set must stay exact");

        let commands = active
            .iter()
            .filter(|spec| spec.id != "hook.registered")
            .map(|spec| {
                (
                    spec.id.to_owned(),
                    vec![sentinel_command(&evidence_path, spec.id)],
                )
            })
            .collect::<BTreeMap<_, _>>();
        let hooks = Hooks::from_user_config(Some(&commands));
        assert_eq!(hooks.subscribed_lifecycle_events().len(), active.len() - 1);
        let drain = Arc::new(AtomicBool::new(false));

        for event_id in &gates {
            let report = tokio::time::timeout(
                Duration::from_secs(5),
                hooks.run_lifecycle_cancellable_journaled(
                    event_id,
                    "{}",
                    None,
                    Some(drain.as_ref()),
                    &journal,
                ),
            )
            .await
            .unwrap_or_else(|_| panic!("timed out running Gate hook {event_id}"))
            .unwrap_or_else(|reason| panic!("Gate hook {event_id} was rejected: {reason}"));
            assert_eq!(report.completed, 1, "Gate hook {event_id} did not run");
            assert_eq!(report.failed, 0, "Gate hook {event_id} failed");
            assert_eq!(report.timed_out, 0, "Gate hook {event_id} timed out");
        }

        let bus = LifecycleBus::new(4096);
        let emitter = LifecycleEmitter::new(bus.clone());
        let health = LifecycleHookHealth::default();
        let (dispatcher, runtime) = LifecycleHookDispatcher::start(
            hooks,
            emitter.clone(),
            LifecycleCorrelation::default(),
            Some(journal.clone()),
            health.clone(),
        );

        for spec in &active {
            if spec.hook_capability != HookCapability::Gate && spec.id != "hook.registered" {
                let event = emit_canonical(&emitter, spec.id).await;
                dispatcher.dispatch(event);
            }
        }
        drop(dispatcher);
        let shutdown = tokio::time::timeout(settle(45), runtime.shutdown())
            .await
            .expect("lifecycle dispatcher did not drain")
            .expect("lifecycle dispatcher worker panicked");
        assert_eq!(shutdown, LifecycleHookShutdown::Drained);

        // Prove the registration event through the same production start path without turning
        // every registration announcement into another shell invocation. Across the two starts,
        // the bus still receives exactly one registration envelope per one of the 193 canonical
        // subscriptions, while each active ID reaches its command exactly once.
        let registration_hooks = Hooks::from_user_config(Some(&BTreeMap::from([(
            "hook.registered".to_owned(),
            vec![sentinel_command(&evidence_path, "hook.registered")],
        )])));
        let (registration_dispatcher, registration_runtime) = LifecycleHookDispatcher::start(
            registration_hooks,
            emitter.clone(),
            LifecycleCorrelation::default(),
            Some(journal.clone()),
            health.clone(),
        );
        drop(registration_dispatcher);
        let registration_shutdown =
            tokio::time::timeout(settle(45), registration_runtime.shutdown())
                .await
                .expect("registration dispatcher did not drain")
                .expect("registration dispatcher worker panicked");
        assert_eq!(registration_shutdown, LifecycleHookShutdown::Drained);

        let expected_async = active.len() - gates.len();
        let snapshot = health.snapshot();
        assert_eq!(snapshot.queued, u64::try_from(expected_async).unwrap());
        assert_eq!(snapshot.completed, u64::try_from(expected_async).unwrap());
        assert_eq!(snapshot.dropped, 0);
        assert_eq!(snapshot.failed, 0);
        assert_eq!(snapshot.timed_out, 0);
        assert_eq!(snapshot.blocked, 0);
        assert_eq!(snapshot.queue_depth, 0);
        assert_eq!(snapshot.open_circuits, 0);

        let expected_invocations = active.len();
        let evidence = read_lines(&evidence_path);
        assert_eq!(evidence.len(), expected_invocations);
        let evidence_ids = evidence.iter().map(String::as_str).collect::<BTreeSet<_>>();
        let active_ids = active.iter().map(|spec| spec.id).collect::<BTreeSet<_>>();
        assert_eq!(evidence_ids, active_ids);
        assert!(evidence_ids.is_disjoint(&reserved));
        assert_eq!(
            evidence
                .iter()
                .filter(|event_id| event_id.as_str() == "hook.registered")
                .count(),
            1,
            "the canonical registration hook must reach its shell command once"
        );

        let journal_events = assert_completed_journal(&journal_path, expected_invocations);
        let journal_ids = journal_events
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(journal_ids, active_ids);
        assert!(journal_ids.is_disjoint(&reserved));
        assert_eq!(
            bus.snapshot()
                .events
                .iter()
                .filter(|event| event.event_id.as_str() == "hook.registered")
                .count(),
            active.len(),
            "start must emit exactly one registration envelope per subscription"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn third_failed_delivery_dispatches_circuit_opened_hook() {
        let temp = TestDir::new("circuit-opened");
        let evidence_path = temp.join("evidence.txt");
        let journal_path = temp.join("journal.jsonl");
        let journal = HookEffectJournal::open(&journal_path).expect("open hook journal");
        let commands = BTreeMap::from([
            ("session.created".to_owned(), vec!["exit 1".to_owned()]),
            (
                "hook.circuit_opened".to_owned(),
                vec![sentinel_command(&evidence_path, "hook.circuit_opened")],
            ),
        ]);
        let hooks = Hooks::from_user_config(Some(&commands));
        let bus = LifecycleBus::new(128);
        let emitter = LifecycleEmitter::new(bus.clone());
        let health = LifecycleHookHealth::default();
        let (dispatcher, runtime) = LifecycleHookDispatcher::start(
            hooks,
            emitter.clone(),
            LifecycleCorrelation::default(),
            Some(journal),
            health.clone(),
        );
        for _ in 0..CIRCUIT_FAILURE_THRESHOLD {
            dispatcher.dispatch(emit_canonical(&emitter, "session.created").await);
        }

        tokio::time::timeout(settle(10), async {
            loop {
                if read_lines(&evidence_path)
                    .iter()
                    .any(|event_id| event_id == "hook.circuit_opened")
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("configured circuit-open hook did not execute");
        drop(dispatcher);
        let shutdown = tokio::time::timeout(settle(10), runtime.shutdown())
            .await
            .expect("circuit test dispatcher did not drain")
            .expect("circuit test dispatcher panicked");
        assert_eq!(shutdown, LifecycleHookShutdown::Drained);

        let snapshot = health.snapshot();
        assert_eq!(snapshot.queued, 4);
        assert_eq!(snapshot.completed, 4);
        assert_eq!(snapshot.failed, 3);
        assert_eq!(snapshot.timed_out, 0);
        assert_eq!(snapshot.dropped, 0);
        assert_eq!(snapshot.queue_depth, 0);
        assert_eq!(snapshot.open_circuits, 1);
        assert_eq!(read_lines(&evidence_path), ["hook.circuit_opened"]);
        assert_eq!(
            bus.snapshot()
                .events
                .iter()
                .filter(|event| event.event_id.as_str() == "hook.circuit_opened")
                .count(),
            1
        );
    }
}
