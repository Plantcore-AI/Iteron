//! Single session owner of detached handles, cancellation, settlement and summary retention.

use super::launch::{
    Collected, DetachedRun, InTurnWorkflowLauncher, Launched, PreparedWorkflow, WorkflowLauncher,
};
use super::progress::{DegradedAgentSink, FanoutProgressSink, PartialWorkSink};
use super::projection::WorkflowRunTerminal;
use super::run_store::{persist_result, run_dir};
use super::summary::{killed_run_summary, run_result_summary, run_status, unreported_run};
use iteron_workflow::{ProgressSink, RunHandle, RunReport, WorkflowEngine};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// One settled background run, announced to the session loop that owns the event queue.
///
/// The supervisor cannot publish anything itself — it lives behind an `Arc` shared with a turn that
/// holds `&mut Agent` — so it reports through a channel the session's `select!` drains. That is what
/// makes a run settling while the operator is idle still reach the screen.
pub struct RunSettled {
    pub run_id: String,
    pub terminal: WorkflowRunTerminal,
    /// The operator-facing line. Names the run, its terminal state, and how to read the result.
    pub notice: String,
    /// Bounded model-facing task notification. The session owner either steers this into a live
    /// writer or starts one follow-up while idle; it is never reclassified as operator input.
    pub notification: String,
}

/// What the session did with the runs it still owned when it ended.
///
/// Returned by the session loop rather than published, because by the time it exists the event
/// queue's reader is already gone: the session ends *because* the frontend hung up. The client
/// prints it after restoring the terminal.
#[derive(Debug, Default)]
pub struct ShutdownReport {
    pub lines: Vec<String>,
}

impl ShutdownReport {
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }
}

/// Total bytes of settled-run summaries this owner keeps in memory for `collect`.
///
/// A bound, not a buffer: past it the OLDEST settled summary is dropped and the drop is recorded, so
/// a `collect` on an evicted run names the durable `result.json` instead of answering "unknown".
/// A silently forgotten result would be indistinguishable from a run that never happened.
const MAX_RETAINED_SUMMARY_BYTES: usize = 4 * 1024 * 1024;
const MAX_TASK_NOTIFICATION_RESULT_BYTES: usize = 48 * 1024;
fn utf8_head(text: &str, max_bytes: usize) -> &str {
    if text.len() <= max_bytes {
        return text;
    }
    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    &text[..end]
}

fn workflow_task_notification(
    name: &str,
    run_id: &str,
    status: &str,
    summary: &str,
    result_path: Option<&Path>,
    report: &RunReport,
) -> String {
    let truncated = summary.len()
        > iteron_tunables::param_integer(
            "cli.workflow.max_task_notification_result_bytes",
            MAX_TASK_NOTIFICATION_RESULT_BYTES,
        );
    let result = utf8_head(
        summary,
        iteron_tunables::param_integer(
            "cli.workflow.max_task_notification_result_bytes",
            MAX_TASK_NOTIFICATION_RESULT_BYTES,
        ),
    );
    let payload = serde_json::json!({
        "task_id": run_id,
        "task_type": "local_workflow",
        "status": status,
        "summary": format!("Dynamic workflow \"{name}\" {status}"),
        "result": result,
        "result_truncated": truncated,
        "full_result_path": result_path,
        "usage": {
            "agent_count": report.cache_hits.saturating_add(report.cache_misses),
            "subagent_tokens": report.tokens,
            "tool_uses": report.tool_calls,
            "duration_ms": report.elapsed_ms,
        }
    });
    format!(
        "<task-notification>\n{}\n</task-notification>",
        serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string())
    )
}

/// How long a session waits for the runs it cancelled at exit before writing their terminal record
/// itself. The engine interrupts a sync JS loop at its own safe point; this bounds the wait so
/// quitting can never hang on a script that ignores it.
pub const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Most session-owned run rows copied into one operator inventory response. Durable history remains
/// available through sidecars; this bound keeps one `/workflows` refresh independent of session age.
const MAX_OPERATOR_INVENTORY_RUNS: usize = 64;

enum SupervisedState {
    Running {
        handle: Arc<RunHandle>,
        started: std::time::Instant,
        /// Set once `cancel` has been requested, so the operator is not told "running" about a run
        /// that is already stopping.
        cancelling: bool,
    },
    /// Settled with a report. `summary` is `None` only when it was evicted under the byte bound.
    Settled { summary: Option<String> },
    /// The engine failed before producing a report.
    Failed { error: String },
}

struct SupervisedRun {
    name: String,
    workflows_dir: PathBuf,
    degraded: Arc<DegradedAgentSink>,
    /// The results this run had already produced, so a kill answers with them rather than with the
    /// `null` the engine resolves a stopped script to.
    partial: Arc<PartialWorkSink>,
    state: SupervisedState,
    /// Monotonic registration order, so eviction drops the oldest settled summary first.
    ordinal: u64,
}

/// Operator-facing state for one workflow run owned by the current interactive session.
///
/// This is deliberately smaller than [`SupervisedState`]: summaries and engine handles never
/// cross into the frontend. The TUI needs identity, lifecycle and bounded progress counters only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisedRunStatus {
    Running,
    Cancelling,
    Settled,
    Failed,
}

/// A bounded snapshot of one session-owned workflow run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisedRunInfo {
    pub run_id: String,
    pub name: String,
    pub status: SupervisedRunStatus,
    pub elapsed_ms: u64,
    pub finished_agents: usize,
    pub running_agents: usize,
    pub dropped_results: usize,
}

fn supervised_run_info(run_id: &str, run: &SupervisedRun) -> SupervisedRunInfo {
    let partial = run.partial.snapshot();
    let (status, elapsed_ms) = match &run.state {
        SupervisedState::Running {
            started,
            cancelling,
            ..
        } => (
            if *cancelling {
                SupervisedRunStatus::Cancelling
            } else {
                SupervisedRunStatus::Running
            },
            started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        ),
        SupervisedState::Settled { .. } => (SupervisedRunStatus::Settled, 0),
        SupervisedState::Failed { .. } => (SupervisedRunStatus::Failed, 0),
    };
    SupervisedRunInfo {
        run_id: run_id.to_string(),
        name: run.name.clone(),
        status,
        elapsed_ms,
        finished_agents: partial.finished.len(),
        running_agents: partial.running,
        dropped_results: partial.dropped,
    }
}

/// The one answer for a settled run whose summary is no longer held in memory.
///
/// `collect` and `cancel` must give the SAME answer here. `cancel` used to reply `Unknown` — "this
/// session never started that run" — to a run this session demonstrably did start, which is
/// indistinguishable from a lost result, the one failure a detached run must not have.
fn evicted_summary(run: &SupervisedRun, run_id: &str, evicted: usize) -> String {
    format!(
        "Workflow `{}` (run {run_id}) settled, but this session no longer holds its summary in \
         memory ({evicted} older result(s) were dropped to stay within its retention bound). The \
         authoritative result is on disk at {}.",
        run.name,
        run_dir(&run.workflows_dir, run_id)
            .join("result.json")
            .display()
    )
}

#[derive(Default)]
struct SupervisorInner {
    runs: std::collections::HashMap<String, SupervisedRun>,
    next_ordinal: u64,
    retained_bytes: usize,
    evicted: usize,
}

/// The session-scoped owner of detached workflow runs.
///
/// # Why it lives beside the session loop and not inside the turn
///
/// A run cannot outlive its turn while the only thing holding it is a local binding inside a method
/// that borrows `&mut Agent`. This type is the owner that fixes that: it is an `Arc` installed on
/// the agent as a [`WorkflowLauncher`] *and* held by `app_server::serve`, i.e. it is reachable from
/// both sides of the turn's exclusive borrow without either side lending the other anything.
///
/// # What it guarantees
///
/// 1. **Nothing is orphaned.** Every detached run is registered before it is announced, and a reaper
///    task holds the handle for as long as the run lives. `serve` cannot return without going
///    through [`Self::shutdown`], which cancels and reaps.
/// 2. **No result is lost.** The reaper persists the terminal sidecar (`iteron workflow list`) and
///    keeps the model-facing summary for `collect`, which is built by [`run_result_summary`] — the
///    same function the in-turn path uses.
/// 3. **The model is never told a turn completed when it did not.** `launch` returns
///    [`Launched::Detached`] with a receipt that states, in words, that there is no result yet.
pub struct WorkflowSupervisor {
    /// A self-reference so a reaper task can be handed the owner without the launcher call site
    /// having to pass one in. `WorkflowLauncher` is implemented for `WorkflowSupervisor` (not for
    /// `Arc<WorkflowSupervisor>`), so `&self` is all `launch` receives.
    me: std::sync::Weak<WorkflowSupervisor>,
    inner: std::sync::Mutex<SupervisorInner>,
    settled: tokio::sync::mpsc::Sender<RunSettled>,
    activity: std::sync::Mutex<Option<tokio::sync::mpsc::Sender<iteron_protocol::ActivityEvent>>>,
    activity_saturated: std::sync::atomic::AtomicU64,
}

impl WorkflowSupervisor {
    #[cfg(all(test, feature = "script-workflows"))]
    pub(super) fn evict_summary_for_test(&self, run_id: &str) {
        let mut inner = self.inner.lock().unwrap();
        let run = inner.runs.get_mut(run_id).unwrap();
        assert!(matches!(run.state, SupervisedState::Settled { .. }));
        run.state = SupervisedState::Settled { summary: None };
        inner.evicted = inner.evicted.saturating_add(1);
    }

    /// The one sentence handed to the model with every receipt. A constant so the exit rule the
    /// model is told and the exit rule [`Self::shutdown`] enforces cannot drift apart.
    pub const OWNERSHIP: &'static str = "This session owns the run. Ending the session stops it at the engine's next safe point; \
         its journal is kept, so `iteron workflow resume <run-id>` continues it in a new process.";

    pub fn new(settled: tokio::sync::mpsc::Sender<RunSettled>) -> Arc<Self> {
        Arc::new_cyclic(|me| WorkflowSupervisor {
            me: me.clone(),
            inner: std::sync::Mutex::new(SupervisorInner::default()),
            settled,
            activity: std::sync::Mutex::new(None),
            activity_saturated: std::sync::atomic::AtomicU64::new(0),
        })
    }

    pub fn set_activity(&self, sender: tokio::sync::mpsc::Sender<iteron_protocol::ActivityEvent>) {
        *self.activity.lock().unwrap() = Some(sender);
    }

    fn publish_activity(&self, event: iteron_protocol::ActivityEvent) {
        debug_assert!(event.validate().is_ok());
        let sender = self.activity.lock().unwrap().clone();
        if sender.is_some_and(|sender| sender.try_send(event).is_err()) {
            self.activity_saturated
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Snapshot the newest session-owned runs in registration order. The response has an explicit
    /// row ceiling and contains no model-authored result bytes.
    pub fn inventory(&self) -> Vec<SupervisedRunInfo> {
        let inner = self.inner.lock().unwrap();
        let mut runs: Vec<_> = inner
            .runs
            .iter()
            .map(|(run_id, run)| (run.ordinal, run_id.as_str(), run))
            .collect();
        runs.sort_by_key(|(ordinal, _, _)| *ordinal);
        let skip = runs.len().saturating_sub(iteron_tunables::param_integer(
            "cli.workflow.max_operator_inventory_runs",
            MAX_OPERATOR_INVENTORY_RUNS,
        ));
        runs.into_iter()
            .skip(skip)
            .map(|(_, run_id, run)| supervised_run_info(run_id, run))
            .collect()
    }

    /// Whether a persisted run id may be resumed through this owner. A running or already-
    /// cancelling run must settle first; replacing its handle would orphan its reaper.
    pub fn may_resume(&self, run_id: &str) -> bool {
        let inner = self.inner.lock().unwrap();
        !inner
            .runs
            .get(run_id)
            .is_some_and(|run| matches!(run.state, SupervisedState::Running { .. }))
    }

    /// Operator kill: trip exactly the selected detached run and return its post-request snapshot.
    /// This bypasses the model-facing `Workflow({cancel})` surface while sharing the same owner and
    /// cancellation token.
    pub fn cancel_for_operator(&self, run_id: &str) -> Result<SupervisedRunInfo, String> {
        let mut inner = self.inner.lock().unwrap();
        let Some(run) = inner.runs.get_mut(run_id) else {
            return Err(format!(
                "workflow run `{run_id}` is not owned by this session"
            ));
        };
        let ordinal = run.ordinal;
        match &mut run.state {
            SupervisedState::Running {
                handle, cancelling, ..
            } => {
                run.partial.note_kill();
                handle.cancel();
                *cancelling = true;
                self.publish_activity(workflow_background_activity(
                    ordinal,
                    "stopping",
                    iteron_protocol::ActivityState::Cancelling,
                    Some(1),
                    Some(iteron_workflow::default_stop_deadline_ms()),
                ));
                Ok(supervised_run_info(run_id, run))
            }
            SupervisedState::Settled { .. } => {
                Err(format!("workflow run `{run_id}` has already settled"))
            }
            SupervisedState::Failed { .. } => {
                Err(format!("workflow run `{run_id}` has already failed"))
            }
        }
    }

    /// Register and start one detached run, spawning the reaper that owns it from here on.
    fn detach(
        &self,
        owner: Arc<WorkflowSupervisor>,
        prepared: PreparedWorkflow,
        runtime: tokio::runtime::Handle,
    ) -> Launched {
        let PreparedWorkflow {
            run_id,
            name,
            workflows_dir,
            spec,
            spawner,
            sink,
            degraded,
            ..
        } = prepared;
        // Fanned in rather than passed by the caller: only a run that DETACHES can be killed out of
        // band, so only a detached run needs its finished work held in memory. Wrapping can never
        // lower what the fan-out reports as its port version below what `sink` already reported.
        let partial = Arc::new(PartialWorkSink::new());
        let sink: Arc<dyn ProgressSink> =
            Arc::new(FanoutProgressSink::new(vec![sink, partial.clone()]));
        let handle = Arc::new(WorkflowEngine::launch(spec, spawner, sink));
        {
            let mut inner = self.inner.lock().unwrap();
            let ordinal = inner.next_ordinal;
            inner.next_ordinal += 1;
            let replaced = inner.runs.insert(
                run_id.clone(),
                SupervisedRun {
                    name: name.clone(),
                    workflows_dir: workflows_dir.clone(),
                    degraded: degraded.clone(),
                    partial,
                    state: SupervisedState::Running {
                        handle: Arc::clone(&handle),
                        started: std::time::Instant::now(),
                        cancelling: false,
                    },
                    ordinal,
                },
            );
            if let Some(SupervisedRun {
                state:
                    SupervisedState::Settled {
                        summary: Some(summary),
                    },
                ..
            }) = replaced
            {
                inner.retained_bytes = inner.retained_bytes.saturating_sub(summary.len());
            }
        }

        // The reaper. It is the only joiner of this handle (`RunHandle::join` consumes the
        // receiver), which is why `shutdown` waits on the settled channel instead of joining too.
        let reaped_id = run_id.clone();
        let reaped_name = name.clone();
        runtime.spawn(async move {
            let outcome = handle.join().await;
            owner.settle(&reaped_id, &reaped_name, outcome).await;
        });

        Launched::Detached(DetachedRun {
            run_id,
            name,
            ownership: iteron_tunables::param_str("cli.workflow.ownership", Self::OWNERSHIP)
                .to_string(),
        })
    }

    /// Record a settled run: persist its terminal sidecar, keep its model-facing summary, announce
    /// it. Called from the reaper, and from [`Self::shutdown`] for a run that ignored its cancel.
    async fn settle(&self, run_id: &str, name: &str, outcome: anyhow::Result<RunReport>) {
        let (workflows_dir, degraded, partial, ordinal) = {
            let inner = self.inner.lock().unwrap();
            match inner.runs.get(run_id) {
                // Already settled (shutdown got there first). Settling twice would publish a second
                // terminal line for one run, so stop here.
                Some(run) if !matches!(run.state, SupervisedState::Running { .. }) => return,
                Some(run) => (
                    run.workflows_dir.clone(),
                    run.degraded.clone(),
                    run.partial.clone(),
                    run.ordinal,
                ),
                None => return,
            }
        };
        self.publish_activity(workflow_background_activity(
            ordinal,
            "persisting-result",
            iteron_protocol::ActivityState::Running,
            None,
            None,
        ));

        // Render first, WITHOUT the lock: both summaries are pure and the report can be large.
        let (report, state, notice, status, model_summary, terminal) = match outcome {
            Ok(report) => {
                // `stopped` is set for exactly the cancellation token this owner trips, so it is
                // the kill signal. A run that returned on its own a moment before the cancel landed
                // reports `false` and is rendered as what it is: completed.
                let summary = if report.stopped {
                    killed_run_summary(
                        name,
                        run_id,
                        &report,
                        &partial.snapshot(),
                        &degraded.reasons(),
                    )
                } else {
                    run_result_summary(name, run_id, &report, &degraded.reasons())
                };
                let terminal_text = if report.stopped {
                    "was killed and kept the results it had already produced"
                } else {
                    "finished in the background"
                };
                let status = if report.stopped {
                    "stopped"
                } else {
                    "completed"
                };
                let terminal = if report.stopped {
                    WorkflowRunTerminal::Cancelled
                } else {
                    WorkflowRunTerminal::Completed
                };
                (
                    report,
                    SupervisedState::Settled {
                        summary: Some(summary.clone()),
                    },
                    format!(
                        "Dynamic workflow `{name}` (run {run_id}) {terminal_text}; `/workflows` shows its \
                         result and controls"
                    ),
                    status,
                    summary,
                    terminal,
                )
            }
            Err(error) => {
                let message = format!("Workflow run failed: {error}");
                (
                    unreported_run(run_id, &message),
                    SupervisedState::Failed {
                        error: message.clone(),
                    },
                    format!("Workflow `{name}` (run {run_id}) failed in the background: {message}"),
                    "failed",
                    message,
                    WorkflowRunTerminal::Failed,
                )
            }
        };

        // CLAIM THE RUN BEFORE WRITING ITS FILE. `shutdown` decides whether to write a synthetic
        // terminal record while holding this same lock and reading this same state, so taking the
        // state first makes "who writes result.json" a single decision instead of a race in which
        // the loser's file lands last. A reaper that finds the state already taken writes nothing.
        let mut notice = notice;
        {
            let mut inner = self.inner.lock().unwrap();
            match inner.runs.get_mut(run_id) {
                Some(run) if matches!(run.state, SupervisedState::Running { .. }) => {
                    run.state = state;
                }
                // Shutdown claimed it in the window above and has already written its record.
                _ => return,
            }
            if let Some(SupervisedState::Settled {
                summary: Some(summary),
            }) = inner.runs.get(run_id).map(|run| &run.state)
            {
                inner.retained_bytes += summary.len();
            }
            evict_summaries(&mut inner);
        }

        let result_path = run_dir(&workflows_dir, run_id).join("result.json");
        let result_persisted = match persist_result(&workflows_dir, run_id, &report) {
            Ok(()) => true,
            Err(error) => {
                // Degrade, never destroy: a sidecar that cannot be written must not cost the
                // operator a run they already paid for. The bounded notification remains available.
                notice.push_str(&format!(
                    " (its result sidecar could not be written: {error})"
                ));
                false
            }
        };
        self.publish_activity(workflow_background_activity(
            ordinal,
            "persisting-result",
            if result_persisted {
                iteron_protocol::ActivityState::Succeeded
            } else {
                iteron_protocol::ActivityState::Failed
            },
            None,
            None,
        ));
        if report.stopped {
            self.publish_activity(workflow_background_activity(
                ordinal,
                "stopped",
                iteron_protocol::ActivityState::Cancelled,
                None,
                None,
            ));
        }

        let notification = workflow_task_notification(
            name,
            run_id,
            status,
            &model_summary,
            result_persisted.then_some(result_path.as_path()),
            &report,
        );

        let _ = self
            .settled
            .send(RunSettled {
                run_id: run_id.to_string(),
                terminal,
                notice,
                notification,
            })
            .await;
    }

    /// Cancel every run still live, wait `grace` for them to settle through their reapers, and write
    /// a terminal record for any that did not.
    ///
    /// The wait is on `settled` — the reapers' channel — because the reaper holds the only joinable
    /// receiver for each handle. Draining it here also means a run that settles *during* shutdown is
    /// recorded with its real report rather than the synthetic one below.
    pub async fn shutdown(
        &self,
        settled: &mut tokio::sync::mpsc::Receiver<RunSettled>,
        grace: std::time::Duration,
    ) -> ShutdownReport {
        let live: Vec<String> = {
            let inner = self.inner.lock().unwrap();
            inner
                .runs
                .iter()
                .filter(|(_, run)| matches!(run.state, SupervisedState::Running { .. }))
                .map(|(id, _)| id.clone())
                .collect()
        };
        if live.is_empty() {
            return ShutdownReport::default();
        }

        {
            let inner = self.inner.lock().unwrap();
            for id in &live {
                let Some(run) = inner.runs.get(id) else {
                    continue;
                };
                let SupervisedState::Running { handle, .. } = &run.state else {
                    continue;
                };
                // Sample BEFORE the cancel, for the reason `note_kill` documents: afterwards the
                // engine has already retired the in-flight rows and the count reads zero.
                run.partial.note_kill();
                self.publish_activity(workflow_background_activity(
                    run.ordinal,
                    "stopping",
                    iteron_protocol::ActivityState::Cancelling,
                    Some(live.len()),
                    Some(u64::try_from(grace.as_millis()).unwrap_or(u64::MAX)),
                ));
                handle.cancel();
            }
        }

        let deadline = tokio::time::Instant::now() + grace;
        let mut outstanding = live.len();
        while outstanding > 0 {
            match tokio::time::timeout_at(deadline, settled.recv()).await {
                Ok(Some(message)) => {
                    if live.contains(&message.run_id) {
                        outstanding -= 1;
                    }
                }
                // The channel cannot close while the supervisor holds a sender, so `None` and a
                // timeout are the same terminal condition: stop waiting and record the truth.
                Ok(None) | Err(_) => break,
            }
        }

        let mut lines = Vec::new();
        let mut inner = self.inner.lock().unwrap();
        for id in live {
            let Some(run) = inner.runs.get_mut(&id) else {
                continue;
            };
            match &run.state {
                SupervisedState::Running { .. } => {
                    // The count goes into the record because this run never reached `settle`, so
                    // this message is the only place its partial work is named at all; `collect`
                    // will answer `Failed` with exactly this string.
                    let finished = run.partial.snapshot().finished.len();
                    let message = format!(
                        "the session ended before this run settled; it was cancelled at exit \
                         ({finished} agent result(s) had already been produced and are in its \
                         journal)"
                    );
                    let _ = persist_result(&run.workflows_dir, &id, &unreported_run(&id, &message));
                    run.state = SupervisedState::Failed { error: message };
                    self.publish_activity(workflow_background_activity(
                        run.ordinal,
                        "stopped",
                        iteron_protocol::ActivityState::Failed,
                        None,
                        None,
                    ));
                    lines.push(format!(
                        "workflow `{}` (run {id}) did not stop within {}s and was recorded as \
                         stopped at exit; resume it with `iteron workflow resume {id}`",
                        run.name,
                        grace.as_secs()
                    ));
                }
                _ => lines.push(format!(
                    "workflow `{}` (run {id}) was stopped when the session ended; resume it with \
                     `iteron workflow resume {id}`",
                    run.name
                )),
            }
        }
        ShutdownReport { lines }
    }
}

fn workflow_background_activity(
    ordinal: u64,
    phase: &'static str,
    state: iteron_protocol::ActivityState,
    stopping_count: Option<usize>,
    deadline_after_ms: Option<u64>,
) -> iteron_protocol::ActivityEvent {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        });
    let persisting = phase == "persisting-result";
    iteron_protocol::ActivityEvent {
        schema_version: iteron_protocol::ACTIVITY_SCHEMA_VERSION,
        id: format!("workflow-{ordinal}:{phase}"),
        parent_id: Some(format!("workflow-{ordinal}")),
        kind: if persisting {
            iteron_protocol::ActivityKind::Persistence
        } else {
            iteron_protocol::ActivityKind::Cancellation
        },
        state,
        owner: iteron_protocol::ActivityOwner::Workflow,
        started_at_unix_ms: now,
        updated_at_unix_ms: now,
        attempt: 0,
        limit: 0,
        next_retry_at_unix_ms: None,
        deadline_unix_ms: deadline_after_ms.map(|delay| now.saturating_add(delay)),
        cancelability: if persisting {
            iteron_protocol::ActivityCancelability::Cooperative
        } else {
            iteron_protocol::ActivityCancelability::Strong
        },
        detail_code: persisting
            .then_some(iteron_protocol::ActivityDetailCode::WorkflowResultPersist),
        progress: stopping_count.map(|count| iteron_protocol::ActivityProgress {
            completed: 0,
            total: u64::try_from(count.max(1))
                .unwrap_or(iteron_protocol::MAX_ACTIVITY_PROGRESS_UNITS)
                .min(iteron_protocol::MAX_ACTIVITY_PROGRESS_UNITS),
        }),
    }
}

/// Drop the oldest settled summaries until the retained bytes fit the bound, counting the drops.
///
/// The entry itself is kept: an evicted run answers `collect` by naming its durable `result.json`,
/// which is a different and honest answer from "unknown run".
fn evict_summaries(inner: &mut SupervisorInner) {
    while inner.retained_bytes
        > iteron_tunables::param_integer(
            "cli.workflow.max_retained_summary_bytes",
            MAX_RETAINED_SUMMARY_BYTES,
        )
    {
        let victim = inner
            .runs
            .iter()
            .filter(|(_, run)| matches!(run.state, SupervisedState::Settled { summary: Some(_) }))
            .min_by_key(|(_, run)| run.ordinal)
            .map(|(id, _)| id.clone());
        let Some(victim) = victim else { return };
        if let Some(run) = inner.runs.get_mut(&victim)
            && let SupervisedState::Settled { summary } = &mut run.state
            && let Some(dropped) = summary.take()
        {
            inner.retained_bytes = inner.retained_bytes.saturating_sub(dropped.len());
            inner.evicted += 1;
        }
    }
}

impl WorkflowLauncher for WorkflowSupervisor {
    fn launch(&self, prepared: PreparedWorkflow) -> Launched {
        if !prepared.background {
            // `background: false` is the model saying it cannot proceed without the result, so the
            // run is byte-for-byte the in-turn run it always was, even with an owner installed.
            // Everything else detaches: holding the conversation open for a whole fan-out is the
            // cost this supervisor exists to remove, and a default that only applied when the model
            // remembered to ask for it did not remove it.
            return InTurnWorkflowLauncher.launch(prepared);
        }
        // No ambient runtime, or no live `Arc` to hand the reaper, means no owner for the run — and
        // a detached run with no owner is an orphan. Run it in-turn instead; the kernel tells the
        // model the request was not granted rather than pretending it was.
        let (Ok(runtime), Some(owner)) = (tokio::runtime::Handle::try_current(), self.me.upgrade())
        else {
            return InTurnWorkflowLauncher.launch(prepared);
        };
        self.detach(owner, prepared, runtime)
    }

    fn collect(&self, run_id: &str) -> Collected {
        let inner = self.inner.lock().unwrap();
        let Some(run) = inner.runs.get(run_id) else {
            return Collected::Unknown(format!(
                "Workflow: run `{run_id}` was not started by this session. `iteron workflow list` \
                 shows every run on disk."
            ));
        };
        match &run.state {
            SupervisedState::Running {
                started,
                cancelling,
                ..
            } => Collected::Running {
                run_id: run_id.to_string(),
                name: if *cancelling {
                    format!("{} (cancelling)", run.name)
                } else {
                    run.name.clone()
                },
                elapsed_ms: started.elapsed().as_millis() as u64,
            },
            SupervisedState::Settled {
                summary: Some(summary),
            } => Collected::Settled {
                summary: summary.clone(),
            },
            SupervisedState::Settled { summary: None } => Collected::Settled {
                summary: evicted_summary(run, run_id, inner.evicted),
            },
            SupervisedState::Failed { error } => Collected::Failed {
                run_id: run_id.to_string(),
                error: error.clone(),
            },
        }
    }

    /// Kill a run, and answer with what killing it produced.
    ///
    /// The kill stays a REQUEST honoured at the engine's next safe point — this returns as soon as
    /// the token is tripped, and the terminal answer is read by a later `collect`, because blocking
    /// here would put a detached run back inside the turn that detaching exists to free. What
    /// changes is that the terminal answer is now a "killed" one carrying the finished agents'
    /// results and a count of what was interrupted ([`killed_run_summary`]), instead of the engine's
    /// bare `null`.
    fn cancel(&self, run_id: &str) -> Collected {
        let mut inner = self.inner.lock().unwrap();
        // Copied out before the mutable borrow below, so the evicted-summary answer can name the
        // same drop count `collect` names.
        let evicted = inner.evicted;
        let Some(run) = inner.runs.get_mut(run_id) else {
            return Collected::Unknown(format!(
                "Workflow: run `{run_id}` was not started by this session, so there is nothing to \
                 cancel."
            ));
        };
        let partial = run.partial.clone();
        match &mut run.state {
            SupervisedState::Running {
                handle,
                started,
                cancelling,
            } => {
                // Sample, then trip the token — never the other way round (see `note_kill`).
                partial.note_kill();
                handle.cancel();
                *cancelling = true;
                Collected::Running {
                    run_id: run_id.to_string(),
                    name: format!("{} (cancelling)", run.name),
                    elapsed_ms: started.elapsed().as_millis() as u64,
                }
            }
            SupervisedState::Settled {
                summary: Some(summary),
            } => Collected::Settled {
                summary: summary.clone(),
            },
            // Settled, but the summary was evicted. This is the SAME answer `collect` gives: a
            // `cancel` that replied "unknown" here would deny a run this session really did own.
            SupervisedState::Settled { summary: None } => Collected::Settled {
                summary: evicted_summary(run, run_id, evicted),
            },
            SupervisedState::Failed { error } => Collected::Failed {
                run_id: run_id.to_string(),
                error: error.clone(),
            },
        }
    }
}
