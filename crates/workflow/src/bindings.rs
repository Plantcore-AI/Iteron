//! The Rust host primitives behind the JS prelude: `__agent`, `__phase`, `__log`.
//!
//! `__agent` is the load-bearing bridge (proven in the B4 spike): it assigns a declaration-order
//! index synchronously, then — for a live call — acquires a [`Governor`] permit (the one global slot
//! pool), `tokio::spawn`s a SEND child running the injected [`AgentSpawner`], and awaits it (racing
//! the run's [`CancellationToken`]), resolving the JS Promise back on the runtime thread.
//!
//! Three engine-depth behaviors live here (design §2.5/§2.6 + review B2/B3):
//!   * **Journal short-circuit (B2):** on a journal hit `__agent` replays the cached OUTCOME —
//!     including `null` — BEFORE touching the Governor, budget, or lifetime cap, so
//!     `parallel(...).filter(Boolean)` is deterministic across a resume.
//!   * **Schema-forced structured output (§2.5):** when `opts.schema` is set, the model's text is
//!     parsed + validated against the JSON Schema; on failure the spawner is re-called with the
//!     errors appended, up to the run's pinned schema-retry ceiling, then degrades to `null`.
//!   * **Cancellation (B3):** each child races the cancel token and is aborted on cancel.
//!
//! Per-run state lives in [`RunState`]/[`AgentEnv`] (owned, never a static — a `OnceLock` silently
//! no-ops on the 2nd run and masks concurrency, per the spike's watch-out).

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rquickjs::function::Async;
use rquickjs::{Ctx, Function};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::cachekey;
use crate::events::{
    PREVIEW_MAX, ProgressEvent, ProgressSink, TOOL_SUMMARY_MAX, WorkflowState, truncate_preview,
};
use crate::journal::{Journal, Outcome, Record};
use crate::schema::{self, SchemaValidator};
use crate::spawner::{AgentActivityReporter, AgentCall, AgentOutcome, AgentSpawner};
use crate::task_dag::runtime::{AttemptTerminal, ExecutionLedger, TaskAdmission, digest_bytes};
use crate::task_dag::{
    AttemptAssignment, AttemptDisposition, AttemptId, AttemptRetryCause, TaskId,
};
use iteron_sched::Governor;
use iteron_sched::backoff::{Jitter, full_jitter};

#[path = "bindings/quorum.rs"]
mod quorum;
use quorum::QuorumGroups;

/// Backward-compatible default aggregate ceiling. A kernel-minted [`crate::RunLimits`] may narrow
/// it, and schema retries consume it one real spawn at a time.
pub const LIFETIME_CAP: usize = 1000;

/// Live rows are sampled at a human-readable cadence. One hertz keeps the running counters current
/// while bounding traffic into frontend sinks that commonly forward through unbounded channels.
const AGENT_ACTIVITY_INTERVAL: Duration = Duration::from_secs(1);

/// Fresh-per-run engine state. All fields are interior-mutable so the `Fn` host closures can share
/// one `Arc<RunState>` without a `&mut`.
pub struct RunState {
    index: AtomicUsize,
    agent_calls: AtomicUsize,
    max_agent_calls: usize,
    phases: Mutex<Vec<String>>,
    errors: AtomicUsize,
    tokens: AtomicU64,
    tool_calls: AtomicU64,
    quorum: QuorumGroups,
}

impl RunState {
    pub fn new(max_agent_calls: usize, early_stop_quorum: crate::EarlyStopQuorumPolicy) -> Self {
        debug_assert!(max_agent_calls > 0);
        RunState {
            index: AtomicUsize::new(0),
            agent_calls: AtomicUsize::new(0),
            max_agent_calls,
            phases: Mutex::new(Vec::new()),
            errors: AtomicUsize::new(0),
            tokens: AtomicU64::new(0),
            tool_calls: AtomicU64::new(0),
            quorum: QuorumGroups::new(early_stop_quorum),
        }
    }

    /// Fold one settled agent's outcome and metrics into the run totals. Every finish event already
    /// carries them; without this they were reported per row and never summed for the run.
    fn observe(&self, state: WorkflowState, tokens: u64, tool_calls: u64) {
        if state == WorkflowState::Error {
            self.errors.fetch_add(1, Ordering::Relaxed);
        }
        self.tokens.fetch_add(tokens, Ordering::Relaxed);
        self.tool_calls.fetch_add(tool_calls, Ordering::Relaxed);
    }

    /// `(errors, tokens, tool_calls)` accumulated across every agent this run settled (cache
    /// replays included — a replayed outcome is still part of the run's result evidence).
    pub fn totals(&self) -> (usize, u64, u64) {
        (
            self.errors.load(Ordering::Relaxed),
            self.tokens.load(Ordering::Relaxed),
            self.tool_calls.load(Ordering::Relaxed),
        )
    }

    /// 1-based declaration-order index, assigned synchronously at `__agent` call time.
    fn next_index(&self) -> usize {
        self.index.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Admit one real child spawn. Journal hits do not consume the aggregate ceiling; every schema
    /// retry does. The compare-and-update keeps concurrent callers from overshooting it.
    fn admit_agent_call(&self) -> bool {
        self.agent_calls
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |calls| {
                (calls < self.max_agent_calls).then_some(calls + 1)
            })
            .is_ok()
    }

    fn begin_quorum(&self, parent: &CancellationToken, members: usize) -> u64 {
        self.quorum.begin(parent, members)
    }

    fn quorum_token(&self, group_id: Option<u64>) -> Option<CancellationToken> {
        self.quorum.token(group_id)
    }

    fn observe_quorum(&self, group_id: Option<u64>, role: &str, evidence: bool) {
        self.quorum.observe(group_id, role, evidence);
    }

    fn end_quorum(&self, group_id: u64) {
        self.quorum.end(group_id);
    }

    /// 1-based first-seen phase index.
    fn phase_index(&self, title: &str) -> usize {
        let mut phases = self.phases.lock().unwrap();
        if let Some(pos) = phases.iter().position(|p| p == title) {
            return pos + 1;
        }
        phases.push(title.to_string());
        phases.len()
    }
}

impl Default for RunState {
    fn default() -> Self {
        Self::new(LIFETIME_CAP, crate::EarlyStopQuorumPolicy::default())
    }
}

/// Everything a live `__agent` call needs, shared by `Arc` across the host closures.
#[derive(Clone)]
pub struct AgentEnv {
    pub state: Arc<RunState>,
    pub spawner: Arc<dyn AgentSpawner>,
    pub sink: Arc<dyn ProgressSink>,
    pub gov: Governor,
    pub cancel: CancellationToken,
    pub journal: Arc<Journal>,
    pub task_dag: Arc<ExecutionLedger>,
    pub speculative_siblings: crate::SpeculativeSiblingPolicy,
    pub task_retry: crate::TaskRetryPolicy,
    pub schema_retry: crate::SchemaRetryPolicy,
}

// ---- JS <-> Rust envelopes -----------------------------------------------------------------------

/// The prelude's `agent()` parses one of these. `ok:false` -> JS `null`; `kind:"structured"` ->
/// return `value` (an object) directly; `kind:"text"` -> return the string.
fn text_envelope(text: &str) -> String {
    serde_json::json!({ "ok": true, "kind": "text", "text": text }).to_string()
}
fn structured_envelope(value: &Value) -> String {
    serde_json::json!({ "ok": true, "kind": "structured", "value": value }).to_string()
}
fn null_envelope(reason: &str) -> String {
    serde_json::json!({ "ok": false, "kind": "null", "reason": reason }).to_string()
}

/// The envelope + progress state for a replayed/finished [`Record`].
fn envelope_for(record: &Record) -> String {
    match &record.outcome {
        Outcome::Structured { value } => structured_envelope(value),
        Outcome::Text { text } => text_envelope(text),
        Outcome::Null { reason } => null_envelope(reason.as_deref().unwrap_or("null")),
        Outcome::Unknown => null_envelope("unknown journal outcome"),
    }
}

/// The wire shape the prelude's `agent()` marshals into `__agent`.
#[derive(serde::Deserialize)]
struct RawCall {
    prompt: String,
    label: Option<String>,
    phase: Option<String>,
    model: Option<String>,
    effort: Option<String>,
    #[serde(rename = "agentType")]
    agent_type: Option<String>,
    #[serde(default)]
    schema: Option<Value>,
    #[serde(default, rename = "quorumGroup")]
    quorum_group: Option<u64>,
    #[serde(default, rename = "speculativeSiblings")]
    speculative_siblings: Option<usize>,
    #[serde(default, rename = "dependsOn")]
    depends_on: Option<Vec<usize>>,
}

/// A short human label for the progress row when the caller gave none: the prompt's first words.
fn label_for(prompt: &str, idx: usize) -> String {
    let trimmed = prompt.trim();
    if trimmed.is_empty() {
        return format!("agent {idx}");
    }
    truncate_preview(trimmed, 40)
}

/// Keep a refused call identifiable without allowing its label to become a multi-line or terminal
/// control surface. Empty labels fall back to the same prompt-derived identity as admitted calls.
fn refusal_label(label: Option<&str>, prompt: &str, idx: usize) -> String {
    label
        .map(|label| truncate_preview(label, 40))
        .filter(|label| !label.is_empty())
        .unwrap_or_else(|| label_for(prompt, idx))
}

/// A requested model id is untrusted routing metadata and may itself be credential-shaped. The
/// engine cannot prove the selected route (that belongs to the spawner), so progress reports only
/// the presence of an override and never reflects the raw id to a terminal sink.
fn progress_model(model: Option<&str>) -> Option<String> {
    model.map(|_| "requested model override".to_string())
}

/// Emit a finished row derived from a [`Record`] (used by both the live path and cache replay).
fn emit_finished(env: &AgentEnv, idx: usize, label: String, record: &Record, duration_ms: u64) {
    let (state, result_preview, error) = match &record.outcome {
        Outcome::Structured { value } => (
            WorkflowState::Done,
            Some(truncate_preview(&value.to_string(), PREVIEW_MAX)),
            None,
        ),
        Outcome::Text { text } => (
            WorkflowState::Done,
            Some(truncate_preview(text, PREVIEW_MAX)),
            None,
        ),
        Outcome::Null { reason } => (
            WorkflowState::Error,
            None,
            Some(
                reason
                    .clone()
                    .unwrap_or_else(|| "agent returned null".into()),
            ),
        ),
        Outcome::Unknown => (
            WorkflowState::Error,
            None,
            Some("unknown journal outcome".into()),
        ),
    };
    env.state.observe(state, record.tokens, record.tool_calls);
    env.sink.emit(ProgressEvent::AgentFinished {
        index: idx,
        label,
        state,
        tokens: record.tokens,
        tool_calls: record.tool_calls,
        duration_ms,
        result_preview,
        last_tool_summary: record
            .last_tool_summary
            .as_deref()
            .map(|s| truncate_preview(s, TOOL_SUMMARY_MAX)),
        error,
    });
}

/// Terminalize a request-metadata refusal without acquiring a Governor permit or calling the
/// spawner. Negative outcomes remain journaled for deterministic resume. The record reflects no
/// rejected routing metadata: it carries one static bounded reason. The progress row retains the
/// separately-sanitized display label so the operator can identify which agent was refused.
async fn settle_metadata_refusal(
    env: &AgentEnv,
    idx: usize,
    task: TaskId,
    label: String,
    key: &str,
    reason: &'static str,
    journal_miss: bool,
) -> String {
    env.sink.emit(ProgressEvent::AgentQueued {
        index: idx,
        label: label.clone(),
        phase: None,
        model: None,
    });
    let record = Record::null(Some(reason.to_owned()));
    if journal_miss
        && env
            .journal
            .record(key, &cachekey::agent_id(key), record.clone())
            .is_err()
    {
        env.sink.emit(ProgressEvent::Log {
            message: "workflow: journal durability failed".into(),
        });
        env.cancel.cancel();
        let _ = env
            .task_dag
            .finish_task_failure(
                task,
                "journal_durability_failed",
                "journal durability failed",
            )
            .await;
        return null_envelope("journal durability failed");
    }
    if env
        .task_dag
        .finish_task_failure(task, "invalid_request_metadata", reason)
        .await
        .is_err()
    {
        env.cancel.cancel();
        return null_envelope("task DAG durability failed");
    }
    emit_finished(env, idx, label, &record, 0);
    null_envelope(reason)
}

#[derive(Debug)]
enum AttemptExecution {
    Settled(AgentOutcome),
    Failed(String),
    UnknownEffect(String),
}

#[derive(Debug)]
struct AttemptRun {
    id: AttemptId,
    elapsed_ms: u64,
    execution: AttemptExecution,
}

#[derive(Debug, Clone)]
struct AttemptLineage {
    assignment: AttemptAssignment,
    retry_of: Option<AttemptId>,
    retry_cause: Option<AttemptRetryCause>,
}

impl AttemptLineage {
    fn initial() -> Self {
        Self {
            assignment: AttemptAssignment::Initial,
            retry_of: None,
            retry_cause: None,
        }
    }

    fn retry(
        assignment: AttemptAssignment,
        retry_of: AttemptId,
        retry_cause: AttemptRetryCause,
    ) -> Self {
        debug_assert!(assignment != AttemptAssignment::Initial);
        Self {
            assignment,
            retry_of: Some(retry_of),
            retry_cause: Some(retry_cause),
        }
    }
}

#[derive(Debug)]
struct CandidateSelection {
    outcome: AgentOutcome,
    evidence_attempt: AttemptId,
    retry_cause: Option<AttemptRetryCause>,
}

/// Reserve one physical-dispatch identity before its external effect begins. A pre-dispatch ceiling
/// refusal creates no attempt because no child effect crossed the broker boundary.
async fn prepare_attempt(
    env: &AgentEnv,
    task: TaskId,
    call: &AgentCall,
    retry_ordinal: usize,
    sibling_ordinal: usize,
    lineage: &AttemptLineage,
) -> Result<AttemptId, String> {
    if !env.state.admit_agent_call() {
        return Err(format!(
            "agent call ceiling {} reached",
            env.state.max_agent_calls
        ));
    }
    let input_digest = digest_bytes(call.prompt.as_bytes());
    env.task_dag
        .begin_attempt(
            task,
            retry_ordinal,
            sibling_ordinal,
            lineage.assignment,
            lineage.retry_of,
            lineage.retry_cause,
            &input_digest,
        )
        .await
}

/// Run one already-journaled SEND child. Cancellation first asks the spawner to settle through its
/// token; only an elapsed cleanup bound aborts the exact task handle and records UnknownEffect.
async fn spawn_child(
    env: &AgentEnv,
    call: &AgentCall,
    idx: usize,
    attempt_id: AttemptId,
) -> AttemptRun {
    let spawner = env.spawner.clone();
    let call = call.clone();
    let call_cancel = call.cancel.clone();
    let (activity, activity_rx) = AgentActivityReporter::channel();
    let mut child = tokio::spawn(async move { spawner.spawn_with_activity(call, activity).await });
    let started = Instant::now();
    let mut interval = tokio::time::interval_at(
        tokio::time::Instant::now() + AGENT_ACTIVITY_INTERVAL,
        AGENT_ACTIVITY_INTERVAL,
    );
    let mut last_emitted = None;
    loop {
        tokio::select! {
            biased;
            _ = call_cancel.cancelled() => {
                let execution = match tokio::time::timeout(
                    env.speculative_siblings.cleanup_timeout(),
                    &mut child,
                ).await {
                    Ok(Ok(outcome)) => AttemptExecution::Settled(outcome),
                    Ok(Err(error)) => AttemptExecution::Failed(format!("agent task failed: {error}")),
                    Err(_) => {
                        child.abort();
                        let _ = child.await;
                        AttemptExecution::UnknownEffect(
                            "child did not acknowledge cancellation before cleanup deadline".into(),
                        )
                    }
                };
                return AttemptRun {
                    id: attempt_id,
                    elapsed_ms: started.elapsed().as_millis() as u64,
                    execution,
                };
            }
            res = &mut child => {
                let execution = match res {
                    Ok(outcome) => AttemptExecution::Settled(outcome),
                    Err(error) => AttemptExecution::Failed(format!("agent task failed: {error}")),
                };
                return AttemptRun {
                    id: attempt_id,
                    elapsed_ms: started.elapsed().as_millis() as u64,
                    execution,
                };
            }
            _ = interval.tick() => {
                let latest = activity_rx.borrow().clone();
                if latest.is_some() && latest != last_emitted {
                    let snapshot = latest.clone().expect("checked as some");
                    env.sink.emit(ProgressEvent::AgentActivity {
                        index: idx,
                        tokens: snapshot.tokens,
                        tool_calls: snapshot.tool_calls,
                        last_tool_summary: snapshot.last_tool_summary,
                    });
                    last_emitted = latest;
                }
            }
        }
    }
}

/// Run one explicit read-only speculative group and return the first positive terminal. Every
/// loser receives a sibling-only cancellation token; cleanup is joined for a finite policy-owned
/// interval before any task is aborted as an exact-handle backstop.
async fn spawn_candidate(
    env: &AgentEnv,
    call: &AgentCall,
    idx: usize,
    task: TaskId,
    retry_ordinal: usize,
    speculative_siblings: usize,
    lineage: &AttemptLineage,
) -> Result<CandidateSelection, String> {
    if speculative_siblings == 0 {
        let attempt = prepare_attempt(env, task, call, retry_ordinal, 0, lineage).await?;
        let run = spawn_child(env, call, idx, attempt).await;
        return settle_sole_attempt(env, task, run).await;
    }
    if env.spawner.execution_class(call) != crate::AgentExecutionClass::ReadOnly {
        return Err(
            "speculative siblings are read-only; isolated writer authority cannot be duplicated"
                .into(),
        );
    }

    let group = call.cancel.child_token();
    let mut tasks = tokio::task::JoinSet::new();
    let mut pending = std::collections::BTreeSet::new();
    let mut first_negative: Option<(AgentOutcome, AttemptId, AttemptRetryCause)> = None;
    let mut first_refusal = None;
    for sibling_ordinal in 0..=speculative_siblings {
        let attempt =
            match prepare_attempt(env, task, call, retry_ordinal, sibling_ordinal, lineage).await {
                Ok(attempt) => attempt,
                Err(reason) => {
                    first_refusal.get_or_insert(reason);
                    continue;
                }
            };
        pending.insert(attempt);
        let env = env.clone();
        let mut sibling = call.clone();
        sibling.cancel = group.child_token();
        tasks.spawn(async move { (attempt, spawn_child(&env, &sibling, idx, attempt).await) });
    }

    let mut runs = Vec::new();
    let mut winner_id = None;
    let mut winner_outcome = None;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok((attempt, run)) => {
                pending.remove(&attempt);
                let positive = match &run.execution {
                    AttemptExecution::Settled(outcome @ AgentOutcome::Text { text, .. })
                        if winner_id.is_none() =>
                    {
                        Some((outcome.clone(), digest_bytes(text.as_bytes())))
                    }
                    _ => None,
                };
                if let Some((outcome, result_digest)) = positive {
                    winner_id = Some(run.id);
                    winner_outcome = Some(outcome);
                    match env
                        .task_dag
                        .record_speculative_winner(task, run.id, &result_digest)
                        .await
                    {
                        Ok(()) if env.speculative_siblings.cancel_losers() => group.cancel(),
                        Ok(()) => {}
                        Err(error) => env.sink.emit(ProgressEvent::Log {
                            message: format!(
                                "workflow: speculative winner receipt unavailable; siblings were not cancelled early: {error}"
                            ),
                        }),
                    }
                }
                if let AttemptExecution::Settled(AgentOutcome::Null { reason }) = &run.execution {
                    first_negative.get_or_insert_with(|| {
                        (
                            AgentOutcome::Null {
                                reason: reason.clone(),
                            },
                            run.id,
                            AttemptRetryCause::NegativeTerminal,
                        )
                    });
                } else if let AttemptExecution::Failed(reason) = &run.execution {
                    first_negative.get_or_insert_with(|| {
                        (
                            AgentOutcome::null(reason.clone()),
                            run.id,
                            AttemptRetryCause::ChildFailure,
                        )
                    });
                }
                runs.push(run);
            }
            Err(error) => {
                first_refusal
                    .get_or_insert_with(|| format!("agent task failed without identity: {error}"));
            }
        }
    }

    // A JoinSet panic/abort loses its returned identity, but not the controller's pre-dispatch WAL.
    // Those exact ids are terminalized as unknown and the selected result is refused below.
    for attempt in pending {
        runs.push(AttemptRun {
            id: attempt,
            elapsed_ms: 0,
            execution: AttemptExecution::UnknownEffect(
                "attempt task ended without a reconciliation receipt".into(),
            ),
        });
    }

    let mut unknown = false;
    for run in runs {
        let is_winner = winner_id == Some(run.id);
        match settle_group_attempt(env, task, run, is_winner, winner_id.is_some()).await {
            Ok(run_unknown) => unknown |= run_unknown,
            Err(error) => {
                env.cancel.cancel();
                return Err(format!("task DAG durability failed: {error}"));
            }
        }
    }
    if unknown {
        return Err(
            "speculative sibling effect outcome is unknown; selected result refused".into(),
        );
    }
    if let (Some(outcome), Some(evidence_attempt)) = (winner_outcome, winner_id) {
        return Ok(CandidateSelection {
            outcome,
            evidence_attempt,
            retry_cause: None,
        });
    }
    if let Some((outcome, evidence_attempt, retry_cause)) = first_negative {
        return Ok(CandidateSelection {
            outcome,
            evidence_attempt,
            retry_cause: Some(retry_cause),
        });
    }
    Err(first_refusal.unwrap_or_else(|| "speculative group produced no terminal".into()))
}

async fn settle_sole_attempt(
    env: &AgentEnv,
    task: TaskId,
    run: AttemptRun,
) -> Result<CandidateSelection, String> {
    let AttemptRun {
        id,
        elapsed_ms,
        execution,
    } = run;
    match execution {
        AttemptExecution::Settled(AgentOutcome::Text {
            text,
            tokens,
            tool_calls,
            last_tool_summary,
        }) => {
            env.task_dag
                .finish_attempt(
                    task,
                    id,
                    tokens,
                    elapsed_ms,
                    AttemptTerminal::Succeeded {
                        result_digest: digest_bytes(text.as_bytes()),
                        disposition: AttemptDisposition::Sole,
                    },
                )
                .await?;
            Ok(CandidateSelection {
                outcome: AgentOutcome::Text {
                    text,
                    tokens,
                    tool_calls,
                    last_tool_summary,
                },
                evidence_attempt: id,
                retry_cause: None,
            })
        }
        AttemptExecution::Settled(AgentOutcome::Null { reason }) => {
            env.task_dag
                .finish_attempt(
                    task,
                    id,
                    0,
                    elapsed_ms,
                    AttemptTerminal::Failed {
                        code: "negative_terminal",
                        detail: reason
                            .clone()
                            .unwrap_or_else(|| "agent returned null".into()),
                        disposition: AttemptDisposition::Negative,
                    },
                )
                .await?;
            Ok(CandidateSelection {
                outcome: AgentOutcome::Null { reason },
                evidence_attempt: id,
                retry_cause: Some(AttemptRetryCause::NegativeTerminal),
            })
        }
        AttemptExecution::Failed(reason) => {
            env.task_dag
                .finish_attempt(
                    task,
                    id,
                    0,
                    elapsed_ms,
                    AttemptTerminal::Failed {
                        code: "child_task_failed",
                        detail: reason.clone(),
                        disposition: AttemptDisposition::Negative,
                    },
                )
                .await?;
            Ok(CandidateSelection {
                outcome: AgentOutcome::null(reason),
                evidence_attempt: id,
                retry_cause: Some(AttemptRetryCause::ChildFailure),
            })
        }
        AttemptExecution::UnknownEffect(reason) => {
            env.task_dag
                .finish_attempt(
                    task,
                    id,
                    0,
                    elapsed_ms,
                    AttemptTerminal::UnknownEffect {
                        reason: reason.clone(),
                    },
                )
                .await?;
            Err(format!("unknown child effect: {reason}"))
        }
    }
}

async fn settle_group_attempt(
    env: &AgentEnv,
    task: TaskId,
    run: AttemptRun,
    winner: bool,
    group_has_winner: bool,
) -> Result<bool, String> {
    let AttemptRun {
        id,
        elapsed_ms,
        execution,
    } = run;
    match execution {
        AttemptExecution::Settled(AgentOutcome::Text { text, tokens, .. }) => {
            env.task_dag
                .finish_attempt(
                    task,
                    id,
                    tokens,
                    elapsed_ms,
                    AttemptTerminal::Succeeded {
                        result_digest: digest_bytes(text.as_bytes()),
                        disposition: if winner {
                            AttemptDisposition::Winner
                        } else {
                            AttemptDisposition::Loser
                        },
                    },
                )
                .await?;
            Ok(false)
        }
        AttemptExecution::Settled(AgentOutcome::Null { reason }) => {
            env.task_dag
                .finish_attempt(
                    task,
                    id,
                    0,
                    elapsed_ms,
                    AttemptTerminal::Failed {
                        code: "negative_terminal",
                        detail: reason.unwrap_or_else(|| "agent returned null".into()),
                        disposition: if group_has_winner {
                            AttemptDisposition::Loser
                        } else {
                            AttemptDisposition::Negative
                        },
                    },
                )
                .await?;
            Ok(false)
        }
        AttemptExecution::Failed(reason) => {
            env.task_dag
                .finish_attempt(
                    task,
                    id,
                    0,
                    elapsed_ms,
                    AttemptTerminal::Failed {
                        code: "child_task_failed",
                        detail: reason,
                        disposition: if group_has_winner {
                            AttemptDisposition::Loser
                        } else {
                            AttemptDisposition::Negative
                        },
                    },
                )
                .await?;
            Ok(false)
        }
        AttemptExecution::UnknownEffect(reason) => {
            env.task_dag
                .finish_attempt(
                    task,
                    id,
                    0,
                    elapsed_ms,
                    AttemptTerminal::UnknownEffect { reason },
                )
                .await?;
            Ok(true)
        }
    }
}

async fn finish_task_for_record(
    env: &AgentEnv,
    task: TaskId,
    record: &Record,
) -> Result<(), String> {
    match &record.outcome {
        Outcome::Text { .. } | Outcome::Structured { .. } => {
            let encoded = serde_json::to_vec(record)
                .map_err(|error| format!("record digest serialization failed: {error}"))?;
            env.task_dag
                .finish_task_success(task, digest_bytes(&encoded))
                .await
        }
        Outcome::Null { reason } => {
            env.task_dag
                .finish_task_failure(
                    task,
                    "negative_terminal",
                    reason.as_deref().unwrap_or("agent returned null"),
                )
                .await
        }
        Outcome::Unknown => {
            env.task_dag
                .finish_task_failure(task, "unknown_journal_outcome", "unknown journal outcome")
                .await
        }
    }
}

/// The no-schema path: one child call -> a `Text`/`Null` record + its envelope.
async fn run_plain(
    env: &AgentEnv,
    call: &AgentCall,
    idx: usize,
    task: TaskId,
    speculative_siblings: usize,
) -> (Record, String) {
    let attempts = env.task_retry.max_attempts().max(1);
    let mut assigned = call.clone();
    let mut lineage = AttemptLineage::initial();
    for attempt in 0..attempts {
        match spawn_candidate(
            env,
            &assigned,
            idx,
            task,
            attempt,
            speculative_siblings,
            &lineage,
        )
        .await
        {
            Ok(CandidateSelection {
                outcome:
                    AgentOutcome::Text {
                        text,
                        tokens,
                        tool_calls,
                        last_tool_summary,
                    },
                ..
            }) => {
                let record = Record::text(text.clone(), tokens, tool_calls, last_tool_summary);
                let envelope = text_envelope(&text);
                return (record, envelope);
            }
            Ok(CandidateSelection {
                outcome: AgentOutcome::Null { reason },
                evidence_attempt,
                retry_cause,
            }) => {
                let exhausted = attempt + 1 >= attempts
                    || env.task_retry.on_failure() == crate::TaskFailureAction::Stop;
                if exhausted {
                    let envelope = null_envelope(reason.as_deref().unwrap_or("null"));
                    return (Record::null(reason), envelope);
                }
                let evidence = reason
                    .as_deref()
                    .map(|value| truncate_preview(value, 512))
                    .unwrap_or_else(|| "definite negative terminal".into());
                let assignment = match env.task_retry.on_failure() {
                    crate::TaskFailureAction::RetrySame => AttemptAssignment::RetrySame,
                    crate::TaskFailureAction::Reassign => AttemptAssignment::Reassigned,
                    crate::TaskFailureAction::Stop => unreachable!("handled as exhausted"),
                };
                let retry_cause = retry_cause
                    .expect("a definite negative candidate must retain its durable terminal cause");
                lineage = AttemptLineage::retry(assignment, evidence_attempt, retry_cause);
                if env.task_retry.on_failure() == crate::TaskFailureAction::Reassign
                    && env.task_retry.preserve_evidence()
                {
                    assigned.prompt = format!(
                        "{}\n\nA prior read-only assignee ended without usable evidence: {}\nIndependently complete the original task.",
                        call.prompt, evidence
                    );
                }
            }
            Err(reason) => {
                let envelope = null_envelope(&reason);
                return (Record::null(Some(reason)), envelope);
            }
        }
    }
    let reason = "task retry policy exhausted without a terminal";
    (Record::null(Some(reason.into())), null_envelope(reason))
}

/// The schema-forced path (design §2.5): parse+validate the output; on failure re-call the spawner
/// with the errors appended, up to the pinned attempt ceiling (spaced by full-jitter backoff); return the
/// validated object as a `Structured` record, or `Null` on exhaustion / a degraded child.
async fn run_with_schema(
    env: &AgentEnv,
    base_call: &AgentCall,
    schema_value: &Value,
    idx: usize,
    task: TaskId,
    speculative_siblings: usize,
) -> (Record, String) {
    let validator = match SchemaValidator::compile(schema_value) {
        Ok(v) => v,
        Err(error) => {
            let reason = format!("invalid schema: {error}");
            env.sink.emit(ProgressEvent::Log {
                message: format!("workflow: agent #{idx} {reason}"),
            });
            let envelope = null_envelope(&reason);
            return (Record::null(Some(reason)), envelope);
        }
    };

    let policy = env.schema_retry.backoff();
    let mut jitter = Jitter::new();
    let mut last_errors: Vec<String> = Vec::new();
    let mut lineage = AttemptLineage::initial();

    for attempt in 0..env.schema_retry.max_attempts() {
        let mut call = base_call.clone();
        if attempt > 0 {
            call.prompt = schema::augment_prompt(&base_call.prompt, &last_errors);
            let delay = full_jitter(&policy, attempt - 1, jitter.next01());
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
        }
        match spawn_candidate(
            env,
            &call,
            idx,
            task,
            attempt as usize,
            speculative_siblings,
            &lineage,
        )
        .await
        {
            Ok(CandidateSelection {
                outcome:
                    AgentOutcome::Text {
                        text,
                        tokens,
                        tool_calls,
                        ..
                    },
                evidence_attempt,
                ..
            }) => {
                match schema::parse_json(&text) {
                    Ok(value) => match validator.validate(&value) {
                        Ok(()) => {
                            let record = Record::structured(value.clone(), tokens, tool_calls);
                            let envelope = structured_envelope(&value);
                            return (record, envelope);
                        }
                        Err(errors) => last_errors = errors,
                    },
                    Err(parse_error) => last_errors = vec![parse_error],
                }
                lineage = AttemptLineage::retry(
                    AttemptAssignment::RetrySame,
                    evidence_attempt,
                    AttemptRetryCause::SchemaValidation,
                );
            }
            // A degraded child or a cancel is terminal: no point retrying a deterministic null.
            Ok(CandidateSelection {
                outcome: AgentOutcome::Null { reason },
                ..
            }) => {
                let envelope = null_envelope(reason.as_deref().unwrap_or("null"));
                return (Record::null(reason), envelope);
            }
            Err(reason) => {
                let envelope = null_envelope(&reason);
                return (Record::null(Some(reason)), envelope);
            }
        }
    }

    let reason = format!(
        "schema validation failed after {} attempts",
        env.schema_retry.max_attempts()
    );
    env.sink.emit(ProgressEvent::Log {
        message: format!("workflow: agent #{idx} {reason}"),
    });
    let envelope = null_envelope(&reason);
    (Record::null(Some(reason)), envelope)
}

/// The `__agent` body: cache short-circuit -> lifetime cap -> permit -> live run -> journal.
async fn run_agent(env: Arc<AgentEnv>, idx: usize, arg: String) -> String {
    let raw: RawCall = match serde_json::from_str(&arg) {
        Ok(call) => call,
        Err(_) => {
            let input_digest = digest_bytes(arg.as_bytes());
            let task = match env.task_dag.begin_task(idx, &input_digest, &[]).await {
                Ok(TaskAdmission::Ready(task)) => task,
                Ok(TaskAdmission::SkippedDependency { .. }) => {
                    unreachable!("a dependency-free task cannot be skipped")
                }
                Err(error) => {
                    env.sink.emit(ProgressEvent::Log {
                        message: format!("workflow: task DAG admission failed: {error}"),
                    });
                    env.cancel.cancel();
                    return null_envelope("task DAG admission failed");
                }
            };
            if env
                .task_dag
                .finish_task_failure(task, "malformed_agent_call", "malformed agent call")
                .await
                .is_err()
            {
                env.cancel.cancel();
                return null_envelope("task DAG durability failed");
            }
            return null_envelope("malformed agent() call");
        }
    };
    let dependencies = raw.depends_on.as_deref().unwrap_or(&[]);

    // Validate routing metadata before catalog lookup, rollout creation, provider dispatch, or a
    // Governor permit. The error type contains no caller text, so the same static reason is safe in
    // the envelope, progress row, and durable negative journal record.
    let metadata = AgentCall::validate_agent_type(raw.agent_type.as_deref())
        .and_then(|()| AgentCall::validate_model(raw.model.as_deref()));

    // --- content key over the CALLER's raw input (deterministic; §2.6) --------------------------
    let key = match metadata {
        Ok(()) => cachekey::agent_key_with_execution(
            &raw.prompt,
            raw.label.as_deref(),
            raw.phase.as_deref(),
            raw.schema.as_ref(),
            raw.model.as_deref(),
            raw.effort.as_deref(),
            raw.agent_type.as_deref(),
            raw.speculative_siblings,
            Some(dependencies),
        ),
        Err(error) => cachekey::rejected_agent_key(&arg, error.code()),
    };
    let input_digest = digest_bytes(arg.as_bytes());
    let task = match env
        .task_dag
        .begin_task(idx, &input_digest, dependencies)
        .await
    {
        Ok(TaskAdmission::Ready(task)) => task,
        Ok(TaskAdmission::SkippedDependency { task, dependency }) => {
            let reason = format!(
                "dependency task {} did not succeed; dependent task {task:?} was skipped",
                dependency.0
            );
            let record = Record::null(Some(reason.clone()));
            if env
                .journal
                .record(&key, &cachekey::agent_id(&key), record.clone())
                .is_err()
            {
                env.cancel.cancel();
                return null_envelope("journal durability failed");
            }
            let label = raw
                .label
                .clone()
                .unwrap_or_else(|| label_for(&raw.prompt, idx));
            emit_finished(&env, idx, label, &record, 0);
            return null_envelope(&reason);
        }
        Err(error) => {
            env.sink.emit(ProgressEvent::Log {
                message: format!("workflow: task DAG admission failed: {error}"),
            });
            env.cancel.cancel();
            return null_envelope("task DAG admission failed");
        }
    };
    let speculative_siblings = raw.speculative_siblings.unwrap_or(0);
    if speculative_siblings > env.speculative_siblings.max_siblings() {
        if env
            .task_dag
            .finish_task_failure(
                task,
                "speculative_sibling_ceiling",
                "speculative sibling request exceeds the host ceiling",
            )
            .await
            .is_err()
        {
            env.cancel.cancel();
            return null_envelope("task DAG durability failed");
        }
        return null_envelope("speculative sibling request exceeds the host ceiling");
    }
    if speculative_siblings > 0 && raw.schema.is_some() {
        // The winner must be selected from verified evidence. Schema validation currently occurs
        // after the physical child settles, so duplicating this call would otherwise cancel a
        // valid sibling merely because an earlier sibling returned invalid JSON.
        if env
            .task_dag
            .finish_task_failure(
                task,
                "speculative_schema_unsupported",
                "schema-validated calls cannot use speculative siblings",
            )
            .await
            .is_err()
        {
            env.cancel.cancel();
            return null_envelope("task DAG durability failed");
        }
        return null_envelope("schema-validated calls cannot use speculative siblings");
    }

    // --- (1) JOURNAL HIT — before Governor / budget / lifetime cap (B2 invariant) ---------------
    if let Some(record) = env.journal.get(&key) {
        if let Err(error) = metadata {
            // Ignore the stored prose for a rejected request. Core wrote the same static outcome,
            // but reconstructing it from the validator also stays safe if a journal was replaced.
            let label = refusal_label(raw.label.as_deref(), &raw.prompt, idx);
            let envelope =
                settle_metadata_refusal(&env, idx, task, label, &key, error.public_reason(), false)
                    .await;
            env.state.observe_quorum(
                raw.quorum_group,
                raw.agent_type.as_deref().unwrap_or("generic"),
                false,
            );
            return envelope;
        }
        let label = raw
            .label
            .clone()
            .unwrap_or_else(|| label_for(&raw.prompt, idx));
        env.sink.emit(ProgressEvent::AgentStarted {
            index: idx,
            label: label.clone(),
            phase: raw.phase.clone(),
            model: progress_model(raw.model.as_deref()),
        });
        if finish_task_for_record(&env, task, &record).await.is_err() {
            env.cancel.cancel();
            return null_envelope("task DAG durability failed");
        }
        emit_finished(&env, idx, label, &record, 0);
        env.state.observe_quorum(
            raw.quorum_group,
            raw.agent_type.as_deref().unwrap_or("generic"),
            matches!(
                &record.outcome,
                Outcome::Text { .. } | Outcome::Structured { .. }
            ),
        );
        return envelope_for(&record);
    }

    if let Err(error) = metadata {
        let label = refusal_label(raw.label.as_deref(), &raw.prompt, idx);
        let envelope =
            settle_metadata_refusal(&env, idx, task, label, &key, error.public_reason(), true)
                .await;
        env.state.observe_quorum(
            raw.quorum_group,
            raw.agent_type.as_deref().unwrap_or("generic"),
            false,
        );
        return envelope;
    }

    let label = raw
        .label
        .clone()
        .unwrap_or_else(|| label_for(&raw.prompt, idx));

    // --- (2) build the bounded live call ---------------------------------------------------------
    let call = AgentCall {
        prompt: raw.prompt.clone(),
        label: Some(label.clone()),
        phase: raw.phase.clone(),
        model: raw.model.clone(),
        effort: raw
            .effort
            .as_deref()
            .and_then(iteron_protocol::Effort::parse),
        agent_type: raw.agent_type.clone(),
        schema: raw.schema.clone(),
        cancel: env
            .state
            .quorum_token(raw.quorum_group)
            .unwrap_or_else(|| env.cancel.child_token()),
    };

    // --- (3) Governor permit — the one global slot pool, held for the whole call ----------------
    // The queued row is emitted BEFORE the permit is requested. `parallel()` marshals every
    // `agent()` call up front, so the whole fan appears at once and the run's denominator is fixed
    // from the first frame; emitting only on admission made the total climb as slots freed up.
    env.sink.emit(ProgressEvent::AgentQueued {
        index: idx,
        label: label.clone(),
        phase: raw.phase.clone(),
        model: progress_model(raw.model.as_deref()),
    });
    let permit = tokio::select! {
        biased;
        _ = call.cancel.cancelled() => {
            let record = Record::null(Some("quorum reached".into()));
            if env.journal.record(&key, &cachekey::agent_id(&key), record.clone()).is_err() {
                env.cancel.cancel();
                return null_envelope("journal durability failed");
            }
            if finish_task_for_record(&env, task, &record).await.is_err() {
                env.cancel.cancel();
                return null_envelope("task DAG durability failed");
            }
            emit_finished(&env, idx, label, &record, 0);
            return null_envelope("quorum reached");
        }
        permit = env.gov.acquire() => permit,
    };
    let started = Instant::now();
    env.sink.emit(ProgressEvent::AgentStarted {
        index: idx,
        label: label.clone(),
        phase: raw.phase.clone(),
        model: progress_model(raw.model.as_deref()),
    });

    // --- (4) run live (schema validate+retry when a schema was supplied) ------------------------
    let (record, envelope) = match &raw.schema {
        Some(schema_value) => {
            run_with_schema(&env, &call, schema_value, idx, task, speculative_siblings).await
        }
        None => run_plain(&env, &call, idx, task, speculative_siblings).await,
    };
    let duration_ms = started.elapsed().as_millis() as u64;

    // --- (5) journal the outcome (positive AND negative — B2) -----------------------------------
    if let Err(error) = env
        .journal
        .record(&key, &cachekey::agent_id(&key), record.clone())
    {
        env.sink.emit(ProgressEvent::Log {
            message: format!("workflow: journal durability failed: {error}"),
        });
        env.cancel.cancel();
        let _ = env
            .task_dag
            .finish_task_failure(
                task,
                "journal_durability_failed",
                "journal durability failed",
            )
            .await;
        return null_envelope("journal durability failed");
    }
    if let Err(error) = finish_task_for_record(&env, task, &record).await {
        env.sink.emit(ProgressEvent::Log {
            message: format!("workflow: task DAG durability failed: {error}"),
        });
        env.cancel.cancel();
        return null_envelope("task DAG durability failed");
    }
    emit_finished(&env, idx, label, &record, duration_ms);
    env.state.observe_quorum(
        raw.quorum_group,
        raw.agent_type.as_deref().unwrap_or("generic"),
        matches!(
            &record.outcome,
            Outcome::Text { .. } | Outcome::Structured { .. }
        ),
    );
    // Quorum cancellation is evidence-driven. Keep the scarce permit until both durable stores
    // have accepted the selected terminal and `observe_quorum` has cancelled only this sibling
    // group; otherwise a queued sibling can acquire the released slot during the fsync window and
    // dispatch after the quorum was already logically satisfied.
    drop(permit);
    envelope
}

/// Register `__agent` / `__phase` / `__log` on the context's globals. Called once per run inside the
/// `AsyncContext::async_with` closure, before the prelude + script are evaluated.
pub fn install<'js>(ctx: &Ctx<'js>, env: &Arc<AgentEnv>) -> rquickjs::Result<()> {
    let globals = ctx.globals();

    // __agent — async. The closure body runs synchronously at call time (so `next_index()` yields
    // declaration order); it then returns the future rquickjs drives.
    {
        let env = env.clone();
        let f = Function::new(
            ctx.clone(),
            Async(move |arg: String| {
                let idx = env.state.next_index();
                let env = env.clone();
                async move { run_agent(env, idx, arg).await }
            }),
        )?;
        globals.set("__agent", f)?;
    }

    {
        let env = env.clone();
        let f = Function::new(ctx.clone(), move |members: usize| -> u64 {
            env.state.begin_quorum(&env.cancel, members)
        })?;
        globals.set("__quorumBegin", f)?;
    }

    {
        let env = env.clone();
        let f = Function::new(ctx.clone(), move |group_id: u64| {
            env.state.end_quorum(group_id);
        })?;
        globals.set("__quorumEnd", f)?;
    }

    // __phase — sync, returns the 1-based first-seen index.
    {
        let env = env.clone();
        let f = Function::new(ctx.clone(), move |title: String| -> i32 {
            let index = env.state.phase_index(&title);
            env.sink.emit(ProgressEvent::Phase { index, title });
            index as i32
        })?;
        globals.set("__phase", f)?;
    }

    // __log — sync narrator.
    {
        let env = env.clone();
        let f = Function::new(ctx.clone(), move |message: String| {
            env.sink.emit(ProgressEvent::Log { message });
        })?;
        globals.set("__log", f)?;
    }

    Ok(())
}
