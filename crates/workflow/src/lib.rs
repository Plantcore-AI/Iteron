//! iteron-workflow — the ultracode-workflow engine (完整复刻 of Claude Code's Workflow feature).
//!
//! It embeds QuickJS (via `rquickjs`) and runs the `.js` workflow scripts with `agent()` /
//! `parallel()` / `pipeline()` / `phase()` / `log()` as ambient globals backed by Rust. The single
//! big language decision (WORKFLOW-REPLICATION-DESIGN.md §1) is to run the scripts rather than
//! reimplement a native builder, so the on-disk scripts execute (with only the mandatory
//! `export const meta` strip + async-fn wrap, review B1).
//!
//! Boundaries this crate keeps:
//!   * It never depends on `iteron-kernel`. The real sub-agent spawn is the [`AgentSpawner`] trait the
//!     kernel/CLI implements (the seam that avoids the dependency cycle, §2.1).
//!   * Concurrency is bounded by `iteron_sched::Governor` — one global slot pool per run.
//!   * Determinism traps (Math.random / Date.now / Date() / performance.now / crypto.getRandomValues)
//!     are installed on `globalThis` before the script runs (`prelude.js`).
//!
//! Three engine-depth features complete the replication:
//!   * **Schema-forced structured output** (`schema.rs`, §2.5): `agent(prompt, {schema})` validates
//!     the model output against a JSON Schema (draft 2020-12) and retries up to 5x, returning the
//!     validated object to JS (or `null` on exhaustion).
//!   * **Journal + resume cache** (`journal.rs` + `cachekey.rs`, §2.6, review B2): every agent
//!     OUTCOME (Structured | Text | Null) is journaled by content hash and replayed on resume;
//!     `__agent` short-circuits on a journal hit BEFORE the Governor/budget/lifetime cap, so
//!     `parallel(...).filter(Boolean)` is deterministic across a resume.
//!   * **Background launch + cancellation** (`RunHandle`, review B3): [`WorkflowEngine::launch`]
//!     returns immediately; [`RunHandle::cancel`] aborts in-flight children, interrupts a sync JS
//!     loop, flushes the journal, and resolves the run as `stopped`.

mod bindings;
mod collaboration;
mod execution_policy;
mod executor;
mod host;
mod quorum;
mod runtime_identity;
mod schema_retry;

pub mod cachekey;
pub mod events;
pub mod journal;
pub mod meta;
pub mod schema;
pub mod spawner;
pub mod task_dag;

pub use bindings::LIFETIME_CAP;
pub use cachekey::{agent_id, agent_key};
pub use collaboration::{
    COLLABORATION_SLOT_VERSION, CollaborationDecision, CollaborationError,
    CollaborationObservation, CollaborationProposal, CollaborationStrategy,
};
pub use events::{
    NullSink, PREVIEW_MAX, PROGRESS_SINK_PORT_VERSION, ProgressEvent, ProgressSink,
    TOOL_SUMMARY_MAX, WorkflowState, fmt_count, fmt_duration, truncate_preview,
};
pub use execution_policy::{
    AgentMessagingTopology, CleanWriterDisposition, ConflictDisposition, MAX_SPECULATIVE_SIBLINGS,
    MAX_TASK_ATTEMPTS, ReadyTaskTieBreak, SpawnDepthControl, SpeculativeSiblingPolicy,
    SpeculativeWinnerEvidence, TaskFailureAction, TaskPrioritySchedulingPolicy, TaskRetryPolicy,
    WriterMergePolicy,
};
pub use host::validate_script;
pub use journal::{JOURNAL_FORMAT_VERSION, Journal, Outcome, Record};
pub use meta::{CompiledWorkflow, Meta, compile, extract_meta, strip_meta};
pub use quorum::{EarlyStopQuorumPolicy, MAX_EARLY_STOP_QUORUM};
pub use runtime_identity::{WorkflowGraphRuntimeIdentity, workflow_graph_runtime_identity};
pub use schema::{RETRY_MAX, SchemaValidator};
pub use schema_retry::SchemaRetryPolicy;
pub use spawner::{
    AGENT_SPAWNER_PORT_VERSION, AgentActivityReporter, AgentCall, AgentExecutionClass,
    AgentOutcome, AgentSpawner,
};

/// Default visible cleanup deadline advertised by owners of a background workflow run. The
/// engine's cancellation token is immediate; composition roots use this value only for their
/// bounded join/kill-and-reap countdown.
pub const DEFAULT_STOP_DEADLINE_MS: u64 = 2_000;

/// Resolve the operator-profiled visible cleanup deadline. Composition roots must call this
/// accessor rather than copying the compiled default so a pinned run profile is honored.
pub fn default_stop_deadline_ms() -> u64 {
    iteron_tunables::param_u64(
        "workflow.lib.default_stop_deadline_ms",
        DEFAULT_STOP_DEADLINE_MS,
    )
    .clamp(1, DEFAULT_STOP_DEADLINE_MS)
}

use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use std::sync::Arc;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

/// Provider-facing child concurrency follows the product policy, not the host's reported core
/// count. The composition root may still install a narrower immutable [`RunLimits`].
const DEFAULT_RUN_CONCURRENCY: usize = 6;

/// Clock reading used for a run id when the system clock is before the Unix epoch. Run ids are
/// metadata only, so a zero prefix is a labelling fallback, never a determinism input.
const RUN_ID_FALLBACK_NANOS: u128 = 0;

const MAX_DEFAULT_RUN_CONCURRENCY: usize = 16;
const DEFAULT_MAX_LOG_EVENTS: usize = 512;
const DEFAULT_MAX_ACTIVITY_EVENTS: usize = 4_096;
const HARD_MAX_LOG_EVENTS: usize = 4_096;
const HARD_MAX_ACTIVITY_EVENTS: usize = 16_384;

fn resolved_progress_limits() -> (usize, usize) {
    let hard_max_log_events =
        iteron_tunables::param_usize("workflow.lib.hard_max_log_events", HARD_MAX_LOG_EVENTS)
            .clamp(1, HARD_MAX_LOG_EVENTS);
    let hard_max_activity_events = iteron_tunables::param_usize(
        "workflow.lib.hard_max_activity_events",
        HARD_MAX_ACTIVITY_EVENTS,
    )
    .clamp(1, HARD_MAX_ACTIVITY_EVENTS);
    (
        iteron_tunables::param_usize(
            "workflow.lib.default_max_log_events",
            DEFAULT_MAX_LOG_EVENTS,
        )
        .clamp(1, hard_max_log_events),
        iteron_tunables::param_usize(
            "workflow.lib.default_max_activity_events",
            DEFAULT_MAX_ACTIVITY_EVENTS,
        )
        .clamp(1, hard_max_activity_events),
    )
}

/// Aggregate engine ceilings supplied by the authority-owning composition root.
///
/// Both values are non-zero and immutable. A workflow script can consume these bounds but cannot
/// widen them, and schema retries count as agent calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunLimits {
    max_concurrency: usize,
    max_agent_calls: usize,
    max_log_events: usize,
    max_activity_events: usize,
}

impl RunLimits {
    pub fn new(max_concurrency: usize, max_agent_calls: usize) -> Result<Self, &'static str> {
        if max_concurrency == 0 {
            return Err("workflow concurrency must be non-zero");
        }
        if max_agent_calls == 0 {
            return Err("workflow agent-call ceiling must be non-zero");
        }
        if max_agent_calls
            > iteron_tunables::param_usize("workflow.bindings.lifetime_cap", LIFETIME_CAP)
        {
            return Err("workflow agent-call ceiling exceeds the hard 1000-call limit");
        }
        let (max_log_events, max_activity_events) = resolved_progress_limits();
        Ok(Self {
            max_concurrency,
            max_agent_calls,
            max_log_events,
            max_activity_events,
        })
    }

    pub fn max_concurrency(self) -> usize {
        self.max_concurrency
    }

    pub fn max_agent_calls(self) -> usize {
        self.max_agent_calls
    }

    pub fn max_log_events(self) -> usize {
        self.max_log_events
    }

    pub fn max_activity_events(self) -> usize {
        self.max_activity_events
    }
}

impl Default for RunLimits {
    fn default() -> Self {
        let (max_log_events, max_activity_events) = resolved_progress_limits();
        let max_default_run_concurrency = iteron_tunables::param_usize(
            "workflow.lib.max_default_run_concurrency",
            MAX_DEFAULT_RUN_CONCURRENCY,
        )
        .clamp(1, MAX_DEFAULT_RUN_CONCURRENCY);
        Self {
            max_concurrency: iteron_tunables::param_usize(
                "workflow.lib.default_run_concurrency",
                DEFAULT_RUN_CONCURRENCY,
            )
            .clamp(1, max_default_run_concurrency),
            max_agent_calls: iteron_tunables::param_usize(
                "workflow.bindings.lifetime_cap",
                LIFETIME_CAP,
            ),
            max_log_events,
            max_activity_events,
        }
    }
}

/// A workflow run identifier. Fresh runs get a time-ordered id; resume reuses a prior one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RunId(String);

impl RunId {
    /// A unique, time-ordered id (`wf_<nanos>_<seq>`). Run ids are metadata, OUTSIDE the determinism
    /// contract (the script never sees them), so a clock read here is fine.
    pub fn generate() -> RunId {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(RUN_ID_FALLBACK_NANOS);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        RunId(format!("wf_{nanos:x}_{seq:x}"))
    }

    /// Wrap an existing id string (e.g. a resume target supplied by the CLI).
    pub fn new(id: impl Into<String>) -> RunId {
        RunId(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RunId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A fully-specified run request. Build with [`RunSpec::new`] + the builder setters, then hand it to
/// [`WorkflowEngine::execute`] (blocking) or [`WorkflowEngine::launch`] (background).
///
/// Script and argument bytes are governed by [`WORKFLOW_SUBMISSION_LIMITS_VERSION`]. The limits are
/// host ceilings rather than tunables: a profile may not enlarge the memory admitted to the shared
/// executor queue.
#[derive(Debug, Clone)]
pub struct RunSpec {
    /// The workflow script source (ESM with a leading `export const meta`).
    pub script: String,
    /// The value exposed to the script as the ambient `args` global.
    pub args: serde_json::Value,
    /// This run's id (journal directory + resume target).
    pub run_id: RunId,
    /// Base directory under which `<run_id>/journal.jsonl` and the task-DAG ledger are durably
    /// written. `None` is an invalid physical-run specification and fails before child dispatch.
    pub workflows_dir: Option<PathBuf>,
    /// A prior run's id whose `journal.jsonl` (under `workflows_dir`) seeds the resume cache.
    pub resume_from: Option<RunId>,
    /// Kernel/composition-root minted aggregate ceilings. Script input never controls this value.
    pub limits: RunLimits,
    /// Owner-minted policy used only by the opt-in `parallelQuorum(...)` DSL primitive.
    pub early_stop_quorum: EarlyStopQuorumPolicy,
    /// Host-owned ceiling and cleanup contract for explicit read-only speculative siblings.
    pub speculative_siblings: SpeculativeSiblingPolicy,
    /// Host-owned retry/reassignment policy for definite negative child terminals.
    pub task_retry: TaskRetryPolicy,
    /// Host-owned schema-repair attempt and jitter policy.  This is distinct from provider retry.
    pub schema_retry: SchemaRetryPolicy,
    /// The operator profile this run was resolved under, when the composition root supplied one.
    /// It is read for prompt-artifact replacement only (`prompt/recovery@v1`); `None` is the
    /// unprofiled run and every compiled default stands.
    pub tunables_profile: Option<Arc<iteron_tunables::ProfileDocument>>,
}

/// Stable version of the workflow submission byte-admission contract.
pub const WORKFLOW_SUBMISSION_LIMITS_VERSION: u32 = 1;

/// Immutable host-admission limits. These are one structural protocol object, not trainer
/// controls: a profile must never widen bytes admitted to the process-wide executor queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkflowSubmissionLimits {
    pub script_bytes: usize,
    pub args_bytes: usize,
    pub total_bytes: usize,
}

pub const WORKFLOW_SUBMISSION_LIMITS: WorkflowSubmissionLimits = WorkflowSubmissionLimits {
    script_bytes: 1024 * 1024,
    args_bytes: 1024 * 1024,
    total_bytes: 1536 * 1024,
};

/// The byte component that crossed the stable workflow submission ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowSubmissionComponent {
    Script,
    Args,
    Total,
}

impl std::fmt::Display for WorkflowSubmissionComponent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Script => "script",
            Self::Args => "args",
            Self::Total => "total",
        })
    }
}

/// Typed refusal returned before an oversized workflow can enter the shared executor queue.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "workflow {component} is {actual_bytes} bytes, exceeding the {limit_bytes}-byte host ceiling"
)]
pub struct WorkflowSubmissionTooLarge {
    pub component: WorkflowSubmissionComponent,
    pub actual_bytes: usize,
    pub limit_bytes: usize,
}

#[derive(Default)]
struct JsonByteCounter(usize);

impl std::io::Write for JsonByteCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl RunSpec {
    pub fn new(script: impl Into<String>) -> RunSpec {
        RunSpec {
            script: script.into(),
            args: serde_json::Value::Null,
            run_id: RunId::generate(),
            workflows_dir: None,
            resume_from: None,
            limits: RunLimits::default(),
            early_stop_quorum: EarlyStopQuorumPolicy::default(),
            speculative_siblings: SpeculativeSiblingPolicy::default(),
            task_retry: TaskRetryPolicy::default(),
            schema_retry: SchemaRetryPolicy::default(),
            tunables_profile: None,
        }
    }
    pub fn with_args(mut self, args: serde_json::Value) -> RunSpec {
        self.args = args;
        self
    }
    pub fn with_run_id(mut self, run_id: RunId) -> RunSpec {
        self.run_id = run_id;
        self
    }
    pub fn with_workflows_dir(mut self, dir: impl Into<PathBuf>) -> RunSpec {
        self.workflows_dir = Some(dir.into());
        self
    }
    pub fn with_resume_from(mut self, run_id: RunId) -> RunSpec {
        self.resume_from = Some(run_id);
        self
    }
    pub fn with_limits(mut self, limits: RunLimits) -> RunSpec {
        self.limits = limits;
        self
    }
    pub fn with_early_stop_quorum(mut self, policy: EarlyStopQuorumPolicy) -> RunSpec {
        self.early_stop_quorum = policy;
        self
    }
    pub fn with_speculative_siblings(mut self, policy: SpeculativeSiblingPolicy) -> RunSpec {
        self.speculative_siblings = policy;
        self
    }
    pub fn with_task_retry(mut self, policy: TaskRetryPolicy) -> RunSpec {
        self.task_retry = policy;
        self
    }
    pub fn with_schema_retry(mut self, policy: SchemaRetryPolicy) -> RunSpec {
        self.schema_retry = policy;
        self
    }
    /// Attach the operator profile this run was resolved under, so a prompt artifact it carries
    /// replaces the compiled text. Passing `None` leaves every compiled default in place.
    pub fn with_tunables_profile(
        mut self,
        profile: Option<Arc<iteron_tunables::ProfileDocument>>,
    ) -> RunSpec {
        self.tunables_profile = profile;
        self
    }

    fn validate_submission_size(&self) -> Result<(), WorkflowSubmissionTooLarge> {
        let script_bytes = self.script.len();
        if script_bytes > WORKFLOW_SUBMISSION_LIMITS.script_bytes {
            return Err(WorkflowSubmissionTooLarge {
                component: WorkflowSubmissionComponent::Script,
                actual_bytes: script_bytes,
                limit_bytes: WORKFLOW_SUBMISSION_LIMITS.script_bytes,
            });
        }
        // Count the wire representation without allocating a second copy of caller-controlled
        // arguments. `serde_json::Value` is structurally serializable; an unexpected encoder
        // refusal is treated as maximally large so admission still fails closed.
        let mut args_counter = JsonByteCounter::default();
        let args_bytes = serde_json::to_writer(&mut args_counter, &self.args)
            .map_or(usize::MAX, |()| args_counter.0);
        if args_bytes > WORKFLOW_SUBMISSION_LIMITS.args_bytes {
            return Err(WorkflowSubmissionTooLarge {
                component: WorkflowSubmissionComponent::Args,
                actual_bytes: args_bytes,
                limit_bytes: WORKFLOW_SUBMISSION_LIMITS.args_bytes,
            });
        }
        let total_bytes = script_bytes.saturating_add(args_bytes);
        if total_bytes > WORKFLOW_SUBMISSION_LIMITS.total_bytes {
            return Err(WorkflowSubmissionTooLarge {
                component: WorkflowSubmissionComponent::Total,
                actual_bytes: total_bytes,
                limit_bytes: WORKFLOW_SUBMISSION_LIMITS.total_bytes,
            });
        }
        Ok(())
    }
}

/// The result of a completed (or stopped) run.
#[derive(Debug, Clone)]
pub struct RunReport {
    pub run_id: RunId,
    /// The script's return value, or `null` when the run was `stopped`.
    pub value: serde_json::Value,
    /// True when the run ended via [`RunHandle::cancel`].
    pub stopped: bool,
    /// Agents replayed from the journal (resume cache hits).
    pub cache_hits: usize,
    /// Agents that ran live (cache misses).
    pub cache_misses: usize,
    /// Agents that settled with a null or otherwise unknown outcome.
    pub errors: usize,
    /// Tokens summed across every agent this run settled. Every finish event already carried this;
    /// nothing aggregated it, so a completed run reported no cost evidence at all.
    pub tokens: u64,
    /// Tool calls summed across every agent this run settled.
    pub tool_calls: u64,
    /// Wall-clock duration of the whole run.
    pub elapsed_ms: u64,
}

/// A background run. Owns the [`CancellationToken`] threaded into every `AgentCall`; [`cancel`] trips
/// it (aborting in-flight children + interrupting a sync JS loop). [`join`] awaits completion.
///
/// [`cancel`]: RunHandle::cancel
/// [`join`]: RunHandle::join
pub struct RunHandle {
    run_id: RunId,
    cancel: CancellationToken,
    result: Mutex<Option<oneshot::Receiver<anyhow::Result<RunReport>>>>,
}

/// A physical workflow may not run without a durable intent/terminal authority. This error is
/// public and downcastable so API callers can distinguish a missing durability root from script,
/// provider, or child failures without matching presentation text.
#[derive(Debug, thiserror::Error)]
#[error("physical workflow execution requires RunSpec.workflows_dir")]
pub struct WorkflowDurabilityRequired;

impl RunHandle {
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// A clone of the run's cancellation token (e.g. to hand to an external stop surface).
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Request cancellation: aborts in-flight children, interrupts a sync JS loop, flushes the
    /// journal, and resolves the run as `stopped`. Idempotent; returns immediately.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// Await the run's completion (whether it finished or was stopped). Consumes the internal
    /// receiver, so it resolves once per handle.
    pub async fn join(&self) -> anyhow::Result<RunReport> {
        let rx = self
            .result
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| anyhow::anyhow!("workflow run already joined"))?;
        rx.await
            .map_err(|_| anyhow::anyhow!("workflow executor dropped before completion"))?
    }
}

/// Resolve this run's journal (append sink + resume source) from the [`RunSpec`].
fn build_journal(spec: &RunSpec) -> anyhow::Result<Arc<Journal>> {
    let dir = spec
        .workflows_dir
        .as_ref()
        .ok_or(WorkflowDurabilityRequired)?;
    let path = dir.join(spec.run_id.as_str()).join("journal.jsonl");
    let resume = spec
        .resume_from
        .as_ref()
        .map(|prior| dir.join(prior.as_str()).join("journal.jsonl"));
    Ok(Arc::new(Journal::open(Some(path), resume)?))
}

/// The workflow runtime. Runs share one bounded process executor while retaining fresh per-run
/// QuickJS, Governor, journal, and task-ledger state.
pub struct WorkflowEngine;

impl WorkflowEngine {
    /// Legacy convenience entry point. It has no durable-root parameter and therefore refuses
    /// physical execution. Build a [`RunSpec`], attach [`RunSpec::with_workflows_dir`], and call
    /// [`WorkflowEngine::execute`] instead.
    ///
    /// Must be awaited inside a multi-thread Tokio runtime (it builds its own `LocalSet` internally).
    pub async fn run(
        script: &str,
        args: serde_json::Value,
        spawner: Arc<dyn AgentSpawner>,
        sink: Arc<dyn ProgressSink>,
    ) -> anyhow::Result<serde_json::Value> {
        let _ = (script, args, spawner, sink);
        Err(WorkflowDurabilityRequired.into())
    }

    /// Run a fully-specified [`RunSpec`] to completion (blocking as a future), returning a full
    /// [`RunReport`] (value + stopped + cache metrics). This is the journal/resume-aware path: pass a
    /// `workflows_dir` to persist, and `resume_from` to replay a prior run's cache.
    ///
    /// Awaited directly on the caller's multi-thread runtime (drives the `!Send` JS engine via an
    /// internal `LocalSet`); for background execution use [`WorkflowEngine::launch`].
    pub async fn execute(
        spec: RunSpec,
        spawner: Arc<dyn AgentSpawner>,
        sink: Arc<dyn ProgressSink>,
    ) -> anyhow::Result<RunReport> {
        if spec.workflows_dir.is_none() {
            return Err(WorkflowDurabilityRequired.into());
        }
        spec.validate_submission_size()?;
        let journal = build_journal(&spec)?;
        let task_dag = Arc::new(task_dag::runtime::ExecutionLedger::open(
            &spec.run_id,
            spec.workflows_dir
                .as_deref()
                .expect("durability preflight established a workflow root"),
            spec.limits,
        )?);
        let cancel = CancellationToken::new();
        let RunSpec {
            script,
            args,
            run_id,
            limits,
            early_stop_quorum,
            speculative_siblings,
            task_retry,
            schema_retry,
            tunables_profile,
            ..
        } = spec;
        host::run_core(host::RunCoreRequest {
            script: &script,
            args,
            run_id,
            limits,
            early_stop_quorum,
            speculative_siblings,
            task_retry,
            schema_retry,
            cancel,
            journal,
            task_dag,
            spawner,
            sink,
            tunables_profile,
        })
        .await
    }

    /// Launch a run in the background and return a [`RunHandle`] immediately (mirrors Claude Code's
    /// background Workflow launch). A bounded process-wide executor drives the `!Send` QuickJS
    /// local set; no workflow allocates its own OS thread or Tokio runtime. The handle's shared
    /// [`CancellationToken`] reaches every in-flight child.
    pub fn launch(
        spec: RunSpec,
        spawner: Arc<dyn AgentSpawner>,
        sink: Arc<dyn ProgressSink>,
    ) -> RunHandle {
        let cancel = CancellationToken::new();
        let run_id = spec.run_id.clone();
        let (tx, rx) = oneshot::channel();

        if spec.workflows_dir.is_none() {
            let _ = tx.send(Err(WorkflowDurabilityRequired.into()));
            return RunHandle {
                run_id,
                cancel,
                result: Mutex::new(Some(rx)),
            };
        }

        executor::submit(executor::ExecutorJob {
            spec,
            spawner,
            sink,
            cancel: cancel.clone(),
            result: tx,
        });

        RunHandle {
            run_id,
            cancel,
            result: Mutex::new(Some(rx)),
        }
    }
}

fn run_executor_job(
    spec: RunSpec,
    spawner: Arc<dyn AgentSpawner>,
    sink: Arc<dyn ProgressSink>,
    cancel: CancellationToken,
    runtime: &tokio::runtime::Runtime,
) -> anyhow::Result<RunReport> {
    let journal = build_journal(&spec)?;
    let task_dag = Arc::new(task_dag::runtime::ExecutionLedger::open(
        &spec.run_id,
        spec.workflows_dir
            .as_deref()
            .ok_or(WorkflowDurabilityRequired)?,
        spec.limits,
    )?);
    let RunSpec {
        script,
        args,
        run_id,
        limits,
        early_stop_quorum,
        speculative_siblings,
        task_retry,
        schema_retry,
        tunables_profile,
        ..
    } = spec;
    runtime.block_on(host::run_core(host::RunCoreRequest {
        script: &script,
        args,
        run_id,
        limits,
        early_stop_quorum,
        speculative_siblings,
        task_retry,
        schema_retry,
        cancel,
        journal,
        task_dag,
        spawner,
        sink,
        tunables_profile,
    }))
}
