//! Per-run admission, counters, phases and retained immutable runtime ports.

use super::quorum::QuorumGroups;
use crate::LIFETIME_CAP;
use crate::events::{ProgressSink, WorkflowState};
use crate::journal::Journal;
use crate::spawner::AgentSpawner;
use crate::task_dag::runtime::ExecutionLedger;
use iteron_sched::Governor;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

const DEFAULT_MAX_LOG_CALLS_PER_RUN: usize = 16_384;
const HARD_MAX_LOG_CALLS_PER_RUN: usize = 65_536;

/// Fresh-per-run engine state. All fields are interior-mutable so the `Fn` host closures can share
/// one `Arc<RunState>` without a `&mut`.
pub struct RunState {
    index: AtomicUsize,
    agent_calls: AtomicUsize,
    max_agent_calls: usize,
    log_calls: AtomicUsize,
    max_log_calls: usize,
    phases: Mutex<HashMap<String, usize>>,
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
            log_calls: AtomicUsize::new(0),
            max_log_calls: iteron_tunables::param_usize(
                "workflow.bindings.default_max_log_calls_per_run",
                DEFAULT_MAX_LOG_CALLS_PER_RUN,
            )
            .clamp(
                1,
                iteron_tunables::param_usize(
                    "workflow.bindings.hard_max_log_calls_per_run",
                    HARD_MAX_LOG_CALLS_PER_RUN,
                )
                .clamp(1, HARD_MAX_LOG_CALLS_PER_RUN),
            ),
            phases: Mutex::new(HashMap::new()),
            errors: AtomicUsize::new(0),
            tokens: AtomicU64::new(0),
            tool_calls: AtomicU64::new(0),
            quorum: QuorumGroups::new(early_stop_quorum),
        }
    }

    /// Fold one settled agent's outcome and metrics into the run totals. Every finish event already
    /// carries them; without this they were reported per row and never summed for the run.
    pub(super) fn observe(&self, state: WorkflowState, tokens: u64, tool_calls: u64) {
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
    pub(super) fn next_index(&self) -> usize {
        self.index.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Admit one real child spawn. Journal hits do not consume the aggregate ceiling; every schema
    /// retry does. The compare-and-update keeps concurrent callers from overshooting it.
    pub(super) fn admit_agent_call(&self) -> bool {
        self.agent_calls
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |calls| {
                (calls < self.max_agent_calls).then_some(calls + 1)
            })
            .is_ok()
    }

    /// Bound host crossings as well as frontend emissions. The sink coalesces ordinary bursts,
    /// while this hard run ceiling stops a script that deliberately loops around `log()` forever.
    pub(super) fn admit_log_call(&self) -> bool {
        self.log_calls
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |calls| {
                (calls < self.max_log_calls).then_some(calls + 1)
            })
            .is_ok()
    }

    pub(super) fn begin_quorum(&self, parent: &CancellationToken, members: usize) -> u64 {
        self.quorum.begin(parent, members)
    }

    pub(super) fn quorum_token(&self, group_id: Option<u64>) -> Option<CancellationToken> {
        self.quorum.token(group_id)
    }

    pub(super) fn observe_quorum(&self, group_id: Option<u64>, role: &str, evidence: bool) {
        self.quorum.observe(group_id, role, evidence);
    }

    pub(super) fn end_quorum(&self, group_id: u64) {
        self.quorum.end(group_id);
    }

    /// 1-based first-seen phase index and whether this call declared the boundary. Duplicate phase
    /// calls do not re-emit, and unique phases share the already bounded agent-call ceiling.
    pub(super) fn phase_index(&self, title: &str) -> Option<(usize, bool)> {
        let mut phases = self.phases.lock().unwrap();
        if let Some(index) = phases.get(title) {
            return Some((*index, false));
        }
        if phases.len() >= self.max_agent_calls {
            return None;
        }
        let index = phases.len() + 1;
        phases.insert(title.to_string(), index);
        Some((index, true))
    }
}

impl Default for RunState {
    fn default() -> Self {
        // `RunLimits::default()` already resolves this id, so reading the raw constant here made
        // the two defaults disagree the moment a profile moved the cap. With no profile installed
        // this is exactly `LIFETIME_CAP`.
        Self::new(
            iteron_tunables::param_usize("workflow.bindings.lifetime_cap", LIFETIME_CAP),
            crate::EarlyStopQuorumPolicy::default(),
        )
    }
}

/// Everything a live `__agent` call needs, shared by `Arc` across the host closures.
#[derive(Clone)]
pub struct AgentEnv {
    pub state: Arc<RunState>,
    pub spawner: Arc<dyn AgentSpawner>,
    pub sink: Arc<dyn ProgressSink>,
    pub gov: Governor,
    pub available_permits: Arc<std::sync::atomic::AtomicUsize>,
    pub cancel: CancellationToken,
    pub journal: Arc<Journal>,
    pub task_dag: Arc<ExecutionLedger>,
    pub speculative_siblings: crate::SpeculativeSiblingPolicy,
    pub task_retry: crate::TaskRetryPolicy,
    pub schema_retry: crate::SchemaRetryPolicy,
    /// The operator profile this run was resolved under, when one was supplied. Read only for
    /// prompt-artifact replacement: it carries model-visible text and reaches no capability,
    /// budget, or tool decision from here.
    pub tunables_profile: Option<Arc<iteron_tunables::ProfileDocument>>,
}

pub(super) struct TrackedPermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
    available: Arc<std::sync::atomic::AtomicUsize>,
}

impl TrackedPermit {
    pub(super) fn new(
        permit: tokio::sync::OwnedSemaphorePermit,
        available: Arc<std::sync::atomic::AtomicUsize>,
    ) -> Self {
        let _ = available.fetch_update(Ordering::AcqRel, Ordering::Acquire, |slots| {
            Some(slots.saturating_sub(1))
        });
        Self {
            _permit: permit,
            available,
        }
    }
}

impl Drop for TrackedPermit {
    fn drop(&mut self) {
        self.available.fetch_add(1, Ordering::Release);
    }
}
