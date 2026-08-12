//! Production adapter from workflow dispatch to the durable task-DAG reducer.
//!
//! The reducer remains synchronous and deterministic. This adapter allocates controller-owned
//! identities and moves every append+fsync onto Tokio's blocking pool so an agent completion never
//! stalls the QuickJS/runtime thread.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use super::hash::digest_json;
use super::types::{
    HARD_MAX_EDGES, HARD_MAX_EVENTS, HARD_MAX_MESSAGES, HARD_MAX_TASKS, valid_digest,
};
use super::{
    Actor, AttemptAssignment, AttemptCompletion, AttemptDisposition, AttemptId, AttemptRetryCause,
    AttemptSpec, BudgetUsage, Command, CommandId, Completion, Config, DagError, DeliveryState,
    Limits, MessageId, MessageKind, TaskBudget, TaskDagStore, TaskId, TaskMessage, TaskSpec,
    TaskState,
};
use crate::{RunId, RunLimits};

/// Highest id assumed present when a replayed snapshot holds none. Every durable id is non-zero,
/// so zero is unused and the next allocation lands on 1.
const EMPTY_SNAPSHOT_MAX_ID: u64 = 0;
const ATTEMPT_TOKEN_CEILING: u64 = 100_000_000;
const TASK_COST_CEILING_MICROUSD: u64 = 100_000_000_000;
const TASK_WALL_CEILING_MS: u64 = 30 * 24 * 60 * 60 * 1_000;

struct Backend(TaskDagStore);

impl Backend {
    fn submit(&mut self, id: CommandId, command: Command) -> Result<(), DagError> {
        self.0.submit(id, command).map(|_| ())
    }

    fn snapshot(&self) -> super::Snapshot {
        self.0.dag().snapshot()
    }
}

#[derive(Clone)]
pub(crate) struct ExecutionLedger {
    backend: Arc<Mutex<Backend>>,
    next_command: Arc<AtomicU64>,
    next_task: Arc<AtomicU64>,
    next_attempt: Arc<AtomicU64>,
    next_message: Arc<AtomicU64>,
    declaration_tasks: Arc<Mutex<BTreeMap<usize, TaskId>>>,
    task_budget: TaskBudget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TaskAdmission {
    Ready(TaskId),
    SkippedDependency { task: TaskId, dependency: TaskId },
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct AttemptRetryLink {
    retry_of: Option<AttemptId>,
    retry_cause: Option<AttemptRetryCause>,
}

impl AttemptRetryLink {
    pub(crate) const fn new(
        retry_of: Option<AttemptId>,
        retry_cause: Option<AttemptRetryCause>,
    ) -> Self {
        Self {
            retry_of,
            retry_cause,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum AttemptTerminal {
    Succeeded {
        result_digest: String,
        disposition: AttemptDisposition,
    },
    Failed {
        code: &'static str,
        detail: String,
        disposition: AttemptDisposition,
    },
    UnknownEffect {
        reason: String,
    },
}

impl ExecutionLedger {
    pub(crate) fn open(
        run_id: &RunId,
        workflows_dir: &Path,
        run_limits: RunLimits,
    ) -> Result<Self, DagError> {
        let max_calls = run_limits.max_agent_calls();
        let limits = Limits {
            // Logical declarations and physical dispatches are different resources. A call that
            // loses the physical-call ceiling still needs a durable task identity and negative
            // terminal; tying task capacity to `max_agent_calls` made one excess sibling cancel
            // already-admitted unrelated work. The reducer's immutable hard ceilings bound the
            // evidence plane, while `RunState::admit_agent_call` remains the exact authority
            // boundary for real child effects.
            max_tasks: HARD_MAX_TASKS,
            max_edges: HARD_MAX_EDGES,
            max_messages: HARD_MAX_MESSAGES,
            max_events: HARD_MAX_EVENTS,
            ..Default::default()
        };
        limits.validate().map_err(DagError::InvalidConfig)?;

        // These are accounting ceilings, not new authority: the kernel spawner still owns the
        // real model/tool/cost limits. The values exactly fit the reducer's hard root ceilings at
        // the maximum supported 1,000 logical calls.
        let graph_budget = TaskBudget {
            max_turns: 1_000_000,
            max_tokens: 100_000_000_000,
            max_cost_microusd: 100_000_000_000_000,
            max_wall_ms: TASK_WALL_CEILING_MS,
        };
        let task_budget = TaskBudget {
            max_turns: u32::try_from(max_calls).unwrap_or(u32::MAX),
            max_tokens: ATTEMPT_TOKEN_CEILING,
            max_cost_microusd: TASK_COST_CEILING_MICROUSD,
            max_wall_ms: TASK_WALL_CEILING_MS,
        };
        let config =
            Config::new(run_id.as_str(), limits, graph_budget).map_err(DagError::InvalidConfig)?;
        let (
            mut backend,
            mut next_command,
            next_task,
            next_attempt,
            next_message,
            declaration_tasks,
        ) = {
            let path = workflows_dir.join(run_id.as_str()).join("task-dag.jsonl");
            let store = TaskDagStore::open(path, config)?;
            let snapshot = store.dag().snapshot();
            let next_task = snapshot
                .tasks
                .iter()
                .map(|task| task.spec.id.0)
                .max()
                .unwrap_or(EMPTY_SNAPSHOT_MAX_ID)
                .saturating_add(1);
            let next_attempt = snapshot
                .attempts
                .iter()
                .map(|attempt| attempt.spec.id.0)
                .max()
                .unwrap_or(EMPTY_SNAPSHOT_MAX_ID)
                .saturating_add(1);
            let next_message = snapshot
                .messages
                .iter()
                .map(|message| message.id.0)
                .max()
                .unwrap_or(EMPTY_SNAPSHOT_MAX_ID)
                .saturating_add(1);
            let mut declaration_tasks = BTreeMap::new();
            for task in &snapshot.tasks {
                if let Some(index) = task.spec.declaration_index {
                    let index = usize::try_from(index).map_err(|_| {
                        DagError::Corrupt("task declaration index cannot fit this runtime".into())
                    })?;
                    declaration_tasks
                        .entry(index)
                        .and_modify(|current: &mut TaskId| {
                            if task.spec.id > *current {
                                *current = task.spec.id;
                            }
                        })
                        .or_insert(task.spec.id);
                }
            }
            (
                Backend(store),
                snapshot.sequence.saturating_add(1),
                next_task,
                next_attempt,
                next_message,
                declaration_tasks,
            )
        };
        reconcile_nonterminal(&mut backend, &mut next_command)?;
        Ok(Self {
            backend: Arc::new(Mutex::new(backend)),
            next_command: Arc::new(AtomicU64::new(next_command)),
            next_task: Arc::new(AtomicU64::new(next_task)),
            next_attempt: Arc::new(AtomicU64::new(next_attempt)),
            next_message: Arc::new(AtomicU64::new(next_message)),
            declaration_tasks: Arc::new(Mutex::new(declaration_tasks)),
            task_budget,
        })
    }

    async fn submit(&self, command: Command) -> Result<(), String> {
        let command_id = self.next_command.fetch_add(1, Ordering::SeqCst);
        let backend = self.backend.clone();
        tokio::task::spawn_blocking(move || {
            let mut backend = backend
                .lock()
                .map_err(|_| "task DAG owner lock was poisoned".to_string())?;
            backend
                .submit(CommandId(command_id), command)
                .map_err(|error| error.to_string())
        })
        .await
        .map_err(|error| format!("task DAG append task failed: {error}"))?
    }

    /// Durably admit one declaration-order task. `dependency_indices` are earlier declaration
    /// indices from the explicit workflow call; dependencies must already have a durable terminal
    /// so a JS scheduling race cannot manufacture or wait forever on an implicit edge.
    pub(crate) async fn begin_task(
        &self,
        index: usize,
        input_digest: &str,
        dependency_indices: &[usize],
    ) -> Result<TaskAdmission, String> {
        if !valid_digest(input_digest) {
            return Err("task input digest must be exactly 64 hexadecimal bytes".into());
        }
        let requested = dependency_indices.iter().copied().collect::<BTreeSet<_>>();
        if requested.len() != dependency_indices.len()
            || requested
                .iter()
                .any(|dependency| *dependency == 0 || *dependency >= index)
        {
            return Err("task dependencies must be unique earlier declaration indices".into());
        }
        let dependencies = {
            let declarations = self
                .declaration_tasks
                .lock()
                .map_err(|_| "task declaration index lock was poisoned".to_string())?;
            requested
                .iter()
                .map(|dependency| {
                    declarations.get(dependency).copied().ok_or_else(|| {
                        format!("task dependency declaration {dependency} is not durable")
                    })
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        if !dependencies.is_empty() {
            let snapshot = self.snapshot().await?;
            for dependency in &dependencies {
                let state = snapshot
                    .tasks
                    .iter()
                    .find(|task| task.spec.id == *dependency)
                    .map(|task| &task.state)
                    .ok_or_else(|| {
                        "task dependency disappeared from the durable DAG".to_string()
                    })?;
                if !state.is_terminal() {
                    return Err(
                        "task dependency must reach a durable terminal before dependent admission"
                            .into(),
                    );
                }
            }
        }
        let id = TaskId(self.next_task.fetch_add(1, Ordering::SeqCst));
        let declaration_index =
            u32::try_from(index).map_err(|_| "task declaration index exceeded u32".to_string())?;
        self.submit(Command::CreateTask {
            actor: Actor::Controller,
            spec: TaskSpec {
                id,
                declaration_index: Some(declaration_index),
                parent: None,
                dependencies,
                label: format!("workflow-agent-{index}"),
                budget: self.task_budget,
            },
        })
        .await?;
        self.declaration_tasks
            .lock()
            .map_err(|_| "task declaration index lock was poisoned".to_string())?
            .insert(index, id);

        let state = self
            .snapshot()
            .await?
            .tasks
            .into_iter()
            .find(|task| task.spec.id == id)
            .map(|task| task.state)
            .ok_or_else(|| "new task disappeared from the durable DAG".to_string())?;
        if let TaskState::SkippedDependency { dependency } = state {
            return Ok(TaskAdmission::SkippedDependency {
                task: id,
                dependency,
            });
        }
        if !matches!(state, TaskState::Ready) {
            return Err("new task did not become ready after terminal dependencies".into());
        }

        // The assignment envelope is content-free but binds a durable message identity to the
        // exact task input. Controller acknowledgement means admission consumed the assignment;
        // it does not pretend a model saw prompt text outside its own child record.
        let message = MessageId(self.next_message.fetch_add(1, Ordering::SeqCst));
        self.submit(Command::SendMessage {
            actor: Actor::Controller,
            message: TaskMessage {
                id: message,
                from: crate::AgentMessagingTopology::owner().durable_sender(),
                to: id,
                kind: MessageKind::Instruction,
                payload: format!("input_sha256:{input_digest}"),
                delivery: DeliveryState::Pending,
            },
        })
        .await?;
        self.submit(Command::AcknowledgeMessage {
            actor: Actor::Controller,
            message,
        })
        .await?;
        self.submit(Command::StartTask {
            actor: Actor::Controller,
            task: id,
        })
        .await?;
        Ok(TaskAdmission::Ready(id))
    }

    pub(crate) async fn begin_attempt(
        &self,
        task: TaskId,
        retry_ordinal: usize,
        sibling_ordinal: usize,
        assignment: AttemptAssignment,
        retry: AttemptRetryLink,
        input_digest: &str,
    ) -> Result<AttemptId, String> {
        // The controller, not the caller, derives evidence from the predecessor's durable
        // terminal. Validation recomputes the same canonical digest while reducing the command,
        // so neither transient prompt text nor unverifiable schema diagnostics can stand in for
        // the evidence that actually survived a restart.
        let prior_evidence_digest = if let Some(prior_id) = retry.retry_of {
            let snapshot = self.snapshot().await?;
            let prior = snapshot
                .attempts
                .iter()
                .find(|attempt| attempt.spec.id == prior_id)
                .ok_or_else(|| {
                    format!("retry predecessor attempt {} does not exist", prior_id.0)
                })?;
            Some(
                digest_json(&prior.state)
                    .map_err(|error| format!("retry predecessor digest failed: {error}"))?,
            )
        } else {
            None
        };
        let id = AttemptId(self.next_attempt.fetch_add(1, Ordering::SeqCst));
        self.submit(Command::RegisterAttempt {
            actor: Actor::Controller,
            attempt: AttemptSpec {
                id,
                task,
                retry_ordinal: u32::try_from(retry_ordinal)
                    .map_err(|_| "retry ordinal exceeded u32".to_string())?,
                sibling_ordinal: u32::try_from(sibling_ordinal)
                    .map_err(|_| "sibling ordinal exceeded u32".to_string())?,
                lineage_version: 1,
                retry_of: retry.retry_of,
                assignment,
                retry_cause: retry.retry_cause,
                prior_evidence_digest,
                input_digest: input_digest.to_owned(),
            },
        })
        .await?;
        self.submit(Command::StartAttempt {
            actor: Actor::Controller,
            attempt: id,
        })
        .await?;
        Ok(id)
    }

    /// Record the exact positive physical attempt that authorizes sibling-only cancellation.
    /// The content-free message is durable and acknowledged before the cancellation token is
    /// triggered; if this append cannot be proven, the controller simply lets every sibling run
    /// to a terminal and performs no evidence-driven early cancellation.
    pub(crate) async fn record_speculative_winner(
        &self,
        task: TaskId,
        attempt: AttemptId,
        result_digest: &str,
    ) -> Result<(), String> {
        if !valid_digest(result_digest) {
            return Err("speculative winner digest must be exactly 64 hexadecimal bytes".into());
        }
        let snapshot = self.snapshot().await?;
        let candidate = snapshot
            .attempts
            .iter()
            .find(|candidate| candidate.spec.id == attempt)
            .ok_or_else(|| "speculative winner attempt is not durable".to_string())?;
        if candidate.spec.task != task || !matches!(candidate.state, super::AttemptState::Running) {
            return Err("speculative winner is not a running attempt of this task".into());
        }
        let message = MessageId(self.next_message.fetch_add(1, Ordering::SeqCst));
        self.submit(Command::SendMessage {
            actor: Actor::Controller,
            message: TaskMessage {
                id: message,
                from: crate::AgentMessagingTopology::owner().durable_sender(),
                to: task,
                kind: MessageKind::Control,
                payload: format!(
                    "speculative_winner:attempt={}:result_sha256={result_digest}",
                    attempt.0
                ),
                delivery: DeliveryState::Pending,
            },
        })
        .await?;
        self.submit(Command::AcknowledgeMessage {
            actor: Actor::Controller,
            message,
        })
        .await
    }

    async fn snapshot(&self) -> Result<super::Snapshot, String> {
        let backend = self.backend.clone();
        tokio::task::spawn_blocking(move || {
            backend
                .lock()
                .map_err(|_| "task DAG owner lock was poisoned".to_string())
                .map(|backend| backend.snapshot())
        })
        .await
        .map_err(|error| format!("task DAG snapshot task failed: {error}"))?
    }

    pub(crate) async fn finish_attempt(
        &self,
        task: TaskId,
        attempt: AttemptId,
        tokens: u64,
        elapsed_ms: u64,
        terminal: AttemptTerminal,
    ) -> Result<(), String> {
        self.submit(Command::ChargeBudget {
            actor: Actor::Controller,
            task,
            delta: BudgetUsage {
                turns: 1,
                tokens,
                cost_microusd: 0,
                wall_ms: elapsed_ms,
            },
        })
        .await?;
        let (completion, disposition, result_digest, code, detail) = match terminal {
            AttemptTerminal::Succeeded {
                result_digest,
                disposition,
            } => (
                AttemptCompletion::Succeeded,
                disposition,
                Some(result_digest),
                None,
                None,
            ),
            AttemptTerminal::Failed {
                code,
                detail,
                disposition,
            } => (
                AttemptCompletion::Failed,
                disposition,
                None,
                Some(code.to_owned()),
                Some(bounded_reason(&detail)),
            ),
            AttemptTerminal::UnknownEffect { reason } => (
                AttemptCompletion::UnknownEffect,
                AttemptDisposition::UnknownEffect,
                None,
                None,
                Some(bounded_reason(&reason)),
            ),
        };
        self.submit(Command::CompleteAttempt {
            actor: Actor::Controller,
            attempt,
            completion,
            disposition,
            result_digest,
            code,
            detail,
        })
        .await
    }

    pub(crate) async fn finish_task_success(
        &self,
        task: TaskId,
        digest: String,
    ) -> Result<(), String> {
        self.submit(Command::CompleteTask {
            actor: Actor::Controller,
            task,
            completion: Completion::Succeeded,
            result_digest: Some(digest),
            code: None,
            detail: None,
        })
        .await
    }

    pub(crate) async fn finish_task_failure(
        &self,
        task: TaskId,
        code: &'static str,
        detail: &str,
    ) -> Result<(), String> {
        self.submit(Command::CompleteTask {
            actor: Actor::Controller,
            task,
            completion: Completion::Failed,
            result_digest: None,
            code: Some(code.to_owned()),
            detail: Some(bounded_reason(detail)),
        })
        .await
    }

    /// Close every controller-owned task/attempt before the run report is released. This is also
    /// called on an in-memory run: cancellation may cause QuickJS to drop a pending host future,
    /// and dropping that future must not erase the attempt's unknown-effect terminal.
    pub(crate) async fn reconcile_nonterminal(&self) -> Result<(), String> {
        let backend = self.backend.clone();
        let next_command = self.next_command.clone();
        tokio::task::spawn_blocking(move || {
            let mut backend = backend
                .lock()
                .map_err(|_| "task DAG owner lock was poisoned".to_string())?;
            let mut next = next_command.load(Ordering::SeqCst);
            reconcile_nonterminal(&mut backend, &mut next).map_err(|error| error.to_string())?;
            next_command.store(next, Ordering::SeqCst);
            Ok(())
        })
        .await
        .map_err(|error| format!("task DAG reconciliation task failed: {error}"))?
    }
}

/// The exclusive store lock proves no prior controller is still alive when a durable run is
/// reopened. Any registered/running attempt therefore has an unknown external effect and is
/// terminalized before new dispatch; its parent task is then failed/cancelled exactly once.
fn reconcile_nonterminal(backend: &mut Backend, next_command: &mut u64) -> Result<(), DagError> {
    let snapshot = backend.snapshot();
    for attempt in snapshot.attempts {
        if attempt.state.is_terminal() {
            continue;
        }
        if matches!(attempt.state, super::AttemptState::Registered) {
            submit_recovery(
                backend,
                next_command,
                Command::StartAttempt {
                    actor: Actor::Controller,
                    attempt: attempt.spec.id,
                },
            )?;
        }
        submit_recovery(
            backend,
            next_command,
            Command::ChargeBudget {
                actor: Actor::Controller,
                task: attempt.spec.task,
                delta: BudgetUsage {
                    turns: 1,
                    tokens: 0,
                    cost_microusd: 0,
                    wall_ms: 0,
                },
            },
        )?;
        submit_recovery(
            backend,
            next_command,
            Command::CompleteAttempt {
                actor: Actor::Controller,
                attempt: attempt.spec.id,
                completion: AttemptCompletion::UnknownEffect,
                disposition: AttemptDisposition::UnknownEffect,
                result_digest: None,
                code: None,
                detail: Some("prior controller exited without an attempt receipt".into()),
            },
        )?;
    }

    let snapshot = backend.snapshot();
    for task in snapshot.tasks {
        match task.state {
            TaskState::Running => submit_recovery(
                backend,
                next_command,
                Command::CompleteTask {
                    actor: Actor::Controller,
                    task: task.spec.id,
                    completion: Completion::Failed,
                    result_digest: None,
                    code: Some("orphan_recovered".into()),
                    detail: Some("prior controller exited before the task terminal".into()),
                },
            )?,
            TaskState::Cancelling { reason } => submit_recovery(
                backend,
                next_command,
                Command::CompleteTask {
                    actor: Actor::Controller,
                    task: task.spec.id,
                    completion: Completion::Cancelled,
                    result_digest: None,
                    code: None,
                    detail: Some(reason),
                },
            )?,
            TaskState::Ready | TaskState::Blocked => {
                let reason = "prior controller exited before task admission".to_string();
                submit_recovery(
                    backend,
                    next_command,
                    Command::RequestCancel {
                        actor: Actor::Controller,
                        task: task.spec.id,
                        reason,
                    },
                )?;
                // The reducer terminalizes an unstarted Ready/Blocked task directly. Running
                // tasks instead enter Cancelling and require an effect acknowledgement above.
            }
            _ => {}
        }
    }
    Ok(())
}

fn submit_recovery(
    backend: &mut Backend,
    next_command: &mut u64,
    command: Command,
) -> Result<(), DagError> {
    let id = CommandId(*next_command);
    *next_command = next_command.saturating_add(1);
    backend.submit(id, command)
}

pub(crate) fn digest_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn bounded_reason(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(1_024)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            static SERIAL: AtomicU64 = AtomicU64::new(0);
            let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "core-workflow-ledger-{label}-{}-{serial}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("create durable workflow root");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn durable_reopen_terminalizes_an_orphaned_attempt_exactly_once() {
        let root = TempDir::new("orphan-reopen");
        let run_id = RunId::new("h07-orphan-reopen");
        let limits = RunLimits::new(1, 2).expect("valid limits");
        let input_digest = "a".repeat(64);
        fs::create_dir_all(root.path().join(run_id.as_str()))
            .expect("pre-provision durable run directory");

        let ledger =
            ExecutionLedger::open(&run_id, root.path(), limits).expect("open fresh ledger");
        let task = match ledger
            .begin_task(1, &input_digest, &[])
            .await
            .expect("admit task")
        {
            TaskAdmission::Ready(task) => task,
            other => panic!("unexpected admission: {other:?}"),
        };
        let attempt = ledger
            .begin_attempt(
                task,
                0,
                0,
                AttemptAssignment::Initial,
                AttemptRetryLink::new(None, None),
                &input_digest,
            )
            .await
            .expect("start attempt");
        drop(ledger);

        let reopened = ExecutionLedger::open(&run_id, root.path(), limits)
            .expect("reopen and reconcile ledger");
        let recovered = reopened.snapshot().await.expect("snapshot recovery");
        assert!(matches!(
            recovered
                .attempts
                .iter()
                .find(|candidate| candidate.spec.id == attempt)
                .map(|candidate| &candidate.state),
            Some(super::super::AttemptState::UnknownEffect { reason })
                if reason == "prior controller exited without an attempt receipt"
        ));
        assert!(matches!(
            recovered
                .tasks
                .iter()
                .find(|candidate| candidate.spec.id == task)
                .map(|candidate| &candidate.state),
            Some(TaskState::Failed { code, detail })
                if code == "orphan_recovered"
                    && detail == "prior controller exited before the task terminal"
        ));
        let recovered_sequence = recovered.sequence;
        drop(reopened);

        let reopened_again = ExecutionLedger::open(&run_id, root.path(), limits)
            .expect("reopen already reconciled ledger");
        let stable = reopened_again
            .snapshot()
            .await
            .expect("snapshot stable ledger");
        assert_eq!(stable.sequence, recovered_sequence);
        assert_eq!(stable.attempts, recovered.attempts);
        assert_eq!(stable.tasks, recovered.tasks);
    }

    #[tokio::test]
    async fn durable_reopen_terminalizes_a_partially_admitted_task_in_one_pass() {
        let root = TempDir::new("partial-admission");
        let run_id = RunId::new("h07-partial-admission");
        let limits = RunLimits::new(1, 1).expect("valid limits");
        fs::create_dir_all(root.path().join(run_id.as_str()))
            .expect("pre-provision durable run directory");
        let ledger =
            ExecutionLedger::open(&run_id, root.path(), limits).expect("open fresh ledger");
        let task = TaskId(1);
        ledger
            .submit(Command::CreateTask {
                actor: Actor::Controller,
                spec: TaskSpec {
                    id: task,
                    declaration_index: Some(1),
                    parent: None,
                    dependencies: Vec::new(),
                    label: "partially-admitted".into(),
                    budget: ledger.task_budget,
                },
            })
            .await
            .expect("persist create before simulated crash");
        drop(ledger);

        let reopened = ExecutionLedger::open(&run_id, root.path(), limits)
            .expect("one reopen fully reconciles partial admission");
        let recovered = reopened.snapshot().await.expect("snapshot recovery");
        assert!(matches!(
            recovered
                .tasks
                .iter()
                .find(|candidate| candidate.spec.id == task)
                .map(|candidate| &candidate.state),
            Some(TaskState::Cancelled { reason })
                if reason == "prior controller exited before task admission"
        ));
        let recovered_sequence = recovered.sequence;
        drop(reopened);

        let reopened_again = ExecutionLedger::open(&run_id, root.path(), limits)
            .expect("reopen already reconciled ledger");
        assert_eq!(
            reopened_again
                .snapshot()
                .await
                .expect("snapshot stable ledger")
                .sequence,
            recovered_sequence
        );
    }
}
