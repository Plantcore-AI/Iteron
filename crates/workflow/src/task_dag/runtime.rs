//! Production adapter from workflow dispatch to the durable task-DAG reducer.
//!
//! The reducer remains synchronous and deterministic. This adapter allocates controller-owned
//! identities and moves every append+fsync onto Tokio's blocking pool so an agent completion never
//! stalls the QuickJS/runtime thread.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use super::{
    Actor, AttemptCompletion, AttemptDisposition, AttemptId, AttemptSpec, BudgetUsage, Command,
    CommandId, Completion, Config, DagError, Limits, TaskBudget, TaskDag, TaskDagStore, TaskId,
    TaskSpec, TaskState,
};
use crate::{RunId, RunLimits};

const ATTEMPT_TOKEN_CEILING: u64 = 100_000_000;
const TASK_COST_CEILING_MICROUSD: u64 = 100_000_000_000;
const TASK_WALL_CEILING_MS: u64 = 30 * 24 * 60 * 60 * 1_000;

enum Backend {
    Durable(TaskDagStore),
    Memory(TaskDag),
}

impl Backend {
    fn submit(&mut self, id: CommandId, command: Command) -> Result<(), DagError> {
        match self {
            Self::Durable(store) => store.submit(id, command).map(|_| ()),
            Self::Memory(dag) => dag.apply(id, command).map(|_| ()),
        }
    }

    fn snapshot(&self) -> super::Snapshot {
        match self {
            Self::Durable(store) => store.dag().snapshot(),
            Self::Memory(dag) => dag.snapshot(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct ExecutionLedger {
    backend: Arc<Mutex<Backend>>,
    next_command: Arc<AtomicU64>,
    next_task: Arc<AtomicU64>,
    next_attempt: Arc<AtomicU64>,
    task_budget: TaskBudget,
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
        workflows_dir: Option<&Path>,
        run_limits: RunLimits,
    ) -> Result<Self, DagError> {
        let max_calls = run_limits.max_agent_calls();
        let limits = Limits {
            max_tasks: max_calls,
            max_edges: max_calls.saturating_mul(2).max(1),
            max_events: max_calls.saturating_mul(24).max(256),
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
        let (mut backend, mut next_command, next_task, next_attempt) = match workflows_dir {
            Some(dir) => {
                let path = dir.join(run_id.as_str()).join("task-dag.jsonl");
                let store = TaskDagStore::open(path, config)?;
                let snapshot = store.dag().snapshot();
                let next_task = snapshot
                    .tasks
                    .iter()
                    .map(|task| task.spec.id.0)
                    .max()
                    .unwrap_or(0)
                    .saturating_add(1);
                let next_attempt = snapshot
                    .attempts
                    .iter()
                    .map(|attempt| attempt.spec.id.0)
                    .max()
                    .unwrap_or(0)
                    .saturating_add(1);
                (
                    Backend::Durable(store),
                    snapshot.sequence.saturating_add(1),
                    next_task,
                    next_attempt,
                )
            }
            None => (Backend::Memory(TaskDag::new(config)?), 1, 1, 1),
        };
        reconcile_nonterminal(&mut backend, &mut next_command)?;
        Ok(Self {
            backend: Arc::new(Mutex::new(backend)),
            next_command: Arc::new(AtomicU64::new(next_command)),
            next_task: Arc::new(AtomicU64::new(next_task)),
            next_attempt: Arc::new(AtomicU64::new(next_attempt)),
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

    pub(crate) async fn begin_task(&self, index: usize) -> Result<TaskId, String> {
        let id = TaskId(self.next_task.fetch_add(1, Ordering::SeqCst));
        self.submit(Command::CreateTask {
            actor: Actor::Controller,
            spec: TaskSpec {
                id,
                parent: None,
                dependencies: Vec::new(),
                label: format!("workflow-agent-{index}"),
                budget: self.task_budget,
            },
        })
        .await?;
        self.submit(Command::StartTask {
            actor: Actor::Controller,
            task: id,
        })
        .await?;
        Ok(id)
    }

    pub(crate) async fn begin_attempt(
        &self,
        task: TaskId,
        retry_ordinal: usize,
        sibling_ordinal: usize,
        input_digest: &str,
    ) -> Result<AttemptId, String> {
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
            TaskState::Ready | TaskState::Blocked => submit_recovery(
                backend,
                next_command,
                Command::RequestCancel {
                    actor: Actor::Controller,
                    task: task.spec.id,
                    reason: "prior controller exited before task admission".into(),
                },
            )?,
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
