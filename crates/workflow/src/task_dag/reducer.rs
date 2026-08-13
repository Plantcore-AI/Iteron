use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::DagError;
use super::hash::{config_digest, digest_json, entry_digest};
use super::types::{
    Attempt, AttemptCompletion, AttemptId, AttemptState, BudgetReservation, BudgetUsage, Command,
    CommandId, Completion, Config, DeliveryState, JoinId, JoinSpec, JoinState, MessageId, Task,
    TaskId, TaskMessage, TaskSpec, TaskState,
};

const LOG_VERSION: u32 = 1;

/// Depth recorded for a task whose dependency set is empty: it is a root of the dependency order,
/// so nothing precedes it.
const ROOT_DEPENDENCY_DEPTH: usize = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyReceipt {
    pub sequence: u64,
    pub replayed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub config: Config,
    pub sequence: u64,
    pub head_digest: String,
    pub tasks: Vec<Task>,
    pub attempts: Vec<Attempt>,
    pub messages: Vec<TaskMessage>,
    pub joins: Vec<JoinSpec>,
}

#[derive(Debug, Clone)]
struct CommandReceipt {
    sequence: u64,
    command_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LogEntry {
    pub(crate) version: u32,
    pub(crate) graph_id: String,
    pub(crate) sequence: u64,
    pub(crate) previous_digest: String,
    pub(crate) command_id: CommandId,
    pub(crate) command_digest: String,
    pub(crate) command: Command,
    pub(crate) entry_digest: String,
}

pub(crate) enum Prepared {
    Replay(ApplyReceipt),
    New(Box<LogEntry>),
}

#[derive(Debug, Clone)]
pub struct TaskDag {
    pub(super) config: Config,
    sequence: u64,
    head_digest: String,
    pub(super) tasks: BTreeMap<TaskId, Task>,
    pub(super) attempts: BTreeMap<AttemptId, Attempt>,
    pub(super) messages: BTreeMap<MessageId, TaskMessage>,
    pub(super) joins: BTreeMap<JoinId, JoinSpec>,
    commands: BTreeMap<CommandId, CommandReceipt>,
    pub(super) edge_count: usize,
    pub(super) root_reservations: BudgetReservation,
}

impl TaskDag {
    pub fn new(config: Config) -> Result<Self, DagError> {
        config.validate().map_err(DagError::InvalidConfig)?;
        let head_digest = config_digest(&config)?;
        Ok(Self {
            config,
            sequence: 0,
            head_digest,
            tasks: BTreeMap::new(),
            attempts: BTreeMap::new(),
            messages: BTreeMap::new(),
            joins: BTreeMap::new(),
            commands: BTreeMap::new(),
            edge_count: 0,
            root_reservations: BudgetReservation::default(),
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn head_digest(&self) -> &str {
        &self.head_digest
    }

    pub fn task(&self, id: TaskId) -> Option<&Task> {
        self.tasks.get(&id)
    }

    pub fn message(&self, id: MessageId) -> Option<&TaskMessage> {
        self.messages.get(&id)
    }

    pub fn attempt(&self, id: AttemptId) -> Option<&Attempt> {
        self.attempts.get(&id)
    }

    pub fn remaining_budget(&self, id: TaskId) -> Result<super::types::TaskBudget, DagError> {
        let task = self.tasks.get(&id).ok_or(DagError::UnknownTask(id.0))?;
        task.spec
            .budget
            .remaining(task.usage, task.child_reservations)
            .ok_or(DagError::Budget("task budget invariant is inconsistent"))
    }

    pub fn remaining_root_budget(&self) -> Result<super::types::TaskBudget, DagError> {
        self.config
            .budget
            .remaining(BudgetUsage::default(), self.root_reservations)
            .ok_or(DagError::Budget("root budget invariant is inconsistent"))
    }

    pub fn ready_tasks(&self) -> Vec<TaskId> {
        let mut ready = self
            .tasks
            .iter()
            .filter_map(|(id, task)| matches!(task.state, TaskState::Ready).then_some(*id))
            .collect::<Vec<_>>();
        crate::TaskPrioritySchedulingPolicy::owner().order_ready(&mut ready);
        ready
    }

    pub fn pending_messages(&self, task: TaskId) -> Result<Vec<&TaskMessage>, DagError> {
        let task = self.tasks.get(&task).ok_or(DagError::UnknownTask(task.0))?;
        Ok(task
            .inbox
            .iter()
            .filter_map(|id| self.messages.get(id))
            .filter(|message| message.delivery == DeliveryState::Pending)
            .collect())
    }

    pub fn join_state(&self, id: JoinId) -> Result<JoinState, DagError> {
        let join = self.joins.get(&id).ok_or(DagError::UnknownJoin(id.0))?;
        let remaining = join
            .members
            .iter()
            .copied()
            .filter(|member| {
                self.tasks
                    .get(member)
                    .is_some_and(|task| !task.state.is_terminal())
            })
            .collect::<Vec<_>>();
        if !remaining.is_empty() {
            return Ok(JoinState::Pending { remaining });
        }
        if join.policy == super::types::JoinPolicy::AllSucceeded {
            let failed = join
                .members
                .iter()
                .copied()
                .filter(|member| {
                    self.tasks
                        .get(member)
                        .is_some_and(|task| !task.state.succeeded())
                })
                .collect::<Vec<_>>();
            if !failed.is_empty() {
                return Ok(JoinState::Failed { members: failed });
            }
        }
        Ok(JoinState::Ready)
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            config: self.config.clone(),
            sequence: self.sequence,
            head_digest: self.head_digest.clone(),
            tasks: self.tasks.values().cloned().collect(),
            attempts: self.attempts.values().cloned().collect(),
            messages: self.messages.values().cloned().collect(),
            joins: self.joins.values().cloned().collect(),
        }
    }

    pub fn apply(
        &mut self,
        command_id: CommandId,
        command: Command,
    ) -> Result<ApplyReceipt, DagError> {
        match self.prepare(command_id, command)? {
            Prepared::Replay(receipt) => Ok(receipt),
            Prepared::New(entry) => {
                let receipt = ApplyReceipt {
                    sequence: entry.sequence,
                    replayed: false,
                };
                self.commit(*entry);
                Ok(receipt)
            }
        }
    }

    pub(crate) fn prepare(
        &self,
        command_id: CommandId,
        command: Command,
    ) -> Result<Prepared, DagError> {
        if command_id.0 == 0 {
            return Err(DagError::InvalidCommandId);
        }
        // Bound every variable-width field before serializing it for the idempotency digest. This
        // keeps a rejected command from creating a second, attacker-sized allocation first.
        self.validate_command_shape(&command)?;
        let command_digest = digest_json(&command)?;
        if let Some(existing) = self.commands.get(&command_id) {
            if existing.command_digest == command_digest {
                return Ok(Prepared::Replay(ApplyReceipt {
                    sequence: existing.sequence,
                    replayed: true,
                }));
            }
            return Err(DagError::CommandConflict(command_id.0));
        }
        if self.sequence as usize >= self.config.limits.max_events {
            return Err(DagError::EventLimit);
        }
        self.validate_command(&command)?;
        let sequence = self.sequence.checked_add(1).ok_or(DagError::EventLimit)?;
        let mut entry = LogEntry {
            version: LOG_VERSION,
            graph_id: self.config.graph_id.clone(),
            sequence,
            previous_digest: self.head_digest.clone(),
            command_id,
            command_digest,
            command,
            entry_digest: String::new(),
        };
        entry.entry_digest = entry_digest(&entry)?;
        Ok(Prepared::New(Box::new(entry)))
    }

    pub(crate) fn replay(&mut self, entry: LogEntry) -> Result<(), DagError> {
        if entry.version != LOG_VERSION {
            return Err(DagError::Corrupt(format!(
                "unsupported command-log version {}",
                entry.version
            )));
        }
        if entry.graph_id != self.config.graph_id {
            return Err(DagError::Corrupt("graph id changed inside the log".into()));
        }
        let expected = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| DagError::Corrupt("sequence overflow".into()))?;
        if entry.sequence != expected {
            return Err(DagError::Corrupt(format!(
                "sequence gap: expected {}, got {}",
                expected, entry.sequence
            )));
        }
        if entry.previous_digest != self.head_digest {
            return Err(DagError::Corrupt(
                "previous digest does not match the head".into(),
            ));
        }
        if entry.command_id.0 == 0 {
            return Err(DagError::Corrupt(
                "command id zero is not valid during replay".into(),
            ));
        }
        if digest_json(&entry.command)? != entry.command_digest {
            return Err(DagError::Corrupt("command digest mismatch".into()));
        }
        if entry_digest(&entry)? != entry.entry_digest {
            return Err(DagError::Corrupt("entry digest mismatch".into()));
        }
        if self.commands.contains_key(&entry.command_id) {
            return Err(DagError::Corrupt(
                "duplicate command id was appended".into(),
            ));
        }
        if self.sequence as usize >= self.config.limits.max_events {
            return Err(DagError::Corrupt(
                "event ceiling exceeded by the log".into(),
            ));
        }
        self.validate_command(&entry.command)
            .map_err(|error| DagError::Corrupt(error.to_string()))?;
        self.commit(entry);
        Ok(())
    }

    pub(crate) fn commit(&mut self, entry: LogEntry) {
        self.apply_validated(&entry.command);
        self.sequence = entry.sequence;
        self.head_digest = entry.entry_digest;
        self.commands.insert(
            entry.command_id,
            CommandReceipt {
                sequence: entry.sequence,
                command_digest: entry.command_digest,
            },
        );
    }

    fn apply_validated(&mut self, command: &Command) {
        match command {
            Command::CreateTask { spec, .. } => self.apply_create(spec.clone()),
            Command::StartTask { task, .. } => {
                self.tasks.get_mut(task).expect("validated task").state = TaskState::Running;
            }
            Command::RegisterAttempt { attempt, .. } => {
                self.attempts.insert(
                    attempt.id,
                    Attempt {
                        spec: attempt.clone(),
                        state: AttemptState::Registered,
                    },
                );
            }
            Command::StartAttempt { attempt, .. } => {
                self.attempts
                    .get_mut(attempt)
                    .expect("validated attempt")
                    .state = AttemptState::Running;
            }
            Command::CompleteAttempt {
                attempt,
                completion,
                disposition,
                result_digest,
                code,
                detail,
                ..
            } => {
                let state = match completion {
                    AttemptCompletion::Succeeded => AttemptState::Succeeded {
                        result_digest: result_digest.clone().expect("validated digest"),
                        disposition: *disposition,
                    },
                    AttemptCompletion::Failed => AttemptState::Failed {
                        code: code.clone().expect("validated code"),
                        detail: detail.clone().unwrap_or_default(),
                        disposition: *disposition,
                    },
                    AttemptCompletion::Cancelled => AttemptState::Cancelled {
                        reason: detail.clone().expect("validated cancellation reason"),
                        disposition: *disposition,
                    },
                    AttemptCompletion::UnknownEffect => AttemptState::UnknownEffect {
                        reason: detail.clone().expect("validated unknown-effect reason"),
                    },
                };
                self.attempts
                    .get_mut(attempt)
                    .expect("validated attempt")
                    .state = state;
            }
            Command::ChargeBudget { task, delta, .. } => {
                let target = self.tasks.get_mut(task).expect("validated task");
                target.usage = target
                    .usage
                    .checked_add(*delta)
                    .expect("validated budget sum");
            }
            Command::SendMessage { message, .. } => {
                self.tasks
                    .get_mut(&message.to)
                    .expect("validated recipient")
                    .inbox
                    .push(message.id);
                self.messages.insert(message.id, message.clone());
            }
            Command::AcknowledgeMessage { message, .. } => {
                self.messages
                    .get_mut(message)
                    .expect("validated message")
                    .delivery = DeliveryState::Acknowledged;
            }
            Command::RegisterJoin { join, .. } => {
                let mut canonical = join.clone();
                canonical.members.sort_unstable();
                self.joins.insert(join.id, canonical);
            }
            Command::RequestCancel { task, reason, .. } => {
                let affected = self
                    .tasks
                    .keys()
                    .copied()
                    .filter(|candidate| self.is_ancestor_or_self(*task, *candidate))
                    .collect::<Vec<_>>();
                for id in affected {
                    let target = self.tasks.get_mut(&id).expect("known affected task");
                    match target.state {
                        TaskState::Blocked | TaskState::Ready => {
                            target.state = TaskState::Cancelled {
                                reason: reason.clone(),
                            };
                        }
                        TaskState::Running => {
                            target.state = TaskState::Cancelling {
                                reason: reason.clone(),
                            };
                        }
                        _ => {}
                    }
                }
                self.resolve_blocked();
            }
            Command::CompleteTask {
                task,
                completion,
                result_digest,
                code,
                detail,
                ..
            } => {
                let preserved_cancel_reason = self.tasks.get(task).and_then(|target| {
                    if let TaskState::Cancelling { reason } = &target.state {
                        Some(reason.clone())
                    } else {
                        None
                    }
                });
                let state = match completion {
                    Completion::Succeeded => TaskState::Succeeded {
                        result_digest: result_digest.clone().expect("validated digest"),
                    },
                    Completion::Failed => TaskState::Failed {
                        code: code.clone().expect("validated code"),
                        detail: detail.clone().unwrap_or_default(),
                    },
                    // A cancellation acknowledgement is bound to the durable cause already in
                    // state. Validation requires the wire reason to match, but projection still
                    // uses the stored value so a late worker response cannot replace it.
                    Completion::Cancelled => TaskState::Cancelled {
                        reason: preserved_cancel_reason.unwrap_or_else(|| {
                            detail.clone().expect("validated cancellation reason")
                        }),
                    },
                };
                self.tasks.get_mut(task).expect("validated task").state = state;
                self.resolve_blocked();
            }
        }
    }

    fn apply_create(&mut self, mut spec: TaskSpec) {
        spec.dependencies.sort_unstable();
        let hierarchy_depth = spec
            .parent
            .and_then(|parent| self.tasks.get(&parent))
            .map_or(0, |parent| parent.hierarchy_depth + 1);
        let dependency_depth = spec
            .dependencies
            .iter()
            .filter_map(|dependency| self.tasks.get(dependency))
            .map(|dependency| dependency.dependency_depth + 1)
            .max()
            .unwrap_or(iteron_tunables::param_integer(
                "workflow.task_dag.reducer.root_dependency_depth",
                ROOT_DEPENDENCY_DEPTH,
            ));
        let state = initial_state(&self.tasks, &spec.dependencies);
        let reservation = spec.budget.reservable();
        match spec.parent {
            Some(parent) => {
                let parent = self.tasks.get_mut(&parent).expect("validated parent");
                parent.child_reservations = parent
                    .child_reservations
                    .checked_add(reservation)
                    .expect("validated reservation sum");
            }
            None => {
                self.root_reservations = self
                    .root_reservations
                    .checked_add(reservation)
                    .expect("validated root reservation sum");
            }
        }
        self.edge_count += spec.dependencies.len() + usize::from(spec.parent.is_some());
        self.tasks.insert(
            spec.id,
            Task {
                spec,
                state,
                usage: BudgetUsage::default(),
                hierarchy_depth,
                dependency_depth,
                inbox: Vec::new(),
                child_reservations: BudgetReservation::default(),
            },
        );
        self.resolve_blocked();
    }

    fn resolve_blocked(&mut self) {
        for _ in 0..self.tasks.len() {
            let transitions = self
                .tasks
                .iter()
                .filter(|(_, task)| matches!(task.state, TaskState::Blocked))
                .filter_map(|(id, task)| {
                    let state = initial_state(&self.tasks, &task.spec.dependencies);
                    (!matches!(state, TaskState::Blocked)).then_some((*id, state))
                })
                .collect::<Vec<_>>();
            if transitions.is_empty() {
                break;
            }
            for (id, state) in transitions {
                self.tasks.get_mut(&id).expect("known blocked task").state = state;
            }
        }
    }
}

fn initial_state(tasks: &BTreeMap<TaskId, Task>, dependencies: &[TaskId]) -> TaskState {
    if let Some(dependency) = dependencies.iter().copied().find(|dependency| {
        tasks
            .get(dependency)
            .is_some_and(|task| task.state.is_terminal() && !task.state.succeeded())
    }) {
        return TaskState::SkippedDependency { dependency };
    }
    if dependencies.iter().all(|dependency| {
        tasks
            .get(dependency)
            .is_some_and(|task| task.state.succeeded())
    }) {
        TaskState::Ready
    } else {
        TaskState::Blocked
    }
}
