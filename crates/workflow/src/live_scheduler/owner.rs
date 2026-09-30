use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::task_dag::BudgetUsage;

use super::ports::{WorkflowControllerPort, WorkflowPlanJournal};
use super::types::{
    AgentTurnLeaseV1, MAX_DIAGNOSTIC_BYTES, MAX_PLAN_CHANGES, MAX_PLAN_REQUESTS,
    MAX_PLAN_REVISIONS, MAX_SCHEDULER_EVENTS, ScheduledTaskV1, StoredReceipt,
    WORKFLOW_SCHEDULER_PORT_VERSION, WorkflowCompletionV1, WorkflowConfigV1, WorkflowDispatchError,
    WorkflowNodeRecordV1, WorkflowNodeStateV1 as State, WorkflowPlanChangeV1,
    WorkflowPlanReceiptV1, WorkflowReplanV1, WorkflowSchedulerError as Error,
    WorkflowSchedulerSnapshotV1, WorkflowStoreError,
};
use super::validation;

/// Sole owner of live plan state. Neither a planner nor the controller can mutate its snapshot.
/// A successful mutation follows a durable commit; ambiguous publication poisons all commands.
pub struct WorkflowScheduler<J: WorkflowPlanJournal> {
    journal: J,
    snapshot: WorkflowSchedulerSnapshotV1,
    poisoned: bool,
}

impl<J: WorkflowPlanJournal> WorkflowScheduler<J> {
    pub fn open(mut journal: J, config: WorkflowConfigV1) -> Result<Self, Error> {
        validation::config(&config)?;
        let stored = journal.load()?;
        let is_new = stored.is_none();
        let snapshot = match stored {
            Some(snapshot) => {
                validation::snapshot(&snapshot)?;
                if snapshot.config != config {
                    return Err(Error::Invalid("stored immutable config differs"));
                }
                snapshot
            }
            None => WorkflowSchedulerSnapshotV1 {
                version: WORKFLOW_SCHEDULER_PORT_VERSION,
                config,
                sequence: 0,
                revision: 0,
                nodes: BTreeMap::new(),
                reserved: BudgetUsage::default(),
                receipts: BTreeMap::new(),
            },
        };
        let mut owner = Self {
            journal,
            snapshot,
            poisoned: false,
        };
        if is_new {
            owner.publish(owner.snapshot.clone(), None)?;
        }
        let mut recovered = owner.snapshot.clone();
        let mut changed = false;
        for node in recovered.nodes.values_mut() {
            if node.state.active() {
                node.state = State::RecoveryRequired {
                    attempt: node
                        .state
                        .attempt()
                        .ok_or(Error::Invalid("active state has no attempt"))?,
                    lease: node.state.lease(),
                    reason: "restart requires controller/supervisor effect reconciliation".into(),
                };
                changed = true;
            }
        }
        if changed {
            owner.commit(recovered)?;
        }
        Ok(owner)
    }

    pub fn snapshot(&self) -> Result<WorkflowSchedulerSnapshotV1, Error> {
        self.ensure_live()?;
        Ok(self.snapshot.clone())
    }

    /// Host-authenticated planning entry point. Model proposals reach this method only through a
    /// controller-owned authority check; JSON contains no operator/sender field.
    pub fn replan(
        &mut self,
        request_id: &str,
        command: WorkflowReplanV1,
    ) -> Result<WorkflowPlanReceiptV1, Error> {
        self.ensure_live()?;
        validation::identifier(request_id)?;
        if command.changes.is_empty() || command.changes.len() > MAX_PLAN_CHANGES {
            return Err(Error::Capacity("plan changes"));
        }
        // Bound untrusted fields before hashing/serialization allocates a second payload copy.
        for change in &command.changes {
            match change {
                WorkflowPlanChangeV1::Add { node }
                | WorkflowPlanChangeV1::ReplacePending { node }
                | WorkflowPlanChangeV1::Retry { node } => {
                    validation::node(node, &self.snapshot.config)?
                }
                WorkflowPlanChangeV1::RemovePending { node_id } if *node_id == 0 => {
                    return Err(Error::Invalid("node id must be nonzero"));
                }
                WorkflowPlanChangeV1::RemovePending { .. } => {}
            }
        }
        let encoded = serde_json::to_vec(&command).map_err(|_| Error::Serialization)?;
        let digest = hex::encode(Sha256::digest(encoded));
        if let Some(stored) = self.snapshot.receipts.get(request_id) {
            if stored.digest != digest {
                return Err(Error::RequestConflict);
            }
            let mut receipt = stored.receipt.clone();
            receipt.replayed = true;
            return Ok(receipt);
        }
        if self.snapshot.receipts.len() >= MAX_PLAN_REQUESTS {
            return Err(Error::Capacity("request receipt"));
        }
        if command.expected_revision != self.snapshot.revision {
            return Err(Error::RevisionConflict {
                expected: command.expected_revision,
                actual: self.snapshot.revision,
            });
        }
        if self.snapshot.revision >= MAX_PLAN_REVISIONS {
            return Err(Error::Capacity("plan revisions"));
        }
        let mut next = self.snapshot.clone();
        let mut touched = BTreeSet::new();
        for change in command.changes {
            let id = match &change {
                WorkflowPlanChangeV1::Add { node }
                | WorkflowPlanChangeV1::ReplacePending { node }
                | WorkflowPlanChangeV1::Retry { node } => node.id,
                WorkflowPlanChangeV1::RemovePending { node_id } => *node_id,
            };
            if !touched.insert(id) {
                return Err(Error::Invalid("node appears twice in a plan revision"));
            }
            match change {
                WorkflowPlanChangeV1::Add { node } => {
                    validation::node(&node, &next.config)?;
                    if next.nodes.contains_key(&node.id) {
                        return Err(Error::Transition("node id cannot be reused"));
                    }
                    next.nodes.insert(
                        node.id,
                        WorkflowNodeRecordV1 {
                            node,
                            state: State::Pending,
                            next_attempt: 1,
                            usage: BudgetUsage::default(),
                            attempt_usage: BudgetUsage::default(),
                            reserved_budget: BudgetUsage::default(),
                        },
                    );
                }
                WorkflowPlanChangeV1::ReplacePending { node } => {
                    validation::node(&node, &next.config)?;
                    let record = next.nodes.get_mut(&id).ok_or(Error::UnknownNode(id))?;
                    if record.state != State::Pending {
                        return Err(Error::Transition("only pending work may be edited"));
                    }
                    record.node = node;
                }
                WorkflowPlanChangeV1::RemovePending { .. } => {
                    let record = next.nodes.get_mut(&id).ok_or(Error::UnknownNode(id))?;
                    if record.state != State::Pending {
                        return Err(Error::Transition("only pending work may be removed"));
                    }
                    record.state = State::Removed;
                }
                WorkflowPlanChangeV1::Retry { node } => {
                    validation::node(&node, &next.config)?;
                    let record = next.nodes.get_mut(&id).ok_or(Error::UnknownNode(id))?;
                    if !matches!(record.state, State::Failed { .. } | State::Cancelled { .. }) {
                        return Err(Error::Transition(
                            "retry requires definite failed/cancelled effect settlement",
                        ));
                    }
                    record.node = node;
                    record.state = State::Pending;
                }
            }
        }
        validation::graph(&next.nodes, &next.config)?;
        next.revision += 1;
        let receipt = WorkflowPlanReceiptV1 {
            version: WORKFLOW_SCHEDULER_PORT_VERSION,
            revision: next.revision,
            sequence: next
                .sequence
                .checked_add(1)
                .ok_or(Error::Capacity("event"))?,
            replayed: false,
        };
        next.receipts.insert(
            request_id.into(),
            StoredReceipt {
                digest,
                receipt: receipt.clone(),
            },
        );
        self.commit(next)?;
        Ok(receipt)
    }

    /// Stable ready ordering. Unknown effects quarantine the workflow; an assigned agent can own
    /// only one active workflow turn, and the controller independently checks global ownership.
    pub fn ready_nodes(&self, now_unix_ms: u64) -> Result<Vec<u64>, Error> {
        self.ensure_live()?;
        if now_unix_ms < self.snapshot.config.started_at_unix_ms {
            return Err(Error::Invalid("host clock must be nonzero"));
        }
        if now_unix_ms >= self.snapshot.config.deadline_unix_ms
            || self
                .snapshot
                .nodes
                .values()
                .any(|n| matches!(n.state, State::RecoveryRequired { .. }))
        {
            return Ok(Vec::new());
        }
        let active = self
            .snapshot
            .nodes
            .values()
            .filter(|n| n.state.active())
            .collect::<Vec<_>>();
        let slots = self
            .snapshot
            .config
            .max_concurrency
            .saturating_sub(active.len());
        let mut occupied = active
            .iter()
            .map(|n| n.node.assigned_agent)
            .collect::<BTreeSet<_>>();
        let mut ready = Vec::new();
        for (id, record) in &self.snapshot.nodes {
            if ready.len() >= slots {
                break;
            }
            if record.state == State::Pending
                && !occupied.contains(&record.node.assigned_agent)
                && record.node.dependencies.iter().all(|id| {
                    self.snapshot.nodes.get(id).is_some_and(|dependency| {
                        matches!(dependency.state, State::Succeeded { .. })
                    })
                })
                && validation::add_reservation(
                    self.snapshot.reserved,
                    self.snapshot.config.budget,
                    record.node.budget,
                )
                .is_ok()
            {
                ready.push(*id);
                occupied.insert(record.node.assigned_agent);
            }
        }
        Ok(ready)
    }

    pub async fn dispatch<C: WorkflowControllerPort + ?Sized>(
        &mut self,
        node_id: u64,
        controller: &C,
        now_unix_ms: u64,
    ) -> Result<State, Error> {
        self.ensure_port(controller)?;
        if !self.ready_nodes(now_unix_ms)?.contains(&node_id) {
            return Err(Error::Transition(
                "node is blocked, busy, quarantined, expired or out of budget",
            ));
        }
        let mut next = self.snapshot.clone();
        let record = next
            .nodes
            .get_mut(&node_id)
            .ok_or(Error::UnknownNode(node_id))?;
        let attempt = record.next_attempt;
        record.next_attempt = attempt.checked_add(1).ok_or(Error::Capacity("attempt"))?;
        let deadline_unix_ms = now_unix_ms
            .saturating_add(record.node.budget.max_wall_ms)
            .min(next.config.deadline_unix_ms);
        record.state = State::Dispatching {
            attempt,
            deadline_unix_ms,
        };
        record.attempt_usage = BudgetUsage::default();
        record.reserved_budget = validation::add_reservation(
            record.reserved_budget,
            next.config.budget,
            record.node.budget,
        )?;
        next.reserved =
            validation::add_reservation(next.reserved, next.config.budget, record.node.budget)?;
        let task = ScheduledTaskV1 {
            workflow_id: next.config.workflow_id.clone(),
            node_id,
            attempt,
            input_digest: record.node.input_digest.clone(),
            assigned_agent: record.node.assigned_agent,
            task: record.node.task.clone(),
            budget: record.node.budget,
            deadline_unix_ms,
        };
        self.commit(next)?;
        // The port is a bounded admission operation, not the duration of the model turn.
        let timeout =
            Duration::from_millis(deadline_unix_ms.saturating_sub(now_unix_ms).min(5_000));
        let reply = tokio::time::timeout(timeout, controller.dispatch(task.clone()))
            .await
            .unwrap_or_else(|_| {
                Err(WorkflowDispatchError::OutcomeUnknown(
                    "controller admission timed out".into(),
                ))
            });
        let state = match reply {
            Ok(handle) if validation::lease(handle, task.assigned_agent).is_ok() => {
                State::Running {
                    attempt,
                    lease: handle,
                    deadline_unix_ms,
                }
            }
            Ok(_) => State::RecoveryRequired {
                attempt,
                lease: None,
                reason: "controller returned a mismatched or invalid active lease".into(),
            },
            Err(WorkflowDispatchError::NotApplied(detail)) => State::Failed {
                attempt,
                detail: bounded_detail(&detail),
            },
            Err(WorkflowDispatchError::OutcomeUnknown(detail)) => State::RecoveryRequired {
                attempt,
                lease: None,
                reason: bounded_detail(&detail),
            },
        };
        let mut next = self.snapshot.clone();
        next.nodes
            .get_mut(&node_id)
            .ok_or(Error::UnknownNode(node_id))?
            .state = state.clone();
        self.commit(next)?;
        Ok(state)
    }

    pub async fn interrupt<C: WorkflowControllerPort + ?Sized>(
        &mut self,
        node_id: u64,
        controller: &C,
    ) -> Result<State, Error> {
        self.ensure_port(controller)?;
        let record = self
            .snapshot
            .nodes
            .get(&node_id)
            .ok_or(Error::UnknownNode(node_id))?;
        let State::Running {
            attempt,
            lease,
            deadline_unix_ms,
        } = record.state
        else {
            return Err(Error::Transition(
                "interrupt requires a running workflow node",
            ));
        };
        let cancelling = State::Cancelling {
            attempt,
            lease,
            deadline_unix_ms,
        };
        let mut next = self.snapshot.clone();
        next.nodes
            .get_mut(&node_id)
            .ok_or(Error::UnknownNode(node_id))?
            .state = cancelling.clone();
        self.commit(next)?;
        let reply = tokio::time::timeout(Duration::from_secs(5), controller.interrupt(lease))
            .await
            .unwrap_or_else(|_| {
                Err(WorkflowDispatchError::OutcomeUnknown(
                    "controller interrupt timed out".into(),
                ))
            });
        if let Err(error) = reply {
            let mut next = self.snapshot.clone();
            next.nodes
                .get_mut(&node_id)
                .ok_or(Error::UnknownNode(node_id))?
                .state = match error {
                WorkflowDispatchError::NotApplied(_) => State::Running {
                    attempt,
                    lease,
                    deadline_unix_ms,
                },
                WorkflowDispatchError::OutcomeUnknown(detail) => State::RecoveryRequired {
                    attempt,
                    lease: Some(lease),
                    reason: bounded_detail(&detail),
                },
            };
            self.commit(next)?;
            return Err(Error::Transition(
                "interrupt refused or effect unknown; inspect node state",
            ));
        }
        Ok(cancelling)
    }

    pub fn expired_nodes(&self, now_unix_ms: u64) -> Result<Vec<u64>, Error> {
        self.ensure_live()?;
        Ok(self
            .snapshot
            .nodes
            .iter()
            .filter_map(|(id, record)| match record.state {
                State::Running {
                    deadline_unix_ms, ..
                } if now_unix_ms >= deadline_unix_ms => Some(*id),
                _ => None,
            })
            .collect())
    }

    /// Record actual supervisor completion. Cancellation acceptance alone cannot call this. The
    /// exact attempt and lease reject late output even when a node has been explicitly reassigned.
    pub fn settle(
        &mut self,
        node_id: u64,
        attempt: u64,
        lease: AgentTurnLeaseV1,
        completion: WorkflowCompletionV1,
        usage: BudgetUsage,
        effects_known: bool,
    ) -> Result<State, Error> {
        self.ensure_live()?;
        let record = self
            .snapshot
            .nodes
            .get(&node_id)
            .ok_or(Error::UnknownNode(node_id))?;
        if record.state.attempt() != Some(attempt)
            || record.state.lease() != Some(lease)
            || !matches!(
                record.state,
                State::Running { .. } | State::Cancelling { .. } | State::RecoveryRequired { .. }
            )
        {
            return Err(Error::StaleLease);
        }
        self.settle_inner(
            node_id,
            attempt,
            Some(lease),
            completion,
            usage,
            effects_known,
        )
    }

    /// Host-only orphan reconciliation for a dispatch with no returned lease. It requires actual
    /// controller/supervisor evidence and never changes an unknown effect into automatic retry.
    pub fn reconcile_stopped(
        &mut self,
        node_id: u64,
        attempt: u64,
        completion: WorkflowCompletionV1,
        usage: BudgetUsage,
        effects_known: bool,
    ) -> Result<State, Error> {
        self.ensure_live()?;
        let record = self
            .snapshot
            .nodes
            .get(&node_id)
            .ok_or(Error::UnknownNode(node_id))?;
        if !matches!(record.state, State::RecoveryRequired { .. })
            || record.state.attempt() != Some(attempt)
        {
            return Err(Error::StaleLease);
        }
        self.settle_inner(
            node_id,
            attempt,
            record.state.lease(),
            completion,
            usage,
            effects_known,
        )
    }

    fn settle_inner(
        &mut self,
        node_id: u64,
        attempt: u64,
        lease: Option<AgentTurnLeaseV1>,
        completion: WorkflowCompletionV1,
        usage: BudgetUsage,
        effects_known: bool,
    ) -> Result<State, Error> {
        let mut next = self.snapshot.clone();
        let record = next
            .nodes
            .get_mut(&node_id)
            .ok_or(Error::UnknownNode(node_id))?;
        let delta = BudgetUsage {
            turns: usage
                .turns
                .checked_sub(record.attempt_usage.turns)
                .ok_or(Error::Budget("cumulative turn usage decreased"))?,
            tokens: usage
                .tokens
                .checked_sub(record.attempt_usage.tokens)
                .ok_or(Error::Budget("cumulative token usage decreased"))?,
            cost_microusd: usage
                .cost_microusd
                .checked_sub(record.attempt_usage.cost_microusd)
                .ok_or(Error::Budget("cumulative cost usage decreased"))?,
            wall_ms: usage
                .wall_ms
                .checked_sub(record.attempt_usage.wall_ms)
                .ok_or(Error::Budget("cumulative wall usage decreased"))?,
        };
        record.usage = record
            .usage
            .checked_add(delta)
            .ok_or(Error::Budget("actual usage counter overflow"))?;
        record.attempt_usage = usage;
        let state = if !effects_known || !validation::usage_fits(usage, record.node.budget) {
            State::RecoveryRequired {
                attempt,
                lease,
                reason: "effect outcome unknown or actual usage exceeds admission".into(),
            }
        } else {
            match completion {
                WorkflowCompletionV1::Succeeded { result_digest } => {
                    validation::digest(&result_digest)?;
                    if matches!(record.state, State::Cancelling { .. }) {
                        return Err(Error::Transition(
                            "cancelled task needs explicit cancelled settlement",
                        ));
                    }
                    State::Succeeded {
                        attempt,
                        result_digest,
                    }
                }
                WorkflowCompletionV1::Failed { detail } => {
                    validation::text(&detail, MAX_DIAGNOSTIC_BYTES)?;
                    State::Failed { attempt, detail }
                }
                WorkflowCompletionV1::Cancelled { detail } => {
                    validation::text(&detail, MAX_DIAGNOSTIC_BYTES)?;
                    State::Cancelled { attempt, detail }
                }
            }
        };
        record.state = state.clone();
        self.commit(next)?;
        Ok(state)
    }

    fn ensure_port<C: WorkflowControllerPort + ?Sized>(&self, controller: &C) -> Result<(), Error> {
        self.ensure_live()?;
        if controller.port_version() != WORKFLOW_SCHEDULER_PORT_VERSION {
            return Err(Error::Invalid("unsupported controller port version"));
        }
        Ok(())
    }

    fn ensure_live(&self) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        Ok(())
    }

    fn commit(&mut self, mut next: WorkflowSchedulerSnapshotV1) -> Result<(), Error> {
        if self.snapshot.sequence >= MAX_SCHEDULER_EVENTS {
            return Err(Error::Capacity("event"));
        }
        next.sequence = self.snapshot.sequence + 1;
        self.publish(next, Some(self.snapshot.sequence))
    }

    fn publish(
        &mut self,
        next: WorkflowSchedulerSnapshotV1,
        expected: Option<u64>,
    ) -> Result<(), Error> {
        self.ensure_live()?;
        validation::snapshot(&next)?;
        match self.journal.commit(expected, &next) {
            Ok(()) => {
                self.snapshot = next;
                Ok(())
            }
            Err(error) => {
                if matches!(
                    error,
                    WorkflowStoreError::OutcomeUnknown | WorkflowStoreError::Conflict
                ) {
                    self.poisoned = true;
                }
                Err(error.into())
            }
        }
    }
}

fn bounded_detail(value: &str) -> String {
    let mut end = value.len().min(MAX_DIAGNOSTIC_BYTES);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    let result = value[..end].replace('\0', "?");
    if result.is_empty() {
        "controller refused the operation".into()
    } else {
        result
    }
}
