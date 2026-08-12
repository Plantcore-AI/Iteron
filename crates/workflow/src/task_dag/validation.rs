use std::collections::BTreeSet;

use super::DagError;
use super::hash::digest_json;
use super::reducer::TaskDag;
use super::types::{
    Actor, AttemptAssignment, AttemptCompletion, AttemptDisposition, AttemptId, AttemptRetryCause,
    AttemptSpec, AttemptState, BudgetReservation, BudgetUsage, Command, Completion, DeliveryState,
    HARD_MAX_ATTEMPTS, JoinSpec, MAX_LABEL_BYTES, MAX_MESSAGE_BYTES, MAX_REASON_BYTES, Task,
    TaskId, TaskMessage, TaskSpec, TaskState, valid_digest, validate_identifier,
};
use super::validation_support::{budget_fits, transition, validate_visible};

impl TaskDag {
    pub(super) fn validate_command(&self, command: &Command) -> Result<(), DagError> {
        match command {
            Command::CreateTask { actor, spec } => self.validate_create(*actor, spec),
            Command::StartTask { actor, task } => {
                if *actor != Actor::Controller {
                    return Err(DagError::Authority("only the controller may admit a task"));
                }
                let task = self.require_task(*task)?;
                if !matches!(task.state, TaskState::Ready) {
                    return Err(transition(task.spec.id, "task is not ready"));
                }
                if let Some(parent) = task.spec.parent {
                    let parent = self.require_task(parent)?;
                    if !matches!(parent.state, TaskState::Running) {
                        return Err(transition(
                            task.spec.id,
                            "task cannot start before its parent is running",
                        ));
                    }
                }
                Ok(())
            }
            Command::RegisterAttempt { actor, attempt } => {
                self.validate_attempt_registration(*actor, attempt)
            }
            Command::StartAttempt { actor, attempt } => {
                if *actor != Actor::Controller {
                    return Err(DagError::Authority(
                        "only the controller may dispatch an attempt",
                    ));
                }
                let attempt = self.require_attempt(*attempt)?;
                if !matches!(attempt.state, AttemptState::Registered) {
                    return Err(DagError::Invalid("attempt is not registered"));
                }
                let task = self.require_task(attempt.spec.task)?;
                if !matches!(task.state, TaskState::Running) {
                    return Err(transition(task.spec.id, "attempt task is not running"));
                }
                Ok(())
            }
            Command::CompleteAttempt {
                actor,
                attempt,
                completion,
                disposition,
                result_digest,
                code,
                detail,
            } => self.validate_attempt_completion(
                *actor,
                *attempt,
                *completion,
                *disposition,
                result_digest.as_deref(),
                code.as_deref(),
                detail.as_deref(),
            ),
            Command::ChargeBudget { actor, task, delta } => {
                if *actor != Actor::Controller {
                    return Err(DagError::Authority(
                        "only the controller may journal verified budget usage",
                    ));
                }
                let task = self.require_task(*task)?;
                if !matches!(
                    task.state,
                    TaskState::Running | TaskState::Cancelling { .. }
                ) {
                    return Err(transition(task.spec.id, "task is not running"));
                }
                if *delta == BudgetUsage::default() {
                    return Err(DagError::Budget("zero usage deltas are not journaled"));
                }
                let usage = task
                    .usage
                    .checked_add(*delta)
                    .ok_or(DagError::Budget("usage counter overflow"))?;
                budget_fits(
                    task.spec.budget,
                    usage,
                    task.child_reservations,
                    BudgetReservation::default(),
                )
            }
            Command::SendMessage { actor, message } => self.validate_message(*actor, message),
            Command::AcknowledgeMessage { actor, message } => {
                let message = self
                    .messages
                    .get(message)
                    .ok_or(DagError::UnknownMessage(message.0))?;
                match *actor {
                    Actor::Controller => {}
                    Actor::Task(id) if id == message.to => self.require_active_actor(*actor)?,
                    Actor::Task(_) => {
                        return Err(DagError::Authority(
                            "only the recipient or controller may acknowledge a message",
                        ));
                    }
                }
                if message.delivery != DeliveryState::Pending {
                    return Err(DagError::Invalid("message is already acknowledged"));
                }
                Ok(())
            }
            Command::RegisterJoin { actor, join } => self.validate_join(*actor, join),
            Command::RequestCancel {
                actor,
                task,
                reason,
            } => self.validate_cancel(*actor, *task, reason),
            Command::CompleteTask {
                actor,
                task,
                completion,
                result_digest,
                code,
                detail,
            } => self.validate_completion(
                *actor,
                *task,
                *completion,
                result_digest.as_deref(),
                code.as_deref(),
                detail.as_deref(),
            ),
        }
    }

    fn validate_create(&self, actor: Actor, spec: &TaskSpec) -> Result<(), DagError> {
        if spec.id.0 == 0 {
            return Err(DagError::Invalid("task id must be non-zero"));
        }
        if self.tasks.contains_key(&spec.id) {
            return Err(DagError::DuplicateTask(spec.id.0));
        }
        if spec.declaration_index == Some(0) {
            return Err(DagError::Invalid("task declaration index must be non-zero"));
        }
        if self.tasks.len() >= self.config.limits.max_tasks {
            return Err(DagError::Capacity { kind: "task" });
        }
        validate_identifier(&spec.label, MAX_LABEL_BYTES, "label").map_err(DagError::Invalid)?;
        spec.budget.validate().map_err(DagError::Budget)?;
        if spec.dependencies.len() > self.config.limits.max_edges {
            return Err(DagError::Capacity { kind: "edge" });
        }
        let dependencies = Command::dependency_set(spec);
        if dependencies.len() != spec.dependencies.len() {
            return Err(DagError::Invalid("task dependencies contain duplicates"));
        }
        let new_edges = dependencies
            .len()
            .checked_add(usize::from(spec.parent.is_some()))
            .ok_or(DagError::Capacity { kind: "edge" })?;
        if self.edge_count.saturating_add(new_edges) > self.config.limits.max_edges {
            return Err(DagError::Capacity { kind: "edge" });
        }

        let (hierarchy_depth, reservation_limit, usage, reserved) = match spec.parent {
            Some(parent_id) => {
                let parent = self.require_task(parent_id)?;
                if parent.state.is_terminal()
                    || matches!(parent.state, TaskState::Cancelling { .. })
                {
                    return Err(transition(parent_id, "parent no longer accepts children"));
                }
                match actor {
                    Actor::Controller => {}
                    Actor::Task(id) if id == parent_id => self.require_active_actor(actor)?,
                    Actor::Task(_) => {
                        return Err(DagError::Authority(
                            "a task may create only its own direct child",
                        ));
                    }
                }
                (
                    parent.hierarchy_depth.saturating_add(1),
                    parent.spec.budget,
                    parent.usage,
                    parent.child_reservations,
                )
            }
            None => {
                if actor != Actor::Controller {
                    return Err(DagError::Authority(
                        "only the controller may create a root task",
                    ));
                }
                (
                    0,
                    self.config.budget,
                    BudgetUsage::default(),
                    self.root_reservations,
                )
            }
        };
        if hierarchy_depth > self.config.limits.max_hierarchy_depth {
            return Err(DagError::Capacity {
                kind: "hierarchy depth",
            });
        }
        budget_fits(reservation_limit, usage, reserved, spec.budget.reservable())?;
        let remaining_wall = reservation_limit
            .max_wall_ms
            .checked_sub(usage.wall_ms)
            .ok_or(DagError::Budget(
                "wall-clock usage exceeds its parent ceiling",
            ))?;
        if spec.budget.max_wall_ms > remaining_wall {
            return Err(DagError::Budget(
                "wall-clock budget exceeds its parent's remaining ceiling",
            ));
        }

        let mut dependency_depth = 0usize;
        for dependency in dependencies {
            if dependency == spec.id {
                return Err(DagError::Invalid("task cannot depend on itself"));
            }
            let dependency_task = self.require_task(dependency)?;
            if spec
                .parent
                .is_some_and(|parent| self.is_ancestor_or_self(dependency, parent))
            {
                return Err(DagError::Invalid(
                    "a child cannot depend on its parent or another ancestor",
                ));
            }
            if spec
                .parent
                .is_some_and(|parent| self.waits_for(dependency, parent))
            {
                return Err(DagError::Invalid(
                    "task creation would cycle dependency and parent-child wait edges",
                ));
            }
            dependency_depth = dependency_depth.max(dependency_task.dependency_depth + 1);
        }
        if dependency_depth > self.config.limits.max_dependency_depth {
            return Err(DagError::Capacity {
                kind: "dependency depth",
            });
        }
        Ok(())
    }

    fn validate_attempt_registration(
        &self,
        actor: Actor,
        attempt: &AttemptSpec,
    ) -> Result<(), DagError> {
        if actor != Actor::Controller {
            return Err(DagError::Authority(
                "only the controller may register an attempt",
            ));
        }
        if attempt.id.0 == 0 {
            return Err(DagError::Invalid("attempt id must be non-zero"));
        }
        if self.attempts.contains_key(&attempt.id) {
            return Err(DagError::Invalid("attempt already exists"));
        }
        if self.attempts.len() >= HARD_MAX_ATTEMPTS {
            return Err(DagError::Capacity { kind: "attempt" });
        }
        let task = self.require_task(attempt.task)?;
        if !matches!(task.state, TaskState::Running) {
            return Err(transition(task.spec.id, "attempt task is not running"));
        }
        if !valid_digest(&attempt.input_digest) {
            return Err(DagError::Invalid(
                "attempt input digest must be exactly 64 hexadecimal bytes",
            ));
        }
        if attempt.lineage_version == 0 {
            if attempt.retry_of.is_some()
                || attempt.retry_cause.is_some()
                || attempt.prior_evidence_digest.is_some()
            {
                return Err(DagError::Invalid(
                    "legacy attempt lineage cannot carry version-one fields",
                ));
            }
            return Ok(());
        }
        if attempt.lineage_version != 1 {
            return Err(DagError::Invalid("unsupported attempt lineage version"));
        }
        match (
            attempt.retry_ordinal,
            attempt.assignment,
            attempt.retry_of,
            attempt.retry_cause,
            attempt.prior_evidence_digest.as_deref(),
        ) {
            (0, AttemptAssignment::Initial, None, None, None) => {}
            (
                retry_ordinal,
                AttemptAssignment::RetrySame | AttemptAssignment::Reassigned,
                Some(prior_id),
                Some(retry_cause),
                Some(evidence_digest),
            ) if retry_ordinal > 0 && valid_digest(evidence_digest) => {
                let prior = self.require_attempt(prior_id)?;
                if prior.spec.task != attempt.task {
                    return Err(DagError::Invalid(
                        "retry predecessor belongs to a different task",
                    ));
                }
                if prior.spec.retry_ordinal.checked_add(1) != Some(retry_ordinal) {
                    return Err(DagError::Invalid(
                        "retry ordinal must immediately follow its predecessor",
                    ));
                }
                if !prior.state.is_terminal() {
                    return Err(DagError::Invalid(
                        "retry predecessor must have a durable terminal",
                    ));
                }
                if matches!(prior.state, AttemptState::UnknownEffect { .. }) {
                    return Err(DagError::Invalid(
                        "an unknown-effect attempt may not be retried or reassigned",
                    ));
                }
                if digest_json(&prior.state)? != evidence_digest {
                    return Err(DagError::Invalid(
                        "retry predecessor evidence digest does not match its durable terminal",
                    ));
                }
                let cause_matches_terminal = match (&prior.state, retry_cause) {
                    (AttemptState::Succeeded { .. }, AttemptRetryCause::SchemaValidation) => true,
                    (AttemptState::Failed { code, .. }, AttemptRetryCause::ChildFailure) => {
                        code == "child_task_failed"
                    }
                    (AttemptState::Failed { code, .. }, AttemptRetryCause::NegativeTerminal) => {
                        code == "negative_terminal"
                    }
                    _ => false,
                };
                if !cause_matches_terminal {
                    return Err(DagError::Invalid(
                        "retry cause is inconsistent with its durable predecessor terminal",
                    ));
                }
            }
            _ => {
                return Err(DagError::Invalid(
                    "attempt assignment lineage is inconsistent",
                ));
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_attempt_completion(
        &self,
        actor: Actor,
        attempt_id: AttemptId,
        completion: AttemptCompletion,
        disposition: AttemptDisposition,
        result_digest: Option<&str>,
        code: Option<&str>,
        detail: Option<&str>,
    ) -> Result<(), DagError> {
        if actor != Actor::Controller {
            return Err(DagError::Authority(
                "only the controller may settle an attempt",
            ));
        }
        let attempt = self.require_attempt(attempt_id)?;
        if !matches!(attempt.state, AttemptState::Running) {
            return Err(DagError::Invalid("attempt is not running"));
        }
        match completion {
            AttemptCompletion::Succeeded => {
                if !result_digest.is_some_and(valid_digest)
                    || code.is_some()
                    || detail.is_some()
                    || matches!(
                        disposition,
                        AttemptDisposition::Negative | AttemptDisposition::UnknownEffect
                    )
                {
                    return Err(DagError::Invalid(
                        "attempt success requires one digest and a selected/loser disposition",
                    ));
                }
            }
            AttemptCompletion::Failed => {
                let code = code.ok_or(DagError::Invalid("attempt failure requires a code"))?;
                validate_identifier(code, 128, "code").map_err(DagError::Invalid)?;
                if let Some(detail) = detail {
                    validate_visible(detail, MAX_REASON_BYTES, "attempt failure detail")?;
                }
                if result_digest.is_some()
                    || !matches!(
                        disposition,
                        AttemptDisposition::Negative | AttemptDisposition::Loser
                    )
                {
                    return Err(DagError::Invalid(
                        "attempt failure requires a negative or loser disposition",
                    ));
                }
            }
            AttemptCompletion::Cancelled => {
                validate_visible(
                    detail.ok_or(DagError::Invalid("attempt cancellation requires a reason"))?,
                    MAX_REASON_BYTES,
                    "attempt cancellation reason",
                )?;
                if result_digest.is_some()
                    || code.is_some()
                    || disposition != AttemptDisposition::Loser
                {
                    return Err(DagError::Invalid(
                        "attempt cancellation must identify an unselected loser",
                    ));
                }
            }
            AttemptCompletion::UnknownEffect => {
                validate_visible(
                    detail.ok_or(DagError::Invalid("unknown effect requires a reason"))?,
                    MAX_REASON_BYTES,
                    "unknown-effect reason",
                )?;
                if result_digest.is_some()
                    || code.is_some()
                    || disposition != AttemptDisposition::UnknownEffect
                {
                    return Err(DagError::Invalid(
                        "unknown-effect terminal requires its exact disposition",
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_message(&self, actor: Actor, message: &TaskMessage) -> Result<(), DagError> {
        if message.id.0 == 0 {
            return Err(DagError::Invalid("message id must be non-zero"));
        }
        if self.messages.contains_key(&message.id) {
            return Err(DagError::DuplicateMessage(message.id.0));
        }
        if self.messages.len() >= self.config.limits.max_messages {
            return Err(DagError::Capacity { kind: "message" });
        }
        if message.delivery != DeliveryState::Pending {
            return Err(DagError::Invalid("new messages must begin pending"));
        }
        if message.payload.is_empty() || message.payload.len() > MAX_MESSAGE_BYTES {
            return Err(DagError::Invalid("message is empty or over its byte limit"));
        }
        let recipient = self.require_task(message.to)?;
        if recipient.state.is_terminal() {
            return Err(transition(
                message.to,
                "terminal task cannot receive a message",
            ));
        }
        match (actor, message.from) {
            (Actor::Controller, None) => {}
            (Actor::Task(actor_id), Some(from)) if actor_id == from => {
                self.require_active_actor(actor)?;
            }
            _ => {
                return Err(DagError::Authority(
                    "message provenance must match the sending actor",
                ));
            }
        }
        Ok(())
    }

    fn validate_join(&self, actor: Actor, join: &JoinSpec) -> Result<(), DagError> {
        if join.id.0 == 0 {
            return Err(DagError::Invalid("join id must be non-zero"));
        }
        if self.joins.contains_key(&join.id) {
            return Err(DagError::DuplicateJoin(join.id.0));
        }
        if self.joins.len() >= self.config.limits.max_joins {
            return Err(DagError::Capacity { kind: "join" });
        }
        if join.members.len() > self.config.limits.max_tasks {
            return Err(DagError::Capacity {
                kind: "join member",
            });
        }
        let members = join.members.iter().copied().collect::<BTreeSet<_>>();
        if members.is_empty() || members.len() != join.members.len() {
            return Err(DagError::Invalid(
                "join members must be non-empty and unique",
            ));
        }
        match join.owner {
            Some(owner) => {
                self.require_task(owner)?;
                match actor {
                    Actor::Controller => {}
                    Actor::Task(id) if id == owner => self.require_active_actor(actor)?,
                    Actor::Task(_) => {
                        return Err(DagError::Authority("a task may register only its own join"));
                    }
                }
                for member in members {
                    self.require_task(member)?;
                    if member == owner || !self.is_ancestor_or_self(owner, member) {
                        return Err(DagError::Authority(
                            "task-owned joins may contain descendants only",
                        ));
                    }
                }
            }
            None => {
                if actor != Actor::Controller {
                    return Err(DagError::Authority(
                        "only the controller may register a root join",
                    ));
                }
                for member in members {
                    self.require_task(member)?;
                }
            }
        }
        Ok(())
    }

    fn validate_cancel(&self, actor: Actor, task: TaskId, reason: &str) -> Result<(), DagError> {
        let target = self.require_task(task)?;
        if target.state.is_terminal() || matches!(target.state, TaskState::Cancelling { .. }) {
            return Err(transition(task, "task is already terminal or cancelling"));
        }
        validate_visible(reason, MAX_REASON_BYTES, "cancel reason")?;
        match actor {
            Actor::Controller => Ok(()),
            Actor::Task(actor_id) => {
                self.require_active_actor(actor)?;
                if self.is_ancestor_or_self(actor_id, task) {
                    Ok(())
                } else {
                    Err(DagError::Authority(
                        "a task may cancel only itself or its descendants",
                    ))
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_completion(
        &self,
        actor: Actor,
        task: TaskId,
        completion: Completion,
        result_digest: Option<&str>,
        code: Option<&str>,
        detail: Option<&str>,
    ) -> Result<(), DagError> {
        self.authorize_task_or_controller(actor, task)?;
        let target = self.require_task(task)?;
        if !matches!(
            target.state,
            TaskState::Running | TaskState::Cancelling { .. }
        ) {
            return Err(transition(task, "only an admitted task can complete"));
        }
        if self
            .tasks
            .values()
            .any(|candidate| candidate.spec.parent == Some(task) && !candidate.state.is_terminal())
        {
            return Err(transition(
                task,
                "task cannot complete while a direct child is nonterminal",
            ));
        }
        if self
            .attempts
            .values()
            .any(|attempt| attempt.spec.task == task && !attempt.state.is_terminal())
        {
            return Err(transition(
                task,
                "task cannot complete while a physical attempt is nonterminal",
            ));
        }
        if let TaskState::Cancelling { reason } = &target.state {
            if completion != Completion::Cancelled {
                return Err(transition(
                    task,
                    "a cancelling task may only acknowledge cancellation",
                ));
            }
            if detail != Some(reason.as_str()) {
                return Err(transition(
                    task,
                    "cancellation acknowledgement must preserve the requested cause",
                ));
            }
        }
        match completion {
            Completion::Succeeded => {
                if !result_digest.is_some_and(valid_digest) || code.is_some() || detail.is_some() {
                    return Err(DagError::Invalid(
                        "success requires exactly one 64-hex result digest",
                    ));
                }
            }
            Completion::Failed => {
                let code = code.ok_or(DagError::Invalid("failure requires a code"))?;
                validate_identifier(code, 128, "code").map_err(DagError::Invalid)?;
                if let Some(detail) = detail {
                    validate_visible(detail, MAX_REASON_BYTES, "failure detail")?;
                }
                if result_digest.is_some() {
                    return Err(DagError::Invalid("failure cannot carry a result digest"));
                }
            }
            Completion::Cancelled => {
                validate_visible(
                    detail.ok_or(DagError::Invalid("cancellation requires a reason"))?,
                    MAX_REASON_BYTES,
                    "cancellation reason",
                )?;
                if result_digest.is_some() || code.is_some() {
                    return Err(DagError::Invalid(
                        "cancellation cannot carry a result digest or code",
                    ));
                }
            }
        }
        Ok(())
    }

    fn require_task(&self, id: TaskId) -> Result<&Task, DagError> {
        self.tasks.get(&id).ok_or(DagError::UnknownTask(id.0))
    }

    fn require_attempt(&self, id: AttemptId) -> Result<&super::types::Attempt, DagError> {
        self.attempts
            .get(&id)
            .ok_or(DagError::Invalid("attempt does not exist"))
    }

    fn authorize_task_or_controller(&self, actor: Actor, task: TaskId) -> Result<(), DagError> {
        match actor {
            Actor::Controller => Ok(()),
            Actor::Task(id) if id == task => {
                self.require_task(id)?;
                Ok(())
            }
            Actor::Task(_) => Err(DagError::Authority(
                "a task may mutate only its own execution state",
            )),
        }
    }

    fn require_active_actor(&self, actor: Actor) -> Result<(), DagError> {
        let Actor::Task(id) = actor else {
            return Ok(());
        };
        let task = self.require_task(id)?;
        if matches!(
            task.state,
            TaskState::Running | TaskState::Cancelling { .. }
        ) {
            Ok(())
        } else {
            Err(transition(id, "task actor is not running"))
        }
    }

    pub(super) fn is_ancestor_or_self(&self, ancestor: TaskId, mut candidate: TaskId) -> bool {
        for _ in 0..=self.config.limits.max_hierarchy_depth {
            if ancestor == candidate {
                return true;
            }
            let Some(parent) = self.tasks.get(&candidate).and_then(|task| task.spec.parent) else {
                return false;
            };
            candidate = parent;
        }
        false
    }
}
