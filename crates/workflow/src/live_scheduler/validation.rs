use std::collections::{BTreeMap, BTreeSet};

use crate::task_dag::{BudgetUsage, TaskBudget};

use super::types::{
    AgentTurnLeaseV1, MAX_DIAGNOSTIC_BYTES, MAX_NODE_TASK_BYTES, MAX_PLAN_DEPTH, MAX_PLAN_EDGES,
    MAX_PLAN_NODES, MAX_PLAN_REQUESTS, MAX_PLAN_REVISIONS, MAX_SCHEDULER_EVENTS,
    WORKFLOW_SCHEDULER_PORT_VERSION, WorkflowConfigV1, WorkflowNodeRecordV1, WorkflowNodeStateV1,
    WorkflowNodeV1, WorkflowSchedulerError as Error, WorkflowSchedulerSnapshotV1,
};

pub(super) fn identifier(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(Error::Invalid(
            "identifier must be bounded ASCII without path/control syntax",
        ));
    }
    Ok(())
}

pub(super) fn digest(value: &str) -> Result<(), Error> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(Error::Invalid("digest must be lowercase SHA-256"));
    }
    Ok(())
}

pub(super) fn text(value: &str, max: usize) -> Result<(), Error> {
    if value.is_empty() || value.len() > max || value.contains('\0') {
        return Err(Error::Invalid(
            "text must be nonempty, bounded and contain no NUL",
        ));
    }
    Ok(())
}

pub(super) fn config(value: &WorkflowConfigV1) -> Result<(), Error> {
    identifier(&value.workflow_id)?;
    budget(value.budget)?;
    if value.max_nodes == 0
        || value.max_nodes > MAX_PLAN_NODES
        || value.max_edges == 0
        || value.max_edges > MAX_PLAN_EDGES
        || value.max_concurrency == 0
        || value.max_concurrency > 64
        || value.started_at_unix_ms == 0
        || value
            .deadline_unix_ms
            .checked_sub(value.started_at_unix_ms)
            .is_none_or(|duration| duration == 0 || duration > value.budget.max_wall_ms)
    {
        return Err(Error::Invalid("workflow limits are outside hard bounds"));
    }
    Ok(())
}

fn budget(value: TaskBudget) -> Result<(), Error> {
    value.validate().map_err(Error::Budget)?;
    if value.max_turns == 0 || value.max_tokens == 0 || value.max_wall_ms == 0 {
        return Err(Error::Budget(
            "turn, token and wall budgets must be finite and positive",
        ));
    }
    Ok(())
}

pub(super) fn fits(value: TaskBudget, parent: TaskBudget) -> bool {
    value.max_turns <= parent.max_turns
        && value.max_tokens <= parent.max_tokens
        && value.max_cost_microusd <= parent.max_cost_microusd
        && value.max_wall_ms <= parent.max_wall_ms
}

pub(super) fn add_reservation(
    current: BudgetUsage,
    limit: TaskBudget,
    child: TaskBudget,
) -> Result<BudgetUsage, Error> {
    let next = BudgetUsage {
        turns: current
            .turns
            .checked_add(u64::from(child.max_turns))
            .ok_or(Error::Budget("turn overflow"))?,
        tokens: current
            .tokens
            .checked_add(child.max_tokens)
            .ok_or(Error::Budget("token overflow"))?,
        cost_microusd: current
            .cost_microusd
            .checked_add(child.max_cost_microusd)
            .ok_or(Error::Budget("cost overflow"))?,
        // Parallel durations are not additive. The graph absolute deadline is independently checked.
        wall_ms: current.wall_ms.max(child.max_wall_ms),
    };
    if !usage_fits(next, limit) {
        return Err(Error::Budget(
            "aggregate attempt reservations exceed graph ceiling",
        ));
    }
    Ok(next)
}

pub(super) fn usage_fits(value: BudgetUsage, limit: TaskBudget) -> bool {
    value.turns <= u64::from(limit.max_turns)
        && value.tokens <= limit.max_tokens
        && value.cost_microusd <= limit.max_cost_microusd
        && value.wall_ms <= limit.max_wall_ms
}

pub(super) fn lease(value: AgentTurnLeaseV1, agent: u64) -> Result<(), Error> {
    if value.agent_id == 0 || value.agent_id != agent || value.incarnation == 0 || value.turn == 0 {
        return Err(Error::Invalid(
            "controller lease does not match admitted agent",
        ));
    }
    Ok(())
}

pub(super) fn node(value: &WorkflowNodeV1, config: &WorkflowConfigV1) -> Result<(), Error> {
    if value.id == 0 || value.assigned_agent == 0 {
        return Err(Error::Invalid("node and agent ids must be nonzero"));
    }
    text(&value.label, 256)?;
    if value.label.chars().any(char::is_control) {
        return Err(Error::Invalid("label contains control text"));
    }
    text(&value.task, MAX_NODE_TASK_BYTES)?;
    digest(&value.input_digest)?;
    budget(value.budget)?;
    if !fits(value.budget, config.budget) {
        return Err(Error::Budget("node exceeds graph ceiling"));
    }
    if value.dependencies.len() > config.max_edges {
        return Err(Error::Capacity("dependency"));
    }
    if value
        .dependencies
        .iter()
        .any(|id| *id == 0 || *id == value.id)
        || value
            .dependencies
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len()
            != value.dependencies.len()
    {
        return Err(Error::Invalid(
            "dependencies contain zero, self or duplicate ids",
        ));
    }
    Ok(())
}

pub(super) fn graph(
    nodes: &BTreeMap<u64, WorkflowNodeRecordV1>,
    config: &WorkflowConfigV1,
) -> Result<(), Error> {
    // Removed ids remain tombstones, so repeatedly deleting work cannot evade lifetime capacity.
    if nodes.len() > config.max_nodes {
        return Err(Error::Capacity("node"));
    }
    let mut edges = 0usize;
    let mut indegree = BTreeMap::new();
    let mut dependents = BTreeMap::<u64, Vec<u64>>::new();
    for (id, record) in nodes {
        node(&record.node, config)?;
        if *id != record.node.id {
            return Err(Error::Invalid("node key differs from identity"));
        }
        if record.state == WorkflowNodeStateV1::Removed {
            continue;
        }
        edges = edges
            .checked_add(record.node.dependencies.len())
            .ok_or(Error::Capacity("edge"))?;
        if edges > config.max_edges {
            return Err(Error::Capacity("edge"));
        }
        indegree.insert(*id, record.node.dependencies.len());
        for dependency in &record.node.dependencies {
            if !nodes
                .get(dependency)
                .is_some_and(|n| n.state != WorkflowNodeStateV1::Removed)
            {
                return Err(Error::Invalid(
                    "dependency refers to missing or removed work",
                ));
            }
            dependents.entry(*dependency).or_default().push(*id);
        }
    }
    let mut ready = indegree
        .iter()
        .filter_map(|(id, degree)| (*degree == 0).then_some((*id, 1usize)))
        .collect::<Vec<_>>();
    let mut depths = BTreeMap::new();
    let mut visited = 0usize;
    while let Some((id, depth)) = ready.pop() {
        if depth > MAX_PLAN_DEPTH {
            return Err(Error::Capacity("dependency depth"));
        }
        visited += 1;
        if let Some(children) = dependents.get(&id) {
            for child in children {
                let maximum = depths.entry(*child).or_insert(1usize);
                *maximum = (*maximum).max(depth + 1);
                let count = indegree
                    .get_mut(child)
                    .ok_or(Error::Invalid("graph index is inconsistent"))?;
                *count -= 1;
                if *count == 0 {
                    ready.push((*child, *maximum));
                }
            }
        }
    }
    if visited != indegree.len() {
        return Err(Error::Invalid("dependency cycle"));
    }
    Ok(())
}

pub(super) fn snapshot(value: &WorkflowSchedulerSnapshotV1) -> Result<(), Error> {
    config(&value.config)?;
    if value.version != WORKFLOW_SCHEDULER_PORT_VERSION
        || value.sequence > MAX_SCHEDULER_EVENTS
        || value.revision > MAX_PLAN_REVISIONS
        || value.revision > value.sequence
        || value.receipts.len() > MAX_PLAN_REQUESTS
        || !usage_fits(value.reserved, value.config.budget)
    {
        return Err(Error::Invalid(
            "stored scheduler is outside version/counter/budget bounds",
        ));
    }
    graph(&value.nodes, &value.config)?;
    let mut active_agents = BTreeSet::new();
    let mut reserved = BudgetUsage::default();
    for record in value.nodes.values() {
        reserved.turns = reserved
            .turns
            .checked_add(record.reserved_budget.turns)
            .ok_or(Error::Invalid("reservation overflow"))?;
        reserved.tokens = reserved
            .tokens
            .checked_add(record.reserved_budget.tokens)
            .ok_or(Error::Invalid("reservation overflow"))?;
        reserved.cost_microusd = reserved
            .cost_microusd
            .checked_add(record.reserved_budget.cost_microusd)
            .ok_or(Error::Invalid("reservation overflow"))?;
        reserved.wall_ms = reserved.wall_ms.max(record.reserved_budget.wall_ms);
        if record.next_attempt == 0
            || record.next_attempt > MAX_SCHEDULER_EVENTS + 1
            || record
                .state
                .attempt()
                .is_some_and(|attempt| attempt == 0 || attempt >= record.next_attempt)
        {
            return Err(Error::Invalid("stored attempt counter is inconsistent"));
        }
        if let Some(handle) = record.state.lease() {
            lease(handle, record.node.assigned_agent)?;
        }
        if let Some(task) = &record.admitted_task
            && (task.workflow_id != value.config.workflow_id
                || task.node_id != record.node.id
                || Some(task.attempt) != record.state.attempt()
                || task.input_digest != record.node.input_digest
                || task.assigned_agent != record.node.assigned_agent
                || task.task != record.node.task
                || task.budget != record.node.budget
                || task.deadline_unix_ms <= value.config.started_at_unix_ms
                || task.deadline_unix_ms > value.config.deadline_unix_ms)
        {
            return Err(Error::Invalid(
                "stored admitted task differs from its node/attempt",
            ));
        }
        match &record.state {
            WorkflowNodeStateV1::Succeeded { result_digest, .. } => digest(result_digest)?,
            WorkflowNodeStateV1::Failed { detail, .. }
            | WorkflowNodeStateV1::Cancelled { detail, .. } => text(detail, MAX_DIAGNOSTIC_BYTES)?,
            WorkflowNodeStateV1::RecoveryRequired { reason, .. } => {
                text(reason, MAX_DIAGNOSTIC_BYTES)?
            }
            WorkflowNodeStateV1::Dispatching {
                deadline_unix_ms, ..
            }
            | WorkflowNodeStateV1::Running {
                deadline_unix_ms, ..
            }
            | WorkflowNodeStateV1::Cancelling {
                deadline_unix_ms, ..
            } => {
                if *deadline_unix_ms == 0 || *deadline_unix_ms > value.config.deadline_unix_ms {
                    return Err(Error::Invalid(
                        "stored attempt deadline exceeds graph deadline",
                    ));
                }
                if !active_agents.insert(record.node.assigned_agent) {
                    return Err(Error::Invalid("agent assigned two active workflow turns"));
                }
            }
            WorkflowNodeStateV1::Pending | WorkflowNodeStateV1::Removed => {}
        }
        if record.attempt_usage.turns > record.usage.turns
            || record.attempt_usage.tokens > record.usage.tokens
            || record.attempt_usage.cost_microusd > record.usage.cost_microusd
            || record.attempt_usage.wall_ms > record.usage.wall_ms
        {
            return Err(Error::Invalid("stored attempt usage exceeds node usage"));
        }
    }
    if active_agents.len() > value.config.max_concurrency || reserved != value.reserved {
        return Err(Error::Invalid(
            "stored concurrency or aggregate reservation is inconsistent",
        ));
    }
    for (request_id, receipt) in &value.receipts {
        identifier(request_id)?;
        digest(&receipt.digest)?;
        if receipt.receipt.version != WORKFLOW_SCHEDULER_PORT_VERSION
            || receipt.receipt.sequence > value.sequence
            || receipt.receipt.revision > value.revision
            || receipt.receipt.replayed
        {
            return Err(Error::Invalid("stored request receipt is inconsistent"));
        }
    }
    Ok(())
}
