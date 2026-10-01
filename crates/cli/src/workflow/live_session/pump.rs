//! Bounded coordinator between graph commands and exact controller-owned settlement receipts.

use super::registry::Graph;
use super::types::{LiveWorkflowError, MAX_PUMP_OPERATIONS};
use crate::runtime::persistent_agents::AgentControlPort;
use iteron_agents::AgentWorkflowTerminal;
use iteron_workflow::live_scheduler::{
    AgentTurnLeaseV1, MAX_DIAGNOSTIC_BYTES, WorkflowCompletionV1, WorkflowNodeStateV1 as State,
    WorkflowSchedulerError,
};
use iteron_workflow::task_dag::BudgetUsage;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn now() -> Result<u64, LiveWorkflowError> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| LiveWorkflowError::Clock)?
            .as_millis(),
    )
    .map_err(|_| LiveWorkflowError::Clock)
}

pub(super) fn bounded_detail(detail: &str) -> String {
    if detail.is_empty() {
        return "execution settled without a summary".into();
    }
    let mut end = detail.len().min(MAX_DIAGNOSTIC_BYTES);
    while !detail.is_char_boundary(end) {
        end -= 1;
    }
    detail[..end].to_owned()
}

pub(super) fn has_work(graph: &Graph) -> Result<bool, LiveWorkflowError> {
    let snapshot = graph.snapshot()?;
    let now = now()?;
    if snapshot.nodes().any(|node| node.state.active()) || !graph.ready_nodes(now)?.is_empty() {
        return Ok(true);
    }
    // Actual host execution has its own inherited absolute deadline. Recovery observation stops
    // after a bounded cleanup interval; the operator may request another proof-only reconcile.
    Ok(
        now <= snapshot.config().deadline_unix_ms.saturating_add(5_000)
            && snapshot
                .nodes()
                .any(|node| matches!(node.state, State::RecoveryRequired { .. })),
    )
}

pub(super) fn reconcile(
    graph: &mut Graph,
    control: &dyn AgentControlPort,
    node_id: u64,
) -> Result<bool, LiveWorkflowError> {
    let snapshot = graph.snapshot()?;
    let record = snapshot
        .node(node_id)
        .ok_or(WorkflowSchedulerError::UnknownNode(node_id))?;
    if !matches!(
        record.state,
        State::Running { .. } | State::Cancelling { .. } | State::RecoveryRequired { .. }
    ) {
        return Err(WorkflowSchedulerError::Transition(
            "reconcile requires admitted active/recovery work",
        )
        .into());
    }
    let task = record
        .admitted_task
        .as_ref()
        .ok_or(LiveWorkflowError::Controller)?;
    let Some(proof) = control
        .workflow_completion(task)
        .map_err(|_| LiveWorkflowError::Controller)?
    else {
        return Ok(false);
    };
    let lease = AgentTurnLeaseV1 {
        agent_id: proof.agent_id.0,
        incarnation: proof.epoch.incarnation,
        turn: proof.epoch.turn,
    };
    if proof.agent_id.0 != task.assigned_agent
        || lease.incarnation == 0
        || lease.turn == 0
        || record
            .state
            .lease()
            .is_some_and(|expected| expected != lease)
    {
        return Err(WorkflowSchedulerError::StaleLease.into());
    }
    let usage = BudgetUsage {
        turns: u64::from(proof.usage.turns),
        tokens: proof.usage.tokens,
        cost_microusd: proof.usage.cost_microusd,
        wall_ms: proof.usage.wall_ms,
    };
    let settlement_known = proof.effects_known && proof.accounting_known;
    if !settlement_known
        && matches!(record.state, State::RecoveryRequired { .. })
        && record.attempt_usage == usage
    {
        return Ok(false);
    }
    let completion = match proof.terminal {
        AgentWorkflowTerminal::Succeeded if !matches!(record.state, State::Cancelling { .. }) => {
            WorkflowCompletionV1::Succeeded {
                result_digest: format!("{:x}", Sha256::digest(proof.summary.as_bytes())),
            }
        }
        AgentWorkflowTerminal::Succeeded | AgentWorkflowTerminal::Cancelled => {
            WorkflowCompletionV1::Cancelled {
                detail: bounded_detail(&proof.summary),
            }
        }
        AgentWorkflowTerminal::Failed => WorkflowCompletionV1::Failed {
            detail: bounded_detail(&proof.summary),
        },
        AgentWorkflowTerminal::StoppedRecovery => WorkflowCompletionV1::Failed {
            detail: "controller execution stopped during recovery; no successful result receipt"
                .into(),
        },
    };
    let attempt = record
        .state
        .attempt()
        .ok_or(LiveWorkflowError::Controller)?;
    if record.state.lease().is_some() {
        graph.settle(node_id, attempt, lease, completion, usage, settlement_known)?;
    } else {
        graph.reconcile_stopped(node_id, attempt, completion, usage, settlement_known)?;
    }
    Ok(true)
}

pub(super) async fn drive(
    graph: &mut Graph,
    control: &dyn AgentControlPort,
    receipt_cursor: &mut usize,
) -> Result<(), LiveWorkflowError> {
    let mut operations = 0;
    let nodes: Vec<_> = graph
        .snapshot()?
        .nodes()
        .filter(|node| {
            matches!(
                node.state,
                State::Running { .. } | State::Cancelling { .. } | State::RecoveryRequired { .. }
            )
        })
        .map(|node| node.node.id)
        .collect();
    // Rotate proof queries so a long-running first lease cannot hide completed later leases.
    // Leave half of this finite batch available for deadlines and fresh ready-node admission.
    if !nodes.is_empty() {
        for _ in 0..nodes.len().min(MAX_PUMP_OPERATIONS / 2) {
            let index = *receipt_cursor % nodes.len();
            *receipt_cursor = (index + 1) % nodes.len();
            reconcile(graph, control, nodes[index])?;
            operations += 1;
        }
    }
    let port = control.workflow_port();
    for id in graph.expired_nodes(now()?)? {
        if operations >= MAX_PUMP_OPERATIONS {
            return Ok(());
        }
        graph.interrupt(id, port.as_ref()).await?;
        operations += 1;
    }
    while operations < MAX_PUMP_OPERATIONS {
        let now = now()?;
        let Some(id) = graph.ready_nodes(now)?.first().copied() else {
            break;
        };
        graph.dispatch(id, port.as_ref(), now).await?;
        operations += 1;
    }
    Ok(())
}
