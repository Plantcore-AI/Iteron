//! One-way workflow dispatch adapter; graph/revision ownership remains in iteron-workflow.
use super::*;
use iteron_agents::AgentWorkflowClaim;
use iteron_protocol::agent_control::AgentBudgetV1;
use iteron_workflow::live_scheduler::{
    AgentTurnLeaseV1, ScheduledTaskV1, WorkflowControllerPort, WorkflowDispatchError,
};

pub(super) fn claim(task: ScheduledTaskV1) -> Result<AgentWorkflowClaim, ControllerError> {
    task.budget.validate().map_err(ControllerError::Invalid)?;
    Ok(AgentWorkflowClaim {
        workflow_id: task.workflow_id,
        node_id: task.node_id,
        attempt: task.attempt,
        input_digest: task.input_digest,
        assigned_agent: AgentIdV1(task.assigned_agent),
        task: task.task,
        budget: AgentBudgetV1 {
            turns: task.budget.max_turns,
            tokens: task.budget.max_tokens,
            cost_microusd: task.budget.max_cost_microusd,
            wall_ms: task.budget.max_wall_ms,
        },
        execution: None,
        deadline_unix_ms: task.deadline_unix_ms,
    })
}
fn error(error: ControllerError) -> WorkflowDispatchError {
    match error {
        ControllerError::Poisoned
        | ControllerError::RecoveryRequired
        | ControllerError::Store(iteron_agents::ControllerStoreError::OutcomeUnknown)
        | ControllerError::Store(iteron_agents::ControllerStoreError::Conflict) => {
            WorkflowDispatchError::OutcomeUnknown(error.to_string())
        }
        _ => WorkflowDispatchError::NotApplied(error.to_string()),
    }
}
#[async_trait]
impl<J: AgentControllerJournal + Send + 'static> WorkflowControllerPort for PersistentAgentHost<J> {
    async fn dispatch(
        &self,
        task: ScheduledTaskV1,
    ) -> Result<AgentTurnLeaseV1, WorkflowDispatchError> {
        let claim = claim(task).map_err(error)?;
        let deadline = claim.deadline_unix_ms;
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| {
                    WorkflowDispatchError::NotApplied("runtime clock is before epoch".into())
                })?
                .as_millis(),
        )
        .map_err(|_| {
            WorkflowDispatchError::NotApplied("runtime clock exceeds the host envelope".into())
        })?;
        let (lease, permit) = {
            let mut controller = self
                .shared
                .controller
                .lock()
                .map_err(|_| error(ControllerError::Poisoned))?;
            if let Some(lease) = controller.existing_workflow_lease(&claim).map_err(error)? {
                return Ok(AgentTurnLeaseV1 {
                    agent_id: lease.agent.agent_id.0,
                    incarnation: lease.epoch.incarnation,
                    turn: lease.epoch.turn,
                });
            }
            let permit = self
                .shared
                .permits
                .clone()
                .try_acquire_owned()
                .map_err(|_| {
                    WorkflowDispatchError::NotApplied("agent concurrency is saturated".into())
                })?;
            let lease = controller.claim_workflow_task(claim, now).map_err(error)?;
            self.notify(controller.revision());
            (lease, permit)
        };
        let result = AgentTurnLeaseV1 {
            agent_id: lease.agent.agent_id.0,
            incarnation: lease.epoch.incarnation,
            turn: lease.epoch.turn,
        };
        if !lease.replayed {
            self.start_execution_with_deadline(
                lease.agent,
                lease.epoch,
                lease.initial,
                permit,
                Some(deadline),
            )
        }
        Ok(result)
    }
    async fn interrupt(&self, lease: AgentTurnLeaseV1) -> Result<(), WorkflowDispatchError> {
        let command = AgentCommandV1::Interrupt {
            agent_id: AgentIdV1(lease.agent_id),
            epoch: AgentEpochV1 {
                incarnation: lease.incarnation,
                turn: lease.turn,
            },
        };
        self.command(
            AgentActor::Operator,
            &format!(
                "workflow-stop:{}:{}:{}",
                lease.agent_id, lease.incarnation, lease.turn
            ),
            command,
        )
        .map(|_| ())
        .map_err(error)
    }
}
