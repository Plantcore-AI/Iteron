use async_trait::async_trait;

use super::types::{
    AgentTurnLeaseV1, ScheduledTaskV1, WORKFLOW_SCHEDULER_PORT_VERSION, WorkflowDispatchError,
    WorkflowSchedulerSnapshotV1, WorkflowStoreError,
};

/// Durable compare-and-publish. Success means stable storage precedes exposure; unknown outcomes
/// poison the caller. An implementation must serialize writers and bound data before decoding.
pub trait WorkflowPlanJournal {
    fn load(&mut self) -> Result<Option<WorkflowSchedulerSnapshotV1>, WorkflowStoreError>;
    fn commit(
        &mut self,
        expected_sequence: Option<u64>,
        next: &WorkflowSchedulerSnapshotV1,
    ) -> Result<(), WorkflowStoreError>;
}

/// Directional boundary to the sole agent/process authority. No shared mutable agent state is
/// exposed. Dispatch must durably bind the exact workflow/node/attempt envelope to the returned
/// lease. A busy agent must be refused rather than queued and reported as already running.
#[async_trait]
pub trait WorkflowControllerPort: Send + Sync {
    fn port_version(&self) -> u32 {
        WORKFLOW_SCHEDULER_PORT_VERSION
    }
    async fn dispatch(
        &self,
        task: ScheduledTaskV1,
    ) -> Result<AgentTurnLeaseV1, WorkflowDispatchError>;
    /// Accepted cancellation is not cleanup evidence. `settle` follows actual supervisor reap.
    async fn interrupt(&self, lease: AgentTurnLeaseV1) -> Result<(), WorkflowDispatchError>;
}
