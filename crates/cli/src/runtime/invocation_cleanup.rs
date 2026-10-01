//! Real private output stores settle before the host publishes its parent terminal. Their
//! physical refusal can replace the loop result, as in the existing invocation contract.
use super::tool_output_spill::{ToolOutputSpillCleanup, ToolOutputSpillStore};
use super::{KernelError, Outcome};
use crate::mcp::McpRuntimeControl;
pub(super) struct InvocationCleanup<'a> {
    pub(super) tool: Option<&'a ToolOutputSpillStore>,
    pub(super) mcp: Option<&'a McpRuntimeControl>,
}
impl InvocationCleanup<'_> {
    pub(super) async fn settle(
        self,
        mut outcome: Result<Outcome, KernelError>,
    ) -> Result<Outcome, KernelError> {
        if let Some(tool) = self.tool
            && tool.cleanup(ToolOutputSpillCleanup::RunEnd).is_err()
        {
            outcome = Err(KernelError::ToolOutputSpill("lifecycle cleanup failed"));
        }
        if let Some(mcp) = self.mcp
            && mcp
                .cleanup_spills(iteron_mcp::McpSpillCleanup::RunEnd)
                .await
                .is_err()
        {
            outcome = Err(KernelError::McpLifecycle("private spill cleanup failed"));
        }
        outcome
    }
}
