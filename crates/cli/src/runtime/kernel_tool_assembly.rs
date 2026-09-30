//! Concrete non-registry call composition; executing domain work remains outside this factory.
use super::context_runtime::TurnResultProjectionBudget;
use super::kernel_tool_call::{KernelOutputProjection, KernelToolCall, KernelToolOutputScope};
use super::{Agent, KernelError};
use iteron_protocol::{Capability, ToolUse, TurnId};
impl Agent {
    pub(super) fn kernel_tool_call(
        &mut self,
        turn: TurnId,
        index: usize,
        call: &ToolUse,
        capability: Capability,
        projection: TurnResultProjectionBudget,
    ) -> Result<KernelToolCall, KernelError> {
        let scope = KernelToolOutputScope {
            events: self.tool_events(turn),
            publication: self.tool_output_publication_factory(),
            spill: self.ordinary_tool_spill_store(&call.name),
            projection: if matches!(
                call.name.as_str(),
                iteron_tools::DISPATCH_AGENT | iteron_tools::WORKFLOW_TOOL
            ) {
                KernelOutputProjection::Bounded(projection)
            } else {
                KernelOutputProjection::Inline
            },
        };
        super::kernel_tool_call::KernelToolCall::begin(
            &mut super::tool_execution_journal::ToolExecutionJournal {
                rollout: &mut self.rollout,
                effects: &mut self.effect_journal,
                ledger: &mut self.ledger,
                failed_actions: &mut self.failed_actions,
                record_failed: &mut self.record_failed,
                diagnostics: &self.diagnostics,
                #[cfg(test)]
                fault: &mut self.fail_next_durable_append,
            },
            scope,
            &self.workspace,
            turn,
            index,
            call,
            capability,
        )
    }
    pub(super) fn complete_kernel_tool_call(
        &mut self,
        call: KernelToolCall,
        result: iteron_protocol::ToolResult,
    ) -> Result<iteron_protocol::ToolResult, KernelError> {
        call.complete(&mut self.tool_execution_journal(), result)
    }
}
