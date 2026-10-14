//! Actual plan publication through its state owner and the same admitted durable writer.
use super::{
    KernelError,
    kernel_dispatch_journal::KernelDispatchJournal,
    task_plan::{TaskPlanInput, TaskPlanOwner},
};
use iteron_protocol::{ToolResult, ToolUse, Trust, TurnId};

pub(super) struct TaskPlanExecution<'record, 'borrow> {
    pub(super) owner: &'borrow mut TaskPlanOwner,
    pub(super) journal: &'borrow mut KernelDispatchJournal<'record>,
}
impl TaskPlanExecution<'_, '_> {
    pub(super) fn execute(
        &mut self,
        turn: TurnId,
        call: &ToolUse,
    ) -> Result<ToolResult, KernelError> {
        if !super::task_plan::bounded_input(&call.input) {
            return Ok(ToolResult {
                tool_use_id: call.id.clone(),
                content: "task plan input exceeds bounded owner admission".into(),
                is_error: true,
                trust: Trust::Untrusted,
                latency_ms: 0,
            });
        }
        let input = serde_json::from_value::<TaskPlanInput>(call.input.clone());
        let content = match input {
            Ok(TaskPlanInput::Inspect) => Ok(self.owner.inspect().to_string()),
            Ok(input) => match self.owner.prepare(input) {
                Ok(prepared) => {
                    let receipt = self.journal.append(turn, prepared.event())?;
                    self.owner
                        .publish(prepared, receipt)
                        .map_err(|reason| KernelError::ContextResolution(reason.into()))?;
                    Ok(self.owner.inspect().to_string())
                }
                Err(reason) => Err(reason),
            },
            Err(_) => Err("invalid bounded task-plan command"),
        };
        Ok(ToolResult {
            tool_use_id: call.id.clone(),
            is_error: content.is_err(),
            content: content.unwrap_or_else(str::to_owned),
            trust: Trust::Untrusted,
            latency_ms: 0,
        })
    }
}
