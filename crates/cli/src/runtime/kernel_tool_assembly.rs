//! Concrete non-registry call composition; executing domain work remains outside this factory.
use super::context_runtime::TurnResultProjectionBudget;
use super::kernel_tool_call::{KernelOutputProjection, KernelToolCall, KernelToolOutputScope};
use super::tool_execution_journal::ToolExecutionJournal;
use super::{Agent, KernelError};
use iteron_protocol::{Capability, ToolResult, ToolUse, TurnId};
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
    /// Commit the terminal for a call that was **refused before dispatch** — a policy or gate
    /// denial, an ADR-003 dedup, an operator drain/interrupt, an exhausted deadline, a broken
    /// record — before projecting it into the live ledger. A failed durable append therefore
    /// cannot make live reproducible counters outrun replay.
    ///
    /// There is no `effect_id` because nothing was admitted: no executor was entered, so there is
    /// no admission event to point at, and minting one would put a lie on the record. That is why
    /// `iteron_record` permits a missing effect id only on an error result — every value this commits
    /// is one (I-42).
    pub(super) fn commit_refused_tool_result(
        &mut self,
        turn: TurnId,
        tool: &str,
        result: &ToolResult,
    ) -> Result<(), KernelError> {
        self.commit_refused_tool_result_with_reason(turn, tool, result, "refused_before_dispatch")
    }

    pub(super) fn commit_refused_tool_result_with_reason(
        &mut self,
        turn: TurnId,
        tool: &str,
        result: &ToolResult,
        reason_code: &'static str,
    ) -> Result<(), KernelError> {
        let events = self.tool_events(turn);
        self.tool_execution_journal()
            .refused_result(turn, tool, result, reason_code, &events)
    }

    pub(super) fn tool_execution_journal(&mut self) -> ToolExecutionJournal<'_> {
        ToolExecutionJournal {
            rollout: &mut self.rollout,
            effects: &mut self.effect_journal,
            ledger: &mut self.ledger,
            failed_actions: &mut self.failed_actions,
            record_failed: &mut self.record_failed,
            diagnostics: &self.diagnostics,
            #[cfg(test)]
            fault: &mut self.fail_next_durable_append,
        }
    }
}
