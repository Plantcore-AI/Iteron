use super::*;

impl Agent {
    #[cfg(test)]
    #[allow(dead_code)]
    pub(super) fn observe_workflow_fan_progress(
        &mut self,
        workflow_run_id: &str,
        tasks: &[core_agents::AgentTask],
        child_ledgers: &std::sync::Arc<std::sync::Mutex<Vec<(u64, Ledger)>>>,
        event: core_workflow::ProgressEvent,
        terminals: &mut [Option<EngineAgentTerminal>],
        workflow_state: &mut WorkflowRunState,
    ) -> Result<(), KernelError> {
        match event {
            core_workflow::ProgressEvent::AgentActivity {
                index,
                tokens,
                tool_calls,
                last_tool_summary,
            } => {
                let Some(task) = index.checked_sub(1).and_then(|index| tasks.get(index)) else {
                    return Err(KernelError::WorkflowEngine(
                        "built-in workflow emitted an invalid activity index".into(),
                    ));
                };
                let activity = last_tool_summary
                    .unwrap_or_else(|| format!("working · {tokens} tokens · {tool_calls} tools"));
                self.ui(UiEvent::Workflow(WorkflowUiEvent::AgentActivity {
                    run_id: workflow_run_id.to_string(),
                    agent_id: task.id,
                    activity,
                }));
            }
            core_workflow::ProgressEvent::AgentFinished {
                index,
                state,
                tokens,
                tool_calls,
                duration_ms,
                result_preview,
                last_tool_summary: _,
                error,
                ..
            } => {
                let Some(zero_index) = index.checked_sub(1) else {
                    return Err(KernelError::WorkflowEngine(
                        "built-in workflow emitted a zero terminal index".into(),
                    ));
                };
                let Some(task) = tasks.get(zero_index) else {
                    return Err(KernelError::WorkflowEngine(
                        "built-in workflow emitted an invalid terminal index".into(),
                    ));
                };
                let Some(slot) = terminals.get_mut(zero_index) else {
                    return Err(KernelError::WorkflowEngine(
                        "built-in workflow terminal exceeded the admitted fan".into(),
                    ));
                };
                if slot.is_some() {
                    return Err(KernelError::WorkflowEngine(
                        "built-in workflow emitted a duplicate terminal".into(),
                    ));
                }
                let interrupted = state == core_workflow::WorkflowState::Error
                    && self.requested_control().interrupts();
                let outcome = match state {
                    core_workflow::WorkflowState::Done => WorkflowAgentOutcomeUi::Done,
                    core_workflow::WorkflowState::Skipped => WorkflowAgentOutcomeUi::SkippedBudget,
                    core_workflow::WorkflowState::Queued
                    | core_workflow::WorkflowState::Running => WorkflowAgentOutcomeUi::NotStarted,
                    core_workflow::WorkflowState::Error if interrupted => {
                        WorkflowAgentOutcomeUi::Interrupted
                    }
                    core_workflow::WorkflowState::Error => WorkflowAgentOutcomeUi::Failed,
                };
                let error_preview = if interrupted {
                    Some("investigator interrupted at a safe point".into())
                } else {
                    error.clone()
                };
                workflow_state.observe(outcome);
                let turns = child_ledgers
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|(ordinal, _)| *ordinal == zero_index as u64)
                    .map(|(_, ledger)| ledger.turns)
                    .unwrap_or(0);
                self.ui(UiEvent::Workflow(WorkflowUiEvent::AgentFinished {
                    run_id: workflow_run_id.to_string(),
                    agent_id: task.id,
                    outcome,
                    turns,
                    tokens,
                    tool_calls,
                    elapsed_ms: duration_ms,
                    summary_preview: result_preview.clone(),
                    error_preview,
                }));
                *slot = Some(EngineAgentTerminal { state, error });
            }
            core_workflow::ProgressEvent::Phase { .. }
            | core_workflow::ProgressEvent::Log { .. }
            | core_workflow::ProgressEvent::AgentQueued { .. }
            | core_workflow::ProgressEvent::AgentStarted { .. } => {}
        }
        Ok(())
    }
}
