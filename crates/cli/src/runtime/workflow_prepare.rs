//! Composition wrappers for existing workflow prepare/resume callers. Actual source admission,
//! allocation, child execution and accounting live in their independent owners.
use super::Agent;
#[cfg(test)]
use super::workflow_preparation::normalize_workflow_script;
impl Agent {
    pub(super) fn prepare_workflow(
        &mut self,
        input: &serde_json::Value,
    ) -> Result<crate::workflow::PreparedWorkflow, String> {
        self.prepare_kernel_workflow(input, None)
    }
    pub(crate) fn prepare_workflow_resume(
        &mut self,
        run: &str,
    ) -> Result<crate::workflow::PreparedWorkflow, String> {
        if !crate::workflow::valid_run_id(run) {
            return Err("Workflow: invalid run id".into());
        }
        let directory = self.runtime_state_dir.join("subagents").join("workflows");
        let manifest = crate::workflow::load_manifest(&directory, run)
            .ok_or("Workflow: persisted manifest unavailable")?;
        if manifest.run_id != run {
            return Err("Workflow: mismatched persisted identity".into());
        }
        let script = crate::workflow::load_script(&directory, run)
            .ok_or("Workflow: persisted script unavailable")?;
        self.prepare_kernel_workflow(
            &serde_json::json!({"script":script,"args":manifest.args,"background":true}),
            Some(run),
        )
    }
    #[cfg(test)]
    pub(super) fn prepare_workflow_with_resume(
        &mut self,
        input: &serde_json::Value,
        resume: Option<&str>,
    ) -> Result<crate::workflow::PreparedWorkflow, String> {
        self.prepare_kernel_workflow(input, resume)
    }
    #[cfg(test)]
    pub(super) async fn launch_workflow(
        &mut self,
        turn: iteron_protocol::TurnId,
        input: serde_json::Value,
    ) -> Result<String, String> {
        let preparation = self.kernel_workflow_preparation(turn);
        let events = self.tool_events(turn);
        let execution = super::workflow_execution::WorkflowExecution {
            deadline: self.run_deadline.current(),
            preparation,
            launcher: self.workflow_launcher.clone(),
            progress: super::workflow_execution::WorkflowProgressProjection {
                sender: self.workflow_progress_tx.clone(),
                frontend: self.frontend_saturation.clone(),
                events: events.clone(),
            },
        };
        let projection = self.turn_result_projection_budget(
            super::context_runtime::ContextBudgetInspection::from_policy(
                Default::default(),
                Default::default(),
            ),
            &[],
        );
        let (mut ports, _) = self.kernel_special_execution(
            turn,
            0,
            super::kernel_special_execution::KernelSpecialKind::Plan,
            projection,
        );
        execution
            .run(
                &input,
                turn,
                &mut ports.journal,
                &mut ports.control,
                &events,
            )
            .await
            .map_err(|error| error.public_summary())?
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_workflow_script;

    #[test]
    fn normalization_removes_only_one_outer_markdown_fence() {
        let source = "```javascript\nexport const meta = { name: 'direct' };\nreturn await agent('work');\n```";
        assert_eq!(
            normalize_workflow_script(source),
            "export const meta = { name: 'direct' };\nreturn await agent('work');"
        );
    }

    #[test]
    fn normalization_preserves_unfenced_script_bytes_and_inner_fences() {
        let source = "  export const meta = { name: 'direct' };\nconst prompt = '```text';\nreturn agent(prompt);\n";
        assert_eq!(normalize_workflow_script(source), source);

        let malformed_outer = "```javascript\nreturn agent('work');\n````";
        assert_eq!(normalize_workflow_script(malformed_outer), malformed_outer);
    }
}
