//! Compatibility fixture wrapper. Production direct execution lives in its own domain.
#[cfg(test)]
impl super::Agent {
    pub(super) async fn spawn_subagent(
        &mut self,
        task: &str,
        index: usize,
    ) -> Result<String, String> {
        let turn = iteron_protocol::TurnId(self.seq_turn);
        let call = iteron_protocol::ToolUse {
            id: format!("fixture-direct-{index}"),
            name: iteron_tools::DISPATCH_AGENT.into(),
            input: serde_json::json!({"task":task}),
        };
        let projection = self.turn_result_projection_budget(
            super::context_runtime::ContextBudgetInspection::from_policy(
                Default::default(),
                Default::default(),
            ),
            std::slice::from_ref(&call),
        );
        let (ports, output) = self.kernel_special_execution(
            turn,
            index,
            super::kernel_special_execution::KernelSpecialKind::Direct,
            projection,
        );
        let result = ports
            .run(
                turn,
                index,
                &call,
                iteron_protocol::Capability::CodeExecuting,
                output,
            )
            .await
            .map_err(|error| error.public_summary())?;
        match result {
            super::kernel_special_execution::KernelSpecialResult::Completed(result)
            | super::kernel_special_execution::KernelSpecialResult::Refused(result) => {
                if result.is_error {
                    Err(result.content)
                } else {
                    Ok(result.content)
                }
            }
            super::kernel_special_execution::KernelSpecialResult::AccountingUnavailable {
                reason,
                ..
            } => Err(reason),
        }
    }
}
