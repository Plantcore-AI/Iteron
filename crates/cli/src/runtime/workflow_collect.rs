//! Compatibility fixture wrapper. Production direct execution lives in its own domain.
#[cfg(test)]
impl super::Agent {
    pub(super) async fn spawn_subagent(
        &mut self,
        task: &str,
        index: usize,
    ) -> Result<String, String> {
        let turn = iteron_protocol::TurnId(self.seq_turn);
        let events = self.tool_events(turn);
        let projection = self.turn_result_projection_budget(
            super::context_runtime::ContextBudgetInspection::from_policy(
                Default::default(),
                Default::default(),
            ),
            &[],
        );
        let (ports, _) = self.kernel_special_execution(
            turn,
            index,
            super::kernel_special_execution::KernelSpecialKind::Direct,
            projection,
        );
        let super::kernel_special_execution::KernelSpecialExecution {
            work,
            mut journal,
            mut control,
            hooks,
            ..
        } = ports;
        let super::kernel_special_execution::KernelDispatchWork::Direct(execution) = work else {
            unreachable!("direct factory kind")
        };
        execution
            .run(
                turn,
                index,
                task,
                &mut journal,
                &mut control,
                &events,
                hooks,
            )
            .await
            .map_err(|error| error.public_summary())?
    }
}
