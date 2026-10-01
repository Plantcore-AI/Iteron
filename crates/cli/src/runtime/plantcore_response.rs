//! Existing legacy sole-call input handshake, compiled only with the explicit legacy adapter.
//! It returns to the ordinary coordinator after real refusal/continuation receipts.
use super::coding_run_coordinator::CodingRunCoordinator;
use super::frontend_events::UiEvent;
use super::tool_presentation::tool_end_ui;
use super::{Agent, KernelError, Outcome};
use iteron_protocol::{Block, Message, Role, ToolResult, Trust, TurnId};
impl Agent {
    pub(super) async fn compose_legacy_input_response(
        &mut self,
        run: &mut CodingRunCoordinator<'_>,
        turn_id: TurnId,
    ) -> Result<Option<Outcome>, KernelError> {
        let total_tools = run.total_tools()?;
        if self.plantcore_runtime_enabled()
            && run
                .legacy_response()?
                .tools
                .iter()
                .any(|tool| tool.name == iteron_tools::REQUEST_USER_INPUT)
        {
            let returned_tools = run.legacy_response()?.tools.clone();
            run.abort_early(self.early_tool_collection(turn_id)).await?;
            let terminal = if total_tools == 1 {
                let tool = &returned_tools[0];
                self.request_plantcore_input_from_value(&tool.id, tool.input.clone())
            } else {
                Err("request_user_input must be the only tool call in the model response".into())
            };
            match terminal {
                Ok(()) => {
                    let tool = &returned_tools[0];
                    self.ui(UiEvent::ToolEnd {
                        id: tool.id.clone(),
                        ok: true,
                        exit_code: None,
                        output: String::new(),
                        diff: None,
                    });
                    run.observe_tools_elapsed(&mut self.ledger)?;
                    return self.finish(turn_id, Outcome::Done).await.map(Some);
                }
                Err(reason) => {
                    let content = serde_json::json!({
                        "status": "error",
                        "reason": "sole_call_required",
                        "message": reason,
                    })
                    .to_string();
                    let mut blocks = Vec::with_capacity(returned_tools.len());
                    for tool in &returned_tools {
                        let result = ToolResult {
                            tool_use_id: tool.id.clone(),
                            content: content.clone(),
                            is_error: true,
                            trust: Trust::Trusted,
                            latency_ms: 0,
                        };
                        self.commit_refused_tool_result(turn_id, &tool.name, &result)?;
                        self.ui(tool_end_ui(tool, &result));
                        blocks.push(Block::ToolResult(result));
                    }
                    run.observe_tools_elapsed(&mut self.ledger)?;
                    run.legacy_refusal(
                        &mut self.coding_transcript_journal(),
                        turn_id,
                        Message {
                            role: Role::User,
                            content: blocks,
                        },
                    )?;
                    if run.error_streak() >= self.budget.max_consecutive_tool_errors {
                        return self.finish(turn_id, Outcome::Stuck).await.map(Some);
                    }
                    if let Some(reason) = self.completed_turn_budget_exhaustion() {
                        return self
                            .finish(turn_id, Outcome::BudgetExhausted(reason))
                            .await
                            .map(Some);
                    }
                    self.advance_turn().await?;
                    run.continued()?;
                    return Ok(None);
                }
            }
        }
        Ok(None)
    }
}
