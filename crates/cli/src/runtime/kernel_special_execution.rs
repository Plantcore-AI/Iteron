//! Exact special-tool selection. The ordinary tool phase never constructs a special execution.
use iteron_protocol::ToolUse;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum KernelSpecialKind {
    Plan,
    Direct,
    Workflow,
    #[cfg(feature = "legacy-plantcore")]
    Artifact,
}

pub(super) fn classify(call: &ToolUse, artifact_enabled: bool) -> Option<KernelSpecialKind> {
    match call.name.as_str() {
        iteron_tools::UPDATE_PLAN => Some(KernelSpecialKind::Plan),
        iteron_tools::DISPATCH_AGENT => Some(KernelSpecialKind::Direct),
        iteron_tools::WORKFLOW_TOOL => Some(KernelSpecialKind::Workflow),
        #[cfg(feature = "legacy-plantcore")]
        iteron_tools::PUBLISH_ARTIFACT if artifact_enabled => Some(KernelSpecialKind::Artifact),
        _ => {
            let _ = artifact_enabled;
            None
        }
    }
}

use super::{
    KernelError,
    direct_child_execution::DirectChildExecution,
    effect_descriptor::{effect_done_terminal, effect_failed_terminal},
    failed_action_cache::FailedActionCache,
    hook_execution::HookExecutionScope,
    hooks::HookDecision,
    kernel_dispatch_control::KernelDispatchControl,
    kernel_dispatch_journal::KernelDispatchJournal,
    kernel_tool_call::{KernelToolCall, KernelToolOutputScope},
    task_plan::TaskPlanOwner,
    task_plan_execution::TaskPlanExecution,
    tool_presentation::tool_end_ui,
    workflow_execution::WorkflowExecution,
};
use iteron_kernel::{effect_class::EffectClass, effects};
use iteron_protocol::{Capability, LifecyclePayload, ToolResult, Trust, TurnId};

pub(super) enum KernelDispatchWork {
    Plan,
    Direct(DirectChildExecution),
    Workflow(WorkflowExecution),
    #[cfg(feature = "legacy-plantcore")]
    Artifact,
}
pub(super) enum KernelSpecialResult {
    Completed(ToolResult),
    Refused(ToolResult),
    AccountingUnavailable { result: ToolResult, reason: String },
}
pub(super) struct KernelSpecialExecution<'a> {
    pub(super) work: KernelDispatchWork,
    pub(super) journal: KernelDispatchJournal<'a>,
    pub(super) failed_actions: &'a mut FailedActionCache,
    pub(super) control: KernelDispatchControl<'a>,
    pub(super) plan: &'a mut TaskPlanOwner,
    pub(super) hooks: HookExecutionScope<'a>,
    #[cfg(feature = "legacy-plantcore")]
    pub(super) artifact: &'a mut super::plantcore::PlantcoreRuntime,
}
impl KernelSpecialExecution<'_> {
    pub(super) async fn run(
        mut self,
        turn: TurnId,
        index: usize,
        call: &ToolUse,
        capability: Capability,
        output: KernelToolOutputScope,
    ) -> Result<KernelSpecialResult, KernelError> {
        let expected = match &self.work {
            KernelDispatchWork::Plan => KernelSpecialKind::Plan,
            KernelDispatchWork::Direct(_) => KernelSpecialKind::Direct,
            KernelDispatchWork::Workflow(_) => KernelSpecialKind::Workflow,
            #[cfg(feature = "legacy-plantcore")]
            KernelDispatchWork::Artifact => KernelSpecialKind::Artifact,
        };
        if classify(call, true) != Some(expected) {
            return Err(KernelError::EffectBoundary(
                "special execution does not match its admitted declaration".into(),
            ));
        }
        let events = output.events.clone();
        if matches!(&self.work, KernelDispatchWork::Workflow(_)) {
            events.emit("workflow.child_proposed", None, LifecyclePayload::default());
            let report = self
                .journal
                .hook(self.hooks.clone())
                .lifecycle("workflow.child_proposed")
                .await?;
            if let HookDecision::Deny(reason) = report.decision {
                let result = tool_result(
                    call,
                    Err(format!("workflow launch blocked by hook: {reason}")),
                    Trust::Workspace,
                );
                self.journal.tool(self.failed_actions).refused_result(
                    turn,
                    &call.name,
                    &result,
                    "workflow_hook_refused",
                    &events,
                )?;
                events.present(tool_end_ui(call, &result));
                return Ok(KernelSpecialResult::Refused(result));
            }
        }
        let workspace = self.journal.workspace().to_owned();
        let admitted = KernelToolCall::begin(
            &mut self.journal.tool(self.failed_actions),
            output,
            &workspace,
            turn,
            index,
            call,
            capability,
        )?;
        let mut accounting = None;
        let effect = admitted.effect_id().clone();
        let result = match self.work {
            KernelDispatchWork::Plan => TaskPlanExecution {
                owner: self.plan,
                journal: &mut self.journal,
            }
            .execute(turn, call)?,
            KernelDispatchWork::Direct(work) => {
                self.journal.observation(
                    turn,
                    iteron_protocol::EventKind::Notice {
                        text: "dispatching read-only subagent".into(),
                    },
                    &events,
                );
                let completion = work
                    .run(
                        turn,
                        index,
                        call.input
                            .get("task")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or(""),
                        &mut self.journal,
                        &mut self.control,
                        &events,
                        self.hooks.clone(),
                    )
                    .await?;
                let (result, source) = completion.into_parts();
                accounting = source;
                tool_result(call, result, Trust::Untrusted)
            }
            KernelDispatchWork::Workflow(work) => {
                let ordinal = self.journal.next_ordinal(turn, EffectClass::Workflow);
                let ticket = self.journal.open(
                    &workspace,
                    turn,
                    EffectClass::Workflow,
                    ordinal,
                    capability,
                    super::tool_presentation::ui_approval_arguments(&call.input),
                )?;
                let result = match work
                    .run(
                        &call.input,
                        turn,
                        &mut self.journal,
                        &mut self.control,
                        &events,
                    )
                    .await
                {
                    Ok(result) => result,
                    Err(error) => {
                        self.journal
                            .settle(ticket, effects::Settlement::Unknown(error.public_summary()))?;
                        return Err(error);
                    }
                };
                let (result, source) = result.into_parts();
                accounting = source;
                let settlement = match &result {
                    Ok(_) => effects::Settlement::Definite(effect_done_terminal(
                        turn,
                        EffectClass::Workflow,
                        ordinal,
                    )),
                    Err(reason) => effects::Settlement::Definite(effect_failed_terminal(
                        turn,
                        EffectClass::Workflow,
                        ordinal,
                        reason,
                    )),
                };
                self.journal.settle(ticket, settlement)?;
                tool_result(call, result, Trust::Untrusted)
            }
            #[cfg(feature = "legacy-plantcore")]
            KernelDispatchWork::Artifact => {
                let started = std::time::Instant::now();
                let result = self
                    .artifact
                    .snapshot_artifact(call.input.clone())
                    .await
                    .map(|artifact| super::plantcore::artifact_result_content(&artifact));
                let mut result = tool_result(call, result, Trust::Workspace);
                result.latency_ms =
                    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                result
            }
        };
        if let Some(source) = &accounting {
            source.begin(&mut self.journal, turn, &effect)?;
        }
        let result = admitted.complete(&mut self.journal.tool(self.failed_actions), result)?;
        if let Some(source) = accounting
            && let Err(error) = source.publish(&mut self.journal, &events, turn, &effect)
        {
            return Ok(KernelSpecialResult::AccountingUnavailable {
                result,
                reason: error.public_summary(),
            });
        }
        Ok(KernelSpecialResult::Completed(result))
    }
}
fn tool_result(call: &ToolUse, result: Result<String, String>, trust: Trust) -> ToolResult {
    let is_error = result.is_err();
    ToolResult {
        tool_use_id: call.id.clone(),
        content: result.unwrap_or_else(|reason| reason),
        is_error,
        trust,
        latency_ms: 0,
    }
}

#[cfg(all(test, unix))]
#[path = "kernel_special_execution_tests.rs"]
mod tests;
