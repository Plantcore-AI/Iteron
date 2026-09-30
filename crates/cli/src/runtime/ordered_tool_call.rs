//! One already-permitted ordered registry effect: actual intent, future, terminal, spill and
//! post observer lifetime. Permission and optional plan/delegation dispatch remain outside.
use super::KernelError;
use super::artifact_publication::{PUBLICATION_UNAVAILABLE, ToolOutputPublicationFactory};
use super::context_runtime::TurnResultProjectionBudget;
use super::effect_journal_owner::UnknownCause;
use super::frontend_events::UiEvent;
use super::hook_execution::{HookExecution, HookExecutionScope};
use super::hooks::HookEvent;
use super::stream_tool_events::StreamToolEvents;
use super::tool_execution_journal::ToolExecutionJournal;
use super::tool_images::PendingToolImageProjection;
use super::tool_interrupt::{await_tool_or_interrupt, interrupted_tool_result};
use super::tool_output_spill::{self, ManagedToolExecution, ToolOutputSpillStore};
use super::tool_presentation::tool_end_ui;
use super::turn_activity::ActivityStage;
use iteron_kernel::effects;
use iteron_protocol::{Capability, LifecyclePayload, ToolResult, intent::ToolIntent};
use iteron_tools::{Registry, ToolExecution};
use std::sync::{Arc, atomic::AtomicBool};
use std::time::Instant;

#[cfg(all(test, unix))]
#[path = "ordered_tool_call_tests.rs"]
mod tests;

pub(super) struct OrderedCallAdmission {
    pub(super) index: usize,
    pub(super) intent: ToolIntent,
    pub(super) capability: Capability,
    pub(super) action_signature: String,
}
pub(super) struct OrderedToolResult {
    pub(super) result: ToolResult,
    pub(super) image_projection: Option<PendingToolImageProjection>,
}
pub(super) struct OrderedToolScope<'a> {
    pub(super) registry: &'a Registry,
    pub(super) interrupt: Option<Arc<AtomicBool>>,
    pub(super) force_cancel: Arc<AtomicBool>,
    pub(super) drain: Arc<AtomicBool>,
    /// A held external dispatch permit requires its in-flight operation to settle on drain.
    pub(super) settle_on_drain: bool,
    pub(super) spill: Option<Arc<ToolOutputSpillStore>>,
    pub(super) projection: TurnResultProjectionBudget,
    pub(super) publication: Arc<dyn ToolOutputPublicationFactory>,
    pub(super) hooks: HookExecutionScope<'a>,
    pub(super) events: StreamToolEvents,
}
pub(super) struct OrderedToolCall<'a> {
    pub(super) journal: ToolExecutionJournal<'a>,
    pub(super) scope: OrderedToolScope<'a>,
}

impl OrderedToolCall<'_> {
    pub(super) async fn execute(
        mut self,
        admission: OrderedCallAdmission,
    ) -> Result<OrderedToolResult, KernelError> {
        if admission.index >= effects::MAX_TOOL_CALLS_PER_TURN {
            return Err(KernelError::EffectBoundary(
                "ordered tool ordinal exceeds its admission envelope".into(),
            ));
        }
        let call = admission.intent.call.clone();
        let turn = self.scope.hooks.turn;
        let queued = self
            .scope
            .hooks
            .activity
            .span(ActivityStage::ToolQueued, Some(turn));
        let ticket = self.journal.open_tool(
            self.scope.hooks.workspace,
            turn,
            admission.index,
            &call,
            admission.capability,
            &self.scope.events,
        )?;
        queued.complete();
        let effect_id = ticket.effect_id().clone();
        let running = self
            .scope
            .hooks
            .activity
            .span(ActivityStage::ToolRunning, Some(turn));
        let started = Instant::now();
        let (mut execution, interrupted) = match await_tool_or_interrupt(
            self.scope
                .registry
                .run_admitted_intent_captured(admission.intent),
            self.scope.interrupt.as_deref(),
            Some(self.scope.force_cancel.as_ref()),
            (!self.scope.settle_on_drain).then_some(self.scope.drain.as_ref()),
        )
        .await
        {
            Ok(execution) => (execution, false),
            Err(reason) => (
                ToolExecution::Unknown(interrupted_tool_result(
                    call.id.clone(),
                    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                    reason,
                ))
                .into(),
                true,
            ),
        };
        running.complete();
        let post_activity = self
            .scope
            .hooks
            .activity
            .span(ActivityStage::ToolPostProcessing, Some(turn));
        match &mut execution.execution {
            ToolExecution::Definite(result) | ToolExecution::Unknown(result) => {
                result.tool_use_id = call.id.clone()
            }
        }
        // The original captured bytes/metadata publish before any model projection. A failure
        // here never changes the physical certainty returned by the executor.
        let publication_error = self
            .scope
            .publication
            .for_call(&call, ticket.intent_sequence())
            .publish_execution(&call, &execution)
            .err();
        let images = std::mem::take(&mut execution.captured_images);
        let mut managed =
            tool_output_spill::manage_execution(self.scope.spill.as_deref(), execution.execution);
        let managed_result = match &mut managed {
            ManagedToolExecution::Definite(result) | ManagedToolExecution::Unknown(result) => {
                result
            }
        };
        if managed_result.project_visible(self.scope.projection.visible_bytes_for(&call.name)) {
            self.scope
                .events
                .projected(managed_result.result.content.len());
        }
        let (execution, mut lease) = tool_output_spill::into_execution_parts(managed);
        let (result, image_projection) = match execution {
            ToolExecution::Definite(result) => {
                let projection = if !result.is_error && !images.is_empty() {
                    let receipt = self.journal.known_result_receipt(
                        ticket,
                        &call.name,
                        &result,
                        0,
                        &self.scope.events,
                    )?;
                    Some(PendingToolImageProjection { receipt, images })
                } else {
                    self.journal.known_result(
                        ticket,
                        &call.name,
                        &result,
                        0,
                        &self.scope.events,
                    )?;
                    None
                };
                if publication_error.is_some() {
                    self.scope
                        .events
                        .present(UiEvent::Notice(PUBLICATION_UNAVAILABLE.into()));
                }
                (result, projection)
            }
            ToolExecution::Unknown(result) => {
                self.journal.settle(ticket, effects::Settlement::Unknown(
                    "executor did not report an authoritative terminal; side-effect state is unknown and automatic retry is forbidden".into()),
                    if interrupted { UnknownCause::OperatorCancelled } else { UnknownCause::Unobserved })?;
                if publication_error.is_some() {
                    self.scope
                        .events
                        .present(UiEvent::Notice(PUBLICATION_UNAVAILABLE.into()));
                }
                self.scope
                    .events
                    .process_terminal(effect_id.clone(), &call.name, &result, false);
                if interrupted {
                    self.scope.events.emit(
                        "tool.call_cancelled",
                        Some(effect_id.clone()),
                        LifecyclePayload::default(),
                    );
                }
                self.scope.events.emit(
                    "tool.call_unknown",
                    Some(effect_id),
                    LifecyclePayload {
                        duration_us: Some(result.latency_ms.saturating_mul(1_000)),
                        ..LifecyclePayload::default()
                    },
                );
                self.journal.ledger.tool(result.latency_ms, 0, true);
                tool_output_spill::cleanup_lease(self.scope.spill.as_deref(), &mut lease)?;
                post_activity.complete();
                self.scope.events.present(tool_end_ui(&call, &result));
                return Err(KernelError::UnknownEffects { count: 1 });
            }
        };
        if result.is_error {
            self.journal
                .failed_actions
                .insert(admission.action_signature, result.content.clone());
        }
        // Compatibility hook payload is kept exact. Its failure cannot erase a known tool
        // terminal, and cleanup/ToolEnd still occur after the physical observer has settled.
        let context = serde_json::json!({"event":"PostToolUse","tool":result.tool_use_id,
            "is_error":result.is_error,"content":iteron_protocol::text::head(&result.content,2000)})
        .to_string();
        let post_hook = HookExecution {
            rollout: self.journal.rollout,
            effects: self.journal.effects,
            record_failed: self.journal.record_failed,
            ledger: self.journal.ledger,
            diagnostics: self.journal.diagnostics,
            #[cfg(test)]
            fault: self.journal.fault,
            scope: self.scope.hooks,
        }
        .compatibility(HookEvent::PostToolUse, &context)
        .await;
        tool_output_spill::cleanup_lease(self.scope.spill.as_deref(), &mut lease)?;
        post_activity.complete();
        self.scope.events.present(tool_end_ui(&call, &result));
        post_hook?;
        Ok(OrderedToolResult {
            result,
            image_projection,
        })
    }
}
