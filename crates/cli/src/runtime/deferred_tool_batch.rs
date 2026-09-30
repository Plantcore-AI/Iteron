//! Actual admitted deferred-tool batch coordinator. It owns pending intent tickets and managed
//! result lifetimes through physical execution, ordered settlement and post observers. Journal,
//! execution, hook and immutable projection owners are independent concrete ports.
use super::KernelError;
use super::artifact_publication::{PUBLICATION_UNAVAILABLE, ToolOutputPublicationFactory};
use super::context_runtime::TurnResultProjectionBudget;
use super::deferred_batch_executor::{DeferredBatchExecutor, DeferredToolReceipt};
use super::deferred_tools::AutoApprovedCall;
use super::effect_journal_owner::UnknownCause;
use super::frontend_events::UiEvent;
use super::hook_execution::{HookExecution, HookExecutionScope};
use super::stream_tool_events::StreamToolEvents;
use super::tool_execution_journal::ToolExecutionJournal;
use super::tool_output_spill::{self, ManagedToolExecution, ToolOutputSpillStore};
use super::tool_presentation::tool_end_ui;
use super::turn_activity::ActivityStage;
use iteron_kernel::effects::{self, EffectTicket};
use iteron_protocol::{LifecyclePayload, ToolResult, ToolUse, TurnId};
use iteron_sched::Governor;
use iteron_tools::Registry;
use std::sync::{Arc, atomic::AtomicBool};

pub(super) struct DeferredToolScope<'a> {
    pub(super) turn: TurnId,
    pub(super) registry: &'a Registry,
    pub(super) governor: &'a Governor,
    pub(super) spill_owner: Option<Arc<ToolOutputSpillStore>>,
    pub(super) interrupt: Option<Arc<AtomicBool>>,
    pub(super) force_cancel: Arc<AtomicBool>,
    pub(super) drain: Arc<AtomicBool>,
    pub(super) projection: TurnResultProjectionBudget,
    pub(super) publication: Arc<dyn ToolOutputPublicationFactory>,
    pub(super) hooks: HookExecutionScope<'a>,
    pub(super) events: StreamToolEvents,
}

pub(super) struct DeferredToolBatch<'a> {
    pub(super) journal: ToolExecutionJournal<'a>,
    pub(super) scope: DeferredToolScope<'a>,
}
struct PendingTool {
    index: usize,
    call: ToolUse,
    signature: String,
    ticket: EffectTicket,
}

impl DeferredToolBatch<'_> {
    pub(super) async fn execute(
        mut self,
        batch: Vec<AutoApprovedCall>,
        results: &mut [Option<ToolResult>],
        any_error: &mut bool,
    ) -> Result<(), KernelError> {
        if batch.len() > effects::MAX_TOOL_CALLS_PER_TURN
            || batch.iter().any(|call| call.index >= results.len())
        {
            return Err(KernelError::ContextResolution(
                "deferred batch exceeds the admitted tool-call envelope".into(),
            ));
        }
        // All intents are durable before polling any executor. A failed barrier leaves every
        // already-opened ticket pending for canonical recovery; no command has started yet.
        let mut pending = Vec::with_capacity(batch.len());
        let mut intents = Vec::with_capacity(batch.len());
        for admitted in batch {
            let AutoApprovedCall {
                index,
                call,
                intent,
                capability,
                action_signature,
            } = admitted;
            let ticket = self.journal.open_tool(
                self.scope.hooks.workspace,
                self.scope.turn,
                index,
                &call,
                capability,
                &self.scope.events,
            )?;
            pending.push(PendingTool {
                index,
                call,
                signature: action_signature,
                ticket,
            });
            intents.push(intent);
        }
        let sources = pending
            .iter()
            .map(|entry| (entry.call.clone(), entry.ticket.intent_sequence()))
            .collect::<Vec<_>>();
        let publication = self.scope.publication.for_calls(&sources);
        let executions = DeferredBatchExecutor::new(
            self.scope.registry,
            self.scope.governor,
            self.scope.spill_owner.clone(),
            self.scope.interrupt.clone(),
            self.scope.force_cancel.clone(),
            self.scope.drain.clone(),
            self.scope.projection,
            publication,
        )
        .execute(intents)
        .await;
        if executions.len() != pending.len() {
            // The physical executor's declaration-order cardinality is structural truth. An
            // impossible mismatch leaves real intents unresolved instead of dropping receipts.
            return Err(KernelError::EffectBoundary(
                "deferred executor returned an invalid receipt envelope".into(),
            ));
        }
        let mut unknown = 0usize;
        let mut completed = Vec::with_capacity(pending.len());
        for (entry, receipt) in pending.into_iter().zip(executions) {
            let DeferredToolReceipt {
                execution,
                spill_store,
                projected_visible,
                operator_interrupted,
                publication_error,
            } = receipt;
            if let Some(visible) = projected_visible {
                self.scope.events.projected(visible);
            }
            let effect_id = entry.ticket.effect_id().clone();
            let (mut managed, definite) = match execution {
                ManagedToolExecution::Definite(managed) => (managed, true),
                ManagedToolExecution::Unknown(managed) => (managed, false),
            };
            let committed = if definite {
                self.journal.known_result(
                    entry.ticket,
                    &entry.call.name,
                    &managed.result,
                    0,
                    &self.scope.events,
                )
            } else {
                let cause = if operator_interrupted {
                    UnknownCause::OperatorCancelled
                } else {
                    UnknownCause::Unobserved
                };
                self.journal.settle(entry.ticket,effects::Settlement::Unknown(
                    "executor dispatched the operation but did not observe an authoritative terminal outcome; automatic retry is forbidden".into(),
                ),cause)
            };
            // Physical truth settles before unavailable publication is presented. A retention
            // error must not manufacture Unknown, free a retry or repeat a successful operation.
            if let Err(error) = committed {
                let _ =
                    tool_output_spill::cleanup_managed_result(spill_store.as_deref(), &mut managed);
                return Err(error);
            }
            if publication_error.is_some() {
                self.scope
                    .events
                    .present(UiEvent::Notice(PUBLICATION_UNAVAILABLE.into()));
            }
            let result = &managed.result;
            if !definite {
                self.scope.events.process_terminal(
                    effect_id.clone(),
                    &entry.call.name,
                    result,
                    false,
                );
                if operator_interrupted {
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
                unknown = unknown.saturating_add(1);
                self.journal.ledger.tool(result.latency_ms, 0, true);
                let terminal_ui = tool_end_ui(&entry.call, result);
                tool_output_spill::cleanup_managed_result(spill_store.as_deref(), &mut managed)?;
                self.scope.events.present(terminal_ui);
                continue;
            }
            // The shared journal already emitted known terminal/process evidence and accounted
            // zero provider-overlap credit after the confirmed terminal barrier.
            *any_error |= result.is_error;
            if result.is_error {
                self.journal
                    .failed_actions
                    .insert(entry.signature, result.content.clone());
            }
            completed.push((entry.index, entry.call, managed, spill_store));
        }
        let post_inputs = completed
            .iter()
            .map(|(_, call, managed, _)| (call.clone(), managed.result.clone()))
            .collect::<Vec<_>>();
        let activity = self
            .scope
            .hooks
            .activity
            .span(ActivityStage::ToolPostProcessing, Some(self.scope.turn));
        let post_result = self.post_tools(&post_inputs).await;
        // Keep actual managed results until every post observer settles, including a typed gate
        // dispatcher failure. Frontend ToolEnd cannot overtake a started PostToolUse command.
        for (index, call, mut managed, spill_store) in completed {
            let terminal_ui = tool_end_ui(&call, &managed.result);
            tool_output_spill::cleanup_managed_result(spill_store.as_deref(), &mut managed)?;
            self.scope.events.present(terminal_ui);
            results[index] = Some(managed.result);
        }
        activity.complete();
        post_result?;
        if unknown > 0 {
            return Err(KernelError::UnknownEffects { count: unknown });
        }
        Ok(())
    }
    async fn post_tools(&mut self, completed: &[(ToolUse, ToolResult)]) -> Result<(), KernelError> {
        HookExecution {
            rollout: self.journal.rollout,
            effects: self.journal.effects,
            record_failed: self.journal.record_failed,
            ledger: self.journal.ledger,
            diagnostics: self.journal.diagnostics,
            #[cfg(test)]
            fault: self.journal.fault,
            scope: self.scope.hooks.clone(),
        }
        .post_tools(completed)
        .await
    }
}
