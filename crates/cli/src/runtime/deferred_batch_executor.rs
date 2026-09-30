//! Physical owner of one already-admitted deferred batch. WAL admission/settlement stay with
//! the caller; this executor owns permit lifetimes, cancellation, spill and bounded projections.

use super::artifact_publication::ToolOutputPublicationPort;
use super::context_runtime::TurnResultProjectionBudget;
use super::tool_interrupt::{await_tool_or_interrupt, interrupted_tool_result};
use super::tool_output_spill::{self, ManagedToolExecution, ToolOutputSpillStore};
use super::tool_presentation::strict_utf8_head;
use iteron_protocol::intent::ToolIntent;
use iteron_sched::Governor;
use iteron_tools::{Registry, ToolExecution};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

pub(super) struct DeferredToolReceipt {
    pub execution: ManagedToolExecution,
    pub spill_store: Option<Arc<ToolOutputSpillStore>>,
    pub projected_visible: Option<usize>,
    pub operator_interrupted: bool,
    pub publication_error: Option<String>,
    pub captured_images: Vec<iteron_tools::CapturedToolImage>,
}

pub(super) struct DeferredBatchExecutor<'a> {
    registry: &'a Registry,
    governor: &'a Governor,
    spill_owner: Option<Arc<ToolOutputSpillStore>>,
    interrupt: Option<Arc<AtomicBool>>,
    force_cancel: Arc<AtomicBool>,
    drain: Arc<AtomicBool>,
    projection: TurnResultProjectionBudget,
    publication: Arc<dyn ToolOutputPublicationPort>,
}

impl<'a> DeferredBatchExecutor<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registry: &'a Registry,
        governor: &'a Governor,
        spill_owner: Option<Arc<ToolOutputSpillStore>>,
        interrupt: Option<Arc<AtomicBool>>,
        force_cancel: Arc<AtomicBool>,
        drain: Arc<AtomicBool>,
        projection: TurnResultProjectionBudget,
        publication: Arc<dyn ToolOutputPublicationPort>,
    ) -> Self {
        Self {
            registry,
            governor,
            spill_owner,
            interrupt,
            force_cancel,
            drain,
            projection,
            publication,
        }
    }

    /// join_all retains declaration order even when physical executors finish out of order.
    /// Every child keeps its governor permit and cancellation scope until its real terminal.
    pub async fn execute(self, intents: Vec<ToolIntent>) -> Vec<DeferredToolReceipt> {
        futures_util::future::join_all(intents.into_iter().map(|intent| {
            let interrupt = self.interrupt.clone();
            let force_cancel = self.force_cancel.clone();
            let drain = self.drain.clone();
            let publication = self.publication.clone();
            let spill_store = if self.registry.is_mcp_effect(&intent.call.name) {
                None
            } else {
                self.spill_owner.clone()
            };
            let registry = self.registry;
            let governor = self.governor;
            let projection = self.projection;
            async move {
                let admitted_call = intent.call.clone();
                let _permit = governor.acquire().await;
                let started = Instant::now();
                let (mut execution, operator_interrupted) = match await_tool_or_interrupt(
                    registry.run_admitted_intent_captured(intent),
                    interrupt.as_deref(),
                    Some(force_cancel.as_ref()),
                    Some(drain.as_ref()),
                )
                .await
                {
                    Ok(execution) => (execution, false),
                    Err(interruption) => (
                        ToolExecution::Unknown(interrupted_tool_result(
                            admitted_call.id.clone(),
                            started.elapsed().as_millis() as u64,
                            interruption,
                        ))
                        .into(),
                        true,
                    ),
                };
                let result = match &mut execution.execution {
                    ToolExecution::Definite(result) | ToolExecution::Unknown(result) => result,
                };
                result.tool_use_id = admitted_call.id.clone();
                let publication_error = publication
                    .publish_execution(&admitted_call, &execution)
                    .err()
                    .map(|error| strict_utf8_head(&error, 2_048));
                let captured_images = std::mem::take(&mut execution.captured_images);
                let mut managed = tool_output_spill::manage_execution(
                    spill_store.as_deref(),
                    execution.execution,
                );
                let result = match &mut managed {
                    ManagedToolExecution::Definite(result)
                    | ManagedToolExecution::Unknown(result) => result,
                };
                let projected_visible = result
                    .project_visible(projection.visible_bytes_for(&admitted_call.name))
                    .then_some(result.result.content.len());
                DeferredToolReceipt {
                    execution: managed,
                    spill_store,
                    projected_visible,
                    operator_interrupted,
                    publication_error,
                    captured_images,
                }
            }
        }))
        .await
    }
}
