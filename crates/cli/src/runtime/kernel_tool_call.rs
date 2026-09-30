//! One admitted non-registry tool-call ticket and its output retention/settlement lifetime.
//! Child/workflow/plan/artifact work stays in its own real domain. This owner receives an observed
//! host result, publishes its original bytes, and accounts the logical call exactly once.
use super::KernelError;
use super::artifact_publication::{
    PUBLICATION_UNAVAILABLE, ToolOutputPublicationFactory, ToolOutputPublicationPort,
};
use super::context_runtime::TurnResultProjectionBudget;
use super::frontend_events::UiEvent;
use super::stream_tool_events::StreamToolEvents;
use super::tool_execution_journal::ToolExecutionJournal;
use super::tool_output_spill::{self, ToolOutputSpillStore};
use super::tool_presentation::tool_end_ui;
use iteron_kernel::effects::EffectTicket;
use iteron_protocol::{Capability, ToolResult, ToolUse, TurnId};
use std::path::Path;
use std::sync::Arc;

pub(super) struct KernelToolOutputScope {
    pub(super) events: StreamToolEvents,
    pub(super) publication: Arc<dyn ToolOutputPublicationFactory>,
    pub(super) spill: Option<Arc<ToolOutputSpillStore>>,
    pub(super) projection: KernelOutputProjection,
}

pub(super) enum KernelOutputProjection {
    Inline,
    Bounded(TurnResultProjectionBudget),
}

pub(super) struct KernelToolCall {
    call: ToolUse,
    ticket: EffectTicket,
    publication: Arc<dyn ToolOutputPublicationPort>,
    spill: Option<Arc<ToolOutputSpillStore>>,
    projection: KernelOutputProjection,
    events: StreamToolEvents,
}
impl KernelToolCall {
    pub(super) fn begin(
        journal: &mut ToolExecutionJournal<'_>,
        scope: KernelToolOutputScope,
        workspace: &Path,
        turn: TurnId,
        index: usize,
        call: &ToolUse,
        capability: Capability,
    ) -> Result<Self, KernelError> {
        let ticket = journal.open_tool(workspace, turn, index, call, capability, &scope.events)?;
        let publication = scope.publication.for_call(call, ticket.intent_sequence());
        Ok(Self {
            call: call.clone(),
            ticket,
            publication,
            spill: scope.spill,
            projection: scope.projection,
            events: scope.events,
        })
    }
    pub(super) fn complete(
        self,
        journal: &mut ToolExecutionJournal<'_>,
        mut result: ToolResult,
    ) -> Result<ToolResult, KernelError> {
        // The admitted declaration remains structural authority even when a child/helper returned
        // a malformed correlation. No output can substitute another call's terminal.
        result.tool_use_id = self.call.id.clone();
        let publication_error = self.publication.publish(&self.call, &result, true).err();
        let (spill, projection) = match self.projection {
            KernelOutputProjection::Inline => (None, None),
            KernelOutputProjection::Bounded(projection) => {
                (self.spill.as_deref(), Some(projection))
            }
        };
        let mut managed = tool_output_spill::manage_result(spill, result);
        if let Some(projection) = projection
            && managed.project_visible(projection.visible_bytes_for(&self.call.name))
        {
            self.events.projected(managed.result.content.len());
        }
        // This actual writer folds one ledger tool entry after the true terminal. Retention
        // failures cannot weaken known execution or manufacture another physical invocation.
        journal.known_result(
            self.ticket,
            &self.call.name,
            &managed.result,
            0,
            &self.events,
        )?;
        tool_output_spill::cleanup_managed_result(spill, &mut managed)?;
        if publication_error.is_some() {
            self.events
                .present(UiEvent::Notice(PUBLICATION_UNAVAILABLE.into()));
        }
        self.events
            .present(tool_end_ui(&self.call, &managed.result));
        Ok(managed.result)
    }
}

#[cfg(all(test, unix))]
#[path = "kernel_tool_call_tests.rs"]
mod tests;
