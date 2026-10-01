//! Physical final-context admission through the same journal, executable hook and ordered inbox.
//! No provider authority is minted here. A control request returns before native projection.
use super::KernelError;
use super::coding_execution_journal::CodingExecutionJournal;
use super::coding_request_execution::CodingRequestExecution;
use super::context_preparation_events::ContextPreparationEvents;
use super::control_ingress::ControlIngress;
use super::force_cancel::ForceCancelSeam;
use super::hook_execution::HookExecutionScope;
use super::inbound_control::inbound_poll_limit;
use super::request_context_publication::RequestContextPublication;
use super::request_cycle::PreparedModelTurn;
use super::request_preparation::RequestConfiguration;
use super::session_control::{InboundControl, SessionControlState};
use super::session_inbox::SessionSubmissionInbox;
use super::stream_tool_events::StreamToolEvents;
use iteron_protocol::{ImageContent, Message, TurnId};

pub(super) struct CodingRequestControl<'a> {
    pub(super) inbox: &'a mut SessionSubmissionInbox,
    pub(super) state: &'a mut SessionControlState,
    pub(super) force_cancel: Option<&'a mut ForceCancelSeam>,
}
pub(super) struct CodingRequestSession<'a> {
    pub(super) journal: CodingExecutionJournal<'a>,
    pub(super) hooks: HookExecutionScope<'a>,
    pub(super) control: CodingRequestControl<'a>,
    pub(super) events: StreamToolEvents,
    pub(super) context_events: ContextPreparationEvents,
    pub(super) publication: RequestContextPublication<'a>,
    pub(super) configuration: RequestConfiguration,
    pub(super) media: super::tool_image_admission::ToolImageAdmission<'a>,
    pub(super) input_images: &'a [ImageContent],
}
pub(super) enum CodingRequestResult {
    Admitted {
        prepared: PreparedModelTurn,
        messages: Vec<Message>,
        recovery: super::context_runtime::ContextBudgetRecoveryGuard,
    },
    RequestedControl(InboundControl),
}
impl CodingRequestSession<'_> {
    pub(super) async fn admit(
        mut self,
        turn: TurnId,
        request: &mut CodingRequestExecution,
    ) -> Result<CodingRequestResult, KernelError> {
        let activity = self.hooks.activity.span(
            super::turn_activity::ActivityStage::LocalPrepare,
            Some(turn),
        );
        request.validate(
            self.journal.request(self.events.clone()),
            &self.context_events,
        )?;
        let payload = request.request_gate()?;
        self.context_events
            .emit(turn, "context.segment.budget_requested", payload);
        let report = self
            .journal
            .hooks(self.hooks)
            .lifecycle("context.segment.budget_requested")
            .await?;
        request.gate_completed(report.decision)?;
        ControlIngress {
            journal: self.journal.approval(),
            inbox: &mut *self.control.inbox,
            control: &mut *self.control.state,
            force_cancel: self.control.force_cancel.as_deref_mut(),
            events: self.events,
        }
        .poll(turn, inbound_poll_limit());
        let control = self.control.state.requested();
        if control != InboundControl::None {
            return Ok(CodingRequestResult::RequestedControl(control));
        }
        request.control_passed()?;
        self.media.admit(request.messages()?, self.input_images)?;
        let (prepared, messages, recovery) =
            request.complete(self.configuration, self.publication)?;
        activity.complete();
        Ok(CodingRequestResult::Admitted {
            prepared,
            messages,
            recovery,
        })
    }
}
