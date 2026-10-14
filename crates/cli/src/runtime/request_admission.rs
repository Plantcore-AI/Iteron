//! One final model-request admission. The undispatched preparation moves through the actual
//! context gate and host control safe point once; neither a rejected nor cancelled gate rearms it.
use super::KernelError;
use super::agent_loop::AgentLoopGuard;
use super::context_preparation_events::ContextPreparationEvents;
use super::context_runtime::ContextBudgetInspection;
use super::hooks::HookDecision;
use super::request_admission_journal::RequestAdmissionJournal;
use super::request_context_publication::RequestContextPublication;
use super::request_preparation::{RequestConfiguration, RequestPreparation};
use iteron_ctx::ContextEstimate;
use iteron_protocol::{AgentLoopState, LifecyclePayload, Message, TurnId};
use iteron_provider::TurnRequest;

#[derive(PartialEq, Eq)]
enum AdmissionPhase {
    Prepared,
    Validated,
    GatePending,
    GatePassed,
    ControlPassed,
    Complete,
    Failed,
}

pub(super) struct RequestAdmission<'a> {
    preparation: RequestPreparation<'a>,
    turn: TurnId,
    estimate: ContextEstimate,
    inspection: ContextBudgetInspection,
    phase: AdmissionPhase,
}

pub(super) struct AdmittedModelRequest {
    pub(super) request: TurnRequest,
    pub(super) requested_max_tokens: u32,
    pub(super) estimate: ContextEstimate,
    pub(super) inspection: ContextBudgetInspection,
}

impl<'a> RequestAdmission<'a> {
    #[cfg(test)]
    pub(super) fn new(
        mut preparation: RequestPreparation<'a>,
        turn: TurnId,
        actual_window: Option<u64>,
        actual_output: u32,
    ) -> Result<Self, KernelError> {
        preparation.bind_route_budget(actual_window, actual_output)?;
        Ok(Self {
            estimate: preparation.estimate(),
            inspection: preparation.inspection(),
            preparation,
            turn,
            phase: AdmissionPhase::Prepared,
        })
    }

    pub(super) fn from_bound(preparation: RequestPreparation<'a>, turn: TurnId) -> Self {
        Self {
            estimate: preparation.estimate(),
            inspection: preparation.inspection(),
            preparation,
            turn,
            phase: AdmissionPhase::Prepared,
        }
    }
    pub(super) fn baseline(&self) -> usize {
        self.preparation.baseline()
    }

    pub(super) fn messages(&self) -> &[Message] {
        &self.preparation.request().messages
    }

    pub(super) fn validate(
        &mut self,
        mut journal: RequestAdmissionJournal<'_>,
        events: &ContextPreparationEvents,
        loop_state: &mut AgentLoopGuard,
    ) -> Result<(), KernelError> {
        self.require(AdmissionPhase::Prepared)?;
        // Consume the stage before every fallible boundary. No second phase/token write can be
        // produced from a partially completed stage, including a failed record append.
        self.phase = AdmissionPhase::Failed;
        journal.model_phase(self.turn)?;
        loop_state.transition(AgentLoopState::AwaitingModel)?;
        journal.record_kernel_tokens(
            self.estimate
                .system_tokens
                .saturating_add(self.estimate.tool_tokens)
                .saturating_add(self.estimate.framing_tokens),
        );
        if let Some(KernelError::ContextWindowExceeded {
            estimated_input_tokens,
            reserved_output_tokens,
            context_window_tokens,
        }) = self.preparation.window_refusal()
        {
            let excess = estimated_input_tokens
                .saturating_add(u64::from(reserved_output_tokens))
                .saturating_sub(context_window_tokens);
            for id in [
                "context.window.overflow_predicted",
                "context.segment.budget_denied",
            ] {
                events.emit(
                    self.turn,
                    id,
                    LifecyclePayload {
                        magnitude: Some(excess),
                        reason_code: Some("context_window_exhausted".into()),
                        ..LifecyclePayload::default()
                    },
                );
            }
        }
        self.preparation.validate()?;
        self.phase = AdmissionPhase::Validated;
        Ok(())
    }

    pub(super) fn request_gate(&mut self) -> Result<LifecyclePayload, KernelError> {
        self.require(AdmissionPhase::Validated)?;
        self.phase = AdmissionPhase::GatePending;
        Ok(LifecyclePayload {
            magnitude: Some(u64::try_from(self.estimate.total_tokens).unwrap_or(u64::MAX)),
            ..LifecyclePayload::default()
        })
    }

    pub(super) fn gate_completed(&mut self, decision: HookDecision) -> Result<(), KernelError> {
        self.require(AdmissionPhase::GatePending)?;
        self.phase = AdmissionPhase::Failed;
        if let HookDecision::Deny(reason) = decision {
            return Err(KernelError::ContextResolution(reason));
        }
        self.phase = AdmissionPhase::GatePassed;
        Ok(())
    }

    /// The host has actually polled/settled ordered control since the executable hook returned.
    /// An interrupted host returns before this transition and cannot produce a transport request.
    pub(super) fn control_passed(&mut self) -> Result<(), KernelError> {
        self.require(AdmissionPhase::GatePassed)?;
        self.phase = AdmissionPhase::ControlPassed;
        Ok(())
    }

    pub(super) fn complete_retained(
        &mut self,
        configuration: RequestConfiguration,
        publication: RequestContextPublication<'_>,
        elapsed_us: u64,
    ) -> Result<AdmittedModelRequest, KernelError> {
        self.require(AdmissionPhase::ControlPassed)?;
        self.phase = AdmissionPhase::Failed;
        self.publish(&publication, elapsed_us);
        let (request, requested_max_tokens) = self.preparation.project_request(configuration)?;
        self.phase = AdmissionPhase::Complete;
        Ok(AdmittedModelRequest {
            request,
            requested_max_tokens,
            estimate: self.estimate,
            inspection: self.inspection,
        })
    }
    fn publish(&self, publication: &RequestContextPublication<'_>, elapsed_us: u64) {
        publication.publish(
            self.turn,
            super::request_context_evidence::ContextRequestObservation {
                system: &self.preparation.request().system,
                messages: &self.preparation.request().messages,
                tools: &self.preparation.request().tools,
                images: &self.preparation.request().input_images,
                estimate: self.estimate,
                output_reserved_tokens: self.preparation.request().max_tokens,
                elapsed_us,
            },
        );
        publication.events().emit(
            self.turn,
            "model.route_requested",
            LifecyclePayload::default(),
        );
        publication.events().emit(
            self.turn,
            "model.request_prepared",
            LifecyclePayload {
                count: Some(u64::try_from(self.messages().len()).unwrap_or(u64::MAX)),
                magnitude: Some(u64::try_from(self.estimate.total_tokens).unwrap_or(u64::MAX)),
                ..LifecyclePayload::default()
            },
        );
    }
    pub(super) fn into_messages(self) -> Option<Vec<Message>> {
        self.preparation.into_messages()
    }

    fn require(&self, phase: AdmissionPhase) -> Result<(), KernelError> {
        if self.phase == phase {
            Ok(())
        } else {
            Err(KernelError::ContextResolution(
                "model request admission is out of order".into(),
            ))
        }
    }
}
