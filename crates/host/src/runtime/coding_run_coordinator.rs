//! Ordinary invocation IO coordinator. The actual transcript/physical obligations belong to
//! CodingRunDriver; this owner retains only pending external handoffs and the next concrete port.
//! Every awaited port is consumed before IO. Composition supplies real owners, never callbacks.
use super::KernelError;
use super::coding_provider_execution::CodingProviderProgress;
use super::coding_provider_session::CodingProviderSession;
use super::coding_request_session::{CodingRequestResult, CodingRequestSession};
use super::coding_response_phase::CodingResponsePhase;
use super::coding_run_driver::CodingRunDriver;
use super::context_runtime::TurnResultProjectionBudget;
use super::early_tool_collection::EarlyToolCollection;
use super::frontend_events::UiEvent;
use super::kernel_special_execution::KernelSpecialResult;
use super::model_response::ModelResponseScope;
use super::pricing::ProviderAttemptGuard;
use super::provider_hedge::HedgedProviderDispatch;
use super::provider_response_commit::ProviderCommitSession;
use super::provider_response_recovery::{
    FailedProviderResponse, ProviderResponseJournal, ProviderResponseScope,
};
use super::provider_turn_driver::{ProviderHedgeSpec, ProviderTurnStart};
use super::request_admission::AdmittedModelRequest;
use super::request_cycle::RequestCycleRecipe;
use super::request_recovery_driver::RequestRecoveryWork;
use super::stream_tool_events::StreamToolEvents;
use super::tool_execution_session::ToolExecutionSession;
use super::tool_image_projection::ToolImageProjection;
use super::tool_result_projection::ToolResultProjectionPolicy;
use super::tool_round_execution::{PermittedKernelCall, ToolRoundProgress};
use super::turn_completion::{CompletionAction, TurnCompletion};
use iteron_ctx::RequestEstimator;
use iteron_obs::Ledger;
use iteron_protocol::{Block, Message, TurnId};
use iteron_provider::{EffortApplication, RateLimitSnapshot};
use iteron_tools::Registry;
use std::path::Path;
use std::time::Instant;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Port {
    Iteration,
    Recovery,
    Request,
    ProviderBegin,
    ProviderAdmission,
    ProviderPump,
    Hedge,
    HedgeAwait,
    ResponseRecovery,
    Usage,
    UsageObservation,
    Reconcile,
    Assistant,
    ResponseBoundary,
    ResponsePhase,
    ResponsePhaseRecorded,
    ResponseSelection,
    ToolPump,
    Kernel,
    KernelAwait,
    ToolSettlement,
    ToolCompletion,
    ModelCompletion,
    ModelDecision,
    Completion,
    Advance,
    Failed,
}
#[derive(Clone, Copy)]
pub(super) enum CodingRunWork {
    Iteration,
    Recovery,
    Request,
    ProviderBegin,
    ProviderPump,
    Hedge,
    ResponseRecovery,
    Usage,
    UsageObservation,
    Reconcile,
    Assistant,
    ResponseBoundary,
    ResponsePhase,
    ResponseSelection,
    ToolPump,
    Kernel,
    ToolSettlement,
    ToolCompletion,
    ModelCompletion,
    Completion,
}
pub(super) enum ProviderRunProgress {
    Hedge,
    Complete(Option<RateLimitSnapshot>),
}
pub(super) enum ResponseSelection {
    Model,
    Tools(Vec<UiEvent>),
    Malformed,
}

pub(super) struct CodingRunCoordinator<'a> {
    driver: &'a mut CodingRunDriver,
    port: Port,
    iteration_turn: Option<TurnId>,
    request: Option<AdmittedModelRequest>,
    hedge: Option<(HedgedProviderDispatch, Instant)>,
    response: Option<CodingResponsePhase>,
    kernel: Option<PermittedKernelCall>,
    kernel_index: Option<usize>,
    action: Option<CompletionAction>,
}
impl<'a> CodingRunCoordinator<'a> {
    pub(super) fn new(driver: &'a mut CodingRunDriver) -> Self {
        Self {
            driver,
            port: Port::Iteration,
            iteration_turn: None,
            request: None,
            hedge: None,
            response: None,
            kernel: None,
            kernel_index: None,
            action: None,
        }
    }
    pub(super) fn work(&self) -> Result<CodingRunWork, KernelError> {
        Ok(match self.port {
            Port::Iteration => CodingRunWork::Iteration,
            Port::Recovery => CodingRunWork::Recovery,
            Port::Request => CodingRunWork::Request,
            Port::ProviderBegin => CodingRunWork::ProviderBegin,
            Port::ProviderPump => CodingRunWork::ProviderPump,
            Port::Hedge => CodingRunWork::Hedge,
            Port::ResponseRecovery => CodingRunWork::ResponseRecovery,
            Port::Usage => CodingRunWork::Usage,
            Port::UsageObservation => CodingRunWork::UsageObservation,
            Port::Reconcile => CodingRunWork::Reconcile,
            Port::Assistant => CodingRunWork::Assistant,
            Port::ResponseBoundary => CodingRunWork::ResponseBoundary,
            Port::ResponsePhase => CodingRunWork::ResponsePhase,
            Port::ResponseSelection => CodingRunWork::ResponseSelection,
            Port::ToolPump => CodingRunWork::ToolPump,
            Port::Kernel => CodingRunWork::Kernel,
            Port::ToolSettlement => CodingRunWork::ToolSettlement,
            Port::ToolCompletion => CodingRunWork::ToolCompletion,
            Port::ModelCompletion => CodingRunWork::ModelCompletion,
            Port::Completion => CodingRunWork::Completion,
            Port::ProviderAdmission
            | Port::HedgeAwait
            | Port::ResponsePhaseRecorded
            | Port::KernelAwait
            | Port::ModelDecision
            | Port::Advance
            | Port::Failed => return Err(boundary()),
        })
    }
    pub(super) fn messages(&self) -> &[Message] {
        self.driver.messages()
    }
    pub(super) fn convergence(
        &self,
    ) -> &super::investigation_convergence::InvestigationConvergence {
        self.driver.convergence()
    }
    pub(super) fn begin_iteration(
        &mut self,
        turn: TurnId,
    ) -> Result<&mut Vec<Message>, KernelError> {
        self.require(Port::Iteration)?;
        self.iteration_turn = Some(turn);
        self.driver.begin_iteration(turn)?;
        self.driver.ingress()
    }
    pub(super) fn prepare(
        &mut self,
        seed: RequestCycleRecipe<'static>,
        estimator: &mut RequestEstimator,
    ) -> Result<(), KernelError> {
        self.require(Port::Iteration)?;
        self.port = Port::Failed;
        self.driver.prepare_request(seed, estimator)?;
        self.port = Port::Recovery;
        Ok(())
    }
    pub(super) fn request_mut(
        &mut self,
    ) -> Result<&mut super::coding_request_execution::CodingRequestExecution, KernelError> {
        if !matches!(self.port, Port::Recovery | Port::Request) {
            return Err(boundary());
        }
        self.driver.request_mut()
    }
    pub(super) fn request(
        &self,
    ) -> Result<&super::coding_request_execution::CodingRequestExecution, KernelError> {
        if !matches!(self.port, Port::Recovery | Port::Request) {
            return Err(boundary());
        }
        self.driver.request()
    }
    pub(super) fn recovery_turn(&self) -> Result<TurnId, KernelError> {
        self.iteration_turn.ok_or_else(boundary)
    }
    pub(super) fn recovery_work(&mut self) -> Result<RequestRecoveryWork<'_>, KernelError> {
        self.require(Port::Recovery)?;
        self.driver.request_mut()?.next_recovery()
    }
    pub(super) fn recovery_finished(&mut self) -> Result<(), KernelError> {
        self.require(Port::Recovery)?;
        self.port = Port::Request;
        Ok(())
    }
    pub(super) async fn admit(
        &mut self,
        session: CodingRequestSession<'_>,
        turn: TurnId,
        provider: &dyn iteron_provider::Provider,
    ) -> Result<Option<super::session_control::InboundControl>, KernelError> {
        self.require(Port::Request)?;
        self.port = Port::Failed;
        match session.admit(turn, self.driver.request_mut()?).await? {
            CodingRequestResult::RequestedControl(control) => Ok(Some(control)),
            CodingRequestResult::Admitted {
                prepared,
                messages,
                recovery,
            } => {
                let effort: EffortApplication =
                    provider.effort_application(&prepared.request.request);
                self.driver.install_admitted_request(messages, recovery)?;
                self.request = Some(self.driver.admitted(*prepared, effort)?);
                self.port = Port::ProviderBegin;
                Ok(None)
            }
        }
    }
    pub(super) fn admitted_request(&mut self) -> Result<AdmittedModelRequest, KernelError> {
        self.require(Port::ProviderBegin)?;
        self.port = Port::ProviderAdmission;
        self.request.take().ok_or_else(boundary)
    }
    pub(super) fn evidence(
        &self,
    ) -> Result<super::coding_run_driver::CodingRequestEvidence, KernelError> {
        self.driver.evidence()
    }
    pub(super) fn early_effects_allowed(&self) -> bool {
        self.driver.early_effects_allowed()
    }
    pub(super) async fn begin_provider(
        &mut self,
        session: CodingProviderSession<'_>,
        start: ProviderTurnStart,
        obligation: ProviderAttemptGuard,
        pricing_now: u64,
    ) -> Result<(), KernelError> {
        self.require(Port::ProviderAdmission)?;
        self.port = Port::Failed;
        session
            .begin(self.driver, start, obligation, pricing_now)
            .await?;
        self.port = Port::ProviderPump;
        Ok(())
    }
    pub(super) async fn pump_provider(
        &mut self,
        session: CodingProviderSession<'_>,
    ) -> Result<ProviderRunProgress, KernelError> {
        self.require(Port::ProviderPump)?;
        self.port = Port::Failed;
        match session.pump(self.driver, self.hedge.take()).await? {
            CodingProviderProgress::Hedge => {
                self.port = Port::Hedge;
                Ok(ProviderRunProgress::Hedge)
            }
            CodingProviderProgress::Complete => {
                let quota = self.driver.provider_execution()?.0.take_quota();
                self.port = Port::ResponseRecovery;
                Ok(ProviderRunProgress::Complete(quota))
            }
        }
    }
    pub(super) fn hedge_spec(&mut self) -> Result<ProviderHedgeSpec<'_>, KernelError> {
        self.require(Port::Hedge)?;
        self.port = Port::HedgeAwait;
        self.driver.provider_execution()?.0.hedge_spec()
    }
    pub(super) fn hedge_returned(
        &mut self,
        dispatch: HedgedProviderDispatch,
        started: Instant,
    ) -> Result<(), KernelError> {
        self.require(Port::HedgeAwait)?;
        self.hedge = Some((dispatch, started));
        self.port = Port::ProviderPump;
        Ok(())
    }
    pub(super) async fn recover_response(
        &mut self,
        journal: ProviderResponseJournal<'_>,
        scope: ProviderResponseScope<'_>,
    ) -> Result<Option<FailedProviderResponse>, KernelError> {
        self.require(Port::ResponseRecovery)?;
        self.port = Port::Failed;
        let failure = self.driver.resolve_provider(journal, scope).await?;
        if failure.is_none() {
            self.port = Port::Usage;
        }
        Ok(failure)
    }
    pub(super) async fn record_usage(
        &mut self,
        session: ProviderCommitSession<'_>,
    ) -> Result<(), KernelError> {
        self.require(Port::Usage)?;
        self.port = Port::Failed;
        self.driver.record_usage(session).await?;
        self.port = Port::UsageObservation;
        Ok(())
    }
    pub(super) fn usage_observed(&mut self) -> Result<(), KernelError> {
        self.require(Port::UsageObservation)?;
        self.port = Port::Reconcile;
        Ok(())
    }
    pub(super) async fn abort_response(
        &mut self,
        session: ProviderCommitSession<'_>,
    ) -> Result<(), KernelError> {
        self.require(Port::UsageObservation)?;
        self.port = Port::Failed;
        self.driver.abort_response(session).await
    }
    pub(super) fn reconcile(
        &mut self,
        session: ProviderCommitSession<'_>,
    ) -> Result<UiEvent, KernelError> {
        self.require(Port::Reconcile)?;
        self.port = Port::Failed;
        let event = self.driver.reconcile(session)?;
        self.port = Port::Assistant;
        Ok(event)
    }
    pub(super) async fn assistant(
        &mut self,
        session: ProviderCommitSession<'_>,
    ) -> Result<(), KernelError> {
        self.require(Port::Assistant)?;
        self.port = Port::Failed;
        self.driver.commit_assistant(session).await?;
        self.port = Port::ResponseBoundary;
        Ok(())
    }
    pub(super) fn response_boundary(&mut self) -> Result<(), KernelError> {
        self.require(Port::ResponseBoundary)?;
        self.port = Port::ResponsePhase;
        Ok(())
    }
    pub(super) fn prepare_response(
        &mut self,
        scope: ToolResultProjectionPolicy<'_>,
    ) -> Result<usize, KernelError> {
        self.require(Port::ResponsePhase)?;
        self.port = Port::Failed;
        let phase = CodingResponsePhase::new(self.driver, scope)?;
        let total = phase.total();
        self.response = Some(phase);
        self.port = Port::ResponsePhaseRecorded;
        Ok(total)
    }
    pub(super) fn response_phase_recorded(&mut self) -> Result<(), KernelError> {
        self.require(Port::ResponsePhaseRecorded)?;
        self.port = Port::Failed;
        if self.response.as_ref().ok_or_else(boundary)?.total() > 0 {
            self.driver.mark_awaiting_tools()?;
        }
        self.port = Port::ResponseSelection;
        Ok(())
    }
    #[cfg(feature = "legacy-plantcore")]
    pub(super) fn total_tools(&self) -> Result<usize, KernelError> {
        Ok(self.response.as_ref().ok_or_else(boundary)?.total())
    }
    pub(super) fn projection(&self) -> Result<TurnResultProjectionBudget, KernelError> {
        Ok(self.response.as_ref().ok_or_else(boundary)?.projection())
    }
    pub(super) fn response_selection(
        &mut self,
        registry: &Registry,
        workspace: &Path,
        verifier: bool,
    ) -> Result<ResponseSelection, KernelError> {
        self.require(Port::ResponseSelection)?;
        self.port = Port::Failed;
        let phase = self.response.as_ref().ok_or_else(boundary)?;
        if self.driver.malformed_tool_terminal()? {
            return Ok(ResponseSelection::Malformed);
        }
        if phase.total() == 0 {
            self.port = Port::ModelCompletion;
            return Ok(ResponseSelection::Model);
        }
        let replayed = phase.begin_tools(self.driver, registry, workspace, verifier)?;
        self.port = Port::ToolPump;
        Ok(ResponseSelection::Tools(replayed))
    }
    pub(super) async fn abort_early(
        &mut self,
        mut collection: EarlyToolCollection<'_>,
    ) -> Result<(), KernelError> {
        collection
            .abort_all(&mut self.driver.early_for_cleanup()?)
            .await
    }
    pub(super) fn observe_tools_elapsed(&self, ledger: &mut Ledger) -> Result<(), KernelError> {
        self.response
            .as_ref()
            .ok_or_else(boundary)?
            .observe_elapsed(ledger);
        Ok(())
    }
    pub(super) fn model_decision(
        &mut self,
        scope: ModelResponseScope<'_>,
    ) -> Result<super::model_response::ModelResponseDecision, KernelError> {
        self.require(Port::ModelCompletion)?;
        self.port = Port::Failed;
        let decision = self.driver.interpret_model(scope)?;
        self.port = Port::ModelDecision;
        Ok(decision)
    }
    pub(super) async fn complete_model(
        &mut self,
        decision: super::model_response::ModelResponseDecision,
        completion: TurnCompletion<'_>,
    ) -> Result<(), KernelError> {
        self.require(Port::ModelDecision)?;
        self.port = Port::Failed;
        let action = self
            .response
            .as_ref()
            .ok_or_else(boundary)?
            .complete_model(self.driver, decision, completion)
            .await?;
        self.action = Some(action);
        self.port = Port::Completion;
        Ok(())
    }
    pub(super) async fn pump_tools(
        &mut self,
        session: ToolExecutionSession<'_>,
    ) -> Result<(), KernelError> {
        self.require(Port::ToolPump)?;
        self.port = Port::Failed;
        match self
            .response
            .as_ref()
            .ok_or_else(boundary)?
            .pump_tools(self.driver, session)
            .await?
        {
            ToolRoundProgress::Complete => self.port = Port::ToolSettlement,
            ToolRoundProgress::Kernel(call) => {
                self.kernel = Some(call);
                self.port = Port::Kernel;
            }
        }
        Ok(())
    }
    pub(super) fn kernel_call(&mut self) -> Result<PermittedKernelCall, KernelError> {
        self.require(Port::Kernel)?;
        self.port = Port::KernelAwait;
        let call = self.kernel.take().ok_or_else(boundary)?;
        self.kernel_index = Some(call.index);
        Ok(call)
    }
    pub(super) fn kernel_returned(
        &mut self,
        result: KernelSpecialResult,
    ) -> Result<(), KernelError> {
        self.require(Port::KernelAwait)?;
        self.port = Port::Failed;
        let index = self.kernel_index.take().ok_or_else(boundary)?;
        self.response
            .as_ref()
            .ok_or_else(boundary)?
            .kernel_returned(self.driver, index, result)?;
        self.port = Port::ToolPump;
        Ok(())
    }
    pub(super) fn has_tool_images(&self) -> Result<bool, KernelError> {
        self.driver.has_tool_images()
    }
    pub(super) async fn settle_tools(
        &mut self,
        images: Option<ToolImageProjection<'_>>,
        events: &StreamToolEvents,
        remaining: u32,
    ) -> Result<bool, KernelError> {
        self.require(Port::ToolSettlement)?;
        self.port = Port::Failed;
        let changed = self
            .response
            .as_mut()
            .ok_or_else(boundary)?
            .settle_tools(self.driver, images, events, remaining)
            .await?;
        self.port = Port::ToolCompletion;
        Ok(changed)
    }
    pub(super) async fn complete_tools(
        &mut self,
        completion: TurnCompletion<'_>,
    ) -> Result<(), KernelError> {
        self.require(Port::ToolCompletion)?;
        self.port = Port::Failed;
        let action = self
            .response
            .as_mut()
            .ok_or_else(boundary)?
            .complete_tools(self.driver, completion)
            .await?;
        self.action = Some(action);
        self.port = Port::Completion;
        Ok(())
    }
    pub(super) fn take_completion(&mut self) -> Result<CompletionAction, KernelError> {
        self.require(Port::Completion)?;
        self.port = Port::Failed;
        let action = self.action.take().ok_or_else(boundary)?;
        if matches!(action, CompletionAction::Continue { .. }) {
            self.port = Port::Advance;
        }
        Ok(action)
    }
    pub(super) fn continued(&mut self) -> Result<(), KernelError> {
        self.require(Port::Advance)?;
        self.response = None;
        self.port = Port::Iteration;
        Ok(())
    }
    pub(super) fn answer_blocks(&self) -> Result<&[Block], KernelError> {
        self.driver.answer_blocks()
    }
    #[cfg(feature = "legacy-plantcore")]
    pub(super) fn legacy_response(
        &self,
    ) -> Result<&super::provider_response_recovery::AcceptedProviderResponse, KernelError> {
        self.driver.response()
    }
    #[cfg(feature = "legacy-plantcore")]
    pub(super) fn legacy_refusal(
        &mut self,
        journal: &mut super::session_transcript::TranscriptAdmissionJournal<'_>,
        turn: TurnId,
        message: Message,
    ) -> Result<(), KernelError> {
        self.require(Port::ResponseSelection)?;
        self.driver.record_legacy_refusal(journal, turn, message)?;
        self.port = Port::Advance;
        Ok(())
    }
    #[cfg(feature = "legacy-plantcore")]
    pub(super) fn error_streak(&self) -> u32 {
        self.driver.error_streak()
    }
    fn require(&self, expected: Port) -> Result<(), KernelError> {
        if self.port == expected {
            Ok(())
        } else {
            Err(boundary())
        }
    }
}
fn boundary() -> KernelError {
    KernelError::EffectBoundary("coding IO handoff is no longer pending".into())
}
