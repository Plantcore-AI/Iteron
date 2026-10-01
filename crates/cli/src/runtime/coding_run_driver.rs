//! The ordinary coding invocation's private working transcript and phase machine.
//! Physical provider/tool/controller/verification owners are concrete ports. This owner never
//! borrows Agent, constructs authority, or replaces a physical terminal with a loop decision.
use super::KernelError;
use super::agent_loop::AgentLoopGuard;
use super::coding_provider_execution::CodingProviderExecution;
use super::context_runtime::{ContextBudgetInspection, TurnResultProjectionBudget};
use super::early_tool_collection::EarlyToolWindow;
use super::investigation_convergence::{
    CandidateDiffState, CandidateWorkspaceBaseline, InvestigationConvergence,
};
use super::model_response::{ModelResponseDecision, ModelResponseInterpreter, ModelResponseScope};
use super::optional_tool_round::OptionalToolRound;
use super::provider_response_commit::{ProviderCommitSession, ProviderResponseCommit};
use super::provider_response_recovery::{
    AcceptedProviderResponse, FailedProviderResponse, ProviderResponseJournal,
    ProviderResponseRecoveryOwner, ProviderResponseResolution, ProviderResponseScope,
};
use super::request_admission::AdmittedModelRequest;
use super::request_cycle::PreparedModelTurn;
use super::stream_tool_events::StreamToolEvents;
use super::submitted_turn_state::SubmittedTurnState;
use super::tool_execution_session::ToolExecutionSession;
use super::tool_image_projection::ToolImageProjection;
use super::tool_response::{ToolResponseMessage, ToolResponseParts};
use super::tool_round_driver::ToolRoundDriver;
use super::tool_round_execution::{ToolRoundExecution, ToolRoundProgress};
use super::turn_completion::{CompletionAction, TurnCompletion};
use iteron_protocol::{
    AgentLoopState, Block, LifecyclePayload, Message, StopReason, ToolResult, ToolUse, TurnId,
};
use iteron_provider::EffortApplication;
use iteron_tools::Registry;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq)]
enum RunPhase {
    Boundary,
    Iteration,
    Preparing,
    Admitted,
    ProviderStarting,
    Provider,
    Committing,
    Response,
    ModelCompletion,
    Tools,
    ToolCompletion,
    Closed,
    Failed,
}
#[derive(Clone, Copy)]
pub(super) struct CodingRequestEvidence {
    pub(super) turn: TurnId,
    pub(super) estimate: iteron_ctx::ContextEstimate,
    pub(super) inspection: ContextBudgetInspection,
    pub(super) effort: EffortApplication,
}
struct ResponseState {
    accepted: AcceptedProviderResponse,
    elapsed: Duration,
    hook_reads: bool,
}
struct ToolsState {
    execution: ToolRoundExecution,
    optional: OptionalToolRound,
    declarations: Arc<[ToolUse]>,
    recovered: bool,
}
pub(super) struct SettledCodingTools {
    message: ToolResponseMessage,
    automatic_candidate: bool,
}
pub(super) struct CodingToolScope<'a> {
    pub(super) registry: &'a Registry,
    pub(super) workspace: &'a Path,
    pub(super) explicit_verification: bool,
    pub(super) queued_reads: Arc<std::sync::atomic::AtomicUsize>,
    pub(super) projection: TurnResultProjectionBudget,
}

pub(super) struct CodingRunDriver {
    messages: Vec<Message>,
    submitted: SubmittedTurnState,
    convergence: InvestigationConvergence,
    baseline: CandidateWorkspaceBaseline,
    phase: RunPhase,
    loop_state: Option<AgentLoopGuard>,
    request: Option<super::coding_request_execution::CodingRequestExecution>,
    evidence: Option<CodingRequestEvidence>,
    provider: Option<CodingProviderExecution>,
    committing: Option<ProviderResponseCommit>,
    response: Option<ResponseState>,
    tools: Option<ToolsState>,
    hook_reads: bool,
}
impl CodingRunDriver {
    pub(super) fn new(messages: Vec<Message>) -> Self {
        Self {
            messages,
            submitted: SubmittedTurnState::default(),
            convergence: InvestigationConvergence::for_general_run(),
            baseline: CandidateWorkspaceBaseline::default(),
            phase: RunPhase::Boundary,
            loop_state: None,
            request: None,
            evidence: None,
            provider: None,
            committing: None,
            response: None,
            tools: None,
            hook_reads: false,
        }
    }
    pub(super) fn messages(&self) -> &[Message] {
        &self.messages
    }
    pub(super) fn ingress(&mut self) -> Result<&mut Vec<Message>, KernelError> {
        self.require(RunPhase::Iteration)?;
        Ok(&mut self.messages)
    }
    pub(super) fn begin_iteration(&mut self, turn: TurnId) -> Result<(), KernelError> {
        self.require(RunPhase::Boundary)?;
        if self.evidence.is_some_and(|prior| turn.0 <= prior.turn.0) {
            return Err(boundary());
        }
        self.response = None;
        self.loop_state = Some(AgentLoopGuard::begin(turn));
        self.phase = RunPhase::Iteration;
        Ok(())
    }
    pub(super) fn convergence(&self) -> &InvestigationConvergence {
        &self.convergence
    }
    pub(super) fn prepare_request(
        &mut self,
        seed: super::request_cycle::RequestCycleRecipe<'static>,
        estimator: &mut iteron_ctx::RequestEstimator,
    ) -> Result<(), KernelError> {
        self.require(RunPhase::Iteration)?;
        let loop_state = self.loop_state.take().ok_or_else(boundary)?;
        self.phase = RunPhase::Preparing;
        self.request = Some(
            super::coding_request_execution::CodingRequestExecution::new(
                seed,
                std::mem::take(&mut self.messages),
                self.submitted.take_context_recovery(),
                loop_state,
                self.submitted.error_streak(),
                estimator,
            ),
        );
        Ok(())
    }
    pub(super) fn request(
        &self,
    ) -> Result<&super::coding_request_execution::CodingRequestExecution, KernelError> {
        self.require(RunPhase::Preparing)?;
        self.request.as_ref().ok_or_else(boundary)
    }
    pub(super) fn request_mut(
        &mut self,
    ) -> Result<&mut super::coding_request_execution::CodingRequestExecution, KernelError> {
        self.require(RunPhase::Preparing)?;
        self.request.as_mut().ok_or_else(boundary)
    }
    pub(super) fn install_admitted_request(
        &mut self,
        messages: Vec<Message>,
        recovery: super::context_runtime::ContextBudgetRecoveryGuard,
    ) -> Result<(), KernelError> {
        self.require(RunPhase::Preparing)?;
        self.messages = messages;
        self.submitted.replace_context_recovery(recovery);
        self.request = None;
        Ok(())
    }
    #[cfg(feature = "legacy-plantcore")]
    pub(super) fn error_streak(&self) -> u32 {
        self.submitted.error_streak()
    }
    pub(super) fn early_effects_allowed(&self) -> bool {
        !self.convergence.enabled()
    }
    pub(super) fn admitted(
        &mut self,
        prepared: PreparedModelTurn,
        effort: EffortApplication,
    ) -> Result<AdmittedModelRequest, KernelError> {
        self.require(RunPhase::Preparing)?;
        self.evidence = Some(CodingRequestEvidence {
            turn: prepared.turn,
            estimate: prepared.request.estimate,
            inspection: prepared.request.inspection,
            effort,
        });
        self.loop_state = Some(prepared.loop_state);
        self.phase = RunPhase::Admitted;
        Ok(prepared.request)
    }
    pub(super) fn evidence(&self) -> Result<CodingRequestEvidence, KernelError> {
        self.evidence.ok_or_else(boundary)
    }
    pub(super) fn provider_start(
        &mut self,
    ) -> Result<(&mut AgentLoopGuard, &SubmittedTurnState), KernelError> {
        self.require(RunPhase::Admitted)?;
        // Phase is consumed before the actual begin future; cancellation cannot admit it twice.
        self.phase = RunPhase::ProviderStarting;
        Ok((
            self.loop_state.as_mut().ok_or_else(boundary)?,
            &self.submitted,
        ))
    }
    pub(super) fn install_provider(
        &mut self,
        provider: CodingProviderExecution,
    ) -> Result<(), KernelError> {
        self.require(RunPhase::ProviderStarting)?;
        self.hook_reads = provider.hooks_gate_reads();
        self.provider = Some(provider);
        self.phase = RunPhase::Provider;
        Ok(())
    }
    pub(super) fn provider_execution(
        &mut self,
    ) -> Result<(&mut CodingProviderExecution, &SubmittedTurnState), KernelError> {
        self.require(RunPhase::Provider)?;
        Ok((
            self.provider.as_mut().ok_or_else(boundary)?,
            &self.submitted,
        ))
    }
    pub(super) async fn resolve_provider(
        &mut self,
        journal: ProviderResponseJournal<'_>,
        scope: ProviderResponseScope<'_>,
    ) -> Result<Option<FailedProviderResponse>, KernelError> {
        self.require(RunPhase::Provider)?;
        self.phase = RunPhase::Failed;
        let (completed, obligation) = self.provider.take().ok_or_else(boundary)?.complete()?;
        match ProviderResponseRecoveryOwner::new(completed)
            .resolve(journal, scope, &mut self.submitted, &mut self.messages)
            .await?
        {
            ProviderResponseResolution::Accepted(response) => {
                self.committing = Some(ProviderResponseCommit::new(*response, obligation));
                self.phase = RunPhase::Committing;
                Ok(None)
            }
            ProviderResponseResolution::Failed(failure) => Ok(Some(failure)),
        }
    }
    pub(super) async fn record_usage(
        &mut self,
        session: ProviderCommitSession<'_>,
    ) -> Result<(), KernelError> {
        self.require(RunPhase::Committing)?;
        self.committing
            .as_mut()
            .ok_or_else(boundary)?
            .record_usage(session)
            .await
    }
    pub(super) async fn abort_response(
        &mut self,
        session: ProviderCommitSession<'_>,
    ) -> Result<(), KernelError> {
        self.phase = RunPhase::Failed;
        self.committing
            .as_mut()
            .ok_or_else(boundary)?
            .abort(session)
            .await
    }
    pub(super) fn reconcile(
        &mut self,
        session: ProviderCommitSession<'_>,
    ) -> Result<super::frontend_events::UiEvent, KernelError> {
        self.require(RunPhase::Committing)?;
        self.committing
            .as_mut()
            .ok_or_else(boundary)?
            .reconcile(session)
    }
    pub(super) async fn commit_assistant(
        &mut self,
        session: ProviderCommitSession<'_>,
    ) -> Result<(), KernelError> {
        self.require(RunPhase::Committing)?;
        self.phase = RunPhase::Failed;
        let commit = self.committing.as_mut().ok_or_else(boundary)?;
        commit.commit_assistant(session, &mut self.messages).await?;
        let commit = self.committing.take().ok_or_else(boundary)?;
        self.response = Some(ResponseState {
            elapsed: commit.stream_elapsed(),
            accepted: commit.complete()?,
            hook_reads: self.hook_reads,
        });
        self.phase = RunPhase::Response;
        Ok(())
    }
    pub(super) fn response(&self) -> Result<&AcceptedProviderResponse, KernelError> {
        self.require(RunPhase::Response)?;
        Ok(&self.response.as_ref().ok_or_else(boundary)?.accepted)
    }
    pub(super) fn malformed_tool_terminal(&self) -> Result<bool, KernelError> {
        let response = self.response()?;
        Ok(response.round.tools().call_count() > 0
            && matches!(
                response.result.stop_reason,
                StopReason::EndTurn
                    | StopReason::StopSequence
                    | StopReason::Refusal
                    | StopReason::PauseTurn
                    | StopReason::Unknown(_)
            ))
    }
    pub(super) fn early_for_cleanup(
        &mut self,
    ) -> Result<Vec<super::tool_turn::EarlyToolInFlight>, KernelError> {
        self.require(RunPhase::Response)?;
        Ok(self
            .response
            .as_mut()
            .ok_or_else(boundary)?
            .accepted
            .round
            .take_early_for_cleanup())
    }
    #[cfg(feature = "legacy-plantcore")]
    pub(super) fn record_legacy_refusal(
        &mut self,
        journal: &mut super::session_transcript::TranscriptAdmissionJournal<'_>,
        turn: TurnId,
        message: Message,
    ) -> Result<(), KernelError> {
        self.require(RunPhase::Response)?;
        self.phase = RunPhase::Failed;
        journal.message(turn, message.clone())?;
        self.messages.push(message);
        self.submitted.settle_tool_round(true);
        self.phase = RunPhase::Boundary;
        Ok(())
    }
    pub(super) fn interpret_model(
        &mut self,
        mut scope: ModelResponseScope<'_>,
    ) -> Result<ModelResponseDecision, KernelError> {
        self.require(RunPhase::Response)?;
        self.phase = RunPhase::Failed;
        let response = &self.response.as_ref().ok_or_else(boundary)?.accepted;
        if response.round.tools().call_count() != 0 {
            return Err(boundary());
        }
        scope.recovered_stream = response.recovered;
        let decision = ModelResponseInterpreter {
            submitted: &mut self.submitted,
            convergence: &mut self.convergence,
            scope,
        }
        .decide(&response.result.stop_reason);
        self.phase = RunPhase::ModelCompletion;
        Ok(decision)
    }
    pub(super) async fn complete_model(
        &mut self,
        decision: ModelResponseDecision,
        completion: TurnCompletion<'_>,
    ) -> Result<CompletionAction, KernelError> {
        self.require(RunPhase::ModelCompletion)?;
        self.phase = RunPhase::Failed;
        let action = completion
            .model(
                decision,
                &mut self.messages,
                &mut self.baseline,
                &mut self.convergence,
                self.loop_state.as_mut().ok_or_else(boundary)?,
            )
            .await?;
        self.accept_completion(action)
    }
    pub(super) fn mark_awaiting_tools(&mut self) -> Result<(), KernelError> {
        self.require(RunPhase::Response)?;
        self.loop_state
            .as_mut()
            .ok_or_else(boundary)?
            .transition(AgentLoopState::AwaitingTool)
    }
    pub(super) fn begin_tools(
        &mut self,
        scope: CodingToolScope<'_>,
    ) -> Result<Vec<super::frontend_events::UiEvent>, KernelError> {
        self.require(RunPhase::Response)?;
        self.phase = RunPhase::Failed;
        let response = self.response.take().ok_or_else(boundary)?;
        if response.accepted.round.tools().call_count() == 0 {
            return Err(boundary());
        }
        let optional = OptionalToolRound::prepare(
            &self.convergence,
            scope.explicit_verification,
            scope.registry,
            scope.workspace,
            response.accepted.round.tools(),
            &response.accepted.tools,
        );
        let declarations: Arc<[ToolUse]> = response.accepted.tools.into();
        let start = response.accepted.round.stream_started();
        let (round, replayed) = ToolRoundDriver::retain_owned(
            declarations.clone(),
            response.accepted.round.into_tool_work()?,
            EarlyToolWindow {
                stream_start: start,
                stream_elapsed: response.elapsed,
                hook_gates_reads: response.hook_reads,
                queued: scope.queued_reads,
                projection: scope.projection,
            },
        )?;
        self.tools = Some(ToolsState {
            execution: ToolRoundExecution::new(round),
            optional,
            declarations,
            recovered: response.accepted.recovered,
        });
        self.phase = RunPhase::Tools;
        Ok(replayed)
    }
    pub(super) async fn pump_tools(
        &mut self,
        session: ToolExecutionSession<'_>,
    ) -> Result<ToolRoundProgress, KernelError> {
        self.require(RunPhase::Tools)?;
        let tools = self.tools.as_mut().ok_or_else(boundary)?;
        tools
            .execution
            .pump(session, &tools.optional, &mut self.baseline)
            .await
    }
    pub(super) fn settle_kernel(
        &mut self,
        index: usize,
        result: ToolResult,
    ) -> Result<(), KernelError> {
        self.require(RunPhase::Tools)?;
        self.tools
            .as_mut()
            .ok_or_else(boundary)?
            .execution
            .settle_kernel(index, result)
    }
    pub(super) fn has_tool_images(&self) -> Result<bool, KernelError> {
        self.require(RunPhase::Tools)?;
        Ok(self
            .tools
            .as_ref()
            .ok_or_else(boundary)?
            .execution
            .has_images())
    }
    pub(super) async fn settle_tools(
        &mut self,
        mut images: Option<ToolImageProjection<'_>>,
        events: &StreamToolEvents,
        remaining: u32,
    ) -> Result<(SettledCodingTools, bool), KernelError> {
        self.require(RunPhase::Tools)?;
        self.phase = RunPhase::Failed;
        let tools = self.tools.take().ok_or_else(boundary)?;
        let round = tools.execution.into_round()?;
        round.validate_complete()?;
        self.submitted.settle_tool_round(round.had_error());
        let diff = if tools.optional.requires_diff(
            self.convergence.candidate_review_active(),
            tools.declarations.len(),
        ) {
            Some(self.baseline.diff_state().await)
        } else {
            None
        };
        let settlement = tools.optional.settle(
            &mut self.convergence,
            &tools.declarations,
            round.results(),
            round.had_error(),
            diff,
        );
        let schemas_changed = round.schemas_changed();
        if tools.recovered {
            round.retain_recovery(&mut self.submitted)?;
        }
        let ToolResponseParts {
            mut message,
            images: captured,
        } = round.into_parts()?;
        for projection in captured {
            if message.append_images(
                images
                    .as_mut()
                    .ok_or_else(boundary)?
                    .project_captured_tool_images(&projection.receipt, &projection.images),
            ) {
                events.present(super::frontend_events::UiEvent::Notice("Tool images exceed the model message image envelope; excess retained images remain unavailable in this request".into()));
            }
        }
        if let Some(request) = settlement.request {
            message.guidance(format!(
                "{} [budget: {} provider turn(s) remain]",
                request.instruction, remaining
            ));
            events.emit(
                "context.segment.updated",
                None,
                LifecyclePayload {
                    count: Some(u64::from(request.observations)),
                    reason_code: Some(request.stage.reason_code().into()),
                    ..Default::default()
                },
            );
        }
        let automatic_candidate =
            settlement.completed_change && matches!(diff, Some(CandidateDiffState::Changed(_)));
        self.phase = RunPhase::ToolCompletion;
        Ok((
            SettledCodingTools {
                message,
                automatic_candidate,
            },
            schemas_changed,
        ))
    }
    pub(super) async fn complete_tools(
        &mut self,
        settled: SettledCodingTools,
        completion: TurnCompletion<'_>,
    ) -> Result<CompletionAction, KernelError> {
        self.require(RunPhase::ToolCompletion)?;
        self.phase = RunPhase::Failed;
        let action = completion
            .tools(
                settled.message,
                settled.automatic_candidate,
                &mut self.messages,
                &mut self.baseline,
                &mut self.convergence,
            )
            .await?;
        self.accept_completion(action)
    }
    pub(super) fn answer_blocks(&self) -> Result<&[Block], KernelError> {
        if self.phase != RunPhase::Closed {
            return Err(boundary());
        }
        Ok(&self
            .response
            .as_ref()
            .ok_or_else(boundary)?
            .accepted
            .result
            .blocks)
    }
    pub(super) fn into_messages(self) -> Result<Vec<Message>, KernelError> {
        match self.request {
            Some(request) => request.into_messages(),
            None => Ok(self.messages),
        }
    }
    fn accept_completion(
        &mut self,
        action: CompletionAction,
    ) -> Result<CompletionAction, KernelError> {
        self.phase = match &action {
            CompletionAction::Continue { applying_steer } => {
                if *applying_steer {
                    self.loop_state
                        .as_mut()
                        .ok_or_else(boundary)?
                        .transition(AgentLoopState::ApplyingSteer)?;
                }
                RunPhase::Boundary
            }
            _ => RunPhase::Closed,
        };
        Ok(action)
    }
    fn require(&self, phase: RunPhase) -> Result<(), KernelError> {
        if self.phase == phase {
            Ok(())
        } else {
            Err(boundary())
        }
    }
}
fn boundary() -> KernelError {
    KernelError::EffectBoundary("coding invocation cannot reuse a consumed execution phase".into())
}
