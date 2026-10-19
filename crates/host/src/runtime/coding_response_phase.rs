//! Owns the real post-provider phase clock, projection allowance and pending completed tool
//! message. Tool handles/leases remain in CodingRunDriver; completion runs only after settlement.
use super::KernelError;
use super::coding_run_driver::{CodingRunDriver, CodingToolScope, SettledCodingTools};
use super::context_runtime::TurnResultProjectionBudget;
use super::frontend_events::UiEvent;
use super::kernel_special_execution::KernelSpecialResult;
use super::model_response::ModelResponseDecision;
use super::stream_tool_events::StreamToolEvents;
use super::tool_execution_session::ToolExecutionSession;
use super::tool_image_projection::ToolImageProjection;
use super::tool_result_projection::ToolResultProjectionPolicy;
use super::tool_round_execution::ToolRoundProgress;
use super::turn_completion::{CompletionAction, TurnCompletion};
use iteron_obs::{Ledger, PhaseSpan};
use iteron_protocol::Phase;
use iteron_tools::Registry;
use std::path::Path;

pub(super) struct CodingResponsePhase {
    clock: PhaseSpan,
    projection: TurnResultProjectionBudget,
    total: usize,
    settled: Option<SettledCodingTools>,
}
impl CodingResponsePhase {
    pub(super) fn new(
        driver: &mut CodingRunDriver,
        scope: ToolResultProjectionPolicy<'_>,
    ) -> Result<Self, KernelError> {
        let clock = PhaseSpan::enter(Phase::Tools);
        let response = driver.response()?;
        let total = response.round.tools().call_count();
        let projection = scope.calculate(&response.tools);
        Ok(Self {
            clock,
            projection,
            total,
            settled: None,
        })
    }
    pub(super) fn total(&self) -> usize {
        self.total
    }
    pub(super) fn projection(&self) -> TurnResultProjectionBudget {
        self.projection
    }
    pub(super) fn observe_elapsed(&self, ledger: &mut Ledger) {
        ledger.phase_tools(self.clock.elapsed_ms());
    }
    pub(super) fn begin_tools(
        &self,
        driver: &mut CodingRunDriver,
        registry: &Registry,
        workspace: &Path,
        explicit_verification: bool,
    ) -> Result<Vec<UiEvent>, KernelError> {
        let queued_reads = driver.response()?.execution.queued_reads();
        driver.begin_tools(CodingToolScope {
            registry,
            workspace,
            explicit_verification,
            queued_reads,
            projection: self.projection,
        })
    }
    pub(super) async fn pump_tools(
        &self,
        driver: &mut CodingRunDriver,
        session: ToolExecutionSession<'_>,
    ) -> Result<ToolRoundProgress, KernelError> {
        driver.pump_tools(session).await
    }
    pub(super) fn kernel_returned(
        &self,
        driver: &mut CodingRunDriver,
        index: usize,
        result: KernelSpecialResult,
    ) -> Result<(), KernelError> {
        let (result, accounting_error) = match result {
            KernelSpecialResult::Completed(result) | KernelSpecialResult::Refused(result) => {
                (result, None)
            }
            KernelSpecialResult::AccountingUnavailable { result, reason } => (result, Some(reason)),
        };
        // The physical known result closes its retained declaration/lease before an unavailable
        // accounting projection stops this invocation. No Known execution is recast as Unknown.
        driver.settle_kernel(index, result)?;
        if let Some(reason) = accounting_error {
            return Err(KernelError::ContextResolution(reason));
        }
        Ok(())
    }
    pub(super) async fn complete_model(
        &self,
        driver: &mut CodingRunDriver,
        decision: ModelResponseDecision,
        completion: TurnCompletion<'_>,
    ) -> Result<CompletionAction, KernelError> {
        driver.complete_model(decision, completion).await
    }
    pub(super) async fn settle_tools(
        &mut self,
        driver: &mut CodingRunDriver,
        images: Option<ToolImageProjection<'_>>,
        events: &StreamToolEvents,
        remaining: u32,
    ) -> Result<bool, KernelError> {
        if self.settled.is_some() {
            return Err(boundary());
        }
        let (settled, schemas_changed) = driver.settle_tools(images, events, remaining).await?;
        self.settled = Some(settled);
        Ok(schemas_changed)
    }
    pub(super) async fn complete_tools(
        &mut self,
        driver: &mut CodingRunDriver,
        completion: TurnCompletion<'_>,
    ) -> Result<CompletionAction, KernelError> {
        let settled = self.settled.take().ok_or_else(boundary)?;
        driver.complete_tools(settled, completion).await
    }
}
fn boundary() -> KernelError {
    KernelError::EffectBoundary("post-provider phase has no retained settled tool message".into())
}
