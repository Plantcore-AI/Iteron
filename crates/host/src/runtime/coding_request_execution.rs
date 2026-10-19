//! Actual invocation request ownership across auxiliary IO and final admission. The working
//! transcript and recovery bridge stay retained on every error, interrupt and cancelled future.
use super::KernelError;
use super::agent_loop::AgentLoopGuard;
use super::compaction_journal::{
    CompactionCommitJournal, CompactionCommitScope, CompactionStateOwner,
};
use super::context_preparation_events::ContextPreparationEvents;
use super::context_runtime::ContextBudgetRecoveryGuard;
use super::hooks::HookDecision;
use super::request_accounting::RequestAccounting;
use super::request_admission_journal::RequestAdmissionJournal;
use super::request_context_publication::RequestContextPublication;
use super::request_cycle::{
    AdmittingRequestCycle, PreparedModelTurn, ReboundRequest, RequestCycle, RequestCycleRecipe,
};
use super::request_preparation::{RequestConfiguration, RequestMessages};
use super::request_recovery_driver::RequestRecoveryWork;
use iteron_ctx::RequestEstimator;
use iteron_protocol::{LifecyclePayload, Message, TurnId};

enum RequestState {
    Recovering(RequestCycle<'static, 'static>),
    Admitting {
        cycle: AdmittingRequestCycle<'static>,
        recovery: ContextBudgetRecoveryGuard,
    },
}
pub(super) struct CodingRequestExecution {
    state: Option<RequestState>,
    error_streak: u32,
    recovery_complete: bool,
}
impl CodingRequestExecution {
    pub(super) fn new(
        mut seed: RequestCycleRecipe<'static>,
        messages: Vec<Message>,
        recovery: ContextBudgetRecoveryGuard,
        loop_state: AgentLoopGuard,
        error_streak: u32,
        estimator: &mut RequestEstimator,
    ) -> Self {
        seed.content.messages = RequestMessages::Owned(messages);
        Self {
            state: Some(RequestState::Recovering(RequestCycle::owned(
                seed, recovery, estimator, loop_state,
            ))),
            error_streak,
            recovery_complete: false,
        }
    }
    pub(super) fn next_recovery(&mut self) -> Result<RequestRecoveryWork<'_>, KernelError> {
        let RequestState::Recovering(cycle) = self.state.as_mut().ok_or_else(boundary)? else {
            return Err(boundary());
        };
        let work = cycle.next_recovery()?;
        if matches!(work, RequestRecoveryWork::Complete) {
            self.recovery_complete = true;
        }
        Ok(work)
    }
    pub(super) fn requested_output(&self) -> Result<u32, KernelError> {
        let RequestState::Recovering(cycle) = self.state.as_ref().ok_or_else(boundary)? else {
            return Err(boundary());
        };
        Ok(cycle.requested_output())
    }
    pub(super) fn gated(&mut self, allowed: bool) -> Result<(), KernelError> {
        self.recovery()?.gated(allowed)
    }
    pub(super) fn summary_completed(
        &mut self,
        result: Result<String, KernelError>,
        turn: TurnId,
    ) -> Result<(), KernelError> {
        self.recovery()?.summary_completed(result, turn)
    }
    pub(super) fn control_checked(&mut self, turn: TurnId) -> Result<(), KernelError> {
        self.recovery()?.control_checked(turn)
    }
    pub(super) fn coverage_completed(
        &mut self,
        result: Result<bool, KernelError>,
        turn: TurnId,
    ) -> Result<(), KernelError> {
        self.recovery()?.coverage_completed(result, turn)
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn assess_and_commit(
        &mut self,
        window: Option<u64>,
        output: u32,
        accounting: RequestAccounting,
        journal: &mut CompactionCommitJournal<'_>,
        scope: CompactionCommitScope,
        estimator: &mut RequestEstimator,
        state: &mut CompactionStateOwner,
    ) -> Result<bool, KernelError> {
        self.recovery()?
            .assess_and_commit(window, output, accounting, journal, scope, estimator, state)
    }
    pub(super) fn bind(
        &mut self,
        turn: TurnId,
        window: Option<u64>,
        output: u32,
    ) -> Result<ReboundRequest, KernelError> {
        if !self.recovery_complete {
            return Err(boundary());
        }
        self.recovery()?
            .prepare_owned_admission(turn, window, output)?;
        let Some(RequestState::Recovering(cycle)) = self.state.take() else {
            return Err(boundary());
        };
        match cycle.bind_owned_after_recovery(turn) {
            Ok((cycle, rebound, recovery)) => {
                self.state = Some(RequestState::Admitting { cycle, recovery });
                Ok(rebound)
            }
            Err(cycle) => {
                self.state = Some(RequestState::Recovering(*cycle));
                Err(boundary())
            }
        }
    }
    pub(super) fn error_streak(&self) -> u32 {
        self.error_streak
    }
    pub(super) fn validate(
        &mut self,
        journal: RequestAdmissionJournal<'_>,
        events: &ContextPreparationEvents,
    ) -> Result<(), KernelError> {
        self.admission()?.validate(journal, events)
    }
    pub(super) fn request_gate(&mut self) -> Result<LifecyclePayload, KernelError> {
        self.admission()?.request_gate()
    }
    pub(super) fn gate_completed(&mut self, decision: HookDecision) -> Result<(), KernelError> {
        self.admission()?.gate_completed(decision)
    }
    pub(super) fn control_passed(&mut self) -> Result<(), KernelError> {
        self.admission()?.control_passed()
    }
    pub(super) fn messages(&self) -> Result<&[Message], KernelError> {
        let RequestState::Admitting { cycle, .. } = self.state.as_ref().ok_or_else(boundary)?
        else {
            return Err(boundary());
        };
        Ok(cycle.messages())
    }
    /// Projection is produced once while the actual source remains held; a validation failure
    /// cannot make the next resident submission forget its admitted/compacted transcript.
    pub(super) fn complete(
        &mut self,
        configuration: RequestConfiguration,
        publication: RequestContextPublication<'_>,
    ) -> Result<(PreparedModelTurn, Vec<Message>, ContextBudgetRecoveryGuard), KernelError> {
        let request = self
            .admission()?
            .project_owned(configuration, publication)?;
        let Some(RequestState::Admitting { cycle, recovery }) = self.state.take() else {
            return Err(boundary());
        };
        let (prepared, messages) = cycle.release_owned(request)?;
        Ok((prepared, messages, recovery))
    }
    pub(super) fn into_messages(self) -> Result<Vec<Message>, KernelError> {
        match self.state.ok_or_else(boundary)? {
            RequestState::Recovering(cycle) => cycle.into_owned_messages(),
            RequestState::Admitting { cycle, .. } => cycle.into_owned_messages(),
        }
    }
    fn recovery(&mut self) -> Result<&mut RequestCycle<'static, 'static>, KernelError> {
        match self.state.as_mut() {
            Some(RequestState::Recovering(cycle)) => Ok(cycle),
            _ => Err(boundary()),
        }
    }
    fn admission(&mut self) -> Result<&mut AdmittingRequestCycle<'static>, KernelError> {
        match self.state.as_mut() {
            Some(RequestState::Admitting { cycle, .. }) => Ok(cycle),
            _ => Err(boundary()),
        }
    }
}
fn boundary() -> KernelError {
    KernelError::EffectBoundary("coding request ownership cannot revisit a consumed stage".into())
}

#[cfg(all(test, unix))]
#[path = "coding_request_execution_tests.rs"]
mod tests;
