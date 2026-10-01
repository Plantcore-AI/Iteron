//! One ordinary logical request lifetime. The actual recovery candidate, current-turn loop
//! state and final admission move together; no second request can reuse a consumed stage.
use super::KernelError;
use super::agent_loop::AgentLoopGuard;
use super::context_runtime::ContextBudgetRecoveryGuard;
use super::hooks::HookDecision;
use super::request_accounting::RequestAccounting;
use super::request_admission::{AdmittedModelRequest, RequestAdmission};
use super::request_admission_journal::RequestAdmissionJournal;
use super::request_context_publication::RequestContextPublication;
use super::request_preparation::{RequestConfiguration, RequestContent, RequestPreparation};
use super::request_recovery_driver::{
    RequestRecoveryDriver, RequestRecoveryScope, RequestRecoveryWork,
};
use iteron_ctx::RequestEstimator;
use iteron_protocol::{LifecyclePayload, Message, TurnId};
use std::time::Instant;

pub(super) struct RequestCycleRecipe<'a> {
    pub(super) content: RequestContent<'a>,
    pub(super) requested_output: u32,
    pub(super) window: Option<u64>,
    pub(super) accounting: RequestAccounting,
    pub(super) recovery: RequestRecoveryScope,
    pub(super) started: Instant,
}
pub(super) struct RequestCycle<'a, 'g> {
    recovery: RequestRecoveryDriver<'a, 'g>,
    loop_state: AgentLoopGuard,
    turn: TurnId,
    started: Instant,
    requested_output: u32,
}
pub(super) struct AdmittingRequestCycle<'a> {
    admission: RequestAdmission<'a>,
    loop_state: AgentLoopGuard,
    turn: TurnId,
    started: Instant,
}
pub(super) struct ReboundRequest {
    pub(super) turn_changed: bool,
    pub(super) baseline: usize,
}
pub(super) struct PreparedModelTurn {
    pub(super) turn: TurnId,
    pub(super) request: AdmittedModelRequest,
    pub(super) loop_state: AgentLoopGuard,
}

impl<'a, 'g> RequestCycle<'a, 'g> {
    pub(super) fn new(
        recipe: RequestCycleRecipe<'a>,
        guard: &'g mut ContextBudgetRecoveryGuard,
        estimator: &mut RequestEstimator,
        loop_state: AgentLoopGuard,
    ) -> Self {
        let turn = recipe.recovery.turn;
        let requested_output = recipe.requested_output;
        recipe.recovery.events.emit(
            turn,
            "context.tokenizer.estimate_started",
            LifecyclePayload::default(),
        );
        let preparation = RequestPreparation::new(
            recipe.content,
            recipe.requested_output,
            recipe.window,
            recipe.accounting,
            estimator,
        );
        recipe.recovery.events.emit(
            turn,
            "context.tokenizer.estimate_completed",
            LifecyclePayload {
                magnitude: Some(
                    u64::try_from(preparation.estimate().total_tokens).unwrap_or(u64::MAX),
                ),
                ..Default::default()
            },
        );
        Self {
            recovery: RequestRecoveryDriver::new(preparation, guard, recipe.recovery),
            loop_state,
            turn,
            started: recipe.started,
            requested_output,
        }
    }
    pub(super) fn next_recovery(&mut self) -> Result<RequestRecoveryWork<'_>, KernelError> {
        self.recovery.next()
    }
    pub(super) fn requested_output(&self) -> u32 {
        self.requested_output
    }
    pub(super) fn gated(&mut self, allowed: bool) -> Result<(), KernelError> {
        self.recovery.gated(allowed)
    }
    pub(super) fn summary_completed(
        &mut self,
        result: Result<String, KernelError>,
        turn: TurnId,
    ) -> Result<(), KernelError> {
        self.recovery.summary_completed(result, turn)
    }
    pub(super) fn control_checked(&mut self, turn: TurnId) -> Result<(), KernelError> {
        self.recovery.control_checked(turn)
    }
    pub(super) fn coverage_completed(
        &mut self,
        result: Result<bool, KernelError>,
        turn: TurnId,
    ) -> Result<(), KernelError> {
        self.recovery.coverage_completed(result, turn)
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn assess_and_commit(
        &mut self,
        window: Option<u64>,
        output: u32,
        accounting: RequestAccounting,
        journal: &mut super::compaction_journal::CompactionCommitJournal<'_>,
        scope: super::compaction_journal::CompactionCommitScope,
        estimator: &mut RequestEstimator,
        state: &mut super::compaction_journal::CompactionStateOwner,
    ) -> Result<bool, KernelError> {
        self.recovery
            .assess_and_commit(window, output, accounting, journal, scope, estimator, state)
    }
    /// Auxiliary work and the real post-summary control barrier have completed. Their current
    /// physical identity and signed route bounds replace the initial request only once.
    pub(super) fn bind_after_recovery(
        self,
        current_turn: TurnId,
        window: Option<u64>,
        output: u32,
    ) -> Result<(AdmittingRequestCycle<'a>, ReboundRequest), KernelError> {
        if current_turn.0 < self.turn.0 {
            return Err(boundary());
        }
        let preparation = self.recovery.into_preparation()?;
        let admission = RequestAdmission::new(preparation, current_turn, window, output)?;
        let baseline = admission.baseline();
        let turn_changed = current_turn != self.turn;
        let loop_state = if turn_changed {
            AgentLoopGuard::begin(current_turn)
        } else {
            self.loop_state
        };
        Ok((
            AdmittingRequestCycle {
                admission,
                loop_state,
                turn: current_turn,
                started: self.started,
            },
            ReboundRequest {
                turn_changed,
                baseline,
            },
        ))
    }
}

impl<'a> AdmittingRequestCycle<'a> {
    pub(super) fn validate(
        &mut self,
        journal: RequestAdmissionJournal<'_>,
        events: &super::context_preparation_events::ContextPreparationEvents,
    ) -> Result<(), KernelError> {
        self.admission
            .validate(journal, events, &mut self.loop_state)
    }
    pub(super) fn request_gate(&mut self) -> Result<LifecyclePayload, KernelError> {
        self.admission.request_gate()
    }
    pub(super) fn gate_completed(&mut self, decision: HookDecision) -> Result<(), KernelError> {
        self.admission.gate_completed(decision)
    }
    pub(super) fn control_passed(&mut self) -> Result<(), KernelError> {
        self.admission.control_passed()
    }
    pub(super) fn messages(&self) -> &[Message] {
        self.admission.messages()
    }
    pub(super) fn complete(
        self,
        configuration: RequestConfiguration,
        publication: RequestContextPublication<'_>,
    ) -> Result<PreparedModelTurn, KernelError> {
        let elapsed_us = u64::try_from(self.started.elapsed().as_micros()).unwrap_or(u64::MAX);
        Ok(PreparedModelTurn {
            turn: self.turn,
            request: self
                .admission
                .complete(configuration, publication, elapsed_us)?,
            loop_state: self.loop_state,
        })
    }
}
fn boundary() -> KernelError {
    KernelError::ContextResolution(
        "request cycle cannot revisit a consumed preparation or admission".into(),
    )
}

#[cfg(all(test, unix))]
#[path = "request_cycle_tests.rs"]
mod tests;
