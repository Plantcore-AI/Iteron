//! Finite emergency-request recovery. This owner retains the real preparation candidate and
//! orders gating, summary, control, coverage, current-route assessment and confirmed publication.
//! Host IO returns typed results; it cannot select another candidate or skip the control barrier.
use super::KernelError;
use super::compaction_journal::{
    CompactionCommitJournal, CompactionCommitScope, CompactionStateOwner,
};
use super::context_preparation_events::ContextPreparationEvents;
use super::context_runtime::{ContextBudgetRecoveryGuard, ContextBudgetRecoveryStage};
use super::request_accounting::RequestAccounting;
use super::request_preparation::RequestPreparation;
use iteron_ctx::{CompactionPolicy, ContextBudgetViolation, RequestEstimator};
use iteron_protocol::{LifecyclePayload, Message, TurnId};

#[derive(Clone, Copy, PartialEq, Eq)]
enum RecoveryPhase {
    Fresh,
    GatePending,
    SummaryReady,
    SummaryPending,
    ControlReady,
    ControlPending,
    CoverageReady,
    CoveragePending,
    AssessmentReady,
    AssessmentPending,
    Settling,
    Complete,
    Failed,
}

pub(super) enum RequestRecoveryWork<'a> {
    Gate(LifecyclePayload),
    Summary(&'a [Message]),
    ControlBarrier,
    Coverage {
        middle: &'a [Message],
        summary: &'a str,
    },
    AssessAndCommit,
    Complete,
}

pub(super) struct RequestRecoveryScope {
    pub(super) turn: TurnId,
    pub(super) policy: CompactionPolicy,
    pub(super) compacted: bool,
    pub(super) covered_on_verifier_error: bool,
    pub(super) events: ContextPreparationEvents,
}

pub(super) enum RequestRecoveryGuard<'g> {
    Owned(ContextBudgetRecoveryGuard),
    #[cfg_attr(not(test), allow(dead_code))]
    Borrowed(&'g mut ContextBudgetRecoveryGuard),
}
impl std::ops::Deref for RequestRecoveryGuard<'_> {
    type Target = ContextBudgetRecoveryGuard;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Owned(guard) => guard,
            Self::Borrowed(guard) => guard,
        }
    }
}
impl std::ops::DerefMut for RequestRecoveryGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Owned(guard) => guard,
            Self::Borrowed(guard) => guard,
        }
    }
}
pub(super) struct RequestRecoveryDriver<'a, 'g> {
    preparation: RequestPreparation<'a>,
    guard: RequestRecoveryGuard<'g>,
    scope: RequestRecoveryScope,
    phase: RecoveryPhase,
    current_turn: TurnId,
    summary: Option<String>,
    covered: bool,
}

impl<'a, 'g> RequestRecoveryDriver<'a, 'g> {
    #[cfg(test)]
    pub(super) fn new(
        preparation: RequestPreparation<'a>,
        guard: &'g mut ContextBudgetRecoveryGuard,
        scope: RequestRecoveryScope,
    ) -> Self {
        let current_turn = scope.turn;
        Self {
            preparation,
            guard: RequestRecoveryGuard::Borrowed(guard),
            scope,
            phase: RecoveryPhase::Fresh,
            current_turn,
            summary: None,
            covered: false,
        }
    }

    /// Every work item is consumed before IO. A dropped host future cannot request the same
    /// summary, coverage or publication again. Only its corresponding typed result advances.
    pub(super) fn next(&mut self) -> Result<RequestRecoveryWork<'_>, KernelError> {
        match self.phase {
            RecoveryPhase::Fresh => {
                if let Some(payload) = self.preparation.recovery_request(
                    &self.scope.policy,
                    self.scope.compacted,
                    &mut self.guard,
                ) {
                    self.phase = RecoveryPhase::GatePending;
                    return Ok(RequestRecoveryWork::Gate(payload));
                }
                self.phase = RecoveryPhase::Complete;
                Ok(RequestRecoveryWork::Complete)
            }
            RecoveryPhase::SummaryReady => {
                self.phase = RecoveryPhase::SummaryPending;
                let plan = self.preparation.plan().ok_or_else(refused)?;
                self.scope.events.emit(
                    self.scope.turn,
                    ContextBudgetRecoveryStage::Started.event_id(),
                    self.preparation
                        .recovery_payload(Some(plan.to_summarize.len())),
                );
                Ok(RequestRecoveryWork::Summary(&plan.to_summarize))
            }
            RecoveryPhase::ControlReady => {
                self.phase = RecoveryPhase::ControlPending;
                Ok(RequestRecoveryWork::ControlBarrier)
            }
            RecoveryPhase::CoverageReady => {
                self.phase = RecoveryPhase::CoveragePending;
                Ok(RequestRecoveryWork::Coverage {
                    middle: &self.preparation.plan().ok_or_else(refused)?.to_summarize,
                    summary: self.summary.as_deref().ok_or_else(refused)?,
                })
            }
            RecoveryPhase::AssessmentReady => {
                self.phase = RecoveryPhase::AssessmentPending;
                Ok(RequestRecoveryWork::AssessAndCommit)
            }
            RecoveryPhase::Settling => {
                if let Some((violation, after)) = self.preparation.settle_recovery(&mut self.guard)
                {
                    self.component_event(
                        TurnId(self.current_turn.0.saturating_sub(1).max(self.scope.turn.0)),
                        ContextBudgetRecoveryStage::Failed,
                        violation,
                        after,
                    );
                }
                self.phase = RecoveryPhase::Complete;
                Ok(RequestRecoveryWork::Complete)
            }
            _ => Err(refused()),
        }
    }

    pub(super) fn gated(&mut self, allowed: bool) -> Result<(), KernelError> {
        self.require(RecoveryPhase::GatePending)?;
        self.preparation
            .authorize_recovery(&self.scope.policy, allowed);
        self.phase = if self.preparation.plan().is_some() {
            RecoveryPhase::SummaryReady
        } else {
            RecoveryPhase::Settling
        };
        Ok(())
    }

    pub(super) fn summary_completed(
        &mut self,
        result: Result<String, KernelError>,
        turn: TurnId,
    ) -> Result<(), KernelError> {
        self.require(RecoveryPhase::SummaryPending)?;
        if turn.0 < self.current_turn.0 {
            self.phase = RecoveryPhase::Failed;
            return Err(refused());
        }
        self.current_turn = turn;
        self.phase = match result {
            Ok(summary) => {
                self.summary = Some(summary);
                RecoveryPhase::ControlReady
            }
            Err(_) => {
                self.scope.events.emit(
                    self.scope.turn,
                    "context.compaction.failed",
                    LifecyclePayload::default(),
                );
                RecoveryPhase::Settling
            }
        };
        Ok(())
    }

    /// Host must poll/settle actual control after summary IO and before returning this receipt.
    /// The current physical turn is monotone because summary/coverage spend their own identities.
    pub(super) fn control_checked(&mut self, turn: TurnId) -> Result<(), KernelError> {
        self.require(RecoveryPhase::ControlPending)?;
        if turn.0 < self.current_turn.0 {
            self.phase = RecoveryPhase::Failed;
            return Err(refused());
        }
        self.current_turn = turn;
        self.phase = if self.scope.policy.coverage_check {
            RecoveryPhase::CoverageReady
        } else {
            self.covered = true;
            RecoveryPhase::AssessmentReady
        };
        Ok(())
    }

    pub(super) fn coverage_completed(
        &mut self,
        result: Result<bool, KernelError>,
        turn: TurnId,
    ) -> Result<(), KernelError> {
        self.require(RecoveryPhase::CoveragePending)?;
        if turn.0 < self.current_turn.0 {
            self.phase = RecoveryPhase::Failed;
            return Err(refused());
        }
        self.current_turn = turn;
        self.covered = result.unwrap_or(self.scope.covered_on_verifier_error);
        self.phase = RecoveryPhase::AssessmentReady;
        Ok(())
    }

    /// The real estimator, immutable current route evidence and one durable writer are explicit
    /// ports. A failed append keeps the actual original transcript and cannot install a candidate.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn assess_and_commit(
        &mut self,
        window: Option<u64>,
        output: u32,
        accounting: RequestAccounting,
        journal: &mut CompactionCommitJournal<'_>,
        mut scope: CompactionCommitScope,
        estimator: &mut RequestEstimator,
        state: &mut CompactionStateOwner,
    ) -> Result<bool, KernelError> {
        self.require(RecoveryPhase::AssessmentPending)?;
        self.phase = RecoveryPhase::Failed;
        self.preparation.bind_route_budget(window, output)?;
        let summary = self.summary.as_deref().ok_or_else(refused)?;
        let turn = TurnId(self.current_turn.0.saturating_sub(1));
        let reason = self.preparation.assess_summary(
            summary,
            self.covered,
            &self.scope.policy,
            estimator,
            accounting,
        )?;
        let committed = if let Some(reason) = reason {
            self.scope.events.emit(
                turn,
                "context.compaction.failed",
                LifecyclePayload {
                    reason_code: Some(reason.into()),
                    ..LifecyclePayload::default()
                },
            );
            if let Some(error) = self.preparation.fatal_recovery_refusal(self.covered) {
                return Err(error);
            }
            false
        } else {
            scope.context_window = window;
            scope.output_reserve = output;
            let receipt = journal.commit(
                turn,
                &self.preparation.request().messages,
                self.preparation.plan().ok_or_else(refused)?,
                summary,
                self.preparation.recovery_reason(),
                self.scope.policy.coverage_check && self.covered,
                scope,
                estimator,
                state,
            )?;
            if let Some((violation, after)) =
                self.preparation.commit_candidate(receipt, estimator)?
            {
                self.component_event(
                    turn,
                    ContextBudgetRecoveryStage::Completed,
                    violation,
                    after,
                );
            }
            true
        };
        self.summary = None;
        self.phase = RecoveryPhase::Settling;
        Ok(committed)
    }

    pub(super) fn into_messages(self) -> Option<Vec<Message>> {
        self.preparation.into_messages()
    }
    #[cfg(test)]
    pub(super) fn into_preparation(self) -> Result<RequestPreparation<'a>, KernelError> {
        self.require(RecoveryPhase::Complete)?;
        Ok(self.preparation)
    }
    fn require(&self, phase: RecoveryPhase) -> Result<(), KernelError> {
        if self.phase == phase {
            Ok(())
        } else {
            Err(refused())
        }
    }
    fn component_event(
        &self,
        turn: TurnId,
        stage: ContextBudgetRecoveryStage,
        violation: ContextBudgetViolation,
        observed: usize,
    ) {
        self.scope.events.emit(
            turn,
            stage.event_id(),
            LifecyclePayload {
                reason_code: Some(violation.reason_code().into()),
                count: Some(u64::try_from(violation.ceiling).unwrap_or(u64::MAX)),
                magnitude: Some(u64::try_from(observed).unwrap_or(u64::MAX)),
                ..LifecyclePayload::default()
            },
        );
    }
}

fn refused() -> KernelError {
    KernelError::ContextResolution("request recovery work lacks its preceding receipt".into())
}

impl RequestRecoveryDriver<'static, 'static> {
    pub(super) fn owned(
        preparation: RequestPreparation<'static>,
        guard: ContextBudgetRecoveryGuard,
        scope: RequestRecoveryScope,
    ) -> Self {
        let current_turn = scope.turn;
        Self {
            preparation,
            guard: RequestRecoveryGuard::Owned(guard),
            scope,
            phase: RecoveryPhase::Fresh,
            current_turn,
            summary: None,
            covered: false,
        }
    }
    pub(super) fn prepare_owned_admission(
        &mut self,
        window: Option<u64>,
        output: u32,
    ) -> Result<(), KernelError> {
        self.require(RecoveryPhase::Complete)?;
        if !matches!(self.guard, RequestRecoveryGuard::Owned(_)) {
            return Err(refused());
        }
        self.preparation.bind_route_budget(window, output)
    }
    pub(super) fn into_owned_parts(
        self,
    ) -> Result<(RequestPreparation<'static>, ContextBudgetRecoveryGuard), Box<Self>> {
        if self.phase != RecoveryPhase::Complete
            || !matches!(self.guard, RequestRecoveryGuard::Owned(_))
        {
            return Err(Box::new(self));
        }
        let RequestRecoveryGuard::Owned(guard) = self.guard else {
            unreachable!("owned recovery guard was checked before consumption")
        };
        Ok((self.preparation, guard))
    }
}
