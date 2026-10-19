//! Retains the current physical provider round and its logical USD obligation together.
//! The host supplies real disjoint ports; retry, capture and settlement stay in their owners.
use super::KernelError;
use super::agent_loop::AgentLoopGuard;
use super::memory_request_exposure::MemoryRequestExposure;
use super::pricing::ProviderAttemptGuard;
use super::provider_execution_scope::ProviderExecutionEvidence;
use super::provider_extension::ProviderExtensionPort;
use super::provider_hedge::HedgedProviderDispatch;
use super::provider_turn_driver::{
    CompletedProviderTurn, ProviderHedgeSpec, ProviderPumpProgress, ProviderTurnDriver,
    ProviderTurnEnvironment, ProviderTurnJournal, ProviderTurnResident, ProviderTurnStart,
};
use iteron_provider::RateLimitSnapshot;
use std::time::Instant;

pub(super) enum CodingProviderProgress {
    Hedge,
    Complete,
}
pub(super) struct CodingProviderExecution {
    driver: Option<ProviderTurnDriver>,
    completed: Option<CompletedProviderTurn>,
    obligation: Option<ProviderAttemptGuard>,
    hook_reads: bool,
    failed: bool,
}
impl CodingProviderExecution {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn begin(
        start: ProviderTurnStart,
        obligation: ProviderAttemptGuard,
        journal: ProviderTurnJournal<'_>,
        environment: ProviderTurnEnvironment<'_>,
        resident: &ProviderTurnResident<'_>,
        extension: ProviderExtensionPort<'_>,
        pricing_now: u64,
        loop_state: &mut AgentLoopGuard,
    ) -> Result<Self, KernelError> {
        let driver = ProviderTurnDriver::begin(
            start,
            journal,
            environment,
            resident,
            extension,
            pricing_now,
            loop_state,
        )
        .await?;
        let hook_reads = driver.hooks_gate_reads();
        Ok(Self {
            driver: Some(driver),
            completed: None,
            obligation: Some(obligation),
            hook_reads,
            failed: false,
        })
    }
    pub(super) fn refused(&self) -> bool {
        self.driver
            .as_ref()
            .is_some_and(ProviderTurnDriver::refused)
    }
    pub(super) fn hooks_gate_reads(&self) -> bool {
        self.hook_reads
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn pump(
        &mut self,
        journal: ProviderTurnJournal<'_>,
        environment: ProviderTurnEnvironment<'_>,
        resident: ProviderTurnResident<'_>,
        extension: ProviderExtensionPort<'_>,
        evidence: ProviderExecutionEvidence<'_>,
        memory: MemoryRequestExposure<'_>,
        hedge: Option<(HedgedProviderDispatch, Instant)>,
    ) -> Result<CodingProviderProgress, KernelError> {
        if self.failed || self.completed.is_some() {
            return Err(boundary());
        }
        // A cancelled/refused future cannot resume this physical phase with another permit.
        self.failed = true;
        let progress = self
            .driver
            .as_mut()
            .ok_or_else(boundary)?
            .pump(
                journal,
                environment,
                resident,
                extension,
                evidence,
                memory,
                hedge,
            )
            .await?;
        match progress {
            ProviderPumpProgress::AwaitHedge => {
                self.failed = false;
                Ok(CodingProviderProgress::Hedge)
            }
            ProviderPumpProgress::Completed(result) => {
                self.completed = Some(self.driver.take().ok_or_else(boundary)?.finish(*result)?);
                self.failed = false;
                Ok(CodingProviderProgress::Complete)
            }
        }
    }
    pub(super) fn hedge_spec(&mut self) -> Result<ProviderHedgeSpec<'_>, KernelError> {
        if self.failed || self.completed.is_some() {
            return Err(boundary());
        }
        self.driver
            .as_mut()
            .ok_or_else(boundary)?
            .hedge_spec()
            .ok_or_else(boundary)
    }
    pub(super) fn take_quota(&mut self) -> Option<RateLimitSnapshot> {
        self.completed
            .as_mut()
            .and_then(|completed| completed.round.take_quota())
    }
    pub(super) fn complete(
        mut self,
    ) -> Result<(CompletedProviderTurn, ProviderAttemptGuard), KernelError> {
        if self.failed {
            return Err(boundary());
        }
        Ok((
            self.completed.take().ok_or_else(boundary)?,
            self.obligation.take().ok_or_else(boundary)?,
        ))
    }
}
fn boundary() -> KernelError {
    KernelError::EffectBoundary("coding provider phase has no retained physical handoff".into())
}
