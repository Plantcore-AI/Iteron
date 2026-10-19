//! Concrete physical-provider pump through the same invocation writer and resident route slots.
//! A hedge is a typed suspension: its independent executor enters only after these borrows end.
use super::KernelError;
use super::artifact_publication::ToolOutputPublicationFactory;
use super::coding_execution_journal::CodingExecutionJournal;
use super::coding_provider_execution::{CodingProviderExecution, CodingProviderProgress};
use super::coding_run_driver::CodingRunDriver;
use super::memory_request_exposure::MemoryRequestExposure;
use super::permission_policy::OperationPolicy;
use super::pricing::ProviderAttemptGuard;
use super::provider_execution_scope::ProviderExecutionEvidence;
use super::provider_extension::ProviderExtensionPort;
use super::provider_hedge::HedgedProviderDispatch;
use super::provider_turn_driver::{
    ProviderTurnEnvironment, ProviderTurnResident, ProviderTurnStart,
};
use super::tool_output_spill::ToolOutputSpillStore;
use iteron_tools::Registry;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

pub(super) struct CodingProviderEvidence<'a> {
    pub(super) workspace: &'a Path,
    pub(super) registry: &'a Registry,
    pub(super) operation: OperationPolicy<'a>,
    pub(super) requested_control: bool,
    pub(super) publication: Arc<dyn ToolOutputPublicationFactory>,
    pub(super) spill: Option<Arc<ToolOutputSpillStore>>,
}
pub(super) struct CodingProviderSession<'a> {
    pub(super) journal: CodingExecutionJournal<'a>,
    pub(super) environment: ProviderTurnEnvironment<'a>,
    pub(super) resident: ProviderTurnResident<'a>,
    pub(super) extension: ProviderExtensionPort<'a>,
    pub(super) evidence: CodingProviderEvidence<'a>,
    pub(super) memory: MemoryRequestExposure<'a>,
}
impl CodingProviderSession<'_> {
    pub(super) async fn begin(
        mut self,
        driver: &mut CodingRunDriver,
        start: ProviderTurnStart,
        obligation: ProviderAttemptGuard,
        pricing_now: u64,
    ) -> Result<(), KernelError> {
        let (loop_state, _) = driver.provider_start()?;
        let (journal, _) = self.journal.provider_and_failed();
        let execution = CodingProviderExecution::begin(
            start,
            obligation,
            journal,
            self.environment,
            &self.resident,
            self.extension,
            pricing_now,
            loop_state,
        )
        .await?;
        if execution.refused() {
            self.memory.refused();
        }
        if execution.hooks_gate_reads() {
            self.journal.effects.note_workspace_mutation();
        }
        driver.install_provider(execution)
    }
    pub(super) async fn pump(
        mut self,
        driver: &mut CodingRunDriver,
        hedge: Option<(HedgedProviderDispatch, Instant)>,
    ) -> Result<CodingProviderProgress, KernelError> {
        let (execution, submitted) = driver.provider_execution()?;
        let (journal, failed_actions) = self.journal.provider_and_failed();
        let evidence = ProviderExecutionEvidence {
            workspace: self.evidence.workspace,
            registry: self.evidence.registry,
            operation: self.evidence.operation,
            failed_actions,
            recovered: submitted,
            requested_control: self.evidence.requested_control,
            publication: self.evidence.publication,
            spill: self.evidence.spill,
        };
        execution
            .pump(
                journal,
                self.environment,
                self.resident,
                self.extension,
                evidence,
                self.memory,
                hedge,
            )
            .await
    }
}
