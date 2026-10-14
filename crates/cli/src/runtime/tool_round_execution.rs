//! Executes the complete finite tool round through real collection, batch, declaration and
//! ordered-effect ports. Special kernel work is handed off only after its ordinary gates pass.
use super::KernelError;
use super::candidate_workspace::CandidateWorkspaceBaseline;
use super::kernel_special_execution::{KernelSpecialKind, classify};
use super::optional_tool_round::OptionalToolRound;
use super::ordered_tool_call::OrderedCallAdmission;
use super::provider_extension::ProviderExtensionPermit;
use super::tool_declaration_admission::ToolAdmissionDecision;
use super::tool_execution_session::ToolExecutionSession;
use super::tool_round_driver::ToolRoundDriver;
use iteron_protocol::{Capability, ToolResult, ToolUse, Trust};
use iteron_sched::Governor;

enum ExecutionPhase {
    Early,
    Ordered,
    AwaitingKernel,
    Completed,
    Failed,
}
struct PendingKernelCall {
    index: usize,
    call: ToolUse,
    // Ownership stays in this controller while the host prepares and executes the special call.
    // Its Drop releases only the actual dispatch lease, never claims a known effect terminal.
    _permit: Option<ProviderExtensionPermit>,
}
pub(super) struct PermittedKernelCall {
    pub(super) kind: KernelSpecialKind,
    pub(super) index: usize,
    pub(super) call: ToolUse,
    pub(super) capability: Capability,
}
pub(super) enum ToolRoundProgress {
    Kernel(PermittedKernelCall),
    Complete,
}
pub(super) struct ToolRoundExecution {
    round: ToolRoundDriver,
    phase: ExecutionPhase,
    pending: Option<PendingKernelCall>,
}
impl ToolRoundExecution {
    pub(super) fn new(round: ToolRoundDriver) -> Self {
        Self {
            round,
            phase: ExecutionPhase::Early,
            pending: None,
        }
    }
    /// A pump consumes concrete journal/permission/control borrowing. When special work is
    /// returned, those borrows end and the host may mint its actual current child/workflow scope.
    /// Pending declarations and a real optional external lease stay exclusively in this owner.
    pub(super) async fn pump(
        &mut self,
        mut session: ToolExecutionSession<'_>,
        optional: &OptionalToolRound,
        baseline: &mut CandidateWorkspaceBaseline,
    ) -> Result<ToolRoundProgress, KernelError> {
        if !matches!(self.phase, ExecutionPhase::Early | ExecutionPhase::Ordered) {
            return Err(boundary());
        }
        let first = matches!(self.phase, ExecutionPhase::Early);
        self.phase = ExecutionPhase::Failed;
        if first {
            let unknown = self.round.collect_early(session.early()).await?;
            if unknown != 0 {
                return Err(KernelError::UnknownEffects { count: unknown });
            }
            if optional.tracked() {
                baseline.capture_before(optional.paths()).await;
            }
            if self
                .round
                .select_batch(session.batch_policy(), optional.excluded())?
            {
                let governor = Governor::new(session.schedule.concurrency);
                self.round.execute_batch(session.batch(&governor)).await?;
            }
        }
        while let Some((index, call, proposal)) = self.round.next_declaration()? {
            if let Some(reason) = optional.refusal(index) {
                let result = session.refuse(
                    &call,
                    ToolResult {
                        tool_use_id: call.id.clone(),
                        content: reason.into(),
                        is_error: true,
                        trust: Trust::Workspace,
                        latency_ms: 0,
                    },
                )?;
                self.round.accept(index, result)?;
                continue;
            }
            let (proposal, capability, action_signature) =
                match session.admission().run(&call, proposal).await? {
                    ToolAdmissionDecision::Permitted {
                        proposal,
                        capability,
                        action_signature,
                    } => (proposal, capability, action_signature),
                    ToolAdmissionDecision::Refused(result) => {
                        self.round.accept(index, result)?;
                        continue;
                    }
                };
            let permit = match session.external_permit(&call).await {
                Ok(permit) => permit,
                Err(()) => {
                    let result = session.external_refusal(&call)?;
                    self.round.accept(index, result)?;
                    continue;
                }
            };
            if let Some(kind) = classify(&call, session.output.artifact_enabled) {
                self.pending = Some(PendingKernelCall {
                    index,
                    call: call.clone(),
                    _permit: permit,
                });
                self.phase = ExecutionPhase::AwaitingKernel;
                return Ok(ToolRoundProgress::Kernel(PermittedKernelCall {
                    kind,
                    index,
                    call,
                    capability,
                }));
            }
            let eligible = proposal.eligible;
            let completed = session
                .ordered(&call, permit.is_some())
                .execute(OrderedCallAdmission {
                    index,
                    intent: proposal.admit(eligible),
                    capability,
                    action_signature,
                })
                .await?;
            self.round
                .accept_ordered(index, completed.result, completed.image_projection)?;
            // Release the actual external permit only after physical settlement and post work.
            drop(permit);
        }
        self.round.validate_complete()?;
        self.phase = ExecutionPhase::Completed;
        Ok(ToolRoundProgress::Complete)
    }
    /// Only the current physically returned result may close this declaration. A delayed host
    /// result cannot advance another slot or release another call's retained external lease.
    pub(super) fn settle_kernel(
        &mut self,
        index: usize,
        result: ToolResult,
    ) -> Result<(), KernelError> {
        if !matches!(self.phase, ExecutionPhase::AwaitingKernel) {
            return Err(boundary());
        }
        let pending = self.pending.as_ref().ok_or_else(boundary)?;
        if pending.index != index || pending.call.id != result.tool_use_id {
            return Err(boundary());
        }
        self.round.accept(index, result)?;
        self.pending.take();
        self.phase = ExecutionPhase::Ordered;
        Ok(())
    }
    pub(super) fn has_images(&self) -> bool {
        self.round.has_images()
    }
    pub(super) fn into_round(self) -> Result<ToolRoundDriver, KernelError> {
        if !matches!(self.phase, ExecutionPhase::Completed) || self.pending.is_some() {
            return Err(boundary());
        }
        self.round.validate_complete()?;
        Ok(self.round)
    }
}
fn boundary() -> KernelError {
    KernelError::EffectBoundary(
        "tool execution cannot advance outside its actual retained phase".into(),
    )
}

#[cfg(all(test, unix))]
#[path = "tool_round_execution_tests.rs"]
mod tests;
