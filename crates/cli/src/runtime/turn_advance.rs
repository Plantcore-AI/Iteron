//! A turn advances only after actual private-content cleanup and terminal policy publication.
//! The prepared transition carries no Agent, callback or frontend state.
use super::KernelError;
use super::failed_action_cache::FailedActionCache;
use super::policy_evidence_recorder::PolicyEvidenceRecorder;
use super::terminal_record::TerminalRecordOwner;
use super::tool_output_spill::{ToolOutputSpillCleanup, ToolOutputSpillStore};
use crate::mcp::McpRuntimeControl;
use iteron_kernel::diagnostics::{DiagnosticEmitter, KernelDiagnostic};
use iteron_obs::Ledger;
use iteron_protocol::{PolicyTerminalOutcome, TurnId};
use iteron_record::Rollout;

pub(super) struct TurnAdvanceCleanup<'a> {
    pub(super) turn: TurnId,
    pub(super) tool: Option<&'a ToolOutputSpillStore>,
    pub(super) mcp: Option<&'a McpRuntimeControl>,
}

pub(super) struct PreparedTurnAdvance {
    turn: TurnId,
}

pub(super) struct TurnAdvanceJournal<'a> {
    pub(super) rollout: &'a mut Rollout,
    pub(super) ledger: &'a mut Ledger,
    pub(super) terminal: &'a mut TerminalRecordOwner,
    pub(super) policy: Option<&'a mut PolicyEvidenceRecorder>,
    pub(super) record_failed: &'a mut bool,
    pub(super) diagnostics: &'a DiagnosticEmitter,
    pub(super) sequence: &'a mut u32,
    pub(super) failed_actions: &'a mut FailedActionCache,
}

impl TurnAdvanceCleanup<'_> {
    pub(super) async fn prepare(self) -> Result<PreparedTurnAdvance, KernelError> {
        // Run both physical cleanup boundaries even if the first refuses. Preserve the original
        // error precedence without losing the MCP cleanup observation.
        let tool = self
            .tool
            .map_or(Ok(()), |store| {
                store.cleanup(ToolOutputSpillCleanup::TurnEnd)
            })
            .map_err(|_| KernelError::ToolOutputSpill("lifecycle cleanup failed"));
        let mcp = match self.mcp {
            Some(runtime) => runtime
                .cleanup_spills(iteron_mcp::McpSpillCleanup::TurnEnd)
                .await
                .map_err(|_| KernelError::McpLifecycle("private spill cleanup failed")),
            None => Ok(()),
        };
        tool?;
        mcp?;
        Ok(PreparedTurnAdvance { turn: self.turn })
    }
}

impl PreparedTurnAdvance {
    pub(super) fn commit(self, ports: TurnAdvanceJournal<'_>) -> Result<(), KernelError> {
        if TurnId(*ports.sequence) != self.turn {
            return Err(KernelError::ContextResolution(
                "prepared turn advance belongs to another turn".into(),
            ));
        }
        if let Some(policy) = ports.policy {
            let verifier = ports.terminal.verifier();
            ports
                .terminal
                .append_policy_outcome(
                    policy,
                    ports.rollout,
                    ports.ledger,
                    self.turn,
                    PolicyTerminalOutcome::Succeeded,
                    verifier,
                    None,
                )
                .map_err(|error| match error.into_record_error() {
                    Ok(error) => {
                        *ports.record_failed = true;
                        ports
                            .diagnostics
                            .emit(KernelDiagnostic::RecordAppendFailed {});
                        KernelError::Record(error)
                    }
                    Err(error) => KernelError::PolicyEvidence(error.to_string()),
                })?;
        }
        ports.terminal.reset_verifier();
        let next = ports
            .sequence
            .checked_add(1)
            .ok_or(KernelError::IdentityExhausted("turn"))?;
        let _ = ports.rollout.refresh_session_cache_async();
        ports.failed_actions.finish_turn();
        *ports.sequence = next;
        Ok(())
    }
}
