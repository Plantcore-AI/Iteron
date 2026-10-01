//! Trusted composition of real turn-end content, policy and sequence owners.
use super::Agent;
use super::KernelError;
use super::turn_advance::{TurnAdvanceCleanup, TurnAdvanceJournal};
use iteron_protocol::TurnId;

impl Agent {
    pub(super) async fn advance_turn(&mut self) -> Result<(), KernelError> {
        let advance = TurnAdvanceCleanup {
            turn: TurnId(self.seq_turn),
            tool: self.tool_output_spill.as_deref(),
            mcp: self.mcp_runtime.as_ref(),
        }
        .prepare()
        .await?;
        // Lazy policy restoration follows physical cleanup as in the original turn transition.
        self.ensure_policy_evidence()?;
        advance.commit(TurnAdvanceJournal {
            rollout: &mut self.rollout,
            ledger: &mut self.ledger,
            terminal: &mut self.terminal_record,
            policy: self.policy_evidence.as_mut(),
            record_failed: &mut self.record_failed,
            diagnostics: &self.diagnostics,
            sequence: &mut self.seq_turn,
            failed_actions: &mut self.failed_actions,
        })
    }
}
