//! Sole invocation-local owner of recovery receipts, error streak and bounded continuation state.

use super::KernelError;
use super::context_runtime::ContextBudgetRecoveryGuard;
use iteron_protocol::{ToolResult, ToolUse};
use std::collections::BTreeMap;
use std::io::Write;

const MAX_RECOVERED_RESULTS: usize = 4_096;
const MAX_RECOVERED_BYTES: usize = 16 * 1_024 * 1_024;

#[derive(Default)]
pub(super) struct SubmittedTurnState {
    consecutive_errors: u32,
    stream_recoveries: u32,
    recovered: BTreeMap<String, (ToolUse, ToolResult)>,
    retained_bytes: usize,
    immediate_candidate_recovery_used: bool,
    context_recovery: ContextBudgetRecoveryGuard,
}

impl SubmittedTurnState {
    pub fn error_streak(&self) -> u32 {
        self.consecutive_errors
    }
    pub fn settle_tool_round(&mut self, had_error: bool) -> u32 {
        self.consecutive_errors = if had_error {
            self.consecutive_errors.saturating_add(1)
        } else {
            0
        };
        self.consecutive_errors
    }
    pub fn stream_recoveries(&self) -> u32 {
        self.stream_recoveries
    }
    pub fn note_stream_recovery(&mut self) -> u32 {
        self.stream_recoveries = self.stream_recoveries.saturating_add(1);
        self.stream_recoveries
    }
    pub fn candidate_recovery_used(&self) -> bool {
        self.immediate_candidate_recovery_used
    }
    pub fn claim_candidate_recovery(&mut self) -> bool {
        if self.immediate_candidate_recovery_used {
            false
        } else {
            self.immediate_candidate_recovery_used = true;
            true
        }
    }
    pub fn claim_context_recovery(
        &mut self,
        violation: &iteron_ctx::ContextBudgetViolation,
    ) -> bool {
        self.context_recovery.claim(violation)
    }
    pub fn settle_context_recovery(&mut self, recovered: bool) {
        self.context_recovery.settle(recovered);
    }
    pub fn recovered_tool(&self, id: &str) -> Option<&(ToolUse, ToolResult)> {
        self.recovered.get(id)
    }
    pub fn retain_recovered_tool(
        &mut self,
        call: &ToolUse,
        result: &ToolResult,
    ) -> Result<(), KernelError> {
        let refused = || {
            KernelError::ContextResolution(
                "interrupted stream receipt capacity or identity refused".into(),
            )
        };
        if call.id.is_empty() || result.tool_use_id != call.id {
            return Err(refused());
        }
        if let Some((existing, _)) = self.recovered.get(&call.id) {
            if existing.name != call.name || existing.input != call.input {
                return Err(refused());
            }
            return Ok(()); // The first observed physical receipt is immutable through projections.
        }
        if self.recovered.len() >= MAX_RECOVERED_RESULTS {
            return Err(refused());
        }
        let mut bounded = CountingWriter {
            bytes: 0,
            limit: MAX_RECOVERED_BYTES.saturating_sub(self.retained_bytes),
        };
        serde_json::to_writer(&mut bounded, &(call, result)).map_err(|_| refused())?;
        self.retained_bytes += bounded.bytes;
        self.recovered
            .insert(call.id.clone(), (call.clone(), result.clone()));
        Ok(())
    }
}

struct CountingWriter {
    bytes: usize,
    limit: usize,
}
impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let next = self
            .bytes
            .checked_add(bytes.len())
            .filter(|next| *next <= self.limit)
            .ok_or_else(|| std::io::Error::other("bounded receipt envelope"))?;
        self.bytes = next;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_RECOVERED_BYTES, SubmittedTurnState};
    use iteron_protocol::{ToolResult, ToolUse, Trust};

    fn call() -> ToolUse {
        ToolUse {
            id: "actual-call".into(),
            name: "read_file".into(),
            input: serde_json::json!({"path":"x"}),
        }
    }
    fn result(content: String) -> ToolResult {
        ToolResult {
            tool_use_id: "actual-call".into(),
            content,
            is_error: false,
            trust: Trust::Workspace,
            latency_ms: 1,
        }
    }

    #[test]
    fn receipt_identity_and_encoded_capacity_refuse_before_state_changes() {
        let mut owner = SubmittedTurnState::default();
        let call = call();
        let large = result("x".repeat(MAX_RECOVERED_BYTES));
        assert!(owner.retain_recovered_tool(&call, &large).is_err());
        assert!(owner.recovered_tool(&call.id).is_none());
        let actual = result("first actual terminal".into());
        owner.retain_recovered_tool(&call, &actual).unwrap();
        owner
            .retain_recovered_tool(&call, &result("later projection".into()))
            .unwrap();
        assert_eq!(
            owner.recovered_tool(&call.id).unwrap().1.content,
            actual.content
        );
        let mut changed = call.clone();
        changed.input = serde_json::json!({"path":"other"});
        assert!(owner.retain_recovered_tool(&changed, &actual).is_err());
        assert_eq!(owner.recovered_tool(&call.id).unwrap().0.input, call.input);
    }

    #[test]
    fn errors_count_logical_rounds_and_candidate_continuation_is_one_shot() {
        let mut owner = SubmittedTurnState::default();
        assert_eq!(owner.settle_tool_round(true), 1);
        assert_eq!(owner.settle_tool_round(true), 2);
        assert_eq!(owner.settle_tool_round(false), 0);
        assert!(!owner.candidate_recovery_used());
        assert!(owner.claim_candidate_recovery());
        assert!(!owner.claim_candidate_recovery());
        assert_eq!(owner.note_stream_recovery(), 1);
        assert_eq!(owner.stream_recoveries(), 1);
    }
}
