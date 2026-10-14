//! A small private observation from the native guarded commit's sealed before/after receipt.
//! No file path or captured buffer outlives execution here; a successful matching ToolDone still
//! has to join it before the single effect owner can report a change.
use super::tool_execution_journal::ToolTerminalReceipt;
use iteron_tools::{CapturedToolExecution, ToolExecution};

pub(super) struct NativeChangeObservation {
    tool_use_id: String,
    tool: String,
    changed_file_commits: u64,
}
impl NativeChangeObservation {
    pub(super) fn capture(captured: &CapturedToolExecution) -> Option<Self> {
        let ToolExecution::Definite(result) = &captured.execution else {
            return None;
        };
        let receipt = captured.native_mutation.as_ref()?;
        if result.is_error || result.tool_use_id != receipt.tool_use_id() {
            return None;
        }
        // The sealed receipt has the native owner's finite member/byte bounds. A replacement
        // with identical bytes is not a positive change; an actual new empty file is a change.
        let changed = receipt
            .files()
            .iter()
            .filter(|file| file.before().is_none_or(|before| before != file.after()))
            .count();
        let changed_file_commits = u64::try_from(changed).ok().filter(|count| *count > 0)?;
        Some(Self {
            tool_use_id: receipt.tool_use_id().to_owned(),
            tool: receipt.logical_tool_name().to_owned(),
            changed_file_commits,
        })
    }
    pub(super) fn confirmed_by(&self, terminal: &ToolTerminalReceipt) -> Option<u64> {
        (terminal.successful()
            && terminal.tool_use_id() == self.tool_use_id
            && terminal.tool() == self.tool)
            .then_some(self.changed_file_commits)
    }
}

#[cfg(test)]
#[path = "native_change_evidence_tests.rs"]
mod tests;
