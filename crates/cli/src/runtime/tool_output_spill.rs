//! Session-owned private overflow retention for ordinary (non-MCP) tool results.
//!
//! The store is deliberately separate from `core_mcp`'s result store. MCP transports own their
//! serialization, cap, and cleanup semantics; this owner sees only ordinary registry results and
//! replaces an oversized result before it can cross the durable record or model-context boundary.

use core_protocol::ToolResult;

mod store;

pub(crate) use store::{ToolOutputSpillLease, ToolOutputSpillStore};

pub(crate) const DEFAULT_TOOL_OUTPUT_MEMORY_THRESHOLD_BYTES: usize = 64 * 1024;
pub(crate) const DEFAULT_TOOL_OUTPUT_SPILL_MAX_BYTES: usize = 16 * 1024 * 1024;
const SCHEMA_MAX_SPILL_BYTES: u64 = 17_179_869_184;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "the shared suffix is the point: each variant names the boundary the spill is cleaned at"
)]
pub(crate) enum ToolOutputSpillCleanup {
    ToolEnd,
    TurnEnd,
    RunEnd,
}

impl ToolOutputSpillCleanup {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::ToolEnd => "tool_end",
            Self::TurnEnd => "turn_end",
            Self::RunEnd => "run_end",
        }
    }

    const fn reached_by(self, boundary: Self) -> bool {
        cleanup_rank(boundary) >= cleanup_rank(self)
    }
}

const fn cleanup_rank(cleanup: ToolOutputSpillCleanup) -> u8 {
    match cleanup {
        ToolOutputSpillCleanup::ToolEnd => 0,
        ToolOutputSpillCleanup::TurnEnd => 1,
        ToolOutputSpillCleanup::RunEnd => 2,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ToolOutputSpillPolicy {
    memory_threshold_bytes: usize,
    spill_max_bytes: usize,
    cleanup: ToolOutputSpillCleanup,
}

impl ToolOutputSpillPolicy {
    pub(crate) fn new(
        memory_threshold_bytes: usize,
        spill_max_bytes: usize,
        cleanup: ToolOutputSpillCleanup,
    ) -> Result<Self, ToolOutputSpillError> {
        if memory_threshold_bytes > spill_max_bytes
            || u64::try_from(spill_max_bytes).unwrap_or(u64::MAX) > SCHEMA_MAX_SPILL_BYTES
        {
            return Err(ToolOutputSpillError::InvalidPolicy);
        }
        Ok(Self {
            memory_threshold_bytes,
            spill_max_bytes,
            cleanup,
        })
    }

    pub(crate) const fn memory_threshold_bytes(self) -> usize {
        self.memory_threshold_bytes
    }

    pub(crate) const fn spill_max_bytes(self) -> usize {
        self.spill_max_bytes
    }

    pub(crate) const fn cleanup(self) -> ToolOutputSpillCleanup {
        self.cleanup
    }
}

impl Default for ToolOutputSpillPolicy {
    fn default() -> Self {
        Self::new(
            DEFAULT_TOOL_OUTPUT_MEMORY_THRESHOLD_BYTES,
            DEFAULT_TOOL_OUTPUT_SPILL_MAX_BYTES,
            ToolOutputSpillCleanup::RunEnd,
        )
        .expect("the built-in ordinary tool-output spill policy is valid")
    }
}

#[derive(Debug)]
pub(crate) struct ManagedToolResult {
    pub(crate) result: ToolResult,
    lease: Option<ToolOutputSpillLease>,
    pub(crate) spilled: bool,
}

pub(crate) enum ManagedToolExecution {
    Definite(ManagedToolResult),
    Unknown(ManagedToolResult),
}

impl ManagedToolResult {
    pub(crate) fn unspilled(result: ToolResult) -> Self {
        Self {
            result,
            lease: None,
            spilled: false,
        }
    }

    pub(crate) fn into_parts(self) -> (ToolResult, Option<ToolOutputSpillLease>, bool) {
        (self.result, self.lease, self.spilled)
    }
}

pub(super) fn manage_result(
    store: Option<&ToolOutputSpillStore>,
    result: ToolResult,
) -> ManagedToolResult {
    match store {
        Some(store) => store.apply(result),
        None => ManagedToolResult::unspilled(result),
    }
}

pub(super) fn manage_execution(
    store: Option<&ToolOutputSpillStore>,
    execution: core_tools::ToolExecution,
) -> ManagedToolExecution {
    match execution {
        core_tools::ToolExecution::Definite(result) => {
            ManagedToolExecution::Definite(manage_result(store, result))
        }
        core_tools::ToolExecution::Unknown(result) => {
            ManagedToolExecution::Unknown(manage_result(store, result))
        }
    }
}

pub(super) fn into_execution_parts(
    execution: ManagedToolExecution,
) -> (core_tools::ToolExecution, Option<ToolOutputSpillLease>) {
    match execution {
        ManagedToolExecution::Definite(managed) => {
            let (result, lease, _) = managed.into_parts();
            (core_tools::ToolExecution::Definite(result), lease)
        }
        ManagedToolExecution::Unknown(managed) => {
            let (result, lease, _) = managed.into_parts();
            (core_tools::ToolExecution::Unknown(result), lease)
        }
    }
}

pub(super) fn cleanup_managed_result(
    store: Option<&ToolOutputSpillStore>,
    managed: &mut ManagedToolResult,
) -> Result<(), super::KernelError> {
    store
        .map_or(Ok(()), |store| store.cleanup_tool(&mut managed.lease))
        .map_err(|_| super::KernelError::ToolOutputSpill("tool-end cleanup failed"))
}

pub(super) fn cleanup_lease(
    store: Option<&ToolOutputSpillStore>,
    lease: &mut Option<ToolOutputSpillLease>,
) -> Result<(), super::KernelError> {
    store
        .map_or(Ok(()), |store| store.cleanup_tool(lease))
        .map_err(|_| super::KernelError::ToolOutputSpill("tool-end cleanup failed"))
}

impl super::Agent {
    pub(super) fn ordinary_tool_spill_store(
        &self,
        tool_name: &str,
    ) -> Option<std::sync::Arc<ToolOutputSpillStore>> {
        if self.registry.is_mcp_effect(tool_name) {
            None
        } else {
            self.tool_output_spill.clone()
        }
    }

    pub(super) fn cleanup_tool_output_spills(
        &self,
        boundary: ToolOutputSpillCleanup,
    ) -> Result<(), super::KernelError> {
        self.tool_output_spill
            .as_ref()
            .map_or(Ok(()), |store| store.cleanup(boundary))
            .map_err(|_| super::KernelError::ToolOutputSpill("lifecycle cleanup failed"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ToolOutputSpillError {
    #[error("invalid ordinary tool-output spill policy")]
    InvalidPolicy,
    #[error("private ordinary tool-output spill storage is unavailable")]
    StorageUnavailable,
    #[error("ordinary tool-output spill handle is unavailable in this session")]
    UnknownHandle,
}

#[cfg(test)]
#[path = "tool_output_spill/tests.rs"]
mod tests;
