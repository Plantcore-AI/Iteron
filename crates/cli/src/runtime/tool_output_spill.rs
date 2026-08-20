//! Session-owned private overflow retention for ordinary (non-MCP) tool results.
//!
//! The store is deliberately separate from `iteron_mcp`'s result store. MCP transports own their
//! serialization, cap, and cleanup semantics; this owner sees only ordinary registry results and
//! replaces an oversized result before it can cross the durable record or model-context boundary.

use iteron_protocol::ToolResult;

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
            || u64::try_from(spill_max_bytes).unwrap_or(u64::MAX)
                > iteron_tunables::param_integer(
                    "cli.runtime.tool_output_spill.schema_max_spill_bytes",
                    SCHEMA_MAX_SPILL_BYTES,
                )
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
        let cleanup = match iteron_tunables::param_enum(
            "cli.runtime.tool_output_spill.default_cleanup",
            "run_end",
        ) {
            "tool_end" => ToolOutputSpillCleanup::ToolEnd,
            "turn_end" => ToolOutputSpillCleanup::TurnEnd,
            "run_end" => ToolOutputSpillCleanup::RunEnd,
            value => {
                // An operator-supplied enum must not abort the process either.
                eprintln!(
                    "tool-output spill: unadmitted cleanup `{value}`; using the built-in run_end"
                );
                ToolOutputSpillCleanup::RunEnd
            }
        };
        // `schema_max_spill_bytes` is an operator-settable ceiling that `new` checks against, and
        // the built-in sizes sit above its tightest legal setting. They are brought under it here
        // rather than asserted to fit: the `.expect()` this replaces aborted the process (exit
        // 101) for `--set cli.runtime.tool_output_spill.schema_max_spill_bytes=0` and for
        // `--set ...default_tool_output_spill_max_bytes=0`.
        // The ceiling is declared in u64 because `new` compares against it in u64.
        let ceiling = usize::try_from(iteron_tunables::param_integer::<u64>(
            "cli.runtime.tool_output_spill.schema_max_spill_bytes",
            SCHEMA_MAX_SPILL_BYTES,
        ))
        .unwrap_or(usize::MAX);
        let spill_max = iteron_tunables::param_integer::<usize>(
            "cli.runtime.tool_output_spill.default_tool_output_spill_max_bytes",
            DEFAULT_TOOL_OUTPUT_SPILL_MAX_BYTES,
        )
        .min(ceiling);
        Self::new(
            iteron_tunables::param_integer::<usize>(
                "cli.runtime.tool_output_spill.default_tool_output_memory_threshold_bytes",
                DEFAULT_TOOL_OUTPUT_MEMORY_THRESHOLD_BYTES,
            )
            .min(spill_max),
            spill_max,
            cleanup,
        )
        .expect("the built-in spill policy is clamped into its own configured ceiling")
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
    execution: iteron_tools::ToolExecution,
) -> ManagedToolExecution {
    match execution {
        iteron_tools::ToolExecution::Definite(result) => {
            ManagedToolExecution::Definite(manage_result(store, result))
        }
        iteron_tools::ToolExecution::Unknown(result) => {
            ManagedToolExecution::Unknown(manage_result(store, result))
        }
    }
}

pub(super) fn into_execution_parts(
    execution: ManagedToolExecution,
) -> (iteron_tools::ToolExecution, Option<ToolOutputSpillLease>) {
    match execution {
        ManagedToolExecution::Definite(managed) => {
            let (result, lease, _) = managed.into_parts();
            (iteron_tools::ToolExecution::Definite(result), lease)
        }
        ManagedToolExecution::Unknown(managed) => {
            let (result, lease, _) = managed.into_parts();
            (iteron_tools::ToolExecution::Unknown(result), lease)
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
    #[cfg(test)]
    #[error("ordinary tool-output spill handle is unavailable in this session")]
    UnknownHandle,
}

#[cfg(test)]
#[path = "tool_output_spill/tests.rs"]
mod tests;
