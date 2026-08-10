//! Small runtime adapters for pure strategy slots.
//!
//! The strategies see only already-gathered observations. World access stays in `ContextPort`,
//! while authority stays in the kernel gate and Registry.

use core_ctx::{ContextPort, ContextPortInput, ContextSlotObservation, ContextStrategy};
use core_protocol::capability_set::CapabilitySet;
use core_protocol::context::RequestId;
use core_protocol::slot::StrategySlot;
use core_protocol::{Capability, ToolUse, Trust, TurnId};
use core_tools::{Registry, ToolPolicyError, ToolPolicyProposal};
use std::path::Path;

pub(crate) struct LiveContext {
    pub text: String,
    pub governing_trust: Trust,
    /// Exact bounded source projection used to assemble `text`. The runtime consumes this only for
    /// content-free decision evidence; durable provider bytes remain the authoritative record.
    pub segments: Vec<core_protocol::context::ContextSegment>,
    pub memory_audit: Option<core_ctx::MemoryRecallAudit>,
}

pub(crate) struct LiveContextRequest<'a> {
    pub workspace: &'a Path,
    pub home_dir: Option<&'a Path>,
    pub dependency_skill_dirs: &'a [(std::path::PathBuf, std::path::PathBuf)],
    pub turn: TurnId,
    pub task: &'a str,
}

pub(crate) fn resolve_live_context(
    strategy: &dyn StrategySlot,
    memory_strategy: &dyn StrategySlot,
    port: &dyn ContextPort,
    request: LiveContextRequest<'_>,
) -> Result<LiveContext, String> {
    let mut observation =
        ContextSlotObservation::baseline(RequestId(u64::from(request.turn.0)), request.task);
    observation.include_outline = false;
    observation.instruction_scopes.clear();
    observation.include_environment = false;
    observation.transcript_turns = 0;
    let plan = ContextStrategy::select_with(
        strategy,
        &observation,
        CapabilitySet::only(Capability::ReadOnly),
    )
    .map_err(str::to_owned)?;
    let (grant, memory_audit) = port
        .resolve_with_memory_audit(
            &plan,
            &ContextPortInput {
                workspace: request.workspace.to_path_buf(),
                home_dir: request.home_dir.map(Path::to_path_buf),
                active_dir: request.workspace.to_path_buf(),
                environment: None,
                transcript: Vec::new(),
                dependency_skill_dirs: request.dependency_skill_dirs.to_vec(),
            },
            memory_strategy,
        )
        .map_err(|error| error.to_string())?;
    let governing_trust = grant.governing_trust().unwrap_or(Trust::Trusted);
    let segments = grant.segments;
    let mut text = String::with_capacity(grant.bytes as usize);
    for segment in &segments {
        text.push_str(&segment.text);
    }
    Ok(LiveContext {
        text,
        governing_trust,
        segments,
        memory_audit,
    })
}

pub(crate) fn propose_tool(
    registry: &Registry,
    policy: &dyn StrategySlot,
    call: ToolUse,
    argument_trust: Trust,
) -> Result<ToolPolicyProposal, ToolPolicyError> {
    registry.propose_intent(policy, call, argument_trust, all_tool_capabilities())
}

fn all_tool_capabilities() -> CapabilitySet {
    CapabilitySet::from_iter_capabilities([
        Capability::ReadOnly,
        Capability::ReversibleLocal,
        Capability::CodeExecuting,
        Capability::TrustMutating,
        Capability::IrreversibleExternal,
    ])
}
