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
}

pub(crate) fn resolve_live_context(
    strategy: &dyn StrategySlot,
    port: &dyn ContextPort,
    workspace: &Path,
    home_dir: Option<&Path>,
    turn: TurnId,
    task: &str,
) -> Result<LiveContext, String> {
    let mut observation = ContextSlotObservation::baseline(RequestId(u64::from(turn.0)), task);
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
    let grant = port
        .resolve(
            &plan,
            &ContextPortInput {
                workspace: workspace.to_path_buf(),
                home_dir: home_dir.map(Path::to_path_buf),
                active_dir: workspace.to_path_buf(),
                environment: None,
                transcript: Vec::new(),
            },
        )
        .map_err(|error| error.to_string())?;
    let governing_trust = grant.governing_trust().unwrap_or(Trust::Trusted);
    let mut text = String::with_capacity(grant.bytes as usize);
    for segment in grant.segments {
        text.push_str(&segment.text);
    }
    Ok(LiveContext {
        text,
        governing_trust,
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
