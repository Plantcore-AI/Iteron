//! Small runtime adapters for pure strategy slots.
//!
//! The strategies see only already-gathered observations. World access stays in `ContextPort`,
//! while authority stays in the kernel gate and Registry.

use core_ctx::{ContextPort, ContextPortInput, ContextSlotObservation, ContextStrategy};
use core_protocol::capability_set::CapabilitySet;
use core_protocol::context::RequestId;
use core_protocol::slot::StrategySlot;
use core_protocol::{Capability, ToolUse, Trust, TurnId, context::ContextSource};
use core_tools::{Registry, ToolPolicyError, ToolPolicyProposal};
use std::path::Path;

pub(crate) struct LiveContext {
    pub text: String,
    pub governing_trust: Trust,
    pub policy_observation: ContextSlotObservation,
    pub policy_plan: core_ctx::ContextPlan,
    /// Exact bounded source projection used to assemble `text`. The runtime consumes this only for
    /// content-free decision evidence; durable provider bytes remain the authoritative record.
    pub segments: Vec<core_protocol::context::ContextSegment>,
    pub memory_audit: Option<core_ctx::MemoryRecallAudit>,
    pub materialization_audit: core_ctx::ContextMaterializationAudit,
    pub benchmark_memory_rejections: u32,
}

pub(crate) struct LiveContextRequest<'a> {
    pub workspace: &'a Path,
    pub home_dir: Option<&'a Path>,
    pub dependency_skill_dirs: &'a [(std::path::PathBuf, std::path::PathBuf)],
    pub turn: TurnId,
    pub task: &'a str,
    pub memory_benchmark_scope: Option<[u8; 32]>,
    pub materialization: core_ctx::ContextMaterializationPolicy,
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
    observation.max_bytes = request.materialization.max_bytes;
    let plan = ContextStrategy::select_with(
        strategy,
        &observation,
        CapabilitySet::only(Capability::ReadOnly),
    )
    .map_err(str::to_owned)?;
    let (mut grant, memory_audit, materialization_audit) = port
        .resolve_with_decision_audit(
            &plan,
            &ContextPortInput {
                workspace: request.workspace.to_path_buf(),
                home_dir: request.home_dir.map(Path::to_path_buf),
                active_dir: request.workspace.to_path_buf(),
                environment: None,
                transcript: Vec::new(),
                dependency_skill_dirs: request.dependency_skill_dirs.to_vec(),
                memory_benchmark_scope: request.memory_benchmark_scope,
                materialization: request.materialization,
            },
            memory_strategy,
        )
        .map_err(|error| error.to_string())?;
    let mut benchmark_memory_rejections = 0u32;
    if request.memory_benchmark_scope.is_some() {
        grant.segments.retain(|segment| {
            let keep = segment.source != ContextSource::Memory;
            if !keep {
                benchmark_memory_rejections = benchmark_memory_rejections.saturating_add(1);
            }
            keep
        });
        grant.bytes = grant.segments.iter().fold(0u32, |total, segment| {
            total.saturating_add(u32::try_from(segment.text.len()).unwrap_or(u32::MAX))
        });
    }
    let governing_trust = grant.governing_trust().unwrap_or(Trust::Trusted);
    let segments = grant.segments;
    let mut text = String::with_capacity(grant.bytes as usize);
    for segment in &segments {
        text.push_str(&segment.text);
    }
    Ok(LiveContext {
        text,
        governing_trust,
        policy_observation: observation,
        policy_plan: plan,
        segments,
        memory_audit,
        materialization_audit,
        benchmark_memory_rejections,
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

#[cfg(test)]
mod tests {
    use super::*;
    use core_protocol::context::{ContextSegment, ContextSource};

    #[test]
    fn benchmark_scope_strips_memory_even_from_a_replacement_context_port() {
        let workspace = std::env::temp_dir().join(format!(
            "core-benchmark-context-isolation-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&workspace).unwrap();
        let port = core_ctx::PortStub::new(vec![
            ContextSegment {
                text: "parent memory".into(),
                trust: Trust::Trusted,
                source: ContextSource::Memory,
            },
            ContextSegment {
                text: "workspace outline".into(),
                trust: Trust::Workspace,
                source: ContextSource::RepoOutline,
            },
        ]);
        let resolved = resolve_live_context(
            &core_ctx::ContextStrategy::default(),
            &core_ctx::MemoryRecallStrategy::default(),
            &port,
            LiveContextRequest {
                workspace: &workspace,
                home_dir: None,
                dependency_skill_dirs: &[],
                turn: TurnId(1),
                task: "inspect",
                memory_benchmark_scope: Some([7; 32]),
                materialization: core_ctx::ContextMaterializationPolicy::default(),
            },
        )
        .unwrap();
        assert_eq!(resolved.text, "workspace outline");
        assert_eq!(resolved.benchmark_memory_rejections, 1);
        assert!(
            resolved
                .segments
                .iter()
                .all(|segment| segment.source != ContextSource::Memory)
        );
        let _ = std::fs::remove_dir_all(workspace);
    }
}
