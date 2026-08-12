//! The optimization module axis.
//!
//! `CoreStrategySlot` groups families by *who owns the policy*; there are nine of them and one of
//! them holds forty-four families. That is the right granularity for the policy-bundle authority
//! model and the wrong granularity for optimization: moving "context policy" as a unit is a
//! forty-four dimensional step, and nothing downstream can say which dimension mattered.
//!
//! This axis is the second classification over the same families, sized so that one optimizer run
//! can own exactly one module. It is deliberately *total* — every family and every exposed
//! parameter maps to exactly one module — because a module axis with an escape hatch cannot
//! support ablation.

use serde::{Deserialize, Serialize};

/// One addressable optimization module.
///
/// Ten are textual (the artifact is natural language) and eighteen are structured (the artifact is
/// a value). The split matters because the two admit completely different optimizer families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleId {
    // --- textual (10) ---
    PromptSystem,
    PromptToolDescription,
    PromptSubagent,
    PromptSkill,
    PromptCompaction,
    PromptVerification,
    PromptPlanner,
    PromptReduce,
    PromptMemoryWrite,
    PromptRecovery,
    // --- structured (18) ---
    ContextAssembly,
    ContextCompaction,
    MemoryRecall,
    ToolExposure,
    ToolArguments,
    ToolEditStrategy,
    ToolSearchStrategy,
    ProviderRouting,
    ProviderSampling,
    ProviderRetry,
    ProviderPromptCache,
    SchedulerParallelism,
    PlannerFanout,
    VerificationQuorum,
    BudgetAllocation,
    SessionStop,
    SessionCheckpoint,
    SessionFork,
}

/// Textual versus structured. An optimizer picks its method from this, not from the module name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleKind {
    /// The artifact is natural language: prompt-evolution methods apply.
    Textual,
    /// The artifact is a value: numeric and combinatorial search applies.
    Structured,
}

impl ModuleId {
    pub const ALL: [Self; 28] = [
        Self::PromptSystem,
        Self::PromptToolDescription,
        Self::PromptSubagent,
        Self::PromptSkill,
        Self::PromptCompaction,
        Self::PromptVerification,
        Self::PromptPlanner,
        Self::PromptReduce,
        Self::PromptMemoryWrite,
        Self::PromptRecovery,
        Self::ContextAssembly,
        Self::ContextCompaction,
        Self::MemoryRecall,
        Self::ToolExposure,
        Self::ToolArguments,
        Self::ToolEditStrategy,
        Self::ToolSearchStrategy,
        Self::ProviderRouting,
        Self::ProviderSampling,
        Self::ProviderRetry,
        Self::ProviderPromptCache,
        Self::SchedulerParallelism,
        Self::PlannerFanout,
        Self::VerificationQuorum,
        Self::BudgetAllocation,
        Self::SessionStop,
        Self::SessionCheckpoint,
        Self::SessionFork,
    ];

    /// Stable wire identity. Profiles and exports address a module by this string, so it is part
    /// of the published surface and may not be renamed without a schema revision.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PromptSystem => "prompt.system",
            Self::PromptToolDescription => "prompt.tool_description",
            Self::PromptSubagent => "prompt.subagent",
            Self::PromptSkill => "prompt.skill",
            Self::PromptCompaction => "prompt.compaction",
            Self::PromptVerification => "prompt.verification",
            Self::PromptPlanner => "prompt.planner",
            Self::PromptReduce => "prompt.reduce",
            Self::PromptMemoryWrite => "prompt.memory_write",
            Self::PromptRecovery => "prompt.recovery",
            Self::ContextAssembly => "context.assembly",
            Self::ContextCompaction => "context.compaction",
            Self::MemoryRecall => "memory.recall",
            Self::ToolExposure => "tool.exposure",
            Self::ToolArguments => "tool.arguments",
            Self::ToolEditStrategy => "tool.edit_strategy",
            Self::ToolSearchStrategy => "tool.search_strategy",
            Self::ProviderRouting => "provider.routing",
            Self::ProviderSampling => "provider.sampling",
            Self::ProviderRetry => "provider.retry",
            Self::ProviderPromptCache => "provider.prompt_cache",
            Self::SchedulerParallelism => "scheduler.parallelism",
            Self::PlannerFanout => "planner.fanout",
            Self::VerificationQuorum => "verification.quorum",
            Self::BudgetAllocation => "budget.allocation",
            Self::SessionStop => "session.stop",
            Self::SessionCheckpoint => "session.checkpoint",
            Self::SessionFork => "session.fork",
        }
    }

    pub const fn kind(self) -> ModuleKind {
        match self {
            Self::PromptSystem
            | Self::PromptToolDescription
            | Self::PromptSubagent
            | Self::PromptSkill
            | Self::PromptCompaction
            | Self::PromptVerification
            | Self::PromptPlanner
            | Self::PromptReduce
            | Self::PromptMemoryWrite
            | Self::PromptRecovery => ModuleKind::Textual,
            _ => ModuleKind::Structured,
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|id| id.as_str() == value)
    }
}

/// The module that owns a family, by ordinal.
///
/// Derived from the family's own metadata rather than a hand-kept table: the domain says what the
/// family is about and the strategy slots say who runs it, and those two together are exactly the
/// information a module assignment encodes. Deriving it means a new family cannot be added without
/// an assignment, which is the property that keeps the axis total.
pub fn family_module(ordinal: u16) -> ModuleId {
    let family = crate::families()
        .iter()
        .find(|family| family.ordinal == ordinal)
        .unwrap_or_else(|| panic!("no family with ordinal {ordinal}"));
    module_for(family)
}

pub(crate) fn module_for(family: &crate::Family) -> ModuleId {
    use crate::Domain;
    // Order matters: the first arm that matches wins, so the most specific identity checks come
    // before the domain fallback. Identities are matched on the stable family id.
    match family.id {
        // Context assembly versus compaction is the split an optimizer actually needs; the domain
        // alone cannot distinguish them.
        "compaction_trigger"
        | "compaction_cooldown_hysteresis"
        | "summary_profile"
        | "multi_stage_summary_topology"
        | "summary_consistency_coverage_check" => ModuleId::ContextCompaction,
        "memory_enable"
        | "memory_budgets"
        | "per_agent_memory_scope"
        | "hybrid_retrieval_fusion_weights"
        | "retrieval_recency_decay"
        | "context_novelty_dedup_threshold" => ModuleId::MemoryRecall,
        "prompt_cache" | "prompt_cache_ttl_breakpoint_strategy" => ModuleId::ProviderPromptCache,
        "retry_backoff_base"
        | "retry_backoff_cap"
        | "retry_max_attempts"
        | "schema_retry_jitter"
        | "mcp_reconnect_backoff"
        | "provider_health_circuit_breaker_state_policy"
        | "failover_eligible_error_taxonomy"
        | "model_fallback_chain"
        | "hedged_request_policy" => ModuleId::ProviderRetry,
        "effort" | "response_verbosity" | "per_agent_effort_thinking" => ModuleId::ProviderSampling,
        "max_turns"
        | "max_usd"
        | "max_tokens"
        | "max_wall_secs"
        | "direct_child_allocation"
        | "system_prefix_budget"
        | "conversation_history_budget"
        | "tool_result_history_budget"
        | "multimodal_token_budget"
        | "context_window_override_reserve"
        | "request_output_cap" => ModuleId::BudgetAllocation,
        "max_consecutive_tool_errors"
        | "early_stop_quorum_policy"
        | "deferred_discovery_threshold" => ModuleId::SessionStop,
        "workspace_checkpoint_cadence"
        | "selective_restore_scope"
        | "rollback_on_verification_failure" => ModuleId::SessionCheckpoint,
        "session_isolation_profile" | "per_session_spawn_cap" => ModuleId::SessionFork,
        "repo_map" | "grep_limits" | "glob_limits" | "list_dir_limits" => {
            ModuleId::ToolSearchStrategy
        }
        "apply_patch_strategy" | "edit_strategy" => ModuleId::ToolEditStrategy,
        "workflow_graph"
        | "workflow_aggregate"
        | "speculative_sibling_count"
        | "speculative_sibling_cancellation"
        | "task_retry_reassignment_policy" => ModuleId::PlannerFanout,
        "verification_quorum_consensus"
        | "incremental_versus_full_verification"
        | "test_selection_strategy"
        | "verifier_feedback_tails"
        | "flaky_test_detection_quarantine"
        | "verify_command" => ModuleId::VerificationQuorum,
        "agent_catalog"
        | "role_specific_model_map"
        | "per_agent_model"
        | "per_agent_tool_profile" => ModuleId::PlannerFanout,
        // Domain fallback. Every arm is spelled out rather than using a wildcard, so adding a
        // domain is a compile error here instead of a silent default — that is what keeps the
        // axis total.
        _ => match family.domain {
            Domain::Provider => ModuleId::ProviderRouting,
            Domain::Reasoning => ModuleId::ProviderSampling,
            Domain::Budget => ModuleId::BudgetAllocation,
            Domain::Context => ModuleId::ContextAssembly,
            Domain::Memory => ModuleId::MemoryRecall,
            Domain::Tooling => ModuleId::ToolExposure,
            Domain::Verification => ModuleId::VerificationQuorum,
            Domain::Orchestration => ModuleId::PlannerFanout,
            Domain::Runtime => ModuleId::SchedulerParallelism,
            Domain::Extensibility => ModuleId::ToolExposure,
            // Observability decides what is durably recorded, which is the checkpoint question.
            Domain::Observability => ModuleId::SessionCheckpoint,
            Domain::Interface => ModuleId::SessionStop,
            Domain::Evaluation => ModuleId::VerificationQuorum,
            Domain::Governance => ModuleId::SessionFork,
        },
    }
}
