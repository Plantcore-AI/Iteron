use crate::{CapabilityRequirement, Domain, ProviderRequirement, RequirementSpec};

const INFERENCE: &[CapabilityRequirement] = &[CapabilityRequirement::Inference];
const PROVIDER_CATALOG: &[CapabilityRequirement] = &[CapabilityRequirement::ProviderCatalog];
const SERVICE_TIER: &[CapabilityRequirement] = &[CapabilityRequirement::ProviderServiceTier];
const PROMPT_CACHE: &[CapabilityRequirement] = &[CapabilityRequirement::ProviderPromptCache];
const REQUEST_COMPRESSION: &[CapabilityRequirement] =
    &[CapabilityRequirement::ProviderRequestCompression];
const PROVIDER_TRANSPORT: &[CapabilityRequirement] = &[CapabilityRequirement::ProviderTransport];
const PROVIDER_REASONING_CONTROL: &[CapabilityRequirement] =
    &[CapabilityRequirement::ProviderReasoningControl];
const PROVIDER_DISCOVERY: &[CapabilityRequirement] = &[CapabilityRequirement::ProviderDiscovery];
const PROVIDER_FAILOVER: &[CapabilityRequirement] = &[CapabilityRequirement::ProviderFailover];
const PROVIDER_HEDGING: &[CapabilityRequirement] = &[CapabilityRequirement::ProviderHedging];
const PROVIDER_RESPONSE_VERBOSITY: &[CapabilityRequirement] = &[
    CapabilityRequirement::ProviderResponseVerbosity,
    CapabilityRequirement::Reasoning,
];
const REASONING: &[CapabilityRequirement] = &[CapabilityRequirement::Reasoning];
const BUDGET: &[CapabilityRequirement] = &[CapabilityRequirement::BudgetAccounting];
const CONTEXT: &[CapabilityRequirement] = &[CapabilityRequirement::ContextRead];
const MEMORY: &[CapabilityRequirement] = &[CapabilityRequirement::MemoryReadWrite];
const TOOLING: &[CapabilityRequirement] = &[CapabilityRequirement::ToolExecution];
const PERSISTENT_PROCESS: &[CapabilityRequirement] = &[CapabilityRequirement::PersistentProcess];
const BACKGROUND_JOB: &[CapabilityRequirement] = &[CapabilityRequirement::BackgroundJob];
const INTERACTIVE_STDIN: &[CapabilityRequirement] = &[CapabilityRequirement::InteractiveStdin];
const PROCESS_SIGNAL: &[CapabilityRequirement] = &[CapabilityRequirement::ProcessSignal];
const FILESYSTEM_WRITE: &[CapabilityRequirement] = &[CapabilityRequirement::FileSystemWrite];
const LANGUAGE_SERVER: &[CapabilityRequirement] = &[CapabilityRequirement::LanguageServer];
const TOOL_CACHE: &[CapabilityRequirement] = &[CapabilityRequirement::ToolResultCache];
const VERIFICATION: &[CapabilityRequirement] = &[CapabilityRequirement::Verification];
const COLLABORATION: &[CapabilityRequirement] = &[CapabilityRequirement::AgentSpawn];
const MESSAGING: &[CapabilityRequirement] = &[CapabilityRequirement::AgentMessaging];
const WORKTREE: &[CapabilityRequirement] = &[CapabilityRequirement::WorktreeIsolation];
const RUNTIME: &[CapabilityRequirement] = &[CapabilityRequirement::RuntimeObservation];
const EXTENSIBILITY: &[CapabilityRequirement] = &[CapabilityRequirement::ExtensionDiscovery];
const MCP: &[CapabilityRequirement] = &[CapabilityRequirement::McpTransport];
const OAUTH: &[CapabilityRequirement] = &[CapabilityRequirement::OAuth];
const OBSERVABILITY: &[CapabilityRequirement] = &[CapabilityRequirement::EvidenceObservation];
const INTERFACE: &[CapabilityRequirement] = &[CapabilityRequirement::OperatorInteraction];
const EVALUATION: &[CapabilityRequirement] = &[CapabilityRequirement::Evaluation];
const GOVERNANCE: &[CapabilityRequirement] = &[CapabilityRequirement::AuthorityConfiguration];

const CATALOG_AGENT: &[CapabilityRequirement] = &[
    CapabilityRequirement::ProviderCatalog,
    CapabilityRequirement::AgentSpawn,
];
const MULTIMODAL_CONTEXT: &[CapabilityRequirement] = &[
    CapabilityRequirement::ProviderMultimodal,
    CapabilityRequirement::ContextRead,
];
const REASONING_CONTROL_AGENT: &[CapabilityRequirement] = &[
    CapabilityRequirement::ProviderReasoningControl,
    CapabilityRequirement::AgentSpawn,
];
const CONTEXT_VERIFY: &[CapabilityRequirement] = &[
    CapabilityRequirement::ContextRead,
    CapabilityRequirement::Verification,
];
const MEMORY_CONTEXT: &[CapabilityRequirement] = &[
    CapabilityRequirement::MemoryReadWrite,
    CapabilityRequirement::ContextRead,
];
const TOOL_CONTEXT: &[CapabilityRequirement] = &[
    CapabilityRequirement::ToolExecution,
    CapabilityRequirement::ContextRead,
];
const LSP_CONTEXT: &[CapabilityRequirement] = &[
    CapabilityRequirement::LanguageServer,
    CapabilityRequirement::ContextRead,
];
const VERIFY_CHECKPOINT: &[CapabilityRequirement] = &[
    CapabilityRequirement::Verification,
    CapabilityRequirement::WorkspaceCheckpoint,
];
const VERIFY_AGENT: &[CapabilityRequirement] = &[
    CapabilityRequirement::Verification,
    CapabilityRequirement::AgentSpawn,
];
const AGENT_CATALOG: &[CapabilityRequirement] = &[
    CapabilityRequirement::AgentSpawn,
    CapabilityRequirement::ProviderCatalog,
];
const AGENT_TOOL: &[CapabilityRequirement] = &[
    CapabilityRequirement::AgentSpawn,
    CapabilityRequirement::ToolExecution,
];
const AGENT_MEMORY: &[CapabilityRequirement] = &[
    CapabilityRequirement::AgentSpawn,
    CapabilityRequirement::MemoryReadWrite,
];
const MCP_CONTEXT: &[CapabilityRequirement] = &[
    CapabilityRequirement::McpTransport,
    CapabilityRequirement::ContextRead,
];
const RESOURCE_CONTEXT: &[CapabilityRequirement] = &[
    CapabilityRequirement::McpResource,
    CapabilityRequirement::ContextRead,
];
const RATE_LIMIT_INFERENCE: &[CapabilityRequirement] = &[
    CapabilityRequirement::RateLimitObservation,
    CapabilityRequirement::Inference,
];
const PROMPT_CACHE_CONTEXT: &[CapabilityRequirement] = &[
    CapabilityRequirement::ProviderPromptCache,
    CapabilityRequirement::ContextRead,
];
const REPLAY_MESSAGING: &[CapabilityRequirement] = &[
    CapabilityRequirement::ReplayEvidence,
    CapabilityRequirement::AgentMessaging,
];
/// Exact provider-scope requirement in canonical ordinal order. Provider dependence is audited
/// independently from the family's coarse domain and never inferred from ordinal ranges.
#[rustfmt::skip]
const PROVIDER_REQUIREMENTS: [ProviderRequirement; crate::EXPECTED_FAMILY_COUNT] = [
    ProviderRequirement::AnyAdmittedRoute, // 1 provider
    ProviderRequirement::SelectedRoute, // 2 model
    ProviderRequirement::AnyAdmittedRoute, // 3 base_url
    // Harness effort always controls local planning/orchestration. Whether the selected adapter can
    // also serialize a semantic reasoning control is a separate family-20/21 capability; an
    // incapable route must omit that wire control rather than deactivate the local policy.
    ProviderRequirement::None, // 4 effort
    ProviderRequirement::None, // 5 max_turns
    ProviderRequirement::None, // 6 max_usd
    ProviderRequirement::None, // 7 max_tokens
    ProviderRequirement::None, // 8 max_wall_secs
    ProviderRequirement::None, // 9 allow_code
    ProviderRequirement::None, // 10 permission_mode
    ProviderRequirement::None, // 11 permission_rules
    ProviderRequirement::None, // 12 bypass_permissions
    ProviderRequirement::SelectedRoute, // 13 compaction_trigger
    ProviderRequirement::None, // 14 verify_command
    ProviderRequirement::None, // 15 retry_backoff_base
    ProviderRequirement::None, // 16 retry_backoff_cap
    ProviderRequirement::None, // 17 retry_max_attempts
    ProviderRequirement::None, // 18 egress_allow
    ProviderRequirement::SelectedRoute, // 19 request_output_cap
    ProviderRequirement::SelectedRoute, // 20 effort_reasoning_map
    ProviderRequirement::SelectedRoute, // 21 thinking_map
    ProviderRequirement::None, // 22 orchestration_map
    // The outer prompt-cache switch is runtime-effective even on an incapable route: that route
    // owns the exact value `false`. Provider capability is an executable external ceiling, not an
    // activation prerequisite that makes the always-active family impossible to resolve.
    ProviderRequirement::None, // 23 prompt_cache
    ProviderRequirement::None, // 24 compaction_adaptive
    ProviderRequirement::None, // 25 compaction_keep_recent
    ProviderRequirement::None, // 26 token_estimator
    // Compaction summaries are produced by the local context runtime. Provider reasoning support
    // only controls whether a semantic effort hint can be serialized on the outbound request.
    ProviderRequirement::None, // 27 summary_profile
    ProviderRequirement::None, // 28 compaction_failure
    ProviderRequirement::None, // 29 instruction_discovery_render
    ProviderRequirement::None, // 30 memory_enable
    ProviderRequirement::None, // 31 memory_budgets
    ProviderRequirement::None, // 32 bm25
    ProviderRequirement::None, // 33 skill_listing_budget
    ProviderRequirement::None, // 34 max_consecutive_tool_errors
    ProviderRequirement::None, // 35 pure_overlap
    ProviderRequirement::None, // 36 pure_concurrency
    ProviderRequirement::None, // 37 failed_action_dedup
    ProviderRequirement::None, // 38 pure_memo_cache
    ProviderRequirement::None, // 39 shell_timeout_output
    ProviderRequirement::None, // 40 read_file_limits
    ProviderRequirement::None, // 41 list_dir_limits
    ProviderRequirement::None, // 42 glob_limits
    ProviderRequirement::None, // 43 grep_limits
    ProviderRequirement::None, // 44 repo_map
    ProviderRequirement::None, // 45 git_limits
    ProviderRequirement::None, // 46 web_fetch_limits
    ProviderRequirement::None, // 47 web_search_cap
    ProviderRequirement::None, // 48 verifier_attempts
    ProviderRequirement::None, // 49 verifier_feedback_tails
    ProviderRequirement::None, // 50 verifier_timeout
    ProviderRequirement::None, // 51 route_topology
    ProviderRequirement::None, // 52 decomposition_profile
    ProviderRequirement::None, // 53 fan_breadth
    ProviderRequirement::None, // 54 admission
    ProviderRequirement::None, // 55 writer_fan_turn_split
    ProviderRequirement::None, // 56 worker_min_turns
    ProviderRequirement::None, // 57 wall_split
    ProviderRequirement::None, // 58 token_split
    ProviderRequirement::None, // 59 fan_concurrency
    ProviderRequirement::None, // 60 child_ceiling
    ProviderRequirement::None, // 61 direct_child_allocation
    // Child effort inheritance is a local orchestration policy. Provider reasoning support only
    // gates the outbound reasoning field; it must not deactivate the checkpointed child policy.
    ProviderRequirement::None, // 62 subagent_effort_inheritance
    ProviderRequirement::None, // 63 report_budget
    ProviderRequirement::None, // 64 join_reduce
    ProviderRequirement::None, // 65 workflow_aggregate
    ProviderRequirement::None, // 66 schema_retry_jitter
    // Local transport bounds remain defined before/without provider capability discovery. The
    // exact admitted route selects an endpoint, but it does not own Core's TCP/TLS deadline.
    ProviderRequirement::None, // 67 provider_connect_tls_timeout
    // Image admission/inspection is a local pre-provider safety boundary and remains effective for
    // text-only routes (where provider-side multimodal admission is separately clamped to zero).
    ProviderRequirement::None, // 68 multimodal_input_admission_decode_envelope
    ProviderRequirement::None, // 69 app_server_sq_eq_backpressure
    ProviderRequirement::AnyAdmittedRoute, // 70 provider_discovery_account_probe_cache_policy
    ProviderRequirement::None, // 71 operator_prompt_stream
    ProviderRequirement::None, // 72 builtin_prompt_corpus
    ProviderRequirement::None, // 73 instruction_bundle
    ProviderRequirement::None, // 74 memory_corpus
    ProviderRequirement::None, // 75 skill_catalog
    ProviderRequirement::None, // 76 agent_catalog
    ProviderRequirement::AnyAdmittedRoute, // 77 provider_model_capability_catalog
    ProviderRequirement::None, // 78 mcp_topology_tool_catalog
    ProviderRequirement::None, // 79 hooks_map
    ProviderRequirement::None, // 80 workflow_graph
    ProviderRequirement::None, // 81 tool_action_space
    ProviderRequirement::SelectedRoute, // 82 rate_card_catalog
    ProviderRequirement::None, // 83 router_lexicons
    ProviderRequirement::None, // 84 environment_snapshot
    ProviderRequirement::None, // 85 web_search_backend_catalog
    ProviderRequirement::AnyAdmittedRoute, // 86 model_fallback_chain
    ProviderRequirement::AnyAdmittedRoute, // 87 failover_eligible_error_taxonomy
    // These are local deterministic governor policies. Typed per-route cost/health observations
    // gate candidate ranking and circuit transitions; their absence must not erase the policy.
    ProviderRequirement::None, // 88 route_quality_cost_latency_objective_weights
    ProviderRequirement::AnyAdmittedRoute, // 89 provider_health_circuit_breaker_state_policy
    ProviderRequirement::SelectedRoute, // 90 hedged_request_policy
    ProviderRequirement::SelectedRoute, // 91 provider_service_tier
    ProviderRequirement::SelectedRoute, // 92 response_verbosity
    ProviderRequirement::AnyAdmittedRoute, // 93 role_specific_model_map
    // Local physical deadlines are installed in every adapter; route capabilities may only
    // narrow wire controls and cannot erase the deadline owner itself.
    ProviderRequirement::None, // 94 provider_request_total_deadline
    ProviderRequirement::None, // 95 stream_idle_watchdog
    ProviderRequirement::SelectedRoute, // 96 context_window_override_reserve
    ProviderRequirement::None, // 97 system_prefix_budget
    ProviderRequirement::None, // 98 conversation_history_budget
    ProviderRequirement::None, // 99 tool_result_history_budget
    // A text-only route owns the exact zero token budget; it must not make the family inactive.
    ProviderRequirement::None, // 100 multimodal_token_budget
    ProviderRequirement::None, // 101 auto_compaction_enable
    ProviderRequirement::None, // 102 compaction_cooldown_hysteresis
    ProviderRequirement::None, // 103 multi_stage_summary_topology
    ProviderRequirement::None, // 104 summary_consistency_coverage_check
    ProviderRequirement::None, // 105 hybrid_retrieval_fusion_weights
    ProviderRequirement::None, // 106 retrieval_recency_decay
    ProviderRequirement::None, // 107 context_novelty_dedup_threshold
    ProviderRequirement::None, // 108 persistent_pty_backend
    ProviderRequirement::None, // 109 concurrent_background_job_cap
    ProviderRequirement::None, // 110 job_idle_stall_timeout
    ProviderRequirement::None, // 111 interactive_stdin_wait_policy
    ProviderRequirement::None, // 112 process_signal_kill_escalation
    ProviderRequirement::None, // 113 process_cwd_continuity
    ProviderRequirement::None, // 114 child_process_environment_reuse
    ProviderRequirement::None, // 115 effecting_tool_concurrency
    ProviderRequirement::None, // 116 write_set_conflict_admission
    ProviderRequirement::None, // 117 tool_output_spill_to_disk_policy
    // The local binary inspector routes before provider dispatch and does not require multimodal
    // provider support.
    ProviderRequirement::None, // 118 binary_media_inspection_routing
    ProviderRequirement::None, // 119 lsp_server_language_selection
    ProviderRequirement::None, // 120 lsp_timeout_restart_policy
    ProviderRequirement::None, // 121 lsp_result_context_budget
    ProviderRequirement::None, // 122 tool_result_cache_ttl
    ProviderRequirement::None, // 123 test_selection_strategy
    ProviderRequirement::None, // 124 incremental_versus_full_verification
    ProviderRequirement::None, // 125 flaky_test_detection_quarantine
    ProviderRequirement::None, // 126 failure_classification_taxonomy
    ProviderRequirement::None, // 127 retry_eligibility_policy
    ProviderRequirement::None, // 128 rollback_on_verification_failure
    ProviderRequirement::None, // 129 workspace_checkpoint_cadence
    ProviderRequirement::None, // 130 selective_restore_scope
    ProviderRequirement::None, // 131 verification_quorum_consensus
    ProviderRequirement::None, // 132 recovery_escalation_policy
    ProviderRequirement::SelectedRoute, // 133 per_agent_model
    // Child effort is a local orchestration ceiling. Unsupported provider reasoning fields are
    // omitted at the adapter boundary rather than deactivating the child policy.
    ProviderRequirement::None, // 134 per_agent_effort_thinking
    ProviderRequirement::None, // 135 per_agent_tool_profile
    ProviderRequirement::None, // 136 per_agent_memory_scope
    ProviderRequirement::None, // 137 spawn_depth_control
    ProviderRequirement::None, // 138 per_session_spawn_cap
    ProviderRequirement::None, // 139 task_priority_scheduling
    ProviderRequirement::None, // 140 speculative_sibling_count
    ProviderRequirement::None, // 141 speculative_sibling_cancellation
    ProviderRequirement::None, // 142 early_stop_quorum_policy
    ProviderRequirement::None, // 143 writer_worktree_isolation_mode
    ProviderRequirement::None, // 144 merge_conflict_arbitration
    ProviderRequirement::None, // 145 inter_agent_messaging_topology
    ProviderRequirement::None, // 146 task_retry_reassignment_policy
    ProviderRequirement::None, // 147 mcp_transport_selection
    ProviderRequirement::None, // 148 deferred_discovery_threshold
    ProviderRequirement::None, // 149 mcp_reconnect_backoff
    ProviderRequirement::None, // 150 per_server_startup_deadline
    ProviderRequirement::None, // 151 per_tool_mcp_deadline
    ProviderRequirement::None, // 152 mcp_result_cap_spill_policy
    ProviderRequirement::None, // 153 oauth_auth_lifecycle_policy
    ProviderRequirement::None, // 154 resource_prompt_plugin_capability_exposure
    ProviderRequirement::SelectedRoute, // 155 request_compression_policy
    ProviderRequirement::None, // 156 http_pool_keepalive_idle_policy
    ProviderRequirement::SelectedRoute, // 157 rate_limit_aware_admission
    ProviderRequirement::SelectedRoute, // 158 prompt_cache_ttl_breakpoint_strategy
    ProviderRequirement::None, // 159 session_isolation_profile
    ProviderRequirement::None, // 160 replay_divergence_detection_policy
];

pub(crate) const fn requirements(ordinal: u16, domain: Domain) -> RequirementSpec {
    let capabilities = match ordinal {
        1 | 77 => PROVIDER_CATALOG,
        // An explicitly selected model needs an admitted inference route, not catalog metadata.
        // Unknown metadata is handled by the conservative context-window fallback; requiring
        // metadata here would reject valid custom model IDs before that fallback can run.
        2 | 19 => INFERENCE,
        3 => PROVIDER_TRANSPORT,
        20 | 21 => PROVIDER_REASONING_CONTROL,
        // Both families have a conservative local ContextWindow owner for routes whose optional
        // model metadata is absent. Metadata may narrow the values, but it is not an activation
        // prerequisite for the executable fallback.
        13 | 96 => CONTEXT,
        // The capability name identifies the external ceiling owner. ProviderRequirement::None
        // below deliberately keeps the outer bool active: an incapable route contributes the
        // exact clamp `false` instead of making the family inactive.
        23 => PROMPT_CACHE,
        // Family 100 retains the provider capability name because it owns an exact external clamp
        // (`0` for text-only routes), but ProviderRequirement::None above prevents activation from
        // depending on that capability.
        100 => MULTIMODAL_CONTEXT,
        158 => PROMPT_CACHE_CONTEXT,
        // Decomposition is a local agent-orchestration policy. Provider reasoning support only
        // controls the outbound child request and must not deactivate the checkpoint policy.
        52 => COLLABORATION,
        62 => REASONING_CONTROL_AGENT,
        70 => PROVIDER_DISCOVERY,
        86 | 87 => PROVIDER_FAILOVER,
        88 => REASONING,
        89 => RUNTIME,
        90 => PROVIDER_HEDGING,
        91 => SERVICE_TIER,
        92 => PROVIDER_RESPONSE_VERBOSITY,
        93 => CATALOG_AGENT,
        67 | 94 | 95 | 156 => RUNTIME,
        104 => CONTEXT_VERIFY,
        105 | 107 => MEMORY_CONTEXT,
        108 | 113 | 114 => PERSISTENT_PROCESS,
        109 | 110 => BACKGROUND_JOB,
        111 => INTERACTIVE_STDIN,
        112 => PROCESS_SIGNAL,
        116 => FILESYSTEM_WRITE,
        117 => TOOL_CONTEXT,
        119 | 120 => LANGUAGE_SERVER,
        121 => LSP_CONTEXT,
        122 => TOOL_CACHE,
        129 | 130 => VERIFY_CHECKPOINT,
        131 => VERIFY_AGENT,
        133 => AGENT_CATALOG,
        135 => AGENT_TOOL,
        136 => AGENT_MEMORY,
        143 => WORKTREE,
        145 => MESSAGING,
        147 | 149 | 150 | 151 => MCP,
        148 => TOOL_CONTEXT,
        152 => MCP_CONTEXT,
        153 => OAUTH,
        154 => RESOURCE_CONTEXT,
        155 => REQUEST_COMPRESSION,
        157 => RATE_LIMIT_INFERENCE,
        160 => REPLAY_MESSAGING,
        _ => match domain {
            Domain::Provider => INFERENCE,
            Domain::Reasoning => REASONING,
            Domain::Budget => BUDGET,
            Domain::Context => CONTEXT,
            Domain::Memory => MEMORY,
            Domain::Tooling => TOOLING,
            Domain::Verification => VERIFICATION,
            Domain::Orchestration => COLLABORATION,
            Domain::Runtime => RUNTIME,
            Domain::Extensibility => EXTENSIBILITY,
            Domain::Observability => OBSERVABILITY,
            Domain::Interface => INTERFACE,
            Domain::Evaluation => EVALUATION,
            Domain::Governance => GOVERNANCE,
        },
    };
    let provider = PROVIDER_REQUIREMENTS[ordinal as usize - 1];
    RequirementSpec {
        provider,
        capabilities,
    }
}
