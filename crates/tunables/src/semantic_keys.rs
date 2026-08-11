//! Stable ownership identities for runtime controls.
//!
//! These keys deliberately live outside the public family-ID declarations. A family may be
//! renamed for clarity or moved while the underlying runtime control keeps the same ownership
//! identity. Conversely, two declarations for one control must repeat its key and are rejected by
//! registry validation.

use crate::EXPECTED_FAMILY_COUNT;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SemanticKeyEntry {
    pub ordinal: u16,
    pub family_id: &'static str,
    pub semantic_key: &'static str,
}

macro_rules! entry {
    ($ordinal:literal, $family_id:literal, $semantic_key:literal) => {
        SemanticKeyEntry {
            ordinal: $ordinal,
            family_id: $family_id,
            semantic_key: $semantic_key,
        }
    };
}

#[rustfmt::skip]
const SEMANTIC_KEYS: [SemanticKeyEntry; EXPECTED_FAMILY_COUNT] = [
    entry!(1, "provider", "iteron.control.provider.route_selection"),
    entry!(2, "model", "iteron.control.provider.model_selection"),
    entry!(3, "base_url", "iteron.control.provider.api_endpoint"),
    entry!(4, "effort", "iteron.control.reasoning.effort_tier"),
    entry!(5, "max_turns", "iteron.control.budget.turn_ceiling"),
    entry!(6, "max_usd", "iteron.control.budget.cost_ceiling_usd"),
    entry!(7, "max_tokens", "iteron.control.budget.token_ceiling"),
    entry!(8, "max_wall_secs", "iteron.control.budget.wall_time_ceiling"),
    entry!(9, "allow_code", "iteron.control.governance.code_execution_admission"),
    entry!(10, "permission_mode", "iteron.control.governance.permission_posture"),
    entry!(11, "permission_rules", "iteron.control.governance.capability_rules"),
    entry!(12, "bypass_permissions", "iteron.control.governance.permission_prompt_bypass"),
    entry!(13, "compaction_trigger", "iteron.control.context.compaction_activation"),
    entry!(14, "verify_command", "iteron.control.verification.command_selection"),
    entry!(15, "retry_backoff_base", "iteron.control.runtime.provider_retry_initial_delay"),
    entry!(16, "retry_backoff_cap", "iteron.control.runtime.provider_retry_maximum_delay"),
    entry!(17, "retry_max_attempts", "iteron.control.runtime.provider_retry_attempt_ceiling"),
    entry!(18, "egress_allow", "iteron.control.governance.egress_allowlist"),
    entry!(19, "request_output_cap", "iteron.control.provider.response_token_ceiling"),
    entry!(20, "effort_reasoning_map", "iteron.control.reasoning.effort_to_reasoning"),
    entry!(21, "thinking_map", "iteron.control.reasoning.effort_to_thinking_budget"),
    entry!(22, "orchestration_map", "iteron.control.orchestration.effort_to_topology"),
    entry!(23, "prompt_cache", "iteron.control.provider.prompt_cache_emission"),
    entry!(24, "compaction_adaptive", "iteron.control.context.compaction_adaptation"),
    entry!(25, "compaction_keep_recent", "iteron.control.context.recent_turn_retention"),
    entry!(26, "token_estimator", "iteron.control.context.token_estimation"),
    entry!(27, "summary_profile", "iteron.control.context.summary_shape"),
    entry!(28, "compaction_failure", "iteron.control.context.compaction_failure_handling"),
    entry!(29, "instruction_discovery_render", "iteron.control.context.instruction_discovery_rendering"),
    entry!(30, "memory_enable", "iteron.control.memory.durable_memory_admission"),
    entry!(31, "memory_budgets", "iteron.control.memory.retrieval_render_write_budgets"),
    entry!(32, "bm25", "iteron.control.context.lexical_retrieval_scoring"),
    entry!(33, "skill_listing_budget", "iteron.control.context.skill_catalog_render_budget"),
    entry!(34, "max_consecutive_tool_errors", "iteron.control.budget.consecutive_tool_error_ceiling"),
    entry!(35, "pure_overlap", "iteron.control.orchestration.pure_tool_overlap"),
    entry!(36, "pure_concurrency", "iteron.control.orchestration.pure_tool_concurrency"),
    entry!(37, "failed_action_dedup", "iteron.control.tooling.failed_action_suppression"),
    entry!(38, "pure_memo_cache", "iteron.control.tooling.deterministic_result_memo"),
    entry!(39, "shell_timeout_output", "iteron.control.tooling.shell_execution_envelope"),
    entry!(40, "read_file_limits", "iteron.control.tooling.file_read_envelope"),
    entry!(41, "list_dir_limits", "iteron.control.tooling.directory_listing_envelope"),
    entry!(42, "glob_limits", "iteron.control.tooling.glob_traversal_envelope"),
    entry!(43, "grep_limits", "iteron.control.tooling.text_search_envelope"),
    entry!(44, "repo_map", "iteron.control.context.repository_map_envelope"),
    entry!(45, "git_limits", "iteron.control.tooling.git_observation_envelope"),
    entry!(46, "web_fetch_limits", "iteron.control.tooling.web_fetch_envelope"),
    entry!(47, "web_search_cap", "iteron.control.tooling.web_search_result_ceiling"),
    entry!(48, "verifier_attempts", "iteron.control.verification.repair_attempt_ceiling"),
    entry!(49, "verifier_feedback_tails", "iteron.control.verification.failure_feedback_tail"),
    entry!(50, "verifier_timeout", "iteron.control.verification.command_deadline"),
    entry!(51, "route_topology", "iteron.control.orchestration.execution_topology"),
    entry!(52, "decomposition_profile", "iteron.control.orchestration.task_decomposition"),
    entry!(53, "fan_breadth", "iteron.control.orchestration.investigator_fanout"),
    entry!(54, "admission", "iteron.control.orchestration.child_admission"),
    entry!(55, "writer_fan_turn_split", "iteron.control.orchestration.writer_investigator_turn_allocation"),
    entry!(56, "worker_min_turns", "iteron.control.orchestration.child_minimum_turns"),
    entry!(57, "wall_split", "iteron.control.orchestration.child_wall_time_allocation"),
    entry!(58, "token_split", "iteron.control.orchestration.child_token_allocation"),
    entry!(59, "fan_concurrency", "iteron.control.orchestration.investigator_concurrency"),
    entry!(60, "child_ceiling", "iteron.control.orchestration.child_resource_ceiling"),
    entry!(61, "direct_child_allocation", "iteron.control.orchestration.direct_child_budget"),
    entry!(62, "subagent_effort_inheritance", "iteron.control.orchestration.child_reasoning_effort"),
    entry!(63, "report_budget", "iteron.control.orchestration.child_report_size"),
    entry!(64, "join_reduce", "iteron.control.orchestration.result_reduction"),
    entry!(65, "workflow_aggregate", "iteron.control.orchestration.workflow_aggregate_budget"),
    entry!(66, "schema_retry_jitter", "iteron.control.runtime.schema_repair_schedule"),
    entry!(67, "provider_connect_tls_timeout", "iteron.control.provider.connection_deadline"),
    entry!(68, "multimodal_input_admission_decode_envelope", "iteron.control.runtime.multimodal_decode_envelope"),
    entry!(69, "app_server_sq_eq_backpressure", "iteron.control.runtime.app_server_queue_backpressure"),
    entry!(70, "provider_discovery_account_probe_cache_policy", "iteron.control.provider.discovery_probe_cache"),
    entry!(71, "operator_prompt_stream", "iteron.control.context.operator_input_stream"),
    entry!(72, "builtin_prompt_corpus", "iteron.control.reasoning.system_prompt_catalog"),
    entry!(73, "instruction_bundle", "iteron.control.context.repository_instruction_set"),
    entry!(74, "memory_corpus", "iteron.control.memory.admitted_record_corpus"),
    entry!(75, "skill_catalog", "iteron.control.extensibility.skill_definition_catalog"),
    entry!(76, "agent_catalog", "iteron.control.extensibility.agent_definition_catalog"),
    entry!(77, "provider_model_capability_catalog", "iteron.control.provider.model_capability_evidence"),
    entry!(78, "mcp_topology_tool_catalog", "iteron.control.extensibility.mcp_server_tool_topology"),
    entry!(79, "hooks_map", "iteron.control.extensibility.lifecycle_hook_bindings"),
    entry!(80, "workflow_graph", "iteron.control.orchestration.workflow_task_graph"),
    entry!(81, "tool_action_space", "iteron.control.tooling.registered_action_space"),
    entry!(82, "rate_card_catalog", "iteron.control.observability.provider_rate_card"),
    entry!(83, "router_lexicons", "iteron.control.reasoning.routing_signal_lexicon"),
    entry!(84, "environment_snapshot", "iteron.control.context.run_environment_snapshot"),
    entry!(85, "web_search_backend_catalog", "iteron.control.extensibility.web_search_backend_catalog"),
    entry!(86, "model_fallback_chain", "iteron.control.provider.route_fallback_order"),
    entry!(87, "failover_eligible_error_taxonomy", "iteron.control.provider.failover_error_classes"),
    entry!(88, "route_quality_cost_latency_objective_weights", "iteron.control.reasoning.routing_objective_weights"),
    entry!(89, "provider_health_circuit_breaker_state_policy", "iteron.control.provider.health_circuit_breaker"),
    entry!(90, "hedged_request_policy", "iteron.control.provider.hedged_request_schedule"),
    entry!(91, "provider_service_tier", "iteron.control.provider.service_tier"),
    entry!(92, "response_verbosity", "iteron.control.reasoning.response_detail"),
    entry!(93, "role_specific_model_map", "iteron.control.orchestration.role_model_assignment"),
    entry!(94, "provider_request_total_deadline", "iteron.control.provider.request_deadline"),
    entry!(95, "stream_idle_watchdog", "iteron.control.provider.stream_idle_deadline"),
    entry!(96, "context_window_override_reserve", "iteron.control.context.model_window_reserve"),
    entry!(97, "system_prefix_budget", "iteron.control.context.system_prefix_allocation"),
    entry!(98, "conversation_history_budget", "iteron.control.context.conversation_history_allocation"),
    entry!(99, "tool_result_history_budget", "iteron.control.context.tool_result_history_allocation"),
    entry!(100, "multimodal_token_budget", "iteron.control.context.multimodal_allocation"),
    entry!(101, "auto_compaction_enable", "iteron.control.context.automatic_compaction_admission"),
    entry!(102, "compaction_cooldown_hysteresis", "iteron.control.context.compaction_hysteresis"),
    entry!(103, "multi_stage_summary_topology", "iteron.control.context.summary_stage_topology"),
    entry!(104, "summary_consistency_coverage_check", "iteron.control.verification.summary_coverage"),
    entry!(105, "hybrid_retrieval_fusion_weights", "iteron.control.memory.hybrid_retrieval_fusion"),
    entry!(106, "retrieval_recency_decay", "iteron.control.memory.recency_weight_decay"),
    entry!(107, "context_novelty_dedup_threshold", "iteron.control.context.novelty_deduplication"),
    entry!(108, "persistent_pty_backend", "iteron.control.tooling.terminal_backend"),
    entry!(109, "concurrent_background_job_cap", "iteron.control.tooling.background_job_concurrency"),
    entry!(110, "job_idle_stall_timeout", "iteron.control.tooling.background_job_idle_deadline"),
    entry!(111, "interactive_stdin_wait_policy", "iteron.control.tooling.interactive_stdin_wait"),
    entry!(112, "process_signal_kill_escalation", "iteron.control.tooling.process_termination_escalation"),
    entry!(113, "process_cwd_continuity", "iteron.control.tooling.process_working_directory"),
    entry!(114, "child_process_environment_reuse", "iteron.control.tooling.child_environment_inheritance"),
    entry!(115, "effecting_tool_concurrency", "iteron.control.orchestration.effecting_tool_concurrency"),
    entry!(116, "write_set_conflict_admission", "iteron.control.tooling.write_set_conflict_gate"),
    entry!(117, "tool_output_spill_to_disk_policy", "iteron.control.tooling.tool_output_spill"),
    entry!(118, "binary_media_inspection_routing", "iteron.control.tooling.binary_media_router"),
    entry!(119, "lsp_server_language_selection", "iteron.control.tooling.language_server_selection"),
    entry!(120, "lsp_timeout_restart_policy", "iteron.control.tooling.language_server_recovery"),
    entry!(121, "lsp_result_context_budget", "iteron.control.context.language_server_result_budget"),
    entry!(122, "tool_result_cache_ttl", "iteron.control.tooling.result_cache_lifetime"),
    entry!(123, "test_selection_strategy", "iteron.control.verification.test_selection"),
    entry!(124, "incremental_versus_full_verification", "iteron.control.verification.incremental_full_mode"),
    entry!(125, "flaky_test_detection_quarantine", "iteron.control.verification.flaky_test_quarantine"),
    entry!(126, "failure_classification_taxonomy", "iteron.control.verification.failure_taxonomy"),
    entry!(127, "retry_eligibility_policy", "iteron.control.verification.retry_admission"),
    entry!(128, "rollback_on_verification_failure", "iteron.control.verification.failure_rollback"),
    entry!(129, "workspace_checkpoint_cadence", "iteron.control.verification.checkpoint_schedule"),
    entry!(130, "selective_restore_scope", "iteron.control.verification.restore_selection"),
    entry!(131, "verification_quorum_consensus", "iteron.control.verification.quorum_consensus"),
    entry!(132, "recovery_escalation_policy", "iteron.control.verification.recovery_escalation"),
    entry!(133, "per_agent_model", "iteron.control.orchestration.agent_model_assignment"),
    entry!(134, "per_agent_effort_thinking", "iteron.control.orchestration.agent_reasoning_assignment"),
    entry!(135, "per_agent_tool_profile", "iteron.control.orchestration.agent_tool_capabilities"),
    entry!(136, "per_agent_memory_scope", "iteron.control.memory.agent_scope_isolation"),
    entry!(137, "spawn_depth_control", "iteron.control.orchestration.spawn_depth_ceiling"),
    entry!(138, "per_session_spawn_cap", "iteron.control.orchestration.session_spawn_budget"),
    entry!(139, "task_priority_scheduling", "iteron.control.orchestration.ready_task_priority"),
    entry!(140, "speculative_sibling_count", "iteron.control.orchestration.speculative_sibling_ceiling"),
    entry!(141, "speculative_sibling_cancellation", "iteron.control.orchestration.speculative_sibling_cancellation"),
    entry!(142, "early_stop_quorum_policy", "iteron.control.orchestration.evidence_quorum_stop"),
    entry!(143, "writer_worktree_isolation_mode", "iteron.control.governance.writer_worktree_isolation"),
    entry!(144, "merge_conflict_arbitration", "iteron.control.verification.child_merge_arbitration"),
    entry!(145, "inter_agent_messaging_topology", "iteron.control.orchestration.agent_message_routing"),
    entry!(146, "task_retry_reassignment_policy", "iteron.control.orchestration.failed_task_reassignment"),
    entry!(147, "mcp_transport_selection", "iteron.control.extensibility.mcp_transport"),
    entry!(148, "deferred_discovery_threshold", "iteron.control.extensibility.tool_schema_discovery_deferral"),
    entry!(149, "mcp_reconnect_backoff", "iteron.control.extensibility.mcp_reconnect_schedule"),
    entry!(150, "per_server_startup_deadline", "iteron.control.extensibility.mcp_server_startup_deadline"),
    entry!(151, "per_tool_mcp_deadline", "iteron.control.extensibility.mcp_tool_deadline"),
    entry!(152, "mcp_result_cap_spill_policy", "iteron.control.extensibility.mcp_result_spill"),
    entry!(153, "oauth_auth_lifecycle_policy", "iteron.control.extensibility.mcp_oauth_lifecycle"),
    entry!(154, "resource_prompt_plugin_capability_exposure", "iteron.control.extensibility.mcp_resource_prompt_exposure"),
    entry!(155, "request_compression_policy", "iteron.control.provider.request_compression"),
    entry!(156, "http_pool_keepalive_idle_policy", "iteron.control.provider.connection_pool_lifetime"),
    entry!(157, "rate_limit_aware_admission", "iteron.control.provider.rate_limit_admission"),
    entry!(158, "prompt_cache_ttl_breakpoint_strategy", "iteron.control.provider.prompt_cache_policy"),
    entry!(159, "session_isolation_profile", "iteron.control.governance.session_isolation"),
    entry!(160, "replay_divergence_detection_policy", "iteron.control.verification.replay_divergence_rejection"),
];

/// Resolve one production declaration against its exact ledger identity during static
/// construction. Both the ordinal and family ID are load-bearing association keys.
pub(crate) const fn semantic_key(ordinal: u16, family_id: &str) -> &'static str {
    assert!(ordinal > 0 && ordinal as usize <= EXPECTED_FAMILY_COUNT);
    let entry = SEMANTIC_KEYS[ordinal as usize - 1];
    assert!(entry.ordinal == ordinal);
    assert!(const_str_eq(entry.family_id, family_id));
    entry.semantic_key
}

/// Return the expected association independently of the family declaration. Registry validation
/// uses this path before consulting the golden digest, so swapped unique keys are rejected.
pub(crate) fn expected_entry(ordinal: u16) -> Option<SemanticKeyEntry> {
    ordinal
        .checked_sub(1)
        .and_then(|index| SEMANTIC_KEYS.get(usize::from(index)))
        .copied()
}

const fn const_str_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}
