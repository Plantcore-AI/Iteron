//! Stable ownership identities for runtime controls.
//!
//! These keys deliberately live outside the public family-ID declarations. A family may be
//! renamed for clarity or moved while the underlying runtime control keeps the same ownership
//! identity. Conversely, two declarations for one control must repeat its key and are rejected by
//! registry validation.

use crate::EXPECTED_FAMILY_COUNT;

const SEMANTIC_KEYS: [&str; EXPECTED_FAMILY_COUNT] = [
    "core.control.provider.route_selection", // 1 provider
    "core.control.provider.model_selection", // 2 model
    "core.control.provider.api_endpoint",    // 3 base_url
    "core.control.reasoning.effort_tier",    // 4 effort
    "core.control.budget.turn_ceiling",      // 5 max_turns
    "core.control.budget.cost_ceiling_usd",  // 6 max_usd
    "core.control.budget.token_ceiling",     // 7 max_tokens
    "core.control.budget.wall_time_ceiling", // 8 max_wall_secs
    "core.control.governance.code_execution_admission", // 9 allow_code
    "core.control.governance.permission_posture", // 10 permission_mode
    "core.control.governance.capability_rules", // 11 permission_rules
    "core.control.governance.permission_prompt_bypass", // 12 bypass_permissions
    "core.control.context.compaction_activation", // 13 compaction_trigger
    "core.control.verification.command_selection", // 14 verify_command
    "core.control.runtime.provider_retry_initial_delay", // 15 retry_backoff_base
    "core.control.runtime.provider_retry_maximum_delay", // 16 retry_backoff_cap
    "core.control.runtime.provider_retry_attempt_ceiling", // 17 retry_max_attempts
    "core.control.governance.egress_allowlist", // 18 egress_allow
    "core.control.provider.response_token_ceiling", // 19 request_output_cap
    "core.control.reasoning.effort_to_reasoning", // 20 effort_reasoning_map
    "core.control.reasoning.effort_to_thinking_budget", // 21 thinking_map
    "core.control.orchestration.effort_to_topology", // 22 orchestration_map
    "core.control.provider.prompt_cache_emission", // 23 prompt_cache
    "core.control.context.compaction_adaptation", // 24 compaction_adaptive
    "core.control.context.recent_turn_retention", // 25 compaction_keep_recent
    "core.control.context.token_estimation", // 26 token_estimator
    "core.control.context.summary_shape",    // 27 summary_profile
    "core.control.context.compaction_failure_handling", // 28 compaction_failure
    "core.control.context.instruction_discovery_rendering", // 29 instruction_discovery_render
    "core.control.memory.durable_memory_admission", // 30 memory_enable
    "core.control.memory.retrieval_render_write_budgets", // 31 memory_budgets
    "core.control.context.lexical_retrieval_scoring", // 32 bm25
    "core.control.context.skill_catalog_render_budget", // 33 skill_listing_budget
    "core.control.budget.consecutive_tool_error_ceiling", // 34 max_consecutive_tool_errors
    "core.control.orchestration.pure_tool_overlap", // 35 pure_overlap
    "core.control.orchestration.pure_tool_concurrency", // 36 pure_concurrency
    "core.control.tooling.failed_action_suppression", // 37 failed_action_dedup
    "core.control.tooling.deterministic_result_memo", // 38 pure_memo_cache
    "core.control.tooling.shell_execution_envelope", // 39 shell_timeout_output
    "core.control.tooling.file_read_envelope", // 40 read_file_limits
    "core.control.tooling.directory_listing_envelope", // 41 list_dir_limits
    "core.control.tooling.glob_traversal_envelope", // 42 glob_limits
    "core.control.tooling.text_search_envelope", // 43 grep_limits
    "core.control.context.repository_map_envelope", // 44 repo_map
    "core.control.tooling.git_observation_envelope", // 45 git_limits
    "core.control.tooling.web_fetch_envelope", // 46 web_fetch_limits
    "core.control.tooling.web_search_result_ceiling", // 47 web_search_cap
    "core.control.verification.repair_attempt_ceiling", // 48 verifier_attempts
    "core.control.verification.failure_feedback_tail", // 49 verifier_feedback_tails
    "core.control.verification.command_deadline", // 50 verifier_timeout
    "core.control.orchestration.execution_topology", // 51 route_topology
    "core.control.orchestration.task_decomposition", // 52 decomposition_profile
    "core.control.orchestration.investigator_fanout", // 53 fan_breadth
    "core.control.orchestration.child_admission", // 54 admission
    "core.control.orchestration.writer_investigator_turn_allocation", // 55 writer_fan_turn_split
    "core.control.orchestration.child_minimum_turns", // 56 worker_min_turns
    "core.control.orchestration.child_wall_time_allocation", // 57 wall_split
    "core.control.orchestration.child_token_allocation", // 58 token_split
    "core.control.orchestration.investigator_concurrency", // 59 fan_concurrency
    "core.control.orchestration.child_resource_ceiling", // 60 child_ceiling
    "core.control.orchestration.direct_child_budget", // 61 direct_child_allocation
    "core.control.orchestration.child_reasoning_effort", // 62 subagent_effort_inheritance
    "core.control.orchestration.child_report_size", // 63 report_budget
    "core.control.orchestration.result_reduction", // 64 join_reduce
    "core.control.orchestration.workflow_aggregate_budget", // 65 workflow_aggregate
    "core.control.runtime.schema_repair_schedule", // 66 schema_retry_jitter
    "core.control.provider.connection_deadline", // 67 provider_connect_tls_timeout
    "core.control.runtime.multimodal_decode_envelope", // 68 multimodal_input_admission_decode_envelope
    "core.control.runtime.app_server_queue_backpressure", // 69 app_server_sq_eq_backpressure
    "core.control.provider.discovery_probe_cache", // 70 provider_discovery_account_probe_cache_policy
    "core.control.context.operator_input_stream",  // 71 operator_prompt_stream
    "core.control.reasoning.system_prompt_catalog", // 72 builtin_prompt_corpus
    "core.control.context.repository_instruction_set", // 73 instruction_bundle
    "core.control.memory.admitted_record_corpus",  // 74 memory_corpus
    "core.control.extensibility.skill_definition_catalog", // 75 skill_catalog
    "core.control.extensibility.agent_definition_catalog", // 76 agent_catalog
    "core.control.provider.model_capability_evidence", // 77 provider_model_capability_catalog
    "core.control.extensibility.mcp_server_tool_topology", // 78 mcp_topology_tool_catalog
    "core.control.extensibility.lifecycle_hook_bindings", // 79 hooks_map
    "core.control.orchestration.workflow_task_graph", // 80 workflow_graph
    "core.control.tooling.registered_action_space", // 81 tool_action_space
    "core.control.observability.provider_rate_card", // 82 rate_card_catalog
    "core.control.reasoning.routing_signal_lexicon", // 83 router_lexicons
    "core.control.context.run_environment_snapshot", // 84 environment_snapshot
    "core.control.extensibility.web_search_backend_catalog", // 85 web_search_backend_catalog
    "core.control.provider.route_fallback_order",  // 86 model_fallback_chain
    "core.control.provider.failover_error_classes", // 87 failover_eligible_error_taxonomy
    "core.control.reasoning.routing_objective_weights", // 88 route_quality_cost_latency_objective_weights
    "core.control.provider.health_circuit_breaker", // 89 provider_health_circuit_breaker_state_policy
    "core.control.provider.hedged_request_schedule", // 90 hedged_request_policy
    "core.control.provider.service_tier",           // 91 provider_service_tier
    "core.control.reasoning.response_detail",       // 92 response_verbosity
    "core.control.orchestration.role_model_assignment", // 93 role_specific_model_map
    "core.control.provider.request_deadline",       // 94 provider_request_total_deadline
    "core.control.provider.stream_idle_deadline",   // 95 stream_idle_watchdog
    "core.control.context.model_window_reserve",    // 96 context_window_override_reserve
    "core.control.context.system_prefix_allocation", // 97 system_prefix_budget
    "core.control.context.conversation_history_allocation", // 98 conversation_history_budget
    "core.control.context.tool_result_history_allocation", // 99 tool_result_history_budget
    "core.control.context.multimodal_allocation",   // 100 multimodal_token_budget
    "core.control.context.automatic_compaction_admission", // 101 auto_compaction_enable
    "core.control.context.compaction_hysteresis",   // 102 compaction_cooldown_hysteresis
    "core.control.context.summary_stage_topology",  // 103 multi_stage_summary_topology
    "core.control.verification.summary_coverage",   // 104 summary_consistency_coverage_check
    "core.control.memory.hybrid_retrieval_fusion",  // 105 hybrid_retrieval_fusion_weights
    "core.control.memory.recency_weight_decay",     // 106 retrieval_recency_decay
    "core.control.context.novelty_deduplication",   // 107 context_novelty_dedup_threshold
    "core.control.tooling.terminal_backend",        // 108 persistent_pty_backend
    "core.control.tooling.background_job_concurrency", // 109 concurrent_background_job_cap
    "core.control.tooling.background_job_idle_deadline", // 110 job_idle_stall_timeout
    "core.control.tooling.interactive_stdin_wait",  // 111 interactive_stdin_wait_policy
    "core.control.tooling.process_termination_escalation", // 112 process_signal_kill_escalation
    "core.control.tooling.process_working_directory", // 113 process_cwd_continuity
    "core.control.tooling.child_environment_inheritance", // 114 child_process_environment_reuse
    "core.control.orchestration.effecting_tool_concurrency", // 115 effecting_tool_concurrency
    "core.control.tooling.write_set_conflict_gate", // 116 write_set_conflict_admission
    "core.control.tooling.tool_output_spill",       // 117 tool_output_spill_to_disk_policy
    "core.control.tooling.binary_media_router",     // 118 binary_media_inspection_routing
    "core.control.tooling.language_server_selection", // 119 lsp_server_language_selection
    "core.control.tooling.language_server_recovery", // 120 lsp_timeout_restart_policy
    "core.control.context.language_server_result_budget", // 121 lsp_result_context_budget
    "core.control.tooling.result_cache_lifetime",   // 122 tool_result_cache_ttl
    "core.control.verification.test_selection",     // 123 test_selection_strategy
    "core.control.verification.incremental_full_mode", // 124 incremental_versus_full_verification
    "core.control.verification.flaky_test_quarantine", // 125 flaky_test_detection_quarantine
    "core.control.verification.failure_taxonomy",   // 126 failure_classification_taxonomy
    "core.control.verification.retry_admission",    // 127 retry_eligibility_policy
    "core.control.verification.failure_rollback",   // 128 rollback_on_verification_failure
    "core.control.verification.checkpoint_schedule", // 129 workspace_checkpoint_cadence
    "core.control.verification.restore_selection",  // 130 selective_restore_scope
    "core.control.verification.quorum_consensus",   // 131 verification_quorum_consensus
    "core.control.verification.recovery_escalation", // 132 recovery_escalation_policy
    "core.control.orchestration.agent_model_assignment", // 133 per_agent_model
    "core.control.orchestration.agent_reasoning_assignment", // 134 per_agent_effort_thinking
    "core.control.orchestration.agent_tool_capabilities", // 135 per_agent_tool_profile
    "core.control.memory.agent_scope_isolation",    // 136 per_agent_memory_scope
    "core.control.orchestration.spawn_depth_ceiling", // 137 spawn_depth_control
    "core.control.orchestration.session_spawn_budget", // 138 per_session_spawn_cap
    "core.control.orchestration.ready_task_priority", // 139 task_priority_scheduling
    "core.control.orchestration.speculative_sibling_ceiling", // 140 speculative_sibling_count
    "core.control.orchestration.speculative_sibling_cancellation", // 141 speculative_sibling_cancellation
    "core.control.orchestration.evidence_quorum_stop",             // 142 early_stop_quorum_policy
    "core.control.governance.writer_worktree_isolation", // 143 writer_worktree_isolation_mode
    "core.control.verification.child_merge_arbitration", // 144 merge_conflict_arbitration
    "core.control.orchestration.agent_message_routing",  // 145 inter_agent_messaging_topology
    "core.control.orchestration.failed_task_reassignment", // 146 task_retry_reassignment_policy
    "core.control.extensibility.mcp_transport",          // 147 mcp_transport_selection
    "core.control.extensibility.mcp_discovery_deferral", // 148 deferred_discovery_threshold
    "core.control.extensibility.mcp_reconnect_schedule", // 149 mcp_reconnect_backoff
    "core.control.extensibility.mcp_server_startup_deadline", // 150 per_server_startup_deadline
    "core.control.extensibility.mcp_tool_deadline",      // 151 per_tool_mcp_deadline
    "core.control.extensibility.mcp_result_spill",       // 152 mcp_result_cap_spill_policy
    "core.control.extensibility.mcp_oauth_lifecycle",    // 153 oauth_auth_lifecycle_policy
    "core.control.extensibility.mcp_resource_prompt_exposure", // 154 resource_prompt_plugin_capability_exposure
    "core.control.provider.request_compression",               // 155 request_compression_policy
    "core.control.provider.connection_pool_lifetime", // 156 http_pool_keepalive_idle_policy
    "core.control.provider.rate_limit_admission",     // 157 rate_limit_aware_admission
    "core.control.provider.prompt_cache_policy",      // 158 prompt_cache_ttl_breakpoint_strategy
    "core.control.governance.session_isolation",      // 159 session_isolation_profile
    "core.control.verification.replay_divergence_rejection", // 160 replay_divergence_detection_policy
];

/// Resolve the stable control identity for one canonical ordinal. The key values themselves are
/// independent data; ordinal is only the declaration-ledger lookup index.
pub(crate) const fn semantic_key(ordinal: u16) -> &'static str {
    assert!(ordinal > 0 && ordinal as usize <= EXPECTED_FAMILY_COUNT);
    SEMANTIC_KEYS[ordinal as usize - 1]
}
