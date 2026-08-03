use core_tunables::{
    ActivationPredicate, CausalPath, CoreStrategySlot, CrossFieldRule, DefaultKind,
    DefaultResolver, DefaultValueRequirement, EXPECTED_FAMILY_COUNT, ExternalCeiling,
    ImplementationStatus, InactiveReason, ProviderRequirement, REGISTRY_DIGEST_SHA256,
    RelevanceLevel, SCALAR_CATALOGS, ScalarDomain, SourceKind, SourceTrust, StructuredValueDomain,
    TunableValue, TunableValueField, ValueKind, canonical_artifact, canonical_artifact_json,
    canonical_payload_json, families, family_semantic_digest, registry_digest, validate_registry,
};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;

macro_rules! relevance {
    ($swe:ident, $terminal:ident) => {
        (RelevanceLevel::$swe, RelevanceLevel::$terminal)
    };
}

const EXPECTED_IDS: [&str; EXPECTED_FAMILY_COUNT] = [
    "provider",                                      // 1
    "model",                                         // 2
    "base_url",                                      // 3
    "effort",                                        // 4
    "max_turns",                                     // 5
    "max_usd",                                       // 6
    "max_tokens",                                    // 7
    "max_wall_secs",                                 // 8
    "allow_code",                                    // 9
    "permission_mode",                               // 10
    "permission_rules",                              // 11
    "bypass_permissions",                            // 12
    "compaction_trigger",                            // 13
    "verify_command",                                // 14
    "retry_backoff_base",                            // 15
    "retry_backoff_cap",                             // 16
    "retry_max_attempts",                            // 17
    "egress_allow",                                  // 18
    "request_output_cap",                            // 19
    "effort_reasoning_map",                          // 20
    "thinking_map",                                  // 21
    "orchestration_map",                             // 22
    "prompt_cache",                                  // 23
    "compaction_adaptive",                           // 24
    "compaction_keep_recent",                        // 25
    "token_estimator",                               // 26
    "summary_profile",                               // 27
    "compaction_failure",                            // 28
    "instruction_discovery_render",                  // 29
    "memory_enable",                                 // 30
    "memory_budgets",                                // 31
    "bm25",                                          // 32
    "skill_listing_budget",                          // 33
    "max_consecutive_tool_errors",                   // 34
    "pure_overlap",                                  // 35
    "pure_concurrency",                              // 36
    "failed_action_dedup",                           // 37
    "pure_memo_cache",                               // 38
    "shell_timeout_output",                          // 39
    "read_file_limits",                              // 40
    "list_dir_limits",                               // 41
    "glob_limits",                                   // 42
    "grep_limits",                                   // 43
    "repo_map",                                      // 44
    "git_limits",                                    // 45
    "web_fetch_limits",                              // 46
    "web_search_cap",                                // 47
    "verifier_attempts",                             // 48
    "verifier_feedback_tails",                       // 49
    "verifier_timeout",                              // 50
    "route_topology",                                // 51
    "decomposition_profile",                         // 52
    "fan_breadth",                                   // 53
    "admission",                                     // 54
    "writer_fan_turn_split",                         // 55
    "worker_min_turns",                              // 56
    "wall_split",                                    // 57
    "token_split",                                   // 58
    "fan_concurrency",                               // 59
    "child_ceiling",                                 // 60
    "direct_child_allocation",                       // 61
    "subagent_effort_inheritance",                   // 62
    "report_budget",                                 // 63
    "join_reduce",                                   // 64
    "workflow_aggregate",                            // 65
    "schema_retry_jitter",                           // 66
    "provider_connect_tls_timeout",                  // 67
    "multimodal_input_admission_decode_envelope",    // 68
    "app_server_sq_eq_backpressure",                 // 69
    "provider_discovery_account_probe_cache_policy", // 70
    "operator_prompt_stream",                        // 71
    "builtin_prompt_corpus",                         // 72
    "instruction_bundle",                            // 73
    "memory_corpus",                                 // 74
    "skill_catalog",                                 // 75
    "agent_catalog",                                 // 76
    "provider_model_capability_catalog",             // 77
    "mcp_topology_tool_catalog",                     // 78
    "hooks_map",                                     // 79
    "workflow_graph",                                // 80
    "tool_action_space",                             // 81
    "rate_card_catalog",                             // 82
    "router_lexicons",                               // 83
    "environment_snapshot",                          // 84
    "web_search_backend_catalog",                    // 85
    "model_fallback_chain",                          // 86
    "failover_eligible_error_taxonomy",              // 87
    "route_quality_cost_latency_objective_weights",  // 88
    "provider_health_circuit_breaker_state_policy",  // 89
    "hedged_request_policy",                         // 90
    "provider_service_tier",                         // 91
    "response_verbosity",                            // 92
    "role_specific_model_map",                       // 93
    "provider_request_total_deadline",               // 94
    "stream_idle_watchdog",                          // 95
    "context_window_override_reserve",               // 96
    "system_prefix_budget",                          // 97
    "conversation_history_budget",                   // 98
    "tool_result_history_budget",                    // 99
    "multimodal_token_budget",                       // 100
    "auto_compaction_enable",                        // 101
    "compaction_cooldown_hysteresis",                // 102
    "multi_stage_summary_topology",                  // 103
    "summary_consistency_coverage_check",            // 104
    "hybrid_retrieval_fusion_weights",               // 105
    "retrieval_recency_decay",                       // 106
    "context_novelty_dedup_threshold",               // 107
    "persistent_pty_backend",                        // 108
    "concurrent_background_job_cap",                 // 109
    "job_idle_stall_timeout",                        // 110
    "interactive_stdin_wait_policy",                 // 111
    "process_signal_kill_escalation",                // 112
    "process_cwd_continuity",                        // 113
    "child_process_environment_reuse",               // 114
    "effecting_tool_concurrency",                    // 115
    "write_set_conflict_admission",                  // 116
    "tool_output_spill_to_disk_policy",              // 117
    "binary_media_inspection_routing",               // 118
    "lsp_server_language_selection",                 // 119
    "lsp_timeout_restart_policy",                    // 120
    "lsp_result_context_budget",                     // 121
    "tool_result_cache_ttl",                         // 122
    "test_selection_strategy",                       // 123
    "incremental_versus_full_verification",          // 124
    "flaky_test_detection_quarantine",               // 125
    "failure_classification_taxonomy",               // 126
    "retry_eligibility_policy",                      // 127
    "rollback_on_verification_failure",              // 128
    "workspace_checkpoint_cadence",                  // 129
    "selective_restore_scope",                       // 130
    "verification_quorum_consensus",                 // 131
    "recovery_escalation_policy",                    // 132
    "per_agent_model",                               // 133
    "per_agent_effort_thinking",                     // 134
    "per_agent_tool_profile",                        // 135
    "per_agent_memory_scope",                        // 136
    "spawn_depth_control",                           // 137
    "per_session_spawn_cap",                         // 138
    "task_priority_scheduling",                      // 139
    "speculative_sibling_count",                     // 140
    "speculative_sibling_cancellation",              // 141
    "early_stop_quorum_policy",                      // 142
    "writer_worktree_isolation_mode",                // 143
    "merge_conflict_arbitration",                    // 144
    "inter_agent_messaging_topology",                // 145
    "task_retry_reassignment_policy",                // 146
    "mcp_transport_selection",                       // 147
    "deferred_discovery_threshold",                  // 148
    "mcp_reconnect_backoff",                         // 149
    "per_server_startup_deadline",                   // 150
    "per_tool_mcp_deadline",                         // 151
    "mcp_result_cap_spill_policy",                   // 152
    "oauth_auth_lifecycle_policy",                   // 153
    "resource_prompt_plugin_capability_exposure",    // 154
    "request_compression_policy",                    // 155
    "http_pool_keepalive_idle_policy",               // 156
    "rate_limit_aware_admission",                    // 157
    "prompt_cache_ttl_breakpoint_strategy",          // 158
    "session_isolation_profile",                     // 159
    "replay_divergence_detection_policy",            // 160
];

const EXPECTED_RELEVANCE: [(RelevanceLevel, RelevanceLevel); EXPECTED_FAMILY_COUNT] = [
    relevance!(High, High),     // 1
    relevance!(High, High),     // 2
    relevance!(Medium, Medium), // 3
    relevance!(High, High),     // 4
    relevance!(High, High),     // 5
    relevance!(Medium, Medium), // 6
    relevance!(High, High),     // 7
    relevance!(High, High),     // 8
    relevance!(High, High),     // 9
    relevance!(High, High),     // 10
    relevance!(High, High),     // 11
    relevance!(High, High),     // 12
    relevance!(High, High),     // 13
    relevance!(High, Medium),   // 14
    relevance!(Medium, Medium), // 15
    relevance!(Medium, Medium), // 16
    relevance!(Medium, High),   // 17
    relevance!(Low, High),      // 18
    relevance!(High, High),     // 19
    relevance!(High, High),     // 20
    relevance!(High, High),     // 21
    relevance!(High, High),     // 22
    relevance!(Medium, Medium), // 23
    relevance!(High, High),     // 24
    relevance!(High, High),     // 25
    relevance!(Medium, High),   // 26
    relevance!(High, High),     // 27
    relevance!(Medium, High),   // 28
    relevance!(High, Medium),   // 29
    relevance!(Medium, Medium), // 30
    relevance!(High, Medium),   // 31
    relevance!(High, Medium),   // 32
    relevance!(Medium, Low),    // 33
    relevance!(High, High),     // 34
    relevance!(Medium, High),   // 35
    relevance!(Medium, High),   // 36
    relevance!(Medium, Medium), // 37
    relevance!(Medium, Medium), // 38
    relevance!(Medium, High),   // 39
    relevance!(High, Medium),   // 40
    relevance!(High, Medium),   // 41
    relevance!(High, Medium),   // 42
    relevance!(High, Medium),   // 43
    relevance!(High, Low),      // 44
    relevance!(High, Medium),   // 45
    relevance!(Medium, Medium), // 46
    relevance!(Low, Medium),    // 47
    relevance!(High, Medium),   // 48
    relevance!(High, Medium),   // 49
    relevance!(High, Medium),   // 50
    relevance!(High, High),     // 51
    relevance!(High, High),     // 52
    relevance!(High, High),     // 53
    relevance!(High, High),     // 54
    relevance!(High, High),     // 55
    relevance!(High, High),     // 56
    relevance!(High, High),     // 57
    relevance!(High, High),     // 58
    relevance!(Medium, High),   // 59
    relevance!(High, High),     // 60
    relevance!(High, High),     // 61
    relevance!(High, High),     // 62
    relevance!(Medium, High),   // 63
    relevance!(High, High),     // 64
    relevance!(Medium, Medium), // 65
    relevance!(Medium, Medium), // 66
    relevance!(Medium, Medium), // 67
    relevance!(Low, Medium),    // 68
    relevance!(Low, Low),       // 69
    relevance!(Medium, Medium), // 70
    relevance!(High, High),     // 71
    relevance!(High, High),     // 72
    relevance!(High, High),     // 73
    relevance!(Medium, High),   // 74
    relevance!(High, Medium),   // 75
    relevance!(Medium, Medium), // 76
    relevance!(High, High),     // 77
    relevance!(Medium, Medium), // 78
    relevance!(High, High),     // 79
    relevance!(High, High),     // 80
    relevance!(High, High),     // 81
    relevance!(Low, Low),       // 82
    relevance!(Medium, High),   // 83
    relevance!(Medium, Medium), // 84
    relevance!(Low, Medium),    // 85
    relevance!(Medium, Medium), // 86
    relevance!(Medium, Medium), // 87
    relevance!(High, High),     // 88
    relevance!(Medium, Medium), // 89
    relevance!(Medium, Medium), // 90
    relevance!(Medium, High),   // 91
    relevance!(Medium, Low),    // 92
    relevance!(High, Medium),   // 93
    relevance!(Medium, High),   // 94
    relevance!(Medium, Medium), // 95
    relevance!(High, High),     // 96
    relevance!(High, Medium),   // 97
    relevance!(High, High),     // 98
    relevance!(High, High),     // 99
    relevance!(Low, Medium),    // 100
    relevance!(High, High),     // 101
    relevance!(High, High),     // 102
    relevance!(High, Medium),   // 103
    relevance!(High, Medium),   // 104
    relevance!(High, Medium),   // 105
    relevance!(High, Medium),   // 106
    relevance!(High, Medium),   // 107
    relevance!(Medium, High),   // 108
    relevance!(Low, High),      // 109
    relevance!(Low, High),      // 110
    relevance!(Low, High),      // 111
    relevance!(Low, High),      // 112
    relevance!(Medium, High),   // 113
    relevance!(Medium, High),   // 114
    relevance!(Medium, High),   // 115
    relevance!(High, Medium),   // 116
    relevance!(Medium, High),   // 117
    relevance!(Low, Medium),    // 118
    relevance!(High, Medium),   // 119
    relevance!(High, Medium),   // 120
    relevance!(High, Medium),   // 121
    relevance!(Medium, Medium), // 122
    relevance!(High, Medium),   // 123
    relevance!(High, Medium),   // 124
    relevance!(High, Medium),   // 125
    relevance!(High, High),     // 126
    relevance!(High, High),     // 127
    relevance!(High, Medium),   // 128
    relevance!(Medium, Low),    // 129
    relevance!(Medium, Low),    // 130
    relevance!(High, Medium),   // 131
    relevance!(High, High),     // 132
    relevance!(High, Medium),   // 133
    relevance!(High, Medium),   // 134
    relevance!(High, Medium),   // 135
    relevance!(High, Medium),   // 136
    relevance!(Medium, High),   // 137
    relevance!(Medium, High),   // 138
    relevance!(Medium, High),   // 139
    relevance!(High, Medium),   // 140
    relevance!(High, Medium),   // 141
    relevance!(High, Medium),   // 142
    relevance!(High, Low),      // 143
    relevance!(High, Low),      // 144
    relevance!(High, Medium),   // 145
    relevance!(High, High),     // 146
    relevance!(Medium, Medium), // 147
    relevance!(Medium, Medium), // 148
    relevance!(Medium, Medium), // 149
    relevance!(Medium, Medium), // 150
    relevance!(Medium, High),   // 151
    relevance!(Medium, Medium), // 152
    relevance!(Low, Low),       // 153
    relevance!(Medium, Medium), // 154
    relevance!(Low, Medium),    // 155
    relevance!(Low, Medium),    // 156
    relevance!(Medium, Medium), // 157
    relevance!(Medium, Medium), // 158
    relevance!(High, High),     // 159
    relevance!(Medium, Medium), // 160
];

const EXPECTED_SLOTS: [&[CoreStrategySlot]; EXPECTED_FAMILY_COUNT] = [
    &[CoreStrategySlot::ModelRouter],                                // 1
    &[CoreStrategySlot::ModelRouter],                                // 2
    &[CoreStrategySlot::ModelRouter],                                // 3
    &[CoreStrategySlot::Planner, CoreStrategySlot::ModelRouter],     // 4
    &[CoreStrategySlot::Scheduler],                                  // 5
    &[CoreStrategySlot::Scheduler],                                  // 6
    &[CoreStrategySlot::Scheduler],                                  // 7
    &[CoreStrategySlot::Scheduler],                                  // 8
    &[CoreStrategySlot::ToolPolicy],                                 // 9
    &[CoreStrategySlot::ToolPolicy],                                 // 10
    &[CoreStrategySlot::ToolPolicy],                                 // 11
    &[CoreStrategySlot::ToolPolicy],                                 // 12
    &[CoreStrategySlot::Context],                                    // 13
    &[CoreStrategySlot::Verifier],                                   // 14
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::ModelRouter],   // 15
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::ModelRouter],   // 16
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::ModelRouter],   // 17
    &[CoreStrategySlot::ToolPolicy],                                 // 18
    &[CoreStrategySlot::ModelRouter, CoreStrategySlot::Context],     // 19
    &[CoreStrategySlot::Planner, CoreStrategySlot::ModelRouter],     // 20
    &[CoreStrategySlot::Planner, CoreStrategySlot::ModelRouter],     // 21
    &[CoreStrategySlot::Planner, CoreStrategySlot::Collaboration],   // 22
    &[CoreStrategySlot::ModelRouter, CoreStrategySlot::Context],     // 23
    &[CoreStrategySlot::Context],                                    // 24
    &[CoreStrategySlot::Context],                                    // 25
    &[CoreStrategySlot::Context, CoreStrategySlot::ModelRouter],     // 26
    &[CoreStrategySlot::Context, CoreStrategySlot::ModelRouter],     // 27
    &[CoreStrategySlot::Context],                                    // 28
    &[CoreStrategySlot::Context],                                    // 29
    &[CoreStrategySlot::Memory, CoreStrategySlot::Context],          // 30
    &[CoreStrategySlot::Memory, CoreStrategySlot::Context],          // 31
    &[CoreStrategySlot::Memory],                                     // 32
    &[CoreStrategySlot::Context, CoreStrategySlot::ToolPolicy],      // 33
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::ToolPolicy],    // 34
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::ToolPolicy],    // 35
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::ToolPolicy],    // 36
    &[CoreStrategySlot::ToolPolicy],                                 // 37
    &[CoreStrategySlot::ToolPolicy],                                 // 38
    &[CoreStrategySlot::ToolPolicy],                                 // 39
    &[CoreStrategySlot::ToolPolicy, CoreStrategySlot::Context],      // 40
    &[CoreStrategySlot::ToolPolicy, CoreStrategySlot::Context],      // 41
    &[CoreStrategySlot::ToolPolicy, CoreStrategySlot::Context],      // 42
    &[CoreStrategySlot::ToolPolicy, CoreStrategySlot::Context],      // 43
    &[CoreStrategySlot::Context, CoreStrategySlot::ToolPolicy],      // 44
    &[CoreStrategySlot::ToolPolicy, CoreStrategySlot::Context],      // 45
    &[CoreStrategySlot::ToolPolicy, CoreStrategySlot::Context],      // 46
    &[CoreStrategySlot::ToolPolicy, CoreStrategySlot::Context],      // 47
    &[CoreStrategySlot::Verifier, CoreStrategySlot::Scheduler],      // 48
    &[CoreStrategySlot::Verifier, CoreStrategySlot::Context],        // 49
    &[CoreStrategySlot::Verifier, CoreStrategySlot::Scheduler],      // 50
    &[CoreStrategySlot::Router, CoreStrategySlot::Collaboration],    // 51
    &[CoreStrategySlot::Planner, CoreStrategySlot::Collaboration],   // 52
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::Collaboration], // 53
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::Collaboration], // 54
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::Collaboration], // 55
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::Collaboration], // 56
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::Collaboration], // 57
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::Collaboration], // 58
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::Collaboration], // 59
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::Collaboration], // 60
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::Collaboration], // 61
    &[
        CoreStrategySlot::Planner,
        CoreStrategySlot::ModelRouter,
        CoreStrategySlot::Collaboration,
    ], // 62
    &[CoreStrategySlot::Context, CoreStrategySlot::Collaboration],   // 63
    &[CoreStrategySlot::Collaboration],                              // 64
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::Collaboration], // 65
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::ModelRouter],   // 66
    &[CoreStrategySlot::ModelRouter],                                // 67
    &[CoreStrategySlot::Context, CoreStrategySlot::ModelRouter],     // 68
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::Router],        // 69
    &[CoreStrategySlot::ModelRouter],                                // 70
    &[CoreStrategySlot::Context, CoreStrategySlot::Planner],         // 71
    &[CoreStrategySlot::Planner, CoreStrategySlot::Context],         // 72
    &[CoreStrategySlot::Context],                                    // 73
    &[CoreStrategySlot::Memory],                                     // 74
    &[CoreStrategySlot::Context, CoreStrategySlot::ToolPolicy],      // 75
    &[
        CoreStrategySlot::Collaboration,
        CoreStrategySlot::ModelRouter,
        CoreStrategySlot::ToolPolicy,
    ], // 76
    &[CoreStrategySlot::ModelRouter],                                // 77
    &[CoreStrategySlot::ToolPolicy],                                 // 78
    &[CoreStrategySlot::ToolPolicy],                                 // 79
    &[CoreStrategySlot::Planner, CoreStrategySlot::Collaboration],   // 80
    &[CoreStrategySlot::ToolPolicy],                                 // 81
    &[CoreStrategySlot::Router, CoreStrategySlot::ModelRouter],      // 82
    &[CoreStrategySlot::Router, CoreStrategySlot::Planner],          // 83
    &[CoreStrategySlot::Context],                                    // 84
    &[CoreStrategySlot::ToolPolicy, CoreStrategySlot::Router],       // 85
    &[CoreStrategySlot::ModelRouter],                                // 86
    &[CoreStrategySlot::ModelRouter],                                // 87
    &[CoreStrategySlot::Router, CoreStrategySlot::ModelRouter],      // 88
    &[CoreStrategySlot::ModelRouter],                                // 89
    &[CoreStrategySlot::ModelRouter],                                // 90
    &[CoreStrategySlot::ModelRouter],                                // 91
    &[CoreStrategySlot::Planner, CoreStrategySlot::ModelRouter],     // 92
    &[
        CoreStrategySlot::ModelRouter,
        CoreStrategySlot::Collaboration,
    ], // 93
    &[CoreStrategySlot::ModelRouter],                                // 94
    &[CoreStrategySlot::ModelRouter],                                // 95
    &[CoreStrategySlot::Context],                                    // 96
    &[CoreStrategySlot::Context],                                    // 97
    &[CoreStrategySlot::Context],                                    // 98
    &[CoreStrategySlot::Context],                                    // 99
    &[CoreStrategySlot::Context],                                    // 100
    &[CoreStrategySlot::Context],                                    // 101
    &[CoreStrategySlot::Context],                                    // 102
    &[CoreStrategySlot::Context],                                    // 103
    &[CoreStrategySlot::Context, CoreStrategySlot::Verifier],        // 104
    &[CoreStrategySlot::Memory, CoreStrategySlot::Context],          // 105
    &[CoreStrategySlot::Memory],                                     // 106
    &[CoreStrategySlot::Context, CoreStrategySlot::Memory],          // 107
    &[CoreStrategySlot::ToolPolicy],                                 // 108
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::ToolPolicy],    // 109
    &[CoreStrategySlot::ToolPolicy],                                 // 110
    &[CoreStrategySlot::ToolPolicy],                                 // 111
    &[CoreStrategySlot::ToolPolicy],                                 // 112
    &[CoreStrategySlot::ToolPolicy],                                 // 113
    &[CoreStrategySlot::ToolPolicy],                                 // 114
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::ToolPolicy],    // 115
    &[CoreStrategySlot::ToolPolicy],                                 // 116
    &[CoreStrategySlot::ToolPolicy],                                 // 117
    &[CoreStrategySlot::Router, CoreStrategySlot::ToolPolicy],       // 118
    &[CoreStrategySlot::ToolPolicy],                                 // 119
    &[CoreStrategySlot::ToolPolicy],                                 // 120
    &[CoreStrategySlot::Context, CoreStrategySlot::ToolPolicy],      // 121
    &[CoreStrategySlot::ToolPolicy],                                 // 122
    &[CoreStrategySlot::Verifier],                                   // 123
    &[CoreStrategySlot::Verifier],                                   // 124
    &[CoreStrategySlot::Verifier],                                   // 125
    &[CoreStrategySlot::Verifier],                                   // 126
    &[CoreStrategySlot::Verifier, CoreStrategySlot::Planner],        // 127
    &[CoreStrategySlot::Verifier],                                   // 128
    &[CoreStrategySlot::Verifier, CoreStrategySlot::ToolPolicy],     // 129
    &[CoreStrategySlot::Verifier],                                   // 130
    &[CoreStrategySlot::Verifier, CoreStrategySlot::Collaboration],  // 131
    &[CoreStrategySlot::Planner, CoreStrategySlot::Verifier],        // 132
    &[
        CoreStrategySlot::ModelRouter,
        CoreStrategySlot::Collaboration,
    ], // 133
    &[CoreStrategySlot::Planner, CoreStrategySlot::Collaboration],   // 134
    &[
        CoreStrategySlot::ToolPolicy,
        CoreStrategySlot::Collaboration,
    ], // 135
    &[CoreStrategySlot::Memory, CoreStrategySlot::Collaboration],    // 136
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::Collaboration], // 137
    &[CoreStrategySlot::Scheduler],                                  // 138
    &[CoreStrategySlot::Scheduler],                                  // 139
    &[CoreStrategySlot::Scheduler],                                  // 140
    &[CoreStrategySlot::Scheduler],                                  // 141
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::Collaboration], // 142
    &[
        CoreStrategySlot::Collaboration,
        CoreStrategySlot::ToolPolicy,
    ], // 143
    &[CoreStrategySlot::Collaboration, CoreStrategySlot::Verifier],  // 144
    &[CoreStrategySlot::Collaboration],                              // 145
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::Collaboration], // 146
    &[CoreStrategySlot::ToolPolicy],                                 // 147
    &[CoreStrategySlot::Context, CoreStrategySlot::ToolPolicy],      // 148
    &[CoreStrategySlot::ToolPolicy],                                 // 149
    &[CoreStrategySlot::ToolPolicy],                                 // 150
    &[CoreStrategySlot::ToolPolicy],                                 // 151
    &[CoreStrategySlot::Context, CoreStrategySlot::ToolPolicy],      // 152
    &[CoreStrategySlot::ToolPolicy],                                 // 153
    &[CoreStrategySlot::ToolPolicy, CoreStrategySlot::Context],      // 154
    &[CoreStrategySlot::ModelRouter],                                // 155
    &[CoreStrategySlot::ModelRouter],                                // 156
    &[CoreStrategySlot::Scheduler, CoreStrategySlot::ModelRouter],   // 157
    &[CoreStrategySlot::Context, CoreStrategySlot::ModelRouter],     // 158
    &[
        CoreStrategySlot::Collaboration,
        CoreStrategySlot::ToolPolicy,
    ], // 159
    &[CoreStrategySlot::Collaboration, CoreStrategySlot::Verifier],  // 160
];

const EXPECTED_PROVIDER_REQUIREMENTS: [ProviderRequirement; EXPECTED_FAMILY_COUNT] = [
    ProviderRequirement::AnyAdmittedRoute, // 1 provider
    ProviderRequirement::SelectedRoute,    // 2 model
    ProviderRequirement::AnyAdmittedRoute, // 3 base_url
    ProviderRequirement::SelectedRoute,    // 4 effort
    ProviderRequirement::None,             // 5 max_turns
    ProviderRequirement::None,             // 6 max_usd
    ProviderRequirement::None,             // 7 max_tokens
    ProviderRequirement::None,             // 8 max_wall_secs
    ProviderRequirement::None,             // 9 allow_code
    ProviderRequirement::None,             // 10 permission_mode
    ProviderRequirement::None,             // 11 permission_rules
    ProviderRequirement::None,             // 12 bypass_permissions
    ProviderRequirement::SelectedRoute,    // 13 compaction_trigger
    ProviderRequirement::None,             // 14 verify_command
    ProviderRequirement::None,             // 15 retry_backoff_base
    ProviderRequirement::None,             // 16 retry_backoff_cap
    ProviderRequirement::None,             // 17 retry_max_attempts
    ProviderRequirement::None,             // 18 egress_allow
    ProviderRequirement::SelectedRoute,    // 19 request_output_cap
    ProviderRequirement::SelectedRoute,    // 20 effort_reasoning_map
    ProviderRequirement::SelectedRoute,    // 21 thinking_map
    ProviderRequirement::None,             // 22 orchestration_map
    ProviderRequirement::SelectedRoute,    // 23 prompt_cache
    ProviderRequirement::None,             // 24 compaction_adaptive
    ProviderRequirement::None,             // 25 compaction_keep_recent
    ProviderRequirement::None,             // 26 token_estimator
    ProviderRequirement::SelectedRoute,    // 27 summary_profile
    ProviderRequirement::None,             // 28 compaction_failure
    ProviderRequirement::None,             // 29 instruction_discovery_render
    ProviderRequirement::None,             // 30 memory_enable
    ProviderRequirement::None,             // 31 memory_budgets
    ProviderRequirement::None,             // 32 bm25
    ProviderRequirement::None,             // 33 skill_listing_budget
    ProviderRequirement::None,             // 34 max_consecutive_tool_errors
    ProviderRequirement::None,             // 35 pure_overlap
    ProviderRequirement::None,             // 36 pure_concurrency
    ProviderRequirement::None,             // 37 failed_action_dedup
    ProviderRequirement::None,             // 38 pure_memo_cache
    ProviderRequirement::None,             // 39 shell_timeout_output
    ProviderRequirement::None,             // 40 read_file_limits
    ProviderRequirement::None,             // 41 list_dir_limits
    ProviderRequirement::None,             // 42 glob_limits
    ProviderRequirement::None,             // 43 grep_limits
    ProviderRequirement::None,             // 44 repo_map
    ProviderRequirement::None,             // 45 git_limits
    ProviderRequirement::None,             // 46 web_fetch_limits
    ProviderRequirement::None,             // 47 web_search_cap
    ProviderRequirement::None,             // 48 verifier_attempts
    ProviderRequirement::None,             // 49 verifier_feedback_tails
    ProviderRequirement::None,             // 50 verifier_timeout
    ProviderRequirement::None,             // 51 route_topology
    ProviderRequirement::SelectedRoute,    // 52 decomposition_profile
    ProviderRequirement::None,             // 53 fan_breadth
    ProviderRequirement::None,             // 54 admission
    ProviderRequirement::None,             // 55 writer_fan_turn_split
    ProviderRequirement::None,             // 56 worker_min_turns
    ProviderRequirement::None,             // 57 wall_split
    ProviderRequirement::None,             // 58 token_split
    ProviderRequirement::None,             // 59 fan_concurrency
    ProviderRequirement::None,             // 60 child_ceiling
    ProviderRequirement::None,             // 61 direct_child_allocation
    ProviderRequirement::SelectedRoute,    // 62 subagent_effort_inheritance
    ProviderRequirement::None,             // 63 report_budget
    ProviderRequirement::None,             // 64 join_reduce
    ProviderRequirement::None,             // 65 workflow_aggregate
    ProviderRequirement::None,             // 66 schema_retry_jitter
    ProviderRequirement::AnyAdmittedRoute, // 67 provider_connect_tls_timeout
    ProviderRequirement::SelectedRoute,    // 68 multimodal_input_admission_decode_envelope
    ProviderRequirement::None,             // 69 app_server_sq_eq_backpressure
    ProviderRequirement::AnyAdmittedRoute, // 70 provider_discovery_account_probe_cache_policy
    ProviderRequirement::None,             // 71 operator_prompt_stream
    ProviderRequirement::None,             // 72 builtin_prompt_corpus
    ProviderRequirement::None,             // 73 instruction_bundle
    ProviderRequirement::None,             // 74 memory_corpus
    ProviderRequirement::None,             // 75 skill_catalog
    ProviderRequirement::None,             // 76 agent_catalog
    ProviderRequirement::AnyAdmittedRoute, // 77 provider_model_capability_catalog
    ProviderRequirement::None,             // 78 mcp_topology_tool_catalog
    ProviderRequirement::None,             // 79 hooks_map
    ProviderRequirement::None,             // 80 workflow_graph
    ProviderRequirement::None,             // 81 tool_action_space
    ProviderRequirement::SelectedRoute,    // 82 rate_card_catalog
    ProviderRequirement::None,             // 83 router_lexicons
    ProviderRequirement::None,             // 84 environment_snapshot
    ProviderRequirement::None,             // 85 web_search_backend_catalog
    ProviderRequirement::AnyAdmittedRoute, // 86 model_fallback_chain
    ProviderRequirement::AnyAdmittedRoute, // 87 failover_eligible_error_taxonomy
    ProviderRequirement::AnyAdmittedRoute, // 88 route_quality_cost_latency_objective_weights
    ProviderRequirement::AnyAdmittedRoute, // 89 provider_health_circuit_breaker_state_policy
    ProviderRequirement::SelectedRoute,    // 90 hedged_request_policy
    ProviderRequirement::SelectedRoute,    // 91 provider_service_tier
    ProviderRequirement::SelectedRoute,    // 92 response_verbosity
    ProviderRequirement::AnyAdmittedRoute, // 93 role_specific_model_map
    ProviderRequirement::SelectedRoute,    // 94 provider_request_total_deadline
    ProviderRequirement::SelectedRoute,    // 95 stream_idle_watchdog
    ProviderRequirement::SelectedRoute,    // 96 context_window_override_reserve
    ProviderRequirement::None,             // 97 system_prefix_budget
    ProviderRequirement::None,             // 98 conversation_history_budget
    ProviderRequirement::None,             // 99 tool_result_history_budget
    ProviderRequirement::SelectedRoute,    // 100 multimodal_token_budget
    ProviderRequirement::None,             // 101 auto_compaction_enable
    ProviderRequirement::None,             // 102 compaction_cooldown_hysteresis
    ProviderRequirement::None,             // 103 multi_stage_summary_topology
    ProviderRequirement::None,             // 104 summary_consistency_coverage_check
    ProviderRequirement::None,             // 105 hybrid_retrieval_fusion_weights
    ProviderRequirement::None,             // 106 retrieval_recency_decay
    ProviderRequirement::None,             // 107 context_novelty_dedup_threshold
    ProviderRequirement::None,             // 108 persistent_pty_backend
    ProviderRequirement::None,             // 109 concurrent_background_job_cap
    ProviderRequirement::None,             // 110 job_idle_stall_timeout
    ProviderRequirement::None,             // 111 interactive_stdin_wait_policy
    ProviderRequirement::None,             // 112 process_signal_kill_escalation
    ProviderRequirement::None,             // 113 process_cwd_continuity
    ProviderRequirement::None,             // 114 child_process_environment_reuse
    ProviderRequirement::None,             // 115 effecting_tool_concurrency
    ProviderRequirement::None,             // 116 write_set_conflict_admission
    ProviderRequirement::None,             // 117 tool_output_spill_to_disk_policy
    ProviderRequirement::SelectedRoute,    // 118 binary_media_inspection_routing
    ProviderRequirement::None,             // 119 lsp_server_language_selection
    ProviderRequirement::None,             // 120 lsp_timeout_restart_policy
    ProviderRequirement::None,             // 121 lsp_result_context_budget
    ProviderRequirement::None,             // 122 tool_result_cache_ttl
    ProviderRequirement::None,             // 123 test_selection_strategy
    ProviderRequirement::None,             // 124 incremental_versus_full_verification
    ProviderRequirement::None,             // 125 flaky_test_detection_quarantine
    ProviderRequirement::None,             // 126 failure_classification_taxonomy
    ProviderRequirement::None,             // 127 retry_eligibility_policy
    ProviderRequirement::None,             // 128 rollback_on_verification_failure
    ProviderRequirement::None,             // 129 workspace_checkpoint_cadence
    ProviderRequirement::None,             // 130 selective_restore_scope
    ProviderRequirement::None,             // 131 verification_quorum_consensus
    ProviderRequirement::None,             // 132 recovery_escalation_policy
    ProviderRequirement::SelectedRoute,    // 133 per_agent_model
    ProviderRequirement::SelectedRoute,    // 134 per_agent_effort_thinking
    ProviderRequirement::None,             // 135 per_agent_tool_profile
    ProviderRequirement::None,             // 136 per_agent_memory_scope
    ProviderRequirement::None,             // 137 spawn_depth_control
    ProviderRequirement::None,             // 138 per_session_spawn_cap
    ProviderRequirement::None,             // 139 task_priority_scheduling
    ProviderRequirement::None,             // 140 speculative_sibling_count
    ProviderRequirement::None,             // 141 speculative_sibling_cancellation
    ProviderRequirement::None,             // 142 early_stop_quorum_policy
    ProviderRequirement::None,             // 143 writer_worktree_isolation_mode
    ProviderRequirement::None,             // 144 merge_conflict_arbitration
    ProviderRequirement::None,             // 145 inter_agent_messaging_topology
    ProviderRequirement::None,             // 146 task_retry_reassignment_policy
    ProviderRequirement::None,             // 147 mcp_transport_selection
    ProviderRequirement::None,             // 148 deferred_discovery_threshold
    ProviderRequirement::None,             // 149 mcp_reconnect_backoff
    ProviderRequirement::None,             // 150 per_server_startup_deadline
    ProviderRequirement::None,             // 151 per_tool_mcp_deadline
    ProviderRequirement::None,             // 152 mcp_result_cap_spill_policy
    ProviderRequirement::None,             // 153 oauth_auth_lifecycle_policy
    ProviderRequirement::None,             // 154 resource_prompt_plugin_capability_exposure
    ProviderRequirement::SelectedRoute,    // 155 request_compression_policy
    ProviderRequirement::AnyAdmittedRoute, // 156 http_pool_keepalive_idle_policy
    ProviderRequirement::SelectedRoute,    // 157 rate_limit_aware_admission
    ProviderRequirement::SelectedRoute,    // 158 prompt_cache_ttl_breakpoint_strategy
    ProviderRequirement::None,             // 159 session_isolation_profile
    ProviderRequirement::None,             // 160 replay_divergence_detection_policy
];

fn family(id: &str) -> &'static core_tunables::Family {
    families()
        .iter()
        .find(|family| family.id == id)
        .unwrap_or_else(|| panic!("missing family {id}"))
}

fn integer_default(id: &str) -> i64 {
    match family(id).default.value {
        Some(TunableValue::Integer { value }) => value,
        other => panic!("{id} does not have an integer default: {other:?}"),
    }
}

fn object_default(id: &str) -> &'static [TunableValueField] {
    match family(id).default.value {
        Some(TunableValue::Object { fields }) => fields,
        other => panic!("{id} does not have an object default: {other:?}"),
    }
}

fn object_integer(id: &str, name: &str) -> i64 {
    let value = object_default(id)
        .iter()
        .find(|field| field.name == name)
        .unwrap_or_else(|| panic!("{id} has no default field {name}"))
        .value;
    match value {
        TunableValue::Integer { value } => value,
        other => panic!("{id}.{name} is not an integer: {other:?}"),
    }
}

#[test]
fn exact_160_entry_contract_is_pinned_per_ordinal() {
    validate_registry().unwrap();
    assert_eq!(families().len(), EXPECTED_FAMILY_COUNT);
    for (index, family) in families().iter().enumerate() {
        let ordinal = index + 1;
        assert_eq!(usize::from(family.ordinal), ordinal);
        assert_eq!(family.id, EXPECTED_IDS[index], "ordinal {ordinal}");
        assert_eq!(
            family.semantic_key, EXPECTED_IDS[index],
            "ordinal {ordinal}"
        );
        assert_eq!(
            (
                family.benchmark_relevance.swe_bench_pro,
                family.benchmark_relevance.terminal_bench_2_1,
            ),
            EXPECTED_RELEVANCE[index],
            "{}",
            family.id
        );
        assert_eq!(
            family.strategy_slots, EXPECTED_SLOTS[index],
            "{}",
            family.id
        );
        assert_eq!(
            family.requirements.provider, EXPECTED_PROVIDER_REQUIREMENTS[index],
            "{}",
            family.id
        );
        assert_eq!(
            family.value_schema.schema_id,
            format!("core://tunables/families/{}/value-v1", family.id)
        );
    }
}

#[test]
fn relevance_is_formal_and_independent_from_causal_path() {
    let cost = family("max_usd");
    let permissions = family("permission_mode");
    assert_eq!(
        cost.benchmark_relevance.causal_path,
        permissions.benchmark_relevance.causal_path
    );
    assert_ne!(
        (
            cost.benchmark_relevance.swe_bench_pro,
            cost.benchmark_relevance.terminal_bench_2_1,
        ),
        (
            permissions.benchmark_relevance.swe_bench_pro,
            permissions.benchmark_relevance.terminal_bench_2_1,
        )
    );
    assert_eq!(
        cost.benchmark_relevance.causal_path.swe_bench_pro,
        CausalPath::Conditional
    );
    let rationales = families()
        .iter()
        .map(|family| family.benchmark_relevance.rationale)
        .collect::<BTreeSet<_>>();
    assert_eq!(rationales.len(), EXPECTED_FAMILY_COUNT);
}

#[test]
fn defaults_resolvers_and_provenance_match_production_truth() {
    let provider = family("provider");
    assert_eq!(provider.default.kind, DefaultKind::Literal);
    assert_eq!(
        provider.default.value,
        Some(TunableValue::Enum { value: "glm" })
    );
    assert_eq!(
        provider
            .source
            .bindings
            .iter()
            .map(|binding| binding.kind)
            .collect::<Vec<_>>(),
        vec![
            SourceKind::Cli,
            SourceKind::Environment,
            SourceKind::UserConfig,
            SourceKind::Builtin,
        ]
    );

    let model = family("model");
    assert_eq!(model.default.kind, DefaultKind::Dynamic);
    assert_eq!(
        model.default.resolver,
        DefaultResolver::ModelMetadata {
            field: "default_model"
        }
    );
    assert_eq!(
        model.default.value,
        Some(TunableValue::Enum { value: "glm-5.2" })
    );

    assert_eq!(integer_default("max_turns"), 40);
    assert_eq!(integer_default("max_wall_secs"), 1_800);
    for (id, expected, environment) in [
        ("retry_backoff_base", 500, "CORE_RETRY_BASE_MS"),
        ("retry_backoff_cap", 30_000, "CORE_RETRY_CAP_MS"),
        ("retry_max_attempts", 6, "CORE_RETRY_MAX_ATTEMPTS"),
    ] {
        let family = family(id);
        assert_eq!(family.default.kind, DefaultKind::Literal);
        assert_eq!(integer_default(id), expected);
        assert_eq!(
            family
                .source
                .bindings
                .iter()
                .map(|binding| binding.kind)
                .collect::<Vec<_>>(),
            vec![
                SourceKind::Environment,
                SourceKind::UserConfig,
                SourceKind::Builtin,
            ]
        );
        assert_eq!(family.source.bindings[0].locator, environment);
    }

    assert_eq!(integer_default("provider_connect_tls_timeout"), 30);
    assert_eq!(integer_default("stream_idle_watchdog"), 120_000);
    assert_eq!(
        object_integer("http_pool_keepalive_idle_policy", "pool_idle_seconds"),
        300
    );
    assert_eq!(
        object_integer("http_pool_keepalive_idle_policy", "tcp_keepalive_seconds"),
        30
    );
    assert_eq!(
        object_integer(
            "provider_discovery_account_probe_cache_policy",
            "eager_budget_milliseconds"
        ),
        1_500
    );
    assert_eq!(
        object_integer(
            "provider_discovery_account_probe_cache_policy",
            "positive_ttl_seconds"
        ),
        900
    );

    let prompt = family("operator_prompt_stream");
    assert_eq!(
        prompt.default.requirement,
        DefaultValueRequirement::Required
    );
    assert!(matches!(
        prompt.default.resolver,
        DefaultResolver::Operator { .. }
    ));
    assert_eq!(prompt.source.bindings.len(), 1);
    assert_eq!(prompt.source.bindings[0].kind, SourceKind::OperatorInput);
    assert_eq!(prompt.source.bindings[0].trust, SourceTrust::Operator);

    let prompt_cache = family("prompt_cache");
    assert_eq!(
        prompt_cache.implementation_status,
        ImplementationStatus::Full
    );
    assert_eq!(prompt_cache.default.kind, DefaultKind::Literal);
    assert_eq!(
        prompt_cache.default.value,
        Some(TunableValue::Boolean { value: true })
    );
    assert_eq!(prompt_cache.value_schema.kind, ValueKind::Bool);
    assert!(matches!(
        prompt_cache.value_schema.domain,
        StructuredValueDomain::Scalar {
            domain: ScalarDomain::Boolean
        }
    ));
    assert_eq!(
        prompt_cache
            .source
            .bindings
            .iter()
            .map(|binding| binding.kind)
            .collect::<Vec<_>>(),
        vec![SourceKind::RustBuilder, SourceKind::Builtin]
    );
    assert_eq!(
        prompt_cache.source.bindings[0].locator,
        "core_provider::ProviderInstance::with_prompt_cache"
    );
    assert!(prompt_cache.value_schema.rules.iter().any(|rule| matches!(
        rule,
        CrossFieldRule::ExternalCeiling {
            field: "$",
            ceiling: ExternalCeiling::ProviderCapability,
        }
    )));
    let prompt_cache_schema = serde_json::to_string(&prompt_cache.value_schema).unwrap();
    assert!(!prompt_cache_schema.contains("ttl"));
    assert!(!prompt_cache_schema.contains("breakpoint"));

    let prompt_cache_strategy = family("prompt_cache_ttl_breakpoint_strategy");
    assert_eq!(
        prompt_cache_strategy.implementation_status,
        ImplementationStatus::Missing
    );
    assert!(matches!(
        prompt_cache_strategy.activation.predicate,
        ActivationPredicate::Unavailable
    ));
    assert_eq!(prompt_cache_strategy.source.bindings.len(), 1);
    assert_eq!(
        prompt_cache_strategy.source.bindings[0].kind,
        SourceKind::Registry
    );
    assert_eq!(prompt_cache_strategy.default.kind, DefaultKind::Dynamic);
    assert_eq!(
        prompt_cache_strategy.default.requirement,
        DefaultValueRequirement::Required
    );
    assert!(matches!(
        prompt_cache_strategy.default.resolver,
        DefaultResolver::Operator { .. }
    ));
    let prompt_cache_strategy_schema =
        serde_json::to_string(&prompt_cache_strategy.value_schema).unwrap();
    assert!(prompt_cache_strategy_schema.contains("ttl_seconds"));
    assert!(prompt_cache_strategy_schema.contains("breakpoint"));

    assert_eq!(
        family("token_estimator").requirements.provider,
        ProviderRequirement::None
    );
    assert_eq!(
        family("oauth_auth_lifecycle_policy").requirements.provider,
        ProviderRequirement::None
    );
    assert!(matches!(
        family("oauth_auth_lifecycle_policy").default.resolver,
        DefaultResolver::Transport { .. }
    ));
    assert!(
        !family("prompt_cache_ttl_breakpoint_strategy")
            .source
            .bindings
            .iter()
            .any(|binding| binding.trust == SourceTrust::ProviderAttested)
    );
}

#[test]
fn activation_source_and_default_invariants_hold_for_every_entry() {
    for family in families() {
        assert!(!family.source.bindings.is_empty(), "{}", family.id);
        let mut source_kinds = BTreeSet::new();
        for binding in family.source.bindings {
            assert!(source_kinds.insert(binding.kind), "{}", family.id);
            assert!(!binding.locator.is_empty(), "{}", family.id);
            let expected = match binding.kind {
                SourceKind::Cli
                | SourceKind::OperatorInput
                | SourceKind::RustBuilder
                | SourceKind::UserConfig
                | SourceKind::Environment => SourceTrust::Operator,
                SourceKind::ProjectConfig | SourceKind::Catalog => SourceTrust::Repository,
                SourceKind::Builtin | SourceKind::DerivedPolicy => SourceTrust::Builtin,
                SourceKind::RuntimeObservation => SourceTrust::RuntimeObservation,
                SourceKind::ExternalProvider => SourceTrust::ProviderAttested,
                SourceKind::GovernedBundle => SourceTrust::GovernedBundle,
                SourceKind::Registry => SourceTrust::RegistryDeclaration,
            };
            assert_eq!(binding.trust, expected, "{}", family.id);
        }
        match family.implementation_status {
            ImplementationStatus::Missing => {
                assert!(matches!(
                    family.activation.predicate,
                    ActivationPredicate::Unavailable
                ));
                assert_eq!(
                    family.activation.inactive_reason,
                    Some(InactiveReason::NotImplemented)
                );
            }
            ImplementationStatus::Partial => {
                assert!(matches!(
                    family.activation.predicate,
                    ActivationPredicate::RuntimeDerived { .. }
                ));
                assert_eq!(
                    family.activation.inactive_reason,
                    Some(InactiveReason::GroupedOrIncompleteSeam)
                );
            }
            ImplementationStatus::Full | ImplementationStatus::FixedHidden => {
                assert!(!matches!(
                    family.activation.predicate,
                    ActivationPredicate::Unavailable
                ));
            }
        }
        match family.default.kind {
            DefaultKind::Literal => {
                assert_eq!(family.default.resolver, DefaultResolver::Literal);
                assert!(family.default.value.is_some(), "{}", family.id);
            }
            DefaultKind::Derived => {
                assert!(!matches!(
                    family.default.resolver,
                    DefaultResolver::Literal | DefaultResolver::Operator { .. }
                ));
            }
            DefaultKind::Dynamic => {
                assert!(!matches!(
                    family.default.resolver,
                    DefaultResolver::Literal | DefaultResolver::GovernedCatalog { .. }
                ));
            }
        }
    }
}

#[test]
fn schema_ast_and_catalog_ids_are_closed_bounded_and_unique() {
    let schema_ids = families()
        .iter()
        .map(|family| family.value_schema.schema_id)
        .collect::<BTreeSet<_>>();
    assert_eq!(schema_ids.len(), EXPECTED_FAMILY_COUNT);
    let scalar_catalog_ids = SCALAR_CATALOGS
        .iter()
        .map(|catalog| catalog.id)
        .collect::<BTreeSet<_>>();
    assert_eq!(scalar_catalog_ids.len(), SCALAR_CATALOGS.len());
    assert_eq!(SCALAR_CATALOGS.len(), 9);

    for family in families() {
        match family.value_schema.domain {
            StructuredValueDomain::Scalar { .. } => assert!(matches!(
                family.value_schema.kind,
                ValueKind::Bool
                    | ValueKind::Enum
                    | ValueKind::Count
                    | ValueKind::Duration
                    | ValueKind::Bytes
                    | ValueKind::Ratio
                    | ValueKind::Decimal
                    | ValueKind::String
            )),
            StructuredValueDomain::List { max_items, .. } => {
                assert_eq!(family.value_schema.kind, ValueKind::List);
                assert!(max_items > 0);
            }
            StructuredValueDomain::Map { max_entries, .. } => {
                assert_eq!(family.value_schema.kind, ValueKind::Map);
                assert!(max_entries > 0);
            }
            StructuredValueDomain::Object {
                fields,
                additional_fields,
            } => {
                assert_eq!(family.value_schema.kind, ValueKind::Policy);
                assert!(!additional_fields);
                assert!(!fields.is_empty());
            }
            StructuredValueDomain::Catalog {
                catalog_id,
                max_entries,
                entry_fields,
                ..
            } => {
                assert_eq!(family.value_schema.kind, ValueKind::Catalog);
                assert!(catalog_id.ends_with("-v1"));
                assert!(max_entries > 0);
                assert!(!entry_fields.is_empty());
            }
        }
    }
}

#[test]
fn corrections_remove_alias_and_cover_multi_slot_effects() {
    assert!(!families().iter().any(|family| {
        family.id == "workflow_spawn_cap"
            || family.aliases.contains(&"workflow_spawn_cap")
            || family.id == "delegation_depth"
            || family.aliases.contains(&"delegation_depth")
    }));
    for id in [
        "retry_backoff_base",
        "pure_overlap",
        "fan_concurrency",
        "agent_catalog",
        "role_specific_model_map",
        "verification_quorum_consensus",
    ] {
        assert!(family(id).strategy_slots.len() >= 2, "{id}");
    }
    assert_eq!(
        family("provider_connect_tls_timeout").requirements.provider,
        ProviderRequirement::AnyAdmittedRoute
    );
}

#[test]
fn status_shape_and_semantic_digest_contract_are_exact() {
    for (status, expected) in [
        (ImplementationStatus::Full, 28),
        (ImplementationStatus::Partial, 52),
        (ImplementationStatus::Missing, 27),
        (ImplementationStatus::FixedHidden, 53),
    ] {
        assert_eq!(
            families()
                .iter()
                .filter(|family| family.implementation_status == status)
                .count(),
            expected,
            "{status:?}"
        );
    }

    for family in families() {
        let digest = family_semantic_digest(family).unwrap();
        assert_eq!(digest.algorithm, "sha256");
        assert_eq!(digest.value.len(), 64);
    }

    let mut changed = *family("provider");
    changed.default.value = Some(TunableValue::Enum { value: "anthropic" });
    assert_ne!(
        family_semantic_digest(family("provider")).unwrap(),
        family_semantic_digest(&changed).unwrap()
    );

    let digest = registry_digest().unwrap();
    assert_eq!(digest.value, REGISTRY_DIGEST_SHA256);
    assert_eq!(digest.value.len(), 64);
}

#[test]
fn canonical_artifact_is_deterministic_and_self_authenticating() {
    let payload = canonical_payload_json().unwrap();
    assert_eq!(payload, canonical_payload_json().unwrap());
    let artifact = canonical_artifact().unwrap();
    assert_eq!(artifact.digest.value, hex::encode(Sha256::digest(&payload)));
    assert_eq!(artifact.payload.family_count, EXPECTED_FAMILY_COUNT);
    assert_eq!(artifact.payload.families.len(), EXPECTED_FAMILY_COUNT);
    assert_eq!(artifact.payload.scalar_catalogs, SCALAR_CATALOGS);
    let pretty = canonical_artifact_json().unwrap();
    assert_eq!(pretty.last(), Some(&b'\n'));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&pretty).unwrap()["digest"]["value"],
        REGISTRY_DIGEST_SHA256
    );
}
