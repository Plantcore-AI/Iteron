use crate::DefaultSpec;

pub(super) const DEFAULTS: [DefaultSpec; 75] = [
    literal_default!(list_value!()), // 86 model_fallback_chain
    literal_default!(list_value!(
        object_value!(
            "error_class" => text_value!("provider.connect_failed"),
            "eligible" => boolean_value!(true),
            "dispatch_state" => enum_value!("pre_dispatch"),
            "version" => text_value!("1.0.0"),
        ),
        object_value!(
            "error_class" => text_value!("provider.rate_limited"),
            "eligible" => boolean_value!(true),
            "dispatch_state" => enum_value!("post_dispatch"),
            "version" => text_value!("1.0.0"),
        ),
        object_value!(
            "error_class" => text_value!("provider.overloaded"),
            "eligible" => boolean_value!(true),
            "dispatch_state" => enum_value!("post_dispatch"),
            "version" => text_value!("1.0.0"),
        ),
        object_value!(
            "error_class" => text_value!("model.unavailable"),
            "eligible" => boolean_value!(true),
            "dispatch_state" => enum_value!("pre_dispatch"),
            "version" => text_value!("1.0.0"),
        ),
    )), // 87 failover_eligible_error_taxonomy
    derived_default!("route_quality_cost_latency_objective_weights"), // 88
    observation_default!("provider.route_health"), // 89
    literal_default!(object_value!(
        "enabled" => boolean_value!(false),
        "delay_milliseconds" => integer_value!(0),
        "max_duplicates" => integer_value!(0),
        "idempotent_only" => boolean_value!(true),
    )), // 90 hedged_request_policy
    provider_default!("service_tier"), // 91 provider_service_tier
    model_default!("response_verbosity"), // 92 response_verbosity
    derived_default!("role_specific_model_map"), // 93
    derived_default_with_value!("provider_request_total_deadline", integer_value!(300_000)), // 94
    derived_default_with_value!("stream_idle_watchdog", integer_value!(60_000)), // 95 stream_idle_watchdog
    model_default!("context_window_and_output_reserve"),                         // 96
    derived_default!("system_prefix_budget"),                                    // 97
    derived_default!("conversation_history_budget"),                             // 98
    derived_default!("tool_result_history_budget"),                              // 99
    // The local ContextMaterializationPolicy owns the executable budget. Provider multimodal
    // capability is an upper clamp (exact zero for text-only routes), not the default resolver.
    derived_default!("multimodal_token_budget"), // 100
    literal_default!(boolean_value!(true)),      // 101 auto_compaction_enable
    derived_default!("compaction_cooldown_hysteresis"), // 102
    literal_default!(enum_value!("single_stage")), // 103
    literal_default!(boolean_value!(true)),      // 104
    derived_default_with_value!(
        "hybrid_retrieval_fusion_weights",
        map_value!("lexical" => decimal_value!(1, 0))
    ), // 105
    derived_default_with_value!("retrieval_recency_decay", decimal_value!(1, 0)), // 106
    derived_default_with_value!("context_novelty_dedup_threshold", decimal_value!(1, 0)), // 107
    dynamic_observation_default!("process.backend"), // 108 persistent_pty_backend
    dynamic_observation_default!("process.background_job_cap"), // 109 concurrent_background_job_cap
    dynamic_observation_default!("process.idle_stall_timeout"), // 110
    dynamic_observation_default!("interactive_process.stdin_wait"), // 111
    literal_default!(enum_value!("term_grace_kill_reap")), // 112
    derived_default!("process_cwd_continuity"),  // 113 process_cwd_continuity
    derived_default!("child_process_environment_reuse"), // 114 child_process_environment_reuse
    // Mirrors the fixed physical scheduler owner. Pure and effecting calls share this outer
    // ceiling; write-set admission below independently narrows effecting batches.
    derived_default_with_value!("effecting_tool_concurrency", integer_value!(16)), // 115 effecting_tool_concurrency
    literal_default!(object_value!(
        "declared_set_required" => boolean_value!(true),
        "overlap" => enum_value!("reject"),
        "unknown_set" => enum_value!("reject"),
    )), // 116 write_set_conflict_admission
    derived_default!("tool_output_spill_to_disk_policy"),                          // 117
    // The local BinaryMediaInspectionPolicy owns routing before provider dispatch.
    derived_default!("binary_media_inspection_routing"), // 118
    dynamic_observation_default!("workspace.languages_and_servers"), // 119
    dynamic_observation_default!("lsp.timeout_restart_policy"), // 120
    derived_default!("lsp_result_context_budget"),       // 121
    derived_default!("tool_result_cache_ttl"),           // 122
    derived_default!("test_selection_strategy"),         // 123
    derived_default_with_value!(
        "incremental_versus_full_verification",
        enum_value!("impacted")
    ), // 124
    derived_default_with_value!(
        "flaky_test_detection_quarantine",
        object_value!(
            "repeat_count" => integer_value!(2),
            "minimum_disagreements" => integer_value!(1),
            "quarantine_seconds" => integer_value!(300),
            "report_disagreement" => boolean_value!(true),
        )
    ), // 125 flaky_test_detection_quarantine
    catalog_default!("failure_classification_taxonomy"), // 126
    derived_default!("retry_eligibility_policy"),        // 127
    literal_default!(enum_value!("off")),                // 128
    literal_default!(object_value!(
        "turn_boundary" => boolean_value!(true),
            "before_verification" => boolean_value!(true),
        "before_drain" => boolean_value!(true),
        "minimum_turn_interval" => integer_value!(1),
    )), // 129 workspace_checkpoint_cadence
    literal_default!(object_value!(
        "mode" => enum_value!("workspace"),
    )), // 130 selective_restore_scope
    derived_default_with_value!(
        "verification_quorum_consensus",
        object_value!(
            "verifiers" => integer_value!(1),
            "required_agreement" => integer_value!(1),
            "strong_veto" => boolean_value!(true),
        )
    ), // 131 verification_quorum_consensus
    literal_default!(enum_value!("retry_replan_stop")),  // 132
    derived_default!("per_agent_model"),                 // 133
    derived_default!("per_agent_effort_thinking"),       // 134
    derived_default!("per_agent_tool_profile"),          // 135
    literal_default!(object_value!(
        "mode" => enum_value!("isolated"),
        "inherit_parent" => boolean_value!(false),
    )), // 136 per_agent_memory_scope
    literal_default!(integer_value!(1)),                 // 137 spawn_depth_control
    derived_default!("per_session_spawn_cap"),           // 138
    literal_default!(object_value!(
        "priority_levels" => integer_value!(1),
        "tie_break" => enum_value!("fifo"),
        "dependency_ready_only" => boolean_value!(true),
    )), // 139 task_priority_scheduling
    derived_default_with_value!("speculative_sibling_count", integer_value!(2)), // 140 speculative_sibling_count
    derived_default!("speculative_sibling_cancellation"),                        // 141
    derived_default_with_value!(
        "early_stop_quorum_policy",
        object_value!(
            "minimum_evidence" => integer_value!(1),
            "required_roles" => integer_value!(0),
            "strong_veto" => boolean_value!(true),
        )
    ), // 142 early_stop_quorum_policy
    literal_default!(boolean_value!(true)), // 143 writer_worktree_isolation_mode
    derived_default!("merge_conflict_arbitration"), // 144
    literal_default!(enum_value!("parent_mediated")), // 145
    derived_default!("task_retry_reassignment_policy"), // 146
    literal_default!(list_value!(enum_value!("stdio"))), // 147 mcp_transport_selection
    derived_default_with_value!("deferred_discovery_threshold", integer_value!(4)), // 148 deferred_discovery_threshold
    derived_default!("mcp_reconnect_backoff"),                                      // 149
    derived_default!("per_server_startup_deadline"),                                // 150
    derived_default!("per_tool_mcp_deadline"),                                      // 151
    derived_default_with_value!(
        "mcp_result_cap_spill_policy",
        object_value!(
            "visible_max_bytes" => integer_value!(1_048_576),
            "spill_max_bytes" => integer_value!(4_194_304),
            "cleanup" => enum_value!("session_end"),
            "private_storage" => boolean_value!(true),
        )
    ), // 152 mcp_result_cap_spill_policy
    transport_default!("oauth_lifecycle"),                                          // 153
    literal_default!(object_value!(
        "resource_discovery" => enum_value!("disabled"),
        "prompt_discovery" => enum_value!("disabled"),
        "resource_tool_ids" => list_value!(),
        "prompt_tool_ids" => list_value!(),
        "plugin_binding_ids" => list_value!(),
        "server_binding_ids" => list_value!(),
        "max_visible_bytes" => integer_value!(0),
    )), // 154 resource_prompt_plugin_capability_exposure
    provider_default!("request_compression"),                                       // 155
    derived_default_with_value!(
        "http_pool_keepalive_idle_policy",
        object_value!(
            "pool_idle_seconds" => integer_value!(300),
            "tcp_keepalive_seconds" => integer_value!(30),
            "connection_reuse" => boolean_value!(true),
        )
    ), // 156 http_pool_keepalive_idle_policy
    dynamic_observation_default_with_value!(
        "provider.rate_limit_snapshot",
        object_value!(
            "minimum_remaining_requests" => integer_value!(0),
            "minimum_remaining_tokens" => integer_value!(0),
            "reset_wait_max_seconds" => integer_value!(0),
            "unknown_quota" => enum_value!("conservative"),
        )
    ), // 157 rate_limit_aware_admission
    provider_default!("prompt_cache_ttl_breakpoint_strategy"),                      // 158
    derived_default_with_value!("session_isolation_profile", enum_value!("hermetic")), // 159
    literal_default!(object_value!(
        "verify_hash_chain" => boolean_value!(true),
        "verify_identity_scope" => boolean_value!(true),
        "verify_effect_terminals" => boolean_value!(true),
        "on_divergence" => enum_value!("fail_closed"),
    )), // 160 replay_divergence_detection_policy
];
