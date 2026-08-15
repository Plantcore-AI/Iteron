use crate::DefaultSpec;

pub(super) const DEFAULTS: [DefaultSpec; 85] = [
    literal_default!(enum_value!("glm")), // 1 provider
    model_default_with_value!("default_model", enum_value!("glm-5.2")), // 2 model
    derived_default!("base_url"),         // 3 base_url
    literal_default!(enum_value!("medium")), // 4 effort
    literal_default!(integer_value!(600)), // 5 max_turns
    operator_default!("max_usd"),         // 6 max_usd
    operator_default!("max_tokens"),      // 7 max_tokens
    literal_default!(integer_value!(14_400)), // 8 max_wall_secs
    literal_default!(boolean_value!(true)), // 9 allow_code
    literal_default!(enum_value!("default")), // 10 permission_mode
    derived_default!("permission_rules"), // 11 permission_rules
    literal_default!(boolean_value!(true)), // 12 bypass_permissions
    derived_default_with_value!(
        "compaction_trigger",
        object_value!(
            "mode" => enum_value!("adaptive"),
            "usable_window_ratio" => decimal_value!(1, 0),
            "fallback_trigger_tokens" => integer_value!(120_000),
            "output_reserve_tokens" => integer_value!(8_192),
        )
    ), // 13 compaction_trigger
    operator_default!("verify_command"),  // 14 verify_command
    literal_default!(integer_value!(500)), // 15 retry_backoff_base
    literal_default!(integer_value!(30_000)), // 16 retry_backoff_cap
    literal_default!(integer_value!(6)),  // 17 retry_max_attempts
    literal_default!(list_value!()),      // 18 egress_allow
    model_default_with_value!("max_output_tokens", integer_value!(8_192)), // 19 request_output_cap
    derived_default!("effort_reasoning_map"), // 20 effort_reasoning_map
    derived_default!("thinking_map"),     // 21 thinking_map
    derived_default!("orchestration_map"), // 22 orchestration_map
    literal_default!(boolean_value!(true)), // 23 prompt_cache
    derived_default_with_value!(
        "compaction_adaptive",
        object_value!(
            "usable_window_ratio" => decimal_value!(1, 0),
            "keep_recent_messages" => integer_value!(0),
            "output_reserve_tokens" => integer_value!(8_192),
        )
    ), // 24 compaction_adaptive
    derived_default_with_value!("compaction_keep_recent", integer_value!(0)), // 25 compaction_keep_recent
    derived_default!("token_estimator"),                                      // 26 token_estimator
    derived_default!("summary_profile"),                                      // 27 summary_profile
    derived_default!("compaction_failure"), // 28 compaction_failure
    derived_default!("instruction_discovery_render"), // 29 instruction_discovery_render
    literal_default!(boolean_value!(true)), // 30 memory_enable
    derived_default!("memory_budgets"),     // 31 memory_budgets
    derived_default!("bm25"),               // 32 bm25
    derived_default!("skill_listing_budget"), // 33 skill_listing_budget
    derived_default_with_value!("max_consecutive_tool_errors", integer_value!(25)), // 34 max_consecutive_tool_errors
    derived_default!("pure_overlap"),        // 35 pure_overlap
    derived_default!("pure_concurrency"),    // 36 pure_concurrency
    derived_default!("failed_action_dedup"), // 37 failed_action_dedup
    derived_default!("pure_memo_cache"),     // 38 pure_memo_cache
    literal_default!(object_value!(
        "timeout_seconds" => integer_value!(120),
        "stdout_max_bytes" => integer_value!(8_388_608),
        "stderr_max_bytes" => integer_value!(8_388_608),
    )), // 39 shell_timeout_output
    derived_default!("read_file_limits"),    // 40 read_file_limits
    derived_default!("list_dir_limits"),     // 41 list_dir_limits
    derived_default!("glob_limits"),         // 42 glob_limits
    derived_default!("grep_limits"),         // 43 grep_limits
    derived_default!("repo_map"),            // 44 repo_map
    derived_default!("git_limits"),          // 45 git_limits
    derived_default!("web_fetch_limits"),    // 46 web_fetch_limits
    derived_default!("web_search_cap"),      // 47 web_search_cap
    derived_default!("verifier_attempts"),   // 48 verifier_attempts
    derived_default!("verifier_feedback_tails"), // 49 verifier_feedback_tails
    derived_default!("verifier_timeout"),    // 50 verifier_timeout
    derived_default!("route_topology"),      // 51 route_topology
    derived_default!("decomposition_profile"), // 52 decomposition_profile
    derived_default!("fan_breadth"),         // 53 fan_breadth
    derived_default!("admission"),           // 54 admission
    derived_default!("writer_fan_turn_split"), // 55 writer_fan_turn_split
    derived_default!("worker_min_turns"),    // 56 worker_min_turns
    derived_default!("wall_split"),          // 57 wall_split
    derived_default!("token_split"),         // 58 token_split
    derived_default!("fan_concurrency"),     // 59 fan_concurrency
    derived_default!("child_ceiling"),       // 60 child_ceiling
    derived_default!("direct_child_allocation"), // 61 direct_child_allocation
    derived_default!("subagent_effort_inheritance"), // 62 subagent_effort_inheritance
    derived_default!("report_budget"),       // 63 report_budget
    derived_default!("join_reduce"),         // 64 join_reduce
    derived_default!("workflow_aggregate"),  // 65 workflow_aggregate
    derived_default!("schema_retry_jitter"), // 66 schema_retry_jitter
    literal_default!(integer_value!(10)),    // 67 provider_connect_tls_timeout
    literal_default!(object_value!(
        "max_images" => integer_value!(8),
        "per_image_raw_bytes" => integer_value!(6_291_456),
        "aggregate_raw_bytes" => integer_value!(25_165_824),
        "max_dimension" => integer_value!(8_192),
        "max_frames" => integer_value!(256),
    )), // 68 multimodal_input_admission_decode_envelope
    literal_default!(object_value!(
        "submission_entries" => integer_value!(256),
        "submission_bytes" => integer_value!(34_866_176),
        "event_entries" => integer_value!(1_024),
        "cosmetic_overflow" => enum_value!("coalesce"),
        "authoritative_overflow" => enum_value!("wait"),
    )), // 69 app_server_sq_eq_backpressure
    literal_default!(object_value!(
        "eager_budget_milliseconds" => integer_value!(0),
        "positive_ttl_seconds" => integer_value!(900),
        "failure_backoff_base_seconds" => integer_value!(60),
        "failure_backoff_cap_seconds" => integer_value!(86_400),
    )), // 70 provider_discovery_account_probe_cache_policy
    operator_default!("operator_prompt_stream"), // 71 operator_prompt_stream
    catalog_default!("builtin_prompt_corpus"), // 72 builtin_prompt_corpus
    catalog_default!("instruction_bundle"),  // 73 instruction_bundle
    catalog_default!("memory_corpus"),       // 74 memory_corpus
    catalog_default!("skill_catalog"),       // 75 skill_catalog
    catalog_default!("agent_catalog"),       // 76 agent_catalog
    catalog_default!("provider_model_capability_catalog"), // 77 provider_model_capability_catalog
    catalog_default!("mcp_topology_tool_catalog"), // 78 mcp_topology_tool_catalog
    catalog_default!("hooks_map"),           // 79 hooks_map
    catalog_default!("workflow_graph"),      // 80 workflow_graph
    catalog_default!("tool_action_space"),   // 81 tool_action_space
    catalog_default!("rate_card_catalog"),   // 82 rate_card_catalog
    catalog_default!("router_lexicons"),     // 83 router_lexicons
    observation_default!("run_boundary.environment_snapshot"), // 84 environment_snapshot
    catalog_default!("web_search_backend_catalog"), // 85 web_search_backend_catalog
];
