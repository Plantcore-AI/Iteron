use crate::CoreStrategySlot as Slot;

/// Exact StrategySlot ledger for all 160 canonical families. There is deliberately no
/// domain-based fallback: multi-slot effects and cross-domain seams remain explicit per ordinal.
#[rustfmt::skip]
const STRATEGY_SLOTS: [&[Slot]; crate::EXPECTED_FAMILY_COUNT] = [
    // Appendix A.1 — public controls.
    &[Slot::ModelRouter],                         // 1 provider
    &[Slot::ModelRouter],                         // 2 model
    &[Slot::ModelRouter],                         // 3 base_url
    &[Slot::Planner, Slot::ModelRouter],           // 4 effort
    &[Slot::Scheduler],                           // 5 max_turns
    &[Slot::Scheduler],                           // 6 max_usd
    &[Slot::Scheduler],                           // 7 max_tokens
    &[Slot::Scheduler],                           // 8 max_wall_secs
    &[Slot::ToolPolicy],                          // 9 allow_code
    &[Slot::ToolPolicy],                          // 10 permission_mode
    &[Slot::ToolPolicy],                          // 11 permission_rules
    &[Slot::ToolPolicy],                          // 12 bypass_permissions
    &[Slot::Context],                             // 13 compaction_trigger
    &[Slot::Verifier],                            // 14 verify_command

    // Appendix A.2 — provider retry/config seams.
    &[Slot::Scheduler, Slot::ModelRouter],         // 15 retry_backoff_base
    &[Slot::Scheduler, Slot::ModelRouter],         // 16 retry_backoff_cap
    &[Slot::Scheduler, Slot::ModelRouter],         // 17 retry_max_attempts
    &[Slot::ToolPolicy],                          // 18 egress_allow

    // Appendix A.3 — fixed production policy.
    &[Slot::ModelRouter, Slot::Context],           // 19 request_output_cap
    &[Slot::Planner, Slot::ModelRouter],           // 20 effort_reasoning_map
    &[Slot::Planner, Slot::ModelRouter],           // 21 thinking_map
    &[Slot::Planner, Slot::Collaboration],         // 22 orchestration_map
    &[Slot::ModelRouter, Slot::Context],           // 23 prompt_cache
    &[Slot::Context],                             // 24 compaction_adaptive
    &[Slot::Context],                             // 25 compaction_keep_recent
    &[Slot::Context, Slot::ModelRouter],           // 26 token_estimator
    &[Slot::Context, Slot::ModelRouter],           // 27 summary_profile
    &[Slot::Context],                             // 28 compaction_failure
    &[Slot::Context],                             // 29 instruction_discovery_render
    &[Slot::Memory, Slot::Context],                // 30 memory_enable
    &[Slot::Memory, Slot::Context],                // 31 memory_budgets
    &[Slot::Memory],                              // 32 bm25
    &[Slot::Context, Slot::ToolPolicy],            // 33 skill_listing_budget
    &[Slot::Scheduler, Slot::ToolPolicy],          // 34 max_consecutive_tool_errors
    &[Slot::Scheduler, Slot::ToolPolicy],          // 35 pure_overlap
    &[Slot::Scheduler, Slot::ToolPolicy],          // 36 pure_concurrency
    &[Slot::ToolPolicy],                          // 37 failed_action_dedup
    &[Slot::ToolPolicy],                          // 38 pure_memo_cache
    &[Slot::ToolPolicy],                          // 39 shell_timeout_output
    &[Slot::ToolPolicy, Slot::Context],            // 40 read_file_limits
    &[Slot::ToolPolicy, Slot::Context],            // 41 list_dir_limits
    &[Slot::ToolPolicy, Slot::Context],            // 42 glob_limits
    &[Slot::ToolPolicy, Slot::Context],            // 43 grep_limits
    &[Slot::Context, Slot::ToolPolicy],            // 44 repo_map
    &[Slot::ToolPolicy, Slot::Context],            // 45 git_limits
    &[Slot::ToolPolicy, Slot::Context],            // 46 web_fetch_limits
    &[Slot::ToolPolicy, Slot::Context],            // 47 web_search_cap
    &[Slot::Verifier, Slot::Scheduler],            // 48 verifier_attempts
    &[Slot::Verifier, Slot::Context],              // 49 verifier_feedback_tails
    &[Slot::Verifier, Slot::Scheduler],            // 50 verifier_timeout
    &[Slot::Router, Slot::Collaboration],          // 51 route_topology
    &[Slot::Planner, Slot::Collaboration],         // 52 decomposition_profile
    &[Slot::Scheduler, Slot::Collaboration],       // 53 fan_breadth
    &[Slot::Scheduler, Slot::Collaboration],       // 54 admission
    &[Slot::Scheduler, Slot::Collaboration],       // 55 writer_fan_turn_split
    &[Slot::Scheduler, Slot::Collaboration],       // 56 worker_min_turns
    &[Slot::Scheduler, Slot::Collaboration],       // 57 wall_split
    &[Slot::Scheduler, Slot::Collaboration],       // 58 token_split
    &[Slot::Scheduler, Slot::Collaboration],       // 59 fan_concurrency
    &[Slot::Scheduler, Slot::Collaboration],       // 60 child_ceiling
    &[Slot::Scheduler, Slot::Collaboration],       // 61 direct_child_allocation
    &[Slot::Planner, Slot::ModelRouter, Slot::Collaboration], // 62 subagent_effort_inheritance
    &[Slot::Context, Slot::Collaboration],         // 63 report_budget
    &[Slot::Collaboration],                       // 64 join_reduce
    &[Slot::Scheduler, Slot::Collaboration],       // 65 workflow_aggregate
    &[Slot::Scheduler, Slot::ModelRouter],         // 66 schema_retry_jitter
    &[Slot::ModelRouter],                         // 67 provider_connect_tls_timeout
    &[Slot::Context, Slot::ModelRouter],           // 68 multimodal_input_admission_decode_envelope
    &[Slot::Scheduler, Slot::Router],              // 69 app_server_sq_eq_backpressure
    &[Slot::ModelRouter],                         // 70 provider_discovery_account_probe_cache_policy

    // Appendix A.4 — content/catalog/component surfaces.
    &[Slot::Context, Slot::Planner],               // 71 operator_prompt_stream
    &[Slot::Planner, Slot::Context],               // 72 builtin_prompt_corpus
    &[Slot::Context],                             // 73 instruction_bundle
    &[Slot::Memory],                              // 74 memory_corpus
    &[Slot::Context, Slot::ToolPolicy],            // 75 skill_catalog
    &[Slot::Collaboration, Slot::ModelRouter, Slot::ToolPolicy], // 76 agent_catalog
    &[Slot::ModelRouter],                         // 77 provider_model_capability_catalog
    &[Slot::ToolPolicy],                          // 78 mcp_topology_tool_catalog
    &[Slot::ToolPolicy],                          // 79 hooks_map
    &[Slot::Planner, Slot::Collaboration],         // 80 workflow_graph
    &[Slot::ToolPolicy],                          // 81 tool_action_space
    &[Slot::Router, Slot::ModelRouter],            // 82 rate_card_catalog
    &[Slot::Router, Slot::Planner],                // 83 router_lexicons
    &[Slot::Context],                             // 84 environment_snapshot
    &[Slot::ToolPolicy, Slot::Router],             // 85 web_search_backend_catalog

    // Appendix F.1 — model routing and transport.
    &[Slot::ModelRouter],                         // 86
    &[Slot::ModelRouter],                         // 87
    &[Slot::Router, Slot::ModelRouter],            // 88
    &[Slot::ModelRouter],                         // 89
    &[Slot::ModelRouter],                         // 90
    &[Slot::ModelRouter],                         // 91
    &[Slot::Planner, Slot::ModelRouter],           // 92
    &[Slot::ModelRouter, Slot::Collaboration],     // 93
    &[Slot::ModelRouter],                         // 94
    &[Slot::ModelRouter],                         // 95

    // Appendix F.2 — context, retrieval, compaction.
    &[Slot::Context],                             // 96
    &[Slot::Context],                             // 97
    &[Slot::Context],                             // 98
    &[Slot::Context],                             // 99
    &[Slot::Context],                             // 100
    &[Slot::Context],                             // 101
    &[Slot::Context],                             // 102
    &[Slot::Context],                             // 103
    &[Slot::Context, Slot::Verifier],              // 104
    &[Slot::Memory, Slot::Context],                // 105
    &[Slot::Memory],                              // 106
    &[Slot::Context, Slot::Memory],                // 107

    // Appendix F.3 — tools, processes, code intelligence.
    &[Slot::ToolPolicy],                          // 108
    &[Slot::Scheduler, Slot::ToolPolicy],          // 109
    &[Slot::ToolPolicy],                          // 110
    &[Slot::ToolPolicy],                          // 111
    &[Slot::ToolPolicy],                          // 112
    &[Slot::ToolPolicy],                          // 113
    &[Slot::ToolPolicy],                          // 114
    &[Slot::Scheduler, Slot::ToolPolicy],          // 115
    &[Slot::ToolPolicy],                          // 116
    &[Slot::ToolPolicy],                          // 117
    &[Slot::Router, Slot::ToolPolicy],             // 118
    &[Slot::ToolPolicy],                          // 119
    &[Slot::ToolPolicy],                          // 120
    &[Slot::Context, Slot::ToolPolicy],            // 121
    &[Slot::ToolPolicy],                          // 122

    // Appendix F.4 — verification and recovery.
    &[Slot::Verifier],                            // 123
    &[Slot::Verifier],                            // 124
    &[Slot::Verifier],                            // 125
    &[Slot::Verifier],                            // 126
    &[Slot::Verifier, Slot::Planner],              // 127
    &[Slot::Verifier],                            // 128
    &[Slot::Verifier, Slot::ToolPolicy],           // 129
    &[Slot::Verifier],                            // 130
    &[Slot::Verifier, Slot::Collaboration],        // 131
    &[Slot::Planner, Slot::Verifier],              // 132

    // Appendix F.5 — agents and collaboration.
    &[Slot::ModelRouter, Slot::Collaboration],     // 133
    &[Slot::Planner, Slot::Collaboration],         // 134
    &[Slot::ToolPolicy, Slot::Collaboration],      // 135
    &[Slot::Memory, Slot::Collaboration],          // 136
    &[Slot::Scheduler, Slot::Collaboration],       // 137
    &[Slot::Scheduler],                           // 138
    &[Slot::Scheduler],                           // 139
    &[Slot::Scheduler],                           // 140
    &[Slot::Scheduler],                           // 141
    &[Slot::Scheduler, Slot::Collaboration],       // 142
    &[Slot::Collaboration, Slot::ToolPolicy],      // 143
    &[Slot::Collaboration, Slot::Verifier],        // 144
    &[Slot::Collaboration],                       // 145
    &[Slot::Scheduler, Slot::Collaboration],       // 146

    // Appendix F.6 — MCP and plugins.
    &[Slot::ToolPolicy],                          // 147
    &[Slot::Context, Slot::ToolPolicy],            // 148
    &[Slot::ToolPolicy],                          // 149
    &[Slot::ToolPolicy],                          // 150
    &[Slot::ToolPolicy],                          // 151
    &[Slot::Context, Slot::ToolPolicy],            // 152
    &[Slot::ToolPolicy],                          // 153
    &[Slot::ToolPolicy, Slot::Context],            // 154

    // Appendix F.7 — session/cache/reliability.
    &[Slot::ModelRouter],                         // 155
    &[Slot::ModelRouter],                         // 156
    &[Slot::Scheduler, Slot::ModelRouter],         // 157
    &[Slot::Context, Slot::ModelRouter],           // 158
    &[Slot::Collaboration, Slot::ToolPolicy],      // 159
    &[Slot::Collaboration, Slot::Verifier],        // 160
];

pub(crate) const fn strategy_slots(ordinal: u16) -> &'static [Slot] {
    STRATEGY_SLOTS[ordinal as usize - 1]
}

pub(crate) const fn primary_strategy_slot(ordinal: u16) -> Slot {
    STRATEGY_SLOTS[ordinal as usize - 1][0]
}
