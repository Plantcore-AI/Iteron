use crate::{BenchmarkCausalPath, BenchmarkRelevance, CausalPath, RelevanceLevel};

#[derive(Debug, Clone, Copy)]
struct Levels {
    swe_bench_pro: RelevanceLevel,
    terminal_bench_2_1: RelevanceLevel,
}

macro_rules! levels {
    ($swe:ident, $terminal:ident) => {
        Levels {
            swe_bench_pro: RelevanceLevel::$swe,
            terminal_bench_2_1: RelevanceLevel::$terminal,
        }
    };
}

/// Exact formal relevance ledger in canonical ordinal order. Relevance is an independently
/// reviewed H/M/L claim; it is never inferred from causal-path shape.
#[rustfmt::skip]
const LEVELS: [Levels; crate::EXPECTED_FAMILY_COUNT] = [
    // Appendix A.1 — public active fixed-shape.
    levels!(High, High),     // 1 provider
    levels!(High, High),     // 2 model
    levels!(Medium, Medium), // 3 base_url
    levels!(High, High),     // 4 effort
    levels!(High, High),     // 5 max_turns
    levels!(Medium, Medium), // 6 max_usd
    levels!(High, High),     // 7 max_tokens
    levels!(High, High),     // 8 max_wall_secs
    levels!(High, High),     // 9 allow_code
    levels!(High, High),     // 10 permission_mode
    levels!(High, High),     // 11 permission_rules
    levels!(High, High),     // 12 bypass_permissions
    levels!(High, High),     // 13 compaction_trigger
    levels!(High, Medium),   // 14 verify_command

    // Appendix A.2 — parsed/staged.
    levels!(Medium, Medium), // 15 retry_backoff_base
    levels!(Medium, Medium), // 16 retry_backoff_cap
    levels!(Medium, High),   // 17 retry_max_attempts
    levels!(Low, High),      // 18 egress_allow

    // Appendix A.3 — hard-coded production policy.
    levels!(High, High),     // 19 request_output_cap
    levels!(High, High),     // 20 effort_reasoning_map
    levels!(High, High),     // 21 thinking_map
    levels!(High, High),     // 22 orchestration_map
    levels!(Medium, Medium), // 23 prompt_cache
    levels!(High, High),     // 24 compaction_adaptive
    levels!(High, High),     // 25 compaction_keep_recent
    levels!(Medium, High),   // 26 token_estimator
    levels!(High, High),     // 27 summary_profile
    levels!(Medium, High),   // 28 compaction_failure
    levels!(High, Medium),   // 29 instruction_discovery_render
    levels!(Medium, Medium), // 30 memory_enable
    levels!(High, Medium),   // 31 memory_budgets
    levels!(High, Medium),   // 32 bm25
    levels!(Medium, Low),    // 33 skill_listing_budget
    levels!(High, High),     // 34 max_consecutive_tool_errors
    levels!(Medium, High),   // 35 pure_overlap
    levels!(Medium, High),   // 36 pure_concurrency
    levels!(Medium, Medium), // 37 failed_action_dedup
    levels!(Medium, Medium), // 38 pure_memo_cache
    levels!(Medium, High),   // 39 shell_timeout_output
    levels!(High, Medium),   // 40 read_file_limits
    levels!(High, Medium),   // 41 list_dir_limits
    levels!(High, Medium),   // 42 glob_limits
    levels!(High, Medium),   // 43 grep_limits
    levels!(High, Low),      // 44 repo_map
    levels!(High, Medium),   // 45 git_limits
    levels!(Medium, Medium), // 46 web_fetch_limits
    levels!(Low, Medium),    // 47 web_search_cap
    levels!(High, Medium),   // 48 verifier_attempts
    levels!(High, Medium),   // 49 verifier_feedback_tails
    levels!(High, Medium),   // 50 verifier_timeout
    levels!(High, High),     // 51 route_topology
    levels!(High, High),     // 52 decomposition_profile
    levels!(High, High),     // 53 fan_breadth
    levels!(High, High),     // 54 admission
    levels!(High, High),     // 55 writer_fan_turn_split
    levels!(High, High),     // 56 worker_min_turns
    levels!(High, High),     // 57 wall_split
    levels!(High, High),     // 58 token_split
    levels!(Medium, High),   // 59 fan_concurrency
    levels!(High, High),     // 60 child_ceiling
    levels!(High, High),     // 61 direct_child_allocation
    levels!(High, High),     // 62 subagent_effort_inheritance
    levels!(Medium, High),   // 63 report_budget
    levels!(High, High),     // 64 join_reduce
    levels!(Medium, Medium), // 65 workflow_aggregate
    levels!(Medium, Medium), // 66 schema_retry_jitter
    levels!(Medium, Medium), // 67 provider_connect_tls_timeout
    levels!(Low, Medium),    // 68 multimodal_input_admission_decode_envelope
    levels!(Low, Low),       // 69 app_server_sq_eq_backpressure
    levels!(Medium, Medium), // 70 provider_discovery_account_probe_cache_policy

    // Appendix A.4 — open-dimensional artifact/component families.
    levels!(High, High),     // 71 operator_prompt_stream
    levels!(High, High),     // 72 builtin_prompt_corpus
    levels!(High, High),     // 73 instruction_bundle
    levels!(Medium, High),   // 74 memory_corpus
    levels!(High, Medium),   // 75 skill_catalog
    levels!(Medium, Medium), // 76 agent_catalog
    levels!(High, High),     // 77 provider_model_capability_catalog
    levels!(Medium, Medium), // 78 mcp_topology_tool_catalog
    levels!(High, High),     // 79 hooks_map
    levels!(High, High),     // 80 workflow_graph
    levels!(High, High),     // 81 tool_action_space
    levels!(Low, Low),       // 82 rate_card_catalog
    levels!(Medium, High),   // 83 router_lexicons
    levels!(Medium, Medium), // 84 environment_snapshot
    levels!(Low, Medium),    // 85 web_search_backend_catalog

    // Appendix F.1 — N-RM01..N-RM10.
    levels!(Medium, Medium), // 86
    levels!(Medium, Medium), // 87
    levels!(High, High),     // 88
    levels!(Medium, Medium), // 89
    levels!(Medium, Medium), // 90
    levels!(Medium, High),   // 91
    levels!(Medium, Low),    // 92
    levels!(High, Medium),   // 93
    levels!(Medium, High),   // 94
    levels!(Medium, Medium), // 95

    // Appendix F.2 — N-CX01..N-CX12.
    levels!(High, High),     // 96
    levels!(High, Medium),   // 97
    levels!(High, High),     // 98
    levels!(High, High),     // 99
    levels!(Low, Medium),    // 100
    levels!(High, High),     // 101
    levels!(High, High),     // 102
    levels!(High, Medium),   // 103
    levels!(High, Medium),   // 104
    levels!(High, Medium),   // 105
    levels!(High, Medium),   // 106
    levels!(High, Medium),   // 107

    // Appendix F.3 — N-TP01..N-TP15.
    levels!(Medium, High),   // 108
    levels!(Low, High),      // 109
    levels!(Low, High),      // 110
    levels!(Low, High),      // 111
    levels!(Low, High),      // 112
    levels!(Medium, High),   // 113
    levels!(Medium, High),   // 114
    levels!(Medium, High),   // 115
    levels!(High, Medium),   // 116
    levels!(Medium, High),   // 117
    levels!(Low, Medium),    // 118
    levels!(High, Medium),   // 119
    levels!(High, Medium),   // 120
    levels!(High, Medium),   // 121
    levels!(Medium, Medium), // 122

    // Appendix F.4 — N-VR01..N-VR10.
    levels!(High, Medium),   // 123
    levels!(High, Medium),   // 124
    levels!(High, Medium),   // 125
    levels!(High, High),     // 126
    levels!(High, High),     // 127
    levels!(High, Medium),   // 128
    levels!(Medium, Low),    // 129
    levels!(Medium, Low),    // 130
    levels!(High, Medium),   // 131
    levels!(High, High),     // 132

    // Appendix F.5 — N-AG01..N-AG14.
    levels!(High, Medium),   // 133
    levels!(High, Medium),   // 134
    levels!(High, Medium),   // 135
    levels!(High, Medium),   // 136
    levels!(Medium, High),   // 137
    levels!(Medium, High),   // 138
    levels!(Medium, High),   // 139
    levels!(High, Medium),   // 140
    levels!(High, Medium),   // 141
    levels!(High, Medium),   // 142
    levels!(High, Low),      // 143
    levels!(High, Low),      // 144
    levels!(High, Medium),   // 145
    levels!(High, High),     // 146

    // Appendix F.6 — N-MP01..N-MP08.
    levels!(Medium, Medium), // 147
    levels!(Medium, Medium), // 148
    levels!(Medium, Medium), // 149
    levels!(Medium, Medium), // 150
    levels!(Medium, High),   // 151
    levels!(Medium, Medium), // 152
    levels!(Low, Low),       // 153
    levels!(Medium, Medium), // 154

    // Appendix F.7 — N-SR01..N-SR06.
    levels!(Low, Medium),    // 155
    levels!(Low, Medium),    // 156
    levels!(Medium, Medium), // 157
    levels!(Medium, Medium), // 158
    levels!(High, High),     // 159
    levels!(Medium, Medium), // 160
];

pub(crate) const fn benchmark_relevance(
    ordinal: u16,
    family_mechanism: &'static str,
    terminal_bench_2_1_path: CausalPath,
    swe_bench_pro_path: CausalPath,
) -> BenchmarkRelevance {
    let levels = LEVELS[ordinal as usize - 1];
    BenchmarkRelevance {
        swe_bench_pro: levels.swe_bench_pro,
        terminal_bench_2_1: levels.terminal_bench_2_1,
        causal_path: BenchmarkCausalPath {
            swe_bench_pro: swe_bench_pro_path,
            terminal_bench_2_1: terminal_bench_2_1_path,
        },
        rationale: family_mechanism,
    }
}
