use crate::ValueSchema;

pub(super) const VALUE_SCHEMAS: [ValueSchema; 30] = [
    object_schema!(
        "memory_budgets",
        [
            scalar_field!("recall_bytes", true, int_domain!(0, 1_048_576, "bytes")),
            scalar_field!("index_bytes", true, int_domain!(0, 1_048_576, "bytes")),
            scalar_field!("fact_bytes", true, int_domain!(0, 1_048_576, "bytes")),
            scalar_field!("total_bytes", true, int_domain!(1, 4_194_304, "bytes"))
        ],
        [
            sum_rule!(["recall_bytes", "index_bytes", "fact_bytes"], "total_bytes"),
            external_rule!("total_bytes", ContextWindow)
        ]
    ),
    map_schema!(
        "bm25",
        3,
        3,
        finite_enum_domain!("k1", "b", "recall_limit"),
        crate::FieldDomain::Scalar {
            domain: decimal_domain!(0, 0, 1000, 0, 4, "number")
        },
        []
    ),
    scalar_schema!(
        "skill_listing_budget",
        Bytes,
        int_domain!(0, 1_048_576, "bytes"),
        [external_rule!("$", ContextWindow)]
    ),
    scalar_schema!(
        "max_consecutive_tool_errors",
        Count,
        int_domain!(1, 1024, "errors"),
        [external_rule!("$", RunBudget)]
    ),
    scalar_schema!(
        "pure_overlap",
        Bool,
        bool_domain!(),
        [external_rule!("$", ToolBudget)]
    ),
    scalar_schema!(
        "pure_concurrency",
        Count,
        int_domain!(1, 1024, "calls"),
        [external_rule!("$", ProcessBudget)]
    ),
    object_schema!(
        "failed_action_dedup",
        [
            scalar_field!("max_identities", true, int_domain!(1, 65_536, "entries")),
            scalar_field!("scope", true, finite_enum_domain!("turn", "run")),
            scalar_field!("failed_only", true, bool_domain!())
        ],
        [external_rule!("max_identities", ToolBudget)]
    ),
    object_schema!(
        "pure_memo_cache",
        [
            scalar_field!("max_entries", true, int_domain!(0, 65_536, "entries")),
            scalar_field!("max_key_bytes", true, int_domain!(1, 65_536, "bytes")),
            scalar_field!("generation_scoped", true, bool_domain!())
        ],
        [external_rule!("max_entries", ToolBudget)]
    ),
    object_schema!(
        "shell_timeout_output",
        [
            scalar_field!("timeout_seconds", true, int_domain!(1, 86_400, "seconds")),
            scalar_field!(
                "stdout_max_bytes",
                true,
                int_domain!(0, 16_777_216, "bytes")
            ),
            scalar_field!(
                "stderr_max_bytes",
                true,
                int_domain!(0, 16_777_216, "bytes")
            )
        ],
        [
            external_rule!("timeout_seconds", ParentWall),
            external_rule!("stdout_max_bytes", ToolBudget),
            external_rule!("stderr_max_bytes", ToolBudget)
        ]
    ),
    object_schema!(
        "read_file_limits",
        [
            scalar_field!(
                "source_max_bytes",
                true,
                int_domain!(1, 134_217_728, "bytes")
            ),
            scalar_field!(
                "output_max_bytes",
                true,
                int_domain!(1, 16_777_216, "bytes")
            ),
            scalar_field!("max_lines", true, int_domain!(1, 1_000_000, "lines"))
        ],
        [
            less_equal_rule!("output_max_bytes", "source_max_bytes"),
            external_rule!("output_max_bytes", ContextWindow)
        ]
    ),
    object_schema!(
        "list_dir_limits",
        [
            scalar_field!("max_depth", true, int_domain!(0, 64, "levels")),
            scalar_field!("max_entries", true, int_domain!(1, 100_000, "entries")),
            scalar_field!(
                "output_max_bytes",
                true,
                int_domain!(1, 16_777_216, "bytes")
            )
        ],
        [external_rule!("output_max_bytes", ContextWindow)]
    ),
    object_schema!(
        "glob_limits",
        [
            scalar_field!("max_depth", true, int_domain!(0, 128, "levels")),
            scalar_field!("max_results", true, int_domain!(1, 100_000, "results")),
            scalar_field!(
                "output_max_bytes",
                true,
                int_domain!(1, 16_777_216, "bytes")
            )
        ],
        [external_rule!("output_max_bytes", ContextWindow)]
    ),
    object_schema!(
        "grep_limits",
        [
            scalar_field!("max_matches", true, int_domain!(1, 1_000_000, "matches")),
            scalar_field!(
                "snippet_max_bytes",
                true,
                int_domain!(1, 1_048_576, "bytes")
            ),
            scalar_field!(
                "output_max_bytes",
                true,
                int_domain!(1, 16_777_216, "bytes")
            )
        ],
        [
            less_equal_rule!("snippet_max_bytes", "output_max_bytes"),
            external_rule!("output_max_bytes", ContextWindow)
        ]
    ),
    object_schema!(
        "repo_map",
        [
            scalar_field!("max_files", true, int_domain!(1, 1_000_000, "files")),
            scalar_field!("max_depth", true, int_domain!(0, 128, "levels")),
            scalar_field!("max_tokens", true, int_domain!(1, 1_000_000, "tokens"))
        ],
        [external_rule!("max_tokens", ContextWindow)]
    ),
    object_schema!(
        "git_limits",
        [
            scalar_field!("timeout_seconds", true, int_domain!(1, 3600, "seconds")),
            scalar_field!(
                "output_max_bytes",
                true,
                int_domain!(1, 16_777_216, "bytes")
            ),
            scalar_field!(
                "status_max_entries",
                true,
                int_domain!(1, 100_000, "entries")
            ),
            scalar_field!("log_max_entries", true, int_domain!(1, 10_000, "entries"))
        ],
        [
            external_rule!("timeout_seconds", ParentWall),
            external_rule!("output_max_bytes", ContextWindow)
        ]
    ),
    object_schema!(
        "web_fetch_limits",
        [
            scalar_field!("body_max_bytes", true, int_domain!(1, 16_777_216, "bytes")),
            scalar_field!("max_redirects", true, int_domain!(0, 32, "redirects")),
            scalar_field!("timeout_seconds", true, int_domain!(1, 300, "seconds")),
            scalar_field!("max_lines", true, int_domain!(1, 100_000, "lines"))
        ],
        [
            external_rule!("body_max_bytes", ContextWindow),
            external_rule!("timeout_seconds", ParentWall)
        ]
    ),
    scalar_schema!(
        "web_search_cap",
        Count,
        int_domain!(0, 1000, "results"),
        [external_rule!("$", ContextWindow)]
    ),
    scalar_schema!(
        "verifier_attempts",
        Count,
        int_domain!(0, 1024, "attempts"),
        [external_rule!("$", RunBudget)]
    ),
    object_schema!(
        "verifier_feedback_tails",
        [
            scalar_field!(
                "command_output_bytes",
                true,
                int_domain!(0, 1_048_576, "bytes")
            ),
            scalar_field!(
                "oracle_output_bytes",
                true,
                int_domain!(0, 1_048_576, "bytes")
            ),
            scalar_field!("total_bytes", true, int_domain!(1, 2_097_152, "bytes"))
        ],
        [
            sum_rule!(
                ["command_output_bytes", "oracle_output_bytes"],
                "total_bytes"
            ),
            external_rule!("total_bytes", ContextWindow)
        ]
    ),
    scalar_schema!(
        "verifier_timeout",
        Duration,
        int_domain!(1, 86_400, "seconds"),
        [external_rule!("$", ParentWall)]
    ),
    scalar_schema!(
        "route_topology",
        Enum,
        finite_enum_domain!("direct", "orchestrated"),
        [external_rule!("$", OperatorAuthority)]
    ),
    object_schema!(
        "decomposition_profile",
        [
            scalar_field!("max_output_tokens", true, int_domain!(1, 65_536, "tokens")),
            scalar_field!(
                "effort",
                true,
                finite_enum_domain!("low", "medium", "high", "xhigh", "max", "ultracode")
            ),
            scalar_field!("thinking_tokens", true, int_domain!(0, 1_000_000, "tokens"))
        ],
        [
            external_rule!("max_output_tokens", ParentTokens),
            external_rule!("thinking_tokens", ProviderCapability)
        ]
    ),
    scalar_schema!(
        "fan_breadth",
        Count,
        int_domain!(1, 1024, "agents"),
        [external_rule!("$", RunBudget)]
    ),
    object_schema!(
        "admission",
        [
            scalar_field!(
                "minimum_remaining_turns",
                true,
                int_domain!(0, 1_000_000, "turns")
            ),
            scalar_field!(
                "minimum_remaining_wall_seconds",
                true,
                int_domain!(0, 86_400, "seconds")
            ),
            scalar_field!("require_capability_subset", true, bool_domain!())
        ],
        [
            external_rule!("minimum_remaining_turns", ParentTurns),
            external_rule!("minimum_remaining_wall_seconds", ParentWall)
        ]
    ),
    scalar_schema!(
        "writer_fan_turn_split",
        Ratio,
        decimal_domain!(0, 0, 1, 0, 6, "ratio"),
        [external_rule!("$", ParentTurns)]
    ),
    scalar_schema!(
        "worker_min_turns",
        Count,
        int_domain!(1, 1_000_000, "turns"),
        [external_rule!("$", ParentTurns)]
    ),
    scalar_schema!(
        "wall_split",
        Ratio,
        decimal_domain!(0, 0, 1, 0, 6, "ratio"),
        [external_rule!("$", ParentWall)]
    ),
    scalar_schema!(
        "token_split",
        Ratio,
        decimal_domain!(0, 0, 1, 0, 6, "ratio"),
        [external_rule!("$", ParentTokens)]
    ),
    scalar_schema!(
        "fan_concurrency",
        Count,
        int_domain!(1, 1024, "agents"),
        [external_rule!("$", ProcessBudget)]
    ),
    object_schema!(
        "child_ceiling",
        [
            scalar_field!("max_turns", true, int_domain!(1, 1_000_000, "turns")),
            scalar_field!("max_wall_seconds", true, int_domain!(1, 86_400, "seconds")),
            scalar_field!(
                "max_consecutive_errors",
                true,
                int_domain!(1, 1024, "errors")
            ),
            list_field!(
                "capabilities",
                true,
                0,
                256,
                true,
                text_domain!(1, 96, NamespacedId)
            )
        ],
        [
            external_rule!("max_turns", ParentTurns),
            external_rule!("max_wall_seconds", ParentWall),
            external_rule!("capabilities", OperatorAuthority)
        ]
    ),
];
