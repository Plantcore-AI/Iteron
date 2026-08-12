use crate::ValueSchema;

pub(super) const VALUE_SCHEMAS: [ValueSchema; 25] = [
    object_schema!(
        "interactive_stdin_wait_policy",
        [
            scalar_field!(
                "poll_milliseconds",
                true,
                int_domain!(1, 60_000, "milliseconds")
            ),
            scalar_field!(
                "idle_timeout_milliseconds",
                true,
                int_domain!(1, 86_400_000, "milliseconds")
            ),
            scalar_field!("operator_prompt", true, bool_domain!())
        ],
        [
            less_equal_rule!("poll_milliseconds", "idle_timeout_milliseconds"),
            external_rule!("idle_timeout_milliseconds", ParentWall)
        ]
    ),
    scalar_schema!(
        "process_signal_kill_escalation",
        Enum,
        finite_enum_domain!("term_grace_kill_reap"),
        [external_rule!("$", BenchmarkProtocol)]
    ),
    object_schema!(
        "process_cwd_continuity",
        [
            scalar_field!(
                "scope",
                true,
                finite_enum_domain!("process", "job", "session")
            ),
            scalar_field!("initial_cwd", true, text_domain!(1, 4096, Path)),
            scalar_field!("preserve_changes", true, bool_domain!())
        ],
        [
            external_rule!("scope", OperatorAuthority),
            external_rule!("initial_cwd", TenantScope),
            external_rule!("preserve_changes", OperatorAuthority)
        ]
    ),
    object_schema!(
        "child_process_environment_reuse",
        [
            scalar_field!("reuse", true, bool_domain!()),
            scalar_field!("max_entries", true, int_domain!(0, 4096, "entries")),
            scalar_field!("max_bytes", true, int_domain!(0, 1_048_576, "bytes")),
            list_field!(
                "blocked_names",
                true,
                0,
                4096,
                true,
                text_domain!(1, 256, Identifier)
            )
        ],
        [
            external_rule!("max_entries", ProcessBudget),
            external_rule!("blocked_names", OperatorAuthority)
        ]
    ),
    scalar_schema!(
        "effecting_tool_concurrency",
        Count,
        int_domain!(1, 1024, "calls"),
        [
            external_rule!("$", ProcessBudget),
            external_rule!("$", OperatorAuthority)
        ]
    ),
    object_schema!(
        "write_set_conflict_admission",
        [
            scalar_field!("declared_set_required", true, bool_domain!()),
            scalar_field!("overlap", true, finite_enum_domain!("reject", "serialize")),
            scalar_field!(
                "unknown_set",
                true,
                finite_enum_domain!("reject", "serialize")
            )
        ],
        [external_rule!("declared_set_required", OperatorAuthority)]
    ),
    object_schema!(
        "tool_output_spill_to_disk_policy",
        [
            scalar_field!(
                "memory_threshold_bytes",
                true,
                int_domain!(0, 1_073_741_824, "bytes")
            ),
            scalar_field!(
                "spill_max_bytes",
                true,
                int_domain!(0, 17_179_869_184, "bytes")
            ),
            scalar_field!(
                "cleanup",
                true,
                finite_enum_domain!("tool_end", "turn_end", "run_end")
            ),
            scalar_field!("private_storage", true, bool_domain!())
        ],
        [
            less_equal_rule!("memory_threshold_bytes", "spill_max_bytes"),
            external_rule!("spill_max_bytes", ToolBudget)
        ]
    ),
    object_schema!(
        "binary_media_inspection_routing",
        [
            map_field!(
                "mime_routes",
                true,
                0,
                1024,
                text_domain!(1, 256, Identifier),
                catalog_enum_domain!("binary-inspectors")
            ),
            scalar_field!(
                "unknown_mime",
                true,
                finite_enum_domain!("reject", "metadata_only")
            ),
            scalar_field!(
                "max_input_bytes",
                true,
                int_domain!(1, 1_073_741_824, "bytes")
            )
        ],
        [
            external_rule!("mime_routes", OperatorAuthority),
            external_rule!("max_input_bytes", ToolBudget)
        ]
    ),
    catalog_schema!(
        "lsp_server_language_selection",
        64,
        [
            scalar_field!("language_id", true, text_domain!(1, 96, Identifier)),
            scalar_field!("server_id", true, text_domain!(1, 96, NamespacedId)),
            scalar_field!("executable", true, text_domain!(1, 4096, Path)),
            list_field!(
                "arguments",
                true,
                0,
                128,
                false,
                text_domain!(1, 4096, Command)
            ),
            list_field!(
                "workspace_markers",
                true,
                0,
                128,
                true,
                text_domain!(1, 256, Path)
            )
        ],
        [external_catalog_rule!("executable", OperatorAuthority)]
    ),
    object_schema!(
        "lsp_timeout_restart_policy",
        [
            scalar_field!(
                "request_timeout_milliseconds",
                true,
                int_domain!(1, 120_000, "milliseconds")
            ),
            scalar_field!("max_restarts", true, int_domain!(0, 8, "restarts")),
            scalar_field!(
                "backoff_base_milliseconds",
                true,
                int_domain!(0, 60_000, "milliseconds")
            ),
            scalar_field!(
                "backoff_cap_milliseconds",
                true,
                int_domain!(0, 60_000, "milliseconds")
            )
        ],
        [
            less_equal_rule!("backoff_base_milliseconds", "backoff_cap_milliseconds"),
            external_rule!("request_timeout_milliseconds", ParentWall)
        ]
    ),
    scalar_schema!(
        "lsp_result_context_budget",
        Count,
        int_domain!(0, 10_000_000, "tokens"),
        [external_rule!("$", ContextWindow)]
    ),
    scalar_schema!(
        "tool_result_cache_ttl",
        Duration,
        int_domain!(0, 86_400, "seconds"),
        [external_rule!("$", RunBudget)]
    ),
    object_schema!(
        "test_selection_strategy",
        [
            scalar_field!(
                "scope",
                true,
                finite_enum_domain!("explicit", "impacted", "lane", "workspace")
            ),
            list_field!(
                "required_commands",
                true,
                0,
                1024,
                true,
                text_domain!(1, 4096, Command)
            ),
            scalar_field!("max_commands", true, int_domain!(1, 1024, "commands"))
        ],
        [
            external_rule!("scope", VerificationFloor),
            external_rule!("required_commands", VerificationFloor)
        ]
    ),
    scalar_schema!(
        "incremental_versus_full_verification",
        Enum,
        finite_enum_domain!("incremental", "impacted", "full"),
        [external_rule!("$", VerificationFloor)]
    ),
    object_schema!(
        "flaky_test_detection_quarantine",
        [
            scalar_field!("repeat_count", true, int_domain!(1, 64, "runs")),
            scalar_field!("minimum_disagreements", true, int_domain!(1, 64, "runs")),
            scalar_field!(
                "quarantine_seconds",
                true,
                int_domain!(0, 604_800, "seconds")
            ),
            scalar_field!("report_disagreement", true, bool_domain!())
        ],
        [
            less_equal_rule!("minimum_disagreements", "repeat_count"),
            external_rule!("repeat_count", RunBudget)
        ]
    ),
    catalog_schema!(
        "failure_classification_taxonomy",
        1024,
        [
            scalar_field!("class_id", true, text_domain!(1, 96, NamespacedId)),
            scalar_field!(
                "outcome",
                true,
                finite_enum_domain!(
                    "pass",
                    "test_failure",
                    "infrastructure_failure",
                    "timeout",
                    "unknown"
                )
            ),
            scalar_field!("terminal", true, bool_domain!()),
            scalar_field!("version", true, text_domain!(1, 64, Semver))
        ],
        [external_catalog_rule!("version", BenchmarkProtocol)]
    ),
    object_schema!(
        "retry_eligibility_policy",
        [
            list_field!(
                "eligible_classes",
                true,
                0,
                1024,
                true,
                text_domain!(1, 96, NamespacedId)
            ),
            scalar_field!("max_attempts", true, int_domain!(0, 64, "attempts")),
            scalar_field!("unknown", true, finite_enum_domain!("stop", "operator"))
        ],
        [
            external_rule!("eligible_classes", VerificationFloor),
            external_rule!("max_attempts", RunBudget)
        ]
    ),
    scalar_schema!(
        "rollback_on_verification_failure",
        Enum,
        finite_enum_domain!("off", "selected_paths", "workspace"),
        [external_rule!("$", OperatorAuthority)]
    ),
    object_schema!(
        "workspace_checkpoint_cadence",
        [
            scalar_field!("turn_boundary", true, bool_domain!()),
            scalar_field!("before_verification", true, bool_domain!()),
            scalar_field!("before_drain", true, bool_domain!()),
            scalar_field!(
                "minimum_turn_interval",
                true,
                int_domain!(0, 10_000, "turns")
            )
        ],
        [external_rule!("minimum_turn_interval", ParentTurns)]
    ),
    object_schema!(
        "selective_restore_scope",
        [
            scalar_field!(
                "mode",
                true,
                finite_enum_domain!("selected_paths", "workspace")
            ),
            list_field!(
                "paths",
                false,
                1,
                100_000,
                true,
                text_domain!(1, 4096, Path)
            )
        ],
        [external_rule!("paths", OperatorAuthority)]
    ),
    object_schema!(
        "verification_quorum_consensus",
        [
            scalar_field!("verifiers", true, int_domain!(1, 64, "verifiers")),
            scalar_field!("required_agreement", true, int_domain!(1, 64, "verifiers")),
            scalar_field!("strong_veto", true, bool_domain!())
        ],
        [
            less_equal_rule!("required_agreement", "verifiers"),
            external_rule!("verifiers", RunBudget)
        ]
    ),
    scalar_schema!(
        "recovery_escalation_policy",
        Enum,
        finite_enum_domain!("retry_replan_stop", "retry_stop", "operator_stop"),
        [external_rule!("$", VerificationFloor)]
    ),
    scalar_schema!(
        "per_agent_model",
        Enum,
        catalog_enum_domain!("model-routes"),
        [
            external_rule!("$", ProviderCapability),
            external_domain_rule!("$", ParentCost)
        ]
    ),
    scalar_schema!(
        "per_agent_effort_thinking",
        Enum,
        finite_enum_domain!("low", "medium", "high", "xhigh", "max", "ultracode"),
        [external_domain_rule!("$", ParentTokens)]
    ),
    map_schema!(
        "per_agent_tool_profile",
        0,
        256,
        text_domain!(1, 96, NamespacedId),
        crate::FieldDomain::Scalar {
            domain: finite_enum_domain!("allow", "ask", "deny")
        },
        [external_rule!("$", OperatorAuthority)]
    ),
];
