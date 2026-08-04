use crate::ValueSchema;

pub(super) const VALUE_SCHEMAS: [ValueSchema; 25] = [
    list_schema!(
        "model_fallback_chain",
        0,
        32,
        true,
        catalog_enum_domain!("model-routes"),
        [external_rule!("$", ProviderCapability)]
    ),
    catalog_schema!(
        "failover_eligible_error_taxonomy",
        1024,
        [
            scalar_field!("error_class", true, text_domain!(1, 96, NamespacedId)),
            scalar_field!("eligible", true, bool_domain!()),
            scalar_field!(
                "dispatch_state",
                true,
                finite_enum_domain!("pre_dispatch", "unknown", "post_dispatch")
            ),
            scalar_field!("version", true, text_domain!(1, 64, Semver))
        ],
        [external_catalog_rule!("version", BenchmarkProtocol)]
    ),
    map_schema!(
        "route_quality_cost_latency_objective_weights",
        3,
        3,
        finite_enum_domain!("quality", "cost", "latency"),
        crate::FieldDomain::Scalar {
            domain: decimal_domain!(0, 0, 1, 0, 6, "weight")
        },
        []
    ),
    object_schema!(
        "provider_health_circuit_breaker_state_policy",
        [
            scalar_field!("failure_threshold", true, int_domain!(1, 1024, "failures")),
            scalar_field!("open_seconds", true, int_domain!(1, 86_400, "seconds")),
            scalar_field!("half_open_probes", true, int_domain!(1, 1024, "probes")),
            scalar_field!("success_threshold", true, int_domain!(1, 1024, "successes"))
        ],
        [
            external_rule!("open_seconds", ParentWall),
            external_rule!("half_open_probes", RunBudget)
        ]
    ),
    object_schema!(
        "hedged_request_policy",
        [
            scalar_field!("enabled", true, bool_domain!()),
            scalar_field!(
                "delay_milliseconds",
                true,
                int_domain!(0, 86_400_000, "milliseconds")
            ),
            scalar_field!("max_duplicates", true, int_domain!(0, 8, "requests")),
            scalar_field!("idempotent_only", true, bool_domain!())
        ],
        [
            requires_bool_rule!("enabled", true, "max_duplicates"),
            external_rule!("delay_milliseconds", ParentWall),
            external_rule!("max_duplicates", ParentCost)
        ]
    ),
    scalar_schema!(
        "provider_service_tier",
        Enum,
        catalog_enum_domain!("provider-service-tiers"),
        [
            external_rule!("$", ProviderCapability),
            external_domain_rule!("$", ParentCost)
        ]
    ),
    scalar_schema!(
        "response_verbosity",
        Enum,
        finite_enum_domain!("concise", "balanced", "detailed"),
        [
            external_rule!("$", ProviderCapability),
            external_domain_rule!("$", ParentTokens)
        ]
    ),
    map_schema!(
        "role_specific_model_map",
        0,
        256,
        catalog_enum_domain!("agent-roles"),
        crate::FieldDomain::Scalar {
            domain: catalog_enum_domain!("model-routes")
        },
        [
            external_rule!("$", ProviderCapability),
            external_domain_rule!("$", ParentCost)
        ]
    ),
    scalar_schema!(
        "provider_request_total_deadline",
        Duration,
        int_domain!(1, 86_400_000, "milliseconds"),
        [external_rule!("$", ParentWall)]
    ),
    scalar_schema!(
        "stream_idle_watchdog",
        Duration,
        int_domain!(1, 86_400_000, "milliseconds"),
        [external_rule!("$", ParentWall)]
    ),
    object_schema!(
        "context_window_override_reserve",
        [
            scalar_field!(
                "model_window_tokens",
                true,
                int_domain!(1, 10_000_000, "tokens")
            ),
            scalar_field!(
                "operator_override_tokens",
                false,
                int_domain!(1, 10_000_000, "tokens")
            ),
            scalar_field!(
                "output_reserve_tokens",
                true,
                int_domain!(0, 1_000_000, "tokens")
            ),
            scalar_field!(
                "verification_reserve_tokens",
                true,
                int_domain!(0, 1_000_000, "tokens")
            )
        ],
        [
            sum_rule!(
                ["output_reserve_tokens", "verification_reserve_tokens"],
                "model_window_tokens"
            ),
            external_rule!("model_window_tokens", ProviderCapability)
        ]
    ),
    scalar_schema!(
        "system_prefix_budget",
        Count,
        int_domain!(0, 10_000_000, "tokens"),
        [external_rule!("$", ContextWindow)]
    ),
    scalar_schema!(
        "conversation_history_budget",
        Count,
        int_domain!(0, 10_000_000, "tokens"),
        [external_rule!("$", ContextWindow)]
    ),
    scalar_schema!(
        "tool_result_history_budget",
        Count,
        int_domain!(0, 10_000_000, "tokens"),
        [external_rule!("$", ContextWindow)]
    ),
    scalar_schema!(
        "multimodal_token_budget",
        Count,
        int_domain!(0, 10_000_000, "tokens"),
        [
            external_rule!("$", ContextWindow),
            external_rule!("$", ProviderCapability)
        ]
    ),
    scalar_schema!(
        "auto_compaction_enable",
        Bool,
        bool_domain!(),
        [external_domain_rule!("$", ContextWindow)]
    ),
    object_schema!(
        "compaction_cooldown_hysteresis",
        [
            scalar_field!("cooldown_turns", true, int_domain!(0, 10_000, "turns")),
            scalar_field!("enter_ratio", true, decimal_domain!(0, 0, 1, 0, 6, "ratio")),
            scalar_field!("exit_ratio", true, decimal_domain!(0, 0, 1, 0, 6, "ratio"))
        ],
        [
            less_equal_rule!("exit_ratio", "enter_ratio"),
            external_rule!("cooldown_turns", ParentTurns)
        ]
    ),
    scalar_schema!(
        "multi_stage_summary_topology",
        Enum,
        finite_enum_domain!("single_stage", "hierarchical", "map_reduce"),
        [external_domain_rule!("$", ContextWindow)]
    ),
    scalar_schema!(
        "summary_consistency_coverage_check",
        Bool,
        bool_domain!(),
        [external_rule!("$", VerificationFloor)]
    ),
    map_schema!(
        "hybrid_retrieval_fusion_weights",
        1,
        8,
        finite_enum_domain!("lexical", "vector", "structural", "reranker"),
        crate::FieldDomain::Scalar {
            domain: decimal_domain!(0, 0, 1, 0, 6, "weight")
        },
        []
    ),
    scalar_schema!(
        "retrieval_recency_decay",
        Ratio,
        decimal_domain!(0, 0, 1, 0, 6, "ratio"),
        [external_rule!("$", TenantScope)]
    ),
    scalar_schema!(
        "context_novelty_dedup_threshold",
        Ratio,
        decimal_domain!(0, 0, 1, 0, 6, "ratio"),
        [external_rule!("$", ContextWindow)]
    ),
    scalar_schema!(
        "persistent_pty_backend",
        Enum,
        finite_enum_domain!("disabled", "one_shot", "persistent"),
        [
            external_domain_rule!("$", ProcessBudget),
            external_rule!("$", OperatorAuthority)
        ]
    ),
    scalar_schema!(
        "concurrent_background_job_cap",
        Count,
        int_domain!(0, 1024, "jobs"),
        [external_rule!("$", ProcessBudget)]
    ),
    scalar_schema!(
        "job_idle_stall_timeout",
        Duration,
        int_domain!(1, 86_400_000, "milliseconds"),
        [external_rule!("$", ParentWall)]
    ),
];
