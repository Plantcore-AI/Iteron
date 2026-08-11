use crate::ValueSchema;

pub(super) const VALUE_SCHEMAS: [ValueSchema; 30] = [
    scalar_schema!(
        "provider",
        Enum,
        catalog_enum_domain!("providers"),
        [external_rule!("$", ProviderCapability)]
    ),
    scalar_schema!(
        "model",
        Enum,
        catalog_enum_domain!("models"),
        [external_rule!("$", ProviderCapability)]
    ),
    scalar_schema!(
        "base_url",
        String,
        text_domain!(1, 2048, Uri),
        [external_rule!("$", OperatorAuthority)]
    ),
    scalar_schema!(
        "effort",
        Enum,
        finite_enum_domain!("low", "medium", "high", "xhigh", "max", "ultracode"),
        [external_rule!("$", OperatorAuthority)]
    ),
    scalar_schema!(
        "max_turns",
        Count,
        int_domain!(1, 1_000_000, "turns"),
        [external_rule!("$", ParentTurns)]
    ),
    scalar_schema!(
        "max_usd",
        Decimal,
        decimal_domain!(0, 0, 1_000_000_000, 0, 6, "usd"),
        [external_rule!("$", ParentCost)]
    ),
    scalar_schema!(
        "max_tokens",
        Count,
        int_domain!(1, 1_000_000_000, "tokens"),
        [external_rule!("$", ParentTokens)]
    ),
    scalar_schema!(
        "max_wall_secs",
        Duration,
        int_domain!(1, 86_400, "seconds"),
        [external_rule!("$", ParentWall)]
    ),
    scalar_schema!(
        "allow_code",
        Bool,
        bool_domain!(),
        [external_rule!("$", OperatorAuthority)]
    ),
    scalar_schema!(
        "permission_mode",
        Enum,
        finite_enum_domain!("default", "acceptEdits", "plan", "yolo"),
        [external_rule!("$", OperatorAuthority)]
    ),
    map_schema!(
        "permission_rules",
        0,
        256,
        text_domain!(1, 96, NamespacedId),
        crate::FieldDomain::Scalar {
            domain: finite_enum_domain!("allow", "ask", "deny")
        },
        [external_rule!("$", OperatorAuthority)]
    ),
    scalar_schema!(
        "bypass_permissions",
        Bool,
        bool_domain!(),
        [external_rule!("$", OperatorAuthority)]
    ),
    object_schema!(
        "compaction_trigger",
        [
            scalar_field!("mode", true, finite_enum_domain!("adaptive", "fixed")),
            scalar_field!(
                "usable_window_ratio",
                true,
                decimal_domain!(1, 2, 9, 1, 4, "ratio")
            ),
            scalar_field!(
                "fallback_trigger_tokens",
                true,
                int_domain!(1, 2_000_000, "tokens")
            ),
            scalar_field!(
                "output_reserve_tokens",
                true,
                int_domain!(0, 1_000_000, "tokens")
            )
        ],
        [
            external_rule!("fallback_trigger_tokens", ContextWindow),
            external_rule!("output_reserve_tokens", ProviderCapability)
        ]
    ),
    scalar_schema!(
        "verify_command",
        String,
        text_domain!(1, 4096, Command),
        [
            external_rule!("$", OperatorAuthority),
            external_rule!("$", VerificationFloor)
        ]
    ),
    scalar_schema!(
        "retry_backoff_base",
        Duration,
        int_domain!(1, 30_000, "milliseconds"),
        [external_rule!("$", ParentWall)]
    ),
    scalar_schema!(
        "retry_backoff_cap",
        Duration,
        int_domain!(1, 60_000, "milliseconds"),
        [external_rule!("$", ParentWall)]
    ),
    scalar_schema!(
        "retry_max_attempts",
        Count,
        int_domain!(1, 10, "attempts"),
        [external_rule!("$", RunBudget)]
    ),
    list_schema!(
        "egress_allow",
        0,
        256,
        true,
        text_domain!(1, 253, NamespacedId),
        [external_rule!("$", OperatorAuthority)]
    ),
    scalar_schema!(
        "request_output_cap",
        Count,
        int_domain!(1, 1_000_000, "tokens"),
        [
            external_rule!("$", ProviderCapability),
            external_rule!("$", ParentTokens)
        ]
    ),
    map_schema!(
        "effort_reasoning_map",
        6,
        6,
        finite_enum_domain!("low", "medium", "high", "xhigh", "max", "ultracode"),
        crate::FieldDomain::Scalar {
            domain: catalog_enum_domain!("provider-reasoning-levels")
        },
        [external_rule!("$", ProviderCapability)]
    ),
    map_schema!(
        "thinking_map",
        6,
        6,
        finite_enum_domain!("low", "medium", "high", "xhigh", "max", "ultracode"),
        crate::FieldDomain::Scalar {
            domain: int_domain!(0, 1_000_000, "tokens")
        },
        [
            external_rule!("$", ProviderCapability),
            external_domain_rule!("$", ParentTokens)
        ]
    ),
    map_schema!(
        "orchestration_map",
        6,
        6,
        finite_enum_domain!("low", "medium", "high", "xhigh", "max", "ultracode"),
        crate::FieldDomain::Scalar {
            domain: finite_enum_domain!("direct", "orchestrated")
        },
        [external_rule!("$", OperatorAuthority)]
    ),
    scalar_schema!(
        "prompt_cache",
        Bool,
        bool_domain!(),
        [external_rule!("$", ProviderCapability)]
    ),
    object_schema!(
        "compaction_adaptive",
        [
            scalar_field!(
                "usable_window_ratio",
                true,
                decimal_domain!(1, 2, 9, 1, 4, "ratio")
            ),
            scalar_field!(
                "keep_recent_messages",
                true,
                int_domain!(0, 1024, "messages")
            ),
            scalar_field!(
                "output_reserve_tokens",
                true,
                int_domain!(0, 1_000_000, "tokens")
            )
        ],
        [external_rule!("output_reserve_tokens", ContextWindow)]
    ),
    scalar_schema!(
        "compaction_keep_recent",
        Count,
        int_domain!(0, 1024, "messages"),
        [external_rule!("$", ContextWindow)]
    ),
    object_schema!(
        "token_estimator",
        [
            scalar_field!("estimator", true, catalog_enum_domain!("token-estimators")),
            scalar_field!(
                "safety_margin",
                true,
                decimal_domain!(0, 0, 0, 0, 0, "ratio")
            )
        ],
        []
    ),
    object_schema!(
        "summary_profile",
        [
            scalar_field!(
                "max_output_tokens",
                true,
                int_domain!(1, 1_000_000, "tokens")
            ),
            scalar_field!(
                "effort",
                true,
                finite_enum_domain!("low", "medium", "high", "xhigh", "max", "ultracode")
            ),
            scalar_field!("preserve_tool_evidence", true, bool_domain!())
        ],
        [
            external_rule!("max_output_tokens", ParentTokens),
            external_domain_rule!("effort", ParentTokens)
        ]
    ),
    scalar_schema!(
        "compaction_failure",
        Enum,
        finite_enum_domain!("fail_closed", "retain_original", "truncate_bounded"),
        [external_domain_rule!("$", ContextWindow)]
    ),
    object_schema!(
        "instruction_discovery_render",
        [
            scalar_field!("max_depth", true, int_domain!(0, 64, "levels")),
            scalar_field!("max_files", true, int_domain!(1, 1024, "files")),
            scalar_field!("per_file_bytes", true, int_domain!(1, 1_048_576, "bytes")),
            scalar_field!("total_bytes", true, int_domain!(1, 8_388_608, "bytes"))
        ],
        [
            less_equal_rule!("per_file_bytes", "total_bytes"),
            external_rule!("total_bytes", ToolBudget)
        ]
    ),
    scalar_schema!(
        "memory_enable",
        Bool,
        bool_domain!(),
        [external_rule!("$", TenantScope)]
    ),
];
