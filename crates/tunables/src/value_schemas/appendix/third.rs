use crate::ValueSchema;

pub(super) const VALUE_SCHEMAS: [ValueSchema; 25] = [
    object_schema!(
        "per_agent_memory_scope",
        [
            scalar_field!(
                "mode",
                true,
                finite_enum_domain!("isolated", "shared_read", "shared_read_write")
            ),
            scalar_field!("scope_id", false, text_domain!(1, 96, NamespacedId)),
            scalar_field!("inherit_parent", true, bool_domain!())
        ],
        [external_rule!("scope_id", TenantScope)]
    ),
    scalar_schema!(
        "spawn_depth_control",
        Count,
        int_domain!(0, 64, "levels"),
        [external_rule!("$", RunBudget)]
    ),
    scalar_schema!(
        "per_session_spawn_cap",
        Count,
        int_domain!(0, 100_000, "agents"),
        [external_rule!("$", RunBudget)]
    ),
    object_schema!(
        "task_priority_scheduling",
        [
            scalar_field!("priority_levels", true, int_domain!(1, 256, "levels")),
            scalar_field!(
                "tie_break",
                true,
                finite_enum_domain!("fifo", "declaration_order")
            ),
            scalar_field!("dependency_ready_only", true, bool_domain!())
        ],
        [external_rule!("priority_levels", RunBudget)]
    ),
    scalar_schema!(
        "speculative_sibling_count",
        Count,
        int_domain!(0, 1024, "agents"),
        [
            external_rule!("$", RunBudget),
            external_rule!("$", ParentCost)
        ]
    ),
    object_schema!(
        "speculative_sibling_cancellation",
        [
            scalar_field!(
                "winner_evidence",
                true,
                finite_enum_domain!("first_verified", "quorum", "best_score")
            ),
            scalar_field!("cancel_losers", true, bool_domain!()),
            scalar_field!(
                "cleanup_timeout_seconds",
                true,
                int_domain!(1, 3600, "seconds")
            ),
            scalar_field!("reconcile_unknown_effects", true, bool_domain!())
        ],
        [
            external_rule!("cleanup_timeout_seconds", ParentWall),
            external_rule!("winner_evidence", VerificationFloor)
        ]
    ),
    object_schema!(
        "early_stop_quorum_policy",
        [
            scalar_field!("minimum_evidence", true, int_domain!(1, 1024, "items")),
            scalar_field!("required_roles", true, int_domain!(0, 256, "roles")),
            scalar_field!("strong_veto", true, bool_domain!())
        ],
        [external_rule!("minimum_evidence", VerificationFloor)]
    ),
    scalar_schema!(
        "writer_worktree_isolation_mode",
        Bool,
        bool_domain!(),
        [external_rule!("$", OperatorAuthority)]
    ),
    object_schema!(
        "merge_conflict_arbitration",
        [
            scalar_field!("on_clean", true, finite_enum_domain!("merge", "serialize")),
            scalar_field!(
                "on_conflict",
                true,
                finite_enum_domain!("reject", "operator", "verified_arbitration")
            ),
            scalar_field!("require_verification", true, bool_domain!())
        ],
        [
            external_rule!("on_conflict", OperatorAuthority),
            external_rule!("require_verification", VerificationFloor)
        ]
    ),
    scalar_schema!(
        "inter_agent_messaging_topology",
        Enum,
        finite_enum_domain!("parent_mediated", "peer", "broadcast"),
        [
            external_rule!("$", OperatorAuthority),
            external_domain_rule!("$", RunBudget)
        ]
    ),
    object_schema!(
        "task_retry_reassignment_policy",
        [
            scalar_field!("max_attempts", true, int_domain!(0, 64, "attempts")),
            scalar_field!(
                "on_failure",
                true,
                finite_enum_domain!("stop", "retry_same", "reassign")
            ),
            scalar_field!("preserve_evidence", true, bool_domain!())
        ],
        [
            external_rule!("max_attempts", RunBudget),
            external_rule!("on_failure", OperatorAuthority)
        ]
    ),
    list_schema!(
        "mcp_transport_selection",
        1,
        2,
        true,
        finite_enum_domain!("stdio", "http"),
        [external_rule!("$", OperatorAuthority)]
    ),
    scalar_schema!(
        "deferred_discovery_threshold",
        Count,
        int_domain!(0, 100_000, "tool_schemas"),
        []
    ),
    object_schema!(
        "mcp_reconnect_backoff",
        [
            scalar_field!("max_attempts", true, int_domain!(0, 64, "attempts")),
            scalar_field!(
                "base_milliseconds",
                true,
                int_domain!(0, 60_000, "milliseconds")
            ),
            scalar_field!(
                "cap_milliseconds",
                true,
                int_domain!(0, 3_600_000, "milliseconds")
            )
        ],
        [
            less_equal_rule!("base_milliseconds", "cap_milliseconds"),
            external_rule!("cap_milliseconds", ParentWall)
        ]
    ),
    object_schema!(
        "per_server_startup_deadline",
        [
            scalar_field!(
                "stdio_milliseconds",
                true,
                int_domain!(1, 86_400_000, "milliseconds")
            ),
            scalar_field!(
                "http_milliseconds",
                true,
                int_domain!(1, 86_400_000, "milliseconds")
            )
        ],
        [
            external_rule!("stdio_milliseconds", ParentWall),
            external_rule!("http_milliseconds", ParentWall)
        ]
    ),
    object_schema!(
        "per_tool_mcp_deadline",
        [
            scalar_field!(
                "stdio_milliseconds",
                true,
                int_domain!(1, 86_400_000, "milliseconds")
            ),
            scalar_field!(
                "http_milliseconds",
                true,
                int_domain!(1, 86_400_000, "milliseconds")
            )
        ],
        [
            external_rule!("stdio_milliseconds", ParentWall),
            external_rule!("http_milliseconds", ParentWall)
        ]
    ),
    object_schema!(
        "mcp_result_cap_spill_policy",
        [
            scalar_field!(
                "visible_max_bytes",
                true,
                int_domain!(0, 16_777_216, "bytes")
            ),
            scalar_field!(
                "spill_max_bytes",
                true,
                int_domain!(0, 1_073_741_824, "bytes")
            ),
            scalar_field!(
                "cleanup",
                true,
                finite_enum_domain!("tool_end", "turn_end", "run_end", "session_end")
            ),
            scalar_field!("private_storage", true, bool_domain!())
        ],
        [
            less_equal_rule!("visible_max_bytes", "spill_max_bytes"),
            crate::CrossFieldRule::Equals {
                field: "private_storage",
                value: crate::RuleValue::Boolean { value: true },
            }
        ]
    ),
    object_schema!(
        "oauth_auth_lifecycle_policy",
        [
            scalar_field!(
                "credential_mode",
                true,
                finite_enum_domain!("bearer", "refresh_token", "mixed")
            ),
            scalar_field!("binding_count", true, int_domain!(1, 1024, "bindings")),
            scalar_field!(
                "refresh_binding_count",
                true,
                int_domain!(0, 1024, "bindings")
            ),
            scalar_field!(
                "revocation_binding_count",
                true,
                int_domain!(0, 1024, "bindings")
            ),
            scalar_field!("refresh_before_expiry_when_capable", true, bool_domain!()),
            scalar_field!(
                "retry_once_after_unauthorized_when_capable",
                true,
                bool_domain!()
            ),
            scalar_field!("revoke_access_after_forbidden", true, bool_domain!()),
            scalar_field!("expiry_skew_seconds", true, int_domain!(0, 3600, "seconds")),
            scalar_field!("revocation_endpoint_configured", true, bool_domain!())
        ],
        [
            less_equal_rule!("refresh_binding_count", "binding_count"),
            less_equal_rule!("revocation_binding_count", "refresh_binding_count"),
            crate::CrossFieldRule::Requires {
                if_field: "credential_mode",
                equals: crate::RuleValue::Enum {
                    value: "refresh_token"
                },
                then_field: "refresh_binding_count",
            },
            crate::CrossFieldRule::Requires {
                if_field: "credential_mode",
                equals: crate::RuleValue::Enum { value: "mixed" },
                then_field: "refresh_binding_count",
            },
            crate::CrossFieldRule::Equals {
                field: "revoke_access_after_forbidden",
                value: crate::RuleValue::Boolean { value: true },
            },
            crate::CrossFieldRule::Equals {
                field: "expiry_skew_seconds",
                value: crate::RuleValue::Integer { value: 30 },
            },
            external_rule!("credential_mode", OperatorAuthority)
        ]
    ),
    object_schema_v3!(
        "resource_prompt_plugin_capability_exposure",
        [
            scalar_field!(
                "resource_discovery",
                true,
                finite_enum_domain!("disabled", "lazy")
            ),
            scalar_field!(
                "prompt_discovery",
                true,
                finite_enum_domain!("disabled", "lazy")
            ),
            list_field!(
                "resource_tool_ids",
                true,
                0,
                512,
                true,
                text_domain!(1, 256, Identifier)
            ),
            list_field!(
                "prompt_tool_ids",
                true,
                0,
                512,
                true,
                text_domain!(1, 256, Identifier)
            ),
            list_field!(
                "plugin_binding_ids",
                true,
                0,
                512,
                true,
                text_domain!(1, 256, NamespacedId)
            ),
            list_field!(
                "server_binding_ids",
                true,
                0,
                512,
                true,
                text_domain!(1, 256, NamespacedId)
            ),
            scalar_field!(
                "max_visible_bytes",
                true,
                int_domain!(0, 16_777_216, "bytes")
            )
        ],
        []
    ),
    scalar_schema!(
        "request_compression_policy",
        Enum,
        finite_enum_domain!("none", "gzip", "zstd"),
        [external_rule!("$", ProviderCapability)]
    ),
    object_schema!(
        "http_pool_keepalive_idle_policy",
        [
            scalar_field!("pool_idle_seconds", true, int_domain!(0, 86_400, "seconds")),
            scalar_field!(
                "tcp_keepalive_seconds",
                true,
                int_domain!(0, 86_400, "seconds")
            ),
            scalar_field!("connection_reuse", true, bool_domain!())
        ],
        [external_rule!("pool_idle_seconds", ParentWall)]
    ),
    object_schema!(
        "rate_limit_aware_admission",
        [
            scalar_field!(
                "minimum_remaining_requests",
                true,
                int_domain!(0, 1_000_000_000, "requests")
            ),
            scalar_field!(
                "minimum_remaining_tokens",
                true,
                int_domain!(0, 1_000_000_000, "tokens")
            ),
            scalar_field!(
                "reset_wait_max_seconds",
                true,
                int_domain!(0, 86_400, "seconds")
            ),
            scalar_field!(
                "unknown_quota",
                true,
                finite_enum_domain!("conservative", "reject")
            )
        ],
        [
            external_rule!("minimum_remaining_requests", ProviderCapability),
            external_rule!("reset_wait_max_seconds", ParentWall)
        ]
    ),
    object_schema!(
        "prompt_cache_ttl_breakpoint_strategy",
        [
            scalar_field!("ttl_seconds", true, int_domain!(0, 86_400, "seconds")),
            scalar_field!(
                "breakpoint",
                true,
                finite_enum_domain!("none", "rolling", "explicit")
            ),
            scalar_field!("invalidate_on_tool_change", true, bool_domain!()),
            scalar_field!(
                "scope",
                true,
                finite_enum_domain!("request", "session", "tenant")
            )
        ],
        [
            external_rule!("$", ProviderCapability),
            external_rule!("scope", TenantScope)
        ]
    ),
    scalar_schema!(
        "session_isolation_profile",
        Enum,
        finite_enum_domain!("hermetic", "durable", "interactive"),
        [
            external_rule!("$", OperatorAuthority),
            external_rule!("$", TenantScope)
        ]
    ),
    object_schema!(
        "replay_divergence_detection_policy",
        [
            scalar_field!("verify_hash_chain", true, bool_domain!()),
            scalar_field!("verify_identity_scope", true, bool_domain!()),
            scalar_field!("verify_effect_terminals", true, bool_domain!()),
            scalar_field!("on_divergence", true, finite_enum_domain!("fail_closed"))
        ],
        [external_rule!("on_divergence", BenchmarkProtocol)]
    ),
];
