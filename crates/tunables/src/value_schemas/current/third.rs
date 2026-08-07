use crate::ValueSchema;

pub(super) const VALUE_SCHEMAS: [ValueSchema; 25] = [
    object_schema!(
        "direct_child_allocation",
        [
            scalar_field!("turns", true, int_domain!(1, 1_000_000, "turns")),
            scalar_field!("tokens", true, int_domain!(1, 1_000_000_000, "tokens")),
            scalar_field!("wall_seconds", true, int_domain!(1, 86_400, "seconds"))
        ],
        [
            external_rule!("turns", ParentTurns),
            external_rule!("tokens", ParentTokens),
            external_rule!("wall_seconds", ParentWall)
        ]
    ),
    scalar_schema!(
        "subagent_effort_inheritance",
        Enum,
        finite_enum_domain!("low", "medium", "high", "xhigh", "max", "ultracode"),
        [external_rule!("$", ProviderCapability)]
    ),
    scalar_schema!(
        "report_budget",
        Bytes,
        int_domain!(1, 16_777_216, "bytes"),
        [external_rule!("$", ContextWindow)]
    ),
    object_schema!(
        "join_reduce",
        [
            scalar_field!("join", true, finite_enum_domain!("wait_all", "fail_fast")),
            scalar_field!(
                "order",
                true,
                finite_enum_domain!("declaration", "completion")
            ),
            scalar_field!("include_failed_evidence", true, bool_domain!())
        ],
        [external_rule!("include_failed_evidence", VerificationFloor)]
    ),
    object_schema!(
        "workflow_aggregate",
        [
            scalar_field!("max_calls", true, int_domain!(1, 1_000_000, "calls")),
            scalar_field!("max_tokens", true, int_domain!(1, 1_000_000_000, "tokens")),
            scalar_field!("max_wall_seconds", true, int_domain!(1, 86_400, "seconds")),
            scalar_field!("max_concurrency", true, int_domain!(1, 1024, "tasks"))
        ],
        [
            external_rule!("max_calls", RunBudget),
            external_rule!("max_tokens", ParentTokens),
            external_rule!("max_wall_seconds", ParentWall)
        ]
    ),
    object_schema!(
        "schema_retry_jitter",
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
                int_domain!(0, 60_000, "milliseconds")
            )
        ],
        [
            less_equal_rule!("base_milliseconds", "cap_milliseconds"),
            external_rule!("cap_milliseconds", ParentWall)
        ]
    ),
    scalar_schema!(
        "provider_connect_tls_timeout",
        Duration,
        int_domain!(1, 86_400, "seconds"),
        [external_rule!("$", ParentWall)]
    ),
    object_schema!(
        "multimodal_input_admission_decode_envelope",
        [
            scalar_field!("max_images", true, int_domain!(0, 64, "images")),
            scalar_field!(
                "per_image_raw_bytes",
                true,
                int_domain!(1, 67_108_864, "bytes")
            ),
            scalar_field!(
                "aggregate_raw_bytes",
                true,
                int_domain!(1, 268_435_456, "bytes")
            ),
            scalar_field!("max_dimension", true, int_domain!(1, 65_536, "pixels")),
            scalar_field!("max_frames", true, int_domain!(1, 4096, "frames"))
        ],
        [
            less_equal_rule!("per_image_raw_bytes", "aggregate_raw_bytes"),
            external_rule!("aggregate_raw_bytes", ContextWindow),
            external_rule!("max_images", ProviderCapability)
        ]
    ),
    object_schema!(
        "app_server_sq_eq_backpressure",
        [
            scalar_field!(
                "submission_entries",
                true,
                int_domain!(1, 65_536, "entries")
            ),
            scalar_field!(
                "submission_bytes",
                true,
                int_domain!(1, 268_435_456, "bytes")
            ),
            scalar_field!("event_entries", true, int_domain!(1, 65_536, "entries")),
            scalar_field!(
                "cosmetic_overflow",
                true,
                finite_enum_domain!("drop", "coalesce")
            ),
            scalar_field!(
                "authoritative_overflow",
                true,
                finite_enum_domain!("wait", "reject")
            )
        ],
        [
            external_rule!("submission_entries", RunBudget),
            external_rule!("event_entries", RunBudget)
        ]
    ),
    object_schema!(
        "provider_discovery_account_probe_cache_policy",
        [
            scalar_field!(
                "eager_budget_milliseconds",
                true,
                int_domain!(1, 60_000, "milliseconds")
            ),
            scalar_field!(
                "positive_ttl_seconds",
                true,
                int_domain!(0, 86_400, "seconds")
            ),
            scalar_field!(
                "failure_backoff_base_seconds",
                true,
                int_domain!(1, 86_400, "seconds")
            ),
            scalar_field!(
                "failure_backoff_cap_seconds",
                true,
                int_domain!(1, 604_800, "seconds")
            )
        ],
        [
            less_equal_rule!(
                "failure_backoff_base_seconds",
                "failure_backoff_cap_seconds"
            ),
            external_rule!("eager_budget_milliseconds", ParentWall)
        ]
    ),
    scalar_schema!(
        "operator_prompt_stream",
        String,
        text_domain!(1, 1_048_576, Utf8),
        [
            external_domain_rule!("$", ContextWindow),
            external_rule!("$", OperatorAuthority)
        ]
    ),
    catalog_schema!(
        "builtin_prompt_corpus",
        1024,
        [
            scalar_field!("id", true, text_domain!(1, 96, NamespacedId)),
            scalar_field!("version", true, text_domain!(1, 64, Semver)),
            scalar_field!("sha256", true, text_domain!(64, 64, Sha256)),
            scalar_field!("max_render_bytes", true, int_domain!(1, 1_048_576, "bytes"))
        ],
        [external_catalog_rule!("max_render_bytes", ContextWindow)]
    ),
    catalog_schema!(
        "instruction_bundle",
        4096,
        [
            scalar_field!("path", true, text_domain!(1, 4096, Path)),
            scalar_field!("trust", true, finite_enum_domain!("operator", "repository")),
            scalar_field!("sha256", true, text_domain!(64, 64, Sha256)),
            scalar_field!("max_bytes", true, int_domain!(1, 1_048_576, "bytes"))
        ],
        [external_catalog_rule!("max_bytes", ContextWindow)]
    ),
    catalog_schema!(
        "memory_corpus",
        100_000,
        [
            scalar_field!("id", true, text_domain!(1, 96, NamespacedId)),
            scalar_field!(
                "scope",
                true,
                finite_enum_domain!("session", "repository", "tenant")
            ),
            scalar_field!("sha256", true, text_domain!(64, 64, Sha256)),
            scalar_field!("max_bytes", true, int_domain!(1, 1_048_576, "bytes"))
        ],
        [
            external_catalog_rule!("scope", TenantScope),
            external_catalog_rule!("max_bytes", ContextWindow)
        ]
    ),
    catalog_schema!(
        "skill_catalog",
        10_000,
        [
            scalar_field!("name", true, text_domain!(1, 96, NamespacedId)),
            scalar_field!("version", true, text_domain!(1, 64, Semver)),
            scalar_field!("sha256", true, text_domain!(64, 64, Sha256)),
            list_field!(
                "tools",
                true,
                0,
                256,
                true,
                text_domain!(1, 96, NamespacedId)
            )
        ],
        [external_catalog_rule!("tools", OperatorAuthority)]
    ),
    catalog_schema!(
        "agent_catalog",
        4096,
        [
            scalar_field!("name", true, text_domain!(1, 96, NamespacedId)),
            scalar_field!("version", true, text_domain!(1, 64, Semver)),
            scalar_field!("sha256", true, text_domain!(64, 64, Sha256)),
            list_field!(
                "requested_tools",
                true,
                0,
                256,
                true,
                text_domain!(1, 96, NamespacedId)
            )
        ],
        [external_catalog_rule!("requested_tools", OperatorAuthority)]
    ),
    catalog_schema!(
        "provider_model_capability_catalog",
        100_000,
        [
            scalar_field!("route_id", true, text_domain!(1, 96, NamespacedId)),
            scalar_field!("model_id", true, text_domain!(1, 256, Identifier)),
            scalar_field!("context_window", true, int_domain!(1, 10_000_000, "tokens")),
            scalar_field!(
                "max_output_tokens",
                true,
                int_domain!(1, 1_000_000, "tokens")
            ),
            scalar_field!("image_input", true, bool_domain!()),
            scalar_field!("evidence_sha256", true, text_domain!(64, 64, Sha256))
        ],
        [less_equal_rule!("max_output_tokens", "context_window")]
    ),
    catalog_schema!(
        "mcp_topology_tool_catalog",
        10_000,
        [
            scalar_field!("server_id", true, text_domain!(1, 96, NamespacedId)),
            scalar_field!("transport", true, finite_enum_domain!("stdio", "http")),
            scalar_field!("tool_name", true, text_domain!(1, 96, NamespacedId)),
            scalar_field!("schema_sha256", true, text_domain!(64, 64, Sha256))
        ],
        [external_catalog_rule!("transport", OperatorAuthority)]
    ),
    map_schema!(
        "hooks_map",
        0,
        256,
        finite_enum_domain!(
            "run_start",
            "turn_start",
            "tool_start",
            "tool_end",
            "run_end"
        ),
        crate::FieldDomain::Object {
            fields: &[
                scalar_field!("matcher", true, text_domain!(1, 1024, Regex)),
                scalar_field!("command", true, text_domain!(1, 4096, Command)),
                scalar_field!("timeout_seconds", true, int_domain!(1, 3600, "seconds"))
            ],
            additional_fields: false
        },
        [external_rule!("$", OperatorAuthority)]
    ),
    map_schema!(
        "workflow_graph",
        1,
        4096,
        text_domain!(1, 96, NamespacedId),
        crate::FieldDomain::Object {
            fields: &[
                list_field!(
                    "dependencies",
                    true,
                    0,
                    4096,
                    true,
                    text_domain!(1, 96, NamespacedId)
                ),
                scalar_field!("action", true, text_domain!(1, 4096, Identifier)),
                scalar_field!("max_attempts", true, int_domain!(1, 64, "attempts"))
            ],
            additional_fields: false
        },
        [external_domain_rule!("$", RunBudget)]
    ),
    catalog_schema!(
        "tool_action_space",
        10_000,
        [
            scalar_field!("name", true, text_domain!(1, 96, NamespacedId)),
            scalar_field!(
                "capability",
                true,
                catalog_enum_domain!("tool-capabilities")
            ),
            scalar_field!(
                "effect_class",
                true,
                finite_enum_domain!(
                    "pure",
                    "reversible_local",
                    "code_executing",
                    "trust_mutating",
                    "irreversible_external"
                )
            ),
            scalar_field!("schema_sha256", true, text_domain!(64, 64, Sha256))
        ],
        [external_catalog_rule!("capability", OperatorAuthority)]
    ),
    catalog_schema!(
        "rate_card_catalog",
        100_000,
        [
            scalar_field!("route_id", true, text_domain!(1, 96, NamespacedId)),
            scalar_field!(
                "input_microusd_per_million",
                true,
                int_domain!(0, 1_000_000_000, "microusd")
            ),
            scalar_field!(
                "output_microusd_per_million",
                true,
                int_domain!(0, 1_000_000_000, "microusd")
            ),
            scalar_field!("signature_sha256", true, text_domain!(64, 64, Sha256))
        ],
        [external_catalog_rule!(
            "signature_sha256",
            BenchmarkProtocol
        )]
    ),
    catalog_schema!(
        "router_lexicons",
        100_000,
        [
            scalar_field!("phrase", true, text_domain!(1, 1024, Utf8)),
            scalar_field!("route", true, text_domain!(1, 96, NamespacedId)),
            scalar_field!("weight", true, decimal_domain!(-1, 0, 1, 0, 6, "weight")),
            scalar_field!("version", true, text_domain!(1, 64, Semver))
        ],
        [external_catalog_rule!("version", BenchmarkProtocol)]
    ),
    map_schema!(
        "environment_snapshot",
        0,
        4096,
        text_domain!(1, 96, NamespacedId),
        crate::FieldDomain::Scalar {
            domain: text_domain!(0, 16_384, Utf8)
        },
        [external_rule!("$", TenantScope)]
    ),
    catalog_schema!(
        "web_search_backend_catalog",
        1024,
        [
            scalar_field!("backend_id", true, text_domain!(1, 96, NamespacedId)),
            scalar_field!("endpoint", true, text_domain!(1, 2048, Uri)),
            scalar_field!("timeout_seconds", true, int_domain!(1, 300, "seconds")),
            scalar_field!("max_results", true, int_domain!(1, 1000, "results"))
        ],
        [
            external_catalog_rule!("endpoint", OperatorAuthority),
            external_catalog_rule!("timeout_seconds", ParentWall)
        ]
    ),
];
