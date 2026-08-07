use crate::{ActivationSpec, SourceSpec};

macro_rules! binding {
    ($kind:ident, $trust:ident, $locator:literal) => {
        crate::SourceBinding {
            kind: crate::SourceKind::$kind,
            trust: crate::SourceTrust::$trust,
            locator: $locator,
        }
    };
}

macro_rules! source {
    ($kind:ident, $trust:ident, $locator:literal) => {
        crate::SourceSpec {
            bindings: &[binding!($kind, $trust, $locator)],
        }
    };
    ([$(($kind:ident, $trust:ident, $locator:literal)),+ $(,)?]) => {
        crate::SourceSpec {
            bindings: &[$(binding!($kind, $trust, $locator)),+],
        }
    };
}

macro_rules! always {
    () => {
        crate::ActivationSpec {
            predicate: crate::ActivationPredicate::Always,
            inactive_reason: None,
        }
    };
}

macro_rules! configured {
    ($($source:ident),+ $(,)?) => {
        crate::ActivationSpec {
            predicate: crate::ActivationPredicate::Configured {
                sources: &[$(crate::SourceKind::$source),+],
            },
            inactive_reason: Some(crate::InactiveReason::ConfigurationAbsent),
        }
    };
}

macro_rules! runtime_derived {
    ($seam:literal) => {
        crate::ActivationSpec {
            predicate: crate::ActivationPredicate::RuntimeDerived { seam: $seam },
            inactive_reason: Some(crate::InactiveReason::GroupedOrIncompleteSeam),
        }
    };
}

macro_rules! unavailable {
    () => {
        crate::ActivationSpec {
            predicate: crate::ActivationPredicate::Unavailable,
            inactive_reason: Some(crate::InactiveReason::NotImplemented),
        }
    };
}

#[rustfmt::skip]
pub(super) const SOURCES: [SourceSpec; crate::EXPECTED_FAMILY_COUNT] = [
    source!([(Cli, Operator, "crates/cli/src/main.rs"), (Environment, Operator, "CORE_PROVIDER"), (UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/cli/src/main.rs")]), // 1 provider
    source!([(Cli, Operator, "crates/cli/src/main.rs"), (Environment, Operator, "CORE_MODEL"), (UserConfig, Operator, "crates/cli/src/config.rs"), (ProjectConfig, Repository, ".core/config.json"), (Builtin, Builtin, "crates/provider/src/static_metadata.rs")]), // 2 model
    source!([(Cli, Operator, "crates/cli/src/main.rs"), (Environment, Operator, "CORE_BASE_URL"), (UserConfig, Operator, "crates/cli/src/config.rs")]), // 3 base_url
    source!([(Cli, Operator, "crates/cli/src/main.rs"), (Environment, Operator, "CORE_EFFORT"), (UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/protocol/src/lib.rs")]), // 4 effort
    source!([(Cli, Operator, "crates/cli/src/main.rs"), (UserConfig, Operator, "crates/cli/src/config.rs"), (ProjectConfig, Repository, ".core/config.json"), (Builtin, Builtin, "crates/protocol/src/lib.rs")]), // 5 max_turns
    source!(UserConfig, Operator, "crates/cli/src/config.rs"), // 6 max_usd
    source!(Cli, Operator, "crates/cli/src/main.rs"), // 7 max_tokens
    source!(UserConfig, Operator, "crates/cli/src/config.rs"), // 8 max_wall_secs
    source!(UserConfig, Operator, "crates/cli/src/config.rs"), // 9 allow_code
    source!(UserConfig, Operator, "crates/cli/src/config.rs"), // 10 permission_mode
    source!(UserConfig, Operator, "crates/cli/src/config.rs"), // 11 permission_rules
    source!(Cli, Operator, "crates/cli/src/main.rs"), // 12 bypass_permissions
    source!(UserConfig, Operator, "crates/cli/src/config.rs"), // 13 compaction_trigger
    source!(UserConfig, Operator, "crates/cli/src/config.rs"), // 14 verify_command
    source!([(Environment, Operator, "CORE_RETRY_BASE_MS"), (UserConfig, Operator, "retry.base_ms"), (Builtin, Builtin, "core_sched::BackoffPolicy::default")]), // 15 retry_backoff_base
    source!([(Environment, Operator, "CORE_RETRY_CAP_MS"), (UserConfig, Operator, "retry.cap_ms"), (Builtin, Builtin, "core_sched::BackoffPolicy::default")]), // 16 retry_backoff_cap
    source!([(Environment, Operator, "CORE_RETRY_MAX_ATTEMPTS"), (UserConfig, Operator, "retry.max_attempts"), (Builtin, Builtin, "core_sched::BackoffPolicy::default")]), // 17 retry_max_attempts
    source!(ProjectConfig, Repository, "crates/cli/src/config.rs"), // 18 egress_allow
    source!([(ExternalProvider, ProviderAttested, "fresh model metadata"), (Catalog, Repository, "crates/provider/src/static_metadata.rs"), (RuntimeObservation, RuntimeObservation, "validated provider cache"), (UserConfig, Operator, "operator-declared model metadata")]), // 19 request_output_cap
    source!(Builtin, Builtin, "crates/cli/src/providers.rs"), // 20 effort_reasoning_map
    source!(Builtin, Builtin, "crates/cli/src/providers.rs"), // 21 thinking_map
    source!(Builtin, Builtin, "crates/cli/src/runtime.rs"), // 22 orchestration_map
    source!([(RustBuilder, Operator, "core_provider::ProviderInstance::with_prompt_cache"), (Builtin, Builtin, "core_provider::ProviderInstance::new")]), // 23 prompt_cache
    source!(DerivedPolicy, Builtin, "crates/ctx/src/compact.rs"), // 24 compaction_adaptive
    source!(Builtin, Builtin, "crates/ctx/src/compact.rs"), // 25 compaction_keep_recent
    source!(Builtin, Builtin, "crates/ctx/src/lib.rs"), // 26 token_estimator
    source!(Builtin, Builtin, "crates/ctx/src/compact.rs"), // 27 summary_profile
    source!(Builtin, Builtin, "crates/ctx/src/compact.rs"), // 28 compaction_failure
    source!(Builtin, Builtin, "crates/ctx/src/instructions.rs"), // 29 instruction_discovery_render
    source!(UserConfig, Operator, "crates/cli/src/config.rs"), // 30 memory_enable
    source!(Builtin, Builtin, "crates/ctx/src/memory.rs"), // 31 memory_budgets
    source!(Builtin, Builtin, "crates/ctx/src/memory.rs"), // 32 bm25
    source!(Builtin, Builtin, "crates/ctx/src/skills.rs"), // 33 skill_listing_budget
    source!(Builtin, Builtin, "crates/protocol/src/lib.rs"), // 34 max_consecutive_tool_errors
    source!(Builtin, Builtin, "crates/tools/src/lib.rs"), // 35 pure_overlap
    source!(Builtin, Builtin, "crates/tools/src/lib.rs"), // 36 pure_concurrency
    source!(Builtin, Builtin, "crates/cli/src/runtime.rs"), // 37 failed_action_dedup
    source!(Builtin, Builtin, "crates/tools/src/lib.rs"), // 38 pure_memo_cache
    source!(Builtin, Builtin, "crates/tools/src/shell.rs"), // 39 shell_timeout_output
    source!(Builtin, Builtin, "crates/tools/src/fs_tools.rs"), // 40 read_file_limits
    source!(Builtin, Builtin, "crates/tools/src/fs_tools.rs"), // 41 list_dir_limits
    source!(Builtin, Builtin, "crates/tools/src/fs_tools.rs"), // 42 glob_limits
    source!(Builtin, Builtin, "crates/tools/src/grep_tool.rs"), // 43 grep_limits
    source!(Builtin, Builtin, "crates/tools/src/fs_tools.rs"), // 44 repo_map
    source!(Builtin, Builtin, "crates/tools/src/git.rs"), // 45 git_limits
    source!(Builtin, Builtin, "crates/tools/src/web.rs"), // 46 web_fetch_limits
    source!(Builtin, Builtin, "crates/tools/src/web.rs"), // 47 web_search_cap
    source!(Builtin, Builtin, "crates/verify/src/lib.rs"), // 48 verifier_attempts
    source!(Builtin, Builtin, "crates/verify/src/lib.rs"), // 49 verifier_feedback_tails
    source!(Builtin, Builtin, "crates/verify/src/lib.rs"), // 50 verifier_timeout
    source!(DerivedPolicy, Builtin, "crates/cli/src/runtime.rs"), // 51 route_topology
    source!(Builtin, Builtin, "crates/cli/src/runtime.rs"), // 52 decomposition_profile
    source!(Builtin, Builtin, "crates/agents/src/lib.rs"), // 53 fan_breadth
    source!(Builtin, Builtin, "crates/kernel/src/admission.rs"), // 54 admission
    source!(Builtin, Builtin, "crates/cli/src/runtime.rs"), // 55 writer_fan_turn_split
    source!(Builtin, Builtin, "crates/cli/src/runtime.rs"), // 56 worker_min_turns
    source!(Builtin, Builtin, "crates/cli/src/runtime.rs"), // 57 wall_split
    source!(Builtin, Builtin, "crates/cli/src/runtime.rs"), // 58 token_split
    source!(Builtin, Builtin, "crates/agents/src/lib.rs"), // 59 fan_concurrency
    source!(Builtin, Builtin, "crates/kernel/src/admission.rs"), // 60 child_ceiling
    source!(Builtin, Builtin, "crates/cli/src/runtime.rs"), // 61 direct_child_allocation
    source!(Builtin, Builtin, "crates/agents/src/lib.rs"), // 62 subagent_effort_inheritance
    source!(Builtin, Builtin, "crates/agents/src/lib.rs"), // 63 report_budget
    source!(Builtin, Builtin, "crates/workflow/src/lib.rs"), // 64 join_reduce
    source!(Builtin, Builtin, "crates/workflow/src/lib.rs"), // 65 workflow_aggregate
    source!(Builtin, Builtin, "crates/cli/src/runtime.rs"), // 66 schema_retry_jitter
    source!(Builtin, Builtin, "crates/provider/src/catalog.rs"), // 67 provider_connect_tls_timeout
    source!(Builtin, Builtin, "crates/cli/src/image_input.rs"), // 68 multimodal_input_admission_decode_envelope
    source!(Builtin, Builtin, "crates/cli/src/tui/app_server.rs"), // 69 app_server_sq_eq_backpressure
    source!(Builtin, Builtin, "crates/cli/src/providers.rs"), // 70 provider_discovery_account_probe_cache_policy
    source!(OperatorInput, Operator, "core_protocol::Op"), // 71 operator_prompt_stream
    source!(Catalog, Repository, "crates/cli/src/main.rs"), // 72 builtin_prompt_corpus
    source!(ProjectConfig, Repository, "crates/ctx/src/instructions.rs"), // 73 instruction_bundle
    source!(Catalog, Repository, "crates/ctx/src/memory.rs"), // 74 memory_corpus
    source!(Catalog, Repository, "crates/ctx/src/skills.rs"), // 75 skill_catalog
    source!(Catalog, Repository, "crates/agents/src/catalog.rs"), // 76 agent_catalog
    source!([(ExternalProvider, ProviderAttested, "fresh provider discovery"), (Catalog, Repository, "crates/provider/src/static_metadata.rs"), (RuntimeObservation, RuntimeObservation, "validated provider cache"), (UserConfig, Operator, "operator-declared provider metadata")]), // 77 provider_model_capability_catalog
    source!(UserConfig, Operator, "crates/cli/src/mcp.rs"), // 78 mcp_topology_tool_catalog
    source!(UserConfig, Operator, "crates/cli/src/runtime/hooks.rs"), // 79 hooks_map
    source!(Catalog, Repository, "crates/workflow/src/lib.rs"), // 80 workflow_graph
    source!(Catalog, Repository, "crates/tools/src/lib.rs"), // 81 tool_action_space
    source!([(GovernedBundle, GovernedBundle, "signed rate-card bundle"), (Builtin, Builtin, "crates/obs/src/lib.rs")]), // 82 rate_card_catalog
    source!(Builtin, Builtin, "crates/agents/src/decompose.rs"), // 83 router_lexicons
    source!(RuntimeObservation, RuntimeObservation, "crates/protocol/src/context.rs"), // 84 environment_snapshot
    source!(Catalog, Repository, "crates/tools/src/web.rs"), // 85 web_search_backend_catalog
    source!(Registry, RegistryDeclaration, "crates/tunables/src/families.rs"), // 86 model_fallback_chain
    source!(Builtin, Builtin, "crates/provider/src/lib.rs"), // 87 failover_eligible_error_taxonomy
    source!(Registry, RegistryDeclaration, "crates/tunables/src/families.rs"), // 88 route_quality_cost_latency_objective_weights
    source!(RuntimeObservation, RuntimeObservation, "crates/provider/src/catalog.rs"), // 89 provider_health_circuit_breaker_state_policy
    source!(Registry, RegistryDeclaration, "crates/tunables/src/families.rs"), // 90 hedged_request_policy
    source!(Registry, RegistryDeclaration, "crates/tunables/src/families.rs"), // 91 provider_service_tier
    source!(Registry, RegistryDeclaration, "crates/tunables/src/families.rs"), // 92 response_verbosity
    source!(DerivedPolicy, Builtin, "crates/cli/src/runtime/workflow_spawner.rs"), // 93 role_specific_model_map
    source!(Builtin, Builtin, "crates/provider/src/responses.rs"), // 94 provider_request_total_deadline
    source!(Builtin, Builtin, "crates/provider/src/responses.rs"), // 95 stream_idle_watchdog
    source!([(ExternalProvider, ProviderAttested, "fresh model metadata"), (Catalog, Repository, "crates/provider/src/static_metadata.rs"), (RuntimeObservation, RuntimeObservation, "validated provider cache"), (UserConfig, Operator, "operator-declared model metadata")]), // 96 context_window_override_reserve
    source!(Builtin, Builtin, "crates/ctx/src/instructions.rs"), // 97 system_prefix_budget
    source!(DerivedPolicy, Builtin, "crates/ctx/src/compact.rs"), // 98 conversation_history_budget
    source!(DerivedPolicy, Builtin, "crates/cli/src/runtime.rs"), // 99 tool_result_history_budget
    source!(Builtin, Builtin, "crates/cli/src/image_input.rs"), // 100 multimodal_token_budget
    source!(Builtin, Builtin, "crates/ctx/src/compact.rs"), // 101 auto_compaction_enable
    source!(DerivedPolicy, Builtin, "crates/ctx/src/compact.rs"), // 102 compaction_cooldown_hysteresis
    source!(Builtin, Builtin, "crates/ctx/src/compact.rs"), // 103 multi_stage_summary_topology
    source!(Registry, RegistryDeclaration, "crates/tunables/src/families.rs"), // 104 summary_consistency_coverage_check
    source!(Builtin, Builtin, "crates/ctx/src/memory.rs"), // 105 hybrid_retrieval_fusion_weights
    source!(Registry, RegistryDeclaration, "crates/tunables/src/families.rs"), // 106 retrieval_recency_decay
    source!(Builtin, Builtin, "crates/ctx/src/memory.rs"), // 107 context_novelty_dedup_threshold
    source!(Registry, RegistryDeclaration, "crates/tunables/src/families.rs"), // 108 persistent_pty_backend
    source!(Registry, RegistryDeclaration, "crates/tunables/src/families.rs"), // 109 concurrent_background_job_cap
    source!(Registry, RegistryDeclaration, "crates/tunables/src/families.rs"), // 110 job_idle_stall_timeout
    source!(Registry, RegistryDeclaration, "crates/tunables/src/families.rs"), // 111 interactive_stdin_wait_policy
    source!(Builtin, Builtin, "crates/sandbox/src/lib.rs"), // 112 process_signal_kill_escalation
    source!(Builtin, Builtin, "crates/tools/src/shell.rs"), // 113 process_cwd_continuity
    source!(Builtin, Builtin, "crates/sandbox/src/lib.rs"), // 114 child_process_environment_reuse
    source!(DerivedPolicy, Builtin, "crates/cli/src/runtime.rs"), // 115 effecting_tool_concurrency
    source!(Builtin, Builtin, "crates/cli/src/runtime.rs"), // 116 write_set_conflict_admission
    source!(Registry, RegistryDeclaration, "crates/tunables/src/families.rs"), // 117 tool_output_spill_to_disk_policy
    source!([(RuntimeObservation, RuntimeObservation, "selected route image capability"), (Builtin, Builtin, "crates/cli/src/image_input.rs")]), // 118 binary_media_inspection_routing
    source!(Registry, RegistryDeclaration, "crates/tunables/src/families.rs"), // 119 lsp_server_language_selection
    source!(Registry, RegistryDeclaration, "crates/tunables/src/families.rs"), // 120 lsp_timeout_restart_policy
    source!(Registry, RegistryDeclaration, "crates/tunables/src/families.rs"), // 121 lsp_result_context_budget
    source!(Builtin, Builtin, "crates/tools/src/lib.rs"), // 122 tool_result_cache_ttl
    source!(Builtin, Builtin, "crates/verify/src/oracle.rs"), // 123 test_selection_strategy
    source!(DerivedPolicy, Builtin, "crates/verify/src/strategy.rs"), // 124 incremental_versus_full_verification
    source!(Builtin, Builtin, "crates/verify/src/strategy.rs"), // 125 flaky_test_detection_quarantine
    source!(Catalog, Repository, "crates/verify/src/oracle.rs"), // 126 failure_classification_taxonomy
    source!(DerivedPolicy, Builtin, "crates/cli/src/runtime.rs"), // 127 retry_eligibility_policy
    source!(Registry, RegistryDeclaration, "crates/tunables/src/families.rs"), // 128 rollback_on_verification_failure
    source!(DerivedPolicy, Builtin, "crates/cli/src/runtime.rs"), // 129 workspace_checkpoint_cadence
    source!(Builtin, Builtin, "crates/record/src/checkpoint.rs"), // 130 selective_restore_scope
    source!(Builtin, Builtin, "crates/verify/src/strategy.rs"), // 131 verification_quorum_consensus
    source!(Builtin, Builtin, "crates/cli/src/runtime.rs"), // 132 recovery_escalation_policy
    source!(DerivedPolicy, Builtin, "crates/cli/src/runtime/workflow_spawner.rs"), // 133 per_agent_model
    source!(DerivedPolicy, Builtin, "crates/cli/src/runtime/workflow_spawner.rs"), // 134 per_agent_effort_thinking
    source!(DerivedPolicy, Builtin, "crates/cli/src/runtime/workflow_spawner.rs"), // 135 per_agent_tool_profile
    source!(Builtin, Builtin, "crates/cli/src/runtime/workflow_spawner.rs"), // 136 per_agent_memory_scope
    source!(Builtin, Builtin, "crates/cli/src/runtime/workflow_spawner.rs"), // 137 spawn_depth_control
    source!(Builtin, Builtin, "crates/workflow/src/lib.rs"), // 138 per_session_spawn_cap
    source!(Builtin, Builtin, "crates/workflow/src/bindings.rs"), // 139 task_priority_scheduling
    source!(Registry, RegistryDeclaration, "crates/tunables/src/families.rs"), // 140 speculative_sibling_count
    source!(Registry, RegistryDeclaration, "crates/tunables/src/families.rs"), // 141 speculative_sibling_cancellation
    source!(Builtin, Builtin, "crates/agents/src/reduce.rs"), // 142 early_stop_quorum_policy
    source!(Registry, RegistryDeclaration, "crates/tunables/src/families.rs"), // 143 writer_worktree_isolation_mode
    source!(Registry, RegistryDeclaration, "crates/tunables/src/families.rs"), // 144 merge_conflict_arbitration
    source!(Builtin, Builtin, "crates/agents/src/reduce.rs"), // 145 inter_agent_messaging_topology
    source!(Registry, RegistryDeclaration, "crates/tunables/src/families.rs"), // 146 task_retry_reassignment_policy
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/mcp/src/http/reqwest_exchange.rs")]), // 147 mcp_transport_selection
    source!(Builtin, Builtin, "crates/cli/src/mcp.rs"), // 148 deferred_discovery_threshold
    source!(Registry, RegistryDeclaration, "crates/tunables/src/families.rs"), // 149 mcp_reconnect_backoff
    source!(Builtin, Builtin, "crates/mcp/src/client.rs"), // 150 per_server_startup_deadline
    source!(Builtin, Builtin, "crates/mcp/src/client.rs"), // 151 per_tool_mcp_deadline
    source!(Builtin, Builtin, "crates/mcp/src/client/content.rs"), // 152 mcp_result_cap_spill_policy
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/mcp/src/oauth.rs")]), // 153 oauth_auth_lifecycle_policy
    source!(Builtin, Builtin, "crates/mcp/src/client/content.rs"), // 154 resource_prompt_plugin_capability_exposure
    source!(Registry, RegistryDeclaration, "crates/tunables/src/families.rs"), // 155 request_compression_policy
    source!(Builtin, Builtin, "crates/provider/src/catalog.rs"), // 156 http_pool_keepalive_idle_policy
    source!(RuntimeObservation, RuntimeObservation, "crates/cli/src/runtime.rs"), // 157 rate_limit_aware_admission
    source!(Registry, RegistryDeclaration, "crates/tunables/src/families.rs"), // 158 prompt_cache_ttl_breakpoint_strategy
    source!(Builtin, Builtin, "crates/record/src/lib.rs"), // 159 session_isolation_profile
    source!(Builtin, Builtin, "crates/record/src/lib.rs"), // 160 replay_divergence_detection_policy
];

#[rustfmt::skip]
pub(super) const ACTIVATIONS: [ActivationSpec; crate::EXPECTED_FAMILY_COUNT] = [
    always!(), // 1 provider
    always!(), // 2 model
    always!(), // 3 base_url
    always!(), // 4 effort
    always!(), // 5 max_turns
    configured!(UserConfig), // 6 max_usd
    configured!(Cli), // 7 max_tokens
    always!(), // 8 max_wall_secs
    always!(), // 9 allow_code
    always!(), // 10 permission_mode
    always!(), // 11 permission_rules
    always!(), // 12 bypass_permissions
    always!(), // 13 compaction_trigger
    configured!(UserConfig), // 14 verify_command
    runtime_derived!("crates/cli/src/config/retry.rs"), // 15 retry_backoff_base
    runtime_derived!("crates/cli/src/config/retry.rs"), // 16 retry_backoff_cap
    runtime_derived!("crates/cli/src/config/retry.rs"), // 17 retry_max_attempts
    unavailable!(), // 18 egress_allow
    always!(), // 19 request_output_cap
    always!(), // 20 effort_reasoning_map
    always!(), // 21 thinking_map
    always!(), // 22 orchestration_map
    always!(), // 23 prompt_cache
    always!(), // 24 compaction_adaptive
    always!(), // 25 compaction_keep_recent
    always!(), // 26 token_estimator
    runtime_derived!("crates/ctx/src/compact.rs"), // 27 summary_profile
    always!(), // 28 compaction_failure
    runtime_derived!("crates/ctx/src/instructions.rs"), // 29 instruction_discovery_render
    always!(), // 30 memory_enable
    runtime_derived!("crates/ctx/src/memory.rs"), // 31 memory_budgets
    always!(), // 32 bm25
    always!(), // 33 skill_listing_budget
    always!(), // 34 max_consecutive_tool_errors
    always!(), // 35 pure_overlap
    always!(), // 36 pure_concurrency
    always!(), // 37 failed_action_dedup
    always!(), // 38 pure_memo_cache
    runtime_derived!("crates/tools/src/shell.rs"), // 39 shell_timeout_output
    runtime_derived!("crates/tools/src/fs_tools.rs"), // 40 read_file_limits
    runtime_derived!("crates/tools/src/fs_tools.rs"), // 41 list_dir_limits
    runtime_derived!("crates/tools/src/fs_tools.rs"), // 42 glob_limits
    runtime_derived!("crates/tools/src/grep_tool.rs"), // 43 grep_limits
    runtime_derived!("crates/tools/src/fs_tools.rs"), // 44 repo_map
    runtime_derived!("crates/tools/src/git.rs"), // 45 git_limits
    runtime_derived!("crates/tools/src/web.rs"), // 46 web_fetch_limits
    always!(), // 47 web_search_cap
    always!(), // 48 verifier_attempts
    runtime_derived!("crates/verify/src/lib.rs"), // 49 verifier_feedback_tails
    always!(), // 50 verifier_timeout
    always!(), // 51 route_topology
    always!(), // 52 decomposition_profile
    always!(), // 53 fan_breadth
    always!(), // 54 admission
    always!(), // 55 writer_fan_turn_split
    always!(), // 56 worker_min_turns
    always!(), // 57 wall_split
    always!(), // 58 token_split
    always!(), // 59 fan_concurrency
    always!(), // 60 child_ceiling
    runtime_derived!("crates/cli/src/runtime.rs"), // 61 direct_child_allocation
    always!(), // 62 subagent_effort_inheritance
    always!(), // 63 report_budget
    always!(), // 64 join_reduce
    runtime_derived!("crates/workflow/src/lib.rs"), // 65 workflow_aggregate
    runtime_derived!("crates/cli/src/runtime.rs"), // 66 schema_retry_jitter
    always!(), // 67 provider_connect_tls_timeout
    runtime_derived!("crates/cli/src/image_input.rs"), // 68 multimodal_input_admission_decode_envelope
    runtime_derived!("crates/cli/src/tui/app_server.rs"), // 69 app_server_sq_eq_backpressure
    runtime_derived!("crates/cli/src/providers.rs"), // 70 provider_discovery_account_probe_cache_policy
    configured!(OperatorInput), // 71 operator_prompt_stream
    always!(), // 72 builtin_prompt_corpus
    always!(), // 73 instruction_bundle
    always!(), // 74 memory_corpus
    always!(), // 75 skill_catalog
    runtime_derived!("crates/agents/src/catalog.rs"), // 76 agent_catalog
    always!(), // 77 provider_model_capability_catalog
    configured!(UserConfig), // 78 mcp_topology_tool_catalog
    configured!(UserConfig), // 79 hooks_map
    always!(), // 80 workflow_graph
    always!(), // 81 tool_action_space
    always!(), // 82 rate_card_catalog
    always!(), // 83 router_lexicons
    always!(), // 84 environment_snapshot
    configured!(Catalog), // 85 web_search_backend_catalog
    unavailable!(), // 86 model_fallback_chain
    runtime_derived!("crates/provider/src/lib.rs"), // 87 failover_eligible_error_taxonomy
    unavailable!(), // 88 route_quality_cost_latency_objective_weights
    runtime_derived!("crates/provider/src/catalog.rs"), // 89 provider_health_circuit_breaker_state_policy
    unavailable!(), // 90 hedged_request_policy
    unavailable!(), // 91 provider_service_tier
    unavailable!(), // 92 response_verbosity
    runtime_derived!("crates/cli/src/runtime/workflow_spawner.rs"), // 93 role_specific_model_map
    always!(), // 94 provider_request_total_deadline
    always!(), // 95 stream_idle_watchdog
    runtime_derived!("crates/ctx/src/compact.rs"), // 96 context_window_override_reserve
    runtime_derived!("crates/ctx/src/instructions.rs"), // 97 system_prefix_budget
    runtime_derived!("crates/ctx/src/compact.rs"), // 98 conversation_history_budget
    runtime_derived!("crates/cli/src/runtime.rs"), // 99 tool_result_history_budget
    runtime_derived!("crates/cli/src/image_input.rs"), // 100 multimodal_token_budget
    always!(), // 101 auto_compaction_enable
    runtime_derived!("crates/ctx/src/compact.rs"), // 102 compaction_cooldown_hysteresis
    runtime_derived!("crates/ctx/src/compact.rs"), // 103 multi_stage_summary_topology
    unavailable!(), // 104 summary_consistency_coverage_check
    runtime_derived!("crates/ctx/src/memory.rs"), // 105 hybrid_retrieval_fusion_weights
    unavailable!(), // 106 retrieval_recency_decay
    runtime_derived!("crates/ctx/src/memory.rs"), // 107 context_novelty_dedup_threshold
    unavailable!(), // 108 persistent_pty_backend
    unavailable!(), // 109 concurrent_background_job_cap
    unavailable!(), // 110 job_idle_stall_timeout
    unavailable!(), // 111 interactive_stdin_wait_policy
    always!(), // 112 process_signal_kill_escalation
    runtime_derived!("crates/tools/src/shell.rs"), // 113 process_cwd_continuity
    runtime_derived!("crates/sandbox/src/lib.rs"), // 114 child_process_environment_reuse
    always!(), // 115 effecting_tool_concurrency
    always!(), // 116 write_set_conflict_admission
    unavailable!(), // 117 tool_output_spill_to_disk_policy
    runtime_derived!("crates/cli/src/image_input.rs"), // 118 binary_media_inspection_routing
    unavailable!(), // 119 lsp_server_language_selection
    unavailable!(), // 120 lsp_timeout_restart_policy
    unavailable!(), // 121 lsp_result_context_budget
    runtime_derived!("crates/tools/src/lib.rs"), // 122 tool_result_cache_ttl
    always!(), // 123 test_selection_strategy
    runtime_derived!("crates/verify/src/strategy.rs"), // 124 incremental_versus_full_verification
    runtime_derived!("crates/verify/src/strategy.rs"), // 125 flaky_test_detection_quarantine
    always!(), // 126 failure_classification_taxonomy
    always!(), // 127 retry_eligibility_policy
    unavailable!(), // 128 rollback_on_verification_failure
    runtime_derived!("crates/cli/src/runtime.rs"), // 129 workspace_checkpoint_cadence
    runtime_derived!("crates/record/src/checkpoint.rs"), // 130 selective_restore_scope
    runtime_derived!("crates/verify/src/strategy.rs"), // 131 verification_quorum_consensus
    always!(), // 132 recovery_escalation_policy
    always!(), // 133 per_agent_model
    always!(), // 134 per_agent_effort_thinking
    always!(), // 135 per_agent_tool_profile
    runtime_derived!("crates/cli/src/runtime/workflow_spawner.rs"), // 136 per_agent_memory_scope
    always!(), // 137 spawn_depth_control
    runtime_derived!("crates/workflow/src/lib.rs"), // 138 per_session_spawn_cap
    runtime_derived!("crates/workflow/src/bindings.rs"), // 139 task_priority_scheduling
    unavailable!(), // 140 speculative_sibling_count
    unavailable!(), // 141 speculative_sibling_cancellation
    runtime_derived!("crates/agents/src/reduce.rs"), // 142 early_stop_quorum_policy
    unavailable!(), // 143 writer_worktree_isolation_mode
    unavailable!(), // 144 merge_conflict_arbitration
    always!(), // 145 inter_agent_messaging_topology
    unavailable!(), // 146 task_retry_reassignment_policy
    configured!(UserConfig), // 147 mcp_transport_selection
    runtime_derived!("crates/cli/src/mcp.rs"), // 148 deferred_discovery_threshold
    unavailable!(), // 149 mcp_reconnect_backoff
    always!(), // 150 per_server_startup_deadline
    always!(), // 151 per_tool_mcp_deadline
    runtime_derived!("crates/mcp/src/client/content.rs"), // 152 mcp_result_cap_spill_policy
    configured!(UserConfig), // 153 oauth_auth_lifecycle_policy
    runtime_derived!("crates/mcp/src/client/content.rs"), // 154 resource_prompt_plugin_capability_exposure
    unavailable!(), // 155 request_compression_policy
    always!(), // 156 http_pool_keepalive_idle_policy
    unavailable!(), // 157 rate_limit_aware_admission
    unavailable!(), // 158 prompt_cache_ttl_breakpoint_strategy
    runtime_derived!("crates/record/src/lib.rs"), // 159 session_isolation_profile
    always!(), // 160 replay_divergence_detection_policy
];
