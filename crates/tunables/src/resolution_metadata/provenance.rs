use crate::{ActivationSpec, SourceSpec};

macro_rules! binding {
    ($kind:ident, $trust:ident, $locator:literal) => {
        crate::SourceBinding {
            kind: crate::SourceKind::$kind,
            trust: crate::SourceTrust::$trust,
            locator: $locator,
            merge: crate::SourceMergePolicy::Override,
        }
    };
    ($kind:ident, $trust:ident, $locator:literal, $merge:ident) => {
        crate::SourceBinding {
            kind: crate::SourceKind::$kind,
            trust: crate::SourceTrust::$trust,
            locator: $locator,
            merge: crate::SourceMergePolicy::$merge,
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
    ([$(($kind:ident, $trust:ident, $locator:literal, $merge:ident)),+ $(,)?]) => {
        crate::SourceSpec {
            bindings: &[$(binding!($kind, $trust, $locator, $merge)),+],
        }
    };
    ([$($binding:expr),+ $(,)?]) => {
        crate::SourceSpec {
            bindings: &[$($binding),+],
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

#[rustfmt::skip]
pub(super) const SOURCES: [SourceSpec; crate::EXPECTED_FAMILY_COUNT] = [
    source!([(Cli, Operator, "crates/cli/src/main.rs"), (Environment, Operator, "ITERON_PROVIDER"), (UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/cli/src/main.rs")]), // 1 provider
    source!([binding!(Cli, Operator, "crates/cli/src/main.rs"), binding!(Environment, Operator, "ITERON_MODEL"), binding!(UserConfig, Operator, "crates/cli/src/config.rs"), binding!(ProjectConfig, Repository, ".iteron/config.json", RouteSuggestion), binding!(Builtin, Builtin, "crates/provider/src/static_metadata.rs")]), // 2 model
    source!([(Cli, Operator, "crates/cli/src/main.rs"), (Environment, Operator, "ITERON_BASE_URL"), (UserConfig, Operator, "crates/cli/src/config.rs")]), // 3 base_url
    source!([(Cli, Operator, "crates/cli/src/main.rs"), (Environment, Operator, "ITERON_EFFORT"), (UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/protocol/src/lib.rs")]), // 4 effort
    source!([binding!(Cli, Operator, "crates/cli/src/main.rs"), binding!(Environment, Operator, "ITERON_MAX_TURNS"), binding!(UserConfig, Operator, "crates/cli/src/config.rs"), binding!(ProjectConfig, Repository, ".iteron/config.json", TightenMaximum), binding!(Builtin, Builtin, "crates/protocol/src/lib.rs")]), // 5 max_turns
    source!([binding!(Cli, Operator, "crates/cli/src/main.rs"), binding!(Environment, Operator, "ITERON_MAX_USD"), binding!(UserConfig, Operator, "crates/cli/src/config.rs"), binding!(ProjectConfig, Repository, ".iteron/config.json", TightenMaximum)]), // 6 max_usd
    source!(Cli, Operator, "crates/cli/src/main.rs"), // 7 max_tokens
    source!([binding!(Cli, Operator, "crates/cli/src/main.rs"), binding!(UserConfig, Operator, "crates/cli/src/config.rs"), binding!(ProjectConfig, Repository, ".iteron/config.json", TightenMaximum), binding!(Builtin, Builtin, "crates/protocol/src/lib.rs")]), // 8 max_wall_secs
    source!([binding!(Cli, Operator, "crates/cli/src/main.rs"), binding!(UserConfig, Operator, "crates/cli/src/config.rs"), binding!(ProjectConfig, Repository, ".iteron/config.json", TightenBooleanGrant), binding!(Builtin, Builtin, "crates/cli/src/main.rs")]), // 9 allow_code
    source!([(Cli, Operator, "crates/cli/src/main.rs"), (Builtin, Builtin, "crates/cli/src/main.rs")]), // 10 permission_mode
    source!(UserConfig, Operator, "crates/cli/src/config.rs"), // 11 permission_rules
    source!([(Cli, Operator, "crates/cli/src/main.rs"), (Builtin, Builtin, "crates/cli/src/main.rs")]), // 12 bypass_permissions
    source!(UserConfig, Operator, "crates/cli/src/config.rs"), // 13 compaction_trigger
    source!(Cli, Operator, "crates/cli/src/main.rs"), // 14 verify_command
    source!([(Environment, Operator, "ITERON_RETRY_BASE_MS"), (UserConfig, Operator, "retry.base_ms"), (Builtin, Builtin, "iteron_sched::BackoffPolicy::default")]), // 15 retry_backoff_base
    source!([(Environment, Operator, "ITERON_RETRY_CAP_MS"), (UserConfig, Operator, "retry.cap_ms"), (Builtin, Builtin, "iteron_sched::BackoffPolicy::default")]), // 16 retry_backoff_cap
    source!([(Environment, Operator, "ITERON_RETRY_MAX_ATTEMPTS"), (UserConfig, Operator, "retry.max_attempts"), (Builtin, Builtin, "iteron_sched::BackoffPolicy::default")]), // 17 retry_max_attempts
    source!([binding!(UserConfig, Operator, "crates/cli/src/config.rs"), binding!(ProjectConfig, Repository, ".iteron/config.json", IntersectAllowSet)]), // 18 egress_allow
    source!([(ExternalProvider, ProviderAttested, "fresh model metadata"), (Catalog, Repository, "crates/provider/src/static_metadata.rs"), (RuntimeObservation, RuntimeObservation, "validated provider cache"), (UserConfig, Operator, "operator-declared model metadata")]), // 19 request_output_cap
    source!(Builtin, Builtin, "crates/cli/src/providers.rs"), // 20 effort_reasoning_map
    source!(Builtin, Builtin, "crates/cli/src/providers.rs"), // 21 thinking_map
    source!(Builtin, Builtin, "crates/cli/src/runtime.rs"), // 22 orchestration_map
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (RustBuilder, Operator, "iteron_provider::ProviderInstance::with_prompt_cache"), (Builtin, Builtin, "iteron_provider::ProviderInstance::new")]), // 23 prompt_cache
    source!(DerivedPolicy, Builtin, "crates/ctx/src/compact.rs"), // 24 compaction_adaptive
    source!(Builtin, Builtin, "crates/ctx/src/compact.rs"), // 25 compaction_keep_recent
    source!(Builtin, Builtin, "crates/ctx/src/lib.rs"), // 26 token_estimator
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/ctx/src/compact.rs")]), // 27 summary_profile
    source!(Builtin, Builtin, "crates/ctx/src/compact.rs"), // 28 compaction_failure
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/ctx/src/instructions.rs")]), // 29 instruction_discovery_render
    source!([(Cli, Operator, "crates/cli/src/main.rs"), (Builtin, Builtin, "crates/cli/src/main.rs")]), // 30 memory_enable
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/ctx/src/memory.rs")]), // 31 memory_budgets
    source!(Builtin, Builtin, "crates/ctx/src/memory.rs"), // 32 bm25
    source!(Builtin, Builtin, "crates/ctx/src/skills.rs"), // 33 skill_listing_budget
    source!([(Cli, Operator, "crates/cli/src/main.rs"), (Builtin, Builtin, "crates/protocol/src/lib.rs")]), // 34 max_consecutive_tool_errors
    source!(Builtin, Builtin, "crates/tools/src/lib.rs"), // 35 pure_overlap
    source!(Builtin, Builtin, "crates/tools/src/lib.rs"), // 36 pure_concurrency
    source!(Builtin, Builtin, "crates/cli/src/runtime.rs"), // 37 failed_action_dedup
    source!(Builtin, Builtin, "crates/tools/src/lib.rs"), // 38 pure_memo_cache
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/tools/src/shell.rs")]), // 39 shell_timeout_output
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/tools/src/fs_tools.rs")]), // 40 read_file_limits
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/tools/src/fs_tools.rs")]), // 41 list_dir_limits
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/tools/src/fs_tools.rs")]), // 42 glob_limits
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/tools/src/grep_tool.rs")]), // 43 grep_limits
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/tools/src/fs_tools.rs")]), // 44 repo_map
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/tools/src/git.rs")]), // 45 git_limits
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/tools/src/web.rs")]), // 46 web_fetch_limits
    source!(Builtin, Builtin, "crates/tools/src/web.rs"), // 47 web_search_cap
    source!(Builtin, Builtin, "crates/verify/src/lib.rs"), // 48 verifier_attempts
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/verify/src/lib.rs")]), // 49 verifier_feedback_tails
    source!(Builtin, Builtin, "crates/verify/src/lib.rs"), // 50 verifier_timeout
    source!(DerivedPolicy, Builtin, "crates/cli/src/runtime_tunables/execution_policy.rs"), // 51 route_topology
    source!(Builtin, Builtin, "crates/cli/src/runtime.rs"), // 52 decomposition_profile
    source!(Builtin, Builtin, "crates/agents/src/lib.rs"), // 53 fan_breadth
    source!(Builtin, Builtin, "crates/cli/src/runtime_tunables/execution_policy.rs"), // 54 admission
    source!(Builtin, Builtin, "crates/cli/src/runtime_tunables/execution_policy.rs"), // 55 writer_fan_turn_split
    source!(Builtin, Builtin, "crates/cli/src/runtime.rs"), // 56 worker_min_turns
    source!(Builtin, Builtin, "crates/cli/src/runtime_tunables/execution_policy.rs"), // 57 wall_split
    source!(Builtin, Builtin, "crates/cli/src/runtime.rs"), // 58 token_split
    source!(Builtin, Builtin, "crates/agents/src/lib.rs"), // 59 fan_concurrency
    source!(Builtin, Builtin, "crates/kernel/src/admission.rs"), // 60 child_ceiling
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/cli/src/runtime_tunables/execution_policy.rs")]), // 61 direct_child_allocation
    source!(Builtin, Builtin, "crates/cli/src/runtime_tunables/execution_policy.rs"), // 62 subagent_effort_inheritance
    source!(Builtin, Builtin, "crates/cli/src/runtime_tunables/execution_policy.rs"), // 63 report_budget
    source!(Builtin, Builtin, "crates/workflow/src/lib.rs"), // 64 join_reduce
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/cli/src/runtime_tunables/execution_policy.rs")]), // 65 workflow_aggregate
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/workflow/src/schema_retry.rs")]), // 66 schema_retry_jitter
    source!(Builtin, Builtin, "crates/provider/src/catalog.rs"), // 67 provider_connect_tls_timeout
    source!(Builtin, Builtin, "crates/cli/src/image_input/decode.rs"), // 68 multimodal_input_admission_decode_envelope
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/cli/src/app_server/backpressure.rs")]), // 69 app_server_sq_eq_backpressure
    source!(Builtin, Builtin, "crates/cli/src/providers.rs"), // 70 provider_discovery_account_probe_cache_policy
    source!(OperatorInput, Operator, "iteron_protocol::Op"), // 71 operator_prompt_stream
    source!(Catalog, Repository, "crates/cli/src/main.rs"), // 72 builtin_prompt_corpus
    source!([binding!(ProjectConfig, Repository, "crates/ctx/src/instructions.rs", RepositoryScoped)]), // 73 instruction_bundle
    source!(Catalog, Repository, "crates/ctx/src/memory.rs"), // 74 memory_corpus
    source!(Catalog, Repository, "crates/ctx/src/skills.rs"), // 75 skill_catalog
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Catalog, Repository, "crates/agents/src/catalog.rs")]), // 76 agent_catalog
    source!([(ExternalProvider, ProviderAttested, "fresh provider discovery"), (Catalog, Repository, "crates/provider/src/static_metadata.rs"), (RuntimeObservation, RuntimeObservation, "validated provider cache"), (UserConfig, Operator, "operator-declared provider metadata")]), // 77 provider_model_capability_catalog
    source!(UserConfig, Operator, "crates/cli/src/mcp.rs"), // 78 mcp_topology_tool_catalog
    source!(UserConfig, Operator, "crates/cli/src/runtime/hooks.rs"), // 79 hooks_map
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Catalog, Repository, "crates/workflow/src/runtime_identity.rs")]), // 80 workflow_graph
    source!(Catalog, Repository, "crates/tools/src/lib.rs"), // 81 tool_action_space
    source!([(GovernedBundle, GovernedBundle, "signed rate-card bundle"), (Builtin, Builtin, "crates/obs/src/lib.rs")]), // 82 rate_card_catalog
    source!(Builtin, Builtin, "crates/agents/src/decompose.rs"), // 83 router_lexicons
    source!(RuntimeObservation, RuntimeObservation, "crates/protocol/src/event.rs"), // 84 environment_snapshot
    source!(Catalog, Repository, "crates/tools/src/web.rs"), // 85 web_search_backend_catalog
    source!([(UserConfig, Operator, "crates/cli/src/config/provider_governor.rs"), (Builtin, Builtin, "crates/cli/src/runtime/provider_governor_state.rs")]), // 86 model_fallback_chain
    source!([(UserConfig, Operator, "crates/cli/src/config/provider_governor.rs"), (Builtin, Builtin, "crates/provider/src/governor_policy.rs")]), // 87 failover_eligible_error_taxonomy
    source!([(UserConfig, Operator, "crates/cli/src/config/provider_governor.rs"), (DerivedPolicy, Builtin, "crates/provider/src/governor_policy.rs")]), // 88 route_quality_cost_latency_objective_weights
    source!([(UserConfig, Operator, "crates/cli/src/config/provider_governor.rs"), (RuntimeObservation, RuntimeObservation, "crates/provider/src/governor.rs")]), // 89 provider_health_circuit_breaker_state_policy
    source!([(UserConfig, Operator, "crates/cli/src/config/provider_governor.rs"), (Builtin, Builtin, "crates/provider/src/governor_policy.rs")]), // 90 hedged_request_policy
    source!([(UserConfig, Operator, "crates/cli/src/config/provider_governor.rs"), (ExternalProvider, ProviderAttested, "crates/provider/src/controls.rs")]), // 91 provider_service_tier
    source!([(UserConfig, Operator, "crates/cli/src/config/provider_governor.rs"), (ExternalProvider, ProviderAttested, "crates/provider/src/controls.rs")]), // 92 response_verbosity
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (DerivedPolicy, Builtin, "crates/cli/src/runtime/workflow_spawner.rs")]), // 93 role_specific_model_map
    source!(Builtin, Builtin, "crates/provider/src/responses.rs"), // 94 provider_request_total_deadline
    source!(Builtin, Builtin, "crates/provider/src/responses.rs"), // 95 stream_idle_watchdog
    source!([(ExternalProvider, ProviderAttested, "fresh model metadata"), (Catalog, Repository, "crates/provider/src/static_metadata.rs"), (RuntimeObservation, RuntimeObservation, "validated provider cache"), (UserConfig, Operator, "operator-declared model metadata")]), // 96 context_window_override_reserve
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/ctx/src/runtime_policy.rs")]), // 97 system_prefix_budget
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (DerivedPolicy, Builtin, "crates/ctx/src/runtime_policy.rs")]), // 98 conversation_history_budget
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (DerivedPolicy, Builtin, "crates/cli/src/runtime.rs")]), // 99 tool_result_history_budget
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/cli/src/image_input.rs")]), // 100 multimodal_token_budget
    source!(Builtin, Builtin, "crates/ctx/src/compact.rs"), // 101 auto_compaction_enable
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (DerivedPolicy, Builtin, "crates/ctx/src/compaction_runtime.rs")]), // 102 compaction_cooldown_hysteresis
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/ctx/src/compaction_runtime.rs")]), // 103 multi_stage_summary_topology
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/cli/src/runtime/compaction_coverage.rs")]), // 104 summary_consistency_coverage_check
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/ctx/src/memory_runtime.rs")]), // 105 hybrid_retrieval_fusion_weights
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/ctx/src/memory_runtime.rs")]), // 106 retrieval_recency_decay
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/ctx/src/memory_runtime.rs")]), // 107 context_novelty_dedup_threshold
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/tools/src/process/policy.rs"), (RuntimeObservation, RuntimeObservation, "crates/tools/src/process/supervisor.rs")]), // 108 persistent_pty_backend
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/tools/src/process/policy.rs"), (RuntimeObservation, RuntimeObservation, "crates/tools/src/process/supervisor.rs")]), // 109 concurrent_background_job_cap
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/tools/src/process/policy.rs"), (RuntimeObservation, RuntimeObservation, "crates/tools/src/process/actor.rs")]), // 110 job_idle_stall_timeout
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/tools/src/process/policy.rs"), (RuntimeObservation, RuntimeObservation, "crates/tools/src/process/actor.rs")]), // 111 interactive_stdin_wait_policy
    source!(Builtin, Builtin, "crates/sandbox/src/lib.rs"), // 112 process_signal_kill_escalation
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/tools/src/process/policy.rs"), (RuntimeObservation, RuntimeObservation, "crates/tools/src/process/supervisor.rs")]), // 113 process_cwd_continuity
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/tools/src/process/policy.rs"), (RuntimeObservation, RuntimeObservation, "crates/sandbox/src/lib.rs")]), // 114 child_process_environment_reuse
    source!(DerivedPolicy, Builtin, "crates/cli/src/runtime.rs"), // 115 effecting_tool_concurrency
    source!(Builtin, Builtin, "crates/cli/src/runtime.rs"), // 116 write_set_conflict_admission
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/cli/src/runtime/tool_output_spill.rs"), (RuntimeObservation, RuntimeObservation, "crates/cli/src/runtime.rs")]), // 117 tool_output_spill_to_disk_policy
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (RuntimeObservation, RuntimeObservation, "selected route image capability"), (Builtin, Builtin, "crates/cli/src/image_input/routing.rs")]), // 118 binary_media_inspection_routing
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/tools/src/lsp/policy.rs"), (RuntimeObservation, RuntimeObservation, "crates/tools/src/lsp/pool.rs")]), // 119 lsp_server_language_selection
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/tools/src/lsp/policy.rs"), (RuntimeObservation, RuntimeObservation, "crates/tools/src/lsp/pool.rs")]), // 120 lsp_timeout_restart_policy
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (DerivedPolicy, Builtin, "crates/ctx/src/runtime_policy.rs")]), // 121 lsp_result_context_budget
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/tools/src/memo.rs")]), // 122 tool_result_cache_ttl
    source!([(UserConfig, Operator, "crates/cli/src/config/verification.rs"), (Builtin, Builtin, "crates/verify/src/oracle.rs")]), // 123 test_selection_strategy
    source!([(UserConfig, Operator, "crates/cli/src/config/verification.rs"), (DerivedPolicy, Builtin, "crates/verify/src/runtime_policy.rs")]), // 124 incremental_versus_full_verification
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/verify/src/runtime_policy.rs"), (DerivedPolicy, Builtin, "crates/verify/src/runtime_policy.rs")]), // 125 flaky_test_detection_quarantine
    source!(Catalog, Repository, "crates/verify/src/oracle.rs"), // 126 failure_classification_taxonomy
    source!(DerivedPolicy, Builtin, "crates/cli/src/runtime.rs"), // 127 retry_eligibility_policy
    source!([(UserConfig, Operator, "crates/cli/src/config/verification.rs"), (DerivedPolicy, Builtin, "crates/verify/src/runtime_policy.rs")]), // 128 rollback_on_verification_failure
    source!([(UserConfig, Operator, "crates/cli/src/config/verification.rs"), (DerivedPolicy, Builtin, "crates/verify/src/runtime_policy.rs")]), // 129 workspace_checkpoint_cadence
    source!([(UserConfig, Operator, "crates/cli/src/config/verification.rs"), (Builtin, Builtin, "crates/verify/src/runtime_policy.rs")]), // 130 selective_restore_scope
    source!([(UserConfig, Operator, "crates/cli/src/config/verification.rs"), (Builtin, Builtin, "crates/verify/src/runtime_policy.rs")]), // 131 verification_quorum_consensus
    source!(Builtin, Builtin, "crates/cli/src/runtime.rs"), // 132 recovery_escalation_policy
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (DerivedPolicy, Builtin, "crates/cli/src/runtime/workflow_spawner.rs")]), // 133 per_agent_model
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (DerivedPolicy, Builtin, "crates/cli/src/runtime/workflow_spawner.rs")]), // 134 per_agent_effort_thinking
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (DerivedPolicy, Builtin, "crates/cli/src/runtime/workflow_spawner.rs")]), // 135 per_agent_tool_profile
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/cli/src/runtime/workflow_spawner.rs")]), // 136 per_agent_memory_scope
    source!(Builtin, Builtin, "crates/cli/src/runtime/workflow_spawner.rs"), // 137 spawn_depth_control
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/workflow/src/lib.rs")]), // 138 per_session_spawn_cap
    source!(Builtin, Builtin, "crates/workflow/src/bindings.rs"), // 139 task_priority_scheduling
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/workflow/src/execution_policy.rs")]), // 140 speculative_sibling_count
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/workflow/src/execution_policy.rs")]), // 141 speculative_sibling_cancellation
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/workflow/src/quorum.rs")]), // 142 early_stop_quorum_policy
    source!(Builtin, Builtin, "crates/cli/src/runtime/workflow_spawner.rs"), // 143 writer_worktree_isolation_mode
    source!(Builtin, Builtin, "crates/cli/src/runtime/workflow_spawner.rs"), // 144 merge_conflict_arbitration
    source!(Builtin, Builtin, "crates/agents/src/reduce.rs"), // 145 inter_agent_messaging_topology
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/workflow/src/execution_policy.rs")]), // 146 task_retry_reassignment_policy
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/mcp/src/http/reqwest_exchange.rs")]), // 147 mcp_transport_selection
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/tools/src/tool_search.rs")]), // 148 deferred_discovery_threshold
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/cli/src/mcp.rs")]), // 149 mcp_reconnect_backoff
    source!(Builtin, Builtin, "crates/mcp/src/client.rs"), // 150 per_server_startup_deadline
    source!(Builtin, Builtin, "crates/mcp/src/client.rs"), // 151 per_tool_mcp_deadline
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/mcp/src/client/content.rs")]), // 152 mcp_result_cap_spill_policy
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/mcp/src/oauth.rs")]), // 153 oauth_auth_lifecycle_policy
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (RuntimeObservation, RuntimeObservation, "crates/cli/src/mcp/session.rs")]), // 154 resource_prompt_plugin_capability_exposure
    source!([(UserConfig, Operator, "crates/cli/src/config/provider_governor.rs"), (ExternalProvider, ProviderAttested, "crates/provider/src/controls.rs")]), // 155 request_compression_policy
    source!(Builtin, Builtin, "crates/provider/src/catalog.rs"), // 156 http_pool_keepalive_idle_policy
    source!([(UserConfig, Operator, "crates/cli/src/config/provider_governor.rs"), (RuntimeObservation, RuntimeObservation, "crates/provider/src/governor.rs")]), // 157 rate_limit_aware_admission
    source!([(UserConfig, Operator, "crates/cli/src/config/provider_governor.rs"), (ExternalProvider, ProviderAttested, "crates/provider/src/controls.rs")]), // 158 prompt_cache_ttl_breakpoint_strategy
    source!([(UserConfig, Operator, "crates/cli/src/config.rs"), (Builtin, Builtin, "crates/cli/src/session_isolation.rs")]), // 159 session_isolation_profile
    source!(Builtin, Builtin, "crates/record/src/lib.rs"), // 160 replay_divergence_detection_policy
];

#[rustfmt::skip]
pub(super) const ACTIVATIONS: [ActivationSpec; crate::EXPECTED_FAMILY_COUNT] = [
    always!(), // 1 provider
    always!(), // 2 model
    always!(), // 3 base_url
    always!(), // 4 effort
    always!(), // 5 max_turns
    configured!(Cli, Environment, UserConfig, ProjectConfig), // 6 max_usd
    configured!(Cli), // 7 max_tokens
    always!(), // 8 max_wall_secs
    always!(), // 9 allow_code
    always!(), // 10 permission_mode
    always!(), // 11 permission_rules
    always!(), // 12 bypass_permissions
    always!(), // 13 compaction_trigger
    configured!(Cli), // 14 verify_command
    always!(), // 15 retry_backoff_base
    always!(), // 16 retry_backoff_cap
    always!(), // 17 retry_max_attempts
    configured!(UserConfig, ProjectConfig), // 18 egress_allow
    always!(), // 19 request_output_cap
    always!(), // 20 effort_reasoning_map
    always!(), // 21 thinking_map
    always!(), // 22 orchestration_map
    always!(), // 23 prompt_cache
    always!(), // 24 compaction_adaptive
    always!(), // 25 compaction_keep_recent
    always!(), // 26 token_estimator
    always!(), // 27 summary_profile
    always!(), // 28 compaction_failure
    always!(), // 29 instruction_discovery_render
    always!(), // 30 memory_enable
    always!(), // 31 memory_budgets
    always!(), // 32 bm25
    always!(), // 33 skill_listing_budget
    always!(), // 34 max_consecutive_tool_errors
    always!(), // 35 pure_overlap
    always!(), // 36 pure_concurrency
    always!(), // 37 failed_action_dedup
    always!(), // 38 pure_memo_cache
    always!(), // 39 shell_timeout_output
    always!(), // 40 read_file_limits
    always!(), // 41 list_dir_limits
    always!(), // 42 glob_limits
    always!(), // 43 grep_limits
    always!(), // 44 repo_map
    always!(), // 45 git_limits
    always!(), // 46 web_fetch_limits
    always!(), // 47 web_search_cap
    always!(), // 48 verifier_attempts
    always!(), // 49 verifier_feedback_tails
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
    always!(), // 61 direct_child_allocation
    always!(), // 62 subagent_effort_inheritance
    always!(), // 63 report_budget
    always!(), // 64 join_reduce
    always!(), // 65 workflow_aggregate
    always!(), // 66 schema_retry_jitter
    always!(), // 67 provider_connect_tls_timeout
    always!(), // 68 multimodal_input_admission_decode_envelope
    always!(), // 69 app_server_sq_eq_backpressure
    always!(), // 70 provider_discovery_account_probe_cache_policy
    configured!(OperatorInput), // 71 operator_prompt_stream
    configured!(Catalog), // 72 builtin_prompt_corpus
    configured!(ProjectConfig), // 73 instruction_bundle
    configured!(Catalog), // 74 memory_corpus
    configured!(Catalog), // 75 skill_catalog
    always!(), // 76 agent_catalog
    configured!(ExternalProvider, Catalog, RuntimeObservation, UserConfig), // 77 provider_model_capability_catalog
    configured!(UserConfig), // 78 mcp_topology_tool_catalog
    configured!(UserConfig), // 79 hooks_map
    always!(), // 80 workflow_graph
    configured!(Catalog), // 81 tool_action_space
    configured!(GovernedBundle, Builtin), // 82 rate_card_catalog
    configured!(Builtin), // 83 router_lexicons
    always!(), // 84 environment_snapshot
    configured!(Catalog), // 85 web_search_backend_catalog
    always!(), // 86 model_fallback_chain
    always!(), // 87 failover_eligible_error_taxonomy
    always!(), // 88 route_quality_cost_latency_objective_weights
    always!(), // 89 provider_health_circuit_breaker_state_policy
    always!(), // 90 hedged_request_policy
    always!(), // 91 provider_service_tier
    always!(), // 92 response_verbosity
    always!(), // 93 role_specific_model_map
    always!(), // 94 provider_request_total_deadline
    always!(), // 95 stream_idle_watchdog
    always!(), // 96 context_window_override_reserve
    always!(), // 97 system_prefix_budget
    always!(), // 98 conversation_history_budget
    always!(), // 99 tool_result_history_budget
    always!(), // 100 multimodal_token_budget
    always!(), // 101 auto_compaction_enable
    always!(), // 102 compaction_cooldown_hysteresis
    always!(), // 103 multi_stage_summary_topology
    always!(), // 104 summary_consistency_coverage_check
    always!(), // 105 hybrid_retrieval_fusion_weights
    always!(), // 106 retrieval_recency_decay
    always!(), // 107 context_novelty_dedup_threshold
    always!(), // 108 persistent_pty_backend
    always!(), // 109 concurrent_background_job_cap
    always!(), // 110 job_idle_stall_timeout
    always!(), // 111 interactive_stdin_wait_policy
    always!(), // 112 process_signal_kill_escalation
    always!(), // 113 process_cwd_continuity
    always!(), // 114 child_process_environment_reuse
    always!(), // 115 effecting_tool_concurrency
    always!(), // 116 write_set_conflict_admission
    always!(), // 117 tool_output_spill_to_disk_policy
    always!(), // 118 binary_media_inspection_routing
    always!(), // 119 lsp_server_language_selection
    always!(), // 120 lsp_timeout_restart_policy
    always!(), // 121 lsp_result_context_budget
    always!(), // 122 tool_result_cache_ttl
    always!(), // 123 test_selection_strategy
    always!(), // 124 incremental_versus_full_verification
    always!(), // 125 flaky_test_detection_quarantine
    always!(), // 126 failure_classification_taxonomy
    always!(), // 127 retry_eligibility_policy
    always!(), // 128 rollback_on_verification_failure
    always!(), // 129 workspace_checkpoint_cadence
    always!(), // 130 selective_restore_scope
    always!(), // 131 verification_quorum_consensus
    always!(), // 132 recovery_escalation_policy
    always!(), // 133 per_agent_model
    always!(), // 134 per_agent_effort_thinking
    always!(), // 135 per_agent_tool_profile
    always!(), // 136 per_agent_memory_scope
    always!(), // 137 spawn_depth_control
    always!(), // 138 per_session_spawn_cap
    always!(), // 139 task_priority_scheduling
    always!(), // 140 speculative_sibling_count
    always!(), // 141 speculative_sibling_cancellation
    always!(), // 142 early_stop_quorum_policy
    always!(), // 143 writer_worktree_isolation_mode
    always!(), // 144 merge_conflict_arbitration
    always!(), // 145 inter_agent_messaging_topology
    always!(), // 146 task_retry_reassignment_policy
    configured!(UserConfig), // 147 mcp_transport_selection
    always!(), // 148 deferred_discovery_threshold
    always!(), // 149 mcp_reconnect_backoff
    always!(), // 150 per_server_startup_deadline
    always!(), // 151 per_tool_mcp_deadline
    always!(), // 152 mcp_result_cap_spill_policy
    configured!(UserConfig), // 153 oauth_auth_lifecycle_policy
    always!(), // 154 resource_prompt_plugin_capability_exposure
    always!(), // 155 request_compression_policy
    always!(), // 156 http_pool_keepalive_idle_policy
    always!(), // 157 rate_limit_aware_admission
    always!(), // 158 prompt_cache_ttl_breakpoint_strategy
    always!(), // 159 session_isolation_profile
    always!(), // 160 replay_divergence_detection_policy
];
