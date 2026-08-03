use crate::benchmark_metadata::benchmark_relevance;
use crate::metadata::{
    OptimizationSeed, aliases, authority, optimization, requirements, risk, strategy_slots,
};
use crate::resolution_metadata::{activation_spec, default_spec, source_spec};
use crate::semantic_keys::semantic_key;
use crate::value_schemas::value_schema;
use crate::{CausalPath as Path, Domain, FAMILY_SCHEMA_VERSION, Family, ImplementationStatus};

macro_rules! family {
    ($status:ident; $ordinal:literal, $id:literal, $semantic_key:expr, $domain:ident, $summary:literal,
     $tb:ident, $swe:ident, $optimization_seed:ident) => {
        Family {
            schema_version: FAMILY_SCHEMA_VERSION,
            ordinal: $ordinal,
            id: $id,
            semantic_key: $semantic_key,
            aliases: aliases($ordinal),
            domain: Domain::$domain,
            summary: $summary,
            activation: activation_spec($ordinal),
            requirements: requirements($ordinal, Domain::$domain),
            strategy_slots: strategy_slots($ordinal),
            default: default_spec($ordinal),
            source: source_spec($ordinal),
            value_schema: value_schema($ordinal),
            benchmark_relevance: benchmark_relevance($ordinal, $summary, Path::$tb, Path::$swe),
            implementation_status: ImplementationStatus::$status,
            optimization: optimization(
                $ordinal,
                OptimizationSeed::$optimization_seed,
                value_schema($ordinal).kind,
            ),
            risk_class: risk(
                $ordinal,
                Domain::$domain,
                authority($ordinal, OptimizationSeed::$optimization_seed),
            ),
            authority_class: authority($ordinal, OptimizationSeed::$optimization_seed),
        }
    };
}

macro_rules! full {
    ($ordinal:literal, $id:literal, $($rest:tt)*) => {
        family!(Full; $ordinal, $id, semantic_key($ordinal, $id), $($rest)*)
    };
}

macro_rules! partial {
    ($ordinal:literal, $id:literal, $($rest:tt)*) => {
        family!(Partial; $ordinal, $id, semantic_key($ordinal, $id), $($rest)*)
    };
}

macro_rules! missing {
    ($ordinal:literal, $id:literal, $($rest:tt)*) => {
        family!(Missing; $ordinal, $id, semantic_key($ordinal, $id), $($rest)*)
    };
}

macro_rules! fixed {
    ($ordinal:literal, $id:literal, $($rest:tt)*) => {
        family!(FixedHidden; $ordinal, $id, semantic_key($ordinal, $id), $($rest)*)
    };
}

/// The declaration order is canonical and ordinals are never reused.
#[rustfmt::skip]
static FAMILIES: &[Family] = &[
    // A — active public configuration families.
    full!(1, "provider", Provider, "Select the inference provider instance.", Conditional, Indirect, RuntimeAdaptive),
    full!(2, "model", Provider, "Select the model within the admitted provider route.", Conditional, Indirect, RuntimeAdaptive),
    full!(3, "base_url", Provider, "Override the provider API root.", Conditional, Conditional, OperatorOnly),
    full!(4, "effort", Reasoning, "Choose the public reasoning-effort tier.", Indirect, Indirect, RuntimeAdaptive),
    full!(5, "max_turns", Budget, "Bound provider attempts for one run.", Direct, Direct, OperatorOnly),
    full!(6, "max_usd", Budget, "Bound signed monetary spend for one run.", Conditional, Conditional, OperatorOnly),
    full!(7, "max_tokens", Budget, "Bound aggregate token use for one run.", Conditional, Conditional, OperatorOnly),
    full!(8, "max_wall_secs", Budget, "Bound run wall-clock duration.", Direct, Direct, OperatorOnly),
    full!(9, "allow_code", Governance, "Admit repository code execution when the operator allows it.", Direct, Indirect, OperatorOnly),
    full!(10, "permission_mode", Governance, "Select the operator permission posture.", Conditional, Conditional, OperatorOnly),
    full!(11, "permission_rules", Governance, "Set per-capability allow, ask, or deny rules.", Conditional, Conditional, OperatorOnly),
    full!(12, "bypass_permissions", Governance, "Explicitly bypass interactive permission prompts.", Conditional, Conditional, OperatorOnly),
    full!(13, "compaction_trigger", Context, "Choose when context compaction starts.", Indirect, Indirect, OfflineSearch),
    full!(14, "verify_command", Verification, "Choose the operator verification command.", Conditional, Direct, OperatorOnly),

    // B — partial or inactive public families.
    partial!(15, "retry_backoff_base", Runtime, "Set the initial provider retry delay.", Conditional, Conditional, OfflineSearch),
    partial!(16, "retry_backoff_cap", Runtime, "Cap provider retry delay.", Conditional, Conditional, OfflineSearch),
    partial!(17, "retry_max_attempts", Runtime, "Bound staged provider retries.", Direct, Direct, OfflineSearch),
    missing!(18, "egress_allow", Governance, "Declare an egress allow policy surface.", None, None, Inactive),

    // C — internal runtime and harness policy families.
    fixed!(19, "request_output_cap", Provider, "Reserve and cap provider response tokens.", Indirect, Indirect, OfflineSearch),
    fixed!(20, "effort_reasoning_map", Reasoning, "Map effort tiers onto provider reasoning controls.", Indirect, Indirect, OfflineSearch),
    fixed!(21, "thinking_map", Reasoning, "Map effort onto explicit thinking budgets.", Indirect, Indirect, OfflineSearch),
    fixed!(22, "orchestration_map", Orchestration, "Map effort onto orchestration eligibility.", Indirect, Indirect, OfflineSearch),
    full!(23, "prompt_cache", Provider, "Enable or disable prompt-cache breakpoint emission for one built provider route.", Conditional, Conditional, OfflineSearch),
    fixed!(24, "compaction_adaptive", Context, "Adapt compaction to model and transcript state.", Indirect, Indirect, RuntimeAdaptive),
    fixed!(25, "compaction_keep_recent", Context, "Choose the verbatim recent-turn retention window.", Indirect, Indirect, OfflineSearch),
    fixed!(26, "token_estimator", Context, "Estimate tokens for admission and compaction.", Conditional, Indirect, CatalogCurated),
    partial!(27, "summary_profile", Context, "Choose the compaction summary shape and budget.", Indirect, Indirect, OfflineSearch),
    fixed!(28, "compaction_failure", Context, "Choose bounded behavior when compaction fails.", Conditional, Conditional, FixedInvariant),
    partial!(29, "instruction_discovery_render", Context, "Discover and render repository instruction files.", Conditional, Indirect, OfflineSearch),
    full!(30, "memory_enable", Memory, "Enable durable memory retrieval and writes.", Conditional, Indirect, OperatorOnly),
    partial!(31, "memory_budgets", Memory, "Bound memory retrieval, render, and write work.", Conditional, Indirect, OfflineSearch),
    fixed!(32, "bm25", Context, "Tune lexical retrieval scoring.", Conditional, Indirect, OfflineSearch),
    fixed!(33, "skill_listing_budget", Context, "Bound skill catalog text exposed to the model.", Conditional, Indirect, OfflineSearch),
    fixed!(34, "max_consecutive_tool_errors", Budget, "Stop a run after repeated tool failures.", Direct, Direct, OfflineSearch),
    fixed!(35, "pure_overlap", Orchestration, "Allow eligible pure tools to overlap inference.", Direct, Indirect, OfflineSearch),
    fixed!(36, "pure_concurrency", Orchestration, "Bound concurrent pure tool calls.", Direct, Indirect, OfflineSearch),
    fixed!(37, "failed_action_dedup", Tooling, "Suppress repeated identical failed actions.", Indirect, Indirect, OfflineSearch),
    fixed!(38, "pure_memo_cache", Tooling, "Memoize deterministic pure tool results.", Conditional, Indirect, OfflineSearch),
    partial!(39, "shell_timeout_output", Tooling, "Bound shell wall time and captured output.", Direct, Indirect, OfflineSearch),
    partial!(40, "read_file_limits", Tooling, "Bound file-read bytes and line ranges.", Conditional, Indirect, OfflineSearch),
    partial!(41, "list_dir_limits", Tooling, "Bound directory listing work and output.", Conditional, Indirect, OfflineSearch),
    partial!(42, "glob_limits", Tooling, "Bound glob traversal and results.", Conditional, Indirect, OfflineSearch),
    partial!(43, "grep_limits", Tooling, "Bound text search traversal and output.", Conditional, Direct, OfflineSearch),
    partial!(44, "repo_map", Context, "Bound and shape repository-map construction.", Conditional, Indirect, OfflineSearch),
    partial!(45, "git_limits", Tooling, "Bound Git observation and diff output.", Conditional, Indirect, OfflineSearch),
    partial!(46, "web_fetch_limits", Tooling, "Bound fetched bytes, redirects, and elapsed time.", Conditional, Conditional, OfflineSearch),
    fixed!(47, "web_search_cap", Tooling, "Bound web-search results admitted to context.", Conditional, Conditional, OfflineSearch),
    fixed!(48, "verifier_attempts", Verification, "Bound verification repair attempts.", Conditional, Direct, OfflineSearch),
    partial!(49, "verifier_feedback_tails", Verification, "Bound failure feedback returned to the model.", Conditional, Indirect, OfflineSearch),
    fixed!(50, "verifier_timeout", Verification, "Bound each verification command.", Direct, Direct, OfflineSearch),
    fixed!(51, "route_topology", Orchestration, "Choose direct versus orchestrated run topology.", Indirect, Indirect, RuntimeAdaptive),
    fixed!(52, "decomposition_profile", Orchestration, "Choose task decomposition shape.", Indirect, Indirect, OfflineSearch),
    fixed!(53, "fan_breadth", Orchestration, "Bound investigator fan-out breadth.", Indirect, Indirect, OfflineSearch),
    fixed!(54, "admission", Orchestration, "Admit bounded child work under parent ceilings.", Conditional, Conditional, FixedInvariant),
    fixed!(55, "writer_fan_turn_split", Orchestration, "Split turns between investigators and the writer.", Indirect, Indirect, OfflineSearch),
    fixed!(56, "worker_min_turns", Orchestration, "Reserve a minimum useful child turn allocation.", Indirect, Indirect, OfflineSearch),
    fixed!(57, "wall_split", Orchestration, "Split remaining wall time across child work.", Indirect, Indirect, OfflineSearch),
    fixed!(58, "token_split", Orchestration, "Split remaining tokens across child work.", Indirect, Indirect, OfflineSearch),
    fixed!(59, "fan_concurrency", Orchestration, "Bound simultaneous investigator agents.", Indirect, Indirect, OfflineSearch),
    fixed!(60, "child_ceiling", Orchestration, "Intersect every child with an immutable parent ceiling.", Conditional, Conditional, FixedInvariant),
    partial!(61, "direct_child_allocation", Orchestration, "Allocate budget to directly spawned children.", Indirect, Indirect, OfflineSearch),
    fixed!(62, "subagent_effort_inheritance", Orchestration, "Choose bounded subagent reasoning effort.", Indirect, Indirect, OfflineSearch),
    fixed!(63, "report_budget", Orchestration, "Bound child report size admitted to the writer.", Conditional, Indirect, OfflineSearch),
    fixed!(64, "join_reduce", Orchestration, "Choose deterministic join and reduction policy.", Indirect, Indirect, OfflineSearch),
    partial!(65, "workflow_aggregate", Orchestration, "Bound aggregate workflow calls and resources.", Indirect, Indirect, OfflineSearch),
    partial!(66, "schema_retry_jitter", Runtime, "Bound schema-repair retries and jitter.", Conditional, Indirect, OfflineSearch),
    fixed!(67, "provider_connect_tls_timeout", Provider, "Bound provider TCP and TLS connection establishment.", Indirect, Indirect, OfflineSearch),
    partial!(68, "multimodal_input_admission_decode_envelope", Runtime, "Bound image count, bytes, dimensions, frames, and decode work.", None, None, FixedInvariant),
    partial!(69, "app_server_sq_eq_backpressure", Runtime, "Bound submission and event queues with typed drop policy.", Conditional, Conditional, FixedInvariant),
    partial!(70, "provider_discovery_account_probe_cache_policy", Provider, "Bound provider startup discovery, probe freshness, and failure backoff.", Conditional, Conditional, OfflineSearch),

    // D — content, catalogs, and environment surfaces.
    full!(71, "operator_prompt_stream", Context, "Operator-authored task and steering text.", Direct, Direct, OperatorOnly),
    fixed!(72, "builtin_prompt_corpus", Reasoning, "Built-in system and workflow prompt corpus.", Indirect, Indirect, OfflineSearch),
    full!(73, "instruction_bundle", Context, "Repository and user instruction content.", Conditional, Direct, CatalogCurated),
    full!(74, "memory_corpus", Memory, "Durable admitted memory records.", Conditional, Indirect, CatalogCurated),
    full!(75, "skill_catalog", Extensibility, "Discovered skill metadata and instructions.", Conditional, Indirect, CatalogCurated),
    partial!(76, "agent_catalog", Extensibility, "Discover bounded agent definitions for model-visible role selection.", Conditional, Indirect, CatalogCurated),
    full!(77, "provider_model_capability_catalog", Provider, "Provider and model capability evidence.", Conditional, Indirect, CatalogCurated),
    full!(78, "mcp_topology_tool_catalog", Extensibility, "Configured MCP servers and their tool schemas.", Conditional, Conditional, OperatorOnly),
    full!(79, "hooks_map", Extensibility, "Lifecycle hook declarations and selectors.", Conditional, Conditional, OperatorOnly),
    full!(80, "workflow_graph", Orchestration, "Declared workflow task graph.", Indirect, Indirect, OfflineSearch),
    fixed!(81, "tool_action_space", Tooling, "Registered tool schemas and capability classes.", Direct, Direct, CatalogCurated),
    fixed!(82, "rate_card_catalog", Observability, "Signed provider pricing evidence.", None, None, CatalogCurated),
    fixed!(83, "router_lexicons", Reasoning, "Lexical signals used by routing policy.", Indirect, Indirect, OfflineSearch),
    fixed!(84, "environment_snapshot", Context, "Durable bounded repository and process environment facts.", Conditional, Indirect, FixedInvariant),
    full!(85, "web_search_backend_catalog", Extensibility, "Available web-search backend definitions.", Conditional, Conditional, CatalogCurated),

    // Appendix F.1 — N-RM01..N-RM10, model routing and transport (10).
    missing!(86, "model_fallback_chain", Provider, "Choose an ordered model fallback chain.", Indirect, Indirect, CatalogCurated),
    partial!(87, "failover_eligible_error_taxonomy", Provider, "Classify provider errors that may admit failover.", Indirect, Indirect, FixedInvariant),
    missing!(88, "route_quality_cost_latency_objective_weights", Reasoning, "Weight route quality, cost, and latency objectives.", Direct, Direct, OfflineSearch),
    partial!(89, "provider_health_circuit_breaker_state_policy", Provider, "Derive route health and circuit-breaker state.", Indirect, Indirect, CatalogCurated),
    missing!(90, "hedged_request_policy", Provider, "Choose bounded duplicate-request hedging.", Indirect, Indirect, CatalogCurated),
    missing!(91, "provider_service_tier", Provider, "Select a provider service tier.", Direct, Indirect, CatalogCurated),
    missing!(92, "response_verbosity", Reasoning, "Select response verbosity independently of effort.", Conditional, Indirect, OfflineSearch),
    partial!(93, "role_specific_model_map", Orchestration, "Map agent roles to admitted model routes.", Indirect, Direct, CatalogCurated),
    fixed!(94, "provider_request_total_deadline", Provider, "Bound the total duration of one provider request.", Direct, Indirect, OfflineSearch),
    fixed!(95, "stream_idle_watchdog", Provider, "Abort a provider stream that stops making progress.", Indirect, Indirect, OfflineSearch),

    // Appendix F.2 — N-CX01..N-CX12, context, retrieval, and compaction (12).
    partial!(96, "context_window_override_reserve", Context, "Resolve the effective context window and output reserve.", Direct, Direct, CatalogCurated),
    partial!(97, "system_prefix_budget", Context, "Bound the stable system prefix.", Indirect, Direct, OfflineSearch),
    partial!(98, "conversation_history_budget", Context, "Bound conversation history admitted to a request.", Direct, Direct, OfflineSearch),
    partial!(99, "tool_result_history_budget", Context, "Bound retained tool-result history.", Direct, Direct, OfflineSearch),
    partial!(100, "multimodal_token_budget", Context, "Bound multimodal content admitted to model context.", Indirect, Conditional, CatalogCurated),
    fixed!(101, "auto_compaction_enable", Context, "Enable automatic bounded context compaction.", Direct, Direct, OfflineSearch),
    partial!(102, "compaction_cooldown_hysteresis", Context, "Avoid repeated compaction around the trigger boundary.", Direct, Direct, OfflineSearch),
    partial!(103, "multi_stage_summary_topology", Context, "Choose a bounded summary-stage topology.", Indirect, Direct, CatalogCurated),
    missing!(104, "summary_consistency_coverage_check", Verification, "Check summary consistency and evidence coverage.", Indirect, Direct, CatalogCurated),
    partial!(105, "hybrid_retrieval_fusion_weights", Memory, "Fuse lexical and optional retrieval signals.", Indirect, Direct, OfflineSearch),
    missing!(106, "retrieval_recency_decay", Memory, "Apply bounded recency decay to retrieval scores.", Indirect, Direct, OfflineSearch),
    partial!(107, "context_novelty_dedup_threshold", Context, "Suppress duplicate or low-novelty context.", Indirect, Direct, OfflineSearch),

    // Appendix F.3 — N-TP01..N-TP15, tools, processes, and code intelligence (15).
    missing!(108, "persistent_pty_backend", Tooling, "Select a persistent PTY backend.", Direct, Indirect, CatalogCurated),
    missing!(109, "concurrent_background_job_cap", Tooling, "Bound concurrent background jobs.", Direct, Conditional, OfflineSearch),
    missing!(110, "job_idle_stall_timeout", Tooling, "Stop a background job that is idle or stalled.", Direct, Conditional, OfflineSearch),
    missing!(111, "interactive_stdin_wait_policy", Tooling, "Bound waits for interactive process input.", Direct, Conditional, CatalogCurated),
    fixed!(112, "process_signal_kill_escalation", Tooling, "Escalate process-group termination and reap children.", Direct, Conditional, FixedInvariant),
    partial!(113, "process_cwd_continuity", Tooling, "Preserve process and working-directory continuity.", Direct, Indirect, CatalogCurated),
    partial!(114, "child_process_environment_reuse", Tooling, "Reuse a bounded child-process environment snapshot.", Direct, Indirect, FixedInvariant),
    fixed!(115, "effecting_tool_concurrency", Orchestration, "Bound concurrency among admitted effecting tools.", Direct, Indirect, OfflineSearch),
    fixed!(116, "write_set_conflict_admission", Tooling, "Admit concurrent writes only when declared write sets do not overlap.", Indirect, Direct, CatalogCurated),
    missing!(117, "tool_output_spill_to_disk_policy", Tooling, "Spill bounded tool output outside model context.", Direct, Indirect, OfflineSearch),
    partial!(118, "binary_media_inspection_routing", Tooling, "Route binary and media inspection by capability.", Indirect, Conditional, CatalogCurated),
    missing!(119, "lsp_server_language_selection", Tooling, "Select LSP servers for discovered languages.", Indirect, Direct, CatalogCurated),
    missing!(120, "lsp_timeout_restart_policy", Tooling, "Bound LSP requests and server restarts.", Indirect, Direct, OfflineSearch),
    missing!(121, "lsp_result_context_budget", Context, "Bound LSP evidence admitted to context.", Indirect, Direct, OfflineSearch),
    partial!(122, "tool_result_cache_ttl", Tooling, "Bound deterministic tool-result cache reuse.", Indirect, Indirect, OfflineSearch),

    // Appendix F.4 — N-VR01..N-VR10, verification, recovery, and rewind (10).
    fixed!(123, "test_selection_strategy", Verification, "Select the verification command and evidence scope.", Indirect, Direct, CatalogCurated),
    partial!(124, "incremental_versus_full_verification", Verification, "Choose incremental or full verification by risk.", Indirect, Direct, OfflineSearch),
    partial!(125, "flaky_test_detection_quarantine", Verification, "Detect disagreement and quarantine flaky evidence.", Indirect, Direct, FixedInvariant),
    fixed!(126, "failure_classification_taxonomy", Verification, "Classify verification failures with a versioned taxonomy.", Direct, Direct, FixedInvariant),
    fixed!(127, "retry_eligibility_policy", Verification, "Retry only verification outcomes that are eligible.", Direct, Direct, OfflineSearch),
    missing!(128, "rollback_on_verification_failure", Verification, "Rollback selected workspace changes after verification failure.", Indirect, Direct, CatalogCurated),
    partial!(129, "workspace_checkpoint_cadence", Verification, "Choose durable workspace checkpoint boundaries.", Conditional, Indirect, CatalogCurated),
    partial!(130, "selective_restore_scope", Verification, "Choose an explicit user-authorized restore scope.", Conditional, Indirect, FixedInvariant),
    partial!(131, "verification_quorum_consensus", Verification, "Require bounded verifier agreement.", Indirect, Direct, OfflineSearch),
    fixed!(132, "recovery_escalation_policy", Verification, "Escalate verification recovery from retry to replan to stop.", Direct, Direct, OfflineSearch),

    // Appendix F.5 — N-AG01..N-AG14, agents, tasks, and collaboration (14).
    full!(133, "per_agent_model", Orchestration, "Choose a model for one admitted agent.", Indirect, Direct, CatalogCurated),
    full!(134, "per_agent_effort_thinking", Orchestration, "Choose effort and thinking for one admitted agent.", Indirect, Direct, OfflineSearch),
    full!(135, "per_agent_tool_profile", Orchestration, "Narrow the tool profile for one admitted agent.", Indirect, Direct, CatalogCurated),
    partial!(136, "per_agent_memory_scope", Memory, "Choose isolated or explicitly shared agent memory.", Indirect, Direct, CatalogCurated),
    fixed!(137, "spawn_depth_control", Orchestration, "Bound recursive agent spawning.", Direct, Indirect, OfflineSearch),
    partial!(138, "per_session_spawn_cap", Orchestration, "Bound total agent spawns in one session.", Direct, Indirect, OfflineSearch),
    partial!(139, "task_priority_scheduling", Orchestration, "Schedule ready tasks by bounded priority.", Direct, Indirect, OfflineSearch),
    missing!(140, "speculative_sibling_count", Orchestration, "Bound speculative sibling agents.", Indirect, Direct, OfflineSearch),
    missing!(141, "speculative_sibling_cancellation", Orchestration, "Cancel losing speculative siblings from evidence.", Indirect, Direct, OfflineSearch),
    partial!(142, "early_stop_quorum_policy", Orchestration, "Stop a fan only after required evidence reaches quorum.", Indirect, Direct, OfflineSearch),
    missing!(143, "writer_worktree_isolation_mode", Governance, "Isolate write-capable agents in worktrees.", Conditional, Direct, FixedInvariant),
    missing!(144, "merge_conflict_arbitration", Verification, "Arbitrate verified child merges and conflicts.", Conditional, Direct, CatalogCurated),
    fixed!(145, "inter_agent_messaging_topology", Orchestration, "Route bounded agent reports through the parent.", Indirect, Direct, CatalogCurated),
    missing!(146, "task_retry_reassignment_policy", Orchestration, "Retry or reassign a failed agent task.", Direct, Direct, OfflineSearch),

    // Appendix F.6 — N-MP01..N-MP08, MCP and plugin lifecycle (8).
    partial!(147, "mcp_transport_selection", Extensibility, "Select an admitted MCP transport.", Indirect, Indirect, CatalogCurated),
    partial!(148, "deferred_discovery_threshold", Extensibility, "Defer MCP discovery after a bounded threshold.", Indirect, Indirect, OfflineSearch),
    missing!(149, "mcp_reconnect_backoff", Extensibility, "Bound MCP reconnect attempts and delay.", Indirect, Indirect, OfflineSearch),
    fixed!(150, "per_server_startup_deadline", Extensibility, "Bound MCP server startup and initialization.", Indirect, Indirect, OfflineSearch),
    fixed!(151, "per_tool_mcp_deadline", Extensibility, "Bound one MCP tool exchange.", Direct, Indirect, OfflineSearch),
    partial!(152, "mcp_result_cap_spill_policy", Extensibility, "Cap or spill MCP results before model exposure.", Indirect, Indirect, OfflineSearch),
    missing!(153, "oauth_auth_lifecycle_policy", Extensibility, "Manage MCP OAuth and authentication lifecycle.", Conditional, Conditional, FixedInvariant),
    partial!(154, "resource_prompt_plugin_capability_exposure", Extensibility, "Expose trusted MCP resources, prompts, and plugin capabilities.", Indirect, Indirect, CatalogCurated),

    // Appendix F.7 — N-SR01..N-SR06, session, cache, and reliability (6).
    missing!(155, "request_compression_policy", Provider, "Select provider request compression.", Indirect, Conditional, OfflineSearch),
    fixed!(156, "http_pool_keepalive_idle_policy", Provider, "Bound HTTP pool idle and TCP keepalive behavior.", Indirect, Conditional, OfflineSearch),
    missing!(157, "rate_limit_aware_admission", Provider, "Gate new provider work from observed rate-limit headroom.", Indirect, Indirect, OfflineSearch),
    missing!(158, "prompt_cache_ttl_breakpoint_strategy", Context, "Declare prompt-cache lifetime and breakpoint strategy when an independent control is implemented.", Indirect, Indirect, OfflineSearch),
    partial!(159, "session_isolation_profile", Governance, "Choose an isolation profile for sessions and evaluations.", Direct, Direct, FixedInvariant),
    fixed!(160, "replay_divergence_detection_policy", Verification, "Reject replay state that diverges from durable evidence.", Indirect, Indirect, FixedInvariant),
];

pub fn families() -> &'static [Family] {
    FAMILIES
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RegistryError;

    #[test]
    fn independent_control_key_rejects_two_ordinary_declarations() {
        let first = family!(Partial;
            137,
            "session_spawn_limit",
            "core.control.orchestration.session_spawn_budget",
            Orchestration,
            "First declaration for a session spawn control.",
            Direct,
            Indirect,
            OfflineSearch
        );
        let second = family!(Partial;
            138,
            "session_spawn_limit_v2",
            "core.control.orchestration.session_spawn_budget",
            Orchestration,
            "Renamed declaration for the same session spawn control.",
            Direct,
            Indirect,
            OfflineSearch
        );

        assert!(matches!(
            crate::validate::validate_semantic_ownership(&[first, second]),
            Err(RegistryError::DuplicateSemanticKey {
                first: "session_spawn_limit",
                second: "session_spawn_limit_v2",
                semantic_key: "core.control.orchestration.session_spawn_budget",
            })
        ));
    }

    #[test]
    fn swapped_unique_control_keys_fail_the_production_mapping_before_digest() {
        let provider_with_model_key = family!(Full;
            1,
            "provider",
            "core.control.provider.model_selection",
            Provider,
            "Provider declaration carrying the model control key.",
            Conditional,
            Indirect,
            RuntimeAdaptive
        );
        let model_with_provider_key = family!(Full;
            2,
            "model",
            "core.control.provider.route_selection",
            Provider,
            "Model declaration carrying the provider control key.",
            Conditional,
            Indirect,
            RuntimeAdaptive
        );

        assert!(matches!(
            crate::validate::validate_semantic_ownership(&[
                provider_with_model_key,
                model_with_provider_key,
            ]),
            Err(RegistryError::SemanticKeyMappingMismatch {
                ordinal: 1,
                actual_id: "provider",
                actual_key: "core.control.provider.model_selection",
                expected_ordinal: 1,
                expected_id: "provider",
                expected_key: "core.control.provider.route_selection",
            })
        ));
    }
}
