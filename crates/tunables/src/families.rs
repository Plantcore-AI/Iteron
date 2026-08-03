use crate::value_schemas::value_schema;
use crate::{
    Availability, BenchmarkImpact as Impact, BenchmarkRelevance, DefaultKind, DefaultSpec, Domain,
    Family, SourceKind, SourceSpec, Trainability,
};

const fn relevance(terminal_bench_2_1: Impact, swe_bench_pro: Impact) -> BenchmarkRelevance {
    BenchmarkRelevance {
        terminal_bench_2_1,
        swe_bench_pro,
        rationale: "Causal class only; quantify with a fixed-model held-out A/B run.",
    }
}

macro_rules! family {
    ($availability:ident; $ordinal:literal, $id:literal, $domain:ident, $summary:literal,
     $default_kind:ident, $default:literal, $source_kind:ident, $locator:literal,
     $tb:ident, $swe:ident, $trainability:ident) => {
        Family {
            ordinal: $ordinal,
            id: $id,
            domain: Domain::$domain,
            summary: $summary,
            default: DefaultSpec {
                kind: DefaultKind::$default_kind,
                value: $default,
            },
            source: SourceSpec {
                kind: SourceKind::$source_kind,
                locator: $locator,
            },
            value_schema: value_schema($ordinal),
            benchmark: relevance(Impact::$tb, Impact::$swe),
            trainability: Trainability::$trainability,
            availability: Availability::$availability,
        }
    };
}

macro_rules! active {
    ($($args:tt)*) => { family!(Active; $($args)*) };
}

macro_rules! partial {
    ($($args:tt)*) => { family!(Partial; $($args)*) };
}

macro_rules! declared {
    ($($args:tt)*) => { family!(Declared; $($args)*) };
}

/// The declaration order is canonical and ordinals are never reused.
#[rustfmt::skip]
static FAMILIES: &[Family] = &[
    // A — active public configuration families.
    active!(1, "provider", Provider, "Select the inference provider instance.", Derived, "resolved route provider", UserConfig, "crates/cli/src/config.rs", Conditional, Indirect, RuntimeAdaptive),
    active!(2, "model", Provider, "Select the model within the admitted provider route.", Derived, "provider default or operator selection", UserConfig, "crates/cli/src/config.rs", Conditional, Indirect, RuntimeAdaptive),
    active!(3, "base_url", Provider, "Override the provider API root.", Derived, "provider catalog endpoint", UserConfig, "crates/cli/src/config.rs", Conditional, Conditional, OperatorOnly),
    active!(4, "effort", Reasoning, "Choose the public reasoning-effort tier.", Literal, "medium", UserConfig, "crates/cli/src/config.rs", Indirect, Indirect, RuntimeAdaptive),
    active!(5, "max_turns", Budget, "Bound provider attempts for one run.", Literal, "40 turns", UserConfig, "crates/cli/src/config.rs", Direct, Direct, OperatorOnly),
    active!(6, "max_usd", Budget, "Bound signed monetary spend for one run.", OperatorRequired, "unbounded unless operator sets a ceiling", UserConfig, "crates/cli/src/config.rs", Conditional, Conditional, OperatorOnly),
    active!(7, "max_tokens", Budget, "Bound aggregate token use for one run.", OperatorRequired, "unbounded unless operator sets a ceiling", Cli, "crates/cli/src/main.rs", Conditional, Conditional, OperatorOnly),
    active!(8, "max_wall_secs", Budget, "Bound run wall-clock duration.", Literal, "1800 seconds", UserConfig, "crates/cli/src/config.rs", Direct, Direct, OperatorOnly),
    active!(9, "allow_code", Governance, "Admit repository code execution when the operator allows it.", Literal, "false", UserConfig, "crates/cli/src/config.rs", Direct, Indirect, OperatorOnly),
    active!(10, "permission_mode", Governance, "Select the operator permission posture.", Literal, "default", UserConfig, "crates/cli/src/config.rs", Conditional, Conditional, OperatorOnly),
    active!(11, "permission_rules", Governance, "Set per-capability allow, ask, or deny rules.", Derived, "mode-derived rules", UserConfig, "crates/cli/src/config.rs", Conditional, Conditional, OperatorOnly),
    active!(12, "bypass_permissions", Governance, "Explicitly bypass interactive permission prompts.", Literal, "false", Cli, "crates/cli/src/main.rs", Conditional, Conditional, OperatorOnly),
    active!(13, "compaction_trigger", Context, "Choose when context compaction starts.", Derived, "model-window adaptive trigger", UserConfig, "crates/cli/src/config.rs", Indirect, Indirect, OfflineSearch),
    active!(14, "verify_command", Verification, "Choose the operator verification command.", OperatorRequired, "none unless operator supplies a command", UserConfig, "crates/cli/src/config.rs", Conditional, Direct, OperatorOnly),

    // B — partial or inactive public families.
    partial!(15, "retry_backoff_base", Runtime, "Set the initial provider retry delay.", Derived, "adapter retry profile", Builtin, "crates/cli/src/config/retry.rs", Conditional, Conditional, OfflineSearch),
    partial!(16, "retry_backoff_cap", Runtime, "Cap provider retry delay.", Derived, "adapter retry profile", Builtin, "crates/cli/src/config/retry.rs", Conditional, Conditional, OfflineSearch),
    partial!(17, "retry_max_attempts", Runtime, "Bound staged provider retries.", Derived, "adapter retry profile", Builtin, "crates/cli/src/config/retry.rs", Direct, Direct, OfflineSearch),
    declared!(18, "egress_allow", Governance, "Declare an egress allow policy surface.", Inactive, "declared but inactive", ProjectConfig, "crates/cli/src/config.rs", None, None, Inactive),

    // C — internal runtime and harness policy families.
    active!(19, "request_output_cap", Provider, "Reserve and cap provider response tokens.", Derived, "provider capability bounded", DerivedPolicy, "crates/cli/src/route.rs", Indirect, Indirect, OfflineSearch),
    active!(20, "effort_reasoning_map", Reasoning, "Map effort tiers onto provider reasoning controls.", Derived, "provider adapter mapping", Builtin, "crates/cli/src/providers.rs", Indirect, Indirect, OfflineSearch),
    active!(21, "thinking_map", Reasoning, "Map effort onto explicit thinking budgets.", Derived, "provider capability mapping", Builtin, "crates/cli/src/providers.rs", Indirect, Indirect, OfflineSearch),
    active!(22, "orchestration_map", Orchestration, "Map effort onto orchestration eligibility.", Derived, "ultracode enables internal orchestration", Builtin, "crates/cli/src/runtime.rs", Indirect, Indirect, OfflineSearch),
    partial!(23, "prompt_cache", Provider, "Control provider prompt-cache use.", Derived, "provider capability default", Builtin, "crates/cli/src/providers.rs", Conditional, Conditional, OfflineSearch),
    active!(24, "compaction_adaptive", Context, "Adapt compaction to model and transcript state.", Derived, "context-window policy", DerivedPolicy, "crates/ctx/src/compact.rs", Indirect, Indirect, RuntimeAdaptive),
    active!(25, "compaction_keep_recent", Context, "Choose the verbatim recent-turn retention window.", Derived, "compaction profile", Builtin, "crates/ctx/src/compact.rs", Indirect, Indirect, OfflineSearch),
    active!(26, "token_estimator", Context, "Estimate tokens for admission and compaction.", Derived, "model tokenizer profile", Catalog, "crates/ctx/src/lib.rs", Conditional, Indirect, CatalogCurated),
    partial!(27, "summary_profile", Context, "Choose the compaction summary shape and budget.", Derived, "compaction profile", Builtin, "crates/ctx/src/compact.rs", Indirect, Indirect, OfflineSearch),
    active!(28, "compaction_failure", Context, "Choose bounded behavior when compaction fails.", Derived, "fail-safe compaction policy", Builtin, "crates/ctx/src/compact.rs", Conditional, Conditional, FixedInvariant),
    partial!(29, "instruction_discovery_render", Context, "Discover and render repository instruction files.", Derived, "bounded nearest-instruction traversal", Builtin, "crates/ctx/src/instructions.rs", Conditional, Indirect, OfflineSearch),
    active!(30, "memory_enable", Memory, "Enable durable memory retrieval and writes.", Literal, "false unless configured", UserConfig, "crates/cli/src/config.rs", Conditional, Indirect, OperatorOnly),
    partial!(31, "memory_budgets", Memory, "Bound memory retrieval, render, and write work.", Derived, "bounded memory policy", Builtin, "crates/ctx/src/memory.rs", Conditional, Indirect, OfflineSearch),
    active!(32, "bm25", Context, "Tune lexical retrieval scoring.", Derived, "built-in BM25 profile", Builtin, "crates/ctx/src/memory.rs", Conditional, Indirect, OfflineSearch),
    active!(33, "skill_listing_budget", Context, "Bound skill catalog text exposed to the model.", Derived, "bounded listing budget", Builtin, "crates/ctx/src/skills.rs", Conditional, Indirect, OfflineSearch),
    active!(34, "max_consecutive_tool_errors", Budget, "Stop a run after repeated tool failures.", Derived, "execution budget", Builtin, "crates/protocol/src/lib.rs", Direct, Direct, OfflineSearch),
    active!(35, "pure_overlap", Orchestration, "Allow eligible pure tools to overlap inference.", Derived, "purity-gated scheduler policy", Builtin, "crates/tools/src/lib.rs", Direct, Indirect, OfflineSearch),
    active!(36, "pure_concurrency", Orchestration, "Bound concurrent pure tool calls.", Derived, "scheduler concurrency ceiling", Builtin, "crates/tools/src/lib.rs", Direct, Indirect, OfflineSearch),
    active!(37, "failed_action_dedup", Tooling, "Suppress repeated identical failed actions.", Derived, "bounded failure ledger", Builtin, "crates/cli/src/runtime.rs", Indirect, Indirect, OfflineSearch),
    active!(38, "pure_memo_cache", Tooling, "Memoize deterministic pure tool results.", Derived, "bounded in-run memo", Builtin, "crates/tools/src/lib.rs", Conditional, Indirect, OfflineSearch),
    partial!(39, "shell_timeout_output", Tooling, "Bound shell wall time and captured output.", Literal, "120 seconds with bounded stdout and stderr", Builtin, "crates/tools/src/shell.rs", Direct, Indirect, OfflineSearch),
    partial!(40, "read_file_limits", Tooling, "Bound file-read bytes and line ranges.", Derived, "tool safety limits", Builtin, "crates/tools/src/fs_tools.rs", Conditional, Indirect, OfflineSearch),
    partial!(41, "list_dir_limits", Tooling, "Bound directory listing work and output.", Derived, "tool safety limits", Builtin, "crates/tools/src/fs_tools.rs", Conditional, Indirect, OfflineSearch),
    partial!(42, "glob_limits", Tooling, "Bound glob traversal and results.", Derived, "tool safety limits", Builtin, "crates/tools/src/fs_tools.rs", Conditional, Indirect, OfflineSearch),
    partial!(43, "grep_limits", Tooling, "Bound text search traversal and output.", Derived, "tool safety limits", Builtin, "crates/tools/src/grep_tool.rs", Conditional, Direct, OfflineSearch),
    partial!(44, "repo_map", Context, "Bound and shape repository-map construction.", Derived, "repository map profile", Builtin, "crates/tools/src/fs_tools.rs", Conditional, Indirect, OfflineSearch),
    partial!(45, "git_limits", Tooling, "Bound Git observation and diff output.", Derived, "Git tool limits", Builtin, "crates/tools/src/git.rs", Conditional, Indirect, OfflineSearch),
    partial!(46, "web_fetch_limits", Tooling, "Bound fetched bytes, redirects, and elapsed time.", Derived, "web fetch policy", Builtin, "crates/tools/src/web.rs", Conditional, Conditional, OfflineSearch),
    active!(47, "web_search_cap", Tooling, "Bound web-search results admitted to context.", Derived, "web search policy", Builtin, "crates/tools/src/web.rs", Conditional, Conditional, OfflineSearch),
    active!(48, "verifier_attempts", Verification, "Bound verification repair attempts.", Derived, "verification policy", Builtin, "crates/verify/src/lib.rs", Conditional, Direct, OfflineSearch),
    partial!(49, "verifier_feedback_tails", Verification, "Bound failure feedback returned to the model.", Derived, "verification policy", Builtin, "crates/verify/src/lib.rs", Conditional, Indirect, OfflineSearch),
    active!(50, "verifier_timeout", Verification, "Bound each verification command.", Derived, "verification policy", Builtin, "crates/verify/src/lib.rs", Direct, Direct, OfflineSearch),
    active!(51, "route_topology", Orchestration, "Choose direct versus orchestrated run topology.", Derived, "route policy", DerivedPolicy, "crates/cli/src/runtime.rs", Indirect, Indirect, RuntimeAdaptive),
    active!(52, "decomposition_profile", Orchestration, "Choose task decomposition shape.", Derived, "workflow profile", Builtin, "crates/cli/src/runtime.rs", Indirect, Indirect, OfflineSearch),
    active!(53, "fan_breadth", Orchestration, "Bound investigator fan-out breadth.", Derived, "workflow profile", Builtin, "crates/agents/src/lib.rs", Indirect, Indirect, OfflineSearch),
    active!(54, "admission", Orchestration, "Admit bounded child work under parent ceilings.", Derived, "intersection-only admission", Builtin, "crates/kernel/src/admission.rs", Conditional, Conditional, FixedInvariant),
    active!(55, "writer_fan_turn_split", Orchestration, "Split turns between investigators and the writer.", Derived, "workflow budget profile", Builtin, "crates/cli/src/runtime.rs", Indirect, Indirect, OfflineSearch),
    active!(56, "worker_min_turns", Orchestration, "Reserve a minimum useful child turn allocation.", Derived, "workflow budget profile", Builtin, "crates/cli/src/runtime.rs", Indirect, Indirect, OfflineSearch),
    active!(57, "wall_split", Orchestration, "Split remaining wall time across child work.", Derived, "parent-bounded allocation", Builtin, "crates/cli/src/runtime.rs", Indirect, Indirect, OfflineSearch),
    active!(58, "token_split", Orchestration, "Split remaining tokens across child work.", Derived, "parent-bounded allocation", Builtin, "crates/cli/src/runtime.rs", Indirect, Indirect, OfflineSearch),
    active!(59, "fan_concurrency", Orchestration, "Bound simultaneous investigator agents.", Derived, "workflow concurrency ceiling", Builtin, "crates/agents/src/lib.rs", Indirect, Indirect, OfflineSearch),
    active!(60, "child_ceiling", Orchestration, "Intersect every child with an immutable parent ceiling.", Derived, "parent budget and capability intersection", Builtin, "crates/kernel/src/admission.rs", Conditional, Conditional, FixedInvariant),
    partial!(61, "direct_child_allocation", Orchestration, "Allocate budget to directly spawned children.", Derived, "parent-bounded allocation", Builtin, "crates/cli/src/runtime.rs", Indirect, Indirect, OfflineSearch),
    active!(62, "subagent_effort_inheritance", Orchestration, "Choose bounded subagent reasoning effort.", Derived, "parent effort mapping", Builtin, "crates/agents/src/lib.rs", Indirect, Indirect, OfflineSearch),
    active!(63, "report_budget", Orchestration, "Bound child report size admitted to the writer.", Derived, "workflow report budget", Builtin, "crates/agents/src/lib.rs", Conditional, Indirect, OfflineSearch),
    active!(64, "join_reduce", Orchestration, "Choose deterministic join and reduction policy.", Derived, "workflow reducer", Builtin, "crates/workflow/src/lib.rs", Indirect, Indirect, OfflineSearch),
    partial!(65, "workflow_aggregate", Orchestration, "Bound aggregate workflow calls and resources.", Derived, "workflow run budget", Builtin, "crates/workflow/src/lib.rs", Indirect, Indirect, OfflineSearch),
    partial!(66, "schema_retry_jitter", Runtime, "Bound schema-repair retries and jitter.", Derived, "provider schema policy", Builtin, "crates/cli/src/runtime.rs", Conditional, Indirect, OfflineSearch),
    active!(67, "delegation_depth", Orchestration, "Bound recursive delegation depth.", Derived, "workflow depth ceiling", Builtin, "crates/workflow/src/lib.rs", Indirect, Indirect, OfflineSearch),
    partial!(68, "multimodal_input_admission_decode_envelope", Runtime, "Bound image count, bytes, dimensions, frames, and decode work.", Literal, "8 images; 6 MiB raw each; 24 MiB raw aggregate", Builtin, "crates/cli/src/image_input.rs", None, None, FixedInvariant),
    partial!(69, "app_server_sq_eq_backpressure", Runtime, "Bound submission and event queues with typed drop policy.", Literal, "SQ 256; EQ 1024; byte-bounded submissions", Builtin, "crates/cli/src/tui/app_server.rs", Conditional, Conditional, FixedInvariant),
    partial!(70, "provider_discovery_account_probe_cache_policy", Provider, "Bound provider startup discovery, probe freshness, and failure backoff.", Literal, "1.5 second eager budget; 15 minute positive TTL", Builtin, "crates/cli/src/providers.rs", Conditional, Conditional, OfflineSearch),

    // D — content, catalogs, and environment surfaces.
    active!(71, "operator_prompt_stream", Context, "Operator-authored task and steering text.", OperatorRequired, "operator input", RuntimeObservation, "core_protocol::Op", Direct, Direct, OperatorOnly),
    active!(72, "builtin_prompt_corpus", Reasoning, "Built-in system and workflow prompt corpus.", Catalog, "source-controlled prompt set", Catalog, "crates/cli/src/main.rs", Indirect, Indirect, OfflineSearch),
    active!(73, "instruction_bundle", Context, "Repository and user instruction content.", Catalog, "nearest admitted instruction files", ProjectConfig, "crates/ctx/src/instructions.rs", Conditional, Direct, CatalogCurated),
    active!(74, "memory_corpus", Memory, "Durable admitted memory records.", Catalog, "tenant and repository scoped corpus", Catalog, "crates/ctx/src/memory.rs", Conditional, Indirect, CatalogCurated),
    active!(75, "skill_catalog", Extensibility, "Discovered skill metadata and instructions.", Catalog, "built-in plus configured skills", Catalog, "crates/ctx/src/skills.rs", Conditional, Indirect, CatalogCurated),
    partial!(76, "agent_catalog", Extensibility, "Discover bounded agent definitions for model-visible role selection.", Catalog, "built-in plus discovered agent definitions; live role binding remains incomplete", Catalog, "crates/agents/src/catalog.rs", Conditional, Indirect, CatalogCurated),
    active!(77, "provider_model_capability_catalog", Provider, "Provider and model capability evidence.", Catalog, "embedded, cached, or operator-declared catalog", Catalog, "crates/cli/src/providers.rs", Conditional, Indirect, CatalogCurated),
    active!(78, "mcp_topology_tool_catalog", Extensibility, "Configured MCP servers and their tool schemas.", Catalog, "trusted stdio server configuration", UserConfig, "crates/cli/src/mcp.rs", Conditional, Conditional, OperatorOnly),
    active!(79, "hooks_map", Extensibility, "Lifecycle hook declarations and selectors.", Catalog, "operator configuration", UserConfig, "crates/cli/src/runtime/hooks.rs", Conditional, Conditional, OperatorOnly),
    active!(80, "workflow_graph", Orchestration, "Declared workflow task graph.", Catalog, "built-in or operator workflow", Catalog, "crates/workflow/src/lib.rs", Indirect, Indirect, OfflineSearch),
    active!(81, "tool_action_space", Tooling, "Registered tool schemas and capability classes.", Catalog, "source-controlled registry plus admitted extensions", Catalog, "crates/tools/src/lib.rs", Direct, Direct, CatalogCurated),
    active!(82, "rate_card_catalog", Observability, "Signed provider pricing evidence.", Catalog, "embedded or operator-bound rate cards", Catalog, "crates/obs/src/lib.rs", None, None, CatalogCurated),
    active!(83, "router_lexicons", Reasoning, "Lexical signals used by routing policy.", Catalog, "source-controlled lexicons", Builtin, "crates/agents/src/decompose.rs", Indirect, Indirect, OfflineSearch),
    active!(84, "environment_snapshot", Context, "Durable bounded repository and process environment facts.", Derived, "captured at the run boundary", RuntimeObservation, "crates/protocol/src/context.rs", Conditional, Indirect, FixedInvariant),
    active!(85, "web_search_backend_catalog", Extensibility, "Available web-search backend definitions.", Catalog, "configured backend catalog", Catalog, "crates/tools/src/web.rs", Conditional, Conditional, CatalogCurated),

    // Appendix F.1 — N-RM01..N-RM10, model routing and transport (10).
    declared!(86, "model_fallback_chain", Provider, "Choose an ordered model fallback chain.", Inactive, "proposed default: unset/empty; inference failover is not wired", Registry, "crates/tunables/src/families.rs", Indirect, Indirect, CatalogCurated),
    partial!(87, "failover_eligible_error_taxonomy", Provider, "Classify provider errors that may admit failover.", Literal, "conservative built-in taxonomy; no inference failover consumer yet", Builtin, "crates/provider/src/lib.rs", Indirect, Indirect, FixedInvariant),
    declared!(88, "route_quality_cost_latency_objective_weights", Reasoning, "Weight route quality, cost, and latency objectives.", Inactive, "proposed default: derived profile; no objective-weight seam", Registry, "crates/tunables/src/families.rs", Direct, Direct, OfflineSearch),
    partial!(89, "provider_health_circuit_breaker_state_policy", Provider, "Derive route health and circuit-breaker state.", Derived, "provider-health derived state; circuit-breaker control remains incomplete", DerivedPolicy, "crates/provider/src/catalog.rs", Indirect, Indirect, CatalogCurated),
    declared!(90, "hedged_request_policy", Provider, "Choose bounded duplicate-request hedging.", Inactive, "proposed default: disabled; no hedged-request seam", Registry, "crates/tunables/src/families.rs", Indirect, Indirect, CatalogCurated),
    declared!(91, "provider_service_tier", Provider, "Select a provider service tier.", Inactive, "proposed default: provider dynamic; no service-tier seam", Registry, "crates/tunables/src/families.rs", Direct, Indirect, CatalogCurated),
    declared!(92, "response_verbosity", Reasoning, "Select response verbosity independently of effort.", Inactive, "proposed default: model dynamic; no verbosity seam", Registry, "crates/tunables/src/families.rs", Conditional, Indirect, OfflineSearch),
    partial!(93, "role_specific_model_map", Orchestration, "Map agent roles to admitted model routes.", Derived, "inherit primary model; per-agent overrides exist but catalog role binding is incomplete", DerivedPolicy, "crates/cli/src/runtime/workflow_spawner.rs", Indirect, Direct, CatalogCurated),
    active!(94, "provider_request_total_deadline", Provider, "Bound the total duration of one provider request.", Derived, "bounded by the remaining run wall time and a 15 minute adapter ceiling", Builtin, "crates/provider/src/responses.rs", Direct, Indirect, OfflineSearch),
    active!(95, "stream_idle_watchdog", Provider, "Abort a provider stream that stops making progress.", Derived, "provider-derived policy with a 120 second adapter idle ceiling", Builtin, "crates/provider/src/responses.rs", Indirect, Indirect, OfflineSearch),

    // Appendix F.2 — N-CX01..N-CX12, context, retrieval, and compaction (12).
    partial!(96, "context_window_override_reserve", Context, "Resolve the effective context window and output reserve.", Derived, "model metadata with dynamic output reserve; no unified override object", DerivedPolicy, "crates/ctx/src/compact.rs", Direct, Direct, CatalogCurated),
    partial!(97, "system_prefix_budget", Context, "Bound the stable system prefix.", Derived, "derived fraction represented by instruction, memory, and skill sub-budgets", Builtin, "crates/ctx/src/instructions.rs", Indirect, Direct, OfflineSearch),
    partial!(98, "conversation_history_budget", Context, "Bound conversation history admitted to a request.", Derived, "derived fraction enforced through aggregate compaction", DerivedPolicy, "crates/ctx/src/compact.rs", Direct, Direct, OfflineSearch),
    partial!(99, "tool_result_history_budget", Context, "Bound retained tool-result history.", Derived, "derived fraction enforced only through aggregate request accounting", DerivedPolicy, "crates/cli/src/runtime.rs", Direct, Direct, OfflineSearch),
    partial!(100, "multimodal_token_budget", Context, "Bound multimodal content admitted to model context.", Derived, "capability-derived byte and decode envelope; token partition remains incomplete", Builtin, "crates/cli/src/image_input.rs", Indirect, Conditional, CatalogCurated),
    active!(101, "auto_compaction_enable", Context, "Enable automatic bounded context compaction.", Literal, "on", Builtin, "crates/ctx/src/compact.rs", Direct, Direct, OfflineSearch),
    partial!(102, "compaction_cooldown_hysteresis", Context, "Avoid repeated compaction around the trigger boundary.", Derived, "derived turn-end and overflow thresholds; no independent cooldown duration", DerivedPolicy, "crates/ctx/src/compact.rs", Direct, Direct, OfflineSearch),
    partial!(103, "multi_stage_summary_topology", Context, "Choose a bounded summary-stage topology.", Literal, "single stage", Builtin, "crates/ctx/src/compact.rs", Indirect, Direct, CatalogCurated),
    declared!(104, "summary_consistency_coverage_check", Verification, "Check summary consistency and evidence coverage.", Inactive, "proposed default: off; no summary coverage checker", Registry, "crates/tunables/src/families.rs", Indirect, Direct, CatalogCurated),
    partial!(105, "hybrid_retrieval_fusion_weights", Memory, "Fuse lexical and optional retrieval signals.", Literal, "BM25-only baseline; no hybrid signal consumer yet", Builtin, "crates/ctx/src/memory.rs", Indirect, Direct, OfflineSearch),
    declared!(106, "retrieval_recency_decay", Memory, "Apply bounded recency decay to retrieval scores.", Inactive, "proposed default: neutral; no recency-decay seam", Registry, "crates/tunables/src/families.rs", Indirect, Direct, OfflineSearch),
    partial!(107, "context_novelty_dedup_threshold", Context, "Suppress duplicate or low-novelty context.", Derived, "conservative identity-based dedup; no unified novelty threshold", Builtin, "crates/ctx/src/memory.rs", Indirect, Direct, OfflineSearch),

    // Appendix F.3 — N-TP01..N-TP15, tools, processes, and code intelligence (15).
    declared!(108, "persistent_pty_backend", Tooling, "Select a persistent PTY backend.", Inactive, "proposed default: disabled with one-shot fallback; no PTY backend", Registry, "crates/tunables/src/families.rs", Direct, Indirect, CatalogCurated),
    declared!(109, "concurrent_background_job_cap", Tooling, "Bound concurrent background jobs.", Inactive, "proposed default: disabled until PTY support; no job table", Registry, "crates/tunables/src/families.rs", Direct, Conditional, OfflineSearch),
    declared!(110, "job_idle_stall_timeout", Tooling, "Stop a background job that is idle or stalled.", Inactive, "proposed default: derived below wall; no background-job seam", Registry, "crates/tunables/src/families.rs", Direct, Conditional, OfflineSearch),
    declared!(111, "interactive_stdin_wait_policy", Tooling, "Bound waits for interactive process input.", Inactive, "proposed default: bounded/dynamic; no interactive-stdin seam", Registry, "crates/tunables/src/families.rs", Direct, Conditional, CatalogCurated),
    active!(112, "process_signal_kill_escalation", Tooling, "Escalate process-group termination and reap children.", Literal, "TERM to KILL built-in escalation", Builtin, "crates/sandbox/src/lib.rs", Direct, Conditional, FixedInvariant),
    partial!(113, "process_cwd_continuity", Tooling, "Preserve process and working-directory continuity.", Literal, "session-scoped workspace with one-shot processes", Builtin, "crates/tools/src/shell.rs", Direct, Indirect, CatalogCurated),
    partial!(114, "child_process_environment_reuse", Tooling, "Reuse a bounded child-process environment snapshot.", Literal, "safe environment snapshot per job; no persistent job reuse", Builtin, "crates/sandbox/src/lib.rs", Direct, Indirect, FixedInvariant),
    active!(115, "effecting_tool_concurrency", Orchestration, "Bound concurrency among admitted effecting tools.", Derived, "serial baseline with bounded non-overlapping auto-approved batches", DerivedPolicy, "crates/cli/src/runtime.rs", Direct, Indirect, OfflineSearch),
    active!(116, "write_set_conflict_admission", Tooling, "Admit concurrent writes only when declared write sets do not overlap.", Literal, "reject overlapping declared write sets", Builtin, "crates/cli/src/runtime.rs", Indirect, Direct, CatalogCurated),
    declared!(117, "tool_output_spill_to_disk_policy", Tooling, "Spill bounded tool output outside model context.", Inactive, "proposed default: threshold derived; no spill-to-disk seam", Registry, "crates/tunables/src/families.rs", Direct, Indirect, OfflineSearch),
    partial!(118, "binary_media_inspection_routing", Tooling, "Route binary and media inspection by capability.", Derived, "capability-derived image admission plus bounded binary refusal", DerivedPolicy, "crates/cli/src/image_input.rs", Indirect, Conditional, CatalogCurated),
    declared!(119, "lsp_server_language_selection", Tooling, "Select LSP servers for discovered languages.", Inactive, "proposed default: auto discovery; no live LSP seam", Registry, "crates/tunables/src/families.rs", Indirect, Direct, CatalogCurated),
    declared!(120, "lsp_timeout_restart_policy", Tooling, "Bound LSP requests and server restarts.", Inactive, "proposed default: bounded backoff; no live LSP seam", Registry, "crates/tunables/src/families.rs", Indirect, Direct, OfflineSearch),
    declared!(121, "lsp_result_context_budget", Context, "Bound LSP evidence admitted to context.", Inactive, "proposed default: derived; no live LSP result seam", Registry, "crates/tunables/src/families.rs", Indirect, Direct, OfflineSearch),
    partial!(122, "tool_result_cache_ttl", Tooling, "Bound deterministic tool-result cache reuse.", Derived, "generation-scoped and determinism-aware; no independent duration TTL", Builtin, "crates/tools/src/lib.rs", Indirect, Indirect, OfflineSearch),

    // Appendix F.4 — N-VR01..N-VR10, verification, recovery, and rewind (10).
    active!(123, "test_selection_strategy", Verification, "Select the verification command and evidence scope.", Derived, "explicit command over the full known workspace", Builtin, "crates/verify/src/oracle.rs", Indirect, Direct, CatalogCurated),
    partial!(124, "incremental_versus_full_verification", Verification, "Choose incremental or full verification by risk.", Derived, "workspace-full gating with lane/full strategy seams; risk derivation is incomplete", DerivedPolicy, "crates/verify/src/strategy.rs", Indirect, Direct, OfflineSearch),
    partial!(125, "flaky_test_detection_quarantine", Verification, "Detect disagreement and quarantine flaky evidence.", Literal, "off unless repeated evidence; disagreement detection exists without quarantine", Builtin, "crates/verify/src/strategy.rs", Indirect, Direct, FixedInvariant),
    active!(126, "failure_classification_taxonomy", Verification, "Classify verification failures with a versioned taxonomy.", Catalog, "built-in versioned outcome taxonomy", Catalog, "crates/verify/src/oracle.rs", Direct, Direct, FixedInvariant),
    active!(127, "retry_eligibility_policy", Verification, "Retry only verification outcomes that are eligible.", Derived, "conservative outcome-classified retry", DerivedPolicy, "crates/cli/src/runtime.rs", Direct, Direct, OfflineSearch),
    declared!(128, "rollback_on_verification_failure", Verification, "Rollback selected workspace changes after verification failure.", Inactive, "proposed default: off/selective; no automatic rollback seam", Registry, "crates/tunables/src/families.rs", Indirect, Direct, CatalogCurated),
    partial!(129, "workspace_checkpoint_cadence", Verification, "Choose durable workspace checkpoint boundaries.", Derived, "drain and verification safe points; not every turn boundary", DerivedPolicy, "crates/cli/src/runtime.rs", Conditional, Indirect, CatalogCurated),
    partial!(130, "selective_restore_scope", Verification, "Choose an explicit user-authorized restore scope.", Literal, "explicit whole-workspace rewind; selective path scope is incomplete", Builtin, "crates/record/src/checkpoint.rs", Conditional, Indirect, FixedInvariant),
    partial!(131, "verification_quorum_consensus", Verification, "Require bounded verifier agreement.", Literal, "single verifier by default; bounded repeat and ensemble seam is not runtime-complete", Builtin, "crates/verify/src/strategy.rs", Indirect, Direct, OfflineSearch),
    active!(132, "recovery_escalation_policy", Verification, "Escalate verification recovery from retry to replan to stop.", Literal, "retry, replan, then stop", Builtin, "crates/cli/src/runtime.rs", Direct, Direct, OfflineSearch),

    // Appendix F.5 — N-AG01..N-AG14, agents, tasks, and collaboration (14).
    active!(133, "per_agent_model", Orchestration, "Choose a model for one admitted agent.", Derived, "inherit parent model unless the workflow call overrides it", DerivedPolicy, "crates/cli/src/runtime/workflow_spawner.rs", Indirect, Direct, CatalogCurated),
    active!(134, "per_agent_effort_thinking", Orchestration, "Choose effort and thinking for one admitted agent.", Derived, "inherit parent effort unless the workflow call overrides it", DerivedPolicy, "crates/cli/src/runtime/workflow_spawner.rs", Indirect, Direct, OfflineSearch),
    active!(135, "per_agent_tool_profile", Orchestration, "Narrow the tool profile for one admitted agent.", Derived, "inherit the parent intersection; writer capability remains explicit", DerivedPolicy, "crates/cli/src/runtime/workflow_spawner.rs", Indirect, Direct, CatalogCurated),
    partial!(136, "per_agent_memory_scope", Memory, "Choose isolated or explicitly shared agent memory.", Literal, "isolated child run state; explicit memory sharing remains incomplete", Builtin, "crates/cli/src/runtime/workflow_spawner.rs", Indirect, Direct, CatalogCurated),
    active!(137, "spawn_depth_control", Orchestration, "Bound recursive agent spawning.", Literal, "one level", Builtin, "crates/cli/src/runtime/workflow_spawner.rs", Direct, Indirect, OfflineSearch),
    active!(138, "per_session_spawn_cap", Orchestration, "Bound total agent spawns in one session.", Derived, "bounded by the workflow lifetime ceiling", Builtin, "crates/workflow/src/lib.rs", Direct, Indirect, OfflineSearch),
    partial!(139, "task_priority_scheduling", Orchestration, "Schedule ready tasks by bounded priority.", Literal, "FIFO and dependency-ready execution; no independent priority field", Builtin, "crates/workflow/src/bindings.rs", Direct, Indirect, OfflineSearch),
    declared!(140, "speculative_sibling_count", Orchestration, "Bound speculative sibling agents.", Inactive, "proposed default: zero; no speculative-sibling seam", Registry, "crates/tunables/src/families.rs", Indirect, Direct, OfflineSearch),
    declared!(141, "speculative_sibling_cancellation", Orchestration, "Cancel losing speculative siblings from evidence.", Inactive, "proposed default: evidence-based; no speculative-sibling seam", Registry, "crates/tunables/src/families.rs", Indirect, Direct, OfflineSearch),
    partial!(142, "early_stop_quorum_policy", Orchestration, "Stop a fan only after required evidence reaches quorum.", Literal, "wait for required ordered evidence; no adaptive quorum", Builtin, "crates/agents/src/reduce.rs", Indirect, Direct, OfflineSearch),
    declared!(143, "writer_worktree_isolation_mode", Governance, "Isolate write-capable agents in worktrees.", Inactive, "proposed default: off until supported; no writer-worktree seam", Registry, "crates/tunables/src/families.rs", Conditional, Direct, FixedInvariant),
    declared!(144, "merge_conflict_arbitration", Verification, "Arbitrate verified child merges and conflicts.", Inactive, "proposed default: verify then explicit merge; no merge-arbitration seam", Registry, "crates/tunables/src/families.rs", Conditional, Direct, CatalogCurated),
    active!(145, "inter_agent_messaging_topology", Orchestration, "Route bounded agent reports through the parent.", Literal, "parent-mediated ordered reports", Builtin, "crates/agents/src/reduce.rs", Indirect, Direct, CatalogCurated),
    declared!(146, "task_retry_reassignment_policy", Orchestration, "Retry or reassign a failed agent task.", Inactive, "proposed default: bounded conservative; no task reassignment seam", Registry, "crates/tunables/src/families.rs", Direct, Direct, OfflineSearch),

    // Appendix F.6 — N-MP01..N-MP08, MCP and plugin lifecycle (8).
    partial!(147, "mcp_transport_selection", Extensibility, "Select an admitted MCP transport.", Literal, "stdio only", Builtin, "crates/mcp/src/client.rs", Indirect, Indirect, CatalogCurated),
    partial!(148, "deferred_discovery_threshold", Extensibility, "Defer MCP discovery after a bounded threshold.", Literal, "eager baseline; no threshold activation", Builtin, "crates/cli/src/mcp.rs", Indirect, Indirect, OfflineSearch),
    declared!(149, "mcp_reconnect_backoff", Extensibility, "Bound MCP reconnect attempts and delay.", Inactive, "proposed default: bounded exponential; no reconnect seam", Registry, "crates/tunables/src/families.rs", Indirect, Indirect, OfflineSearch),
    active!(150, "per_server_startup_deadline", Extensibility, "Bound MCP server startup and initialization.", Derived, "bounded per-server deadline with a 15 second handshake ceiling", Builtin, "crates/mcp/src/client.rs", Indirect, Indirect, OfflineSearch),
    active!(151, "per_tool_mcp_deadline", Extensibility, "Bound one MCP tool exchange.", Derived, "bounded per-tool deadline with a 60 second request ceiling", Builtin, "crates/mcp/src/client.rs", Direct, Indirect, OfflineSearch),
    partial!(152, "mcp_result_cap_spill_policy", Extensibility, "Cap or spill MCP results before model exposure.", Literal, "bounded in memory by the frame ceiling; no spill path", Builtin, "crates/mcp/src/client/content.rs", Indirect, Indirect, OfflineSearch),
    declared!(153, "oauth_auth_lifecycle_policy", Extensibility, "Manage MCP OAuth and authentication lifecycle.", Inactive, "proposed default: protocol/provider derived; no OAuth lifecycle seam", Registry, "crates/tunables/src/families.rs", Conditional, Conditional, FixedInvariant),
    partial!(154, "resource_prompt_plugin_capability_exposure", Extensibility, "Expose trusted MCP resources, prompts, and plugin capabilities.", Literal, "disabled unless trusted; only tools are discovered and non-text resources are omitted", Builtin, "crates/mcp/src/client/content.rs", Indirect, Indirect, CatalogCurated),

    // Appendix F.7 — N-SR01..N-SR06, session, cache, and reliability (6).
    declared!(155, "request_compression_policy", Provider, "Select provider request compression.", Inactive, "proposed default: provider capability; no request-compression seam", Registry, "crates/tunables/src/families.rs", Indirect, Conditional, OfflineSearch),
    active!(156, "http_pool_keepalive_idle_policy", Provider, "Bound HTTP pool idle and TCP keepalive behavior.", Literal, "300 second pool idle timeout and 30 second TCP keepalive", Builtin, "crates/provider/src/catalog.rs", Indirect, Conditional, OfflineSearch),
    declared!(157, "rate_limit_aware_admission", Provider, "Gate new provider work from observed rate-limit headroom.", Inactive, "proposed default: conservative; snapshots are observed but not used for admission", Registry, "crates/tunables/src/families.rs", Indirect, Indirect, OfflineSearch),
    partial!(158, "prompt_cache_ttl_breakpoint_strategy", Context, "Choose prompt-cache lifetime and breakpoints.", Derived, "provider-capability breakpoint placement; no independent TTL", DerivedPolicy, "crates/provider/src/anthropic.rs", Indirect, Indirect, OfflineSearch),
    partial!(159, "session_isolation_profile", Governance, "Choose an isolation profile for sessions and evaluations.", Literal, "hermetic for evaluation; production session profile is fixed and incomplete", Builtin, "crates/record/src/lib.rs", Direct, Direct, FixedInvariant),
    active!(160, "replay_divergence_detection_policy", Verification, "Reject replay state that diverges from durable evidence.", Literal, "fail closed", Builtin, "crates/record/src/lib.rs", Indirect, Indirect, FixedInvariant),
];

pub fn families() -> &'static [Family] {
    FAMILIES
}
