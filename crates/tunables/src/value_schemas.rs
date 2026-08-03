use crate::{EXPECTED_FAMILY_COUNT, NumericType, StructuredValueDomain, ValueKind, ValueSchema};

macro_rules! structured_domain {
    (Bool, $description:literal, $unit:literal) => {
        StructuredValueDomain::Boolean
    };
    (Enum, "low, medium, high, xhigh, max, ultracode", $unit:literal) => {
        StructuredValueDomain::FiniteEnum {
            values: &["low", "medium", "high", "xhigh", "max", "ultracode"],
            open_catalog: false,
            catalog_ref: None,
        }
    };
    (Enum, $description:literal, $unit:literal) => {
        StructuredValueDomain::FiniteEnum {
            values: &[],
            open_catalog: true,
            catalog_ref: Some("core://tunables/catalogs/admitted-values-v1"),
        }
    };
    (Count, "positive integer", $unit:literal) => {
        StructuredValueDomain::Numeric {
            numeric_type: NumericType::Integer,
            min: Some(1),
            max: Some(1_000_000),
            unit: $unit,
        }
    };
    (Count, $description:literal, $unit:literal) => {
        StructuredValueDomain::Numeric {
            numeric_type: NumericType::Integer,
            min: Some(0),
            max: Some(1_000_000),
            unit: $unit,
        }
    };
    (Duration, "positive integer seconds", $unit:literal) => {
        StructuredValueDomain::Numeric {
            numeric_type: NumericType::Integer,
            min: Some(1),
            max: Some(86_400),
            unit: $unit,
        }
    };
    (Duration, "positive integer milliseconds", $unit:literal) => {
        StructuredValueDomain::Numeric {
            numeric_type: NumericType::Integer,
            min: Some(1),
            max: Some(86_400_000),
            unit: $unit,
        }
    };
    (Duration, $description:literal, $unit:literal) => {
        StructuredValueDomain::Numeric {
            numeric_type: NumericType::Integer,
            min: Some(0),
            max: Some(86_400_000),
            unit: $unit,
        }
    };
    (Bytes, "positive integer bytes", $unit:literal) => {
        StructuredValueDomain::Numeric {
            numeric_type: NumericType::Integer,
            min: Some(1),
            max: Some(1_073_741_824),
            unit: $unit,
        }
    };
    (Bytes, $description:literal, $unit:literal) => {
        StructuredValueDomain::Numeric {
            numeric_type: NumericType::Integer,
            min: Some(0),
            max: Some(1_073_741_824),
            unit: $unit,
        }
    };
    (Ratio, $description:literal, $unit:literal) => {
        StructuredValueDomain::Numeric {
            numeric_type: NumericType::Decimal,
            min: Some(0),
            max: Some(1),
            unit: $unit,
        }
    };
    (Decimal, $description:literal, $unit:literal) => {
        StructuredValueDomain::Numeric {
            numeric_type: NumericType::Decimal,
            min: Some(0),
            max: Some(1_000_000_000),
            unit: $unit,
        }
    };
    (String, $description:literal, $unit:literal) => {
        StructuredValueDomain::Text {
            min_bytes: 0,
            max_bytes: Some(1_048_576),
            format: $unit,
        }
    };
    (List, $description:literal, $unit:literal) => {
        StructuredValueDomain::List {
            min_items: 0,
            max_items: Some(4_096),
            item_schema: "core://tunables/schemas/namespaced-id-v1",
            unique_items: true,
        }
    };
    (Map, $description:literal, $unit:literal) => {
        StructuredValueDomain::Map {
            min_entries: 0,
            max_entries: Some(4_096),
            key_schema: "core://tunables/schemas/namespaced-id-v1",
            value_schema: "core://tunables/schemas/bounded-map-value-v1",
        }
    };
    (Policy, $description:literal, $unit:literal) => {
        StructuredValueDomain::Composite {
            schema_ref: "core://tunables/schemas/bounded-policy-v1",
            max_bytes: 262_144,
            max_nodes: 4_096,
            max_depth: 32,
        }
    };
    (Catalog, $description:literal, $unit:literal) => {
        StructuredValueDomain::Catalog {
            min_entries: 0,
            max_entries: Some(10_000),
            entry_schema: "core://tunables/schemas/versioned-catalog-entry-v1",
            open_catalog: true,
        }
    };
}

macro_rules! schema {
    (Enum, "low, medium, high, xhigh, max, ultracode", $constraint:literal, $unit:literal) => {
        ValueSchema {
            kind: ValueKind::Enum,
            domain: StructuredValueDomain::FiniteEnum {
                values: &["low", "medium", "high", "xhigh", "max", "ultracode"],
                open_catalog: false,
                catalog_ref: None,
            },
            description: "low, medium, high, xhigh, max, ultracode",
            constraints: &[$constraint],
        }
    };
    (Count, "positive integer", $constraint:literal, $unit:literal) => {
        ValueSchema {
            kind: ValueKind::Count,
            domain: StructuredValueDomain::Numeric {
                numeric_type: NumericType::Integer,
                min: Some(1),
                max: Some(1_000_000),
                unit: $unit,
            },
            description: "positive integer",
            constraints: &[$constraint],
        }
    };
    (Duration, "positive integer seconds", $constraint:literal, $unit:literal) => {
        ValueSchema {
            kind: ValueKind::Duration,
            domain: StructuredValueDomain::Numeric {
                numeric_type: NumericType::Integer,
                min: Some(1),
                max: Some(86_400),
                unit: $unit,
            },
            description: "positive integer seconds",
            constraints: &[$constraint],
        }
    };
    (Duration, "positive integer milliseconds", $constraint:literal, $unit:literal) => {
        ValueSchema {
            kind: ValueKind::Duration,
            domain: StructuredValueDomain::Numeric {
                numeric_type: NumericType::Integer,
                min: Some(1),
                max: Some(86_400_000),
                unit: $unit,
            },
            description: "positive integer milliseconds",
            constraints: &[$constraint],
        }
    };
    (Bytes, "positive integer bytes", $constraint:literal, $unit:literal) => {
        ValueSchema {
            kind: ValueKind::Bytes,
            domain: StructuredValueDomain::Numeric {
                numeric_type: NumericType::Integer,
                min: Some(1),
                max: Some(1_073_741_824),
                unit: $unit,
            },
            description: "positive integer bytes",
            constraints: &[$constraint],
        }
    };
    (String, "absolute HTTP or HTTPS URI", $constraint:literal, $unit:literal) => {
        ValueSchema {
            kind: ValueKind::String,
            domain: StructuredValueDomain::Text {
                min_bytes: 1,
                max_bytes: Some(1_048_576),
                format: $unit,
            },
            description: "absolute HTTP or HTTPS URI",
            constraints: &[$constraint],
        }
    };
    (String, "non-empty command string", $constraint:literal, $unit:literal) => {
        ValueSchema {
            kind: ValueKind::String,
            domain: StructuredValueDomain::Text {
                min_bytes: 1,
                max_bytes: Some(1_048_576),
                format: $unit,
            },
            description: "non-empty command string",
            constraints: &[$constraint],
        }
    };
    ($kind:ident, $description:literal, $constraint:literal, $unit:literal) => {
        ValueSchema {
            kind: ValueKind::$kind,
            domain: structured_domain!($kind, $description, $unit),
            description: $description,
            constraints: &[$constraint],
        }
    };
}

/// Positional value schemas aligned with the canonical family ordinals.
///
/// The fixed-size array makes omission a compile error; registry validation additionally rejects
/// blank domain text. Ordinals are stable and never reused.
#[rustfmt::skip]
static VALUE_SCHEMAS: [ValueSchema; EXPECTED_FAMILY_COUNT] = [
    // A — active public configuration families.
    schema!(Enum, "configured provider identifier", "must resolve to an admitted provider route", "provider id"), // 1 provider
    schema!(Enum, "model identifier advertised by the selected provider", "must satisfy the route capability envelope", "model id"), // 2 model
    schema!(String, "absolute HTTP or HTTPS URI", "operator-owned override; credentials and fragments are forbidden", "URI"), // 3 base_url
    schema!(Enum, "low, medium, high, xhigh, max, ultracode", "must not exceed the operator effort ceiling", "choice"), // 4 effort
    schema!(Count, "positive integer", "minimum 1 and bounded by the parent run ceiling", "turns"), // 5 max_turns
    schema!(Decimal, "non-negative finite decimal", "must not exceed the operator monetary ceiling", "USD"), // 6 max_usd
    schema!(Count, "positive integer", "must remain within the aggregate run token ceiling", "tokens"), // 7 max_tokens
    schema!(Duration, "positive integer seconds", "minimum 1 and bounded by the parent run wall ceiling", "seconds"), // 8 max_wall_secs
    schema!(Bool, "true or false", "true requires explicit operator code-execution authority", "boolean"), // 9 allow_code
    schema!(Enum, "declared permission-mode identifier", "may only preserve or reduce operator authority", "choice"), // 10 permission_mode
    schema!(Map, "capability keys to allow, ask, or deny decisions", "must be intersected with the selected permission mode", "rule entries"), // 11 permission_rules
    schema!(Bool, "true or false", "true requires explicit operator selection and never becomes a learned value", "boolean"), // 12 bypass_permissions
    schema!(Policy, "bounded trigger policy or model-window-derived threshold", "must reserve response and verification capacity", "policy object"), // 13 compaction_trigger
    schema!(String, "non-empty command string", "operator supplied and executed only through the admitted verification sandbox", "command"), // 14 verify_command

    // B — staged or inactive public families.
    schema!(Duration, "positive integer milliseconds", "bounded by retry cap and remaining request deadline", "milliseconds"), // 15 retry_backoff_base
    schema!(Duration, "positive integer milliseconds", "not lower than the base delay or above remaining wall time", "milliseconds"), // 16 retry_backoff_cap
    schema!(Count, "positive integer", "bounded attempts; terminal and post-stream failures are not blindly retried", "attempts"), // 17 retry_max_attempts
    schema!(List, "normalized admitted egress destinations", "empty means no additional egress authority", "destination entries"), // 18 egress_allow

    // C — internal runtime and harness policy families.
    schema!(Count, "positive integer", "must fit the selected model output capability and run token ceiling", "tokens"), // 19 request_output_cap
    schema!(Map, "effort tier to provider reasoning setting", "every public effort tier resolves to a supported bounded setting", "mapping entries"), // 20 effort_reasoning_map
    schema!(Map, "effort tier to non-negative thinking budget", "budget must fit request output and provider capability ceilings", "mapping entries"), // 21 thinking_map
    schema!(Map, "effort tier to admitted orchestration mode", "may not grant tools, children, or budgets beyond the parent", "mapping entries"), // 22 orchestration_map
    schema!(Policy, "disabled or provider-supported cache policy", "must preserve provider compatibility and request privacy", "policy object"), // 23 prompt_cache
    schema!(Policy, "bounded context-aware compaction policy", "must retain required instructions, evidence, and response reserve", "policy object"), // 24 compaction_adaptive
    schema!(Count, "non-negative integer", "must fit the effective context window after required reserves", "recent messages"), // 25 compaction_keep_recent
    schema!(Policy, "registered tokenizer or conservative estimator policy", "must never exceed the signed model capability when admitting work", "policy object"), // 26 token_estimator
    schema!(Policy, "registered summary shape and budget", "summary plus retained history must fit the context ceiling", "policy object"), // 27 summary_profile
    schema!(Enum, "fail-safe compaction outcome", "must not silently discard mandatory context or widen budgets", "choice"), // 28 compaction_failure
    schema!(Policy, "bounded nearest-instruction traversal and render policy", "must remain within admitted roots, depth, byte, and file ceilings", "policy object"), // 29 instruction_discovery_render
    schema!(Bool, "true or false", "true requires configured tenant and repository memory authority", "boolean"), // 30 memory_enable
    schema!(Map, "positive retrieval, render, and write ceilings", "every component is bounded by the parent context and effect budgets", "budget entries"), // 31 memory_budgets
    schema!(Map, "finite BM25 coefficients and tokenization choices", "coefficients remain within the registered retrieval profile", "parameter entries"), // 32 bm25
    schema!(Bytes, "non-negative integer bytes", "must fit the model-visible context budget", "bytes"), // 33 skill_listing_budget
    schema!(Count, "positive integer", "minimum 1 and bounded by the total tool-call budget", "consecutive errors"), // 34 max_consecutive_tool_errors
    schema!(Bool, "true or false", "overlap is permitted only for effects classified as pure", "boolean"), // 35 pure_overlap
    schema!(Count, "positive integer", "bounded by scheduler and process concurrency ceilings", "concurrent calls"), // 36 pure_concurrency
    schema!(Policy, "bounded failed-action identity and suppression policy", "may suppress only equivalent failed actions within one run", "policy object"), // 37 failed_action_dedup
    schema!(Policy, "bounded memoization policy for deterministic pure tools", "impure or identity-unstable results are never reused", "policy object"), // 38 pure_memo_cache
    schema!(Policy, "positive timeout plus stdout and stderr byte ceilings", "all components fit the remaining tool and run budgets", "policy object"), // 39 shell_timeout_output
    schema!(Policy, "positive byte, line, and range ceilings", "reads remain inside admitted roots and aggregate tool budgets", "policy object"), // 40 read_file_limits
    schema!(Policy, "positive traversal and result ceilings", "listing remains inside admitted roots and aggregate tool budgets", "policy object"), // 41 list_dir_limits
    schema!(Policy, "positive traversal, depth, and result ceilings", "glob expansion remains inside admitted roots", "policy object"), // 42 glob_limits
    schema!(Policy, "positive traversal, match, and output ceilings", "search remains inside admitted roots and aggregate tool budgets", "policy object"), // 43 grep_limits
    schema!(Policy, "positive file, byte, token, and depth ceilings", "repository map must fit the model-visible context budget", "policy object"), // 44 repo_map
    schema!(Policy, "positive Git traversal, diff, and output ceilings", "operations remain observational and inside the admitted repository", "policy object"), // 45 git_limits
    schema!(Policy, "positive byte, redirect, and elapsed-time ceilings", "destinations remain inside the admitted network policy", "policy object"), // 46 web_fetch_limits
    schema!(Count, "non-negative integer", "results must fit the configured search and context ceilings", "results"), // 47 web_search_cap
    schema!(Count, "non-negative integer", "repair attempts remain within turn, token, and wall ceilings", "attempts"), // 48 verifier_attempts
    schema!(Policy, "positive stdout and stderr tail ceilings", "feedback must fit the next-turn context reserve", "policy object"), // 49 verifier_feedback_tails
    schema!(Duration, "positive integer seconds", "must fit the remaining verification and run wall budgets", "seconds"), // 50 verifier_timeout
    schema!(Enum, "direct or admitted orchestrated topology", "orchestration requires eligible effort and parent ceilings", "choice"), // 51 route_topology
    schema!(Policy, "registered bounded decomposition profile", "generated work remains acyclic and inside parent budgets", "policy object"), // 52 decomposition_profile
    schema!(Count, "positive integer", "bounded by child count and concurrency ceilings", "agents"), // 53 fan_breadth
    schema!(Policy, "intersection-only child admission policy", "children may only preserve or reduce parent authority and budgets", "policy object"), // 54 admission
    schema!(Ratio, "finite ratio from 0 through 1", "investigator and writer shares sum within the available turn budget", "ratio"), // 55 writer_fan_turn_split
    schema!(Count, "positive integer", "cannot exceed the child allocation or parent turn ceiling", "turns"), // 56 worker_min_turns
    schema!(Ratio, "finite ratio from 0 through 1", "child allocations sum within remaining parent wall time", "ratio"), // 57 wall_split
    schema!(Ratio, "finite ratio from 0 through 1", "child allocations sum within remaining parent tokens", "ratio"), // 58 token_split
    schema!(Count, "positive integer", "cannot exceed admitted child count or scheduler concurrency", "agents"), // 59 fan_concurrency
    schema!(Policy, "immutable parent capability and budget envelope", "every child value is an intersection with this envelope", "policy object"), // 60 child_ceiling
    schema!(Policy, "bounded direct-child turn, token, wall, and cost allocation", "aggregate allocations remain within the parent envelope", "policy object"), // 61 direct_child_allocation
    schema!(Enum, "registered child effort tier", "must not exceed parent effort or provider capability", "choice"), // 62 subagent_effort_inheritance
    schema!(Bytes, "positive integer bytes", "aggregate child reports must fit writer context capacity", "bytes"), // 63 report_budget
    schema!(Policy, "registered deterministic join and reduction policy", "preserves declaration order and single-writer authority", "policy object"), // 64 join_reduce
    schema!(Policy, "positive aggregate calls, tokens, wall, cost, and concurrency ceilings", "all workflow tasks share one parent-bounded ledger", "policy object"), // 65 workflow_aggregate
    schema!(Policy, "bounded retry count and non-negative jitter window", "must fit remaining request deadline and never duplicate terminal effects", "policy object"), // 66 schema_retry_jitter
    schema!(Duration, "positive integer seconds", "fixed transport default remains bounded by the request and run deadlines", "seconds"), // 67 provider_connect_tls_timeout
    schema!(Policy, "positive image count, byte, dimension, frame, and decode ceilings", "aggregate decode work remains within the fixed admission envelope", "policy object"), // 68 multimodal_input_admission_decode_envelope
    schema!(Policy, "positive submission/event entry and byte capacities", "queues remain bounded with typed overflow behavior", "policy object"), // 69 app_server_sq_eq_backpressure
    schema!(Policy, "positive discovery budget, cache TTL, and failure-backoff values", "account probes remain bounded and never invent provider capability", "policy object"), // 70 provider_discovery_account_probe_cache_policy

    // D — content, catalogs, and environment surfaces.
    schema!(String, "UTF-8 operator-authored text", "bounded by submission, context, and protocol size ceilings", "text bytes"), // 71 operator_prompt_stream
    schema!(Catalog, "source-controlled prompt records", "records are versioned and fit their rendering budgets", "prompt records"), // 72 builtin_prompt_corpus
    schema!(Catalog, "admitted repository and user instruction records", "trust order, roots, depth, count, and bytes remain bounded", "instruction records"), // 73 instruction_bundle
    schema!(Catalog, "tenant- and repository-scoped memory records", "scope, trust, count, and rendered bytes remain bounded", "memory records"), // 74 memory_corpus
    schema!(Catalog, "discovered skill metadata and instruction records", "progressive disclosure and listing budgets remain enforced", "skill records"), // 75 skill_catalog
    schema!(Catalog, "declared agent-definition records", "records grant no runtime role or tool authority until admitted", "agent records"), // 76 agent_catalog
    schema!(Catalog, "signed or operator-declared provider capability records", "route decisions may use only fresh compatible evidence", "capability records"), // 77 provider_model_capability_catalog
    schema!(Catalog, "admitted MCP server and tool-schema records", "server trust and model-visible schema bytes remain bounded", "MCP records"), // 78 mcp_topology_tool_catalog
    schema!(Map, "lifecycle event selectors to bounded hook declarations", "hooks require trusted origin, bounded process execution, and redacted evidence", "hook entries"), // 79 hooks_map
    schema!(Map, "acyclic workflow tasks and dependency edges", "task count, depth, fan-out, and aggregate budgets remain bounded", "graph entries"), // 80 workflow_graph
    schema!(Catalog, "registered tool schemas and capability classes", "every tool retains explicit purity, effect, permission, and output bounds", "tool records"), // 81 tool_action_space
    schema!(Catalog, "signed provider pricing records", "unknown or stale prices are never invented", "rate-card records"), // 82 rate_card_catalog
    schema!(Catalog, "source-controlled routing token and phrase sets", "entries remain versioned, bounded, and evaluation-reviewed", "lexicon records"), // 83 router_lexicons
    schema!(Map, "bounded repository and process environment facts", "capture excludes secrets and preserves tenant and working-directory identity", "fact entries"), // 84 environment_snapshot
    schema!(Catalog, "configured web-search backend definitions", "each backend retains explicit trust, egress, timeout, and result ceilings", "backend records"), // 85 web_search_backend_catalog

    // Appendix F.1 — N-RM01..N-RM10, model routing and transport (10).
    schema!(List, "ordered admitted model route identifiers", "the chain is finite and every route stays inside operator authority and budget ceilings", "route entries"), // 86 model_fallback_chain
    schema!(Catalog, "versioned provider failure classes eligible or ineligible for failover", "unknown, post-dispatch, and terminal failures fail closed", "taxonomy records"), // 87 failover_eligible_error_taxonomy
    schema!(Map, "finite non-negative quality, cost, and latency weights", "weights form one bounded normalized route objective", "weight entries"), // 88 route_quality_cost_latency_objective_weights
    schema!(Policy, "bounded health states, failure thresholds, open intervals, and recovery probes", "state remains scoped to one admitted provider route", "policy object"), // 89 provider_health_circuit_breaker_state_policy
    schema!(Policy, "bounded hedge delay, duplicate count, and eligibility predicates", "spend, concurrency, idempotency, and request deadlines remain enforced", "policy object"), // 90 hedged_request_policy
    schema!(Enum, "service tiers advertised by the selected provider route", "selection remains inside operator cost and priority ceilings", "choice"), // 91 provider_service_tier
    schema!(Enum, "registered model verbosity levels", "verbosity cannot widen output or token ceilings", "choice"), // 92 response_verbosity
    schema!(Map, "agent roles to admitted model route identifiers", "each mapping remains within parent provider, cost, effort, and capability ceilings", "mapping entries"), // 93 role_specific_model_map
    schema!(Duration, "positive integer milliseconds", "must fit the remaining run wall time and provider transport ceiling", "milliseconds"), // 94 provider_request_total_deadline
    schema!(Duration, "positive integer milliseconds", "must not exceed the provider request total deadline", "milliseconds"), // 95 stream_idle_watchdog

    // Appendix F.2 — N-CX01..N-CX12, context, retrieval, and compaction (12).
    schema!(Policy, "signed model window plus non-negative override and reserve fields", "effective input plus every reserve cannot exceed the signed model capability", "policy object"), // 96 context_window_override_reserve
    schema!(Count, "non-negative integer", "system prefix plus all other context partitions fit the effective context window", "tokens"), // 97 system_prefix_budget
    schema!(Count, "non-negative integer", "retained conversation history fits its named context partition", "tokens"), // 98 conversation_history_budget
    schema!(Count, "non-negative integer", "retained tool results fit their named context partition", "tokens"), // 99 tool_result_history_budget
    schema!(Count, "non-negative integer", "multimodal tokens and decode work fit model capability and request ceilings", "tokens"), // 100 multimodal_token_budget
    schema!(Bool, "true or false", "disabling cannot bypass a hard context-window admission failure", "boolean"), // 101 auto_compaction_enable
    schema!(Policy, "non-negative cooldown and bounded enter/exit thresholds", "hysteresis cannot compact mandatory or already-protected context", "policy object"), // 102 compaction_cooldown_hysteresis
    schema!(Enum, "registered bounded summary topologies", "all stages preserve the task anchor and fit the context ceiling", "choice"), // 103 multi_stage_summary_topology
    schema!(Bool, "true or false", "a failed enabled check never licenses silent context loss", "boolean"), // 104 summary_consistency_coverage_check
    schema!(Map, "finite non-negative lexical, vector, structural, and reranker weights", "fusion remains deterministic and bounded to admitted retrieval sources", "weight entries"), // 105 hybrid_retrieval_fusion_weights
    schema!(Ratio, "finite ratio from 0 through 1", "decay is monotone and cannot elevate untrusted or out-of-scope records", "ratio per time bucket"), // 106 retrieval_recency_decay
    schema!(Ratio, "finite ratio from 0 through 1", "dedup never removes mandatory instructions or required evidence", "similarity threshold"), // 107 context_novelty_dedup_threshold

    // Appendix F.3 — N-TP01..N-TP15, tools, processes, and code intelligence (15).
    schema!(Enum, "disabled, one-shot, or registered persistent PTY backend", "backend remains within process, filesystem, network, and wall ceilings", "choice"), // 108 persistent_pty_backend
    schema!(Count, "non-negative integer", "cannot exceed process and effecting-tool concurrency ceilings", "background jobs"), // 109 concurrent_background_job_cap
    schema!(Duration, "positive integer milliseconds", "must remain below the job and run wall deadlines", "milliseconds"), // 110 job_idle_stall_timeout
    schema!(Policy, "bounded wait, poll, prompt, and timeout rules", "interactive input preserves operator ordering and cannot grant authority", "policy object"), // 111 interactive_stdin_wait_policy
    schema!(Enum, "registered TERM, grace, KILL, and reap escalation sequences", "unknown effects are reconciled and all descendants are reaped", "choice"), // 112 process_signal_kill_escalation
    schema!(Policy, "session, job, process, and working-directory continuity rules", "resolved working directories remain inside admitted roots", "policy object"), // 113 process_cwd_continuity
    schema!(Policy, "bounded child-environment snapshot, reuse, and refresh rules", "secrets and blocked variables never enter a reusable snapshot", "policy object"), // 114 child_process_environment_reuse
    schema!(Count, "positive integer", "bounded by scheduler, write-set, permission, process, and effect-ledger ceilings", "concurrent effecting calls"), // 115 effecting_tool_concurrency
    schema!(Policy, "declared write sets and bounded overlap decisions", "ambiguous or overlapping authority never admits unsafe concurrent mutation", "policy object"), // 116 write_set_conflict_admission
    schema!(Policy, "non-negative in-memory threshold plus bounded spill storage and cleanup", "model-visible output remains capped and spill paths stay private", "policy object"), // 117 tool_output_spill_to_disk_policy
    schema!(Policy, "registered binary and media inspectors with capability predicates", "routing never decodes unsupported content or bypasses admission envelopes", "policy object"), // 118 binary_media_inspection_routing
    schema!(Catalog, "language, workspace, and registered LSP server selectors", "only admitted binaries and roots may be discovered or launched", "server records"), // 119 lsp_server_language_selection
    schema!(Policy, "positive request deadline, restart ceiling, and bounded backoff", "restart cannot exceed process, attempt, or wall ceilings", "policy object"), // 120 lsp_timeout_restart_policy
    schema!(Count, "non-negative integer", "LSP evidence fits its context partition and preserves provenance", "tokens"), // 121 lsp_result_context_budget
    schema!(Duration, "non-negative integer seconds", "reuse is restricted to deterministic tools and compatible session identities", "seconds"), // 122 tool_result_cache_ttl

    // Appendix F.4 — N-VR01..N-VR10, verification, recovery, and rewind (10).
    schema!(Policy, "bounded explicit, impacted, lane, or workspace test-selection rules", "repository-required and regression tests cannot be omitted", "policy object"), // 123 test_selection_strategy
    schema!(Enum, "incremental, impacted, or full verification scope", "selected scope may only strengthen the applicable verification floor", "choice"), // 124 incremental_versus_full_verification
    schema!(Policy, "bounded repeat, disagreement, quarantine, and expiry rules", "a flake is reported and never silently converted into acceptance", "policy object"), // 125 flaky_test_detection_quarantine
    schema!(Catalog, "versioned verification failure classes", "unknown and infrastructure failures never count as candidate success", "taxonomy records"), // 126 failure_classification_taxonomy
    schema!(Policy, "failure classes to bounded retry decisions", "terminal, unknown-effect, and exhausted failures are not retried", "policy object"), // 127 retry_eligibility_policy
    schema!(Enum, "off or registered selective rollback mode", "rollback never undoes external effects or unowned paths", "choice"), // 128 rollback_on_verification_failure
    schema!(Policy, "bounded turn, verification, or drain checkpoint triggers", "cadence cannot weaken the durability floor", "policy object"), // 129 workspace_checkpoint_cadence
    schema!(Policy, "explicit user-authorized paths or whole-workspace scope", "restore cannot escape the checkpoint, root, or external-effect boundary", "policy object"), // 130 selective_restore_scope
    schema!(Policy, "positive verifier count, repeat ceiling, and agreement rule", "a weaker oracle cannot override a stronger veto or required scope", "policy object"), // 131 verification_quorum_consensus
    schema!(Enum, "bounded retry, replan, stop, or operator-escalation sequence", "success cannot be reported with unresolved required failures", "choice"), // 132 recovery_escalation_policy

    // Appendix F.5 — N-AG01..N-AG14, agents, tasks, and collaboration (14).
    schema!(Enum, "model route inherited from the parent or explicitly admitted for one agent", "cannot exceed parent provider, cost, and capability ceilings", "model route"), // 133 per_agent_model
    schema!(Enum, "registered effort or thinking tier for one agent", "cannot exceed parent effort, output, or provider capability ceilings", "choice"), // 134 per_agent_effort_thinking
    schema!(Map, "tool and permission profile for one agent", "the effective profile is an intersection with parent authority", "profile entries"), // 135 per_agent_tool_profile
    schema!(Policy, "isolated or explicitly shared scoped memory rules", "records never cross tenant, repository, or session boundaries", "policy object"), // 136 per_agent_memory_scope
    schema!(Count, "non-negative integer", "cannot exceed the parent delegation-depth ceiling", "levels"), // 137 spawn_depth_control
    schema!(Count, "non-negative integer", "all child attempts count against one immutable session ceiling", "agents"), // 138 per_session_spawn_cap
    schema!(Policy, "bounded priority classes, FIFO tie-breaks, and dependency readiness", "scheduling preserves dependency and parent-budget constraints", "policy object"), // 139 task_priority_scheduling
    schema!(Count, "non-negative integer", "speculative siblings fit agent, token, cost, wall, and concurrency ceilings", "agents"), // 140 speculative_sibling_count
    schema!(Policy, "bounded evidence, cancellation, join, and cleanup rules", "cancellation preserves journals and reconciles unknown effects", "policy object"), // 141 speculative_sibling_cancellation
    schema!(Policy, "positive evidence quorum plus bounded early-stop predicates", "required evidence and stronger vetoes cannot be skipped", "policy object"), // 142 early_stop_quorum_policy
    schema!(Bool, "true or false", "concurrent write-capable agents require isolated worktrees and explicit ownership", "boolean"), // 143 writer_worktree_isolation_mode
    schema!(Policy, "verify, merge, serialize, reject, or explicitly arbitrate conflicts", "ambiguous ownership and failed verification stop the merge", "policy object"), // 144 merge_conflict_arbitration
    schema!(Enum, "parent-mediated, peer, broadcast, or registered messaging topology", "message count, bytes, trust, and ordering remain bounded", "choice"), // 145 inter_agent_messaging_topology
    schema!(Policy, "bounded task retry, replacement, and reassignment decisions", "aggregate child and parent budgets remain conserved", "policy object"), // 146 task_retry_reassignment_policy

    // Appendix F.6 — N-MP01..N-MP08, MCP and plugin lifecycle (8).
    schema!(Enum, "stdio or other registered trusted MCP transport", "transport remains inside process, credential, and network authority", "choice"), // 147 mcp_transport_selection
    schema!(Count, "non-negative schema, tool, or server threshold", "deferred discovery remains bounded and required servers are not hidden", "discovery units"), // 148 deferred_discovery_threshold
    schema!(Policy, "bounded reconnect attempts and exponential delay intervals", "terminal authentication and exhausted deadlines are not retried", "policy object"), // 149 mcp_reconnect_backoff
    schema!(Duration, "positive integer milliseconds", "bounded by aggregate MCP startup and run wall ceilings", "milliseconds"), // 150 per_server_startup_deadline
    schema!(Duration, "positive integer milliseconds", "bounded by remaining tool and run wall ceilings", "milliseconds"), // 151 per_tool_mcp_deadline
    schema!(Policy, "non-negative visible-output cap plus bounded spill and cleanup rules", "results fit context, storage, trust, and privacy ceilings", "policy object"), // 152 mcp_result_cap_spill_policy
    schema!(Policy, "protocol-derived credentials, refresh, expiry, and revocation rules", "authentication material remains outside model-visible state", "policy object"), // 153 oauth_auth_lifecycle_policy
    schema!(Policy, "trusted resource, prompt, plugin, and capability exposure rules", "only admitted bounded capabilities become model-visible", "policy object"), // 154 resource_prompt_plugin_capability_exposure

    // Appendix F.7 — N-SR01..N-SR06, session, cache, and reliability (6).
    schema!(Enum, "none or provider-supported request compression", "compression preserves request semantics, privacy, and provider compatibility", "choice"), // 155 request_compression_policy
    schema!(Policy, "positive HTTP pool idle, TCP keepalive, and connection reuse values", "transport values fit provider and run deadlines", "policy object"), // 156 http_pool_keepalive_idle_policy
    schema!(Policy, "observed quota headroom, reset time, and bounded admission decisions", "admission cannot invent quota or exceed run and provider ceilings", "policy object"), // 157 rate_limit_aware_admission
    schema!(Policy, "provider-supported cache TTL, breakpoint, and invalidation rules", "cache identity preserves privacy, scope, and request compatibility", "policy object"), // 158 prompt_cache_ttl_breakpoint_strategy
    schema!(Enum, "registered hermetic, durable, or interactive session-isolation profile", "profiles cannot weaken tenant, repository, credential, or replay boundaries", "choice"), // 159 session_isolation_profile
    schema!(Policy, "fail-closed replay divergence predicates and evidence", "hash, identity, scope, and effect divergence never continue silently", "policy object"), // 160 replay_divergence_detection_policy
];

pub(crate) const fn value_schema(ordinal: u16) -> ValueSchema {
    VALUE_SCHEMAS[ordinal as usize - 1]
}
