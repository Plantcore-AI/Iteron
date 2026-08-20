use super::fixed::{
    auto_compaction_owner_value, effecting_tool_concurrency_owner_value,
    process_signal_kill_escalation_owner_value, recovery_escalation_owner_value,
    retry_eligibility_owner_value, write_set_conflict_admission_owner_value,
};
use super::value::{boolv, dec, en, int, list, map, object, text};
use super::{
    FactGapReason, FactLayer, ProviderProcessFactError, ProviderProcessFactGap,
    ProviderProcessFactsInput, ProviderProcessFactsReport, VerificationOwnerFacts,
    owner::OwnerSnapshot,
};
use iteron_tunables::{FixedAuthorityId, ResolutionValue, RuntimeResolutionBuilder, SourceKind};
use iteron_verify::{
    VERIFIER_SLOT_VERSION, VerificationRollbackMode, VerificationSelectionMode, VerifierScope,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

pub(super) fn apply(
    builder: &mut RuntimeResolutionBuilder,
    input: &ProviderProcessFactsInput<'_>,
    owner: &OwnerSnapshot,
    report: &mut ProviderProcessFactsReport,
) -> Result<(), ProviderProcessFactError> {
    add_governor_defaults(builder, input, report)?;
    let role_routes = super::super::execution_policy::admitted_role_model_routes(
        input.agent_catalog,
        &input.selection.provider_id,
        &input.selection.model_id,
    )
    .map_err(|_| ProviderProcessFactError::EvidenceEncoding)?;
    builder.observe_default(
        "role_specific_model_map",
        map(role_routes
            .into_iter()
            .map(|(role, route)| (role, en(&route)))),
    )?;
    report.observed_defaults.push("role_specific_model_map");
    let transport_timeouts = iteron_provider::provider_transport_timeout_policy();
    let request_total_ms = duration_milliseconds(
        transport_timeouts.request_total,
        "provider_request_total_deadline",
    )?;
    let stream_idle_ms =
        duration_milliseconds(transport_timeouts.stream_idle, "stream_idle_watchdog")?;
    builder.observe_default("provider_request_total_deadline", int(request_total_ms))?;
    report
        .observed_defaults
        .push("provider_request_total_deadline");
    builder.attest_literal_owner("stream_idle_watchdog", int(stream_idle_ms))?;
    report.observed_defaults.push("stream_idle_watchdog");
    builder.attest_fixed_authority(
        "provider_request_total_deadline",
        FixedAuthorityId::StrategyInvariant,
        int(effective_wall_timeout(
            request_total_ms,
            input.budget.max_wall_secs,
        )?),
    )?;
    builder.attest_fixed_authority(
        "stream_idle_watchdog",
        FixedAuthorityId::StrategyInvariant,
        int(effective_wall_timeout(
            stream_idle_ms,
            input.budget.max_wall_secs,
        )?),
    )?;

    add_context_defaults(builder, input, owner, report)?;
    add_tooling_defaults(builder, input, report)?;
    builder.observe_default(
        "compaction_cooldown_hysteresis",
        object([
            ("cooldown_turns", int(1)),
            ("enter_ratio", dec(75, 2)),
            ("exit_ratio", dec(5, 1)),
        ]),
    )?;
    report
        .observed_defaults
        .push("compaction_cooldown_hysteresis");
    let binary = input.binary_media_policy;
    builder.observe_default(
        "binary_media_inspection_routing",
        object([
            (
                "mime_routes",
                map(binary
                    .mime_routes()
                    .into_iter()
                    .map(|(mime, inspector)| (mime, en(&inspector)))),
            ),
            (
                "unknown_mime",
                en(match binary.unknown_mime() {
                    crate::image_input::UnknownMimePolicy::Reject => "reject",
                    crate::image_input::UnknownMimePolicy::MetadataOnly => "metadata_only",
                }),
            ),
            (
                "max_input_bytes",
                int(super::value::i64u(
                    binary.max_input_bytes() as u64,
                    "binary_media_inspection_routing",
                )?),
            ),
        ]),
    )?;
    report
        .observed_defaults
        .push("binary_media_inspection_routing");
    builder.observe_default(
        "tool_result_cache_ttl",
        int(super::value::i64u(
            input.registry.tool_result_cache_ttl_seconds(),
            "tool_result_cache_ttl",
        )?),
    )?;
    report.observed_defaults.push("tool_result_cache_ttl");

    let signal_value = process_signal_kill_escalation_owner_value();
    builder.attest_literal_owner("process_signal_kill_escalation", signal_value.clone())?;
    builder.attest_fixed_authority(
        "process_signal_kill_escalation",
        FixedAuthorityId::RuntimeInvariant,
        signal_value,
    )?;
    report
        .observed_defaults
        .push("process_signal_kill_escalation");
    let effecting_concurrency = effecting_tool_concurrency_owner_value()?;
    builder.attest_literal_owner("effecting_tool_concurrency", effecting_concurrency.clone())?;
    builder.attest_fixed_authority(
        "effecting_tool_concurrency",
        FixedAuthorityId::StrategyInvariant,
        effecting_concurrency,
    )?;
    report.observed_defaults.push("effecting_tool_concurrency");
    let write_set_admission = write_set_conflict_admission_owner_value();
    builder.attest_literal_owner("write_set_conflict_admission", write_set_admission.clone())?;
    builder.attest_fixed_authority(
        "write_set_conflict_admission",
        FixedAuthorityId::StrategyInvariant,
        write_set_admission,
    )?;
    report
        .observed_defaults
        .push("write_set_conflict_admission");

    add_verification_defaults(builder, input, report)?;
    let failure_taxonomy = failure_classification_catalog_value()?;
    builder.observe_default("failure_classification_taxonomy", failure_taxonomy.clone())?;
    builder.attest_fixed_authority(
        "failure_classification_taxonomy",
        FixedAuthorityId::RuntimeInvariant,
        failure_taxonomy,
    )?;
    report
        .observed_defaults
        .push("failure_classification_taxonomy");
    Ok(())
}

fn duration_milliseconds(
    duration: std::time::Duration,
    family: &'static str,
) -> Result<i64, ProviderProcessFactError> {
    let milliseconds = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
    super::value::i64u(milliseconds, family)
}

fn effective_wall_timeout(
    owner_milliseconds: i64,
    max_wall_secs: u64,
) -> Result<i64, ProviderProcessFactError> {
    if max_wall_secs == 0 {
        return Ok(owner_milliseconds);
    }
    let wall_milliseconds = max_wall_secs.saturating_mul(1_000).min(86_400_000);
    Ok(owner_milliseconds.min(super::value::i64u(wall_milliseconds, "parent_wall")?))
}

pub(crate) fn failure_classification_catalog_value()
-> Result<iteron_tunables::ResolutionValue, ProviderProcessFactError> {
    const CATALOG_ID: &str = "iteron://tunables/catalogs/failure_classification_taxonomy-v1";
    #[derive(Serialize)]
    struct CanonicalCatalog<'a> {
        canonicalization: &'static str,
        catalog_id: &'static str,
        entries: &'a [iteron_verify::VerificationFailureTaxonomyEntry],
    }
    let entries = iteron_verify::verification_failure_taxonomy();
    let bytes = serde_json::to_vec(&CanonicalCatalog {
        canonicalization: "iteron-verification-failure-taxonomy-json-v1",
        catalog_id: CATALOG_ID,
        entries,
    })
    .map_err(|_| ProviderProcessFactError::EvidenceEncoding)?;
    Ok(iteron_tunables::ResolutionValue::CatalogRef {
        catalog_id: CATALOG_ID.to_owned(),
        digest_sha256: hex::encode(Sha256::digest(&bytes)),
        entry_count: u64::try_from(entries.len()).map_err(|_| {
            ProviderProcessFactError::IntegerOverflow("failure_classification_taxonomy")
        })?,
        canonical_bytes: u64::try_from(bytes.len()).map_err(|_| {
            ProviderProcessFactError::IntegerOverflow("failure_classification_taxonomy")
        })?,
    })
}

fn add_tooling_defaults(
    builder: &mut RuntimeResolutionBuilder,
    input: &ProviderProcessFactsInput<'_>,
    report: &mut ProviderProcessFactsReport,
) -> Result<(), ProviderProcessFactError> {
    let spill = crate::runtime::tool_output_spill::ToolOutputSpillPolicy::default();
    builder.observe_default(
        "tool_output_spill_to_disk_policy",
        object([
            (
                "memory_threshold_bytes",
                int(super::value::i64u(
                    spill.memory_threshold_bytes() as u64,
                    "tool_output_spill_to_disk_policy",
                )?),
            ),
            (
                "spill_max_bytes",
                int(super::value::i64u(
                    spill.spill_max_bytes() as u64,
                    "tool_output_spill_to_disk_policy",
                )?),
            ),
            ("cleanup", en(spill.cleanup().label())),
            ("private_storage", boolv(true)),
        ]),
    )?;
    report
        .observed_defaults
        .push("tool_output_spill_to_disk_policy");

    {
        // The immutable owner exists even when this registry intentionally exposes no process
        // tools (for example a read-only standalone workflow). Keeping the policy resolvable lets
        // the same 160-family checkpoint flow into children; activation separately records that
        // no process effect can consume it in this runtime.
        let policy = input
            .registry
            .process_control()
            .map_or_else(iteron_tools::ProcessRuntimePolicy::default, |control| {
                control.policy()
            });
        for (family, value) in [
            ("persistent_pty_backend", en(policy.backend.as_str())),
            (
                "concurrent_background_job_cap",
                int(i64::try_from(policy.max_background_jobs).map_err(|_| {
                    ProviderProcessFactError::IntegerOverflow("concurrent_background_job_cap")
                })?),
            ),
            (
                "job_idle_stall_timeout",
                int(super::value::i64u(
                    policy.idle_stall_milliseconds,
                    "job_idle_stall_timeout",
                )?),
            ),
            (
                "interactive_stdin_wait_policy",
                object([
                    (
                        "poll_milliseconds",
                        int(super::value::i64u(
                            policy.stdin_wait.poll_milliseconds,
                            "interactive_stdin_wait_policy",
                        )?),
                    ),
                    (
                        "idle_timeout_milliseconds",
                        int(super::value::i64u(
                            policy.stdin_wait.idle_timeout_milliseconds,
                            "interactive_stdin_wait_policy",
                        )?),
                    ),
                    ("operator_prompt", boolv(policy.stdin_wait.operator_prompt)),
                ]),
            ),
        ] {
            builder.observe_default(family, value)?;
            report.observed_defaults.push(family);
        }
        let launch = iteron_tools::ProcessLaunchPolicy::owner(input.workspace)
            .map_err(|_| ProviderProcessFactError::EvidenceEncoding)?;
        builder.observe_default(
            "process_cwd_continuity",
            object([
                ("scope", en(launch.cwd.scope.as_str())),
                (
                    "initial_cwd",
                    text(&launch.cwd.initial_cwd.to_string_lossy()),
                ),
                ("preserve_changes", boolv(launch.cwd.preserve_changes)),
            ]),
        )?;
        report.observed_defaults.push("process_cwd_continuity");
        builder.observe_default(
            "child_process_environment_reuse",
            object([
                ("reuse", boolv(launch.environment.reuse)),
                (
                    "max_entries",
                    int(i64::try_from(launch.environment.max_entries).map_err(|_| {
                        ProviderProcessFactError::IntegerOverflow("child_process_environment_reuse")
                    })?),
                ),
                (
                    "max_bytes",
                    int(i64::try_from(launch.environment.max_bytes).map_err(|_| {
                        ProviderProcessFactError::IntegerOverflow("child_process_environment_reuse")
                    })?),
                ),
                (
                    "blocked_names",
                    list(
                        launch
                            .environment
                            .blocked_names
                            .iter()
                            .map(|name| text(name)),
                    ),
                ),
            ]),
        )?;
        report
            .observed_defaults
            .push("child_process_environment_reuse");
    }

    if let Some(control) = input.registry.lsp_control() {
        let policy = control.policy();
        builder.observe_default(
            "lsp_server_language_selection",
            list(policy.routes.iter().map(|route| {
                object([
                    ("language_id", text(&route.language_id)),
                    ("server_id", text(&route.server_id)),
                    ("executable", text(&route.executable)),
                    (
                        "arguments",
                        list(route.arguments.iter().map(|argument| text(argument))),
                    ),
                    (
                        "workspace_markers",
                        list(route.workspace_markers.iter().map(|marker| text(marker))),
                    ),
                ])
            })),
        )?;
        report
            .observed_defaults
            .push("lsp_server_language_selection");
        builder.observe_default(
            "lsp_timeout_restart_policy",
            object([
                (
                    "request_timeout_milliseconds",
                    int(super::value::i64u(
                        policy.recovery.request_timeout_milliseconds,
                        "lsp_timeout_restart_policy",
                    )?),
                ),
                ("max_restarts", int(i64::from(policy.recovery.max_restarts))),
                (
                    "backoff_base_milliseconds",
                    int(super::value::i64u(
                        policy.recovery.backoff_base_milliseconds,
                        "lsp_timeout_restart_policy",
                    )?),
                ),
                (
                    "backoff_cap_milliseconds",
                    int(super::value::i64u(
                        policy.recovery.backoff_cap_milliseconds,
                        "lsp_timeout_restart_policy",
                    )?),
                ),
            ]),
        )?;
        report.observed_defaults.push("lsp_timeout_restart_policy");
    } else {
        // The policy families remain effective even when this registry intentionally exposes no
        // LSP surface. An empty route catalog is the exact disabled selection; the recovery value
        // is still decoded and sealed so a later process cannot invent different bounds.
        builder.observe_default(
            "lsp_server_language_selection",
            list(std::iter::empty::<iteron_tunables::ResolutionValue>()),
        )?;
        report
            .observed_defaults
            .push("lsp_server_language_selection");
        let recovery = iteron_tools::LspRecoveryPolicy::default();
        builder.observe_default(
            "lsp_timeout_restart_policy",
            object([
                (
                    "request_timeout_milliseconds",
                    int(super::value::i64u(
                        recovery.request_timeout_milliseconds,
                        "lsp_timeout_restart_policy",
                    )?),
                ),
                ("max_restarts", int(i64::from(recovery.max_restarts))),
                (
                    "backoff_base_milliseconds",
                    int(super::value::i64u(
                        recovery.backoff_base_milliseconds,
                        "lsp_timeout_restart_policy",
                    )?),
                ),
                (
                    "backoff_cap_milliseconds",
                    int(super::value::i64u(
                        recovery.backoff_cap_milliseconds,
                        "lsp_timeout_restart_policy",
                    )?),
                ),
            ]),
        )?;
        report.observed_defaults.push("lsp_timeout_restart_policy");
    }
    Ok(())
}

fn add_governor_defaults(
    builder: &mut RuntimeResolutionBuilder,
    input: &ProviderProcessFactsInput<'_>,
    report: &mut ProviderProcessFactsReport,
) -> Result<(), ProviderProcessFactError> {
    let source = if input.provider_governor_configured {
        SourceKind::UserConfig
    } else {
        SourceKind::Builtin
    };
    literal_with_override(
        builder,
        report,
        "model_fallback_chain",
        list(std::iter::empty()),
        if input.provider_governor.fallback_routes.is_empty() {
            SourceKind::Builtin
        } else {
            SourceKind::UserConfig
        },
        list(
            input
                .provider_governor
                .fallback_routes
                .iter()
                .map(|route| en(route)),
        ),
    )?;

    let builtin_failover = failover_taxonomy_value(&crate::config::builtin_failover_rules());
    let resolved_failover = failover_taxonomy_value(&input.provider_governor.policy.failover);
    literal_with_override(
        builder,
        report,
        "failover_eligible_error_taxonomy",
        builtin_failover,
        source,
        resolved_failover,
    )?;

    let weights = input.provider_governor.policy.objectives;
    let weight = |millionths: u32| dec(i64::from(millionths), 6);
    let objectives = map([
        ("quality".to_owned(), weight(weights.quality_millionths)),
        ("cost".to_owned(), weight(weights.cost_millionths)),
        ("latency".to_owned(), weight(weights.latency_millionths)),
    ]);
    if input.provider_governor_configured {
        builder.declare(
            "route_quality_cost_latency_objective_weights",
            SourceKind::UserConfig,
            objectives,
        )?;
        report
            .declared_owner_values
            .push("route_quality_cost_latency_objective_weights");
    } else {
        builder.observe_default("route_quality_cost_latency_objective_weights", objectives)?;
        report
            .observed_defaults
            .push("route_quality_cost_latency_objective_weights");
    }

    let circuit = input.provider_governor.policy.circuit;
    let circuit_value = object([
        (
            "failure_threshold",
            int(i64::from(circuit.failure_threshold)),
        ),
        (
            "open_seconds",
            int(super::value::i64u(
                circuit.open_for.as_secs(),
                "provider_health",
            )?),
        ),
        ("half_open_probes", int(i64::from(circuit.half_open_probes))),
        (
            "success_threshold",
            int(i64::from(circuit.success_threshold)),
        ),
    ]);
    if input.provider_governor_configured {
        builder.declare(
            "provider_health_circuit_breaker_state_policy",
            SourceKind::UserConfig,
            circuit_value,
        )?;
        report
            .declared_owner_values
            .push("provider_health_circuit_breaker_state_policy");
    } else {
        builder.observe_default(
            "provider_health_circuit_breaker_state_policy",
            circuit_value,
        )?;
        report
            .observed_defaults
            .push("provider_health_circuit_breaker_state_policy");
    }

    let hedge = input.provider_governor.policy.hedge;
    literal_with_override(
        builder,
        report,
        "hedged_request_policy",
        hedge_policy_value(iteron_provider::HedgePolicy::default())?,
        source,
        hedge_policy_value(hedge)?,
    )?;

    let controls = input.provider_governor.controls;
    let service_tier = en(controls.service_tier.label());
    let verbosity = en(controls.verbosity.label());
    if input.provider_governor_configured {
        builder.declare(
            "provider_service_tier",
            SourceKind::UserConfig,
            service_tier,
        )?;
        builder.declare("response_verbosity", SourceKind::UserConfig, verbosity)?;
        report.declared_owner_values.push("provider_service_tier");
        report.declared_owner_values.push("response_verbosity");
    } else {
        builder.observe_default("provider_service_tier", service_tier)?;
        builder.observe_default("response_verbosity", verbosity)?;
        report.observed_defaults.push("provider_service_tier");
        report.observed_defaults.push("response_verbosity");
    }
    Ok(())
}

fn failover_taxonomy_value(
    rules: &std::collections::BTreeSet<iteron_provider::FailoverRule>,
) -> ResolutionValue {
    use iteron_provider::FailurePoint;

    list(rules.iter().map(|rule| {
        object([
            ("error_class", text(rule.class.label())),
            ("eligible", boolv(true)),
            (
                "dispatch_state",
                en(match rule.point {
                    FailurePoint::PreDispatch => "pre_dispatch",
                    FailurePoint::ProvenTerminal => "post_dispatch",
                }),
            ),
            ("version", text("1.0.0")),
        ])
    }))
}

fn hedge_policy_value(
    hedge: iteron_provider::HedgePolicy,
) -> Result<ResolutionValue, ProviderProcessFactError> {
    Ok(object([
        ("enabled", boolv(hedge.enabled)),
        (
            "delay_milliseconds",
            int(super::value::i64u(
                u64::try_from(hedge.delay.as_millis()).unwrap_or(u64::MAX),
                "hedged_request_policy",
            )?),
        ),
        ("max_duplicates", int(i64::from(hedge.max_duplicates))),
        ("idempotent_only", boolv(hedge.idempotent_only)),
    ]))
}

/// Sample the immutable physical baseline first, then publish only a real non-baseline override.
/// If an unconfigured Builtin owner drifts, the deliberate Builtin declaration reaches the
/// canonical builder invariant and fails fresh composition instead of silently changing policy.
fn literal_with_override(
    builder: &mut RuntimeResolutionBuilder,
    report: &mut ProviderProcessFactsReport,
    family: &'static str,
    literal: ResolutionValue,
    source: SourceKind,
    value: ResolutionValue,
) -> Result<(), ProviderProcessFactError> {
    builder.attest_literal_owner(family, literal.clone())?;
    report.observed_defaults.push(family);
    if value != literal {
        builder.declare(family, source, value)?;
        report.declared_owner_values.push(family);
    }
    Ok(())
}

fn add_context_defaults(
    builder: &mut RuntimeResolutionBuilder,
    input: &ProviderProcessFactsInput<'_>,
    _owner: &OwnerSnapshot,
    report: &mut ProviderProcessFactsReport,
) -> Result<(), ProviderProcessFactError> {
    let (actual_window, execution_window, output_reserve) = super::context_owner_window(input)?;
    let policy =
        iteron_ctx::ContextBudgetPolicy::for_usable_window(execution_window, output_reserve, 0);

    // Family 96 preserves the provider-attested physical window for durable route identity and
    // truthful telemetry. The component budgets below are still sized from `execution_window`;
    // EffectiveCore re-derives that same local cap before validating or materializing a prompt.
    // Unknown metadata keeps the already-bounded fallback rather than inventing a capability.
    let effective_window = actual_window.unwrap_or(execution_window);
    builder.observe_default(
        "context_window_override_reserve",
        object([
            (
                "model_window_tokens",
                int(super::value::i64u(
                    effective_window as u64,
                    "context_window",
                )?),
            ),
            ("output_reserve_tokens", int(i64::from(output_reserve))),
            ("verification_reserve_tokens", int(0)),
            (
                "instruction_budget_tokens",
                int(super::value::i64u(
                    policy.instruction_tokens as u64,
                    "instruction_budget_tokens",
                )?),
            ),
            (
                "task_context_budget_tokens",
                int(super::value::i64u(
                    policy.task_context_tokens as u64,
                    "task_context_budget_tokens",
                )?),
            ),
            (
                "memory_budget_tokens",
                int(super::value::i64u(
                    policy.memory_tokens as u64,
                    "memory_budget_tokens",
                )?),
            ),
            (
                "attachment_budget_tokens",
                int(super::value::i64u(
                    policy.attachment_tokens as u64,
                    "attachment_budget_tokens",
                )?),
            ),
            (
                "tool_schema_budget_tokens",
                int(super::value::i64u(
                    policy.tool_schema_tokens as u64,
                    "tool_schema_budget_tokens",
                )?),
            ),
        ]),
    )?;
    report
        .observed_defaults
        .push("context_window_override_reserve");
    for (family, value) in [
        ("system_prefix_budget", policy.stable_prefix_tokens),
        ("conversation_history_budget", policy.transcript_tokens),
        ("tool_result_history_budget", policy.tool_result_tokens),
    ] {
        builder.observe_default(family, int(super::value::i64u(value as u64, family)?))?;
        report.observed_defaults.push(family);
    }
    // Family 100 follows the selected execution window. A larger provider-attested physical
    // window must not re-widen this default after the composition root chooses a narrower local
    // execution ceiling. Unsupported and unverified routes continue to own an exact zero.
    let multimodal_tokens = default_multimodal_tokens(
        input.model_capabilities.image_input,
        execution_window,
        output_reserve,
    );
    builder.observe_default(
        "multimodal_token_budget",
        int(super::value::i64u(
            multimodal_tokens as u64,
            "multimodal_token_budget",
        )?),
    )?;
    report.observed_defaults.push("multimodal_token_budget");
    // Zero is an exact disabled-surface budget, not missing evidence. If LSP is installed the same
    // pinned field becomes its physical admission ceiling.
    builder.observe_default(
        "lsp_result_context_budget",
        int(super::value::i64u(
            policy.lsp_result_tokens as u64,
            "lsp_result_context_budget",
        )?),
    )?;
    report.observed_defaults.push("lsp_result_context_budget");

    // Families 105/106 are literal defaults, but the receipt must come from the same typed policy
    // the context materializer consumes. Reading the owner first prevents a registry literal from
    // minting a production-owner receipt if the physical defaults ever drift.
    let retrieval = iteron_ctx::MemoryRetrievalPolicy::default()
        .validate()
        .map_err(|_| ProviderProcessFactError::EvidenceEncoding)?;
    let mut weights = Vec::new();
    for (signal, weight_ppm) in [
        ("lexical", retrieval.lexical_weight_ppm),
        ("structural", retrieval.structural_weight_ppm),
        ("vector", retrieval.vector_weight_ppm),
        ("reranker", retrieval.reranker_weight_ppm),
    ] {
        if weight_ppm != 0 {
            weights.push((signal.to_owned(), ppm_decimal(weight_ppm)));
        }
    }
    builder.attest_literal_owner("hybrid_retrieval_fusion_weights", map(weights))?;
    report
        .observed_defaults
        .push("hybrid_retrieval_fusion_weights");
    builder.attest_literal_owner(
        "retrieval_recency_decay",
        ppm_decimal(retrieval.recency_decay_ppm),
    )?;
    report.observed_defaults.push("retrieval_recency_decay");
    builder.attest_literal_owner(
        "context_novelty_dedup_threshold",
        ppm_decimal(retrieval.novelty_dedup_threshold_ppm),
    )?;
    report
        .observed_defaults
        .push("context_novelty_dedup_threshold");

    builder.attest_literal_owner("auto_compaction_enable", boolv(input.compaction.enabled))?;
    builder.attest_fixed_authority(
        "auto_compaction_enable",
        FixedAuthorityId::StrategyInvariant,
        auto_compaction_owner_value(),
    )?;
    report.declared_owner_values.push("auto_compaction_enable");
    builder.attest_literal_owner(
        "multi_stage_summary_topology",
        en(match input.compaction.summary_topology {
            iteron_ctx::SummaryTopology::SingleStage => "single_stage",
            iteron_ctx::SummaryTopology::Hierarchical => "hierarchical",
            iteron_ctx::SummaryTopology::MapReduce => "map_reduce",
        }),
    )?;
    report
        .observed_defaults
        .push("multi_stage_summary_topology");
    builder.attest_literal_owner(
        "summary_consistency_coverage_check",
        boolv(input.compaction.coverage_check),
    )?;
    report
        .declared_owner_values
        .push("summary_consistency_coverage_check");
    Ok(())
}

fn default_multimodal_tokens(
    image_input: Option<bool>,
    execution_window: usize,
    output_reserve: u32,
) -> usize {
    if image_input != Some(true) {
        return 0;
    }
    let usable =
        execution_window.saturating_sub(usize::try_from(output_reserve).unwrap_or(usize::MAX));
    if usable == 0 {
        return 0;
    }
    // Preserve the context owner's normal ten-percent split while ensuring that every capable
    // route with usable context can admit at least one estimated multimodal token.
    iteron_ctx::ContextBudgetPolicy::for_usable_window(execution_window, output_reserve, 0)
        .multimodal_tokens
        .max(1)
}

fn ppm_decimal(value: u32) -> iteron_tunables::ResolutionValue {
    let mut coefficient = i64::from(value);
    let mut scale = 6;
    while scale > 0 && coefficient % 10 == 0 {
        coefficient /= 10;
        scale -= 1;
    }
    dec(coefficient, scale)
}

fn add_verification_defaults(
    builder: &mut RuntimeResolutionBuilder,
    input: &ProviderProcessFactsInput<'_>,
    report: &mut ProviderProcessFactsReport,
) -> Result<(), ProviderProcessFactError> {
    match input.verification {
        VerificationOwnerFacts::Configured {
            command,
            floor,
            plan,
        } => {
            if command.is_empty()
                || command.len() > 4_096
                || floor.version != VERIFIER_SLOT_VERSION
                || plan.validate_against(floor).is_err()
            {
                return Err(ProviderProcessFactError::InvalidVerificationCommand);
            }
            builder.observe_default(
                "test_selection_strategy",
                object([
                    ("scope", en(scope(plan.scope))),
                    (
                        "required_commands",
                        list(
                            input
                                .verification_policy
                                .required_commands
                                .iter()
                                .map(|command| text(command)),
                        ),
                    ),
                    (
                        "max_commands",
                        int(i64::from(input.verification_policy.max_commands)),
                    ),
                ]),
            )?;
            report.observed_defaults.push("test_selection_strategy");
        }
        VerificationOwnerFacts::Disabled => {
            builder.observe_default(
                "test_selection_strategy",
                object([
                    ("scope", en("workspace")),
                    (
                        "required_commands",
                        list(std::iter::empty::<iteron_tunables::ResolutionValue>()),
                    ),
                    (
                        "max_commands",
                        int(i64::from(input.verification_policy.max_commands)),
                    ),
                ]),
            )?;
            report.observed_defaults.push("test_selection_strategy");
        }
        VerificationOwnerFacts::GetterUnavailable => unsupported(
            builder,
            report,
            123,
            "test_selection_strategy",
            FactGapReason::OwnerGetterMissing,
        )?,
    }

    let policy = input.verification_policy;
    declare_verification_owner(
        builder,
        report,
        "incremental_versus_full_verification",
        if input
            .verification_config
            .and_then(|config| config.selection)
            .is_some()
        {
            SourceKind::UserConfig
        } else {
            SourceKind::DerivedPolicy
        },
        en(match policy.selection {
            VerificationSelectionMode::Incremental => "incremental",
            VerificationSelectionMode::Impacted => "impacted",
            VerificationSelectionMode::Full => "full",
        }),
    )?;
    let flaky_value = object([
        ("repeat_count", int(i64::from(policy.flaky.repeat_count))),
        (
            "minimum_disagreements",
            int(i64::from(policy.flaky.minimum_disagreements)),
        ),
        (
            "quarantine_seconds",
            int(i64::from(policy.flaky.quarantine_seconds)),
        ),
        (
            "report_disagreement",
            boolv(policy.flaky.report_disagreement),
        ),
    ]);
    let default_flaky = iteron_verify::FlakyQuarantinePolicy::default();
    literal_with_override(
        builder,
        report,
        "flaky_test_detection_quarantine",
        object([
            ("repeat_count", int(i64::from(default_flaky.repeat_count))),
            (
                "minimum_disagreements",
                int(i64::from(default_flaky.minimum_disagreements)),
            ),
            (
                "quarantine_seconds",
                int(i64::from(default_flaky.quarantine_seconds)),
            ),
            (
                "report_disagreement",
                boolv(default_flaky.report_disagreement),
            ),
        ]),
        SourceKind::DerivedPolicy,
        flaky_value,
    )?;
    let retry_eligibility = retry_eligibility_owner_value(&policy.retry);
    declare_verification_owner(
        builder,
        report,
        "retry_eligibility_policy",
        SourceKind::DerivedPolicy,
        retry_eligibility.clone(),
    )?;
    builder.attest_fixed_authority(
        "retry_eligibility_policy",
        FixedAuthorityId::StrategyInvariant,
        retry_eligibility_owner_value(&iteron_verify::VerificationRuntimePolicy::default().retry),
    )?;

    let rollback_configured = input
        .verification_config
        .and_then(|config| config.rollback.as_ref())
        .is_some();
    let rollback_mode = match policy.restore.mode {
        VerificationRollbackMode::Off => "off",
        VerificationRollbackMode::SelectedPaths => "selected_paths",
        VerificationRollbackMode::Workspace => "workspace",
    };
    literal_with_override(
        builder,
        report,
        "rollback_on_verification_failure",
        en("off"),
        if rollback_configured {
            SourceKind::UserConfig
        } else {
            SourceKind::DerivedPolicy
        },
        en(rollback_mode),
    )?;
    literal_with_override(
        builder,
        report,
        "workspace_checkpoint_cadence",
        object([
            ("turn_boundary", boolv(true)),
            ("before_verification", boolv(true)),
            ("before_drain", boolv(true)),
            ("minimum_turn_interval", int(1)),
        ]),
        if input
            .verification_config
            .and_then(|config| config.checkpoint.as_ref())
            .is_some()
        {
            SourceKind::UserConfig
        } else {
            SourceKind::DerivedPolicy
        },
        object([
            ("turn_boundary", boolv(policy.checkpoint.turn_boundary)),
            (
                "before_verification",
                boolv(policy.checkpoint.before_verification),
            ),
            ("before_drain", boolv(policy.checkpoint.before_drain)),
            (
                "minimum_turn_interval",
                int(i64::from(policy.checkpoint.minimum_turn_interval)),
            ),
        ]),
    )?;

    let restore_scope_mode = match policy.restore.mode {
        VerificationRollbackMode::SelectedPaths => "selected_paths",
        VerificationRollbackMode::Off | VerificationRollbackMode::Workspace => "workspace",
    };
    let mut restore_fields =
        std::collections::BTreeMap::from([("mode".to_owned(), en(restore_scope_mode))]);
    if policy.restore.mode == VerificationRollbackMode::SelectedPaths {
        restore_fields.insert(
            "paths".to_owned(),
            list(policy.restore.paths.iter().map(|path| text(path))),
        );
    }
    literal_with_override(
        builder,
        report,
        "selective_restore_scope",
        object([("mode", en("workspace"))]),
        if rollback_configured {
            SourceKind::UserConfig
        } else {
            SourceKind::Builtin
        },
        iteron_tunables::ResolutionValue::Object {
            fields: restore_fields,
        },
    )?;
    literal_with_override(
        builder,
        report,
        "verification_quorum_consensus",
        object([
            ("verifiers", int(1)),
            ("required_agreement", int(1)),
            ("strong_veto", boolv(true)),
        ]),
        if input
            .verification_config
            .and_then(|config| config.quorum.as_ref())
            .is_some()
        {
            SourceKind::UserConfig
        } else {
            SourceKind::Builtin
        },
        object([
            ("verifiers", int(i64::from(policy.quorum.verifiers))),
            (
                "required_agreement",
                int(i64::from(policy.quorum.required_agreement)),
            ),
            ("strong_veto", boolv(policy.quorum.strong_veto)),
        ]),
    )?;

    builder.attest_literal_owner(
        "recovery_escalation_policy",
        recovery_escalation_owner_value(),
    )?;
    report.observed_defaults.push("recovery_escalation_policy");

    Ok(())
}

fn declare_verification_owner(
    builder: &mut RuntimeResolutionBuilder,
    report: &mut ProviderProcessFactsReport,
    family: &'static str,
    source: SourceKind,
    value: iteron_tunables::ResolutionValue,
) -> Result<(), ProviderProcessFactError> {
    builder.declare(family, source, value)?;
    report.declared_owner_values.push(family);
    Ok(())
}

fn unsupported(
    builder: &mut RuntimeResolutionBuilder,
    report: &mut ProviderProcessFactsReport,
    ordinal: u16,
    family: &'static str,
    reason: FactGapReason,
) -> Result<(), ProviderProcessFactError> {
    builder.observe_default_unsupported(family, reason.code())?;
    report.push_gap(ProviderProcessFactGap::new(
        ordinal,
        family,
        FactLayer::Default,
        reason,
    ));
    Ok(())
}

const fn scope(scope: VerifierScope) -> &'static str {
    match scope {
        VerifierScope::Lane => "lane",
        VerifierScope::Workspace => "workspace",
    }
}

#[cfg(test)]
mod tests {
    use super::default_multimodal_tokens;

    #[test]
    fn multimodal_default_uses_the_selected_execution_window() {
        let execution_window = 280_192;
        let output_reserve = 8_192;
        let expected =
            iteron_ctx::ContextBudgetPolicy::for_usable_window(execution_window, output_reserve, 0)
                .multimodal_tokens;

        assert!(expected > 0);
        assert_eq!(
            default_multimodal_tokens(Some(true), execution_window, output_reserve),
            expected
        );
    }

    #[test]
    fn multimodal_default_is_nonzero_only_for_a_capable_route_with_usable_context() {
        assert_eq!(default_multimodal_tokens(Some(true), 9, 8), 1);
        assert_eq!(default_multimodal_tokens(Some(true), 8, 8), 0);
        assert_eq!(default_multimodal_tokens(Some(false), 280_192, 8_192), 0);
        assert_eq!(default_multimodal_tokens(None, 280_192, 8_192), 0);
    }
}
