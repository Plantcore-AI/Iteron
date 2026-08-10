use super::value::{boolv, dec, en, int, list, map, object, text};
use super::{
    FactGapReason, FactLayer, ProviderProcessFactError, ProviderProcessFactGap,
    ProviderProcessFactsInput, ProviderProcessFactsReport, VerificationOwnerFacts,
    owner::OwnerSnapshot,
};
use core_tunables::{RuntimeResolutionBuilder, SourceKind};
use core_verify::{VERIFIER_SLOT_VERSION, VerifierScope};

pub(super) fn apply(
    builder: &mut RuntimeResolutionBuilder,
    input: &ProviderProcessFactsInput<'_>,
    owner: &OwnerSnapshot,
    report: &mut ProviderProcessFactsReport,
) -> Result<(), ProviderProcessFactError> {
    add_governor_defaults(builder, input, report)?;
    unsupported(
        builder,
        report,
        93,
        "role_specific_model_map",
        FactGapReason::OwnerGetterMissing,
    )?;
    // The provider keeps these timeouts private. The 900 s embedded fallback remains usable, but
    // this evidence says the owner itself could not be queried.
    unsupported(
        builder,
        report,
        94,
        "provider_request_total_deadline",
        FactGapReason::OwnerGetterMissing,
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
    unsupported(
        builder,
        report,
        118,
        "binary_media_inspection_routing",
        FactGapReason::OwnerSchemaMismatch,
    )?;
    unsupported(
        builder,
        report,
        122,
        "tool_result_cache_ttl",
        FactGapReason::OwnerGetterMissing,
    )?;

    add_verification_defaults(builder, input, report)?;
    // Governed-catalog evidence cannot encode Unsupported: the builder requires a real catalog
    // reference and digest. Leaving it absent is materially different from publishing an empty
    // taxonomy.
    report.push_gap(ProviderProcessFactGap::new(
        126,
        "failure_classification_taxonomy",
        FactLayer::Default,
        FactGapReason::GovernedCatalogMaterializerMissing,
    ));
    unsupported(
        builder,
        report,
        127,
        "retry_eligibility_policy",
        FactGapReason::OwnerGetterMissing,
    )?;
    Ok(())
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

    if let Some(control) = input.registry.process_control() {
        let policy = control.policy();
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
    } else {
        for family in [
            "persistent_pty_backend",
            "concurrent_background_job_cap",
            "job_idle_stall_timeout",
            "interactive_stdin_wait_policy",
        ] {
            builder.observe_default_absent(family, "process_surface_absent")?;
        }
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
        for family in [
            "lsp_server_language_selection",
            "lsp_timeout_restart_policy",
        ] {
            builder.observe_default_absent(family, "language_server_surface_absent")?;
        }
    }
    Ok(())
}

fn add_governor_defaults(
    builder: &mut RuntimeResolutionBuilder,
    input: &ProviderProcessFactsInput<'_>,
    report: &mut ProviderProcessFactsReport,
) -> Result<(), ProviderProcessFactError> {
    use core_provider::FailurePoint;

    let source = if input.provider_governor_configured {
        SourceKind::UserConfig
    } else {
        SourceKind::Builtin
    };
    if !input.provider_governor.fallback_routes.is_empty() {
        builder.declare(
            "model_fallback_chain",
            SourceKind::UserConfig,
            list(
                input
                    .provider_governor
                    .fallback_routes
                    .iter()
                    .map(|route| en(route)),
            ),
        )?;
        report.declared_owner_values.push("model_fallback_chain");
    }
    builder.declare(
        "failover_eligible_error_taxonomy",
        source,
        list(input.provider_governor.policy.failover.iter().map(|rule| {
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
        })),
    )?;
    report
        .declared_owner_values
        .push("failover_eligible_error_taxonomy");

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
    builder.declare(
        "hedged_request_policy",
        source,
        object([
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
        ]),
    )?;
    report.declared_owner_values.push("hedged_request_policy");

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

fn add_context_defaults(
    builder: &mut RuntimeResolutionBuilder,
    input: &ProviderProcessFactsInput<'_>,
    owner: &OwnerSnapshot,
    report: &mut ProviderProcessFactsReport,
) -> Result<(), ProviderProcessFactError> {
    let Some(window) = input
        .model_capabilities
        .context_window_tokens
        .filter(|window| *window > 0)
        .and_then(|window| usize::try_from(window.min(10_000_000)).ok())
    else {
        for family in [
            "context_window_override_reserve",
            "system_prefix_budget",
            "conversation_history_budget",
            "tool_result_history_budget",
            "multimodal_token_budget",
        ] {
            builder.observe_default_absent(family, "model_context_window_unknown")?;
        }
        if owner.lsp_surface {
            builder.observe_default_absent(
                "lsp_result_context_budget",
                "model_context_window_unknown",
            )?;
        }
        return Ok(());
    };

    // Output metadata is authoritative when present. An unknown output cap reserves the exact
    // resolved compaction fallback (bounded by the model window), rather than rediscovering an
    // unrelated 8K constant in the request path. Verification currently contributes no provider
    // request segment of its own, so its honest reserve is zero.
    let output_reserve = input
        .model_capabilities
        .max_output_tokens
        .map(usize::try_from)
        .transpose()
        .map_err(|_| ProviderProcessFactError::IntegerOverflow("max_output_tokens"))?
        .unwrap_or_else(|| input.compaction.trigger_tokens.min(window))
        .min(window);
    let output_reserve_u32 = u32::try_from(output_reserve)
        .map_err(|_| ProviderProcessFactError::IntegerOverflow("max_output_tokens"))?;
    let policy = core_ctx::ContextBudgetPolicy::for_usable_window(window, output_reserve_u32, 0);

    builder.observe_default(
        "context_window_override_reserve",
        object([
            (
                "model_window_tokens",
                int(super::value::i64u(window as u64, "context_window")?),
            ),
            ("output_reserve_tokens", int(i64::from(output_reserve_u32))),
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
    if input.model_capabilities.image_input == Some(true) {
        builder.observe_default(
            "multimodal_token_budget",
            int(super::value::i64u(
                policy.multimodal_tokens as u64,
                "multimodal_token_budget",
            )?),
        )?;
        report.observed_defaults.push("multimodal_token_budget");
    } else {
        builder.observe_default_absent(
            "multimodal_token_budget",
            "provider_multimodal_not_attested",
        )?;
    }
    if owner.lsp_surface {
        builder.observe_default(
            "lsp_result_context_budget",
            int(super::value::i64u(
                policy.lsp_result_tokens as u64,
                "lsp_result_context_budget",
            )?),
        )?;
        report.observed_defaults.push("lsp_result_context_budget");
    }
    Ok(())
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
                    ("required_commands", list([text(command)])),
                    ("max_commands", int(1)),
                ]),
            )?;
            report.observed_defaults.push("test_selection_strategy");

            // This is a typed verifier plan, not a candidate copied back as evidence. The runtime
            // detects any disagreement and does not quarantine it, so those two facts are exact.
            builder.declare(
                "flaky_test_detection_quarantine",
                SourceKind::Builtin,
                object([
                    ("repeat_count", int(i64::from(plan.attempts))),
                    ("minimum_disagreements", int(1)),
                    ("quarantine_seconds", int(0)),
                    ("report_disagreement", boolv(plan.report_flake)),
                ]),
            )?;
            report
                .declared_owner_values
                .push("flaky_test_detection_quarantine");
            builder.observe_default(
                "incremental_versus_full_verification",
                en(match plan.scope {
                    VerifierScope::Lane => "incremental",
                    VerifierScope::Workspace => "full",
                }),
            )?;
            report
                .observed_defaults
                .push("incremental_versus_full_verification");
        }
        VerificationOwnerFacts::Disabled => unsupported(
            builder,
            report,
            123,
            "test_selection_strategy",
            FactGapReason::ExplicitlyDisabled,
        )?,
        VerificationOwnerFacts::GetterUnavailable => unsupported(
            builder,
            report,
            123,
            "test_selection_strategy",
            FactGapReason::OwnerGetterMissing,
        )?,
    }

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
