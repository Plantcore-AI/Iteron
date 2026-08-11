use super::value::{boolv, dec, en, int, list, text, upper};
use super::{
    FactGapReason, FactLayer, ProviderProcessFactError, ProviderProcessFactGap,
    ProviderProcessFactsInput, ProviderProcessFactsReport, VerificationOwnerFacts,
};
use iteron_tunables::{ExternalCeiling, RuntimeResolutionBuilder};
use iteron_verify::VerifierScope;

pub(super) fn apply(
    builder: &mut RuntimeResolutionBuilder,
    input: &ProviderProcessFactsInput<'_>,
    report: &mut ProviderProcessFactsReport,
) -> Result<(), ProviderProcessFactError> {
    add_governor_constraints(builder, input, report)?;
    add_wall_constraints(builder, input, report)?;
    add_context_constraints(builder, input, report)?;
    add_process_constraints(builder, input, report)?;
    add_verification_constraints(builder, input, report)?;
    Ok(())
}

fn add_governor_constraints(
    builder: &mut RuntimeResolutionBuilder,
    input: &ProviderProcessFactsInput<'_>,
    report: &mut ProviderProcessFactsReport,
) -> Result<(), ProviderProcessFactError> {
    let fallback = list(
        input
            .provider_governor
            .fallback_routes
            .iter()
            .map(|route| en(route)),
    );
    super::value::domain(
        builder,
        "model_fallback_chain",
        "$",
        ExternalCeiling::ProviderCapability,
        [fallback],
    )?;
    report.constrained(
        "model_fallback_chain",
        "$",
        ExternalCeiling::ProviderCapability,
    );

    let failover = list(input.provider_governor.policy.failover.iter().map(|rule| {
        super::value::object([
            ("error_class", super::value::text(rule.class.label())),
            ("eligible", boolv(true)),
            (
                "dispatch_state",
                en(match rule.point {
                    iteron_provider::FailurePoint::PreDispatch => "pre_dispatch",
                    iteron_provider::FailurePoint::ProvenTerminal => "post_dispatch",
                }),
            ),
            ("version", super::value::text("1.0.0")),
        ])
    }));
    builder.constrain(
        "failover_eligible_error_taxonomy",
        "version",
        ExternalCeiling::BenchmarkProtocol,
        iteron_tunables::ConstraintValue::Exact { value: failover },
    )?;
    report.constrained(
        "failover_eligible_error_taxonomy",
        "version",
        ExternalCeiling::BenchmarkProtocol,
    );

    let hedge = input.provider_governor.policy.hedge;
    upper(
        builder,
        "hedged_request_policy",
        "delay_milliseconds",
        ExternalCeiling::ParentWall,
        int(super::value::i64u(
            input.budget.max_wall_secs.saturating_mul(1_000),
            "hedged_request_policy",
        )?),
    )?;
    report.constrained(
        "hedged_request_policy",
        "delay_milliseconds",
        ExternalCeiling::ParentWall,
    );
    upper(
        builder,
        "hedged_request_policy",
        "max_duplicates",
        ExternalCeiling::ParentCost,
        int(i64::from(hedge.max_duplicates)),
    )?;
    report.constrained(
        "hedged_request_policy",
        "max_duplicates",
        ExternalCeiling::ParentCost,
    );

    let controls = input.provider_governor.controls;
    super::value::domain(
        builder,
        "provider_service_tier",
        "$",
        ExternalCeiling::ProviderCapability,
        input
            .provider_control_capabilities
            .service_tiers
            .iter()
            .map(|tier| en(tier.label())),
    )?;
    super::value::domain(
        builder,
        "provider_service_tier",
        "$",
        ExternalCeiling::ParentCost,
        [en(controls.service_tier.label())],
    )?;
    super::value::domain(
        builder,
        "response_verbosity",
        "$",
        ExternalCeiling::ProviderCapability,
        input
            .provider_control_capabilities
            .verbosity
            .iter()
            .map(|verbosity| en(verbosity.label())),
    )?;
    super::value::domain(
        builder,
        "response_verbosity",
        "$",
        ExternalCeiling::ParentTokens,
        [en(controls.verbosity.label())],
    )?;
    for (family, ceiling) in [
        ("provider_service_tier", ExternalCeiling::ProviderCapability),
        ("provider_service_tier", ExternalCeiling::ParentCost),
        ("response_verbosity", ExternalCeiling::ProviderCapability),
        ("response_verbosity", ExternalCeiling::ParentTokens),
    ] {
        report.constrained(family, "$", ceiling);
    }
    Ok(())
}

fn add_wall_constraints(
    builder: &mut RuntimeResolutionBuilder,
    input: &ProviderProcessFactsInput<'_>,
    report: &mut ProviderProcessFactsReport,
) -> Result<(), ProviderProcessFactError> {
    if input.budget.max_wall_secs == 0 {
        for (ordinal, family, field) in [
            (
                89,
                "provider_health_circuit_breaker_state_policy",
                "open_seconds",
            ),
            (94, "provider_request_total_deadline", "$"),
            (95, "stream_idle_watchdog", "$"),
        ] {
            gap(
                report,
                ordinal,
                family,
                field,
                ExternalCeiling::ParentWall,
                FactGapReason::ExternalCeilingBelowSchemaMinimum,
            );
        }
        upper(
            builder,
            "provider_health_circuit_breaker_state_policy",
            "half_open_probes",
            ExternalCeiling::RunBudget,
            int(1),
        )?;
        report.constrained(
            "provider_health_circuit_breaker_state_policy",
            "half_open_probes",
            ExternalCeiling::RunBudget,
        );
        return Ok(());
    }
    let wall_ms = input
        .budget
        .max_wall_secs
        .saturating_mul(1_000)
        .min(86_400_000);
    let wall_ms = int(super::value::i64u(wall_ms, "parent_wall")?);
    upper(
        builder,
        "provider_health_circuit_breaker_state_policy",
        "open_seconds",
        ExternalCeiling::ParentWall,
        int(super::value::i64u(
            input.budget.max_wall_secs.min(86_400),
            "provider_health_open_seconds",
        )?),
    )?;
    report.constrained(
        "provider_health_circuit_breaker_state_policy",
        "open_seconds",
        ExternalCeiling::ParentWall,
    );
    upper(
        builder,
        "provider_health_circuit_breaker_state_policy",
        "half_open_probes",
        ExternalCeiling::RunBudget,
        int(i64::from(input.budget.max_turns.max(1))),
    )?;
    report.constrained(
        "provider_health_circuit_breaker_state_policy",
        "half_open_probes",
        ExternalCeiling::RunBudget,
    );
    for family in ["provider_request_total_deadline", "stream_idle_watchdog"] {
        upper(
            builder,
            family,
            "$",
            ExternalCeiling::ParentWall,
            wall_ms.clone(),
        )?;
        report.constrained(family, "$", ExternalCeiling::ParentWall);
    }
    Ok(())
}

fn add_context_constraints(
    builder: &mut RuntimeResolutionBuilder,
    input: &ProviderProcessFactsInput<'_>,
    report: &mut ProviderProcessFactsReport,
) -> Result<(), ProviderProcessFactError> {
    let window = input
        .model_capabilities
        .context_window_tokens
        .filter(|value| *value > 0)
        .map(|value| value.min(10_000_000));
    let window_value = window
        .map(|value| super::value::i64u(value, "context_window"))
        .transpose()?
        .map(int);
    if let Some(value) = &window_value {
        super::value::domain_max(
            builder,
            "context_window_override_reserve",
            "model_window_tokens",
            ExternalCeiling::ProviderCapability,
            value.clone(),
        )?;
        report.constrained(
            "context_window_override_reserve",
            "model_window_tokens",
            ExternalCeiling::ProviderCapability,
        );
    } else {
        gap(
            report,
            96,
            "context_window_override_reserve",
            "model_window_tokens",
            ExternalCeiling::ProviderCapability,
            FactGapReason::RequiredOwnerFieldUnknown,
        );
    }
    for (ordinal, family) in [
        (97, "system_prefix_budget"),
        (98, "conversation_history_budget"),
        (99, "tool_result_history_budget"),
        (100, "multimodal_token_budget"),
    ] {
        if let Some(value) = &window_value {
            upper(
                builder,
                family,
                "$",
                ExternalCeiling::ContextWindow,
                value.clone(),
            )?;
            report.constrained(family, "$", ExternalCeiling::ContextWindow);
        } else {
            gap(
                report,
                ordinal,
                family,
                "$",
                ExternalCeiling::ContextWindow,
                FactGapReason::RequiredOwnerFieldUnknown,
            );
        }
    }
    if input.model_capabilities.image_input == Some(true) {
        if let Some(value) = &window_value {
            upper(
                builder,
                "multimodal_token_budget",
                "$",
                ExternalCeiling::ProviderCapability,
                value.clone(),
            )?;
            report.constrained(
                "multimodal_token_budget",
                "$",
                ExternalCeiling::ProviderCapability,
            );
        }
    } else {
        gap(
            report,
            100,
            "multimodal_token_budget",
            "$",
            ExternalCeiling::ProviderCapability,
            FactGapReason::CapabilityNotAttested,
        );
    }
    if super::owner::has_tool(input.registry, "lsp_query") {
        if let Some(value) = &window_value {
            upper(
                builder,
                "lsp_result_context_budget",
                "$",
                ExternalCeiling::ContextWindow,
                value.clone(),
            )?;
            report.constrained(
                "lsp_result_context_budget",
                "$",
                ExternalCeiling::ContextWindow,
            );
        } else {
            gap(
                report,
                121,
                "lsp_result_context_budget",
                "$",
                ExternalCeiling::ContextWindow,
                FactGapReason::RequiredOwnerFieldUnknown,
            );
        }
    }

    if window.is_some() {
        super::value::domain(
            builder,
            "auto_compaction_enable",
            "$",
            ExternalCeiling::ContextWindow,
            [boolv(false), boolv(true)],
        )?;
        report.constrained(
            "auto_compaction_enable",
            "$",
            ExternalCeiling::ContextWindow,
        );
    } else {
        gap(
            report,
            101,
            "auto_compaction_enable",
            "$",
            ExternalCeiling::ContextWindow,
            FactGapReason::RequiredOwnerFieldUnknown,
        );
    }

    let turns = int(i64::from(input.budget.max_turns.min(10_000)));
    upper(
        builder,
        "compaction_cooldown_hysteresis",
        "cooldown_turns",
        ExternalCeiling::ParentTurns,
        turns.clone(),
    )?;
    report.constrained(
        "compaction_cooldown_hysteresis",
        "cooldown_turns",
        ExternalCeiling::ParentTurns,
    );
    let topologies = match window {
        Some(window) if window >= 64_000 => {
            vec![en("single_stage"), en("hierarchical"), en("map_reduce")]
        }
        Some(window) if window >= 32_000 => {
            vec![en("single_stage"), en("hierarchical")]
        }
        _ => vec![en("single_stage")],
    };
    super::value::domain(
        builder,
        "multi_stage_summary_topology",
        "$",
        ExternalCeiling::ContextWindow,
        topologies,
    )?;
    report.constrained(
        "multi_stage_summary_topology",
        "$",
        ExternalCeiling::ContextWindow,
    );
    upper(
        builder,
        "retrieval_recency_decay",
        "$",
        ExternalCeiling::TenantScope,
        dec(1, 0),
    )?;
    report.constrained("retrieval_recency_decay", "$", ExternalCeiling::TenantScope);
    upper(
        builder,
        "context_novelty_dedup_threshold",
        "$",
        ExternalCeiling::ContextWindow,
        dec(1, 0),
    )?;
    report.constrained(
        "context_novelty_dedup_threshold",
        "$",
        ExternalCeiling::ContextWindow,
    );
    upper(
        builder,
        "tool_result_cache_ttl",
        "$",
        ExternalCeiling::RunBudget,
        int(super::value::i64u(
            input.budget.max_wall_secs.min(86_400),
            "tool_result_cache_ttl",
        )?),
    )?;
    report.constrained("tool_result_cache_ttl", "$", ExternalCeiling::RunBudget);
    upper(
        builder,
        "workspace_checkpoint_cadence",
        "minimum_turn_interval",
        ExternalCeiling::ParentTurns,
        turns,
    )?;
    report.constrained(
        "workspace_checkpoint_cadence",
        "minimum_turn_interval",
        ExternalCeiling::ParentTurns,
    );
    Ok(())
}

fn add_process_constraints(
    builder: &mut RuntimeResolutionBuilder,
    input: &ProviderProcessFactsInput<'_>,
    report: &mut ProviderProcessFactsReport,
) -> Result<(), ProviderProcessFactError> {
    upper(
        builder,
        "tool_output_spill_to_disk_policy",
        "spill_max_bytes",
        ExternalCeiling::ToolBudget,
        int(super::value::i64u(
            crate::runtime::tool_output_spill::DEFAULT_TOOL_OUTPUT_SPILL_MAX_BYTES as u64,
            "tool_output_spill_to_disk_policy",
        )?),
    )?;
    report.constrained(
        "tool_output_spill_to_disk_policy",
        "spill_max_bytes",
        ExternalCeiling::ToolBudget,
    );

    if let Some(control) = input.registry.process_control() {
        let policy = control.policy();
        let backend = en(policy.backend.as_str());
        for ceiling in [
            ExternalCeiling::ProcessBudget,
            ExternalCeiling::OperatorAuthority,
        ] {
            super::value::domain(
                builder,
                "persistent_pty_backend",
                "$",
                ceiling,
                [backend.clone()],
            )?;
            report.constrained("persistent_pty_backend", "$", ceiling);
        }
        upper(
            builder,
            "concurrent_background_job_cap",
            "$",
            ExternalCeiling::ProcessBudget,
            int(i64::try_from(policy.max_background_jobs).map_err(|_| {
                ProviderProcessFactError::IntegerOverflow("concurrent_background_job_cap")
            })?),
        )?;
        report.constrained(
            "concurrent_background_job_cap",
            "$",
            ExternalCeiling::ProcessBudget,
        );

        let parent_wall_milliseconds = input.budget.max_wall_secs.saturating_mul(1_000);
        upper(
            builder,
            "job_idle_stall_timeout",
            "$",
            ExternalCeiling::ParentWall,
            int(super::value::i64u(
                parent_wall_milliseconds,
                "job_idle_stall_timeout",
            )?),
        )?;
        report.constrained("job_idle_stall_timeout", "$", ExternalCeiling::ParentWall);
        upper(
            builder,
            "interactive_stdin_wait_policy",
            "idle_timeout_milliseconds",
            ExternalCeiling::ParentWall,
            int(super::value::i64u(
                parent_wall_milliseconds,
                "interactive_stdin_wait_policy",
            )?),
        )?;
        report.constrained(
            "interactive_stdin_wait_policy",
            "idle_timeout_milliseconds",
            ExternalCeiling::ParentWall,
        );
    }

    if let Some(control) = input.registry.lsp_control() {
        let policy = control.policy();
        let routes = list(policy.routes.iter().map(|route| {
            super::value::object([
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
        }));
        super::value::domain(
            builder,
            "lsp_server_language_selection",
            "executable",
            ExternalCeiling::OperatorAuthority,
            [routes],
        )?;
        report.constrained(
            "lsp_server_language_selection",
            "executable",
            ExternalCeiling::OperatorAuthority,
        );
        upper(
            builder,
            "lsp_timeout_restart_policy",
            "request_timeout_milliseconds",
            ExternalCeiling::ParentWall,
            int(super::value::i64u(
                input.budget.max_wall_secs.saturating_mul(1_000),
                "lsp_timeout_restart_policy",
            )?),
        )?;
        report.constrained(
            "lsp_timeout_restart_policy",
            "request_timeout_milliseconds",
            ExternalCeiling::ParentWall,
        );
    }

    for (ordinal, family, field, ceiling, reason) in [
        (
            93,
            "role_specific_model_map",
            "$",
            ExternalCeiling::ProviderCapability,
            FactGapReason::OwnerSchemaMismatch,
        ),
        (
            93,
            "role_specific_model_map",
            "$",
            ExternalCeiling::ParentCost,
            FactGapReason::IndependentAuthorityMissing,
        ),
        (
            112,
            "process_signal_kill_escalation",
            "$",
            ExternalCeiling::BenchmarkProtocol,
            FactGapReason::IndependentAuthorityMissing,
        ),
        (
            113,
            "process_cwd_continuity",
            "initial_cwd",
            ExternalCeiling::TenantScope,
            FactGapReason::OwnerSchemaMismatch,
        ),
        (
            114,
            "child_process_environment_reuse",
            "max_entries",
            ExternalCeiling::ProcessBudget,
            FactGapReason::IndependentAuthorityMissing,
        ),
        (
            114,
            "child_process_environment_reuse",
            "blocked_names",
            ExternalCeiling::OperatorAuthority,
            FactGapReason::OwnerGetterMissing,
        ),
        (
            115,
            "effecting_tool_concurrency",
            "$",
            ExternalCeiling::ProcessBudget,
            FactGapReason::IndependentAuthorityMissing,
        ),
        (
            115,
            "effecting_tool_concurrency",
            "$",
            ExternalCeiling::OperatorAuthority,
            FactGapReason::OwnerGetterMissing,
        ),
        (
            116,
            "write_set_conflict_admission",
            "declared_set_required",
            ExternalCeiling::OperatorAuthority,
            FactGapReason::OwnerGetterMissing,
        ),
        (
            118,
            "binary_media_inspection_routing",
            "mime_routes",
            ExternalCeiling::OperatorAuthority,
            FactGapReason::OwnerSchemaMismatch,
        ),
        (
            118,
            "binary_media_inspection_routing",
            "max_input_bytes",
            ExternalCeiling::ToolBudget,
            FactGapReason::IndependentAuthorityMissing,
        ),
    ] {
        gap(report, ordinal, family, field, ceiling, reason);
    }
    Ok(())
}

fn add_verification_constraints(
    builder: &mut RuntimeResolutionBuilder,
    input: &ProviderProcessFactsInput<'_>,
    report: &mut ProviderProcessFactsReport,
) -> Result<(), ProviderProcessFactError> {
    match input.verification {
        VerificationOwnerFacts::Configured { command, floor, .. } => {
            let scopes = match floor.scope_floor {
                VerifierScope::Lane => vec![en("lane"), en("workspace")],
                VerifierScope::Workspace => vec![en("workspace")],
            };
            super::value::domain(
                builder,
                "test_selection_strategy",
                "scope",
                ExternalCeiling::VerificationFloor,
                scopes,
            )?;
            report.constrained(
                "test_selection_strategy",
                "scope",
                ExternalCeiling::VerificationFloor,
            );
            super::value::domain(
                builder,
                "test_selection_strategy",
                "required_commands",
                ExternalCeiling::VerificationFloor,
                [list([text(command)])],
            )?;
            report.constrained(
                "test_selection_strategy",
                "required_commands",
                ExternalCeiling::VerificationFloor,
            );
        }
        VerificationOwnerFacts::Disabled | VerificationOwnerFacts::GetterUnavailable => {
            for field in ["scope", "required_commands"] {
                gap(
                    report,
                    123,
                    "test_selection_strategy",
                    field,
                    ExternalCeiling::VerificationFloor,
                    FactGapReason::IndependentAuthorityMissing,
                );
            }
        }
    }
    for (ordinal, family, field, ceiling, reason) in [
        (
            124,
            "incremental_versus_full_verification",
            "$",
            ExternalCeiling::VerificationFloor,
            FactGapReason::OwnerSchemaMismatch,
        ),
        (
            125,
            "flaky_test_detection_quarantine",
            "repeat_count",
            ExternalCeiling::RunBudget,
            FactGapReason::IndependentAuthorityMissing,
        ),
        (
            126,
            "failure_classification_taxonomy",
            "version",
            ExternalCeiling::BenchmarkProtocol,
            FactGapReason::GovernedCatalogMaterializerMissing,
        ),
        (
            127,
            "retry_eligibility_policy",
            "eligible_classes",
            ExternalCeiling::VerificationFloor,
            FactGapReason::OwnerGetterMissing,
        ),
        (
            127,
            "retry_eligibility_policy",
            "max_attempts",
            ExternalCeiling::RunBudget,
            FactGapReason::OwnerGetterMissing,
        ),
        (
            130,
            "selective_restore_scope",
            "paths",
            ExternalCeiling::OperatorAuthority,
            FactGapReason::OwnerGetterMissing,
        ),
        (
            131,
            "verification_quorum_consensus",
            "verifiers",
            ExternalCeiling::RunBudget,
            FactGapReason::OwnerSchemaMismatch,
        ),
        (
            132,
            "recovery_escalation_policy",
            "$",
            ExternalCeiling::VerificationFloor,
            FactGapReason::OwnerGetterMissing,
        ),
    ] {
        gap(report, ordinal, family, field, ceiling, reason);
    }
    Ok(())
}

fn gap(
    report: &mut ProviderProcessFactsReport,
    ordinal: u16,
    family: &'static str,
    field: &'static str,
    ceiling: ExternalCeiling,
    reason: FactGapReason,
) {
    report.push_gap(ProviderProcessFactGap::new(
        ordinal,
        family,
        FactLayer::Constraint { field, ceiling },
        reason,
    ));
}
