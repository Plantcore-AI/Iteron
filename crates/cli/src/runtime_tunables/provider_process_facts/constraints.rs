use super::value::{boolv, dec, en, int, list, map, text, upper};
use super::{
    FactGapReason, FactLayer, ProviderProcessFactError, ProviderProcessFactGap,
    ProviderProcessFactsInput, ProviderProcessFactsReport, VerificationOwnerFacts,
};
use iteron_tunables::{ExternalCeiling, RuntimeResolutionBuilder};
use iteron_verify::{VerificationRollbackMode, VerificationSelectionMode, VerifierScope};

pub(super) fn apply(
    builder: &mut RuntimeResolutionBuilder,
    input: &ProviderProcessFactsInput<'_>,
    report: &mut ProviderProcessFactsReport,
) -> Result<(), ProviderProcessFactError> {
    add_governor_constraints(builder, input, report)?;
    add_wall_constraints(builder, input, report)?;
    add_context_constraints(builder, input, report)?;
    add_process_constraints(builder, input, report)?;
    add_binary_media_constraints(builder, input, report)?;
    add_verification_constraints(builder, input, report)?;
    Ok(())
}

fn add_governor_constraints(
    builder: &mut RuntimeResolutionBuilder,
    input: &ProviderProcessFactsInput<'_>,
    report: &mut ProviderProcessFactsReport,
) -> Result<(), ProviderProcessFactError> {
    let role_routes = super::super::execution_policy::admitted_role_model_routes(
        input.agent_catalog,
        &input.selection.provider_id,
        &input.selection.model_id,
    )
    .map_err(|_| ProviderProcessFactError::EvidenceEncoding)?;
    let role_routes = map(role_routes
        .into_iter()
        .map(|(role, route)| (role, en(&route))));
    for ceiling in [
        ExternalCeiling::ProviderCapability,
        ExternalCeiling::ParentCost,
    ] {
        super::value::domain(
            builder,
            "role_specific_model_map",
            "$",
            ceiling,
            [role_routes.clone()],
        )?;
        report.constrained("role_specific_model_map", "$", ceiling);
    }
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
    let (actual_window, execution_window, _) = super::context_owner_window(input)?;
    let window_value = actual_window
        .map(|value| super::value::i64u(value as u64, "context_window"))
        .transpose()?
        .map(int);
    let execution_window_value = int(super::value::i64u(
        execution_window as u64,
        "context_window",
    )?);
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
    for family in [
        "system_prefix_budget",
        "conversation_history_budget",
        "tool_result_history_budget",
    ] {
        upper(
            builder,
            family,
            "$",
            ExternalCeiling::ContextWindow,
            execution_window_value.clone(),
        )?;
        report.constrained(family, "$", ExternalCeiling::ContextWindow);
    }
    if let Some(value) = &window_value {
        upper(
            builder,
            "multimodal_token_budget",
            "$",
            ExternalCeiling::ContextWindow,
            value.clone(),
        )?;
        report.constrained(
            "multimodal_token_budget",
            "$",
            ExternalCeiling::ContextWindow,
        );
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
        super::value::domain(
            builder,
            "multimodal_token_budget",
            "$",
            ExternalCeiling::ProviderCapability,
            [int(0)],
        )?;
        report.constrained(
            "multimodal_token_budget",
            "$",
            ExternalCeiling::ProviderCapability,
        );
    }
    upper(
        builder,
        "lsp_result_context_budget",
        "$",
        ExternalCeiling::ContextWindow,
        execution_window_value,
    )?;
    report.constrained(
        "lsp_result_context_budget",
        "$",
        ExternalCeiling::ContextWindow,
    );

    super::value::domain(
        builder,
        "auto_compaction_enable",
        "$",
        ExternalCeiling::ContextWindow,
        [boolv(input.compaction.enabled)],
    )?;
    report.constrained(
        "auto_compaction_enable",
        "$",
        ExternalCeiling::ContextWindow,
    );
    super::value::domain(
        builder,
        "summary_consistency_coverage_check",
        "$",
        ExternalCeiling::VerificationFloor,
        [boolv(input.compaction.coverage_check)],
    )?;
    report.constrained(
        "summary_consistency_coverage_check",
        "$",
        ExternalCeiling::VerificationFloor,
    );

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
    let topologies = match actual_window {
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
    super::value::domain(
        builder,
        "retrieval_recency_decay",
        "$",
        ExternalCeiling::TenantScope,
        [dec(1, 0)],
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

    {
        let policy = input
            .registry
            .process_control()
            .map_or_else(iteron_tools::ProcessRuntimePolicy::default, |control| {
                control.policy()
            });
        let launch = iteron_tools::ProcessLaunchPolicy::owner(input.workspace)
            .map_err(|_| ProviderProcessFactError::EvidenceEncoding)?;
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
        super::value::domain(
            builder,
            "process_cwd_continuity",
            "scope",
            ExternalCeiling::OperatorAuthority,
            [en(launch.cwd.scope.as_str())],
        )?;
        report.constrained(
            "process_cwd_continuity",
            "scope",
            ExternalCeiling::OperatorAuthority,
        );
        super::value::domain(
            builder,
            "process_cwd_continuity",
            "initial_cwd",
            ExternalCeiling::TenantScope,
            [text(&launch.cwd.initial_cwd.to_string_lossy())],
        )?;
        report.constrained(
            "process_cwd_continuity",
            "initial_cwd",
            ExternalCeiling::TenantScope,
        );
        super::value::domain(
            builder,
            "process_cwd_continuity",
            "preserve_changes",
            ExternalCeiling::OperatorAuthority,
            [boolv(launch.cwd.preserve_changes)],
        )?;
        report.constrained(
            "process_cwd_continuity",
            "preserve_changes",
            ExternalCeiling::OperatorAuthority,
        );
        upper(
            builder,
            "child_process_environment_reuse",
            "max_entries",
            ExternalCeiling::ProcessBudget,
            int(i64::try_from(launch.environment.max_entries).map_err(|_| {
                ProviderProcessFactError::IntegerOverflow("child_process_environment_reuse")
            })?),
        )?;
        report.constrained(
            "child_process_environment_reuse",
            "max_entries",
            ExternalCeiling::ProcessBudget,
        );
        super::value::domain(
            builder,
            "child_process_environment_reuse",
            "blocked_names",
            ExternalCeiling::OperatorAuthority,
            [list(
                launch
                    .environment
                    .blocked_names
                    .iter()
                    .map(|name| text(name)),
            )],
        )?;
        report.constrained(
            "child_process_environment_reuse",
            "blocked_names",
            ExternalCeiling::OperatorAuthority,
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

    super::value::exact(
        builder,
        "process_signal_kill_escalation",
        "$",
        ExternalCeiling::BenchmarkProtocol,
        en(iteron_sandbox::ProcessSignalKillEscalationPolicy::ID),
    )?;
    report.constrained(
        "process_signal_kill_escalation",
        "$",
        ExternalCeiling::BenchmarkProtocol,
    );

    let effecting = crate::runtime::effecting_tool_admission_policy();
    let concurrency = int(super::value::i64z(
        effecting.max_concurrency,
        "effecting_tool_concurrency",
    )?);
    upper(
        builder,
        "effecting_tool_concurrency",
        "$",
        ExternalCeiling::ProcessBudget,
        concurrency.clone(),
    )?;
    report.constrained(
        "effecting_tool_concurrency",
        "$",
        ExternalCeiling::ProcessBudget,
    );
    super::value::domain(
        builder,
        "effecting_tool_concurrency",
        "$",
        ExternalCeiling::OperatorAuthority,
        [concurrency],
    )?;
    report.constrained(
        "effecting_tool_concurrency",
        "$",
        ExternalCeiling::OperatorAuthority,
    );
    super::value::domain(
        builder,
        "write_set_conflict_admission",
        "declared_set_required",
        ExternalCeiling::OperatorAuthority,
        [boolv(effecting.declared_set_required)],
    )?;
    report.constrained(
        "write_set_conflict_admission",
        "declared_set_required",
        ExternalCeiling::OperatorAuthority,
    );
    Ok(())
}

fn add_binary_media_constraints(
    builder: &mut RuntimeResolutionBuilder,
    input: &ProviderProcessFactsInput<'_>,
    report: &mut ProviderProcessFactsReport,
) -> Result<(), ProviderProcessFactError> {
    let policy = input.binary_media_policy;
    super::value::domain(
        builder,
        "binary_media_inspection_routing",
        "mime_routes",
        ExternalCeiling::OperatorAuthority,
        [map(policy
            .mime_routes()
            .into_iter()
            .map(|(mime, inspector)| (mime, en(&inspector))))],
    )?;
    report.constrained(
        "binary_media_inspection_routing",
        "mime_routes",
        ExternalCeiling::OperatorAuthority,
    );
    upper(
        builder,
        "binary_media_inspection_routing",
        "max_input_bytes",
        ExternalCeiling::ToolBudget,
        int(super::value::i64u(
            policy.max_input_bytes() as u64,
            "binary_media_inspection_routing",
        )?),
    )?;
    report.constrained(
        "binary_media_inspection_routing",
        "max_input_bytes",
        ExternalCeiling::ToolBudget,
    );
    Ok(())
}

fn add_verification_constraints(
    builder: &mut RuntimeResolutionBuilder,
    input: &ProviderProcessFactsInput<'_>,
    report: &mut ProviderProcessFactsReport,
) -> Result<(), ProviderProcessFactError> {
    match input.verification {
        VerificationOwnerFacts::Configured { floor, .. } => {
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
                [list(
                    input
                        .verification_policy
                        .required_commands
                        .iter()
                        .map(|command| text(command)),
                )],
            )?;
            report.constrained(
                "test_selection_strategy",
                "required_commands",
                ExternalCeiling::VerificationFloor,
            );
        }
        VerificationOwnerFacts::Disabled => {
            super::value::domain(
                builder,
                "test_selection_strategy",
                "scope",
                ExternalCeiling::VerificationFloor,
                [en("workspace")],
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
                [list(std::iter::empty::<iteron_tunables::ResolutionValue>())],
            )?;
            report.constrained(
                "test_selection_strategy",
                "required_commands",
                ExternalCeiling::VerificationFloor,
            );
        }
        VerificationOwnerFacts::GetterUnavailable => {
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
    let allowed_selection = match input.verification {
        VerificationOwnerFacts::Configured { .. }
            if input.verification_policy.required_commands.len() > 1 =>
        {
            // A narrow value is admitted only when its resolved command vector also contains the
            // exact full workspace command as the final gate. The resolver cannot invent this
            // vector and the runtime executes it without applying selection a second time.
            vec![en(match input.verification_policy.selection {
                VerificationSelectionMode::Incremental => "incremental",
                VerificationSelectionMode::Impacted => "impacted",
                VerificationSelectionMode::Full => "full",
            })]
        }
        VerificationOwnerFacts::Configured { .. }
        | VerificationOwnerFacts::Disabled
        | VerificationOwnerFacts::GetterUnavailable => vec![en("full")],
    };
    super::value::domain(
        builder,
        "incremental_versus_full_verification",
        "$",
        ExternalCeiling::VerificationFloor,
        allowed_selection,
    )?;
    report.constrained(
        "incremental_versus_full_verification",
        "$",
        ExternalCeiling::VerificationFloor,
    );
    upper(
        builder,
        "flaky_test_detection_quarantine",
        "repeat_count",
        ExternalCeiling::RunBudget,
        int(i64::from(input.budget.max_turns.min(64).max(1))),
    )?;
    report.constrained(
        "flaky_test_detection_quarantine",
        "repeat_count",
        ExternalCeiling::RunBudget,
    );

    let rollback = match input.verification_policy.restore.mode {
        VerificationRollbackMode::Off => "off",
        VerificationRollbackMode::SelectedPaths => "selected_paths",
        VerificationRollbackMode::Workspace => "workspace",
    };
    super::value::domain(
        builder,
        "rollback_on_verification_failure",
        "$",
        ExternalCeiling::OperatorAuthority,
        [en(rollback)],
    )?;
    report.constrained(
        "rollback_on_verification_failure",
        "$",
        ExternalCeiling::OperatorAuthority,
    );
    if input.verification_policy.restore.mode == VerificationRollbackMode::SelectedPaths {
        super::value::domain(
            builder,
            "selective_restore_scope",
            "paths",
            ExternalCeiling::OperatorAuthority,
            [list(
                input
                    .verification_policy
                    .restore
                    .paths
                    .iter()
                    .map(|path| text(path)),
            )],
        )?;
        report.constrained(
            "selective_restore_scope",
            "paths",
            ExternalCeiling::OperatorAuthority,
        );
    }
    upper(
        builder,
        "verification_quorum_consensus",
        "verifiers",
        ExternalCeiling::RunBudget,
        int(i64::from(input.budget.max_turns.min(64).max(1))),
    )?;
    report.constrained(
        "verification_quorum_consensus",
        "verifiers",
        ExternalCeiling::RunBudget,
    );

    super::value::domain(
        builder,
        "retry_eligibility_policy",
        "eligible_classes",
        ExternalCeiling::VerificationFloor,
        [list(
            input
                .verification_policy
                .retry
                .eligible_classes
                .iter()
                .map(|class| text(class.id())),
        )],
    )?;
    report.constrained(
        "retry_eligibility_policy",
        "eligible_classes",
        ExternalCeiling::VerificationFloor,
    );
    upper(
        builder,
        "retry_eligibility_policy",
        "max_attempts",
        ExternalCeiling::RunBudget,
        int(i64::from(input.verification_policy.retry.max_attempts)),
    )?;
    report.constrained(
        "retry_eligibility_policy",
        "max_attempts",
        ExternalCeiling::RunBudget,
    );

    super::value::exact(
        builder,
        "failure_classification_taxonomy",
        "version",
        ExternalCeiling::BenchmarkProtocol,
        super::defaults::failure_classification_catalog_value()?,
    )?;
    report.constrained(
        "failure_classification_taxonomy",
        "version",
        ExternalCeiling::BenchmarkProtocol,
    );
    super::value::domain(
        builder,
        "recovery_escalation_policy",
        "$",
        ExternalCeiling::VerificationFloor,
        [en(iteron_verify::VerificationRecoveryEscalationPolicy::ID)],
    )?;
    report.constrained(
        "recovery_escalation_policy",
        "$",
        ExternalCeiling::VerificationFloor,
    );
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
