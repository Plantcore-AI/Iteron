use super::*;

use super::values::{capability_list, int, text};
use iteron_protocol::Capability;
use iteron_tunables::{ConstraintValue, DecimalValue, ExternalCeiling, ResolutionValue};

pub(super) fn apply(
    builder: &mut RuntimeResolutionBuilder,
    input: &ExecutionFactsInput<'_>,
    report: &mut ExecutionFactsReport,
) -> Result<(), ExecutionFactError> {
    add_tool_and_verifier_constraints(builder, input, report)?;
    add_orchestration_constraints(builder, input, report)?;
    add_runtime_constraints(builder, input, report)?;
    add_prompt_constraints(builder, input, report)?;
    add_unrepresentable_constraints(report);
    Ok(())
}

fn add_tool_and_verifier_constraints(
    builder: &mut RuntimeResolutionBuilder,
    input: &ExecutionFactsInput<'_>,
    report: &mut ExecutionFactsReport,
) -> Result<(), ExecutionFactError> {
    upper(
        builder,
        "shell_timeout_output",
        "timeout_seconds",
        ExternalCeiling::ParentWall,
        int(i64v(input.budget.max_wall_secs, "shell_timeout_output")?),
    )?;
    for field in ["stdout_max_bytes", "stderr_max_bytes"] {
        upper(
            builder,
            "shell_timeout_output",
            field,
            ExternalCeiling::ToolBudget,
            int(i64u(
                iteron_sandbox::Confinement::UNCONFINED_MAX_OUTPUT_BYTES,
                "shell_timeout_output",
            )?),
        )?;
    }
    report.mark("shell_timeout_output", FactStage::Constraint);

    upper(
        builder,
        "verifier_attempts",
        "$",
        ExternalCeiling::RunBudget,
        int(i64::from(iteron_verify::strategy::MAX_VERIFIER_ATTEMPTS)),
    )?;
    report.mark("verifier_attempts", FactStage::Constraint);
    upper(
        builder,
        "verifier_timeout",
        "$",
        ExternalCeiling::ParentWall,
        int(i64v(input.budget.max_wall_secs, "verifier_timeout")?),
    )?;
    report.mark("verifier_timeout", FactStage::Constraint);
    Ok(())
}

fn add_orchestration_constraints(
    builder: &mut RuntimeResolutionBuilder,
    input: &ExecutionFactsInput<'_>,
    report: &mut ExecutionFactsReport,
) -> Result<(), ExecutionFactError> {
    let workflow = iteron_workflow::RunLimits::default();
    upper(
        builder,
        "fan_breadth",
        "$",
        ExternalCeiling::RunBudget,
        int(i64u(workflow.max_agent_calls(), "fan_breadth")?),
    )?;
    upper(
        builder,
        "worker_min_turns",
        "$",
        ExternalCeiling::ParentTurns,
        int(i64::from(input.budget.max_turns)),
    )?;
    upper(
        builder,
        "fan_concurrency",
        "$",
        ExternalCeiling::ProcessBudget,
        int(i64u(workflow.max_concurrency(), "fan_concurrency")?),
    )?;
    for family in ["fan_breadth", "worker_min_turns", "fan_concurrency"] {
        report.mark(family, FactStage::Constraint);
    }

    if input.budget.max_tokens.is_some() {
        upper(
            builder,
            "token_split",
            "$",
            ExternalCeiling::ParentTokens,
            ResolutionValue::Decimal {
                value: DecimalValue {
                    coefficient: 1,
                    scale: 0,
                },
            },
        )?;
        report.mark("token_split", FactStage::Constraint);
    } else {
        report.gap(
            "token_split",
            FactStage::Constraint,
            GapReason::ConstraintAuthorityUnavailable,
        );
    }

    let child_capabilities = input
        .authority_ceiling
        .intersect(CapabilitySet::only(Capability::ReadOnly));
    upper(
        builder,
        "child_ceiling",
        "max_turns",
        ExternalCeiling::ParentTurns,
        int(i64::from(input.budget.max_turns)),
    )?;
    upper(
        builder,
        "child_ceiling",
        "max_wall_seconds",
        ExternalCeiling::ParentWall,
        int(i64v(input.budget.max_wall_secs, "child_ceiling")?),
    )?;
    domain(
        builder,
        "child_ceiling",
        "capabilities",
        ExternalCeiling::OperatorAuthority,
        [capability_list(child_capabilities)],
    )?;
    report.mark("child_ceiling", FactStage::Constraint);

    domain(
        builder,
        "subagent_effort_inheritance",
        "$",
        ExternalCeiling::ProviderCapability,
        input.inherited_effort_domain(),
    )?;
    report.mark("subagent_effort_inheritance", FactStage::Constraint);
    report.gap(
        "join_reduce",
        FactStage::Constraint,
        GapReason::OwnerQueryUnavailable,
    );

    add_partial_workflow_constraints(builder, input, workflow, report)
}

fn add_partial_workflow_constraints(
    builder: &mut RuntimeResolutionBuilder,
    input: &ExecutionFactsInput<'_>,
    workflow: iteron_workflow::RunLimits,
    report: &mut ExecutionFactsReport,
) -> Result<(), ExecutionFactError> {
    upper(
        builder,
        "workflow_aggregate",
        "max_calls",
        ExternalCeiling::RunBudget,
        int(i64u(workflow.max_agent_calls(), "workflow_aggregate")?),
    )?;
    upper(
        builder,
        "workflow_aggregate",
        "max_wall_seconds",
        ExternalCeiling::ParentWall,
        int(i64v(input.budget.max_wall_secs, "workflow_aggregate")?),
    )?;
    if let Some(tokens) = input.budget.max_tokens {
        upper(
            builder,
            "workflow_aggregate",
            "max_tokens",
            ExternalCeiling::ParentTokens,
            int(i64v(tokens, "workflow_aggregate")?),
        )?;
    } else {
        report.gap(
            "workflow_aggregate",
            FactStage::Constraint,
            GapReason::ConstraintAuthorityUnavailable,
        );
    }
    upper(
        builder,
        "schema_retry_jitter",
        "cap_milliseconds",
        ExternalCeiling::ParentWall,
        int(i64v(
            input.budget.max_wall_secs.saturating_mul(1_000),
            "schema_retry_jitter",
        )?),
    )?;
    report.mark("workflow_aggregate", FactStage::Constraint);
    report.mark("schema_retry_jitter", FactStage::Constraint);
    Ok(())
}

fn add_runtime_constraints(
    builder: &mut RuntimeResolutionBuilder,
    input: &ExecutionFactsInput<'_>,
    report: &mut ExecutionFactsReport,
) -> Result<(), ExecutionFactError> {
    upper(
        builder,
        "provider_connect_tls_timeout",
        "$",
        ExternalCeiling::ParentWall,
        int(i64v(
            input.budget.max_wall_secs,
            "provider_connect_tls_timeout",
        )?),
    )?;
    report.mark("provider_connect_tls_timeout", FactStage::Constraint);

    upper(
        builder,
        "app_server_sq_eq_backpressure",
        "submission_entries",
        ExternalCeiling::RunBudget,
        int(i64u(
            crate::app_server::SQ_CAPACITY,
            "app_server_sq_eq_backpressure",
        )?),
    )?;
    upper(
        builder,
        "app_server_sq_eq_backpressure",
        "event_entries",
        ExternalCeiling::RunBudget,
        int(i64u(
            crate::app_server::EQ_CAPACITY,
            "app_server_sq_eq_backpressure",
        )?),
    )?;
    report.mark("app_server_sq_eq_backpressure", FactStage::Constraint);
    upper(
        builder,
        "provider_discovery_account_probe_cache_policy",
        "eager_budget_milliseconds",
        ExternalCeiling::ParentWall,
        int(i64v(
            input.budget.max_wall_secs.saturating_mul(1_000),
            "provider_discovery_account_probe_cache_policy",
        )?),
    )?;
    report.mark(
        "provider_discovery_account_probe_cache_policy",
        FactStage::Constraint,
    );
    Ok(())
}

fn add_prompt_constraints(
    builder: &mut RuntimeResolutionBuilder,
    input: &ExecutionFactsInput<'_>,
    report: &mut ExecutionFactsReport,
) -> Result<(), ExecutionFactError> {
    let Some(prompt) = input.operator_prompt else {
        return Ok(());
    };
    domain(
        builder,
        "operator_prompt_stream",
        "$",
        ExternalCeiling::OperatorAuthority,
        [text(prompt)],
    )?;
    let Some(window) = input.model_capabilities.context_window_tokens else {
        report.gap(
            "operator_prompt_stream",
            FactStage::Constraint,
            GapReason::ConstraintAuthorityUnavailable,
        );
        return Ok(());
    };
    if u64::try_from(iteron_ctx::estimate_tokens(prompt)).unwrap_or(u64::MAX) > window {
        report.gap(
            "operator_prompt_stream",
            FactStage::Constraint,
            GapReason::ValueExceedsAuthority,
        );
        return Ok(());
    }
    domain(
        builder,
        "operator_prompt_stream",
        "$",
        ExternalCeiling::ContextWindow,
        [text(prompt)],
    )?;
    report.mark("operator_prompt_stream", FactStage::Constraint);
    Ok(())
}

fn add_unrepresentable_constraints(report: &mut ExecutionFactsReport) {
    for family in ["writer_fan_turn_split", "wall_split"] {
        report.gap(
            family,
            FactStage::Constraint,
            GapReason::ConstraintUnitMismatch,
        );
    }
    for family in [
        "read_file_limits",
        "list_dir_limits",
        "glob_limits",
        "grep_limits",
        "repo_map",
        "git_limits",
        "web_fetch_limits",
        "web_search_cap",
        "verifier_feedback_tails",
        "report_budget",
        "multimodal_input_admission_decode_envelope",
    ] {
        report.gap(
            family,
            FactStage::Constraint,
            GapReason::ConstraintUnitMismatch,
        );
    }
    report.gap(
        "pure_overlap",
        FactStage::Constraint,
        GapReason::ConstraintAuthorityUnavailable,
    );
    for family in ["failed_action_dedup", "pure_memo_cache"] {
        report.gap(
            family,
            FactStage::Constraint,
            GapReason::OwnerProjectionNotVisible,
        );
    }
    report.gap(
        "decomposition_profile",
        FactStage::Constraint,
        GapReason::ProviderCapabilityIncomplete,
    );
    report.gap(
        "route_topology",
        FactStage::Constraint,
        GapReason::DynamicPolicyNotRepresentable,
    );
    for family in [
        "builtin_prompt_corpus",
        "instruction_bundle",
        "memory_corpus",
        "skill_catalog",
        "agent_catalog",
        "mcp_topology_tool_catalog",
        "tool_action_space",
        "rate_card_catalog",
        "router_lexicons",
        "web_search_backend_catalog",
    ] {
        report.gap(
            family,
            FactStage::Constraint,
            GapReason::GovernedCatalogNotAdmissible,
        );
    }
    for family in ["hooks_map", "workflow_graph"] {
        report.gap(
            family,
            FactStage::Constraint,
            GapReason::CatalogResolverValueShapeMismatch,
        );
    }
    report.gap(
        "environment_snapshot",
        FactStage::Constraint,
        GapReason::OpaqueEnvironmentNotAMap,
    );
}

fn upper(
    builder: &mut RuntimeResolutionBuilder,
    family: &str,
    field: &str,
    ceiling: ExternalCeiling,
    value: ResolutionValue,
) -> Result<(), ExecutionFactError> {
    builder.constrain(
        family,
        field,
        ceiling,
        ConstraintValue::UpperBound { value },
    )?;
    Ok(())
}

fn domain(
    builder: &mut RuntimeResolutionBuilder,
    family: &str,
    field: &str,
    ceiling: ExternalCeiling,
    values: impl IntoIterator<Item = ResolutionValue>,
) -> Result<(), ExecutionFactError> {
    builder.constrain(
        family,
        field,
        ceiling,
        ConstraintValue::Domain {
            minimum: None,
            maximum: None,
            allowed_values: Some(values.into_iter().collect()),
            required_values: None,
            preferred: None,
        },
    )?;
    Ok(())
}
