use super::*;

use super::values::{
    agent_catalog_value, boolv, environment_snapshot_value, hook_catalog_value, int,
};
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
    add_content_identity_constraints(builder, input, report)?;
    add_unrepresentable_constraints(report);
    Ok(())
}

fn add_tool_and_verifier_constraints(
    builder: &mut RuntimeResolutionBuilder,
    input: &ExecutionFactsInput<'_>,
    report: &mut ExecutionFactsReport,
) -> Result<(), ExecutionFactError> {
    domain(
        builder,
        "pure_overlap",
        "$",
        ExternalCeiling::ToolBudget,
        [boolv(input.registry.pure_overlap_enabled())],
    )?;
    upper(
        builder,
        "pure_concurrency",
        "$",
        ExternalCeiling::ProcessBudget,
        int(i64u(
            iteron_tunables::param_integer(
                "cli.runtime.default_max_tool_concurrency",
                crate::runtime::DEFAULT_MAX_TOOL_CONCURRENCY,
            ),
            "pure_concurrency",
        )?),
    )?;
    upper(
        builder,
        "failed_action_dedup",
        "max_identities",
        ExternalCeiling::ToolBudget,
        int(i64u(
            crate::runtime::failed_action_cache_max_identities(),
            "failed_action_dedup",
        )?),
    )?;
    upper(
        builder,
        "pure_memo_cache",
        "max_entries",
        ExternalCeiling::ToolBudget,
        int(i64u(
            input.registry.pure_memo_cache_policy().max_entries,
            "pure_memo_cache",
        )?),
    )?;
    upper(
        builder,
        "web_search_cap",
        "$",
        ExternalCeiling::ContextWindow,
        int(i64u(iteron_tools::WEB_SEARCH_RESULT_CAP, "web_search_cap")?),
    )?;
    for family in [
        "pure_overlap",
        "pure_concurrency",
        "failed_action_dedup",
        "pure_memo_cache",
        "web_search_cap",
    ] {
        report.mark(family, FactStage::Constraint);
    }
    for (family, field, ceiling) in [
        ("read_file_limits", "output_max_bytes", 16_i64 * 1024 * 1024),
        ("list_dir_limits", "output_max_bytes", 16_i64 * 1024 * 1024),
        ("glob_limits", "output_max_bytes", 16_i64 * 1024 * 1024),
        ("repo_map", "max_tokens", 1_000_000_i64),
        ("web_fetch_limits", "body_max_bytes", 16_i64 * 1024 * 1024),
    ] {
        upper(
            builder,
            family,
            field,
            ExternalCeiling::ToolBudget,
            int(ceiling),
        )?;
        report.mark(family, FactStage::Constraint);
    }
    upper(
        builder,
        "web_fetch_limits",
        "timeout_seconds",
        ExternalCeiling::ParentWall,
        int(i64v(input.budget.max_wall_secs, "web_fetch_limits")?),
    )?;
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
        "grep_limits",
        "output_max_bytes",
        ExternalCeiling::ContextWindow,
        int(i64u(
            iteron_tools::ObservationToolPolicy::default()
                .grep
                .output_max_bytes,
            "grep_limits",
        )?),
    )?;
    report.mark("grep_limits", FactStage::Constraint);
    upper(
        builder,
        "git_limits",
        "timeout_seconds",
        ExternalCeiling::ParentWall,
        int(i64v(input.budget.max_wall_secs, "git_limits")?),
    )?;
    upper(
        builder,
        "git_limits",
        "output_max_bytes",
        ExternalCeiling::ContextWindow,
        int(i64u(
            iteron_tools::ObservationToolPolicy::default()
                .git
                .output_max_bytes,
            "git_limits",
        )?),
    )?;
    report.mark("git_limits", FactStage::Constraint);

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
        "verifier_feedback_tails",
        "total_bytes",
        ExternalCeiling::ToolBudget,
        int(i64u(
            iteron_verify::MAX_VERIFICATION_FEEDBACK_BYTES,
            "verifier_feedback_tails",
        )?),
    )?;
    report.mark("verifier_feedback_tails", FactStage::Constraint);
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
    let execution = super::super::execution_policy::ExecutionRuntimePolicy::owner(
        input.effort,
        input.budget,
        input.run_limits,
    );
    let decomposition = iteron_agents::DecompositionProfile::owner();
    upper(
        builder,
        "decomposition_profile",
        "max_output_tokens",
        ExternalCeiling::ParentTokens,
        int(i64v(
            input.budget.max_tokens.unwrap_or(
                super::super::execution_policy::absent_budget_decomposition_token_ceiling(),
            ),
            "decomposition_profile",
        )?),
    )?;
    upper(
        builder,
        "decomposition_profile",
        "thinking_tokens",
        ExternalCeiling::RunBudget,
        int(i64::from(decomposition.thinking_tokens)),
    )?;
    report.mark("decomposition_profile", FactStage::Constraint);
    domain(
        builder,
        "route_topology",
        "$",
        ExternalCeiling::OperatorAuthority,
        [super::values::en(match execution.route_topology {
            super::super::execution_policy::RouteTopology::Direct => "direct",
            super::super::execution_policy::RouteTopology::Orchestrated => "orchestrated",
        })],
    )?;
    upper(
        builder,
        "admission",
        "minimum_remaining_turns",
        ExternalCeiling::ParentTurns,
        int(i64::from(input.budget.max_turns)),
    )?;
    upper(
        builder,
        "admission",
        "minimum_remaining_wall_seconds",
        ExternalCeiling::ParentWall,
        int(i64v(input.budget.max_wall_secs, "admission")?),
    )?;
    upper(
        builder,
        "writer_fan_turn_split",
        "minimum_writer_turns",
        ExternalCeiling::ParentTurns,
        int(i64::from(input.budget.max_turns)),
    )?;
    upper(
        builder,
        "wall_split",
        "minimum_fan_seconds",
        ExternalCeiling::ParentWall,
        int(i64v(input.budget.max_wall_secs, "wall_split")?),
    )?;
    upper(
        builder,
        "direct_child_allocation",
        "minimum_child_turns",
        ExternalCeiling::ParentTurns,
        int(i64::from(input.budget.max_turns)),
    )?;
    upper(
        builder,
        "direct_child_allocation",
        "minimum_remaining_wall_seconds",
        ExternalCeiling::ParentWall,
        int(i64v(input.budget.max_wall_secs, "direct_child_allocation")?),
    )?;
    upper(
        builder,
        "report_budget",
        "$",
        ExternalCeiling::ToolBudget,
        int(16 * 1024 * 1024),
    )?;
    for family in [
        "route_topology",
        "admission",
        "writer_fan_turn_split",
        "wall_split",
        "direct_child_allocation",
        "report_budget",
    ] {
        report.mark(family, FactStage::Constraint);
    }
    let workflow = input.run_limits;
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

    // This family is a dimensionless share of whatever parent-token budget exists. The parent
    // authority always caps a share at one even when it has no finite aggregate token ceiling;
    // requiring `max_tokens: Some` would make the fixed half-split policy unresolved on the normal
    // unlimited-token path.
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
        [super::values::capability_list(child_capabilities)],
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
    domain(
        builder,
        "join_reduce",
        "include_failed_evidence",
        ExternalCeiling::VerificationFloor,
        [boolv(
            iteron_agents::join_reduce_policy().include_failed_evidence,
        )],
    )?;
    report.mark("join_reduce", FactStage::Constraint);

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
            crate::app_server::AppServerQueuePolicy::owner().submission_entries(),
            "app_server_sq_eq_backpressure",
        )?),
    )?;
    upper(
        builder,
        "app_server_sq_eq_backpressure",
        "event_entries",
        ExternalCeiling::RunBudget,
        int(i64u(
            crate::app_server::AppServerQueuePolicy::owner().event_entries(),
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

    let image = crate::image_input::multimodal_decode_envelope();
    upper(
        builder,
        "multimodal_input_admission_decode_envelope",
        "aggregate_raw_bytes",
        ExternalCeiling::ToolBudget,
        int(i64u(
            image.aggregate_raw_bytes,
            "multimodal_input_admission_decode_envelope",
        )?),
    )?;
    report.mark(
        "multimodal_input_admission_decode_envelope",
        FactStage::Constraint,
    );
    Ok(())
}

fn add_content_identity_constraints(
    builder: &mut RuntimeResolutionBuilder,
    input: &ExecutionFactsInput<'_>,
    report: &mut ExecutionFactsReport,
) -> Result<(), ExecutionFactError> {
    if let Some(hooks) = input.hooks_catalog.as_ref() {
        domain(
            builder,
            "hooks_map",
            "command_sha256",
            ExternalCeiling::OperatorAuthority,
            [hook_catalog_value(hooks)?],
        )?;
        report.mark("hooks_map", FactStage::Constraint);
    }
    let environment =
        iteron_protocol::EnvironmentSnapshotIdentity::from_optional(input.environment);
    domain(
        builder,
        "environment_snapshot",
        "$",
        ExternalCeiling::TenantScope,
        [environment_snapshot_value(&environment)?],
    )?;
    report.mark("environment_snapshot", FactStage::Constraint);

    let agent_catalog = agent_catalog_value(&input.agent_catalog.runtime_identity())?;
    domain(
        builder,
        "agent_catalog",
        "requested_tools",
        ExternalCeiling::OperatorAuthority,
        [agent_catalog],
    )?;
    report.mark("agent_catalog", FactStage::Constraint);
    Ok(())
}

fn add_unrepresentable_constraints(report: &mut ExecutionFactsReport) {
    for family in [
        "builtin_prompt_corpus",
        "instruction_bundle",
        "memory_corpus",
        "skill_catalog",
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
