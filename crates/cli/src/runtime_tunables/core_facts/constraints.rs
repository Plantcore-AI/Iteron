use super::*;

/// Ceiling applied to summary output and compaction effort when the run declares no aggregate
/// parent-token budget. Absent means unbounded authority, so this only has to be large enough not
/// to constrain any real effort tier.
const UNBOUNDED_PARENT_TOKEN_CEILING: i64 = 1_000_000;

pub(super) fn add_constraints(
    builder: &mut RuntimeResolutionBuilder,
    input: &CoreFactsInput<'_>,
    report: &mut CoreFactsReport,
) -> Result<(), CoreFactError> {
    let route = input.route;
    domain_one(
        builder,
        "provider",
        "$",
        ExternalCeiling::ProviderCapability,
        en(&route.route.provider_id),
    )?;
    domain_one(
        builder,
        "model",
        "$",
        ExternalCeiling::ProviderCapability,
        en(&route.route.model_id),
    )?;
    operator_one(builder, "base_url", text(input.base_url.value))?;
    // Effort is first a local harness policy (planning/orchestration and child ceilings). It must
    // remain effective even when the selected provider cannot serialize a semantic effort field.
    // Provider reasoning/thinking maps below stay capability-gated; adapters independently omit an
    // unsupported wire control.
    operator_one(builder, "effort", en(input.effort.value.label()))?;
    if route
        .capabilities
        .contains(&CapabilityRequirement::ProviderReasoningControl)
    {
        domain_one(
            builder,
            "effort_reasoning_map",
            "$",
            ExternalCeiling::ProviderCapability,
            effort_reasoning_map(),
        )?;
        domain_one(
            builder,
            "thinking_map",
            "$",
            ExternalCeiling::ProviderCapability,
            thinking_map(),
        )?;
    }
    upper(
        builder,
        "max_turns",
        "$",
        ExternalCeiling::ParentTurns,
        int(input.budget.max_turns.into()),
    )?;
    if let Some(usd) = input.budget.max_usd {
        upper(
            builder,
            "max_usd",
            "$",
            ExternalCeiling::ParentCost,
            money(usd)?,
        )?;
    }
    add_token_constraints(builder, input, report)?;
    upper(
        builder,
        "max_wall_secs",
        "$",
        ExternalCeiling::ParentWall,
        int(i64v(input.budget.max_wall_secs, "wall")?),
    )?;
    operator_one(builder, "allow_code", boolv(input.allow_code.value))?;
    operator_one(
        builder,
        "permission_mode",
        en(input.permission_mode.value.label()),
    )?;
    operator_one(builder, "permission_rules", rules(input.permission_rules)?)?;
    operator_one(
        builder,
        "bypass_permissions",
        boolv(input.bypass_permissions.value),
    )?;
    if input.operator_egress_allow.is_some() || input.project_egress_allow.is_some() {
        operator_one(
            builder,
            "egress_allow",
            text_list(input.operator_egress_allow.unwrap_or_default()),
        )?;
    }
    add_compaction_constraints(builder, input)?;
    upper(
        builder,
        "instruction_discovery_render",
        "total_bytes",
        ExternalCeiling::ToolBudget,
        int(i64u(
            iteron_ctx::InstructionDiscoveryPolicy::owner().total_bytes,
            "instruction_discovery_render",
        )?),
    )?;
    if let Some(requested) = input.verify_command {
        operator_one(builder, "verify_command", text(requested))?;
        if let Some(planned) = input.verifier_plan_command {
            domain_min(
                builder,
                "verify_command",
                "$",
                ExternalCeiling::VerificationFloor,
                text(planned),
            )?;
        } else {
            report.gaps.push(CoreFactGap::VerificationPlanAbsent);
        }
    }
    upper(
        builder,
        "retry_backoff_base",
        "$",
        ExternalCeiling::ParentWall,
        int(i64v(
            input.budget.max_wall_secs.saturating_mul(1_000),
            "wall_ms",
        )?),
    )?;
    upper(
        builder,
        "retry_backoff_cap",
        "$",
        ExternalCeiling::ParentWall,
        int(i64v(
            input.budget.max_wall_secs.saturating_mul(1_000),
            "wall_ms",
        )?),
    )?;
    upper(
        builder,
        "retry_max_attempts",
        "$",
        ExternalCeiling::RunBudget,
        int(input.budget.max_consecutive_tool_errors.into()),
    )?;
    operator_one(builder, "orchestration_map", orchestration_map())?;
    if route
        .capabilities
        .contains(&CapabilityRequirement::ProviderPromptCache)
    {
        domain_many(
            builder,
            "prompt_cache",
            "$",
            ExternalCeiling::ProviderCapability,
            [boolv(false), boolv(true)],
        )?;
    } else {
        domain_one(
            builder,
            "prompt_cache",
            "$",
            ExternalCeiling::ProviderCapability,
            boolv(false),
        )?;
    }
    // Retaining the original transcript is the complete fail-safe domain even when the selected
    // route cannot attest a model window. Unknown metadata must not make this fixed policy
    // unresolved or silently permit a truncating failure mode.
    domain_one(
        builder,
        "compaction_failure",
        "$",
        ExternalCeiling::ContextWindow,
        en("retain_original"),
    )?;
    domain_many(
        builder,
        "memory_enable",
        "$",
        ExternalCeiling::TenantScope,
        if input.tenant_allows_memory {
            vec![boolv(false), boolv(true)]
        } else {
            vec![boolv(false)]
        },
    )?;
    upper(
        builder,
        "max_consecutive_tool_errors",
        "$",
        ExternalCeiling::RunBudget,
        int(input.budget.max_consecutive_tool_errors.into()),
    )?;
    Ok(())
}

fn add_token_constraints(
    builder: &mut RuntimeResolutionBuilder,
    input: &CoreFactsInput<'_>,
    report: &mut CoreFactsReport,
) -> Result<(), CoreFactError> {
    let cap = input
        .budget
        .max_tokens
        .map(|tokens| i64v(tokens, "parent_tokens"))
        .transpose()?;
    if let Some(cap) = cap {
        upper(
            builder,
            "max_tokens",
            "$",
            ExternalCeiling::ParentTokens,
            int(cap),
        )?;
    }
    // Compaction is a local context operation. Parent tokens bound both its output and its local
    // reasoning effort; provider reasoning capability only controls outbound serialization.
    let parent_token_ceiling = cap.unwrap_or(iteron_tunables::param_integer(
        "cli.runtime_tunables.core_facts.constraints.unbounded_parent_token_ceiling",
        UNBOUNDED_PARENT_TOKEN_CEILING,
    ));
    upper(
        builder,
        "summary_profile",
        "max_output_tokens",
        ExternalCeiling::ParentTokens,
        int(parent_token_ceiling),
    )?;
    domain_many(
        builder,
        "summary_profile",
        "effort",
        ExternalCeiling::ParentTokens,
        Effort::ALL
            .into_iter()
            .filter(|effort| i64::from(effort.thinking_budget()) <= parent_token_ceiling)
            .map(|effort| en(effort.label())),
    )?;
    // An absent aggregate parent-token budget means unbounded authority, not missing authority.
    // Family 19 is still bounded by its own schema and provider/request envelope, so publish that
    // complete domain rather than leaving an always-active fixed family unresolved.
    upper(
        builder,
        "request_output_cap",
        "$",
        ExternalCeiling::ParentTokens,
        int(parent_token_ceiling),
    )?;
    if input
        .budget
        .max_tokens
        .is_none_or(|tokens| tokens >= u64::from(Effort::Ultracode.thinking_budget()))
    {
        domain_one(
            builder,
            "thinking_map",
            "$",
            ExternalCeiling::ParentTokens,
            thinking_map(),
        )?;
    } else {
        report
            .gaps
            .push(CoreFactGap::ParentTokenCeilingBelowThinkingMap);
    }
    Ok(())
}

fn add_compaction_constraints(
    builder: &mut RuntimeResolutionBuilder,
    input: &CoreFactsInput<'_>,
) -> Result<(), CoreFactError> {
    let output_reserve = super::model_output_reserve(input);
    // With no provider window, the executable context decoder uses exactly the fixed compaction
    // fallback plus family-19's output reserve as its synthetic usable window. Bind every fixed
    // context policy to that same owner value instead of leaving an active family unresolved.
    let context_ceiling = super::compaction_context_ceiling(input);
    let context_ceiling_value = int(i64v(context_ceiling, "context_window")?);
    upper(
        builder,
        "compaction_trigger",
        "fallback_trigger_tokens",
        ExternalCeiling::ContextWindow,
        context_ceiling_value.clone(),
    )?;
    upper(
        builder,
        "compaction_adaptive",
        "output_reserve_tokens",
        ExternalCeiling::ContextWindow,
        context_ceiling_value.clone(),
    )?;
    upper(
        builder,
        "compaction_keep_recent",
        "$",
        ExternalCeiling::ContextWindow,
        context_ceiling_value,
    )?;
    // With unknown metadata, the canonical family-19 fallback is the conservative request
    // envelope. With attested metadata, that live value may only narrow the envelope. Both
    // compaction reserve and the actual request cap consume the same pinned value.
    domain_max(
        builder,
        "compaction_trigger",
        "output_reserve_tokens",
        ExternalCeiling::ProviderCapability,
        int(i64v(output_reserve, "request_output_cap")?),
    )?;
    domain_max(
        builder,
        "request_output_cap",
        "$",
        ExternalCeiling::ProviderCapability,
        int(i64v(output_reserve, "request_output_cap")?),
    )?;
    let materialization = iteron_ctx::ContextMaterializationPolicy::default();
    let materialization_ceiling = int(i64::from(materialization.max_bytes));
    upper(
        builder,
        "memory_budgets",
        "total_bytes",
        ExternalCeiling::ContextWindow,
        materialization_ceiling.clone(),
    )?;
    upper(
        builder,
        "skill_listing_budget",
        "$",
        ExternalCeiling::ContextWindow,
        materialization_ceiling,
    )?;
    Ok(())
}
