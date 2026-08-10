use super::*;

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
    if route
        .capabilities
        .contains(&CapabilityRequirement::ProviderReasoningControl)
    {
        domain_many(
            builder,
            "effort",
            "$",
            ExternalCeiling::ProviderCapability,
            Effort::ALL.into_iter().map(|e| en(e.label())),
        )?;
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
        domain_many(
            builder,
            "summary_profile",
            "effort",
            ExternalCeiling::ProviderCapability,
            Effort::ALL.into_iter().map(|e| en(e.label())),
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
    add_compaction_constraints(builder, input, report)?;
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
        report
            .gaps
            .push(CoreFactGap::PromptCacheCapabilityUnattested);
    }
    if input.model_capabilities.context_window_tokens.is_some() {
        domain_one(
            builder,
            "compaction_failure",
            "$",
            ExternalCeiling::ContextWindow,
            en("retain_original"),
        )?;
    } else {
        report.gaps.push(CoreFactGap::ContextWindowUnknown);
    }
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
    let Some(tokens) = input.budget.max_tokens else {
        report.gaps.push(CoreFactGap::ParentTokenCeilingAbsent);
        return Ok(());
    };
    let cap = int(i64v(tokens, "parent_tokens")?);
    upper(
        builder,
        "max_tokens",
        "$",
        ExternalCeiling::ParentTokens,
        cap.clone(),
    )?;
    upper(
        builder,
        "request_output_cap",
        "$",
        ExternalCeiling::ParentTokens,
        cap.clone(),
    )?;
    upper(
        builder,
        "summary_profile",
        "max_output_tokens",
        ExternalCeiling::ParentTokens,
        cap,
    )?;
    if tokens >= u64::from(Effort::Ultracode.thinking_budget()) {
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
    report: &mut CoreFactsReport,
) -> Result<(), CoreFactError> {
    if let Some(window) = input.model_capabilities.context_window_tokens {
        upper(
            builder,
            "compaction_trigger",
            "fallback_trigger_tokens",
            ExternalCeiling::ContextWindow,
            int(i64v(window, "context_window")?),
        )?;
        upper(
            builder,
            "compaction_adaptive",
            "output_reserve_tokens",
            ExternalCeiling::ContextWindow,
            int(i64v(window, "context_window")?),
        )?;
    }
    if let Some(output) = input.model_capabilities.max_output_tokens {
        domain_max(
            builder,
            "compaction_trigger",
            "output_reserve_tokens",
            ExternalCeiling::ProviderCapability,
            int(output.into()),
        )?;
        domain_max(
            builder,
            "request_output_cap",
            "$",
            ExternalCeiling::ProviderCapability,
            int(output.into()),
        )?;
    }
    // A token window does not itself attest byte or message ceilings. These remain unresolved
    // until the context owner exposes typed projections instead of silently mixing units.
    report.gaps.extend([
        CoreFactGap::ContextByteCeilingNotOwned,
        CoreFactGap::ContextMessageCeilingNotOwned,
    ]);
    Ok(())
}
