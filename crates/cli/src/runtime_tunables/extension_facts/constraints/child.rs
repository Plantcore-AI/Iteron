use super::{add_domain, gap_constraint, missing_authority};
use crate::runtime_tunables::extension_facts::value::{en, text, tool_profile};
use crate::runtime_tunables::extension_facts::{
    ExtensionFactError, ExtensionFactsInput, ExtensionFactsReport, ExtensionGapReason, GapImpact,
};
use core_protocol::Effort;
use core_tunables::{CapabilityRequirement, ExternalCeiling, RuntimeResolutionBuilder};

pub(super) fn apply(
    builder: &mut RuntimeResolutionBuilder,
    input: &ExtensionFactsInput<'_>,
    report: &mut ExtensionFactsReport,
) -> Result<(), ExtensionFactError> {
    let route = format!(
        "{}:{}",
        input.route.route.provider_id, input.route.route.model_id
    );
    let capabilities = &input.route.capabilities;
    if capabilities.contains(&CapabilityRequirement::ProviderCatalog)
        && capabilities.contains(&CapabilityRequirement::AgentSpawn)
    {
        add_domain(
            builder,
            report,
            133,
            "per_agent_model",
            "$",
            ExternalCeiling::ProviderCapability,
            [en(&route)],
        )?;
    } else {
        gap_constraint(
            report,
            133,
            "per_agent_model",
            "$",
            ExternalCeiling::ProviderCapability,
            ExtensionGapReason::CapabilityNotAttested,
            GapImpact::Blocking,
        );
    }
    match input.authorities.parent_cost_model_routes {
        Some(routes) => add_domain(
            builder,
            report,
            133,
            "per_agent_model",
            "$",
            ExternalCeiling::ParentCost,
            routes.iter().map(|route| en(route)),
        )?,
        None => missing_authority(
            report,
            133,
            "per_agent_model",
            "$",
            ExternalCeiling::ParentCost,
        ),
    }

    let effort_active = capabilities.contains(&CapabilityRequirement::ProviderReasoningControl)
        && capabilities.contains(&CapabilityRequirement::AgentSpawn)
        && input.model_capabilities.semantic_effort == Some(true);
    if effort_active {
        add_domain(
            builder,
            report,
            134,
            "per_agent_effort_thinking",
            "$",
            ExternalCeiling::ProviderCapability,
            Effort::ALL.into_iter().map(|effort| en(effort.label())),
        )?;
        add_domain(
            builder,
            report,
            134,
            "per_agent_effort_thinking",
            "$",
            ExternalCeiling::ParentTokens,
            Effort::ALL
                .into_iter()
                .filter(|effort| {
                    input
                        .budget
                        .max_tokens
                        .is_none_or(|tokens| u64::from(effort.thinking_budget()) <= tokens)
                })
                .map(|effort| en(effort.label())),
        )?;
    }

    match input.authorities.operator_tool_profiles {
        Some(profiles) => add_domain(
            builder,
            report,
            135,
            "per_agent_tool_profile",
            "$",
            ExternalCeiling::OperatorAuthority,
            profiles.iter().map(tool_profile),
        )?,
        None => missing_authority(
            report,
            135,
            "per_agent_tool_profile",
            "$",
            ExternalCeiling::OperatorAuthority,
        ),
    }

    if let Some(scope_id) = input
        .child_overlay
        .and_then(|child| child.memory_scope.as_ref())
        .and_then(|scope| scope.scope_id.as_deref())
    {
        match input.authorities.tenant_memory_scope_ids {
            Some(ids) => add_domain(
                builder,
                report,
                136,
                "per_agent_memory_scope",
                "scope_id",
                ExternalCeiling::TenantScope,
                ids.iter().map(|id| text(id)),
            )?,
            None => missing_authority(
                report,
                136,
                "per_agent_memory_scope",
                "scope_id",
                ExternalCeiling::TenantScope,
            ),
        }
        debug_assert!(!scope_id.is_empty());
    }
    Ok(())
}
