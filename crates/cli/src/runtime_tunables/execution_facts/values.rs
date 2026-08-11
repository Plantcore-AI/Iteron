use super::*;

use iteron_protocol::{Capability, Effort};
use iteron_tunables::{DecimalValue, ResolutionValue, SourceKind};
use std::collections::BTreeMap;

pub(super) fn apply(
    builder: &mut RuntimeResolutionBuilder,
    input: &ExecutionFactsInput<'_>,
    report: &mut ExecutionFactsReport,
) -> Result<(), ExecutionFactError> {
    // The scheduler may narrow `max_tool_concurrency`; its effective result has no sibling-module
    // query API. Recording the public product ceiling as the effective value would be false.
    report.gap(
        "pure_concurrency",
        FactStage::Default,
        GapReason::OwnerProjectionNotVisible,
    );

    observe(
        builder,
        report,
        "verifier_attempts",
        int(i64::from(iteron_verify::strategy::MAX_VERIFIER_ATTEMPTS)),
    )?;
    observe(
        builder,
        report,
        "fan_breadth",
        int(i64u(iteron_agents::FAN_CAP, "fan_breadth")?),
    )?;
    observe(
        builder,
        report,
        "worker_min_turns",
        int(i64::from(worker_min_turns()?)),
    )?;
    observe(
        builder,
        report,
        "token_split",
        ResolutionValue::Decimal {
            value: token_split()?,
        },
    )?;
    let limits = iteron_workflow::RunLimits::default();
    observe(
        builder,
        report,
        "fan_concurrency",
        int(i64u(limits.max_concurrency(), "fan_concurrency")?),
    )?;

    let child = iteron_agents::subagent_budget_ceiling();
    let child_capabilities = CapabilitySet::only(Capability::ReadOnly);
    observe(
        builder,
        report,
        "child_ceiling",
        object([
            ("max_turns", int(i64::from(child.max_turns))),
            (
                "max_wall_seconds",
                int(i64v(child.max_wall_secs, "child_ceiling")?),
            ),
            (
                "max_consecutive_errors",
                int(i64::from(child.max_consecutive_tool_errors)),
            ),
            ("capabilities", capability_list(child_capabilities)),
        ]),
    )?;

    report.gap(
        "join_reduce",
        FactStage::Default,
        GapReason::OwnerQueryUnavailable,
    );

    if let Some(prompt) = input.operator_prompt {
        builder.declare(
            "operator_prompt_stream",
            SourceKind::OperatorInput,
            text(prompt),
        )?;
        report.mark("operator_prompt_stream", FactStage::Default);
    }

    record_non_catalog_default_gaps(report);
    Ok(())
}

pub(super) fn record_catalog_and_owner_gaps(
    input: &ExecutionFactsInput<'_>,
    report: &mut ExecutionFactsReport,
) {
    for family in [
        "builtin_prompt_corpus",
        "instruction_bundle",
        "memory_corpus",
        "skill_catalog",
        "agent_catalog",
        "provider_model_capability_catalog",
        "tool_action_space",
        "rate_card_catalog",
        "router_lexicons",
    ] {
        report.gap(
            family,
            FactStage::Default,
            GapReason::GovernedCatalogNotAdmissible,
        );
    }
    if !input.configured_mcp.is_empty() {
        report.gap(
            "mcp_topology_tool_catalog",
            FactStage::Default,
            GapReason::GovernedCatalogNotAdmissible,
        );
    }
    if input.hooks_configured {
        report.gap(
            "hooks_map",
            FactStage::Default,
            GapReason::CatalogResolverValueShapeMismatch,
        );
    }
    report.gap(
        "workflow_graph",
        FactStage::Default,
        GapReason::CatalogResolverValueShapeMismatch,
    );
    report.gap(
        "environment_snapshot",
        FactStage::Default,
        GapReason::OpaqueEnvironmentNotAMap,
    );
    if input.inventory_web_search() {
        report.gap(
            "web_search_backend_catalog",
            FactStage::Inventory,
            GapReason::CredentialFreeWebInventoryUnavailable,
        );
        report.gap(
            "web_search_backend_catalog",
            FactStage::Default,
            GapReason::GovernedCatalogNotAdmissible,
        );
    }
}

fn record_non_catalog_default_gaps(report: &mut ExecutionFactsReport) {
    for (family, reason) in [
        ("pure_overlap", GapReason::OwnerProjectionNotVisible),
        ("failed_action_dedup", GapReason::OwnerProjectionNotVisible),
        ("pure_memo_cache", GapReason::OwnerProjectionNotVisible),
        (
            "shell_timeout_output",
            GapReason::OwnerValueDiffersFromLiteral,
        ),
        ("read_file_limits", GapReason::SchemaCannotExpressOwner),
        ("list_dir_limits", GapReason::SchemaCannotExpressOwner),
        ("glob_limits", GapReason::SchemaCannotExpressOwner),
        ("grep_limits", GapReason::OwnerQueryUnavailable),
        ("repo_map", GapReason::SchemaCannotExpressOwner),
        ("git_limits", GapReason::OwnerQueryUnavailable),
        ("web_fetch_limits", GapReason::SchemaCannotExpressOwner),
        ("web_search_cap", GapReason::OwnerQueryUnavailable),
        (
            "verifier_feedback_tails",
            GapReason::SchemaCannotExpressOwner,
        ),
        ("verifier_timeout", GapReason::OwnerQueryUnavailable),
        ("route_topology", GapReason::DynamicPolicyNotRepresentable),
        ("decomposition_profile", GapReason::OwnerQueryUnavailable),
        ("admission", GapReason::SchemaCannotExpressOwner),
        (
            "writer_fan_turn_split",
            GapReason::DynamicPolicyNotRepresentable,
        ),
        ("wall_split", GapReason::DynamicPolicyNotRepresentable),
        (
            "direct_child_allocation",
            GapReason::SchemaCannotExpressOwner,
        ),
        (
            "subagent_effort_inheritance",
            GapReason::DynamicPolicyNotRepresentable,
        ),
        ("report_budget", GapReason::SchemaCannotExpressOwner),
        ("workflow_aggregate", GapReason::SchemaCannotExpressOwner),
        ("schema_retry_jitter", GapReason::OwnerProjectionNotVisible),
        (
            "multimodal_input_admission_decode_envelope",
            GapReason::OwnerProjectionNotVisible,
        ),
        (
            "provider_discovery_account_probe_cache_policy",
            GapReason::OwnerProjectionNotVisible,
        ),
    ] {
        report.gap(family, FactStage::Default, reason);
    }
}

fn worker_min_turns() -> Result<u32, ExecutionFactError> {
    let ceiling = iteron_agents::subagent_budget_ceiling();
    (1..=ceiling.max_turns.saturating_add(8))
        .find_map(|parent_turns| iteron_agents::subagent_budget(parent_turns, 3, None))
        .map(|budget| budget.max_turns)
        .ok_or(ExecutionFactError::ChildAllocationUnavailable)
}

fn token_split() -> Result<DecimalValue, ExecutionFactError> {
    let observed = iteron_agents::subagent_budget(8, 3, Some(100))
        .and_then(|budget| budget.max_tokens)
        .ok_or(ExecutionFactError::ChildAllocationUnavailable)?;
    Ok(DecimalValue {
        coefficient: i64v(observed, "token_split")?,
        scale: 2,
    })
}

fn observe(
    builder: &mut RuntimeResolutionBuilder,
    report: &mut ExecutionFactsReport,
    family: &'static str,
    value: ResolutionValue,
) -> Result<(), ExecutionFactError> {
    builder.observe_default(family, value)?;
    report.mark(family, FactStage::Default);
    Ok(())
}

pub(super) fn int(value: i64) -> ResolutionValue {
    ResolutionValue::Integer { value }
}

pub(super) fn text(value: &str) -> ResolutionValue {
    ResolutionValue::Text {
        value: value.to_owned(),
    }
}

pub(super) fn en(value: &str) -> ResolutionValue {
    ResolutionValue::Enum {
        value: value.to_owned(),
    }
}

pub(super) fn object<const N: usize>(values: [(&str, ResolutionValue); N]) -> ResolutionValue {
    ResolutionValue::Object {
        fields: values
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect::<BTreeMap<_, _>>(),
    }
}

pub(super) fn capability_list(capabilities: CapabilitySet) -> ResolutionValue {
    ResolutionValue::List {
        items: capabilities
            .iter()
            .map(|capability| {
                text(match capability {
                    Capability::ReadOnly => "read_only",
                    Capability::ReversibleLocal => "reversible_local",
                    Capability::CodeExecuting => "code_executing",
                    Capability::TrustMutating => "trust_mutating",
                    Capability::IrreversibleExternal => "irreversible_external",
                })
            })
            .collect(),
    }
}

impl ExecutionFactsInput<'_> {
    fn inventory_web_search(&self) -> bool {
        self.registry
            .specs()
            .iter()
            .any(|spec| spec.name == "web_search")
    }

    pub(super) fn inherited_effort_domain(&self) -> Vec<ResolutionValue> {
        if self.model_capabilities.semantic_effort == Some(true) {
            Effort::ALL
                .into_iter()
                .map(|effort| en(effort.label()))
                .collect()
        } else {
            vec![en(self.effort.label())]
        }
    }
}
