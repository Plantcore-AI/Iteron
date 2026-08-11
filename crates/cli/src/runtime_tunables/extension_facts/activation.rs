use super::owner::OwnerSnapshot;
use super::{
    AgentMemoryMode, ExtensionFactError, ExtensionFactsInput, ExtensionFactsReport,
    ExtensionGapReason, FactLayer, GapImpact,
};
use iteron_tunables::{CapabilityRequirement, RuntimeResolutionBuilder};

pub(super) fn apply(
    builder: &mut RuntimeResolutionBuilder,
    input: &ExtensionFactsInput<'_>,
    owner: &OwnerSnapshot,
    report: &mut ExtensionFactsReport,
) -> Result<(), ExtensionFactError> {
    add_memory_activation(builder, input, owner, report)?;

    for (ordinal, family, seam) in [
        (
            155,
            "request_compression_policy",
            "crates/provider/src/controls.rs",
        ),
        (
            157,
            "rate_limit_aware_admission",
            "crates/provider/src/governor.rs",
        ),
        (
            158,
            "prompt_cache_ttl_breakpoint_strategy",
            "crates/provider/src/controls.rs",
        ),
    ] {
        observed(builder, owner, report, ordinal, family, seam, true)?;
    }

    observed(
        builder,
        owner,
        report,
        134,
        "per_agent_effort_thinking",
        "crates/cli/src/runtime/workflow_spawner.rs",
        owner.collaboration_active() && input.model_capabilities.semantic_effort == Some(true),
    )?;

    observed(
        builder,
        owner,
        report,
        138,
        "per_session_spawn_cap",
        "crates/workflow/src/lib.rs",
        owner.collaboration_active(),
    )?;
    observed(
        builder,
        owner,
        report,
        142,
        "early_stop_quorum_policy",
        "crates/workflow/src/quorum.rs",
        owner.collaboration_active(),
    )?;
    for (ordinal, family, seam) in [
        (
            140,
            "speculative_sibling_count",
            "crates/workflow/src/bindings.rs",
        ),
        (
            141,
            "speculative_sibling_cancellation",
            "crates/workflow/src/bindings.rs",
        ),
        (
            146,
            "task_retry_reassignment_policy",
            "crates/workflow/src/bindings.rs",
        ),
    ] {
        observed(
            builder,
            owner,
            report,
            ordinal,
            family,
            seam,
            owner.collaboration_active(),
        )?;
    }

    observed(
        builder,
        owner,
        report,
        148,
        "deferred_discovery_threshold",
        "crates/tools/src/tool_search.rs",
        owner.tool_search_surface(),
    )?;

    observed(
        builder,
        owner,
        report,
        149,
        "mcp_reconnect_backoff",
        "crates/cli/src/mcp.rs",
        owner.configured_mcp(),
    )?;

    observed(
        builder,
        owner,
        report,
        152,
        "mcp_result_cap_spill_policy",
        "crates/mcp/src/client/content.rs",
        owner.live_mcp(),
    )?;

    observed(
        builder,
        owner,
        report,
        154,
        "resource_prompt_plugin_capability_exposure",
        "crates/cli/src/mcp.rs",
        owner.resource_prompt_surface(),
    )?;

    observed(
        builder,
        owner,
        report,
        159,
        "session_isolation_profile",
        "crates/cli/src/session_isolation.rs",
        true,
    )?;
    Ok(())
}

fn add_memory_activation(
    builder: &mut RuntimeResolutionBuilder,
    input: &ExtensionFactsInput<'_>,
    owner: &OwnerSnapshot,
    report: &mut ExtensionFactsReport,
) -> Result<(), ExtensionFactError> {
    let observed_scope = input
        .child_overlay
        .and_then(|child| child.memory_scope.as_ref());
    let capabilities = &input.route.capabilities;
    // An isolated child has no memory workspace attached by `KernelSpawner::build_child`; the
    // family is therefore observed but inactive. Shared modes are active only when both the child
    // launch surface and read/write memory authority are attested for that exact route.
    let requests_shared_memory =
        observed_scope.is_some_and(|scope| scope.mode != AgentMemoryMode::Isolated);
    let capable = capabilities.contains(&CapabilityRequirement::AgentSpawn)
        && capabilities.contains(&CapabilityRequirement::MemoryReadWrite);
    let active = requests_shared_memory && capable;
    observed(
        builder,
        owner,
        report,
        136,
        "per_agent_memory_scope",
        "crates/cli/src/runtime/workflow_spawner.rs",
        active,
    )?;
    if requests_shared_memory && !capable {
        report.gap(
            136,
            "per_agent_memory_scope",
            FactLayer::Activation,
            ExtensionGapReason::CapabilityNotAttested,
            GapImpact::Blocking,
        );
    } else if observed_scope.is_none() {
        report.gap(
            136,
            "per_agent_memory_scope",
            FactLayer::Activation,
            ExtensionGapReason::RequiredOwnerObservationMissing,
            if owner.collaboration_active() {
                GapImpact::Blocking
            } else {
                GapImpact::Inactive
            },
        );
    }
    Ok(())
}

fn observed(
    builder: &mut RuntimeResolutionBuilder,
    owner: &OwnerSnapshot,
    report: &mut ExtensionFactsReport,
    ordinal: u16,
    family: &'static str,
    seam: &'static str,
    active: bool,
) -> Result<(), ExtensionFactError> {
    builder.activate(
        family,
        seam,
        active,
        owner.digest_for(family, if active { "active" } else { "inactive" })?,
    )?;
    report.mark(ordinal, family, FactLayer::Activation);
    Ok(())
}
