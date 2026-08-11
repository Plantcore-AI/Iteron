//! Production-owner facts for tunable ordinals 133 through 160.
//!
//! These families sit at three boundaries where a plausible scalar is especially dangerous:
//! child overlays, MCP transport instances, and durable replay. The adapter accepts the effective
//! owner observations, keeps authority domains independent, and reports typed gaps whenever the
//! canonical schema collapses distinctions made by production.

#![allow(
    dead_code,
    reason = "the adapter is compiled before the composition root starts consuming its report"
)]

#[path = "extension_facts/activation.rs"]
mod activation;
#[path = "extension_facts/constraints.rs"]
mod constraints;
#[path = "extension_facts/owner.rs"]
mod owner;
#[path = "extension_facts/types.rs"]
mod types;
#[path = "extension_facts/value.rs"]
mod value;
#[path = "extension_facts/values.rs"]
mod values;

pub(crate) use types::*;

use crate::config::McpServerConfig;
use crate::providers::ModelCapabilities;
use iteron_protocol::Budget;
use iteron_tools::Registry;
use iteron_tunables::{RouteCapabilities, RuntimeResolutionBuilder};
use iteron_workflow::RunLimits;
use owner::OwnerSnapshot;

pub(crate) const FIRST_EXTENSION_ORDINAL: u16 = 133;
pub(crate) const LAST_EXTENSION_ORDINAL: u16 = 160;

/// Exact composition-root facts sampled before the immutable tunables checkpoint is resolved.
/// `route` and `model_capabilities` must describe the child route when `child_overlay` is present;
/// a parent-route attestation must never be reused for a routed child.
pub(crate) struct ExtensionFactsInput<'a> {
    pub route: &'a RouteCapabilities,
    pub model_capabilities: &'a ModelCapabilities,
    pub budget: &'a Budget,
    pub registry: &'a Registry,
    pub run_limits: RunLimits,
    pub session_spawn_ledger: &'a crate::runtime::SessionSpawnLedger,
    pub child_overlay: Option<&'a ChildOverlayObservation>,
    pub configured_mcp: &'a [McpServerConfig],
    pub mcp_reconnect: iteron_mcp::reconnect::ReconnectPolicy,
    pub mcp_deadlines: iteron_mcp::McpDeadlinePolicy,
    pub mcp_result_policy: iteron_mcp::McpResultPolicy,
    pub early_stop_quorum: iteron_workflow::EarlyStopQuorumPolicy,
    pub speculative_siblings: iteron_workflow::SpeculativeSiblingPolicy,
    pub task_retry: iteron_workflow::TaskRetryPolicy,
    pub writer_merge: iteron_workflow::WriterMergePolicy,
    pub session_profile: SessionIsolationProfile,
    pub replay_owner: ReplayOwnerObservation,
    pub provider_governor: &'a crate::config::ResolvedProviderGovernorConfig,
    pub provider_governor_configured: bool,
    pub provider_control_capabilities: &'a iteron_provider::ProviderControlCapabilities,
    pub authorities: ExtensionAuthorityFacts<'a>,
}

/// Add all representable facts for 133..=160. Success means the evidence was well formed and
/// accepted by the builder; callers must also require `!report.is_resolution_blocked()` before
/// describing the checkpoint as resolved.
pub(crate) fn apply_extension_facts(
    builder: &mut RuntimeResolutionBuilder,
    input: ExtensionFactsInput<'_>,
) -> Result<ExtensionFactsReport, ExtensionFactError> {
    validate_input(&input)?;
    let owner = OwnerSnapshot::capture(&input)?;
    let mut report = ExtensionFactsReport::default();

    record_unavailable_families(&owner, &mut report);
    values::apply(builder, &input, &mut report)?;
    constraints::apply(builder, &input, &mut report)?;
    activation::apply(builder, &input, &owner, &mut report)?;
    report.finish();
    Ok(report)
}

fn validate_input(input: &ExtensionFactsInput<'_>) -> Result<(), ExtensionFactError> {
    input
        .budget
        .validate()
        .map_err(|_| ExtensionFactError::InvalidBudget)?;
    let Some(child) = input.child_overlay else {
        return Ok(());
    };
    if child.provider_id != input.route.route.provider_id
        || child.model_id != input.route.route.model_id
    {
        return Err(ExtensionFactError::ChildRouteIdentityMismatch);
    }
    let valid_name = |value: &str| {
        !value.is_empty()
            && value.len() <= 96
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/')
            })
    };
    if !valid_name(&child.agent_name)
        || child.tool_profile.len() > 256
        || child.tool_profile.keys().any(|key| !valid_name(key))
        || child
            .memory_scope
            .as_ref()
            .and_then(|scope| scope.scope_id.as_deref())
            .is_some_and(|scope_id| !valid_name(scope_id))
    {
        return Err(ExtensionFactError::InvalidChildOverlay);
    }
    Ok(())
}

const UNAVAILABLE: &[(u16, &str)] = &[];

fn record_unavailable_families(_owner: &OwnerSnapshot, report: &mut ExtensionFactsReport) {
    for &(ordinal, family) in UNAVAILABLE {
        report.gap(
            ordinal,
            family,
            FactLayer::Implementation,
            ExtensionGapReason::RegistryUnavailable,
            GapImpact::Unavailable,
        );
    }
}
