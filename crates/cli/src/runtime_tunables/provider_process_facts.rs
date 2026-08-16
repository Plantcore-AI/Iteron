//! Production-owner facts for tunable ordinals 86 through 132.
//!
//! This adapter is intentionally strict about the difference between an implemented runtime
//! surface and a value that satisfies the registry schema. Provider health, for example, is a
//! real typed owner, but it does not expose circuit-breaker thresholds. Likewise, an image decoder
//! is not a binary-inspector routing table. Such mismatches produce typed gaps and inactive
//! activation evidence; they never become zeroes, empty collections, or candidate-authored facts.

#![allow(
    dead_code,
    reason = "the adapter is compiled before the composition root starts consuming its report"
)]

#[path = "provider_process_facts/constraints.rs"]
mod constraints;
#[path = "provider_process_facts/defaults.rs"]
mod defaults;
#[path = "provider_process_facts/fixed.rs"]
mod fixed;
#[path = "provider_process_facts/owner.rs"]
mod owner;
#[path = "provider_process_facts/types.rs"]
mod types;
#[path = "provider_process_facts/value.rs"]
mod value;

pub(crate) use defaults::failure_classification_catalog_value;
pub(crate) use fixed::live_fixed_authority_samples;
pub(crate) use types::*;

use crate::providers::{ModelCapabilities, ModelSelection, ProviderDirectory};
use iteron_ctx::CompactionPolicy;
use iteron_protocol::Budget;
use iteron_tools::Registry;
use iteron_tunables::{
    CapabilityRequirement, ProductionOwnerSymbolId, RouteCapabilities, RuntimeResolutionBuilder,
};
use iteron_verify::{VerifierPlan, VerifierSlotObservation};
use owner::OwnerSnapshot;
use std::path::Path;

/// Exact context owner projection shared by value and constraint collection. `actual_window` is
/// provider-attested; `execution_window` is the conservative local ceiling used when metadata is
/// unknown and matches `EffectiveCore`'s compaction-trigger + family-19 fallback byte-for-byte.
pub(super) fn context_owner_window(
    input: &ProviderProcessFactsInput<'_>,
) -> Result<(Option<usize>, usize, u32), ProviderProcessFactError> {
    let actual_window = input
        .model_capabilities
        .context_window_tokens
        .filter(|window| *window > 0)
        .and_then(|window| usize::try_from(window.min(10_000_000)).ok());
    let output_reserve = input
        .model_capabilities
        .max_output_tokens
        .unwrap_or(super::core_facts::UNKNOWN_MODEL_OUTPUT_TOKENS);
    let output_reserve_usize = usize::try_from(output_reserve)
        .map_err(|_| ProviderProcessFactError::IntegerOverflow("max_output_tokens"))?;
    let execution_window = actual_window.unwrap_or_else(|| {
        input
            .compaction
            .trigger_tokens
            .saturating_add(output_reserve_usize)
            .min(10_000_000)
    });
    Ok((actual_window, execution_window, output_reserve))
}

/// Verification facts already chosen by the verifier owner. Absence and inability to query the
/// owner are separate states; neither is projected as an empty command list.
#[derive(Debug, Clone, Copy)]
pub(crate) enum VerificationOwnerFacts<'a> {
    Configured {
        command: &'a str,
        floor: &'a VerifierSlotObservation,
        plan: &'a VerifierPlan,
    },
    Disabled,
    GetterUnavailable,
}

pub(crate) struct ProviderProcessFactsInput<'a> {
    pub agent_catalog: &'a iteron_agents::AgentCatalog,
    pub directory: &'a ProviderDirectory,
    pub selection: &'a ModelSelection,
    pub model_capabilities: &'a ModelCapabilities,
    pub route: &'a RouteCapabilities,
    pub budget: &'a Budget,
    pub compaction: &'a CompactionPolicy,
    pub registry: &'a Registry,
    pub workspace: &'a Path,
    pub verification: VerificationOwnerFacts<'a>,
    pub verification_policy: &'a iteron_verify::VerificationRuntimePolicy,
    /// Presence means this policy came from trusted user configuration. The shared project config
    /// is never passed through this seam.
    pub verification_config: Option<&'a crate::config::VerificationConfig>,
    pub provider_governor: &'a crate::config::ResolvedProviderGovernorConfig,
    pub provider_governor_configured: bool,
    pub provider_control_capabilities: &'a iteron_provider::ProviderControlCapabilities,
    pub binary_media_policy: &'a crate::image_input::BinaryMediaInspectionPolicy,
}

/// Add every representable owner fact for ordinals 86..=132. A successful return means the facts
/// were well-formed and accepted by the builder, not that every family resolved: `report.gaps`
/// remains the authoritative inventory of missing owners and schema mismatches.
pub(crate) fn apply_provider_process_facts(
    builder: &mut RuntimeResolutionBuilder,
    input: ProviderProcessFactsInput<'_>,
) -> Result<ProviderProcessFactsReport, ProviderProcessFactError> {
    validate_input(&input)?;
    let owner = OwnerSnapshot::capture(&input)?;
    let mut report = ProviderProcessFactsReport::default();

    record_registry_unavailable(&owner, &mut report);
    defaults::apply(builder, &input, &owner, &mut report)?;
    constraints::apply(builder, &input, &mut report)?;
    submit_owner_symbols(builder)?;
    Ok(report)
}

fn submit_owner_symbols(
    builder: &mut RuntimeResolutionBuilder,
) -> Result<(), ProviderProcessFactError> {
    use ProductionOwnerSymbolId as Owner;
    for (owner, families) in [
        (
            Owner::ProviderGovernor,
            &[
                "model_fallback_chain",
                "failover_eligible_error_taxonomy",
                "route_quality_cost_latency_objective_weights",
                "provider_health_circuit_breaker_state_policy",
                "hedged_request_policy",
                "provider_service_tier",
                "response_verbosity",
            ][..],
        ),
        (Owner::AgentOverlayPolicy, &["role_specific_model_map"][..]),
        (
            Owner::ContextMaterializationPolicy,
            &[
                "context_window_override_reserve",
                "system_prefix_budget",
                "conversation_history_budget",
                "tool_result_history_budget",
                "multimodal_token_budget",
                "context_novelty_dedup_threshold",
                "lsp_result_context_budget",
            ][..],
        ),
        (
            Owner::CompactionPolicy,
            &[
                "compaction_cooldown_hysteresis",
                "multi_stage_summary_topology",
                "summary_consistency_coverage_check",
            ][..],
        ),
        (
            Owner::VerificationPolicy,
            &[
                "test_selection_strategy",
                "incremental_versus_full_verification",
                "flaky_test_detection_quarantine",
                "rollback_on_verification_failure",
                "workspace_checkpoint_cadence",
                "selective_restore_scope",
                "verification_quorum_consensus",
                "retry_eligibility_policy",
            ][..],
        ),
        (
            Owner::MemoryPolicy,
            &["hybrid_retrieval_fusion_weights", "retrieval_recency_decay"][..],
        ),
        (
            Owner::ProcessRuntimePolicy,
            &[
                "persistent_pty_backend",
                "concurrent_background_job_cap",
                "job_idle_stall_timeout",
                "interactive_stdin_wait_policy",
                "process_cwd_continuity",
                "child_process_environment_reuse",
                "tool_output_spill_to_disk_policy",
                "tool_result_cache_ttl",
            ][..],
        ),
        (
            Owner::BinaryMediaPolicy,
            &["binary_media_inspection_routing"][..],
        ),
        (
            Owner::LspRuntimePolicy,
            &[
                "lsp_server_language_selection",
                "lsp_timeout_restart_policy",
            ][..],
        ),
    ] {
        builder.submit_owner_symbol(owner, families)?;
    }
    Ok(())
}

fn validate_input(input: &ProviderProcessFactsInput<'_>) -> Result<(), ProviderProcessFactError> {
    input
        .budget
        .validate()
        .map_err(|_| ProviderProcessFactError::InvalidBudget)?;
    if input
        .directory
        .entry(&input.selection.provider_id)
        .is_none()
    {
        return Err(ProviderProcessFactError::UnknownProvider);
    }
    if input.directory.selection_capabilities(input.selection) != *input.model_capabilities {
        return Err(ProviderProcessFactError::StaleModelCapabilities);
    }
    if input.route.route.provider_id != input.selection.provider_id
        || input.route.route.model_id != input.selection.model_id
    {
        return Err(ProviderProcessFactError::RouteIdentityMismatch);
    }
    input
        .provider_control_capabilities
        .validate(&input.provider_governor.controls)
        .map_err(|_| ProviderProcessFactError::ProviderControlMismatch)?;
    input
        .verification_policy
        .validate()
        .map_err(|_| ProviderProcessFactError::InvalidVerificationPolicy)?;
    match input.verification {
        VerificationOwnerFacts::Configured { command, floor, .. } => {
            let commands = &input.verification_policy.required_commands;
            if commands.last().map(String::as_str) != Some(command)
                || (input.verification_policy.selection
                    == iteron_verify::VerificationSelectionMode::Full
                    && commands.len() != 1)
                || (input.verification_policy.selection
                    != iteron_verify::VerificationSelectionMode::Full
                    && commands.len() < 2)
                || floor.scope_floor != iteron_verify::VerifierScope::Workspace
            {
                return Err(ProviderProcessFactError::InvalidVerificationPolicy);
            }
        }
        VerificationOwnerFacts::Disabled | VerificationOwnerFacts::GetterUnavailable => {
            if !input.verification_policy.required_commands.is_empty() {
                return Err(ProviderProcessFactError::InvalidVerificationPolicy);
            }
        }
    }
    if !input
        .verification_policy
        .restore
        .require_operator_confirmation
        || u32::from(input.verification_policy.quorum.verifiers) > input.budget.max_turns
        || u32::from(input.verification_policy.flaky.repeat_count) > input.budget.max_turns
    {
        return Err(ProviderProcessFactError::InvalidVerificationPolicy);
    }
    for route in &input.provider_governor.fallback_routes {
        let (provider_id, model_id) = route
            .split_once(':')
            .ok_or(ProviderProcessFactError::InvalidFallbackRoute)?;
        let fallback = ModelSelection {
            provider_id: provider_id.to_owned(),
            model_id: model_id.to_owned(),
        };
        if fallback == *input.selection
            || input.directory.validate_selection(&fallback, true).is_err()
        {
            return Err(ProviderProcessFactError::InvalidFallbackRoute);
        }
    }

    let process = owner::has_process_surface(input.registry);
    let lsp = owner::has_tool(input.registry, "lsp_query");
    let pure_cache = input
        .registry
        .specs()
        .iter()
        .any(|spec| spec.purity == iteron_protocol::Purity::Pure);
    let capabilities = &input.route.capabilities;
    let consistent = capabilities.contains(&CapabilityRequirement::PersistentProcess) == process
        && capabilities.contains(&CapabilityRequirement::LanguageServer) == lsp
        && capabilities.contains(&CapabilityRequirement::ToolResultCache) == pure_cache
        && capabilities.contains(&CapabilityRequirement::ProviderMultimodal)
            == (input.model_capabilities.image_input == Some(true));
    if !consistent {
        return Err(ProviderProcessFactError::StaleRouteCapabilities);
    }
    Ok(())
}

const UNAVAILABLE: &[(u16, &str)] = &[];

fn record_registry_unavailable(owner: &OwnerSnapshot, report: &mut ProviderProcessFactsReport) {
    for &(ordinal, family) in UNAVAILABLE {
        let owner_present = matches!(ordinal, 109..=111) && owner.process_surface
            || matches!(ordinal, 119..=121) && owner.lsp_surface;
        report.unavailable_families.push(family);
        report.push_gap(ProviderProcessFactGap::new(
            ordinal,
            family,
            FactLayer::Implementation,
            if owner_present {
                FactGapReason::RegistryUnavailableOwnerPresent
            } else {
                FactGapReason::RegistryUnavailable
            },
        ));
    }
}
