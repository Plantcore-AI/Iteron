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

#[path = "provider_process_facts/activations.rs"]
mod activations;
#[path = "provider_process_facts/constraints.rs"]
mod constraints;
#[path = "provider_process_facts/defaults.rs"]
mod defaults;
#[path = "provider_process_facts/owner.rs"]
mod owner;
#[path = "provider_process_facts/types.rs"]
mod types;
#[path = "provider_process_facts/value.rs"]
mod value;

pub(crate) use types::*;

use crate::providers::{ModelCapabilities, ModelSelection, ProviderDirectory};
use core_ctx::CompactionPolicy;
use core_protocol::Budget;
use core_tools::Registry;
use core_tunables::{CapabilityRequirement, RouteCapabilities, RuntimeResolutionBuilder};
use core_verify::{VerifierPlan, VerifierSlotObservation};
use owner::OwnerSnapshot;
use std::path::Path;

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
    pub directory: &'a ProviderDirectory,
    pub selection: &'a ModelSelection,
    pub model_capabilities: &'a ModelCapabilities,
    pub route: &'a RouteCapabilities,
    pub budget: &'a Budget,
    pub compaction: &'a CompactionPolicy,
    pub registry: &'a Registry,
    pub workspace: &'a Path,
    pub verification: VerificationOwnerFacts<'a>,
    pub provider_governor: &'a crate::config::ResolvedProviderGovernorConfig,
    pub provider_governor_configured: bool,
    pub provider_control_capabilities: &'a core_provider::ProviderControlCapabilities,
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
    activations::apply(builder, &input, &owner, &mut report)?;
    Ok(report)
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
        .any(|spec| spec.purity == core_protocol::Purity::Pure);
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

const UNAVAILABLE: &[(u16, &str)] = &[(128, "rollback_on_verification_failure")];

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
