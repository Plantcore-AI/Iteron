#[path = "constraints/child.rs"]
mod child;
#[path = "constraints/mcp.rs"]
mod mcp;
#[path = "constraints/orchestration.rs"]
mod orchestration;
#[path = "constraints/session.rs"]
mod session;

use super::value::{domain, lower, upper};
use super::{
    ExtensionFactError, ExtensionFactsInput, ExtensionFactsReport, ExtensionGapReason, FactLayer,
    GapImpact,
};
use iteron_tunables::{ExternalCeiling, ResolutionValue, RuntimeResolutionBuilder};

pub(super) fn apply(
    builder: &mut RuntimeResolutionBuilder,
    input: &ExtensionFactsInput<'_>,
    report: &mut ExtensionFactsReport,
) -> Result<(), ExtensionFactError> {
    provider_governor(builder, input, report)?;
    child::apply(builder, input, report)?;
    orchestration::apply(builder, input, report)?;
    mcp::apply(builder, input, report)?;
    session::apply(builder, input, report)?;
    Ok(())
}

fn provider_governor(
    builder: &mut RuntimeResolutionBuilder,
    input: &ExtensionFactsInput<'_>,
    report: &mut ExtensionFactsReport,
) -> Result<(), ExtensionFactError> {
    let controls = input.provider_governor.controls;
    add_domain(
        builder,
        report,
        155,
        "request_compression_policy",
        "$",
        ExternalCeiling::ProviderCapability,
        input
            .provider_control_capabilities
            .compression
            .iter()
            .map(|value| super::value::en(value.label())),
    )?;

    let rate = input.provider_governor.policy.rate_admission;
    add_domain(
        builder,
        report,
        157,
        "rate_limit_aware_admission",
        "minimum_remaining_requests",
        ExternalCeiling::ProviderCapability,
        [super::value::int(super::value::i64v(
            rate.minimum_remaining_requests,
            "rate_limit_aware_admission",
        )?)],
    )?;
    add_upper(
        builder,
        report,
        157,
        "rate_limit_aware_admission",
        "reset_wait_max_seconds",
        ExternalCeiling::ParentWall,
        super::value::int(super::value::i64v(
            input.budget.max_wall_secs.min(86_400),
            "rate_limit_aware_admission",
        )?),
    )?;

    let cache = controls.prompt_cache;
    let cache_value = super::value::object([
        (
            "ttl_seconds",
            super::value::int(i64::from(cache.ttl_seconds)),
        ),
        ("breakpoint", super::value::en(cache.breakpoint.label())),
        (
            "invalidate_on_tool_change",
            super::value::boolv(cache.invalidate_on_tool_change),
        ),
        ("scope", super::value::en(cache.scope.label())),
    ]);
    add_domain(
        builder,
        report,
        158,
        "prompt_cache_ttl_breakpoint_strategy",
        "$",
        ExternalCeiling::ProviderCapability,
        [cache_value],
    )?;
    add_domain(
        builder,
        report,
        158,
        "prompt_cache_ttl_breakpoint_strategy",
        "scope",
        ExternalCeiling::TenantScope,
        [super::value::en(cache.scope.label())],
    )?;
    Ok(())
}

pub(super) fn add_upper(
    builder: &mut RuntimeResolutionBuilder,
    report: &mut ExtensionFactsReport,
    ordinal: u16,
    family: &'static str,
    field: &'static str,
    ceiling: ExternalCeiling,
    value: ResolutionValue,
) -> Result<(), ExtensionFactError> {
    upper(builder, family, field, ceiling, value)?;
    report.mark(ordinal, family, FactLayer::Constraint { field, ceiling });
    Ok(())
}

pub(super) fn add_domain(
    builder: &mut RuntimeResolutionBuilder,
    report: &mut ExtensionFactsReport,
    ordinal: u16,
    family: &'static str,
    field: &'static str,
    ceiling: ExternalCeiling,
    allowed: impl IntoIterator<Item = ResolutionValue>,
) -> Result<(), ExtensionFactError> {
    domain(builder, family, field, ceiling, allowed)?;
    report.mark(ordinal, family, FactLayer::Constraint { field, ceiling });
    Ok(())
}

pub(super) fn add_lower(
    builder: &mut RuntimeResolutionBuilder,
    report: &mut ExtensionFactsReport,
    ordinal: u16,
    family: &'static str,
    field: &'static str,
    ceiling: ExternalCeiling,
    value: ResolutionValue,
) -> Result<(), ExtensionFactError> {
    lower(builder, family, field, ceiling, value)?;
    report.mark(ordinal, family, FactLayer::Constraint { field, ceiling });
    Ok(())
}

pub(super) fn missing_authority(
    report: &mut ExtensionFactsReport,
    ordinal: u16,
    family: &'static str,
    field: &'static str,
    ceiling: ExternalCeiling,
) {
    gap_constraint(
        report,
        ordinal,
        family,
        field,
        ceiling,
        ExtensionGapReason::IndependentAuthorityMissing,
        GapImpact::Blocking,
    );
}

pub(super) fn gap_constraint(
    report: &mut ExtensionFactsReport,
    ordinal: u16,
    family: &'static str,
    field: &'static str,
    ceiling: ExternalCeiling,
    reason: ExtensionGapReason,
    impact: GapImpact,
) {
    report.gap(
        ordinal,
        family,
        FactLayer::Constraint { field, ceiling },
        reason,
        impact,
    );
}
