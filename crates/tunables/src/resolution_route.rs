use crate::resolution_prepare::PreparedInput;
use crate::resolution_types::{EntryOutcome, InactiveCause, RejectionReason, ResolutionValue};
use crate::{Family, ProviderRequirement};

pub(super) fn provider_gate(
    family: &Family,
    prepared: &PreparedInput,
    selected_value: &ResolutionValue,
    explicit: bool,
) -> Option<EntryOutcome> {
    if matches!(family.id, "provider" | "model") && prepared.input.runtime.selected_route.is_none()
    {
        return Some(requirement_failure(
            explicit,
            family.requirements.provider,
            None,
            family.requirements.capabilities.to_vec(),
        ));
    }
    if let Some(expected) = route_identity_value(family.id, prepared)
        && scalar_text(selected_value) != Some(expected)
    {
        return Some(EntryOutcome::Rejected {
            reason: RejectionReason::CrossFieldRule {
                detail_code: if explicit {
                    "explicit_request_route_identity_mismatch"
                } else {
                    "default_route_identity_mismatch"
                },
            },
        });
    }
    let requirement = family.requirements.provider;
    if requirement == ProviderRequirement::None {
        return None;
    }
    let Some(route) = capable_route(family, prepared) else {
        let fallback = fallback_route(requirement, prepared);
        let missing = fallback
            .map(|route| missing_capabilities(family, route))
            .unwrap_or_else(|| family.requirements.capabilities.to_vec());
        return Some(requirement_failure(
            explicit,
            requirement,
            fallback.map(|route| route.route.clone()),
            missing,
        ));
    };
    debug_assert!(missing_capabilities(family, route).is_empty());
    None
}

/// Default-only families are gated before dynamic default lookup. An unavailable provider route is
/// an inactive runtime condition, not missing resolver evidence.
pub(super) fn default_availability(
    family: &Family,
    prepared: &PreparedInput,
) -> Option<EntryOutcome> {
    if matches!(family.id, "provider" | "model") && prepared.input.runtime.selected_route.is_none()
    {
        return Some(EntryOutcome::Inactive {
            cause: InactiveCause::ProviderRouteMissing {
                requirement: family.requirements.provider,
            },
        });
    }
    let requirement = family.requirements.provider;
    if requirement == ProviderRequirement::None || capable_route(family, prepared).is_some() {
        return None;
    }
    let fallback = fallback_route(requirement, prepared);
    Some(if let Some(route) = fallback {
        EntryOutcome::Inactive {
            cause: InactiveCause::CapabilitiesMissing {
                route: Some(route.route.clone()),
                capabilities: missing_capabilities(family, route),
            },
        }
    } else {
        EntryOutcome::Inactive {
            cause: InactiveCause::ProviderRouteMissing { requirement },
        }
    })
}

fn capable_route<'a>(
    family: &Family,
    prepared: &'a PreparedInput,
) -> Option<&'a crate::RouteCapabilities> {
    match family.requirements.provider {
        ProviderRequirement::None => None,
        ProviderRequirement::SelectedRoute => prepared
            .selected_route()
            .filter(|route| missing_capabilities(family, route).is_empty()),
        ProviderRequirement::AnyAdmittedRoute if family.id == "provider" => prepared
            .selected_route()
            .filter(|route| missing_capabilities(family, route).is_empty()),
        ProviderRequirement::AnyAdmittedRoute => prepared
            .selected_route()
            .filter(|route| missing_capabilities(family, route).is_empty())
            .or_else(|| {
                prepared
                    .input
                    .runtime
                    .admitted_routes
                    .iter()
                    .find(|route| missing_capabilities(family, route).is_empty())
            }),
    }
}

fn fallback_route(
    requirement: ProviderRequirement,
    prepared: &PreparedInput,
) -> Option<&crate::RouteCapabilities> {
    match requirement {
        ProviderRequirement::None => None,
        ProviderRequirement::SelectedRoute => prepared.selected_route(),
        ProviderRequirement::AnyAdmittedRoute => prepared
            .selected_route()
            .or_else(|| prepared.input.runtime.admitted_routes.first()),
    }
}

fn missing_capabilities(
    family: &Family,
    route: &crate::RouteCapabilities,
) -> Vec<crate::CapabilityRequirement> {
    let mut missing = family
        .requirements
        .capabilities
        .iter()
        .filter(|capability| !route.capabilities.contains(capability))
        .copied()
        .collect::<Vec<_>>();
    missing.sort_unstable();
    missing.dedup();
    missing
}

fn requirement_failure(
    explicit: bool,
    requirement: ProviderRequirement,
    route: Option<crate::RouteIdentity>,
    mut missing: Vec<crate::CapabilityRequirement>,
) -> EntryOutcome {
    missing.sort_unstable();
    missing.dedup();
    if explicit {
        EntryOutcome::Rejected {
            reason: RejectionReason::ProviderRequirement {
                requirement,
                route,
                missing_capabilities: missing,
            },
        }
    } else if route.is_none() {
        EntryOutcome::Inactive {
            cause: InactiveCause::ProviderRouteMissing { requirement },
        }
    } else {
        EntryOutcome::Inactive {
            cause: InactiveCause::CapabilitiesMissing {
                route,
                capabilities: missing,
            },
        }
    }
}

fn route_identity_value<'a>(family: &str, prepared: &'a PreparedInput) -> Option<&'a str> {
    let selected = prepared.input.runtime.selected_route.as_ref()?;
    match family {
        "provider" => Some(&selected.provider_id),
        "model" => Some(&selected.model_id),
        _ => None,
    }
}

fn scalar_text(value: &ResolutionValue) -> Option<&str> {
    match value {
        ResolutionValue::Text { value } | ResolutionValue::Enum { value } => Some(value),
        _ => None,
    }
}
