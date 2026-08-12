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
    if !policy_requires_provider_capability(family.id, selected_value, prepared) {
        let route = fallback_route(requirement, prepared);
        return route
            .is_none()
            .then(|| requirement_failure(explicit, requirement, None, Vec::new()));
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
    if requirement == ProviderRequirement::None
        || !default_policy_requires_provider_capability(family.id, prepared)
        || capable_route(family, prepared).is_some()
    {
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

/// Policy declarations are not themselves provider capabilities. A disabled hedge remains an
/// active, auditable policy even on a route that cannot hedge; failover taxonomy is likewise
/// inert until an actual fallback chain exists. Capability attestation becomes load-bearing only
/// when the selected value can cause the corresponding physical behavior.
fn policy_requires_provider_capability(
    family_id: &str,
    selected_value: &ResolutionValue,
    prepared: &PreparedInput,
) -> bool {
    match family_id {
        "model_fallback_chain" => {
            matches!(selected_value, ResolutionValue::List { items } if !items.is_empty())
        }
        "failover_eligible_error_taxonomy" => configured_fallback_chain_present(prepared),
        "provider_health_circuit_breaker_state_policy" => false,
        "hedged_request_policy" => object_boolean(selected_value, "enabled").unwrap_or(true),
        "provider_service_tier" => scalar_text(selected_value) != Some("provider_default"),
        "response_verbosity" => scalar_text(selected_value) != Some("model_default"),
        "request_compression_policy" => scalar_text(selected_value) != Some("none"),
        "prompt_cache_ttl_breakpoint_strategy" => !prompt_cache_is_disabled(selected_value),
        _ => true,
    }
}

fn default_policy_requires_provider_capability(family_id: &str, prepared: &PreparedInput) -> bool {
    match family_id {
        // The embedded fallback-chain default is empty, so it cannot dispatch a second route and
        // must remain an effective auditable policy on providers that do not support failover.
        // Any non-empty declaration is checked by `policy_requires_provider_capability` above.
        "model_fallback_chain"
        | "provider_health_circuit_breaker_state_policy"
        | "provider_service_tier"
        | "response_verbosity"
        | "request_compression_policy"
        | "prompt_cache_ttl_breakpoint_strategy" => false,
        "failover_eligible_error_taxonomy" => configured_fallback_chain_present(prepared),
        // The embedded hedge default is the canonical disabled policy. Any enabled value arrives
        // as a selected declaration and is checked by `policy_requires_provider_capability`.
        "hedged_request_policy" => false,
        _ => true,
    }
}

fn configured_fallback_chain_present(prepared: &PreparedInput) -> bool {
    let declared = prepared
        .input
        .declared_values
        .iter()
        .find(|candidate| candidate.family == "model_fallback_chain")
        .map(|candidate| &candidate.value);
    let profiled = prepared
        .input
        .profile
        .as_ref()
        .and_then(|profile| {
            profile
                .values
                .iter()
                .find(|candidate| candidate.family == "model_fallback_chain")
        })
        .map(|candidate| &candidate.value);
    declared
        .or(profiled)
        .is_some_and(|value| matches!(value, ResolutionValue::List { items } if !items.is_empty()))
}

fn object_boolean(value: &ResolutionValue, field: &str) -> Option<bool> {
    let ResolutionValue::Object { fields } = value else {
        return None;
    };
    match fields.get(field) {
        Some(ResolutionValue::Boolean { value }) => Some(*value),
        _ => None,
    }
}

fn prompt_cache_is_disabled(value: &ResolutionValue) -> bool {
    let ResolutionValue::Object { fields } = value else {
        return false;
    };
    // With no breakpoint and a zero TTL the provider cannot emit cache controls. The
    // invalidation and scope fields are inert bookkeeping in that state and must not turn a
    // physically disabled policy into a provider-capability requirement.
    matches!(
        fields.get("ttl_seconds"),
        Some(ResolutionValue::Integer { value: 0 })
    ) && matches!(
        fields.get("breakpoint"),
        Some(ResolutionValue::Enum { value }) if value == "none"
    )
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CapabilityRequirement, DeclaredValue, ProviderRequirement, REGISTRY_DIGEST_SHA256,
        REGISTRY_ID, REGISTRY_REVISION, RESOLUTION_SCHEMA_VERSION, ResolutionInput,
        RouteCapabilities, RouteIdentity, RuntimeContext, SourceKind, families,
    };
    use std::collections::{BTreeMap, BTreeSet};

    fn prepared(with_fallback: bool) -> PreparedInput {
        let route = RouteIdentity {
            provider_id: "fixture:provider".into(),
            model_id: "fixture:model".into(),
            route_revision: "fixture:v1".into(),
            catalog_digest_sha256:
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        };
        let declared_values = with_fallback
            .then(|| DeclaredValue {
                family: "model_fallback_chain".into(),
                source: SourceKind::UserConfig,
                evidence_digest_sha256:
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                value: ResolutionValue::List {
                    items: vec![ResolutionValue::Enum {
                        value: "fixture:fallback".into(),
                    }],
                },
            })
            .into_iter()
            .collect();
        PreparedInput {
            input: ResolutionInput {
                schema_version: RESOLUTION_SCHEMA_VERSION,
                registry_id: REGISTRY_ID.into(),
                registry_revision: REGISTRY_REVISION,
                registry_digest: REGISTRY_DIGEST_SHA256.into(),
                profile: None,
                declared_values,
                default_evidence: Vec::new(),
                activation_evidence: Vec::new(),
                constraint_evidence: Vec::new(),
                runtime: RuntimeContext {
                    admitted_routes: vec![RouteCapabilities {
                        route: route.clone(),
                        capabilities: BTreeSet::new(),
                        attestation_digest_sha256:
                            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                                .into(),
                    }],
                    selected_route: Some(route),
                    catalogs: Vec::new(),
                },
            },
            input_digest_sha256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                .into(),
            profile_digest_sha256: None,
        }
    }

    fn hedge_value(enabled: bool) -> ResolutionValue {
        ResolutionValue::Object {
            fields: BTreeMap::from([(
                "enabled".into(),
                ResolutionValue::Boolean { value: enabled },
            )]),
        }
    }

    fn cache_value(enabled: bool) -> ResolutionValue {
        ResolutionValue::Object {
            fields: BTreeMap::from([
                (
                    "ttl_seconds".into(),
                    ResolutionValue::Integer {
                        value: if enabled { 300 } else { 0 },
                    },
                ),
                (
                    "breakpoint".into(),
                    ResolutionValue::Enum {
                        value: if enabled { "rolling" } else { "none" }.into(),
                    },
                ),
                (
                    "invalidate_on_tool_change".into(),
                    // This matches `PromptCacheConfig::default_for(false)`: invalidation remains
                    // enabled as inert bookkeeping even when TTL/breakpoint make wire caching
                    // physically impossible.
                    ResolutionValue::Boolean { value: true },
                ),
                (
                    "scope".into(),
                    ResolutionValue::Enum {
                        value: "session".into(),
                    },
                ),
            ]),
        }
    }

    #[test]
    fn inert_policy_declarations_do_not_invent_provider_capabilities() {
        let without_fallback = prepared(false);
        let fallback_chain = families()
            .iter()
            .find(|family| family.id == "model_fallback_chain")
            .unwrap();
        let empty_chain = ResolutionValue::List { items: Vec::new() };
        assert!(provider_gate(fallback_chain, &without_fallback, &empty_chain, false).is_none());
        assert!(default_availability(fallback_chain, &without_fallback).is_none());

        let taxonomy = families()
            .iter()
            .find(|family| family.id == "failover_eligible_error_taxonomy")
            .unwrap();
        let taxonomy_value = ResolutionValue::List { items: Vec::new() };
        assert!(provider_gate(taxonomy, &without_fallback, &taxonomy_value, true).is_none());

        let hedge = families()
            .iter()
            .find(|family| family.id == "hedged_request_policy")
            .unwrap();
        assert!(provider_gate(hedge, &without_fallback, &hedge_value(false), true).is_none());

        for (family_id, value) in [
            (
                "provider_service_tier",
                ResolutionValue::Enum {
                    value: "provider_default".into(),
                },
            ),
            (
                "response_verbosity",
                ResolutionValue::Enum {
                    value: "model_default".into(),
                },
            ),
            (
                "request_compression_policy",
                ResolutionValue::Enum {
                    value: "none".into(),
                },
            ),
            ("prompt_cache_ttl_breakpoint_strategy", cache_value(false)),
        ] {
            let family = families()
                .iter()
                .find(|family| family.id == family_id)
                .unwrap();
            assert!(provider_gate(family, &without_fallback, &value, false).is_none());
            assert!(default_availability(family, &without_fallback).is_none());
        }

        for (family_id, expected_capability) in [
            (
                "route_quality_cost_latency_objective_weights",
                CapabilityRequirement::Reasoning,
            ),
            (
                "provider_health_circuit_breaker_state_policy",
                CapabilityRequirement::RuntimeObservation,
            ),
        ] {
            let family = families()
                .iter()
                .find(|family| family.id == family_id)
                .unwrap();
            assert_eq!(
                family.requirements.provider,
                if family_id == "provider_health_circuit_breaker_state_policy" {
                    ProviderRequirement::AnyAdmittedRoute
                } else {
                    ProviderRequirement::None
                }
            );
            assert_eq!(family.requirements.capabilities, &[expected_capability]);
            assert!(
                provider_gate(
                    family,
                    &without_fallback,
                    &ResolutionValue::Object {
                        fields: BTreeMap::new(),
                    },
                    false,
                )
                .is_none()
            );
            assert!(default_availability(family, &without_fallback).is_none());
        }
    }

    #[test]
    fn physical_policy_paths_fail_closed_without_exact_route_capability() {
        let with_fallback = prepared(true);
        let fallback_chain = families()
            .iter()
            .find(|family| family.id == "model_fallback_chain")
            .unwrap();
        let fallback_outcome = provider_gate(
            fallback_chain,
            &with_fallback,
            &ResolutionValue::List {
                items: vec![ResolutionValue::Enum {
                    value: "fixture:fallback".into(),
                }],
            },
            true,
        )
        .expect("operator-declared non-empty fallback activates physical failover gating");
        assert!(matches!(
            fallback_outcome,
            EntryOutcome::Rejected {
                reason: RejectionReason::ProviderRequirement {
                    missing_capabilities,
                    ..
                }
            } if missing_capabilities == vec![CapabilityRequirement::ProviderFailover]
        ));

        let taxonomy = families()
            .iter()
            .find(|family| family.id == "failover_eligible_error_taxonomy")
            .unwrap();
        let taxonomy_outcome = provider_gate(
            taxonomy,
            &with_fallback,
            &ResolutionValue::List { items: Vec::new() },
            true,
        )
        .expect("non-empty fallback activates physical failover capability gating");
        assert!(matches!(
            taxonomy_outcome,
            EntryOutcome::Rejected {
                reason: RejectionReason::ProviderRequirement {
                    missing_capabilities,
                    ..
                }
            } if missing_capabilities == vec![CapabilityRequirement::ProviderFailover]
        ));

        let hedge = families()
            .iter()
            .find(|family| family.id == "hedged_request_policy")
            .unwrap();
        let hedge_outcome = provider_gate(hedge, &with_fallback, &hedge_value(true), true)
            .expect("enabled hedge activates physical hedge capability gating");
        assert!(matches!(
            hedge_outcome,
            EntryOutcome::Rejected {
                reason: RejectionReason::ProviderRequirement {
                    missing_capabilities,
                    ..
                }
            } if missing_capabilities == vec![CapabilityRequirement::ProviderHedging]
        ));

        for (family_id, value, expected) in [
            (
                "provider_service_tier",
                ResolutionValue::Enum {
                    value: "priority".into(),
                },
                vec![CapabilityRequirement::ProviderServiceTier],
            ),
            (
                "response_verbosity",
                ResolutionValue::Enum {
                    value: "detailed".into(),
                },
                vec![
                    CapabilityRequirement::ProviderResponseVerbosity,
                    CapabilityRequirement::Reasoning,
                ],
            ),
            (
                "request_compression_policy",
                ResolutionValue::Enum {
                    value: "gzip".into(),
                },
                vec![CapabilityRequirement::ProviderRequestCompression],
            ),
            (
                "prompt_cache_ttl_breakpoint_strategy",
                cache_value(true),
                vec![
                    CapabilityRequirement::ProviderPromptCache,
                    CapabilityRequirement::ContextRead,
                ],
            ),
        ] {
            let family = families()
                .iter()
                .find(|family| family.id == family_id)
                .unwrap();
            let outcome = provider_gate(family, &with_fallback, &value, true)
                .expect("a non-default wire policy requires exact route capability");
            assert!(matches!(
                outcome,
                EntryOutcome::Rejected {
                    reason: RejectionReason::ProviderRequirement {
                        missing_capabilities,
                        ..
                    }
                } if missing_capabilities == expected
            ));
        }
    }
}
