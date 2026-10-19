//! Pure child route selection over already-held native provider objects. No model name can
//! construct a provider, refresh a catalog, discover a credential or add a route to the governor.
use super::KernelSpawnerContext;
use crate::runtime::GovernedProviderRoute;
use iteron_protocol::PricingRoute;
use iteron_provider::Provider;
use iteron_provider::catalog::{ModelRouterError, ModelRouterObservation, ModelRouterStrategy};
use std::sync::Arc;

pub(super) struct NativeChildRoute {
    pub(super) provider: Arc<dyn Provider>,
    pub(super) identity: PricingRoute,
    pub(super) context_window: Option<u64>,
    pub(super) output_cap: Option<u32>,
    pub(super) fallbacks: Vec<GovernedProviderRoute>,
}

pub(super) fn observation(
    cx: &KernelSpawnerContext,
    definition: Option<String>,
    requested: Option<String>,
) -> Result<ModelRouterObservation, ModelRouterError> {
    if cx.fallback_provider_routes.len() >= iteron_provider::catalog::MAX_RESOLVED_ROUTES {
        return Err(ModelRouterError::InvalidObservation(
            "native child route set exceeds its bound",
        ));
    }
    let mut models = vec![cx.model.clone()];
    // An unqualified model name cannot choose between two held provider identities. A model
    // matching the primary still means the primary; its failover chain remains separate.
    for route in &cx.fallback_provider_routes {
        if route.route.model_id == cx.model || !selectable(route) {
            continue;
        }
        let count = cx
            .fallback_provider_routes
            .iter()
            .filter(|candidate| {
                candidate.route.model_id == route.route.model_id && selectable(candidate)
            })
            .count();
        if count == 1 {
            models.push(route.route.model_id.clone());
        }
    }
    Ok(ModelRouterObservation {
        version: iteron_provider::catalog::MODEL_ROUTER_SLOT_VERSION,
        resolved_routes: models,
        definition_model: definition,
        call_model: requested,
    })
}

pub(super) fn select(
    cx: &KernelSpawnerContext,
    observation: &ModelRouterObservation,
) -> Result<NativeChildRoute, ModelRouterError> {
    let proposed = ModelRouterStrategy::route_with(
        cx.compiled_policy_bundle.slots().model_router.as_ref(),
        observation,
        cx.authority_ceiling,
    )?;
    if proposed.model == cx.model {
        return Ok(NativeChildRoute {
            provider: cx.provider.clone(),
            identity: PricingRoute {
                provider_id: cx.provider_id.clone(),
                model_id: cx.model.clone(),
                catalog_digest: cx.catalog_digest.clone(),
                capability_digest: cx.capability_digest.clone(),
            },
            context_window: cx.model_context_window,
            output_cap: cx.model_max_output_tokens,
            fallbacks: cx.fallback_provider_routes.clone(),
        });
    }
    let mut matches = cx
        .fallback_provider_routes
        .iter()
        .filter(|route| route.route.model_id == proposed.model && selectable(route));
    let selected = matches
        .next()
        .ok_or(ModelRouterError::RouteWithoutEvidence)?;
    if matches.next().is_some() {
        return Err(ModelRouterError::InvalidObservation(
            "child model names multiple native provider routes",
        ));
    }
    if !cx
        .provider_governor
        .as_ref()
        .is_some_and(|governor| governor.supports_route(&selected.id()))
    {
        return Err(ModelRouterError::RouteWithoutEvidence);
    }
    // These are executable inherited ceilings, not newly resolved tunables. The exact adapter
    // still attests its physical output bound at actual dispatch, before any provider IO.
    let inherited_context = match (cx.model_context_window, selected.context_window_tokens) {
        (Some(parent), Some(child)) => Some(parent.min(child)),
        (_, None) => None,
        (None, Some(_)) => None,
    };
    let native_cap = crate::runtime_tunables::core_facts::default_request_output_tokens(
        selected.max_output_tokens,
    );
    Ok(NativeChildRoute {
        provider: selected.provider.clone(),
        identity: selected.route.clone(),
        context_window: inherited_context,
        output_cap: Some(
            cx.model_max_output_tokens
                .map_or(native_cap, |parent| parent.min(native_cap)),
        ),
        fallbacks: cx
            .fallback_provider_routes
            .iter()
            .filter(|route| route.id() != selected.id())
            .cloned()
            .collect(),
    })
}

fn selectable(route: &GovernedProviderRoute) -> bool {
    route.tool_calling == Some(true)
        && route.context_window_tokens.is_some_and(|window| window > 0)
        && route.max_output_tokens.is_some_and(|cap| cap > 0)
}
