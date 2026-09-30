//! Own initial catalog resolution, trust-by-origin route selection and authenticated pricing.
//! This launch coordinator consumes the directory and returns one provisional route. Runtime
//! ModelSelected/RateCardBound receipts remain required before any physical provider request.
use super::UNIX_SECS_ON_UNUSABLE_CLOCK;
use crate::{config, pricing, providers};
use std::sync::Arc;

pub(crate) struct RouteLaunchInput<'a> {
    pub(crate) directory: providers::ProviderDirectory,
    pub(crate) provider_name: &'a str,
    pub(crate) provider_origin: config::ConfigOrigin,
    pub(crate) provider_was_explicit: bool,
    pub(crate) requested_model: Option<&'a str>,
    pub(crate) model_origin: Option<config::ConfigOrigin>,
    pub(crate) recording_provider_transport:
        Option<&'a iteron_provider::RecordingProviderTransport>,
    pub(crate) rate_cards: &'a [pricing::RateCardConfig],
    pub(crate) settle_catalogs: bool,
    pub(crate) one_shot: bool,
    pub(crate) resuming: bool,
    pub(crate) max_usd: Option<f64>,
    pub(crate) machine_output: bool,
}

pub(crate) struct AdmittedLaunchRoute {
    pub(crate) directory: providers::ProviderDirectory,
    pub(crate) selection: providers::ModelSelection,
    pub(crate) provider: Arc<dyn iteron_provider::Provider>,
    pub(crate) capabilities: providers::ModelCapabilities,
    pub(crate) catalog_digest: String,
    pub(crate) capability_digest: String,
    pub(crate) pricing: Option<Arc<dyn iteron_obs::PricingPort>>,
    pub(crate) pricing_observed_at: u64,
}

pub(crate) async fn admit(input: RouteLaunchInput<'_>) -> anyhow::Result<AdmittedLaunchRoute> {
    let RouteLaunchInput {
        directory: mut provider_directory,
        provider_name,
        provider_origin,
        provider_was_explicit,
        requested_model,
        model_origin,
        recording_provider_transport,
        rate_cards,
        settle_catalogs,
        one_shot,
        resuming,
        max_usd,
        machine_output,
    } = input;
    // One-shot/headless callers have no first-frame boundary, so settle an unresolved selected
    // route before constructing its provider. Interactive TUI discovery is deliberately left
    // dormant here: `tui::run` draws first, then its existing provider-refresh task calls
    // `settle()`, which is the sole signal that may start provider network I/O. Cached/static and
    // explicitly qualified routes can still construct immediately; an unproved route remains an
    // unavailable provider until the post-paint picker publishes verified evidence.
    if settle_catalogs
        && provider_directory.needs_settled_catalogs(requested_model, provider_name)
        && !provider_directory.settle().await
    {
        eprintln!(
            "provider refresh is still running after the 500ms first-use budget; continuing with validated cached/static route facts"
        );
    }

    // Resolve one explicit `(provider, model)` pair from the dynamic catalogs. A trusted provider
    // selection is authoritative. A bare project model is even stricter: it is valid only within
    // that provider. With no model, never fail over to a different provider implicitly; doing so
    // would silently change the credentialed egress destination.
    let selection_result: Result<providers::ModelSelection, String> = if let Some(model_id) =
        requested_model
    {
        let qualified_provider = model_id
            .split_once(':')
            .map(|(provider_id, _)| provider_id)
            .filter(|provider_id| provider_directory.entry(provider_id).is_some());
        let qualifier_may_route = qualified_provider.is_none_or(|qualified_provider| {
            model_origin.is_some_and(|origin| {
                config::qualifier_may_route(
                    qualified_provider,
                    provider_name,
                    origin,
                    provider_origin,
                )
            })
        });
        if qualified_provider.is_some() && !qualifier_may_route {
            Err(format!(
                "model qualifier `{}` conflicts with the higher- or equal-precedence provider `{provider_name}`",
                qualified_provider.unwrap_or_default()
            ))
        } else if qualified_provider.is_some() {
            provider_directory.resolve_model(model_id, Some(provider_name))
        } else if provider_was_explicit {
            let selection = providers::ModelSelection {
                provider_id: provider_name.to_owned(),
                model_id: model_id.to_owned(),
            };
            provider_directory
                .validate_selection(&selection, true)
                .map(|()| selection)
        } else {
            provider_directory.resolve_model(model_id, Some(provider_name))
        }
    } else {
        provider_directory
            .default_selection(provider_name)
            .ok_or_else(|| provider_directory.resolution_error(provider_name))
    };

    let (selection, provider_arc) = match selection_result {
        Ok(selection) => {
            let built = match recording_provider_transport {
                Some(transport) => provider_directory.build_with_transport(&selection, transport),
                None => provider_directory.build(&selection),
            };
            match built {
                Ok(provider) => (selection, provider),
                Err(error) if one_shot => {
                    anyhow::bail!("selected provider/model is unavailable: {error}")
                }
                Err(error) => {
                    eprintln!("provider unavailable: {error}");
                    let provider = provider_directory
                        .unavailable_provider(selection.provider_id.clone(), error);
                    (selection, provider)
                }
            }
        }
        Err(error) if one_shot => anyhow::bail!("cannot resolve provider/model: {error}"),
        Err(error) => {
            eprintln!("provider unavailable: {error}");
            let selection = providers::ModelSelection {
                provider_id: provider_name.to_owned(),
                model_id: requested_model.unwrap_or_default().to_owned(),
            };
            let provider = provider_directory.unavailable_provider(provider_name.to_owned(), error);
            (selection, provider)
        }
    };
    let model = selection.model_id.clone();
    let provider_id = selection.provider_id.clone();
    let model_capabilities = provider_directory.selection_capabilities(&selection);
    let (catalog_digest, capability_digest) = provider_directory.selection_digests(&selection);
    let pricing_route = iteron_protocol::PricingRoute {
        provider_id: provider_id.clone(),
        model_id: model.clone(),
        catalog_digest: catalog_digest.clone(),
        capability_digest: capability_digest.clone(),
    };
    // Read and authenticate operator pricing material before creating a rollout. A missing or bad
    // key must not leave a genesis-less record, and a positive ceiling must never start unpriced.
    let pricing_port = pricing::load_authority(rate_cards)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(iteron_tunables::param_integer(
            "cli.main.unix_secs_on_unusable_clock",
            UNIX_SECS_ON_UNUSABLE_CLOCK,
        ));
    let selected_rate_card = pricing_port
        .as_ref()
        .map(|port| port.resolve_rate_card(&pricing_route, now))
        .transpose()?
        .flatten();
    if !resuming && max_usd.is_some_and(|ceiling| ceiling > 0.0) && selected_rate_card.is_none() {
        // Say how to fix it. This refusal is correct — an unpriced ceiling is not a ceiling — but
        // without a route to the tooling it reads as "this feature is not for you" (I-40).
        anyhow::bail!(
            "cannot enforce the requested USD ceiling: the exact selected route has no active verified rate card.\n\
             Produce one with `iteron pricing print-digests` (the route to pin) then `iteron pricing sign <card.json>`,\n\
             and install the printed object under `rate_cards` in ~/.iteron/config.json."
        );
    }
    if pricing_port.is_some() && selected_rate_card.is_none() && !machine_output {
        // The operator configured cards and none of them matched this route — almost always a
        // digest that moved. Naming the cause beats leaving the run silently unpriced (I-40).
        eprintln!(
            "note: rate cards are configured but none is active for this exact route, so this run reports token usage and no cost. `iteron pricing print-digests` prints the route to sign."
        );
    }

    Ok(AdmittedLaunchRoute {
        directory: provider_directory,
        selection,
        provider: provider_arc,
        capabilities: model_capabilities,
        catalog_digest,
        capability_digest,
        pricing: pricing_port,
        pricing_observed_at: now,
    })
}
