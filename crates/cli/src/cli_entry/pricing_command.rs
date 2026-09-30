//! Operator pricing tooling without a session or paid attempt.

use super::options::{Cli, PricingAction};
use crate::config::FileConfig;
use crate::{config, output, pricing, providers};
const BUILTIN_DEFAULT_PROVIDER: &str = "openai";

/// `iteron pricing <print-digests|sign>` — the shipped path to a priced run (I-40).
///
/// Neither action opens a rollout, admits a provider effect, or spends a token. `print-digests`
/// resolves the same route the agent would record and prints it; `sign` turns an operator-authored
/// card into the exact configuration entry that installs it. Together they close the gap that made
/// cost display and the USD ceiling unreachable for every public user.
pub(crate) async fn run_pricing_command(
    cli: &Cli,
    user_file: &FileConfig,
    action: &PricingAction,
) -> anyhow::Result<u8> {
    match action {
        PricingAction::PrintDigests => {
            // Same trusted precedence as a run (CLI > env > user config > built-in): a route
            // printed from different inputs than the one recorded would sign the wrong card.
            let configured_providers = user_file.providers.clone().unwrap_or_default();
            let (provider_name, _origin) = config::pick_trusted_string(
                cli.provider.clone(),
                config::env_string("ITERON_PROVIDER"),
                user_file.provider.clone(),
                iteron_tunables::param_str(
                    "cli.main.builtin_default_provider",
                    BUILTIN_DEFAULT_PROVIDER,
                ),
            );
            let directory = providers::ProviderDirectory::discover(&configured_providers).await?;
            let requested_model = cli
                .model
                .clone()
                .or_else(|| config::env_string("ITERON_MODEL"))
                .or_else(|| user_file.model.clone());
            let selection = match requested_model.as_deref() {
                Some(model_id) => directory
                    .resolve_model(model_id, Some(&provider_name))
                    .map_err(|error| anyhow::anyhow!("cannot resolve model: {error}"))?,
                None => directory.default_selection(&provider_name).ok_or_else(|| {
                    anyhow::anyhow!("provider `{provider_name}` has no selectable model")
                })?,
            };
            let (catalog_digest, capability_digest) = directory.selection_digests(&selection);
            let route = iteron_protocol::PricingRoute {
                provider_id: selection.provider_id.clone(),
                model_id: selection.model_id.clone(),
                catalog_digest,
                capability_digest,
            };
            println!("{}", serde_json::to_string_pretty(&route)?);
            eprintln!(
                "this is the `route` of a rate card for {}/{}. Both digests pin the exact catalog \
and capability evidence recorded at selection time; a card signed for a different route is not \
resolved and the run stays unpriced.",
                route.provider_id, route.model_id
            );
            Ok(output::EXIT_SUCCESS)
        }
        PricingAction::Sign {
            card,
            key_env,
            signer_id,
        } => {
            let raw = if card.as_os_str() == "-" {
                std::io::read_to_string(std::io::stdin().lock())?
            } else {
                std::fs::read_to_string(card)
                    .map_err(|error| anyhow::anyhow!("rate card {}: {error}", card.display()))?
            };
            let rate_card: iteron_protocol::RateCard =
                serde_json::from_str(&raw).map_err(|error| {
                    anyhow::anyhow!("rate card is not a valid unsigned RateCard document: {error}")
                })?;
            let key_material = std::env::var(key_env).map_err(|_| {
                anyhow::anyhow!("pricing key environment variable `{key_env}` is not set")
            })?;
            let entry = pricing::sign_config_entry(rate_card, signer_id, key_env, &key_material)?;
            // Validate what we are about to hand the operator through the same gate the loader
            // uses, so a card cannot be published here and rejected at startup.
            pricing::validate_rate_card_configs(std::slice::from_ref(&entry))
                .map_err(anyhow::Error::msg)?;
            println!("{}", serde_json::to_string_pretty(&entry)?);
            eprintln!(
                "append this object to `rate_cards` in ~/.iteron/config.json and export `{key_env}`. \
Only the variable NAME is written; the key bytes stay in your environment."
            );
            Ok(output::EXIT_SUCCESS)
        }
    }
}
