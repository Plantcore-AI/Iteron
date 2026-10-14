//! Initial provider/catalog construction and credential containment from trusted launch sources.
use super::Cli;
use crate::config::FileConfig;
use crate::{config, providers, recording_provider, startup};
use iteron_tools::Registry;
use std::path::Path;
pub(crate) const BUILTIN_DEFAULT_PROVIDER: &str = "openai";
pub(crate) const CLI_OVERRIDE_PROVIDER_ID: &str = "cli-override";

pub(crate) fn validate_plantcore_provider_credentials(
    configured_providers: &[config::ProviderConfig],
    eager_provider_ids: &[String],
) -> anyhow::Result<()> {
    const REQUIRED_ENV: &str = "ITERON_PROVIDER_API_KEY";

    for provider_id in eager_provider_ids {
        let provider = configured_providers
            .iter()
            .find(|provider| provider.id == *provider_id)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "PlantCore provider `{provider_id}` must be operator-configured with credential env `{REQUIRED_ENV}`"
                )
            })?;
        let credential = provider.resolved_credential().map_err(anyhow::Error::msg)?;
        if credential.env_name() != Some(REQUIRED_ENV) {
            anyhow::bail!(
                "PlantCore provider `{provider_id}` must use credential env `{REQUIRED_ENV}`"
            );
        }
    }
    Ok(())
}

pub(crate) struct InitialRoute {
    pub(crate) provider_name: String,
    pub(crate) provider_origin: config::ConfigOrigin,
    pub(crate) provider_was_explicit: bool,
    pub(crate) configured_providers: Vec<config::ProviderConfig>,
    pub(crate) requested_model: Option<String>,
    pub(crate) model_origin: Option<config::ConfigOrigin>,
    pub(crate) provider_directory: providers::ProviderDirectory,
    pub(crate) recording_provider_transport: Option<iteron_provider::RecordingProviderTransport>,
    pub(crate) credential_env_names: Vec<String>,
}
// Keep trusted inputs and the two disjoint mutable assembly owners explicit at startup.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn assemble(
    cli: &Cli,
    repo: &Path,
    file: &FileConfig,
    user_file: &FileConfig,
    plantcore_serve: bool,
    recording_provider_ca_file: Option<&Path>,
    pricing_key_env_names: Vec<String>,
    registry: &mut Registry,
    startup: &mut startup::StartupTiming,
) -> anyhow::Result<InitialRoute> {
    // Routing-sensitive defaults never consult the repository config. A cloned project must not
    // be able to redirect source code (and an operator credential) to another provider or host.
    // Exact precedence: CLI > environment > trusted user config > built-in.
    let (mut provider_name, mut provider_origin) = config::pick_trusted_string(
        cli.provider.clone(),
        config::env_string("ITERON_PROVIDER"),
        user_file.provider.clone(),
        iteron_tunables::param_str(
            "cli.main.builtin_default_provider",
            BUILTIN_DEFAULT_PROVIDER,
        ),
    );
    let mut provider_was_explicit = provider_origin != config::ConfigOrigin::Builtin;
    let model_candidate = config::pick_model_string(
        cli.model.clone(),
        config::env_string("ITERON_MODEL"),
        user_file.model.clone(),
        file.model.clone(),
    );
    let mut configured_providers = user_file.providers.clone().unwrap_or_default();
    let endpoint_override = config::pick_optional_trusted_string(
        cli.base_url.clone(),
        config::env_string("ITERON_BASE_URL"),
        user_file.base_url.clone(),
    );
    if let Some((api_root, endpoint_origin)) = endpoint_override
        && endpoint_origin.routing_priority() >= provider_origin.routing_priority()
    {
        // The credential MUST be named explicitly. Deriving it from the provider NAME — which is
        // resolved before the override is applied, with a silent fallback to `OPENAI_API_KEY` —
        // meant `iteron --base-url https://gateway/v1` shipped whatever key the default provider
        // happened to use to an arbitrary host. A credential leaves this machine only for an
        // endpoint the operator paired it with in the same breath.
        let key_env = config::pick_optional_trusted_string(
            cli.key_env.clone(),
            config::env_string("ITERON_KEY_ENV"),
            None,
        )
        .map(|(name, _)| name)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "--base-url needs an explicit credential: pass --key-env <NAME> (or ITERON_KEY_ENV) naming the environment variable holding the key for {api_root}, or declare a named provider with its own `credential` in ~/.iteron/config.json"
            )
        })?;
        let temporary = config::ProviderConfig {
            id: CLI_OVERRIDE_PROVIDER_ID.into(),
            display_name: Some("Compatible endpoint override".into()),
            adapter: "openai_chat".into(),
            error_profile: None,
            api_root,
            key_env: Some(key_env),
            credential: None,
            enabled: true,
            catalog: true,
            models: Vec::new(),
            model_capabilities: std::collections::BTreeMap::new(),
        };
        let validation = FileConfig {
            providers: Some(vec![temporary.clone()]),
            ..FileConfig::default()
        };
        validation.validate().map_err(anyhow::Error::msg)?;
        configured_providers.push(temporary);
        provider_name = CLI_OVERRIDE_PROVIDER_ID.into();
        provider_origin = endpoint_origin;
        provider_was_explicit = true;
    } else if cli.key_env.is_some() {
        anyhow::bail!(
            "--key-env only names the credential for --base-url; a configured provider declares its own `credential` in ~/.iteron/config.json"
        );
    }
    // Only the providers this launch can actually route to are resolved before the first byte is
    // printed: the selected one, plus any provider named by an explicit model qualifier. The rest
    // continue in the background and the model picker joins them. Waiting for all of them is why a
    // launch with five configured providers paid for four it was never going to use.
    // Nobody chose this provider: it is the build-time fallback, which cannot know which account
    // this machine has. If it has no credential and some other route does, route there instead, so
    // "install it and run it" works for whoever installed it rather than failing on a variable for
    // a provider they may never have signed up for.
    //
    // Gated on `Builtin` precisely so an explicit choice is never rerouted. Silently sending an
    // operator's credential to a provider they did not name would be a spend and disclosure
    // decision, and those are theirs. This reads local credential presence only: no catalog, no
    // request, nothing that could make startup depend on the network.
    if provider_origin == config::ConfigOrigin::Builtin
        && let Ok(local) = providers::ProviderDirectory::inspect_local(&configured_providers)
        && !local.has_credential(&provider_name)
        && let Some(credentialed) = local.first_credentialed_provider()
    {
        provider_name = credentialed.to_owned();
    }

    let mut eager_providers = vec![provider_name.clone()];
    if let Some((model, _)) = model_candidate.as_ref()
        && let Some((qualifier, _)) = model.split_once(':')
    {
        eager_providers.push(qualifier.to_owned());
    }
    if plantcore_serve {
        validate_plantcore_provider_credentials(&configured_providers, &eager_providers)?;
    }
    let recording_provider_transport = recording_provider_ca_file
        .map(|path| recording_provider::prepare(path, &configured_providers, &provider_name))
        .transpose()?;
    let provider_directory =
        providers::ProviderDirectory::discover_eagerly(&configured_providers, &eager_providers)
            .await?;
    startup.mark(startup::StartupPhase::ProviderDiscover);
    let mut credential_env_names = provider_directory.credential_env_names();
    credential_env_names.extend(pricing_key_env_names);
    credential_env_names.sort();
    credential_env_names.dedup();
    registry.set_sensitive_env_names(credential_env_names.clone());
    // One bit, set once, read per bash call: which of the two execution postures this run uses.
    // A file-backed credential is never in the environment, so the env deny-list above says
    // nothing about it. The one place a tool, a child agent, or a hook can reach a file is the
    // workspace, so a credential file inside it is refused outright rather than trusted to stay
    // unread. Credential files outside the workspace remain unreachable by construction.
    let exposed_credentials = provider_directory.credential_files_inside(repo);
    if let Some(path) = exposed_credentials.first() {
        anyhow::bail!(
            "credential file {} is inside the workspace, where tools, subagents, and hooks can read it; move it outside {} (for example under ~/.iteron/credentials)",
            path.display(),
            repo.display()
        );
    }

    let (requested_model, model_origin) = match model_candidate {
        Some((model, origin)) => (Some(model), Some(origin)),
        None => (None, None),
    };
    Ok(InitialRoute {
        provider_name,
        provider_origin,
        provider_was_explicit,
        configured_providers,
        requested_model,
        model_origin,
        provider_directory,
        recording_provider_transport,
        credential_env_names,
    })
}
