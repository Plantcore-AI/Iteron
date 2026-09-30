//! Operator configuration to exact immutable provider instances and explicit model catalogs.
//! Construction never performs discovery; credential validation receives its candidate route here.
use super::{
    CatalogProvenance, DEEPSEEK_API_ROOT, MINIMAX_API_ROOT, OPENAI_API_ROOT, ProviderEntry,
    ProviderOrigin, load_static_provider_metadata,
};
use crate::config::{ProviderConfig, ProviderCredential};
use iteron_provider::catalog::glm_standard_schema_catalog;
use iteron_provider::{
    AccountProbe, AdapterKind, ApiRoot, CatalogSnapshot, CatalogStrategy, Compatibility,
    CredentialSource, ErrorProfile, ModelDescriptor, ModelFamily, ProviderInstance, RawModel,
    Selectability, StaticProviderMetadata,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
struct Builtin {
    id: &'static str,
    display_name: &'static str,
    adapter: AdapterKind,
    api_root: &'static str,
    key_env: &'static str,
}

const BUILTINS: &[Builtin] = &[
    Builtin {
        id: "anthropic",
        display_name: "Anthropic",
        adapter: AdapterKind::AnthropicMessages,
        api_root: "https://api.anthropic.com/v1",
        key_env: "ANTHROPIC_API_KEY",
    },
    Builtin {
        id: "openai",
        display_name: "OpenAI",
        adapter: AdapterKind::OpenAiResponses,
        api_root: OPENAI_API_ROOT,
        key_env: "OPENAI_API_KEY",
    },
    Builtin {
        id: "deepseek",
        display_name: "DeepSeek",
        adapter: AdapterKind::OpenAiCompatibleChat,
        api_root: DEEPSEEK_API_ROOT,
        key_env: "DEEPSEEK_API_KEY",
    },
    Builtin {
        id: "glm",
        display_name: "GLM / 智谱",
        adapter: AdapterKind::OpenAiCompatibleChat,
        api_root: "https://open.bigmodel.cn/api/paas/v4",
        key_env: "GLM_API_KEY",
    },
    Builtin {
        id: "minimax",
        display_name: "MiniMax",
        adapter: AdapterKind::OpenAiCompatibleChat,
        api_root: MINIMAX_API_ROOT,
        key_env: "MINIMAX_API_KEY",
    },
    Builtin {
        id: "fireworks",
        display_name: "Fireworks",
        adapter: AdapterKind::OpenAiCompatibleChat,
        api_root: "https://api.fireworks.ai/inference/v1",
        key_env: "FIREWORKS_API_KEY",
    },
];

#[cfg(test)]
pub(super) fn builtin_entries() -> anyhow::Result<Vec<ProviderEntry>> {
    builtin_entries_with_metadata(StaticProviderMetadata::embedded())
}

pub(super) fn builtin_entries_with_metadata(
    static_metadata: Arc<StaticProviderMetadata>,
) -> anyhow::Result<Vec<ProviderEntry>> {
    BUILTINS
        .iter()
        .map(|builtin| {
            let credential = builtin_credential(builtin.id, builtin.key_env);
            let instance = ProviderInstance::new(
                builtin.id,
                builtin.display_name,
                builtin.adapter,
                ApiRoot::parse(builtin.api_root)?,
                None,
            )?
            .with_credential_source(credential_source(&credential))
            .with_static_metadata(static_metadata.clone());
            let (catalog_enabled, mut catalog_error) = catalog_configuration(&instance, true);
            // GLM publishes a finite model enum in the exact standard Chat Completions request
            // schema, but no list-models operation. Expose that official schema without turning
            // on discovery: it is endpoint compatibility evidence only, never credential/account
            // entitlement evidence, and this construction performs no network request.
            let catalog = if builtin.id == "glm"
                && instance.api_root().as_str() == static_metadata.glm_api_root()
            {
                // `Unsupported` describes network discovery, not the static official evidence we
                // just loaded. Do not leave a contradictory catalog error on a usable manifest.
                catalog_error = None;
                Some(glm_standard_schema_catalog(&instance)?)
            } else {
                None
            };
            let catalog_provenance = if catalog.is_some() {
                CatalogProvenance::StaticOfficial {
                    version: static_metadata.glm_catalog_version().into(),
                    source: static_metadata.glm_catalog_source().into(),
                }
            } else {
                CatalogProvenance::Unavailable
            };
            // Resolved once here, through exactly the source a turn would use, so the display
            // filter never re-reads a credential file per rendered frame.
            let credential_present = instance.has_credential();
            Ok(ProviderEntry {
                instance,
                credential,
                origin: ProviderOrigin::Builtin,
                credential_present,
                enabled: true,
                catalog_enabled,
                catalog,
                catalog_error,
                catalog_fallback_explicit: false,
                catalog_stale: false,
                catalog_provenance,
                declared_capabilities: BTreeMap::new(),
            })
        })
        .collect::<Result<Vec<_>, iteron_provider::ProviderError>>()
        .map_err(Into::into)
}

pub(super) fn is_glm_standard_schema_entry(entry: &ProviderEntry) -> bool {
    entry.id() == "glm"
        && entry.instance.adapter() == AdapterKind::OpenAiCompatibleChat
        && entry.instance.api_root().as_str() == entry.instance.static_metadata().glm_api_root()
        && !entry.catalog_enabled
        && matches!(
            &entry.catalog_provenance,
            CatalogProvenance::StaticOfficial { .. }
        )
}

// Iteron default-route preferences apply only to leaves admitted by this account's live catalog.
// A preferred model name never establishes endpoint support or account availability.
pub(super) const OPENAI_API_MODEL_PREFERENCE: &[&str] = &[
    "gpt-6-astra",
    "gpt-5.6-sol",
    "gpt-5.6-terra",
    "gpt-5.6-luna",
    "gpt-5.5",
];

pub(super) fn is_builtin_openai_entry(entry: &ProviderEntry) -> bool {
    entry.id() == "openai"
        && entry.origin == ProviderOrigin::Builtin
        && entry.instance.adapter() == AdapterKind::OpenAiResponses
        && entry.instance.api_root().as_str() == OPENAI_API_ROOT
}

#[cfg(test)]
pub(super) fn entry_from_config(config: &ProviderConfig) -> anyhow::Result<ProviderEntry> {
    entry_from_config_with_metadata(config, StaticProviderMetadata::embedded())
}

pub(super) fn entry_from_config_with_metadata(
    config: &ProviderConfig,
    static_metadata: Arc<StaticProviderMetadata>,
) -> anyhow::Result<ProviderEntry> {
    let adapter = match config.adapter.as_str() {
        "anthropic_messages" => AdapterKind::AnthropicMessages,
        "openai_responses" => AdapterKind::OpenAiResponses,
        "openai_chat" => AdapterKind::OpenAiCompatibleChat,
        _ => anyhow::bail!("provider `{}` has an unsupported adapter", config.id),
    };
    let credential = config.resolved_credential().map_err(anyhow::Error::msg)?;
    let display_name = config.display_name.as_deref().unwrap_or(&config.id);
    let mut instance = ProviderInstance::new(
        config.id.clone(),
        display_name,
        adapter,
        ApiRoot::parse(&config.api_root)?,
        None,
    )?
    .with_credential_source(credential_source(&credential))
    .with_static_metadata(static_metadata);
    if let Some(profile) = config.error_profile.as_deref() {
        let profile = match profile {
            "anthropic" => ErrorProfile::Anthropic,
            "openai" => ErrorProfile::OpenAi,
            "deepseek" => ErrorProfile::DeepSeek,
            "glm" => ErrorProfile::Glm,
            "minimax" => ErrorProfile::MiniMax,
            "fireworks" => ErrorProfile::Fireworks,
            "custom" => ErrorProfile::CustomConservative,
            unsupported => anyhow::bail!(
                "provider `{}` has unsupported error_profile `{unsupported}`",
                config.id
            ),
        };
        instance = instance.with_error_profile(profile);
    }
    let (catalog_enabled, catalog_error) = catalog_configuration(&instance, config.catalog);
    // An operator manifest is an explicit coding-turn compatibility declaration. It is used only
    // when discovery is unavailable or deliberately disabled, so it cannot silently override an
    // authoritative provider catalog. The dedicated family also makes the manual provenance
    // visible in the hierarchical picker without changing the provider-domain descriptor schema.
    let catalog = (!catalog_enabled)
        .then(|| operator_manifest_catalog(&instance, &config.models))
        .flatten();
    let catalog_provenance = if catalog.is_some() {
        CatalogProvenance::OperatorManifest
    } else if !catalog_enabled {
        CatalogProvenance::OperatorExplicit
    } else {
        CatalogProvenance::Unavailable
    };
    // Same fact as for a built-in, computed from whatever source the operator declared. It never
    // gates this entry's visibility — an operator-configured provider is always offered — but it
    // keeps `credential_present` meaning one thing across both origins.
    let credential_present = instance.has_credential();
    Ok(ProviderEntry {
        instance,
        credential,
        origin: ProviderOrigin::OperatorConfigured,
        credential_present,
        enabled: config.enabled,
        catalog_enabled,
        catalog,
        catalog_error,
        catalog_fallback_explicit: false,
        catalog_stale: false,
        catalog_provenance,
        declared_capabilities: config.model_capabilities.clone(),
    })
}

/// Build a deterministic catalog from operator-declared coding-turn model ids. `None` preserves
/// explicit `provider:model-id` fallback for legacy manual providers with no manifest (including
/// built-in GLM), while a non-empty manifest closes selection to precisely the declared leaves.
fn operator_manifest_catalog(
    instance: &ProviderInstance,
    model_ids: &[String],
) -> Option<CatalogSnapshot> {
    if model_ids.is_empty() {
        return None;
    }
    let mut ids = model_ids.to_vec();
    ids.sort();
    ids.dedup();
    let models = ids
        .into_iter()
        .map(|id| ModelDescriptor {
            raw: RawModel {
                display_name: Some(id.clone()),
                id,
                created_at: None,
                owned_by: None,
                supports_image_input: None,
            },
            family_id: "manual".into(),
            compatibility: Compatibility::Compatible,
            selectability: Selectability::Selectable,
        })
        .collect::<Vec<_>>();
    Some(CatalogSnapshot {
        provider_instance_id: instance.id().into(),
        adapter: instance.adapter(),
        families: vec![ModelFamily {
            id: "manual".into(),
            display_name: "Manual / operator declared".into(),
            models: models.clone(),
        }],
        models,
    })
}

/// Convert a provider's catalog strategy into the effective CLI behavior. An unsupported catalog
/// is not a failed account: keep the provider selectable through an explicit `provider:model-id`,
/// retain the reason for the picker, and never guess a `/models` URL from the inference root.
pub(super) fn catalog_configuration(
    instance: &ProviderInstance,
    requested: bool,
) -> (bool, Option<String>) {
    match instance.catalog_strategy() {
        CatalogStrategy::Unsupported { reason } => (
            false,
            Some(format!(
                "catalog unsupported: {reason}; select explicitly with /model {}:<model-id>",
                instance.id()
            )),
        ),
        _ => (requested, None),
    }
}

pub(super) fn manual_model_allowed(entry: &ProviderEntry) -> bool {
    entry.catalog_fallback_explicit
        || !entry.catalog_enabled
        || matches!(
            entry.instance.catalog_strategy(),
            CatalogStrategy::Unsupported { .. }
        )
}

/// Account probes are an explicit provider capability, never inferred merely from compatible wire
/// syntax. DeepSeek exposes a normal-key balance check; Fireworks exposes suspend state on its
/// separate control plane. All other accounts honestly remain balance-unknown until a typed error.
///
/// `catalog = false` is documented as the operator's opt-out from speculative discovery requests
/// for that instance. It used to gate only `/models` while the account probe kept firing, so the
/// documented "no discovery traffic" setting still produced a round trip on every launch.
pub(super) fn account_probe_for(entry: &ProviderEntry) -> Option<AccountProbe> {
    if !entry.catalog_enabled {
        return None;
    }
    if entry.id() == "deepseek" && entry.instance.api_root().as_str() == DEEPSEEK_API_ROOT {
        Some(AccountProbe::DeepSeekBalance)
    } else if matches!(
        entry.instance.catalog_strategy(),
        CatalogStrategy::FireworksControlPlane { .. }
    ) {
        Some(AccountProbe::FireworksSuspendState)
    } else {
        None
    }
}

/// Apply the small provider-specific overlay that cannot be recovered from the generic OpenAI
/// model-list schema. Fireworks is intentionally absent: its control-plane descriptors already
/// carry authoritative chat/tool/serverless/readiness metadata and must never be weakened by a
/// name heuristic.
pub(super) fn apply_provider_catalog_policy(entry: &ProviderEntry, catalog: &mut CatalogSnapshot) {
    let policy = if entry.instance.api_root().as_str() == MINIMAX_API_ROOT {
        CatalogOverlay::MiniMax
    } else if entry.id() == "openai" && entry.instance.api_root().as_str() == OPENAI_API_ROOT {
        CatalogOverlay::OpenAi
    } else {
        CatalogOverlay::None
    };
    if policy == CatalogOverlay::None {
        return;
    }

    for model in &mut catalog.models {
        apply_model_overlay(policy, model);
    }
    // Families contain descriptor clones for stable tree rendering; update those copies too.
    for family in &mut catalog.families {
        for model in &mut family.models {
            apply_model_overlay(policy, model);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CatalogOverlay {
    None,
    MiniMax,
    OpenAi,
}

fn apply_model_overlay(policy: CatalogOverlay, model: &mut iteron_provider::ModelDescriptor) {
    if model.compatibility != Compatibility::Unknown {
        return;
    }
    let compatible = match policy {
        CatalogOverlay::MiniMax => model.raw.id.to_ascii_lowercase().starts_with("minimax-"),
        CatalogOverlay::OpenAi => is_openai_fine_tuned_text_model(&model.raw.id),
        CatalogOverlay::None => false,
    };
    if compatible {
        model.compatibility = Compatibility::Compatible;
        model.selectability = Selectability::Selectable;
    }
}

pub(super) fn is_openai_fine_tuned_text_model(model_id: &str) -> bool {
    let Some(base) = model_id
        .to_ascii_lowercase()
        .strip_prefix("ft:")
        .and_then(|rest| rest.split(':').next())
        .map(str::to_owned)
    else {
        return false;
    };
    ["gpt-", "chatgpt-", "o1", "o3", "o4", "codex"]
        .iter()
        .any(|prefix| base.starts_with(prefix))
}

/// Every provider id this configuration can route to, built-ins first. `iteron setup` offers these
/// and refuses anything else, so a typo is caught before a credential is written for a route that
/// does not exist.
///
/// DELIBERATELY UNFILTERED, and it must stay that way. `/model` and `iteron auth status` hide a
/// built-in with no credential (see [`ProviderEntry::is_offerable`]); this list must not, because
/// `iteron setup` exists precisely to give a credential to a provider that has none. Applying the
/// display filter here would make every uncredentialed provider permanently unconfigurable — the
/// only way to get a credential would be to already have one. The inconsistency is the point.
pub(crate) fn configured_provider_ids(user: &[ProviderConfig]) -> Vec<String> {
    let mut ids: Vec<String> = BUILTINS
        .iter()
        .map(|builtin| builtin.id.to_owned())
        .collect();
    for configured in user {
        if !ids.iter().any(|id| id == &configured.id) {
            ids.push(configured.id.clone());
        }
    }
    ids
}

/// Build the exact route a provider id resolves to, with a candidate credential supplied directly
/// and nothing persisted. This is what lets `iteron setup` reject a wrong key BEFORE writing it.
pub(super) fn candidate_instance(
    provider_id: &str,
    user: &[ProviderConfig],
    credential: &str,
) -> anyhow::Result<ProviderInstance> {
    let metadata = load_static_provider_metadata()?;
    if let Some(builtin) = BUILTINS.iter().find(|builtin| builtin.id == provider_id) {
        return Ok(ProviderInstance::new(
            builtin.id,
            builtin.display_name,
            builtin.adapter,
            ApiRoot::parse(builtin.api_root)?,
            Some(credential.to_owned()),
        )?
        .with_static_metadata(metadata));
    }
    let configured = user
        .iter()
        .find(|configured| configured.id == provider_id)
        .ok_or_else(|| anyhow::anyhow!("provider `{provider_id}` is not configured"))?;
    let mut entry = entry_from_config_with_metadata(configured, metadata)?;
    entry.instance = entry
        .instance
        .with_credential_source(CredentialSource::env_value(Some(credential.to_owned())));
    Ok(entry.instance)
}

fn environment_credential(key_env: &str) -> Option<String> {
    std::env::var(key_env)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

/// Turn a declared credential into the live source a provider resolves on every turn.
///
/// The env variant keeps the historical snapshot: a running process's own environment is not a
/// rotation channel, and re-reading it would change nothing except the failure mode. The file
/// variant is genuinely re-read, which is what lets a hosted subscription token rotate under a
/// running Core (I-22).
fn credential_source(credential: &ProviderCredential) -> CredentialSource {
    match credential {
        ProviderCredential::Env { name } => {
            CredentialSource::env(name.clone(), environment_credential(name))
        }
        ProviderCredential::File { path } => CredentialSource::file(PathBuf::from(path)),
    }
}

/// The credential a built-in provider uses.
///
/// The environment variable still wins: exporting a key is the explicit, per-invocation override
/// and must behave exactly as before. Only when it is absent does a built-in fall back to the
/// credential file `iteron setup` writes, which is what makes the wizard reach a working first turn
/// without asking an operator to edit `providers` by hand (a built-in id may not be redeclared
/// there at all).
fn builtin_credential(provider_id: &str, key_env: &'static str) -> ProviderCredential {
    if environment_credential(key_env).is_some() {
        return ProviderCredential::Env {
            name: key_env.into(),
        };
    }
    match crate::config::credential_file_path(provider_id) {
        Some(path) if path.exists() => ProviderCredential::File {
            path: path.display().to_string(),
        },
        // Naming the variable an operator would export keeps the "missing credential" line
        // actionable; a path that does not exist would only say where nothing is.
        _ => ProviderCredential::Env {
            name: key_env.into(),
        },
    }
}
