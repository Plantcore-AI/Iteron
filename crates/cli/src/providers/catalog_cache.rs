//! Private credential-scoped last-known catalog store and its validated serialized candidates.
use super::cache_storage::{
    CatalogCacheScopeKey, credential_scope, valid_credential_scope, write_private_file_atomic,
};
use super::{
    CATALOG_CACHE_FILE, CATALOG_CACHE_FUTURE_SKEW_SECS, CATALOG_CACHE_TTL_SECS,
    CATALOG_CACHE_VERSION, CATALOG_CLASSIFIER_VERSION, CatalogProvenance,
    MAX_CACHED_FAMILIES_PER_ENTRY, MAX_CACHED_MODELS_PER_ENTRY, MAX_CACHED_MODELS_TOTAL,
    MAX_CACHED_TEXT_BYTES, MAX_CATALOG_CACHE_BYTES, MAX_CATALOG_CACHE_ENTRIES, ProviderEntry,
    adapter_key, catalog_strategy_key, current_unix_secs, valid_cached_optional_text,
    valid_cached_text,
};
use iteron_provider::{
    ApiRoot, CatalogSnapshot, Compatibility, ModelDescriptor, ModelFamily, ProviderInstance,
    RawModel, Selectability,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CatalogCache {
    version: u32,
    entries: Vec<CachedCatalog>,
}

impl Default for CatalogCache {
    fn default() -> Self {
        Self {
            version: CATALOG_CACHE_VERSION,
            entries: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CachedCatalog {
    pub(super) provider_id: String,
    pub(super) api_root: String,
    pub(super) catalog_strategy: String,
    pub(super) adapter: String,
    pub(super) credential_scope: String,
    pub(super) fetched_at_unix_secs: u64,
    pub(super) classifier_version: u32,
    pub(super) families: Vec<CachedFamily>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CachedFamily {
    pub(super) id: String,
    pub(super) display_name: String,
    pub(super) models: Vec<CachedModel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CachedModel {
    pub(super) id: String,
    pub(super) display_name: Option<String>,
    pub(super) created_at: Option<String>,
    pub(super) owned_by: Option<String>,
    pub(super) supports_image_input: Option<bool>,
    pub(super) compatibility: CachedCompatibility,
    pub(super) selectability: CachedSelectability,
}

type CatalogCacheIdentity = (String, String, String, String, String);

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CachedCompatibility {
    Compatible,
    Unknown,
    Incompatible,
}

/// Stable codes for Core-owned policy reasons. Provider error bodies are deliberately not a
/// variant: only reasons emitted by our catalog classifier may cross the persistence boundary.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CachedSelectability {
    Selectable,
    CompatibilityUnknown,
    NotCodingTurn,
    FireworksConflictingMetadata,
    FireworksNotReady,
    FireworksStatusNotOk,
    FireworksNoServerlessDeployment,
    FireworksPrivateNoHealthyDeployment,
    FireworksNotPublic,
    FireworksChatDisabled,
    FireworksNoToolCalling,
    FireworksAccountBillingBlocked,
    FireworksAccountPermissionBlocked,
    FireworksAccountMetadataConflicting,
}

impl CachedSelectability {
    fn from_live(value: &Selectability) -> Option<Self> {
        match value {
            Selectability::Selectable => Some(Self::Selectable),
            Selectability::Disabled { reason } => match *reason {
                "coding-turn compatibility is unknown" => Some(Self::CompatibilityUnknown),
                "model is not a coding-turn model" => Some(Self::NotCodingTurn),
                "Fireworks returned conflicting metadata for this model" => {
                    Some(Self::FireworksConflictingMetadata)
                }
                "Fireworks model is not ready" => Some(Self::FireworksNotReady),
                "Fireworks model status is not OK" => Some(Self::FireworksStatusNotOk),
                "Fireworks model has no serverless deployment" => {
                    Some(Self::FireworksNoServerlessDeployment)
                }
                "private model has no healthy default deployment; Iteron does not infer #deployment routing" => {
                    Some(Self::FireworksPrivateNoHealthyDeployment)
                }
                "Fireworks public catalog model is not marked public" => {
                    Some(Self::FireworksNotPublic)
                }
                "Fireworks Chat Completions is not enabled for this model" => {
                    Some(Self::FireworksChatDisabled)
                }
                "Fireworks model does not advertise tool calling" => {
                    Some(Self::FireworksNoToolCalling)
                }
                "Fireworks account billing is blocked" => {
                    Some(Self::FireworksAccountBillingBlocked)
                }
                "Fireworks account permission is blocked" => {
                    Some(Self::FireworksAccountPermissionBlocked)
                }
                "Fireworks account metadata is conflicting" => {
                    Some(Self::FireworksAccountMetadataConflicting)
                }
                _ => None,
            },
        }
    }

    fn to_live(self) -> Selectability {
        match self {
            Self::Selectable => Selectability::Selectable,
            Self::CompatibilityUnknown => Selectability::Disabled {
                reason: "coding-turn compatibility is unknown",
            },
            Self::NotCodingTurn => Selectability::Disabled {
                reason: "model is not a coding-turn model",
            },
            Self::FireworksConflictingMetadata => Selectability::Disabled {
                reason: "Fireworks returned conflicting metadata for this model",
            },
            Self::FireworksNotReady => Selectability::Disabled {
                reason: "Fireworks model is not ready",
            },
            Self::FireworksStatusNotOk => Selectability::Disabled {
                reason: "Fireworks model status is not OK",
            },
            Self::FireworksNoServerlessDeployment => Selectability::Disabled {
                reason: "Fireworks model has no serverless deployment",
            },
            Self::FireworksPrivateNoHealthyDeployment => Selectability::Disabled {
                reason: "private model has no healthy default deployment; Iteron does not infer #deployment routing",
            },
            Self::FireworksNotPublic => Selectability::Disabled {
                reason: "Fireworks public catalog model is not marked public",
            },
            Self::FireworksChatDisabled => Selectability::Disabled {
                reason: "Fireworks Chat Completions is not enabled for this model",
            },
            Self::FireworksNoToolCalling => Selectability::Disabled {
                reason: "Fireworks model does not advertise tool calling",
            },
            Self::FireworksAccountBillingBlocked => Selectability::Disabled {
                reason: "Fireworks account billing is blocked",
            },
            Self::FireworksAccountPermissionBlocked => Selectability::Disabled {
                reason: "Fireworks account permission is blocked",
            },
            Self::FireworksAccountMetadataConflicting => Selectability::Disabled {
                reason: "Fireworks account metadata is conflicting",
            },
        }
    }
}

impl CatalogCache {
    pub(super) fn load(path: &Path) -> Self {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return Self::default();
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len()
                > iteron_tunables::param_integer(
                    "cli.providers.max_catalog_cache_bytes",
                    MAX_CATALOG_CACHE_BYTES,
                ) as u64
        {
            return Self::default();
        }
        let Ok(file) = File::open(path) else {
            return Self::default();
        };
        #[cfg(unix)]
        let Ok(opened_metadata) = file.metadata() else {
            return Self::default();
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.dev() != opened_metadata.dev()
                || metadata.ino() != opened_metadata.ino()
                || opened_metadata.mode() & 0o077 != 0
            {
                return Self::default();
            }
        }
        // Do not trust the metadata/read gap: another process could grow the file after the size
        // check. `take(MAX + 1)` makes the actual allocation/read bound authoritative.
        let mut bytes = Vec::with_capacity(metadata.len() as usize + 1);
        let Ok(_) = file
            .take(
                (iteron_tunables::param_integer(
                    "cli.providers.max_catalog_cache_bytes",
                    MAX_CATALOG_CACHE_BYTES,
                ) + 1) as u64,
            )
            .read_to_end(&mut bytes)
        else {
            return Self::default();
        };
        if bytes.len()
            > iteron_tunables::param_integer(
                "cli.providers.max_catalog_cache_bytes",
                MAX_CATALOG_CACHE_BYTES,
            )
        {
            return Self::default();
        }
        serde_json::from_slice::<Self>(&bytes)
            .ok()
            .filter(Self::is_valid)
            .unwrap_or_default()
    }

    pub(super) fn is_valid(&self) -> bool {
        if self.version != CATALOG_CACHE_VERSION || self.entries.len() > MAX_CATALOG_CACHE_ENTRIES {
            return false;
        }
        let mut identities = BTreeSet::new();
        let mut total_models = 0usize;
        for entry in &self.entries {
            if !entry.is_valid() || !identities.insert(entry.identity()) {
                return false;
            }
            let Some(next) = total_models.checked_add(entry.model_count()) else {
                return false;
            };
            total_models = next;
            if total_models
                > iteron_tunables::param_integer(
                    "cli.providers.max_cached_models_total",
                    MAX_CACHED_MODELS_TOTAL,
                )
            {
                return false;
            }
        }
        true
    }

    pub(super) fn lookup(
        &self,
        entry: &ProviderEntry,
        scope_key: &CatalogCacheScopeKey,
    ) -> Option<CatalogSnapshot> {
        let identity = cache_identity(entry, scope_key)?;
        self.entries
            .iter()
            .rev()
            .find(|cached| cached.identity() == identity && cached.is_fresh())
            .and_then(|cached| cached.to_snapshot(&entry.instance, scope_key))
    }

    pub(super) fn upsert(
        &mut self,
        entry: &ProviderEntry,
        scope_key: &CatalogCacheScopeKey,
    ) -> bool {
        let Some(cached) = CachedCatalog::from_entry(entry, scope_key) else {
            return false;
        };
        // One current LKG per logical provider id. A root/strategy change deliberately cannot
        // reuse the old entry; replacing it also prevents dead identities accumulating forever.
        self.entries
            .retain(|existing| existing.provider_id != cached.provider_id);
        self.entries.push(cached);
        while self.entries.len() > MAX_CATALOG_CACHE_ENTRIES
            || self.total_models()
                > iteron_tunables::param_integer(
                    "cli.providers.max_cached_models_total",
                    MAX_CACHED_MODELS_TOTAL,
                )
        {
            self.entries.remove(0);
        }
        true
    }

    fn total_models(&self) -> usize {
        self.entries.iter().map(CachedCatalog::model_count).sum()
    }

    pub(super) fn save_atomic(&mut self, path: &Path) -> io::Result<()> {
        self.version = CATALOG_CACHE_VERSION;
        let bytes = loop {
            let bytes = serde_json::to_vec(self).map_err(io::Error::other)?;
            if bytes.len()
                <= iteron_tunables::param_integer(
                    "cli.providers.max_catalog_cache_bytes",
                    MAX_CATALOG_CACHE_BYTES,
                )
            {
                break bytes;
            }
            if self.entries.len() <= 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "provider catalog cache entry exceeds byte bound",
                ));
            }
            self.entries.remove(0);
        };
        write_private_file_atomic(path, &bytes, CATALOG_CACHE_FILE)
    }
}

impl CachedCatalog {
    pub(super) fn from_entry(
        entry: &ProviderEntry,
        scope_key: &CatalogCacheScopeKey,
    ) -> Option<Self> {
        if !entry.catalog_enabled
            || entry.catalog_stale
            || entry.catalog_provenance != CatalogProvenance::DynamicFresh
        {
            return None;
        }
        let catalog = entry.catalog.as_ref()?;
        let families = catalog
            .families
            .iter()
            .map(|family| {
                let models = family
                    .models
                    .iter()
                    .map(|model| {
                        Some(CachedModel {
                            id: model.raw.id.clone(),
                            display_name: model.raw.display_name.clone(),
                            created_at: model.raw.created_at.clone(),
                            owned_by: model.raw.owned_by.clone(),
                            supports_image_input: model.raw.supports_image_input,
                            compatibility: match model.compatibility {
                                Compatibility::Compatible => CachedCompatibility::Compatible,
                                Compatibility::Unknown => CachedCompatibility::Unknown,
                                Compatibility::Incompatible => CachedCompatibility::Incompatible,
                            },
                            selectability: CachedSelectability::from_live(&model.selectability)?,
                        })
                    })
                    .collect::<Option<Vec<_>>>()?;
                Some(CachedFamily {
                    id: family.id.clone(),
                    display_name: family.display_name.clone(),
                    models,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        let cached = Self {
            provider_id: entry.id().into(),
            api_root: entry.instance.api_root().as_str().into(),
            catalog_strategy: catalog_strategy_key(entry.instance.catalog_strategy()),
            adapter: adapter_key(entry.instance.adapter()).into(),
            credential_scope: credential_scope(&entry.instance, scope_key)?,
            fetched_at_unix_secs: current_unix_secs()?,
            classifier_version: CATALOG_CLASSIFIER_VERSION,
            families,
        };
        cached.is_valid().then_some(cached)
    }

    pub(super) fn is_valid(&self) -> bool {
        if !valid_cached_text(&self.provider_id, 128, false)
            || !valid_cached_text(&self.api_root, 2_048, false)
            || ApiRoot::parse(&self.api_root)
                .ok()
                .is_none_or(|root| root.as_str() != self.api_root)
            || !valid_cached_text(&self.catalog_strategy, 2_048, false)
            || !matches!(
                self.adapter.as_str(),
                "anthropic_messages" | "openai_chat" | "openai_responses"
            )
            || !valid_credential_scope(&self.credential_scope)
            || self.fetched_at_unix_secs == 0
            || self.classifier_version != CATALOG_CLASSIFIER_VERSION
            || current_unix_secs().is_none_or(|now| {
                self.fetched_at_unix_secs
                    > now.saturating_add(iteron_tunables::param_integer(
                        "cli.providers.catalog_cache_future_skew_secs",
                        CATALOG_CACHE_FUTURE_SKEW_SECS,
                    ))
            })
            || self.families.len()
                > iteron_tunables::param_integer(
                    "cli.providers.max_cached_families_per_entry",
                    MAX_CACHED_FAMILIES_PER_ENTRY,
                )
            || self.model_count()
                > iteron_tunables::param_integer(
                    "cli.providers.max_cached_models_per_entry",
                    MAX_CACHED_MODELS_PER_ENTRY,
                )
        {
            return false;
        }
        let mut family_ids = BTreeSet::new();
        let mut model_ids = BTreeSet::new();
        self.families.iter().all(|family| {
            valid_cached_text(
                &family.id,
                iteron_tunables::param_integer(
                    "cli.providers.max_cached_text_bytes",
                    MAX_CACHED_TEXT_BYTES,
                ),
                false,
            ) && valid_cached_text(
                &family.display_name,
                iteron_tunables::param_integer(
                    "cli.providers.max_cached_text_bytes",
                    MAX_CACHED_TEXT_BYTES,
                ),
                false,
            ) && family_ids.insert(family.id.as_str())
                && family.models.iter().all(|model| {
                    valid_cached_text(
                        &model.id,
                        iteron_tunables::param_integer(
                            "cli.providers.max_cached_text_bytes",
                            MAX_CACHED_TEXT_BYTES,
                        ),
                        false,
                    ) && valid_cached_optional_text(model.display_name.as_deref())
                        && valid_cached_optional_text(model.created_at.as_deref())
                        && valid_cached_optional_text(model.owned_by.as_deref())
                        && model_ids.insert(model.id.as_str())
                })
        })
    }

    fn identity(&self) -> CatalogCacheIdentity {
        (
            self.provider_id.clone(),
            self.api_root.clone(),
            self.catalog_strategy.clone(),
            self.adapter.clone(),
            self.credential_scope.clone(),
        )
    }

    fn model_count(&self) -> usize {
        self.families.iter().map(|family| family.models.len()).sum()
    }

    fn is_fresh(&self) -> bool {
        current_unix_secs().is_some_and(|now| {
            now.saturating_sub(self.fetched_at_unix_secs)
                <= iteron_tunables::param_integer(
                    "cli.providers.catalog_cache_ttl_secs",
                    CATALOG_CACHE_TTL_SECS,
                )
                && self.fetched_at_unix_secs
                    <= now.saturating_add(iteron_tunables::param_integer(
                        "cli.providers.catalog_cache_future_skew_secs",
                        CATALOG_CACHE_FUTURE_SKEW_SECS,
                    ))
        })
    }

    fn to_snapshot(
        &self,
        instance: &ProviderInstance,
        scope_key: &CatalogCacheScopeKey,
    ) -> Option<CatalogSnapshot> {
        if self.identity() != cache_identity_for_instance(instance, scope_key)? || !self.is_valid()
        {
            return None;
        }
        let mut models = Vec::with_capacity(self.model_count());
        let families = self
            .families
            .iter()
            .map(|family| {
                let family_models = family
                    .models
                    .iter()
                    .map(|model| ModelDescriptor {
                        raw: RawModel {
                            id: model.id.clone(),
                            display_name: model.display_name.clone(),
                            created_at: model.created_at.clone(),
                            owned_by: model.owned_by.clone(),
                            supports_image_input: model.supports_image_input,
                        },
                        family_id: family.id.clone(),
                        compatibility: match model.compatibility {
                            CachedCompatibility::Compatible => Compatibility::Compatible,
                            CachedCompatibility::Unknown => Compatibility::Unknown,
                            CachedCompatibility::Incompatible => Compatibility::Incompatible,
                        },
                        selectability: model.selectability.to_live(),
                    })
                    .collect::<Vec<_>>();
                models.extend(family_models.iter().cloned());
                ModelFamily {
                    id: family.id.clone(),
                    display_name: family.display_name.clone(),
                    models: family_models,
                }
            })
            .collect();
        models.sort_by(|left, right| left.raw.id.cmp(&right.raw.id));
        Some(CatalogSnapshot {
            provider_instance_id: instance.id().into(),
            adapter: instance.adapter(),
            models,
            families,
        })
    }
}

#[cfg(test)]
impl CatalogCache {
    pub(super) fn fixture_parts(version: u32, entries: Vec<CachedCatalog>) -> Self {
        Self { version, entries }
    }
    pub(super) fn fixture_entries(&self) -> &[CachedCatalog] {
        &self.entries
    }
    pub(super) fn fixture_version(&self) -> u32 {
        self.version
    }
}

fn cache_identity(
    entry: &ProviderEntry,
    scope_key: &CatalogCacheScopeKey,
) -> Option<CatalogCacheIdentity> {
    cache_identity_for_instance(&entry.instance, scope_key)
}

fn cache_identity_for_instance(
    instance: &ProviderInstance,
    scope_key: &CatalogCacheScopeKey,
) -> Option<CatalogCacheIdentity> {
    Some((
        instance.id().into(),
        instance.api_root().as_str().into(),
        catalog_strategy_key(instance.catalog_strategy()),
        adapter_key(instance.adapter()).into(),
        credential_scope(instance, scope_key)?,
    ))
}
