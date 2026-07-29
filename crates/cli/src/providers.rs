//! Operator-owned provider instances and their dynamic model catalogs.
//!
//! This module is the CLI-side composition layer. Wire protocols and error classification live in
//! `core-provider`; this layer supplies built-in instance definitions, merges trusted user config,
//! performs bounded discovery concurrently, and resolves an explicit `(provider, model)` pair.

use crate::config::ProviderConfig;
use core_provider::catalog::glm_standard_schema_catalog;
use core_provider::{
    AccountAvailability, AccountProbe, AccountProbeResult, AdapterKind, ApiRoot,
    BalanceAvailability, CatalogSnapshot, CatalogStrategy, Compatibility, ErrorProfile,
    HealthReportingProvider, ModelDescriptor, ModelFamily, Provider, ProviderError, ProviderHealth,
    ProviderHealthStore, ProviderInstance, RawModel, Selectability, StaticProviderMetadata,
    StreamItem, TurnRequest, TurnResult, discover_catalog, probe_account,
};
use futures_util::future::join_all;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::time::{SystemTime, UNIX_EPOCH};

// Six built-ins plus at most 64 trusted custom instances (the config validator's ceiling).
const MAX_PROVIDER_INSTANCES: usize = 70;
const OPENAI_API_ROOT: &str = "https://api.openai.com/v1";
const DEEPSEEK_API_ROOT: &str = "https://api.deepseek.com";
const MINIMAX_API_ROOT: &str = "https://api.minimax.io/v1";
const CATALOG_CACHE_VERSION: u32 = 3;
const CATALOG_CLASSIFIER_VERSION: u32 = 1;
const CATALOG_CACHE_FILE: &str = "catalogs-v3.json";
const CATALOG_CACHE_SCOPE_KEY_FILE: &str = "catalog-scope-v1.key";
const CATALOG_CACHE_SCOPE_KEY_BYTES: usize = 32;
const CATALOG_CACHE_SCOPE_PREFIX: &str = "hmac-sha256:";
const CATALOG_CACHE_TTL_SECS: u64 = 30 * 24 * 60 * 60;
const CATALOG_CACHE_FUTURE_SKEW_SECS: u64 = 24 * 60 * 60;
const MAX_CATALOG_CACHE_BYTES: usize = 16 * 1024 * 1024;
const MAX_CATALOG_CACHE_ENTRIES: usize = MAX_PROVIDER_INSTANCES;
const MAX_CACHED_MODELS_PER_ENTRY: usize = 10_000;
const MAX_CACHED_MODELS_TOTAL: usize = 50_000;
const MAX_CACHED_FAMILIES_PER_ENTRY: usize = 1_024;
const MAX_CACHED_TEXT_BYTES: usize = 512;
const STATIC_PROVIDER_METADATA_FILE: &str = "provider-metadata.json";
static CACHE_TEMP_NONCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModelSelection {
    pub provider_id: String,
    pub model_id: String,
}

/// Versioned, provenance-bearing execution limits for one exact route. Unknown fields remain
/// `None`; dynamic model visibility never implies undocumented capacity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModelCapabilities {
    pub context_window_tokens: Option<u64>,
    pub max_output_tokens: Option<u32>,
    pub tool_calling: Option<bool>,
    pub semantic_effort: Option<bool>,
    pub version: Option<String>,
    pub source: Option<String>,
}

impl ModelCapabilities {
    const fn unknown() -> Self {
        Self {
            context_window_tokens: None,
            max_output_tokens: None,
            tool_calling: None,
            semantic_effort: None,
            version: None,
            source: None,
        }
    }
}

/// Stable evidence class for the model inventory attached to one provider entry. This is kept
/// separate from the snapshot itself so equal model ids cannot make operator, static, cached and
/// credential-visible catalogs hash to the same provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CatalogProvenance {
    Unavailable,
    DynamicFresh,
    /// A still-valid, credential-scoped snapshot loaded without another discovery request.
    CachedFresh,
    StaticOfficial {
        version: String,
        source: String,
    },
    OperatorManifest,
    OperatorExplicit,
}

#[derive(Clone)]
pub(crate) struct ProviderEntry {
    pub instance: ProviderInstance,
    pub key_env: String,
    pub enabled: bool,
    pub catalog_enabled: bool,
    pub catalog: Option<CatalogSnapshot>,
    pub catalog_error: Option<String>,
    /// A discovery failure that is not evidence about inference authorization. The hierarchical
    /// picker remains fail-closed, but an operator may explicitly type `provider:model-id`.
    pub catalog_fallback_explicit: bool,
    /// True only for cached display evidence that must not authorize a picker selection.
    pub catalog_stale: bool,
    catalog_provenance: CatalogProvenance,
}

impl ProviderEntry {
    pub fn id(&self) -> &str {
        self.instance.id()
    }

    pub fn display_name(&self) -> &str {
        self.instance.display_name()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogCache {
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
struct CachedCatalog {
    provider_id: String,
    api_root: String,
    catalog_strategy: String,
    adapter: String,
    credential_scope: String,
    fetched_at_unix_secs: u64,
    classifier_version: u32,
    families: Vec<CachedFamily>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CachedFamily {
    id: String,
    display_name: String,
    models: Vec<CachedModel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CachedModel {
    id: String,
    display_name: Option<String>,
    created_at: Option<String>,
    owned_by: Option<String>,
    compatibility: CachedCompatibility,
    selectability: CachedSelectability,
}

/// Installation-local HMAC key used only to bind credential-visible inventory to the credential
/// that produced it. The key has no serde/debug surface and is kept in a separate fixed-size file;
/// Unix additionally enforces exact owner/0600 metadata, while Windows rejects reparse paths and
/// inherits the operator cache directory's ACL.
#[derive(Clone)]
struct CatalogCacheScopeKey([u8; CATALOG_CACHE_SCOPE_KEY_BYTES]);

type CatalogCacheIdentity = (String, String, String, String, String);

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CachedCompatibility {
    Compatible,
    Unknown,
    Incompatible,
}

/// Stable codes for Core-owned policy reasons. Provider error bodies are deliberately not a
/// variant: only reasons emitted by our catalog classifier may cross the persistence boundary.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CachedSelectability {
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
                "private model has no healthy default deployment; Core does not infer #deployment routing" => {
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
                reason: "private model has no healthy default deployment; Core does not infer #deployment routing",
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
    fn load(path: &Path) -> Self {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return Self::default();
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_CATALOG_CACHE_BYTES as u64
        {
            return Self::default();
        }
        let Ok(file) = File::open(path) else {
            return Self::default();
        };
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
            .take((MAX_CATALOG_CACHE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
        else {
            return Self::default();
        };
        if bytes.len() > MAX_CATALOG_CACHE_BYTES {
            return Self::default();
        }
        serde_json::from_slice::<Self>(&bytes)
            .ok()
            .filter(Self::is_valid)
            .unwrap_or_default()
    }

    fn is_valid(&self) -> bool {
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
            if total_models > MAX_CACHED_MODELS_TOTAL {
                return false;
            }
        }
        true
    }

    fn lookup(
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

    fn upsert(&mut self, entry: &ProviderEntry, scope_key: &CatalogCacheScopeKey) -> bool {
        let Some(cached) = CachedCatalog::from_entry(entry, scope_key) else {
            return false;
        };
        // One current LKG per logical provider id. A root/strategy change deliberately cannot
        // reuse the old entry; replacing it also prevents dead identities accumulating forever.
        self.entries
            .retain(|existing| existing.provider_id != cached.provider_id);
        self.entries.push(cached);
        while self.entries.len() > MAX_CATALOG_CACHE_ENTRIES
            || self.total_models() > MAX_CACHED_MODELS_TOTAL
        {
            self.entries.remove(0);
        }
        true
    }

    fn total_models(&self) -> usize {
        self.entries.iter().map(CachedCatalog::model_count).sum()
    }

    fn save_atomic(&mut self, path: &Path) -> io::Result<()> {
        self.version = CATALOG_CACHE_VERSION;
        let bytes = loop {
            let bytes = serde_json::to_vec(self).map_err(io::Error::other)?;
            if bytes.len() <= MAX_CATALOG_CACHE_BYTES {
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

        let parent = path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "cache path has no parent")
        })?;
        let directory = prepare_private_cache_directory(parent)?;
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(CATALOG_CACHE_FILE);
        let mut temporary = None;
        let nonce = CACHE_TEMP_NONCE.fetch_add(1, AtomicOrdering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        for attempt in 0..16u8 {
            let candidate = parent.join(format!(
                ".{file_name}.tmp-{}-{timestamp:x}-{nonce:x}-{attempt}",
                std::process::id()
            ));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&candidate) {
                Ok(file) => {
                    temporary = Some((candidate, file));
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        let Some((temporary_path, mut file)) = temporary else {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not reserve an atomic provider-cache temporary file",
            ));
        };
        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary_path, path)?;
            // Persist the rename itself where the platform supports directory fsync.
            if let Some(directory) = directory {
                let _ = directory.sync_all();
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        result
    }
}

impl CachedCatalog {
    fn from_entry(entry: &ProviderEntry, scope_key: &CatalogCacheScopeKey) -> Option<Self> {
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

    fn is_valid(&self) -> bool {
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
                self.fetched_at_unix_secs > now.saturating_add(CATALOG_CACHE_FUTURE_SKEW_SECS)
            })
            || self.families.len() > MAX_CACHED_FAMILIES_PER_ENTRY
            || self.model_count() > MAX_CACHED_MODELS_PER_ENTRY
        {
            return false;
        }
        let mut family_ids = BTreeSet::new();
        let mut model_ids = BTreeSet::new();
        self.families.iter().all(|family| {
            valid_cached_text(&family.id, MAX_CACHED_TEXT_BYTES, false)
                && valid_cached_text(&family.display_name, MAX_CACHED_TEXT_BYTES, false)
                && family_ids.insert(family.id.as_str())
                && family.models.iter().all(|model| {
                    valid_cached_text(&model.id, MAX_CACHED_TEXT_BYTES, false)
                        && valid_cached_optional_text(model.display_name.as_deref())
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
            now.saturating_sub(self.fetched_at_unix_secs) <= CATALOG_CACHE_TTL_SECS
                && self.fetched_at_unix_secs <= now.saturating_add(CATALOG_CACHE_FUTURE_SKEW_SECS)
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

fn current_unix_secs() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

fn valid_cached_text(value: &str, max_bytes: usize, allow_empty: bool) -> bool {
    (allow_empty || !value.is_empty())
        && value.len() <= max_bytes
        && !value.chars().any(char::is_control)
}

fn valid_cached_optional_text(value: Option<&str>) -> bool {
    value.is_none_or(|value| valid_cached_text(value, MAX_CACHED_TEXT_BYTES, false))
}

fn credential_scope(
    instance: &ProviderInstance,
    scope_key: &CatalogCacheScopeKey,
) -> Option<String> {
    let scope = instance.catalog_cache_credential_scope(&scope_key.0)?;
    let mut encoded = String::with_capacity(CATALOG_CACHE_SCOPE_PREFIX.len() + scope.len() * 2);
    encoded.push_str(CATALOG_CACHE_SCOPE_PREFIX);
    for byte in scope {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    Some(encoded)
}

fn valid_credential_scope(value: &str) -> bool {
    let Some(hex) = value.strip_prefix(CATALOG_CACHE_SCOPE_PREFIX) else {
        return false;
    };
    hex.len() == CATALOG_CACHE_SCOPE_KEY_BYTES * 2
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn adapter_key(adapter: AdapterKind) -> &'static str {
    match adapter {
        AdapterKind::AnthropicMessages => "anthropic_messages",
        AdapterKind::OpenAiCompatibleChat => "openai_chat",
        AdapterKind::OpenAiResponses => "openai_responses",
    }
}

fn catalog_strategy_key(strategy: &CatalogStrategy) -> String {
    match strategy {
        CatalogStrategy::AnthropicModels => "anthropic-models".into(),
        CatalogStrategy::OpenAiModels => "openai-models".into(),
        CatalogStrategy::FireworksControlPlane { api_root } => {
            format!("fireworks-control:{}", api_root.as_str())
        }
        CatalogStrategy::Unsupported { .. } => "unsupported".into(),
    }
}

fn error_profile_key(profile: ErrorProfile) -> &'static str {
    match profile {
        ErrorProfile::Anthropic => "anthropic",
        ErrorProfile::OpenAi => "openai",
        ErrorProfile::DeepSeek => "deepseek",
        ErrorProfile::Glm => "glm",
        ErrorProfile::MiniMax => "minimax",
        ErrorProfile::Fireworks => "fireworks",
        ErrorProfile::CustomConservative => "custom-conservative",
    }
}

fn compatibility_key(value: Compatibility) -> &'static str {
    match value {
        Compatibility::Compatible => "compatible",
        Compatibility::Unknown => "unknown",
        Compatibility::Incompatible => "incompatible",
    }
}

fn hash_selectability(hasher: &mut Sha256, value: &Selectability) {
    match value {
        Selectability::Selectable => hash_part(hasher, b"selectable"),
        Selectability::Disabled { reason } => {
            hash_part(hasher, b"disabled");
            // Reasons are Core-owned &'static policy strings, never provider error text.
            hash_part(hasher, reason.as_bytes());
        }
    }
}

fn hash_catalog_provenance(hasher: &mut Sha256, provenance: &CatalogProvenance) {
    match provenance {
        CatalogProvenance::Unavailable => hash_part(hasher, b"unavailable"),
        CatalogProvenance::DynamicFresh => hash_part(hasher, b"dynamic-fresh"),
        CatalogProvenance::CachedFresh => hash_part(hasher, b"cached-fresh"),
        CatalogProvenance::StaticOfficial { version, source } => {
            hash_part(hasher, b"static-official");
            hash_part(hasher, version.as_bytes());
            hash_part(hasher, source.as_bytes());
        }
        CatalogProvenance::OperatorManifest => hash_part(hasher, b"operator-manifest"),
        CatalogProvenance::OperatorExplicit => hash_part(hasher, b"operator-explicit"),
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

impl CatalogCacheScopeKey {
    #[cfg(any(unix, windows))]
    fn load_or_create(cache_path: &Path) -> io::Result<Self> {
        Self::load_or_create_with_rng(cache_path, fill_scope_key_from_os)
    }

    #[cfg(any(unix, windows))]
    fn load_or_create_with_rng(
        cache_path: &Path,
        fill_random: impl FnOnce(&mut [u8]) -> io::Result<()>,
    ) -> io::Result<Self> {
        let parent = cache_path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "cache path has no parent")
        })?;
        let directory = prepare_private_cache_directory(parent)?;
        let key_path = parent.join(CATALOG_CACHE_SCOPE_KEY_FILE);
        match load_existing_scope_key(&key_path) {
            Ok(key) => return Ok(key),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        let mut bytes = [0_u8; CATALOG_CACHE_SCOPE_KEY_BYTES];
        fill_random(&mut bytes)?;
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "operating-system randomness returned an invalid cache key",
            ));
        }

        let nonce = CACHE_TEMP_NONCE.fetch_add(1, AtomicOrdering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let mut temporary = None;
        for attempt in 0..16u8 {
            let candidate = parent.join(format!(
                ".{CATALOG_CACHE_SCOPE_KEY_FILE}.tmp-{}-{timestamp:x}-{nonce:x}-{attempt}",
                std::process::id()
            ));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&candidate) {
                Ok(file) => {
                    temporary = Some((candidate, file));
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        let Some((temporary_path, mut file)) = temporary else {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not reserve an atomic provider-cache key temporary file",
            ));
        };

        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            match fs::hard_link(&temporary_path, &key_path) {
                Ok(()) => {
                    fs::remove_file(&temporary_path)?;
                    if let Some(directory) = &directory {
                        let _ = directory.sync_all();
                    }
                    load_existing_scope_key(&key_path)
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    fs::remove_file(&temporary_path)?;
                    load_existing_scope_key(&key_path)
                }
                Err(error) => Err(error),
            }
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        result
    }

    /// Targets outside the explicitly admitted Unix/Windows OS-RNG set stay disabled. Silently
    /// deriving a key from time/process state would turn the HMAC into a naked hash.
    #[cfg(not(any(unix, windows)))]
    fn load_or_create(_cache_path: &Path) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "persistent provider catalog cache requires a trusted OS RNG",
        ))
    }
}

#[cfg(any(unix, windows))]
fn fill_scope_key_from_os(destination: &mut [u8]) -> io::Result<()> {
    getrandom::fill(destination).map_err(|error| {
        let kind = if error == getrandom::Error::UNSUPPORTED {
            io::ErrorKind::Unsupported
        } else {
            io::ErrorKind::Other
        };
        io::Error::new(kind, "operating-system randomness is unavailable")
    })
}

fn prepare_private_cache_directory(path: &Path) -> io::Result<Option<File>> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "provider cache parent is not a real directory",
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "provider cache parent must not be a Windows reparse point",
            ));
        }
    }
    #[cfg(unix)]
    fs::set_permissions(path, {
        use std::os::unix::fs::PermissionsExt;
        fs::Permissions::from_mode(0o700)
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let directory = File::open(path)?;
        let opened_metadata = directory.metadata()?;
        if metadata.dev() != opened_metadata.dev()
            || metadata.ino() != opened_metadata.ino()
            || opened_metadata.mode() & 0o777 != 0o700
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "provider cache directory identity or permissions changed",
            ));
        }
        Ok(Some(directory))
    }
    #[cfg(not(unix))]
    {
        Ok(None)
    }
}

#[cfg(any(unix, windows))]
fn load_existing_scope_key(path: &Path) -> io::Result<CatalogCacheScopeKey> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() != CATALOG_CACHE_SCOPE_KEY_BYTES as u64
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "provider cache scope key is not a regular fixed-size file",
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "provider cache scope key must not be a Windows reparse point",
            ));
        }
    }
    let file = File::open(path)?;
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() || opened_metadata.len() != CATALOG_CACHE_SCOPE_KEY_BYTES as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "opened provider cache scope key is not a regular fixed-size file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let parent_metadata = fs::symlink_metadata(path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "cache key path has no parent")
        })?)?;
        if metadata.dev() != opened_metadata.dev()
            || metadata.ino() != opened_metadata.ino()
            || opened_metadata.mode() & 0o777 != 0o600
            || opened_metadata.nlink() != 1
            || opened_metadata.uid() != parent_metadata.uid()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "provider cache scope key identity, owner, or permissions are unsafe",
            ));
        }
    }
    let mut bytes = Vec::with_capacity(CATALOG_CACHE_SCOPE_KEY_BYTES + 1);
    file.take((CATALOG_CACHE_SCOPE_KEY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() != CATALOG_CACHE_SCOPE_KEY_BYTES || bytes.iter().all(|byte| *byte == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "provider cache scope key has invalid content",
        ));
    }
    let mut key = [0_u8; CATALOG_CACHE_SCOPE_KEY_BYTES];
    key.copy_from_slice(&bytes);
    Ok(CatalogCacheScopeKey(key))
}

fn default_catalog_cache_path() -> Option<PathBuf> {
    let home = PathBuf::from(std::env::var_os("HOME")?);
    if !home.is_absolute() {
        return None;
    }
    Some(core_protocol::home::path(&home, "cache/providers").join(CATALOG_CACHE_FILE))
}

fn default_static_provider_metadata_path() -> Option<PathBuf> {
    let home = PathBuf::from(std::env::var_os("HOME")?);
    home.is_absolute()
        .then(|| core_protocol::home::path(&home, STATIC_PROVIDER_METADATA_FILE))
}

fn load_static_provider_metadata() -> anyhow::Result<Arc<StaticProviderMetadata>> {
    let metadata = if let Some(path) = default_static_provider_metadata_path() {
        StaticProviderMetadata::load_optional(&path)?
            .unwrap_or_else(StaticProviderMetadata::embedded)
    } else {
        StaticProviderMetadata::embedded()
    };
    let now = current_unix_secs()
        .ok_or_else(|| anyhow::anyhow!("system clock is before the Unix epoch"))?;
    metadata.validate_capture_times(now)?;
    Ok(metadata)
}

fn apply_catalog_failure(
    entry: &mut ProviderEntry,
    health_store: &ProviderHealthStore,
    error: &ProviderError,
) {
    if catalog_failure_blocks_inference(error) {
        health_store.update_from_error(entry.id(), error);
        entry.catalog_fallback_explicit = false;
    } else {
        // A list-models permission failure, timeout, or malformed catalog says nothing about
        // whether a known inference model can run. Keep discovery and inference health separate.
        entry.catalog_fallback_explicit = true;
    }
    entry.catalog_error = Some(error.public_summary());
}

fn catalog_failure_blocks_inference(error: &ProviderError) -> bool {
    match error {
        ProviderError::NoKey | ProviderError::MissingCredential { .. } => true,
        ProviderError::Configuration(_) => true,
        _ => error.normalized().is_some_and(|failure| {
            matches!(
                failure.availability,
                core_provider::AvailabilityTransition::Account(
                    AccountAvailability::AuthenticationBlocked
                        | AccountAvailability::BillingBlocked
                )
            )
        }),
    }
}

fn apply_catalog_result(
    entry: &mut ProviderEntry,
    health: &ProviderHealthStore,
    result: Result<CatalogSnapshot, ProviderError>,
) {
    match result {
        Ok(mut catalog) => {
            apply_provider_catalog_policy(entry, &mut catalog);
            health.mark_ready(entry.id());
            entry.catalog = Some(catalog);
            entry.catalog_error = None;
            entry.catalog_stale = false;
            entry.catalog_provenance = CatalogProvenance::DynamicFresh;
        }
        Err(error) => apply_catalog_failure(entry, health, &error),
    }
}

fn apply_probe_result(
    entry: &ProviderEntry,
    health: &ProviderHealthStore,
    probe: AccountProbe,
    result: Result<AccountProbeResult, ProviderError>,
) {
    match result {
        Ok(result) => health.update_from_probe(entry.id(), probe, result),
        Err(error) if catalog_failure_blocks_inference(&error) => {
            health.update_from_error(entry.id(), &error)
        }
        Err(_) => {}
    }
}

/// Immutable catalog/configuration plus a shared, interior-mutable account health store.
#[derive(Clone)]
pub(crate) struct ProviderDirectory {
    entries: Arc<Vec<ProviderEntry>>,
    health: ProviderHealthStore,
}

impl ProviderDirectory {
    /// Environment variable names whose values back configured providers. Names are safe control
    /// metadata; values remain inside provider instances. Operator shell children remove these
    /// variables so `!env` cannot expose inference credentials to the TUI.
    pub(crate) fn credential_env_names(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|entry| entry.key_env.clone())
            .collect()
    }

    /// Construct all built-ins plus trusted user instances, then discover credential-visible
    /// catalogs concurrently across provider instances. Missing credentials make zero network
    /// requests.
    pub async fn discover(user: &[ProviderConfig]) -> anyhow::Result<Self> {
        let static_metadata = load_static_provider_metadata()?;
        let mut entries = builtin_entries_with_metadata(static_metadata.clone())?;
        let mut ids: BTreeSet<String> = entries.iter().map(|entry| entry.id().to_owned()).collect();

        for configured in user {
            if !ids.insert(configured.id.clone()) {
                anyhow::bail!(
                    "provider id `{}` is reserved or already configured",
                    configured.id
                );
            }
            entries.push(entry_from_config_with_metadata(
                configured,
                static_metadata.clone(),
            )?);
        }
        if entries.len() > MAX_PROVIDER_INSTANCES {
            anyhow::bail!("provider directory exceeds {MAX_PROVIDER_INSTANCES} instances");
        }

        Self::discover_entries(entries, default_catalog_cache_path()).await
    }

    async fn discover_entries(
        entries: Vec<ProviderEntry>,
        cache_path: Option<PathBuf>,
    ) -> anyhow::Result<Self> {
        if entries.len() > MAX_PROVIDER_INSTANCES {
            anyhow::bail!("provider directory exceeds {MAX_PROVIDER_INSTANCES} instances");
        }
        let health = ProviderHealthStore::new(MAX_PROVIDER_INSTANCES);
        let cache_scope_key = cache_path.as_deref().and_then(|path| {
            CatalogCacheScopeKey::load_or_create(path)
                .map_err(|_| {
                    eprintln!(
                        "warning: provider catalog cache credential scope is unavailable; persistent catalog cache is disabled"
                    )
                })
                .ok()
        });
        let cache = Arc::new(match (&cache_path, &cache_scope_key) {
            (Some(path), Some(_)) => CatalogCache::load(path),
            _ => CatalogCache::default(),
        });

        let discovered = join_all(entries.into_iter().map(|mut entry| {
            let health = health.clone();
            let cache = cache.clone();
            let cache_scope_key = cache_scope_key.clone();
            async move {
                // A valid cache is exact provider/API/adapter/classifier and credential-scoped
                // evidence. It may satisfy model discovery until its fixed TTL, but never proves
                // account health: missing credentials and typed probe failures still gate use.
                let mut served_from_cache = false;
                if entry.catalog_enabled
                    && let Some(scope_key) = cache_scope_key.as_ref()
                    && let Some(catalog) = cache.lookup(&entry, scope_key)
                {
                    entry.catalog = Some(catalog);
                    entry.catalog_stale = false;
                    entry.catalog_provenance = CatalogProvenance::CachedFresh;
                    served_from_cache = true;
                }
                if !entry.enabled {
                    return entry;
                }
                if !entry.instance.has_credential() {
                    health.mark_missing_credential(entry.id());
                    return entry;
                }
                // Provider instances remain concurrent through the outer `join_all`, but evidence
                // for one instance has a deliberate order: observe its catalog first, then run and
                // apply its typed account probe. This makes a documented positive balance/suspension
                // observation the later authority for the exact recovery scope encoded by
                // `ProviderHealthStore::update_from_probe`, instead of pretending two concurrently
                // completed reads had a meaningful fixed observation order. Unsupported catalogs
                // (notably GLM) are disabled at construction, so they still make no speculative
                // `/models` request.
                if entry.catalog_enabled && !served_from_cache {
                    let result = discover_catalog(&entry.instance).await;
                    apply_catalog_result(&mut entry, &health, result);
                }
                if let Some(probe) = account_probe_for(&entry) {
                    let result = probe_account(&entry.instance, probe).await;
                    apply_probe_result(&entry, &health, probe, result);
                }
                entry
            }
        }))
        .await;

        // A cache write is best-effort operational state: a read-only home or full disk must not
        // take a working provider offline. Only fresh dynamic snapshots are admitted; cached and
        // operator-manifest catalogs can never recursively refresh their own provenance.
        if let (Some(path), Some(scope_key)) = (cache_path, cache_scope_key.as_ref()) {
            let mut next_cache = (*cache).clone();
            let mut changed = false;
            for entry in &discovered {
                changed |= next_cache.upsert(entry, scope_key);
            }
            if changed && next_cache.save_atomic(&path).is_err() {
                eprintln!("warning: provider catalog cache could not be persisted");
            }
        }

        Ok(Self {
            entries: Arc::new(discovered),
            health,
        })
    }

    pub fn entries(&self) -> &[ProviderEntry] {
        &self.entries
    }

    pub fn entry(&self, provider_id: &str) -> Option<&ProviderEntry> {
        self.entries.iter().find(|entry| entry.id() == provider_id)
    }

    pub fn health(&self, provider_id: &str) -> ProviderHealth {
        self.health.get(provider_id)
    }

    /// A model-leaf block learned from a typed turn failure. Keeping this separate from
    /// `blocked_reason` lets the picker grey only the failed model while siblings stay usable.
    pub fn model_blocked_reason(&self, provider_id: &str, model_id: &str) -> Option<String> {
        self.health
            .is_model_unavailable(provider_id, model_id)
            .then(|| {
                format!(
                    "known unavailable from the last provider response; retry explicitly with /model retry {provider_id}:{model_id}"
                )
            })
    }

    /// An account-wide reason that prevents every descendant from being selected. Unknown balance
    /// is deliberately absent from this list: unknown is a warning, not evidence of no credit.
    pub fn blocked_reason(&self, entry: &ProviderEntry) -> Option<String> {
        self.account_blocked_reason(entry).or_else(|| {
            entry.catalog_stale.then(|| {
                // Credential-scoped cache identity prevents one account from seeing another
                // account's private inventory. Even for the same account, stale names remain
                // display evidence and can never authorize selection.
                "stale cached catalog is informational only; refresh required before selection"
                    .into()
            })
        })
    }

    fn account_blocked_reason(&self, entry: &ProviderEntry) -> Option<String> {
        if !entry.enabled {
            return Some("disabled in user config".into());
        }
        let health = self.health(entry.id());
        if health.balance == BalanceAvailability::Depleted {
            return Some("balance depleted".into());
        }
        let account_reason = match health.availability {
            AccountAvailability::MissingCredential => {
                let cache_note = if entry.catalog_stale {
                    "; cached models are informational only"
                } else {
                    ""
                };
                Some(format!(
                    "missing credential ({}){cache_note}",
                    entry.key_env
                ))
            }
            AccountAvailability::AuthenticationBlocked => Some("authentication failed".into()),
            AccountAvailability::BillingBlocked => Some("billing or quota unavailable".into()),
            AccountAvailability::PermissionBlocked => Some("permission denied".into()),
            AccountAvailability::ConfigurationError => Some("provider configuration error".into()),
            AccountAvailability::Discovering => Some("catalog discovery in progress".into()),
            // Rate limiting and degradation are temporary. They remain selectable so a bounded
            // retry or later recovery can succeed; the picker renders them as warnings.
            AccountAvailability::Unknown
            | AccountAvailability::Ready
            | AccountAvailability::RateLimited
            | AccountAvailability::Degraded => None,
        };
        if account_reason.is_some() {
            return account_reason;
        }
        None
    }

    pub fn status_label(&self, entry: &ProviderEntry) -> String {
        if let Some(reason) = self.blocked_reason(entry) {
            return reason;
        }
        let health = self.health(entry.id());
        let account = if is_glm_standard_schema_entry(entry) {
            "official static schema · account entitlement unknown"
        } else if !entry.catalog_enabled && entry.catalog.is_some() {
            "manual catalog ready"
        } else if matches!(
            entry.instance.catalog_strategy(),
            CatalogStrategy::Unsupported { .. }
        ) {
            "manual model required"
        } else {
            match health.availability {
                AccountAvailability::Ready => "catalog ready",
                AccountAvailability::RateLimited => "temporarily rate limited",
                AccountAvailability::Degraded => "provider degraded",
                _ if entry.catalog.is_some() => "catalog ready",
                _ if entry.catalog_error.is_some() => "catalog unavailable",
                _ if !entry.catalog_enabled => "catalog disabled by operator",
                _ => "account state unknown",
            }
        };
        let balance = match health.balance {
            BalanceAvailability::Unknown => "balance unknown",
            BalanceAvailability::Sufficient => "balance available",
            BalanceAvailability::Depleted => "balance depleted",
        };
        format!("{account} · {balance}")
    }

    /// Resolve `/model` input. `provider:model` is always unambiguous; a bare model id resolves to
    /// the current provider first, then to a unique dynamic-catalog match.
    pub fn resolve_model(
        &self,
        value: &str,
        current_provider: Option<&str>,
    ) -> Result<ModelSelection, String> {
        let value = value.trim();
        if value.is_empty() {
            return Err("model id is empty".into());
        }
        if let Some((provider_id, model_id)) = value
            .split_once(':')
            .filter(|(provider_id, _)| self.entry(provider_id).is_some())
        {
            if provider_id.is_empty() || model_id.is_empty() {
                return Err("use provider:model-id".into());
            }
            let selection = ModelSelection {
                provider_id: provider_id.to_owned(),
                model_id: model_id.to_owned(),
            };
            self.validate_selection(&selection, true)?;
            return Ok(selection);
        }

        let catalog_matches: Vec<&ProviderEntry> =
            self.entries
                .iter()
                .filter(|entry| {
                    entry.catalog.as_ref().is_some_and(|catalog| {
                        catalog.models.iter().any(|model| model.raw.id == value)
                    })
                })
                .collect();
        // Cached names and disabled leaves are informational evidence. They must not create a
        // false ambiguity or steal precedence from a fresh selectable route with the same id.
        let matches: Vec<&ProviderEntry> = catalog_matches
            .iter()
            .copied()
            .filter(|entry| self.blocked_reason(entry).is_none())
            .filter(|entry| {
                entry.catalog.as_ref().is_some_and(|catalog| {
                    catalog.models.iter().any(|model| {
                        model.raw.id == value
                            && model.selectability == Selectability::Selectable
                            && self.model_blocked_reason(entry.id(), value).is_none()
                    })
                })
            })
            .collect();
        let entry = current_provider
            .and_then(|provider_id| matches.iter().copied().find(|entry| entry.id() == provider_id))
            .or_else(|| (matches.len() == 1).then(|| matches[0]))
            .ok_or_else(|| {
                if catalog_matches.is_empty() {
                    "model is absent from every discovered catalog; use provider:model-id for a catalog-disabled or unsupported provider".to_string()
                } else if matches.is_empty() {
                    let providers = catalog_matches
                        .iter()
                        .map(|entry| entry.id())
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!("model is visible but unavailable across {providers}")
                } else {
                    let providers = matches
                        .iter()
                        .map(|entry| entry.id())
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!("model id is ambiguous across {providers}; use provider:{value}")
                }
            })?;
        let selection = ModelSelection {
            provider_id: entry.id().to_owned(),
            model_id: value.to_owned(),
        };
        self.validate_selection(&selection, false)?;
        Ok(selection)
    }

    /// Pick the documented default for an official static schema, otherwise the first compatible
    /// model in the provider/operator catalog. This is used only when the operator supplied no
    /// model; Core does not invent or retain a stale hard-coded default model id.
    pub fn default_selection(&self, provider_id: &str) -> Option<ModelSelection> {
        let entry = self.entry(provider_id)?;
        if self.blocked_reason(entry).is_some() {
            return None;
        }
        let catalog = entry.catalog.as_ref()?;
        // A static schema is not a credential-visible ordering. Honor the documented default
        // instead of accidentally choosing the lexicographically first identifier. Dynamic and
        // operator catalogs keep their existing deterministic first-selectable behavior.
        let preferred = is_glm_standard_schema_entry(entry)
            .then(|| entry.instance.static_metadata().glm_default_model())
            .and_then(|default| catalog.models.iter().find(|model| model.raw.id == default));
        let model = preferred
            .filter(|model| {
                matches!(model.selectability, Selectability::Selectable)
                    && self
                        .model_blocked_reason(provider_id, &model.raw.id)
                        .is_none()
            })
            .or_else(|| {
                catalog.models.iter().find(|model| {
                    matches!(model.selectability, Selectability::Selectable)
                        && self
                            .model_blocked_reason(provider_id, &model.raw.id)
                            .is_none()
                })
            })?;
        Some(ModelSelection {
            provider_id: provider_id.to_owned(),
            model_id: model.raw.id.clone(),
        })
    }

    /// Validate both account and model before a runtime swap. If a successful dynamic catalog is
    /// present, a model absent from it is rejected. An explicit model is accepted only when the
    /// operator deliberately disabled discovery for that gateway.
    pub fn validate_selection(
        &self,
        selection: &ModelSelection,
        explicit: bool,
    ) -> Result<(), String> {
        self.validate_selection_inner(selection, explicit, true)
    }

    /// Admit exactly one operator-requested retry of a previously blocked model leaf.
    /// Catalog compatibility and every account-wide gate are still validated; only the learned
    /// leaf marker is ignored for this validation and then removed. A repeated provider failure
    /// recreates the marker through `HealthReportingProvider`.
    pub fn clear_model_unavailable_for_retry(
        &self,
        selection: &ModelSelection,
    ) -> Result<bool, String> {
        self.validate_selection_inner(selection, true, false)?;
        Ok(self
            .health
            .clear_model_unavailable_for_retry(&selection.provider_id, &selection.model_id))
    }

    fn validate_selection_inner(
        &self,
        selection: &ModelSelection,
        explicit: bool,
        enforce_model_health: bool,
    ) -> Result<(), String> {
        let entry = self
            .entry(&selection.provider_id)
            .ok_or_else(|| format!("unknown provider `{}`", selection.provider_id))?;
        let explicit_catalog_fallback = explicit && entry.catalog_fallback_explicit;
        if let Some(reason) = self.account_blocked_reason(entry) {
            return Err(format!("{} is unavailable: {reason}", entry.display_name()));
        }
        if entry.catalog_stale && !explicit_catalog_fallback {
            return Err(format!(
                "{} is unavailable: stale cached catalog is informational only; refresh required before selection",
                entry.display_name()
            ));
        }
        if enforce_model_health
            && let Some(reason) =
                self.model_blocked_reason(&selection.provider_id, &selection.model_id)
        {
            return Err(format!(
                "model `{}` is unavailable for {}: {reason}",
                selection.model_id,
                entry.display_name()
            ));
        }
        if let Some(catalog) = &entry.catalog
            && !explicit_catalog_fallback
        {
            let model = catalog
                .models
                .iter()
                .find(|model| model.raw.id == selection.model_id)
                .ok_or_else(|| {
                    format!(
                        "model `{}` is not in {}'s current catalog",
                        selection.model_id,
                        entry.display_name()
                    )
                })?;
            if let Selectability::Disabled { reason } = model.selectability {
                return Err(format!(
                    "model `{}` is unavailable: {reason}",
                    selection.model_id
                ));
            }
            return Ok(());
        }
        if explicit && manual_model_allowed(entry) {
            return Ok(());
        }
        Err(format!(
            "{} has no usable model catalog{}",
            entry.display_name(),
            entry
                .catalog_error
                .as_deref()
                .map(|error| format!(": {error}"))
                .unwrap_or_default()
        ))
    }

    /// Instantiate the already-validated wire adapter. A `Provider::turn` is exactly one physical
    /// transport attempt so the kernel can durably journal it before dispatch; transparent retry
    /// decorators are intentionally excluded until they expose a per-attempt WAL callback.
    pub fn build(&self, selection: &ModelSelection) -> Result<Arc<dyn Provider>, String> {
        self.validate_selection(selection, true)?;
        let entry = self
            .entry(&selection.provider_id)
            .ok_or_else(|| format!("unknown provider `{}`", selection.provider_id))?;
        let provider = entry
            .instance
            .build_turn_provider()
            .map_err(|error| error.to_string())?;
        Ok(Arc::new(
            HealthReportingProvider::new(
                provider,
                selection.provider_id.clone(),
                self.health.clone(),
            )
            .with_model_scoped_account_failures(
                entry.instance.error_profile() == ErrorProfile::Fireworks,
            )
            .with_static_metadata_notice(
                entry.instance.static_metadata_handle(),
                entry.instance.adapter(),
                entry.instance.error_profile(),
                entry.instance.api_root().as_str(),
                selection.model_id.clone(),
            ),
        ))
    }

    /// Return only capabilities documented for this exact endpoint/model pair. The official GLM
    /// 5.2 model page names the standard Chat Completions id and its 1M/128K bounds; no other route
    /// inherits those values by family or wire-compatibility heuristics.
    pub fn selection_capabilities(&self, selection: &ModelSelection) -> ModelCapabilities {
        let Some(entry) = self.entry(&selection.provider_id) else {
            return ModelCapabilities::unknown();
        };
        let metadata = entry.instance.static_metadata();
        if entry.instance.api_root().as_str() == metadata.glm_api_root()
            && entry.instance.adapter() == AdapterKind::OpenAiCompatibleChat
            && entry.instance.error_profile() == ErrorProfile::Glm
            && let Some(capabilities) = metadata.glm_model_capabilities(&selection.model_id)
        {
            return ModelCapabilities {
                context_window_tokens: capabilities.context_window_tokens,
                max_output_tokens: capabilities.max_output_tokens,
                tool_calling: capabilities.tool_calling,
                semantic_effort: capabilities.semantic_effort,
                version: Some(capabilities.version.clone()),
                source: Some(capabilities.source.clone()),
            };
        }
        ModelCapabilities::unknown()
    }

    /// Deterministic, content-only provenance for the route recorded in the rollout. The digest
    /// contains no credential or raw provider error. A manual model gets an explicit manual-policy
    /// marker instead of pretending dynamic capability evidence existed.
    pub fn selection_digests(&self, selection: &ModelSelection) -> (String, String) {
        let Some(entry) = self.entry(&selection.provider_id) else {
            return (String::new(), String::new());
        };
        let mut catalog = Sha256::new();
        let execution_provenance = if entry.catalog_fallback_explicit {
            // A failed discovery can leave cached names on screen, but an explicitly typed route
            // is operator evidence. Never hash stale display inventory as execution evidence.
            CatalogProvenance::OperatorExplicit
        } else {
            entry.catalog_provenance.clone()
        };
        hash_part(&mut catalog, b"core-provider-catalog-v2");
        hash_part(&mut catalog, entry.id().as_bytes());
        hash_part(&mut catalog, entry.instance.api_root().as_str().as_bytes());
        hash_part(
            &mut catalog,
            adapter_key(entry.instance.adapter()).as_bytes(),
        );
        hash_part(
            &mut catalog,
            catalog_strategy_key(entry.instance.catalog_strategy()).as_bytes(),
        );
        hash_catalog_provenance(&mut catalog, &execution_provenance);
        if let Some(snapshot) = entry
            .catalog
            .as_ref()
            .filter(|_| !entry.catalog_fallback_explicit)
        {
            // Do not rely on a remote page order (or a future constructor) for provenance.
            let mut models: Vec<_> = snapshot.models.iter().collect();
            models.sort_by(|left, right| left.raw.id.cmp(&right.raw.id));
            for model in models {
                hash_part(&mut catalog, model.raw.id.as_bytes());
                hash_part(&mut catalog, model.family_id.as_bytes());
                hash_part(
                    &mut catalog,
                    compatibility_key(model.compatibility).as_bytes(),
                );
                hash_selectability(&mut catalog, &model.selectability);
            }
        } else {
            hash_part(&mut catalog, b"no-snapshot");
        }

        let mut capability = Sha256::new();
        hash_part(&mut capability, b"core-provider-capability-v2");
        hash_part(&mut capability, entry.id().as_bytes());
        hash_part(&mut capability, selection.model_id.as_bytes());
        hash_part(
            &mut capability,
            adapter_key(entry.instance.adapter()).as_bytes(),
        );
        hash_part(
            &mut capability,
            error_profile_key(entry.instance.error_profile()).as_bytes(),
        );
        if let Some(revision) = entry.instance.static_metadata().route_revision_evidence(
            entry.instance.adapter(),
            entry.instance.error_profile(),
            entry.instance.api_root().as_str(),
            &selection.model_id,
        ) {
            hash_part(&mut capability, revision.as_bytes());
        } else {
            hash_part(&mut capability, b"no-static-route-revision");
        }
        hash_catalog_provenance(&mut capability, &execution_provenance);
        let documented = self.selection_capabilities(selection);
        hash_part(
            &mut capability,
            documented
                .context_window_tokens
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown-context".into())
                .as_bytes(),
        );
        hash_part(
            &mut capability,
            documented
                .max_output_tokens
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown-output".into())
                .as_bytes(),
        );
        hash_part(
            &mut capability,
            match documented.tool_calling {
                Some(true) => b"tools:true",
                Some(false) => b"tools:false",
                None => b"tools:unknown",
            },
        );
        hash_part(
            &mut capability,
            match documented.semantic_effort {
                Some(true) => b"effort:true",
                Some(false) => b"effort:false",
                None => b"effort:unknown",
            },
        );
        hash_part(
            &mut capability,
            documented
                .version
                .as_deref()
                .unwrap_or("unknown-version")
                .as_bytes(),
        );
        hash_part(
            &mut capability,
            documented
                .source
                .as_deref()
                .unwrap_or("unknown-source")
                .as_bytes(),
        );
        if let Some(model) = entry
            .catalog
            .as_ref()
            .filter(|_| !entry.catalog_fallback_explicit)
            .and_then(|snapshot| {
                snapshot
                    .models
                    .iter()
                    .find(|model| model.raw.id == selection.model_id)
            })
        {
            hash_part(
                &mut capability,
                compatibility_key(model.compatibility).as_bytes(),
            );
            hash_selectability(&mut capability, &model.selectability);
        } else {
            hash_part(&mut capability, b"no-model-descriptor");
        }
        (digest_string(catalog), digest_string(capability))
    }

    /// A non-networking placeholder used only so the interactive picker can open when no account
    /// is currently selectable. One-shot mode rejects the same state before creating a rollout.
    pub fn unavailable_provider(
        &self,
        provider_id: impl Into<String>,
        reason: impl Into<String>,
    ) -> Arc<dyn Provider> {
        Arc::new(UnavailableProvider {
            provider_id: provider_id.into(),
            reason: reason.into(),
        })
    }
}

fn hash_part(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn digest_string(hasher: Sha256) -> String {
    let bytes = hasher.finalize();
    let mut output = String::with_capacity(7 + bytes.len() * 2);
    output.push_str("sha256:");
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub(crate) fn stable_digest(label: &str, parts: &[String]) -> String {
    let mut hasher = Sha256::new();
    hash_part(&mut hasher, label.as_bytes());
    for part in parts {
        hash_part(&mut hasher, part.as_bytes());
    }
    digest_string(hasher)
}

struct UnavailableProvider {
    provider_id: String,
    reason: String,
}

#[async_trait::async_trait]
impl Provider for UnavailableProvider {
    fn provider_instance_id(&self) -> Option<&str> {
        Some(&self.provider_id)
    }

    async fn turn(
        &self,
        _request: &TurnRequest,
        _on_item: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        Err(ProviderError::Configuration(format!(
            "provider `{}` is unavailable: {}",
            self.provider_id, self.reason
        )))
    }
}

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
fn builtin_entries() -> anyhow::Result<Vec<ProviderEntry>> {
    builtin_entries_with_metadata(StaticProviderMetadata::embedded())
}

fn builtin_entries_with_metadata(
    static_metadata: Arc<StaticProviderMetadata>,
) -> anyhow::Result<Vec<ProviderEntry>> {
    BUILTINS
        .iter()
        .map(|builtin| {
            let credential = environment_credential(builtin.key_env);
            let instance = ProviderInstance::new(
                builtin.id,
                builtin.display_name,
                builtin.adapter,
                ApiRoot::parse(builtin.api_root)?,
                credential,
            )?
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
            Ok(ProviderEntry {
                instance,
                key_env: builtin.key_env.into(),
                enabled: true,
                catalog_enabled,
                catalog,
                catalog_error,
                catalog_fallback_explicit: false,
                catalog_stale: false,
                catalog_provenance,
            })
        })
        .collect::<Result<Vec<_>, core_provider::ProviderError>>()
        .map_err(Into::into)
}

fn is_glm_standard_schema_entry(entry: &ProviderEntry) -> bool {
    entry.id() == "glm"
        && entry.instance.adapter() == AdapterKind::OpenAiCompatibleChat
        && entry.instance.api_root().as_str() == entry.instance.static_metadata().glm_api_root()
        && !entry.catalog_enabled
        && matches!(
            &entry.catalog_provenance,
            CatalogProvenance::StaticOfficial { .. }
        )
}

#[cfg(test)]
fn entry_from_config(config: &ProviderConfig) -> anyhow::Result<ProviderEntry> {
    entry_from_config_with_metadata(config, StaticProviderMetadata::embedded())
}

fn entry_from_config_with_metadata(
    config: &ProviderConfig,
    static_metadata: Arc<StaticProviderMetadata>,
) -> anyhow::Result<ProviderEntry> {
    let adapter = match config.adapter.as_str() {
        "anthropic_messages" => AdapterKind::AnthropicMessages,
        "openai_responses" => AdapterKind::OpenAiResponses,
        "openai_chat" => AdapterKind::OpenAiCompatibleChat,
        _ => anyhow::bail!("provider `{}` has an unsupported adapter", config.id),
    };
    let credential = environment_credential(&config.key_env);
    let display_name = config.display_name.as_deref().unwrap_or(&config.id);
    let mut instance = ProviderInstance::new(
        config.id.clone(),
        display_name,
        adapter,
        ApiRoot::parse(&config.api_root)?,
        credential,
    )?
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
    Ok(ProviderEntry {
        instance,
        key_env: config.key_env.clone(),
        enabled: config.enabled,
        catalog_enabled,
        catalog,
        catalog_error,
        catalog_fallback_explicit: false,
        catalog_stale: false,
        catalog_provenance,
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
fn catalog_configuration(instance: &ProviderInstance, requested: bool) -> (bool, Option<String>) {
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

fn manual_model_allowed(entry: &ProviderEntry) -> bool {
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
fn account_probe_for(entry: &ProviderEntry) -> Option<AccountProbe> {
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
fn apply_provider_catalog_policy(entry: &ProviderEntry, catalog: &mut CatalogSnapshot) {
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

fn apply_model_overlay(policy: CatalogOverlay, model: &mut core_provider::ModelDescriptor) {
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

fn is_openai_fine_tuned_text_model(model_id: &str) -> bool {
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

fn environment_credential(key_env: &str) -> Option<String> {
    std::env::var(key_env)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_provider::{ModelDescriptor, ModelFamily, RawModel};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::Duration;

    static CACHE_TEST_ID: AtomicU64 = AtomicU64::new(0);

    fn test_cache_path(label: &str) -> PathBuf {
        let id = CACHE_TEST_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!(
                "core-provider-cache-{label}-{}-{id}",
                std::process::id()
            ))
            .join(CATALOG_CACHE_FILE)
    }

    fn remove_test_cache(path: &Path) {
        if let Some(parent) = path.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }

    fn spawn_json_server(body: String) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 2_048];
            loop {
                let read = stream.read(&mut chunk).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
                assert!(request.len() < 16 * 1024);
            }
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body,
            )
            .unwrap();
            stream.flush().unwrap();
        });
        (format!("http://{address}/v1"), handle)
    }

    fn closed_api_root() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        format!("http://{address}/v1")
    }

    fn offline_entry(id: &str, adapter: AdapterKind, catalog_enabled: bool) -> ProviderEntry {
        ProviderEntry {
            instance: ProviderInstance::new(
                id,
                id,
                adapter,
                ApiRoot::parse("http://127.0.0.1:9/v1").unwrap(),
                None,
            )
            .unwrap(),
            key_env: format!("{id}_KEY").to_ascii_uppercase(),
            enabled: true,
            catalog_enabled,
            catalog: None,
            catalog_error: None,
            catalog_fallback_explicit: false,
            catalog_stale: false,
            catalog_provenance: CatalogProvenance::Unavailable,
        }
    }

    fn glm_static_entry(credential: Option<String>) -> ProviderEntry {
        glm_static_entry_with_metadata(credential, StaticProviderMetadata::embedded())
    }

    fn glm_static_entry_with_metadata(
        credential: Option<String>,
        metadata: Arc<StaticProviderMetadata>,
    ) -> ProviderEntry {
        let instance = ProviderInstance::new(
            "glm",
            "GLM / 智谱",
            AdapterKind::OpenAiCompatibleChat,
            ApiRoot::parse(metadata.glm_api_root()).unwrap(),
            credential,
        )
        .unwrap()
        .with_static_metadata(metadata.clone());
        let (catalog_enabled, _) = catalog_configuration(&instance, true);
        let catalog = Some(glm_standard_schema_catalog(&instance).unwrap());
        ProviderEntry {
            instance,
            key_env: "GLM_API_KEY".into(),
            enabled: true,
            catalog_enabled,
            catalog,
            catalog_error: None,
            catalog_fallback_explicit: false,
            catalog_stale: false,
            catalog_provenance: CatalogProvenance::StaticOfficial {
                version: metadata.glm_catalog_version().into(),
                source: metadata.glm_catalog_source().into(),
            },
        }
    }

    #[test]
    fn builtin_roots_and_adapters_are_exact() {
        let expected = [
            (
                "anthropic",
                "https://api.anthropic.com/v1",
                AdapterKind::AnthropicMessages,
            ),
            (
                "openai",
                "https://api.openai.com/v1",
                AdapterKind::OpenAiResponses,
            ),
            (
                "deepseek",
                "https://api.deepseek.com",
                AdapterKind::OpenAiCompatibleChat,
            ),
            (
                "glm",
                "https://open.bigmodel.cn/api/paas/v4",
                AdapterKind::OpenAiCompatibleChat,
            ),
            (
                "minimax",
                MINIMAX_API_ROOT,
                AdapterKind::OpenAiCompatibleChat,
            ),
            (
                "fireworks",
                "https://api.fireworks.ai/inference/v1",
                AdapterKind::OpenAiCompatibleChat,
            ),
        ];
        for (actual, expected) in BUILTINS.iter().zip(expected) {
            assert_eq!(actual.id, expected.0);
            assert_eq!(actual.api_root, expected.1);
            assert_eq!(actual.adapter, expected.2);
        }
    }

    fn policy_entry_with_credential(
        id: &str,
        api_root: &str,
        credential: Option<&str>,
    ) -> ProviderEntry {
        let instance = ProviderInstance::new(
            id,
            id,
            AdapterKind::OpenAiCompatibleChat,
            ApiRoot::parse(api_root).unwrap(),
            credential.map(str::to_owned),
        )
        .unwrap();
        let (catalog_enabled, catalog_error) = catalog_configuration(&instance, true);
        ProviderEntry {
            instance,
            key_env: format!("{}_KEY", id.to_ascii_uppercase()),
            enabled: true,
            catalog_enabled,
            catalog: None,
            catalog_error,
            catalog_fallback_explicit: false,
            catalog_stale: false,
            catalog_provenance: CatalogProvenance::Unavailable,
        }
    }

    fn policy_entry(id: &str, api_root: &str) -> ProviderEntry {
        policy_entry_with_credential(id, api_root, Some("test-key"))
    }

    fn descriptor(
        id: &str,
        compatibility: Compatibility,
        selectability: Selectability,
    ) -> ModelDescriptor {
        ModelDescriptor {
            raw: RawModel {
                id: id.into(),
                display_name: Some(id.into()),
                created_at: None,
                owned_by: None,
            },
            family_id: "other".into(),
            compatibility,
            selectability,
        }
    }

    fn snapshot(provider_id: &str, models: Vec<ModelDescriptor>) -> CatalogSnapshot {
        CatalogSnapshot {
            provider_instance_id: provider_id.into(),
            adapter: AdapterKind::OpenAiCompatibleChat,
            families: vec![ModelFamily {
                id: "other".into(),
                display_name: "Other / unclassified".into(),
                models: models.clone(),
            }],
            models,
        }
    }

    fn catalogued_entry(id: &str, api_root: &str, model_id: &str) -> ProviderEntry {
        let mut entry = policy_entry(id, api_root);
        entry.catalog = Some(snapshot(
            id,
            vec![descriptor(
                model_id,
                Compatibility::Compatible,
                Selectability::Selectable,
            )],
        ));
        entry.catalog_provenance = CatalogProvenance::DynamicFresh;
        entry
    }

    fn test_scope_key(path: &Path) -> CatalogCacheScopeKey {
        CatalogCacheScopeKey::load_or_create(path).unwrap()
    }

    fn seed_cache(path: &Path, entry: &ProviderEntry) {
        let scope_key = test_scope_key(path);
        let mut cache = CatalogCache::default();
        assert!(cache.upsert(entry, &scope_key));
        cache.save_atomic(path).unwrap();
    }

    #[test]
    fn catalog_cache_round_trips_atomically_without_credentials_or_errors() {
        let path = test_cache_path("round-trip");
        let mut source =
            catalogued_entry("cache-test", "https://gateway.example/v1/", "gpt-4o-mini");
        let disabled = descriptor(
            "zzz-unknown",
            Compatibility::Unknown,
            Selectability::Disabled {
                reason: "coding-turn compatibility is unknown",
            },
        );
        source
            .catalog
            .as_mut()
            .unwrap()
            .models
            .push(disabled.clone());
        source.catalog.as_mut().unwrap().families[0]
            .models
            .push(disabled);
        source.catalog_error = Some("raw-error-with-test-key".into());
        seed_cache(&path, &source);

        let bytes = fs::read(&path).unwrap();
        assert!(bytes.len() <= MAX_CATALOG_CACHE_BYTES);
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            !text.contains("test-key"),
            "credentials must never be cached"
        );
        assert!(
            !text.contains("raw-error"),
            "raw errors must never be cached"
        );
        let naked_credential_hash = {
            let bytes = Sha256::digest(b"test-key");
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        assert!(
            !text.contains(&naked_credential_hash),
            "a naked credential hash must never be cached"
        );
        assert!(text.contains(CATALOG_CACHE_SCOPE_PREFIX));
        let key_bytes =
            fs::read(path.parent().unwrap().join(CATALOG_CACHE_SCOPE_KEY_FILE)).unwrap();
        assert_eq!(key_bytes.len(), CATALOG_CACHE_SCOPE_KEY_BYTES);
        assert!(
            !key_bytes
                .windows(b"test-key".len())
                .any(|window| window == b"test-key"),
            "the local scope key must not contain the provider credential"
        );
        assert_eq!(
            fs::read_dir(path.parent().unwrap()).unwrap().count(),
            2,
            "atomic temporary files must not remain after commit"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(path.parent().unwrap().join(CATALOG_CACHE_SCOPE_KEY_FILE))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        let loaded = CatalogCache::load(&path);
        assert_eq!(loaded.version, CATALOG_CACHE_VERSION);
        let scope_key = test_scope_key(&path);
        let snapshot = loaded.lookup(&source, &scope_key).unwrap();
        assert_eq!(snapshot, source.catalog.clone().unwrap());
        assert_eq!(snapshot.models[0].raw.id, "gpt-4o-mini");
        assert_eq!(snapshot.models[0].selectability, Selectability::Selectable);

        let wrong_root = policy_entry("cache-test", "https://other.example/v1");
        assert!(
            loaded.lookup(&wrong_root, &scope_key).is_none(),
            "provider id alone must never cross an API-root/strategy boundary"
        );
        remove_test_cache(&path);
    }

    #[test]
    fn catalog_cache_rejects_wrong_versions_corruption_and_all_hard_bounds() {
        let path = test_cache_path("bounds");
        fs::create_dir_all(path.parent().unwrap()).unwrap();

        fs::write(&path, br#"{"version":999,"entries":[]}"#).unwrap();
        assert!(CatalogCache::load(&path).entries.is_empty());
        fs::write(&path, b"{not-json").unwrap();
        assert!(CatalogCache::load(&path).entries.is_empty());
        fs::write(&path, vec![b' '; MAX_CATALOG_CACHE_BYTES + 1]).unwrap();
        assert!(CatalogCache::load(&path).entries.is_empty());

        let source = catalogued_entry("cache-bounds", "https://gateway.example/v1", "gpt-4o-mini");
        let scope_key = test_scope_key(&path);
        let cached = CachedCatalog::from_entry(&source, &scope_key).unwrap();
        let too_many_entries = CatalogCache {
            version: CATALOG_CACHE_VERSION,
            entries: vec![cached.clone(); MAX_CATALOG_CACHE_ENTRIES + 1],
        };
        assert!(!too_many_entries.is_valid());

        let mut too_many_models = cached.clone();
        too_many_models.families[0].models = (0..=MAX_CACHED_MODELS_PER_ENTRY)
            .map(|index| CachedModel {
                id: format!("model-{index}"),
                display_name: None,
                created_at: None,
                owned_by: None,
                compatibility: CachedCompatibility::Compatible,
                selectability: CachedSelectability::Selectable,
            })
            .collect();
        assert!(!too_many_models.is_valid());

        let mut expired = cached.clone();
        expired.fetched_at_unix_secs = current_unix_secs()
            .unwrap()
            .saturating_sub(CATALOG_CACHE_TTL_SECS + 1);
        let expired_cache = CatalogCache {
            version: CATALOG_CACHE_VERSION,
            entries: vec![expired],
        };
        assert!(expired_cache.lookup(&source, &scope_key).is_none());

        let mut wrong_classifier = cached;
        wrong_classifier.classifier_version += 1;
        assert!(!wrong_classifier.is_valid());
        remove_test_cache(&path);
    }

    #[cfg(unix)]
    #[test]
    fn catalog_cache_scope_key_rejects_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let path = test_cache_path("scope-key-symlink");
        prepare_private_cache_directory(path.parent().unwrap()).unwrap();
        let target = path.parent().unwrap().join("untrusted-key-target");
        fs::write(&target, [7_u8; CATALOG_CACHE_SCOPE_KEY_BYTES]).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(
            &target,
            path.parent().unwrap().join(CATALOG_CACHE_SCOPE_KEY_FILE),
        )
        .unwrap();

        assert!(CatalogCacheScopeKey::load_or_create(&path).is_err());
        remove_test_cache(&path);
    }

    #[test]
    fn d13_13_rng_unavailable_is_unsupported_without_a_weak_fallback_key() {
        let path = test_cache_path("unsupported-rng");
        let error = CatalogCacheScopeKey::load_or_create_with_rng(&path, |_| {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "test target has no admitted OS CSPRNG",
            ))
        })
        .err()
        .expect("an unsupported RNG must disable persistent catalog caching");

        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(
            !path
                .parent()
                .unwrap()
                .join(CATALOG_CACHE_SCOPE_KEY_FILE)
                .exists(),
            "time, pid, and temporary-file nonces must never become fallback key material"
        );
        remove_test_cache(&path);
    }

    #[tokio::test]
    async fn d13_13_fresh_cache_serves_a_second_run_without_rediscovery() {
        let path = test_cache_path("refresh");
        let body = serde_json::json!({
            "data": [{"id": "gpt-4o-mini", "owned_by": "openai"}]
        })
        .to_string();
        let (api_root, server) = spawn_json_server(body);
        let target = policy_entry("refresh-test", &api_root);

        let directory =
            ProviderDirectory::discover_entries(vec![target.clone()], Some(path.clone()))
                .await
                .unwrap();
        // The fixture accepts exactly one request and then exits. Any second discovery attempt
        // therefore fails closed instead of accidentally making this a cache-hit-shaped test.
        server.join().unwrap();
        let refreshed = directory.entry("refresh-test").unwrap();
        assert!(!refreshed.catalog_stale);
        assert_eq!(
            refreshed.catalog.as_ref().unwrap().models[0].raw.id,
            "gpt-4o-mini"
        );
        let scope_key = test_scope_key(&path);
        assert!(
            CatalogCache::load(&path)
                .lookup(refreshed, &scope_key)
                .is_some()
        );

        let second = ProviderDirectory::discover_entries(vec![target], Some(path.clone()))
            .await
            .unwrap();
        let cached = second.entry("refresh-test").unwrap();
        assert_eq!(cached.catalog_provenance, CatalogProvenance::CachedFresh);
        assert!(!cached.catalog_stale);
        assert!(cached.catalog_error.is_none());
        assert_eq!(
            second
                .resolve_model("gpt-4o-mini", Some("refresh-test"))
                .unwrap(),
            ModelSelection {
                provider_id: "refresh-test".into(),
                model_id: "gpt-4o-mini".into(),
            }
        );
        remove_test_cache(&path);
    }

    #[tokio::test]
    async fn missing_credential_cannot_load_cached_inventory() {
        let path = test_cache_path("missing-key");
        let api_root = "http://127.0.0.1:9/v1";
        let source = catalogued_entry("missing-cache", api_root, "gpt-4o-mini");
        seed_cache(&path, &source);
        let target = offline_entry("missing-cache", AdapterKind::OpenAiCompatibleChat, true);

        let directory = ProviderDirectory::discover_entries(vec![target], Some(path.clone()))
            .await
            .unwrap();
        let cached = directory.entry("missing-cache").unwrap();
        assert!(!cached.catalog_stale);
        assert!(cached.catalog.is_none());
        assert_eq!(
            directory.health("missing-cache").availability,
            AccountAvailability::MissingCredential,
            "the credential early-exit proves no network result replaced account state"
        );
        let reason = directory.blocked_reason(cached).unwrap();
        assert!(reason.contains("missing credential"));
        assert!(!reason.contains("cached models"));
        assert!(
            directory
                .validate_selection(
                    &ModelSelection {
                        provider_id: "missing-cache".into(),
                        model_id: "gpt-4o-mini".into(),
                    },
                    true,
                )
                .is_err()
        );
        remove_test_cache(&path);
    }

    #[tokio::test]
    async fn d13_13_cache_identity_is_credential_scoped_across_accounts() {
        let path = test_cache_path("different-key");
        let api_root = closed_api_root();
        let source = catalogued_entry("different-cache", &api_root, "private-model");
        seed_cache(&path, &source);
        let target =
            policy_entry_with_credential("different-cache", &api_root, Some("replacement-key"));

        let directory = ProviderDirectory::discover_entries(vec![target], Some(path.clone()))
            .await
            .unwrap();
        let entry = directory.entry("different-cache").unwrap();
        assert!(!entry.catalog_stale);
        assert!(entry.catalog.is_none());
        assert!(entry.catalog_error.is_some());
        assert!(
            directory
                .resolve_model("private-model", Some("different-cache"))
                .is_err(),
            "inventory learned with one credential must be invisible after credential rotation"
        );
        remove_test_cache(&path);
    }

    #[test]
    fn rotating_local_scope_key_invalidates_existing_cache() {
        let path = test_cache_path("rotated-local-key");
        let source = catalogued_entry(
            "scope-rotation",
            "https://gateway.example/v1",
            "private-model",
        );
        seed_cache(&path, &source);
        let cache = CatalogCache::load(&path);
        let original_key = test_scope_key(&path);
        assert!(cache.lookup(&source, &original_key).is_some());

        fs::remove_file(path.parent().unwrap().join(CATALOG_CACHE_SCOPE_KEY_FILE)).unwrap();
        let replacement_key = test_scope_key(&path);
        assert!(
            cache.lookup(&source, &replacement_key).is_none(),
            "an old HMAC must not survive local scope-key rotation"
        );
        remove_test_cache(&path);
    }

    #[tokio::test]
    async fn expired_cache_cannot_skip_refresh_or_authorize_a_bare_selection() {
        let path = test_cache_path("expired");
        let api_root = closed_api_root();
        let source = catalogued_entry("expired-cache", &api_root, "gpt-4o-mini");
        seed_cache(&path, &source);
        let mut expired = CatalogCache::load(&path);
        expired.entries[0].fetched_at_unix_secs = current_unix_secs()
            .unwrap()
            .saturating_sub(CATALOG_CACHE_TTL_SECS + 1);
        expired.save_atomic(&path).unwrap();
        let target = policy_entry("expired-cache", &api_root);

        let directory = ProviderDirectory::discover_entries(vec![target], Some(path.clone()))
            .await
            .unwrap();
        let entry = directory.entry("expired-cache").unwrap();
        assert!(!entry.catalog_stale);
        assert!(entry.catalog.is_none());
        assert!(entry.catalog_error.is_some());
        assert!(
            directory
                .validate_selection(
                    &ModelSelection {
                        provider_id: "expired-cache".into(),
                        model_id: "gpt-4o-mini".into(),
                    },
                    true,
                )
                .is_ok(),
            "an explicit route is operator evidence, not cached-catalog authorization"
        );
        assert!(
            directory
                .resolve_model("gpt-4o-mini", Some("expired-cache"))
                .is_err(),
            "an expired cache must not authorize a bare picker selection"
        );
        remove_test_cache(&path);
    }

    #[test]
    fn stale_display_evidence_does_not_make_bare_model_resolution_ambiguous() {
        let model_id = "gpt-4o-mini";
        let fresh = catalogued_entry("fresh", "https://fresh.example/v1", model_id);
        let mut stale = catalogued_entry("stale", "https://stale.example/v1", model_id);
        stale.catalog_stale = true;
        stale.catalog_provenance = CatalogProvenance::CachedFresh;
        let health = ProviderHealthStore::new(4);
        health.mark_ready("fresh");
        health.mark_ready("stale");
        let directory = ProviderDirectory {
            entries: Arc::new(vec![stale, fresh]),
            health,
        };

        assert_eq!(
            directory.resolve_model(model_id, Some("stale")).unwrap(),
            ModelSelection {
                provider_id: "fresh".into(),
                model_id: model_id.into(),
            }
        );
    }

    #[test]
    fn route_digests_separate_dynamic_operator_static_and_cached_provenance() {
        let model_id = "gpt-4o-mini";
        let dynamic = catalogued_entry("same", "https://same.example/v1", model_id);
        let mut operator = dynamic.clone();
        operator.catalog_provenance = CatalogProvenance::OperatorManifest;
        let mut static_catalog = dynamic.clone();
        static_catalog.catalog_provenance = CatalogProvenance::StaticOfficial {
            version: "schema@test-v1".into(),
            source: "https://docs.example/schema".into(),
        };
        let mut cached_fresh = dynamic.clone();
        cached_fresh.catalog_provenance = CatalogProvenance::CachedFresh;
        let selection = ModelSelection {
            provider_id: "same".into(),
            model_id: model_id.into(),
        };
        let digest_for = |entry| {
            ProviderDirectory {
                entries: Arc::new(vec![entry]),
                health: ProviderHealthStore::new(1),
            }
            .selection_digests(&selection)
        };

        let digests = [
            digest_for(dynamic),
            digest_for(operator),
            digest_for(static_catalog),
            digest_for(cached_fresh),
        ];
        for left in 0..digests.len() {
            for right in left + 1..digests.len() {
                assert_ne!(digests[left], digests[right]);
            }
        }
    }

    #[test]
    fn fatal_refresh_failures_keep_cached_names_informational_only() {
        for (availability, expected) in [
            (AccountAvailability::AuthenticationBlocked, "authentication"),
            (AccountAvailability::BillingBlocked, "balance"),
        ] {
            let mut entry =
                catalogued_entry("fatal-cache", "https://gateway.example/v1", "gpt-4o-mini");
            entry.catalog_stale = true;
            let health = ProviderHealthStore::new(4);
            let error = ProviderError::ApiResponse(core_provider::ApiResponseError {
                status: 403,
                body: "raw provider body".into(),
                body_truncated: false,
                retry_after: None,
                normalized: Box::new(core_provider::NormalizedFailure {
                    adapter: AdapterKind::OpenAiCompatibleChat,
                    error_profile: ErrorProfile::CustomConservative,
                    code: Some("fatal".into()),
                    public_message: "account unavailable",
                    scope: core_provider::ErrorScope::Account,
                    availability: core_provider::AvailabilityTransition::Account(availability),
                    retry: core_provider::RetryDisposition::Never,
                    request_id: None,
                }),
            });
            apply_catalog_failure(&mut entry, &health, &error);
            assert!(entry.catalog.is_some(), "cached names remain visible");
            let directory = ProviderDirectory {
                entries: Arc::new(vec![entry]),
                health,
            };
            assert!(
                directory
                    .blocked_reason(&directory.entries()[0])
                    .unwrap()
                    .contains(expected)
            );
        }

        let mut entry =
            catalogued_entry("config-cache", "https://gateway.example/v1", "gpt-4o-mini");
        entry.catalog_stale = true;
        let health = ProviderHealthStore::new(4);
        apply_catalog_failure(
            &mut entry,
            &health,
            &ProviderError::Configuration("bad catalog strategy".into()),
        );
        let directory = ProviderDirectory {
            entries: Arc::new(vec![entry]),
            health,
        };
        assert!(
            directory
                .blocked_reason(&directory.entries()[0])
                .unwrap()
                .contains("configuration")
        );
    }

    #[test]
    fn catalog_only_permission_failure_allows_only_explicit_inference_fallback() {
        let mut entry =
            catalogued_entry("list-denied", "https://gateway.example/v1", "cached-model");
        entry.catalog_stale = true;
        let health = ProviderHealthStore::new(4);
        let error = ProviderError::ApiResponse(core_provider::ApiResponseError {
            status: 403,
            body: "secret provider payload".into(),
            body_truncated: false,
            retry_after: None,
            normalized: Box::new(core_provider::NormalizedFailure {
                adapter: AdapterKind::OpenAiCompatibleChat,
                error_profile: ErrorProfile::CustomConservative,
                code: Some("permission_denied".into()),
                public_message: "provider permission is unavailable",
                scope: core_provider::ErrorScope::Account,
                availability: core_provider::AvailabilityTransition::Account(
                    AccountAvailability::PermissionBlocked,
                ),
                retry: core_provider::RetryDisposition::Never,
                request_id: None,
            }),
        });
        apply_catalog_failure(&mut entry, &health, &error);
        assert_eq!(
            health.get("list-denied").availability,
            AccountAvailability::Unknown,
            "catalog permission is not inference permission evidence"
        );
        assert!(entry.catalog_fallback_explicit);
        let directory = ProviderDirectory {
            entries: Arc::new(vec![entry]),
            health,
        };
        assert!(
            directory
                .validate_selection(
                    &ModelSelection {
                        provider_id: "list-denied".into(),
                        model_id: "operator-known-model".into(),
                    },
                    true,
                )
                .is_ok()
        );
        assert!(
            directory
                .resolve_model("cached-model", Some("list-denied"))
                .is_err(),
            "stale picker leaves remain informational and disabled"
        );
    }

    #[test]
    fn catalog_then_authoritative_probe_has_deterministic_recovery_semantics() {
        let billing_error = || {
            ProviderError::ApiResponse(core_provider::ApiResponseError {
                status: 429,
                body: "private provider payload".into(),
                body_truncated: false,
                retry_after: None,
                normalized: Box::new(core_provider::NormalizedFailure {
                    adapter: AdapterKind::OpenAiCompatibleChat,
                    error_profile: ErrorProfile::DeepSeek,
                    code: Some("insufficient_quota".into()),
                    public_message: "provider billing or quota is unavailable",
                    scope: core_provider::ErrorScope::Account,
                    availability: core_provider::AvailabilityTransition::Account(
                        AccountAvailability::BillingBlocked,
                    ),
                    retry: core_provider::RetryDisposition::Never,
                    request_id: Some("catalog-request".into()),
                }),
            })
        };
        let positive_balance = || AccountProbeResult {
            availability: AccountAvailability::Ready,
            balance: BalanceAvailability::Sufficient,
        };

        let mut catalog_then_probe =
            policy_entry("catalog-then-probe", "https://gateway.example/v1");
        let health = ProviderHealthStore::new(2);
        apply_catalog_result(&mut catalog_then_probe, &health, Err(billing_error()));
        assert_eq!(
            health.get(catalog_then_probe.id()).availability,
            AccountAvailability::BillingBlocked
        );
        apply_probe_result(
            &catalog_then_probe,
            &health,
            AccountProbe::DeepSeekBalance,
            Ok(positive_balance()),
        );
        assert_eq!(
            health.get(catalog_then_probe.id()),
            ProviderHealth {
                availability: AccountAvailability::Ready,
                balance: BalanceAvailability::Sufficient,
                last_error_code: None,
                last_request_id: None,
            },
            "the later documented positive-balance probe is authoritative recovery evidence"
        );

        let mut probe_then_catalog =
            policy_entry("probe-then-catalog", "https://gateway.example/v1");
        apply_probe_result(
            &probe_then_catalog,
            &health,
            AccountProbe::DeepSeekBalance,
            Ok(positive_balance()),
        );
        apply_catalog_result(&mut probe_then_catalog, &health, Err(billing_error()));
        assert_eq!(
            health.get(probe_then_catalog.id()).availability,
            AccountAvailability::BillingBlocked,
            "reversing observation order has different semantics, so concurrent completion cannot be relabelled after the fact"
        );
    }

    #[test]
    fn catalog_transport_error_is_publicly_redacted() {
        let mut entry = policy_entry("safe-error", "https://gateway.example/v1");
        let health = ProviderHealthStore::new(1);
        apply_catalog_failure(
            &mut entry,
            &health,
            &ProviderError::Http(
                "request failed for https://gateway.example/models?pageToken=sk-secret".into(),
            ),
        );
        let visible = entry.catalog_error.unwrap();
        assert_eq!(visible, "provider transport failed");
        assert!(!visible.contains("sk-secret"));
    }

    #[test]
    fn builtin_catalog_and_probe_strategies_are_provider_specific() {
        let entries = builtin_entries().unwrap();
        let deepseek = entries
            .iter()
            .find(|entry| entry.id() == "deepseek")
            .unwrap();
        let glm = entries.iter().find(|entry| entry.id() == "glm").unwrap();
        let minimax = entries
            .iter()
            .find(|entry| entry.id() == "minimax")
            .unwrap();
        let fireworks = entries
            .iter()
            .find(|entry| entry.id() == "fireworks")
            .unwrap();

        assert_eq!(
            account_probe_for(deepseek),
            Some(AccountProbe::DeepSeekBalance)
        );
        assert_eq!(minimax.instance.api_root().as_str(), MINIMAX_API_ROOT);
        assert!(matches!(
            fireworks.instance.catalog_strategy(),
            CatalogStrategy::FireworksControlPlane { api_root }
                if api_root.as_str() == "https://api.fireworks.ai/v1"
        ));
        assert_eq!(
            account_probe_for(fireworks),
            Some(AccountProbe::FireworksSuspendState)
        );

        assert!(matches!(
            glm.instance.catalog_strategy(),
            CatalogStrategy::Unsupported { reason }
                if reason.contains("no model-list endpoint")
        ));
        assert!(!glm.catalog_enabled, "GLM must never guess GET /models");
        let catalog = glm
            .catalog
            .as_ref()
            .expect("built-in GLM must expose its official static schema");
        assert_eq!(
            catalog.models.len(),
            glm.instance.static_metadata().glm_models().len()
        );
        assert!(catalog.models.iter().all(|model| {
            glm.instance
                .static_metadata()
                .glm_models()
                .contains(&model.raw.id)
                && model.compatibility == Compatibility::Compatible
                && model.selectability == Selectability::Selectable
        }));
        assert!(
            glm.catalog_error.is_none(),
            "the official static schema is not a catalog failure"
        );
    }

    #[test]
    fn minimax_text_overlay_updates_flat_and_family_descriptors() {
        let entry = policy_entry("minimax", MINIMAX_API_ROOT);
        let unknown = descriptor(
            "MiniMax-M2.1",
            Compatibility::Unknown,
            Selectability::Disabled {
                reason: "coding-turn compatibility is unknown",
            },
        );
        let image = descriptor(
            "MiniMax-Image-01",
            Compatibility::Incompatible,
            Selectability::Disabled {
                reason: "model is not a coding-turn model",
            },
        );
        let mut catalog = snapshot("minimax", vec![unknown, image]);
        apply_provider_catalog_policy(&entry, &mut catalog);

        for models in [
            catalog.models.as_slice(),
            catalog.families[0].models.as_slice(),
        ] {
            assert_eq!(models[0].compatibility, Compatibility::Compatible);
            assert_eq!(models[0].selectability, Selectability::Selectable);
            assert_eq!(models[1].compatibility, Compatibility::Incompatible);
            assert!(matches!(
                models[1].selectability,
                Selectability::Disabled { .. }
            ));
        }
    }

    #[test]
    fn openai_fine_tuned_text_id_remains_one_model_id_and_is_selectable() {
        let mut entry = policy_entry("openai", OPENAI_API_ROOT);
        let model_id = "ft:gpt-4o-mini-2024-07-18:org:project:suffix:id";
        let unknown = descriptor(
            model_id,
            Compatibility::Unknown,
            Selectability::Disabled {
                reason: "coding-turn compatibility is unknown",
            },
        );
        let mut catalog = snapshot("openai", vec![unknown]);
        apply_provider_catalog_policy(&entry, &mut catalog);
        assert_eq!(catalog.models[0].selectability, Selectability::Selectable);
        entry.catalog = Some(catalog);

        let health = ProviderHealthStore::new(4);
        health.mark_ready("openai");
        let directory = ProviderDirectory {
            entries: Arc::new(vec![entry]),
            health,
        };
        assert_eq!(
            directory.resolve_model(model_id, Some("openai")).unwrap(),
            ModelSelection {
                provider_id: "openai".into(),
                model_id: model_id.into(),
            },
            "the colon inside an OpenAI fine-tune id is not a provider separator"
        );
    }

    #[test]
    fn fireworks_control_plane_metadata_is_not_weakened_by_name_heuristics() {
        let entry = policy_entry("fireworks", "https://api.fireworks.ai/inference/v1");
        let selectable = descriptor(
            "accounts/fireworks/models/qwen-good",
            Compatibility::Compatible,
            Selectability::Selectable,
        );
        let disabled = descriptor(
            "accounts/fireworks/models/qwen-no-tools",
            Compatibility::Incompatible,
            Selectability::Disabled {
                reason: "Fireworks model does not advertise tool calling",
            },
        );
        let mut catalog = snapshot("fireworks", vec![selectable, disabled]);
        let before = catalog.clone();
        apply_provider_catalog_policy(&entry, &mut catalog);
        assert_eq!(catalog, before);
    }

    #[tokio::test]
    async fn glm_static_schema_is_account_neutral_and_uses_documented_default() {
        let directory = ProviderDirectory::discover_entries(
            vec![glm_static_entry(Some("test-key".into()))],
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            directory.health("glm").availability,
            AccountAvailability::Unknown,
            "a schema enum is not credential entitlement evidence"
        );
        assert_eq!(
            directory.resolve_model("glm:glm-5.2", None).unwrap(),
            ModelSelection {
                provider_id: "glm".into(),
                model_id: "glm-5.2".into(),
            }
        );
        assert_eq!(
            directory.default_selection("glm").unwrap().model_id,
            "glm-5.2"
        );
        let capabilities = directory.selection_capabilities(&ModelSelection {
            provider_id: "glm".into(),
            model_id: "glm-5.2".into(),
        });
        assert_eq!(capabilities.context_window_tokens, Some(1_000_000));
        assert_eq!(capabilities.max_output_tokens, Some(128_000));
        assert_eq!(capabilities.tool_calling, Some(true));
        assert_eq!(capabilities.semantic_effort, Some(true));
        assert!(
            capabilities
                .version
                .as_deref()
                .is_some_and(|version| version.starts_with("glm-5.2-model-page@2026-07-15+sha256:"))
        );
        assert_eq!(
            capabilities.source.as_deref(),
            Some("https://docs.bigmodel.cn/cn/guide/models/text/glm-5.2")
        );
        assert_eq!(
            directory.selection_capabilities(&ModelSelection {
                provider_id: "glm".into(),
                model_id: "glm-5.1".into(),
            }),
            ModelCapabilities::unknown(),
            "a family neighbour never inherits GLM-5.2 limits"
        );
        assert!(
            directory
                .resolve_model("glm:glm-undocumented", None)
                .unwrap_err()
                .contains("not in")
        );
        assert!(
            directory
                .status_label(directory.entry("glm").unwrap())
                .contains("official static schema · account entitlement unknown")
        );
    }

    #[tokio::test]
    async fn refreshed_static_metadata_updates_catalog_capability_adapter_and_run_notice() {
        let now = current_unix_secs().unwrap();
        let captured = now.saturating_sub(42 * 24 * 60 * 60);
        let mut document: serde_json::Value = serde_json::from_str(include_str!(
            "../../provider/static-provider-metadata-v1.json"
        ))
        .unwrap();
        document["bundle_revision"] = serde_json::json!("operator-refresh@test-v2");
        document["glm_standard_chat"]["version"] =
            serde_json::json!("glm-chat-completions-schema@test-v2");
        document["glm_standard_chat"]["captured_at_unix_secs"] = serde_json::json!(captured);
        document["glm_standard_chat"]["default_model"] = serde_json::json!("glm-5.1");
        document["glm_standard_chat"]["capabilities"]["glm-5.1"] = serde_json::json!({
            "version": "glm-5.1-model-page@test-v2",
            "source": "https://docs.bigmodel.cn/operator-refresh-test",
            "captured_at_unix_secs": captured,
            "context_window_tokens": 131072,
            "max_output_tokens": 8192,
            "tool_calling": true,
            "semantic_effort": true
        });
        StaticProviderMetadata::stamp_content_versions(&mut document).unwrap();
        let metadata = Arc::new(
            StaticProviderMetadata::from_slice(&serde_json::to_vec(&document).unwrap()).unwrap(),
        );
        let directory = ProviderDirectory::discover_entries(
            vec![glm_static_entry_with_metadata(
                Some("test-key".into()),
                metadata,
            )],
            None,
        )
        .await
        .unwrap();
        let selection = directory.default_selection("glm").unwrap();
        assert_eq!(selection.model_id, "glm-5.1");
        let capabilities = directory.selection_capabilities(&selection);
        assert_eq!(capabilities.context_window_tokens, Some(131_072));
        assert_eq!(capabilities.max_output_tokens, Some(8_192));
        assert!(
            capabilities
                .version
                .as_deref()
                .is_some_and(|version| version.starts_with("glm-5.1-model-page@test-v2+sha256:"))
        );

        let provider = directory.build(&selection).unwrap();
        let request = TurnRequest {
            model: selection.model_id,
            system: "stable prefix".into(),
            messages: Vec::new(),
            input_images: Vec::new(),
            tools: Vec::new(),
            max_tokens: 1_024,
            cache_system: true,
            thinking_budget: 4_096,
            reasoning_effort: core_protocol::ReasoningEffort::Medium,
        };
        assert!(matches!(
            provider.effort_application(&request),
            core_provider::EffortApplication::Mapped { .. }
        ));
        let notice = provider.run_notice(&request).unwrap();
        assert_eq!(notice.code, "static_metadata");
        assert!(notice.message.contains("42 days old (stale)"));
        assert!(notice.message.contains("provider revision changed"));
        assert_eq!(
            provider.run_notice(&request),
            Some(notice),
            "the proposal remains repeatable until the kernel durably commits it"
        );
    }

    #[tokio::test]
    async fn glm_static_schema_without_key_is_visible_but_every_leaf_is_disabled() {
        let directory = ProviderDirectory::discover_entries(vec![glm_static_entry(None)], None)
            .await
            .unwrap();
        let entry = directory.entry("glm").unwrap();
        assert_eq!(
            directory.health("glm").availability,
            AccountAvailability::MissingCredential
        );
        assert!(
            directory
                .blocked_reason(entry)
                .unwrap()
                .contains("missing credential")
        );
        assert!(directory.default_selection("glm").is_none());
        for model in &entry.catalog.as_ref().unwrap().models {
            assert!(
                directory
                    .resolve_model(&format!("glm:{}", model.raw.id), None)
                    .unwrap_err()
                    .contains("missing credential")
            );
        }
    }

    #[test]
    fn operator_manifest_becomes_a_sorted_selectable_manual_family() {
        let config = ProviderConfig {
            id: "gateway".into(),
            display_name: Some("Operator gateway".into()),
            adapter: "openai_chat".into(),
            error_profile: None,
            api_root: "https://gateway.example/v1".into(),
            key_env: "GATEWAY_KEY".into(),
            enabled: true,
            catalog: false,
            models: vec!["vendor/model-b".into(), "vendor/model-a".into()],
        };
        let entry = entry_from_config(&config).unwrap();
        let catalog = entry.catalog.as_ref().unwrap();
        assert_eq!(catalog.families.len(), 1);
        assert_eq!(catalog.families[0].id, "manual");
        assert_eq!(
            catalog.families[0].display_name,
            "Manual / operator declared"
        );
        assert_eq!(
            catalog
                .models
                .iter()
                .map(|model| model.raw.id.as_str())
                .collect::<Vec<_>>(),
            ["vendor/model-a", "vendor/model-b"]
        );
        assert!(catalog.models.iter().all(|model| {
            model.compatibility == Compatibility::Compatible
                && model.selectability == Selectability::Selectable
        }));

        let health = ProviderHealthStore::new(4);
        health.mark_ready("gateway");
        let directory = ProviderDirectory {
            entries: Arc::new(vec![entry]),
            health,
        };
        assert_eq!(
            directory
                .resolve_model("gateway:vendor/model-a", None)
                .unwrap()
                .model_id,
            "vendor/model-a"
        );
        assert!(
            directory
                .resolve_model("gateway:undeclared", None)
                .unwrap_err()
                .contains("not in")
        );
        assert!(
            directory
                .status_label(directory.entry("gateway").unwrap())
                .contains("manual catalog ready")
        );
    }

    #[test]
    fn trusted_config_can_select_an_explicit_error_profile() {
        let mut config = ProviderConfig {
            id: "gateway".into(),
            display_name: None,
            adapter: "openai_chat".into(),
            error_profile: Some("deepseek".into()),
            api_root: "https://gateway.example/v1".into(),
            key_env: "GATEWAY_KEY".into(),
            enabled: true,
            catalog: false,
            models: Vec::new(),
        };
        assert_eq!(
            entry_from_config(&config).unwrap().instance.error_profile(),
            ErrorProfile::DeepSeek
        );

        config.error_profile = None;
        assert_eq!(
            entry_from_config(&config).unwrap().instance.error_profile(),
            ErrorProfile::CustomConservative,
            "an unknown root without an operator declaration remains conservative"
        );
        config.error_profile = Some("guess".into());
        assert!(entry_from_config(&config).is_err());
    }

    #[test]
    fn known_unavailable_model_is_rejected_and_skipped_as_default() {
        let mut entry = offline_entry("gateway", AdapterKind::OpenAiCompatibleChat, true);
        entry.catalog = Some(snapshot(
            "gateway",
            vec![
                descriptor(
                    "model-a",
                    Compatibility::Compatible,
                    Selectability::Selectable,
                ),
                descriptor(
                    "model-b",
                    Compatibility::Compatible,
                    Selectability::Selectable,
                ),
            ],
        ));
        let health = ProviderHealthStore::new(4);
        health.mark_ready("gateway");
        health.update_from_turn_error(
            "gateway",
            "model-a",
            &ProviderError::ApiResponse(core_provider::ApiResponseError {
                status: 404,
                body: String::new(),
                body_truncated: false,
                retry_after: None,
                normalized: Box::new(core_provider::NormalizedFailure {
                    adapter: AdapterKind::OpenAiCompatibleChat,
                    error_profile: core_provider::ErrorProfile::CustomConservative,
                    code: Some("model_not_found".into()),
                    public_message: "model unavailable",
                    scope: core_provider::ErrorScope::Model,
                    availability: core_provider::AvailabilityTransition::ModelUnavailable,
                    retry: core_provider::RetryDisposition::Never,
                    request_id: None,
                }),
            }),
        );
        let directory = ProviderDirectory {
            entries: Arc::new(vec![entry]),
            health,
        };

        assert!(
            directory
                .validate_selection(
                    &ModelSelection {
                        provider_id: "gateway".into(),
                        model_id: "model-a".into(),
                    },
                    true,
                )
                .unwrap_err()
                .contains("known unavailable")
        );
        assert_eq!(
            directory.default_selection("gateway").unwrap().model_id,
            "model-b"
        );
    }

    #[test]
    fn explicit_retry_clears_only_the_model_leaf_and_never_an_account_gate() {
        let entry = catalogued_entry("retry-gateway", "https://gateway.example/v1", "model-a");
        let health = ProviderHealthStore::new(4);
        health.mark_ready("retry-gateway");
        let model_failure = ProviderError::ApiResponse(core_provider::ApiResponseError {
            status: 404,
            body: String::new(),
            body_truncated: false,
            retry_after: None,
            normalized: Box::new(core_provider::NormalizedFailure {
                adapter: AdapterKind::OpenAiCompatibleChat,
                error_profile: core_provider::ErrorProfile::CustomConservative,
                code: Some("model_not_found".into()),
                public_message: "model unavailable",
                scope: core_provider::ErrorScope::Model,
                availability: core_provider::AvailabilityTransition::ModelUnavailable,
                retry: core_provider::RetryDisposition::Never,
                request_id: None,
            }),
        });
        health.update_from_turn_error("retry-gateway", "model-a", &model_failure);
        let directory = ProviderDirectory {
            entries: Arc::new(vec![entry]),
            health: health.clone(),
        };
        let selection = ModelSelection {
            provider_id: "retry-gateway".into(),
            model_id: "model-a".into(),
        };

        assert!(directory.validate_selection(&selection, true).is_err());
        assert_eq!(
            directory.clear_model_unavailable_for_retry(&selection),
            Ok(true)
        );
        assert!(directory.validate_selection(&selection, true).is_ok());
        assert_eq!(
            directory.clear_model_unavailable_for_retry(&selection),
            Ok(false),
            "retry admission is explicit and one-shot"
        );

        health.update_from_turn_error("retry-gateway", "model-a", &model_failure);
        health.update_from_error(
            "retry-gateway",
            &ProviderError::ApiResponse(core_provider::ApiResponseError {
                status: 429,
                body: String::new(),
                body_truncated: false,
                retry_after: None,
                normalized: Box::new(core_provider::NormalizedFailure {
                    adapter: AdapterKind::OpenAiCompatibleChat,
                    error_profile: core_provider::ErrorProfile::OpenAi,
                    code: Some("insufficient_quota".into()),
                    public_message: "provider billing or quota is unavailable",
                    scope: core_provider::ErrorScope::Account,
                    availability: core_provider::AvailabilityTransition::Account(
                        AccountAvailability::BillingBlocked,
                    ),
                    retry: core_provider::RetryDisposition::Never,
                    request_id: None,
                }),
            }),
        );
        assert!(
            directory
                .clear_model_unavailable_for_retry(&selection)
                .is_err()
        );
        assert!(health.is_model_unavailable("retry-gateway", "model-a"));
        assert_eq!(
            health.blocked_account("retry-gateway"),
            Some(AccountAvailability::BillingBlocked)
        );
    }

    #[test]
    fn missing_credential_is_grey_and_unknown_balance_is_not() {
        let missing = offline_entry("missing", AdapterKind::OpenAiCompatibleChat, true);
        let health = ProviderHealthStore::new(4);
        health.mark_missing_credential(missing.id());
        let directory = ProviderDirectory {
            entries: Arc::new(vec![missing.clone()]),
            health: health.clone(),
        };
        assert!(
            directory
                .blocked_reason(&missing)
                .unwrap()
                .contains("missing")
        );

        let health = ProviderHealthStore::new(4);
        health.mark_ready(missing.id());
        let directory = ProviderDirectory {
            entries: Arc::new(vec![missing.clone()]),
            health,
        };
        assert_eq!(
            directory.health(missing.id()).balance,
            BalanceAvailability::Unknown
        );
        assert!(directory.blocked_reason(&missing).is_none());
        assert!(directory.status_label(&missing).contains("balance unknown"));
    }

    #[test]
    fn explicit_model_is_only_allowed_for_catalog_disabled_gateway() {
        let gateway = offline_entry("gateway", AdapterKind::OpenAiCompatibleChat, false);
        let health = ProviderHealthStore::new(4);
        health.mark_ready(gateway.id());
        let directory = ProviderDirectory {
            entries: Arc::new(vec![gateway]),
            health,
        };
        assert_eq!(
            directory
                .resolve_model("gateway:vendor-model", None)
                .unwrap(),
            ModelSelection {
                provider_id: "gateway".into(),
                model_id: "vendor-model".into(),
            }
        );
    }

    #[test]
    fn enabled_catalog_without_snapshot_fails_closed() {
        let entry = offline_entry("catalogued", AdapterKind::OpenAiCompatibleChat, true);
        let health = ProviderHealthStore::new(4);
        health.mark_ready(entry.id());
        let directory = ProviderDirectory {
            entries: Arc::new(vec![entry]),
            health,
        };
        assert!(
            directory
                .resolve_model("catalogued:made-up", None)
                .unwrap_err()
                .contains("no usable model catalog")
        );
    }
}
