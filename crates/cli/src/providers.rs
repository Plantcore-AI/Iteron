//! Operator-owned provider instances and their dynamic model catalogs.
//!
//! This module is the CLI-side composition layer. Wire protocols and error classification live in
//! `iteron-provider`; this layer supplies built-in instance definitions, merges trusted user config,
//! performs bounded discovery concurrently, and resolves an explicit `(provider, model)` pair.

mod cache_storage;
mod cache_writeback;
mod catalog_cache;
mod catalog_view;
mod directory;
mod discovery;
mod instance_factory;
mod probe_cache;
mod selection_identity;
use cache_storage::CatalogCacheScopeKey;
use catalog_cache::CatalogCache;
#[cfg(test)]
use catalog_cache::{CachedCatalog, CachedCompatibility, CachedModel, CachedSelectability};
pub(crate) use catalog_view::{
    ProviderCatalogEntry, ProviderCatalogSubscription, ProviderCatalogView,
};
pub(crate) use directory::ProviderDirectory;
use probe_cache::{
    CachedAvailability, CachedBalance, CachedProbeOutcome, ProbeCache, ProbeDecision, ProbeUpdates,
    probe_identity,
};
#[cfg(test)]
use probe_cache::{CachedProbe, probe_backoff_secs};

#[path = "providers/setup_effect.rs"]
mod setup_effect;

use crate::config::{ProviderConfig, ProviderCredential};
pub(crate) use instance_factory::configured_provider_ids;
use instance_factory::{
    account_probe_for, apply_provider_catalog_policy, builtin_entries_with_metadata,
    candidate_instance, entry_from_config_with_metadata,
};
#[cfg(test)]
use instance_factory::{builtin_entries, entry_from_config};
use iteron_provider::{
    AccountAvailability, AccountProbe, AccountProbeResult, AdapterKind, CatalogSnapshot,
    CatalogStrategy, Compatibility, ErrorProfile, Provider, ProviderAttemptSemantics,
    ProviderError, ProviderHealthStore, ProviderInstance, Selectability, StaticProviderMetadata,
    StreamItem, TurnRequest, TurnResult,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Six built-ins plus at most 64 trusted custom instances (the config validator's ceiling).
const MAX_PROVIDER_INSTANCES: usize = 70;
const OPENAI_API_ROOT: &str = "https://api.openai.com/v1";
const DEEPSEEK_API_ROOT: &str = "https://api.deepseek.com";
const MINIMAX_API_ROOT: &str = "https://api.minimax.io/v1";
const CATALOG_CACHE_VERSION: u32 = 4;
const CATALOG_CLASSIFIER_VERSION: u32 = 1;
const CATALOG_CACHE_FILE: &str = "catalogs-v4.json";
const CATALOG_CACHE_SCOPE_KEY_FILE: &str = "catalog-scope-v1.key";
const CATALOG_CACHE_SCOPE_KEY_BYTES: usize = 32;
const CATALOG_CACHE_SCOPE_PREFIX: &str = "hmac-sha256:";
/// Provenance stamped on capabilities that came from the operator config rather than from a
/// captured vendor snapshot. It participates in the capability digest, so a route that starts
/// trusting a declared number is recorded as a different route.
const OPERATOR_DECLARED_CAPABILITY_VERSION: &str = "operator-declared-capability-v1";
const OPERATOR_DECLARED_CAPABILITY_SOURCE: &str =
    "operator config (providers[].model_capabilities)";
const FIREWORKS_IMAGE_CAPABILITY_VERSION: &str = "fireworks-model-catalog.supportsImageInput-v1";
const FIREWORKS_IMAGE_CAPABILITY_SOURCE: &str =
    "https://docs.fireworks.ai/api-reference/list-models";
const CATALOG_CACHE_TTL_SECS: u64 = 30 * 24 * 60 * 60;
const CATALOG_CACHE_FUTURE_SKEW_SECS: u64 = 24 * 60 * 60;
const MAX_CATALOG_CACHE_BYTES: usize = 16 * 1024 * 1024;
const MAX_CATALOG_CACHE_ENTRIES: usize = MAX_PROVIDER_INSTANCES;
const MAX_CACHED_MODELS_PER_ENTRY: usize = 10_000;
const MAX_CACHED_MODELS_TOTAL: usize = 50_000;
const MAX_CACHED_FAMILIES_PER_ENTRY: usize = 1_024;
const MAX_CACHED_TEXT_BYTES: usize = 512;
const STATIC_PROVIDER_METADATA_FILE: &str = "provider-metadata.json";
/// Blocking network budget before first paint. Zero is load-bearing: validated cache/static facts
/// render immediately and all network refresh work remains deferred.
const EAGER_DISCOVERY_BUDGET: Duration = Duration::ZERO;
/// A selected route may wait briefly for its post-paint refresh at first real use. This is not a
/// launch/paint budget: the cached/static route is projected immediately, and a slow refresh stays
/// visible as pending instead of holding the interface indefinitely.
const SELECTED_PROVIDER_REFRESH_WAIT: Duration = Duration::from_millis(500);
/// Timestamp component of a cache temp-file name when the clock reads before the epoch. The pid,
/// the atomic nonce and the attempt counter in the same name still keep it unique.
const CACHE_TEMP_TIMESTAMP_ON_UNUSABLE_CLOCK: u128 = 0;
const PROBE_CACHE_FILE: &str = "account-probes-v1.json";
const PROBE_CACHE_VERSION: u32 = 1;
/// A positive probe is evidence for minutes, not days: balance and suspension both move under the
/// operator's feet. Long enough that repeated launches stop paying, short enough to notice.
const PROBE_CACHE_TTL_SECS: u64 = 15 * 60;
/// A failing probe backs off exponentially instead of costing a round trip on every launch: one
/// minute, then two, four… up to a day. A key rejected weeks ago is retried once a day, not once
/// per `iteron` invocation.
const PROBE_BACKOFF_BASE_SECS: u64 = 60;
const PROBE_BACKOFF_CAP_SECS: u64 = 24 * 60 * 60;
const MAX_PROBE_FAILURE_EXPONENT: u32 = 32;
const MAX_PROBE_CACHE_BYTES: usize = 64 * 1024;
const MAX_PROBE_CACHE_ENTRIES: usize = MAX_PROVIDER_INSTANCES;

/// Immutable bootstrap owner for provider discovery and account-probe reuse. Discovery happens
/// before a run checkpoint can be resolved, so resumed checkpoints may only attest these exact
/// binary-owned values; a different pin is rejected instead of pretending it changed work that
/// already happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct ProviderDiscoveryPolicy {
    eager_budget_milliseconds: u64,
    positive_ttl_seconds: u64,
    failure_backoff_base_seconds: u64,
    failure_backoff_cap_seconds: u64,
}

impl ProviderDiscoveryPolicy {
    pub(crate) fn owner() -> Self {
        Self {
            eager_budget_milliseconds: EAGER_DISCOVERY_BUDGET.as_millis() as u64,
            positive_ttl_seconds: iteron_tunables::param_integer(
                "cli.providers.probe_cache_ttl_secs",
                PROBE_CACHE_TTL_SECS,
            ),
            failure_backoff_base_seconds: iteron_tunables::param_integer(
                "cli.providers.probe_backoff_base_secs",
                PROBE_BACKOFF_BASE_SECS,
            ),
            failure_backoff_cap_seconds: iteron_tunables::param_integer(
                "cli.providers.probe_backoff_cap_secs",
                PROBE_BACKOFF_CAP_SECS,
            ),
        }
    }

    pub(crate) const fn eager_budget_milliseconds(self) -> u64 {
        self.eager_budget_milliseconds
    }

    pub(crate) const fn positive_ttl_seconds(self) -> u64 {
        self.positive_ttl_seconds
    }

    pub(crate) const fn failure_backoff_base_seconds(self) -> u64 {
        self.failure_backoff_base_seconds
    }

    pub(crate) const fn failure_backoff_cap_seconds(self) -> u64 {
        self.failure_backoff_cap_seconds
    }

    const fn eager_budget(self) -> Duration {
        Duration::from_millis(self.eager_budget_milliseconds)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModelSelection {
    pub provider_id: String,
    pub model_id: String,
}

const LAST_SUCCESS_ROUTE_VERSION: u8 = 1;
const LAST_SUCCESS_ROUTE_MAX_BYTES: u64 = 16 * 1024;

fn last_success_route_max_bytes() -> u64 {
    iteron_tunables::param_integer(
        "cli.providers.last_success_route_max_bytes",
        LAST_SUCCESS_ROUTE_MAX_BYTES,
    )
    .clamp(1, LAST_SUCCESS_ROUTE_MAX_BYTES)
}

/// Content-free, versioned preference learned only from a successful provider turn. It carries
/// catalog/capability identities so startup never treats a stale model name as authority.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LastSuccessRouteSnapshot {
    version: u8,
    provider_id: String,
    model_id: String,
    catalog_digest: String,
    capability_digest: String,
    source: String,
}

impl LastSuccessRouteSnapshot {
    pub(crate) fn successful(
        selection: &ModelSelection,
        catalog_digest: String,
        capability_digest: String,
    ) -> Self {
        Self {
            version: LAST_SUCCESS_ROUTE_VERSION,
            provider_id: selection.provider_id.clone(),
            model_id: selection.model_id.clone(),
            catalog_digest,
            capability_digest,
            source: "successful_provider_turn".into(),
        }
    }

    pub(crate) fn selection(&self) -> ModelSelection {
        ModelSelection {
            provider_id: self.provider_id.clone(),
            model_id: self.model_id.clone(),
        }
    }

    pub(crate) fn load_validated(
        path: &std::path::Path,
        directory: &ProviderDirectory,
    ) -> Result<Option<Self>, String> {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("cannot inspect last-success route: {error}")),
        };
        if !metadata.file_type().is_file() || metadata.len() > last_success_route_max_bytes() {
            return Err("last-success route is not a bounded regular file".into());
        }
        let bytes = std::fs::read(path)
            .map_err(|error| format!("cannot read last-success route: {error}"))?;
        let snapshot: Self = serde_json::from_slice(&bytes)
            .map_err(|error| format!("cannot decode last-success route: {error}"))?;
        if snapshot.version != LAST_SUCCESS_ROUTE_VERSION
            || snapshot.source != "successful_provider_turn"
        {
            return Err("last-success route version/source is unsupported".into());
        }
        let selection = snapshot.selection();
        directory.validate_selection(&selection, false)?;
        let (catalog, capability) = directory.selection_digests(&selection);
        if catalog != snapshot.catalog_digest || capability != snapshot.capability_digest {
            return Err("last-success route catalog/capability identity changed".into());
        }
        Ok(Some(snapshot))
    }

    /// Capture a bounded immutable value; actual filesystem publication belongs to the
    /// independently journaled advisory worker.
    pub(crate) fn maintenance_bytes(&self) -> Result<Vec<u8>, String> {
        let bytes = serde_json::to_vec(self)
            .map_err(|error| format!("cannot encode last-success route: {error}"))?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > last_success_route_max_bytes() {
            return Err("last-success route exceeded its fixed byte ceiling".into());
        }
        Ok(bytes)
    }
}

/// Versioned, provenance-bearing execution limits for one exact route. Unknown fields remain
/// `None`; dynamic model visibility never implies undocumented capacity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModelCapabilities {
    pub context_window_tokens: Option<u64>,
    pub max_output_tokens: Option<u32>,
    pub tool_calling: Option<bool>,
    pub semantic_effort: Option<bool>,
    pub image_input: Option<bool>,
    pub image_input_version: Option<String>,
    pub image_input_source: Option<String>,
    pub routing_objectives: Option<iteron_provider::RouteObjectiveScores>,
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
            image_input: None,
            image_input_version: None,
            image_input_source: None,
            routing_objectives: None,
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

impl CatalogProvenance {
    /// Operator-facing name for the evidence class behind the visible model inventory.
    fn label(&self) -> String {
        match self {
            Self::Unavailable => "unavailable".into(),
            Self::DynamicFresh => "provider catalog (fresh)".into(),
            Self::CachedFresh => "provider catalog (cached)".into(),
            Self::StaticOfficial { version, source } => {
                format!("official static schema {version} ({source})")
            }
            Self::OperatorManifest => "operator manifest".into(),
            Self::OperatorExplicit => "operator-typed model".into(),
        }
    }
}

/// Who put this provider entry in the directory.
///
/// The directory is a known-endpoints catalog first and an offer second. Without this fact the two
/// are indistinguishable: an operator opening `/model` on a fresh machine sees six vendors he never
/// named and cannot tell which line he is responsible for. Display surfaces read this to decide
/// what to offer and how to label it; routing never reads it, because a named route must resolve
/// exactly as before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderOrigin {
    /// Shipped in `BUILTINS`. A known endpoint this binary knows how to speak to, which is not the
    /// same as an endpoint this machine can use.
    Builtin,
    /// Declared by the operator in the `providers` array of their config document.
    OperatorConfigured,
}

impl ProviderOrigin {
    /// Short enough to sit inside the existing ` · `-joined status suffix without rewriting it.
    pub fn label(self) -> &'static str {
        match self {
            Self::Builtin => "built-in",
            Self::OperatorConfigured => "your config",
        }
    }
}

#[derive(Clone)]
pub(crate) struct ProviderEntry {
    pub instance: ProviderInstance,
    /// Where this instance's credential is declared. Only the NAME (an environment variable or a
    /// file path) lives here; the value is resolved per turn inside the provider instance.
    pub credential: ProviderCredential,
    origin: ProviderOrigin,
    /// Whether a credential actually resolved at construction, which `credential` cannot answer:
    /// for a built-in with neither variable nor file, `builtin_credential` deliberately still
    /// reports the variable an operator would export, so the "missing credential" line stays
    /// actionable. That makes the declared source a hint, not evidence of presence.
    credential_present: bool,
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
    /// Per-model facts the operator declared for this instance, keyed by model id. Empty for
    /// built-ins, whose facts come from the static metadata document instead.
    declared_capabilities: BTreeMap<String, crate::config::ProviderModelCapabilities>,
}

impl ProviderEntry {
    pub fn id(&self) -> &str {
        self.instance.id()
    }

    pub fn display_name(&self) -> &str {
        self.instance.display_name()
    }

    /// Value-free credential provenance for `/status`, `/config`, and `iteron auth status`.
    pub fn credential_display(&self) -> String {
        self.instance.credential_status().display()
    }

    /// The evidence class behind this entry's visible model inventory.
    pub fn catalog_provenance_label(&self) -> String {
        self.catalog_provenance.label()
    }

    /// Who put this entry in the directory.
    pub fn origin(&self) -> ProviderOrigin {
        self.origin
    }

    /// Whether a credential resolved for this entry when the directory was composed.
    pub fn credential_present(&self) -> bool {
        self.credential_present
    }

    /// Whether this entry should be OFFERED on a display surface (`/model`, `iteron auth status`
    /// with no argument). Reachability is a separate question and is never gated on this: an
    /// explicit `provider:model` still resolves, and `iteron setup` still lists everything.
    ///
    /// A built-in with no credential is a known endpoint the operator cannot use, so listing it
    /// only adds noise he must learn to ignore. An operator-configured entry is always offered even
    /// with no credential, because he asked for it by name and hiding it would hide his own typo.
    pub fn is_offerable(&self) -> bool {
        self.credential_present() || matches!(self.origin, ProviderOrigin::OperatorConfigured)
    }

    /// The underlying service two entries share, derived from the api_root host rather than from a
    /// hand-maintained table: `DeepSeek`, `DeepSeek OpenAI-compatible (IOB pin)` and
    /// `DeepSeek Anthropic-compatible (IOB pin)` are three access methods for `api.deepseek.com`,
    /// and three display names saying the same word read as a bug until they are grouped by it.
    pub fn service_key(&self) -> &str {
        api_root_host(self.instance.api_root().as_str())
    }
}

/// Host component of an already-parsed, normalized api_root (`scheme://host[:port]/path`).
///
/// `ApiRoot::parse` guarantees an absolute HTTP(S) URL with a host and no user information, so this
/// is a slice, not a re-parse. The port is kept: two ports on one host are two endpoints, and
/// collapsing them would group routes that are not the same service instance.
fn api_root_host(api_root: &str) -> &str {
    let after_scheme = api_root
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(api_root);
    after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme)
}

fn current_unix_secs() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn valid_cached_text(value: &str, max_bytes: usize, allow_empty: bool) -> bool {
    (allow_empty || !value.is_empty())
        && value.len() <= max_bytes
        && !value.chars().any(char::is_control)
}

fn valid_cached_optional_text(value: Option<&str>) -> bool {
    value.is_none_or(|value| {
        valid_cached_text(
            value,
            iteron_tunables::param_integer(
                "cli.providers.max_cached_text_bytes",
                MAX_CACHED_TEXT_BYTES,
            ),
            false,
        )
    })
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

fn default_catalog_cache_path() -> Option<PathBuf> {
    let home = iteron_protocol::home::operator()?;
    Some(iteron_protocol::home::path(&home, "cache/providers").join(CATALOG_CACHE_FILE))
}

/// The probe cache lives beside the catalog cache and shares its directory guarantees.
fn probe_cache_path_for(catalog_cache_path: Option<&Path>) -> Option<PathBuf> {
    Some(catalog_cache_path?.with_file_name(PROBE_CACHE_FILE))
}

fn default_static_provider_metadata_path() -> Option<PathBuf> {
    let home = iteron_protocol::home::operator()?;
    Some(iteron_protocol::home::path(
        &home,
        STATIC_PROVIDER_METADATA_FILE,
    ))
}

/// Operator opt-in that restores fail-closed loading of the metadata override.
const STRICT_STATIC_PROVIDER_METADATA_ENV: &str = "ITERON_STRICT_PROVIDER_METADATA";

fn strict_static_provider_metadata() -> bool {
    std::env::var(STRICT_STATIC_PROVIDER_METADATA_ENV)
        .is_ok_and(|value| matches!(value.trim(), "1" | "true" | "yes"))
}

/// Resolve the active document plus, when the override was rejected in the tolerant mode, the
/// bounded operator warning that names the file and the parse error.
///
/// A malformed override is an operator-refresh mistake in ONE data file, not a reason to take the
/// whole binary offline: the loader error used to propagate through discovery and out of both entry
/// points, killing even credential-free local commands, with no bypass flag (I-48). It now degrades
/// to the embedded snapshot; `strict` restores fail-closed loading.
fn resolve_static_provider_metadata(
    path: Option<&std::path::Path>,
    strict: bool,
) -> Result<(Arc<StaticProviderMetadata>, Option<String>), iteron_provider::ProviderError> {
    let Some(path) = path else {
        return Ok((StaticProviderMetadata::embedded(), None));
    };
    match StaticProviderMetadata::load_optional(path) {
        Ok(loaded) => Ok((
            loaded.unwrap_or_else(StaticProviderMetadata::embedded),
            None,
        )),
        Err(error) if !strict => Ok((
            StaticProviderMetadata::embedded(),
            Some(format!(
                "ignoring the provider metadata override at {}: {error}; using the embedded snapshot (set {STRICT_STATIC_PROVIDER_METADATA_ENV}=1 to fail instead)",
                path.display()
            )),
        )),
        Err(error) => Err(error),
    }
}

fn load_static_provider_metadata() -> anyhow::Result<Arc<StaticProviderMetadata>> {
    let (metadata, warning) = resolve_static_provider_metadata(
        default_static_provider_metadata_path().as_deref(),
        strict_static_provider_metadata(),
    )?;
    if let Some(warning) = warning {
        eprintln!("warning: {warning}");
    }
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
                iteron_provider::AvailabilityTransition::Account(
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

/// Everything one instance's network resolution needs. Cloned per instance so eager and deferred
/// work are literally the same code path.
#[derive(Clone)]
struct ResolveContext {
    health: ProviderHealthStore,
    probe_cache: Arc<ProbeCache>,
    probe_updates: ProbeUpdates,
    cache_scope_key: Option<CatalogCacheScopeKey>,
}

fn ordered_entries(mut indexed: Vec<(usize, ProviderEntry)>) -> Vec<ProviderEntry> {
    // The configured order is the operator's order and shows up in the picker; concurrent
    // completion must not reorder it.
    indexed.sort_by_key(|(index, _)| *index);
    indexed.into_iter().map(|(_, entry)| entry).collect()
}

/// Local half of resolving one instance: a valid cache is exact provider/API/adapter/classifier and
/// credential-scoped evidence. It may satisfy model discovery until its fixed TTL, but never proves
/// account health: missing credentials and typed probe failures still gate use.
fn prime_entry_from_cache(
    entry: &mut ProviderEntry,
    cache: &CatalogCache,
    cache_scope_key: Option<&CatalogCacheScopeKey>,
) -> bool {
    if entry.catalog_enabled
        && let Some(scope_key) = cache_scope_key
        && let Some(catalog) = cache.lookup(entry, scope_key)
    {
        entry.catalog = Some(catalog);
        entry.catalog_stale = false;
        entry.catalog_provenance = CatalogProvenance::CachedFresh;
        return true;
    }
    false
}

/// Network half of resolving one instance. Cache priming already happened.
async fn resolve_entry(
    mut entry: ProviderEntry,
    served_from_cache: bool,
    context: &ResolveContext,
) -> ProviderEntry {
    let ResolveContext {
        health,
        probe_cache,
        probe_updates,
        cache_scope_key,
    } = context;
    if !entry.enabled {
        return entry;
    }
    if !entry.instance.has_credential() {
        health.mark_missing_credential(entry.id());
        return entry;
    }
    // Provider instances remain concurrent through the outer `join_all`, but evidence for one
    // instance has a deliberate order: observe its catalog first, then run and apply its typed
    // account probe. This makes a documented positive balance/suspension observation the later
    // authority for the exact recovery scope encoded by `ProviderHealthStore::update_from_probe`,
    // instead of pretending two concurrently completed reads had a meaningful fixed observation
    // order. Unsupported catalogs (notably GLM) are disabled at construction, so they still make
    // no speculative `/models` request.
    if entry.catalog_enabled && !served_from_cache {
        let result = iteron_provider::discover_catalog(&entry.instance).await;
        apply_catalog_result(&mut entry, health, result);
    }
    let Some(probe) = account_probe_for(&entry) else {
        return entry;
    };
    // The probe used to run unconditionally, even behind a catalog cache hit and even for an
    // account that has been rejecting the same key for weeks. Persisted evidence now decides.
    let identity = cache_scope_key
        .as_ref()
        .and_then(|scope_key| probe_identity(&entry, probe, scope_key));
    let now = current_unix_secs();
    let decision = match (&identity, now) {
        (Some(identity), Some(now)) => {
            probe_cache.decide(identity, now, ProviderDiscoveryPolicy::owner())
        }
        _ => ProbeDecision::Run { failures: 0 },
    };
    match decision {
        ProbeDecision::Skip => {}
        ProbeDecision::Reuse(result) => apply_probe_result(&entry, health, probe, Ok(result)),
        ProbeDecision::Run { failures } => {
            let result = iteron_provider::probe_account(&entry.instance, probe).await;
            if let (Some(identity), Some(now)) = (identity, now) {
                probe_updates.record(
                    identity,
                    now,
                    match &result {
                        Ok(result) => CachedProbeOutcome::Observed {
                            availability: CachedAvailability::from_live(result.availability),
                            balance: CachedBalance::from_live(result.balance),
                        },
                        Err(_) => CachedProbeOutcome::Failed {
                            consecutive_failures: failures.saturating_add(1),
                        },
                    },
                );
            }
            apply_probe_result(&entry, health, probe, result);
        }
    }
    entry
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

/// The outcome of validating a candidate credential against its real endpoint.
pub(crate) struct CredentialProof {
    /// The model the validating request actually ran against.
    pub model_id: String,
}

/// Dispatch ONE minimal real request with a candidate credential.
///
/// A syntactically valid but wrong key passes every startup check today and only fails on the
/// operator's first real turn, after a wizard has already told them they are set up (I-27). The
/// only evidence that a credential works is the provider accepting it, so setup asks the provider.
pub(crate) async fn validate_credential(
    provider_id: &str,
    user: &[ProviderConfig],
    credential: &str,
) -> Result<CredentialProof, String> {
    let instance =
        candidate_instance(provider_id, user, credential).map_err(|error| error.to_string())?;
    let model_id = validation_model(&instance).await?;
    let provider = instance
        .build_turn_provider()
        .map_err(|error| format!("cannot build a request for `{provider_id}`: {error}"))?;
    if provider.attempt_semantics() != ProviderAttemptSemantics::Single {
        return Err(
            "credential validation refused a provider with opaque internal retries; every physical setup attempt must cross Iteron's durable boundary"
                .into(),
        );
    }
    // One token of output against one short message: enough for the provider to authenticate and
    // authorize the route, cheap enough to run on every setup.
    let request = TurnRequest {
        model: model_id.clone(),
        system: String::new(),
        messages: vec![iteron_protocol::Message::user_text("ping")],
        input_images: Vec::new(),
        tools: Vec::new().into(),
        max_tokens: 16,
        cache_system: false,
        thinking_budget: 0,
        reasoning_effort: iteron_protocol::ReasoningEffort::Low,
        controls: Default::default(),
    };
    let mut journal = setup_effect::SetupEffectJournal::open()?;
    // This is a setup-operation identity, deliberately not a rollout/run attempt. Intent reaches
    // stable storage before the only admitted physical request can cross the provider boundary.
    let attempt = journal.begin(provider_id, &model_id)?;
    match tokio::time::timeout(
        setup_effect::physical_deadline(),
        provider.turn(&request, &mut |_item: StreamItem| {}),
    )
    .await
    {
        Ok(Ok(_)) => {
            journal.terminal(
                &attempt,
                setup_effect::SetupAttemptOutcome::Succeeded,
                setup_effect::SetupAttemptReason::Accepted,
            )?;
            Ok(CredentialProof { model_id })
        }
        Ok(Err(error)) => {
            let (outcome, reason_code) = if setup_provider_outcome_is_unobservable(&error) {
                (
                    setup_effect::SetupAttemptOutcome::Unknown,
                    setup_effect::SetupAttemptReason::ProviderOutcomeUnobservable,
                )
            } else {
                (
                    setup_effect::SetupAttemptOutcome::FailedDefinite,
                    setup_effect::SetupAttemptReason::ProviderFailedDefinite,
                )
            };
            // Terminal durability precedes the operator-facing return. Provider bodies and the
            // candidate credential never enter this setup-operation record.
            journal.terminal(&attempt, outcome, reason_code)?;
            Err(describe_validation_failure(&error))
        }
        Err(_) => {
            journal.terminal(
                &attempt,
                setup_effect::SetupAttemptOutcome::Unknown,
                setup_effect::SetupAttemptReason::SetupDeadline,
            )?;
            Err("credential validation reached its 60 second deadline; the provider outcome is unknown and was not retried".into())
        }
    }
}

fn setup_provider_outcome_is_unobservable(error: &ProviderError) -> bool {
    matches!(
        error,
        ProviderError::Interrupted
            | ProviderError::DeadlineExceeded
            | ProviderError::Timeout { .. }
            | ProviderError::Stream(_)
            | ProviderError::Decode(_)
    )
}

/// Pick a model to validate against without asking the operator for one.
async fn validation_model(instance: &ProviderInstance) -> Result<String, String> {
    if instance.api_root().as_str() == instance.static_metadata().glm_api_root()
        && instance.adapter() == AdapterKind::OpenAiCompatibleChat
    {
        return Ok(instance.static_metadata().glm_default_model().to_owned());
    }
    match iteron_provider::discover_catalog(instance).await {
        Ok(snapshot) => snapshot
            .models
            .iter()
            .find(|model| matches!(model.selectability, Selectability::Selectable))
            .map(|model| model.raw.id.clone())
            .ok_or_else(|| {
                format!(
                    "`{}` accepted the credential but published no model this build can run a coding turn against",
                    instance.id()
                )
            }),
        Err(error) => Err(describe_validation_failure(&error)),
    }
}

/// Turn a provider failure into the one line an operator can act on. Provider bodies are never
/// copied: some gateways echo the credential back inside their error payload.
fn describe_validation_failure(error: &ProviderError) -> String {
    match error {
        ProviderError::MissingCredential { .. } => "the credential was empty".into(),
        ProviderError::ApiResponse(response) => match response.status {
            401 | 403 => format!(
                "the provider rejected this credential (HTTP {}): {}",
                response.status, response.normalized.public_message
            ),
            402 | 429 => format!(
                "the credential authenticated but the account cannot serve a request (HTTP {}): {}",
                response.status, response.normalized.public_message
            ),
            status => format!(
                "the provider refused the validating request (HTTP {status}): {}",
                response.normalized.public_message
            ),
        },
        ProviderError::Api { status, .. } => match status {
            401 | 403 => format!("the provider rejected this credential (HTTP {status})"),
            status => format!("the provider refused the validating request (HTTP {status})"),
        },
        ProviderError::UnsupportedCatalog { reason, .. } => format!(
            "this endpoint publishes no model list ({reason}); declare `models` for it in ~/.iteron/config.json"
        ),
        other => format!("the validating request failed: {other}"),
    }
}
