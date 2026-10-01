//! Immutable operator catalog and its exact read/selection/build authority. Physical discovery
//! is owned separately; cache state, scope secrets and persistence stay behind their own ports.
use super::cache_storage::CatalogCacheScopeKey;
use super::cache_writeback::DiscoveryPersistence;
use super::catalog_cache::CatalogCache;
use super::discovery::{DiscoverySettlement, ProviderDiscoveryOwner, ProviderRefreshActivity};
use super::instance_factory::{
    OPENAI_API_MODEL_PREFERENCE, is_builtin_openai_entry, is_glm_standard_schema_entry,
    manual_model_allowed,
};
use super::probe_cache::{ProbeCache, ProbeUpdates};
use super::{
    CatalogProvenance, FIREWORKS_IMAGE_CAPABILITY_SOURCE, FIREWORKS_IMAGE_CAPABILITY_VERSION,
    MAX_PROVIDER_INSTANCES, ModelCapabilities, ModelSelection, OPERATOR_DECLARED_CAPABILITY_SOURCE,
    OPERATOR_DECLARED_CAPABILITY_VERSION, ProviderConfig, ProviderDiscoveryPolicy, ProviderEntry,
    ResolveContext, UnavailableProvider, builtin_entries_with_metadata, default_catalog_cache_path,
    entry_from_config_with_metadata, load_static_provider_metadata, ordered_entries,
    prime_entry_from_cache, probe_cache_path_for, resolve_entry,
};
use futures_util::future::join_all;
use iteron_provider::{
    AccountAvailability, BalanceAvailability, CatalogStrategy, ErrorProfile,
    HealthReportingProvider, ModelDescriptor, Provider, ProviderHealth, ProviderHealthStore,
    Selectability,
};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
/// Immutable catalog/configuration plus a shared, interior-mutable account health store.
#[derive(Clone)]
pub(crate) struct ProviderDirectory {
    entries: Arc<Vec<ProviderEntry>>,
    health: ProviderHealthStore,
    /// Instances whose network discovery was deliberately NOT awaited before the first frame.
    /// `None` once every instance is resolved, which is also the shape every legacy caller gets.
    deferred: Option<Arc<ProviderDiscoveryOwner>>,
    refresh_activity: ProviderRefreshActivity,
}

impl ProviderDirectory {
    /// Attach deferred discovery to the same bounded live-activity ingress as the resident runtime.
    /// If discovery already settled, the terminal snapshot is emitted immediately; no refresh is
    /// restarted and no network work happens here.
    pub(crate) fn set_activity(
        &self,
        tx: tokio::sync::mpsc::Sender<iteron_protocol::ActivityEvent>,
    ) {
        self.refresh_activity.install(tx);
    }

    /// Cross the first-paint boundary through the sole physical discovery owner.
    pub(crate) fn begin_settle_after_paint(&self) -> bool {
        self.deferred
            .as_ref()
            .is_none_or(|owner| owner.begin_after_paint())
    }

    /// Environment variable names whose values back configured providers. Names are safe control
    /// metadata; values remain inside provider instances. Operator shell children remove these
    /// variables so `!env` cannot expose inference credentials to the TUI.
    pub(crate) fn credential_env_names(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter_map(|entry| entry.credential.env_name().map(str::to_owned))
            .collect()
    }

    /// Credential FILES backing configured providers. A file-backed subscription token never
    /// appears in the environment, so the env-name redaction set alone would let its path — and
    /// therefore, through any read tool, its value — reach an agent, a tool, or a hook.
    pub(crate) fn credential_file_paths(&self) -> Vec<PathBuf> {
        self.entries
            .iter()
            .filter_map(|entry| {
                entry
                    .instance
                    .credential_source()
                    .file_path()
                    .map(Path::to_path_buf)
            })
            .collect()
    }

    /// Credential files that live INSIDE the workspace.
    ///
    /// The workspace is precisely the region a tool, a child agent, and a hook may read. Keeping a
    /// credential VALUE out of provider output is worth nothing if `read_file` can open the file
    /// it came from, and confinement is owned by another layer, so the composition root refuses
    /// the route rather than trusting a boundary it does not enforce.
    pub(crate) fn credential_files_inside(&self, workspace: &Path) -> Vec<PathBuf> {
        self.credential_file_paths()
            .into_iter()
            .filter(|path| {
                let resolved = path.canonicalize().unwrap_or_else(|_| path.clone());
                let workspace = workspace
                    .canonicalize()
                    .unwrap_or_else(|_| workspace.to_path_buf());
                resolved.starts_with(&workspace)
            })
            .collect()
    }

    /// Construct all built-ins plus trusted user instances, then discover credential-visible
    /// catalogs concurrently across provider instances. Missing credentials make zero network
    /// requests.
    pub async fn discover(user: &[ProviderConfig]) -> anyhow::Result<Self> {
        Self::discover_entries(Self::compose_entries(user)?, default_catalog_cache_path()).await
    }

    /// Build the operator-visible directory without starting catalog or account network probes.
    ///
    /// Credential provenance and presence are local facts. Commands such as `iteron auth status`
    /// must remain bounded even when a configured endpoint black-holes DNS or TCP; health remains
    /// honestly unknown until a launch or explicit setup validation produces evidence.
    pub fn inspect_local(user: &[ProviderConfig]) -> anyhow::Result<Self> {
        let entries = Self::compose_entries(user)?;
        Ok(Self {
            health: ProviderHealthStore::new(entries.len()),
            entries: Arc::new(entries),
            deferred: None,
            refresh_activity: ProviderRefreshActivity::default(),
        })
    }

    /// Discovery for a launch that already knows where it is routing.
    ///
    /// Only the instances named in `eager` are eligible for pre-paint resolution; with the
    /// canonical zero budget every network future remains dormant until
    /// [`ProviderDirectory::settle`] is called after first paint. Awaiting every configured
    /// provider is what let one
    /// black-holed endpoint hold the whole launch for a 15 s catalog deadline plus another for its
    /// account probe.
    pub async fn discover_eagerly(
        user: &[ProviderConfig],
        eager: &[String],
    ) -> anyhow::Result<Self> {
        Self::discover_entries_eagerly(
            Self::compose_entries(user)?,
            default_catalog_cache_path(),
            Some(eager),
        )
        .await
    }

    fn compose_entries(user: &[ProviderConfig]) -> anyhow::Result<Vec<ProviderEntry>> {
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
        if entries.len()
            > iteron_tunables::param_integer(
                "cli.providers.max_provider_instances",
                MAX_PROVIDER_INSTANCES,
            )
        {
            anyhow::bail!("provider directory exceeds {MAX_PROVIDER_INSTANCES} instances");
        }
        Ok(entries)
    }

    async fn discover_entries(
        entries: Vec<ProviderEntry>,
        cache_path: Option<PathBuf>,
    ) -> anyhow::Result<Self> {
        Self::discover_entries_eagerly(entries, cache_path, None).await
    }

    /// `eager: None` resolves every instance synchronously — the shape every non-launch caller and
    /// every test still gets. `Some(ids)` splits the work as described on `discover_eagerly`.
    async fn discover_entries_eagerly(
        entries: Vec<ProviderEntry>,
        cache_path: Option<PathBuf>,
        eager: Option<&[String]>,
    ) -> anyhow::Result<Self> {
        if entries.len()
            > iteron_tunables::param_integer(
                "cli.providers.max_provider_instances",
                MAX_PROVIDER_INSTANCES,
            )
        {
            anyhow::bail!("provider directory exceeds {MAX_PROVIDER_INSTANCES} instances");
        }
        let health = ProviderHealthStore::new(iteron_tunables::param_integer(
            "cli.providers.max_provider_instances",
            MAX_PROVIDER_INSTANCES,
        ));
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
        let probe_cache_path = cache_scope_key
            .as_ref()
            .and_then(|_| probe_cache_path_for(cache_path.as_deref()));
        let probe_cache = Arc::new(match &probe_cache_path {
            Some(path) => ProbeCache::load(path),
            None => ProbeCache::default(),
        });
        let probe_updates = ProbeUpdates::default();

        // Cache priming is local evidence: it costs no request, so it happens for EVERY instance
        // — eager or deferred — before anything is allowed to wait. That is also what makes the
        // eager timeout safe: the fallback is the catalog the cache already proved.
        let primed: Vec<(usize, ProviderEntry, bool)> = entries
            .into_iter()
            .enumerate()
            .map(|(index, mut entry)| {
                let served = prime_entry_from_cache(&mut entry, &cache, cache_scope_key.as_ref());
                (index, entry, served)
            })
            .collect();
        let (eager_entries, mut pending): (Vec<_>, Vec<_>) = match eager {
            None => (primed, Vec::new()),
            Some(ids) => primed
                .into_iter()
                .partition(|(_, entry, _)| ids.iter().any(|id| id == entry.id())),
        };

        let context = ResolveContext {
            health: health.clone(),
            probe_cache: probe_cache.clone(),
            probe_updates: probe_updates.clone(),
            cache_scope_key: cache_scope_key.clone(),
        };
        let budget = eager.map(|_| ProviderDiscoveryPolicy::owner().eager_budget());
        let mut resolved: Vec<(usize, ProviderEntry)> = Vec::new();
        // A zero eager budget means exactly zero provider polls before first paint. Wrapping the
        // future in `timeout(Duration::ZERO, ...)` is not equivalent: Tokio may poll a locally
        // ready socket once and nondeterministically adopt that provider while identical slower
        // providers remain deferred. Keep the launch result independent of network timing.
        let eager_entries = if budget.is_some_and(|budget| budget.is_zero()) {
            pending.extend(eager_entries);
            Vec::new()
        } else {
            eager_entries
        };
        for (index, entry, served, settled) in
            join_all(eager_entries.into_iter().map(|(index, entry, served)| {
                let context = context.clone();
                async move {
                    let Some(budget) = budget else {
                        return (
                            index,
                            resolve_entry(entry, served, &context).await,
                            served,
                            true,
                        );
                    };
                    // The bound is the whole point: keep whatever the cache already proved and let
                    // the slow endpoint finish behind the frame with the deferred instances.
                    let fallback = entry.clone();
                    match tokio::time::timeout(budget, resolve_entry(entry, served, &context)).await
                    {
                        Ok(entry) => (index, entry, served, true),
                        Err(_) => (index, fallback, served, false),
                    }
                }
            }))
            .await
        {
            if settled {
                resolved.push((index, entry));
            } else {
                pending.push((index, entry, served));
            }
        }

        let persistence = DiscoveryPersistence::new(
            cache,
            cache_scope_key,
            cache_path,
            probe_cache,
            probe_cache_path,
            probe_updates,
        );
        if pending.is_empty() {
            let discovered = ordered_entries(resolved);
            persistence.commit(&discovered);
            return Ok(Self {
                entries: Arc::new(discovered),
                health,
                deferred: None,
                refresh_activity: ProviderRefreshActivity::default(),
            });
        }

        // What the caller sees NOW: the eagerly resolved instances plus the pending ones at their
        // cache-primed state. Nothing here is a network result the caller has not paid for.
        let immediate = ordered_entries(
            resolved
                .iter()
                .cloned()
                .chain(
                    pending
                        .iter()
                        .map(|(index, entry, _)| (*index, entry.clone())),
                )
                .collect(),
        );
        let deferred_ids: BTreeSet<String> = pending
            .iter()
            .map(|(_, entry, _)| entry.id().to_owned())
            .collect();
        let refresh_activity = ProviderRefreshActivity::pending();

        Ok(Self {
            entries: Arc::new(immediate),
            health,
            deferred: Some(Arc::new(ProviderDiscoveryOwner::new(
                deferred_ids,
                pending,
                resolved,
                context,
                persistence,
                refresh_activity.clone(),
            ))),
            refresh_activity,
        })
    }

    /// Start and join deferred discovery so a full-catalog read (the model picker, cross-provider
    /// model resolution) sees every instance. Interactive callers invoke this only after first
    /// paint; construction alone never polls a provider. Idempotent, and cheap once landed.
    pub(crate) async fn settle(&mut self) -> bool {
        let Some(owner) = self.deferred.clone() else {
            return true;
        };
        match owner.settle().await {
            DiscoverySettlement::Settled(entries) => {
                self.entries = entries;
                self.deferred = None;
                true
            }
            DiscoverySettlement::Pending => false,
            DiscoverySettlement::Abandoned => {
                self.deferred = None;
                false
            }
        }
    }

    pub(crate) fn discovery_pending(&self) -> bool {
        self.deferred.is_some()
    }

    /// Host publication joins the same physical task to its real terminal; selected-route calls
    /// retain their short observation timeout. This does not launch another refresh or retry.
    pub(crate) async fn settle_complete(&mut self) -> bool {
        let Some(owner) = self.deferred.clone() else {
            return true;
        };
        match owner.settle_complete().await {
            DiscoverySettlement::Settled(entries) => {
                self.entries = entries;
                self.deferred = None;
                true
            }
            DiscoverySettlement::Abandoned => {
                self.deferred = None;
                false
            }
            DiscoverySettlement::Pending => false,
        }
    }

    /// True when this launch is about to read routing evidence that deferred discovery has not
    /// produced yet, so the caller must [`settle`](Self::settle) first. The common case — a routed
    /// provider that was resolved eagerly, offering the requested model — never waits.
    pub(crate) fn needs_settled_catalogs(&self, model_id: Option<&str>, provider_id: &str) -> bool {
        let Some(deferred) = self.deferred.as_ref() else {
            return false;
        };
        // The routed provider itself. `--resume` adopts the provider recorded in the rollout, which
        // the launch had no way to name before discovery began, so the eager set can miss exactly
        // the instance every request is about to go to. Its id, not its catalog, is what decides:
        // a deferred instance can already carry a cache-primed catalog and still owe its account
        // probe. Routing on half-resolved evidence is how a launch reports "no selectable model"
        // for a provider that is perfectly healthy.
        if deferred.is_pending(provider_id) {
            return true;
        }
        let Some(model_id) = model_id else {
            return false;
        };
        // A provider-qualified id is resolved against that provider alone.
        if let Some((qualifier, _)) = model_id.split_once(':')
            && self.entry(qualifier).is_some()
        {
            return deferred.is_pending(qualifier);
        }
        !self.entry(provider_id).is_some_and(|entry| {
            entry
                .catalog
                .as_ref()
                .is_some_and(|catalog| catalog.models.iter().any(|model| model.raw.id == model_id))
        })
    }

    pub fn entries(&self) -> &[ProviderEntry] {
        &self.entries
    }

    /// Clone the exact captured catalog/configuration for host controls. Selection through this
    /// owner never runs deferred discovery or silently replaces its advertised identity.
    pub(crate) fn frozen_client_snapshot(&self) -> Self {
        Self {
            entries: self.entries.clone(),
            health: self.health.clone(),
            deferred: None,
            refresh_activity: ProviderRefreshActivity::default(),
        }
    }

    /// The entries a display surface should OFFER, in the same order `entries` returns them.
    ///
    /// This is strictly a presentation filter. Everything dropped here stays fully routable through
    /// `entry`, `resolve_model` and an explicit `provider:model`, and stays offered by
    /// `configured_provider_ids` so `iteron setup` can give it the credential it is missing.
    pub fn offerable_entries(&self) -> impl Iterator<Item = &ProviderEntry> {
        self.entries.iter().filter(|entry| entry.is_offerable())
    }

    pub fn entry(&self, provider_id: &str) -> Option<&ProviderEntry> {
        self.entries.iter().find(|entry| entry.id() == provider_id)
    }

    /// Whether this provider has a credential available right now, from any source.
    pub fn has_credential(&self, provider_id: &str) -> bool {
        self.entry(provider_id)
            .is_some_and(|entry| entry.instance.has_credential())
    }

    /// The first provider holding a credential, in built-ins-then-configured order.
    ///
    /// A build-time default cannot know which account the operator actually has, so on a fresh
    /// machine it names a provider they may never have signed up for and the first run dies on a
    /// missing variable. This answers the question the constant was standing in for: of the routes
    /// this machine can actually authenticate, which comes first.
    ///
    /// Deliberately credential presence only. It reads no catalog and makes no request, so it is
    /// safe to call before discovery, and a present-but-rejected key still resolves here and then
    /// fails loudly on its own terms rather than being silently skipped.
    pub fn first_credentialed_provider(&self) -> Option<&str> {
        self.entries
            .iter()
            .find(|entry| entry.instance.has_credential())
            .map(|entry| entry.id())
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
                    entry.credential.display()
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

    /// Say WHY a provider yielded no route, using the evidence the directory already holds.
    ///
    /// `default_selection` returns `None` for four unrelated states — no credential, a rejected
    /// credential, an unreachable provider, and a stale cached catalog — and the composition root
    /// used to collapse all four into `provider ... has no selectable discovered model`, which
    /// tells an operator on a clean machine nothing at all (I-05). Each state keeps its own line,
    /// and a missing credential names the exact variable to set.
    pub fn resolution_error(&self, provider_id: &str) -> String {
        let Some(entry) = self.entry(provider_id) else {
            let known: Vec<&str> = self.entries.iter().map(ProviderEntry::id).collect();
            return format!(
                "provider `{provider_id}` is not configured (known: {}); run `iteron setup` or declare it in ~/.iteron/config.json",
                known.join(", ")
            );
        };
        match self.blocked_reason(entry) {
            Some(reason) => {
                let remedy = match self.health(entry.id()).availability {
                    // Nothing on this machine can authenticate anywhere: that is a setup state,
                    // not a fault of whichever provider the fallback happened to name. Reporting
                    // it as one provider's problem sends a first-time operator to sign up with a
                    // vendor chosen at build time, so say what is actually true and list every
                    // variable this configuration would honour.
                    AccountAvailability::MissingCredential
                        if self.first_credentialed_provider().is_none() =>
                    {
                        format!(
                            ". No provider on this machine has a credential yet, so this is a \
                             setup step rather than a problem with `{provider_id}`.\n\
                             Any one of these will do:\n  {}\n\
                             For `{provider_id}`: run `iteron setup --byok {provider_id}`, or \
                             without a terminal: printenv <VAR> | iteron setup --byok \
                             {provider_id} --stdin",
                            self.credential_env_names().join(", ")
                        )
                    }
                    AccountAvailability::MissingCredential => format!(
                        "; run `iteron setup --byok {provider_id}`, or set it in the environment"
                    ),
                    AccountAvailability::AuthenticationBlocked => format!(
                        "; the credential ({}) was rejected — run `iteron setup --byok {provider_id}` to replace it",
                        entry.credential.display()
                    ),
                    _ => String::new(),
                };
                format!("provider `{provider_id}` is unavailable: {reason}{remedy}")
            }
            // Not blocked and still no model: discovery could not reach the provider, or it
            // returned nothing this build can dispatch a coding turn against.
            None => match entry.catalog_error.as_deref() {
                Some(error) => format!(
                    "provider `{provider_id}` returned no usable catalog: {error}; check network reachability of {} or pin a model with --model",
                    entry.instance.api_root().as_str()
                ),
                None => format!(
                    "provider `{provider_id}` has no selectable discovered model at {}; pin one explicitly with --model {provider_id}:<model-id>",
                    entry.instance.api_root().as_str()
                ),
            },
        }
    }

    /// Pick a provider's documented or version-pinned preferred model when it is actually
    /// selectable in this account's catalog. This is used only when no model was supplied.
    pub fn default_selection(&self, provider_id: &str) -> Option<ModelSelection> {
        let entry = self.entry(provider_id)?;
        if self.blocked_reason(entry).is_some() {
            return None;
        }
        let catalog = entry.catalog.as_ref()?;
        // A preferred model is considered only after the current account catalog and model
        // health admit it. Operator catalogs and credentials remain the selection authority.
        let admissible = |model: &&ModelDescriptor| {
            matches!(model.selectability, Selectability::Selectable)
                && self
                    .model_blocked_reason(provider_id, &model.raw.id)
                    .is_none()
        };
        let preferred = if is_glm_standard_schema_entry(entry) {
            catalog.models.iter().find(|model| {
                model.raw.id == entry.instance.static_metadata().glm_default_model()
                    && admissible(model)
            })
        } else if is_builtin_openai_entry(entry) {
            OPENAI_API_MODEL_PREFERENCE.iter().find_map(|preferred| {
                catalog
                    .models
                    .iter()
                    .find(|model| model.raw.id == *preferred && admissible(model))
            })
        } else {
            None
        };
        let model = preferred.or_else(|| catalog.models.iter().find(admissible))?;
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
        let descriptor = entry.catalog.as_ref().and_then(|catalog| {
            catalog
                .models
                .iter()
                .find(|model| model.raw.id == selection.model_id)
        });
        self.validate_entry_selection(entry, selection, explicit, enforce_model_health, descriptor)
    }

    pub(super) fn validate_entry_selection(
        &self,
        entry: &ProviderEntry,
        selection: &ModelSelection,
        explicit: bool,
        enforce_model_health: bool,
        descriptor: Option<&ModelDescriptor>,
    ) -> Result<(), String> {
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
        if entry.catalog.is_some() && !explicit_catalog_fallback {
            let model = descriptor.ok_or_else(|| {
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
        self.build_inner(selection, None)
    }

    /// Build the selected route with a fixed host transport. Only the cloned selected
    /// `ProviderInstance` receives it; every other provider and HTTP subsystem remains unchanged.
    pub fn build_with_transport(
        &self,
        selection: &ModelSelection,
        transport: &dyn iteron_provider::catalog::HttpTransport,
    ) -> Result<Arc<dyn Provider>, String> {
        self.build_inner(selection, Some(transport))
    }

    fn build_inner(
        &self,
        selection: &ModelSelection,
        transport: Option<&dyn iteron_provider::catalog::HttpTransport>,
    ) -> Result<Arc<dyn Provider>, String> {
        self.validate_selection(selection, true)?;
        let entry = self
            .entry(&selection.provider_id)
            .ok_or_else(|| format!("unknown provider `{}`", selection.provider_id))?;
        let instance = match transport {
            Some(transport) => entry
                .instance
                .clone()
                .with_fixed_http_transport(transport)
                .map_err(|error| error.to_string())?,
            None => entry.instance.clone(),
        };
        let provider = instance
            .build_turn_provider()
            .map_err(|error| error.to_string())?;
        let image_input = self.selection_capabilities(selection).image_input;
        let provider: Arc<dyn Provider> = Arc::new(
            HealthReportingProvider::new(
                provider,
                selection.provider_id.clone(),
                self.health.clone(),
            )
            .with_model_scoped_account_failures(
                entry.instance.error_profile() == ErrorProfile::Fireworks,
            )
            .with_image_input_support(image_input)
            .with_idempotent_request_support(transport.is_some())
            .with_static_metadata_notice(
                entry.instance.static_metadata_handle(),
                entry.instance.adapter(),
                entry.instance.error_profile(),
                entry.instance.api_root().as_str(),
                selection.model_id.clone(),
            ),
        );
        if let Some(deferred) = self
            .deferred
            .as_ref()
            .filter(|deferred| deferred.is_pending(&selection.provider_id))
        {
            Ok(deferred.admit_provider(provider))
        } else {
            Ok(provider)
        }
    }

    /// Return only capabilities documented for this exact endpoint/model pair. The route identity
    /// is the (api_root, model) pair — the exact egress destination plus the model id — so a
    /// wire-compatible gateway at another API root still inherits nothing. Requiring the GLM
    /// adapter and error profile as well left every other provider with unknown capabilities, which
    /// silently disabled the over-window preflight and degraded the statusline (I-30).
    pub fn selection_capabilities(&self, selection: &ModelSelection) -> ModelCapabilities {
        let Some(entry) = self.entry(&selection.provider_id) else {
            return ModelCapabilities::unknown();
        };
        let descriptor = entry.catalog.as_ref().and_then(|snapshot| {
            snapshot
                .models
                .iter()
                .find(|model| model.raw.id == selection.model_id)
        });
        self.entry_selection_capabilities(entry, selection, descriptor)
    }

    pub(super) fn entry_selection_capabilities(
        &self,
        entry: &ProviderEntry,
        selection: &ModelSelection,
        descriptor: Option<&ModelDescriptor>,
    ) -> ModelCapabilities {
        let mut resolved = ModelCapabilities::unknown();
        let metadata = entry.instance.static_metadata();
        if let Some(capabilities) = metadata
            .route_model_capabilities(entry.instance.api_root().as_str(), &selection.model_id)
        {
            resolved.context_window_tokens = capabilities.context_window_tokens;
            resolved.max_output_tokens = capabilities.max_output_tokens;
            resolved.tool_calling = capabilities.tool_calling;
            resolved.semantic_effort = capabilities.semantic_effort;
            resolved.image_input = capabilities.image_input;
            resolved.routing_objectives = capabilities.routing_objectives;
            resolved.version = Some(capabilities.version.clone());
            resolved.source = Some(capabilities.source.clone());
            if capabilities.image_input.is_some() {
                resolved.image_input_version = Some(capabilities.version.clone());
                resolved.image_input_source = Some(capabilities.source.clone());
            }
        }
        if resolved.image_input.is_none()
            && entry.instance.error_profile() == ErrorProfile::Fireworks
            && let Some(supported) = descriptor
                .filter(|_| !entry.catalog_fallback_explicit)
                .and_then(|model| model.raw.supports_image_input)
        {
            resolved.image_input = Some(supported);
            resolved.image_input_version = Some(FIREWORKS_IMAGE_CAPABILITY_VERSION.into());
            resolved.image_input_source = Some(FIREWORKS_IMAGE_CAPABILITY_SOURCE.into());
        }
        // An official vendor snapshot outranks a hand-written number, so this is reached only
        // when the static document cannot speak for this route. The declaration is marked as
        // operator provenance rather than borrowing a version/source that would read like
        // captured vendor evidence, which keeps the capability digest honest about where the
        // number came from.
        if let Some(declared) = entry.declared_capabilities.get(&selection.model_id) {
            if resolved.context_window_tokens.is_none()
                && let Some(window) = declared.context_window_tokens
            {
                resolved.context_window_tokens = Some(window);
                resolved.version = Some(OPERATOR_DECLARED_CAPABILITY_VERSION.into());
                resolved.source = Some(OPERATOR_DECLARED_CAPABILITY_SOURCE.into());
            }
            if resolved.image_input.is_none()
                && let Some(supported) = declared.image_input
            {
                resolved.image_input = Some(supported);
                resolved.image_input_version = Some(OPERATOR_DECLARED_CAPABILITY_VERSION.into());
                resolved.image_input_source = Some(OPERATOR_DECLARED_CAPABILITY_SOURCE.into());
            }
            if resolved.routing_objectives.is_none()
                && let Some(scores) = declared.routing_objectives
            {
                resolved.routing_objectives = Some(scores);
                resolved.version = Some(OPERATOR_DECLARED_CAPABILITY_VERSION.into());
                resolved.source = Some(OPERATOR_DECLARED_CAPABILITY_SOURCE.into());
            }
        }
        resolved
    }

    /// Content-only identity of the selected physical route and admitted metadata.
    pub fn selection_digests(&self, selection: &ModelSelection) -> (String, String) {
        let Some(entry) = self.entry(&selection.provider_id) else {
            return (String::new(), String::new());
        };
        super::selection_identity::project(entry, selection, self.selection_capabilities(selection))
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

#[cfg(test)]
#[path = "directory/tests.rs"]
mod tests;
