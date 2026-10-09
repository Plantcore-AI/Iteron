//! Immutable presentation facts. This surface holds no provider constructor, credential source,
//! discovery worker or mutable account-health authority.
use super::{ModelCapabilities, ModelSelection, ProviderDirectory, ProviderOrigin};
use crate::route::{RouteLimits, RouteView};
use iteron_provider::CatalogSnapshot;
use std::{collections::BTreeMap, sync::Arc};

#[derive(Debug, Clone)]
pub(crate) struct ProviderCatalogEntry {
    id: String,
    display_name: String,
    origin: ProviderOrigin,
    offerable: bool,
    service_key: String,
    status: String,
    blocked: Option<String>,
    resolution_error: String,
    route: RouteView,
    pub(crate) catalog: Option<CatalogSnapshot>,
    pub(crate) catalog_enabled: bool,
    pub(crate) catalog_error: Option<String>,
    pub(crate) catalog_stale: bool,
    pub(crate) discovery_pending: bool,
}
impl ProviderCatalogEntry {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }
    pub(crate) fn display_name(&self) -> &str {
        &self.display_name
    }
    pub(crate) fn origin(&self) -> ProviderOrigin {
        self.origin
    }
    pub(crate) fn is_offerable(&self) -> bool {
        self.offerable
    }
    pub(crate) fn service_key(&self) -> &str {
        &self.service_key
    }
}

#[derive(Debug, Clone)]
struct CatalogRouteFacts {
    capabilities: ModelCapabilities,
    digests: (String, String),
    blocked: Option<String>,
    validation: Result<(), String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ProviderCatalogView {
    entries: Arc<Vec<ProviderCatalogEntry>>,
    routes: Arc<BTreeMap<(String, String), CatalogRouteFacts>>,
    inventory_digest: String,
    discovery_pending: bool,
    discovery_error: Option<String>,
}
impl ProviderCatalogView {
    /// Called only by the host after inventory admission. Count and text limits precede copying.
    pub(crate) fn capture(
        directory: &ProviderDirectory,
        selected: &ModelSelection,
        inventory_digest: String,
        discovery_pending: bool,
    ) -> Result<Self, String> {
        let mut total_models = 0_usize;
        let mut text_bytes = 0_usize;
        if directory.entries().len() > 70 {
            return Err("provider view exceeds its entry bound".into());
        }
        for entry in directory.entries() {
            identity(entry.id())?;
            if let Some(catalog) = &entry.catalog {
                total_models = total_models.saturating_add(catalog.models.len());
                if total_models > 50_000 || catalog.families.len() > 1_024 {
                    return Err("provider view exceeds its catalog bound".into());
                }
                let family_models = catalog
                    .families
                    .iter()
                    .map(|family| family.models.len())
                    .sum::<usize>();
                if family_models > catalog.models.len() {
                    return Err("provider view has duplicate family expansion".into());
                }
                for model in catalog
                    .models
                    .iter()
                    .chain(catalog.families.iter().flat_map(|family| &family.models))
                {
                    identity(&model.raw.id)?;
                    for text in [
                        Some(model.raw.id.as_str()),
                        model.raw.display_name.as_deref(),
                        model.raw.created_at.as_deref(),
                        model.raw.owned_by.as_deref(),
                        Some(model.family_id.as_str()),
                    ]
                    .into_iter()
                    .flatten()
                    {
                        text_bytes = text_bytes.saturating_add(text.len());
                        if text.len() > 512 || text_bytes > 16 * 1024 * 1024 {
                            return Err("provider view exceeds its text bound".into());
                        }
                    }
                }
                for family in &catalog.families {
                    text_bytes = text_bytes
                        .saturating_add(family.id.len())
                        .saturating_add(family.display_name.len());
                    if family.id.len() > 512
                        || family.display_name.len() > 512
                        || text_bytes > 16 * 1024 * 1024
                    {
                        return Err("provider view exceeds its family text bound".into());
                    }
                }
            }
        }
        let mut entries = Vec::new();
        let mut routes = BTreeMap::new();
        for entry in directory.entries() {
            let mut catalog = entry.catalog.clone();
            if let Some(catalog) = &mut catalog {
                for model in catalog.models.iter_mut().chain(
                    catalog
                        .families
                        .iter_mut()
                        .flat_map(|family| &mut family.models),
                ) {
                    model.raw.display_name = model.raw.display_name.as_deref().map(display);
                    model.raw.created_at = model.raw.created_at.as_deref().map(display);
                    model.raw.owned_by = model.raw.owned_by.as_deref().map(display);
                }
                for family in &mut catalog.families {
                    family.display_name = display(&family.display_name);
                }
            }
            let base_selection = ModelSelection {
                provider_id: entry.id().into(),
                model_id: String::new(),
            };
            let route =
                RouteView::resolve(directory, &base_selection, RouteView::unresolved().limits)
                    .presentation_only();
            entries.push(ProviderCatalogEntry {
                id: entry.id().into(),
                display_name: display(entry.display_name()),
                origin: entry.origin(),
                offerable: entry.is_offerable(),
                service_key: display(entry.service_key()),
                status: display(&directory.status_label(entry)),
                blocked: directory.blocked_reason(entry).as_deref().map(display),
                resolution_error: display(&directory.resolution_error(entry.id())),
                route,
                catalog,
                catalog_enabled: entry.catalog_enabled,
                catalog_error: entry.catalog_error.as_deref().map(display),
                catalog_stale: entry.catalog_stale,
                discovery_pending: directory.provider_discovery_pending(entry.id()),
            });
            let catalog_identity = super::selection_identity::CatalogIdentity::capture(entry);
            let models = entry.catalog.as_ref().into_iter().flat_map(|catalog| {
                catalog
                    .models
                    .iter()
                    .map(|model| (model.raw.id.as_str(), Some(model)))
            });
            let selected_descriptor = entry.catalog.as_ref().and_then(|catalog| {
                catalog
                    .models
                    .iter()
                    .find(|model| model.raw.id == selected.model_id)
            });
            for (model, descriptor) in models.chain(
                (selected.provider_id == entry.id())
                    .then_some((selected.model_id.as_str(), selected_descriptor)),
            ) {
                identity(model)?;
                let selection = ModelSelection {
                    provider_id: entry.id().into(),
                    model_id: model.into(),
                };
                let mut capabilities =
                    directory.entry_selection_capabilities(entry, &selection, descriptor);
                let (catalog_digest, capability_digest) =
                    catalog_identity.for_model(entry, &selection, capabilities.clone(), descriptor);
                let digests = (
                    client_sha256(catalog_digest)?,
                    client_sha256(capability_digest)?,
                );
                capabilities.source = capabilities.source.as_deref().map(display);
                capabilities.version = capabilities.version.as_deref().map(display);
                capabilities.image_input_source =
                    capabilities.image_input_source.as_deref().map(display);
                capabilities.image_input_version =
                    capabilities.image_input_version.as_deref().map(display);
                routes.insert(
                    (selection.provider_id.clone(), selection.model_id.clone()),
                    CatalogRouteFacts {
                        capabilities,
                        digests,
                        blocked: directory
                            .model_blocked_reason(entry.id(), model)
                            .as_deref()
                            .map(display),
                        validation: directory
                            .validate_entry_selection(entry, &selection, true, true, descriptor)
                            .map_err(|reason| display(&reason)),
                    },
                );
            }
        }
        Ok(Self {
            entries: Arc::new(entries),
            routes: Arc::new(routes),
            inventory_digest,
            discovery_pending,
            discovery_error: None,
        })
    }
    /// Trusted host assembly consumes the admitted draft after hashing the matching inventory.
    pub(crate) fn with_inventory_digest(mut self, digest: String) -> Self {
        self.inventory_digest = digest;
        self
    }
    pub(crate) fn selection_available(&self, selection: &ModelSelection) -> bool {
        self.routes
            .get(&(selection.provider_id.clone(), selection.model_id.clone()))
            .is_some_and(|route| route.validation.is_ok())
    }
    pub(crate) fn inventory_digest(&self) -> &str {
        &self.inventory_digest
    }
    pub(crate) fn discovery_pending(&self) -> bool {
        self.discovery_pending
    }
    pub(crate) fn discovery_error(&self) -> Option<&str> {
        self.discovery_error.as_deref()
    }
    /// A failed refresh retains the admitted route snapshot and reports the actual terminal.
    pub(crate) fn with_discovery_error(mut self, reason: Option<&str>) -> Self {
        self.discovery_error = reason.map(display);
        self
    }
    pub(crate) fn entries(&self) -> &[ProviderCatalogEntry] {
        &self.entries
    }
    pub(crate) fn entry(&self, id: &str) -> Option<&ProviderCatalogEntry> {
        self.entries.iter().find(|entry| entry.id == id)
    }
    pub(crate) fn blocked_reason(&self, entry: &ProviderCatalogEntry) -> Option<String> {
        entry.blocked.clone()
    }
    pub(crate) fn status_label(&self, entry: &ProviderCatalogEntry) -> String {
        entry.status.clone()
    }
    pub(crate) fn model_blocked_reason(&self, provider: &str, model: &str) -> Option<String> {
        self.routes
            .get(&(provider.into(), model.into()))
            .and_then(|route| route.blocked.clone())
    }
    pub(crate) fn resolution_error(&self, provider: &str) -> String {
        self.entry(provider)
            .map(|entry| entry.resolution_error.clone())
            .unwrap_or_else(|| "provider is absent from the captured host inventory".into())
    }
    pub(crate) fn selection_capabilities(&self, selection: &ModelSelection) -> ModelCapabilities {
        self.routes
            .get(&(selection.provider_id.clone(), selection.model_id.clone()))
            .map(|route| route.capabilities.clone())
            .unwrap_or_else(ModelCapabilities::unknown)
    }
    pub(crate) fn selection_digests(&self, selection: &ModelSelection) -> (String, String) {
        self.routes
            .get(&(selection.provider_id.clone(), selection.model_id.clone()))
            .map(|route| route.digests.clone())
            .unwrap_or_default()
    }
    pub(crate) fn resolve_model(
        &self,
        value: &str,
        preferred: Option<&str>,
    ) -> Result<ModelSelection, String> {
        let value = value.trim();
        identity(value)?;
        if let Some((provider, model)) = value
            .split_once(':')
            .filter(|(provider, _)| self.entry(provider).is_some())
        {
            return self.admitted_selection(provider, model);
        }
        let matches = self
            .entries
            .iter()
            .filter(|entry| {
                self.routes
                    .get(&(entry.id.clone(), value.into()))
                    .is_some_and(|route| route.validation.is_ok())
            })
            .collect::<Vec<_>>();
        let entry = preferred
            .and_then(|provider| matches.iter().find(|entry| entry.id == provider).copied())
            .or_else(|| (matches.len() == 1).then(|| matches[0]))
            .ok_or_else(|| {
                if matches.len() > 1 {
                    "model id is ambiguous; use provider:model".to_owned()
                } else {
                    "model is absent or unavailable in the captured host inventory".to_owned()
                }
            })?;
        self.admitted_selection(entry.id(), value)
    }
    fn admitted_selection(&self, provider: &str, model: &str) -> Result<ModelSelection, String> {
        let route = self
            .routes
            .get(&(provider.into(), model.into()))
            .ok_or("route is absent from the captured host inventory")?;
        route.validation.clone()?;
        Ok(ModelSelection {
            provider_id: provider.into(),
            model_id: model.into(),
        })
    }
    pub(crate) fn route_view(&self, selection: &ModelSelection, limits: RouteLimits) -> RouteView {
        let mut view = self
            .entry(&selection.provider_id)
            .map(|entry| entry.route.clone())
            .unwrap_or_else(RouteView::unresolved);
        let capabilities = self.selection_capabilities(selection);
        view.provider_id = selection.provider_id.clone();
        view.model_id = selection.model_id.clone();
        view.limits = limits;
        view.context_window_tokens = capabilities.context_window_tokens;
        view.max_output_tokens = capabilities.max_output_tokens;
        view.capability_source = capabilities.source;
        view.blocked_reason = self
            .entry(&selection.provider_id)
            .and_then(|entry| entry.blocked.clone())
            .or_else(|| self.model_blocked_reason(&selection.provider_id, &selection.model_id));
        if self.entry(&selection.provider_id).is_none() {
            view.blocked_reason =
                Some("provider is absent from the captured host inventory".into());
        } else if !self
            .routes
            .contains_key(&(selection.provider_id.clone(), selection.model_id.clone()))
        {
            view.blocked_reason = Some("route is absent from the captured host inventory".into());
        }
        view
    }
}
/// Native route journals retain their tagged commitment; public `*_sha256` fields carry only
/// its exact lowercase hexadecimal payload. This changes the representation, never the hash.
fn client_sha256(mut native: String) -> Result<String, String> {
    let valid = native.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    });
    if !valid {
        return Err("native route commitment is not a canonical SHA-256 identity".into());
    }
    native.replace_range(..7, "");
    Ok(native)
}
fn identity(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 512
        || value.chars().any(char::is_control)
        || iteron_record::redact::scrub_route_identifier(value) != value
    {
        Err("route has an unsafe or oversized identity".into())
    } else {
        Ok(())
    }
}
fn display(value: &str) -> String {
    iteron_record::redact::scrub(
        &value
            .chars()
            .filter(|character| !character.is_control())
            .take(512)
            .collect::<String>(),
    )
}

/// A read-only latest-value subscription, without a sender or host owner.
#[derive(Clone)]
pub(crate) struct ProviderCatalogSubscription(
    tokio::sync::watch::Receiver<Arc<ProviderCatalogView>>,
);
impl ProviderCatalogSubscription {
    pub(crate) fn new(receiver: tokio::sync::watch::Receiver<Arc<ProviderCatalogView>>) -> Self {
        Self(receiver)
    }
    pub(crate) fn current(&self) -> ProviderCatalogView {
        self.0.borrow().as_ref().clone()
    }
    pub(crate) fn try_changed(
        &mut self,
    ) -> Result<Option<ProviderCatalogView>, tokio::sync::watch::error::RecvError> {
        if !self.0.has_changed()? {
            return Ok(None);
        }
        Ok(Some(self.0.borrow_and_update().as_ref().clone()))
    }
    pub(crate) async fn changed(
        &mut self,
    ) -> Result<ProviderCatalogView, tokio::sync::watch::error::RecvError> {
        self.0.changed().await?;
        Ok(self.0.borrow_and_update().as_ref().clone())
    }
}
