//! Immutable bootstrap evidence and route handles shared by all operator clients.

use std::sync::Arc;

use iteron_protocol::client_inventory::{
    ClientInventoryKindV1, ClientInventoryQueryV1, ClientModelSelectionV1,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::plugin_runtime::RuntimePlugins;
use crate::providers::{ModelSelection, ProviderDirectory};

const MAX_PROVIDERS: usize = 70;
const MAX_MODELS: usize = 50_001;
const MAX_ID_BYTES: usize = 512;

pub(crate) struct ClientInventoryOwner {
    directory: ProviderDirectory,
    digest: String,
    providers: Vec<Value>,
    models: Vec<Value>,
    plugins: Vec<Value>,
}

impl ClientInventoryOwner {
    /// Only the trusted bootstrap supplies these real captured owners. No config or package file
    /// is reopened, no network discovery runs, and no provider is built until a route is selected.
    pub(crate) fn capture(
        directory: &ProviderDirectory,
        plugins: &RuntimePlugins,
        selected: &ModelSelection,
    ) -> Result<Arc<Self>, String> {
        if directory.entries().len() > MAX_PROVIDERS {
            return Err("provider inventory exceeds its hard bound".into());
        }
        let directory = directory.frozen_client_snapshot();
        let mut providers = Vec::new();
        let mut models = Vec::new();
        for entry in directory.entries() {
            check_identity(entry.id())?;
            let model_count = entry
                .catalog
                .as_ref()
                .map_or(0, |catalog| catalog.models.len());
            providers.push(json!({"provider_id":entry.id(),"display_name":safe(entry.display_name()),"enabled":entry.enabled,
                "catalog_available":entry.catalog.is_some(),"catalog_stale":entry.catalog_stale,
                "catalog_enabled":entry.catalog_enabled,"catalog_provenance":safe(&entry.catalog_provenance_label()),"model_count":model_count,
                "discovery_pending":entry.catalog.is_none() && entry.catalog_error.is_none() && entry.catalog_enabled}));
            if let Some(catalog) = &entry.catalog {
                for model in &catalog.models {
                    if models.len() >= MAX_MODELS {
                        return Err("model inventory exceeds its hard bound".into());
                    }
                    let selection = ModelSelection {
                        provider_id: entry.id().into(),
                        model_id: model.raw.id.clone(),
                    };
                    check_identity(&selection.model_id)?;
                    models.push(model_record(&directory, &selection, false));
                }
            }
        }
        if !models.iter().any(|model| {
            model["provider_id"] == selected.provider_id && model["model_id"] == selected.model_id
        }) && directory.entry(&selected.provider_id).is_some()
        {
            check_identity(&selected.provider_id)?;
            check_identity(&selected.model_id)?;
            if models.len() >= MAX_MODELS {
                return Err("selected model exceeds inventory bound".into());
            }
            models.push(model_record(&directory, selected, true));
        }
        let plugins = plugins
            .inventory_snapshot()
            .into_iter()
            .map(|plugin| {
                serde_json::to_value(plugin)
                    .map_err(|_| "verified plugin inventory serialization failed".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let bytes = serde_json::to_vec(&(&providers, &models, &plugins))
            .map_err(|_| "bootstrap inventory identity unavailable")?;
        Ok(Arc::new(Self {
            directory,
            digest: hex::encode(Sha256::digest(bytes)),
            providers,
            models,
            plugins,
        }))
    }

    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }

    pub(crate) fn read(&self, query: &ClientInventoryQueryV1) -> Option<Value> {
        let records = match query.kind {
            ClientInventoryKindV1::Providers => self.providers.iter().collect::<Vec<_>>(),
            ClientInventoryKindV1::Models => self
                .models
                .iter()
                .filter(|model| {
                    query
                        .provider_id
                        .as_ref()
                        .is_none_or(|provider| model["provider_id"] == *provider)
                })
                .collect::<Vec<_>>(),
            ClientInventoryKindV1::Plugins => self.plugins.iter().collect::<Vec<_>>(),
            _ => return None,
        };
        Some(page(
            query,
            &records,
            "captured_bootstrap",
            true,
            Some(&self.digest),
        ))
    }

    pub(crate) fn resolve(
        &self,
        request: &ClientModelSelectionV1,
    ) -> Result<crate::app_server::ModelSelection, String> {
        request.validate()?;
        if request.inventory_digest_sha256 != self.digest {
            return Err("bootstrap inventory identity changed; read the current inventory".into());
        }
        let record = self
            .models
            .iter()
            .find(|record| {
                record["provider_id"] == request.provider_id
                    && record["model_id"] == request.model_id
            })
            .ok_or("route is absent from the captured inventory")?;
        if record["selectable"] != true {
            return Err("captured route is unavailable or stale; refresh through the trusted provider owner".into());
        }
        if record["catalog_digest_sha256"] != request.catalog_digest_sha256
            || record["capability_digest_sha256"] != request.capability_digest_sha256
        {
            return Err(
                "selected catalog/capability identity does not match the captured route".into(),
            );
        }
        let selection = ModelSelection {
            provider_id: request.provider_id.clone(),
            model_id: request.model_id.clone(),
        };
        let provider = self.directory.build(&selection)?;
        let capabilities = self.directory.selection_capabilities(&selection);
        Ok(crate::app_server::ModelSelection {
            provider,
            provider_id: request.provider_id.clone(),
            model_id: request.model_id.clone(),
            catalog_digest: request.catalog_digest_sha256.clone(),
            capability_digest: request.capability_digest_sha256.clone(),
            context_window_tokens: capabilities.context_window_tokens,
            max_output_tokens: capabilities.max_output_tokens,
        })
    }
}

fn model_record(
    directory: &ProviderDirectory,
    selection: &ModelSelection,
    explicit: bool,
) -> Value {
    let capabilities = directory.selection_capabilities(selection);
    let (catalog, capability) = directory.selection_digests(selection);
    let stale = directory
        .entry(&selection.provider_id)
        .is_none_or(|entry| entry.catalog_stale);
    json!({"provider_id":selection.provider_id,"model_id":selection.model_id,
        "catalog_digest_sha256":catalog,"capability_digest_sha256":capability,
        "selectable":!stale && directory.validate_selection(selection, explicit).is_ok(),"explicit_selected_route":explicit,
        "context_window_tokens":capabilities.context_window_tokens,"max_output_tokens":capabilities.max_output_tokens,
        "tool_calling":capabilities.tool_calling,"semantic_effort":capabilities.semantic_effort,"image_input":capabilities.image_input,
        "capability_version":capabilities.version.as_deref().map(safe),"capability_source":capabilities.source.as_deref().map(safe)})
}

fn check_identity(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || value.chars().any(char::is_control)
        || safe(value) != value
    {
        Err("bootstrap route has an unsafe or oversized identity".into())
    } else {
        Ok(())
    }
}

pub(crate) fn safe(value: &str) -> String {
    iteron_record::redact::scrub(value)
}

pub(crate) fn page<T: serde::Serialize>(
    query: &ClientInventoryQueryV1,
    records: &[T],
    provenance: &str,
    available: bool,
    digest: Option<&str>,
) -> Value {
    let start = (query.offset as usize).min(records.len());
    let end = start
        .saturating_add(query.limit as usize)
        .min(records.len());
    json!({"type":"client_inventory_v1","contract_version":iteron_protocol::client_inventory::CLIENT_INVENTORY_VERSION,
        "kind":query.kind,"provenance":provenance,"available":available,"inventory_digest_sha256":digest,
        "total":records.len(),"offset":query.offset,"next_offset":(end < records.len()).then_some(end),"records":&records[start..end]})
}
