//! Pure route/catalog identity over the actual selected entry and capability evidence.
use super::{
    CatalogProvenance, ModelCapabilities, ModelSelection, ProviderEntry, adapter_key,
    catalog_strategy_key, compatibility_key, digest_string, error_profile_key,
    hash_catalog_provenance, hash_part, hash_selectability,
};
use sha2::{Digest as _, Sha256};
/// Catalog identity is independent of the selected model. Bulk inventory captures hash/sort the
/// actual provider snapshot once, while every model retains the same capability identity bytes.
pub(super) struct CatalogIdentity {
    digest: String,
    provenance: CatalogProvenance,
}
impl CatalogIdentity {
    pub(super) fn capture(entry: &ProviderEntry) -> Self {
        let mut catalog = Sha256::new();
        let execution_provenance = if entry.catalog_fallback_explicit {
            // A failed discovery can leave cached names on screen, but an explicitly typed route
            // is operator evidence. Never hash stale display inventory as execution evidence.
            CatalogProvenance::OperatorExplicit
        } else {
            entry.catalog_provenance.clone()
        };
        hash_part(&mut catalog, b"iteron-provider-catalog-v2");
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
                hash_part(
                    &mut catalog,
                    match model.raw.supports_image_input {
                        Some(true) => b"images:true",
                        Some(false) => b"images:false",
                        None => b"images:unknown",
                    },
                );
            }
        } else {
            hash_part(&mut catalog, b"no-snapshot");
        }

        Self {
            digest: digest_string(catalog),
            provenance: execution_provenance,
        }
    }
    pub(super) fn for_model(
        &self,
        entry: &ProviderEntry,
        selection: &ModelSelection,
        documented: ModelCapabilities,
        descriptor: Option<&iteron_provider::ModelDescriptor>,
    ) -> (String, String) {
        (
            self.digest.clone(),
            capability_digest(entry, selection, documented, &self.provenance, descriptor),
        )
    }
}
pub(super) fn project(
    entry: &ProviderEntry,
    selection: &ModelSelection,
    documented: ModelCapabilities,
) -> (String, String) {
    let descriptor = entry.catalog.as_ref().and_then(|snapshot| {
        snapshot
            .models
            .iter()
            .find(|model| model.raw.id == selection.model_id)
    });
    CatalogIdentity::capture(entry).for_model(entry, selection, documented, descriptor)
}
fn capability_digest(
    entry: &ProviderEntry,
    selection: &ModelSelection,
    documented: ModelCapabilities,
    execution_provenance: &CatalogProvenance,
    descriptor: Option<&iteron_provider::ModelDescriptor>,
) -> String {
    let mut capability = Sha256::new();
    hash_part(&mut capability, b"iteron-provider-capability-v2");
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
    hash_catalog_provenance(&mut capability, execution_provenance);
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
        match documented.image_input {
            Some(true) => b"images:true",
            Some(false) => b"images:false",
            None => b"images:unknown",
        },
    );
    for score in documented
        .routing_objectives
        .map(|scores| {
            [
                scores.quality_millionths,
                scores.cost_efficiency_millionths,
                scores.latency_millionths,
            ]
        })
        .unwrap_or([u32::MAX; 3])
    {
        hash_part(&mut capability, score.to_string().as_bytes());
    }
    hash_part(
        &mut capability,
        documented
            .image_input_version
            .as_deref()
            .unwrap_or("unknown-image-version")
            .as_bytes(),
    );
    hash_part(
        &mut capability,
        documented
            .image_input_source
            .as_deref()
            .unwrap_or("unknown-image-source")
            .as_bytes(),
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
    if let Some(model) = descriptor.filter(|_| !entry.catalog_fallback_explicit) {
        hash_part(
            &mut capability,
            compatibility_key(model.compatibility).as_bytes(),
        );
        hash_selectability(&mut capability, &model.selectability);
    } else {
        hash_part(&mut capability, b"no-model-descriptor");
    }
    digest_string(capability)
}
