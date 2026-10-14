//! Native selected-route preparation from a trusted captured provider directory. Public clients
//! supply only checked route identities; this owner constructs the actual host transport handle.
use crate::providers::{ModelSelection, ProviderDirectory};
use iteron_provider::Provider;
use std::sync::Arc;

/// Host-only prepared route. This is neither wire-deserializable nor a provider configuration.
pub(crate) struct HostModelSelection {
    pub(crate) provider: Arc<dyn Provider>,
    pub(crate) provider_id: String,
    pub(crate) model_id: String,
    pub(crate) catalog_digest: String,
    pub(crate) capability_digest: String,
    pub(crate) context_window_tokens: Option<u64>,
    pub(crate) max_output_tokens: Option<u32>,
}
impl HostModelSelection {
    pub(crate) fn capture(
        directory: &ProviderDirectory,
        selection: &ModelSelection,
    ) -> Result<Self, String> {
        let provider = directory.build(selection)?;
        let capabilities = directory.selection_capabilities(selection);
        let (catalog_digest, capability_digest) = directory.selection_digests(selection);
        Ok(Self {
            provider,
            provider_id: selection.provider_id.clone(),
            model_id: selection.model_id.clone(),
            catalog_digest,
            capability_digest,
            context_window_tokens: capabilities.context_window_tokens,
            max_output_tokens: capabilities.max_output_tokens,
        })
    }
}
