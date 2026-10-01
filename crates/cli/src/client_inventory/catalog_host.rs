//! Host-owned discovery, immutable inventory replacement and explicit model-health retry.
use super::CapturedClientInventory;
use crate::{
    plugin_runtime::RuntimePlugins,
    providers::{
        ModelSelection, ProviderCatalogSubscription, ProviderCatalogView, ProviderDirectory,
    },
};
use iteron_protocol::client_inventory::{ClientInventoryQueryV1, ClientModelSelectionV1};
use serde_json::Value;
use std::sync::{
    Arc, Mutex, RwLock,
    atomic::{AtomicBool, Ordering},
};

pub(crate) struct ClientInventoryOwner {
    live_directory: Mutex<ProviderDirectory>,
    captured: RwLock<Arc<CapturedClientInventory>>,
    plugins: Vec<Value>,
    selected: ModelSelection,
    first_frame: AtomicBool,
    projection: tokio::sync::watch::Sender<Arc<ProviderCatalogView>>,
}
impl ClientInventoryOwner {
    pub(crate) fn capture(
        directory: &ProviderDirectory,
        plugins: &RuntimePlugins,
        selected: &ModelSelection,
    ) -> Result<Arc<Self>, String> {
        let plugins = plugins
            .inventory_snapshot()
            .into_iter()
            .map(|plugin| {
                serde_json::to_value(plugin)
                    .map_err(|_| "verified plugin inventory serialization failed".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let draft = ProviderCatalogView::capture(
            directory,
            selected,
            String::new(),
            directory.discovery_pending(),
        )?;
        let captured = CapturedClientInventory::capture(directory, &plugins, selected, &draft)?;
        let projection = draft.with_inventory_digest(captured.digest.clone());
        let (projection, _) = tokio::sync::watch::channel(Arc::new(projection));
        Ok(Arc::new(Self {
            live_directory: Mutex::new(directory.clone()),
            captured: RwLock::new(Arc::new(captured)),
            plugins,
            selected: selected.clone(),
            first_frame: AtomicBool::new(false),
            projection,
        }))
    }
    pub(crate) fn session_directory(&self) -> ProviderDirectory {
        self.captured
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .directory
            .clone()
    }
    pub(crate) fn digest(&self) -> String {
        self.captured
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .digest
            .clone()
    }
    pub(crate) fn read(&self, query: &ClientInventoryQueryV1) -> Option<Value> {
        self.captured
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .read(query)
    }
    pub(crate) fn resolve(
        &self,
        request: &ClientModelSelectionV1,
    ) -> Result<crate::model_route::HostModelSelection, String> {
        // One snapshot supplies the public identity check and the actual provider constructor.
        self.captured
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .resolve(request)
    }
    pub(crate) fn catalog_subscription(&self) -> ProviderCatalogSubscription {
        ProviderCatalogSubscription::new(self.projection.subscribe())
    }
    pub(crate) fn catalog_view(&self) -> ProviderCatalogView {
        self.projection.borrow().as_ref().clone()
    }
    /// Actual first-frame acknowledgement crosses the physical discovery boundary synchronously.
    /// One host worker retains the sole discovery join until it can publish a frozen inventory.
    pub(crate) fn first_frame(self: &Arc<Self>) -> Result<ProviderCatalogView, String> {
        if self
            .first_frame
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(self.catalog_view());
        }
        let mut directory = self
            .live_directory
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if !directory.begin_settle_after_paint() {
            return Err(
                "provider discovery was abandoned; restart or inspect the provider configuration"
                    .into(),
            );
        }
        if !directory.discovery_pending() {
            return self.refresh();
        }
        let owner = self.clone();
        tokio::spawn(async move {
            directory.settle_complete().await;
            let mut live = owner
                .live_directory
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *live = directory;
            // Invalid provider output leaves the previously admitted snapshot in force. A catalog
            // that cannot pass the projection bounds never becomes executable through this port.
            if let Err(reason) = owner.publish_locked(&live) {
                eprintln!(
                    "warning: provider inventory refresh refused: {}",
                    crate::client_inventory::safe(&reason)
                );
            }
        });
        Ok(self.catalog_view())
    }
    pub(crate) fn refresh(&self) -> Result<ProviderCatalogView, String> {
        let live = self
            .live_directory
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.publish_locked(&live)
    }
    pub(crate) fn retry(
        &self,
        request: &ClientModelSelectionV1,
    ) -> Result<ProviderCatalogView, String> {
        request.validate()?;
        let live = self
            .live_directory
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        {
            let captured = self
                .captured
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if request.inventory_digest_sha256 != captured.digest {
                return Err("inventory changed; read the current inventory before retrying".into());
            }
            let record = captured
                .models
                .iter()
                .find(|record| {
                    record["provider_id"] == request.provider_id
                        && record["model_id"] == request.model_id
                })
                .ok_or("retry route is absent from the captured inventory")?;
            if record["catalog_digest_sha256"] != request.catalog_digest_sha256
                || record["capability_digest_sha256"] != request.capability_digest_sha256
            {
                return Err("retry catalog/capability identity changed".into());
            }
        }
        let selection = ModelSelection {
            provider_id: request.provider_id.clone(),
            model_id: request.model_id.clone(),
        };
        if !live.clear_model_unavailable_for_retry(&selection)? {
            return Err("that model has no learned unavailable marker".into());
        }
        self.publish_locked(&live)
    }
    fn publish_locked(&self, directory: &ProviderDirectory) -> Result<ProviderCatalogView, String> {
        let draft = ProviderCatalogView::capture(
            directory,
            &self.selected,
            String::new(),
            directory.discovery_pending(),
        )?;
        let captured =
            CapturedClientInventory::capture(directory, &self.plugins, &self.selected, &draft)?;
        let view = draft.with_inventory_digest(captured.digest.clone());
        let mut current = self
            .captured
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *current = Arc::new(captured);
        // Publish while holding the inventory swap: a projection never advertises a digest whose
        // trusted directory has not yet been installed. Readers still receive immutable values.
        self.projection.send_replace(Arc::new(view.clone()));
        Ok(view)
    }
}
