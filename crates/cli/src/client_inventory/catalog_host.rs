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
            let view = self.catalog_view();
            return match view.discovery_error() {
                Some(reason) => Err(reason.to_owned()),
                None => Ok(view),
            };
        }
        let mut directory = self
            .live_directory
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if !directory.begin_settle_after_paint() {
            let reason =
                "provider discovery was abandoned; restart or inspect the provider configuration";
            self.retain_discovery_failure(reason)?;
            return Err(reason.into());
        }
        if !directory.discovery_pending() {
            return self.refresh();
        }
        let owner = self.clone();
        tokio::spawn(async move {
            let settled = directory.settle_complete().await;
            let failure = {
                let mut live = owner
                    .live_directory
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if settled {
                    match owner.publish_locked(&directory) {
                        Ok(_) => {
                            *live = directory;
                            None
                        }
                        Err(reason) => Some(reason),
                    }
                } else {
                    Some(
                        "provider discovery did not complete; the admitted inventory was retained"
                            .into(),
                    )
                }
            };
            // No invalid catalog enters either executable owner. Close the discovery projection
            // over the retained admitted directory, rather than leaving a false pending spinner.
            if let Some(reason) = failure
                && let Err(error) = owner.retain_discovery_failure(&reason)
            {
                eprintln!(
                    "warning: provider inventory terminal could not be published: {}",
                    crate::client_inventory::safe(&error)
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
    fn retain_discovery_failure(&self, reason: &str) -> Result<ProviderCatalogView, String> {
        let mut live = self
            .live_directory
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let retained = self.session_directory();
        let view = self.publish_with_error(&retained, Some(reason))?;
        *live = retained;
        Ok(view)
    }
    fn publish_locked(&self, directory: &ProviderDirectory) -> Result<ProviderCatalogView, String> {
        self.publish_with_error(directory, self.catalog_view().discovery_error())
    }
    fn publish_with_error(
        &self,
        directory: &ProviderDirectory,
        error: Option<&str>,
    ) -> Result<ProviderCatalogView, String> {
        let draft = ProviderCatalogView::capture(
            directory,
            &self.selected,
            String::new(),
            directory.discovery_pending(),
        )?
        .with_discovery_error(error);
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
