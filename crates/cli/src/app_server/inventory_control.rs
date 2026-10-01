//! Immutable public inventory projection captured from the installed runtime owners.

use super::ControlReply;
use crate::runtime::Agent;
use crate::runtime::client_inventory::RuntimeClientInventory;
use iteron_protocol::client_inventory::ClientInventoryQueryV1;
use std::sync::Mutex;

pub(super) struct InventorySurface {
    inventory: Mutex<RuntimeClientInventory>,
    catalog: Option<std::sync::Arc<crate::client_inventory::ClientInventoryOwner>>,
}

impl InventorySurface {
    pub(super) fn capture(agent: &Agent) -> Self {
        Self {
            inventory: Mutex::new(agent.capture_client_inventory()),
            catalog: agent.client_inventory_owner(),
        }
    }
    pub(super) fn refresh(&self, agent: &Agent) {
        if let Some(owner) = &self.catalog {
            if let Err(reason) = owner.refresh() {
                eprintln!(
                    "warning: provider inventory refresh refused: {}",
                    crate::client_inventory::safe(&reason)
                );
            }
        }
        *self
            .inventory
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = agent.capture_client_inventory();
    }
    pub(super) fn read(&self, query: ClientInventoryQueryV1) -> ControlReply {
        match self
            .inventory
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .read(query)
        {
            Ok(value) => ControlReply::Inventory(value),
            Err(reason) => ControlReply::Refused(reason.into()),
        }
    }
    pub(super) fn catalog(&self, command: super::ProviderCatalogControl) -> ControlReply {
        let Some(owner) = &self.catalog else {
            return ControlReply::Refused("this session has no captured provider catalog".into());
        };
        let result = match command {
            super::ProviderCatalogControl::FirstFrame => owner.first_frame(),
            super::ProviderCatalogControl::Refresh => owner.refresh(),
            super::ProviderCatalogControl::Retry(request) => owner.retry(&request),
        };
        match result {
            Ok(view) => ControlReply::ProviderCatalog(Box::new(view)),
            Err(reason) => ControlReply::Refused(reason),
        }
    }
}
