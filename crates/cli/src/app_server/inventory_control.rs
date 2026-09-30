//! Immutable public inventory projection captured from the installed runtime owners.

use super::ControlReply;
use crate::runtime::Agent;
use crate::runtime::client_inventory::RuntimeClientInventory;
use iteron_protocol::client_inventory::ClientInventoryQueryV1;
use std::sync::Mutex;

pub(super) struct InventorySurface(Mutex<RuntimeClientInventory>);

impl InventorySurface {
    pub(super) fn capture(agent: &Agent) -> Self {
        Self(Mutex::new(agent.capture_client_inventory()))
    }
    pub(super) fn refresh(&self, agent: &Agent) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = agent.capture_client_inventory();
    }
    pub(super) fn read(&self, query: ClientInventoryQueryV1) -> ControlReply {
        match self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .read(query)
        {
            Ok(value) => ControlReply::Inventory(value),
            Err(reason) => ControlReply::Refused(reason.into()),
        }
    }
}
