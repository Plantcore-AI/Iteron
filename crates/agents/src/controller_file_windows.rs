//! Agent-owned revision/schema adapter; platform support owns only private byte publication.

use std::path::Path;

use iteron_support::durable_windows_state::{WindowsSnapshotStore, WindowsStateError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AgentControllerJournal, AgentControllerSnapshot, ControllerStoreError};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    sha256: String,
    snapshot: AgentControllerSnapshot,
}

pub(crate) struct WindowsAgentFileJournal {
    store: WindowsSnapshotStore,
}

impl WindowsAgentFileJournal {
    pub(crate) fn open(directory: &Path) -> Result<Self, ControllerStoreError> {
        Ok(Self {
            store: WindowsSnapshotStore::open(directory, "agents").map_err(store_error)?,
        })
    }
}

impl AgentControllerJournal for WindowsAgentFileJournal {
    fn load(&mut self) -> Result<Option<AgentControllerSnapshot>, ControllerStoreError> {
        let Some(bytes) = self.store.load().map_err(store_error)? else {
            return Ok(None);
        };
        let envelope: Envelope =
            serde_json::from_slice(&bytes).map_err(|_| ControllerStoreError::Unavailable)?;
        let payload = serde_json::to_vec(&envelope.snapshot)
            .map_err(|_| ControllerStoreError::Unavailable)?;
        if envelope.version != 1 || envelope.sha256 != format!("{:x}", Sha256::digest(payload)) {
            return Err(ControllerStoreError::Unavailable);
        }
        Ok(Some(envelope.snapshot))
    }

    fn commit(
        &mut self,
        expected: Option<u64>,
        next: &AgentControllerSnapshot,
    ) -> Result<(), ControllerStoreError> {
        let current = self.load()?.map(|snapshot| snapshot.revision());
        let next_revision = match expected {
            Some(revision) => revision.checked_add(1),
            None => Some(0),
        };
        if current != expected || next_revision != Some(next.revision()) {
            return Err(ControllerStoreError::Conflict);
        }
        let payload = serde_json::to_vec(next).map_err(|_| ControllerStoreError::Unavailable)?;
        let envelope = Envelope {
            version: 1,
            sha256: format!("{:x}", Sha256::digest(payload)),
            snapshot: next.clone(),
        };
        let bytes = serde_json::to_vec(&envelope).map_err(|_| ControllerStoreError::Unavailable)?;
        self.store
            .publish(&bytes, expected.is_none())
            .map_err(store_error)
    }
}

fn store_error(error: WindowsStateError) -> ControllerStoreError {
    match error {
        WindowsStateError::Unavailable => ControllerStoreError::Unavailable,
        WindowsStateError::Conflict => ControllerStoreError::Conflict,
        WindowsStateError::OutcomeUnknown => ControllerStoreError::OutcomeUnknown,
    }
}
