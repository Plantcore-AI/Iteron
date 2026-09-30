//! Workflow-owned schema and CAS over the Windows private byte publication port.

use std::path::Path;

use iteron_support::durable_windows_state::{WindowsSnapshotStore, WindowsStateError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{WorkflowPlanJournal, WorkflowSchedulerSnapshotV1, WorkflowStoreError};
use crate::live_scheduler::MAX_PLAN_STORE_BYTES;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    digest: String,
    snapshot: WorkflowSchedulerSnapshotV1,
}

pub struct WorkflowFileJournal {
    store: WindowsSnapshotStore,
}

impl WorkflowFileJournal {
    /// The composition root must provision a private application-state directory. Remote shares,
    /// reparse points, public DACLs and unsupported filesystems are refused before domain load.
    pub fn open(directory: &Path) -> Result<Self, WorkflowStoreError> {
        Ok(Self {
            store: WindowsSnapshotStore::open(directory, "workflow").map_err(store_error)?,
        })
    }
}

impl WorkflowPlanJournal for WorkflowFileJournal {
    fn load(&mut self) -> Result<Option<WorkflowSchedulerSnapshotV1>, WorkflowStoreError> {
        let Some(bytes) = self.store.load().map_err(store_error)? else {
            return Ok(None);
        };
        let envelope: Envelope =
            serde_json::from_slice(&bytes).map_err(|_| WorkflowStoreError::Unavailable)?;
        let payload =
            serde_json::to_vec(&envelope.snapshot).map_err(|_| WorkflowStoreError::Unavailable)?;
        if envelope.version != 1 || envelope.digest != hex::encode(Sha256::digest(payload)) {
            return Err(WorkflowStoreError::Unavailable);
        }
        Ok(Some(envelope.snapshot))
    }

    fn commit(
        &mut self,
        expected: Option<u64>,
        next: &WorkflowSchedulerSnapshotV1,
    ) -> Result<(), WorkflowStoreError> {
        let current = self.load()?.map(|snapshot| snapshot.sequence());
        if current != expected {
            return Err(WorkflowStoreError::Conflict);
        }
        let payload = serde_json::to_vec(next).map_err(|_| WorkflowStoreError::Unavailable)?;
        let envelope = Envelope {
            version: 1,
            digest: hex::encode(Sha256::digest(payload)),
            snapshot: next.clone(),
        };
        let bytes = serde_json::to_vec(&envelope).map_err(|_| WorkflowStoreError::Unavailable)?;
        if bytes.len() as u64 > MAX_PLAN_STORE_BYTES {
            return Err(WorkflowStoreError::Unavailable);
        }
        self.store
            .publish(&bytes, expected.is_none())
            .map_err(store_error)
    }
}

fn store_error(error: WindowsStateError) -> WorkflowStoreError {
    match error {
        WindowsStateError::Unavailable => WorkflowStoreError::Unavailable,
        WindowsStateError::Conflict => WorkflowStoreError::Conflict,
        WindowsStateError::OutcomeUnknown => WorkflowStoreError::OutcomeUnknown,
    }
}
