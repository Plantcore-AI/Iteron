use super::model::{
    ContentTombstone, ContentTombstoneReason, MAX_CONTENT_REVOCATIONS, STORE_VERSION,
};
use super::{
    ContentStoreError, Layout, OwnerLock, StoreLock, ensure_layout, lock_owner, lock_store,
    read_edges, read_state, write_state, write_tombstone,
};
use core_protocol::{
    ErasureAuthorityId, ErasureContentDigest, ErasureOperationId, RunId, TenantId,
};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions, TryLockError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContentRevocationSummary {
    pub(crate) references: u32,
    pub(crate) affected_sessions: u32,
    pub(crate) generation: u64,
    pub(crate) coverage: core_protocol::ErasurePropagationCoverage,
}

/// Holds the tenant content lock and every referenced rollout lock across all destructive phases.
pub(crate) struct ContentRevocationGuard {
    layout: Layout,
    digest: ErasureContentDigest,
    references: usize,
    affected_runs: Vec<RunId>,
    affected_sessions: usize,
    _store_lock: StoreLock,
    _owner_locks: Vec<OwnerLock>,
    _run_locks: Vec<RunLock>,
}

impl ContentRevocationGuard {
    pub(crate) fn begin(
        runs_dir: &std::path::Path,
        tenant: &TenantId,
        digest: ErasureContentDigest,
    ) -> Result<Option<Self>, ContentStoreError> {
        let layout = Layout::new(runs_dir, tenant);
        ensure_layout(&layout)?;
        let store_lock = lock_store(&layout)?;
        let state = read_state(&layout)?;
        let edges = read_edges(&layout, &digest)?;
        let key_exists = layout.object_path(&layout.keys, &digest).exists();
        let blob_exists = layout.object_path(&layout.blobs, &digest).exists();
        if state.tombstone(&digest).is_none() && edges.is_empty() && !key_exists && !blob_exists {
            return Ok(None);
        }
        let affected_runs = edges
            .iter()
            .map(|edge| (edge.run_id.0.clone(), edge.run_id.clone()))
            .collect::<BTreeMap<_, _>>()
            .into_values()
            .collect::<Vec<_>>();
        let mut owner_locks = Vec::with_capacity(affected_runs.len());
        let mut run_locks = Vec::with_capacity(affected_runs.len());
        let mut affected_sessions = 0usize;
        for run in &affected_runs {
            owner_locks.push(lock_owner(&layout, run)?);
            let path = crate::validated_run_path(runs_dir, run, ".jsonl")
                .map_err(|_| ContentStoreError::Corrupt)?;
            let file = match OpenOptions::new().read(true).append(true).open(path) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            affected_sessions = affected_sessions.saturating_add(1);
            match file.try_lock() {
                Ok(()) => run_locks.push(RunLock(file)),
                Err(TryLockError::WouldBlock) => {
                    return Err(ContentStoreError::ActiveWriter {
                        run_id: run.clone(),
                    });
                }
                Err(TryLockError::Error(error)) => return Err(error.into()),
            }
        }
        Ok(Some(Self {
            layout,
            digest,
            references: edges.len(),
            affected_runs,
            affected_sessions,
            _store_lock: store_lock,
            _owner_locks: owner_locks,
            _run_locks: run_locks,
        }))
    }

    pub(crate) fn tombstone(
        &self,
        operation_id: &ErasureOperationId,
        authority_id: &ErasureAuthorityId,
        revoked_at_unix_ms: u64,
    ) -> Result<u64, ContentStoreError> {
        let mut state = read_state(&self.layout)?;
        if let Some(existing) = state.tombstone(&self.digest) {
            write_tombstone(&self.layout, existing)?;
            return Ok(existing.generation);
        }
        if state.tombstones.len() >= MAX_CONTENT_REVOCATIONS {
            return Err(ContentStoreError::RevocationBound {
                max: MAX_CONTENT_REVOCATIONS,
            });
        }
        let generation = state
            .generation
            .checked_add(1)
            .ok_or(ContentStoreError::Corrupt)?;
        let tombstone = ContentTombstone {
            version: STORE_VERSION,
            digest: self.digest.clone(),
            operation_id: operation_id.clone(),
            authority_id: authority_id.clone(),
            revoked_at_unix_ms,
            reason: ContentTombstoneReason::AuthorityRevoked,
            generation,
        };
        state.generation = generation;
        let position = state
            .tombstones
            .binary_search_by(|entry| entry.digest.cmp(&self.digest))
            .unwrap_or_else(|position| position);
        state.tombstones.insert(position, tombstone.clone());
        // The generation ledger is the fail-closed read gate. Persist it before deleting a key or
        // touching a rebuildable projection; a crash can leave extra ciphertext, never readable
        // stale content.
        write_state(&self.layout, &state)?;
        write_tombstone(&self.layout, &tombstone)?;
        Ok(generation)
    }

    pub(crate) fn shred(&self) -> Result<(), ContentStoreError> {
        let state = read_state(&self.layout)?;
        if state.tombstone(&self.digest).is_none() {
            return Err(ContentStoreError::Corrupt);
        }
        remove_durable(&self.layout.object_path(&self.layout.keys, &self.digest))?;
        super::crate_sync_dir(&self.layout.keys)?;
        remove_durable(&self.layout.object_path(&self.layout.blobs, &self.digest))?;
        super::crate_sync_dir(&self.layout.blobs)?;
        Ok(())
    }

    pub(crate) fn propagate(&self) -> Result<(), ContentStoreError> {
        for run in &self.affected_runs {
            let sidecar = crate::validated_run_path(&self.layout.runs_dir, run, ".meta.json")
                .map_err(|_| ContentStoreError::Corrupt)?;
            if let Err(error) = std::fs::remove_file(sidecar)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                return Err(error.into());
            }
        }
        // Reindex skips every journal whose content handle now resolves to a tombstone. The
        // revocation generation also invalidates any cache raced before this rewrite.
        crate::session::reindex(&self.layout.runs_dir)
            .map_err(|error| ContentStoreError::Io(std::io::Error::other(error.to_string())))?;
        Ok(())
    }

    pub(crate) fn verify(&self) -> Result<ContentRevocationSummary, ContentStoreError> {
        let state = read_state(&self.layout)?;
        let Some(tombstone) = state.tombstone(&self.digest) else {
            return Err(ContentStoreError::Corrupt);
        };
        if self
            .layout
            .object_path(&self.layout.keys, &self.digest)
            .exists()
            || self
                .layout
                .object_path(&self.layout.blobs, &self.digest)
                .exists()
        {
            return Err(ContentStoreError::Unresolved {
                digest: self.digest.clone(),
                reason: "material_not_shredded",
            });
        }
        // Re-read the complete bounded reference set after shredding and prove the one serving
        // gate rejects every extant handle at the exact durable generation. This catches a future
        // surface that writes an edge but bypasses tombstone state before a Verified receipt can
        // be produced.
        for edge in read_edges(&self.layout, &self.digest)? {
            match super::load_bytes(&self.layout, &edge.digest) {
                Err(ContentStoreError::Revoked { digest, generation })
                    if digest == self.digest && generation == tombstone.generation => {}
                _ => {
                    return Err(ContentStoreError::Unresolved {
                        digest: self.digest.clone(),
                        reason: "derivative_revocation_guard_unverified",
                    });
                }
            }
        }
        Ok(ContentRevocationSummary {
            references: u32::try_from(self.references).map_err(|_| {
                ContentStoreError::ReferenceBound {
                    max: super::model::MAX_CONTENT_REFERENCES,
                }
            })?,
            affected_sessions: u32::try_from(self.affected_sessions).map_err(|_| {
                ContentStoreError::ReferenceBound {
                    max: super::model::MAX_CONTENT_REFERENCES,
                }
            })?,
            generation: tombstone.generation,
            coverage: super::guarded_derivative_coverage(),
        })
    }
}

fn remove_durable(path: &std::path::Path) -> Result<(), ContentStoreError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

struct RunLock(File);

impl Drop for RunLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}
