use super::model::{
    ContentTombstone, ContentTombstoneReason, MAX_CONTENT_LINEAGE_EDGES, MAX_CONTENT_REVOCATIONS,
    STORE_VERSION,
};
use super::{
    ContentStoreError, Layout, OwnerLock, StoreLock, ensure_layout, lineage, lock_owner,
    lock_store, read_edges, read_state, write_state, write_tombstone,
};
use iteron_protocol::{
    ErasureAuthorityId, ErasureContentDigest, ErasureOperationId, RunId, TenantId,
};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions, TryLockError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContentRevocationSummary {
    pub(crate) references: u32,
    pub(crate) affected_sessions: u32,
    pub(crate) generation: u64,
    pub(crate) coverage: iteron_protocol::ErasurePropagationCoverage,
}

/// Holds the tenant content lock and every referenced rollout lock across all destructive phases.
pub(crate) struct ContentRevocationGuard {
    layout: Layout,
    root_digest: ErasureContentDigest,
    digests: Vec<ErasureContentDigest>,
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
        let digests = collect_closure(&layout, &digest)?;
        let mut edges = Vec::new();
        for affected in &digests {
            let next = read_edges(&layout, affected)?;
            if edges.len().saturating_add(next.len())
                > iteron_tunables::param_integer(
                    "record.content_store.model.max_content_lineage_edges",
                    MAX_CONTENT_LINEAGE_EDGES,
                )
            {
                return Err(ContentStoreError::ReferenceBound {
                    max: iteron_tunables::param_integer(
                        "record.content_store.model.max_content_lineage_edges",
                        MAX_CONTENT_LINEAGE_EDGES,
                    ),
                });
            }
            edges.extend(next);
        }
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
            root_digest: digest,
            digests,
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
        let generation = if let Some(existing) = state.tombstone(&self.root_digest) {
            existing.generation
        } else {
            state
                .generation
                .checked_add(1)
                .ok_or(ContentStoreError::Corrupt)?
        };
        let missing = self
            .digests
            .iter()
            .filter(|digest| state.tombstone(digest).is_none())
            .count();
        if state.tombstones.len().saturating_add(missing)
            > iteron_tunables::param_integer(
                "record.content_store.model.max_content_revocations",
                MAX_CONTENT_REVOCATIONS,
            )
        {
            return Err(ContentStoreError::RevocationBound {
                max: iteron_tunables::param_integer(
                    "record.content_store.model.max_content_revocations",
                    MAX_CONTENT_REVOCATIONS,
                ),
            });
        }
        state.generation = state.generation.max(generation);
        for digest in &self.digests {
            if state.tombstone(digest).is_some() {
                continue;
            }
            let tombstone = ContentTombstone {
                version: STORE_VERSION,
                digest: digest.clone(),
                operation_id: operation_id.clone(),
                authority_id: authority_id.clone(),
                revoked_at_unix_ms,
                reason: ContentTombstoneReason::AuthorityRevoked,
                generation,
            };
            let position = state
                .tombstones
                .binary_search_by(|entry| entry.digest.cmp(digest))
                .unwrap_or_else(|position| position);
            state.tombstones.insert(position, tombstone);
        }
        // The generation ledger is the fail-closed read gate. Persist it before deleting a key or
        // touching a rebuildable projection; a crash can leave extra ciphertext, never readable
        // stale content.
        write_state(&self.layout, &state)?;
        for digest in &self.digests {
            let tombstone = state.tombstone(digest).ok_or(ContentStoreError::Corrupt)?;
            write_tombstone(&self.layout, tombstone)?;
        }
        Ok(generation)
    }

    pub(crate) fn shred(&self) -> Result<(), ContentStoreError> {
        let state = read_state(&self.layout)?;
        for digest in &self.digests {
            if state.tombstone(digest).is_none() {
                return Err(ContentStoreError::Corrupt);
            }
            remove_durable(&self.layout.object_path(&self.layout.keys, digest))?;
        }
        super::crate_sync_dir(&self.layout.keys)?;
        for digest in &self.digests {
            remove_durable(&self.layout.object_path(&self.layout.blobs, digest))?;
        }
        super::crate_sync_dir(&self.layout.blobs)?;
        Ok(())
    }

    pub(crate) fn propagate(&self) -> Result<(), ContentStoreError> {
        for run in &self.affected_runs {
            let sidecar = crate::validated_run_path(&self.layout.runs_dir, run, ".meta.json")
                .map_err(|_| ContentStoreError::Corrupt)?;
            remove_durable(&sidecar)?;
        }
        // Do not rebuild while holding the tenant content lock: the private session-cache writer
        // must acquire that same lock to publish its CAS handle and would fail Busy here. Removing
        // the global manifest is the fail-closed propagation step. The next `session::list` lazily
        // rebuilds projections after this guard drops, and every replay/hydration still crosses
        // the durable tombstone gate.
        remove_durable(&self.layout.runs_dir.join("sessions.index"))?;
        crate::cache_io::sync_dir(&self.layout.runs_dir)?;
        Ok(())
    }

    pub(crate) fn verify(&self) -> Result<ContentRevocationSummary, ContentStoreError> {
        let state = read_state(&self.layout)?;
        let Some(tombstone) = state.tombstone(&self.root_digest) else {
            return Err(ContentStoreError::Corrupt);
        };
        for digest in &self.digests {
            if self.layout.object_path(&self.layout.keys, digest).exists()
                || self.layout.object_path(&self.layout.blobs, digest).exists()
            {
                return Err(ContentStoreError::Unresolved {
                    digest: digest.clone(),
                    reason: "material_not_shredded",
                });
            }
        }
        let coverage =
            super::coverage::verify_registered_adapters(&self.layout, &state, &self.digests)?;
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
            coverage,
        })
    }
}

fn collect_closure(
    layout: &Layout,
    root: &ErasureContentDigest,
) -> Result<Vec<ErasureContentDigest>, ContentStoreError> {
    let mut pending = std::collections::VecDeque::from([root.clone()]);
    let mut visited = std::collections::BTreeSet::new();
    let mut edge_count = 0usize;
    while let Some(digest) = pending.pop_front() {
        if !visited.insert(digest.clone()) {
            continue;
        }
        if visited.len()
            > iteron_tunables::param_integer(
                "record.content_store.model.max_content_revocations",
                MAX_CONTENT_REVOCATIONS,
            )
        {
            return Err(ContentStoreError::RevocationBound {
                max: iteron_tunables::param_integer(
                    "record.content_store.model.max_content_revocations",
                    MAX_CONTENT_REVOCATIONS,
                ),
            });
        }
        for edge in lineage::descendants(layout, &digest)? {
            edge_count = edge_count.saturating_add(1);
            if edge_count
                > iteron_tunables::param_integer(
                    "record.content_store.model.max_content_lineage_edges",
                    MAX_CONTENT_LINEAGE_EDGES,
                )
            {
                return Err(ContentStoreError::ReferenceBound {
                    max: iteron_tunables::param_integer(
                        "record.content_store.model.max_content_lineage_edges",
                        MAX_CONTENT_LINEAGE_EDGES,
                    ),
                });
            }
            if !visited.contains(&edge.derivative_digest) {
                pending.push_back(edge.derivative_digest);
            }
        }
    }
    Ok(visited.into_iter().collect())
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
