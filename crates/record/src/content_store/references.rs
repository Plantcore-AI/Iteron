//! Bounded reconciliation for mutable derivative manifests backed by immutable content blobs.

use super::model::{
    MAX_CONTENT_REFERENCES, MAX_REFERENCE_EDGE_BYTES, ReferenceEdge, STORE_VERSION,
};
use super::storage::{
    Layout, crate_sync_dir, ensure_layout, load_bytes, lock_owner_shared, lock_store, read_limited,
    remove_if_present,
};
use super::{ContentReferenceSurface, ContentStoreError, PrivateContentSource, lineage};
use iteron_protocol::{ErasureContentDigest, RunId, Seq, TenantId};
use std::collections::BTreeSet;
use std::path::Path;

pub(super) fn verify_source_owner_locked(
    layout: &Layout,
    source: &PrivateContentSource,
) -> Result<(), ContentStoreError> {
    crate::validate_run_id(&source.owner).map_err(|_| ContentStoreError::Corrupt)?;
    let run_dir = layout.run_reference_dir(&source.owner);
    let entries = std::fs::read_dir(&run_dir).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            ContentStoreError::Unresolved {
                digest: source.digest.clone(),
                reason: "lineage_source_owner_missing",
            }
        } else {
            ContentStoreError::Io(error)
        }
    })?;
    let mut count = 0usize;
    for entry in entries.take(
        iteron_tunables::param_integer(
            "record.content_store.model.max_content_references",
            MAX_CONTENT_REFERENCES,
        ) + 1,
    ) {
        if count
            == iteron_tunables::param_integer(
                "record.content_store.model.max_content_references",
                MAX_CONTENT_REFERENCES,
            )
        {
            return Err(ContentStoreError::ReferenceBound {
                max: iteron_tunables::param_integer(
                    "record.content_store.model.max_content_references",
                    MAX_CONTENT_REFERENCES,
                ),
            });
        }
        count = count.saturating_add(1);
        let edge: ReferenceEdge = serde_json::from_slice(&read_limited(
            &entry?.path(),
            iteron_tunables::param_integer(
                "record.content_store.model.max_reference_edge_bytes",
                MAX_REFERENCE_EDGE_BYTES,
            ),
        )?)?;
        if edge.version != STORE_VERSION || edge.run_id != source.owner {
            return Err(ContentStoreError::Corrupt);
        }
        if edge.digest == source.digest {
            return Ok(());
        }
    }
    Err(ContentStoreError::Unresolved {
        digest: source.digest.clone(),
        reason: "lineage_source_reference_missing",
    })
}

/// Guard every non-journal content lineage edge owned by a run.
///
/// Record-field handles are authenticated while their chain payload is hydrated. This additional
/// pass covers sources copied into memory/context, exports, datasets, and other derivatives whose
/// source digest is intentionally not embedded in the immutable Event schema.
pub fn guard_private_content_for_run(
    runs_dir: &Path,
    tenant: &TenantId,
    run: &RunId,
) -> Result<u32, ContentStoreError> {
    crate::validate_run_id(run).map_err(|_| ContentStoreError::Corrupt)?;
    let layout = Layout::new(runs_dir, tenant);
    // Legacy inline journals predate the private-content store. Replaying one is read-only and
    // must not create a store or require a filesystem locking primitive merely to prove that no
    // derivative lineage exists.
    if !layout.store_exists()? {
        return Ok(0);
    }
    ensure_layout(&layout)?;
    let _owner_lock = lock_owner_shared(&layout, run)?;
    let run_dir = layout.run_reference_dir(run);
    let entries = match std::fs::read_dir(&run_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    let mut digests = BTreeSet::new();
    let mut sources = BTreeSet::new();
    let mut edge_count = 0usize;
    for entry in entries.take(
        iteron_tunables::param_integer(
            "record.content_store.model.max_content_references",
            MAX_CONTENT_REFERENCES,
        ) + 1,
    ) {
        if edge_count
            == iteron_tunables::param_integer(
                "record.content_store.model.max_content_references",
                MAX_CONTENT_REFERENCES,
            )
        {
            return Err(ContentStoreError::ReferenceBound {
                max: iteron_tunables::param_integer(
                    "record.content_store.model.max_content_references",
                    MAX_CONTENT_REFERENCES,
                ),
            });
        }
        edge_count = edge_count.saturating_add(1);
        let edge: ReferenceEdge = serde_json::from_slice(&read_limited(
            &entry?.path(),
            iteron_tunables::param_integer(
                "record.content_store.model.max_reference_edge_bytes",
                MAX_REFERENCE_EDGE_BYTES,
            ),
        )?)?;
        if edge.version != STORE_VERSION || edge.run_id != *run {
            return Err(ContentStoreError::Corrupt);
        }
        if edge.surface != ContentReferenceSurface::RecordField {
            for source in lineage::sources_for_reference(
                &layout,
                run,
                &edge.digest,
                Seq(edge.seq),
                edge.surface,
            )? {
                sources.insert(source);
            }
            digests.insert(edge.digest);
        }
    }
    for source in &sources {
        verify_source_owner_locked(&layout, source)?;
        let _ = load_bytes(&layout, &source.digest)?;
    }
    for digest in &digests {
        let _ = load_bytes(&layout, digest)?;
    }
    u32::try_from(digests.len()).map_err(|_| ContentStoreError::ReferenceBound {
        max: iteron_tunables::param_integer(
            "record.content_store.model.max_content_references",
            MAX_CONTENT_REFERENCES,
        ),
    })
}

/// Inventory the physical record-field sources owned by one run for a derivative writer.
///
/// The returned set is content-addressed and bounded; callers must pass it back to
/// `put_derived`, which re-validates every source under the store lock before publishing lineage.
pub fn private_content_sources_for_run(
    runs_dir: &Path,
    tenant: &TenantId,
    run: &RunId,
) -> Result<Vec<PrivateContentSource>, ContentStoreError> {
    crate::validate_run_id(run).map_err(|_| ContentStoreError::Corrupt)?;
    let layout = Layout::new(runs_dir, tenant);
    ensure_layout(&layout)?;
    let _owner_lock = lock_owner_shared(&layout, run)?;
    let run_dir = layout.run_reference_dir(run);
    let entries = match std::fs::read_dir(&run_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut sources = BTreeSet::new();
    let mut edge_count = 0usize;
    for entry in entries.take(
        iteron_tunables::param_integer(
            "record.content_store.model.max_content_references",
            MAX_CONTENT_REFERENCES,
        ) + 1,
    ) {
        if edge_count
            == iteron_tunables::param_integer(
                "record.content_store.model.max_content_references",
                MAX_CONTENT_REFERENCES,
            )
        {
            return Err(ContentStoreError::ReferenceBound {
                max: iteron_tunables::param_integer(
                    "record.content_store.model.max_content_references",
                    MAX_CONTENT_REFERENCES,
                ),
            });
        }
        edge_count = edge_count.saturating_add(1);
        let edge: ReferenceEdge = serde_json::from_slice(&read_limited(
            &entry?.path(),
            iteron_tunables::param_integer(
                "record.content_store.model.max_reference_edge_bytes",
                MAX_REFERENCE_EDGE_BYTES,
            ),
        )?)?;
        if edge.version != STORE_VERSION || edge.run_id != *run {
            return Err(ContentStoreError::Corrupt);
        }
        if edge.surface == ContentReferenceSurface::RecordField {
            load_bytes(&layout, &edge.digest)?;
            sources.insert(PrivateContentSource {
                owner: run.clone(),
                digest: edge.digest,
            });
        }
    }
    Ok(sources.into_iter().collect())
}

/// Retain exactly the named `(sequence, digest)` edges for one mutable derivative surface.
///
/// Call this only after its handle-only manifest is durably replaced. A crash before reconciliation
/// leaves extra encrypted references; a crash during reconciliation leaves at most a reverse edge,
/// which the next bounded pass removes. It can never shred content still named by the manifest.
pub fn retain_private_content_references(
    runs_dir: &Path,
    tenant: &TenantId,
    owner: &RunId,
    surface: ContentReferenceSurface,
    desired: &[(Seq, ErasureContentDigest)],
) -> Result<u32, ContentStoreError> {
    crate::validate_run_id(owner).map_err(|_| ContentStoreError::Corrupt)?;
    if desired.len()
        > iteron_tunables::param_integer(
            "record.content_store.model.max_content_references",
            MAX_CONTENT_REFERENCES,
        )
    {
        return Err(ContentStoreError::ReferenceBound {
            max: iteron_tunables::param_integer(
                "record.content_store.model.max_content_references",
                MAX_CONTENT_REFERENCES,
            ),
        });
    }
    let desired = desired
        .iter()
        .map(|(seq, digest)| (seq.0, digest.clone()))
        .collect::<BTreeSet<_>>();
    let layout = Layout::new(runs_dir, tenant);
    ensure_layout(&layout)?;
    let _store_lock = lock_store(&layout)?;
    let run_dir = layout.run_reference_dir(owner);
    let entries = match std::fs::read_dir(&run_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && desired.is_empty() => {
            return Ok(0);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(ContentStoreError::Unresolved {
                digest: desired
                    .iter()
                    .next()
                    .expect("non-empty desired set")
                    .1
                    .clone(),
                reason: "reference_missing",
            });
        }
        Err(error) => return Err(error.into()),
    };
    let mut seen = BTreeSet::new();
    let mut stale = Vec::new();
    let mut edge_count = 0usize;
    for entry in entries.take(
        iteron_tunables::param_integer(
            "record.content_store.model.max_content_references",
            MAX_CONTENT_REFERENCES,
        ) + 1,
    ) {
        if edge_count
            == iteron_tunables::param_integer(
                "record.content_store.model.max_content_references",
                MAX_CONTENT_REFERENCES,
            )
        {
            return Err(ContentStoreError::ReferenceBound {
                max: iteron_tunables::param_integer(
                    "record.content_store.model.max_content_references",
                    MAX_CONTENT_REFERENCES,
                ),
            });
        }
        edge_count = edge_count.saturating_add(1);
        let reverse_path = entry?.path();
        let edge: ReferenceEdge = serde_json::from_slice(&read_limited(
            &reverse_path,
            iteron_tunables::param_integer(
                "record.content_store.model.max_reference_edge_bytes",
                MAX_REFERENCE_EDGE_BYTES,
            ),
        )?)?;
        if edge.version != STORE_VERSION || edge.run_id != *owner {
            return Err(ContentStoreError::Corrupt);
        }
        if edge.surface != surface {
            continue;
        }
        let identity = (edge.seq, edge.digest.clone());
        if edge.ordinal == 0 && desired.contains(&identity) {
            let name = reverse_path.file_name().ok_or(ContentStoreError::Corrupt)?;
            if !layout
                .object_path(&layout.refs, &edge.digest)
                .join(name)
                .is_file()
            {
                return Err(ContentStoreError::Unresolved {
                    digest: edge.digest,
                    reason: "reference_missing",
                });
            }
            seen.insert(identity);
        } else {
            stale.push((reverse_path, edge));
        }
    }
    if !desired.is_subset(&seen) {
        let digest = desired
            .difference(&seen)
            .next()
            .expect("subset comparison found a missing reference")
            .1
            .clone();
        return Err(ContentStoreError::Unresolved {
            digest,
            reason: "reference_missing",
        });
    }

    let removed = stale.len();
    for (reverse_path, edge) in stale {
        lineage::remove_for_reference_locked(&layout, &edge)?;
        let name = reverse_path.file_name().ok_or(ContentStoreError::Corrupt)?;
        let digest_dir = layout.object_path(&layout.refs, &edge.digest);
        remove_if_present(&digest_dir.join(name))?;
        remove_if_present(&reverse_path)?;
        let has_references = match std::fs::read_dir(&digest_dir) {
            Ok(mut entries) => entries.next().transpose()?.is_some(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        if !has_references {
            remove_if_present(&layout.object_path(&layout.keys, &edge.digest))?;
            crate_sync_dir(&layout.keys)?;
            remove_if_present(&layout.object_path(&layout.blobs, &edge.digest))?;
            crate_sync_dir(&layout.blobs)?;
            let _ = std::fs::remove_dir(&digest_dir);
        }
    }
    if std::fs::read_dir(&run_dir)?.next().transpose()?.is_none() {
        std::fs::remove_dir(&run_dir)?;
    }
    crate_sync_dir(&layout.run_refs)?;
    u32::try_from(removed).map_err(|_| ContentStoreError::ReferenceBound {
        max: iteron_tunables::param_integer(
            "record.content_store.model.max_content_references",
            MAX_CONTENT_REFERENCES,
        ),
    })
}

/// Idempotently release one exact derivative handle without reconciling unrelated handles on the
/// same surface. Invocation-scoped attachments use this after their durable Message handoff; a
/// surface-wide `retain` would incorrectly delete older file attachments owned by the run.
#[allow(clippy::too_many_arguments)]
pub(super) fn release_private_content_reference(
    runs_dir: &Path,
    tenant: &TenantId,
    owner: &RunId,
    surface: ContentReferenceSurface,
    seq: Seq,
    digest: &ErasureContentDigest,
) -> Result<bool, ContentStoreError> {
    let layout = Layout::new(runs_dir, tenant);
    ensure_layout(&layout)?;
    let _store_lock = lock_store(&layout)?;
    let run_dir = layout.run_reference_dir(owner);
    let entries = match std::fs::read_dir(&run_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let mut count = 0usize;
    let mut found = None;
    for entry in entries.take(
        iteron_tunables::param_integer(
            "record.content_store.model.max_content_references",
            MAX_CONTENT_REFERENCES,
        ) + 1,
    ) {
        if count
            == iteron_tunables::param_integer(
                "record.content_store.model.max_content_references",
                MAX_CONTENT_REFERENCES,
            )
        {
            return Err(ContentStoreError::ReferenceBound {
                max: iteron_tunables::param_integer(
                    "record.content_store.model.max_content_references",
                    MAX_CONTENT_REFERENCES,
                ),
            });
        }
        count = count.saturating_add(1);
        let reverse_path = entry?.path();
        let edge: ReferenceEdge = serde_json::from_slice(&read_limited(
            &reverse_path,
            iteron_tunables::param_integer(
                "record.content_store.model.max_reference_edge_bytes",
                MAX_REFERENCE_EDGE_BYTES,
            ),
        )?)?;
        if edge.version != STORE_VERSION || edge.run_id != *owner {
            return Err(ContentStoreError::Corrupt);
        }
        if edge.surface == surface
            && edge.seq == seq.0
            && edge.ordinal == 0
            && edge.digest == *digest
        {
            found = Some((reverse_path, edge));
            break;
        }
    }
    let Some((reverse_path, edge)) = found else {
        return Ok(false);
    };
    lineage::remove_for_reference_locked(&layout, &edge)?;
    let name = reverse_path
        .file_name()
        .ok_or(ContentStoreError::Corrupt)?
        .to_owned();
    let digest_dir = layout.object_path(&layout.refs, &edge.digest);
    remove_if_present(&digest_dir.join(name))?;
    remove_if_present(&reverse_path)?;
    let has_references = match std::fs::read_dir(&digest_dir) {
        Ok(mut entries) => entries.next().transpose()?.is_some(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    if !has_references {
        remove_if_present(&layout.object_path(&layout.keys, &edge.digest))?;
        crate_sync_dir(&layout.keys)?;
        remove_if_present(&layout.object_path(&layout.blobs, &edge.digest))?;
        crate_sync_dir(&layout.blobs)?;
        let _ = std::fs::remove_dir(&digest_dir);
    }
    if std::fs::read_dir(&run_dir)?.next().transpose()?.is_none() {
        std::fs::remove_dir(&run_dir)?;
    }
    crate_sync_dir(&layout.run_refs)?;
    Ok(true)
}
