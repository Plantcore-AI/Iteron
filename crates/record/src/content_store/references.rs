//! Bounded reconciliation for mutable derivative manifests backed by immutable content blobs.

use super::model::{
    MAX_CONTENT_REFERENCES, MAX_REFERENCE_EDGE_BYTES, ReferenceEdge, STORE_VERSION,
};
use super::storage::{
    Layout, crate_sync_dir, ensure_layout, load_bytes, lock_owner_shared, lock_store, read_limited,
    remove_if_present,
};
use super::{ContentReferenceSurface, ContentStoreError};
use iteron_protocol::{ErasureContentDigest, RunId, Seq, TenantId};
use std::collections::BTreeSet;
use std::path::Path;

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
    ensure_layout(&layout)?;
    let _owner_lock = lock_owner_shared(&layout, run)?;
    let run_dir = layout.run_reference_dir(run);
    let entries = match std::fs::read_dir(&run_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    let mut digests = BTreeSet::new();
    let mut edge_count = 0usize;
    for entry in entries.take(MAX_CONTENT_REFERENCES + 1) {
        if edge_count == MAX_CONTENT_REFERENCES {
            return Err(ContentStoreError::ReferenceBound {
                max: MAX_CONTENT_REFERENCES,
            });
        }
        edge_count = edge_count.saturating_add(1);
        let edge: ReferenceEdge =
            serde_json::from_slice(&read_limited(&entry?.path(), MAX_REFERENCE_EDGE_BYTES)?)?;
        if edge.version != STORE_VERSION || edge.run_id != *run {
            return Err(ContentStoreError::Corrupt);
        }
        if edge.surface != ContentReferenceSurface::RecordField {
            digests.insert(edge.digest);
        }
    }
    for digest in &digests {
        let _ = load_bytes(&layout, digest)?;
    }
    u32::try_from(digests.len()).map_err(|_| ContentStoreError::ReferenceBound {
        max: MAX_CONTENT_REFERENCES,
    })
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
    if desired.len() > MAX_CONTENT_REFERENCES {
        return Err(ContentStoreError::ReferenceBound {
            max: MAX_CONTENT_REFERENCES,
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
    for entry in entries.take(MAX_CONTENT_REFERENCES + 1) {
        if edge_count == MAX_CONTENT_REFERENCES {
            return Err(ContentStoreError::ReferenceBound {
                max: MAX_CONTENT_REFERENCES,
            });
        }
        edge_count = edge_count.saturating_add(1);
        let reverse_path = entry?.path();
        let edge: ReferenceEdge =
            serde_json::from_slice(&read_limited(&reverse_path, MAX_REFERENCE_EDGE_BYTES)?)?;
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
    crate_sync_dir(&layout.run_refs)?;
    u32::try_from(removed).map_err(|_| ContentStoreError::ReferenceBound {
        max: MAX_CONTENT_REFERENCES,
    })
}
