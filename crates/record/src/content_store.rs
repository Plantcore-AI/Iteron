//! Tenant-scoped encrypted content-addressed storage shared by records and large artifacts.

mod crypto;
mod derivative;
mod encoding;
mod fields;
mod model;
mod references;
mod revocation;
mod storage;

pub use derivative::PrivateContentDerivativeStore;
pub use model::{
    ContentReferenceSurface, MAX_PRIVATE_CONTENT_BYTES, MAX_PRIVATE_CONTENT_PREVIEW_BYTES,
    PrivateContentClass, PrivateContentHandle, PrivateContentRetention,
};
pub use references::{guard_private_content_for_run, retain_private_content_references};
pub(crate) use revocation::ContentRevocationGuard;

use core_protocol::{ErasureContentDigest, RunId, Seq, TenantId};
use model::{
    ENVELOPE_FIELD, MAX_CONTENT_JSON_BYTES, MAX_CONTENT_REFERENCES, MAX_REFERENCE_EDGE_BYTES,
    ReferenceEdge, STORE_VERSION,
};
use sha2::{Digest, Sha256};
use std::path::Path;
use storage::{
    Layout, OwnerLock, StoreLock, crate_sync_dir, ensure_available_locked, ensure_layout,
    load_bytes, load_bytes_with_state, lock_owner, lock_owner_shared, lock_store, read_edges,
    read_limited, read_state, remove_if_present, store_locked, write_edge_locked, write_state,
    write_tombstone,
};

#[derive(Debug, thiserror::Error)]
pub enum ContentStoreError {
    #[error("private content storage is busy")]
    Busy,
    #[error("private content exceeds the {max}-byte bound")]
    ContentTooLarge { max: usize },
    #[error("private content reference graph exceeds the {max}-edge bound")]
    ReferenceBound { max: usize },
    #[error("private content revocation ledger exceeds the {max}-entry bound")]
    RevocationBound { max: usize },
    #[error("private content {digest} is revoked at generation {generation}")]
    Revoked {
        digest: ErasureContentDigest,
        generation: u64,
    },
    #[error("private content {digest} is unresolved ({reason})")]
    Unresolved {
        digest: ErasureContentDigest,
        reason: &'static str,
    },
    #[error("private content reference names active run {run_id}")]
    ActiveWriter { run_id: RunId },
    #[error(
        "run {run_id} still has private content retained by {owners} external derivative owner(s)"
    )]
    RetainedByDerivative { run_id: RunId, owners: u32 },
    #[error("private content store is corrupt or has an unsupported schema")]
    Corrupt,
    #[error("invalid private content preview bound")]
    InvalidPreviewBound,
    #[error("record fields cannot be opened as mutable private-content derivatives")]
    InvalidDerivativeSurface,
    #[error("private-content derivative bound must be within 1..={max} bytes")]
    InvalidDerivativeBound { max: usize },
    #[error("private-content derivative handle does not match its store contract")]
    InvalidDerivativeHandle,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

/// A live non-journal derivative holds this lease while it can serve private bytes. Revocation
/// acquires the same owner lock before tombstoning, so it cannot race a stale in-memory copy.
pub struct PrivateContentOwnerLease {
    owner: RunId,
    _lock: OwnerLock,
}

impl PrivateContentOwnerLease {
    pub fn owner(&self) -> &RunId {
        &self.owner
    }
}

pub fn acquire_private_content_owner(
    runs_dir: &Path,
    tenant: &TenantId,
    owner: &RunId,
) -> Result<PrivateContentOwnerLease, ContentStoreError> {
    crate::validate_run_id(owner).map_err(|_| ContentStoreError::Corrupt)?;
    let layout = Layout::new(runs_dir, tenant);
    ensure_layout(&layout)?;
    Ok(PrivateContentOwnerLease {
        owner: owner.clone(),
        _lock: lock_owner_shared(&layout, owner)?,
    })
}

/// Store encrypted bytes and register their owning record edge before a caller persists the
/// handle. The returned preview is bounded live data and must not be serialized beside the handle.
#[allow(clippy::too_many_arguments)]
pub fn put_private_content(
    runs_dir: &Path,
    tenant: &TenantId,
    run: &RunId,
    seq: Seq,
    class: PrivateContentClass,
    retention: PrivateContentRetention,
    bytes: &[u8],
    preview_bytes: usize,
) -> Result<PrivateContentHandle, ContentStoreError> {
    put_private_content_at_surface(
        runs_dir,
        tenant,
        run,
        seq,
        class,
        ContentReferenceSurface::RecordField,
        retention,
        bytes,
        preview_bytes,
    )
}

/// Store content owned by a non-record derivative while binding it to the same revocation graph.
#[allow(clippy::too_many_arguments)]
pub fn put_private_content_at_surface(
    runs_dir: &Path,
    tenant: &TenantId,
    run: &RunId,
    seq: Seq,
    class: PrivateContentClass,
    surface: ContentReferenceSurface,
    retention: PrivateContentRetention,
    bytes: &[u8],
    preview_bytes: usize,
) -> Result<PrivateContentHandle, ContentStoreError> {
    if preview_bytes > MAX_PRIVATE_CONTENT_PREVIEW_BYTES {
        return Err(ContentStoreError::InvalidPreviewBound);
    }
    crate::validate_run_id(run).map_err(|_| ContentStoreError::Corrupt)?;
    ensure_content_bound(bytes)?;
    let layout = Layout::new(runs_dir, tenant);
    ensure_layout(&layout)?;
    let _lock = lock_store(&layout)?;
    let digest = digest_bytes(bytes);
    store_locked(&layout, &digest, bytes)?;
    write_edge_locked(
        &layout,
        &digest,
        run,
        seq,
        0,
        class_label(class),
        surface,
        retention,
    )?;
    Ok(PrivateContentHandle {
        digest,
        byte_len: u32::try_from(bytes.len()).map_err(|_| ContentStoreError::ContentTooLarge {
            max: MAX_CONTENT_JSON_BYTES,
        })?,
        class,
        preview: bounded_preview(bytes, preview_bytes),
    })
}

fn read_private_content_at_reference(
    runs_dir: &Path,
    tenant: &TenantId,
    owner: &RunId,
    seq: Seq,
    surface: ContentReferenceSurface,
    handle: &PrivateContentHandle,
) -> Result<Vec<u8>, ContentStoreError> {
    let layout = Layout::new(runs_dir, tenant);
    ensure_layout(&layout)?;
    let _store_lock = lock_store(&layout)?;
    let run_dir = layout.run_reference_dir(owner);
    let entries = std::fs::read_dir(&run_dir).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            ContentStoreError::Unresolved {
                digest: handle.digest.clone(),
                reason: "reference_missing",
            }
        } else {
            ContentStoreError::Io(error)
        }
    })?;
    let mut found = false;
    let mut count = 0usize;
    for entry in entries.take(MAX_CONTENT_REFERENCES + 1) {
        if count == MAX_CONTENT_REFERENCES {
            return Err(ContentStoreError::ReferenceBound {
                max: MAX_CONTENT_REFERENCES,
            });
        }
        count = count.saturating_add(1);
        let edge: ReferenceEdge =
            serde_json::from_slice(&read_limited(&entry?.path(), MAX_REFERENCE_EDGE_BYTES)?)?;
        if edge.version != STORE_VERSION || edge.run_id != *owner {
            return Err(ContentStoreError::Corrupt);
        }
        if edge.seq == seq.0
            && edge.ordinal == 0
            && edge.surface == surface
            && edge.field_class == class_label(handle.class)
            && edge.digest == handle.digest
        {
            found = true;
            break;
        }
    }
    if !found {
        return Err(ContentStoreError::Unresolved {
            digest: handle.digest.clone(),
            reason: "reference_missing",
        });
    }
    load_bytes(&layout, &handle.digest)
}

pub fn guard_private_content(
    runs_dir: &Path,
    tenant: &TenantId,
    digest: &ErasureContentDigest,
) -> Result<(), ContentStoreError> {
    let _ = load_bytes(&Layout::new(runs_dir, tenant), digest)?;
    Ok(())
}

pub fn register_private_content_reference(
    runs_dir: &Path,
    tenant: &TenantId,
    digest: &ErasureContentDigest,
    run: &RunId,
    seq: Seq,
    surface: ContentReferenceSurface,
    retention: PrivateContentRetention,
) -> Result<(), ContentStoreError> {
    crate::validate_run_id(run).map_err(|_| ContentStoreError::Corrupt)?;
    let layout = Layout::new(runs_dir, tenant);
    ensure_layout(&layout)?;
    let _lock = lock_store(&layout)?;
    ensure_available_locked(&layout, digest)?;
    write_edge_locked(
        &layout,
        digest,
        run,
        seq,
        0,
        surface.label(),
        surface,
        retention,
    )
}

pub fn private_content_digest(bytes: &[u8]) -> ErasureContentDigest {
    digest_bytes(bytes)
}

pub fn content_revocation_generation(
    runs_dir: &Path,
    tenant: &TenantId,
) -> Result<u64, ContentStoreError> {
    Ok(read_state(&Layout::new(runs_dir, tenant))?.generation)
}

/// Release every reference owned by one inactive run. Material shared by another run is retained;
/// an unreferenced blob is key-shredded and unlinked. Callers must hold the rollout writer lock.
pub fn release_private_content_for_run(
    runs_dir: &Path,
    tenant: &TenantId,
    run: &RunId,
) -> Result<u32, ContentStoreError> {
    crate::validate_run_id(run).map_err(|_| ContentStoreError::Corrupt)?;
    let layout = Layout::new(runs_dir, tenant);
    ensure_layout(&layout)?;
    let _lock = lock_store(&layout)?;
    release_run_locked(&layout, run)
}

/// Store-lock guard proving an exact-session unlink cannot leave a known external derivative.
///
/// Another record-field edge is independent ownership of equal bytes and is allowed. A
/// non-record edge owned by another identity is a real derivative manifest; without its owning
/// subsystem removing that handle, deleting the journal would leave the content readable. The
/// store lock closes the probe/delete race until [`Self::commit`] releases the run's edges.
pub(crate) struct ExactRunContentRelease {
    layout: Layout,
    run: RunId,
    _store_lock: StoreLock,
    _owner_lock: OwnerLock,
}

impl ExactRunContentRelease {
    pub(crate) fn prepare(
        runs_dir: &Path,
        tenant: &TenantId,
        run: &RunId,
    ) -> Result<Self, ContentStoreError> {
        crate::validate_run_id(run).map_err(|_| ContentStoreError::Corrupt)?;
        let layout = Layout::new(runs_dir, tenant);
        ensure_layout(&layout)?;
        let store_lock = lock_store(&layout)?;
        let owner_lock = lock_owner(&layout, run)?;
        let run_dir = layout.run_reference_dir(run);
        let entries = match std::fs::read_dir(&run_dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    layout,
                    run: run.clone(),
                    _store_lock: store_lock,
                    _owner_lock: owner_lock,
                });
            }
            Err(error) => return Err(error.into()),
        };
        let mut digests = std::collections::BTreeSet::new();
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
            digests.insert(edge.digest);
        }
        let mut owners = std::collections::BTreeSet::new();
        for digest in digests {
            for edge in read_edges(&layout, &digest)? {
                if edge.run_id != *run && edge.surface != ContentReferenceSurface::RecordField {
                    owners.insert(edge.run_id.0);
                }
            }
        }
        if !owners.is_empty() {
            return Err(ContentStoreError::RetainedByDerivative {
                run_id: run.clone(),
                owners: u32::try_from(owners.len()).map_err(|_| {
                    ContentStoreError::ReferenceBound {
                        max: MAX_CONTENT_REFERENCES,
                    }
                })?,
            });
        }
        Ok(Self {
            layout,
            run: run.clone(),
            _store_lock: store_lock,
            _owner_lock: owner_lock,
        })
    }

    pub(crate) fn commit(self) -> Result<u32, ContentStoreError> {
        release_run_locked(&self.layout, &self.run)
    }
}

/// Recover reference cleanup after a crash that durably unlinked a journal before releasing its
/// private-content edges. The scan is bounded and runs only on destructive retention paths.
pub(crate) fn release_private_content_for_absent_runs(
    runs_dir: &Path,
    tenant: &TenantId,
) -> Result<u32, ContentStoreError> {
    let layout = Layout::new(runs_dir, tenant);
    ensure_layout(&layout)?;
    let _lock = lock_store(&layout)?;
    let mut run_dirs = Vec::new();
    for entry in
        std::fs::read_dir(&layout.run_refs)?.take(model::MAX_CONTENT_RUNS.saturating_add(1))
    {
        if run_dirs.len() == model::MAX_CONTENT_RUNS {
            return Err(ContentStoreError::ReferenceBound {
                max: model::MAX_CONTENT_RUNS,
            });
        }
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            return Err(ContentStoreError::Corrupt);
        }
        run_dirs.push(entry.path());
    }

    let mut released = 0u32;
    for run_dir in run_dirs {
        let mut owner = None;
        let mut has_record_edge = false;
        let mut edge_count = 0usize;
        for entry in std::fs::read_dir(&run_dir)?.take(MAX_CONTENT_REFERENCES + 1) {
            if edge_count == MAX_CONTENT_REFERENCES {
                return Err(ContentStoreError::ReferenceBound {
                    max: MAX_CONTENT_REFERENCES,
                });
            }
            edge_count = edge_count.saturating_add(1);
            let path = entry?.path();
            let edge: ReferenceEdge =
                serde_json::from_slice(&read_limited(&path, MAX_REFERENCE_EDGE_BYTES)?)?;
            if edge.version != STORE_VERSION
                || layout.run_reference_dir(&edge.run_id) != run_dir
                || crate::validate_run_id(&edge.run_id).is_err()
                || owner
                    .as_ref()
                    .is_some_and(|candidate| candidate != &edge.run_id)
            {
                return Err(ContentStoreError::Corrupt);
            }
            has_record_edge |= edge.surface == ContentReferenceSurface::RecordField;
            owner = Some(edge.run_id);
        }
        let Some(owner) = owner else {
            std::fs::remove_dir(&run_dir)?;
            continue;
        };
        // Projection owners deliberately have no journal. They remain until their projection is
        // replaced or the referenced content is revoked, and must not be mistaken for a crashed
        // exact-session cleanup.
        if !has_record_edge {
            continue;
        }
        let rollout = crate::validated_run_path(runs_dir, &owner, ".jsonl")
            .map_err(|_| ContentStoreError::Corrupt)?;
        if !rollout.try_exists()? {
            released = released
                .checked_add(release_run_locked(&layout, &owner)?)
                .ok_or(ContentStoreError::ReferenceBound {
                    max: MAX_CONTENT_REFERENCES,
                })?;
        }
    }
    Ok(released)
}

fn release_run_locked(layout: &Layout, run: &RunId) -> Result<u32, ContentStoreError> {
    let run_dir = layout.run_reference_dir(run);
    let entries = match std::fs::read_dir(&run_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    let mut released = 0usize;
    for entry in entries.take(MAX_CONTENT_REFERENCES + 1) {
        if released == MAX_CONTENT_REFERENCES {
            return Err(ContentStoreError::ReferenceBound {
                max: MAX_CONTENT_REFERENCES,
            });
        }
        let run_edge = entry?.path();
        let edge: ReferenceEdge =
            serde_json::from_slice(&read_limited(&run_edge, MAX_REFERENCE_EDGE_BYTES)?)?;
        if edge.version != STORE_VERSION || edge.run_id != *run {
            return Err(ContentStoreError::Corrupt);
        }
        let edge_id = run_edge
            .file_name()
            .ok_or(ContentStoreError::Corrupt)?
            .to_owned();
        let digest_dir = layout.object_path(&layout.refs, &edge.digest);
        remove_if_present(&digest_dir.join(edge_id))?;
        remove_if_present(&run_edge)?;
        let digest_has_references = match std::fs::read_dir(&digest_dir) {
            Ok(mut entries) => entries.next().transpose()?.is_some(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        if !digest_has_references {
            remove_if_present(&layout.object_path(&layout.keys, &edge.digest))?;
            crate_sync_dir(&layout.keys)?;
            remove_if_present(&layout.object_path(&layout.blobs, &edge.digest))?;
            crate_sync_dir(&layout.blobs)?;
            let _ = std::fs::remove_dir(&digest_dir);
        }
        released = released.saturating_add(1);
    }
    let _ = std::fs::remove_dir(&run_dir);
    crate_sync_dir(&layout.run_refs)?;
    u32::try_from(released).map_err(|_| ContentStoreError::ReferenceBound {
        max: MAX_CONTENT_REFERENCES,
    })
}

/// Production coverage, not an inventory of possible enum variants.
///
/// Session projections and the session index persist content-bearing titles and reject stale
/// material whenever the tenant revocation generation changes. Prompt history persists only
/// encrypted handles and hydrates through `load_bytes`. Other namespaces remain false until a
/// production writer, source-to-derivative lineage, and every production read path all use the same
/// durable gate. In particular, the trajectory registry now has a gated handle store, but its
/// record-backed opener has no production caller and transformed source lineage is not yet durable.
pub(crate) fn guarded_derivative_coverage() -> core_protocol::ErasurePropagationCoverage {
    core_protocol::ErasurePropagationCoverage {
        session_projections: true,
        indexes: true,
        prompt_history: true,
        attachments: false,
        tool_artifacts: false,
        checkpoints: false,
        memory_context: false,
        exports: false,
        telemetry_debug: false,
        trajectories: false,
        datasets: false,
        evaluator_inputs: false,
        candidate_stores: false,
    }
}

pub(crate) fn externalize_event_payload(
    runs_dir: &Path,
    tenant: &TenantId,
    run: &RunId,
    seq: Seq,
    payload: &mut serde_json::Value,
) -> Result<(), ContentStoreError> {
    let layout = Layout::new(runs_dir, tenant);
    ensure_layout(&layout)?;
    let _lock = lock_store(&layout)?;
    let mut ordinal = 0u16;
    fields::visit_content_fields(payload, |field_class, value| {
        let (bytes, encoding) = encoding::encode(value)?;
        ensure_content_bound(&bytes)?;
        let digest = digest_bytes(&bytes);
        store_locked(&layout, &digest, &bytes)?;
        write_edge_locked(
            &layout,
            &digest,
            run,
            seq,
            ordinal,
            field_class,
            ContentReferenceSurface::RecordField,
            PrivateContentRetention::Session,
        )?;
        ordinal = ordinal
            .checked_add(1)
            .ok_or(ContentStoreError::ReferenceBound {
                max: usize::from(u16::MAX),
            })?;
        *value = serde_json::Value::String(encoding::marker(&digest, encoding));
        Ok::<(), ContentStoreError>(())
    })?;
    let object = payload.as_object_mut().ok_or(ContentStoreError::Corrupt)?;
    if object
        .insert(
            ENVELOPE_FIELD.to_owned(),
            serde_json::Value::from(STORE_VERSION),
        )
        .is_some()
    {
        return Err(ContentStoreError::Corrupt);
    }
    Ok(())
}

pub(crate) fn hydrate_event_payload(
    runs_dir: &Path,
    tenant: &TenantId,
    payload: &mut serde_json::Value,
) -> Result<(), ContentStoreError> {
    let Some(version) = payload
        .as_object_mut()
        .ok_or(ContentStoreError::Corrupt)?
        .remove(ENVELOPE_FIELD)
    else {
        // Inline legacy events predate private-reference markers. Never reinterpret their user
        // strings as handles merely because the text happens to share the marker prefix.
        return Ok(());
    };
    if version.as_u64() != Some(u64::from(STORE_VERSION)) {
        return Err(ContentStoreError::Corrupt);
    }
    let layout = Layout::new(runs_dir, tenant);
    let state = read_state(&layout)?;
    fields::visit_content_fields(payload, |_class, value| {
        let serde_json::Value::String(candidate) = value else {
            return Ok(());
        };
        let Some((digest, encoding)) = encoding::parse_marker(candidate)? else {
            return Ok(());
        };
        if let Some(tombstone) = state.tombstone(&digest) {
            return Err(ContentStoreError::Revoked {
                digest,
                generation: tombstone.generation,
            });
        }
        let bytes = load_bytes_with_state(&layout, &state, &digest)?;
        *value = encoding::decode(&bytes, encoding)
            .map_err(|reason| ContentStoreError::Unresolved { digest, reason })?;
        Ok(())
    })
}

fn bounded_preview(bytes: &[u8], limit: usize) -> Option<String> {
    if limit == 0 || bytes.is_empty() {
        return None;
    }
    let text = String::from_utf8_lossy(bytes);
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    Some(text[..end].to_owned())
}

fn class_label(class: PrivateContentClass) -> &'static str {
    match class {
        PrivateContentClass::Transcript => "transcript",
        PrivateContentClass::ModelThinking => "model_thinking",
        PrivateContentClass::ToolOutput => "tool_output",
        PrivateContentClass::ToolArguments => "tool_arguments",
        PrivateContentClass::Attachment => "attachment",
        PrivateContentClass::Context => "context",
        PrivateContentClass::Memory => "memory",
        PrivateContentClass::Artifact => "artifact",
        PrivateContentClass::Checkpoint => "checkpoint",
        PrivateContentClass::Export => "export",
        PrivateContentClass::TelemetryDebug => "telemetry_debug",
        PrivateContentClass::Trajectory => "trajectory",
        PrivateContentClass::Dataset => "dataset",
        PrivateContentClass::EvaluatorInput => "evaluator_input",
        PrivateContentClass::Candidate => "candidate",
    }
}

fn ensure_content_bound(bytes: &[u8]) -> Result<(), ContentStoreError> {
    if bytes.len() > MAX_CONTENT_JSON_BYTES {
        Err(ContentStoreError::ContentTooLarge {
            max: MAX_CONTENT_JSON_BYTES,
        })
    } else {
        Ok(())
    }
}

fn digest_bytes(bytes: &[u8]) -> ErasureContentDigest {
    ErasureContentDigest::new(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
        .expect("sha256 formatting is a valid content digest")
}

#[cfg(test)]
#[path = "content_store/tests.rs"]
mod tests;
