use super::crypto;
use super::metadata;
use super::model::{
    CONTENT_ROOT, ContentTombstone, MAX_CONTENT_JSON_BYTES, MAX_CONTENT_REFERENCES,
    MAX_CONTENT_REVOCATIONS, MAX_REFERENCE_EDGE_BYTES, MAX_REVOCATION_STATE_BYTES, ReferenceEdge,
    RevocationState, STORE_VERSION,
};
use super::{
    ContentReferenceSurface, ContentStoreError, PrivateContentRetention, digest_bytes,
    ensure_content_bound,
};
use iteron_protocol::{ErasureContentDigest, RunId, Seq, TenantId};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};

static READY_LAYOUTS: OnceLock<RwLock<HashSet<PathBuf>>> = OnceLock::new();

#[cfg(test)]
std::thread_local! {
    pub(super) static STATE_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    pub(super) static BLOB_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub(super) struct Layout {
    pub(super) runs_dir: PathBuf,
    pub(super) blobs: PathBuf,
    pub(super) keys: PathBuf,
    pub(super) refs: PathBuf,
    pub(super) run_refs: PathBuf,
    pub(super) run_ref_lookup: PathBuf,
    pub(super) lineage_from: PathBuf,
    pub(super) lineage_to: PathBuf,
    pub(super) owner_locks: PathBuf,
    pub(super) tombstones: PathBuf,
    pub(super) state: PathBuf,
    pub(super) lock: PathBuf,
    scope: PathBuf,
    scope_hash: String,
}

impl Layout {
    pub(super) fn new(runs_dir: &Path, tenant: &TenantId) -> Self {
        let scope_hash = hex::encode(Sha256::digest(tenant.0.as_bytes()));
        let scope = runs_dir
            .join(CONTENT_ROOT)
            .join(format!("v{STORE_VERSION}"))
            .join(&scope_hash);
        Self {
            runs_dir: runs_dir.to_path_buf(),
            blobs: scope.join("blobs"),
            keys: scope.join("keys"),
            refs: scope.join("refs"),
            run_refs: scope.join("run-refs"),
            run_ref_lookup: scope.join("run-ref-lookup"),
            lineage_from: scope.join("lineage-from"),
            lineage_to: scope.join("lineage-to"),
            owner_locks: scope.join("owner-locks"),
            tombstones: scope.join("tombstones"),
            state: scope.join("revocations.json"),
            lock: scope.join("store.lock"),
            scope,
            scope_hash,
        }
    }

    pub(super) fn object_path(&self, dir: &Path, digest: &ErasureContentDigest) -> PathBuf {
        dir.join(digest.as_str().trim_start_matches("sha256:"))
    }

    pub(super) fn run_reference_dir(&self, run: &RunId) -> PathBuf {
        self.run_refs
            .join(hex::encode(Sha256::digest(run.0.as_bytes())))
    }

    fn run_reference_lookup_dir(&self, run: &RunId) -> PathBuf {
        self.run_ref_lookup
            .join(hex::encode(Sha256::digest(run.0.as_bytes())))
    }

    pub(super) fn store_exists(&self) -> Result<bool, ContentStoreError> {
        self.scope.try_exists().map_err(ContentStoreError::from)
    }

    fn owner_lock_path(&self, owner: &RunId) -> PathBuf {
        self.owner_locks
            .join(hex::encode(Sha256::digest(owner.0.as_bytes())))
    }
}

pub(super) fn ensure_layout(layout: &Layout) -> Result<(), ContentStoreError> {
    let ready = READY_LAYOUTS.get_or_init(|| RwLock::new(HashSet::new()));
    if ready
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains(&layout.scope)
    {
        return Ok(());
    }
    crate::create_state_dir(&layout.runs_dir)?;
    for dir in [
        &layout.scope,
        &layout.blobs,
        &layout.keys,
        &layout.refs,
        &layout.run_refs,
        &layout.run_ref_lookup,
        &layout.lineage_from,
        &layout.lineage_to,
        &layout.owner_locks,
        &layout.tombstones,
    ] {
        std::fs::create_dir_all(dir)?;
        set_private_dir(dir)?;
    }
    let mut ready = ready
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if ready.len() >= 128 {
        ready.clear();
    }
    ready.insert(layout.scope.clone());
    Ok(())
}

pub(super) fn lock_owner(layout: &Layout, owner: &RunId) -> Result<OwnerLock, ContentStoreError> {
    let path = layout.owner_lock_path(owner);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)?;
    set_private_file(&path)?;
    match file.try_lock() {
        Ok(()) => Ok(OwnerLock(file)),
        Err(TryLockError::WouldBlock) => Err(ContentStoreError::ActiveWriter {
            run_id: owner.clone(),
        }),
        Err(TryLockError::Error(error)) => Err(error.into()),
    }
}

pub(super) fn lock_owner_shared(
    layout: &Layout,
    owner: &RunId,
) -> Result<OwnerLock, ContentStoreError> {
    let path = layout.owner_lock_path(owner);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)?;
    set_private_file(&path)?;
    match file.try_lock_shared() {
        Ok(()) => Ok(OwnerLock(file)),
        Err(TryLockError::WouldBlock) => Err(ContentStoreError::ActiveWriter {
            run_id: owner.clone(),
        }),
        Err(TryLockError::Error(error)) => Err(error.into()),
    }
}

pub(super) struct OwnerLock(File);

impl Drop for OwnerLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

pub(super) fn lock_store(layout: &Layout) -> Result<StoreLock, ContentStoreError> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&layout.lock)?;
    set_private_file(&layout.lock)?;
    match file.try_lock() {
        Ok(()) => {
            let mut lock = StoreLock {
                file,
                write_state: None,
                metadata_lease: None,
            };
            lock.metadata_lease = Some(metadata::write_lease(&layout.scope)?);
            // Fence legacy binaries durably before the first compact mutation. A crash may
            // leave a fenced legacy-only store, which this version still reads normally.
            let mut state = read_state(layout)?;
            if state.metadata_format.is_none() {
                state.metadata_format = Some(2);
                write_state(layout, &state)?;
            }
            lock.write_state = Some(state);
            Ok(lock)
        }
        Err(TryLockError::WouldBlock) => Err(ContentStoreError::Busy),
        Err(TryLockError::Error(error)) => Err(error.into()),
    }
}

pub(super) fn lock_store_shared(layout: &Layout) -> Result<StoreLock, ContentStoreError> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&layout.lock)?;
    set_private_file(&layout.lock)?;
    match file.try_lock_shared() {
        Ok(()) => {
            let lock = StoreLock {
                file,
                write_state: None,
                metadata_lease: None,
            };
            metadata::refresh(&layout.scope, false)?;
            Ok(lock)
        }
        Err(TryLockError::WouldBlock) => Err(ContentStoreError::Busy),
        Err(TryLockError::Error(error)) => Err(error.into()),
    }
}

pub(super) struct StoreLock {
    file: File,
    write_state: Option<RevocationState>,
    metadata_lease: Option<metadata::WriteLease>,
}

impl StoreLock {
    /// The exclusive lease excludes revocation between fields of one publication. This snapshot
    /// is borrowed only by non-revoking writes; destructive phases keep their explicit rereads.
    pub(super) fn write_state(&self) -> Result<&RevocationState, ContentStoreError> {
        self.write_state.as_ref().ok_or(ContentStoreError::Corrupt)
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        // Close the descriptor and release the index pin while peers are still excluded.
        self.metadata_lease.take();
        let _ = self.file.unlock();
    }
}

pub(super) fn store_locked(
    layout: &Layout,
    state: &RevocationState,
    digest: &ErasureContentDigest,
    bytes: &[u8],
) -> Result<(), ContentStoreError> {
    ensure_not_revoked(state, digest)?;
    let key_path = layout.object_path(&layout.keys, digest);
    let blob_path = layout.object_path(&layout.blobs, digest);
    let key = material_metadata(&key_path)?;
    let blob = material_metadata(&blob_path)?;
    if key.as_ref().is_some_and(std::fs::Metadata::is_file)
        && blob.as_ref().is_some_and(std::fs::Metadata::is_file)
    {
        // Deduplication still authenticates and compares the physical bytes. Only the state
        // already validated under this exact lease is reused, never cached plaintext.
        let existing = load_bytes_with_state(layout, state, digest)?;
        return if existing == bytes {
            Ok(())
        } else {
            Err(ContentStoreError::Corrupt)
        };
    }
    if key.is_some() != blob.is_some() {
        return Err(ContentStoreError::Unresolved {
            digest: digest.clone(),
            reason: "partial_material",
        });
    }
    if key.is_some() || blob.is_some() {
        return Err(ContentStoreError::Corrupt);
    }
    let aad = aad(layout, digest);
    let (key, blob) = crypto::seal(bytes, &aad).map_err(|_| ContentStoreError::Corrupt)?;
    buffered_replace(&key_path, &key)?;
    buffered_replace(&blob_path, &blob)?;
    Ok(())
}

pub(super) fn ensure_available_locked(
    layout: &Layout,
    state: &RevocationState,
    digest: &ErasureContentDigest,
) -> Result<(), ContentStoreError> {
    ensure_not_revoked(state, digest)?;
    let key = layout.object_path(&layout.keys, digest);
    let blob = layout.object_path(&layout.blobs, digest);
    if key.is_file() && blob.is_file() {
        Ok(())
    } else {
        Err(ContentStoreError::Unresolved {
            digest: digest.clone(),
            reason: "material_missing",
        })
    }
}

fn material_metadata(path: &Path) -> Result<Option<std::fs::Metadata>, ContentStoreError> {
    match std::fs::metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn ensure_not_revoked(
    state: &RevocationState,
    digest: &ErasureContentDigest,
) -> Result<(), ContentStoreError> {
    if let Some(tombstone) = state.tombstone(digest) {
        return Err(ContentStoreError::Revoked {
            digest: digest.clone(),
            generation: tombstone.generation,
        });
    }
    Ok(())
}

pub(super) fn load_bytes(
    layout: &Layout,
    digest: &ErasureContentDigest,
) -> Result<Vec<u8>, ContentStoreError> {
    let state = read_state(layout)?;
    load_bytes_with_state(layout, &state, digest)
}

pub(super) fn load_bytes_with_state(
    layout: &Layout,
    state: &RevocationState,
    digest: &ErasureContentDigest,
) -> Result<Vec<u8>, ContentStoreError> {
    load_bytes_with_state_bounded(layout, state, digest, None)
}

pub(super) fn load_bytes_with_state_bounded(
    layout: &Layout,
    state: &RevocationState,
    digest: &ErasureContentDigest,
    remaining: Option<usize>,
) -> Result<Vec<u8>, ContentStoreError> {
    #[cfg(test)]
    BLOB_READS.with(|reads| reads.set(reads.get() + 1));
    if let Some(tombstone) = state.tombstone(digest) {
        return Err(ContentStoreError::Revoked {
            digest: digest.clone(),
            generation: tombstone.generation,
        });
    }
    let key_path = layout.object_path(&layout.keys, digest);
    let blob_path = layout.object_path(&layout.blobs, digest);
    let key = read_limited(&key_path, 64).map_err(|_| ContentStoreError::Unresolved {
        digest: digest.clone(),
        reason: "key_missing",
    })?;
    let blob = read_limited(
        &blob_path,
        remaining
            .unwrap_or(MAX_CONTENT_JSON_BYTES)
            .min(MAX_CONTENT_JSON_BYTES)
            .saturating_add(64),
    )
    .map_err(|_| ContentStoreError::Unresolved {
        digest: digest.clone(),
        reason: "blob_missing",
    })?;
    let bytes = crypto::open(&key, &blob, &aad(layout, digest)).map_err(|_| {
        ContentStoreError::Unresolved {
            digest: digest.clone(),
            reason: "authentication_failed",
        }
    })?;
    ensure_content_bound(&bytes)?;
    if remaining.is_some_and(|remaining| bytes.len() > remaining) {
        return Err(ContentStoreError::ContentTooLarge {
            max: remaining.unwrap_or(0),
        });
    }
    if digest_bytes(&bytes) != *digest {
        return Err(ContentStoreError::Unresolved {
            digest: digest.clone(),
            reason: "digest_mismatch",
        });
    }
    Ok(bytes)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn write_edge_locked(
    layout: &Layout,
    digest: &ErasureContentDigest,
    run: &RunId,
    seq: Seq,
    ordinal: u16,
    field_class: &str,
    surface: ContentReferenceSurface,
    retention: PrivateContentRetention,
) -> Result<(), ContentStoreError> {
    write_edges_locked(
        layout,
        digest,
        run,
        seq,
        ordinal,
        field_class,
        &[surface],
        retention,
        reference_limit(),
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn write_record_edges_locked(
    layout: &Layout,
    digest: &ErasureContentDigest,
    run: &RunId,
    seq: Seq,
    ordinal: u16,
    field_class: &str,
    semantic: Option<ContentReferenceSurface>,
) -> Result<(), ContentStoreError> {
    let surfaces = [
        ContentReferenceSurface::RecordField,
        semantic.unwrap_or(ContentReferenceSurface::RecordField),
    ];
    write_edges_locked(
        layout,
        digest,
        run,
        seq,
        ordinal,
        field_class,
        &surfaces[..if semantic.is_some() { 2 } else { 1 }],
        PrivateContentRetention::Session,
        reference_limit(),
    )
}

/// A field has at most its record root and one semantic reference. Admit both against the
/// committed counts before publishing one frame, so the pair cannot overrun either index.
#[allow(clippy::too_many_arguments)]
fn write_edges_locked(
    layout: &Layout,
    digest: &ErasureContentDigest,
    run: &RunId,
    seq: Seq,
    ordinal: u16,
    field_class: &str,
    surfaces: &[ContentReferenceSurface],
    retention: PrivateContentRetention,
    limit: usize,
) -> Result<(), ContentStoreError> {
    if surfaces.is_empty()
        || surfaces.len() > 2
        || (surfaces.len() == 2 && surfaces[0] == surfaces[1])
    {
        return Err(ContentStoreError::Corrupt);
    }
    let dir = layout.object_path(&layout.refs, digest);
    let run_dir = layout.run_reference_dir(run);
    let mut changes = Vec::with_capacity(surfaces.len() * 3);
    let mut run_added = 0usize;
    let mut digest_added = 0usize;
    for &surface in surfaces {
        let edge = ReferenceEdge {
            version: STORE_VERSION,
            digest: digest.clone(),
            run_id: run.clone(),
            seq: seq.0,
            ordinal,
            field_class: field_class.to_owned(),
            surface,
            retention,
        };
        let bytes = serde_json::to_vec(&edge)?;
        if bytes.len()
            > iteron_tunables::param_integer(
                "record.content_store.model.max_reference_edge_bytes",
                MAX_REFERENCE_EDGE_BYTES,
            )
        {
            return Err(ContentStoreError::Corrupt);
        }
        let id = reference_edge_id(&bytes);
        let run_path = run_dir.join(format!("{id}.json"));
        let path = dir.join(format!("{id}.json"));
        for (candidate, added) in [(run_path, &mut run_added), (path, &mut digest_added)] {
            if metadata::is_file(&candidate)? {
                if read_limited(&candidate, MAX_REFERENCE_EDGE_BYTES)? != bytes {
                    return Err(ContentStoreError::Corrupt);
                }
            } else {
                *added += 1;
                changes.push((candidate, Some(bytes.clone())));
            }
        }
        let lookup_path =
            reference_lookup_path(layout, digest, run, seq, ordinal, field_class, surface);
        if !metadata::is_file(&lookup_path)? {
            changes.push((lookup_path, Some(id.into_bytes())));
        }
    }
    for (directory, added) in [(&run_dir, run_added), (&dir, digest_added)] {
        if added != 0
            && metadata_count(directory)?
                .checked_add(added)
                .is_none_or(|next| next > limit)
        {
            return Err(ContentStoreError::ReferenceBound { max: limit });
        }
    }
    // Both directions and direct lookups for the complete pair commit together. A failed
    // preflight or append cannot leave just the first new reference admitted.
    metadata::replace_batch(&changes)?;
    Ok(())
}

fn reference_limit() -> usize {
    iteron_tunables::param_integer(
        "record.content_store.model.max_content_references",
        MAX_CONTENT_REFERENCES,
    )
}

fn metadata_count(dir: &Path) -> Result<usize, ContentStoreError> {
    if let Some(count) = metadata::reference_count(dir)? {
        return Ok(count);
    }
    match metadata::read_dir(dir) {
        Ok(entries) => Ok(entries
            .take(
                iteron_tunables::param_integer(
                    "record.content_store.model.max_content_references",
                    MAX_CONTENT_REFERENCES,
                ) + 1,
            )
            .collect::<std::io::Result<Vec<_>>>()?
            .len()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn reference_edge_path(
    layout: &Layout,
    digest: &ErasureContentDigest,
    run: &RunId,
    seq: Seq,
    ordinal: u16,
    field_class: &str,
    surface: ContentReferenceSurface,
) -> Result<PathBuf, ContentStoreError> {
    let lookup = reference_lookup_path(layout, digest, run, seq, ordinal, field_class, surface);
    match read_limited(&lookup, 64) {
        Ok(id) => {
            if id.len() != 64 || !id.iter().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(ContentStoreError::Corrupt);
            }
            let id = std::str::from_utf8(&id).map_err(|_| ContentStoreError::Corrupt)?;
            return Ok(layout.run_reference_dir(run).join(format!("{id}.json")));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    // Stores created before the direct lookup index are still replayable. This bounded legacy
    // path is deliberately absent for newly-written references, so steady-state reads remain one
    // lookup plus one edge read instead of a directory scan. A subsequent store rebuild can
    // materialize lookup pointers without changing the durable edge format.
    let run_dir = layout.run_reference_dir(run);
    let entries = match metadata::read_dir(&run_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(ContentStoreError::Unresolved {
                digest: digest.clone(),
                reason: "reference_missing",
            });
        }
        Err(error) => return Err(error.into()),
    };
    let limit = iteron_tunables::param_integer(
        "record.content_store.model.max_content_references",
        MAX_CONTENT_REFERENCES,
    );
    for entry in entries.take(limit.saturating_add(1)) {
        let path = entry?.path();
        let bytes = read_limited(
            &path,
            iteron_tunables::param_integer(
                "record.content_store.model.max_reference_edge_bytes",
                MAX_REFERENCE_EDGE_BYTES,
            ),
        )?;
        let edge: ReferenceEdge = serde_json::from_slice(&bytes)?;
        if edge.version != STORE_VERSION || edge.run_id != *run {
            return Err(ContentStoreError::Corrupt);
        }
        if edge.digest == *digest
            && edge.seq == seq.0
            && edge.ordinal == ordinal
            && edge.field_class == field_class
            && edge.surface == surface
        {
            return Ok(path);
        }
    }
    Err(ContentStoreError::Unresolved {
        digest: digest.clone(),
        reason: "reference_missing",
    })
}

fn reference_lookup_path(
    layout: &Layout,
    digest: &ErasureContentDigest,
    run: &RunId,
    seq: Seq,
    ordinal: u16,
    field_class: &str,
    surface: ContentReferenceSurface,
) -> PathBuf {
    layout
        .run_reference_lookup_dir(run)
        .join(reference_lookup_id(
            digest,
            seq,
            ordinal,
            field_class,
            surface,
        ))
}

fn reference_lookup_id(
    digest: &ErasureContentDigest,
    seq: Seq,
    ordinal: u16,
    field_class: &str,
    surface: ContentReferenceSurface,
) -> String {
    let mut hash = Sha256::new();
    hash.update(b"iteron-content-reference-lookup-v1\0");
    hash.update(digest.as_str().as_bytes());
    hash.update(seq.0.to_be_bytes());
    hash.update(ordinal.to_be_bytes());
    hash.update(field_class.as_bytes());
    hash.update(surface.label().as_bytes());
    hex::encode(hash.finalize())
}

fn reference_edge_id(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(super) fn read_edges(
    layout: &Layout,
    digest: &ErasureContentDigest,
) -> Result<Vec<ReferenceEdge>, ContentStoreError> {
    let dir = layout.object_path(&layout.refs, digest);
    let entries = match metadata::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut edges = Vec::new();
    for entry in entries.take(
        iteron_tunables::param_integer(
            "record.content_store.model.max_content_references",
            MAX_CONTENT_REFERENCES,
        ) + 1,
    ) {
        if edges.len()
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
        let path = entry?.path();
        let bytes = read_limited(
            &path,
            iteron_tunables::param_integer(
                "record.content_store.model.max_reference_edge_bytes",
                MAX_REFERENCE_EDGE_BYTES,
            ),
        )?;
        let edge: ReferenceEdge = serde_json::from_slice(&bytes)?;
        if edge.version != STORE_VERSION || edge.digest != *digest {
            return Err(ContentStoreError::Corrupt);
        }
        crate::validate_run_id(&edge.run_id).map_err(|_| ContentStoreError::Corrupt)?;
        edges.push(edge);
    }
    edges.sort_by(|left, right| {
        (&left.run_id.0, left.seq, left.ordinal).cmp(&(&right.run_id.0, right.seq, right.ordinal))
    });
    Ok(edges)
}

pub(super) fn read_state(layout: &Layout) -> Result<RevocationState, ContentStoreError> {
    #[cfg(test)]
    STATE_READS.with(|reads| reads.set(reads.get() + 1));
    let bytes = match read_limited(
        &layout.state,
        iteron_tunables::param_integer(
            "record.content_store.model.max_revocation_state_bytes",
            MAX_REVOCATION_STATE_BYTES,
        ),
    ) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RevocationState::empty());
        }
        Err(error) => return Err(error.into()),
    };
    let state: RevocationState = serde_json::from_slice(&bytes)?;
    if state.version != STORE_VERSION
        || state.metadata_format.is_some_and(|format| format != 2)
        || state.tombstones.len()
            > iteron_tunables::param_integer(
                "record.content_store.model.max_content_revocations",
                MAX_CONTENT_REVOCATIONS,
            )
        || state
            .tombstones
            .windows(2)
            .any(|pair| pair[0].digest >= pair[1].digest)
        || state
            .tombstones
            .iter()
            .any(|entry| entry.version != STORE_VERSION || entry.generation > state.generation)
    {
        return Err(ContentStoreError::Corrupt);
    }
    Ok(state)
}

pub(super) fn write_state(
    layout: &Layout,
    state: &RevocationState,
) -> Result<(), ContentStoreError> {
    if state.tombstones.len()
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
    let bytes = serde_json::to_vec(state)?;
    if bytes.len()
        > iteron_tunables::param_integer(
            "record.content_store.model.max_revocation_state_bytes",
            MAX_REVOCATION_STATE_BYTES,
        )
    {
        return Err(ContentStoreError::RevocationBound {
            max: iteron_tunables::param_integer(
                "record.content_store.model.max_content_revocations",
                MAX_CONTENT_REVOCATIONS,
            ),
        });
    }
    private_replace(&layout.state, &bytes)
}

pub(super) fn write_tombstone(
    layout: &Layout,
    tombstone: &ContentTombstone,
) -> Result<(), ContentStoreError> {
    let bytes = serde_json::to_vec_pretty(tombstone)?;
    private_replace(
        &layout.object_path(&layout.tombstones, &tombstone.digest),
        &bytes,
    )
}

pub(super) fn read_limited(path: &Path, max: usize) -> std::io::Result<Vec<u8>> {
    metadata::read(path, max)
}

pub(super) fn private_replace(path: &Path, bytes: &[u8]) -> Result<(), ContentStoreError> {
    if metadata::location(path).is_some() {
        return metadata::replace_batch(&[(path.to_path_buf(), Some(bytes.to_vec()))])
            .map_err(ContentStoreError::from);
    }
    crate::cache_io::atomic_replace_private(path, bytes).map_err(ContentStoreError::from)
}

/// Immutable material uses a private scratch file plus rename, with OS-write acknowledgement.
/// A process crash cannot expose partial ciphertext at its final path. Revocation metadata uses
/// the separately durable `private_replace` path above.
fn buffered_replace(path: &Path, bytes: &[u8]) -> Result<(), ContentStoreError> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    for _ in 0..16 {
        let nonce = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let scratch = path.with_extension(format!("pending-{}-{nonce}", std::process::id()));
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = match options.open(&scratch) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        };
        let result = file.write_all(bytes).and_then(|()| {
            drop(file);
            std::fs::rename(&scratch, path)
        });
        if result.is_err() {
            let _ = std::fs::remove_file(&scratch);
        }
        return result.map_err(ContentStoreError::from);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "private content scratch path exhausted",
    )
    .into())
}

fn aad(layout: &Layout, digest: &ErasureContentDigest) -> Vec<u8> {
    format!(
        "core-private-content-v1\0{}\0{}",
        layout.scope_hash,
        digest.as_str()
    )
    .into_bytes()
}

pub(super) fn crate_sync_dir(path: &Path) -> Result<(), ContentStoreError> {
    crate::cache_io::sync_dir(path).map_err(ContentStoreError::from)
}

pub(super) fn remove_if_present(path: &Path) -> Result<(), ContentStoreError> {
    let mut removed = vec![path.to_path_buf()];
    if let Some((scope, relative)) = metadata::location(path) {
        if relative.starts_with("run-refs/") {
            match read_limited(path, MAX_REFERENCE_EDGE_BYTES) {
                Ok(bytes) => {
                    let edge: ReferenceEdge = serde_json::from_slice(&bytes)?;
                    if edge.version != STORE_VERSION {
                        return Err(ContentStoreError::Corrupt);
                    }
                    removed.push(
                        scope
                            .join("run-ref-lookup")
                            .join(hex::encode(Sha256::digest(edge.run_id.0.as_bytes())))
                            .join(reference_lookup_id(
                                &edge.digest,
                                Seq(edge.seq),
                                edge.ordinal,
                                &edge.field_class,
                                edge.surface,
                            )),
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        metadata::replace_batch(
            &removed
                .iter()
                .cloned()
                .map(|path| (path, None))
                .collect::<Vec<_>>(),
        )?;
    }
    for path in removed {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_file(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_private_file(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_dir(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests;
