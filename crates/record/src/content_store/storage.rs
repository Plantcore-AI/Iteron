use super::crypto;
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
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};

static READY_LAYOUTS: OnceLock<RwLock<HashSet<PathBuf>>> = OnceLock::new();

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
    ready
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(layout.scope.clone());
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
        Ok(()) => Ok(StoreLock(file)),
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
        Ok(()) => Ok(StoreLock(file)),
        Err(TryLockError::WouldBlock) => Err(ContentStoreError::Busy),
        Err(TryLockError::Error(error)) => Err(error.into()),
    }
}

pub(super) struct StoreLock(File);

impl Drop for StoreLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

pub(super) fn store_locked(
    layout: &Layout,
    digest: &ErasureContentDigest,
    bytes: &[u8],
) -> Result<(), ContentStoreError> {
    ensure_available_locked(layout, digest).or_else(|error| match error {
        ContentStoreError::Unresolved {
            reason: "material_missing",
            ..
        } => Ok(()),
        other => Err(other),
    })?;
    let key_path = layout.object_path(&layout.keys, digest);
    let blob_path = layout.object_path(&layout.blobs, digest);
    if key_path.is_file() && blob_path.is_file() {
        let existing = load_bytes(layout, digest)?;
        return if existing == bytes {
            Ok(())
        } else {
            Err(ContentStoreError::Corrupt)
        };
    }
    if key_path.exists() != blob_path.exists() {
        return Err(ContentStoreError::Unresolved {
            digest: digest.clone(),
            reason: "partial_material",
        });
    }
    let aad = aad(layout, digest);
    let (key, blob) = crypto::seal(bytes, &aad).map_err(|_| ContentStoreError::Corrupt)?;
    private_replace(&key_path, &key)?;
    private_replace(&blob_path, &blob)?;
    Ok(())
}

pub(super) fn ensure_available_locked(
    layout: &Layout,
    digest: &ErasureContentDigest,
) -> Result<(), ContentStoreError> {
    let state = read_state(layout)?;
    if let Some(tombstone) = state.tombstone(digest) {
        return Err(ContentStoreError::Revoked {
            digest: digest.clone(),
            generation: tombstone.generation,
        });
    }
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
    let blob = read_limited(&blob_path, MAX_CONTENT_JSON_BYTES + 64).map_err(|_| {
        ContentStoreError::Unresolved {
            digest: digest.clone(),
            reason: "blob_missing",
        }
    })?;
    let bytes = crypto::open(&key, &blob, &aad(layout, digest)).map_err(|_| {
        ContentStoreError::Unresolved {
            digest: digest.clone(),
            reason: "authentication_failed",
        }
    })?;
    ensure_content_bound(&bytes)?;
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
    let dir = layout.object_path(&layout.refs, digest);
    std::fs::create_dir_all(&dir)?;
    set_private_dir(&dir)?;
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
    // The reverse edge is durable first. The tenant store lock excludes a revoker until both
    // edges exist; after a crash, exact-session cleanup can still discover this incomplete write.
    // No journal marker is appended until this function returns, so an absent forward edge cannot
    // hide content that an accepted record already references.
    let run_dir = layout.run_reference_dir(run);
    std::fs::create_dir_all(&run_dir)?;
    set_private_dir(&run_dir)?;
    let run_path = run_dir.join(format!("{id}.json"));
    if !run_path.exists() {
        let count = std::fs::read_dir(&run_dir)?
            .take(
                iteron_tunables::param_integer(
                    "record.content_store.model.max_content_references",
                    MAX_CONTENT_REFERENCES,
                ) + 1,
            )
            .count();
        if count
            >= iteron_tunables::param_integer(
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
        private_replace(&run_path, &bytes)?;
    }
    let lookup_dir = layout.run_reference_lookup_dir(run);
    std::fs::create_dir_all(&lookup_dir)?;
    set_private_dir(&lookup_dir)?;
    let lookup_path =
        reference_lookup_path(layout, digest, run, seq, ordinal, field_class, surface);
    if !lookup_path.exists() {
        private_replace(&lookup_path, id.as_bytes())?;
    }
    let path = dir.join(format!("{id}.json"));
    if !path.exists() {
        let count = std::fs::read_dir(&dir)?
            .take(
                iteron_tunables::param_integer(
                    "record.content_store.model.max_content_references",
                    MAX_CONTENT_REFERENCES,
                ) + 1,
            )
            .count();
        if count
            >= iteron_tunables::param_integer(
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
        private_replace(&path, &bytes)?;
    }
    Ok(())
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
    let entries = match std::fs::read_dir(&run_dir) {
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
    let mut hash = Sha256::new();
    hash.update(b"iteron-content-reference-lookup-v1\0");
    hash.update(digest.as_str().as_bytes());
    hash.update(seq.0.to_be_bytes());
    hash.update(ordinal.to_be_bytes());
    hash.update(field_class.as_bytes());
    hash.update(surface.label().as_bytes());
    layout
        .run_reference_lookup_dir(run)
        .join(hex::encode(hash.finalize()))
}

fn reference_edge_id(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(super) fn read_edges(
    layout: &Layout,
    digest: &ErasureContentDigest,
) -> Result<Vec<ReferenceEdge>, ContentStoreError> {
    let dir = layout.object_path(&layout.refs, digest);
    let entries = match std::fs::read_dir(&dir) {
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
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take((max + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "private content object exceeds its bound",
        ));
    }
    Ok(bytes)
}

pub(super) fn private_replace(path: &Path, bytes: &[u8]) -> Result<(), ContentStoreError> {
    crate::cache_io::atomic_replace_private(path, bytes).map_err(ContentStoreError::from)
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
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
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
