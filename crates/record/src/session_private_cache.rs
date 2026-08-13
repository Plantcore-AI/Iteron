//! Private, rebuildable session-cache projections.
//!
//! The public cache files contain only bounded CAS manifests. Every content-bearing
//! [`SessionMeta`] byte lives in the tenant private-content store and is derived from the
//! record-field handles owned by the run. Hydration therefore re-enters the exact owner/surface
//! read gate and source revocation invalidates even a copied, pre-revocation manifest.

use super::SessionMeta;
use crate::{
    ContentReferenceSurface, ContentStoreError, PrivateContentClass, PrivateContentDerivativeStore,
    PrivateContentHandle, PrivateContentNamespace, PrivateContentRetention, RecordError,
};
use iteron_protocol::{RunId, Seq, TenantId};
use serde::{Deserialize, Serialize};
use std::path::Path;

const MANIFEST_VERSION: u16 = 1;
const SESSION_PROJECTION_SEQ: Seq = Seq(u64::MAX - 1);
const SESSION_INDEX_SEQ: Seq = Seq(u64::MAX);
const CONTENT_BUSY_RETRY_ATTEMPTS: usize = 401;
const CONTENT_BUSY_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(5);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheManifest {
    version: u16,
    owner: RunId,
    tenant: TenantId,
    seq: u64,
    surface: ContentReferenceSurface,
    handle: PrivateContentHandle,
}

struct StagedCache {
    store: PrivateContentDerivativeStore,
    seq: Seq,
    handle: PrivateContentHandle,
    manifest: Vec<u8>,
}

impl StagedCache {
    fn commit(self) -> Result<(), RecordError> {
        let desired = [(self.seq, self.handle.digest)];
        retry_content_busy(|| self.store.retain(&desired))
            .map(|_| ())
            .map_err(Into::into)
    }
}

fn retry_content_busy<T>(
    mut operation: impl FnMut() -> Result<T, ContentStoreError>,
) -> Result<T, ContentStoreError> {
    for attempt in 0..iteron_tunables::param_integer(
        "record.session_private_cache.content_busy_retry_attempts",
        CONTENT_BUSY_RETRY_ATTEMPTS,
    ) {
        match operation() {
            Err(ContentStoreError::Busy)
                if attempt + 1
                    < iteron_tunables::param_integer(
                        "record.session_private_cache.content_busy_retry_attempts",
                        CONTENT_BUSY_RETRY_ATTEMPTS,
                    ) =>
            {
                std::thread::sleep(iteron_tunables::param_duration(
                    "record.session_private_cache.content_busy_retry_delay",
                    CONTENT_BUSY_RETRY_DELAY,
                ));
            }
            result => return result,
        }
    }
    unreachable!("the bounded private-cache retry loop always returns")
}

fn surface_spec(
    surface: ContentReferenceSurface,
) -> Result<(PrivateContentClass, Seq), RecordError> {
    match surface {
        ContentReferenceSurface::SessionProjection => Ok((
            PrivateContentClass::SessionProjection,
            SESSION_PROJECTION_SEQ,
        )),
        ContentReferenceSurface::SessionIndex => {
            Ok((PrivateContentClass::SessionIndex, SESSION_INDEX_SEQ))
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid session-cache content surface",
        )
        .into()),
    }
}

fn open_store(
    runs_dir: &Path,
    tenant: &TenantId,
    owner: &RunId,
    surface: ContentReferenceSurface,
) -> Result<(PrivateContentDerivativeStore, Seq), RecordError> {
    let (class, seq) = surface_spec(surface)?;
    let namespace = PrivateContentNamespace::from_surface(surface).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unregistered session-cache content surface",
        )
    })?;
    Ok((
        PrivateContentDerivativeStore::open_registered(
            runs_dir.to_path_buf(),
            tenant.clone(),
            owner.clone(),
            namespace,
            class,
            PrivateContentRetention::Session,
            crate::cache_io::MAX_SESSION_META_BYTES,
        )?,
        seq,
    ))
}

fn stage(
    runs_dir: &Path,
    meta: &SessionMeta,
    surface: ContentReferenceSurface,
) -> Result<StagedCache, RecordError> {
    let bytes = serde_json::to_vec(meta)?;
    if bytes.len() > crate::cache_io::MAX_SESSION_META_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "session metadata exceeds the cache byte limit",
        )
        .into());
    }
    let (store, seq) = open_store(runs_dir, &meta.tenant, &meta.run_id, surface)?;
    let handle = retry_content_busy(|| store.put_derived_from_run(seq, &bytes, &meta.run_id))?;
    let manifest = serde_json::to_vec(&CacheManifest {
        version: MANIFEST_VERSION,
        owner: meta.run_id.clone(),
        tenant: meta.tenant.clone(),
        seq: seq.0,
        surface,
        handle: handle.clone(),
    })?;
    if manifest.len() > crate::cache_io::MAX_INDEX_LINE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "session cache manifest exceeds the cache byte limit",
        )
        .into());
    }
    Ok(StagedCache {
        store,
        seq,
        handle,
        manifest,
    })
}

fn hydrate(
    runs_dir: &Path,
    bytes: &[u8],
    expected_surface: ContentReferenceSurface,
) -> Result<SessionMeta, RecordError> {
    let manifest: CacheManifest = serde_json::from_slice(bytes)?;
    let (expected_class, expected_seq) = surface_spec(expected_surface)?;
    if manifest.version != MANIFEST_VERSION
        || manifest.surface != expected_surface
        || manifest.seq != expected_seq.0
        || manifest.handle.class != expected_class
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid session cache manifest",
        )
        .into());
    }
    let (store, _) = open_store(
        runs_dir,
        &manifest.tenant,
        &manifest.owner,
        expected_surface,
    )?;
    let private = retry_content_busy(|| store.read_at(expected_seq, &manifest.handle))?;
    let meta: SessionMeta = serde_json::from_slice(&private)?;
    if meta.run_id != manifest.owner || meta.tenant != manifest.tenant {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "session cache manifest owner mismatch",
        )
        .into());
    }
    Ok(meta)
}

pub(crate) fn read_sidecar(runs_dir: &Path, bytes: &[u8]) -> Result<SessionMeta, RecordError> {
    hydrate(runs_dir, bytes, ContentReferenceSurface::SessionProjection)
}

pub(crate) fn read_index_line(runs_dir: &Path, bytes: &[u8]) -> Result<SessionMeta, RecordError> {
    hydrate(runs_dir, bytes, ContentReferenceSurface::SessionIndex)
}

pub(super) fn write_sidecar(
    runs_dir: &Path,
    path: &Path,
    meta: &SessionMeta,
    defer_dir_sync: bool,
) -> Result<(), RecordError> {
    let staged = stage(runs_dir, meta, ContentReferenceSurface::SessionProjection)?;
    if defer_dir_sync {
        crate::cache_io::atomic_replace_deferring_dir_sync(path, &staged.manifest)?;
    } else {
        crate::cache_io::atomic_replace(path, &staged.manifest)?;
    }
    staged.commit()
}

pub(super) fn sidecar_matches(runs_dir: &Path, persisted: &[u8], expected: &SessionMeta) -> bool {
    read_sidecar(runs_dir, persisted)
        .is_ok_and(|actual| serde_json::to_vec(&actual).ok() == serde_json::to_vec(expected).ok())
}

pub(super) fn write_index<'a>(
    runs_dir: &Path,
    path: &Path,
    metas: impl IntoIterator<Item = &'a SessionMeta>,
) -> Result<(), RecordError> {
    let mut ordered: Vec<&SessionMeta> = metas.into_iter().collect();
    ordered.sort_by(|left, right| left.run_id.0.cmp(&right.run_id.0));
    let mut staged = Vec::with_capacity(ordered.len());
    let mut bytes = Vec::new();
    for meta in ordered {
        let next = stage(runs_dir, meta, ContentReferenceSurface::SessionIndex)?;
        let physical_len = next.manifest.len().checked_add(1).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "session index line length overflow",
            )
        })?;
        if physical_len > crate::cache_io::MAX_INDEX_LINE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "session index manifest exceeds the cache byte limit",
            )
            .into());
        }
        bytes.extend_from_slice(&next.manifest);
        bytes.push(b'\n');
        staged.push(next);
    }
    crate::cache_io::atomic_replace(path, &bytes)?;
    for next in staged {
        next.commit()?;
    }
    Ok(())
}
