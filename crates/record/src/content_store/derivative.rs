//! Shared storage adapter for mutable, non-journal derivatives.

use super::{
    ContentReferenceSurface, ContentStoreError, PrivateContentClass, PrivateContentHandle,
    PrivateContentOwnerLease, PrivateContentRetention, acquire_private_content_owner,
    put_private_content_at_surface, retain_private_content_references,
};
use iteron_protocol::{ErasureContentDigest, RunId, Seq, TenantId};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A bounded handle-only derivative store sharing the record content revocation graph.
///
/// This holds the owner's read lease for its lifetime, so revocation cannot race content already
/// admitted to the derivative. Manifests persist only returned handles; hydration always re-enters
/// the tenant tombstone gate.
#[derive(Clone)]
pub struct PrivateContentDerivativeStore {
    runs_dir: PathBuf,
    tenant: TenantId,
    owner: RunId,
    surface: ContentReferenceSurface,
    class: PrivateContentClass,
    retention: PrivateContentRetention,
    max_bytes: usize,
    _owner_lease: Arc<PrivateContentOwnerLease>,
}

impl PrivateContentDerivativeStore {
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        runs_dir: impl Into<PathBuf>,
        tenant: TenantId,
        owner: RunId,
        surface: ContentReferenceSurface,
        class: PrivateContentClass,
        retention: PrivateContentRetention,
        max_bytes: usize,
    ) -> Result<Self, ContentStoreError> {
        if surface == ContentReferenceSurface::RecordField {
            return Err(ContentStoreError::InvalidDerivativeSurface);
        }
        if max_bytes == 0 || max_bytes > super::model::MAX_CONTENT_JSON_BYTES {
            return Err(ContentStoreError::InvalidDerivativeBound {
                max: super::model::MAX_CONTENT_JSON_BYTES,
            });
        }
        let runs_dir = runs_dir.into();
        let owner_lease = acquire_private_content_owner(&runs_dir, &tenant, &owner)?;
        Ok(Self {
            runs_dir,
            tenant,
            owner,
            surface,
            class,
            retention,
            max_bytes,
            _owner_lease: Arc::new(owner_lease),
        })
    }

    pub fn put(&self, seq: Seq, bytes: &[u8]) -> Result<PrivateContentHandle, ContentStoreError> {
        if bytes.len() > self.max_bytes {
            return Err(ContentStoreError::ContentTooLarge {
                max: self.max_bytes,
            });
        }
        put_private_content_at_surface(
            &self.runs_dir,
            &self.tenant,
            &self.owner,
            seq,
            self.class,
            self.surface,
            self.retention,
            bytes,
            0,
        )
    }

    pub fn read_at(
        &self,
        seq: Seq,
        handle: &PrivateContentHandle,
    ) -> Result<Vec<u8>, ContentStoreError> {
        let byte_len = usize::try_from(handle.byte_len)
            .map_err(|_| ContentStoreError::InvalidDerivativeHandle)?;
        if handle.class != self.class || byte_len > self.max_bytes {
            return Err(ContentStoreError::InvalidDerivativeHandle);
        }
        let bytes = super::read_private_content_at_reference(
            &self.runs_dir,
            &self.tenant,
            &self.owner,
            seq,
            self.surface,
            handle,
        )?;
        if bytes.len() != byte_len {
            return Err(ContentStoreError::InvalidDerivativeHandle);
        }
        Ok(bytes)
    }

    /// Reconcile one handle-only manifest after its atomic replacement.
    pub fn retain(
        &self,
        desired: &[(Seq, ErasureContentDigest)],
    ) -> Result<u32, ContentStoreError> {
        retain_private_content_references(
            &self.runs_dir,
            &self.tenant,
            &self.owner,
            self.surface,
            desired,
        )
    }

    pub fn owner(&self) -> &RunId {
        &self.owner
    }

    pub fn runs_dir(&self) -> &Path {
        &self.runs_dir
    }
}
