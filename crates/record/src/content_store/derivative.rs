//! Shared storage adapter for mutable, non-journal derivatives.

use super::coverage::{ReadGateRegistration, WriterRegistration};
use super::model::ReferenceEdge;
use super::storage::Layout;
use super::{
    ContentReferenceSurface, ContentStoreError, PrivateContentClass, PrivateContentHandle,
    PrivateContentNamespace, PrivateContentOwnerLease, PrivateContentRetention,
    PrivateContentSource, acquire_private_content_owner, private_content_sources_for_run,
    put_private_content_at_surface, put_private_content_at_surface_with_sources,
    references::release_private_content_reference, retain_private_content_references,
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
    namespace: PrivateContentNamespace,
    surface: ContentReferenceSurface,
    class: PrivateContentClass,
    retention: PrivateContentRetention,
    max_bytes: usize,
    _owner_lease: Arc<PrivateContentOwnerLease>,
}

impl PrivateContentDerivativeStore {
    #[allow(clippy::too_many_arguments)]
    pub fn open_registered(
        runs_dir: impl Into<PathBuf>,
        tenant: TenantId,
        owner: RunId,
        namespace: PrivateContentNamespace,
        class: PrivateContentClass,
        retention: PrivateContentRetention,
        max_bytes: usize,
    ) -> Result<Self, ContentStoreError> {
        let registration = registered_writer(namespace)
            .filter(|registration| registration.derivative_class() == Some(class))
            .ok_or(ContentStoreError::InvalidDerivativeHandle)?;
        debug_assert_eq!(registration.namespace(), namespace);
        Self::open_surface(
            runs_dir, tenant, owner, namespace, class, retention, max_bytes,
        )
    }

    #[cfg(test)]
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
        let namespace = PrivateContentNamespace::from_surface(surface)
            .ok_or(ContentStoreError::InvalidDerivativeSurface)?;
        Self::open_surface(
            runs_dir, tenant, owner, namespace, class, retention, max_bytes,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn open_surface(
        runs_dir: impl Into<PathBuf>,
        tenant: TenantId,
        owner: RunId,
        namespace: PrivateContentNamespace,
        class: PrivateContentClass,
        retention: PrivateContentRetention,
        max_bytes: usize,
    ) -> Result<Self, ContentStoreError> {
        let surface = namespace.surface();
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
            namespace,
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

    /// Materialize a derivative while durably binding every source handle before the caller can
    /// publish its manifest. Reads subsequently re-check these edges and source revocation walks
    /// them transitively, so a copied value cannot outlive the authority of its inputs.
    pub fn put_derived(
        &self,
        seq: Seq,
        bytes: &[u8],
        sources: &[PrivateContentSource],
    ) -> Result<PrivateContentHandle, ContentStoreError> {
        if bytes.len() > self.max_bytes {
            return Err(ContentStoreError::ContentTooLarge {
                max: self.max_bytes,
            });
        }
        put_private_content_at_surface_with_sources(
            &self.runs_dir,
            &self.tenant,
            &self.owner,
            seq,
            self.class,
            self.surface,
            self.retention,
            bytes,
            0,
            sources,
        )
    }

    /// Bind a derivative to all record-field handles physically owned by one source run.
    pub fn put_derived_from_run(
        &self,
        seq: Seq,
        bytes: &[u8],
        source_run: &RunId,
    ) -> Result<PrivateContentHandle, ContentStoreError> {
        let sources = private_content_sources_for_run(&self.runs_dir, &self.tenant, source_run)?;
        self.put_derived(seq, bytes, &sources)
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

    /// Return the exact, durably registered lineage sources for a manifest entry.
    ///
    /// This is used by mutable manifests which persist source identity for later full-state
    /// rewrites. Revalidating the durable graph prevents a modified manifest from relabelling a
    /// derivative as if it came from a different still-live source.
    pub fn sources_at(
        &self,
        seq: Seq,
        handle: &PrivateContentHandle,
    ) -> Result<Vec<PrivateContentSource>, ContentStoreError> {
        super::private_content_sources_at_reference(
            &self.runs_dir,
            &self.tenant,
            &self.owner,
            seq,
            self.surface,
            handle,
        )
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

    /// Idempotently release one exact handle while preserving every other manifest/reference on
    /// the same surface.
    pub fn release(
        &self,
        seq: Seq,
        digest: &ErasureContentDigest,
    ) -> Result<bool, ContentStoreError> {
        release_private_content_reference(
            &self.runs_dir,
            &self.tenant,
            &self.owner,
            self.surface,
            seq,
            digest,
        )
    }

    pub fn owner(&self) -> &RunId {
        &self.owner
    }

    pub fn namespace(&self) -> PrivateContentNamespace {
        self.namespace
    }

    pub fn runs_dir(&self) -> &Path {
        &self.runs_dir
    }
}

/// Registration is owned by the production derivative adapter, not the erasure receipt builder.
/// Adding an enum variant or passing a class used by another namespace therefore yields no token.
pub(super) const fn registered_writer(
    namespace: PrivateContentNamespace,
) -> Option<WriterRegistration> {
    let class = match namespace {
        PrivateContentNamespace::SessionProjection => PrivateContentClass::SessionProjection,
        PrivateContentNamespace::SessionIndex => PrivateContentClass::SessionIndex,
        PrivateContentNamespace::PromptHistory => PrivateContentClass::Transcript,
        PrivateContentNamespace::Attachment => PrivateContentClass::Attachment,
        PrivateContentNamespace::ToolArtifact => PrivateContentClass::ToolOutput,
        PrivateContentNamespace::Export => PrivateContentClass::Export,
        PrivateContentNamespace::Trajectory => PrivateContentClass::Trajectory,
        PrivateContentNamespace::Dataset => PrivateContentClass::Dataset,
        PrivateContentNamespace::EvaluatorInput => PrivateContentClass::EvaluatorInput,
        PrivateContentNamespace::CandidateStore => PrivateContentClass::Candidate,
        PrivateContentNamespace::Checkpoint | PrivateContentNamespace::MemoryContext => {
            return None;
        }
    };
    Some(WriterRegistration::derivative(namespace, class))
}

pub(super) fn registered_read_gate(writer: WriterRegistration) -> Option<ReadGateRegistration> {
    registered_writer(writer.namespace())
        .filter(|registered| registered.derivative_class() == writer.derivative_class())
        .map(|_| ReadGateRegistration::new(writer, verify_derivative_read_gate))
}

fn verify_derivative_read_gate(
    layout: &Layout,
    edge: &ReferenceEdge,
    class: Option<PrivateContentClass>,
) -> Result<Vec<u8>, ContentStoreError> {
    let class = class.ok_or(ContentStoreError::InvalidDerivativeHandle)?;
    let handle = PrivateContentHandle {
        digest: edge.digest.clone(),
        byte_len: 0,
        class,
        preview: None,
    };
    super::read_private_content_at_reference_locked(
        layout,
        &edge.run_id,
        Seq(edge.seq),
        edge.surface,
        &handle,
    )
}
