//! Durable, scoped public artifacts. Runtime producers and public clients share this owner.
//!
//! Public identity names the exact served bytes: scrubbed text or captured binary data.
//! Content handles participate in the
//! record owner's erasure and source-revocation graph. No client-supplied file locator is admitted.

mod captured_image;
mod material_provenance;
pub(crate) mod request_manifest;
mod storage;
mod structural;
#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};

use base64::Engine;
use iteron_protocol::client_artifact::{
    CLIENT_ARTIFACT_VERSION, ClientArtifactCommandV1, ClientArtifactDescriptorV1,
};
use iteron_protocol::{Capability, RunId, Seq, SessionId, TenantId};
use iteron_record::{
    MAX_PRIVATE_CONTENT_BYTES, PrivateContentClass, PrivateContentDerivativeStore,
    PrivateContentHandle, PrivateContentNamespace, PrivateContentRetention, PrivateContentSource,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const MAX_ARTIFACTS: usize = 256;
const MAX_CATALOG_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SOURCES: usize = 256;
const FIRST_SEQUENCE: u64 = 1_u64 << 62;
const LAST_SEQUENCE: u64 = 1_u64 << 63;

/// Authenticated host scope captured before genesis exists; every read verifies canonical metadata.
#[derive(Clone)]
pub(crate) struct ArtifactReadScope {
    runs: PathBuf,
    tenant: TenantId,
    run: RunId,
    workspace: PathBuf,
}

impl ArtifactReadScope {
    pub(crate) fn capture(runs: PathBuf, tenant: TenantId, run: RunId, workspace: PathBuf) -> Self {
        Self {
            runs,
            tenant,
            run,
            workspace,
        }
    }

    pub(crate) fn read(
        &self,
        authenticated_thread: &SessionId,
        command: ClientArtifactCommandV1,
    ) -> Result<Value, ArtifactStoreError> {
        DurableArtifactStore::open(
            &self.runs,
            self.tenant.clone(),
            self.run.clone(),
            &self.workspace,
        )?
        .read(authenticated_thread, command)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ArtifactSchema {
    ToolOutput,
    McpResult,
    FinalAnswer,
    FileDiff,
    FileSnapshot,
    CapturedReplacement,
    ProviderRequestBody,
    ProviderRequestManifest,
    ContextMaterialArchive,
    ViewportImage,
    ViewportImageObservation,
    BrowserObservation,
    DesktopObservation,
}

impl ArtifactSchema {
    fn schema(self) -> &'static str {
        match self {
            Self::ToolOutput => "iteron.tool-output.v1",
            Self::McpResult => "iteron.mcp-result.v1",
            Self::FinalAnswer => "iteron.final-answer.v1",
            Self::FileDiff => "iteron.file-diff.v1",
            Self::FileSnapshot => "iteron.file-snapshot.v1",
            Self::CapturedReplacement => "iteron.captured-replacement.v1",
            Self::ProviderRequestBody => "iteron.provider-request-body.v1",
            Self::ProviderRequestManifest => "iteron.provider-request-manifest.v1",
            Self::ContextMaterialArchive => "iteron.context-material-archive.v1",
            Self::ViewportImage => "iteron.viewport-image.v1",
            Self::ViewportImageObservation => "iteron.viewport-image-observation.v1",
            Self::BrowserObservation => "iteron.browser-observation.v1",
            Self::DesktopObservation => "iteron.desktop-observation.v1",
        }
    }

    fn mime_type(self) -> &'static str {
        match self {
            Self::ViewportImage => "image/png",
            _ => "text/plain; charset=utf-8",
        }
    }

    fn namespace(self) -> (PrivateContentNamespace, PrivateContentClass) {
        match self {
            Self::ToolOutput
            | Self::McpResult
            | Self::ViewportImage
            | Self::ViewportImageObservation => (
                PrivateContentNamespace::ToolArtifact,
                PrivateContentClass::ToolOutput,
            ),
            Self::BrowserObservation | Self::DesktopObservation => (
                PrivateContentNamespace::ToolArtifact,
                PrivateContentClass::ToolOutput,
            ),
            Self::FinalAnswer
            | Self::FileDiff
            | Self::FileSnapshot
            | Self::CapturedReplacement
            | Self::ProviderRequestBody
            | Self::ProviderRequestManifest
            | Self::ContextMaterialArchive => {
                (PrivateContentNamespace::Export, PrivateContentClass::Export)
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ArtifactStoreError {
    Scope,
    Unavailable,
    PublicationUnknown,
    Corrupt,
    Capacity,
    InvalidRequest,
}

impl std::fmt::Display for ArtifactStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Scope => "artifact unavailable in this authenticated workspace",
            Self::Unavailable => "artifact store unavailable or busy",
            Self::PublicationUnknown => {
                "artifact publication outcome unknown; reopen the retained owner catalog"
            }
            Self::Corrupt => "artifact integrity verification failed",
            Self::Capacity => "artifact exceeds the retained content quota",
            Self::InvalidRequest => "artifact request exceeds its bounded contract",
        })
    }
}

#[derive(Clone)]
pub(crate) struct DurableArtifactStore {
    runs: PathBuf,
    tenant: TenantId,
    run: RunId,
    workspace: PathBuf,
    workspace_digest: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    tenant: TenantId,
    run: RunId,
    workspace_digest: String,
    next_sequence: u64,
    evicted: u64,
    entries: Vec<Entry>,
    // Prepared before CAS publication. Restart discards an incomplete publication by exact ref.
    pending: Option<ContentRef>,
    // Persist removal before releasing references; retrying release is idempotent after a crash.
    releasing: Vec<ContentRef>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    descriptor: ClientArtifactDescriptorV1,
    content: ContentRef,
    #[serde(default)]
    dependencies: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContentRef {
    sequence: u64,
    schema: ArtifactSchema,
    handle: PrivateContentHandle,
}

impl DurableArtifactStore {
    /// The runtime writer already holds the authenticated Rollout and an actual durable effect
    /// ticket. Capture that immutable authority once; never replay the complete WAL per physical
    /// request. Public readers still use `open` and its independently verified metadata gates.
    pub(crate) fn from_rollout_writer(
        rollout: &iteron_record::Rollout,
        workspace: &Path,
    ) -> Result<Self, ArtifactStoreError> {
        let runs = rollout
            .path()
            .parent()
            .ok_or(ArtifactStoreError::Scope)?
            .canonicalize()
            .map_err(|_| ArtifactStoreError::Scope)?;
        let workspace = workspace
            .canonicalize()
            .map_err(|_| ArtifactStoreError::Scope)?;
        Ok(Self {
            workspace_digest: hex::encode(Sha256::digest(workspace.to_string_lossy().as_bytes())),
            runs,
            tenant: rollout.tenant().clone(),
            run: rollout.run_id().clone(),
            workspace,
        })
    }

    /// Inputs come only from the authenticated runtime/rollout owner, never from wire JSON.
    pub(crate) fn open(
        runs_dir: &Path,
        tenant: TenantId,
        run: RunId,
        workspace: &Path,
    ) -> Result<Self, ArtifactStoreError> {
        let canonical = workspace
            .canonicalize()
            .map_err(|_| ArtifactStoreError::Scope)?;
        let meta =
            iteron_record::session::meta(runs_dir, &run).map_err(|_| ArtifactStoreError::Scope)?;
        if meta.tenant != tenant
            || Path::new(&meta.cwd).canonicalize().ok().as_ref() != Some(&canonical)
        {
            return Err(ArtifactStoreError::Scope);
        }
        Ok(Self {
            runs: runs_dir
                .canonicalize()
                .map_err(|_| ArtifactStoreError::Scope)?,
            tenant,
            run,
            workspace_digest: hex::encode(Sha256::digest(canonical.to_string_lossy().as_bytes())),
            workspace: canonical,
        })
    }

    fn empty_manifest(&self) -> Manifest {
        Manifest {
            version: CLIENT_ARTIFACT_VERSION,
            tenant: self.tenant.clone(),
            run: self.run.clone(),
            workspace_digest: self.workspace_digest.clone(),
            next_sequence: FIRST_SEQUENCE,
            evicted: 0,
            entries: Vec::new(),
            pending: None,
            releasing: Vec::new(),
        }
    }

    fn private(
        &self,
        schema: ArtifactSchema,
    ) -> Result<PrivateContentDerivativeStore, ArtifactStoreError> {
        let (namespace, class) = schema.namespace();
        PrivateContentDerivativeStore::open_registered(
            &self.runs,
            self.tenant.clone(),
            self.run.clone(),
            namespace,
            class,
            PrivateContentRetention::Session,
            MAX_PRIVATE_CONTENT_BYTES,
        )
        .map_err(|_error| {
            #[cfg(test)]
            eprintln!("artifact CAS owner admission failed: {_error}");
            ArtifactStoreError::Unavailable
        })
    }

    fn validate_manifest(&self, manifest: &Manifest) -> Result<(), ArtifactStoreError> {
        if manifest.version != CLIENT_ARTIFACT_VERSION
            || manifest.tenant != self.tenant
            || manifest.run != self.run
            || manifest.workspace_digest != self.workspace_digest
            || manifest.entries.len() > MAX_ARTIFACTS
            || manifest.releasing.len() > MAX_ARTIFACTS
            || (manifest.pending.is_some() && !manifest.releasing.is_empty())
            || !(FIRST_SEQUENCE..LAST_SEQUENCE).contains(&manifest.next_sequence)
            || catalog_bytes(&manifest.entries)? > MAX_CATALOG_BYTES
        {
            return Err(ArtifactStoreError::Corrupt);
        }
        let mut identities = std::collections::BTreeSet::new();
        for entry in &manifest.entries {
            if !identities.insert(&entry.descriptor.artifact_id)
                || entry.descriptor.source_event_seq == 0
                || entry.descriptor.bytes != u64::from(entry.content.handle.byte_len)
                || entry.descriptor.bytes as usize > MAX_PRIVATE_CONTENT_BYTES
                || entry.content.handle.digest.as_str()
                    != format!("sha256:{}", entry.descriptor.artifact_id)
                || entry.descriptor.schema != entry.content.schema.schema()
                || entry.descriptor.required_capability != Capability::ReadOnly
                || !entry.descriptor.complete
                || entry.descriptor.mime_type != entry.content.schema.mime_type()
            {
                return Err(ArtifactStoreError::Corrupt);
            }
            validate_reference(&entry.content, manifest.next_sequence)?;
        }
        for reference in manifest.pending.iter().chain(&manifest.releasing) {
            validate_reference(reference, manifest.next_sequence)?;
        }
        for entry in &manifest.entries {
            let unique = entry
                .dependencies
                .iter()
                .collect::<std::collections::BTreeSet<_>>();
            if unique.len() != entry.dependencies.len() || unique.len() > MAX_SOURCES {
                return Err(ArtifactStoreError::Corrupt);
            }
            for dependency in &entry.dependencies {
                if manifest.entries.iter().all(|source| {
                    source.descriptor.artifact_id != *dependency
                        || source.content.sequence >= entry.content.sequence
                }) {
                    return Err(ArtifactStoreError::Corrupt);
                }
            }
        }
        Ok(())
    }

    fn recover(
        &self,
        manifest: &mut Manifest,
        file: &storage::ManifestFile,
    ) -> Result<(), ArtifactStoreError> {
        if let Some(pending) = manifest.pending.take() {
            manifest.releasing.push(pending);
            file.write(manifest)?;
        }
        if manifest.releasing.is_empty() {
            return Ok(());
        }
        for reference in &manifest.releasing {
            self.private(reference.schema)?
                .release(Seq(reference.sequence), &reference.handle.digest)
                .map_err(|_error| {
                    #[cfg(test)]
                    eprintln!("artifact CAS retention release failed: {_error}");
                    ArtifactStoreError::Unavailable
                })?;
        }
        manifest.releasing.clear();
        file.write(manifest)
    }

    /// Publish complete text before a producer applies preview/truncation. Scrubbing is owned here.
    /// Sources must be real retained private handles; fabricated content hashes are rejected by CAS.
    pub(crate) fn publish_text(
        &self,
        source_event_seq: u64,
        schema: ArtifactSchema,
        text: &str,
        sources: &[PrivateContentSource],
    ) -> Result<ClientArtifactDescriptorV1, ArtifactStoreError> {
        if text.len() > MAX_PRIVATE_CONTENT_BYTES || sources.len() > MAX_SOURCES {
            return Err(ArtifactStoreError::Capacity);
        }
        if matches!(schema, ArtifactSchema::ViewportImage) {
            return Err(ArtifactStoreError::InvalidRequest);
        }
        let served = iteron_record::redact::scrub(text);
        self.publish_served(source_event_seq, schema, &served, sources, &[])
    }

    fn publish_served(
        &self,
        source_event_seq: u64,
        schema: ArtifactSchema,
        served: &str,
        sources: &[PrivateContentSource],
        dependencies: &[ClientArtifactDescriptorV1],
    ) -> Result<ClientArtifactDescriptorV1, ArtifactStoreError> {
        if matches!(schema, ArtifactSchema::ViewportImage) {
            return Err(ArtifactStoreError::InvalidRequest);
        }
        self.publish_bytes(
            source_event_seq,
            schema,
            served.as_bytes(),
            sources,
            dependencies,
        )
    }

    fn publish_bytes(
        &self,
        source_event_seq: u64,
        schema: ArtifactSchema,
        served: &[u8],
        sources: &[PrivateContentSource],
        dependencies: &[ClientArtifactDescriptorV1],
    ) -> Result<ClientArtifactDescriptorV1, ArtifactStoreError> {
        if source_event_seq == 0 {
            return Err(ArtifactStoreError::InvalidRequest);
        }
        if served.len() > MAX_PRIVATE_CONTENT_BYTES
            || sources.len().saturating_add(dependencies.len()) > MAX_SOURCES
        {
            return Err(ArtifactStoreError::Capacity);
        }
        let artifact_id = hex::encode(Sha256::digest(served));
        let file =
            storage::ManifestFile::acquire(self, true)?.ok_or(ArtifactStoreError::Unavailable)?;
        let mut manifest = file.read()?.unwrap_or_else(|| self.empty_manifest());
        self.validate_manifest(&manifest)?;
        self.recover(&mut manifest, &file)?;
        let mut private_sources = sources.to_vec();
        let mut dependency_ids = std::collections::BTreeSet::new();
        for descriptor in dependencies {
            let entry = manifest
                .entries
                .iter()
                .find(|entry| entry.descriptor == *descriptor)
                .ok_or(ArtifactStoreError::Unavailable)?;
            self.bytes(entry)?;
            if dependency_ids.insert(descriptor.artifact_id.clone()) {
                private_sources.push(PrivateContentSource {
                    owner: self.run.clone(),
                    digest: entry.content.handle.digest.clone(),
                });
            }
        }
        if let Some(entry) = manifest
            .entries
            .iter()
            .find(|entry| entry.descriptor.artifact_id == artifact_id)
        {
            self.bytes(entry)?;
            // Identity addresses served bytes, so repeated bytes return the first retained
            // publication. This is a lookup receipt: never relabel its schema/source as the
            // later producer or silently rebind the original revocation lineage.
            return Ok(entry.descriptor.clone());
        }
        while manifest.entries.len() >= MAX_ARTIFACTS
            || catalog_bytes(&manifest.entries)?.saturating_add(served.len() as u64)
                > MAX_CATALOG_BYTES
        {
            let evicted = manifest
                .entries
                .iter()
                .map(|entry| eviction_set(&manifest.entries, &entry.descriptor.artifact_id))
                .find(|ids| ids.is_disjoint(&dependency_ids))
                .ok_or(ArtifactStoreError::Capacity)?;
            let mut kept = Vec::with_capacity(manifest.entries.len());
            for entry in manifest.entries.drain(..) {
                if evicted.contains(&entry.descriptor.artifact_id) {
                    manifest.releasing.push(entry.content);
                    manifest.evicted = manifest.evicted.saturating_add(1);
                } else {
                    kept.push(entry);
                }
            }
            manifest.entries = kept;
        }
        if !manifest.releasing.is_empty() {
            file.write(&manifest)?;
            self.recover(&mut manifest, &file)?;
        }
        let sequence = manifest.next_sequence;
        manifest.next_sequence = sequence
            .checked_add(1)
            .filter(|next| *next < LAST_SEQUENCE)
            .ok_or(ArtifactStoreError::Capacity)?;
        let reference = ContentRef {
            sequence,
            schema,
            handle: PrivateContentHandle {
                digest: iteron_protocol::ErasureContentDigest::new(format!("sha256:{artifact_id}"))
                    .map_err(|_| ArtifactStoreError::Corrupt)?,
                byte_len: served.len() as u32,
                class: schema.namespace().1,
                preview: None,
            },
        };
        manifest.pending = Some(reference.clone());
        file.write(&manifest)?;
        let private = self.private(schema)?;
        let handle = private
            .put_derived(Seq(sequence), served, &private_sources)
            .map_err(|_error| {
                #[cfg(test)]
                eprintln!("artifact CAS retained publication failed: {_error}");
                ArtifactStoreError::Unavailable
            })?;
        if handle != reference.handle
            || private
                .read_at(Seq(sequence), &handle)
                .map_err(|_| ArtifactStoreError::Corrupt)?
                != served
        {
            return Err(ArtifactStoreError::Corrupt);
        }
        let descriptor = ClientArtifactDescriptorV1 {
            artifact_id,
            schema: schema.schema().into(),
            mime_type: schema.mime_type().into(),
            bytes: served.len() as u64,
            complete: true,
            required_capability: Capability::ReadOnly,
            source_event_seq,
        };
        manifest.entries.push(Entry {
            descriptor: descriptor.clone(),
            content: reference,
            dependencies: dependency_ids.into_iter().collect(),
        });
        manifest.pending = None;
        file.write(&manifest)?;
        Ok(descriptor)
    }

    fn bytes(&self, entry: &Entry) -> Result<Vec<u8>, ArtifactStoreError> {
        let bytes = self
            .private(entry.content.schema)?
            .read_at(Seq(entry.content.sequence), &entry.content.handle)
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        if hex::encode(Sha256::digest(&bytes)) != entry.descriptor.artifact_id {
            return Err(ArtifactStoreError::Corrupt);
        }
        Ok(bytes)
    }

    pub(crate) fn read(
        &self,
        authenticated_thread: &SessionId,
        command: ClientArtifactCommandV1,
    ) -> Result<Value, ArtifactStoreError> {
        command
            .validate()
            .map_err(|_| ArtifactStoreError::InvalidRequest)?;
        if command.thread_id() != authenticated_thread {
            return Err(ArtifactStoreError::Scope);
        }
        let Some(file) = storage::ManifestFile::acquire(self, false)? else {
            return match command {
                ClientArtifactCommandV1::List { .. } => Ok(listing(&[], 0)),
                ClientArtifactCommandV1::Read { .. } => Err(ArtifactStoreError::Unavailable),
            };
        };
        let manifest = file.read()?.ok_or(ArtifactStoreError::Unavailable)?;
        self.validate_manifest(&manifest)?;
        // Read-only clients never repair state. Pending publications are unpublished; releasing
        // entries have already left the catalog. The next trusted producer retries cleanup.
        match command {
            ClientArtifactCommandV1::List { .. } => {
                let entries = manifest
                    .entries
                    .iter()
                    .filter(|entry| self.bytes(entry).is_ok())
                    .map(|entry| entry.descriptor.clone())
                    .collect::<Vec<_>>();
                Ok(listing(&entries, manifest.evicted))
            }
            ClientArtifactCommandV1::Read {
                artifact_id,
                offset,
                max_bytes,
                ..
            } => {
                let entry = manifest
                    .entries
                    .iter()
                    .find(|entry| entry.descriptor.artifact_id == artifact_id)
                    .ok_or(ArtifactStoreError::Unavailable)?;
                let bytes = self.bytes(entry)?;
                let start =
                    usize::try_from(offset).map_err(|_| ArtifactStoreError::InvalidRequest)?;
                if start > bytes.len() {
                    return Err(ArtifactStoreError::InvalidRequest);
                }
                let end = start.saturating_add(max_bytes as usize).min(bytes.len());
                Ok(json!({
                    "type":"artifact_chunk_v1", "contract_version":CLIENT_ARTIFACT_VERSION,
                    "artifact":entry.descriptor, "offset":offset, "next_offset":end,
                    "eof":end == bytes.len(), "provenance":"retained_owner_manifest",
                    "retention":"session", "content_base64":base64::engine::general_purpose::STANDARD.encode(&bytes[start..end]),
                }))
            }
        }
    }
}

fn eviction_set(entries: &[Entry], first: &str) -> std::collections::BTreeSet<String> {
    let mut removed = std::collections::BTreeSet::from([first.to_owned()]);
    for _ in 0..MAX_ARTIFACTS {
        let before = removed.len();
        for entry in entries {
            if entry.dependencies.iter().any(|id| removed.contains(id)) {
                removed.insert(entry.descriptor.artifact_id.clone());
            }
        }
        if removed.len() == before {
            break;
        }
    }
    removed
}

fn catalog_bytes(entries: &[Entry]) -> Result<u64, ArtifactStoreError> {
    entries.iter().try_fold(0_u64, |total, entry| {
        total
            .checked_add(entry.descriptor.bytes)
            .ok_or(ArtifactStoreError::Corrupt)
    })
}

fn validate_reference(reference: &ContentRef, next: u64) -> Result<(), ArtifactStoreError> {
    if !(FIRST_SEQUENCE..next).contains(&reference.sequence)
        || reference.handle.class != reference.schema.namespace().1
        || reference.handle.byte_len as usize > MAX_PRIVATE_CONTENT_BYTES
    {
        return Err(ArtifactStoreError::Corrupt);
    }
    Ok(())
}

fn listing(entries: &[ClientArtifactDescriptorV1], evicted: u64) -> Value {
    json!({"type":"artifacts_v1", "contract_version":CLIENT_ARTIFACT_VERSION,
        "artifacts":entries, "evicted_artifacts":evicted,
        "retention":"session", "provenance":"retained_owner_manifest"})
}

/// Erasure's verified record receipt is the authority for removing the handle-only public index.
pub(crate) fn remove_erased_catalog(
    runs: &Path,
    receipt: &iteron_protocol::ErasureReceipt,
) -> Result<(), ArtifactStoreError> {
    if receipt.state() != iteron_protocol::ErasureState::Verified {
        return Err(ArtifactStoreError::Scope);
    }
    let iteron_protocol::ErasureTarget::ExactSession { scope_id, run_id } =
        &receipt.request().target
    else {
        return Err(ArtifactStoreError::Scope);
    };
    storage::remove_catalog(
        runs,
        &TenantId(scope_id.as_str().into()),
        &RunId(run_id.as_str().into()),
    )
}
