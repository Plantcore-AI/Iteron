//! Durable, scoped public artifacts. Runtime producers and public clients share this owner.
//!
//! Public identity names the scrubbed bytes actually served. Content handles participate in the
//! record owner's erasure and source-revocation graph. No client-supplied file locator is admitted.

mod storage;
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
pub(crate) enum ArtifactTextSchema {
    ToolOutput,
    FinalAnswer,
    FileDiff,
    CapturedReplacement,
}

impl ArtifactTextSchema {
    fn schema(self) -> &'static str {
        match self {
            Self::ToolOutput => "iteron.tool-output.v1",
            Self::FinalAnswer => "iteron.final-answer.v1",
            Self::FileDiff => "iteron.file-diff.v1",
            Self::CapturedReplacement => "iteron.captured-replacement.v1",
        }
    }

    fn namespace(self) -> (PrivateContentNamespace, PrivateContentClass) {
        match self {
            Self::ToolOutput => (
                PrivateContentNamespace::ToolArtifact,
                PrivateContentClass::ToolOutput,
            ),
            Self::FinalAnswer | Self::FileDiff | Self::CapturedReplacement => {
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
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContentRef {
    sequence: u64,
    schema: ArtifactTextSchema,
    handle: PrivateContentHandle,
}

impl DurableArtifactStore {
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
        schema: ArtifactTextSchema,
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
        .map_err(|_| ArtifactStoreError::Unavailable)
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
                || entry.descriptor.mime_type != "text/plain; charset=utf-8"
            {
                return Err(ArtifactStoreError::Corrupt);
            }
            validate_reference(&entry.content, manifest.next_sequence)?;
        }
        for reference in manifest.pending.iter().chain(&manifest.releasing) {
            validate_reference(reference, manifest.next_sequence)?;
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
                .map_err(|_| ArtifactStoreError::Unavailable)?;
        }
        manifest.releasing.clear();
        file.write(manifest)
    }

    /// Publish complete text before a producer applies preview/truncation. Scrubbing is owned here.
    /// Sources must be real retained private handles; fabricated content hashes are rejected by CAS.
    pub(crate) fn publish_text(
        &self,
        source_event_seq: u64,
        schema: ArtifactTextSchema,
        text: &str,
        sources: &[PrivateContentSource],
    ) -> Result<ClientArtifactDescriptorV1, ArtifactStoreError> {
        if source_event_seq == 0 {
            return Err(ArtifactStoreError::InvalidRequest);
        }
        if text.len() > MAX_PRIVATE_CONTENT_BYTES || sources.len() > MAX_SOURCES {
            return Err(ArtifactStoreError::Capacity);
        }
        let served = iteron_record::redact::scrub(text);
        if served.len() > MAX_PRIVATE_CONTENT_BYTES {
            return Err(ArtifactStoreError::Capacity);
        }
        let artifact_id = hex::encode(Sha256::digest(served.as_bytes()));
        let file =
            storage::ManifestFile::acquire(self, true)?.ok_or(ArtifactStoreError::Unavailable)?;
        let mut manifest = file.read()?.unwrap_or_else(|| self.empty_manifest());
        self.validate_manifest(&manifest)?;
        self.recover(&mut manifest, &file)?;
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
            let entry = manifest.entries.remove(0);
            manifest.releasing.push(entry.content);
            manifest.evicted = manifest.evicted.saturating_add(1);
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
            .put_derived(Seq(sequence), served.as_bytes(), sources)
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        if handle != reference.handle
            || private
                .read_at(Seq(sequence), &handle)
                .map_err(|_| ArtifactStoreError::Corrupt)?
                != served.as_bytes()
        {
            return Err(ArtifactStoreError::Corrupt);
        }
        let descriptor = ClientArtifactDescriptorV1 {
            artifact_id,
            schema: schema.schema().into(),
            mime_type: "text/plain; charset=utf-8".into(),
            bytes: served.len() as u64,
            complete: true,
            required_capability: Capability::ReadOnly,
            source_event_seq,
        };
        manifest.entries.push(Entry {
            descriptor: descriptor.clone(),
            content: reference,
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
