//! Durable handle-only manifests for content-bearing offline-evolution derivatives.
//!
//! The evolution control plane remains offline and non-authoritative, but its datasets,
//! evaluator inputs, and candidate artifacts are still copies of revocable record content.  This
//! adapter keeps only a bounded private-content handle in the evolution tree and forces every
//! consumer back through the record tombstone and lineage gate.

use crate::verifier_crypto::sha256_hex;
use iteron_protocol::{ErasureContentDigest, RunId, Seq, TenantId};
use iteron_record::{
    PrivateContentClass, PrivateContentDerivativeStore, PrivateContentHandle,
    PrivateContentNamespace, PrivateContentRetention, PrivateContentSource,
};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const MANIFEST_SCHEMA_VERSION: u16 = 1;
const MAX_MANIFEST_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EvolutionDerivativeKind {
    Dataset,
    EvaluatorInput,
    Candidate,
}

impl EvolutionDerivativeKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Dataset => "dataset",
            Self::EvaluatorInput => "evaluator-input",
            Self::Candidate => "candidate",
        }
    }

    const fn namespace(self) -> PrivateContentNamespace {
        match self {
            Self::Dataset => PrivateContentNamespace::Dataset,
            Self::EvaluatorInput => PrivateContentNamespace::EvaluatorInput,
            Self::Candidate => PrivateContentNamespace::CandidateStore,
        }
    }

    const fn class(self) -> PrivateContentClass {
        match self {
            Self::Dataset => PrivateContentClass::Dataset,
            Self::EvaluatorInput => PrivateContentClass::EvaluatorInput,
            Self::Candidate => PrivateContentClass::Candidate,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredDerivativeManifest {
    schema_version: u16,
    kind: EvolutionDerivativeKind,
    key_digest: String,
    tenant_id: TenantId,
    owner: RunId,
    sequence: u64,
    handle: PrivateContentHandle,
}

#[derive(Debug, Clone)]
pub(crate) struct EvolutionPrivateContent {
    manifest_root: PathBuf,
    content_runs_dir: PathBuf,
    tenant_id: TenantId,
}

#[derive(Debug, thiserror::Error)]
pub enum EvolutionPrivateContentError {
    #[error("private evolution content storage failed: {0}")]
    Content(#[from] iteron_record::ContentStoreError),
    #[error("private evolution manifest I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("private evolution manifest JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("private evolution content key must be a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("private evolution content does not belong to the configured tenant")]
    TenantMismatch,
    #[error("private evolution manifest is missing for {kind}/{digest}")]
    MissingManifest { kind: &'static str, digest: String },
    #[error("private evolution manifest is malformed or conflicts with its content address")]
    InvalidManifest,
    #[error("private evolution manifest path is a symlink or unexpected file kind: {0}")]
    InvalidPath(PathBuf),
    #[error("private evolution content digest does not match its governed identity")]
    ContentDigestMismatch,
}

impl EvolutionPrivateContent {
    pub(crate) fn open(
        manifest_root: impl Into<PathBuf>,
        content_runs_dir: impl Into<PathBuf>,
        tenant_id: TenantId,
    ) -> Result<Self, EvolutionPrivateContentError> {
        let manifest_root = manifest_root.into();
        let content_runs_dir = content_runs_dir.into();
        prepare_directory(&manifest_root)?;
        Ok(Self {
            manifest_root,
            content_runs_dir,
            tenant_id,
        })
    }

    pub(crate) fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub(crate) fn store(
        &self,
        kind: EvolutionDerivativeKind,
        key_digest: &str,
        bytes: &[u8],
        sources: &[PrivateContentSource],
    ) -> Result<(), EvolutionPrivateContentError> {
        validate_digest(key_digest)?;
        let actual = sha256_hex(bytes);
        if actual != key_digest {
            return Err(EvolutionPrivateContentError::ContentDigestMismatch);
        }
        let owner = owner_for(kind, key_digest);
        let sequence = Seq(0);
        let store = self.derivative_store(kind, owner.clone(), bytes.len().max(1))?;
        let handle = if sources.is_empty() {
            store.put(sequence, bytes)?
        } else {
            store.put_derived(sequence, bytes, sources)?
        };
        if handle.digest.as_str() != format!("sha256:{key_digest}") {
            let _ = store.release(sequence, &handle.digest);
            return Err(EvolutionPrivateContentError::ContentDigestMismatch);
        }
        let manifest = StoredDerivativeManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            kind,
            key_digest: key_digest.to_owned(),
            tenant_id: self.tenant_id.clone(),
            owner,
            sequence: sequence.0,
            handle: handle.clone(),
        };
        if let Err(error) = self.publish_manifest(&manifest) {
            let _ = store.release(sequence, &handle.digest);
            return Err(error);
        }
        Ok(())
    }

    /// Hydrate through the content tombstone and transitive-source gate.
    pub(crate) fn read(
        &self,
        kind: EvolutionDerivativeKind,
        key_digest: &str,
    ) -> Result<Vec<u8>, EvolutionPrivateContentError> {
        let manifest = self.load_manifest(kind, key_digest)?;
        let max_bytes = usize::try_from(manifest.handle.byte_len)
            .map_err(|_| EvolutionPrivateContentError::InvalidManifest)?
            .max(1);
        let store = self.derivative_store(kind, manifest.owner.clone(), max_bytes)?;
        let bytes = store.read_at(Seq(manifest.sequence), &manifest.handle)?;
        if sha256_hex(&bytes) != key_digest {
            return Err(EvolutionPrivateContentError::ContentDigestMismatch);
        }
        Ok(bytes)
    }

    /// Resolve a gated derivative as a source for the next materialization.
    pub(crate) fn source(
        &self,
        kind: EvolutionDerivativeKind,
        key_digest: &str,
    ) -> Result<PrivateContentSource, EvolutionPrivateContentError> {
        // Reading first is intentional: merely finding a stale handle must not authorize a new
        // descendant after its source was revoked.
        drop(self.read(kind, key_digest)?);
        let manifest = self.load_manifest(kind, key_digest)?;
        Ok(PrivateContentSource {
            owner: manifest.owner,
            digest: manifest.handle.digest,
        })
    }

    fn derivative_store(
        &self,
        kind: EvolutionDerivativeKind,
        owner: RunId,
        max_bytes: usize,
    ) -> Result<PrivateContentDerivativeStore, EvolutionPrivateContentError> {
        Ok(PrivateContentDerivativeStore::open_registered(
            &self.content_runs_dir,
            self.tenant_id.clone(),
            owner,
            kind.namespace(),
            kind.class(),
            PrivateContentRetention::ExplicitRevocation,
            max_bytes.min(iteron_record::MAX_PRIVATE_CONTENT_BYTES),
        )?)
    }

    fn publish_manifest(
        &self,
        manifest: &StoredDerivativeManifest,
    ) -> Result<(), EvolutionPrivateContentError> {
        let directory = self.kind_directory(manifest.kind)?;
        let path = directory.join(format!("{}.json", manifest.key_digest));
        let bytes = serde_json::to_vec(manifest)?;
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(EvolutionPrivateContentError::InvalidManifest);
        }
        if path.exists() {
            let existing = read_limited(&path)?;
            return if existing == bytes {
                Ok(())
            } else {
                Err(EvolutionPrivateContentError::InvalidManifest)
            };
        }

        let temporary = directory.join(format!(
            ".{}.{}.tmp",
            manifest.key_digest,
            std::process::id()
        ));
        reject_symlink(&temporary)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            match std::fs::hard_link(&temporary, &path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if read_limited(&path)? != bytes {
                        return Err(EvolutionPrivateContentError::InvalidManifest);
                    }
                }
                Err(error) => return Err(error.into()),
            }
            Ok(())
        })();
        drop(file);
        match result {
            Ok(()) => {
                std::fs::remove_file(&temporary)?;
                sync_directory(&directory)
            }
            Err(error) => {
                let _ = std::fs::remove_file(&temporary);
                Err(error)
            }
        }
    }

    fn load_manifest(
        &self,
        kind: EvolutionDerivativeKind,
        key_digest: &str,
    ) -> Result<StoredDerivativeManifest, EvolutionPrivateContentError> {
        validate_digest(key_digest)?;
        let path = self
            .kind_directory(kind)?
            .join(format!("{key_digest}.json"));
        if !path.exists() {
            return Err(EvolutionPrivateContentError::MissingManifest {
                kind: kind.label(),
                digest: key_digest.to_owned(),
            });
        }
        reject_symlink(&path)?;
        let manifest: StoredDerivativeManifest = serde_json::from_slice(&read_limited(&path)?)?;
        if manifest.schema_version != MANIFEST_SCHEMA_VERSION
            || manifest.kind != kind
            || manifest.key_digest != key_digest
            || manifest.tenant_id != self.tenant_id
            || manifest.sequence != 0
            || manifest.owner != owner_for(kind, key_digest)
            || manifest.handle.class != kind.class()
            || manifest.handle.digest.as_str() != format!("sha256:{key_digest}")
        {
            return Err(EvolutionPrivateContentError::InvalidManifest);
        }
        Ok(manifest)
    }

    fn kind_directory(
        &self,
        kind: EvolutionDerivativeKind,
    ) -> Result<PathBuf, EvolutionPrivateContentError> {
        let directory = self.manifest_root.join(kind.label());
        prepare_directory(&directory)?;
        Ok(directory)
    }
}

pub(crate) fn source_for_trajectory(
    tenant: &TenantId,
    run_id: &str,
    envelope_digest: &str,
) -> Result<PrivateContentSource, EvolutionPrivateContentError> {
    validate_digest(envelope_digest)?;
    if tenant.0.is_empty() {
        return Err(EvolutionPrivateContentError::TenantMismatch);
    }
    Ok(PrivateContentSource {
        owner: RunId(run_id.to_owned()),
        digest: ErasureContentDigest::new(format!("sha256:{envelope_digest}"))
            .map_err(|_| EvolutionPrivateContentError::InvalidDigest)?,
    })
}

fn owner_for(kind: EvolutionDerivativeKind, digest: &str) -> RunId {
    RunId(format!("evo-{}-{}", kind.label(), &digest[..32]))
}

fn validate_digest(value: &str) -> Result<(), EvolutionPrivateContentError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(EvolutionPrivateContentError::InvalidDigest)
    }
}

fn prepare_directory(path: &Path) -> Result<(), EvolutionPrivateContentError> {
    reject_symlink(path)?;
    std::fs::create_dir_all(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(EvolutionPrivateContentError::InvalidPath(
            path.to_path_buf(),
        ));
    }
    Ok(())
}

fn reject_symlink(path: &Path) -> Result<(), EvolutionPrivateContentError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(
            EvolutionPrivateContentError::InvalidPath(path.to_path_buf()),
        ),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn read_limited(path: &Path) -> Result<Vec<u8>, EvolutionPrivateContentError> {
    reject_symlink(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES as u64 {
        return Err(EvolutionPrivateContentError::InvalidPath(
            path.to_path_buf(),
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?
        .take((MAX_MANIFEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(EvolutionPrivateContentError::InvalidManifest);
    }
    Ok(bytes)
}

fn sync_directory(path: &Path) -> Result<(), EvolutionPrivateContentError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_protocol::{
        ErasureAuthorityId, ErasureOperationId, ErasureScopeId, ErasureState, ErasureTarget,
    };

    fn test_root() -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "iteron-evolution-private-{}-{nonce}",
            std::process::id()
        ))
    }

    fn only_digest(root: &Path, kind: EvolutionDerivativeKind) -> String {
        let directory = root.join(kind.label());
        let mut digests = std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .path()
                    .file_stem()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        digests.sort();
        digests.dedup();
        assert!(!digests.is_empty());
        digests[0].clone()
    }

    #[test]
    fn production_dataset_evaluator_and_candidate_reads_close_after_trajectory_revocation() {
        let root = test_root();
        crate::run_offline_transcript(&root).expect("production offline pipeline succeeds");
        let manifest_root = root.join("evolution-private");
        let content_runs_dir = root.join("trajectory/.private-content");
        let private =
            EvolutionPrivateContent::open(&manifest_root, &content_runs_dir, TenantId::default())
                .unwrap();

        let trajectory_manifest =
            std::fs::read_to_string(root.join("trajectory/trajectory-registry.jsonl")).unwrap();
        let trajectory: serde_json::Value =
            serde_json::from_str(trajectory_manifest.lines().next().unwrap()).unwrap();
        let digest = trajectory["content_digest"].as_str().unwrap();
        let receipt = iteron_record::erasure::execute_erasure(
            &content_runs_dir,
            iteron_protocol::ErasureRequest {
                operation_id: ErasureOperationId::new("evolution-private-revoke").unwrap(),
                authority_id: ErasureAuthorityId::new("operator.owner").unwrap(),
                requested_at_unix_ms: 1,
                target: ErasureTarget::ContentRevocation {
                    scope_id: ErasureScopeId::new("default").unwrap(),
                    content_digest: ErasureContentDigest::new(format!("sha256:{digest}")).unwrap(),
                },
            },
        )
        .unwrap();
        assert_eq!(receipt.state(), ErasureState::Verified);

        for kind in [
            EvolutionDerivativeKind::Dataset,
            EvolutionDerivativeKind::EvaluatorInput,
            EvolutionDerivativeKind::Candidate,
        ] {
            let key = only_digest(&manifest_root, kind);
            assert!(
                private.read(kind, &key).is_err(),
                "{kind:?} survived source revocation"
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
