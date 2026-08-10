//! Signed, self-contained evaluation evidence directories.

use crate::attestation::RunAttestation;
use crate::measurement::{KernelTaxLine, PairedEvaluationReport, compare_manifests};
use crate::pareto::{ParetoPoint, ParetoReport, pareto_frontier};
use crate::types::EvaluationManifest;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const INDEX_DOMAIN: &[u8] = b"iteron-eval/evidence-bundle-index/v1\0";
const SIGNATURE_DOMAIN: &[u8] = b"iteron-eval/evidence-bundle-signature/v1\0";
const MAX_MANIFEST_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ATTESTATION_BYTES: u64 = 8 * 1024 * 1024;
const MAX_GENERATED_BYTES: u64 = 16 * 1024 * 1024;
const MAX_INDEX_BYTES: u64 = 2 * 1024 * 1024;
const MAX_BUNDLE_FILES: usize = 16;
const MAX_BUNDLE_BYTES: u64 = 600 * 1024 * 1024;

mod verify;
pub use verify::verify_evidence_bundle;

#[derive(Clone)]
pub struct EvidenceSigner(SigningKey);

impl fmt::Debug for EvidenceSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceSigner")
            .field("secret", &"[REDACTED]")
            .field("public_key", &self.public_key_hex())
            .finish()
    }
}

impl EvidenceSigner {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&seed))
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.0.verifying_key().as_bytes())
    }
}

pub struct EvidenceBundleInput<'a> {
    pub destination: &'a Path,
    pub baseline_result: &'a Path,
    pub baseline_attestation: &'a Path,
    pub baseline_arm: &'a str,
    pub baseline_id: &'a str,
    pub candidate_result: &'a Path,
    pub candidate_attestation: &'a Path,
    pub candidate_arm: &'a str,
    pub candidate_id: &'a str,
    pub minimum_pairs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleFile {
    pub role: String,
    pub file_name: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleComparison {
    pub baseline_id: String,
    pub baseline_arm: String,
    pub candidate_id: String,
    pub candidate_arm: String,
    pub minimum_pairs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnsignedBundleIndex {
    schema_version: u8,
    bundle_type: String,
    public_key: String,
    comparison: BundleComparison,
    files: Vec<BundleFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBundleIndex {
    pub schema_version: u8,
    pub bundle_type: String,
    pub public_key: String,
    pub comparison: BundleComparison,
    pub files: Vec<BundleFile>,
    pub index_sha256: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedEvidenceBundle {
    pub index: EvidenceBundleIndex,
    pub paired: PairedEvaluationReport,
    pub pareto: ParetoReport,
}

#[derive(Debug, thiserror::Error)]
pub enum EvidenceBundleError {
    #[error("invalid evidence bundle input: {0}")]
    InvalidInput(String),
    #[error("evidence artifact `{path}` is invalid: {reason}")]
    Artifact { path: String, reason: String },
    #[error("evidence bundle I/O at `{path}`: {reason}")]
    Io { path: String, reason: String },
    #[error("evidence bundle JSON is invalid: {0}")]
    Json(String),
    #[error("evidence bundle signature or trusted signer does not verify")]
    Signature,
    #[error("evidence bundle index or file digest does not verify")]
    Digest,
    #[error(transparent)]
    Measurement(#[from] crate::measurement::MeasurementError),
    #[error(transparent)]
    Pareto(#[from] crate::pareto::ParetoError),
    #[error(transparent)]
    Attestation(#[from] crate::attestation::AttestationError),
}

pub fn compile_evidence_bundle(
    input: EvidenceBundleInput<'_>,
    signer: &EvidenceSigner,
) -> Result<VerifiedEvidenceBundle, EvidenceBundleError> {
    validate_label(input.baseline_id)?;
    validate_label(input.candidate_id)?;
    if input.baseline_id == input.candidate_id {
        return Err(EvidenceBundleError::InvalidInput(
            "baseline and candidate ids must differ".into(),
        ));
    }
    if input.destination.exists() {
        return Err(EvidenceBundleError::InvalidInput(
            "destination already exists".into(),
        ));
    }
    let baseline_bytes = read_regular(input.baseline_result, MAX_MANIFEST_BYTES)?;
    let candidate_bytes = read_regular(input.candidate_result, MAX_MANIFEST_BYTES)?;
    let baseline: EvaluationManifest = decode(&baseline_bytes)?;
    let candidate: EvaluationManifest = decode(&candidate_bytes)?;
    let baseline_attestation_bytes =
        read_regular(input.baseline_attestation, MAX_ATTESTATION_BYTES)?;
    let candidate_attestation_bytes =
        read_regular(input.candidate_attestation, MAX_ATTESTATION_BYTES)?;
    let baseline_attestation: RunAttestation = decode(&baseline_attestation_bytes)?;
    let candidate_attestation: RunAttestation = decode(&candidate_attestation_bytes)?;
    validate_attestation(&baseline_attestation, &baseline, &baseline_bytes)?;
    validate_attestation(&candidate_attestation, &candidate, &candidate_bytes)?;

    let paired = compare_manifests(
        &baseline,
        input.baseline_arm,
        &candidate,
        input.candidate_arm,
        input.minimum_pairs,
        "signed_evidence_bundle",
        KernelTaxLine::reserved(),
    )?;
    let pareto = pareto_frontier(vec![
        ParetoPoint::from_manifest_arm(input.baseline_id, &baseline, input.baseline_arm)?,
        ParetoPoint::from_manifest_arm(input.candidate_id, &candidate, input.candidate_arm)?,
    ])?;
    let comparison = BundleComparison {
        baseline_id: input.baseline_id.into(),
        baseline_arm: input.baseline_arm.into(),
        candidate_id: input.candidate_id.into(),
        candidate_arm: input.candidate_arm.into(),
        minimum_pairs: input.minimum_pairs,
    };

    let parent = input.destination.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|error| io(parent, error))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = parent.join(format!(
        ".core-evidence-{}-{nonce:x}.tmp",
        std::process::id()
    ));
    std::fs::create_dir(&temporary).map_err(|error| io(&temporary, error))?;
    let result = write_bundle(BundleWriteInput {
        directory: &temporary,
        baseline: &baseline_bytes,
        candidate: &candidate_bytes,
        baseline_attestation: &baseline_attestation_bytes,
        candidate_attestation: &candidate_attestation_bytes,
        paired: &paired,
        pareto: &pareto,
        comparison,
        signer,
    })
    .and_then(|index| {
        std::fs::rename(&temporary, input.destination)
            .map_err(|error| io(input.destination, error))?;
        Ok(index)
    });
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&temporary);
    }
    result?;
    verify_evidence_bundle(input.destination, &signer.public_key_hex())
}

struct BundleWriteInput<'a> {
    directory: &'a Path,
    baseline: &'a [u8],
    candidate: &'a [u8],
    baseline_attestation: &'a [u8],
    candidate_attestation: &'a [u8],
    paired: &'a PairedEvaluationReport,
    pareto: &'a ParetoReport,
    comparison: BundleComparison,
    signer: &'a EvidenceSigner,
}

fn write_bundle(input: BundleWriteInput<'_>) -> Result<EvidenceBundleIndex, EvidenceBundleError> {
    let entries = [
        (
            "baseline_manifest",
            "baseline.json",
            input.baseline.to_vec(),
        ),
        (
            "candidate_manifest",
            "candidate.json",
            input.candidate.to_vec(),
        ),
        (
            "baseline_attestation",
            "baseline.attestation.json",
            input.baseline_attestation.to_vec(),
        ),
        (
            "candidate_attestation",
            "candidate.attestation.json",
            input.candidate_attestation.to_vec(),
        ),
        ("paired_report", "paired.json", pretty_json(input.paired)?),
        ("pareto_report", "pareto.json", pretty_json(input.pareto)?),
    ];
    let mut files = Vec::with_capacity(entries.len());
    for (role, name, bytes) in entries {
        write_new(&input.directory.join(name), &bytes)?;
        files.push(BundleFile {
            role: role.into(),
            file_name: name.into(),
            bytes: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(&bytes)),
        });
    }
    let unsigned = UnsignedBundleIndex {
        schema_version: 1,
        bundle_type: "iteron-eval-signed-evidence".into(),
        public_key: input.signer.public_key_hex(),
        comparison: input.comparison,
        files,
    };
    let unsigned_bytes = serde_json::to_vec(&unsigned)
        .map_err(|error| EvidenceBundleError::Json(error.to_string()))?;
    let index_sha256 = index_digest(&unsigned_bytes);
    let mut preimage = Vec::with_capacity(SIGNATURE_DOMAIN.len() + unsigned_bytes.len());
    preimage.extend_from_slice(SIGNATURE_DOMAIN);
    preimage.extend_from_slice(&unsigned_bytes);
    let signature = input.signer.0.sign(&preimage);
    let index = EvidenceBundleIndex {
        schema_version: unsigned.schema_version,
        bundle_type: unsigned.bundle_type,
        public_key: unsigned.public_key,
        comparison: unsigned.comparison,
        files: unsigned.files,
        index_sha256,
        signature: hex::encode(signature.to_bytes()),
    };
    write_new(
        &input.directory.join("bundle.index.json"),
        &pretty_json(&index)?,
    )?;
    Ok(index)
}

fn validate_attestation(
    attestation: &RunAttestation,
    manifest: &EvaluationManifest,
    manifest_bytes: &[u8],
) -> Result<(), EvidenceBundleError> {
    attestation.verify_digest()?;
    if attestation.run_id != manifest.run_id
        || attestation.corpus_version != manifest.corpus_version
        || attestation.dataset_digest != manifest.dataset_digest
        || attestation.model != manifest.model
        || attestation.provider != manifest.provider
        || attestation.bundle_digest != manifest.bundle_digest
        || attestation.purpose != manifest.purpose
    {
        return Err(EvidenceBundleError::InvalidInput(
            "run attestation does not bind its evaluation manifest".into(),
        ));
    }
    let expected_digest = hex::encode(Sha256::digest(manifest_bytes));
    if !attestation.artifacts.iter().any(|artifact| {
        artifact.role == "evaluation_result"
            && artifact.bytes == manifest_bytes.len() as u64
            && artifact.sha256 == expected_digest
    }) {
        return Err(EvidenceBundleError::InvalidInput(
            "run attestation does not bind the exact manifest bytes".into(),
        ));
    }
    Ok(())
}

fn validate_label(value: &str) -> Result<(), EvidenceBundleError> {
    if value.trim().is_empty()
        || value.len() > 128
        || value.chars().any(|character| character.is_control())
    {
        return Err(EvidenceBundleError::InvalidInput(
            "candidate labels must be bounded printable text".into(),
        ));
    }
    Ok(())
}

fn read_regular(path: &Path, maximum: u64) -> Result<Vec<u8>, EvidenceBundleError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| io(path, error))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > maximum
    {
        return Err(EvidenceBundleError::Artifact {
            path: path.display().to_string(),
            reason: "expected a bounded regular non-symlink file".into(),
        });
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    std::fs::File::open(path)
        .map_err(|error| io(path, error))?
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| io(path, error))?;
    if bytes.len() as u64 > maximum {
        return Err(EvidenceBundleError::Artifact {
            path: path.display().to_string(),
            reason: "file grew beyond its fixed limit while reading".into(),
        });
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), EvidenceBundleError> {
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| io(path, error))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| io(path, error))
}

fn pretty_json(value: &impl Serialize) -> Result<Vec<u8>, EvidenceBundleError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| EvidenceBundleError::Json(error.to_string()))?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_GENERATED_BYTES {
        return Err(EvidenceBundleError::InvalidInput(
            "generated evidence exceeds its fixed size limit".into(),
        ));
    }
    Ok(bytes)
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, EvidenceBundleError> {
    serde_json::from_slice(bytes).map_err(|error| EvidenceBundleError::Json(error.to_string()))
}

fn index_digest(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(INDEX_DOMAIN);
    digest.update(bytes);
    hex::encode(digest.finalize())
}

fn io(path: &Path, error: std::io::Error) -> EvidenceBundleError {
    EvidenceBundleError::Io {
        path: path.display().to_string(),
        reason: error.to_string(),
    }
}
