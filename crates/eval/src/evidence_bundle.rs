//! Signed, self-contained evaluation evidence directories.

use crate::attestation::RunAttestation;
use crate::measurement::{KernelTaxLine, PairedEvaluationReport, compare_manifests};
use crate::pareto::{ParetoPoint, ParetoReport, pareto_frontier};
use crate::types::{CostStatus, EvaluationManifest, Partition, RunStatus};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::io::{Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const INDEX_DOMAIN: &[u8] = b"iteron-eval/evidence-bundle-index/v1\0";
const SIGNATURE_DOMAIN: &[u8] = b"iteron-eval/evidence-bundle-signature/v1\0";
const ROW_ID_DOMAIN: &[u8] = b"iteron-eval/evidence-row/v1\0";
const ROWS_DIGEST_DOMAIN: &[u8] = b"iteron-eval/evidence-rows/v1\0";
pub const EVIDENCE_ROWS_SCHEMA_ID: &str = "iteron-eval/evidence-rows/v1";
pub const EVIDENCE_ROWS_SCHEMA_VERSION: u8 = 1;
pub const MAX_EVIDENCE_ROWS: usize = 4_096;
pub const MAX_EVIDENCE_ROWS_BYTES: usize = 2 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ATTESTATION_BYTES: u64 = 8 * 1024 * 1024;
const MAX_GENERATED_BYTES: u64 = 16 * 1024 * 1024;
const MAX_INDEX_BYTES: u64 = 2 * 1024 * 1024;
const MAX_BUNDLE_FILES: usize = 16;
const MAX_BUNDLE_BYTES: u64 = 600 * 1024 * 1024;

fn max_bundle_bytes() -> u64 {
    iteron_tunables::param_integer("eval.evidence_bundle.max_bundle_bytes", MAX_BUNDLE_BYTES)
}

fn max_evidence_rows() -> usize {
    iteron_tunables::param_integer("eval.evidence_bundle.max_evidence_rows", MAX_EVIDENCE_ROWS)
        .min(MAX_EVIDENCE_ROWS)
}

fn max_evidence_rows_bytes() -> usize {
    iteron_tunables::param_integer(
        "eval.evidence_bundle.max_evidence_rows_bytes",
        MAX_EVIDENCE_ROWS_BYTES,
    )
    .min(MAX_EVIDENCE_ROWS_BYTES)
}

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

/// Provenance is part of the signed schema so a synthetic acceptance fixture can never be
/// rendered or exported as measured benchmark evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRowsProvenance {
    Measured,
    SyntheticFixture,
}

/// One exhaustive terminal result class shared by bundle emission, verification, offline tuning
/// and the experiment lab. Train versus held-out is the orthogonal, typed `partition` field: a
/// held-out success must remain scoreable while still being structurally ineligible for tuning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRowOutcome {
    Success,
    TaskFailure,
    InfrastructureFailure,
    Censored,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRow {
    pub row_id: String,
    pub run_id: String,
    pub candidate_id: String,
    pub candidate_digest: Option<String>,
    pub dataset_digest: String,
    pub task: String,
    pub config: String,
    pub seed: u64,
    pub partition: Partition,
    pub outcome: EvidenceRowOutcome,
    pub resolved: Option<bool>,
    pub elapsed_ms: u64,
    pub cost_status: CostStatus,
    pub cost_usd: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRowsDocument {
    pub schema_version: u8,
    pub schema_id: String,
    pub provenance: EvidenceRowsProvenance,
    pub rows: Vec<EvidenceRow>,
    pub document_sha256: String,
}

#[derive(Serialize)]
struct UnsignedEvidenceRows<'a> {
    schema_version: u8,
    schema_id: &'a str,
    provenance: EvidenceRowsProvenance,
    rows: &'a [EvidenceRow],
}

#[derive(Serialize)]
struct EvidenceRowIdentity<'a> {
    run_id: &'a str,
    candidate_id: &'a str,
    candidate_digest: Option<&'a str>,
    dataset_digest: &'a str,
    task: &'a str,
    config: &'a str,
    seed: u64,
    partition: Partition,
}

impl EvidenceRowsDocument {
    pub fn validate(&self) -> Result<(), EvidenceBundleError> {
        if self.schema_version != EVIDENCE_ROWS_SCHEMA_VERSION
            || self.schema_id != EVIDENCE_ROWS_SCHEMA_ID
            || self.rows.is_empty()
            || self.rows.len() > max_evidence_rows()
        {
            return Err(EvidenceBundleError::InvalidInput(
                "evidence rows violate the frozen v1 envelope".into(),
            ));
        }
        let encoded = serde_json::to_vec(self)
            .map_err(|error| EvidenceBundleError::Json(error.to_string()))?;
        if encoded.len() > max_evidence_rows_bytes() {
            return Err(EvidenceBundleError::InvalidInput(
                "evidence rows exceed the frozen v1 byte bound".into(),
            ));
        }
        let mut identities = BTreeSet::new();
        let mut previous = None;
        for row in &self.rows {
            validate_evidence_row(row)?;
            if !identities.insert(row.row_id.as_str())
                || previous.is_some_and(|previous| previous >= row.row_id.as_str())
            {
                return Err(EvidenceBundleError::InvalidInput(
                    "evidence row identities must be unique and canonically ordered".into(),
                ));
            }
            previous = Some(row.row_id.as_str());
        }
        if self.document_sha256 != evidence_rows_digest(self)? {
            return Err(EvidenceBundleError::Digest);
        }
        Ok(())
    }

    pub fn is_synthetic_fixture(&self) -> bool {
        self.provenance == EvidenceRowsProvenance::SyntheticFixture
    }
}

/// Decode the exact committed/runtime row schema with duplicate fields, unknown fields, invalid
/// identities, non-canonical order and oversized documents all rejected.
pub fn parse_evidence_rows(bytes: &[u8]) -> Result<EvidenceRowsDocument, EvidenceBundleError> {
    if bytes.len() > max_evidence_rows_bytes() {
        return Err(EvidenceBundleError::InvalidInput(
            "evidence rows exceed the frozen v1 byte bound".into(),
        ));
    }
    let document: EvidenceRowsDocument = decode(bytes)?;
    document.validate()?;
    Ok(document)
}

/// Production emitter for the frozen row contract. Its provenance cannot be selected by callers.
pub fn emit_evidence_rows(
    baseline: &EvaluationManifest,
    baseline_id: &str,
    baseline_arm: &str,
    candidate: &EvaluationManifest,
    candidate_id: &str,
    candidate_arm: &str,
) -> Result<EvidenceRowsDocument, EvidenceBundleError> {
    validate_label(baseline_id)?;
    validate_label(candidate_id)?;
    let mut rows = rows_from_manifest(baseline, baseline_id, baseline_arm)?;
    rows.extend(rows_from_manifest(candidate, candidate_id, candidate_arm)?);
    build_evidence_rows(EvidenceRowsProvenance::Measured, rows)
}

/// Emit the same v1 document for one tuner candidate/arm. `compile_evidence_bundle` composes these
/// exact rows for its two arms; this entry point prevents the tuner from maintaining a second
/// observation schema.
pub fn emit_candidate_evidence_rows(
    manifest: &EvaluationManifest,
    candidate_id: &str,
    arm: &str,
) -> Result<EvidenceRowsDocument, EvidenceBundleError> {
    validate_label(candidate_id)?;
    build_evidence_rows(
        EvidenceRowsProvenance::Measured,
        rows_from_manifest(manifest, candidate_id, arm)?,
    )
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnsignedBundleIndex {
    schema_version: u8,
    bundle_type: String,
    public_key: String,
    comparison: BundleComparison,
    evidence_rows: EvidenceRowsDocument,
    files: Vec<BundleFile>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBundleIndex {
    pub schema_version: u8,
    pub bundle_type: String,
    pub public_key: String,
    pub comparison: BundleComparison,
    pub evidence_rows: EvidenceRowsDocument,
    pub files: Vec<BundleFile>,
    pub index_sha256: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedEvidenceBundle {
    pub index: EvidenceBundleIndex,
    pub evidence_rows: EvidenceRowsDocument,
    pub paired: PairedEvaluationReport,
    pub pareto: ParetoReport,
    _verified: VerifiedEvidenceSeal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifiedEvidenceSeal {
    index_sha256: String,
    evidence_rows_sha256: String,
}

impl VerifiedEvidenceBundle {
    pub fn is_synthetic_fixture(&self) -> bool {
        self.evidence_rows.is_synthetic_fixture()
    }

    pub(crate) fn validate_in_memory_seal(&self) -> Result<(), EvidenceBundleError> {
        self.evidence_rows.validate()?;
        if self.index.index_sha256 != self._verified.index_sha256
            || self.evidence_rows.document_sha256 != self._verified.evidence_rows_sha256
            || self.index.evidence_rows != self.evidence_rows
        {
            return Err(EvidenceBundleError::Digest);
        }
        Ok(())
    }
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
    let baseline_bytes = read_regular(
        input.baseline_result,
        iteron_tunables::param_integer(
            "eval.evidence_bundle.max_manifest_bytes",
            MAX_MANIFEST_BYTES,
        ),
    )?;
    let candidate_bytes = read_regular(
        input.candidate_result,
        iteron_tunables::param_integer(
            "eval.evidence_bundle.max_manifest_bytes",
            MAX_MANIFEST_BYTES,
        ),
    )?;
    let baseline: EvaluationManifest = decode(&baseline_bytes)?;
    let candidate: EvaluationManifest = decode(&candidate_bytes)?;
    let baseline_attestation_bytes = read_regular(
        input.baseline_attestation,
        iteron_tunables::param_integer(
            "eval.evidence_bundle.max_attestation_bytes",
            MAX_ATTESTATION_BYTES,
        ),
    )?;
    let candidate_attestation_bytes = read_regular(
        input.candidate_attestation,
        iteron_tunables::param_integer(
            "eval.evidence_bundle.max_attestation_bytes",
            MAX_ATTESTATION_BYTES,
        ),
    )?;
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
    let evidence_rows = emit_evidence_rows(
        &baseline,
        input.baseline_id,
        input.baseline_arm,
        &candidate,
        input.candidate_id,
        input.candidate_arm,
    )?;

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
        evidence_rows,
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
    evidence_rows: EvidenceRowsDocument,
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
        evidence_rows: input.evidence_rows,
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
        evidence_rows: unsigned.evidence_rows,
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
    if !valid_ascii_wire_text(value, 128) {
        return Err(EvidenceBundleError::InvalidInput(
            "candidate labels must be bounded printable ASCII text".into(),
        ));
    }
    Ok(())
}

fn rows_from_manifest(
    manifest: &EvaluationManifest,
    candidate_id: &str,
    arm: &str,
) -> Result<Vec<EvidenceRow>, EvidenceBundleError> {
    validate_label(arm)?;
    let mut rows = manifest
        .cells
        .iter()
        .filter(|cell| cell.config == arm)
        .map(|cell| {
            let (outcome, resolved) = match cell.run_status {
                RunStatus::Completed if cell.resolved == Some(true) => {
                    (EvidenceRowOutcome::Success, Some(true))
                }
                RunStatus::Completed => (EvidenceRowOutcome::TaskFailure, Some(false)),
                RunStatus::Censored => (EvidenceRowOutcome::Censored, None),
                RunStatus::Errored | RunStatus::TimedOut => {
                    (EvidenceRowOutcome::InfrastructureFailure, None)
                }
            };
            let mut row = EvidenceRow {
                row_id: String::new(),
                run_id: manifest.run_id.clone(),
                candidate_id: candidate_id.into(),
                candidate_digest: manifest.bundle_digest.clone(),
                dataset_digest: manifest.dataset_digest.clone(),
                task: cell.task.clone(),
                config: cell.config.clone(),
                seed: cell.seed,
                partition: cell.partition,
                outcome,
                resolved,
                elapsed_ms: cell.elapsed_ms,
                cost_status: cell.cost_status,
                cost_usd: cell.cost_usd,
            };
            row.row_id = evidence_row_id(&row)?;
            validate_evidence_row(&row)?;
            Ok(row)
        })
        .collect::<Result<Vec<_>, EvidenceBundleError>>()?;
    if rows.is_empty() {
        return Err(EvidenceBundleError::InvalidInput(format!(
            "selected arm `{arm}` has no evidence rows"
        )));
    }
    rows.sort_by(|left, right| left.row_id.cmp(&right.row_id));
    Ok(rows)
}

fn build_evidence_rows(
    provenance: EvidenceRowsProvenance,
    mut rows: Vec<EvidenceRow>,
) -> Result<EvidenceRowsDocument, EvidenceBundleError> {
    rows.sort_by(|left, right| left.row_id.cmp(&right.row_id));
    let mut document = EvidenceRowsDocument {
        schema_version: EVIDENCE_ROWS_SCHEMA_VERSION,
        schema_id: EVIDENCE_ROWS_SCHEMA_ID.into(),
        provenance,
        rows,
        document_sha256: String::new(),
    };
    document.document_sha256 = evidence_rows_digest(&document)?;
    document.validate()?;
    Ok(document)
}

fn validate_evidence_row(row: &EvidenceRow) -> Result<(), EvidenceBundleError> {
    for value in [
        row.run_id.as_str(),
        row.candidate_id.as_str(),
        row.task.as_str(),
        row.config.as_str(),
    ] {
        if !valid_ascii_wire_text(value, 256) {
            return Err(EvidenceBundleError::InvalidInput(
                "evidence row labels must be bounded printable ASCII text".into(),
            ));
        }
    }
    if !valid_sha256(&row.row_id)
        || !valid_sha256(&row.dataset_digest)
        || row
            .candidate_digest
            .as_deref()
            .is_some_and(|digest| !valid_sha256(digest))
        || row.row_id != evidence_row_id(row)?
        || row
            .cost_usd
            .is_some_and(|cost| !cost.is_finite() || cost < 0.0)
        || match row.cost_status {
            CostStatus::Known => row.cost_usd.is_none(),
            CostStatus::Zero | CostStatus::Unknown => row.cost_usd.is_some(),
        }
    {
        return Err(EvidenceBundleError::InvalidInput(
            "evidence row identity, digest, or cost is invalid".into(),
        ));
    }
    let consistent_outcome = match row.outcome {
        EvidenceRowOutcome::Success => row.resolved == Some(true),
        EvidenceRowOutcome::TaskFailure => row.resolved == Some(false),
        EvidenceRowOutcome::InfrastructureFailure => row.resolved.is_none(),
        EvidenceRowOutcome::Censored => row.resolved.is_none(),
    };
    if !consistent_outcome {
        return Err(EvidenceBundleError::InvalidInput(
            "evidence row outcome does not match its partition/result".into(),
        ));
    }
    Ok(())
}

fn evidence_row_id(row: &EvidenceRow) -> Result<String, EvidenceBundleError> {
    let identity = EvidenceRowIdentity {
        run_id: &row.run_id,
        candidate_id: &row.candidate_id,
        candidate_digest: row.candidate_digest.as_deref(),
        dataset_digest: &row.dataset_digest,
        task: &row.task,
        config: &row.config,
        seed: row.seed,
        partition: row.partition,
    };
    let bytes = serde_json::to_vec(&identity)
        .map_err(|error| EvidenceBundleError::Json(error.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(ROW_ID_DOMAIN);
    digest.update(bytes);
    Ok(format!("sha256:{}", hex::encode(digest.finalize())))
}

fn evidence_rows_digest(document: &EvidenceRowsDocument) -> Result<String, EvidenceBundleError> {
    let unsigned = UnsignedEvidenceRows {
        schema_version: document.schema_version,
        schema_id: &document.schema_id,
        provenance: document.provenance,
        rows: &document.rows,
    };
    let bytes = serde_json::to_vec(&unsigned)
        .map_err(|error| EvidenceBundleError::Json(error.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(ROWS_DIGEST_DOMAIN);
    digest.update(bytes);
    Ok(format!("sha256:{}", hex::encode(digest.finalize())))
}

fn valid_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn valid_ascii_wire_text(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.bytes().all(|byte| (b' '..=b'~').contains(&byte))
        && value.bytes().any(|byte| byte != b' ')
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
    if bytes.len() as u64
        > iteron_tunables::param_integer(
            "eval.evidence_bundle.max_generated_bytes",
            MAX_GENERATED_BYTES,
        )
    {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const FIXTURE_PUBLIC_KEY: &str =
        "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618";

    fn fixture() -> VerifiedEvidenceBundle {
        verify_evidence_bundle(
            &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/evidence-bundle-v1"),
            FIXTURE_PUBLIC_KEY,
        )
        .unwrap()
    }

    #[test]
    fn frozen_fixture_is_closed_canonical_bounded_and_covers_all_results_plus_held_out() {
        let fixture_root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/evidence-bundle-v1");
        let document = fixture().evidence_rows;
        assert!(document.is_synthetic_fixture());
        assert_eq!(
            document
                .rows
                .iter()
                .map(|row| row.outcome)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                EvidenceRowOutcome::Success,
                EvidenceRowOutcome::TaskFailure,
                EvidenceRowOutcome::InfrastructureFailure,
            ])
        );
        assert_eq!(
            document
                .rows
                .iter()
                .filter(|row| row.partition == Partition::HeldOut)
                .count(),
            1
        );
        assert_eq!(
            parse_evidence_rows(&serde_json::to_vec(&document).unwrap()).unwrap(),
            document
        );

        let mut unknown: serde_json::Value = serde_json::to_value(&document).unwrap();
        unknown["rows"][0]["pin_only_runtime_authority"] = serde_json::json!(true);
        assert!(parse_evidence_rows(&serde_json::to_vec(&unknown).unwrap()).is_err());
        let encoded = serde_json::to_string(&document).unwrap();
        let duplicate_field = encoded.replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
            1,
        );
        assert!(parse_evidence_rows(duplicate_field.as_bytes()).is_err());

        let mut duplicate = document.clone();
        duplicate.rows.push(duplicate.rows[0].clone());
        duplicate
            .rows
            .sort_by(|left, right| left.row_id.cmp(&right.row_id));
        duplicate.document_sha256 = evidence_rows_digest(&duplicate).unwrap();
        assert!(duplicate.validate().is_err());

        assert!(validate_label("candidate arm").is_ok());
        assert!(validate_label("candidate-é").is_err());
        let mut non_ascii = document.clone();
        non_ascii.rows[0].task = "é".into();
        non_ascii.rows[0].row_id = evidence_row_id(&non_ascii.rows[0]).unwrap();
        non_ascii
            .rows
            .sort_by(|left, right| left.row_id.cmp(&right.row_id));
        non_ascii.document_sha256 = evidence_rows_digest(&non_ascii).unwrap();
        assert!(non_ascii.validate().is_err());

        let baseline: EvaluationManifest =
            decode(&std::fs::read(fixture_root.join("baseline.json")).unwrap()).unwrap();
        let candidate: EvaluationManifest =
            decode(&std::fs::read(fixture_root.join("candidate.json")).unwrap()).unwrap();
        let emitted = emit_evidence_rows(
            &baseline,
            "baseline",
            "baseline_arm",
            &candidate,
            "candidate",
            "candidate_arm",
        )
        .unwrap();
        assert_eq!(emitted.schema_id, document.schema_id);
        assert_eq!(emitted.provenance, EvidenceRowsProvenance::Measured);
        assert!(
            emitted
                .rows
                .iter()
                .all(|row| row.partition == Partition::HeldOut)
        );
    }

    #[test]
    fn frozen_json_schemas_cover_the_exact_signed_fixture_shape() {
        let row_schema: serde_json::Value =
            serde_json::from_str(include_str!("../schemas/evidence-rows-v1.schema.json")).unwrap();
        let index_schema: serde_json::Value = serde_json::from_str(include_str!(
            "../schemas/evidence-bundle-index-v1.schema.json"
        ))
        .unwrap();
        let fixture_index: serde_json::Value = serde_json::from_slice(
            &std::fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("fixtures/evidence-bundle-v1/bundle.index.json"),
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(
            row_schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(
            row_schema["properties"]["schema_id"]["const"],
            EVIDENCE_ROWS_SCHEMA_ID
        );
        assert_eq!(
            row_schema["properties"]["rows"]["maxItems"],
            MAX_EVIDENCE_ROWS
        );
        assert_eq!(
            index_schema["properties"]["evidence_rows"]["$ref"],
            "#/$defs/evidence_rows"
        );

        fn embed_refs(value: &mut serde_json::Value) {
            match value {
                serde_json::Value::Object(fields) => {
                    for value in fields.values_mut() {
                        embed_refs(value);
                    }
                }
                serde_json::Value::Array(values) => {
                    for value in values {
                        embed_refs(value);
                    }
                }
                serde_json::Value::String(reference) if reference.starts_with("#/$defs/") => {
                    *reference = reference.replacen("#/$defs/", "#/$defs/evidence_rows/$defs/", 1);
                }
                _ => {}
            }
        }
        let mut embedded_contract = row_schema.clone();
        let embedded_fields = embedded_contract.as_object_mut().unwrap();
        for annotation in ["$schema", "$id", "title", "description"] {
            embedded_fields.remove(annotation);
        }
        embed_refs(&mut embedded_contract);
        assert_eq!(embedded_contract, index_schema["$defs"]["evidence_rows"]);

        let required = |schema: &serde_json::Value| {
            schema["required"]
                .as_array()
                .unwrap()
                .iter()
                .map(|field| field.as_str().unwrap().to_owned())
                .collect::<BTreeSet<_>>()
        };
        let fields = |value: &serde_json::Value| {
            value
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>()
        };
        assert_eq!(required(&index_schema), fields(&fixture_index));
        let fixture_rows = &fixture_index["evidence_rows"];
        assert_eq!(required(&row_schema), fields(fixture_rows));
        let row_shape = &row_schema["$defs"]["evidence_row"];
        for row in fixture_rows["rows"].as_array().unwrap() {
            assert_eq!(required(row_shape), fields(row));
        }

        // The fixture is not merely shape-compatible: the Rust verifier also checks canonical
        // row identities/digest, the file digests, index signature, and recomputed reports.
        fixture();
    }
}
