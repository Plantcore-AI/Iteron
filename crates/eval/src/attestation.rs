//! Reproducible, content-addressed benchmark run attestation.

use crate::corpus::CorpusManifest;
use crate::types::{BenchmarkReference, EvaluationPurpose};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const ATTESTATION_DOMAIN: &[u8] = b"iteron-eval/run-attestation/v1\0";
const MAX_ATTESTATION_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ITERON_BINARY_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_RESULT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_CORPUS_BYTES: u64 = 4 * 1024 * 1024;
const MAX_ATTEMPT_LEDGER_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDigest {
    pub role: String,
    pub file_name: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterEvidence {
    pub name: String,
    pub task_count: u32,
    pub dataset_revisions: Vec<String>,
    pub environment_setup_commits: Vec<String>,
    pub environment_images: Vec<String>,
    pub references_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionLimits {
    pub seeds: u64,
    pub minimum_seeds: u64,
    pub workers: u16,
    pub max_attempts: u8,
    pub max_turns: Option<u32>,
    pub run_timeout_secs: u64,
    pub checkout_timeout_secs: u64,
    pub oracle_timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunAttestation {
    pub schema_version: u8,
    pub runner_version: String,
    pub run_id: String,
    pub corpus_version: String,
    pub dataset_digest: String,
    pub tunables_registry_digest: String,
    pub model: String,
    pub provider: Option<String>,
    pub bundle_digest: Option<String>,
    pub purpose: EvaluationPurpose,
    pub limits: ExecutionLimits,
    pub attempt_ledger_head: String,
    pub attempt_record_count: u64,
    pub adapters: Vec<AdapterEvidence>,
    pub artifacts: Vec<ArtifactDigest>,
    pub attestation_sha256: String,
}

pub struct RunAttestationInput<'a> {
    pub run_id: &'a str,
    pub corpus: &'a CorpusManifest,
    pub core_path: &'a Path,
    pub corpus_path: &'a Path,
    pub result_path: &'a Path,
    pub attempt_ledger_path: &'a Path,
    pub attempt_ledger_head: &'a str,
    pub attempt_record_count: u64,
    pub model: &'a str,
    pub provider: Option<&'a str>,
    pub bundle_digest: Option<&'a str>,
    pub purpose: EvaluationPurpose,
    pub limits: ExecutionLimits,
}

#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error("attestation artifact `{path}` is invalid: {reason}")]
    Artifact { path: String, reason: String },
    #[error("attestation I/O at `{path}`: {reason}")]
    Io { path: String, reason: String },
    #[error("attestation JSON is invalid: {0}")]
    Json(String),
    #[error("run attestation digest mismatch")]
    DigestMismatch,
    #[error("run attestation artifact set does not match the supplied files")]
    ArtifactMismatch,
}

impl RunAttestation {
    pub fn build(input: RunAttestationInput<'_>) -> Result<Self, AttestationError> {
        let mut attestation = Self {
            schema_version: 1,
            runner_version: env!("CARGO_PKG_VERSION").into(),
            run_id: input.run_id.into(),
            corpus_version: input.corpus.corpus_version.clone(),
            dataset_digest: input.corpus.dataset_digest.clone(),
            tunables_registry_digest: iteron_tunables::registry_digest()
                .map_err(|error| AttestationError::Artifact {
                    path: "iteron-tunables".into(),
                    reason: error.to_string(),
                })?
                .value,
            model: input.model.into(),
            provider: input.provider.map(str::to_owned),
            bundle_digest: input.bundle_digest.map(str::to_owned),
            purpose: input.purpose,
            limits: input.limits,
            attempt_ledger_head: input.attempt_ledger_head.into(),
            attempt_record_count: input.attempt_record_count,
            adapters: adapter_evidence(input.corpus)?,
            artifacts: vec![
                artifact_digest(
                    "core_binary",
                    input.core_path,
                    iteron_tunables::param_integer(
                        "eval.attestation.max_iteron_binary_bytes",
                        MAX_ITERON_BINARY_BYTES,
                    ),
                )?,
                artifact_digest(
                    "corpus",
                    input.corpus_path,
                    iteron_tunables::param_integer(
                        "eval.attestation.max_corpus_bytes",
                        MAX_CORPUS_BYTES,
                    ),
                )?,
                artifact_digest(
                    "evaluation_result",
                    input.result_path,
                    iteron_tunables::param_integer(
                        "eval.attestation.max_result_bytes",
                        MAX_RESULT_BYTES,
                    ),
                )?,
                artifact_digest(
                    "attempt_ledger",
                    input.attempt_ledger_path,
                    iteron_tunables::param_integer(
                        "eval.attestation.max_attempt_ledger_bytes",
                        MAX_ATTEMPT_LEDGER_BYTES,
                    ),
                )?,
            ],
            attestation_sha256: String::new(),
        };
        attestation.attestation_sha256 = attestation.digest()?;
        Ok(attestation)
    }

    pub fn verify_digest(&self) -> Result<(), AttestationError> {
        if self.schema_version != 1 || self.attestation_sha256 != self.digest()? {
            return Err(AttestationError::DigestMismatch);
        }
        Ok(())
    }

    pub fn verify_artifacts(
        &self,
        core_path: &Path,
        corpus_path: &Path,
        result_path: &Path,
        attempt_ledger_path: &Path,
    ) -> Result<(), AttestationError> {
        let actual = vec![
            artifact_digest(
                "core_binary",
                core_path,
                iteron_tunables::param_integer(
                    "eval.attestation.max_iteron_binary_bytes",
                    MAX_ITERON_BINARY_BYTES,
                ),
            )?,
            artifact_digest(
                "corpus",
                corpus_path,
                iteron_tunables::param_integer(
                    "eval.attestation.max_corpus_bytes",
                    MAX_CORPUS_BYTES,
                ),
            )?,
            artifact_digest(
                "evaluation_result",
                result_path,
                iteron_tunables::param_integer(
                    "eval.attestation.max_result_bytes",
                    MAX_RESULT_BYTES,
                ),
            )?,
            artifact_digest(
                "attempt_ledger",
                attempt_ledger_path,
                iteron_tunables::param_integer(
                    "eval.attestation.max_attempt_ledger_bytes",
                    MAX_ATTEMPT_LEDGER_BYTES,
                ),
            )?,
        ];
        if self.artifacts != actual {
            return Err(AttestationError::ArtifactMismatch);
        }
        self.verify_digest()
    }

    fn digest(&self) -> Result<String, AttestationError> {
        let mut unsigned = self.clone();
        unsigned.attestation_sha256.clear();
        let bytes = serde_json::to_vec(&unsigned)
            .map_err(|error| AttestationError::Json(error.to_string()))?;
        let mut digest = Sha256::new();
        digest.update(ATTESTATION_DOMAIN);
        digest.update(bytes);
        Ok(hex::encode(digest.finalize()))
    }
}

pub fn sidecar_path(output: &Path) -> PathBuf {
    let name = output
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("iteron-eval-result.json");
    output.with_file_name(format!("{name}.attestation.json"))
}

pub fn write_atomic(attestation: &RunAttestation, path: &Path) -> Result<(), AttestationError> {
    attestation.verify_digest()?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|error| io(parent, error))?;
    if path.exists() {
        return Err(AttestationError::Artifact {
            path: path.display().to_string(),
            reason: "refusing to replace an existing attestation".into(),
        });
    }
    let temporary = parent.join(format!(
        ".iteron-eval-attestation-{}.tmp",
        attestation.run_id
    ));
    let bytes = serde_json::to_vec_pretty(attestation)
        .map_err(|error| AttestationError::Json(error.to_string()))?;
    if bytes.len() as u64
        > iteron_tunables::param_integer(
            "eval.attestation.max_attestation_bytes",
            MAX_ATTESTATION_BYTES,
        )
    {
        return Err(AttestationError::Artifact {
            path: path.display().to_string(),
            reason: "attestation exceeds its fixed size limit".into(),
        });
    }
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|error| io(&temporary, error))?;
    file.write_all(&bytes)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|error| io(&temporary, error))?;
    std::fs::rename(&temporary, path).map_err(|error| io(path, error))?;
    Ok(())
}

fn adapter_evidence(corpus: &CorpusManifest) -> Result<Vec<AdapterEvidence>, AttestationError> {
    let mut grouped: BTreeMap<&str, Vec<&BenchmarkReference>> = BTreeMap::new();
    for reference in corpus
        .tasks
        .iter()
        .filter_map(|task| task.benchmark.as_ref().map(|binding| &binding.reference))
    {
        grouped.entry(&reference.name).or_default().push(reference);
    }
    grouped
        .into_iter()
        .map(|(name, mut references)| {
            references.sort_by(|left, right| {
                (
                    &left.instance_id,
                    &left.dataset_revision,
                    &left.test_patch_sha256,
                )
                    .cmp(&(
                        &right.instance_id,
                        &right.dataset_revision,
                        &right.test_patch_sha256,
                    ))
            });
            let bytes = serde_json::to_vec(&references)
                .map_err(|error| AttestationError::Json(error.to_string()))?;
            let revisions = references
                .iter()
                .map(|reference| reference.dataset_revision.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let commits = references
                .iter()
                .map(|reference| reference.environment_setup_commit.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let images = references
                .iter()
                .filter_map(|reference| reference.environment_image.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            Ok(AdapterEvidence {
                name: name.into(),
                task_count: references.len().try_into().unwrap_or(u32::MAX),
                dataset_revisions: revisions,
                environment_setup_commits: commits,
                environment_images: images,
                references_sha256: hex::encode(Sha256::digest(bytes)),
            })
        })
        .collect()
}

fn artifact_digest(
    role: &str,
    path: &Path,
    maximum: u64,
) -> Result<ArtifactDigest, AttestationError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| io(path, error))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(AttestationError::Artifact {
            path: path.display().to_string(),
            reason: "artifact must be a regular non-symlink file".into(),
        });
    }
    if metadata.len() > maximum {
        return Err(AttestationError::Artifact {
            path: path.display().to_string(),
            reason: format!("artifact exceeds its fixed {maximum}-byte limit"),
        });
    }
    let mut file = std::fs::File::open(path).map_err(|error| io(path, error))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| io(path, error))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(ArtifactDigest {
        role: role.into(),
        file_name: path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| role.into()),
        bytes: metadata.len(),
        sha256: hex::encode(digest.finalize()),
    })
}

fn io(path: &Path, error: std::io::Error) -> AttestationError {
    AttestationError::Io {
        path: path.display().to_string(),
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::{BenchmarkBinding, CORPUS_SCHEMA_VERSION, Provenance, digest_tasks};
    use crate::types::Partition;

    #[test]
    fn digest_detects_attestation_mutation() {
        let mut attestation = RunAttestation {
            schema_version: 1,
            runner_version: "test".into(),
            run_id: "run".into(),
            corpus_version: "corpus".into(),
            dataset_digest: "sha256:dataset".into(),
            tunables_registry_digest: "registry".into(),
            model: "model".into(),
            provider: None,
            bundle_digest: None,
            purpose: EvaluationPurpose::Score,
            limits: ExecutionLimits {
                seeds: 1,
                minimum_seeds: 1,
                workers: 1,
                max_attempts: 1,
                max_turns: Some(1),
                run_timeout_secs: 1,
                checkout_timeout_secs: 1,
                oracle_timeout_secs: 1,
            },
            attempt_ledger_head: "0".repeat(64),
            attempt_record_count: 0,
            adapters: Vec::new(),
            artifacts: Vec::new(),
            attestation_sha256: String::new(),
        };
        attestation.attestation_sha256 = attestation.digest().unwrap();
        attestation.verify_digest().unwrap();
        attestation.model = "different".into();
        assert!(matches!(
            attestation.verify_digest(),
            Err(AttestationError::DigestMismatch)
        ));
    }

    #[test]
    fn adapter_evidence_binds_official_revision_and_reference_bytes() {
        let task = crate::corpus::CorpusTask {
            id: "instance-1".into(),
            repo_url: "https://example.invalid/repo.git".into(),
            commit: "a".repeat(40),
            prompt: "fix".into(),
            verify_command: "true".into(),
            ground_truth_command: "true".into(),
            dockerhub_tag: Some("fixture@sha256:abc".into()),
            fail_to_pass: vec!["f2p".into()],
            pass_to_pass: vec!["p2p".into()],
            test_cmd: BTreeMap::from([("python".into(), "true".into())]),
            partition: Partition::HeldOut,
            provenance: Provenance {
                source: "fixture".into(),
                task_id: "instance-1".into(),
                license: None,
            },
            benchmark: Some(BenchmarkBinding {
                reference: BenchmarkReference {
                    name: "swe-bench-pro".into(),
                    instance_id: "instance-1".into(),
                    dataset_revision: "dataset-commit".into(),
                    environment_setup_commit: "environment-commit".into(),
                    environment_image: Some("fixture@sha256:abc".into()),
                    test_patch_sha256: "b".repeat(64),
                },
                test_patch: "diff --git a/x b/x\n".into(),
            }),
        };
        let tasks = vec![task];
        let corpus = CorpusManifest {
            schema_version: CORPUS_SCHEMA_VERSION,
            corpus_version: "adapter-fixture".into(),
            dataset_digest: digest_tasks(&tasks).unwrap(),
            tasks,
        };
        let adapters = adapter_evidence(&corpus).unwrap();
        assert_eq!(adapters.len(), 1);
        assert_eq!(adapters[0].name, "swe-bench-pro");
        assert_eq!(adapters[0].task_count, 1);
        assert_eq!(adapters[0].dataset_revisions, ["dataset-commit"]);
        assert_eq!(adapters[0].references_sha256.len(), 64);
    }
}
