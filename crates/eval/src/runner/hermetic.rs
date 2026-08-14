//! Hermetic evaluation wrapper and provider-free deterministic fixture.

use super::{
    MAX_EVAL_CELLS, ParallelEvalOptions, RunnerError, run_evaluation_parallel,
    validate_parallel_options,
};
use crate::attempts::{AttemptEvent, AttemptKey, AttemptLedger};
use crate::corpus::CorpusManifest;
use crate::process::find_core;
use crate::types::{EvaluationManifest, RunStatus};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

pub const HERMETIC_RUN_SCHEMA_VERSION: u16 = 2;
pub const HERMETIC_RUN_PREVIOUS_SCHEMA_VERSION: u16 = 1;
const MAX_HERMETIC_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

/// Operator-supplied immutable identities required by the hermetic entry point. Every digest is
/// checked against an observed artifact or folded into the run-contract identity before mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HermeticRunPins {
    pub campaign_id: String,
    pub model_sha256: String,
    pub provider_revision_sha256: String,
    pub container_runtime_sha256: String,
    pub toolchain_manifest_path: PathBuf,
    pub toolchain_manifest_sha256: String,
    pub config_sha256: String,
    pub seed_schedule_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenModelProviderIdentity {
    pub model: String,
    pub model_sha256: String,
    pub provider: String,
    pub provider_revision_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HermeticRepositoryPin {
    pub task_id: String,
    pub repo_url: String,
    pub git_commit: String,
    pub dataset_revision: Option<String>,
    pub environment_setup_commit: Option<String>,
    pub environment_image: Option<String>,
    pub test_patch_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhysicalAttemptIdentity {
    pub physical_attempt_id: String,
    pub task: String,
    pub config: String,
    pub seed: u64,
    pub attempt: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HermeticRunManifest {
    pub schema_version: u16,
    pub campaign_id: String,
    pub frozen_model_provider: FrozenModelProviderIdentity,
    pub corpus_sha256: String,
    pub iteron_binary_sha256: String,
    pub toolchain_manifest_sha256: String,
    pub container_runtime_sha256: String,
    pub config_sha256: String,
    pub seed_schedule_sha256: String,
    pub reference_inputs_sha256: String,
    pub container_inputs_sha256: String,
    pub run_contract_sha256: String,
    pub evaluation_manifest_sha256: String,
    pub attempt_ledger_sha256: String,
    pub attempt_ledger_head: String,
    pub repositories: Vec<HermeticRepositoryPin>,
    pub physical_attempts: Vec<PhysicalAttemptIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HermeticRunManifestV1 {
    schema_version: u16,
    campaign_id: String,
    frozen_model_provider: FrozenModelProviderIdentity,
    corpus_sha256: String,
    iteron_binary_sha256: String,
    toolchain_manifest_sha256: String,
    container_runtime_sha256: String,
    config_sha256: String,
    seed_schedule_sha256: String,
    run_contract_sha256: String,
    evaluation_manifest_sha256: String,
    attempt_ledger_sha256: String,
    attempt_ledger_head: String,
    repositories: Vec<HermeticRepositoryPin>,
    physical_attempts: Vec<PhysicalAttemptIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HermeticFixtureReceipt {
    pub schema_id: &'static str,
    pub deterministic: bool,
    pub first_sha256: String,
    pub second_sha256: String,
    pub physical_attempts: usize,
    pub live_score_claimed: bool,
}

impl HermeticRunManifest {
    /// Strictly load the current manifest or migrate exactly N-1. Older or future schemas refuse.
    pub fn from_json(bytes: &[u8]) -> Result<Self, RunnerError> {
        if bytes.len() as u64 > MAX_HERMETIC_MANIFEST_BYTES {
            return Err(RunnerError::InvalidOption(
                "hermetic manifest exceeds its byte bound".into(),
            ));
        }
        let value = crate::strict_json::parse_json_no_duplicates(bytes)
            .map_err(|error| RunnerError::InvalidOption(error.to_string()))?;
        let schema = value
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                RunnerError::InvalidOption("hermetic schema_version is absent".into())
            })?;
        let manifest = match schema {
            version if version == HERMETIC_RUN_SCHEMA_VERSION as u64 => {
                serde_json::from_value(value)
                    .map_err(|error| RunnerError::InvalidOption(error.to_string()))?
            }
            version if version == HERMETIC_RUN_PREVIOUS_SCHEMA_VERSION as u64 => {
                let legacy: HermeticRunManifestV1 = serde_json::from_value(value)
                    .map_err(|error| RunnerError::InvalidOption(error.to_string()))?;
                let reference_inputs_sha256 = digest_serialized(&legacy.repositories)?;
                let container_inputs_sha256 = container_inputs_digest(
                    &legacy.container_runtime_sha256,
                    &legacy.repositories,
                )?;
                Self {
                    schema_version: HERMETIC_RUN_SCHEMA_VERSION,
                    campaign_id: legacy.campaign_id,
                    frozen_model_provider: legacy.frozen_model_provider,
                    corpus_sha256: legacy.corpus_sha256,
                    iteron_binary_sha256: legacy.iteron_binary_sha256,
                    toolchain_manifest_sha256: legacy.toolchain_manifest_sha256,
                    container_runtime_sha256: legacy.container_runtime_sha256,
                    config_sha256: legacy.config_sha256,
                    seed_schedule_sha256: legacy.seed_schedule_sha256,
                    reference_inputs_sha256,
                    container_inputs_sha256,
                    run_contract_sha256: legacy.run_contract_sha256,
                    evaluation_manifest_sha256: legacy.evaluation_manifest_sha256,
                    attempt_ledger_sha256: legacy.attempt_ledger_sha256,
                    attempt_ledger_head: legacy.attempt_ledger_head,
                    repositories: legacy.repositories,
                    physical_attempts: legacy.physical_attempts,
                }
            }
            actual => {
                return Err(RunnerError::InvalidOption(format!(
                    "hermetic schema_version {actual} is unsupported"
                )));
            }
        };
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<(), RunnerError> {
        if self.schema_version != HERMETIC_RUN_SCHEMA_VERSION
            || !valid_hermetic_id(&self.campaign_id)
            || self.frozen_model_provider.model.trim().is_empty()
            || self.frozen_model_provider.provider.trim().is_empty()
        {
            return Err(RunnerError::InvalidOption(
                "hermetic manifest identity is invalid".into(),
            ));
        }
        for digest in [
            &self.frozen_model_provider.model_sha256,
            &self.frozen_model_provider.provider_revision_sha256,
            &self.corpus_sha256,
            &self.iteron_binary_sha256,
            &self.toolchain_manifest_sha256,
            &self.container_runtime_sha256,
            &self.config_sha256,
            &self.seed_schedule_sha256,
            &self.reference_inputs_sha256,
            &self.container_inputs_sha256,
            &self.run_contract_sha256,
            &self.evaluation_manifest_sha256,
            &self.attempt_ledger_sha256,
        ] {
            validate_hermetic_digest(digest)?;
        }
        if !valid_raw_sha256(&self.attempt_ledger_head)
            || self.repositories.is_empty()
            || self.physical_attempts.is_empty()
            || self.reference_inputs_sha256 != digest_serialized(&self.repositories)?
            || self.container_inputs_sha256
                != container_inputs_digest(&self.container_runtime_sha256, &self.repositories)?
        {
            return Err(RunnerError::InvalidOption(
                "hermetic manifest correlation is invalid".into(),
            ));
        }
        let observed = HermeticObservedInputs {
            corpus_sha256: self.corpus_sha256.clone(),
            iteron_binary_sha256: self.iteron_binary_sha256.clone(),
            toolchain_manifest_sha256: self.toolchain_manifest_sha256.clone(),
            reference_inputs_sha256: self.reference_inputs_sha256.clone(),
            container_inputs_sha256: self.container_inputs_sha256.clone(),
        };
        if self.run_contract_sha256
            != digest_serialized(&(
                &self.campaign_id,
                &self.frozen_model_provider,
                &observed,
                &self.container_runtime_sha256,
                &self.config_sha256,
                &self.seed_schedule_sha256,
            ))?
        {
            return Err(RunnerError::InvalidOption(
                "hermetic run contract digest is invalid".into(),
            ));
        }
        let mut attempts = self.physical_attempts.clone();
        attempts.sort();
        if attempts != self.physical_attempts
            || attempts
                .windows(2)
                .any(|pair| pair[0].physical_attempt_id == pair[1].physical_attempt_id)
        {
            return Err(RunnerError::InvalidOption(
                "physical attempt identities are not unique and sorted".into(),
            ));
        }
        Ok(())
    }
}

/// Hermetic runner entry point. The legacy entry point remains available but makes no hermetic
/// claim; callers must supply and match every immutable identity here.
pub async fn run_evaluation_hermetic(
    options: &ParallelEvalOptions,
    pins: &HermeticRunPins,
) -> Result<(EvaluationManifest, HermeticRunManifest), RunnerError> {
    validate_parallel_options(options)?;
    validate_hermetic_pins(options, pins)?;
    for path in [
        options.output_path.clone(),
        crate::attempts::sidecar_path(&options.output_path),
        crate::attestation::sidecar_path(&options.output_path),
        hermetic_sidecar_path(&options.output_path),
    ] {
        if path
            .try_exists()
            .map_err(|source| RunnerError::WriteArtifact {
                path: path.display().to_string(),
                source,
            })?
        {
            return Err(RunnerError::InvalidOption(format!(
                "hermetic output `{}` must be create-new",
                path.display()
            )));
        }
    }
    let corpus = CorpusManifest::load(&options.corpus_path)?;
    let repositories = repository_pins(&corpus);
    validate_repository_pins(&repositories)?;
    let core = find_core(options.core_bin.as_deref())?;
    let observed = HermeticObservedInputs {
        corpus_sha256: digest_regular_file(&options.corpus_path, 4 * 1024 * 1024)?,
        iteron_binary_sha256: digest_regular_file(&core, 1024 * 1024 * 1024)?,
        toolchain_manifest_sha256: digest_regular_file(
            &pins.toolchain_manifest_path,
            16 * 1024 * 1024,
        )?,
        reference_inputs_sha256: digest_serialized(&repositories)?,
        container_inputs_sha256: container_inputs_digest(
            &pins.container_runtime_sha256,
            &repositories,
        )?,
    };
    if observed.toolchain_manifest_sha256 != pins.toolchain_manifest_sha256 {
        return Err(RunnerError::InvalidOption(
            "toolchain manifest does not match its immutable pin".into(),
        ));
    }
    let frozen_model_provider = FrozenModelProviderIdentity {
        model: options.model.clone(),
        model_sha256: pins.model_sha256.clone(),
        provider: options
            .provider
            .clone()
            .ok_or_else(|| RunnerError::InvalidOption("provider must be explicit".into()))?,
        provider_revision_sha256: pins.provider_revision_sha256.clone(),
    };
    let run_contract_sha256 = digest_serialized(&(
        &pins.campaign_id,
        &frozen_model_provider,
        &observed,
        &pins.container_runtime_sha256,
        &pins.config_sha256,
        &pins.seed_schedule_sha256,
    ))?;
    let evaluation = run_evaluation_parallel(options).await?;
    let attempt_path = crate::attempts::sidecar_path(&options.output_path);
    let ledger = AttemptLedger::open(&attempt_path)?;
    let physical_attempts =
        load_physical_attempts(&attempt_path, &pins.campaign_id, &run_contract_sha256)?;
    let post_repositories = repository_pins(&CorpusManifest::load(&options.corpus_path)?);
    validate_repository_pins(&post_repositories)?;
    let post = HermeticObservedInputs {
        corpus_sha256: digest_regular_file(&options.corpus_path, 4 * 1024 * 1024)?,
        iteron_binary_sha256: digest_regular_file(&core, 1024 * 1024 * 1024)?,
        toolchain_manifest_sha256: digest_regular_file(
            &pins.toolchain_manifest_path,
            16 * 1024 * 1024,
        )?,
        reference_inputs_sha256: digest_serialized(&post_repositories)?,
        container_inputs_sha256: container_inputs_digest(
            &pins.container_runtime_sha256,
            &post_repositories,
        )?,
    };
    if observed != post {
        return Err(RunnerError::InvalidOption(
            "a hermetic input changed during execution".into(),
        ));
    }
    let manifest = HermeticRunManifest {
        schema_version: HERMETIC_RUN_SCHEMA_VERSION,
        campaign_id: pins.campaign_id.clone(),
        frozen_model_provider,
        corpus_sha256: observed.corpus_sha256,
        iteron_binary_sha256: observed.iteron_binary_sha256,
        toolchain_manifest_sha256: observed.toolchain_manifest_sha256,
        container_runtime_sha256: pins.container_runtime_sha256.clone(),
        config_sha256: pins.config_sha256.clone(),
        seed_schedule_sha256: pins.seed_schedule_sha256.clone(),
        reference_inputs_sha256: observed.reference_inputs_sha256,
        container_inputs_sha256: observed.container_inputs_sha256,
        run_contract_sha256,
        evaluation_manifest_sha256: digest_regular_file(&options.output_path, 256 * 1024 * 1024)?,
        attempt_ledger_sha256: digest_regular_file(&attempt_path, 64 * 1024 * 1024)?,
        attempt_ledger_head: ledger.head_hash().into(),
        repositories,
        physical_attempts,
    };
    manifest.validate()?;
    write_hermetic_manifest(&manifest, &hermetic_sidecar_path(&options.output_path))?;
    Ok((evaluation, manifest))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct HermeticObservedInputs {
    corpus_sha256: String,
    iteron_binary_sha256: String,
    toolchain_manifest_sha256: String,
    reference_inputs_sha256: String,
    container_inputs_sha256: String,
}

pub fn hermetic_config_sha256(options: &ParallelEvalOptions) -> Result<String, RunnerError> {
    digest_serialized(&serde_json::json!({
        "allow_local_repositories": options.allow_local_repositories,
        "model": &options.model,
        "provider": &options.provider,
        "purpose": options.purpose,
        "seeds": options.seeds,
        "minimum_seeds": options.minimum_seeds,
        "run_timeout_secs": options.run_timeout.as_secs(),
        "checkout_timeout_secs": options.checkout_timeout.as_secs(),
        "oracle_timeout_secs": options.oracle_timeout.as_secs(),
        "workers": options.workers,
        "max_turns": options.max_turns,
        "uncapped": options.uncapped,
        "max_attempts": options.max_attempts,
    }))
}

pub fn hermetic_seed_schedule_sha256(seeds: u64) -> Result<String, RunnerError> {
    if seeds == 0 || seeds > MAX_EVAL_CELLS as u64 {
        return Err(RunnerError::InvalidOption(
            "hermetic seed schedule is outside its bound".into(),
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(b"iteron-eval/hermetic-seeds/v1\0");
    for seed in 0..seeds {
        hasher.update(seed.to_le_bytes());
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn validate_hermetic_pins(
    options: &ParallelEvalOptions,
    pins: &HermeticRunPins,
) -> Result<(), RunnerError> {
    if !valid_hermetic_id(&pins.campaign_id)
        || options.provider.as_deref().is_none_or(str::is_empty)
        || !pins.toolchain_manifest_path.is_absolute()
    {
        return Err(RunnerError::InvalidOption(
            "hermetic campaign and provider identities must be explicit".into(),
        ));
    }
    for digest in [
        &pins.model_sha256,
        &pins.provider_revision_sha256,
        &pins.container_runtime_sha256,
        &pins.toolchain_manifest_sha256,
        &pins.config_sha256,
        &pins.seed_schedule_sha256,
    ] {
        validate_hermetic_digest(digest)?;
    }
    if pins.config_sha256 != hermetic_config_sha256(options)? {
        return Err(RunnerError::InvalidOption(
            "evaluation configuration does not match its immutable pin".into(),
        ));
    }
    if pins.seed_schedule_sha256 != hermetic_seed_schedule_sha256(options.seeds)? {
        return Err(RunnerError::InvalidOption(
            "seed schedule does not match its immutable pin".into(),
        ));
    }
    Ok(())
}

fn valid_hermetic_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':')
        })
}

fn validate_hermetic_digest(value: &str) -> Result<(), RunnerError> {
    value
        .strip_prefix("sha256:")
        .filter(|digest| valid_raw_sha256(digest))
        .map(|_| ())
        .ok_or_else(|| RunnerError::InvalidOption("hermetic digest is invalid".into()))
}

fn valid_raw_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digest_serialized(value: &impl Serialize) -> Result<String, RunnerError> {
    let bytes = serde_json::to_vec(value).map_err(RunnerError::Encode)?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn digest_regular_file(path: &Path, maximum: u64) -> Result<String, RunnerError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|source| RunnerError::WriteArtifact {
            path: path.display().to_string(),
            source,
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        return Err(RunnerError::InvalidOption(format!(
            "hermetic input `{}` is not a bounded regular file",
            path.display()
        )));
    }
    let mut input = std::io::Read::take(
        std::fs::File::open(path).map_err(|source| RunnerError::WriteArtifact {
            path: path.display().to_string(),
            source,
        })?,
        maximum.saturating_add(1),
    );
    let mut hasher = Sha256::new();
    let mut bytes = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = std::io::Read::read(&mut input, &mut bytes).map_err(|source| {
            RunnerError::WriteArtifact {
                path: path.display().to_string(),
                source,
            }
        })?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > maximum {
            return Err(RunnerError::InvalidOption(format!(
                "hermetic input `{}` exceeds its byte bound",
                path.display()
            )));
        }
        hasher.update(&bytes[..read]);
    }
    if total != metadata.len() {
        return Err(RunnerError::InvalidOption(format!(
            "hermetic input `{}` changed while being read",
            path.display()
        )));
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn repository_pins(corpus: &CorpusManifest) -> Vec<HermeticRepositoryPin> {
    let mut pins = corpus
        .tasks
        .iter()
        .map(|task| HermeticRepositoryPin {
            task_id: task.id.clone(),
            repo_url: task.repo_url.clone(),
            git_commit: task.commit.clone(),
            dataset_revision: task
                .benchmark
                .as_ref()
                .map(|binding| binding.reference.dataset_revision.clone()),
            environment_setup_commit: task
                .benchmark
                .as_ref()
                .map(|binding| binding.reference.environment_setup_commit.clone()),
            environment_image: task
                .benchmark
                .as_ref()
                .and_then(|binding| binding.reference.environment_image.clone()),
            test_patch_sha256: task
                .benchmark
                .as_ref()
                .map(|binding| binding.reference.test_patch_sha256.clone()),
        })
        .collect::<Vec<_>>();
    pins.sort();
    pins
}

fn validate_repository_pins(repositories: &[HermeticRepositoryPin]) -> Result<(), RunnerError> {
    if repositories.is_empty() {
        return Err(RunnerError::InvalidOption(
            "hermetic corpus has no repository pins".into(),
        ));
    }
    for pin in repositories {
        let commit = pin.git_commit.as_bytes();
        let immutable_commit = matches!(commit.len(), 40 | 64)
            && commit
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte));
        let immutable_image = pin.environment_image.as_deref().is_none_or(|image| {
            image
                .rsplit_once("@sha256:")
                .is_some_and(|(_, digest)| valid_raw_sha256(digest))
        });
        let immutable_environment = pin
            .environment_setup_commit
            .as_deref()
            .is_none_or(|digest| {
                matches!(digest.len(), 40 | 64)
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            });
        let immutable_patch = pin
            .test_patch_sha256
            .as_deref()
            .is_none_or(|digest| digest.strip_prefix("sha256:").is_some_and(valid_raw_sha256));
        if !valid_hermetic_id(&pin.task_id)
            || pin.repo_url.is_empty()
            || !immutable_commit
            || !immutable_image
            || !immutable_environment
            || !immutable_patch
        {
            return Err(RunnerError::InvalidOption(format!(
                "repository/container/reference pin is not immutable for task {}",
                pin.task_id
            )));
        }
    }
    Ok(())
}

fn container_inputs_digest(
    runtime_sha256: &str,
    repositories: &[HermeticRepositoryPin],
) -> Result<String, RunnerError> {
    let images = repositories
        .iter()
        .filter_map(|pin| pin.environment_image.as_ref())
        .collect::<Vec<_>>();
    digest_serialized(&(runtime_sha256, images))
}

#[derive(Deserialize)]
struct AttemptLedgerProbe {
    event: AttemptEvent,
}

fn load_physical_attempts(
    path: &Path,
    campaign_id: &str,
    run_contract_sha256: &str,
) -> Result<Vec<PhysicalAttemptIdentity>, RunnerError> {
    let input = std::fs::File::open(path).map_err(|source| RunnerError::WriteArtifact {
        path: path.display().to_string(),
        source,
    })?;
    let mut attempts = Vec::new();
    for line in std::io::BufReader::new(input).lines() {
        let line = line.map_err(|source| RunnerError::WriteArtifact {
            path: path.display().to_string(),
            source,
        })?;
        if line.is_empty() {
            continue;
        }
        let record: AttemptLedgerProbe = serde_json::from_str(&line)
            .map_err(|error| RunnerError::InvalidOption(error.to_string()))?;
        let AttemptEvent::Planned { key } = record.event else {
            continue;
        };
        let physical_attempt_id = digest_serialized(&(
            "iteron-eval/physical-attempt/v1",
            campaign_id,
            run_contract_sha256,
            &key,
        ))?;
        attempts.push(PhysicalAttemptIdentity {
            physical_attempt_id,
            task: key.task,
            config: key.config,
            seed: key.seed,
            attempt: key.attempt,
        });
    }
    attempts.sort();
    if attempts.is_empty()
        || attempts
            .windows(2)
            .any(|pair| pair[0].physical_attempt_id == pair[1].physical_attempt_id)
    {
        return Err(RunnerError::InvalidOption(
            "attempt ledger has no unique durable physical attempts".into(),
        ));
    }
    Ok(attempts)
}

pub fn hermetic_sidecar_path(output: &Path) -> PathBuf {
    let name = output
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("iteron-eval-result.json");
    output.with_file_name(format!("{name}.hermetic.json"))
}

fn write_hermetic_manifest(manifest: &HermeticRunManifest, path: &Path) -> Result<(), RunnerError> {
    let bytes = serde_json::to_vec_pretty(manifest).map_err(RunnerError::Encode)?;
    if bytes.len() as u64 > MAX_HERMETIC_MANIFEST_BYTES {
        return Err(RunnerError::InvalidOption(
            "hermetic manifest exceeds its byte bound".into(),
        ));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|source| RunnerError::CreatePath {
        path: parent.display().to_string(),
        source,
    })?;
    let temporary = parent.join(format!(".iteron-hermetic-{}.tmp", manifest.campaign_id));
    let mut output = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|source| RunnerError::WriteArtifact {
            path: temporary.display().to_string(),
            source,
        })?;
    output
        .write_all(&bytes)
        .and_then(|()| output.write_all(b"\n"))
        .and_then(|()| output.sync_all())
        .map_err(|source| RunnerError::WriteArtifact {
            path: temporary.display().to_string(),
            source,
        })?;
    if path.exists() {
        return Err(RunnerError::InvalidOption(
            "refusing to replace an existing hermetic manifest".into(),
        ));
    }
    std::fs::rename(&temporary, path).map_err(|source| RunnerError::WriteArtifact {
        path: path.display().to_string(),
        source,
    })
}

/// Provider-free deterministic engineering fixture. It constructs the same pinned synthetic run
/// twice and requires byte identity; it intentionally produces no benchmark score.
pub(super) fn deterministic_hermetic_manifest() -> Result<HermeticRunManifest, RunnerError> {
    static NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let fixture_root = std::env::temp_dir().join(format!(
        "iteron-hermetic-fixture-{}-{}",
        std::process::id(),
        NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir(&fixture_root).map_err(|source| RunnerError::CreatePath {
        path: fixture_root.display().to_string(),
        source,
    })?;
    let result = (|| {
        let repositories = vec![HermeticRepositoryPin {
            task_id: "synthetic-held-out-001".into(),
            repo_url: "https://example.invalid/iteron/hermetic-fixture.git".into(),
            git_commit: "1".repeat(40),
            dataset_revision: Some("synthetic-fixture-v1".into()),
            environment_setup_commit: Some("2".repeat(40)),
            environment_image: Some(format!("fixture.invalid/iteron@sha256:{}", "3".repeat(64))),
            test_patch_sha256: Some(format!("sha256:{}", "4".repeat(64))),
        }];
        let frozen_model_provider = FrozenModelProviderIdentity {
            model: "synthetic/frozen-model-v1".into(),
            model_sha256: format!("sha256:{}", "5".repeat(64)),
            provider: "synthetic-provider".into(),
            provider_revision_sha256: format!("sha256:{}", "6".repeat(64)),
        };
        let observed = HermeticObservedInputs {
            corpus_sha256: format!("sha256:{}", "7".repeat(64)),
            iteron_binary_sha256: format!("sha256:{}", "8".repeat(64)),
            toolchain_manifest_sha256: format!("sha256:{}", "9".repeat(64)),
            reference_inputs_sha256: digest_serialized(&repositories)?,
            container_inputs_sha256: container_inputs_digest(
                &format!("sha256:{}", "a".repeat(64)),
                &repositories,
            )?,
        };
        let config_sha256 = format!("sha256:{}", "b".repeat(64));
        let seed_schedule_sha256 = hermetic_seed_schedule_sha256(2)?;
        let run_contract_sha256 = digest_serialized(&(
            "synthetic-two-run",
            &frozen_model_provider,
            &observed,
            &format!("sha256:{}", "a".repeat(64)),
            &config_sha256,
            &seed_schedule_sha256,
        ))?;
        let ledger_path = fixture_root.join("physical-attempts.jsonl");
        let mut ledger = AttemptLedger::create(&ledger_path)?;
        for seed in [0_u64, 1] {
            let key = AttemptKey {
                task: "synthetic-held-out-001".into(),
                config: "verify_ON".into(),
                seed,
                attempt: 1,
            };
            ledger.append(AttemptEvent::Planned { key: key.clone() })?;
            ledger.append(AttemptEvent::Started { key: key.clone() })?;
            ledger.append(AttemptEvent::Finished {
                key,
                run_status: RunStatus::Completed,
                failure_phase: None,
            })?;
        }
        let attempt_ledger_head = ledger.head_hash().to_owned();
        drop(ledger);
        let physical_attempts =
            load_physical_attempts(&ledger_path, "synthetic-two-run", &run_contract_sha256)?;
        let manifest = HermeticRunManifest {
            schema_version: HERMETIC_RUN_SCHEMA_VERSION,
            campaign_id: "synthetic-two-run".into(),
            frozen_model_provider,
            corpus_sha256: observed.corpus_sha256,
            iteron_binary_sha256: observed.iteron_binary_sha256,
            toolchain_manifest_sha256: observed.toolchain_manifest_sha256,
            container_runtime_sha256: format!("sha256:{}", "a".repeat(64)),
            config_sha256,
            seed_schedule_sha256,
            reference_inputs_sha256: observed.reference_inputs_sha256,
            container_inputs_sha256: observed.container_inputs_sha256,
            run_contract_sha256,
            evaluation_manifest_sha256: format!("sha256:{}", "c".repeat(64)),
            attempt_ledger_sha256: digest_regular_file(&ledger_path, 64 * 1024 * 1024)?,
            attempt_ledger_head,
            repositories,
            physical_attempts,
        };
        manifest.validate()?;
        Ok(manifest)
    })();
    let _ = std::fs::remove_dir_all(&fixture_root);
    result
}

/// Provider-free deterministic engineering fixture. It executes two physical-attempt ledgers for
/// the same pinned synthetic run and requires byte identity; it is not an evaluation campaign and
/// intentionally produces no benchmark score.
pub fn deterministic_hermetic_fixture() -> Result<HermeticFixtureReceipt, RunnerError> {
    let first =
        serde_json::to_vec(&deterministic_hermetic_manifest()?).map_err(RunnerError::Encode)?;
    let second =
        serde_json::to_vec(&deterministic_hermetic_manifest()?).map_err(RunnerError::Encode)?;
    let first_sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&first)));
    let second_sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&second)));
    if first != second || first_sha256 != second_sha256 {
        return Err(RunnerError::InvalidOption(
            "two-run hermetic fixture is not deterministic".into(),
        ));
    }
    let physical_attempts = HermeticRunManifest::from_json(&first)?
        .physical_attempts
        .len();
    Ok(HermeticFixtureReceipt {
        schema_id: "iteron-eval/hermetic-two-run-fixture/1",
        deterministic: true,
        first_sha256,
        second_sha256,
        physical_attempts,
        live_score_claimed: false,
    })
}

pub fn run_hermetic_fixture_cli(args: &[String]) -> std::process::ExitCode {
    let result = (|| -> Result<HermeticFixtureReceipt, RunnerError> {
        let [flag, output] = args else {
            return Err(RunnerError::InvalidOption(
                "expected --output followed by one create-new path".into(),
            ));
        };
        if flag != "--output" {
            return Err(RunnerError::InvalidOption(
                "expected --output followed by one create-new path".into(),
            ));
        }
        let output = Path::new(output);
        if !output.is_absolute() {
            return Err(RunnerError::InvalidOption(
                "hermetic fixture output must be absolute".into(),
            ));
        }
        let receipt = deterministic_hermetic_fixture()?;
        let bytes = serde_json::to_vec_pretty(&receipt).map_err(RunnerError::Encode)?;
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(output)
            .map_err(|source| RunnerError::WriteArtifact {
                path: output.display().to_string(),
                source,
            })?;
        file.write_all(&bytes)
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .map_err(|source| RunnerError::WriteArtifact {
                path: output.display().to_string(),
                source,
            })?;
        Ok(receipt)
    })();
    match result {
        Ok(receipt) => match serde_json::to_writer(io::stdout().lock(), &receipt) {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(_) => std::process::ExitCode::from(2),
        },
        Err(error) => {
            eprintln!("iteron hermetic fixture: {error}");
            std::process::ExitCode::from(2)
        }
    }
}
