//! Version-pinned open-harness adapter whose candidates are scored only by Core's oracle.
//!
//! The pinned coordinator is a provider-facing trust boundary and therefore is not wrapped in the
//! repository sandbox that strips provider credentials and denies all network. Its task execution
//! environment must independently deny repository egress (the checked-in SWE-agent spec passes
//! Docker `--network=none` and does not pass provider credentials). The captured diff is then
//! scored again by Core's egress-off oracle.

use crate::corpus::CorpusTask;
use crate::process::{ProcessSpec, run_process};
use crate::runner::{materialize_repository, score_candidate_diff};
use crate::types::TwoSidedOracleReceipt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const HARNESS_OUTPUT_LIMIT: usize = 8 * 1024 * 1024;
const HARNESS_SPEC_LIMIT: u64 = 256 * 1024;
const MAX_HARNESS_ARGUMENTS: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CandidateOutput {
    #[default]
    StdoutJson,
    /// SWE-agent's pinned single-run prediction artifact.
    SweAgentPrediction {
        /// May use the same substitutions as `arguments`, including `{artifact_dir}`.
        path: String,
    },
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceHarnessSpec {
    pub name: String,
    pub source_url: String,
    /// Full immutable Git object id for the external harness source.
    pub revision: String,
    /// Host launcher, for example `python3`.
    pub launcher: String,
    /// Repository-relative, tracked wrapper/entrypoint.
    pub entrypoint: String,
    /// Arguments support `{workspace}`, `{repo_url}`, `{commit}`, `{task_id}`, `{prompt}`,
    /// `{model}`, `{provider}`, `{dockerhub_tag}`, and `{artifact_dir}` substitutions.
    pub arguments: Vec<String>,
    #[serde(default)]
    pub candidate_output: CandidateOutput,
}

impl ReferenceHarnessSpec {
    pub fn load(path: &Path) -> Result<Self, ReferenceHarnessError> {
        let file = std::fs::File::open(path)
            .map_err(|error| ReferenceHarnessError::SpecRead(error.to_string()))?;
        let mut bytes = Vec::new();
        file.take(
            iteron_tunables::param_integer(
                "eval.reference_harness.harness_spec_limit",
                HARNESS_SPEC_LIMIT,
            ) + 1,
        )
        .read_to_end(&mut bytes)
        .map_err(|error| ReferenceHarnessError::SpecRead(error.to_string()))?;
        if bytes.len() as u64
            > iteron_tunables::param_integer(
                "eval.reference_harness.harness_spec_limit",
                HARNESS_SPEC_LIMIT,
            )
        {
            return Err(ReferenceHarnessError::InvalidSpec(
                "reference-harness spec exceeds 256 KiB".into(),
            ));
        }
        let spec: Self = serde_json::from_slice(&bytes)
            .map_err(|error| ReferenceHarnessError::InvalidSpec(error.to_string()))?;
        spec.validate()?;
        Ok(spec)
    }

    pub fn validate(&self) -> Result<(), ReferenceHarnessError> {
        if self.name.trim().is_empty()
            || self.name.len() > 256
            || self.launcher.trim().is_empty()
            || self.launcher.len() > 1_024
            || self.entrypoint.trim().is_empty()
            || self.entrypoint.len() > 2_048
            || self.arguments.len()
                > iteron_tunables::param_integer(
                    "eval.reference_harness.max_harness_arguments",
                    MAX_HARNESS_ARGUMENTS,
                )
        {
            return Err(ReferenceHarnessError::InvalidSpec(
                "name, launcher, entrypoint, or argument count is outside its bound".into(),
            ));
        }
        if !is_git_oid(&self.revision) {
            return Err(ReferenceHarnessError::InvalidSpec(
                "revision must be a full lowercase Git object id".into(),
            ));
        }
        let url = url::Url::parse(&self.source_url).map_err(|error| {
            ReferenceHarnessError::InvalidSpec(format!("invalid source_url: {error}"))
        })?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(ReferenceHarnessError::InvalidSpec(
                "source_url must be a credential-free HTTPS URL".into(),
            ));
        }
        let entrypoint = Path::new(&self.entrypoint);
        if entrypoint.is_absolute()
            || entrypoint
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(ReferenceHarnessError::InvalidSpec(
                "entrypoint must stay inside the pinned source checkout".into(),
            ));
        }
        for argument in &self.arguments {
            if argument.len() > 64 * 1024 || argument.contains('\0') {
                return Err(ReferenceHarnessError::InvalidSpec(
                    "harness argument exceeds its bound or contains NUL".into(),
                ));
            }
        }
        if let CandidateOutput::SweAgentPrediction { path } = &self.candidate_output
            && (path.trim().is_empty() || path.len() > 8 * 1024 || path.contains('\0'))
        {
            return Err(ReferenceHarnessError::InvalidSpec(
                "candidate prediction path is empty, too long, or contains NUL".into(),
            ));
        }
        if self.candidate_output == CandidateOutput::Unknown {
            return Err(ReferenceHarnessError::InvalidSpec(
                "unknown candidate output kind".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedHarnessCandidate {
    pub schema_version: u32,
    pub candidate_diff: String,
    /// Retained for audit only. `score_candidate` never consults this field.
    pub self_reported_resolved: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceHarnessScore {
    pub harness: String,
    pub harness_revision: String,
    pub self_reported_resolved: Option<bool>,
    pub core_oracle: TwoSidedOracleReceipt,
}

impl ReferenceHarnessScore {
    pub fn resolved(&self) -> bool {
        self.core_oracle.resolved
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReferenceHarnessError {
    #[error("cannot read reference-harness spec: {0}")]
    SpecRead(String),
    #[error("invalid reference-harness spec: {0}")]
    InvalidSpec(String),
    #[error("reference-harness checkout is not pinned and clean: {0}")]
    UnpinnedCheckout(String),
    #[error("reference harness failed: {0}")]
    Execution(String),
    #[error("reference harness output is not the strict candidate contract: {0}")]
    Output(String),
    #[error("Core oracle could not score the reference harness candidate: {0}")]
    Oracle(String),
}

#[derive(Debug, Clone)]
pub struct ReferenceHarnessAdapter {
    spec: ReferenceHarnessSpec,
    source_checkout: PathBuf,
}

impl ReferenceHarnessAdapter {
    pub async fn materialize(
        spec: ReferenceHarnessSpec,
        source_checkout: PathBuf,
        timeout: Duration,
    ) -> Result<Self, ReferenceHarnessError> {
        spec.validate()?;
        if source_checkout.exists() {
            return Err(ReferenceHarnessError::UnpinnedCheckout(format!(
                "refusing to reuse existing checkout `{}`",
                source_checkout.display()
            )));
        }
        let parent = source_checkout.parent().ok_or_else(|| {
            ReferenceHarnessError::UnpinnedCheckout(
                "source checkout does not have a parent directory".into(),
            )
        })?;
        std::fs::create_dir_all(parent)
            .map_err(|error| ReferenceHarnessError::UnpinnedCheckout(error.to_string()))?;
        let clone = run_process(&ProcessSpec {
            program: PathBuf::from("git"),
            args: vec![
                "clone".into(),
                "--quiet".into(),
                "--no-checkout".into(),
                "--no-tags".into(),
                "--filter=blob:none".into(),
                "--".into(),
                spec.source_url.clone().into(),
                source_checkout.as_os_str().to_owned(),
            ],
            cwd: None,
            clear_env: false,
            inherit_env: Vec::new(),
            env: clean_git_environment(),
            timeout,
            max_output_bytes: iteron_tunables::param_integer(
                "eval.reference_harness.harness_output_limit",
                HARNESS_OUTPUT_LIMIT,
            ),
        })
        .await
        .map_err(|error| ReferenceHarnessError::Execution(error.to_string()))?;
        if !clone.success() {
            return Err(ReferenceHarnessError::Execution(format!(
                "pinned harness clone failed with exit {}",
                clone.exit_code
            )));
        }
        let checkout = run_process(&ProcessSpec {
            program: PathBuf::from("git"),
            args: vec![
                "checkout".into(),
                "--quiet".into(),
                "--detach".into(),
                spec.revision.clone().into(),
            ],
            cwd: Some(source_checkout.clone()),
            clear_env: false,
            inherit_env: Vec::new(),
            env: clean_git_environment(),
            timeout,
            max_output_bytes: iteron_tunables::param_integer(
                "eval.reference_harness.harness_output_limit",
                HARNESS_OUTPUT_LIMIT,
            ),
        })
        .await
        .map_err(|error| ReferenceHarnessError::Execution(error.to_string()))?;
        if !checkout.success() {
            return Err(ReferenceHarnessError::Execution(format!(
                "pinned harness checkout failed with exit {}",
                checkout.exit_code
            )));
        }
        Self::new(spec, source_checkout)
    }

    pub fn new(
        spec: ReferenceHarnessSpec,
        source_checkout: PathBuf,
    ) -> Result<Self, ReferenceHarnessError> {
        spec.validate()?;
        validate_checkout(&spec, &source_checkout)?;
        Ok(Self {
            spec,
            source_checkout,
        })
    }

    pub fn spec(&self) -> &ReferenceHarnessSpec {
        &self.spec
    }

    pub async fn capture_candidate(
        &self,
        task: &CorpusTask,
        workspace: &Path,
        model: &str,
        provider: Option<&str>,
        timeout: Duration,
    ) -> Result<CapturedHarnessCandidate, ReferenceHarnessError> {
        materialize_repository(task, workspace, timeout)
            .await
            .map_err(|error| {
                ReferenceHarnessError::Execution(format!(
                    "cannot materialize pinned task workspace: {error}"
                ))
            })?;
        let workspace = workspace.canonicalize().map_err(|error| {
            ReferenceHarnessError::Execution(format!(
                "cannot canonicalize pinned task workspace: {error}"
            ))
        })?;
        let artifact_key = hex::encode(Sha256::digest(format!("{}\0{model}", task.id).as_bytes()));
        let artifact_dir = workspace
            .parent()
            .unwrap_or(&workspace)
            .join(".iteron-eval-reference")
            .join(artifact_key);
        if artifact_dir.exists() {
            return Err(ReferenceHarnessError::Execution(format!(
                "refusing to reuse reference-harness artifact directory `{}`",
                artifact_dir.display()
            )));
        }
        std::fs::create_dir_all(&artifact_dir)
            .map_err(|error| ReferenceHarnessError::Execution(error.to_string()))?;
        let entrypoint = self.source_checkout.join(&self.spec.entrypoint);
        let entrypoint_metadata = std::fs::symlink_metadata(&entrypoint).map_err(|error| {
            ReferenceHarnessError::Execution(format!(
                "cannot inspect pinned harness entrypoint: {error}"
            ))
        })?;
        let canonical_source = self.source_checkout.canonicalize().map_err(|error| {
            ReferenceHarnessError::Execution(format!(
                "cannot canonicalize pinned harness checkout: {error}"
            ))
        })?;
        let canonical_entrypoint = entrypoint.canonicalize().map_err(|error| {
            ReferenceHarnessError::Execution(format!(
                "cannot canonicalize pinned harness entrypoint: {error}"
            ))
        })?;
        if entrypoint_metadata.file_type().is_symlink()
            || !entrypoint_metadata.is_file()
            || !canonical_entrypoint.starts_with(&canonical_source)
        {
            return Err(ReferenceHarnessError::Execution(
                "pinned harness entrypoint must be a regular non-symlink file inside its checkout"
                    .into(),
            ));
        }
        let mut args = vec![canonical_entrypoint.as_os_str().to_owned()];
        args.extend(self.spec.arguments.iter().map(|argument| {
            expand_argument(argument, task, &workspace, &artifact_dir, model, provider).into()
        }));
        let output = run_process(&ProcessSpec {
            program: PathBuf::from(&self.spec.launcher),
            args,
            cwd: Some(self.source_checkout.clone()),
            clear_env: false,
            inherit_env: Vec::new(),
            env: Vec::new(),
            timeout,
            max_output_bytes: iteron_tunables::param_integer(
                "eval.reference_harness.harness_output_limit",
                HARNESS_OUTPUT_LIMIT,
            ),
        })
        .await
        .map_err(|error| ReferenceHarnessError::Execution(error.to_string()))?;
        if output.timed_out {
            return Err(ReferenceHarnessError::Execution(
                "wall-clock timeout expired".into(),
            ));
        }
        if !output.success() {
            return Err(ReferenceHarnessError::Execution(format!(
                "exit={}, stdout_truncated={}, stderr_truncated={}",
                output.exit_code, output.stdout_truncated, output.stderr_truncated
            )));
        }
        let candidate = match &self.spec.candidate_output {
            CandidateOutput::StdoutJson => {
                if output.stdout_truncated {
                    return Err(ReferenceHarnessError::Output(
                        "stdout candidate contract was truncated".into(),
                    ));
                }
                serde_json::from_slice(&output.stdout)
                    .map_err(|error| ReferenceHarnessError::Output(error.to_string()))?
            }
            CandidateOutput::SweAgentPrediction { path } => {
                let expanded =
                    expand_argument(path, task, &workspace, &artifact_dir, model, provider);
                let prediction_path = PathBuf::from(expanded);
                let relative_prediction = prediction_path.strip_prefix(&artifact_dir);
                if !prediction_path.is_absolute()
                    || relative_prediction.is_err()
                    || relative_prediction.is_ok_and(|relative| {
                        relative
                            .components()
                            .any(|component| matches!(component, std::path::Component::ParentDir))
                    })
                {
                    return Err(ReferenceHarnessError::Output(
                        "SWE-agent prediction path escapes the fresh artifact directory".into(),
                    ));
                }
                let canonical_artifact_dir = artifact_dir.canonicalize().map_err(|error| {
                    ReferenceHarnessError::Output(format!(
                        "cannot canonicalize reference artifact directory: {error}"
                    ))
                })?;
                let canonical_prediction = prediction_path.canonicalize().map_err(|error| {
                    ReferenceHarnessError::Output(format!(
                        "cannot canonicalize SWE-agent prediction: {error}"
                    ))
                })?;
                if !canonical_prediction.starts_with(&canonical_artifact_dir) {
                    return Err(ReferenceHarnessError::Output(
                        "SWE-agent prediction resolves outside the fresh artifact directory".into(),
                    ));
                }
                read_swe_agent_prediction(&prediction_path, &task.id, model)?
            }
            CandidateOutput::Unknown => {
                return Err(ReferenceHarnessError::Output(
                    "unknown candidate output kind".into(),
                ));
            }
        };
        if candidate.schema_version != 1 {
            return Err(ReferenceHarnessError::Output(format!(
                "unsupported schema_version {}",
                candidate.schema_version
            )));
        }
        Ok(candidate)
    }

    pub async fn score_candidate(
        &self,
        task: &CorpusTask,
        candidate: CapturedHarnessCandidate,
        oracle_workspace: &Path,
        checkout_timeout: Duration,
        oracle_timeout: Duration,
    ) -> Result<ReferenceHarnessScore, ReferenceHarnessError> {
        let receipt = score_candidate_diff(
            task,
            &candidate.candidate_diff,
            oracle_workspace,
            checkout_timeout,
            oracle_timeout,
        )
        .await
        .map_err(ReferenceHarnessError::Oracle)?;
        Ok(ReferenceHarnessScore {
            harness: self.spec.name.clone(),
            harness_revision: self.spec.revision.clone(),
            self_reported_resolved: candidate.self_reported_resolved,
            core_oracle: receipt,
        })
    }
}

fn validate_checkout(
    spec: &ReferenceHarnessSpec,
    checkout: &Path,
) -> Result<(), ReferenceHarnessError> {
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(checkout)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env(
                "GIT_CONFIG_GLOBAL",
                if cfg!(windows) { "NUL" } else { "/dev/null" },
            )
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .map_err(|error| ReferenceHarnessError::UnpinnedCheckout(error.to_string()))
    };
    let head = git(&["rev-parse", "HEAD"])?;
    if !head.status.success() || String::from_utf8_lossy(&head.stdout).trim() != spec.revision {
        return Err(ReferenceHarnessError::UnpinnedCheckout(
            "HEAD does not equal the configured revision".into(),
        ));
    }
    let status = git(&["status", "--porcelain", "--untracked-files=normal"])?;
    if !status.status.success() || !status.stdout.is_empty() {
        return Err(ReferenceHarnessError::UnpinnedCheckout(
            "source checkout has tracked or untracked changes".into(),
        ));
    }
    let tracked = Command::new("git")
        .arg("-C")
        .arg(checkout)
        .args(["ls-files", "--error-unmatch", "--"])
        .arg(&spec.entrypoint)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .map_err(|error| ReferenceHarnessError::UnpinnedCheckout(error.to_string()))?;
    if !tracked.status.success() {
        return Err(ReferenceHarnessError::UnpinnedCheckout(
            "entrypoint is not tracked by the pinned source commit".into(),
        ));
    }
    let origin = git(&["config", "--get", "remote.origin.url"])?;
    if !origin.status.success() || String::from_utf8_lossy(&origin.stdout).trim() != spec.source_url
    {
        return Err(ReferenceHarnessError::UnpinnedCheckout(
            "origin URL does not equal the configured credential-free source URL".into(),
        ));
    }
    Ok(())
}

fn expand_argument(
    argument: &str,
    task: &CorpusTask,
    workspace: &Path,
    artifact_dir: &Path,
    model: &str,
    provider: Option<&str>,
) -> String {
    let substitutions = [
        ("{workspace}", workspace.display().to_string()),
        ("{repo_url}", task.repo_url.clone()),
        ("{commit}", task.commit.clone()),
        ("{task_id}", task.id.clone()),
        ("{prompt}", task.prompt.clone()),
        ("{model}", model.to_owned()),
        ("{provider}", provider.unwrap_or("").to_owned()),
        (
            "{dockerhub_tag}",
            task.dockerhub_tag.clone().unwrap_or_default(),
        ),
        ("{artifact_dir}", artifact_dir.display().to_string()),
    ];
    let mut expanded = String::with_capacity(argument.len());
    let mut remaining = argument;
    while !remaining.is_empty() {
        if let Some((needle, value)) = substitutions
            .iter()
            .find(|(needle, _)| remaining.starts_with(needle))
        {
            expanded.push_str(value);
            remaining = &remaining[needle.len()..];
        } else {
            let character = remaining
                .chars()
                .next()
                .expect("remaining was checked as non-empty");
            expanded.push(character);
            remaining = &remaining[character.len_utf8()..];
        }
    }
    expanded
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SweAgentPrediction {
    model_name_or_path: String,
    instance_id: String,
    model_patch: Option<String>,
}

fn read_swe_agent_prediction(
    path: &Path,
    expected_instance: &str,
    expected_model: &str,
) -> Result<CapturedHarnessCandidate, ReferenceHarnessError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| ReferenceHarnessError::Output(error.to_string()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ReferenceHarnessError::Output(
            "SWE-agent prediction must be a regular non-symlink file".into(),
        ));
    }
    let file = std::fs::File::open(path)
        .map_err(|error| ReferenceHarnessError::Output(error.to_string()))?;
    let mut bytes = Vec::new();
    file.take(
        iteron_tunables::param_integer(
            "eval.reference_harness.harness_output_limit",
            HARNESS_OUTPUT_LIMIT,
        ) as u64
            + 1,
    )
    .read_to_end(&mut bytes)
    .map_err(|error| ReferenceHarnessError::Output(error.to_string()))?;
    if bytes.len()
        > iteron_tunables::param_integer(
            "eval.reference_harness.harness_output_limit",
            HARNESS_OUTPUT_LIMIT,
        )
    {
        return Err(ReferenceHarnessError::Output(
            "SWE-agent prediction exceeds 8 MiB".into(),
        ));
    }
    let prediction: SweAgentPrediction = serde_json::from_slice(&bytes)
        .map_err(|error| ReferenceHarnessError::Output(error.to_string()))?;
    if prediction.instance_id != expected_instance {
        return Err(ReferenceHarnessError::Output(format!(
            "SWE-agent prediction instance `{}` does not match `{expected_instance}`",
            prediction.instance_id
        )));
    }
    if prediction.model_name_or_path != expected_model {
        return Err(ReferenceHarnessError::Output(format!(
            "SWE-agent prediction model `{}` does not match frozen model `{expected_model}`",
            prediction.model_name_or_path
        )));
    }
    Ok(CapturedHarnessCandidate {
        schema_version: 1,
        candidate_diff: prediction.model_patch.unwrap_or_default(),
        self_reported_resolved: None,
    })
}

fn clean_git_environment() -> Vec<(OsString, OsString)> {
    vec![
        ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
        (
            "GIT_CONFIG_GLOBAL".into(),
            if cfg!(windows) { "NUL" } else { "/dev/null" }.into(),
        ),
        ("GIT_TERMINAL_PROMPT".into(), "0".into()),
    ]
}

fn is_git_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::Provenance;
    use crate::types::Partition;
    use std::collections::BTreeMap;

    #[test]
    fn substitutions_are_single_pass_and_preserve_placeholder_text_in_values() {
        let task = CorpusTask {
            id: "fixture".into(),
            repo_url: "https://example.invalid/repo.git".into(),
            commit: "0".repeat(40),
            prompt: "keep {model} and {provider} literal".into(),
            verify_command: "true".into(),
            ground_truth_command: "true".into(),
            dockerhub_tag: None,
            fail_to_pass: vec!["fixture".into()],
            pass_to_pass: Vec::new(),
            test_cmd: BTreeMap::from([("sh".into(), "true".into())]),
            partition: Partition::HeldOut,
            provenance: Provenance {
                source: "fixture".into(),
                task_id: "fixture".into(),
                license: None,
            },
            benchmark: None,
        };
        let expanded = expand_argument(
            "{prompt}|{model}|{provider}",
            &task,
            Path::new("/workspace"),
            Path::new("/artifact"),
            "frozen-model",
            Some("fixed-provider"),
        );
        assert_eq!(
            expanded,
            "keep {model} and {provider} literal|frozen-model|fixed-provider"
        );
    }
}
