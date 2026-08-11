use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Hard ceilings remain code-owned even when the session selects a smaller runtime policy.
pub const MAX_BACKGROUND_JOBS: usize = 16;
pub const MAX_IDLE_STALL_MILLISECONDS: u64 = 86_400_000;
pub const MAX_STDIN_POLL_MILLISECONDS: u64 = 60_000;
pub const MAX_CHILD_ENV_ENTRIES: usize = 4_096;
pub const MAX_CHILD_ENV_BYTES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistentBackendSelection {
    Disabled,
    OneShot,
    Persistent,
}

impl PersistentBackendSelection {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::OneShot => "one_shot",
            Self::Persistent => "persistent",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InteractiveStdinWaitPolicy {
    pub poll_milliseconds: u64,
    pub idle_timeout_milliseconds: u64,
    pub operator_prompt: bool,
}

impl InteractiveStdinWaitPolicy {
    fn validate(self) -> Result<Self, ProcessPolicyError> {
        if !(1..=MAX_STDIN_POLL_MILLISECONDS).contains(&self.poll_milliseconds) {
            return Err(ProcessPolicyError::PollMilliseconds);
        }
        if !(1..=MAX_IDLE_STALL_MILLISECONDS).contains(&self.idle_timeout_milliseconds) {
            return Err(ProcessPolicyError::InteractiveIdleTimeout);
        }
        if self.poll_milliseconds > self.idle_timeout_milliseconds {
            return Err(ProcessPolicyError::PollExceedsIdle);
        }
        Ok(self)
    }
}

/// One immutable process policy, installed before this session admits its first job.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProcessRuntimePolicy {
    pub backend: PersistentBackendSelection,
    pub max_background_jobs: usize,
    pub idle_stall_milliseconds: u64,
    pub stdin_wait: InteractiveStdinWaitPolicy,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessCwdScope {
    Job,
}

impl ProcessCwdScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Job => "job",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProcessCwdPolicy {
    pub scope: ProcessCwdScope,
    pub initial_cwd: PathBuf,
    pub preserve_changes: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildProcessEnvironmentPolicy {
    pub reuse: bool,
    pub max_entries: usize,
    pub max_bytes: usize,
    pub blocked_names: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProcessLaunchPolicy {
    pub cwd: ProcessCwdPolicy,
    pub environment: ChildProcessEnvironmentPolicy,
}

/// The immutable launch owner installed before the first process effect. Environment values are
/// deliberately kept out of serde/debug evidence: the checkpoint records only the bounded policy,
/// while this private snapshot is the value actually inherited by every child in the session.
#[derive(Clone)]
pub(crate) struct InstalledProcessLaunchPolicy {
    pub policy: ProcessLaunchPolicy,
    pub child_environment: Vec<(OsString, OsString)>,
}

impl ProcessLaunchPolicy {
    pub fn owner(workspace: &Path) -> Result<Self, ProcessPolicyError> {
        Self::new(
            ProcessCwdPolicy {
                scope: ProcessCwdScope::Job,
                initial_cwd: workspace.to_path_buf(),
                preserve_changes: true,
            },
            ChildProcessEnvironmentPolicy {
                reuse: true,
                max_entries: MAX_CHILD_ENV_ENTRIES,
                max_bytes: MAX_CHILD_ENV_BYTES,
                blocked_names: Vec::new(),
            },
        )
    }

    pub fn new(
        cwd: ProcessCwdPolicy,
        mut environment: ChildProcessEnvironmentPolicy,
    ) -> Result<Self, ProcessPolicyError> {
        if !cwd.initial_cwd.is_absolute() || !cwd.preserve_changes {
            return Err(ProcessPolicyError::CwdPolicy);
        }
        if environment.max_entries > MAX_CHILD_ENV_ENTRIES
            || environment.max_bytes > MAX_CHILD_ENV_BYTES
        {
            return Err(ProcessPolicyError::EnvironmentPolicy);
        }
        environment.blocked_names.sort();
        environment.blocked_names.dedup();
        if environment.blocked_names.len() > MAX_CHILD_ENV_ENTRIES
            || environment.blocked_names.iter().any(|name| {
                name.is_empty()
                    || name.len() > 256
                    || !name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            })
        {
            return Err(ProcessPolicyError::EnvironmentPolicy);
        }
        Ok(Self { cwd, environment })
    }

    pub fn validate_root(&self, root: &Path) -> Result<(), ProcessPolicyError> {
        let root = root
            .canonicalize()
            .map_err(|_| ProcessPolicyError::CwdPolicy)?;
        let configured = self
            .cwd
            .initial_cwd
            .canonicalize()
            .map_err(|_| ProcessPolicyError::CwdPolicy)?;
        if root != configured {
            return Err(ProcessPolicyError::CwdPolicy);
        }
        Ok(())
    }
}

impl ProcessRuntimePolicy {
    pub fn new(
        backend: PersistentBackendSelection,
        max_background_jobs: usize,
        idle_stall_milliseconds: u64,
        stdin_wait: InteractiveStdinWaitPolicy,
    ) -> Result<Self, ProcessPolicyError> {
        let policy = Self {
            backend,
            max_background_jobs,
            idle_stall_milliseconds,
            stdin_wait: stdin_wait.validate()?,
        };
        if policy.max_background_jobs > MAX_BACKGROUND_JOBS {
            return Err(ProcessPolicyError::BackgroundJobCap);
        }
        if !(1..=MAX_IDLE_STALL_MILLISECONDS).contains(&policy.idle_stall_milliseconds) {
            return Err(ProcessPolicyError::IdleStallTimeout);
        }
        match policy.backend {
            PersistentBackendSelection::Disabled if policy.max_background_jobs != 0 => {
                return Err(ProcessPolicyError::DisabledWithCapacity);
            }
            PersistentBackendSelection::OneShot | PersistentBackendSelection::Persistent
                if policy.max_background_jobs == 0 =>
            {
                return Err(ProcessPolicyError::EnabledWithoutCapacity);
            }
            _ => {}
        }
        Ok(policy)
    }
}

impl Default for ProcessRuntimePolicy {
    fn default() -> Self {
        Self::new(
            PersistentBackendSelection::Persistent,
            8,
            5 * 60 * 1_000,
            InteractiveStdinWaitPolicy {
                poll_milliseconds: 1_000,
                idle_timeout_milliseconds: 5 * 60 * 1_000,
                operator_prompt: true,
            },
        )
        .expect("the built-in process policy must satisfy its hard ceilings")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProcessPolicyError {
    #[error("background job cap exceeds the fixed {MAX_BACKGROUND_JOBS}-job ceiling")]
    BackgroundJobCap,
    #[error("idle/stall timeout must be within 1..={MAX_IDLE_STALL_MILLISECONDS}ms")]
    IdleStallTimeout,
    #[error("stdin poll interval must be within 1..={MAX_STDIN_POLL_MILLISECONDS}ms")]
    PollMilliseconds,
    #[error("interactive stdin idle timeout must be within 1..={MAX_IDLE_STALL_MILLISECONDS}ms")]
    InteractiveIdleTimeout,
    #[error("stdin poll interval cannot exceed its idle timeout")]
    PollExceedsIdle,
    #[error("a disabled process backend must have zero background capacity")]
    DisabledWithCapacity,
    #[error("an enabled process backend must admit at least one background job")]
    EnabledWithoutCapacity,
    #[error("process cwd policy must bind the absolute job workspace and preserve its changes")]
    CwdPolicy,
    #[error("child process environment policy exceeds its bounded owner envelope")]
    EnvironmentPolicy,
    #[error("process launch policy was already installed for this registry")]
    LaunchPolicyAlreadyInstalled,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_policy_validates_cross_field_and_hard_bounds() {
        assert!(ProcessRuntimePolicy::default().max_background_jobs <= MAX_BACKGROUND_JOBS);
        assert!(matches!(
            ProcessRuntimePolicy::new(
                PersistentBackendSelection::Disabled,
                1,
                1,
                InteractiveStdinWaitPolicy {
                    poll_milliseconds: 1,
                    idle_timeout_milliseconds: 1,
                    operator_prompt: false,
                },
            ),
            Err(ProcessPolicyError::DisabledWithCapacity)
        ));
    }
}
