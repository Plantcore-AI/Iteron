use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Hard ceilings remain code-owned even when the session selects a smaller runtime policy.
pub const MAX_BACKGROUND_JOBS: usize = 16;
pub const MAX_IDLE_STALL_MILLISECONDS: u64 = 86_400_000;
pub const MAX_STDIN_POLL_MILLISECONDS: u64 = 60_000;
pub const MAX_CHILD_ENV_ENTRIES: usize = 4_096;
pub const MAX_CHILD_ENV_BYTES: usize = 1_048_576;

/// Shipped runtime defaults, all inside the hard ceilings above.
/// Background jobs one session may hold open, half the `MAX_BACKGROUND_JOBS` ceiling.
const DEFAULT_BACKGROUND_JOB_CAP: usize = 8;
/// Silence after which a job is reported as idle or stalled rather than waited on further.
const DEFAULT_IDLE_STALL_MILLISECONDS: u64 = 5 * 60 * 1_000;
/// How often an interactive job is polled while it is waiting on stdin.
const DEFAULT_STDIN_POLL_MILLISECONDS: u64 = 250;
/// Silence on an interactive job before its stdin wait gives up.
const DEFAULT_INTERACTIVE_IDLE_TIMEOUT_MILLISECONDS: u64 = 5 * 60 * 1_000;
/// Whether a job blocked on stdin surfaces a prompt to the operator; on, because the alternative
/// is a job that appears hung with no way to see what it wants.
const DEFAULT_OPERATOR_PROMPT: bool = true;

fn hard_max_background_jobs() -> usize {
    iteron_tunables::param_usize(
        "tools.process.policy.max_background_jobs",
        MAX_BACKGROUND_JOBS,
    )
    .clamp(1, MAX_BACKGROUND_JOBS)
}

fn max_idle_stall_milliseconds() -> u64 {
    iteron_tunables::param_u64(
        "tools.process.policy.max_idle_stall_milliseconds",
        MAX_IDLE_STALL_MILLISECONDS,
    )
    .clamp(1, MAX_IDLE_STALL_MILLISECONDS)
}

fn max_stdin_poll_milliseconds() -> u64 {
    iteron_tunables::param_u64(
        "tools.process.policy.max_stdin_poll_milliseconds",
        MAX_STDIN_POLL_MILLISECONDS,
    )
    .clamp(1, MAX_STDIN_POLL_MILLISECONDS)
}

fn max_child_env_entries() -> usize {
    iteron_tunables::param_usize(
        "tools.process.policy.max_child_env_entries",
        MAX_CHILD_ENV_ENTRIES,
    )
    .clamp(1, MAX_CHILD_ENV_ENTRIES)
}

fn max_child_env_bytes() -> usize {
    iteron_tunables::param_usize(
        "tools.process.policy.max_child_env_bytes",
        MAX_CHILD_ENV_BYTES,
    )
    .clamp(1, MAX_CHILD_ENV_BYTES)
}
/// Process implementation selected when no installed profile overrides it.
const DEFAULT_PERSISTENT_BACKEND: &str = "persistent";

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

    fn from_profile(value: &str) -> Self {
        match value {
            "disabled" => Self::Disabled,
            "one_shot" => Self::OneShot,
            "persistent" => Self::Persistent,
            _ => Self::Persistent,
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
        if !(1..=max_stdin_poll_milliseconds()).contains(&self.poll_milliseconds) {
            return Err(ProcessPolicyError::PollMilliseconds);
        }
        if !(1..=max_idle_stall_milliseconds()).contains(&self.idle_timeout_milliseconds) {
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
                max_entries: max_child_env_entries(),
                max_bytes: max_child_env_bytes(),
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
        if environment.max_entries > max_child_env_entries()
            || environment.max_bytes > max_child_env_bytes()
        {
            return Err(ProcessPolicyError::EnvironmentPolicy);
        }
        environment.blocked_names.sort();
        environment.blocked_names.dedup();
        if environment.blocked_names.len() > max_child_env_entries()
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
        if policy.max_background_jobs > hard_max_background_jobs() {
            return Err(ProcessPolicyError::BackgroundJobCap);
        }
        if !(1..=max_idle_stall_milliseconds()).contains(&policy.idle_stall_milliseconds) {
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
        // The `expect` below is a real invariant, not decoration: this constructor has no error
        // path. A tier-2 override is therefore held to the same code-owned ceilings the constant
        // already satisfied, by clamping here rather than by panicking at startup. With no profile
        // installed every clamp is a no-op on its own compiled default.
        let backend = PersistentBackendSelection::from_profile(iteron_tunables::param_str(
            "tools.process.policy.default_persistent_backend",
            DEFAULT_PERSISTENT_BACKEND,
        ));
        let configured_background_job_cap = iteron_tunables::param_usize(
            "tools.process.policy.default_background_job_cap",
            iteron_tunables::param_integer(
                "tools.process.policy.default_background_job_cap",
                DEFAULT_BACKGROUND_JOB_CAP,
            ),
        )
        .clamp(1, hard_max_background_jobs());
        let background_job_cap = if backend == PersistentBackendSelection::Disabled {
            0
        } else {
            configured_background_job_cap
        };
        let idle_ceiling = max_idle_stall_milliseconds();
        let idle_stall_milliseconds = iteron_tunables::param_u64(
            "tools.process.policy.default_idle_stall_milliseconds",
            iteron_tunables::param_integer(
                "tools.process.policy.default_idle_stall_milliseconds",
                DEFAULT_IDLE_STALL_MILLISECONDS,
            ),
        )
        .clamp(1, idle_ceiling);
        let stdin_poll_ceiling = max_stdin_poll_milliseconds().min(idle_ceiling);
        let stdin_poll_milliseconds = iteron_tunables::param_u64(
            "tools.process.policy.default_stdin_poll_milliseconds",
            iteron_tunables::param_integer(
                "tools.process.policy.default_stdin_poll_milliseconds",
                DEFAULT_STDIN_POLL_MILLISECONDS,
            ),
        )
        .clamp(1, stdin_poll_ceiling);
        let interactive_idle_timeout_milliseconds = iteron_tunables::param_u64(
            "tools.process.policy.default_interactive_idle_timeout_milliseconds",
            iteron_tunables::param_integer(
                "tools.process.policy.default_interactive_idle_timeout_milliseconds",
                DEFAULT_INTERACTIVE_IDLE_TIMEOUT_MILLISECONDS,
            ),
        )
        .clamp(stdin_poll_milliseconds, idle_ceiling);
        Self::new(
            backend,
            background_job_cap,
            idle_stall_milliseconds,
            InteractiveStdinWaitPolicy {
                poll_milliseconds: stdin_poll_milliseconds,
                idle_timeout_milliseconds: interactive_idle_timeout_milliseconds,
                operator_prompt: iteron_tunables::param_bool(
                    "tools.process.policy.default_operator_prompt",
                    DEFAULT_OPERATOR_PROMPT,
                ),
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
