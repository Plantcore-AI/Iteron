use serde::{Deserialize, Serialize};

/// Hard ceilings remain code-owned even when the session selects a smaller runtime policy.
pub const MAX_BACKGROUND_JOBS: usize = 16;
pub const MAX_IDLE_STALL_MILLISECONDS: u64 = 86_400_000;
pub const MAX_STDIN_POLL_MILLISECONDS: u64 = 60_000;

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
