//! Runtime-effective verification selection, consensus, quarantine, and recovery policy.
//!
//! The strategy slot chooses the strength/scope floor. This policy owns the orthogonal harness
//! controls which used to exist only as tunable catalog shapes: how many admitted commands run,
//! how their outcomes form a quorum, when disagreement becomes quarantined evidence, and whether
//! an operator-authorised workspace checkpoint may be restored after a genuine test failure.

use crate::VerificationOutcome;
use serde::{Deserialize, Serialize};

pub const MAX_VERIFICATION_COMMANDS: usize = 64;
pub const MAX_VERIFICATION_PATHS: usize = 100_000;
pub const MAX_VERIFICATION_COMMAND_BYTES: usize = 4_096;
pub const MAX_PHYSICAL_VERIFIER_RUNS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationSelectionMode {
    /// Run the first admitted command. Intended for the narrowest feedback loop.
    Incremental,
    /// Run the admitted impacted-command prefix selected by the composition root.
    Impacted,
    /// Run every admitted command before accepting completion.
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationRollbackMode {
    Off,
    SelectedPaths,
    Workspace,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationCheckpointPolicy {
    pub turn_boundary: bool,
    pub before_verification: bool,
    pub before_drain: bool,
    pub minimum_turn_interval: u32,
}

impl Default for VerificationCheckpointPolicy {
    fn default() -> Self {
        Self {
            turn_boundary: true,
            before_verification: false,
            before_drain: false,
            minimum_turn_interval: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationRestorePolicy {
    pub mode: VerificationRollbackMode,
    pub paths: Vec<String>,
    /// This is an assertion about the provenance of the resolved value, not an instruction to
    /// prompt from inside the kernel. A trusted composition root may set it false only after it
    /// has independently established operator authority.
    pub require_operator_confirmation: bool,
}

impl Default for VerificationRestorePolicy {
    fn default() -> Self {
        Self {
            mode: VerificationRollbackMode::Off,
            paths: Vec::new(),
            require_operator_confirmation: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlakyQuarantinePolicy {
    pub repeat_count: u8,
    pub minimum_disagreements: u8,
    pub quarantine_seconds: u32,
    pub report_disagreement: bool,
}

impl Default for FlakyQuarantinePolicy {
    fn default() -> Self {
        Self {
            repeat_count: 1,
            minimum_disagreements: 1,
            quarantine_seconds: 0,
            report_disagreement: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationQuorumPolicy {
    pub verifiers: u8,
    pub required_agreement: u8,
    pub strong_veto: bool,
}

impl Default for VerificationQuorumPolicy {
    fn default() -> Self {
        Self {
            verifiers: 1,
            required_agreement: 1,
            strong_veto: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationRuntimePolicy {
    pub selection: VerificationSelectionMode,
    pub required_commands: Vec<String>,
    pub max_commands: u16,
    pub flaky: FlakyQuarantinePolicy,
    pub quorum: VerificationQuorumPolicy,
    pub checkpoint: VerificationCheckpointPolicy,
    pub restore: VerificationRestorePolicy,
}

impl Default for VerificationRuntimePolicy {
    fn default() -> Self {
        Self {
            selection: VerificationSelectionMode::Full,
            required_commands: Vec::new(),
            max_commands: 1,
            flaky: FlakyQuarantinePolicy::default(),
            quorum: VerificationQuorumPolicy::default(),
            checkpoint: VerificationCheckpointPolicy::default(),
            restore: VerificationRestorePolicy::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationPolicyError {
    EmptyCommand,
    CommandTooLarge,
    TooManyCommands,
    InvalidFlakyPolicy,
    InvalidQuorum,
    InvalidRestorePolicy,
    InvalidCheckpointPolicy,
}

impl std::fmt::Display for VerificationPolicyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::EmptyCommand => "verification command is empty",
            Self::CommandTooLarge => "verification command exceeds its byte ceiling",
            Self::TooManyCommands => "verification command count exceeds its bounded ceiling",
            Self::InvalidFlakyPolicy => "flaky verification policy is inconsistent",
            Self::InvalidQuorum => "verification quorum is inconsistent",
            Self::InvalidRestorePolicy => "verification restore policy is inconsistent",
            Self::InvalidCheckpointPolicy => "verification checkpoint cadence is inconsistent",
        })
    }
}

impl std::error::Error for VerificationPolicyError {}

impl VerificationRuntimePolicy {
    pub fn validate(&self) -> Result<(), VerificationPolicyError> {
        let limit = usize::from(self.max_commands);
        if limit == 0
            || limit > MAX_VERIFICATION_COMMANDS
            || self.required_commands.len() > limit
            || self.required_commands.len() > MAX_VERIFICATION_COMMANDS
        {
            return Err(VerificationPolicyError::TooManyCommands);
        }
        if self
            .required_commands
            .iter()
            .any(|command| command.is_empty())
        {
            return Err(VerificationPolicyError::EmptyCommand);
        }
        if self
            .required_commands
            .iter()
            .any(|command| command.len() > MAX_VERIFICATION_COMMAND_BYTES)
        {
            return Err(VerificationPolicyError::CommandTooLarge);
        }
        if self.flaky.repeat_count == 0
            || self.flaky.minimum_disagreements == 0
            || self.flaky.minimum_disagreements > self.flaky.repeat_count
        {
            return Err(VerificationPolicyError::InvalidFlakyPolicy);
        }
        if self.quorum.verifiers == 0
            || self.quorum.required_agreement == 0
            || self.quorum.required_agreement > self.quorum.verifiers
        {
            return Err(VerificationPolicyError::InvalidQuorum);
        }
        if !self.required_commands.is_empty()
            && self
                .selected_commands()
                .len()
                .saturating_mul(usize::from(self.flaky.repeat_count))
                .saturating_mul(usize::from(self.quorum.verifiers))
                > MAX_PHYSICAL_VERIFIER_RUNS
        {
            return Err(VerificationPolicyError::InvalidQuorum);
        }
        if self.checkpoint.minimum_turn_interval > 10_000 {
            return Err(VerificationPolicyError::InvalidCheckpointPolicy);
        }
        if self.restore.paths.len() > MAX_VERIFICATION_PATHS
            || self.restore.paths.iter().any(|path| {
                path.is_empty()
                    || path.len() > MAX_VERIFICATION_COMMAND_BYTES
                    || path.starts_with('/')
                    || path.split('/').any(|segment| segment == "..")
            })
            || (self.restore.mode == VerificationRollbackMode::SelectedPaths
                && self.restore.paths.is_empty())
            || (self.restore.mode != VerificationRollbackMode::SelectedPaths
                && !self.restore.paths.is_empty())
        {
            return Err(VerificationPolicyError::InvalidRestorePolicy);
        }
        Ok(())
    }

    /// Commands selected for one completion claim. The composition root owns the ordering; this
    /// method only applies the immutable bounded selection mode.
    pub fn selected_commands(&self) -> &[String] {
        let count = match self.selection {
            VerificationSelectionMode::Incremental => {
                usize::from(!self.required_commands.is_empty())
            }
            VerificationSelectionMode::Impacted => self
                .required_commands
                .len()
                .min(usize::from(self.quorum.verifiers).max(1)),
            VerificationSelectionMode::Full => self.required_commands.len(),
        };
        &self.required_commands[..count]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationConsensus {
    Accepted,
    Rejected,
    Flaky,
    Indeterminate,
}

/// Fold independent physical verifier outcomes without converting disagreement or unavailable
/// evidence into green. A strong test-failure veto always wins when configured.
pub fn verification_consensus(
    policy: VerificationQuorumPolicy,
    minimum_disagreements: u8,
    outcomes: &[VerificationOutcome],
) -> VerificationConsensus {
    let bounded = &outcomes[..outcomes.len().min(usize::from(policy.verifiers))];
    if bounded.is_empty() {
        return VerificationConsensus::Indeterminate;
    }
    let pass = bounded
        .iter()
        .filter(|outcome| **outcome == VerificationOutcome::Pass)
        .count();
    let failed = bounded
        .iter()
        .filter(|outcome| **outcome == VerificationOutcome::TestFailure)
        .count();
    let disagreements = bounded.len().saturating_sub(
        bounded
            .iter()
            .filter(|outcome| **outcome == bounded[0])
            .count(),
    );
    if policy.strong_veto && failed > 0 {
        return VerificationConsensus::Rejected;
    }
    if disagreements >= usize::from(minimum_disagreements) {
        return VerificationConsensus::Flaky;
    }
    if pass >= usize::from(policy.required_agreement) {
        return VerificationConsensus::Accepted;
    }
    if failed >= usize::from(policy.required_agreement) {
        return VerificationConsensus::Rejected;
    }
    VerificationConsensus::Indeterminate
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_and_consensus_never_turn_missing_or_disagreement_green() {
        let policy = VerificationRuntimePolicy {
            selection: VerificationSelectionMode::Full,
            required_commands: vec!["check-fast".into(), "check-all".into()],
            max_commands: 2,
            quorum: VerificationQuorumPolicy {
                verifiers: 2,
                required_agreement: 2,
                strong_veto: true,
            },
            ..VerificationRuntimePolicy::default()
        };
        policy.validate().unwrap();
        assert_eq!(
            policy.selected_commands(),
            &["check-fast".to_string(), "check-all".to_string()]
        );
        assert_eq!(
            verification_consensus(policy.quorum, 1, &[VerificationOutcome::Pass]),
            VerificationConsensus::Indeterminate
        );
        assert_eq!(
            verification_consensus(
                policy.quorum,
                1,
                &[VerificationOutcome::Pass, VerificationOutcome::TestFailure]
            ),
            VerificationConsensus::Rejected
        );
        let no_veto = VerificationQuorumPolicy {
            strong_veto: false,
            ..policy.quorum
        };
        assert_eq!(
            verification_consensus(
                no_veto,
                1,
                &[VerificationOutcome::Pass, VerificationOutcome::TestFailure]
            ),
            VerificationConsensus::Flaky
        );
    }
}
