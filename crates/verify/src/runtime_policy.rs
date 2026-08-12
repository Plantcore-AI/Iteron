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
pub const MAX_VERIFICATION_FEEDBACK_BYTES: usize = 2 * 1024 * 1024;
pub const DEFAULT_VERIFIER_TIMEOUT_SECS: u64 = 300;
pub const DEFAULT_VERIFICATION_REPAIR_ATTEMPTS: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailureClass {
    TestFailure,
    TimedOut,
    InfrastructureFailure,
    Cancelled,
}

impl VerificationFailureClass {
    pub const fn id(self) -> &'static str {
        match self {
            Self::TestFailure => "verification.test_failure",
            Self::TimedOut => "verification.timed_out",
            Self::InfrastructureFailure => "verification.infrastructure_failure",
            Self::Cancelled => "verification.cancelled",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownVerificationRetryAction {
    Stop,
    Operator,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationRetryPolicy {
    pub eligible_classes: Vec<VerificationFailureClass>,
    pub max_attempts: u32,
    pub unknown: UnknownVerificationRetryAction,
}

impl Default for VerificationRetryPolicy {
    fn default() -> Self {
        Self {
            eligible_classes: vec![VerificationFailureClass::TestFailure],
            max_attempts: DEFAULT_VERIFICATION_REPAIR_ATTEMPTS,
            unknown: UnknownVerificationRetryAction::Stop,
        }
    }
}

impl VerificationRetryPolicy {
    pub fn admits(&self, class: VerificationFailureClass) -> bool {
        self.eligible_classes.contains(&class)
    }
}

/// Fixed recovery escalation owned by the physical verification loop.
///
/// An eligible candidate failure consumes one bounded repair attempt, returns a new model turn to
/// replan/fix, and eventually stops at the immutable attempt ceiling. Ineligible failure classes
/// stop immediately. Keeping this typed owner next to the retry policy lets composition attest the
/// exact FixedHidden family instead of inventing resolver evidence disconnected from execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationRecoveryEscalationPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationRecoveryAction {
    RetryReplan,
    StopIneligible,
    StopExhausted,
}

impl VerificationRecoveryEscalationPolicy {
    pub const ID: &'static str = "retry_replan_stop";

    pub fn decide(
        self,
        retry: &VerificationRetryPolicy,
        class: VerificationFailureClass,
        completed_attempts: u32,
    ) -> VerificationRecoveryAction {
        if !retry.admits(class) {
            VerificationRecoveryAction::StopIneligible
        } else if completed_attempts.saturating_add(1) >= retry.max_attempts {
            VerificationRecoveryAction::StopExhausted
        } else {
            VerificationRecoveryAction::RetryReplan
        }
    }
}

pub const fn verification_recovery_escalation_policy() -> VerificationRecoveryEscalationPolicy {
    VerificationRecoveryEscalationPolicy
}

/// Immutable context-admission bounds for physical and aggregate verifier feedback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationFeedbackTailPolicy {
    pub command_output_bytes: usize,
    pub oracle_output_bytes: usize,
    pub total_bytes: usize,
}

impl Default for VerificationFeedbackTailPolicy {
    fn default() -> Self {
        Self {
            command_output_bytes: 1_000,
            oracle_output_bytes: 4_000,
            total_bytes: 3_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationSelectionMode {
    /// Run the trusted incremental feedback command(s), then the mandatory full workspace gate.
    Incremental,
    /// Run the trusted impacted feedback command(s), then the mandatory full workspace gate.
    Impacted,
    /// Run the mandatory full workspace gate.
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
            before_drain: true,
            minimum_turn_interval: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationRestorePolicy {
    pub mode: VerificationRollbackMode,
    pub paths: Vec<String>,
    /// Assertion that the runtime must obtain one live exact operator decision immediately before
    /// this destructive effect. It is fixed true by validation and is never a configuration knob.
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
    /// Exact per-command wall deadline, independently tightened by the enclosing run deadline.
    #[serde(default = "default_verifier_timeout_secs")]
    pub verifier_timeout_secs: u64,
    pub selection: VerificationSelectionMode,
    pub required_commands: Vec<String>,
    pub max_commands: u16,
    pub flaky: FlakyQuarantinePolicy,
    pub quorum: VerificationQuorumPolicy,
    pub checkpoint: VerificationCheckpointPolicy,
    pub restore: VerificationRestorePolicy,
    pub feedback: VerificationFeedbackTailPolicy,
    pub retry: VerificationRetryPolicy,
}

impl Default for VerificationRuntimePolicy {
    fn default() -> Self {
        Self {
            verifier_timeout_secs: DEFAULT_VERIFIER_TIMEOUT_SECS,
            selection: VerificationSelectionMode::Full,
            required_commands: Vec::new(),
            max_commands: 1,
            flaky: FlakyQuarantinePolicy::default(),
            quorum: VerificationQuorumPolicy::default(),
            checkpoint: VerificationCheckpointPolicy::default(),
            restore: VerificationRestorePolicy::default(),
            feedback: VerificationFeedbackTailPolicy::default(),
            retry: VerificationRetryPolicy::default(),
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
    InvalidFeedbackPolicy,
    InvalidTimeoutPolicy,
    InvalidRetryPolicy,
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
            Self::InvalidFeedbackPolicy => "verification feedback bounds are inconsistent",
            Self::InvalidTimeoutPolicy => "verification timeout is outside its bounded domain",
            Self::InvalidRetryPolicy => "verification retry policy is inconsistent",
        })
    }
}

impl std::error::Error for VerificationPolicyError {}

impl VerificationRuntimePolicy {
    pub fn validate(&self) -> Result<(), VerificationPolicyError> {
        if !(1..=86_400).contains(&self.verifier_timeout_secs) {
            return Err(VerificationPolicyError::InvalidTimeoutPolicy);
        }
        if self.retry.max_attempts == 0
            || self.retry.max_attempts > 64
            || self.retry.eligible_classes.len() > 4
            || self
                .retry
                .eligible_classes
                .windows(2)
                .any(|classes| classes[0] >= classes[1])
        {
            return Err(VerificationPolicyError::InvalidRetryPolicy);
        }
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
        if !self.checkpoint.before_drain || self.checkpoint.minimum_turn_interval > 10_000 {
            return Err(VerificationPolicyError::InvalidCheckpointPolicy);
        }
        if self.feedback.command_output_bytes > 1_048_576
            || self.feedback.oracle_output_bytes > 1_048_576
            || self.feedback.total_bytes == 0
            || self.feedback.total_bytes > MAX_VERIFICATION_FEEDBACK_BYTES
        {
            return Err(VerificationPolicyError::InvalidFeedbackPolicy);
        }
        if !self.restore.require_operator_confirmation
            || self.restore.paths.len() > MAX_VERIFICATION_PATHS
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

    /// Commands selected for one completion claim. The trusted composition root has already
    /// materialized the selected narrow feedback commands followed by the mandatory full
    /// workspace gate. Runtime must execute the complete vector; applying `selection` again here
    /// used to silently drop that final gate for incremental and impacted modes.
    pub fn selected_commands(&self) -> &[String] {
        &self.required_commands
    }
}

const fn default_verifier_timeout_secs() -> u64 {
    DEFAULT_VERIFIER_TIMEOUT_SECS
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

    #[test]
    fn drain_checkpoint_and_operator_confirmation_are_non_disableable_invariants() {
        let mut policy = VerificationRuntimePolicy::default();
        policy.checkpoint.before_drain = false;
        assert_eq!(
            policy.validate(),
            Err(VerificationPolicyError::InvalidCheckpointPolicy)
        );

        let mut policy = VerificationRuntimePolicy::default();
        policy.restore.require_operator_confirmation = false;
        assert_eq!(
            policy.validate(),
            Err(VerificationPolicyError::InvalidRestorePolicy)
        );
    }

    #[test]
    fn verifier_timeout_is_bounded_and_part_of_the_typed_policy() {
        let mut policy = VerificationRuntimePolicy {
            verifier_timeout_secs: 0,
            ..VerificationRuntimePolicy::default()
        };
        assert_eq!(
            policy.validate(),
            Err(VerificationPolicyError::InvalidTimeoutPolicy)
        );

        policy.verifier_timeout_secs = 86_401;
        assert_eq!(
            policy.validate(),
            Err(VerificationPolicyError::InvalidTimeoutPolicy)
        );

        policy.verifier_timeout_secs = 1;
        policy
            .validate()
            .expect("one second is the minimum admitted timeout");
    }

    #[test]
    fn retry_policy_is_typed_bounded_and_defaults_to_test_failures_only() {
        let policy = VerificationRuntimePolicy::default();
        assert!(policy.retry.admits(VerificationFailureClass::TestFailure));
        assert!(!policy.retry.admits(VerificationFailureClass::TimedOut));
        assert!(
            !policy
                .retry
                .admits(VerificationFailureClass::InfrastructureFailure)
        );
        assert_eq!(policy.retry.max_attempts, 3);

        let mut invalid = policy.clone();
        invalid.retry.max_attempts = 0;
        assert_eq!(
            invalid.validate(),
            Err(VerificationPolicyError::InvalidRetryPolicy)
        );
        invalid.retry.max_attempts = 65;
        assert_eq!(
            invalid.validate(),
            Err(VerificationPolicyError::InvalidRetryPolicy)
        );
        invalid.retry.max_attempts = 2;
        invalid.retry.eligible_classes = vec![
            VerificationFailureClass::TimedOut,
            VerificationFailureClass::TestFailure,
        ];
        assert_eq!(
            invalid.validate(),
            Err(VerificationPolicyError::InvalidRetryPolicy),
            "canonical policy order prevents ambiguous checkpoint identity"
        );
    }

    #[test]
    fn fixed_recovery_owner_drives_retry_replan_then_stop() {
        let retry = VerificationRetryPolicy::default();
        let owner = verification_recovery_escalation_policy();
        assert_eq!(
            VerificationRecoveryEscalationPolicy::ID,
            "retry_replan_stop"
        );
        assert_eq!(
            owner.decide(&retry, VerificationFailureClass::TestFailure, 0),
            VerificationRecoveryAction::RetryReplan
        );
        assert_eq!(
            owner.decide(&retry, VerificationFailureClass::TestFailure, 2),
            VerificationRecoveryAction::StopExhausted
        );
        assert_eq!(
            owner.decide(&retry, VerificationFailureClass::TimedOut, 0),
            VerificationRecoveryAction::StopIneligible
        );
    }
}
