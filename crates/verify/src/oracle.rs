//! Oracles, ranked by strength. A weak oracle never vetoes (ADR-005 R6).

use iteron_sandbox::{Confinement, Sandbox};
use std::path::PathBuf;

/// How much authority an oracle's verdict carries. The ranking is a type, not a convention.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum OracleStrength {
    /// An LLM judging correctness. Advisory only; never enters the selection function.
    Weakest = 0,
    /// Generated reproduction tests. Contribute evidence; may rank, never veto.
    Weak = 1,
    /// LSP diagnostics, regression-suite deltas. May rank; may not veto alone.
    Medium = 2,
    /// The repo's real test suite, the compiler, the type checker. May VETO.
    Strong = 3,
}

impl OracleStrength {
    /// Only a Strong oracle may veto a candidate outright.
    pub fn may_veto(self) -> bool {
        self == OracleStrength::Strong
    }
}

/// The execution-level result of verification.
///
/// This is deliberately not a boolean: a candidate that failed its tests is actionable model
/// feedback, while an oracle that timed out, could not start, or was cancelled is harness state.
/// Conflating those cases makes the completion gate spend retries on infrastructure faults and
/// eventually misreport them as candidate failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationOutcome {
    /// The verification command completed successfully.
    Pass,
    /// The command ran to completion and reported that the candidate is incorrect.
    TestFailure,
    /// The command exceeded its bounded verification deadline.
    TimedOut,
    /// The sandbox or command runner could not execute the verification command.
    InfrastructureFailure,
    /// The caller cancelled verification before it produced a verdict.
    Cancelled,
}

impl VerificationOutcome {
    pub const fn is_pass(self) -> bool {
        matches!(self, Self::Pass)
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Pass => "passed",
            Self::TestFailure => "test failure",
            Self::TimedOut => "timed out",
            Self::InfrastructureFailure => "infrastructure failure",
            Self::Cancelled => "cancelled",
        }
    }
}

/// An oracle's verdict on a candidate (or on the current working tree).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub strength: OracleStrength,
    pub outcome: VerificationOutcome,
    /// Human-legible detail (e.g. the failing test output), truncated for context hygiene.
    pub detail: String,
}

impl Verdict {
    pub fn new(
        strength: OracleStrength,
        outcome: VerificationOutcome,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            strength,
            outcome,
            detail: detail.into(),
        }
    }

    pub const fn passed(&self) -> bool {
        self.outcome.is_pass()
    }

    /// A caller-side cancellation is still a typed oracle verdict even though the sandbox-backed
    /// oracle itself does not own the caller's cancellation source.
    pub fn cancelled(detail: impl Into<String>) -> Self {
        Self::new(
            OracleStrength::Strong,
            VerificationOutcome::Cancelled,
            detail,
        )
    }

    /// A caller-side absolute deadline can expire more precisely than the sandbox's whole-second
    /// process timeout. Preserve that distinction in the same typed result.
    pub fn timed_out(detail: impl Into<String>) -> Self {
        Self::new(
            OracleStrength::Strong,
            VerificationOutcome::TimedOut,
            detail,
        )
    }
}

/// Something that can judge the current state of the workspace.
#[async_trait::async_trait]
pub trait Oracle: Send + Sync {
    fn strength(&self) -> OracleStrength;
    /// Evaluate the current workspace. Execution failures and cancellation remain fail-closed,
    /// but are represented separately from a candidate's test failure.
    async fn evaluate(&self) -> Verdict;
}

/// The strong oracle: run the repo's real test command in the egress-off sandbox. This is the
/// verification gate the harness runs instead of trusting the model's "done".
pub struct TestOracle {
    sandbox: Box<dyn Sandbox>,
    workspace: PathBuf,
    command: String,
    timeout_secs: u64,
    sensitive_env_names: Vec<String>,
}

impl TestOracle {
    pub fn new(sandbox: Box<dyn Sandbox>, workspace: PathBuf, command: String) -> Self {
        TestOracle {
            sandbox,
            workspace,
            command,
            timeout_secs: 300,
            sensitive_env_names: Vec::new(),
        }
    }

    /// Tighten the oracle's own process-group timeout to the caller's remaining run budget.
    pub fn with_timeout_secs(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs.max(1);
        self
    }

    /// Remove the trusted provider directory's exact credential variables from the verification
    /// child process. Only variable names cross this boundary; credential values remain ambient to
    /// the provider process and are never inspected by the oracle.
    pub fn with_sensitive_env_names(mut self, mut names: Vec<String>) -> Self {
        names.sort();
        names.dedup();
        self.sensitive_env_names = names;
        self
    }
}

#[async_trait::async_trait]
impl Oracle for TestOracle {
    fn strength(&self) -> OracleStrength {
        OracleStrength::Strong
    }

    async fn evaluate(&self) -> Verdict {
        let mut conf = Confinement::egress_off(&self.workspace);
        conf.timeout_secs = self.timeout_secs;
        conf.sensitive_env_names = self.sensitive_env_names.clone();
        match self.sandbox.run(&self.command, &conf).await {
            Ok(out) => {
                let outcome = if out.timed_out {
                    VerificationOutcome::TimedOut
                } else if out.exit_code == 0 {
                    VerificationOutcome::Pass
                } else if matches!(out.exit_code, 126 | 127) {
                    // POSIX shells reserve 126/127 for "found but cannot execute" and "command
                    // not found". The configured oracle did not actually run in either case;
                    // spending candidate-fix retries on that condition would be dishonest.
                    VerificationOutcome::InfrastructureFailure
                } else {
                    VerificationOutcome::TestFailure
                };
                let mut detail = String::new();
                if out.timed_out {
                    detail.push_str("[timed out]\n");
                } else if matches!(out.exit_code, 126 | 127) {
                    detail.push_str(&format!(
                        "[verification command could not execute: exit {}]\n",
                        out.exit_code
                    ));
                }
                if out.stdout_truncated || out.stderr_truncated {
                    detail.push_str(&format!(
                        "[output truncated: stdout={}, stderr={}]\n",
                        out.stdout_truncated, out.stderr_truncated
                    ));
                }
                // Keep the tail (test failures print last), UTF-8-safe (code review CRITICAL:
                // a raw byte slice panics on a multibyte char at the cut).
                let combined = format!("{}\n{}", out.stdout, out.stderr);
                detail.push_str(&iteron_protocol::text::tail(&combined, 4000));
                Verdict::new(OracleStrength::Strong, outcome, detail)
            }
            Err(e) => Verdict::new(
                OracleStrength::Strong,
                VerificationOutcome::InfrastructureFailure,
                format!("oracle could not run tests: {e}"),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RecordingSandbox {
        sensitive_env_names: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    #[async_trait::async_trait]
    impl Sandbox for RecordingSandbox {
        async fn run(
            &self,
            _command: &str,
            conf: &Confinement,
        ) -> Result<iteron_sandbox::RunOutput, iteron_sandbox::SandboxError> {
            *self.sensitive_env_names.lock().unwrap() = conf.sensitive_env_names.clone();
            Ok(iteron_sandbox::RunOutput {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                stdout_truncated: false,
                stderr_truncated: false,
                timed_out: false,
            })
        }
    }

    #[test]
    fn only_strong_may_veto() {
        assert!(OracleStrength::Strong.may_veto());
        assert!(!OracleStrength::Medium.may_veto());
        assert!(!OracleStrength::Weak.may_veto());
        assert!(!OracleStrength::Weakest.may_veto());
    }

    #[test]
    fn strength_is_ordered() {
        assert!(OracleStrength::Strong > OracleStrength::Weak);
        assert!(OracleStrength::Weak > OracleStrength::Weakest);
    }

    #[tokio::test]
    async fn test_oracle_passes_exact_credential_names_to_confinement() {
        let observed = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let oracle = TestOracle::new(
            Box::new(RecordingSandbox {
                sensitive_env_names: observed.clone(),
            }),
            std::env::temp_dir(),
            "true".into(),
        )
        .with_sensitive_env_names(vec![
            "GATEWAY_KEY".into(),
            "GATEWAY_KEY".into(),
            "ANOTHER_CREDENTIAL".into(),
        ]);

        assert!(oracle.evaluate().await.passed());
        assert_eq!(
            *observed.lock().unwrap(),
            vec!["ANOTHER_CREDENTIAL", "GATEWAY_KEY"]
        );
    }

    struct FixedOutputSandbox(iteron_sandbox::RunOutput);

    #[async_trait::async_trait]
    impl Sandbox for FixedOutputSandbox {
        async fn run(
            &self,
            _command: &str,
            _conf: &Confinement,
        ) -> Result<iteron_sandbox::RunOutput, iteron_sandbox::SandboxError> {
            Ok(self.0.clone())
        }
    }

    #[tokio::test]
    async fn test_oracle_preserves_truncation_evidence_across_utf8_safe_tail() {
        let oracle = TestOracle::new(
            Box::new(FixedOutputSandbox(iteron_sandbox::RunOutput {
                exit_code: 1,
                stdout: "写".repeat(2_000),
                stderr: "尾".repeat(2_000),
                stdout_truncated: true,
                stderr_truncated: true,
                timed_out: false,
            })),
            std::env::temp_dir(),
            "test".into(),
        );

        let verdict = oracle.evaluate().await;
        assert_eq!(verdict.outcome, VerificationOutcome::TestFailure);
        assert!(
            verdict
                .detail
                .contains("[output truncated: stdout=true, stderr=true]")
        );
        assert!(verdict.detail.contains("… (truncated)"));
        assert!(verdict.detail.contains('尾'));
    }

    #[tokio::test]
    async fn test_oracle_timeout_is_typed_and_bounded_evidence() {
        let oracle = TestOracle::new(
            Box::new(FixedOutputSandbox(iteron_sandbox::RunOutput {
                exit_code: -1,
                stdout: "partial verification output".into(),
                stderr: String::new(),
                stdout_truncated: false,
                stderr_truncated: false,
                timed_out: true,
            })),
            std::env::temp_dir(),
            "test".into(),
        );

        let verdict = oracle.evaluate().await;
        assert_eq!(verdict.outcome, VerificationOutcome::TimedOut);
        assert!(!verdict.passed());
        assert!(verdict.detail.starts_with("[timed out]"));
        assert!(verdict.detail.contains("partial verification output"));
    }

    struct ErrorSandbox(iteron_sandbox::SandboxError);

    #[async_trait::async_trait]
    impl Sandbox for ErrorSandbox {
        async fn run(
            &self,
            _command: &str,
            _conf: &Confinement,
        ) -> Result<iteron_sandbox::RunOutput, iteron_sandbox::SandboxError> {
            Err(match &self.0 {
                iteron_sandbox::SandboxError::Unsupported => {
                    iteron_sandbox::SandboxError::Unsupported
                }
                iteron_sandbox::SandboxError::Spawn(detail) => {
                    iteron_sandbox::SandboxError::Spawn(detail.clone())
                }
                iteron_sandbox::SandboxError::Profile(detail) => {
                    iteron_sandbox::SandboxError::Profile(detail.clone())
                }
            })
        }
    }

    #[tokio::test]
    async fn sandbox_refusal_is_infrastructure_failure_not_test_failure() {
        let oracle = TestOracle::new(
            Box::new(ErrorSandbox(iteron_sandbox::SandboxError::Unsupported)),
            std::env::temp_dir(),
            "test".into(),
        );

        let verdict = oracle.evaluate().await;
        assert_eq!(verdict.outcome, VerificationOutcome::InfrastructureFailure);
        assert!(verdict.detail.contains("could not run tests"));
    }

    #[tokio::test]
    async fn missing_verification_command_is_infrastructure_failure() {
        let oracle = TestOracle::new(
            Box::new(FixedOutputSandbox(iteron_sandbox::RunOutput {
                exit_code: 127,
                stdout: String::new(),
                stderr: "missing-check: command not found".into(),
                stdout_truncated: false,
                stderr_truncated: false,
                timed_out: false,
            })),
            std::env::temp_dir(),
            "missing-check".into(),
        );

        let verdict = oracle.evaluate().await;
        assert_eq!(verdict.outcome, VerificationOutcome::InfrastructureFailure);
        assert!(verdict.detail.contains("exit 127"));
    }

    #[test]
    fn typed_outcomes_cannot_claim_pass_for_non_pass_states() {
        for outcome in [
            VerificationOutcome::TestFailure,
            VerificationOutcome::TimedOut,
            VerificationOutcome::InfrastructureFailure,
            VerificationOutcome::Cancelled,
        ] {
            let verdict = Verdict::new(OracleStrength::Strong, outcome, outcome.label());
            assert!(!verdict.passed(), "{} must fail closed", outcome.label());
        }
        assert!(Verdict::new(OracleStrength::Strong, VerificationOutcome::Pass, "ok").passed());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_oracle_runs_the_command_and_reports_exit() {
        use iteron_sandbox::platform_sandbox;
        let dir = std::env::temp_dir();
        let o = TestOracle::new(platform_sandbox(), dir, "exit 0".into());
        assert!(o.evaluate().await.passed());
        let o2 = TestOracle::new(platform_sandbox(), std::env::temp_dir(), "exit 1".into());
        assert_eq!(
            o2.evaluate().await.outcome,
            VerificationOutcome::TestFailure,
            "a nonzero exit is a candidate test failure"
        );
    }
}
