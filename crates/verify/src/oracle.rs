//! Oracles, ranked by strength. A weak oracle never vetoes (ADR-005 R6).

use core_sandbox::{Confinement, Sandbox};
use std::path::PathBuf;

/// How much authority an oracle's verdict carries. The ranking is a type, not a convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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

/// An oracle's verdict on a candidate (or on the current working tree).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub strength: OracleStrength,
    pub passed: bool,
    /// Human-legible detail (e.g. the failing test output), truncated for context hygiene.
    pub detail: String,
}

/// Something that can judge the current state of the workspace.
#[async_trait::async_trait]
pub trait Oracle: Send + Sync {
    fn strength(&self) -> OracleStrength;
    /// Evaluate the current workspace. Returns a verdict; an execution failure is itself a
    /// non-pass (a test command that cannot run is not a pass).
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
                let passed = !out.timed_out && out.exit_code == 0;
                let mut detail = String::new();
                if out.timed_out {
                    detail.push_str("[timed out]\n");
                }
                // Keep the tail (test failures print last), UTF-8-safe (code review CRITICAL:
                // a raw byte slice panics on a multibyte char at the cut).
                let combined = format!("{}\n{}", out.stdout, out.stderr);
                detail.push_str(&core_protocol::text::tail(&combined, 4000));
                Verdict {
                    strength: OracleStrength::Strong,
                    passed,
                    detail,
                }
            }
            Err(e) => Verdict {
                strength: OracleStrength::Strong,
                passed: false, // a test command that cannot run is not a pass
                detail: format!("oracle could not run tests: {e}"),
            },
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
        ) -> Result<core_sandbox::RunOutput, core_sandbox::SandboxError> {
            *self.sensitive_env_names.lock().unwrap() = conf.sensitive_env_names.clone();
            Ok(core_sandbox::RunOutput {
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

        assert!(oracle.evaluate().await.passed);
        assert_eq!(
            *observed.lock().unwrap(),
            vec!["ANOTHER_CREDENTIAL", "GATEWAY_KEY"]
        );
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_oracle_runs_the_command_and_reports_exit() {
        use core_sandbox::platform_sandbox;
        let dir = std::env::temp_dir();
        let o = TestOracle::new(platform_sandbox(), dir, "exit 0".into());
        assert!(o.evaluate().await.passed);
        let o2 = TestOracle::new(platform_sandbox(), std::env::temp_dir(), "exit 1".into());
        assert!(!o2.evaluate().await.passed, "a nonzero exit is not a pass");
    }
}
