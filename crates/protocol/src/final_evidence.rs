//! Host observations accompanying an answer. These values are not completion requirements and
//! grant no authority. Model prose, generic exit status and Done are never test-suite receipts.
use crate::{RunId, Seq, TenantId, TurnId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostConfiguredCheckV1 {
    NotObserved,
    Passed,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostFinalCoverageV1 {
    /// Only the current live invocation's committed observations; not a historical test audit.
    LiveInvocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostFinalCorrectionV1 {
    TestSuccessUnverified,
    ConfiguredCheckFailed,
}

impl HostFinalCorrectionV1 {
    pub fn message(self) -> &'static str {
        match self {
            Self::TestSuccessUnverified => {
                "Test-suite success is unverified by host evidence; tool output, a successful command, and model prose are not test-suite receipts."
            }
            Self::ConfiguredCheckFailed => {
                "The configured check did not pass; test-suite success is not established by host evidence."
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostFinalEvidenceV1 {
    pub tenant: TenantId,
    pub run_id: RunId,
    pub first_turn: TurnId,
    pub final_turn: TurnId,
    /// Actual fsynced Done source, independent of the assistant Message and model assertions.
    pub source_seq: Seq,
    pub observed_tool_completions: u64,
    pub observed_tool_failures: u64,
    pub configured_check: HostConfiguredCheckV1,
    pub configured_check_source_seq: Option<Seq>,
    pub effects_known: bool,
    pub write_capable_effect_admitted: bool,
    pub coverage: HostFinalCoverageV1,
    /// These limits are explicit. No filesystem diff or suite identity check is introduced here.
    pub workspace_diff_inspected: bool,
    pub test_suite_identity_verified: bool,
    pub correction: Option<HostFinalCorrectionV1>,
}
