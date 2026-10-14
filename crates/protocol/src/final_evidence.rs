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

/// Observed work, independent of terminal success and optional check status. No category
/// certifies current workspace state, relevant test-suite identity or absence of problems.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostFinalWorkStateV1 {
    #[default]
    Unverified,
    ChangedUnverified,
}
impl HostFinalWorkStateV1 {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unverified => "work remains unverified",
            Self::ChangedUnverified => "native changes observed; suite unverified",
        }
    }
    fn is_unverified(&self) -> bool {
        *self == Self::Unverified
    }
}
fn is_zero(value: &u64) -> bool {
    *value == 0
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
    /// Count of byte-changing native file commits in this live invocation. Repeated commits to
    /// one file each count; this is neither a distinct-file count nor a current workspace scan.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub observed_native_file_changes: u64,
    /// Last actual successful ToolDone joined to a sealed guarded native mutation receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_change_source_seq: Option<Seq>,
    #[serde(default, skip_serializing_if = "HostFinalWorkStateV1::is_unverified")]
    pub work_state: HostFinalWorkStateV1,
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

impl HostFinalEvidenceV1 {
    /// Shared readonly consistency check. The host still establishes the actual receipt; valid
    /// scalar shape alone cannot manufacture a native change or any dispatch authority.
    pub fn native_change_evidence_valid(&self) -> bool {
        match (
            self.observed_native_file_changes,
            self.native_change_source_seq,
            self.work_state,
        ) {
            (0, None, HostFinalWorkStateV1::Unverified) => true,
            (count, Some(seq), HostFinalWorkStateV1::ChangedUnverified) => {
                count > 0
                    && seq.0 > 0
                    && seq < self.source_seq
                    && self.observed_tool_completions > self.observed_tool_failures
                    && self.write_capable_effect_admitted
            }
            _ => false,
        }
    }
}
