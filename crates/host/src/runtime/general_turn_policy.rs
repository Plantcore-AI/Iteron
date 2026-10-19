//! Zero-state policy for ordinary coding turns.
//! Ticket graph, localization and owner-audit logic is physically absent from this build.
//! Real verification filesystem identities are owned by candidate_workspace independently.

pub(super) use super::candidate_workspace::{
    CandidateDiffState, CandidateWorkspaceBaseline, VerificationCandidateGuard,
};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ConvergenceStage {}
impl ConvergenceStage {
    pub(super) const fn reason_code(self) -> &'static str {
        match self {}
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ConvergenceRequest {
    pub(super) observations: u32,
    pub(super) instruction: &'static str,
    pub(super) stage: ConvergenceStage,
}
#[derive(Debug, Default)]
pub(super) struct InvestigationConvergence;
impl InvestigationConvergence {
    #[inline]
    pub(super) fn for_general_run() -> Self {
        Self
    }
    #[inline]
    pub(super) const fn enabled(&self) -> bool {
        false
    }
    #[inline]
    pub(super) const fn patch_trial_active(&self) -> bool {
        false
    }
    #[inline]
    pub(super) const fn candidate_change_allowed(&self) -> bool {
        true
    }
    #[inline]
    pub(super) const fn candidate_change_required(&self) -> bool {
        false
    }
    #[inline]
    pub(super) fn candidate_revision_required(&self) -> bool {
        false
    }
    #[inline]
    pub(super) const fn structural_repair_read_required(&self) -> bool {
        false
    }
    #[inline]
    pub(super) const fn behavior_counterexample_read_required(&self) -> bool {
        false
    }
    #[inline]
    pub(super) fn reopen_immediate_candidate_action(&mut self) -> bool {
        false
    }
    #[inline]
    pub(super) fn guard_verification_candidate(
        &mut self,
        _candidate: CandidateDiffState,
    ) -> VerificationCandidateGuard {
        VerificationCandidateGuard::Verify
    }
    #[inline]
    pub(super) fn has_failed_verification_candidate(&self) -> bool {
        false
    }
    #[inline]
    pub(super) fn remember_verification_test_failure(&mut self, _candidate: CandidateDiffState) {}
    #[inline]
    pub(super) const fn localization_plateau_active(&self) -> bool {
        false
    }
    #[inline]
    pub(super) const fn localized_closure_active(&self) -> bool {
        false
    }
    #[inline]
    pub(super) fn observe_localization_scopes_for_round(
        &mut self,
        _scopes: impl IntoIterator<Item = String>,
        _clean_no_candidate_round: bool,
    ) -> Option<ConvergenceRequest> {
        None
    }
    #[inline]
    pub(super) fn localization_scope(
        _tool_name: &str,
        _input: &serde_json::Value,
    ) -> Option<String> {
        None
    }
    #[inline]
    pub(super) const fn candidate_review_active(&self) -> bool {
        false
    }
    #[inline]
    pub(super) const fn candidate_handoff_terminal(&self) -> bool {
        false
    }
    #[inline]
    pub(super) const fn candidate_owner_evidence_required(&self) -> bool {
        false
    }
    #[inline]
    pub(super) const fn evidence_insufficient_terminal(&self) -> bool {
        false
    }
    #[inline]
    pub(super) fn authorized_repair_paths(&self) -> &[PathBuf] {
        &[]
    }
    #[inline]
    pub(super) fn mutation_failure_signature(_tool: &str, _diagnostic: &str) -> [u8; 32] {
        [0; 32]
    }
    #[inline]
    pub(super) fn stable_key_search_supports_owner(
        _pattern: &str,
        _evidence: Option<iteron_tools::WorkspaceEvidence>,
    ) -> bool {
        false
    }
    #[inline]
    pub(super) fn observe_candidate_round(
        &mut self,
        _diff: CandidateDiffState,
        _attempted_mutation: bool,
        _mutation_failure: Option<[u8; 32]>,
        _exact_read: bool,
        _stable_key_search: bool,
    ) -> Option<ConvergenceRequest> {
        None
    }
    #[inline]
    pub(super) fn verification_failed(
        &mut self,
        _rolled_back: bool,
        _structural_regression: bool,
    ) -> Option<ConvergenceRequest> {
        None
    }
    #[inline]
    pub(super) fn verification_passed(&mut self) {}
    #[inline]
    pub(super) fn observe_round(
        &mut self,
        _candidate_change_outstanding: Option<bool>,
        _completed_targeted_observation: bool,
        _repair_evidence: Option<iteron_tools::RepairEvidenceReceipt>,
        _completed_observation: bool,
    ) -> Option<ConvergenceRequest> {
        None
    }
}
