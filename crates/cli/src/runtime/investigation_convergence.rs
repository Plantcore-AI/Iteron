//! Evidence-phase convergence policy for tool-driven investigation.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

const GRAPH_PROGRESS_INSTRUCTION: &str = "[Iteron graph progress] The repair graph remains open. Continue only with a bounded observation that fills or refutes a named producer, boundary, consumer, invariant, or verifier slot, then submit updated typed repair evidence. Do not repeat equivalent observations for confidence.";
const GRAPH_NO_PROGRESS_INSTRUCTION: &str = "[Iteron graph no-progress] The latest receipt did not change the repair graph. Do not repeat the same evidence digest or equivalent observation. Address a different open slot with exact evidence, or report evidence-insufficient when the bounded frontier is genuinely exhausted; observation count alone never ends the investigation.";
const GRAPH_EXHAUSTED_INSTRUCTION: &str = "[Iteron evidence-insufficient terminal] The typed repair graph has no remaining evidence slots and did not authorize a repair intent. Do not call more tools or guess a patch. Briefly report the unresolved evidence boundary and stop.";
const CANDIDATE_CHANGE_INSTRUCTION: &str = "[Iteron repair selected] Typed repair evidence selected a hypothesis and authorized candidate paths. Change only the authorized path set at the earliest violated producer-boundary-consumer edge, preserve recorded invariants, then inspect the diff and run the narrowest focused verifier. When editing a structured identifier, date, serial, or template pattern, change only the task-evidenced segment and preserve the count and order of every orthogonal literal or variable token unless source-backed evidence requires otherwise. Do not reopen discovery or add speculative compatibility behavior.";
const CANDIDATE_REVIEW_INSTRUCTION: &str = "[Iteron candidate review] An actual candidate mutation exists. Review only the candidate paths, diff, required behavior, preserved invariants, and focused verifier. The diff must close every already-visible producer-boundary-consumer edge, including control-flow ordering; a state write left inside an unawaited async branch does not close a downstream continuation. For structured identifier, date, serial, or template patterns, reject collateral changes to token count or order that the task did not require. If the evidence does not support a causally complete patch, revise or revert it and conclude evidence-insufficient; otherwise verify and finish without reopening discovery.";
const CANDIDATE_OWNER_EVIDENCE_INSTRUCTION: &str = "[Iteron post-candidate reference audit required] A first non-empty candidate exists. Before revision or handoff, grep one exact stable key introduced or depended on by the candidate over the smallest scope containing every owner/reference. Every new executable identifier must resolve to a local, parameter, or declared import in that runtime module; a same-name repository occurrence does not prove it is bound. For declarative metadata, prefer the row's immutable primary/foreign identity over a display name, rule field, or short business code, and audit every current, bootstrap, and upgrade mirror returned for that identity. Every new identifier/reference must close through an existing definition and usage/active owner. If all occurrences are in the candidate, or repository/user-visible semantic evidence names a conflicting concept, complete the source-backed closure or remove the guess; never defer it to UAT. Then revise once or preserve only a supported candidate.";
const CANDIDATE_OWNER_EVIDENCE_READY_INSTRUCTION: &str = "[Iteron post-candidate reference audit ready] The bounded stable-key audit returned owner/reference or metadata context for the current candidate. If one exact definition or caller block is still needed, read it once now; then make at most one coherent revision, revert an unsupported reference, or preserve the supported candidate for verification. Do not reopen broad discovery.";
const CANDIDATE_OWNER_BLOCK_READY_INSTRUCTION: &str = "[Iteron owner block ready] The one bounded owner/caller read is complete. Before handoff, confirm the diff closes every already-visible data and control-flow edge; a write inside an unawaited async branch does not order a downstream continuation. Revise the candidate once from that evidence, or preserve it for verification; do not call more observation tools or reopen discovery.";
const VERIFICATION_COUNTEREXAMPLE_INSTRUCTION: &str = "[Iteron verifier counterexample] The focused verifier refuted the selected repair. The reverted candidate is not terminal while verifier retry policy permits continuation: return to the typed repair graph, record the counterexample, and fill the newly opened slot before selecting another repair.";
const VERIFICATION_REVISION_INSTRUCTION: &str = "[Iteron verifier counterexample] The focused verifier refuted the current candidate, which remains in the workspace. Review or revert only the authorized paths using the verifier evidence; do not reopen broad discovery. Revise existing source with an exact-hunk edit or patch; do not replace or recreate a whole existing file. A reverted candidate may return to graph explanation while verifier retry policy permits continuation.";
const UNCHANGED_FAILED_CANDIDATE_INSTRUCTION: &str = "The strong verifier already rejected this exact candidate state. Make a real candidate transition or fully revert the candidate before requesting verification again.";
const UNCHANGED_FAILED_CANDIDATE_TERMINAL_INSTRUCTION: &str = "The rejected candidate was submitted unchanged again after the transition request. Verification was not rerun; stopping this bounded repair loop.";
const CANDIDATE_WITHDRAWN_INSTRUCTION: &str = "[Iteron evidence-insufficient terminal] The current workspace change-set matches its pre-candidate baseline: the candidate has been fully reverted and no outstanding repair remains. Do not call tools, restart discovery, verify the absent candidate, or attempt a replacement edit. Briefly report that the available evidence did not support the candidate and stop.";
const CANDIDATE_HANDOFF_INSTRUCTION: &str = "[Iteron candidate handoff] The candidate diff is stable only if it closes every already-visible producer-boundary-consumer edge, including required control-flow ordering. If so, preserve it, stop mutating, and hand it off for the configured verifier or final response; otherwise make the one supported causal revision without reopening discovery.";
const NET_ZERO_RECOVERY_INSTRUCTION: &str = "[Iteron net-zero candidate] The attempted mutation left no candidate diff. At most one exact reread of the localized target may be used to correct stale edit context; otherwise stop without forcing a mutation.";
const REJECTED_MUTATION_RECOVERY_INSTRUCTION: &str = "[Iteron mutation rejected] The mutation tool made no workspace change. Treat its diagnostic as recovery evidence, correct the exact path or hunk, and make one supported mutation. This is not a candidate or a reverted patch; do not create probe files or reopen broad discovery.";
const LOCALIZATION_PLATEAU_INSTRUCTION: &str = "[Iteron localization plateau] Broad discovery is closed and the bounded exact owner evidence is now available. Compare its task-relevant producer, boundary, and consumer: if it exposes a concrete mismatch, make the smallest supported edit next; otherwise conclude that the visible evidence is insufficient. Do not reread the same scope or resume synonym or directory search.";
const LOCALIZATION_EXHAUSTED_INSTRUCTION: &str = "[Iteron localized decision] The same bounded source region was read again and added no localization evidence, so observation tools are now closed. If the evidence already exposes a concrete mismatch, make that smallest supported edit now; otherwise report the unresolved evidence boundary and stop. Do not promise another read, grep, test, or future action.";
const LOCALIZED_CLOSURE_INSTRUCTION: &str = "[Iteron localized closure] Two distinct exact source owners have now been consumed without a tool error or candidate mutation. Either make the smallest supported edit next, use one final exact read batch to close a named dependency, or conclude evidence-insufficient. Broad search, shell discovery, diff review, and directory traversal are closed.";
const LOCALIZED_EXPANSION_COMPLETE_INSTRUCTION: &str = "[Iteron localized decision] The one bounded exact-read expansion is complete. Make the smallest supported edit now, or conclude evidence-insufficient; do not call more observation tools.";
const STRUCTURAL_REGRESSION_REFRESH_INSTRUCTION: &str = "[Iteron structural repair refresh] Verification regressed from an executable candidate to a parser/load/syntax failure. Read the currently changed target once to refresh the exact hunk; do not search elsewhere or retry stale replacement text.";
const STRUCTURAL_REGRESSION_REPAIR_INSTRUCTION: &str = "[Iteron structural repair] The current changed hunk is refreshed. Make one surgical exact-hunk edit or patch that restores structural integrity while preserving the prior behavior fix; do not replace or recreate a whole existing file. Then let the focused verifier decide. Do not reopen discovery.";
const BEHAVIOR_COUNTEREXAMPLE_REFRESH_INSTRUCTION: &str = "[Iteron verifier counterexample refresh] The focused verifier disproved the current behavior or ownership hypothesis. Before another mutation, inspect the exact next owner or consumer block named by the counterexample or already-visible source. Use at most one bounded grep when its path is unknown, then read the exact block; do not keep tuning the rejected owner or reopen broad discovery.";

fn graph_progress_instruction() -> &'static str {
    iteron_tunables::param_str(
        "cli.runtime.investigation_convergence.graph_progress_instruction",
        GRAPH_PROGRESS_INSTRUCTION,
    )
}

fn graph_no_progress_instruction() -> &'static str {
    iteron_tunables::param_str(
        "cli.runtime.investigation_convergence.graph_no_progress_instruction",
        GRAPH_NO_PROGRESS_INSTRUCTION,
    )
}

fn graph_exhausted_instruction() -> &'static str {
    iteron_tunables::param_str(
        "cli.runtime.investigation_convergence.graph_exhausted_instruction",
        GRAPH_EXHAUSTED_INSTRUCTION,
    )
}

fn candidate_change_instruction() -> &'static str {
    iteron_tunables::param_str(
        "cli.runtime.investigation_convergence.candidate_change_instruction",
        CANDIDATE_CHANGE_INSTRUCTION,
    )
}

fn candidate_review_instruction() -> &'static str {
    iteron_tunables::param_str(
        "cli.runtime.investigation_convergence.candidate_review_instruction",
        CANDIDATE_REVIEW_INSTRUCTION,
    )
}

fn candidate_owner_evidence_instruction() -> &'static str {
    iteron_tunables::param_str(
        "cli.runtime.investigation_convergence.candidate_owner_evidence_instruction",
        CANDIDATE_OWNER_EVIDENCE_INSTRUCTION,
    )
}

fn candidate_owner_evidence_ready_instruction() -> &'static str {
    iteron_tunables::param_str(
        "cli.runtime.investigation_convergence.candidate_owner_evidence_ready_instruction",
        CANDIDATE_OWNER_EVIDENCE_READY_INSTRUCTION,
    )
}

fn candidate_owner_block_ready_instruction() -> &'static str {
    iteron_tunables::param_str(
        "cli.runtime.investigation_convergence.candidate_owner_block_ready_instruction",
        CANDIDATE_OWNER_BLOCK_READY_INSTRUCTION,
    )
}

fn verification_counterexample_instruction() -> &'static str {
    iteron_tunables::param_str(
        "cli.runtime.investigation_convergence.verification_counterexample_instruction",
        VERIFICATION_COUNTEREXAMPLE_INSTRUCTION,
    )
}

fn verification_revision_instruction() -> &'static str {
    iteron_tunables::param_str(
        "cli.runtime.investigation_convergence.verification_revision_instruction",
        VERIFICATION_REVISION_INSTRUCTION,
    )
}

fn candidate_withdrawn_instruction() -> &'static str {
    iteron_tunables::param_str(
        "cli.runtime.investigation_convergence.candidate_withdrawn_instruction",
        CANDIDATE_WITHDRAWN_INSTRUCTION,
    )
}

fn unchanged_failed_candidate_instruction() -> &'static str {
    iteron_tunables::param_str(
        "cli.runtime.investigation_convergence.unchanged_failed_candidate_instruction",
        UNCHANGED_FAILED_CANDIDATE_INSTRUCTION,
    )
}

fn unchanged_failed_candidate_terminal_instruction() -> &'static str {
    iteron_tunables::param_str(
        "cli.runtime.investigation_convergence.unchanged_failed_candidate_terminal_instruction",
        UNCHANGED_FAILED_CANDIDATE_TERMINAL_INSTRUCTION,
    )
}

fn candidate_handoff_instruction() -> &'static str {
    iteron_tunables::param_str(
        "cli.runtime.investigation_convergence.candidate_handoff_instruction",
        CANDIDATE_HANDOFF_INSTRUCTION,
    )
}

fn net_zero_recovery_instruction() -> &'static str {
    iteron_tunables::param_str(
        "cli.runtime.investigation_convergence.net_zero_recovery_instruction",
        NET_ZERO_RECOVERY_INSTRUCTION,
    )
}

fn rejected_mutation_recovery_instruction() -> &'static str {
    iteron_tunables::param_str(
        "cli.runtime.investigation_convergence.rejected_mutation_recovery_instruction",
        REJECTED_MUTATION_RECOVERY_INSTRUCTION,
    )
}

fn localization_plateau_instruction() -> &'static str {
    iteron_tunables::param_str(
        "cli.runtime.investigation_convergence.localization_plateau_instruction",
        LOCALIZATION_PLATEAU_INSTRUCTION,
    )
}

fn localization_exhausted_instruction() -> &'static str {
    iteron_tunables::param_str(
        "cli.runtime.investigation_convergence.localization_exhausted_instruction",
        LOCALIZATION_EXHAUSTED_INSTRUCTION,
    )
}

fn localized_closure_instruction() -> &'static str {
    iteron_tunables::param_str(
        "cli.runtime.investigation_convergence.localized_closure_instruction",
        LOCALIZED_CLOSURE_INSTRUCTION,
    )
}

fn localized_expansion_complete_instruction() -> &'static str {
    iteron_tunables::param_str(
        "cli.runtime.investigation_convergence.localized_expansion_complete_instruction",
        LOCALIZED_EXPANSION_COMPLETE_INSTRUCTION,
    )
}

fn structural_regression_refresh_instruction() -> &'static str {
    iteron_tunables::param_str(
        "cli.runtime.investigation_convergence.structural_regression_refresh_instruction",
        STRUCTURAL_REGRESSION_REFRESH_INSTRUCTION,
    )
}

fn structural_regression_repair_instruction() -> &'static str {
    iteron_tunables::param_str(
        "cli.runtime.investigation_convergence.structural_regression_repair_instruction",
        STRUCTURAL_REGRESSION_REPAIR_INSTRUCTION,
    )
}

fn behavior_counterexample_refresh_instruction() -> &'static str {
    iteron_tunables::param_str(
        "cli.runtime.investigation_convergence.behavior_counterexample_refresh_instruction",
        BEHAVIOR_COUNTEREXAMPLE_REFRESH_INSTRUCTION,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ConvergenceStage {
    Explain,
    Mutate,
    Review,
    EvidenceInsufficient,
}

impl ConvergenceStage {
    pub(super) const fn reason_code(self) -> &'static str {
        match self {
            Self::Explain => "strategy_graph_explain",
            Self::Mutate => "strategy_graph_mutate",
            Self::Review => "strategy_graph_review",
            Self::EvidenceInsufficient => "strategy_evidence_insufficient",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ConvergenceRequest {
    pub(super) observations: u32,
    pub(super) instruction: &'static str,
    pub(super) stage: ConvergenceStage,
}

/// Strategy state follows evidence transitions instead of a fixed round deadline. Global run
/// budgets remain authoritative, but a model is never forced to guess merely because it reached
/// an arbitrary turn number.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct InvestigationConvergence {
    observations: u32,
    state: GraphState,
    last_receipt_digest: Option<String>,
    open_slots: u32,
    authorized_repair_paths: Vec<PathBuf>,
    localization_scopes: BTreeSet<String>,
    non_novel_localization_batches: u8,
    localization_plateau: bool,
    localization_exhausted: bool,
    initial_localization_plateau: bool,
    initial_exact_read_paths: BTreeSet<String>,
    localized_closure_active: bool,
    last_candidate_diff: Option<[u8; 32]>,
    last_mutation_failure: Option<[u8; 32]>,
    net_zero_reread_available: bool,
    candidate_owner_evidence_required: bool,
    post_candidate_evidence_available: bool,
    structural_repair_read_required: bool,
    behavior_counterexample_read_required: bool,
    failed_verification_candidates: BTreeSet<CandidateDiffState>,
    consecutive_unchanged_failed_completions: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum GraphState {
    #[default]
    Discover,
    Explain,
    Mutate,
    Review,
    NetZeroRecovery,
    Handoff,
    Done,
    EvidenceInsufficient,
}

/// Pre-change identities for exactly the paths named by structured candidate tools. Capturing is
/// lazy (the first candidate write pays for it), bounded by the same transaction ceiling as the
/// tools, and preserves identities across later revisions. Any unavailable identity fails open to
/// continued review: without an exact pre-image the controller must not claim a revert.
#[derive(Debug, Default)]
pub(super) struct CandidateWorkspaceBaseline {
    paths: BTreeMap<PathBuf, iteron_tools::WorkspaceCandidatePathIdentity>,
    incomplete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum CandidateDiffState {
    Unavailable,
    Empty,
    Changed([u8; 32]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VerificationCandidateGuard {
    Verify,
    RequireTransition(&'static str),
    Stop(&'static str),
}

impl CandidateWorkspaceBaseline {
    pub(super) async fn capture_before<'a>(&mut self, paths: impl IntoIterator<Item = &'a Path>) {
        for path in paths {
            if self.paths.contains_key(path) {
                continue;
            }
            match iteron_tools::workspace_candidate_path_identity(path).await {
                Ok(identity) => {
                    self.paths.insert(path.to_owned(), identity);
                }
                Err(_) => self.incomplete = true,
            }
        }
    }

    pub(super) async fn diff_state(&self) -> CandidateDiffState {
        if self.incomplete || self.paths.is_empty() {
            return CandidateDiffState::Unavailable;
        }
        let mut changed = false;
        let mut digest = Sha256::new();
        for (path, baseline) in &self.paths {
            match iteron_tools::workspace_candidate_path_identity(path).await {
                Ok(current) if current == *baseline => {}
                Ok(current) => {
                    changed = true;
                    digest.update(path.as_os_str().as_encoded_bytes());
                    digest.update([0]);
                    for identity in [*baseline, current] {
                        match identity {
                            iteron_tools::WorkspaceCandidatePathIdentity::Missing => {
                                digest.update([0])
                            }
                            iteron_tools::WorkspaceCandidatePathIdentity::File(bytes) => {
                                digest.update([1]);
                                digest.update(bytes);
                            }
                        }
                    }
                }
                Err(_) => return CandidateDiffState::Unavailable,
            }
        }
        if changed {
            CandidateDiffState::Changed(digest.finalize().into())
        } else {
            CandidateDiffState::Empty
        }
    }
}

impl InvestigationConvergence {
    pub(super) fn for_run() -> Self {
        let initial_localization_plateau = iteron_tunables::param_bool(
            "cli.runtime.investigation_convergence.initial_localization_plateau",
            false,
        );
        Self {
            localization_plateau: initial_localization_plateau,
            initial_localization_plateau,
            ..Self::default()
        }
    }

    /// The graph-only tool surface is a recovery mode after an independent verifier
    /// counterexample, never the default coding path.
    pub(super) const fn patch_trial_active(&self) -> bool {
        matches!(self.state, GraphState::Explain)
    }

    /// Ordinary repairs may mutate directly in Discover. A voluntarily selected typed receipt
    /// enters Mutate, while a live candidate remains revisable in Review. Explain deliberately
    /// requires a new receipt before another candidate after a verifier-owned rollback.
    pub(super) const fn candidate_change_allowed(&self) -> bool {
        matches!(
            self.state,
            GraphState::Discover
                | GraphState::Mutate
                | GraphState::Review
                | GraphState::NetZeroRecovery
        )
    }

    pub(super) const fn candidate_change_required(&self) -> bool {
        matches!(self.state, GraphState::Mutate)
    }

    /// Once a strong verifier has rejected candidate bytes, the next transition must preserve the
    /// existing source outside the counterexample. `edit` and `apply_patch` can still revise or
    /// delete exact hunks and can create a genuinely new file; hiding `write_file` only removes the
    /// high-risk whole-file replacement path that discards unrelated code during repair.
    pub(super) fn candidate_revision_required(&self) -> bool {
        self.candidate_change_required() && !self.failed_verification_candidates.is_empty()
    }

    /// A verifier-proven structural regression gets one exact current-hunk refresh before another
    /// mutation. This prevents stale replacement text from deadlocking mutate-only recovery.
    pub(super) const fn structural_repair_read_required(&self) -> bool {
        self.structural_repair_read_required
    }

    /// A behavioral verifier counterexample may invalidate ownership rather than syntax. Keep the
    /// live candidate frozen while one bounded owner/consumer block is retrieved, then reopen only
    /// exact-hunk mutation. This avoids both blind tuning and speculative whole-file replacement.
    pub(super) const fn behavior_counterexample_read_required(&self) -> bool {
        self.behavior_counterexample_read_required
    }

    /// Reopen exactly one immediate mutation surface when an automated implementation turn ended
    /// by promising the edit instead of issuing it.  Ordinary Discover/Mutate states may narrow to
    /// Mutate.  An evidence-insufficient terminal is recoverable only when it came from the local
    /// read plateau before any candidate or verifier rejection; graph exhaustion, withdrawal and
    /// rejected-candidate terminals remain closed.
    pub(super) fn reopen_immediate_candidate_action(&mut self) -> bool {
        let recoverable_state = matches!(self.state, GraphState::Discover | GraphState::Mutate)
            || (matches!(self.state, GraphState::EvidenceInsufficient)
                && self.localization_exhausted);
        if !recoverable_state
            || self.last_candidate_diff.is_some()
            || !self.failed_verification_candidates.is_empty()
        {
            return false;
        }
        self.state = GraphState::Mutate;
        self.net_zero_reread_available = false;
        self.candidate_owner_evidence_required = false;
        self.post_candidate_evidence_available = false;
        self.structural_repair_read_required = false;
        self.behavior_counterexample_read_required = false;
        self.last_mutation_failure = None;
        true
    }

    /// Suppress only a completion that would rerun the strong verifier over bytes it has already
    /// refuted. The first unchanged completion gets one transition request; the second stops the
    /// loop. An unavailable identity cannot prove equality and therefore preserves the existing
    /// verifier behavior.
    pub(super) fn guard_verification_candidate(
        &mut self,
        candidate: CandidateDiffState,
    ) -> VerificationCandidateGuard {
        if candidate == CandidateDiffState::Unavailable {
            self.consecutive_unchanged_failed_completions = 0;
            return VerificationCandidateGuard::Verify;
        }
        if !self.failed_verification_candidates.contains(&candidate) {
            self.consecutive_unchanged_failed_completions = 0;
            return VerificationCandidateGuard::Verify;
        }

        self.consecutive_unchanged_failed_completions = self
            .consecutive_unchanged_failed_completions
            .saturating_add(1);
        if self.consecutive_unchanged_failed_completions == 1 {
            self.state = GraphState::Mutate;
            self.net_zero_reread_available = false;
            self.candidate_owner_evidence_required = false;
            self.post_candidate_evidence_available = false;
            self.structural_repair_read_required = false;
            self.behavior_counterexample_read_required = false;
            VerificationCandidateGuard::RequireTransition(unchanged_failed_candidate_instruction())
        } else {
            self.state = GraphState::EvidenceInsufficient;
            self.candidate_owner_evidence_required = false;
            self.post_candidate_evidence_available = false;
            self.structural_repair_read_required = false;
            self.behavior_counterexample_read_required = false;
            VerificationCandidateGuard::Stop(unchanged_failed_candidate_terminal_instruction())
        }
    }

    pub(super) fn has_failed_verification_candidate(&self) -> bool {
        !self.failed_verification_candidates.is_empty()
    }

    /// Only a definite behavior failure with an exact identity owns candidate memory. The set is
    /// run-local and bounded by the verifier retry ceiling, so returning to any previously rejected
    /// candidate cannot evade the guard through an A -> B -> A cycle. An unavailable identity
    /// preserves the prior fail-open behavior and clears equality claims it cannot substantiate.
    pub(super) fn remember_verification_test_failure(&mut self, candidate: CandidateDiffState) {
        if candidate == CandidateDiffState::Unavailable {
            self.failed_verification_candidates.clear();
        } else {
            self.failed_verification_candidates.insert(candidate);
        }
        self.consecutive_unchanged_failed_completions = 0;
    }

    /// Repeated broad observations retain exact reads and candidate edits but close repository-
    /// wide discovery. This depends on evidence scope novelty, not on a provider-turn deadline.
    pub(super) const fn localization_plateau_active(&self) -> bool {
        self.localization_plateau && !self.localization_exhausted
    }

    pub(super) const fn localized_closure_active(&self) -> bool {
        self.localized_closure_active && !self.localization_exhausted
    }

    /// Record successful native observation scopes from one provider batch. Different query text
    /// over the same root is not new localization evidence; a newly narrowed subtree or exact
    /// source region is. Two repeated-scope batches close broad search, and one later non-novel
    /// exact-read batch closes observation so the next turn can only edit or conclude.
    #[cfg(test)]
    fn observe_localization_scopes(
        &mut self,
        scopes: impl IntoIterator<Item = String>,
    ) -> Option<ConvergenceRequest> {
        self.observe_localization_scopes_for_round(scopes, true)
    }

    pub(super) fn observe_localization_scopes_for_round(
        &mut self,
        scopes: impl IntoIterator<Item = String>,
        clean_no_candidate_round: bool,
    ) -> Option<ConvergenceRequest> {
        if !matches!(self.state, GraphState::Discover) || self.localization_exhausted {
            return None;
        }
        let mut observed = false;
        let mut novel = false;
        let mut exact_read = false;
        for scope in scopes {
            let scope = scope.trim();
            if scope.is_empty() {
                continue;
            }
            observed = true;
            exact_read |= scope.starts_with("read_file:");
            if self.initial_localization_plateau
                && clean_no_candidate_round
                && scope.starts_with("read_file:")
                && self.initial_exact_read_paths.len() < 3
            {
                let identity = scope.strip_prefix("read_file:").unwrap_or(scope);
                let path = identity.split_once('@').map_or(identity, |(path, _)| path);
                self.initial_exact_read_paths.insert(path.to_owned());
            }
            novel |= self.localization_scopes.insert(scope.to_owned());
        }
        if !observed {
            return None;
        }
        if self.localized_closure_active && clean_no_candidate_round && exact_read {
            self.localized_closure_active = false;
            self.localization_exhausted = true;
            self.state = GraphState::Mutate;
            return Some(self.request(
                localized_expansion_complete_instruction(),
                ConvergenceStage::Mutate,
            ));
        }
        if self.initial_localization_plateau
            && clean_no_candidate_round
            && self.initial_exact_read_paths.len() >= 2
        {
            self.localized_closure_active = true;
            return Some(self.request(localized_closure_instruction(), ConvergenceStage::Explain));
        }
        if novel {
            if self.localization_plateau && exact_read {
                self.non_novel_localization_batches = 0;
                return Some(self.request(
                    localization_plateau_instruction(),
                    ConvergenceStage::Explain,
                ));
            }
            // A provider commonly changes query text over the same broad root, then consumes one
            // exact file from those results.  The exact path is useful focus, but it is not a
            // reason to reopen repository-wide discovery and erase the already observed
            // diminishing return.  Close only the broad surface; exact reads and candidate edits
            // remain available.  This is scope/evidence driven rather than a provider-turn cap.
            if exact_read && self.non_novel_localization_batches > 0 {
                self.localization_plateau = true;
                self.non_novel_localization_batches = 0;
                return Some(self.request(
                    localization_plateau_instruction(),
                    ConvergenceStage::Explain,
                ));
            }
            self.non_novel_localization_batches = 0;
            return None;
        }

        if self.localization_plateau {
            self.localization_exhausted = true;
            self.state = GraphState::Mutate;
            return Some(self.request(
                localization_exhausted_instruction(),
                ConvergenceStage::Mutate,
            ));
        }

        self.non_novel_localization_batches = self.non_novel_localization_batches.saturating_add(1);
        if self.non_novel_localization_batches < 2 {
            return None;
        }
        self.localization_plateau = true;
        self.non_novel_localization_batches = 0;
        Some(self.request(
            localization_plateau_instruction(),
            ConvergenceStage::Explain,
        ))
    }

    /// Normalize discovery by the workspace root it inspects. Different query text or discovery
    /// tools over the same root are not new localization evidence; a narrower path or exact file is.
    pub(super) fn localization_scope(tool_name: &str, input: &serde_json::Value) -> Option<String> {
        let raw_path = input
            .get("path")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|path| !path.is_empty());
        let (kind, raw_path) = match (tool_name, raw_path) {
            ("grep" | "glob" | "list_dir", path) => ("workspace", path.unwrap_or(".")),
            (_, Some(path)) => (tool_name, path),
            _ => return None,
        };
        let path = raw_path
            .strip_prefix("./")
            .filter(|path| !path.is_empty())
            .unwrap_or(raw_path);
        if tool_name == "read_file" {
            let offset = input
                .get("offset")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            return Some(format!("{kind}:{path}@{offset}"));
        }
        Some(format!("{kind}:{path}"))
    }

    /// Keep the provider on the bounded diff/revision/verification surface for a live candidate or
    /// its single exact-reread net-zero recovery. Historical writes alone do not keep it open.
    pub(super) const fn candidate_review_active(&self) -> bool {
        matches!(self.state, GraphState::Review | GraphState::NetZeroRecovery)
    }

    pub(super) const fn candidate_handoff_terminal(&self) -> bool {
        matches!(self.state, GraphState::Handoff)
    }

    /// Every first non-empty candidate gets one bounded post-candidate stable-key audit before any
    /// revision or handoff. Pre-edit evidence cannot validate identifiers introduced by the diff.
    pub(super) const fn candidate_owner_evidence_required(&self) -> bool {
        matches!(self.state, GraphState::Review) && self.candidate_owner_evidence_required
    }

    /// A converged net-zero candidate is terminal evidence-insufficient, not permission to reopen
    /// discovery. The next provider request has no tool surface and can only explain the boundary.
    pub(super) const fn evidence_insufficient_terminal(&self) -> bool {
        matches!(self.state, GraphState::EvidenceInsufficient)
    }

    /// When non-empty, candidate mutation is confined to paths carried by the typed repair receipt
    /// that selected the hypothesis. The default direct path intentionally leaves this empty and
    /// relies on the registry's workspace confinement.
    pub(super) fn authorized_repair_paths(&self) -> &[PathBuf] {
        &self.authorized_repair_paths
    }

    pub(super) fn mutation_failure_signature(tool: &str, diagnostic: &str) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(tool.as_bytes());
        for word in diagnostic.split_whitespace().take(64) {
            digest.update([0]);
            if word.bytes().any(|byte| byte.is_ascii_digit()) {
                digest.update(b"#");
            } else {
                digest.update(word.to_ascii_lowercase().as_bytes());
            }
        }
        digest.finalize().into()
    }

    /// Stable identifiers are deliberately language-neutral and bounded. The native grep tool
    /// supplies all-occurrence retrieval plus enclosing-block expansion; this predicate only
    /// decides whether the provider actually asked for that high-signal operation.
    pub(super) fn is_stable_key(pattern: &str) -> bool {
        let pattern = pattern.trim();
        if !(6..=256).contains(&pattern.len())
            || pattern.bytes().any(|byte| byte.is_ascii_whitespace())
            || !pattern.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'_' | b'$' | b'-' | b'.' | b'/' | b':' | b'#')
            })
        {
            return false;
        }
        let has_qualifier = pattern
            .bytes()
            .any(|byte| matches!(byte, b'_' | b'$' | b'-' | b'.' | b'/' | b':' | b'#'));
        let has_case_or_digit_signal = pattern.bytes().any(|byte| byte.is_ascii_uppercase())
            || pattern.bytes().any(|byte| byte.is_ascii_digit());
        // A single short lowercase word is usually a field category (`type`, `name`, `status`,
        // `pattern`), not an identity. Compound names, case/digit-qualified symbols, and long
        // exact values retain enough information to drive an all-occurrence owner search without
        // embedding a language, framework, or business dictionary in the controller.
        has_qualifier || has_case_or_digit_signal || pattern.len() >= 12
    }

    pub(super) fn stable_key_search_supports_owner(
        pattern: &str,
        evidence: Option<iteron_tools::WorkspaceEvidence>,
    ) -> bool {
        if !Self::is_stable_key(pattern) {
            return false;
        }
        matches!(
            evidence,
            Some(iteron_tools::WorkspaceEvidence::Insufficient(
                iteron_tools::WorkspaceEvidenceInsufficiencyReason::CausalContrastUnproven
                    | iteron_tools::WorkspaceEvidenceInsufficiencyReason::SingleContext
                    | iteron_tools::WorkspaceEvidenceInsufficiencyReason::SourceAnchorsRequired
                    | iteron_tools::WorkspaceEvidenceInsufficiencyReason::UndifferentiatedContexts
                    | iteron_tools::WorkspaceEvidenceInsufficiencyReason::SingleFileOnly
            ))
        )
    }

    /// Reconcile one tool round against exact candidate bytes. A changed fingerprint is progress;
    /// the same fingerprint without new evidence is ready for handoff, not another speculative
    /// edit. A net-zero mutation gets one exact-reread recovery opportunity and never creates an
    /// obligation to mutate.
    pub(super) fn observe_candidate_round(
        &mut self,
        diff: CandidateDiffState,
        attempted_mutation: bool,
        mutation_failure: Option<[u8; 32]>,
        exact_read: bool,
        stable_key_search: bool,
    ) -> Option<ConvergenceRequest> {
        if matches!(
            self.state,
            GraphState::Done | GraphState::Handoff | GraphState::EvidenceInsufficient
        ) {
            return None;
        }
        let repeated_failure =
            mutation_failure.is_some() && mutation_failure == self.last_mutation_failure;
        if attempted_mutation {
            self.last_mutation_failure = mutation_failure;
            self.localized_closure_active = false;
        }
        if stable_key_search {
            self.candidate_owner_evidence_required = false;
        }

        if self.structural_repair_read_required
            && matches!(diff, CandidateDiffState::Changed(_))
            && !attempted_mutation
        {
            if exact_read {
                self.structural_repair_read_required = false;
                self.state = GraphState::Mutate;
                return Some(self.request(
                    structural_regression_repair_instruction(),
                    ConvergenceStage::Mutate,
                ));
            }
            self.state = GraphState::Review;
            return Some(self.request(
                structural_regression_refresh_instruction(),
                ConvergenceStage::Review,
            ));
        }

        if self.behavior_counterexample_read_required
            && matches!(diff, CandidateDiffState::Changed(_))
            && !attempted_mutation
        {
            if exact_read {
                self.behavior_counterexample_read_required = false;
                self.state = GraphState::Mutate;
                return Some(self.request(
                    verification_revision_instruction(),
                    ConvergenceStage::Mutate,
                ));
            }
            self.state = GraphState::Review;
            return Some(self.request(
                behavior_counterexample_refresh_instruction(),
                ConvergenceStage::Review,
            ));
        }

        match diff {
            CandidateDiffState::Unavailable => None,
            CandidateDiffState::Changed(fingerprint) => {
                self.net_zero_reread_available = false;
                if self.last_candidate_diff.is_some()
                    && self.candidate_owner_evidence_required
                    && !stable_key_search
                {
                    self.state = GraphState::Review;
                    return Some(self.request(
                        candidate_owner_evidence_instruction(),
                        ConvergenceStage::Review,
                    ));
                }
                if self.last_candidate_diff == Some(fingerprint)
                    && stable_key_search
                    && self.post_candidate_evidence_available
                {
                    if exact_read {
                        self.post_candidate_evidence_available = false;
                    }
                    self.state = GraphState::Review;
                    return Some(self.request(
                        if exact_read {
                            candidate_owner_block_ready_instruction()
                        } else {
                            candidate_owner_evidence_ready_instruction()
                        },
                        ConvergenceStage::Review,
                    ));
                }
                if self.last_candidate_diff == Some(fingerprint)
                    && exact_read
                    && self.post_candidate_evidence_available
                    && !attempted_mutation
                {
                    self.post_candidate_evidence_available = false;
                    self.state = GraphState::Review;
                    return Some(self.request(
                        candidate_owner_block_ready_instruction(),
                        ConvergenceStage::Review,
                    ));
                }
                if self.last_candidate_diff == Some(fingerprint) || repeated_failure {
                    self.state = GraphState::Handoff;
                    return Some(
                        self.request(candidate_handoff_instruction(), ConvergenceStage::Review),
                    );
                }
                let first_candidate = self.last_candidate_diff.is_none();
                if !first_candidate {
                    self.post_candidate_evidence_available = false;
                    self.candidate_owner_evidence_required = false;
                }
                self.last_candidate_diff = Some(fingerprint);
                self.state = GraphState::Review;
                if first_candidate {
                    self.post_candidate_evidence_available = true;
                    self.candidate_owner_evidence_required = true;
                }
                Some(self.request(
                    if self.candidate_owner_evidence_required {
                        candidate_owner_evidence_instruction()
                    } else {
                        candidate_review_instruction()
                    },
                    ConvergenceStage::Review,
                ))
            }
            CandidateDiffState::Empty => {
                self.last_candidate_diff = None;
                if attempted_mutation {
                    if mutation_failure.is_some() {
                        if repeated_failure {
                            return Some(self.withdraw_candidate());
                        }
                        self.net_zero_reread_available = false;
                        return Some(self.request(
                            rejected_mutation_recovery_instruction(),
                            ConvergenceStage::Explain,
                        ));
                    }
                    if matches!(self.state, GraphState::NetZeroRecovery) || repeated_failure {
                        return Some(self.withdraw_candidate());
                    }
                    self.net_zero_reread_available = true;
                    self.state = GraphState::NetZeroRecovery;
                    return Some(
                        self.request(net_zero_recovery_instruction(), ConvergenceStage::Explain),
                    );
                }
                if matches!(self.state, GraphState::NetZeroRecovery) && exact_read {
                    if !self.net_zero_reread_available {
                        return Some(self.withdraw_candidate());
                    }
                    self.net_zero_reread_available = false;
                    return Some(
                        self.request(net_zero_recovery_instruction(), ConvergenceStage::Explain),
                    );
                }
                if matches!(self.state, GraphState::NetZeroRecovery) {
                    return Some(self.withdraw_candidate());
                }
                None
            }
        }
    }

    fn withdraw_candidate(&mut self) -> ConvergenceRequest {
        self.state = GraphState::EvidenceInsufficient;
        self.net_zero_reread_available = false;
        self.candidate_owner_evidence_required = false;
        self.post_candidate_evidence_available = false;
        self.structural_repair_read_required = false;
        self.behavior_counterexample_read_required = false;
        self.authorized_repair_paths.clear();
        self.request(
            candidate_withdrawn_instruction(),
            ConvergenceStage::EvidenceInsufficient,
        )
    }

    /// A focused verifier failure is evidence against the selected repair, not an observation
    /// count deadline. Once the candidate has been rolled back, reopen graph explanation and let
    /// the independent verifier retry policy decide whether another selection is admissible. If
    /// the bytes remain, require a real candidate mutation or revert before review or verification.
    pub(super) fn verification_failed(
        &mut self,
        rolled_back: bool,
        structural_regression: bool,
    ) -> Option<ConvergenceRequest> {
        if matches!(
            self.state,
            GraphState::Done | GraphState::EvidenceInsufficient
        ) {
            return None;
        }
        if rolled_back {
            self.state = GraphState::Explain;
            self.last_candidate_diff = None;
            self.last_mutation_failure = None;
            self.net_zero_reread_available = false;
            self.candidate_owner_evidence_required = false;
            self.post_candidate_evidence_available = false;
            self.structural_repair_read_required = false;
            self.behavior_counterexample_read_required = false;
            self.open_slots = self.open_slots.max(1);
            self.authorized_repair_paths.clear();
            Some(self.request(
                verification_counterexample_instruction(),
                ConvergenceStage::Explain,
            ))
        } else if structural_regression {
            self.state = GraphState::Review;
            self.last_mutation_failure = None;
            self.net_zero_reread_available = false;
            self.candidate_owner_evidence_required = false;
            self.post_candidate_evidence_available = false;
            self.structural_repair_read_required = true;
            self.behavior_counterexample_read_required = false;
            Some(self.request(
                structural_regression_refresh_instruction(),
                ConvergenceStage::Review,
            ))
        } else {
            self.state = GraphState::Review;
            self.last_mutation_failure = None;
            self.net_zero_reread_available = false;
            self.candidate_owner_evidence_required = false;
            self.post_candidate_evidence_available = false;
            self.structural_repair_read_required = false;
            self.behavior_counterexample_read_required = true;
            Some(self.request(
                behavior_counterexample_refresh_instruction(),
                ConvergenceStage::Review,
            ))
        }
    }

    /// Verification is the successful terminal of the graph-governed repair lifecycle.
    pub(super) fn verification_passed(&mut self) {
        self.state = GraphState::Done;
        self.structural_repair_read_required = false;
        self.behavior_counterexample_read_required = false;
        self.failed_verification_candidates.clear();
        self.consecutive_unchanged_failed_completions = 0;
    }

    fn request(&self, instruction: &'static str, stage: ConvergenceStage) -> ConvergenceRequest {
        ConvergenceRequest {
            observations: self.observations,
            instruction,
            stage,
        }
    }

    /// Observe one completed tool round. Discover is the direct repair fast path: reads and
    /// searches do not inject graph instructions, and the first actual mutation enters Review.
    /// A typed receipt is optional before that first candidate; if supplied, it selects exact
    /// paths. Explain is entered only by a graph receipt or a verifier counterexample and requires
    /// a selected receipt before another candidate. Global budgets remain the safety ceiling.
    pub(super) fn observe_round(
        &mut self,
        candidate_change_outstanding: Option<bool>,
        completed_targeted_observation: bool,
        repair_evidence: Option<iteron_tools::RepairEvidenceReceipt>,
        completed_observation: bool,
    ) -> Option<ConvergenceRequest> {
        if let Some(candidate_change_outstanding) = candidate_change_outstanding {
            if candidate_change_outstanding {
                self.state = GraphState::Review;
                return Some(
                    self.request(candidate_review_instruction(), ConvergenceStage::Review),
                );
            }
            return self.observe_candidate_round(
                CandidateDiffState::Empty,
                true,
                None,
                false,
                false,
            );
        }
        if matches!(
            self.state,
            GraphState::Review
                | GraphState::NetZeroRecovery
                | GraphState::Handoff
                | GraphState::Done
                | GraphState::EvidenceInsufficient
        ) || !completed_observation
        {
            return None;
        }

        self.observations = self.observations.saturating_add(1);
        if let Some(repair_evidence) = repair_evidence {
            let iteron_tools::RepairEvidenceReceipt {
                digest,
                open_slots,
                mut repair_paths,
                selected_hypothesis,
                progress,
            } = repair_evidence;
            let same_digest = self.last_receipt_digest.as_deref() == Some(digest.as_str());
            self.last_receipt_digest = Some(digest);
            self.open_slots = open_slots;

            let selected = selected_hypothesis
                .as_deref()
                .is_some_and(|hypothesis| !hypothesis.trim().is_empty());
            repair_paths.sort();
            repair_paths.dedup();
            if selected && !repair_paths.is_empty() {
                self.authorized_repair_paths = repair_paths;
                self.state = GraphState::Mutate;
                return Some(
                    self.request(candidate_change_instruction(), ConvergenceStage::Mutate),
                );
            }

            self.authorized_repair_paths.clear();
            if open_slots == 0 {
                self.state = GraphState::EvidenceInsufficient;
                return Some(self.request(
                    graph_exhausted_instruction(),
                    ConvergenceStage::EvidenceInsufficient,
                ));
            }
            self.state = GraphState::Explain;
            let no_progress = same_digest || !progress;
            return Some(if no_progress {
                self.request(graph_no_progress_instruction(), ConvergenceStage::Explain)
            } else {
                self.request(graph_progress_instruction(), ConvergenceStage::Explain)
            });
        }

        if matches!(self.state, GraphState::Mutate) {
            return Some(self.request(candidate_change_instruction(), ConvergenceStage::Mutate));
        }

        if matches!(self.state, GraphState::Discover) {
            return None;
        }

        if completed_targeted_observation {
            return Some(self.request(graph_progress_instruction(), ConvergenceStage::Explain));
        }

        if matches!(self.state, GraphState::Explain) {
            return Some(self.request(graph_no_progress_instruction(), ConvergenceStage::Explain));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt(
        digest: &str,
        open_slots: u32,
        repair_paths: &[&str],
        selected_hypothesis: Option<&str>,
        progress: bool,
    ) -> iteron_tools::RepairEvidenceReceipt {
        iteron_tools::RepairEvidenceReceipt {
            digest: digest.to_owned(),
            open_slots,
            repair_paths: repair_paths.iter().map(PathBuf::from).collect(),
            selected_hypothesis: selected_hypothesis.map(str::to_owned),
            progress,
        }
    }

    #[test]
    fn default_observations_keep_the_direct_candidate_path_open_without_graph_prompts() {
        let mut policy = InvestigationConvergence::default();

        assert!(!policy.patch_trial_active());
        assert!(policy.candidate_change_allowed());
        assert_eq!(policy.observe_round(None, false, None, true), None);
        assert_eq!(policy.observe_round(None, true, None, true), None);
        assert!(!policy.patch_trial_active());
        assert!(policy.candidate_change_allowed());
        assert!(!policy.candidate_change_required());
        assert!(policy.authorized_repair_paths().is_empty());

        for _ in 0..8 {
            assert_eq!(policy.observe_round(None, true, None, true), None);
            assert!(policy.candidate_change_allowed());
            assert!(!policy.candidate_change_required());
            assert!(!policy.evidence_insufficient_terminal());
        }
    }

    #[test]
    fn graph_open_slots_and_same_digest_no_progress_remain_explain() {
        let mut policy = InvestigationConvergence::default();

        let progress = policy
            .observe_round(
                None,
                false,
                Some(receipt("graph-a", 2, &[], None, true)),
                true,
            )
            .expect("an open graph receipt enters explanation");
        assert_eq!(progress.stage, ConvergenceStage::Explain);
        assert!(progress.instruction.contains("graph remains open"));
        assert!(policy.patch_trial_active());

        for _ in 0..8 {
            let no_progress = policy
                .observe_round(
                    None,
                    true,
                    Some(receipt("graph-a", 2, &[], None, false)),
                    true,
                )
                .expect("no-progress guidance is bounded but non-terminal");
            assert_eq!(no_progress.stage, ConvergenceStage::Explain);
            assert!(no_progress.instruction.contains("did not change"));
            assert!(!policy.candidate_change_required());
            assert!(!policy.evidence_insufficient_terminal());
        }
    }

    #[test]
    fn typed_repair_selection_opens_only_authorized_candidate_paths() {
        let mut policy = InvestigationConvergence::default();

        let selected = policy
            .observe_round(
                None,
                false,
                Some(receipt(
                    "graph-selected",
                    0,
                    &["src/producer.rs", "src/producer.rs", "src/consumer.rs"],
                    Some("producer violates boundary contract"),
                    true,
                )),
                true,
            )
            .expect("a selected typed repair enters mutation");
        assert_eq!(selected.stage, ConvergenceStage::Mutate);
        assert!(policy.candidate_change_required());
        assert!(!policy.patch_trial_active());
        assert_eq!(
            policy.authorized_repair_paths(),
            &[
                PathBuf::from("src/consumer.rs"),
                PathBuf::from("src/producer.rs")
            ]
        );

        let still_mutating = policy
            .observe_round(None, true, None, true)
            .expect("a failed or no-op candidate call cannot reopen discovery");
        assert_eq!(still_mutating.stage, ConvergenceStage::Mutate);
        assert!(policy.candidate_change_required());

        let review = policy
            .observe_round(Some(true), false, None, true)
            .expect("an actual byte mutation enters review");
        assert_eq!(review.stage, ConvergenceStage::Review);
        assert!(policy.candidate_review_active());
    }

    #[test]
    fn incomplete_or_unauthorized_receipts_never_open_edit_or_expire_by_count() {
        let mut policy = InvestigationConvergence::default();

        let no_paths = policy
            .observe_round(
                None,
                false,
                Some(receipt("no-paths", 1, &[], Some("selected"), false)),
                true,
            )
            .expect("selection without paths remains explanation-only");
        assert_eq!(no_paths.stage, ConvergenceStage::Explain);
        assert!(!policy.candidate_change_required());

        for ordinal in 0..16 {
            let digest = format!("missing-selection-{ordinal}");
            let no_selection = policy
                .observe_round(
                    None,
                    true,
                    Some(receipt(&digest, 1, &["src/file.rs"], None, false)),
                    true,
                )
                .expect("paths without a hypothesis remain explanation-only");
            assert_eq!(no_selection.stage, ConvergenceStage::Explain);
            assert!(!policy.candidate_change_required());
            assert!(!policy.evidence_insufficient_terminal());
        }
    }

    #[test]
    fn closed_frontier_without_repair_intent_is_terminal() {
        let mut policy = InvestigationConvergence::default();

        let exhausted = policy
            .observe_round(
                None,
                false,
                Some(receipt("exhausted", 0, &[], None, true)),
                true,
            )
            .expect("a closed frontier without a repair is explicit evidence insufficiency");
        assert_eq!(exhausted.stage, ConvergenceStage::EvidenceInsufficient);
        assert!(
            exhausted
                .instruction
                .contains("no remaining evidence slots")
        );
        assert!(policy.evidence_insufficient_terminal());
        assert!(!policy.patch_trial_active());
        assert!(
            !policy.reopen_immediate_candidate_action(),
            "a typed graph-exhausted terminal must never be reopened by prose"
        );
    }

    #[test]
    fn verifier_counterexample_reopens_but_net_zero_retry_is_bounded() {
        let mut policy = InvestigationConvergence::default();
        policy.observe_round(Some(true), false, None, true);

        let counterexample = policy
            .verification_failed(true, false)
            .expect("a verifier-owned rollback reopens graph explanation");
        assert_eq!(counterexample.stage, ConvergenceStage::Explain);
        assert!(counterexample.instruction.contains("counterexample"));
        assert!(policy.patch_trial_active());
        assert!(!policy.candidate_change_allowed());
        assert!(!policy.evidence_insufficient_terminal());
        assert!(policy.authorized_repair_paths().is_empty());

        policy.observe_round(
            None,
            false,
            Some(receipt(
                "selected-after-counterexample",
                0,
                &["src/file.rs"],
                Some("revised"),
                true,
            )),
            true,
        );
        policy.observe_round(Some(true), false, None, true);
        let net_zero = policy
            .observe_round(Some(false), false, None, true)
            .expect("the first net-zero mutation permits one exact reread");
        assert_eq!(net_zero.stage, ConvergenceStage::Explain);
        assert!(net_zero.instruction.contains("At most one exact reread"));
        assert!(policy.candidate_review_active());

        let reread = policy
            .observe_candidate_round(CandidateDiffState::Empty, false, None, true, false)
            .expect("one exact reread remains available");
        assert_eq!(reread.stage, ConvergenceStage::Explain);
        let stalled = policy
            .observe_candidate_round(CandidateDiffState::Empty, true, None, false, false)
            .expect("another net-zero mutation after the reread is terminal");
        assert_eq!(stalled.stage, ConvergenceStage::EvidenceInsufficient);
        assert!(stalled.instruction.contains("fully reverted"));
        assert!(policy.evidence_insufficient_terminal());
        assert!(!policy.candidate_review_active());
        assert!(policy.authorized_repair_paths().is_empty());
        assert_eq!(policy.observe_round(None, true, None, true), None);
    }

    #[test]
    fn rejected_mutation_is_not_misclassified_as_a_reverted_candidate() {
        let mut policy = InvestigationConvergence::default();
        let failure = InvestigationConvergence::mutation_failure_signature(
            "edit",
            "old and new are identical and would not change target bytes",
        );

        let recovery = policy
            .observe_candidate_round(CandidateDiffState::Empty, true, Some(failure), false, false)
            .expect("a first rejected mutation keeps exact recovery open");
        assert!(
            recovery
                .instruction
                .contains("mutation tool made no workspace change")
        );
        assert!(!policy.candidate_review_active());
        assert!(!policy.evidence_insufficient_terminal());
        assert!(policy.candidate_change_allowed());

        assert_eq!(
            policy.observe_candidate_round(CandidateDiffState::Empty, false, None, false, false,),
            None,
            "a subsequent failed read must not withdraw a candidate that never existed"
        );
        let terminal = policy
            .observe_candidate_round(CandidateDiffState::Empty, true, Some(failure), false, false)
            .expect("repeating the same rejected mutation remains bounded");
        assert_eq!(terminal.stage, ConvergenceStage::EvidenceInsufficient);
        assert!(policy.evidence_insufficient_terminal());
    }

    #[test]
    fn verifier_failure_with_live_candidate_requires_fresh_owner_read_then_revision() {
        let mut policy = InvestigationConvergence::default();
        let candidate = CandidateDiffState::Changed([9; 32]);
        policy.observe_candidate_round(candidate, true, None, false, false);
        policy.observe_candidate_round(candidate, false, None, false, true);
        policy.observe_candidate_round(candidate, false, None, false, false);
        assert!(policy.candidate_handoff_terminal());

        policy.remember_verification_test_failure(candidate);
        let revision = policy
            .verification_failed(false, false)
            .expect("a failing verifier requires a transition from the live candidate");
        assert_eq!(revision.stage, ConvergenceStage::Review);
        assert!(!policy.candidate_change_required());
        assert!(!policy.candidate_revision_required());
        assert!(policy.candidate_review_active());
        assert!(policy.behavior_counterexample_read_required());
        assert!(policy.candidate_change_allowed());
        assert_eq!(policy.last_candidate_diff, Some([9; 32]));

        let still_reading = policy
            .observe_candidate_round(candidate, false, None, false, false)
            .expect("a grep-only or text-only round must not hand off the rejected candidate");
        assert_eq!(still_reading.stage, ConvergenceStage::Review);
        assert!(policy.behavior_counterexample_read_required());
        assert!(!policy.candidate_handoff_terminal());

        let refreshed = policy
            .observe_candidate_round(candidate, false, None, true, false)
            .expect("one exact owner read reopens surgical candidate revision");
        assert_eq!(refreshed.stage, ConvergenceStage::Mutate);
        assert!(!policy.behavior_counterexample_read_required());
        assert!(policy.candidate_change_required());
        assert!(policy.candidate_revision_required());

        policy.verification_passed();
        assert!(!policy.patch_trial_active());
        assert!(!policy.candidate_change_required());
        assert!(!policy.candidate_revision_required());
        assert!(!policy.candidate_review_active());
        assert!(!policy.candidate_change_allowed());
        assert!(policy.failed_verification_candidates.is_empty());
        assert_eq!(policy.observe_round(None, true, None, true), None);
    }

    #[test]
    fn structural_regression_gets_one_fresh_read_before_surgical_mutation() {
        let mut policy = InvestigationConvergence::default();
        let behavior_candidate = CandidateDiffState::Changed([8; 32]);
        let broken_candidate = CandidateDiffState::Changed([9; 32]);
        policy.observe_candidate_round(behavior_candidate, true, None, false, false);
        policy.remember_verification_test_failure(behavior_candidate);
        policy.observe_candidate_round(broken_candidate, true, None, false, false);
        policy.remember_verification_test_failure(broken_candidate);

        let refresh = policy
            .verification_failed(false, true)
            .expect("a parser regression gets one current-hunk refresh");
        assert_eq!(refresh.stage, ConvergenceStage::Review);
        assert!(
            refresh
                .instruction
                .contains("Read the currently changed target once")
        );
        assert!(policy.structural_repair_read_required());
        assert!(!policy.candidate_change_required());

        let repair = policy
            .observe_candidate_round(broken_candidate, false, None, true, false)
            .expect("the exact refresh opens one surgical mutation");
        assert_eq!(repair.stage, ConvergenceStage::Mutate);
        assert!(repair.instruction.contains("restores structural integrity"));
        assert!(!policy.structural_repair_read_required());
        assert!(policy.candidate_change_required());
        assert!(policy.candidate_revision_required());
    }

    #[test]
    fn verification_candidate_guard_blocks_identical_changed_or_empty_state() {
        for candidate in [
            CandidateDiffState::Changed([7; 32]),
            CandidateDiffState::Empty,
        ] {
            let mut policy = InvestigationConvergence::default();
            let mut verifier_invocations = 0;

            if policy.guard_verification_candidate(candidate) == VerificationCandidateGuard::Verify
            {
                verifier_invocations += 1;
                policy.remember_verification_test_failure(candidate);
            }
            assert!(matches!(
                policy.guard_verification_candidate(candidate),
                VerificationCandidateGuard::RequireTransition(instruction)
                    if instruction.contains("real candidate transition")
            ));
            assert!(policy.candidate_change_required());
            assert!(!policy.candidate_review_active());
            assert!(matches!(
                policy.guard_verification_candidate(candidate),
                VerificationCandidateGuard::Stop(instruction)
                    if instruction.contains("stopping this bounded repair loop")
            ));
            assert_eq!(verifier_invocations, 1);
            assert!(policy.evidence_insufficient_terminal());
        }
    }

    #[test]
    fn verification_candidate_guard_blocks_rejected_candidate_cycle() {
        let mut policy = InvestigationConvergence::default();
        let first = CandidateDiffState::Changed([3; 32]);
        let second = CandidateDiffState::Changed([4; 32]);
        policy.remember_verification_test_failure(first);

        assert_eq!(
            policy.guard_verification_candidate(second),
            VerificationCandidateGuard::Verify
        );
        policy.remember_verification_test_failure(second);

        assert!(matches!(
            policy.guard_verification_candidate(first),
            VerificationCandidateGuard::RequireTransition(instruction)
                if instruction.contains("real candidate transition")
        ));
        assert!(policy.candidate_change_required());
    }

    #[test]
    fn verification_candidate_guard_leaves_fresh_candidate_and_pass_path_untouched() {
        let mut policy = InvestigationConvergence::default();
        let candidate = CandidateDiffState::Changed([5; 32]);

        assert_eq!(
            policy.guard_verification_candidate(candidate),
            VerificationCandidateGuard::Verify
        );
        policy.remember_verification_test_failure(CandidateDiffState::Changed([4; 32]));
        assert_eq!(
            policy.guard_verification_candidate(candidate),
            VerificationCandidateGuard::Verify
        );
        policy.verification_passed();
        assert!(policy.failed_verification_candidates.is_empty());
        assert!(!policy.candidate_change_allowed());
    }

    #[test]
    fn verification_candidate_guard_fails_open_when_state_is_unavailable() {
        let mut policy = InvestigationConvergence::default();
        policy.remember_verification_test_failure(CandidateDiffState::Changed([6; 32]));

        assert_eq!(
            policy.guard_verification_candidate(CandidateDiffState::Unavailable),
            VerificationCandidateGuard::Verify
        );
        policy.remember_verification_test_failure(CandidateDiffState::Unavailable);
        assert_eq!(
            policy.guard_verification_candidate(CandidateDiffState::Unavailable),
            VerificationCandidateGuard::Verify
        );
        assert_eq!(
            policy.guard_verification_candidate(CandidateDiffState::Changed([6; 32])),
            VerificationCandidateGuard::Verify,
            "an unavailable failure must not retain an older equality claim"
        );
    }

    #[tokio::test]
    async fn candidate_identity_tracks_current_bytes_not_historical_mutation() {
        let root = std::env::temp_dir().join(format!(
            "iteron-candidate-baseline-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("candidate.txt");
        let unrelated = root.join("preexisting-dirty.txt");
        std::fs::write(&target, "original\n").unwrap();
        std::fs::write(&unrelated, "operator bytes\n").unwrap();

        let mut baseline = CandidateWorkspaceBaseline::default();
        baseline.capture_before([target.as_path()]).await;
        std::fs::write(&target, "candidate\n").unwrap();
        let CandidateDiffState::Changed(candidate_fingerprint) = baseline.diff_state().await else {
            panic!("candidate bytes must produce a diff fingerprint");
        };

        // Unrelated dirty bytes are outside the typed candidate path population and cannot keep a
        // reverted candidate artificially alive.
        std::fs::write(&unrelated, "operator bytes changed\n").unwrap();
        assert_eq!(
            baseline.diff_state().await,
            CandidateDiffState::Changed(candidate_fingerprint),
            "unrelated workspace changes cannot perturb the normalized candidate fingerprint"
        );
        std::fs::write(&target, "original\n").unwrap();
        assert_eq!(baseline.diff_state().await, CandidateDiffState::Empty);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn repeated_localization_scopes_close_broad_search_then_observation() {
        let mut policy = InvestigationConvergence::default();

        let broad_scopes = [
            InvestigationConvergence::localization_scope(
                "grep",
                &serde_json::json!({"pattern":"FirstOwner"}),
            ),
            InvestigationConvergence::localization_scope(
                "glob",
                &serde_json::json!({"pattern":"**/*.rs"}),
            ),
            InvestigationConvergence::localization_scope("list_dir", &serde_json::json!({})),
        ];
        assert!(
            broad_scopes
                .iter()
                .all(|scope| scope.as_deref() == Some("workspace:.")),
            "pathless workspace discovery must share one broad root scope"
        );

        assert_eq!(
            policy.observe_localization_scopes([broad_scopes[0].clone().unwrap()]),
            None
        );
        assert_eq!(
            policy.observe_localization_scopes([broad_scopes[1].clone().unwrap()]),
            None
        );
        let plateau = policy
            .observe_localization_scopes([broad_scopes[2].clone().unwrap()])
            .expect("three same-root broad batches close broad localization");
        assert_eq!(plateau.stage, ConvergenceStage::Explain);
        assert!(plateau.instruction.contains("Broad discovery is closed"));
        assert!(policy.localization_plateau_active());
        assert!(!policy.candidate_change_required());

        let exact_read = InvestigationConvergence::localization_scope(
            "read_file",
            &serde_json::json!({"path":"./src/owner.rs"}),
        )
        .unwrap();
        assert_eq!(exact_read, "read_file:src/owner.rs@0");
        let decision = policy
            .observe_localization_scopes([exact_read.clone()])
            .expect("the first exact owner read must prompt an edit-or-stop decision");
        assert_eq!(decision.stage, ConvergenceStage::Explain);
        assert!(decision.instruction.contains("concrete mismatch"));
        assert!(policy.localization_plateau_active());
        assert!(policy.candidate_change_allowed());
        let exhausted = policy
            .observe_localization_scopes([exact_read])
            .expect("re-reading the same exact region closes observation");
        assert_eq!(exhausted.stage, ConvergenceStage::Mutate);
        assert!(
            exhausted
                .instruction
                .contains("observation tools are now closed")
        );
        assert!(!policy.localization_plateau_active());
        assert!(policy.candidate_change_required());
        assert!(policy.candidate_change_allowed());
        assert!(!policy.evidence_insufficient_terminal());
        assert!(policy.reopen_immediate_candidate_action());
        assert!(policy.candidate_change_required());
        assert!(!policy.evidence_insufficient_terminal());
    }

    #[test]
    fn distinct_exact_read_offsets_are_distinct_localization_evidence() {
        let first = InvestigationConvergence::localization_scope(
            "read_file",
            &serde_json::json!({"path":"src/owner.rs", "offset":400, "limit":80}),
        );
        let second = InvestigationConvergence::localization_scope(
            "read_file",
            &serde_json::json!({"path":"src/owner.rs", "offset":480, "limit":80}),
        );
        let same_start_shorter = InvestigationConvergence::localization_scope(
            "read_file",
            &serde_json::json!({"path":"src/owner.rs", "offset":400, "limit":20}),
        );
        assert_eq!(first.as_deref(), Some("read_file:src/owner.rs@400"));
        assert_eq!(second.as_deref(), Some("read_file:src/owner.rs@480"));
        assert_eq!(same_start_shorter, first);
    }

    #[test]
    fn initial_plateau_closes_after_two_clean_distinct_file_reads() {
        let mut policy = InvestigationConvergence {
            initial_localization_plateau: true,
            localization_plateau: true,
            ..InvestigationConvergence::default()
        };
        let first = policy.observe_localization_scopes_for_round(
            ["read_file:src/producer.rs@0".to_owned()],
            true,
        );
        assert!(first.is_some());
        assert!(!policy.localized_closure_active());

        let closure = policy
            .observe_localization_scopes_for_round(["read_file:src/consumer.rs@0".to_owned()], true)
            .expect("two clean distinct files activate localized closure");
        assert!(
            closure
                .instruction
                .contains("Two distinct exact source owners")
        );
        assert!(policy.localized_closure_active());
        assert!(!policy.candidate_change_required());

        let decision = policy
            .observe_localization_scopes_for_round(
                ["read_file:src/dependency.rs@40".to_owned()],
                true,
            )
            .expect("one exact expansion closes observation");
        assert_eq!(decision.stage, ConvergenceStage::Mutate);
        assert!(policy.candidate_change_required());
        assert!(!policy.localized_closure_active());
    }

    #[test]
    fn same_file_offsets_or_error_batches_do_not_activate_initial_closure() {
        let mut policy = InvestigationConvergence {
            initial_localization_plateau: true,
            localization_plateau: true,
            ..InvestigationConvergence::default()
        };
        policy.observe_localization_scopes_for_round(["read_file:src/owner.rs@0".to_owned()], true);
        policy
            .observe_localization_scopes_for_round(["read_file:src/owner.rs@200".to_owned()], true);
        assert!(!policy.localized_closure_active());

        policy
            .observe_localization_scopes_for_round(["read_file:src/other.rs@0".to_owned()], false);
        assert!(!policy.localized_closure_active());
    }

    #[test]
    fn exact_focus_after_repeated_broad_scope_closes_only_broad_discovery() {
        let mut policy = InvestigationConvergence::default();

        assert_eq!(
            policy.observe_localization_scopes(["workspace:.".to_owned()]),
            None
        );
        assert_eq!(
            policy.observe_localization_scopes(["workspace:.".to_owned()]),
            None,
            "one repeated broad scope records diminishing return without a turn deadline"
        );
        let focused = policy
            .observe_localization_scopes(["read_file:src/owner.rs".to_owned()])
            .expect("consuming an exact result must not reopen broad discovery");
        assert_eq!(focused.stage, ConvergenceStage::Explain);
        assert!(focused.instruction.contains("Broad discovery is closed"));
        assert!(policy.localization_plateau_active());
        assert!(policy.candidate_change_allowed());
        assert!(!policy.evidence_insufficient_terminal());
    }

    #[test]
    fn stable_diff_or_repeated_mutation_failure_hands_off() {
        let mut policy = InvestigationConvergence::default();
        policy.observe_candidate_round(
            CandidateDiffState::Changed([7; 32]),
            true,
            None,
            false,
            false,
        );
        policy.observe_candidate_round(
            CandidateDiffState::Changed([7; 32]),
            false,
            None,
            false,
            true,
        );
        policy.observe_candidate_round(
            CandidateDiffState::Changed([7; 32]),
            false,
            None,
            false,
            false,
        );
        assert!(policy.candidate_handoff_terminal());

        let first = InvestigationConvergence::mutation_failure_signature(
            "edit",
            "anchor not found near line 41 after 2 attempts",
        );
        let second = InvestigationConvergence::mutation_failure_signature(
            "edit",
            "anchor not found near line 917 after 8 attempts",
        );
        assert_eq!(first, second);

        let mut policy = InvestigationConvergence::default();
        policy.observe_candidate_round(
            CandidateDiffState::Changed([1; 32]),
            true,
            Some(first),
            false,
            false,
        );
        policy.observe_candidate_round(
            CandidateDiffState::Changed([1; 32]),
            false,
            None,
            false,
            true,
        );
        let gated = policy
            .observe_candidate_round(
                CandidateDiffState::Changed([2; 32]),
                true,
                Some(second),
                false,
                false,
            )
            .expect("a reformulated mutation with the same failure class converges");
        assert_eq!(gated.stage, ConvergenceStage::Review);
        assert!(policy.candidate_handoff_terminal());
    }

    #[test]
    fn one_stable_key_round_unlocks_one_candidate_revision() {
        assert!(InvestigationConvergence::is_stable_key(
            "Registry.Owner:type"
        ));
        for generic in [
            "owner field",
            "type",
            "name",
            "status",
            "pattern",
            "subtype",
            "entity",
        ] {
            assert!(
                !InvestigationConvergence::is_stable_key(generic),
                "{generic} is a category, not a stable identity"
            );
        }
        assert!(InvestigationConvergence::stable_key_search_supports_owner(
            "Registry.Owner:type",
            Some(iteron_tools::WorkspaceEvidence::Insufficient(
                iteron_tools::WorkspaceEvidenceInsufficiencyReason::SingleContext,
            )),
        ));
        for weak_result in [
            iteron_tools::WorkspaceEvidenceInsufficiencyReason::NoMatch,
            iteron_tools::WorkspaceEvidenceInsufficiencyReason::NoFocusedContext,
            iteron_tools::WorkspaceEvidenceInsufficiencyReason::CoverageIncomplete,
        ] {
            assert!(
                !InvestigationConvergence::stable_key_search_supports_owner(
                    "Registry.Owner:type",
                    Some(iteron_tools::WorkspaceEvidence::Insufficient(weak_result)),
                ),
                "{weak_result:?} must not unlock candidate revision"
            );
        }

        let mut policy = InvestigationConvergence::default();
        let selected = policy
            .observe_candidate_round(
                CandidateDiffState::Changed([3; 32]),
                true,
                None,
                false,
                false,
            )
            .expect("the first candidate requests missing owner evidence");
        assert!(selected.instruction.contains("reference audit required"));
        assert!(policy.candidate_owner_evidence_required());

        let evidence = policy
            .observe_candidate_round(
                CandidateDiffState::Changed([3; 32]),
                false,
                None,
                false,
                true,
            )
            .expect("one stable-key search keeps the revision surface open");
        assert!(evidence.instruction.contains("reference audit ready"));
        assert!(!policy.candidate_owner_evidence_required());
        assert!(!policy.candidate_handoff_terminal());

        let owner_block = policy
            .observe_candidate_round(
                CandidateDiffState::Changed([3; 32]),
                false,
                None,
                true,
                false,
            )
            .expect("one exact owner read remains before the bounded revision");
        assert!(owner_block.instruction.contains("owner block ready"));
        assert!(!policy.candidate_handoff_terminal());

        policy.observe_candidate_round(
            CandidateDiffState::Changed([4; 32]),
            true,
            None,
            false,
            false,
        );
        policy.observe_candidate_round(
            CandidateDiffState::Changed([4; 32]),
            false,
            None,
            false,
            false,
        );
        assert!(policy.candidate_handoff_terminal());
    }

    #[test]
    fn first_candidate_always_requires_one_post_candidate_reference_audit() {
        let mut policy = InvestigationConvergence::default();
        assert_eq!(
            policy.observe_localization_scopes(["workspace:src".to_owned()]),
            None,
            "pre-edit localization may already include high-signal stable-key search"
        );

        let review = policy
            .observe_candidate_round(
                CandidateDiffState::Changed([5; 32]),
                true,
                None,
                false,
                false,
            )
            .expect("the first candidate enters a post-candidate audit");
        assert!(review.instruction.contains("reference audit required"));
        assert!(policy.candidate_owner_evidence_required());

        let unaudited_read = policy
            .observe_candidate_round(
                CandidateDiffState::Changed([5; 32]),
                false,
                None,
                true,
                false,
            )
            .expect("an exact read alone cannot substitute for the stable-key audit");
        assert!(
            unaudited_read
                .instruction
                .contains("reference audit required")
        );
        assert!(policy.candidate_owner_evidence_required());
        assert!(!policy.candidate_handoff_terminal());

        let unaudited_diff_review = policy
            .observe_candidate_round(
                CandidateDiffState::Changed([5; 32]),
                false,
                None,
                false,
                false,
            )
            .expect("git-diff review cannot bypass a missing reference audit");
        assert!(
            unaudited_diff_review
                .instruction
                .contains("reference audit required")
        );
        assert!(policy.candidate_owner_evidence_required());
        assert!(!policy.candidate_handoff_terminal());

        let audited = policy
            .observe_candidate_round(
                CandidateDiffState::Changed([5; 32]),
                false,
                None,
                false,
                true,
            )
            .expect("one post-candidate stable-key audit is bounded and sufficient");
        assert!(audited.instruction.contains("reference audit ready"));
        assert!(!policy.candidate_owner_evidence_required());

        let audited_exact_read = policy
            .observe_candidate_round(
                CandidateDiffState::Changed([5; 32]),
                false,
                None,
                true,
                false,
            )
            .expect("one exact owner read is available only after the audit");
        assert!(audited_exact_read.instruction.contains("owner block ready"));

        policy.observe_candidate_round(
            CandidateDiffState::Changed([5; 32]),
            false,
            None,
            false,
            false,
        );
        assert!(policy.candidate_handoff_terminal());
    }
}
