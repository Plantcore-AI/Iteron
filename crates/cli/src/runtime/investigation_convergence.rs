//! Evidence-phase convergence policy for tool-driven investigation.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const GRAPH_PROGRESS_INSTRUCTION: &str = "[Iteron graph progress] The repair graph remains open. Continue only with a bounded observation that fills or refutes a named producer, boundary, consumer, invariant, or verifier slot, then submit updated typed repair evidence. Do not repeat equivalent observations for confidence.";
const GRAPH_NO_PROGRESS_INSTRUCTION: &str = "[Iteron graph no-progress] The latest receipt did not change the repair graph. Do not repeat the same evidence digest or equivalent observation. Address a different open slot with exact evidence, or report evidence-insufficient when the bounded frontier is genuinely exhausted; observation count alone never ends the investigation.";
const GRAPH_EXHAUSTED_INSTRUCTION: &str = "[Iteron evidence-insufficient terminal] The typed repair graph has no remaining evidence slots and did not authorize a repair intent. Do not call more tools or guess a patch. Briefly report the unresolved evidence boundary and stop.";
const CANDIDATE_CHANGE_INSTRUCTION: &str = "[Iteron repair selected] Typed repair evidence selected a hypothesis and authorized candidate paths. Change only the authorized path set at the earliest violated producer-boundary-consumer edge, preserve recorded invariants, then inspect the diff and run the narrowest focused verifier. Do not reopen discovery or add speculative compatibility behavior.";
const CANDIDATE_REVIEW_INSTRUCTION: &str = "[Iteron candidate review] An actual candidate mutation exists. Review only the candidate paths, diff, required behavior, preserved invariants, and focused verifier. If the evidence does not support the patch, revert it and conclude evidence-insufficient; otherwise verify and finish without reopening discovery.";
const VERIFICATION_COUNTEREXAMPLE_INSTRUCTION: &str = "[Iteron verifier counterexample] The focused verifier refuted the selected repair. The reverted candidate is not terminal while verifier retry policy permits continuation: return to the typed repair graph, record the counterexample, and fill the newly opened slot before selecting another repair.";
const VERIFICATION_REVISION_INSTRUCTION: &str = "[Iteron verifier counterexample] The focused verifier refuted the current candidate, which remains in the workspace. Review or revert only the authorized paths using the verifier evidence; do not reopen broad discovery. A reverted candidate may return to graph explanation while verifier retry policy permits continuation.";
const CANDIDATE_WITHDRAWN_INSTRUCTION: &str = "[Iteron evidence-insufficient terminal] The current workspace change-set matches its pre-candidate baseline: the candidate has been fully reverted and no outstanding repair remains. Do not call tools, restart discovery, verify the absent candidate, or attempt a replacement edit. Briefly report that the available evidence did not support the candidate and stop.";

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum GraphState {
    #[default]
    Discover,
    Explain,
    Mutate,
    Review,
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

    /// `true` is the conservative answer for an incomplete or transiently unreadable baseline.
    /// `false` is returned only when every candidate path is byte-identical to its pre-change
    /// state, including the missing -> created -> missing case.
    pub(super) async fn outstanding(&self) -> bool {
        if self.incomplete || self.paths.is_empty() {
            return true;
        }
        for (path, baseline) in &self.paths {
            match iteron_tools::workspace_candidate_path_identity(path).await {
                Ok(current) if current == *baseline => {}
                Ok(_) | Err(_) => return true,
            }
        }
        false
    }
}

impl InvestigationConvergence {
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
            GraphState::Discover | GraphState::Mutate | GraphState::Review
        )
    }

    pub(super) const fn candidate_change_required(&self) -> bool {
        matches!(self.state, GraphState::Mutate)
    }

    /// Keep the provider on the bounded diff/revision/verification surface only while the current
    /// workspace still differs from the pre-candidate change-set. Historical writes alone are not
    /// a candidate: a fully reverted patch transitions to the terminal state below.
    pub(super) const fn candidate_review_active(&self) -> bool {
        matches!(self.state, GraphState::Review)
    }

    /// A withdrawn candidate is terminal evidence-insufficient, not permission to reopen
    /// discovery. The next provider request therefore has no tool surface and can only explain the
    /// evidence boundary and stop.
    pub(super) const fn evidence_insufficient_terminal(&self) -> bool {
        matches!(self.state, GraphState::EvidenceInsufficient)
    }

    /// When non-empty, candidate mutation is confined to paths carried by the typed repair receipt
    /// that selected the hypothesis. The default direct path intentionally leaves this empty and
    /// relies on the registry's workspace confinement.
    pub(super) fn authorized_repair_paths(&self) -> &[PathBuf] {
        &self.authorized_repair_paths
    }

    /// A focused verifier failure is evidence against the selected repair, not an observation
    /// count deadline. Once the candidate has been rolled back, reopen graph explanation and let
    /// the independent verifier retry policy decide whether another selection is admissible. If
    /// the bytes remain, keep the bounded review surface so they can be revised or reverted first.
    pub(super) fn verification_failed(&mut self, rolled_back: bool) -> Option<ConvergenceRequest> {
        if matches!(
            self.state,
            GraphState::Done | GraphState::EvidenceInsufficient
        ) {
            return None;
        }
        if rolled_back || !matches!(self.state, GraphState::Mutate | GraphState::Review) {
            self.state = GraphState::Explain;
            self.open_slots = self.open_slots.max(1);
            self.authorized_repair_paths.clear();
            Some(self.request(
                verification_counterexample_instruction(),
                ConvergenceStage::Explain,
            ))
        } else {
            self.state = GraphState::Review;
            Some(self.request(
                verification_revision_instruction(),
                ConvergenceStage::Review,
            ))
        }
    }

    /// Verification is the successful terminal of the graph-governed repair lifecycle.
    pub(super) fn verification_passed(&mut self) {
        self.state = GraphState::Done;
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
            } else {
                self.state = GraphState::EvidenceInsufficient;
                self.authorized_repair_paths.clear();
                return Some(self.request(
                    candidate_withdrawn_instruction(),
                    ConvergenceStage::EvidenceInsufficient,
                ));
            }
        }
        if matches!(
            self.state,
            GraphState::Review | GraphState::Done | GraphState::EvidenceInsufficient
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
    }

    #[test]
    fn rollback_is_terminal_but_verifier_counterexample_can_reopen_explanation() {
        let mut policy = InvestigationConvergence::default();
        policy.observe_round(Some(true), false, None, true);

        let counterexample = policy
            .verification_failed(true)
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
        let withdrawn = policy
            .observe_round(Some(false), false, None, true)
            .expect("an ordinary exact rollback is terminal evidence-insufficient");
        assert_eq!(withdrawn.stage, ConvergenceStage::EvidenceInsufficient);
        assert!(withdrawn.instruction.contains("fully reverted"));
        assert!(policy.evidence_insufficient_terminal());
        assert!(!policy.candidate_review_active());
        assert!(policy.authorized_repair_paths().is_empty());
        assert_eq!(policy.observe_round(None, true, None, true), None);
    }

    #[test]
    fn verifier_failure_with_candidate_keeps_review_and_pass_marks_done() {
        let mut policy = InvestigationConvergence::default();
        policy.observe_round(Some(true), false, None, true);

        let revision = policy
            .verification_failed(false)
            .expect("a failing verifier keeps the live candidate reviewable");
        assert_eq!(revision.stage, ConvergenceStage::Review);
        assert!(policy.candidate_review_active());
        assert!(policy.candidate_change_allowed());

        policy.verification_passed();
        assert!(!policy.patch_trial_active());
        assert!(!policy.candidate_change_required());
        assert!(!policy.candidate_review_active());
        assert!(!policy.candidate_change_allowed());
        assert_eq!(policy.observe_round(None, true, None, true), None);
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
        assert!(baseline.outstanding().await);

        // Unrelated dirty bytes are outside the typed candidate path population and cannot keep a
        // reverted candidate artificially alive.
        std::fs::write(&unrelated, "operator bytes changed\n").unwrap();
        std::fs::write(&target, "original\n").unwrap();
        assert!(!baseline.outstanding().await);
        let _ = std::fs::remove_dir_all(root);
    }
}
