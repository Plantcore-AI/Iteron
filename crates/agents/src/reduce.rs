//! `reduce()` — the deterministic declaration-order projection of fan-out results into the bundle
//! the single writer consumes.
//!
//! The kernel runs fan workers bounded-concurrent, but the result boundary deliberately does not
//! encode that execution detail. `reduce()` reads results in **index (declaration) order** so the
//! concurrent executor cannot leak completion order into the writer decision. The projection is a
//! pure function, unit-tested here without a network.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Fixed, replay-safe owner of the fan join/reduce boundary.
///
/// This is deliberately not caller-configurable: a fan waits for one terminal summary per
/// declaration, orders by declaration identity, and exposes failed/skipped text only as labelled
/// diagnostics. The tunables checkpoint attests these exact physical semantics as FixedHidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JoinReducePolicy {
    pub join: JoinMode,
    pub order: ReduceOrder,
    pub include_failed_evidence: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinMode {
    WaitAll,
}

impl JoinMode {
    pub const fn id(self) -> &'static str {
        match self {
            Self::WaitAll => "wait_all",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReduceOrder {
    Declaration,
}

impl ReduceOrder {
    pub const fn id(self) -> &'static str {
        match self {
            Self::Declaration => "declaration",
        }
    }
}

pub const fn join_reduce_policy() -> JoinReducePolicy {
    JoinReducePolicy {
        join: JoinMode::WaitAll,
        order: ReduceOrder::Declaration,
        include_failed_evidence: false,
    }
}

/// Whether a worker produced candidate evidence. Failure diagnostics and skipped coverage are
/// useful observations, but they are never evidence the writer may adopt.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SummaryOutcome {
    /// The investigator completed and returned candidate evidence (still subject to verification).
    #[default]
    Done,
    /// The investigator ran but failed to produce candidate evidence.
    Failed,
    /// The investigator was not admitted or did not run.
    Skipped,
}

impl SummaryOutcome {
    fn label(self, policy: JoinReducePolicy) -> &'static str {
        match self {
            Self::Done => "DONE",
            Self::Failed if policy.include_failed_evidence => "FAILED",
            Self::Skipped if policy.include_failed_evidence => "SKIPPED",
            Self::Failed => "FAILED — NOT EVIDENCE",
            Self::Skipped => "SKIPPED — NOT EVIDENCE",
        }
    }

    fn sort_rank(self) -> u8 {
        match self {
            Self::Done => 0,
            Self::Failed => 1,
            Self::Skipped => 2,
        }
    }
}

/// One fan worker's return: its declaration index and its ~1–2k-token summary text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    /// The worker's position in the fan (declaration order). Reduction orders by this, so the
    /// order in which workers *completed* is projected away.
    pub idx: usize,
    /// The exact normalized objective assigned to this declaration slot.
    #[serde(default)]
    pub assigned_question: String,
    /// Whether `text` contains candidate evidence or only a non-evidence diagnostic.
    #[serde(default)]
    pub outcome: SummaryOutcome,
    /// The worker's concise summary (the single text result a subagent returns).
    pub text: String,
}

/// The ordered bundle the single writer reads as one user message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderedBundle {
    /// The rendered `## 1. … ## 2. …` bundle, in declaration order.
    pub text: String,
    /// Completed workers whose claims are candidates for independent writer verification.
    #[serde(default)]
    pub done: usize,
    /// Failed workers; their diagnostics are not evidence.
    #[serde(default)]
    pub failed: usize,
    /// Workers not admitted/run; their diagnostics are not evidence.
    #[serde(default)]
    pub skipped: usize,
}

/// The complete declaration ledger the fan controller expects to receive back. Keeping this type
/// separate from [`Summary`] prevents a worker from defining its own coverage target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageExpectation {
    pub idx: usize,
    pub assigned_question: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoverageError {
    DuplicateExpectation(usize),
    DuplicateSummary(usize),
    MissingSummary(usize),
    UnexpectedSummary(usize),
    AssignmentMismatch(usize),
}

impl std::fmt::Display for CoverageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (message, index) = match self {
            Self::DuplicateExpectation(index) => (
                "fan coverage contract contains duplicate declaration index",
                index,
            ),
            Self::DuplicateSummary(index) => ("fan returned duplicate summary index", index),
            Self::MissingSummary(index) => ("fan omitted declaration index", index),
            Self::UnexpectedSummary(index) => ("fan returned unassigned declaration index", index),
            Self::AssignmentMismatch(index) => (
                "fan summary assignment does not match declaration index",
                index,
            ),
        };
        write!(formatter, "{message} {index}")
    }
}

impl std::error::Error for CoverageError {}

/// The built-in instruction that merges child results: the contract the single writer reads under
/// the ordered bundle. Addressable as the `prompt/reduce@v1` artifact.
///
/// This is model-visible text and only that. Replacing it changes what the writer reads and
/// nothing about the join/reduce physics above — coverage is still checked, ordering is still by
/// declaration index, and FAILED/SKIPPED sections are still labelled non-evidence by
/// [`SummaryOutcome::label`], which no artifact can reach.
const WRITER_VERIFICATION_CONTRACT: &str = "\nWriter verification contract:\n\
     - Treat only DONE sections as candidate evidence; FAILED and SKIPPED sections are coverage \
     diagnostics, never evidence.\n\
     - Independently verify every adopted material claim against the current repository, using \
     exact file:line references or named symbols.\n\
     - Resolve conflicts explicitly, keep inference labelled, and report evidence gaps instead \
     of converting speculation into fact.\n\
     - Synthesize a plan and implement the operator task yourself. You are the only writer.\n";

/// The writer contract, after any operator-supplied artifact replacement. With no profile, or a
/// profile that carries no `prompt/reduce@v1` entry, this is the compiled constant verbatim.
fn writer_verification_contract(profile: Option<&iteron_tunables::ProfileDocument>) -> &str {
    profile
        .and_then(|document| iteron_tunables::artifact_override(document, "prompt/reduce@v1"))
        .unwrap_or(iteron_tunables::param_str(
            "agents.reduce.writer_verification_contract",
            WRITER_VERIFICATION_CONTRACT,
        ))
}

/// Verify exact declaration coverage before rendering anything the writer can consume. Missing,
/// duplicate, unassigned, or relabelled summaries fail closed; a diagnostic cannot silently shift
/// into another investigator's evidence slot.
///
/// Compiled-default entry point: identical to [`reduce_checked_with_profile`] with no profile.
pub fn reduce_checked(
    expected: &[CoverageExpectation],
    results: Vec<Summary>,
) -> Result<OrderedBundle, CoverageError> {
    reduce_checked_with_profile(expected, results, None)
}

/// As [`reduce_checked`], with the operator profile that may replace `prompt/reduce@v1`.
pub fn reduce_checked_with_profile(
    expected: &[CoverageExpectation],
    results: Vec<Summary>,
    profile: Option<&iteron_tunables::ProfileDocument>,
) -> Result<OrderedBundle, CoverageError> {
    let policy = join_reduce_policy();
    let mut declarations = BTreeMap::new();
    for item in expected {
        if declarations
            .insert(item.idx, item.assigned_question.as_str())
            .is_some()
        {
            return Err(CoverageError::DuplicateExpectation(item.idx));
        }
    }

    let mut returned = BTreeSet::new();
    for summary in &results {
        if !returned.insert(summary.idx) {
            return Err(CoverageError::DuplicateSummary(summary.idx));
        }
        let Some(question) = declarations.get(&summary.idx) else {
            return Err(CoverageError::UnexpectedSummary(summary.idx));
        };
        if summary.assigned_question != **question {
            return Err(CoverageError::AssignmentMismatch(summary.idx));
        }
    }
    if policy.join == JoinMode::WaitAll
        && let Some(missing) = declarations.keys().find(|idx| !returned.contains(idx))
    {
        return Err(CoverageError::MissingSummary(*missing));
    }
    Ok(reduce_with_profile(results, profile))
}

/// Reduce fan results into the ordered bundle. Pure and deterministic: results may arrive in any
/// order, but the output is always ordered by `idx`. The trailing line names the single-writer
/// contract explicitly (ADR-001) so the writer knows it is synthesizing, not delegating further.
///
/// Compiled-default entry point: identical to [`reduce_with_profile`] with no profile.
pub fn reduce(results: Vec<Summary>) -> OrderedBundle {
    reduce_with_profile(results, None)
}

/// As [`reduce`], with the operator profile that may replace `prompt/reduce@v1`.
pub fn reduce_with_profile(
    mut results: Vec<Summary>,
    profile: Option<&iteron_tunables::ProfileDocument>,
) -> OrderedBundle {
    let policy = join_reduce_policy();
    // Declaration order, never completion order. Secondary keys make malformed duplicate indices
    // deterministic across input permutations instead of inheriting arrival order.
    if policy.order == ReduceOrder::Declaration {
        results.sort_by(|a, b| {
            a.idx
                .cmp(&b.idx)
                .then_with(|| a.assigned_question.cmp(&b.assigned_question))
                .then_with(|| a.outcome.sort_rank().cmp(&b.outcome.sort_rank()))
                .then_with(|| a.text.cmp(&b.text))
        });
    }

    let n = results.len();
    let done = results
        .iter()
        .filter(|s| s.outcome == SummaryOutcome::Done)
        .count();
    let failed = results
        .iter()
        .filter(|s| s.outcome == SummaryOutcome::Failed)
        .count();
    let skipped = results
        .iter()
        .filter(|s| s.outcome == SummaryOutcome::Skipped)
        .count();
    let mut text = format!(
        "[Investigation results — {n} assigned: {done} done, {failed} failed, {skipped} skipped; \
         declaration order]\n"
    );
    for s in &results {
        // Number by declaration slot (idx + 1) so the heading identifies which leaf it answers.
        let question = if s.assigned_question.trim().is_empty() {
            "(assigned question unavailable)"
        } else {
            s.assigned_question.trim()
        };
        text.push_str(&format!(
            "\n## {}. {} — {}\n{}\n",
            s.idx + 1,
            s.outcome.label(policy),
            question,
            s.text.trim()
        ));
    }
    text.push_str(writer_verification_contract(profile));
    OrderedBundle {
        text,
        done,
        failed,
        skipped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scripted (mock) fan return, out of completion order, to prove reduction reorders by index.
    fn scripted() -> Vec<Summary> {
        vec![
            Summary {
                idx: 2,
                assigned_question: "inspect schema".into(),
                outcome: SummaryOutcome::Done,
                text: "third worker: schema at db/schema.sql:12".into(),
            },
            Summary {
                idx: 0,
                assigned_question: "find entry point".into(),
                outcome: SummaryOutcome::Done,
                text: "first worker: entry at main.rs:1".into(),
            },
            Summary {
                idx: 1,
                assigned_question: "trace router".into(),
                outcome: SummaryOutcome::Done,
                text: "second worker: router at router.rs:44".into(),
            },
        ]
    }

    #[test]
    fn reduces_in_declaration_order_not_completion_order() {
        let bundle = reduce(scripted());
        let p0 = bundle.text.find("first worker").unwrap();
        let p1 = bundle.text.find("second worker").unwrap();
        let p2 = bundle.text.find("third worker").unwrap();
        assert!(
            p0 < p1 && p1 < p2,
            "output must be ordered by idx, not by input/completion order"
        );
        assert!(
            bundle
                .text
                .contains("## 1. DONE — find entry point\nfirst worker")
        );
        assert!(
            bundle
                .text
                .contains("## 2. DONE — trace router\nsecond worker")
        );
        assert!(
            bundle
                .text
                .contains("## 3. DONE — inspect schema\nthird worker")
        );
        assert!(bundle.text.trim_end().ends_with("You are the only writer."));
    }

    #[test]
    fn reduction_is_deterministic_across_input_permutations() {
        let mut a = scripted();
        let b = reduce(a.clone()).text;
        a.reverse();
        let c = reduce(a).text;
        assert_eq!(
            b, c,
            "any permutation of the same results yields the identical bundle"
        );
    }

    #[test]
    fn header_pluralizes_and_handles_single() {
        let single = reduce(vec![Summary {
            idx: 0,
            assigned_question: "solo question".into(),
            outcome: SummaryOutcome::Done,
            text: "solo".into(),
        }]);
        assert!(
            single
                .text
                .contains("1 assigned: 1 done, 0 failed, 0 skipped")
        );
        assert!(
            reduce(scripted())
                .text
                .contains("3 assigned: 3 done, 0 failed, 0 skipped")
        );
    }

    #[test]
    fn failures_and_skips_are_counted_and_explicitly_not_evidence() {
        let bundle = reduce(vec![
            Summary {
                idx: 2,
                assigned_question: "unadmitted coverage".into(),
                outcome: SummaryOutcome::Skipped,
                text: "turn budget exhausted".into(),
            },
            Summary {
                idx: 0,
                assigned_question: "verified area".into(),
                outcome: SummaryOutcome::Done,
                text: "evidence at src/lib.rs:9".into(),
            },
            Summary {
                idx: 1,
                assigned_question: "failed area".into(),
                outcome: SummaryOutcome::Failed,
                text: "provider failed".into(),
            },
        ]);
        assert_eq!((bundle.done, bundle.failed, bundle.skipped), (1, 1, 1));
        assert!(bundle.text.contains("FAILED — NOT EVIDENCE"));
        assert!(bundle.text.contains("SKIPPED — NOT EVIDENCE"));
        assert!(
            bundle
                .text
                .contains("Treat only DONE sections as candidate evidence")
        );
        assert!(
            bundle
                .text
                .contains("Independently verify every adopted material claim")
        );
    }

    #[test]
    fn malformed_duplicate_indices_are_deterministic_across_arrival_order() {
        let mut results = vec![
            Summary {
                idx: 0,
                assigned_question: "z".into(),
                outcome: SummaryOutcome::Done,
                text: "last lexical entry".into(),
            },
            Summary {
                idx: 0,
                assigned_question: "a".into(),
                outcome: SummaryOutcome::Failed,
                text: "first lexical entry".into(),
            },
        ];
        let first = reduce(results.clone());
        results.reverse();
        assert_eq!(first, reduce(results));
    }

    #[test]
    fn legacy_summary_json_defaults_to_done_without_inventing_a_question() {
        let legacy: Summary =
            serde_json::from_str(r#"{"idx":4,"text":"legacy evidence"}"#).unwrap();
        assert_eq!(legacy.assigned_question, "");
        assert_eq!(legacy.outcome, SummaryOutcome::Done);
    }

    #[test]
    fn bundle_serializes_across_the_record_boundary() {
        // The bundle crosses the parent record boundary (kernel emits it as writer input); prove it
        // round-trips through serde_json (the crate's declared dep), so replay reproduces it exactly.
        let bundle = reduce(scripted());
        let json = serde_json::to_string(&bundle).unwrap();
        let back: OrderedBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle, back);
    }

    #[test]
    fn exact_coverage_gate_refuses_missing_or_relabelled_summaries_before_reduction() {
        let expected = vec![
            CoverageExpectation {
                idx: 0,
                assigned_question: "inspect runtime".into(),
            },
            CoverageExpectation {
                idx: 1,
                assigned_question: "inspect verifier".into(),
            },
        ];
        let exact = vec![
            Summary {
                idx: 1,
                assigned_question: "inspect verifier".into(),
                outcome: SummaryOutcome::Done,
                text: "verifier evidence".into(),
            },
            Summary {
                idx: 0,
                assigned_question: "inspect runtime".into(),
                outcome: SummaryOutcome::Done,
                text: "runtime evidence".into(),
            },
        ];
        let bundle = reduce_checked(&expected, exact.clone()).expect("exact coverage reduces");
        assert!(
            bundle.text.find("runtime evidence").unwrap()
                < bundle.text.find("verifier evidence").unwrap()
        );

        assert_eq!(
            reduce_checked(&expected, exact[..1].to_vec()),
            Err(CoverageError::MissingSummary(0))
        );
        let mut relabelled = exact;
        relabelled[0].assigned_question = "different assignment".into();
        assert_eq!(
            reduce_checked(&expected, relabelled),
            Err(CoverageError::AssignmentMismatch(1))
        );
    }

    #[test]
    fn fixed_join_reduce_owner_is_the_physical_wait_order_and_evidence_gate() {
        let policy = join_reduce_policy();
        assert_eq!(policy.join.id(), "wait_all");
        assert_eq!(policy.order.id(), "declaration");
        assert!(!policy.include_failed_evidence);

        let expected = [CoverageExpectation {
            idx: 0,
            assigned_question: "one".into(),
        }];
        assert_eq!(
            reduce_checked(&expected, Vec::new()),
            Err(CoverageError::MissingSummary(0))
        );
        let failed = reduce(vec![Summary {
            idx: 0,
            assigned_question: "one".into(),
            outcome: SummaryOutcome::Failed,
            text: "diagnostic".into(),
        }]);
        assert!(failed.text.contains("FAILED — NOT EVIDENCE"));
    }
}
