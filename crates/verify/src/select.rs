//! Candidate selection over an oracle ensemble, and the resolve-vs-ceiling gap.
//!
//! When N candidate patches exist, select deterministically (ADR-005 R9: non-judgment steps
//! are code, not model calls): content-addressed dedup, then rank by the oracle ensemble with
//! the strength rule (a weak oracle never vetoes), then majority vote, tie-broken by first
//! appearance. The resolve-vs-ceiling gap = (a correct candidate existed) minus (we selected a
//! correct one) — the field's most actionable, unreported metric.

use sha2::{Digest, Sha256};

/// A candidate solution (e.g. a patch), with the verdicts oracles gave it.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// The candidate's content (a diff / patch text). Used for content-addressed dedup.
    pub content: String,
    /// Verdicts, one per oracle that judged this candidate.
    pub verdicts: Vec<(super::OracleStrength, bool)>,
    /// Ground truth, ONLY known in eval (never at run time). Used to compute the ceiling gap.
    pub is_correct_oracle: Option<bool>,
}

impl Candidate {
    fn digest(&self) -> String {
        hex::encode(Sha256::digest(self.content.as_bytes()))
    }

    /// Is this candidate vetoed? Only a Strong oracle's failing verdict vetoes (R6).
    fn vetoed(&self) -> bool {
        self.verdicts
            .iter()
            .any(|(s, passed)| s.may_veto() && !passed)
    }

    /// A rank score: strong passes weigh most, then medium, then weak (evidence only). Weakest
    /// never contributes to selection.
    fn score(&self) -> i64 {
        self.verdicts
            .iter()
            .map(|(s, passed)| {
                let w: i64 = match s {
                    super::OracleStrength::Strong => 100,
                    super::OracleStrength::Medium => 10,
                    super::OracleStrength::Weak => 1,
                    super::OracleStrength::Weakest => 0, // advisory: never enters selection
                };
                if *passed { w } else { -w }
            })
            .sum()
    }
}

/// The outcome of selecting among candidates.
#[derive(Debug, Clone)]
pub struct Selection {
    /// Index of the chosen candidate in the deduped set, or None if all were vetoed.
    pub chosen: Option<usize>,
    /// Deduped candidates (content-addressed).
    pub deduped: Vec<Candidate>,
    /// resolve-vs-ceiling gap components (eval only, when ground truth is known):
    /// `ceiling` = a correct candidate existed; `resolved` = we selected a correct one.
    pub ceiling: bool,
    pub resolved: bool,
}

/// Select deterministically among candidates.
pub fn select(candidates: Vec<Candidate>) -> Selection {
    // 1. content-addressed dedup, keeping first appearance (tie-break anchor).
    let mut seen = std::collections::HashSet::new();
    let mut deduped: Vec<Candidate> = Vec::new();
    for c in candidates {
        if seen.insert(c.digest()) {
            deduped.push(c);
        }
    }

    // 2. drop vetoed candidates (strong-oracle failures only).
    let live: Vec<usize> = (0..deduped.len())
        .filter(|&i| !deduped[i].vetoed())
        .collect();

    // 3. among the living, pick the highest score; ties break by first appearance (lowest index).
    let chosen = live.iter().copied().max_by(|&a, &b| {
        deduped[a].score().cmp(&deduped[b].score()).then(b.cmp(&a)) // lower index wins the tie -> reverse so max_by keeps it
    });

    // 4. resolve-vs-ceiling (eval only).
    let ceiling = deduped.iter().any(|c| c.is_correct_oracle == Some(true));
    let resolved = chosen
        .map(|i| deduped[i].is_correct_oracle == Some(true))
        .unwrap_or(false);

    Selection {
        chosen,
        deduped,
        ceiling,
        resolved,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OracleStrength::*;

    fn cand(
        content: &str,
        verdicts: Vec<(crate::OracleStrength, bool)>,
        correct: Option<bool>,
    ) -> Candidate {
        Candidate {
            content: content.into(),
            verdicts,
            is_correct_oracle: correct,
        }
    }

    #[test]
    fn a_strong_failing_oracle_vetoes() {
        let sel = select(vec![
            cand("patch-a", vec![(Strong, false)], None), // vetoed
            cand("patch-b", vec![(Strong, true)], None),
        ]);
        assert_eq!(
            sel.chosen,
            Some(1),
            "the vetoed candidate must not be chosen"
        );
    }

    #[test]
    fn a_weak_oracle_never_vetoes_only_ranks() {
        // patch-a fails only a WEAK oracle; it must remain selectable, just lower-ranked.
        let sel = select(vec![
            cand("patch-a", vec![(Weak, false)], None),
            cand("patch-b", vec![(Weak, true)], None),
        ]);
        assert_eq!(sel.chosen, Some(1), "weak passes rank above weak fails");
        // but if patch-a were the only candidate, a weak fail must NOT veto it away:
        let sel2 = select(vec![cand("only", vec![(Weak, false)], None)]);
        assert_eq!(
            sel2.chosen,
            Some(0),
            "a weak oracle failure must never veto the only candidate"
        );
    }

    #[test]
    fn dedup_is_content_addressed() {
        let sel = select(vec![
            cand("same", vec![(Strong, true)], None),
            cand("same", vec![(Strong, true)], None),
        ]);
        assert_eq!(sel.deduped.len(), 1, "identical candidates dedup to one");
    }

    #[test]
    fn resolve_vs_ceiling_gap_is_measured() {
        // A correct patch exists (ceiling=true) but a strong oracle wrongly vetoed it and we
        // chose an incorrect one (resolved=false) -> the gap the metric exists to expose.
        let sel = select(vec![
            cand("correct-but-vetoed", vec![(Strong, false)], Some(true)),
            cand("wrong-but-passes", vec![(Strong, true)], Some(false)),
        ]);
        assert!(sel.ceiling, "a correct candidate existed");
        assert!(
            !sel.resolved,
            "we did not select a correct one -> resolve-vs-ceiling gap"
        );
    }
}
