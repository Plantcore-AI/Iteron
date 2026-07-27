//! Candidate selection over an oracle ensemble, and the resolve-vs-ceiling gap.
//!
//! When N candidate patches exist, select deterministically (ADR-005 R9: non-judgment steps
//! are code, not model calls): content-addressed dedup, then rank by the oracle ensemble with
//! the strength rule (a weak oracle never vetoes), then a strength-dominant lexicographic
//! comparison (net Strong, then net Medium, then net Weak; a stronger tier is never overturned
//! by any amount of weaker evidence), tie-broken by first appearance. The resolve-vs-ceiling
//! gap = (a correct candidate existed)
//! minus (we selected a correct one) — the field's most actionable, unreported metric.

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

    /// The strength-dominant rank key: net signed verdicts per tier, ordered so a stronger
    /// oracle always outranks a weaker one no matter how much weaker evidence accumulates.
    /// Compared lexicographically as `(net Strong, net Medium, net Weak)`, a single Strong pass
    /// can never be overturned by any number of Medium/Weak passes; this honors the design rule
    /// that weaker oracles may rank but never override a stronger tier's signal (a plain
    /// weighted sum would let e.g. eleven Medium passes outweigh one Strong pass). Weakest is
    /// advisory and never enters selection.
    fn strength_key(&self) -> (i64, i64, i64) {
        let (mut strong, mut medium, mut weak) = (0i64, 0i64, 0i64);
        for (s, passed) in &self.verdicts {
            let delta: i64 = if *passed { 1 } else { -1 };
            match s {
                super::OracleStrength::Strong => strong += delta,
                super::OracleStrength::Medium => medium += delta,
                super::OracleStrength::Weak => weak += delta,
                super::OracleStrength::Weakest => {} // advisory: never enters selection
            }
        }
        (strong, medium, weak)
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

    // 3. among the living, pick the strength-dominant maximum; ties break by first appearance
    //    (lowest index). The reversed secondary key makes the lower index compare as greater, so
    //    max_by (which keeps the last maximal element) returns it.
    let chosen = live.iter().copied().max_by(|&a, &b| {
        deduped[a]
            .strength_key()
            .cmp(&deduped[b].strength_key())
            .then(b.cmp(&a))
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

impl Selection {
    /// The resolve-vs-ceiling gap for THIS selection: a correct candidate existed
    /// (`ceiling`) yet we did not select one (`!resolved`) — a solvable task left on the
    /// table. This is the single per-task signal the headline metric aggregates. It is
    /// meaningful only where ground truth (`Candidate::is_correct_oracle`) is known (eval);
    /// at run time both components are false and this is trivially false.
    pub fn resolve_vs_ceiling_gap(&self) -> bool {
        self.ceiling && !self.resolved
    }
}

/// The resolve-vs-ceiling metric aggregated over many selections — the field's most
/// actionable, unreported number (ADR-005). It answers: of the tasks a correct candidate was
/// actually produced for, how often did selection fail to pick a correct one?
///
/// The per-selection `ceiling`/`resolved` booleans already existed but nothing folded or
/// emitted them: every caller re-derived the gap inline and no batch-level headline ever
/// reached a log or eval report. This type is that emittable form — deterministic,
/// order-independent structured counts plus a one-line [`std::fmt::Display`] record a runtime
/// verify-phase log or an eval reducer can surface directly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResolveCeilingMetric {
    /// Selections observed.
    pub total: u64,
    /// Selections where a correct candidate existed (the achievable ceiling).
    pub ceiling: u64,
    /// Selections where we actually selected a correct candidate. Always `<= ceiling`:
    /// selecting a correct candidate implies one existed.
    pub resolved: u64,
    /// Selections where a correct candidate existed but we failed to select one
    /// (`ceiling && !resolved`). Equals `ceiling - resolved`.
    pub gap: u64,
}

impl ResolveCeilingMetric {
    /// Fold a batch of selections into the metric. Deterministic and order-independent.
    pub fn from_selections<'a, I>(selections: I) -> Self
    where
        I: IntoIterator<Item = &'a Selection>,
    {
        let mut metric = Self::default();
        for selection in selections {
            metric.record(selection);
        }
        metric
    }

    /// Fold one more selection into the running metric, so a runtime verify phase can emit an
    /// updated headline incrementally rather than buffering every selection first.
    pub fn record(&mut self, selection: &Selection) {
        self.total += 1;
        if selection.ceiling {
            self.ceiling += 1;
        }
        if selection.resolved {
            self.resolved += 1;
        }
        if selection.resolve_vs_ceiling_gap() {
            self.gap += 1;
        }
    }

    /// Fraction of *solvable* selections (a correct candidate existed) that selection
    /// nonetheless failed to resolve — the actionable headline. `None` when nothing was
    /// solvable, so a zero-ceiling batch never masquerades as a perfect selector (a 0.0 gap).
    pub fn gap_rate(&self) -> Option<f64> {
        (self.ceiling > 0).then(|| self.gap as f64 / self.ceiling as f64)
    }

    /// Fraction of solvable selections we actually resolved (`= 1 - gap_rate`). `None` when
    /// nothing was solvable.
    pub fn resolved_rate(&self) -> Option<f64> {
        (self.ceiling > 0).then(|| self.resolved as f64 / self.ceiling as f64)
    }
}

impl std::fmt::Display for ResolveCeilingMetric {
    /// One emittable line carrying the headline numbers. Percentage is of the *solvable*
    /// denominator (the ceiling), which is the number the gap exists to expose.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.gap_rate() {
            Some(rate) => write!(
                formatter,
                "resolve_vs_ceiling: gap={}/{} ({:.1}% of solvable tasks unselected), resolved={}, total={}",
                self.gap,
                self.ceiling,
                rate * 100.0,
                self.resolved,
                self.total
            ),
            None => write!(
                formatter,
                "resolve_vs_ceiling: gap=0/0 (no solvable task observed), total={}",
                self.total
            ),
        }
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

    #[test]
    fn equal_weighted_scores_choose_the_first_candidate() {
        let sel = select(vec![
            cand("first", vec![(Medium, true), (Weak, false)], None),
            cand("second", vec![(Medium, true), (Weak, false)], None),
        ]);
        assert_eq!(sel.chosen, Some(0), "lowest deduped index wins a tie");
    }

    #[test]
    fn per_selection_gap_is_a_first_class_method() {
        let gapped = select(vec![
            cand("correct-but-vetoed", vec![(Strong, false)], Some(true)),
            cand("wrong-but-passes", vec![(Strong, true)], Some(false)),
        ]);
        assert!(
            gapped.resolve_vs_ceiling_gap(),
            "a solvable task we left unselected is the gap"
        );

        let closed = select(vec![cand(
            "right-and-picked",
            vec![(Strong, true)],
            Some(true),
        )]);
        assert!(!closed.resolve_vs_ceiling_gap(), "resolved -> no gap");

        let unsolvable = select(vec![cand("wrong", vec![(Strong, true)], Some(false))]);
        assert!(
            !unsolvable.resolve_vs_ceiling_gap(),
            "no correct candidate existed -> not a gap"
        );
    }

    #[test]
    fn batch_metric_folds_counts_and_emits_the_headline() {
        let gapped = select(vec![
            cand("correct-but-vetoed", vec![(Strong, false)], Some(true)),
            cand("wrong-but-passes", vec![(Strong, true)], Some(false)),
        ]);
        let resolved = select(vec![cand(
            "right-and-picked",
            vec![(Strong, true)],
            Some(true),
        )]);
        let unsolvable = select(vec![cand("all-wrong", vec![(Weak, true)], Some(false))]);

        let metric = ResolveCeilingMetric::from_selections([&gapped, &resolved, &unsolvable]);
        assert_eq!(metric.total, 3);
        assert_eq!(metric.ceiling, 2);
        assert_eq!(metric.resolved, 1);
        assert_eq!(metric.gap, 1);
        // resolved is always a subset of ceiling, so the gap is exactly their difference.
        assert_eq!(metric.gap, metric.ceiling - metric.resolved);
        assert_eq!(metric.gap_rate(), Some(0.5));
        assert_eq!(metric.resolved_rate(), Some(0.5));
        assert!(metric.to_string().contains("resolve_vs_ceiling"));
        assert!(metric.to_string().contains("1/2"));
    }

    #[test]
    fn zero_ceiling_batch_is_undefined_not_a_perfect_score() {
        let unsolvable = select(vec![cand("wrong", vec![(Strong, true)], Some(false))]);
        let metric = ResolveCeilingMetric::from_selections([&unsolvable]);
        assert_eq!(metric.ceiling, 0);
        assert_eq!(
            metric.gap_rate(),
            None,
            "no solvable task -> undefined, never 0.0"
        );
        assert_eq!(metric.resolved_rate(), None);
        assert!(metric.to_string().contains("no solvable task"));
    }

    #[test]
    fn weakest_advice_never_changes_selection() {
        let baseline = select(vec![
            cand("higher", vec![(Weak, true)], None),
            cand("lower", vec![(Weak, false)], None),
        ]);
        let with_advice = select(vec![
            cand("higher", vec![(Weak, true), (Weakest, false)], None),
            cand("lower", vec![(Weak, false), (Weakest, true)], None),
        ]);
        assert_eq!(baseline.chosen, Some(0));
        assert_eq!(with_advice.chosen, baseline.chosen);
    }
}
