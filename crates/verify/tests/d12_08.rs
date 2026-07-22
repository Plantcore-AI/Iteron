//! D12-08 oracle: the resolve-vs-ceiling gap is a first-class, EMITTABLE metric on
//! `verify::select`, not a number each caller re-derives inline. The per-selection boolean and
//! the aggregate headline are computed by, and surfaced from, the verify crate itself.
//!
//! RED before the fix: `Selection::resolve_vs_ceiling_gap` and `ResolveCeilingMetric` do not
//! exist on the base branch, so this file fails to compile there. GREEN after the fix.

use core_verify::select::{select, Candidate, ResolveCeilingMetric};
use core_verify::OracleStrength::{self, Strong, Weak};

fn cand(content: &str, verdicts: Vec<(OracleStrength, bool)>, correct: Option<bool>) -> Candidate {
    Candidate {
        content: content.into(),
        verdicts,
        is_correct_oracle: correct,
    }
}

/// The single most important case the metric exists to expose: a correct patch was produced
/// but a strong oracle vetoed it and we selected a wrong one. The gap is surfaced as a method
/// on the very `Selection` the production selector returns.
#[test]
fn per_selection_gap_is_exposed_by_the_selector() {
    let gapped = select(vec![
        cand("correct-but-vetoed", vec![(Strong, false)], Some(true)),
        cand("wrong-but-passes", vec![(Strong, true)], Some(false)),
    ]);
    assert!(gapped.ceiling, "a correct candidate existed");
    assert!(!gapped.resolved, "we did not select a correct one");
    assert!(
        gapped.resolve_vs_ceiling_gap(),
        "ceiling && !resolved must read as a gap"
    );

    let closed = select(vec![cand("correct-and-picked", vec![(Strong, true)], Some(true))]);
    assert!(
        !closed.resolve_vs_ceiling_gap(),
        "selecting the correct candidate closes the gap"
    );

    let unsolvable = select(vec![cand("all-wrong", vec![(Strong, true)], Some(false))]);
    assert!(
        !unsolvable.resolve_vs_ceiling_gap(),
        "no correct candidate ever existed -> not a gap, not a selector failure"
    );
}

/// The aggregate is the emittable headline: fold many selections, expose the solvable
/// denominator, the gap count, the gap rate, and a one-line record a log/report can print.
#[test]
fn batch_metric_aggregates_and_emits_the_headline() {
    let gapped = select(vec![
        cand("correct-but-vetoed", vec![(Strong, false)], Some(true)),
        cand("wrong-but-passes", vec![(Strong, true)], Some(false)),
    ]);
    let resolved = select(vec![cand("correct-and-picked", vec![(Strong, true)], Some(true))]);
    let unsolvable = select(vec![cand("nothing-correct", vec![(Weak, true)], Some(false))]);

    let metric = ResolveCeilingMetric::from_selections([&gapped, &resolved, &unsolvable]);
    assert_eq!(metric.total, 3, "three selections observed");
    assert_eq!(metric.ceiling, 2, "two tasks had a correct candidate");
    assert_eq!(metric.resolved, 1, "we selected a correct one exactly once");
    assert_eq!(metric.gap, 1, "one solvable task was left unselected");
    // A resolved selection always had a ceiling, so the gap is exactly the difference.
    assert_eq!(metric.gap, metric.ceiling - metric.resolved);

    assert_eq!(
        metric.gap_rate(),
        Some(0.5),
        "half of the solvable tasks were left unselected"
    );
    assert_eq!(metric.resolved_rate(), Some(0.5));

    // The emitted one-line record carries the headline numbers verbatim.
    let line = metric.to_string();
    assert!(
        line.contains("resolve_vs_ceiling"),
        "emitted line names the metric: {line}"
    );
    assert!(
        line.contains("1/2"),
        "emitted line carries gap/ceiling: {line}"
    );
}

/// `record` streams selections one at a time and must land on the same counts as a batch fold,
/// so a runtime verify phase can emit a running headline without buffering.
#[test]
fn streaming_record_matches_a_batch_fold() {
    let a = select(vec![
        cand("correct-but-vetoed", vec![(Strong, false)], Some(true)),
        cand("wrong-but-passes", vec![(Strong, true)], Some(false)),
    ]);
    let b = select(vec![cand("correct-and-picked", vec![(Strong, true)], Some(true))]);

    let mut streamed = ResolveCeilingMetric::default();
    streamed.record(&a);
    streamed.record(&b);

    assert_eq!(streamed, ResolveCeilingMetric::from_selections([&a, &b]));
}

/// A batch with no solvable task must report an undefined rate, never a flattering 0.0 gap.
#[test]
fn zero_ceiling_batch_reports_none_not_a_perfect_score() {
    let unsolvable = select(vec![cand("wrong", vec![(Strong, true)], Some(false))]);
    let metric = ResolveCeilingMetric::from_selections([&unsolvable]);
    assert_eq!(metric.ceiling, 0);
    assert_eq!(metric.gap, 0);
    assert_eq!(
        metric.gap_rate(),
        None,
        "no solvable task -> undefined, must not read as 0% gap"
    );
    assert_eq!(metric.resolved_rate(), None);
    assert!(
        metric.to_string().contains("no solvable task"),
        "the emitted line must not fabricate a perfect score"
    );
}
