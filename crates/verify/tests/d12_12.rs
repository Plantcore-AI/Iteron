//! D12-12: `select()` must rank strength-dominant, not by a plain weighted sum.
//!
//! `score()`'s contract is "strong passes weigh most, then medium, then weak" (a strength
//! hierarchy), and lib.rs states the design rule that trusting a weaker oracle "silently selects
//! wrong patches — designed out". A plain signed weighted sum (Strong=100, Medium=10, Weak=1)
//! violates both: eleven Medium passes (110) outrank a single Strong pass (100), letting
//! accumulated weaker evidence override the repo's real test suite. These tests pin the
//! strength-dominant (lexicographic) ranking and the first-appearance tie-break the gap flagged
//! as untested.

use core_verify::OracleStrength::{self, Medium, Strong, Weak};
use core_verify::select::{Candidate, select};

fn cand(content: &str, verdicts: Vec<(OracleStrength, bool)>) -> Candidate {
    Candidate {
        content: content.into(),
        verdicts,
        is_correct_oracle: None,
    }
}

#[test]
fn a_single_strong_pass_outranks_any_pile_of_weaker_passes() {
    // One Strong pass vs eleven Medium passes. A weighted sum scores 100 vs 110 and picks the
    // Medium pile (index 1); a strength-dominant key is net Strong 1 vs 0, so the Strong-passed
    // candidate must win. This is the doc/impl mismatch the gap exists to close.
    let strong_validated = cand("strong-validated", vec![(Strong, true)]);
    let medium_pile = cand("medium-only", vec![(Medium, true); 11]);

    let sel = select(vec![strong_validated, medium_pile]);
    assert_eq!(
        sel.chosen,
        Some(0),
        "a Strong oracle's pass must never be overturned by accumulated Medium evidence"
    );
}

#[test]
fn medium_dominates_any_pile_of_weak() {
    // The same principle one tier down: a single Medium pass must beat any number of Weak passes.
    // Weighted sum: 10 vs 50 -> picks the Weak pile; strength-dominant: net Medium 1 vs 0.
    let medium_validated = cand("medium-validated", vec![(Medium, true)]);
    let weak_pile = cand("weak-only", vec![(Weak, true); 50]);

    let sel = select(vec![medium_validated, weak_pile]);
    assert_eq!(
        sel.chosen,
        Some(0),
        "a Medium oracle's pass must dominate any amount of Weak evidence"
    );
}

#[test]
fn weaker_tiers_still_order_candidates_a_stronger_tier_left_tied() {
    // Both candidates carry a Strong pass (net Strong tied) and no Medium; Weak then ranks them.
    // Weaker oracles "may rank, never override" — here they legitimately break a stronger-tier tie.
    let weak_fail = cand("weak-fail", vec![(Strong, true), (Weak, false)]);
    let weak_pass = cand("weak-pass", vec![(Strong, true), (Weak, true)]);

    let sel = select(vec![weak_fail, weak_pass]);
    assert_eq!(
        sel.chosen,
        Some(1),
        "with the stronger tiers tied, Weak evidence ranks the candidates"
    );
}

#[test]
fn exact_strength_ties_break_by_first_appearance() {
    // Identical strength keys must resolve to the lowest deduped index (first appearance),
    // deterministically — the tie-break the gap flagged as untested.
    let first = cand("first", vec![(Strong, true), (Weak, false)]);
    let second = cand("second", vec![(Strong, true), (Weak, false)]);

    let sel = select(vec![first, second]);
    assert_eq!(
        sel.chosen,
        Some(0),
        "an exact strength tie is broken by first appearance (lowest index)"
    );
}
