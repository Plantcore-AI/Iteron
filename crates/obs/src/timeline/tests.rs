use super::*;
use iteron_protocol::{EffectId, Event, EventKind, Seq, ToolResult, Trust, TurnId, Usage};

fn event(seq: u64, kind: EventKind) -> Event {
    Event {
        seq: Seq(seq),
        turn: TurnId(1),
        kind,
    }
}

fn effect_done(seq: u64, tool: &str, duration_ms: Option<u64>) -> Event {
    event(
        seq,
        EventKind::EffectDone {
            id: EffectId(format!("effect-{seq}")),
            tool: tool.into(),
            duration_ms,
            provider_route_attempt: None,
        },
    )
}

fn turn_end(seq: u64, ttft_ms: Option<u64>, decode_ms: Option<u64>, items: Option<u32>) -> Event {
    event(
        seq,
        EventKind::TurnEnd {
            usage: Usage::default(),
            ttft_ms,
            decode_ms,
            stream_items: items,
        },
    )
}

/// The reader is a pure function: the same event stream built in memory yields the identical
/// report with no I/O at all. This is the standing `Ledger` restriction applied to the projection,
/// and it is what stops the timeline from quietly becoming a second measurement site.
#[test]
fn the_fold_is_pure_and_repeatable() {
    let events = vec![
        effect_done(0, "provider", Some(1200)),
        effect_done(1, "hook", Some(30)),
    ];
    let entries: Vec<_> = events.iter().map(|e| (Some(e.seq.0 * 1_000), e)).collect();
    let first = fold(entries.iter().copied());
    let second = fold(entries.iter().copied());
    assert_eq!(first, second);
}

/// Percentiles come from the individual observations, never from a sum. A reader that divided a
/// total by a count would report this set as ~30ms and hide the 900ms tail entirely.
#[test]
fn percentiles_are_computed_from_spans_not_from_totals() {
    let samples: Vec<Event> = [1u64, 2, 2, 3, 3, 3, 900]
        .iter()
        .enumerate()
        .map(|(index, ms)| effect_done(index as u64, "provider", Some(*ms)))
        .collect();
    let entries: Vec<_> = samples.iter().map(|e| (Some(e.seq.0 * 10), e)).collect();
    let timeline = fold(entries);

    let provider = &timeline.effects["provider"];
    assert_eq!(provider.count, 7);
    assert_eq!(provider.max_ms, Some(900));
    assert_eq!(provider.p50_ms, Some(3));
    assert_eq!(
        provider.p99_ms,
        Some(900),
        "the tail must survive; it is the only reason to compute a percentile"
    );
}

/// All seven classes land in the breakdown under the label the record itself uses, so a class
/// added later appears without this file being edited.
#[test]
fn every_effect_class_is_broken_out_under_its_own_recorded_label() {
    let classes = [
        "provider",
        "hook",
        "subagent",
        "verify",
        "checkpoint",
        "workflow",
    ];
    let events: Vec<Event> = classes
        .iter()
        .enumerate()
        .map(|(index, class)| effect_done(index as u64, class, Some(10 * (index as u64 + 1))))
        .collect();
    let entries: Vec<_> = events.iter().map(|e| (Some(e.seq.0 * 1_000), e)).collect();
    let timeline = fold(entries);
    for class in classes {
        assert!(
            timeline.effects.contains_key(class),
            "{class} missing from the breakdown"
        );
    }
}

/// An effect with no proven terminal is COUNTED but contributes no sample. Dropping it would
/// silently shorten every percentile; imputing a zero would claim it was instantaneous.
#[test]
fn an_unproven_effect_is_counted_and_never_imputed() {
    let unknown = event(
        1,
        EventKind::EffectUnknown {
            id: EffectId("effect-1".into()),
            tool: "provider".into(),
            reason: "no terminal observed".into(),
            provider_route_attempt: None,
        },
    );
    let done = effect_done(0, "provider", Some(100));
    let entries = vec![(Some(0u64), &done), (Some(1_000u64), &unknown)];
    let timeline = fold(entries);

    let provider = &timeline.effects["provider"];
    assert_eq!(provider.count, 2, "both observations are counted");
    assert_eq!(provider.unmeasured, 1);
    assert_eq!(provider.total_ms, 100, "the unknown contributes nothing");
    assert_eq!(provider.max_ms, Some(100));
}

/// A rollout written before #102 has no offsets, so its wall span is unknown -- and the residual
/// must be unknown with it rather than defaulting to the negative of whatever was attributed.
#[test]
fn a_rollout_without_offsets_reports_unknown_rather_than_zero() {
    let done = effect_done(0, "provider", Some(500));
    let timeline = fold(vec![(None, &done)]);

    assert_eq!(timeline.coverage.lines, 1);
    assert_eq!(timeline.coverage.timed_lines, 0);
    assert_eq!(timeline.coverage.wall_ms, None);
    assert_eq!(timeline.coverage.residual_ms, None);
    assert_eq!(
        timeline.coverage.attributed_ms, 500,
        "what IS provable is still reported"
    );
    assert_eq!(timeline.segments[0].span_ms, None);
}

/// The resume seam. Two writers, so the offset drops; the reader splits and times each segment
/// exactly, and the gap between them never enters `wall_ms`.
#[test]
fn a_resumed_run_splits_into_segments_and_the_join_is_never_timed() {
    let events: Vec<Event> = (0..4)
        .map(|seq| effect_done(seq, "hook", Some(1)))
        .collect();
    // Segment one runs 0..2_000us; segment two restarts at 0 and runs to 5_000us.
    let offsets = [Some(0u64), Some(2_000), Some(0), Some(5_000)];
    let entries: Vec<_> = offsets
        .iter()
        .copied()
        .zip(events.iter())
        .collect::<Vec<_>>();
    let timeline = fold(entries);

    assert_eq!(timeline.segments.len(), 2, "the offset drop is the seam");
    assert_eq!(timeline.segments[0].span_ms, Some(2));
    assert_eq!(timeline.segments[1].span_ms, Some(5));
    assert_eq!(
        timeline.coverage.wall_ms,
        Some(7),
        "wall time is the sum of the segments; the join between them is unknown, not zero"
    );
}

/// One untimed line poisons its whole segment. Reporting the timed subset as the segment span
/// would understate it by exactly the part nobody can see -- the failure mode this design exists
/// to prevent.
#[test]
fn one_untimed_line_makes_its_whole_segment_unknown() {
    let events: Vec<Event> = (0..3)
        .map(|seq| effect_done(seq, "hook", Some(1)))
        .collect();
    let entries = vec![
        (Some(0u64), &events[0]),
        (None, &events[1]),
        (Some(9_000u64), &events[2]),
    ];
    let timeline = fold(entries);
    assert_eq!(timeline.segments.len(), 1);
    assert_eq!(timeline.segments[0].span_ms, None);
    assert_eq!(timeline.coverage.wall_ms, None);
    assert_eq!(timeline.coverage.timed_lines, 2);
    assert_eq!(timeline.coverage.lines, 3);
}

/// The breakdown is NOT a partition, and the report says so with a signed residual. Pure tools
/// overlap decode by design, so attributed work can exceed the wall span it sits inside; a
/// negative residual is the harness working, not an accounting error.
#[test]
fn overlapping_work_reports_a_negative_residual_instead_of_hiding_it() {
    let provider = effect_done(0, "provider", Some(1_000));
    let tool = event(
        1,
        EventKind::ToolDone {
            result: ToolResult {
                tool_use_id: "read_file".into(),
                content: String::new(),
                is_error: false,
                latency_ms: 800,
                trust: Trust::Workspace,
            },
            effect_id: None,
            tool: Some("read_file".into()),
        },
    );
    // One second of wall clock, 1.8s of attributed work: the tool ran during the stream.
    let entries = vec![(Some(0u64), &provider), (Some(1_000_000u64), &tool)];
    let timeline = fold(entries);

    assert_eq!(timeline.coverage.wall_ms, Some(1_000));
    assert_eq!(timeline.coverage.attributed_ms, 1_800);
    assert_eq!(
        timeline.coverage.residual_ms,
        Some(-800),
        "overlap must surface as a negative residual, never be clamped to zero"
    );
}

/// Turn timing rides through, and a turn with no measurement is counted without inventing one.
#[test]
fn turn_timing_separates_measured_turns_from_unmeasured_ones() {
    let measured = turn_end(0, Some(300), Some(1_700), Some(42));
    let unmeasured = turn_end(1, None, None, None);
    let entries = vec![(Some(0u64), &measured), (Some(1_000u64), &unmeasured)];
    let timeline = fold(entries);

    assert_eq!(timeline.turns.count, 2);
    assert_eq!(timeline.turns.ttft.max_ms, Some(300));
    assert_eq!(timeline.turns.decode.max_ms, Some(1_700));
    assert_eq!(timeline.turns.ttft.unmeasured, 1);
    assert_eq!(
        timeline.turns.stream_items, 42,
        "an unmeasured turn contributes no items rather than a fabricated zero-length stream"
    );
}
