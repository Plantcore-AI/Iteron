//! The offline timeline reader (#104): turn a replayed rollout into a waterfall, a per-class
//! breakdown and a distribution, with the gaps reported rather than filled in.
//!
//! # Why this lives in `core-obs` and takes no path
//!
//! [`fold`] is a pure function of an already-replayed event stream. It has no clock, no
//! filesystem, no process and no network — the same standing restriction the [`crate::Ledger`]
//! carries, and for the same reason: a projection that could measure would immediately become a
//! second, disagreeing source of truth beside the record it is supposed to be reading. The caller
//! verifies the hash chain (`core_record::replay_timed`) and hands the result in; if the bytes
//! would not pass the audit path, no timeline is produced from them.
//!
//! # What "honest" means here, concretely
//!
//! Three different things can be unknown, and the report distinguishes all three rather than
//! rendering any of them as zero:
//!
//! 1. **A line has no offset.** Written before #102. The segment containing it cannot be timed.
//! 2. **A join between two segments.** A resumed run restarts its monotonic origin, so the offset
//!    drops. Subtracting across that seam would be subtracting two unrelated clocks.
//! 3. **An effect with no proven terminal.** `EffectUnknown` carries no duration by construction.
//!
//! # Why the breakdown is not a partition
//!
//! Pure tools are dispatched mid-stream and overlap the provider by design (the flagship overlap).
//! So the per-class totals can exceed the wall span they sit inside, and `residual_ms` is reported
//! as an explicit signed remainder rather than silently absorbed. A reader that presented these as
//! slices of a pie would be lying about the concurrency the harness was built to have.

use core_protocol::{Event, EventKind};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One contiguous run of lines written by a single writer.
///
/// A resumed run produces more than one. Offsets are exact WITHIN a segment and meaningless
/// ACROSS segments, which is the whole reason this type exists instead of a single run span.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Segment {
    pub first_seq: u64,
    pub last_seq: u64,
    pub events: u64,
    /// Wall time from the first to the last line of this segment. `None` when any line in it
    /// lacked an offset, because a partial span is not a span.
    pub span_ms: Option<u64>,
}

/// A distribution, not a total. `summary()` reports saturating sums, which cannot answer "is the
/// tail bad" — the question that actually matters when a run feels slow but averages fine.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Distribution {
    pub count: u64,
    pub total_ms: u64,
    pub p50_ms: Option<u64>,
    pub p90_ms: Option<u64>,
    pub p99_ms: Option<u64>,
    pub max_ms: Option<u64>,
    /// Observations that exist but carry no duration — an `EffectUnknown`, or an effect whose
    /// terminal predates #101. Counted, never dropped: a silently shorter sample is how a
    /// percentile starts lying.
    pub unmeasured: u64,
}

impl Distribution {
    fn from_samples(mut samples: Vec<u64>, unmeasured: u64) -> Self {
        samples.sort_unstable();
        let count = samples.len() as u64 + unmeasured;
        Self {
            count,
            total_ms: samples.iter().copied().fold(0u64, u64::saturating_add),
            p50_ms: percentile(&samples, 50),
            p90_ms: percentile(&samples, 90),
            p99_ms: percentile(&samples, 99),
            max_ms: samples.last().copied(),
            unmeasured,
        }
    }
}

/// Nearest-rank, computed from the individual observations rather than from a sum.
fn percentile(sorted: &[u64], p: u64) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = (p.saturating_mul(sorted.len() as u64)).div_ceil(100).max(1);
    sorted.get((rank as usize).min(sorted.len()) - 1).copied()
}

/// What the reader could and could not account for. Printed, never absorbed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    pub lines: u64,
    /// Lines carrying a segment offset. Below `lines` means the rollout predates #102 in part.
    pub timed_lines: u64,
    /// Sum of every segment's span. Time between segments is deliberately NOT included: it is
    /// unknown, not zero.
    pub wall_ms: Option<u64>,
    /// Sum of every measured effect and tool duration. This is a coverage figure, not a share of
    /// `wall_ms`, because overlapping work is counted once per span it belongs to.
    pub attributed_ms: u64,
    /// `wall_ms - attributed_ms`. **Signed on purpose**: it goes negative exactly when the harness
    /// did what it was designed to do and overlapped tool execution with decode. A negative
    /// residual is a health signal, not an error.
    pub residual_ms: Option<i64>,
}

/// The full report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timeline {
    pub segments: Vec<Segment>,
    /// Keyed by the durable effect-class label (`provider`, `hook`, `subagent`, `verify`,
    /// `checkpoint`, `workflow`) exactly as the record spells it, so a new class appears here the
    /// day it is first recorded without this file being edited.
    pub effects: BTreeMap<String, Distribution>,
    /// Registry tool calls, keyed by tool name, measured at the registry (`ToolResult::latency_ms`)
    /// rather than at the effect boundary, because that is the number the record actually holds
    /// for them and two scopes for one call would disagree.
    pub tools: BTreeMap<String, Distribution>,
    pub turns: Turns,
    pub coverage: Coverage,
}

/// Per-turn model timing, from `TurnEnd` (#103).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Turns {
    pub count: u64,
    pub ttft: Distribution,
    pub decode: Distribution,
    /// Total stream items across all measured turns. Kept raw so inter-token time is derived by
    /// whoever needs it rather than pre-averaged here into a number nobody can decompose.
    pub stream_items: u64,
}

/// Fold a replayed, chain-verified stream into the report.
///
/// `entries` is `(segment offset, event)` in record order — exactly what
/// `core_record::replay_timed` yields.
pub fn fold<'a, I>(entries: I) -> Timeline
where
    I: IntoIterator<Item = (Option<u64>, &'a Event)>,
{
    let mut timeline = Timeline::default();
    let mut segment: Option<OpenSegment> = None;
    let mut previous_ts: Option<u64> = None;

    let mut effect_samples: BTreeMap<String, (Vec<u64>, u64)> = BTreeMap::new();
    let mut tool_samples: BTreeMap<String, (Vec<u64>, u64)> = BTreeMap::new();
    let mut ttft: Vec<u64> = Vec::new();
    let mut decode: Vec<u64> = Vec::new();
    let mut unmeasured_turns = 0u64;

    for (ts_us, event) in entries {
        timeline.coverage.lines = timeline.coverage.lines.saturating_add(1);
        if ts_us.is_some() {
            timeline.coverage.timed_lines = timeline.coverage.timed_lines.saturating_add(1);
        }

        // A DROP in the offset is the resume seam: a new writer restarted its monotonic origin.
        // Splitting here is what stops the reader from subtracting two unrelated clocks and
        // reporting a confidently wrong negative duration.
        let starts_segment = match (previous_ts, ts_us) {
            (Some(previous), Some(current)) => current < previous,
            (None, Some(_)) => previous_ts.is_none() && segment.is_none(),
            _ => false,
        };
        let seq = event.seq.0;
        match segment.as_mut() {
            Some(open) if !starts_segment => {
                open.last_seq = seq;
                open.end = ts_us.or(open.end);
                open.events = open.events.saturating_add(1);
                if ts_us.is_none() {
                    // One untimed line poisons the whole segment's span: a partial span is not a
                    // span, and reporting the timed subset as if it were the segment would
                    // understate it by exactly the part nobody can see.
                    open.start = None;
                    open.end = None;
                }
            }
            _ => {
                if let Some(open) = segment.take() {
                    timeline.segments.push(close_segment(open));
                }
                segment = Some(OpenSegment {
                    first_seq: seq,
                    last_seq: seq,
                    start: ts_us,
                    end: ts_us,
                    events: 1,
                });
            }
        }
        previous_ts = ts_us;

        match &event.kind {
            EventKind::EffectDone {
                tool, duration_ms, ..
            } => record_sample(&mut effect_samples, tool, *duration_ms),
            EventKind::EffectFailed {
                tool, duration_ms, ..
            } => record_sample(&mut effect_samples, tool, *duration_ms),
            // No terminal was observed, so there is no duration and never will be. It is counted
            // as an observation so the class's `count` stays truthful.
            EventKind::EffectUnknown { tool, .. } => record_sample(&mut effect_samples, tool, None),
            EventKind::ToolDone { result, .. } => {
                record_sample(
                    &mut tool_samples,
                    &result.tool_use_id,
                    Some(result.latency_ms),
                );
            }
            EventKind::TurnEnd {
                ttft_ms,
                decode_ms,
                stream_items,
                ..
            } => {
                timeline.turns.count = timeline.turns.count.saturating_add(1);
                match (ttft_ms, decode_ms) {
                    (Some(first), Some(rest)) => {
                        ttft.push(*first);
                        decode.push(*rest);
                    }
                    _ => unmeasured_turns = unmeasured_turns.saturating_add(1),
                }
                timeline.turns.stream_items = timeline
                    .turns
                    .stream_items
                    .saturating_add(u64::from(stream_items.unwrap_or(0)));
            }
            _ => {}
        }
    }
    if let Some(open) = segment.take() {
        timeline.segments.push(close_segment(open));
    }

    timeline.effects = effect_samples
        .into_iter()
        .map(|(key, (samples, unmeasured))| (key, Distribution::from_samples(samples, unmeasured)))
        .collect();
    timeline.tools = tool_samples
        .into_iter()
        .map(|(key, (samples, unmeasured))| (key, Distribution::from_samples(samples, unmeasured)))
        .collect();
    timeline.turns.ttft = Distribution::from_samples(ttft, unmeasured_turns);
    timeline.turns.decode = Distribution::from_samples(decode, unmeasured_turns);

    // Wall time is the sum of the segments only. The gap BETWEEN segments is a process that was
    // not running, or was running unobserved; either way it is unknown, and adding it would be
    // inventing the one number this whole design refuses to invent.
    timeline.coverage.wall_ms = timeline.segments.iter().try_fold(0u64, |total, segment| {
        segment.span_ms.map(|span| total.saturating_add(span))
    });
    timeline.coverage.attributed_ms = timeline
        .effects
        .values()
        .chain(timeline.tools.values())
        .fold(0u64, |total, distribution| {
            total.saturating_add(distribution.total_ms)
        });
    timeline.coverage.residual_ms = timeline.coverage.wall_ms.map(|wall| {
        i64::try_from(wall).unwrap_or(i64::MAX)
            - i64::try_from(timeline.coverage.attributed_ms).unwrap_or(i64::MAX)
    });
    timeline
}

/// A segment still being accumulated. Named rather than a tuple because `start`/`end` are both
/// `Option<u64>` and swapping them silently would produce a plausible, wrong span.
struct OpenSegment {
    first_seq: u64,
    last_seq: u64,
    /// `None` the moment any line in this segment lacks an offset.
    start: Option<u64>,
    end: Option<u64>,
    events: u64,
}

fn close_segment(open: OpenSegment) -> Segment {
    Segment {
        first_seq: open.first_seq,
        last_seq: open.last_seq,
        events: open.events,
        span_ms: match (open.start, open.end) {
            (Some(start), Some(end)) => Some(end.saturating_sub(start).div_ceil(1_000)),
            _ => None,
        },
    }
}

fn record_sample(into: &mut BTreeMap<String, (Vec<u64>, u64)>, key: &str, sample: Option<u64>) {
    let entry = into.entry(key.to_string()).or_default();
    match sample {
        Some(value) => entry.0.push(value),
        None => entry.1 = entry.1.saturating_add(1),
    }
}

#[cfg(test)]
mod tests;
