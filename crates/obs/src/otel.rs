//! The OTel GenAI projection (#105): turn the durable record outward without becoming a second
//! source of truth.
//!
//! # The one rule this module exists to enforce
//!
//! **It may not measure anything.** Every value it emits is read out of an event the record
//! already holds. There is no clock here, no filesystem, no process and no network — the same
//! standing restriction the [`crate::Ledger`] and [`crate::timeline`] carry. That is not a
//! limitation of the implementation, it IS the design: an exporter that could measure would
//! immediately start disagreeing with the record it claims to export, and the disagreement would
//! surface as a dashboard that contradicts the audit log.
//!
//! The practical consequence is worth stating plainly: **if a number is not in the record, it is
//! not exportable.** Adding a metric therefore means adding it to the record first, where it is
//! hash-chained and replayable, and only then projecting it here.
//!
//! # What is exported
//!
//! Spans, one per brokered effect, carrying the boundary's own `duration_ms` (#101), plus one per
//! model turn carrying `ttft_ms` / `decode_ms` (#103). Metrics: per-class effect duration, per-turn
//! time-to-first-token, and token usage by cache class.
//!
//! # Bounded, and honest about it
//!
//! A run can produce more spans than any collector wants in one payload, so the batch is capped
//! and the overflow is **counted and reported** in `dropped`. Silent truncation is a defect, not a
//! safety valve: a consumer that sees 512 spans and no drop count will believe it saw the run.

use crate::timeline::Timeline;
use iteron_protocol::{Event, EventKind};
use serde::{Deserialize, Serialize};

pub mod catalog;
pub mod lifecycle;

/// Maximum spans in one exported payload. A run that exceeds it reports the overflow rather than
/// quietly shipping a prefix.
pub const MAX_SPANS: usize = 4096;

/// One exported span. Deliberately a flat, self-describing row rather than the full OTLP protobuf
/// shape: the collector-facing encoding is the caller's concern, and keeping the projection flat is
/// what makes "every field traces to a record event" checkable by reading one struct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    /// `gen_ai.operation.name` for provider turns; the effect class label otherwise.
    pub name: String,
    /// The record sequence this span was projected from. The audit trail back to the byte that
    /// justifies the span — without it, "traceable to a record event" is a claim rather than a
    /// property.
    pub seq: u64,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attributes: Vec<(String, String)>,
}

/// One exported metric point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metric {
    pub name: String,
    pub value: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attributes: Vec<(String, String)>,
}

/// A complete export payload for one run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Export {
    pub run_id: String,
    pub spans: Vec<Span>,
    pub metrics: Vec<Metric>,
    /// Live canonical lifecycle projection. Bounded independently from the durable projection and
    /// content-free by construction; absent for legacy/one-shot callers without a live bus.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<lifecycle::LifecycleTelemetrySnapshot>,
    /// Spans that did not fit the bound. **Always present, even at zero**, so a consumer never has
    /// to infer completeness from the absence of a field.
    pub dropped: u64,
}

/// Project a replayed run into the export payload.
///
/// Pure. `timeline` supplies the already-computed distributions (#104) so this module never
/// recomputes a statistic and cannot drift from what `iteron --timeline` reports for the same run.
pub fn project(run_id: &str, events: &[&Event], timeline: &Timeline) -> Export {
    let mut export = Export {
        run_id: run_id.to_string(),
        ..Export::default()
    };

    for event in events {
        let span = match &event.kind {
            // Only PROVEN terminals become spans. An `EffectUnknown` has no duration by
            // construction, and emitting it as a zero-length span would tell a dashboard the
            // effect completed instantly when the record says the opposite.
            EventKind::EffectDone {
                tool,
                duration_ms: Some(duration_ms),
                ..
            } => Some(Span {
                name: tool.clone(),
                seq: event.seq.0,
                duration_ms: *duration_ms,
                attributes: vec![("effect.outcome".into(), "done".into())],
            }),
            EventKind::EffectFailed {
                tool,
                duration_ms: Some(duration_ms),
                ..
            } => Some(Span {
                name: tool.clone(),
                seq: event.seq.0,
                duration_ms: *duration_ms,
                attributes: vec![("effect.outcome".into(), "failed".into())],
            }),
            EventKind::ToolDone { result, .. } => Some(Span {
                name: format!("tool {}", result.tool_use_id),
                seq: event.seq.0,
                duration_ms: result.latency_ms,
                attributes: vec![("tool.is_error".into(), result.is_error.to_string())],
            }),
            EventKind::TurnEnd {
                ttft_ms: Some(ttft_ms),
                decode_ms: Some(decode_ms),
                ..
            } => Some(Span {
                name: "chat".into(),
                seq: event.seq.0,
                duration_ms: ttft_ms.saturating_add(*decode_ms),
                attributes: vec![
                    ("gen_ai.operation.name".into(), "chat".into()),
                    (
                        "gen_ai.server.time_to_first_token_ms".into(),
                        ttft_ms.to_string(),
                    ),
                ],
            }),
            _ => None,
        };
        let Some(span) = span else { continue };
        if export.spans.len() >= MAX_SPANS {
            export.dropped = export.dropped.saturating_add(1);
            continue;
        }
        export.spans.push(span);
    }

    // Metrics are read straight off the timeline, never recomputed, so a dashboard and
    // `iteron --timeline` can never disagree about the same run.
    for (class, distribution) in &timeline.effects {
        export.metrics.push(Metric {
            name: "iteron.effect.duration_ms".into(),
            value: distribution.total_ms,
            attributes: vec![
                ("effect.class".into(), class.clone()),
                ("count".into(), distribution.count.to_string()),
            ],
        });
    }
    if let Some(p50) = timeline.turns.ttft.p50_ms {
        export.metrics.push(Metric {
            name: "iteron.turn.ttft_ms.p50".into(),
            value: p50,
            attributes: Vec::new(),
        });
    }
    export
}

#[cfg(test)]
mod tests {
    use super::*;
    use iteron_protocol::{EffectId, Seq, TurnId, Usage};

    fn event(seq: u64, kind: EventKind) -> Event {
        Event {
            seq: Seq(seq),
            turn: TurnId(1),
            kind,
        }
    }

    /// The load-bearing property: nothing is exported that the record does not contain. An
    /// `EffectUnknown` has no duration, so it must produce no span at all -- a zero-length span
    /// would tell a dashboard the effect completed instantly while the record says no terminal was
    /// ever observed.
    #[test]
    fn an_unproven_effect_produces_no_span() {
        let unknown = event(
            0,
            EventKind::EffectUnknown {
                id: EffectId("effect-0".into()),
                tool: "provider".into(),
                reason: "no terminal observed".into(),
            },
        );
        let export = project("run-1", &[&unknown], &Timeline::default());
        assert!(export.spans.is_empty());
        assert_eq!(export.dropped, 0);
    }

    /// An effect whose terminal predates #101 carries no duration, so it is likewise not
    /// exportable. "If it is not in the record it is not exportable" has to hold for legacy
    /// records too, or the exporter starts inventing history.
    #[test]
    fn a_terminal_without_a_duration_is_not_exportable() {
        let legacy = event(
            0,
            EventKind::EffectDone {
                id: EffectId("effect-0".into()),
                tool: "hook".into(),
                duration_ms: None,
            },
        );
        let export = project("run-1", &[&legacy], &Timeline::default());
        assert!(export.spans.is_empty());
    }

    /// Every span names the record sequence it came from, so the claim "traceable to a record
    /// event" is a property of the payload rather than a promise in a document.
    #[test]
    fn every_span_carries_the_sequence_that_justifies_it() {
        let done = event(
            7,
            EventKind::EffectDone {
                id: EffectId("effect-7".into()),
                tool: "provider".into(),
                duration_ms: Some(1200),
            },
        );
        let export = project("run-1", &[&done], &Timeline::default());
        assert_eq!(export.spans.len(), 1);
        assert_eq!(export.spans[0].seq, 7);
        assert_eq!(export.spans[0].duration_ms, 1200);
    }

    /// Overflow is counted and reported. A consumer that saw the cap and no drop count would
    /// believe it had seen the whole run.
    #[test]
    fn overflow_is_counted_never_silently_truncated() {
        let events: Vec<Event> = (0..(MAX_SPANS as u64 + 5))
            .map(|seq| {
                event(
                    seq,
                    EventKind::EffectDone {
                        id: EffectId(format!("effect-{seq}")),
                        tool: "hook".into(),
                        duration_ms: Some(1),
                    },
                )
            })
            .collect();
        let refs: Vec<&Event> = events.iter().collect();
        let export = project("run-1", &refs, &Timeline::default());
        assert_eq!(export.spans.len(), MAX_SPANS);
        assert_eq!(export.dropped, 5);
    }

    /// A turn's first-token time rides out under the gen_ai convention, and the span length is the
    /// turn's own two halves rather than anything this module measured.
    #[test]
    fn a_turn_exports_its_first_token_time_under_the_gen_ai_convention() {
        let turn = event(
            3,
            EventKind::TurnEnd {
                usage: Usage::default(),
                ttft_ms: Some(300),
                decode_ms: Some(1_700),
                stream_items: Some(42),
            },
        );
        let export = project("run-1", &[&turn], &Timeline::default());
        assert_eq!(export.spans[0].duration_ms, 2_000);
        assert!(
            export.spans[0]
                .attributes
                .iter()
                .any(|(key, value)| key == "gen_ai.server.time_to_first_token_ms" && value == "300")
        );
    }

    /// Metrics are read off the timeline, never recomputed here, so the dashboard and
    /// `iteron --timeline` cannot disagree about the same run.
    #[test]
    fn metrics_are_read_from_the_timeline_rather_than_recomputed() {
        let done = event(
            0,
            EventKind::EffectDone {
                id: EffectId("effect-0".into()),
                tool: "provider".into(),
                duration_ms: Some(1200),
            },
        );
        let timeline = crate::timeline::fold(vec![(Some(0u64), &done)]);
        let export = project("run-1", &[&done], &timeline);
        let metric = export
            .metrics
            .iter()
            .find(|metric| metric.name == "iteron.effect.duration_ms")
            .expect("effect metric");
        assert_eq!(metric.value, timeline.effects["provider"].total_ms);
    }
}
