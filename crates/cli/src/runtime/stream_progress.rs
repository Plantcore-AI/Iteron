//! Sole owner of coalesced internal stream counters and frontend emission cadence.

use iteron_provider::StreamItem;
use std::time::{Duration, Instant};

/// One provider attempt's stream timing, measured in the runtime and carried to the durable
/// `TurnEnd` (#103).
///
/// Every field is `Option` and that is load-bearing. A non-streaming adapter, a replayed turn, or
/// an attempt that failed before its first byte has no time-to-first-token at all, and a `0` would
/// claim an instantaneous first token rather than admitting the measurement never happened. The
/// default is therefore "nothing observed", not "zero".
///
/// These are NOT a partition of `phase_model_ms`, which stays the outer bound: pure tools are
/// dispatched mid-stream and overlap decode by design, so `ttft + decode` can be less than the
/// model phase and the two must never be reconciled by force.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct StreamTiming {
    pub(super) ttft_ms: Option<u64>,
    pub(super) decode_ms: Option<u64>,
    pub(super) stream_items: Option<u32>,
}

/// Coalesced progress for internal provider turns whose text is consumed by the kernel rather than
/// appended to the assistant transcript. A single latest update is enough for the UI; limiting
/// sends to the draw cadence prevents a chatty SSE stream from filling the unbounded event bridge.
/// Minimum spacing between coalesced internal-progress emissions. Matches the UI draw cadence: a
/// faster rate would add events the frame loop cannot show, a slower one would make the kernel
/// activity line visibly lag the stream.
const INTERNAL_STREAM_PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

pub(super) struct InternalStreamProgress {
    kind: crate::workflow::KernelActivityKind,
    tx: Option<tokio::sync::mpsc::Sender<crate::workflow::WorkflowRunUiEvent>>,
    output_chars: usize,
    thinking_chars: usize,
    last_emitted: Option<(usize, usize, Instant)>,
}

impl InternalStreamProgress {
    pub(super) fn new(
        kind: crate::workflow::KernelActivityKind,
        tx: Option<tokio::sync::mpsc::Sender<crate::workflow::WorkflowRunUiEvent>>,
    ) -> Self {
        Self {
            kind,
            tx,
            output_chars: 0,
            thinking_chars: 0,
            last_emitted: None,
        }
    }

    pub(super) fn start(&mut self) {
        self.emit(true);
    }

    pub(super) fn observe(&mut self, item: &StreamItem) {
        match item {
            StreamItem::Accepted | StreamItem::CompatibilityNotice(_) => return,
            StreamItem::TextDelta(delta) => {
                self.output_chars = self.output_chars.saturating_add(delta.chars().count());
            }
            StreamItem::ThinkingDelta(delta) => {
                self.thinking_chars = self.thinking_chars.saturating_add(delta.chars().count());
            }
            StreamItem::ToolUseComplete(_)
            | StreamItem::RateLimit(_)
            | StreamItem::TurnComplete { .. } => return,
        }
        self.emit(false);
    }

    pub(super) fn complete_output(&mut self, text: &str) {
        self.output_chars = self.output_chars.max(text.chars().count());
        self.emit(true);
    }

    fn emit(&mut self, force: bool) {
        let now = Instant::now();
        let counts = (self.output_chars, self.thinking_chars);
        let due = self.last_emitted.is_none_or(|(output, thinking, at)| {
            counts != (output, thinking)
                && (force
                    || now.saturating_duration_since(at)
                        >= iteron_tunables::param_duration(
                            "cli.runtime.internal_stream_progress_interval",
                            INTERNAL_STREAM_PROGRESS_INTERVAL,
                        ))
        });
        if !due && !force {
            return;
        }
        if self
            .last_emitted
            .is_some_and(|(output, thinking, _)| counts == (output, thinking))
        {
            return;
        }
        if let Some(tx) = &self.tx {
            let _ = tx.try_send(crate::workflow::WorkflowRunUiEvent::KernelActivity {
                kind: self.kind,
                output_chars: self.output_chars,
                thinking_chars: self.thinking_chars,
            });
        }
        self.last_emitted = Some((self.output_chars, self.thinking_chars, now));
    }
}
