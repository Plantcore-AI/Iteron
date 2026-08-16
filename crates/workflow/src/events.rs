//! Live progress events + the sink the frontend renders. This mirrors Claude Code's workflow field
//! set (label, phase, state, tokens, tool_calls, duration_ms, result_preview, last_tool_summary)
//! but stays presentation-agnostic: the CLI's plain renderer (design §3.5) and a future ratatui
//! tree both consume this one enum. We adopt the 5-state semantic model over the raw wire.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// v3 adds [`ProgressEvent::AgentCancelling`], separating the prompt cancellation acknowledgement
/// from bounded effect cleanup. A sink built against an older lifecycle cannot make that tail
/// visible, so the engine refuses it rather than silently rendering the child as idle.
pub const PROGRESS_SINK_PORT_VERSION: u32 = 3;

/// The semantic lifecycle state of one agent row (design §3.1). `Queued` and `Skipped` are derived
/// in the higher layers; the slice emits `Running`/`Done`/`Error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowState {
    Queued,
    Running,
    Done,
    Error,
    Skipped,
}

/// One live milestone. Every field is already bounded for its purpose by the emitter
/// (`result_preview` 400, `last_tool_summary` 60). A requested model override is represented by a
/// static marker because the engine cannot authenticate or safely reflect the raw route id; a sink
/// can render these fields verbatim.
#[derive(Debug, Clone)]
pub enum ProgressEvent {
    /// A `phase(title)` boundary. `index` is the 1-based first-seen order.
    Phase { index: usize, title: String },
    /// A `log(msg)` narrator line.
    Log { message: String },
    /// An `agent()` call was DECLARED and is waiting on a Governor permit. Emitted before the permit
    /// is requested, so the whole fan is visible (and the done/total denominator fixed) from the
    /// first frame instead of growing as slots free up.
    AgentQueued {
        index: usize,
        label: String,
        phase: Option<String>,
        model: Option<String>,
    },
    /// An `agent()` call began running (permit acquired).
    AgentStarted {
        index: usize,
        label: String,
        phase: Option<String>,
        model: Option<String>,
        /// Time spent visible in the workflow queue before admission.
        queued_ms: u64,
        /// Slots still available immediately after this child acquired its permit.
        available_permits: usize,
    },
    /// Per-turn activity of a running child (tokens/tool_calls climbing). Emitted only by the full
    /// child-`Agent` spawner; the single-completion slice does not stream these. Kept so the ratatui
    /// tree increment has its seam.
    AgentActivity {
        index: usize,
        tokens: u64,
        tool_calls: u64,
        last_tool_summary: Option<String>,
    },
    /// Cancellation was acknowledged immediately; effect cleanup continues until this explicit
    /// deadline and may still settle as unknown effect.
    AgentCancelling {
        index: usize,
        cleanup_deadline_ms: u64,
    },
    /// An `agent()` call finished (or degraded to null).
    AgentFinished {
        index: usize,
        label: String,
        state: WorkflowState,
        tokens: u64,
        tool_calls: u64,
        duration_ms: u64,
        result_preview: Option<String>,
        last_tool_summary: Option<String>,
        error: Option<String>,
    },
}

/// The frontend seam. Implementations must be cheap and non-blocking; the engine calls `emit` from
/// its single JS-driver thread, so calls are already serialized (no line interleaving).
pub trait ProgressSink: Send + Sync {
    fn port_version(&self) -> u32 {
        PROGRESS_SINK_PORT_VERSION
    }

    fn emit(&self, event: ProgressEvent);
}

const LOG_BURST: u32 = 4;
const ACTIVITY_BURST: u32 = 32;
const LOG_REFILL: Duration = Duration::from_millis(250);
const ACTIVITY_REFILL: Duration = Duration::from_millis(50);
const LOG_MESSAGE_MAX_BYTES: usize = 2 * 1024;

fn log_burst() -> u32 {
    iteron_tunables::param_integer("workflow.events.log_burst", LOG_BURST).clamp(1, LOG_BURST)
}

fn activity_burst() -> u32 {
    iteron_tunables::param_integer("workflow.events.activity_burst", ACTIVITY_BURST)
        .clamp(1, ACTIVITY_BURST)
}

fn log_refill() -> Duration {
    iteron_tunables::param_duration("workflow.events.log_refill", LOG_REFILL)
        .clamp(LOG_REFILL, Duration::from_secs(60))
}

fn activity_refill() -> Duration {
    iteron_tunables::param_duration("workflow.events.activity_refill", ACTIVITY_REFILL)
        .clamp(ACTIVITY_REFILL, Duration::from_secs(60))
}

fn log_message_max_bytes() -> usize {
    iteron_tunables::param_usize(
        "workflow.events.log_message_max_bytes",
        LOG_MESSAGE_MAX_BYTES,
    )
    .clamp(1, LOG_MESSAGE_MAX_BYTES)
}

struct TokenBucket {
    tokens: u32,
    capacity: u32,
    refill: Duration,
    updated: Instant,
}

impl TokenBucket {
    fn new(capacity: u32, refill: Duration) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill,
            updated: Instant::now(),
        }
    }

    fn take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.updated);
        let refill_nanos = self.refill.as_nanos().max(1);
        let replenished = (elapsed.as_nanos() / refill_nanos).min(u32::MAX as u128) as u32;
        if replenished > 0 {
            self.tokens = self.tokens.saturating_add(replenished).min(self.capacity);
            self.updated += self.refill.saturating_mul(replenished);
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

struct BoundedProgressState {
    log_bucket: TokenBucket,
    activity_bucket: TokenBucket,
    log_emitted: usize,
    activity_emitted: usize,
    suppressed_logs: u64,
    suppressed_activity: u64,
    pending_log: Option<String>,
}

/// Per-run backpressure in front of every frontend implementation. JS narration and sampled child
/// activity are lossy/coalescible; lifecycle boundaries are always forwarded immediately. This
/// keeps a custom sink from accidentally turning an adversarial script into unbounded producer CPU
/// even when the final transport has its own bounded channel.
pub(crate) struct BoundedProgressSink {
    inner: Arc<dyn ProgressSink>,
    max_log_events: usize,
    max_activity_events: usize,
    state: Mutex<BoundedProgressState>,
}

impl BoundedProgressSink {
    pub(crate) fn new(
        inner: Arc<dyn ProgressSink>,
        max_log_events: usize,
        max_activity_events: usize,
    ) -> Self {
        Self {
            inner,
            max_log_events,
            max_activity_events,
            state: Mutex::new(BoundedProgressState {
                log_bucket: TokenBucket::new(log_burst(), log_refill()),
                activity_bucket: TokenBucket::new(activity_burst(), activity_refill()),
                log_emitted: 0,
                activity_emitted: 0,
                suppressed_logs: 0,
                suppressed_activity: 0,
                pending_log: None,
            }),
        }
    }

    pub(crate) fn flush_suppressed(&self) {
        let summary = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.suppressed_logs == 0 && state.suppressed_activity == 0 {
                None
            } else {
                let latest = state.pending_log.take();
                let summary = ProgressEvent::Log {
                    message: truncate_preview(
                        &format!(
                            "workflow: coalesced {} narration and {} activity updates{}",
                            state.suppressed_logs,
                            state.suppressed_activity,
                            latest
                                .as_deref()
                                .map(|message| format!("; latest: {message}"))
                                .unwrap_or_default()
                        ),
                        PREVIEW_MAX,
                    ),
                };
                state.suppressed_logs = 0;
                state.suppressed_activity = 0;
                Some(summary)
            }
        };
        if let Some(summary) = summary {
            self.inner.emit(summary);
        }
    }
}

impl ProgressSink for BoundedProgressSink {
    fn emit(&self, event: ProgressEvent) {
        let forwarded = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match event {
                ProgressEvent::Log { message } => {
                    let message = truncate_preview(
                        &iteron_protocol::text::head(&message, log_message_max_bytes()),
                        PREVIEW_MAX,
                    );
                    if state.log_emitted >= self.max_log_events || !state.log_bucket.take() {
                        state.suppressed_logs = state.suppressed_logs.saturating_add(1);
                        state.pending_log = Some(message);
                        None
                    } else {
                        state.log_emitted = state.log_emitted.saturating_add(1);
                        let suppressed = std::mem::take(&mut state.suppressed_logs);
                        state.pending_log = None;
                        let message = if suppressed == 0 {
                            message
                        } else {
                            truncate_preview(
                                &format!("[coalesced {suppressed}] {message}"),
                                PREVIEW_MAX,
                            )
                        };
                        Some(ProgressEvent::Log { message })
                    }
                }
                ProgressEvent::AgentActivity { .. }
                    if state.activity_emitted >= self.max_activity_events
                        || !state.activity_bucket.take() =>
                {
                    state.suppressed_activity = state.suppressed_activity.saturating_add(1);
                    None
                }
                ProgressEvent::AgentActivity {
                    index,
                    tokens,
                    tool_calls,
                    last_tool_summary,
                } => {
                    state.activity_emitted = state.activity_emitted.saturating_add(1);
                    let suppressed = std::mem::take(&mut state.suppressed_activity);
                    let last_tool_summary = if suppressed == 0 {
                        last_tool_summary
                    } else {
                        Some(truncate_preview(
                            &format!(
                                "{} (+{suppressed} updates)",
                                last_tool_summary.unwrap_or_default()
                            ),
                            TOOL_SUMMARY_MAX,
                        ))
                    };
                    Some(ProgressEvent::AgentActivity {
                        index,
                        tokens,
                        tool_calls,
                        last_tool_summary,
                    })
                }
                authoritative => Some(authoritative),
            }
        };
        if let Some(event) = forwarded {
            self.inner.emit(event);
        }
    }
}

/// Discards everything — for tests / headless runs that only want the return value.
pub struct NullSink;

impl ProgressSink for NullSink {
    fn emit(&self, _event: ProgressEvent) {}
}

/// Claude Code's result/prompt preview bound.
pub const PREVIEW_MAX: usize = 400;
/// Claude Code's `last_tool_summary` bound.
pub const TOOL_SUMMARY_MAX: usize = 60;

/// Neutralize non-whitespace control characters, trim + collapse whitespace, and truncate to `max`
/// chars, appending `…` when cut. Char-boundary safe and suitable for one-line display fields.
pub fn truncate_preview(s: &str, max: usize) -> String {
    let mut neutralized = String::with_capacity(s.len());
    for character in s.chars() {
        if character.is_control() && !character.is_whitespace() {
            neutralized.extend(character.escape_default());
        } else {
            neutralized.push(character);
        }
    }
    let collapsed = neutralized.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= max {
        return collapsed;
    }
    let head: String = collapsed.chars().take(max).collect();
    format!("{head}…")
}

/// Claude Code's `Na` number format: k/M-suffixed with a trailing `.0` stripped (`12.3k`, `1M`).
pub fn fmt_count(n: u64) -> String {
    fn scaled(value: f64, suffix: &str) -> String {
        let mut number = format!("{value:.1}");
        if let Some(stripped) = number.strip_suffix(".0") {
            number = stripped.to_string();
        }
        format!("{number}{suffix}")
    }
    if n >= 1_000_000 {
        scaled(n as f64 / 1_000_000.0, "M")
    } else if n >= 1_000 {
        scaled(n as f64 / 1_000.0, "k")
    } else {
        n.to_string()
    }
}

/// Claude Code's duration format: `< 60000ms -> "3.2s"`, minutes above.
pub fn fmt_duration(ms: u64) -> String {
    if ms < 60_000 {
        let s = ms as f64 / 1000.0;
        let mut v = format!("{s:.1}s");
        if v.ends_with(".0s") {
            v = format!("{}s", &v[..v.len() - 3]);
        }
        v
    } else {
        let total_secs = ms / 1000;
        let minutes = total_secs / 60;
        let seconds = total_secs % 60;
        format!("{minutes}m{seconds}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct CollectSink(Mutex<Vec<ProgressEvent>>);

    impl ProgressSink for CollectSink {
        fn emit(&self, event: ProgressEvent) {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(event);
        }
    }

    #[test]
    fn count_format_strips_trailing_zero() {
        assert_eq!(fmt_count(0), "0");
        assert_eq!(fmt_count(999), "999");
        assert_eq!(fmt_count(1_000), "1k");
        assert_eq!(fmt_count(12_340), "12.3k");
        assert_eq!(fmt_count(1_000_000), "1M");
        assert_eq!(fmt_count(2_500_000), "2.5M");
    }

    #[test]
    fn duration_format_matches_cc() {
        assert_eq!(fmt_duration(3_200), "3.2s");
        assert_eq!(fmt_duration(5_000), "5s");
        assert_eq!(fmt_duration(65_000), "1m5s");
    }

    #[test]
    fn preview_truncates_on_char_boundary() {
        let out = truncate_preview("  hello   world  ", 100);
        assert_eq!(out, "hello world");
        let long = "x".repeat(500);
        let cut = truncate_preview(&long, PREVIEW_MAX);
        assert_eq!(cut.chars().count(), PREVIEW_MAX + 1); // 400 + the ellipsis
        assert!(cut.ends_with('…'));
    }

    #[test]
    fn preview_is_one_line_and_neutralizes_terminal_controls() {
        let out = truncate_preview("dead\nagent \u{1b}[31mred\u{7}", 100);
        assert_eq!(out, "dead agent \\u{1b}[31mred\\u{7}");
        assert!(!out.chars().any(char::is_control));
    }

    #[test]
    fn per_run_sink_bounds_lossy_updates_but_never_lifecycle_boundaries() {
        let collected = Arc::new(CollectSink::default());
        let sink = BoundedProgressSink::new(collected.clone(), 2, 1);
        for ordinal in 0..100_000 {
            sink.emit(ProgressEvent::Log {
                message: format!("line {ordinal}"),
            });
        }
        for tokens in 1..=3 {
            sink.emit(ProgressEvent::AgentActivity {
                index: 1,
                tokens,
                tool_calls: 0,
                last_tool_summary: None,
            });
        }
        sink.emit(ProgressEvent::Phase {
            index: 1,
            title: "authoritative".into(),
        });
        sink.emit(ProgressEvent::AgentCancelling {
            index: 1,
            cleanup_deadline_ms: 300,
        });
        sink.flush_suppressed();

        let events = collected
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, ProgressEvent::AgentActivity { .. }))
                .count(),
            1
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, ProgressEvent::Phase { .. }))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, ProgressEvent::AgentCancelling { .. }))
        );
        assert!(events.iter().any(|event| {
            matches!(event, ProgressEvent::Log { message } if message.contains("coalesced 99998 narration and 2 activity") && message.contains("latest: line 99999"))
        }));
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, ProgressEvent::Log { .. }))
                .count(),
            3,
            "100k JS log calls may reach the frontend only as two samples plus one coalesced summary"
        );
    }

    #[test]
    fn content_free_lifecycle_numbers_survive_the_bounded_sink_exactly() {
        let collected = Arc::new(CollectSink::default());
        let sink = BoundedProgressSink::new(collected.clone(), 1, 1);
        sink.emit(ProgressEvent::AgentStarted {
            index: 7,
            label: "worker".into(),
            phase: None,
            model: None,
            queued_ms: 17,
            available_permits: 2,
        });
        sink.emit(ProgressEvent::AgentCancelling {
            index: 7,
            cleanup_deadline_ms: 300,
        });

        let events = collected
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(matches!(
            events.as_slice(),
            [
                ProgressEvent::AgentStarted {
                    index: 7,
                    queued_ms: 17,
                    available_permits: 2,
                    ..
                },
                ProgressEvent::AgentCancelling {
                    index: 7,
                    cleanup_deadline_ms: 300,
                }
            ]
        ));
    }
}
