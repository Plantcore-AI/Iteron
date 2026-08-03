//! Live progress events + the sink the frontend renders. This mirrors Claude Code's workflow field
//! set (label, phase, state, tokens, tool_calls, duration_ms, result_preview, last_tool_summary)
//! but stays presentation-agnostic: the CLI's plain renderer (design §3.5) and a future ratatui
//! tree both consume this one enum. We adopt the 5-state semantic model over the raw wire.

/// v2 adds [`ProgressEvent::AgentQueued`]: a declared-but-not-yet-admitted row. A sink built against
/// v1 cannot render a fixed denominator, so the engine refuses it rather than silently dropping the
/// queued half of the run.
pub const PROGRESS_SINK_PORT_VERSION: u32 = 2;

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

/// One live milestone. Every field is already truncated to Claude Code's bounds by the emitter
/// (result_preview 400, last_tool_summary 60) so a sink can render it verbatim.
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

/// Discards everything — for tests / headless runs that only want the return value.
pub struct NullSink;

impl ProgressSink for NullSink {
    fn emit(&self, _event: ProgressEvent) {}
}

/// Claude Code's result/prompt preview bound.
pub const PREVIEW_MAX: usize = 400;
/// Claude Code's `last_tool_summary` bound.
pub const TOOL_SUMMARY_MAX: usize = 60;

/// Trim + collapse whitespace + truncate to `max` chars, appending `…` when cut. Char-boundary safe.
pub fn truncate_preview(s: &str, max: usize) -> String {
    let collapsed = s.split_whitespace().collect::<Vec<_>>().join(" ");
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
}
