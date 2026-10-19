//! Pure projections of settled or interrupted workflow evidence.

use super::progress::PartialWork;
use iteron_workflow::events::{fmt_count, fmt_duration};
use iteron_workflow::{RunId, RunReport};

/// The ERROR block naming the agents that resolved to JS `null`.
///
/// One function, used by both renderings below, because a degraded `agent()` is deleted by a
/// script's idiomatic `.filter(Boolean)`: if the two summaries disagreed about how a degradation is
/// reported, an exhausted budget would reach the model as a plausibly-short result on whichever
/// path forgot it.
fn degraded_section(degraded: &[String]) -> String {
    if degraded.is_empty() {
        return String::new();
    }
    format!(
        "\n\nERROR: {} agent(s) did not complete and were resolved to null:\n{}",
        degraded.len(),
        degraded
            .iter()
            .map(|reason| format!("  - {reason}"))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

/// The one rendering of a settled run for the model.
///
/// Extracted from the in-turn tool handler so the detached path cannot drift from it: a background
/// run's `collect` returns this exact string, so "ran in-turn" and "ran detached then collected"
/// differ in *when* the model is told and in nothing else.
pub fn run_result_summary(
    name: &str,
    run_id: &str,
    report: &RunReport,
    degraded: &[String],
) -> String {
    let value =
        serde_json::to_string_pretty(&report.value).unwrap_or_else(|_| report.value.to_string());
    let degraded_section = degraded_section(degraded);
    format!(
        "Workflow `{name}` (run {run_id}) {}: {} agent(s) replayed from cache, {} ran live.{degraded_section}\n\nResult:\n{value}",
        if report.stopped {
            "stopped"
        } else {
            "finished"
        },
        report.cache_hits,
        report.cache_misses
    )
}

/// The one rendering of a KILLED run for the model — the counterpart of [`run_result_summary`],
/// which renders a run that reached its own `return`.
///
/// A kill is a deliberate act with a result, not a crash, and the two must not read the same. The
/// engine cannot make that distinction here: it resolves a stopped run's value to `null` because a
/// half-evaluated script value is meaningless, so the finished agents' work survives only because
/// [`PartialWorkSink`] kept it. This states, in one string, what was produced, what was interrupted,
/// and where the durable copy is — the three facts that separate "I stopped it, and here is what I
/// got" from "it died and everything is gone".
pub fn killed_run_summary(
    name: &str,
    run_id: &str,
    report: &RunReport,
    partial: &PartialWork,
    degraded: &[String],
) -> String {
    let produced = if partial.finished.is_empty() {
        "No agent had finished when the kill was requested, so this run produced no partial result."
            .to_string()
    } else {
        format!(
            "{} agent(s) finished before the kill, and their results ARE this run's output:\n{}",
            partial.finished.len(),
            partial
                .finished
                .iter()
                .map(|agent| format!("  - #{} {}: {}", agent.index, agent.label, agent.result))
                .collect::<Vec<_>>()
                .join("\n")
        )
    };
    let omitted = if partial.dropped > 0 {
        format!(
            "\n({} further result(s) exceeded this session's retention bound and are omitted here; \
             the run's journal on disk has every one.)",
            partial.dropped
        )
    } else {
        String::new()
    };
    // Always stated, including as zero: "nothing was interrupted" is itself an answer the client
    // needs in order to know the partial result above is the whole result.
    let interrupted = format!(
        "\n{} agent(s) were still running when the kill was requested; their work was discarded.",
        partial.running
    );
    format!(
        "Workflow `{name}` (run {run_id}) was KILLED at the engine's next safe point. It never \
         reached its own `return`, so it has no return value — this is a cancellation with a \
         partial result, not a crash.\n\n{produced}{omitted}{interrupted}{}\n\n{} agent(s) replayed \
         from cache, {} ran live. `iteron workflow list` records the run.",
        degraded_section(degraded),
        report.cache_hits,
        report.cache_misses
    )
}

/// The terminal record for a run that produced no report of its own.
///
/// A run that never reported is still a directory `iteron workflow list` enumerates — `persist_inputs`
/// created it before the engine started — so leaving it unwritten is the "stub that never reaches a
/// terminal state" failure, one layer up. The zeroed totals mean "none were settled", which is true:
/// the engine failed before it could aggregate any. They are not a claim that the run was free.
pub fn unreported_run(run_id: &str, message: &str) -> RunReport {
    RunReport {
        run_id: RunId::new(run_id.to_string()),
        value: serde_json::json!({ "error": message }),
        stopped: true,
        cache_hits: 0,
        cache_misses: 0,
        errors: 0,
        tokens: 0,
        tool_calls: 0,
        elapsed_ms: 0,
    }
}

/// Stable CLI outcome label for a settled workflow. Cancellation takes precedence because it has
/// its own operator action and exit contract even if some children failed before the interrupt.
pub fn run_status(report: &RunReport) -> &'static str {
    if report.stopped {
        "stopped"
    } else if report.errors > 0 {
        "failed"
    } else {
        "done"
    }
}

/// Stable process contract for `iteron workflow run|resume|watch`: clean success is 0, any settled
/// agent failure is 1, and operator cancellation remains 130.
pub fn run_exit_code(report: &RunReport) -> u8 {
    if report.stopped {
        crate::output::EXIT_INTERRUPTED
    } else if report.errors > 0 {
        crate::output::EXIT_WORKFLOW_FAILED
    } else {
        crate::output::EXIT_SUCCESS
    }
}

/// The terminal status line shared by TTY and piped workflow commands.
pub fn final_status_line(run_id: &str, report: &RunReport) -> String {
    format!(
        "run {run_id} \u{b7} {} \u{b7} {} failed \u{b7} {} tok \u{b7} {} tool call(s) \u{b7} {} \u{b7} cache {} hit / {} miss",
        run_status(report),
        report.errors,
        fmt_count(report.tokens),
        report.tool_calls,
        fmt_duration(report.elapsed_ms),
        report.cache_hits,
        report.cache_misses
    )
}
