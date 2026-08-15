//! Cooperative cancellation boundary for registry tool executors.
//!
//! Provider streams already race the session interrupt flag. Registry tools need the same latency
//! contract, but their durable settlement differs by purity: a dropped pure read is a definite
//! cancellation, while a dropped admitted effect has an unknown terminal state. This module owns
//! only the common future race and the conservative unknown-result payload; the orchestrator owns
//! settlement.

use iteron_protocol::{ToolResult, Trust};
use std::time::Duration;

const TOOL_INTERRUPT_POLL_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ToolInterruption {
    Cooperative,
    Forced,
    Drain,
}

/// Await one executor until it produces an authoritative result or the session interrupt becomes
/// true. Returning `Err(())` drops the executor future at this boundary. Callers decide whether
/// that cancellation is a definite failure (pure reads) or an unknown outcome (admitted effects).
pub(super) async fn await_tool_or_interrupt<F>(
    future: F,
    interrupt: Option<&std::sync::atomic::AtomicBool>,
    force_cancel: Option<&std::sync::atomic::AtomicBool>,
    drain: Option<&std::sync::atomic::AtomicBool>,
) -> Result<F::Output, ToolInterruption>
where
    F: std::future::Future,
{
    use std::sync::atomic::Ordering;

    if interrupt.is_none() && force_cancel.is_none() && drain.is_none() {
        return Ok(future.await);
    }
    let stopped = || {
        if force_cancel.is_some_and(|flag| flag.load(Ordering::Acquire)) {
            Some(ToolInterruption::Forced)
        } else if drain.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            Some(ToolInterruption::Drain)
        } else if interrupt.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            Some(ToolInterruption::Cooperative)
        } else {
            None
        }
    };
    if let Some(reason) = stopped() {
        return Err(reason);
    }
    tokio::pin!(future);
    loop {
        tokio::select! {
            biased;
            result = &mut future => return Ok(result),
            () = tokio::time::sleep(iteron_tunables::param_duration("cli.runtime.tool_interrupt.tool_interrupt_poll_interval", TOOL_INTERRUPT_POLL_INTERVAL)) => {
                if let Some(reason) = stopped() {
                    return Err(reason);
                }
            }
        }
    }
}

pub(super) fn interrupted_tool_result(
    tool_use_id: String,
    latency_ms: u64,
    interruption: ToolInterruption,
) -> ToolResult {
    let authority = match interruption {
        ToolInterruption::Forced => "force-cancelled",
        ToolInterruption::Drain => "drained",
        ToolInterruption::Cooperative => "interrupted",
    };
    ToolResult {
        tool_use_id,
        content: format!(
            "operator {authority} the admitted tool before its executor reported a terminal outcome; side-effect state is unknown and automatic retry is forbidden"
        ),
        is_error: true,
        trust: Trust::Workspace,
        latency_ms,
    }
}

pub(super) fn is_interrupted_tool_result(result: &ToolResult) -> bool {
    result
        .content
        .starts_with("operator interrupted the admitted tool")
        || result
            .content
            .starts_with("operator force-cancelled the admitted tool")
        || result
            .content
            .starts_with("operator drained the admitted tool")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[tokio::test]
    async fn force_cancel_is_distinct_and_wins_over_cooperative_interrupt() {
        let cooperative = AtomicBool::new(true);
        let force = AtomicBool::new(true);
        let drain = AtomicBool::new(false);
        let result = await_tool_or_interrupt(
            std::future::pending::<()>(),
            Some(&cooperative),
            Some(&force),
            Some(&drain),
        )
        .await;
        assert_eq!(result, Err(ToolInterruption::Forced));
        assert!(force.load(Ordering::Acquire));
    }
}
