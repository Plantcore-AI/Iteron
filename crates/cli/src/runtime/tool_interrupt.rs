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

/// Await one executor until it produces an authoritative result or the session interrupt becomes
/// true. Returning `Err(())` drops the executor future at this boundary. Callers decide whether
/// that cancellation is a definite failure (pure reads) or an unknown outcome (admitted effects).
pub(super) async fn await_tool_or_interrupt<F>(
    future: F,
    interrupt: Option<&std::sync::atomic::AtomicBool>,
    drain: Option<&std::sync::atomic::AtomicBool>,
) -> Result<F::Output, ()>
where
    F: std::future::Future,
{
    use std::sync::atomic::Ordering;

    if interrupt.is_none() && drain.is_none() {
        return Ok(future.await);
    }
    let stopped = || {
        interrupt.is_some_and(|flag| flag.load(Ordering::Relaxed))
            || drain.is_some_and(|flag| flag.load(Ordering::Relaxed))
    };
    if stopped() {
        return Err(());
    }
    tokio::pin!(future);
    loop {
        tokio::select! {
            biased;
            result = &mut future => return Ok(result),
            () = tokio::time::sleep(TOOL_INTERRUPT_POLL_INTERVAL) => {
                if stopped() {
                    return Err(());
                }
            }
        }
    }
}

pub(super) fn interrupted_tool_result(tool_use_id: String, latency_ms: u64) -> ToolResult {
    ToolResult {
        tool_use_id,
        content: "operator interrupted the admitted tool before its executor reported a terminal outcome; side-effect state is unknown and automatic retry is forbidden".into(),
        is_error: true,
        trust: Trust::Workspace,
        latency_ms,
    }
}

pub(super) fn is_interrupted_tool_result(result: &ToolResult) -> bool {
    result
        .content
        .starts_with("operator interrupted the admitted tool")
}
