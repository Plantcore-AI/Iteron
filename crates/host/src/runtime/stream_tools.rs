//! Frozen operation-specific eligibility for streamed execution. Every call, including pure
//! reads, passes the real permission/authority ceiling before overlap can poll its executor.
use super::permission_policy::{OperationPolicy, evaluate_operation};
use iteron_protocol::{Capability, Purity, Verdict};
use iteron_tools::{Registry, ToolPolicyProposal};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

pub(super) struct StreamToolControl {
    pub(super) deadline: Option<Instant>,
    pub(super) requested: bool,
    pub(super) interrupt: Option<Arc<AtomicBool>>,
    pub(super) force_cancel: Arc<AtomicBool>,
    pub(super) drain: Arc<AtomicBool>,
}
impl StreamToolControl {
    fn stopped(&self) -> bool {
        self.requested
            || self
                .deadline
                .is_some_and(|deadline| deadline <= Instant::now())
            || self.force_cancel.load(Ordering::Acquire)
            || self.drain.load(Ordering::Relaxed)
            || self
                .interrupt
                .as_ref()
                .is_some_and(|flag| flag.load(Ordering::Relaxed))
    }
}

/// Pure reads cross the same actual operation gate as effects. An explicit deny/request or
/// tighter task ceiling routes to ordered handling instead of bypassing through overlap.
pub(super) fn early_capability(
    registry: &Registry,
    proposal: &ToolPolicyProposal,
    policy: OperationPolicy<'_>,
    record_failed: bool,
    control: &StreamToolControl,
) -> Option<Capability> {
    let call = &proposal.intent.call;
    if record_failed
        || control.stopped()
        || registry.is_mcp_effect(&call.name)
        || matches!(
            call.name.as_str(),
            iteron_tools::DISPATCH_AGENT
                | iteron_tools::WORKFLOW_TOOL
                | iteron_tools::REQUEST_USER_INPUT
        )
    {
        return None;
    }
    let effects = registry.operation_effects(call)?;
    let admission = evaluate_operation(&call.name, &effects, policy);
    let pure = proposal.intent.purity == Purity::Pure;
    let allowed = if pure {
        admission.capability == Capability::ReadOnly
    } else {
        matches!(
            admission.capability,
            Capability::ReversibleLocal | Capability::CodeExecuting
        )
    };
    (allowed
        && admission.verdict == Verdict::Auto
        && !admission.ceiling_blocks
        && !admission.taint_blocks)
        .then_some(admission.capability)
}
