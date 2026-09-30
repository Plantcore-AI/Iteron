//! Streaming admission for ordinary Auto-approved local tools.
//!
//! The execution gate follows Codex's tool policy: parallel-capable handlers share a
//! read guard, mutations requiring ordering retain an exclusive guard through execution.

use super::{Agent, InboundControl};
use iteron_protocol::{Capability, Trust, Verdict};

impl Agent {
    pub(super) fn early_local_tool_capability(
        &self,
        proposal: &iteron_tools::ToolPolicyProposal,
        governing_trust: Trust,
    ) -> Option<Capability> {
        let call = &proposal.intent.call;
        if self.record_failed
            || self.run_deadline_exhausted()
            || self.requested_control() != InboundControl::None
            || self.registry.is_mcp_effect(&call.name)
            || matches!(
                call.name.as_str(),
                iteron_tools::DISPATCH_AGENT
                    | iteron_tools::WORKFLOW_TOOL
                    | iteron_tools::REQUEST_USER_INPUT
            )
        {
            return None;
        }
        let admission = self.tool_operation_admission(call, governing_trust);
        let capability = admission.capability;
        if !matches!(
            capability,
            Capability::ReversibleLocal | Capability::CodeExecuting
        ) {
            return None;
        }
        (admission.verdict == Verdict::Auto).then_some(capability)
    }
}
