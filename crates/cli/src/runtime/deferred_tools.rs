//! Data and conflict detection for auto-approved deferred tool batches.

use iteron_protocol::{Capability, ToolUse};

/// Fixed owner for the effecting-tool scheduler and its write-set admission gate.
///
/// This is deliberately not user/project serde. Production construction and the tunables fact
/// adapter both read this value, so the checkpoint cannot claim a wider batch or weaker conflict
/// rule than the executor actually applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub(crate) struct EffectingToolAdmissionPolicy {
    pub max_concurrency: usize,
    pub declared_set_required: bool,
    pub overlap: &'static str,
    pub unknown_set: &'static str,
}

pub(crate) fn effecting_tool_admission_policy() -> EffectingToolAdmissionPolicy {
    EffectingToolAdmissionPolicy {
        max_concurrency: iteron_tunables::param_integer(
            "cli.runtime.default_max_tool_concurrency",
            super::DEFAULT_MAX_TOOL_CONCURRENCY,
        ),
        declared_set_required: true,
        overlap: "reject",
        unknown_set: "reject",
    }
}

/// One deferred call admitted by the capability gate for concurrent execution.
pub(super) struct AutoApprovedCall {
    /// Index in model tool order; also the durable effect ordinal.
    pub(super) index: usize,
    pub(super) call: ToolUse,
    pub(super) intent: iteron_protocol::intent::ToolIntent,
    pub(super) capability: Capability,
    pub(super) action_signature: String,
    pub(super) audit_arguments: serde_json::Value,
}

/// Workspace paths a tool call explicitly names in its structured arguments.
pub(super) fn declared_write_paths(
    input: &serde_json::Value,
) -> std::collections::BTreeSet<String> {
    let mut paths = std::collections::BTreeSet::new();
    if let Some(path) = input.get("path").and_then(|value| value.as_str()) {
        paths.insert(path.to_string());
    }
    if let Some(files) = input.get("files").and_then(|value| value.as_array()) {
        for file in files {
            if let Some(path) = file.get("path").and_then(|value| value.as_str()) {
                paths.insert(path.to_string());
            }
        }
    }
    paths
}
