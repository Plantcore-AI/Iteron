//! Data and conflict detection for auto-approved deferred tool batches.

use iteron_protocol::{Capability, ToolUse};

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
