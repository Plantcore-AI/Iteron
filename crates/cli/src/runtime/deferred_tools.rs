//! Data and conflict detection for auto-approved deferred tool batches.

use iteron_protocol::{Capability, ToolUse};

const MAX_DECLARED_WRITE_PATHS: usize = 64;
const MAX_DECLARED_WRITE_PATH_BYTES: usize = 4_096;
pub(super) const BASH_WRITE_DOMAIN: &str = "bash:*";

fn max_declared_write_paths() -> usize {
    iteron_tunables::param_integer(
        "cli.runtime.deferred_tools.max_declared_write_paths",
        MAX_DECLARED_WRITE_PATHS,
    )
    .clamp(1, MAX_DECLARED_WRITE_PATHS)
}

fn max_declared_write_path_bytes() -> usize {
    iteron_tunables::param_integer(
        "cli.runtime.deferred_tools.max_declared_write_path_bytes",
        MAX_DECLARED_WRITE_PATH_BYTES,
    )
    .clamp(1, MAX_DECLARED_WRITE_PATH_BYTES)
}

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
) -> Result<std::collections::BTreeSet<String>, &'static str> {
    let mut paths = std::collections::BTreeSet::new();
    if let Some(path) = input.get("path").and_then(|value| value.as_str()) {
        paths.insert(validated_relative_write_path(path)?);
    }
    if input.get("files").is_some_and(|value| !value.is_array()) {
        return Err("files must be an array");
    }
    if let Some(files) = input.get("files").and_then(serde_json::Value::as_array) {
        for file in files {
            let path = file
                .get("path")
                .and_then(serde_json::Value::as_str)
                .ok_or("each files entry must contain a string path")?;
            paths.insert(validated_relative_write_path(path)?);
        }
    }
    if input.get("writes").is_some_and(|value| !value.is_array()) {
        return Err("writes must be an array");
    }
    if let Some(writes) = input.get("writes").and_then(serde_json::Value::as_array) {
        if writes.len() > max_declared_write_paths() {
            return Err("writes exceeds its bounded item ceiling");
        }
        for path in writes {
            let path = path.as_str().ok_or("writes entries must be strings")?;
            paths.insert(validated_relative_write_path(path)?);
        }
    }
    if paths.len() > max_declared_write_paths() {
        return Err("combined declared write set exceeds its bounded item ceiling");
    }
    Ok(paths)
}

/// Scheduler conflict keys for one admitted call. Shell without a declared set is isolated in a
/// synthetic tool domain, while shell with a set retains both that domain and its exact paths.
pub(super) fn scheduling_write_paths(
    tool: &str,
    input: &serde_json::Value,
) -> Result<std::collections::BTreeSet<String>, &'static str> {
    let mut paths = declared_write_paths(input)?;
    if tool == "bash" {
        paths.insert(BASH_WRITE_DOMAIN.to_owned());
    }
    Ok(paths)
}

fn validated_relative_write_path(path: &str) -> Result<String, &'static str> {
    if path.is_empty() || path.len() > max_declared_write_path_bytes() {
        return Err("declared write path is empty or too long");
    }
    let candidate = std::path::Path::new(path);
    if candidate.is_absolute() {
        return Err("declared write path must be workspace-relative");
    }
    let mut normalized = std::path::PathBuf::new();
    for component in candidate.components() {
        match component {
            std::path::Component::Normal(part) => normalized.push(part),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => {
                return Err("declared write path escapes the workspace");
            }
        }
    }
    let normalized = normalized
        .to_str()
        .ok_or("declared write path is not UTF-8")?;
    if normalized.is_empty() {
        return Err("declared write path resolves to the workspace root");
    }
    Ok(normalized.to_owned())
}
