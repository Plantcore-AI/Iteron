//! Data and conflict detection for auto-approved deferred tool batches.

use super::KernelError;
use super::failed_action_cache::FailedActionCache;
use super::permission_policy::{OperationPolicy, evaluate_operation};
use super::tool_turn::DeferredToolCall;
use iteron_protocol::{Capability, ToolUse, Verdict};
use iteron_tools::Registry;
use std::collections::BTreeSet;

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
}

/// Frozen trusted views for the leading non-conflicting deferred batch. This scanner has no
/// approval, journal, process or capability mutation port.
pub(super) struct DeferredBatchPolicy<'a> {
    pub(super) registry: &'a Registry,
    pub(super) operation: OperationPolicy<'a>,
    pub(super) failed_actions: &'a FailedActionCache,
    pub(super) declared_set_required: bool,
    pub(super) external_dispatch_gate: bool,
    pub(super) plantcore_gateway_enabled: bool,
}

impl DeferredBatchPolicy<'_> {
    pub(super) fn select(
        &self,
        deferred: &[DeferredToolCall],
        excluded: &BTreeSet<usize>,
    ) -> Result<Vec<AutoApprovedCall>, KernelError> {
        if deferred.len() > iteron_kernel::effects::MAX_TOOL_CALLS_PER_TURN {
            return Err(KernelError::ContextResolution(
                "deferred declarations exceed the admitted envelope".into(),
            ));
        }
        let mut batch = Vec::with_capacity(deferred.len());
        let mut claimed: BTreeSet<String> = BTreeSet::new();
        let mut signatures = BTreeSet::new();
        for (index, call, proposal) in deferred {
            if excluded.contains(index)
                || matches!(
                    call.name.as_str(),
                    iteron_tools::DISPATCH_AGENT | iteron_tools::WORKFLOW_TOOL
                )
                || self.external_dispatch_gate
                    && (self.registry.is_mcp_effect(&call.name)
                        || self.plantcore_gateway_enabled
                            && call.name == "plantcore-run-gateway__tool_search")
            {
                break;
            }
            let signature = format!("{}::{}", call.name, call.input);
            // Stop before repeat declarations so the ordered owner can answer an actual failed
            // operation from its receipt. No duplicate world effect is hidden by concurrency.
            if self.failed_actions.contains_key(&signature) || !signatures.insert(signature.clone())
            {
                break;
            }
            let proposal = match proposal {
                Ok(proposal) => proposal.clone(),
                Err(_) => break,
            };
            if proposal.eligible.iter().next().is_none() {
                break;
            }
            let Some(effects) = self.registry.operation_effects(call) else {
                break;
            };
            let admission = evaluate_operation(&call.name, &effects, self.operation);
            if admission.verdict != Verdict::Auto
                || admission.ceiling_blocks
                || admission.taint_blocks
            {
                break;
            }
            let declared = match scheduling_write_paths(&call.name, &call.input) {
                Ok(paths) => paths,
                Err(_) => break,
            };
            if self.declared_set_required
                && declared.is_empty()
                && admission.capability != Capability::ReadOnly
            {
                break;
            }
            if declared.iter().any(|path| {
                claimed
                    .iter()
                    .any(|known| write_paths_conflict(path, known))
            }) {
                break;
            }
            claimed.extend(declared);
            let eligible = proposal.eligible;
            batch.push(AutoApprovedCall {
                index: *index,
                call: call.clone(),
                intent: proposal.admit(eligible),
                capability: admission.capability,
                action_signature: signature,
            });
        }
        Ok(batch)
    }
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

/// Scheduler conflict keys for one admitted call. An undeclared shell write set remains empty so
/// the caller's `declared_set_required` policy keeps it in the ordered executor. A shell call with
/// an explicit set retains both its tool domain and its exact paths, preventing two shell commands
/// from racing even when their declarations differ.
pub(super) fn scheduling_write_paths(
    tool: &str,
    input: &serde_json::Value,
) -> Result<std::collections::BTreeSet<String>, &'static str> {
    let mut paths = declared_write_paths(input)?;
    if tool == "bash" && !paths.is_empty() {
        paths.insert(BASH_WRITE_DOMAIN.to_owned());
    }
    Ok(paths)
}

/// True when two normalized scheduler keys name the same path or an ancestor/descendant pair.
/// The synthetic shell domain contains `*` but no slash, so it only conflicts with itself.
pub(super) fn write_paths_conflict(left: &str, right: &str) -> bool {
    left == right
        || left
            .strip_prefix(right)
            .is_some_and(|suffix| suffix.starts_with('/'))
        || right
            .strip_prefix(left)
            .is_some_and(|suffix| suffix.starts_with('/'))
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
