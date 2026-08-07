//! The `Workflow` tool — the public surface the model calls to launch an ultracode workflow, mirroring
//! Claude Code's `Workflow({name?, script?, scriptPath?, args?})`.
//!
//! It is registered ONLY in the writer `Registry::coding_agent` (never in `read_only`), so a
//! read-only investigator cannot recurse into a fan-out of writer sub-agents — the same gating
//! discipline as `dispatch_agent` (design §4.1).
//!
//! STATUS: in-turn launch is LIVE, and so is detached launch where a session owns runs. Legacy
//! `background`/`collect`/`cancel` inputs remain accepted by the CLI for replay compatibility but
//! are intentionally absent from the model schema; lifecycle control belongs to `/workflows`.
//! Detached runs are answered by the CLI's `WorkflowSupervisor` through the
//! `WorkflowLauncher` seam. A `background` request in a context with no owner runs in-turn and the
//! tool result says the request was not granted; it is never silently downgraded.
//! The kernel intercepts this tool by name (like `DISPATCH_AGENT`)
//! and drives `core_workflow::WorkflowEngine::launch` with a `KernelSpawner` built from the running
//! agent's route (see `crates/kernel` `launch_workflow`). This registered executor therefore never
//! runs on the kernel path; its body is only a fallback message for a non-kernel caller (e.g. a
//! direct `Registry::run_effect` in a test). The CLI `core workflow run/list/resume/watch` remains
//! the standalone, streaming entry point.

use crate::{Registry, ToolError, boxfut, err_result, ok_result};
use core_protocol::{Capability, Purity, ToolSpec};

/// The tool name the kernel will intercept once in-turn launch lands (parallels [`crate::DISPATCH_AGENT`]).
pub const WORKFLOW_TOOL: &str = "Workflow";

pub(crate) fn register(registry: &mut Registry) -> Result<(), ToolError> {
    registry.push_tool(
        ToolSpec {
            name: WORKFLOW_TOOL.into(),
            description: "Launch an ultracode workflow: use the built-in dynamic planner with \
                          `name: \"ultracode\"`, or provide an ESM script that orchestrates parallel \
                          sub-agents via agent()/parallel()/pipeline()/phase()/log(). Provide the \
                          script inline (`script`) or by path (`scriptPath`), plus optional `args` \
                          exposed to the script as the ambient `args`. The workflow fans out real \
                          sub-agents under a bounded concurrency governor and returns their results. \
                          Use it for wide, structured multi-agent work that a single turn cannot do. \
                          A run launches in the background: you get an immediate task id, the \
                          conversation stays usable, and the runtime notifies the main thread with \
                          the bounded result when it settles. Use `/workflows` for live progress, \
                          stop, and resume."
                .into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "built-in workflow name; `ultracode` runs planning -> dynamic read-only fan -> reduce inside one engine-owned run"
                    },
                    "script": {
                        "type": "string",
                        "description": "inline ESM workflow source (first statement `export const meta = {…}`)"
                    },
                    "scriptPath": {
                        "type": "string",
                        "description": "path to a workflow script to run/iterate on instead of inlining it"
                    },
                    "args": {
                        "description": "arbitrary JSON exposed to the script as the ambient `args`"
                    },
                    "resumeFromRunId": {
                        "type": "string",
                        "description": "same-session run id to resume; completed unchanged agent() calls replay from cache"
                    }
                }
            }),
            // Effecting so it is never early-dispatched (the kernel will intercept it by name, like
            // dispatch_agent); ReversibleLocal keeps it out of the egress/irreversible auto-approve set.
            purity: Purity::Effecting,
            capability: Capability::ReversibleLocal,
        },
        |call, _root| {
            boxfut::box_it(async move {
                let id = call.id.clone();
                // `collect`/`cancel` address a run that already exists, so they need no script.
                // Only an owner can answer them, and a non-kernel caller has none.
                for field in ["collect", "cancel"] {
                    if call
                        .input
                        .get(field)
                        .and_then(|value| value.as_str())
                        .is_some_and(|value| !value.trim().is_empty())
                    {
                        return err_result(
                            id,
                            format!(
                                "Workflow: `{field}` addresses a run owned by a live session; this \
                                 caller owns none. Use `core workflow list` to inspect runs on disk."
                            ),
                        );
                    }
                }
                let has_name = call
                    .input
                    .get("name")
                    .and_then(|value| value.as_str())
                    .is_some_and(|value| !value.trim().is_empty());
                let has_script = call
                    .input
                    .get("script")
                    .and_then(|value| value.as_str())
                    .is_some_and(|value| !value.trim().is_empty());
                let has_path = call
                    .input
                    .get("scriptPath")
                    .and_then(|value| value.as_str())
                    .is_some_and(|value| !value.trim().is_empty());
                let selectors = usize::from(has_name)
                    .saturating_add(usize::from(has_script))
                    .saturating_add(usize::from(has_path));
                if selectors != 1 {
                    return err_result(
                        id,
                        "Workflow: provide exactly one of `name`, `script` (inline ESM), or `scriptPath`"
                            .into(),
                    );
                }
                // Fallback only: on the kernel path this tool is intercepted by name and never
                // reaches this executor. A non-kernel caller gets an actionable pointer.
                ok_result(
                    id,
                    "Workflow received. On an interactive kernel path this launches under the \
                     session owner and detaches by default; outside it, run `core workflow run \
                     <script.js> [--args <json>]` to execute it live with streaming progress."
                        .into(),
                )
            })
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_schema_uses_task_notification_lifecycle_not_polling_controls() {
        let registry = Registry::coding_agent(std::env::temp_dir()).unwrap();
        let spec = registry
            .specs()
            .into_iter()
            .find(|spec| spec.name == WORKFLOW_TOOL)
            .expect("writer registry exposes Workflow");
        let properties = spec.input_schema["properties"]
            .as_object()
            .expect("Workflow properties");
        assert!(properties.contains_key("resumeFromRunId"));
        for legacy in ["background", "collect", "cancel"] {
            assert!(
                !properties.contains_key(legacy),
                "{legacy} is a hidden replay compatibility input, not model lifecycle guidance"
            );
        }
        assert!(
            spec.description
                .contains("runtime notifies the main thread")
        );
    }
}
