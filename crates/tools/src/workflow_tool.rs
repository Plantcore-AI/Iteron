//! The `Workflow` tool — the public surface the model calls to launch an ultracode workflow, mirroring
//! Claude Code's `Workflow({script?, scriptPath?, args?})`.
//!
//! It is registered ONLY in the writer `Registry::coding_agent` (never in `read_only`), so a
//! read-only investigator cannot recurse into a fan-out of writer sub-agents — the same gating
//! discipline as `dispatch_agent` (design §4.1).
//!
//! STATUS: in-turn launch is LIVE. The kernel intercepts this tool by name (like `DISPATCH_AGENT`)
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
            description: "Launch an ultracode workflow: an ESM script that orchestrates parallel \
                          sub-agents via agent()/parallel()/pipeline()/phase()/log(). Provide the \
                          script inline (`script`) or by path (`scriptPath`), plus optional `args` \
                          exposed to the script as the ambient `args`. The workflow fans out real \
                          sub-agents under a bounded concurrency governor and returns their results. \
                          Use it for wide, structured multi-agent work that a single turn cannot do."
                .into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
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
                if !has_script && !has_path {
                    return err_result(
                        id,
                        "Workflow: provide either `script` (inline ESM) or `scriptPath`".into(),
                    );
                }
                // Fallback only: on the kernel path this tool is intercepted by name and never
                // reaches this executor. A non-kernel caller gets an actionable pointer.
                ok_result(
                    id,
                    "Workflow received. On the kernel path this launches in-turn; outside it, run \
                     `core workflow run <script.js> [--args <json>]` to execute it live with \
                     streaming progress."
                        .into(),
                )
            })
        },
    )
}
