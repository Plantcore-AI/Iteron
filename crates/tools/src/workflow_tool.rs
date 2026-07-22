//! The `Workflow` tool — the public surface the model calls to launch an ultracode workflow, mirroring
//! Claude Code's `Workflow({script?, scriptPath?, args?})`.
//!
//! It is registered ONLY in the writer `Registry::coding_agent` (never in `read_only`), so a
//! read-only investigator cannot recurse into a fan-out of writer sub-agents — the same gating
//! discipline as `dispatch_agent` (design §4.1).
//!
//! FIRST-SLICE STATUS: the live launch path is the CLI `core workflow run <script.js>`, which wires a
//! real provider-backed spawner + progress renderer. In-turn interception (the kernel catching this
//! tool by name, like `DISPATCH_AGENT`, and driving `core_workflow::WorkflowEngine`) is the exact seam
//! left for the next increment; until then this executor returns an actionable message instead of a
//! silent no-op.

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
                // In-turn launch is not yet wired (the kernel does not intercept this tool in the
                // first slice). Direct the operator to the live CLI path rather than pretend to run.
                ok_result(
                    id,
                    "Workflow received. In-turn launch is not enabled in this build yet; run this \
                     script with `core workflow run <script.js> [--args <json>]` to execute it live \
                     with streaming progress."
                        .into(),
                )
            })
        },
    )
}
