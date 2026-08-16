//! The `Workflow` tool — the public surface the model calls to launch a task-specific,
//! model-directed workflow from inline ESM or a script path.
//!
//! It is registered ONLY in the writer `Registry::coding_agent` (never in `read_only`), so a
//! read-only investigator cannot recurse into a fan-out of writer sub-agents — the same gating
//! discipline as `dispatch_agent` (design §4.1).
//!
//! STATUS: in-turn launch is LIVE, and so is detached launch where a session owns runs. Legacy
//! `name`/`collect`/`cancel` inputs may remain accepted by the CLI for replay compatibility but are
//! intentionally absent from the model schema; lifecycle control belongs to `/workflows`.
//! Detached runs are answered by the CLI's `WorkflowSupervisor` through the `WorkflowLauncher`
//! seam. A `background` request in a context with no owner runs in-turn and the tool result says
//! the request was not granted; it is never silently downgraded.
//! The kernel intercepts this tool by name (like `DISPATCH_AGENT`)
//! and drives `iteron_workflow::WorkflowEngine::launch` with a `KernelSpawner` built from the running
//! agent's route (see `crates/kernel` `launch_workflow`). This registered executor therefore never
//! runs on the kernel path; its body is only a fallback message for a non-kernel caller (e.g. a
//! direct `Registry::run_effect` in a test). The CLI `iteron workflow run/list/resume/watch` remains
//! the standalone, streaming entry point.

use crate::{Registry, ToolError, boxfut, err_result, ok_result};
use iteron_protocol::{Capability, Purity, ToolSpec};

/// The tool name the kernel intercepts for workflow launches (parallels [`crate::DISPATCH_AGENT`]).
pub const WORKFLOW_TOOL: &str = "Workflow";

pub(crate) fn register(registry: &mut Registry) -> Result<(), ToolError> {
    registry.push_tool(
        ToolSpec {
            name: iteron_tunables::param_str("tools.workflow_tool.workflow_tool", WORKFLOW_TOOL).into(),
            description: "Launch a bounded, task-specific multi-agent workflow only when the \
                          operator opted into orchestration in this turn, asked for it in their own \
                          words (for example workflow, parallel agents, fan out, 并行, 编排, or \
                          动态工作流), or an active skill or slash command explicitly requires it. \
                          Never infer opt-in merely because a task looks parallelizable. For a new \
                          run, prefer one direct `Workflow` call with concise inline ESM in `script`, \
                          composed from the task and repository context already available. Do not \
                          run shell commands, inspect HOME or governance files, or create a temporary \
                          script solely to prepare this call. Do not wrap inline ESM in Markdown \
                          fences. Use `scriptPath` only when the operator named an existing workflow \
                          file or the repository already contains a reusable one. The task-specific \
                          topology may use a bounded composition of \
                          agent()/parallel()/pipeline()/phase()/log(); handle null values and failures \
                          explicitly. Omit `background` or set it false when this turn needs the \
                          result; set it true only for independent work. If validation rejects the \
                          ESM, fix the reported error and retry `Workflow` directly instead of using \
                          shell reconnaissance. Use `/workflows` for progress, stop, and resume."
                .into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "script": {
                        "type": "string",
                        "description": "preferred for new runs: concise inline ESM, with optional first statement `export const meta = {…}`; send source only, without Markdown fences or a temporary file"
                    },
                    "scriptPath": {
                        "type": "string",
                        "description": "path to an existing reusable workflow the operator named or the repository already contains; do not create a temporary script instead of using `script`"
                    },
                    "background": {
                        "type": "boolean",
                        "description": "omit or set false when results are prerequisites for the current turn; true only for independent work the current turn does not depend on"
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
                                 caller owns none. Use `iteron workflow list` to inspect runs on disk."
                            ),
                        );
                    }
                }
                let has_legacy_name = call
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
                let selectors = usize::from(has_script).saturating_add(usize::from(has_path));
                if has_legacy_name || selectors != 1 {
                    return err_result(
                        id,
                        "Workflow: provide exactly one of `script` (inline ESM) or `scriptPath`"
                            .into(),
                    );
                }
                // Fallback only: on the kernel path this tool is intercepted by name and never
                // reaches this executor. A non-kernel caller gets an actionable pointer.
                ok_result(
                    id,
                    "Workflow received. On an interactive kernel path this runs in-turn by default; \
                     request `background: true` only for independent work. Outside the kernel, run \
                     `iteron workflow run <script.js> [--args <json>]` to execute it live with \
                     streaming progress."
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
    fn model_schema_exposes_generic_model_directed_workflows() {
        let registry = Registry::coding_agent(std::env::temp_dir()).unwrap();
        let spec = registry
            .specs()
            .into_iter()
            .find(|spec| spec.name == WORKFLOW_TOOL)
            .expect("writer registry exposes Workflow");
        let properties = spec.input_schema["properties"]
            .as_object()
            .expect("Workflow properties");
        assert!(properties.contains_key("script"));
        assert!(properties.contains_key("scriptPath"));
        assert!(properties.contains_key("resumeFromRunId"));
        for legacy in ["name", "collect", "cancel"] {
            assert!(
                !properties.contains_key(legacy),
                "{legacy} is hidden legacy compatibility, not model guidance"
            );
        }
        assert_eq!(properties["background"]["type"], "boolean");
        assert!(properties["background"].get("default").is_none());
        assert!(
            properties["background"]["description"]
                .as_str()
                .expect("background description")
                .contains("prerequisites for the current turn")
        );
        // The gating and direct-launch rules live closest to the call site, so the model gets them
        // even when a surrounding prompt is terse.
        assert!(
            spec.description
                .contains("only when the operator opted into orchestration")
        );
        assert!(
            spec.description
                .contains("Never infer opt-in merely because a task looks parallelizable")
        );
        assert!(
            spec.description
                .contains("prefer one direct `Workflow` call")
        );
        assert!(
            spec.description
                .contains("inspect HOME or governance files")
        );
        assert!(spec.description.contains("solely to prepare this call"));
        assert!(
            spec.description
                .contains("Do not wrap inline ESM in Markdown fences")
        );
        assert!(spec.description.contains("retry `Workflow` directly"));
        assert!(spec.description.contains("task-specific topology"));
        assert!(
            spec.description
                .contains("agent()/parallel()/pipeline()/phase()/log()")
        );
        assert!(
            spec.description
                .contains("handle null values and failures explicitly")
        );
        assert!(
            properties["script"]["description"]
                .as_str()
                .expect("script description")
                .contains("without Markdown fences")
        );
        assert!(
            properties["scriptPath"]["description"]
                .as_str()
                .expect("scriptPath description")
                .contains("existing reusable workflow")
        );
        assert!(!spec.description.contains("ultracode"));
        assert!(!spec.description.contains("detaches by default"));
    }

    #[tokio::test]
    async fn fallback_requires_exactly_one_model_supplied_script() {
        let registry = Registry::coding_agent(std::env::temp_dir()).unwrap();
        for input in [
            serde_json::json!({}),
            serde_json::json!({"name": "ultracode"}),
            serde_json::json!({
                "name": "ultracode",
                "script": "export const meta = {};"
            }),
            serde_json::json!({"script": "export const meta = {};", "scriptPath": "flow.js"}),
        ] {
            let result = registry
                .run(iteron_protocol::ToolUse {
                    id: "invalid-workflow".into(),
                    name: WORKFLOW_TOOL.into(),
                    input,
                })
                .await;
            assert!(result.is_error);
            assert!(
                result
                    .content
                    .contains("exactly one of `script` (inline ESM) or `scriptPath`")
            );
        }

        let result = registry
            .run(iteron_protocol::ToolUse {
                id: "inline-workflow".into(),
                name: WORKFLOW_TOOL.into(),
                input: serde_json::json!({
                    "script": "export const meta = {};",
                    "background": false
                }),
            })
            .await;
        assert!(!result.is_error);
        assert!(result.content.contains("runs in-turn by default"));
    }
}
