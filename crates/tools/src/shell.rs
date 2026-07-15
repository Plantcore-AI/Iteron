//! The bash tool: Effecting / CodeExecuting, run through the **egress-off sandbox** (ADR-007).
//!
//! Repo-controlled code runs under a sandbox that denies network and ambient HOME reads by
//! default and confines writes to the workspace. Tool output still returns to the already-selected
//! model provider, so this is capability confinement, not a claim of complete information-flow
//! isolation. On a platform without a wired backend, code execution refuses closed.

use crate::{Registry, ToolError, ToolExecution, effectfut};
use core_protocol::{Capability, Purity, ToolResult, ToolSpec, Trust};
use core_sandbox::{Confinement, SandboxError, platform_sandbox};

const TIMEOUT_SECS: u64 = 120;
const MAX_OUTPUT: usize = 20_000;

pub(crate) fn register(r: &mut Registry) -> Result<(), ToolError> {
    let sensitive_env_names = r.sensitive_env_names_handle();
    r.register_external_effect(
        ToolSpec {
            name: "bash".into(),
            description: "Run a bash command in the workspace root. Use for building, running \
                          tests, and git. Output is truncated if large. Directory changes do \
                          not persist across calls; chain with `&&`."
                .into(),
            input_schema: serde_json::json!({
                "type":"object",
                "properties":{"command":{"type":"string"}},
                "required":["command"]
            }),
            purity: Purity::Effecting,
            capability: Capability::CodeExecuting,
        },
        move |call, root| {
            let sensitive_env_names = sensitive_env_names.clone();
            effectfut::box_it(async move {
                let id = call.id.clone();
                let cmd = call
                    .input
                    .get("command")
                    .and_then(|x| x.as_str())
                    .unwrap_or("");
                if cmd.is_empty() {
                    return ToolExecution::Definite(tool_result(id, "empty command".into(), true));
                }
                let sensitive_env_names = sensitive_env_names.lock().unwrap().clone();
                run_bash(&root, cmd, id, sensitive_env_names).await
            })
        },
    )
}

/// Run a bash command through the egress-off sandbox (ADR-007). Network is denied and writes
/// are confined to the workspace; on an unsupported platform the sandbox refuses rather than
/// running UNconfined.
async fn run_bash(
    root: &std::path::Path,
    command: &str,
    tool_use_id: String,
    sensitive_env_names: Vec<String>,
) -> ToolExecution {
    let sb = platform_sandbox();
    let mut conf = Confinement::egress_off(root);
    conf.timeout_secs = TIMEOUT_SECS;
    conf.sensitive_env_names = sensitive_env_names;
    let out = match sb.run(command, &conf).await {
        Ok(output) => output,
        Err(error @ (SandboxError::Unsupported | SandboxError::Profile(_))) => {
            return ToolExecution::Definite(tool_result(tool_use_id, error.to_string(), true));
        }
        Err(SandboxError::Spawn(_)) => {
            // The backend may have crossed process spawn before a pipe/wait failure. Without a
            // durable process handle and workspace reconciliation, replay is unsafe.
            return ToolExecution::Unknown(tool_result(
                tool_use_id,
                "sandbox process outcome is unknown; Core will not retry automatically".into(),
                true,
            ));
        }
    };

    let mut combined = String::new();
    if !out.stdout.is_empty() {
        combined.push_str(&out.stdout);
    }
    if !out.stderr.is_empty() {
        combined.push_str("\n[stderr]\n");
        combined.push_str(&out.stderr);
    }
    // UTF-8-safe head/tail elision (protocol::text): a fixed byte slice would panic on any
    // multibyte char at the cut (code review CRITICAL). The elision is the ACI hygiene keep.
    combined = core_protocol::text::elide_middle(&combined, MAX_OUTPUT);
    if out.timed_out {
        return ToolExecution::Unknown(tool_result(
            tool_use_id,
            format!(
                "[timed out after {TIMEOUT_SECS}s; workspace may be partially changed]\n{combined}"
            ),
            true,
        ));
    }
    ToolExecution::Definite(tool_result(
        tool_use_id,
        format!("[exit {}]\n{combined}", out.exit_code),
        out.exit_code != 0,
    ))
}

fn tool_result(tool_use_id: String, content: String, is_error: bool) -> ToolResult {
    ToolResult {
        tool_use_id,
        content,
        is_error,
        trust: Trust::Workspace,
        latency_ms: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bash_runs_and_captures_exit_and_output() {
        let dir = std::env::temp_dir();
        let execution = run_bash(&dir, "echo hello && exit 3", "call".into(), Vec::new()).await;
        let ToolExecution::Definite(result) = execution else {
            panic!("a normal non-zero exit is still a definite terminal");
        };
        assert!(result.content.contains("hello"));
        assert!(result.content.contains("[exit 3]"));
        assert!(result.is_error, "non-zero exits must not look successful");
    }
}
