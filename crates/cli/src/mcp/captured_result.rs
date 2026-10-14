//! Adapt verified transport body data without changing the MCP attempt's certainty.

use iteron_tools::{CapturedToolExecution, CapturedToolOutput};

const CAPTURE_UNAVAILABLE: &str = "Complete MCP response retention is unavailable";
const RESULT_SCHEMA: &str = "iteron.mcp-result.v1";

pub(super) fn mcp_captured_tool_execution(
    tool_use_id: String,
    outcome: iteron_mcp::McpToolOutcome,
) -> CapturedToolExecution {
    let evidence = match &outcome {
        iteron_mcp::McpToolOutcome::Completed { evidence, .. }
        | iteron_mcp::McpToolOutcome::Unknown { evidence, .. } => Some(evidence),
        iteron_mcp::McpToolOutcome::FailedDefinite { evidence, .. } => evidence.as_ref(),
    };
    let captured = evidence.and_then(iteron_mcp::McpToolCallEvidence::captured_result);
    let output = captured.and_then(|captured| {
        captured.json().map(|text| CapturedToolOutput {
            schema: RESULT_SCHEMA.into(),
            text: text.into(),
        })
    });
    let unavailable = captured.is_some_and(iteron_mcp::McpCapturedResult::is_unavailable);
    let mut execution =
        CapturedToolExecution::from(super::mcp_tool_execution(tool_use_id, outcome));
    if let Some(output) = output {
        execution.captured_outputs.push(output);
    }
    if unavailable {
        execution.capture_error = Some(CAPTURE_UNAVAILABLE.into());
    }
    execution
}
