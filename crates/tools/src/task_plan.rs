//! Writer-only optional planning surface. The resident host owns its durable plan journal.
use crate::{Registry, ToolError, boxfut, err_result};
use iteron_protocol::{Capability, Purity, ToolSpec};
pub const UPDATE_PLAN: &str = "update_plan";
pub(crate) fn register(registry: &mut Registry) -> Result<(), ToolError> {
    registry.push_tool(ToolSpec {
        name: UPDATE_PLAN.into(),
        description: "Maintain an optional plan for a long task. Simple questions need no plan. Inspect first for revision and submission sequence, then replace steps and unresolved obligations after steering changes scope. Statuses are model reports, not verification evidence.".into(),
        input_schema: serde_json::json!({
            "type":"object", "additionalProperties":false,
            "properties": {
                "operation":{"type":"string","enum":["inspect","replace"]},
                "expected_revision":{"type":"integer","minimum":0},
                "observed_submission_seq":{"type":"integer","minimum":1},
                "steps":{"type":"array","maxItems":32,"items":{"type":"object","additionalProperties":false,"required":["description","status"],"properties":{"description":{"type":"string","maxLength":512},"status":{"type":"string","enum":["pending","in_progress","completed"]}}}},
                "obligations":{"type":"array","maxItems":32,"items":{"type":"string","maxLength":512}}
            },"required":["operation"]
        }),
        purity: Purity::Effecting, capability: Capability::ReadOnly,
    }, |call, _| boxfut::box_it(async move {
        err_result(call.id, "update_plan requires the resident durable task-plan owner".into())
    }))
}
