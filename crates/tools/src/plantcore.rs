use crate::{Registry, ToolError, boxfut, err_result};
use iteron_protocol::{Capability, Purity, ToolSpec};

pub const REQUEST_USER_INPUT: &str = "request_user_input";
pub const PUBLISH_ARTIFACT: &str = "publish_artifact";

pub(crate) fn register(registry: &mut Registry) -> Result<(), ToolError> {
    registry.push_tool(
        ToolSpec {
            name: REQUEST_USER_INPUT.into(),
            description: "End this PlantCore Run with one typed question for the user. This must be the only tool call in the model response.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "prompt_utf8": {
                        "type": "string"
                    }
                },
                "required": ["prompt_utf8"]
            }),
            purity: Purity::Pure,
            capability: Capability::ReadOnly,
        },
        |call, _root| {
            boxfut::box_it(async move {
                err_result(
                    call.id,
                    "request_user_input escaped the runtime terminal interceptor".into(),
                )
            })
        },
    )?;
    registry.push_tool(
        ToolSpec {
            name: PUBLISH_ARTIFACT.into(),
            description: "Declare an immutable snapshot of one file under /workspace/output for the PlantCore Worker to upload.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "logical_name": {"type": "string"},
                    "relative_path": {"type": "string"},
                    "media_type": {"type": "string"}
                },
                "required": ["logical_name", "relative_path", "media_type"]
            }),
            purity: Purity::Effecting,
            capability: Capability::ReversibleLocal,
        },
        |call, _root| {
            boxfut::box_it(async move {
                err_result(
                    call.id,
                    "publish_artifact escaped the runtime snapshot interceptor".into(),
                )
            })
        },
    )
}
