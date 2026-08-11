//! Stable selection of content-bearing leaves in the durable event JSON.

use serde_json::{Map, Value};

pub(super) fn visit_content_fields<E>(
    payload: &mut Value,
    mut visit: impl FnMut(&'static str, &mut Value) -> Result<(), E>,
) -> Result<(), E> {
    let Some(event) = payload.get_mut("kind").and_then(Value::as_object_mut) else {
        return Ok(());
    };
    let Some(kind) = event.get("kind").and_then(Value::as_str).map(str::to_owned) else {
        return Ok(());
    };
    match kind.as_str() {
        "message" => {
            if let Some(message) = event.get_mut("message") {
                visit_message(message, &mut visit)?;
            }
        }
        "compaction" => {
            if let Some(messages) = event.get_mut("messages").and_then(Value::as_array_mut) {
                for message in messages {
                    visit_message(message, &mut visit)?;
                }
            }
        }
        "text" => member(event, "delta", "model_text", &mut visit)?,
        "thinking" => member(event, "delta", "model_thinking", &mut visit)?,
        "tool_ready" => {
            if let Some(tool) = event.get_mut("tool").and_then(Value::as_object_mut) {
                member(tool, "input", "tool_arguments", &mut visit)?;
            }
        }
        "tool_done" => {
            if let Some(result) = event.get_mut("result").and_then(Value::as_object_mut) {
                member(result, "content", "tool_result", &mut visit)?;
            }
        }
        "effect_intent" | "approval" => {
            member(event, "arguments", "effect_arguments", &mut visit)?;
            member(event, "workspace", "workspace_path", &mut visit)?;
        }
        "effect_unknown" | "effect_failed" => {
            member(event, "reason", "effect_error", &mut visit)?;
        }
        "notice" => member(event, "text", "operator_notice", &mut visit)?,
        "run_start" => {
            member(event, "cwd", "workspace_path", &mut visit)?;
            member(event, "agent_definition_tag", "session_tag", &mut visit)?;
            visit_environment(event.get_mut("environment"), &mut visit)?;
        }
        "context_injection" => {
            member(event, "text", "memory_context", &mut visit)?;
            if let Some(instructions) = event.get_mut("instructions").and_then(Value::as_object_mut)
            {
                member(instructions, "text", "instructions", &mut visit)?;
                visit_environment(instructions.get_mut("environment"), &mut visit)?;
            }
        }
        "checkpoint" => member(event, "tree_ref", "checkpoint", &mut visit)?,
        "subagent_spawned" => member(event, "agent", "agent_label", &mut visit)?,
        "subagent_finished" | "subagent_finished_v2" => {
            member(event, "error_detail", "workflow_error", &mut visit)?;
        }
        "workflow" | "workflow_v2" => {
            if let Some(workflow) = event.get_mut("event").and_then(Value::as_object_mut) {
                visit_workflow(workflow, &mut visit)?;
            }
        }
        "artifact_produced" => {
            if let Some(artifact) = event.get_mut("artifact").and_then(Value::as_object_mut) {
                member(artifact, "locator", "artifact_locator", &mut visit)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn visit_message<E>(
    message: &mut Value,
    visit: &mut impl FnMut(&'static str, &mut Value) -> Result<(), E>,
) -> Result<(), E> {
    let Some(blocks) = message.get_mut("content").and_then(Value::as_array_mut) else {
        return Ok(());
    };
    for block in blocks {
        let Some(block) = block.as_object_mut() else {
            continue;
        };
        let block_type = block
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        match block_type.as_str() {
            "text" => member(block, "text", "message_text", visit)?,
            "thinking" => member(block, "thinking", "message_thinking", visit)?,
            "provider_state" => member(block, "payload", "provider_state", visit)?,
            "tool_use" => member(block, "input", "tool_arguments", visit)?,
            "tool_result" => member(block, "content", "tool_result", visit)?,
            _ => {}
        }
    }
    Ok(())
}

fn visit_environment<E>(
    environment: Option<&mut Value>,
    visit: &mut impl FnMut(&'static str, &mut Value) -> Result<(), E>,
) -> Result<(), E> {
    if let Some(environment) = environment.and_then(Value::as_object_mut) {
        member(environment, "text", "environment", visit)?;
    }
    Ok(())
}

fn visit_workflow<E>(
    workflow: &mut Map<String, Value>,
    visit: &mut impl FnMut(&'static str, &mut Value) -> Result<(), E>,
) -> Result<(), E> {
    match workflow
        .get("event")
        .and_then(Value::as_str)
        .unwrap_or_default()
    {
        "started" => member(workflow, "name", "workflow_name", visit)?,
        "planned" => {
            if let Some(tasks) = workflow.get_mut("tasks").and_then(Value::as_array_mut) {
                for task in tasks {
                    if let Some(task) = task.as_object_mut() {
                        member(task, "label", "workflow_task", visit)?;
                    }
                }
            }
        }
        "child_finished" | "finished" => {
            member(workflow, "error_detail", "workflow_error", visit)?;
        }
        _ => {}
    }
    Ok(())
}

fn member<E>(
    object: &mut Map<String, Value>,
    key: &str,
    class: &'static str,
    visit: &mut impl FnMut(&'static str, &mut Value) -> Result<(), E>,
) -> Result<(), E> {
    if let Some(value) = object.get_mut(key)
        && !value.is_null()
    {
        visit(class, value)?;
    }
    Ok(())
}
