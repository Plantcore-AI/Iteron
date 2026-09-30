//! Live graph commands use the public owner; rendering consumes immutable typed observations.

use std::sync::{Arc, atomic::AtomicBool};

use iteron_workflow::live_scheduler::{WorkflowNodeStateV1, WorkflowReplanV1};

use super::{App, Session, block, command_dispatch, item, kv, transcript_effect, ui_safe_text};
use crate::workflow::live_session::{LiveWorkflowCommandV1, LiveWorkflowReplyV1};

const MAX_COMMAND_BYTES: usize = 64 * 1024;
const MAX_RENDERED_NODES: usize = 32;
const HELP: &str =
    "/workflows live open|read|pump ID | interrupt|reconcile ID NODE | replan ID REQUEST_ID JSON";

fn parse(argument: &str) -> Result<LiveWorkflowCommandV1, String> {
    if argument.len() > MAX_COMMAND_BYTES {
        return Err("workflow command exceeds 64 KiB".into());
    }
    let (verb, rest) = argument
        .trim()
        .split_once(' ')
        .unwrap_or((argument.trim(), ""));
    let command = match verb {
        "open" => LiveWorkflowCommandV1::Open {
            workflow_id: rest.trim().into(),
        },
        "read" => LiveWorkflowCommandV1::Read {
            workflow_id: rest.trim().into(),
        },
        "pump" => LiveWorkflowCommandV1::Pump {
            workflow_id: rest.trim().into(),
        },
        "interrupt" | "reconcile" => {
            let args = rest.split_whitespace().take(3).collect::<Vec<_>>();
            if args.len() != 2 {
                return Err(HELP.into());
            }
            let workflow_id = args[0].to_owned();
            let node_id = args[1]
                .parse::<u64>()
                .map_err(|_| "supply a nonzero node ID from the actual graph view")?;
            if verb == "interrupt" {
                LiveWorkflowCommandV1::Interrupt {
                    workflow_id,
                    node_id,
                }
            } else {
                LiveWorkflowCommandV1::Reconcile {
                    workflow_id,
                    node_id,
                }
            }
        }
        "replan" => {
            let (workflow_id, rest) = rest.trim().split_once(' ').ok_or(HELP)?;
            let (request_id, plan) = rest.trim().split_once(' ').ok_or(HELP)?;
            let plan: WorkflowReplanV1 =
                serde_json::from_str(plan).map_err(|_| "invalid strict WorkflowReplanV1 JSON")?;
            LiveWorkflowCommandV1::Replan {
                workflow_id: workflow_id.into(),
                request_id: request_id.into(),
                plan,
            }
        }
        _ => return Err(HELP.into()),
    };
    command.validate().map_err(|error| error.to_string())?;
    Ok(command)
}

pub(super) fn queue(
    app: &mut App,
    session: &Session,
    effects: &mut transcript_effect::Supervisor,
    interrupt: &Arc<AtomicBool>,
    argument: &str,
) {
    match parse(argument) {
        Ok(command) => command_dispatch::queue_command_control(
            app,
            session,
            effects,
            interrupt,
            crate::app_server::Control::LiveWorkflow(command),
            transcript_effect::ControlKind::LiveWorkflow,
        ),
        Err(reason) => app.note(block::NoticeLevel::Warn, &reason),
    }
}

fn state_label(state: &WorkflowNodeStateV1) -> &'static str {
    match state {
        WorkflowNodeStateV1::Pending => "pending",
        WorkflowNodeStateV1::Dispatching { .. } => "dispatching",
        WorkflowNodeStateV1::Running { .. } => "running",
        WorkflowNodeStateV1::Cancelling { .. } => "cancelling",
        WorkflowNodeStateV1::Succeeded { .. } => "succeeded",
        WorkflowNodeStateV1::Failed { .. } => "failed",
        WorkflowNodeStateV1::Cancelled { .. } => "cancelled",
        WorkflowNodeStateV1::RecoveryRequired { .. } => "recovery required",
        WorkflowNodeStateV1::Removed => "removed",
    }
}

pub(super) fn render(app: &mut App, reply: &LiveWorkflowReplyV1) {
    let view = &reply.view;
    let mut rows = vec![
        kv("workflow", &ui_safe_text(&view.config.workflow_id)),
        kv(
            "revision / sequence",
            &format!("{} / {}", view.revision, view.sequence),
        ),
        kv(
            "nodes / ready",
            &format!("{} / {}", view.nodes.len(), view.ready.len()),
        ),
        kv(
            "reserved",
            &format!(
                "{} turns · {} tokens · {} microUSD · {} ms",
                view.reserved.turns,
                view.reserved.tokens,
                view.reserved.cost_microusd,
                view.reserved.wall_ms
            ),
        ),
        kv(
            "deadline",
            &format!("{} Unix ms", view.config.deadline_unix_ms),
        ),
    ];
    if let Some(receipt) = &reply.receipt {
        rows.push(kv(
            "plan receipt",
            &format!(
                "revision {} · sequence {}{}",
                receipt.revision,
                receipt.sequence,
                if receipt.replayed { " · replayed" } else { "" }
            ),
        ));
    }
    if let Some(error) = &view.driver_error {
        rows.push(block::PanelRow::Note(format!(
            "driver: {}",
            ui_safe_text(error)
        )));
    }
    for record in view.nodes.iter().take(MAX_RENDERED_NODES) {
        rows.push(item(
            "◇",
            &format!(
                "{} · {} · agent {} · {}",
                record.node.id,
                ui_safe_text(&record.node.label),
                record.node.assigned_agent,
                state_label(&record.state)
            ),
            "",
        ));
        if let WorkflowNodeStateV1::RecoveryRequired { reason, .. } = &record.state {
            rows.push(block::PanelRow::Note(format!(
                "recovery: {}",
                ui_safe_text(reason)
            )));
        }
    }
    if view.nodes.len() > MAX_RENDERED_NODES {
        rows.push(block::PanelRow::Note(format!(
            "{} additional nodes remain in the public typed view",
            view.nodes.len() - MAX_RENDERED_NODES
        )));
    }
    rows.push(block::PanelRow::Note(
        "observed graph state; terminal settlement requires matching host completion proof".into(),
    ));
    app.panel("◇", "live workflow", rows);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_commands_cannot_supply_budget_path_or_completion_evidence() {
        assert!(matches!(
            parse("read flow-1").unwrap(),
            LiveWorkflowCommandV1::Read { .. }
        ));
        for command in [
            "open ../flow",
            "pump flow extra",
            "interrupt flow 0",
            "reconcile flow 1 extra",
            "replan flow req {\"expected_revision\":0,\"changes\":[],\"effects_known\":true}",
        ] {
            assert!(parse(command).is_err(), "{command}");
        }
        assert!(parse(&"x".repeat(MAX_COMMAND_BYTES + 1)).is_err());
    }
}
