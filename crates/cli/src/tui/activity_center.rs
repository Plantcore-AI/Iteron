//! Activity Center uses typed public owner handles; transcript labels carry no control authority.
use super::{App, Session, block, command_dispatch, item, transcript_effect, ui_safe_text};
use iteron_protocol::activity_control::{ActivityControlV1, ActivityTargetV1};
use iteron_protocol::agent_control::{AgentEpochV1, AgentIdV1};
use serde_json::Value;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(super) fn queue(
    app: &mut App,
    session: &Session,
    effects: &mut transcript_effect::Supervisor,
    interrupt: &Arc<AtomicBool>,
    argument: &str,
) {
    let Some(thread) = session.client.thread_snapshot_v1() else {
        app.note(block::NoticeLevel::Warn, "public thread unavailable");
        return;
    };
    let command = match parse(argument, thread.thread_id, thread.run_id) {
        Ok(command) => command,
        Err(reason) => {
            app.note(block::NoticeLevel::Warn, reason);
            return;
        }
    };
    command_dispatch::queue_command_control(
        app,
        session,
        effects,
        interrupt,
        crate::app_server::Control::ActivityCenter(command),
        transcript_effect::ControlKind::ActivityCenter,
    );
}
fn parse(
    argument: &str,
    thread_id: iteron_protocol::SessionId,
    run_id: iteron_protocol::RunId,
) -> Result<ActivityControlV1, &'static str> {
    if argument.len() > 1024 {
        return Err("activity command exceeds bound");
    }
    let words = argument.split_whitespace().take(7).collect::<Vec<_>>();
    if words.is_empty() || words == ["list"] {
        return Ok(ActivityControlV1::List { thread_id, run_id });
    }
    if words.len() < 3 || !matches!(words[0], "attach" | "stop") {
        return Err(
            "/activity [list|attach|stop TYPE ID] · agent stop additionally requires INCARNATION TURN",
        );
    }
    let target = match words[1] {
        "process" => ActivityTargetV1::Process {
            job_id: words[2].into(),
        },
        "workflow" => ActivityTargetV1::Workflow {
            run_id: words[2].into(),
        },
        "mcp" => ActivityTargetV1::Mcp {
            name: words[2].into(),
        },
        "verifier" => ActivityTargetV1::Verifier {
            task_id: words[2].into(),
        },
        "agent" => ActivityTargetV1::PersistentAgent {
            agent_id: AgentIdV1(words[2].parse().map_err(|_| "invalid agent id")?),
            epoch: if words[0] == "stop" {
                if words.len() != 5 {
                    return Err("agent stop needs actual observed INCARNATION TURN");
                }
                Some(AgentEpochV1 {
                    incarnation: words[3].parse().map_err(|_| "invalid incarnation")?,
                    turn: words[4].parse().map_err(|_| "invalid epoch turn")?,
                })
            } else {
                None
            },
        },
        _ => return Err("activity TYPE is process|agent|workflow|mcp|verifier"),
    };
    if !matches!(
        &target,
        ActivityTargetV1::PersistentAgent { epoch: Some(_), .. }
    ) && words.len() != 3
    {
        return Err("unexpected activity arguments");
    }
    let command = if words[0] == "attach" {
        ActivityControlV1::Inspect {
            thread_id,
            run_id,
            target,
            stdout_cursor: 0,
            stderr_cursor: 0,
        }
    } else {
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        ActivityControlV1::Stop {
            thread_id,
            run_id,
            target,
            request_id: format!(
                "activity-stop-{}-{time}-{}",
                std::process::id(),
                REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ),
        }
    };
    command.validate()?;
    Ok(command)
}
pub(super) fn render(app: &mut App, value: &Value) {
    let data = &value["data"];
    let mut rows = Vec::new();
    if let Some(activities) = data["activities"].as_array() {
        for activity in activities {
            let target = &activity["target"];
            let kind = target["kind"].as_str().unwrap_or("unknown");
            let id = target["job_id"]
                .as_str()
                .or_else(|| target["run_id"].as_str())
                .or_else(|| target["name"].as_str())
                .or_else(|| target["task_id"].as_str())
                .map(str::to_string)
                .unwrap_or_else(|| target["agent_id"].to_string());
            let display_kind = if kind == "persistent_agent" {
                "agent"
            } else {
                kind
            };
            let state = activity["state"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| activity["state"].to_string());
            rows.push(item(
                "•",
                &format!("{} {}", display_kind, ui_safe_text(&id)),
                &format!(
                    "{} · {}",
                    ui_safe_text(&state),
                    activity["source"].as_str().unwrap_or("unavailable")
                ),
            ));
            if activity["stop_supported"] == true {
                let suffix = if kind == "persistent_agent" {
                    format!(
                        " {} {}",
                        target["epoch"]["incarnation"], target["epoch"]["turn"]
                    )
                } else {
                    String::new()
                };
                rows.push(block::PanelRow::Note(format!("/activity attach {display_kind} {id} · /activity stop {display_kind} {id}{suffix}")));
            }
        }
        rows.push(item("•", "omitted", &data["omitted"].to_string()));
        rows.push(item(
            "•",
            "owners",
            &ui_safe_text(&data["owners"].to_string()),
        ));
    } else {
        // Typed owner replies are bounded; this is a selected task's own output/receipt, not a new terminal assertion.
        let encoded = serde_json::to_string_pretty(data).unwrap_or_default();
        let mut take = encoded.len().min(32 * 1024);
        while !encoded.is_char_boundary(take) {
            take -= 1;
        }
        rows.push(block::PanelRow::Note(ui_safe_text(&encoded[..take])));
        if take < encoded.len() {
            rows.push(block::PanelRow::Note(
                "display shortened; use public ActivityCenterV1 for the bounded owner reply".into(),
            ));
        }
    }
    if rows.is_empty() {
        rows.push(block::PanelRow::Note("no retained owner activities".into()));
    }
    app.panel("⋯", "activity center", rows);
}
#[cfg(test)]
mod tests {
    use super::parse;
    use iteron_protocol::{RunId, SessionId};
    #[test]
    fn stop_requires_real_agent_epoch_and_never_accepts_shell_or_path() {
        let scope = || (SessionId("thread".into()), RunId("run".into()));
        let (thread, run) = scope();
        assert!(parse("stop agent 1", thread, run).is_err());
        let (thread, run) = scope();
        assert!(parse("stop agent 1 2 0", thread, run).is_ok());
        let (thread, run) = scope();
        assert!(parse("stop shell /tmp/file", thread, run).is_err());
        let (thread, run) = scope();
        assert!(
            parse("attach verifier vfy-host-9", thread, run)
                .unwrap()
                .is_read_only()
        );
    }
}
