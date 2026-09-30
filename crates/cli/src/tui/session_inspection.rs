//! Session preview and trace consume the same scoped public control as external clients.

use super::{App, SessionPreview, app_server, block, kv, ui_safe_text};
use iteron_protocol::thread_lifecycle::ThreadLifecycleCommandV1;
use iteron_protocol::{Outcome, RunId};
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};

pub(super) async fn request(
    sender: mpsc::Sender<app_server::ControlRequest>,
    run: String,
) -> Result<SessionPreview, String> {
    let (reply, receive) = oneshot::channel();
    let request = app_server::ControlRequest {
        control: app_server::Control::ThreadLifecycle(ThreadLifecycleCommandV1::Inspect {
            run_id: RunId(run),
        }),
        reply,
    };
    let result = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        sender
            .send(request)
            .await
            .map_err(|_| "session control is unavailable")?;
        receive
            .await
            .map_err(|_| "session inspection reply is unavailable")
    })
    .await
    .map_err(|_| "session inspection timed out".to_owned())?
    .map_err(str::to_owned)?;
    match result {
        app_server::ControlReply::ThreadLifecycle(inspection)
            if inspection["type"] == "thread_inspection_v1" =>
        {
            Ok(SessionPreview { inspection })
        }
        app_server::ControlReply::Refused(reason) => Err(reason),
        _ => Err("unexpected session inspection reply".into()),
    }
}

pub(super) fn recorded_outcome_label(outcome: Option<&Outcome>) -> &'static str {
    match outcome {
        Some(Outcome::Done) => "done",
        Some(Outcome::Drained) => "drained",
        Some(Outcome::BudgetExhausted(_)) => "budget exhausted",
        Some(Outcome::Interrupted) => "interrupted",
        Some(Outcome::Stuck) => "stuck",
        Some(Outcome::HarnessError) => "harness error",
        None => "no terminal",
    }
}

pub(super) fn render(app: &mut App, value: &Value) {
    let history = &value["history"];
    let goal = &value["recent_goal"];
    let terminal = &value["recorded_terminal"];
    let mut rows = vec![
        kv("run", text(&value["run_id"])),
        kv("title", text(&history["title"])),
        kv("workspace", text(&value["workspace"])),
        kv("turns", &history["turns"].to_string()),
        kv("selected", &history["active"].to_string()),
        kv("archived", &history["archived"].to_string()),
        kv("pinned", &history["pinned"].to_string()),
        kv("execution", "not inferred from record terminal"),
    ];
    if !goal.is_null() {
        rows.push(kv("recent goal", text(&goal["text"])));
        rows.push(kv(
            "goal source",
            &format!(
                "{} seq {}{}",
                text(&goal["source_run_id"]),
                goal["source_seq"],
                if goal["complete"] == true {
                    ""
                } else {
                    " · shortened"
                }
            ),
        ));
    } else {
        rows.push(kv("recent goal", "no recorded user text"));
    }
    rows.push(kv(
        "recorded outcome",
        if terminal["available"] == true {
            text(&terminal["outcome"])
        } else {
            text(&terminal["reason_code"])
        },
    ));
    if terminal["available"] == true {
        rows.push(kv(
            "terminal source",
            &format!(
                "{} seq {}",
                text(&terminal["source_run_id"]),
                terminal["source_seq"]
            ),
        ));
    }
    let changes = &value["changes"];
    if changes["available"] == true {
        let count = changes["file_diff_artifacts"]
            .as_array()
            .map_or(0, Vec::len);
        rows.push(kv(
            "retained changes",
            &format!(
                "{count} native commit receipts · {} evicted artifacts",
                changes["evicted_artifacts"]
            ),
        ));
        rows.push(block::PanelRow::Note("/artifacts lists retained full snapshots; untracked workspace changes are not inferred".into()));
    } else {
        rows.push(kv("retained changes", text(&changes["reason_code"])));
    }
    rows.push(kv("background", text(&value["background"]["reason_code"])));
    rows.push(block::PanelRow::Note(
        "/sessions trace RUN reads verified record pages; /sessions resume RUN adopts this session"
            .into(),
    ));
    app.panel("◫", "session preview", rows);
}

pub(super) fn render_trace(app: &mut App, value: &Value) {
    let run = text(&value["run_id"]);
    let mut rows = vec![
        kv("run", run),
        kv("source", "verified physical record · redacted display"),
    ];
    for event in value["events"].as_array().into_iter().flatten() {
        rows.push(kv(
            "record",
            &format!(
                "seq {} · turn {} · complete {}",
                event["source_seq"], event["turn_id"], event["complete"]
            ),
        ));
        let display = if event["complete"] == true {
            serde_json::to_string_pretty(&event["display_event"]).unwrap_or_default()
        } else {
            text(&event["display_json_prefix"]).to_owned()
        };
        // The transport retains a bounded page; the terminal explains its smaller display window.
        let safe = ui_safe_text(&display);
        let mut end = safe.len().min(8192);
        while !safe.is_char_boundary(end) {
            end -= 1;
        }
        rows.push(block::PanelRow::Note(safe[..end].to_owned()));
        if end < safe.len() {
            rows.push(block::PanelRow::Note(
                "terminal display shortened; public TraceRead retains the bounded page".into(),
            ));
        }
    }
    if value["has_more"] == true {
        rows.push(block::PanelRow::Note(format!(
            "next: /sessions trace {run} {}",
            value["next_seq"]
        )));
    }
    rows.push(block::PanelRow::Note(
        "r raw shows transcript cards; /artifacts reads complete retained tool output".into(),
    ));
    app.panel("≡", "verified trace", rows);
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or("unavailable")
}
