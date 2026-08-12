//! Operator job-control projection over the model process-tool supervisor.

use super::*;

/// Byte and cursor counters shown when the supervisor's reply omits or mistypes the field. Zero is
/// the pre-write value of both counters, so a malformed reply reads as "nothing observed yet".
const MISSING_COUNTER: u64 = 0;
/// Stdin is reported as still open when the supervisor's reply omits `stdin_closed`. Claiming a
/// close we did not observe would tell the operator a write is impossible when it may still land.
const STDIN_CLOSED_UNKNOWN: bool = false;
/// Retention gaps are reported only when the supervisor says so. Absent the flag, the displayed
/// frame is treated as contiguous rather than annotating output the supervisor never called lossy.
const RETENTION_GAP_UNKNOWN: bool = false;

#[derive(Debug, Clone)]
pub(super) struct AttachedJob {
    job_id: String,
    stdout_cursor: u64,
    stderr_cursor: u64,
}

pub(super) async fn handle(app: &mut App, session: &mut Session, arg: &str) {
    let input = arg.trim();
    match input.split_once(' ') {
        None if matches!(input, "" | "list") => inventory(app, session).await,
        None if input == "clean" => clean(app, session).await,
        None if input == "refresh" => refresh(app, session).await,
        None if input == "detach" => detach(app),
        Some(("attach", job_id)) => attach(app, session, job_id.trim()).await,
        Some(("stop", job_id)) => stop(app, session, job_id.trim()).await,
        Some(("eof", job_id)) => write(app, session, job_id.trim(), String::new(), true).await,
        Some(("write", rest)) => {
            let Some((job_id, text)) = rest.trim().split_once(' ') else {
                usage(app);
                return;
            };
            write(app, session, job_id, text.to_owned(), false).await;
        }
        _ => usage(app),
    }
}

async fn clean(app: &mut App, session: &mut Session) {
    match session
        .control(app_server::Control::Job(app_server::JobControl::Clean))
        .await
    {
        Some(app_server::ControlReply::Jobs(value)) => {
            let count = value.as_array().map_or(0, Vec::len);
            app.note(
                block::NoticeLevel::Info,
                format!(
                    "cleaned {count} retained background job{}",
                    if count == 1 { "" } else { "s" }
                ),
            );
            inventory(app, session).await;
        }
        Some(app_server::ControlReply::Refused(reason)) => {
            app.note(block::NoticeLevel::Err, reason)
        }
        _ => app.note(
            block::NoticeLevel::Err,
            "the background-process supervisor is no longer reachable",
        ),
    }
}

async fn inventory(app: &mut App, session: &mut Session) {
    match session
        .control(app_server::Control::Job(app_server::JobControl::Inventory))
        .await
    {
        Some(app_server::ControlReply::Jobs(value)) => render_inventory(app, &value),
        Some(app_server::ControlReply::Refused(reason)) => {
            app.note(block::NoticeLevel::Err, reason)
        }
        _ => app.note(
            block::NoticeLevel::Err,
            "the background-process supervisor is no longer reachable",
        ),
    }
}

async fn attach(app: &mut App, session: &mut Session, job_id: &str) {
    if job_id.is_empty() {
        usage(app);
        return;
    }
    request_page(app, session, job_id.to_owned(), 0, 0).await;
}

async fn refresh(app: &mut App, session: &mut Session) {
    let Some(attached) = app.attached_job.clone() else {
        app.note(
            block::NoticeLevel::Warn,
            "no job is attached; use `/jobs attach ID`",
        );
        return;
    };
    request_page(
        app,
        session,
        attached.job_id,
        attached.stdout_cursor,
        attached.stderr_cursor,
    )
    .await;
}

async fn request_page(
    app: &mut App,
    session: &mut Session,
    job_id: String,
    stdout_cursor: u64,
    stderr_cursor: u64,
) {
    match session
        .control(app_server::Control::Job(app_server::JobControl::Attach {
            job_id: job_id.clone(),
            stdout_cursor,
            stderr_cursor,
        }))
        .await
    {
        Some(app_server::ControlReply::Jobs(value)) => {
            let next_stdout = cursor(&value, "stdout", "next_cursor").unwrap_or(stdout_cursor);
            let next_stderr = cursor(&value, "stderr", "next_cursor").unwrap_or(stderr_cursor);
            app.attached_job = Some(AttachedJob {
                job_id: job_id.clone(),
                stdout_cursor: next_stdout,
                stderr_cursor: next_stderr,
            });
            render_page(app, &job_id, &value);
        }
        Some(app_server::ControlReply::Refused(reason)) => {
            app.note(block::NoticeLevel::Err, reason)
        }
        _ => app.note(
            block::NoticeLevel::Err,
            "the background-process supervisor is no longer reachable",
        ),
    }
}

fn detach(app: &mut App) {
    match app.attached_job.take() {
        Some(attached) => app.note(
            block::NoticeLevel::Info,
            format!("detached from {}; the job keeps running", attached.job_id),
        ),
        None => app.note(block::NoticeLevel::Info, "no job was attached"),
    }
}

async fn stop(app: &mut App, session: &mut Session, job_id: &str) {
    if job_id.is_empty() {
        usage(app);
        return;
    }
    match session
        .control(app_server::Control::Job(app_server::JobControl::Stop {
            job_id: job_id.to_owned(),
        }))
        .await
    {
        Some(app_server::ControlReply::Jobs(value)) => {
            render_page(app, job_id, &value);
            if app
                .attached_job
                .as_ref()
                .is_some_and(|attached| attached.job_id == job_id)
            {
                app.attached_job = None;
            }
        }
        Some(app_server::ControlReply::Refused(reason)) => {
            app.note(block::NoticeLevel::Err, reason)
        }
        _ => app.note(
            block::NoticeLevel::Err,
            "the background-process supervisor is no longer reachable",
        ),
    }
}

async fn write(app: &mut App, session: &mut Session, job_id: &str, input: String, eof: bool) {
    if job_id.is_empty() {
        usage(app);
        return;
    }
    match session
        .control(app_server::Control::Job(app_server::JobControl::Write {
            job_id: job_id.to_owned(),
            input,
            eof,
        }))
        .await
    {
        Some(app_server::ControlReply::Jobs(value)) => app.panel(
            "›",
            &format!("job input — {job_id}"),
            vec![
                kv(
                    "accepted bytes",
                    &value
                        .get("accepted_bytes")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(MISSING_COUNTER)
                        .to_string(),
                ),
                kv(
                    "stdin",
                    if value
                        .get("stdin_closed")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(STDIN_CLOSED_UNKNOWN)
                    {
                        "closed"
                    } else {
                        "open"
                    },
                ),
            ],
        ),
        Some(app_server::ControlReply::Refused(reason)) => {
            app.note(block::NoticeLevel::Err, reason)
        }
        _ => app.note(
            block::NoticeLevel::Err,
            "the background-process supervisor is no longer reachable",
        ),
    }
}

fn render_inventory(app: &mut App, value: &serde_json::Value) {
    let jobs = value.as_array().map(Vec::as_slice).unwrap_or_default();
    let mut rows = jobs
        .iter()
        .map(|job| {
            let id = string(job, "job_id");
            let state = job
                .get("state")
                .and_then(|state| state.get("kind"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            let backend = string(job, "backend");
            let command = string(job, "command");
            item(
                "•",
                &format!("{id} · {state}"),
                &format!("{backend} · {command}"),
            )
        })
        .collect::<Vec<_>>();
    if rows.is_empty() {
        rows.push(block::PanelRow::Note("no retained background jobs".into()));
    }
    rows.push(block::PanelRow::Note(
        "`/jobs attach ID` · `refresh` · `detach` · `write ID TEXT` · `eof ID` · `stop ID` · `clean`".into(),
    ));
    app.panel("◉", "background jobs", rows);
}

fn render_page(app: &mut App, job_id: &str, value: &serde_json::Value) {
    let state = value
        .get("state")
        .and_then(|state| state.get("kind"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let mut rows = vec![kv("state", state), kv("backend", string(value, "backend"))];
    for stream in ["stdout", "stderr"] {
        let Some(frame) = value.get(stream) else {
            continue;
        };
        let gap = frame
            .get("gap")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(RETENTION_GAP_UNKNOWN);
        let text = frame
            .get("text")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        rows.push(kv(
            stream,
            &format!(
                "cursor {}{}",
                frame
                    .get("next_cursor")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(MISSING_COUNTER),
                if gap { " · retention gap" } else { "" }
            ),
        ));
        for line in text.lines().take(80) {
            rows.push(block::PanelRow::Note(format!("{stream}> {line}")));
        }
    }
    rows.push(block::PanelRow::Note(
        "attached locally · `/jobs refresh` reads from the displayed cursors · `/jobs detach` leaves the process running"
            .into(),
    ));
    app.panel("◉", &format!("job — {job_id}"), rows);
}

fn cursor(value: &serde_json::Value, stream: &str, field: &str) -> Option<u64> {
    value.get(stream)?.get(field)?.as_u64()
}

fn string<'a>(value: &'a serde_json::Value, field: &str) -> &'a str {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
}

fn usage(app: &mut App) {
    app.note(
        block::NoticeLevel::Err,
        "usage: /jobs [list|attach ID|refresh|detach|write ID TEXT|eof ID|stop ID|clean]",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_is_bounded_semantic_and_command_output_is_not_confused_with_state() {
        let mut app = App::new();
        render_inventory(
            &mut app,
            &serde_json::json!([{
                "job_id":"job-0000000000000001-00000001",
                "backend":"linux_bubblewrap_pipes",
                "command":"cargo test",
                "state":{"kind":"running"},
                "stdout_cursor":12,
                "stderr_cursor":0
            }]),
        );
        let block::BlockKind::Panel { title, rows } = &app.transcript.last().unwrap().kind else {
            panic!("inventory must render a semantic panel");
        };
        assert_eq!(title, "background jobs");
        let block::PanelRow::Item { label, hint } = &rows[0] else {
            panic!("one job must render as one typed item");
        };
        assert!(label.contains("running"), "{label}");
        assert!(hint.contains("cargo test"), "{hint}");
        assert!(!hint.contains("stdout>"), "inventory never copies output");
    }
}
