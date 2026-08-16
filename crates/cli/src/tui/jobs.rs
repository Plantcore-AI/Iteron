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
/// Lines rendered from one attached-job output frame. The cursor printed with the frame lets the
/// operator pull the rest, so stopping here withholds output rather than losing it.
const JOB_FRAME_PREVIEW_LINES: usize = 80;

#[derive(Debug, Clone)]
pub(super) struct AttachedJob {
    job_id: String,
    stdout_cursor: u64,
    stderr_cursor: u64,
}

pub(super) fn queue(
    app: &mut App,
    session: &Session,
    effects: &mut transcript_effect::Supervisor,
    interrupt: &Arc<AtomicBool>,
    arg: &str,
) {
    let input = arg.trim();
    let control = match input.split_once(' ') {
        None if matches!(input, "" | "list") => app_server::JobControl::Inventory,
        None if input == "clean" => app_server::JobControl::Clean,
        None if input == "refresh" => {
            let Some(attached) = app.attached_job.clone() else {
                app.note(
                    block::NoticeLevel::Warn,
                    "no job is attached; use `/jobs attach ID`",
                );
                return;
            };
            app_server::JobControl::Attach {
                job_id: attached.job_id,
                stdout_cursor: attached.stdout_cursor,
                stderr_cursor: attached.stderr_cursor,
            }
        }
        None if input == "detach" => {
            detach(app);
            return;
        }
        Some(("attach", job_id)) if !job_id.trim().is_empty() => app_server::JobControl::Attach {
            job_id: job_id.trim().to_owned(),
            stdout_cursor: 0,
            stderr_cursor: 0,
        },
        Some(("stop", job_id)) if !job_id.trim().is_empty() => app_server::JobControl::Stop {
            job_id: job_id.trim().to_owned(),
        },
        Some(("eof", job_id)) if !job_id.trim().is_empty() => app_server::JobControl::Write {
            job_id: job_id.trim().to_owned(),
            input: String::new(),
            eof: true,
        },
        Some(("write", rest)) => {
            let Some((job_id, text)) = rest.trim().split_once(' ') else {
                usage(app);
                return;
            };
            app_server::JobControl::Write {
                job_id: job_id.to_owned(),
                input: text.to_owned(),
                eof: false,
            }
        }
        _ => {
            usage(app);
            return;
        }
    };
    let request = transcript_effect::Request::Control {
        sender: session.control_sender(),
        control: app_server::Control::Job(control),
        interrupt: interrupt.clone(),
        kind: transcript_effect::ControlKind::Jobs {
            command: input.to_owned(),
        },
    };
    if effects.start(request).is_ok() {
        app.status = "job control pending…".into();
    } else {
        app.note(
            block::NoticeLevel::Warn,
            "job control not queued: another local effect is pending",
        );
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

pub(super) fn render_control_reply(app: &mut App, command: &str, value: &serde_json::Value) {
    let input = command.trim();
    match input.split_once(' ') {
        None if matches!(input, "" | "list") => render_inventory(app, value),
        None if input == "clean" => {
            let count = value.as_array().map_or(0, Vec::len);
            app.note(
                block::NoticeLevel::Info,
                format!(
                    "cleaned {count} retained background job{}",
                    if count == 1 { "" } else { "s" }
                ),
            );
        }
        None if input == "refresh" => {
            let Some(attached) = app.attached_job.clone() else {
                return;
            };
            let next_stdout =
                cursor(value, "stdout", "next_cursor").unwrap_or(attached.stdout_cursor);
            let next_stderr =
                cursor(value, "stderr", "next_cursor").unwrap_or(attached.stderr_cursor);
            app.attached_job = Some(AttachedJob {
                job_id: attached.job_id.clone(),
                stdout_cursor: next_stdout,
                stderr_cursor: next_stderr,
            });
            render_page(app, &attached.job_id, value);
        }
        Some(("attach", job_id)) => {
            let job_id = job_id.trim();
            app.attached_job = Some(AttachedJob {
                job_id: job_id.to_owned(),
                stdout_cursor: cursor(value, "stdout", "next_cursor").unwrap_or(0),
                stderr_cursor: cursor(value, "stderr", "next_cursor").unwrap_or(0),
            });
            render_page(app, job_id, value);
        }
        Some(("stop", job_id)) => {
            let job_id = job_id.trim();
            render_page(app, job_id, value);
            if app
                .attached_job
                .as_ref()
                .is_some_and(|attached| attached.job_id == job_id)
            {
                app.attached_job = None;
            }
        }
        Some(("write" | "eof", rest)) => {
            let job_id = rest.split_whitespace().next().unwrap_or("unknown");
            app.panel(
                "›",
                &format!("job input — {job_id}"),
                vec![
                    kv(
                        "accepted bytes",
                        &value
                            .get("accepted_bytes")
                            .and_then(serde_json::Value::as_u64)
                            .unwrap_or(iteron_tunables::param_integer(
                                "cli.tui.jobs.missing_counter",
                                MISSING_COUNTER,
                            ))
                            .to_string(),
                    ),
                    kv(
                        "stdin",
                        if value
                            .get("stdin_closed")
                            .and_then(serde_json::Value::as_bool)
                            .unwrap_or(iteron_tunables::param_bool(
                                "cli.tui.jobs.stdin_closed_unknown",
                                STDIN_CLOSED_UNKNOWN,
                            ))
                        {
                            "closed"
                        } else {
                            "open"
                        },
                    ),
                ],
            );
        }
        _ => usage(app),
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
            .unwrap_or(iteron_tunables::param_bool(
                "cli.tui.jobs.retention_gap_unknown",
                RETENTION_GAP_UNKNOWN,
            ));
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
                    .unwrap_or(iteron_tunables::param_integer(
                        "cli.tui.jobs.missing_counter",
                        MISSING_COUNTER
                    )),
                if gap { " · retention gap" } else { "" }
            ),
        ));
        for line in text.lines().take(iteron_tunables::param_integer(
            "cli.tui.jobs.job_frame_preview_lines",
            JOB_FRAME_PREVIEW_LINES,
        )) {
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
