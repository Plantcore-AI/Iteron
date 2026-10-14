//! Optional maintenance is reported from its journal and never painted as parent-run completion.
use super::{App, Session, block, item, ui_safe_text};
use iteron_protocol::advisory_maintenance::{MaintenanceKindV1, MaintenanceStateV1};
use iteron_protocol::advisory_maintenance_control::{
    MaintenanceAvailabilityCodeV1, MaintenanceAvailabilityV1, MaintenanceEventV1, MaintenanceReadV1,
};

pub(super) fn apply(app: &mut App, session: &Session, event: MaintenanceEventV1) {
    if event.validate().is_err()
        || session.client.thread_snapshot_v1().is_none_or(|thread| {
            thread.run_id != event.run_id || thread.thread_id != event.thread_id
        })
    {
        return;
    }
    observe(app, &event);
}

fn observe(app: &mut App, event: &MaintenanceEventV1) {
    for job in event.observation.jobs.iter().filter(|job| {
        job.last_revision == event.observation.journal_revision
            && matches!(
                job.state,
                MaintenanceStateV1::Failed | MaintenanceStateV1::ReconciliationNeeded
            )
    }) {
        app.note(
            block::NoticeLevel::Warn,
            format!(
                "Background {} update {}; inspect /finalization for details.",
                kind(job.kind),
                if job.state == MaintenanceStateV1::Failed {
                    "failed"
                } else {
                    "needs reconciliation"
                },
            ),
        );
    }
}

pub(super) fn availability(app: &mut App, session: &Session, event: MaintenanceAvailabilityV1) {
    if session
        .client
        .thread_snapshot_v1()
        .is_some_and(|thread| thread.run_id == event.run_id && thread.thread_id == event.thread_id)
    {
        app.note(
            block::NoticeLevel::Warn,
            format!(
                "Maintenance status {}; inspect /finalization for details.",
                match event.code {
                    MaintenanceAvailabilityCodeV1::Unavailable => "is unavailable",
                    MaintenanceAvailabilityCodeV1::ReconciliationNeeded => "needs reconciliation",
                    MaintenanceAvailabilityCodeV1::InvalidObservation => "could not be read",
                }
            ),
        );
    }
}

pub(super) fn render(app: &mut App, session: &Session) {
    let Some(thread) = session.client.thread_snapshot_v1() else {
        return;
    };
    let reply = session.client.maintenance_v1(MaintenanceReadV1::Read {
        thread_id: thread.thread_id,
        after_revision: 0,
        limit: 64,
    });
    render_reply(app, &reply);
}

fn render_reply(app: &mut App, reply: &serde_json::Value) {
    let event = serde_json::from_value::<MaintenanceEventV1>(reply["event"].clone());
    let Ok(event) = event else {
        app.panel(
            "⋯",
            "advisory maintenance",
            vec![item(
                "•",
                "observation",
                reply["reason_code"].as_str().unwrap_or("unavailable"),
            )],
        );
        return;
    };
    if event.validate().is_err() {
        return;
    }
    let observation = event.observation;
    let mut rows = vec![
        item(
            "•",
            "presentation gaps",
            &reply["presentation"]["presentation_gaps"].to_string(),
        ),
        item("•", "source", "independent maintenance journal"),
        item("•", "revision", &observation.journal_revision.to_string()),
        item(
            "•",
            "history",
            &format!(
                "{} omitted · {} dropped",
                observation.omitted_jobs, observation.dropped_jobs
            ),
        ),
    ];
    for job in observation.jobs.iter().rev() {
        rows.push(item(
            "•",
            &format!("{} #{} · turn {}", kind(job.kind), job.job_id.0, job.turn),
            &format!(
                "{}{}",
                state(job.state),
                job.reason_code
                    .as_deref()
                    .map(|code| format!(" · {}", ui_safe_text(code)))
                    .unwrap_or_default()
            ),
        ));
    }
    if observation.jobs.is_empty() {
        rows.push(block::PanelRow::Note("no retained journal jobs".into()));
    }
    app.panel("⋯", "advisory maintenance", rows);
}
fn kind(value: MaintenanceKindV1) -> &'static str {
    match value {
        MaintenanceKindV1::LastSuccessfulRoute => "route cache",
        MaintenanceKindV1::TokenCalibration => "token calibration",
    }
}
fn state(value: MaintenanceStateV1) -> &'static str {
    match value {
        MaintenanceStateV1::Queued => "queued",
        MaintenanceStateV1::Running => "running",
        MaintenanceStateV1::Completed => "completed",
        MaintenanceStateV1::Failed => "failed",
        MaintenanceStateV1::ReconciliationNeeded => "reconciliation needed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(state: MaintenanceStateV1) -> MaintenanceEventV1 {
        serde_json::from_value(json!({
            "thread_id": "thread", "run_id": "run",
            "observation": {
                "version": 1,
                "scope_sha256": format!("sha256:{}", "a".repeat(64)),
                "journal_revision": 3,
                "journal_sha256": format!("sha256:{}", "b".repeat(64)),
                "evidence_source": "maintenance_journal",
                "jobs": [{
                    "job_id": 1, "kind": "last_successful_route", "turn": 0,
                    "state": state,
                    "input_sha256": format!("sha256:{}", "c".repeat(64)),
                    "queued_unix_ms": 1, "started_unix_ms": 2, "finished_unix_ms": 3,
                    "last_revision": 3, "reason_code": null
                }],
                "dropped_jobs": 0, "omitted_jobs": 0
            }
        }))
        .unwrap()
    }

    fn terminal_text(app: &mut App) -> String {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 30)).unwrap();
        terminal.draw(|frame| crate::tui::draw(frame, app)).unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[test]
    fn background_progress_is_quiet_and_explicit_read_retains_journal_detail() {
        let mut app = App::new();
        app.stream_text("Hi! How can I help?");
        app.flush_text();
        let before = app.history.blocks().len();
        let screen = terminal_text(&mut app);
        for state in [
            MaintenanceStateV1::Queued,
            MaintenanceStateV1::Running,
            MaintenanceStateV1::Completed,
        ] {
            let event = event(state);
            event.validate().unwrap();
            observe(&mut app, &event);
        }
        assert_eq!(app.history.blocks().len(), before);
        assert_eq!(terminal_text(&mut app), screen);
        assert!(!screen.contains("route cache"));
        assert!(!screen.contains("journal revision"));
        let reply = json!({"event": event(MaintenanceStateV1::Completed), "presentation": {"presentation_gaps": 0}});
        render_reply(&mut app, &reply);
        let semantic = app.history.blocks().last().unwrap().to_text();
        assert!(semantic.contains("independent maintenance journal"));
        assert!(semantic.contains("route cache #1"));
        assert!(semantic.contains("completed"));
        let screen = terminal_text(&mut app);
        assert!(screen.contains("advisory maintenance"));
        assert!(screen.contains("route cache #1"));
    }

    #[test]
    fn maintenance_failures_keep_actionable_warning_without_replaying_old_jobs() {
        for state in [
            MaintenanceStateV1::Failed,
            MaintenanceStateV1::ReconciliationNeeded,
        ] {
            let mut app = App::new();
            let before = app.history.blocks().len();
            let mut event = event(state);
            event.observation.jobs[0].reason_code = Some("cache_publication_unknown".into());
            observe(&mut app, &event);
            assert_eq!(app.history.blocks().len(), before + 1);
            let last = app.history.blocks().last().unwrap();
            assert!(matches!(
                last.kind,
                block::BlockKind::Notice {
                    level: block::NoticeLevel::Warn,
                    ..
                }
            ));
            let semantic = last.to_text();
            assert!(semantic.contains("Background route cache update"));
            assert!(semantic.contains("/finalization"));
            assert!(!semantic.contains("journal revision"));
            let screen = terminal_text(&mut app);
            assert!(screen.contains("Background route cache update"));
            assert!(screen.contains("/finalization"));
            event.observation.journal_revision += 1;
            observe(&mut app, &event);
            assert_eq!(app.history.blocks().len(), before + 1);
            assert!(!app.run.running());
        }
    }
}
