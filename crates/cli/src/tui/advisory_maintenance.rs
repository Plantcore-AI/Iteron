//! Optional maintenance is reported from its journal and never painted as parent-run completion.
use super::{App, Session, block, item, ui_safe_text};
use iteron_protocol::advisory_maintenance::{MaintenanceKindV1, MaintenanceStateV1};
use iteron_protocol::advisory_maintenance_control::{
    MaintenanceAvailabilityV1, MaintenanceEventV1, MaintenanceReadV1,
};

pub(super) fn apply(app: &mut App, session: &Session, event: MaintenanceEventV1) {
    if event.validate().is_err()
        || session.client.thread_snapshot_v1().is_none_or(|thread| {
            thread.run_id != event.run_id || thread.thread_id != event.thread_id
        })
    {
        return;
    }
    for job in event
        .observation
        .jobs
        .iter()
        .filter(|job| job.last_revision == event.observation.journal_revision)
    {
        app.note(
            block::NoticeLevel::Info,
            format!(
                "advisory {} #{}: {} · journal revision {}",
                kind(job.kind),
                job.job_id.0,
                state(job.state),
                job.last_revision
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
                "maintenance observation {:?} · job state unchanged by this error",
                event.code
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
