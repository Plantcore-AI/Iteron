//! Typed answer/finalization presentation. Only RunEnded releases the resident turn for input.

use super::{App, Session, block, item, ui_safe_text};
use iteron_protocol::turn_publication::{
    TurnFinalOutcomeV1, TurnPublicationEventV1, TurnPublicationFactV1, TurnPublicationReadV1,
    TurnPublicationSnapshotV1,
};

pub(super) fn apply(app: &mut App, session: &Session, event: TurnPublicationEventV1) {
    let Some(thread) = session.client.thread_snapshot_v1() else {
        return;
    };
    if event.validate().is_err() || event.run_id != thread.run_id {
        app.note(
            block::NoticeLevel::Warn,
            "invalid or foreign turn publication was refused",
        );
        return;
    }
    match event.fact {
        TurnPublicationFactV1::AnswerAvailable { .. } => {
            app.flush_text();
            if app.running {
                app.status = "answer available · finalizing run record…".into();
            }
        }
        TurnPublicationFactV1::TurnFinalized { outcome, .. } => {
            app.flush_text();
            if app.running {
                app.status = format!("{} · releasing turn…", outcome_label(outcome));
            }
        }
    }
}

fn outcome_label(outcome: TurnFinalOutcomeV1) -> &'static str {
    match outcome {
        TurnFinalOutcomeV1::Done => "completed",
        TurnFinalOutcomeV1::Drained => "drained",
        TurnFinalOutcomeV1::BudgetExhausted => "budget exhausted",
        TurnFinalOutcomeV1::Interrupted => "interrupted",
        TurnFinalOutcomeV1::Stuck => "stuck",
        TurnFinalOutcomeV1::HarnessError => "harness error",
    }
}

pub(super) fn render(app: &mut App, session: &Session) {
    super::advisory_maintenance::render(app, session);
    let Some(thread) = session.client.thread_snapshot_v1() else {
        app.note(
            block::NoticeLevel::Warn,
            "turn publications are unavailable until the thread is bound",
        );
        return;
    };
    let reply = session
        .client
        .turn_publications_v1(TurnPublicationReadV1::Read {
            thread_id: thread.thread_id,
        });
    let snapshot = serde_json::from_value::<TurnPublicationSnapshotV1>(reply["snapshot"].clone());
    let Ok(snapshot) = snapshot else {
        app.note(
            block::NoticeLevel::Warn,
            "turn publications are unavailable",
        );
        return;
    };
    let mut rows = vec![item("•", "recovery", &format!("{:?}", snapshot.recovery))];
    for event in snapshot.events.iter().rev().take(32) {
        let label = match &event.fact {
            TurnPublicationFactV1::AnswerAvailable { message_seq } => {
                format!("answer available · message {message_seq}")
            }
            TurnPublicationFactV1::TurnFinalized {
                outcome,
                budget_limit,
            } => format!(
                "finalized · {}{}",
                outcome_label(*outcome),
                budget_limit
                    .as_ref()
                    .map(|limit| format!(" · {}", ui_safe_text(limit)))
                    .unwrap_or_default()
            ),
        };
        rows.push(item(
            "•",
            &format!("turn {} · source {}", event.turn_id.0, event.source_seq),
            &label,
        ));
    }
    rows.push(item(
        "•",
        "scope",
        "Recent durable facts; input readiness is a separate session boundary.",
    ));
    app.panel("≡", "answer and finalization", rows);
}
