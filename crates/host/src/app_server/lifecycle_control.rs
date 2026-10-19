//! Session lifecycle hook gate and advisory hook execution owner.

use super::{AtomicBool, EventPublisher, LifecyclePayload, Op, SubmissionId, TurnId};

#[derive(Clone, Copy)]
pub(super) struct HookExecution<'a> {
    pub(super) hooks: &'a crate::runtime::hooks::Hooks,
    pub(super) journal: Option<&'a crate::runtime::hooks::journal::HookEffectJournal>,
    pub(super) events: &'a EventPublisher,
    pub(super) cancel: Option<&'a AtomicBool>,
    pub(super) drain: Option<&'a AtomicBool>,
}

pub(super) async fn run_lifecycle_gate(
    execution: HookExecution<'_>,
    event_id: &'static str,
    submission_id: SubmissionId,
    turn_id: Option<TurnId>,
) -> Result<(), String> {
    let HookExecution {
        hooks,
        journal,
        events,
        cancel,
        drain,
    } = execution;
    if hooks.is_empty_for_lifecycle(event_id) {
        return Ok(());
    }
    let journal = journal.ok_or_else(|| {
        "hook gate failed closed because its durable journal is unavailable".to_string()
    })?;
    let context = serde_json::json!({
        "catalog_version": iteron_protocol::lifecycle::LIFECYCLE_CATALOG_VERSION.0,
        "event_id": event_id,
        "submission_id": submission_id.0,
        "turn_id": turn_id.map(|turn| turn.0),
    })
    .to_string();
    events.record_lifecycle(
        "hook.matched",
        turn_id,
        Some(submission_id),
        LifecyclePayload::default(),
    );
    events.record_lifecycle(
        "hook.started",
        turn_id,
        Some(submission_id),
        LifecyclePayload::default(),
    );
    let report = hooks
        .run_lifecycle_cancellable_journaled(event_id, &context, cancel, drain, journal)
        .await
        .map_err(str::to_owned)?;
    if report.timed_out > 0 {
        events.record_lifecycle(
            "hook.timed_out",
            turn_id,
            Some(submission_id),
            LifecyclePayload {
                count: Some(u64::from(report.timed_out)),
                ..LifecyclePayload::default()
            },
        );
    }
    if report.failed > 0 {
        events.record_lifecycle(
            "hook.failed",
            turn_id,
            Some(submission_id),
            LifecyclePayload {
                count: Some(u64::from(report.failed)),
                ..LifecyclePayload::default()
            },
        );
    }
    match report.decision {
        crate::runtime::hooks::HookDecision::Allow => {
            events.record_lifecycle(
                "hook.completed",
                turn_id,
                Some(submission_id),
                LifecyclePayload {
                    count: Some(u64::from(report.completed)),
                    ..LifecyclePayload::default()
                },
            );
            Ok(())
        }
        crate::runtime::hooks::HookDecision::Deny(reason) => {
            events.record_lifecycle(
                "hook.blocked",
                turn_id,
                Some(submission_id),
                LifecyclePayload::default(),
            );
            Err(reason)
        }
    }
}

/// Run a compatibility hook once, outside the canonical lifecycle dispatcher. These names remain
/// supported for existing operator configuration, but never alias into canonical subscriptions:
/// doing both here is what previously double-ran `session.idle` and `tool.call_completed` hooks.
pub(super) async fn run_legacy_hook(
    execution: HookExecution<'_>,
    event: crate::runtime::hooks::HookEvent,
    submission_id: Option<SubmissionId>,
    turn_id: Option<TurnId>,
    context: String,
) {
    let HookExecution {
        hooks,
        journal,
        events,
        cancel,
        drain,
    } = execution;
    if hooks.is_empty_for(event) {
        return;
    }
    let Some(journal) = journal else {
        events.record_lifecycle(
            "hook.failed",
            turn_id,
            submission_id,
            LifecyclePayload {
                reason_code: Some("durable_journal_unavailable".into()),
                ..LifecyclePayload::default()
            },
        );
        return;
    };
    events.record_lifecycle(
        "hook.matched",
        turn_id,
        submission_id,
        LifecyclePayload::default(),
    );
    events.record_lifecycle(
        "hook.started",
        turn_id,
        submission_id,
        LifecyclePayload::default(),
    );
    let decision = hooks
        .run_cancellable_journaled(event, &context, cancel, drain, journal)
        .await;
    let outcome = if matches!(decision, crate::runtime::hooks::HookDecision::Deny(_)) {
        "blocked"
    } else {
        "completed"
    };
    events.record_lifecycle(
        if outcome == "blocked" {
            "hook.blocked"
        } else {
            "hook.completed"
        },
        turn_id,
        submission_id,
        LifecyclePayload::default(),
    );
}

/// Preserve the text compatibility hooks historically received without copying encoded image
/// payloads or file contents into a command's stdin. Attachment counts are sufficient context for
/// the old hook surface; canonical hooks use the structured lifecycle envelope.
pub(super) fn legacy_user_prompt_context(op: &Op, submission_id: SubmissionId) -> Option<String> {
    let (prompt, image_count, file_count) = match op {
        Op::UserInput { text } => (text.as_str(), 0usize, 0usize),
        Op::UserInputV2 { segments } => {
            let prompt = segments
                .as_slice()
                .iter()
                .find_map(|segment| match segment {
                    iteron_protocol::ContentSegment::Text { text } => Some(text.as_str()),
                    iteron_protocol::ContentSegment::Image { .. }
                    | iteron_protocol::ContentSegment::Unknown => None,
                })?;
            let images = segments
                .as_slice()
                .iter()
                .filter(|segment| matches!(segment, iteron_protocol::ContentSegment::Image { .. }))
                .count();
            (prompt, images, 0)
        }
        Op::UserInputV3 {
            text,
            images,
            files,
        } => (text.as_str(), images.len(), files.len()),
        Op::ApprovalResponse { .. }
        | Op::Steer { .. }
        | Op::Interrupt
        | Op::ForceCancel
        | Op::Drain
        | Op::Unknown => return None,
    };
    Some(
        serde_json::json!({
            "event": "UserPromptSubmit",
            "submission_id": submission_id.0,
            "prompt": prompt,
            "image_count": image_count,
            "file_count": file_count,
        })
        .to_string(),
    )
}
