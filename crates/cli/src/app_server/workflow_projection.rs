//! Workflow progress and actual terminal notification projection.

use super::{EventPublisher, LifecyclePayload, ServerEvent};

/// Project workflow-engine milestones into the same canonical lifecycle stream before they reach
/// the frontend. The engine event is authoritative; this observer is bounded and cannot delay it.
pub(super) async fn publish_workflow_progress(
    events: &mut EventPublisher,
    progress: crate::workflow::WorkflowRunUiEvent,
) {
    use iteron_workflow::events::{ProgressEvent, WorkflowState};

    match &progress {
        crate::workflow::WorkflowRunUiEvent::KernelActivity { kind, .. } => match kind {
            crate::workflow::KernelActivityKind::Planning => events.record_workflow_lifecycle(
                "workflow.planning_delta",
                None,
                LifecyclePayload::default(),
            ),
            crate::workflow::KernelActivityKind::Compaction => events.record_lifecycle(
                "context.compaction.started",
                None,
                None,
                LifecyclePayload::default(),
            ),
        },
        crate::workflow::WorkflowRunUiEvent::Started { run_id, .. } => {
            events.record_workflow_lifecycle(
                "workflow.run_started",
                Some(run_id),
                LifecyclePayload::default(),
            );
        }
        crate::workflow::WorkflowRunUiEvent::Progress { run_id, event } => match event {
            ProgressEvent::Phase { title, .. } => events.transition_workflow_phase(run_id, title),
            ProgressEvent::Log { .. } => events.record_workflow_lifecycle(
                "workflow.planning_delta",
                Some(run_id),
                LifecyclePayload::default(),
            ),
            ProgressEvent::AgentQueued { index, .. } => events.record_workflow_child_lifecycle(
                "workflow.child_proposed",
                run_id,
                *index,
                LifecyclePayload::default(),
            ),
            ProgressEvent::AgentStarted { index, .. } => events.record_workflow_child_lifecycle(
                "workflow.child_started",
                run_id,
                *index,
                LifecyclePayload::default(),
            ),
            ProgressEvent::AgentActivity {
                index,
                tokens,
                tool_calls,
                ..
            } => events.record_workflow_child_lifecycle(
                "workflow.child_progress",
                run_id,
                *index,
                LifecyclePayload {
                    count: Some(*tool_calls),
                    magnitude: Some(*tokens),
                    ..LifecyclePayload::default()
                },
            ),
            ProgressEvent::AgentCancelling {
                index,
                cleanup_deadline_ms,
            } => {
                events.record_workflow_child_lifecycle(
                    "workflow.child_progress",
                    run_id,
                    *index,
                    LifecyclePayload {
                        outcome_code: Some("cancelling".into()),
                        magnitude: Some(*cleanup_deadline_ms),
                        ..LifecyclePayload::default()
                    },
                );
                let _ = events
                    .publish(ServerEvent::Activity(workflow_child_cancelling_activity(
                        run_id,
                        *index,
                        *cleanup_deadline_ms,
                    )))
                    .await;
            }
            ProgressEvent::AgentFinished {
                index,
                state,
                tokens,
                tool_calls,
                duration_ms,
                ..
            } => events.record_workflow_child_lifecycle(
                if matches!(state, WorkflowState::Done | WorkflowState::Skipped) {
                    "workflow.child_completed"
                } else {
                    "workflow.child_failed"
                },
                run_id,
                *index,
                LifecyclePayload {
                    outcome_code: Some(
                        match state {
                            WorkflowState::Queued => "queued",
                            WorkflowState::Running => "running",
                            WorkflowState::Done => "done",
                            WorkflowState::Error => "error",
                            WorkflowState::Skipped => "skipped",
                        }
                        .into(),
                    ),
                    count: Some(*tool_calls),
                    duration_us: Some(duration_ms.saturating_mul(1_000)),
                    magnitude: Some(*tokens),
                    ..LifecyclePayload::default()
                },
            ),
        },
        crate::workflow::WorkflowRunUiEvent::Finished { run_id, terminal } => {
            events.finish_workflow_phase(run_id, *terminal);
            events.record_workflow_lifecycle(
                match terminal {
                    crate::workflow::WorkflowRunTerminal::Completed => "workflow.run_completed",
                    crate::workflow::WorkflowRunTerminal::Cancelled => "workflow.run_cancelled",
                    // The frozen catalog's resolved terminal is `run_completed`; the outcome code
                    // preserves failure without inventing a 193rd event or misclassifying it as an
                    // operator cancellation.
                    crate::workflow::WorkflowRunTerminal::Failed => "workflow.run_completed",
                },
                Some(run_id),
                LifecyclePayload {
                    outcome_code: Some(
                        match terminal {
                            crate::workflow::WorkflowRunTerminal::Completed => "completed",
                            crate::workflow::WorkflowRunTerminal::Cancelled => "cancelled",
                            crate::workflow::WorkflowRunTerminal::Failed => "failed",
                        }
                        .into(),
                    ),
                    ..LifecyclePayload::default()
                },
            );
        }
    }
    let _ = events.publish(ServerEvent::WorkflowRun(progress)).await;
}

pub(super) fn workflow_child_cancelling_activity(
    run_id: &str,
    index: usize,
    cleanup_deadline_ms: u64,
) -> iteron_protocol::ActivityEvent {
    use std::hash::{Hash, Hasher};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        });
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    run_id.hash(&mut hasher);
    let run = hasher.finish();
    iteron_protocol::ActivityEvent {
        schema_version: iteron_protocol::ACTIVITY_SCHEMA_VERSION,
        id: format!("workflow-{run:x}:child-{index}:cancelling"),
        parent_id: Some(format!("workflow-{run:x}")),
        kind: iteron_protocol::ActivityKind::Cancellation,
        state: iteron_protocol::ActivityState::Cancelling,
        owner: iteron_protocol::ActivityOwner::Workflow,
        started_at_unix_ms: now,
        updated_at_unix_ms: now,
        attempt: 0,
        limit: 0,
        next_retry_at_unix_ms: None,
        deadline_unix_ms: Some(now.saturating_add(cleanup_deadline_ms)),
        cancelability: iteron_protocol::ActivityCancelability::Strong,
        detail_code: None,
        progress: None,
    }
}

/// Publish one settled background run: settle its card, then say what happened.
///
/// Both events, always. The card settles on every terminal state for the same reason the in-turn
/// path settles it on both exits — a run whose tree spins forever is a transcript that is wrong —
/// and the notice is the operator's copy of an outcome that otherwise only the model can read.
pub(super) async fn publish_settled(
    events: &mut EventPublisher,
    settled: crate::workflow::RunSettled,
) -> String {
    let run_id = settled.run_id.clone();
    let notification = format!(
        "{}\n{}",
        crate::runtime::RUNTIME_NOTIFICATION_PREFIX,
        settled.notification,
    );
    publish_workflow_progress(
        events,
        crate::workflow::WorkflowRunUiEvent::Finished {
            run_id,
            terminal: settled.terminal,
        },
    )
    .await;
    let _ = events.publish(ServerEvent::Notice(settled.notice)).await;
    notification
}
