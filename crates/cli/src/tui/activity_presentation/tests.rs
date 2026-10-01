use super::{ActivityPresentation, ActivityReaction, MAX_ACTIVE, MAX_ACTIVE_BYTES};
use iteron_protocol::{
    ACTIVITY_SCHEMA_VERSION, ActivityCancelability, ActivityDetailCode, ActivityEvent,
    ActivityKind, ActivityOwner, ActivityState,
};
use std::time::{Duration, Instant};

fn event(id: impl Into<String>) -> ActivityEvent {
    ActivityEvent {
        schema_version: ACTIVITY_SCHEMA_VERSION,
        id: id.into(),
        parent_id: None,
        kind: ActivityKind::Tool,
        state: ActivityState::Running,
        owner: ActivityOwner::Runtime,
        started_at_unix_ms: 1,
        updated_at_unix_ms: 1,
        attempt: 1,
        limit: 1,
        next_retry_at_unix_ms: None,
        deadline_unix_ms: None,
        cancelability: ActivityCancelability::Cooperative,
        detail_code: Some(ActivityDetailCode::ToolRunning),
        progress: None,
    }
}

#[test]
fn capacity_loss_preserves_existing_observations_and_never_fabricates_a_task_terminal() {
    let mut owner = ActivityPresentation::default();
    for index in 0..MAX_ACTIVE {
        assert!(matches!(
            owner.observe(event(format!("task-{index}")), true),
            ActivityReaction::None
        ));
    }
    assert!(matches!(
        owner.observe(event("excess"), true),
        ActivityReaction::Saturated
    ));
    assert_eq!(owner.values().count(), MAX_ACTIVE);
    assert!(!owner.contains("excess"));
    assert!(owner.has_presentation_gap());
    assert!(
        owner
            .values()
            .all(|observation| !observation.event().state.is_terminal())
    );
    let mut observed_terminal = event("task-0");
    observed_terminal.state = ActivityState::Succeeded;
    owner.observe(observed_terminal, true);
    assert!(!owner.contains("task-0"));
    owner.observe(event("task-0"), true);
    assert!(
        !owner.contains("task-0"),
        "late updates do not reopen an observed terminal"
    );
    owner.observe(event("new-task"), true);
    assert!(owner.contains("new-task"));
    owner.retire_run_observations();
    assert!(!owner.has_active());
    assert!(!owner.has_presentation_gap());
    owner.observe(event("new-task"), true);
    assert!(
        !owner.has_active(),
        "RunEnded retires advisory IDs without publishing fake success"
    );
}

#[test]
fn actual_string_capacity_is_charged_before_retaining_a_valid_small_id() {
    let mut owner = ActivityPresentation::default();
    owner.observe(event("kept"), true);
    let mut large_capacity = String::with_capacity(MAX_ACTIVE_BYTES * 2);
    large_capacity.push_str("small-id");
    let observed = event(large_capacity);
    assert!(observed.validate().is_ok());
    assert!(matches!(
        owner.observe(observed, true),
        ActivityReaction::Saturated
    ));
    assert_eq!(owner.values().count(), 1);
    assert!(owner.contains("kept"));
    assert!(owner.active_bytes <= MAX_ACTIVE_BYTES);
}

#[test]
fn request_sent_and_provider_response_keep_distinct_authority_and_the_original_wait_clock() {
    let mut owner = ActivityPresentation::default();
    let sent = Instant::now() - Duration::from_secs(3);
    owner.observe_request_sent(sent);
    assert!(!owner.provider_wait().unwrap().accepted);
    owner.observe_provider_response(Instant::now());
    let waiting = owner.provider_wait().unwrap();
    assert!(waiting.accepted);
    assert_eq!(waiting.started, sent);
    owner.finish_provider_wait();
    assert!(owner.provider_wait().is_none());
    owner.observe_request_sent(Instant::now());
    assert!(
        !owner.provider_wait().unwrap().accepted,
        "a new transport cannot inherit provider acceptance"
    );
    owner.retire_run_observations();
    assert!(owner.provider_wait().is_none());
}

#[test]
fn repeated_terminal_rows_do_not_evict_unrelated_retired_identity() {
    let mut owner = ActivityPresentation::default();
    let mut first = event("first");
    first.state = ActivityState::Succeeded;
    owner.observe(first, true);
    for _ in 0..1_000 {
        let mut repeated = event("repeated");
        repeated.state = ActivityState::Succeeded;
        owner.observe(repeated, true);
    }
    assert_eq!(owner.retired.len(), 2);
    owner.observe(event("first"), true);
    assert!(!owner.has_active());
}
