use super::*;
use crate::pending::{PendingRequests, ReplyDisposition};

fn ready(at_ms: u64) -> Session {
    let mut session = Session::new(RestartPolicy::default());
    session.apply(Event::InitializeSent, at_ms).unwrap();
    session.apply(Event::Initialized, at_ms).unwrap();
    session
}

#[test]
fn requests_are_refused_until_the_handshake_completes() {
    let mut session = Session::new(RestartPolicy::default());
    assert!(matches!(
        session.guard_request(),
        Err(LspError::NotReady {
            state: "uninitialized"
        })
    ));
    session.apply(Event::InitializeSent, 0).unwrap();
    assert!(matches!(
        session.guard_request(),
        Err(LspError::NotReady {
            state: "initializing"
        })
    ));
    session.apply(Event::Initialized, 1).unwrap();
    assert!(session.guard_request().is_ok());
}

#[test]
fn clean_shutdown_requires_acknowledged_shutdown_exit_and_eof() {
    let mut session = ready(0);
    session.apply(Event::ShutdownSent, 1).unwrap();
    session.apply(Event::ExitSent, 2).unwrap();
    assert_eq!(
        session.apply(Event::StreamClosed, 3).unwrap(),
        State::AwaitingExitStatus
    );
    assert_eq!(
        session.apply(Event::ProcessExitedSuccessfully, 4).unwrap(),
        State::Exited
    );
    assert!(matches!(
        session.plan_restart(4),
        Err(LspError::NotReady { state: "exited" })
    ));

    let mut reverse_order = ready(0);
    reverse_order.apply(Event::ShutdownSent, 1).unwrap();
    reverse_order.apply(Event::ExitSent, 2).unwrap();
    assert_eq!(
        reverse_order
            .apply(Event::ProcessExitedSuccessfully, 3)
            .unwrap(),
        State::AwaitingStreamClose
    );
    assert_eq!(
        reverse_order.apply(Event::StreamClosed, 4).unwrap(),
        State::Exited
    );
}

#[test]
fn eof_before_shutdown_acknowledgement_is_a_crash_not_a_clean_exit() {
    let mut session = ready(0);
    session.apply(Event::ShutdownSent, 1).unwrap();
    assert_eq!(
        session.apply(Event::StreamClosed, 2).unwrap(),
        State::Crashed
    );

    let mut failed_after_exit = ready(0);
    failed_after_exit.apply(Event::ShutdownSent, 1).unwrap();
    failed_after_exit.apply(Event::ExitSent, 2).unwrap();
    failed_after_exit.apply(Event::StreamClosed, 3).unwrap();
    assert_eq!(
        failed_after_exit.apply(Event::ProcessFailed, 4).unwrap(),
        State::Crashed
    );
}

#[test]
fn unexpected_stream_close_crashes_every_live_protocol_phase() {
    let mut uninitialized = Session::new(RestartPolicy::default());
    assert_eq!(
        uninitialized.apply(Event::StreamClosed, 0).unwrap(),
        State::Crashed
    );

    let mut initializing = Session::new(RestartPolicy::default());
    initializing.apply(Event::InitializeSent, 0).unwrap();
    assert_eq!(
        initializing.apply(Event::StreamClosed, 1).unwrap(),
        State::Crashed
    );

    let mut live = ready(0);
    assert_eq!(live.apply(Event::ProcessFailed, 1).unwrap(), State::Crashed);
}

#[test]
fn restart_budget_and_backoff_are_both_enforced() {
    let mut session = ready(0);
    let mut now = 1u64;
    let mut delays = Vec::new();
    for expected in [250u64, 500, 1_000] {
        session.apply(Event::ProcessFailed, now).unwrap();
        let delay = session.plan_restart(now).unwrap();
        delays.push(delay);
        assert_eq!(delay, expected);
        assert_eq!(session.state(), State::RestartBackoff);
        assert_eq!(
            session.apply(Event::InitializeSent, now + delay - 1),
            Err(LspError::RestartBackoffActive { remaining_ms: 1 })
        );
        now += delay;
        session.apply(Event::InitializeSent, now).unwrap();
        session.apply(Event::Initialized, now).unwrap();
        now += 1;
    }
    assert_eq!(delays, vec![250, 500, 1_000]);

    session.apply(Event::ProcessFailed, now).unwrap();
    assert_eq!(
        session.plan_restart(now),
        Err(LspError::RestartBudgetExhausted { attempts: 3 })
    );
}

#[test]
fn only_distinct_successful_requests_restore_restart_credit() {
    let mut session = ready(0);
    session.apply(Event::ProcessFailed, 1).unwrap();
    let delay = session.plan_restart(1).unwrap();
    session.apply(Event::InitializeSent, 1 + delay).unwrap();
    session.apply(Event::Initialized, 1 + delay).unwrap();
    let ready_at = 1 + delay;
    let mut pending = PendingRequests::new(1);
    let first_correlation = pending.issue("textDocument/hover", 0, 1_000).unwrap();
    let second_correlation = pending.issue("textDocument/definition", 0, 1_000).unwrap();
    let third_correlation = pending.issue("textDocument/references", 0, 1_000).unwrap();
    let ReplyDisposition::Accepted(first) = pending.resolve(1, first_correlation.id(), 1).unwrap()
    else {
        panic!("first request should complete");
    };
    let ReplyDisposition::Accepted(second) =
        pending.resolve(1, second_correlation.id(), 1).unwrap()
    else {
        panic!("second request should complete");
    };
    let ReplyDisposition::Accepted(third) = pending.resolve(1, third_correlation.id(), 1).unwrap()
    else {
        panic!("third request should complete");
    };

    assert!(!session.note_request_succeeded(first, ready_at + 1).unwrap());
    assert_eq!(session.restarts(), 1);
    assert!(
        !session
            .note_request_succeeded(first, ready_at + HEALTHY_RESTART_RESET_AFTER_MS)
            .unwrap()
    );
    assert_eq!(session.restarts(), 1, "a replayed success cannot heal");
    assert!(
        !session
            .note_request_succeeded(second, ready_at + HEALTHY_RESTART_RESET_AFTER_MS)
            .unwrap()
    );
    assert_eq!(session.restarts(), 1);
    assert!(
        session
            .note_request_succeeded(third, ready_at + HEALTHY_RESTART_RESET_AFTER_MS)
            .unwrap()
    );
    assert_eq!(session.restarts(), 0);

    let crashed_at = ready_at + HEALTHY_RESTART_RESET_AFTER_MS + 1;
    session.apply(Event::ProcessFailed, crashed_at).unwrap();
    let delay = session.plan_restart(crashed_at).unwrap();
    let next_ready = crashed_at + delay;
    session.apply(Event::InitializeSent, next_ready).unwrap();
    session.apply(Event::Initialized, next_ready).unwrap();
    for replay in [first, second, third] {
        assert!(
            !session
                .note_request_succeeded(replay, next_ready + HEALTHY_RESTART_RESET_AFTER_MS)
                .unwrap()
        );
    }
    assert_eq!(
        session.restarts(),
        1,
        "old completed requests cannot heal a new epoch"
    );
}

#[test]
fn restart_policy_rejects_unbounded_or_inverted_configuration() {
    let disabled = RestartPolicy::new(0, 1, 1).unwrap();
    let mut no_restart = Session::new(disabled);
    no_restart.apply(Event::InitializeSent, 0).unwrap();
    no_restart.apply(Event::Initialized, 0).unwrap();
    no_restart.apply(Event::ProcessFailed, 1).unwrap();
    assert_eq!(
        no_restart.plan_restart(1),
        Err(LspError::RestartBudgetExhausted { attempts: 0 })
    );
    assert!(matches!(
        RestartPolicy::new(MAX_RESTART_ATTEMPTS + 1, 1, 1),
        Err(LspError::InvalidRestartAttempts { .. })
    ));
    assert!(matches!(
        RestartPolicy::new(1, 0, 1),
        Err(LspError::InvalidRestartBackoff { field: "base", .. })
    ));
    assert_eq!(
        RestartPolicy::new(1, 10, 5),
        Err(LspError::InvalidRestartBackoffOrder {
            base_ms: 10,
            max_ms: 5
        })
    );
}

#[test]
fn backoff_math_saturates_and_clock_regression_is_typed() {
    let policy = RestartPolicy::default();
    assert_eq!(policy.backoff_ms(u32::MAX), policy.max_backoff_ms());

    let mut session = ready(100);
    assert_eq!(
        session.apply(Event::ProcessFailed, 99),
        Err(LspError::ClockRegressed {
            previous_ms: 100,
            current_ms: 99
        })
    );
    assert_eq!(session.state(), State::Ready);
}

#[test]
fn restart_backoff_deadline_overflow_is_typed_without_state_mutation() {
    let mut session = ready(u64::MAX - 2);
    session.apply(Event::ProcessFailed, u64::MAX - 1).unwrap();
    assert_eq!(
        session.plan_restart(u64::MAX - 1),
        Err(LspError::TimeOverflow {
            operation: "restart backoff",
            base_ms: u64::MAX - 1,
            delta_ms: RestartPolicy::default().base_backoff_ms()
        })
    );
    assert_eq!(session.state(), State::Crashed);
    assert_eq!(session.restarts(), 0);
}

#[test]
fn duplicate_or_out_of_order_peer_events_are_inert() {
    let mut session = ready(0);
    assert_eq!(session.apply(Event::Initialized, 1).unwrap(), State::Ready);
    assert_eq!(session.apply(Event::ExitSent, 2).unwrap(), State::Ready);
}
