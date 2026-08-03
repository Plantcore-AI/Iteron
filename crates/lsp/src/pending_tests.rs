use super::*;

#[test]
fn construction_and_admission_have_hard_bounds() {
    assert_eq!(
        PendingRequests::with_capacity(0).unwrap_err(),
        LspError::InvalidPendingCapacity {
            value: 0,
            max: MAX_IN_FLIGHT
        }
    );
    assert_eq!(
        PendingRequests::with_capacity(MAX_IN_FLIGHT + 1).unwrap_err(),
        LspError::InvalidPendingCapacity {
            value: MAX_IN_FLIGHT + 1,
            max: MAX_IN_FLIGHT
        }
    );

    let mut pending = PendingRequests::with_capacity(2).unwrap();
    pending.issue(1, "definition", 0, 1_000).unwrap();
    pending.issue(2, "hover", 0, 1_000).unwrap();
    assert_eq!(
        pending.issue(3, "references", 0, 1_000),
        Err(LspError::Backpressure { limit: 2 })
    );
    assert_eq!(pending.in_flight(), 2);
    assert_eq!(pending.rejected(), 1);
}

#[test]
fn duplicate_ids_never_replace_a_live_waiter() {
    let mut pending = PendingRequests::with_capacity(1).unwrap();
    pending.issue(7, "original", 10, 100).unwrap();
    assert_eq!(
        pending.issue(7, "replacement", 10, 100),
        Err(LspError::DuplicateRequest { id: 7 })
    );
    let expired = pending.expire(110).unwrap();
    assert_eq!(expired[0].method, "original");
    assert_eq!(pending.rejected(), 1);
}

#[test]
fn request_deadlines_cannot_be_disabled_or_made_effectively_infinite() {
    let mut pending = PendingRequests::default();
    assert!(matches!(
        pending.issue(1, "hover", 0, 0),
        Err(LspError::InvalidTimeout {
            kind: "request",
            ..
        })
    ));
    assert!(matches!(
        pending.issue(2, "hover", 0, MAX_REQUEST_TIMEOUT_MS + 1),
        Err(LspError::InvalidTimeout {
            kind: "request",
            ..
        })
    ));
    assert_eq!(pending.rejected(), 2);
}

#[test]
fn expiry_reports_total_elapsed_time_at_and_after_the_deadline() {
    let mut pending = PendingRequests::default();
    pending.issue(1, "definition", 1_000, 500).unwrap();
    assert!(pending.expire(1_499).unwrap().is_empty());
    assert_eq!(
        pending.expire(1_500).unwrap(),
        vec![Expired {
            id: 1,
            method: "definition",
            elapsed_ms: 500
        }]
    );

    pending.issue(2, "hover", 2_000, 10).unwrap();
    assert_eq!(pending.expire(2_100).unwrap()[0].elapsed_ms, 100);
    assert_eq!(pending.timed_out(), 2);
}

#[test]
fn late_replies_are_not_live_and_expiry_order_is_stable() {
    let mut pending = PendingRequests::default();
    for id in [30u64, 10, 20] {
        pending.issue(id, "hover", 0, 5).unwrap();
    }
    let ids: Vec<u64> = pending
        .expire(1_000)
        .unwrap()
        .into_iter()
        .map(|entry| entry.id)
        .collect();
    assert_eq!(ids, vec![10, 20, 30]);
    assert!(!pending.resolve(10));
}

#[test]
fn cancellation_is_counted_separately() {
    let mut pending = PendingRequests::default();
    pending.issue(1, "hover", 0, 1_000).unwrap();
    assert!(pending.cancel(1));
    assert!(!pending.cancel(1));
    assert_eq!(pending.cancelled(), 1);
    assert_eq!(pending.timed_out(), 0);
}

#[test]
fn a_regressed_clock_is_typed_and_does_not_expire_early() {
    let mut pending = PendingRequests::default();
    pending.issue(1, "hover", 100, 50).unwrap();
    assert_eq!(
        pending.expire(99),
        Err(LspError::ClockRegressed {
            previous_ms: 100,
            current_ms: 99
        })
    );
    assert_eq!(pending.in_flight(), 1);
    assert_eq!(pending.expire(150).unwrap().len(), 1);
}

#[test]
fn deadline_addition_saturates_without_panicking() {
    let mut pending = PendingRequests::default();
    pending
        .issue(1, "hover", u64::MAX - 1, MAX_REQUEST_TIMEOUT_MS)
        .unwrap();
    assert_eq!(pending.expire(u64::MAX).unwrap()[0].elapsed_ms, 1);
}
