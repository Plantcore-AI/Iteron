use super::*;

fn pending(generation: u64, capacity: usize) -> PendingRequests {
    PendingRequests::with_capacity(generation, capacity).unwrap()
}

#[test]
fn construction_and_admission_have_hard_bounds() {
    assert_eq!(
        PendingRequests::with_capacity(7, 0).unwrap_err(),
        LspError::InvalidPendingCapacity {
            value: 0,
            max: MAX_IN_FLIGHT
        }
    );
    assert_eq!(
        PendingRequests::with_capacity(7, MAX_IN_FLIGHT + 1).unwrap_err(),
        LspError::InvalidPendingCapacity {
            value: MAX_IN_FLIGHT + 1,
            max: MAX_IN_FLIGHT
        }
    );

    let mut pending = pending(7, 2);
    let first = pending.issue("definition", 0, 1_000).unwrap();
    let second = pending.issue("hover", 0, 1_000).unwrap();
    assert_eq!((first.id, second.id), (1, 2));
    assert_eq!(
        pending.issue("references", 0, 1_000),
        Err(LspError::Backpressure { limit: 2 })
    );
    assert_eq!(pending.in_flight(), 2);
    assert_eq!(pending.rejected(), 1);
}

#[test]
fn ids_are_monotonic_and_never_reused_after_retirement() {
    let mut pending = PendingRequests::new(41);
    let first = pending.issue("definition", 0, 1_000).unwrap();
    assert_eq!(
        pending.resolve(41, first.id, 1).unwrap(),
        ReplyDisposition::Accepted(CompletedRequest { correlation: first })
    );
    let second = pending.issue("hover", 1, 1_000).unwrap();
    assert_eq!(second.id, first.id + 1);
    assert_eq!(second.generation, 41);
    assert_eq!(second.method, "hover");
}

#[test]
fn a_duplicate_reply_is_typed_and_cannot_resolve_a_new_request() {
    let mut pending = PendingRequests::new(9);
    let first = pending.issue("definition", 0, 100).unwrap();
    assert_eq!(
        pending.resolve(9, first.id, 1).unwrap(),
        ReplyDisposition::Accepted(CompletedRequest { correlation: first })
    );
    let second = pending.issue("hover", 1, 100).unwrap();

    assert_eq!(
        pending.resolve(9, first.id, 2).unwrap(),
        ReplyDisposition::Duplicate(first)
    );
    assert_eq!(pending.in_flight(), 1);
    assert_eq!(
        pending.resolve(9, second.id, 2).unwrap(),
        ReplyDisposition::Accepted(CompletedRequest {
            correlation: second
        })
    );
}

#[test]
fn an_old_generation_cannot_alias_the_same_wire_id_in_a_new_generation() {
    let mut old = PendingRequests::new(10);
    let old_request = old.issue("definition", 0, 100).unwrap();
    let mut current = PendingRequests::new(11);
    let current_request = current.issue("hover", 0, 100).unwrap();
    assert_eq!(old_request.id, current_request.id);

    assert_eq!(
        current.resolve(10, old_request.id, 1).unwrap(),
        ReplyDisposition::ForeignGeneration {
            expected: 11,
            received: 10,
            id: old_request.id
        }
    );
    assert_eq!(current.in_flight(), 1);
    assert_eq!(
        current.resolve(11, current_request.id, 1).unwrap(),
        ReplyDisposition::Accepted(CompletedRequest {
            correlation: current_request
        })
    );
}

#[test]
fn request_deadlines_cannot_be_disabled_or_made_effectively_infinite() {
    let mut pending = PendingRequests::new(1);
    assert!(matches!(
        pending.issue("hover", 0, 0),
        Err(LspError::InvalidTimeout {
            kind: "request",
            ..
        })
    ));
    assert!(matches!(
        pending.issue("hover", 0, MAX_REQUEST_TIMEOUT_MS + 1),
        Err(LspError::InvalidTimeout {
            kind: "request",
            ..
        })
    ));
    assert_eq!(pending.rejected(), 2);
}

#[test]
fn expiry_reports_total_elapsed_time_and_stable_id_order() {
    let mut pending = PendingRequests::new(4);
    let first = pending.issue("definition", 1_000, 500).unwrap();
    let second = pending.issue("hover", 1_000, 500).unwrap();
    assert!(pending.expire(1_499).unwrap().is_empty());
    assert_eq!(
        pending.expire(1_500).unwrap(),
        vec![
            Expired {
                generation: 4,
                id: first.id,
                method: "definition",
                elapsed_ms: 500
            },
            Expired {
                generation: 4,
                id: second.id,
                method: "hover",
                elapsed_ms: 500
            }
        ]
    );
    assert_eq!(pending.timed_out(), 2);
    assert!(matches!(
        pending.resolve(4, first.id, 1_500).unwrap(),
        ReplyDisposition::Late(Expired { id, .. }) if id == first.id
    ));
}

#[test]
fn cancellation_remains_charged_until_response_or_expiry() {
    let mut pending = pending(15, 2);
    let first = pending.issue("hover", 0, 10).unwrap();
    let second = pending.issue("definition", 0, 20).unwrap();
    assert_eq!(
        pending.cancel(15, first.id, 1).unwrap(),
        CancelDisposition::CancellationRequested(first)
    );
    assert_eq!(
        pending.cancel(15, second.id, 1).unwrap(),
        CancelDisposition::CancellationRequested(second)
    );
    assert_eq!(pending.in_flight(), 2);
    assert_eq!(pending.cancelling(), 2);
    assert_eq!(
        pending.issue("references", 1, 100),
        Err(LspError::Backpressure { limit: 2 })
    );

    assert_eq!(
        pending.resolve(15, first.id, 2).unwrap(),
        ReplyDisposition::Cancelled(first)
    );
    let replacement = pending.issue("references", 2, 100).unwrap();
    assert!(
        replacement.id > second.id,
        "a cancelled id must never be reused"
    );
    assert_eq!(pending.expire(20).unwrap()[0].id, second.id);
    assert_eq!(pending.cancelled(), 2);
}

#[test]
fn repeated_cancel_is_idempotent_and_deadline_is_enforced_without_sweep() {
    let mut pending = PendingRequests::new(2);
    let request = pending.issue("hover", 0, 10).unwrap();
    assert_eq!(
        pending.cancel(2, request.id, 1).unwrap(),
        CancelDisposition::CancellationRequested(request)
    );
    assert_eq!(
        pending.cancel(2, request.id, 2).unwrap(),
        CancelDisposition::AlreadyCancelling(request)
    );
    assert_eq!(pending.cancelled(), 1);
    assert_eq!(
        pending.resolve(2, request.id, 10).unwrap(),
        ReplyDisposition::Late(Expired {
            generation: 2,
            id: request.id,
            method: "hover",
            elapsed_ms: 10
        })
    );
    assert_eq!(pending.timed_out(), 1);
}

#[test]
fn a_regressed_clock_is_typed_and_does_not_expire_early() {
    let mut pending = PendingRequests::new(1);
    pending.issue("hover", 100, 50).unwrap();
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
fn deadline_overflow_is_typed_and_does_not_admit_a_shortened_request() {
    let mut pending = PendingRequests::new(1);
    assert_eq!(
        pending.issue("hover", u64::MAX - 1, MAX_REQUEST_TIMEOUT_MS),
        Err(LspError::TimeOverflow {
            operation: "request deadline",
            base_ms: u64::MAX - 1,
            delta_ms: MAX_REQUEST_TIMEOUT_MS
        })
    );
    assert_eq!(pending.in_flight(), 0);
    assert_eq!(pending.rejected(), 1);
}

#[test]
fn allocated_wire_ids_never_exceed_the_signed_lsp_integer_domain() {
    let mut pending = PendingRequests::new(1);
    pending.next_id = Some(MAX_JSONRPC_NUMERIC_ID);
    let last = pending.issue("hover", 0, 10).unwrap();
    assert_eq!(last.id, MAX_JSONRPC_NUMERIC_ID);
    assert_eq!(last.wire_id(), serde_json::json!(i32::MAX));
    pending.resolve(1, last.id, 1).unwrap();
    assert_eq!(
        pending.issue("hover", 1, 10),
        Err(LspError::RequestIdExhausted { generation: 1 })
    );
}

#[test]
fn tombstones_are_bounded_but_old_ids_remain_unusable() {
    let mut pending = pending(3, 1);
    let first = pending.issue("one", 0, 10).unwrap();
    assert!(matches!(
        pending.resolve(3, first.id, 1).unwrap(),
        ReplyDisposition::Accepted(_)
    ));
    let second = pending.issue("two", 1, 10).unwrap();
    pending.resolve(3, second.id, 2).unwrap();

    assert_eq!(
        pending.resolve(3, first.id, 2).unwrap(),
        ReplyDisposition::Retired {
            generation: 3,
            id: first.id
        }
    );
}
