//! D10-01 — the TUI must talk to the runtime as a *versioned App Server client*, not by
//! co-composing the runtime and pushing bare submissions onto its queue.
//!
//! The frontend seam is `core_cli::app_server::AppServerClient`. A genuine versioned client
//! must, before it will forward anything:
//!
//!   1. complete a version handshake and refuse a peer whose SQ/EQ protocol version differs
//!      (skew is surfaced up front, not one rejected submission at a time);
//!   2. stamp every forwarded submission with the single negotiated protocol version, so the
//!      server can validate it with `SqEnvelope::into_current`;
//!   3. report a closed submission queue instead of losing the operator's intent silently.
//!
//! A frontend that co-composes the runtime — stuffing `Op` values straight onto the queue —
//! satisfies none of these: there is no handshake to refuse skew and no client type to test.
//! On the pre-fix base this test file's target does not exist, so it is RED; the fix adds the
//! versioned client and it turns GREEN.

use core_cli::{AppServerClient, Disconnected};
use core_protocol::{Op, PROTOCOL_VERSION, ProtocolVersionError, SqEnvelope};
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::mpsc::unbounded_channel;

#[test]
fn handshake_accepts_the_matching_server_version_and_stamps_submissions() {
    let (tx, mut rx) = unbounded_channel::<SqEnvelope>();
    let client = AppServerClient::connect(PROTOCOL_VERSION, tx)
        .expect("a server speaking the current version accepts the handshake");

    assert_eq!(
        client.negotiated_version(),
        PROTOCOL_VERSION,
        "the client stamps submissions with the negotiated version"
    );

    // Submissions are forwarded, in order, each wrapped in a version-stamped envelope the
    // server can validate — never a bare op assumed to be understood.
    client.submit(Op::Interrupt).expect("submit reaches the queue");
    client.submit(Op::Drain).expect("submit reaches the queue");

    let first = rx.try_recv().expect("first submission is queued");
    assert_eq!(first.protocol_version, PROTOCOL_VERSION);
    assert!(
        matches!(first.into_current(), Ok(Op::Interrupt)),
        "the server accepts the stamped envelope and recovers the op"
    );

    let second = rx.try_recv().expect("second submission is queued");
    assert_eq!(second.protocol_version, PROTOCOL_VERSION);
    assert!(matches!(second.into_current(), Ok(Op::Drain)));

    assert_eq!(
        rx.try_recv().unwrap_err(),
        TryRecvError::Empty,
        "exactly the two submitted ops were forwarded"
    );
}

#[test]
fn handshake_refuses_a_newer_server_version_and_forwards_nothing() {
    let (tx, mut rx) = unbounded_channel::<SqEnvelope>();
    // Hand the client a clone so the channel stays open and we can prove nothing was pushed.
    let err = AppServerClient::connect(PROTOCOL_VERSION + 1, tx.clone())
        .expect_err("a peer on a different version must be refused");

    assert_eq!(
        err,
        ProtocolVersionError {
            expected: PROTOCOL_VERSION,
            actual: PROTOCOL_VERSION + 1,
        }
    );
    assert_eq!(
        rx.try_recv().unwrap_err(),
        TryRecvError::Empty,
        "a refused handshake never forwards a submission"
    );
}

#[test]
fn handshake_refuses_an_older_server_version() {
    let (tx, _rx) = unbounded_channel::<SqEnvelope>();
    let err = AppServerClient::connect(PROTOCOL_VERSION - 1, tx)
        .expect_err("an older peer version must be refused too");
    assert_eq!(err.expected, PROTOCOL_VERSION);
    assert_eq!(err.actual, PROTOCOL_VERSION - 1);
}

#[test]
fn submit_reports_a_closed_queue_instead_of_losing_intent() {
    let (tx, rx) = unbounded_channel::<SqEnvelope>();
    let client = AppServerClient::current(tx);
    // The run task that owned the receiver has ended: the App Server is gone.
    drop(rx);
    assert_eq!(
        client.submit(Op::Drain),
        Err(Disconnected),
        "a disconnected runtime surfaces as an error the frontend can act on"
    );
}
