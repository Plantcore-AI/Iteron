//! The TUI's versioned client handle to the runtime App Server.
//!
//! Historically the interactive TUI *co-composed the runtime*: it held the kernel `Agent` and
//! stuffed bare `Op` values straight onto the submission queue, implicitly assuming the peer
//! spoke its own in-process protocol version. That is not what a client of a versioned App
//! Server does. When the runtime is later extracted behind a transport (ADR-010, the planned
//! App Server boundary), a frontend that never negotiated a version would keep stamping
//! submissions the peer is free to reject mid-session.
//!
//! [`AppServerClient`] is that missing seam. It completes a version handshake against the
//! server's advertised SQ/EQ [`PROTOCOL_VERSION`](core_protocol::PROTOCOL_VERSION) *before* it
//! will accept any submission, refuses to attach to a peer speaking a different version, and
//! stamps every submission it forwards with the single negotiated version. The frontend talks
//! to the runtime strictly as a versioned client rather than as a co-author of its wire.

use core_protocol::{Op, PROTOCOL_VERSION, ProtocolVersionError, SqEnvelope};
use tokio::sync::mpsc::UnboundedSender;

/// A version-negotiated client of the runtime App Server.
///
/// The client cannot be constructed without a completed handshake, so a version-skewed
/// frontend can never obtain a handle it would use to push envelopes the server rejects.
#[derive(Debug, Clone)]
pub(crate) struct AppServerClient {
    submissions: UnboundedSender<SqEnvelope>,
    negotiated_version: u32,
}

/// A submission could not be delivered because the runtime App Server is gone.
///
/// This is the client-side view of a closed submission queue: the run task that owned the
/// receiver has ended, so there is no longer a server to accept the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Disconnected;

impl std::fmt::Display for Disconnected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "the App Server submission queue is closed; the runtime is no longer reachable",
        )
    }
}

impl std::error::Error for Disconnected {}

impl AppServerClient {
    /// Complete a versioned handshake with a server advertising `server_version`.
    ///
    /// The client refuses to attach to a peer speaking a different SQ/EQ version: skew is
    /// surfaced up front as a [`ProtocolVersionError`] instead of being discovered one
    /// rejected submission at a time. On success every later submission is stamped with the
    /// negotiated version.
    ///
    /// The in-process frontend uses [`current`](Self::current); this skew-refusing constructor
    /// is the entry point for the future extracted transport and is exercised by the tests.
    #[allow(dead_code)]
    pub(crate) fn connect(
        server_version: u32,
        submissions: UnboundedSender<SqEnvelope>,
    ) -> Result<Self, ProtocolVersionError> {
        if server_version != PROTOCOL_VERSION {
            return Err(ProtocolVersionError {
                expected: PROTOCOL_VERSION,
                actual: server_version,
            });
        }
        Ok(Self {
            submissions,
            negotiated_version: server_version,
        })
    }

    /// Attach to the in-process runtime, which by construction speaks the frontend's own
    /// [`PROTOCOL_VERSION`](core_protocol::PROTOCOL_VERSION).
    ///
    /// This is the handshake for today's modular monolith. Extracting the App Server over a
    /// transport replaces it with [`connect`](Self::connect) fed the version read off the
    /// live connection.
    pub(crate) fn current(submissions: UnboundedSender<SqEnvelope>) -> Self {
        Self {
            submissions,
            negotiated_version: PROTOCOL_VERSION,
        }
    }

    /// The protocol version agreed during the handshake and stamped on every submission.
    #[allow(dead_code)]
    pub(crate) fn negotiated_version(&self) -> u32 {
        self.negotiated_version
    }

    /// Submit one operation to the runtime, stamped with the negotiated protocol version.
    ///
    /// Returns [`Disconnected`] when the server side of the queue has been dropped, letting
    /// the frontend preserve the operator's intent instead of losing it silently.
    pub(crate) fn submit(&self, op: Op) -> Result<(), Disconnected> {
        self.submissions
            .send(SqEnvelope::with_version(self.negotiated_version, op))
            .map_err(|_| Disconnected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc::error::TryRecvError;
    use tokio::sync::mpsc::unbounded_channel;

    #[test]
    fn matching_version_connects_and_stamps_every_submission() {
        let (tx, mut rx) = unbounded_channel::<SqEnvelope>();
        let client = AppServerClient::connect(PROTOCOL_VERSION, tx)
            .expect("the current server version accepts the handshake");
        assert_eq!(client.negotiated_version(), PROTOCOL_VERSION);

        client
            .submit(Op::Interrupt)
            .expect("submit reaches the queue");
        let envelope = rx.try_recv().expect("submission is queued");
        assert_eq!(envelope.protocol_version, PROTOCOL_VERSION);
        assert!(matches!(envelope.into_current(), Ok(Op::Interrupt)));
        assert_eq!(rx.try_recv().unwrap_err(), TryRecvError::Empty);
    }

    #[test]
    fn version_skew_is_refused_up_front() {
        let (tx, mut rx) = unbounded_channel::<SqEnvelope>();
        let err = AppServerClient::connect(PROTOCOL_VERSION + 1, tx.clone())
            .expect_err("a peer on a different version must be refused");
        assert_eq!(err.expected, PROTOCOL_VERSION);
        assert_eq!(err.actual, PROTOCOL_VERSION + 1);
        assert_eq!(rx.try_recv().unwrap_err(), TryRecvError::Empty);
        assert!(AppServerClient::connect(PROTOCOL_VERSION - 1, tx).is_err());
    }

    #[test]
    fn submit_reports_a_closed_queue() {
        let (tx, rx) = unbounded_channel::<SqEnvelope>();
        let client = AppServerClient::current(tx);
        drop(rx);
        assert_eq!(client.submit(Op::Drain), Err(Disconnected));
    }
}
