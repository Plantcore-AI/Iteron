//! The transport seam: what "an MCP connection" means independently of how bytes move.
//!
//! Until now `McpClient` *was* the transport. Its `connect` takes a command and argv, its state is
//! a `ChildStdin`/`ChildStdout` pair, and every caller above it — discovery, the tool catalog, the
//! supervisor, reconnect — reaches an MCP server only by owning a child process. That is a fine
//! design for one transport and an impossible one for two: adding HTTP by widening `McpClient`
//! would put a URL, a bearer credential, and a process id in the same struct, and every existing
//! caller would have to learn which half is inhabited.
//!
//! So the seam is drawn at the *narrowest true* interface. Everything above the transport speaks
//! JSON-RPC — a method name, a params object, and either one correlated response or nothing. That
//! is the whole contract, and it is transport-free:
//!
//! - **framing** differs (newline-delimited on a pipe; `application/json` or `text/event-stream`
//!   over HTTP) and stays below the seam,
//! - **correlation** differs (skip interleaved notifications on a shared pipe; match within one
//!   response body over HTTP) and stays below the seam,
//! - **certainty** — whether a failed `tools/call` may already have taken effect — is the one
//!   thing that must cross the seam, because the scheduler's `McpToolOutcome::Unknown` exists
//!   precisely to carry it. The HTTP side derives it from the status code
//!   ([`crate::http::effect_certainty`]); the stdio side derives it from whether the pipe write
//!   had begun ([`crate::evidence::DispatchClock`]).
//!
//! `McpWire` returns boxed futures rather than using `async fn` in trait position. That is
//! deliberate and not a stylistic accident: the supervisor stores transports behind a trait object
//! so a session can hold a heterogeneous set of servers, and an `async fn` in a trait is not
//! dyn-compatible. Boxing here costs one allocation per JSON-RPC call, against a syscall and a
//! network round trip.

use crate::{McpError, client::McpClient};
use serde_json::Value;
use std::{future::Future, pin::Pin};

/// A boxed, `Send` future — the dyn-compatible shape every [`McpWire`] method returns.
pub type McpFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, McpError>> + Send + 'a>>;

/// Which transport carries one MCP server binding.
///
/// The wire names are the vocabulary of the `mcp_transport_selection` tunable
/// (`crates/tunables/src/value_schemas/appendix/third.rs`), whose domain is `enum[stdio]` today.
/// Widening that domain is the *last* step of admitting HTTP, not the first: a domain that offers
/// a value this binary cannot honour turns a configuration typo into a silent stdio fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum McpTransportKind {
    /// A supervised child process, newline-delimited JSON-RPC on its stdin/stdout.
    Stdio,
    /// An HTTP endpoint, JSON-RPC over `application/json` or `text/event-stream`.
    Http,
}

impl McpTransportKind {
    /// The tunable-domain token for this transport.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Stdio => "stdio",
            Self::Http => "http",
        }
    }

    /// Whether this binary can actually select the transport.
    pub const fn is_selectable(self) -> bool {
        matches!(self, Self::Stdio | Self::Http)
    }

    /// Parse a transport token from operator configuration, refusing anything this binary cannot
    /// honour. An unknown token and an unavailable-but-known token are deliberately different
    /// errors: the first is a typo, the second is a build that does not carry the client.
    pub fn select(token: &str) -> Result<Self, McpError> {
        let kind = match token {
            "stdio" => Self::Stdio,
            "http" => Self::Http,
            _ => {
                return Err(McpError::InvalidEndpoint {
                    field: "transport",
                    limit: 0,
                });
            }
        };
        Ok(kind)
    }
}

/// One MCP transport: correlated JSON-RPC requests and fire-and-forget notifications.
///
/// Implementations own their own deadline. A caller that needs a shorter bound composes one
/// outside; a caller that supplies none must still not be able to wait forever.
pub trait McpWire: Send + Sync {
    fn transport_kind(&self) -> McpTransportKind;

    /// Send one request and resolve with the correlated JSON-RPC `result`, or a typed failure.
    fn send_request<'a>(&'a self, method: &'a str, params: Value) -> McpFuture<'a, Value>;

    /// Send one notification. Success means the peer accepted the bytes, never that it acted.
    fn send_notification<'a>(&'a self, method: &'a str, params: Value) -> McpFuture<'a, ()>;
}

impl McpWire for McpClient {
    fn transport_kind(&self) -> McpTransportKind {
        McpTransportKind::Stdio
    }

    fn send_request<'a>(&'a self, method: &'a str, params: Value) -> McpFuture<'a, Value> {
        Box::pin(self.call(method, params))
    }

    fn send_notification<'a>(&'a self, method: &'a str, params: Value) -> McpFuture<'a, ()> {
        Box::pin(async move {
            // The inherent notifier is deliberately unbounded so the handshake can run inside one
            // outer budget. Reaching it through the seam, where no outer budget is implied, would
            // otherwise let a peer that never drains its pipe block a caller forever.
            match tokio::time::timeout(
                self.request_timeout(),
                self.notify_unbounded_by_outer_deadline(method, params),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err(McpError::Deadline {
                    operation: format!("notify `{method}`"),
                }),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_tokens_round_trip_through_the_tunable_vocabulary() {
        assert_eq!(McpTransportKind::Stdio.wire_name(), "stdio");
        assert_eq!(McpTransportKind::Http.wire_name(), "http");
        assert_eq!(
            McpTransportKind::select("stdio").unwrap(),
            McpTransportKind::Stdio
        );
    }

    #[test]
    fn both_shipped_transports_are_selectable_and_typos_fail_closed() {
        assert!(McpTransportKind::Http.is_selectable());
        assert_eq!(
            McpTransportKind::select("http").unwrap(),
            McpTransportKind::Http
        );
        assert!(matches!(
            McpTransportKind::select("htp"),
            Err(McpError::InvalidEndpoint { .. })
        ));
        assert!(matches!(
            McpTransportKind::select(""),
            Err(McpError::InvalidEndpoint { .. })
        ));
    }

    #[test]
    fn the_selectable_set_is_exactly_the_published_tunable_domain() {
        let selectable: Vec<&str> = [McpTransportKind::Stdio, McpTransportKind::Http]
            .into_iter()
            .filter(|kind| kind.is_selectable())
            .map(McpTransportKind::wire_name)
            .collect();
        assert_eq!(selectable, ["stdio", "http"]);
    }

    #[test]
    fn the_stdio_client_satisfies_the_seam_as_a_trait_object() {
        fn assert_dyn_compatible(_: Option<&dyn McpWire>) {}
        // A compile-time assertion: the seam must stay dyn-compatible, because a session holds a
        // heterogeneous set of servers behind one collection.
        assert_dyn_compatible(None::<&McpClient>.map(|client| client as &dyn McpWire));
    }
}
