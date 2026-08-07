//! The production Streamable HTTP/SSE MCP transport.
//!
//! # Why this exists as code and not as a document
//!
//! The socket adapter is deliberately smaller than the decision core. The hard parts are:
//!
//! - deciding what an endpoint URL is allowed to be, before a credential is ever attached to one,
//! - deciding how a bearer credential reaches a request without becoming printable,
//! - re-deriving JSON-RPC message boundaries from an event stream, under ceilings,
//! - deciding, from a status code, whether a failed `tools/call` may already have taken effect.
//!
//! Those decisions remain testable through [`McpHttpExchange`], while [`ReqwestMcpExchange`] is the
//! admitted production adapter. Redirects and implicit retries are disabled and response bodies
//! remain streaming, so the framing ceilings govern the real network path.
//!
//! # The transport, end to end
//!
//! One MCP request is one HTTP request:
//!
//! ```text
//!   POST {endpoint}
//!   accept: application/json, text/event-stream
//!   content-type: application/json
//!   mcp-protocol-version: {negotiated revision}
//!   authorization: Bearer …        (only when the credential is Fresh)
//!   mcp-session-id: …              (only after the server issued one)
//!
//!   {"jsonrpc":"2.0","id":7,"method":"tools/call","params":{…}}
//! ```
//!
//! and the response is one of exactly three things:
//!
//! | response | meaning | handled by |
//! |---|---|---|
//! | `200` + `application/json` | one JSON-RPC message | [`sse::read_json_response`] |
//! | `200` + `text/event-stream` | a stream of JSON-RPC messages, one per SSE event | [`sse::read_matching_sse_response`] |
//! | `202`/`204`, empty | a notification was accepted | [`McpHttpDisposition::Accepted`] |
//!
//! Anything else is classified by [`classify`] and never guessed at.
//!
//! # The five decisions that are not obvious
//!
//! **1. Plaintext HTTP is admissible only to loopback.** Not "discouraged" — refused at parse
//! time ([`McpHttpEndpoint::parse`]). A bearer token on a plaintext non-loopback hop is a
//! credential handed to every device on the path, and the failure is silent: the transport works
//! perfectly, which is exactly why nobody notices. Loopback is carved out because it is the real
//! development case and the credential does not leave the host.
//!
//! **2. A URL never carries the credential.** `https://user:pass@host/` parses in most URL
//! libraries and would put a secret in a config file, in `Debug` output, and in every error that
//! echoes the endpoint. Userinfo is rejected outright; credentials arrive only through
//! [`crate::token::Token`], which cannot be printed at all.
//!
//! **3. The endpoint is an authority boundary, so redirects are answered, not followed.** A `3xx`
//! becomes [`crate::McpError::HttpRedirectRefused`]. Following one would replay the bearer token and the
//! request body to a host the operator never configured, chosen by the peer — the same rule
//! `crates/provider/src/catalog.rs` already applies to model providers.
//!
//! **4. Operator configuration names extra headers; it does not contain them.** Exactly as
//! `McpLaunchConfig::with_sensitive_env_names` does for the process transport, an
//! [`McpHttpHeaderPolicy`] holds header *names* whose values are resolved from the environment at
//! dispatch. Reserved names — `authorization`, `mcp-session-id`, `content-type`, `accept`, and the
//! hop-by-hop set — are refused, so operator text cannot overwrite the credential or the framing
//! contract it is layered on.
//!
//! **5. Certainty is derived from the status code, not from whether an error occurred.** This is
//! the axis the rest of the runtime already has: `McpToolOutcome::Unknown` exists because a remote
//! effect may have been applied before the failure. Over a pipe, "did the write begin" is the best
//! available proxy. Over HTTP the answer is much sharper and often *worse*: a `500` means the
//! server received, parsed, and dispatched the call and then failed — the tool may well have run.
//! [`effect_certainty`] encodes that, and `503` and `429` are separated out precisely because they
//! are the two common statuses that promise the request was *not* served.
//!
//! # Deliberate boundary
//!
//! - **No resumability.** The `Last-Event-ID` replay of the streamable-HTTP revision needs server
//!   state and a redelivery contract; [`sse::SseEvent`] retains the `id` field so the decoder does
//!   not have to change when that lands, but nothing acts on it yet.
//! - **No implicit elicitation.** A caller must install a typed [`crate::McpElicitationHandler`]
//!   before form elicitation is advertised. Noninteractive clients advertise nothing and answer an
//!   unsolicited request with `Method not found`.

mod endpoint;
mod port;
mod reqwest_exchange;
pub mod sse;
mod status;
mod wire;

pub use endpoint::{
    MAX_MCP_HTTP_HEADER_NAME_BYTES, MAX_MCP_HTTP_HEADERS, MAX_MCP_HTTP_HOST_BYTES,
    MAX_MCP_HTTP_PATH_BYTES, MAX_MCP_HTTP_URL_BYTES, McpHttpEndpoint, McpHttpHeaderPolicy,
    McpHttpScheme, RESERVED_HEADER_NAMES, validate_header_name,
};
pub use port::{
    MAX_MCP_SESSION_ID_BYTES, MCP_HTTP_ACCEPT, MCP_JSON_MEDIA_TYPE, MCP_SSE_MEDIA_TYPE,
    McpHeaderValue, McpHttpExchange, McpHttpRequest, McpHttpResponse, McpHttpResponseHead,
    McpSessionId, build_post,
};
pub use reqwest_exchange::ReqwestMcpExchange;
pub use status::{
    McpEffectCertainty, McpHttpDisposition, classify, effect_certainty, parse_media_type,
    parse_retry_after,
};
pub use wire::{McpHttpWire, NowSecs};
