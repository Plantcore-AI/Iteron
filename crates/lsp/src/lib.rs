//! Language-server lifecycle: framing, session state, document versions, in-flight requests.
//!
//! This crate is the *pure* half of BR-3. It owns no process and performs no spawn, so it stays
//! outside the effect boundary the kernel brokers (conformance N5). A driver supplies bytes and
//! clock readings; every decision here is a total function of the state and that input, which is
//! what makes a crashed server, a stale diagnostic and a timed-out request reproducible in a test
//! rather than only in production.
//!
//! The bounds are not decoration. A language server is an untrusted peer that shares a workspace
//! with the agent: it can emit an unbounded diagnostic storm, answer nothing, or die mid-frame.
//! Each of those is a typed outcome below, and each drop is counted rather than silently absorbed.

pub mod documents;
pub mod framing;
pub mod intel;
pub mod lifecycle;
pub mod pending;

/// A single header block may not exceed this. Real servers send two short headers; anything
/// larger is a peer trying to make us buffer before we have seen a `Content-Length`.
pub const MAX_HEADER_BYTES: usize = 8 * 1024;

/// Hard ceiling on one message body. Chosen well above a large `textDocument/publishDiagnostics`
/// payload and well below a size that would let one message exhaust the agent's memory.
pub const MAX_CONTENT_BYTES: usize = 16 * 1024 * 1024;

/// How many requests may be in flight before the caller must wait. Backpressure is a bound on
/// *our* memory, so it is enforced on admission rather than by dropping an already-sent request.
pub const MAX_IN_FLIGHT: usize = 256;

/// How many locations one answer may carry into the agent's context. `references` on a common
/// symbol legitimately returns thousands; forwarding all of them would spend the whole context
/// window on one tool result. The excess is counted and reported, never silently dropped.
pub const MAX_LOCATIONS: usize = 200;

/// Typed failures. Every variant is a decision some caller has to make, which is why none of them
/// collapse into a stringly-typed catch-all.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LspError {
    #[error("i/o: {0}")]
    Io(String),
    #[error("malformed header block: {0}")]
    Header(String),
    #[error("header block exceeded {limit} bytes")]
    HeaderTooLarge { limit: usize },
    #[error("Content-Length missing")]
    MissingContentLength,
    #[error("Content-Length {value} exceeds {limit} bytes")]
    ContentTooLarge { value: usize, limit: usize },
    #[error("server closed the stream mid-message")]
    TruncatedMessage,
    #[error("body was not valid utf-8")]
    InvalidUtf8,
    #[error("body was not valid json: {0}")]
    Json(String),
    #[error("too many requests in flight (limit {limit})")]
    Backpressure { limit: usize },
    #[error("request id {id} is already in flight")]
    DuplicateRequestId { id: u64 },
    #[error("request {id} timed out after {elapsed_ms}ms")]
    Timeout { id: u64, elapsed_ms: u64 },
    #[error("server is {state}, which cannot accept requests")]
    NotReady { state: &'static str },
    #[error("server exhausted its restart budget after {attempts} attempts")]
    RestartBudgetExhausted { attempts: u32 },
    #[error("result was computed against version {issued}, document is now at {have}")]
    StaleResult { have: i32, issued: i32 },
    #[error("document {uri} is not open")]
    UnknownDocument { uri: String },
}
