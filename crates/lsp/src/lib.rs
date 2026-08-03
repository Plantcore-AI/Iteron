//! Language-server lifecycle: framing, session state, document versions, in-flight requests.
//!
//! This crate is the protocol/state substrate for the *pure* halves of BR-3 and BR-4. It owns no
//! process and performs no spawn, so it stays outside the effect boundary the kernel brokers
//! (conformance N5). A future driver must supply the supervised transport, process status, clock,
//! request correlation, and effect-boundary freshness recheck; this crate does not claim that
//! integration or complete LSP lifecycle support.
//!
//! The bounds are not decoration. A language server is an untrusted peer that shares a workspace
//! with the agent: it can emit an unbounded diagnostic storm, answer nothing, or die mid-frame.
//! Each of those is a typed outcome below, and each drop is counted rather than silently absorbed.

pub mod documents;
pub mod framing;
mod headers;
pub mod intel;
pub mod lifecycle;
pub mod pending;

/// Supervisor-assigned identity of one language-server process/transport lifetime.
///
/// Readers, pending requests, document state, and lifecycle state must all carry the epoch they
/// were created for. Requiring this newtype at ingress keeps delayed work from being silently
/// relabelled as belonging to the current server after a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ServerEpoch(u64);

impl ServerEpoch {
    /// Mint an epoch at the process supervisor boundary. Supervisors must never reuse a generation
    /// for another process lifetime.
    pub const fn new(generation: u64) -> Self {
        Self(generation)
    }

    pub const fn generation(self) -> u64 {
        self.0
    }
}

/// A single header block may not exceed this. Real servers send two short headers; anything
/// larger is a peer trying to make us buffer before we have seen a `Content-Length`.
pub const MAX_HEADER_BYTES: usize = 8 * 1024;

/// Hard ceiling on one message body. Chosen well above a large `textDocument/publishDiagnostics`
/// payload and well below a size that would let one message exhaust the agent's memory.
pub const MAX_CONTENT_BYTES: usize = 16 * 1024 * 1024;

/// A frame is scanned with a streaming deserializer before any `serde_json::Value` tree is built.
/// These limits bound the DOM overhead that a compact but extremely wide JSON body could induce.
pub const MAX_MESSAGE_JSON_NODES: usize = 96 * 1024;
pub const MAX_MESSAGE_JSON_STRING_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_MESSAGE_JSON_OBJECT_MEMBERS: usize = 64 * 1024;
pub const MAX_MESSAGE_JSON_ARRAY_ITEMS: usize = 64 * 1024;
pub const MAX_MESSAGE_JSON_DEPTH: usize = 64;

/// How many requests may be in flight before the caller must wait. Backpressure is a bound on
/// *our* memory, so it is enforced on admission rather than by dropping an already-sent request.
pub const MAX_IN_FLIGHT: usize = 256;

/// JSON-RPC numeric ids use the interoperable signed LSP integer domain.
pub const MAX_JSONRPC_NUMERIC_ID: u32 = i32::MAX as u32;

/// A client never needs to keep every file in a repository open at once. This bound also caps the
/// URI and per-document bookkeeping retained after an untrusted server has replied.
pub const MAX_OPEN_DOCUMENTS: usize = 512;

/// URI bytes retained as a document-store key. LSP uses UTF-8 JSON strings, so this is a byte
/// bound rather than a character count.
pub const MAX_DOCUMENT_URI_BYTES: usize = 4 * 1024;

/// Diagnostics are bounded on all three useful axes: top-level count, encoded bytes, and JSON
/// structure. The store also has a cross-document byte ceiling below.
pub const MAX_DIAGNOSTICS_PER_DOCUMENT: usize = 1_024;
pub const MAX_DIAGNOSTIC_BYTES_PER_DOCUMENT: usize = 1024 * 1024;
pub const MAX_DIAGNOSTIC_BYTES_TOTAL: usize = 16 * 1024 * 1024;
pub const MAX_DIAGNOSTIC_JSON_NODES: usize = 32 * 1024;
pub const MAX_DIAGNOSTIC_JSON_NODES_TOTAL: usize = 256 * 1024;
pub const MAX_DIAGNOSTIC_JSON_DEPTH: usize = 64;
pub const MAX_DIAGNOSTIC_MESSAGE_BYTES: usize = 64 * 1024;
pub const MAX_DIAGNOSTIC_SOURCE_BYTES: usize = 1024;
pub const MAX_DIAGNOSTIC_CODE_BYTES: usize = 4 * 1024;
pub const MAX_DIAGNOSTIC_RELATED_INFORMATION: usize = 64;
pub const MAX_DIAGNOSTIC_RELATED_MESSAGE_BYTES: usize = 16 * 1024;

/// LSP `uinteger` is bounded to 2^31-1 even though Rust's natural storage type is wider.
pub const MAX_LSP_POSITION: u32 = i32::MAX as u32;

/// Request deadlines are mandatory and cannot be configured into an effective infinity.
pub const MIN_REQUEST_TIMEOUT_MS: u64 = 1;
pub const MAX_REQUEST_TIMEOUT_MS: u64 = 120_000;

/// Framing reads have separate header and body deadlines. A timeout is terminal for that stream:
/// cancellation can leave a partial frame consumed, so the caller must tear down the session.
pub const MIN_READ_TIMEOUT_MS: u64 = 1;
pub const MAX_READ_TIMEOUT_MS: u64 = 120_000;
pub const DEFAULT_HEADER_READ_TIMEOUT_MS: u64 = 5_000;
pub const DEFAULT_BODY_READ_TIMEOUT_MS: u64 = 30_000;

/// Restart safety bounds. Strategy may choose a value inside these ceilings, but cannot remove the
/// ceiling or reset a crash budget after one lucky response.
pub const MAX_RESTART_ATTEMPTS: u32 = 8;
pub const MIN_RESTART_BACKOFF_MS: u64 = 1;
pub const MAX_RESTART_BACKOFF_MS: u64 = 60_000;
pub const HEALTHY_RESTART_RESET_AFTER_MS: u64 = 60_000;
pub const HEALTHY_RESTART_RESET_AFTER_SUCCESSES: u32 = 3;

/// How many locations one answer may carry into the agent's context. `references` on a common
/// symbol legitimately returns thousands; forwarding all of them would spend the whole context
/// window on one tool result. The excess is counted and reported, never silently dropped.
pub const MAX_LOCATIONS: usize = 200;
pub const MAX_LOCATION_INPUTS: usize = 4_096;

/// Hover output is context, not an arbitrary server-owned document. Both retained text and the
/// number of fragments inspected are capped and truncation remains observable.
pub const MAX_HOVER_BYTES: usize = 64 * 1024;
pub const MAX_HOVER_FRAGMENTS: usize = 256;

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
    #[error("JSON {dimension} envelope is {value} (limit {limit}) before DOM construction")]
    JsonEnvelopeExceeded {
        dimension: &'static str,
        value: usize,
        limit: usize,
    },
    #[error("{phase} read timed out after {limit_ms}ms; the stream must be discarded")]
    ReadTimeout { phase: &'static str, limit_ms: u64 },
    #[error("{kind} timeout {value_ms}ms is outside [{min_ms}, {max_ms}]ms")]
    InvalidTimeout {
        kind: &'static str,
        value_ms: u64,
        min_ms: u64,
        max_ms: u64,
    },
    #[error("too many requests in flight (limit {limit})")]
    Backpressure { limit: usize },
    #[error("pending-request capacity {value} is outside [1, {max}]")]
    InvalidPendingCapacity { value: usize, max: usize },
    #[error("request id {id} is already in flight")]
    DuplicateRequestId { id: u64 },
    #[error("request ids are exhausted for generation {generation}")]
    RequestIdExhausted { generation: u64 },
    #[error("the monotonic {kind} sequence is exhausted")]
    SequenceExhausted { kind: &'static str },
    #[error("{operation} timestamp overflow: {base_ms}ms + {delta_ms}ms")]
    TimeOverflow {
        operation: &'static str,
        base_ms: u64,
        delta_ms: u64,
    },
    #[error("request {id} timed out after {elapsed_ms}ms")]
    Timeout { id: u64, elapsed_ms: u64 },
    #[error("injected monotonic clock regressed from {previous_ms}ms to {current_ms}ms")]
    ClockRegressed { previous_ms: u64, current_ms: u64 },
    #[error("open-document limit reached ({limit})")]
    DocumentLimit { limit: usize },
    #[error("document URI is {value} bytes (limit {limit})")]
    DocumentUriTooLong { value: usize, limit: usize },
    #[error("document URI is empty, contains controls, or has no valid scheme")]
    InvalidDocumentUri,
    #[error("diagnostic count is {value} (per-document limit {limit})")]
    DiagnosticsTooMany { value: usize, limit: usize },
    #[error("diagnostic JSON is {value} bytes (per-document limit {limit})")]
    DiagnosticsTooLarge { value: usize, limit: usize },
    #[error("diagnostic JSON contains more than {limit} nodes")]
    DiagnosticsTooComplex { limit: usize },
    #[error("diagnostic JSON depth {value} exceeds {limit}")]
    DiagnosticsTooDeep { value: usize, limit: usize },
    #[error("diagnostic store would retain {value} bytes (global limit {limit})")]
    DiagnosticStoreFull { value: usize, limit: usize },
    #[error("diagnostic store would retain {value} JSON nodes (global limit {limit})")]
    DiagnosticNodeStoreFull { value: usize, limit: usize },
    #[error("diagnostic {index} is malformed: {reason}")]
    MalformedDiagnostic { index: usize, reason: &'static str },
    #[error("server is {state}, which cannot accept requests")]
    NotReady { state: &'static str },
    #[error("server epoch mismatch: expected generation {expected}, received {received}")]
    ServerEpochMismatch { expected: u64, received: u64 },
    #[error("restart backoff has {remaining_ms}ms remaining")]
    RestartBackoffActive { remaining_ms: u64 },
    #[error("server exhausted its restart budget after {attempts} attempts")]
    RestartBudgetExhausted { attempts: u32 },
    #[error("restart attempts {value} exceed {max}")]
    InvalidRestartAttempts { value: u32, max: u32 },
    #[error("{field} restart backoff {value_ms}ms is outside [{min_ms}, {max_ms}]ms")]
    InvalidRestartBackoff {
        field: &'static str,
        value_ms: u64,
        min_ms: u64,
        max_ms: u64,
    },
    #[error("base restart backoff {base_ms}ms exceeds maximum {max_ms}ms")]
    InvalidRestartBackoffOrder { base_ms: u64, max_ms: u64 },
    #[error("result was computed against version {issued}, document is now at {have}")]
    StaleResult { have: i32, issued: i32 },
    #[error("document {uri} is not open")]
    UnknownDocument { uri: String },
    #[error("document {uri} is desynchronized and requires a full-text resync")]
    DocumentDesynchronized { uri: String },
    #[error("diagnostics for {uri} have unknown or mismatched freshness and are not actionable")]
    DiagnosticsNotActionable { uri: String },
    #[error("location limit {value} is outside [1, {max}]")]
    InvalidLocationLimit { value: usize, max: usize },
    #[error("result claims future version {issued}, document is at {have}")]
    FutureResult { have: i32, issued: i32 },
    #[error("result was computed for document incarnation {issued}, current incarnation is {have}")]
    StaleDocumentIncarnation { have: u64, issued: u64 },
    #[error("result came from server generation {issued}, current generation is {have}")]
    StaleServerGeneration { have: u64, issued: u64 },
    #[error("position ({line}, {character}) exceeds the LSP ceiling {max}")]
    InvalidPosition { line: u32, character: u32, max: u32 },
    #[error("range start follows range end")]
    InvalidRange,
    #[error("completed request was not issued against a document snapshot")]
    ResultNotBoundToDocument,
}
