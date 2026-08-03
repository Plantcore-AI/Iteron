//! core-provider — the model seam.
//!
//! The load-bearing capability here is **mid-stream `tool_use` completion detection**: the
//! Anthropic streaming grammar guarantees a tool call's input is fully known at that block's
//! `content_block_stop`, strictly before `message_stop` (ADR-004). That is the flagship
//! signal the whole overlap story depends on, so the SSE parser is the heart of this crate
//! and is unit-tested against a recorded fixture (no network needed) — which doubles as the
//! reproducibility story: recorded model outputs replay exactly (ADR-006 promise (b)).
//!
//! Vertical slice: the Anthropic Messages API, streaming, with usage by cache class. The
//! cache-region linter (ADR-002 amendment) and the rate-limit governor (tail-latency
//! dossier) are present as an interface + a conservative default, with the richer policy
//! marked TODO against their ADRs.

use core_protocol::{Block, Message, StopReason, ToolSpec, ToolUse};
use std::time::{Duration, SystemTime};

pub mod anthropic;
pub mod catalog;
pub mod openai;
pub mod responses;
pub mod sse;
mod static_metadata;
mod usage;

pub use anthropic::Anthropic;
pub use catalog::{
    AccountAvailability, AccountProbe, AccountProbeResult, AdapterKind, ApiRoot,
    BalanceAvailability, BuiltinProvider, CatalogSnapshot, CatalogStrategy, Compatibility,
    ErrorProfile, ModelDescriptor, ModelFamily, ModelHealth, ProviderHealth, ProviderHealthStore,
    ProviderInstance, RawModel, Selectability, discover_catalog, probe_account,
};
pub use openai::OpenAiCompat;
pub use responses::OpenAiResponses;
pub use sse::{StreamItem, parse_sse_stream};
pub use static_metadata::{StaticModelCapabilities, StaticProviderMetadata};
pub use usage::{UsageIncompleteReason, UsageReport};

/// Maximum bytes retained from any non-success provider response. The response is dropped as
/// soon as the cap is crossed; provider-controlled error pages can therefore never create an
/// unbounded allocation in the agent.
pub const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;
const ERROR_BODY_TIMEOUT: Duration = Duration::from_secs(5);

/// Whether retrying the same request is safe from the provider's point of view. The scheduler
/// applies the separate, stricter rule that a committed stream is never retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDisposition {
    Never,
    Transient,
}

/// Whether one [`Provider::turn`] call can cross more than one transport dispatch boundary.
/// The kernel can journal exactly one attempt only for `Single`; opaque internal retries must be
/// disabled or exposed through a future per-attempt WAL callback before paid inference is safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderAttemptSemantics {
    Single,
    OpaqueInternalRetries,
}

/// The narrowest resource a normalized provider failure is known to affect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorScope {
    Account,
    Model,
    Request,
    Provider,
}

/// A failure may update either the provider account or just the selected model. Keeping those
/// cases separate prevents one inaccessible model from greying out a healthy account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvailabilityTransition {
    None,
    Account(AccountAvailability),
    ModelUnavailable,
}

/// Secret-safe, provider-independent failure metadata suitable for schedulers and user
/// interfaces. `public_message` is chosen from fixed text; provider bodies are never copied to
/// it because some gateways echo credentials or request payloads in errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedFailure {
    pub adapter: AdapterKind,
    pub error_profile: ErrorProfile,
    pub code: Option<String>,
    pub public_message: &'static str,
    pub scope: ErrorScope,
    pub availability: AvailabilityTransition,
    pub retry: RetryDisposition,
    pub request_id: Option<String>,
}

/// Metadata attached to a non-success HTTP response from a provider.
///
/// `ProviderError::Api` is retained for source compatibility with recorded providers and
/// downstream tests. Live HTTP providers use this richer form so a scheduler can respect a
/// server's `Retry-After` hint without parsing an error string.
#[derive(Clone, PartialEq, Eq)]
pub struct ApiResponseError {
    pub status: u16,
    /// Bounded diagnostic payload for controlled logs. Never shown by `Display`.
    pub body: String,
    pub body_truncated: bool,
    pub retry_after: Option<Duration>,
    pub normalized: Box<NormalizedFailure>,
}

impl std::fmt::Debug for ApiResponseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApiResponseError")
            .field("status", &self.status)
            .field("body", &"[REDACTED]")
            .field("body_bytes", &self.body.len())
            .field("body_truncated", &self.body_truncated)
            .field("retry_after", &self.retry_after)
            .field("normalized", &self.normalized)
            .finish()
    }
}

impl std::fmt::Display for ApiResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (HTTP {})",
            self.normalized.public_message, self.status
        )?;
        if let Some(code) = &self.normalized.code {
            write!(f, " [{code}]")?;
        }
        if let Some(request_id) = &self.normalized.request_id {
            write!(f, " (request {request_id})")?;
        }
        Ok(())
    }
}

/// A provider failure delivered *inside* an otherwise successful streaming HTTP response.
/// This is distinct from a decode error: the bytes were valid, and the provider deliberately
/// reported a typed failure. `status` is optional because streaming protocols do not always
/// carry an HTTP-equivalent status code.
#[derive(Clone, PartialEq, Eq)]
pub struct StreamError {
    pub provider: &'static str,
    pub code: Option<String>,
    /// Bounded provider diagnostic. Never shown by `Display`.
    pub message: String,
    pub status: Option<u16>,
    pub retry_after: Option<Duration>,
    pub normalized: Box<NormalizedFailure>,
}

impl std::fmt::Debug for StreamError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StreamError")
            .field("provider", &self.provider)
            .field("code", &self.normalized.code)
            .field("message", &"[REDACTED]")
            .field("message_bytes", &self.message.len())
            .field("status", &self.status)
            .field("retry_after", &self.retry_after)
            .field("normalized", &self.normalized)
            .finish()
    }
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} stream error: {}",
            self.provider, self.normalized.public_message
        )?;
        if let Some(code) = &self.normalized.code {
            write!(f, " ({code})")?;
        }
        if let Some(request_id) = &self.normalized.request_id {
            write!(f, " (request {request_id})")?;
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("http: {0}")]
    Http(String),
    /// Compatibility form used by deterministic test/replay providers. The body is deliberately
    /// omitted from Display just like the live structured form.
    #[error("provider API failure (HTTP {status})")]
    Api { status: u16, body: String },
    #[error("{0}")]
    ApiResponse(ApiResponseError),
    #[error("{0}")]
    Stream(StreamError),
    #[error("stream decode: {0}")]
    Decode(String),
    /// A completed, billable provider turn explicitly refused the request. This is a typed
    /// terminal condition, not a malformed response and never a successful completion.
    #[error("provider refused the turn")]
    Refusal,
    /// The adapter preserved a valid future stop code, but this runtime has no safe action for it.
    /// Display/Debug do not expose the provider-controlled raw code; callers may inspect the
    /// bounded carrier explicitly.
    #[error("provider returned an unrecognized stop reason")]
    UnknownStopReason {
        code: Box<core_protocol::StopReasonCode>,
    },
    #[error("logical run wall-clock deadline exhausted")]
    DeadlineExceeded,
    /// The runtime aborted this turn mid-stream in response to a cooperative interrupt (e.g.
    /// Ctrl-C). Synthesized by the kernel — like [`ProviderError::DeadlineExceeded`] — when the
    /// interrupt flag flips true while a provider stream is still in flight: the pending turn
    /// future is dropped, which closes the transport and stops decoding immediately. The turn
    /// produced no authoritative usage, so it is never retried.
    #[error("provider turn interrupted mid-stream")]
    Interrupted,
    #[error("no api key: set ANTHROPIC_API_KEY in the Core process environment")]
    NoKey,
    #[error("provider credential is missing for {provider}")]
    MissingCredential { provider: String },
    #[error("provider catalog is unsupported for {provider}: {reason}")]
    UnsupportedCatalog { provider: String, reason: String },
    #[error("invalid provider configuration: {0}")]
    Configuration(String),
    #[error("provider {provider} is blocked by known account state {availability:?}")]
    KnownAccountUnavailable {
        provider: String,
        availability: AccountAvailability,
    },
    #[error("model {model} is known unavailable for provider {provider}")]
    KnownModelUnavailable { provider: String, model: String },
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

impl ProviderError {
    /// HTTP-equivalent status when the provider supplied one. This accessor intentionally
    /// covers both the compatibility `Api` variant and the richer production variants.
    pub fn status(&self) -> Option<u16> {
        match self {
            ProviderError::Api { status, .. } => Some(*status),
            ProviderError::ApiResponse(error) => Some(error.status),
            ProviderError::Stream(error) => error.status,
            _ => None,
        }
    }

    /// Provider-requested retry delay, if one was supplied out of band or in band.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            ProviderError::ApiResponse(error) => error.retry_after,
            ProviderError::Stream(error) => error.retry_after,
            _ => None,
        }
    }

    /// Provider-normalized retry decision for a potentially billable inference request.
    ///
    /// `Transient` means the provider gave an unambiguous retry signal: an explicit rate-limit
    /// or overload status/code. It deliberately excludes generic transport failures, request
    /// timeouts, conflicts, and ordinary 5xx responses. Those failures can happen after a
    /// provider accepted work, and this protocol has no portable idempotency key with which to
    /// prove that replaying the request cannot duplicate work or charges. OpenAI-compatible
    /// gateways also commonly report exhausted billing quota as HTTP 429, so typed quota errors
    /// override the otherwise retryable status.
    pub fn retry_disposition(&self) -> RetryDisposition {
        match self {
            ProviderError::ApiResponse(error) => error.normalized.retry,
            ProviderError::Stream(error) => error.normalized.retry,
            ProviderError::Api { status, .. } => retry_for_status(*status),
            ProviderError::Http(_) => RetryDisposition::Never,
            ProviderError::Decode(_)
            | ProviderError::Refusal
            | ProviderError::UnknownStopReason { .. }
            | ProviderError::DeadlineExceeded
            | ProviderError::Interrupted
            | ProviderError::NoKey
            | ProviderError::MissingCredential { .. }
            | ProviderError::UnsupportedCatalog { .. }
            | ProviderError::Configuration(_)
            | ProviderError::KnownAccountUnavailable { .. }
            | ProviderError::KnownModelUnavailable { .. }
            | ProviderError::Json(_) => RetryDisposition::Never,
        }
    }

    /// Secret-safe normalized metadata when the provider supplied enough information.
    pub fn normalized(&self) -> Option<&NormalizedFailure> {
        match self {
            ProviderError::ApiResponse(error) => Some(&error.normalized),
            ProviderError::Stream(error) => Some(&error.normalized),
            _ => None,
        }
    }

    /// A secret-safe message for operator-facing status surfaces. Transport and decode errors
    /// can contain request URLs, cursors, echoed payload fragments, or parser diagnostics, so
    /// their raw `Display` text is reserved for controlled diagnostics.
    pub fn public_summary(&self) -> String {
        match self {
            ProviderError::ApiResponse(error) => error.to_string(),
            ProviderError::Stream(error) => error.to_string(),
            ProviderError::Api { status, .. } => {
                format!("provider API request failed (HTTP {status})")
            }
            ProviderError::Http(_) => "provider transport failed".into(),
            ProviderError::Decode(_) | ProviderError::Json(_) => {
                "provider response was invalid".into()
            }
            ProviderError::Refusal => "provider refused the request".into(),
            ProviderError::UnknownStopReason { .. } => {
                "provider returned an unsupported stop reason".into()
            }
            ProviderError::DeadlineExceeded => "run wall-clock deadline exhausted".into(),
            ProviderError::Interrupted => "run was interrupted before the turn completed".into(),
            ProviderError::NoKey | ProviderError::MissingCredential { .. } => {
                "provider credential is missing".into()
            }
            ProviderError::UnsupportedCatalog { .. } => "provider catalog is unsupported".into(),
            ProviderError::Configuration(_) => "provider configuration is invalid".into(),
            ProviderError::KnownAccountUnavailable { availability, .. } => {
                format!("provider account is unavailable ({availability:?})")
            }
            ProviderError::KnownModelUnavailable { .. } => {
                "the selected model is known unavailable".into()
            }
        }
    }
}

fn retry_for_status(status: u16) -> RetryDisposition {
    // 429 and 529 have explicit rate-limit/overload meaning. A bare 408, 409, or 5xx does not
    // prove a billable inference request was never accepted, so replay is unsafe without a
    // provider-specific idempotency contract.
    if matches!(status, 429 | 529) {
        RetryDisposition::Transient
    } else {
        RetryDisposition::Never
    }
}

/// Parse the standard `Retry-After` header. Both delta-seconds and HTTP-date forms are
/// supported. A date in the past becomes an immediate retry rather than underflowing.
pub(crate) fn retry_after_from_headers(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let raw = headers.get(reqwest::header::RETRY_AFTER)?.to_str().ok()?;
    parse_retry_after_at(raw, SystemTime::now())
}

pub(crate) fn request_id_from_headers(headers: &reqwest::header::HeaderMap) -> Option<String> {
    ["request-id", "x-request-id"]
        .into_iter()
        .find_map(|name| headers.get(name)?.to_str().ok().map(ToOwned::to_owned))
        .and_then(sanitize_request_id)
}

/// What the response headers say about the caller's remaining quota.
///
/// Both vendors publish this on every successful response, and Core read none of it: header
/// extraction handled `Retry-After` and the request id only, so the first visible sign of an
/// exhausted budget was the 429 that had already cost a request (I-53). Every field is `Option`
/// because a gateway may forward some headers and drop others, and a `0` remaining is the single
/// most alarming value this type can hold — it must never be minted from an absent header.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RateLimitSnapshot {
    pub requests_remaining: Option<u64>,
    pub tokens_remaining: Option<u64>,
    /// Time until the request budget refills, normalized from whichever form the vendor sent.
    pub requests_reset: Option<Duration>,
    pub tokens_reset: Option<Duration>,
}

impl RateLimitSnapshot {
    pub const fn is_empty(&self) -> bool {
        self.requests_remaining.is_none()
            && self.tokens_remaining.is_none()
            && self.requests_reset.is_none()
            && self.tokens_reset.is_none()
    }

    /// One line for a status screen. `None` when the route published nothing to report, so a
    /// caller never renders a row of dashes that looks like an exhausted budget.
    pub fn summary(&self) -> Option<String> {
        if self.is_empty() {
            return None;
        }
        let mut parts = Vec::new();
        if let Some(requests) = self.requests_remaining {
            parts.push(format!("requests {requests}"));
        }
        if let Some(tokens) = self.tokens_remaining {
            parts.push(format!("tokens {tokens}"));
        }
        let reset = self
            .requests_reset
            .into_iter()
            .chain(self.tokens_reset)
            .max();
        if let Some(reset) = reset {
            parts.push(format!("resets in {}s", reset.as_secs()));
        }
        Some(parts.join(", "))
    }
}

/// Anthropic and OpenAI spell the same four facts differently. Order is (requests-remaining,
/// tokens-remaining, requests-reset, tokens-reset) per vendor; the first header present wins.
const RATE_LIMIT_HEADERS: [[&str; 2]; 4] = [
    [
        "anthropic-ratelimit-requests-remaining",
        "x-ratelimit-remaining-requests",
    ],
    [
        "anthropic-ratelimit-tokens-remaining",
        "x-ratelimit-remaining-tokens",
    ],
    [
        "anthropic-ratelimit-requests-reset",
        "x-ratelimit-reset-requests",
    ],
    [
        "anthropic-ratelimit-tokens-reset",
        "x-ratelimit-reset-tokens",
    ],
];

pub(crate) fn rate_limit_from_headers(
    headers: &reqwest::header::HeaderMap,
) -> Option<RateLimitSnapshot> {
    rate_limit_from_headers_at(headers, SystemTime::now())
}

fn rate_limit_from_headers_at(
    headers: &reqwest::header::HeaderMap,
    now: SystemTime,
) -> Option<RateLimitSnapshot> {
    let raw = |index: usize| -> Option<&str> {
        RATE_LIMIT_HEADERS[index]
            .into_iter()
            .find_map(|name| headers.get(name)?.to_str().ok())
    };
    let snapshot = RateLimitSnapshot {
        requests_remaining: raw(0).and_then(|value| value.trim().parse().ok()),
        tokens_remaining: raw(1).and_then(|value| value.trim().parse().ok()),
        requests_reset: raw(2).and_then(|value| parse_rate_limit_reset_at(value, now)),
        tokens_reset: raw(3).and_then(|value| parse_rate_limit_reset_at(value, now)),
    };
    (!snapshot.is_empty()).then_some(snapshot)
}

/// Normalize a reset header to "time from now". Anthropic sends an RFC 3339 instant; OpenAI sends
/// a compact duration (`1s`, `6m0s`, `120ms`). A reset already in the past is `ZERO`, never an
/// underflow, on exactly the same rule `Retry-After` already uses.
fn parse_rate_limit_reset_at(raw: &str, now: SystemTime) -> Option<Duration> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Ok(seconds) = raw.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    if let Some(instant) = parse_rfc3339_utc(raw) {
        return Some(instant.duration_since(now).unwrap_or(Duration::ZERO));
    }
    parse_compact_duration(raw)
}

/// `1h2m3s`, `6m0s`, `120ms`, `1.5s` — the form OpenAI uses for its reset headers.
fn parse_compact_duration(raw: &str) -> Option<Duration> {
    let mut total = Duration::ZERO;
    let mut rest = raw;
    let mut matched = false;
    while !rest.is_empty() {
        let split = rest.find(|c: char| !c.is_ascii_digit() && c != '.')?;
        let (value, remainder) = rest.split_at(split);
        let value: f64 = value.parse().ok()?;
        // Longest unit first: `ms` must not be read as `m` followed by a stray `s`.
        let (unit_len, seconds) = if remainder.starts_with("ms") {
            (2, value / 1_000.0)
        } else if let Some(unit) = remainder.chars().next() {
            let scale = match unit {
                's' => 1.0,
                'm' => 60.0,
                'h' => 3_600.0,
                'd' => 86_400.0,
                _ => return None,
            };
            (unit.len_utf8(), value * scale)
        } else {
            return None;
        };
        total = total.checked_add(Duration::try_from_secs_f64(seconds).ok()?)?;
        matched = true;
        rest = &remainder[unit_len..];
    }
    matched.then_some(total)
}

/// `YYYY-MM-DDTHH:MM:SSZ`, the only shape either vendor emits here. Deliberately strict: a
/// timestamp this code cannot prove it understands yields `None` rather than a wrong deadline.
fn parse_rfc3339_utc(raw: &str) -> Option<SystemTime> {
    let raw = raw.strip_suffix('Z').or_else(|| raw.strip_suffix('z'))?;
    let (date, time) = raw.split_once('T')?;
    // Fractional seconds carry no information a quota display can use.
    let time = time.split_once('.').map_or(time, |(whole, _)| whole);
    let mut date = date.split('-');
    let year: i64 = date.next()?.parse().ok()?;
    let month: i64 = date.next()?.parse().ok()?;
    let day: i64 = date.next()?.parse().ok()?;
    if date.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let mut time = time.split(':');
    let hour: u64 = time.next()?.parse().ok()?;
    let minute: u64 = time.next()?.parse().ok()?;
    let second: u64 = time.next()?.parse().ok()?;
    if time.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    // Howard Hinnant's days-from-civil: exact, branch-light, and no calendar dependency.
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(i64::try_from(hour * 3_600 + minute * 60 + second).ok()?)?;
    if seconds < 0 {
        return std::time::UNIX_EPOCH.checked_sub(Duration::from_secs(seconds.unsigned_abs()));
    }
    std::time::UNIX_EPOCH.checked_add(Duration::from_secs(seconds as u64))
}

/// Consume a non-success provider response into a bounded, normalized error. This is shared by
/// turn and catalog transports so quota/auth decisions cannot diverge between screens.
pub(crate) async fn api_error_from_response(
    response: reqwest::Response,
    adapter: AdapterKind,
    error_profile: ErrorProfile,
) -> ProviderError {
    use futures_util::StreamExt as _;

    let status = response.status().as_u16();
    let retry_after = retry_after_from_headers(response.headers());
    let request_id = request_id_from_headers(response.headers());
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::with_capacity(4096);
    let mut body_truncated = false;
    let deadline = tokio::time::Instant::now() + ERROR_BODY_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            body_truncated = true;
            break;
        }
        let next = match tokio::time::timeout(remaining, stream.next()).await {
            Ok(next) => next,
            Err(_) => {
                body_truncated = true;
                break;
            }
        };
        let Some(next) = next else { break };
        let Ok(chunk) = next else {
            body_truncated = true;
            break;
        };
        if extend_bounded_error_body(&mut bytes, &chunk) {
            body_truncated = true;
            break;
        }
        if bytes.len() == MAX_ERROR_BODY_BYTES {
            // Exactly-at-limit bodies are retained. If there is another chunk, the next
            // iteration marks truncation without extending the allocation.
            continue;
        }
    }
    let body = bounded_lossy_error_body(&bytes);
    let code = extract_error_code(&body);
    let normalized = normalize_failure(adapter, error_profile, Some(status), code, request_id);
    ProviderError::ApiResponse(ApiResponseError {
        status,
        body,
        body_truncated,
        retry_after,
        normalized: Box::new(normalized),
    })
}

fn bounded_lossy_error_body(bytes: &[u8]) -> String {
    let mut body = String::from_utf8_lossy(bytes).into_owned();
    if body.len() > MAX_ERROR_BODY_BYTES {
        let mut end = MAX_ERROR_BODY_BYTES;
        while !body.is_char_boundary(end) {
            end -= 1;
        }
        body.truncate(end);
    }
    body
}

/// Append one transport chunk, returning true when bytes had to be discarded.
fn extend_bounded_error_body(body: &mut Vec<u8>, chunk: &[u8]) -> bool {
    let remaining = MAX_ERROR_BODY_BYTES.saturating_sub(body.len());
    if chunk.len() > remaining {
        body.extend_from_slice(&chunk[..remaining]);
        true
    } else {
        body.extend_from_slice(chunk);
        false
    }
}

fn extract_error_code(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let detail = value.get("error").unwrap_or(&value);
    detail
        .get("code")
        .and_then(json_scalar_string)
        .or_else(|| detail.get("type").and_then(json_scalar_string))
        .or_else(|| value.get("code").and_then(json_scalar_string))
        .or_else(|| value.get("type").and_then(json_scalar_string))
        .or_else(|| {
            value
                .pointer("/base_resp/status_code")
                .and_then(json_scalar_string)
        })
        .or_else(|| {
            value
                .pointer("/baseResp/statusCode")
                .and_then(json_scalar_string)
        })
}

/// MiniMax returns business failures in an HTTP 200 Chat Completions envelope. When `base_resp`
/// is present, only status code zero is success; every non-zero code becomes the same typed,
/// scheduler-visible in-band failure used by explicit stream error events.
pub(crate) fn minimax_base_response_failure_for(
    adapter: AdapterKind,
    error_profile: ErrorProfile,
    provider: &'static str,
    data: &str,
    value: &serde_json::Value,
    response_retry_after: Option<Duration>,
    request_id: Option<String>,
) -> Result<Option<StreamError>, ProviderError> {
    let status_code = value
        .pointer("/base_resp/status_code")
        .or_else(|| value.pointer("/baseResp/statusCode"));
    let Some(status_code) = status_code else {
        return Ok(None);
    };
    let code = json_scalar_string(status_code).ok_or_else(|| {
        ProviderError::Decode("MiniMax base_resp.status_code was not an integer".into())
    })?;
    let code_value = code.parse::<i64>().map_err(|_| {
        ProviderError::Decode("MiniMax base_resp.status_code was not an integer".into())
    })?;
    if code_value == 0 {
        return Ok(None);
    }
    Ok(Some(decode_stream_error_for(
        adapter,
        error_profile,
        provider,
        data,
        response_retry_after,
        request_id,
    )))
}

fn parse_retry_after_at(raw: &str, now: SystemTime) -> Option<Duration> {
    if let Ok(seconds) = raw.trim().parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let when = httpdate::parse_http_date(raw.trim()).ok()?;
    Some(when.duration_since(now).unwrap_or(Duration::ZERO))
}

/// Decode the common provider error envelope used by both Anthropic SSE `event:error` frames
/// and OpenAI-compatible top-level `{ "error": ... }` chunks. Providers are regrettably not
/// uniform, so all fields remain optional and the original protocol-specific code is retained.
/// Decode an in-band provider error using the same normalization contract as non-2xx HTTP
/// responses. Kept crate-visible so multiple transport adapters cannot drift in classification.
pub(crate) fn decode_stream_error_for(
    adapter: AdapterKind,
    error_profile: ErrorProfile,
    provider: &'static str,
    data: &str,
    response_retry_after: Option<Duration>,
    request_id: Option<String>,
) -> StreamError {
    let value: serde_json::Value = match serde_json::from_str(data) {
        Ok(value) => value,
        Err(error) => {
            let normalized = normalize_failure(
                adapter,
                error_profile,
                None,
                Some("malformed_error_event".to_string()),
                request_id,
            );
            return StreamError {
                provider,
                code: Some("malformed_error_event".to_string()),
                message: bounded_diagnostic(&format!(
                    "provider emitted malformed error JSON: {error}"
                )),
                status: None,
                retry_after: response_retry_after,
                normalized: Box::new(normalized),
            };
        }
    };
    let detail = value.get("error").unwrap_or(&value);
    let code = detail
        .get("code")
        .and_then(json_scalar_string)
        .or_else(|| detail.get("type").and_then(json_scalar_string))
        .or_else(|| value.get("type").and_then(json_scalar_string))
        .or_else(|| {
            value
                .pointer("/base_resp/status_code")
                .and_then(json_scalar_string)
        })
        .or_else(|| {
            value
                .pointer("/baseResp/statusCode")
                .and_then(json_scalar_string)
        });
    let message = bounded_diagnostic(
        detail
            .get("message")
            .and_then(|value| value.as_str())
            .or_else(|| value.get("message").and_then(|value| value.as_str()))
            .or_else(|| {
                value
                    .pointer("/base_resp/status_msg")
                    .and_then(|value| value.as_str())
            })
            .or_else(|| {
                value
                    .pointer("/baseResp/statusMsg")
                    .and_then(|value| value.as_str())
            })
            .unwrap_or("provider emitted an error without a message"),
    );
    let status = detail
        .get("status")
        .and_then(json_u16)
        .or_else(|| detail.get("status_code").and_then(json_u16))
        .or_else(|| value.get("status").and_then(json_u16))
        .or_else(|| code.as_deref().and_then(infer_status));
    let retry_after = detail
        .get("retry_after")
        .and_then(json_duration)
        .or_else(|| detail.get("retry_after_seconds").and_then(json_duration))
        .or_else(|| value.get("retry_after").and_then(json_duration))
        .or(response_retry_after);

    let normalized = normalize_failure(adapter, error_profile, status, code.clone(), request_id);
    StreamError {
        provider,
        code,
        message,
        status,
        retry_after,
        normalized: Box::new(normalized),
    }
}

fn bounded_diagnostic(value: &str) -> String {
    const MAX_DIAGNOSTIC_BYTES: usize = 1024;
    if value.len() <= MAX_DIAGNOSTIC_BYTES {
        return value.to_string();
    }
    let mut end = MAX_DIAGNOSTIC_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

fn sanitized_code(code: Option<String>) -> Option<String> {
    let code = code?;
    let clean: String = code
        .chars()
        .take(128)
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        })
        .collect();
    (!clean.is_empty()).then_some(clean)
}

pub(crate) fn normalize_failure(
    adapter: AdapterKind,
    error_profile: ErrorProfile,
    status: Option<u16>,
    code: Option<String>,
    request_id: Option<String>,
) -> NormalizedFailure {
    let code = sanitized_code(code);
    let lower = code.as_deref().unwrap_or_default().to_ascii_lowercase();
    let kind =
        profile_failure_kind(error_profile, &lower).or_else(|| portable_failure_kind(&lower));

    let (public_message, scope, availability, retry) =
        if kind == Some(FailureKind::Auth) || status == Some(401) {
            (
                "provider authentication was rejected",
                ErrorScope::Account,
                AvailabilityTransition::Account(AccountAvailability::AuthenticationBlocked),
                RetryDisposition::Never,
            )
        } else if kind == Some(FailureKind::Billing) || status == Some(402) {
            (
                "provider billing or quota is unavailable",
                ErrorScope::Account,
                AvailabilityTransition::Account(AccountAvailability::BillingBlocked),
                RetryDisposition::Never,
            )
        } else if kind == Some(FailureKind::ModelUnavailable) {
            (
                "the selected model is unavailable",
                ErrorScope::Model,
                AvailabilityTransition::ModelUnavailable,
                RetryDisposition::Never,
            )
        } else if kind == Some(FailureKind::Permission) {
            (
                "provider account is not permitted to make this request",
                ErrorScope::Account,
                AvailabilityTransition::Account(AccountAvailability::PermissionBlocked),
                RetryDisposition::Never,
            )
        } else if kind == Some(FailureKind::ProviderOverload) {
            (
                "provider is temporarily unavailable",
                ErrorScope::Provider,
                AvailabilityTransition::Account(AccountAvailability::Degraded),
                RetryDisposition::Transient,
            )
        } else if kind == Some(FailureKind::ModelOverload) {
            (
                "the selected model is temporarily overloaded",
                ErrorScope::Model,
                AvailabilityTransition::None,
                RetryDisposition::Transient,
            )
        } else if kind == Some(FailureKind::QuotaWindow) {
            (
                "provider quota window is exhausted",
                ErrorScope::Account,
                AvailabilityTransition::Account(AccountAvailability::RateLimited),
                // MiniMax 2056 and GLM 1310 reset in a later quota window. Without a trusted reset
                // timestamp, immediate exponential retries only spend the caller's retry budget.
                RetryDisposition::Never,
            )
        } else if status == Some(403) {
            (
                "provider access is forbidden",
                ErrorScope::Account,
                AvailabilityTransition::Account(AccountAvailability::PermissionBlocked),
                RetryDisposition::Never,
            )
        } else if kind == Some(FailureKind::RateLimit) || status == Some(429) {
            (
                "provider rate limit reached",
                ErrorScope::Account,
                AvailabilityTransition::Account(AccountAvailability::RateLimited),
                RetryDisposition::Transient,
            )
        } else if status == Some(529) {
            (
                "provider is temporarily unavailable",
                ErrorScope::Provider,
                AvailabilityTransition::Account(AccountAvailability::Degraded),
                RetryDisposition::Transient,
            )
        } else if status.is_some_and(|value| (500..=599).contains(&value)) {
            (
                "provider is temporarily unavailable",
                ErrorScope::Provider,
                AvailabilityTransition::Account(AccountAvailability::Degraded),
                // The server may have accepted and billed the request before failing. Generic
                // server errors are therefore observable but not automatically replayed.
                RetryDisposition::Never,
            )
        } else if matches!(status, Some(408 | 409)) {
            (
                "provider request could not complete",
                ErrorScope::Request,
                AvailabilityTransition::None,
                RetryDisposition::Never,
            )
        } else {
            (
                "provider request was rejected",
                ErrorScope::Request,
                AvailabilityTransition::None,
                RetryDisposition::Never,
            )
        };

    NormalizedFailure {
        adapter,
        error_profile,
        code,
        public_message,
        scope,
        availability,
        retry,
        request_id: request_id.and_then(sanitize_request_id),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailureKind {
    Auth,
    Billing,
    Permission,
    ModelUnavailable,
    RateLimit,
    QuotaWindow,
    ProviderOverload,
    ModelOverload,
}

/// Interpret only codes documented by the selected provider. Numeric codes are deliberately
/// absent from the portable vocabulary because vendors reuse the same number for different
/// account states.
fn profile_failure_kind(profile: ErrorProfile, code: &str) -> Option<FailureKind> {
    match profile {
        ErrorProfile::MiniMax => match code {
            "1002" => Some(FailureKind::RateLimit),
            "1004" | "2049" => Some(FailureKind::Auth),
            "1008" => Some(FailureKind::Billing),
            "2056" => Some(FailureKind::QuotaWindow),
            _ => None,
        },
        ErrorProfile::Glm => match code {
            "1000" | "1001" | "1002" | "1003" | "1004" => Some(FailureKind::Auth),
            "1113" | "1309" => Some(FailureKind::Billing),
            "1211" | "1212" | "1311" => Some(FailureKind::ModelUnavailable),
            "1220" => Some(FailureKind::Permission),
            "1302" | "1303" => Some(FailureKind::RateLimit),
            "1305" => Some(FailureKind::ProviderOverload),
            "1310" => Some(FailureKind::QuotaWindow),
            "1312" => Some(FailureKind::ModelOverload),
            value
                if value
                    .parse::<u16>()
                    .is_ok_and(|number| (1110..=1121).contains(&number)) =>
            {
                Some(FailureKind::Permission)
            }
            _ => None,
        },
        ErrorProfile::Anthropic
        | ErrorProfile::OpenAi
        | ErrorProfile::DeepSeek
        | ErrorProfile::Fireworks
        | ErrorProfile::CustomConservative => None,
    }
}

fn portable_failure_kind(code: &str) -> Option<FailureKind> {
    match code {
        "authentication_error" | "invalid_api_key" | "invalid_token" | "unauthorized" => {
            Some(FailureKind::Auth)
        }
        "insufficient_quota"
        | "insufficient_balance"
        | "billing_error"
        | "billing_not_active"
        | "billing_hard_limit_reached"
        | "credit_balance_too_low" => Some(FailureKind::Billing),
        "permission_error" | "permission_denied" | "account_suspended" => {
            Some(FailureKind::Permission)
        }
        "model_not_found" | "model_not_found_error" | "model_not_available" => {
            Some(FailureKind::ModelUnavailable)
        }
        "rate_limit_error" | "rate_limit_exceeded" | "too_many_requests" => {
            Some(FailureKind::RateLimit)
        }
        "overloaded_error" | "overloaded" => Some(FailureKind::ProviderOverload),
        _ => None,
    }
}

fn sanitize_request_id(value: String) -> Option<String> {
    let clean: String = value
        .chars()
        .take(256)
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        })
        .collect();
    (!clean.is_empty()).then_some(clean)
}

fn json_scalar_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn json_u16(value: &serde_json::Value) -> Option<u16> {
    value
        .as_u64()
        .and_then(|value| u16::try_from(value).ok())
        .or_else(|| value.as_str()?.parse::<u16>().ok())
}

fn json_duration(value: &serde_json::Value) -> Option<Duration> {
    if let Some(seconds) = value.as_u64() {
        return Some(Duration::from_secs(seconds));
    }
    let seconds = value
        .as_f64()
        .or_else(|| value.as_str()?.parse::<f64>().ok())?;
    (seconds.is_finite() && seconds >= 0.0)
        .then(|| Duration::try_from_secs_f64(seconds).ok())
        .flatten()
}

fn infer_status(code: &str) -> Option<u16> {
    match code.to_ascii_lowercase().as_str() {
        "request_timeout" | "timeout_error" => Some(408),
        "conflict" | "conflict_error" => Some(409),
        "rate_limit_error" | "rate_limit_exceeded" | "too_many_requests" => Some(429),
        "overloaded_error" | "overloaded" => Some(529),
        "api_error" | "server_error" | "internal_server_error" => Some(500),
        _ => None,
    }
}

/// A request for one model turn. The transcript is append-only (ADR-002 R2): `messages` is
/// never edited in place, only appended to between turns.
#[derive(Debug, Clone)]
pub struct TurnRequest {
    pub model: String,
    pub system: String,
    pub messages: Vec<Message>,
    /// Provider-neutral image attachments for this top-level submission.
    ///
    /// The kernel validates and scopes these before constructing the request; adapters that
    /// advertise image support may serialize them without re-reading files or interpreting MIME
    /// types. Text-only requests always carry an empty vector.
    pub input_images: Vec<core_protocol::ImageContent>,
    pub tools: Vec<ToolSpec>,
    pub max_tokens: u32,
    /// Cache breakpoint after the system prompt + tools (the stable prefix). ADR-002:
    /// tools -> system -> messages ordering; the volatile task text goes after the boundary.
    pub cache_system: bool,
    /// Extended-thinking / reasoning token budget (0 = off). Set from the effort level.
    pub thinking_budget: u32,
    /// Semantic model effort, independent of the thinking-token budget and of harness
    /// orchestration. Adapters must not infer this value from `thinking_budget`.
    pub reasoning_effort: core_protocol::ReasoningEffort,
}

/// Bounded, secret-free strategy notice emitted before a provider request. Notices are
/// observational: they never veto dispatch or change the wire request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderNotice {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone)]
struct StaticMetadataNoticeRoute {
    metadata: std::sync::Arc<StaticProviderMetadata>,
    adapter: AdapterKind,
    profile: ErrorProfile,
    api_root: String,
    model: String,
}

impl StaticMetadataNoticeRoute {
    fn notice_at(&self, now_unix_secs: u64) -> Option<String> {
        self.metadata.run_notice(
            self.adapter,
            self.profile,
            &self.api_root,
            &self.model,
            now_unix_secs,
        )
    }

    fn notice(&self) -> Option<String> {
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        self.notice_at(now)
    }
}

/// How a provider adapter serialized the requested semantic effort for this route/model.
/// `Exact` means the semantic value was sent without adapter-side downgrade; it does **not** prove
/// that the selected model accepts that value. Capability proof belongs to a provenance-bearing
/// model catalog descriptor, which the current catalog does not yet provide. This keeps
/// UI/telemetry honest: label it "sent exact", while `BudgetBased`, `Mapped`, and `ToggleOnly`
/// describe weaker controls and `Unsupported` sends no semantic control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffortApplication {
    Exact {
        requested: core_protocol::ReasoningEffort,
    },
    Mapped {
        requested: core_protocol::ReasoningEffort,
        sent: core_protocol::ReasoningEffort,
    },
    BudgetBased {
        requested: core_protocol::ReasoningEffort,
        budget_tokens: u32,
    },
    ToggleOnly {
        requested: core_protocol::ReasoningEffort,
        enabled: bool,
    },
    Unsupported {
        requested: core_protocol::ReasoningEffort,
    },
}

/// The completed result of one model turn, assembled from the stream.
#[derive(Debug, Clone)]
pub struct TurnResult {
    pub blocks: Vec<Block>,
    pub stop_reason: StopReason,
    pub usage: UsageReport,
}

impl TurnResult {
    pub fn tool_uses(&self) -> Vec<ToolUse> {
        self.blocks
            .iter()
            .filter_map(|b| match b {
                Block::ToolUse(t) => Some(t.clone()),
                _ => None,
            })
            .collect()
    }
    pub fn text(&self) -> String {
        self.blocks
            .iter()
            .filter_map(|b| match b {
                Block::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("")
    }
}

/// The model seam. The kernel talks to this trait, so a recorded-transcript replay provider
/// and the live Anthropic provider are interchangeable (ADR-006).
#[async_trait::async_trait]
pub trait Provider: Send + Sync {
    /// Stable configured provider-instance identity for route/accounting binding. Production
    /// wrappers report the exact catalog instance they dispatch through; unidentified providers
    /// cannot support a verified priced route.
    fn provider_instance_id(&self) -> Option<&str> {
        None
    }

    fn attempt_semantics(&self) -> ProviderAttemptSemantics {
        ProviderAttemptSemantics::Single
    }

    /// Whether this provider can faithfully serialize [`TurnRequest::input_images`].
    ///
    /// Unknown adapters and gateways must remain conservative. Wrappers around another provider
    /// should forward the inner capability rather than infer it from a model name.
    fn supports_image_input(&self) -> bool {
        false
    }

    /// Report the adapter's actual control surface before the request is sent. Implementations
    /// must be conservative for unknown gateways/models; wire compatibility alone is not proof of
    /// effort support.
    fn effort_application(&self, req: &TurnRequest) -> EffortApplication {
        EffortApplication::Unsupported {
            requested: req.reasoning_effort,
        }
    }

    /// Propose bounded strategy/world evidence that the kernel must record once per logical run
    /// before admitting a provider effect. This method must be pure and repeatable: the durable
    /// append is the commit boundary, so a failed append or a resumed run may ask again.
    fn run_notice(&self, _req: &TurnRequest) -> Option<ProviderNotice> {
        None
    }

    /// Surface cache-hygiene concerns uniformly for every adapter without turning a heuristic
    /// into an availability gate. Unlike [`Self::run_notice`], this is evaluated and may be
    /// emitted before every request. The stable-prefix scan is relevant only when caching is on.
    fn preflight_notice(&self, req: &TurnRequest) -> Option<ProviderNotice> {
        if !req.cache_system {
            return None;
        }
        cache_bomb_in_prefix(&req.system).map(|reason| ProviderNotice {
            code: "cache_hygiene",
            message: reason.into(),
        })
    }

    /// Run one turn. The callback receives `StreamItem`s as they arrive, so the scheduler can
    /// dispatch a pure tool at its `ToolUseComplete` (mid-stream), before this future
    /// resolves. That callback is the flagship overlap hook.
    async fn turn(
        &self,
        req: &TurnRequest,
        on_item: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError>;
}

/// Run one provider turn, but abort the in-flight stream the moment a cooperative interrupt is
/// observed.
///
/// A [`Provider::turn`] call is a single future whose only cancellation path is being dropped.
/// Awaiting it directly means a slow, wedged, or maliciously-stalled stream ignores an operator
/// interrupt (Ctrl-C) until the model decides to finish — there is no mid-stream cancellation.
/// This races the turn against a bounded poll of `cancel`: while the flag stays clear the turn
/// runs (and its `on_item` callback keeps firing) untouched; the moment the flag is set, the turn
/// future is dropped — which closes the transport and stops decoding — and
/// [`ProviderError::Interrupted`] is returned. Worst-case latency from flag-set to abort is one
/// `poll_interval`.
///
/// `cancel` is `None` for callers with no interrupt installed, in which case this is exactly a
/// bare `provider.turn(..).await` with no added polling. A completed turn always wins over a
/// simultaneously-observed interrupt, so a turn that finishes in the same tick is never discarded.
pub async fn turn_cancellable(
    provider: &dyn Provider,
    request: &TurnRequest,
    on_item: &mut (dyn FnMut(StreamItem) + Send),
    cancel: Option<&std::sync::atomic::AtomicBool>,
    poll_interval: Duration,
) -> Result<TurnResult, ProviderError> {
    use std::sync::atomic::Ordering;
    let Some(cancel) = cancel else {
        return provider.turn(request, on_item).await;
    };
    // An interrupt that is already pending must not even open the stream.
    if cancel.load(Ordering::Relaxed) {
        return Err(ProviderError::Interrupted);
    }
    // `async_trait` returns a `Pin<Box<dyn Future + Send>>`, which is `Unpin`, so `&mut turn` is
    // itself a `Future` and can be re-polled across loop iterations without an explicit pin.
    let mut turn = provider.turn(request, on_item);
    loop {
        tokio::select! {
            biased;
            result = &mut turn => return result,
            () = tokio::time::sleep(poll_interval) => {
                if cancel.load(Ordering::Relaxed) {
                    // Returning drops `turn`, cancelling the in-flight provider stream: the
                    // transport future is dropped and the connection is closed.
                    return Err(ProviderError::Interrupted);
                }
            }
        }
    }
}

/// Decorates a live provider with shared account-health reporting without buffering, replacing,
/// or replaying stream items. Put this wrapper outside retry if the UI should see only the final
/// result, or inside retry if it should see transient attempt health as it occurs.
pub struct HealthReportingProvider {
    inner: Box<dyn Provider>,
    provider_instance_id: String,
    health: ProviderHealthStore,
    account_failures_are_model_scoped: bool,
    static_metadata_notice: Option<StaticMetadataNoticeRoute>,
}

impl HealthReportingProvider {
    pub fn new(
        inner: Box<dyn Provider>,
        provider_instance_id: impl Into<String>,
        health: ProviderHealthStore,
    ) -> Self {
        Self {
            inner,
            provider_instance_id: provider_instance_id.into(),
            health,
            account_failures_are_model_scoped: false,
            static_metadata_notice: None,
        }
    }

    /// Multi-account inference keys (Fireworks) cannot safely project one private account's
    /// runtime billing/permission failure onto every sibling/public model in the instance.
    pub fn with_model_scoped_account_failures(mut self, enabled: bool) -> Self {
        self.account_failures_are_model_scoped = enabled;
        self
    }

    /// Attach the proven route used to compute a secret-free snapshot-freshness proposal at the
    /// actual preflight boundary. The kernel owns once-per-run durable commit and replay state;
    /// this wrapper deliberately remains repeatable after a failed append.
    pub fn with_static_metadata_notice(
        mut self,
        metadata: std::sync::Arc<StaticProviderMetadata>,
        adapter: AdapterKind,
        profile: ErrorProfile,
        api_root: impl Into<String>,
        model: impl Into<String>,
    ) -> Self {
        self.static_metadata_notice = Some(StaticMetadataNoticeRoute {
            metadata,
            adapter,
            profile,
            api_root: api_root.into(),
            model: model.into(),
        });
        self
    }

    pub fn health_store(&self) -> &ProviderHealthStore {
        &self.health
    }
}

#[async_trait::async_trait]
impl Provider for HealthReportingProvider {
    fn provider_instance_id(&self) -> Option<&str> {
        Some(&self.provider_instance_id)
    }

    fn attempt_semantics(&self) -> ProviderAttemptSemantics {
        self.inner.attempt_semantics()
    }

    fn supports_image_input(&self) -> bool {
        self.inner.supports_image_input()
    }

    fn effort_application(&self, request: &TurnRequest) -> EffortApplication {
        self.inner.effort_application(request)
    }

    fn run_notice(&self, request: &TurnRequest) -> Option<ProviderNotice> {
        let inner = self.inner.run_notice(request);
        let metadata = self
            .static_metadata_notice
            .as_ref()
            .and_then(StaticMetadataNoticeRoute::notice);
        match (metadata, inner) {
            (Some(metadata), Some(inner)) => Some(ProviderNotice {
                code: "static_metadata",
                message: format!("{metadata}; {}: {}", inner.code, inner.message),
            }),
            (Some(metadata), None) => Some(ProviderNotice {
                code: "static_metadata",
                message: metadata,
            }),
            (None, inner) => inner,
        }
    }

    fn preflight_notice(&self, request: &TurnRequest) -> Option<ProviderNotice> {
        self.inner.preflight_notice(request)
    }

    async fn turn(
        &self,
        request: &TurnRequest,
        on_item: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        if let Some(availability) = self.health.blocked_account(&self.provider_instance_id) {
            return Err(ProviderError::KnownAccountUnavailable {
                provider: self.provider_instance_id.clone(),
                availability,
            });
        }
        if self
            .health
            .is_model_unavailable(&self.provider_instance_id, &request.model)
        {
            return Err(ProviderError::KnownModelUnavailable {
                provider: self.provider_instance_id.clone(),
                model: request.model.clone(),
            });
        }

        let result = self.inner.turn(request, on_item).await;
        match &result {
            Ok(_) => self
                .health
                .mark_turn_ready(&self.provider_instance_id, &request.model),
            Err(error) => self.health.update_from_turn_error_with_scope(
                &self.provider_instance_id,
                &request.model,
                error,
                self.account_failures_are_model_scoped,
            ),
        }
        result
    }
}

/// Match a provider model id against a documented family without accepting lookalike prefixes
/// (`gpt-50` must not match `gpt-5`). Namespaced ids and OpenAI fine-tune ids are normalized only
/// syntactically; the caller must still require the correct provider profile.
pub(crate) fn model_matches_family(model_id: &str, family: &str) -> bool {
    let leaf = model_id.rsplit('/').next().unwrap_or(model_id);
    let candidate = leaf.strip_prefix("ft:").unwrap_or(leaf);
    candidate == family
        || candidate.strip_prefix(family).is_some_and(|suffix| {
            suffix.starts_with('-') || suffix.starts_with('.') || suffix.starts_with(':')
        })
}

/// Detect a potentially cache-busting prefix (ADR-002 amendment / ADR-007 R15). The
/// content linter cannot see runtime timing, but it CAN catch the common static busters: a
/// clock, a UUID, a per-request nonce embedded in what should be a stable prefix.
///
/// Returns a bounded, content-free reason for an observable warning. This heuristic must never
/// refuse a request: ordinary instructions may legitimately describe dates, clocks, or nonces.
pub fn cache_bomb_in_prefix(system: &str) -> Option<&'static str> {
    // Deliberately explicit. The one sanctioned nonce (per-tenant cache_salt, ADR-009) is folded
    // at block 0 by the provider, not embedded in the system text, so it is not seen here.
    const MARKERS: &[(&str, &str)] = &[
        ("current time", "a clock in the prefix"),
        ("timestamp:", "a timestamp in the prefix"),
        ("today's date", "a date in the prefix"),
        ("request-id", "a per-request id in the prefix"),
        ("nonce", "a nonce in the prefix"),
    ];
    let low = system.to_ascii_lowercase();
    for (needle, why) in MARKERS {
        if low.contains(needle) {
            return Some(why);
        }
    }
    None
}

#[cfg(test)]
mod guard_tests {
    use super::*;
    use core_protocol::Usage;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn request(model: &str) -> TurnRequest {
        TurnRequest {
            model: model.into(),
            system: "stable system".into(),
            messages: Vec::new(),
            input_images: Vec::new(),
            tools: Vec::new(),
            max_tokens: 32,
            cache_system: false,
            thinking_budget: 0,
            reasoning_effort: core_protocol::ReasoningEffort::Low,
        }
    }

    fn spawn_one_shot_sse(body: String) -> (String, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}/v1", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut header_end = None;
            let mut expected_len = None;
            loop {
                let mut chunk = [0_u8; 4096];
                let read = stream.read(&mut chunk).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                if header_end.is_none()
                    && let Some(index) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                {
                    let end = index + 4;
                    let headers = String::from_utf8_lossy(&request[..end]);
                    expected_len = headers.lines().find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    });
                    header_end = Some(end);
                }
                if let (Some(end), Some(length)) = (header_end, expected_len)
                    && request.len() >= end.saturating_add(length)
                {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
            String::from_utf8(request).unwrap()
        });
        (origin, server)
    }

    fn typed_error(profile: ErrorProfile, code: &str, status: u16) -> ProviderError {
        ProviderError::ApiResponse(ApiResponseError {
            status,
            body: "provider-controlled secret".into(),
            body_truncated: false,
            retry_after: None,
            normalized: Box::new(normalize_failure(
                AdapterKind::OpenAiCompatibleChat,
                profile,
                Some(status),
                Some(code.into()),
                None,
            )),
        })
    }

    struct BillingProvider {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl Provider for BillingProvider {
        async fn turn(
            &self,
            _request: &TurnRequest,
            _on_item: &mut (dyn FnMut(StreamItem) + Send),
        ) -> Result<TurnResult, ProviderError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(typed_error(ErrorProfile::OpenAi, "insufficient_quota", 429))
        }
    }

    struct OneBadModelProvider {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl Provider for OneBadModelProvider {
        async fn turn(
            &self,
            request: &TurnRequest,
            _on_item: &mut (dyn FnMut(StreamItem) + Send),
        ) -> Result<TurnResult, ProviderError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if request.model == "missing-model" {
                return Err(typed_error(ErrorProfile::OpenAi, "model_not_found", 404));
            }
            Ok(TurnResult {
                blocks: Vec::new(),
                stop_reason: StopReason::EndTurn,
                usage: UsageReport::complete(Usage::default()),
            })
        }
    }

    struct OneFireworksAccountFailureModelProvider {
        calls: Arc<AtomicUsize>,
        code: &'static str,
        status: u16,
    }

    #[async_trait::async_trait]
    impl Provider for OneFireworksAccountFailureModelProvider {
        async fn turn(
            &self,
            request: &TurnRequest,
            _on_item: &mut (dyn FnMut(StreamItem) + Send),
        ) -> Result<TurnResult, ProviderError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if request.model == "private-blocked" {
                return Err(typed_error(ErrorProfile::Fireworks, self.code, self.status));
            }
            Ok(TurnResult {
                blocks: Vec::new(),
                stop_reason: StopReason::EndTurn,
                usage: UsageReport::complete(Usage::default()),
            })
        }
    }
    #[test]
    fn linter_flags_a_clock_in_the_prefix() {
        assert!(cache_bomb_in_prefix("You are a coding agent. Today's date is ...").is_some());
    }
    #[test]
    fn linter_passes_a_clean_prefix() {
        assert!(cache_bomb_in_prefix("You are a careful coding agent. Edit minimally.").is_none());
    }

    #[test]
    fn static_metadata_notice_age_is_evaluated_at_preflight_time() {
        const DAY_SECS: u64 = 24 * 60 * 60;
        const CAPTURED_AT: u64 = 1_783_987_200;
        let route = StaticMetadataNoticeRoute {
            metadata: StaticProviderMetadata::embedded(),
            adapter: AdapterKind::OpenAiCompatibleChat,
            profile: ErrorProfile::Glm,
            api_root: "https://open.bigmodel.cn/api/paas/v4".into(),
            model: "glm-5.1".into(),
        };

        assert!(
            route
                .notice_at(CAPTURED_AT + 30 * DAY_SECS)
                .unwrap()
                .contains("catalog is 30 days old (fresh)")
        );
        assert!(
            route
                .notice_at(CAPTURED_AT + 31 * DAY_SECS)
                .unwrap()
                .contains("catalog is 31 days old (stale)")
        );
    }

    #[test]
    fn all_live_adapters_surface_the_same_date_notice_without_refusing_preflight() {
        let mut request = request("model");
        request.cache_system = true;
        request.system = "You are a coding agent. Today's date is supplied by the harness.".into();
        let root = ApiRoot::parse("https://example.invalid/v1").unwrap();
        let providers: Vec<Box<dyn Provider>> = vec![
            Box::new(
                crate::anthropic::Anthropic::with_root("test-key".into(), root.clone()).unwrap(),
            ),
            Box::new(
                crate::openai::OpenAiCompat::with_root("test-key".into(), root.clone()).unwrap(),
            ),
            Box::new(
                crate::responses::OpenAiResponses::with_root("test-key".into(), root).unwrap(),
            ),
        ];
        let expected = Some(ProviderNotice {
            code: "cache_hygiene",
            message: "a date in the prefix".into(),
        });
        for provider in providers {
            assert_eq!(provider.preflight_notice(&request), expected);
        }

        request.cache_system = false;
        assert!(
            crate::anthropic::Anthropic::new("test-key".into(), None)
                .unwrap()
                .preflight_notice(&request)
                .is_none(),
            "a prefix that will not be cached needs no cache warning"
        );
    }

    #[tokio::test]
    async fn date_bearing_cached_prefix_completes_on_all_three_live_transports() {
        let mut request = request("model");
        request.cache_system = true;
        request.system = "Today's date is 2026-07-20; use it when naming the report.".into();

        let anthropic_sse = concat!(
            "event: message_start\n",
            "data: {\"message\":{\"usage\":{\"input_tokens\":1}}}\n\n",
            "event: message_delta\n",
            "data: {\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n\n",
            "event: message_stop\n",
            "data: {}\n\n"
        )
        .to_string();
        let chat_sse = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\n",
            "data: {\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n\n",
            "data: [DONE]\n\n"
        )
        .to_string();
        let responses_sse = concat!(
            "event: response.completed\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[],\"usage\":{\"input_tokens\":1,\"input_tokens_details\":{\"cached_tokens\":0},\"output_tokens\":1,\"output_tokens_details\":{\"reasoning_tokens\":0},\"total_tokens\":2}}}\n\n"
        )
        .to_string();

        let (anthropic_root, anthropic_server) = spawn_one_shot_sse(anthropic_sse);
        let (chat_root, chat_server) = spawn_one_shot_sse(chat_sse);
        let (responses_root, responses_server) = spawn_one_shot_sse(responses_sse);
        let providers: Vec<Box<dyn Provider>> = vec![
            Box::new(
                crate::anthropic::Anthropic::new("test-key".into(), Some(anthropic_root)).unwrap(),
            ),
            Box::new(
                crate::openai::OpenAiCompat::try_new("test-key".into(), Some(chat_root)).unwrap(),
            ),
            Box::new(
                crate::responses::OpenAiResponses::new("test-key".into(), Some(responses_root))
                    .unwrap(),
            ),
        ];

        for provider in providers {
            assert_eq!(
                provider
                    .preflight_notice(&request)
                    .map(|notice| notice.code),
                Some("cache_hygiene")
            );
            assert!(provider.turn(&request, &mut |_| {}).await.is_ok());
        }
        for server in [anthropic_server, chat_server, responses_server] {
            let wire = server.join().unwrap();
            assert!(wire.contains("Today's date is 2026-07-20"));
        }
    }

    #[tokio::test]
    async fn chat_stream_without_usage_completes_with_typed_incomplete_evidence() {
        let body = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\n",
            "data: [DONE]\n\n"
        )
        .to_string();
        let (root, server) = spawn_one_shot_sse(body);
        let provider = crate::openai::OpenAiCompat::try_new("test-key".into(), Some(root)).unwrap();
        let mut terminal_usage = None;

        let result = provider
            .turn(&request("model"), &mut |item| {
                if let StreamItem::TurnComplete { usage, .. } = item {
                    terminal_usage = Some(usage);
                }
            })
            .await
            .expect("valid content remains a successful turn when the provider omits usage");

        assert_eq!(result.text(), "ok");
        assert_eq!(result.usage, UsageReport::provider_omitted());
        assert_eq!(terminal_usage, Some(UsageReport::provider_omitted()));
        let _wire = server.join().unwrap();
    }

    #[test]
    fn adapter_sources_have_no_ambient_environment_reads() {
        for (name, source) in [
            ("anthropic", include_str!("anthropic.rs")),
            ("openai_chat", include_str!("openai.rs")),
            ("openai_responses", include_str!("responses.rs")),
        ] {
            assert!(
                !source.contains("std::env::") && !source.contains("std::env "),
                "{name} adapter must receive credentials and API roots from the CLI composition root"
            );
        }
    }

    #[test]
    fn all_adapters_drive_from_injected_config_with_process_environment_cleared() {
        let executable = std::env::current_exe().unwrap();
        let output = std::process::Command::new(executable)
            .env_clear()
            .args([
                "--exact",
                "guard_tests::date_bearing_cached_prefix_completes_on_all_three_live_transports",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "injected adapter subprocess failed with an empty environment:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn retry_after_accepts_delta_seconds_and_http_date() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        assert_eq!(
            parse_retry_after_at("17", now),
            Some(Duration::from_secs(17))
        );

        let later = now + Duration::from_secs(23);
        let date = httpdate::fmt_http_date(later);
        assert_eq!(
            parse_retry_after_at(&date, now),
            Some(Duration::from_secs(23))
        );
    }

    #[test]
    fn retry_after_past_date_is_zero_and_garbage_is_absent() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let past = httpdate::fmt_http_date(now - Duration::from_secs(1));
        assert_eq!(parse_retry_after_at(&past, now), Some(Duration::ZERO));
        assert_eq!(parse_retry_after_at("eventually", now), None);
    }

    /// I-53: header extraction handled `Retry-After` and the request id only, so remaining quota
    /// was invisible until a 429 had already been paid for. Both vendors publish it on every
    /// successful response, in different spellings and different reset formats.
    #[test]
    fn remaining_quota_is_read_from_both_vendors_before_any_rejection() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let headers = |pairs: &[(&str, &str)]| {
            let mut map = reqwest::header::HeaderMap::new();
            for (name, value) in pairs {
                map.insert(
                    reqwest::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    value.parse().unwrap(),
                );
            }
            map
        };

        let anthropic = rate_limit_from_headers_at(
            &headers(&[
                ("anthropic-ratelimit-requests-remaining", "48"),
                ("anthropic-ratelimit-tokens-remaining", "199000"),
                ("anthropic-ratelimit-tokens-reset", "1970-01-12T13:47:05Z"),
            ]),
            now,
        )
        .expect("a published quota is a snapshot");
        assert_eq!(anthropic.requests_remaining, Some(48));
        assert_eq!(anthropic.tokens_remaining, Some(199_000));
        assert_eq!(anthropic.tokens_reset, Some(Duration::from_secs(25)));
        assert_eq!(
            anthropic.requests_reset, None,
            "an absent header stays absent instead of becoming an invented deadline"
        );
        assert_eq!(
            anthropic.summary().as_deref(),
            Some("requests 48, tokens 199000, resets in 25s")
        );

        let openai = rate_limit_from_headers_at(
            &headers(&[
                ("x-ratelimit-remaining-requests", "0"),
                ("x-ratelimit-remaining-tokens", "12"),
                ("x-ratelimit-reset-requests", "6m0s"),
                ("x-ratelimit-reset-tokens", "120ms"),
            ]),
            now,
        )
        .expect("a published quota is a snapshot");
        assert_eq!(openai.requests_remaining, Some(0));
        assert_eq!(openai.tokens_remaining, Some(12));
        assert_eq!(openai.requests_reset, Some(Duration::from_secs(360)));
        assert_eq!(openai.tokens_reset, Some(Duration::from_millis(120)));

        assert_eq!(
            rate_limit_from_headers_at(&headers(&[("x-request-id", "req-1")]), now),
            None,
            "a route that publishes no quota must not render a row of zeroes"
        );
    }

    #[test]
    fn a_reset_header_core_cannot_prove_it_understands_is_absent_not_zero() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        assert_eq!(
            parse_rate_limit_reset_at("30", now),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            parse_rate_limit_reset_at("1h2m3s", now),
            Some(Duration::from_secs(3_723))
        );
        assert_eq!(
            parse_rate_limit_reset_at("1.5s", now),
            Some(Duration::from_millis(1_500))
        );
        assert_eq!(parse_rate_limit_reset_at("", now), None);
        assert_eq!(parse_rate_limit_reset_at("soon", now), None);
        assert_eq!(parse_rate_limit_reset_at("2024-13-01T00:00:00Z", now), None);
        assert_eq!(
            parse_rate_limit_reset_at("2024-01-01T00:00:00+02:00", now),
            None
        );
        assert_eq!(
            parse_rate_limit_reset_at("1970-01-01T00:00:00Z", now),
            Some(Duration::ZERO),
            "a reset already in the past is now, never an underflow"
        );
        assert_eq!(
            parse_rfc3339_utc("2024-02-29T12:34:56.789Z"),
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_709_210_096)),
            "leap days and fractional seconds are both handled exactly"
        );
    }

    #[test]
    fn stream_error_envelope_retains_typed_metadata() {
        let error = decode_stream_error_for(
            AdapterKind::AnthropicMessages,
            ErrorProfile::Anthropic,
            "anthropic",
            r#"{"type":"error","error":{"type":"overloaded_error","message":"busy","retry_after":1.5}}"#,
            None,
            None,
        );
        assert_eq!(error.code.as_deref(), Some("overloaded_error"));
        assert_eq!(error.message, "busy");
        assert_eq!(error.status, Some(529));
        assert_eq!(error.retry_after, Some(Duration::from_millis(1_500)));
    }

    #[test]
    fn malformed_stream_error_is_still_a_structured_failure() {
        let error = decode_stream_error_for(
            AdapterKind::OpenAiCompatibleChat,
            ErrorProfile::CustomConservative,
            "openai",
            "{nope",
            Some(Duration::from_secs(2)),
            None,
        );
        assert_eq!(error.code.as_deref(), Some("malformed_error_event"));
        assert!(error.message.contains("malformed error JSON"));
        assert_eq!(error.retry_after, Some(Duration::from_secs(2)));
    }

    #[test]
    fn typed_quota_codes_override_ambiguous_http_429() {
        for (profile, code) in [
            (ErrorProfile::OpenAi, "insufficient_quota"),
            (ErrorProfile::MiniMax, "1008"),
            (ErrorProfile::Glm, "1113"),
        ] {
            let failure = normalize_failure(
                AdapterKind::OpenAiCompatibleChat,
                profile,
                Some(429),
                Some(code.into()),
                None,
            );
            assert_eq!(failure.retry, RetryDisposition::Never);
            assert_eq!(
                failure.availability,
                AvailabilityTransition::Account(AccountAvailability::BillingBlocked)
            );
        }

        let bare = normalize_failure(
            AdapterKind::OpenAiCompatibleChat,
            ErrorProfile::Glm,
            Some(429),
            None,
            None,
        );
        assert_eq!(bare.retry, RetryDisposition::Transient);
        assert_eq!(
            bare.availability,
            AvailabilityTransition::Account(AccountAvailability::RateLimited),
            "a bare GLM/OpenAI-compatible 429 must not be guessed to mean arrears"
        );

        let glm_account = normalize_failure(
            AdapterKind::OpenAiCompatibleChat,
            ErrorProfile::Glm,
            Some(429),
            Some("1110".into()),
            None,
        );
        assert_eq!(glm_account.retry, RetryDisposition::Never);
        assert_eq!(glm_account.scope, ErrorScope::Account);
    }

    #[test]
    fn paid_retry_classification_fails_closed_for_ambiguous_failures() {
        assert_eq!(
            ProviderError::Http("response headers timed out".into()).retry_disposition(),
            RetryDisposition::Never
        );
        for status in [408, 409, 500, 502, 503, 504] {
            assert_eq!(
                ProviderError::Api {
                    status,
                    body: String::new(),
                }
                .retry_disposition(),
                RetryDisposition::Never,
                "bare HTTP {status} must not replay a possibly accepted paid request"
            );
        }
        for status in [429, 529] {
            assert_eq!(
                ProviderError::Api {
                    status,
                    body: String::new(),
                }
                .retry_disposition(),
                RetryDisposition::Transient,
                "HTTP {status} is an explicit rate-limit/overload signal"
            );
        }

        let generic_server_failure = normalize_failure(
            AdapterKind::OpenAiCompatibleChat,
            ErrorProfile::OpenAi,
            Some(503),
            None,
            None,
        );
        assert_eq!(generic_server_failure.retry, RetryDisposition::Never);

        let typed_overload = normalize_failure(
            AdapterKind::AnthropicMessages,
            ErrorProfile::Anthropic,
            Some(503),
            Some("overloaded_error".into()),
            None,
        );
        assert_eq!(typed_overload.retry, RetryDisposition::Transient);
    }

    #[test]
    fn minimax_quota_window_is_not_misclassified_as_depleted_balance() {
        let failure = normalize_failure(
            AdapterKind::OpenAiCompatibleChat,
            ErrorProfile::MiniMax,
            None,
            Some("2056".into()),
            None,
        );
        assert_eq!(failure.scope, ErrorScope::Account);
        assert_eq!(
            failure.availability,
            AvailabilityTransition::Account(AccountAvailability::RateLimited),
        );
        assert_eq!(failure.retry, RetryDisposition::Never);
    }

    #[test]
    fn glm_business_codes_preserve_scope_availability_and_retry_semantics() {
        let cases = [
            (
                "1211",
                ErrorScope::Model,
                AvailabilityTransition::ModelUnavailable,
                RetryDisposition::Never,
            ),
            (
                "1212",
                ErrorScope::Model,
                AvailabilityTransition::ModelUnavailable,
                RetryDisposition::Never,
            ),
            (
                "1220",
                ErrorScope::Account,
                AvailabilityTransition::Account(AccountAvailability::PermissionBlocked),
                RetryDisposition::Never,
            ),
            (
                "1302",
                ErrorScope::Account,
                AvailabilityTransition::Account(AccountAvailability::RateLimited),
                RetryDisposition::Transient,
            ),
            // Legacy GLM code retained for old clients and recorded responses.
            (
                "1303",
                ErrorScope::Account,
                AvailabilityTransition::Account(AccountAvailability::RateLimited),
                RetryDisposition::Transient,
            ),
            (
                "1305",
                ErrorScope::Provider,
                AvailabilityTransition::Account(AccountAvailability::Degraded),
                RetryDisposition::Transient,
            ),
            (
                "1309",
                ErrorScope::Account,
                AvailabilityTransition::Account(AccountAvailability::BillingBlocked),
                RetryDisposition::Never,
            ),
            (
                "1310",
                ErrorScope::Account,
                AvailabilityTransition::Account(AccountAvailability::RateLimited),
                RetryDisposition::Never,
            ),
            (
                "1311",
                ErrorScope::Model,
                AvailabilityTransition::ModelUnavailable,
                RetryDisposition::Never,
            ),
            // Legacy GLM code: one model is busy, not permanently unavailable.
            (
                "1312",
                ErrorScope::Model,
                AvailabilityTransition::None,
                RetryDisposition::Transient,
            ),
        ];
        for (code, scope, availability, retry) in cases {
            let failure = normalize_failure(
                AdapterKind::OpenAiCompatibleChat,
                ErrorProfile::Glm,
                Some(429),
                Some(code.into()),
                None,
            );
            assert_eq!(failure.scope, scope, "scope for GLM {code}");
            assert_eq!(
                failure.availability, availability,
                "availability for GLM {code}",
            );
            assert_eq!(failure.retry, retry, "retry for GLM {code}");
        }
    }

    #[test]
    fn minimax_success_envelope_requires_an_integer_zero() {
        let success_data = r#"{"base_resp":{"status_code":0,"status_msg":"ok"}}"#;
        let success: serde_json::Value = serde_json::from_str(success_data).unwrap();
        assert!(
            minimax_base_response_failure_for(
                AdapterKind::OpenAiCompatibleChat,
                ErrorProfile::MiniMax,
                "minimax",
                success_data,
                &success,
                None,
                None,
            )
            .unwrap()
            .is_none()
        );

        let failure_data = r#"{"base_resp":{"status_code":2056,"status_msg":"wait"}}"#;
        let failure: serde_json::Value = serde_json::from_str(failure_data).unwrap();
        let error = minimax_base_response_failure_for(
            AdapterKind::OpenAiCompatibleChat,
            ErrorProfile::MiniMax,
            "minimax",
            failure_data,
            &failure,
            None,
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(error.code.as_deref(), Some("2056"));
        assert_eq!(error.normalized.retry, RetryDisposition::Never);

        let malformed_data = r#"{"base_resp":{"status_code":"success"}}"#;
        let malformed: serde_json::Value = serde_json::from_str(malformed_data).unwrap();
        assert!(
            minimax_base_response_failure_for(
                AdapterKind::OpenAiCompatibleChat,
                ErrorProfile::MiniMax,
                "minimax",
                malformed_data,
                &malformed,
                None,
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn nested_minimax_code_and_request_id_are_normalized() {
        assert_eq!(
            extract_error_code(r#"{"base_resp":{"status_code":1008}}"#).as_deref(),
            Some("1008")
        );
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-request-id", "req_abc-123".parse().unwrap());
        assert_eq!(
            request_id_from_headers(&headers).as_deref(),
            Some("req_abc-123")
        );
    }

    #[test]
    fn provider_body_is_never_in_display_text() {
        let error = ApiResponseError {
            status: 429,
            body: "secret sk-live-never-print".into(),
            body_truncated: false,
            retry_after: None,
            normalized: Box::new(normalize_failure(
                AdapterKind::OpenAiCompatibleChat,
                ErrorProfile::OpenAi,
                Some(429),
                Some("insufficient_quota".into()),
                Some("req-safe".into()),
            )),
        };
        let display = error.to_string();
        assert!(!display.contains("sk-live-never-print"));
        assert!(display.contains("req-safe"));
    }

    #[test]
    fn provider_error_body_storage_is_strictly_bounded() {
        let mut body = vec![b'a'; MAX_ERROR_BODY_BYTES - 2];
        assert!(extend_bounded_error_body(&mut body, b"12345"));
        assert_eq!(body.len(), MAX_ERROR_BODY_BYTES);
        assert_eq!(&body[MAX_ERROR_BODY_BYTES - 2..], b"12");
        assert!(extend_bounded_error_body(&mut body, b"more"));
        assert_eq!(body.len(), MAX_ERROR_BODY_BYTES);

        let invalid_utf8 = vec![0xff; MAX_ERROR_BODY_BYTES];
        assert!(bounded_lossy_error_body(&invalid_utf8).len() <= MAX_ERROR_BODY_BYTES);
    }

    #[test]
    fn numeric_error_codes_are_scoped_by_provider_profile() {
        let minimax = normalize_failure(
            AdapterKind::OpenAiCompatibleChat,
            ErrorProfile::MiniMax,
            None,
            Some("1002".into()),
            None,
        );
        assert_eq!(minimax.retry, RetryDisposition::Transient);
        assert_eq!(
            minimax.availability,
            AvailabilityTransition::Account(AccountAvailability::RateLimited)
        );

        let glm = normalize_failure(
            AdapterKind::OpenAiCompatibleChat,
            ErrorProfile::Glm,
            None,
            Some("1002".into()),
            None,
        );
        assert_eq!(glm.retry, RetryDisposition::Never);
        assert_eq!(
            glm.availability,
            AvailabilityTransition::Account(AccountAvailability::AuthenticationBlocked)
        );

        let custom = normalize_failure(
            AdapterKind::OpenAiCompatibleChat,
            ErrorProfile::CustomConservative,
            None,
            Some("1002".into()),
            None,
        );
        assert_eq!(custom.scope, ErrorScope::Request);
        assert_eq!(custom.availability, AvailabilityTransition::None);
        assert_eq!(custom.retry, RetryDisposition::Never);
    }

    #[test]
    fn structured_error_debug_redacts_raw_provider_diagnostics() {
        let api = match typed_error(ErrorProfile::OpenAi, "insufficient_quota", 429) {
            ProviderError::ApiResponse(error) => error,
            _ => unreachable!(),
        };
        let api_debug = format!("{api:?}");
        assert!(!api_debug.contains("provider-controlled secret"));
        assert!(api_debug.contains("[REDACTED]"));

        let stream = decode_stream_error_for(
            AdapterKind::OpenAiCompatibleChat,
            ErrorProfile::OpenAi,
            "openai",
            r#"{"error":{"code":"rate_limit_error","message":"sk-secret-in-message"}}"#,
            None,
            None,
        );
        let stream_debug = format!("{stream:?}");
        assert!(!stream_debug.contains("sk-secret-in-message"));
        assert!(stream_debug.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn known_billing_failure_gates_the_second_turn_before_inner_provider() {
        let calls = Arc::new(AtomicUsize::new(0));
        let health = ProviderHealthStore::new(8);
        let provider = HealthReportingProvider::new(
            Box::new(BillingProvider {
                calls: calls.clone(),
            }),
            "openai",
            health.clone(),
        );

        let mut sink = |_| {};
        assert!(provider.turn(&request("gpt"), &mut sink).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let second = provider.turn(&request("gpt"), &mut sink).await;
        assert!(matches!(
            second,
            Err(ProviderError::KnownAccountUnavailable {
                availability: AccountAvailability::BillingBlocked,
                ..
            })
        ));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "second turn made a network call"
        );
    }

    #[tokio::test]
    async fn model_failure_blocks_only_the_selected_model_leaf() {
        let calls = Arc::new(AtomicUsize::new(0));
        let health = ProviderHealthStore::new(8);
        let provider = HealthReportingProvider::new(
            Box::new(OneBadModelProvider {
                calls: calls.clone(),
            }),
            "openai",
            health.clone(),
        );
        let mut sink = |_| {};

        assert!(
            provider
                .turn(&request("missing-model"), &mut sink)
                .await
                .is_err()
        );
        assert!(health.is_model_unavailable("openai", "missing-model"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        assert!(matches!(
            provider.turn(&request("missing-model"), &mut sink).await,
            Err(ProviderError::KnownModelUnavailable { .. })
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        assert!(
            provider
                .turn(&request("working-model"), &mut sink)
                .await
                .is_ok()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(
            health.is_model_unavailable("openai", "missing-model"),
            "a different model's success must not clear the failed leaf"
        );
    }

    #[tokio::test]
    async fn fireworks_account_failures_can_be_isolated_to_one_model_leaf() {
        for (code, status, expected_availability) in [
            (
                "insufficient_quota",
                429,
                AccountAvailability::BillingBlocked,
            ),
            (
                "permission_denied",
                403,
                AccountAvailability::PermissionBlocked,
            ),
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let health = ProviderHealthStore::new(8);
            let provider = HealthReportingProvider::new(
                Box::new(OneFireworksAccountFailureModelProvider {
                    calls: calls.clone(),
                    code,
                    status,
                }),
                "fireworks",
                health.clone(),
            )
            .with_model_scoped_account_failures(true);
            let mut sink = |_| {};

            let first = provider.turn(&request("private-blocked"), &mut sink).await;
            let normalized = first
                .as_ref()
                .expect_err("the selected private model must fail")
                .normalized()
                .expect("fixture must emit a normalized provider failure");
            assert_eq!(
                normalized.availability,
                AvailabilityTransition::Account(expected_availability),
                "the transport classification remains account-scoped for {code}"
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert!(health.is_model_unavailable("fireworks", "private-blocked"));
            assert_eq!(
                health.model_health("fireworks", "private-blocked"),
                Some(ModelHealth {
                    last_error_code: Some(code.into()),
                    last_request_id: None,
                })
            );
            assert_eq!(
                health.get("fireworks"),
                ProviderHealth::default(),
                "a model-scoped {code} failure must not poison account health"
            );
            assert_eq!(
                health.blocked_account("fireworks"),
                None,
                "a model-scoped {code} failure must not gate sibling models"
            );

            assert!(matches!(
                provider.turn(&request("private-blocked"), &mut sink).await,
                Err(ProviderError::KnownModelUnavailable { .. })
            ));
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "the known-bad model made a second inner provider call for {code}"
            );

            assert!(
                provider
                    .turn(&request("public-sibling"), &mut sink)
                    .await
                    .is_ok(),
                "a sibling model must remain callable after {code}"
            );
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            assert_eq!(health.blocked_account("fireworks"), None);
            assert!(health.is_model_unavailable("fireworks", "private-blocked"));
            assert!(
                !health.is_model_unavailable("fireworks", "public-sibling"),
                "the successful sibling must not inherit the failed leaf marker"
            );
        }
    }

    // ---- D1-16: an interrupt must be able to abort an in-flight provider stream ----
    #[tokio::test]
    async fn d1_16_interrupt_aborts_in_flight_provider_stream() {
        use std::sync::atomic::AtomicBool;

        // Records, via its `Drop`, whether the turn future was dropped (aborted) rather than run
        // to completion — the observable proof of mid-stream cancellation.
        struct DropFlag(Arc<AtomicBool>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        // A provider whose stream starts (emits deltas), signals it is in flight, then hangs
        // forever: the model never sends its terminal frame, so the only way the turn can end is
        // by being dropped.
        struct HangingStreamProvider {
            streaming: Arc<AtomicBool>,
            dropped: Arc<AtomicBool>,
        }
        #[async_trait::async_trait]
        impl Provider for HangingStreamProvider {
            async fn turn(
                &self,
                _request: &TurnRequest,
                on_item: &mut (dyn FnMut(StreamItem) + Send),
            ) -> Result<TurnResult, ProviderError> {
                on_item(StreamItem::TextDelta("hel".into()));
                on_item(StreamItem::TextDelta("lo".into()));
                let _guard = DropFlag(self.dropped.clone());
                self.streaming.store(true, Ordering::SeqCst);
                std::future::pending::<()>().await;
                unreachable!("a hung stream can only end by being dropped");
            }
        }

        let cancel = Arc::new(AtomicBool::new(false));
        let streaming = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let provider = HangingStreamProvider {
            streaming: streaming.clone(),
            dropped: dropped.clone(),
        };

        let mut seen: Vec<String> = Vec::new();
        let mut on_item = |item: StreamItem| {
            if let StreamItem::TextDelta(t) = item {
                seen.push(t);
            }
        };

        // Flip the interrupt only once the stream is genuinely in flight, so the test proves the
        // abort happened MID-stream and not before dispatch.
        let cancel_bg = cancel.clone();
        let streaming_bg = streaming.clone();
        let flipper = tokio::spawn(async move {
            while !streaming_bg.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            cancel_bg.store(true, Ordering::SeqCst);
        });

        // If cancellation did not work the call would hang on the stream and the outer timeout
        // would trip instead of returning.
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            turn_cancellable(
                &provider,
                &request("hanging"),
                &mut on_item,
                Some(cancel.as_ref()),
                Duration::from_millis(2),
            ),
        )
        .await
        .expect("turn_cancellable must abort the in-flight stream, not wait for it to finish");
        flipper.await.unwrap();

        assert!(
            matches!(result, Err(ProviderError::Interrupted)),
            "a mid-stream interrupt must surface as ProviderError::Interrupted, got {result:?}"
        );
        assert!(
            dropped.load(Ordering::SeqCst),
            "the in-flight provider stream future must be dropped (aborted), not left running"
        );
        assert_eq!(
            seen,
            vec!["hel".to_string(), "lo".to_string()],
            "stream items emitted before the interrupt must still be observed"
        );

        // Guard against a degenerate always-Interrupted implementation: with the flag never set,
        // a provider that completes must pass straight through as Ok.
        struct DoneProvider;
        #[async_trait::async_trait]
        impl Provider for DoneProvider {
            async fn turn(
                &self,
                _request: &TurnRequest,
                on_item: &mut (dyn FnMut(StreamItem) + Send),
            ) -> Result<TurnResult, ProviderError> {
                on_item(StreamItem::TextDelta("done".into()));
                Ok(TurnResult {
                    blocks: vec![Block::Text {
                        text: "done".into(),
                    }],
                    stop_reason: StopReason::EndTurn,
                    usage: UsageReport::complete(Usage::default()),
                })
            }
        }
        let never = Arc::new(AtomicBool::new(false));
        let mut sink = |_item: StreamItem| {};
        let ok = turn_cancellable(
            &DoneProvider,
            &request("done"),
            &mut sink,
            Some(never.as_ref()),
            Duration::from_millis(2),
        )
        .await
        .expect("a turn that completes before any interrupt must pass through as Ok");
        assert_eq!(ok.text(), "done");
        assert!(!never.load(Ordering::SeqCst));
    }
}
