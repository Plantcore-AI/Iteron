//! The failure taxonomy: turning a status code into a decision, and into a certainty.
//!
//! Two orthogonal questions come out of one status code, and conflating them is the classic bug:
//!
//! 1. **What should the transport do next?** — [`McpHttpDisposition`].
//! 2. **May the tool already have run?** — [`effect_certainty`].
//!
//! They are orthogonal because the answers disagree. A `500` is retryable *and* the effect may
//! already have been applied; retrying it can apply the effect twice. A `429` is retryable *and*
//! definitely not applied; retrying it is free. A transport that only tracked "retryable" would
//! treat those identically, which is how a retry loop silently duplicates a write.

use crate::McpError;

/// Longest `content-type` token accepted before parameters are stripped. A real media type is far
/// shorter, so anything past this is a hostile header, not a type this client must understand.
const MAX_MEDIA_TYPE_BYTES: usize = 128;
/// Digits accepted in a `Retry-After` delta-seconds value. Bounding the text before `parse` keeps
/// a long digit run from being parsed at all.
const MAX_RETRY_AFTER_DIGITS: usize = 6;
/// Longest honoured `Retry-After` delay. Beyond one hour the peer is effectively asking this
/// client to stall forever, and the reconnect policy's own backoff is the better answer.
const MAX_RETRY_AFTER_SECS: u64 = 3_600;

/// Whether an effect may already exist on the far side.
///
/// This is the same axis `McpToolOutcome::{FailedDefinite, Unknown}` carries. `Unknown` is the
/// conservative answer and must be the default for anything ambiguous: reporting a definite
/// failure for a call that actually ran is the direction that loses data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpEffectCertainty {
    /// The peer provably did not act on this request.
    Definite,
    /// The peer may have acted. Never retry a non-idempotent call on this.
    Unknown,
}

/// What the transport does with one response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpHttpDisposition {
    /// `200`: a body carrying one or more JSON-RPC messages.
    Body,
    /// `202`/`204`: accepted with no body. Correct for a notification, a protocol error for a
    /// request, because a request that gets no response can never be correlated.
    Accepted,
    /// `401`/`403`: the credential was rejected. `revoke` distinguishes "refresh and retry" from
    /// "this credential is finished" — a `403` that keeps being retried with the same token is an
    /// account lockout waiting to happen.
    Unauthorized { revoke: bool },
    /// `404` while a session was in flight: the server forgot the session. Re-initialize; do not
    /// treat it as a missing endpoint, because the URL was right a moment ago.
    SessionExpired,
    /// Worth another attempt after backoff.
    Retry,
    /// `3xx`: answered, never followed.
    Redirect,
    /// Everything else, including a `404` with no session in flight.
    Terminal,
}

/// Classify one status.
///
/// `has_session` is load-bearing on exactly one code: a `404` means "no such endpoint" when no
/// session exists and "your session is gone" when one does. Getting that wrong sends an operator
/// to check a URL that was never wrong.
pub const fn classify(status: u16, has_session: bool) -> McpHttpDisposition {
    match status {
        200 => McpHttpDisposition::Body,
        202 | 204 => McpHttpDisposition::Accepted,
        300..=399 => McpHttpDisposition::Redirect,
        401 => McpHttpDisposition::Unauthorized { revoke: false },
        403 => McpHttpDisposition::Unauthorized { revoke: true },
        404 if has_session => McpHttpDisposition::SessionExpired,
        408 | 425 | 429 => McpHttpDisposition::Retry,
        500..=599 => McpHttpDisposition::Retry,
        _ => McpHttpDisposition::Terminal,
    }
}

/// Whether a `tools/call` that met this status may already have taken effect.
///
/// The two carve-outs are the point. `501 Not Implemented` and `503 Service Unavailable` are the
/// server stating it did not run the request; every other 5xx, and `408 Request Timeout`, mean the
/// server had the bytes and something failed afterwards — the tool may well have executed. Every
/// 4xx other than `408` is a rejection before dispatch.
pub const fn effect_certainty(status: u16) -> McpEffectCertainty {
    match status {
        408 => McpEffectCertainty::Unknown,
        501 | 503 => McpEffectCertainty::Definite,
        500..=599 => McpEffectCertainty::Unknown,
        _ => McpEffectCertainty::Definite,
    }
}

impl McpHttpDisposition {
    /// The typed failure for a disposition that cannot yield a response, or `None` when the
    /// response is usable.
    pub fn into_error(self, status: u16) -> Option<McpError> {
        match self {
            Self::Body | Self::Accepted => None,
            Self::Redirect => Some(McpError::HttpRedirectRefused),
            Self::SessionExpired => Some(McpError::SessionExpired),
            Self::Unauthorized { .. } | Self::Retry | Self::Terminal => {
                Some(McpError::HttpStatus { status })
            }
        }
    }

    /// Whether another attempt is admissible *for an idempotent request*. Callers holding a
    /// non-idempotent request must consult [`effect_certainty`] as well.
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::Retry)
    }
}

/// Strip parameters from a `content-type` and lowercase it.
///
/// Refuses anything that is not a bounded token, so a hostile media type cannot become a large
/// allocation or reach a diagnostic with control characters in it.
pub fn parse_media_type(header: &str) -> Option<String> {
    let media_type = header.split(';').next()?.trim();
    if media_type.is_empty()
        || media_type.len()
            > iteron_tunables::param_integer(
                "mcp.http.status.max_media_type_bytes",
                MAX_MEDIA_TYPE_BYTES,
            )
        || !media_type.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'+' | b'.' | b'_')
        })
    {
        return None;
    }
    Some(media_type.to_ascii_lowercase())
}

/// Parse `Retry-After` as delta-seconds, bounded to one hour.
///
/// The HTTP-date form is deliberately not parsed and yields `None`: parsing dates needs either a
/// dependency or a hand-rolled calendar, and a wrong answer here schedules a retry at the wrong
/// time. `None` falls back to the reconnect policy's own backoff, which is always safe.
pub fn parse_retry_after(header: &str) -> Option<u64> {
    let value = header.trim();
    if value.is_empty()
        || value.len()
            > iteron_tunables::param_integer(
                "mcp.http.status.max_retry_after_digits",
                MAX_RETRY_AFTER_DIGITS,
            )
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    value.parse::<u64>().ok().filter(|secs| {
        *secs
            <= iteron_tunables::param_integer(
                "mcp.http.status.max_retry_after_secs",
                MAX_RETRY_AFTER_SECS,
            )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_retryable_status_and_an_uncertain_effect_are_not_the_same_question() {
        // The failure this prevents: one "retryable" flag drives the retry loop, so a 500 whose
        // tool already ran is retried exactly like a 429 that never reached the tool, and the
        // effect is applied twice with nothing recording the duplicate.
        assert!(classify(500, false).is_retryable());
        assert!(classify(429, false).is_retryable());
        assert_eq!(effect_certainty(500), McpEffectCertainty::Unknown);
        assert_eq!(effect_certainty(429), McpEffectCertainty::Definite);
    }

    #[test]
    fn the_two_statuses_that_promise_the_request_was_not_served_stay_definite() {
        assert_eq!(effect_certainty(501), McpEffectCertainty::Definite);
        assert_eq!(effect_certainty(503), McpEffectCertainty::Definite);
        for uncertain in [408, 500, 502, 504, 507, 599] {
            assert_eq!(
                effect_certainty(uncertain),
                McpEffectCertainty::Unknown,
                "status {uncertain} had the bytes; the tool may have run"
            );
        }
        for definite in [200, 400, 401, 403, 404, 405, 409, 413, 415, 422, 429] {
            assert_eq!(
                effect_certainty(definite),
                McpEffectCertainty::Definite,
                "status {definite} is a rejection before dispatch"
            );
        }
    }

    #[test]
    fn a_404_means_two_different_things_depending_on_whether_a_session_exists() {
        assert_eq!(classify(404, false), McpHttpDisposition::Terminal);
        assert_eq!(classify(404, true), McpHttpDisposition::SessionExpired);
        assert!(matches!(
            classify(404, true).into_error(404),
            Some(McpError::SessionExpired)
        ));
    }

    #[test]
    fn a_redirect_is_answered_and_never_followed() {
        for status in [301, 302, 303, 307, 308] {
            assert_eq!(classify(status, false), McpHttpDisposition::Redirect);
            assert!(matches!(
                classify(status, false).into_error(status),
                Some(McpError::HttpRedirectRefused)
            ));
            assert!(!classify(status, false).is_retryable());
        }
    }

    #[test]
    fn a_403_marks_the_credential_finished_and_a_401_only_asks_for_a_refresh() {
        // Retrying a 403 with the same credential is how an account gets locked out.
        assert_eq!(
            classify(401, false),
            McpHttpDisposition::Unauthorized { revoke: false }
        );
        assert_eq!(
            classify(403, false),
            McpHttpDisposition::Unauthorized { revoke: true }
        );
        assert!(!classify(401, false).is_retryable());
        assert!(!classify(403, false).is_retryable());
    }

    #[test]
    fn success_shapes_carry_no_error_and_the_status_reaches_the_diagnostic() {
        assert!(classify(200, false).into_error(200).is_none());
        assert_eq!(classify(202, false), McpHttpDisposition::Accepted);
        assert_eq!(classify(204, true), McpHttpDisposition::Accepted);
        let error = classify(418, false).into_error(418).unwrap();
        assert_eq!(
            error.public_summary(),
            "MCP HTTP endpoint returned status 418"
        );
    }

    #[test]
    fn media_types_lose_their_parameters_and_hostile_ones_are_dropped() {
        assert_eq!(
            parse_media_type("text/event-stream; charset=utf-8").as_deref(),
            Some("text/event-stream")
        );
        assert_eq!(
            parse_media_type("Application/JSON").as_deref(),
            Some("application/json")
        );
        for hostile in [
            "",
            "  ",
            "text/\u{1b}[31m",
            &"a".repeat(129),
            "text/event stream",
        ] {
            assert_eq!(parse_media_type(hostile), None, "{hostile:?}");
        }
    }

    #[test]
    fn retry_after_accepts_delta_seconds_and_declines_to_guess_at_dates() {
        assert_eq!(parse_retry_after("30"), Some(30));
        assert_eq!(parse_retry_after("  30 "), Some(30));
        assert_eq!(parse_retry_after("3600"), Some(3_600));
        // Over the ceiling, and the HTTP-date form: both fall back to the reconnect policy's own
        // backoff rather than to a number this module guessed.
        assert_eq!(parse_retry_after("3601"), None);
        assert_eq!(parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT"), None);
        assert_eq!(parse_retry_after("-1"), None);
        assert_eq!(parse_retry_after(""), None);
        assert_eq!(parse_retry_after("99999999999999"), None);
    }
}
