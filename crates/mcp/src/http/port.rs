//! The narrow port a future HTTP client implements, and the pure request builder above it.
//!
//! This is the only place in the design that a dependency edge would touch. Everything else in
//! [`super`] is arithmetic on bytes.

use super::endpoint::{McpHttpEndpoint, McpHttpHeaderPolicy, validate_header_name};
use crate::{McpError, McpFuture, protocol_version::REQUESTED_PROTOCOL_VERSION, token::Token};
use tokio::io::AsyncBufRead;

/// Both response shapes are advertised on every request, because the server chooses. A client that
/// advertised only one would make a compliant server's other shape look like a protocol error.
pub const MCP_HTTP_ACCEPT: &str = "application/json, text/event-stream";
pub const MCP_JSON_MEDIA_TYPE: &str = "application/json";
pub const MCP_SSE_MEDIA_TYPE: &str = "text/event-stream";
pub const MAX_MCP_SESSION_ID_BYTES: usize = 128;
/// Ceiling on one outbound header value. Held well under what any server accepts for a whole
/// header block, so a value assembled from peer-supplied parts cannot grow the request unbounded.
pub const MAX_MCP_HEADER_VALUE_BYTES: usize = 8192;

/// A session identity issued by the server.
///
/// It is a capability — anyone holding it can act as this session — so its `Debug` is redacted for
/// the same reason [`crate::token::Token`] has none at all. Unlike a bearer token it must be
/// comparable and storable by value, which is why it is redacted rather than unprintable.
#[derive(Clone, PartialEq, Eq)]
pub struct McpSessionId(String);

impl std::fmt::Debug for McpSessionId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("McpSessionId(<redacted>)")
    }
}

impl McpSessionId {
    /// Accept only bounded visible ASCII. A session id is echoed into a request header, so a value
    /// containing CR, LF, or NUL is header injection performed by the peer.
    pub fn parse(value: &str) -> Result<Self, McpError> {
        if value.is_empty()
            || value.len()
                > iteron_tunables::param_integer(
                    "mcp.http.port.max_mcp_session_id_bytes",
                    MAX_MCP_SESSION_ID_BYTES,
                )
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(McpError::InvalidEndpoint {
                field: "session_id",
                limit: iteron_tunables::param_integer(
                    "mcp.http.port.max_mcp_session_id_bytes",
                    MAX_MCP_SESSION_ID_BYTES,
                ),
            });
        }
        Ok(Self(value.to_owned()))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// One request header value.
///
/// Implements neither `Debug` nor `Display`: `authorization` is one of these, and the compiler
/// refusing to interpolate it is worth more than a redaction pass that has to remember.
#[derive(Clone, PartialEq, Eq)]
pub struct McpHeaderValue(String);

impl McpHeaderValue {
    /// Construct a header value, refusing anything that could terminate the header itself.
    pub fn new(value: impl Into<String>) -> Result<Self, McpError> {
        let value = value.into();
        if value.is_empty()
            || value.len()
                > iteron_tunables::param_integer(
                    "mcp.http.port.max_mcp_header_value_bytes",
                    MAX_MCP_HEADER_VALUE_BYTES,
                )
            || !value
                .bytes()
                .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte))
        {
            return Err(McpError::InvalidEndpoint {
                field: "header_value",
                limit: iteron_tunables::param_integer(
                    "mcp.http.port.max_mcp_header_value_bytes",
                    MAX_MCP_HEADER_VALUE_BYTES,
                ),
            });
        }
        Ok(Self(value))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// One outbound HTTP request, fully decided.
///
/// Not `Debug`: it carries the bearer credential. [`Self::public_summary`] is what a diagnostic
/// gets — the method and the authority, never the path, never a header value.
pub struct McpHttpRequest {
    method: &'static str,
    url: String,
    origin: String,
    headers: Vec<(String, McpHeaderValue)>,
    body: String,
}

impl McpHttpRequest {
    pub fn method(&self) -> &'static str {
        self.method
    }

    /// The absolute request URL. Named `expose_` because a path or query can itself be a secret.
    pub fn expose_url(&self) -> &str {
        &self.url
    }

    pub fn headers(&self) -> &[(String, McpHeaderValue)] {
        &self.headers
    }

    pub fn body(&self) -> &str {
        &self.body
    }

    pub fn public_summary(&self) -> String {
        format!("{} {}", self.method, self.origin)
    }
}

/// What a client reports back about one response, before the body is read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct McpHttpResponseHead {
    pub status: u16,
    /// The `content-type` with parameters stripped and lowercased, when present.
    pub media_type: Option<String>,
    /// The `mcp-session-id` the server issued or confirmed.
    pub session_id: Option<McpSessionId>,
    /// `retry-after` in seconds, when it was expressed as delta-seconds.
    pub retry_after_secs: Option<u64>,
}

/// One response: a decided head, plus a body the framing layer reads incrementally.
///
/// The body is an [`AsyncBufRead`] rather than a collected `Vec<u8>` for a reason the SSE case
/// makes unavoidable: an event stream has no length, and collecting it first would mean waiting
/// for a stream that is designed not to end.
pub struct McpHttpResponse {
    pub head: McpHttpResponseHead,
    pub body: Box<dyn AsyncBufRead + Send + Unpin>,
}

/// The dependency edge, as one method.
///
/// Implementations MUST:
/// - **not follow redirects.** The configured endpoint is an authority boundary; a redirect target
///   is chosen by the peer and must never receive the credential or the body. Surface the `3xx`.
/// - **not retry internally.** Retry policy is [`super::classify`]'s output plus
///   [`crate::reconnect`]; a client that silently retries turns one `tools/call` into two, and the
///   second one is invisible to the effect ledger.
/// - **apply their own connect and read timeouts**, since the caller's deadline bounds the whole
///   exchange but cannot bound a socket that never returns.
pub trait McpHttpExchange: Send + Sync {
    fn exchange(&self, request: McpHttpRequest) -> McpFuture<'_, McpHttpResponse>;
}

/// Build the POST that carries one JSON-RPC frame.
///
/// The credential is consulted through [`Token::authorize`], which refuses inside the refresh skew
/// margin. That refusal happens *here*, before dispatch, and it is the whole point: a token that
/// expires in flight produces a 401 that is indistinguishable from a revocation, so the transport
/// must never be the thing that discovers expiry.
pub fn build_post(
    endpoint: &McpHttpEndpoint,
    credential: Option<&Token>,
    now_secs: u64,
    session: Option<&McpSessionId>,
    extra: &[(String, McpHeaderValue)],
    policy: &McpHttpHeaderPolicy,
    frame: String,
) -> Result<McpHttpRequest, McpError> {
    build_post_with_version(
        endpoint,
        credential,
        now_secs,
        session,
        extra,
        policy,
        (REQUESTED_PROTOCOL_VERSION, frame),
    )
}

/// Build a POST using the protocol revision selected by initialize negotiation.
///
/// [`build_post`] remains the useful pre-handshake/default form. A live HTTP session must switch
/// to this form after initialize because the transport contract requires every subsequent request
/// to carry the negotiated revision, which can be older than the version the client proposed.
pub(crate) fn build_post_with_version(
    endpoint: &McpHttpEndpoint,
    credential: Option<&Token>,
    now_secs: u64,
    session: Option<&McpSessionId>,
    extra: &[(String, McpHeaderValue)],
    policy: &McpHttpHeaderPolicy,
    protocol_frame: (&str, String),
) -> Result<McpHttpRequest, McpError> {
    let (protocol_version, frame) = protocol_frame;
    if frame.len() > crate::MAX_FRAME_BYTES {
        return Err(McpError::FrameTooLarge {
            limit: crate::MAX_FRAME_BYTES,
        });
    }
    let mut headers = vec![
        (
            "accept".to_owned(),
            McpHeaderValue::new(iteron_tunables::param_str(
                "mcp.http.port.mcp_http_accept",
                MCP_HTTP_ACCEPT,
            ))?,
        ),
        (
            "content-type".to_owned(),
            McpHeaderValue::new(MCP_JSON_MEDIA_TYPE)?,
        ),
        (
            "mcp-protocol-version".to_owned(),
            McpHeaderValue::new(protocol_version)?,
        ),
    ];
    if let Some(credential) = credential {
        let secret = credential.authorize(now_secs)?;
        headers.push((
            "authorization".to_owned(),
            McpHeaderValue::new(format!("Bearer {secret}"))?,
        ));
    }
    if let Some(session) = session {
        headers.push((
            "mcp-session-id".to_owned(),
            McpHeaderValue::new(session.expose())?,
        ));
    }
    // Operator headers are appended last but validated against the same reserved set that
    // configuration was validated against, so a later code path cannot smuggle one in.
    for (name, value) in extra {
        validate_header_name(name)?;
        if !policy.names().iter().any(|declared| declared == name) {
            return Err(McpError::InvalidEndpoint {
                field: "undeclared_header",
                limit: policy.names().len(),
            });
        }
        headers.push((name.clone(), value.clone()));
    }
    Ok(McpHttpRequest {
        method: "POST",
        url: endpoint.expose_url(),
        origin: endpoint.public_origin(),
        headers,
        body: frame,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::{EXPIRY_SKEW_SECS, TokenError};

    fn endpoint() -> McpHttpEndpoint {
        McpHttpEndpoint::parse("https://example.com/mcp").unwrap()
    }

    fn header<'a>(request: &'a McpHttpRequest, name: &str) -> Option<&'a str> {
        request
            .headers()
            .iter()
            .find(|(header, _)| header == name)
            .map(|(_, value)| value.expose())
    }

    #[test]
    fn a_post_advertises_both_response_shapes_and_the_negotiated_protocol_version() {
        let request = build_post(
            &endpoint(),
            None,
            0,
            None,
            &[],
            &McpHttpHeaderPolicy::default(),
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}".into(),
        )
        .unwrap();
        assert_eq!(request.method(), "POST");
        assert_eq!(request.expose_url(), "https://example.com:443/mcp");
        assert_eq!(header(&request, "accept"), Some(MCP_HTTP_ACCEPT));
        assert_eq!(header(&request, "content-type"), Some(MCP_JSON_MEDIA_TYPE));
        assert_eq!(
            header(&request, "mcp-protocol-version"),
            Some(REQUESTED_PROTOCOL_VERSION)
        );
        assert_eq!(header(&request, "authorization"), None);
        assert_eq!(header(&request, "mcp-session-id"), None);
    }

    #[test]
    fn a_credential_inside_the_refresh_margin_is_refused_before_dispatch_not_after_a_401() {
        // The failure this prevents: the request goes out with a token that expires in flight, the
        // 401 comes back, and a stale credential is now indistinguishable from a revoked one at
        // exactly the moment an operator needs them separated.
        let token = Token::new("sk-live-secret", 1_000);
        let fresh = build_post(
            &endpoint(),
            Some(&token),
            900,
            None,
            &[],
            &McpHttpHeaderPolicy::default(),
            "{}".into(),
        )
        .unwrap();
        assert_eq!(
            header(&fresh, "authorization"),
            Some("Bearer sk-live-secret")
        );

        let stale = build_post(
            &endpoint(),
            Some(&token),
            1_000 - EXPIRY_SKEW_SECS,
            None,
            &[],
            &McpHttpHeaderPolicy::default(),
            "{}".into(),
        );
        assert!(matches!(
            stale,
            Err(McpError::Credential(TokenError::Expired { .. }))
        ));

        let mut revoked = Token::new("sk-live-secret", u64::MAX);
        revoked.revoke();
        assert!(matches!(
            build_post(
                &endpoint(),
                Some(&revoked),
                0,
                None,
                &[],
                &McpHttpHeaderPolicy::default(),
                "{}".into()
            ),
            Err(McpError::Credential(TokenError::Revoked))
        ));
    }

    #[test]
    fn no_diagnostic_reaches_the_credential_the_path_or_the_session() {
        let token = Token::new("sk-live-secret", u64::MAX);
        let session = McpSessionId::parse("sess-abcdef").unwrap();
        let request = build_post(
            &McpHttpEndpoint::parse("https://example.com/hooks/s3cr3t").unwrap(),
            Some(&token),
            0,
            Some(&session),
            &[],
            &McpHttpHeaderPolicy::default(),
            "{}".into(),
        )
        .unwrap();
        let summary = request.public_summary();
        assert_eq!(summary, "POST https://example.com:443");
        assert!(!summary.contains("sk-live-secret"));
        assert!(!summary.contains("s3cr3t"));
        assert!(!summary.contains("sess-abcdef"));
        // The session id is storable and comparable, so it is redacted rather than unprintable.
        assert_eq!(format!("{session:?}"), "McpSessionId(<redacted>)");
        assert!(!format!("{session:?}").contains("abcdef"));
        // And a credential-bearing error never carries the value either.
        let expired = Token::new("sk-live-secret", 0);
        let Err(error) = build_post(
            &endpoint(),
            Some(&expired),
            10,
            None,
            &[],
            &McpHttpHeaderPolicy::default(),
            "{}".into(),
        ) else {
            panic!("an expired credential must refuse the request");
        };
        assert!(!error.to_string().contains("sk-live-secret"));
        assert!(!error.public_summary().contains("sk-live-secret"));
    }

    #[test]
    fn a_peer_supplied_session_id_cannot_inject_a_header() {
        // The server controls this value, and it is echoed straight back into a request header.
        for hostile in [
            "sess\r\nauthorization: Bearer stolen",
            "sess\nx: y",
            "sess id",
            "sess\0",
            "",
        ] {
            assert!(
                matches!(
                    McpSessionId::parse(hostile),
                    Err(McpError::InvalidEndpoint {
                        field: "session_id",
                        ..
                    })
                ),
                "must refuse: {hostile:?}"
            );
        }
        assert!(McpSessionId::parse(&"s".repeat(MAX_MCP_SESSION_ID_BYTES)).is_ok());
        assert!(McpSessionId::parse(&"s".repeat(MAX_MCP_SESSION_ID_BYTES + 1)).is_err());
    }

    #[test]
    fn a_header_value_can_never_terminate_its_own_header() {
        assert!(McpHeaderValue::new("plain").is_ok());
        assert!(McpHeaderValue::new("with\ttab").is_ok());
        for hostile in ["a\r\nb: c", "a\nb", "a\0b", ""] {
            assert!(McpHeaderValue::new(hostile).is_err(), "{hostile:?}");
        }
    }

    #[test]
    fn an_extra_header_must_be_both_admissible_and_declared() {
        let policy = McpHttpHeaderPolicy::new(vec!["x-tenant".into()]).unwrap();
        let declared = vec![("x-tenant".to_owned(), McpHeaderValue::new("acme").unwrap())];
        let request =
            build_post(&endpoint(), None, 0, None, &declared, &policy, "{}".into()).unwrap();
        assert_eq!(header(&request, "x-tenant"), Some("acme"));

        // Declared in code but absent from operator configuration: refused, so a code path cannot
        // add a header the operator never agreed to send to this endpoint.
        let undeclared = vec![("x-other".to_owned(), McpHeaderValue::new("v").unwrap())];
        assert!(matches!(
            build_post(
                &endpoint(),
                None,
                0,
                None,
                &undeclared,
                &policy,
                "{}".into()
            ),
            Err(McpError::InvalidEndpoint {
                field: "undeclared_header",
                ..
            })
        ));

        // And reserved names are refused even when a policy somehow lists them.
        let forged = vec![(
            "authorization".to_owned(),
            McpHeaderValue::new("Bearer stolen").unwrap(),
        )];
        assert!(build_post(&endpoint(), None, 0, None, &forged, &policy, "{}".into()).is_err());
    }

    #[test]
    fn an_oversized_frame_is_refused_at_the_same_ceiling_as_the_pipe_transport() {
        let oversized = "x".repeat(crate::MAX_FRAME_BYTES + 1);
        assert!(matches!(
            build_post(
                &endpoint(),
                None,
                0,
                None,
                &[],
                &McpHttpHeaderPolicy::default(),
                oversized
            ),
            Err(McpError::FrameTooLarge { .. })
        ));
    }
}
