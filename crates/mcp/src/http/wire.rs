//! The HTTP transport itself, over the [`McpHttpExchange`] port.
//!
//! Everything here is decision logic: build the request, classify the status, pick the framing,
//! carry the session forward. It is a complete transport that runs, and is tested, against a fake
//! exchange — which is the point. When an HTTP client is admitted, the change is one `impl
//! McpHttpExchange`, not a new transport.

use super::{
    McpEffectCertainty, McpHttpDisposition, McpHttpEndpoint, McpHttpExchange, McpHttpHeaderPolicy,
    McpHttpResponse, McpSessionId, classify, effect_certainty,
    port::{McpHeaderValue, build_post_with_version},
    sse::{SseInbound, SseLimits, read_json_response, read_matching_sse_response_with},
};
use crate::{
    MAX_FRAME_BYTES, McpError, McpFuture, McpTransportKind, McpWire, request, token::Token,
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::sync::{Mutex, RwLock};

/// Monotonic seconds, in the domain [`Token`] expiry is expressed in.
///
/// Injected rather than read from a global clock: token expiry is the one thing in this transport
/// whose bugs only appear at a particular time of day, so it must be exactly reproducible in a
/// test rather than approximately reproducible on a machine.
pub type NowSecs = Arc<dyn Fn() -> u64 + Send + Sync>;

/// An MCP server reached over HTTP.
pub struct McpHttpWire<E: McpHttpExchange> {
    endpoint: McpHttpEndpoint,
    exchange: E,
    now_secs: NowSecs,
    credential: Mutex<Option<Token>>,
    session: Mutex<Option<McpSessionId>>,
    header_policy: McpHttpHeaderPolicy,
    extra_headers: Vec<(String, McpHeaderValue)>,
    limits: SseLimits,
    protocol_version: RwLock<String>,
    elicitation: Option<Arc<dyn crate::McpElicitationHandler>>,
    next_id: AtomicU64,
    pub server_name: String,
}

impl<E: McpHttpExchange> McpHttpWire<E> {
    pub fn new(
        endpoint: McpHttpEndpoint,
        exchange: E,
        now_secs: NowSecs,
        server_name: String,
    ) -> Result<Self, McpError> {
        crate::tool_filter::validate_server_name(&server_name)?;
        Ok(Self {
            endpoint,
            exchange,
            now_secs,
            credential: Mutex::new(None),
            session: Mutex::new(None),
            header_policy: McpHttpHeaderPolicy::default(),
            extra_headers: Vec::new(),
            limits: SseLimits::default(),
            protocol_version: RwLock::new(
                crate::protocol_version::REQUESTED_PROTOCOL_VERSION.to_owned(),
            ),
            elicitation: None,
            next_id: AtomicU64::new(1),
            server_name,
        })
    }

    pub fn with_credential(self, credential: Token) -> Self {
        Self {
            credential: Mutex::new(Some(credential)),
            ..self
        }
    }

    /// Replace the bearer credential after an OAuth refresh. The old token is dropped while the
    /// mutex is held and can never race into a later request.
    pub async fn replace_credential(&self, credential: Token) {
        *self.credential.lock().await = Some(credential);
    }

    pub async fn credential_state(&self, now_secs: u64) -> crate::token::State {
        self.credential
            .lock()
            .await
            .as_ref()
            .map_or(crate::token::State::Absent, |credential| {
                credential.state(now_secs)
            })
    }

    /// Mark the current credential terminally revoked after an authorization server refusal.
    pub async fn revoke_credential(&self) {
        if let Some(credential) = self.credential.lock().await.as_mut() {
            credential.revoke();
        }
    }

    /// Declare the operator's extra headers and their resolved values together, so a value can
    /// never be attached to a name the operator did not admit.
    pub fn with_headers(
        self,
        policy: McpHttpHeaderPolicy,
        values: Vec<(String, McpHeaderValue)>,
    ) -> Result<Self, McpError> {
        for (name, _) in &values {
            if !policy.names().iter().any(|declared| declared == name) {
                return Err(McpError::InvalidEndpoint {
                    field: "undeclared_header",
                    limit: policy.names().len(),
                });
            }
        }
        Ok(Self {
            header_policy: policy,
            extra_headers: values,
            ..self
        })
    }

    pub fn with_limits(self, limits: SseLimits) -> Self {
        Self { limits, ..self }
    }

    /// Pin the revision selected by the initialize handshake for every later HTTP request.
    pub async fn set_protocol_version(&self, version: impl Into<String>) {
        *self.protocol_version.write().await = version.into();
    }

    pub fn with_elicitation_handler(self, handler: Arc<dyn crate::McpElicitationHandler>) -> Self {
        Self {
            elicitation: Some(handler),
            ..self
        }
    }

    pub fn endpoint(&self) -> &McpHttpEndpoint {
        &self.endpoint
    }

    /// The session identity the server issued, if any.
    pub async fn session(&self) -> Option<McpSessionId> {
        self.session.lock().await.clone()
    }

    /// Send one request and report both the result and whether a failure may already have taken
    /// effect on the server.
    ///
    /// The certainty is not an afterthought on the error: it is what
    /// `McpToolOutcome::{FailedDefinite, Unknown}` is built from, and losing it turns "the tool may
    /// have run" into "the tool failed".
    pub async fn call_with_certainty(
        &self,
        method: &str,
        params: Value,
    ) -> (Result<Value, McpError>, McpEffectCertainty) {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let frame = match request(id, method, params) {
            Ok(frame) => frame,
            // Nothing was dispatched: serialization failed before any byte could leave.
            Err(error) => return (Err(error), McpEffectCertainty::Definite),
        };
        let (head, body) = match self.dispatch(frame).await {
            Ok(response) => (response.head, response.body),
            Err(error) => {
                let certainty = certainty_of(&error);
                return (Err(error), certainty);
            }
        };
        let status = head.status;
        let disposition = classify(
            status,
            head.session_id.is_some() || self.has_session().await,
        );
        if let Some(session_id) = head.session_id {
            *self.session.lock().await = Some(session_id);
        }
        if let Some(error) = disposition.into_error(status) {
            return (Err(error), effect_certainty(status));
        }
        if disposition == McpHttpDisposition::Accepted {
            return (
                Err(McpError::Protocol(
                    "request answered without a JSON-RPC response".into(),
                )),
                // The peer accepted the bytes and declined to answer; it may well have acted.
                McpEffectCertainty::Unknown,
            );
        }
        let result = self.read_body(head.media_type.as_deref(), body, id).await;
        let certainty = match &result {
            Ok(_) => McpEffectCertainty::Definite,
            // A matching JSON-RPC error is an authoritative remote terminal, exactly as on stdio.
            Err(McpError::Server { .. }) => McpEffectCertainty::Definite,
            // Every framing or truncation failure happens after the server had the request.
            Err(_) => McpEffectCertainty::Unknown,
        };
        (result, certainty)
    }

    async fn has_session(&self) -> bool {
        self.session.lock().await.is_some()
    }

    async fn dispatch(&self, frame: String) -> Result<McpHttpResponse, McpError> {
        let credential = self.credential.lock().await;
        let session = self.session.lock().await.clone();
        let protocol_version = self.protocol_version.read().await.clone();
        let http_request = build_post_with_version(
            &self.endpoint,
            credential.as_ref(),
            (self.now_secs)(),
            session.as_ref(),
            &self.extra_headers,
            &self.header_policy,
            (&protocol_version, frame),
        )?;
        drop(credential);
        self.exchange.exchange(http_request).await
    }

    async fn read_body(
        &self,
        media_type: Option<&str>,
        mut body: Box<dyn tokio::io::AsyncBufRead + Send + Unpin>,
        id: u64,
    ) -> Result<Value, McpError> {
        match media_type {
            Some(super::MCP_JSON_MEDIA_TYPE) => {
                read_json_response(&mut body, id, MAX_FRAME_BYTES).await
            }
            Some(super::MCP_SSE_MEDIA_TYPE) => {
                read_matching_sse_response_with(body, id, self.limits, self).await
            }
            // Guessing is the failure mode: a proxy error page served as `text/html` would be fed
            // to the JSON parser and reported as a protocol violation by the MCP server.
            _ => Err(McpError::UnsupportedMediaType),
        }
    }

    async fn answer_inbound(&self, message: Value) -> Result<(), McpError> {
        let Some(id) = message.get("id").cloned() else {
            // Notifications do not receive JSON-RPC responses. Unknown notifications are ignored
            // so an additive server feature cannot tear down an otherwise valid tool response.
            return Ok(());
        };
        if !(id.is_u64() || id.is_i64() || id.is_string()) {
            return self
                .send_server_response(json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": {"code": -32600, "message": "Invalid Request"}
                }))
                .await;
        }
        let method = message.get("method").and_then(Value::as_str);
        let result = match (method, self.elicitation.as_ref()) {
            (Some("elicitation/create"), Some(handler)) => {
                let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
                match crate::ElicitationRequest::parse(params) {
                    Ok(request) => match handler.elicit(&self.server_name, request.clone()).await {
                        Ok(response) => response.into_result(&request),
                        Err(_) => Err(McpError::Protocol("elicitation handler failed".into())),
                    },
                    Err(error) => Err(error),
                }
            }
            (Some("elicitation/create"), None) => {
                return self
                    .send_server_response(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {"code": -32601, "message": "Method not found"}
                    }))
                    .await;
            }
            _ => {
                return self
                    .send_server_response(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {"code": -32601, "message": "Method not found"}
                    }))
                    .await;
            }
        };
        let response = match result {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err(_) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32602, "message": "Invalid params"}
            }),
        };
        self.send_server_response(response).await
    }

    async fn send_server_response(&self, response: Value) -> Result<(), McpError> {
        let frame = crate::encode_frame(&response)?;
        let response = self.dispatch(frame).await?;
        let status = response.head.status;
        if let Some(session_id) = response.head.session_id {
            *self.session.lock().await = Some(session_id);
        }
        match classify(status, self.has_session().await).into_error(status) {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl<E: McpHttpExchange> SseInbound for McpHttpWire<E> {
    fn handle<'a>(&'a self, message: Value) -> McpFuture<'a, ()> {
        Box::pin(async move { self.answer_inbound(message).await })
    }
}

/// A transport failure raised before any status was seen. The request may or may not have been
/// written to the socket, and nothing here can tell, so the conservative answer is the only
/// honest one — except for a credential refusal, which happens strictly before dispatch.
fn certainty_of(error: &McpError) -> McpEffectCertainty {
    match error {
        McpError::Credential(_)
        | McpError::InvalidEndpoint { .. }
        | McpError::FrameTooLarge { .. } => McpEffectCertainty::Definite,
        _ => McpEffectCertainty::Unknown,
    }
}

impl<E: McpHttpExchange> McpWire for McpHttpWire<E> {
    fn transport_kind(&self) -> McpTransportKind {
        McpTransportKind::Http
    }

    fn send_request<'a>(&'a self, method: &'a str, params: Value) -> McpFuture<'a, Value> {
        Box::pin(async move { self.call_with_certainty(method, params).await.0 })
    }

    fn send_notification<'a>(&'a self, method: &'a str, params: Value) -> McpFuture<'a, ()> {
        Box::pin(async move {
            let frame = crate::encode_frame(&json!({
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
            }))?;
            let response = self.dispatch(frame).await?;
            let status = response.head.status;
            let disposition = classify(status, response.head.session_id.is_some());
            if let Some(session_id) = response.head.session_id {
                *self.session.lock().await = Some(session_id);
            }
            match disposition.into_error(status) {
                Some(error) => Err(error),
                // A body is legal here (a server may answer a notification with an empty stream);
                // it is simply not read, because there is nothing to correlate it with.
                None => Ok(()),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{McpHttpRequest, McpHttpResponseHead};
    use std::sync::Mutex as StdMutex;
    use tokio::io::BufReader;

    /// A scripted exchange. It records what it was asked to send, so the request-side contract is
    /// observable, and replays canned responses in order.
    struct ScriptedExchange {
        responses: StdMutex<Vec<(McpHttpResponseHead, String)>>,
        seen: StdMutex<Vec<(String, Vec<String>, String)>>,
    }

    impl ScriptedExchange {
        fn new(responses: Vec<(McpHttpResponseHead, String)>) -> Arc<Self> {
            Arc::new(Self {
                responses: StdMutex::new(responses.into_iter().rev().collect()),
                seen: StdMutex::new(Vec::new()),
            })
        }

        fn header_names(&self, index: usize) -> Vec<String> {
            self.seen.lock().unwrap()[index].1.clone()
        }

        fn body(&self, index: usize) -> String {
            self.seen.lock().unwrap()[index].2.clone()
        }

        fn call_count(&self) -> usize {
            self.seen.lock().unwrap().len()
        }
    }

    impl McpHttpExchange for Arc<ScriptedExchange> {
        fn exchange(&self, request: McpHttpRequest) -> McpFuture<'_, McpHttpResponse> {
            self.seen.lock().unwrap().push((
                request.expose_url().to_owned(),
                request
                    .headers()
                    .iter()
                    .map(|(name, _)| name.clone())
                    .collect(),
                request.body().to_owned(),
            ));
            let next = self.responses.lock().unwrap().pop();
            Box::pin(async move {
                let (head, body) = next.ok_or(McpError::TransportClosed)?;
                Ok(McpHttpResponse {
                    head,
                    body: Box::new(BufReader::new(std::io::Cursor::new(body.into_bytes()))),
                })
            })
        }
    }

    fn head(status: u16, media_type: Option<&str>) -> McpHttpResponseHead {
        McpHttpResponseHead {
            status,
            media_type: media_type.map(str::to_owned),
            session_id: None,
            retry_after_secs: None,
        }
    }

    fn http_wire(exchange: Arc<ScriptedExchange>) -> McpHttpWire<Arc<ScriptedExchange>> {
        McpHttpWire::new(
            McpHttpEndpoint::parse("https://example.com/mcp").unwrap(),
            exchange,
            Arc::new(|| 1_000),
            "remote".into(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn a_json_response_completes_a_request_and_the_wire_reports_its_transport() {
        let exchange = ScriptedExchange::new(vec![(
            head(200, Some("application/json")),
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}".into(),
        )]);
        let wire = http_wire(exchange.clone());
        assert_eq!(wire.transport_kind(), McpTransportKind::Http);
        let result = wire.send_request("tools/list", json!({})).await.unwrap();
        assert!(result.get("tools").is_some());
        assert_eq!(exchange.call_count(), 1);
        assert!(exchange.body(0).contains("\"method\":\"tools/list\""));
        assert_eq!(
            exchange.header_names(0),
            ["accept", "content-type", "mcp-protocol-version"]
        );
    }

    #[tokio::test]
    async fn an_event_stream_response_is_framed_past_interleaved_notifications() {
        let exchange = ScriptedExchange::new(vec![(
            head(200, Some("text/event-stream")),
            concat!(
                ": keepalive\n",
                "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\"}\n\n",
                "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[]}}\n\n",
            )
            .into(),
        )]);
        let result = http_wire(exchange)
            .send_request("tools/call", json!({"name": "t"}))
            .await
            .unwrap();
        assert!(result.get("content").is_some());
    }

    struct AcceptPublicName;

    impl crate::McpElicitationHandler for AcceptPublicName {
        fn elicit<'a>(
            &'a self,
            server_name: &'a str,
            request: crate::ElicitationRequest,
        ) -> McpFuture<'a, crate::ElicitationResponse> {
            Box::pin(async move {
                assert_eq!(server_name, "remote");
                assert_eq!(request.message(), "Choose a public name");
                Ok(crate::ElicitationResponse::accept(json!({"name": "leaf"})))
            })
        }
    }

    #[tokio::test]
    async fn an_interleaved_elicitation_is_answered_before_the_original_response_completes() {
        let exchange = ScriptedExchange::new(vec![
            (
                head(200, Some("text/event-stream")),
                concat!(
                    "data: {\"jsonrpc\":\"2.0\",\"id\":\"ask-1\",\"method\":\"elicitation/create\",",
                    "\"params\":{\"mode\":\"form\",\"message\":\"Choose a public name\",",
                    "\"requestedSchema\":{\"type\":\"object\",\"properties\":{",
                    "\"name\":{\"type\":\"string\"}},\"required\":[\"name\"]}}}\n\n",
                    "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[]}}\n\n",
                )
                .into(),
            ),
            (head(202, None), String::new()),
        ]);
        let wire = http_wire(exchange.clone()).with_elicitation_handler(Arc::new(AcceptPublicName));
        let result = wire
            .send_request("tools/call", json!({"name": "interactive"}))
            .await
            .unwrap();
        assert!(result.get("content").is_some());
        assert_eq!(exchange.call_count(), 2);
        assert!(exchange.body(1).contains("\"id\":\"ask-1\""));
        assert!(exchange.body(1).contains("\"action\":\"accept\""));
        assert!(exchange.body(1).contains("\"name\":\"leaf\""));
    }

    #[tokio::test]
    async fn an_unadvertised_elicitation_fails_closed_and_the_tool_response_still_arrives() {
        let exchange = ScriptedExchange::new(vec![
            (
                head(200, Some("text/event-stream")),
                concat!(
                    "data: {\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"elicitation/create\",\"params\":{}}\n\n",
                    "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n",
                )
                .into(),
            ),
            (head(202, None), String::new()),
        ]);
        let result = http_wire(exchange.clone())
            .send_request("tools/call", json!({}))
            .await
            .unwrap();
        assert_eq!(result["ok"], true);
        assert!(exchange.body(1).contains("\"code\":-32601"));
    }

    #[tokio::test]
    async fn a_session_the_server_issues_is_carried_into_every_later_request() {
        // The failure this prevents: the session id is read and dropped, so the second request
        // looks like a new client and the server answers 404 — which then reads as a wrong URL.
        let mut issued = head(200, Some("application/json"));
        issued.session_id = Some(McpSessionId::parse("sess-1").unwrap());
        let exchange = ScriptedExchange::new(vec![
            (
                issued,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}".into(),
            ),
            (
                head(200, Some("application/json")),
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}".into(),
            ),
        ]);
        let wire = http_wire(exchange.clone());
        wire.send_request("initialize", json!({})).await.unwrap();
        assert_eq!(
            wire.session().await.map(|id| id.expose().to_owned()),
            Some("sess-1".to_owned())
        );
        wire.send_request("tools/list", json!({})).await.unwrap();
        assert!(exchange.header_names(1).contains(&"mcp-session-id".into()));
        assert!(!exchange.header_names(0).contains(&"mcp-session-id".into()));
    }

    #[tokio::test]
    async fn a_404_after_a_session_exists_is_an_expired_session_not_a_missing_endpoint() {
        let mut issued = head(200, Some("application/json"));
        issued.session_id = Some(McpSessionId::parse("sess-1").unwrap());
        let exchange = ScriptedExchange::new(vec![
            (
                issued,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}".into(),
            ),
            (head(404, None), String::new()),
        ]);
        let wire = http_wire(exchange);
        wire.send_request("initialize", json!({})).await.unwrap();
        let (result, certainty) = wire.call_with_certainty("tools/list", json!({})).await;
        assert!(matches!(result, Err(McpError::SessionExpired)));
        assert_eq!(certainty, McpEffectCertainty::Definite);
    }

    #[tokio::test]
    async fn a_server_side_failure_reports_that_the_tool_may_already_have_run() {
        // This is the whole reason certainty crosses the seam: a 500 means the server had the
        // call. Reporting a definite failure here would let a retry apply the effect twice.
        let exchange = ScriptedExchange::new(vec![(head(500, None), String::new())]);
        let (result, certainty) = http_wire(exchange)
            .call_with_certainty("tools/call", json!({"name": "write"}))
            .await;
        assert!(matches!(result, Err(McpError::HttpStatus { status: 500 })));
        assert_eq!(certainty, McpEffectCertainty::Unknown);

        let exchange = ScriptedExchange::new(vec![(head(429, None), String::new())]);
        let (result, certainty) = http_wire(exchange)
            .call_with_certainty("tools/call", json!({"name": "write"}))
            .await;
        assert!(matches!(result, Err(McpError::HttpStatus { status: 429 })));
        assert_eq!(certainty, McpEffectCertainty::Definite);
    }

    #[tokio::test]
    async fn a_redirect_is_refused_and_the_credential_never_reaches_the_second_authority() {
        let exchange = ScriptedExchange::new(vec![(head(302, None), String::new())]);
        let wire = http_wire(exchange.clone()).with_credential(Token::new("sk-secret", u64::MAX));
        let (result, certainty) = wire.call_with_certainty("tools/list", json!({})).await;
        assert!(matches!(result, Err(McpError::HttpRedirectRefused)));
        assert_eq!(certainty, McpEffectCertainty::Definite);
        assert_eq!(
            exchange.call_count(),
            1,
            "the transport must not follow the redirect itself"
        );
    }

    #[tokio::test]
    async fn a_stale_credential_is_refused_before_the_exchange_is_ever_called() {
        // Nothing was dispatched, so the effect is definitely absent — and, crucially, the port
        // was never reached, so no 401 can later be mistaken for a revocation.
        let exchange = ScriptedExchange::new(vec![(
            head(200, Some("application/json")),
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}".into(),
        )]);
        let wire = http_wire(exchange.clone()).with_credential(Token::new("sk-secret", 1_010));
        let (result, certainty) = wire.call_with_certainty("tools/list", json!({})).await;
        assert!(matches!(result, Err(McpError::Credential(_))));
        assert_eq!(certainty, McpEffectCertainty::Definite);
        assert_eq!(exchange.call_count(), 0);
    }

    #[tokio::test]
    async fn an_unexpected_media_type_is_refused_rather_than_parsed_hopefully() {
        // A proxy's `text/html` error page fed to the JSON parser would be reported as an MCP
        // protocol violation by a server that never saw the request.
        for media_type in [None, Some("text/html"), Some("application/octet-stream")] {
            let exchange =
                ScriptedExchange::new(vec![(head(200, media_type), "<html>oops</html>".into())]);
            let (result, certainty) = http_wire(exchange)
                .call_with_certainty("tools/list", json!({}))
                .await;
            assert!(
                matches!(result, Err(McpError::UnsupportedMediaType)),
                "{media_type:?}"
            );
            assert_eq!(certainty, McpEffectCertainty::Unknown);
        }
    }

    #[tokio::test]
    async fn an_accepted_notification_succeeds_and_an_accepted_request_does_not() {
        let exchange = ScriptedExchange::new(vec![(head(202, None), String::new())]);
        let wire = http_wire(exchange);
        wire.send_notification("notifications/initialized", json!({}))
            .await
            .unwrap();

        let exchange = ScriptedExchange::new(vec![(head(202, None), String::new())]);
        let (result, certainty) = http_wire(exchange)
            .call_with_certainty("tools/list", json!({}))
            .await;
        assert!(matches!(result, Err(McpError::Protocol(_))));
        assert_eq!(
            certainty,
            McpEffectCertainty::Unknown,
            "the peer took the bytes and declined to answer"
        );
    }

    #[tokio::test]
    async fn a_declared_operator_header_is_sent_and_an_undeclared_one_cannot_be_attached() {
        let policy = McpHttpHeaderPolicy::new(vec!["x-tenant".into()]).unwrap();
        let exchange = ScriptedExchange::new(vec![(
            head(200, Some("application/json")),
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}".into(),
        )]);
        let wire = http_wire(exchange.clone())
            .with_headers(
                policy.clone(),
                vec![("x-tenant".into(), McpHeaderValue::new("acme").unwrap())],
            )
            .unwrap();
        wire.send_request("tools/list", json!({})).await.unwrap();
        assert!(exchange.header_names(0).contains(&"x-tenant".into()));

        let refused = http_wire(ScriptedExchange::new(vec![])).with_headers(
            policy,
            vec![("x-other".into(), McpHeaderValue::new("v").unwrap())],
        );
        assert!(matches!(
            refused.map(|_| ()),
            Err(McpError::InvalidEndpoint {
                field: "undeclared_header",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn the_http_wire_is_usable_through_the_transport_seam_as_a_trait_object() {
        let exchange = ScriptedExchange::new(vec![(
            head(200, Some("application/json")),
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}".into(),
        )]);
        let wire = http_wire(exchange);
        let seam: &dyn McpWire = &wire;
        assert_eq!(seam.transport_kind(), McpTransportKind::Http);
        assert_eq!(
            seam.send_request("tools/list", json!({})).await.unwrap()["ok"],
            true
        );
    }
}
