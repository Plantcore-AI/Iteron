//! The HTTP transport itself, over the [`McpHttpExchange`] port.
//!
//! Everything here is decision logic: build the request, classify the status, pick the framing,
//! carry the session forward. It is a complete transport that runs, and is tested, against a fake
//! exchange — which is the point. When an HTTP client is admitted, the change is one `impl
//! McpHttpExchange`, not a new transport.

use super::{
    McpEffectCertainty, McpHttpDisposition, McpHttpEndpoint, McpHttpExchange, McpHttpHeaderPolicy,
    McpHttpResponse, McpSessionId, classify, effect_certainty,
    port::{McpHeaderValue, build_post_with_routing, build_sse_get},
    sse::{
        SseInbound, SseLimits, SseReadOutcome, read_json_response,
        read_matching_sse_response_resumable,
    },
};
use crate::{
    MAX_FRAME_BYTES, McpError, McpFuture, McpTransportKind, McpWire, request, token::Token,
};
use base64::Engine as _;
use serde_json::{Value, json};
use std::collections::BTreeMap;
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
    parameter_headers: RwLock<BTreeMap<String, Vec<ParameterHeader>>>,
    pub server_name: String,
}

#[derive(Clone)]
struct ParameterHeader {
    argument: String,
    suffix: String,
    value_type: String,
}

struct PreparedCall {
    frame: String,
    method: String,
    routed_name: Option<String>,
    parameter_headers: Vec<(String, McpHeaderValue)>,
    resets_parameter_headers: bool,
    id: u64,
    dispatch_observer: Option<Box<dyn FnOnce() + Send>>,
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
                crate::protocol_version::STATEFUL_REQUESTED_PROTOCOL_VERSION.to_owned(),
            ),
            elicitation: None,
            next_id: AtomicU64::new(1),
            parameter_headers: RwLock::new(BTreeMap::new()),
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

    pub(crate) async fn clear_session(&self) {
        *self.session.lock().await = None;
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
        self.call_with_certainty_and_dispatch_observer(method, params, None)
            .await
    }

    pub(crate) async fn call_with_certainty_and_dispatch_observer(
        &self,
        method: &str,
        params: Value,
        dispatch_observer: Option<Box<dyn FnOnce() + Send>>,
    ) -> (Result<Value, McpError>, McpEffectCertainty) {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let parameter_headers = self.parameter_headers_for_call(method, &params).await;
        let resets_parameter_headers = method == "tools/list" && params.get("cursor").is_none();
        let routed_name = match method {
            "tools/call" | "prompts/get" => params.get("name"),
            "resources/read" => params.get("uri"),
            _ => None,
        };
        let routed_name = routed_name
            .and_then(Value::as_str)
            .map(encode_mirrored_text);
        let frame = match request(id, method, params) {
            Ok(frame) => frame,
            // Nothing was dispatched: serialization failed before any byte could leave.
            Err(error) => return (Err(error), McpEffectCertainty::Definite),
        };
        let call = self.execute_call_frame(PreparedCall {
            frame,
            method: method.to_owned(),
            routed_name,
            parameter_headers,
            resets_parameter_headers,
            id,
            dispatch_observer,
        });
        if method == "tools/call"
            && !self.is_modern().await
            && self.elicitation.is_some()
            && self.has_session().await
        {
            let inbound_response = match self.open_inbound_stream().await {
                Ok(response) => response,
                Err(error) => return (Err(error), McpEffectCertainty::Definite),
            };
            let inbound = self.listen_for_inbound(inbound_response);
            tokio::pin!(call);
            tokio::pin!(inbound);
            tokio::select! {
                biased;
                result = &mut inbound => match result {
                    Ok(()) => call.await,
                    Err(error) => (Err(error), McpEffectCertainty::Unknown),
                },
                result = &mut call => result,
            }
        } else {
            call.await
        }
    }

    async fn execute_call_frame(
        &self,
        call: PreparedCall,
    ) -> (Result<Value, McpError>, McpEffectCertainty) {
        let dispatched = self
            .dispatch_with_observer(
                call.frame,
                Some(&call.method),
                call.routed_name.as_deref(),
                &call.parameter_headers,
                call.dispatch_observer,
            )
            .await;
        let (head, body) = match dispatched {
            Ok(response) => (response.head, response.body),
            Err(error) => {
                let certainty = certainty_of(&error);
                return (Err(error), certainty);
            }
        };
        let status = head.status;
        let insufficient_scope = head.insufficient_scope.clone();
        let modern = self.is_modern().await;
        let disposition = classify(
            status,
            !modern && (head.session_id.is_some() || self.has_session().await),
        );
        if !modern && let Some(session_id) = head.session_id {
            *self.session.lock().await = Some(session_id);
        }
        if status == 400 && head.media_type.as_deref() == Some(super::MCP_JSON_MEDIA_TYPE) {
            let result = match self
                .read_body(head.media_type.as_deref(), body, call.id)
                .await
            {
                Ok(_) => Err(McpError::HttpStatus { status }),
                Err(error) => Err(error),
            };
            return (result, McpEffectCertainty::Definite);
        }
        if let Some(error) = disposition.into_error(status) {
            if status == 403
                && let Some(scopes) = insufficient_scope
            {
                return (
                    Err(McpError::InsufficientScope { scopes }),
                    McpEffectCertainty::Definite,
                );
            }
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
        let result = self
            .read_body(head.media_type.as_deref(), body, call.id)
            .await;
        if call.method == "tools/list"
            && let Ok(value) = &result
        {
            self.remember_parameter_headers(value, call.resets_parameter_headers)
                .await;
        }
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

    async fn is_modern(&self) -> bool {
        self.protocol_version.read().await.as_str() == crate::MODERN_PROTOCOL_VERSION
    }

    async fn dispatch(
        &self,
        frame: String,
        method: Option<&str>,
        name: Option<&str>,
        parameter_headers: &[(String, McpHeaderValue)],
    ) -> Result<McpHttpResponse, McpError> {
        self.dispatch_with_observer(frame, method, name, parameter_headers, None)
            .await
    }

    async fn dispatch_with_observer(
        &self,
        frame: String,
        method: Option<&str>,
        name: Option<&str>,
        parameter_headers: &[(String, McpHeaderValue)],
        dispatch_observer: Option<Box<dyn FnOnce() + Send>>,
    ) -> Result<McpHttpResponse, McpError> {
        let credential = self.credential.lock().await;
        let session = self.session.lock().await.clone();
        let protocol_version = self.protocol_version.read().await.clone();
        let modern = protocol_version == crate::MODERN_PROTOCOL_VERSION;
        let http_request = build_post_with_routing(
            &self.endpoint,
            credential.as_ref(),
            (self.now_secs)(),
            if modern { None } else { session.as_ref() },
            &self.extra_headers,
            &self.header_policy,
            (&protocol_version, frame),
            modern.then_some((method.unwrap_or("unknown"), name)),
            parameter_headers,
        )?;
        drop(credential);
        if let Some(observer) = dispatch_observer {
            observer();
        }
        self.exchange.exchange(http_request).await
    }

    async fn parameter_headers_for_call(
        &self,
        method: &str,
        params: &Value,
    ) -> Vec<(String, McpHeaderValue)> {
        if method != "tools/call" {
            return Vec::new();
        }
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return Vec::new();
        };
        let Some(arguments) = params.get("arguments").and_then(Value::as_object) else {
            return Vec::new();
        };
        self.parameter_headers
            .read()
            .await
            .get(name)
            .into_iter()
            .flatten()
            .filter_map(|header| {
                let value = arguments.get(&header.argument)?;
                encode_parameter_value(value, &header.value_type)
                    .and_then(|value| McpHeaderValue::new(value).ok())
                    .map(|value| {
                        (
                            format!("mcp-param-{}", header.suffix.to_ascii_lowercase()),
                            value,
                        )
                    })
            })
            .collect()
    }

    async fn remember_parameter_headers(&self, result: &Value, reset: bool) {
        let mut catalog = BTreeMap::new();
        for tool in result
            .get("tools")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(name) = tool.get("name").and_then(Value::as_str) else {
                continue;
            };
            let Some(properties) = tool
                .get("inputSchema")
                .and_then(|schema| schema.get("properties"))
                .and_then(Value::as_object)
            else {
                continue;
            };
            let mut headers = Vec::new();
            for (argument, schema) in properties {
                let Some(suffix) = schema.get("x-mcp-header").and_then(Value::as_str) else {
                    continue;
                };
                let Some(value_type) = schema.get("type").and_then(Value::as_str) else {
                    continue;
                };
                if valid_parameter_suffix(suffix)
                    && matches!(value_type, "string" | "integer" | "number" | "boolean")
                {
                    headers.push(ParameterHeader {
                        argument: argument.clone(),
                        suffix: suffix.to_owned(),
                        value_type: value_type.to_owned(),
                    });
                }
            }
            if !headers.is_empty() {
                catalog.insert(name.to_owned(), headers);
            }
        }
        let mut retained = self.parameter_headers.write().await;
        if reset {
            retained.clear();
        }
        retained.extend(catalog);
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
                let initial =
                    read_matching_sse_response_resumable(body, id, self.limits, self).await?;
                match initial {
                    SseReadOutcome::Response(value) => Ok(value),
                    SseReadOutcome::Closed {
                        last_event_id,
                        retry_ms,
                    } if !self.is_modern().await && last_event_id.is_some() => {
                        let delay = retry_ms.unwrap_or(1_000).min(10_000);
                        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                        let credential = self.credential.lock().await;
                        let session = self.session.lock().await.clone();
                        let version = self.protocol_version.read().await.clone();
                        let request = build_sse_get(
                            &self.endpoint,
                            credential.as_ref(),
                            (self.now_secs)(),
                            session.as_ref(),
                            &version,
                            last_event_id.as_deref(),
                        )?;
                        drop(credential);
                        let response = self.exchange.exchange(request).await?;
                        if response.head.status != 200
                            || response.head.media_type.as_deref()
                                != Some(super::MCP_SSE_MEDIA_TYPE)
                        {
                            return Err(McpError::TransportClosed);
                        }
                        if let Some(session_id) = response.head.session_id {
                            *self.session.lock().await = Some(session_id);
                        }
                        match read_matching_sse_response_resumable(
                            response.body,
                            id,
                            self.limits,
                            self,
                        )
                        .await?
                        {
                            SseReadOutcome::Response(value) => Ok(value),
                            SseReadOutcome::Closed { .. } => Err(McpError::TransportClosed),
                        }
                    }
                    SseReadOutcome::Closed { .. } => Err(McpError::TransportClosed),
                }
            }
            // Guessing is the failure mode: a proxy error page served as `text/html` would be fed
            // to the JSON parser and reported as a protocol violation by the MCP server.
            _ => Err(McpError::UnsupportedMediaType),
        }
    }

    async fn open_inbound_stream(&self) -> Result<McpHttpResponse, McpError> {
        let credential = self.credential.lock().await;
        let session = self.session.lock().await.clone();
        let version = self.protocol_version.read().await.clone();
        let request = build_sse_get(
            &self.endpoint,
            credential.as_ref(),
            (self.now_secs)(),
            session.as_ref(),
            &version,
            None,
        )?;
        drop(credential);
        let response = self.exchange.exchange(request).await?;
        if response.head.status != 200
            || response.head.media_type.as_deref() != Some(super::MCP_SSE_MEDIA_TYPE)
        {
            return Err(McpError::TransportClosed);
        }
        Ok(response)
    }

    async fn listen_for_inbound(&self, response: McpHttpResponse) -> Result<(), McpError> {
        let _ = read_matching_sse_response_resumable(response.body, u64::MAX, self.limits, self)
            .await?;
        Ok(())
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
        let response = self.dispatch(frame, None, None, &[]).await?;
        let status = response.head.status;
        if !self.is_modern().await
            && let Some(session_id) = response.head.session_id
        {
            *self.session.lock().await = Some(session_id);
        }
        match classify(status, !self.is_modern().await && self.has_session().await)
            .into_error(status)
        {
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

fn valid_parameter_suffix(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        ..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
                )
        })
}

fn encode_parameter_value(value: &Value, value_type: &str) -> Option<String> {
    let rendered = match value_type {
        "string" => value.as_str()?.to_owned(),
        "integer" | "number" if value.is_number() => value.to_string(),
        "boolean" => value.as_bool()?.to_string(),
        _ => return None,
    };
    Some(encode_mirrored_text(&rendered))
}

fn encode_mirrored_text(rendered: &str) -> String {
    let plain = !rendered.is_empty()
        && rendered.trim() == rendered
        && rendered
            .bytes()
            .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte));
    if plain {
        rendered.to_owned()
    } else {
        format!(
            "=?base64?{}?=",
            base64::engine::general_purpose::STANDARD.encode(rendered.as_bytes())
        )
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
            let response = self.dispatch(frame, Some(method), None, &[]).await?;
            let status = response.head.status;
            let modern = self.is_modern().await;
            let disposition = classify(status, !modern && response.head.session_id.is_some());
            if !modern && let Some(session_id) = response.head.session_id {
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

    type RecordedRequest = (String, Vec<(String, String)>, String);

    /// A scripted exchange. It records what it was asked to send, so the request-side contract is
    /// observable, and replays canned responses in order.
    struct ScriptedExchange {
        responses: StdMutex<Vec<(McpHttpResponseHead, String)>>,
        seen: StdMutex<Vec<RecordedRequest>>,
    }

    impl ScriptedExchange {
        fn new(responses: Vec<(McpHttpResponseHead, String)>) -> Arc<Self> {
            Arc::new(Self {
                responses: StdMutex::new(responses.into_iter().rev().collect()),
                seen: StdMutex::new(Vec::new()),
            })
        }

        fn header_names(&self, index: usize) -> Vec<String> {
            self.seen.lock().unwrap()[index]
                .1
                .iter()
                .map(|(name, _)| name.clone())
                .collect()
        }

        fn header_value(&self, index: usize, expected: &str) -> Option<String> {
            self.seen.lock().unwrap()[index]
                .1
                .iter()
                .find(|(name, _)| name == expected)
                .map(|(_, value)| value.clone())
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
                    .map(|(name, value)| (name.clone(), value.expose().to_owned()))
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
            insufficient_scope: None,
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
    async fn json_rpc_integer_ids_remain_exact_above_javascript_safe_integer_range() {
        const HIGH_ID: u64 = 9_007_199_254_740_993;
        let exchange = ScriptedExchange::new(vec![(
            head(200, Some("application/json")),
            format!("{{\"jsonrpc\":\"2.0\",\"id\":{HIGH_ID},\"result\":{{\"tools\":[]}}}}"),
        )]);
        let wire = http_wire(exchange.clone());
        wire.next_id.store(HIGH_ID, Ordering::SeqCst);
        wire.send_request("tools/list", json!({})).await.unwrap();
        assert!(exchange.body(0).contains(&format!("\"id\":{HIGH_ID}")));
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

    #[tokio::test]
    async fn a_gracefully_closed_sse_response_reconnects_once_with_its_event_id() {
        let exchange = ScriptedExchange::new(vec![
            (
                head(200, Some("text/event-stream")),
                "id: event-7\nretry: 0\ndata:\n\n".into(),
            ),
            (
                head(200, Some("text/event-stream")),
                "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n".into(),
            ),
        ]);
        let result = http_wire(exchange.clone())
            .send_request("tools/call", json!({"name":"retry"}))
            .await
            .unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(exchange.call_count(), 2);
        assert_eq!(
            exchange.header_value(1, "last-event-id").as_deref(),
            Some("event-7")
        );
    }

    #[tokio::test]
    async fn custom_parameter_headers_encode_unsafe_values_and_ignore_unannotated_fields() {
        let exchange = ScriptedExchange::new(Vec::new());
        let wire = http_wire(exchange);
        wire.remember_parameter_headers(
            &json!({
                "tools":[{
                    "name":"headers",
                    "inputSchema":{"type":"object","properties":{
                        "region":{"type":"string","x-mcp-header":"Region"},
                        "debug":{"type":"boolean","x-mcp-header":"Debug"},
                        "ignored":{"type":"string"}
                    }}
                }]
            }),
            true,
        )
        .await;
        let headers = wire
            .parameter_headers_for_call(
                "tools/call",
                &json!({
                    "name":"headers",
                    "arguments":{"region":" 北 ","debug":true,"ignored":"secret"}
                }),
            )
            .await;
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].0, "mcp-param-debug");
        assert_eq!(headers[0].1.expose(), "true");
        assert_eq!(headers[1].0, "mcp-param-region");
        assert!(headers[1].1.expose().starts_with("=?base64?"));
        assert!(headers.iter().all(|(name, _)| !name.contains("ignored")));
    }

    #[tokio::test]
    async fn parameter_header_catalog_merges_pages_and_resets_on_a_fresh_listing() {
        let exchange = ScriptedExchange::new(Vec::new());
        let wire = http_wire(exchange);
        wire.remember_parameter_headers(
            &json!({"tools":[{"name":"first","inputSchema":{"properties":{
                "region":{"type":"string","x-mcp-header":"Region"}
            }}}]}),
            true,
        )
        .await;
        wire.remember_parameter_headers(
            &json!({"tools":[{"name":"second","inputSchema":{"properties":{
                "count":{"type":"integer","x-mcp-header":"Count"}
            }}}]}),
            false,
        )
        .await;
        assert_eq!(wire.parameter_headers.read().await.len(), 2);

        wire.remember_parameter_headers(&json!({"tools":[]}), true)
            .await;
        assert!(wire.parameter_headers.read().await.is_empty());
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
    async fn stateless_2026_sends_route_headers_and_ignores_session_ids() {
        let mut issued = head(200, Some("application/json"));
        issued.session_id = Some(McpSessionId::parse("ignored").unwrap());
        let exchange = ScriptedExchange::new(vec![(
            issued,
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}".into(),
        )]);
        let wire = http_wire(exchange.clone());
        wire.set_protocol_version(crate::MODERN_PROTOCOL_VERSION)
            .await;
        wire.send_request("tools/call", json!({"name": "echo"}))
            .await
            .unwrap();
        let names = exchange.header_names(0);
        assert!(names.contains(&"mcp-method".into()));
        assert!(names.contains(&"mcp-name".into()));
        assert!(!names.contains(&"mcp-session-id".into()));
        assert_eq!(wire.session().await, None);
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
