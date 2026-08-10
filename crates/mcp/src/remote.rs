//! High-level MCP client over streamable HTTP.

use crate::client::{render_extension_content, render_tool_content};
use crate::http::{
    McpEffectCertainty, McpHeaderValue, McpHttpEndpoint, McpHttpHeaderPolicy, McpHttpWire, NowSecs,
    ReqwestMcpExchange,
};
use crate::pagination::{ToolListLimits, ToolListPagination};
use crate::protocol_version::{REQUESTED_PROTOCOL_VERSION, negotiate_initialize_result};
use crate::tool_catalog::ToolCatalogBuilder;
use crate::tool_filter::{McpToolFilter, validate_bare_tool_name, validate_server_name};
use crate::{McpError, McpServerPolicy, McpToolCallEvidence, McpToolOutcome, McpWire};
use core_protocol::{ToolSpec, capability_set::CapabilitySet};
use serde_json::{Value, json};
use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

struct OAuthState {
    client: crate::oauth::OAuthClient,
    grant: crate::oauth::OAuthRefreshGrant,
}

/// Capabilities declared by the server during the authenticated initialize handshake.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct McpServerCapabilities {
    pub tools: bool,
    pub resources: bool,
    pub prompts: bool,
}

/// A connected HTTP MCP server with the same governed discovery and effect outcome contract as
/// the stdio client.
pub struct McpRemoteClient {
    wire: Arc<McpHttpWire<ReqwestMcpExchange>>,
    negotiated_protocol_version: String,
    capabilities: McpServerCapabilities,
    oauth: Option<Mutex<OAuthState>>,
    authentication_configured: bool,
    oauth_policy: crate::oauth::McpOAuthLifecyclePolicy,
    deadlines: crate::McpTransportDeadlines,
    result_policy: crate::McpResultPolicy,
    spill_store: crate::result_policy::McpSpillStore,
    pub server_name: String,
}

impl McpRemoteClient {
    pub async fn connect(
        endpoint: McpHttpEndpoint,
        server_name: String,
        credential: Option<crate::token::Token>,
        header_policy: McpHttpHeaderPolicy,
        headers: Vec<(String, McpHeaderValue)>,
        oauth_grant: Option<crate::oauth::OAuthRefreshGrant>,
    ) -> Result<Self, McpError> {
        Self::connect_with_policies(
            endpoint,
            server_name,
            credential,
            header_policy,
            headers,
            oauth_grant,
            crate::McpDeadlinePolicy::default().http(),
            crate::McpResultPolicy::default(),
        )
        .await
    }

    /// Connect under the exact transport deadlines and result policy decoded from the session's
    /// immutable tunables checkpoint.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_with_policies(
        endpoint: McpHttpEndpoint,
        server_name: String,
        credential: Option<crate::token::Token>,
        header_policy: McpHttpHeaderPolicy,
        headers: Vec<(String, McpHeaderValue)>,
        oauth_grant: Option<crate::oauth::OAuthRefreshGrant>,
        deadlines: crate::McpTransportDeadlines,
        result_policy: crate::McpResultPolicy,
    ) -> Result<Self, McpError> {
        Self::connect_with_elicitation_and_policies(
            endpoint,
            server_name,
            credential,
            header_policy,
            headers,
            oauth_grant,
            None,
            deadlines,
            result_policy,
        )
        .await
    }

    /// Connect with an interactive form-elicitation surface. Supplying the handler is the only
    /// path that advertises the capability; noninteractive callers therefore fail closed by
    /// construction.
    pub async fn connect_with_elicitation(
        endpoint: McpHttpEndpoint,
        server_name: String,
        credential: Option<crate::token::Token>,
        header_policy: McpHttpHeaderPolicy,
        headers: Vec<(String, McpHeaderValue)>,
        oauth_grant: Option<crate::oauth::OAuthRefreshGrant>,
        elicitation: Option<Arc<dyn crate::McpElicitationHandler>>,
    ) -> Result<Self, McpError> {
        Self::connect_with_elicitation_and_policies(
            endpoint,
            server_name,
            credential,
            header_policy,
            headers,
            oauth_grant,
            elicitation,
            crate::McpDeadlinePolicy::default().http(),
            crate::McpResultPolicy::default(),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn connect_with_elicitation_and_policies(
        endpoint: McpHttpEndpoint,
        server_name: String,
        credential: Option<crate::token::Token>,
        header_policy: McpHttpHeaderPolicy,
        headers: Vec<(String, McpHeaderValue)>,
        oauth_grant: Option<crate::oauth::OAuthRefreshGrant>,
        elicitation: Option<Arc<dyn crate::McpElicitationHandler>>,
        deadlines: crate::McpTransportDeadlines,
        result_policy: crate::McpResultPolicy,
    ) -> Result<Self, McpError> {
        validate_server_name(&server_name)?;
        let advertises_elicitation = elicitation.is_some();
        let now: NowSecs = Arc::new(unix_now);
        let authentication_configured = credential.is_some() || oauth_grant.is_some();
        let oauth_policy = crate::oauth::McpOAuthLifecyclePolicy::for_binding(
            credential.is_some(),
            oauth_grant.is_some(),
            oauth_grant
                .as_ref()
                .is_some_and(crate::oauth::OAuthRefreshGrant::revocation_endpoint_configured),
        );
        let mut wire = McpHttpWire::new(
            endpoint,
            ReqwestMcpExchange::with_deadlines(deadlines)?,
            now,
            server_name.clone(),
        )?
        .with_headers(header_policy, headers)?;
        if let Some(credential) = credential {
            wire = wire.with_credential(credential);
        }
        if let Some(elicitation) = elicitation {
            wire = wire.with_elicitation_handler(elicitation);
        }
        let wire = Arc::new(wire);
        let mut client = Self {
            wire: wire.clone(),
            negotiated_protocol_version: String::new(),
            capabilities: McpServerCapabilities::default(),
            oauth: oauth_grant
                .map(|grant| {
                    Ok::<_, McpError>(Mutex::new(OAuthState {
                        client: crate::oauth::OAuthClient::new()?,
                        grant,
                    }))
                })
                .transpose()?,
            authentication_configured,
            oauth_policy,
            deadlines,
            result_policy,
            spill_store: crate::result_policy::McpSpillStore::create()?,
            server_name,
        };
        client.refresh_if_needed().await?;
        let initialize = tokio::time::timeout(
            deadlines.startup(),
            wire.send_request(
                "initialize",
                json!({
                    "protocolVersion": REQUESTED_PROTOCOL_VERSION,
                    "capabilities": if advertises_elicitation {
                        json!({"elicitation": {"form": {}}})
                    } else {
                        json!({})
                    },
                    "clientInfo": {"name": "core", "version": env!("CARGO_PKG_VERSION")}
                }),
            ),
        )
        .await
        .map_err(|_| McpError::Deadline {
            operation: "initialize handshake".into(),
        })??;
        client.negotiated_protocol_version = negotiate_initialize_result(&initialize)?;
        wire.set_protocol_version(client.negotiated_protocol_version.clone())
            .await;
        client.capabilities = capabilities_from(&initialize);
        tokio::time::timeout(
            deadlines.startup(),
            wire.send_notification("notifications/initialized", json!({})),
        )
        .await
        .map_err(|_| McpError::Deadline {
            operation: "initialized notification".into(),
        })??;
        Ok(client)
    }

    pub fn negotiated_protocol_version(&self) -> &str {
        &self.negotiated_protocol_version
    }

    pub fn capabilities(&self) -> McpServerCapabilities {
        self.capabilities
    }

    pub fn deadlines(&self) -> crate::McpTransportDeadlines {
        self.deadlines
    }

    pub fn result_policy(&self) -> crate::McpResultPolicy {
        self.result_policy
    }

    /// Apply an owning lifecycle boundary to this connection's private result store.
    pub fn cleanup_spills(&self, boundary: crate::McpSpillCleanup) -> Result<(), McpError> {
        self.spill_store
            .cleanup(self.result_policy.cleanup(), boundary)
    }

    pub fn oauth_policy(&self) -> crate::oauth::McpOAuthLifecyclePolicy {
        self.oauth_policy
    }

    pub async fn list_tools_governed(
        &self,
        filter: &McpToolFilter,
        policy: &McpServerPolicy,
        host_ceiling: CapabilitySet,
    ) -> Result<Vec<ToolSpec>, McpError> {
        filter.validate()?;
        policy.validate()?;
        if !self.capabilities.tools {
            return Ok(Vec::new());
        }
        self.refresh_if_needed().await?;
        let mut pagination = ToolListPagination::new(ToolListLimits::default());
        let mut catalog =
            ToolCatalogBuilder::governed(filter.clone(), policy.clone(), host_ceiling);
        let mut cursor = None;
        loop {
            pagination.begin_page()?;
            let params = cursor
                .take()
                .map_or_else(|| json!({}), |cursor| json!({"cursor": cursor}));
            let result = self.wire.send_request("tools/list", params).await?;
            let next_cursor = pagination.accept_page(&result)?;
            catalog.accept_page(&self.server_name, &result)?;
            let Some(next_cursor) = next_cursor else {
                return Ok(catalog.finish());
            };
            cursor = Some(next_cursor);
        }
    }

    pub async fn call_tool_outcome_observed<F>(
        &self,
        name: &str,
        arguments: Value,
        on_dispatch: F,
    ) -> McpToolOutcome
    where
        F: FnOnce() + Send + 'static,
    {
        if let Err(error) = validate_bare_tool_name(name) {
            return McpToolOutcome::FailedDefinite {
                error,
                evidence: None,
            };
        }
        if let Err(error) = self.refresh_if_needed().await {
            return McpToolOutcome::FailedDefinite {
                error,
                evidence: None,
            };
        }
        on_dispatch();
        let started = Instant::now();
        let (mut result, mut certainty) = self
            .wire
            .call_with_certainty(
                "tools/call",
                json!({"name": name, "arguments": arguments.clone()}),
            )
            .await;
        if matches!(result, Err(McpError::HttpStatus { status: 401 }))
            && certainty == McpEffectCertainty::Definite
            && self.refresh_after_rejection().await.is_ok()
        {
            (result, certainty) = self
                .wire
                .call_with_certainty("tools/call", json!({"name": name, "arguments": arguments}))
                .await;
        }
        let elapsed = u64::try_from(started.elapsed().as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        let evidence = McpToolCallEvidence::new(
            &self.server_name,
            name,
            NonZeroU64::new(elapsed).expect("elapsed was clamped to at least one"),
        );
        let result = match result {
            Ok(result) => result,
            Err(error) if certainty == McpEffectCertainty::Definite => {
                if matches!(error, McpError::HttpStatus { status: 403 }) {
                    self.wire.revoke_credential().await;
                }
                return McpToolOutcome::FailedDefinite {
                    error,
                    evidence: Some(evidence),
                };
            }
            Err(error) => return McpToolOutcome::Unknown { error, evidence },
        };
        let output = match render_tool_content(&result, self.result_policy, &self.spill_store) {
            Ok(output) => output,
            Err(error) => {
                return McpToolOutcome::FailedDefinite {
                    error,
                    evidence: Some(evidence),
                };
            }
        };
        if let Err(error) = self.cleanup_spills(crate::McpSpillCleanup::ToolEnd) {
            return McpToolOutcome::FailedDefinite {
                error,
                evidence: Some(evidence),
            };
        }
        McpToolOutcome::Completed {
            content: output,
            is_error: result
                .get("isError")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            evidence,
        }
    }

    /// Invoke the standard resource/prompt surface under the same response ceilings as tools.
    pub async fn call_extension(&self, method: &str, params: Value) -> Result<Value, McpError> {
        match method {
            "resources/list" | "resources/read" if self.capabilities.resources => {}
            "prompts/list" | "prompts/get" if self.capabilities.prompts => {}
            _ => return Err(McpError::Protocol("MCP capability is not declared".into())),
        }
        self.refresh_if_needed().await?;
        self.wire.send_request(method, params).await
    }

    pub async fn call_extension_rendered(
        &self,
        method: &str,
        params: Value,
    ) -> Result<String, McpError> {
        let result = self.call_extension(method, params).await?;
        let content = render_extension_content(&result, self.result_policy, &self.spill_store)?;
        self.cleanup_spills(crate::McpSpillCleanup::ToolEnd)?;
        Ok(content)
    }

    pub async fn call_extension_outcome_observed<F>(
        &self,
        method: &str,
        params: Value,
        on_dispatch: F,
    ) -> McpToolOutcome
    where
        F: FnOnce() + Send + 'static,
    {
        match method {
            "resources/list" | "resources/read" if self.capabilities.resources => {}
            "prompts/list" | "prompts/get" if self.capabilities.prompts => {}
            _ => {
                return McpToolOutcome::FailedDefinite {
                    error: McpError::Protocol("MCP capability is not declared".into()),
                    evidence: None,
                };
            }
        }
        if let Err(error) = self.refresh_if_needed().await {
            return McpToolOutcome::FailedDefinite {
                error,
                evidence: None,
            };
        }
        on_dispatch();
        let started = Instant::now();
        let (result, certainty) = self.wire.call_with_certainty(method, params).await;
        let elapsed = u64::try_from(started.elapsed().as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        let evidence = McpToolCallEvidence::new(
            &self.server_name,
            method,
            NonZeroU64::new(elapsed).expect("elapsed was clamped to at least one"),
        );
        let result = match result {
            Ok(result) => result,
            Err(error) if certainty == McpEffectCertainty::Definite => {
                return McpToolOutcome::FailedDefinite {
                    error,
                    evidence: Some(evidence),
                };
            }
            Err(error) => return McpToolOutcome::Unknown { error, evidence },
        };
        match render_extension_content(&result, self.result_policy, &self.spill_store) {
            Ok(content) => match self.cleanup_spills(crate::McpSpillCleanup::ToolEnd) {
                Ok(()) => McpToolOutcome::Completed {
                    content,
                    is_error: false,
                    evidence,
                },
                Err(error) => McpToolOutcome::FailedDefinite {
                    error,
                    evidence: Some(evidence),
                },
            },
            Err(error) => McpToolOutcome::FailedDefinite {
                error,
                evidence: Some(evidence),
            },
        }
    }

    pub async fn replace_credential(&self, credential: crate::token::Token) {
        self.wire.replace_credential(credential).await;
    }

    pub async fn revoke_oauth(&self) -> Result<(), McpError> {
        if let Some(oauth) = &self.oauth {
            let oauth = oauth.lock().await;
            oauth.client.revoke(&oauth.grant).await?;
        }
        self.wire.revoke_credential().await;
        Ok(())
    }

    async fn refresh_if_needed(&self) -> Result<(), McpError> {
        if !self.authentication_configured {
            return Ok(());
        }
        let now = unix_now();
        if self.wire.credential_state(now).await == crate::token::State::Fresh {
            return Ok(());
        }
        self.refresh_after_rejection().await
    }

    async fn refresh_after_rejection(&self) -> Result<(), McpError> {
        let oauth = self
            .oauth
            .as_ref()
            .ok_or(McpError::Credential(crate::token::TokenError::Absent))?;
        let mut oauth = oauth.lock().await;
        let OAuthState { client, grant } = &mut *oauth;
        let token = client.refresh(grant, unix_now()).await?;
        self.wire.replace_credential(token).await;
        Ok(())
    }
}

fn capabilities_from(initialize: &Value) -> McpServerCapabilities {
    let capabilities = initialize.get("capabilities").and_then(Value::as_object);
    McpServerCapabilities {
        tools: capabilities.is_some_and(|value| value.contains_key("tools")),
        resources: capabilities.is_some_and(|value| value.contains_key("resources")),
        prompts: capabilities.is_some_and(|value| value.contains_key("prompts")),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc as StdArc, Mutex as StdMutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn capability_projection_is_exact_and_unknown_fields_grant_nothing() {
        let capabilities = capabilities_from(&json!({
            "capabilities": {"tools": {}, "resources": {}, "unknown": {}}
        }));
        assert_eq!(
            capabilities,
            McpServerCapabilities {
                tools: true,
                resources: true,
                prompts: false,
            }
        );
    }

    async fn read_request(socket: &mut TcpStream) -> String {
        let mut request = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            let read = socket.read(&mut chunk).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            let Some(head_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
                continue;
            };
            let header = String::from_utf8_lossy(&request[..head_end]);
            let content_length = header
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|value| value.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            if request.len() >= head_end + 4 + content_length {
                break;
            }
        }
        String::from_utf8(request).unwrap()
    }

    async fn full_server() -> (
        String,
        StdArc<StdMutex<Vec<String>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let seen = StdArc::new(StdMutex::new(Vec::new()));
        let recorded = seen.clone();
        let task = tokio::spawn(async move {
            for _ in 0..7 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let request = read_request(&mut socket).await;
                let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
                let message: Value = serde_json::from_str(body).unwrap();
                let method = message.get("method").and_then(Value::as_str).unwrap();
                let id = message.get("id").cloned();
                recorded.lock().unwrap().push(request);

                if id.is_none() {
                    socket
                        .write_all(
                            b"HTTP/1.1 202 Accepted\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                        )
                        .await
                        .unwrap();
                    continue;
                }
                let result = match method {
                    "initialize" => json!({
                        "protocolVersion": REQUESTED_PROTOCOL_VERSION,
                        "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                        "serverInfo": {"name": "fixture", "version": "1.0.0"}
                    }),
                    "tools/list" => json!({"tools": [{
                        "name": "read_public",
                        "description": "read public data",
                        "inputSchema": {"type": "object", "properties": {}}
                    }]}),
                    "resources/list" => json!({"resources": [{
                        "uri": "plantcore://guide", "name": "guide"
                    }]}),
                    "resources/read" => json!({"contents": [{
                        "uri": "plantcore://guide", "text": "hello"
                    }]}),
                    "prompts/list" => json!({"prompts": [{"name": "review"}]}),
                    "prompts/get" => json!({"messages": [{
                        "role": "user", "content": {"type": "text", "text": "review this"}
                    }]}),
                    other => panic!("unexpected method {other}"),
                };
                let frame = json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string();
                let session = if method == "initialize" {
                    "mcp-session-id: fixture-session\r\n"
                } else {
                    ""
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n{session}content-length: {}\r\nconnection: close\r\n\r\n{frame}",
                    frame.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
                socket.shutdown().await.unwrap();
            }
        });
        (format!("http://{address}/mcp"), seen, task)
    }

    #[tokio::test]
    async fn production_remote_client_completes_handshake_tools_resources_and_prompts() {
        let (url, seen, server) = full_server().await;
        let client = McpRemoteClient::connect(
            McpHttpEndpoint::parse(&url).unwrap(),
            "fixture".into(),
            None,
            McpHttpHeaderPolicy::default(),
            Vec::new(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            client.negotiated_protocol_version(),
            REQUESTED_PROTOCOL_VERSION
        );
        assert_eq!(
            client.capabilities(),
            McpServerCapabilities {
                tools: true,
                resources: true,
                prompts: true,
            }
        );
        let tools = client
            .list_tools_governed(
                &McpToolFilter::default(),
                &McpServerPolicy::default(),
                crate::default_host_ceiling(),
            )
            .await
            .unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "fixture__read_public");
        assert_eq!(
            client
                .call_extension("resources/list", json!({}))
                .await
                .unwrap()["resources"][0]["name"],
            "guide"
        );
        assert_eq!(
            client
                .call_extension("resources/read", json!({"uri": "plantcore://guide"}))
                .await
                .unwrap()["contents"][0]["text"],
            "hello"
        );
        assert_eq!(
            client
                .call_extension("prompts/list", json!({}))
                .await
                .unwrap()["prompts"][0]["name"],
            "review"
        );
        assert_eq!(
            client
                .call_extension("prompts/get", json!({"name": "review"}))
                .await
                .unwrap()["messages"][0]["role"],
            "user"
        );
        server.await.unwrap();

        let requests = seen.lock().unwrap();
        assert!(requests[0].contains(&format!(
            "\"protocolVersion\":\"{REQUESTED_PROTOCOL_VERSION}\""
        )));
        assert!(requests[0].contains("\"capabilities\":{}"));
        assert!(
            requests[2..]
                .iter()
                .all(|request| request.contains("mcp-session-id: fixture-session"))
        );
        assert!(
            requests[2..]
                .iter()
                .all(|request| request.contains(&format!(
                    "mcp-protocol-version: {REQUESTED_PROTOCOL_VERSION}"
                )))
        );
    }
}
