//! High-level MCP client over streamable HTTP.

use crate::client::{render_extension_content, render_tool_content};
use crate::http::{
    McpEffectCertainty, McpHeaderValue, McpHttpEndpoint, McpHttpHeaderPolicy, McpHttpWire, NowSecs,
    ReqwestMcpExchange,
};
use crate::pagination::{ToolListLimits, ToolListPagination};
use crate::protocol_version::{
    DiscoveryNegotiation, DiscoveryRejection, McpProtocolMode, STATEFUL_REQUESTED_PROTOCOL_VERSION,
    discover_params, discovery_allows_stateful_fallback, discovery_rejection, modern_params,
    negotiate_discovery, negotiate_initialize_result, require_modern_discovery,
};
use crate::tool_catalog::ToolCatalogBuilder;
use crate::tool_filter::{McpToolFilter, validate_bare_tool_name, validate_server_name};
use crate::{McpError, McpServerPolicy, McpToolCallEvidence, McpToolOutcome, McpWire};
use iteron_protocol::{ToolSpec, capability_set::CapabilitySet};
use serde_json::{Value, json};
use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

/// A `tools/call` result that omits `isError` is a success: the field is optional in the protocol
/// and absence must not be read as failure.
const TOOL_RESULT_IS_ERROR_DEFAULT: bool = false;

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
    protocol_mode: McpProtocolMode,
    list_cache: crate::cache::McpListCache,
    advertises_elicitation: bool,
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
            McpProtocolMode::Stateful,
        )
        .await
    }

    /// Prefer 2026 discovery and negotiate a stateful fallback on the same HTTP endpoint.
    pub async fn connect_auto(
        endpoint: McpHttpEndpoint,
        server_name: String,
        credential: Option<crate::token::Token>,
        header_policy: McpHttpHeaderPolicy,
        headers: Vec<(String, McpHeaderValue)>,
        oauth_grant: Option<crate::oauth::OAuthRefreshGrant>,
    ) -> Result<Self, McpError> {
        Self::connect_auto_with_policies(
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

    #[allow(clippy::too_many_arguments)]
    pub async fn connect_auto_with_policies(
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
            McpProtocolMode::Auto,
        )
        .await
    }

    /// Connect using the 2026-07-28 stateless HTTP protocol.
    pub async fn connect_2026(
        endpoint: McpHttpEndpoint,
        server_name: String,
        credential: Option<crate::token::Token>,
        header_policy: McpHttpHeaderPolicy,
        headers: Vec<(String, McpHeaderValue)>,
        oauth_grant: Option<crate::oauth::OAuthRefreshGrant>,
    ) -> Result<Self, McpError> {
        Self::connect_with_elicitation_and_policies(
            endpoint,
            server_name,
            credential,
            header_policy,
            headers,
            oauth_grant,
            None,
            crate::McpDeadlinePolicy::default().http(),
            crate::McpResultPolicy::default(),
            McpProtocolMode::Stateless2026,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn connect_2026_with_policies(
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
            McpProtocolMode::Stateless2026,
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
            McpProtocolMode::Stateful,
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
        protocol_mode: McpProtocolMode,
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
            protocol_mode,
            list_cache: crate::cache::McpListCache::new(),
            advertises_elicitation,
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
        let mut stateful_request_version = STATEFUL_REQUESTED_PROTOCOL_VERSION.to_owned();
        if protocol_mode.prefers_modern() {
            wire.set_protocol_version(crate::MODERN_PROTOCOL_VERSION)
                .await;
            let discover =
                || client.send_request_with_auth_retry("server/discover", discover_params());
            let first = tokio::time::timeout(deadlines.startup(), discover())
                .await
                .map_err(|_| McpError::Deadline {
                    operation: "2026 discovery handshake".into(),
                })?;
            let discovery = match first {
                Err(McpError::HttpStatus { status: 503 }) if protocol_mode.prefers_modern() => {
                    tokio::time::timeout(deadlines.startup(), discover())
                        .await
                        .map_err(|_| McpError::Deadline {
                            operation: "2026 discovery retry".into(),
                        })?
                }
                Err(error)
                    if matches!(
                        discovery_rejection(&error),
                        Some(DiscoveryRejection::RetryModern)
                    ) =>
                {
                    tokio::time::timeout(deadlines.startup(), discover())
                        .await
                        .map_err(|_| McpError::Deadline {
                            operation: "2026 discovery version retry".into(),
                        })?
                }
                result => result,
            };
            let negotiation = match discovery {
                Ok(result) => negotiate_discovery(&result)?,
                Err(error)
                    if protocol_mode == McpProtocolMode::Auto
                        && matches!(
                            discovery_rejection(&error),
                            Some(DiscoveryRejection::Stateful(_))
                        ) =>
                {
                    let Some(DiscoveryRejection::Stateful(version)) = discovery_rejection(&error)
                    else {
                        unreachable!("guard requires a stateful discovery rejection")
                    };
                    DiscoveryNegotiation::Stateful(version)
                }
                Err(error)
                    if protocol_mode == McpProtocolMode::Auto
                        && discovery_allows_stateful_fallback(&error) =>
                {
                    DiscoveryNegotiation::Stateful(STATEFUL_REQUESTED_PROTOCOL_VERSION.to_owned())
                }
                Err(error) => return Err(error),
            };
            match negotiation {
                DiscoveryNegotiation::Modern(version, capabilities) => {
                    client.negotiated_protocol_version = version;
                    client.capabilities = capabilities;
                    client.protocol_mode = McpProtocolMode::Stateless2026;
                    return Ok(client);
                }
                legacy @ DiscoveryNegotiation::Stateful(_)
                    if protocol_mode == McpProtocolMode::Stateless2026 =>
                {
                    require_modern_discovery(legacy)?;
                    unreachable!("strict modern negotiation cannot select a stateful version")
                }
                DiscoveryNegotiation::Stateful(version) => {
                    stateful_request_version = version;
                    client.protocol_mode = McpProtocolMode::Stateful;
                }
            }
        }
        wire.set_protocol_version(&stateful_request_version).await;
        let initialize_params = || {
            json!({
                "protocolVersion": stateful_request_version,
                "capabilities": if advertises_elicitation {
                    json!({"elicitation": {"form": {}}})
                } else {
                    json!({})
                },
                "clientInfo": {"name": "iteron", "version": env!("CARGO_PKG_VERSION")}
            })
        };
        let initialize = tokio::time::timeout(
            deadlines.startup(),
            client.send_request_with_auth_retry("initialize", initialize_params()),
        )
        .await
        .map_err(|_| McpError::Deadline {
            operation: "initialize handshake".into(),
        })?;
        let initialize = match initialize {
            Err(McpError::HttpStatus { status: 503 }) => tokio::time::timeout(
                deadlines.startup(),
                client.send_request_with_auth_retry("initialize", initialize_params()),
            )
            .await
            .map_err(|_| McpError::Deadline {
                operation: "initialize retry".into(),
            })?,
            result => result,
        }?;
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

    pub fn protocol_mode(&self) -> McpProtocolMode {
        self.protocol_mode
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
            let result = self.request("tools/list", params).await?;
            let next_cursor = pagination.accept_page(&result)?;
            catalog.accept_page(&self.server_name, &result)?;
            let Some(next_cursor) = next_cursor else {
                let mut tools = catalog.finish();
                if self.protocol_mode.is_stateless() {
                    tools.sort_by(|left, right| left.name.cmp(&right.name));
                }
                return Ok(tools);
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
                match self.params(json!({"name": name, "arguments": arguments.clone()})) {
                    Ok(params) => params,
                    Err(error) => {
                        return McpToolOutcome::FailedDefinite {
                            error,
                            evidence: None,
                        };
                    }
                },
            )
            .await;
        if matches!(result, Err(McpError::HttpStatus { status: 401 }))
            && certainty == McpEffectCertainty::Definite
            && self.refresh_after_rejection().await.is_ok()
        {
            (result, certainty) = self
                .wire
                .call_with_certainty(
                    "tools/call",
                    match self.params(json!({"name": name, "arguments": arguments})) {
                        Ok(params) => params,
                        Err(error) => {
                            return McpToolOutcome::FailedDefinite {
                                error,
                                evidence: None,
                            };
                        }
                    },
                )
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
        if self.protocol_mode.is_stateless()
            && result.get("resultType").and_then(Value::as_str) == Some("input_required")
        {
            return McpToolOutcome::FailedDefinite {
                error: McpError::Protocol(
                    "MCP MRTR input requires an interactive host handler".into(),
                ),
                evidence: Some(evidence),
            };
        }
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
            is_error: result.get("isError").and_then(Value::as_bool).unwrap_or(
                iteron_tunables::param_bool(
                    "mcp.remote.tool_result_is_error_default",
                    TOOL_RESULT_IS_ERROR_DEFAULT,
                ),
            ),
            evidence,
        }
    }

    /// Run an explicitly interactive 2026 tool call. Each additional request requires a fresh
    /// handler decision; the ordinary tool-call path never retries into MRTR.
    pub async fn call_tool_with_mrtr(
        &self,
        name: &str,
        arguments: Value,
        handler: &dyn crate::McpMrtrHandler,
    ) -> Result<String, McpError> {
        if !self.protocol_mode.is_stateless() {
            return Err(McpError::Protocol(
                "MRTR requires the 2026 stateless protocol".into(),
            ));
        }
        validate_bare_tool_name(name)?;
        let mut state = crate::mrtr::MrtrState::new();
        let mut params = json!({"name": name, "arguments": arguments});
        let started = Instant::now();
        loop {
            let remaining = self
                .deadlines
                .tool_call()
                .checked_sub(started.elapsed())
                .ok_or_else(|| McpError::Deadline {
                    operation: "MCP MRTR total interaction".into(),
                })?;
            let result = tokio::time::timeout(
                remaining,
                self.send_request_with_auth_retry("tools/call", self.params(params.clone())?),
            )
            .await
            .map_err(|_| McpError::Deadline {
                operation: "MCP MRTR total interaction".into(),
            })??;
            match state.inspect(&result)? {
                crate::mrtr::MrtrResult::Complete => {
                    let output =
                        render_tool_content(&result, self.result_policy, &self.spill_store)?;
                    self.cleanup_spills(crate::McpSpillCleanup::ToolEnd)?;
                    return Ok(output);
                }
                crate::mrtr::MrtrResult::InputRequired {
                    request_state,
                    requests,
                } => {
                    let decision = if requests.is_empty() {
                        crate::McpInputDecision::Approve(Vec::new())
                    } else {
                        let remaining = self
                            .deadlines
                            .tool_call()
                            .checked_sub(started.elapsed())
                            .ok_or_else(|| McpError::Deadline {
                            operation: "MCP MRTR total interaction".into(),
                        })?;
                        tokio::time::timeout(
                            remaining,
                            handler.request(
                                &self.server_name,
                                name,
                                request_state.as_deref(),
                                requests.clone(),
                            ),
                        )
                        .await
                        .map_err(|_| McpError::Deadline {
                            operation: "MCP MRTR user input".into(),
                        })??
                    };
                    let continuation = state.responses(request_state, &requests, decision)?;
                    let object = params.as_object_mut().expect("tool params are an object");
                    object.remove("requestState");
                    object.remove("inputResponses");
                    if let Some(request_state) = continuation.request_state {
                        object.insert("requestState".into(), Value::String(request_state));
                    }
                    if let Some(input_responses) = continuation.input_responses {
                        object.insert("inputResponses".into(), input_responses);
                    }
                }
            }
        }
    }

    /// Run a 2026 MRTR tool call without erasing post-dispatch uncertainty from the product
    /// effect ledger. All rounds share one total deadline and one external-effect dispatch mark.
    pub async fn call_tool_with_mrtr_outcome_observed<F>(
        &self,
        name: &str,
        arguments: Value,
        handler: &dyn crate::McpMrtrHandler,
        on_dispatch: F,
    ) -> McpToolOutcome
    where
        F: FnOnce() + Send + 'static,
    {
        if !self.protocol_mode.is_stateless() {
            return McpToolOutcome::FailedDefinite {
                error: McpError::Protocol("MRTR requires the 2026 stateless protocol".into()),
                evidence: None,
            };
        }
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
        let started = Instant::now();
        let mut state = crate::mrtr::MrtrState::new();
        let mut params = json!({"name": name, "arguments": arguments});
        let first_params = match self.params(params.clone()) {
            Ok(params) => params,
            Err(error) => {
                return McpToolOutcome::FailedDefinite {
                    error,
                    evidence: None,
                };
            }
        };
        on_dispatch();
        let mut first_params = Some(first_params);
        loop {
            let Some(remaining) = self.deadlines.tool_call().checked_sub(started.elapsed()) else {
                return remote_mrtr_unknown(
                    &self.server_name,
                    name,
                    started,
                    McpError::Deadline {
                        operation: "MCP MRTR total interaction".into(),
                    },
                );
            };
            let wire_params = match first_params.take() {
                Some(params) => params,
                None => match self.params(params.clone()) {
                    Ok(params) => params,
                    Err(error) => {
                        return remote_mrtr_failure(&self.server_name, name, started, error);
                    }
                },
            };
            let round = tokio::time::timeout(
                remaining,
                self.wire
                    .call_with_certainty("tools/call", wire_params.clone()),
            )
            .await;
            let (mut result, mut certainty) = match round {
                Ok(outcome) => outcome,
                Err(_) => {
                    return remote_mrtr_unknown(
                        &self.server_name,
                        name,
                        started,
                        McpError::Deadline {
                            operation: "MCP MRTR total interaction".into(),
                        },
                    );
                }
            };
            if matches!(result, Err(McpError::HttpStatus { status: 401 }))
                && certainty == McpEffectCertainty::Definite
                && self.refresh_after_rejection().await.is_ok()
            {
                let Some(remaining) = self.deadlines.tool_call().checked_sub(started.elapsed())
                else {
                    return remote_mrtr_unknown(
                        &self.server_name,
                        name,
                        started,
                        McpError::Deadline {
                            operation: "MCP MRTR total interaction".into(),
                        },
                    );
                };
                match tokio::time::timeout(
                    remaining,
                    self.wire.call_with_certainty("tools/call", wire_params),
                )
                .await
                {
                    Ok(outcome) => (result, certainty) = outcome,
                    Err(_) => {
                        return remote_mrtr_unknown(
                            &self.server_name,
                            name,
                            started,
                            McpError::Deadline {
                                operation: "MCP MRTR total interaction".into(),
                            },
                        );
                    }
                }
            }
            let result = match result {
                Ok(result) => result,
                Err(error) if certainty == McpEffectCertainty::Definite => {
                    if matches!(error, McpError::HttpStatus { status: 403 }) {
                        self.wire.revoke_credential().await;
                    }
                    return remote_mrtr_failure(&self.server_name, name, started, error);
                }
                Err(error) => {
                    return remote_mrtr_unknown(&self.server_name, name, started, error);
                }
            };
            match state.inspect(&result) {
                Ok(crate::mrtr::MrtrResult::Complete) => {
                    let evidence = remote_mrtr_evidence(&self.server_name, name, started);
                    let output =
                        match render_tool_content(&result, self.result_policy, &self.spill_store) {
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
                    return McpToolOutcome::Completed {
                        content: output,
                        is_error: result.get("isError").and_then(Value::as_bool).unwrap_or(
                            iteron_tunables::param_bool(
                                "mcp.remote.tool_result_is_error_default",
                                TOOL_RESULT_IS_ERROR_DEFAULT,
                            ),
                        ),
                        evidence,
                    };
                }
                Ok(crate::mrtr::MrtrResult::InputRequired {
                    request_state,
                    requests,
                }) => {
                    let decision = if requests.is_empty() {
                        crate::McpInputDecision::Approve(Vec::new())
                    } else {
                        let Some(remaining) =
                            self.deadlines.tool_call().checked_sub(started.elapsed())
                        else {
                            return remote_mrtr_failure(
                                &self.server_name,
                                name,
                                started,
                                McpError::Deadline {
                                    operation: "MCP MRTR total interaction".into(),
                                },
                            );
                        };
                        match tokio::time::timeout(
                            remaining,
                            handler.request(
                                &self.server_name,
                                name,
                                request_state.as_deref(),
                                requests.clone(),
                            ),
                        )
                        .await
                        {
                            Ok(Ok(decision)) => decision,
                            Ok(Err(error)) => {
                                return remote_mrtr_failure(
                                    &self.server_name,
                                    name,
                                    started,
                                    error,
                                );
                            }
                            Err(_) => {
                                return remote_mrtr_failure(
                                    &self.server_name,
                                    name,
                                    started,
                                    McpError::Deadline {
                                        operation: "MCP MRTR user input".into(),
                                    },
                                );
                            }
                        }
                    };
                    let continuation = match state.responses(request_state, &requests, decision) {
                        Ok(continuation) => continuation,
                        Err(error) => {
                            return remote_mrtr_failure(&self.server_name, name, started, error);
                        }
                    };
                    let object = params.as_object_mut().expect("tool params are an object");
                    object.remove("requestState");
                    object.remove("inputResponses");
                    if let Some(request_state) = continuation.request_state {
                        object.insert("requestState".into(), Value::String(request_state));
                    }
                    if let Some(input_responses) = continuation.input_responses {
                        object.insert("inputResponses".into(), input_responses);
                    }
                }
                Err(error) => {
                    return remote_mrtr_failure(&self.server_name, name, started, error);
                }
            }
        }
    }

    fn params(&self, params: Value) -> Result<Value, McpError> {
        if self.protocol_mode.is_stateless() {
            modern_params(params)
        } else {
            Ok(params)
        }
    }

    async fn request(&self, method: &str, params: Value) -> Result<Value, McpError> {
        if self.protocol_mode.is_stateless()
            && method.ends_with("/list")
            && let Some(cached) = self.list_cache.get(method, &params)
        {
            return Ok(cached);
        }
        let first = self
            .send_request_with_auth_retry(method, self.params(params.clone())?)
            .await;
        let first = match first {
            Err(McpError::HttpStatus { status })
                if method.ends_with("/list")
                    && crate::http::classify(status, false).is_retryable() =>
            {
                self.send_request_with_auth_retry(method, self.params(params.clone())?)
                    .await
            }
            result => result,
        };
        let result = match first {
            Err(McpError::SessionExpired)
                if !self.protocol_mode.is_stateless() && method.ends_with("/list") =>
            {
                self.reinitialize_stateful().await?;
                self.send_request_with_auth_retry(method, self.params(params.clone())?)
                    .await?
            }
            result => result?,
        };
        if self.protocol_mode.is_stateless() && method.ends_with("/list") {
            self.list_cache.put(method, &params, &result)?;
        }
        Ok(result)
    }

    async fn send_request_with_auth_retry(
        &self,
        method: &str,
        params: Value,
    ) -> Result<Value, McpError> {
        let first = self.wire.send_request(method, params.clone()).await;
        match first {
            Err(error @ McpError::HttpStatus { status: 401 }) if self.oauth.is_some() => {
                if self.refresh_after_rejection().await.is_ok() {
                    self.wire.send_request(method, params).await
                } else {
                    Err(error)
                }
            }
            result => result,
        }
    }

    async fn reinitialize_stateful(&self) -> Result<(), McpError> {
        self.wire.clear_session().await;
        self.wire
            .set_protocol_version(STATEFUL_REQUESTED_PROTOCOL_VERSION)
            .await;
        let initialize = tokio::time::timeout(
            self.deadlines.startup(),
            self.wire.send_request(
                "initialize",
                json!({
                    "protocolVersion": STATEFUL_REQUESTED_PROTOCOL_VERSION,
                    "capabilities": if self.advertises_elicitation {
                        json!({"elicitation": {"form": {}}})
                    } else {
                        json!({})
                    },
                    "clientInfo": {"name": "iteron", "version": env!("CARGO_PKG_VERSION")}
                }),
            ),
        )
        .await
        .map_err(|_| McpError::Deadline {
            operation: "MCP HTTP session re-initialize".into(),
        })??;
        let version = negotiate_initialize_result(&initialize)?;
        if version != self.negotiated_protocol_version
            || capabilities_from(&initialize) != self.capabilities
        {
            return Err(McpError::Protocol(
                "MCP server contract changed while replacing an expired session".into(),
            ));
        }
        self.wire.set_protocol_version(version).await;
        tokio::time::timeout(
            self.deadlines.startup(),
            self.wire
                .send_notification("notifications/initialized", json!({})),
        )
        .await
        .map_err(|_| McpError::Deadline {
            operation: "MCP HTTP session re-initialized notification".into(),
        })??;
        Ok(())
    }

    /// Invoke the standard resource/prompt surface under the same response ceilings as tools.
    pub async fn call_extension(&self, method: &str, params: Value) -> Result<Value, McpError> {
        match method {
            "resources/list" | "resources/read" if self.capabilities.resources => {}
            "prompts/list" | "prompts/get" if self.capabilities.prompts => {}
            _ => return Err(McpError::Protocol("MCP capability is not declared".into())),
        }
        self.refresh_if_needed().await?;
        if self.protocol_mode.is_stateless() && matches!(method, "resources/list" | "prompts/list")
        {
            let mut pages = crate::pagination::ExtensionPagination::new(method)?;
            let mut request = params;
            loop {
                let result = self.request(method, request).await?;
                let Some(next) = pages.accept(&result)? else {
                    return Ok(pages.finish());
                };
                request = next;
            }
        }
        self.request(method, params).await
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
        let params = match self.params(params) {
            Ok(params) => params,
            Err(error) => {
                return McpToolOutcome::FailedDefinite {
                    error,
                    evidence: None,
                };
            }
        };
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

fn remote_mrtr_evidence(server: &str, name: &str, started: Instant) -> McpToolCallEvidence {
    let elapsed = u64::try_from(started.elapsed().as_millis())
        .unwrap_or(u64::MAX)
        .max(1);
    McpToolCallEvidence::new(
        server,
        name,
        NonZeroU64::new(elapsed).expect("elapsed was clamped to at least one"),
    )
}

fn remote_mrtr_failure(
    server: &str,
    name: &str,
    started: Instant,
    error: McpError,
) -> McpToolOutcome {
    McpToolOutcome::FailedDefinite {
        error,
        evidence: Some(remote_mrtr_evidence(server, name, started)),
    }
}

fn remote_mrtr_unknown(
    server: &str,
    name: &str,
    started: Instant,
    error: McpError,
) -> McpToolOutcome {
    McpToolOutcome::Unknown {
        error,
        evidence: remote_mrtr_evidence(server, name, started),
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
    use crate::protocol_version::STATEFUL_REQUESTED_PROTOCOL_VERSION;
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
                        "protocolVersion": STATEFUL_REQUESTED_PROTOCOL_VERSION,
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

    async fn expiring_session_server() -> (
        String,
        StdArc<StdMutex<Vec<String>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let seen = StdArc::new(StdMutex::new(Vec::new()));
        let recorded = seen.clone();
        let task = tokio::spawn(async move {
            for index in 0..6 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let request = read_request(&mut socket).await;
                let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
                let message: Value = serde_json::from_str(body).unwrap();
                recorded.lock().unwrap().push(request);
                if index == 2 {
                    socket
                        .write_all(
                            b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                        )
                        .await
                        .unwrap();
                    continue;
                }
                let Some(id) = message.get("id") else {
                    socket
                        .write_all(
                            b"HTTP/1.1 202 Accepted\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                        )
                        .await
                        .unwrap();
                    continue;
                };
                let method = message.get("method").and_then(Value::as_str).unwrap();
                let result = if method == "initialize" {
                    json!({
                        "protocolVersion": STATEFUL_REQUESTED_PROTOCOL_VERSION,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "fixture", "version": "1.0.0"}
                    })
                } else {
                    assert_eq!(method, "tools/list");
                    json!({"tools": [{
                        "name": "read_public",
                        "description": "read public data",
                        "inputSchema": {"type": "object"}
                    }]})
                };
                let frame = json!({"jsonrpc":"2.0", "id":id, "result":result}).to_string();
                let session = match index {
                    0 => "mcp-session-id: session-old\r\n",
                    3 => "mcp-session-id: session-new\r\n",
                    _ => "",
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n{session}content-length: {}\r\nconnection: close\r\n\r\n{frame}",
                    frame.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        (format!("http://{address}/mcp"), seen, task)
    }

    async fn unauthorized_then_refresh_server() -> (
        String,
        StdArc<StdMutex<Vec<String>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let seen = StdArc::new(StdMutex::new(Vec::new()));
        let recorded = seen.clone();
        let task = tokio::spawn(async move {
            for index in 0..4 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let request = read_request(&mut socket).await;
                recorded.lock().unwrap().push(request.clone());
                let response = match index {
                    0 => "HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_owned(),
                    1 => {
                        assert!(request.starts_with("POST /refresh "));
                        let body = r#"{"access_token":"access-next","expires_in":3600,"token_type":"Bearer","scope":"mcp"}"#;
                        format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len())
                    }
                    2 => {
                        assert!(
                            request
                                .to_ascii_lowercase()
                                .contains("authorization: bearer access-next")
                        );
                        let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
                        let message: Value = serde_json::from_str(body).unwrap();
                        let id = message.get("id").unwrap();
                        let frame = json!({
                            "jsonrpc":"2.0",
                            "id":id,
                            "result":{
                                "protocolVersion":STATEFUL_REQUESTED_PROTOCOL_VERSION,
                                "capabilities":{"tools":{}},
                                "serverInfo":{"name":"fixture","version":"1"}
                            }
                        }).to_string();
                        format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nmcp-session-id: refreshed\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{frame}", frame.len())
                    }
                    _ => "HTTP/1.1 202 Accepted\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_owned(),
                };
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        (format!("http://{address}"), seen, task)
    }

    struct RejectInputs;

    impl crate::McpMrtrHandler for RejectInputs {
        fn request<'a>(
            &'a self,
            _server_name: &'a str,
            _tool_name: &'a str,
            _request_state: Option<&'a str>,
            _requests: Vec<crate::McpInputRequest>,
        ) -> crate::McpFuture<'a, crate::McpInputDecision> {
            Box::pin(async { Ok(crate::McpInputDecision::Reject) })
        }
    }

    struct ApproveInputs;

    impl crate::McpMrtrHandler for ApproveInputs {
        fn request<'a>(
            &'a self,
            server_name: &'a str,
            tool_name: &'a str,
            request_state: Option<&'a str>,
            requests: Vec<crate::McpInputRequest>,
        ) -> crate::McpFuture<'a, crate::McpInputDecision> {
            Box::pin(async move {
                assert_eq!(server_name, "fixture");
                assert_eq!(tool_name, "interactive");
                assert_eq!(request_state, Some("approval-1"));
                assert_eq!(requests.len(), 1);
                Ok(crate::McpInputDecision::Approve(vec![(
                    requests[0].id().to_owned(),
                    json!({"confirm": true}),
                )]))
            })
        }
    }

    #[tokio::test]
    async fn stateless_mrtr_requires_a_handler_and_rejection_never_replays_the_tool() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let seen = StdArc::new(StdMutex::new(Vec::new()));
        let recorded = seen.clone();
        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let request = read_request(&mut socket).await;
                let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
                let message: Value = serde_json::from_str(body).unwrap();
                let id = message.get("id").unwrap();
                let method = message.get("method").and_then(Value::as_str).unwrap();
                recorded.lock().unwrap().push(request);
                let result = match method {
                    "server/discover" => json!({
                        "resultType": "complete",
                        "supportedVersions": [crate::MODERN_PROTOCOL_VERSION],
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "fixture", "version": "1"}
                    }),
                    "tools/call" => json!({
                        "resultType": "input_required",
                        "requestState": "approval-1",
                        "inputRequests": {"confirm": {
                            "method": "elicitation/create",
                            "params": {
                                "message": "Continue?",
                                "requestedSchema": {
                                    "type":"object",
                                    "properties":{"confirm":{"type":"boolean"}},
                                    "required":["confirm"]
                                }
                            }
                        }}
                    }),
                    other => panic!("unexpected method {other}"),
                };
                let frame = json!({"jsonrpc":"2.0", "id":id, "result":result}).to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{frame}",
                    frame.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let client = McpRemoteClient::connect_2026(
            McpHttpEndpoint::parse(&format!("http://{address}/mcp")).unwrap(),
            "fixture".into(),
            None,
            McpHttpHeaderPolicy::default(),
            Vec::new(),
            None,
        )
        .await
        .unwrap();
        assert!(matches!(
            client
                .call_tool_outcome_observed("interactive", json!({}), || {})
                .await,
            McpToolOutcome::FailedDefinite {
                error: McpError::Protocol(_),
                ..
            }
        ));
        assert!(matches!(
            client
                .call_tool_with_mrtr("interactive", json!({}), &RejectInputs)
                .await,
            Err(McpError::Cancelled { .. })
        ));
        server.await.unwrap();
        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert!(!requests[1].contains("inputResponses"));
        assert!(!requests[2].contains("inputResponses"));
    }

    #[tokio::test]
    async fn stateless_http_mrtr_resumes_with_correlated_input_and_one_dispatch_mark() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for index in 0..3 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let request = read_request(&mut socket).await;
                let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
                let message: Value = serde_json::from_str(body).unwrap();
                let id = message.get("id").unwrap();
                let method = message.get("method").and_then(Value::as_str).unwrap();
                let result = match (index, method) {
                    (0, "server/discover") => json!({
                        "resultType": "complete",
                        "supportedVersions": [crate::MODERN_PROTOCOL_VERSION],
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "fixture", "version": "1"}
                    }),
                    (1, "tools/call") => {
                        assert!(message["params"].get("inputResponses").is_none());
                        json!({
                            "resultType": "input_required",
                            "requestState": "approval-1",
                            "inputRequests": {"confirm": {
                                "method": "elicitation/create",
                                "params": {
                                    "message": "Continue?",
                                    "requestedSchema": {
                                        "type":"object",
                                        "properties":{"confirm":{"type":"boolean"}},
                                        "required":["confirm"]
                                    }
                                }
                            }}
                        })
                    }
                    (2, "tools/call") => {
                        assert_eq!(message["params"]["requestState"], "approval-1");
                        assert_eq!(
                            message["params"]["inputResponses"]["confirm"]["action"],
                            "accept"
                        );
                        assert_eq!(
                            message["params"]["inputResponses"]["confirm"]["content"],
                            json!({"confirm": true})
                        );
                        json!({
                            "resultType": "complete",
                            "content": [{"type":"text", "text":"continued"}]
                        })
                    }
                    other => panic!("unexpected request {other:?}"),
                };
                let frame = json!({"jsonrpc":"2.0", "id":id, "result":result}).to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{frame}",
                    frame.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let client = McpRemoteClient::connect_2026(
            McpHttpEndpoint::parse(&format!("http://{address}/mcp")).unwrap(),
            "fixture".into(),
            None,
            McpHttpHeaderPolicy::default(),
            Vec::new(),
            None,
        )
        .await
        .unwrap();
        let dispatches = StdArc::new(StdMutex::new(0_u8));
        let observed = dispatches.clone();
        let outcome = client
            .call_tool_with_mrtr_outcome_observed(
                "interactive",
                json!({}),
                &ApproveInputs,
                move || *observed.lock().unwrap() += 1,
            )
            .await;
        assert!(matches!(
            outcome,
            McpToolOutcome::Completed {
                content,
                is_error: false,
                ..
            } if content == "continued\n"
        ));
        assert_eq!(*dispatches.lock().unwrap(), 1);
        server.await.unwrap();
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
            STATEFUL_REQUESTED_PROTOCOL_VERSION
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
            "\"protocolVersion\":\"{STATEFUL_REQUESTED_PROTOCOL_VERSION}\""
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
                    "mcp-protocol-version: {STATEFUL_REQUESTED_PROTOCOL_VERSION}"
                )))
        );
    }

    #[tokio::test]
    async fn expired_session_reinitializes_once_before_replaying_a_read_only_list() {
        let (url, seen, server) = expiring_session_server().await;
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
            client
                .list_tools_governed(
                    &McpToolFilter::default(),
                    &McpServerPolicy::default(),
                    crate::default_host_ceiling(),
                )
                .await
                .unwrap()
                .len(),
            1
        );
        server.await.unwrap();

        let requests = seen.lock().unwrap();
        assert!(
            requests[2]
                .to_ascii_lowercase()
                .contains("mcp-session-id: session-old")
        );
        assert!(!requests[3].to_ascii_lowercase().contains("mcp-session-id:"));
        assert!(
            requests[5]
                .to_ascii_lowercase()
                .contains("mcp-session-id: session-new")
        );
    }

    #[tokio::test]
    async fn unauthorized_initialize_refreshes_once_and_retries_once() {
        let (origin, seen, server) = unauthorized_then_refresh_server().await;
        let grant = crate::oauth::OAuthRefreshGrant::new(
            McpHttpEndpoint::parse(&format!("{origin}/refresh")).unwrap(),
            None,
            "refresh-initial".into(),
            Some("client".into()),
            None,
            crate::oauth::TokenEndpointAuthMethod::None,
            vec!["mcp".into()],
        )
        .unwrap();
        let client = McpRemoteClient::connect(
            McpHttpEndpoint::parse(&format!("{origin}/mcp")).unwrap(),
            "fixture".into(),
            Some(crate::token::Token::new("access-stale", u64::MAX)),
            McpHttpHeaderPolicy::default(),
            Vec::new(),
            Some(grant),
        )
        .await
        .unwrap();
        assert_eq!(
            client.negotiated_protocol_version(),
            STATEFUL_REQUESTED_PROTOCOL_VERSION
        );
        server.await.unwrap();
        let requests = seen.lock().unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.starts_with("POST /refresh "))
                .count(),
            1
        );
    }
}
