//! OAuth refresh and revocation effects for remote MCP bindings.

use crate::http::McpHttpEndpoint;
use crate::token::Token;
use crate::{MAX_FRAME_BYTES, McpError};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

const OAUTH_TIMEOUT: Duration = Duration::from_secs(30);
/// TCP connect is bounded well below the whole-exchange timeout so an unreachable authorization
/// server fails fast instead of consuming the full request budget.
const OAUTH_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_OAUTH_SECRET_BYTES: usize = 8192;
/// Ceiling on a configured OAuth client id. It is a registered identifier, not a credential, so it
/// is bounded far tighter than a secret and never reaches a request body unchecked.
const MAX_OAUTH_CLIENT_ID_BYTES: usize = 1024;

/// Refresh authority. Secrets are process-local and this type deliberately implements neither
/// `Debug` nor `Display`.
pub struct OAuthRefreshGrant {
    endpoint: McpHttpEndpoint,
    revoke_endpoint: Option<McpHttpEndpoint>,
    refresh_token: String,
    client_id: Option<String>,
    client_secret: Option<String>,
    token_auth_method: TokenEndpointAuthMethod,
    granted_scopes: std::collections::BTreeSet<String>,
    persistence: Option<Arc<dyn OAuthRefreshPersistence>>,
}

/// Refreshed secret material handed only to the caller-provided private credential store.
/// Deliberately implements neither `Debug` nor `Display`.
pub struct OAuthRefreshUpdate {
    access_token: String,
    expires_at_unix: u64,
    refresh_token: String,
    granted_scopes: Vec<String>,
}

impl OAuthRefreshUpdate {
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    pub const fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    pub fn refresh_token(&self) -> &str {
        &self.refresh_token
    }

    pub fn granted_scopes(&self) -> &[String] {
        &self.granted_scopes
    }
}

/// Persistence boundary for rotated OAuth credentials. Implementations must keep the update
/// private and install it atomically before the refreshed token can be used by the client.
pub trait OAuthRefreshPersistence: Send + Sync {
    fn persist(&self, update: &OAuthRefreshUpdate) -> Result<(), McpError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenEndpointAuthMethod {
    None,
    ClientSecretBasic,
    ClientSecretPost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpOAuthCredentialMode {
    Disabled,
    Bearer,
    RefreshToken,
}

/// Content-free lifecycle facts enforced by one remote MCP binding. This is deliberately separate
/// from `OAuthRefreshGrant`, whose secrets cannot implement `Debug` or `Serialize`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct McpOAuthLifecyclePolicy {
    credential_mode: McpOAuthCredentialMode,
    refresh_before_expiry_when_capable: bool,
    retry_once_after_unauthorized_when_capable: bool,
    revoke_access_after_forbidden: bool,
    expiry_skew_seconds: u64,
    revocation_endpoint_configured: bool,
}

impl McpOAuthLifecyclePolicy {
    pub const fn for_binding(
        credential_configured: bool,
        refresh_configured: bool,
        revocation_endpoint_configured: bool,
    ) -> Self {
        let credential_mode = if refresh_configured {
            McpOAuthCredentialMode::RefreshToken
        } else if credential_configured {
            McpOAuthCredentialMode::Bearer
        } else {
            McpOAuthCredentialMode::Disabled
        };
        Self {
            credential_mode,
            refresh_before_expiry_when_capable: refresh_configured,
            retry_once_after_unauthorized_when_capable: refresh_configured,
            revoke_access_after_forbidden: credential_configured || refresh_configured,
            expiry_skew_seconds: crate::token::EXPIRY_SKEW_SECS,
            revocation_endpoint_configured: refresh_configured && revocation_endpoint_configured,
        }
    }

    pub const fn credential_mode(self) -> McpOAuthCredentialMode {
        self.credential_mode
    }

    pub const fn refresh_before_expiry_when_capable(self) -> bool {
        self.refresh_before_expiry_when_capable
    }

    pub const fn retry_once_after_unauthorized_when_capable(self) -> bool {
        self.retry_once_after_unauthorized_when_capable
    }

    pub const fn revoke_access_after_forbidden(self) -> bool {
        self.revoke_access_after_forbidden
    }

    pub const fn expiry_skew_seconds(self) -> u64 {
        self.expiry_skew_seconds
    }

    pub const fn revocation_endpoint_configured(self) -> bool {
        self.revocation_endpoint_configured
    }
}

impl OAuthRefreshGrant {
    pub fn new(
        endpoint: McpHttpEndpoint,
        revoke_endpoint: Option<McpHttpEndpoint>,
        refresh_token: String,
        client_id: Option<String>,
        client_secret: Option<String>,
        token_auth_method: TokenEndpointAuthMethod,
        granted_scopes: impl IntoIterator<Item = String>,
    ) -> Result<Self, McpError> {
        validate_secret(&refresh_token)?;
        if let Some(client_secret) = &client_secret {
            validate_secret(client_secret)?;
        }
        if let Some(client_id) = &client_id
            && (client_id.is_empty()
                || client_id.len()
                    > iteron_tunables::param_integer(
                        "mcp.oauth.max_oauth_client_id_bytes",
                        MAX_OAUTH_CLIENT_ID_BYTES,
                    )
                || client_id.chars().any(char::is_control))
        {
            return Err(McpError::InvalidEndpoint {
                field: "oauth_client_id",
                limit: iteron_tunables::param_integer(
                    "mcp.oauth.max_oauth_client_id_bytes",
                    MAX_OAUTH_CLIENT_ID_BYTES,
                ),
            });
        }
        if token_auth_method != TokenEndpointAuthMethod::None
            && (client_id.is_none() || client_secret.is_none())
        {
            return Err(McpError::InvalidEndpoint {
                field: "oauth_token_auth",
                limit: 0,
            });
        }
        Ok(Self {
            endpoint,
            revoke_endpoint,
            refresh_token,
            client_id,
            client_secret,
            token_auth_method,
            granted_scopes: granted_scopes.into_iter().collect(),
            persistence: None,
        })
    }

    pub fn with_persistence(mut self, persistence: Arc<dyn OAuthRefreshPersistence>) -> Self {
        self.persistence = Some(persistence);
        self
    }

    pub(crate) fn revocation_endpoint_configured(&self) -> bool {
        self.revoke_endpoint.is_some()
    }
}

pub(crate) struct OAuthClient {
    client: reqwest::Client,
}

impl OAuthClient {
    pub(crate) fn new() -> Result<Self, McpError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(iteron_tunables::param_duration(
                "mcp.oauth.oauth_connect_timeout",
                OAUTH_CONNECT_TIMEOUT,
            ))
            .timeout(iteron_tunables::param_duration(
                "mcp.oauth.oauth_timeout",
                OAUTH_TIMEOUT,
            ))
            .build()
            .map_err(|_| transport_error("client"))?;
        Ok(Self { client })
    }

    pub(crate) async fn refresh(
        &self,
        grant: &mut OAuthRefreshGrant,
        now_secs: u64,
    ) -> Result<Token, McpError> {
        let mut form = vec![
            ("grant_type", "refresh_token".to_owned()),
            ("refresh_token", grant.refresh_token.clone()),
        ];
        let mut request = self.client.post(grant.endpoint.expose_url());
        match grant.token_auth_method {
            TokenEndpointAuthMethod::None => {
                if let Some(client_id) = &grant.client_id {
                    form.push(("client_id", client_id.clone()));
                }
            }
            TokenEndpointAuthMethod::ClientSecretBasic => {
                request = request.basic_auth(
                    grant.client_id.as_deref().unwrap_or_default(),
                    grant.client_secret.as_deref(),
                );
            }
            TokenEndpointAuthMethod::ClientSecretPost => {
                if let Some(client_id) = &grant.client_id {
                    form.push(("client_id", client_id.clone()));
                }
                if let Some(client_secret) = &grant.client_secret {
                    form.push(("client_secret", client_secret.clone()));
                }
            }
        }
        let response = request
            .form(&form)
            .send()
            .await
            .map_err(|_| transport_error("refresh"))?;
        let status = response.status().as_u16();
        if (300..=399).contains(&status) {
            return Err(McpError::HttpRedirectRefused);
        }
        if !response.status().is_success() {
            return Err(McpError::HttpStatus { status });
        }
        let bytes = read_bounded_body(response, "refresh_body").await?;
        let response: RefreshResponse = serde_json::from_slice(&bytes)?;
        if response
            .token_type
            .as_deref()
            .is_some_and(|kind| !kind.eq_ignore_ascii_case("bearer"))
        {
            return Err(McpError::Protocol(
                "OAuth refresh returned a non-bearer token".into(),
            ));
        }
        let refreshed_scopes =
            validate_refresh_scope(response.scope.as_deref(), &grant.granted_scopes)?;
        validate_secret(&response.access_token)?;
        let refresh_token = if let Some(rotated) = response.refresh_token {
            validate_secret(&rotated)?;
            rotated
        } else {
            grant.refresh_token.clone()
        };
        let expires_at_unix = now_secs.saturating_add(response.expires_in);
        let update = OAuthRefreshUpdate {
            access_token: response.access_token.clone(),
            expires_at_unix,
            refresh_token: refresh_token.clone(),
            granted_scopes: refreshed_scopes.iter().cloned().collect(),
        };
        if let Some(persistence) = &grant.persistence {
            persistence.persist(&update)?;
        }
        grant.refresh_token = refresh_token;
        grant.granted_scopes = refreshed_scopes;
        Ok(Token::new(response.access_token, expires_at_unix))
    }

    pub(crate) async fn revoke(&self, grant: &OAuthRefreshGrant) -> Result<(), McpError> {
        let Some(endpoint) = &grant.revoke_endpoint else {
            return Ok(());
        };
        let mut form = vec![
            ("token", grant.refresh_token.clone()),
            ("token_type_hint", "refresh_token".to_owned()),
        ];
        let mut request = self.client.post(endpoint.expose_url());
        match grant.token_auth_method {
            TokenEndpointAuthMethod::None => {
                if let Some(client_id) = &grant.client_id {
                    form.push(("client_id", client_id.clone()));
                }
            }
            TokenEndpointAuthMethod::ClientSecretBasic => {
                request = request.basic_auth(
                    grant.client_id.as_deref().unwrap_or_default(),
                    grant.client_secret.as_deref(),
                );
            }
            TokenEndpointAuthMethod::ClientSecretPost => {
                if let Some(client_id) = &grant.client_id {
                    form.push(("client_id", client_id.clone()));
                }
                if let Some(client_secret) = &grant.client_secret {
                    form.push(("client_secret", client_secret.clone()));
                }
            }
        }
        let response = request
            .form(&form)
            .send()
            .await
            .map_err(|_| transport_error("revoke"))?;
        let status = response.status().as_u16();
        if (300..=399).contains(&status) {
            return Err(McpError::HttpRedirectRefused);
        }
        if !response.status().is_success() {
            return Err(McpError::HttpStatus { status });
        }
        Ok(())
    }
}

async fn read_bounded_body(
    mut response: reqwest::Response,
    stage: &'static str,
) -> Result<Vec<u8>, McpError> {
    let mut bytes = Vec::with_capacity(
        response
            .content_length()
            .unwrap_or(0)
            .min(MAX_FRAME_BYTES as u64) as usize,
    );
    while let Some(chunk) = response.chunk().await.map_err(|_| transport_error(stage))? {
        if bytes.len().saturating_add(chunk.len()) > MAX_FRAME_BYTES {
            return Err(McpError::FrameTooLarge {
                limit: MAX_FRAME_BYTES,
            });
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[derive(Deserialize)]
struct RefreshResponse {
    access_token: String,
    expires_in: u64,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

fn validate_refresh_scope(
    scope: Option<&str>,
    granted: &std::collections::BTreeSet<String>,
) -> Result<std::collections::BTreeSet<String>, McpError> {
    let Some(scope) = scope else {
        return Ok(granted.clone());
    };
    if scope.is_empty()
        || scope.len() > MAX_OAUTH_SECRET_BYTES
        || scope.chars().any(char::is_control)
    {
        return Err(McpError::Protocol("OAuth refresh scope is invalid".into()));
    }
    let scopes = scope
        .split_ascii_whitespace()
        .map(str::to_owned)
        .collect::<std::collections::BTreeSet<_>>();
    if !scopes.is_subset(granted) {
        return Err(McpError::Protocol(
            "OAuth refresh scope exceeds the original grant".into(),
        ));
    }
    Ok(scopes)
}

fn validate_secret(secret: &str) -> Result<(), McpError> {
    if secret.is_empty()
        || secret.len()
            > iteron_tunables::param_integer(
                "mcp.oauth.max_oauth_secret_bytes",
                MAX_OAUTH_SECRET_BYTES,
            )
        || secret.contains('\0')
    {
        return Err(McpError::InvalidEndpoint {
            field: "oauth_token",
            limit: iteron_tunables::param_integer(
                "mcp.oauth.max_oauth_secret_bytes",
                MAX_OAUTH_SECRET_BYTES,
            ),
        });
    }
    Ok(())
}

fn transport_error(stage: &'static str) -> McpError {
    McpError::Io(format!("MCP OAuth {stage} failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex as StdMutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    async fn read_request(socket: &mut TcpStream) -> String {
        let mut request = Vec::new();
        let mut chunk = [0_u8; 2048];
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

    async fn oauth_server() -> (
        String,
        Arc<StdMutex<Vec<String>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let recorded = seen.clone();
        let task = tokio::spawn(async move {
            for response_body in [
                Some(
                    r#"{"access_token":"access-next","expires_in":3600,"refresh_token":"refresh-next","token_type":"Bearer","scope":"mcp"}"#,
                ),
                None,
            ] {
                let (mut socket, _) = listener.accept().await.unwrap();
                let request = read_request(&mut socket).await;
                recorded.lock().unwrap().push(request);
                let body = response_body.unwrap_or("");
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
                socket.shutdown().await.unwrap();
            }
        });
        (format!("http://{address}"), seen, task)
    }

    #[tokio::test]
    async fn refresh_rotates_the_grant_accepts_additive_fields_and_revoke_uses_the_rotation() {
        let (origin, seen, server) = oauth_server().await;
        let mut grant = OAuthRefreshGrant::new(
            McpHttpEndpoint::parse(&format!("{origin}/refresh")).unwrap(),
            Some(McpHttpEndpoint::parse(&format!("{origin}/revoke")).unwrap()),
            "refresh-initial".into(),
            Some("client-id".into()),
            Some("client-secret".into()),
            TokenEndpointAuthMethod::ClientSecretPost,
            ["mcp".to_owned()],
        )
        .unwrap();
        let client = OAuthClient::new().unwrap();
        let token = client.refresh(&mut grant, 1_000).await.unwrap();
        assert_eq!(token.state(1_001), crate::token::State::Fresh);
        client.revoke(&grant).await.unwrap();
        server.await.unwrap();

        let requests = seen.lock().unwrap();
        assert!(requests[0].starts_with("POST /refresh "));
        assert!(requests[0].contains("grant_type=refresh_token"));
        assert!(requests[0].contains("refresh_token=refresh-initial"));
        assert!(requests[1].starts_with("POST /revoke "));
        assert!(requests[1].contains("token=refresh-next"));
        assert!(requests[1].contains("token_type_hint=refresh_token"));
    }

    #[test]
    fn credential_authority_is_bounded_and_not_printable() {
        assert!(
            OAuthRefreshGrant::new(
                McpHttpEndpoint::parse("https://example.com/token").unwrap(),
                None,
                String::new(),
                None,
                None,
                TokenEndpointAuthMethod::None,
                Vec::new(),
            )
            .is_err()
        );
        assert!(
            OAuthRefreshGrant::new(
                McpHttpEndpoint::parse("https://example.com/token").unwrap(),
                None,
                "r".into(),
                Some("bad\nclient".into()),
                None,
                TokenEndpointAuthMethod::None,
                Vec::new(),
            )
            .is_err()
        );
        assert!(
            OAuthRefreshGrant::new(
                McpHttpEndpoint::parse("https://example.com/token").unwrap(),
                None,
                "refresh".into(),
                Some("client".into()),
                None,
                TokenEndpointAuthMethod::ClientSecretBasic,
                Vec::new(),
            )
            .is_err()
        );
        let granted = std::collections::BTreeSet::from(["mcp".to_owned()]);
        assert!(validate_refresh_scope(None, &granted).is_ok());
        assert!(validate_refresh_scope(Some("mcp"), &granted).is_ok());
        assert!(validate_refresh_scope(Some("mcp admin"), &granted).is_err());
        assert!(validate_refresh_scope(Some("other"), &granted).is_err());
    }
}
