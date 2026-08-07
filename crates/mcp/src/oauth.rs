//! OAuth refresh and revocation effects for remote MCP bindings.

use crate::http::McpHttpEndpoint;
use crate::token::Token;
use crate::{MAX_FRAME_BYTES, McpError};
use serde::Deserialize;
use std::time::Duration;

const OAUTH_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_OAUTH_SECRET_BYTES: usize = 8192;

/// Refresh authority. Secrets are process-local and this type deliberately implements neither
/// `Debug` nor `Display`.
pub struct OAuthRefreshGrant {
    endpoint: McpHttpEndpoint,
    revoke_endpoint: Option<McpHttpEndpoint>,
    refresh_token: String,
    client_id: Option<String>,
    client_secret: Option<String>,
}

impl OAuthRefreshGrant {
    pub fn new(
        endpoint: McpHttpEndpoint,
        revoke_endpoint: Option<McpHttpEndpoint>,
        refresh_token: String,
        client_id: Option<String>,
        client_secret: Option<String>,
    ) -> Result<Self, McpError> {
        validate_secret(&refresh_token)?;
        if let Some(client_secret) = &client_secret {
            validate_secret(client_secret)?;
        }
        if let Some(client_id) = &client_id
            && (client_id.is_empty()
                || client_id.len() > 1024
                || client_id.chars().any(char::is_control))
        {
            return Err(McpError::InvalidEndpoint {
                field: "oauth_client_id",
                limit: 1024,
            });
        }
        Ok(Self {
            endpoint,
            revoke_endpoint,
            refresh_token,
            client_id,
            client_secret,
        })
    }
}

pub(crate) struct OAuthClient {
    client: reqwest::Client,
}

impl OAuthClient {
    pub(crate) fn new() -> Result<Self, McpError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(OAUTH_TIMEOUT)
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
        if let Some(client_id) = &grant.client_id {
            form.push(("client_id", client_id.clone()));
        }
        if let Some(client_secret) = &grant.client_secret {
            form.push(("client_secret", client_secret.clone()));
        }
        let response = self
            .client
            .post(grant.endpoint.expose_url())
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
        let bytes = response
            .bytes()
            .await
            .map_err(|_| transport_error("refresh_body"))?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(McpError::FrameTooLarge {
                limit: MAX_FRAME_BYTES,
            });
        }
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
        validate_secret(&response.access_token)?;
        if let Some(rotated) = response.refresh_token {
            validate_secret(&rotated)?;
            grant.refresh_token = rotated;
        }
        Ok(Token::from_expires_in(
            response.access_token,
            now_secs,
            response.expires_in,
        ))
    }

    pub(crate) async fn revoke(&self, grant: &OAuthRefreshGrant) -> Result<(), McpError> {
        let Some(endpoint) = &grant.revoke_endpoint else {
            return Ok(());
        };
        let mut form = vec![
            ("token", grant.refresh_token.clone()),
            ("token_type_hint", "refresh_token".to_owned()),
        ];
        if let Some(client_id) = &grant.client_id {
            form.push(("client_id", client_id.clone()));
        }
        if let Some(client_secret) = &grant.client_secret {
            form.push(("client_secret", client_secret.clone()));
        }
        let response = self
            .client
            .post(endpoint.expose_url())
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

#[derive(Deserialize)]
struct RefreshResponse {
    access_token: String,
    expires_in: u64,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
}

fn validate_secret(secret: &str) -> Result<(), McpError> {
    if secret.is_empty() || secret.len() > MAX_OAUTH_SECRET_BYTES || secret.contains('\0') {
        return Err(McpError::InvalidEndpoint {
            field: "oauth_token",
            limit: MAX_OAUTH_SECRET_BYTES,
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
            )
            .is_err()
        );
    }
}
