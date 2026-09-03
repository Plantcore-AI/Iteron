//! Bounded browser OAuth login for one configured HTTP MCP resource.

use super::credential_store::StoredCredential;
use crate::config::McpServerConfig;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use url::Url;

const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(180);
const CALLBACK_REQUEST_LIMIT: usize = 16 * 1024;
const METADATA_LIMIT: usize = 256 * 1024;
const REQUIRED_SCOPE: &str = "mcp";

#[derive(Deserialize)]
struct ResourceMetadata {
    resource: String,
    authorization_servers: Vec<String>,
}

#[derive(Deserialize)]
struct AuthorizationMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(default)]
    registration_endpoint: Option<String>,
    #[serde(default)]
    revocation_endpoint: Option<String>,
    #[serde(default)]
    client_id_metadata_document_supported: bool,
    #[serde(default)]
    authorization_response_iss_parameter_supported: bool,
    #[serde(default)]
    token_endpoint_auth_methods_supported: Vec<String>,
}

#[derive(Deserialize)]
struct RegistrationResponse {
    client_id: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default = "default_expires_in")]
    expires_in: u64,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

struct Callback {
    code: String,
    issuer: Option<String>,
}

pub(crate) enum LoginOutcome {
    NotRequired,
    Credential(Box<StoredCredential>),
}

pub(crate) async fn login(
    server: &McpServerConfig,
    requested_client_id: Option<&str>,
    modern: bool,
) -> anyhow::Result<LoginOutcome> {
    let resource = Url::parse(
        server
            .url
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("HTTP MCP server has no URL"))?,
    )?;
    validate_endpoint(&resource, "resource")?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(HTTP_TIMEOUT)
        .build()?;
    let Some(protected) = discover_resource(&client, &resource).await? else {
        if accepts_unauthenticated_probe(&client, &resource).await? {
            return Ok(LoginOutcome::NotRequired);
        }
        anyhow::bail!("MCP protected-resource metadata was not found");
    };
    if Url::parse(&protected.resource)? != resource {
        anyhow::bail!("MCP protected-resource metadata does not match the configured resource");
    }
    let issuer_url = protected
        .authorization_servers
        .first()
        .ok_or_else(|| anyhow::anyhow!("MCP resource advertises no authorization server"))
        .and_then(|value| Url::parse(value).map_err(Into::into))?;
    validate_endpoint(&issuer_url, "issuer")?;
    let authorization = discover_authorization(&client, &issuer_url).await?;
    if Url::parse(&authorization.issuer)? != issuer_url {
        anyhow::bail!("MCP authorization metadata issuer mismatch");
    }
    validate_token_endpoint_auth_methods(&authorization.token_endpoint_auth_methods_supported)?;
    let authorization_endpoint = Url::parse(&authorization.authorization_endpoint)?;
    let token_endpoint = Url::parse(&authorization.token_endpoint)?;
    validate_endpoint(&authorization_endpoint, "authorization endpoint")?;
    validate_endpoint(&token_endpoint, "token endpoint")?;
    require_same_origin(&issuer_url, &authorization_endpoint)?;
    require_same_origin(&issuer_url, &token_endpoint)?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let callback_id = callback_id(resource.as_str());
    let callback_path = if authorization.authorization_response_iss_parameter_supported {
        "/callback".to_owned()
    } else {
        format!("/callback/{callback_id}")
    };
    let redirect_uri = format!("http://127.0.0.1:{port}{callback_path}");
    let client_id = match requested_client_id.or_else(|| {
        server
            .oauth
            .as_ref()
            .and_then(|configured| configured.client_id.as_deref())
    }) {
        Some(value) => {
            validate_client_id(
                value,
                authorization.client_id_metadata_document_supported,
                modern,
            )?;
            value.to_owned()
        }
        None if modern => anyhow::bail!(
            "2026 MCP OAuth requires --client-id with an HTTPS Client ID Metadata Document URL"
        ),
        None => register_client(&client, &authorization, &redirect_uri).await?,
    };

    let state = random_url_token()?;
    let verifier = random_url_token()?;
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let mut authorize_url = authorization_endpoint;
    authorize_url
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", &state)
        .append_pair("resource", resource.as_str())
        .append_pair("scope", REQUIRED_SCOPE);
    println!("Open this URL to authorize MCP access:\n{authorize_url}");
    let _ = open_browser(authorize_url.as_str()).await;
    let callback = tokio::time::timeout(
        callback_timeout(),
        receive_callback(listener, &callback_path, &state),
    )
    .await
    .map_err(|_| anyhow::anyhow!("MCP OAuth callback timed out"))??;
    if authorization.authorization_response_iss_parameter_supported {
        let callback_issuer = callback
            .issuer
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("MCP OAuth callback omitted its issuer"))?;
        if !constant_time_eq(callback_issuer.as_bytes(), authorization.issuer.as_bytes()) {
            anyhow::bail!("MCP OAuth callback issuer mismatch");
        }
    } else if callback.issuer.is_some() {
        anyhow::bail!("MCP OAuth callback returned an unadvertised issuer");
    }
    let token = exchange_code(
        &client,
        &token_endpoint,
        &callback.code,
        &client_id,
        &redirect_uri,
        &verifier,
        resource.as_str(),
    )
    .await?;
    if token
        .token_type
        .as_deref()
        .is_some_and(|kind| !kind.eq_ignore_ascii_case("bearer"))
    {
        anyhow::bail!("MCP OAuth token endpoint returned a non-bearer token");
    }
    validate_granted_scope(token.scope.as_deref())?;
    let revocation_endpoint = authorization
        .revocation_endpoint
        .map(|value| {
            let endpoint = Url::parse(&value)?;
            validate_endpoint(&endpoint, "revocation endpoint")?;
            require_same_origin(&issuer_url, &endpoint)?;
            Ok::<_, anyhow::Error>(endpoint.to_string())
        })
        .transpose()?;
    StoredCredential::new(
        server,
        resource.to_string(),
        authorization.issuer,
        client_id,
        token.access_token,
        token.refresh_token,
        unix_now().saturating_add(token.expires_in),
        token_endpoint.to_string(),
        revocation_endpoint,
    )
    .map(Box::new)
    .map(LoginOutcome::Credential)
}

pub(crate) async fn revoke(credential: &StoredCredential) -> anyhow::Result<()> {
    let Some(endpoint) = credential.revocation_endpoint.as_deref() else {
        return Ok(());
    };
    let token = credential
        .refresh_token
        .as_deref()
        .unwrap_or(&credential.access_token);
    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(HTTP_TIMEOUT)
        .build()?
        .post(endpoint)
        .form(&[
            ("token", token),
            ("client_id", credential.client_id.as_str()),
        ])
        .send()
        .await?;
    if !response.status().is_success() {
        anyhow::bail!("MCP OAuth revocation endpoint rejected the request");
    }
    Ok(())
}

async fn discover_resource(
    client: &reqwest::Client,
    resource: &Url,
) -> anyhow::Result<Option<ResourceMetadata>> {
    let path = resource.path().trim_start_matches('/');
    let mut candidates = vec![format!("/.well-known/oauth-protected-resource/{path}")];
    if path.is_empty() {
        candidates.clear();
    }
    candidates.push("/.well-known/oauth-protected-resource".into());
    for path in candidates {
        let mut metadata_url = resource.clone();
        metadata_url.set_path(&path);
        metadata_url.set_query(None);
        let response = client.get(metadata_url).send().await?;
        if response.status().as_u16() == 404 {
            continue;
        }
        return decode_json(response).await.map(Some);
    }
    Ok(None)
}

async fn accepts_unauthenticated_probe(
    client: &reqwest::Client,
    resource: &Url,
) -> anyhow::Result<bool> {
    let response = client
        .post(resource.clone())
        .header("MCP-Protocol-Version", iteron_mcp::MODERN_PROTOCOL_VERSION)
        .header("Mcp-Method", "server/discover")
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover",
            "params": {"_meta": {}}
        }))
        .send()
        .await?;
    if response.status().is_redirection() {
        anyhow::bail!("MCP OAuth probe redirect refused");
    }
    Ok(response.status().is_success())
}

async fn discover_authorization(
    client: &reqwest::Client,
    issuer: &Url,
) -> anyhow::Result<AuthorizationMetadata> {
    let mut metadata_url = issuer.clone();
    metadata_url.set_path("/.well-known/oauth-authorization-server");
    metadata_url.set_query(None);
    decode_json(client.get(metadata_url).send().await?).await
}

async fn register_client(
    client: &reqwest::Client,
    metadata: &AuthorizationMetadata,
    redirect_uri: &str,
) -> anyhow::Result<String> {
    let endpoint = metadata.registration_endpoint.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "authorization server requires --client-id and advertises no dynamic registration"
        )
    })?;
    let response = client
        .post(endpoint)
        .json(&serde_json::json!({
            "client_name": "Iteron",
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none"
        }))
        .send()
        .await?;
    let registered: RegistrationResponse = decode_json(response).await?;
    validate_client_id(&registered.client_id, false, false)?;
    Ok(registered.client_id)
}

#[allow(clippy::too_many_arguments)]
async fn exchange_code(
    client: &reqwest::Client,
    endpoint: &Url,
    code: &str,
    client_id: &str,
    redirect_uri: &str,
    verifier: &str,
    resource: &str,
) -> anyhow::Result<TokenResponse> {
    let response = client
        .post(endpoint.clone())
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("code_verifier", verifier),
            ("resource", resource),
        ])
        .send()
        .await?;
    decode_json(response).await
}

async fn decode_json<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> anyhow::Result<T> {
    if response.status().is_redirection() {
        anyhow::bail!("MCP OAuth metadata redirect refused");
    }
    if !response.status().is_success() {
        anyhow::bail!("MCP OAuth endpoint returned HTTP {}", response.status());
    }
    let bytes = response.bytes().await?;
    if bytes.len() > METADATA_LIMIT {
        anyhow::bail!("MCP OAuth response exceeds its byte bound");
    }
    Ok(serde_json::from_slice(&bytes)?)
}

async fn receive_callback(
    listener: tokio::net::TcpListener,
    expected_path: &str,
    expected_state: &str,
) -> anyhow::Result<Callback> {
    let (mut stream, peer) = listener.accept().await?;
    if !peer.ip().is_loopback() {
        anyhow::bail!("MCP OAuth callback was not loopback");
    }
    let mut bytes = vec![0_u8; CALLBACK_REQUEST_LIMIT];
    let read = stream.read(&mut bytes).await?;
    let request = std::str::from_utf8(&bytes[..read])?;
    let target = request
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("GET "))
        .and_then(|line| line.split_once(' '))
        .map(|(target, _)| target)
        .ok_or_else(|| anyhow::anyhow!("invalid MCP OAuth callback request"))?;
    let callback_url = Url::parse(&format!("http://127.0.0.1{target}"))?;
    if callback_url.path() != expected_path {
        anyhow::bail!("MCP OAuth callback path mismatch");
    }
    let values = callback_url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<std::collections::BTreeMap<_, _>>();
    let state = values
        .get("state")
        .ok_or_else(|| anyhow::anyhow!("MCP OAuth callback omitted state"))?;
    if !constant_time_eq(state.as_bytes(), expected_state.as_bytes()) {
        anyhow::bail!("MCP OAuth callback state mismatch");
    }
    if let Some(error) = values.get("error") {
        anyhow::bail!("MCP OAuth authorization was refused: {error}");
    }
    let code = values
        .get("code")
        .filter(|value| !value.is_empty() && value.len() <= 8192)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("MCP OAuth callback omitted code"))?;
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 41\r\nConnection: close\r\n\r\nAuthorization complete. Return to Iteron.")
        .await?;
    Ok(Callback {
        code,
        issuer: values.get("iss").cloned(),
    })
}

fn validate_client_id(
    value: &str,
    cimd_advertised: bool,
    require_cimd: bool,
) -> anyhow::Result<()> {
    if value.is_empty() || value.len() > 8192 || value.chars().any(char::is_control) {
        anyhow::bail!("invalid MCP OAuth client id");
    }
    let cimd = Url::parse(value).ok().filter(|url| url.scheme() == "https");
    if require_cimd && cimd.is_none() {
        anyhow::bail!("2026 MCP OAuth client id must be an HTTPS metadata document URL");
    }
    if let Some(url) = cimd {
        validate_endpoint(&url, "client id metadata document")?;
        if !cimd_advertised {
            anyhow::bail!("authorization server does not advertise Client ID Metadata Documents");
        }
    }
    Ok(())
}

fn validate_granted_scope(scope: Option<&str>) -> anyhow::Result<()> {
    let Some(scope) = scope else {
        // RFC 6749 defines omission as identical to the requested scope.
        return Ok(());
    };
    if scope.is_empty() || scope.len() > 4096 || scope.chars().any(char::is_control) {
        anyhow::bail!("MCP OAuth token endpoint returned an invalid scope");
    }
    let scopes = scope
        .split_ascii_whitespace()
        .collect::<std::collections::BTreeSet<_>>();
    if !scopes.contains(REQUIRED_SCOPE) {
        anyhow::bail!("MCP OAuth token scope omitted the required MCP scope");
    }
    if scopes.len() != 1 {
        anyhow::bail!("MCP OAuth token scope exceeded the requested scope");
    }
    Ok(())
}

fn validate_token_endpoint_auth_methods(methods: &[String]) -> anyhow::Result<()> {
    if methods.len() > 16
        || methods
            .iter()
            .any(|method| method.len() > 64 || method.chars().any(char::is_control))
    {
        anyhow::bail!("MCP OAuth token endpoint auth methods are invalid");
    }
    if !methods.is_empty() && !methods.iter().any(|method| method == "none") {
        anyhow::bail!("MCP OAuth token endpoint does not support public PKCE clients");
    }
    Ok(())
}

fn validate_endpoint(url: &Url, field: &str) -> anyhow::Result<()> {
    let loopback = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        anyhow::bail!("MCP OAuth {field} must use HTTPS or loopback HTTP");
    }
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        anyhow::bail!("MCP OAuth {field} contains forbidden URL components");
    }
    Ok(())
}

fn require_same_origin(expected: &Url, actual: &Url) -> anyhow::Result<()> {
    if expected.scheme() != actual.scheme()
        || expected.host_str() != actual.host_str()
        || expected.port_or_known_default() != actual.port_or_known_default()
    {
        anyhow::bail!("MCP OAuth endpoint crosses its issuer origin");
    }
    Ok(())
}

fn random_url_token() -> anyhow::Result<String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("system entropy unavailable"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn callback_id(resource: &str) -> String {
    URL_SAFE_NO_PAD.encode(&Sha256::digest(resource.as_bytes())[..9])
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    difference == 0
}

async fn open_browser(url: &str) -> bool {
    #[cfg(target_os = "macos")]
    let mut command = tokio::process::Command::new("open");
    #[cfg(target_os = "linux")]
    let mut command = tokio::process::Command::new("xdg-open");
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = tokio::process::Command::new("cmd");
        command.args(["/C", "start", ""]);
        command
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    return false;
    command.arg(url).kill_on_drop(true);
    match command.spawn() {
        Ok(mut child) => tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .ok()
            .and_then(Result::ok)
            .is_some_and(|status| status.success()),
        Err(_) => false,
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn callback_timeout() -> Duration {
    #[cfg(debug_assertions)]
    if let Some(milliseconds) = std::env::var("ITERON_TEST_MCP_OAUTH_CALLBACK_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
    {
        return Duration::from_millis(milliseconds.clamp(10, CALLBACK_TIMEOUT.as_millis() as u64));
    }
    CALLBACK_TIMEOUT
}

const fn default_expires_in() -> u64 {
    3600
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_identity_and_state_comparison_are_stable() {
        assert_eq!(callback_id("https://example.com/mcp").len(), 12);
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"other"));
        assert!(!constant_time_eq(b"same", b"same-longer"));
    }

    #[test]
    fn oauth_endpoints_are_origin_and_transport_bound() {
        assert!(
            validate_endpoint(&Url::parse("http://127.0.0.1:1/token").unwrap(), "token").is_ok()
        );
        assert!(
            validate_endpoint(&Url::parse("http://example.com/token").unwrap(), "token").is_err()
        );
        assert!(
            require_same_origin(
                &Url::parse("https://a.example/issuer").unwrap(),
                &Url::parse("https://a.example/token").unwrap()
            )
            .is_ok()
        );
        assert!(
            require_same_origin(
                &Url::parse("https://a.example/issuer").unwrap(),
                &Url::parse("https://b.example/token").unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn modern_client_ids_and_granted_scopes_fail_closed() {
        assert!(validate_client_id("https://client.example/iteron.json", true, true).is_ok());
        assert!(validate_client_id("registered-client", true, true).is_err());
        assert!(validate_client_id("https://client.example/iteron.json", false, true).is_err());
        assert!(validate_granted_scope(None).is_ok());
        assert!(validate_granted_scope(Some("mcp")).is_ok());
        assert!(validate_granted_scope(Some("other")).is_err());
        assert!(validate_granted_scope(Some("mcp admin")).is_err());
        assert!(validate_token_endpoint_auth_methods(&["none".into()]).is_ok());
        assert!(validate_token_endpoint_auth_methods(&["client_secret_basic".into()]).is_err());
    }
}
