//! Bounded browser OAuth login for one configured HTTP MCP resource.

use super::credential_store::StoredCredential;
use crate::config::{McpServerConfig, OAuthClientRegistration};
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

pub(crate) struct LoginOptions<'a> {
    pub(crate) resource: Option<&'a str>,
    pub(crate) expected_issuer: Option<&'a str>,
    pub(crate) scopes: Option<&'a [String]>,
    pub(crate) registration: Option<OAuthClientRegistration>,
    pub(crate) client_id: Option<&'a str>,
    pub(crate) client_secret_env: Option<&'a str>,
}

#[derive(Deserialize)]
struct ResourceMetadata {
    resource: String,
    authorization_servers: Vec<String>,
    #[serde(default)]
    scopes_supported: Vec<String>,
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
    #[serde(default)]
    scopes_supported: Vec<String>,
}

#[derive(Deserialize)]
struct RegistrationResponse {
    client_id: String,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    token_endpoint_auth_method: Option<String>,
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

struct ResolvedClient {
    client_id: String,
    client_secret: Option<String>,
    token_auth_method: iteron_mcp::oauth::TokenEndpointAuthMethod,
}

struct ProbeResult {
    unauthenticated: bool,
    resource_metadata: Option<Url>,
    resource: Option<Url>,
    scope: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScopeSource {
    Operator,
    Discovered,
    Empty,
}

#[derive(Debug)]
struct OAuthProviderRefusal {
    scope_rejected: bool,
}

impl std::fmt::Display for OAuthProviderRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MCP OAuth provider refused the authorization request")
    }
}

impl std::error::Error for OAuthProviderRefusal {}

fn scope_was_rejected(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<OAuthProviderRefusal>()
        .is_some_and(|refusal| refusal.scope_rejected)
}

pub(crate) enum LoginOutcome {
    NotRequired,
    Credential(Box<StoredCredential>),
}

pub(crate) async fn login(
    server: &McpServerConfig,
    options: LoginOptions<'_>,
) -> anyhow::Result<LoginOutcome> {
    let endpoint = Url::parse(
        server
            .url
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("HTTP MCP server has no URL"))?,
    )?;
    validate_endpoint(&endpoint, "resource")?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(HTTP_TIMEOUT)
        .build()?;
    let probe = probe_resource(&client, &endpoint).await?;
    if probe.unauthenticated {
        return Ok(LoginOutcome::NotRequired);
    }
    let configured_oauth = server.oauth.as_ref();
    let explicit_resource = options
        .resource
        .or_else(|| configured_oauth.and_then(|oauth| oauth.resource.as_deref()));
    let protected = discover_resource(
        &client,
        &endpoint,
        explicit_resource,
        probe.resource_metadata.as_ref(),
    )
    .await?
    .ok_or_else(|| anyhow::anyhow!("MCP protected-resource metadata was not found"))?;
    let resource = Url::parse(&protected.resource)?;
    validate_endpoint(&resource, "resource")?;
    if let Some(explicit) = explicit_resource {
        if Url::parse(explicit)? != resource {
            anyhow::bail!("MCP protected-resource metadata does not match the configured resource");
        }
    } else if !same_origin(&endpoint, &resource) && probe.resource.as_ref() != Some(&resource) {
        anyhow::bail!("MCP protected-resource metadata crosses the configured endpoint origin");
    }
    let issuer_url = protected
        .authorization_servers
        .first()
        .ok_or_else(|| anyhow::anyhow!("MCP resource advertises no authorization server"))
        .and_then(|value| Url::parse(value).map_err(Into::into))?;
    validate_endpoint(&issuer_url, "issuer")?;
    if let Some(expected_issuer) = options.expected_issuer
        && Url::parse(expected_issuer)? != issuer_url
    {
        anyhow::bail!("MCP OAuth scope step-up issuer mismatch");
    }
    let authorization = discover_authorization(&client, &issuer_url).await?;
    if Url::parse(&authorization.issuer)? != issuer_url {
        anyhow::bail!("MCP authorization metadata issuer mismatch");
    }
    validate_token_endpoint_auth_methods(&authorization.token_endpoint_auth_methods_supported)?;
    let authorization_endpoint = Url::parse(&authorization.authorization_endpoint)?;
    let token_endpoint = Url::parse(&authorization.token_endpoint)?;
    validate_endpoint(&authorization_endpoint, "authorization endpoint")?;
    validate_endpoint(&token_endpoint, "token endpoint")?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let callback_id = callback_id(resource.as_str());
    let callback_path = if authorization.authorization_response_iss_parameter_supported {
        "/callback".to_owned()
    } else {
        format!("/callback/{callback_id}")
    };
    let redirect_uri = format!("http://127.0.0.1:{port}{callback_path}");
    let configured_client_id = configured_oauth.and_then(|oauth| oauth.client_id.as_deref());
    let requested_client_id = options.client_id.or(configured_client_id);
    let secret_env = options
        .client_secret_env
        .or_else(|| configured_oauth.and_then(|oauth| oauth.client_secret_env.as_deref()));
    let client_secret = secret_env
        .map(|name| {
            std::env::var(name)
                .map_err(|_| anyhow::anyhow!("MCP OAuth client secret environment is absent"))
        })
        .transpose()?;
    let registration = options
        .registration
        .or_else(|| configured_oauth.map(|oauth| oauth.registration))
        .unwrap_or_default();
    let (mut requested_scopes, scope_source) = if let Some(scopes) = options.scopes {
        (scopes.to_vec(), ScopeSource::Operator)
    } else if let Some(scopes) = configured_oauth
        .filter(|oauth| !oauth.scopes.is_empty())
        .map(|oauth| oauth.scopes.clone())
    {
        (scopes, ScopeSource::Operator)
    } else if !probe.scope.is_empty() {
        (probe.scope, ScopeSource::Discovered)
    } else if !protected.scopes_supported.is_empty() {
        (protected.scopes_supported, ScopeSource::Discovered)
    } else if !authorization.scopes_supported.is_empty() {
        (
            authorization.scopes_supported.clone(),
            ScopeSource::Discovered,
        )
    } else {
        (Vec::new(), ScopeSource::Empty)
    };
    validate_scopes(&requested_scopes)?;
    let mut retried_without_scopes = false;
    let (token, resolved) = loop {
        let resolved = resolve_client(
            &client,
            &authorization,
            registration,
            requested_client_id,
            client_secret.clone(),
            &redirect_uri,
            &requested_scopes,
        )
        .await?;
        let state = random_url_token()?;
        let verifier = random_url_token()?;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let mut authorize_url = authorization_endpoint.clone();
        authorize_url
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &resolved.client_id)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("state", &state)
            .append_pair("resource", resource.as_str());
        if !requested_scopes.is_empty() {
            authorize_url
                .query_pairs_mut()
                .append_pair("scope", &requested_scopes.join(" "));
        }
        println!("Open this URL to authorize MCP access:\n{authorize_url}");
        let _ = open_browser(authorize_url.as_str()).await;
        let callback = tokio::time::timeout(
            callback_timeout(),
            receive_callback(&listener, &callback_path, &state),
        )
        .await
        .map_err(|_| anyhow::anyhow!("MCP OAuth callback timed out"))?;
        let callback = match callback {
            Ok(callback) => callback,
            Err(error)
                if scope_source == ScopeSource::Discovered
                    && !retried_without_scopes
                    && scope_was_rejected(&error) =>
            {
                requested_scopes.clear();
                retried_without_scopes = true;
                continue;
            }
            Err(error) => {
                if scope_source == ScopeSource::Operator && scope_was_rejected(&error) {
                    anyhow::bail!("MCP OAuth configured scope was rejected");
                }
                return Err(error);
            }
        };
        if authorization.authorization_response_iss_parameter_supported {
            let callback_issuer = callback
                .issuer
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("MCP OAuth callback omitted its issuer"))?;
            if !constant_time_eq(callback_issuer.as_bytes(), authorization.issuer.as_bytes()) {
                anyhow::bail!("MCP OAuth callback issuer mismatch");
            }
        } else if let Some(callback_issuer) = callback.issuer.as_deref()
            && !constant_time_eq(callback_issuer.as_bytes(), authorization.issuer.as_bytes())
        {
            anyhow::bail!("MCP OAuth callback issuer mismatch");
        }
        match exchange_code(
            &client,
            &token_endpoint,
            &callback.code,
            &resolved,
            &redirect_uri,
            &verifier,
            resource.as_str(),
        )
        .await
        {
            Ok(token) => break (token, resolved),
            Err(error)
                if scope_source == ScopeSource::Discovered
                    && !retried_without_scopes
                    && scope_was_rejected(&error) =>
            {
                requested_scopes.clear();
                retried_without_scopes = true;
            }
            Err(error) => {
                if scope_source == ScopeSource::Operator && scope_was_rejected(&error) {
                    anyhow::bail!("MCP OAuth configured scope was rejected");
                }
                return Err(error);
            }
        }
    };
    if token
        .token_type
        .as_deref()
        .is_some_and(|kind| !kind.eq_ignore_ascii_case("bearer"))
    {
        anyhow::bail!("MCP OAuth token endpoint returned a non-bearer token");
    }
    let granted_scopes = validate_granted_scope(token.scope.as_deref(), &requested_scopes)?;
    let revocation_endpoint = authorization
        .revocation_endpoint
        .map(|value| {
            let endpoint = Url::parse(&value)?;
            validate_endpoint(&endpoint, "revocation endpoint")?;
            Ok::<_, anyhow::Error>(endpoint.to_string())
        })
        .transpose()?;
    StoredCredential::new(
        server,
        resource.to_string(),
        authorization.issuer,
        resolved.client_id,
        resolved.client_secret,
        resolved.token_auth_method,
        requested_scopes,
        granted_scopes,
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
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(HTTP_TIMEOUT)
        .build()?;
    let mut form = vec![("token", token), ("token_type_hint", "refresh_token")];
    let mut request = client.post(endpoint);
    match credential.token_auth_method {
        iteron_mcp::oauth::TokenEndpointAuthMethod::None => {
            form.push(("client_id", credential.client_id.as_str()));
        }
        iteron_mcp::oauth::TokenEndpointAuthMethod::ClientSecretBasic => {
            request =
                request.basic_auth(&credential.client_id, credential.client_secret.as_deref());
        }
        iteron_mcp::oauth::TokenEndpointAuthMethod::ClientSecretPost => {
            form.push(("client_id", credential.client_id.as_str()));
            form.push((
                "client_secret",
                credential.client_secret.as_deref().unwrap_or_default(),
            ));
        }
    }
    let response = request.form(&form).send().await?;
    if !response.status().is_success() {
        anyhow::bail!("MCP OAuth revocation endpoint rejected the request");
    }
    Ok(())
}

async fn discover_resource(
    client: &reqwest::Client,
    endpoint: &Url,
    explicit_resource: Option<&str>,
    challenge_metadata: Option<&Url>,
) -> anyhow::Result<Option<ResourceMetadata>> {
    if let Some(metadata_url) = challenge_metadata {
        validate_endpoint(metadata_url, "resource metadata")?;
        return decode_json(client.get(metadata_url.clone()).send().await?)
            .await
            .map(Some);
    }
    let base = explicit_resource
        .map(Url::parse)
        .transpose()?
        .unwrap_or_else(|| endpoint.clone());
    let path = base.path().trim_start_matches('/');
    let mut candidates = vec![format!("/.well-known/oauth-protected-resource/{path}")];
    if path.is_empty() {
        candidates.clear();
    }
    candidates.push("/.well-known/oauth-protected-resource".into());
    for path in candidates {
        let mut metadata_url = base.clone();
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

async fn probe_resource(client: &reqwest::Client, resource: &Url) -> anyhow::Result<ProbeResult> {
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
    let unauthenticated = response.status().is_success();
    let (resource_metadata, resource, scope) = if response.status().as_u16() == 401 {
        parse_www_authenticate(response.headers())?
    } else {
        (None, None, Vec::new())
    };
    Ok(ProbeResult {
        unauthenticated,
        resource_metadata,
        resource,
        scope,
    })
}

fn parse_www_authenticate(
    headers: &reqwest::header::HeaderMap,
) -> anyhow::Result<(Option<Url>, Option<Url>, Vec<String>)> {
    let mut metadata = None;
    let mut resource = None;
    let mut scopes = Vec::new();
    for value in headers.get_all(reqwest::header::WWW_AUTHENTICATE) {
        let Some(challenge) = value
            .to_str()
            .ok()
            .and_then(iteron_mcp::http::parse_bearer_challenge)
        else {
            continue;
        };
        if let Some(raw) = challenge.resource_metadata {
            let url = Url::parse(&raw)?;
            validate_endpoint(&url, "resource metadata")?;
            metadata = Some(url);
        }
        if let Some(raw) = challenge.resource {
            let url = Url::parse(&raw)?;
            validate_endpoint(&url, "resource")?;
            resource = Some(url);
        }
        if !challenge.scopes.is_empty() {
            scopes = challenge.scopes;
        }
    }
    validate_scopes(&scopes)?;
    Ok((metadata, resource, scopes))
}

async fn discover_authorization(
    client: &reqwest::Client,
    issuer: &Url,
) -> anyhow::Result<AuthorizationMetadata> {
    let issuer_path = issuer.path().trim_matches('/');
    let suffix = if issuer_path.is_empty() {
        String::new()
    } else {
        format!("/{issuer_path}")
    };
    let candidates = [
        format!("/.well-known/oauth-authorization-server{suffix}"),
        format!("/.well-known/openid-configuration{suffix}"),
        if issuer_path.is_empty() {
            "/.well-known/openid-configuration".to_owned()
        } else {
            format!("/{issuer_path}/.well-known/openid-configuration")
        },
    ];
    for path in candidates {
        let mut metadata_url = issuer.clone();
        metadata_url.set_path(&path);
        metadata_url.set_query(None);
        let response = client.get(metadata_url).send().await?;
        if response.status().as_u16() == 404 {
            continue;
        }
        return decode_json(response).await;
    }
    anyhow::bail!("MCP authorization metadata was not found")
}

async fn register_client(
    client: &reqwest::Client,
    metadata: &AuthorizationMetadata,
    redirect_uri: &str,
    scopes: &[String],
) -> anyhow::Result<ResolvedClient> {
    let endpoint = metadata.registration_endpoint.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "authorization server requires --client-id and advertises no dynamic registration"
        )
    })?;
    let endpoint = Url::parse(endpoint)?;
    validate_endpoint(&endpoint, "registration endpoint")?;
    let requested_method = if metadata
        .token_endpoint_auth_methods_supported
        .iter()
        .any(|method| method == "client_secret_basic")
    {
        "client_secret_basic"
    } else if metadata
        .token_endpoint_auth_methods_supported
        .iter()
        .any(|method| method == "client_secret_post")
    {
        "client_secret_post"
    } else if metadata.token_endpoint_auth_methods_supported.is_empty()
        || metadata
            .token_endpoint_auth_methods_supported
            .iter()
            .any(|method| method == "none")
    {
        "none"
    } else {
        anyhow::bail!("MCP OAuth token endpoint supports no compatible client authentication");
    };
    let mut registration = serde_json::json!({
        "client_name": "Iteron",
        "application_type": "native",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": requested_method
    });
    if !scopes.is_empty() {
        registration["scope"] = serde_json::Value::String(scopes.join(" "));
    }
    let response = client.post(endpoint).json(&registration).send().await?;
    let registered: RegistrationResponse = decode_json(response).await?;
    validate_client_id(&registered.client_id, false, false)?;
    if let Some(secret) = &registered.client_secret {
        validate_secret(secret)?;
    }
    let token_auth_method = resolve_token_auth_method(
        registered
            .token_endpoint_auth_method
            .as_deref()
            .or(Some(requested_method)),
        registered.client_secret.is_some(),
        &metadata.token_endpoint_auth_methods_supported,
    )?;
    Ok(ResolvedClient {
        client_id: registered.client_id,
        client_secret: registered.client_secret,
        token_auth_method,
    })
}

async fn resolve_client(
    client: &reqwest::Client,
    metadata: &AuthorizationMetadata,
    strategy: OAuthClientRegistration,
    requested_client_id: Option<&str>,
    client_secret: Option<String>,
    redirect_uri: &str,
    scopes: &[String],
) -> anyhow::Result<ResolvedClient> {
    if strategy == OAuthClientRegistration::Dcr {
        if requested_client_id.is_some() || client_secret.is_some() {
            anyhow::bail!("DCR does not accept a pre-registered client id or secret");
        }
        return register_client(client, metadata, redirect_uri, scopes).await;
    }
    if let Some(client_id) = requested_client_id {
        let is_cimd = Url::parse(client_id)
            .ok()
            .is_some_and(|url| url.scheme() == "https");
        if strategy == OAuthClientRegistration::Auto && client_secret.is_some() {
            validate_client_id(client_id, false, false)?;
            let token_auth_method = resolve_token_auth_method(
                None,
                true,
                &metadata.token_endpoint_auth_methods_supported,
            )?;
            return Ok(ResolvedClient {
                client_id: client_id.to_owned(),
                client_secret,
                token_auth_method,
            });
        }
        let use_cimd = strategy == OAuthClientRegistration::Cimd
            || (strategy == OAuthClientRegistration::Auto
                && is_cimd
                && metadata.client_id_metadata_document_supported
                && (metadata.token_endpoint_auth_methods_supported.is_empty()
                    || metadata
                        .token_endpoint_auth_methods_supported
                        .iter()
                        .any(|method| method == "none")));
        if use_cimd {
            validate_client_id(
                client_id,
                metadata.client_id_metadata_document_supported,
                true,
            )?;
            if client_secret.is_some() {
                anyhow::bail!("CIMD clients cannot use a configured client secret");
            }
            let token_auth_method = resolve_token_auth_method(
                Some("none"),
                false,
                &metadata.token_endpoint_auth_methods_supported,
            )?;
            if !metadata.token_endpoint_auth_methods_supported.is_empty()
                && !metadata
                    .token_endpoint_auth_methods_supported
                    .iter()
                    .any(|method| method == "none")
            {
                anyhow::bail!("CIMD requires a public token endpoint client");
            }
            return Ok(ResolvedClient {
                client_id: client_id.to_owned(),
                client_secret: None,
                token_auth_method,
            });
        }
        if strategy == OAuthClientRegistration::Auto && is_cimd {
            if metadata.registration_endpoint.is_some() {
                return register_client(client, metadata, redirect_uri, scopes).await;
            }
            anyhow::bail!(
                "MCP_AUTH_REGISTRATION_UNSUPPORTED: authorization server does not support this CIMD client and advertises no DCR endpoint"
            );
        }
        validate_client_id(client_id, false, false)?;
        let token_auth_method = resolve_token_auth_method(
            None,
            client_secret.is_some(),
            &metadata.token_endpoint_auth_methods_supported,
        )?;
        return Ok(ResolvedClient {
            client_id: client_id.to_owned(),
            client_secret,
            token_auth_method,
        });
    }
    if strategy == OAuthClientRegistration::Cimd {
        anyhow::bail!("CIMD registration requires an HTTPS client metadata URL");
    }
    if metadata.registration_endpoint.is_some() {
        return register_client(client, metadata, redirect_uri, scopes).await;
    }
    anyhow::bail!(
        "MCP_AUTH_REGISTRATION_UNSUPPORTED: provide a pre-registered client, a CIMD URL, or use an authorization server with DCR"
    )
}

fn resolve_token_auth_method(
    declared: Option<&str>,
    has_secret: bool,
    supported: &[String],
) -> anyhow::Result<iteron_mcp::oauth::TokenEndpointAuthMethod> {
    use iteron_mcp::oauth::TokenEndpointAuthMethod;
    let parse = |value: &str| match value {
        "none" => Some(TokenEndpointAuthMethod::None),
        "client_secret_basic" => Some(TokenEndpointAuthMethod::ClientSecretBasic),
        "client_secret_post" => Some(TokenEndpointAuthMethod::ClientSecretPost),
        _ => None,
    };
    if let Some(declared) = declared {
        let method = parse(declared)
            .ok_or_else(|| anyhow::anyhow!("unsupported MCP OAuth token auth method"))?;
        if !supported.is_empty() && !supported.iter().any(|candidate| candidate == declared) {
            anyhow::bail!(
                "MCP OAuth registered token auth method is not advertised by the authorization server"
            );
        }
        if method != TokenEndpointAuthMethod::None && !has_secret {
            anyhow::bail!("MCP OAuth token auth method requires a client secret");
        }
        return Ok(method);
    }
    if !has_secret {
        if supported.is_empty() || supported.iter().any(|method| method == "none") {
            return Ok(TokenEndpointAuthMethod::None);
        }
        anyhow::bail!("MCP OAuth token endpoint does not support public PKCE clients");
    }
    if supported
        .iter()
        .any(|method| method == "client_secret_basic")
    {
        return Ok(TokenEndpointAuthMethod::ClientSecretBasic);
    }
    if supported
        .iter()
        .any(|method| method == "client_secret_post")
    {
        return Ok(TokenEndpointAuthMethod::ClientSecretPost);
    }
    anyhow::bail!("MCP OAuth token endpoint supports no compatible client authentication")
}

#[allow(clippy::too_many_arguments)]
async fn exchange_code(
    client: &reqwest::Client,
    endpoint: &Url,
    code: &str,
    resolved: &ResolvedClient,
    redirect_uri: &str,
    verifier: &str,
    resource: &str,
) -> anyhow::Result<TokenResponse> {
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", verifier),
        ("resource", resource),
    ];
    let mut request = client.post(endpoint.clone());
    match resolved.token_auth_method {
        iteron_mcp::oauth::TokenEndpointAuthMethod::None => {
            form.push(("client_id", &resolved.client_id));
        }
        iteron_mcp::oauth::TokenEndpointAuthMethod::ClientSecretBasic => {
            request = request.basic_auth(&resolved.client_id, resolved.client_secret.as_deref());
        }
        iteron_mcp::oauth::TokenEndpointAuthMethod::ClientSecretPost => {
            form.push(("client_id", &resolved.client_id));
            form.push((
                "client_secret",
                resolved.client_secret.as_deref().unwrap_or_default(),
            ));
        }
    }
    let response = request.form(&form).send().await?;
    if response.status().is_client_error() {
        let scope_rejected = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(';')
                    .next()
                    .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
            })
            && serde_json::from_slice::<serde_json::Value>(&read_bounded_body(response).await?)
                .ok()
                .and_then(|value| {
                    value
                        .get("error")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                })
                .as_deref()
                == Some("invalid_scope");
        return Err(OAuthProviderRefusal { scope_rejected }.into());
    }
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
    let media_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if !media_type.is_some_and(|value| value.eq_ignore_ascii_case("application/json")) {
        anyhow::bail!("MCP OAuth endpoint returned a non-JSON content type");
    }
    let bytes = read_bounded_body(response).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

async fn read_bounded_body(mut response: reqwest::Response) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(
        response
            .content_length()
            .unwrap_or(0)
            .min(METADATA_LIMIT as u64) as usize,
    );
    while let Some(chunk) = response.chunk().await? {
        if bytes.len().saturating_add(chunk.len()) > METADATA_LIMIT {
            anyhow::bail!("MCP OAuth response exceeds its byte bound");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn receive_callback(
    listener: &tokio::net::TcpListener,
    expected_path: &str,
    expected_state: &str,
) -> anyhow::Result<Callback> {
    let (mut stream, peer) = listener.accept().await?;
    if !peer.ip().is_loopback() {
        anyhow::bail!("MCP OAuth callback was not loopback");
    }
    let bytes = read_callback_request_line(&mut stream).await?;
    let request = std::str::from_utf8(&bytes)?;
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
    if values.contains_key("error") {
        stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: 39\r\nConnection: close\r\n\r\nAuthorization request was not accepted.")
            .await?;
        return Err(OAuthProviderRefusal {
            scope_rejected: values
                .get("error")
                .is_some_and(|error| error == "invalid_scope"),
        }
        .into());
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

async fn read_callback_request_line(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
) -> anyhow::Result<Vec<u8>> {
    let mut request = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    loop {
        let remaining = CALLBACK_REQUEST_LIMIT.saturating_sub(request.len());
        if remaining == 0 {
            anyhow::bail!("MCP OAuth callback request line exceeds its byte bound");
        }
        let read_limit = remaining.min(chunk.len());
        let read = stream.read(&mut chunk[..read_limit]).await?;
        if read == 0 {
            anyhow::bail!("MCP OAuth callback request ended before its request line");
        }
        request.extend_from_slice(&chunk[..read]);
        if request.contains(&b'\n') {
            return Ok(request);
        }
    }
}

fn validate_client_id(
    value: &str,
    cimd_advertised: bool,
    require_cimd: bool,
) -> anyhow::Result<()> {
    if value.is_empty() || value.len() > 8192 || value.chars().any(char::is_control) {
        anyhow::bail!("invalid MCP OAuth client id");
    }
    if require_cimd {
        let url = Url::parse(value)
            .ok()
            .filter(|url| url.scheme() == "https")
            .ok_or_else(|| {
                anyhow::anyhow!("2026 MCP OAuth client id must be an HTTPS metadata document URL")
            })?;
        validate_endpoint(&url, "client id metadata document")?;
        if !cimd_advertised {
            anyhow::bail!("authorization server does not advertise Client ID Metadata Documents");
        }
    }
    Ok(())
}

fn validate_granted_scope(
    scope: Option<&str>,
    requested: &[String],
) -> anyhow::Result<Vec<String>> {
    let Some(scope) = scope else {
        // RFC 6749 defines omission as identical to the requested scope.
        return Ok(requested.to_vec());
    };
    if scope.is_empty() || scope.len() > 4096 || scope.chars().any(char::is_control) {
        anyhow::bail!("MCP OAuth token endpoint returned an invalid scope");
    }
    let scopes = scope
        .split_ascii_whitespace()
        .collect::<std::collections::BTreeSet<_>>();
    let requested = requested
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    if !scopes.is_subset(&requested) {
        anyhow::bail!("MCP OAuth token scope exceeded the requested scope");
    }
    Ok(scopes.into_iter().map(str::to_owned).collect())
}

fn validate_scopes(scopes: &[String]) -> anyhow::Result<()> {
    if scopes.len() > 64 || scopes.iter().map(String::len).sum::<usize>() > 4096 {
        anyhow::bail!("MCP OAuth scopes exceed their bound");
    }
    let mut seen = std::collections::BTreeSet::new();
    for scope in scopes {
        if scope.is_empty()
            || scope.len() > 256
            || scope.chars().any(char::is_whitespace)
            || scope.chars().any(char::is_control)
            || !seen.insert(scope)
        {
            anyhow::bail!("MCP OAuth scope is invalid");
        }
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

fn same_origin(expected: &Url, actual: &Url) -> bool {
    expected.scheme() == actual.scheme()
        && expected.host_str() == actual.host_str()
        && expected.port_or_known_default() == actual.port_or_known_default()
}

fn validate_secret(value: &str) -> anyhow::Result<()> {
    if value.is_empty() || value.len() > 8192 || value.contains('\0') {
        anyhow::bail!("invalid MCP OAuth client secret");
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
    fn oauth_endpoints_are_transport_bound() {
        assert!(
            validate_endpoint(&Url::parse("http://127.0.0.1:1/token").unwrap(), "token").is_ok()
        );
        assert!(
            validate_endpoint(&Url::parse("http://example.com/token").unwrap(), "token").is_err()
        );
    }

    #[test]
    fn modern_client_ids_and_granted_scopes_fail_closed() {
        assert!(validate_client_id("https://client.example/iteron.json", true, true).is_ok());
        assert!(validate_client_id("registered-client", true, true).is_err());
        assert!(validate_client_id("https://client.example/iteron.json", false, true).is_err());
        let requested = vec!["mcp".to_owned()];
        assert!(validate_granted_scope(None, &requested).is_ok());
        assert!(validate_granted_scope(Some("mcp"), &requested).is_ok());
        assert!(validate_granted_scope(Some("other"), &requested).is_err());
        assert!(validate_granted_scope(Some("mcp admin"), &requested).is_err());
        assert!(validate_token_endpoint_auth_methods(&["none".into()]).is_ok());
        assert!(validate_token_endpoint_auth_methods(&["client_secret_basic".into()]).is_ok());
        assert!(validate_token_endpoint_auth_methods(&["private_key_jwt".into()]).is_ok());
        assert!(
            resolve_token_auth_method(
                Some("client_secret_post"),
                true,
                &["client_secret_basic".into()]
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn callback_request_line_accepts_fragmented_tcp_input() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        let write = tokio::spawn(async move {
            writer.write_all(b"GET /call").await.unwrap();
            tokio::task::yield_now().await;
            writer
                .write_all(b"back?code=ok&state=s HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await
                .unwrap();
        });
        let request = read_callback_request_line(&mut reader).await.unwrap();
        write.await.unwrap();
        assert!(request.starts_with(b"GET /callback?code=ok&state=s HTTP/1.1\r\n"));
    }

    #[tokio::test]
    async fn auto_treats_an_https_client_with_a_secret_as_pre_registered() {
        let metadata = AuthorizationMetadata {
            issuer: "https://issuer.example".into(),
            authorization_endpoint: "https://issuer.example/authorize".into(),
            token_endpoint: "https://issuer.example/token".into(),
            registration_endpoint: Some("https://issuer.example/register".into()),
            revocation_endpoint: None,
            client_id_metadata_document_supported: true,
            authorization_response_iss_parameter_supported: false,
            token_endpoint_auth_methods_supported: vec!["client_secret_basic".into()],
            scopes_supported: Vec::new(),
        };
        let resolved = resolve_client(
            &reqwest::Client::new(),
            &metadata,
            OAuthClientRegistration::Auto,
            Some("https://client.example/id"),
            Some("secret".into()),
            "http://127.0.0.1:1234/callback",
            &[],
        )
        .await
        .unwrap();
        assert_eq!(resolved.client_id, "https://client.example/id");
        assert_eq!(resolved.client_secret.as_deref(), Some("secret"));
        assert_eq!(
            resolved.token_auth_method,
            iteron_mcp::oauth::TokenEndpointAuthMethod::ClientSecretBasic
        );
    }

    #[tokio::test]
    async fn dcr_rejects_unsafe_registration_endpoints_before_dispatch() {
        for endpoint in [
            "http://example.com/register",
            "https://user@example.com/register",
            "https://example.com/register#fragment",
        ] {
            let metadata = AuthorizationMetadata {
                issuer: "https://issuer.example".into(),
                authorization_endpoint: "https://issuer.example/authorize".into(),
                token_endpoint: "https://issuer.example/token".into(),
                registration_endpoint: Some(endpoint.into()),
                revocation_endpoint: None,
                client_id_metadata_document_supported: false,
                authorization_response_iss_parameter_supported: false,
                token_endpoint_auth_methods_supported: vec!["none".into()],
                scopes_supported: Vec::new(),
            };
            let error = match register_client(
                &reqwest::Client::new(),
                &metadata,
                "http://127.0.0.1:1234/callback",
                &[],
            )
            .await
            {
                Ok(_) => panic!("unsafe registration endpoint must fail before the request"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("registration endpoint"));
        }
    }
}
