//! Private, server-bound MCP OAuth credential storage.

use super::commands::{AuthAction, Format};
use crate::config::{McpServerConfig, McpTransportConfig};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::path::PathBuf;

const CREDENTIAL_SCHEMA_VERSION: u32 = 1;
const MAX_CREDENTIAL_BYTES: u64 = 64 * 1024;

/// Secret-bearing persisted value. Deliberately no `Debug` implementation.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredCredential {
    schema_version: u32,
    binding_id: String,
    pub(crate) server_name: String,
    pub(crate) resource: String,
    pub(crate) issuer: String,
    pub(crate) client_id: String,
    pub(crate) access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) refresh_token: Option<String>,
    pub(crate) expires_at_unix: u64,
    pub(crate) token_endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) revocation_endpoint: Option<String>,
}

impl StoredCredential {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        server: &McpServerConfig,
        resource: String,
        issuer: String,
        client_id: String,
        access_token: String,
        refresh_token: Option<String>,
        expires_at_unix: u64,
        token_endpoint: String,
        revocation_endpoint: Option<String>,
    ) -> anyhow::Result<Self> {
        validate_public_field("resource", &resource)?;
        validate_public_field("issuer", &issuer)?;
        validate_public_field("client_id", &client_id)?;
        validate_public_field("token_endpoint", &token_endpoint)?;
        if let Some(endpoint) = &revocation_endpoint {
            validate_public_field("revocation_endpoint", endpoint)?;
        }
        validate_secret(&access_token)?;
        if let Some(token) = &refresh_token {
            validate_secret(token)?;
        }
        Ok(Self {
            schema_version: CREDENTIAL_SCHEMA_VERSION,
            binding_id: binding_id(server)?,
            server_name: server.name.clone(),
            resource,
            issuer,
            client_id,
            access_token,
            refresh_token,
            expires_at_unix,
            token_endpoint,
            revocation_endpoint,
        })
    }
}

pub(crate) fn local_status(server: &McpServerConfig) -> &'static str {
    if pending_path(server).is_some_and(|path| {
        path.metadata()
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age <= std::time::Duration::from_secs(10 * 60))
    }) {
        return "pending";
    }
    match load(server) {
        Ok(Some(credential)) if credential.expires_at_unix <= unix_now() => "expired",
        Ok(Some(_)) => "authenticated",
        Ok(None) => "unauthenticated",
        Err(_) => "invalid",
    }
}

pub(crate) fn save(server: &McpServerConfig, credential: &StoredCredential) -> anyhow::Result<()> {
    let expected = binding_id(server)?;
    if credential.binding_id != expected || credential.server_name != server.name {
        anyhow::bail!("MCP credential binding does not match the configured server");
    }
    validate_binding(server, credential)?;
    let path = credential_path(server)
        .ok_or_else(|| anyhow::anyhow!("cannot resolve the MCP credential directory"))?;
    let bytes = serde_json::to_vec(credential)?;
    if bytes.len() as u64 > MAX_CREDENTIAL_BYTES {
        anyhow::bail!("MCP credential document exceeds its private storage bound");
    }
    crate::config::write_private_atomic(&path, &bytes)
}

pub(crate) fn load(server: &McpServerConfig) -> anyhow::Result<Option<StoredCredential>> {
    let Some(path) = credential_path(server) else {
        return Ok(None);
    };
    let file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if file.metadata()?.len() > MAX_CREDENTIAL_BYTES {
        anyhow::bail!("MCP credential document exceeds its private storage bound");
    }
    let credential: StoredCredential = serde_json::from_reader(file)?;
    if credential.schema_version != CREDENTIAL_SCHEMA_VERSION
        || credential.server_name != server.name
        || credential.binding_id != binding_id(server)?
    {
        anyhow::bail!("MCP credential binding does not match the configured server");
    }
    validate_binding(server, &credential)?;
    validate_secret(&credential.access_token)?;
    if let Some(token) = &credential.refresh_token {
        validate_secret(token)?;
    }
    Ok(Some(credential))
}

pub(crate) fn delete(server: &McpServerConfig) -> anyhow::Result<bool> {
    let Some(path) = credential_path(server) else {
        return Ok(false);
    };
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub(crate) async fn run_auth(action: &AuthAction) -> anyhow::Result<u8> {
    let config = crate::config::FileConfig::load_user()?;
    match action {
        AuthAction::Login { name, client_id } => {
            let server = find(&config, name)?;
            if server.transport != McpTransportConfig::Http {
                anyhow::bail!("MCP OAuth login is available only for HTTP servers");
            }
            if matches!(local_status(server), "authenticated") {
                println!("MCP server `{name}` is already authenticated");
                return Ok(crate::output::EXIT_SUCCESS);
            }
            if matches!(local_status(server), "pending") {
                anyhow::bail!("MCP OAuth login is already pending for `{name}`");
            }
            mark_pending(server)?;
            let result = super::oauth_login::login(server, client_id.as_deref(), true).await;
            clear_pending(server)?;
            match result.map_err(auth_login_error)? {
                super::oauth_login::LoginOutcome::NotRequired => {
                    println!("MCP server `{name}` does not require authentication");
                }
                super::oauth_login::LoginOutcome::Credential(credential) => {
                    save(server, &credential)?;
                    println!("authenticated MCP server `{name}`");
                }
            }
            Ok(crate::output::EXIT_SUCCESS)
        }
        AuthAction::Logout { name } => {
            let server = find(&config, name)?;
            if let Ok(Some(credential)) = load(server) {
                let _ = super::oauth_login::revoke(&credential).await;
            }
            let removed = delete(server)?;
            clear_pending(server)?;
            println!(
                "{}",
                if removed {
                    "removed local MCP credentials"
                } else {
                    "no local MCP credentials were stored"
                }
            );
            Ok(crate::output::EXIT_SUCCESS)
        }
        AuthAction::Status { name, format } => {
            let server = find(&config, name)?;
            let status = local_status(server);
            match format {
                Format::Text => println!("{name}: {status}"),
                Format::Json => println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({
                        "server": name,
                        "authentication": status,
                    }))?
                ),
            }
            Ok(crate::output::EXIT_SUCCESS)
        }
    }
}

fn auth_login_error(error: anyhow::Error) -> anyhow::Error {
    let message = error.to_string();
    let code = if message.contains("issuer mismatch")
        || message.contains("resource metadata does not match")
    {
        "MCP_AUTH_ISSUER_MISMATCH"
    } else if message.contains("callback timed out") {
        "MCP_AUTH_CALLBACK_TIMEOUT"
    } else {
        "MCP_AUTH_FAILED"
    };
    anyhow::anyhow!("{code}: {message}")
}

fn credential_path(server: &McpServerConfig) -> Option<PathBuf> {
    let root = crate::config::config_home()?;
    let directory = iteron_protocol::home::path(&root, "mcp-credentials");
    Some(directory.join(binding_id(server).ok()?))
}

fn pending_path(server: &McpServerConfig) -> Option<PathBuf> {
    credential_path(server).map(|path| path.with_extension("pending"))
}

fn mark_pending(server: &McpServerConfig) -> anyhow::Result<()> {
    let path = pending_path(server)
        .ok_or_else(|| anyhow::anyhow!("cannot resolve the MCP credential directory"))?;
    let bytes = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 1,
        "startedAtUnix": unix_now(),
    }))?;
    crate::config::write_private_atomic(&path, &bytes)
}

fn clear_pending(server: &McpServerConfig) -> anyhow::Result<()> {
    let Some(path) = pending_path(server) else {
        return Ok(());
    };
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn binding_id(server: &McpServerConfig) -> anyhow::Result<String> {
    let encoded = serde_json::to_vec(server)?;
    let mut digest = Sha256::new();
    digest.update(b"iteron-mcp-credential-binding-v1\0");
    digest.update((encoded.len() as u64).to_be_bytes());
    digest.update(encoded);
    Ok(hex::encode(digest.finalize()))
}

fn find<'a>(
    config: &'a crate::config::FileConfig,
    name: &str,
) -> anyhow::Result<&'a McpServerConfig> {
    config
        .mcp_servers
        .as_deref()
        .unwrap_or_default()
        .iter()
        .find(|server| server.name == name)
        .ok_or_else(|| anyhow::anyhow!("unknown MCP server `{name}`"))
}

fn validate_public_field(field: &str, value: &str) -> anyhow::Result<()> {
    if value.is_empty() || value.len() > 8192 || value.chars().any(char::is_control) {
        anyhow::bail!("invalid MCP credential {field}");
    }
    Ok(())
}

fn validate_secret(value: &str) -> anyhow::Result<()> {
    if value.is_empty() || value.len() > 8192 || value.contains('\0') {
        anyhow::bail!("invalid MCP credential secret");
    }
    Ok(())
}

fn validate_binding(server: &McpServerConfig, credential: &StoredCredential) -> anyhow::Result<()> {
    if server.url.as_deref() != Some(credential.resource.as_str()) {
        anyhow::bail!("MCP credential resource does not match the configured server");
    }
    let issuer = url::Url::parse(&credential.issuer)?;
    for endpoint in [
        Some(credential.token_endpoint.as_str()),
        credential.revocation_endpoint.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        let endpoint = url::Url::parse(endpoint)?;
        if issuer.scheme() != endpoint.scheme()
            || issuer.host_str() != endpoint.host_str()
            || issuer.port_or_known_default() != endpoint.port_or_known_default()
        {
            anyhow::bail!("MCP credential endpoint does not match its issuer");
        }
    }
    Ok(())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn server(name: &str) -> McpServerConfig {
        McpServerConfig {
            name: name.into(),
            origin: crate::config::McpServerOrigin::default(),
            transport: McpTransportConfig::Http,
            command: None,
            args: Vec::new(),
            env_names: Vec::new(),
            url: Some("https://example.com/mcp".into()),
            header_env: BTreeMap::new(),
            oauth: None,
            tools: iteron_mcp::McpToolFilter::default(),
            policy: iteron_mcp::McpServerPolicy::default(),
        }
    }

    #[test]
    fn binding_changes_with_server_identity() {
        assert_ne!(
            binding_id(&server("one")).unwrap(),
            binding_id(&server("two")).unwrap()
        );
    }

    #[test]
    fn persisted_document_is_bound_and_bounded() {
        let server = server("safe");
        let credential = StoredCredential::new(
            &server,
            "https://example.com/mcp".into(),
            "https://auth.example.com".into(),
            "client".into(),
            "access-secret".into(),
            Some("refresh-secret".into()),
            99,
            "https://auth.example.com/token".into(),
            None,
        )
        .unwrap();
        let encoded = serde_json::to_vec(&credential).unwrap();
        assert!((encoded.len() as u64) < MAX_CREDENTIAL_BYTES);
        let decoded: StoredCredential = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.binding_id, binding_id(&server).unwrap());
        assert!(validate_binding(&server, &decoded).is_ok());
    }

    #[test]
    fn resource_and_issuer_endpoint_changes_cannot_reuse_a_credential() {
        let server = server("safe");
        let mut credential = StoredCredential::new(
            &server,
            "https://example.com/mcp".into(),
            "https://auth.example.com".into(),
            "client".into(),
            "access-secret".into(),
            None,
            99,
            "https://auth.example.com/token".into(),
            None,
        )
        .unwrap();
        credential.resource = "https://other.example/mcp".into();
        assert!(validate_binding(&server, &credential).is_err());
        credential.resource = "https://example.com/mcp".into();
        credential.token_endpoint = "https://other-auth.example/token".into();
        assert!(validate_binding(&server, &credential).is_err());
    }
}
