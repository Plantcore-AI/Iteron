//! Operator-owned MCP configuration and provider-free diagnostics.

use crate::config::{FileConfig, McpServerConfig, McpServerOrigin, McpTransportConfig};
use clap::{Subcommand, ValueEnum};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Format {
    Text,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub(crate) enum AuthAction {
    /// Start an OAuth login for one configured HTTP server.
    Login {
        name: String,
        /// Pre-registered client id or HTTPS Client ID Metadata Document URL.
        #[arg(long)]
        client_id: Option<String>,
    },
    /// Remove locally stored credentials for one server.
    Logout { name: String },
    /// Show local credential status without revealing credentials.
    Status {
        name: String,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub(crate) enum Action {
    /// Add one operator-owned MCP server.
    Add {
        name: String,
        #[arg(long, conflicts_with = "stdio")]
        url: Option<String>,
        #[arg(long, value_name = "COMMAND", conflicts_with = "url")]
        stdio: Option<String>,
        /// Environment-variable name explicitly granted to this stdio server. Repeatable.
        #[arg(long = "env", value_name = "NAME", requires = "stdio")]
        env_names: Vec<String>,
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// List configured MCP servers.
    List {
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Inspect one configured MCP server.
    Get {
        name: String,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Remove one configured MCP server.
    Remove { name: String },
    /// Inspect locally stored MCP authentication.
    Auth {
        #[command(subcommand)]
        action: AuthAction,
    },
    /// Connect, negotiate, and discover tools without calling a business tool.
    Test {
        name: String,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Show configured state without opening a connection.
    Status {
        name: Option<String>,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Validate all MCP configuration, optionally opening bounded discovery connections.
    Doctor {
        #[arg(long)]
        connect: bool,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
}

#[derive(Serialize)]
struct ServerView<'a> {
    name: &'a str,
    transport: &'static str,
    endpoint: String,
    authentication: &'static str,
}

#[derive(Serialize)]
struct Diagnostic<'a> {
    command: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<&'a str>,
    outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol_version: Option<&'a str>,
    diagnostics: Vec<&'static str>,
    remediation: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_count: Option<usize>,
}

#[derive(Serialize)]
struct StatusView<'a> {
    name: &'a str,
    transport: &'static str,
    connection_state: &'static str,
    protocol_version: Option<&'static str>,
    tool_count: Option<usize>,
    last_error_time: Option<&'static str>,
    authentication: &'static str,
}

#[derive(Serialize)]
struct ProbeDiagnostic {
    server: String,
    outcome: &'static str,
    protocol_version: Option<String>,
    diagnostics: Vec<&'static str>,
    remediation: Vec<&'static str>,
    tool_count: Option<usize>,
}

pub(crate) async fn run(action: &Action) -> anyhow::Result<u8> {
    match action {
        Action::Add {
            name,
            url,
            stdio,
            env_names,
            args,
        } => add(name, url.as_deref(), stdio.as_deref(), env_names, args),
        Action::List { format } => list(*format),
        Action::Get { name, format } => get(name, *format),
        Action::Remove { name } => remove(name),
        Action::Test { name, format } => test(name, *format).await,
        Action::Status { name, format } => status(name.as_deref(), *format),
        Action::Doctor { connect, format } => doctor(*connect, *format).await,
        Action::Auth { action } => super::credential_store::run_auth(action).await,
    }
}

fn add(
    name: &str,
    url: Option<&str>,
    stdio: Option<&str>,
    env_names: &[String],
    args: &[String],
) -> anyhow::Result<u8> {
    let server = match (url, stdio) {
        (Some(url), None) if args.is_empty() => McpServerConfig {
            name: name.to_owned(),
            origin: McpServerOrigin::default(),
            transport: McpTransportConfig::Http,
            command: None,
            args: Vec::new(),
            env_names: Vec::new(),
            url: Some(url.to_owned()),
            header_env: BTreeMap::new(),
            oauth: None,
            tools: iteron_mcp::McpToolFilter::default(),
            policy: iteron_mcp::McpServerPolicy::default(),
        },
        (None, Some(command)) => McpServerConfig {
            name: name.to_owned(),
            origin: McpServerOrigin::default(),
            transport: McpTransportConfig::Stdio,
            command: Some(command.to_owned()),
            args: args.to_vec(),
            env_names: env_names.to_vec(),
            url: None,
            header_env: BTreeMap::new(),
            oauth: None,
            tools: iteron_mcp::McpToolFilter::default(),
            policy: iteron_mcp::McpServerPolicy::default(),
        },
        (Some(_), None) => anyhow::bail!("HTTP MCP servers do not accept trailing argv"),
        _ => anyhow::bail!("pass exactly one of --url or --stdio"),
    };
    let name = name.to_owned();
    let stored_name = name.clone();
    let path = crate::config::update_user_config(move |config| {
        let servers = config.mcp_servers.get_or_insert_with(Vec::new);
        if servers.iter().any(|existing| existing.name == stored_name) {
            return Err(format!("MCP server `{stored_name}` is already configured"));
        }
        servers.push(server);
        config.validate()
    })?;
    println!("added MCP server `{name}` to {}", path.display());
    Ok(crate::output::EXIT_SUCCESS)
}

fn list(format: Format) -> anyhow::Result<u8> {
    let config = FileConfig::load_user()?;
    let servers = config.mcp_servers.as_deref().unwrap_or_default();
    match format {
        Format::Text => {
            for server in servers {
                let view = view(server);
                println!(
                    "{}\t{}\t{}\t{}",
                    view.name, view.transport, view.endpoint, view.authentication
                );
            }
        }
        Format::Json => println!("{}", serde_json::to_string(&views(servers))?),
    }
    Ok(crate::output::EXIT_SUCCESS)
}

fn get(name: &str, format: Format) -> anyhow::Result<u8> {
    let config = FileConfig::load_user()?;
    let server = find(&config, name)?;
    let value = sanitized_config(server)?;
    match format {
        Format::Text => println!("{}", serde_json::to_string_pretty(&value)?),
        Format::Json => println!("{}", serde_json::to_string(&value)?),
    }
    Ok(crate::output::EXIT_SUCCESS)
}

fn sanitized_config(server: &McpServerConfig) -> anyhow::Result<serde_json::Value> {
    let mut value = serde_json::to_value(server)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("MCP server configuration is not an object"))?;
    if let Some(url) = server.url.as_deref() {
        let endpoint = iteron_mcp::http::McpHttpEndpoint::parse(url)?;
        object.insert(
            "url".into(),
            serde_json::Value::String(endpoint.public_origin()),
        );
    }
    object.insert(
        "authentication".into(),
        serde_json::Value::String(if server.oauth.is_some() {
            "environment".into()
        } else {
            super::credential_store::local_status(server).into()
        }),
    );
    Ok(value)
}

fn remove(name: &str) -> anyhow::Result<u8> {
    let name = name.to_owned();
    let path = crate::config::update_user_config(|config| {
        let servers = config.mcp_servers.get_or_insert_with(Vec::new);
        let before = servers.len();
        servers.retain(|server| server.name != name);
        if servers.len() == before {
            return Err(format!("unknown MCP server `{name}`"));
        }
        if servers.is_empty() {
            config.mcp_servers = None;
        }
        Ok(())
    })?;
    println!("removed MCP server `{name}` from {}", path.display());
    Ok(crate::output::EXIT_SUCCESS)
}

async fn test(name: &str, format: Format) -> anyhow::Result<u8> {
    let config = FileConfig::load_user()?;
    let server = match find(&config, name) {
        Ok(server) => server,
        Err(_) => {
            emit_probe(
                format,
                "mcp.test",
                &ProbeDiagnostic {
                    server: name.to_owned(),
                    outcome: "fail",
                    protocol_version: None,
                    diagnostics: vec!["MCP_SERVER_UNKNOWN"],
                    remediation: vec![remediation("MCP_SERVER_UNKNOWN")],
                    tool_count: None,
                },
            )?;
            return Ok(crate::output::EXIT_HARNESS);
        }
    };
    let result = probe(server).await;
    emit_probe(format, "mcp.test", &result)?;
    Ok(if result.outcome == "pass" {
        crate::output::EXIT_SUCCESS
    } else {
        crate::output::EXIT_HARNESS
    })
}

async fn probe(server: &McpServerConfig) -> ProbeDiagnostic {
    let client = super::connect_configured_server(server, &[]).await;
    match client {
        Ok(client) => {
            let version = client.negotiated_protocol_version().to_owned();
            let tools = match client
                .list_tools_governed(
                    &server.tools,
                    &server.policy,
                    iteron_mcp::default_host_ceiling(),
                )
                .await
            {
                Ok(tools) => tools,
                Err(error) => {
                    let code = diagnostic_code(&error);
                    return ProbeDiagnostic {
                        server: server.name.clone(),
                        outcome: "fail",
                        protocol_version: Some(version),
                        diagnostics: vec![code],
                        remediation: vec![remediation(code)],
                        tool_count: None,
                    };
                }
            };
            ProbeDiagnostic {
                server: server.name.clone(),
                outcome: "pass",
                protocol_version: Some(version),
                diagnostics: Vec::new(),
                remediation: Vec::new(),
                tool_count: Some(tools.len()),
            }
        }
        Err(error) => {
            let code = diagnostic_code(&error);
            ProbeDiagnostic {
                server: server.name.clone(),
                outcome: "fail",
                protocol_version: None,
                diagnostics: vec![code],
                remediation: vec![remediation(code)],
                tool_count: None,
            }
        }
    }
}

fn status(name: Option<&str>, format: Format) -> anyhow::Result<u8> {
    let config = FileConfig::load_user()?;
    let servers = config.mcp_servers.as_deref().unwrap_or_default();
    let selected = match name {
        Some(name) => match find(&config, name) {
            Ok(server) => vec![server],
            Err(_) => {
                emit_diagnostic(
                    format,
                    Diagnostic {
                        command: "mcp.status",
                        server: Some(name),
                        outcome: "fail",
                        protocol_version: None,
                        diagnostics: vec!["MCP_SERVER_UNKNOWN"],
                        remediation: vec![remediation("MCP_SERVER_UNKNOWN")],
                        tool_count: None,
                    },
                )?;
                return Ok(crate::output::EXIT_HARNESS);
            }
        },
        None => servers.iter().collect(),
    };
    match format {
        Format::Text => {
            for server in selected {
                let status = status_view(server);
                println!(
                    "{}\t{}\t{}\tprotocol=-\ttools=-\tlast_error=-\tauth={}",
                    status.name, status.connection_state, status.transport, status.authentication
                );
            }
        }
        Format::Json => {
            let values = selected.into_iter().map(status_view).collect::<Vec<_>>();
            println!("{}", serde_json::to_string(&values)?);
        }
    }
    Ok(crate::output::EXIT_SUCCESS)
}

fn status_view(server: &McpServerConfig) -> StatusView<'_> {
    StatusView {
        name: &server.name,
        transport: transport(server),
        connection_state: "not_connected",
        protocol_version: None,
        tool_count: None,
        last_error_time: None,
        authentication: if server.oauth.is_some() {
            "environment"
        } else {
            super::credential_store::local_status(server)
        },
    }
}

async fn doctor(connect: bool, format: Format) -> anyhow::Result<u8> {
    let config = match FileConfig::load_user().and_then(|config| {
        config
            .validate()
            .map_err(anyhow::Error::msg)
            .map(|()| config)
    }) {
        Ok(config) => config,
        Err(_) => {
            emit_diagnostic(
                format,
                Diagnostic {
                    command: "mcp.doctor",
                    server: None,
                    outcome: "fail",
                    protocol_version: None,
                    diagnostics: vec!["MCP_CONFIG_INVALID"],
                    remediation: vec![remediation("MCP_CONFIG_INVALID")],
                    tool_count: None,
                },
            )?;
            return Ok(crate::output::EXIT_HARNESS);
        }
    };
    let servers = config.mcp_servers.as_deref().unwrap_or_default();
    let mut checks = Vec::with_capacity(servers.len());
    for server in servers {
        checks.push(if connect {
            probe(server).await
        } else {
            local_check(server)
        });
    }
    let failed = checks.iter().any(|check| check.outcome != "pass");
    emit_doctor(format, &checks, failed)?;
    Ok(if failed {
        crate::output::EXIT_HARNESS
    } else {
        crate::output::EXIT_SUCCESS
    })
}

fn local_check(server: &McpServerConfig) -> ProbeDiagnostic {
    let code = match server.transport {
        McpTransportConfig::Stdio
            if !server.command.as_deref().is_some_and(command_is_available) =>
        {
            Some("MCP_COMMAND_NOT_FOUND")
        }
        McpTransportConfig::Http
            if server
                .oauth
                .as_ref()
                .is_some_and(|oauth| std::env::var_os(&oauth.access_token_env).is_none()) =>
        {
            Some("MCP_AUTH_REQUIRED")
        }
        McpTransportConfig::Http
            if matches!(
                super::credential_store::local_status(server),
                "expired" | "invalid"
            ) =>
        {
            Some("MCP_AUTH_REQUIRED")
        }
        _ => None,
    };
    ProbeDiagnostic {
        server: server.name.clone(),
        outcome: if code.is_some() { "fail" } else { "pass" },
        protocol_version: None,
        diagnostics: code.into_iter().collect(),
        remediation: code.into_iter().map(remediation).collect(),
        tool_count: None,
    }
}

fn command_is_available(command: &str) -> bool {
    let path = std::path::Path::new(command);
    if path.components().count() > 1 {
        return path.is_file();
    }
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|directory| directory.join(command).is_file())
    })
}

fn emit_doctor(format: Format, checks: &[ProbeDiagnostic], failed: bool) -> anyhow::Result<()> {
    match format {
        Format::Text => {
            println!("mcp.doctor: {}", if failed { "fail" } else { "pass" });
            for check in checks {
                println!("{}: {}", check.server, check.outcome);
                for (code, remediation) in check.diagnostics.iter().zip(&check.remediation) {
                    println!("diagnostic: {code}");
                    println!("remediation: {remediation}");
                }
            }
        }
        Format::Json => println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "command": "mcp.doctor",
                "outcome": if failed { "fail" } else { "pass" },
                "checks": checks,
            }))?
        ),
    }
    Ok(())
}

fn find<'a>(config: &'a FileConfig, name: &str) -> anyhow::Result<&'a McpServerConfig> {
    config
        .mcp_servers
        .as_deref()
        .unwrap_or_default()
        .iter()
        .find(|server| server.name == name)
        .ok_or_else(|| anyhow::anyhow!("unknown MCP server `{name}`"))
}

fn views(servers: &[McpServerConfig]) -> Vec<ServerView<'_>> {
    servers.iter().map(view).collect()
}

fn view(server: &McpServerConfig) -> ServerView<'_> {
    ServerView {
        name: &server.name,
        transport: transport(server),
        endpoint: match server.transport {
            McpTransportConfig::Stdio => {
                server.command.as_deref().unwrap_or("<invalid>").to_owned()
            }
            McpTransportConfig::Http => server
                .url
                .as_deref()
                .and_then(|url| iteron_mcp::http::McpHttpEndpoint::parse(url).ok())
                .map_or_else(
                    || "<invalid>".to_owned(),
                    |endpoint| endpoint.public_origin(),
                ),
        },
        authentication: if server.oauth.is_some() {
            "environment"
        } else {
            super::credential_store::local_status(server)
        },
    }
}

fn transport(server: &McpServerConfig) -> &'static str {
    match server.transport {
        McpTransportConfig::Stdio => "stdio",
        McpTransportConfig::Http => "http",
    }
}

fn diagnostic_code(error: &iteron_mcp::McpError) -> &'static str {
    match error {
        iteron_mcp::McpError::UnsupportedProtocolVersion { .. }
        | iteron_mcp::McpError::InvalidProtocolVersion { .. } => "MCP_PROTOCOL_UNSUPPORTED",
        iteron_mcp::McpError::Credential(_) => "MCP_AUTH_REQUIRED",
        iteron_mcp::McpError::HttpStatus { status: 401 | 403 } => "MCP_AUTH_REQUIRED",
        iteron_mcp::McpError::Deadline { .. } => "MCP_TRANSPORT_TIMEOUT",
        iteron_mcp::McpError::Protocol(message)
            if message.starts_with("MCP server/discover")
                || message.starts_with("MCP discovery") =>
        {
            "MCP_DISCOVER_INVALID"
        }
        iteron_mcp::McpError::ToolListCursorCycle
        | iteron_mcp::McpError::ToolListPageLimit { .. }
        | iteron_mcp::McpError::ToolListToolLimit { .. }
        | iteron_mcp::McpError::ToolListByteLimit { .. } => "MCP_TOOL_CATALOG_INVALID",
        _ => "MCP_CONNECTION_FAILED",
    }
}

fn remediation(code: &str) -> &'static str {
    match code {
        "MCP_CONFIG_INVALID" => "Fix the MCP server configuration and run doctor again.",
        "MCP_SERVER_UNKNOWN" => "Run `iteron mcp list` and use a configured server name.",
        "MCP_PROTOCOL_UNSUPPORTED" => "Upgrade the server or Iteron to a shared protocol version.",
        "MCP_DISCOVER_INVALID" => "Check the server's 2026 discovery implementation.",
        "MCP_AUTH_REQUIRED" => {
            "Run `iteron mcp auth login <name>` or refresh configured credentials."
        }
        "MCP_COMMAND_NOT_FOUND" => "Install the executable or use an absolute command path.",
        "MCP_TRANSPORT_TIMEOUT" => "Check the server and network, then retry.",
        "MCP_TOOL_CATALOG_INVALID" => "Fix the server tool catalog before reconnecting.",
        _ => "Check the server process or endpoint and run `iteron mcp test <name>`.",
    }
}

fn emit_probe(
    format: Format,
    command: &'static str,
    value: &ProbeDiagnostic,
) -> anyhow::Result<()> {
    match format {
        Format::Text => {
            println!("{command} `{}`: {}", value.server, value.outcome);
            if let Some(version) = &value.protocol_version {
                println!("protocol: {version}");
            }
            if let Some(count) = value.tool_count {
                println!("tools: {count}");
            }
            for (code, remediation) in value.diagnostics.iter().zip(&value.remediation) {
                println!("diagnostic: {code}");
                println!("remediation: {remediation}");
            }
        }
        Format::Json => println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "command": command,
                "server": value.server,
                "outcome": value.outcome,
                "protocol_version": value.protocol_version,
                "diagnostics": value.diagnostics,
                "remediation": value.remediation,
                "tool_count": value.tool_count,
            }))?
        ),
    }
    Ok(())
}

fn emit_diagnostic(format: Format, value: Diagnostic<'_>) -> anyhow::Result<()> {
    match format {
        Format::Text => {
            let server = value
                .server
                .map_or(String::new(), |name| format!(" `{name}`"));
            println!("{}{}: {}", value.command, server, value.outcome);
            if let Some(version) = value.protocol_version {
                println!("protocol: {version}");
            }
            if let Some(count) = value.tool_count {
                println!("tools: {count}");
            }
            for diagnostic in value.diagnostics {
                println!("diagnostic: {diagnostic}");
            }
            for remediation in value.remediation {
                println!("remediation: {remediation}");
            }
        }
        Format::Json => println!("{}", serde_json::to_string(&value)?),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_views_never_contain_environment_values() {
        let secret = "mcp-secret-marker";
        unsafe { std::env::set_var("MCP_TEST_SECRET", secret) };
        let server = McpServerConfig {
            name: "safe".into(),
            origin: McpServerOrigin::default(),
            transport: McpTransportConfig::Http,
            command: None,
            args: Vec::new(),
            env_names: Vec::new(),
            url: Some("https://example.com/private?token=mcp-secret-marker".into()),
            header_env: BTreeMap::from([("X-Key".into(), "MCP_TEST_SECRET".into())]),
            oauth: None,
            tools: iteron_mcp::McpToolFilter::default(),
            policy: iteron_mcp::McpServerPolicy::default(),
        };
        let rendered = serde_json::to_string(&view(&server)).unwrap();
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains("MCP_TEST_SECRET"));
        assert!(!rendered.contains("private"));
        assert!(!rendered.contains("token"));
        assert_eq!(view(&server).endpoint, "https://example.com:443");
    }

    #[test]
    fn stable_diagnostic_codes_cover_operator_recovery_paths() {
        assert_eq!(
            diagnostic_code(&iteron_mcp::McpError::Deadline {
                operation: "test".into()
            }),
            "MCP_TRANSPORT_TIMEOUT"
        );
        assert_eq!(
            diagnostic_code(&iteron_mcp::McpError::HttpStatus { status: 401 }),
            "MCP_AUTH_REQUIRED"
        );
        assert_eq!(
            diagnostic_code(&iteron_mcp::McpError::UnsupportedProtocolVersion {
                client_version: "2026-07-28".into(),
                server_version: "2099-01-01".into(),
            }),
            "MCP_PROTOCOL_UNSUPPORTED"
        );
        assert_eq!(
            diagnostic_code(&iteron_mcp::McpError::Protocol(
                "MCP server/discover did not complete".into()
            )),
            "MCP_DISCOVER_INVALID"
        );
    }
}
