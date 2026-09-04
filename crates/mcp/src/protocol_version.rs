use crate::McpError;
use serde_json::Value;

/// The newest MCP protocol version this client implements.
///
/// Keep older final revisions in [`SUPPORTED_PROTOCOL_VERSIONS`]: discovery starts with this
/// version, then a stateful initialize may request an explicitly selected older revision.
pub const MODERN_PROTOCOL_VERSION: &str = "2026-07-28";
pub(crate) const REQUESTED_PROTOCOL_VERSION: &str = MODERN_PROTOCOL_VERSION;
pub(crate) const STATEFUL_REQUESTED_PROTOCOL_VERSION: &str = "2025-11-25";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpProtocolMode {
    /// Prefer 2026 discovery and use the server-selected stateful protocol when discovery proves
    /// that the peer is legacy-only.
    Auto,
    Stateful,
    Stateless2026,
}

impl McpProtocolMode {
    pub const fn is_stateless(self) -> bool {
        matches!(self, Self::Stateless2026)
    }

    pub const fn prefers_modern(self) -> bool {
        matches!(self, Self::Auto | Self::Stateless2026)
    }
}

const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &[
    REQUESTED_PROTOCOL_VERSION,
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
];
const MAX_PROTOCOL_VERSION_BYTES: usize = 64;

/// Validate the version selected by the server before the initialized notification is sent.
///
/// Unknown versions are not assumed compatible. A version is copied into a diagnostic only after
/// it passes the small token grammar and byte ceiling, so an untrusted server cannot inject
/// control text or an unbounded value into operator output.
pub(crate) fn negotiate_initialize_result(result: &Value) -> Result<String, McpError> {
    let Some(server_version) = result.get("protocolVersion").and_then(Value::as_str) else {
        return Err(invalid_protocol_version(
            STATEFUL_REQUESTED_PROTOCOL_VERSION,
        ));
    };
    if !is_bounded_protocol_token(server_version) {
        return Err(invalid_protocol_version(
            STATEFUL_REQUESTED_PROTOCOL_VERSION,
        ));
    }
    if !SUPPORTED_PROTOCOL_VERSIONS.contains(&server_version) {
        return Err(McpError::UnsupportedProtocolVersion {
            client_version: STATEFUL_REQUESTED_PROTOCOL_VERSION.to_owned(),
            server_version: server_version.to_owned(),
        });
    }
    Ok(server_version.to_owned())
}

pub(crate) fn client_metadata() -> Value {
    serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": {
            "name": "iteron",
            "version": env!("CARGO_PKG_VERSION")
        },
        "io.modelcontextprotocol/clientCapabilities": {
            "tools": {},
            "elicitation": {"form": {}}
        }
    })
}

pub(crate) fn modern_params(mut params: Value) -> Result<Value, McpError> {
    let object = params
        .as_object_mut()
        .ok_or_else(|| McpError::Protocol("MCP request params must be an object".into()))?;
    let metadata = client_metadata();
    let client_fields = metadata
        .as_object()
        .expect("repository-owned client metadata is an object");
    let target = object
        .entry("_meta")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or_else(|| McpError::Protocol("MCP request _meta must be an object".into()))?;
    for (key, value) in client_fields {
        target.insert(key.clone(), value.clone());
    }
    Ok(params)
}

pub(crate) fn discover_params() -> Value {
    serde_json::json!({"_meta": client_metadata()})
}

pub(crate) enum DiscoveryNegotiation {
    Modern(String, crate::McpServerCapabilities),
    Stateful(String),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DiscoveryRejection {
    RetryModern,
    Stateful(String),
}

pub(crate) fn parse_protocol_version_rejection(error: &Value) -> Option<(String, Vec<String>)> {
    let data = error.get("data")?.as_object()?;
    let requested = data
        .get("requested")?
        .as_str()
        .filter(|version| is_bounded_protocol_token(version))?
        .to_owned();
    let supported = data.get("supported")?.as_array()?;
    if supported.is_empty() || supported.len() > SUPPORTED_PROTOCOL_VERSIONS.len() {
        return None;
    }
    let supported = supported
        .iter()
        .map(|version| {
            version
                .as_str()
                .filter(|version| is_bounded_protocol_token(version))
                .map(str::to_owned)
        })
        .collect::<Option<Vec<_>>>()?;
    Some((requested, supported))
}

pub(crate) fn discovery_rejection(error: &McpError) -> Option<DiscoveryRejection> {
    let McpError::ProtocolVersionRejected {
        requested,
        supported,
    } = error
    else {
        return None;
    };
    if requested != MODERN_PROTOCOL_VERSION
        || supported
            .iter()
            .any(|version| !SUPPORTED_PROTOCOL_VERSIONS.contains(&version.as_str()))
    {
        return None;
    }
    if supported
        .iter()
        .any(|version| version == MODERN_PROTOCOL_VERSION)
    {
        return Some(DiscoveryRejection::RetryModern);
    }
    SUPPORTED_PROTOCOL_VERSIONS
        .iter()
        .copied()
        .find(|candidate| supported.iter().any(|version| version == candidate))
        .map(|version| DiscoveryRejection::Stateful(version.to_owned()))
}

pub(crate) fn negotiate_discovery(result: &Value) -> Result<DiscoveryNegotiation, McpError> {
    if result.get("resultType").and_then(Value::as_str) != Some("complete") {
        return Err(McpError::Protocol(
            "MCP server/discover did not complete".into(),
        ));
    }
    let supported = result
        .get("supportedVersions")
        .and_then(Value::as_array)
        .ok_or_else(|| McpError::Protocol("MCP discovery omitted supportedVersions".into()))?;
    let mut versions = Vec::with_capacity(supported.len());
    for version in supported {
        let version = version
            .as_str()
            .filter(|version| is_bounded_protocol_token(version))
            .ok_or_else(|| invalid_protocol_version(MODERN_PROTOCOL_VERSION))?;
        if !SUPPORTED_PROTOCOL_VERSIONS.contains(&version) {
            return Err(McpError::UnsupportedProtocolVersion {
                client_version: MODERN_PROTOCOL_VERSION.into(),
                server_version: version.to_owned(),
            });
        }
        versions.push(version);
    }
    if versions.is_empty() {
        return Err(McpError::Protocol(
            "MCP discovery returned no supported protocol versions".into(),
        ));
    }
    if !versions.contains(&MODERN_PROTOCOL_VERSION) {
        let selected = SUPPORTED_PROTOCOL_VERSIONS
            .iter()
            .copied()
            .find(|candidate| versions.contains(candidate))
            .expect("all discovered versions were validated as supported");
        return Ok(DiscoveryNegotiation::Stateful(selected.to_owned()));
    }
    let capabilities = result.get("capabilities").and_then(Value::as_object);
    Ok(DiscoveryNegotiation::Modern(
        MODERN_PROTOCOL_VERSION.into(),
        crate::McpServerCapabilities {
            tools: capabilities.is_some_and(|value| value.contains_key("tools")),
            resources: capabilities.is_some_and(|value| value.contains_key("resources")),
            prompts: capabilities.is_some_and(|value| value.contains_key("prompts")),
        },
    ))
}

pub(crate) fn discovery_allows_stateful_fallback(error: &McpError) -> bool {
    matches!(
        error,
        McpError::Server { code: -32601, .. } | McpError::HttpStatus { status: 404 | 405 }
    )
}

pub(crate) fn require_modern_discovery(
    negotiation: DiscoveryNegotiation,
) -> Result<(String, crate::McpServerCapabilities), McpError> {
    match negotiation {
        DiscoveryNegotiation::Modern(version, capabilities) => Ok((version, capabilities)),
        DiscoveryNegotiation::Stateful(server_version) => {
            Err(McpError::UnsupportedProtocolVersion {
                client_version: MODERN_PROTOCOL_VERSION.into(),
                server_version,
            })
        }
    }
}

fn is_bounded_protocol_token(version: &str) -> bool {
    !version.is_empty()
        && version.len()
            <= iteron_tunables::param_integer(
                "mcp.protocol_version.max_protocol_version_bytes",
                MAX_PROTOCOL_VERSION_BYTES,
            )
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
}

/// Permit version details in a public diagnostic only when the client side is repository-owned
/// vocabulary and the peer side has the bounded dated shape used by MCP revisions.
pub(crate) fn is_actionable_version_mismatch(client_version: &str, server_version: &str) -> bool {
    SUPPORTED_PROTOCOL_VERSIONS.contains(&client_version)
        && is_dated_protocol_version(server_version)
}

fn is_dated_protocol_version(version: &str) -> bool {
    let bytes = version.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| !matches!(index, 4 | 7) && !byte.is_ascii_digit())
    {
        return false;
    }

    let month = (bytes[5] - b'0') * 10 + (bytes[6] - b'0');
    let day = (bytes[8] - b'0') * 10 + (bytes[9] - b'0');
    (1..=12).contains(&month) && (1..=31).contains(&day)
}

fn invalid_protocol_version(client_version: &str) -> McpError {
    McpError::InvalidProtocolVersion {
        client_version: client_version.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_repository_supported_version_is_accepted() {
        let version = negotiate_initialize_result(&json!({
            "protocolVersion": STATEFUL_REQUESTED_PROTOCOL_VERSION
        }))
        .unwrap();
        assert_eq!(version, STATEFUL_REQUESTED_PROTOCOL_VERSION);
    }

    #[test]
    fn modern_discovery_requires_complete_and_the_exact_version() {
        let (version, capabilities) = require_modern_discovery(
            negotiate_discovery(&json!({
                "resultType": "complete",
                "supportedVersions": [MODERN_PROTOCOL_VERSION],
                "capabilities": {"tools": {}, "resources": {}}
            }))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(version, MODERN_PROTOCOL_VERSION);
        assert!(capabilities.tools);
        assert!(capabilities.resources);
        assert!(!capabilities.prompts);
        assert!(
            require_modern_discovery(
                negotiate_discovery(&json!({
                    "resultType": "complete",
                    "supportedVersions": ["2025-11-25"]
                }))
                .unwrap()
            )
            .is_err()
        );
        assert!(matches!(
            negotiate_discovery(&json!({
                "resultType": "complete",
                "supportedVersions": [1]
            })),
            Err(McpError::InvalidProtocolVersion { client_version })
                if client_version == MODERN_PROTOCOL_VERSION
        ));
    }

    #[test]
    fn auto_discovery_selects_only_a_known_legacy_version() {
        assert!(matches!(
            negotiate_discovery(&json!({
                "resultType": "complete",
                "supportedVersions": ["2025-06-18", "2025-11-25"]
            }))
            .unwrap(),
            DiscoveryNegotiation::Stateful(version) if version == "2025-11-25"
        ));
        assert!(
            negotiate_discovery(&json!({
                "resultType": "complete",
                "supportedVersions": ["2025-11-25", "2099-01-01"]
            }))
            .is_err()
        );
    }

    #[test]
    fn auto_fallback_requires_explicit_legacy_protocol_evidence() {
        assert!(discovery_allows_stateful_fallback(&McpError::Server {
            code: -32601,
            message: "Method not found".into(),
        }));
        for status in [400, 401, 403, 408, 429, 500] {
            assert!(!discovery_allows_stateful_fallback(&McpError::HttpStatus {
                status
            }));
        }
        for status in [404, 405] {
            assert!(discovery_allows_stateful_fallback(&McpError::HttpStatus {
                status
            }));
        }
    }

    #[test]
    fn structured_version_rejections_only_authorize_bounded_known_actions() {
        let current = McpError::ProtocolVersionRejected {
            requested: MODERN_PROTOCOL_VERSION.into(),
            supported: vec![MODERN_PROTOCOL_VERSION.into()],
        };
        assert_eq!(
            discovery_rejection(&current),
            Some(DiscoveryRejection::RetryModern)
        );

        let legacy = McpError::ProtocolVersionRejected {
            requested: MODERN_PROTOCOL_VERSION.into(),
            supported: vec![
                "2025-06-18".into(),
                STATEFUL_REQUESTED_PROTOCOL_VERSION.into(),
            ],
        };
        assert_eq!(
            discovery_rejection(&legacy),
            Some(DiscoveryRejection::Stateful(
                STATEFUL_REQUESTED_PROTOCOL_VERSION.into()
            ))
        );

        for rejected in [
            McpError::ProtocolVersionRejected {
                requested: "2099-01-01".into(),
                supported: vec![STATEFUL_REQUESTED_PROTOCOL_VERSION.into()],
            },
            McpError::ProtocolVersionRejected {
                requested: MODERN_PROTOCOL_VERSION.into(),
                supported: vec![
                    STATEFUL_REQUESTED_PROTOCOL_VERSION.into(),
                    "2099-01-01".into(),
                ],
            },
        ] {
            assert_eq!(discovery_rejection(&rejected), None);
        }
    }

    #[test]
    fn modern_metadata_is_attached_without_overwriting_business_params() {
        let params = modern_params(json!({"name": "echo"})).unwrap();
        assert_eq!(params["name"], "echo");
        assert_eq!(
            params["_meta"]["io.modelcontextprotocol/protocolVersion"],
            MODERN_PROTOCOL_VERSION
        );
    }

    #[test]
    fn actionable_public_mismatch_requires_known_client_and_dated_server() {
        let credential_shaped = ["gh", "p_", "AbCdEf1234567890"].concat();
        assert!(is_actionable_version_mismatch(
            REQUESTED_PROTOCOL_VERSION,
            "2099-01-01"
        ));
        assert!(!is_actionable_version_mismatch(
            &credential_shaped,
            "2099-01-01"
        ));
        for server_version in [
            credential_shaped.as_str(),
            "20990101",
            "2099-00-01",
            "2099-13-01",
            "2099-01-00",
            "2099-01-32",
        ] {
            assert!(!is_actionable_version_mismatch(
                REQUESTED_PROTOCOL_VERSION,
                server_version
            ));
        }
    }

    #[test]
    fn missing_or_non_string_versions_are_typed_failures() {
        for result in [json!({}), json!({"protocolVersion": 20241105})] {
            let error = negotiate_initialize_result(&result).unwrap_err();
            assert!(matches!(
                error,
                McpError::InvalidProtocolVersion { ref client_version }
                    if client_version == STATEFUL_REQUESTED_PROTOCOL_VERSION
            ));
        }
    }

    #[test]
    fn unbounded_or_unsafe_versions_are_not_reflected() {
        for server_version in [
            "x".repeat(MAX_PROTOCOL_VERSION_BYTES + 1),
            "2024-11-05\nforged".to_owned(),
        ] {
            let result = json!({"protocolVersion": server_version});
            let error = negotiate_initialize_result(&result).unwrap_err();
            let diagnostic = error.to_string();
            assert!(matches!(error, McpError::InvalidProtocolVersion { .. }));
            assert!(!diagnostic.contains(&server_version));
        }
    }

    #[test]
    fn a_newer_unknown_version_names_both_sides_and_fails_closed() {
        let error =
            negotiate_initialize_result(&json!({"protocolVersion": "2099-01-01"})).unwrap_err();
        assert!(matches!(
            error,
            McpError::UnsupportedProtocolVersion {
                ref client_version,
                ref server_version,
            } if client_version == STATEFUL_REQUESTED_PROTOCOL_VERSION && server_version == "2099-01-01"
        ));
        let diagnostic = error.to_string();
        assert!(diagnostic.contains(STATEFUL_REQUESTED_PROTOCOL_VERSION));
        assert!(diagnostic.contains("2099-01-01"));
    }
}
