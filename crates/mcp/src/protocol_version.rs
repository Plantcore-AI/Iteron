use crate::McpError;
use serde_json::Value;

/// The newest (and currently only) MCP protocol version this client implements.
pub(crate) const REQUESTED_PROTOCOL_VERSION: &str = "2024-11-05";

const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &[REQUESTED_PROTOCOL_VERSION];
const MAX_PROTOCOL_VERSION_BYTES: usize = 64;

/// Validate the version selected by the server before the initialized notification is sent.
///
/// Unknown versions are not assumed compatible. A version is copied into a diagnostic only after
/// it passes the small token grammar and byte ceiling, so an untrusted server cannot inject
/// control text or an unbounded value into operator output.
pub(crate) fn negotiate_initialize_result(result: &Value) -> Result<String, McpError> {
    let Some(server_version) = result.get("protocolVersion").and_then(Value::as_str) else {
        return Err(invalid_protocol_version());
    };
    if !is_bounded_protocol_token(server_version) {
        return Err(invalid_protocol_version());
    }
    if !SUPPORTED_PROTOCOL_VERSIONS.contains(&server_version) {
        return Err(McpError::UnsupportedProtocolVersion {
            client_version: REQUESTED_PROTOCOL_VERSION.to_owned(),
            server_version: server_version.to_owned(),
        });
    }
    Ok(server_version.to_owned())
}

fn is_bounded_protocol_token(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= MAX_PROTOCOL_VERSION_BYTES
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
}

fn invalid_protocol_version() -> McpError {
    McpError::InvalidProtocolVersion {
        client_version: REQUESTED_PROTOCOL_VERSION.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_repository_supported_version_is_accepted() {
        let version = negotiate_initialize_result(&json!({
            "protocolVersion": REQUESTED_PROTOCOL_VERSION
        }))
        .unwrap();
        assert_eq!(version, REQUESTED_PROTOCOL_VERSION);
    }

    #[test]
    fn missing_or_non_string_versions_are_typed_failures() {
        for result in [json!({}), json!({"protocolVersion": 20241105})] {
            let error = negotiate_initialize_result(&result).unwrap_err();
            assert!(matches!(
                error,
                McpError::InvalidProtocolVersion { ref client_version }
                    if client_version == REQUESTED_PROTOCOL_VERSION
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
            } if client_version == REQUESTED_PROTOCOL_VERSION && server_version == "2099-01-01"
        ));
        let diagnostic = error.to_string();
        assert!(diagnostic.contains(REQUESTED_PROTOCOL_VERSION));
        assert!(diagnostic.contains("2099-01-01"));
    }
}
