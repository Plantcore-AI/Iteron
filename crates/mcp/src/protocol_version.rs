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
