//! Bounded parsing for the Bearer challenge fields MCP uses.

const MAX_CHALLENGE_BYTES: usize = 8 * 1024;
const MAX_SCOPE_COUNT: usize = 64;
const MAX_SCOPE_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpBearerChallenge {
    pub error: Option<String>,
    pub resource: Option<String>,
    pub resource_metadata: Option<String>,
    pub scopes: Vec<String>,
}

pub fn parse_bearer_challenge(value: &str) -> Option<McpBearerChallenge> {
    if value.is_empty()
        || value.len() > MAX_CHALLENGE_BYTES
        || value
            .bytes()
            .any(|byte| byte != b'\t' && !(0x20..=0x7e).contains(&byte))
    {
        return None;
    }
    let mut bearer = false;
    let mut error = None;
    let mut resource = None;
    let mut resource_metadata = None;
    let mut scope = None;
    for part in split_quoted(value)? {
        let part = part.trim();
        if part.is_empty() {
            return None;
        }
        let (candidate, parameter) = match part.split_once(char::is_whitespace) {
            Some((candidate, rest)) if !candidate.contains('=') => {
                bearer = candidate.eq_ignore_ascii_case("bearer");
                (candidate, rest.trim())
            }
            _ => ("", part),
        };
        if !candidate.is_empty() && !bearer {
            continue;
        }
        if !bearer {
            continue;
        }
        let (name, raw) = parameter.split_once('=')?;
        let name = name.trim().to_ascii_lowercase();
        let decoded = decode_value(raw.trim())?;
        let slot = match name.as_str() {
            "error" => &mut error,
            "resource" => &mut resource,
            "resource_metadata" => &mut resource_metadata,
            "scope" => &mut scope,
            _ => continue,
        };
        if slot.replace(decoded).is_some() {
            return None;
        }
    }
    if error.is_none() && resource.is_none() && resource_metadata.is_none() && scope.is_none() {
        return None;
    }
    let scopes = scope.map_or_else(|| Some(Vec::new()), |value| parse_scopes(&value))?;
    Some(McpBearerChallenge {
        error,
        resource,
        resource_metadata,
        scopes,
    })
}

fn split_quoted(value: &str) -> Option<Vec<String>> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        match character {
            '\\' if quoted => {
                current.push(character);
                escaped = true;
            }
            '"' => {
                quoted = !quoted;
                current.push(character);
            }
            ',' if !quoted => parts.push(std::mem::take(&mut current)),
            _ => current.push(character),
        }
    }
    if quoted || escaped {
        return None;
    }
    parts.push(current);
    Some(parts)
}

fn decode_value(value: &str) -> Option<String> {
    if let Some(inner) = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    {
        let mut decoded = String::with_capacity(inner.len());
        let mut escaped = false;
        for character in inner.chars() {
            if escaped {
                if !matches!(character, '"' | '\\') {
                    return None;
                }
                decoded.push(character);
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                return None;
            } else {
                decoded.push(character);
            }
        }
        (!escaped).then_some(decoded)
    } else if !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b',' | b'"' | b'='))
    {
        Some(value.to_owned())
    } else {
        None
    }
}

fn parse_scopes(value: &str) -> Option<Vec<String>> {
    if value.is_empty() || value.len() > MAX_SCOPE_BYTES {
        return None;
    }
    let scopes = value.split(' ').map(str::to_owned).collect::<Vec<_>>();
    if scopes.len() > MAX_SCOPE_COUNT
        || scopes.iter().any(|scope| {
            scope.is_empty()
                || scope.len() > 256
                || scope
                    .bytes()
                    .any(|byte| !byte.is_ascii_graphic() || matches!(byte, b',' | b'"' | b'='))
        })
    {
        return None;
    }
    Some(scopes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_mcp_fields_from_mixed_challenges() {
        let challenge = parse_bearer_challenge(
            r#"Basic realm="ignored", Bearer error="insufficient_scope", error_description="scope=admin, not \"root\"", scope="files:read files:write", resource="https://mcp.example", resource_metadata="https://mcp.example/.well-known/resource""#,
        )
        .unwrap();
        assert_eq!(challenge.error.as_deref(), Some("insufficient_scope"));
        assert_eq!(challenge.resource.as_deref(), Some("https://mcp.example"));
        assert_eq!(challenge.scopes, ["files:read", "files:write"]);
        assert_eq!(
            challenge.resource_metadata.as_deref(),
            Some("https://mcp.example/.well-known/resource")
        );
    }

    #[test]
    fn malformed_and_ambiguous_challenges_fail_closed() {
        for value in [
            r#"Bearer error="insufficient_scope", scope="read  write""#,
            r#"Bearer error="insufficient_scope", scope="read", scope="write""#,
            r#"Bearer error="insufficient_scope", scope="read\write""#,
            "Bearer error=insufficient_scope\n",
        ] {
            assert!(parse_bearer_challenge(value).is_none(), "{value}");
        }
    }
}
