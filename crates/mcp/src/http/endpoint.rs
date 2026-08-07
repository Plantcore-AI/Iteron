//! The typed configuration surface: what an MCP HTTP endpoint is allowed to be.
//!
//! Every rule here is a refusal at parse time rather than a check at dispatch time, because the
//! whole value of a typed endpoint is that a constructed [`McpHttpEndpoint`] needs no further
//! validation anywhere downstream. A string that reaches the request builder has already been
//! decided.

use crate::McpError;
use std::collections::BTreeSet;

pub const MAX_MCP_HTTP_URL_BYTES: usize = 2048;
pub const MAX_MCP_HTTP_HOST_BYTES: usize = 255;
pub const MAX_MCP_HTTP_PATH_BYTES: usize = 1024;
pub const MAX_MCP_HTTP_HEADERS: usize = 32;
pub const MAX_MCP_HTTP_HEADER_NAME_BYTES: usize = 64;

/// Header names operator configuration may never supply.
///
/// The first four would let operator text overwrite the credential, the session identity, or the
/// framing contract the response reader depends on. The rest are hop-by-hop or connection-control
/// headers that belong to whichever client eventually implements
/// [`super::McpHttpExchange`] — a transport that lets configuration set `transfer-encoding` has
/// handed request smuggling to whoever can edit a config file.
pub const RESERVED_HEADER_NAMES: &[&str] = &[
    "authorization",
    "mcp-session-id",
    "mcp-protocol-version",
    "content-type",
    "accept",
    "content-length",
    "host",
    "connection",
    "transfer-encoding",
    "upgrade",
    "te",
    "trailer",
    "proxy-authorization",
    "cookie",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpHttpScheme {
    Https,
    /// Plaintext. Admissible only to a loopback host — see [`McpHttpEndpoint::parse`].
    Http,
}

impl McpHttpScheme {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Https => "https",
            Self::Http => "http",
        }
    }

    const fn default_port(self) -> u16 {
        match self {
            Self::Https => 443,
            Self::Http => 80,
        }
    }
}

/// A validated MCP HTTP endpoint.
///
/// Implements neither `Debug` nor `Display`, for the same reason [`crate::token::Token`] does not:
/// a path or query string is frequently the credential itself (a per-tenant webhook path, a signed
/// URL, a session-bearing path). [`Self::public_origin`] is what diagnostics get — scheme, host,
/// and port, which an operator needs to resolve a misconfiguration and which carry no secret.
#[derive(Clone, PartialEq, Eq)]
pub struct McpHttpEndpoint {
    scheme: McpHttpScheme,
    /// Lowercased. IPv6 literals retain their brackets, so this is directly usable as an authority.
    host: String,
    port: u16,
    /// Always begins with `/`, and includes any query string.
    path: String,
}

impl McpHttpEndpoint {
    /// Parse an absolute `http`/`https` URL under the endpoint rules.
    ///
    /// Refused, each for a reason that is silent if it is merely discouraged:
    /// - a non-loopback `http://` URL — a bearer token on a plaintext hop still works, which is
    ///   why the leak is never noticed,
    /// - userinfo (`https://user:pass@host/`) — a secret in configuration and in every echo of it,
    /// - a fragment — it is never sent, so accepting one silently drops operator intent,
    /// - non-ASCII — an internationalised host must be punycode before it reaches here, because
    ///   two visually identical hosts must not be two different authorities,
    /// - anything over the byte ceilings.
    pub fn parse(url: &str) -> Result<Self, McpError> {
        if url.is_empty() || url.len() > MAX_MCP_HTTP_URL_BYTES {
            return Err(invalid("url", MAX_MCP_HTTP_URL_BYTES));
        }
        if !url.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(invalid("url_charset", MAX_MCP_HTTP_URL_BYTES));
        }
        let (scheme, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (McpHttpScheme::Https, rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            (McpHttpScheme::Http, rest)
        } else {
            return Err(invalid("scheme", 0));
        };
        if rest.contains('#') {
            return Err(invalid("fragment", 0));
        }

        let (authority, raw_path) = match rest.find(['/', '?']) {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, "/"),
        };
        if authority.contains('@') {
            return Err(invalid("userinfo", 0));
        }
        let (host, port) = parse_authority(authority, scheme)?;

        // A URL may legally jump straight from authority to query (`https://h?q=1`); the request
        // target still has to be origin-form, so the empty path is restored here rather than left
        // for whichever client eventually builds the request.
        let path = if raw_path.starts_with('?') {
            format!("/{raw_path}")
        } else {
            raw_path.to_owned()
        };
        if path.len() > MAX_MCP_HTTP_PATH_BYTES {
            return Err(invalid("path", MAX_MCP_HTTP_PATH_BYTES));
        }

        if scheme == McpHttpScheme::Http && !is_loopback_host(&host) {
            return Err(invalid("plaintext_non_loopback", 0));
        }
        Ok(Self {
            scheme,
            host,
            port,
            path,
        })
    }

    pub fn scheme(&self) -> McpHttpScheme {
        self.scheme
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// `scheme://host:port` — the authority, always with an explicit port so two spellings of the
    /// same endpoint compare equal. Safe to log: it contains no path, query, or credential.
    pub fn public_origin(&self) -> String {
        format!("{}://{}:{}", self.scheme.as_str(), self.host, self.port)
    }

    /// The full request URL. Reachable only through a named method, never through a formatter.
    pub fn expose_url(&self) -> String {
        format!("{}{}", self.public_origin(), self.path)
    }

    /// Whether another endpoint is the same authority. This is what a redirect check would need if
    /// following one were ever admitted; today it is what proves the refusal is about authority.
    pub fn same_origin(&self, other: &Self) -> bool {
        self.scheme == other.scheme && self.host == other.host && self.port == other.port
    }
}

fn parse_authority(authority: &str, scheme: McpHttpScheme) -> Result<(String, u16), McpError> {
    if authority.is_empty() || authority.len() > MAX_MCP_HTTP_HOST_BYTES {
        return Err(invalid("host", MAX_MCP_HTTP_HOST_BYTES));
    }
    if let Some(after_bracket) = authority.strip_prefix('[') {
        let (inside, remainder) = after_bracket
            .split_once(']')
            .ok_or_else(|| invalid("ipv6_host", MAX_MCP_HTTP_HOST_BYTES))?;
        if inside.is_empty()
            || !inside
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b':' || byte == b'.')
        {
            return Err(invalid("ipv6_host", MAX_MCP_HTTP_HOST_BYTES));
        }
        let host = format!("[{}]", inside.to_ascii_lowercase());
        return Ok((host, parse_port_suffix(remainder, scheme)?));
    }
    let (host, port_suffix) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    let host = host.to_ascii_lowercase();
    validate_registered_host(&host)?;
    let port = match port_suffix {
        Some(port) => parse_port(port)?,
        None => scheme.default_port(),
    };
    Ok((host, port))
}

fn parse_port_suffix(remainder: &str, scheme: McpHttpScheme) -> Result<u16, McpError> {
    match remainder.strip_prefix(':') {
        Some(port) => parse_port(port),
        None if remainder.is_empty() => Ok(scheme.default_port()),
        None => Err(invalid("port", u16::MAX as usize)),
    }
}

fn parse_port(port: &str) -> Result<u16, McpError> {
    // Rejecting a leading zero as well as an out-of-range value keeps one port one spelling, so
    // `:0443` and `:443` cannot become two endpoints that are the same authority.
    if port.is_empty()
        || port.len() > 5
        || !port.bytes().all(|byte| byte.is_ascii_digit())
        || (port.len() > 1 && port.starts_with('0'))
    {
        return Err(invalid("port", u16::MAX as usize));
    }
    match port.parse::<u16>() {
        Ok(0) | Err(_) => Err(invalid("port", u16::MAX as usize)),
        Ok(port) => Ok(port),
    }
}

fn validate_registered_host(host: &str) -> Result<(), McpError> {
    if host.is_empty()
        || host.len() > MAX_MCP_HTTP_HOST_BYTES
        || host.starts_with('.')
        || host.ends_with('.')
        || host.contains("..")
    {
        return Err(invalid("host", MAX_MCP_HTTP_HOST_BYTES));
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(invalid("host", MAX_MCP_HTTP_HOST_BYTES));
        }
    }
    Ok(())
}

/// Loopback by literal, not by resolution. A name that merely *resolves* to `127.0.0.1` today is
/// not a loopback guarantee: DNS is attacker-influenceable and the answer can change between the
/// check and the connection, so only spellings that cannot leave the host are admitted.
fn is_loopback_host(host: &str) -> bool {
    if host == "localhost" || host == "[::1]" || host == "[0:0:0:0:0:0:0:1]" {
        return true;
    }
    let Some(rest) = host.strip_prefix("127.") else {
        return false;
    };
    let octets: Vec<&str> = rest.split('.').collect();
    octets.len() == 3
        && octets
            .iter()
            .all(|octet| !octet.is_empty() && octet.len() <= 3 && octet.parse::<u8>().is_ok())
}

/// Additional request headers, by name only.
///
/// The same shape as `McpLaunchConfig::with_sensitive_env_names`: configuration names a credential,
/// it never contains one. The value is resolved from the process environment at dispatch, so a
/// header value can neither be committed to a repository nor read back out of the config file.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct McpHttpHeaderPolicy {
    names: Vec<String>,
}

impl McpHttpHeaderPolicy {
    pub fn new(names: Vec<String>) -> Result<Self, McpError> {
        if names.len() > MAX_MCP_HTTP_HEADERS {
            return Err(invalid("headers", MAX_MCP_HTTP_HEADERS));
        }
        let mut seen = BTreeSet::new();
        for name in &names {
            validate_header_name(name)?;
            if !seen.insert(name.as_str()) {
                return Err(invalid("header_name", MAX_MCP_HTTP_HEADER_NAME_BYTES));
            }
        }
        Ok(Self { names })
    }

    pub fn names(&self) -> &[String] {
        &self.names
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

/// A header name usable in operator configuration: lowercase, bounded, and not reserved.
///
/// Lowercase is required rather than normalised. HTTP field names are case-insensitive, so
/// accepting `Authorization` and lowercasing it would make the reserved-name check depend on
/// normalisation order; requiring the canonical spelling makes the check total.
pub fn validate_header_name(name: &str) -> Result<(), McpError> {
    if name.is_empty()
        || name.len() > MAX_MCP_HTTP_HEADER_NAME_BYTES
        || !name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
        || RESERVED_HEADER_NAMES.contains(&name)
    {
        return Err(invalid("header_name", MAX_MCP_HTTP_HEADER_NAME_BYTES));
    }
    Ok(())
}

fn invalid(field: &'static str, limit: usize) -> McpError {
    McpError::InvalidEndpoint { field, limit }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ordinary_https_endpoint_normalises_to_an_explicit_authority() {
        let endpoint = McpHttpEndpoint::parse("https://Example.COM/mcp?v=1").unwrap();
        assert_eq!(endpoint.scheme(), McpHttpScheme::Https);
        assert_eq!(endpoint.host(), "example.com");
        assert_eq!(endpoint.port(), 443);
        assert_eq!(endpoint.path(), "/mcp?v=1");
        assert_eq!(endpoint.public_origin(), "https://example.com:443");
        assert_eq!(endpoint.expose_url(), "https://example.com:443/mcp?v=1");
    }

    #[test]
    fn a_bare_authority_and_a_query_only_url_both_get_an_origin_form_path() {
        assert_eq!(
            McpHttpEndpoint::parse("https://example.com")
                .unwrap()
                .path(),
            "/"
        );
        // Without this, the request target would be `?q=1`, which is not a legal origin-form
        // target and which every client would render differently.
        assert_eq!(
            McpHttpEndpoint::parse("https://example.com?q=1")
                .unwrap()
                .path(),
            "/?q=1"
        );
    }

    #[test]
    fn plaintext_is_admissible_to_loopback_and_refused_everywhere_else() {
        // The failure this prevents: a bearer credential on a plaintext hop. It works perfectly,
        // so the leak produces no symptom at all.
        for loopback in [
            "http://localhost:3000/mcp",
            "http://127.0.0.1:8080/",
            "http://127.13.0.9/",
            "http://[::1]:9000/mcp",
        ] {
            assert!(
                McpHttpEndpoint::parse(loopback).is_ok(),
                "loopback must remain usable: {loopback}"
            );
        }
        for remote in [
            "http://example.com/mcp",
            "http://10.0.0.5/mcp",
            // Not loopback by resolution: only spellings that cannot leave the host qualify.
            "http://localhost.attacker.example/mcp",
            "http://127.0.0.1.attacker.example/mcp",
            "http://[2001:db8::1]/mcp",
        ] {
            assert!(
                matches!(
                    McpHttpEndpoint::parse(remote),
                    Err(McpError::InvalidEndpoint { .. })
                ),
                "plaintext must be refused off-host: {remote}"
            );
        }
    }

    #[test]
    fn a_url_can_never_be_the_place_a_credential_lives() {
        // Most URL parsers accept userinfo happily, which would put a secret into a config file,
        // into `Debug`, and into every diagnostic that echoes the endpoint.
        for url in [
            "https://user:password@example.com/mcp",
            "https://token@example.com/mcp",
        ] {
            assert!(matches!(
                McpHttpEndpoint::parse(url),
                Err(McpError::InvalidEndpoint {
                    field: "userinfo",
                    ..
                })
            ));
        }
    }

    #[test]
    fn structurally_unusable_urls_are_typed_refusals() {
        for (url, reason) in [
            ("", "empty"),
            ("example.com/mcp", "no scheme"),
            ("ftp://example.com/", "wrong scheme"),
            ("ws://example.com/", "wrong scheme"),
            ("https://example.com/mcp#frag", "fragment is never sent"),
            ("https:///mcp", "no host"),
            ("https://exa mple.com/", "space"),
            ("https://exämple.com/", "non-ASCII must be punycode first"),
            ("https://example.com:0/", "port zero"),
            ("https://example.com:99999/", "port overflow"),
            ("https://example.com:0443/", "one port, one spelling"),
            ("https://example.com:/", "empty port"),
            ("https://example.com:x/", "non-numeric port"),
            ("https://-example.com/", "leading hyphen label"),
            ("https://example..com/", "empty label"),
            ("https://[::1/", "unterminated IPv6 literal"),
            ("https://[zz::1]/", "non-hex IPv6 literal"),
        ] {
            assert!(
                matches!(
                    McpHttpEndpoint::parse(url),
                    Err(McpError::InvalidEndpoint { .. })
                ),
                "must refuse ({reason}): {url}"
            );
        }
        let oversized = format!("https://example.com/{}", "p".repeat(MAX_MCP_HTTP_URL_BYTES));
        assert!(McpHttpEndpoint::parse(&oversized).is_err());
    }

    #[test]
    fn an_endpoint_is_not_printable_and_its_origin_carries_no_path() {
        // `McpHttpEndpoint` implements neither Debug nor Display; a path is frequently the
        // credential (a signed URL, a per-tenant webhook path). If someone derives Debug on it
        // later, this test's premise is the reason not to.
        let endpoint = McpHttpEndpoint::parse("https://example.com/hooks/s3cr3t-path").unwrap();
        assert!(!endpoint.public_origin().contains("s3cr3t"));
        assert!(endpoint.expose_url().contains("s3cr3t"));
    }

    #[test]
    fn same_origin_compares_authority_and_ignores_path() {
        let first = McpHttpEndpoint::parse("https://example.com/a").unwrap();
        let second = McpHttpEndpoint::parse("https://example.com:443/b?q=1").unwrap();
        let other_port = McpHttpEndpoint::parse("https://example.com:8443/a").unwrap();
        let other_host = McpHttpEndpoint::parse("https://evil.example/a").unwrap();
        assert!(first.same_origin(&second));
        assert!(!first.same_origin(&other_port));
        assert!(!first.same_origin(&other_host));
    }

    #[test]
    fn configuration_cannot_name_a_header_that_would_overwrite_the_credential_or_the_framing() {
        for reserved in RESERVED_HEADER_NAMES {
            assert!(
                validate_header_name(reserved).is_err(),
                "reserved header must be refused: {reserved}"
            );
        }
        // Case is required, not normalised: otherwise the reserved check depends on when
        // normalisation ran relative to it.
        assert!(validate_header_name("Authorization").is_err());
        assert!(validate_header_name("x-tenant").is_ok());
        assert!(validate_header_name("x_tenant-2").is_ok());
        assert!(validate_header_name("x tenant").is_err());
        assert!(validate_header_name("x-tenant\r\nauthorization").is_err());
        assert!(validate_header_name("").is_err());
        assert!(validate_header_name(&"x".repeat(MAX_MCP_HTTP_HEADER_NAME_BYTES + 1)).is_err());
    }

    #[test]
    fn a_header_policy_is_bounded_and_duplicate_free() {
        assert!(McpHttpHeaderPolicy::new(vec![]).unwrap().is_empty());
        assert_eq!(
            McpHttpHeaderPolicy::new(vec!["x-a".into(), "x-b".into()])
                .unwrap()
                .names(),
            ["x-a", "x-b"]
        );
        assert!(McpHttpHeaderPolicy::new(vec!["x-a".into(), "x-a".into()]).is_err());
        assert!(
            McpHttpHeaderPolicy::new(vec!["x-a".into(); MAX_MCP_HTTP_HEADERS + 1]).is_err(),
            "the count ceiling is checked before the duplicate scan"
        );
    }
}
