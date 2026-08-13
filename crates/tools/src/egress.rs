//! Immutable host admission for first-party network tools.
//!
//! This policy is deliberately narrower than a process sandbox. It governs the network clients
//! owned by `iteron-tools` (`web_fetch` and `web_search`); it never pretends that inspecting an
//! arbitrary shell string can enforce host-level network confinement. A configured empty set
//! denies every first-party destination. An absent policy preserves the explicitly selected
//! legacy/unconfined posture, while a present policy is installed once before the registry can be
//! activated.

use std::collections::BTreeSet;

pub const MAX_EGRESS_HOSTS: usize = 256;
pub const MAX_EGRESS_HOST_BYTES: usize = 253;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressAllowPolicy {
    destinations: BTreeSet<EgressDestination>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct EgressDestination {
    host: String,
    port: Option<u16>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EgressPolicyError {
    #[error("egress allowlist exceeds the {MAX_EGRESS_HOSTS}-destination bound")]
    TooManyDestinations,
    #[error("invalid egress destination `{value}`: {reason}")]
    InvalidDestination { value: String, reason: &'static str },
}

impl EgressAllowPolicy {
    pub fn new(destinations: impl IntoIterator<Item = String>) -> Result<Self, EgressPolicyError> {
        let values = destinations.into_iter().collect::<Vec<_>>();
        if values.len()
            > iteron_tunables::param_usize("tools.egress.max_egress_hosts", MAX_EGRESS_HOSTS)
        {
            return Err(EgressPolicyError::TooManyDestinations);
        }
        let mut admitted = BTreeSet::new();
        for value in values {
            admitted.insert(parse_destination(&value)?);
        }
        Ok(Self {
            destinations: admitted,
        })
    }

    pub fn permits(&self, host: &str, port: Option<u16>) -> bool {
        let host = canonical_runtime_host(host);
        self.destinations.contains(&EgressDestination {
            host: host.clone(),
            port,
        }) || self
            .destinations
            .contains(&EgressDestination { host, port: None })
    }

    pub fn destination_count(&self) -> usize {
        self.destinations.len()
    }
}

fn parse_destination(value: &str) -> Result<EgressDestination, EgressPolicyError> {
    let invalid = |reason| EgressPolicyError::InvalidDestination {
        value: value.to_owned(),
        reason,
    };
    if value.is_empty()
        || value.len()
            > iteron_tunables::param_integer(
                "tools.egress.max_egress_host_bytes",
                MAX_EGRESS_HOST_BYTES,
            )
        || value.trim() != value
    {
        return Err(invalid(
            "expected 1..=253 bytes with no surrounding whitespace",
        ));
    }
    if value.contains("//") || value.contains('/') || value.contains('@') || value.contains('?') {
        return Err(invalid(
            "expected an exact host or host:port, not a URL or path",
        ));
    }
    let (host, port) = match value.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            let port = port
                .parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .ok_or_else(|| invalid("port must be an integer in 1..=65535"))?;
            (host, Some(port))
        }
        Some(_) => return Err(invalid("IPv6 literals are not accepted; use a DNS host")),
        None => (value, None),
    };
    let host = canonical_configured_host(host).ok_or_else(|| {
        invalid("host must be an exact ASCII DNS name or IPv4 address without wildcards")
    })?;
    Ok(EgressDestination { host, port })
}

fn canonical_runtime_host(host: &str) -> String {
    host.strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
        .to_ascii_lowercase()
}

fn canonical_configured_host(host: &str) -> Option<String> {
    if host.is_empty() || host.ends_with('.') || !host.is_ascii() {
        return None;
    }
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return Some(host.to_owned());
    }
    let canonical = host.to_ascii_lowercase();
    if canonical.len()
        > iteron_tunables::param_integer(
            "tools.egress.max_egress_host_bytes",
            MAX_EGRESS_HOST_BYTES,
        )
        || canonical.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return None;
    }
    Some(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_hosts_and_optional_ports_are_distinct() {
        let policy =
            EgressAllowPolicy::new(["EXAMPLE.com".to_owned(), "api.example.net:8443".to_owned()])
                .unwrap();
        assert!(policy.permits("example.com", Some(443)));
        assert!(policy.permits("EXAMPLE.COM", Some(80)));
        assert!(policy.permits("api.example.net", Some(8443)));
        assert!(!policy.permits("api.example.net", Some(443)));
        assert!(!policy.permits("child.example.com", Some(443)));
    }

    #[test]
    fn empty_policy_denies_and_ambiguous_entries_are_refused() {
        assert!(
            !EgressAllowPolicy::new([])
                .unwrap()
                .permits("example.com", Some(443))
        );
        for value in [
            "https://example.com",
            "*.example.com",
            "example.com/",
            " example.com",
            "example.com:0",
            "a..example.com",
        ] {
            assert!(
                EgressAllowPolicy::new([value.to_owned()]).is_err(),
                "{value}"
            );
        }
    }
}
