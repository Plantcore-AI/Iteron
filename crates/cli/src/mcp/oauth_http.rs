//! Network-bound HTTP requests used by MCP OAuth discovery and token exchange.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use reqwest::{Method, RequestBuilder};
use url::{Host, Url};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NetworkZone {
    Public,
    Private,
    Loopback,
}

impl NetworkZone {
    pub(super) fn permits(self, target: Self) -> bool {
        match self {
            Self::Public => target == Self::Public,
            Self::Private => target != Self::Loopback,
            Self::Loopback => true,
        }
    }
}

struct ResolvedTarget {
    domain: Option<String>,
    addresses: Vec<SocketAddr>,
    zone: NetworkZone,
}

pub(super) struct OAuthHttpClient {
    source_zone: NetworkZone,
    connect_timeout: Duration,
    request_timeout: Duration,
}

impl OAuthHttpClient {
    pub(super) async fn new(source: &Url, request_timeout: Duration) -> anyhow::Result<Self> {
        validate_endpoint(source, "resource")?;
        let connect_timeout = Duration::from_secs(10).min(request_timeout);
        let source = resolve_target(source, connect_timeout).await?;
        Ok(Self {
            source_zone: source.zone,
            connect_timeout,
            request_timeout,
        })
    }

    #[cfg(test)]
    pub(super) fn with_source_zone(source_zone: NetworkZone) -> Self {
        Self {
            source_zone,
            connect_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(1),
        }
    }

    pub(super) async fn get(&self, url: &Url, field: &str) -> anyhow::Result<RequestBuilder> {
        self.request(Method::GET, url, field).await
    }

    pub(super) async fn post(&self, url: &Url, field: &str) -> anyhow::Result<RequestBuilder> {
        self.request(Method::POST, url, field).await
    }

    async fn request(
        &self,
        method: Method,
        url: &Url,
        field: &str,
    ) -> anyhow::Result<RequestBuilder> {
        validate_endpoint(url, field)?;
        let target = resolve_target(url, self.connect_timeout).await?;
        if !self.source_zone.permits(target.zone) {
            anyhow::bail!("MCP OAuth {field} crosses into a more privileged network zone");
        }
        let mut client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(self.connect_timeout)
            .timeout(self.request_timeout);
        if let Some(domain) = target.domain {
            client = client.resolve_to_addrs(&domain, &target.addresses);
        }
        Ok(client.build()?.request(method, url.clone()))
    }
}

async fn resolve_target(url: &Url, timeout: Duration) -> anyhow::Result<ResolvedTarget> {
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("MCP OAuth URL has no known port"))?;
    let (domain, addresses) = match url
        .host()
        .ok_or_else(|| anyhow::anyhow!("MCP OAuth URL has no host"))?
    {
        Host::Ipv4(address) => (None, vec![SocketAddr::new(address.into(), port)]),
        Host::Ipv6(address) => (None, vec![SocketAddr::new(address.into(), port)]),
        Host::Domain(domain) => {
            let addresses = tokio::time::timeout(timeout, tokio::net::lookup_host((domain, port)))
                .await
                .map_err(|_| anyhow::anyhow!("MCP OAuth DNS lookup timed out"))??
                .collect::<Vec<_>>();
            (Some(domain.to_owned()), addresses)
        }
    };
    if addresses.is_empty() {
        anyhow::bail!("MCP OAuth DNS lookup returned no addresses");
    }
    let zone = uniform_zone(addresses.iter().map(SocketAddr::ip))?;
    Ok(ResolvedTarget {
        domain,
        addresses,
        zone,
    })
}

fn uniform_zone(addresses: impl IntoIterator<Item = IpAddr>) -> anyhow::Result<NetworkZone> {
    let mut addresses = addresses.into_iter();
    let zone = addresses
        .next()
        .map(classify_ip)
        .ok_or_else(|| anyhow::anyhow!("MCP OAuth DNS lookup returned no addresses"))?;
    if addresses.any(|address| classify_ip(address) != zone) {
        anyhow::bail!("MCP OAuth hostname resolves across network zones");
    }
    Ok(zone)
}

pub(super) fn classify_ip(ip: IpAddr) -> NetworkZone {
    let ip = match ip {
        IpAddr::V6(address) => address.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    };
    if ip.is_loopback() {
        NetworkZone::Loopback
    } else if is_non_public_ip(ip) {
        NetworkZone::Private
    } else {
        NetworkZone::Public
    }
}

fn is_non_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => {
            let octets = address.octets();
            address.is_private()
                || address.is_link_local()
                || address.is_unspecified()
                || address.is_broadcast()
                || address.is_documentation()
                || address.is_multicast()
                || octets[0] == 0
                || octets[0] >= 240
                || (octets[0] == 100 && octets[1] & 0xc0 == 64)
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 198 && matches!(octets[1], 18 | 19))
        }
        IpAddr::V6(address) => {
            let first = address.segments()[0];
            address.is_unspecified()
                || address.is_multicast()
                || first & 0xfe00 == 0xfc00
                || first & 0xffc0 == 0xfe80
                || address
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| is_non_public_ip(IpAddr::V4(mapped)))
        }
    }
}

pub(super) fn validate_endpoint(url: &Url, field: &str) -> anyhow::Result<()> {
    let loopback = url.host().is_some_and(|host| match host {
        Host::Domain(host) => host.eq_ignore_ascii_case("localhost"),
        Host::Ipv4(address) => address.is_loopback(),
        Host::Ipv6(address) => address.is_loopback(),
    });
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        anyhow::bail!("MCP OAuth {field} must use HTTPS or loopback HTTP");
    }
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        anyhow::bail!("MCP OAuth {field} contains forbidden URL components");
    }
    Ok(())
}

#[cfg(test)]
#[path = "oauth_http_tests.rs"]
mod tests;
