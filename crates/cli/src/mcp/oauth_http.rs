//! CLI adapter for the shared MCP OAuth network boundary.

use std::time::Duration;

use reqwest::{RequestBuilder, Url};

pub(super) use iteron_mcp::oauth::OAuthNetworkZone as NetworkZone;

pub(super) struct OAuthHttpClient(iteron_mcp::oauth::OAuthHttpClient);

impl OAuthHttpClient {
    pub(super) async fn new(source: &Url, request_timeout: Duration) -> anyhow::Result<Self> {
        Ok(Self(
            iteron_mcp::oauth::OAuthHttpClient::new(source, request_timeout)
                .await
                .map_err(|_| {
                    anyhow::anyhow!("MCP OAuth resource is outside the bounded network policy")
                })?,
        ))
    }

    pub(super) fn with_source_zone(source_zone: NetworkZone) -> Self {
        Self(iteron_mcp::oauth::OAuthHttpClient::with_source_zone(
            source_zone,
            Duration::from_secs(1),
        ))
    }

    pub(super) const fn source_zone(&self) -> NetworkZone {
        self.0.source_zone()
    }

    pub(super) async fn validate_target(&self, url: &Url) -> anyhow::Result<()> {
        self.0.validate_target(url).await.map_err(|_| {
            anyhow::anyhow!(
                "MCP OAuth authorization endpoint is outside the bounded network policy"
            )
        })
    }

    pub(super) async fn get(&self, url: &Url, field: &str) -> anyhow::Result<RequestBuilder> {
        self.0
            .get(url)
            .await
            .map_err(|_| anyhow::anyhow!("MCP OAuth {field} is outside the bounded network policy"))
    }

    pub(super) async fn post(&self, url: &Url, field: &str) -> anyhow::Result<RequestBuilder> {
        self.0
            .post(url)
            .await
            .map_err(|_| anyhow::anyhow!("MCP OAuth {field} is outside the bounded network policy"))
    }
}

pub(super) fn validate_endpoint(url: &Url, field: &str) -> anyhow::Result<()> {
    iteron_mcp::oauth::validate_oauth_endpoint(url)
        .map_err(|_| anyhow::anyhow!("MCP OAuth {field} is outside the bounded network policy"))
}

#[cfg(test)]
#[path = "oauth_http_tests.rs"]
mod tests;
