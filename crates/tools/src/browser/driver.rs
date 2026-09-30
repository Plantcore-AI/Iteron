//! Real bounded W3C wire commands; transport uncertainty is never an ordinary empty result.
use super::types::BrowserConfig;
use futures_util::StreamExt as _;
use reqwest::{Client, Method};
use serde_json::Value;
use std::time::Duration;

pub(super) struct Driver {
    client: Client,
    configuration: BrowserConfig,
}
impl Driver {
    pub(super) fn new(configuration: BrowserConfig) -> Result<Self, &'static str> {
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| "browser_http_unavailable")?;
        Ok(Self {
            client,
            configuration,
        })
    }
    pub(super) async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        issued: &mut bool,
    ) -> Result<Value, &'static str> {
        let url = self
            .configuration
            .endpoint
            .join(path)
            .map_err(|_| "browser_driver_route_invalid")?;
        if url.origin() != self.configuration.endpoint.origin() {
            return Err("browser_driver_route_invalid");
        }
        let mut request = self.client.request(method, url);
        if let Some(body) = body {
            request = request.json(&body);
        }
        // This is conservative: connect failure can be no-dispatch, but no guess can hide a
        // driver command that reached the remote actor before its reply was lost.
        *issued = true;
        let response = request
            .send()
            .await
            .map_err(|_| "browser_driver_outcome_unknown")?;
        if !response.status().is_success() {
            return Err("browser_driver_outcome_unknown");
        }
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| "browser_driver_reply_unknown")?;
            if bytes.len().saturating_add(chunk.len()) > 12 * 1024 * 1024 {
                return Err("browser_driver_reply_exceeds_bound");
            }
            bytes.extend_from_slice(&chunk);
        }
        let envelope: Value =
            serde_json::from_slice(&bytes).map_err(|_| "browser_driver_reply_invalid")?;
        let value = envelope
            .get("value")
            .ok_or("browser_driver_reply_invalid")?;
        if value.get("error").is_some() {
            return Err("browser_driver_outcome_unknown");
        }
        Ok(value.clone())
    }
}
pub(super) fn driver_id(raw: &str) -> Result<&str, &'static str> {
    if raw.is_empty()
        || raw.len() > 200
        || !raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        Err("browser_driver_identity_invalid")
    } else {
        Ok(raw)
    }
}
