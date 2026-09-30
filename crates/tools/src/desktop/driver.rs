//! Native driver requests retain transport uncertainty and a bounded physical response.
use super::types::DesktopConfig;
use futures_util::StreamExt as _;
use reqwest::{Client, Method};
use serde_json::{Value, json};
use std::time::Duration;
pub(super) struct Driver {
    client: Client,
    endpoint: url::Url,
}
impl Driver {
    pub(super) fn new(config: &DesktopConfig) -> Result<Self, &'static str> {
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(180))
            .build()
            .map_err(|_| "desktop_http_unavailable")?;
        Ok(Self {
            client,
            endpoint: config.endpoint.clone(),
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
            .endpoint
            .join(path)
            .map_err(|_| "desktop_driver_route_invalid")?;
        if url.origin() != self.endpoint.origin() {
            return Err("desktop_driver_route_invalid");
        }
        let mut request = self.client.request(method, url);
        if path != "session" {
            request = request.timeout(Duration::from_secs(10));
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        *issued = true;
        let response = request
            .send()
            .await
            .map_err(|_| "desktop_driver_outcome_unknown")?;
        if !response.status().is_success() {
            return Err("desktop_driver_outcome_unknown");
        }
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| "desktop_driver_reply_unknown")?;
            if bytes.len().saturating_add(chunk.len()) > 12 * 1024 * 1024 {
                return Err("desktop_driver_reply_exceeds_bound");
            }
            bytes.extend_from_slice(&chunk);
        }
        let envelope: Value =
            serde_json::from_slice(&bytes).map_err(|_| "desktop_driver_reply_invalid")?;
        let value = envelope
            .get("value")
            .ok_or("desktop_driver_reply_invalid")?;
        if value.get("error").is_some() {
            return Err("desktop_driver_outcome_unknown");
        }
        *issued = false;
        Ok(value.clone())
    }
    pub(super) async fn native(
        &self,
        session: &str,
        method: &str,
        args: Value,
        issued: &mut bool,
    ) -> Result<Value, &'static str> {
        self.request(
            Method::POST,
            &format!("session/{session}/execute/sync"),
            Some(json!({"script":method,"args":[args]})),
            issued,
        )
        .await
    }
}
pub(super) fn identifier(raw: &str) -> Result<&str, &'static str> {
    if raw.is_empty()
        || raw.len() > 200
        || !raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        Err("desktop_driver_identity_invalid")
    } else {
        Ok(raw)
    }
}
