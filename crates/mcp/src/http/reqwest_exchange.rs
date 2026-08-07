//! Production HTTP effect adapter for the transport decision core.

use super::{
    McpHttpExchange, McpHttpRequest, McpHttpResponse, McpHttpResponseHead, McpSessionId,
    parse_media_type, parse_retry_after,
};
use crate::{McpError, McpFuture};
use futures_util::TryStreamExt;
use std::io;
use std::time::Duration;
use tokio::io::BufReader;
use tokio_util::io::StreamReader;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(120);

/// The one admitted network edge for MCP streamable HTTP.
///
/// Redirects and automatic retries are disabled at client construction. The body remains a
/// backpressured byte stream, so an SSE response is never collected before the framing ceilings
/// in `sse.rs` inspect it.
#[derive(Clone)]
pub struct ReqwestMcpExchange {
    client: reqwest::Client,
}

impl ReqwestMcpExchange {
    pub fn new() -> Result<Self, McpError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(EXCHANGE_TIMEOUT)
            .pool_max_idle_per_host(2)
            .user_agent(concat!("plantcore-core/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| transport_error("client"))?;
        Ok(Self { client })
    }
}

impl McpHttpExchange for ReqwestMcpExchange {
    fn exchange(&self, request: McpHttpRequest) -> McpFuture<'_, McpHttpResponse> {
        Box::pin(async move {
            let method = reqwest::Method::from_bytes(request.method().as_bytes())
                .map_err(|_| transport_error("method"))?;
            let mut outbound = self.client.request(method, request.expose_url());
            for (name, value) in request.headers() {
                let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| endpoint_error("header_name"))?;
                let value = reqwest::header::HeaderValue::from_str(value.expose())
                    .map_err(|_| endpoint_error("header_value"))?;
                outbound = outbound.header(name, value);
            }
            let response = outbound
                .body(request.body().to_owned())
                .send()
                .await
                .map_err(|_| transport_error("exchange"))?;

            let status = response.status().as_u16();
            let media_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .and_then(parse_media_type);
            let session_id = response
                .headers()
                .get("mcp-session-id")
                .and_then(|value| value.to_str().ok())
                .map(McpSessionId::parse)
                .transpose()?;
            let retry_after_secs = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(parse_retry_after);
            let stream = response
                .bytes_stream()
                .map_err(|_| io::Error::other("MCP HTTP response body closed"));
            let reader = StreamReader::new(stream);
            Ok(McpHttpResponse {
                head: McpHttpResponseHead {
                    status,
                    media_type,
                    session_id,
                    retry_after_secs,
                },
                body: Box::new(BufReader::new(reader)),
            })
        })
    }
}

fn endpoint_error(field: &'static str) -> McpError {
    McpError::InvalidEndpoint { field, limit: 0 }
}

fn transport_error(stage: &'static str) -> McpError {
    McpError::Io(format!("MCP HTTP {stage} failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{McpHttpEndpoint, McpHttpWire, NowSecs};
    use crate::wire::McpWire;
    use serde_json::json;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn server(response: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0_u8; 16 * 1024];
            let read = socket.read(&mut request).await.unwrap();
            assert!(String::from_utf8_lossy(&request[..read]).contains("POST /mcp"));
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        format!("http://{address}/mcp")
    }

    #[tokio::test]
    async fn production_exchange_reaches_loopback_and_streams_json() {
        let url = server(concat!(
            "HTTP/1.1 200 OK\r\n",
            "content-type: application/json\r\n",
            "content-length: 45\r\n",
            "connection: close\r\n\r\n",
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}"
        ))
        .await;
        let wire = McpHttpWire::new(
            McpHttpEndpoint::parse(&url).unwrap(),
            ReqwestMcpExchange::new().unwrap(),
            Arc::new(|| 0_u64) as NowSecs,
            "loopback".into(),
        )
        .unwrap();
        let result = wire.send_request("ping", json!({})).await.unwrap();
        assert_eq!(result["ok"], true);
    }

    #[tokio::test]
    async fn production_exchange_does_not_follow_redirects() {
        let url = server(concat!(
            "HTTP/1.1 302 Found\r\n",
            "location: https://example.com/stolen\r\n",
            "content-length: 0\r\n",
            "connection: close\r\n\r\n"
        ))
        .await;
        let wire = McpHttpWire::new(
            McpHttpEndpoint::parse(&url).unwrap(),
            ReqwestMcpExchange::new().unwrap(),
            Arc::new(|| 0_u64) as NowSecs,
            "loopback".into(),
        )
        .unwrap();
        assert!(matches!(
            wire.send_request("ping", json!({})).await,
            Err(McpError::HttpRedirectRefused)
        ));
    }
}
