use iteron_mcp::oauth::{OAuthHttpClient, OAuthNetworkZone};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn oauth_requests_ignore_ambient_proxy_configuration() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_address = target.local_addr().unwrap();
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_url = format!("http://{}", proxy.local_addr().unwrap());

    for name in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        // This integration-test binary contains only this test, so its process environment is not
        // shared with another test thread.
        unsafe { std::env::set_var(name, &proxy_url) };
    }
    for name in ["NO_PROXY", "no_proxy"] {
        unsafe { std::env::remove_var(name) };
    }

    let target_task = tokio::spawn(async move {
        let (mut socket, _) = target.accept().await.unwrap();
        let mut request = [0_u8; 1024];
        let read = socket.read(&mut request).await.unwrap();
        assert!(String::from_utf8_lossy(&request[..read]).starts_with("GET /token "));
        socket
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .await
            .unwrap();
    });

    let client =
        OAuthHttpClient::with_source_zone(OAuthNetworkZone::Loopback, Duration::from_secs(1));
    let response = client
        .get(&format!("http://{target_address}/token").parse().unwrap())
        .await
        .unwrap()
        .send()
        .await
        .unwrap();

    assert!(response.status().is_success());
    target_task.await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), proxy.accept())
            .await
            .is_err(),
        "OAuth request reached the ambient proxy"
    );
}
