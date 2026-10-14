use super::super::{BrowserConfig, proxy::BrowserProxy};
use crate::EgressAllowPolicy;
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

async fn request(proxy: std::net::SocketAddr, url: &str) -> Vec<u8> {
    let mut socket = TcpStream::connect(proxy).await.unwrap();
    let request = format!(
        "GET {url} HTTP/1.1\r\nHost: forged.invalid\r\nProxy-Authorization: test-sensitive\r\nConnection: close\r\n\r\n"
    );
    socket.write_all(request.as_bytes()).await.unwrap();
    socket.shutdown().await.unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), socket.read_to_end(&mut response)).await;
    response
}
#[tokio::test]
async fn actual_proxy_origin_policy_idle_and_generation_limits() {
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let requests = Arc::new(AtomicU64::new(0));
    let served = requests.clone();
    let (headers, mut received) = tokio::sync::mpsc::channel(4);
    let worker = tokio::spawn(async move {
        while let Ok((mut socket, _)) = server.accept().await {
            served.fetch_add(1, Ordering::AcqRel);
            let headers = headers.clone();
            tokio::spawn(async move {
                let mut bytes = Vec::new();
                let mut byte = [0u8; 1];
                while !bytes.ends_with(b"\r\n\r\n") {
                    if socket.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    bytes.push(byte[0]);
                }
                let _ = headers.send(String::from_utf8(bytes).unwrap()).await;
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
            });
        }
    });
    let origin = format!("http://{address}/");
    let configuration =
        BrowserConfig::new("http://127.0.0.1:19180/", vec![origin.clone()]).unwrap();
    let policy = Arc::new(OnceLock::new());
    policy.set(None).unwrap();
    let proxy = BrowserProxy::start(configuration.clone(), policy)
        .await
        .unwrap();
    assert!(request(proxy.address, &origin).await.is_empty());
    assert_eq!(requests.load(Ordering::Acquire), 0);
    let lease = proxy.activate().unwrap();
    let response = request(proxy.address, &origin).await;
    assert!(response.ends_with(b"ok"));
    let header = received.recv().await.unwrap();
    assert!(header.contains(&format!("Host: {address}")));
    assert!(!header.contains("forged.invalid"));
    assert!(!header.contains("test-sensitive"));
    assert!(
        request(proxy.address, "http://127.0.0.1:1/")
            .await
            .is_empty()
    );
    assert_eq!(requests.load(Ordering::Acquire), 1);
    drop(lease);
    assert!(request(proxy.address, &origin).await.is_empty());
    assert_eq!(requests.load(Ordering::Acquire), 1);
    let denied = Arc::new(OnceLock::new());
    denied
        .set(Some(EgressAllowPolicy::new(Vec::<String>::new()).unwrap()))
        .unwrap();
    let denied = BrowserProxy::start(configuration, denied).await.unwrap();
    let _lease = denied.activate().unwrap();
    assert!(request(denied.address, &origin).await.is_empty());
    assert_eq!(requests.load(Ordering::Acquire), 1);
    worker.abort();
}

#[tokio::test]
async fn old_live_tunnel_is_closed_and_cannot_resume_on_new_admitted_action() {
    let remote = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = remote.local_addr().unwrap();
    let config = BrowserConfig::new(
        "http://127.0.0.1:19180/",
        vec![format!("https://{address}/")],
    )
    .unwrap();
    let policy = Arc::new(OnceLock::new());
    policy.set(None).unwrap();
    let proxy = BrowserProxy::start(config, policy).await.unwrap();
    let lease = proxy.activate().unwrap();
    let mut client = TcpStream::connect(proxy.address).await.unwrap();
    client
        .write_all(format!("CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let (mut server, _) = remote.accept().await.unwrap();
    let mut ready = [0u8; 39];
    client.read_exact(&mut ready).await.unwrap();
    assert_eq!(&ready, b"HTTP/1.1 200 Connection Established\r\n\r\n");
    client.write_all(b"first").await.unwrap();
    let mut first = [0u8; 5];
    server.read_exact(&mut first).await.unwrap();
    assert_eq!(&first, b"first");
    drop(lease);
    let _new = proxy.activate().unwrap();
    let mut tail = [0u8; 8];
    let count = tokio::time::timeout(Duration::from_secs(2), server.read(&mut tail))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        count, 0,
        "old generation tunnel survived into a new admitted action"
    );
}
