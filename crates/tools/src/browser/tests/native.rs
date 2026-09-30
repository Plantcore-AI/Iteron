//! Explicit native final gate. This must run against a real operator-started ChromeDriver;
//! the ordinary transport fault fixtures do not prove native browser behavior.
use super::{Root, call, content, successful};
use crate::{
    Registry,
    browser::{BrowserConfig, register},
};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

#[tokio::test]
#[ignore = "final native gate requires ITERON_TEST_WEBDRIVER_ENDPOINT with a real isolated ChromeDriver"]
async fn actual_native_controlled_page_png_pointer_key_and_post() {
    let endpoint=std::env::var("ITERON_TEST_WEBDRIVER_ENDPOINT").expect("set explicit real ChromeDriver endpoint; never replace native proof with the transport fixture");
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}/", server.local_addr().unwrap());
    let posts = Arc::new(AtomicU64::new(0));
    let counted = posts.clone();
    let (posted, mut body) = tokio::sync::mpsc::channel(4);
    let worker = tokio::spawn(async move {
        while let Ok((mut socket, _)) = server.accept().await {
            let counted = counted.clone();
            let posted = posted.clone();
            tokio::spawn(async move {
                let mut bytes = Vec::new();
                let mut byte = [0u8; 1];
                while !bytes.ends_with(b"\r\n\r\n") {
                    if bytes.len() > 16 * 1024 || socket.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    bytes.push(byte[0]);
                }
                let header = String::from_utf8(bytes).unwrap();
                let is_post = header.starts_with("POST /publish ");
                let length = header
                    .lines()
                    .find_map(|line| {
                        line.split_once(':')
                            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                            .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if length > 8192 {
                    return;
                }
                let mut bytes = vec![0; length];
                if socket.read_exact(&mut bytes).await.is_err() {
                    return;
                }
                let page = if is_post {
                    counted.fetch_add(1, Ordering::AcqRel);
                    let _ = posted.send(bytes).await;
                    "<!doctype html><html><body><h1>Published once</h1></body></html>"
                } else {
                    "<!doctype html><html><body><form method='post' action='/publish'><input id='message' name='message'><button id='publish' type='submit'>Publish</button></form><button style='position:fixed;left:8px;top:80px;width:120px;height:40px' onclick=\"document.getElementById('marker').textContent='pointer received'\">Pointer</button><p id='marker'></p></body></html>"
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}",
                    page.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    let root = Root::new();
    let mut registry = Registry::coding_agent(&root.0).unwrap();
    registry.install_egress_allow_policy(None).unwrap();
    register(
        &mut registry,
        BrowserConfig::new(&endpoint, vec![origin.clone()]).unwrap(),
    )
    .unwrap();
    let opened = registry
        .run_effect_captured(call("browser", json!({"action":"open","url":origin})))
        .await;
    successful(&opened);
    let mut page = content(&opened);
    assert!(page["html_preview"].as_str().unwrap().contains("Publish"));
    assert_eq!(posts.load(Ordering::Acquire), 0);
    let screenshot = registry
        .run_effect_captured(call(
            "computer",
            json!({"action":"screenshot","page_ref":page["page_ref"]}),
        ))
        .await;
    successful(&screenshot);
    assert_eq!(screenshot.captured_images.len(), 1);
    assert!(screenshot.captured_images[0].bytes().len() > 256);
    assert!(screenshot.captured_images[0].width() > 100);
    page = content(&screenshot);
    let pointer = registry
        .run_effect_captured(call(
            "computer",
            json!({"action":"pointer","page_ref":page["page_ref"],"x":32,"y":96}),
        ))
        .await;
    successful(&pointer);
    page = content(&pointer);
    assert!(
        page["html_preview"]
            .as_str()
            .unwrap()
            .contains("pointer received")
    );
    let key = registry
        .run_effect_captured(call(
            "computer",
            json!({"action":"key","page_ref":page["page_ref"],"key":"tab"}),
        ))
        .await;
    successful(&key);
    page = content(&key);
    let typed=registry.run_effect_captured(call("browser",json!({"action":"type","page_ref":page["page_ref"],"selector":"#message","text":"controlled native publication"}))).await;
    successful(&typed);
    page = content(&typed);
    assert_eq!(posts.load(Ordering::Acquire), 0);
    let publish = registry
        .run_effect_captured(call(
            "browser",
            json!({"action":"click","page_ref":page["page_ref"],"selector":"#publish"}),
        ))
        .await;
    successful(&publish);
    page = content(&publish);
    let received = tokio::time::timeout(std::time::Duration::from_secs(3), body.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        String::from_utf8(received)
            .unwrap()
            .contains("controlled+native+publication")
    );
    assert_eq!(posts.load(Ordering::Acquire), 1);
    let close = registry
        .run_effect_captured(call(
            "browser",
            json!({"action":"close","page_ref":page["close_ref"]}),
        ))
        .await;
    successful(&close);
    worker.abort();
}
