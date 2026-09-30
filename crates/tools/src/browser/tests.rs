use super::{BrowserConfig, register};
use crate::{CapturedToolExecution, OperationEffects, Registry, ToolExecution};
use iteron_protocol::{Capability, ToolUse};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

mod native;
mod proxy;

static NEXT: AtomicU64 = AtomicU64::new(1);
struct Root(std::path::PathBuf);
impl Root {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "iteron-browser-core-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        Self(root.canonicalize().unwrap())
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn call(name: &str, input: Value) -> ToolUse {
    ToolUse {
        id: format!("browser-call-{}", NEXT.fetch_add(1, Ordering::Relaxed)),
        name: name.into(),
        input,
    }
}
fn result(captured: &CapturedToolExecution) -> &iteron_protocol::ToolResult {
    match &captured.execution {
        ToolExecution::Definite(result) | ToolExecution::Unknown(result) => result,
    }
}
fn content(captured: &CapturedToolExecution) -> Value {
    serde_json::from_str(&result(captured).content).unwrap()
}
fn successful(captured: &CapturedToolExecution) {
    assert!(
        matches!(&captured.execution,ToolExecution::Definite(result) if !result.is_error),
        "{captured:?}"
    );
}
fn png() -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/l9sAAAAASUVORK5CYII=").unwrap()
}

#[derive(Default)]
struct DriverState {
    url: String,
    source: String,
    requests: Vec<String>,
    actions: u64,
    clicks: u64,
    alive: bool,
    lose_click_reply: bool,
    navigate_after_screenshot: bool,
    proxy: String,
}
struct DriverFixture {
    endpoint: String,
    state: Arc<Mutex<DriverState>>,
    worker: tokio::task::JoinHandle<()>,
}
impl Drop for DriverFixture {
    fn drop(&mut self) {
        self.worker.abort();
    }
}
impl DriverFixture {
    // This is a physical HTTP remote-end fault oracle, not a native browser substitute.
    async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(DriverState {
            source: "<html><input id='text'><button id='post'>post</button></html>".into(),
            ..Default::default()
        }));
        let serving = state.clone();
        let worker = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let serving = serving.clone();
                tokio::spawn(async move {
                    let mut bytes = Vec::new();
                    let mut single = [0u8; 1];
                    while !bytes.ends_with(b"\r\n\r\n") {
                        if bytes.len() > 16 * 1024 || socket.read_exact(&mut single).await.is_err()
                        {
                            return;
                        }
                        bytes.push(single[0]);
                    }
                    let header = String::from_utf8(bytes).unwrap();
                    let first = header.lines().next().unwrap();
                    let parts = first.split_whitespace().collect::<Vec<_>>();
                    let length = header
                        .lines()
                        .find_map(|line| {
                            line.split_once(':')
                                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                                .and_then(|(_, length)| length.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if length > 128 * 1024 {
                        return;
                    }
                    let mut body = vec![0; length];
                    if socket.read_exact(&mut body).await.is_err() {
                        return;
                    }
                    let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                    let mut state = serving.lock().await;
                    state.requests.push(format!("{} {}", parts[0], parts[1]));
                    let value = match (parts[0], parts[1]) {
                        ("POST", "/session") => {
                            state.alive = true;
                            state.proxy = body["capabilities"]["alwaysMatch"]["proxy"]["httpProxy"]
                                .as_str()
                                .unwrap()
                                .into();
                            json!({"sessionId":"driver-private-1","capabilities":{"browserName":"chrome","acceptInsecureCerts":false,"proxy":{"proxyType":"manual","httpProxy":state.proxy,"sslProxy":state.proxy}}})
                        }
                        ("POST", "/session/driver-private-1/url") => {
                            state.url = body["url"].as_str().unwrap().into();
                            Value::Null
                        }
                        ("GET", "/session/driver-private-1/url") => json!(state.url),
                        ("GET", "/session/driver-private-1/source") => json!(state.source),
                        ("POST", "/session/driver-private-1/element") => {
                            json!({"element-6066-11e4-a52e-4f735466cecf":"element-private-1"})
                        }
                        ("POST", "/session/driver-private-1/element/element-private-1/click") => {
                            state.clicks += 1;
                            if state.lose_click_reply {
                                state.lose_click_reply = false;
                                return;
                            }
                            state.source.push_str("<p>clicked</p>");
                            Value::Null
                        }
                        ("POST", "/session/driver-private-1/element/element-private-1/value") => {
                            state.source.push_str(body["text"].as_str().unwrap());
                            Value::Null
                        }
                        ("POST", "/session/driver-private-1/actions") => {
                            state.actions += 1;
                            state.source.push_str("<p>action</p>");
                            Value::Null
                        }
                        ("GET", "/session/driver-private-1/screenshot") => {
                            use base64::Engine as _;
                            if state.navigate_after_screenshot {
                                state.url = "http://not-admitted.invalid/".into();
                            }
                            json!(base64::engine::general_purpose::STANDARD.encode(png()))
                        }
                        ("DELETE", "/session/driver-private-1") => {
                            state.alive = false;
                            Value::Null
                        }
                        _ => panic!("unexpected physical driver request {first}"),
                    };
                    drop(state);
                    let bytes = json!({"value":value}).to_string();
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        bytes.len()
                    );
                    let _ = socket.write_all(header.as_bytes()).await;
                    let _ = socket.write_all(bytes.as_bytes()).await;
                });
            }
        });
        Self {
            endpoint,
            state,
            worker,
        }
    }
}
fn registry(root: &Root, driver: &DriverFixture) -> Registry {
    let mut registry = Registry::coding_agent(&root.0).unwrap();
    registry.install_egress_allow_policy(None).unwrap();
    register(
        &mut registry,
        BrowserConfig::new(&driver.endpoint, vec!["http://127.0.0.1:19181/".into()]).unwrap(),
    )
    .unwrap();
    registry
}
async fn open(registry: &Registry) -> Value {
    let opened = registry
        .run_effect_captured(call(
            "browser",
            json!({"action":"open","url":"http://127.0.0.1:19181/"}),
        ))
        .await;
    successful(&opened);
    content(&opened)
}

#[test]
fn disabled_default_and_every_declared_action_retain_external_authority() {
    let root = Root::new();
    let registry = Registry::coding_agent(&root.0).unwrap();
    assert!(registry.purity_of("browser").is_none());
    assert!(registry.purity_of("computer").is_none());
    for name in ["browser", "computer"] {
        for action in ["observe", "screenshot", "key", "click", "nonsense"] {
            let effect = OperationEffects::classify(
                &call(name, json!({"action":action,"pure":true,"approved":true})),
                Capability::CodeExecuting,
            );
            assert!(effect.required.contains(Capability::CodeExecuting));
            assert!(effect.required.contains(Capability::IrreversibleExternal));
        }
    }
    for endpoint in [
        "https://127.0.0.1:9222/",
        "http://localhost:9222/",
        "http://127.0.0.1:9222/session/",
        "http://user:password@127.0.0.1:9222/",
    ] {
        assert!(BrowserConfig::new(endpoint, vec!["https://example.com/".into()]).is_err());
    }
}

#[tokio::test]
async fn real_http_browser_computer_capture_and_generation_refusal() {
    let root = Root::new();
    let driver = DriverFixture::new().await;
    let registry = registry(&root, &driver);
    let opened = open(&registry).await;
    assert!(opened["html_preview"].as_str().unwrap().contains("<button"));
    assert!(opened["observed_unix_ms"].as_u64().unwrap() > 0);
    assert!(!opened.to_string().contains("driver-private"));
    let screenshot = registry
        .run_effect_captured(call(
            "computer",
            json!({"action":"screenshot","page_ref":opened["page_ref"]}),
        ))
        .await;
    successful(&screenshot);
    assert_eq!(screenshot.captured_images.len(), 1);
    let image = &screenshot.captured_images[0];
    assert_eq!(image.bytes(), png());
    assert_eq!(image.width(), 1);
    assert!(image.observation().unwrap().observed_unix_ms() > 0);
    assert_eq!(
        image.observation().unwrap().source_url(),
        "http://127.0.0.1:19181/"
    );
    assert_eq!(content(&screenshot)["surface"], "computer");
    assert_eq!(
        content(&screenshot)["execution_scope"],
        "isolated_browser_viewport"
    );
    let mut page = content(&screenshot);
    for action in [
        json!({"action":"pointer","page_ref":page["page_ref"],"x":12,"y":12}),
        json!({"action":"key","page_ref":"placeholder","key":"enter"}),
    ] {
        let mut action = action;
        action["page_ref"] = page["page_ref"].clone();
        let output = registry.run_effect_captured(call("computer", action)).await;
        successful(&output);
        page = content(&output);
    }
    assert_eq!(driver.state.lock().await.actions, 2);
    let closed = registry
        .run_effect_captured(call(
            "browser",
            json!({"action":"close","page_ref":page["close_ref"]}),
        ))
        .await;
    successful(&closed);
    let fresh = open(&registry).await;
    assert_ne!(fresh["close_ref"], opened["close_ref"]);
    let before = driver.state.lock().await.requests.len();
    for input in [
        json!({"action":"close","page_ref":opened["close_ref"]}),
        json!({"action":"observe","page_ref":opened["page_ref"]}),
        json!({"action":"observe","page_ref":fresh["page_ref"],"session":"driver-private-1"}),
    ] {
        let refused = registry.run_effect_captured(call("browser", input)).await;
        assert!(matches!(refused.execution,ToolExecution::Definite(ref result) if result.is_error));
    }
    assert_eq!(driver.state.lock().await.requests.len(), before);
}

#[tokio::test]
async fn stale_dom_never_clicks_and_actual_lost_click_is_unknown_not_retried() {
    let root = Root::new();
    let driver = DriverFixture::new().await;
    let registry = registry(&root, &driver);
    let opened = open(&registry).await;
    driver
        .state
        .lock()
        .await
        .source
        .push_str("<p>external DOM change</p>");
    let stale = registry
        .run_effect_captured(call(
            "browser",
            json!({"action":"click","page_ref":opened["page_ref"],"selector":"#post"}),
        ))
        .await;
    assert!(result(&stale).is_error);
    assert_eq!(driver.state.lock().await.clicks, 0);
    let observed = registry
        .run_effect_captured(call(
            "browser",
            json!({"action":"observe","page_ref":opened["page_ref"]}),
        ))
        .await;
    successful(&observed);
    let page = content(&observed);
    driver.state.lock().await.lose_click_reply = true;
    let lost = registry
        .run_effect_captured(call(
            "browser",
            json!({"action":"click","page_ref":page["page_ref"],"selector":"#post"}),
        ))
        .await;
    assert!(matches!(lost.execution, ToolExecution::Unknown(_)));
    assert_eq!(driver.state.lock().await.clicks, 1);
    let lost = content(&lost);
    assert!(lost["owner_reconciliation_required"].as_bool().unwrap());
    let before = driver.state.lock().await.requests.len();
    let retry = registry
        .run_effect_captured(call(
            "computer",
            json!({"action":"key","page_ref":page["page_ref"],"key":"enter"}),
        ))
        .await;
    assert!(result(&retry).is_error);
    assert_eq!(driver.state.lock().await.requests.len(), before);
    assert_eq!(driver.state.lock().await.clicks, 1);
    let closed = registry
        .run_effect_captured(call(
            "browser",
            json!({"action":"close","page_ref":lost["close_ref"]}),
        ))
        .await;
    successful(&closed);
    assert!(!driver.state.lock().await.alive);
}

#[tokio::test]
async fn screenshot_navigation_race_discards_pixels_and_origin_refusal_has_no_driver_io() {
    let root = Root::new();
    let driver = DriverFixture::new().await;
    let registry = registry(&root, &driver);
    let refused = registry
        .run_effect_captured(call(
            "browser",
            json!({"action":"open","url":"https://not-admitted.invalid/"}),
        ))
        .await;
    assert!(result(&refused).is_error);
    assert!(driver.state.lock().await.requests.is_empty());
    let opened = open(&registry).await;
    driver.state.lock().await.navigate_after_screenshot = true;
    let raced = registry
        .run_effect_captured(call(
            "computer",
            json!({"action":"screenshot","page_ref":opened["page_ref"]}),
        ))
        .await;
    assert!(matches!(raced.execution, ToolExecution::Unknown(_)));
    assert!(raced.captured_images.is_empty());
    assert!(raced.captured_outputs.is_empty());
}

#[tokio::test]
async fn oversized_and_nested_inputs_are_refused_before_driver_or_proxy_io() {
    let root = Root::new();
    let driver = DriverFixture::new().await;
    let mut registry = Registry::read_only(&root.0).unwrap();
    register(
        &mut registry,
        BrowserConfig::new(&driver.endpoint, vec!["https://example.com".into()]).unwrap(),
    )
    .unwrap();
    for call in [
        call("browser", json!({"action":"open","url":"x".repeat(2049)})),
        call(
            "browser",
            json!({"action":"open","url":{"nested":["unbounded-value"]}}),
        ),
        call(
            "computer",
            json!({"action":"key","page_ref":"x","key":"x".repeat(33)}),
        ),
        call(
            "computer",
            json!({"action":"pointer","page_ref":"x","x":4097,"y":0}),
        ),
    ] {
        let captured = registry.run_effect_captured(call).await;
        assert!(matches!(captured.execution,ToolExecution::Definite(result) if result.is_error));
    }
    assert!(driver.state.lock().await.requests.is_empty());
}
