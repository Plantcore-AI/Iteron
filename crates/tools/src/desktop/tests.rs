//! Physical HTTP fault oracle. This proves wire/ownership behavior, not native OS support.
use super::{DesktopConfig, register};
use crate::{CapturedToolExecution, OperationEffects, Registry, ToolExecution};
use iteron_protocol::{Capability, ToolUse, tool_image::ToolImageScopeV1};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
const PNG: &str =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/l9sAAAAASUVORK5CYII=";
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Workspace(std::path::PathBuf);
impl Workspace {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "iteron-desktop-fixture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn call(input: Value) -> ToolUse {
    ToolUse {
        id: format!("native-{}", NEXT.fetch_add(1, Ordering::Relaxed)),
        name: "desktop".into(),
        input,
    }
}
fn result(output: &CapturedToolExecution) -> &iteron_protocol::ToolResult {
    match &output.execution {
        ToolExecution::Definite(value) | ToolExecution::Unknown(value) => value,
    }
}
fn content(output: &CapturedToolExecution) -> Value {
    serde_json::from_str(&result(output).content).unwrap()
}
#[derive(Default)]
struct State {
    requests: Vec<Value>,
    clicks: usize,
    lose_click: bool,
    source: String,
}
struct Fixture {
    endpoint: String,
    state: Arc<Mutex<State>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fixture {
    async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(State {
            source: r#"<Application><Button identifier="one"/></Application>"#.into(),
            ..Default::default()
        }));
        let observed = state.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let observed = observed.clone();
                tokio::spawn(async move {
                    let mut headers = Vec::new();
                    let mut byte = [0];
                    while !headers.ends_with(b"\r\n\r\n") {
                        if headers.len() > 16 * 1024 || socket.read_exact(&mut byte).await.is_err()
                        {
                            return;
                        }
                        headers.push(byte[0]);
                    }
                    let headers = String::from_utf8(headers).unwrap();
                    let line = headers.lines().next().unwrap();
                    let parts = line.split_whitespace().collect::<Vec<_>>();
                    let len = headers
                        .lines()
                        .find_map(|line| {
                            line.split_once(':')
                                .filter(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                                .and_then(|(_, v)| v.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if len > 64 * 1024 {
                        return;
                    }
                    let mut bytes = vec![0; len];
                    if socket.read_exact(&mut bytes).await.is_err() {
                        return;
                    }
                    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                    let mut state = observed.lock().await;
                    state.requests.push(body.clone());
                    let value = match (parts[0], parts[1]) {
                        ("POST", "/session") => {
                            json!({"sessionId":"native-session","capabilities":body["capabilities"]["alwaysMatch"]})
                        }
                        ("POST", "/session/native-session/element") => {
                            json!({"element-6066-11e4-a52e-4f735466cecf":"native-element"})
                        }
                        ("DELETE", "/session/native-session") => Value::Null,
                        ("POST", "/session/native-session/execute/sync") => {
                            match body["script"].as_str().unwrap() {
                                "macos: source" => json!(state.source),
                                "macos: listDisplays" => json!({"1":{"id":1,"isMain":true}}),
                                "macos: screenshots" => {
                                    assert_eq!(body["args"][0]["displayId"], 1);
                                    json!([{"id":1,"isMain":true,"payload":PNG}])
                                }
                                "macos: click" => {
                                    state.clicks += 1;
                                    if state.lose_click {
                                        return;
                                    }
                                    Value::Null
                                }
                                "macos: keys" | "macos: scroll" => Value::Null,
                                other => panic!("unexpected native method {other}"),
                            }
                        }
                        _ => panic!("unexpected driver path {line}"),
                    };
                    drop(state);
                    let payload = serde_json::to_vec(&json!({"value":value})).unwrap();
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        payload.len()
                    );
                    let _ = socket.write_all(header.as_bytes()).await;
                    let _ = socket.write_all(&payload).await;
                });
            }
        });
        Self {
            endpoint,
            state,
            task,
        }
    }
    fn registry(&self, workspace: &Workspace) -> Registry {
        let mut registry = Registry::read_only(&workspace.0).unwrap();
        register(
            &mut registry,
            DesktopConfig::new(&self.endpoint, "com.example.NativeFixture").unwrap(),
        )
        .unwrap();
        registry
    }
}
#[tokio::test]
async fn native_registration_is_inert_and_real_png_scope_is_honest() {
    let root = Workspace::new();
    let fixture = Fixture::new().await;
    let registry = fixture.registry(&root);
    assert!(fixture.state.lock().await.requests.is_empty());
    let refused = registry
        .run_effect_captured(call(
            json!({"action":"open","driver":{"url":"http://elsewhere/"}}),
        ))
        .await;
    assert!(result(&refused).is_error);
    assert!(fixture.state.lock().await.requests.is_empty());
    let opened = registry
        .run_effect_captured(call(json!({"action":"open"})))
        .await;
    assert!(!result(&opened).is_error, "{opened:?}");
    assert_eq!(content(&opened)["execution_scope"], "native_mac_desktop");
    assert_eq!(
        content(&opened)["screen_scope"],
        "main_display_including_other_apps"
    );
    let observation = opened.captured_images[0].observation().unwrap();
    assert_eq!(observation.scope(), ToolImageScopeV1::NativeMacDesktop);
    assert_eq!(
        observation.source_url(),
        "macos-application://com.example.NativeFixture"
    );
    let first = fixture.state.lock().await.requests[0].clone();
    assert_eq!(
        first["capabilities"]["alwaysMatch"]["appium:bundleId"],
        "com.example.NativeFixture"
    );
    assert!(
        first["capabilities"]["alwaysMatch"]
            .get("appium:prerun")
            .is_none()
    );
}
#[tokio::test]
async fn lost_native_mutation_is_not_repeated_and_actual_close_settles_owner() {
    let root = Workspace::new();
    let fixture = Fixture::new().await;
    let registry = fixture.registry(&root);
    let opened = registry
        .run_effect_captured(call(json!({"action":"open"})))
        .await;
    let view = content(&opened)["view_ref"].as_str().unwrap().to_owned();
    fixture.state.lock().await.lose_click = true;
    let lost = registry
        .run_effect_captured(call(
            json!({"action":"click","view_ref":view,"selector":"one"}),
        ))
        .await;
    assert!(matches!(lost.execution, ToolExecution::Unknown(_)));
    let close = content(&lost)["close_ref"].as_str().unwrap().to_owned();
    let rejected = registry
        .run_effect_captured(call(
            json!({"action":"click","view_ref":view,"selector":"one"}),
        ))
        .await;
    assert!(result(&rejected).is_error);
    assert_eq!(fixture.state.lock().await.clicks, 1);
    let closed = registry
        .run_effect_captured(call(json!({"action":"close","view_ref":close})))
        .await;
    assert!(!result(&closed).is_error);
    assert_eq!(content(&closed)["closed"], true);
}
#[tokio::test]
async fn changed_native_app_source_requires_observation_before_action() {
    let root = Workspace::new();
    let fixture = Fixture::new().await;
    let registry = fixture.registry(&root);
    let opened = registry
        .run_effect_captured(call(json!({"action":"open"})))
        .await;
    let view = content(&opened)["view_ref"].as_str().unwrap().to_owned();
    fixture.state.lock().await.source = "<Application><Dialog/></Application>".into();
    let rejected = registry
        .run_effect_captured(call(
            json!({"action":"click","view_ref":view,"selector":"one"}),
        ))
        .await;
    assert!(matches!(rejected.execution, ToolExecution::Definite(_)));
    assert!(result(&rejected).is_error);
    assert_eq!(fixture.state.lock().await.clicks, 0);
    let observed = registry
        .run_effect_captured(call(json!({"action":"observe","view_ref":view})))
        .await;
    assert!(!result(&observed).is_error);
    assert_ne!(content(&observed)["view_ref"], view);
}
#[test]
fn native_desktop_requires_all_physical_authority_classes() {
    let effects = OperationEffects::classify(
        &call(json!({"action":"observe","view_ref":"native"})),
        Capability::CodeExecuting,
    );
    for capability in [
        Capability::CodeExecuting,
        Capability::ReversibleLocal,
        Capability::TrustMutating,
        Capability::IrreversibleExternal,
    ] {
        assert!(effects.required.contains(capability));
    }
    for endpoint in [
        "https://127.0.0.1:4723/",
        "http://example.com:4723/",
        "http://localhost:4723/",
        "http://127.0.0.1:4723/session/x",
    ] {
        assert!(DesktopConfig::new(endpoint, "com.example.Fixture").is_err());
    }
}
#[tokio::test]
#[ignore = "requires operator-selected local Appium Mac2 and native OS automation permissions"]
async fn real_native_mac2_main_desktop_observation_and_session_close() {
    let endpoint = std::env::var("ITERON_TEST_MAC2_ENDPOINT").expect("explicit native endpoint");
    let bundle =
        std::env::var("ITERON_TEST_MAC2_BUNDLE").expect("explicit disposable test application");
    let root = Workspace::new();
    let mut registry = Registry::read_only(&root.0).unwrap();
    register(
        &mut registry,
        DesktopConfig::new(&endpoint, &bundle).unwrap(),
    )
    .unwrap();
    let opened = registry
        .run_effect_captured(call(json!({"action":"open"})))
        .await;
    assert!(!result(&opened).is_error, "{opened:?}");
    assert_eq!(
        opened.captured_images[0].observation().unwrap().scope(),
        ToolImageScopeV1::NativeMacDesktop
    );
    let view = content(&opened)["view_ref"].as_str().unwrap().to_owned();
    let closed = registry
        .run_effect_captured(call(json!({"action":"close","view_ref":view})))
        .await;
    assert!(!result(&closed).is_error, "{closed:?}");
}
