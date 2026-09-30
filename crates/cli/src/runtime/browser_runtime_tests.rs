//! Actual registry/HTTP/runtime admission and image journey. The HTTP remote end is an IO oracle;
//! native Chrome execution is a separate explicit platform gate in tools/browser/tests/native.rs.
use super::{Agent, Budget, Outcome, Rollout, UiEvent};
use base64::Engine as _;
use iteron_protocol::{
    Block, Capability, EventKind, PermissionMode, Role, RunId, SessionId, TenantId, ToolUse, Trust,
    Verdict, capability_set::CapabilitySet, client_artifact::ClientArtifactCommandV1,
};
use iteron_provider::{Provider, ProviderError, StreamItem, TurnRequest, TurnResult, UsageReport};
use iteron_tools::{
    Registry, ToolExecution,
    browser::{BrowserConfig, register},
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

const ORIGIN: &str = "http://127.0.0.1:19181/";
const PNG: &str =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/l9sAAAAASUVORK5CYII=";
const IMAGE_SHA: &str = "a38a4ff7320a3d8764ac959b264f15e335360d7c1e23a0627dee7f366c95c58f";
struct Driver {
    endpoint: String,
    requests: Arc<AtomicUsize>,
    html: String,
    worker: tokio::task::JoinHandle<()>,
}
impl Drop for Driver {
    fn drop(&mut self) {
        self.worker.abort();
    }
}
impl Driver {
    async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap());
        let requests = Arc::new(AtomicUsize::new(0));
        let count = requests.clone();
        let html = format!(
            "<html><body>{}<p>tail-actual-full-html</p></body></html>",
            "actual-dom-fixture-".repeat(8192)
        );
        let source = html.clone();
        let worker = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let count = count.clone();
                let source = source.clone();
                tokio::spawn(async move {
                    let transaction = async {
                        let mut header = Vec::new();
                        let mut one = [0u8; 1];
                        while !header.ends_with(b"\r\n\r\n") {
                            if header.len() > 16384 {
                                return;
                            }
                            if socket.read_exact(&mut one).await.is_err() {
                                return;
                            }
                            header.push(one[0]);
                        }
                        let Ok(header) = String::from_utf8(header) else {
                            return;
                        };
                        let parts = header
                            .lines()
                            .next()
                            .unwrap()
                            .split_whitespace()
                            .collect::<Vec<_>>();
                        if parts.len() < 2 {
                            return;
                        }
                        let length = header
                            .lines()
                            .find_map(|line| {
                                line.split_once(':')
                                    .filter(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                                    .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if length > 128 * 1024 {
                            return;
                        }
                        let mut bytes = vec![0u8; length];
                        if socket.read_exact(&mut bytes).await.is_err() {
                            return;
                        }
                        let input: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                        count.fetch_add(1, Ordering::SeqCst);
                        let value = match (parts[0], parts[1]) {
                            ("POST", "/session") => {
                                let proxy =
                                    input["capabilities"]["alwaysMatch"]["proxy"]["httpProxy"]
                                        .clone();
                                json!({"sessionId":"actual-driver-1","capabilities":{"browserName":"chrome","acceptInsecureCerts":false,"proxy":{"proxyType":"manual","httpProxy":proxy,"sslProxy":proxy}}})
                            }
                            ("POST", "/session/actual-driver-1/url") => Value::Null,
                            ("GET", "/session/actual-driver-1/url") => json!(ORIGIN),
                            ("GET", "/session/actual-driver-1/source") => json!(source),
                            ("GET", "/session/actual-driver-1/screenshot") => json!(PNG),
                            ("DELETE", "/session/actual-driver-1") => Value::Null,
                            _ => json!({"error":"unsupported fixture driver action"}),
                        };
                        let body = json!({"value":value}).to_string();
                        let reply = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(reply.as_bytes()).await;
                    };
                    let _ =
                        tokio::time::timeout(std::time::Duration::from_secs(5), transaction).await;
                });
            }
        });
        Self {
            endpoint,
            requests,
            html,
            worker,
        }
    }
    fn registry(&self, workspace: &std::path::Path) -> Registry {
        let mut registry = Registry::read_only(workspace).unwrap();
        registry.install_egress_allow_policy(None).unwrap();
        register(
            &mut registry,
            BrowserConfig::new(&self.endpoint, vec![ORIGIN.into()]).unwrap(),
        )
        .unwrap();
        registry
    }
}
struct Script {
    calls: Vec<ToolUse>,
    second: Option<&'static str>,
    step: AtomicUsize,
    observed: Mutex<Vec<Block>>,
}
#[async_trait::async_trait]
impl Provider for Script {
    async fn turn(
        &self,
        request: &TurnRequest,
        on_item: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        let step = self.step.fetch_add(1, Ordering::SeqCst);
        if step > 0 {
            let mut seen = self.observed.lock().await;
            for block in request.messages.iter().flat_map(|message| &message.content) {
                if matches!(block, Block::ToolImage(_)) {
                    seen.push(block.clone());
                }
            }
        }
        let calls = if step == 0 {
            self.calls.clone()
        } else if step == 1 && self.second.is_some() {
            let result = request
                .messages
                .iter()
                .flat_map(|message| &message.content)
                .find_map(|block| match block {
                    Block::ToolResult(result)
                        if result.tool_use_id == "open-actual" && !result.is_error =>
                    {
                        Some(result)
                    }
                    _ => None,
                })
                .expect("actual open did not produce its tool result");
            let metadata: Value = serde_json::from_str(&result.content)
                .expect("bounded browser preview lost its metadata JSON");
            vec![ToolUse {
                id: "pixels-actual".into(),
                name: self.second.unwrap().into(),
                input: json!({"action":"screenshot","page_ref":metadata["page_ref"]}),
            }]
        } else {
            Vec::new()
        };
        let stop_reason = if calls.is_empty() {
            iteron_protocol::StopReason::EndTurn
        } else {
            iteron_protocol::StopReason::ToolUse
        };
        let blocks = if calls.is_empty() {
            vec![Block::Text {
                text: "observed physical fixture".into(),
            }]
        } else {
            calls
                .into_iter()
                .map(|call| {
                    on_item(StreamItem::ToolUseComplete(call.clone()));
                    Block::ToolUse(call)
                })
                .collect()
        };
        Ok(TurnResult {
            blocks,
            stop_reason,
            usage: UsageReport::complete(iteron_protocol::Usage::default()),
        })
    }
    fn supports_image_input(&self) -> bool {
        true
    }
}
fn agent(
    workspace: &std::path::Path,
    registry: Registry,
    calls: Vec<ToolUse>,
    second: Option<&'static str>,
) -> (Agent, Arc<Script>) {
    let rollout = Rollout::open(
        &workspace.join(".iteron/runs"),
        &RunId("browser-runtime".into()),
        TenantId::default(),
    )
    .unwrap();
    let provider = Arc::new(Script {
        calls,
        second,
        step: AtomicUsize::new(0),
        observed: Mutex::new(Vec::new()),
    });
    let mut agent = Agent::new(
        provider.clone(),
        registry,
        rollout,
        "vision-fixture".into(),
        "system".into(),
        Budget {
            max_turns: 4,
            max_usd: None,
            max_tokens: None,
            max_wall_secs: 20,
            max_consecutive_tool_errors: 8,
        },
    );
    super::gate_integration_tests::pin_test_tunables_with_edits(&mut agent, []);
    agent.workspace = workspace.to_path_buf();
    agent.context_budget_policy.tool_schema_tokens = 20_000;
    agent.context_budget_policy.tool_result_tokens = 40_000;
    agent.permission_mode = PermissionMode::Yolo;
    (agent, provider)
}
fn open_call() -> ToolUse {
    ToolUse {
        id: "open-actual".into(),
        name: "browser".into(),
        input: json!({"action":"open","url":ORIGIN}),
    }
}

#[tokio::test]
async fn actual_browser_and_computer_require_named_external_permission_and_hard_ceilings() {
    for name in ["browser", "computer"] {
        for case in [
            "no_approval",
            "blanket_allow",
            "external_allow",
            "plan",
            "authority_ceiling",
            "policy_ceiling",
            "cap_deny",
        ] {
            let workspace = super::gate_integration_tests::temp_ws("browser-runtime-gates");
            let driver = Driver::new().await;
            let registry = driver.registry(&workspace);
            // Host-owned fixture setup supplies a current viewport for computer. This direct registry
            // setup is deliberately outside the runtime admission claim; assertions start afterward.
            let call = if name == "computer" {
                let opened = registry.run_effect_captured(open_call()).await;
                let ToolExecution::Definite(result) = opened.execution else {
                    panic!()
                };
                assert!(!result.is_error);
                let metadata: Value = serde_json::from_str(&result.content).unwrap();
                ToolUse {
                    id: "computer-gate".into(),
                    name: name.into(),
                    input: json!({"action":"screenshot","page_ref":metadata["page_ref"]}),
                }
            } else {
                open_call()
            };
            let call_id = call.id.clone();
            let baseline = driver.requests.load(Ordering::SeqCst);
            let (mut agent, _) = agent(&workspace, registry, vec![call], None);
            if case != "no_approval" {
                agent.permission_rules.set_tool(name, Verdict::Auto);
                agent.permission_rules.allow_cap(Capability::CodeExecuting);
            }
            if !matches!(case, "no_approval" | "blanket_allow") {
                agent
                    .permission_rules
                    .set_tool(&format!("{name}:external"), Verdict::Auto);
            }
            match case {
                "plan" => agent.permission_mode = PermissionMode::Plan,
                "authority_ceiling" => {
                    agent.narrow_authority_ceiling(CapabilitySet::only(Capability::CodeExecuting))
                }
                "policy_ceiling" => {
                    agent.narrow_policy_capabilities(CapabilitySet::only(Capability::CodeExecuting))
                }
                "cap_deny" => agent
                    .permission_rules
                    .set_cap(Capability::IrreversibleExternal, Verdict::Deny),
                _ => {}
            }
            assert_eq!(
                tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    agent.run("exercise physical action permission")
                )
                .await
                .unwrap()
                .unwrap(),
                Outcome::Done
            );
            let events = iteron_record::replay(agent.rollout.path()).unwrap();
            let admitted=events.iter().any(|event|matches!(&event.kind,EventKind::EffectIntent{tool_use_id,..} if tool_use_id==&call_id));
            if case == "external_allow" {
                assert!(admitted);
                assert!(driver.requests.load(Ordering::SeqCst) > baseline);
            } else {
                assert!(!admitted, "{name} {case}");
                assert_eq!(
                    driver.requests.load(Ordering::SeqCst),
                    baseline,
                    "{name} {case}"
                );
            }
            drop(agent);
            std::fs::remove_dir_all(workspace).unwrap();
        }
    }
}

fn download(
    store: &crate::artifacts::DurableArtifactStore,
    thread: &SessionId,
    id: &str,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut offset = 0u64;
    for _ in 0..130 {
        let chunk = store
            .read(
                thread,
                ClientArtifactCommandV1::Read {
                    thread_id: thread.clone(),
                    artifact_id: id.into(),
                    offset,
                    max_bytes: 64 * 1024,
                },
            )
            .unwrap();
        bytes.extend(
            base64::engine::general_purpose::STANDARD
                .decode(chunk["content_base64"].as_str().unwrap())
                .unwrap(),
        );
        offset = chunk["next_offset"].as_u64().unwrap();
        if chunk["eof"] == true {
            return bytes;
        }
    }
    panic!("download exceeded finite artifact envelope")
}
#[tokio::test]
async fn actual_tool_terminal_pixels_reach_the_model_and_private_recovery_with_complete_html() {
    for name in ["browser", "computer"] {
        let workspace = super::gate_integration_tests::temp_ws("browser-runtime-pixels");
        let driver = Driver::new().await;
        let (mut agent, provider) = agent(
            &workspace,
            driver.registry(&workspace),
            vec![open_call()],
            Some(name),
        );
        // Explicit operator bypass permits subsequent actions after untrusted page data enters
        // context; the hard ceilings and Deny cases are separately exercised above.
        agent.bypass_permissions = true;
        let (tx, mut rx) = tokio::sync::mpsc::channel(1024);
        agent.ui_tx = Some(tx);
        assert_eq!(
            tokio::time::timeout(
                std::time::Duration::from_secs(30),
                agent.run("inspect browser pixels")
            )
            .await
            .unwrap()
            .unwrap(),
            Outcome::Done
        );
        let observed = provider.observed.lock().await;
        assert_eq!(observed.len(), 1);
        let Block::ToolImage(image) = &observed[0] else {
            panic!()
        };
        image.validate().unwrap();
        assert_eq!(image.tool_use_id, "pixels-actual");
        assert_eq!(image.artifact_id, IMAGE_SHA);
        assert_eq!(image.image.data.as_str(), PNG);
        assert_eq!(image.trust(), Trust::Untrusted);
        let events = iteron_record::replay(agent.rollout.path()).unwrap();
        let terminal=events.iter().find(|event|matches!(&event.kind,EventKind::ToolDone{result,..} if result.tool_use_id=="pixels-actual"&&!result.is_error)).unwrap();
        assert_eq!(image.terminal_seq, terminal.seq);
        assert_eq!(image.owner_run, *agent.rollout.run_id());
        let observation = events
            .iter()
            .find(|event| matches!(event.kind, EventKind::ToolImageObservedV1 { .. }))
            .unwrap();
        assert!(observation.seq.0 > terminal.seq.0);
        let recovered = Agent::messages_from_rollout(agent.rollout.path()).unwrap();
        assert!(recovered.iter().any(|message| {
            message.role == Role::User
                && message
                    .content
                    .iter()
                    .any(|block| matches!(block,Block::ToolImage(replayed) if replayed==image))
        }));
        let jsonl = std::fs::read_to_string(agent.rollout.path()).unwrap();
        assert!(!jsonl.contains(PNG));
        let thread = SessionId(agent.rollout.run_id().0.clone());
        let store = crate::artifacts::DurableArtifactStore::open(
            agent.rollout.path().parent().unwrap(),
            agent.rollout.tenant().clone(),
            agent.rollout.run_id().clone(),
            &workspace,
        )
        .unwrap();
        let catalog = store
            .read(
                &thread,
                ClientArtifactCommandV1::List {
                    thread_id: thread.clone(),
                },
            )
            .unwrap();
        let items = catalog["artifacts"].as_array().unwrap();
        assert_eq!(
            download(&store, &thread, IMAGE_SHA),
            base64::engine::general_purpose::STANDARD
                .decode(PNG)
                .unwrap()
        );
        let html = items
            .iter()
            .find(|item| item["schema"] == "iteron.browser-observation.v1")
            .expect("complete browser source was not retained");
        let body: Value = serde_json::from_slice(&download(
            &store,
            &thread,
            html["artifact_id"].as_str().unwrap(),
        ))
        .unwrap();
        assert_eq!(body["html"], driver.html);
        assert!(body["metadata"]["omitted_source_bytes"].as_u64().unwrap() > 0);
        let manifest = items
            .iter()
            .find(|item| item["schema"] == "iteron.viewport-image-observation.v1")
            .unwrap();
        let body: Value = serde_json::from_slice(&download(
            &store,
            &thread,
            manifest["artifact_id"].as_str().unwrap(),
        ))
        .unwrap();
        assert_eq!(body["retained_image"]["artifact_id"], IMAGE_SHA);
        assert_eq!(body["source_event_seq"], terminal.seq.0);
        while let Ok(event) = rx.try_recv() {
            if let UiEvent::Notice(message) = event {
                assert!(
                    !message.contains("retention is unavailable")
                        && !message.contains("screenshot remains unavailable"),
                    "{message}"
                );
            }
        }
        drop(observed);
        drop(agent);
        std::fs::remove_dir_all(workspace).unwrap();
    }
}
