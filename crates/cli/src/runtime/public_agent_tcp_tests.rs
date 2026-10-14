//! Actual native financial authority, App Server and public-agent controls over owned TCP.
use super::{Agent, SelectedRoute, gate_integration_tests};
use crate::config::{ProviderConfig, ProviderCredential};
use crate::providers::{ModelSelection, ProviderDirectory};
use futures_util::FutureExt;
use iteron_obs::{HmacPricingAuthority, HmacPricingKey};
use iteron_protocol::{Budget, EventKind, PROTOCOL_VERSION, PricingRoute, RunId, TenantId};
use iteron_provider::catalog::HttpTransport;
use iteron_provider::{ProviderError, ProviderTransportTimeoutPolicy};
use iteron_record::Rollout;
use iteron_tunables::ResolutionValue;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{
    TcpListener, TcpStream,
    tcp::{OwnedReadHalf, OwnedWriteHalf},
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{self, pki_types::PrivatePkcs8KeyDer};

// Match the existing native TLS fixture: retain the actual host/model authority and normally
// validate its case-owned CA; only DNS and the transport destination are injected.
struct NativeTransport {
    address: SocketAddr,
    certificate: reqwest::Certificate,
}
impl HttpTransport for NativeTransport {
    fn client(
        &self,
        policy: ProviderTransportTimeoutPolicy,
    ) -> Result<reqwest::Client, ProviderError> {
        let policy = policy.validate()?;
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(policy.connect_tls)
            .timeout(policy.request_total)
            .resolve("api.openai.com", self.address)
            .add_root_certificate(self.certificate.clone());
        if policy.connection_reuse {
            builder = builder
                .pool_idle_timeout(policy.pool_idle)
                .tcp_keepalive((!policy.tcp_keepalive.is_zero()).then_some(policy.tcp_keepalive));
        } else {
            builder = builder.pool_max_idle_per_host(0).tcp_keepalive(None);
        }
        builder
            .build()
            .map_err(|_| ProviderError::Configuration("fixture TLS client unavailable".into()))
    }
}

fn integer(value: u64) -> ResolutionValue {
    ResolutionValue::Integer {
        value: i64::try_from(value).unwrap(),
    }
}
fn transport_tunables(
    policy: ProviderTransportTimeoutPolicy,
) -> Vec<(&'static str, ResolutionValue)> {
    vec![
        (
            "provider_connect_tls_timeout",
            integer(policy.connect_tls.as_secs()),
        ),
        (
            "provider_request_total_deadline",
            integer(policy.request_total.as_millis().try_into().unwrap()),
        ),
        (
            "stream_idle_watchdog",
            integer(policy.stream_idle.as_millis().try_into().unwrap()),
        ),
        (
            "http_pool_keepalive_idle_policy",
            ResolutionValue::Object {
                fields: BTreeMap::from([
                    (
                        "pool_idle_seconds".into(),
                        integer(policy.pool_idle.as_secs()),
                    ),
                    (
                        "tcp_keepalive_seconds".into(),
                        integer(policy.tcp_keepalive.as_secs()),
                    ),
                    (
                        "connection_reuse".into(),
                        ResolutionValue::Boolean {
                            value: policy.connection_reuse,
                        },
                    ),
                ]),
            },
        ),
    ]
}

struct Workspace(PathBuf, bool);
impl Drop for Workspace {
    fn drop(&mut self) {
        if self.1 {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn native_agent(workspace: &Path, transport: &NativeTransport) -> Agent {
    let credential = workspace.join("fixture-native-token");
    std::fs::write(&credential, "fixture-only-native-token\n").unwrap();
    std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
    let directory = ProviderDirectory::inspect_local(&[ProviderConfig {
        id: "public-native-tcp".into(),
        display_name: None,
        adapter: "openai_chat".into(),
        error_profile: Some("openai".into()),
        api_root: "https://api.openai.com/v1".into(),
        key_env: None,
        credential: Some(ProviderCredential::File {
            path: credential.display().to_string(),
        }),
        enabled: true,
        catalog: false,
        models: vec!["gpt-5.6".into()],
        model_capabilities: BTreeMap::new(),
    }])
    .unwrap();
    let selection = ModelSelection {
        provider_id: "public-native-tcp".into(),
        model_id: "gpt-5.6".into(),
    };
    let native = directory
        .build_with_transport(&selection, transport)
        .unwrap();
    assert!(
        native
            .physical_input_token_ceiling(&selection.model_id)
            .is_some()
    );
    assert_eq!(
        native.usage_bound_semantics(),
        iteron_provider::ProviderUsageBoundSemantics::PartitionedInput
    );
    let (catalog_digest, capability_digest) = directory.selection_digests(&selection);
    let route = PricingRoute {
        provider_id: selection.provider_id.clone(),
        model_id: selection.model_id.clone(),
        catalog_digest: catalog_digest.clone(),
        capability_digest: capability_digest.clone(),
    };
    let rollout = Rollout::open(
        &workspace.join(".iteron/runs"),
        &RunId("public-native-tcp".into()),
        TenantId::default(),
    )
    .unwrap();
    let mut agent = Agent::new(
        native.clone(),
        iteron_tools::Registry::coding_agent_for_tests(workspace).unwrap(),
        rollout,
        selection.model_id.clone(),
        "fixture system".into(),
        Budget {
            max_turns: 4,
            max_usd: None,
            max_tokens: Some(4_000_000),
            max_wall_secs: 30,
            max_consecutive_tool_errors: 3,
        },
    );
    agent.workspace = workspace.to_owned();
    agent.effort = iteron_protocol::Effort::Low;
    // Seed only composition identity before genesis. Dispatch still requires the actual native
    // provider, the durable selection below and authenticated pricing; no input proof is replaced.
    super::provider_selection::ProviderSelectionOwner::validate_selection(&native, &route).unwrap();
    agent.provider_selection.fixture_selection(
        Some(SelectedRoute {
            route: route.clone(),
        }),
        native.clone(),
    );
    let policy = iteron_provider::provider_transport_timeout_policy();
    let mut edits = transport_tunables(policy);
    edits.extend([
        ("max_turns", integer(4)),
        ("max_tokens", integer(4_000_000)),
        ("max_wall_secs", integer(30)),
        (
            "effort",
            ResolutionValue::Enum {
                value: "low".into(),
            },
        ),
    ]);
    gate_integration_tests::record_test_genesis_with_tunable_edits(&mut agent, workspace, edits);
    let key = [42; 32];
    let signed = iteron_obs::sign_rate_card(
        iteron_protocol::RateCard {
            version: iteron_protocol::PricingVersion::V1,
            route,
            provenance: "public-native-tcp-fixture@v1".into(),
            issued_at_unix_secs: 1,
            expires_at_unix_secs: u64::MAX,
            // Synthetic case rates, with complete physical usage below; never a vendor tariff.
            rates: iteron_protocol::TokenRateCard {
                input_microusd_per_million: 1,
                output_microusd_per_million: 1,
                cache_creation_microusd_per_million: 1,
                cache_read_microusd_per_million: 1,
                thinking_microusd_per_million: 1,
            },
        },
        "public-native-fixture-authority",
        key,
    )
    .unwrap();
    agent.set_pricing_port(Arc::new(
        HmacPricingAuthority::new(vec![(signed, HmacPricingKey::from_bytes(key))]).unwrap(),
    ));
    agent
        .record_operator_model_selection(
            native,
            selection.provider_id,
            selection.model_id,
            catalog_digest,
            capability_digest,
        )
        .unwrap();
    assert!(agent.bind_selected_rate_card().unwrap());
    gate_integration_tests::install_test_provider_governor_from_tunables(&mut agent);
    agent
}

async fn native_requests(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    observed: mpsc::Sender<Value>,
    mut release: mpsc::Receiver<()>,
) {
    // One aggregate deadline bounds both physical requests, including pauses for live controls.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    for _ in 0..2 {
        let (socket, _) = tokio::time::timeout_at(deadline, listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut stream = tokio::time::timeout_at(deadline, acceptor.accept(socket))
            .await
            .unwrap()
            .unwrap();
        let mut request = Vec::new();
        let mut chunk = [0u8; 4096];
        let body = loop {
            let count = tokio::time::timeout_at(deadline, stream.read(&mut chunk))
                .await
                .unwrap()
                .unwrap();
            assert!(count > 0 && request.len() + count <= 1024 * 1024);
            request.extend_from_slice(&chunk[..count]);
            let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") else {
                continue;
            };
            let headers = std::str::from_utf8(&request[..end]).unwrap();
            assert!(headers.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"));
            assert!(headers.lines().any(|line| {
                line.split_once(':').is_some_and(|(name, value)| {
                    name.eq_ignore_ascii_case("host") && value.trim() == "api.openai.com"
                })
            }));
            let length = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':')
                        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                        .map(|(_, value)| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            assert!(length <= 1024 * 1024);
            let start = end + 4;
            if request.len() >= start + length {
                break serde_json::from_slice::<Value>(&request[start..start + length]).unwrap();
            }
        };
        assert_eq!(body["model"], "gpt-5.6");
        assert!(body["max_tokens"].as_u64().is_some_and(|cap| cap > 0));
        tokio::time::timeout_at(deadline, observed.send(body))
            .await
            .unwrap()
            .unwrap();
        assert!(
            tokio::time::timeout_at(deadline, release.recv())
                .await
                .unwrap()
                .is_some()
        );
        let response = concat!(
            "data: {\"id\":\"public-native\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"parity reply\"},\"finish_reason\":null}],\"usage\":null}\n\n",
            "data: {\"id\":\"public-native\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":2,\"total_tokens\":13,\"prompt_tokens_details\":{\"cached_tokens\":0,\"cache_creation_tokens\":0},\"completion_tokens_details\":{\"reasoning_tokens\":0}}}\n\n",
            "data: [DONE]\n\n"
        );
        let reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
            response.len()
        );
        tokio::time::timeout_at(deadline, stream.write_all(reply.as_bytes()))
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout_at(deadline, stream.shutdown())
            .await
            .unwrap()
            .unwrap();
    }
}

struct Client {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}
impl Client {
    async fn connect(
        address: SocketAddr,
        token: &str,
        version: u32,
        cursor: u64,
        observer: bool,
    ) -> Self {
        let stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(address))
            .await
            .unwrap()
            .unwrap();
        let (reader, writer) = stream.into_split();
        let mut client = Self {
            reader: BufReader::new(reader),
            writer,
        };
        client
            .send(
                json!({"type":"hello","bearer_token":token,"protocol_version":version,
            "resume_from":cursor,"observation_only":observer}),
            )
            .await;
        let greeting = client.receive().await;
        assert_eq!(greeting["type"], "hello");
        if observer {
            assert_eq!(greeting["client_access"], "observe");
        }
        client
    }
    async fn send(&mut self, value: Value) {
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(b'\n');
        tokio::time::timeout(Duration::from_secs(10), self.writer.write_all(&bytes))
            .await
            .unwrap()
            .unwrap();
    }
    async fn receive(&mut self) -> Value {
        let mut bytes = Vec::new();
        let mut bounded = (&mut self.reader).take(1024 * 1024 + 1);
        let count = tokio::time::timeout(
            Duration::from_secs(10),
            bounded.read_until(b'\n', &mut bytes),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(count > 0 && count <= 1024 * 1024);
        serde_json::from_slice(&bytes).unwrap()
    }
    async fn reply(&mut self, id: u64) -> Value {
        for _ in 0..64 {
            let frame = self.receive().await;
            assert_ne!(frame["type"], "error", "control was refused");
            if frame["type"] == "control_reply" && frame["request_id"] == id {
                return frame["reply"].clone();
            }
        }
        panic!("bounded public control reply not observed");
    }
    async fn control(&mut self, id: u64, version: u32, control: Value) {
        self.send(
            json!({"type":"control","protocol_version":version,"request_id":id,"control":control}),
        )
        .await;
    }
    async fn submit(&mut self, text: &str) {
        self.send(json!({"type":"submit","protocol_version":PROTOCOL_VERSION,"op":{"op":"user_input","text":text}})).await;
    }
    async fn terminal(&mut self) -> Value {
        for _ in 0..64 {
            let frame = self.receive().await;
            assert_ne!(frame["type"], "error");
            if frame["type"] == "result" {
                return frame;
            }
        }
        panic!("bounded terminal result not observed");
    }
}

// Timeout never drops an unobserved fixture task: cancellation is followed by its actual join.
async fn finish<T>(mut task: JoinHandle<T>) -> Result<T, &'static str> {
    match tokio::time::timeout(Duration::from_secs(10), &mut task).await {
        Ok(result) => result.map_err(|_| "owned fixture task failed"),
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err("owned fixture task exceeded its shutdown deadline")
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_public_agent_receipts_cross_tcp_connections_while_parent_dispatch_is_live() {
    let mut workspace = Workspace(
        gate_integration_tests::temp_ws("native-public-agent-tcp"),
        true,
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let generated = rcgen::generate_simple_self_signed(vec!["api.openai.com".into()]).unwrap();
    let transport = NativeTransport {
        address: listener.local_addr().unwrap(),
        certificate: reqwest::Certificate::from_der(generated.cert.der().as_ref()).unwrap(),
    };
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![generated.cert.der().clone()],
        PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der()).into(),
    )
    .unwrap();
    let agent = native_agent(&workspace.0, &transport);
    let rollout = agent.rollout.path().to_owned();
    let endpoint = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = endpoint.local_addr().unwrap();
    // Preserve the directory if a task's physical destruction cannot be observed.
    workspace.1 = false;
    let attached = crate::app_server::attach(agent, false, true).unwrap();
    let core_abort = attached.task.abort_handle();
    let token = "07".repeat(32); // Case-owned authentication; no operator key or global environment.
    let (seen, mut request_seen) = mpsc::channel(2);
    let (release, released) = mpsc::channel(2);
    let provider = tokio::spawn(native_requests(
        listener,
        TlsAcceptor::from(Arc::new(tls)),
        seen,
        released,
    ));
    let transport_task = tokio::spawn(async move {
        crate::tui::headless::serve_test_listener(attached, endpoint, &token).await
    });
    let journey = AssertUnwindSafe(async {
        let mut client = Client::connect(address, &"07".repeat(32), PROTOCOL_VERSION, 0, false).await;
        client.submit("establish the real parent route").await;
        let first = request_seen.recv().await.unwrap();
        assert!(first["messages"].to_string().contains("establish the real parent route"));
        release.send(()).await.unwrap();
        let terminal = client.terminal().await;
        assert_eq!(terminal["result"]["outcome"], "done");
        assert_eq!(terminal["result"]["cost_status"], "known");
        client.control(201, PROTOCOL_VERSION, json!({"type":"turn_budget","set":4})).await;
        assert_eq!(client.reply(201).await["type"], "turn_budget");
        client.control(202, PROTOCOL_VERSION, json!({"type":"agents_v1","command":{
            "type":"enable","capabilities":["read_only"],
            "budget":{"turns":1,"tokens":2000000,"cost_microusd":1000000,"wall_ms":10000},
            "max_agents":4,"max_pending_per_agent":8,"parallel":2}})).await;
        let enabled = client.reply(202).await;
        assert_eq!(enabled["type"], "agents_enabled_v1");
        let root = enabled["agents"][0]["agent_id"].as_u64().unwrap();
        client.control(203, PROTOCOL_VERSION, json!({"type":"agents_v1","command":{
            "type":"command","request_id":"root-message-1","command":{"type":"send_message","agent_id":root,"text":"accepted mailbox probe"}}})).await;
        let accepted = client.reply(203).await;
        assert_eq!(accepted["type"], "agent_receipt_v1");
        let message = accepted["receipt"]["message_id"].as_u64().unwrap();
        client.submit("continue the parent while observing its controller").await;
        let second = request_seen.recv().await.unwrap();
        assert!(second["messages"].to_string().contains("continue the parent while observing its controller"));
        assert!(second["messages"].to_string().contains("accepted mailbox probe"));
        client.control(204, PROTOCOL_VERSION, json!({"type":"agents_v1","command":{"type":"list"}})).await;
        let live = client.reply(204).await;
        assert_eq!(live["type"], "agents_v1");
        assert_eq!(live["agents"][0]["queued_messages"], 0);
        let mut observer = Client::connect(address, &"07".repeat(32), PROTOCOL_VERSION - 1,
            terminal["seq"].as_u64().unwrap(), true).await;
        observer.control(205, PROTOCOL_VERSION - 1, json!({"type":"agents_v1","command":{"type":"message_receipt","message_id":message}})).await;
        assert_eq!(observer.reply(205).await["message"]["state"]["type"], "consumed");
        observer.control(206, PROTOCOL_VERSION - 1, json!({"type":"agents_v1","command":{
            "type":"command","request_id":"observer-mutation","command":{"type":"send_message","agent_id":root,"text":"forbidden"}}})).await;
        let mut refused = false;
        for _ in 0..64 {
            let frame = observer.receive().await;
            if frame["type"] == "error" { assert_eq!(frame["code"], "observer_authority"); refused = true; break; }
        }
        assert!(refused);
        release.send(()).await.unwrap();
        let terminal = client.terminal().await;
        assert_eq!(terminal["result"]["outcome"], "done");
        assert_eq!(terminal["result"]["cost_status"], "known");
        client.control(207, PROTOCOL_VERSION, json!({"type":"resident_service_v1","command":{"action":"read"}})).await;
        let service = client.reply(207).await;
        client.control(208, PROTOCOL_VERSION, json!({"type":"resident_service_v1","command":{"action":"stop","scope":service["service"]["scope"]}})).await;
        assert_eq!(client.reply(208).await["status"], "requested");
        drop(observer);
        drop(client);
    }).catch_unwind();
    let result = tokio::time::timeout(Duration::from_secs(35), journey).await;
    if !matches!(result, Ok(Ok(()))) {
        transport_task.abort();
        core_abort.abort();
        provider.abort();
        let _ = tokio::join!(finish(transport_task), finish(provider));
        tokio::time::timeout(Duration::from_secs(5), async {
            while !core_abort.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled App Server task must finish before workspace removal");
        workspace.1 = true;
        match result {
            Ok(Err(panic)) => std::panic::resume_unwind(panic),
            _ => panic!("public native TCP journey exceeded its finite deadline"),
        }
    }
    // Both joins are observed before asserting either result, including a failed provider task.
    let (provider_closed, transport_closed) =
        tokio::join!(finish(provider), finish(transport_task));
    if provider_closed.is_err() || !matches!(transport_closed, Ok(Ok(()))) {
        core_abort.abort();
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        while !core_abort.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("App Server destruction must finish before workspace removal");
    workspace.1 = true;
    provider_closed.unwrap();
    transport_closed.unwrap().unwrap();
    assert!(
        core_abort.is_finished(),
        "the actual App Server shutdown was joined"
    );
    let events = iteron_record::replay(&rollout).unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(&event.kind,
        EventKind::EffectIntent { tool, .. } if tool == "provider"))
            .count(),
        2
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(&event.kind,
        EventKind::Done { outcome } if outcome == "Done"))
            .count(),
        2
    );
}
