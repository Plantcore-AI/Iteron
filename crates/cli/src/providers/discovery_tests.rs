//! Real native request verifies discovery admission preserves wire capture and finite output caps.
use super::{DiscoverySettlement, ProviderDiscoveryOwner, ProviderRefreshActivity};
use crate::providers::{
    CatalogCache, DiscoveryPersistence, ProbeCache, ProbeUpdates, ResolveContext,
};
use iteron_protocol::{Message, ReasoningEffort};
use iteron_provider::output_ceiling::ProviderOutputBudget;
use iteron_provider::request_capture::{
    ProviderRequestObserver, ProviderWireRequest, RequestCaptureError,
};
use iteron_provider::{OpenAiCompat, Provider, ProviderHealthStore, TurnRequest};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Default)]
struct Witness {
    body: Mutex<Vec<u8>>,
    dispatched: Mutex<bool>,
}
impl ProviderRequestObserver for Witness {
    fn prepared(&self, request: ProviderWireRequest<'_>) -> Result<(), RequestCaptureError> {
        *self.body.lock().unwrap() = request.body.to_vec();
        assert_eq!(request.serialized_output_tokens, 61);
        Ok(())
    }
    fn dispatching(&self) -> Result<(), RequestCaptureError> {
        assert!(!self.body.lock().unwrap().is_empty());
        *self.dispatched.lock().unwrap() = true;
        Ok(())
    }
    fn unavailable(&self, _: &'static str) -> Result<(), RequestCaptureError> {
        panic!("post-paint wrapper lost native request observation")
    }
}
fn owner() -> Arc<ProviderDiscoveryOwner> {
    let probes = Arc::new(ProbeCache::default());
    let updates = ProbeUpdates::default();
    Arc::new(ProviderDiscoveryOwner::new(
        BTreeSet::new(),
        Vec::new(),
        Vec::new(),
        ResolveContext {
            health: ProviderHealthStore::default(),
            probe_cache: probes.clone(),
            probe_updates: updates.clone(),
            cache_scope_key: None,
        },
        DiscoveryPersistence {
            cache: Arc::new(CatalogCache::default()),
            cache_scope_key: None,
            cache_path: None,
            probe_cache: probes,
            probe_cache_path: None,
            probe_updates: updates,
        },
        ProviderRefreshActivity::pending(),
    ))
}
async fn wire_body(listener: TcpListener) -> Vec<u8> {
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut bytes = Vec::new();
    let body = loop {
        let mut chunk = [0; 4096];
        let read = socket.read(&mut chunk).await.unwrap();
        assert_ne!(read, 0);
        assert!(bytes.len() + read <= 64 * 1024);
        bytes.extend_from_slice(&chunk[..read]);
        let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") else {
            continue;
        };
        let headers = std::str::from_utf8(&bytes[..end]).unwrap();
        let length: usize = headers
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().unwrap())
            })
            .unwrap();
        if bytes.len() >= end + 4 + length {
            break bytes[end + 4..end + 4 + length].to_vec();
        }
    };
    let response = br#"{"error":{"message":"fixture stop","type":"invalid_request_error"}}"#;
    let headers = format!(
        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.len()
    );
    socket.write_all(headers.as_bytes()).await.unwrap();
    socket.write_all(response).await.unwrap();
    body
}
#[tokio::test]
async fn real_native_wire_capture_and_output_cap_survive_discovery_admission() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let root = format!("http://{}/v1", listener.local_addr().unwrap());
    let owner = owner();
    let provider = owner.admit_provider(Arc::new(
        OpenAiCompat::try_new("fixture-credential".into(), Some(root)).unwrap(),
    ));
    let request = TurnRequest {
        model: "fixture-model".into(),
        system: "fixture system".into(),
        messages: vec![Message::user_text("native exact wire 中文")],
        input_images: Vec::new(),
        tools: Vec::new().into(),
        max_tokens: 61,
        cache_system: false,
        thinking_budget: 0,
        reasoning_effort: ReasoningEffort::Low,
        controls: Default::default(),
    };
    assert_eq!(
        provider
            .physical_output_token_ceiling(ProviderOutputBudget::from(&request))
            .unwrap(),
        Some(61)
    );
    assert!(owner.begin_after_paint());
    assert!(matches!(
        owner.settle().await,
        DiscoverySettlement::Settled(_)
    ));
    let server = tokio::spawn(wire_body(listener));
    let witness = Witness::default();
    assert!(
        tokio::time::timeout(
            Duration::from_secs(3),
            provider.turn_observed(&request, &mut |_| {}, &witness)
        )
        .await
        .unwrap()
        .is_err()
    );
    let sent = tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sent, *witness.body.lock().unwrap());
    assert!(*witness.dispatched.lock().unwrap());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&sent).unwrap()["max_tokens"],
        61
    );
}
