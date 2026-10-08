use super::*;
use crate::{
    Anthropic, ApiRoot, HealthReportingProvider, OpenAiCompat, OpenAiResponses, Provider,
    ProviderHealthStore, RecordingProviderTransport, TurnRequest,
};
use iteron_protocol::{Message, ReasoningEffort};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[derive(Default)]
struct Observation {
    body: Vec<u8>,
    order: Vec<&'static str>,
}
struct Witness {
    observation: Mutex<Observation>,
    refuse: Option<&'static str>,
    delay: Option<&'static str>,
}
impl ProviderRequestObserver for Witness {
    fn prepared(&self, request: ProviderWireRequest<'_>) -> Result<(), RequestCaptureError> {
        if self.refuse == Some("prepared") {
            return Err(RequestCaptureError::ReconciliationNeeded);
        }
        if self.delay == Some("prepared") {
            std::thread::sleep(Duration::from_millis(30));
        }
        assert_eq!(request.method, "POST");
        assert_eq!(request.content_type, "application/json");
        let mut observation = self.observation.lock().unwrap();
        observation.body = request.body.to_vec();
        observation.order.push("prepared");
        Ok(())
    }
    fn dispatching(&self) -> Result<(), RequestCaptureError> {
        if self.refuse == Some("dispatching") {
            return Err(RequestCaptureError::ReconciliationNeeded);
        }
        if self.delay == Some("dispatching") {
            std::thread::sleep(Duration::from_millis(30));
        }
        self.observation.lock().unwrap().order.push("dispatching");
        Ok(())
    }
    fn unavailable(&self, _: &'static str) -> Result<(), RequestCaptureError> {
        panic!("live adapter and health wrapper must preserve exact capture")
    }
}

fn request() -> TurnRequest {
    TurnRequest {
        model: "fixture-model".into(),
        system: "effective system fixture".into(),
        messages: vec![Message::user_text("exact request \"quotes\" 中文")],
        input_images: Vec::new(),
        tools: Vec::new().into(),
        max_tokens: 64,
        cache_system: false,
        thinking_budget: 0,
        reasoning_effort: ReasoningEffort::Low,
        controls: Default::default(),
    }
}

fn tls_configuration() -> (TlsAcceptor, RecordingProviderTransport) {
    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let transport = RecordingProviderTransport::from_pem(generated.cert.pem().as_bytes()).unwrap();
    let configuration = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![generated.cert.der().clone()],
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der())),
        )
        .unwrap();
    (TlsAcceptor::from(Arc::new(configuration)), transport)
}

fn provider(
    adapter: AdapterKind,
    root: ApiRoot,
    transport: &RecordingProviderTransport,
) -> Box<dyn Provider> {
    let key = "credential_header_canary".to_string();
    let inner: Box<dyn Provider> = match adapter {
        AdapterKind::AnthropicMessages => {
            Box::new(Anthropic::with_transport(key, root, transport).unwrap())
        }
        AdapterKind::OpenAiCompatibleChat => {
            Box::new(OpenAiCompat::with_transport(key, root, transport).unwrap())
        }
        AdapterKind::OpenAiResponses => {
            Box::new(OpenAiResponses::with_transport(key, root, transport).unwrap())
        }
    };
    Box::new(HealthReportingProvider::new(
        inner,
        "fixture",
        ProviderHealthStore::new(1),
    ))
}

async fn received_body(listener: TcpListener, acceptor: TlsAcceptor) -> Vec<u8> {
    let (stream, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let mut stream = tokio::time::timeout(Duration::from_secs(3), acceptor.accept(stream))
        .await
        .unwrap()
        .unwrap();
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    let body = loop {
        let count = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut chunk))
            .await
            .unwrap()
            .unwrap();
        assert_ne!(count, 0);
        assert!(bytes.len() + count <= 64 * 1024);
        bytes.extend_from_slice(&chunk[..count]);
        let Some(header_end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") else {
            continue;
        };
        let headers = std::str::from_utf8(&bytes[..header_end]).unwrap();
        let length: usize = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().unwrap())
            })
            .unwrap();
        let offset = header_end + 4;
        if bytes.len() >= offset + length {
            break bytes[offset..offset + length].to_vec();
        }
    };
    let payload = br#"{"error":{"message":"fixture stop","type":"invalid_request_error"}}"#;
    let headers = format!(
        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream.write_all(headers.as_bytes()).await.unwrap();
    stream.write_all(payload).await.unwrap();
    let _ = stream.shutdown().await;
    body
}

#[tokio::test]
async fn every_live_adapter_and_health_wrapper_observe_the_exact_tls_wire_body() {
    for adapter in [
        AdapterKind::AnthropicMessages,
        AdapterKind::OpenAiCompatibleChat,
        AdapterKind::OpenAiResponses,
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let root = ApiRoot::parse(&format!(
            "https://localhost:{}/v1",
            listener.local_addr().unwrap().port()
        ))
        .unwrap();
        let (acceptor, transport) = tls_configuration();
        let provider = provider(adapter, root, &transport);
        let server = tokio::spawn(received_body(listener, acceptor));
        let witness = Witness {
            observation: Mutex::new(Observation::default()),
            refuse: None,
            delay: None,
        };
        let result = provider
            .turn_observed(&request(), &mut |_| {}, &witness)
            .await;
        assert!(matches!(result, Err(ProviderError::ApiResponse(_))));
        let wire = server.await.unwrap();
        let observed = witness.observation.lock().unwrap();
        assert_eq!(observed.body, wire);
        assert_eq!(observed.order, ["prepared", "dispatching"]);
        assert!(!String::from_utf8_lossy(&wire).contains("credential_header_canary"));
    }
}

#[tokio::test]
async fn refused_preparation_or_dispatch_barrier_opens_no_socket_for_any_live_adapter() {
    for adapter in [
        AdapterKind::AnthropicMessages,
        AdapterKind::OpenAiCompatibleChat,
        AdapterKind::OpenAiResponses,
    ] {
        for refusal in ["prepared", "dispatching"] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let root = ApiRoot::parse(&format!(
                "https://localhost:{}/v1",
                listener.local_addr().unwrap().port()
            ))
            .unwrap();
            let (_, transport) = tls_configuration();
            let provider = provider(adapter, root, &transport);
            let witness = Witness {
                observation: Mutex::new(Observation::default()),
                refuse: Some(refusal),
                delay: None,
            };
            let result = provider
                .turn_observed(&request(), &mut |_| {}, &witness)
                .await;
            assert!(matches!(
                result,
                Err(ProviderError::RequestCaptureRefusedBeforeDispatch)
            ));
            assert!(
                tokio::time::timeout(Duration::from_millis(25), listener.accept())
                    .await
                    .is_err()
            );
        }
    }
}

#[tokio::test]
async fn slow_observation_deadline_remains_proven_zero_network() {
    for adapter in [
        AdapterKind::AnthropicMessages,
        AdapterKind::OpenAiCompatibleChat,
        AdapterKind::OpenAiResponses,
    ] {
        for phase in ["prepared", "dispatching"] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let root = ApiRoot::parse(&format!(
                "https://localhost:{}/v1",
                listener.local_addr().unwrap().port()
            ))
            .unwrap();
            let (_, transport) = tls_configuration();
            let provider = provider(adapter, root, &transport);
            let witness = Witness {
                observation: Mutex::new(Observation::default()),
                refuse: None,
                delay: Some(phase),
            };
            let mut request = request();
            request.controls.transport.connect_tls = Duration::from_millis(5);
            request.controls.transport.request_total = Duration::from_millis(20);
            request.controls.transport.stream_idle = Duration::from_millis(10);
            let result = provider
                .turn_observed(&request, &mut |_| {}, &witness)
                .await;
            assert!(matches!(
                result,
                Err(ProviderError::RequestDeadlineBeforeDispatch)
            ));
            assert!(
                tokio::time::timeout(Duration::from_millis(25), listener.accept())
                    .await
                    .is_err()
            );
        }
    }
}
