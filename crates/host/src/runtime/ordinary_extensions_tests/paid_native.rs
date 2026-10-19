//! Actual native TLS dispatch and signed charging through an ordinary SDK provider export.
use super::{agent_with_budget_and_tunables, binding};
use crate::config::{ProviderConfig, ProviderCredential};
use crate::plugin_runtime::ordinary::OrdinaryDescriptor;
use crate::providers::{ModelSelection, ProviderDirectory};
use crate::runtime::provider_charge_evidence::route_accounting_id;
use crate::runtime::{Outcome, gate_integration_tests};
use iteron_extension_sdk::NativeProviderRegistrationV1;
use iteron_obs::{CostState, HmacPricingAuthority, HmacPricingKey};
use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::{Budget, Capability, EventKind, PricingRoute, RunId, Usage};
use iteron_provider::catalog::HttpTransport;
use iteron_provider::{ProviderError, ProviderTransportTimeoutPolicy};
use iteron_tunables::ResolutionValue;
use serde_json::Value;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{self, pki_types::PrivatePkcs8KeyDer};

// The adapter's native authority and hostname remain exact. Only the host's transport routes
// that hostname to this private TLS listener, with its specific certificate trusted normally.
struct LoopbackNativeTransport {
    address: SocketAddr,
    certificate: reqwest::Certificate,
}
impl HttpTransport for LoopbackNativeTransport {
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

fn transport_tunables(
    policy: ProviderTransportTimeoutPolicy,
) -> [(&'static str, ResolutionValue); 4] {
    let integer = |value| ResolutionValue::Integer {
        value: i64::try_from(value).unwrap(),
    };
    [
        (
            "provider_connect_tls_timeout",
            integer(policy.connect_tls.as_secs()),
        ),
        (
            "provider_request_total_deadline",
            integer(u64::try_from(policy.request_total.as_millis()).unwrap()),
        ),
        (
            "stream_idle_watchdog",
            integer(u64::try_from(policy.stream_idle.as_millis()).unwrap()),
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

async fn native_request(listener: &TcpListener, acceptor: TlsAcceptor) -> Value {
    // One absolute physical server deadline bounds accept, TLS, request read and reply write.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let (socket, _) = tokio::time::timeout_at(deadline, listener.accept())
        .await
        .expect("the SDK native adapter connects within its fixture watchdog")
        .unwrap();
    let mut stream = tokio::time::timeout_at(deadline, acceptor.accept(socket))
        .await
        .expect("the exact native hostname completes TLS")
        .unwrap();
    let mut request = Vec::new();
    let mut chunk = [0u8; 4096];
    let body = loop {
        let count = tokio::time::timeout_at(deadline, stream.read(&mut chunk))
            .await
            .expect("native request read is bounded")
            .unwrap();
        assert!(count > 0, "the native adapter sent a complete HTTP request");
        assert!(request.len() + count <= 1024 * 1024);
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
    let response = concat!(
        "data: {\"id\":\"sdk-paid-native\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"SDK paid native answer\"},\"finish_reason\":null}],\"usage\":null}\n\n",
        "data: {\"id\":\"sdk-paid-native\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":2,\"total_tokens\":13,\"prompt_tokens_details\":{\"cached_tokens\":3,\"cache_creation_tokens\":0},\"completion_tokens_details\":{\"reasoning_tokens\":0}}}\n\n",
        "data: [DONE]\n\n"
    );
    let reply = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
        response.len()
    );
    tokio::time::timeout_at(deadline, stream.write_all(reply.as_bytes()))
        .await
        .expect("the actual authoritative usage reply is bounded")
        .unwrap();
    body
}

#[tokio::test]
async fn signed_known_native_sdk_export_charges_actual_cached_usage_then_refuses_exhausted_io() {
    let root = gate_integration_tests::temp_ws("sdk-paid-native");
    let credential = root.with_extension("sdk-paid-native-credential");
    std::fs::write(&credential, "fixture-native-token\n").unwrap();
    std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
    let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
    let generated = rcgen::generate_simple_self_signed(vec!["api.openai.com".into()]).unwrap();
    let transport = LoopbackNativeTransport {
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
    let directory = ProviderDirectory::inspect_local(&[ProviderConfig {
        id: "sdk-paid-native".into(),
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
        provider_id: "sdk-paid-native".into(),
        model_id: "gpt-5.6".into(),
    };
    // The host-injected client is fixed to its actual construction policy. The ordinary
    // schema fixture samples pool settings; it cannot attest a different physical client.
    let transport_policy = iteron_provider::provider_transport_timeout_policy();
    let native = directory
        .build_with_transport(&selection, &transport)
        .unwrap();
    assert!(native.physical_input_token_ceiling("gpt-5.6").is_some());
    assert_eq!(
        native.usage_bound_semantics(),
        iteron_provider::ProviderUsageBoundSemantics::PartitionedInput
    );
    let run = RunId("sdk-paid-native".into());
    let mut owner = agent_with_budget_and_tunables(
        &root,
        &run,
        native.clone(),
        Budget {
            max_usd: Some(20.0),
            ..Budget::default()
        },
        transport_tunables(transport_policy),
    );
    owner.model = selection.model_id.clone();
    owner
        .record_genesis_with_tunables(root.display().to_string(), 1, String::new(), None)
        .unwrap();
    let (catalog_digest, capability_digest) = directory.selection_digests(&selection);
    let route = PricingRoute {
        provider_id: selection.provider_id.clone(),
        model_id: selection.model_id.clone(),
        catalog_digest: catalog_digest.clone(),
        capability_digest: capability_digest.clone(),
    };
    let key = [42; 32];
    let signed = iteron_obs::sign_rate_card(
        iteron_protocol::RateCard {
            version: iteron_protocol::PricingVersion::V1,
            route: route.clone(),
            provenance: "sdk-paid-native-fixture@v1".into(),
            issued_at_unix_secs: 1,
            expires_at_unix_secs: u64::MAX,
            rates: iteron_protocol::TokenRateCard {
                input_microusd_per_million: 1_000_000,
                output_microusd_per_million: 2_000_000,
                // This fixture server actually reports zero cache writes. Do not promote an
                // omitted count to a measurement; the reported cache-read class still costs.
                cache_creation_microusd_per_million: 0,
                cache_read_microusd_per_million: 1_000_000,
                thinking_microusd_per_million: 0,
            },
        },
        "sdk-fixture-authority",
        key,
    )
    .unwrap();
    owner.set_pricing_port(Arc::new(
        HmacPricingAuthority::new(vec![(signed, HmacPricingKey::from_bytes(key))]).unwrap(),
    ));
    owner
        .install_ordinary_extensions(
            vec![binding(
                OrdinaryDescriptor::Provider(NativeProviderRegistrationV1 {
                    version: 1,
                    name: "sample__paid_native".into(),
                    host_provider_id: selection.provider_id.clone(),
                    host_model_id: selection.model_id.clone(),
                }),
                iteron_marketplace::Surface::Provider,
                CapabilitySet::only(Capability::IrreversibleExternal),
            )],
            &directory,
            None,
        )
        .unwrap();
    owner
        .select_ordinary_extension_provider("sample__paid_native")
        .unwrap();
    // Rebind the same exported route to the actual host-injected TLS transport through the
    // existing journaled operator transaction. No model metadata or physical proof is replaced.
    owner
        .record_operator_model_selection(
            native,
            selection.provider_id.clone(),
            selection.model_id.clone(),
            catalog_digest,
            capability_digest,
        )
        .unwrap();
    assert!(owner.bind_selected_rate_card().unwrap());
    let effective = crate::runtime_tunables::effective_runtime::decode_checkpoint(
        owner.tunables_checkpoint().unwrap(),
        None,
    )
    .unwrap()
    .core;
    let governor = effective.provider_governor;
    assert_eq!(governor.controls.transport, transport_policy);
    owner.set_provider_controls(governor.controls).unwrap();
    owner
        .install_provider_governor(
            governor.policy,
            std::iter::once(owner.governed_route_id()).chain(governor.fallback_routes),
        )
        .unwrap();
    let server_listener = listener.clone();
    let server = tokio::spawn(async move {
        native_request(&server_listener, TlsAcceptor::from(Arc::new(tls))).await
    });
    assert_eq!(
        owner.run("SDK paid native request anchor").await.unwrap(),
        Outcome::Done
    );
    let body = server.await.unwrap();
    assert_eq!(body["model"], "gpt-5.6");
    assert!(
        body["messages"]
            .to_string()
            .contains("SDK paid native request anchor")
    );
    assert!(body["max_tokens"].as_u64().is_some_and(|cap| cap > 0));
    assert!(matches!(
        owner.ledger.cost_state(),
        CostState::Known {
            amount_microusd: 15,
            ..
        }
    ));
    assert_eq!(owner.usd_budget.as_ref().unwrap().spent_microusd(), 15);
    let events = iteron_record::replay(owner.rollout.path()).unwrap();
    assert!(events.iter().any(|event| matches!(&event.kind,
        EventKind::ModelSelected { provider_id, model_id, .. }
            if provider_id == &selection.provider_id && model_id == &selection.model_id)));
    assert!(events.iter().any(|event| matches!(&event.kind,
        EventKind::RateCardBound { rate_card } if rate_card.rate_card.route == route)));
    assert!(events.iter().any(|event| matches!(&event.kind,
    EventKind::TurnEnd { usage, .. } if *usage == Usage {
        input: 8, output: 2, cache_read: 3, cache_creation: 0, thinking: 0
    })));
    let physical = events
        .iter()
        .filter(|event| matches!(&event.kind, EventKind::EffectIntent { tool, .. } if tool == "provider"))
        .collect::<Vec<_>>();
    assert_eq!(
        physical.len(),
        1,
        "exactly one paid native transport was admitted"
    );
    let EventKind::EffectIntent {
        id: physical_id, ..
    } = &physical[0].kind
    else {
        unreachable!()
    };
    let accounted_route = route_accounting_id("sdk-paid-native:gpt-5.6");
    assert!(events.iter().any(|event| matches!(&event.kind,
    EventKind::EffectDone { id, tool, provider_route_attempt: Some(attempt), .. }
        if id == physical_id && tool == "provider"
            && attempt.route_id == accounted_route
            && matches!(&attempt.cost, iteron_protocol::ProviderRouteCostTruth::Known {
                amount_microusd: 15, projection: Some(projection), ..
            } if projection.usage == Usage {
                input: 8, output: 2, cache_read: 3, cache_creation: 0, thinking: 0
            }))));

    // Tighten through the existing durable ceiling transaction to the actual spent amount.
    // This does not change any meter or make another paid request fit by a prompt estimate.
    owner.budget.max_usd = Some(0.000015);
    owner.synchronize_usd_budget().unwrap();
    assert_eq!(owner.effective_max_usd(), Some(0.000015));
    assert_eq!(owner.usd_budget.as_ref().unwrap().ceiling_microusd(), 15);
    let refused = owner
        .follow_up("SDK exhausted native request must never dispatch")
        .await;
    assert!(
        matches!(
            &refused,
            Ok(Outcome::BudgetExhausted("max_usd"))
                | Err(crate::runtime::KernelError::InvalidRouteMetadata {
                    field: "provider_budget_envelope",
                    reason: "remaining hard budget cannot cover physical input and minimum output upper bounds",
                })
        ),
        "the exhausted native route refuses before physical IO: {refused:?}"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
    let after = iteron_record::replay(owner.rollout.path()).unwrap();
    assert_eq!(
        after
            .iter()
            .filter(|event| matches!(&event.kind, EventKind::EffectIntent { tool, .. } if tool == "provider"))
            .count(),
        physical.len()
    );
    assert!(after.iter().any(|event| matches!(
        event.kind,
        EventKind::UsdCeilingChanged {
            max_microusd: 15,
            ..
        }
    )));
    assert_eq!(owner.usd_budget.as_ref().unwrap().spent_microusd(), 15);
    drop(owner);
    std::fs::remove_file(credential).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}
