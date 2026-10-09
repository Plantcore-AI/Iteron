//! Actual ordinary SDK Agent/native-route/record/observer journeys; final unified gate pending.
use super::*;
use crate::plugin_runtime::ordinary::{OrdinaryBinding, OrdinaryDescriptor};
use crate::runtime::{Agent, KernelError, Outcome, gate_integration_tests};
use iteron_extension_sdk::UiStatusV1;
use iteron_protocol::capability_set::CapabilitySet;
use iteron_protocol::{
    Block, Budget, Capability, EventKind, PermissionMode, PricingRoute, RunId, StopReason,
    TenantId, ToolUse, Usage, Verdict,
};
use iteron_provider::{Provider, ProviderError, StreamItem, TurnRequest, TurnResult, UsageReport};
use iteron_record::Rollout;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
struct NativeToolJourney {
    calls: AtomicUsize,
}
#[async_trait::async_trait]
impl Provider for NativeToolJourney {
    async fn turn(
        &self,
        request: &TurnRequest,
        _: &mut (dyn FnMut(StreamItem) + Send),
    ) -> Result<TurnResult, ProviderError> {
        let index = self.calls.fetch_add(1, Ordering::AcqRel);
        let blocks = if index == 0 {
            assert!(request.tools.iter().any(|tool| tool.name == "sample__read"));
            vec![Block::ToolUse(ToolUse {
                id: "sdk-read-call".into(),
                name: "sample__read".into(),
                input: json!({}),
            })]
        } else {
            vec![Block::Text {
                text: "native SDK journey completed".into(),
            }]
        };
        Ok(TurnResult {
            blocks,
            stop_reason: if index == 0 {
                StopReason::ToolUse
            } else {
                StopReason::EndTurn
            },
            usage: UsageReport::complete(Usage::default()),
        })
    }
}
fn agent(workspace: &std::path::Path, run: &RunId, provider: Arc<dyn Provider>) -> Agent {
    agent_with_budget(workspace, run, provider, Budget::default())
}
fn agent_with_budget(
    workspace: &std::path::Path,
    run: &RunId,
    provider: Arc<dyn Provider>,
    budget: Budget,
) -> Agent {
    let rollout = Rollout::open(&workspace.join(".iteron/runs"), run, TenantId::default()).unwrap();
    let mut agent = Agent::new(
        provider,
        iteron_tools::Registry::coding_agent_for_tests(workspace).unwrap(),
        rollout,
        "fixture-model".into(),
        "fixture system".into(),
        budget,
    );
    agent.workspace = workspace.to_owned();
    gate_integration_tests::pin_test_tunables_with_edits(&mut agent, []);
    agent
}
fn binding(
    descriptor: OrdinaryDescriptor,
    surface: iteron_marketplace::Surface,
    capabilities: CapabilitySet,
) -> OrdinaryBinding {
    OrdinaryBinding {
        plugin: "sample-sdk".into(),
        version: "1.0.0".into(),
        manifest_sha256: "a".repeat(64),
        surface,
        key: descriptor.name().into(),
        capabilities,
        descriptor,
    }
}
fn bindings() -> Vec<OrdinaryBinding> {
    vec![
        binding(
            OrdinaryDescriptor::Tool(iteron_extension_sdk::ToolRecipeV1 {
                version: 1,
                name: "sample__read".into(),
                description: "Native sample note reader".into(),
                primitive: "read_file".into(),
                fixed_arguments: json!({"path":"notes.md"}).as_object().unwrap().clone(),
                write_paths: vec![],
            }),
            iteron_marketplace::Surface::Tool,
            CapabilitySet::only(Capability::ReadOnly),
        ),
        binding(
            OrdinaryDescriptor::Ui(UiStatusV1 {
                version: 1,
                name: "sample__status".into(),
                label: "Native tools".into(),
                facts: vec![StatusFactV1::ToolCalls, StatusFactV1::Phase],
            }),
            iteron_marketplace::Surface::Ui,
            CapabilitySet::only(Capability::ReadOnly),
        ),
        binding(
            OrdinaryDescriptor::EventSubscription(EventSubscriptionV1 {
                version: 1,
                name: "sample__events".into(),
                event_ids: vec!["model.request_sent".into()],
                queue_capacity: 4,
            }),
            iteron_marketplace::Surface::EventSubscription,
            CapabilitySet::only(Capability::ReadOnly),
        ),
    ]
}
#[tokio::test]
async fn actual_main_native_recipe_and_same_owner_status_events_reopen_without_rebinding() {
    let root = gate_integration_tests::temp_ws("sdk-native-main");
    std::fs::write(root.join("notes.md"), "sdk-read-anchor").unwrap();
    let run = RunId("sdk-native-main".into());
    let provider = Arc::new(NativeToolJourney {
        calls: AtomicUsize::new(0),
    });
    let mut owner = agent(&root, &run, provider.clone());
    owner
        .record_genesis_with_tunables(root.display().to_string(), 1, String::new(), None)
        .unwrap();
    let directory = ProviderDirectory::inspect_local(&[]).unwrap();
    owner
        .install_ordinary_extensions(bindings(), &directory, None)
        .unwrap();
    let port = owner.ordinary_extensions_port().unwrap();
    let before = port.snapshot().unwrap();
    assert_eq!(before.status.widgets.len(), 1);
    assert_eq!(before.event_subscriptions, vec!["sample__events"]);
    assert_eq!(
        owner.run("read notes using sample__read").await.unwrap(),
        Outcome::Done
    );
    assert_eq!(provider.calls.load(Ordering::Acquire), 2);
    let events = port.events("sample__events", 64, 0).unwrap();
    assert!(!events.events.is_empty());
    let status = port.snapshot().unwrap();
    assert!(
        matches!(&status.status.widgets[0].values[&StatusFactV1::ToolCalls],HostStatusValueV1::Known{value}if value=="1")
    );
    let path = owner.rollout.path().to_owned();
    let replay = iteron_record::replay(&path).unwrap();
    assert!(replay.iter().any(|event|matches!(&event.kind,EventKind::ToolDone{result,tool,..}if tool.as_deref()==Some("sample__read")&&!result.is_error&&result.content.contains("sdk-read-anchor"))));
    assert_eq!(
        replay
            .iter()
            .filter(|event| matches!(event.kind, EventKind::OrdinaryExtensionBindingsV1 { .. }))
            .count(),
        1
    );
    drop(owner);
    let mut resumed = agent(&root, &run, provider);
    resumed
        .set_resume(Agent::messages_from_rollout(&path).unwrap())
        .unwrap();
    resumed
        .install_ordinary_extensions(bindings(), &directory, None)
        .unwrap();
    assert_eq!(
        resumed
            .ordinary_extensions_port()
            .unwrap()
            .snapshot()
            .unwrap()
            .catalog_sha256,
        before.catalog_sha256
    );
    drop(resumed);
    std::fs::remove_dir_all(root).unwrap();
}
#[tokio::test]
async fn actual_main_alias_obeys_base_named_deny_even_with_bypass() {
    let root = gate_integration_tests::temp_ws("sdk-base-deny");
    std::fs::write(root.join("notes.md"), "must-not-read").unwrap();
    let run = RunId("sdk-base-deny".into());
    let mut owner = agent(
        &root,
        &run,
        Arc::new(NativeToolJourney {
            calls: AtomicUsize::new(0),
        }),
    );
    let mut rules = iteron_protocol::PermissionRules::default();
    rules.set_tool("read_file", Verdict::Deny);
    owner.bypass_permissions = true;
    owner
        .configure_initial_runtime_policy(
            iteron_protocol::Effort::Medium,
            PermissionMode::Default,
            rules,
        )
        .unwrap();
    owner
        .record_genesis_with_tunables(root.display().to_string(), 1, String::new(), None)
        .unwrap();
    owner
        .install_ordinary_extensions(
            bindings(),
            &ProviderDirectory::inspect_local(&[]).unwrap(),
            None,
        )
        .unwrap();
    assert_eq!(owner.run("read notes").await.unwrap(), Outcome::Done);
    assert!(iteron_record::replay(owner.rollout.path()).unwrap().iter().any(|event|matches!(&event.kind,EventKind::ToolDone{result,tool,..}if tool.as_deref()==Some("sample__read")&&result.is_error&&!result.content.contains("must-not-read"))));
    drop(owner);
    std::fs::remove_dir_all(root).unwrap();
}
#[tokio::test]
async fn reopened_catalog_change_refuses_and_removes_every_new_executable_alias() {
    let root = gate_integration_tests::temp_ws("sdk-catalog-mismatch");
    let run = RunId("sdk-catalog-mismatch".into());
    let provider = Arc::new(NativeToolJourney {
        calls: AtomicUsize::new(0),
    });
    let directory = ProviderDirectory::inspect_local(&[]).unwrap();
    let mut owner = agent(&root, &run, provider.clone());
    owner
        .record_genesis_with_tunables(root.display().to_string(), 1, String::new(), None)
        .unwrap();
    owner
        .install_ordinary_extensions(bindings(), &directory, None)
        .unwrap();
    drop(owner);
    let mut reopened = agent(&root, &run, provider);
    let mut changed = bindings();
    if let OrdinaryDescriptor::Tool(recipe) = &mut changed[0].descriptor {
        recipe
            .fixed_arguments
            .insert("path".into(), json!("different.md"));
    }
    assert!(
        reopened
            .install_ordinary_extensions(changed, &directory, None)
            .is_err()
    );
    assert!(reopened.ordinary_extensions_port().is_none());
    assert!(reopened.registry.capability_of("sample__read").is_none());
    assert!(reopened.registry.capability_of("read_file").is_some());
    drop(reopened);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn reopened_unbound_message_v2_refuses_catalog_without_aliases_binding_or_provider_io() {
    use iteron_protocol::{
        Event, ImageContent, ImageMediaType, Message, Role, Seq, TurnId,
        tool_image::{ToolImageObservationV1, ToolImageScopeV1},
    };
    let scratch = crate::runtime::test_tempdir::tempdir().unwrap();
    let root = scratch.path();
    let run = RunId("sdk-unbound-message-v2".into());
    let provider = Arc::new(NativeToolJourney {
        calls: AtomicUsize::new(0),
    });
    let mut owner = agent(root, &run, provider.clone());
    owner
        .record_genesis_with_tunables(root.display().to_string(), 1, String::new(), None)
        .unwrap();
    // Synthetic, validated untrusted pixels exercise the actual new record vocabulary. This
    // observation is data; it grants no tool effect or terminal authority to this fixture.
    let observation = ToolImageObservationV1 {
        version: 1,
        tool_use_id: "unbound-pixels".into(),
        owner_tenant: TenantId::default(),
        owner_run: run.clone(),
        terminal_seq: Seq(1),
        observed_unix_ms: 1,
        source_url_display: "https://example.com/".into(),
        scope: ToolImageScopeV1::IsolatedBrowserViewport,
        artifact_id: "a38a4ff7320a3d8764ac959b264f15e335360d7c1e23a0627dee7f366c95c58f".into(),
        width: 1,
        height: 1,
        image: ImageContent::new(ImageMediaType::Png, "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/l9sAAAAASUVORK5CYII=").unwrap(),
    };
    observation.validate().unwrap();
    let kind = EventKind::message(Message {
        role: Role::User,
        content: vec![Block::ToolImage(observation)],
    });
    assert!(matches!(kind, EventKind::MessageV2 { .. }));
    owner
        .rollout
        .append(&Event {
            seq: Seq::ZERO,
            turn: TurnId(0),
            kind,
        })
        .unwrap();
    let path = owner.rollout.path().to_owned();
    drop(owner);

    let mut reopened = agent(root, &run, provider.clone());
    let prior_bytes = std::fs::read(&path).unwrap();
    let replay = iteron_record::replay(&path).unwrap();
    assert!(
        replay
            .iter()
            .any(|event| matches!(event.kind, EventKind::MessageV2 { .. }))
    );
    assert!(!replay.iter().any(|event| matches!(
        event.kind,
        EventKind::Message { .. }
            | EventKind::EffectIntent { .. }
            | EventKind::OrdinaryExtensionBindingsV1 { .. }
    )));
    let result = reopened.install_ordinary_extensions(
        bindings(),
        &ProviderDirectory::inspect_local(&[]).unwrap(),
        None,
    );
    assert!(matches!(
        result,
        Err(KernelError::OrdinaryExtension(
            "ordinary SDK cannot replace an unbound historical lineage"
        ))
    ));
    assert!(reopened.ordinary_extensions_port().is_none());
    assert!(reopened.registry.capability_of("sample__read").is_none());
    assert!(reopened.registry.capability_of("read_file").is_some());
    assert_eq!(provider.calls.load(Ordering::Acquire), 0);
    assert_eq!(std::fs::read(&path).unwrap(), prior_bytes);
    assert!(
        !iteron_record::replay(&path)
            .unwrap()
            .iter()
            .any(|event| matches!(event.kind, EventKind::OrdinaryExtensionBindingsV1 { .. }))
    );
    drop(reopened);
}

#[test]
fn actual_emitter_rebind_uses_the_new_bus_and_keeps_old_bus_events_unavailable() {
    let root = gate_integration_tests::temp_ws("sdk-real-bus-rebind");
    let run = RunId("sdk-real-bus-rebind".into());
    let mut owner = agent(
        &root,
        &run,
        Arc::new(NativeToolJourney {
            calls: AtomicUsize::new(0),
        }),
    );
    owner
        .record_genesis_with_tunables(root.display().to_string(), 1, String::new(), None)
        .unwrap();
    owner
        .install_ordinary_extensions(
            bindings(),
            &ProviderDirectory::inspect_local(&[]).unwrap(),
            None,
        )
        .unwrap();
    let old = owner.lifecycle_emitter.clone().unwrap();
    let port = owner.ordinary_extensions_port().unwrap();
    let next = iteron_obs::lifecycle::LifecycleEmitter::new(
        iteron_obs::lifecycle::LifecycleBus::default(),
    );
    owner.set_lifecycle_emitter(next);
    old.emit(
        "model.request_sent",
        iteron_obs::lifecycle::LifecycleCorrelation::default(),
        iteron_protocol::LifecyclePayload::default(),
    )
    .unwrap();
    assert!(
        port.events("sample__events", 64, 0)
            .unwrap()
            .events
            .is_empty()
    );
    owner.lifecycle_event(
        "model.request_sent",
        None,
        iteron_protocol::LifecyclePayload::default(),
    );
    assert_eq!(
        port.events("sample__events", 64, 0).unwrap().events.len(),
        1
    );
    drop(owner);
    std::fs::remove_dir_all(root).unwrap();
}
#[cfg(unix)]
#[tokio::test]
async fn native_provider_export_uses_signed_route_and_cannot_dispatch_over_a_financial_ceiling() {
    use std::os::unix::fs::PermissionsExt;
    let root = gate_integration_tests::temp_ws("sdk-native-budget");
    let credential = root.with_extension("sdk-credential");
    std::fs::write(
        &credential,
        "fixture-native-token
",
    )
    .unwrap();
    std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("https://{}/v1", listener.local_addr().unwrap());
    let configured = crate::config::ProviderConfig {
        id: "sdk-native".into(),
        display_name: Some("SDK native fixture".into()),
        adapter: "openai_chat".into(),
        error_profile: None,
        api_root: endpoint,
        key_env: None,
        credential: Some(crate::config::ProviderCredential::File {
            path: credential.display().to_string(),
        }),
        enabled: true,
        catalog: false,
        models: vec!["sdk-model".into()],
        model_capabilities: BTreeMap::new(),
    };
    let directory = ProviderDirectory::inspect_local(&[configured]).unwrap();
    let selection = ModelSelection {
        provider_id: "sdk-native".into(),
        model_id: "sdk-model".into(),
    };
    let provider = directory.build(&selection).unwrap();
    let run = RunId("sdk-native-budget".into());
    let mut owner = agent_with_budget(
        &root,
        &run,
        provider,
        Budget {
            max_usd: Some(0.000001),
            ..Budget::default()
        },
    );
    owner.model = "sdk-model".into();
    owner
        .record_genesis_with_tunables(root.display().to_string(), 1, String::new(), None)
        .unwrap();
    let route = PricingRoute {
        provider_id: "sdk-native".into(),
        model_id: "sdk-model".into(),
        catalog_digest: directory.selection_digests(&selection).0,
        capability_digest: directory.selection_digests(&selection).1,
    };
    let key = [42; 32];
    let signed = iteron_obs::sign_rate_card(
        iteron_protocol::RateCard {
            version: iteron_protocol::PricingVersion::V1,
            route,
            provenance: "sdk-native-fixture@v1".into(),
            issued_at_unix_secs: 1,
            expires_at_unix_secs: u64::MAX,
            rates: iteron_protocol::TokenRateCard {
                input_microusd_per_million: 1_000_000,
                output_microusd_per_million: 2_000_000,
                cache_creation_microusd_per_million: 1_250_000,
                cache_read_microusd_per_million: 100_000,
                thinking_microusd_per_million: 3_000_000,
            },
        },
        "sdk-fixture-authority",
        key,
    )
    .unwrap();
    let pricing = Arc::new(
        iteron_obs::HmacPricingAuthority::new(vec![(
            signed,
            iteron_obs::HmacPricingKey::from_bytes(key),
        )])
        .unwrap(),
    );
    owner.set_pricing_port(pricing);
    let all = CapabilitySet::from_iter_capabilities([
        Capability::ReadOnly,
        Capability::IrreversibleExternal,
    ]);
    owner
        .install_ordinary_extensions(
            vec![binding(
                OrdinaryDescriptor::Provider(NativeProviderRegistrationV1 {
                    version: 1,
                    name: "sample__provider".into(),
                    host_provider_id: "sdk-native".into(),
                    host_model_id: "sdk-model".into(),
                }),
                iteron_marketplace::Surface::Provider,
                all,
            )],
            &directory,
            None,
        )
        .unwrap();
    owner
        .select_ordinary_extension_provider("sample__provider")
        .unwrap();
    let snapshot = owner
        .ordinary_extensions_port()
        .unwrap()
        .snapshot()
        .unwrap();
    assert_eq!(snapshot.providers[0].host_provider_id, "sdk-native");
    assert!(matches!(
        owner
            .run("must not exceed the signed budget")
            .await
            .unwrap(),
        Outcome::BudgetExhausted(_)
    ));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
    let replay = iteron_record::replay(owner.rollout.path()).unwrap();
    assert!(
        replay
            .iter()
            .any(|event| matches!(event.kind, EventKind::RateCardBound { .. }))
    );
    assert!(
        !replay
            .iter()
            .any(|event| matches!(event.kind, EventKind::EffectIntent { .. }))
    );
    drop(owner);
    std::fs::remove_file(credential).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn ordinary_provider_export_drives_the_real_native_http_adapter_and_wal() {
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let root = gate_integration_tests::temp_ws("sdk-native-io");
    let credential = root.with_extension("sdk-native-credential");
    std::fs::write(&credential, "fixture-native-token\n").unwrap();
    std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) =
            tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap();
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 4096];
        let mut expected = None;
        loop {
            let read =
                tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut chunk))
                    .await
                    .unwrap()
                    .unwrap();
            assert!(read > 0);
            assert!(bytes.len() + read <= 1024 * 1024);
            bytes.extend_from_slice(&chunk[..read]);
            if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                if expected.is_none() {
                    let headers = std::str::from_utf8(&bytes[..end]).unwrap();
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            line.split_once(':')
                                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                                .map(|(_, value)| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap();
                    assert!(length <= 1024 * 1024);
                    expected = Some((end + 4, length));
                }
                let (start, length) = expected.unwrap();
                if bytes.len() >= start + length {
                    let body: serde_json::Value =
                        serde_json::from_slice(&bytes[start..start + length]).unwrap();
                    assert_eq!(body["model"], "sdk-model");
                    assert!(
                        body["messages"]
                            .to_string()
                            .contains("SDK native request anchor")
                    );
                    break;
                }
            }
        }
        let response = concat!(
            "data: {\"id\":\"sdk-native-response\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"SDK native answer\"},\"finish_reason\":null}],\"usage\":null}\n\n",
            "data: {\"id\":\"sdk-native-response\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5,\"prompt_tokens_details\":{\"cached_tokens\":0},\"completion_tokens_details\":{\"reasoning_tokens\":0}}}\n\n",
            "data: [DONE]\n\n"
        );
        let reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
            response.len()
        );
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.write_all(reply.as_bytes()),
        )
        .await
        .unwrap()
        .unwrap();
    });
    let config = crate::config::ProviderConfig {
        id: "sdk-native".into(),
        display_name: None,
        adapter: "openai_chat".into(),
        error_profile: None,
        api_root: format!("http://{address}/v1"),
        key_env: None,
        credential: Some(crate::config::ProviderCredential::File {
            path: credential.display().to_string(),
        }),
        enabled: true,
        catalog: false,
        models: vec!["sdk-model".into()],
        model_capabilities: BTreeMap::new(),
    };
    let directory = ProviderDirectory::inspect_local(&[config]).unwrap();
    let selection = ModelSelection {
        provider_id: "sdk-native".into(),
        model_id: "sdk-model".into(),
    };
    let provider = directory.build(&selection).unwrap();
    let run = RunId("sdk-native-io".into());
    let mut owner = agent(&root, &run, provider);
    owner.model = "sdk-model".into();
    owner
        .record_genesis_with_tunables(root.display().to_string(), 1, String::new(), None)
        .unwrap();
    owner
        .install_ordinary_extensions(
            vec![binding(
                OrdinaryDescriptor::Provider(NativeProviderRegistrationV1 {
                    version: 1,
                    name: "sample__native".into(),
                    host_provider_id: "sdk-native".into(),
                    host_model_id: "sdk-model".into(),
                }),
                iteron_marketplace::Surface::Provider,
                CapabilitySet::only(Capability::IrreversibleExternal),
            )],
            &directory,
            None,
        )
        .unwrap();
    owner
        .select_ordinary_extension_provider("sample__native")
        .unwrap();
    assert_eq!(
        owner.run("SDK native request anchor").await.unwrap(),
        Outcome::Done
    );
    server.await.unwrap();
    let events = iteron_record::replay(owner.rollout.path()).unwrap();
    assert!(events.iter().any(|event|matches!(&event.kind,EventKind::ModelSelected{provider_id,model_id,..}if provider_id=="sdk-native"&&model_id=="sdk-model")));
    assert!(
        events
            .iter()
            .any(|event| matches!(event.kind, EventKind::EffectIntent { .. }))
    );
    assert!(
        Agent::messages_from_rollout(owner.rollout.path())
            .unwrap()
            .iter()
            .any(|message| serde_json::to_string(message)
                .unwrap()
                .contains("SDK native answer"))
    );
    drop(owner);
    std::fs::remove_file(credential).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}
