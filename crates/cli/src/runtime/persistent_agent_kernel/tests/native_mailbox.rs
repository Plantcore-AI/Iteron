//! Actual retained Agent/controller/effect-journal paths with semantic input selected but native
//! serialization absent, unsupported, refused, or successfully retained before consumption.
use super::{
    AgentActor, AgentStateV1, Arc, Ordering, ProviderFixture, Store, Workspace, setup_with_store,
    spawn, until,
};
use iteron_protocol::agent_control::{AgentMessageIdV1, AgentMessageStateV1};
use iteron_protocol::{EventKind, ProviderRouteUsageTruth};

#[tokio::test]
async fn native_omission_and_unsupported_capture_never_consume_or_dispatch() {
    for unsupported_capture in [false, true] {
        let workspace = Workspace::new();
        let provider = Arc::new(ProviderFixture {
            omit_native_user: !unsupported_capture,
            unsupported_capture,
            ..Default::default()
        });
        let (host, runtime, _, _keepalive) =
            setup_with_store(&workspace, provider.clone(), false, Store::default());
        let child = spawn(&host, "semantic mailbox selection is insufficient");
        until(|| {
            host.inspect(AgentActor::Operator, child).is_ok_and(|view| {
                matches!(
                    view.state,
                    AgentStateV1::Idle | AgentStateV1::RecoveryRequired { .. }
                )
            })
        })
        .await;
        assert_eq!(provider.requests.load(Ordering::SeqCst), 0);
        assert_eq!(provider.prepared.load(Ordering::SeqCst), 0);
        assert!(!matches!(
            host.message(AgentActor::Operator, AgentMessageIdV1(1))
                .unwrap()
                .state,
            AgentMessageStateV1::Consumed { .. }
        ));
        let resident = runtime
            .residents
            .lock()
            .unwrap()
            .get(&child)
            .unwrap()
            .clone();
        let child = resident.lock().await;
        let events = iteron_record::replay(child.rollout.path()).unwrap();
        assert!(events.iter().any(|event| matches!(&event.kind,
            EventKind::EffectFailed { tool, provider_route_attempt: Some(receipt), .. }
            if tool == "provider" && receipt.usage == ProviderRouteUsageTruth::NotDispatched)));
        assert!(!events.iter().any(|event| matches!(&event.kind,
            EventKind::EffectDone { tool, .. } if tool == "provider")));
    }
}

#[tokio::test]
async fn retained_native_request_then_failed_controller_barrier_has_zero_dispatch() {
    let workspace = Workspace::new();
    let provider = Arc::new(ProviderFixture::default());
    let (host, runtime, _, _keepalive) = setup_with_store(
        &workspace,
        provider.clone(),
        false,
        Store {
            fail_consumed: true,
            ..Default::default()
        },
    );
    let child = spawn(&host, "prepared request must precede the consumed append");
    until(|| {
        host.inspect(AgentActor::Operator, child).is_ok_and(|view| {
            matches!(
                view.state,
                AgentStateV1::Idle | AgentStateV1::RecoveryRequired { .. }
            )
        })
    })
    .await;
    assert_eq!(provider.requests.load(Ordering::SeqCst), 0);
    assert!(!matches!(
        host.message(AgentActor::Operator, AgentMessageIdV1(1))
            .unwrap()
            .state,
        AgentMessageStateV1::Consumed { .. }
    ));
    let resident = runtime
        .residents
        .lock()
        .unwrap()
        .get(&child)
        .unwrap()
        .clone();
    let child = resident.lock().await;
    let store = crate::artifacts::DurableArtifactStore::from_rollout_writer(
        &child.rollout,
        &child.workspace,
    )
    .unwrap();
    let thread = iteron_protocol::SessionId(child.run_id.0.clone());
    let catalog = store
        .read(
            &thread,
            iteron_protocol::client_artifact::ClientArtifactCommandV1::List {
                thread_id: thread.clone(),
            },
        )
        .unwrap();
    assert!(
        catalog["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["schema"] == "iteron.provider-request-manifest.v1")
    );
    let events = iteron_record::replay(child.rollout.path()).unwrap();
    assert!(events.iter().any(|event| matches!(&event.kind,
        EventKind::EffectFailed { tool, provider_route_attempt: Some(receipt), .. }
        if tool == "provider" && receipt.usage == ProviderRouteUsageTruth::NotDispatched)));
}
