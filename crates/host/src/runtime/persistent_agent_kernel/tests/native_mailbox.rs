//! Actual retained Agent/controller/effect-journal paths with semantic input selected but native
//! serialization absent, unsupported, or refused before consumption and physical dispatch.
use super::{
    AgentActor, AgentStateV1, Arc, Ordering, ProviderFixture, Store, Workspace, setup_with_store,
    spawn, until,
};
use crate::runtime::persistent_agents::AgentControlPort;
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
async fn native_request_then_failed_controller_barrier_has_zero_dispatch() {
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
    assert_eq!(
        provider.native_preparation_attempts.load(Ordering::SeqCst),
        1
    );
    assert_eq!(provider.prepared.load(Ordering::SeqCst), 0);
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
    // The standalone persistence contract separates actual native-input confirmation from
    // optional request diagnostics. This failed controller barrier must retain its compact
    // causal journal, not invent a successful preparation or an archive disabled by default.
    // Opt-in publication/reopen and failed-invocation drain remain independently covered by
    // request_manifest_tests::{physical_manifest_sources_and_scrubbed_bytes_survive_actual_writer_reopen,
    // failed_invocations_drain_prepared_diagnostics_while_the_agent_remains_resident}.
    child.flush_request_archive().unwrap();
    let archive = child.request_archive_status();
    assert_eq!(archive["enabled"], false);
    assert_eq!(archive["availability"], "not_captured");
    assert_eq!(archive["submitted_requests"], 0);
    assert_eq!(archive["pending_requests"], 0);
    assert_eq!(archive["failed_captures"], 0);
    let store = crate::artifacts::DurableArtifactStore::from_rollout_writer(
        &child.rollout,
        &child.workspace,
    )
    .unwrap();
    let thread = iteron_protocol::SessionId(child.rollout.run_id().0.clone());
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
            .all(|row| row["schema"] != "iteron.provider-request-manifest.v1"),
        "default compact journaling must not fabricate an optional request manifest"
    );
    let events = iteron_record::replay(child.rollout.path()).unwrap();
    let intents: Vec<_> = events
        .iter()
        .filter_map(|event| match &event.kind {
            EventKind::EffectIntent {
                id,
                tool,
                provider_route_attempt: Some(identity),
                ..
            } if tool == "provider" => Some((event, id, identity)),
            _ => None,
        })
        .collect();
    assert_eq!(
        intents.len(),
        1,
        "one native attempt needs one durable intent"
    );
    let (intent, effect_id, identity) = intents[0];
    let failures: Vec<_> = events
        .iter()
        .filter_map(|event| match &event.kind {
            EventKind::EffectFailed {
                id,
                tool,
                provider_route_attempt: Some(receipt),
                ..
            } if tool == "provider" && id == effect_id => Some((event, receipt)),
            _ => None,
        })
        .collect();
    assert_eq!(
        failures.len(),
        1,
        "the admitted intent needs one failed terminal"
    );
    let (failure, receipt) = failures[0];
    assert_eq!(failure.turn, intent.turn);
    assert!(failure.seq.0 > intent.seq.0);
    assert_eq!(&receipt.identity(), identity);
    assert_eq!(receipt.usage, ProviderRouteUsageTruth::NotDispatched);
    assert!(!events.iter().any(|event| matches!(&event.kind,
        EventKind::EffectDone { tool, .. } | EventKind::EffectUnknown { tool, .. }
        if tool == "provider")));
}
