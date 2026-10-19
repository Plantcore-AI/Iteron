use super::*;
use crate::app_server::{navigation_agent, wire};
use crate::client_effects::tunables_simulation::tests::request_bytes;
fn scratch() -> std::path::PathBuf {
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "iteron-scoped-simulation-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    root
}
#[test]
fn simulation_request_has_no_root_tenant_config_or_authority_fields() {
    let input = serde_json::json!({"thread_id":"t","run_id":"r","relative_path":"request.json"});
    assert!(serde_json::from_value::<TunablesLoadV1>(input.clone()).is_ok());
    for name in [
        "workspace",
        "tenant",
        "policy",
        "status",
        "report",
        "resolved_values",
        "activation",
        "actor",
    ] {
        let mut forged = input.clone();
        forged[name] = serde_json::json!("untrusted");
        assert!(serde_json::from_value::<TunablesLoadV1>(forged).is_err());
    }
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_native_read_keeps_slot_and_scope_after_lost_observer_and_respects_ceiling() {
    let root = scratch();
    let mut agent = navigation_agent(&root);
    std::fs::write(root.join("request.json"), request_bytes()).unwrap();
    let (handle, mut ends) = wire().unwrap();
    let thread = SessionId("simulation-thread".into());
    let run = agent.rollout.run_id().clone();
    ends.events
        .bind_lifecycle_identity(thread.clone(), run.clone());
    let reader = ends.events.contract.clone();
    let (settled, _rx) = tokio::sync::mpsc::channel(2);
    let activity = ActivitySurface::capture(
        &agent,
        None,
        None,
        crate::workflow::WorkflowSupervisor::new(settled),
    );
    let (exclusion, service) = reader.workspace_read_admission().unwrap();
    let (started, observed) = std::sync::mpsc::sync_channel(1);
    let (release, wait) = std::sync::mpsc::channel();
    let native = NativeTunablesSimulation::capture(&agent, "request.json".into())
        .unwrap()
        .pause_before_read(started, wait);
    let scope = activity.scope_lease(&reader, &thread, &run).unwrap();
    let slot = service.capacity.clone().try_acquire_owned().unwrap();
    let (reply, receive) = oneshot::channel();
    drop(receive);
    spawn_read(
        native,
        thread.clone(),
        run.clone(),
        scope,
        slot,
        exclusion.try_exclude().unwrap(),
        reply,
    );
    tokio::task::spawn_blocking(move || {
        observed
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap()
    })
    .await
    .unwrap();
    assert!(service.capacity.clone().try_acquire_owned().is_err());
    assert!(activity.client_effect_gate().try_write_owned().is_err());
    assert!(
        handle
            .client
            .submit(iteron_protocol::Op::Steer {
                text: "during physical read".into()
            })
            .is_err()
    );
    release.send(()).unwrap();
    assert!(service.shutdown().await);
    assert!(activity.client_effect_gate().try_write_owned().is_ok());
    let command = || TunablesLoadV1 {
        thread_id: thread.clone(),
        run_id: run.clone(),
        relative_path: "request.json".into(),
    };
    let (reply, receive) = oneshot::channel();
    dispatch(&agent, reader.clone(), &activity, command(), reply);
    let ControlReply::TunablesSimulation(receipt) =
        tokio::time::timeout(std::time::Duration::from_secs(5), receive)
            .await
            .unwrap()
            .unwrap()
    else {
        panic!("actual scoped host view expected")
    };
    assert_eq!(receipt.run_id, run);
    assert_eq!(receipt.thread_id, thread);
    assert_eq!(
        receipt.view.entries.len(),
        iteron_tunables::EXPECTED_FAMILY_COUNT
    );
    assert!(service.shutdown().await);
    agent.narrow_authority_ceiling(iteron_protocol::capability_set::CapabilitySet::none());
    let (reply, receive) = oneshot::channel();
    dispatch(&agent, reader, &activity, command(), reply);
    assert!(matches!(receive.await.unwrap(), ControlReply::Refused(_)));
    assert!(service.capacity.try_acquire().is_ok());
    drop(handle);
    drop(ends);
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}
