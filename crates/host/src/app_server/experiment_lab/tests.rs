use super::*;
use crate::app_server::wire;
use crate::client_effects::experiment_lab::tests::{fixture, request};

#[test]
fn lab_command_cannot_supply_roots_effect_receipts_or_activation_authority() {
    let command = serde_json::json!({"thread_id":"t","run_id":"r","action":{"type":"list"}});
    assert!(serde_json::from_value::<LabCommandV1>(command.clone()).is_ok());
    for field in [
        "workspace",
        "tenant",
        "actor",
        "policy",
        "root",
        "promotion",
        "scope_epoch",
        "config",
    ] {
        let mut forged = command.clone();
        forged[field] = serde_json::json!("untrusted");
        assert!(serde_json::from_value::<LabCommandV1>(forged).is_err());
    }
    let mut activation = command;
    activation["action"] = serde_json::json!({"type":"promote","bundle_id":"b"});
    assert!(serde_json::from_value::<LabCommandV1>(activation).is_err());
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_observer_retains_real_native_request_slot_sq_and_adoption_until_completion() {
    let (root, agent) = fixture();
    let (handle, mut ends) = wire().unwrap();
    let thread = SessionId("lab-thread".into());
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
    let (exclusion, service) = reader.lab_admission().unwrap();
    let (started, observed) = std::sync::mpsc::sync_channel(1);
    let (release, wait) = std::sync::mpsc::channel();
    let native = request(&agent).pause(started, wait);
    let custody = Custody {
        service: service.clone(),
        lease: Some(Lease {
            _scope: activity.scope_lease(&reader, &thread, &run).unwrap(),
            _sq: exclusion.try_exclude().unwrap(),
            _slot: service.capacity.clone().try_acquire_owned().unwrap(),
        }),
        mutating: true,
    };
    let (reply, receive) = oneshot::channel();
    drop(receive);
    spawn_native(native, thread, run, custody, reply);
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
                text: "during physical lab write".into()
            })
            .is_err()
    );
    release.send(()).unwrap();
    assert!(service.shutdown().await);
    assert!(activity.client_effect_gate().try_write_owned().is_ok());
    assert!(service.unresolved.lock().unwrap().is_none());
    assert_eq!(
        std::fs::read_dir(root.join(".iteron/experiments/requests"))
            .unwrap()
            .count(),
        1
    );
    drop(reader);
    drop(service);
    drop(handle);
    drop(ends);
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_published_file_without_host_receipt_keeps_unknown_custody() {
    let (root, agent) = fixture();
    let (handle, mut ends) = wire().unwrap();
    let thread = SessionId("lost-lab-receipt".into());
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
    let (exclusion, service) = reader.lab_admission().unwrap();
    let custody = Custody {
        service: service.clone(),
        lease: Some(Lease {
            _scope: activity.scope_lease(&reader, &thread, &run).unwrap(),
            _sq: exclusion.try_exclude().unwrap(),
            _slot: service.capacity.clone().try_acquire_owned().unwrap(),
        }),
        mutating: true,
    };
    let (reply, receive) = oneshot::channel();
    spawn_native(
        request(&agent).panic_after_publish(),
        thread,
        run,
        custody,
        reply,
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(5), receive)
            .await
            .unwrap()
            .is_err()
    );
    let file = std::fs::read_dir(root.join(".iteron/experiments/requests"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let actual: serde_json::Value =
        serde_json::from_slice(&std::fs::read(file.path()).unwrap()).unwrap();
    assert_eq!(actual["status"], "requested");
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            if service.unresolved.lock().unwrap().is_some() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(service.unresolved.lock().unwrap().is_some());
    assert!(service.capacity.clone().try_acquire_owned().is_err());
    assert!(activity.client_effect_gate().try_write_owned().is_err());
    assert!(
        handle
            .client
            .submit(iteron_protocol::Op::Steer {
                text: "unsafe adoption".into()
            })
            .is_err()
    );
    drop(reader);
    drop(service);
    drop(handle);
    drop(ends);
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}
