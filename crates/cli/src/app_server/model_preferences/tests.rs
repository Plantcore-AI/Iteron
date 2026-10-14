use super::*;
use crate::app_server::{Op, navigation_agent, wire};
use std::path::PathBuf;

fn scratch() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "iteron-model-preference-host-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root.canonicalize().unwrap()
}

#[test]
fn public_read_cannot_supply_preference_target_or_installation_authority() {
    let input = serde_json::json!({"thread_id":"t","run_id":"r","after_revision":0});
    assert!(serde_json::from_value::<ModelPreferenceReadV1>(input.clone()).is_ok());
    for field in [
        "path",
        "provider_id",
        "model_id",
        "status",
        "revision",
        "actor",
        "workspace",
        "tenant",
    ] {
        let mut forged = input.clone();
        forged[field] = serde_json::json!("untrusted");
        assert!(serde_json::from_value::<ModelPreferenceReadV1>(forged).is_err());
    }
}

#[cfg(any(unix, windows))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detached_actual_config_writer_keeps_sq_and_adoption_until_native_result() {
    let root = scratch();
    let agent = navigation_agent(&root);
    let (handle, mut ends) = wire().unwrap();
    let run = agent.rollout.run_id().clone();
    let thread = SessionId("preference-thread".into());
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
    let (exclusion, service) = reader.preference_admission().unwrap();
    let path = root.join("operator-config.json");
    let lock = path.with_extension("json.lock");
    std::fs::write(&path, b"{\"effort\":\"low\"}").unwrap();
    std::fs::write(&lock, b"actual existing config writer lock").unwrap();
    service.state.lock().unwrap().active = true;
    let custody = Custody {
        service: service.clone(),
        lease: Some(Lease {
            _scope: activity.scope_lease(&reader, &thread, &run).unwrap(),
            _submissions: exclusion.try_exclude().unwrap(),
        }),
        started: false,
    };
    // This is the same detached physical dispatch used only after the real route receipt. There
    // is no retained observer/JoinHandle; the actual global lock keeps installation incomplete.
    start_native_write(
        Some(UserPreferenceTarget::fixture(path.clone())),
        thread.clone(),
        run.clone(),
        "fixture-navigation".into(),
        "m".into(),
        custody,
    );
    assert_eq!(
        reader.model_preference_after(0).unwrap().status,
        PreferenceWriteStatus::Pending
    );
    assert!(
        handle
            .client
            .submit(Op::Steer {
                text: "cannot race the physical writer".into()
            })
            .is_err()
    );
    assert!(activity.client_effect_gate().try_write_owned().is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"{\"effort\":\"low\"}");
    std::fs::remove_file(lock).unwrap();
    assert!(service.shutdown().await);
    let receipt = read(
        &reader,
        ModelPreferenceReadV1 {
            thread_id: thread.clone(),
            run_id: run.clone(),
            after_revision: 0,
        },
    );
    let ControlReply::ModelPreference(Some(receipt)) = receipt else {
        panic!("actual host receipt expected")
    };
    assert_eq!(receipt.status, PreferenceWriteStatus::Installed);
    let written: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(written["provider"], "fixture-navigation");
    assert_eq!(written["model"], "m");
    assert_eq!(written["effort"], "low");
    assert!(activity.client_effect_gate().try_write_owned().is_ok());
    assert!(
        handle
            .client
            .submit(Op::Steer {
                text: "after actual installation".into()
            })
            .is_ok()
    );
    assert!(matches!(
        read(
            &reader,
            ModelPreferenceReadV1 {
                thread_id: thread,
                run_id: RunId("foreign".into()),
                after_revision: 0
            }
        ),
        ControlReply::Refused(_)
    ));
    drop(handle);
    drop(ends);
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn refused_selection_leaves_previous_native_receipt_unchanged() {
    let root = scratch();
    let agent = navigation_agent(&root);
    let (handle, mut ends) = wire().unwrap();
    let thread = SessionId("preference-thread".into());
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
    let (exclusion, service) = reader.preference_admission().unwrap();
    {
        let mut state = service.state.lock().unwrap();
        state.revision = 2;
        state.active = true;
        state.last = Some(PreferenceReceipt {
            thread_id: thread.clone(),
            run_id: run.clone(),
            revision: 2,
            provider_id: "previous".into(),
            model_id: "previous-model".into(),
            status: PreferenceWriteStatus::Installed,
        });
    }
    let mut custody = Custody {
        service: service.clone(),
        lease: Some(Lease {
            _scope: activity.scope_lease(&reader, &thread, &run).unwrap(),
            _submissions: exclusion.try_exclude().unwrap(),
        }),
        started: false,
    };
    custody.finish(PreferenceWriteStatus::NotInstalled);
    let previous = service.after(0).unwrap();
    assert_eq!(previous.revision, 2);
    assert_eq!(previous.provider_id, "previous");
    assert_eq!(previous.status, PreferenceWriteStatus::Installed);
    assert!(service.shutdown().await);
    drop(handle);
    drop(ends);
    drop(agent);
    std::fs::remove_dir_all(root).unwrap();
}
