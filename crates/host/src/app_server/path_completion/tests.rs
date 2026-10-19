use super::fixture::*;
use std::time::Duration;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_completion_observer_retains_real_worker_slot_and_adoption_scope() {
    let (root, agent) = crate::client_effects::experiment_lab::tests::fixture();
    std::fs::write(root.join("actual.txt"), b"native candidate").unwrap();
    let fixture = host_from_agent(agent);
    let (start, started) = std::sync::mpsc::sync_channel(1);
    let (release, wait) = std::sync::mpsc::channel();
    let mut port = fixture.port();
    port.binding.source = port.binding.source.pause(start, wait);
    let observer = tokio::spawn(port.complete("act".into()));
    tokio::task::spawn_blocking(move || started.recv_timeout(Duration::from_secs(3)).unwrap())
        .await
        .unwrap();
    observer.abort();
    let _ = observer.await;
    assert!(
        fixture
            .activity
            .client_effect_gate()
            .try_write_owned()
            .is_err()
    );
    assert!(fixture.port().complete("act".into()).await.is_err());
    release.send(()).unwrap();
    assert!(fixture.wait_physical().await);
    assert!(
        fixture
            .activity
            .client_effect_gate()
            .try_write_owned()
            .is_ok()
    );
    assert_eq!(
        fixture.port().complete("act".into()).await.unwrap().items,
        vec!["actual.txt"]
    );
    assert!(fixture.shutdown().await);
    assert!(fixture.port().complete("act".into()).await.is_err());
    drop(fixture);
    std::fs::remove_dir_all(root).unwrap();
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[tokio::test]
async fn actual_authority_tightening_invalidates_captured_port_before_native_scan() {
    let (root, agent) = crate::client_effects::experiment_lab::tests::fixture();
    let mut fixture = host_from_agent(agent);
    let old = fixture.port();
    fixture
        .agent
        .narrow_authority_ceiling(iteron_protocol::capability_set::CapabilitySet::none());
    fixture
        .ends
        .events
        .contract
        .refresh_path_completion(&fixture.agent);
    assert!(old.complete("".into()).await.is_err());
    assert!(fixture.port().complete("".into()).await.is_err());
    assert!(fixture.shutdown().await);
    drop(fixture);
    std::fs::remove_dir_all(root).unwrap();
}
