use super::*;
use crate::app_server::{AppServerHandle, ServerEnds, navigation_agent, wire};
use std::time::Duration;
pub(crate) struct HostFixture {
    agent: Agent,
    handle: AppServerHandle,
    ends: ServerEnds,
    activity: ActivitySurface,
}
pub(crate) fn host_fixture(root: &std::path::Path) -> HostFixture {
    let agent = navigation_agent(root);
    host_from_agent(agent)
}
fn host_from_agent(agent: Agent) -> HostFixture {
    let (handle, mut ends) = wire().unwrap();
    let thread = SessionId("completion-thread".into());
    let run = agent.rollout.run_id().clone();
    ends.events.bind_lifecycle_identity(thread, run);
    let (settled, _receiver) = tokio::sync::mpsc::channel(2);
    let activity = ActivitySurface::capture(
        &agent,
        None,
        None,
        crate::workflow::WorkflowSupervisor::new(settled),
    );
    ends.events.contract.bind_export_owner(&agent, &activity);
    HostFixture {
        agent,
        handle,
        ends,
        activity,
    }
}
impl HostFixture {
    pub(crate) fn port(&self) -> PathCompletionPort {
        self.handle
            .client
            .path_completion_port(self.agent.rollout.run_id())
            .unwrap()
    }
    pub(crate) async fn shutdown(&self) -> bool {
        self.ends.events.contract.shutdown_path_completions().await
    }
    async fn wait_physical(&self) -> bool {
        let binding = self.ends.events.contract.completion_binding().unwrap();
        let capacity = binding.service.capacity.get().unwrap().clone();
        tokio::time::timeout(Duration::from_secs(5), capacity.acquire_owned())
            .await
            .is_ok_and(|permit| permit.is_ok())
    }
}
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
