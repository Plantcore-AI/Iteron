use super::*;
use crate::app_server::{AppServerHandle, ServerEnds, navigation_agent, wire};
#[cfg(test)]
use std::time::Duration;
pub struct HostFixture {
    pub(super) agent: Agent,
    pub(super) handle: AppServerHandle,
    pub(super) ends: ServerEnds,
    #[allow(dead_code)] // Retains the host activity owner for the fixture lifetime.
    pub(super) activity: ActivitySurface,
}
pub fn host_fixture(root: &std::path::Path) -> HostFixture {
    let agent = navigation_agent(root);
    host_from_agent(agent)
}
pub(super) fn host_from_agent(agent: Agent) -> HostFixture {
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
    pub fn port(&self) -> PathCompletionPort {
        self.handle
            .client
            .path_completion_port(self.agent.rollout.run_id())
            .unwrap()
    }
    pub async fn shutdown(&self) -> bool {
        self.ends.events.contract.shutdown_path_completions().await
    }
    #[cfg(test)]
    pub(super) async fn wait_physical(&self) -> bool {
        let binding = self.ends.events.contract.completion_binding().unwrap();
        let capacity = binding.service.capacity.get().unwrap().clone();
        tokio::time::timeout(Duration::from_secs(5), capacity.acquire_owned())
            .await
            .is_ok_and(|permit| permit.is_ok())
    }
}
