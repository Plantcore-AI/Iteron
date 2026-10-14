//! Session-scoped public projection of the actual durable workflow owner.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use tokio::sync::{Semaphore, oneshot};

use super::ControlReply;
use crate::runtime::Agent;
use crate::runtime::persistent_agents::AgentControlPort;
use crate::workflow::live_session::{
    LiveWorkflowCommandV1, LiveWorkflowPolicy, LiveWorkflowPort, LiveWorkflowSession,
};

const MAX_PENDING_CONTROLS: usize = 8;

struct Owner {
    root: PathBuf,
    controller: Arc<dyn AgentControlPort>,
    port: Arc<dyn LiveWorkflowPort>,
}

pub(super) struct LiveWorkflowSurface {
    owner: Mutex<Option<Owner>>,
    capacity: Arc<Semaphore>,
}

impl LiveWorkflowSurface {
    pub(super) fn capture(agent: &Agent) -> Self {
        let surface = Self {
            owner: Mutex::new(None),
            capacity: Arc::new(Semaphore::new(MAX_PENDING_CONTROLS)),
        };
        surface.refresh(agent);
        surface
    }

    /// Preserve the graph owner across controls and turns. Only the trusted runtime can replace
    /// the controller or authenticated rollout scope; no request carries a root or host policy.
    pub(super) fn refresh(&self, agent: &Agent) {
        let mut owner = self
            .owner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(controller) = agent.persistent_agent_control_port() else {
            *owner = None;
            return;
        };
        let Some(root) = state_root(agent) else {
            *owner = None;
            return;
        };
        if owner.as_ref().is_some_and(|current| {
            current.root == root && Arc::ptr_eq(&current.controller, &controller)
        }) {
            return;
        }
        let Ok(limits) = agent.persistent_agent_host_limits() else {
            *owner = None;
            return;
        };
        let Ok(policy) = LiveWorkflowPolicy::from_host_limits(&limits) else {
            *owner = None;
            return;
        };
        *owner = LiveWorkflowSession::new(root.clone(), policy, controller.clone())
            .ok()
            .map(|port| Owner {
                root,
                controller,
                port,
            });
    }

    pub(super) fn dispatch(
        &self,
        command: LiveWorkflowCommandV1,
        reply: oneshot::Sender<ControlReply>,
    ) {
        if let Err(error) = command.validate() {
            let _ = reply.send(ControlReply::Refused(error.to_string()));
            return;
        }
        let Some(port) = self
            .owner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|owner| owner.port.clone())
        else {
            let _ = reply.send(ControlReply::Refused(
                "live workflows require enabled persistent agents and verified finite host limits"
                    .into(),
            ));
            return;
        };
        let Ok(permit) = self.capacity.clone().try_acquire_owned() else {
            let _ = reply.send(ControlReply::Refused(
                "live workflow controls are busy; retry after a pending command settles".into(),
            ));
            return;
        };
        // The owner keeps admitted WAL work alive if a connection stops waiting. Keeping the
        // detached operation bounded also lets the parent provider future continue being polled.
        tokio::spawn(async move {
            let result = match port.command(command).await {
                Ok(value) => ControlReply::LiveWorkflow(Box::new(value)),
                Err(error) => ControlReply::Refused(error.to_string()),
            };
            let _ = reply.send(result);
            drop(permit);
        });
    }
}

fn state_root(agent: &Agent) -> Option<PathBuf> {
    let runs = agent.rollout.path().parent()?.canonicalize().ok()?;
    let workspace = agent.workspace.canonicalize().ok()?;
    let identity =
        serde_json::to_vec(&(agent.rollout.tenant(), agent.rollout.run_id(), workspace)).ok()?;
    Some(
        runs.join(".live-workflows")
            .join(hex::encode(Sha256::digest(identity))),
    )
}
