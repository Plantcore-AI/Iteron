//! Public plugin management retains the exact host owner and the same adoption generation lease.
use super::{ControlReply, activity_control::ActivitySurface, product_contract::ContractReader};
use crate::{plugin_runtime::PluginManagementOwner, runtime::Agent};
use iteron_protocol::{RunId, plugin_control::PluginControlV1};
use serde_json::json;
use std::sync::{Arc, Mutex};
use tokio::sync::{Semaphore, oneshot};
#[derive(Clone)]
struct Binding {
    run: RunId,
    owner: Option<Arc<PluginManagementOwner>>,
}
pub(super) struct PluginControlSurface {
    binding: Mutex<Binding>,
    capacity: Mutex<Option<Arc<Semaphore>>>,
}
impl PluginControlSurface {
    pub(super) fn capture(agent: &Agent) -> Self {
        Self {
            binding: Mutex::new(binding(agent)),
            capacity: Mutex::new(None),
        }
    }
    pub(super) fn refresh(&self, agent: &Agent) {
        *self
            .binding
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = binding(agent);
    }
    pub(super) fn dispatch(
        &self,
        activity: &ActivitySurface,
        reader: ContractReader,
        command: PluginControlV1,
        reply: oneshot::Sender<ControlReply>,
    ) {
        if let Err(reason) = command.validate() {
            let _ = reply.send(ControlReply::Refused(reason.into()));
            return;
        }
        let (thread, run) = command.scope();
        let lease = match activity.scope_lease(&reader, thread, run) {
            Ok(lease) => lease,
            Err(reason) => {
                let _ = reply.send(ControlReply::Refused(reason.into()));
                return;
            }
        };
        let binding = self
            .binding
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if binding.run != *run {
            let _ = reply.send(ControlReply::Refused("plugin run scope changed".into()));
            return;
        }
        let Some(owner) = binding.owner else {
            let _ = reply.send(ControlReply::Refused(
                "no installed plugin management owner or prepared candidate".into(),
            ));
            return;
        };
        let capacity = self
            .capacity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert_with(|| Arc::new(Semaphore::new(8)))
            .clone();
        let permit = match capacity.try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let _ = reply.send(ControlReply::Refused(
                    "plugin control capacity reached".into(),
                ));
                return;
            }
        };
        let thread = thread.clone();
        let run = run.clone();
        tokio::spawn(async move {
            let value = owner.execute(command).await;
            let reply_value = match value {
                Ok(value) => ControlReply::PluginManagement(
                    json!({"type":"plugin_management_v1","thread_id":thread,"run_id":run,"data":value}),
                ),
                Err(reason) => ControlReply::Refused(reason.into()),
            };
            let _ = reply.send(reply_value);
            drop(permit);
            drop(lease);
        });
    }
}
fn binding(agent: &Agent) -> Binding {
    Binding {
        run: agent.rollout.run_id().clone(),
        owner: agent.plugin_management_port(),
    }
}
