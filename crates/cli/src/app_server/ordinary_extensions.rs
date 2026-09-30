//! Detached reads retain the actual SDK owner and adoption admission through bounded physical work.
use super::{ControlReply, activity_control::ActivitySurface, product_contract::ContractReader};
use crate::runtime::Agent;
use iteron_extension_sdk::{ExtensionReadErrorV1, OrdinaryExtensionsReadPort};
use iteron_protocol::{RunId, ordinary_extension_control::OrdinaryExtensionReadV1};
use serde_json::json;
use std::sync::{Arc, Mutex};
use tokio::sync::{Semaphore, oneshot};

mod projection;
#[derive(Clone)]
struct Binding {
    run: RunId,
    owner: Arc<dyn OrdinaryExtensionsReadPort>,
}
pub(super) struct OrdinaryExtensionsSurface {
    binding: Mutex<Option<Binding>>,
    capacity: Mutex<Option<Arc<Semaphore>>>,
}
impl OrdinaryExtensionsSurface {
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
        command: OrdinaryExtensionReadV1,
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
        let Some(binding) = binding else {
            let _ = reply.send(ControlReply::OrdinaryExtensions(json!({"type":"ordinary_extensions_v1","thread_id":thread,"run_id":run,"configured":false,"availability":"not_bound"})));
            return;
        };
        if binding.run != *run {
            let _ = reply.send(ControlReply::Refused("extension run scope changed".into()));
            return;
        }
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
                    "extension read capacity reached".into(),
                ));
                return;
            }
        };
        let thread = thread.clone();
        let run = run.clone();
        // The actual blocking worker owns admission. Observer disconnect/caller cancellation
        // cannot release its permit or adoption lease while it still advances a reader cursor.
        let worker_run = run.clone();
        let worker = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _lease = lease;
            match command {
                OrdinaryExtensionReadV1::Read { offset, limit, .. } => {
                    binding.owner.snapshot().and_then(|value| {
                        projection::snapshot(value, usize::from(offset), usize::from(limit))
                    })
                }
                OrdinaryExtensionReadV1::Events {
                    name,
                    limit,
                    timeout_ms,
                    ..
                } => binding
                    .owner
                    .events(&name, usize::from(limit), u64::from(timeout_ms))
                    .and_then(|value| projection::events(value, &worker_run, &name)),
            }
        });
        tokio::spawn(async move {
            let outcome = worker
                .await
                .unwrap_or(Err(ExtensionReadErrorV1::Unavailable));
            let value = match outcome {
                Ok(data) => {
                    json!({"type":"ordinary_extensions_v1","thread_id":thread,"run_id":run,"configured":true,"availability":"available","data":data})
                }
                Err(error) => {
                    json!({"type":"ordinary_extensions_v1","thread_id":thread,"run_id":run,"configured":true,"availability":error})
                }
            };
            let _ = reply.send(ControlReply::OrdinaryExtensions(value));
        });
    }
}
fn binding(agent: &Agent) -> Option<Binding> {
    agent.ordinary_extensions_port().map(|owner| Binding {
        run: agent.rollout.run_id().clone(),
        owner,
    })
}
