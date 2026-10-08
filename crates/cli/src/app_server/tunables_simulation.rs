//! Actual operator file-read admission, retained independently of the renderer or TCP observer.
use super::{ControlReply, activity_control::ActivitySurface, product_contract::ContractReader};
use crate::client_effects::tunables_simulation::NativeTunablesSimulation;
use crate::runtime::Agent;
use iteron_protocol::{RunId, SessionId};
use std::sync::Arc;
use tokio::sync::{OwnedRwLockReadGuard, OwnedSemaphorePermit, Semaphore, oneshot};

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TunablesLoadV1 {
    pub(crate) thread_id: SessionId,
    pub(crate) run_id: RunId,
    pub(crate) relative_path: String,
}
#[derive(Debug, serde::Serialize)]
pub(crate) struct ScopedTunablesSimulationV1 {
    pub(crate) thread_id: SessionId,
    pub(crate) run_id: RunId,
    pub(crate) view: crate::client_effects::tunables_simulation::TunablesSimulationV1,
}
pub(super) struct WorkspaceReadService {
    capacity: Arc<Semaphore>,
}
impl Default for WorkspaceReadService {
    fn default() -> Self {
        Self {
            capacity: Arc::new(Semaphore::new(1)),
        }
    }
}
impl WorkspaceReadService {
    pub(super) async fn shutdown(&self) -> bool {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.capacity.clone().acquire_owned(),
        )
        .await
        .is_ok_and(|permit| permit.is_ok())
    }
}
pub(super) fn dispatch(
    agent: &Agent,
    reader: ContractReader,
    activity: &ActivitySurface,
    command: TunablesLoadV1,
    reply: oneshot::Sender<ControlReply>,
) {
    if agent.rollout.run_id() != &command.run_id {
        let _ = reply.send(ControlReply::Refused(
            "tunables request belongs to a previous run".into(),
        ));
        return;
    }
    let scope = match activity.scope_lease(&reader, &command.thread_id, &command.run_id) {
        Ok(scope) => scope,
        Err(reason) => {
            let _ = reply.send(ControlReply::Refused(reason.into()));
            return;
        }
    };
    let native = match NativeTunablesSimulation::capture(agent, command.relative_path) {
        Ok(native) => native,
        Err(reason) => {
            let _ = reply.send(ControlReply::Refused(reason.into()));
            return;
        }
    };
    let Some((exclusion, service)) = reader.workspace_read_admission() else {
        let _ = reply.send(ControlReply::Refused(
            "workspace read has no submission exclusion".into(),
        ));
        return;
    };
    let slot = match service.capacity.clone().try_acquire_owned() {
        Ok(slot) => slot,
        Err(_) => {
            let _ = reply.send(ControlReply::Refused(
                "workspace source read is already active".into(),
            ));
            return;
        }
    };
    let submissions = match exclusion.try_exclude() {
        Ok(submissions) => submissions,
        Err(reason) => {
            let _ = reply.send(ControlReply::Refused(reason));
            return;
        }
    };
    spawn_read(
        native,
        command.thread_id,
        command.run_id,
        scope,
        slot,
        submissions,
        reply,
    );
}
fn spawn_read(
    native: NativeTunablesSimulation,
    thread_id: SessionId,
    run_id: RunId,
    scope: OwnedRwLockReadGuard<()>,
    slot: OwnedSemaphorePermit,
    submissions: super::session_factory::SubmissionExclusionLease,
    reply: oneshot::Sender<ControlReply>,
) {
    drop(tokio::task::spawn_blocking(move || {
        let _slot = slot;
        let _submissions = submissions;
        let _scope = scope;
        let result = native.execute();
        let response = match result {
            Ok(view) => ControlReply::TunablesSimulation(Box::new(ScopedTunablesSimulationV1 {
                thread_id,
                run_id,
                view,
            })),
            Err(reason) => ControlReply::Refused(reason.into()),
        };
        let _ = reply.send(response);
    }));
}
#[cfg(test)]
mod tests;
