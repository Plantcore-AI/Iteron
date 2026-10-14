//! Offline native lab control through the actual current host scope and submission custody.
use super::{
    ControlReply, activity_control::ActivitySurface, product_contract::ContractReader,
    session_factory::SubmissionExclusionLease,
};
use crate::client_effects::experiment_lab::{LabActionV1, LabFactsV1, NativeExperimentLab};
use crate::runtime::Agent;
use iteron_protocol::{RunId, SessionId};
use std::sync::{Arc, Mutex};
use tokio::sync::{OwnedRwLockReadGuard, OwnedSemaphorePermit, Semaphore, oneshot};
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LabCommandV1 {
    pub(crate) thread_id: SessionId,
    pub(crate) run_id: RunId,
    pub(crate) action: LabActionV1,
}
#[derive(Debug, serde::Serialize)]
pub(crate) struct ScopedLabFactsV1 {
    pub(crate) thread_id: SessionId,
    pub(crate) run_id: RunId,
    pub(crate) facts: LabFactsV1,
}
pub(super) struct LabService {
    capacity: Arc<Semaphore>,
    unresolved: Mutex<Option<Lease>>,
}
impl Default for LabService {
    fn default() -> Self {
        Self {
            capacity: Arc::new(Semaphore::new(1)),
            unresolved: Mutex::new(None),
        }
    }
}
struct Lease {
    _scope: OwnedRwLockReadGuard<()>,
    _sq: SubmissionExclusionLease,
    _slot: OwnedSemaphorePermit,
}
struct Custody {
    service: Arc<LabService>,
    lease: Option<Lease>,
    mutating: bool,
}
impl Custody {
    fn finish(&mut self, unknown: bool) {
        let Some(lease) = self.lease.take() else {
            return;
        };
        if unknown {
            *self
                .service
                .unresolved
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(lease);
        } else {
            drop(lease);
        }
    }
}
impl Drop for Custody {
    fn drop(&mut self) {
        self.finish(self.mutating);
    }
}
impl LabService {
    pub(super) async fn shutdown(&self) -> bool {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.capacity.clone().acquire_owned(),
        )
        .await
        .is_ok_and(|result| result.is_ok())
    }
}
pub(super) fn dispatch(
    agent: &Agent,
    reader: ContractReader,
    activity: &ActivitySurface,
    command: LabCommandV1,
    reply: oneshot::Sender<ControlReply>,
) {
    if agent.rollout.run_id() != &command.run_id {
        let _ = reply.send(ControlReply::Refused(
            "lab command belongs to a previous run".into(),
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
    let native = match NativeExperimentLab::capture(agent, command.action) {
        Ok(native) => native,
        Err(reason) => {
            let _ = reply.send(ControlReply::Refused(reason.into()));
            return;
        }
    };
    let Some((exclusion, service)) = reader.lab_admission() else {
        let _ = reply.send(ControlReply::Refused(
            "lab has no submission exclusion".into(),
        ));
        return;
    };
    let slot = match service.capacity.clone().try_acquire_owned() {
        Ok(slot) => slot,
        Err(_) => {
            let _ = reply.send(ControlReply::Refused(
                "prior lab operation is active or publication remains unobserved".into(),
            ));
            return;
        }
    };
    let sq = match exclusion.try_exclude() {
        Ok(sq) => sq,
        Err(reason) => {
            let _ = reply.send(ControlReply::Refused(reason));
            return;
        }
    };
    let custody = Custody {
        service,
        lease: Some(Lease {
            _slot: slot,
            _scope: scope,
            _sq: sq,
        }),
        mutating: native.mutating(),
    };
    spawn_native(native, command.thread_id, command.run_id, custody, reply);
}
fn spawn_native(
    native: NativeExperimentLab,
    thread_id: SessionId,
    run_id: RunId,
    mut custody: Custody,
    reply: oneshot::Sender<ControlReply>,
) {
    drop(tokio::task::spawn_blocking(move || {
        let completion = native.execute();
        custody.finish(completion.publication_unknown);
        let response = match completion.facts {
            Ok(facts) => ControlReply::Lab(Box::new(ScopedLabFactsV1 {
                thread_id,
                run_id,
                facts,
            })),
            Err(_) if completion.publication_unknown => ControlReply::Refused(
                "lab publication is unconfirmed; retained admission prevents retry or session replacement".into(),
            ),
            Err(reason) => ControlReply::Refused(reason.into()),
        };
        let _ = reply.send(response);
    }));
}

#[cfg(test)]
mod tests;
