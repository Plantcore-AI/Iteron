//! Existing /init intent behind real host scope, submission exclusion and retained native work.
use super::{ControlReply, activity_control::ActivitySurface, product_contract::ContractReader};
use crate::client_effects::project_init::{
    InitEntry, InitStatus, NativeProjectInit, ProjectInitReceipt,
};
use crate::runtime::Agent;
use iteron_protocol::{RunId, SessionId};
use std::sync::{Arc, Mutex};
use tokio::sync::{Notify, OwnedRwLockReadGuard, oneshot};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProjectInitV1 {
    pub(crate) thread_id: SessionId,
    pub(crate) run_id: RunId,
}
impl ProjectInitV1 {
    fn validate(&self) -> bool {
        !self.thread_id.0.is_empty()
            && self.thread_id.0.len() <= 200
            && !self.run_id.0.is_empty()
            && self.run_id.0.len() <= 200
    }
}
struct Lease {
    _scope: OwnedRwLockReadGuard<()>,
    _submissions: super::session_factory::SubmissionExclusionLease,
}
#[derive(Default)]
pub(super) struct ProjectInitService {
    state: Mutex<State>,
    settled: Notify,
}
#[derive(Default)]
struct State {
    active: bool,
    unresolved: Option<Lease>,
}
impl ProjectInitService {
    pub(super) async fn shutdown(&self) -> bool {
        let settled = self.settled.notified();
        tokio::pin!(settled);
        settled.as_mut().enable();
        {
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !state.active {
                return state.unresolved.is_none();
            }
        }
        if tokio::time::timeout(std::time::Duration::from_secs(5), settled)
            .await
            .is_err()
        {
            return false;
        }
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        !state.active && state.unresolved.is_none()
    }
}
struct Custody {
    service: Arc<ProjectInitService>,
    lease: Option<Lease>,
}
impl Custody {
    fn finish(&mut self, unknown: bool) {
        let Some(lease) = self.lease.take() else {
            return;
        };
        let mut state = self
            .service
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if unknown {
            state.unresolved = Some(lease);
        } else {
            drop(lease);
        }
        state.active = false;
        self.service.settled.notify_waiters();
    }
}
impl Drop for Custody {
    fn drop(&mut self) {
        self.finish(true);
    }
}

pub(super) fn dispatch(
    agent: &Agent,
    reader: ContractReader,
    activity: &ActivitySurface,
    command: ProjectInitV1,
    reply: oneshot::Sender<ControlReply>,
) {
    if !command.validate() || agent.rollout.run_id() != &command.run_id {
        let _ = reply.send(ControlReply::Refused(
            "project initialization identity is invalid or stale".into(),
        ));
        return;
    }
    let scope = match activity.scope_lease(&reader, &command.thread_id, &command.run_id) {
        Ok(scope) => scope,
        Err(reason) => {
            let _ = reply.send(ControlReply::Refused(reason));
            return;
        }
    };
    let Some((exclusion, service)) = reader.project_init_admission() else {
        let _ = reply.send(ControlReply::Refused(
            "project initialization has no submission exclusion".into(),
        ));
        return;
    };
    let mut state = service
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if state.active || state.unresolved.is_some() {
        let _ = reply.send(ControlReply::Refused(
            "prior project initialization is active or unobserved".into(),
        ));
        return;
    }
    let submissions = match exclusion.try_exclude() {
        Ok(submissions) => submissions,
        Err(reason) => {
            let _ = reply.send(ControlReply::Refused(reason));
            return;
        }
    };
    let native = NativeProjectInit::capture(agent);
    state.active = true;
    drop(state);
    let mut custody = Custody {
        service,
        lease: Some(Lease {
            _scope: scope,
            _submissions: submissions,
        }),
    };
    tokio::spawn(async move {
        // Both custody and the true native task outlive caller cancellation. No external timeout
        // can return a fictional NotPublished or free the workspace while a syscall still runs.
        let receipt = match tokio::task::spawn_blocking(move || native.execute()).await {
            Ok(receipt) => receipt,
            Err(_) => ProjectInitReceipt {
                source_run: command.run_id,
                entries: vec![InitEntry {
                    name: "project_initialization",
                    status: InitStatus::PublicationUnknown,
                }],
                refusal: Some("native initialization worker ended without an observed receipt"),
            },
        };
        custody.finish(receipt.unknown());
        let _ = reply.send(ControlReply::ProjectInit(receipt));
    });
}
#[cfg(test)]
mod tests;
