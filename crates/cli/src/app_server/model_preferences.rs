//! Actual selected-route preference writer. ModelSelected and user-default installation are
//! separate receipts; a storage failure never repeats or reverses the route transaction.
use super::{
    ControlReply, EventPublisher, ModelSelection, activity_control::ActivitySurface,
    product_contract::ContractReader,
};
use crate::config::preferences::{PreferenceWriteStatus, UserPreferenceTarget};
use crate::runtime::Agent;
use iteron_protocol::{RunId, SessionId};
use std::sync::{Arc, Mutex};
use tokio::sync::{Notify, OwnedRwLockReadGuard, oneshot};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ModelPreferenceReadV1 {
    pub(crate) thread_id: SessionId,
    pub(crate) run_id: RunId,
    pub(crate) after_revision: u64,
}
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct PreferenceReceipt {
    pub(crate) thread_id: SessionId,
    pub(crate) run_id: RunId,
    pub(crate) revision: u64,
    pub(crate) provider_id: String,
    pub(crate) model_id: String,
    pub(crate) status: PreferenceWriteStatus,
}
struct Lease {
    _scope: OwnedRwLockReadGuard<()>,
    _submissions: super::session_factory::SubmissionExclusionLease,
}
#[derive(Default)]
struct State {
    revision: u64,
    active: bool,
    last: Option<PreferenceReceipt>,
    unresolved: Option<Lease>,
}
#[derive(Default)]
pub(super) struct PreferenceService {
    state: Mutex<State>,
    settled: Notify,
}
impl PreferenceService {
    pub(super) fn after(&self, revision: u64) -> Option<PreferenceReceipt> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .last
            .as_ref()
            .filter(|receipt| receipt.revision > revision)
            .cloned()
    }
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
    service: Arc<PreferenceService>,
    lease: Option<Lease>,
    started: bool,
}
impl Custody {
    fn finish(&mut self, status: PreferenceWriteStatus) {
        let Some(lease) = self.lease.take() else {
            return;
        };
        let mut state = self
            .service
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if status == PreferenceWriteStatus::InstallationUnknown {
            state.unresolved = Some(lease);
        } else {
            drop(lease);
        }
        state.active = false;
        if self.started {
            if let Some(revision) = state.revision.checked_add(1) {
                state.revision = revision;
                if let Some(last) = &mut state.last {
                    last.revision = revision;
                    last.status = status;
                }
            }
        }
        self.service.settled.notify_waiters();
    }
}
impl Drop for Custody {
    fn drop(&mut self) {
        self.finish(if self.started {
            PreferenceWriteStatus::InstallationUnknown
        } else {
            PreferenceWriteStatus::NotInstalled
        });
    }
}
pub(super) fn read(reader: &ContractReader, command: ModelPreferenceReadV1) -> ControlReply {
    match reader.model_preference_scoped(
        &command.thread_id,
        &command.run_id,
        command.after_revision,
    ) {
        Ok(receipt) => ControlReply::ModelPreference(receipt),
        Err(reason) => ControlReply::Refused(reason.into()),
    }
}
#[allow(clippy::too_many_arguments)]
pub(super) async fn select_default(
    agent: &mut Agent,
    events: &mut EventPublisher,
    activity: &ActivitySurface,
    selection: ModelSelection,
    reply: oneshot::Sender<ControlReply>,
) {
    let reader = events.contract.clone();
    let Some(scope) = reader.snapshot() else {
        let _ = reply.send(ControlReply::Refused(
            "model default has no current host scope".into(),
        ));
        return;
    };
    let target = UserPreferenceTarget::capture();
    let scope_lease = match activity.scope_lease(&reader, &scope.thread_id, &scope.run_id) {
        Ok(lease) => lease,
        Err(reason) => {
            let _ = reply.send(ControlReply::Refused(reason.into()));
            return;
        }
    };
    let Some((exclusion, service)) = reader.preference_admission() else {
        let _ = reply.send(ControlReply::Refused(
            "model default has no submission exclusion".into(),
        ));
        return;
    };
    {
        let mut state = service
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.active || state.unresolved.is_some() || state.revision.checked_add(2).is_none() {
            let _ = reply.send(ControlReply::Refused(
                "prior model default write is active or unobserved".into(),
            ));
            return;
        }
        state.active = true;
    }
    let submissions = match exclusion.try_exclude() {
        Ok(lease) => lease,
        Err(reason) => {
            service
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .active = false;
            service.settled.notify_waiters();
            let _ = reply.send(ControlReply::Refused(reason.into()));
            return;
        }
    };
    let mut custody = Custody {
        service: service.clone(),
        lease: Some(Lease {
            _scope: scope_lease,
            _submissions: submissions,
        }),
        started: false,
    };
    let selected = super::model_control::apply(agent, events, selection).await;
    if !matches!(&selected, ControlReply::State(_)) {
        custody.finish(PreferenceWriteStatus::NotInstalled);
        let _ = reply.send(selected);
        return;
    }
    let Some((provider_id, model_id)) = agent.operator_selected_model_default() else {
        custody.finish(PreferenceWriteStatus::NotInstalled);
        let _ = reply.send(selected);
        return;
    };
    start_native_write(
        target,
        scope.thread_id,
        scope.run_id,
        provider_id,
        model_id,
        custody,
    );
    let _ = reply.send(selected);
}

fn start_native_write(
    target: Option<UserPreferenceTarget>,
    thread_id: SessionId,
    run_id: RunId,
    provider_id: String,
    model_id: String,
    mut custody: Custody,
) {
    {
        let mut state = custody
            .service
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.revision += 1;
        state.last = Some(PreferenceReceipt {
            thread_id,
            run_id,
            revision: state.revision,
            provider_id: provider_id.clone(),
            model_id: model_id.clone(),
            status: PreferenceWriteStatus::Pending,
        });
    }
    custody.started = true;
    let Some(target) = target else {
        custody.finish(PreferenceWriteStatus::NotInstalled);
        return;
    };
    // Route receipt is delivered immediately. The physically retained native worker never holds
    // Agent, retries provider selection, borrows the renderer, or depends on this observer.
    // Physical work owns custody itself. Dropping an observer or the JoinHandle cannot release
    // either real exclusion; unwinding the native worker retains an unobserved installation.
    drop(tokio::task::spawn_blocking(move || {
        let status = target.write_selected_model(&provider_id, &model_id);
        custody.finish(status);
    }));
}

#[cfg(test)]
mod tests;
