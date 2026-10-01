//! Ordinary operator shell intake. Current Agent policy is captured only at the idle host boundary.
//! Physical execution is detached from presentation while actual SQ/adoption exclusions remain held.
use super::{ControlReply, activity_control::ActivitySurface, product_contract::ContractReader};
use crate::client_effects::shell::{NativeShellScope, ShellCleanup};
use crate::runtime::Agent;
use iteron_protocol::{RunId, SessionId};
use std::sync::{Arc, Mutex};
use tokio::sync::{OwnedRwLockReadGuard, oneshot, watch};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperatorShellV1 {
    pub(crate) thread_id: SessionId,
    pub(crate) run_id: RunId,
    pub(crate) command: String,
}
impl std::fmt::Debug for OperatorShellV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OperatorShellV1")
            .field("command_bytes", &self.command.len())
            .finish_non_exhaustive()
    }
}
impl OperatorShellV1 {
    fn validate(&self) -> Result<(), &'static str> {
        if self.thread_id.0.is_empty()
            || self.thread_id.0.len() > 200
            || self.run_id.0.is_empty()
            || self.run_id.0.len() > 200
            || self.command.trim().is_empty()
            || self.command.len() > 64 * 1024
            || self.command.capacity() > 64 * 1024
            || self.command.contains('\0')
        {
            Err("operator shell identity or command exceeds its finite bound")
        } else {
            Ok(())
        }
    }
}
#[derive(Default)]
pub(super) struct ShellService {
    unresolved: Mutex<Option<ShellLease>>,
    active: Mutex<Option<watch::Sender<bool>>>,
    settled: tokio::sync::Notify,
}
impl ShellService {
    pub(super) async fn shutdown(&self) -> bool {
        // Register before checking the real active owner: a completion cannot be lost between
        // this observation and the bounded wait. No active owner means no clock or native work.
        let changed = self.settled.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        let active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let Some(cancel) = active else {
            return self
                .unresolved
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_none();
        };
        let _ = cancel.send(true);
        if tokio::time::timeout(std::time::Duration::from_secs(3), changed)
            .await
            .is_err()
        {
            return false;
        }
        self.active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_none()
            && self
                .unresolved
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_none()
    }

    fn admit(
        self: &Arc<Self>,
        reader: &ContractReader,
        activity: &ActivitySurface,
        command: &OperatorShellV1,
    ) -> Result<ShellLease, String> {
        if self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
        {
            return Err("a physical operator shell is already admitted".into());
        }
        if self
            .unresolved
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
        {
            return Err("prior shell cleanup remains unobserved; new execution is refused".into());
        }
        let scope = activity.scope_lease(reader, &command.thread_id, &command.run_id)?;
        let (exclusion, _) = reader
            .shell_admission()
            .ok_or("operator shell has no physical submission exclusion")?;
        let submissions = exclusion.try_exclude()?;
        // Exclusive SQ slots already bound total admitted shell population to one. The native
        // task retains these exact permits; there is no second queue or copied session state.
        Ok(ShellLease {
            _scope: scope,
            _submissions: submissions,
        })
    }
}
struct ShellLease {
    _scope: OwnedRwLockReadGuard<()>,
    _submissions: super::session_factory::SubmissionExclusionLease,
}
struct Custody {
    service: Arc<ShellService>,
    lease: Option<ShellLease>,
}
impl Custody {
    fn finish(&mut self, cleanup: ShellCleanup) {
        let Some(lease) = self.lease.take() else {
            return;
        };
        if cleanup == ShellCleanup::Unobserved {
            *self
                .service
                .unresolved
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(lease);
            self.service
                .active
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
        } else {
            self.service
                .active
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            drop(lease);
        }
        self.service.settled.notify_waiters();
    }
}
impl Drop for Custody {
    fn drop(&mut self) {
        self.finish(ShellCleanup::Unobserved);
    }
}
pub(super) fn dispatch(
    agent: &Agent,
    reader: ContractReader,
    activity: &ActivitySurface,
    command: OperatorShellV1,
    cancel: Option<watch::Receiver<bool>>,
    reply: oneshot::Sender<ControlReply>,
) {
    if let Err(reason) = command.validate() {
        let _ = reply.send(ControlReply::Refused(reason.into()));
        return;
    }
    if agent.rollout.run_id() != &command.run_id {
        let _ = reply.send(ControlReply::Refused(
            "operator shell source changed before capture".into(),
        ));
        return;
    }
    let Some((_, service)) = reader.shell_admission() else {
        let _ = reply.send(ControlReply::Refused(
            "operator shell admission is unavailable".into(),
        ));
        return;
    };
    let lease = match service.admit(&reader, activity, &command) {
        Ok(lease) => lease,
        Err(reason) => {
            let _ = reply.send(ControlReply::Refused(reason));
            return;
        }
    };
    let native = NativeShellScope::capture(agent, command.command);
    let (host_cancel, cancelled) = watch::channel(false);
    *service
        .active
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(host_cancel.clone());
    let mut custody = Custody {
        service,
        lease: Some(lease),
    };
    tokio::spawn(async move {
        let physical = native.execute(cancelled);
        tokio::pin!(physical);
        let completion = if let Some(mut local) = cancel {
            if *local.borrow() {
                let _ = host_cancel.send(true);
            }
            tokio::select! {
                result = &mut physical => result,
                _ = local.changed() => { let _ = host_cancel.send(true); physical.await },
            }
        } else {
            physical.await
        };
        custody.finish(completion.cleanup);
        let _ = reply.send(ControlReply::OperatorShell(completion));
    });
}
#[cfg(test)]
mod tests;
