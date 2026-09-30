//! Private bridge to Main's existing runtime. Public callers cannot provide a root lease or stop flag.
use super::{
    AgentActor, AgentControllerJournal, AgentEpochV1, AgentSettlement, AgentStateV1, AgentViewV1,
    ControllerError, LiveAgentMailbox, MAX_INPUT_BATCH, PersistentAgentHost, weak_mailbox,
};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) struct ParentRuntimeTurn {
    pub view: AgentViewV1,
    pub mailbox: LiveAgentMailbox,
    pub(super) epoch: AgentEpochV1,
}
pub(super) struct ParentStop {
    pub epoch: AgentEpochV1,
    pub signal: Weak<AtomicBool>,
}
impl<J: AgentControllerJournal + Send + 'static> PersistentAgentHost<J> {
    pub(super) fn begin_parent(
        &self,
        source: String,
        stop: Arc<AtomicBool>,
    ) -> Result<ParentRuntimeTurn, ControllerError> {
        let started_at = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| ControllerError::Invalid("parent clock is before epoch"))?
                .as_millis(),
        )
        .map_err(|_| ControllerError::Capacity)?;
        // Consistent lock order is controller then signal. Commands signal only after their
        // durable controller commit, and never retain this lock across runtime IO.
        let mut controller = self
            .shared
            .controller
            .lock()
            .map_err(|_| ControllerError::Poisoned)?;
        let mut signal = self
            .shared
            .parent_stop
            .lock()
            .map_err(|_| ControllerError::Poisoned)?;
        if signal.is_some() {
            return Err(ControllerError::StaleEpoch);
        }
        let epoch = controller.begin_parent_runtime_turn(source, started_at)?;
        *signal = Some(ParentStop {
            epoch,
            signal: Arc::downgrade(&stop),
        });
        let id = controller.root_id();
        let initial = match controller.deliver(id, epoch, true) {
            Ok(initial) => initial,
            Err(error) => {
                let _ = controller.finish_turn_with_usage(
                    id,
                    epoch,
                    "Parent mailbox delivery failed; recovery is required",
                    Default::default(),
                    false,
                );
                *signal = None;
                self.notify(controller.revision());
                return Err(error);
            }
        };
        if initial.len() > MAX_INPUT_BATCH {
            return Err(ControllerError::Capacity);
        }
        let view = controller.inspect(AgentActor::Operator, id)?;
        self.notify(controller.revision());
        Ok(ParentRuntimeTurn {
            view,
            epoch,
            mailbox: LiveAgentMailbox {
                id,
                epoch,
                port: Arc::new(weak_mailbox::WeakMailbox::new(self)),
                witnesses: Arc::new(Mutex::new(BTreeMap::new())),
                deferred: Arc::new(Mutex::new(initial)),
            },
        })
    }
    pub(super) fn finish_parent(
        &self,
        turn: &ParentRuntimeTurn,
        result: &AgentSettlement,
        wall_ms: u64,
    ) -> Result<(), ControllerError> {
        let settled = self.settle(turn.view.agent_id, turn.epoch, result, wall_ms.max(1));
        if let Ok(mut signal) = self.shared.parent_stop.lock()
            && signal
                .as_ref()
                .is_some_and(|signal| signal.epoch == turn.epoch)
        {
            *signal = None;
        }
        settled
    }
    /// A persisted interrupt/close requests physical stop; the acknowledgement never claims reap.
    pub(super) fn signal_parent_stop(&self) -> Result<(), ControllerError> {
        let controller = self
            .shared
            .controller
            .lock()
            .map_err(|_| ControllerError::Poisoned)?;
        let state = controller
            .inspect(AgentActor::Operator, controller.root_id())?
            .state;
        let signal = self
            .shared
            .parent_stop
            .lock()
            .map_err(|_| ControllerError::Poisoned)?;
        if let Some(signal) = signal.as_ref()
            && matches!(state, AgentStateV1::Interrupting { epoch } | AgentStateV1::Closing { epoch }
                if epoch == signal.epoch)
            && let Some(stop) = signal.signal.upgrade()
        {
            stop.store(true, Ordering::Release);
        }
        Ok(())
    }
}
