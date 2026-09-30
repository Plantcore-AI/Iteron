//! Private bridge to Main's existing runtime. Public callers cannot provide a root lease or stop flag.
use super::{
    AgentActor, AgentControllerJournal, AgentEpochV1, AgentSettlement, AgentStateV1, AgentViewV1,
    ControllerError, LiveAgentMailbox, MAX_INPUT_BATCH, PersistentAgentHost, weak_mailbox,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub(crate) struct ParentRuntimeTurn {
    pub view: AgentViewV1,
    pub mailbox: LiveAgentMailbox,
    pub(super) epoch: AgentEpochV1,
    started: Instant,
}
impl ParentRuntimeTurn {
    pub(crate) fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis())
            .unwrap_or(u64::MAX)
            .max(1)
    }
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
        let started = Instant::now();
        let root = self
            .shared
            .controller
            .lock()
            .map_err(|_| ControllerError::Poisoned)?
            .root_id();
        let pending = self
            .shared
            .pending_settlements
            .lock()
            .map_err(|_| ControllerError::Poisoned)?
            .get(&root)
            .cloned();
        if let Some((epoch, result, wall)) = pending {
            self.settle(root, epoch, &result, wall)?;
            self.shared
                .pending_settlements
                .lock()
                .map_err(|_| ControllerError::Poisoned)?
                .remove(&root);
        }
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
        let prepared = controller.deliver(id, epoch, true).and_then(|initial| {
            if initial.len() > MAX_INPUT_BATCH {
                return Err(ControllerError::Capacity);
            }
            Ok((initial, controller.inspect(AgentActor::Operator, id)?))
        });
        let (initial, view) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                stop.store(true, Ordering::Release);
                let result = AgentSettlement {
                    turns: 0,
                    summary: "Parent mailbox preparation failed; recovery is required".into(),
                    tokens: 0,
                    cost_microusd: 0,
                    effects_known: false,
                    terminal: iteron_agents::AgentWorkflowTerminal::StoppedRecovery,
                };
                let wall = u64::try_from(started.elapsed().as_millis())
                    .unwrap_or(u64::MAX)
                    .max(1);
                let quarantined = controller.finish_turn_with_terminal(
                    id,
                    epoch,
                    &result.summary,
                    super::AgentUsageV1 {
                        wall_ms: wall,
                        ..Default::default()
                    },
                    false,
                    result.terminal,
                );
                *signal = None;
                self.notify(controller.revision());
                if quarantined.is_err() {
                    self.shared
                        .pending_settlements
                        .lock()
                        .map_err(|_| ControllerError::Poisoned)?
                        .insert(id, (epoch, result, wall));
                }
                return Err(error);
            }
        };
        self.notify(controller.revision());
        Ok(ParentRuntimeTurn {
            view,
            epoch,
            started,
            mailbox: LiveAgentMailbox {
                id,
                epoch,
                port: Arc::new(weak_mailbox::WeakMailbox::new(self)),
                witnesses: Arc::new(Mutex::new(
                    super::prepared_mailbox::MailboxWitnesses::default(),
                )),
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
        let wall_ms = wall_ms.max(turn.elapsed_ms());
        let settled = self.settle(turn.view.agent_id, turn.epoch, result, wall_ms);
        // Release the live signal even if retaining a retry proof itself fails. The controller
        // remains active/poisoned until the exact terminal barrier or trusted recovery succeeds.
        if let Ok(mut signal) = self.shared.parent_stop.lock()
            && signal
                .as_ref()
                .is_some_and(|signal| signal.epoch == turn.epoch)
        {
            *signal = None;
        }
        if settled.is_err() {
            self.shared
                .pending_settlements
                .lock()
                .map_err(|_| ControllerError::Poisoned)?
                .insert(turn.view.agent_id, (turn.epoch, result.clone(), wall_ms));
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
