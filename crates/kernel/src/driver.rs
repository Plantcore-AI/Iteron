//! K9: the bounded agent-loop driver.
//!
//! The driver is the only thing in the kernel that runs a reducer action. It pulls commands from a
//! bounded submission queue, folds each into the pure reducer, routes the returned action requests
//! to injected ports or the effect boundary, and emits events on a bounded queue with backpressure.
//! It decides nothing: every branch belongs to `crate::reducer`, and every effect belongs to
//! `crate::effects`.
//!
//! # Why both queues are bounded, and what "bounded" costs
//!
//! An unbounded channel does not remove backpressure, it relocates it — into memory, where it
//! surfaces as an OOM under exactly the load you most wanted to survive. So:
//!
//! * **SQ full** — a producer either awaits a slot ([`SubmissionQueue::submit`]) or receives an
//!   explicit [`Rejected`] ([`SubmissionQueue::try_submit`]). There is no third option, and in
//!   particular there is no drop.
//! * **EQ full** — the emitter awaits. Events are never dropped, never coalesced, never sampled.
//!
//! # Why port replies do not go through the SQ
//!
//! The obvious design has the driver push each port reply back onto the SQ. It deadlocks: the
//! driver is the SQ's only consumer, so a driver blocked on a full SQ is a driver that will never
//! drain it. Replies therefore land in a private, separately bounded queue that is drained ahead of
//! the SQ — which also gives the loop the right priority, since a reply to work already in flight
//! must be handled before new work is admitted.

use crate::ports::TurnPorts;
use crate::reducer::reduce;
use crate::turn_action::ActionRequest;
use crate::turn_command::Command;
use crate::turn_protocol::{ProviderFailure, ProviderTermination};
use crate::turn_state::TurnState;
use iteron_protocol::Outcome;
use std::collections::VecDeque;

/// Hard ceiling on port replies queued inside the driver.
///
/// One turn's reducer output is a handful of actions, so this is orders of magnitude of headroom.
/// It exists so that "the internal queue is bounded too" is a fact rather than an assumption.
pub const MAX_PENDING_REPLIES: usize = 256;

/// A submission the queue refused, handed back intact.
///
/// The value comes back with the rejection on purpose. A queue that consumed the caller's data and
/// then reported failure would force every caller to keep a copy, and the ones that forgot would
/// drop submissions exactly under the load that caused the rejection.
#[derive(Debug, PartialEq, Eq)]
pub struct Rejected {
    pub command: Command,
    pub reason: RejectReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RejectReason {
    #[error("the submission queue is at its bound; retry or await a slot")]
    QueueFull,
    #[error("the driver has stopped consuming submissions")]
    DriverGone,
}

/// Why a port could not do what was asked.
///
/// The split is load-bearing. A durable-append failure is not a port problem: it means the audit
/// record no longer describes the run, and *the reducer* owns what that implies — it has an
/// explicit `RecordFailed` transition to `HarnessError`. Folding it into a generic port error would
/// abort the loop from the outside and make that transition unreachable, which is precisely the
/// kind of branch-that-cannot-happen the reducer split exists to eliminate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PortFault {
    #[error("durable append failed: {0}")]
    Record(String),
    #[error("{0}")]
    Port(String),
}

/// What the driver could not do.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DriverError {
    #[error("the submission queue closed before the run reached a terminal state")]
    SubmissionsClosed,
    #[error("the event queue closed before the run reached a terminal state")]
    EventsClosed,
    #[error("the driver's internal reply queue reached its bound of {MAX_PENDING_REPLIES}")]
    ReplyQueueFull,
    #[error("a port refused the dispatch: {0}")]
    Port(String),
}

/// The bounded submission queue. Producers hold the sender.
#[derive(Debug, Clone)]
pub struct SubmissionQueue {
    tx: tokio::sync::mpsc::Sender<Command>,
}

impl SubmissionQueue {
    /// Await a slot. This is the backpressure path: a producer that outruns the driver is slowed
    /// down rather than allowed to grow the queue.
    pub async fn submit(&self, command: Command) -> Result<(), Rejected> {
        self.tx.send(command).await.map_err(|error| Rejected {
            command: error.0,
            reason: RejectReason::DriverGone,
        })
    }

    /// Take a slot if one is free, otherwise say so. This is the explicit-reject path, for
    /// producers that must not block — a UI thread, a signal handler.
    pub fn try_submit(&self, command: Command) -> Result<(), Rejected> {
        use tokio::sync::mpsc::error::TrySendError;
        self.tx.try_send(command).map_err(|error| match error {
            TrySendError::Full(command) => Rejected {
                command,
                reason: RejectReason::QueueFull,
            },
            TrySendError::Closed(command) => Rejected {
                command,
                reason: RejectReason::DriverGone,
            },
        })
    }

    pub fn capacity_remaining(&self) -> usize {
        self.tx.capacity()
    }
}

/// One observable thing the driver did. Emitted on the bounded event queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverEvent {
    /// An action request was routed. Carrying the request itself keeps the event stream a faithful
    /// projection of the reducer's output rather than a second, drifting description of it.
    Routed(ActionRequest),
    /// The run reached a terminal state.
    Finished(Outcome),
}

/// The bounded event queue. Emission applies backpressure; nothing is ever dropped.
#[derive(Debug, Clone)]
pub struct EventQueue {
    tx: tokio::sync::mpsc::Sender<DriverEvent>,
}

impl EventQueue {
    pub async fn emit(&self, event: DriverEvent) -> Result<(), DriverError> {
        self.tx
            .send(event)
            .await
            .map_err(|_| DriverError::EventsClosed)
    }

    pub fn capacity_remaining(&self) -> usize {
        self.tx.capacity()
    }
}

/// Build the two bounded queues and their consuming ends.
pub fn bounded_queues(
    submission_capacity: usize,
    event_capacity: usize,
) -> (
    SubmissionQueue,
    tokio::sync::mpsc::Receiver<Command>,
    EventQueue,
    tokio::sync::mpsc::Receiver<DriverEvent>,
) {
    let (sq_tx, sq_rx) = tokio::sync::mpsc::channel(submission_capacity.max(1));
    let (eq_tx, eq_rx) = tokio::sync::mpsc::channel(event_capacity.max(1));
    (
        SubmissionQueue { tx: sq_tx },
        sq_rx,
        EventQueue { tx: eq_tx },
        eq_rx,
    )
}

/// What a provider dispatch answered with.
pub enum ProviderReply {
    Completed {
        termination: ProviderTermination,
        tool_calls: u32,
    },
    Failed(ProviderFailure),
}

/// The bounded agent loop.
pub struct TurnDriver<P: TurnPorts> {
    state: TurnState,
    ports: P,
    events: EventQueue,
    /// Port replies awaiting the reducer. Bounded; see the module note on why these do not go
    /// through the SQ.
    replies: VecDeque<Command>,
}

impl<P: TurnPorts> TurnDriver<P> {
    pub fn new(state: TurnState, ports: P, events: EventQueue) -> Self {
        Self {
            state,
            ports,
            events,
            replies: VecDeque::new(),
        }
    }

    pub fn state(&self) -> &TurnState {
        &self.state
    }

    pub fn into_ports(self) -> P {
        self.ports
    }

    /// Drive until the reducer declares a terminal outcome.
    ///
    /// Priority is deliberate: a reply to work already in flight is handled before a new submission
    /// is admitted. The alternative lets an operator's typing starve the turn that is mid-dispatch.
    pub async fn run(
        &mut self,
        submissions: &mut tokio::sync::mpsc::Receiver<Command>,
    ) -> Result<Outcome, DriverError> {
        loop {
            let command = match self.replies.pop_front() {
                Some(command) => command,
                None => submissions
                    .recv()
                    .await
                    .ok_or(DriverError::SubmissionsClosed)?,
            };

            let (next, actions) = reduce(&self.state, command);
            self.state = next;

            for action in actions {
                self.events
                    .emit(DriverEvent::Routed(action.clone()))
                    .await?;
                if let Some(outcome) = self.route(action).await? {
                    self.events
                        .emit(DriverEvent::Finished(outcome.clone()))
                        .await?;
                    return Ok(outcome);
                }
            }
        }
    }

    /// Route one action request. Returns the terminal outcome if this action ended the run.
    async fn route(&mut self, action: ActionRequest) -> Result<Option<Outcome>, DriverError> {
        match action {
            ActionRequest::SelectContext => match self.ports.select_context().await {
                Ok(grant) => self.push_reply(Command::ContextResolved {
                    grant: Box::new(grant),
                })?,
                Err(fault) => self.fault(fault)?,
            },
            ActionRequest::SampleBudget => {
                let ceiling = self.ports.sample_budget().await;
                self.push_reply(Command::BudgetSampled { ceiling })?;
            }
            ActionRequest::ObserveControl => {
                let signal = self.ports.observe_control().await;
                self.push_reply(Command::ControlObserved { signal })?;
            }
            ActionRequest::AdmitSteers { turn } => {
                let count = self.ports.admit_steers(turn).await;
                self.push_reply(Command::Steered { count })?;
            }
            ActionRequest::CallProvider { turn } => match self.ports.call_provider(turn).await {
                ProviderReply::Completed {
                    termination,
                    tool_calls,
                } => self.push_reply(Command::ProviderCompleted {
                    termination,
                    tool_calls,
                })?,
                ProviderReply::Failed(failure) => {
                    self.push_reply(Command::ProviderFailed { failure })?
                }
            },
            ActionRequest::DispatchTools { turn, calls } => {
                let any_error = self.ports.dispatch_tools(turn, calls).await;
                self.push_reply(Command::ToolsCompleted { any_error })?;
            }
            ActionRequest::RunVerify { turn, attempt } => {
                let outcome = self.ports.run_verify(turn, attempt).await;
                self.push_reply(Command::VerifyCompleted { outcome })?;
            }
            ActionRequest::Checkpoint { turn } => {
                // A failed checkpoint does not become a quiet Drained: the operator asked for a
                // durable snapshot and did not get one.
                if let Err(fault) = self.ports.checkpoint(turn).await {
                    self.fault(fault)?;
                }
            }
            ActionRequest::Notice { text } => self.ports.notice(text).await,
            ActionRequest::Continue { turn, reason } => self.ports.continuation(turn, reason).await,
            ActionRequest::AdvanceTurn { turn } => {
                if let Err(fault) = self.ports.advance_turn(turn).await {
                    self.fault(fault)?;
                }
            }
            ActionRequest::Finish { outcome } => return Ok(Some(outcome)),
        }
        Ok(None)
    }

    /// Hand a port fault to whoever owns it: a broken record goes to the reducer as a command, and
    /// anything else stops the driver, because only the reducer can turn a fault into an outcome.
    fn fault(&mut self, fault: PortFault) -> Result<(), DriverError> {
        match fault {
            PortFault::Record(_) => self.push_reply(Command::RecordFailed),
            PortFault::Port(reason) => Err(DriverError::Port(reason)),
        }
    }

    /// Queue a port reply. Refuses rather than growing without limit — the same rule the SQ follows,
    /// applied to the queue the driver owns itself.
    fn push_reply(&mut self, command: Command) -> Result<(), DriverError> {
        if self.replies.len() >= MAX_PENDING_REPLIES {
            return Err(DriverError::ReplyQueueFull);
        }
        self.replies.push_back(command);
        Ok(())
    }
}
