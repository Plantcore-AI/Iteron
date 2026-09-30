//! Provider-independent host for persistent agents. The controller owns durable state;
//! the runtime port owns resident contexts and physical cancellation/reaping.

use async_trait::async_trait;
use futures_util::FutureExt;
use iteron_agents::{
    AgentActor, AgentController, AgentControllerJournal, AgentMailboxMessage, ControllerError,
};
use iteron_protocol::agent_control::{
    AgentCommandV1, AgentControlReplyV1, AgentEpochV1, AgentIdV1, AgentMessageIdV1,
    AgentMessageStateV1, AgentStateV1, AgentUsageV1, AgentViewV1,
};
use iteron_protocol::{Block, Message, Role};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Semaphore, watch};

#[path = "persistent_agents/parent_turn.rs"]
mod parent_turn;
pub(super) mod prepared_mailbox;
#[path = "persistent_agents/weak_mailbox.rs"]
mod weak_mailbox;
pub(crate) use parent_turn::ParentRuntimeTurn;
#[path = "persistent_agents/provider_budget.rs"]
mod provider_budget;
#[path = "persistent_agents/workflow.rs"]
mod workflow;
pub(crate) use provider_budget::{RuntimeProviderBudgetAdmission, RuntimeProviderBudgetPort};

const MAX_PARALLEL_AGENTS: usize = 64;
const MAX_WAIT_MS: u64 = 60_000;
const MAX_INPUT_BATCH: usize = 128;

/// Transport and model tools bind the actor before calling this port. Actor identity is never
/// decoded from command JSON. Queries are current observations and must not be memoized.
#[async_trait]
pub(crate) trait AgentControlPort: Send + Sync {
    fn begin_parent_turn(
        &self,
        _source: String,
        _stop: Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<ParentRuntimeTurn, ControllerError> {
        Err(ControllerError::Permission)
    }
    fn finish_parent_turn(
        &self,
        _turn: &ParentRuntimeTurn,
        _result: &AgentSettlement,
        _wall_ms: u64,
    ) -> Result<(), ControllerError> {
        Err(ControllerError::Permission)
    }

    fn provider_budget_port(&self) -> Result<Arc<dyn RuntimeProviderBudgetPort>, ControllerError> {
        Err(ControllerError::Permission)
    }
    fn workspace_witness(
        &self,
    ) -> Result<Option<iteron_agents::AgentWorkspaceWitness>, ControllerError>;
    fn record_workspace_witness(
        &self,
        expected: Option<&iteron_agents::AgentWorkspaceWitness>,
        witness: iteron_agents::AgentWorkspaceWitness,
    ) -> Result<(), ControllerError>;
    fn host_limits(&self) -> Result<AgentHostLimits, ControllerError>;
    fn workflow_port(&self) -> Arc<dyn iteron_workflow::live_scheduler::WorkflowControllerPort>;
    fn workflow_completion(
        &self,
        task: &iteron_workflow::live_scheduler::ScheduledTaskV1,
    ) -> Result<Option<iteron_agents::AgentWorkflowCompletion>, ControllerError>;
    fn command(
        &self,
        actor: AgentActor,
        request_id: &str,
        command: AgentCommandV1,
    ) -> Result<AgentControlReplyV1, ControllerError>;
    fn list(&self, actor: AgentActor) -> Result<Vec<AgentViewV1>, ControllerError>;
    fn inspect(&self, actor: AgentActor, id: AgentIdV1) -> Result<AgentViewV1, ControllerError>;
    fn message(
        &self,
        actor: AgentActor,
        id: AgentMessageIdV1,
    ) -> Result<AgentMailboxMessage, ControllerError>;
    async fn wait(
        &self,
        actor: AgentActor,
        after_revision: u64,
        timeout_ms: u64,
    ) -> Result<AgentObservation, ControllerError>;
}

#[derive(Debug, Clone)]
pub(crate) struct AgentHostLimits {
    pub root: AgentViewV1,
    pub remaining: iteron_protocol::agent_control::AgentBudgetV1,
    /// None is absence of independently known monetary admission truth; never an invented cap.
    pub monetary_remaining: Option<u64>,
    pub max_agents: usize,
    pub max_concurrency: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct AgentObservation {
    pub revision: u64,
    pub agents: Vec<AgentViewV1>,
    pub timed_out: bool,
}

/// Every runtime result follows actual settlement. Unknown provider cost or unfinished process
/// cleanup is effects_known=false and leaves durable ownership quarantined.
#[derive(Clone)]
pub(crate) struct AgentSettlement {
    pub turns: u32,
    pub summary: String,
    pub tokens: u64,
    pub cost_microusd: u64,
    pub effects_known: bool,
    pub terminal: iteron_agents::AgentWorkflowTerminal,
}

#[async_trait]
pub(crate) trait PersistentAgentRuntime: Send + Sync {
    /// A repeated id must retain its context. This port must enforce the inherited runtime budget,
    /// apply only epoch-bound inputs and stop its processes before returning a known settlement.
    async fn execute(
        &self,
        agent: AgentViewV1,
        epoch: AgentEpochV1,
        initial: Vec<AgentMailboxMessage>,
        mailbox: LiveAgentMailbox,
    ) -> AgentSettlement;

    /// Called before durable spawn acceptance; rejects unsupported authority/profile combinations.
    fn validate_spawn(&self, command: &AgentCommandV1) -> Result<(), ControllerError>;
    fn monetary_remaining(&self) -> Result<Option<u64>, ControllerError> {
        Ok(None)
    }
}

trait MailboxPort: Send + Sync {
    fn provider_budget_port(
        &self,
        id: AgentIdV1,
        epoch: AgentEpochV1,
    ) -> Result<Arc<dyn RuntimeProviderBudgetPort>, ControllerError>;
    fn message(&self, id: AgentMessageIdV1) -> Result<AgentMailboxMessage, ControllerError>;
    fn deliver(
        &self,
        id: AgentIdV1,
        epoch: AgentEpochV1,
    ) -> Result<Vec<AgentMailboxMessage>, ControllerError>;
    fn consumed(
        &self,
        id: AgentIdV1,
        epoch: AgentEpochV1,
        messages: &[AgentMessageIdV1],
    ) -> Result<(), ControllerError>;
    fn state(&self, id: AgentIdV1) -> Result<AgentStateV1, ControllerError>;
}

/// Host-only evidence carried into the resident runtime. Receiving an inbox batch records
/// Delivered. Only exact user text in an actual model request records Consumed. This confirmation
/// means request inclusion; it never claims that a remote provider processed or obeyed the input.
#[derive(Clone)]
pub(crate) struct LiveAgentMailbox {
    id: AgentIdV1,
    epoch: AgentEpochV1,
    port: Arc<dyn MailboxPort>,
    witnesses: Arc<Mutex<prepared_mailbox::MailboxWitnesses>>,
    deferred: Arc<Mutex<Vec<AgentMailboxMessage>>>,
}

impl LiveAgentMailbox {
    pub(super) fn provider_budget_port(
        &self,
    ) -> Result<Arc<dyn RuntimeProviderBudgetPort>, ControllerError> {
        self.port.provider_budget_port(self.id, self.epoch)
    }
    pub fn stop_requested(&self) -> bool {
        !matches!(self.port.state(self.id), Ok(AgentStateV1::Running { epoch }) if epoch == self.epoch)
    }

    pub fn receive(&self) -> Result<Vec<AgentMailboxMessage>, ControllerError> {
        let mut deferred = self
            .deferred
            .lock()
            .map_err(|_| ControllerError::Poisoned)?;
        let fresh = self.port.deliver(self.id, self.epoch)?;
        if deferred.len().saturating_add(fresh.len()) > MAX_INPUT_BATCH {
            return Err(ControllerError::Capacity);
        }
        deferred.extend(fresh);
        Ok(std::mem::take(&mut *deferred))
    }

    /// Render one host-authenticated source envelope. It cannot grant execution authority.
    pub fn render(&self, input: &AgentMailboxMessage) -> Result<String, ControllerError> {
        let durable = self.port.message(input.id)?;
        if input != &durable
            || input.state != (AgentMessageStateV1::Delivered { epoch: self.epoch })
        {
            return Err(ControllerError::StaleEpoch);
        }
        if input.receiver != self.id {
            return Err(ControllerError::Permission);
        }
        let text = input
            .text
            .as_deref()
            .ok_or(ControllerError::UnknownMessage)?;
        if format!("{:x}", Sha256::digest(text.as_bytes())) != input.content_sha256 {
            return Err(ControllerError::Invalid("mailbox content witness mismatch"));
        }
        let sender = input
            .sender
            .map_or_else(|| "operator".into(), |sender| format!("agent:{}", sender.0));
        let envelope = format!(
            "[agent input id={} from={} to={} incarnation={} turn={} digest={}]\n{}\n[/agent input id={}]",
            input.id.0,
            sender,
            self.id.0,
            self.epoch.incarnation,
            self.epoch.turn,
            input.content_sha256,
            text,
            input.id.0
        );
        let mut witnesses = self
            .witnesses
            .lock()
            .map_err(|_| ControllerError::Poisoned)?;
        witnesses.register_envelope(input.id, envelope.clone())?;
        Ok(envelope)
    }

    /// A reopened transcript may contain a Delivered steer from an interrupted epoch. Only
    /// envelopes backed by a durable Consumed receipt may survive into another request.
    pub fn expire_restored(&self, messages: &mut [Message]) -> Result<bool, ControllerError> {
        let mut changed = false;
        let mut inspected = 0usize;
        for message in messages
            .iter_mut()
            .filter(|message| message.role == Role::User)
        {
            for block in &mut message.content {
                let Block::Text { text } = block else {
                    continue;
                };
                let mut cursor = 0usize;
                while let Some(offset) = text[cursor..].find("[agent input id=") {
                    inspected += 1;
                    if inspected > 4096 {
                        return Err(ControllerError::Capacity);
                    }
                    let start = cursor + offset;
                    let Some(header_end) = text[start..].find("]\n").map(|n| start + n) else {
                        break;
                    };
                    if header_end - start > 512 {
                        cursor = start + 1;
                        continue;
                    }
                    let header = &text[start..header_end + 1];
                    let fields: Vec<_> = header
                        .trim_start_matches("[agent input ")
                        .trim_end_matches(']')
                        .split(' ')
                        .collect();
                    if fields.len() != 6 {
                        cursor = header_end + 1;
                        continue;
                    }
                    let id = fields[0]
                        .strip_prefix("id=")
                        .and_then(|s| s.parse::<u64>().ok());
                    let Some(id) = id else {
                        cursor = header_end + 1;
                        continue;
                    };
                    let suffix = format!("\n[/agent input id={id}]");
                    let Some(end) = text[header_end + 2..]
                        .find(&suffix)
                        .map(|n| header_end + 2 + n)
                    else {
                        cursor = header_end + 1;
                        continue;
                    };
                    let body = &text[header_end + 2..end];
                    if body.len() > iteron_protocol::agent_control::MAX_AGENT_TEXT_BYTES {
                        return Err(ControllerError::Capacity);
                    }
                    let durable = match self.port.message(AgentMessageIdV1(id)) {
                        Ok(durable) => durable,
                        Err(ControllerError::UnknownMessage) => {
                            cursor = end + suffix.len();
                            continue;
                        }
                        Err(error) => return Err(error),
                    };
                    let sender = durable
                        .sender
                        .map_or_else(|| "operator".into(), |id| format!("agent:{}", id.0));
                    let incarnation = fields[3]
                        .strip_prefix("incarnation=")
                        .and_then(|s| s.parse::<u64>().ok());
                    let turn = fields[4]
                        .strip_prefix("turn=")
                        .and_then(|s| s.parse::<u64>().ok());
                    let valid = durable.receiver == self.id
                        && fields[1] == format!("from={sender}")
                        && fields[2] == format!("to={}", self.id.0)
                        && fields[5] == format!("digest={}", durable.content_sha256)
                        && format!("{:x}", Sha256::digest(body.as_bytes()))
                            == durable.content_sha256;
                    if !valid {
                        cursor = end + suffix.len();
                        continue;
                    }
                    let consumed = matches!(durable.state,AgentMessageStateV1::Consumed{epoch}
                        if Some(epoch.incarnation)==incarnation && Some(epoch.turn)==turn);
                    if consumed {
                        cursor = end + suffix.len();
                        continue;
                    }
                    let replacement =
                        format!("[agent input {id} expired before request inclusion]");
                    text.replace_range(start..end + suffix.len(), &replacement);
                    cursor = start + replacement.len();
                    changed = true;
                }
            }
        }
        Ok(changed)
    }

    /// Remove envelopes that never entered a model request before this epoch settled. The
    /// runtime persists the revised transcript, so a follow-up/restart cannot apply stale steer.
    pub fn expire_unrequested(&self, messages: &mut [Message]) -> Result<bool, ControllerError> {
        let witnesses = self
            .witnesses
            .lock()
            .map_err(|_| ControllerError::Poisoned)?;
        let mut changed = false;
        for message in messages
            .iter_mut()
            .filter(|message| message.role == Role::User)
        {
            for block in &mut message.content {
                if let Block::Text { text } = block {
                    for (id, envelope) in witnesses.envelopes.iter() {
                        if text.contains(envelope) {
                            *text = text.replace(
                                envelope,
                                &format!("[agent input {} expired before request inclusion]", id.0),
                            );
                            changed = true;
                        }
                    }
                }
            }
        }
        Ok(changed)
    }
}

struct Shared<J> {
    controller: Mutex<AgentController<J>>,
    runtime: Arc<dyn PersistentAgentRuntime>,
    permits: Arc<Semaphore>,
    parallel: usize,
    changed: watch::Sender<u64>,
    parent_stop: Mutex<Option<parent_turn::ParentStop>>,
    pending_settlements: Mutex<BTreeMap<AgentIdV1, (AgentEpochV1, AgentSettlement, u64)>>,
}

pub(crate) struct PersistentAgentHost<J> {
    shared: Arc<Shared<J>>,
}

impl<J> Clone for PersistentAgentHost<J> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
        }
    }
}

impl<J: AgentControllerJournal + Send + 'static> PersistentAgentHost<J> {
    /// Explicit installation only. Ordinary single-agent sessions create no journal, workers,
    /// model schemas, watch channels or runtime contexts for this subsystem.
    pub fn new(
        controller: AgentController<J>,
        runtime: Arc<dyn PersistentAgentRuntime>,
        parallel: usize,
    ) -> Result<Self, ControllerError> {
        if parallel == 0 || parallel > MAX_PARALLEL_AGENTS {
            return Err(ControllerError::Invalid(
                "invalid persistent-agent concurrency",
            ));
        }
        tokio::runtime::Handle::try_current()
            .map_err(|_| ControllerError::Invalid("agent host requires a running executor"))?;
        let (changed, _) = watch::channel(controller.revision());
        Ok(Self {
            shared: Arc::new(Shared {
                controller: Mutex::new(controller),
                runtime,
                permits: Arc::new(Semaphore::new(parallel)),
                parallel,
                changed,
                parent_stop: Mutex::new(None),
                pending_settlements: Mutex::new(BTreeMap::new()),
            }),
        })
    }

    fn notify(&self, revision: u64) {
        self.shared.changed.send_if_modified(|current| {
            if revision > *current {
                *current = revision;
                true
            } else {
                false
            }
        });
    }

    fn settle(
        &self,
        id: AgentIdV1,
        epoch: AgentEpochV1,
        result: &AgentSettlement,
        wall_ms: u64,
    ) -> Result<(), ControllerError> {
        let mut controller = self
            .shared
            .controller
            .lock()
            .map_err(|_| ControllerError::Poisoned)?;
        let current = controller.inspect(AgentActor::Operator, id)?;
        // Another retained-proof retry may already have persisted this terminal while a worker
        // was taking its bounded pending snapshot. Only the controller can leave an active epoch
        // for Idle/Closed; stale snapshots must not reapply usage or overwrite a later lease.
        if current.state.epoch() != Some(epoch)
            && current.incarnation >= epoch.incarnation
            && matches!(current.state, AgentStateV1::Idle | AgentStateV1::Closed)
        {
            return Ok(());
        }
        let settled = controller.finish_turn_with_terminal(
            id,
            epoch,
            &result.summary,
            AgentUsageV1 {
                turns: result.turns,
                tokens: result.tokens,
                cost_microusd: result.cost_microusd,
                wall_ms,
            },
            result.effects_known,
            result.terminal,
        );
        self.notify(controller.revision());
        settled
    }

    fn start_execution(
        &self,
        view: AgentViewV1,
        epoch: AgentEpochV1,
        initial: Vec<AgentMailboxMessage>,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) {
        let host = self.clone();
        let mailbox = LiveAgentMailbox {
            id: view.agent_id,
            epoch,
            port: Arc::new(weak_mailbox::WeakMailbox::new(self)),
            witnesses: Arc::new(Mutex::new(prepared_mailbox::MailboxWitnesses::default())),
            deferred: Arc::new(Mutex::new(Vec::new())),
        };
        tokio::spawn(async move {
            let id = view.agent_id;
            let wall =
                Duration::from_millis(view.budget.wall_ms.saturating_sub(view.usage.wall_ms));
            let started = Instant::now();
            let execution = std::panic::AssertUnwindSafe(
                host.shared.runtime.execute(view, epoch, initial, mailbox),
            )
            .catch_unwind();
            let result = match tokio::time::timeout(wall, execution).await {
                Ok(Ok(result)) => result,
                Ok(Err(_)) | Err(_) => AgentSettlement {
                    turns: 0,
                    summary: "Agent deadline expired; physical effects require reconciliation"
                        .into(),
                    tokens: 0,
                    cost_microusd: 0,
                    effects_known: false,
                    terminal: iteron_agents::AgentWorkflowTerminal::StoppedRecovery,
                },
            };
            let elapsed = u64::try_from(started.elapsed().as_millis())
                .unwrap_or(u64::MAX)
                .max(1);
            if host.settle(id, epoch, &result, elapsed).is_err()
                && let Ok(mut pending) = host.shared.pending_settlements.lock()
            {
                pending.insert(id, (epoch, result, elapsed));
            }
            drop(permit);
            // A queued follow-up can start only after the previous physical runtime settled.
            let _ = host.dispatch_ready();
        });
    }

    fn dispatch_ready(&self) -> Result<(), ControllerError> {
        // Definite storage refusal retains the exact physical settlement for a bounded retry.
        // Unknown commits remain poisoned; no terminal or budget claim is fabricated.
        let pending = self
            .shared
            .pending_settlements
            .lock()
            .map_err(|_| ControllerError::Poisoned)?
            .clone();
        for (id, (epoch, result, wall)) in pending {
            self.settle(id, epoch, &result, wall)?;
            self.shared
                .pending_settlements
                .lock()
                .map_err(|_| ControllerError::Poisoned)?
                .remove(&id);
        }
        let views = self.list(AgentActor::Operator)?;
        for view in views.into_iter().filter(|agent| {
            agent.parent_id.is_some()
                && agent.state == AgentStateV1::Idle
                && agent.queued_messages > 0
        }) {
            let Ok(permit) = self.shared.permits.clone().try_acquire_owned() else {
                break;
            };
            let claimed = {
                let mut controller = self
                    .shared
                    .controller
                    .lock()
                    .map_err(|_| ControllerError::Poisoned)?;
                let started_at = u64::try_from(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|_| ControllerError::Invalid("runtime clock is before epoch"))?
                        .as_millis(),
                )
                .map_err(|_| ControllerError::Capacity)?;
                match controller.begin_runtime_turn(view.agent_id, started_at) {
                    Ok(Some(epoch)) => {
                        let initial = match controller.deliver(view.agent_id, epoch, true) {
                            Ok(initial) => initial,
                            Err(error) => {
                                let result = AgentSettlement {
                                    turns: 0,
                                    summary: "Mailbox delivery failed before runtime dispatch"
                                        .into(),
                                    tokens: 0,
                                    cost_microusd: 0,
                                    effects_known: true,
                                    terminal: iteron_agents::AgentWorkflowTerminal::Failed,
                                };
                                self.shared
                                    .pending_settlements
                                    .lock()
                                    .map_err(|_| ControllerError::Poisoned)?
                                    .insert(view.agent_id, (epoch, result, 1));
                                return Err(error);
                            }
                        };
                        self.notify(controller.revision());
                        Some((
                            controller.inspect(AgentActor::Operator, view.agent_id)?,
                            epoch,
                            initial,
                        ))
                    }
                    Ok(None) | Err(ControllerError::Budget) => None,
                    Err(error) => return Err(error),
                }
            };
            let Some((view, epoch, initial)) = claimed else {
                continue;
            };
            self.start_execution(view, epoch, initial, permit);
        }
        Ok(())
    }
}

#[async_trait]
impl<J: AgentControllerJournal + Send + 'static> AgentControlPort for PersistentAgentHost<J> {
    fn begin_parent_turn(
        &self,
        source: String,
        stop: Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<ParentRuntimeTurn, ControllerError> {
        self.begin_parent(source, stop)
    }
    fn finish_parent_turn(
        &self,
        turn: &ParentRuntimeTurn,
        result: &AgentSettlement,
        wall_ms: u64,
    ) -> Result<(), ControllerError> {
        self.finish_parent(turn, result, wall_ms)
    }

    fn provider_budget_port(&self) -> Result<Arc<dyn RuntimeProviderBudgetPort>, ControllerError> {
        let id = self
            .shared
            .controller
            .lock()
            .map_err(|_| ControllerError::Poisoned)?
            .root_id();
        Ok(Arc::new(provider_budget::ProviderPort::new(
            self.clone(),
            id,
            None,
        )))
    }
    fn workspace_witness(
        &self,
    ) -> Result<Option<iteron_agents::AgentWorkspaceWitness>, ControllerError> {
        self.shared
            .controller
            .lock()
            .map_err(|_| ControllerError::Poisoned)?
            .workspace_witness()
    }
    fn record_workspace_witness(
        &self,
        expected: Option<&iteron_agents::AgentWorkspaceWitness>,
        witness: iteron_agents::AgentWorkspaceWitness,
    ) -> Result<(), ControllerError> {
        let mut controller = self
            .shared
            .controller
            .lock()
            .map_err(|_| ControllerError::Poisoned)?;
        controller.record_workspace_witness(expected, witness)?;
        self.notify(controller.revision());
        Ok(())
    }
    fn host_limits(&self) -> Result<AgentHostLimits, ControllerError> {
        let controller = self
            .shared
            .controller
            .lock()
            .map_err(|_| ControllerError::Poisoned)?;
        let root = controller.inspect(AgentActor::Operator, controller.root_id())?;
        let views = controller.list(AgentActor::Operator)?;
        if controller.provider_budget_recovery_required()
            || views
                .iter()
                .any(|view| matches!(view.state, AgentStateV1::RecoveryRequired { .. }))
        {
            return Err(ControllerError::RecoveryRequired);
        }
        let mut used = AgentUsageV1::default();
        let pending = controller.pending_provider_usage()?;
        used.tokens = pending.tokens;
        used.cost_microusd = pending.cost_microusd;
        for view in views {
            used.turns = used
                .turns
                .checked_add(view.usage.turns)
                .ok_or(ControllerError::Budget)?;
            used.tokens = used
                .tokens
                .checked_add(view.usage.tokens)
                .ok_or(ControllerError::Budget)?;
            used.cost_microusd = used
                .cost_microusd
                .checked_add(view.usage.cost_microusd)
                .ok_or(ControllerError::Budget)?;
            used.wall_ms = used
                .wall_ms
                .checked_add(view.usage.wall_ms)
                .ok_or(ControllerError::Budget)?;
        }
        let monetary_remaining = self.shared.runtime.monetary_remaining()?;
        let remaining = iteron_protocol::agent_control::AgentBudgetV1 {
            turns: root.budget.turns.saturating_sub(used.turns),
            tokens: root.budget.tokens.saturating_sub(used.tokens),
            cost_microusd: root
                .budget
                .cost_microusd
                .saturating_sub(used.cost_microusd)
                .min(monetary_remaining.unwrap_or(0)),
            wall_ms: root.budget.wall_ms.saturating_sub(used.wall_ms),
        };
        Ok(AgentHostLimits {
            root,
            remaining,
            monetary_remaining,
            max_agents: controller.snapshot().config().max_agents,
            max_concurrency: self.shared.parallel,
        })
    }

    fn workflow_port(&self) -> Arc<dyn iteron_workflow::live_scheduler::WorkflowControllerPort> {
        Arc::new(self.clone())
    }
    fn workflow_completion(
        &self,
        task: &iteron_workflow::live_scheduler::ScheduledTaskV1,
    ) -> Result<Option<iteron_agents::AgentWorkflowCompletion>, ControllerError> {
        let claim = workflow::claim(task.clone())?;
        self.shared
            .controller
            .lock()
            .map_err(|_| ControllerError::Poisoned)?
            .workflow_completion(&claim)
    }

    fn command(
        &self,
        actor: AgentActor,
        request_id: &str,
        command: AgentCommandV1,
    ) -> Result<AgentControlReplyV1, ControllerError> {
        self.shared.runtime.validate_spawn(&command)?;
        let reply = {
            let mut controller = self
                .shared
                .controller
                .lock()
                .map_err(|_| ControllerError::Poisoned)?;
            let reply = controller.execute(actor, request_id, command)?;
            self.notify(controller.revision());
            reply
        };
        // Acceptance remains valid if later execution cannot start. A worker never starts twice
        // because begin_turn is the durable controller claim under the same state-owner mutex.
        self.signal_parent_stop()?;
        let _ = self.dispatch_ready();
        Ok(reply)
    }

    fn list(&self, actor: AgentActor) -> Result<Vec<AgentViewV1>, ControllerError> {
        self.shared
            .controller
            .lock()
            .map_err(|_| ControllerError::Poisoned)?
            .list(actor)
    }

    fn inspect(&self, actor: AgentActor, id: AgentIdV1) -> Result<AgentViewV1, ControllerError> {
        self.shared
            .controller
            .lock()
            .map_err(|_| ControllerError::Poisoned)?
            .inspect(actor, id)
    }

    fn message(
        &self,
        actor: AgentActor,
        id: AgentMessageIdV1,
    ) -> Result<AgentMailboxMessage, ControllerError> {
        self.shared
            .controller
            .lock()
            .map_err(|_| ControllerError::Poisoned)?
            .message(actor, id)
    }

    async fn wait(
        &self,
        actor: AgentActor,
        after_revision: u64,
        timeout_ms: u64,
    ) -> Result<AgentObservation, ControllerError> {
        if timeout_ms == 0 || timeout_ms > MAX_WAIT_MS {
            return Err(ControllerError::Invalid(
                "agent wait exceeds its bounded timeout",
            ));
        }
        // Subscribe before inspecting, so a change between inspection and waiting is retained.
        let mut changed = self.shared.changed.subscribe();
        let observe = || {
            let controller = self
                .shared
                .controller
                .lock()
                .map_err(|_| ControllerError::Poisoned)?;
            Ok::<_, ControllerError>((controller.revision(), controller.list(actor)?))
        };
        let (revision, agents) = observe()?;
        if after_revision > revision {
            return Err(ControllerError::Invalid(
                "agent wait cursor is ahead of durable state",
            ));
        }
        if revision > after_revision {
            return Ok(AgentObservation {
                revision,
                agents,
                timed_out: false,
            });
        }
        let timed_out = tokio::time::timeout(Duration::from_millis(timeout_ms), changed.changed())
            .await
            .is_err();
        let (revision, agents) = observe()?;
        Ok(AgentObservation {
            revision,
            agents,
            timed_out,
        })
    }
}

impl<J: AgentControllerJournal + Send + 'static> MailboxPort for PersistentAgentHost<J> {
    fn provider_budget_port(
        &self,
        id: AgentIdV1,
        epoch: AgentEpochV1,
    ) -> Result<Arc<dyn RuntimeProviderBudgetPort>, ControllerError> {
        let controller = self
            .shared
            .controller
            .lock()
            .map_err(|_| ControllerError::Poisoned)?;
        if controller.inspect(AgentActor::Operator, id)?.state.epoch() != Some(epoch) {
            return Err(ControllerError::StaleEpoch);
        }
        Ok(Arc::new(provider_budget::ProviderPort::new(
            self.clone(),
            id,
            Some(epoch),
        )))
    }
    fn message(&self, id: AgentMessageIdV1) -> Result<AgentMailboxMessage, ControllerError> {
        AgentControlPort::message(self, AgentActor::Operator, id)
    }
    fn deliver(
        &self,
        id: AgentIdV1,
        epoch: AgentEpochV1,
    ) -> Result<Vec<AgentMailboxMessage>, ControllerError> {
        let mut controller = self
            .shared
            .controller
            .lock()
            .map_err(|_| ControllerError::Poisoned)?;
        let input = controller.deliver(id, epoch, false)?;
        self.notify(controller.revision());
        Ok(input)
    }

    fn consumed(
        &self,
        id: AgentIdV1,
        epoch: AgentEpochV1,
        messages: &[AgentMessageIdV1],
    ) -> Result<(), ControllerError> {
        let mut controller = self
            .shared
            .controller
            .lock()
            .map_err(|_| ControllerError::Poisoned)?;
        controller.mark_consumed(id, epoch, messages)?;
        self.notify(controller.revision());
        Ok(())
    }

    fn state(&self, id: AgentIdV1) -> Result<AgentStateV1, ControllerError> {
        self.inspect(AgentActor::Operator, id)
            .map(|view| view.state)
    }
}
