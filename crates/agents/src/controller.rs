//! Persistent agent identity and mailbox authority, independent of providers and schedulers.
//!
//! A journal commit precedes every accepted transition. Runtime delivery, model consumption and
//! terminal settlement are separate host-only transitions. A replayed running agent needs effect
//! reconciliation; opening a store never restarts an unknown execution.

use crate::controller_error::{ControllerError, ControllerStoreError};
use crate::mailbox::{AgentMailbox, AgentMailboxMessage};
use iteron_protocol::agent_control::{
    AGENT_CONTROL_VERSION, AgentBudgetV1, AgentCommandV1, AgentControlReplyV1, AgentEpochV1,
    AgentIdV1, AgentMessageIdV1, AgentMessageKindV1, AgentStateV1, AgentUsageV1, AgentViewV1,
    MAX_AGENT_REQUEST_ID_BYTES, MAX_AGENT_TEXT_BYTES,
};
use iteron_protocol::{Capability, capability_set::CapabilitySet};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

mod snapshot_validation;
mod workflow_claim;
use snapshot_validation::validate_snapshot;
pub use workflow_claim::{AgentWorkflowClaim, AgentWorkflowCompletion, AgentWorkflowLease};

const MAX_AGENTS: usize = 64;
const MAX_RECEIPTS: usize = 8_192;
const MAX_HIERARCHY_DEPTH: usize = 16;
const MAX_SNAPSHOT_BYTES: usize = 32 * 1024 * 1024;
const MAX_REVISION: u64 = 65_536;

/// Constructed by the authenticated host, never decoded from model/client JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentActor {
    Operator,
    Agent(AgentIdV1),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentControllerConfig {
    pub workspace_scope: String,
    pub root_capabilities: CapabilitySet,
    pub root_budget: AgentBudgetV1,
    pub max_agents: usize,
    pub max_pending_per_agent: usize,
}

impl AgentControllerConfig {
    fn validate(&self) -> Result<(), ControllerError> {
        self.root_budget
            .validate()
            .map_err(ControllerError::Invalid)?;
        if self.workspace_scope.is_empty()
            || self.workspace_scope.len() > 256
            || self.workspace_scope.chars().any(char::is_control)
            || self.max_agents == 0
            || self.max_agents > MAX_AGENTS
            || self.max_pending_per_agent == 0
            || self.max_pending_per_agent > 128
            || !self.root_capabilities.contains(Capability::ReadOnly)
        {
            return Err(ControllerError::Invalid(
                "invalid controller scope, capacity or root authority",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentRecord {
    view: AgentViewV1,
    next_turn: u64,
    active_task: Option<AgentMessageIdV1>,
    turns_used: u32,
    tokens_used: u64,
    cost_used: u64,
    #[serde(default)]
    wall_used_ms: u64,
    #[serde(default)]
    runtime_started_at_unix_ms: Option<u64>,
    reserved_turns: u32,
    reserved_tokens: u64,
    reserved_cost: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestReceipt {
    digest: String,
    reply: AgentControlReplyV1,
}

/// Opaque durable state. Storage adapters serialize it; they have no mutable agent-state port.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentControllerSnapshot {
    version: u32,
    config: AgentControllerConfig,
    revision: u64,
    next_agent: u64,
    agents: BTreeMap<AgentIdV1, AgentRecord>,
    mailbox: AgentMailbox,
    receipts: BTreeMap<String, RequestReceipt>,
    #[serde(default)]
    workflow_claims: BTreeMap<String, workflow_claim::WorkflowReceipt>,
}

impl AgentControllerSnapshot {
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn config(&self) -> &AgentControllerConfig {
        &self.config
    }
}

/// Compare-and-commit must be durable before returning Ok. A uncertain fsync/rename result is
/// OutcomeUnknown, not a definite refusal. This seam admits file, database and in-memory tests
/// without giving the controller a filesystem, transport, provider or clock dependency.
pub trait AgentControllerJournal {
    fn load(&mut self) -> Result<Option<AgentControllerSnapshot>, ControllerStoreError>;
    fn commit(
        &mut self,
        expected_revision: Option<u64>,
        next: &AgentControllerSnapshot,
    ) -> Result<(), ControllerStoreError>;
}

pub struct AgentController<J> {
    journal: J,
    snapshot: AgentControllerSnapshot,
    poisoned: bool,
}

impl<J: AgentControllerJournal> AgentController<J> {
    pub fn open(mut journal: J, config: AgentControllerConfig) -> Result<Self, ControllerError> {
        config.validate()?;
        let loaded = journal.load().map_err(ControllerError::Store)?;
        let mut snapshot = match loaded {
            Some(snapshot) => {
                validate_snapshot(&snapshot)?;
                if snapshot.config != config {
                    return Err(ControllerError::Invalid(
                        "controller configuration differs from durable genesis",
                    ));
                }
                snapshot
            }
            None => {
                let root = record(
                    AgentIdV1(1),
                    None,
                    "root".into(),
                    &config,
                    config.root_capabilities,
                    config.root_budget,
                    Vec::new(),
                );
                let mailbox = AgentMailbox::new(config.max_pending_per_agent);
                let snapshot = AgentControllerSnapshot {
                    version: AGENT_CONTROL_VERSION,
                    config,
                    revision: 0,
                    next_agent: 2,
                    agents: BTreeMap::from([(AgentIdV1(1), root)]),
                    mailbox,
                    receipts: BTreeMap::new(),
                    workflow_claims: BTreeMap::new(),
                };
                journal
                    .commit(None, &snapshot)
                    .map_err(ControllerError::Store)?;
                snapshot
            }
        };
        // Durable running ownership is preserved and quarantined before the host receives any
        // live capability. Delivered input is not downgraded to Accepted or silently replayed.
        let expected = snapshot.revision;
        let mut changed = false;
        for agent in snapshot.agents.values_mut() {
            if let Some(epoch) = agent.view.state.epoch()
                && !matches!(agent.view.state, AgentStateV1::RecoveryRequired { .. })
            {
                agent.view.state = AgentStateV1::RecoveryRequired { epoch };
                changed = true;
            }
        }
        if changed {
            snapshot.revision = next_revision(expected)?;
            journal
                .commit(Some(expected), &snapshot)
                .map_err(ControllerError::Store)?;
        }
        Ok(Self {
            journal,
            snapshot,
            poisoned: false,
        })
    }

    pub fn root_id(&self) -> AgentIdV1 {
        AgentIdV1(1)
    }
    pub fn revision(&self) -> u64 {
        self.snapshot.revision
    }
    pub fn snapshot(&self) -> &AgentControllerSnapshot {
        &self.snapshot
    }

    pub fn list(&self, actor: AgentActor) -> Result<Vec<AgentViewV1>, ControllerError> {
        self.check_live()?;
        self.check_actor(actor)?;
        Ok(self
            .snapshot
            .agents
            .values()
            .filter(|agent| self.can_message(actor, agent.view.agent_id))
            .map(|agent| self.project(agent))
            .collect())
    }

    pub fn inspect(
        &self,
        actor: AgentActor,
        id: AgentIdV1,
    ) -> Result<AgentViewV1, ControllerError> {
        self.check_live()?;
        self.check_actor(actor)?;
        if !self.can_message(actor, id) {
            return Err(ControllerError::Permission);
        }
        self.snapshot
            .agents
            .get(&id)
            .map(|agent| self.project(agent))
            .ok_or(ControllerError::UnknownAgent)
    }

    pub fn message(
        &self,
        actor: AgentActor,
        id: AgentMessageIdV1,
    ) -> Result<AgentMailboxMessage, ControllerError> {
        self.check_live()?;
        self.check_actor(actor)?;
        let message = self
            .snapshot
            .mailbox
            .message(id)
            .ok_or(ControllerError::UnknownMessage)?;
        if actor != AgentActor::Operator
            && actor != AgentActor::Agent(message.receiver)
            && message.sender.map(AgentActor::Agent) != Some(actor)
        {
            return Err(ControllerError::Permission);
        }
        Ok(message.clone())
    }

    pub fn execute(
        &mut self,
        actor: AgentActor,
        request_id: &str,
        command: AgentCommandV1,
    ) -> Result<AgentControlReplyV1, ControllerError> {
        self.check_live()?;
        self.check_actor(actor)?;
        command.validate().map_err(ControllerError::Invalid)?;
        if request_id.is_empty()
            || request_id.len() > MAX_AGENT_REQUEST_ID_BYTES
            || !request_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b':' | b'_' | b'-'))
        {
            return Err(ControllerError::Invalid("invalid agent request identity"));
        }
        let namespace = match actor {
            AgentActor::Operator => "operator".into(),
            AgentActor::Agent(id) => format!("agent:{}", id.0),
        };
        let key = format!("{namespace}:{request_id}");
        let digest = digest(&command)?;
        if let Some(prior) = self.snapshot.receipts.get(&key) {
            if prior.digest != digest {
                return Err(ControllerError::RequestConflict);
            }
            let mut reply = prior.reply.clone();
            reply.replayed = true;
            return Ok(reply);
        }
        if self.snapshot.receipts.len() >= MAX_RECEIPTS {
            return Err(ControllerError::Capacity);
        }
        let mut next = self.snapshot.clone();
        let (agent_id, message_id) = match command {
            AgentCommandV1::Spawn {
                parent_id,
                label,
                task,
                capabilities,
                budget,
                write_paths,
            } => {
                if actor != AgentActor::Operator && actor != AgentActor::Agent(parent_id) {
                    return Err(ControllerError::Permission);
                }
                self.check_open(parent_id)?;
                let parent = next
                    .agents
                    .get_mut(&parent_id)
                    .ok_or(ControllerError::UnknownAgent)?;
                if !capabilities.is_subset_of(parent.view.capabilities)
                    || !capabilities.contains(Capability::ReadOnly)
                {
                    return Err(ControllerError::Permission);
                }
                if self.depth(parent_id)? >= MAX_HIERARCHY_DEPTH
                    || next.agents.len() >= next.config.max_agents
                {
                    return Err(ControllerError::Capacity);
                }
                let parent = next
                    .agents
                    .get_mut(&parent_id)
                    .ok_or(ControllerError::UnknownAgent)?;
                if !budget.fits_within(parent.view.budget) {
                    return Err(ControllerError::Budget);
                }
                reserve(parent, budget)?;
                if parent_id != self.root_id()
                    && write_paths.iter().any(|path| {
                        !parent
                            .view
                            .write_paths
                            .iter()
                            .any(|allowed| path_within(path, allowed))
                    })
                {
                    return Err(ControllerError::Permission);
                }
                if !write_paths.is_empty() && !capabilities.contains(Capability::ReversibleLocal) {
                    return Err(ControllerError::Permission);
                }
                if next
                    .agents
                    .values()
                    .filter(|agent| agent.view.state != AgentStateV1::Closed)
                    .any(|agent| {
                        agent.view.agent_id != parent_id
                            && agent.view.parent_id.is_some()
                            && agent.view.write_paths.iter().any(|existing| {
                                write_paths.iter().any(|path| {
                                    path_within(path, existing) || path_within(existing, path)
                                })
                            })
                    })
                {
                    return Err(ControllerError::Permission);
                }
                let id = AgentIdV1(next.next_agent);
                next.next_agent = next
                    .next_agent
                    .checked_add(1)
                    .ok_or(ControllerError::Capacity)?;
                next.agents.insert(
                    id,
                    record(
                        id,
                        Some(parent_id),
                        label,
                        &next.config,
                        capabilities,
                        budget,
                        write_paths,
                    ),
                );
                let message = enqueue(&mut next, actor, id, task, AgentMessageKindV1::Task, None)?;
                (id, Some(message))
            }
            AgentCommandV1::SendMessage { agent_id, text } => {
                if !self.can_message(actor, agent_id) {
                    return Err(ControllerError::Permission);
                }
                self.check_open(agent_id)?;
                let message = enqueue(
                    &mut next,
                    actor,
                    agent_id,
                    text,
                    AgentMessageKindV1::Message,
                    None,
                )?;
                (agent_id, Some(message))
            }
            AgentCommandV1::FollowupTask { agent_id, text } => {
                self.check_control(actor, agent_id)?;
                self.check_open(agent_id)?;
                let message = enqueue(
                    &mut next,
                    actor,
                    agent_id,
                    text,
                    AgentMessageKindV1::Task,
                    None,
                )?;
                (agent_id, Some(message))
            }
            AgentCommandV1::Steer {
                agent_id,
                epoch,
                text,
            } => {
                self.check_control(actor, agent_id)?;
                self.check_running(agent_id, epoch)?;
                let message = enqueue(
                    &mut next,
                    actor,
                    agent_id,
                    text,
                    AgentMessageKindV1::Steer,
                    Some(epoch),
                )?;
                (agent_id, Some(message))
            }
            AgentCommandV1::Interrupt { agent_id, epoch } => {
                self.check_control(actor, agent_id)?;
                self.check_running(agent_id, epoch)?;
                next.agents
                    .get_mut(&agent_id)
                    .ok_or(ControllerError::UnknownAgent)?
                    .view
                    .state = AgentStateV1::Interrupting { epoch };
                (agent_id, None)
            }
            AgentCommandV1::Close {
                agent_id,
                include_descendants,
            } => {
                self.check_control(actor, agent_id)?;
                if !include_descendants
                    && next.agents.values().any(|agent| {
                        agent.view.parent_id == Some(agent_id)
                            && agent.view.state != AgentStateV1::Closed
                    })
                {
                    return Err(ControllerError::Invalid(
                        "closing an agent with live children requires explicit subtree close",
                    ));
                }
                let ids: Vec<_> = next
                    .agents
                    .keys()
                    .copied()
                    .filter(|id| {
                        *id == agent_id
                            || (include_descendants && self.is_descendant(*id, agent_id))
                    })
                    .collect();
                for id in ids {
                    let agent = next
                        .agents
                        .get_mut(&id)
                        .ok_or(ControllerError::UnknownAgent)?;
                    agent.view.state = match agent.view.state {
                        AgentStateV1::Idle | AgentStateV1::Closed => AgentStateV1::Closed,
                        AgentStateV1::RecoveryRequired { .. } => {
                            return Err(ControllerError::RecoveryRequired);
                        }
                        state => AgentStateV1::Closing {
                            epoch: state.epoch().ok_or(ControllerError::StaleEpoch)?,
                        },
                    };
                    next.mailbox.reject_accepted(id);
                }
                (agent_id, None)
            }
        };
        next.revision = next_revision(self.snapshot.revision)?;
        let reply = AgentControlReplyV1 {
            version: AGENT_CONTROL_VERSION,
            revision: next.revision,
            agent_id,
            message_id,
            state: next
                .agents
                .get(&agent_id)
                .ok_or(ControllerError::UnknownAgent)?
                .view
                .state,
            replayed: false,
        };
        next.receipts.insert(
            key,
            RequestReceipt {
                digest,
                reply: reply.clone(),
            },
        );
        self.commit(next)?;
        Ok(reply)
    }

    /// Host dispatch claim. Plain messages in an idle mailbox never produce a model request.
    pub fn begin_turn(&mut self, id: AgentIdV1) -> Result<Option<AgentEpochV1>, ControllerError> {
        self.begin_turn_inner(id, None)
    }

    /// Real runtime admission persists a clock anchor before execution. After a crash it cannot
    /// use the legacy zero-usage reconciliation path or silently restart its wall budget.
    pub fn begin_runtime_turn(
        &mut self,
        id: AgentIdV1,
        started_at_unix_ms: u64,
    ) -> Result<Option<AgentEpochV1>, ControllerError> {
        if started_at_unix_ms == 0 {
            return Err(ControllerError::Invalid("runtime clock anchor is missing"));
        }
        self.begin_turn_inner(id, Some(started_at_unix_ms))
    }

    fn begin_turn_inner(
        &mut self,
        id: AgentIdV1,
        started_at_unix_ms: Option<u64>,
    ) -> Result<Option<AgentEpochV1>, ControllerError> {
        self.check_live()?;
        self.check_open(id)?;
        let record = self
            .snapshot
            .agents
            .get(&id)
            .ok_or(ControllerError::UnknownAgent)?;
        if record.view.state != AgentStateV1::Idle {
            return Ok(None);
        }
        let task = self.snapshot.mailbox.pending_task(id);
        let Some(task) = task else {
            return Ok(None);
        };
        if record
            .turns_used
            .checked_add(record.reserved_turns)
            .is_none_or(|used| used >= record.view.budget.turns)
            || record
                .tokens_used
                .checked_add(record.reserved_tokens)
                .is_none_or(|used| used >= record.view.budget.tokens)
            || record
                .cost_used
                .checked_add(record.reserved_cost)
                .is_none_or(|used| used > record.view.budget.cost_microusd)
            || record.wall_used_ms >= record.view.budget.wall_ms
        {
            return Err(ControllerError::Budget);
        }
        let mut next = self.snapshot.clone();
        let record = next
            .agents
            .get_mut(&id)
            .ok_or(ControllerError::UnknownAgent)?;
        let epoch = AgentEpochV1 {
            incarnation: record.view.incarnation,
            turn: record.next_turn,
        };
        record.next_turn = record
            .next_turn
            .checked_add(1)
            .ok_or(ControllerError::Capacity)?;
        record.turns_used += 1;
        record.active_task = Some(task);
        record.runtime_started_at_unix_ms = started_at_unix_ms;
        record.view.state = AgentStateV1::Running { epoch };
        next.revision = next_revision(next.revision)?;
        self.commit(next)?;
        Ok(Some(epoch))
    }

    /// Host-only safe-point claim, preserving mailbox sequence. Task follow-ups queued during a
    /// running turn remain for its next turn; steering never migrates across an epoch boundary.
    pub fn deliver(
        &mut self,
        id: AgentIdV1,
        epoch: AgentEpochV1,
        starting_turn: bool,
    ) -> Result<Vec<AgentMailboxMessage>, ControllerError> {
        self.check_live()?;
        self.check_running(id, epoch)?;
        let mut next = self.snapshot.clone();
        let active_task = next
            .agents
            .get(&id)
            .ok_or(ControllerError::UnknownAgent)?
            .active_task;
        let delivered = next.mailbox.deliver(id, epoch, active_task, starting_turn);
        if next.mailbox == self.snapshot.mailbox {
            return Ok(delivered);
        }
        next.revision = next_revision(next.revision)?;
        self.commit(next)?;
        Ok(delivered)
    }

    /// A durable consumed receipt is emitted only when the runtime proves the exact inputs have
    /// entered a model request. Transport delivery or a stored message alone cannot call this.
    pub fn mark_consumed(
        &mut self,
        id: AgentIdV1,
        epoch: AgentEpochV1,
        messages: &[AgentMessageIdV1],
    ) -> Result<(), ControllerError> {
        self.check_live()?;
        self.check_running(id, epoch)?;
        if messages.is_empty() {
            return Ok(());
        }
        let mut next = self.snapshot.clone();
        next.mailbox.mark_consumed(id, epoch, messages)?;
        next.revision = next_revision(next.revision)?;
        self.commit(next)
    }

    /// Physical runtime settlement follows cancellation/reaping and actual usage accounting.
    /// Unknown effects leave the agent quarantined and cannot be followed up blindly.
    pub fn finish_turn(
        &mut self,
        id: AgentIdV1,
        epoch: AgentEpochV1,
        summary: &str,
        tokens: u64,
        cost_microusd: u64,
        effects_known: bool,
    ) -> Result<(), ControllerError> {
        self.finish_turn_with_usage(
            id,
            epoch,
            summary,
            AgentUsageV1 {
                turns: 0,
                tokens,
                cost_microusd,
                wall_ms: 0,
            },
            effects_known,
        )
    }

    /// Host supplies elapsed execution time after real settlement. Wall time is cumulative across
    /// follow-ups and survives restart; creating another turn cannot reset the lifetime ceiling.
    pub fn finish_turn_with_usage(
        &mut self,
        id: AgentIdV1,
        epoch: AgentEpochV1,
        summary: &str,
        usage: AgentUsageV1,
        effects_known: bool,
    ) -> Result<(), ControllerError> {
        self.check_live()?;
        if summary.len() > MAX_AGENT_TEXT_BYTES || summary.contains('\0') {
            return Err(ControllerError::Capacity);
        }
        let current = self
            .snapshot
            .agents
            .get(&id)
            .ok_or(ControllerError::UnknownAgent)?;
        if current.view.state.epoch() != Some(epoch)
            || matches!(current.view.state, AgentStateV1::RecoveryRequired { .. })
        {
            return Err(ControllerError::StaleEpoch);
        }
        let workflow_budget_fits =
            workflow_claim::settlement_fits(&self.snapshot, id, epoch, usage);
        let mut next = self.snapshot.clone();
        let record = next
            .agents
            .get_mut(&id)
            .ok_or(ControllerError::UnknownAgent)?;
        record.tokens_used = record
            .tokens_used
            .checked_add(usage.tokens)
            .ok_or(ControllerError::Budget)?;
        record.cost_used = record
            .cost_used
            .checked_add(usage.cost_microusd)
            .ok_or(ControllerError::Budget)?;
        record.wall_used_ms = record
            .wall_used_ms
            .checked_add(usage.wall_ms)
            .ok_or(ControllerError::Budget)?;
        let within_budget = workflow_budget_fits
            && record
                .tokens_used
                .checked_add(record.reserved_tokens)
                .is_some_and(|used| used <= record.view.budget.tokens)
            && record
                .cost_used
                .checked_add(record.reserved_cost)
                .is_some_and(|used| used <= record.view.budget.cost_microusd)
            && record.wall_used_ms <= record.view.budget.wall_ms;
        record.view.last_summary = Some(summary.to_owned());
        record.view.state = if !effects_known || !within_budget {
            AgentStateV1::RecoveryRequired { epoch }
        } else if matches!(record.view.state, AgentStateV1::Closing { .. }) {
            AgentStateV1::Closed
        } else {
            AgentStateV1::Idle
        };
        let active_task = record.active_task;
        if !matches!(record.view.state, AgentStateV1::RecoveryRequired { .. }) {
            record.active_task = None;
            record.runtime_started_at_unix_ms = None;
        }
        // Unconsumed inputs at a settled epoch have an explicit rejected outcome. They are not
        // mislabeled as consumed and are never delivered into a later turn.
        workflow_claim::record_completion(
            &mut next,
            id,
            epoch,
            summary,
            usage,
            effects_known && within_budget,
        );
        next.mailbox.settle_epoch(id, epoch, active_task);
        next.revision = next_revision(next.revision)?;
        self.commit(next)
    }

    /// Host supplies reconciliation evidence before restoring an interrupted incarnation.
    /// Previous active turns and delivered inputs remain terminal and cannot be replayed.
    pub fn reconcile_stopped(
        &mut self,
        id: AgentIdV1,
        epoch: AgentEpochV1,
        effects_known: bool,
        close: bool,
    ) -> Result<(), ControllerError> {
        if self
            .snapshot
            .agents
            .get(&id)
            .is_some_and(|record| record.runtime_started_at_unix_ms.is_some())
        {
            return Err(ControllerError::RecoveryRequired);
        }
        self.reconcile_stopped_with_usage(id, epoch, effects_known, close, AgentUsageV1::default())
    }

    /// Recovered usage is additional unsettled usage beyond the already persisted counters.
    /// The authenticated host must derive it from the physical journal/effect receipts. A control
    /// client or model cannot invoke this port by asserting an effects_known JSON field.
    pub fn reconcile_stopped_with_usage(
        &mut self,
        id: AgentIdV1,
        epoch: AgentEpochV1,
        effects_known: bool,
        close: bool,
        recovered_usage: AgentUsageV1,
    ) -> Result<(), ControllerError> {
        self.check_live()?;
        if !effects_known {
            return Err(ControllerError::RecoveryRequired);
        }
        let current = self
            .snapshot
            .agents
            .get(&id)
            .ok_or(ControllerError::UnknownAgent)?;
        if current.view.state != (AgentStateV1::RecoveryRequired { epoch }) {
            return Err(ControllerError::StaleEpoch);
        }
        if recovered_usage.turns != 0
            || (current.runtime_started_at_unix_ms.is_some() && recovered_usage.wall_ms == 0)
        {
            return Err(ControllerError::Invalid(
                "recovery needs measured elapsed usage without double-counting its turn",
            ));
        }
        let mut next = self.snapshot.clone();
        let record = next
            .agents
            .get_mut(&id)
            .ok_or(ControllerError::UnknownAgent)?;
        record.tokens_used = record
            .tokens_used
            .checked_add(recovered_usage.tokens)
            .ok_or(ControllerError::Budget)?;
        record.cost_used = record
            .cost_used
            .checked_add(recovered_usage.cost_microusd)
            .ok_or(ControllerError::Budget)?;
        record.wall_used_ms = record
            .wall_used_ms
            .checked_add(recovered_usage.wall_ms)
            .ok_or(ControllerError::Budget)?;
        if !close
            && (record
                .tokens_used
                .checked_add(record.reserved_tokens)
                .is_none_or(|used| used > record.view.budget.tokens)
                || record
                    .cost_used
                    .checked_add(record.reserved_cost)
                    .is_none_or(|used| used > record.view.budget.cost_microusd)
                || record.wall_used_ms > record.view.budget.wall_ms)
        {
            return Err(ControllerError::Budget);
        }
        record.view.incarnation = record
            .view
            .incarnation
            .checked_add(1)
            .ok_or(ControllerError::Capacity)?;
        let active_task = record.active_task.take();
        record.runtime_started_at_unix_ms = None;
        record.view.state = if close {
            AgentStateV1::Closed
        } else {
            AgentStateV1::Idle
        };
        workflow_claim::recover_completion(&mut next, id, epoch, recovered_usage)?;
        next.mailbox.reconcile(id, active_task, close);
        next.revision = next_revision(next.revision)?;
        self.commit(next)
    }

    fn commit(&mut self, next: AgentControllerSnapshot) -> Result<(), ControllerError> {
        validate_snapshot(&next)?;
        if serde_json::to_vec(&next)
            .map_err(|_| ControllerError::Invalid("snapshot serialization failed"))?
            .len()
            > MAX_SNAPSHOT_BYTES
        {
            return Err(ControllerError::Capacity);
        }
        match self.journal.commit(Some(self.snapshot.revision), &next) {
            Ok(()) => {
                self.snapshot = next;
                Ok(())
            }
            Err(error) => {
                if matches!(
                    error,
                    ControllerStoreError::OutcomeUnknown | ControllerStoreError::Conflict
                ) {
                    self.poisoned = true;
                }
                Err(ControllerError::Store(error))
            }
        }
    }

    fn check_live(&self) -> Result<(), ControllerError> {
        if self.poisoned {
            Err(ControllerError::Poisoned)
        } else {
            Ok(())
        }
    }
    fn check_actor(&self, actor: AgentActor) -> Result<(), ControllerError> {
        if let AgentActor::Agent(id) = actor {
            self.check_open(id)?;
        }
        Ok(())
    }
    fn check_open(&self, id: AgentIdV1) -> Result<(), ControllerError> {
        match self
            .snapshot
            .agents
            .get(&id)
            .ok_or(ControllerError::UnknownAgent)?
            .view
            .state
        {
            AgentStateV1::Closed | AgentStateV1::Closing { .. } => Err(ControllerError::Closed),
            AgentStateV1::RecoveryRequired { .. } => Err(ControllerError::RecoveryRequired),
            AgentStateV1::Idle
            | AgentStateV1::Running { .. }
            | AgentStateV1::Interrupting { .. } => Ok(()),
        }
    }
    fn check_running(&self, id: AgentIdV1, epoch: AgentEpochV1) -> Result<(), ControllerError> {
        let state = self
            .snapshot
            .agents
            .get(&id)
            .ok_or(ControllerError::UnknownAgent)?
            .view
            .state;
        if state != (AgentStateV1::Running { epoch }) {
            return Err(ControllerError::StaleEpoch);
        }
        Ok(())
    }
    fn check_control(&self, actor: AgentActor, target: AgentIdV1) -> Result<(), ControllerError> {
        if !self.snapshot.agents.contains_key(&target) {
            return Err(ControllerError::UnknownAgent);
        }
        match actor {
            AgentActor::Operator => Ok(()),
            AgentActor::Agent(sender) if sender != target && self.is_descendant(target, sender) => {
                Ok(())
            }
            _ => Err(ControllerError::Permission),
        }
    }
    fn can_message(&self, actor: AgentActor, target: AgentIdV1) -> bool {
        let Some(receiver) = self.snapshot.agents.get(&target) else {
            return false;
        };
        match actor {
            AgentActor::Operator => true,
            AgentActor::Agent(sender) => self.snapshot.agents.get(&sender).is_some_and(|source| {
                source.view.workspace_scope == receiver.view.workspace_scope
                    && (sender == target
                        || source.view.parent_id == Some(target)
                        || receiver.view.parent_id == Some(sender)
                        || (source.view.parent_id.is_some()
                            && source.view.parent_id == receiver.view.parent_id))
            }),
        }
    }
    fn is_descendant(&self, child: AgentIdV1, parent: AgentIdV1) -> bool {
        let mut current = child;
        for _ in 0..MAX_HIERARCHY_DEPTH {
            let Some(next) = self
                .snapshot
                .agents
                .get(&current)
                .and_then(|record| record.view.parent_id)
            else {
                return false;
            };
            if next == parent {
                return true;
            }
            current = next;
        }
        false
    }
    fn depth(&self, id: AgentIdV1) -> Result<usize, ControllerError> {
        let mut current = id;
        for depth in 0..=MAX_HIERARCHY_DEPTH {
            let record = self
                .snapshot
                .agents
                .get(&current)
                .ok_or(ControllerError::UnknownAgent)?;
            match record.view.parent_id {
                Some(parent) => current = parent,
                None => return Ok(depth),
            }
        }
        Err(ControllerError::Invalid(
            "agent hierarchy is cyclic or too deep",
        ))
    }
    fn project(&self, record: &AgentRecord) -> AgentViewV1 {
        let mut view = record.view.clone();
        view.queued_messages = self.snapshot.mailbox.pending_count(view.agent_id);
        view.usage = AgentUsageV1 {
            turns: record.turns_used,
            tokens: record.tokens_used,
            cost_microusd: record.cost_used,
            wall_ms: record.wall_used_ms,
        };
        view
    }
}

fn record(
    id: AgentIdV1,
    parent: Option<AgentIdV1>,
    label: String,
    config: &AgentControllerConfig,
    capabilities: CapabilitySet,
    budget: AgentBudgetV1,
    write_paths: Vec<String>,
) -> AgentRecord {
    AgentRecord {
        view: AgentViewV1 {
            agent_id: id,
            parent_id: parent,
            label,
            workspace_scope: config.workspace_scope.clone(),
            incarnation: 1,
            state: AgentStateV1::Idle,
            capabilities,
            budget,
            write_paths,
            queued_messages: 0,
            last_summary: None,
            usage: AgentUsageV1::default(),
        },
        next_turn: 1,
        active_task: None,
        turns_used: 0,
        tokens_used: 0,
        cost_used: 0,
        wall_used_ms: 0,
        runtime_started_at_unix_ms: None,
        reserved_turns: 0,
        reserved_tokens: 0,
        reserved_cost: 0,
    }
}

fn reserve(record: &mut AgentRecord, budget: AgentBudgetV1) -> Result<(), ControllerError> {
    let turns = record
        .reserved_turns
        .checked_add(budget.turns)
        .ok_or(ControllerError::Budget)?;
    let tokens = record
        .reserved_tokens
        .checked_add(budget.tokens)
        .ok_or(ControllerError::Budget)?;
    let cost = record
        .reserved_cost
        .checked_add(budget.cost_microusd)
        .ok_or(ControllerError::Budget)?;
    if turns
        .checked_add(record.turns_used)
        .is_none_or(|total| total > record.view.budget.turns)
        || tokens
            .checked_add(record.tokens_used)
            .is_none_or(|total| total > record.view.budget.tokens)
        || cost
            .checked_add(record.cost_used)
            .is_none_or(|total| total > record.view.budget.cost_microusd)
    {
        return Err(ControllerError::Budget);
    }
    record.reserved_turns = turns;
    record.reserved_tokens = tokens;
    record.reserved_cost = cost;
    Ok(())
}

fn enqueue(
    snapshot: &mut AgentControllerSnapshot,
    actor: AgentActor,
    receiver: AgentIdV1,
    text: String,
    kind: AgentMessageKindV1,
    expected_epoch: Option<AgentEpochV1>,
) -> Result<AgentMessageIdV1, ControllerError> {
    let sender = match actor {
        AgentActor::Operator => None,
        AgentActor::Agent(id) => Some(id),
    };
    snapshot
        .mailbox
        .enqueue(sender, receiver, text, kind, expected_epoch)
}

fn next_revision(revision: u64) -> Result<u64, ControllerError> {
    revision
        .checked_add(1)
        .filter(|next| *next <= MAX_REVISION)
        .ok_or(ControllerError::Capacity)
}
fn digest(value: &impl Serialize) -> Result<String, ControllerError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| ControllerError::Invalid("request serialization failed"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
fn path_within(path: &str, parent: &str) -> bool {
    let path = path.replace('\\', "/");
    let parent = parent.replace('\\', "/");
    path == parent
        || path
            .strip_prefix(&parent)
            .is_some_and(|tail| tail.starts_with('/'))
}
