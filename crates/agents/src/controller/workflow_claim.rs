//! Host-only atomic workflow attribution. The scheduler supplies intent; this owner alone
//! admits an exact idle agent, mailbox task and runtime epoch in one durable transition.
use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentWorkflowClaim {
    pub workflow_id: String,
    pub node_id: u64,
    pub attempt: u64,
    pub input_digest: String,
    pub assigned_agent: AgentIdV1,
    pub task: String,
    pub budget: AgentBudgetV1,
    pub deadline_unix_ms: u64,
}
impl AgentWorkflowClaim {
    fn validate(&self) -> Result<(), ControllerError> {
        if self.workflow_id.is_empty()
            || self.workflow_id.len() > 128
            || self.workflow_id.chars().any(char::is_control)
            || self.node_id == 0
            || self.attempt == 0
            || self.assigned_agent.0 == 0
            || self.input_digest.len() != 64
            || !self
                .input_digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ControllerError::Invalid("invalid workflow attribution"));
        }
        iteron_protocol::agent_control::validate_text(&self.task)
            .map_err(ControllerError::Invalid)?;
        self.budget.validate().map_err(ControllerError::Invalid)
    }
    fn key(&self) -> Result<String, ControllerError> {
        digest(&(&self.workflow_id, self.node_id, self.attempt))
    }
}
#[derive(Debug, Clone)]
pub struct AgentWorkflowLease {
    pub agent: AgentViewV1,
    pub epoch: AgentEpochV1,
    pub initial: Vec<AgentMailboxMessage>,
    pub replayed: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentWorkflowTerminal {
    Succeeded,
    Failed,
    Cancelled,
    StoppedRecovery,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentWorkflowCompletion {
    pub agent_id: AgentIdV1,
    pub epoch: AgentEpochV1,
    pub summary: String,
    pub usage: AgentUsageV1,
    pub effects_known: bool,
    pub terminal: AgentWorkflowTerminal,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkflowReceipt {
    claim: AgentWorkflowClaim,
    epoch: AgentEpochV1,
    message: AgentMessageIdV1,
    completion: Option<AgentWorkflowCompletion>,
}
impl<J: AgentControllerJournal> AgentController<J> {
    pub fn claim_workflow_task(
        &mut self,
        claim: AgentWorkflowClaim,
        now_unix_ms: u64,
    ) -> Result<AgentWorkflowLease, ControllerError> {
        self.check_live()?;
        claim.validate()?;
        let key = claim.key()?;
        if let Some(lease) = self.existing_workflow_lease(&claim)? {
            return Ok(lease);
        }
        if now_unix_ms == 0 || claim.deadline_unix_ms <= now_unix_ms {
            return Err(ControllerError::Budget);
        }
        if self.snapshot.workflow_claims.len() >= MAX_RECEIPTS {
            return Err(ControllerError::Capacity);
        }
        self.check_open(claim.assigned_agent)?;
        let current = self
            .snapshot
            .agents
            .get(&claim.assigned_agent)
            .ok_or(ControllerError::UnknownAgent)?;
        if current.view.state != AgentStateV1::Idle
            || self.snapshot.mailbox.pending_count(claim.assigned_agent) > 0
        {
            return Err(ControllerError::Invalid(
                "workflow agent is busy or has pending inputs",
            ));
        }
        let remaining = AgentBudgetV1 {
            turns: current
                .view
                .budget
                .turns
                .saturating_sub(current.turns_used)
                .saturating_sub(current.reserved_turns),
            tokens: current
                .view
                .budget
                .tokens
                .saturating_sub(current.tokens_used)
                .saturating_sub(current.reserved_tokens),
            cost_microusd: current
                .view
                .budget
                .cost_microusd
                .saturating_sub(current.cost_used)
                .saturating_sub(current.reserved_cost),
            wall_ms: current
                .view
                .budget
                .wall_ms
                .saturating_sub(current.wall_used_ms)
                .min(claim.deadline_unix_ms - now_unix_ms),
        };
        if !claim.budget.fits_within(remaining) {
            return Err(ControllerError::Budget);
        }
        let mut next = self.snapshot.clone();
        let message = next.mailbox.enqueue(
            None,
            claim.assigned_agent,
            claim.task.clone(),
            AgentMessageKindV1::Task,
            None,
        )?;
        let record = next
            .agents
            .get_mut(&claim.assigned_agent)
            .ok_or(ControllerError::UnknownAgent)?;
        let epoch = AgentEpochV1 {
            incarnation: record.view.incarnation,
            turn: record.next_turn,
        };
        record.next_turn = record
            .next_turn
            .checked_add(1)
            .ok_or(ControllerError::Capacity)?;
        record.turns_used = record
            .turns_used
            .checked_add(1)
            .ok_or(ControllerError::Budget)?;
        record.active_task = Some(message);
        record.runtime_started_at_unix_ms = Some(now_unix_ms);
        record.view.state = AgentStateV1::Running { epoch };
        let initial = next
            .mailbox
            .deliver(claim.assigned_agent, epoch, Some(message), true);
        next.workflow_claims.insert(
            key,
            WorkflowReceipt {
                claim: claim.clone(),
                epoch,
                message,
                completion: None,
            },
        );
        next.revision = next_revision(next.revision)?;
        self.commit(next)?;
        let mut agent = self.inspect(AgentActor::Operator, claim.assigned_agent)?;
        // The runtime sees a tighter absolute ceiling for this execution; durable identity retains
        // its lifetime ceiling and the claim retains the independently bounded node envelope.
        agent.reserved = AgentUsageV1::default();
        agent.budget.turns = agent
            .usage
            .turns
            .saturating_sub(1)
            .saturating_add(claim.budget.turns);
        agent.budget.tokens = agent.usage.tokens.saturating_add(claim.budget.tokens);
        agent.budget.cost_microusd = agent
            .usage
            .cost_microusd
            .saturating_add(claim.budget.cost_microusd);
        agent.budget.wall_ms = agent.usage.wall_ms.saturating_add(claim.budget.wall_ms);
        Ok(AgentWorkflowLease {
            agent,
            epoch,
            initial,
            replayed: false,
        })
    }
    pub fn existing_workflow_lease(
        &self,
        claim: &AgentWorkflowClaim,
    ) -> Result<Option<AgentWorkflowLease>, ControllerError> {
        self.check_live()?;
        claim.validate()?;
        let key = claim.key()?;
        if let Some(receipt) = self.snapshot.workflow_claims.get(&key) {
            if receipt.claim != *claim {
                return Err(ControllerError::RequestConflict);
            }
            if receipt.completion.is_some() {
                return Err(ControllerError::RecoveryRequired);
            }
            let agent = self.inspect(AgentActor::Operator, claim.assigned_agent)?;
            if agent.state
                != (AgentStateV1::Running {
                    epoch: receipt.epoch,
                })
            {
                return Err(ControllerError::RecoveryRequired);
            }
            return Ok(Some(AgentWorkflowLease {
                agent,
                epoch: receipt.epoch,
                initial: Vec::new(),
                replayed: true,
            }));
        }
        Ok(None)
    }
    pub fn workflow_completion(
        &self,
        claim: &AgentWorkflowClaim,
    ) -> Result<Option<AgentWorkflowCompletion>, ControllerError> {
        self.check_live()?;
        let receipt = self
            .snapshot
            .workflow_claims
            .get(&claim.key()?)
            .ok_or(ControllerError::UnknownMessage)?;
        if receipt.claim != *claim {
            return Err(ControllerError::RequestConflict);
        }
        Ok(receipt.completion.clone())
    }
    /// A clock anchor is recovery evidence, never authority to resume unknown effects.
    pub fn recovery_anchor(
        &self,
        id: AgentIdV1,
        epoch: AgentEpochV1,
    ) -> Result<Option<u64>, ControllerError> {
        self.check_live()?;
        let record = self
            .snapshot
            .agents
            .get(&id)
            .ok_or(ControllerError::UnknownAgent)?;
        if record.view.state != (AgentStateV1::RecoveryRequired { epoch }) {
            return Err(ControllerError::StaleEpoch);
        }
        Ok(record.runtime_started_at_unix_ms)
    }
}
pub(super) fn settlement_fits(
    snapshot: &AgentControllerSnapshot,
    id: AgentIdV1,
    epoch: AgentEpochV1,
    usage: AgentUsageV1,
) -> bool {
    snapshot
        .workflow_claims
        .values()
        .filter(|receipt| receipt.claim.assigned_agent == id && receipt.epoch == epoch)
        .all(|receipt| {
            usage.turns <= receipt.claim.budget.turns
                && usage.tokens <= receipt.claim.budget.tokens
                && usage.cost_microusd <= receipt.claim.budget.cost_microusd
                && usage.wall_ms <= receipt.claim.budget.wall_ms
        })
}
pub(super) fn record_completion(
    snapshot: &mut AgentControllerSnapshot,
    id: AgentIdV1,
    epoch: AgentEpochV1,
    summary: &str,
    usage: AgentUsageV1,
    effects_known: bool,
    terminal: AgentWorkflowTerminal,
) {
    for receipt in snapshot
        .workflow_claims
        .values_mut()
        .filter(|receipt| receipt.claim.assigned_agent == id && receipt.epoch == epoch)
    {
        receipt.completion = Some(AgentWorkflowCompletion {
            agent_id: id,
            epoch,
            summary: summary.into(),
            usage: AgentUsageV1 {
                turns: usage.turns.max(1),
                ..usage
            },
            effects_known,
            terminal,
        });
    }
}
pub(super) fn recover_completion(
    snapshot: &mut AgentControllerSnapshot,
    id: AgentIdV1,
    epoch: AgentEpochV1,
    additional: AgentUsageV1,
) -> Result<(), ControllerError> {
    for receipt in snapshot
        .workflow_claims
        .values_mut()
        .filter(|receipt| receipt.claim.assigned_agent == id && receipt.epoch == epoch)
    {
        let completion = receipt.completion.get_or_insert(AgentWorkflowCompletion {
            agent_id: id,
            epoch,
            summary: "Runtime effects reconciled after restart".into(),
            usage: AgentUsageV1 {
                turns: 1,
                ..AgentUsageV1::default()
            },
            effects_known: false,
            terminal: AgentWorkflowTerminal::StoppedRecovery,
        });
        completion.usage.turns = completion
            .usage
            .turns
            .checked_add(additional.turns)
            .ok_or(ControllerError::Budget)?;
        completion.usage.tokens = completion
            .usage
            .tokens
            .checked_add(additional.tokens)
            .ok_or(ControllerError::Budget)?;
        completion.usage.cost_microusd = completion
            .usage
            .cost_microusd
            .checked_add(additional.cost_microusd)
            .ok_or(ControllerError::Budget)?;
        completion.usage.wall_ms = completion
            .usage
            .wall_ms
            .checked_add(additional.wall_ms)
            .ok_or(ControllerError::Budget)?;
        completion.effects_known = true;
        completion.terminal = AgentWorkflowTerminal::StoppedRecovery;
    }
    Ok(())
}
pub(super) fn validate_claims(snapshot: &AgentControllerSnapshot) -> Result<(), ControllerError> {
    if snapshot.workflow_claims.len() > MAX_RECEIPTS {
        return Err(ControllerError::Capacity);
    }
    for (key, receipt) in &snapshot.workflow_claims {
        receipt.claim.validate()?;
        let record = snapshot
            .agents
            .get(&receipt.claim.assigned_agent)
            .ok_or(ControllerError::UnknownAgent)?;
        let message = snapshot
            .mailbox
            .message(receipt.message)
            .ok_or(ControllerError::UnknownMessage)?;
        if key != &receipt.claim.key()?
            || !receipt.claim.budget.fits_within(record.view.budget)
            || receipt.epoch.turn == 0
            || receipt.epoch.turn >= record.next_turn
            || receipt.epoch.incarnation == 0
            || receipt.epoch.incarnation > record.view.incarnation
            || receipt.claim.deadline_unix_ms == 0
            || message.receiver != record.view.agent_id
            || message.kind != AgentMessageKindV1::Task
            || message.content_sha256
                != format!("{:x}", Sha256::digest(receipt.claim.task.as_bytes()))
        {
            return Err(ControllerError::Invalid("invalid durable workflow claim"));
        }
        if let Some(completion) = &receipt.completion {
            if completion.agent_id != record.view.agent_id
                || completion.epoch != receipt.epoch
                || completion.summary.len() > MAX_AGENT_TEXT_BYTES
                || completion.summary.contains('\0')
                || completion.usage.turns == 0
            {
                return Err(ControllerError::Invalid(
                    "invalid durable workflow completion",
                ));
            }
        } else if record.view.state.epoch() != Some(receipt.epoch) {
            return Err(ControllerError::Invalid(
                "unsettled workflow lost its runtime epoch",
            ));
        }
    }
    Ok(())
}
