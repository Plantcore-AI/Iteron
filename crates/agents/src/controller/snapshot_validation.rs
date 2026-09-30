//! Read-only validation of durable controller snapshots before authority becomes live.

use super::{
    AgentControllerSnapshot, ControllerError, MAX_HIERARCHY_DEPTH, MAX_RECEIPTS, MAX_REVISION,
    path_within,
};
use iteron_protocol::Capability;
use iteron_protocol::agent_control::{
    AGENT_CONTROL_VERSION, AgentIdV1, AgentMessageKindV1, AgentStateV1, MAX_AGENT_TEXT_BYTES,
    validate_label, validate_write_paths,
};

pub(super) fn validate_snapshot(snapshot: &AgentControllerSnapshot) -> Result<(), ControllerError> {
    snapshot.config.validate()?;
    if let Some(witness) = &snapshot.workspace_witness {
        witness.validate()?;
        if !snapshot
            .config
            .root_capabilities
            .contains(Capability::ReversibleLocal)
        {
            return Err(ControllerError::Invalid(
                "writer witness lacks inherited write authority",
            ));
        }
    }
    if snapshot.version != AGENT_CONTROL_VERSION
        || snapshot.revision > MAX_REVISION
        || snapshot.agents.len() > snapshot.config.max_agents
        || snapshot.receipts.len() > MAX_RECEIPTS
        || !snapshot.agents.contains_key(&AgentIdV1(1))
        || snapshot.next_agent <= snapshot.agents.keys().map(|id| id.0).max().unwrap_or(0)
    {
        return Err(ControllerError::Invalid(
            "invalid controller snapshot envelope",
        ));
    }
    for (id, record) in &snapshot.agents {
        if id.0 == 0
            || *id != record.view.agent_id
            || record.view.incarnation == 0
            || record.next_turn == 0
            || record.next_turn > u64::from(record.turns_used) + 1
            || !record.view.capabilities.contains(Capability::ReadOnly)
            || record.view.queued_messages != 0
            || record.view.usage != iteron_protocol::agent_control::AgentUsageV1::default()
            || record.view.reserved != iteron_protocol::agent_control::AgentUsageV1::default()
            || record.view.workspace_scope != snapshot.config.workspace_scope
            || !record
                .view
                .capabilities
                .is_subset_of(snapshot.config.root_capabilities)
            || !record.view.budget.fits_within(snapshot.config.root_budget)
            || record
                .view
                .last_summary
                .as_ref()
                .is_some_and(|text| text.len() > MAX_AGENT_TEXT_BYTES || text.contains('\0'))
        {
            return Err(ControllerError::Invalid(
                "invalid durable agent identity or authority",
            ));
        }
        record
            .view
            .budget
            .validate()
            .map_err(ControllerError::Invalid)?;
        validate_label(&record.view.label).map_err(ControllerError::Invalid)?;
        validate_write_paths(&record.view.write_paths).map_err(ControllerError::Invalid)?;
        if !record.view.write_paths.is_empty()
            && !record
                .view
                .capabilities
                .contains(Capability::ReversibleLocal)
        {
            return Err(ControllerError::Invalid(
                "durable writer has no write authority",
            ));
        }
        let reserved_fits = record.reserved_turns <= record.view.budget.turns
            && record.reserved_tokens <= record.view.budget.tokens
            && record.reserved_cost <= record.view.budget.cost_microusd;
        let usage_fits = record
            .turns_used
            .checked_add(record.reserved_turns)
            .is_some_and(|used| used <= record.view.budget.turns)
            && record
                .tokens_used
                .checked_add(record.reserved_tokens)
                .is_some_and(|used| used <= record.view.budget.tokens)
            && record
                .cost_used
                .checked_add(record.reserved_cost)
                .is_some_and(|used| used <= record.view.budget.cost_microusd)
            && record.wall_used_ms <= record.view.budget.wall_ms;
        if !reserved_fits
            || (!usage_fits
                && !matches!(
                    record.view.state,
                    AgentStateV1::RecoveryRequired { .. } | AgentStateV1::Closed
                ))
        {
            return Err(ControllerError::Invalid(
                "durable budget exceeds reservation envelope",
            ));
        }
        let children = snapshot
            .agents
            .values()
            .filter(|child| child.view.parent_id == Some(*id));
        let mut reservation = (0_u32, 0_u64, 0_u64);
        for child in children {
            reservation.0 = reservation
                .0
                .checked_add(child.view.budget.turns)
                .ok_or(ControllerError::Budget)?;
            reservation.1 = reservation
                .1
                .checked_add(child.view.budget.tokens)
                .ok_or(ControllerError::Budget)?;
            reservation.2 = reservation
                .2
                .checked_add(child.view.budget.cost_microusd)
                .ok_or(ControllerError::Budget)?;
        }
        if reservation
            != (
                record.reserved_turns,
                record.reserved_tokens,
                record.reserved_cost,
            )
        {
            return Err(ControllerError::Invalid(
                "durable budget reservations disagree with child ownership",
            ));
        }
        if (*id == AgentIdV1(1)) != record.view.parent_id.is_none() {
            return Err(ControllerError::Invalid("invalid durable root identity"));
        }
        if *id == AgentIdV1(1)
            && (record.view.capabilities != snapshot.config.root_capabilities
                || record.view.budget != snapshot.config.root_budget
                || !record.view.write_paths.is_empty())
        {
            return Err(ControllerError::Invalid(
                "durable root differs from genesis authority",
            ));
        }
        let mut ancestor = *id;
        let mut root_found = false;
        for _ in 0..=MAX_HIERARCHY_DEPTH {
            let current = snapshot
                .agents
                .get(&ancestor)
                .ok_or(ControllerError::Invalid("missing durable parent"))?;
            match current.view.parent_id {
                None => {
                    root_found = true;
                    break;
                }
                Some(parent) => {
                    let parent_record = snapshot
                        .agents
                        .get(&parent)
                        .ok_or(ControllerError::Invalid("missing durable parent"))?;
                    if !current
                        .view
                        .capabilities
                        .is_subset_of(parent_record.view.capabilities)
                        || !current.view.budget.fits_within(parent_record.view.budget)
                        || (parent != AgentIdV1(1)
                            && current.view.write_paths.iter().any(|path| {
                                !parent_record
                                    .view
                                    .write_paths
                                    .iter()
                                    .any(|allowed| path_within(path, allowed))
                            }))
                    {
                        return Err(ControllerError::Invalid(
                            "durable child exceeds parent authority",
                        ));
                    }
                    ancestor = parent;
                }
            }
        }
        if !root_found {
            return Err(ControllerError::Invalid(
                "cyclic or too deep durable hierarchy",
            ));
        }
        if let Some(epoch) = record.view.state.epoch() {
            if record.runtime_started_at_unix_ms == Some(0) {
                return Err(ControllerError::Invalid(
                    "invalid durable runtime clock anchor",
                ));
            }
            if epoch.incarnation != record.view.incarnation
                || epoch.turn == 0
                || epoch.turn >= record.next_turn
            {
                return Err(ControllerError::Invalid("invalid durable active epoch"));
            }
            let active_task = record
                .active_task
                .and_then(|id| snapshot.mailbox.message(id))
                .ok_or(ControllerError::Invalid("durable active task is missing"))?;
            if active_task.receiver != *id || active_task.kind != AgentMessageKindV1::Task {
                return Err(ControllerError::Invalid(
                    "durable active task has the wrong owner",
                ));
            }
        } else if record.active_task.is_some() || record.runtime_started_at_unix_ms.is_some() {
            return Err(ControllerError::Invalid(
                "idle agent retains an active task",
            ));
        }
    }
    super::workflow_claim::validate_claims(snapshot)?;
    snapshot.mailbox.validate(
        &snapshot.agents.keys().copied().collect(),
        snapshot.config.max_pending_per_agent,
    )?;
    for receipt in snapshot.receipts.values() {
        if !valid_digest(&receipt.digest)
            || receipt.reply.version != AGENT_CONTROL_VERSION
            || receipt.reply.revision == 0
            || receipt.reply.revision > snapshot.revision
            || receipt.reply.replayed
            || !snapshot.agents.contains_key(&receipt.reply.agent_id)
            || receipt.reply.message_id.is_some_and(|id| {
                snapshot
                    .mailbox
                    .message(id)
                    .is_none_or(|message| message.receiver != receipt.reply.agent_id)
            })
        {
            return Err(ControllerError::Invalid("invalid durable request receipt"));
        }
    }
    Ok(())
}

fn valid_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
