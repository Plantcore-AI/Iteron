//! Bounded mailbox state owner. Only typed transitions can change delivery acknowledgements.

use crate::controller_error::ControllerError;
use iteron_protocol::agent_control::{
    AgentEpochV1, AgentIdV1, AgentMessageIdV1, AgentMessageKindV1, AgentMessageStateV1,
    MAX_AGENT_TEXT_BYTES, validate_epoch, validate_text,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const MAX_MESSAGES: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentMailboxMessage {
    pub id: AgentMessageIdV1,
    pub sender: Option<AgentIdV1>,
    pub receiver: AgentIdV1,
    pub sequence: u64,
    pub kind: AgentMessageKindV1,
    pub state: AgentMessageStateV1,
    pub text: Option<String>,
    pub content_sha256: String,
    pub expected_epoch: Option<AgentEpochV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentMailbox {
    next_message: u64,
    max_pending: usize,
    messages: BTreeMap<AgentMessageIdV1, AgentMailboxMessage>,
}

impl AgentMailbox {
    pub(crate) fn new(max_pending: usize) -> Self {
        Self {
            next_message: 1,
            max_pending,
            messages: BTreeMap::new(),
        }
    }

    pub(crate) fn message(&self, id: AgentMessageIdV1) -> Option<&AgentMailboxMessage> {
        self.messages.get(&id)
    }

    pub(crate) fn pending_count(&self, id: AgentIdV1) -> usize {
        self.messages
            .values()
            .filter(|message| {
                message.receiver == id
                    && matches!(
                        message.state,
                        AgentMessageStateV1::Accepted | AgentMessageStateV1::Delivered { .. }
                    )
            })
            .count()
    }

    pub(crate) fn pending_task(&self, id: AgentIdV1) -> Option<AgentMessageIdV1> {
        self.messages
            .values()
            .find(|message| {
                message.receiver == id
                    && message.kind == AgentMessageKindV1::Task
                    && message.state == AgentMessageStateV1::Accepted
            })
            .map(|message| message.id)
    }

    pub(crate) fn enqueue(
        &mut self,
        sender: Option<AgentIdV1>,
        receiver: AgentIdV1,
        text: String,
        kind: AgentMessageKindV1,
        expected_epoch: Option<AgentEpochV1>,
    ) -> Result<AgentMessageIdV1, ControllerError> {
        validate_text(&text).map_err(ControllerError::Invalid)?;
        if self.messages.len() >= MAX_MESSAGES || self.pending_count(receiver) >= self.max_pending {
            return Err(ControllerError::Capacity);
        }
        let id = AgentMessageIdV1(self.next_message);
        self.next_message = self
            .next_message
            .checked_add(1)
            .ok_or(ControllerError::Capacity)?;
        self.messages.insert(
            id,
            AgentMailboxMessage {
                id,
                sender,
                receiver,
                sequence: id.0,
                kind,
                state: AgentMessageStateV1::Accepted,
                content_sha256: format!("{:x}", Sha256::digest(text.as_bytes())),
                text: Some(text),
                expected_epoch,
            },
        );
        Ok(id)
    }

    pub(crate) fn deliver(
        &mut self,
        receiver: AgentIdV1,
        epoch: AgentEpochV1,
        active_task: Option<AgentMessageIdV1>,
        starting: bool,
    ) -> Vec<AgentMailboxMessage> {
        let mut delivered = Vec::new();
        for message in self.messages.values_mut().filter(|message| {
            message.receiver == receiver && message.state == AgentMessageStateV1::Accepted
        }) {
            if message
                .expected_epoch
                .is_some_and(|expected| expected != epoch)
            {
                reject(message);
                continue;
            }
            if message.kind == AgentMessageKindV1::Task
                && (!starting || active_task != Some(message.id))
            {
                continue;
            }
            message.state = AgentMessageStateV1::Delivered { epoch };
            delivered.push(message.clone());
        }
        delivered
    }

    pub(crate) fn mark_consumed(
        &mut self,
        receiver: AgentIdV1,
        epoch: AgentEpochV1,
        ids: &[AgentMessageIdV1],
    ) -> Result<(), ControllerError> {
        if ids.len() > self.max_pending {
            return Err(ControllerError::Capacity);
        }
        // Validate the complete batch before mutation, so the standalone mailbox port is atomic
        // even without the controller's clone-and-commit transaction.
        for id in ids {
            let message = self
                .messages
                .get(id)
                .ok_or(ControllerError::UnknownMessage)?;
            if message.receiver != receiver
                || !matches!(message.state,
                AgentMessageStateV1::Delivered { epoch: delivered } | AgentMessageStateV1::Consumed { epoch: delivered } if delivered == epoch)
            {
                return Err(ControllerError::StaleEpoch);
            }
        }
        for id in ids {
            let message = self
                .messages
                .get_mut(id)
                .ok_or(ControllerError::UnknownMessage)?;
            message.state = AgentMessageStateV1::Consumed { epoch };
            message.text = None;
        }
        Ok(())
    }

    pub(crate) fn reject_accepted(&mut self, receiver: AgentIdV1) {
        for message in self.messages.values_mut().filter(|message| {
            message.receiver == receiver && message.state == AgentMessageStateV1::Accepted
        }) {
            reject(message);
        }
    }

    pub(crate) fn settle_epoch(
        &mut self,
        receiver: AgentIdV1,
        epoch: AgentEpochV1,
        active_task: Option<AgentMessageIdV1>,
    ) {
        for message in self
            .messages
            .values_mut()
            .filter(|message| message.receiver == receiver)
        {
            if matches!(message.state, AgentMessageStateV1::Delivered { epoch: delivered } if delivered == epoch)
                || (message.state == AgentMessageStateV1::Accepted
                    && (message.expected_epoch == Some(epoch) || active_task == Some(message.id)))
            {
                reject(message);
            }
        }
    }

    pub(crate) fn reconcile(
        &mut self,
        receiver: AgentIdV1,
        active_task: Option<AgentMessageIdV1>,
        close: bool,
    ) {
        for message in self
            .messages
            .values_mut()
            .filter(|message| message.receiver == receiver)
        {
            if matches!(message.state, AgentMessageStateV1::Delivered { .. })
                || (message.state == AgentMessageStateV1::Accepted
                    && (message.expected_epoch.is_some()
                        || active_task == Some(message.id)
                        || close))
            {
                reject(message);
            }
        }
    }

    pub(crate) fn validate(
        &self,
        agent_ids: &BTreeSet<AgentIdV1>,
        expected_pending: usize,
    ) -> Result<(), ControllerError> {
        if self.messages.len() > MAX_MESSAGES
            || self.max_pending != expected_pending
            || self.next_message <= self.messages.keys().map(|id| id.0).max().unwrap_or(0)
        {
            return Err(ControllerError::Invalid("invalid durable mailbox envelope"));
        }
        for (id, message) in &self.messages {
            if id.0 == 0
                || *id != message.id
                || message.sequence != id.0
                || !agent_ids.contains(&message.receiver)
                || message
                    .sender
                    .is_some_and(|sender| !agent_ids.contains(&sender))
                || message.content_sha256.len() != 64
                || !message
                    .content_sha256
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                || message.text.as_ref().is_some_and(|text| {
                    text.len() > MAX_AGENT_TEXT_BYTES || validate_text(text).is_err()
                })
                || (message.kind == AgentMessageKindV1::Steer) != message.expected_epoch.is_some()
                || message
                    .expected_epoch
                    .is_some_and(|epoch| validate_epoch(epoch).is_err())
                || matches!(message.state, AgentMessageStateV1::Delivered { epoch } | AgentMessageStateV1::Consumed { epoch }
                    if validate_epoch(epoch).is_err() || message.expected_epoch.is_some_and(|expected| expected != epoch))
                || (matches!(
                    message.state,
                    AgentMessageStateV1::Consumed { .. } | AgentMessageStateV1::Rejected
                ) && message.text.is_some())
            {
                return Err(ControllerError::Invalid("invalid durable mailbox message"));
            }
            if let Some(text) = &message.text {
                if format!("{:x}", Sha256::digest(text.as_bytes())) != message.content_sha256 {
                    return Err(ControllerError::Invalid(
                        "durable mailbox content digest mismatch",
                    ));
                }
            } else if matches!(
                message.state,
                AgentMessageStateV1::Accepted | AgentMessageStateV1::Delivered { .. }
            ) {
                return Err(ControllerError::Invalid(
                    "pending durable mailbox payload is missing",
                ));
            }
        }
        if agent_ids
            .iter()
            .any(|id| self.pending_count(*id) > self.max_pending)
        {
            return Err(ControllerError::Capacity);
        }
        Ok(())
    }
}

fn reject(message: &mut AgentMailboxMessage) {
    message.state = AgentMessageStateV1::Rejected;
    message.text = None;
}
