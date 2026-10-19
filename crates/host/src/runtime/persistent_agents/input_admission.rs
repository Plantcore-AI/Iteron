//! Sealed mailbox input crosses the host SQ queue without granting operator authority. Public
//! submission JSON has no activation field; each safe point validates the same live epoch owner.
use super::{
    AgentEpochV1, AgentMailboxMessage, AgentMessageIdV1, AgentMessageStateV1, ControllerError,
    LiveAgentMailbox,
};
use iteron_protocol::agent_input::{
    AgentInputAdmissionV1, AgentInputSourceV1, MAX_AGENT_INPUT_SOURCES,
};
use iteron_protocol::{EventKind, Trust};
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Clone)]
pub(in crate::runtime) struct AgentInputActivation {
    mailbox: LiveAgentMailbox,
    input_id: AgentMessageIdV1,
    epoch: AgentEpochV1,
    sender: Option<iteron_protocol::agent_control::AgentIdV1>,
    content_sha256: String,
    queued_sha256: String,
}
impl std::fmt::Debug for AgentInputActivation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentInputActivation")
            .field("input_id", &self.input_id)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}
pub(in crate::runtime) struct ResolvedAgentInput {
    pub(in crate::runtime) text: String,
    pub(in crate::runtime) admission: Option<AgentInputAdmissionV1>,
}
fn hash(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}
fn agent_steer_text(text: &str) -> String {
    format!("Agent steering data received while the run was active:\n{text}")
}
impl LiveAgentMailbox {
    pub(in crate::runtime) fn source_admission(
        &self,
        inputs: &[AgentMailboxMessage],
        projection: &str,
    ) -> Result<Option<AgentInputAdmissionV1>, ControllerError> {
        if inputs.len() > MAX_AGENT_INPUT_SOURCES {
            return Err(ControllerError::Capacity);
        }
        let mut sources = Vec::new();
        for input in inputs {
            if input.receiver != self.id
                || input != &self.port.message(input.id)?
                || input.state != (AgentMessageStateV1::Delivered { epoch: self.epoch })
            {
                return Err(ControllerError::StaleEpoch);
            }
            if let Some(sender) = input.sender {
                sources.push(AgentInputSourceV1 {
                    message_id: input.id,
                    sender,
                    content_sha256: input.content_sha256.clone(),
                });
            }
        }
        if sources.is_empty() {
            return Ok(None);
        }
        let witnesses = self
            .witnesses
            .lock()
            .map_err(|_| ControllerError::Poisoned)?;
        if !witnesses.has_projection(
            &inputs.iter().map(|input| input.id).collect::<Vec<_>>(),
            projection,
        ) {
            return Err(ControllerError::Invalid(
                "agent input projection was not host rendered",
            ));
        }
        let admission = AgentInputAdmissionV1 {
            version: 1,
            receiver: self.id,
            epoch: self.epoch,
            projection_sha256: hash(projection),
            sources,
        };
        admission.validate().map_err(ControllerError::Invalid)?;
        Ok(Some(admission))
    }
    /// The host calls this only after the matching WAL intent has completed its real barrier.
    /// Mere rendering/queueing does not admit low-trust data to a native request.
    pub(in crate::runtime) fn confirm_source_admission(
        &self,
        admission: &AgentInputAdmissionV1,
    ) -> Result<(), ControllerError> {
        admission.validate().map_err(ControllerError::Invalid)?;
        if admission.receiver != self.id || admission.epoch != self.epoch {
            return Err(ControllerError::StaleEpoch);
        }
        let ids = admission
            .sources
            .iter()
            .map(|source| {
                let durable = self.port.message(source.message_id)?;
                if durable.receiver != self.id
                    || durable.sender != Some(source.sender)
                    || durable.content_sha256 != source.content_sha256
                    || durable.state != (AgentMessageStateV1::Delivered { epoch: self.epoch })
                {
                    return Err(ControllerError::StaleEpoch);
                }
                Ok(source.message_id)
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.witnesses
            .lock()
            .map_err(|_| ControllerError::Poisoned)?
            .admit_source_projection(&ids, &admission.projection_sha256)
    }
    pub(in crate::runtime) fn steer_activation(
        &self,
        input: &AgentMailboxMessage,
    ) -> Result<(String, AgentInputActivation), ControllerError> {
        let text = self.render(input)?;
        self.witnesses
            .lock()
            .map_err(|_| ControllerError::Poisoned)?
            .register(&[input.id], &agent_steer_text(&text))?;
        Ok((
            text.clone(),
            AgentInputActivation {
                mailbox: self.clone(),
                input_id: input.id,
                epoch: self.epoch,
                sender: input.sender,
                content_sha256: input.content_sha256.clone(),
                queued_sha256: hash(&text),
            },
        ))
    }
}
impl AgentInputActivation {
    pub(in crate::runtime) fn resolve(
        &self,
        current: Option<&LiveAgentMailbox>,
        queued: &str,
    ) -> Result<ResolvedAgentInput, ControllerError> {
        let current = current.ok_or(ControllerError::StaleEpoch)?;
        if current.id != self.mailbox.id
            || current.epoch != self.epoch
            || !Arc::ptr_eq(&current.witnesses, &self.mailbox.witnesses)
            || hash(queued) != self.queued_sha256
        {
            return Err(ControllerError::StaleEpoch);
        }
        let durable = current.port.message(self.input_id)?;
        if durable.sender != self.sender || durable.content_sha256 != self.content_sha256 {
            return Err(ControllerError::Invalid(
                "agent input activation source changed",
            ));
        }
        let text = agent_steer_text(queued);
        let admission = current.source_admission(std::slice::from_ref(&durable), &text)?;
        Ok(ResolvedAgentInput { text, admission })
    }
}

/// A malformed/torn low-trust intent cannot regain trust on replay. The record writer and scoped
/// verified replay supply authority; text resembling an envelope never reaches this typed branch.
pub(in crate::runtime) fn replay_reference_trust(kind: &EventKind) -> Option<Trust> {
    matches!(kind, EventKind::AgentInputAdmittedV1 { .. }).then_some(Trust::Untrusted)
}

#[cfg(test)]
#[path = "input_admission_tests.rs"]
mod tests;
