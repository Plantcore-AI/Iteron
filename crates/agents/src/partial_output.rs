//! Bounded, ephemeral resident output. Durable controller state is the authority for the epoch;
//! this owner retains only served model text and does not persist or reconstruct lost streams.
use crate::ControllerError;
use iteron_protocol::agent_control::{
    AgentEpochV1, AgentIdV1, AgentMessageIdV1, AgentStateV1, AgentViewV1, MAX_AGENT_TEXT_BYTES,
    MAX_AGENT_WRITE_PATH_BYTES,
};
use iteron_protocol::agent_output::{
    AgentOutputSourceV1, AgentPartialOutputV1, AgentPartialStateV1,
};
use std::collections::BTreeMap;

pub struct AgentPartialOutputOwner {
    capacity: usize,
    sequence: u64,
    outputs: BTreeMap<AgentIdV1, AgentPartialOutputV1>,
}
impl AgentPartialOutputOwner {
    /// Capacity is the already-admitted controller inventory bound; no independent agents exist.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.min(64),
            sequence: 0,
            outputs: BTreeMap::new(),
        }
    }

    /// The host supplies its inspected durable view and the actual task delivery receipt.
    /// Text must already have passed the host's streaming redactor. It remains untrusted data.
    pub fn append(
        &mut self,
        view: &AgentViewV1,
        epoch: AgentEpochV1,
        task: AgentMessageIdV1,
        source: &AgentOutputSourceV1,
        served_delta: &str,
    ) -> Result<bool, ControllerError> {
        if view.state.epoch() != Some(epoch)
            || view.incarnation != epoch.incarnation
            || !matches!(
                view.state,
                AgentStateV1::Running { .. }
                    | AgentStateV1::Interrupting { .. }
                    | AgentStateV1::Closing { .. }
            )
        {
            return Err(ControllerError::StaleEpoch);
        }
        if task.0 == 0
            || source.provider_intent_seq == 0
            || [&source.tenant.0, &source.run_id.0, &source.effect_id.0]
                .into_iter()
                .any(|id| {
                    id.is_empty()
                        || id.len() > MAX_AGENT_WRITE_PATH_BYTES
                        || id.chars().any(char::is_control)
                })
            || served_delta.contains('\0')
        {
            return Err(ControllerError::Invalid("invalid partial output source"));
        }
        if served_delta.is_empty() {
            return Ok(false);
        }
        if !self.outputs.contains_key(&view.agent_id) && self.outputs.len() >= self.capacity {
            return Err(ControllerError::Capacity);
        }
        let prior = self.outputs.get(&view.agent_id);
        let same_epoch = prior.filter(|prior| prior.epoch == epoch);
        if let Some(prior) = same_epoch {
            if prior.task_message_id != Some(task) {
                return Err(ControllerError::StaleEpoch);
            }
            if let Some(old) = &prior.source
                && (old.tenant != source.tenant
                    || old.run_id != source.run_id
                    || source.provider_intent_seq < old.provider_intent_seq
                    || (source.provider_intent_seq == old.provider_intent_seq && old != source))
            {
                return Err(ControllerError::StaleEpoch);
            }
        }
        // A new physical attempt owns a fresh prefix. Retried output is not concatenated into a
        // fictitious successful response. Earlier observations are replaced with a new source.
        let previous = same_epoch.filter(|prior| prior.source.as_ref() == Some(source));
        if previous.is_some_and(|prior| prior.truncated) {
            return Ok(false);
        }
        let old = previous
            .and_then(|prior| prior.text.as_deref())
            .unwrap_or("");
        let room = MAX_AGENT_TEXT_BYTES.saturating_sub(old.len());
        let mut retained = served_delta.len().min(room);
        while !served_delta.is_char_boundary(retained) {
            retained -= 1;
        }
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(ControllerError::Capacity)?;
        let mut text = String::with_capacity(old.len() + retained);
        text.push_str(old);
        text.push_str(&served_delta[..retained]);
        self.outputs.insert(
            view.agent_id,
            AgentPartialOutputV1 {
                agent_id: view.agent_id,
                epoch,
                task_message_id: Some(task),
                observation_sequence: sequence,
                state: AgentPartialStateV1::Observed,
                source: Some(source.clone()),
                text: Some(text),
                truncated: retained != served_delta.len(),
                trust: iteron_protocol::Trust::Untrusted,
            },
        );
        self.sequence = sequence;
        Ok(true)
    }

    /// A restored unknown epoch never serves ephemeral text as confirmed output. No disk path,
    /// activity counter, or terminal summary is used to reconstruct the stream.
    pub fn decorate(&self, view: &mut AgentViewV1) {
        view.partial_output = match view.state {
            AgentStateV1::RecoveryRequired { epoch } => Some(AgentPartialOutputV1 {
                agent_id: view.agent_id,
                epoch,
                task_message_id: None,
                observation_sequence: self.sequence,
                state: AgentPartialStateV1::Unknown,
                source: None,
                text: None,
                truncated: false,
                trust: iteron_protocol::Trust::Untrusted,
            }),
            state => self
                .outputs
                .get(&view.agent_id)
                .filter(|output| {
                    output.epoch.incarnation == view.incarnation
                        && state.epoch().is_none_or(|epoch| epoch == output.epoch)
                })
                .cloned(),
        };
    }
}

#[cfg(test)]
mod tests;
