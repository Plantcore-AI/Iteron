//! Host admission evidence for agent-authored data. This WAL intent lowers request trust and
//! preserves provenance; it is neither operator instruction authority nor a consumed receipt.
use crate::agent_control::{AgentEpochV1, AgentIdV1, AgentMessageIdV1};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MAX_AGENT_INPUT_SOURCES: usize = 128;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentInputSourceV1 {
    pub message_id: AgentMessageIdV1,
    pub sender: AgentIdV1,
    pub content_sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentInputAdmissionV1 {
    pub version: u32,
    pub receiver: AgentIdV1,
    pub epoch: AgentEpochV1,
    pub projection_sha256: String,
    pub sources: Vec<AgentInputSourceV1>,
}
impl AgentInputAdmissionV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        let hash = |text: &str| {
            text.len() == 64
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        };
        let mut ids = BTreeSet::new();
        if self.version != 1
            || self.receiver.0 == 0
            || self.epoch.incarnation == 0
            || self.epoch.turn == 0
            || !hash(&self.projection_sha256)
            || self.sources.is_empty()
            || self.sources.len() > MAX_AGENT_INPUT_SOURCES
            || self.sources.iter().any(|source| {
                source.message_id.0 == 0
                    || source.sender.0 == 0
                    || !hash(&source.content_sha256)
                    || !ids.insert(source.message_id)
            })
        {
            return Err("invalid agent input admission");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn admission() -> AgentInputAdmissionV1 {
        AgentInputAdmissionV1 {
            version: 1,
            receiver: AgentIdV1(2),
            epoch: AgentEpochV1 {
                incarnation: 1,
                turn: 1,
            },
            projection_sha256: "a".repeat(64),
            sources: vec![AgentInputSourceV1 {
                message_id: AgentMessageIdV1(7),
                sender: AgentIdV1(1),
                content_sha256: "b".repeat(64),
            }],
        }
    }
    #[test]
    fn bounded_epoch_source_identity_rejects_duplicate_and_malformed_evidence() {
        let valid = admission();
        valid.validate().unwrap();
        let mut duplicate = valid.clone();
        duplicate.sources.push(duplicate.sources[0].clone());
        assert!(duplicate.validate().is_err());
        let mut stale = valid.clone();
        stale.epoch.turn = 0;
        assert!(stale.validate().is_err());
        let mut malformed = valid.clone();
        malformed.sources[0].content_sha256 = "G".repeat(64);
        assert!(malformed.validate().is_err());
        let mut excessive = valid;
        excessive
            .sources
            .resize(MAX_AGENT_INPUT_SOURCES + 1, excessive.sources[0].clone());
        assert!(excessive.validate().is_err());
    }
}
