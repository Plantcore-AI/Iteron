//! Public host controls for the persistent-agent owner. Authentication supplies actor authority.

use crate::agent_control::{
    AgentBudgetV1, AgentCommandV1, AgentIdV1, AgentMessageIdV1, MAX_AGENT_REQUEST_ID_BYTES,
};
use crate::capability_set::CapabilitySet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientAgentControlV1 {
    Enable {
        capabilities: CapabilitySet,
        budget: AgentBudgetV1,
        max_agents: u8,
        max_pending_per_agent: u8,
        parallel: u8,
    },
    Command {
        request_id: String,
        command: AgentCommandV1,
    },
    #[serde(deserialize_with = "deserialize_list")]
    List,
    Inspect {
        agent_id: AgentIdV1,
    },
    MessageReceipt {
        message_id: AgentMessageIdV1,
    },
    Wait {
        after_revision: u64,
        timeout_ms: u64,
    },
}

fn deserialize_list<'de, D>(deserializer: D) -> Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
{
    // Serde's internally tagged unit visitor ignores the remaining map even when the enum has
    // deny_unknown_fields. Validate this zero-field payload without changing the public unit
    // variant or its existing {"type":"list"} serialization.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Empty {}

    Empty::deserialize(deserializer).map(|_| ())
}

impl ClientAgentControlV1 {
    pub fn is_read_only(&self) -> bool {
        matches!(
            self,
            Self::List | Self::Inspect { .. } | Self::MessageReceipt { .. } | Self::Wait { .. }
        )
    }

    pub fn is_enable(&self) -> bool {
        matches!(self, Self::Enable { .. })
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Enable {
                budget,
                max_agents,
                max_pending_per_agent,
                parallel,
                ..
            } => {
                budget.validate()?;
                if *max_agents == 0
                    || *max_agents > 64
                    || *max_pending_per_agent == 0
                    || *max_pending_per_agent > 128
                    || *parallel == 0
                    || *parallel > *max_agents
                {
                    return Err("agent controller capacities exceed the bounded host contract");
                }
            }
            Self::Command {
                request_id,
                command,
            } => {
                if request_id.is_empty()
                    || request_id.len() > MAX_AGENT_REQUEST_ID_BYTES
                    || !request_id.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
                    })
                {
                    return Err("agent request identity exceeds its bounded contract");
                }
                command.validate()?;
            }
            Self::Inspect { agent_id } if agent_id.0 == 0 => {
                return Err("agent identity must be non-zero");
            }
            Self::MessageReceipt { message_id } if message_id.0 == 0 => {
                return Err("message identity must be non-zero");
            }
            Self::Wait { timeout_ms, .. } if *timeout_ms == 0 || *timeout_ms > 60_000 => {
                return Err("agent observation wait must be 1..60000 ms");
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_and_recovery_evidence_are_not_client_inputs() {
        assert!(
            serde_json::from_str::<ClientAgentControlV1>(r#"{"type":"list","actor":"operator"}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<ClientAgentControlV1>(
                r#"{"type":"wait","after_revision":0,"timeout_ms":1,"effects_known":true}"#
            )
            .is_err()
        );
        assert!(
            ClientAgentControlV1::Wait {
                after_revision: 0,
                timeout_ms: 60_001
            }
            .validate()
            .is_err()
        );
        assert!(
            ClientAgentControlV1::Inspect {
                agent_id: AgentIdV1(0)
            }
            .validate()
            .is_err()
        );
        assert!(ClientAgentControlV1::List.is_read_only());
    }

    #[test]
    fn list_retains_its_existing_wire_shape_and_rejects_every_extra_authority_field() {
        let list: ClientAgentControlV1 = serde_json::from_str(r#"{"type":"list"}"#).unwrap();
        assert!(matches!(list, ClientAgentControlV1::List));
        assert_eq!(
            serde_json::to_value(list).unwrap(),
            serde_json::json!({"type": "list"})
        );
        for input in [
            r#"{"type":"list","effects_known":true}"#,
            r#"{"type":"list","actor":"operator"}"#,
            r#"{"type":"list","path":"/another/run"}"#,
            r#"{"type":"list","unknown":null}"#,
        ] {
            assert!(serde_json::from_str::<ClientAgentControlV1>(input).is_err());
        }
    }
}
