//! Operator Activity Center addresses actual owner handles, never presentation labels.
use crate::agent_control::{AgentEpochV1, AgentIdV1};
use crate::{RunId, SessionId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActivityTargetV1 {
    Process {
        job_id: String,
    },
    PersistentAgent {
        agent_id: AgentIdV1,
        #[serde(default)]
        epoch: Option<AgentEpochV1>,
    },
    Workflow {
        run_id: String,
    },
    Mcp {
        name: String,
    },
    Verifier {
        task_id: String,
    },
}
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ActivityControlV1 {
    List {
        thread_id: SessionId,
        run_id: RunId,
    },
    Inspect {
        thread_id: SessionId,
        run_id: RunId,
        target: ActivityTargetV1,
        stdout_cursor: u64,
        stderr_cursor: u64,
    },
    Stop {
        thread_id: SessionId,
        run_id: RunId,
        target: ActivityTargetV1,
        request_id: String,
    },
}
impl ActivityControlV1 {
    pub fn scope(&self) -> (&SessionId, &RunId) {
        match self {
            Self::List { thread_id, run_id }
            | Self::Inspect {
                thread_id, run_id, ..
            }
            | Self::Stop {
                thread_id, run_id, ..
            } => (thread_id, run_id),
        }
    }
    pub fn is_read_only(&self) -> bool {
        !matches!(self, Self::Stop { .. })
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        let bounded = |value: &str| {
            !value.is_empty() && value.len() <= 200 && !value.chars().any(char::is_control)
        };
        let (thread, run) = self.scope();
        if thread.0.is_empty()
            || thread.0.len() > 256
            || thread.0.chars().any(char::is_control)
            || !bounded(&run.0)
        {
            return Err("activity_scope_bounds");
        }
        let target = match self {
            Self::List { .. } => return Ok(()),
            Self::Inspect { target, .. } | Self::Stop { target, .. } => target,
        };
        match target {
            ActivityTargetV1::PersistentAgent { agent_id, epoch } => {
                if agent_id.0 == 0 || epoch.is_some_and(|epoch| epoch.incarnation == 0) {
                    return Err("activity_agent_identity");
                }
                if matches!(self, Self::Stop { .. }) && epoch.is_none() {
                    return Err("activity_stop_requires_epoch");
                }
            }
            ActivityTargetV1::Process { job_id } if !bounded(job_id) => {
                return Err("activity_target_bounds");
            }
            ActivityTargetV1::Workflow { run_id } if !bounded(run_id) => {
                return Err("activity_target_bounds");
            }
            ActivityTargetV1::Mcp { name } if !bounded(name) => {
                return Err("activity_target_bounds");
            }
            ActivityTargetV1::Verifier { task_id } if !bounded(task_id) => {
                return Err("activity_target_bounds");
            }
            _ => {}
        }
        if let Self::Stop { request_id, .. } = self
            && (request_id.is_empty()
                || request_id.len() > 128
                || request_id.chars().any(char::is_control))
        {
            return Err("activity_request_id_bounds");
        }
        Ok(())
    }
}
impl<'de> Deserialize<'de> for ActivityControlV1 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
        enum Wire {
            List {
                thread_id: SessionId,
                run_id: RunId,
            },
            Inspect {
                thread_id: SessionId,
                run_id: RunId,
                target: ActivityTargetV1,
                #[serde(default)]
                stdout_cursor: u64,
                #[serde(default)]
                stderr_cursor: u64,
            },
            Stop {
                thread_id: SessionId,
                run_id: RunId,
                target: ActivityTargetV1,
                request_id: String,
            },
        }
        let value = match Wire::deserialize(deserializer)? {
            Wire::List { thread_id, run_id } => Self::List { thread_id, run_id },
            Wire::Inspect {
                thread_id,
                run_id,
                target,
                stdout_cursor,
                stderr_cursor,
            } => Self::Inspect {
                thread_id,
                run_id,
                target,
                stdout_cursor,
                stderr_cursor,
            },
            Wire::Stop {
                thread_id,
                run_id,
                target,
                request_id,
            } => Self::Stop {
                thread_id,
                run_id,
                target,
                request_id,
            },
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}
#[cfg(test)]
mod tests {
    use super::ActivityControlV1;
    use serde_json::json;
    #[test]
    fn strict_owner_handles_and_epoch_guard_do_not_accept_activity_actor_or_path() {
        let read = json!({"action":"inspect","thread_id":"thread","run_id":"run","target":{"kind":"verifier","task_id":"turn-0:verification"}});
        assert!(
            serde_json::from_value::<ActivityControlV1>(read.clone())
                .unwrap()
                .is_read_only()
        );
        for field in ["actor", "path", "state", "effects_known"] {
            let mut forged = read.clone();
            forged[field] = json!("operator");
            assert!(serde_json::from_value::<ActivityControlV1>(forged).is_err());
        }
        assert!(serde_json::from_value::<ActivityControlV1>(json!({"action":"stop","thread_id":"thread","run_id":"run","request_id":"stop","target":{"kind":"persistent_agent","agent_id":1}})).is_err());
    }
}
