//! Operator session navigation supplies identities; native constructors and leases stay in the host.
use crate::{Effort, RunId, Seq, SessionId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionNavigationV1 {
    New {
        thread_id: SessionId,
        run_id: RunId,
    },
    Resume {
        thread_id: SessionId,
        run_id: RunId,
        target_run_id: RunId,
    },
    Fork {
        thread_id: SessionId,
        run_id: RunId,
        /// Omitted selects the actual verified physical tail in the trusted host.
        #[serde(default)]
        through_seq: Option<u64>,
    },
}
impl SessionNavigationV1 {
    pub fn thread_id(&self) -> &SessionId {
        match self {
            Self::New { thread_id, .. }
            | Self::Resume { thread_id, .. }
            | Self::Fork { thread_id, .. } => thread_id,
        }
    }
    pub fn run_id(&self) -> &RunId {
        match self {
            Self::New { run_id, .. } | Self::Resume { run_id, .. } | Self::Fork { run_id, .. } => {
                run_id
            }
        }
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.thread_id().0.is_empty()
            || self.thread_id().0.len() > 256
            || self.thread_id().0.chars().any(char::is_control)
        {
            return Err("invalid session identity");
        }
        crate::thread_lifecycle::ThreadLifecycleCommandV1::Read {
            run_id: self.run_id().clone(),
        }
        .validate()?;
        match self {
            Self::Resume { target_run_id, .. } => {
                crate::thread_lifecycle::ThreadLifecycleCommandV1::Read {
                    run_id: target_run_id.clone(),
                }
                .validate()?
            }
            Self::Fork { through_seq, .. } if *through_seq == Some(0) => {
                return Err("fork requires an actual positive journal sequence");
            }
            _ => {}
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionNavigationReplyV1 {
    pub version: u32,
    pub thread_id: SessionId,
    pub origin_run_id: RunId,
    pub run_id: RunId,
    pub fresh: bool,
    pub provider_id: String,
    pub model_id: String,
    pub effort: Effort,
    pub context_window_tokens: Option<u64>,
    pub messages: usize,
    pub turns: u32,
    pub checkpoint_digest_sha256: String,
    pub blocked: Option<String>,
    pub substituted_route: Option<String>,
    pub transcript: SessionTranscriptV1,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionTranscriptV1 {
    pub source: String,
    pub total_blocks: usize,
    pub omitted_blocks: usize,
    pub blocks: Vec<SessionTranscriptBlockV1>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionTranscriptBlockV1 {
    pub source_run_id: RunId,
    pub source_seq: Seq,
    pub content_truncated: bool,
    pub content: SessionTranscriptContentV1,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionTranscriptContentV1 {
    User {
        text: String,
    },
    Assistant {
        text: String,
    },
    Thinking {
        text: String,
    },
    Tool {
        name: String,
        args: Value,
        recorded_is_error: Option<bool>,
        output: String,
        latency_ms: Option<u64>,
    },
}
#[cfg(test)]
mod tests {
    use super::SessionNavigationV1;
    use serde_json::json;
    #[test]
    fn navigation_cannot_supply_a_locator_provider_or_authority_and_preserves_portable_ids() {
        let base = json!({"action":"resume","thread_id":"thread","run_id":"current","target_run_id":"legacy session.中文"});
        assert!(
            serde_json::from_value::<SessionNavigationV1>(base.clone())
                .unwrap()
                .validate()
                .is_ok()
        );
        for field in [
            "path",
            "tenant",
            "workspace",
            "provider",
            "credentials",
            "budget",
            "actor",
            "rollout",
            "effects_known",
            "cancel",
        ] {
            let mut forged = base.clone();
            forged[field] = json!(true);
            assert!(
                serde_json::from_value::<SessionNavigationV1>(forged).is_err(),
                "{field}"
            );
        }
        assert!(serde_json::from_value::<SessionNavigationV1>(json!({"action":"resume","thread_id":"thread","run_id":"current","target_run_id":"../foreign"})).unwrap().validate().is_err());
        assert!(
            serde_json::from_value::<SessionNavigationV1>(
                json!({"action":"fork","thread_id":"thread","run_id":"current","through_seq":0})
            )
            .unwrap()
            .validate()
            .is_err()
        );
    }
}
