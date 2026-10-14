//! Existing operator interactions shared by local and authenticated remote clients.
//! The client names its selected scope; neither a side question nor a form answer mints authority.

use crate::{RunId, SessionId};
use serde::{Deserialize, Serialize};

pub const CLIENT_INTERACTION_VERSION: u32 = 1;
pub const MAX_SIDE_QUESTION_BYTES: usize = 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SideCommandV1 {
    pub thread_id: SessionId,
    pub run_id: RunId,
    pub command: SideActionV1,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum SideActionV1 {
    Status {},
    Ask { text: String },
    Close {},
}

impl std::fmt::Debug for SideActionV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Status {} => formatter.write_str("Status"),
            Self::Ask { text } => formatter
                .debug_struct("Ask")
                .field("text_bytes", &text.len())
                .finish(),
            Self::Close {} => formatter.write_str("Close"),
        }
    }
}

impl std::fmt::Debug for SideCommandV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SideCommandV1")
            .field("command", &self.command)
            .finish_non_exhaustive()
    }
}

impl SideCommandV1 {
    pub fn is_read_only(&self) -> bool {
        matches!(self.command, SideActionV1::Status {})
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.thread_id.0.is_empty()
            || self.thread_id.0.len() > 256
            || self.thread_id.0.chars().any(char::is_control)
        {
            return Err("invalid side thread identity");
        }
        crate::thread_lifecycle::ThreadLifecycleCommandV1::Read {
            run_id: self.run_id.clone(),
        }
        .validate()?;
        if let SideActionV1::Ask { text } = &self.command
            && (text.trim().is_empty() || text.len() > MAX_SIDE_QUESTION_BYTES)
        {
            return Err("side question exceeds its bounded contract");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{SideActionV1, SideCommandV1};
    use crate::{RunId, SessionId};

    #[test]
    fn side_requests_carry_scope_and_no_client_authority() {
        let command = SideCommandV1 {
            thread_id: SessionId("session-run".into()),
            run_id: RunId("run".into()),
            command: SideActionV1::Ask {
                text: "inspect the existing parser".into(),
            },
        };
        assert!(command.validate().is_ok());
        assert!(!command.is_read_only());
        let mut wire = serde_json::to_value(command).unwrap();
        for field in ["actor", "workspace", "provider", "budget", "approval"] {
            wire[field] = serde_json::json!("untrusted");
            assert!(serde_json::from_value::<SideCommandV1>(wire.clone()).is_err());
            wire.as_object_mut().unwrap().remove(field);
        }
        wire["command"] = serde_json::json!({"action":"status","text":"hidden payload"});
        assert!(serde_json::from_value::<SideCommandV1>(wire).is_err());
    }

    #[test]
    fn only_side_status_is_an_observer_control() {
        let mut command = SideCommandV1 {
            thread_id: SessionId("session-run".into()),
            run_id: RunId("run".into()),
            command: SideActionV1::Status {},
        };
        assert!(command.validate().is_ok());
        assert!(command.is_read_only());
        command.command = SideActionV1::Close {};
        assert!(!command.is_read_only());
        command.run_id = RunId("../foreign".into());
        assert!(command.validate().is_err());
    }
}
