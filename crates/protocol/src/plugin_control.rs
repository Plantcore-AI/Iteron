//! Plugin management accepts verified host receipt IDs, never package paths or trust-key grants.
use crate::{RunId, SessionId};
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum PluginControlV1 {
    List {
        thread_id: SessionId,
        run_id: RunId,
    },
    SetEnabled {
        thread_id: SessionId,
        run_id: RunId,
        plugin_id: String,
        enabled: bool,
    },
    SetPrecedence {
        thread_id: SessionId,
        run_id: RunId,
        plugin_id: String,
        precedence: u32,
    },
    Rollback {
        thread_id: SessionId,
        run_id: RunId,
        plugin_id: String,
    },
    Install {
        thread_id: SessionId,
        run_id: RunId,
        receipt_id: String,
    },
}
impl PluginControlV1 {
    pub fn scope(&self) -> (&SessionId, &RunId) {
        match self {
            Self::List { thread_id, run_id }
            | Self::SetEnabled {
                thread_id, run_id, ..
            }
            | Self::SetPrecedence {
                thread_id, run_id, ..
            }
            | Self::Rollback {
                thread_id, run_id, ..
            }
            | Self::Install {
                thread_id, run_id, ..
            } => (thread_id, run_id),
        }
    }
    pub fn is_read_only(&self) -> bool {
        matches!(self, Self::List { .. })
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        let (thread, run) = self.scope();
        if thread.0.is_empty()
            || thread.0.len() > 256
            || run.0.is_empty()
            || run.0.len() > 200
            || thread.0.chars().chain(run.0.chars()).any(char::is_control)
        {
            return Err("plugin_scope_bounds");
        }
        let name = match self {
            Self::List { .. } => return Ok(()),
            Self::SetEnabled { plugin_id, .. }
            | Self::SetPrecedence { plugin_id, .. }
            | Self::Rollback { plugin_id, .. } => plugin_id,
            Self::Install { receipt_id, .. } => receipt_id,
        };
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err("plugin_identity_bounds");
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::PluginControlV1;
    use serde_json::json;
    #[test]
    fn trusted_receipt_identity_is_the_only_public_install_locator() {
        let value = json!({"action":"install","thread_id":"thread","run_id":"run","receipt_id":"prepared-1"});
        let command = serde_json::from_value::<PluginControlV1>(value.clone()).unwrap();
        assert!(command.validate().is_ok());
        assert!(!command.is_read_only());
        for field in ["path", "actor", "trusted_key", "capabilities", "digest"] {
            let mut forged = value.clone();
            forged[field] = json!("forged");
            assert!(serde_json::from_value::<PluginControlV1>(forged).is_err());
        }
    }
}
