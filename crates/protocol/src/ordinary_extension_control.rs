//! Ordinary SDK observers read actual host bindings; no install, callback, actor or credential input.
use crate::{RunId, SessionId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum OrdinaryExtensionReadV1 {
    Read {
        thread_id: SessionId,
        run_id: RunId,
        #[serde(default)]
        offset: u16,
        #[serde(default = "default_limit")]
        limit: u16,
    },
    Events {
        thread_id: SessionId,
        run_id: RunId,
        name: String,
        #[serde(default = "default_limit")]
        limit: u16,
        #[serde(default)]
        timeout_ms: u32,
    },
}
fn default_limit() -> u16 {
    16
}
impl OrdinaryExtensionReadV1 {
    pub fn scope(&self) -> (&SessionId, &RunId) {
        match self {
            Self::Read {
                thread_id, run_id, ..
            }
            | Self::Events {
                thread_id, run_id, ..
            } => (thread_id, run_id),
        }
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        let (thread, run) = self.scope();
        if thread.0.is_empty()
            || thread.0.len() > 256
            || run.0.is_empty()
            || run.0.len() > 200
            || thread.0.chars().chain(run.0.chars()).any(char::is_control)
        {
            return Err("extension_scope_bounds");
        }
        match self {
            Self::Read { offset, limit, .. } if *offset <= 64 && (1..=32).contains(limit) => Ok(()),
            Self::Events {
                name,
                limit,
                timeout_ms,
                ..
            } if (1..=64).contains(limit)
                && *timeout_ms <= 60_000
                && name.len() <= 64
                && name.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
                && name
                    .split_once("__")
                    .is_some_and(|(left, right)| !left.is_empty() && !right.is_empty())
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')) =>
            {
                Ok(())
            }
            _ => Err("extension_read_bounds"),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::OrdinaryExtensionReadV1;
    use serde_json::json;
    #[test]
    fn observer_does_not_accept_authority_or_locator_fields_and_work_is_bounded() {
        let source = json!({"action":"events","thread_id":"thread","run_id":"run","name":"sample__events","limit":64,"timeout_ms":60000});
        assert!(
            serde_json::from_value::<OrdinaryExtensionReadV1>(source.clone())
                .unwrap()
                .validate()
                .is_ok()
        );
        for key in [
            "actor",
            "path",
            "credential",
            "install",
            "emit",
            "capabilities",
            "callback",
        ] {
            let mut forged = source.clone();
            forged[key] = json!("forged");
            assert!(serde_json::from_value::<OrdinaryExtensionReadV1>(forged).is_err());
        }
        for (key, value) in [("limit", 0), ("limit", 65), ("timeout_ms", 60001)] {
            let mut invalid = source.clone();
            invalid[key] = json!(value);
            assert!(
                serde_json::from_value::<OrdinaryExtensionReadV1>(invalid)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
    }
}
