//! Explicit loopback service lifecycle, independent of a particular client or runtime turn.
use crate::{RunId, SessionId, TenantId};
use serde::{Deserialize, Serialize};

pub const RESIDENT_SERVICE_VERSION: u32 = 1;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResidentServiceScopeV1 {
    pub service_id: String,
    pub thread_id: SessionId,
    pub tenant: TenantId,
    pub workspace_sha256: String,
}
impl ResidentServiceScopeV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        let digest = |v: &str| {
            v.len() == 64
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if !digest(&self.service_id)
            || !digest(&self.workspace_sha256)
            || self.thread_id.0.is_empty()
            || self.thread_id.0.len() > 256
            || self.tenant.0.is_empty()
            || self.tenant.0.len() > 256
            || self.thread_id.0.chars().any(char::is_control)
            || self.tenant.0.chars().any(char::is_control)
        {
            return Err("invalid resident service scope");
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResidentServiceCommandV1 {
    Read {},
    Stop { scope: ResidentServiceScopeV1 },
}
impl ResidentServiceCommandV1 {
    pub fn is_read_only(&self) -> bool {
        matches!(self, Self::Read {})
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResidentServiceViewV1 {
    pub version: u32,
    pub scope: ResidentServiceScopeV1,
    pub endpoint: std::net::SocketAddr,
    pub current_run_id: RunId,
    pub stopping: bool,
    /// A request accepted by the service is not a confirmed physical shutdown.
    pub shutdown_completed: bool,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn service_commands_cannot_supply_runtime_authority_or_a_shutdown_receipt() {
        assert!(
            serde_json::from_value::<ResidentServiceCommandV1>(
                serde_json::json!({"action":"read"})
            )
            .unwrap()
            .is_read_only()
        );
        for key in [
            "path",
            "actor",
            "tenant",
            "token",
            "shutdown_completed",
            "force",
            "run_id",
        ] {
            assert!(
                serde_json::from_value::<ResidentServiceCommandV1>(
                    serde_json::json!({"action":"read",(key):true})
                )
                .is_err()
            );
        }
    }
}
