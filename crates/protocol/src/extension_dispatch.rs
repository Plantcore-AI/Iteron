//! A host-installed restriction on already admitted extension dispatch. This port grants no authority.
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionSurfaceV1 {
    Skill,
    Agent,
    Hook,
    McpServer,
    LanguageServer,
    Implementation,
    Tool,
    Provider,
    Ui,
    EventSubscription,
}
/// Evaluated against an existing verified binding at its actual dispatch boundary.
/// `true` preserves the existing admission; `false` revokes that generation's future dispatch.
pub trait ExtensionDispatchPolicy: Send + Sync + std::fmt::Debug {
    fn admits(&self, surface: ExtensionSurfaceV1, key: &str) -> bool;
}

pub fn language_server_dispatch_key(language: &str, command: &str) -> String {
    use sha2::{Digest, Sha256};
    format!(
        "{language}/{}",
        Sha256::digest(command.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}
