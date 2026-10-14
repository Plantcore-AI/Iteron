//! Immutable optional-script surface shared by enabled and disabled builds.

/// The parsed workflow header (best-effort; every field is optional).
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct Meta {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub phases: Option<Vec<String>>,
}

#[derive(Debug, thiserror::Error)]
#[error("JavaScript workflows require a build with the script-workflows feature")]
pub struct ScriptWorkflowsUnavailable;
