//! Stable, built-in-only model-visible tool-description surface.
//!
//! Tool descriptions are optimizable text, but tool identity and authority are not.  This catalog
//! therefore names only the production tools compiled into `iteron-tools`.  Runtime/MCP tools are
//! deliberately absent: their descriptions are untrusted external input, not Iteron artifacts.

use crate::ModuleId;
use serde::Serialize;

pub const TOOL_TEXT_REGISTRY_ID: &str = "iteron-builtin-tool-descriptions";
pub const TOOL_TEXT_SCHEMA_VERSION: u16 = 1;

/// One independently replaceable built-in `ToolSpec::description`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ToolTextArtifact {
    /// Stable profile address: `tool/<canonical ToolSpec name>/description@v1`.
    pub id: &'static str,
    /// Exact canonical `ToolSpec::name`; this field itself is never replaced.
    pub tool: &'static str,
    pub module: ModuleId,
    /// Source declaration containing the compiled default.
    pub decl: &'static str,
    /// The only runtime field affected by replacement.
    pub effect: &'static str,
    pub overridable: bool,
}

macro_rules! tool_text {
    ($name:literal, $decl:literal) => {
        ToolTextArtifact {
            id: concat!("tool/", $name, "/description@v1"),
            tool: $name,
            module: ModuleId::PromptToolDescription,
            decl: $decl,
            effect: "only this built-in tool's model-visible ToolSpec.description; identity, schema and authority metadata are unchanged",
            overridable: true,
        }
    };
}

/// Total catalog for the union of built-in production tools registered by `iteron-tools`.
///
/// `iteron-tools` has a registration-boundary test that compares this catalog with the complete
/// `Registry::coding_agent` ToolSpec set.  Adding a built-in without adding its stable address (or
/// publishing a stale address) therefore fails that crate's focused contract test.
pub const TOOL_TEXT_ARTIFACTS: &[ToolTextArtifact] = &[
    tool_text!(
        "repo_map",
        "crates/tools/src/fs_tools.rs:ToolSpec::description"
    ),
    tool_text!(
        "grep",
        "crates/tools/src/grep_tool.rs:ToolSpec::description"
    ),
    tool_text!(
        "read_file",
        "crates/tools/src/fs_tools.rs:ToolSpec::description"
    ),
    tool_text!(
        "list_dir",
        "crates/tools/src/fs_tools.rs:ToolSpec::description"
    ),
    tool_text!("glob", "crates/tools/src/fs_tools.rs:ToolSpec::description"),
    tool_text!("git_diff", "crates/tools/src/git.rs:ToolSpec::description"),
    tool_text!(
        "git_status",
        "crates/tools/src/git_observe.rs:ToolSpec::description"
    ),
    tool_text!(
        "git_log",
        "crates/tools/src/git_observe.rs:ToolSpec::description"
    ),
    tool_text!(
        "read_memory",
        "crates/tools/src/mem.rs:ToolSpec::description"
    ),
    tool_text!(
        "use_skill",
        "crates/tools/src/skill.rs:ToolSpec::description"
    ),
    tool_text!("edit", "crates/tools/src/edit.rs:ToolSpec::description"),
    tool_text!(
        "apply_patch",
        "crates/tools/src/multi_file_patch.rs:ToolSpec::description"
    ),
    tool_text!(
        "write_file",
        "crates/tools/src/write_file.rs:ToolSpec::description"
    ),
    tool_text!("bash", "crates/tools/src/shell.rs:ToolSpec::description"),
    tool_text!(
        "process_start",
        "crates/tools/src/process/mod.rs:ToolSpec::description"
    ),
    tool_text!(
        "process_list",
        "crates/tools/src/process/mod.rs:ToolSpec::description"
    ),
    tool_text!(
        "process_poll",
        "crates/tools/src/process/mod.rs:ToolSpec::description"
    ),
    tool_text!(
        "process_write",
        "crates/tools/src/process/mod.rs:ToolSpec::description"
    ),
    tool_text!(
        "process_resize",
        "crates/tools/src/process/mod.rs:ToolSpec::description"
    ),
    tool_text!(
        "process_stop",
        "crates/tools/src/process/mod.rs:ToolSpec::description"
    ),
    tool_text!(
        "lsp_query",
        "crates/tools/src/lsp/mod.rs:ToolSpec::description"
    ),
    tool_text!("web_fetch", "crates/tools/src/web.rs:ToolSpec::description"),
    tool_text!(
        "web_search",
        "crates/tools/src/web.rs:ToolSpec::description"
    ),
    tool_text!(
        "dispatch_agent",
        "crates/tools/src/lib.rs:register_dispatch_agent"
    ),
    tool_text!(
        "Workflow",
        "crates/tools/src/workflow_tool.rs:ToolSpec::description"
    ),
    tool_text!(
        "tool_search",
        "crates/tools/src/tool_search.rs:ToolSpec::description"
    ),
];

#[must_use]
pub fn tool_text_artifact(tool_name: &str) -> Option<&'static ToolTextArtifact> {
    TOOL_TEXT_ARTIFACTS
        .iter()
        .find(|artifact| artifact.tool == tool_name)
}

#[must_use]
pub fn tool_text_artifact_by_id(id: &str) -> Option<&'static ToolTextArtifact> {
    TOOL_TEXT_ARTIFACTS
        .iter()
        .find(|artifact| artifact.id == id)
}

/// Digest the exact ordered publication rows.  The order is intentional and stable, matching the
/// built-in registration order rather than hash-map iteration or runtime discovery order.
#[must_use]
pub fn tool_text_registry_digest_sha256() -> String {
    use sha2::Digest as _;

    let bytes = serde_json::to_vec(&(
        TOOL_TEXT_REGISTRY_ID,
        TOOL_TEXT_SCHEMA_VERSION,
        TOOL_TEXT_ARTIFACTS,
    ))
    .expect("static tool-description catalog must serialize");
    hex::encode(sha2::Sha256::digest(bytes))
}
