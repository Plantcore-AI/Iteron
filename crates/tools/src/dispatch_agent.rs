//! The direct-child call schema and bounded metadata from the host-pinned agent catalog.
use crate::{DISPATCH_AGENT, Registry, ToolError, boxfut, err_result};
use iteron_protocol::{Capability, Purity, ToolSpec};

/// Listing cap only: the runtime still validates every explicit name against its full pinned catalog.
pub const MAX_DISPATCH_AGENT_PROFILES: usize = 16;
const MAX_PROFILE_DESCRIPTION_CHARS: usize = 80;
const MAX_PROFILE_METADATA_BYTES: usize = 4096;
const MAX_PROFILE_NAME_BYTES: usize = 128;
const MAX_PROFILE_TOOLS: usize = 32;
const PROFILE_PARAMETER_DESCRIPTION: &str = "Optional existing agent profile name. Select a narrow profile for a task with a fixed tool requirement. Omission selects generic; unknown or disallowed names are refused.";

/// Host-provided public metadata, excluding the child system prompt or any execution authority.
pub struct DispatchAgentProfile {
    pub name: String,
    pub description: String,
    pub tools: Vec<String>,
}

impl Registry {
    /// Refresh both eager and deferred schemas from the same accepted, immutable runtime catalog.
    /// This advertises choices; child construction independently applies the actual tool filter.
    pub fn set_dispatch_agent_profiles(
        &mut self,
        profiles: &[DispatchAgentProfile],
        omitted: bool,
    ) {
        let Some(tool) = self
            .tools
            .iter_mut()
            .find(|tool| tool.spec.name == DISPATCH_AGENT)
        else {
            return;
        };
        let valid_name = |name: &str| {
            !name.is_empty()
                && name.len() <= MAX_PROFILE_NAME_BYTES
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        };
        let mut description = format!(
            "{PROFILE_PARAMETER_DESCRIPTION}\nPinned profiles (configured tools; host policy may narrow further):"
        );
        let mut examples = Vec::new();
        let mut truncated = omitted || profiles.len() > MAX_DISPATCH_AGENT_PROFILES;
        let mut metadata_bytes = serde_json::to_string(&description).unwrap().len() + 200; // Hint and schema keys.
        for profile in profiles.iter().take(MAX_DISPATCH_AGENT_PROFILES) {
            if !valid_name(&profile.name)
                || profile.tools.len() > MAX_PROFILE_TOOLS
                || profile.tools.iter().any(|name| !valid_name(name))
            {
                truncated = true;
                continue;
            }
            let bounded: String = profile
                .description
                .chars()
                .take(MAX_PROFILE_DESCRIPTION_CHARS)
                .filter(|ch| !ch.is_control() || ch.is_whitespace())
                .collect();
            let summary = bounded.split_whitespace().collect::<Vec<_>>().join(" ");
            let row = format!(
                "\n- {}: {}; tools: [{}]",
                profile.name,
                summary,
                profile.tools.join(", ")
            );
            // Count the name twice because examples and the description both carry it.
            let bytes = serde_json::to_string(&row).unwrap().len() + profile.name.len() + 4;
            if metadata_bytes + bytes > MAX_PROFILE_METADATA_BYTES {
                truncated = true;
                continue;
            }
            metadata_bytes += bytes;
            description.push_str(&row);
            examples.push(profile.name.clone());
        }
        if truncated {
            description.push_str("\nAdditional profiles omitted from this bounded listing; inspect /agents for the pinned catalog. Explicit names remain valid.");
        }
        let parameter = &mut tool.spec.input_schema["properties"]["agent_type"];
        let examples = serde_json::json!(examples);
        if parameter["description"].as_str() == Some(description.as_str())
            && parameter["examples"] == examples
        {
            return;
        }
        parameter["description"] = description.into();
        parameter["examples"] = examples;
        if let Some(catalog) = &self.deferred_tool_catalog {
            catalog.insert(tool.spec.clone());
        }
        self.invalidate_spec_snapshot();
    }
}

pub(super) fn register_dispatch_agent(r: &mut Registry) -> Result<(), ToolError> {
    r.push_tool(
        ToolSpec {
            name: DISPATCH_AGENT.into(),
            description: "Delegate a READ-ONLY investigation to a subagent with its own fresh \
                          context: it explores the repo (read/grep/list/repo_map) and returns a \
                          concise summary. Use for wide search or multi-file investigation to \
                          keep your own context clean. The subagent cannot edit or run code; you \
                          remain the only writer. Give it a specific question and the output you \
                          want. Optionally select an existing agent_type whose configured tools \
                          further restrict the child's read-only toolset."
                .into(),
            input_schema: serde_json::json!({
                "type":"object",
                "properties":{
                    "task":{"type":"string","description":"the investigation question + desired output"},
                    "agent_type":{"type":"string","description":"Optional existing agent profile name; its tools allowlist narrows the read-only child tools (for example a profile configured with tools: [read_file]). Defaults to generic. Unknown or disallowed profiles are refused."}
                },
                "required":["task"]
            }),
            // Effecting so it is not early-dispatched; the kernel intercepts by name before the
            // normal effecting path and runs the subagent itself.
            purity: Purity::Effecting,
            capability: Capability::ReversibleLocal,
        },
        |call, _root| {
            boxfut::box_it(async move {
                // Never reached: the kernel intercepts DISPATCH_AGENT. This is a safety net.
                err_result(call.id, "dispatch_agent must be handled by the kernel".into())
            })
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn pinned_profiles_update_eager_and_deferred_snapshots_with_a_bounded_listing() {
        let mut registry = Registry::coding_agent(std::env::temp_dir()).unwrap();
        let old = registry.spec_snapshot();
        let profiles = (0..MAX_DISPATCH_AGENT_PROFILES + 1)
            .map(|index| DispatchAgentProfile {
                name: format!("reader-{index}"),
                description: "Reads one requested file.".into(),
                tools: vec!["read_file".into()],
            })
            .collect::<Vec<_>>();
        registry.set_dispatch_agent_profiles(&profiles, false);
        let current = registry.spec_snapshot();
        assert!(!std::sync::Arc::ptr_eq(&old, &current));
        registry.set_dispatch_agent_profiles(&profiles, false);
        assert!(std::sync::Arc::ptr_eq(&current, &registry.spec_snapshot()));
        let spec = current
            .specs()
            .iter()
            .find(|spec| spec.name == DISPATCH_AGENT)
            .unwrap();
        let parameter = &spec.input_schema["properties"]["agent_type"];
        assert_eq!(
            parameter["examples"].as_array().unwrap().len(),
            MAX_DISPATCH_AGENT_PROFILES
        );
        assert!(
            parameter.get("enum").is_none(),
            "omitted names must remain valid runtime choices"
        );
        assert!(
            parameter["description"]
                .as_str()
                .unwrap()
                .contains("Additional profiles omitted")
        );
        assert!(
            old.specs()
                .iter()
                .find(|spec| spec.name == DISPATCH_AGENT)
                .unwrap()
                .input_schema["properties"]["agent_type"]
                .get("examples")
                .is_none()
        );
        let admitted = current
            .specs()
            .iter()
            .map(|spec| spec.name.clone())
            .collect();
        let initial = registry.specs_for_task(&admitted, "read_file", Some(1));
        assert!(initial.iter().all(|spec| spec.name != DISPATCH_AGENT));
        let result = registry
            .run(iteron_protocol::ToolUse {
                id: "discover-dispatch".into(),
                name: "tool_search".into(),
                input: serde_json::json!({"query":"dispatch_agent","limit":1}),
            })
            .await;
        assert!(!result.is_error, "{}", result.content);
        let discovery: serde_json::Value = serde_json::from_str(&result.content).unwrap();
        assert_eq!(
            discovery["exposed_tools"],
            serde_json::json!([DISPATCH_AGENT])
        );
        // Discovery returns names; the next request carries each newly exposed schema.
        let next = registry.specs_for_task(&admitted, "read_file", Some(1));
        let deferred = next
            .iter()
            .find(|spec| spec.name == DISPATCH_AGENT)
            .unwrap();
        assert_eq!(
            &deferred.input_schema["properties"]["agent_type"],
            parameter
        );
        let oversized = profiles
            .into_iter()
            .map(|mut profile| {
                profile.description = "\"\\".repeat(MAX_PROFILE_DESCRIPTION_CHARS);
                profile.tools = vec!["x".repeat(MAX_PROFILE_NAME_BYTES); MAX_PROFILE_TOOLS];
                profile
            })
            .collect::<Vec<_>>();
        registry.set_dispatch_agent_profiles(&oversized, false);
        let bounded = registry.spec_snapshot();
        let parameter = &bounded
            .specs()
            .iter()
            .find(|spec| spec.name == DISPATCH_AGENT)
            .unwrap()
            .input_schema["properties"]["agent_type"];
        assert!(serde_json::to_vec(parameter).unwrap().len() <= MAX_PROFILE_METADATA_BYTES);
        assert!(parameter["examples"].as_array().unwrap().is_empty());
        assert!(parameter.get("enum").is_none());
    }
}
