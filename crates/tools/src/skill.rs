//! `use_skill` — load one skill's instructions on demand (Claude Code SKILL.md parity, R5).
//!
//! The always-injected skill index (name + description per skill) lets the model see what skills
//! exist; when a listing looks relevant it calls `use_skill(name)` to pull the full body. `Pure`/
//! `ReadOnly` (it reads instruction files), so it is early-dispatchable and memoized. The body is
//! framed as "hints, not overrides" and carries the skill's store trust (a project/Untrusted skill
//! taints the turn's egress via `ToolResult.trust`, ADR-007).

use crate::{Registry, ToolError, boxfut, err_result};
use core_ctx::skills::{SkillCatalog, user_skills_dir};
use core_protocol::{Capability, Purity, ToolResult, ToolSpec, Trust};

pub(crate) fn register(r: &mut Registry) -> Result<(), ToolError> {
    r.push_tool(
        ToolSpec {
            name: "use_skill".into(),
            description: "Load a skill's instructions by name (from the skills index in the system \
                          prompt). Use when a skill listing is relevant to the current task."
                .into(),
            input_schema: serde_json::json!({
                "type":"object",
                "properties":{"name":{"type":"string","description":"the skill name from the skills index"}},
                "required":["name"]
            }),
            purity: Purity::Pure,
            capability: Capability::ReadOnly,
        },
        |call, root| {
            boxfut::box_it(async move {
                let id = call.id.clone();
                let name = call.input.get("name").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
                if name.is_empty() {
                    return err_result(id, "use_skill needs a `name`".into());
                }
                let catalog = match user_skills_dir() {
                    Some(user) => SkillCatalog::discover(&user, &root),
                    None => SkillCatalog::discover_without_user(&root),
                };
                match catalog.get(&name) {
                    Some(skill) => {
                        let trust = skill.trust;
                        ToolResult {
                            tool_use_id: id,
                            content: skill.framed(),
                            // A skill below the user tier taints the turn (never elevate above Workspace).
                            trust: if trust == Trust::Trusted { Trust::Workspace } else { trust },
                            is_error: false,
                            latency_ms: 0,
                        }
                    }
                    None => err_result(id, format!("no skill `{name}` (see the skills index)")),
                }
            })
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn use_skill_is_pure_readonly() {
        let dir = std::env::temp_dir();
        let r = Registry::read_only(&dir).unwrap();
        assert_eq!(r.purity_of("use_skill"), Some(Purity::Pure));
        assert_eq!(r.capability_of("use_skill"), Some(Capability::ReadOnly));
    }
}
