//! `use_skill` — load one skill's instructions on demand (Claude Code SKILL.md parity, R5).
//!
//! The always-injected skill index (name + description per skill) lets the model see what skills
//! exist; when a listing looks relevant it calls `use_skill(name)` to pull the full body. `Pure`/
//! `ReadOnly` (it reads instruction files), so it is early-dispatchable and memoized. The body is
//! framed as "hints, not overrides" and carries the skill's store trust (a project/Untrusted skill
//! taints the turn's egress via `ToolResult.trust`, ADR-007).

use crate::{Registry, ToolError, boxfut, err_result};
use iteron_ctx::skills::SkillCatalog;
use iteron_protocol::{Capability, Purity, ToolResult, ToolSpec, Trust};
use std::path::Path;

fn load_skill(id: String, name: &str, root: &Path, operator_home: Option<&Path>) -> ToolResult {
    let catalog = SkillCatalog::discover_for_operator(operator_home, root);
    match catalog.get(name) {
        Some(skill) => {
            let trust = skill.trust;
            ToolResult {
                tool_use_id: id,
                content: skill.framed(),
                // A skill below the user tier taints the turn (never elevate above Workspace).
                trust: if trust == Trust::Trusted {
                    Trust::Workspace
                } else {
                    trust
                },
                is_error: false,
                latency_ms: 0,
            }
        }
        None => err_result(id, format!("no skill `{name}` (see the skills index)")),
    }
}

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
                let home = iteron_protocol::home::operator();
                load_skill(id, &name, &root, home.as_deref())
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

    #[test]
    fn use_skill_loads_the_same_portable_operator_root_as_the_index() {
        let base =
            std::env::temp_dir().join(format!("core-use-portable-skill-{}", std::process::id()));
        let home = base.join("home");
        let repo = base.join("repo");
        let skill = home.join(".agents/skills/portable");
        std::fs::create_dir_all(&skill).unwrap();
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(
            skill.join("SKILL.md"),
            "---\nname: portable\ndescription: shared helper\n---\nPortable body.\n",
        )
        .unwrap();

        let result = load_skill("call-1".into(), "portable", &repo, Some(&home));
        assert!(!result.is_error, "{}", result.content);
        assert!(result.content.contains("Portable body."));
        let _ = std::fs::remove_dir_all(&base);
    }
}
