//! `AgentDef` and `ToolFilter` — the interpreted agent definition the fan-out draws from, plus the
//! zero-dependency frontmatter parse and the "tools can only narrow the read-only set" load check.
//!
//! An agent definition mirrors Claude Code's `~/.claude/agents/<name>.md` (frontmatter + body), but
//! with the ADR-007 security treatment: the body is the subagent's *system* prompt; `tools` can only
//! **narrow** a fixed read-only registry (ADR-001, single writer); and a definition that names a
//! write/exec/dispatch tool is a **load error surfaced at catalog build**, never a silent grant.

use core_protocol::{Budget, Trust};

use serde::{Deserialize, Serialize};

/// The read-only tool set an agent may use — the base every fan-out worker gets, which `ToolFilter`
/// can only narrow. Mirrors `core_tools::Registry::read_only` (`crates/tools/src/lib.rs`), which
/// registers the five filesystem discovery tools plus confined Git observations,
/// progressive-disclosure memory recall, and on-demand skill loading. Hard-coded here because this
/// pure policy crate must not depend on the executor's `tools` crate; the build-plane conformance
/// check constructs the real registry and compares its names with this contract.
pub const READ_ONLY_TOOLS: &[&str] = &[
    "read_file",
    "list_dir",
    "glob",
    "grep",
    "repo_map",
    "git_diff",
    "git_status",
    "git_log",
    "read_memory",
    "use_skill",
];

/// Tool names that write, execute, or dispatch — refused if an `Allow` list names one, because a
/// fan-out worker is read-only (ADR-001). Core's writer vocabulary is listed explicitly before
/// the common aliases from other harnesses (Claude Code / Codex / Cline), so importing a foreign
/// definition cannot smuggle a writer past the narrowing rule.
const WRITE_EXEC_DISPATCH: &[&str] = &[
    "edit",
    "bash",
    "dispatch_agent",
    "process_start",
    "process_write",
    "process_stop",
    "write",
    "notebookedit",
    "multiedit",
    "apply_patch",
    "shell",
    "task",
];

/// The subagent system prompt for the built-in generic investigator. It names the complete
/// `READ_ONLY_TOOLS` capability contract; executors should resolve this `AgentDef` instead of
/// maintaining a second prompt with a smaller, drifting tool inventory.
pub(crate) const SUBAGENT_SYSTEM: &str = "You are a read-only investigation subagent. Explore the \
    repository with read_file, list_dir, glob, grep, repo_map, git_diff, git_status, git_log, \
    read_memory, and use_skill to answer the question. You cannot edit files or run code. When \
    done, reply with a concise summary (aim for under ~1500 tokens): the direct answer, with \
    file:line references for anything you claim.";

/// How an agent's `tools` frontmatter narrows the read-only registry. Tools can only **narrow**
/// (ADR-001): `All` is the whole read-only set, `Allow` intersects it, `Deny` subtracts from it.
/// `Deny` is the recommended idiom (the local Claude Code agents use `disallowedTools:` precisely so
/// MCP tools survive — a bare `Allow` of `[Read, Grep]` would strip every `mcp__*` tool).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolFilter {
    /// Inherit the whole read-only set.
    All,
    /// Allow only these (intersected with the read-only set).
    Allow(Vec<String>),
    /// Allow everything in the read-only set except these.
    Deny(Vec<String>),
}

impl ToolFilter {
    /// Apply this filter to the built-in read-only set, returning the effective tool names.
    ///
    /// This is the pure narrowing policy the kernel's executor consumes when it builds a worker's
    /// registry: it can never *add* a tool, only keep a subset of `READ_ONLY_TOOLS`. (MCP `mcp__*`
    /// tools, if any, are layered by the kernel above this base; matching is case-insensitive to
    /// tolerate `Read`/`read_file`-style casing from imported definitions.)
    pub fn narrow(&self) -> Vec<String> {
        let named = |names: &[String], t: &str| names.iter().any(|n| n.eq_ignore_ascii_case(t));
        match self {
            ToolFilter::All => READ_ONLY_TOOLS.iter().map(|s| s.to_string()).collect(),
            ToolFilter::Allow(names) => READ_ONLY_TOOLS
                .iter()
                .filter(|t| named(names, t))
                .map(|s| s.to_string())
                .collect(),
            ToolFilter::Deny(names) => READ_ONLY_TOOLS
                .iter()
                .filter(|t| !named(names, t))
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

/// Is `name` a write/execute/dispatch tool (which an agent definition may never grant)?
pub(crate) fn is_write_exec_dispatch(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    WRITE_EXEC_DISPATCH.contains(&n.as_str())
}

/// An interpreted agent definition: a fully-resolved worker template the fan-out can spawn.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDef {
    /// Catalog key (frontmatter `name`; required).
    pub name: String,
    /// The listing entry — a compact, cache-stable projection (frontmatter `description`).
    pub description: String,
    /// The subagent's system prompt (the frontmatter body).
    pub system: String,
    /// Narrows the read-only registry only (never widens it).
    pub tools: ToolFilter,
    /// Per-agent model override; `None` = inherit the parent's model.
    pub model: Option<String>,
    /// Bounded budget (invariant #1); defaults to the cheap subagent budget.
    pub budget: Budget,
    /// Trust tier, from the discovery origin (ADR-007).
    pub trust: Trust,
}

/// The largest budget a discovered subagent may receive. Admission can only narrow this ceiling.
/// Raised to 30 turns: fan workers now run bounded-concurrent (owned tasks under a `Governor`), so
/// each admitted investigator gets its own real budget rather than a thin slice of one serial chain;
/// total cost stays bounded by the shared `max_usd`/wall/run-deadline ceilings and the permit count.
pub fn subagent_budget_ceiling() -> Budget {
    Budget {
        max_turns: 30,
        // No verified per-route rate card is inherited by a discovered worker yet. Turn/time
        // ceilings remain enforceable; a guessed dollar ceiling would not.
        max_usd: None,
        max_tokens: None,
        max_wall_secs: 300,
        max_consecutive_tool_errors: 3,
    }
}

/// Allocate one direct-investigator budget while reserving about half of the remaining turns for
/// the single writer (rebalanced from two thirds: the writer still keeps the dominant share, but a
/// bounded-concurrent fan no longer needs to starve investigators down a serial chain). This is the
/// authoritative policy consumed by the kernel: budget arithmetic belongs here with the agent
/// definition, so the execution plane cannot grow a second set of mirrored limits.
pub fn subagent_budget(
    remaining_turns: u32,
    remaining_wall_secs: u64,
    remaining_tokens: Option<u64>,
) -> Option<Budget> {
    let ceiling = subagent_budget_ceiling();
    // Half-plus-one keeps the writer strictly dominant while relaxing the old two-thirds reserve.
    let writer_reserve = ((remaining_turns / 2).saturating_add(1))
        .max(2)
        .min(remaining_turns);
    let child_turns = remaining_turns
        .saturating_sub(writer_reserve)
        .min(ceiling.max_turns);
    if child_turns < 2
        || remaining_wall_secs < 3
        || remaining_tokens.is_some_and(|tokens| tokens < 2)
    {
        return None;
    }
    Some(Budget {
        max_turns: child_turns,
        max_usd: ceiling.max_usd,
        max_tokens: remaining_tokens.map(|tokens| tokens / 2),
        max_wall_secs: (remaining_wall_secs / 3).clamp(1, ceiling.max_wall_secs),
        max_consecutive_tool_errors: ceiling.max_consecutive_tool_errors,
    })
}

impl AgentDef {
    /// The built-in read-only investigator (the design's `generic()`): the default worker a fan-out
    /// leaf resolves to when it names no `agent_type`. It is Trusted (harness-authored), inherits
    /// the parent model, and can use the whole read-only set.
    pub fn generic() -> AgentDef {
        AgentDef {
            name: "generic".into(),
            description:
                "Read-only investigation subagent: explores files, globs, repository map, \
                confined Git observations, memory, and skills; returns a concise summary with \
                file:line references. Cannot edit files or run code."
                    .into(),
            system: SUBAGENT_SYSTEM.into(),
            tools: ToolFilter::All,
            model: None,
            budget: subagent_budget_ceiling(),
            trust: Trust::Trusted,
        }
    }
}

/// Parse one agent-definition file into an `AgentDef`, or a `LoadError` explaining the rejection.
///
/// Zero-dependency (Principal §zero-dependency-first): a hand-written frontmatter split + key/value
/// parse, no `serde_yaml`. The rejections, in order: suspicious Unicode (bidi/invisible-char
/// injection, ADR-007); missing `---` fences; missing required `name`; and an `Allow` list that
/// names a write/exec/dispatch tool (the narrowing rule — the same fail-loud discipline as the
/// tool-registration purity check, `crates/tools/src/lib.rs:94`).
pub(crate) fn parse_def(
    source: &str,
    text: &str,
    trust: Trust,
) -> Result<AgentDef, super::LoadError> {
    let err = |reason: String| super::LoadError {
        source: source.to_string(),
        reason,
    };

    if let Some(cp) = super::suspicious_unicode(text) {
        return Err(err(format!(
            "contains suspicious Unicode (U+{cp:04X}); refusing to load (ADR-007)"
        )));
    }
    let (kv, body) =
        split_frontmatter(text).ok_or_else(|| err("missing `---` frontmatter fences".into()))?;

    let name = kv_get(&kv, "name")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| err("frontmatter missing required `name`".into()))?;
    let description = kv_get(&kv, "description").unwrap_or_default();
    let model = kv_get(&kv, "model").filter(|s| !s.is_empty() && s != "inherit");

    // `tools:` is an allowlist; `disallowedTools:` is a denylist; neither = inherit all.
    let tools = if let Some(list) = kv_get_list(&kv, "tools") {
        ToolFilter::Allow(list)
    } else if let Some(list) = kv_get_list(&kv, "disallowedTools") {
        ToolFilter::Deny(list)
    } else {
        ToolFilter::All
    };

    // Narrowing check: an Allow list naming a write/exec/dispatch tool is an attempted *grant*,
    // which ADR-001 forbids. A Deny list naming one is merely redundant (belt-and-suspenders) and
    // is allowed. This is the footgun the local Claude Code agents document in a comment.
    let grant = match &tools {
        ToolFilter::Allow(names) => names.iter().find(|n| is_write_exec_dispatch(n)),
        _ => None,
    };
    if let Some(bad) = grant {
        return Err(err(format!(
            "`tools` names `{bad}`, a write/exec/dispatch tool; an agent's `tools` can only \
             NARROW the read-only set, never grant a writer (ADR-001 / ADR-013)"
        )));
    }

    Ok(AgentDef {
        name,
        description,
        system: body.trim().to_string(),
        tools,
        model,
        budget: subagent_budget_ceiling(),
        trust,
    })
}

/// Split `---`-fenced frontmatter from the body. Returns the key/value pairs and the body, or
/// `None` if the file does not open with a `---` fence and close with another. Comment lines
/// (`# ...`) inside the frontmatter are skipped, matching the local agents' inline-comment idiom.
fn split_frontmatter(text: &str) -> Option<(Vec<(String, String)>, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    while i < lines.len() && lines[i].trim().is_empty() {
        i += 1;
    }
    if i >= lines.len() || lines[i].trim() != "---" {
        return None;
    }
    let open = i;
    let close = ((open + 1)..lines.len()).find(|&j| lines[j].trim() == "---")?;

    let mut kv = Vec::new();
    for line in &lines[open + 1..close] {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = l.split_once(':') {
            kv.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let body = lines[close + 1..].join("\n");
    Some((kv, body))
}

fn kv_get(kv: &[(String, String)], key: &str) -> Option<String> {
    kv.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
}

/// Parse a frontmatter list value: `[a, b, c]`, a bare `a, b`, or a single scalar. Quotes are
/// stripped; empty items dropped. Returns `None` only when the key is absent (a present-but-empty
/// `tools: []` yields `Some(vec![])` — a definition that may use no tools, which is valid).
fn kv_get_list(kv: &[(String, String)], key: &str) -> Option<Vec<String>> {
    let raw = kv_get(kv, key)?;
    let inner = raw.trim();
    let inner = inner.strip_prefix('[').unwrap_or(inner);
    let inner = inner.strip_suffix(']').unwrap_or(inner);
    let items = inner
        .split(',')
        .map(|s| s.trim().trim_matches(['"', '\'']).to_string())
        .filter(|s| !s.is_empty())
        .collect();
    Some(items)
}

#[cfg(test)]
mod tests {

    /// `core-ctx` duplicates this list because the reverse dependency edge would be a cycle.
    ///
    /// A duplicated security list is only safe while something notices it drifting. `core-agents`
    /// can see both, so the check lives here: every name this crate refuses must also be refused
    /// by the skill catalog, or a skill could declare a writer that an agent definition could not.
    #[test]
    fn the_skill_catalog_refuses_everything_this_crate_refuses() {
        for refused in WRITE_EXEC_DISPATCH {
            assert!(
                core_ctx::skills::SKILL_REFUSED_TOOLS
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case(refused)),
                "`{refused}` is refused for agent definitions but not for skills; the two lists \
                 have drifted and a skill could declare it"
            );
        }
    }
    use super::*;

    #[test]
    fn generic_names_the_complete_read_only_contract() {
        let g = AgentDef::generic();
        assert_eq!(g.name, "generic");
        assert_eq!(g.system, SUBAGENT_SYSTEM);
        assert!(
            g.system
                .starts_with("You are a read-only investigation subagent.")
        );
        for tool in READ_ONLY_TOOLS {
            assert!(
                g.system.contains(tool),
                "generic investigator prompt must advertise read-only tool `{tool}`"
            );
        }
        assert_eq!(g.trust, Trust::Trusted);
        assert_eq!(g.tools, ToolFilter::All);
        assert!(g.model.is_none());
        assert_eq!(g.budget.max_turns, 30);
    }

    #[test]
    fn direct_subagent_budget_is_writer_first_and_bounded() {
        // The writer keeps about half; a budget too small to leave a >=2-turn child bypasses the fan.
        assert!(subagent_budget(4, 300, None).is_none());
        assert!(subagent_budget(60, 2, None).is_none());
        assert!(subagent_budget(60, 300, Some(0)).is_none());
        assert!(subagent_budget(60, 300, Some(1)).is_none());

        let minimum =
            subagent_budget(6, 9, Some(100)).expect("two child turns remain after writer reserve");
        assert_eq!(minimum.max_turns, 2);
        assert_eq!(minimum.max_wall_secs, 3);
        assert_eq!(minimum.max_tokens, Some(50));

        let capped = subagent_budget(u32::MAX, u64::MAX, None)
            .expect("large inputs remain bounded without overflowing");
        assert_eq!(capped.max_turns, 30);
        assert_eq!(capped.max_usd, None);
        assert_eq!(capped.max_wall_secs, 300);
        assert_eq!(capped.max_consecutive_tool_errors, 3);
    }

    #[test]
    fn parses_frontmatter_and_body() {
        let text = "---\nname: mapper\ndescription: Maps the module graph.\nmodel: opus\n\
                    disallowedTools: [edit, bash]\n---\nYou map dependencies. Report edges only.\n";
        let def = parse_def("mapper.md", text, Trust::Workspace).unwrap();
        assert_eq!(def.name, "mapper");
        assert_eq!(def.description, "Maps the module graph.");
        assert_eq!(def.model.as_deref(), Some("opus"));
        assert_eq!(
            def.tools,
            ToolFilter::Deny(vec!["edit".into(), "bash".into()])
        );
        assert_eq!(def.system, "You map dependencies. Report edges only.");
        assert_eq!(def.trust, Trust::Workspace);
    }

    #[test]
    fn allow_list_naming_a_writer_is_a_load_error() {
        // The core narrowing invariant: `tools:` (an allowlist) may not grant a writer.
        let text =
            "---\nname: sneaky\ndescription: tries to write\ntools: [read_file, edit]\n---\nbody\n";
        let e = parse_def("sneaky.md", text, Trust::Workspace).unwrap_err();
        assert!(
            e.reason.contains("edit"),
            "reason should name the offending tool: {}",
            e.reason
        );
        assert!(
            e.reason.contains("NARROW"),
            "reason should cite the narrowing rule: {}",
            e.reason
        );

        // Same for bash and dispatch_agent, and case-insensitively for foreign casings.
        for bad in ["bash", "dispatch_agent", "Write", "Bash"] {
            let t = format!("---\nname: x\ndescription: d\ntools: [read_file, {bad}]\n---\nb\n");
            assert!(
                parse_def("x.md", &t, Trust::Workspace).is_err(),
                "must reject tools:[{bad}]"
            );
        }
    }

    #[test]
    fn deny_list_naming_a_writer_is_allowed() {
        // Denying a writer is redundant, not a grant — it must load.
        let text = "---\nname: ok\ndescription: d\ndisallowedTools: [edit, bash]\n---\nbody\n";
        assert!(parse_def("ok.md", text, Trust::Workspace).is_ok());
    }

    #[test]
    fn rejects_bidi_injection_and_missing_name() {
        let bidi = "---\nname: x\ndescription: d\n---\nnormal \u{202E}reversed\n";
        assert!(parse_def("x.md", bidi, Trust::Workspace).is_err());
        let no_name = "---\ndescription: d\n---\nbody\n";
        assert!(parse_def("x.md", no_name, Trust::Workspace).is_err());
        let no_fence = "name: x\ndescription: d\nbody\n";
        assert!(parse_def("x.md", no_fence, Trust::Workspace).is_err());
    }

    #[test]
    fn tool_filter_narrows_never_widens() {
        assert_eq!(
            ToolFilter::All.narrow(),
            vec![
                "read_file",
                "list_dir",
                "glob",
                "grep",
                "repo_map",
                "git_diff",
                "git_status",
                "git_log",
                "read_memory",
                "use_skill",
            ]
        );
        assert_eq!(
            ToolFilter::Allow(vec!["GLOB".into(), "git_status".into(), "use_skill".into()])
                .narrow(),
            vec!["glob", "git_status", "use_skill"]
        );
        // An Allow of a non-read-only tool cannot widen — it simply matches nothing here.
        assert!(ToolFilter::Allow(vec!["edit".into()]).narrow().is_empty());
        let denied = ToolFilter::Deny(vec!["grep".into(), "read_memory".into()]).narrow();
        assert!(!denied.contains(&"grep".to_string()));
        assert!(!denied.contains(&"read_memory".to_string()));
        assert!(denied.contains(&"read_file".to_string()));
        assert!(denied.contains(&"git_diff".to_string()));
    }
}
