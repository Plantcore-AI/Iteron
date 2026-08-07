//! `AgentDef` and `ToolFilter` — the interpreted agent definition the fan-out draws from, plus the
//! zero-dependency frontmatter parse and the "tools can only narrow the read-only set" load check.
//!
//! An agent definition mirrors Claude Code's `~/.claude/agents/<name>.md` (frontmatter + body), but
//! with the ADR-007 security treatment: the body is the subagent's *system* prompt; `tools` can only
//! **narrow** a fixed read-only registry (ADR-001, single writer); and a definition that names a
//! write/exec/dispatch tool is a **load error surfaced at catalog build**, never a silent grant.

use core_protocol::{Budget, Trust};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_AGENT_NAME_BYTES: usize = 128;
const MAX_AGENT_DESCRIPTION_BYTES: usize = 4 * 1024;
const MAX_AGENT_SYSTEM_BYTES: usize = 256 * 1024;
const MAX_AGENT_MODEL_BYTES: usize = 512;
const MAX_AGENT_TOOL_NAMES: usize = 128;
const MAX_AGENT_TOOL_NAME_BYTES: usize = 256;

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

/// Internal agent type used by the built-in Ultracode workflow's first, dynamic planning phase.
/// It is intentionally tool-less and one-turn: the model proposes investigation leaves, while the
/// harness still normalizes, narrows, and caps those leaves before the workflow may fan out.
pub const ULTRACODE_PLANNER_NAME: &str = "ultracode-planner";

const ULTRACODE_PLANNER_SYSTEM: &str = "You plan a READ-ONLY repository investigation. Return \
    mutually distinct, non-overlapping, self-contained assignments. Every line must name a \
    concrete search scope and the evidence expected from that worker. Cover different causal \
    surfaces rather than paraphrasing the task. Do not inspect the repository, propose edits, ask \
    questions, add a preamble, or add a conclusion. Output exactly one assignment per line.";

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

    /// The built-in dynamic-workflow planner. It is visible to the engine's pinned catalog but has
    /// no tools and exactly one provider turn, so planning cannot quietly become a second explorer.
    pub fn ultracode_planner() -> AgentDef {
        AgentDef {
            name: ULTRACODE_PLANNER_NAME.into(),
            description: "Internal one-turn planner for the built-in Ultracode workflow.".into(),
            system: ULTRACODE_PLANNER_SYSTEM.into(),
            tools: ToolFilter::Allow(Vec::new()),
            model: None,
            budget: Budget {
                max_turns: 1,
                max_usd: None,
                max_tokens: Some(4_096),
                max_wall_secs: 60,
                max_consecutive_tool_errors: 1,
            },
            trust: Trust::Trusted,
        }
    }

    /// Content identity for every execution-relevant field of this immutable definition.
    ///
    /// The tag is safe to persist: it contains no prompt or path bytes, and length framing avoids
    /// concatenation ambiguity. Description is intentionally excluded because changing catalog
    /// help text must not pretend to change the worker that ran.
    pub fn execution_digest(&self) -> String {
        let mut digest = Sha256::new();
        let tools =
            serde_json::to_vec(&self.tools).expect("ToolFilter serialization is infallible");
        let budget = serde_json::to_vec(&self.budget).expect("Budget serialization is infallible");
        let trust = serde_json::to_vec(&self.trust).expect("Trust serialization is infallible");
        for part in [
            self.name.as_bytes(),
            self.system.as_bytes(),
            tools.as_slice(),
            self.model.as_deref().unwrap_or("").as_bytes(),
            budget.as_slice(),
            trust.as_slice(),
        ] {
            digest.update((part.len() as u64).to_be_bytes());
            digest.update(part);
        }
        format!("sha256:{:x}", digest.finalize())
    }

    /// A bounded, secret-free session tag naming the exact worker semantics.
    pub fn execution_tag(&self) -> String {
        // A bare content-address shape is intentionally preserved by the record redactor; adding
        // a prose prefix makes the same high-entropy digest look like a credential and fail closed.
        self.execution_digest()
    }

    /// Refuse malformed programmatic definitions at the execution seam as well as at discovery.
    pub fn validate(&self) -> Result<(), String> {
        if !valid_agent_name(&self.name) {
            return Err(format!(
                "agent name must be 1..={MAX_AGENT_NAME_BYTES} ASCII bytes from [A-Za-z0-9_.-]"
            ));
        }
        if self.description.len() > MAX_AGENT_DESCRIPTION_BYTES {
            return Err(format!(
                "agent description exceeds {MAX_AGENT_DESCRIPTION_BYTES} bytes"
            ));
        }
        if self
            .description
            .chars()
            .any(|character| character.is_control())
        {
            return Err("agent description must be control-free".into());
        }
        if self.system.trim().is_empty() || self.system.len() > MAX_AGENT_SYSTEM_BYTES {
            return Err(format!(
                "agent system prompt must be non-blank and at most {MAX_AGENT_SYSTEM_BYTES} bytes"
            ));
        }
        if self
            .system
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        {
            return Err("agent system prompt contains a disallowed control character".into());
        }
        let tool_names = match &self.tools {
            ToolFilter::All => &[][..],
            ToolFilter::Allow(names) | ToolFilter::Deny(names) => names.as_slice(),
        };
        if tool_names.len() > MAX_AGENT_TOOL_NAMES {
            return Err(format!(
                "agent tool policy exceeds {MAX_AGENT_TOOL_NAMES} names"
            ));
        }
        let mut canonical_tool_names = std::collections::BTreeSet::new();
        for name in tool_names {
            let canonical = name.to_ascii_lowercase();
            if name.is_empty()
                || name.len() > MAX_AGENT_TOOL_NAME_BYTES
                || name.chars().any(char::is_control)
                || !canonical_tool_names.insert(canonical)
            {
                return Err(
                    "agent tool names must be unique, non-blank, control-free, and bounded".into(),
                );
            }
        }
        if let Some(model) = &self.model
            && (model.trim().is_empty()
                || model.len() > MAX_AGENT_MODEL_BYTES
                || model.chars().any(char::is_control))
        {
            return Err(format!(
                "agent model must be non-blank, control-free, and at most {MAX_AGENT_MODEL_BYTES} bytes"
            ));
        }
        self.budget
            .validate()
            .map_err(|reason| format!("invalid agent budget: {reason}"))?;
        let ceiling = subagent_budget_ceiling();
        if self.budget.max_turns > ceiling.max_turns
            || self.budget.max_wall_secs > ceiling.max_wall_secs
            || self.budget.max_consecutive_tool_errors > ceiling.max_consecutive_tool_errors
        {
            return Err("agent budget exceeds the built-in subagent ceiling".into());
        }
        Ok(())
    }
}

fn valid_agent_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_AGENT_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
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
    let (kv, body) = split_frontmatter(text).map_err(err)?;

    const KNOWN_KEYS: &[&str] = &[
        "name",
        "description",
        "model",
        "tools",
        "disallowedTools",
        "maxTurns",
        "maxUsd",
        "maxTokens",
        "maxWallSecs",
        "maxConsecutiveToolErrors",
    ];
    let mut seen = std::collections::BTreeSet::new();
    for (key, _) in &kv {
        if !KNOWN_KEYS.contains(&key.as_str()) {
            return Err(err(format!("unknown frontmatter key `{key}`")));
        }
        if !seen.insert(key.as_str()) {
            return Err(err(format!("duplicate frontmatter key `{key}`")));
        }
    }
    if seen.contains("tools") && seen.contains("disallowedTools") {
        return Err(err(
            "`tools` and `disallowedTools` are mutually exclusive narrowing policies".into(),
        ));
    }

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

    let ceiling = subagent_budget_ceiling();
    let budget = Budget {
        max_turns: parse_bounded_u32(&kv, "maxTurns", ceiling.max_turns, &err)?,
        max_usd: parse_optional_f64(&kv, "maxUsd", &err)?,
        max_tokens: parse_optional_u64(&kv, "maxTokens", &err)?,
        max_wall_secs: parse_bounded_u64(&kv, "maxWallSecs", ceiling.max_wall_secs, &err)?,
        max_consecutive_tool_errors: parse_bounded_u32(
            &kv,
            "maxConsecutiveToolErrors",
            ceiling.max_consecutive_tool_errors,
            &err,
        )?,
    };
    let def = AgentDef {
        name,
        description,
        system: body.trim().to_string(),
        tools,
        model,
        budget,
        trust,
    };
    def.validate().map_err(err)?;
    Ok(def)
}

fn parse_bounded_u32(
    kv: &[(String, String)],
    key: &str,
    default: u32,
    err: &impl Fn(String) -> super::LoadError,
) -> Result<u32, super::LoadError> {
    let Some(raw) = kv_get(kv, key) else {
        return Ok(default);
    };
    let value = raw
        .parse::<u32>()
        .map_err(|_| err(format!("`{key}` must be an unsigned integer")))?;
    if value > default {
        return Err(err(format!(
            "`{key}` exceeds the built-in ceiling {default}"
        )));
    }
    Ok(value)
}

fn parse_bounded_u64(
    kv: &[(String, String)],
    key: &str,
    default: u64,
    err: &impl Fn(String) -> super::LoadError,
) -> Result<u64, super::LoadError> {
    let Some(raw) = kv_get(kv, key) else {
        return Ok(default);
    };
    let value = raw
        .parse::<u64>()
        .map_err(|_| err(format!("`{key}` must be an unsigned integer")))?;
    if value > default {
        return Err(err(format!(
            "`{key}` exceeds the built-in ceiling {default}"
        )));
    }
    Ok(value)
}

fn parse_optional_u64(
    kv: &[(String, String)],
    key: &str,
    err: &impl Fn(String) -> super::LoadError,
) -> Result<Option<u64>, super::LoadError> {
    kv_get(kv, key)
        .map(|raw| {
            raw.parse::<u64>()
                .map_err(|_| err(format!("`{key}` must be an unsigned integer")))
        })
        .transpose()
}

fn parse_optional_f64(
    kv: &[(String, String)],
    key: &str,
    err: &impl Fn(String) -> super::LoadError,
) -> Result<Option<f64>, super::LoadError> {
    let value = kv_get(kv, key)
        .map(|raw| {
            raw.parse::<f64>()
                .map_err(|_| err(format!("`{key}` must be a finite non-negative number")))
        })
        .transpose()?;
    if value.is_some_and(|value| !value.is_finite() || value < 0.0) {
        return Err(err(format!("`{key}` must be a finite non-negative number")));
    }
    Ok(value)
}

/// Split `---`-fenced frontmatter from the body. Malformed fences/lines are explicit errors.
/// Comment lines (`# ...`) inside the frontmatter are skipped, matching the local agents'
/// inline-comment idiom.
fn split_frontmatter(text: &str) -> Result<(Vec<(String, String)>, String), String> {
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    while i < lines.len() && lines[i].trim().is_empty() {
        i += 1;
    }
    if i >= lines.len() || lines[i].trim() != "---" {
        return Err("missing `---` frontmatter fences".into());
    }
    let open = i;
    let close = ((open + 1)..lines.len())
        .find(|&j| lines[j].trim() == "---")
        .ok_or_else(|| "missing closing `---` frontmatter fence".to_string())?;

    let mut kv = Vec::new();
    for line in &lines[open + 1..close] {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let (key, value) = l
            .split_once(':')
            .ok_or_else(|| format!("malformed frontmatter line `{l}` (expected `key: value`)"))?;
        let key = key.trim();
        if key.is_empty() {
            return Err("frontmatter key cannot be blank".into());
        }
        kv.push((key.to_string(), value.trim().to_string()));
    }
    let body = lines[close + 1..].join("\n");
    Ok((kv, body))
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
    fn parses_only_narrowing_budgets_and_rejects_ambiguous_or_mistyped_policy() {
        let text = "---\nname: bounded\ndescription: d\ntools: [read_file]\n\
                    maxTurns: 4\nmaxUsd: 0.25\nmaxTokens: 99\nmaxWallSecs: 12\n\
                    maxConsecutiveToolErrors: 1\n---\nBounded worker.\n";
        let def = parse_def("bounded.md", text, Trust::Workspace).unwrap();
        assert_eq!(def.budget.max_turns, 4);
        assert_eq!(def.budget.max_usd, Some(0.25));
        assert_eq!(def.budget.max_tokens, Some(99));
        assert_eq!(def.budget.max_wall_secs, 12);
        assert_eq!(def.budget.max_consecutive_tool_errors, 1);

        for invalid in [
            "---\nname: x\nmaxTurns: 31\n---\nbody\n",
            "---\nname: x\nmaxUsd: NaN\n---\nbody\n",
            "---\nname: x\ntools: [read_file]\ndisallowedTools: [grep]\n---\nbody\n",
            "---\nname: x\nname: y\n---\nbody\n",
            "---\nname: x\nmaxTruns: 2\n---\nbody\n",
            "---\nname: x\nnot a field\n---\nbody\n",
            "---\nname: x\ntools: [read_file, READ_FILE]\n---\nbody\n",
            "---\nname: x\ndescription: terminal\u{1b}[31m\n---\nbody\n",
        ] {
            assert!(parse_def("invalid.md", invalid, Trust::Workspace).is_err());
        }
    }

    #[test]
    fn execution_digest_changes_only_with_execution_semantics() {
        let base = AgentDef::generic();
        let digest = base.execution_digest();
        assert!(digest.starts_with("sha256:"));
        assert_eq!(digest.len(), 71);
        assert_eq!(base.execution_tag(), digest);

        let mut help_only = base.clone();
        help_only.description.push_str(" clearer help");
        assert_eq!(help_only.execution_digest(), digest);

        for changed in [
            {
                let mut value = base.clone();
                value.system.push_str(" extra rule");
                value
            },
            {
                let mut value = base.clone();
                value.tools = ToolFilter::Allow(vec!["read_file".into()]);
                value
            },
            {
                let mut value = base.clone();
                value.budget.max_turns -= 1;
                value
            },
            {
                let mut value = base.clone();
                value.model = Some("same-provider-other-route".into());
                value
            },
        ] {
            assert_ne!(changed.execution_digest(), digest);
        }
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
