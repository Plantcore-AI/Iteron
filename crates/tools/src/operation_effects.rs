//! Host-owned operation classification. Model declarations never narrow authority.
//!
//! Shell is an interpreter: arbitrary programs, substitutions and scripts have unknown effects.
//! Only a small literal grammar is classified more narrowly. Unknown commands retain every
//! effect capability rather than silently inheriting the shell tool's code-execution class.

use iteron_protocol::{Capability, ToolUse, capability_set::CapabilitySet};
use serde::Serialize;

const MAX_COMMAND_BYTES: usize = 64 * 1024;
const MAX_TARGETS: usize = 64;
const MAX_TARGET_BYTES: usize = 2_048;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectKnowledge {
    Classified,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperationEffects {
    pub required: CapabilitySet,
    pub knowledge: EffectKnowledge,
    pub targets: Vec<String>,
    pub reason: &'static str,
}

impl OperationEffects {
    pub(crate) fn include_resolved_target(&mut self, target: &str) {
        if self.required.contains(Capability::ReversibleLocal) && is_trust_path(target) {
            self.required = CapabilitySet::from_iter_capabilities(
                self.required.iter().chain([Capability::TrustMutating]),
            );
        }
    }

    /// The registered capability is always retained, including code execution for literal
    /// observation commands. Classification is an additional constraint, never a replacement.
    pub fn classify(call: &ToolUse, registered: Capability) -> Self {
        if matches!(call.name.as_str(), "browser" | "computer")
            && registered == Capability::CodeExecuting
        {
            return Self {
                required: CapabilitySet::from_iter_capabilities([
                    Capability::CodeExecuting,
                    Capability::IrreversibleExternal,
                ]),
                knowledge: EffectKnowledge::Classified,
                targets: call
                    .input
                    .get("url")
                    .and_then(serde_json::Value::as_str)
                    .filter(|url| url.len() <= MAX_TARGET_BYTES)
                    .map(|url| vec![url.into()])
                    .unwrap_or_default(),
                reason: "browser commands may navigate, authenticate or publish; every action requires explicit external authority",
            };
        }
        if matches!(call.name.as_str(), "bash" | "process_start")
            && registered == Capability::CodeExecuting
        {
            return shell_effects(call);
        }
        if call.name == "process_write" && registered == Capability::CodeExecuting {
            return unknown_shell();
        }
        let mut capabilities = vec![registered];
        let mut targets = Vec::new();
        let complete = collect_paths(&call.input, &mut targets);
        if registered == Capability::ReversibleLocal
            && (!complete || targets.iter().any(|path| is_trust_path(path)))
        {
            capabilities.push(Capability::TrustMutating);
        }
        Self {
            required: CapabilitySet::from_iter_capabilities(capabilities),
            knowledge: if complete {
                EffectKnowledge::Classified
            } else {
                EffectKnowledge::Unknown
            },
            targets,
            reason: "registered operation and structured target paths",
        }
    }
}

pub fn is_trust_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.split(['/', '\\']).any(|part| {
        matches!(
            part,
            ".git"
                | ".gitattributes"
                | ".gitmodules"
                | ".gitconfig"
                | ".github"
                | ".iteron"
                | ".claude"
                | ".agents"
                | ".codex"
                | "agents.md"
                | "claude.md"
                | "skill.md"
                | ".mcp.json"
        )
    })
}

fn collect_paths(input: &serde_json::Value, paths: &mut Vec<String>) -> bool {
    let mut complete = true;
    if let Some(path) = input.get("path").and_then(serde_json::Value::as_str) {
        complete &= push_target(paths, path);
    }
    if let Some(files) = input.get("files").and_then(serde_json::Value::as_array) {
        complete &= files.len() <= MAX_TARGETS;
        for file in files.iter().take(MAX_TARGETS) {
            if let Some(path) = file.get("path").and_then(serde_json::Value::as_str) {
                complete &= push_target(paths, path);
            }
        }
    }
    complete
}

fn push_target(targets: &mut Vec<String>, value: &str) -> bool {
    if targets.len() < MAX_TARGETS && value.len() <= MAX_TARGET_BYTES {
        targets.push(value.to_owned());
        true
    } else {
        false
    }
}

fn unknown_shell() -> OperationEffects {
    OperationEffects {
        required: CapabilitySet::from_iter_capabilities([
            Capability::CodeExecuting,
            Capability::ReversibleLocal,
            Capability::TrustMutating,
            Capability::IrreversibleExternal,
        ]),
        knowledge: EffectKnowledge::Unknown,
        targets: Vec::new(),
        reason: "opaque shell execution may write files, mutate trust or affect external systems",
    }
}

fn shell_effects(call: &ToolUse) -> OperationEffects {
    let Some(command) = call
        .input
        .get("command")
        .and_then(serde_json::Value::as_str)
    else {
        return unknown_shell();
    };
    let Some(words) = literal_words(command) else {
        return unknown_shell();
    };
    let Some(program) = words.first().map(String::as_str) else {
        return unknown_shell();
    };
    // These shell builtins do not dispatch another program or select an arbitrary file. Even
    // they retain CodeExecuting: interpreter startup and the execution environment are separate
    // authority boundaries. printf -v only sets a shell-local variable.
    if cfg!(unix)
        && matches!(iteron_sandbox::confined_shell(), "/bin/bash" | "/bin/sh")
        && matches!(program, "printf" | "echo" | "pwd" | "true" | "false")
    {
        return OperationEffects {
            required: CapabilitySet::only(Capability::CodeExecuting),
            knowledge: EffectKnowledge::Classified,
            targets: Vec::new(),
            reason: "literal shell builtin without redirection, expansion or nested execution",
        };
    }
    // A remote command can additionally execute arbitrary local helpers (SSH ProxyCommand,
    // curl config, git hooks) or read a local script/config. Its external target is useful for
    // approval, but is not evidence that the other effects are absent.
    let mut result = unknown_shell();
    if matches!(program, "curl" | "wget" | "ssh" | "scp" | "sftp" | "rsync")
        || (program == "git"
            && words
                .get(1)
                .is_some_and(|word| matches!(word.as_str(), "push" | "fetch" | "pull" | "clone")))
    {
        result.reason =
            "remote operation with potentially effecting local helpers or configuration";
        for word in words.iter().skip(1).filter(|word| !word.starts_with('-')) {
            push_target(&mut result.targets, word);
        }
    }
    result
}

/// Parse only literal words. Rejecting a valid shell expression is conservative: it becomes
/// unknown, not a syntax rejection or a promise of read-only execution. Quotes and escaped
/// literals are supported, but shell expansion/control grammar never enters the narrow path.
fn literal_words(command: &str) -> Option<Vec<String>> {
    if command.len() > MAX_COMMAND_BYTES
        || command.chars().any(|c| {
            matches!(
                c,
                '$' | '`'
                    | ';'
                    | '&'
                    | '|'
                    | '<'
                    | '>'
                    | '('
                    | ')'
                    | '{'
                    | '}'
                    | '#'
                    | '*'
                    | '?'
                    | '['
                    | ']'
                    | '~'
            ) || (c.is_control() && c != '\t')
        })
    {
        return None;
    }
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escaped = false;
    let mut started = false;
    for c in command.chars() {
        if escaped {
            word.push(c);
            escaped = false;
            started = true;
        } else if c == '\\' && quote != Some('\'') {
            escaped = true;
            started = true;
        } else if let Some(delimiter) = quote {
            if c == delimiter {
                quote = None;
            } else {
                word.push(c);
            }
        } else if matches!(c, '\'' | '"') {
            quote = Some(c);
            started = true;
        } else if c.is_ascii_whitespace() {
            if started {
                words.push(std::mem::take(&mut word));
                started = false;
                if words.len() > MAX_TARGETS {
                    return None;
                }
            }
        } else {
            word.push(c);
            started = true;
        }
    }
    if escaped || quote.is_some() {
        return None;
    }
    if started {
        words.push(word);
    }
    (words.len() <= MAX_TARGETS).then_some(words)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn shell(command: &str) -> OperationEffects {
        OperationEffects::classify(
            &ToolUse {
                id: "call".into(),
                name: "bash".into(),
                input: json!({"command": command}),
            },
            Capability::CodeExecuting,
        )
    }

    #[test]
    fn compound_shell_and_model_write_declarations_never_narrow_unknown_effects() {
        for command in [
            "echo ok; git push",
            "printf $(curl https://example.invalid)",
            "echo ok > AGENTS.md",
            "python script.py",
            "git status",
            "printf 'unterminated",
            "env printf ok",
        ] {
            let effects = shell(command);
            assert_eq!(effects.knowledge, EffectKnowledge::Unknown, "{command}");
            assert!(effects.required.contains(Capability::CodeExecuting));
            assert!(effects.required.contains(Capability::TrustMutating));
            assert!(effects.required.contains(Capability::IrreversibleExternal));
        }
        let call = ToolUse {
            id: "call".into(),
            name: "bash".into(),
            input: json!({"command":"python script.py", "writes":[]}),
        };
        assert_eq!(
            OperationEffects::classify(&call, Capability::CodeExecuting),
            shell("python script.py")
        );
    }

    #[test]
    fn literal_observation_keeps_execution_authority_and_external_targets_are_visible() {
        let observation = shell("printf '%s' 'hello world'");
        assert_eq!(observation.knowledge, EffectKnowledge::Classified);
        assert_eq!(
            observation.required,
            CapabilitySet::only(Capability::CodeExecuting)
        );
        let external = shell("curl --request POST https://example.invalid/publish");
        assert!(external.required.contains(Capability::IrreversibleExternal));
        assert!(
            external
                .targets
                .contains(&"https://example.invalid/publish".to_owned())
        );
    }

    #[test]
    fn nested_patch_targets_keep_local_authority_and_add_trust_authority() {
        let call = ToolUse {
            id: "call".into(),
            name: "apply_patch".into(),
            input: json!({"files":[{"path":"src/main.rs"},{"path":"nested/AGENTS.md"}]}),
        };
        let effects = OperationEffects::classify(&call, Capability::ReversibleLocal);
        assert!(effects.required.contains(Capability::ReversibleLocal));
        assert!(effects.required.contains(Capability::TrustMutating));
        assert_eq!(effects.targets.len(), 2);
    }

    #[test]
    fn targets_beyond_classification_bounds_cannot_hide_trust_writes() {
        let mut files = vec![json!({"path":"src/main.rs"}); MAX_TARGETS];
        files.push(json!({"path":"AGENTS.md"}));
        for input in [
            json!({"files":files}),
            json!({"path":format!("{}/AGENTS.md", "x".repeat(MAX_TARGET_BYTES))}),
        ] {
            let effects = OperationEffects::classify(
                &ToolUse {
                    id: "call".into(),
                    name: "apply_patch".into(),
                    input,
                },
                Capability::ReversibleLocal,
            );
            assert_eq!(effects.knowledge, EffectKnowledge::Unknown);
            assert!(effects.required.contains(Capability::TrustMutating));
            assert!(effects.required.contains(Capability::ReversibleLocal));
            assert!(effects.targets.len() <= MAX_TARGETS);
        }
    }

    #[test]
    fn discovered_agent_skill_and_config_surfaces_are_trust_mutations() {
        for path in [
            ".agents/skills/example/SKILL.md",
            ".codex/config.toml",
            ".codex/skills/example/SKILL.md",
            ".mcp.json",
        ] {
            let effects = OperationEffects::classify(
                &ToolUse {
                    id: "call".into(),
                    name: "write_file".into(),
                    input: json!({"path":path}),
                },
                Capability::ReversibleLocal,
            );
            assert!(
                effects.required.contains(Capability::TrustMutating),
                "{path}"
            );
        }
    }

    #[test]
    fn process_launch_and_stdin_do_not_bypass_shell_effect_classification() {
        for (tool, input) in [
            ("process_start", json!({"command":"python untrusted.py"})),
            (
                "process_write",
                json!({"session_id":1,"chars":"git push\n"}),
            ),
        ] {
            let effects = OperationEffects::classify(
                &ToolUse {
                    id: "call".into(),
                    name: tool.into(),
                    input,
                },
                Capability::CodeExecuting,
            );
            assert_eq!(effects.knowledge, EffectKnowledge::Unknown);
            assert!(effects.required.contains(Capability::TrustMutating));
            assert!(effects.required.contains(Capability::IrreversibleExternal));
        }
    }
}
