//! The slash-command registry + completion logic (R6 SOTA UX). One source of truth drives `/help`,
//! the autocomplete menu, and (by exhaustive match in the dispatcher) the fact that every listed
//! command is handled. Pure + testable: no TTY, no I/O.

/// One slash command's metadata.
pub struct Cmd {
    pub name: &'static str,
    pub args: &'static str,
    pub help: &'static str,
}

/// Every slash command core's TUI supports. Alphabetical-ish by theme; the dispatcher matches
/// each `name` (plus a few aliases handled there). Keep this in sync with `handle_command`.
pub const COMMANDS: &[Cmd] = &[
    Cmd {
        name: "help",
        args: "",
        help: "show this command list",
    },
    Cmd {
        name: "clear",
        args: "",
        help: "clear the transcript (the run stays resumable)",
    },
    Cmd {
        name: "compact",
        args: "[focus]",
        help: "summarize the transcript now (optional focus)",
    },
    Cmd {
        name: "context",
        args: "",
        help: "context token estimate + cache hit",
    },
    Cmd {
        name: "cost",
        args: "",
        help: "spend + token usage so far",
    },
    Cmd {
        name: "status",
        args: "",
        help: "session status: model, effort, mode, cost, cwd, run id",
    },
    Cmd {
        name: "model",
        args: "[id|retry [id]]",
        help: "show, set, or explicitly retry one unavailable model",
    },
    Cmd {
        name: "effort",
        args: "[level]",
        help: "low|medium|high|xhigh|max|ultracode",
    },
    Cmd {
        name: "mode",
        args: "[m]",
        help: "permission mode: default|acceptEdits|plan|yolo (Shift+Tab cycles)",
    },
    Cmd {
        name: "permissions",
        args: "[allow|ask|deny <cap>]",
        help: "show / edit session permission rules",
    },
    Cmd {
        name: "allow-code",
        args: "[on|off]",
        help: "allow sandboxed code execution (a /permissions shortcut)",
    },
    Cmd {
        name: "diff",
        args: "",
        help: "show the working-tree diff (--stat)",
    },
    Cmd {
        name: "memory",
        args: "add|list|forget",
        help: "remembered facts (add / list / forget)",
    },
    Cmd {
        name: "sessions",
        args: "",
        help: "list recorded sessions in this repo",
    },
    Cmd {
        name: "workflows",
        args: "",
        help: "show ultracode workflow and investigator progress",
    },
    Cmd {
        name: "fork",
        args: "",
        help: "branch the current session (shared past, divergent future)",
    },
    Cmd {
        name: "rewind",
        args: "",
        help: "rewind: branch the conversation to redo from here",
    },
    Cmd {
        name: "resume",
        args: "",
        help: "how to resume a prior session (lists them)",
    },
    Cmd {
        name: "export",
        args: "[path]",
        help: "write the transcript to a markdown file",
    },
    Cmd {
        name: "agents",
        args: "",
        help: "list discovered agent definitions",
    },
    Cmd {
        name: "skills",
        args: "",
        help: "list discovered skills (use_skill loads one)",
    },
    Cmd {
        name: "tools",
        args: "",
        help: "list every tool the agent can use + its capability",
    },
    Cmd {
        name: "mcp",
        args: "",
        help: "list connected MCP tools",
    },
    Cmd {
        name: "hooks",
        args: "",
        help: "show loaded lifecycle hooks (user config)",
    },
    Cmd {
        name: "config",
        args: "",
        help: "show session + file config",
    },
    Cmd {
        name: "theme",
        args: "",
        help: "pick a color theme (live preview)",
    },
    Cmd {
        name: "init",
        args: "",
        help: "scaffold .core/config.json + AGENTS.md",
    },
    Cmd {
        name: "quit",
        args: "",
        help: "leave (or Esc / Ctrl-D)",
    },
];

/// Commands whose name starts with `prefix` (the text after the leading '/'), for autocomplete.
/// An exact match sorts first; otherwise alphabetical by name. Case-insensitive.
pub fn complete_slash(prefix: &str) -> Vec<&'static Cmd> {
    let p = prefix.to_ascii_lowercase();
    let mut v: Vec<&'static Cmd> = COMMANDS.iter().filter(|c| c.name.starts_with(&p)).collect();
    v.sort_by(|a, b| {
        let ae = (a.name != p) as u8;
        let be = (b.name != p) as u8;
        ae.cmp(&be).then_with(|| a.name.cmp(b.name))
    });
    v
}

/// If `input` (a single-line buffer, idle) is a slash-command being typed — starts with '/', has no
/// space yet — return the prefix (text after '/'). `None` means "no slash-completion here".
pub fn slash_prefix(input: &str) -> Option<&str> {
    let rest = input.strip_prefix('/')?;
    if rest.contains(char::is_whitespace) {
        return None; // already past the command name -> typing args, no menu
    }
    Some(rest)
}

/// Extract the `@`-mention token immediately before `cursor` (a byte index into `input`), if the
/// cursor is inside an `@path` token. Returns (token_start_byte, partial_path). For file completion.
pub fn at_mention_at(input: &str, cursor: usize) -> Option<(usize, &str)> {
    let cursor = cursor.min(input.len());
    let before = &input[..cursor];
    // find the last '@' not preceded by a non-space (so "a@b" is not a mention, " @b" is)
    let at = before.rfind('@')?;
    // the char before '@' must be start-of-line or whitespace
    if at > 0 {
        let prev = before[..at].chars().next_back().unwrap_or(' ');
        if !prev.is_whitespace() {
            return None;
        }
    }
    let token = &before[at + 1..];
    if token.contains(char::is_whitespace) {
        return None; // the mention already ended
    }
    Some((at, token))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_nonempty_and_help_is_first() {
        assert!(!COMMANDS.is_empty());
        assert_eq!(COMMANDS[0].name, "help");
    }

    #[test]
    fn complete_slash_filters_and_orders() {
        let m = complete_slash("co");
        let names: Vec<_> = m.iter().map(|c| c.name).collect();
        assert!(
            names.contains(&"compact")
                && names.contains(&"context")
                && names.contains(&"cost")
                && names.contains(&"config")
        );
        assert!(!names.contains(&"help"));
        // exact match sorts first
        let m2 = complete_slash("mode");
        assert_eq!(m2[0].name, "mode");
    }

    #[test]
    fn slash_prefix_detects_command_typing() {
        assert_eq!(slash_prefix("/mod"), Some("mod"));
        assert_eq!(slash_prefix("/"), Some(""));
        assert_eq!(slash_prefix("/mode plan"), None); // past the name
        assert_eq!(slash_prefix("hello"), None);
        assert_eq!(slash_prefix("/effort "), None);
    }

    #[test]
    fn at_mention_detection() {
        assert_eq!(at_mention_at("look at @src/li", 15), Some((8, "src/li")));
        assert_eq!(at_mention_at("@main", 5), Some((0, "main")));
        assert_eq!(at_mention_at("email a@b.com", 13), None); // '@' not after whitespace
        assert_eq!(at_mention_at("done @ now", 10), None); // token ended by space
        assert_eq!(at_mention_at("no mention", 5), None);
    }

    #[test]
    fn every_command_has_help() {
        for c in COMMANDS {
            assert!(!c.help.is_empty(), "{} needs help text", c.name);
            assert!(
                c.name
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch == '-'),
                "{} bad name",
                c.name
            );
        }
    }
}
