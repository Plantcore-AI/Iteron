//! The typed slash-command registry, parser, and completion contract. One source of truth drives
//! `/help` and autocomplete; every registered command resolves to either the exhaustive in-process
//! dispatcher or an explicit terminal intercept. Pure + testable: no TTY, no I/O.

/// The canonical identity of every command advertised by the TUI.
///
/// The live dispatcher matches this enum exhaustively. Adding a registry entry therefore cannot
/// silently fall through a string wildcard: it must use an existing handler identity or add a new
/// variant and a corresponding dispatch arm.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SlashCommand {
    Help,
    Clear,
    Compact,
    Context,
    Cost,
    Status,
    Model,
    Effort,
    Mode,
    Permissions,
    AllowCode,
    Diff,
    Memory,
    Sessions,
    Workflows,
    Fork,
    Rewind,
    Resume,
    Export,
    Agents,
    Skills,
    Tools,
    Mcp,
    Hooks,
    Config,
    Login,
    Theme,
    Init,
    Quit,
}

/// A command execution path that is deliberately outside the ordinary in-process dispatcher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalIntercept {
    /// Compaction redraws before awaiting the kernel and therefore needs the live terminal handle.
    Compact,
}

/// The defined dispatch effect for a registered command in a headless/in-process harness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchRoute {
    /// The command has an arm in `handle_registered_command`.
    InProcess(SlashCommand),
    /// The command is recognized but needs an interactive terminal facility unavailable headlessly.
    NotHere(TerminalIntercept),
}

impl SlashCommand {
    /// Return the command's execution route. This match is intentionally exhaustive.
    pub const fn dispatch_route(self) -> DispatchRoute {
        match self {
            Self::Compact => DispatchRoute::NotHere(TerminalIntercept::Compact),
            Self::Help
            | Self::Clear
            | Self::Context
            | Self::Cost
            | Self::Status
            | Self::Model
            | Self::Effort
            | Self::Mode
            | Self::Permissions
            | Self::AllowCode
            | Self::Diff
            | Self::Memory
            | Self::Sessions
            | Self::Workflows
            | Self::Fork
            | Self::Rewind
            | Self::Resume
            | Self::Export
            | Self::Agents
            | Self::Skills
            | Self::Tools
            | Self::Mcp
            | Self::Hooks
            | Self::Config
            | Self::Login
            | Self::Theme
            | Self::Init
            | Self::Quit => DispatchRoute::InProcess(self),
        }
    }
}

/// One slash command's metadata.
pub struct Cmd {
    pub command: SlashCommand,
    pub name: &'static str,
    pub args: &'static str,
    pub help: &'static str,
}

/// Every slash command core's TUI supports. Help and completion consume these canonical spellings;
/// parsing resolves each entry to the typed identity matched by the live dispatcher.
pub const COMMANDS: &[Cmd] = &[
    Cmd {
        command: SlashCommand::Help,
        name: "help",
        args: "",
        help: "show this command list",
    },
    Cmd {
        command: SlashCommand::Clear,
        name: "clear",
        args: "",
        help: "clear the transcript (the run stays resumable)",
    },
    Cmd {
        command: SlashCommand::Compact,
        name: "compact",
        args: "[focus]",
        help: "summarize the transcript now (optional focus)",
    },
    Cmd {
        command: SlashCommand::Context,
        name: "context",
        args: "",
        help: "context token estimate + cache hit",
    },
    Cmd {
        command: SlashCommand::Cost,
        name: "cost",
        args: "",
        help: "spend + token usage so far",
    },
    Cmd {
        command: SlashCommand::Status,
        name: "status",
        args: "",
        help: "session status: model, effort, mode, cost, cwd, run id",
    },
    Cmd {
        command: SlashCommand::Model,
        name: "model",
        args: "[id|retry [id]]",
        help: "show, set, or explicitly retry one unavailable model",
    },
    Cmd {
        command: SlashCommand::Effort,
        name: "effort",
        args: "[level]",
        help: "low|medium|high|xhigh|max|ultracode",
    },
    Cmd {
        command: SlashCommand::Mode,
        name: "mode",
        args: "[m]",
        help: "permission mode: default|acceptEdits|plan|yolo (Shift+Tab cycles)",
    },
    Cmd {
        command: SlashCommand::Permissions,
        name: "permissions",
        args: "[allow|ask|deny <cap>]",
        help: "show / edit session permission rules",
    },
    Cmd {
        command: SlashCommand::AllowCode,
        name: "allow-code",
        args: "[on|off]",
        help: "allow sandboxed code execution (a /permissions shortcut)",
    },
    Cmd {
        command: SlashCommand::Diff,
        name: "diff",
        args: "",
        help: "show the working-tree diff (--stat)",
    },
    Cmd {
        command: SlashCommand::Memory,
        name: "memory",
        args: "add|list|forget",
        help: "remembered facts (add / list / forget)",
    },
    Cmd {
        command: SlashCommand::Sessions,
        name: "sessions",
        args: "",
        help: "list recorded sessions in this repo",
    },
    Cmd {
        command: SlashCommand::Workflows,
        name: "workflows",
        args: "",
        help: "show ultracode workflow and investigator progress",
    },
    Cmd {
        command: SlashCommand::Fork,
        name: "fork",
        args: "",
        help: "branch the current session (shared past, divergent future)",
    },
    Cmd {
        command: SlashCommand::Rewind,
        name: "rewind",
        args: "",
        help: "rewind: branch the conversation to redo from here",
    },
    Cmd {
        command: SlashCommand::Resume,
        name: "resume",
        args: "",
        help: "how to resume a prior session (lists them)",
    },
    Cmd {
        command: SlashCommand::Export,
        name: "export",
        args: "[path]",
        help: "write the transcript to a markdown file",
    },
    Cmd {
        command: SlashCommand::Agents,
        name: "agents",
        args: "",
        help: "list discovered agent definitions",
    },
    Cmd {
        command: SlashCommand::Skills,
        name: "skills",
        args: "",
        help: "list discovered skills (use_skill loads one)",
    },
    Cmd {
        command: SlashCommand::Tools,
        name: "tools",
        args: "",
        help: "list every tool the agent can use + its capability",
    },
    Cmd {
        command: SlashCommand::Mcp,
        name: "mcp",
        args: "",
        help: "list connected MCP tools",
    },
    Cmd {
        command: SlashCommand::Hooks,
        name: "hooks",
        args: "",
        help: "show loaded lifecycle hooks (user config)",
    },
    Cmd {
        command: SlashCommand::Config,
        name: "config",
        args: "",
        help: "show the resolved route + effective limits",
    },
    Cmd {
        command: SlashCommand::Login,
        name: "login",
        args: "",
        help: "check the current credential against the provider (setup runs in `core setup`)",
    },
    Cmd {
        command: SlashCommand::Theme,
        name: "theme",
        args: "",
        help: "pick a color theme (live preview)",
    },
    Cmd {
        command: SlashCommand::Init,
        name: "init",
        args: "",
        help: "scaffold .core/config.json + AGENTS.md",
    },
    Cmd {
        command: SlashCommand::Quit,
        name: "quit",
        args: "",
        help: "leave (or Esc / Ctrl-D)",
    },
];

/// A non-advertised spelling retained for compatibility. Aliases resolve to the same typed
/// identity as their canonical command and intentionally stay out of help and completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Alias {
    name: &'static str,
    command: SlashCommand,
}

const ALIASES: &[Alias] = &[
    Alias {
        name: "?",
        command: SlashCommand::Help,
    },
    Alias {
        name: "perms",
        command: SlashCommand::Permissions,
    },
    Alias {
        name: "allow_code",
        command: SlashCommand::AllowCode,
    },
    Alias {
        name: "mem",
        command: SlashCommand::Memory,
    },
    Alias {
        name: "tasks",
        command: SlashCommand::Workflows,
    },
    Alias {
        name: "exit",
        command: SlashCommand::Quit,
    },
];

/// One successfully parsed canonical command or alias.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invocation {
    pub command: SlashCommand,
    pub args: String,
}

/// A slash token that is not part of the typed registry or its explicit alias table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnknownCommand<'a> {
    pub name: &'a str,
}

/// Parse the command text after the leading slash into a typed invocation.
pub fn parse(input: &str) -> Result<Invocation, UnknownCommand<'_>> {
    let mut words = input.split_whitespace();
    let name = words.next().unwrap_or("");
    // Preserve the dispatcher's historical whitespace normalization for command arguments.
    let args = words.collect::<Vec<_>>().join(" ");
    let command = COMMANDS
        .iter()
        .find(|candidate| candidate.name == name)
        .map(|candidate| candidate.command)
        .or_else(|| {
            ALIASES
                .iter()
                .find(|candidate| candidate.name == name)
                .map(|candidate| candidate.command)
        })
        .ok_or(UnknownCommand { name })?;
    Ok(Invocation { command, args })
}

/// A typed invocation together with the execution effect selected by the pure router.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutedInvocation {
    pub invocation: Invocation,
    pub route: DispatchRoute,
}

/// Resolve one input through the same pure routing layer used by the live TUI. Unit tests invoke
/// this directly as a headless harness.
pub fn dispatch(input: &str) -> Result<RoutedInvocation, UnknownCommand<'_>> {
    parse(input).map(|invocation| RoutedInvocation {
        route: invocation.command.dispatch_route(),
        invocation,
    })
}

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
    use std::collections::HashSet;

    #[test]
    fn registry_is_nonempty_and_help_is_first() {
        assert_eq!(COMMANDS.first().map(|command| command.name), Some("help"));
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
        let mut names = HashSet::new();
        let mut commands = HashSet::new();
        for c in COMMANDS {
            assert!(!c.help.is_empty(), "{} needs help text", c.name);
            assert!(
                c.name
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch == '-'),
                "{} bad name",
                c.name
            );
            assert!(names.insert(c.name), "duplicate command name `{}`", c.name);
            assert!(
                commands.insert(c.command),
                "typed command {:?} is registered more than once",
                c.command
            );
        }
    }

    #[test]
    fn d10_17_g1_registry_to_dispatcher_contract_is_complete() {
        for registered in COMMANDS {
            let invocation = parse(registered.name)
                .unwrap_or_else(|_| panic!("registered /{} is unreachable", registered.name));
            assert_eq!(
                invocation.command, registered.command,
                "/{} resolves to the wrong typed handler",
                registered.name
            );
            match invocation.command.dispatch_route() {
                DispatchRoute::InProcess(command) => {
                    // `handle_registered_command` exhaustively matches `SlashCommand`, so this
                    // typed identity has a live arm and cannot reach the unknown-string branch.
                    assert_eq!(command, registered.command);
                }
                DispatchRoute::NotHere(TerminalIntercept::Compact) => {
                    assert_eq!(registered.command, SlashCommand::Compact);
                }
            }
        }
    }

    #[test]
    fn d10_17_g2_every_registered_name_has_a_defined_headless_outcome() {
        for registered in COMMANDS {
            let input = format!("{} headless-probe", registered.name);
            let outcome = dispatch(&input).unwrap_or_else(|unknown| {
                panic!(
                    "registered /{} fell through to unknown /{}",
                    registered.name, unknown.name
                )
            });
            assert!(matches!(
                outcome.route,
                DispatchRoute::InProcess(_) | DispatchRoute::NotHere(TerminalIntercept::Compact)
            ));
        }

        assert_eq!(
            dispatch("definitely-not-registered"),
            Err(UnknownCommand {
                name: "definitely-not-registered"
            }),
            "only genuinely unregistered names may use the unknown-command path"
        );
    }

    #[test]
    fn compatibility_aliases_resolve_without_entering_help_or_completion() {
        let expected = [
            ("?", SlashCommand::Help),
            ("perms", SlashCommand::Permissions),
            ("allow_code", SlashCommand::AllowCode),
            ("mem", SlashCommand::Memory),
            ("tasks", SlashCommand::Workflows),
            ("exit", SlashCommand::Quit),
        ];
        for (alias, command) in expected {
            assert_eq!(
                parse(alias).map(|invocation| invocation.command),
                Ok(command)
            );
            assert!(COMMANDS.iter().all(|registered| registered.name != alias));
            assert!(
                complete_slash(alias)
                    .iter()
                    .all(|registered| registered.name != alias),
                "aliases must never become advertised completion entries"
            );
        }
    }
}
