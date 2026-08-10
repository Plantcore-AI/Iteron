//! The typed slash-command registry, parser, and completion contract. One source of truth drives
//! `/help` and autocomplete; every registered command resolves to either the exhaustive in-process
//! dispatcher or an explicit terminal intercept. Pure + testable: no TTY, no I/O (the one question
//! that needs the filesystem — "is this leading `/` a dropped path?" — takes the probe as an
//! injected predicate).

use std::path::Path;

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
    Telemetry,
    Cost,
    Status,
    Budget,
    Model,
    Effort,
    Mode,
    Permissions,
    AllowCode,
    Diff,
    Memory,
    Sessions,
    Side,
    Workflows,
    Jobs,
    Fork,
    Rewind,
    Resume,
    Transcript,
    Export,
    Agents,
    Skills,
    Tools,
    Mcp,
    Hooks,
    Config,
    Tunables,
    Lab,
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
    /// A side conversation makes a provider call from a slash command, so it redraws a pending
    /// frame before awaiting the answer for exactly the same reason compaction does.
    Side,
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
            Self::Side => DispatchRoute::NotHere(TerminalIntercept::Side),
            Self::Help
            | Self::Clear
            | Self::Context
            | Self::Telemetry
            | Self::Cost
            | Self::Status
            | Self::Budget
            | Self::Model
            | Self::Effort
            | Self::Mode
            | Self::Permissions
            | Self::AllowCode
            | Self::Diff
            | Self::Memory
            | Self::Sessions
            | Self::Workflows
            | Self::Jobs
            | Self::Fork
            | Self::Rewind
            | Self::Resume
            | Self::Transcript
            | Self::Export
            | Self::Agents
            | Self::Skills
            | Self::Tools
            | Self::Mcp
            | Self::Hooks
            | Self::Config
            | Self::Tunables
            | Self::Lab
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
        args: "[stats|list|add|preview|delete]",
        help: "token usage and typed file/diff/IDE/LSP context chips",
    },
    Cmd {
        command: SlashCommand::Telemetry,
        name: "telemetry",
        args: "",
        help: "local lifecycle, Hook and exporter health (content-free)",
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
        command: SlashCommand::Budget,
        name: "budget",
        args: "[turns]",
        help: "show the turn ceiling; `/budget <turns>` raises it for this session",
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
        args: "[stat]",
        help: "review staged, unstaged, untracked, rename, binary, and conflict state",
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
        args: "[new|switch|preview|rename|pin|unpin|archive|unarchive|delete]",
        help: "browse and manage recorded sessions in this repo",
    },
    Cmd {
        command: SlashCommand::Side,
        name: "side",
        args: "[question|status|close]",
        help: "ask on the side: its own context, cost and record; nothing enters this transcript",
    },
    Cmd {
        command: SlashCommand::Workflows,
        name: "workflows",
        args: "",
        help: "show ultracode workflow and investigator progress",
    },
    Cmd {
        command: SlashCommand::Jobs,
        name: "jobs",
        args: "[list|attach|refresh|detach|write|eof|stop]",
        help: "inspect and control background process jobs",
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
        args: "[seq] [all|code|conversation] [keep|delete] [apply]",
        help: "preview or apply a checkpointed code/conversation rewind",
    },
    Cmd {
        command: SlashCommand::Resume,
        name: "resume",
        args: "[run-id]",
        help: "resume a prior session here (lists them)",
    },
    Cmd {
        command: SlashCommand::Transcript,
        name: "transcript",
        args: "[query]",
        help: "open the fullscreen searchable transcript viewer",
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
        args: "[status|restart|stop|cancel] [server]",
        help: "show and control session-owned MCP servers",
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
        command: SlashCommand::Tunables,
        name: "tunables",
        args: "[query|registry|load <file>]",
        help: "browse this run's 160 effective families (or an explicit registry/simulation)",
    },
    Cmd {
        command: SlashCommand::Lab,
        name: "lab",
        args: "[list|request <family> <json>|compare <bundle> <trusted-key>|promote]",
        help: "offline experiment requests and signed evidence comparison",
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

/// Is `name` — the word immediately after a leading `/` — a spelling this registry actually
/// serves? Canonical names and compatibility aliases both count; nothing else does.
pub fn is_registered(name: &str) -> bool {
    COMMANDS.iter().any(|candidate| candidate.name == name)
        || ALIASES.iter().any(|candidate| candidate.name == name)
}

/// The longest leading token worth treating as a dropped path. A terminal can paste an arbitrarily
/// long line; past this bound we stop reasoning about it as a filename (and never `stat` it).
const MAX_DROPPED_PATH_BYTES: usize = 4 * 1024;

/// Resolve a draft that begins with `/` into either a slash-command body or "not a command".
///
/// A file or folder dropped onto a Unix terminal arrives as bare text that begins with `/`, which
/// is exactly the shape of a slash command. Testing only for that leading byte handed every drop
/// to the command lane, so a dropped `.heic`, `.pdf`, folder, multi-file drop, or escaped path was
/// echoed as an unknown command — and the draft was thrown away with it.
///
/// The decision here is made on POSITIVE evidence of a path, never on a list of file types:
///
/// 1. a registered command or alias name always wins, so `/model` stays a command even on a
///    machine that happens to have a `/model` entry on disk;
/// 2. otherwise the leading token is a path when it has more than one segment (`/a/b` — no
///    registered name can contain a separator), when the terminal shell-escaped it
///    (`/Photos/My\ Trip.heic`), or when it names an entry that exists on this filesystem
///    (`/tmp`, a dropped folder).
///
/// Anything else stays a command. That is deliberate: a typo like `/helpp` has no path evidence,
/// so it still reaches the dispatcher and still earns "unknown command" instead of being silently
/// forwarded to the model.
///
/// `exists` is injected so this stays pure and table-testable; the TUI binds it to
/// `std::fs::symlink_metadata`.
pub fn slash_command_body<'a>(text: &'a str, exists: &dyn Fn(&Path) -> bool) -> Option<&'a str> {
    let text = text.trim_start();
    let body = text.strip_prefix('/')?;
    let name = body.split_whitespace().next().unwrap_or("");
    // A bare "/" names no path at all; keep its historical unknown-command answer.
    if name.is_empty() || is_registered(name) {
        return Some(body);
    }
    (!leading_token_is_path(text, exists)).then_some(body)
}

/// Positive path evidence for the first token of `text` (which starts with `/`).
fn leading_token_is_path(text: &str, exists: &dyn Fn(&Path) -> bool) -> bool {
    let raw = leading_shell_token(text);
    if raw.len() > MAX_DROPPED_PATH_BYTES {
        return false;
    }
    let decoded = unescape_shell_token(raw);
    // More than one segment: a registered name can never contain a separator.
    if decoded.trim_start_matches('/').contains('/') {
        return true;
    }
    // The terminal escaped a space or quote for us — that is drop syntax, not a command name.
    if decoded.len() != raw.len() {
        return true;
    }
    // Last, and the only branch that touches the filesystem: it names something real.
    !decoded.is_empty() && exists(Path::new(&decoded))
}

/// The first whitespace-delimited token, honouring the backslash escaping a terminal applies when
/// it drops a path containing spaces.
fn leading_shell_token(text: &str) -> &str {
    let mut escaped = false;
    for (offset, character) in text.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character.is_whitespace() {
            return &text[..offset];
        }
    }
    text
}

/// Undo terminal drop escaping. A trailing lone backslash is kept so the decoded length only
/// differs from the raw length when an escape was really consumed.
fn unescape_shell_token(token: &str) -> String {
    let mut decoded = String::with_capacity(token.len());
    let mut escaped = false;
    for character in token.chars() {
        if escaped {
            decoded.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else {
            decoded.push(character);
        }
    }
    if escaped {
        decoded.push('\\');
    }
    decoded
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

    /// A fake filesystem holding exactly what an operator might drag onto the terminal. Keeping the
    /// probe injected means the table below is hermetic: it asserts the RULE, not this machine.
    fn fake_filesystem() -> impl Fn(&Path) -> bool {
        let present: HashSet<&'static str> = HashSet::from([
            "/",
            "/tmp",
            "/Users/op/Pictures",
            "/Users/op/IMG_0042.heic",
            "/Users/op/notes.pdf",
            "/Users/op/My Trip.heic",
            "/model", // a real entry whose name collides with a registered command
        ]);
        move |path: &Path| path.to_str().is_some_and(|text| present.contains(text))
    }

    /// N-2: a dropped file, folder, or multi-file drop begins with `/` on Unix and was therefore
    /// dispatched as a slash command — the draft destroyed, the drop replaced by "unknown
    /// command". Each row below is a form that actually failed, or a control that must not change.
    #[test]
    fn dropped_paths_leave_the_command_lane_and_typos_stay_in_it() {
        let exists = fake_filesystem();
        let cases: &[(&str, bool, &str)] = &[
            // ---- the drops (a path, never a command) ----
            (
                "/Users/op/IMG_0042.heic",
                false,
                "the default macOS/iPhone photo format",
            ),
            ("/Users/op/IMG_0042.HEIC", false, "extension case"),
            ("/Users/op/notes.pdf", false, "pdf"),
            ("/Users/op/notes.txt", false, "txt"),
            ("/Users/op/logo.svg", false, "svg"),
            (
                "/Users/op/shot.png",
                false,
                "a supported image is still not a command",
            ),
            (
                "/Users/op/Pictures",
                false,
                "a dropped folder (multi-segment)",
            ),
            (
                "/tmp",
                false,
                "a single-segment folder, decided by the probe",
            ),
            (
                "/Users/op/a.png /Users/op/b.png",
                false,
                "two files dropped at once",
            ),
            (
                "/Users/op/a.png /Users/op/b.heic /Users/op/c.pdf",
                false,
                "three files dropped at once",
            ),
            (
                r"/Users/op/My\ Trip.heic",
                false,
                "the terminal escapes spaces when it drops",
            ),
            (
                r"/Users/op/My\ Trip.heic /Users/op/b.png",
                false,
                "escaped path plus a second file",
            ),
            ("/Users/op/shot.png\n", false, "a trailing newline"),
            ("   /Users/op/shot.png  ", false, "surrounding whitespace"),
            (
                "/Volumes/Backup/2026/report.pdf",
                false,
                "a path that need not exist to be a path",
            ),
            (
                "/Users/op/Pictures/",
                false,
                "a folder drop with a trailing separator",
            ),
            // ---- the controls (still a command) ----
            ("/help", true, "a canonical command"),
            ("/model gpt-5-codex", true, "a command with arguments"),
            ("/compact focus on the parser", true, "a terminal intercept"),
            ("/?", true, "the help alias"),
            ("/perms", true, "an alias"),
            ("/mem", true, "an alias"),
            ("/tasks", true, "an alias"),
            ("/allow_code", true, "an alias with an underscore"),
            ("/exit", true, "an alias"),
            ("  /status  ", true, "a command with surrounding whitespace"),
            (
                "/helpp",
                true,
                "a typo must still reach the unknown-command notice",
            ),
            ("/modle", true, "another typo"),
            ("/", true, "a bare slash names no path"),
            (
                "/help /Users/op/shot.png",
                true,
                "a path in the ARGUMENTS does not unmake the command",
            ),
            (
                "/model",
                true,
                "the registry outranks a filesystem entry of the same name",
            ),
        ];
        for (input, is_command, reason) in cases {
            assert_eq!(
                slash_command_body(input, &exists).is_some(),
                *is_command,
                "{reason}: {input:?} routed the wrong way"
            );
        }
    }

    /// The body handed to the dispatcher is unchanged for anything that IS a command.
    #[test]
    fn a_command_body_is_the_text_after_the_slash() {
        let exists = fake_filesystem();
        assert_eq!(
            slash_command_body("/model gpt-5-codex", &exists),
            Some("model gpt-5-codex")
        );
        assert_eq!(slash_command_body("  /help", &exists), Some("help"));
        assert_eq!(slash_command_body("/helpp", &exists), Some("helpp"));
        assert_eq!(slash_command_body("not a command", &exists), None);
        assert_eq!(slash_command_body("!cargo test", &exists), None);
    }

    /// Whatever the filesystem says, every advertised spelling stays dispatchable.
    #[test]
    fn no_registered_spelling_can_be_mistaken_for_a_drop() {
        let everything_exists = |_: &Path| true;
        for name in COMMANDS
            .iter()
            .map(|command| command.name)
            .chain(ALIASES.iter().map(|alias| alias.name))
        {
            let input = format!("/{name}");
            assert!(
                slash_command_body(&input, &everything_exists).is_some(),
                "/{name} stopped being a command"
            );
            assert!(
                parse(name).is_ok(),
                "/{name} is advertised but does not parse"
            );
        }
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

    /// The turn ceiling was unreachable from inside a session: no registered command could raise
    /// it, so a run that saturated `max_turns` could only be rescued by restarting the process.
    #[test]
    fn budget_command_carries_the_requested_turn_ceiling() {
        assert_eq!(
            parse("budget 200"),
            Ok(Invocation {
                command: SlashCommand::Budget,
                args: "200".into(),
            })
        );
        assert_eq!(
            parse("budget").map(|invocation| invocation.args),
            Ok(String::new()),
            "the bare form reports the ceiling instead of changing it"
        );
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
                DispatchRoute::NotHere(TerminalIntercept::Side) => {
                    assert_eq!(registered.command, SlashCommand::Side);
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
                DispatchRoute::InProcess(_)
                    | DispatchRoute::NotHere(TerminalIntercept::Compact | TerminalIntercept::Side)
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
