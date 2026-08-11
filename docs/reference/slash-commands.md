# Slash commands

The typed TUI command registry drives both `/help` and completion. Every canonical
entry resolves to an exhaustive in-process handler or an explicit terminal-only
intercept (`/compact`, `/side`); an added entry cannot silently fall through to the generic
unknown-command response. Commands with required arguments complete into the editor
rather than dispatching an incomplete operation.

| Command | Purpose |
| --- | --- |
| `/help` | Show the command list |
| `/clear` | Clear the visible transcript; the run remains resumable |
| `/compact [focus]` | Summarize the transcript now |
| `/context` | Context token estimate and cache state |
| `/cost` | Spend and token usage known so far |
| `/status` | Model, effort, mode, cost, directory, and run id |
| `/model [id\|retry [id]]` | Show, select, or retry a model |
| `/effort [level]` | Show or select effort |
| `/mode [mode]` | Show or select permission mode |
| `/permissions [allow\|ask\|deny cap]` | Show or edit session capability rules |
| `/allow-code [on\|off]` | Shortcut for the code-execution grant |
| `/diff` | Show the working-tree diff summary |
| `/memory add\|list\|forget` | Manage remembered facts |
| `/sessions` | List repository sessions |
| `/side [question\|status\|close]` | Ask on the side: a second conversation with its own context, cost and record |
| `/workflows` | Summarize the workflow cards already in this transcript |
| `/fork` | Branch the current session |
| `/rewind` | Branch the conversation from the current point |
| `/resume [run-id]` | Resume a recorded session in this terminal: the live session adopts that run's journal, transcript and identity |
| `/transcript [query]` | Open the fullscreen, bounded transcript search/view surface |
| `/export [path]` | Background-export Markdown without overwriting (Linux anonymous-inode publication; fail-closed elsewhere) |
| `/agents` | List the current run's immutable agent-definition snapshot |
| `/skills` | List discovered skills |
| `/tools` | List registered tools and capabilities |
| `/mcp [status\|restart\|stop\|cancel] [server]` | Show and control the session-owned lazy MCP servers |
| `/hooks` | Show user-configured lifecycle hooks |
| `/config` | Show resolved session and file configuration |
| `/tunables [query\|load <file>]` | Search all 160 canonical families, or inspect a workspace-relative frozen-request simulation |
| `/theme` | Select a color theme with preview |
| `/init` | Scaffold repository `.iteron/config.json` and `AGENTS.md` |
| `/quit` | Leave the TUI |

Compatibility aliases resolve to the same typed command identity but are not
advertised by help or completion. The names above are the documented registry; use
`/help` in your installed build for its exact list.

`/side` opens a second conversation beside the session. It is deliberately separate on
all three axes the session line reports:

- **Context** — its own message list. Nothing said in it enters the session transcript,
  nothing from the session is replayed into it, and the session's context estimate and
  compaction threshold do not move. It is a conversation, not a one-shot: a second
  `/side <question>` continues the first.
- **Record** — its own hash-chained journal under `<runs>/side/`. It is deliberately not
  written into the sessions directory, so it can never win the most-recent lookup that
  `--continue` resolves and never appears in `/sessions`. This also means it is not
  reachable by `iteron --resume`; the journal is on disk for audit, not for continuation.
- **Cost** — its own ledger, reported with the answer and by `/side status`. The session's
  cost line does not move because a side conversation ran.

What it deliberately shares: the provider handle and the durable route (so its spend is
priced by the same signed rate card), the workspace, the interrupt flag, and — when the
session has one — the shared USD ceiling. Money is money; a side conversation that could
spend past `--max-usd` by keeping its own books would be an accounting trick.

A side conversation gets read-only tools only and cannot delegate, run commands, edit
files, or open a side conversation of its own. It does not inherit the session's
transcript, so tell it the context it needs. `/side close` ends it and reports what it
cost; the next `/side <question>` starts a new one with a new record.

An ask is a foreground control request, exactly like `/compact`: the terminal waits for
the answer, and if a session turn is in flight the ask is applied at that turn's boundary
rather than racing it. The wait is bounded by the side conversation's own wall-clock and
turn ceilings, not by the session's.

`/tunables` is a read-only inspection surface. Its catalog mode shows registry
metadata, with requested/effective values explicitly marked as not resolved. The
Linux `load` accepts one explicit JSON request no larger than 1 MiB through retained,
no-follow workspace capabilities, resolves it with the provider-free resolver, and
displays only the resolver's bounded redacted value previews. Platforms without an
equivalent confined reader fail closed. Neither mode edits configuration, binds values
to the running process, authenticates evidence, trains a policy, or claims benchmark
improvement.
