# Slash commands

The typed TUI command registry drives both `/help` and completion. Every canonical
entry resolves to an exhaustive in-process handler or an explicit terminal-only
intercept (`/compact`); an added entry cannot silently fall through to the generic
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
| `/workflows` | Summarize the workflow cards already in this transcript |
| `/fork` | Branch the current session |
| `/rewind` | Branch the conversation from the current point |
| `/resume` | List sessions and show resume guidance |
| `/transcript [query]` | Open the fullscreen, bounded transcript search/view surface |
| `/export [path]` | Background-export Markdown without overwriting (Linux anonymous-inode publication; fail-closed elsewhere) |
| `/agents` | List discovered agent definitions |
| `/skills` | List discovered skills |
| `/tools` | List registered tools and capabilities |
| `/mcp` | List connected MCP tools |
| `/hooks` | Show user-configured lifecycle hooks |
| `/config` | Show resolved session and file configuration |
| `/theme` | Select a color theme with preview |
| `/init` | Scaffold repository `.core/config.json` and `AGENTS.md` |
| `/quit` | Leave the TUI |

Compatibility aliases resolve to the same typed command identity but are not
advertised by help or completion. The names above are the documented registry; use
`/help` in your installed build for its exact list.
