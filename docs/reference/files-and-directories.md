# Files and directories

Core Code uses one product state-directory name: `.core`. It does not merge
historical product directories.

## Operator-owned state

| Path | Purpose |
| --- | --- |
| `~/.core/config.json` | Trusted user defaults, provider instances, signed rate cards, MCP servers, and hooks |
| `~/.core/history/*.json` | Scrubbed, bounded prompt history and the last text-only draft (`prompt_history`; never attachments) |
| `~/.core/provider-metadata.json` | Optional, strictly versioned replacement for dated built-in provider metadata |
| `~/.core/skills/<name>/SKILL.md` | Trusted operator skills |
| `~/.core/agents/*.md` | Trusted operator agent definitions |
| `~/.core/memory/` | Trusted operator memory |

These paths can grant process execution or routing authority where documented.
Protect them like other operator configuration.

## Repository-local state

| Path | Purpose |
| --- | --- |
| `<repo>/.core/config.json` | Untrusted project defaults and tighter ceilings |
| `<repo>/.core/runs/*.jsonl` | Hash-chained session records by default |
| `<repo>/.core/skills/<name>/SKILL.md` | Workspace-tier project skills |
| `<repo>/.core/agents/*.md` | Workspace-tier agent definitions |
| `<repo>/.core/memory/` | Project memory |
| `<repo>/.core/memory.local/` | Machine-local project memory surface |
| `<repo>/.core/instructions.md` | Repository instruction source |

Core Code also discovers `AGENTS.md` and `CLAUDE.md` as repository instruction
inputs. Their text is not operator authority and is framed with source trust.

## Repository hygiene

Do not commit real run records, user configuration, plaintext credentials, or
machine-local memory. A project may intentionally version reviewed project skills,
agent definitions, instructions, or safe config ceilings, but they remain
repository input and cannot grant themselves higher authority.
