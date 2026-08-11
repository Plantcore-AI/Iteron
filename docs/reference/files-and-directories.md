# Files and directories

Iteron uses one product state-directory name: `.core`. It does not merge
historical product directories.

## Operator-owned state

| Path | Purpose |
| --- | --- |
| `~/.iteron/config.json` | Trusted user defaults, provider instances, signed rate cards, MCP servers, and hooks |
| `~/.iteron/history/*.json` | Scrubbed, bounded prompt history and the last text-only draft (`prompt_history`; never attachments) |
| `~/.iteron/provider-metadata.json` | Optional, strictly versioned replacement for dated built-in provider metadata |
| `~/.iteron/skills/<name>/SKILL.md` | Trusted operator skills |
| `~/.iteron/agents/*.md` | Trusted operator agent definitions (see [Executable agent definitions](agent-definitions.md)) |
| `~/.core/memory/` | Trusted operator memory |

These paths can grant process execution or routing authority where documented.
Protect them like other operator configuration.

## Repository-local state

| Path | Purpose |
| --- | --- |
| `<repo>/.iteron/config.json` | Untrusted project defaults and tighter ceilings |
| `<repo>/.iteron/runs/*.jsonl` | Hash-chained session records by default |
| `<repo>/.iteron/skills/<name>/SKILL.md` | Workspace-tier project skills |
| `<repo>/.iteron/agents/*.md` | Workspace-tier agent definitions |
| `<repo>/.core/memory/` | Project memory |
| `<repo>/.core/memory.local/` | Machine-local project memory surface |
| `<repo>/.iteron/instructions.md` | Repository instruction source |

Iteron also discovers `AGENTS.md` and `CLAUDE.md` as repository instruction
inputs. Their text is not operator authority and is framed with source trust.

## Repository hygiene

Do not commit real run records, user configuration, plaintext credentials, or
machine-local memory. A project may intentionally version reviewed project skills,
agent definitions, instructions, or safe config ceilings, but they remain
repository input and cannot grant themselves higher authority.
