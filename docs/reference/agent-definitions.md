# Executable agent definitions

Core discovers agent definitions once when a run or standalone workflow starts. The accepted set
is immutable for that runtime. User definitions live in `~/.core/agents/*.md`; repository
definitions live under `.core/agents/*.md`. Definitions below dependency/vendor directories are
reported and stripped.

```markdown
---
name: reviewer
description: Reviews one bounded source area.
tools: [read_file, grep, git_diff]
model: inherit
maxTurns: 8
maxTokens: 12000
maxWallSecs: 90
maxConsecutiveToolErrors: 2
---
Review the assigned area. Report direct evidence with file and line references.
```

`name` and the body are required. Names are case-sensitive and use only ASCII letters, digits,
period, underscore, and hyphen. Unknown or duplicate frontmatter keys are errors. `tools` and
`disallowedTools` are mutually exclusive:

- `tools` retains only named tools from Core's built-in read-only registry.
- `disallowedTools` removes named tools from that registry.
- Omitting both keeps the complete read-only registry.

An agent definition cannot grant edit, process, shell, web-egress, workflow, or delegation tools.
Every child also receives a read-only capability ceiling, no executable lifecycle hooks, and no
permission bypass. The former special `agentType: "writer"` behavior is not supported.

The optional budget fields may only narrow the built-in child ceiling: at most 30 turns, 300 wall
seconds, and 3 consecutive tool errors. `maxTokens` and a finite non-negative `maxUsd` add further
ceilings. A nested USD ceiling that cannot be represented by the shared parent cost ledger is
refused rather than approximated.

`model: inherit` uses the parent's exact selected route. A different model is accepted only when
the spawner has separately resolved provider, capability, and pricing evidence for that route. The
current workflow spawner owns only the parent route and therefore refuses a different model instead
of reusing incorrect digests.

Workflow JavaScript selects a definition with `agent(prompt, {agentType: "reviewer"})`. An unknown
or differently-cased name resolves to `null` with a bounded refusal reason before a rollout or
provider effect is opened. Each admitted child records a SHA-256 content identity covering its
name, system prompt, tool filter, model policy, budget, and trust tier in session genesis.
