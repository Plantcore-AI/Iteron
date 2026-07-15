# Skills, hooks, and MCP

Core Code has initial extension surfaces with different trust and effect models.
They are not one interchangeable plugin API.

## Skills

A skill is a directory containing `SKILL.md`:

```text
<root>/.core/skills/<name>/SKILL.md
```

The file has `name` and `description` frontmatter plus an instruction body.
Core Code injects a bounded name/description index and loads a body on demand through
the `use_skill` tool.

- `~/.core/skills` is operator-owned and trusted.
- `<repo>/.core/skills` is workspace input, not authority.
- repository symlinks and skills under dependency/vendor paths are rejected or
  stripped.
- suspicious bidirectional or invisible Unicode is rejected.

Use `/skills` to inspect discovery.

## Lifecycle hooks

Hooks are arbitrary operator commands and therefore load **only** from
`~/.core/config.json`. Supported event keys are `SessionStart`,
`UserPromptSubmit`, `PreToolUse`, `PostToolUse`, and `Stop`.

```json
{
  "hooks": {
    "PreToolUse": ["/path/to/operator-owned-policy-check"]
  }
}
```

A `PreToolUse` hook blocks only with exit code `2`. Spawn failure, timeout, or any
other exit code is no opinion, so hooks are a best-effort tightening layer rather
than the load-bearing permission gate. Hooks run with operator authority and see
live JSON input; a logging hook can capture material that normal rollout
redaction would hide.

## MCP servers

MCP stdio servers also load only from trusted user configuration because
Core Code spawns their command at startup:

```json
{
  "mcp_servers": [
    {
      "name": "example",
      "command": "/absolute/path/to/operator-owned-server",
      "args": []
    }
  ]
}
```

Discovered MCP tools are currently classified as `irreversible_external` because
they can reach external systems outside the local sandbox. Every call therefore
requires approval; `--allow-code` and `yolo` do not auto-approve it.

!!! note "Current limit"
    Core Code implements an initial stdio client and tool registration path, not a
    complete production MCP lifecycle. Reconnect, broader transport support, and
    full interoperability evidence remain roadmap work.
