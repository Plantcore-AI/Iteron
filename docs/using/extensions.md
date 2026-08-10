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
  "schema_version": 2,
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

MCP servers load only from trusted user configuration. A local server uses supervised stdio:

```json
{
  "schema_version": 2,
  "mcp_servers": [
    {
      "name": "example",
      "command": "/absolute/path/to/operator-owned-server",
      "args": []
    }
  ]
}
```

A remote server uses Streamable HTTP. Plain HTTP is accepted only on loopback; non-loopback
servers must use HTTPS. Header and OAuth values are named by environment variable so credentials
never become printable configuration:

```json
{
  "schema_version": 2,
  "mcp_servers": [
    {
      "name": "remote-example",
      "transport": "http",
      "url": "https://mcp.example.com/mcp",
      "header_env": { "x-tenant": "CORE_MCP_TENANT" },
      "oauth": {
        "access_token_env": "CORE_MCP_ACCESS_TOKEN",
        "expires_at_env": "CORE_MCP_ACCESS_EXPIRES_AT",
        "refresh_url": "https://mcp.example.com/oauth/token",
        "refresh_token_env": "CORE_MCP_REFRESH_TOKEN",
        "revoke_url": "https://mcp.example.com/oauth/revoke",
        "client_id": "core-code",
        "client_secret_env": "CORE_MCP_CLIENT_SECRET"
      }
    }
  ]
}
```

Remote sessions negotiate current and compatible final MCP revisions, carry the negotiated version
and server session on later requests, stream bounded SSE, and refuse redirects or implicit effect
retries. Tools, resources, and prompts are available through the client API. Form elicitation is
advertised only by an interactive frontend that installs an operator decision handler; one-shot and
other noninteractive paths fail closed. OAuth refresh rotates the retained refresh token and
explicit revocation clears the active bearer credential.

Configured servers are session-owned and lazy: startup registers bounded proxy tools but does not
spawn a stdio process or contact an HTTP endpoint. The first search/resource/prompt request opens
the server under the session's pinned reconnect, deadline, and result-retention policy. Use `/mcp`
for live per-server phase/generation/catalog status, or `/mcp cancel|restart|stop <server>` to act on
that exact session owner. Restart clears the retained catalog and reconnects on the next request.

Discovered MCP tools are currently classified as `irreversible_external` because
they can reach external systems outside the local sandbox. Every call therefore
requires approval; `--allow-code` and `yolo` do not auto-approve it.

### Bounding one server's authority

`tools` filters exact bare names; `policy` bounds the capability classes the
server's tools may carry. They are not two spellings of the same control. A
filter can only name tools that already exist, so a server that publishes a new
tool after you configured it is admitted by an empty allow list. A policy binds
the server, including the tools it has not published yet.

```json
{
  "schema_version": 2,
  "mcp_servers": [
    {
      "name": "example",
      "command": "/absolute/path/to/operator-owned-server",
      "args": [],
      "tools": { "deny": ["delete_all"] },
      "policy": {
        "capabilities": ["irreversible_external"],
        "tools": { "risky_tool": [] }
      }
    }
  ]
}
```

Both `policy.capabilities` and each `policy.tools` entry are intersected with
what the host already allows, never unioned. Omitting `policy` inherits the host
ceiling unchanged; writing a wider set than the host permits does not widen
anything. A tool left with no admitted class is not exposed to the model at all
rather than exposed with a reduced one.

!!! note "Transport recovery"
    Stdio lifecycle recovery and bounded reconnect are supervised. HTTP requests carry effect
    certainty and never retry a possibly-applied tool call. SSE `Last-Event-ID` redelivery is not
    inferred without a server replay contract.
