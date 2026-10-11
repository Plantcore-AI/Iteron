# Skills, hooks, and MCP

Iteron has initial extension surfaces with different trust and effect models.
They are not one interchangeable plugin API.

## Skills

A skill is a directory containing `SKILL.md`:

```text
<root>/.iteron/skills/<name>/SKILL.md
```

The file has `name` and `description` frontmatter plus an instruction body.
Iteron injects a bounded name/description index and loads a body on demand through
the `use_skill` tool.

- `~/.iteron/skills` is operator-owned and trusted.
- `<repo>/.iteron/skills` is workspace input, not authority.
- repository symlinks and skills under dependency/vendor paths are rejected or
  stripped.
- suspicious bidirectional or invisible Unicode is rejected.

Use `/skills` to inspect discovery. Same-name sources keep the declared source
precedence and emit a captured conflict diagnostic; a project skill cannot
silently replace an operator skill. Effective Skills inventory includes a paged
diagnostic sidecar with source-path digests, without exposing native paths.

## Lifecycle hooks

Hooks are arbitrary operator commands. User hooks come from the operator's captured
`~/.iteron/config.json`; project configuration cannot install executable hooks.
An explicitly enabled, signature-verified plugin may contribute hooks only after
its requested capabilities are intersected with the host ceiling. Compatibility
event keys are `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`,
and `Stop`. Plugins can also bind registered canonical lifecycle events.

```json
{
  "schema_version": 2,
  "hooks": {
    "PreToolUse": ["/path/to/operator-owned-policy-check"]
  }
}
```

`PreToolUse` is an admission gate. Every configured handler must return a terminal
allow decision: exit `0` allows; exit `2`, another failed exit, spawn failure,
timeout or cancellation denies the action. Other compatibility events are advisory.
Canonical events have the registry's fixed `observe`, `augment` or `gate` class;
only a gate can deny admission. Augment output must pass the bounded payload
schema and cannot grant tools, permissions or budget.

The actual hook owner bounds deadlines and process concurrency, then applies
outcomes in configured order. Cancellation retains physical cleanup ownership.
Unmatched durable hook intents remain unknown after a crash; an inventory read
never authorizes command replay. Hooks use a credential-sanitized helper
environment but see live JSON input; a logging hook can capture material that
normal rollout redaction would hide. Arbitrary trusted commands may have their
own external effects, which the hook driver does not account as zero.

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
      "header_env": { "x-tenant": "ITERON_MCP_TENANT" },
      "oauth": {
        "access_token_env": "ITERON_MCP_ACCESS_TOKEN",
        "expires_at_env": "ITERON_MCP_ACCESS_EXPIRES_AT",
        "refresh_url": "https://mcp.example.com/oauth/token",
        "refresh_token_env": "ITERON_MCP_REFRESH_TOKEN",
        "revoke_url": "https://mcp.example.com/oauth/revoke",
        "client_id": "iteron",
        "client_secret_env": "ITERON_MCP_CLIENT_SECRET"
      }
    }
  ]
}
```

Remote sessions negotiate current and compatible final MCP revisions, carry the negotiated version
and server session on later requests, stream bounded SSE, and refuse redirects or implicit effect
retries. Tools, resources, and prompts are available through the client API. Form elicitation is
advertised only by an interactive frontend that installs an operator decision handler; one-shot and
other noninteractive paths fail closed. The 2026 multi-round `input_required` flow is limited to
`tools/call`; resource and prompt extensions neither advertise that request capability nor treat an
`input_required` result as success. The form handler accepts only its documented basic-schema
subset and rejects unsupported validation keywords before collecting input. OAuth refresh rotates
the retained refresh token and explicit revocation clears the active bearer credential.

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

## Effective extension inventory

Compatible clients can read the installed `Plugins`, `Hooks` and `Skills` kinds
through the public client inventory controls. These are captured facts from the
existing package, executable-hook and context owners; inspection does not scan
package trees, load skill bodies or run callbacks.

Package records show verified source, version, declared scope, operator precedence,
requested capabilities and the actual composed binding capabilities. Those
capabilities do not replace later operation, task, permission or budget checks.
Hook records show source class, event, private-command digest, admission class,
deadline and failure/order/recovery policy. The digest joins a verified package's
hook binding without exposing its command text. Skill records retain captured
source/version, trust, path selection and declared tool narrowing; a prefix
commitment is labeled as a prefix and does not prove a complete lazy body.

Prompt tokens and model requests are not attributed per package, skill or arbitrary
hook command. The inventory reports these as unavailable, with bounded observed
metadata sizes where captured. Consult the actual provider/tool ledgers for their
accounting scope; unavailable costs are not zero.
