# Configuration

Core Code uses strict JSON configuration. Unknown fields are rejected and each
file is limited to 1 MiB.

## Locations and trust

| Location | Authority |
| --- | --- |
| `~/.core/config.json` | Operator-owned; may select providers, endpoints, effort, MCP processes, hooks, and grants |
| `<repo>/.core/config.json` | Repository input; may select a bare model and tighten selected ceilings or grants, but cannot redirect provider traffic or spawn commands |

A repository config symlink is rejected. An operator may intentionally symlink
their own user config, but its contents are still bounded and strictly parsed.

## Top-level fields

| Field | Type | User config | Project config |
| --- | --- | --- | --- |
| `model` | string | provider-qualified or bare default | bare id only, constrained to trusted provider |
| `provider` | string | provider instance default | ignored |
| `base_url` | string | trusted compatible endpoint | ignored |
| `max_turns` | positive integer | ceiling | may only tighten |
| `max_usd` | finite non-negative number | optional ceiling | may introduce or tighten |
| `max_wall_secs` | positive integer | default `1800` if absent | may only tighten |
| `allow_code` | boolean | may grant | `false` may tighten; `true` cannot grant |
| `effort` | string | allowed | ignored |
| `compaction_trigger_tokens` | positive integer | allowed | ignored |
| `providers` | array | allowed, maximum 64 | ignored |
| `mcp_servers` | array | allowed | ignored |
| `hooks` | object of command arrays | allowed | ignored for execution |
| `egress_allow` | string array | schema field only | schema field only |

!!! warning "No active egress-allow contract"
    `egress_allow` is accepted by the current schema but is not wired to a public
    runtime configuration path. Do not rely on it to grant or prove network
    access. Code execution remains egress-off in the documented sandbox contract.

## Example user configuration

```json
{
  "provider": "glm",
  "model": "glm-5.2",
  "max_turns": 40,
  "max_usd": 5.0,
  "max_wall_secs": 1800,
  "allow_code": false,
  "effort": "medium",
  "compaction_trigger_tokens": 120000
}
```

The example contains no credential. Provider keys are always indirect environment
references.

## Provider objects

Each user-defined provider requires:

- `id`: lowercase ASCII slug, at most 64 bytes;
- `adapter`: `anthropic_messages`, `openai_responses`, or `openai_chat`;
- `api_root`: HTTPS absolute root, except exact loopback HTTP;
- `key_env`: uppercase environment-variable name.

Optional fields are `display_name`, `error_profile`, `enabled`, `catalog`, and a
bounded `models` manifest. See [configure a provider](../getting-started/providers.md).

## Precedence

Provider and endpoint routing use only:

```text
CLI > environment > trusted user config > built-in
```

Turn and monetary budgets allow project values only as a monotone tightening of
trusted settings. Inspect the resolved state with `/config` and `/status`.
