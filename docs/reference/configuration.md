# Configuration

Core Code uses strict JSON configuration. Unknown fields are rejected and each
file is limited to 1 MiB.

The current file schema is `schema_version: 2`. Configs written before the version field existed
are treated as v0; v1 configs are also migrated losslessly in memory. A config from a newer schema
is rejected with an upgrade-or-downgrade instruction before strict field decoding; Core never
guesses at future semantics.

## Locations and trust

| Location | Authority |
| --- | --- |
| `~/.core/config.json` | Operator-owned; may select providers, endpoints, signed rate cards, effort, MCP processes, hooks, and grants |
| `<repo>/.core/config.json` | Repository input; may select a bare model and tighten selected ceilings or grants, but cannot redirect provider traffic or spawn commands |

A repository config symlink is rejected. An operator may intentionally symlink
their own user config, but its contents are still bounded and strictly parsed.

## Top-level fields

| Field | Type | User config | Project config |
| --- | --- | --- | --- |
| `schema_version` | integer (`2`) | format discriminator | format discriminator |
| `model` | string | provider-qualified or bare default | bare id only, constrained to trusted provider |
| `provider` | string | provider instance default | ignored |
| `base_url` | string | trusted compatible endpoint | ignored |
| `max_turns` | positive integer | ceiling | may only tighten |
| `max_usd` | finite non-negative number | optional ceiling | may introduce or tighten |
| `max_wall_secs` | positive integer | default `1800` if absent | may only tighten |
| `allow_code` | boolean | may grant | `false` may tighten; `true` cannot grant |
| `effort` | string | allowed | ignored |
| `compaction_trigger_tokens` | positive integer | allowed | ignored |
| `retry` | object | operator-owned policy | parsed and ignored |
| `completion_notifications` | boolean | bounded run/approval/long-idle attention notifications; default `false` | parsed and ignored |
| `providers` | array | allowed, maximum 64 | ignored |
| `rate_cards` | array | allowed, maximum 256 | ignored |
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
  "schema_version": 2,
  "provider": "glm",
  "model": "glm-5.2",
  "max_turns": 40,
  "max_usd": 5.0,
  "max_wall_secs": 1800,
  "allow_code": false,
  "effort": "medium",
  "completion_notifications": false,
  "compaction_trigger_tokens": 120000,
  "retry": {
    "base_ms": 500,
    "cap_ms": 30000,
    "max_attempts": 6
  }
}
```

The example contains no credential. Provider keys are always indirect environment
references.

`completion_notifications` is a TUI-only, operator-owned preference. It defaults to `false` and,
when enabled, emits one bounded attention notification for a completed run, a new approval request,
or a 30-second quiet period during live work. A positively identified terminal may select fixed OSC
9 / OSC 777 desktop-notification bytes only through the same single writer that owns retained TUI
frames; ordinary or nonterminal stdout falls back to one BEL byte. Repository configuration cannot
enable or disable notifications, and streamed or untrusted text is never copied into terminal
control output.

`retry` contains only bounded numeric policy: `base_ms` is `1..=30000`, `cap_ms` is between
`base_ms` and `60000`, and `max_attempts` (including the initial request) is `1..=10`. Numeric
environment overrides use `CORE_RETRY_BASE_MS`, `CORE_RETRY_CAP_MS`, and
`CORE_RETRY_MAX_ATTEMPTS`, with environment taking precedence over user config. Repository retry
policy is always ignored because it can change paid-request timing and count.

!!! warning "Retry overrides are staged, not active"
    Core validates and resolves trusted retry policy, but does not yet install the transparent
    `RetryProvider` decorator in production. The kernel rejects opaque internal retries until each
    physical provider attempt can receive its own durable write-ahead intent. The CLI emits a
    warning when a trusted override is present; default production behavior remains one physical
    request per journaled attempt.

## Provider objects

Each user-defined provider requires:

- `id`: lowercase ASCII slug, at most 64 bytes;
- `adapter`: `anthropic_messages`, `openai_responses`, or `openai_chat`;
- `api_root`: HTTPS absolute root, except exact loopback HTTP;
- `key_env`: uppercase environment-variable name.

Optional fields are `display_name`, `error_profile`, `enabled`, `catalog`, and a
bounded `models` manifest. See [configure a provider](../getting-started/providers.md).

## Signed rate cards

`rate_cards` is an operator-owned manifest of immutable, pre-signed pricing artifacts. Each entry
contains:

- `version` (`"v1"`), `provider_id`, `model_id`, `catalog_digest`, and
  `capability_digest` for the exact selected route;
- `provenance`, `issued_at_unix_secs`, and `expires_at_unix_secs`;
- `rates`, with fixed-point micro-USD-per-million-token values for `input`, `output`,
  `cache_creation`, `cache_read`, and `thinking` classes;
- `signer_id`, `rate_card_digest`, and `signature` (`hmac-sha256:...`);
- `key_env`, the uppercase environment-variable name containing the corresponding 32-byte key as
  64 hexadecimal characters.

Plaintext key fields are rejected by the strict schema. Core reads only the named environment
variable, authenticates the artifact before opening a rollout, and injects an opaque pricing port;
the kernel never receives key bytes or fetches a price. The artifact's full route must match the
catalog and capability digests recorded by `ModelSelected`, and its half-open validity interval must
be active. A positive `max_usd` with no exact active verified card is refused before a provider
request. Repository `rate_cards` are warned about and ignored.

The signing format is the canonical `core_obs::sign_rate_card` v1 format so operator pricing tools
can produce the public artifact offline. Durable projections retain the card digest and signed
projection timestamp; authenticated replay therefore does not consult a current price catalog.

## Precedence

Provider and endpoint routing use only:

```text
CLI > environment > trusted user config > built-in
```

Turn and monetary budgets allow project values only as a monotone tightening of
trusted settings. Inspect the resolved state with `/config` and `/status`.
