# Configure a provider

Iteron resolves provider routing only from operator-controlled sources. A
cloned repository cannot redirect your model traffic or credential to a new host.

## Built-in providers

| Provider id | Wire adapter | Credential environment variable |
| --- | --- | --- |
| `glm` | OpenAI-compatible Chat | `GLM_API_KEY` |
| `anthropic` | Anthropic Messages | `ANTHROPIC_API_KEY` |
| `openai` | OpenAI Responses | `OPENAI_API_KEY` |
| `deepseek` | OpenAI-compatible Chat | `DEEPSEEK_API_KEY` |
| `minimax` | OpenAI-compatible Chat | `MINIMAX_API_KEY` |
| `fireworks` | OpenAI-compatible Chat | `FIREWORKS_API_KEY` |

The built-in default is `glm`. For its exact standard Chat endpoint, Iteron
ships a versioned static manifest whose documented default is `glm-5.2`. That
manifest proves endpoint schema compatibility, **not** that a particular account
is funded or entitled to every listed model. Without a credential, its leaves are
visible but unavailable.

The GLM schema/capability snapshots and Anthropic effort beta metadata are dated
world data. Core emits one preflight notice per selected provider showing the age
of every static snapshot used by that run and whether an operator replacement
changed its provider revision. See [static provider metadata](../reference/provider-metadata.md)
for the offline refresh path; no network response silently rewrites these claims.

## Select a built-in provider

For one run:

```sh
iteron --provider anthropic --model PROVIDER_MODEL_ID
```

Or set trusted user defaults in `~/.iteron/config.json`:

```json
{
  "schema_version": 2,
  "provider": "anthropic",
  "model": "PROVIDER_MODEL_ID"
}
```

Credential values stay in environment variables. Do not add them to JSON.

## Define a compatible provider instance

Operator-defined providers also live only in `~/.iteron/config.json`:

```json
{
  "schema_version": 2,
  "provider": "gateway",
  "providers": [
    {
      "id": "gateway",
      "display_name": "Internal compatible gateway",
      "adapter": "openai_chat",
      "error_profile": "custom",
      "api_root": "https://gateway.example.invalid/v1",
      "key_env": "GATEWAY_API_KEY",
      "enabled": true,
      "catalog": false,
      "models": ["declared-model-id"],
      "model_capabilities": {
        "declared-model-id": {
          "context_window_tokens": 1048576,
          "image_input": true
        }
      }
    }
  ]
}
```

`model_capabilities` is optional. Core has no portable way to discover a context window or image
support. Fireworks' typed `supportsImageInput` catalog field and Core's static vendor snapshots are
used when present; custom gateways can declare the exact model capability here. Without a window,
compaction falls back to the absolute
`compaction_trigger_tokens` instead of a share of the window, and the pre-flight admission check
cannot run. Declaring it is you stating a number you read in your provider's documentation; it is
not evidence of entitlement, and an official vendor snapshot for the same route still wins. See
the [configuration reference](../reference/configuration.md#model_capabilities) for the bounds.

The example domain is deliberately non-routable. Replace it with a trusted HTTPS
API root. Exact loopback hosts may use HTTP; other HTTP roots, embedded
credentials, queries, and fragments are rejected.

Supported adapters are `anthropic_messages`, `openai_responses`, and
`openai_chat`. A declared model list is an operator manifest, not account
discovery evidence.

## Project configuration cannot reroute traffic

A repository may place a bare `model` id in `.iteron/config.json`, but it remains
constrained to the independently selected provider. Repository values for
`provider`, `base_url`, `providers`, MCP processes, hooks, effort, or a grant of
code execution are ignored or rejected as appropriate.

See the [configuration reference](../reference/configuration.md) and
[provider matrix](../reference/providers.md) for the complete contract.
