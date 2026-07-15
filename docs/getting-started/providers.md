# Configure a provider

Core Code resolves provider routing only from operator-controlled sources. A
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

The built-in default is `glm`. For its exact standard Chat endpoint, Core Code
ships a versioned static manifest whose documented default is `glm-5.2`. That
manifest proves endpoint schema compatibility, **not** that a particular account
is funded or entitled to every listed model. Without a credential, its leaves are
visible but unavailable.

## Select a built-in provider

For one run:

```sh
core --provider anthropic --model PROVIDER_MODEL_ID
```

Or set trusted user defaults in `~/.core/config.json`:

```json
{
  "provider": "anthropic",
  "model": "PROVIDER_MODEL_ID"
}
```

Credential values stay in environment variables. Do not add them to JSON.

## Define a compatible provider instance

Operator-defined providers also live only in `~/.core/config.json`:

```json
{
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
      "models": ["declared-model-id"]
    }
  ]
}
```

The example domain is deliberately non-routable. Replace it with a trusted HTTPS
API root. Exact loopback hosts may use HTTP; other HTTP roots, embedded
credentials, queries, and fragments are rejected.

Supported adapters are `anthropic_messages`, `openai_responses`, and
`openai_chat`. A declared model list is an operator manifest, not account
discovery evidence.

## Project configuration cannot reroute traffic

A repository may place a bare `model` id in `.core/config.json`, but it remains
constrained to the independently selected provider. Repository values for
`provider`, `base_url`, `providers`, MCP processes, hooks, effort, or a grant of
code execution are ignored or rejected as appropriate.

See the [configuration reference](../reference/configuration.md) and
[provider matrix](../reference/providers.md) for the complete contract.
