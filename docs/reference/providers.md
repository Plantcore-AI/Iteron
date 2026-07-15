# Provider matrix

This matrix describes built-in routing and wire adapters in the current source.
It does not promise account entitlement, funding, or availability of every model
documented by a provider.

| Id | Adapter | Built-in API family | Credential | Catalog note |
| --- | --- | --- | --- | --- |
| `glm` | OpenAI-compatible Chat | GLM standard Chat Completions | `GLM_API_KEY` | Versioned static official schema manifest; no guessed list-models call |
| `anthropic` | Anthropic Messages | Anthropic v1 | `ANTHROPIC_API_KEY` | Availability depends on credential and endpoint behavior |
| `openai` | OpenAI Responses | OpenAI v1 | `OPENAI_API_KEY` | Uses the Responses adapter |
| `deepseek` | OpenAI-compatible Chat | DeepSeek v1 | `DEEPSEEK_API_KEY` | Provider-specific error profile |
| `minimax` | OpenAI-compatible Chat | MiniMax compatible root | `MINIMAX_API_KEY` | Provider-specific error profile |
| `fireworks` | OpenAI-compatible Chat | Fireworks inference v1 | `FIREWORKS_API_KEY` | Provider-specific error profile |

## Default selection

The built-in provider default is `glm`. Its exact standard root has a source-
versioned model enum whose documented default is `glm-5.2`. Core Code selects it
only when the provider entry is usable; missing credentials keep the leaves
disabled.

## Availability states

The selection UI distinguishes usable, unavailable, disabled, and unknown
evidence. In particular:

- schema or catalog presence is not account entitlement;
- a private deployment without a healthy default is not guessed;
- a compatible gateway without a model-list endpoint needs an operator manifest
  or explicit model;
- provider errors can update account or model health;
- a grey entry is intentionally not selectable.

## Capability evidence

Reasoning effort, context limits, caching, and other model capabilities are
attached only where the exact endpoint/model evidence supports them. A family
neighbor does not inherit the limits documented for another model.

The catalog implementation is evolving. Use `/model` and `/status` as the runtime
view, and report stale or contradictory provider evidence with a synthetic
reproduction.
