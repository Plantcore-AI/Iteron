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

Fresh sessions first reuse a validated last-success route when one exists and no
operator route was supplied. Otherwise they prefer the built-in `openai` route
when it has a locally usable credential; if not, Iteron selects the first
locally credentialed provider. An explicit CLI, environment, or trusted user
route is not replaced.
No provider or model is assumed to be available to every account. For the
built-in OpenAI Responses route, Iteron prefers Codex v0.156.0's API-visible
model order only among models admitted by the live catalog; `gpt-6-astra` is
first when available. Other providers retain their documented or catalog
selection behavior. Explicit model choices remain authoritative.

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
