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

## Ark Chat continuation

For explicitly configured Chat routes at these exact API roots, Iteron retains
returned `reasoning_content` and `encrypted_content` in private continuation
state:

- `https://ark.cn-beijing.volces.com/api/v3`
- `https://ark.cn-beijing.volces.com/api/plan/v3`
- `https://ark.cn-beijing.volces.com/api/coding/v3`

Ark documents that some models return a thinking summary and encrypted original
thinking by default. The encrypted field can arrive in a separate stream chunk.
It must be returned intact during tool continuation; a successful response alone
does not establish correct continuation, because omission may silently reduce
quality. When both fields are supplied, Ark gives the encrypted original
precedence. See [Ark deep thinking](https://docs.volcengine.com/docs/ark/deep-thinking?lang=en)
and [integration FAQ](https://docs.volcengine.com/docs/ark/go-live-faq?lang=zh).

The adapter retains the complete encrypted value without interpreting it;
identical repeats are idempotent and conflicting values are rejected. Plaintext
reasoning deltas are concatenated. This follows the [Chat stream schema](https://docs.volcengine.com/docs/ark/chat-api?lang=zh&redirect=1).
Both fields are stored as `ark.chat.thinking.v1`. The state survives transcript serialization
and is replayed only for the same provider instance, exact API root and model
identifier. Reusing the same instance with another supported Ark endpoint or a different
model rejects matching continuation state before dispatch. Other instances and unknown state
versions remain opaque. Portable thinking display blocks cannot reconstruct
missing continuation state from an older transcript.
Legacy generic Chat reasoning state lacks endpoint/model binding; on the same
Ark instance it is rejected before dispatch and requires a fresh session.

Encrypted state is excluded from text/thinking stream deltas and debug output.
It remains present in the private durable transcript and prepared request, which
must be treated as sensitive. State is bounded by the existing reasoning payload
limit (at most 4 MiB encoded) and stream/output limits; malformed or oversized
state fails without reflecting its contents. Cancellation does not publish a
completed state or automatically replay the interrupted request.

This protocol support does not add a built-in Ark account, discover entitlement,
or infer model capabilities from names. Custom routes do not gain a guaranteed
reasoning effort setting: `low` or another requested effort is applied only when
the exact route/model capability evidence permits it. API roots and credentials
for standard usage, Agent Plan and Coding Plan are separate; configure the route
that belongs to the account. See [Ark route configuration](https://docs.volcengine.com/docs/ark/integrate-third-party-tools?lang=zh).
