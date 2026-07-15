# Context, usage, and cost

Context-window, cache, token, and monetary numbers have different evidence
sources. Core Code attempts to expose what it knows without turning an estimate
into an exact claim.

## Context construction

The current context layer can combine bounded repository instructions, memory,
skill listings, source outlines, transcript history, and compaction output. Each
source carries a trust tier, and discovery has byte or entry ceilings.

Compaction is a lossy summary operation triggered by configured context pressure
or `/compact`. It helps bound a run; it is not a cryptographic or semantic proof
that every earlier detail remains represented.

## Token and cache state

Provider usage fields are preferred when the adapter exposes them. A local token
estimate may be useful for display or compaction policy, but it is not the same as
the provider's authoritative billed input or cache accounting.

`/context` exposes the current estimate and cache state available to the session.
Its precision depends on the route and event evidence.

## Monetary state

Core Code's cost state can be known or unknown. It does not infer a dollar amount
from token counts when there is no trusted price source for the exact provider,
model, and route. `max_usd` therefore cannot be described as a universal billing
guarantee across every compatible endpoint.

Machine output carries `cost_usd`, `cost_status`, and `cost_reason` so callers can
distinguish an exact amount from unavailable accounting.

Trustworthy route-bound context, cache, and cost truth remain an explicit M0
roadmap gate.
