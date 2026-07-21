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

Core Code's cost state can be known or unknown. An operator-signed, versioned rate
card is bound to the exact provider, model, catalog digest, and capability digest.
For each authoritative usage sample, the injected pricing strategy produces a
fixed-point micro-USD projection; the record stores its card digest, timestamp,
usage, amount, content digest, and HMAC. The kernel records and enforces that
evidence but does not fetch prices or hold the signing key.

Without an exact active verified card, Core does not infer a dollar amount from
token counts. Such runs remain `Unknown{NoVerifiedRateCard}`, and a positive
`max_usd` fails closed before a provider request. With a verified card, crossing
the ceiling stops the run as `BudgetExhausted("max_usd")`. The ceiling bounds
Core's signed projection, not an independent guarantee about a provider invoice.

The effective monetary ceiling is recorded in session genesis, inherited by
forks, and restored monotonically on resume: a later invocation may tighten it
but cannot omit or widen it. Any dispatched provider request that ends without
authoritative usage closes the shared parent/descendant ceiling as unknown
before another request can be admitted.

Machine output carries `cost_usd`, `cost_status`, and `cost_reason` so callers can
distinguish an exact amount from unavailable accounting.

Authenticated replay uses the durable signed projection timestamp and amount,
not a current price fetch. Replay without the operator trust port remains Unknown
rather than trusting an unauthenticated cached dollar value.
