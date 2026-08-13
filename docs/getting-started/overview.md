# Overview

Iteron is the first coding vertical of a broader agent-runtime design. The
current product is a terminal application: the `iteron` executable composes a model
provider, repository tools, a durable run record, permissions, sandbox policy,
verification, and the TUI or one-shot frontend.

## Who it is for

The current pre-alpha is intended for:

- contributors testing the runtime and terminal experience;
- developers evaluating provider, permission, record, or replay behavior;
- users willing to operate it in a disposable or recoverable repository;
- researchers working on bounded orchestration and governed strategy contracts.

It is not yet a supported replacement for a production coding-agent workflow.

## Delivered and targeted

| Area | Present today | Still target work |
| --- | --- | --- |
| Frontend | Interactive TUI; one-shot text, JSON, and JSONL | Stable frontend-independent App Server |
| Providers | Three wire adapters and six built-in provider profiles | Complete provider lifecycle and production conformance |
| Repository work | Read, search, edit, shell, Git, memory, skills, hooks, initial MCP tools | Atomic multi-file patch, persistent PTY, complete LSP/MCP lifecycle |
| Safety | Permission lattice, bounded budgets, scoped effects, macOS/Linux sandbox backends | Audited single effect path and comprehensive hostile-repository evidence |
| Durability | Hash-chained local run records, resume, continue, and fork | Pure reducer, full crash reconciliation, versioned external protocol |
| Evolution | Non-authoritative types and promotion-boundary contracts | Dataset registry, held-out evaluation, shadow, canary, promotion, rollback |

## Five invariants

Iteron evaluates mechanisms against five project invariants:

1. **Bounded** — loops, retries, queues, output, time, cost, and concurrency have
   explicit ceilings.
2. **Recoverable** — interruption and crash need explicit recovery semantics.
3. **Reproducible** — recorded nondeterminism replays; model output is not silently
   regenerated.
4. **Observable** — phase, usage, effects, verification, and strategy attribution
   are emitted where implemented.
5. **Security-bounded** — authority can only narrow from its operator-set ceiling,
   never self-widen, and its blast radius is explicit.

These are design requirements, not a claim that every current code path has
completed production evidence.

## Next steps

- [Install from source](installation.md)
- [Set up a provider key with BYOK](setup-and-byok.md)
- [Configure a custom provider](providers.md)
- [Open a first session](first-session.md)
- [Understand permission modes](../using/permissions-and-sandbox.md)
