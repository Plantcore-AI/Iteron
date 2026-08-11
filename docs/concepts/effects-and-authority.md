# Effects and authority

Iteron separates what a tool proposes from what the runtime is allowed to do.
The iteron types express both purity and capability so scheduling and permission
decisions do not depend only on command text.

## Purity

- A **pure** tool has no intended observable effect and may be eligible for early
  dispatch or memoization under its confinement contract.
- An **effecting** tool waits for the complete model turn and passes through
  policy before execution.

Purity is not permission. A mislabeled implementation is a security defect, and
registration rejects incompatible purity/capability shapes.

## Capability lattice

The capability classes are `read_only`, `reversible_local`, `code_executing`,
`trust_mutating`, and `irreversible_external`. Permission modes form one policy
table over those classes. Plan mode is a hard read-only overlay; trust-mutating
and irreversible external actions cannot be auto-approved by any mode or session
rule.

Repository configuration can tighten a trusted grant or budget. It cannot mint
code execution, provider routing, endpoint routing, MCP processes, or lifecycle
hooks.

## Effect identity and unknown outcomes

Externally visible effects need durable identities and a terminal state. If
Iteron observes dispatch but cannot prove completion, it records an unknown outcome
instead of automatically repeating a potentially duplicated operation.

The repository contains an initial durable effect-journal path, but not every
tool effect has been consolidated behind the final single-broker target. This is
why the architecture page distinguishes present modularity from microkernel
conformance.

## Untrusted inputs

Repository files, model output, web pages, MCP descriptions, tool output, and
project instructions are data with explicit trust provenance. They may guide a
task, but they do not become operator authority because they contain imperative
language.
