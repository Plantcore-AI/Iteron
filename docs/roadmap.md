# Roadmap

Core is pre-alpha. Milestones are evidence gates rather than marketing dates.

## M0 — Truth and safety

- trustworthy real-repository evaluation and explicit failed-run handling;
- route-bound context, token, cache, and cost truth;
- transactional file edits and reproducible effective-run manifests;
- one audited effect path with crash reconciliation;
- provider, sandbox, permission, record, and recovery integration tests.

## M1 — Runtime and protocol

- pure reducer and long-lived session runtime;
- versioned App Server commands and events;
- bounded queues, backpressure, reconnect, resume, and replay;
- TUI and CLI as clients rather than owners of the runtime;
- injected, versioned capability ports.

## M2 — Production coding substrate

- persistent PTY and background process lifecycle;
- atomic multi-file patch, Git/worktree, search, and LSP integration;
- complete provider and MCP lifecycle, skills, hooks, and plugins;
- observability, fault injection, real-repository soak, and cross-platform policy;
- signed, reproducible distribution with upgrade and rollback testing.

## M3 — Controlled collaboration

- durable tasks, messages, budgets, cancellation, steering, and deterministic join;
- isolated writer worktrees and validating merge;
- concurrency only where fixed-model evaluation demonstrates quality or latency
  benefit.

This product capability does not change the project's human development model:
one Owner/Project Lead with final override, plus an open-ended group of human
maintainer/engineers who freely choose explicit modular boundaries. Each
maintainer may bind one persistent agent to their declared boundaries.

## M4 — Governed evolution

- immutable trajectory and dataset registries;
- held-out evaluation, shadow, canary, promotion, and rollback;
- bounded strategy slots for search, bandits, SFT, GRPO, and offline RL;
- a second non-coding vertical without a kernel branch.

Live self-evolution is intentionally not on the critical path until M0–M3 evidence
is reliable.

## Good community entry points

- regression and conformance tests;
- provider capability fixtures and documentation;
- cross-platform sandbox/process behavior;
- TUI accessibility, terminal compatibility, and snapshot coverage;
- MCP interoperability fixtures;
- documentation and small, reproducible bug fixes.
