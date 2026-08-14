# Roadmap

Iteron is pre-alpha. This roadmap uses acceptance evidence rather than dates or
feature-count marketing. A milestone is not complete because code exists; it is
accepted only when its stated integration, failure, recovery, security, and
operational gates pass on real repositories.

## Delivered baseline

The repository already contains a usable development baseline:

- terminal-native TUI and one-shot text/JSON/stream-JSON CLI;
- bounded provider adapters and credential-aware model discovery;
- typed workspace tools, permissions, hooks, skills, verification, and MCP client;
- macOS Seatbelt and Linux bubblewrap backends with live boundary tests;
- hash-chained session records with resume, continue, fork, and checkpoints;
- modular protocol, runtime, provider, context, execution, evidence, evaluation,
  and evolution crates;
- machine-validated source ownership and internal dependency boundaries.

This baseline is evidence for future milestones, not proof that a milestone is
accepted.

## Milestone status

| Milestone | State | Acceptance meaning |
| --- | --- | --- |
| M0 — Truth and safety | In progress | Runtime claims match durable and provider evidence under failure |
| M1 — Runtime and protocol | Not accepted | A long-lived versioned runtime owns lifecycle independently of clients |
| M2 — Production coding substrate | Not accepted | Real repositories pass security, soak, release, and rollback gates |
| M3 — Controlled collaboration | Not accepted | Durable multi-task execution improves measured outcomes without weakening human ownership |
| M4 — Governed evolution | Not accepted | Learning candidates can be evaluated and promoted without self-granted authority |

## M0 — Truth and safety

**Objective:** make every material UI, usage, cost, effect, completion, and recovery
claim traceable to authoritative evidence.

Acceptance gates:

- trustworthy real-repository evaluation with explicit failed-run accounting;
- route-bound context, cache, token, and cost truth;
- transactional edits and reproducible effective-run manifests;
- one audited effect path with crash and unknown-outcome reconciliation;
- provider, sandbox, permission, record, and recovery integration tests;
- fault injection for partial streams, timeouts, cancellation, and corrupt state.

Community entry points include reproducible failure fixtures, provider evidence
tests, cost/usage truth, sandbox behavior, and recovery cases. A new UI metric
without an authoritative source is a non-goal.

## M1 — Runtime and protocol

**Objective:** move session lifecycle behind a versioned runtime boundary so TUI,
CLI, and future clients are adapters rather than owners.

Acceptance gates:

- pure reducer and long-lived session runtime;
- versioned App Server commands, events, negotiation, and compatibility tests;
- bounded queues, backpressure, reconnect, resume, and replay;
- injected, versioned capability ports with no ambient authority;
- graceful shutdown, cancellation, and supervision across client loss;
- TUI and one-shot CLI proven against the same server contract.

Replacing in-process calls with an unversioned socket or moving logic without
changing ownership is a non-goal.

## M2 — Production coding substrate

**Objective:** make the coding distribution dependable on sustained, real-world
repository work.

Acceptance gates:

- persistent PTY and background process lifecycle;
- atomic multi-file patch, Git/worktree, search, and LSP integration;
- complete provider and MCP lifecycle plus bounded skills, hooks, and plugins;
- observability, fault injection, real-repository soak, and cross-platform policy;
- signed and attestable distribution with SBOM, upgrade, rollback, and installer
  canaries;
- stable compatibility and deprecation policy backed by conformance suites.

More tools without process ownership, recovery, or measurements are a non-goal.

## M3 — Controlled collaboration

**Objective:** support bounded concurrent agent work only where isolation and
fixed-model evaluation show a real benefit.

Acceptance gates:

- durable tasks, messages, budgets, cancellation, steering, and deterministic
  join semantics;
- isolated writer worktrees and validating merge;
- explicit ownership of partial failure and orphan cleanup;
- concurrency admitted only when fixed-model evaluation improves quality or
  latency without raising risk beyond policy;
- human maintainers retain design, review, merge, incident, and release authority.

This product capability does not create an agent-swarm development organization.
Iteron has one human Project Owner with final override and an open-ended group
of human maintainers who choose explicit modular boundaries. Agents do not
negotiate or approve project work.

## M4 — Governed evolution

**Objective:** allow strategy improvement without allowing a learned component to
change authority, evidence, budgets, or its own promotion criteria.

Acceptance gates:

- immutable trajectory and consent-aware dataset registries;
- held-out evaluation, shadow, canary, promotion, rollback, and audit trails;
- bounded strategy slots with optimizer-neutral harness-producer provenance
  (legacy SFT/preference/GRPO/RL names never authorize model training);
- independent evaluation ownership and contamination controls;
- a second non-coding vertical demonstrated without a kernel branch.

Live self-evolution is intentionally outside the critical path until M0–M3 are
accepted. Training directly on unreviewed private sessions or optimizing safety
policy is a non-goal.

## Tracking and contribution

Milestone work should be represented by public epic issues with a single
acceptance owner, linked evidence, explicit non-goals, and independently claimable
sub-issues. The initial public bootstrap is tracked in
[issue #6](https://github.com/Plantcore-AI/Iteron/issues/6).

Good community entry points:

- regression and conformance tests;
- provider capability fixtures and documentation;
- cross-platform sandbox and process behavior;
- TUI accessibility, terminal compatibility, and PTY coverage;
- MCP interoperability fixtures;
- documentation, release verification, and small reproducible bug fixes.
